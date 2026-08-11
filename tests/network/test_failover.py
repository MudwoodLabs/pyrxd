"""Request-level failover across ElectrumX endpoints.

Three properties are worth more than the rest:

* a dead endpoint must not be an outage (failover happens at all);
* a node VERDICT must never be retried against a different node (no shopping for
  a server that likes a rejected transaction);
* ``broadcast`` must replay the SAME BYTES or nothing — a retry that could send a
  different transaction is a double-spend generator, not resilience.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from pyrxd.hash import double_sha256
from pyrxd.network.electrumx import ElectrumXClient
from pyrxd.network.failover import FailoverElectrumXClient
from pyrxd.network.registry import Endpoint, NetworkProfile
from pyrxd.security.errors import NetworkError, PolicyRejection, TlsPinMismatchError, ValidationError
from pyrxd.security.types import BTC_MAX_SATS, BlockHeight, RawTx, Txid

pytestmark = pytest.mark.asyncio

_RAW_TX = bytes(range(65)) * 2  # >64 bytes so RawTx validates
_EXPECTED_TXID = double_sha256(_RAW_TX)[::-1].hex()
_GENESIS = "7c1797514a165b0d99953a993a2a42081d6c0706026c36c06fc6fe728f93a5dd"


class FakeClient:
    """A stand-in ElectrumXClient that records calls and raises on demand.

    Only the surface the failover wrapper touches is implemented; anything else
    would be scaffolding that never runs.
    """

    def __init__(self, url: str) -> None:
        self.url = url
        self.calls: list[tuple[str, object]] = []
        self.closed = 0
        self.tip_error: Exception | None = None
        self.tip_value: int = 100
        self.broadcast_error: Exception | None = None
        self.broadcast_result: str | None = None
        self.chain_error: Exception | None = None
        self.chain_checks = 0
        self.extension_error: Exception | None = None
        # The read-back an "already known" claim must survive (audit B6): by default the
        # node really does hold the transaction it says it holds.
        self.get_transaction_error: Exception | None = None
        self.get_transaction_result: bytes | None = None

    async def assert_chain(self, expected: str) -> str:
        self.chain_checks += 1
        self.calls.append(("assert_chain", expected))
        if self.chain_error is not None:
            raise self.chain_error
        return expected

    async def get_tip_height(self) -> BlockHeight:
        self.calls.append(("get_tip_height", None))
        if self.tip_error is not None:
            raise self.tip_error
        return BlockHeight(self.tip_value)

    async def broadcast(self, raw_tx: bytes) -> Txid:
        self.calls.append(("broadcast", bytes(raw_tx)))
        if self.broadcast_error is not None:
            raise self.broadcast_error
        return Txid(self.broadcast_result or _EXPECTED_TXID)

    async def get_transaction(self, txid: Txid) -> RawTx:
        self.calls.append(("get_transaction", str(txid)))
        if self.get_transaction_error is not None:
            raise self.get_transaction_error
        return RawTx(self.get_transaction_result if self.get_transaction_result is not None else _RAW_TX)

    async def call_extension(self, method: str, params: list | None = None) -> object:
        self.calls.append(("call_extension", method))
        if self.extension_error is not None:
            raise self.extension_error
        return {"ok": method}

    async def close(self) -> None:
        self.closed += 1


def build(urls: list[str], *, genesis: str | None = None, verify_chain: bool = False):
    """Return ``(client, {url: FakeClient})`` wired through the injected factory."""
    profile = NetworkProfile(
        network="regtest",
        endpoints=tuple(Endpoint(url=u, allow_insecure=u.startswith("ws://")) for u in urls),
        genesis_hash=genesis,
    )
    fakes: dict[str, FakeClient] = {u: FakeClient(u) for u in urls}

    def factory(endpoint: Endpoint) -> FakeClient:
        return fakes[endpoint.url]

    client = FailoverElectrumXClient(
        profile,
        client_factory=factory,  # type: ignore[arg-type]
        verify_chain=verify_chain,
    )
    return client, fakes


A = "wss://a.example/"
B = "wss://b.example/"
C = "wss://c.example/"


# ── failover on reads ─────────────────────────────────────────────────────────


async def test_first_endpoint_down_second_is_used() -> None:
    client, fakes = build([A, B])
    fakes[A].tip_error = NetworkError("ElectrumX connection lost")
    fakes[B].tip_value = 4242

    assert int(await client.get_tip_height()) == 4242
    assert ("get_tip_height", None) in fakes[A].calls
    assert ("get_tip_height", None) in fakes[B].calls


async def test_a_working_endpoint_is_promoted_so_the_next_call_skips_the_dead_one() -> None:
    client, fakes = build([A, B])
    fakes[A].tip_error = NetworkError("down")

    await client.get_tip_height()
    assert client.active_url == B

    fakes[A].calls.clear()
    await client.get_tip_height()
    assert fakes[A].calls == []  # the known-dead endpoint is not re-tried first


async def test_failed_endpoint_client_is_closed_and_rebuilt() -> None:
    client, fakes = build([A, B])
    fakes[A].tip_error = NetworkError("down")
    await client.get_tip_height()
    assert fakes[A].closed == 1


async def test_all_endpoints_down_raises_naming_the_count() -> None:
    client, fakes = build([A, B, C])
    for fake in fakes.values():
        fake.tip_error = NetworkError("down")

    with pytest.raises(NetworkError, match="all 3 ElectrumX endpoint"):
        await client.get_tip_height()


async def test_single_endpoint_behaviour_is_unchanged() -> None:
    """One configured endpoint = the old behaviour: the error surfaces, nothing else
    is tried, because there is nothing else."""
    client, fakes = build([A])
    fakes[A].tip_error = NetworkError("ElectrumX request timed out")

    with pytest.raises(NetworkError):
        await client.get_tip_height()
    assert len(fakes[A].calls) == 1


# ── no blind retry of node verdicts / non-idempotent calls ────────────────────


async def test_policy_rejection_is_never_retried_on_another_endpoint() -> None:
    """A node verdict is an ANSWER. Re-asking a different node is shopping for a
    server with laxer rules, and it would bury the reject reason."""
    client, fakes = build([A, B])
    fakes[A].broadcast_error = PolicyRejection("node rejected", code=-26, reason="mandatory-script-verify-flag-failed")

    with pytest.raises(PolicyRejection):
        await client.broadcast(_RAW_TX)
    assert fakes[B].calls == []


async def test_policy_rejection_on_a_read_is_not_retried_either() -> None:
    client, fakes = build([A, B])
    fakes[A].tip_error = PolicyRejection("node said no", code=1, reason="dust")

    with pytest.raises(PolicyRejection):
        await client.get_tip_height()
    assert fakes[B].calls == []


async def test_call_extension_is_not_retried_by_default() -> None:
    """`call_extension` reaches arbitrary indexer RPCs; the failover layer cannot
    know whether replaying one is safe, so it does not."""
    client, fakes = build([A, B])
    fakes[A].extension_error = NetworkError("down")

    with pytest.raises(NetworkError):
        await client.call_extension("some.mutating.method")
    assert fakes[B].calls == []


async def test_call_extension_retries_when_the_caller_declares_it_idempotent() -> None:
    client, fakes = build([A, B])
    fakes[A].extension_error = NetworkError("down")

    assert await client.call_extension("glyph.get_token", idempotent=True) == {"ok": "glyph.get_token"}


async def test_tls_pin_mismatch_is_not_routed_around() -> None:
    """A substituted server must be loud, not silently skipped."""
    client, fakes = build([A, B])
    fakes[A].tip_error = TlsPinMismatchError("pin mismatch")

    with pytest.raises(TlsPinMismatchError):
        await client.get_tip_height()
    assert fakes[B].calls == []


# ── broadcast semantics ───────────────────────────────────────────────────────


async def test_broadcast_replays_byte_identical_payloads() -> None:
    """The safety property behind allowing a broadcast retry at all: the bytes are
    captured once, so a retry can never be a DIFFERENT transaction."""
    client, fakes = build([A, B])
    fakes[A].broadcast_error = NetworkError("ElectrumX connection lost")

    assert str(await client.broadcast(_RAW_TX)) == _EXPECTED_TXID
    sent = [payload for name, payload in fakes[A].calls + fakes[B].calls if name == "broadcast"]
    assert len(sent) == 2
    assert sent[0] == sent[1] == _RAW_TX


async def test_broadcast_already_known_after_a_transport_failure_is_success() -> None:
    """The lost-response case: node A accepted the tx and the socket died. Node B
    saying "I already have this" proves the transaction is live — reporting failure
    would be a lie about a transaction that is on the network."""
    client, fakes = build([A, B])
    fakes[A].broadcast_error = NetworkError("ElectrumX connection lost")
    fakes[B].broadcast_error = PolicyRejection("node rejected", code=1, reason="txn-already-known")

    assert str(await client.broadcast(_RAW_TX)) == _EXPECTED_TXID


async def test_broadcast_already_in_chain_code_after_a_failure_is_success() -> None:
    client, fakes = build([A, B])
    fakes[A].broadcast_error = NetworkError("down")
    fakes[B].broadcast_error = PolicyRejection("already", code=-27, reason="transaction already in block chain")

    assert str(await client.broadcast(_RAW_TX)) == _EXPECTED_TXID


async def test_broadcast_already_known_is_refused_when_the_node_cannot_produce_the_tx() -> None:
    """B6: an "already known" claim is a CLAIM, not evidence.

    After a transport failure elsewhere, a hostile or broken secondary can answer any
    broadcast with RPC ``-27`` / ``txn-already-known`` and the wrapper reported SUCCESS
    for a transaction that was never accepted anywhere — the caller then polls forever
    for a ghost, and on a swap path believes its leg is locked. The claim must be
    corroborated by a read that actually returns the transaction.
    """
    client, fakes = build([A, B])
    fakes[A].broadcast_error = NetworkError("ElectrumX connection lost")
    fakes[B].broadcast_error = PolicyRejection("already", code=-27, reason="transaction already in block chain")
    fakes[B].get_transaction_error = NetworkError("no such mempool or blockchain transaction")

    with pytest.raises(NetworkError):
        await client.broadcast(_RAW_TX)


async def test_broadcast_already_known_is_refused_when_the_read_back_is_a_different_tx() -> None:
    """The read-back is bound to the SAME bytes: a node that serves some other transaction
    has not demonstrated it holds ours."""
    client, fakes = build([A, B])
    fakes[A].broadcast_error = NetworkError("down")
    fakes[B].broadcast_error = PolicyRejection("already", code=-27, reason="txn-already-known")
    fakes[B].get_transaction_result = bytes(range(70)) * 2  # a valid RawTx, but not ours

    with pytest.raises(NetworkError):
        await client.broadcast(_RAW_TX)


async def test_broadcast_already_known_is_refused_when_the_node_cannot_be_read_at_all() -> None:
    """Fail-closed on a MISSING capability too: a client with no ``get_transaction`` cannot
    corroborate its own claim, so the claim is not honored."""
    client, fakes = build([A, B])
    fakes[A].broadcast_error = NetworkError("down")
    fakes[B].broadcast_error = PolicyRejection("already", code=-27, reason="txn-already-known")
    fakes[B].get_transaction = None  # type: ignore[assignment]  # no read surface at all

    with pytest.raises(NetworkError):
        await client.broadcast(_RAW_TX)


async def test_broadcast_already_known_corroborated_by_a_read_is_still_success() -> None:
    """The honest lost-response case keeps working: node B really does hold the tx."""
    client, fakes = build([A, B])
    fakes[A].broadcast_error = NetworkError("ElectrumX connection lost")
    fakes[B].broadcast_error = PolicyRejection("already", code=-27, reason="txn-already-known")

    assert str(await client.broadcast(_RAW_TX)) == _EXPECTED_TXID
    assert ("get_transaction", _EXPECTED_TXID) in fakes[B].calls


async def test_broadcast_already_known_on_the_FIRST_attempt_still_raises() -> None:
    """No transport fault happened, so "already known" is information, not noise.
    Swallowing it here would hide a genuine double-submit from the caller."""
    client, fakes = build([A, B])
    fakes[A].broadcast_error = PolicyRejection("node rejected", code=1, reason="txn-already-in-mempool")

    with pytest.raises(PolicyRejection):
        await client.broadcast(_RAW_TX)
    assert fakes[B].calls == []


async def test_broadcast_rejects_a_txid_that_is_not_the_hash_of_what_was_sent() -> None:
    """The txid is a pure function of the bytes; a server returning something else is
    answering about a different transaction, and the caller would poll for a ghost."""
    client, fakes = build([A])
    fakes[A].broadcast_result = "ff" * 32

    with pytest.raises(NetworkError, match="returned txid"):
        await client.broadcast(_RAW_TX)


async def test_broadcast_all_endpoints_down_raises() -> None:
    client, fakes = build([A, B])
    for fake in fakes.values():
        fake.broadcast_error = NetworkError("down")

    with pytest.raises(NetworkError, match="broadcast failed on all 2"):
        await client.broadcast(_RAW_TX)


# ── chain binding ─────────────────────────────────────────────────────────────


async def test_each_endpoint_is_chain_checked_once() -> None:
    client, fakes = build([A, B], genesis=_GENESIS, verify_chain=True)

    await client.get_tip_height()
    await client.get_tip_height()
    assert fakes[A].chain_checks == 1
    assert fakes[B].chain_checks == 0  # never needed


async def test_a_wrong_chain_endpoint_is_refused_not_failed_over() -> None:
    """Failing over to a server on a DIFFERENT chain is worse than the outage it
    avoids: it is how a regtest command reaches mainnet."""
    client, fakes = build([A, B], genesis=_GENESIS, verify_chain=True)
    fakes[A].chain_error = ValidationError("ElectrumX endpoint is on the wrong chain")

    with pytest.raises(ValidationError, match="wrong chain"):
        await client.get_tip_height()
    assert fakes[B].calls == []


async def test_a_transport_failure_during_the_chain_check_does_fail_over() -> None:
    """A dead endpoint is a dead endpoint, even when it dies during verification."""
    client, fakes = build([A, B], genesis=_GENESIS, verify_chain=True)
    fakes[A].chain_error = NetworkError("connection lost")
    fakes[B].tip_value = 77

    assert int(await client.get_tip_height()) == 77
    assert fakes[B].chain_checks == 1


async def test_a_genesisless_profile_is_refused_rather_than_silently_unverified() -> None:
    """Was ``test_no_chain_check_when_the_profile_has_no_genesis``, which asserted the bug.

    ``_client_for`` used to skip ``assert_chain`` outright when the profile carried
    no genesis hash, so ``verify_chain=True`` on a genesis-less profile degraded to
    "no chain check at all" — measured at 0 checks — while the caller believed the
    binding was being verified. That is the state an un-normalized ``PYRXD_NETWORK``
    put the CLI into (``genesis_hash_for("REGTEST") is None``), and it is the one
    check that would have caught a "regtest" run pointed at a mainnet server.

    Construction now fails closed instead; opting out must be explicit.
    """
    with pytest.raises(ValidationError, match="no genesis hash is known"):
        build([A], genesis=None, verify_chain=True)


async def test_verify_chain_false_still_permits_a_genesisless_profile() -> None:
    """The explicit opt-out is preserved — that is the escape hatch for a chain
    pyrxd ships no constant for, and it is the caller's stated decision."""
    client, fakes = build([A], genesis=None, verify_chain=False)
    await client.get_tip_height()
    assert fakes[A].chain_checks == 0


async def test_verify_chain_false_skips_the_check() -> None:
    client, fakes = build([A], genesis=_GENESIS, verify_chain=False)
    await client.get_tip_height()
    assert fakes[A].chain_checks == 0


# ── lifecycle + construction ──────────────────────────────────────────────────


async def test_close_closes_every_underlying_client() -> None:
    client, fakes = build([A, B])
    fakes[A].tip_error = NetworkError("down")
    await client.get_tip_height()  # opens both
    await client.close()
    assert fakes[B].closed == 1


async def test_context_manager_is_lazy_and_closes_on_exit() -> None:
    client, fakes = build([A])
    async with client as c:
        assert fakes[A].calls == []  # no eager connect
        await c.get_tip_height()
    assert fakes[A].closed == 1


async def test_rejects_a_non_profile() -> None:
    with pytest.raises(ValidationError, match="NetworkProfile"):
        FailoverElectrumXClient("wss://a.example/")  # type: ignore[arg-type]


async def test_rejects_a_non_positive_timeout() -> None:
    profile = NetworkProfile.build("mainnet", [A])
    with pytest.raises(ValidationError, match="positive"):
        FailoverElectrumXClient(profile, timeout=0)


async def test_urls_property_reflects_preference_order() -> None:
    client, fakes = build([A, B])
    fakes[A].tip_error = NetworkError("down")
    await client.get_tip_height()
    assert client.urls[0] == B


# ── a truthful large balance must not look like a broken endpoint ─────────────


async def test_a_whale_utxo_does_not_evict_every_healthy_endpoint() -> None:
    """The second-order damage of applying Bitcoin's supply cap to Radiant photons.

    ``ElectrumXClient.get_utxos`` bounded ``value`` with ``Satoshis`` (2.1e15 = 21,000,000
    BTC) on the RADIANT read path, where MAX_MONEY is 2.1e18. A UTXO above 21,000,000 RXD
    therefore raised, and the raise surfaced as ``NetworkError`` — indistinguishable, here,
    from a dropped socket. ``_run`` reads that as a transport fault and ``_discard``s the
    endpoint, so a wallet holding one large coin walked its whole endpoint list, closing
    each healthy server in turn, and finished with "failed on all N endpoints".

    Uses REAL ``ElectrumXClient`` instances (only the wire call is stubbed), because the
    parsing under test is exactly what a fake would have to reimplement.
    """
    whale = BTC_MAX_SATS + 1
    payload = [
        {"tx_hash": "11" * 32, "tx_pos": 0, "value": 100_000, "height": 900},
        {"tx_hash": "22" * 32, "tx_pos": 1, "value": whale, "height": 901},
    ]
    profile = NetworkProfile(
        network="regtest",
        endpoints=tuple(Endpoint(url=u, allow_insecure=False) for u in (A, B, C)),
        genesis_hash=None,
    )
    reals: dict[str, ElectrumXClient] = {}

    def factory(endpoint: Endpoint) -> ElectrumXClient:
        real = ElectrumXClient([endpoint.url])
        real._call = AsyncMock(return_value=payload)  # type: ignore[method-assign]
        reals[endpoint.url] = real
        return real

    client = FailoverElectrumXClient(profile, client_factory=factory, verify_chain=False)
    got = await client.get_utxos("ab" * 32)

    assert [u.value for u in got] == [100_000, whale]
    # One endpoint answered; the other two were never even built, let alone discarded.
    assert list(reals) == [A]
    assert client.active_url == A
