"""The autonomous claim asks a second operator before it takes a node rejection as final (#937).

``RadiantChainIO.broadcast`` raises the first endpoint's node rejection as the verdict. For the
autonomous claim that lets one lagging, stricter or lying server hold the claim back alone while the
maker's refund timelock runs. ``RadiantChainIO.with_second_opinion`` (wired by
``make_radiant_claim_leg(..., second_opinion=...)``) asks one client per operator before raising.

The servers are real ``ElectrumXClient`` objects whose wire (``_call``) is answered by the ``_Node``
mempool model from ``test_claim_executor_echo_mismatch``, so the echo check, the JSON-RPC
error mapping and the read-back hash check are production code. Each node is given its own URL, so
its operator (``source_key``) comes from ``pyrxd.network.source_identity``, not from the test.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Any

import pytest

from pyrxd.gravity.radiant_leg import RadiantChainIO, SecondOpinionTxid, SeenStore
from pyrxd.gravity.watch import ExecOutcome
from pyrxd.gravity.watch.claim_executor import CovenantClaimContext, make_radiant_claim_leg, sidecar_leg_resolver
from pyrxd.network.electrumx import ElectrumXClient
from pyrxd.network.source_identity import source_key
from pyrxd.security.errors import NetworkError, PolicyRejection, TlsPinMismatchError, ValidationError

from test_claim_executor_echo_mismatch import (  # isort: skip
    _COVENANT,
    _LIE,
    _SCRIPT_FAILED,
    _Node,
    _armed,
    _assert_paid_once,
    _spends,
    _txid,
)

_REJECTED = "the first endpoint's own reason"


class _OpNode(_Node):
    """A ``_Node`` at *url* (so its operator is derived from that URL) that also serves a raw
    transaction from its mempool on ``blockchain.transaction.get``, and can be made to fail."""

    def __init__(self, url: str) -> None:
        super().__init__()
        ElectrumXClient.__init__(self, [url])
        #: Raised from every broadcast instead of answering, when set.
        self.fail: Exception | None = None
        #: Whether ``blockchain.transaction.get`` serves mempool bytes (a read-back).
        self.serves = True
        self.reads: list[str] = []

    async def _call(self, method: str, params: list[Any]) -> Any:
        if method == "blockchain.transaction.broadcast" and self.fail is not None:
            self.broadcasts.append(bytes.fromhex(params[0]))
            raise self.fail
        if method == "blockchain.transaction.get" and params[1:] == [False]:
            self.reads.append(params[0])
            raw = self.mempool.get(params[0]) if self.serves else None
            if raw is None:
                raise NetworkError("No such mempool or blockchain transaction")
            return raw.hex()
        return await super()._call(method, params)


def _primary() -> _OpNode:
    node = _OpNode("wss://electrum.alpha.example/")
    node.reject = (-26, _REJECTED)
    return node


def _second(name: str = "beta") -> _OpNode:
    return _OpNode(f"wss://electrum.{name}.example/")


# --------------------------------------------------------------------------- RadiantChainIO.broadcast


async def test_a_second_operator_that_takes_a_rejected_transaction_makes_the_broadcast_succeed() -> None:
    primary, second = _primary(), _second()
    raw = os.urandom(80)
    txid = await RadiantChainIO(primary).with_second_opinion((second,)).broadcast(raw)
    assert txid == _txid(raw)
    assert isinstance(txid, SecondOpinionTxid), "the caller can tell only a second opinion took it"
    assert primary.broadcasts == [raw] and second.broadcasts == [raw], "the same bytes, once each"
    assert set(second.mempool) == {_txid(raw)}


async def test_the_shared_chain_io_still_takes_the_first_rejection_as_final() -> None:
    """Honest path for the attended callers: ``with_second_opinion`` returns a NEW chain IO."""
    primary, second = _primary(), _second()
    shared = RadiantChainIO(primary)
    claim_io = shared.with_second_opinion((second,))
    assert claim_io is not shared and shared.second_opinion == () and claim_io.second_opinion == (second,)
    with pytest.raises(PolicyRejection) as info:
        await shared.broadcast(os.urandom(80))
    assert info.value.reason == _REJECTED
    assert second.broadcasts == [], "the shared chain IO never asks the second operator"


async def test_an_accepted_broadcast_never_asks_the_second_operator() -> None:
    primary, second = _primary(), _second()
    primary.reject = None
    raw = os.urandom(80)
    txid = await RadiantChainIO(primary).with_second_opinion((second,)).broadcast(raw)
    assert txid == _txid(raw) and type(txid) is str
    assert second.broadcasts == []


async def test_when_every_operator_refuses_the_first_rejection_is_raised() -> None:
    primary, second, third = _primary(), _second("beta"), _second("gamma")
    second.reject = (-26, "the second endpoint's reason")
    third.fail = NetworkError("connection reset")
    raw = os.urandom(80)
    with pytest.raises(PolicyRejection) as info:
        await RadiantChainIO(primary).with_second_opinion((second, third)).broadcast(raw)
    assert info.value.reason == _REJECTED, "the first endpoint's verdict, not a later one"
    assert info.value.__cause__ is None and info.value.__context__ is None, "nothing is chained onto it"
    assert second.broadcasts == [raw] and third.broadcasts == [raw], "every operator was asked"


async def test_a_later_operator_is_asked_after_an_earlier_one_fails() -> None:
    primary, second, third = _primary(), _second("beta"), _second("gamma")
    second.fail = NetworkError("connection reset")
    raw = os.urandom(80)
    assert await RadiantChainIO(primary).with_second_opinion((second, third)).broadcast(raw) == _txid(raw)
    assert set(third.mempool) == {_txid(raw)}


async def test_the_first_operator_that_takes_it_ends_the_round(caplog) -> None:
    """Every operator is asked at once; the first that takes it ends the round and the rest are
    cancelled, so a slower one never finishes its ask."""
    primary, quick, slow = (
        _primary(),
        _SlowNode("wss://electrum.beta.example/"),
        _SlowNode("wss://electrum.gamma.example/"),
    )
    slow.delay = 5.0
    raw = os.urandom(80)
    io = RadiantChainIO(primary).with_second_opinion((slow, quick))
    with caplog.at_level(logging.WARNING):
        assert await asyncio.wait_for(io.broadcast(raw), 2.0) == _txid(raw)
    assert set(quick.mempool) == {_txid(raw)} and slow.broadcasts == [], "the slow ask was cancelled"
    said = " | ".join(r.getMessage() for r in caplog.records)
    assert "beta.example took it" in said and "outcome unknown): gamma.example" in said, said


async def test_a_second_operator_that_echoes_another_txid_is_not_believed() -> None:
    primary, second = _primary(), _second()
    second.lie = True
    with pytest.raises(PolicyRejection) as info:
        await RadiantChainIO(primary).with_second_opinion((second,)).broadcast(os.urandom(80))
    assert info.value.reason == _REJECTED


async def test_a_custom_client_whose_reply_is_another_txid_is_not_believed() -> None:
    """The reply is compared with the txid hashed from the bytes, whatever the client checked."""

    class _Unchecked:
        source_key = source_key("wss://electrum.beta.example/")

        async def broadcast(self, raw: bytes) -> str:
            return _LIE

        async def get_transaction(self, txid: str) -> bytes:  # pragma: no cover - never reached
            raise AssertionError("not a read-back case")

    with pytest.raises(PolicyRejection):
        await RadiantChainIO(_primary()).with_second_opinion((_Unchecked(),)).broadcast(os.urandom(80))


async def test_already_have_counts_only_when_the_bytes_are_served_back() -> None:
    primary, second = _primary(), _second()
    raw = os.urandom(80)
    second.mempool[_txid(raw)] = raw
    second.reject = (-27, "txn-already-known")
    second.serves = False
    io = RadiantChainIO(primary).with_second_opinion((second,))
    with pytest.raises(PolicyRejection) as info:
        await io.broadcast(raw)
    assert info.value.reason == _REJECTED, "an uncorroborated 'already have' is a claim, not evidence"
    assert second.reads == [_txid(raw)]

    second.serves = True
    assert await io.broadcast(raw) == _txid(raw)


async def test_a_custom_client_that_serves_other_bytes_back_is_not_believed() -> None:
    """The read-back compares bytes itself; a custom client need not hash-check what it serves."""
    raw = os.urandom(80)

    class _Claims:
        source_key = source_key("wss://electrum.beta.example/")

        async def broadcast(self, raw_tx: bytes) -> str:
            raise PolicyRejection("already", code=-27, reason="txn-already-known")

        async def get_transaction(self, txid: str) -> bytes:
            return os.urandom(80)

    with pytest.raises(PolicyRejection) as info:
        await RadiantChainIO(_primary()).with_second_opinion((_Claims(),)).broadcast(raw)
    assert info.value.reason == _REJECTED


async def test_a_tls_pin_mismatch_on_a_second_operator_is_raised_when_no_other_takes_it() -> None:
    primary, second, third = _primary(), _second("beta"), _second("gamma")
    second.fail = TlsPinMismatchError("pin mismatch")
    third.reject = (-26, "the third endpoint's reason")
    with pytest.raises(TlsPinMismatchError):
        await RadiantChainIO(primary).with_second_opinion((second, third)).broadcast(os.urandom(80))
    assert third.broadcasts, "the other operator was still asked"


async def test_a_tls_pin_mismatch_is_logged_but_another_operator_may_still_take_it(caplog) -> None:
    primary, second, third = _primary(), _second("beta"), _SlowNode("wss://electrum.gamma.example/")
    second.fail = TlsPinMismatchError("pin mismatch")
    third.delay = 0.05  # the pin mismatch is in before the taker answers
    raw = os.urandom(80)
    with caplog.at_level(logging.ERROR):
        txid = await RadiantChainIO(primary).with_second_opinion((second, third)).broadcast(raw)
    assert txid == _txid(raw) and isinstance(txid, SecondOpinionTxid)
    assert any(r.levelno == logging.ERROR and "TLS pin" in r.getMessage() for r in caplog.records)


# --------------------------------------------------------------------------- which clients qualify


def test_distinct_operators_are_accepted() -> None:
    io = RadiantChainIO(_primary()).with_second_opinion((_second("beta"), _second("gamma")))
    assert len(io.second_opinion) == 2


@pytest.mark.parametrize(
    ("make", "message"),
    [
        (lambda: (_OpNode("wss://other.alpha.example/"),), "same operator as the broadcast client"),
        (lambda: (_second("beta"), _OpNode("wss://other.beta.example/")), "same source"),
        (
            lambda: (ElectrumXClient(["wss://electrum.beta.example/", "wss://electrum.gamma.example/"]),),
            "does not say which source",
        ),
        (lambda: [_second()], "must be a tuple"),
        (lambda: (object(),), "must provide broadcast()"),
    ],
    ids=["primary-operator", "duplicate-operator", "several-operators", "not-a-tuple", "not-a-client"],
)
def test_a_set_that_is_not_one_client_per_other_operator_is_refused(make, message) -> None:
    with pytest.raises(ValidationError, match=message):
        RadiantChainIO(_primary()).with_second_opinion(make())


def test_the_constructor_applies_the_same_rules() -> None:
    with pytest.raises(ValidationError, match="same operator as the broadcast client"):
        RadiantChainIO(_primary(), second_opinion=(_OpNode("wss://other.alpha.example/"),))


def test_a_primary_over_several_operators_may_be_second_guessed_by_its_own_per_source_clients() -> None:
    """The documented wiring for pyrxd's shipped endpoints: the primary cannot say which operator
    answered, so every operator is asked once."""
    primary = ElectrumXClient(["wss://electrum.alpha.example/", "wss://electrum.beta.example/"])
    io = RadiantChainIO(primary).with_second_opinion(primary.per_source_clients())
    assert [str(source_key(c._urls[0])) for c in io.second_opinion] == [str(k) for k in primary.source_keys]


# --------------------------------------------------------------------------- the claim leg wiring


class _NoFees:
    def next_fee_input(self):  # pragma: no cover - the wiring tests build a leg and never claim
        raise AssertionError("no claim is built here")


def _context() -> CovenantClaimContext:
    return CovenantClaimContext(swap_id="swap-1", taker_pkh=os.urandom(20), maker_pkh=os.urandom(20))


def test_the_claim_leg_gets_its_own_chain_io_and_the_shared_one_is_unchanged() -> None:
    shared, second = RadiantChainIO(_primary()), _second()
    leg = make_radiant_claim_leg(
        _context(), chain_io=shared, fee_source=_NoFees(), network="bcrt", second_opinion=(second,)
    )
    assert leg.chain_io is not shared and leg.chain_io.second_opinion == (second,)
    assert shared.second_opinion == ()


def test_the_claim_leg_without_a_second_opinion_uses_the_shared_chain_io() -> None:
    shared = RadiantChainIO(_primary())
    leg = make_radiant_claim_leg(_context(), chain_io=shared, fee_source=_NoFees(), network="bcrt")
    assert leg.chain_io is shared


def test_the_sidecar_resolver_refuses_a_bad_set_when_it_is_built(tmp_path) -> None:
    shared = RadiantChainIO(_primary())
    with pytest.raises(ValidationError, match="same operator as the broadcast client"):
        sidecar_leg_resolver(
            tmp_path,
            chain_io=shared,
            fee_source=_NoFees(),
            network="bcrt",
            second_opinion=(_OpNode("wss://other.alpha.example/"),),
        )


async def test_the_sidecar_resolver_forwards_the_second_opinion(tmp_path) -> None:
    ctx = _context()
    (tmp_path / "swap-1.claim.json").write_text(json.dumps(ctx.to_dict()))
    second = _second()
    resolve = sidecar_leg_resolver(
        tmp_path, chain_io=RadiantChainIO(_primary()), fee_source=_NoFees(), network="bcrt", second_opinion=(second,)
    )
    leg = await resolve("swap-1", None)
    assert leg is not None and leg.chain_io.second_opinion == (second,)


# --------------------------------------------------------------------------- the executor, end to end


@pytest.fixture
def tick(caplog):
    async def _tick(ex, rec):
        from test_watch_claim_executor import _claim_decision

        caplog.clear()
        with caplog.at_level(logging.INFO):
            outcome = await ex.execute("swap-1", rec, _claim_decision())
        return outcome, " | ".join(r.getMessage() for r in caplog.records)

    return _tick


async def _with_second_opinion(
    primary: _OpNode, second: _OpNode, seen: SeenStore | None = None, *, resend_ticks: int | None = None
):
    ex, rec, fees = await _armed(primary, seen)
    leg = await ex._resolve_leg("swap-1", rec)
    leg.chain_io = leg.chain_io.with_second_opinion((second,))
    if resend_ticks is not None:
        ex._resend_ticks = resend_ticks
    return ex, rec, fees


def _one_chain(*nodes: _OpNode) -> None:
    """Mine every node's mempool into one block that every node sees."""
    block: dict[str, bytes] = {}
    for node in nodes:
        block.update(node.mempool)
        node.mempool.clear()
    for node in nodes:
        node.confirmed.update(block)


async def test_a_claim_one_endpoint_refuses_lands_through_a_second_operator(tick) -> None:
    primary, second = _OpNode("wss://electrum.alpha.example/"), _second()
    seen = SeenStore()
    ex, rec, fees = await _with_second_opinion(primary, second, seen)
    primary.reject = (-26, _SCRIPT_FAILED)

    outcome, said = await tick(ex, rec)
    assert outcome is ExecOutcome.BROADCAST, said
    assert len(primary.broadcasts) == 1 and second.broadcasts == primary.broadcasts
    assert "first endpoint rejected" in said and "beta.example took it" in said
    assert "not marked seen" in said
    claim = second.broadcasts[0]

    # Later ticks re-send the SAME bytes: no new fee input, nothing new relayed. The second node
    # answers "already have" and serves them back.
    for _ in range(3):
        outcome, said = await tick(ex, rec)
        assert outcome is ExecOutcome.DECLINED and "re-sent the same bytes" in said, said
    assert len(fees.outpoints) == 1, "the shared fee pool is not drained while the claim waits"
    assert set(primary.broadcasts) == {claim} and set(second.broadcasts) == {claim}
    assert set(second.mempool) == {_txid(claim)}

    _one_chain(primary, second)
    outcome, said = await tick(ex, rec)
    assert outcome is ExecOutcome.DECLINED and "already spent" in said, said
    assert _assert_paid_once(second, fees) == _txid(claim)


async def test_a_lying_second_opinion_cannot_disarm_the_claim(tick) -> None:
    """A first review's case: the first endpoint refuses for a passing reason, and a second-opinion
    server answers with the right txid but keeps nothing. Marking that seen would stop every later
    tick and leave the asset to the maker's refund. The held bytes go to the first endpoint first."""
    primary, liar = _OpNode("wss://electrum.alpha.example/"), _second()
    liar.relay = False
    seen = SeenStore()
    ex, rec, fees = await _with_second_opinion(primary, liar, seen)
    primary.reject = (-26, "txn-mempool-conflict (code 18)")

    outcome, said = await tick(ex, rec)
    assert outcome is ExecOutcome.BROADCAST, said
    assert liar.mempool == {} and primary.mempool == {}
    claim = primary.broadcasts[0]

    primary.reject = None
    outcome, said = await tick(ex, rec)
    assert outcome is ExecOutcome.DECLINED and "now taken by the broadcast client" in said, said
    assert primary.broadcasts == [claim, claim] and len(fees.outpoints) == 1
    assert set(primary.mempool) == {_txid(claim)}

    outcome, said = await tick(ex, rec)
    assert outcome is ExecOutcome.DECLINED and "already broadcast" in said, said
    _one_chain(primary, liar)
    assert _assert_paid_once(primary, fees) == _txid(claim)


async def test_a_held_claim_the_first_endpoint_already_has_is_marked_seen(tick) -> None:
    """The normal honest relay: the second node relayed the claim and the first endpoint now holds
    it, so the re-send gets "already have" from the first endpoint itself."""
    primary, second = _OpNode("wss://electrum.alpha.example/"), _second()
    seen = SeenStore()
    ex, rec, fees = await _with_second_opinion(primary, second, seen)
    primary.reject = (-26, "txn-mempool-conflict (code 18)")
    outcome, said = await tick(ex, rec)
    assert outcome is ExecOutcome.BROADCAST, said
    claim = second.broadcasts[0]

    primary.reject = None
    primary.mempool[_txid(claim)] = claim  # relayed peer to peer
    outcome, said = await tick(ex, rec)
    assert outcome is ExecOutcome.DECLINED and "now taken by the broadcast client" in said, said
    assert second.broadcasts == [claim], "the first endpoint's own answer ends it"
    assert ex._held == {}
    outcome, said = await tick(ex, rec)
    assert outcome is ExecOutcome.DECLINED and "already broadcast" in said, said
    assert len(fees.outpoints) == 1


async def test_a_held_claim_is_rebuilt_once_its_re_sends_run_out(tick) -> None:
    """A liar that keeps nothing while the first endpoint refuses THESE bytes (say, for their fee
    input) delays the claim by the re-send count, then a rebuild on a new fee input goes to the
    first endpoint again."""
    primary, liar = _OpNode("wss://electrum.alpha.example/"), _second()
    liar.relay = False
    ex, rec, fees = await _with_second_opinion(primary, liar, SeenStore(), resend_ticks=2)
    primary.reject = (-26, "bad-txns-premature-spend-of-coinbase")

    outcome, said = await tick(ex, rec)
    assert outcome is ExecOutcome.BROADCAST, said
    for left in (1, 0):
        outcome, said = await tick(ex, rec)
        assert outcome is ExecOutcome.DECLINED and f"({left} re-sends left)" in said, said
    assert len(fees.outpoints) == 1

    primary.reject = None
    outcome, said = await tick(ex, rec)
    assert outcome is ExecOutcome.BROADCAST, said
    assert len(fees.outpoints) == 2, "rebuilt on a new fee input after the hold ended"
    rebuilt = primary.broadcasts[-1]
    assert rebuilt != primary.broadcasts[0]
    _one_chain(primary, liar)
    assert _assert_paid_once(primary, fees) == _txid(rebuilt)


async def test_a_held_claim_every_server_refuses_ends_the_hold(tick) -> None:
    primary, second = _OpNode("wss://electrum.alpha.example/"), _second()
    ex, rec, fees = await _with_second_opinion(primary, second, SeenStore())
    primary.reject = (-26, _SCRIPT_FAILED)
    outcome, said = await tick(ex, rec)
    assert outcome is ExecOutcome.BROADCAST, said

    second.mempool.clear()  # evicted
    second.reject = (-26, "the second endpoint's reason")
    outcome, said = await tick(ex, rec)
    assert outcome is ExecOutcome.FAILED and "rebuilding next tick" in said, said

    primary.reject = second.reject = None
    outcome, said = await tick(ex, rec)
    assert outcome is ExecOutcome.BROADCAST, said
    assert len(fees.outpoints) == 2


async def test_a_held_claim_re_send_transport_failure_counts_down(tick) -> None:
    primary, second = _OpNode("wss://electrum.alpha.example/"), _second()
    ex, rec, _fees = await _with_second_opinion(primary, second, SeenStore(), resend_ticks=1)
    primary.reject = (-26, _SCRIPT_FAILED)
    outcome, said = await tick(ex, rec)
    assert outcome is ExecOutcome.BROADCAST, said

    primary.fail = NetworkError("connection reset")
    outcome, said = await tick(ex, rec)
    assert outcome is ExecOutcome.FAILED and "re-send failed (transient)" in said, said
    assert ex._held == {}, "the last re-send ends the hold even when it fails"


@pytest.mark.parametrize("bad", [0, -1, True, 1.5, "10"])
def test_the_re_send_count_must_be_a_positive_int(bad) -> None:
    from pyrxd.gravity.swap_coordinator import MarginPolicy
    from pyrxd.gravity.watch import ClaimExecutor

    with pytest.raises(ValidationError, match="second_opinion_resend_ticks"):
        ClaimExecutor(
            resolve_leg=None,
            claim_status_source=None,
            claim_bytes_source=None,
            policy=MarginPolicy.estimated(),
            network="bcrt",
            second_opinion_resend_ticks=bad,
        )


async def test_a_claim_every_operator_refuses_is_still_retried_and_never_disarmed(tick) -> None:
    primary, second = _OpNode("wss://electrum.alpha.example/"), _second()
    seen = SeenStore()
    ex, rec, fees = await _with_second_opinion(primary, second, seen)
    primary.reject = second.reject = (-26, _SCRIPT_FAILED)

    outcome, said = await tick(ex, rec)
    assert outcome is ExecOutcome.DECLINED, said
    assert "consensus rule (retrying)" in said

    primary.reject = None
    outcome, said = await tick(ex, rec)
    assert outcome is ExecOutcome.BROADCAST, said
    assert len(fees.outpoints) == 2
    claim = primary.broadcasts[-1]
    assert _COVENANT in _spends(claim)


# --------------------------------------------------------------------------- Mythos #947 fix round


class _SlowNode(_OpNode):
    """An ``_OpNode`` whose broadcast waits *delay* seconds first (``None``: no wait; ``inf``: hangs)."""

    def __init__(self, url: str) -> None:
        super().__init__(url)
        self.delay: float | None = None

    async def _call(self, method: str, params: list[Any]) -> Any:
        if method == "blockchain.transaction.broadcast" and self.delay is not None:
            if self.delay == float("inf"):
                await asyncio.Event().wait()
            await asyncio.sleep(self.delay)
        return await super()._call(method, params)


class _Custom:
    """A custom second-opinion client: says its operator, and raises *error* from every call."""

    def __init__(self, key, error: BaseException | None = None) -> None:
        self.source_key = key
        self.error = error
        self.broadcasts: list[bytes] = []

    async def broadcast(self, raw: bytes) -> str:
        self.broadcasts.append(raw)
        if self.error is not None:
            raise self.error
        return _txid(raw)

    async def get_transaction(self, txid: str) -> bytes:  # pragma: no cover - not a read-back case
        raise AssertionError("not a read-back case")


# F1: one host is one operator, whatever key a client on it declares.


def test_a_client_on_the_broadcast_clients_host_is_refused_whatever_key_it_declares() -> None:
    disguised = _Custom(source_key("wss://electrum.alpha.example:50004/", operator="beta-op"))
    assert str(disguised.source_key) != str(_primary().source_key), "a key unequal by value"
    with pytest.raises(ValidationError, match="counted as two sources"):
        RadiantChainIO(_primary()).with_second_opinion((disguised,))
    with pytest.raises(ValidationError, match="counted as two sources"):
        RadiantChainIO(_primary(), second_opinion=(disguised,))


def test_a_declared_operator_on_another_host_is_still_accepted() -> None:
    """Honest path for F1: a declaration on a host of its own is a second opinion."""
    declared = _Custom(source_key("wss://electrum.beta.example/", operator="beta-op"))
    assert RadiantChainIO(_primary()).with_second_opinion((declared,)).second_opinion == (declared,)


# F4: any failure of one client is "did not take it", and a held claim always counts down.


async def test_a_custom_client_that_raises_its_own_error_is_passed_over() -> None:
    primary, third = _primary(), _second("gamma")
    broken = _Custom(source_key("wss://electrum.beta.example/"), RuntimeError("custom client bug"))
    raw = os.urandom(80)
    io = RadiantChainIO(primary).with_second_opinion((broken, third))
    assert await io.broadcast(raw) == _txid(raw), "the next operator is still asked"
    assert broken.broadcasts == [raw]

    alone = RadiantChainIO(_primary()).with_second_opinion((broken,))
    with pytest.raises(PolicyRejection) as info:
        await alone.broadcast(raw)
    assert info.value.reason == _REJECTED and info.value.__context__ is None


async def test_a_read_back_that_raises_its_own_error_is_not_taken() -> None:
    class _BrokenRead(_Custom):
        async def broadcast(self, raw: bytes) -> str:
            raise PolicyRejection("already", code=-27, reason="txn-already-known")

        async def get_transaction(self, txid: str) -> bytes:
            raise RuntimeError("custom client bug")

    io = RadiantChainIO(_primary()).with_second_opinion((_BrokenRead(source_key("wss://electrum.beta.example/")),))
    with pytest.raises(PolicyRejection) as info:
        await io.broadcast(os.urandom(80))
    assert info.value.reason == _REJECTED


async def test_a_held_claim_whose_second_opinion_breaks_ends_the_hold(tick) -> None:
    """The Mythos #947 F4 case: a custom second opinion that starts raising its own error during a
    hold used to skip the count-down, holding the claim until a restart."""
    primary = _OpNode("wss://electrum.alpha.example/")
    custom = _Custom(source_key("wss://electrum.beta.example/"))
    ex, rec, fees = await _armed(primary, SeenStore())
    leg = await ex._resolve_leg("swap-1", rec)
    leg.chain_io = leg.chain_io.with_second_opinion((custom,))
    primary.reject = (-26, _SCRIPT_FAILED)
    outcome, said = await tick(ex, rec)
    assert outcome is ExecOutcome.BROADCAST and ex._held, said

    custom.error = RuntimeError("custom client bug")
    outcome, said = await tick(ex, rec)
    assert outcome is ExecOutcome.FAILED and "rebuilding next tick" in said, said
    assert ex._held == {}

    primary.reject = None
    outcome, said = await tick(ex, rec)
    assert outcome is ExecOutcome.BROADCAST, said
    assert len(fees.outpoints) == 2, "rebuilt once the hold ended"


async def test_a_cancelled_re_send_still_counts_down(tick) -> None:
    """The reconciler's tick watchdog cancels a tick that outruns its budget; that re-send is spent."""
    primary, second = _OpNode("wss://electrum.alpha.example/"), _SlowNode("wss://electrum.beta.example/")
    ex, rec, _fees = await _with_second_opinion(primary, second, SeenStore(), resend_ticks=2)
    primary.reject = (-26, _SCRIPT_FAILED)
    outcome, said = await tick(ex, rec)
    assert outcome is ExecOutcome.BROADCAST, said
    (outpoint,) = ex._held

    second.delay = float("inf")
    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(tick(ex, rec), 0.2)
    assert ex._held[outpoint][1] == 1, "one re-send spent"
    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(tick(ex, rec), 0.2)
    assert ex._held == {}, "the last one ends the hold"


# F5: the whole round runs under one time budget.


async def test_a_hanging_second_opinion_does_not_stop_another_from_taking_it() -> None:
    """The re-review's MEDIUM: asked in turn under one budget, a hanging first client spent it all
    and the next operator was never asked."""
    primary, hung, third = _primary(), _SlowNode("wss://electrum.beta.example/"), _second("gamma")
    hung.delay = float("inf")
    raw = os.urandom(80)
    io = RadiantChainIO(primary, second_opinion=(hung, third), second_opinion_timeout_s=0.5)
    assert await asyncio.wait_for(io.broadcast(raw), 5.0) == _txid(raw)
    assert set(third.mempool) == {_txid(raw)}


async def test_hanging_second_opinions_end_the_round_at_the_budget() -> None:
    primary, hung, third = (
        _primary(),
        _SlowNode("wss://electrum.beta.example/"),
        _SlowNode("wss://electrum.gamma.example/"),
    )
    hung.delay = third.delay = float("inf")
    io = RadiantChainIO(primary, second_opinion=(hung, third), second_opinion_timeout_s=0.1)
    loop = asyncio.get_running_loop()
    began = loop.time()
    with pytest.raises(PolicyRejection) as info:
        # The outer bound only keeps a broken budget from hanging the suite; it is not the subject.
        await asyncio.wait_for(io.broadcast(os.urandom(80)), 5.0)
    took = loop.time() - began
    assert info.value.reason == _REJECTED
    assert 0.1 <= took < 1.0, took


async def test_the_operators_are_asked_at_once_not_in_turn() -> None:
    """Two operators that each answer after 0.25 s fit a 0.4 s round only when asked together."""
    primary = _primary()
    slow1, slow2 = _SlowNode("wss://electrum.beta.example/"), _SlowNode("wss://electrum.gamma.example/")
    slow1.reject = (-26, "the second endpoint's reason")
    slow1.delay = slow2.delay = 0.25
    raw = os.urandom(80)
    io = RadiantChainIO(primary, second_opinion=(slow1, slow2), second_opinion_timeout_s=0.4)
    assert await asyncio.wait_for(io.broadcast(raw), 5.0) == _txid(raw)
    assert set(slow2.mempool) == {_txid(raw)}


async def test_a_slow_second_opinion_inside_the_budget_still_takes_it() -> None:
    """Honest path for F5."""
    primary, slow = _primary(), _SlowNode("wss://electrum.beta.example/")
    slow.delay = 0.05
    raw = os.urandom(80)
    io = RadiantChainIO(primary, second_opinion=(slow,), second_opinion_timeout_s=2.0)
    assert await io.broadcast(raw) == _txid(raw)


def test_the_default_budget_and_with_second_opinion_keeps_it() -> None:
    from pyrxd.gravity.radiant_leg import SECOND_OPINION_TIMEOUT_S

    assert RadiantChainIO(_primary())._second_opinion_timeout_s == SECOND_OPINION_TIMEOUT_S
    io = RadiantChainIO(_primary(), second_opinion_timeout_s=3.0).with_second_opinion((_second(),))
    assert io._second_opinion_timeout_s == 3.0


@pytest.mark.parametrize("bad", [0, -1.0, float("inf"), float("nan"), True, "10"])
def test_the_budget_must_be_a_finite_positive_number(bad) -> None:
    with pytest.raises(ValidationError, match="second_opinion_timeout_s"):
        RadiantChainIO(_primary(), second_opinion_timeout_s=bad)


async def test_a_held_re_send_with_a_pin_mismatch_only_counts_down(tick) -> None:
    primary, second = _OpNode("wss://electrum.alpha.example/"), _second()
    ex, rec, _fees = await _with_second_opinion(primary, second, SeenStore(), resend_ticks=3)
    primary.reject = (-26, _SCRIPT_FAILED)
    outcome, said = await tick(ex, rec)
    assert outcome is ExecOutcome.BROADCAST, said
    (outpoint,) = ex._held

    second.fail = TlsPinMismatchError("pin mismatch")
    outcome, said = await tick(ex, rec)
    assert outcome is ExecOutcome.FAILED and "re-send failed (transient)" in said, said
    assert ex._held[outpoint][1] == 2, "one tick spent; the hold goes on"
