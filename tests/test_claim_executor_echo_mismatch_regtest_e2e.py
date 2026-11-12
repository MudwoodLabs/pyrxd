"""The #789 echo-mismatch re-send, on a real Radiant node behind a real RXinDexer ElectrumX.

``tests/test_claim_executor_echo_mismatch.py`` proves the executor's logic against a modelled
server. Two things only a real stack can settle:

* what the node and ElectrumX answer when the SAME claim bytes are sent again, (a) while the claim
  is in the mempool and (b) after it is mined, and whether ``RadiantChainIO`` maps each to "taken";
* whether the covenant read the executor makes before re-sending (``blockchain.scripthash.listunspent``)
  still shows a covenant whose claim is in the mempool, which decides whether the re-send is reached
  at all.

Measured here, on ``radiant-core`` at :data:`pyrxd.devnet.DEFAULT_RADIANT_VERSION` and
``rxindexer-electrumx:regtest`` (both pinned in the assertions below, verbatim):

* (a) a re-send of a transaction the mempool holds is ACCEPTED: ``sendrawtransaction`` returns the
  txid and ElectrumX answers ``{"result": "<txid>"}``. It is NOT a "txn-already-in-mempool"
  rejection, which the unit tests' modelled server used to answer before this run; the model now
  answers as this stack does. Either reaches the executor as "the broadcast client took it".
* (b) a re-send of a mined transaction is refused, ``-27 transaction already in block chain``, which
  ElectrumX wraps as code 1, ``"the transaction was rejected by network rules.\\n\\ntransaction
  already in block chain\\n[<raw hex>]"``. ``ElectrumXClient`` raises ``PolicyRejection`` and
  ``RadiantChainIO`` maps it to ``_AlreadyKnown``.
* ElectrumX's ``listunspent`` drops an output as soon as a mempool transaction spends it. So when the
  server lied about a claim that DID relay, the next tick reads the covenant as spent and stops
  ("covenant already spent") before the held bytes are re-sent: no new fee input, nothing re-sent.
  The re-send path runs when the claim did not relay (case 2), or under a client whose UTXO read is
  mempool-blind.

The four #789 cases run against the real node, through a real ``ClaimExecutor`` →
``RadiantCovenantLeg`` → ``RadiantChainIO`` → ``ElectrumXClient`` over ws to ElectrumX. The only
fake on the Radiant side is :class:`_LyingClient`, which overrides ``_call`` for
``blockchain.transaction.broadcast`` only, and only to lie about (or drop) the broadcast. The BTC claim
the executor scrapes ``p`` from is a real one, built by the BTC HTLC leg against fakes, as in the
unit test.

1. The node takes the claim and the wrapper echoes another txid: no rebuild, no new fee input; mined,
   one claim and one fee input are spent.
2. The wrapper drops the claim and lies: the next tick re-sends the same bytes, the node takes them
   and the claim is marked seen.
3. A genuine transport failure: nothing is held and the next tick rebuilds on a new fee input.
4. A real node rejection (a fee input signed with the wrong key, so its P2PKH script fails): it
   reaches the executor as ``PolicyRejection``, is paged as a consensus rejection, the claim is not
   marked seen, and the next tick lands a claim on a good fee input.

OPERATOR-RUN, not in ``task test-regtest`` or ``.github/workflows/integration.yml``: it needs the
``rxindexer-electrumx:regtest`` image, which no workflow builds and ``pyrxd regtest setup`` does not
provide, on top of the radiant-core image. Opt-in with ``RADIANT_REGTEST=1``; skips when docker or
either image is absent. Its own docker network and container names; REGTEST ONLY; every key comes
from ``PrivateKey()`` / ``generate_keypair``.

Run::

    RADIANT_REGTEST=1 pytest -o "addopts=" -m integration -s tests/test_claim_executor_echo_mismatch_regtest_e2e.py
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import hashlib
import logging
import os
import shutil
import subprocess
import time
from typing import Any

import pytest
from test_htlc_regtest_e2e import _IMAGE, _pay_to_spk, _RegtestNode

from pyrxd.btc_wallet import taproot as t
from pyrxd.btc_wallet.htlc_leg import BitcoinTaprootLeg
from pyrxd.btc_wallet.keys import generate_keypair
from pyrxd.btc_wallet.payment import BtcUtxo
from pyrxd.btc_wallet.taproot import btc_txid_from_raw
from pyrxd.gravity.htlc_covenant import build_htlc_covenant_rxd
from pyrxd.gravity.htlc_spend import FeeInput
from pyrxd.gravity.radiant_leg import RadiantChainIO, RadiantCovenantLeg, SeenStore, _AlreadyKnown
from pyrxd.gravity.swap_coordinator import MarginPolicy
from pyrxd.gravity.swap_state import NegotiatedTerms, SwapRecord, SwapState
from pyrxd.gravity.watch import ClaimExecutor, ExecOutcome
from pyrxd.hash import hash256
from pyrxd.keys import PrivateKey
from pyrxd.network.electrumx import ElectrumXClient
from pyrxd.security.errors import NetworkError, PolicyRejection
from pyrxd.security.types import Hex20
from pyrxd.transaction.transaction import Transaction

from test_watch_claim_executor import (  # isort: skip
    _claim_decision,
    _FakeBytesSource,
    _FakeFundingReader,
    _FakeStatusSource,
    _RecordingBroadcaster,
    _resolver,
    _xonly,
)

pytestmark = pytest.mark.integration

_NETWORK = "claim-echo-mismatch-regtest-net"
_CONTAINER = "claim-echo-mismatch-regtest"
_ELECTRUMX = "claim-echo-mismatch-regtest-electrumx"
_ELECTRUMX_IMAGE = "rxindexer-electrumx:regtest"
#: The RPC port radiantd listens on in regtest (no ``-rpcport`` is passed).
_RPC_PORT = 17443
_LIE = "ee" * 32
_AMOUNT = 1_000_000
#: The whole fee input is the miner fee (``FeeInput``); 0.1 RXD clears a claim at the mainnet floor.
_FEE = 10_000_000


def _docker(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=120)


def _txid(raw: bytes) -> str:
    return hash256(raw)[::-1].hex()


def _p2pkh(key: PrivateKey) -> bytes:
    return b"\x76\xa9\x14" + bytes(Hex20(key.public_key().hash160())) + b"\x88\xac"


class _Stack:
    """The node, and an ElectrumX in front of it on a docker network of their own."""

    def __init__(self) -> None:
        # The ElectrumX reaches the node by container name, which Radiant-Core's DNS-rebinding check
        # refuses ("rejected: disallowed Host header", 403) unless the name is allowed.
        self.node = _RegtestNode(container=_CONTAINER, extra_args=(f"-rpcallowhost={_CONTAINER}",))
        self.url = ""

    def start(self) -> None:
        self.stop()
        made = _docker("network", "create", _NETWORK)
        if made.returncode != 0:
            raise RuntimeError(f"docker network create failed: {made.stderr.strip()}")
        self.node.start()
        joined = _docker("network", "connect", _NETWORK, _CONTAINER)
        if joined.returncode != 0:
            raise RuntimeError(f"docker network connect failed: {joined.stderr.strip()}")
        up = _docker(
            "run", "-d", "--name", _ELECTRUMX, "--network", _NETWORK,
            "--tmpfs", "/data:exec,mode=1777",
            # An ephemeral loopback port: never a fixed one another stack may hold.
            "-p", "127.0.0.1::50011",
            "-e", "NET=regtest", "-e", "COIN=Radiant", "-e", "DB_ENGINE=rocksdb",
            "-e", "DB_DIRECTORY=/data", "-e", "SSL_CERTFILE=/data/s.crt", "-e", "SSL_KEYFILE=/data/s.key",
            "-e", f"DAEMON_URL=http://{self.node.user}:{self.node.password}@{_CONTAINER}:{_RPC_PORT}/",
            "-e", "SERVICES=tcp://0.0.0.0:50010,ws://0.0.0.0:50011",
            "-e", "REST_API_ENABLED=0", "-e", "CACHE_MB=200",
            _ELECTRUMX_IMAGE,
        )  # fmt: skip
        if up.returncode != 0:
            raise RuntimeError(f"failed to start ElectrumX: {up.stderr.strip()}")
        port = _docker("port", _ELECTRUMX, "50011").stdout.strip().rsplit(":", 1)[-1]
        assert port.isdigit(), f"ElectrumX published no port: {port!r}"
        self.url = f"ws://127.0.0.1:{port}/"
        self.wait_synced()

    def stop(self) -> None:
        _docker("rm", "-f", _ELECTRUMX)
        self.node.stop()
        _docker("network", "rm", _NETWORK)

    def wait_synced(self, timeout: float = 90.0) -> None:
        """Until ElectrumX's tip is the node's (a fresh ElectrumX may need a while to serve at all)."""
        want = int(self.node.cli("getblockcount"))  # type: ignore[call-overload]
        deadline = time.monotonic() + timeout
        last: object = None
        while time.monotonic() < deadline:
            try:
                last = _run_apart(_tip(self.url))
                if last == want:
                    return
            except Exception as exc:  # not serving yet
                last = exc
            time.sleep(0.5)
        raise RuntimeError(f"ElectrumX did not reach the node's tip {want}: {last!r}")

    def mine(self, n: int = 1) -> None:
        self.node.mine(n)
        self.wait_synced()


def _run_apart(coro: Any) -> Any:
    """Run *coro* on its own loop in another thread: the tests that wait on ElectrumX are async."""
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result()


async def _tip(url: str) -> int:
    c = ElectrumXClient([url], allow_insecure=True)
    try:
        return int(await c.get_tip_height())
    finally:
        await c.close()


@pytest.fixture(scope="module")
def stack():
    if not os.environ.get("RADIANT_REGTEST"):
        pytest.skip("RADIANT_REGTEST not set (opt-in for the live regtest e2e)")
    if shutil.which("docker") is None:
        pytest.skip("docker not available")
    for image in (_IMAGE, _ELECTRUMX_IMAGE):
        if _docker("image", "inspect", image).returncode != 0:
            pytest.skip(f"{image} image not available")
    s = _Stack()
    s.start()
    try:
        yield s
    finally:
        s.stop()


class _LyingClient(ElectrumXClient):
    """A real ``ElectrumXClient`` over ws to the real ElectrumX. Only the broadcast reply can lie.

    ``mode``: ``"honest"`` forwards; ``"lie"`` forwards, then answers :data:`_LIE`; ``"drop"`` sends
    nothing and answers :data:`_LIE`; ``"down"`` sends nothing and fails in transport. Every other
    method goes to the server untouched. ``replies`` records what the server really answered.
    """

    def __init__(self, url: str) -> None:
        super().__init__([url], allow_insecure=True)
        self.mode = "honest"
        self.sent: list[bytes] = []
        self.replies: list[str] = []

    async def _call(self, method: str, params: list[Any]) -> Any:
        if method != "blockchain.transaction.broadcast":
            return await super()._call(method, params)
        self.sent.append(bytes.fromhex(params[0]))
        if self.mode == "down":
            raise NetworkError("connection reset by peer")
        if self.mode == "drop":
            return _LIE
        try:
            result = await super()._call(method, params)
        except Exception as exc:
            self.replies.append(f"raised {type(exc).__name__}: {getattr(exc, 'reason', exc)}")
            raise
        self.replies.append(f"result {result}")
        return _LIE if self.mode == "lie" else result


class _FundedFees:
    """Real fee UTXOs on the node, handed out once each like ``CappedFeeWalletSource``.

    ``wrong_key_next`` makes the next one carry a key that does not own it, so the claim spending it
    fails its P2PKH script: a genuine node rejection.
    """

    def __init__(self, stack: _Stack, n: int) -> None:
        self._stack = stack
        self._pool: list[tuple[str, PrivateKey]] = []
        for _ in range(n):
            key = PrivateKey()
            self._pool.append((_pay_to_spk(stack.node, _p2pkh(key), _FEE), key))
        stack.wait_synced()
        self.outpoints: list[str] = []
        self.wrong_key_next = False

    def next_fee_input(self) -> FeeInput:
        txid, key = self._pool.pop(0)
        self.outpoints.append(f"{txid}:0")
        wif = PrivateKey().wif() if self.wrong_key_next else key.wif()
        self.wrong_key_next = False
        return FeeInput(txid=txid, vout=0, value=_FEE, scriptpubkey=_p2pkh(key), wif=wif)


class _Armed:
    def __init__(self, ex: ClaimExecutor, rec: SwapRecord, fees: _FundedFees, client: _LyingClient, seen: SeenStore):
        self.ex, self.rec, self.fees, self.client, self.seen = ex, rec, fees, client, seen
        self.covenant = str(rec.radiant_covenant_outpoint)


async def _armed(stack: _Stack, *, fee_inputs: int = 3) -> _Armed:
    """A funded covenant on the node and a ClaimExecutor wired to it through the real stack."""
    taker_kp, maker_kp = generate_keypair("bcrt"), generate_keypair("bcrt")
    taker_pkh = bytes(Hex20(PrivateKey().public_key().hash160()))
    maker_pkh = bytes(Hex20(PrivateKey().public_key().hash160()))
    p = os.urandom(32)
    h = hashlib.sha256(p).digest()
    cov = build_htlc_covenant_rxd(amount=_AMOUNT, taker_pkh=taker_pkh, maker_pkh=maker_pkh, hashlock=h, refund_csv=144)
    cov_txid = _pay_to_spk(stack.node, cov.funded_spk, _AMOUNT)
    fees = _FundedFees(stack, fee_inputs)
    terms = NegotiatedTerms(
        hashlock=h,
        btc_sats=100_000,
        radiant_amount=_AMOUNT,
        t_btc=t.Timelock(72, t.TimeUnit.BLOCKS),
        t_rxd=t.Timelock(144, t.TimeUnit.BLOCKS),
        asset_variant="rxd",
        genesis_ref=b"",
        taker_dest_hash=cov.expected_taker_hash,
        maker_dest_hash=cov.expected_maker_hash,
        btc_claim_pubkey_xonly=_xonly(maker_kp),
        btc_refund_pubkey_xonly=_xonly(taker_kp),
    )
    bc = _RecordingBroadcaster()
    btc_leg = BitcoinTaprootLeg(
        network="bcrt",
        taker_keypair=taker_kp,
        funding_utxo=BtcUtxo(txid="ab" * 32, vout=0, value=200_000),
        maker_claim_pubkey_xonly=_xonly(maker_kp),
        broadcaster=bc,
        funding_reader=_FakeFundingReader(),
        refund_to_scriptpubkey=b"\x00\x14" + os.urandom(20),
        claim_to_scriptpubkey=b"\x00\x14" + os.urandom(20),
        fee_sats=500,
        min_confirmations=1,
        maker_claim_privkey=maker_kp._privkey.unsafe_raw_bytes(),
    )
    locator = btc_leg._htlc(terms).with_funding(t.BtcOutpoint("cd" * 32, 0), terms.btc_sats)
    await btc_leg.claim(locator, p)
    raw_claim = bc.raw_seen[0]
    claim_txid = btc_txid_from_raw(raw_claim)

    client = _LyingClient(stack.url)
    leg = RadiantCovenantLeg(
        network="bcrt", taker_pkh=taker_pkh, maker_pkh=maker_pkh, chain_io=RadiantChainIO(client), fee_source=fees
    )
    seen = SeenStore()
    ex = ClaimExecutor(
        resolve_leg=_resolver(leg),
        claim_status_source=_FakeStatusSource(claim_txid=claim_txid),
        claim_bytes_source=_FakeBytesSource({claim_txid: raw_claim}),
        policy=MarginPolicy.estimated(),
        network="bcrt",
        seen_store=seen,
    )
    rec = SwapRecord(
        state=SwapState.SECRET_REVEALED,
        terms=terms,
        counterchain_locator=locator,
        radiant_covenant_outpoint=f"{cov_txid}:0",
    )
    return _Armed(ex, rec, fees, client, seen)


@pytest.fixture
def tick(caplog):
    """One reconciler tick: ``(outcome, the reason the executor logged)``."""

    async def _tick(a: _Armed):
        caplog.clear()
        with caplog.at_level(logging.INFO, logger="pyrxd.gravity.watch.claim_executor"):
            outcome = await a.ex.execute("swap-1", a.rec, _claim_decision())
        said = [r.getMessage() for r in caplog.records if r.name == "pyrxd.gravity.watch.claim_executor"]
        return outcome, " | ".join(said)

    return _tick


def _in_mempool(stack: _Stack, txid: str) -> bool:
    return txid in stack.node.cli("getrawmempool")  # type: ignore[operator]


def _wait_electrumx_mempool(stack: _Stack, outpoint: str, timeout: float = 30.0) -> None:
    """Until ElectrumX no longer lists *outpoint* as unspent: its mempool view lags the node's."""
    txid, vout = outpoint.split(":")
    spk = bytes.fromhex(stack.node.cli("gettxout", txid, vout, "false")["scriptPubKey"]["hex"])  # type: ignore[index]
    sh = hashlib.sha256(spk).digest()[::-1]
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        utxos = _run_apart(_utxos(stack.url, sh))
        if f"{txid}:{vout}" not in {f"{u.tx_hash}:{u.tx_pos}" for u in utxos}:
            return
        time.sleep(0.5)
    raise AssertionError(f"ElectrumX still lists {outpoint} unspent {timeout}s after the node's mempool spent it")


async def _utxos(url: str, sh: bytes):
    c = ElectrumXClient([url], allow_insecure=True)
    try:
        return await c.get_utxos(sh)
    finally:
        await c.close()


def _assert_paid_once(stack: _Stack, a: _Armed) -> str:
    """After mining: the covenant is spent once, by a confirmed claim, and the only dispensed fee
    input spent is that claim's own. Returns the claim's txid."""
    txid, vout = a.covenant.split(":")
    assert stack.node.cli("gettxout", txid, vout, "true") in ("", None), "the covenant is spent"
    assert stack.node.cli("getrawmempool") == [], "nothing left in the mempool"
    spent = [o for o in a.fees.outpoints if stack.node.cli("gettxout", *o.split(":"), "true") in ("", None)]
    assert len(spent) == 1, f"exactly one fee input committed, got {spent} of {a.fees.outpoints}"
    claims = [
        raw
        for raw in a.client.sent
        if (tx := Transaction.from_hex(raw)) is not None
        and {f"{i.source_txid}:{i.source_output_index}" for i in tx.inputs} == {a.covenant, spent[0]}
    ]
    assert claims, "the confirmed claim is one this executor sent"
    claim_txid = _txid(claims[0])
    assert int(stack.node.cli("getrawtransaction", claim_txid, "true")["confirmations"]) >= 1  # type: ignore[index]
    return claim_txid


# --------------------------------------------------------------------------- the node's own replies


async def test_what_the_stack_answers_a_re_send_in_the_mempool_and_after_mining(stack) -> None:
    """(a) and (b), recorded verbatim, through ElectrumX and straight to the node."""
    a = await _armed(stack, fee_inputs=1)
    raw = await _one_claim(a)
    local = _txid(raw)
    assert _in_mempool(stack, local)

    # (a) In the mempool: accepted, the txid back, at every layer.
    node_reply = stack.node.cli("sendrawtransaction", raw.hex())
    assert node_reply == local, f"radiant-core answered a mempool re-send with {node_reply!r}"
    a.client.mode = "honest"
    assert await RadiantChainIO(a.client).broadcast(raw) == local
    assert a.client.replies[-1] == f"result {local}", a.client.replies[-1]
    print(f"\n[re-send, in mempool] node sendrawtransaction -> {node_reply!r}; ElectrumX -> {a.client.replies[-1]!r}")

    # (b) Mined: refused as already in the chain, which RadiantChainIO reads as "already known".
    stack.mine(1)
    with pytest.raises(RuntimeError) as node_err:
        stack.node.cli("sendrawtransaction", raw.hex())
    assert "transaction already in block chain" in str(node_err.value), node_err.value
    with pytest.raises(PolicyRejection) as direct:
        await ElectrumXClient.broadcast(a.client, raw)
    assert direct.value.code == 1 and "transaction already in block chain" in (direct.value.reason or "")
    with pytest.raises(_AlreadyKnown):
        await RadiantChainIO(a.client).broadcast(raw)
    print(f"[re-send, mined] node -> {str(node_err.value)!r}; ElectrumX -> {a.client.replies[-1]!r}")
    await a.client.close()


async def _one_claim(a: _Armed) -> bytes:
    """One honest claim through the executor; returns the bytes it sent."""
    outcome = await a.ex.execute("swap-1", a.rec, _claim_decision())
    assert outcome is ExecOutcome.BROADCAST, outcome
    return a.client.sent[-1]


# --------------------------------------------------------------------------- the four #789 cases


async def test_1_a_lie_about_a_relayed_claim_neither_rebuilds_nor_spends_a_new_fee_input(stack, tick) -> None:
    a = await _armed(stack)
    a.client.mode = "lie"
    outcome, reason = await tick(a)
    assert outcome is ExecOutcome.FAILED and "re-sending the same bytes" in reason, reason
    first = a.client.sent[0]
    assert _in_mempool(stack, _txid(first)), "the node took the claim the server lied about"
    assert set(a.ex._held) == {a.covenant}
    assert not a.seen.has_seen(f"claim:{a.covenant}".encode())

    # ElectrumX now lists the covenant spent, so the next tick stops at the covenant read: the held
    # bytes are never re-sent, and no fee input is dispensed for a rebuild.
    _wait_electrumx_mempool(stack, a.covenant)
    a.client.mode = "honest"
    outcome, reason = await tick(a)
    assert outcome is ExecOutcome.DECLINED and "already spent" in reason, reason
    assert a.client.sent == [first], "nothing re-sent or rebuilt"
    assert len(a.fees.outpoints) == 1

    stack.mine(1)
    outcome, reason = await tick(a)
    assert outcome is ExecOutcome.DECLINED and "already spent" in reason, reason
    assert _assert_paid_once(stack, a) == _txid(first)
    await a.client.close()


async def test_2_a_lie_about_a_dropped_claim_is_re_sent_and_the_same_bytes_land(stack, tick) -> None:
    a = await _armed(stack)
    a.client.mode = "drop"
    outcome, reason = await tick(a)
    assert outcome is ExecOutcome.FAILED and "re-sending the same bytes" in reason, reason
    first = a.client.sent[0]
    assert not _in_mempool(stack, _txid(first))

    a.client.mode = "honest"
    outcome, reason = await tick(a)
    assert outcome is ExecOutcome.DECLINED and "now taken by the broadcast client" in reason, reason
    assert a.client.sent == [first, first], "the same bytes, re-sent"
    assert a.client.replies == [f"result {_txid(first)}"], a.client.replies
    assert len(a.fees.outpoints) == 1, "no fee input dispensed for a rebuild"
    assert a.seen.has_seen(f"claim:{a.covenant}".encode()) and a.ex._held == {}
    assert _in_mempool(stack, _txid(first))

    stack.mine(1)
    outcome, reason = await tick(a)
    assert outcome is ExecOutcome.DECLINED, reason
    assert _assert_paid_once(stack, a) == _txid(first)
    await a.client.close()


async def test_3_a_genuine_transport_failure_rebuilds_on_a_new_fee_input(stack, tick) -> None:
    a = await _armed(stack)
    a.client.mode = "down"
    outcome, reason = await tick(a)
    assert outcome is ExecOutcome.FAILED and "claim broadcast failed" in reason, reason
    assert "echo mismatch" not in reason and a.ex._held == {}

    a.client.mode = "honest"
    outcome, reason = await tick(a)
    assert outcome is ExecOutcome.BROADCAST, reason
    assert len(a.fees.outpoints) == 2 and a.client.sent[1] != a.client.sent[0]
    stack.mine(1)
    assert _assert_paid_once(stack, a) == _txid(a.client.sent[1])
    await a.client.close()


async def test_4_a_real_node_rejection_reaches_the_executor_and_never_disarms_the_claim(stack, tick) -> None:
    a = await _armed(stack)
    a.fees.wrong_key_next = True
    outcome, reason = await tick(a)
    assert outcome is ExecOutcome.DECLINED and "consensus rule (retrying)" in reason, reason
    assert len(a.client.replies) == 1 and a.client.replies[0].startswith("raised "), a.client.replies
    assert "mandatory-script-verify-flag-failed" in a.client.replies[0], a.client.replies[0]
    print(f"\n[node rejection] ElectrumX -> {a.client.replies[0][:300]!r}")
    assert not a.seen.has_seen(f"claim:{a.covenant}".encode()), "a rejection never disarms the claim"
    assert a.ex._held == {}
    assert stack.node.cli("getrawmempool") == []

    outcome, reason = await tick(a)
    assert outcome is ExecOutcome.BROADCAST, reason
    assert len(a.fees.outpoints) == 2
    stack.mine(1)
    assert _assert_paid_once(stack, a) == _txid(a.client.sent[1])
    await a.client.close()


def test_the_node_is_regtest_at_the_mainnet_floor(stack) -> None:
    assert stack.node.cli("getblockchaininfo")["chain"] == "regtest"  # type: ignore[index]
    assert stack.node.relay_rate() == 10_000, "photons per byte: mainnet's 0.10 RXD/kB"
