"""A broadcast echo mismatch on the autonomous claim is retried by REBUILDING the claim — and that
cannot pay twice (#780, #786).

``ElectrumXClient.broadcast`` raises ``BroadcastEchoMismatch`` when the server's reply names some
other txid. ``RadiantChainIO.broadcast`` wraps every client exception except a node rejection as
``NetworkError``, so ``ClaimExecutor`` reads the mismatch as a transient FAILED and, on a later tick, calls
``claim_asset`` again: a NEW claim with a freshly dispensed fee input. That is safe because:

* the covenant output is spendable once, and every claim pays the same fixed destination, so at
  most one claim confirms and the asset moves once;
* a rebuilt claim's fee input is committed only if THAT claim confirms. A claim that conflicts with
  one already in the mempool is refused, and its fee input stays unspent. That refusal is a node
  rejection (``PolicyRejection``), and the executor must read it as transient, not as a permanent
  verdict that marks the claim seen: the relayed claim it conflicts with may still be evicted.

Everything here is production code except the SERVER: the executor drives a real
``RadiantCovenantLeg`` over a real ``RadiantChainIO`` over a real ``ElectrumXClient`` whose ``_call``
(the JSON-RPC wire) is answered by :class:`_Node`, which models a mempool that refuses a second
spend of an outpoint and a block that confirms the mempool. The BTC claim the executor scrapes ``p``
from is a real one, built by the BTC HTLC leg.
"""

from __future__ import annotations

import hashlib
import logging
import os
from typing import Any

import pytest

from pyrxd.btc_wallet import taproot as t
from pyrxd.btc_wallet.htlc_leg import BitcoinTaprootLeg
from pyrxd.btc_wallet.keys import generate_keypair
from pyrxd.btc_wallet.payment import BtcUtxo
from pyrxd.btc_wallet.taproot import btc_txid_from_raw
from pyrxd.gravity.htlc_covenant import build_htlc_covenant_rxd
from pyrxd.gravity.htlc_spend import FeeInput
from pyrxd.gravity.radiant_leg import RadiantChainIO, RadiantCovenantLeg
from pyrxd.gravity.swap_coordinator import MarginPolicy
from pyrxd.gravity.swap_state import NegotiatedTerms, SwapRecord, SwapState
from pyrxd.gravity.watch import ClaimExecutor, ExecOutcome
from pyrxd.hash import hash256
from pyrxd.keys import PrivateKey
from pyrxd.network.electrumx import ElectrumXClient, _rpc_error
from pyrxd.security.errors import BroadcastEchoMismatch, NetworkError, PolicyRejection
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

_AMOUNT = 100_000
_COVENANT_TXID = "cd" * 32
_COVENANT = f"{_COVENANT_TXID}:0"
#: A well-formed txid for some OTHER transaction: what a lying server echoes.
_LIE = "ee" * 32


def _txid(raw: bytes) -> str:
    return hash256(raw)[::-1].hex()


def _spends(raw: bytes) -> set[str]:
    """The outpoints *raw* spends; empty for bytes that are not a transaction."""
    tx = Transaction.from_hex(raw)
    if tx is None:
        return set()
    return {f"{i.source_txid}:{i.source_output_index}" for i in tx.inputs}


def _wrapped(node_reason: str, raw_hex: str) -> str:
    """How ElectrumX words a failed broadcast (code 1): Radiant-Core/ElectrumX and
    Radiant-Core/RXinDexer, electrumx/server/session.py, read 2026-10-31."""
    return f"the transaction was rejected by network rules.\n\n{node_reason}\n[{raw_hex}]"


class _Node(ElectrumXClient):
    """A real ``ElectrumXClient``; only ``_call`` (the wire) and ``_ensure_connected`` are faked.

    A mempool that refuses a transaction spending an outpoint another mempool or confirmed
    transaction already spends, and :meth:`mine`, which confirms the mempool. ``listunspent`` is
    mempool-BLIND, the worst case for the executor: the covenant reads unspent until a claim is
    mined. ``lie`` echoes :data:`_LIE`; ``relay`` False drops the transaction instead of admitting it.
    """

    def __init__(self) -> None:
        super().__init__(["wss://fake.invalid/"])
        self.relay, self.lie = True, False
        #: ``(code, node reason)`` to refuse every broadcast with, when set. Code 1 is ElectrumX's
        #: wrapper around the node's reason (:func:`_wrapped`); any other code carries it bare.
        self.reject: tuple[int, str] | None = None
        self.mempool: dict[str, bytes] = {}
        self.confirmed: dict[str, bytes] = {}
        self.broadcasts: list[bytes] = []

    async def _ensure_connected(self) -> None:
        return None

    def _spent(self) -> set[str]:
        return {o for raw in (*self.mempool.values(), *self.confirmed.values()) for o in _spends(raw)}

    def mine(self) -> None:
        self.confirmed.update(self.mempool)
        self.mempool.clear()

    async def _call(self, method: str, params: list[Any]) -> Any:
        if method == "blockchain.scripthash.listunspent":
            confirmed_spent = {o for raw in self.confirmed.values() for o in _spends(raw)}
            if _COVENANT in confirmed_spent:
                return []
            return [{"tx_hash": _COVENANT_TXID, "tx_pos": 0, "value": _AMOUNT, "height": 100}]
        if method == "blockchain.transaction.get":
            if params[0] == _COVENANT_TXID:
                return {"txid": params[0], "confirmations": 1}
            raise NetworkError("No such mempool or blockchain transaction")
        if method == "blockchain.transaction.broadcast":
            raw = bytes.fromhex(params[0])
            self.broadcasts.append(raw)
            # Errors go through the client's own JSON-RPC error mapping, as a real reply would.
            if self.reject is not None:
                code, reason = self.reject
                raise _rpc_error(code, _wrapped(reason, params[0]) if code == 1 else reason)
            if _spends(raw) & self._spent():
                raise _rpc_error(1, _wrapped("txn-mempool-conflict (code 18)", params[0]))
            if self.relay:
                self.mempool[_txid(raw)] = raw
            return _LIE if self.lie else _txid(raw)
        raise AssertionError(f"unexpected RPC {method} {params}")


class _CountingFeeSource:
    """Dispense-once, like ``CappedFeeWalletSource``: every call hands out a NEW fee input."""

    def __init__(self) -> None:
        self.key = PrivateKey()
        self.outpoints: list[str] = []

    def next_fee_input(self) -> FeeInput:
        txid = os.urandom(32).hex()
        self.outpoints.append(f"{txid}:0")
        pkh = bytes(Hex20(self.key.public_key().hash160()))
        return FeeInput(
            txid=txid,
            vout=0,
            value=10_000_000,
            scriptpubkey=b"\x76\xa9\x14" + pkh + b"\x88\xac",
            wif=self.key.wif(),
        )


async def _armed(node: _Node, seen_store: Any = None):
    """A ClaimExecutor wired to a real leg over *node*, plus the record and fee source."""
    taker_kp, maker_kp = generate_keypair("bcrt"), generate_keypair("bcrt")
    taker_pkh, maker_pkh = os.urandom(20), os.urandom(20)
    p = os.urandom(32)
    h = hashlib.sha256(p).digest()
    cov = build_htlc_covenant_rxd(amount=_AMOUNT, taker_pkh=taker_pkh, maker_pkh=maker_pkh, hashlock=h, refund_csv=144)
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
        refund_to_scriptpubkey=b"\x00\x14" + b"\x33" * 20,
        claim_to_scriptpubkey=b"\x00\x14" + b"\x44" * 20,
        fee_sats=500,
        min_confirmations=1,
        maker_claim_privkey=maker_kp._privkey.unsafe_raw_bytes(),
    )
    locator = btc_leg._htlc(terms).with_funding(t.BtcOutpoint("cd" * 32, 0), terms.btc_sats)
    await btc_leg.claim(locator, p)
    raw_claim = bc.raw_seen[0]
    claim_txid = btc_txid_from_raw(raw_claim)

    fees = _CountingFeeSource()
    leg = RadiantCovenantLeg(
        network="bcrt", taker_pkh=taker_pkh, maker_pkh=maker_pkh, chain_io=RadiantChainIO(node), fee_source=fees
    )
    ex = ClaimExecutor(
        resolve_leg=_resolver(leg),
        claim_status_source=_FakeStatusSource(claim_txid=claim_txid),
        claim_bytes_source=_FakeBytesSource({claim_txid: raw_claim}),
        policy=MarginPolicy.estimated(),
        network="bcrt",
        seen_store=seen_store,
    )
    rec = SwapRecord(
        state=SwapState.SECRET_REVEALED,
        terms=terms,
        counterchain_locator=locator,
        radiant_covenant_outpoint=_COVENANT,
    )
    return ex, rec, fees


@pytest.fixture
def tick(caplog):
    """One reconciler tick through ``ClaimExecutor.execute``: ``(outcome, the reason it logged)``."""

    async def _tick(ex: ClaimExecutor, rec: SwapRecord):
        caplog.clear()
        with caplog.at_level(logging.INFO, logger="pyrxd.gravity.watch.claim_executor"):
            outcome = await ex.execute("swap-1", rec, _claim_decision())
        said = [r.getMessage() for r in caplog.records if r.name == "pyrxd.gravity.watch.claim_executor"]
        return outcome, " | ".join(said)

    return _tick


def _assert_paid_once(node: _Node, fees: _CountingFeeSource) -> str:
    """The chain after the dust settles: ONE claim confirmed, the covenant spent once, and no fee
    input committed except the confirmed claim's own. Returns that claim's txid."""
    claims = [raw for raw in node.confirmed.values() if _COVENANT in _spends(raw)]
    assert len(claims) == 1, "exactly one claim confirmed"
    committed_fees = {o for raw in node.confirmed.values() for o in _spends(raw)} & set(fees.outpoints)
    assert committed_fees == _spends(claims[0]) - {_COVENANT}, "only the confirmed claim's fee input is spent"
    assert len(committed_fees) == 1
    return _txid(claims[0])


async def test_the_mismatch_reaches_the_executor_as_a_network_error() -> None:
    """The premise of the retry: ``RadiantChainIO`` wraps the mismatch, and the local txid survives."""
    node = _Node()
    node.lie = True
    raw = os.urandom(80)
    with pytest.raises(NetworkError) as info:
        await RadiantChainIO(node).broadcast(raw)
    assert isinstance(info.value.__cause__, BroadcastEchoMismatch)
    assert _txid(raw) in str(info.value), "the reason names the transaction actually sent"


async def test_a_lie_about_a_relayed_claim_is_rebuilt_and_cannot_pay_twice(tick) -> None:
    node = _Node()
    ex, rec, fees = await _armed(node)
    node.lie = True  # admits the claim to the mempool, then lies about it

    outcome, reason = await tick(ex, rec)
    assert outcome is ExecOutcome.FAILED
    first = node.broadcasts[0]
    assert _txid(first) in reason and "claim broadcast failed" in reason
    assert set(node.mempool) == {_txid(first)}

    # The next tick rebuilds: a new fee input, a different claim over the SAME covenant output.
    node.lie = False
    outcome, reason = await tick(ex, rec)
    assert outcome is ExecOutcome.FAILED, reason
    assert len(fees.outpoints) == 2, "rebuilt with a freshly dispensed fee input"
    second = node.broadcasts[1]
    assert second != first and _COVENANT in _spends(first) & _spends(second)
    assert set(node.mempool) == {_txid(first)}, "the rebuild conflicts with the relayed claim and is refused"

    node.mine()
    outcome, reason = await tick(ex, rec)
    assert outcome is ExecOutcome.DECLINED, reason
    assert "already spent" in reason
    assert len(node.broadcasts) == 2, "a spent covenant sends nothing"
    assert _assert_paid_once(node, fees) == _txid(first)


async def test_a_lie_about_a_dropped_claim_is_rebuilt_and_the_rebuild_lands(tick) -> None:
    node = _Node()
    ex, rec, fees = await _armed(node)
    node.lie, node.relay = True, False  # drops the claim AND lies

    outcome, _ = await tick(ex, rec)
    assert outcome is ExecOutcome.FAILED
    assert node.mempool == {}

    node.lie, node.relay = False, True
    outcome, reason = await tick(ex, rec)
    assert outcome is ExecOutcome.BROADCAST, reason
    rebuilt = node.broadcasts[1]
    assert rebuilt != node.broadcasts[0] and len(fees.outpoints) == 2

    node.mine()
    outcome, _ = await tick(ex, rec)
    assert outcome is ExecOutcome.DECLINED
    assert _assert_paid_once(node, fees) == _txid(rebuilt)
    assert fees.outpoints[0] not in {o for raw in node.confirmed.values() for o in _spends(raw)}, (
        "the dropped claim's fee input was never committed"
    )


async def test_an_honest_broadcast_is_unchanged(tick) -> None:
    node = _Node()
    ex, rec, fees = await _armed(node)
    outcome, reason = await tick(ex, rec)
    assert outcome is ExecOutcome.BROADCAST, reason
    assert len(fees.outpoints) == 1 and len(node.broadcasts) == 1
    node.mine()
    assert _assert_paid_once(node, fees) == _txid(node.broadcasts[0])


# --------------------------------------------------------------------------- node rejections
#
# A node rejection reaches ClaimExecutor as PolicyRejection through the real RadiantChainIO. A
# permanent one (a script or policy verdict on the claim) is marked seen so the executor stops
# re-carving fee inputs for a claim the node will never take; a passing one (a conflict, a missing
# input) is retried like any failure, because marking it seen would disarm the claim for good.

#: How Radiant-Core words a claim whose script fails (src/node/transaction.cpp: -26 with the state).
_SCRIPT_FAILED = "mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation) (code 16)"


@pytest.mark.parametrize("code", [1, -26], ids=["through-electrumx", "bare"])
async def test_a_node_rejection_reaches_the_executor_as_itself(code) -> None:
    node = _Node()
    node.reject = (code, _SCRIPT_FAILED)
    raw = os.urandom(80)
    with pytest.raises(PolicyRejection) as info:
        await RadiantChainIO(node).broadcast(raw)
    assert type(info.value) is PolicyRejection and info.value.code == code
    assert "mandatory-script-verify-flag-failed" in (info.value.reason or ""), "the node's reason survives"
    assert raw.hex()[:20] not in str(info.value) and "[" not in str(info.value), "ElectrumX's raw-tx line is dropped"


async def test_already_known_is_still_the_idempotent_sentinel(tick) -> None:
    """A rejection that says the node already has this tx stays a success with the local txid."""
    node = _Node()
    ex, rec, _fees = await _armed(node)
    node.reject = (1, "txn-already-known")
    outcome, reason = await tick(ex, rec)
    assert outcome is ExecOutcome.BROADCAST, reason
    assert _txid(node.broadcasts[0]) in reason


@pytest.mark.parametrize(
    ("code", "node_reason"),
    [
        (1, _SCRIPT_FAILED),
        (-26, _SCRIPT_FAILED),
        (-26, "bad-txns-vout-negative (code 16)"),
    ],
    ids=["script-electrumx", "script-bare", "bad-txns"],
)
async def test_a_permanent_rejection_declines_once_and_stops_recarving(tick, code, node_reason) -> None:
    from pyrxd.gravity.radiant_leg import SeenStore

    node = _Node()
    ex, rec, fees = await _armed(node, SeenStore())
    node.reject = (code, node_reason)

    outcome, reason = await tick(ex, rec)
    assert outcome is ExecOutcome.DECLINED, reason
    assert "PERMANENTLY rejected" in reason and node_reason.split(" ")[0] in reason
    assert len(node.broadcasts) == 1 and len(fees.outpoints) == 1

    outcome, reason = await tick(ex, rec)
    assert outcome is ExecOutcome.DECLINED, reason
    assert "already broadcast" in reason
    assert len(node.broadcasts) == 1 and len(fees.outpoints) == 1, "no second fee input is carved"


@pytest.mark.parametrize(
    "reply",
    [
        (1, "txn-mempool-conflict (code 18)"),
        (-26, "txn-mempool-conflict (code 18)"),
        (1, "Missing inputs"),
        (-25, "Missing inputs"),
        # A transient state wins over a permanent-looking prefix on the same reason.
        (-26, "bad-txns-inputs-missingorspent"),
        (-26, "bad-txns-nonfinal"),
        (-26, "non-final (code 64)"),
        (-26, "non-BIP68-final (code 64)"),
        # Fee answers retry: the next tick's fee input, and so the fee rate, differs.
        (1, "66: min relay fee not met"),
        (-26, "insufficient priority (code 66)"),
        (-26, "insufficient fee"),
        (-26, "absurdly-high-fee"),
        # Policy answers retry: one node's local rules, which another node may not apply.
        (-26, "non-mandatory-script-verify-flag (Non-canonical signature) (code 64)"),
        (-26, "scriptsig-not-pushonly (code 16)"),
        (1, "scriptpubkey (code 64)"),
        (1, "dust (code 64)"),
        (-26, "bad-txns-nonstandard-inputs (code 64)"),
        (1, "too-long-mempool-chain"),
        (1, ""),
        (-26, "some-rule-this-client-does-not-know"),
    ],
    ids=[
        "conflict-electrumx",
        "conflict-bare",
        "missing-inputs-electrumx",
        "missing-inputs-bare",
        "missingorspent",
        "bad-txns-nonfinal",
        "non-final",
        "non-bip68-final",
        "min-relay-fee",
        "insufficient-priority",
        "insufficient-fee",
        "absurdly-high-fee",
        "non-mandatory",
        "scriptsig",
        "scriptpubkey",
        "dust",
        "nonstandard-inputs",
        "long-chain",
        "no-reason",
        "unknown-reason",
    ],
)
async def test_a_passing_or_unknown_rejection_is_retried_and_the_claim_stays_armed(tick, reply) -> None:
    from pyrxd.gravity.radiant_leg import SeenStore

    node = _Node()
    ex, rec, _fees = await _armed(node, SeenStore())
    node.reject = reply

    outcome, reason = await tick(ex, rec)
    assert outcome is ExecOutcome.FAILED, reason
    assert "claim broadcast failed" in reason and "PERMANENTLY" not in reason

    # The state passes; the claim is still armed, so the next tick sends it.
    node.reject = None
    outcome, reason = await tick(ex, rec)
    assert outcome is ExecOutcome.BROADCAST, reason
    assert len(node.broadcasts) == 2


async def test_a_conflict_with_an_evicted_claim_still_claims(tick) -> None:
    """The case marking a conflict seen would lose: our relayed claim is evicted after the conflict."""
    from pyrxd.gravity.radiant_leg import SeenStore

    node = _Node()
    ex, rec, fees = await _armed(node, SeenStore())
    node.lie = True  # relays the first claim, then lies about it

    outcome, _ = await tick(ex, rec)
    assert outcome is ExecOutcome.FAILED
    node.lie = False
    outcome, reason = await tick(ex, rec)
    assert outcome is ExecOutcome.FAILED, reason
    assert "txn-mempool-conflict" in reason

    node.mempool.clear()  # the first claim is evicted
    outcome, reason = await tick(ex, rec)
    assert outcome is ExecOutcome.BROADCAST, reason
    node.mine()
    assert _assert_paid_once(node, fees) == _txid(node.broadcasts[2])


#: Each reason that must retry although it sits beside a consensus word, keyed by the marker that
#: makes it retry. Hand-written, so deleting a marker from the executor fails its case; the test
#: below keeps this table in step with the executor's tuples.
_RETRY_BESIDE_A_CONSENSUS_WORD = {
    "txn-mempool-conflict": "txn-mempool-conflict",
    "missing inputs": "Missing inputs",
    "missing-inputs": "missing-inputs",
    "inputs-missingorspent": "bad-txns-inputs-missingorspent",
    "non-final": "non-final",
    "nonfinal": "bad-txns-nonfinal",
    "non-bip68-final": "non-BIP68-final",
    "too-long-mempool-chain": "too-long-mempool-chain",
    "non-mandatory-script-verify-flag": "non-mandatory-script-verify-flag (Non-canonical signature)",
    "nonstandard": "bad-txns-nonstandard-inputs",
    "scriptsig-": "scriptsig-not-pushonly",
    "scriptpubkey": "scriptpubkey",
    "dust": "dust",
}


def test_every_retry_marker_has_a_case() -> None:
    from pyrxd.gravity.watch import claim_executor

    markers = {*claim_executor._TRANSIENT_REJECTION_MARKERS, *claim_executor._POLICY_REJECTION_MARKERS}
    assert markers and set(_RETRY_BESIDE_A_CONSENSUS_WORD) == markers


@pytest.mark.parametrize("marker", sorted(_RETRY_BESIDE_A_CONSENSUS_WORD))
def test_a_retry_marker_wins_over_a_consensus_word(marker) -> None:
    """Every transient or policy marker is load-bearing: with it gone, the consensus word beside it
    would disarm the claim."""
    from pyrxd.gravity.watch.claim_executor import _is_permanent_rejection
    from pyrxd.network.electrumx import _policy_rejection

    reason = _RETRY_BESIDE_A_CONSENSUS_WORD[marker]
    assert marker in reason.lower()
    assert not _is_permanent_rejection(_policy_rejection(-26, f"bad-txns-vout-negative {reason}"))
    # Honest pair: the consensus word alone is permanent.
    assert _is_permanent_rejection(_policy_rejection(-26, "bad-txns-vout-negative"))
