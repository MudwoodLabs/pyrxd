"""A broadcast echo mismatch on the autonomous claim is retried by REBUILDING the claim — and that
cannot pay twice (#780, #786).

``ElectrumXClient.broadcast`` raises ``BroadcastEchoMismatch`` when the server's reply names some
other txid. ``RadiantChainIO.broadcast`` wraps every client exception as ``NetworkError``, so
``ClaimExecutor`` reads the mismatch as a transient FAILED and, on a later tick, calls
``claim_asset`` again: a NEW claim with a freshly dispensed fee input. That is safe because:

* the covenant output is spendable once, and every claim pays the same fixed destination, so at
  most one claim confirms and the asset moves once;
* a rebuilt claim's fee input is committed only if THAT claim confirms. A claim that conflicts with
  one already in the mempool is refused, and its fee input stays unspent.

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
from pyrxd.network.electrumx import ElectrumXClient
from pyrxd.security.errors import BroadcastEchoMismatch, NetworkError
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
            if _spends(raw) & self._spent():
                raise NetworkError("the transaction was rejected by network rules. txn-mempool-conflict")
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


async def _armed(node: _Node):
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
