"""The autonomous claim executor never answers an ambiguous broadcast with a NEW claim (#786 review).

When the server's broadcast reply names some other txid, ``ElectrumXClient.broadcast`` raises
``BroadcastEchoMismatch``: the claim may have relayed. ``RadiantChainIO.broadcast`` wrapped every
exception as ``NetworkError``, so ``ClaimExecutor`` read it as a transient failure and, on the next
tick, called ``claim_asset`` again — building a new claim with a freshly dispensed fee input, every
tick, for as long as the lie lasted. With a dispense-once capped fee pool that walks the pool.

Everything here is production code except the SERVER: the executor drives a real
``RadiantCovenantLeg`` over a real ``RadiantChainIO`` over a real ``ElectrumXClient`` whose ``_call``
(the JSON-RPC wire) is answered by :class:`_Server`. The BTC claim the executor scrapes ``p`` from is a
real one, built by the BTC HTLC leg. The fee source counts dispenses; that count is the fee inputs the
executor consumed, and a rebuilt claim is the only thing that increments it.
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
from pyrxd.gravity.radiant_leg import RadiantChainIO, RadiantCovenantLeg, SeenStore
from pyrxd.gravity.swap_coordinator import MarginPolicy
from pyrxd.gravity.swap_state import NegotiatedTerms, SwapRecord, SwapState
from pyrxd.gravity.watch import ClaimExecutor, ExecOutcome
from pyrxd.hash import hash256
from pyrxd.keys import PrivateKey
from pyrxd.network.electrumx import ElectrumXClient
from pyrxd.security.errors import BroadcastEchoMismatch, NetworkError
from pyrxd.security.types import Hex20

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
#: A well-formed txid for some OTHER transaction — what a lying server echoes.
_LIE = "ee" * 32


def _txid(raw: bytes) -> str:
    return hash256(raw)[::-1].hex()


class _Server(ElectrumXClient):
    """A real ``ElectrumXClient``; only ``_call`` (the wire) and ``_ensure_connected`` are faked.

    Holds the funded covenant and a mempool. ``relay`` puts a broadcast transaction in the mempool;
    ``lie`` echoes :data:`_LIE`; ``fail`` raises a transport error instead of answering.
    """

    def __init__(self) -> None:
        super().__init__(["wss://fake.invalid/"])
        self.relay, self.lie, self.fail = True, False, False
        self.mempool: dict[str, bytes] = {}
        self.broadcasts: list[bytes] = []

    async def _ensure_connected(self) -> None:
        return None

    async def _call(self, method: str, params: list[Any]) -> Any:
        if method == "blockchain.scripthash.listunspent":
            return [{"tx_hash": _COVENANT_TXID, "tx_pos": 0, "value": _AMOUNT, "height": 100}]
        if method == "blockchain.transaction.get":
            txid = params[0]
            if txid == _COVENANT_TXID:
                return {"txid": txid, "confirmations": 1}
            if txid in self.mempool:
                return {"txid": txid}  # unconfirmed: no depth yet
            raise NetworkError("No such mempool or blockchain transaction")
        if method == "blockchain.transaction.broadcast":
            raw = bytes.fromhex(params[0])
            self.broadcasts.append(raw)
            if self.fail:
                raise NetworkError("connection reset by peer")
            if self.relay:
                self.mempool[_txid(raw)] = raw
            return _LIE if self.lie else _txid(raw)
        raise AssertionError(f"unexpected RPC {method} {params}")


class _CountingFeeSource:
    """Dispense-once, like ``CappedFeeWalletSource``: every call hands out a NEW fee input."""

    def __init__(self) -> None:
        self.key = PrivateKey()
        self.dispensed = 0

    def next_fee_input(self) -> FeeInput:
        self.dispensed += 1
        pkh = bytes(Hex20(self.key.public_key().hash160()))
        return FeeInput(
            txid=os.urandom(32).hex(),
            vout=0,
            value=10_000_000,
            scriptpubkey=b"\x76\xa9\x14" + pkh + b"\x88\xac",
            wif=self.key.wif(),
        )


async def _armed(server: _Server, *, seen_store: SeenStore | None = None):
    """A ClaimExecutor wired to a real leg over *server*, plus the record and fee source."""
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
    # The maker's real BTC claim, revealing p — what the executor scrapes.
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
        network="bcrt", taker_pkh=taker_pkh, maker_pkh=maker_pkh, chain_io=RadiantChainIO(server), fee_source=fees
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
        radiant_covenant_outpoint=f"{_COVENANT_TXID}:0",
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


async def test_the_chain_io_lets_the_mismatch_through_unwrapped() -> None:
    server = _Server()
    server.lie = True
    raw = os.urandom(80)
    with pytest.raises(BroadcastEchoMismatch) as info:
        await RadiantChainIO(server).broadcast(raw)
    assert not isinstance(info.value, NetworkError), "a NetworkError reads as 'retry', and the retry rebuilds"
    assert info.value.local_txid == _txid(raw)
    assert info.value.raw_tx == raw, "the exact bytes sent, so a retry can re-send them"


@pytest.mark.parametrize("seen_store", [SeenStore, None], ids=["seen-store", "no-seen-store"])
async def test_a_lie_about_a_relayed_claim_is_found_on_the_chain_not_rebuilt(seen_store, tick) -> None:
    """Without a SeenStore the executor has no fire-once guard, and a mempool-blind read keeps
    saying "unspent": the kept record is then the only thing stopping a rebuild."""
    server = _Server()
    ex, rec, fees = await _armed(server, seen_store=seen_store() if seen_store else None)
    server.lie = True  # relays, then lies about it

    outcome, reason = await tick(ex, rec)
    assert outcome is ExecOutcome.FAILED
    assert "may have relayed" in reason
    sent = server.broadcasts[0]
    assert _txid(sent) in reason, "the reason names the claim actually sent"
    assert fees.dispensed == 1

    server.lie = False
    outcome, reason = await tick(ex, rec)
    assert outcome is ExecOutcome.DECLINED, reason
    assert "on the chain" in reason
    assert fees.dispensed == 1, "no new fee input: nothing was rebuilt"
    assert server.broadcasts == [sent], "found on the chain, so nothing was sent again"

    # A later tick is still a no-op (the fire-once guard, or the kept record), with nothing sent.
    for _ in range(2):
        outcome, _ = await tick(ex, rec)
        assert outcome is ExecOutcome.DECLINED
        assert server.broadcasts == [sent] and fees.dispensed == 1


async def test_a_lie_about_a_dropped_claim_resends_the_same_bytes(tick) -> None:
    server = _Server()
    ex, rec, fees = await _armed(server)
    server.lie, server.relay = True, False  # drops it AND lies

    outcome, _ = await tick(ex, rec)
    assert outcome is ExecOutcome.FAILED
    assert server.mempool == {}

    # Still lying on the next tick: the same bytes go out again, and still no new fee input.
    outcome, _ = await tick(ex, rec)
    assert outcome is ExecOutcome.FAILED
    assert len(server.broadcasts) == 2 and server.broadcasts[1] == server.broadcasts[0]
    assert fees.dispensed == 1

    server.lie, server.relay = False, True
    outcome, reason = await tick(ex, rec)
    assert outcome is ExecOutcome.BROADCAST, reason
    assert len(server.broadcasts) == 3 and server.broadcasts[2] == server.broadcasts[0], "byte for byte"
    assert fees.dispensed == 1, "the re-send spends the fee input the first claim already carried"
    assert set(server.mempool) == {_txid(server.broadcasts[0])}


async def test_a_genuine_network_failure_still_retries_with_a_new_claim(tick) -> None:
    """The honest path: a transport failure is still a transient FAILED, and the next tick claims."""
    server = _Server()
    ex, rec, fees = await _armed(server)
    server.fail = True

    outcome, reason = await tick(ex, rec)
    assert outcome is ExecOutcome.FAILED
    assert "claim broadcast failed" in reason
    assert ex._ambiguous_claims == {}, "a transport failure is not an ambiguous echo"

    server.fail = False
    outcome, reason = await tick(ex, rec)
    assert outcome is ExecOutcome.BROADCAST, reason
    assert fees.dispensed == 2, "retried the way it always has: a freshly built claim"
    assert server.broadcasts[1] != server.broadcasts[0]


async def test_an_honest_first_broadcast_is_unchanged(tick) -> None:
    server = _Server()
    ex, rec, fees = await _armed(server)
    outcome, reason = await tick(ex, rec)
    assert outcome is ExecOutcome.BROADCAST, reason
    assert fees.dispensed == 1 and len(server.broadcasts) == 1
