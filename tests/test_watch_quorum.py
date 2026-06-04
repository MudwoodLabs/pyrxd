"""Tests for the watchtower observation/quorum layer (``gravity.watch.quorum``).

Fakes for the BTC claim source + RXD chain source. Covers claim detection,
depth pass-through, asset-lock-height derivation (incl. bogus-source guard),
the v1 single-source low-corroboration flag, and an observe→decide integration
check (conservative min-depth must not produce a premature PAGE_CLAIM).
"""

from __future__ import annotations

import hashlib
import os

from pyrxd.btc_wallet import taproot as t
from pyrxd.gravity.swap_coordinator import MarginPolicy
from pyrxd.gravity.swap_state import NegotiatedTerms, SwapRecord, SwapState
from pyrxd.gravity.watch import BtcClaimStatus, ChainObserver, Intent, decide

COV_OUTPOINT = "ab" * 32 + ":0"


def _xonly() -> bytes:
    import coincurve

    return coincurve.PublicKeyXOnly.from_secret(os.urandom(32)).format()


def _terms() -> NegotiatedTerms:
    return NegotiatedTerms(
        hashlock=hashlib.sha256(os.urandom(32)).digest(),
        btc_sats=100_000,
        radiant_amount=1_000,
        t_btc=t.Timelock(144, t.TimeUnit.BLOCKS),
        t_rxd=t.Timelock(72, t.TimeUnit.BLOCKS),
        asset_variant="ft",
        genesis_ref=b"\xaa" * 36,
        taker_dest_hash=b"\x11" * 32,
        maker_dest_hash=b"\x22" * 32,
        btc_claim_pubkey_xonly=_xonly(),
        btc_refund_pubkey_xonly=_xonly(),
    )


def _locator() -> t.BtcHtlcLocator:
    htlc = t.build_htlc(
        hashlock=hashlib.sha256(os.urandom(32)).digest(),
        claim_pubkey_xonly=_xonly(),
        refund_pubkey_xonly=_xonly(),
        timeout=t.Timelock(144, t.TimeUnit.BLOCKS),
    )
    return htlc.with_funding(t.BtcOutpoint("cd" * 32, 1), 100_000)


def _policy() -> MarginPolicy:
    return MarginPolicy(
        margin=t.Timelock(72, t.TimeUnit.BLOCKS),
        block_interval_s=600.0,
        is_measured=False,
        btc_claim_reorg_depth=t.Timelock(6, t.TimeUnit.BLOCKS),
        rxd_claim_burial=t.Timelock(2, t.TimeUnit.BLOCKS),
        rxd_block_interval_s=300.0,
    )


def _record(state=SwapState.BOTH_LOCKED, *, with_locator=True, with_covenant=True) -> SwapRecord:
    return SwapRecord(
        state=state,
        terms=_terms(),
        counterchain_locator=_locator() if with_locator else None,
        radiant_covenant_outpoint=COV_OUTPOINT if with_covenant else None,
    )


class FakeBtc:
    def __init__(self, status: BtcClaimStatus, confs: int = 0):
        self._status = status
        self._confs = confs
        self.claim_status_calls: list[tuple[str, int]] = []

    async def claim_status(self, funding_txid, funding_vout):
        self.claim_status_calls.append((funding_txid, funding_vout))
        return self._status

    async def confirmations(self, claim_txid):
        return self._confs


class FakeRxd:
    def __init__(self, tip: int, cov_confs: int | None = None):
        self._tip = tip
        self._cov = cov_confs

    async def tip_height(self):
        return self._tip

    async def covenant_confirmations(self, outpoint):
        return self._cov


# --- tests ----------------------------------------------------------------


async def test_maker_not_claimed():
    btc = FakeBtc(BtcClaimStatus(claimed=False))
    obs = await ChainObserver(btc=btc, rxd=FakeRxd(tip=200, cov_confs=101)).observe("s", _record())
    assert obs.maker_has_claimed_btc is False
    assert obs.btc_claim_confirmations is None
    assert obs.now_rxd_height == 200
    assert obs.asset_locked_at_height == 100  # 200 - 101 + 1
    assert obs.low_corroboration is True  # v1 RXD single-source
    # the funding outpoint was queried
    assert btc.claim_status_calls == [("cd" * 32, 1)]


async def test_maker_claimed_fills_depth():
    btc = FakeBtc(BtcClaimStatus(claimed=True, claim_txid="ef" * 32), confs=6)
    obs = await ChainObserver(btc=btc, rxd=FakeRxd(tip=200, cov_confs=101)).observe("s", _record())
    assert obs.maker_has_claimed_btc is True
    assert obs.btc_claim_confirmations == 6


async def test_covenant_unmined_yields_none_lock_height():
    btc = FakeBtc(BtcClaimStatus(claimed=False))
    obs = await ChainObserver(btc=btc, rxd=FakeRxd(tip=200, cov_confs=None)).observe("s", _record())
    assert obs.asset_locked_at_height is None


async def test_no_covenant_outpoint_yields_none_lock_height():
    btc = FakeBtc(BtcClaimStatus(claimed=False))
    rec = _record(with_covenant=False)
    obs = await ChainObserver(btc=btc, rxd=FakeRxd(tip=200, cov_confs=101)).observe("s", rec)
    assert obs.asset_locked_at_height is None


async def test_no_locator_skips_btc_query():
    btc = FakeBtc(BtcClaimStatus(claimed=False))
    rec = _record(state=SwapState.NEGOTIATED, with_locator=False, with_covenant=False)
    obs = await ChainObserver(btc=btc, rxd=FakeRxd(tip=200)).observe("s", rec)
    assert obs.maker_has_claimed_btc is False
    assert btc.claim_status_calls == []  # no funding outpoint to watch yet


async def test_bogus_covenant_confs_guarded_to_none():
    # cov_confs > tip + 1 (impossible on an honest chain) ⇒ candidate < 0 ⇒ None, not negative.
    btc = FakeBtc(BtcClaimStatus(claimed=False))
    obs = await ChainObserver(btc=btc, rxd=FakeRxd(tip=200, cov_confs=500)).observe("s", _record())
    assert obs.asset_locked_at_height is None


async def test_corroboration_flag_toggles():
    btc = FakeBtc(BtcClaimStatus(claimed=False))
    rxd = FakeRxd(tip=200, cov_confs=101)
    assert (
        await ChainObserver(btc=btc, rxd=rxd, rxd_corroborated=False).observe("s", _record())
    ).low_corroboration is True
    assert (
        await ChainObserver(btc=btc, rxd=rxd, rxd_corroborated=True).observe("s", _record())
    ).low_corroboration is False


async def test_observe_then_decide_min_depth_no_premature_claim():
    # Quorum returns the conservative MIN depth (3 < required 6) ⇒ gate WAIT ⇒ no PAGE_CLAIM.
    btc = FakeBtc(BtcClaimStatus(claimed=True, claim_txid="ef" * 32), confs=3)
    rec = _record(state=SwapState.SECRET_REVEALED)
    obs = await ChainObserver(btc=btc, rxd=FakeRxd(tip=150, cov_confs=51)).observe("s", rec)  # locked at 100
    d = decide(record=rec, observations=obs, policy=_policy(), safety_window_blocks=6)
    assert d.intent is Intent.WATCH  # NOT a premature PAGE_CLAIM


async def test_observe_then_decide_safe_depth_pages_claim_with_corroboration_flag():
    btc = FakeBtc(BtcClaimStatus(claimed=True, claim_txid="ef" * 32), confs=6)
    rec = _record(state=SwapState.SECRET_REVEALED)
    obs = await ChainObserver(btc=btc, rxd=FakeRxd(tip=150, cov_confs=51)).observe("s", rec)  # locked at 100
    d = decide(record=rec, observations=obs, policy=_policy(), safety_window_blocks=6)
    assert d.intent is Intent.PAGE_CLAIM
    assert d.low_corroboration is True  # propagated from the single-source RXD read
