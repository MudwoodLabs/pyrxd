"""Truth-table tests for the pure watchtower decision core (``gravity.watch.decide``).

Pure, no chain/network. Covers every Intent branch, the chain-truth-dominates rule
(claim race assessed from BOTH_LOCKED, not just SECRET_REVEALED), fail-closed paths
(missing depth, lying ``now < lock``), and low-corroboration propagation. The
finality-gate math is exercised indirectly — decide() consumes the real
``assess_claim_finality`` / ``should_taker_refund_proactively``, never a re-derivation.
"""

from __future__ import annotations

import hashlib
import os

import pytest

from pyrxd.btc_wallet import taproot as t
from pyrxd.gravity.swap_coordinator import MarginPolicy
from pyrxd.gravity.swap_state import NegotiatedTerms, SwapRecord, SwapState
from pyrxd.gravity.watch import Intent, Observations, decide
from pyrxd.security.errors import ValidationError

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _xonly() -> bytes:
    import coincurve

    return coincurve.PublicKeyXOnly.from_secret(os.urandom(32)).format()


def _btc_terms(*, t_btc_blocks: int = 144, t_rxd_blocks: int = 72) -> NegotiatedTerms:
    p = os.urandom(32)
    return NegotiatedTerms(
        hashlock=hashlib.sha256(p).digest(),
        btc_sats=100_000,
        radiant_amount=1_000,
        t_btc=t.Timelock(t_btc_blocks, t.TimeUnit.BLOCKS),
        t_rxd=t.Timelock(t_rxd_blocks, t.TimeUnit.BLOCKS),
        asset_variant="ft",
        genesis_ref=b"\xaa" * 36,
        taker_dest_hash=b"\x11" * 32,
        maker_dest_hash=b"\x22" * 32,
        btc_claim_pubkey_xonly=_xonly(),
        btc_refund_pubkey_xonly=_xonly(),
    )


def _eth_terms() -> NegotiatedTerms:
    p = os.urandom(32)
    return NegotiatedTerms(
        hashlock=hashlib.sha256(p).digest(),
        btc_sats=100_000,
        radiant_amount=1_000,
        t_btc=t.Timelock(144, t.TimeUnit.BLOCKS),
        t_rxd=t.Timelock(72, t.TimeUnit.BLOCKS),
        asset_variant="ft",
        genesis_ref=b"\xaa" * 36,
        taker_dest_hash=b"\x11" * 32,
        maker_dest_hash=b"\x22" * 32,
        btc_claim_pubkey_xonly=b"\x00" * 32,
        btc_refund_pubkey_xonly=b"\x00" * 32,
        counter_chain="eth",
        value_amount=10**15,
        eth_timeout_unix_s=4_000_000_000,
    )


def _policy() -> MarginPolicy:
    # Explicit reorg depths so the gate math is deterministic in tests:
    #   required BTC depth = 6 blocks; RXD claim burial = 2 blocks.
    return MarginPolicy(
        margin=t.Timelock(72, t.TimeUnit.BLOCKS),
        block_interval_s=600.0,
        is_measured=False,
        btc_claim_reorg_depth=t.Timelock(6, t.TimeUnit.BLOCKS),
        rxd_claim_burial=t.Timelock(2, t.TimeUnit.BLOCKS),
        rxd_block_interval_s=300.0,
    )


def _record(state: SwapState, *, terms: NegotiatedTerms | None = None) -> SwapRecord:
    return SwapRecord(state=state, terms=terms or _btc_terms())


SAFETY = 6
LOCK = 100  # asset_locked_at_height
# t_rxd = 72 → maker CSV refund opens at LOCK + 72 = 172.
REFUND_OPENS = LOCK + 72


def _decide(record, obs):
    return decide(record=record, observations=obs, policy=_policy(), safety_window_blocks=SAFETY)


# ---------------------------------------------------------------------------
# Terminal / out-of-scope
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "state",
    [
        SwapState.COMPLETED,
        SwapState.MUTUAL_REFUND,
        SwapState.ABORTED,
        SwapState.ASSET_REFUNDED_TAKER_ACTS,
        SwapState.ONE_SIDED_LOSS_TAKER,
    ],
)
def test_terminal_states_retire(state):
    d = _decide(_record(state), Observations(maker_has_claimed_btc=False, now_rxd_height=150))
    assert d.intent is Intent.RETIRE


def test_eth_swap_is_noop_v1():
    rec = _record(SwapState.BOTH_LOCKED, terms=_eth_terms())
    d = _decide(rec, Observations(maker_has_claimed_btc=False, now_rxd_height=150, asset_locked_at_height=LOCK))
    assert d.intent is Intent.NOOP


# ---------------------------------------------------------------------------
# Claim race (maker revealed p) — gate verdict drives the page
# ---------------------------------------------------------------------------


def test_claim_safe_pages_claim():
    # FINAL (6 conf) and room to bury (now well before refund opens) → SAFE → PAGE_CLAIM.
    obs = Observations(
        maker_has_claimed_btc=True, now_rxd_height=150, asset_locked_at_height=LOCK, btc_claim_confirmations=6
    )
    d = _decide(_record(SwapState.SECRET_REVEALED), obs)
    assert d.intent is Intent.PAGE_CLAIM
    assert d.recommended_action == "taker_scrape_and_claim_asset"
    assert d.deadline_rxd_height == REFUND_OPENS


def test_claim_wait_keeps_watching():
    # NOT_YET_FINAL (3 conf) but window has room → WAIT → WATCH (no page).
    obs = Observations(
        maker_has_claimed_btc=True, now_rxd_height=150, asset_locked_at_height=LOCK, btc_claim_confirmations=3
    )
    d = _decide(_record(SwapState.SECRET_REVEALED), obs)
    assert d.intent is Intent.WATCH


def test_claim_squeezed_pages_decision():
    # FINAL but window closing (1 block left < rxd_burial 2) → SQUEEZED → PAGE_SQUEEZED.
    obs = Observations(
        maker_has_claimed_btc=True,
        now_rxd_height=REFUND_OPENS - 1,
        asset_locked_at_height=LOCK,
        btc_claim_confirmations=6,
    )
    d = _decide(_record(SwapState.SECRET_REVEALED), obs)
    assert d.intent is Intent.PAGE_SQUEEZED
    assert "vulnerable" in d.recommended_action.lower() or "winner" in d.recommended_action.lower()


def test_claim_race_dominates_lagging_record():
    # Chain shows the maker claimed, but the record still says BOTH_LOCKED (operator
    # offline). The claim race must be assessed anyway (Gap 2/7).
    obs = Observations(
        maker_has_claimed_btc=True, now_rxd_height=150, asset_locked_at_height=LOCK, btc_claim_confirmations=6
    )
    d = _decide(_record(SwapState.BOTH_LOCKED), obs)
    assert d.intent is Intent.PAGE_CLAIM


def test_claim_missing_depth_fails_closed():
    obs = Observations(
        maker_has_claimed_btc=True, now_rxd_height=150, asset_locked_at_height=LOCK, btc_claim_confirmations=None
    )
    d = _decide(_record(SwapState.SECRET_REVEALED), obs)
    assert d.intent is Intent.PAGE_SQUEEZED


def test_claim_missing_lock_height_fails_closed():
    obs = Observations(
        maker_has_claimed_btc=True, now_rxd_height=150, asset_locked_at_height=None, btc_claim_confirmations=6
    )
    d = _decide(_record(SwapState.SECRET_REVEALED), obs)
    assert d.intent is Intent.PAGE_SQUEEZED


def test_claim_now_below_lock_fails_closed():
    # now_rxd_height < asset_locked_at_height ⇒ lying/lagging node ⇒ gate raises ⇒ fail-closed page.
    obs = Observations(
        maker_has_claimed_btc=True, now_rxd_height=50, asset_locked_at_height=LOCK, btc_claim_confirmations=6
    )
    d = _decide(_record(SwapState.SECRET_REVEALED), obs)
    assert d.intent is Intent.PAGE_SQUEEZED


# ---------------------------------------------------------------------------
# Refund / stall / danger states (maker has NOT revealed p)
# ---------------------------------------------------------------------------


def test_asset_vulnerable_pages_decision():
    obs = Observations(maker_has_claimed_btc=False, now_rxd_height=170, asset_locked_at_height=LOCK)
    d = _decide(_record(SwapState.ASSET_VULNERABLE), obs)
    assert d.intent is Intent.PAGE_SQUEEZED


def test_params_mismatch_pages_btc_refund():
    obs = Observations(maker_has_claimed_btc=False, now_rxd_height=150)
    d = _decide(_record(SwapState.PARAMS_MISMATCH), obs)
    assert d.intent is Intent.PAGE_REFUND
    assert d.recommended_action == "taker_refund_btc"


def test_both_locked_refund_not_due_watches():
    # now well before (maturity - safety) = 172 - 6 = 166.
    obs = Observations(maker_has_claimed_btc=False, now_rxd_height=150, asset_locked_at_height=LOCK)
    d = _decide(_record(SwapState.BOTH_LOCKED), obs)
    assert d.intent is Intent.WATCH


def test_both_locked_refund_due_pages_refund():
    # now >= maturity - safety (166) → proactive refund due.
    obs = Observations(maker_has_claimed_btc=False, now_rxd_height=167, asset_locked_at_height=LOCK)
    d = _decide(_record(SwapState.BOTH_LOCKED), obs)
    assert d.intent is Intent.PAGE_REFUND
    assert d.recommended_action == "maybe_refund_asset_on_maker_stall"


def test_maker_stalls_pages_refund():
    obs = Observations(maker_has_claimed_btc=False, now_rxd_height=150, asset_locked_at_height=LOCK)
    d = _decide(_record(SwapState.MAKER_STALLS), obs)
    assert d.intent is Intent.PAGE_REFUND


def test_both_locked_unknown_lock_height_watches():
    obs = Observations(maker_has_claimed_btc=False, now_rxd_height=150, asset_locked_at_height=None)
    d = _decide(_record(SwapState.BOTH_LOCKED), obs)
    assert d.intent is Intent.WATCH


@pytest.mark.parametrize("state", [SwapState.NEGOTIATED, SwapState.BTC_LOCKED])
def test_pre_lock_states_watch(state):
    obs = Observations(maker_has_claimed_btc=False, now_rxd_height=150)
    d = _decide(_record(state), obs)
    assert d.intent is Intent.WATCH


# ---------------------------------------------------------------------------
# Low-corroboration propagation + input validation
# ---------------------------------------------------------------------------


def test_low_corroboration_propagates():
    obs = Observations(
        maker_has_claimed_btc=False, now_rxd_height=167, asset_locked_at_height=LOCK, low_corroboration=True
    )
    d = _decide(_record(SwapState.BOTH_LOCKED), obs)
    assert d.intent is Intent.PAGE_REFUND
    assert d.low_corroboration is True


def test_decide_rejects_bad_inputs():
    rec = _record(SwapState.BOTH_LOCKED)
    obs = Observations(maker_has_claimed_btc=False, now_rxd_height=150, asset_locked_at_height=LOCK)
    with pytest.raises(ValidationError):
        decide(record=rec, observations=obs, policy=_policy(), safety_window_blocks=-1)
    with pytest.raises(ValidationError):
        decide(record="not a record", observations=obs, policy=_policy(), safety_window_blocks=SAFETY)


def test_observations_validation():
    with pytest.raises(ValidationError):
        Observations(maker_has_claimed_btc=False, now_rxd_height=-1)
    with pytest.raises(ValidationError):
        Observations(maker_has_claimed_btc=False, now_rxd_height=10, btc_claim_confirmations=-3)
