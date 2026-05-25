"""Formal cross-chain safety invariants for the Gravity HTLC swap FSM.

``test_swap_state.py`` checks the FSM's *structure* (no stranding, terminal
exits, legal/illegal edges). This file checks its *safety semantics* — the
economic properties an atomic swap must guarantee — by reachability analysis
over the real transition table plus property tests over NegotiatedTerms.

The invariants (stated precisely so they are falsifiable):

  I1  ATOMICITY OF THE TAKER WIN. Every path that reaches COMPLETED (taker got
      the asset) passes through SECRET_REVEALED (the maker claimed BTC and thus
      published p). There is no path where the taker obtains the asset without
      the maker first being able to obtain the BTC. => no one-sided TAKER win.

  I2  ONE-SIDED TAKER LOSS IS BOUNDED. ONE_SIDED_LOSS_TAKER is reachable ONLY
      via SECRET_REVEALED -> ASSET_VULNERABLE (the taker went offline AFTER the
      secret was revealed and let the Radiant CSV refund window pass). It is NOT
      reachable from any state before the secret is out. => the only way a taker
      loses is by ignoring a revealed secret past t_rxd; the protocol never
      strands a diligent taker.

  I3  REFUND ALWAYS AVAILABLE PRE-REVEAL. From every locked state reachable
      before SECRET_REVEALED (BTC_LOCKED, PARAMS_MISMATCH, BOTH_LOCKED,
      MAKER_STALLS), a refund-only terminal (ABORTED / MUTUAL_REFUND /
      ASSET_REFUNDED_TAKER_ACTS) is reachable. => no pre-reveal deadlock.

  I4  NO HAPPY-PATH LOSS. ONE_SIDED_LOSS_TAKER is NOT reachable on any path that
      goes through COMPLETED, and COMPLETED is reachable. => the success
      terminal and the loss terminal are mutually exclusive outcomes.

  I5  ORDERING (NegotiatedTerms). t_btc > t_rxd in the same unit is rejected at
      construction (the maker must hold the LONGER refund window so the taker can
      always refund Radiant before the BTC refund opens). Property-tested.
"""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from pyrxd.btc_wallet.taproot import Timelock as TL
from pyrxd.btc_wallet.taproot import TimeUnit
from pyrxd.gravity.swap_state import (
    TERMINAL_STATES,
    TRANSITIONS,
    NegotiatedTerms,
    SwapState,
)
from pyrxd.security.errors import ValidationError

# ── reachability helpers over the real transition graph ─────────────────────


def _reachable_from(start: SwapState) -> set[SwapState]:
    """All states reachable from ``start`` (inclusive) over TRANSITIONS."""
    seen = {start}
    frontier = [start]
    while frontier:
        cur = frontier.pop()
        for src, dst in TRANSITIONS:
            if src == cur and dst not in seen:
                seen.add(dst)
                frontier.append(dst)
    return seen


def _all_paths(start: SwapState, goal: SwapState, _path=None) -> list[list[SwapState]]:
    """Every simple path start->goal (FSM is small + acyclic enough to enumerate)."""
    _path = (_path or []) + [start]
    if start == goal:
        return [_path]
    paths = []
    for src, dst in TRANSITIONS:
        if src == start and dst not in _path:  # simple paths only
            paths += _all_paths(dst, goal, _path)
    return paths


# ── I1: atomicity of the taker win ──────────────────────────────────────────


def test_I1_every_completed_path_passes_through_secret_revealed():
    paths = _all_paths(SwapState.NEGOTIATED, SwapState.COMPLETED)
    assert paths, "COMPLETED must be reachable from NEGOTIATED"
    for p in paths:
        assert SwapState.SECRET_REVEALED in p, (
            f"path to COMPLETED bypasses SECRET_REVEALED: {[s.value for s in p]} "
            "=> taker could get the asset without the maker being able to claim BTC"
        )


# ── I2: one-sided taker loss is bounded ─────────────────────────────────────


def test_I2_one_sided_loss_only_via_secret_revealed_then_vulnerable():
    paths = _all_paths(SwapState.NEGOTIATED, SwapState.ONE_SIDED_LOSS_TAKER)
    assert paths, "ONE_SIDED_LOSS_TAKER must be reachable (it is a real residual risk)"
    for p in paths:
        i_sr = p.index(SwapState.SECRET_REVEALED) if SwapState.SECRET_REVEALED in p else -1
        i_av = p.index(SwapState.ASSET_VULNERABLE) if SwapState.ASSET_VULNERABLE in p else -1
        assert i_sr >= 0 and i_av > i_sr, (
            f"taker loss reachable WITHOUT secret-revealed->vulnerable ordering: {[s.value for s in p]}"
        )


def test_I2_taker_loss_unreachable_before_secret_is_out():
    """No locked state that precedes SECRET_REVEALED can reach ONE_SIDED_LOSS_TAKER
    without first passing through SECRET_REVEALED."""
    pre_reveal = [SwapState.BTC_LOCKED, SwapState.PARAMS_MISMATCH, SwapState.BOTH_LOCKED, SwapState.MAKER_STALLS]
    for s in pre_reveal:
        for p in _all_paths(s, SwapState.ONE_SIDED_LOSS_TAKER):
            assert SwapState.SECRET_REVEALED in p, (
                f"{s.value} reaches taker-loss WITHOUT a secret reveal: {[x.value for x in p]}"
            )


# ── I3: refund always available pre-reveal ──────────────────────────────────


def test_I3_refund_reachable_from_every_pre_reveal_locked_state():
    refund_terminals = {
        SwapState.ABORTED,
        SwapState.MUTUAL_REFUND,
        SwapState.ASSET_REFUNDED_TAKER_ACTS,
    }
    pre_reveal = [SwapState.BTC_LOCKED, SwapState.PARAMS_MISMATCH, SwapState.BOTH_LOCKED, SwapState.MAKER_STALLS]
    for s in pre_reveal:
        reach = _reachable_from(s)
        assert reach & refund_terminals, f"{s.value} cannot reach any refund terminal (pre-reveal deadlock)"


# ── I4: no happy-path loss ──────────────────────────────────────────────────


def test_I4_completed_and_loss_are_mutually_exclusive():
    # COMPLETED is terminal, so a path through COMPLETED cannot continue to loss.
    assert SwapState.COMPLETED in TERMINAL_STATES
    assert SwapState.ONE_SIDED_LOSS_TAKER in TERMINAL_STATES
    # And COMPLETED is genuinely reachable.
    assert SwapState.COMPLETED in _reachable_from(SwapState.NEGOTIATED)
    # From COMPLETED, nothing is reachable but itself.
    assert _reachable_from(SwapState.COMPLETED) == {SwapState.COMPLETED}


# ── I5: ordering invariant on NegotiatedTerms ───────────────────────────────


def _terms(t_btc_v: int, t_rxd_v: int) -> NegotiatedTerms:
    return NegotiatedTerms(
        hashlock=b"\x01" * 32,
        btc_sats=100_000,
        radiant_amount=1_000,
        t_btc=TL(t_btc_v, TimeUnit.BLOCKS),
        t_rxd=TL(t_rxd_v, TimeUnit.BLOCKS),
        asset_variant="rxd",
        genesis_ref=b"",
        taker_dest_hash=b"\x11" * 32,
        maker_dest_hash=b"\x22" * 32,
        btc_claim_pubkey_xonly=b"\x33" * 32,
        btc_refund_pubkey_xonly=b"\x44" * 32,
    )


@given(
    t_btc=st.integers(min_value=1, max_value=65535),
    t_rxd=st.integers(min_value=1, max_value=65535),
)
def test_I5_terms_enforce_t_btc_strictly_greater_same_unit(t_btc, t_rxd):
    if t_btc > t_rxd:
        terms = _terms(t_btc, t_rxd)  # must succeed
        assert terms.t_btc.value > terms.t_rxd.value
    else:
        # t_btc <= t_rxd in the same unit must be rejected (would let the BTC
        # refund open before/at the Radiant refund — the taker could be griefed).
        try:
            _terms(t_btc, t_rxd)
            raised = False
        except ValidationError:
            raised = True
        assert raised, f"terms accepted unsafe ordering t_btc={t_btc} <= t_rxd={t_rxd}"
