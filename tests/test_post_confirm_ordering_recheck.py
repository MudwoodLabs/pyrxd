"""#564: the post-confirm ordering recheck, on both corridors, at the covenant's REAL depth.

The ETH half is a fix. `_assert_eth_lock_timing_still_safe` passed `max_covenant_confirm_wait_s=0`
and no `elapsed_blocks`, so the gate's default of 0 applied and it judged the NEGOTIATED window
from a clock that only ever moves in the permissive direction. That is not "weakly
discriminating": swept against the real gate it refused NOTHING (see
`test_the_shipped_form_refused_nothing_on_the_whole_grid`).

The BTC half is a REFUSAL TO SHIP, recorded here as an executable reason rather than as prose.
#564's own analysis said the class is "one post-confirm ordering recheck, on both corridors, with
the covenant's real depth", and that fixing only the ETH instance repeats the failure this repo
keeps recording. Measured, the twin does not exist to be written: `t_btc` is a RELATIVE CSV counted
from the taker's funding, not an absolute deadline like `eth_timeout_unix_s`, and
`derive_counter_timelock` sizes it to survive `elapsed = reserve` and no further — the only slack
past that is one flooring step. Both shapes of the twin therefore refuse honest swaps, and a guard
that refuses valid work is a bug.
`test_the_btc_derivation_leaves_no_headroom_for_a_post_confirm_rerun` derives that property from
the production derivation and compares it against the maker's own mandatory wait, so the day
someone gives the derivation a drift reserve this test fails and the exemption has to be re-read
instead of inherited.
"""

from __future__ import annotations

import ast
import inspect
import math
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "scripts"))

from _dust_swap_shared import derive_counter_timelock, elapsed_reserve_blocks

import pyrxd.gravity.swap_coordinator as sc
from pyrxd.btc_wallet import taproot as bt
from pyrxd.gravity.eth_rxd_timelock import (
    CrossClockMargin,
    assert_covenant_confirms_before_eth_deadline,
    eth_absolute_to_rxd_relative_blocks,
)
from pyrxd.gravity.swap_coordinator import (
    ESTIMATED_BTC_CLAIM_REORG_DEPTH_BLOCKS,
    ESTIMATED_RXD_CLAIM_BURIAL_BLOCKS,
    MarginPolicy,
    SwapCoordinator,
    assert_timelock_margin,
)
from pyrxd.gravity.swap_state import SwapState
from pyrxd.security.errors import ValidationError
from tests.test_swap_coordinator import (
    _NOW,
    FakeEthLeg,
    FakeRadiantLeg,
    _eth_terms,
    _eth_to_btc_locked,
    _final,
    generate_secret,
)

# --------------------------------------------------------------------------------------------
# The production ETH parameters these numbers are measured at. `eth_swap_run.py`'s own defaults
# (--eth-timeout-s 86400, --rxd-claim-burial-s 1800, --rxd-confirm-slack-s 600,
# --rounding-slack-s 300) plus the 768 s steady-state finality lag and the 3600 s stall budget a
# real-value token leg is required to carry.
_PROD_MARGIN = CrossClockMargin(
    eth_reorg_finality_s=768,
    rxd_claim_burial_s=1800,
    rxd_confirm_slack_s=600,
    rounding_slack_s=300,
    eth_finality_stall_tolerance_s=3600,
)
#: The MEASURED Radiant p10 the module records (2026-08-26, 720 intervals) — the tail the sizer
#: divides by and the gate must be given.
_FAST_TAIL_S = 36.0
_T_LOCK = 1_800_000_000
_ETH_TIMEOUT = _T_LOCK + 86_400


def _prod_t_rxd() -> bt.Timelock:
    return eth_absolute_to_rxd_relative_blocks(
        eth_timeout_unix_s=_ETH_TIMEOUT,
        expected_rxd_lock_time_unix_s=_T_LOCK,
        margin=_PROD_MARGIN,
        rxd_block_interval_s=_FAST_TAIL_S,
    )


def _gate_at(*, depth: int, realised_interval_s: float, elapsed_blocks: int) -> bool:
    """The real gate, asked the post-confirm question.

    MODEL, stated so the numbers below can be checked: the covenant mined at ``_T_LOCK``; the ETH
    deadline is ABSOLUTE at ``_T_LOCK + 86_400``; at revalidation the covenant is ``depth`` blocks
    deep and those blocks took ``depth * realised_interval_s`` seconds, so the caller's clock
    reads ``_T_LOCK + depth * realised_interval_s``.
    """
    try:
        assert_covenant_confirms_before_eth_deadline(
            now_unix_s=_T_LOCK + int(depth * realised_interval_s),
            eth_timeout_unix_s=_ETH_TIMEOUT,
            margin=_PROD_MARGIN,
            t_rxd=_prod_t_rxd(),
            rxd_block_interval_s=_FAST_TAIL_S,
            max_covenant_confirm_wait_s=0,
            elapsed_blocks=elapsed_blocks,
        )
        return True
    except ValidationError:
        return False


# --------------------------------------------------------------------------------------------
# The ETH half — the fix, through the production entry point.
# --------------------------------------------------------------------------------------------


async def test_the_recheck_is_handed_the_covenants_real_depth(monkeypatch) -> None:
    """Reachability, at the production entry point: `post_asset_lock_revalidate` — the only
    transition into BOTH_LOCKED — must reach the gate carrying the depth the chain reports.

    Asserted on the value that ARRIVES rather than on the source arrangement: a spy on the gate
    cannot be fooled by an alias, a reassigned local, or a wrapper.
    """
    secret, h = generate_secret()
    terms = _eth_terms(hashlock=h, eth_timeout_unix_s=_NOW + 40_000)
    rxd = FakeRadiantLeg(report_confs=1)
    coord = await _eth_to_btc_locked(
        leg=FakeEthLeg(preimage=secret, verdict=_final()), terms=terms, rxd=rxd, now_unix_s=_NOW
    )
    seen: list[int] = []
    monkeypatch.setattr(
        sc, "assert_covenant_confirms_before_eth_deadline", lambda **kw: seen.append(kw["elapsed_blocks"])
    )
    rxd.report_confs = 17  # the covenant aged between the taker's funding and this revalidation
    await coord.post_asset_lock_revalidate(await rxd.expected_covenant_scriptpubkey(terms), now_unix_s=_NOW)
    assert seen == [17], (
        f"the post-confirm recheck reached the gate with elapsed_blocks={seen}, not the 17 "
        "confirmations the leg reports. An empty list means it did not reach the gate at all."
    )


async def test_a_covenant_that_aged_past_the_window_is_refused_at_BOTH_LOCKED() -> None:
    """The refusal, through the real gate and the real transition.

    The depth GROWS between the taker's funding and the maker's revalidation — that is the whole
    point of a second run, and it is why the fixture bumps `report_confs` rather than starting
    high (starting high is refused at step 7 of the pre-fund gate, which is a different test).
    """
    secret, h = generate_secret()
    terms = _eth_terms(hashlock=h, eth_timeout_unix_s=_NOW + 40_000)
    rxd = FakeRadiantLeg(report_confs=1)
    coord = await _eth_to_btc_locked(
        leg=FakeEthLeg(preimage=secret, verdict=_final()), terms=terms, rxd=rxd, now_unix_s=_NOW
    )
    rxd.report_confs = 40
    with pytest.raises(ValidationError, match="open too EARLY"):
        await coord.post_asset_lock_revalidate(await rxd.expected_covenant_scriptpubkey(terms), now_unix_s=_NOW)
    assert coord.record.state is SwapState.BTC_LOCKED, "the maker must NOT advance to BOTH_LOCKED"
    assert rxd.claimed_with is None, "and must not have revealed p"


async def test_the_SAME_terms_still_reach_BOTH_LOCKED_at_the_fund_time_depth() -> None:
    """The paired honest path. Identical terms and deadline; only the covenant's age differs.

    Without this, the refusal above would be indistinguishable from a `t_rxd` that was simply too
    small — and a recheck that refuses the honest case is a defect, not a safe default.
    """
    secret, h = generate_secret()
    terms = _eth_terms(hashlock=h, eth_timeout_unix_s=_NOW + 40_000)
    rxd = FakeRadiantLeg(report_confs=1)
    coord = await _eth_to_btc_locked(
        leg=FakeEthLeg(preimage=secret, verdict=_final()), terms=terms, rxd=rxd, now_unix_s=_NOW
    )
    rec = await coord.post_asset_lock_revalidate(await rxd.expected_covenant_scriptpubkey(terms), now_unix_s=_NOW)
    assert rec.state is SwapState.BOTH_LOCKED


async def test_a_leg_that_cannot_report_the_depth_fails_closed(monkeypatch) -> None:
    """A missing depth read must REFUSE, not read as zero elapsed — zero is the permissive
    direction, and a gate that quietly falls back to it is the vacuous run all over again."""
    secret, h = generate_secret()
    terms = _eth_terms(hashlock=h, eth_timeout_unix_s=_NOW + 40_000)
    rxd = FakeRadiantLeg(report_confs=1)
    coord = await _eth_to_btc_locked(
        leg=FakeEthLeg(preimage=secret, verdict=_final()), terms=terms, rxd=rxd, now_unix_s=_NOW
    )
    # Removed AFTER the taker's own funding gate has used it, so this models the leg the maker's
    # process is wired with, not a swap that could never have been funded. monkeypatch restores it.
    monkeypatch.delattr(FakeRadiantLeg, "verify_maker_asset_funded")
    with pytest.raises(ValidationError, match="elapsed CSV depth"):
        await coord.post_asset_lock_revalidate(await rxd.expected_covenant_scriptpubkey(terms), now_unix_s=_NOW)
    assert coord.record.state is SwapState.BTC_LOCKED


def test_elapsed_blocks_cannot_be_omitted_by_a_caller() -> None:
    """Correct-by-construction, not documentation. The shipped defect was an OMISSION — the gate's
    own default of 0 applied because the call site said nothing — so the parameter carries no
    default and a caller that forgets it fails to construct rather than passing vacuously."""
    param = inspect.signature(SwapCoordinator._assert_eth_lock_timing_still_safe).parameters["elapsed_blocks"]
    assert param.default is inspect.Parameter.empty, (
        "elapsed_blocks has a default again — the next caller can reproduce #564 by omission"
    )
    assert param.kind is inspect.Parameter.KEYWORD_ONLY


# --------------------------------------------------------------------------------------------
# The ETH half — what it costs and what it buys, measured against the real gate.
# --------------------------------------------------------------------------------------------


def test_the_shipped_form_refused_nothing_on_the_whole_grid() -> None:
    """The claim that made #564 worth fixing, as a measurement rather than an argument.

    Anchored on the caller's clock with `elapsed_blocks=0`, the post-confirm run cannot fail from
    timing at all under the inverted relation: a later anchor only makes a LOWER bound easier to
    clear. 12,010 points, zero refusals.
    """
    depths = range(0, 1201)
    intervals = (1.0, 5.0, 9.0, 18.0, 36.0, 120.0, 221.0, 296.0, 600.0, 2325.0)
    checked = 0
    refused = []
    for depth in depths:
        for r in intervals:
            checked += 1
            if not _gate_at(depth=depth, realised_interval_s=r, elapsed_blocks=0):
                refused.append((depth, r))
    assert checked == 12_010, f"the grid changed size ({checked}); the count in the docstrings is stale"
    assert refused == [], f"the shipped form refused at {refused[:5]} — the vacuity claim is now wrong"


@pytest.mark.parametrize(
    ("depth", "boundary_s"),
    [(1, 12.0), (2, 24.0), (6, 32.0), (12, 34.0), (50, 35.52), (300, 35.92)],
)
def test_the_refusal_boundary_converges_on_the_fast_tail_from_below(depth: int, boundary_s: float) -> None:
    """The refusal boundary, bisected against the real gate — the numbers the docstrings quote.

    It refuses only BELOW the tail the terms were sized with, and approaches it asymptotically
    without reaching it. That is the whole honest-work argument: the only chain this gate refuses
    is one running faster than the p10 the sizer divided by, which is exactly the direction that
    eats the taker's claim window.
    """
    lo, hi = 0.0, 5000.0
    assert not _gate_at(depth=depth, realised_interval_s=lo, elapsed_blocks=depth), "should refuse at 0 s/blk"
    assert _gate_at(depth=depth, realised_interval_s=hi, elapsed_blocks=depth), "should pass at 5000 s/blk"
    for _ in range(80):
        mid = (lo + hi) / 2
        if _gate_at(depth=depth, realised_interval_s=mid, elapsed_blocks=depth):
            hi = mid
        else:
            lo = mid
    assert math.isclose(hi, boundary_s, abs_tol=0.01), f"depth {depth}: boundary moved to {hi:.4f} s/blk"
    assert hi < _FAST_TAIL_S, "the boundary must stay strictly below the fast tail"


@pytest.mark.parametrize("realised_s", [36.0, 221.0, 296.0, 671.0])
def test_it_refuses_no_depth_at_any_measured_radiant_interval(realised_s: float) -> None:
    """The honest-path sweep, paired with the refusal above: p10 36 s, median 221 s, mean 296 s and
    p90 671 s are the figures `eth_rxd_timelock` records from 720 mainnet intervals. At every one
    of them, at every covenant depth the window admits, the recheck passes."""
    t_rxd = _prod_t_rxd().value
    refused = [d for d in range(1, t_rxd) if not _gate_at(depth=d, realised_interval_s=realised_s, elapsed_blocks=d)]
    assert refused == [], f"refused at depths {refused[:5]} on a chain running at {realised_s} s/blk"


def test_what_the_depth_buys_a_chain_running_at_18_seconds() -> None:
    """The other side of the conditional: the case the fix exists for. At half the fast tail the
    shipped form passes at every depth and the fixed one refuses from depth 10 up."""
    fast_chain = 18.0
    shipped = [
        d for d in (1, 10, 20, 50, 300) if not _gate_at(depth=d, realised_interval_s=fast_chain, elapsed_blocks=0)
    ]
    assert shipped == [], "the shipped form is supposed to be blind here; it now refuses"
    fixed = [d for d in (1, 10, 20, 50, 300) if not _gate_at(depth=d, realised_interval_s=fast_chain, elapsed_blocks=d)]
    assert fixed == [10, 20, 50, 300], f"the fixed form refused at {fixed}, not from depth 10 up"


# --------------------------------------------------------------------------------------------
# The BTC half — the reason there is no twin, derived rather than asserted.
# --------------------------------------------------------------------------------------------

#: (t_rxd_blocks, margin_blocks, i_rxd, i_btc, burial). The runner's own defaults first
#: (`btc_swap_two_host.py`: t_rxd 120, margin 36, 300/600), then longer legs and a deeper burial,
#: so the property is not a coincidence of one parameter set.
_BTC_PARAMS = [
    (120, 36, 300.0, 600.0, ESTIMATED_RXD_CLAIM_BURIAL_BLOCKS),
    (120, 36, 221.0, 600.0, ESTIMATED_RXD_CLAIM_BURIAL_BLOCKS),
    (240, 36, 300.0, 600.0, ESTIMATED_RXD_CLAIM_BURIAL_BLOCKS),
    (720, 36, 300.0, 600.0, ESTIMATED_RXD_CLAIM_BURIAL_BLOCKS),
    (2000, 36, 300.0, 600.0, 20),
    (2000, 12, 300.0, 600.0, 20),
]


@pytest.mark.parametrize(("t_rxd", "margin", "i_rxd", "i_btc", "burial"), _BTC_PARAMS)
def test_the_btc_derivation_leaves_no_headroom_for_a_post_confirm_rerun(
    t_rxd: int, margin: int, i_rxd: float, i_btc: float, burial: int
) -> None:
    """WHY THE BTC CORRIDOR HAS NO POST-CONFIRM ORDERING RECHECK — derived from the production
    derivation, not restated from a review.

    `derive_counter_timelock` solves `t_rxd * i_rxd >= t_btc * i_btc + margin * i_btc` for the
    largest `t_btc` that survives `elapsed = elapsed_reserve_blocks(...)`. So the gate's accepted
    range ends at that reserve, plus at most the one flooring step the derivation's `//` leaves
    behind — a rounding artefact, never a budget for drift.

    Which is what forecloses the twin. A second run at revalidation necessarily sees a DEEPER
    covenant: depth only grows, and the maker waits `btc_claim_reorg_depth` BITCOIN blocks for the
    taker's funding to bury before it revalidates at all. Priced at the policy's own intervals that
    wait alone advances the covenant by `depth * i_btc / i_rxd` blocks, and this asserts that
    number is bigger than the whole headroom — so the rerun refuses honest, correctly-derived terms
    before any chain misbehaves.

    If this fails because the headroom grew, `derive_counter_timelock` has gained a drift reserve
    and the twin becomes writable. Re-read the exemption on
    `SwapCoordinator._assert_btc_counter_funding_verified` rather than editing these numbers.
    """
    reserve = elapsed_reserve_blocks(rxd_claim_burial_blocks=burial)
    t_btc = derive_counter_timelock(
        t_rxd_blocks=t_rxd,
        margin_blocks=margin,
        rxd_block_interval_s=i_rxd,
        btc_block_interval_s=i_btc,
        elapsed_reserve_blocks=reserve,
    )
    policy = MarginPolicy(
        margin=bt.Timelock(margin, bt.TimeUnit.BLOCKS),
        block_interval_s=i_btc,
        is_measured=False,
        rxd_block_interval_s=i_rxd,
        accept_flat_burial=True,
    )
    lock_btc = bt.Timelock(t_btc, bt.TimeUnit.BLOCKS)
    lock_rxd = bt.Timelock(t_rxd, bt.TimeUnit.BLOCKS)

    def accepts(elapsed: int) -> bool:
        try:
            assert_timelock_margin(lock_btc, lock_rxd, policy, elapsed_blocks=elapsed)
            return True
        except ValidationError:
            return False

    # Brute-forced, not solved: the boundary is whatever the real gate says it is.
    accepted = [e for e in range(0, t_rxd) if accepts(e)]
    assert accepted, "the derived terms are refused at every depth — the derivation itself is broken"
    max_accepted = max(accepted)
    assert accepted == list(range(0, max_accepted + 1)), "the accepted set is not a prefix; the gate is not monotone"

    headroom = max_accepted - reserve
    flooring_step = math.ceil(i_btc / i_rxd)
    assert 0 <= headroom <= flooring_step, (
        f"the gate accepts {headroom} blocks beyond the {reserve}-block reserve, which is more than "
        f"the {flooring_step}-block flooring artefact. derive_counter_timelock now leaves real "
        "headroom — re-read the exemption before concluding the twin is still unwritable."
    )
    # The honest maker's own wait, in Radiant blocks at the policy's intervals.
    honest_growth = ESTIMATED_BTC_CLAIM_REORG_DEPTH_BLOCKS * i_btc / i_rxd
    assert honest_growth > headroom, (
        f"waiting {ESTIMATED_BTC_CLAIM_REORG_DEPTH_BLOCKS} BTC blocks advances the covenant "
        f"{honest_growth:.1f} Radiant blocks, which now fits inside the {headroom}-block headroom — "
        "a post-confirm rerun may have become viable on the BTC corridor."
    )


def test_the_btc_ordering_gate_still_runs_only_at_fund_time() -> None:
    """The membership half of the same exemption: `assert_timelock_margin`'s production call sites.

    Both live inside `pre_btc_lock_check`. A third would be the post-confirm rerun the test above
    measured as refusing honest terms — so this fails and points at that measurement rather than
    letting the rerun land on the strength of the symmetry argument alone.
    """
    src = Path(sc.__file__).read_text()
    tree = ast.parse(src)
    enclosing: dict[int, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for sub in ast.walk(node):
                if isinstance(sub, ast.Call) and ast.unparse(sub.func).endswith("assert_timelock_margin"):
                    enclosing.setdefault(sub.lineno, node.name)
    assert enclosing, "no assert_timelock_margin call found in the coordinator — the scan has broken"
    assert sorted(set(enclosing.values())) == ["pre_btc_lock_check"], (
        f"assert_timelock_margin is now called from {sorted(set(enclosing.values()))}. If that is a "
        "post-confirm rerun, read the measurement on _assert_btc_counter_funding_verified first: "
        "both shapes of it refuse honest, production-derived terms."
    )
    assert len(enclosing) == 2, f"expected the two pre-fund call sites, found {len(enclosing)}"
