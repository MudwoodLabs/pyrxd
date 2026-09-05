"""#580 item 1: a watchtower page must never name a coordinator step the coordinator refuses.

``decide()`` assesses the claim race from CHAIN TRUTH and deliberately ignores ``record.state``
when deciding *whether* to page. It then used that same state-blindness to pick *which step to
name*, and the coordinator's two claim methods are strictly state-gated:

    taker_scrape_and_claim_asset       SECRET_REVEALED only
    taker_claim_asset_from_vulnerable  ASSET_VULNERABLE only
    taker_observed_reveal              BOTH_LOCKED only

So an ASSET_VULNERABLE record — the state the gate ITSELF creates when it squeezes — was paged
``taker_scrape_and_claim_asset``, which raises "only valid from SECRET_REVEALED". That is minutes
lost after ``p`` is public and under a running timelock, which is when minutes cost the asset.

THE REQUIRED STATES ARE READ OUT OF THE COORDINATOR'S SOURCE, not hand-typed here. A hand-kept
copy of "which step needs which state" is the shape that produced the defect in the first place:
the pattern already existed for exactly one action (``"investigate (mutual_refund is only valid
from BOTH_LOCKED)"``) and was never generalised. Both guard spellings are scanned — the
``is not SwapState.X`` form and ``taker_refund_btc``'s ``state not in (X, Y)`` form — because a
scanner that knows one spelling of a rule is blind to the other.
"""

from __future__ import annotations

import ast
import hashlib
import itertools
import os
import pathlib

import pytest

from pyrxd.btc_wallet import taproot as t
from pyrxd.gravity.finality import CounterClaimState
from pyrxd.gravity.swap_coordinator import MarginPolicy
from pyrxd.gravity.swap_state import (
    TERMINAL_STATES,
    NegotiatedTerms,
    SwapRecord,
    SwapState,
    can_transition,
)
from pyrxd.gravity.watch import Intent, Observations, decide

_COORDINATOR = pathlib.Path(__file__).resolve().parent.parent / "src" / "pyrxd" / "gravity" / "swap_coordinator.py"

# The three claim-flow steps this module is about, and nothing else — the sweep below asks only
# whether a NAMED step is runnable, so it needs the coordinator's whole guard map, but these are
# the ones a claim-race page may legitimately name.
_CLAIM_STEP_NAMES = frozenset(
    {"taker_observed_reveal", "taker_scrape_and_claim_asset", "taker_claim_asset_from_vulnerable"}
)


# ---------------------------------------------------------------------------
# Derive "which coordinator step accepts which states" from the coordinator's own guards
# ---------------------------------------------------------------------------


def _state_guards() -> dict[str, frozenset[SwapState]]:
    """``{method name: states it accepts}``, read off ``SwapCoordinator``'s own refusal guards.

    Recognises both spellings the coordinator actually uses:

    * ``if self.record.state is not SwapState.X: raise``      (one state)
    * ``if state not in (SwapState.X, SwapState.Y): raise``   (a set), where ``state`` is a local
      bound to ``self.record.state`` earlier in the same method.

    A method with no such guard is absent from the map: "accepts anything" and "we could not read
    its guard" are then the same answer, which is why the non-vacuity test below pins the map's
    contents rather than trusting the scan to have found something.
    """
    tree = ast.parse(_COORDINATOR.read_text())
    out: dict[str, frozenset[SwapState]] = {}
    for cls in (n for n in ast.walk(tree) if isinstance(n, ast.ClassDef) and n.name == "SwapCoordinator"):
        for fn in cls.body:
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            # Locals aliased to self.record.state, so `state not in (...)` is recognised too.
            aliases = {"self.record.state"}
            for node in ast.walk(fn):
                if (
                    isinstance(node, ast.Assign)
                    and len(node.targets) == 1
                    and isinstance(node.targets[0], ast.Name)
                    and ast.unparse(node.value) == "self.record.state"
                ):
                    aliases.add(node.targets[0].id)
            found: set[SwapState] = set()
            for node in ast.walk(fn):
                if not (isinstance(node, ast.If) and isinstance(node.test, ast.Compare)):
                    continue
                cmp_ = node.test
                if ast.unparse(cmp_.left) not in aliases or len(cmp_.ops) != 1:
                    continue
                if not any(isinstance(n, ast.Raise) for n in ast.walk(node)):
                    continue
                right = cmp_.comparators[0]
                if isinstance(cmp_.ops[0], ast.IsNot):
                    names = [ast.unparse(right)]
                elif isinstance(cmp_.ops[0], ast.NotIn) and isinstance(right, (ast.Tuple, ast.List, ast.Set)):
                    names = [ast.unparse(e) for e in right.elts]
                else:
                    continue
                if not all(n.startswith("SwapState.") for n in names):
                    continue
                found |= {SwapState[n.split(".", 1)[1]] for n in names}
            if found:
                # A method may carry the guard twice (the BTC body and its ETH variant); union is
                # wrong there only if the two disagree, and the pin below proves they do not.
                out[fn.name] = frozenset(found) if fn.name not in out else out[fn.name] | frozenset(found)
    return out


def test_the_guard_map_is_not_vacuous():
    """The scan must actually find the guards this whole module is derived from.

    Without this the sweep passes gloriously when the scanner returns ``{}`` — every named step
    would be "unconstrained" and nothing could ever fail. A vacuous pass is indistinguishable
    from a real one in the output, so it gets its own assertion.
    """
    guards = _state_guards()
    assert guards["taker_scrape_and_claim_asset"] == frozenset({SwapState.SECRET_REVEALED})
    assert guards["taker_claim_asset_from_vulnerable"] == frozenset({SwapState.ASSET_VULNERABLE})
    assert guards["taker_observed_reveal"] == frozenset({SwapState.BOTH_LOCKED})
    assert guards["mutual_refund"] == frozenset({SwapState.BOTH_LOCKED})
    # The OTHER spelling — `state not in (...)`. If the scanner ever loses this branch, this is
    # the assertion that says so rather than the sweep quietly under-checking.
    assert guards["taker_refund_btc"] == frozenset({SwapState.BTC_LOCKED, SwapState.PARAMS_MISMATCH})


# ---------------------------------------------------------------------------
# Fixtures (mirroring tests/test_watch_decide.py: t_rxd 72, t_btc 36, lock at 100)
# ---------------------------------------------------------------------------

LOCK = 100
REFUND_OPENS = LOCK + 72
SAFETY = 6


def _xonly() -> bytes:
    import coincurve

    return coincurve.PublicKeyXOnly.from_secret(os.urandom(32)).format()


def _terms(*, eth: bool = False) -> NegotiatedTerms:
    p = os.urandom(32)
    extra = {"counter_chain": "eth", "value_amount": 10**15, "eth_timeout_unix_s": 4_000_000_000} if eth else {}
    return NegotiatedTerms(
        hashlock=hashlib.sha256(p).digest(),
        btc_sats=100_000,
        radiant_amount=1_000,
        t_btc=t.Timelock(36, t.TimeUnit.BLOCKS),
        t_rxd=t.Timelock(72, t.TimeUnit.BLOCKS),
        asset_variant="ft",
        genesis_ref=b"\xaa" * 36,
        taker_dest_hash=b"\x11" * 32,
        maker_dest_hash=b"\x22" * 32,
        btc_claim_pubkey_xonly=_xonly() if not eth else b"\x00" * 32,
        btc_refund_pubkey_xonly=_xonly() if not eth else b"\x00" * 32,
        **extra,
    )


def _policy(*, eth: bool = False) -> MarginPolicy:
    return MarginPolicy(
        margin=t.Timelock(72, t.TimeUnit.BLOCKS),
        block_interval_s=600.0,
        is_measured=False,
        btc_claim_reorg_depth=t.Timelock(6, t.TimeUnit.BLOCKS),
        rxd_claim_burial=t.Timelock(2, t.TimeUnit.BLOCKS),
        rxd_block_interval_s=300.0,
        **({"eth_finalization_window_s": 768} if eth else {}),
    )


def _decide(state: SwapState, obs: Observations, *, eth: bool = False):
    return decide(
        record=SwapRecord(state=state, terms=_terms(eth=eth)),
        observations=obs,
        policy=_policy(eth=eth),
        safety_window_blocks=SAFETY,
    )


_NON_TERMINAL = sorted((s for s in SwapState if s not in TERMINAL_STATES), key=lambda s: s.value)


def _btc_claim_shapes() -> list[tuple[str, Observations]]:
    """Every BTC claim-race shape that emits an action: SAFE, SQUEEZED, and both fail-closed paths."""
    return [
        (
            "safe",
            Observations(
                maker_has_claimed_btc=True, now_rxd_height=150, asset_locked_at_height=LOCK, btc_claim_confirmations=6
            ),
        ),
        (
            "squeezed",
            Observations(
                maker_has_claimed_btc=True, now_rxd_height=171, asset_locked_at_height=LOCK, btc_claim_confirmations=1
            ),
        ),
        # Missing lock height / depth -> "finality un-assessable" fail-closed page.
        (
            "unassessable",
            Observations(
                maker_has_claimed_btc=True, now_rxd_height=150, asset_locked_at_height=None, btc_claim_confirmations=6
            ),
        ),
        # now < lock -> the gate raises -> the other fail-closed page.
        (
            "gate-raises",
            Observations(
                maker_has_claimed_btc=True, now_rxd_height=50, asset_locked_at_height=LOCK, btc_claim_confirmations=6
            ),
        ),
    ]


def _eth_claim_shapes() -> list[tuple[str, Observations]]:
    return [
        (
            "safe",
            Observations(
                maker_has_claimed_btc=False,
                eth_claim_detected=True,
                eth_claim_finality=CounterClaimState.FINAL,
                now_rxd_height=150,
                asset_locked_at_height=LOCK,
            ),
        ),
        (
            "squeezed",
            Observations(
                maker_has_claimed_btc=False,
                eth_claim_detected=True,
                eth_claim_finality=CounterClaimState.FINAL,
                now_rxd_height=171,
                asset_locked_at_height=LOCK,
            ),
        ),
        (
            "unassessable",
            Observations(
                maker_has_claimed_btc=False,
                eth_claim_detected=True,
                eth_claim_finality=None,
                now_rxd_height=150,
                asset_locked_at_height=LOCK,
            ),
        ),
        (
            "gate-raises",
            Observations(
                maker_has_claimed_btc=False,
                eth_claim_detected=True,
                eth_claim_finality=CounterClaimState.FINAL,
                now_rxd_height=50,
                asset_locked_at_height=LOCK,
            ),
        ),
    ]


def _named_steps(action: str, guards: dict[str, frozenset[SwapState]]) -> list[str]:
    """Coordinator step names the action string INSTRUCTS the operator to run, in order.

    An ``investigate`` page is exempt by design: it names steps only to say which state each one
    NEEDS, which is the opposite of instructing the operator to run one. That exemption is not a
    hole — ``test_no_step_states_pages_investigate_and_says_why`` pins what it must contain.
    """
    if action.startswith("investigate"):
        return []
    return sorted((n for n in guards if n in action), key=action.index)


# ---------------------------------------------------------------------------
# The sweep: no page, in any state, on either counter-chain, may name an unrunnable step
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("eth", [False, True], ids=["btc", "eth"])
@pytest.mark.parametrize("state", _NON_TERMINAL, ids=lambda s: s.value)
def test_no_claim_page_names_a_step_the_record_cannot_run(state, eth):
    guards = _state_guards()
    shapes = _eth_claim_shapes() if eth else _btc_claim_shapes()
    saw_action = False
    for label, obs in shapes:
        d = _decide(state, obs, eth=eth)
        if d.recommended_action is None:
            continue
        saw_action = True
        steps = _named_steps(d.recommended_action, guards)
        if not steps:
            assert d.recommended_action.startswith("investigate"), (
                f"{state.value}/{label}: an action naming no coordinator step must say so: {d.recommended_action!r}"
            )
            continue
        first = steps[0]
        assert state in guards[first], (
            f"{state.value}/{label} (eth={eth}) pages {first!r}, which the coordinator refuses from "
            f"{state.value} (it accepts only {sorted(s.value for s in guards[first])}). "
            f"Full action: {d.recommended_action!r}"
        )
    assert saw_action, f"{state.value} (eth={eth}) produced no actionable page — the sweep ran empty here"


@pytest.mark.parametrize("eth", [False, True], ids=["btc", "eth"])
@pytest.mark.parametrize("state", _NON_TERMINAL, ids=lambda s: s.value)
def test_named_step_sequences_are_real_fsm_walks(state, eth):
    """A multi-step page must be a walk the state machine can actually take.

    Naming a state-valid FIRST step and then an unreachable second one would pass the sweep above
    and still strand the operator one step in. Each consecutive pair must have an FSM edge from a
    state the earlier step accepts to a state the later one requires.
    """
    guards = _state_guards()
    for _label, obs in _eth_claim_shapes() if eth else _btc_claim_shapes():
        d = _decide(state, obs, eth=eth)
        steps = _named_steps(d.recommended_action or "", guards)
        for before, after in itertools.pairwise(steps):
            assert any(can_transition(src, dst) for src in guards[before] for dst in guards[after]), (
                f"{state.value}: {before!r} cannot lead to {after!r} — no FSM edge between their states"
            )


# ---------------------------------------------------------------------------
# The specific cases, named
# ---------------------------------------------------------------------------


def test_asset_vulnerable_with_a_final_claim_pages_the_vulnerable_step():
    """The issue's own reproduction: ASSET_VULNERABLE + a 6-conf maker claim.

    Chain truth still drives the PAGE (the gate says SAFE), and that is unchanged — only the step
    name is now one the record can run.
    """
    obs = Observations(
        maker_has_claimed_btc=True, now_rxd_height=150, asset_locked_at_height=LOCK, btc_claim_confirmations=6
    )
    d = _decide(SwapState.ASSET_VULNERABLE, obs)
    assert d.intent is Intent.PAGE_CLAIM
    assert d.recommended_action == "taker_claim_asset_from_vulnerable"
    assert d.deadline_rxd_height == REFUND_OPENS


def test_both_locked_lagging_record_is_told_to_observe_the_reveal_first():
    """The chain-truth-dominates case the module docstring calls spec-flow Gap 2/7.

    ``taker_scrape_and_claim_asset`` alone is refused from BOTH_LOCKED; ``taker_observed_reveal``
    is the taker-side transition that makes it runnable.
    """
    obs = Observations(
        maker_has_claimed_btc=True, now_rxd_height=150, asset_locked_at_height=LOCK, btc_claim_confirmations=6
    )
    d = _decide(SwapState.BOTH_LOCKED, obs)
    assert d.intent is Intent.PAGE_CLAIM
    assert d.recommended_action == "taker_observed_reveal, then taker_scrape_and_claim_asset"


def test_secret_revealed_squeeze_does_not_lead_with_the_vulnerable_only_step():
    """The mirror defect: the SQUEEZED page named ``taker_claim_asset_from_vulnerable`` with no
    state check, so a SECRET_REVEALED record got an ASSET_VULNERABLE-only step."""
    obs = Observations(
        maker_has_claimed_btc=True, now_rxd_height=171, asset_locked_at_height=LOCK, btc_claim_confirmations=1
    )
    d = _decide(SwapState.SECRET_REVEALED, obs)
    assert d.intent is Intent.PAGE_SQUEEZED
    assert d.recommended_action.startswith("taker_scrape_and_claim_asset")
    assert d.recommended_action.endswith("then taker_claim_asset_from_vulnerable (winner-take-all) vs accept loss")


def test_asset_vulnerable_squeeze_is_unchanged():
    """The one state the old string was already right for — pinned so the fix cannot regress it."""
    obs = Observations(
        maker_has_claimed_btc=True, now_rxd_height=171, asset_locked_at_height=LOCK, btc_claim_confirmations=1
    )
    d = _decide(SwapState.ASSET_VULNERABLE, obs)
    assert d.recommended_action == "taker_claim_asset_from_vulnerable (winner-take-all) vs accept loss"


def test_secret_revealed_safe_page_still_names_the_plain_step():
    """THE HONEST PATH. The overwhelmingly common case must keep the one-word action it had — a
    fix that made every page a paragraph would be its own operator-facing defect."""
    obs = Observations(
        maker_has_claimed_btc=True, now_rxd_height=150, asset_locked_at_height=LOCK, btc_claim_confirmations=6
    )
    d = _decide(SwapState.SECRET_REVEALED, obs)
    assert d.intent is Intent.PAGE_CLAIM
    assert d.recommended_action == "taker_scrape_and_claim_asset"
    # And the autonomy discriminator is untouched — #580 is an alert-text fix, not an arming change.
    assert d.autonomous_asset_claim is True


@pytest.mark.parametrize(
    "state", [SwapState.PARAMS_MISMATCH, SwapState.MAKER_STALLS, SwapState.BTC_LOCKED, SwapState.NEGOTIATED]
)
def test_no_step_states_page_investigate_and_say_why(state):
    """States with no valid claim step get a REPORT, not a step name and not silence.

    The page still goes out, at the same severity, with the same deadline — refusing to page here
    would be far worse than naming a wrong step. It just says which step needs which state, so the
    operator learns it from the page instead of from a ValidationError.
    """
    obs = Observations(
        maker_has_claimed_btc=True, now_rxd_height=150, asset_locked_at_height=LOCK, btc_claim_confirmations=6
    )
    d = _decide(state, obs)
    assert d.intent is Intent.PAGE_CLAIM  # still paged
    action = d.recommended_action
    assert action.startswith("investigate")
    assert state.value in action
    for step in _CLAIM_STEP_NAMES:
        assert step in action, f"the investigate page must say what {step} needs"


def test_eth_branch_gets_the_same_treatment():
    """The ETH arm carried a byte-identical copy of the defect; it must carry the fix too."""
    obs = Observations(
        maker_has_claimed_btc=False,
        eth_claim_detected=True,
        eth_claim_finality=CounterClaimState.FINAL,
        now_rxd_height=150,
        asset_locked_at_height=LOCK,
    )
    assert _decide(SwapState.ASSET_VULNERABLE, obs, eth=True).recommended_action == "taker_claim_asset_from_vulnerable"
    assert (
        _decide(SwapState.BOTH_LOCKED, obs, eth=True).recommended_action
        == "taker_observed_reveal, then taker_scrape_and_claim_asset"
    )
    # ETH SAFE must still NOT arm the BTC-only autonomous claim discriminator.
    assert _decide(SwapState.SECRET_REVEALED, obs, eth=True).autonomous_asset_claim is False
