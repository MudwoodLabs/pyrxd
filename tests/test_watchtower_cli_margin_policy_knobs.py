"""#580 item 2: every MarginPolicy knob a measured watchtower needs must be settable from the CLI.

``--measured`` is real-value mode. It built the policy through ``MarginPolicy.measured()`` while
never passing ``rxd_claim_inclusion`` — the blocks reserved for the taker's own claim to be MINED
before its burial starts counting — so a real-value tower ran on the shipped ESTIMATE of 2 with no
flag to change it. On a congested Radiant mempool where claims routinely take 5 blocks to be mined,
``_claim_floor_blocks`` reserved 2, and the gate certified SAFE at a height where the claim could
not be mined in time, let alone buried. ``burial_safety_factor`` was unreachable the same way.

This is the same shape as the ``rxd_block_interval_fast_s`` HIGH fixed earlier: a knob added to the
policy and never wired to the entry point. The field's own comment already made the argument one
layer in — *"a knob only settable through the raw dataclass is not a knob"* — and it applies to the
CLI too.

SO THE GUARD IS DERIVED FROM THE SIGNATURE, not from a list of the two knobs that happened to be
missing today. ``MarginPolicy.measured``'s own parameters are read with ``inspect``, the forwarded
set is read out of ``_policy_from_args``'s AST, and they are compared BOTH WAYS. The next field
someone adds is a failing test rather than another silently-unreachable knob.
"""

from __future__ import annotations

import ast
import dataclasses
import hashlib
import inspect
import logging
import os
import pathlib

import pytest

from pyrxd.btc_wallet import taproot as t
from pyrxd.gravity.finality import CounterClaimFinality, CounterClaimState
from pyrxd.gravity.swap_coordinator import (
    ESTIMATED_RXD_CLAIM_INCLUSION_BLOCKS,
    ClaimFinality,
    MarginPolicy,
    assess_claim_finality,
)
from pyrxd.gravity.swap_state import NegotiatedTerms, SwapRecord, SwapState
from pyrxd.gravity.watch import Intent, Observations, decide
from pyrxd.gravity.watch import run as run_module
from pyrxd.gravity.watch.run import _parse_args, _policy_from_args, _report_claim_reserves

_RUN_PY = pathlib.Path(__file__).resolve().parent.parent / "src" / "pyrxd" / "gravity" / "watch" / "run.py"

#: :class:`MarginPolicy` FIELDS the tower deliberately does NOT set, each with the reason. A tower
#: flag would be WRONG for these, not merely missing — so they are exempt, not overlooked.
#:
#: Keyed on FIELDS, not on ``measured()``'s parameters, because that is the universe the guards
#: below now run over — see ``test_every_margin_policy_FIELD_is_reachable_from_the_cli``.
_NOT_A_TOWER_KNOB: dict[str, str] = {
    # One tower watches MANY swaps, and the value at risk is per-swap. decide() supplies it from
    # each record's own terms (`_value_at_risk_photons`); a single chain-wide flag would apply one
    # swap's value to all of them.
    "value_at_risk_photons": "per-swap; decide() reads it from each record's own terms",
    # Set by the constructors themselves — `estimated()` pins is_measured=False, `measured()` pins
    # both True. The CLI chooses between them with `--measured`, which IS the flag for these.
    "is_measured": "chosen by --measured, which picks the constructor",
    "require_measured": "chosen by --measured, which picks the constructor",
    # FUND-TIME gates only: `SwapCoordinator` reads these in `assert_eth_ordering` /
    # the post-confirm recheck, i.e. before and around the taker's funding broadcast. The
    # watchtower never funds anything (alert-only, keyless) and never calls those gates —
    # `test_the_fund_time_only_fields_really_are_unread_by_the_tower` is the evidence, not this
    # sentence.
    "cross_clock_margin": "fund-time ETH ordering gate; no watchtower code path reads it",
    "max_covenant_confirm_wait_s": "fund-time ETH ordering gate; no watchtower code path reads it",
}


def _forwarded_keywords(*ctors: str) -> set[str]:
    """Keyword names ``_policy_from_args`` passes to the named ``MarginPolicy`` constructors.

    Defaults to ``measured`` alone, which is what the two original guards ask about. The
    field-level guard passes both, because the ESTIMATED branch is a real production policy too:
    an alert-only tower watching an ETH counter leg builds its policy there.
    """
    ctors = ctors or ("measured",)
    tree = ast.parse(_RUN_PY.read_text())
    fn = next(
        n
        for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == "_policy_from_args"
    )
    wanted = {f"MarginPolicy.{c}" for c in ctors}
    calls = [n for n in ast.walk(fn) if isinstance(n, ast.Call) and ast.unparse(n.func) in wanted]
    assert calls, f"_policy_from_args no longer calls {sorted(wanted)} — this guard has stopped running"
    return {kw.arg for call in calls for kw in call.keywords if kw.arg is not None}


def test_every_measured_policy_knob_is_reachable_from_the_cli():
    """DIRECTION 1: a constructor parameter with no CLI route is an unreachable knob."""
    params = {
        name
        for name, p in inspect.signature(MarginPolicy.measured).parameters.items()
        if p.kind is inspect.Parameter.KEYWORD_ONLY
    }
    assert params, "could not read MarginPolicy.measured's parameters — this guard is running empty"
    missing = params - _forwarded_keywords() - set(_NOT_A_TOWER_KNOB)
    assert not missing, (
        f"MarginPolicy.measured takes {sorted(missing)}, which --measured cannot set: the tower "
        "silently uses the default. Either wire a flag in _policy_from_args or add it to "
        "_NOT_A_TOWER_KNOB with the reason."
    )


def test_the_cli_forwards_nothing_the_constructor_does_not_take():
    """DIRECTION 2: a forwarded keyword that is no longer a parameter is a check that has stopped
    running (and a TypeError waiting for the first --measured operator)."""
    params = set(inspect.signature(MarginPolicy.measured).parameters)
    assert not (_forwarded_keywords() - params)


def test_the_exemption_list_still_names_real_parameters():
    """An exemption for a field that no longer exists is a stale excuse hiding a real gap.

    Checked against the DATACLASS, not against ``measured()``'s signature — the exemption list now
    covers fields that constructor never took, which is the blind spot this file's field-level
    guard exists to close.
    """
    stale = set(_NOT_A_TOWER_KNOB) - _policy_field_names()
    assert not stale, f"{sorted(stale)} are exempt from a check about fields MarginPolicy no longer has"


# ---------------------------------------------------------------------------
# The guard's UNIVERSE: MarginPolicy's fields, not one constructor's signature
# ---------------------------------------------------------------------------
#
# The two guards above ask "does every parameter of `MarginPolicy.measured` reach the CLI?", and
# the AST derivation below asks the same question of that constructor's call keywords. Both take
# `measured()`'s SIGNATURE as the definition of "the set of policy knobs" — so a field that
# constructor never accepted is invisible to both, and passes them vacuously.
#
# `eth_finalization_window_s` was exactly that. It is required (non-None) for a finalized-checkpoint
# counter leg: without it `assess_claim_finality` RAISES on every depth-less verdict, `_decide_eth`
# catches that and pages `PAGE_SQUEEZED` "verify finality manually", and a tower watching a healthy
# ETH swap did so on EVERY tick for the whole window between the maker's claim and its finalized
# checkpoint (~13 min steady-state; hours during a finality stall, which is the case the stall
# budget exists for). The guards written to stop precisely this class reported clean throughout —
# the mechanism built to catch a class carrying the error of the instance it was built from.
#
# So the universe is `dataclasses.fields(MarginPolicy)`, the way `_float_field_names` already does
# it one layer in, minus an exemption list that is itself checked against those fields.


def _policy_field_names() -> set[str]:
    names = {f.name for f in dataclasses.fields(MarginPolicy)}
    assert names, "could not read MarginPolicy's fields — this guard is running empty"
    return names


def _unreachable_policy_fields(field_names: set[str]) -> set[str]:
    """Of ``field_names``, those no ``MarginPolicy`` constructor call in ``_policy_from_args``
    passes and that are not exempt. Takes its universe as an ARGUMENT so the mechanism can be
    tested against a field it was not built from."""
    return set(field_names) - _forwarded_keywords("measured", "estimated") - set(_NOT_A_TOWER_KNOB)


def test_every_margin_policy_FIELD_is_reachable_from_the_cli():
    """DIRECTION 1, widened: a FIELD with no CLI route is an unreachable knob, whether or not
    ``measured()`` happens to name it.

    SCOPE, STATED RATHER THAN LEFT TO BE ASSUMED. This asks whether SOME constructor call in
    ``_policy_from_args`` forwards the field — not whether BOTH do. A field wired into the
    ``--measured`` branch and dropped from the estimated one still passes here, and that was
    confirmed by planting it: removing only the estimated-branch forwarding of
    ``eth_finalization_window_s`` left this test green while five behavioural tests below went red
    (``test_the_eth_window_comes_from_the_chain_id_and_is_PER_CHAIN``,
    ``test_the_window_changes_what_the_watchtower_PAGES_for_an_ETH_swap`` among them). Which fields
    an ALERT-ONLY tower needs is a judgement no AST scan answers honestly, so that half is covered
    by tests that build a policy with the shipped parser and look at what the tower does with it.
    """
    missing = _unreachable_policy_fields(_policy_field_names())
    assert not missing, (
        f"MarginPolicy has {sorted(missing)}, which no watchtower invocation can set: the tower "
        "silently uses the field default. Wire a flag in _policy_from_args (BOTH branches, if an "
        "alert-only tower needs it) or add it to _NOT_A_TOWER_KNOB with the reason."
    )


def test_the_field_universe_is_strictly_wider_than_the_constructor_signature():
    """NON-VACUITY, and the whole argument for this section in one assertion.

    If the two sets were equal, the field-level guard would be a restatement of the
    signature-level one and would have been blind to `eth_finalization_window_s` in the same way.
    """
    params = {
        name
        for name, p in inspect.signature(MarginPolicy.measured).parameters.items()
        if p.kind is inspect.Parameter.KEYWORD_ONLY
    }
    fields = _policy_field_names()
    assert fields > params, (
        "MarginPolicy.measured now names every field, so this guard has stopped adding anything — "
        "check whether the signature-derived guards are still the narrower ones."
    )


def test_the_field_guard_catches_a_field_it_was_NOT_built_from():
    """SCOPE, not instance. Planting the demonstrated defect proves nothing about generality: a fix
    at the site and a fix of the class behave identically on it. So run the mechanism over a field
    name that has nothing to do with ETH finality and check it is reported."""
    assert _unreachable_policy_fields({"a_knob_nobody_wired_up"}) == {"a_knob_nobody_wired_up"}
    # ...and the reverse: a name that IS forwarded must not be reported, or the guard would fire on
    # everything and its passing would mean nothing.
    assert _unreachable_policy_fields({"block_interval_s"}) == set()


def test_the_fund_time_only_fields_really_are_unread_by_the_tower():
    """The EVIDENCE for two exemptions above, rather than the sentence asserting it.

    ``cross_clock_margin`` and ``max_covenant_confirm_wait_s`` are exempt because no watchtower
    code path reads them. That is a claim about coverage, and claims about coverage were wrong
    every time they were checked in this codebase — so check it: nothing in the shipped
    ``pyrxd.gravity.watch`` package names either attribute.
    """
    watch_pkg = pathlib.Path(run_module.__file__).parent
    modules = sorted(watch_pkg.rglob("*.py"))
    assert modules, "found no watchtower modules to scan — this check is running empty"
    reads = {
        (p.name, node.lineno)
        for p in modules
        for node in ast.walk(ast.parse(p.read_text()))
        if isinstance(node, ast.Attribute) and node.attr in {"cross_clock_margin", "max_covenant_confirm_wait_s"}
    }
    assert not reads, f"the exemption says the tower never reads these; it does, at {sorted(reads)}"


def test_the_tower_never_reads_policy_margin_so_its_parser_default_is_inert():
    """Why ``--margin-blocks``'s parser default (72) is left disagreeing with
    ``ESTIMATED_DEFAULT_MARGIN_BLOCKS`` (36) instead of being "aligned".

    ``policy.margin`` is consumed by ``assert_timelock_margin``, which is a FUND-TIME gate: the
    only callers are ``SwapCoordinator``'s own funding paths. The watchtower neither reads the
    field nor calls that gate, so the number it carries changes no verdict — and 72 is the more
    conservative of the two, so lowering it would move a fund-relevant field in the unsafe
    direction to fix nothing. Both halves are checked here rather than asserted in prose.
    """
    watch_pkg = pathlib.Path(run_module.__file__).parent
    modules = sorted(watch_pkg.rglob("*.py"))
    assert modules, "found no watchtower modules to scan — this check is running empty"
    trees = {p.name: ast.parse(p.read_text()) for p in modules}
    margin_reads = {
        (name, node.lineno)
        for name, tree in trees.items()
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute) and node.attr == "margin"
    }
    assert not margin_reads, f"something in the tower now reads .margin, at {sorted(margin_reads)}"
    gate_calls = {
        (name, node.lineno)
        for name, tree in trees.items()
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and ast.unparse(node.func).endswith("assert_timelock_margin")
    }
    assert not gate_calls, f"the tower now calls assert_timelock_margin, at {sorted(gate_calls)}"


# ---------------------------------------------------------------------------
# Through the SHIPPED parser: the flag must change the gate's verdict, not just a field
# ---------------------------------------------------------------------------

_MEASURED = ["--records-dir", "/tmp/x", "--measured", "--rxd-block-interval-fast-s", "36", "--accept-flat-burial"]


def _policy(*extra: str) -> MarginPolicy:
    return _policy_from_args(_parse_args([*_MEASURED, *extra]))


def test_measured_without_the_flag_still_uses_the_shipped_estimate():
    """THE HONEST PATH: an existing --measured invocation keeps working, unchanged."""
    p = _policy()
    assert p.require_measured is True
    assert p.rxd_claim_inclusion == t.Timelock(ESTIMATED_RXD_CLAIM_INCLUSION_BLOCKS, t.TimeUnit.BLOCKS)
    assert p.burial_safety_factor == 1.0


def test_the_inclusion_flag_reaches_the_policy_through_the_shipped_parser():
    assert _policy("--rxd-claim-inclusion", "5").rxd_claim_inclusion == t.Timelock(5, t.TimeUnit.BLOCKS)


def test_the_safety_factor_flag_reaches_the_policy_through_the_shipped_parser():
    assert _policy("--burial-safety-factor", "2.5").burial_safety_factor == 2.5


def test_the_inclusion_flag_changes_the_gate_verdict():
    """The knob must MOVE THE VERDICT, not merely land in a field.

    lock=100, t_rxd=72 -> the maker's refund opens at 172. Flat burial is 2, so the claim floor is
    ``2 + rxd_claim_inclusion``. At height 167 there are 5 blocks left: enough at the estimate of
    2 (floor 4), not enough at a measured 5 (floor 7). Those are the two sides of the operator's
    scenario — a congested mempool where the estimate certifies a claim that cannot be mined.
    """
    args = {
        "counter_claim_finality": CounterClaimFinality.from_btc_depth(6, 6),
        "now_rxd_height": 167,
        "asset_locked_at_height": 100,
        "t_rxd": t.Timelock(72, t.TimeUnit.BLOCKS),
    }
    assert assess_claim_finality(policy=_policy(), **args) is ClaimFinality.SAFE
    assert assess_claim_finality(policy=_policy("--rxd-claim-inclusion", "5"), **args) is ClaimFinality.SQUEEZED


def _record() -> SwapRecord:
    import coincurve

    p = os.urandom(32)
    xonly = lambda: coincurve.PublicKeyXOnly.from_secret(os.urandom(32)).format()  # noqa: E731
    return SwapRecord(
        state=SwapState.SECRET_REVEALED,
        terms=NegotiatedTerms(
            hashlock=hashlib.sha256(p).digest(),
            btc_sats=100_000,
            radiant_amount=1_000,
            t_btc=t.Timelock(36, t.TimeUnit.BLOCKS),
            t_rxd=t.Timelock(72, t.TimeUnit.BLOCKS),
            asset_variant="ft",
            genesis_ref=b"\xaa" * 36,
            taker_dest_hash=b"\x11" * 32,
            maker_dest_hash=b"\x22" * 32,
            btc_claim_pubkey_xonly=xonly(),
            btc_refund_pubkey_xonly=xonly(),
        ),
    )


def test_the_flag_changes_what_the_watchtower_PAGES():
    """Through the tower's own decision core, which is what an operator actually experiences: the
    same swap at the same height pages CLAIM on the estimate and SQUEEZED on the measurement."""
    obs = Observations(
        maker_has_claimed_btc=True, now_rxd_height=167, asset_locked_at_height=100, btc_claim_confirmations=6
    )
    kw = {"record": _record(), "observations": obs, "safety_window_blocks": 6}
    assert decide(policy=_policy(), **kw).intent is Intent.PAGE_CLAIM
    assert decide(policy=_policy("--rxd-claim-inclusion", "5"), **kw).intent is Intent.PAGE_SQUEEZED


# ---------------------------------------------------------------------------
# ...and the number REACHES A HUMAN
# ---------------------------------------------------------------------------


# Taken from the module rather than written out: the tower logs to "pyrxd.watchtower", not its
# module path, and a literal here that drifts from it captures nothing while every INFO assertion
# below still LOOKS like it ran (a WARNING assertion would pass anyway — root captures those).
_LOGGER = run_module.logger.name


def _report(caplog, *extra: str) -> str:
    args = _parse_args([*_MEASURED, *extra])
    caplog.clear()
    with caplog.at_level(logging.INFO, logger=_LOGGER):
        _report_claim_reserves(_policy_from_args(args), requested_inclusion_blocks=args.rxd_claim_inclusion)
    assert caplog.records, f"nothing was logged to {_LOGGER!r} — the report reaches no human"
    return "\n".join(r.getMessage() for r in caplog.records)


def test_the_reserves_are_printed_where_an_operator_will_see_them(caplog):
    """A knob whose effect is invisible is half a knob. The reserve appeared on no surface at all
    before this — the operator could neither confirm the flag took nor tell an estimate was in use."""
    text = _report(caplog, "--rxd-claim-inclusion", "5")
    assert "rxd_claim_inclusion=5 blk" in text
    assert "measured, --rxd-claim-inclusion" in text
    # 2 (burial) + 5 (inclusion) — the same number _claim_floor_blocks computes, from that function.
    assert "flat floor 7 RXD block(s)" in text


def test_a_real_value_tower_on_the_estimate_says_so_loudly(caplog):
    text = _report(caplog)
    assert "SHIPPED ESTIMATE" in text
    assert any(r.levelno >= logging.WARNING for r in caplog.records), "the estimate warning must be a WARNING"
    assert "--rxd-claim-inclusion" in text


def test_supplying_the_measurement_silences_the_warning(caplog):
    """PAIRED WITH THE WARNING ABOVE: an operator who did the work must not be nagged, or the
    warning becomes noise and stops being read."""
    _report(caplog, "--rxd-claim-inclusion", "5")
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]


def test_the_estimated_alert_only_tower_reports_but_does_not_warn(caplog):
    """The default alert-only tower is not in real-value mode, so the estimate is fine there — it
    still reports the numbers, because they are what every page's verdict is computed from."""
    args = _parse_args(["--records-dir", "/tmp/x"])
    caplog.clear()
    with caplog.at_level(logging.INFO, logger=_LOGGER):
        _report_claim_reserves(_policy_from_args(args), requested_inclusion_blocks=args.rxd_claim_inclusion)
    assert "claim-race reserves (estimated policy)" in "\n".join(r.getMessage() for r in caplog.records)
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]


def test_the_report_has_a_production_caller():
    """A report nothing calls is not a report. ``_amain`` must invoke it on the path every tower
    start takes — the same reachability check that this whole issue is an instance of."""
    tree = ast.parse(_RUN_PY.read_text())
    fn = next(
        n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == "_amain"
    )
    assert any(isinstance(n, ast.Call) and ast.unparse(n.func) == "_report_claim_reserves" for n in ast.walk(fn)), (
        "_amain does not call _report_claim_reserves — the reserves reach no human"
    )


@pytest.mark.parametrize("bad", ["0", "-1"])
def test_an_impossible_inclusion_reserve_is_refused(bad):
    """The policy's floor of 1 (a claim broadcast at H cannot be mined at H) still applies through
    the flag — the CLI must not be a way around a construction-time floor."""
    from pyrxd.security.errors import ValidationError

    with pytest.raises(ValidationError):
        _policy("--rxd-claim-inclusion", bad)


# ---------------------------------------------------------------------------
# The OTHER branch: without --measured, a policy flag must be REFUSED, never dropped
# ---------------------------------------------------------------------------
#
# The AST guard above derives its set from calls to ``MarginPolicy.measured`` — so it covers the
# ``--measured`` branch completely and says nothing at all about the one below it. The estimated
# branch called ``MarginPolicy.estimated(block_interval_s=..., accept_flat_burial=...)`` and
# forwarded neither ``--rxd-claim-inclusion`` nor ``--burial-safety-factor`` (nor ten others),
# while ``_report_claim_reserves`` derived its provenance label from the ARGV rather than from the
# policy — so the surface #580 added so an operator could confirm the flag TOOK was the surface
# that certified a flag that had been dropped. Measured on the shipped parser before the fix:
#
#   --rxd-claim-inclusion 5 --burial-safety-factor 3
#     -> "rxd_claim_inclusion=2 blk (measured, --rxd-claim-inclusion) ... burial_safety_factor=1.00"
#
# Every reserve assertion in this file ran under ``_MEASURED``, and the one estimated-path test
# passed no flags, so the combination was never exercised.


def _policy_from_args_ast() -> ast.FunctionDef:
    tree = ast.parse(_RUN_PY.read_text())
    return next(
        n
        for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == "_policy_from_args"
    )


def _args_attribute_reads(*nodes: ast.AST) -> set[str]:
    """Every ``args.<dest>`` named anywhere under these nodes."""
    return {
        n.attr
        for node in nodes
        for n in ast.walk(node)
        if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id == "args"
    }


def _derived_measured_only_flags() -> set[str]:
    """Recompute ``_MEASURED_ONLY_POLICY_FLAGS`` from the code, so the tuple is not its own witness.

    ``{dests read under ``if args.measured:``} - {dests the estimated path also reads}``. The
    measured branch delegates to ``_reorg_cost_from_args``, so its reads count too — after checking
    that it is called from the measured branch ONLY, which is what makes attributing them here
    correct rather than convenient.
    """
    fn = _policy_from_args_ast()
    branch = next(n for n in fn.body if isinstance(n, ast.If) and ast.unparse(n.test) == "args.measured")
    rest = [n for n in fn.body if n is not branch]

    helper_calls = [
        n for n in ast.walk(fn) if isinstance(n, ast.Call) and ast.unparse(n.func) == "_reorg_cost_from_args"
    ]
    assert helper_calls, "_policy_from_args no longer calls _reorg_cost_from_args — this derivation has broken"
    in_branch = {id(n) for n in ast.walk(branch)}
    assert all(id(c) in in_branch for c in helper_calls), (
        "_reorg_cost_from_args is now called outside the --measured branch; its argument reads can "
        "no longer be attributed to that branch alone"
    )
    helper = next(
        n
        for n in ast.walk(ast.parse(_RUN_PY.read_text()))
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == "_reorg_cost_from_args"
    )

    inside = _args_attribute_reads(*branch.body, helper)
    outside = _args_attribute_reads(*rest, *branch.orelse)
    return inside - outside - {"measured"}


def test_the_measured_only_flag_list_matches_the_code_both_ways():
    """The tell is a tuple of names near the top of a file; this is what produces that list.

    Both directions: a knob wired into the measured branch and left off the tuple is silently
    dropped again on the estimated branch (the original defect), and a name on the tuple the
    measured branch no longer reads is a refusal with nothing behind it.
    """
    derived = _derived_measured_only_flags()
    assert derived, "the derivation found no measured-only flags — it has stopped running"
    listed = set(run_module._MEASURED_ONLY_POLICY_FLAGS)
    assert listed == derived, (
        f"_MEASURED_ONLY_POLICY_FLAGS is stale: missing {sorted(derived - listed)}, extra {sorted(listed - derived)}"
    )


def test_the_two_flags_the_review_found_are_in_that_set():
    """Non-vacuity, named. A derivation that returned the wrong set would still satisfy the
    equality above, because the tuple would have been written from the same wrong derivation."""
    assert {"rxd_claim_inclusion", "burial_safety_factor"} <= set(run_module._MEASURED_ONLY_POLICY_FLAGS)


def test_a_flag_with_a_LIVE_OUTSIDE_USE_is_warned_about_not_refused(caplog):
    """The honest-path partner to the refusal above, and the case it originally got wrong.

    `--rxd-block-interval-s` was in that parametrisation until this change. It also feeds
    `preflight_timing`, so supplying it without `--measured` genuinely does something — refusing it
    was a guard refusing valid work, and it pushed the operator toward the 300 s default, silencing
    the very warning about paging after the safety window."""
    import logging

    with caplog.at_level(logging.WARNING, logger=run_module.logger.name):
        policy = _policy_from_args(_parse_args(["--records-dir", "/tmp/x", "--rxd-block-interval-s", "42"]))
    assert policy is not None, "must not refuse"
    assert any("did not reach the MarginPolicy" in r.getMessage() for r in caplog.records), (
        "accepting it silently would restore the ORIGINAL bug — the operator has to learn the "
        f"policy did not take it. Got: {[r.getMessage() for r in caplog.records]}"
    )


@pytest.mark.parametrize(
    ("flag", "value"),
    [
        ("--rxd-claim-inclusion", "5"),
        ("--burial-safety-factor", "3"),
        ("--margin-blocks", "100"),
        ("--btc-reorg-depth", "12"),
        ("--rxd-claim-burial", "9"),
        ("--rxd-reorg-cost-per-block", "1000"),
        ("--rxd-block-interval-fast-s", "36"),
    ],
)
def test_a_policy_flag_without_measured_is_refused_not_dropped(flag, value):
    from pyrxd.security.errors import ValidationError

    with pytest.raises(ValidationError) as e:
        _policy_from_args(_parse_args(["--records-dir", "/tmp/x", flag, value]))
    assert flag in str(e.value)


def test_the_plain_estimated_tower_still_starts():
    """THE HONEST PATH, paired with every refusal above: the default alert-only invocation — the
    one the README documents and the one most towers actually run — is untouched."""
    p = _policy_from_args(_parse_args(["--records-dir", "/tmp/x"]))
    assert p.is_measured is False
    assert p.block_interval_s == 600.0


@pytest.mark.parametrize("extra", [[], ["--accept-flat-burial"], ["--block-interval-s", "610"]])
def test_the_flags_the_estimated_branch_really_carries_are_not_refused(extra):
    """The other side of the refusal. ``--block-interval-s`` and ``--accept-flat-burial`` DO reach
    the estimated policy, so refusing them would be a guard refusing valid work."""
    p = _policy_from_args(_parse_args(["--records-dir", "/tmp/x", *extra]))
    assert p.block_interval_s == (610.0 if "--block-interval-s" in extra else 600.0)
    assert p.accept_flat_burial is ("--accept-flat-burial" in extra)


def test_the_report_refuses_to_label_a_reserve_the_flag_did_not_set(caplog):
    """The second layer, and the one that would have caught the original bug at runtime: the
    provenance label is checked against the policy before it is printed.

    Constructed by hand precisely because ``_policy_from_args`` no longer produces this pairing —
    the point is that the REPORT cannot assert 'measured, --rxd-claim-inclusion' over a number the
    flag did not set, whatever hands it that policy.
    """
    from pyrxd.security.errors import ValidationError

    shipped_estimate = _policy_from_args(_parse_args([*_MEASURED]))
    with caplog.at_level(logging.INFO, logger=_LOGGER):
        with pytest.raises(ValidationError) as e:
            _report_claim_reserves(shipped_estimate, requested_inclusion_blocks=5)
    assert "did not reach the policy" in str(e.value)
    assert "measured, --rxd-claim-inclusion" not in "\n".join(r.getMessage() for r in caplog.records)


def test_the_report_prints_when_the_flag_did_take(caplog):
    """Paired honest path: the check must not stand between a correct run and its report."""
    with caplog.at_level(logging.INFO, logger=_LOGGER):
        _report_claim_reserves(_policy("--rxd-claim-inclusion", "5"), requested_inclusion_blocks=5)
    assert "rxd_claim_inclusion=5 blk (measured, --rxd-claim-inclusion)" in "\n".join(
        r.getMessage() for r in caplog.records
    )


class TestTheRefusalDoesNotBlockHonestWork:
    """`_ALSO_USED_OUTSIDE_THE_POLICY` is an EXEMPTION from a refusal, so it is checked both ways.

    The refusal shipped in #636 was over-broad by exactly one flag: `--rxd-block-interval-s` also
    feeds `preflight_timing`, which warns that a slow tick can page AFTER the safety window it
    protects. Exiting 1 on it pushed the operator toward the 300 s default and silenced that
    warning — a guard refusing valid work, and pressure in the unsafe direction.

    An exemption that stops being true is a refusal quietly turned off; a missing one is honest
    work refused. Both derived from the source, never from this file's own opinion.
    """

    @staticmethod
    def _read_outside_the_policy() -> set[str]:
        """Measured-only dests read anywhere except `_policy_from_args` AND the helpers it calls."""
        import ast
        import re
        from pathlib import Path

        src = Path(run_module.__file__).read_text()
        tree = ast.parse(src)

        def span(name: str) -> tuple[int, int]:
            fn = next(
                f for f in ast.walk(tree) if isinstance(f, (ast.FunctionDef, ast.AsyncFunctionDef)) and f.name == name
            )
            return fn.lineno, max(getattr(x, "lineno", fn.lineno) for x in ast.walk(fn))

        policy_lo, policy_hi = span("_policy_from_args")
        # ...and every helper it calls, whose reads are policy reads too. Missing these is how a
        # first pass at this check reported six flags instead of one.
        helpers = [
            n.func.id
            for n in ast.walk(tree)
            if isinstance(n, ast.Call)
            and isinstance(n.func, ast.Name)
            and n.func.id.startswith("_")
            and policy_lo <= getattr(n, "lineno", 0) <= policy_hi
        ]
        spans = [(policy_lo, policy_hi)]
        for h in helpers:
            try:
                spans.append(span(h))
            except StopIteration:
                continue

        lines = src.splitlines()
        out = set()
        for dest in run_module._MEASURED_ONLY_POLICY_FLAGS:
            for i, line in enumerate(lines, start=1):
                if re.search(rf"args\.{re.escape(dest)}\b", line) and not any(lo <= i <= hi for lo, hi in spans):
                    out.add(dest)
        return out

    def test_every_exemption_really_is_used_outside_the_policy(self) -> None:
        outside = self._read_outside_the_policy()
        stale = set(run_module._ALSO_USED_OUTSIDE_THE_POLICY) - outside
        assert not stale, (
            f"{sorted(stale)} are exempt from the measured-only refusal, but nothing outside "
            "_policy_from_args reads them any more. The exemption is now a refusal silently "
            "switched off — delete it."
        )

    def test_the_reverse_direction_is_reviewed_by_hand_and_says_why(self) -> None:
        """NOT automated, deliberately, and this test exists to say so rather than to leave a
        one-directional check looking complete.

        A read outside `_policy_from_args` is not by itself a reason to exempt a flag.
        `rxd_claim_inclusion` has one — `_report_claim_reserves(..., requested_inclusion_blocks=)`
        — but that call sits AFTER the policy is built, so it cannot run when the refusal fires;
        it reports what was requested rather than doing something independent of the policy.
        `rxd_block_interval_s`'s read feeds `preflight_timing`, a safety warning that has nothing
        to do with the policy at all.

        Distinguishing those two mechanically means asking whether a call is reachable when an
        earlier one raises, which no AST scan answers honestly. So the exemption list is reviewed,
        and what IS derived is the direction that can be: an exemption naming a flag with no
        outside read at all is stale, and that is checked above.
        """
        outside = self._read_outside_the_policy()
        assert set(run_module._ALSO_USED_OUTSIDE_THE_POLICY) <= outside
        assert outside - set(run_module._ALSO_USED_OUTSIDE_THE_POLICY) == {"rxd_claim_inclusion"}, (
            "the set of measured-only flags read outside the policy has changed; re-review which "
            "of them do something INDEPENDENT of the policy and update the exemption list"
        )

    def test_the_derivation_is_not_vacuous(self) -> None:
        """It found six flags before the helper spans were accounted for, and would find zero if
        the scan broke. Pin that it finds the one real case."""
        assert self._read_outside_the_policy() == {"rxd_block_interval_s", "rxd_claim_inclusion"}


# ---------------------------------------------------------------------------
# ...and the ETH window through the SHIPPED parser, all the way to what the tower PAGES
# ---------------------------------------------------------------------------

_ESTIMATED = ["--records-dir", "/tmp/x"]


def _est_policy(*extra: str) -> MarginPolicy:
    """The DEFAULT alert-only tower's policy, built by the shipped parser."""
    return _policy_from_args(_parse_args([*_ESTIMATED, *extra]))


def _eth_record() -> SwapRecord:
    p = os.urandom(32)
    return SwapRecord(
        state=SwapState.SECRET_REVEALED,
        terms=NegotiatedTerms(
            hashlock=hashlib.sha256(p).digest(),
            btc_sats=100_000,
            radiant_amount=1_000,
            t_btc=t.Timelock(36, t.TimeUnit.BLOCKS),
            t_rxd=t.Timelock(72, t.TimeUnit.BLOCKS),
            asset_variant="ft",
            genesis_ref=b"\xaa" * 36,
            taker_dest_hash=b"\x11" * 32,
            maker_dest_hash=b"\x22" * 32,
            # The documented 32-byte zero placeholder: `NegotiatedTerms` REFUSES a real Taproot key
            # on an ETH swap, so a real key here would be a fixture the system cannot produce.
            btc_claim_pubkey_xonly=b"\x00" * 32,
            btc_refund_pubkey_xonly=b"\x00" * 32,
            counter_chain="eth",
            value_amount=10**15,
            eth_timeout_unix_s=4_000_000_000,
        ),
    )


def test_the_eth_window_comes_from_the_chain_id_and_is_PER_CHAIN():
    """The window is a per-chain FACT with provenance (``pyrxd.eth_wallet.chains``), so the flag
    defaults to the registry rather than to one number that would be wrong for every other chain."""
    assert _est_policy("--eth-rpc-url", "http://x", "--eth-chain-id", "1").eth_finalization_window_s == 768
    assert _est_policy("--eth-rpc-url", "http://x", "--eth-chain-id", "8453").eth_finalization_window_s == 900
    assert _est_policy("--eth-rpc-url", "http://x", "--eth-chain-id", "59144").eth_finalization_window_s == 6000


def test_the_explicit_window_flag_overrides_the_registry():
    p = _est_policy("--eth-rpc-url", "http://x", "--eth-chain-id", "1", "--eth-finalization-window-s", "1200")
    assert p.eth_finalization_window_s == 1200


def test_the_measured_branch_carries_the_window_too():
    """BOTH branches. An alert-only tower and a --measured one watch the same ETH swaps."""
    assert _policy(*("--eth-rpc-url", "http://x", "--eth-chain-id", "8453")).eth_finalization_window_s == 900


def test_a_btc_only_tower_still_has_no_window():
    """THE OTHER BRANCH, and the honest path: a depth-based counter leg uses
    ``btc_claim_reorg_depth`` and must stay exactly as it was — None, not a number."""
    assert _est_policy().eth_finalization_window_s is None
    assert _policy().eth_finalization_window_s is None


def test_an_unknown_chain_id_fails_closed_and_names_the_flag(caplog):
    """A guessed window is the UNSAFE direction: too small a reserve lets the gate say WAIT with
    too little margin. So an unvetted chain keeps today's fail-closed None and the operator is told
    which flag fixes it — rather than silently inheriting the L1 floor."""
    with caplog.at_level(logging.ERROR, logger=_LOGGER):
        p = _est_policy("--eth-rpc-url", "http://x", "--eth-chain-id", "31337")
    assert p.eth_finalization_window_s is None
    assert any("--eth-finalization-window-s" in r.getMessage() for r in caplog.records), (
        f"the operator must be told what to pass. Got: {[r.getMessage() for r in caplog.records]}"
    )


def test_the_window_changes_what_the_watchtower_PAGES_for_an_ETH_swap():
    """THE HALF THAT REACHES A HUMAN — through the tower's own decision core, on a policy the
    shipped CLI built.

    lock=100, t_rxd=72 -> the maker's refund opens at 172. The estimated policy's flat burial is 6
    and its inclusion reserve 2; the ETH finalization reserve is ceil(768 / 300 s) = 3, so the
    claim floor is 11 and 12 blocks of headroom is a WAIT. Without the window the gate cannot be
    evaluated at all and every tick of this healthy swap pages SQUEEZED "verify finality manually".
    """
    obs = Observations(
        maker_has_claimed_btc=False,
        now_rxd_height=160,
        asset_locked_at_height=100,
        eth_claim_detected=True,
        eth_claim_finality=CounterClaimState.NOT_YET_FINAL_LIVE,
    )
    kw = {"record": _eth_record(), "observations": obs, "safety_window_blocks": 6}

    blind = decide(policy=_est_policy(), **kw)
    assert blind.intent is Intent.PAGE_SQUEEZED
    assert "un-assessable" in blind.reason

    wired = decide(policy=_est_policy("--eth-rpc-url", "http://x", "--eth-chain-id", "1"), **kw)
    assert wired.intent is Intent.WATCH, f"a healthy pre-finality ETH swap must not page: {wired.reason}"


def test_the_window_does_not_turn_a_real_squeeze_into_a_wait():
    """PAIRED WITH THE ABOVE, and the direction that would matter for funds: wiring the reserve
    must not make the gate more permissive. Same swap 5 blocks later — 7 blocks of headroom
    against a floor of 11 — still pages SQUEEZED, now for the real reason."""
    obs = Observations(
        maker_has_claimed_btc=False,
        now_rxd_height=165,
        asset_locked_at_height=100,
        eth_claim_detected=True,
        eth_claim_finality=CounterClaimState.NOT_YET_FINAL_LIVE,
    )
    d = decide(
        record=_eth_record(),
        observations=obs,
        policy=_est_policy("--eth-rpc-url", "http://x", "--eth-chain-id", "1"),
        safety_window_blocks=6,
    )
    assert d.intent is Intent.PAGE_SQUEEZED
    assert "window closing" in d.reason


def test_the_eth_reserve_is_printed_where_an_operator_will_see_it(caplog):
    """A knob whose effect is invisible is half a knob — the same rule the claim-race reserves
    already follow. ceil(768 / 300 s) = 3 RXD blocks."""
    caplog.clear()
    with caplog.at_level(logging.INFO, logger=_LOGGER):
        _report_claim_reserves(
            _est_policy("--eth-rpc-url", "http://x", "--eth-chain-id", "1"), requested_inclusion_blocks=None
        )
    text = "\n".join(r.getMessage() for r in caplog.records)
    assert "eth_finalization_window_s=768 s" in text
    assert "3 RXD block(s) reserved" in text


def test_a_btc_only_tower_does_not_print_an_eth_reserve(caplog):
    """The other branch of that conditional: a BTC tower's report must not grow a line about a
    counter chain it is not watching."""
    caplog.clear()
    with caplog.at_level(logging.INFO, logger=_LOGGER):
        _report_claim_reserves(_est_policy(), requested_inclusion_blocks=None)
    assert "ETH counter-leg finality reserve" not in "\n".join(r.getMessage() for r in caplog.records)


# ---------------------------------------------------------------------------
# PRESENCE, not "differs from the default"
# ---------------------------------------------------------------------------
#
# The refusal above compared `getattr(args, dest)` with the parser's default, so `--flag <default>`
# was indistinguishable from never passing the flag — and the original defect ("the value went
# nowhere, silently") survived for exactly one spelling per flag. Not a harmless spelling: two
# parser defaults disagree with what the estimated policy holds, so an operator who typed either
# number was running the other one.


def _parser_default(dest: str):
    return run_module._build_parser().get_default(dest)


def _typeable_defaults() -> set[str]:
    """Measured-only dests whose parser default can actually be TYPED on a command line. A
    ``None`` default has no spelling, so it was never vulnerable to the value comparison."""
    return {d for d in run_module._MEASURED_ONLY_POLICY_FLAGS if _parser_default(d) is not None}


def test_there_really_are_flags_whose_default_can_be_typed():
    """NON-VACUITY for everything below. If every measured-only flag defaulted to None, the whole
    section would be exercising a case that cannot occur and passing for that reason."""
    assert _typeable_defaults(), "no measured-only flag has a typeable default — this section is empty"


@pytest.mark.parametrize("dest", run_module._MEASURED_ONLY_POLICY_FLAGS)
def test_presence_is_detected_for_every_measured_only_flag(dest):
    """STRUCTURAL OVER THE TUPLE, so a flag added to it is covered without anyone remembering to.

    Uses the flag's OWN parser default as the value wherever it has one — that is precisely the
    spelling the value comparison could not see.
    """
    flag = "--" + dest.replace("_", "-")
    default = _parser_default(dest)
    value = str(default) if default is not None else "7"
    assert dest not in run_module._supplied_policy_flags(_ESTIMATED), "not passed, yet reported present"
    assert dest in run_module._supplied_policy_flags([*_ESTIMATED, flag, value]), (
        f"{flag} {value} was on the command line and went undetected"
    )


@pytest.mark.parametrize("dest", sorted(_typeable_defaults() - set(run_module._ALSO_USED_OUTSIDE_THE_POLICY)))
def test_a_policy_flag_at_its_OWN_parser_default_is_refused_not_dropped(dest):
    """End to end through the shipped parser: the refusal now fires on every spelling, not only on
    values that differ from the default. Derived from the tuple, minus the one flag that has a live
    consumer outside the policy (warned, never refused — see the honest-path test below)."""
    from pyrxd.security.errors import ValidationError

    flag = "--" + dest.replace("_", "-")
    with pytest.raises(ValidationError) as e:
        _policy_from_args(_parse_args([*_ESTIMATED, flag, str(_parser_default(dest))]))
    assert flag in str(e.value)


def test_the_two_parser_defaults_that_disagree_with_the_estimated_policy():
    """WHY presence has to beat value here, pinned as an assertion rather than left in prose.

    ``--margin-blocks`` defaults to 72 while ``MarginPolicy.estimated()`` holds 36 blocks, and
    ``--rxd-claim-burial`` defaults to 2 while it holds 6. Before the presence fix both were
    ACCEPTED and DROPPED, so the operator ran the number they had not typed.

    Neither default is changed. ``--rxd-claim-burial 2`` is the deliberate dust-run value —
    ``scripts/dust_swap_run.py`` and ``scripts/dust_swap_resume.py`` default to 2 and
    ``docs/runbooks/watchtower-operations.md`` prints it in the startup line it tells operators to
    read — so raising it to 6 would make the tower page SQUEEZED on swaps its own runners consider
    fine. ``--margin-blocks``'s value is inert in the tower (see
    ``test_the_tower_never_reads_policy_margin_so_its_parser_default_is_inert``) and 72 is the more
    conservative of the two. If someone aligns either one, this fails and they re-read that
    argument first.
    """
    estimated = MarginPolicy.estimated()
    assert _parser_default("margin_blocks") == 72
    assert estimated.margin == t.Timelock(36, t.TimeUnit.BLOCKS)
    assert _parser_default("rxd_claim_burial") == 2
    assert estimated.rxd_claim_burial == t.Timelock(6, t.TimeUnit.BLOCKS)


def test_the_flag_with_a_live_outside_use_is_still_warned_at_its_default_not_refused(caplog):
    """THE HONEST PATH FOR THE WIDER REFUSAL. ``--rxd-block-interval-s 300`` is now DETECTED where
    it previously was not, so the exemption has to hold at the default spelling too — otherwise
    presence detection would have re-introduced exactly the over-broad refusal this branch exists
    to undo."""
    with caplog.at_level(logging.WARNING, logger=_LOGGER):
        policy = _policy_from_args(_parse_args([*_ESTIMATED, "--rxd-block-interval-s", "300"]))
    assert policy is not None, "must not refuse"
    assert any("did not reach the MarginPolicy" in r.getMessage() for r in caplog.records)


def test_a_hand_built_namespace_keeps_the_old_predicate_and_still_starts():
    """``_policy_from_args`` is reached through ``_parse_args`` on every shipped path, but an
    embedder can hand it a Namespace with no presence set. That must degrade to the old
    value-vs-default comparison, not to "nothing was ever supplied" and not to a crash."""
    from pyrxd.security.errors import ValidationError

    args = _parse_args([*_ESTIMATED])
    delattr(args, run_module._SUPPLIED_ATTR)
    assert _policy_from_args(args).is_measured is False
    args = _parse_args([*_ESTIMATED, "--margin-blocks", "100"])
    delattr(args, run_module._SUPPLIED_ATTR)
    with pytest.raises(ValidationError):
        _policy_from_args(args)
