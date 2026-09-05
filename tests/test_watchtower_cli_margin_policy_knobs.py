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
import hashlib
import inspect
import logging
import os
import pathlib

import pytest

from pyrxd.btc_wallet import taproot as t
from pyrxd.gravity.finality import CounterClaimFinality
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

#: Constructor keywords the tower deliberately does NOT expose, each with the reason. A tower flag
#: would be WRONG for these, not merely missing — so they are exempt, not overlooked.
_DELIBERATELY_NOT_A_TOWER_FLAG = {
    # One tower watches MANY swaps, and the value at risk is per-swap. decide() supplies it from
    # each record's own terms (`_value_at_risk_photons`); a single chain-wide flag would apply one
    # swap's value to all of them.
    "value_at_risk_photons",
}


def _forwarded_keywords() -> set[str]:
    """Keyword names ``_policy_from_args`` actually passes to ``MarginPolicy.measured(...)``."""
    tree = ast.parse(_RUN_PY.read_text())
    fn = next(
        n
        for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == "_policy_from_args"
    )
    calls = [n for n in ast.walk(fn) if isinstance(n, ast.Call) and ast.unparse(n.func) == "MarginPolicy.measured"]
    assert calls, "_policy_from_args no longer calls MarginPolicy.measured — this guard has stopped running"
    return {kw.arg for call in calls for kw in call.keywords if kw.arg is not None}


def test_every_measured_policy_knob_is_reachable_from_the_cli():
    """DIRECTION 1: a constructor parameter with no CLI route is an unreachable knob."""
    params = {
        name
        for name, p in inspect.signature(MarginPolicy.measured).parameters.items()
        if p.kind is inspect.Parameter.KEYWORD_ONLY
    }
    assert params, "could not read MarginPolicy.measured's parameters — this guard is running empty"
    missing = params - _forwarded_keywords() - _DELIBERATELY_NOT_A_TOWER_FLAG
    assert not missing, (
        f"MarginPolicy.measured takes {sorted(missing)}, which --measured cannot set: the tower "
        "silently uses the default. Either wire a flag in _policy_from_args or add it to "
        "_DELIBERATELY_NOT_A_TOWER_FLAG with the reason."
    )


def test_the_cli_forwards_nothing_the_constructor_does_not_take():
    """DIRECTION 2: a forwarded keyword that is no longer a parameter is a check that has stopped
    running (and a TypeError waiting for the first --measured operator)."""
    params = set(inspect.signature(MarginPolicy.measured).parameters)
    assert not (_forwarded_keywords() - params)


def test_the_exemption_list_still_names_real_parameters():
    """An exemption for a parameter that no longer exists is a stale excuse hiding a real gap."""
    params = set(inspect.signature(MarginPolicy.measured).parameters)
    assert params >= _DELIBERATELY_NOT_A_TOWER_FLAG


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
        _report_claim_reserves(_policy_from_args(args), inclusion_measured=args.rxd_claim_inclusion is not None)
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
        _report_claim_reserves(_policy_from_args(args), inclusion_measured=args.rxd_claim_inclusion is not None)
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
