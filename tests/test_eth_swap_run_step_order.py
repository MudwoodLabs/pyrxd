"""The dust runner locks the Radiant asset BEFORE it funds the counter leg.

This is not style. The maker is the party that knows `p`, so a maker who locks second holds a free
option: it can watch the taker fund and walk away having risked nothing. HZ-1 (#392) enforces the
rule from the other side — `taker_funds_btc` refuses until the covenant is verified on chain.

The runner did the reverse for as long as HZ-1 has existed, and every run died at that gate. Nothing
caught it: the runner is the production entry point for the ETH<->RXD corridor, it is not driven by
any test, and exercising it by hand costs real mainnet value. So the order is asserted here, on the
runner's own AST, rather than trusted to review.

Coarse by nature — it checks call ORDER, not semantics. It is aimed squarely at the regression that
actually happened, and it is the only automated check standing between this script and a repeat.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

_SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
_RUNNER = _SCRIPTS / "eth_swap_run.py"

#: EVERY runner that funds a counter leg against a Radiant covenant. The bug was found in one of
#: these and was present in three — including both mainnet runners — so the guard is applied to the
#: set rather than to the file that happened to surface it.
_ALL_RUNNERS = [
    "eth_swap_run.py",
    "dust_swap_run.py",
    "eth_swap_grief_run.py",
    "btc_swap_two_host.py",
    "eth_swap_two_host.py",
]

#: Any of these means "the maker's asset is now locked on Radiant".
_LOCK_CALLS = {"wait_for_covenant_funding", "lock_singleton_into_covenant", "lock_ft_into_covenant"}
#: The two-host scripts verify the maker's lock through a different call than the dust runners.
_LOCK_CALLS_ANY = _LOCK_CALLS | {"verify_maker_asset_funded", "taker_verify_asset_funding"}
_FUND_CALL = "taker_funds_btc"


def _called_names_in_order(fn: ast.AST) -> list[tuple[int, str]]:
    """(line, name) for every call in `fn`, in source order, unwrapping await/attribute."""
    out = []
    for node in ast.walk(fn):
        if isinstance(node, ast.Call):
            f = node.func
            name = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", None)
            if name:
                out.append((node.lineno, name))
    return sorted(out)


@pytest.fixture(scope="module")
def dust_stage():
    tree = ast.parse(_RUNNER.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "run_sepolia_dust":
            return node
    pytest.fail("run_sepolia_dust not found — the runner was renamed; update this guard")


def test_the_radiant_lock_precedes_the_counter_leg_fund(dust_stage):
    """EVERY asset variant must lock first, and each must be present.

    A first version asserted `min(lock_lines) < min(fund_lines)`. That passes while any ONE branch
    locks early — so deleting the rxd branch's lock entirely left it green, because the nft and ft
    branches above it still matched. Caught by planting exactly that. The rule is per-variant, so
    the assertion has to be per-variant: all three present, and the LAST of them before the fund.
    """
    calls = _called_names_in_order(dust_stage)
    by_name = {n: ln for ln, n in reversed(calls)}
    fund_lines = [ln for ln, n in calls if n == _FUND_CALL]
    assert fund_lines, f"no {_FUND_CALL} call found in the dust stage"

    missing = _LOCK_CALLS - by_name.keys()
    assert not missing, (
        f"asset variant(s) with no Radiant lock step: {sorted(missing)}. That variant funds the "
        "counter leg against an unlocked covenant, which HZ-1 refuses and which hands the maker "
        "a free option."
    )
    lock_lines = [ln for ln, n in calls if n in _LOCK_CALLS]
    assert max(lock_lines) < min(fund_lines), (
        f"the runner funds the counter leg (line {min(fund_lines)}) before a Radiant lock step "
        f"(line {max(lock_lines)}). HZ-1 refuses that order, so the run cannot complete — and a "
        "maker locking second holds a free option over the taker."
    )


def test_the_maker_verifies_the_counter_leg_before_revealing_the_preimage(dust_stage):
    """The other half of the reorder. Moving the lock earlier displaced the maker's go/no-go check,
    which cannot run before a contract exists. It has to land before `p` becomes public, because
    that is the moment it protects — after the reveal there is nothing left to refuse."""
    calls = _called_names_in_order(dust_stage)
    verify = [ln for ln, n in calls if n == "maker_verify_counter_funding"]
    claim = [ln for ln, n in calls if n == "maker_claims_btc"]

    assert verify, "maker_verify_counter_funding is not called — the reveal is unguarded"
    assert claim, "maker_claims_btc not found in the dust stage"
    assert min(verify) < min(claim), (
        f"the maker reveals p (line {min(claim)}) before verifying the counter leg pays it "
        f"(line {min(verify)}) — once p is public the counterparty can take their leg regardless"
    )


def test_the_operator_is_not_asked_to_attest_that_the_covenant_is_funded(dust_stage):
    """A question whose answer is on the chain must be asked of the chain.

    The previous code asked the operator to confirm "you have funded the RXD covenant SPK on
    mainnet and it has >= 1 conf". Under --yes that auto-answered itself, so the run asserted a
    fact nothing had checked and handed it straight to a gate that disagreed."""
    src = _RUNNER.read_text()
    assert "you have funded the RXD covenant SPK" not in src, (
        "the operator attestation is back; poll the chain with wait_for_covenant_funding instead"
    )


@pytest.mark.parametrize("script", _ALL_RUNNERS)
def test_no_runner_asks_the_operator_to_attest_the_covenant_is_funded(script):
    """Not one of them, not just the one the bug was found in.

    Three of five runners shipped this attestation and two of those were MAINNET. The prompt is not
    a safety mechanism — HZ-1 checks the covenant independently — but under --yes it makes the run
    assert a fact nobody verified, which is strictly worse than not asking.
    """
    src = (_SCRIPTS / script).read_text()
    assert "you have funded the RXD covenant SPK" not in src, (
        f"{script} asks the operator to attest the covenant is funded; --yes fabricates that "
        "answer. Poll the chain with wait_for_covenant_funding instead."
    )


@pytest.mark.parametrize("script", _ALL_RUNNERS)
def test_every_runner_locks_the_radiant_asset_before_funding_the_counter_leg(script):
    """The ordering rule holds for all of them. Checks the whole module, since these scripts differ
    in shape — some drive the stage from a function, some inline it."""
    tree = ast.parse((_SCRIPTS / script).read_text())
    calls = _called_names_in_order(tree)
    fund = [ln for ln, n in calls if n == _FUND_CALL]
    lock = [ln for ln, n in calls if n in _LOCK_CALLS_ANY]
    if not fund:
        pytest.skip(f"{script} does not fund a counter leg")
    assert lock, (
        f"{script} calls {_FUND_CALL} with no Radiant lock step anywhere. HZ-1 refuses that, and a "
        "maker locking second holds a free option over the taker."
    )
    assert min(lock) < min(fund), (
        f"{script} funds the counter leg (line {min(fund)}) before locking the Radiant asset (line {min(lock)})"
    )


@pytest.mark.parametrize("script", _ALL_RUNNERS)
def test_the_wait_helpers_are_imported_where_they_are_called(script):
    """A name used but not imported is a NameError at the worst possible moment.

    Written because it happened: replacing the attestations in the two-host scripts left the helper
    called and un-imported, and the guards above stayed green — they check call ORDER and the
    absence of a string, neither of which notices an unresolvable name. Ruff's F821 caught it. This
    is the cheap in-suite version of that, scoped to the helpers this refactor introduced, so the
    same slip does not depend on the linter alone.
    """
    tree = ast.parse((_SCRIPTS / script).read_text())
    called = {n for _, n in _called_names_in_order(tree)}
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            imported |= {a.asname or a.name for a in node.names}
        elif isinstance(node, ast.Import):
            imported |= {(a.asname or a.name).split(".")[0] for a in node.names}
        elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            imported.add(node.name)

    for helper in ("wait_for_covenant_funding", "wait_for_covenant_via_leg"):
        if helper in called:
            assert helper in imported, (
                f"{script} calls {helper}() but never imports or defines it — NameError at the "
                "moment the run reaches the covenant lock, with the counter leg not yet funded"
            )
