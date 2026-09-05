"""#564: the post-asset-lock recheck runs on the MAKER's host, and its docstring said otherwise.

It read: refuse to advance "— the taker refunds the counter leg rather than proceed". That names a
party the code cannot speak for. In the two-host flow the only caller is the maker's process, and
the taker phase never calls it at all, so a failure stops the MAKER revealing `p` and the maker's
recovery is the CSV refund of its OWN covenant. Maker self-restraint, not a control the taker holds
over a hostile maker — a maker who wants to skip it simply does not call it.

That distinction decides what the gate is worth, so it is pinned here rather than left as prose.
Tests pin that a sentence is EMITTED, never that it is CORRECT, which is how a docstring drifts
from the code beside it in silence. What CAN be pinned is the structural fact the sentence depends
on: who calls it. If someone later wires it into the taker phase, this fails and the prose has to
be revisited with it.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

from pyrxd.gravity.swap_coordinator import SwapCoordinator

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "eth_swap_two_host.py"
_CALL = "post_asset_lock_revalidate"


def _functions_calling(path: Path, name: str) -> set[str]:
    """Top-level function names whose body contains a call to ``name``."""
    tree = ast.parse(path.read_text())
    out = set()
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute) and sub.func.attr == name:
                out.add(node.name)
    return out


def test_the_two_host_script_calls_it_at_all() -> None:
    """Non-vacuity. Every assertion below is about the SET of callers; an empty set would satisfy
    'no taker phase calls it' while proving nothing."""
    assert _functions_calling(_SCRIPT, _CALL), f"no function in {_SCRIPT.name} calls {_CALL} — the scan has broken"


def test_only_a_MAKER_phase_calls_it() -> None:
    callers = _functions_calling(_SCRIPT, _CALL)
    assert all("maker" in c for c in callers), (
        f"{_CALL} is called from {sorted(callers)}. The docstring on "
        "`_assert_eth_lock_timing_still_safe` explains that this is a maker-side self-restraint "
        "gate BECAUSE only the maker's process runs it. If that has changed, the docstring is now "
        "wrong and must be revisited with this test."
    )


def test_no_TAKER_phase_calls_it() -> None:
    """The other direction, stated separately: 'every caller is a maker phase' would also hold if
    a taker phase called it through a differently-named helper, so name the taker side explicitly."""
    callers = _functions_calling(_SCRIPT, _CALL)
    assert not [c for c in callers if "taker" in c], f"a taker phase now calls {_CALL}: {sorted(callers)}"


def test_the_docstring_no_longer_attributes_the_recovery_to_the_taker() -> None:
    """The retracted claim, pinned as a negative so it cannot quietly return.

    Narrow on purpose: it matches the specific sentence that was wrong, not the word 'taker', which
    the corrected docstring legitimately uses several times when describing the taker's OWN
    defences."""
    doc = inspect.getdoc(SwapCoordinator._assert_eth_lock_timing_still_safe) or ""
    assert "the taker refunds the counter leg rather" not in doc, (
        "the docstring again says a failure here means the taker refunds — but this runs on the "
        "maker's host and the maker's recovery is the CSV refund of its own covenant"
    )
    assert "maker" in doc.lower(), "the corrected docstring must say whose gate this is"
