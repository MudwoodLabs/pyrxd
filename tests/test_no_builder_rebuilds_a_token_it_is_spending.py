"""Re-creating a spent token's output from a pubkey hash strips its covenant.

This defect has now been found THREE times in the same codebase, each time as a fresh
instance rather than as the class:

1. ``prepare_authority_gated_reveal`` — fixed by taking ``authority_script``;
2. ``prepare_delegate_setup`` — found by the security panel, fixed by taking
   ``parent_scripts``, and its docstring already named the hazard forty lines from the
   code that still had it;
3. ``prepare_container_child_reveal`` — found by a later review, in a method whose own
   docstring asserted the output was "byte-identical to the one being spent".

Each fix was applied at the site. Nothing enumerated the class, so the next instance was
invisible until someone went looking again. This test enumerates it.

THE PREDICATE, derived rather than hand-kept
--------------------------------------------
A locking script built for a ref that arrives as a PARAMETER is a script for a token that
already exists on chain — the builder is RE-CREATING it. A script built for a ref derived
locally (from the commit outpoint) is a token being MINTED, where building from a pubkey
hash is the only thing you can do and is correct.

So: AST-walk ``builder.py``, find every ``build_nft_locking_script(<pkh>, <ref>)`` /
``build_ft_locking_script(...)`` call whose ref argument is a parameter of the enclosing
method, and require each to be an explicitly reviewed exemption.

Both directions are checked. A new call site with no entry is the original defect. An
entry naming a call site that no longer exists is a reason that has stopped applying, and
those rot silently — the guard's own logic would otherwise treat it as out of scope.
"""

from __future__ import annotations

import ast
import pathlib

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_BUILDER = _ROOT / "src" / "pyrxd" / "glyph" / "builder.py"

_SCRIPT_BUILDERS = {"build_nft_locking_script", "build_ft_locking_script"}

#: Call sites that build a locking script for a ref they were HANDED, with the reason each
#: is safe. Reviewed, not derived — the guard derives the SET, this pins the judgement.
#: If you are adding an entry, the question to answer is: can the token whose ref this is
#: be carrying a covenant (authority-gated, mutable, soulbound)? If yes, take its script.
_REVIEWED: dict[str, str] = {
    "_build_premine_script": (
        "a FALSE POSITIVE of this scan, which is intraprocedural. Its `token_ref` parameter is "
        "not an existing token: both callers derive it locally as "
        "`GlyphRef(txid=commit_txid, vout=0)` (builder.py, both `build_reveal_outputs`), so the "
        "premine output MINTS the dMint token's first FT units in the same reveal that creates "
        "it. There is no covenant to strip because there is no prior UTXO. Verified 2026-09-13 "
        "by reading both call sites; if either ever passes a ref it was handed, this entry is "
        "wrong and must go."
    ),
    "build_transfer_locking_script": (
        "a low-level transfer helper whose entire purpose is to build a NEW output for a "
        "ref under a NEW owner. Re-owning is the caller's stated intent, the covenant "
        "question is theirs to answer, and it mints nothing it did not already hold."
    ),
}


def _recreating_call_sites() -> dict[str, list[int]]:
    """method name -> lines where it builds a script for a ref it was passed."""
    tree = ast.parse(_BUILDER.read_text(encoding="utf-8"))
    found: dict[str, list[int]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        params = {a.arg for a in node.args.args} | {a.arg for a in node.args.kwonlyargs}
        for call in ast.walk(node):
            if not isinstance(call, ast.Call):
                continue
            name = getattr(call.func, "id", getattr(call.func, "attr", None))
            if name not in _SCRIPT_BUILDERS or len(call.args) < 2:
                continue
            # the ref argument's root identifier: `container_ref` / `params.new_owner_pkh`
            root = ast.unparse(call.args[1]).split(".")[0]
            if root in params:
                found.setdefault(node.name, []).append(call.lineno)
    return found


def test_the_scan_is_not_vacuous() -> None:
    """If the AST walk stops matching, "no unreviewed call sites" must not read as success."""
    tree = ast.parse(_BUILDER.read_text(encoding="utf-8"))
    total = sum(
        1
        for n in ast.walk(tree)
        if isinstance(n, ast.Call) and getattr(n.func, "id", getattr(n.func, "attr", None)) in _SCRIPT_BUILDERS
    )
    assert total >= 5, (
        f"only {total} locking-script builder calls found in builder.py — the AST walk has "
        "stopped matching and this guard is passing over nothing"
    )


def test_every_builder_that_recreates_a_token_it_was_handed_is_reviewed() -> None:
    """The original defect: a new call site rebuilding a token from a pubkey hash."""
    unreviewed = {m: lines for m, lines in _recreating_call_sites().items() if m not in _REVIEWED}
    assert not unreviewed, (
        "these builder methods build a locking script for a ref they were PASSED — i.e. they "
        "re-create a token that already exists on chain. Rebuilding from a pubkey hash returns "
        "an authority-gated, mutable or soulbound token as a plain NFT: same ref, covenant "
        "gone, unrecoverable by the holder.\n"
        f"  {unreviewed}\n"
        "Take the token's OWN script and re-emit it verbatim, cross-checked with "
        "`script_carries_ref` — as prepare_delegate_setup, prepare_authority_gated_reveal and "
        "prepare_container_child_reveal all now do. If it is genuinely safe, add it to "
        "_REVIEWED with the reason."
    )


def test_no_reviewed_entry_has_outlived_its_call_site() -> None:
    """The other direction. An exemption whose call site is gone is a reason nobody will
    re-read, sitting in a list that still looks like it is doing work."""
    live = set(_recreating_call_sites())
    stale = sorted(set(_REVIEWED) - live)
    assert not stale, (
        f"_REVIEWED names call sites that no longer re-create a handed-in ref: {stale}. "
        "The code changed under the exemption; delete the entry so the next reader is not "
        "inheriting a judgement about something that no longer exists."
    )


def test_the_three_known_offenders_take_a_script_not_a_pubkey_hash() -> None:
    """Pins the fixes themselves, so none of the three can quietly regress to a Hex20."""
    tree = ast.parse(_BUILDER.read_text(encoding="utf-8"))
    expected = {
        "prepare_authority_gated_reveal": "authority_script",
        "prepare_delegate_setup": "parent_scripts",
        "prepare_container_child_reveal": "container_script",
    }
    seen: dict[str, set[str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name in expected:
            seen[node.name] = {a.arg for a in node.args.args} | {a.arg for a in node.args.kwonlyargs}
    missing = sorted(set(expected) - set(seen))
    assert not missing, f"these builder methods no longer exist — update this guard: {missing}"
    for method, param in expected.items():
        assert param in seen[method], (
            f"{method} no longer takes `{param}`. It was changed to take the token's own script "
            "precisely so that rebuilding it from a pubkey hash is not expressible."
        )
