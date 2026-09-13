"""The four new write sides are BUILDER-level, and nothing in pyrxd mints through them.

A security panel put this three ways and they are the same fact: the write sides have no caller in
`src/`; the repo's reachability guard is green because it walks `tree.body` (module level) and
every one of them is a METHOD; and the three regtest suites that prove them on a node were in no
CI workflow. The capability is real and consensus-proven — it is just not reachable from
`GlyphClient`, `GlyphMinter`, or any CLI command.

THAT IS A DELIBERATE SCOPE, NOT AN OVERSIGHT, and this file is what makes it checkable rather than
a sentence in a CHANGELOG that nothing evaluates. Wiring them through the client and CLI is a
feature in its own right (the minter's reveal builder is hard-wired to one input and two outputs;
an authority-gated reveal needs two of each); shipping them as builder APIs in the meantime is
honest, and lets the branch stop rotting against main.

WHY NOT WIDEN THE REACHABILITY GUARD INSTEAD. Tried, reverted, and worth recording so nobody
spends the afternoon again: walking one level into class bodies flags 29 symbols, and almost all
are correct SDK surface — `GlyphClient.transfer_nft` is *meant* to be called by a user, not by
pyrxd. Exempting methods whose class is itself exported fixes that and re-exempts `GlyphBuilder`,
which is where these four live. So the guard cannot express this question; a pinned membership can.

If one of these gains a production caller, this test fails and the entry must go — which is the
signal that the scope changed and the CHANGELOG's "builder-level" wording is now false.
"""

from __future__ import annotations

import ast
import pathlib

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_SRC = _ROOT / "src" / "pyrxd"

#: `GlyphBuilder` methods that build the four write sides, none of which any shipped code calls.
#: Reviewed, not derived: each is consumer API reached through `pyrxd.glyph.GlyphBuilder`.
_BUILDER_ONLY_WRITE_SIDES = {
    "prepare_delegate_setup",  # `by`/`in` delegation — the base and its tokens
    "prepare_authority_gated_reveal",  # AUTHORITY — mint an item under an issuer's gate
    "prepare_dat_commit",  # DAT — data storage, commit half
    "prepare_dat_reveal",  # DAT — reveal half
    "prepare_burn_proof",  # BURN — the OP_RETURN proof output
}


def _shipped_call_sites(name: str) -> list[str]:
    """Every `foo(...)` or `.foo(...)` call to *name* in shipped source, excluding its own def."""
    hits = []
    for path in sorted(_SRC.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            called = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
            if called == name:
                hits.append(f"{path.relative_to(_ROOT).as_posix()}:{node.lineno}")
    return hits


def test_the_write_sides_are_still_builder_only() -> None:
    """Both directions, so the entry cannot rot either way."""
    for name in sorted(_BUILDER_ONLY_WRITE_SIDES):
        assert (_SRC / "glyph" / "builder.py").read_text().count(f"def {name}(") == 1, (
            f"{name} is not defined on the builder any more — update this list"
        )
        callers = _shipped_call_sites(name)
        assert not callers, (
            f"{name} now has a shipped caller ({callers}). That is good news and this entry is "
            "stale: the CHANGELOG and docs say these are builder-level and NOT mintable through "
            "GlyphClient or the CLI, which is no longer true. Update both, then drop it here."
        )


def test_the_docs_say_so_where_a_user_would_look() -> None:
    """The scope is only honest if it reaches the reader. The glossary claimed the opposite —
    'ships no prepare_authority_* builder — you cannot mint one with pyrxd today' — which this
    branch made false, and DAT was described as decode/classify-only."""
    glossary = (_ROOT / "docs" / "concepts" / "glossary.md").read_text(encoding="utf-8")
    flat = " ".join(glossary.split())
    assert "ships no `prepare_authority_*` builder" not in flat, (
        "the glossary still says pyrxd cannot build an authority-gated mint; this branch added "
        "prepare_authority_gated_reveal"
    )
    assert "builder-level" in flat.lower() or "GlyphBuilder" in flat, (
        "the glossary should say where these live — a user told 'you cannot' will not go looking"
    )
