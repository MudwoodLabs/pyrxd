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
import re

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


def _glossary_entry(glossary: str, term: str) -> str:
    """The flattened text of the top-level ``- **term**`` glossary bullet, and NOTHING past the
    next top-level bullet.

    Bounding the match is the whole point. Matching over the entire flattened page let a claim
    reverted in one bullet hide behind unrelated wording surviving in a DIFFERENT bullet two
    paragraphs away — see the docstring on the test below for the exact case a reviewer found.
    """
    pattern = re.compile(rf"^- \*\*{re.escape(term)}\*\*.*?(?=\n- \*\*|\Z)", re.MULTILINE | re.DOTALL)
    match = pattern.search(glossary)
    assert match is not None, f"no top-level glossary bullet for {term!r} — did its heading move?"
    return " ".join(match.group(0).split())


#: Glossary bullets that make a specific "used to say this could not be built; now says
#: builder-level" claim about one write side — checked against THAT bullet's own text, never the
#: page as a whole. Reviewed, not derived: matching English prose is a judgement call, not
#: something to derive from source.
#:
#: Only AUTHORITY and DAT are here, not all four write sides in `_BUILDER_ONLY_WRITE_SIDES` above.
#: #634 shipped `prepare_delegate_setup` (delegate/`by`) and `prepare_burn_proof` (BURN) too, but
#: never gave either an equivalent glossary claim: BURN's bullet still reads "no burn builder
#: exists ... don't assume it's mintable", which `prepare_burn_proof` already contradicts, and
#: delegate/`by` has no bullet discussing it at all. That is a real, separate doc-staleness bug —
#: this test does not cover it, and its absence here is not evidence the other two are fine.
_MARKER_CLAIMS = {
    "AUTHORITY": "ships no `prepare_authority_*` builder",
    "DAT": "no builder ships for it",
}


def test_the_docs_say_so_where_a_user_would_look() -> None:
    """The scope is only honest if it reaches the reader, IN THE BULLET ABOUT THAT MARKER — not
    merely somewhere on a 300-line page. The glossary claimed the opposite of reality for both —
    'ships no `prepare_authority_*` builder — you cannot mint one with pyrxd today' for AUTHORITY,
    'no builder ships for it' for DAT — which this branch made false for both.

    A reviewer reverted the DAT bullet to that pre-fix claim and the OLD file-wide version of this
    assertion (`"builder-level" in flat.lower() or "GlyphBuilder" in flat` over the whole
    flattened glossary) still passed, because the word "GlyphBuilder" survives in the unrelated
    AUTHORITY bullet two paragraphs away. Checking each marker's own bullet text is what catches
    that revert.
    """
    assert set(_MARKER_CLAIMS) == {"AUTHORITY", "DAT"}, (
        "the set of markers this test checks changed size — re-read the module docstring comment "
        "above _MARKER_CLAIMS before editing it; a marker gaining or losing a glossary claim needs "
        "a human look, not a silent update"
    )
    glossary = (_ROOT / "docs" / "concepts" / "glossary.md").read_text(encoding="utf-8")
    for marker, old_false_claim in sorted(_MARKER_CLAIMS.items()):
        entry = _glossary_entry(glossary, marker)
        assert old_false_claim not in entry, (
            f"the {marker} glossary bullet reverted to its pre-#634 claim ({old_false_claim!r}); "
            f"pyrxd now builds {marker} via GlyphBuilder"
        )
        assert "builder-level" in entry.lower() or "GlyphBuilder" in entry, (
            f"the {marker} bullet should say where its write side lives — a user told 'you cannot' "
            "will not go looking — and that must be true IN THIS BULLET, not merely somewhere else "
            "on the page"
        )
