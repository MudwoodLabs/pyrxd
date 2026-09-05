"""No PUBLISHED artifact may assert the pre-#482 timelock ordering.

0.22.0 was a security release for exactly this defect class: every version through 0.21.0 shipped
conformance vectors that ACCEPTED `t_btc > t_rxd` — the arrangement in which the maker refunds its
own leg while `p` is still secret and then claims the counter leg, taking both. A second implementer
who got the direction RIGHT would have run our vectors, failed, and been told by a spec with a green
test run behind it to adopt the vulnerable one.

The vectors were regenerated. The PROSE was not guarded, and one sentence survived: HZ-4 in
`docs/htlc-handshake-wire-format.md` still read "`t_btc` ... must still exceed `t_rxd`" while the
same document said the opposite at two other places and the code refused it. A reader reaching
HZ-4 first had no way to know which sentence to believe.

Nothing here re-checks what the CODE does — `tests/test_htlc_handshake_conformance_vectors.py` and
the swap-state guards own that. This pins what we PUBLISH, because a spec is a claim about what an
implementation SHOULD do, and ours is read by at least one second implementer.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]

#: Working space, not published. `docs/solutions/` records dated incidents that legitimately
#: describe past mistakes in the past tense.
_PRIVATE = ("brainstorms", "plans", "solutions")

#: An ordering CLAIM: one symbol, a comparative, the other symbol. Matched across newlines because
#: the surviving instance wrapped mid-sentence — a line-oriented grep did not see it, which is part
#: of why it lasted.
_CLAIM = re.compile(
    r"(?P<left>t_btc|t_rxd)[^.]{0,140}?"
    r"(?P<cmp>must still exceed|must exceed|exceeds|greater than|longer than)"
    r"[^.]{0,80}?(?P<right>t_rxd|t_btc)",
    re.S,
)

#: Markers that make an inverted ordering a MENTION rather than an assertion — the use/mention
#: distinction. Without this, correcting the defect in prose would trip the guard written to catch
#: it, which has happened three times in this repo.
_MENTION = re.compile(
    r"what breaks|if it is inverted|must not|never|attack|vulnerab|exploit|"
    r"previously|used to|no longer|incorrect|wrong|pre-#482|before #482",
    re.I,
)


def _published_files() -> list[Path]:
    """Derived from the tree, not hand-kept: any published doc or vector naming BOTH symbols.

    A hand-kept list is the failure this repo keeps recording — it silently stops covering a file
    added later. If a new spec starts discussing the ordering, it is in scope automatically.
    """
    out = []
    for root in ("docs", "conformance", "README.md"):
        p = _ROOT / root
        files = [p] if p.is_file() else [f for f in p.rglob("*") if f.is_file()]
        for f in files:
            if f.suffix not in {".md", ".rst", ".json", ".txt"}:
                continue
            if any(s in f.relative_to(_ROOT).parts for s in _PRIVATE):
                continue
            try:
                txt = f.read_text(errors="ignore")
            except OSError:
                continue
            if "t_btc" in txt and "t_rxd" in txt:
                out.append(f)
    return sorted(out)


def _paragraph_around(text: str, start: int, end: int) -> str:
    """The enclosing paragraph — NOT a fixed character window.

    A 260-char window was the first attempt and it silently disabled the whole guard: it reached
    back into the PREVIOUS hazard note, found an unrelated "a second implementer MUST NOT infer",
    and excused the real assertion three paragraphs later. The planted defect passed. Mentions are
    introduced in the same paragraph as the thing they mention, so that is the honest scope.
    """
    lo = max(text.rfind("\n\n", 0, start) + 2, text.rfind("\n#", 0, start) + 1, 0)
    nxt = text.find("\n\n", end)
    return text[lo : (len(text) if nxt == -1 else nxt)]


def _inverted_claims(text: str) -> list[tuple[int, str]]:
    """Every claim asserting `t_btc > t_rxd`, minus the ones that name it as the broken case."""
    bad = []
    for m in _CLAIM.finditer(text):
        if m.group("left") != "t_btc" or m.group("right") != "t_rxd":
            continue
        line = text[: m.start()].count("\n") + 1
        if _MENTION.search(_paragraph_around(text, m.start(), m.end())):
            continue
        bad.append((line, " ".join(m.group(0).split())))
    return bad


def test_the_scan_actually_reaches_the_published_specs() -> None:
    """A scanner over an empty file set passes vacuously — the exact shape of a guard that reads
    like coverage and checks nothing. Pin that it finds the documents it exists to police."""
    files = _published_files()
    names = {f.relative_to(_ROOT).as_posix() for f in files}
    assert "docs/htlc-handshake-wire-format.md" in names, "the handshake spec must be in scope"
    assert "conformance/htlc-handshake-vectors.json" in names, "the published vectors must be in scope"
    assert len(files) >= 3, f"suspiciously few published files discuss the ordering: {sorted(names)}"


@pytest.mark.parametrize("path", _published_files(), ids=lambda p: p.relative_to(_ROOT).as_posix())
def test_no_published_file_asserts_the_exploitable_ordering(path: Path) -> None:
    bad = _inverted_claims(path.read_text(errors="ignore"))
    assert not bad, (
        f"{path.relative_to(_ROOT)} asserts the pre-#482 ordering: "
        + "; ".join(f"line {ln}: {frag}" for ln, frag in bad)
        + ". The maker refunds its own leg while p is still secret, then claims the counter leg "
        "with p — taking both. Correct direction: t_rxd must exceed t_btc."
    )


def test_the_correct_direction_is_stated_somewhere() -> None:
    """The other half. A file could pass above by saying nothing at all, so pin that the spec
    positively teaches the safe relation rather than merely avoiding the unsafe sentence."""
    spec = (_ROOT / "docs/htlc-handshake-wire-format.md").read_text()
    forward = [
        m for m in _CLAIM.finditer(spec) if m.group("left") == "t_rxd" and m.group("right") == "t_btc"
    ]
    assert forward, "the handshake spec must state that t_rxd exceeds t_btc, not merely omit the inverse"


class TestTheGuardCanTellUseFromMention:
    """A phrase scanner that flags a correction quoting the old wrong text is worse than none —
    it makes fixing the defect look like committing it. Both directions pinned."""

    def test_a_real_inverted_assertion_is_caught(self) -> None:
        assert _inverted_claims("On an ETH swap `t_btc` must still exceed\n`t_rxd` (see the guard).")

    def test_naming_the_inverted_case_as_broken_is_not_caught(self) -> None:
        assert not _inverted_claims(
            "**What breaks if it is inverted.** A spec asserting `t_btc` must exceed `t_rxd` "
            "hands the maker both legs."
        )

    def test_describing_the_old_published_defect_is_not_caught(self) -> None:
        assert not _inverted_claims(
            "Every version through 0.21.0 shipped vectors in which `t_btc` must exceed `t_rxd`; "
            "that was the exploitable arrangement."
        )
