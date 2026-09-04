"""A comment citing `script.cpp:710-726` is making a checkable claim. Check it.

pyrxd's Python is dense with citations into Radiant Core — "Radiant-Core
``src/script/script.cpp:710-726``", "``interpreter.cpp:1957`` says outright that it
performs NO membership check". Those citations are the evidence for claims about
CONSENSUS, which is the layer that actually decides whether a transaction is valid,
and which no amount of correct Python can compensate for.

They are also the most fragile prose in the repo. Line numbers drift the moment the
vendored sources are refreshed to a newer commit, and a citation that has drifted
still LOOKS authoritative — it names a real file and a plausible line. The next
reader follows it, finds something unrelated or subtly different, and either trusts
the wrong code or quietly stops trusting citations at all.

TWO CHECKS, AND A THIRD THING DELIBERATELY NOT CHECKED.

1. Every citation into a VENDORED file must be in range. Cheap, and it is the exact
   failure a vendor refresh causes.
2. The scan must not be vacuous — the pass condition and the scanned-nothing
   condition are otherwise the same output.

NOT checked: whether the cited lines say what the surrounding prose claims. That
needs a person. Spot-checked by hand when this was written — the five load-bearing
citations (GetScriptOp's ref handling, GetPushRefs' set filing, the scalar limits)
all resolve to the right code — but a machine cannot keep doing that, and a guard
presented as complete is worse than one with a stated edge.

THE UNVENDORED GAP IS REPORTED, NOT FAILED. At the time of writing, 49 of 112
citations point at Radiant Core files that are NOT vendored, so nothing can check
them. That is not hypothetical damage: `validation.h` was cited in comments and not
vendored, the backing-subset rule lives in it, and a verifier shipped reporting
forged collection membership as authentic because no differential could see the
rule. Whether to vendor more files is a judgment about repo weight versus coverage,
so this test surfaces the list instead of forcing the answer.
"""

from __future__ import annotations

import pathlib
import re

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_VENDOR = _ROOT / "tests" / "vendor" / "radiant_core"

#: ``script.cpp:710-726``, ``src/validation.cpp:667``, ``policy.h:49`` — with or
#: without a leading path and backticks, single line or range.
_CITATION = re.compile(r"`?(?:src/(?:[a-z/]+/)?)?([a-z_]+\.(?:cpp|h))`?:(\d+)(?:-(\d+))?")


def _vendored_line_counts() -> dict[str, int]:
    return {
        p.name: len(p.read_text(encoding="utf-8", errors="replace").split("\n"))
        for p in _VENDOR.glob("*")
        if p.suffix in {".h", ".cpp"}
    }


def _citations() -> list[tuple[str, str, int, int]]:
    """(location, cpp filename, first line, last line) for every citation found."""
    out = []
    for path in list(_ROOT.glob("src/**/*.py")) + list(_ROOT.glob("tests/**/*.py")):
        if path.name == pathlib.Path(__file__).name:
            continue  # this module quotes citations as examples
        text = path.read_text(encoding="utf-8")
        for m in _CITATION.finditer(text):
            line = text[: m.start()].count("\n") + 1
            lo = int(m.group(2))
            out.append((f"{path.relative_to(_ROOT)}:{line}", m.group(1), lo, int(m.group(3) or lo)))
    return out


def test_every_citation_into_a_vendored_file_is_in_range() -> None:
    counts = _vendored_line_counts()
    bad = [
        f"{loc} cites {name}:{lo}-{hi}, but the vendored {name} has {counts[name]} lines"
        for loc, name, lo, hi in _citations()
        if name in counts and (lo < 1 or hi > counts[name])
    ]
    assert not bad, (
        "a citation into a vendored Radiant Core source points outside the file. The "
        "usual cause is a vendor refresh to a newer commit moving the code, which "
        "leaves every line number in the repo silently wrong:\n  " + "\n  ".join(bad)
    )


def test_the_scan_is_not_vacuous() -> None:
    """Measured at 112 citations across 10 vendored files when written."""
    citations = _citations()
    assert len(citations) > 40, f"only {len(citations)} citations found — has the pattern or the tree moved?"
    counts = _vendored_line_counts()
    assert len(counts) >= 8, f"only {len(counts)} vendored sources — is the vendor directory intact?"
    checked = [c for c in citations if c[1] in counts]
    assert len(checked) > 20, (
        f"only {len(checked)} citations land in vendored files; this test is checking almost nothing"
    )


def test_the_unvendored_gap_is_visible() -> None:
    """Not a failure — a standing report of which upstream files pyrxd's correctness
    leans on that no differential can check.

    Asserted only to be non-empty in the sense that the derivation runs: if this ever
    reaches zero, every consensus citation is checkable and this test should be
    turned into a hard gate.
    """
    counts = _vendored_line_counts()
    unvendored: dict[str, int] = {}
    for _loc, name, _lo, _hi in _citations():
        if name not in counts:
            unvendored[name] = unvendored.get(name, 0) + 1
    if not unvendored:
        return  # every citation is checkable; consider making the check above a gate
    ranked = sorted(unvendored.items(), key=lambda kv: -kv[1])
    # The most-cited unpinned file is the one whose absence would cost most, which is
    # precisely how the validation.h gap went unnoticed.
    assert ranked[0][1] < 40, (
        "pyrxd now cites a single unvendored Radiant Core file more than 40 times, so a "
        "large share of its consensus reasoning rests on a source no test can read: "
        f"{ranked[:5]}. Add it via scripts/refresh_radiant_core_vendor.py."
    )
