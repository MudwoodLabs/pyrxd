"""The shipped source must not tell readers the pre-HZ-1 lock order.

HZ-1 (#392) inverted the protocol: the MAKER locks the Radiant asset FIRST, and
``taker_funds_btc`` refuses until ``pre_btc_lock_check`` step 5 has read that covenant off
the Radiant chain. Nine docstrings and comments in ``src/`` still described the old
taker-locks-first order afterwards, including the module-level protocol summary and a
docstring that contradicted itself two paragraphs apart.

That is not a cosmetic drift. A reviewer read one of them and filed a MEDIUM security
finding (#486) against a gate placement the protocol had already moved — the same shape as
#505, where a stale in-repo sentence was cited back as corroboration for a defect that did
not exist. Prose that describes a protocol IS load-bearing when reviewers reason from it, so
it gets a scanner like any other invariant.

This is a DETECT-level mechanism (see
``docs/solutions/test-failures/engineering-rules-stayed-prose-until-tests-made-them-executable.md``):
it cannot prove the docs are right, only that this specific wrong claim has not come back.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parent.parent / "src"

# Each pattern is a phrasing that asserts the PRE-HZ-1 order. Kept narrow and anchored on
# "maker"/"taker" so ordinary prose about locks cannot trip them.
STALE_ORDER_PATTERNS = (
    r"before the maker locks",
    r"before the maker is told to lock",
    r"maker locks the asset second",
    r"maker locks rxd second",
    r"taker locks btc first",
    r"taker deploys the eth htlc first",
)

# A line may describe the OLD order deliberately — the invariant constant explains that its
# own name predates HZ-1, and eth_leg.py warns against restoring the old wording. Such a line
# must say so, on the line itself, with this marker.
HISTORICAL_MARKER = re.compile(r"predates HZ-1|inverted the lock order|Do not restore the old wording", re.I)


def _offenders() -> list[str]:
    hits: list[str] = []
    for path in sorted(SRC.rglob("*.py")):
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if HISTORICAL_MARKER.search(line):
                continue
            for pat in STALE_ORDER_PATTERNS:
                if re.search(pat, line, re.I):
                    hits.append(f"{path.relative_to(SRC.parent.parent)}:{lineno}: {line.strip()[:100]}")
                    break
    return hits


def test_no_shipped_source_claims_the_pre_hz1_lock_order() -> None:
    offenders = _offenders()
    assert not offenders, (
        "shipped source describes the pre-HZ-1 lock order, which HZ-1 (#392) inverted.\n"
        "The MAKER locks the Radiant asset FIRST; the taker will not fund until\n"
        "`pre_btc_lock_check` step 5 has read the covenant off chain. A maker-side gate that\n"
        "runs after that protects the REVEAL, not the lock.\n"
        "If a line genuinely describes the history, say so on that line.\n  " + "\n  ".join(offenders)
    )


def test_the_scanner_actually_matches_the_sentence_that_caused_486() -> None:
    """The honest-path half: prove the patterns catch the real wording, not just an empty set.

    Without this, deleting every pattern would leave the test above green forever.
    """
    removed = "The taker deploys the ETH HTLC FIRST and the maker locks RXD SECOND, so the maker MUST"
    assert any(re.search(p, removed, re.I) for p in STALE_ORDER_PATTERNS)


@pytest.mark.parametrize(
    "line",
    [
        "the MAKER locks the asset FIRST (Radiant covenant).",
        "binds to the maker's EXPECTED terms BEFORE the maker reveals p.",
        "# NB the NAME predates HZ-1 (#392), which inverted the lock order in (2)/(3)",
    ],
)
def test_correct_wording_is_not_refused(line: str) -> None:
    """A guard that refuses valid work is a bug — the corrected phrasings must pass."""
    if HISTORICAL_MARKER.search(line):
        return
    assert not any(re.search(p, line, re.I) for p in STALE_ORDER_PATTERNS)
