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

_ROOT = Path(__file__).resolve().parent.parent
SRC = _ROOT / "src"

#: The PUBLISHED, PRESCRIPTIVE surface — what a reader builds against.
#:
#: The lock-order scan below originally covered ``src/`` alone. That is why #568 corrected the
#: handshake spec while four user-facing pages kept teaching the superseded protocol, and why a
#: runner's ``--help`` kept teaching the superseded timelock rule: neither is in ``src/``.
#:
#: ``docs/brainstorms/`` and ``docs/plans/`` are excluded — they are dated working drafts, and a
#: draft that records what we believed in June is not stale, it is a record.
_SCANNED_DIRS = (
    _ROOT / "src",
    _ROOT / "scripts",
    _ROOT / "conformance",
    _ROOT / "docs" / "how-to",
    _ROOT / "docs" / "tutorials",
    _ROOT / "docs" / "concepts",
    _ROOT / "docs" / "solutions",
)
_SCANNED_GLOBS = ("*.py", "*.md", "*.json")


def _scanned_files():
    seen = []
    for d in _SCANNED_DIRS:
        if not d.exists():
            continue
        for g in _SCANNED_GLOBS:
            seen.extend(d.rglob(g))
    seen.extend(p for p in (_ROOT / "docs").glob("*.md"))
    return sorted(set(seen))


#: Phrasings that assert the PRE-#482 timelock direction, in either variable naming.
#:
#: BOTH namings matter: #568 swept for ``t_btc`` and left ``t_counterchain`` / ``t_counter``
#: untouched in the how-to, the tutorial and the audit-scope table. Same rule, different letter.
#: Both hyphens matter too — the specs use U+2212 MINUS, the source uses ASCII.
STALE_TIMELOCK_PATTERNS = (
    r"t_btc\s*[-\u2212]\s*t_rxd\s*[>\u2265]",
    r"t_(btc|counter|counterchain)\s*[>\u2265]\s*t_rxd\s*\+\s*margin",
    r"must exceed t_rxd \+ margin",
    r"(btc|bitcoin)\s+(\w+\s+)?(is|takes|carries|holds)\s+the\s+longer",
    r"leg claimed \*?\*?second\*?\*?.{0,60}shorter",
)

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
HISTORICAL_MARKER = re.compile(
    r"predates HZ-1|inverted the lock order|Do not restore the old wording"
    # For the timelock family: the constructions a CORRECTION uses to quote what it replaced.
    # Deliberately explicit — a loose marker (\"no longer\", \"superseded\") would excuse the very
    # lines this scanner exists to catch.
    r"|until 2026|until #\d|pre-#482|before #482|the old text|this asserted|ran compared"
    r"|was constructed as|said the opposite|stated the exact reverse|published the opposite"
    r"|taught the opposite|stated the reverse|not regenerated since",
    re.I,
)

#: A historical note wraps: the marker opens the callout and the quoted rule lands a line or two
#: later. Look back this far — small enough that an unrelated correction upstream cannot excuse a
#: stale line, large enough for prose that reflows.
_MARKER_LOOKBACK = 3


def _is_marked(lines: list[str], idx: int) -> bool:
    start = max(0, idx - _MARKER_LOOKBACK)
    return any(HISTORICAL_MARKER.search(x) for x in lines[start : idx + 1])


def _offenders(patterns: tuple[str, ...] = STALE_ORDER_PATTERNS) -> list[str]:
    hits: list[str] = []
    for path in _scanned_files():
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (UnicodeDecodeError, OSError):  # pragma: no cover - binary/unreadable
            continue
        for idx, line in enumerate(lines):
            if _is_marked(lines, idx):
                continue
            for pat in patterns:
                if re.search(pat, line, re.I):
                    hits.append(f"{path.relative_to(_ROOT)}:{idx + 1}: {line.strip()[:100]}")
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


def test_no_published_surface_teaches_the_pre_482_timelock_direction() -> None:
    """The counterpart to the lock-order scan, for the TIMELOCK direction.

    #482 inverted it and #568 corrected the handshake spec. Four user-facing pages kept the
    old rule anyway — ``docs/how-to/build-a-cross-chain-swap.md``, the tutorial, the dry-run
    how-to and the security-audit-scope table — because they spell it ``t_counterchain`` /
    ``t_counter`` and the sweep looked for ``t_btc``. One of them carried a MUST directive
    for the check that permits the maker to take both legs, and the audit-scope row told an
    external auditor the wrong invariant was the one being enforced.
    """
    offenders = _offenders(STALE_TIMELOCK_PATTERNS)
    assert not offenders, (
        "the published surface teaches the pre-#482 timelock direction.\n"
        "The maker holds p, LOCKS the Radiant leg and CLAIMS the counter leg, so the leg it\n"
        "LOCKS carries the LONGER refund. In wall clock (#567):\n"
        "    t_rxd * i_rxd >= t_counter * i_counter + margin * i_counter\n"
        "If a line genuinely quotes the superseded rule, say so within 3 lines above it.\n  " + "\n  ".join(offenders)
    )


@pytest.mark.parametrize(
    "sentence",
    [
        # the four pages, as they actually read before 2026-09-02
        "The timelocks must satisfy **`t_counterchain > t_rxd + margin`**: the leg claimed",
        "The coordinator refuses to proceed unless `t_counter > t_rxd + margin`.",
        "the `t_counterchain > t_rxd + margin` safety invariant — read",
        "| `SWAP-TIMELOCK-INVARIANT` | high | mitigated | `t_counter > t_rxd + margin` is client-enforced",
        # the runner --help, and the gate's own docstring
        'help="(maker) the BTC HTLC CSV (must exceed t_rxd + margin)"',
        "3. The cross-chain timelock ordering. BTC: the same-clock margin ``t_btc - t_rxd >= margin``.",
        # both hyphen spellings of the reversed subtraction
        "The taker's client MUST verify `t_BTC \u2212 t_RXD \u2265 margin` before funding",
        "The whole cross-chain safety invariant (``t_BTC - t_RXD >= margin``) rides on",
        # the prose forms
        "BTC also takes the longer timelock as the slower, harder-to-reorg chain",
        "The leg claimed **second** must have the **shorter** refund window",
    ],
)
def test_the_timelock_scanner_catches_every_sentence_that_actually_shipped(sentence: str) -> None:
    """Non-vacuity, from the real corpus.

    Each string is a line that WAS in the tree. A scanner is only worth its runtime if it
    fires on the wording that actually got past review — and every one of these did.
    """
    assert any(re.search(p, sentence, re.I) for p in STALE_TIMELOCK_PATTERNS), sentence


@pytest.mark.parametrize(
    "line",
    [
        "t_rxd * i_rxd >= t_btc * i_btc + margin * i_btc",
        "The timelocks must satisfy, **in wall clock**:",
        "the leg it LOCKS carries the LONGER refund window and the leg it CLAIMS the shorter",
        'raise SystemExit(f"--t-rxd must be > --t-btc (Radiant is the longer leg)")',
        "the maker locks the asset FIRST and the taker funds the counter leg SECOND",
    ],
)
def test_correct_timelock_wording_is_not_refused(line: str) -> None:
    """A guard that refuses valid work is a bug. The CORRECTED phrasings must all pass —
    including the runner refusal that names Radiant as the longer leg, which is now right."""
    assert not any(re.search(p, line, re.I) for p in STALE_TIMELOCK_PATTERNS), line
