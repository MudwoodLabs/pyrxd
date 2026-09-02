"""No expression may mix a RADIANT-block count with a BITCOIN-block margin.

The defect this scans for (#567) shipped in THREE runners at once, each spelling
it identically::

    t_btc = t_rxd - margin - 4

``t_rxd`` counts Radiant blocks (~300 s); ``margin`` counts Bitcoin blocks
(~600 s). Subtracting one from the other is a unit conflation that yields a
NEGATIVE wall-clock margin at every realistic parameter — the layout where the
maker refunds the leg it locked and still claims the other with ``p``.

The correct derivation converts to SECONDS first, which structurally separates
the two: ``t_rxd`` meets an interval, and the margin is applied on the far side.
So "these two identifiers never appear in one arithmetic expression" is not a
heuristic — it is the shape of the fix.

Why a scanner and not three fixes: the three copies were fixed together, and a
FOURTH runner (``btc_swap_two_host``) was missed and kept the pre-inversion
ordering in its CLI defaults. Enumerating siblings by hand is what failed; this
enumerates them by parsing.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_RXD_BLOCK_NAMES = ("t_rxd", "rxd_blocks", "t_rxd_blocks")
_MARGIN_NAMES = ("margin_blocks", "margin")

#: The ONE place the two quantities are allowed to be reconciled — and it does so
#: in seconds, so even here they do not meet inside a single expression.
_ALLOWLIST = {"scripts/_dust_swap_shared.py"}


def _offending_expressions(source: str) -> list[str]:
    """Every arithmetic expression naming BOTH a Radiant-block count and a margin."""
    hits = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.BinOp) or not isinstance(node.op, (ast.Add, ast.Sub)):
            continue
        text = ast.unparse(node)
        if any(r in text for r in _RXD_BLOCK_NAMES) and any(m in text for m in _MARGIN_NAMES):
            hits.append(text)
    return hits


def test_the_scanner_actually_catches_the_shipped_defect():
    """Non-vacuity: the detector must fire on the exact expression that shipped.

    Without this, a scanner that silently matches nothing is indistinguishable
    from a codebase that is clean.
    """
    planted = "t_btc = t_rxd - margin_blocks - 4\n"
    assert _offending_expressions(planted), "scanner failed to flag the #567 formula"


def test_the_scanner_does_not_flag_the_correct_derivation():
    """Honest-path: converting through seconds must NOT trip the scanner."""
    correct = (
        "usable = int((t_rxd_blocks * rxd_block_interval_s) // btc_block_interval_s)\n"
        "t_btc_blocks = usable - margin_blocks\n"
    )
    assert not _offending_expressions(correct)


@pytest.mark.parametrize(
    "path",
    sorted(p for p in [*(_ROOT / "scripts").glob("*.py"), *(_ROOT / "src").rglob("*.py")] if p.is_file()),
    ids=lambda p: str(p.relative_to(_ROOT)),
)
def test_no_cross_chain_block_arithmetic(path):
    rel = str(path.relative_to(_ROOT))
    if rel in _ALLOWLIST:
        pytest.skip(f"{rel} is the single allowed derivation, and it works in seconds")
    offending = _offending_expressions(path.read_text())
    assert not offending, (
        f"{rel} mixes a RADIANT-block count with a BITCOIN-block margin in one expression: "
        f"{offending}. Use scripts/_dust_swap_shared.derive_counter_timelock, which converts "
        f"to seconds first."
    )
