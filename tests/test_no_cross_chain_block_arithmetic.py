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
_CANONICAL_DERIVATION = "scripts/_dust_swap_shared.py"


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
    """Honest-path, against the REAL file rather than a synthetic string.

    ``derive_counter_timelock`` is the one place a Radiant block count and a Bitcoin margin are
    reconciled, and it needs NO exemption: converting to seconds first puts the two identifiers in
    different statements. Asserting that here is strictly better than an allowlist entry — an
    exemption is an untested claim, and the skip it produced reported green while saying nothing.
    """
    src = (_ROOT / _CANONICAL_DERIVATION).read_text()
    assert "def derive_counter_timelock" in src, f"{_CANONICAL_DERIVATION} no longer holds the derivation"
    assert not _offending_expressions(src)


@pytest.mark.parametrize(
    "path",
    sorted(p for p in [*(_ROOT / "scripts").glob("*.py"), *(_ROOT / "src").rglob("*.py")] if p.is_file()),
    ids=lambda p: str(p.relative_to(_ROOT)),
)
def test_no_cross_chain_block_arithmetic(path):
    rel = str(path.relative_to(_ROOT))
    offending = _offending_expressions(path.read_text())
    assert not offending, (
        f"{rel} mixes a RADIANT-block count with a BITCOIN-block margin in one expression: "
        f"{offending}. Use scripts/_dust_swap_shared.derive_counter_timelock, which converts "
        f"to seconds first."
    )
