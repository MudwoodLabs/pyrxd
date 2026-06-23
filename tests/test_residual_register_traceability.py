"""Machine-checked, drift-proof traceability for the audit residual register.

Parses the residual register in ``docs/security-audit-scope.md`` (rows shaped
``| `RESIDUAL-ID` | sev | status | … | where |``) and asserts:

1. **Every code/test path the register cites actually exists.** A moved/deleted module or test named
   in a residual's "where" pointer fails this test, so the auditor-facing register can't silently rot
   (e.g. a renamed ``capped_fee_source.py`` would be caught).
2. **Residual IDs are unique.** The brief itself warns the legacy numbering had collisions (a
   duplicated ``#8``); stable IDs must not collide.

This is the *lightweight, reliable* form of residual→artifact traceability: it machine-checks the
register's concrete references rather than hand-maintaining a separate 40-row ID→test map (which would
drift in its own right). Extend by adding a ``tests/…`` path to a residual's "where" column — this test
then enforces that the cited test keeps existing.
"""

from __future__ import annotations

import re
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
_SCOPE = _REPO / "docs" / "security-audit-scope.md"

# A residual-register row: starts with a backtick-quoted UPPER-CASE stable ID in the first cell.
_ROW = re.compile(r"^\|\s*`([A-Z][A-Z0-9-]+)`\s*\|")
# A code/test path reference: a backtick-quoted token ending in .py.
_PYTOKEN = re.compile(r"`([\w./-]+\.py)`")


def _resolve(token: str) -> Path | None:
    """Resolve a register path token to a real file, or None. Handles repo-root-relative
    (``tests/x.py``), src/pyrxd-relative (``gravity/x.py``), and bare basenames (``x.py``)."""
    for cand in (_REPO / token, _REPO / "src" / "pyrxd" / token):
        if cand.is_file():
            return cand
    base = Path(token).name
    for root in ("src", "tests", "scripts"):
        hits = list((_REPO / root).rglob(base))
        if hits:
            return hits[0]
    return None


def _register_rows() -> list[tuple[str, str]]:
    """Return (residual_id, full_row_text) for every residual-register row."""
    rows = []
    for line in _SCOPE.read_text(encoding="utf-8").splitlines():
        m = _ROW.match(line)
        if m:
            rows.append((m.group(1), line))
    return rows


def test_scope_doc_present_and_has_residuals():
    assert _SCOPE.is_file(), f"{_SCOPE} missing"
    rows = _register_rows()
    assert len(rows) >= 20, f"expected the full residual register; found only {len(rows)} rows"


def test_every_cited_path_in_the_residual_register_exists():
    missing: list[str] = []
    for rid, line in _register_rows():
        for tok in _PYTOKEN.findall(line):
            if _resolve(tok) is None:
                missing.append(f"{rid} → {tok}")
    assert not missing, "residual register cites non-existent paths (drift): " + "; ".join(missing)


def test_residual_ids_are_unique():
    seen: dict[str, int] = {}
    for rid, _ in _register_rows():
        seen[rid] = seen.get(rid, 0) + 1
    dupes = {rid: n for rid, n in seen.items() if n > 1}
    assert not dupes, f"duplicate residual IDs in the register: {dupes}"
