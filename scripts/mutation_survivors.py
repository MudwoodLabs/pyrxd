#!/usr/bin/env python3
"""Turn cosmic-ray session databases into a human-triageable survivor list.

``cr-report`` prints one block per *job* — operator name, occurrence index and a
job id — with no file:line and no source context. That is enough to count
survivors and useless for triaging them: you cannot tell an annotation-equivalent
``bytes | None`` rewrite from a deleted byte-order reversal without opening the
file yourself, 300 times.

The session ``.sqlite`` already holds everything needed. ``mutation_specs`` carries
``start_pos_row`` (the 1-based line), ``definition_name`` (the enclosing function)
and the operator; ``work_results`` carries the ``test_outcome`` and the unified
``diff`` cosmic-ray applied. This joins the two, keeps the survivors, and emits
Markdown grouped by module and sorted by line so a reviewer can walk a file
top-to-bottom.

Usage::

    python scripts/mutation_survivors.py OUT.md SESSION.sqlite [SESSION.sqlite ...]

Each row is one surviving mutant: the line it sits on, the enclosing definition,
the mutation operator, and the changed source line (``-`` original, ``+`` mutant).
"""

from __future__ import annotations

import re
import sqlite3
import sys
from collections import defaultdict
from pathlib import Path

# The cosmic-ray operator names are long and repetitive ("core/ReplaceComparisonOperator_Eq_NotEq").
# Strip the namespace so the table stays readable; the full name is recoverable from the diff.
_PREFIX = "core/"

# The single largest equivalent-mutant class: `X | None` in a type annotation rewritten to
# `X + None`, `X & None` &c. `from __future__ import annotations` makes annotations strings that
# are never evaluated, so these cannot be killed and are pure noise in a triage list. Flagging
# rather than dropping them keeps the file a complete record — the reader can skip the marked rows,
# but nothing is silently missing if the heuristic is ever wrong.
_ANNOTATION_CONTEXT = re.compile(r"(->|:\s*[\w\.\[\]\"' ]+\s*[|+\-*/&^%<>])")


def _likely_annotation_equivalent(operator: str, original: str) -> bool:
    if not operator.startswith("ReplaceBinaryOperator_BitOr_"):
        return False
    return bool(_ANNOTATION_CONTEXT.search(original))


def _mutation_lines(diff: str) -> tuple[str, str]:
    """Pull the single ``-``/``+`` pair out of a cosmic-ray unified diff.

    Returns ``(original, mutant)`` already stripped. Cosmic-ray emits exactly one
    changed line per mutant, so anything else means an unexpected diff shape and we
    degrade to empty strings rather than guessing.
    """
    minus = [ln[1:].strip() for ln in diff.splitlines() if ln.startswith("-") and not ln.startswith("---")]
    plus = [ln[1:].strip() for ln in diff.splitlines() if ln.startswith("+") and not ln.startswith("+++")]
    return (minus[0] if len(minus) == 1 else "", plus[0] if len(plus) == 1 else "")


def _escape(text: str) -> str:
    """Make a source line safe inside a Markdown table cell."""
    return text.replace("|", "\\|").replace("\n", " ")


def collect(session_paths: list[str]) -> dict[str, list[tuple[int, str, str, str, str]]]:
    """Read every session and return survivors keyed by module path."""
    by_module: dict[str, list[tuple[int, str, str, str, str]]] = defaultdict(list)
    for raw in session_paths:
        path = Path(raw)
        if not path.exists():
            print(f"warning: no such session: {path}", file=sys.stderr)
            continue
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            rows = conn.execute(
                """
                SELECT s.module_path, s.start_pos_row, s.definition_name,
                       s.operator_name, r.diff
                  FROM mutation_specs s
                  JOIN work_results r ON r.job_id = s.job_id
                 WHERE r.test_outcome = 'SURVIVED'
                """
            ).fetchall()
        finally:
            conn.close()
        for module_path, line, definition, operator, diff in rows:
            original, mutant = _mutation_lines(diff or "")
            by_module[module_path].append(
                (
                    line or 0,
                    definition or "(module level)",
                    (operator or "").removeprefix(_PREFIX),
                    original,
                    mutant,
                )
            )
    return by_module


def _generated_stamp() -> str:
    """`YYYY-MM-DD (<short sha>)` for the tree this run describes, or the date alone."""
    import datetime
    import subprocess

    date = datetime.date.today().isoformat()
    try:
        sha = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True, check=True
        ).stdout.strip()
    except Exception:  # pragma: no cover - a tarball checkout has no git
        return date
    return f"{date} (`{sha}`)"


def render(by_module: dict[str, list[tuple[int, str, str, str, str]]]) -> str:
    """Render the survivor map as a Markdown document."""
    out: list[str] = [
        "# Surviving mutants",
        "",
        "Generated by `scripts/mutation_survivors.py` from the cosmic-ray session databases.",
        "One row per **surviving** mutant: the suite ran that mutated line and no assertion failed.",
        "",
        # Rows QUOTE SOURCE, so an undated table silently ages into fiction: the
        # assert_timelock_margin rows kept showing `t_btc - t_rxd` for weeks after #482/#567
        # changed what that function computes. Stamp when it was produced.
        f"> **Snapshot generated {_generated_stamp()}.** Rows quote the source as it stood then.",
        "> If the tree has moved since, a quoted line may no longer exist in that form — re-run",
        "> `task mutate` before triaging against today's code.",
        "",
        "A survivor is *not* automatically a bug — see the equivalent-mutant classes catalogued in",
        "`docs/how-to/mutation-testing.md` (type annotations, error-message f-strings,",
        "interpreter-detail rewrites). Triage means deciding, per row, whether the mutated behaviour",
        "is genuinely indistinguishable or whether nothing tests it.",
        "",
    ]
    if not by_module:
        out += ["_No surviving mutants recorded._", ""]
        return "\n".join(out)

    total = sum(len(v) for v in by_module.values())
    flagged = sum(
        1
        for rows in by_module.values()
        for _, _, operator, original, _ in rows
        if _likely_annotation_equivalent(operator, original)
    )
    out += [
        f"**{total} surviving mutants across {len(by_module)} modules**, "
        f"of which {flagged} are marked `annot` — a type annotation rewritten by a BitOr-family "
        "operator, which cannot change behaviour. Start with the unmarked rows.",
        "",
    ]

    for module_path in sorted(by_module):
        survivors = sorted(by_module[module_path], key=lambda r: (r[0], r[2]))
        marked = sum(1 for _, _, op, orig, _ in survivors if _likely_annotation_equivalent(op, orig))
        out += [
            f"## `{module_path}` — {len(survivors)} survivors ({marked} `annot`)",
            "",
            "| Line | Definition | Operator | Original | Mutant | |",
            "|---|---|---|---|---|---|",
        ]
        for line, definition, operator, original, mutant in survivors:
            flag = "`annot`" if _likely_annotation_equivalent(operator, original) else ""
            out.append(
                f"| {line} | `{_escape(definition)}` | `{_escape(operator)}` "
                f"| `{_escape(original)}` | `{_escape(mutant)}` | {flag} |"
            )
        out.append("")
    return "\n".join(out)


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print(__doc__, file=sys.stderr)
        return 2
    out_path, sessions = Path(argv[1]), argv[2:]
    by_module = collect(sessions)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(render(by_module), encoding="utf-8")
    total = sum(len(v) for v in by_module.values())
    print(f"wrote {total} surviving mutants to {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
