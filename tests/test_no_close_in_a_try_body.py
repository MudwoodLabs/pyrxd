"""A test must not close a client, socket or server at the END of a ``try`` body.

``client.close()`` as the last statement of ``try:`` runs only when every assertion above it passed,
so the one run where the resource matters — a failing one — leaks it, and the leak shows up later as
an unrelated warning or a hung loop in some other test. Close it in ``finally`` or with ``with``.

Found in ``tests/test_taker_funding_spv_gate.py`` (two ElectrumX clients) and in three daemon-socket
probes whose ``close()`` was skipped whenever ``connect`` raised. This scan keeps the pattern out.
"""

from __future__ import annotations

import ast
from pathlib import Path

_TESTS = Path(__file__).resolve().parent


def closes_in_a_try_body(source: str) -> list[int]:
    """Lines of ``.close()`` / ``.aclose()`` calls that sit in a ``try`` body (not its ``finally``)."""
    found: list[int] = []

    def visit(stmts: list[ast.stmt], in_try_body: bool) -> None:
        for st in stmts:
            if isinstance(st, ast.Try):
                visit(st.body, True)
                for handler in st.handlers:
                    visit(handler.body, in_try_body)
                visit(st.orelse, in_try_body)
                visit(st.finalbody, False)
                continue
            if isinstance(st, (ast.With, ast.AsyncWith, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                visit(st.body, False)  # a with-block or a new scope owns its own cleanup
                continue
            if isinstance(st, (ast.If, ast.For, ast.AsyncFor, ast.While)):
                visit(st.body, in_try_body)
                visit(st.orelse, in_try_body)
                continue
            if in_try_body:
                found.extend(
                    node.lineno
                    for node in ast.walk(st)
                    if isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr in ("close", "aclose")
                )

    visit(ast.parse(source).body, False)
    return found


def test_no_test_closes_a_resource_in_a_try_body() -> None:
    offenders = []
    scanned = 0
    for path in sorted(_TESTS.rglob("*.py")):
        if "vendor" in path.parts:
            continue
        scanned += 1
        offenders += [f"{path.relative_to(_TESTS)}:{n}" for n in closes_in_a_try_body(path.read_text("utf-8"))]
    assert scanned > 300, f"only {scanned} test files scanned — the walk is not reading tests/"
    assert not offenders, "close() at the end of a try body leaks on a failing assertion; use finally/with:\n  " + (
        "\n  ".join(offenders)
    )


def test_the_scan_finds_the_pattern_and_passes_the_fixes() -> None:
    """The two shapes this file was written for, and their fixed forms."""
    leaky = (
        "async def t():\n"
        "    try:\n"
        "        client = make()\n"
        "        assert await client.read()\n"
        "        await client.close()\n"
        "    finally:\n"
        "        server.close()\n"
        "def probe():\n"
        "    while True:\n"
        "        if ready():\n"
        "            s = sock()\n"
        "            try:\n"
        "                s.connect(path)\n"
        "                s.close()\n"
        "            except OSError:\n"
        "                pass\n"
    )
    assert closes_in_a_try_body(leaky) == [5, 14]
    fixed = (
        "async def t():\n"
        "    try:\n"
        "        client = make()\n"
        "        try:\n"
        "            assert await client.read()\n"
        "        finally:\n"
        "            await client.close()\n"
        "    finally:\n"
        "        server.close()\n"
        "def probe():\n"
        "    with sock() as s:\n"
        "        try:\n"
        "            s.connect(path)\n"
        "        except OSError:\n"
        "            pass\n"
    )
    assert closes_in_a_try_body(fixed) == []
