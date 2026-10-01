"""Every message that names an endpoint does so through ``redacted_url`` — derived from the source.

The CLI sweep (``tests/cli/test_endpoint_secrets_never_printed.py``) runs the commands it can
drive to a network read; many ``fix: check that <endpoint> is reachable`` hints sit behind a
funded wallet or a mint in progress and are out of a subprocess test's reach. This scan covers
those: in every module under ``src/pyrxd``, an f-string that interpolates ``electrumx_url`` or an
``X.url`` attribute, and a ``logger.*`` call passing an ``X.url`` argument, must wrap it in
:func:`pyrxd.network.redaction.redacted_url`. The set of sites is derived by walking the AST, not
listed by hand; the non-vacuity assertion fails if the walk ever stops finding the wrapped ones.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pyrxd

SRC = Path(pyrxd.__file__).resolve().parent
_WRAPPERS = {"redacted_url"}
_LOG_METHODS = {"debug", "info", "warning", "error", "exception", "critical", "log"}


def _names_an_endpoint(node: ast.AST) -> bool:
    if isinstance(node, ast.Attribute) and node.attr in ("url", "electrumx_url"):
        return True
    return isinstance(node, ast.Name) and node.id == "electrumx_url"


def _is_wrapped(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in _WRAPPERS
        and any(_names_an_endpoint(a) for a in node.args)
    )


def _sites() -> tuple[list[str], list[str]]:
    """``(raw sites, wrapped sites)`` as ``path:line``."""
    raw: list[str] = []
    wrapped: list[str] = []
    for path in sorted(SRC.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        rel = path.relative_to(SRC)
        for node in ast.walk(tree):
            exprs: list[ast.AST] = []
            if isinstance(node, ast.FormattedValue):
                exprs = [node.value]
            elif (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in _LOG_METHODS
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id in ("logger", "log", "logging", "_log", "_logger")
            ):
                exprs = list(node.args[1:])
            for e in exprs:
                if _names_an_endpoint(e):
                    raw.append(f"{rel}:{e.lineno}")
                elif _is_wrapped(e):
                    wrapped.append(f"{rel}:{e.lineno}")
    return raw, wrapped


def test_no_message_names_an_endpoint_url_unredacted() -> None:
    raw, wrapped = _sites()
    assert raw == [], "endpoint URL interpolated into a message without redacted_url():\n" + "\n".join(raw)
    # Non-vacuity: when this was written the walk found 32 wrapped sites (25 CLI f-strings, 6
    # failover log lines, 1 registry message). A walk that finds far fewer has stopped working.
    assert len(wrapped) >= 30, wrapped
