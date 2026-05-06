"""Output helpers: human / JSON / quiet rendering.

Three output modes drive every command's stdout:

* ``human`` (default): tables, color, friendly photon formatting.
* ``json``: machine-readable; one JSON object per command result.
* ``quiet``: bare result only (e.g. just a txid for ``send``).

A command builds a result dict and calls :func:`emit`, which dispatches
based on the active mode in the :class:`CliContext`.
"""

from __future__ import annotations

import json as _json
from typing import Any


def format_photons(n: int, *, with_rxd: bool = True) -> str:
    """Format an integer photon count for human display.

    1 RXD = 100_000_000 photons (Bitcoin-style satoshi conversion).
    """
    if not isinstance(n, int) or isinstance(n, bool):
        raise TypeError("photons must be int")
    formatted = f"{n:,}"
    if not with_rxd:
        return f"{formatted} photons"
    rxd = n / 100_000_000
    return f"{formatted} photons ({rxd:.8f} RXD)"


def emit(
    payload: dict[str, Any],
    *,
    mode: str = "human",
    quiet_field: str | None = None,
    human_lines: list[str] | None = None,
) -> str:
    """Render *payload* for the active output *mode*.

    Parameters
    ----------
    payload:
        The command's result as a flat dict. Used directly in JSON mode.
    mode:
        One of ``human``, ``json``, ``quiet``.
    quiet_field:
        Field name to print bare in quiet mode. Required if mode='quiet'.
    human_lines:
        Pre-formatted lines for human mode. If omitted, falls back to a
        simple ``key: value`` per line over *payload*.
    """
    if mode == "json":
        # ensure_ascii=True (Python default, made explicit) so non-ASCII bytes
        # in any string field are \u-escaped — defense against terminal-control
        # / bidi-override injection through a CBOR-sourced field surfaced by a
        # future inspect path. Don't flip this without rerunning the threat model.
        return _json.dumps(payload, ensure_ascii=True, separators=(",", ": "), indent=2)
    if mode == "quiet":
        if quiet_field is None:
            # Caller didn't pick a field; default to printing nothing.
            return ""
        value = payload.get(quiet_field, "")
        return str(value)
    # human
    if human_lines is not None:
        return "\n".join(human_lines)
    # Fallback: key: value per line.
    return "\n".join(f"{k}: {v}" for k, v in payload.items())


def emit_table(
    rows: list[dict[str, Any]],
    columns: list[str],
    *,
    mode: str = "human",
    quiet_field: str | None = None,
) -> str:
    """Render a list of dict rows as a table (or JSON array, or quiet stream).

    Quiet mode prints one *quiet_field* value per line.
    """
    if mode == "json":
        # See note on emit() above — ensure_ascii=True is explicit defense.
        return _json.dumps(rows, ensure_ascii=True, separators=(",", ": "), indent=2)
    if mode == "quiet":
        if quiet_field is None:
            return ""
        return "\n".join(str(r.get(quiet_field, "")) for r in rows)
    # Human table: simple, fixed-width columns.
    if not rows:
        return "(none)"
    widths = {col: max(len(col), max(len(str(r.get(col, ""))) for r in rows)) for col in columns}
    header = "  ".join(col.ljust(widths[col]) for col in columns)
    separator = "  ".join("-" * widths[col] for col in columns)
    lines = [header, separator]
    lines.extend("  ".join(str(r.get(col, "")).ljust(widths[col]) for col in columns) for r in rows)
    return "\n".join(lines)
