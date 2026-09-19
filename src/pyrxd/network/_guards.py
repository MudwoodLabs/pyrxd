"""Re-export of the untrusted-JSON coercions, which now live one layer down.

The functions themselves moved to :mod:`pyrxd.security.json_guards` so that a
caller can reach them without executing ``pyrxd.network.__init__`` — that
``__init__`` eagerly re-exports the ElectrumX and Bitcoin clients, so importing
anything under ``pyrxd.network`` pulls in ``coincurve``, ``aiohttp`` and
``websockets``. None of the three has a pure-Python wheel, so under Pyodide the
import fails outright, and :mod:`pyrxd.glyph.mark_anchor` — which coerces an
endpoint's confirmation depth through :func:`nonneg_int` — was unreachable from
the browser inspect page for that reason alone.

This module stays because ~30 call sites import from it and a move that
rewrites them all is a move that can silently rewrite one of them wrongly.
It re-exports; it does NOT redefine. ``tests/network/test_guards.py`` asserts
the identity, the same way ``GENESIS_BLOCK_HASHES`` is asserted to be
re-exported rather than copied.
"""

from __future__ import annotations

from ..security.json_guards import finite_int, hex_str, merkle_branch, nonneg_int, require_bool

__all__ = ["finite_int", "hex_str", "merkle_branch", "nonneg_int", "require_bool"]
