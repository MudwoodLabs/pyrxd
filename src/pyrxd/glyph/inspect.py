"""Public façade for the Glyph inspect surface.

The CLI command ``pyrxd glyph inspect`` and the browser-hosted inspect
tool (loaded via Pyodide at ``docs/inspect_static/inspect/``) share a
common set of pure-Python helpers. Those helpers live in
:mod:`pyrxd.glyph._inspect_core` so they're decoupled from the CLI's
infrastructure (``click``, ``HdWallet``, signing, network clients). The
browser tool imports through this façade, which simply re-exports the
core helpers under public names (no underscore prefix).

Public surface:

* :func:`classify_input` — dispatch a raw string to its form
  (``"txid" | "contract" | "outpoint" | "script"``)
* :func:`classify_raw_tx` — classify every output (and reveal CBOR) for
  a pre-fetched raw transaction. Synchronous; takes pre-fetched bytes
  rather than an ElectrumXClient, so the browser tool can fetch via the
  native WebSocket API and feed bytes straight into the same classifier
  the CLI uses
* :func:`inspect_contract` — decode a 72-char Glyph contract id
* :func:`inspect_outpoint` — decode a ``txid:vout`` outpoint
* :func:`inspect_script` — classify a hex-encoded locking script and
  extract type-specific fields
* :func:`sanitize_display_string` — strip control / format / combining
  Unicode codepoints from any string sourced from CBOR before display
* :func:`truncate_for_human` — cap a sanitized string at the project's
  display cap
* :func:`skeleton` — apply Unicode TR39 confusable reduction; two
  strings that "look the same" produce identical skeletons
* :func:`looks_confusable_with_latin` — high-level check that flags
  Latin-impersonating spoofs (e.g. Cyrillic-letter "USDC")

Errors: every helper here raises
:class:`pyrxd.security.errors.ValidationError` on invalid input. The
CLI layer translates these into ``UserError`` with cause/fix
decorations. External callers should ``except ValidationError`` and
display the message string directly.

If you are inside the pyrxd codebase, import the underlying helpers
directly from ``pyrxd.glyph._inspect_core``. If you are outside (web
UI, downstream tooling), import from this module — it commits to a
stable signature and shape.
"""

from __future__ import annotations

# Re-export the SDK-level helpers under public names. These come
# directly from the pure-Python core module — NOT from the CLI module
# — so importing this façade doesn't transitively pull click, HdWallet,
# coincurve, aiohttp, websockets, or Cryptodome.Cipher. That property
# is asserted by ``tests/web/test_inspect_imports_pyodide_clean.py``.
from ._inspect_core import (
    _classify_input as classify_input,
)
from ._inspect_core import (
    _classify_raw_tx as classify_raw_tx,
)
from ._inspect_core import (
    _inspect_contract as inspect_contract,
)
from ._inspect_core import (
    _inspect_outpoint as inspect_outpoint,
)
from ._inspect_core import (
    _inspect_script as inspect_script,
)
from ._inspect_core import (
    _sanitize_display_string as sanitize_display_string,
)
from ._inspect_core import (
    _truncate_for_human as truncate_for_human,
)
from .confusables import looks_confusable_with_latin, skeleton

# The async ``_inspect_txid_inner`` requires an ElectrumXClient (or
# something quacking like one) plus an event loop, neither of which is
# straightforward to set up under Pyodide's WASM runtime. The web UI
# fetches the raw bytes via the browser's native ``WebSocket`` API and
# hands them to ``classify_raw_tx`` instead — that helper does the same
# threat-model checks the CLI's --fetch path applies, just without the
# coroutine + client coupling. We deliberately do not re-export
# ``_inspect_txid_inner`` here.

__all__ = [
    "classify_input",
    "classify_raw_tx",
    "inspect_contract",
    "inspect_outpoint",
    "inspect_script",
    "looks_confusable_with_latin",
    "sanitize_display_string",
    "skeleton",
    "truncate_for_human",
]
