"""Public façade for the Glyph inspect surface.

The CLI command ``pyrxd glyph inspect`` is implemented as a set of
``_``-prefixed helpers inside :mod:`pyrxd.cli.glyph_cmds`. The web UI
hosted at ``docs/inspect/`` (loaded into a browser via Pyodide) needs
the same surface, but **must not** import from CLI internals — that
couples a public-facing tool to private implementation details that can
churn freely.

This module re-exports the inspect helpers as a stable public API so
external callers (the web UI today, future SDK users tomorrow) have a
documented contract:

* :func:`classify_input` — dispatch a raw string to its form
  (``"txid" | "contract" | "outpoint" | "script"``)
* :func:`classify_raw_tx` — classify every output (and reveal CBOR) for
  a pre-fetched raw transaction. Synchronous; takes pre-fetched bytes
  rather than an ElectrumXClient, so the web UI can fetch via the
  browser's native WebSocket and feed bytes straight into the same
  classifier the CLI uses
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

If you are inside the pyrxd codebase, import the underlying helpers
directly. If you are outside (web UI, downstream tooling), import from
this module — it commits to a stable signature and shape.
"""

from __future__ import annotations

# Re-export from the CLI module. The aliasing renames drop the leading
# underscore so callers don't have to reach into a `_`-prefixed name —
# that's the entire point of this façade.
from ..cli.glyph_cmds import (
    _classify_input as classify_input,
)
from ..cli.glyph_cmds import (
    _classify_raw_tx as classify_raw_tx,
)
from ..cli.glyph_cmds import (
    _inspect_contract as inspect_contract,
)
from ..cli.glyph_cmds import (
    _inspect_outpoint as inspect_outpoint,
)
from ..cli.glyph_cmds import (
    _inspect_script as inspect_script,
)
from ..cli.glyph_cmds import (
    _sanitize_display_string as sanitize_display_string,
)
from ..cli.glyph_cmds import (
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
