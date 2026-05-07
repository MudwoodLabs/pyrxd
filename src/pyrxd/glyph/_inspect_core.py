"""Pure-Python inspect helpers, decoupled from the CLI infrastructure.

This module hosts the helpers the inspect tool uses — both the CLI
(``pyrxd glyph inspect ...``) and the browser-hosted inspect tool
(``docs/inspect_static/inspect/``). Keeping them here, separate from
``pyrxd.cli.glyph_cmds``, means callers can import the inspect surface
without dragging in the rest of the CLI's import graph (``click``,
``HdWallet``, signing, network clients, etc.).

Why this exists:

The CLI module ``glyph_cmds.py`` imports ``HdWallet`` (signing →
``coincurve``), the ElectrumX client (→ ``websockets``), and ``aiohttp``
at module top level. A caller doing ``from pyrxd.glyph import inspect``
would, before this split, transitively pull in all of those — none of
which the inspect helpers actually need. Under Pyodide this manifests
as ``micropip.install`` trying to fetch ``coincurve`` (no pure-Python
wheel exists) and failing the page boot.

The split keeps the helpers pure: the only deps they reach for are
``pyrxd.glyph.types`` / ``script`` / ``dmint`` / ``inspector`` /
``payload`` (all clean), ``pyrxd.transaction.transaction`` (clean), and
``pyrxd.hash`` (clean since the OpenSSL-3 / RIPEMD160 fix).

Errors:

The helpers raise ``ValidationError`` (from ``pyrxd.security.errors``)
on bad input. The CLI wraps these as ``UserError`` at the boundary so
the user sees the existing CLI-formatted message with ``cause`` /
``fix`` lines. The browser tool's glue catches them and translates to
its structured-dict response.
"""

from __future__ import annotations

import unicodedata

from ..hash import hash256
from ..security.errors import ValidationError
from ..security.types import Txid
from ..transaction.transaction import Transaction

# --- Length / shape constants ----------------------------------------------
#
# These mirror the values the CLI used previously (verbatim — the wire
# behaviour is unchanged across the move). The CLI re-imports them from
# here so a single change updates both surfaces.
_TXID_HEX_LEN = 64
_CONTRACT_HEX_LEN = 72
# The minimum script we'd reasonably classify is plain P2PKH (25 bytes / 50 hex).
_MIN_SCRIPT_HEX_LEN = 50
# Cap accidental "paste a whole tx" before running every classifier on it.
_MAX_SCRIPT_HEX_LEN = 20_000

# --- Network-fetch (--fetch) safety bounds ---------------------------------
# Radiant policy max for a tx is 4 MB. Anything larger is consensus-invalid
# and either a buggy server or an attacker probing for a parser-DoS.
_MAX_RAW_TX_BYTES = 4_000_000
# Per-tx structural caps. A real Radiant tx today has a few inputs/outputs;
# 100k is generous head-room and bounds total classification work.
_MAX_INPUT_COUNT = 100_000
_MAX_OUTPUT_COUNT = 100_000
# Per-string display cap in human mode for any user-controllable CBOR field.
# JSON mode preserves the full string (still ASCII-safe via ensure_ascii).
_HUMAN_STRING_CAP = 200


# Unicode general categories that must NOT reach a terminal: control (Cc),
# format (Cf — includes BOM, bidi-overrides, ZWJ/ZWNJ, tag chars), unassigned
# (Cn), private-use (Co), line/paragraph separators (Zl/Zp), and combining
# marks (Mn/Me — overlay glyphs onto the previous char). This subsumes the
# explicit bidi-override / BOM allow-list the previous version maintained.
_UNICODE_STRIP_CATEGORIES = frozenset({"Cc", "Cf", "Cn", "Co", "Zl", "Zp", "Mn", "Me"})


def _sanitize_display_string(s: str) -> str:
    """Strip control + invisible + combining codepoints from a string before printing.

    Defense against terminal-injection / homoglyph / bidi-override attacks via
    CBOR-sourced fields (token name, description, ticker, attrs.*, creator.pubkey,
    etc.). A hostile token deployer can embed ANSI CSI escapes, zero-width joiners,
    bidi-override codepoints, tag chars, or combining marks in their metadata; an
    inspect of the deploy tx would otherwise pass them straight to the user's
    terminal — the deployer's name could appear to flip directionality, hide
    chars, or imitate adjacent fields.

    Strips any character whose Unicode general category is one of:

        Cc — ASCII / C1 control (includes \\x1b ANSI ESC, \\x07 BEL)
        Cf — format chars (BOM, bidi overrides, ZWJ/ZWNJ, tag chars, …)
        Cn — unassigned codepoints
        Co — private-use area
        Zl, Zp — line / paragraph separators (\\u2028, \\u2029)
        Mn, Me — combining marks (overlay onto previous char)

    Replaces each stripped char with a literal "?" so the user sees that
    something was filtered.

    Non-`str` input is returned unchanged (defensive — the type signature
    forbids it but the type system doesn't enforce that at runtime).
    """
    if not isinstance(s, str):
        return s
    out: list[str] = []
    for ch in s:
        if unicodedata.category(ch) in _UNICODE_STRIP_CATEGORIES:
            out.append("?")
        else:
            out.append(ch)
    return "".join(out)


def _truncate_for_human(s: str, cap: int = _HUMAN_STRING_CAP) -> str:
    """Truncate a sanitized string for human-mode display."""
    if len(s) <= cap:
        return s
    return s[: cap - 1] + "…"


def _classify_input(s: str) -> tuple[str, str]:
    """Dispatch on input shape. Returns (form, normalised_value).

    form ∈ {"txid", "contract", "outpoint", "script"}.

    Auto-detect rules (unambiguous by length / content):
      * 64 hex → txid
      * 72 hex → contract
      * contains ":" → outpoint (validated downstream)
      * 50–20_000 even-length hex → script

    A bare 64-hex string is always treated as a txid even though it could
    structurally also be a 32-byte payload-hash push prefix; the txid form
    is the only one users hit in practice from a block explorer.

    Leading/trailing whitespace is stripped here (ergonomics — users paste
    from explorers and shells often add a newline). This is BEFORE the
    downstream ``Txid`` newtype's regex check, but ``Txid`` rejects any
    embedded whitespace so the strip is safe. If a future change loosened
    ``Txid`` to accept internal whitespace this would silently propagate;
    keep the validators tight.
    """
    s = s.strip()
    if not s:
        raise ValidationError("inspect input is empty")
    if ":" in s:
        return ("outpoint", s)
    lowered = s.lower()
    if len(lowered) == _TXID_HEX_LEN and all(c in "0123456789abcdef" for c in lowered):
        return ("txid", lowered)
    if len(lowered) == _CONTRACT_HEX_LEN and all(c in "0123456789abcdef" for c in lowered):
        return ("contract", lowered)
    if (
        _MIN_SCRIPT_HEX_LEN <= len(lowered) <= _MAX_SCRIPT_HEX_LEN
        and len(lowered) % 2 == 0
        and all(c in "0123456789abcdef" for c in lowered)
    ):
        return ("script", lowered)
    raise ValidationError(f"could not classify input (length {len(s)})")


def _inspect_contract(contract_hex: str) -> dict:
    """Decode a 72-char contract id. Return a flat dict for emit()."""
    from .types import GlyphRef

    ref = GlyphRef.from_contract_hex(contract_hex)
    return {
        "form": "contract",
        "txid": ref.txid,
        "vout": ref.vout,
        "outpoint": f"{ref.txid}:{ref.vout}",
        "wire_hex": ref.to_bytes().hex(),
    }


def _inspect_outpoint(s: str) -> dict:
    """Parse a `txid:vout` string. Returns a flat dict for emit().

    Rejects malformed input loudly so the user sees a clear error rather
    than a confusing downstream traceback.
    """
    from .types import GlyphRef

    if s.count(":") != 1:
        raise ValidationError(f"outpoint must be exactly one 'txid:vout', got {s!r}")
    txid_str, vout_str = s.split(":", 1)
    try:
        vout = int(vout_str, 10)
    except ValueError as exc:
        raise ValidationError(f"vout is not an integer: {vout_str!r}") from exc
    ref = GlyphRef(txid=Txid(txid_str.lower()), vout=vout)
    return {
        "form": "outpoint",
        "txid": ref.txid,
        "vout": ref.vout,
        "outpoint": f"{ref.txid}:{ref.vout}",
        "wire_hex": ref.to_bytes().hex(),
    }


def _inspect_script(script_hex: str) -> dict:
    """Classify a single hex-encoded locking script. Returns a flat dict."""
    from .dmint import DmintState
    from .script import (
        MUTABLE_NFT_SCRIPT_RE,
        extract_owner_pkh_from_commit_script,
        extract_owner_pkh_from_ft_script,
        extract_owner_pkh_from_nft_script,
        extract_payload_hash_from_commit_script,
        extract_ref_from_ft_script,
        extract_ref_from_nft_script,
        is_commit_ft_script,
        is_commit_nft_script,
        is_ft_script,
        is_nft_script,
        parse_mutable_nft_script,
    )

    try:
        script = bytes.fromhex(script_hex)
    except ValueError as exc:
        raise ValidationError("script is not valid hex") from exc

    base = {"form": "script", "length": len(script), "hex": script_hex}

    # Plain P2PKH check first (cheapest, common).
    if len(script) == 25 and script[:3] == b"\x76\xa9\x14" and script[23:] == b"\x88\xac":
        return {**base, "type": "p2pkh", "owner_pkh": script[3:23].hex()}

    if is_nft_script(script_hex):
        ref = extract_ref_from_nft_script(script)
        pkh = extract_owner_pkh_from_nft_script(script)
        return {
            **base,
            "type": "nft",
            "ref_txid": ref.txid,
            "ref_vout": ref.vout,
            "ref_outpoint": f"{ref.txid}:{ref.vout}",
            "owner_pkh": bytes(pkh).hex(),
        }

    if is_ft_script(script_hex):
        ref = extract_ref_from_ft_script(script)
        pkh = extract_owner_pkh_from_ft_script(script)
        return {
            **base,
            "type": "ft",
            "ref_txid": ref.txid,
            "ref_vout": ref.vout,
            "ref_outpoint": f"{ref.txid}:{ref.vout}",
            "owner_pkh": bytes(pkh).hex(),
        }

    if MUTABLE_NFT_SCRIPT_RE.fullmatch(script_hex):
        parsed = parse_mutable_nft_script(script)
        if parsed is not None:
            ref, payload_hash = parsed
            return {
                **base,
                "type": "mut",
                "ref_txid": ref.txid,
                "ref_vout": ref.vout,
                "ref_outpoint": f"{ref.txid}:{ref.vout}",
                "payload_hash": payload_hash.hex(),
            }

    if is_commit_nft_script(script_hex):
        return {
            **base,
            "type": "commit-nft",
            "payload_hash": extract_payload_hash_from_commit_script(script).hex(),
            "owner_pkh": bytes(extract_owner_pkh_from_commit_script(script)).hex(),
        }

    if is_commit_ft_script(script_hex):
        return {
            **base,
            "type": "commit-ft",
            "payload_hash": extract_payload_hash_from_commit_script(script).hex(),
            "owner_pkh": bytes(extract_owner_pkh_from_commit_script(script)).hex(),
        }

    # dMint contract is variable-length and parser-only; try last.
    try:
        state = DmintState.from_script(script)
    except ValidationError:
        return {**base, "type": "unknown"}

    return {
        **base,
        "type": "dmint",
        "version": "v1" if state.is_v1 else "v2",
        "contract_ref_outpoint": f"{state.contract_ref.txid}:{state.contract_ref.vout}",
        "token_ref_outpoint": f"{state.token_ref.txid}:{state.token_ref.vout}",
        "height": state.height,
        "max_height": state.max_height,
        "reward": state.reward,
        "algo": state.algo.name,
        "daa_mode": state.daa_mode.name,
    }


def _classify_raw_tx(txid_hex: str, raw: bytes, *, only_vout: int | None = None) -> dict:
    """Classify every output (and reveal CBOR) for a pre-fetched transaction.

    Synchronous, network-free core. The CLI's ``--fetch`` path wraps this
    with an async ``ElectrumXClient.get_transaction`` call; the browser
    inspect tool calls this directly after performing its own WebSocket
    fetch in JS.

    Threat-model guards:

    * Validate ``txid_hex`` via the ``Txid`` newtype.
    * Refuse ``raw`` shorter than 65 bytes (Merkle-forgery defence; the
      ``RawTx`` newtype enforces this at its boundary, but ``raw`` here
      is a plain ``bytes`` so we re-check explicitly).
    * Refuse ``raw`` larger than ``_MAX_RAW_TX_BYTES`` (Radiant policy max).
    * Server-honesty check: ``hash256(raw)[::-1].hex() == txid_hex`` so a
      hostile source can't return some *other* tx.
    * Refuse parsed txs with more than ``_MAX_OUTPUT_COUNT`` /
      ``_MAX_INPUT_COUNT`` entries — bounds total classification work.
    * Wrap per-output classification in try/except so one malformed script
      cannot abort the listing.
    * Use ``GlyphInspector.find_reveal_metadata`` (already swallows
      exceptions around ``decode_payload``) for input metadata extraction.
    * Sanitize every CBOR-derived display string before it leaves this
      function.

    Errors raised here are bare ``ValidationError`` instances. The CLI
    layer wraps them in ``UserError`` with cause/fix so the user-visible
    formatted output is unchanged. Callers handling structured error
    output (the browser tool's glue) read the message string directly.

    :param raw: pre-fetched raw transaction bytes (NOT hex).
    :param only_vout: if not None, restrict the outputs list to a single
        vout — used by the ``--resolve`` outpoint flow.
    """
    from .inspector import GlyphInspector

    txid = Txid(txid_hex.lower())  # raises ValidationError on bad shape

    if len(raw) <= 64:
        raise ValidationError(f"raw bytes too short for a valid transaction ({len(raw)} bytes; need >64)")

    if len(raw) > _MAX_RAW_TX_BYTES:
        raise ValidationError(
            f"transaction is larger than the policy max "
            f"(server returned {len(raw)} bytes; policy max is {_MAX_RAW_TX_BYTES})"
        )

    computed = hash256(bytes(raw))[::-1].hex()
    if computed != str(txid):
        raise ValidationError(
            f"server returned a transaction whose hash does not match the requested txid "
            f"(requested {txid}, got {computed})"
        )

    tx = Transaction.from_hex(bytes(raw))
    if tx is None:
        raise ValidationError("could not parse the raw transaction bytes")

    if len(tx.inputs) > _MAX_INPUT_COUNT or len(tx.outputs) > _MAX_OUTPUT_COUNT:
        raise ValidationError(
            f"transaction structure exceeds inspect's safety caps (inputs={len(tx.inputs)}, outputs={len(tx.outputs)})"
        )

    output_rows: list[dict] = []
    enumerated = list(enumerate(tx.outputs))
    if only_vout is not None:
        if not (0 <= only_vout < len(tx.outputs)):
            raise ValidationError(f"vout {only_vout} is out of range (transaction has {len(tx.outputs)} output(s))")
        enumerated = [(only_vout, tx.outputs[only_vout])]

    for idx, out in enumerated:
        try:
            script_bytes = out.locking_script.serialize()
            row = _inspect_script(script_bytes.hex())
            row.pop("form", None)  # always "script" — redundant inside a tx listing
            row["vout"] = idx
            row["satoshis"] = out.satoshis
            output_rows.append(row)
        except Exception as exc:  # defensive: any classifier crash → unknown row
            output_rows.append(
                {
                    "vout": idx,
                    "type": "error",
                    "error": type(exc).__name__,
                    "satoshis": out.satoshis,
                }
            )

    # IMPORTANT: every string field surfaced into ``metadata_payload`` MUST
    # be passed through ``_sanitize_display_string`` first. JSON mode escapes
    # non-ASCII via ``ensure_ascii=True``, but human mode prints these strings
    # straight to the terminal where ANSI / bidi-override / zero-width
    # injection would land. ``protocol`` is a list of CBOR-supplied values
    # — coerce each to ``str`` and sanitize before display, since
    # ``str(list_of_strings)`` calls ``repr`` on each element and ``repr``
    # does NOT escape U+202E and friends.
    inspector = GlyphInspector()
    scriptsigs = [bytes(inp.unlocking_script.serialize()) for inp in tx.inputs]
    found = inspector.find_reveal_metadata(scriptsigs)
    metadata_payload: dict | None = None
    if found is not None:
        input_idx, metadata = found
        metadata_payload = {
            "input_index": input_idx,
            "protocol": [_sanitize_display_string(str(p)) for p in metadata.protocol],
            "name": _sanitize_display_string(metadata.name) if metadata.name else "",
            "ticker": _sanitize_display_string(metadata.ticker) if metadata.ticker else "",
            "description": _sanitize_display_string(metadata.description) if metadata.description else "",
            "decimals": metadata.decimals,
        }
        if metadata.main is not None:
            from ..hash import sha256

            metadata_payload["main"] = (
                f"<media: {_sanitize_display_string(metadata.main.mime_type)}, "
                f"{len(metadata.main.data)} bytes, "
                f"sha256={sha256(metadata.main.data).hex()}>"
            )

    return {
        "form": "txid",
        "txid": str(txid),
        "byte_length": len(raw),
        "input_count": len(tx.inputs),
        "output_count": len(tx.outputs),
        "outputs": output_rows,
        "metadata": metadata_payload,
    }
