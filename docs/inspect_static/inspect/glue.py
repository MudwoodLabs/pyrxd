"""Pyodide-side glue between the browser UI and the ``pyrxd.glyph.inspect`` façade.

This module is loaded into the Pyodide WASM runtime by ``inspect.js`` and
exposes two entry points — :func:`run` for offline classification of a
user-pasted string, and :func:`inspect_txid_with_raw` for classifying a
transaction whose raw bytes JS already fetched. Both return a
JSON-serialisable dict that the JS side renders without further parsing.

Design rules:

* **No exceptions cross the bridge.** Every error becomes a structured
  ``{"ok": False, "error": ..., "form": ...}`` dict that the JS side can
  display directly. Pyodide can surface Python exceptions to JS but the
  resulting `Error` objects are awkward to inspect from the renderer.
* **No async.** Network fetches happen in JS using the browser's native
  WebSocket API; this module is pure synchronous classification.
* **Sanitize once, here.** Any string that came out of CBOR or any other
  attacker-controllable source passes through ``sanitize_display_string``
  before going into the returned dict. The JS side trusts the dict;
  sanitization is this module's job.
* **Truncate display strings here too.** The 200-char human cap is
  applied before the dict crosses the bridge so the JS side doesn't have
  to re-implement the limit.
"""

from __future__ import annotations

import sys

# AES shim for Pyodide. ``pyrxd`` imports ``Cryptodome.Cipher.AES``
# (from ``pycryptodomex``), which only ships C-extension wheels and
# therefore can't be installed via micropip under WASM. Pyodide ships
# the sibling package ``pycryptodome`` (no -x), which exposes the same
# API under the ``Crypto`` namespace. Installing it via micropip and
# aliasing ``Cryptodome`` → ``Crypto`` lets pyrxd import unchanged.
#
# This block is a no-op when ``Cryptodome`` is already importable
# (i.e. native Python with pycryptodomex installed) — the import below
# fails on Pyodide before pyrxd's import chain triggers, then we route
# every ``Cryptodome.*`` lookup through the ``Crypto.*`` package.
try:
    import Cryptodome  # noqa: F401  # native pycryptodomex path
except ImportError:
    import Crypto
    import Crypto.Cipher
    import Crypto.Hash

    sys.modules["Cryptodome"] = Crypto
    sys.modules["Cryptodome.Cipher"] = Crypto.Cipher
    sys.modules["Cryptodome.Hash"] = Crypto.Hash
    # The two specific submodules pyrxd actually imports from. Aliasing
    # the parent isn't enough because ``from Cryptodome.Cipher import AES``
    # walks the dotted path and looks up ``AES`` as an attribute of
    # ``Cryptodome.Cipher``. We populate the same namespace so the
    # attribute exists.
    from Crypto.Cipher import AES as _AES

    sys.modules["Cryptodome.Cipher.AES"] = _AES

from pyrxd.glyph import inspect as _inspect

# Maximum hex characters we'll accept in a paste. Larger inputs are
# refused before any classification work — defense against accidental
# "I pasted a 4MB tx hex dump file" and against a hostile script trying
# to feed pathological inputs to the classifiers. Mirrors the CLI's
# ``_MAX_SCRIPT_HEX_LEN`` but tightened: web users paste, CLI users
# pipe — different blast radius.
_MAX_PASTE_LEN_CHARS = 200_000  # = 100 KB binary equivalent

# Truncation cap for any user-controlled string we render in the human
# view. Same value the CLI uses (``_HUMAN_STRING_CAP`` in glyph_cmds).
_HUMAN_STRING_CAP = 200


def run(raw_input: str) -> dict:
    """Classify ``raw_input`` and return a render-ready result dict.

    Result shape (keys present in every successful return):

    * ``ok`` — bool. Always True on success, False on any error.
    * ``form`` — one of ``"txid" | "contract" | "outpoint" | "script"`` on
      success; ``"error"`` on failure.
    * ``input`` — the (lowercased, normalised) string we classified. Useful
      for the URL share-param path so the UI's render and the URL stay in
      sync.
    * ``payload`` — the per-form result dict from ``pyrxd.glyph.inspect``
      (with all CBOR-derived strings sanitized).

    Failure shape:

    * ``ok`` — False
    * ``form`` — ``"error"``
    * ``error`` — short human-readable message (already sanitized)
    * ``hint`` — optional follow-up suggestion (e.g. "use --fetch")
    """
    if not isinstance(raw_input, str):
        return _err("input must be a string", form="error")

    stripped = raw_input.strip()
    if not stripped:
        return _err("input is empty", form="error")

    if len(stripped) > _MAX_PASTE_LEN_CHARS:
        return _err(
            f"input too long ({len(stripped):,} chars); cap is "
            f"{_MAX_PASTE_LEN_CHARS:,}. For larger inputs use the CLI: "
            f"pyrxd glyph inspect <txid> --fetch",
            form="error",
        )

    try:
        form, value = _inspect.classify_input(stripped)
    except Exception as exc:
        return _err(_safe_error(exc), form="error")

    # Each form has its own dispatcher. Once classification accepted the
    # shape, any downstream failure is a parser-level rejection of a
    # well-shaped-but-invalid input, so the form-specific hint is always
    # the useful follow-up. We catch the broad ``Exception`` here rather
    # than just ``ValidationError`` because the CLI helpers raise
    # ``UserError`` for some failure modes (e.g. malformed outpoint vout)
    # and we want a uniform structured-dict response either way.
    try:
        if form == "txid":
            payload = _inspect_txid_offline(value)
        elif form == "contract":
            payload = _inspect.inspect_contract(value)
        elif form == "outpoint":
            payload = _inspect.inspect_outpoint(value)
        elif form == "script":
            payload = _inspect.inspect_script(value)
        else:
            return _err(f"internal: unknown form {form!r}", form="error")
    except Exception as exc:
        return _err(_safe_error(exc), form="error", hint=_hint_for(form))

    # Sanitize any string fields that could have come from attacker-controlled
    # bytes. Today the offline forms don't surface CBOR strings — that's
    # PR-C territory — but we walk the dict defensively so a future
    # change can't accidentally leak unsanitized text past this boundary.
    sanitized = _sanitize_payload_strings(payload)

    return {
        "ok": True,
        "form": form,
        "input": stripped.lower() if form != "outpoint" else stripped,
        "payload": sanitized,
    }


def _inspect_txid_offline(value: str) -> dict:
    """txid form before fetch: render a "press the button to fetch" stub.

    The page renders this as a card with a "Fetch from network" button.
    On click, JS uses the browser's native WebSocket to pull the raw
    transaction from the configured ElectrumX server, then calls
    :func:`inspect_txid_with_raw` to classify the result.
    """
    return {
        "form": "txid",
        "txid": value,
        "needs_fetch": True,
        "message": (
            "This looks like a txid. Press the button below to fetch the "
            "raw transaction from the Radiant network and classify each "
            "output."
        ),
    }


def inspect_txid_with_raw(txid: str, raw_hex: str) -> dict:
    """Classify a transaction whose raw bytes JS already fetched.

    The JS side opens a WebSocket to the configured ElectrumX server,
    sends ``blockchain.transaction.get`` for ``txid``, and hands the
    returned hex to this function. The same threat-model guards that
    the CLI's ``--fetch`` path applies — size cap, hash256 server-honesty
    check, structural caps, per-output try/except, sanitised metadata —
    run here as well, because we re-use the same ``classify_raw_tx``
    helper the CLI uses.

    Result shape mirrors :func:`run` for consistency: a top-level dict
    with ``ok``, ``form="txid"``, ``input`` (the txid), and ``payload``
    (the classification dict from ``classify_raw_tx``). On failure,
    ``ok=False`` and a structured error+hint pair as elsewhere.
    """
    if not isinstance(txid, str) or not isinstance(raw_hex, str):
        return _err("txid and raw_hex must both be strings", form="error")

    txid = txid.strip().lower()
    raw_hex = raw_hex.strip()

    if len(txid) != 64:
        return _err(
            f"txid is {len(txid)} chars; expected 64",
            form="error",
            hint=_hint_for("contract"),
        )

    if not raw_hex:
        return _err("raw_hex is empty", form="error")

    # Length cap on the *hex string* — equivalent to twice the byte cap
    # the CLI applies (4 MB binary = 8 MB hex). Refusing oversize input
    # before parsing avoids spending classifier work on pathological
    # responses from a hostile or buggy server.
    if len(raw_hex) > 8_000_000:
        return _err(
            f"raw_hex too long ({len(raw_hex):,} chars); cap is 8,000,000",
            form="error",
        )

    try:
        raw = bytes.fromhex(raw_hex)
    except ValueError as exc:
        return _err(f"raw_hex is not valid hex: {_safe_error(exc)}", form="error")

    try:
        payload = _inspect.classify_raw_tx(txid, raw)
    except Exception as exc:
        return _err(
            _safe_error(exc),
            form="error",
            hint=(
                "If the error mentions hash mismatch, the ElectrumX server "
                "returned the wrong transaction — try again or change "
                "servers. Other errors usually mean the bytes are malformed."
            ),
        )

    sanitized = _sanitize_payload_strings(payload)
    return {
        "ok": True,
        "form": "txid",
        "input": txid,
        "payload": sanitized,
    }


def _hint_for(form: str) -> str:
    """A one-line follow-up hint per failed-form."""
    return {
        "contract": (
            "Glyph contract ids are 72 hex characters: "
            "<32-byte txid in display order><4-byte vout in big endian>"
        ),
        "outpoint": (
            "Outpoints look like '<64-char-txid>:<vout-int>' "
            "— check your colon and length"
        ),
        "script": (
            "Scripts are hex-encoded locking-script bytes. "
            "P2PKH is 25 bytes (50 hex chars); FT is 75 bytes (150 hex chars)."
        ),
        "txid": "",
    }.get(form, "")


def _err(message: str, *, form: str, hint: str = "") -> dict:
    """Build a structured error result. ``message`` and ``hint`` are passed
    through the sanitizer so a hostile parser exception text can't leak
    control bytes into the DOM."""
    return {
        "ok": False,
        "form": form,
        "error": _truncate(_inspect.sanitize_display_string(message)),
        "hint": _truncate(_inspect.sanitize_display_string(hint)) if hint else "",
    }


def _safe_error(exc: BaseException) -> str:
    """Render an exception as a single-line string fit for display.

    Strips the exception class name and any nested chain — the user only
    needs the message. ``str(exc)`` already does the right thing for
    ``ValidationError`` (the project's own exception).
    """
    text = str(exc) or type(exc).__name__
    return text.splitlines()[0] if text else "(unknown error)"


def _truncate(s: str, cap: int = _HUMAN_STRING_CAP) -> str:
    """Apply the human-string display cap. Returns ``s`` unchanged if
    short enough."""
    return _inspect.truncate_for_human(s, cap=cap) if isinstance(s, str) else s


def _sanitize_payload_strings(value):
    """Recursively walk a dict/list payload and sanitize every string.

    Leaves non-strings alone. Used as the final step before the result
    dict crosses the bridge: any string the JS side will eventually
    write to the DOM has already had control / format / combining
    codepoints stripped.

    This is paranoid — today's offline forms don't carry CBOR strings —
    but threading the sanitizer through a single point now means PR-C
    can't accidentally regress when it adds ``main``, ``name``,
    ``description``, ``ticker``, etc. to the payload.
    """
    if isinstance(value, str):
        return _inspect.sanitize_display_string(value)
    if isinstance(value, dict):
        return {k: _sanitize_payload_strings(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_sanitize_payload_strings(v) for v in value]
    if isinstance(value, tuple):
        return tuple(_sanitize_payload_strings(v) for v in value)
    return value
