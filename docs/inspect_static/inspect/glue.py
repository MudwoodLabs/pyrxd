"""Pyodide-side glue between the browser UI and the ``pyrxd.glyph.inspect`` façade.

This module is loaded into the Pyodide WASM runtime by ``inspect.js`` and
exposes one entry point — :func:`run` — that the JS side calls with a
user-pasted string. It returns a JSON-serialisable dict that the JS side
renders without any further parsing.

Design rules:

* **No exceptions cross the bridge.** Every error becomes a structured
  ``{"ok": False, "error": ..., "form": ...}`` dict that the JS side can
  display directly. Pyodide can surface Python exceptions to JS but the
  resulting `Error` objects are awkward to inspect from the renderer.
* **No async.** Network fetches happen in JS (see PR-C); this module is
  pure synchronous classification.
* **Sanitize once, here.** Any string that came out of CBOR or any other
  attacker-controllable source passes through ``sanitize_display_string``
  before going into the returned dict. The JS side trusts the dict;
  sanitization is this module's job.
* **Truncate display strings here too.** The 200-char human cap is
  applied before the dict crosses the bridge so the JS side doesn't have
  to re-implement the limit.
"""

from __future__ import annotations

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
    """txid form without --fetch: render a friendly placeholder.

    PR-C wires the network fetch path. Until then a bare 64-hex paste
    just gets a "looks like a txid; use --fetch" rendering so the user
    knows the input was recognised but action is required.
    """
    return {
        "form": "txid",
        "txid": value,
        "needs_fetch": True,
        "message": (
            "This looks like a txid. Fetching the transaction from the "
            "Radiant network is the next step — that path is wired in "
            "the next release. For now, paste a script hex, contract id, "
            "or outpoint to see classification offline."
        ),
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
