"""Pyodide-side glue between the browser UI and the ``pyrxd.glyph.inspect`` façade.

This module is loaded into the Pyodide WASM runtime by ``inspect.js`` and
exposes, among others, :func:`run` for offline classification of a
user-pasted string, :func:`inspect_txid_with_raw` for classifying a
transaction whose raw bytes JS already fetched, and
:func:`spent_output_bindings` for checking a reveal's payloads against the
commits they spent (:func:`spent_output_binding` is its one-prevout form). Each returns a JSON-serialisable dict that the JS side
renders without further parsing.

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

import functools
import sys
import unicodedata

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
    # Availability probe — we don't reference the import binding,
    # we're only catching ImportError to drive the Pyodide alias setup
    # below. Using importlib.util.find_spec to make the intent loud
    # to both readers and code-scanning tools (CodeQL's py/unused-import
    # flags the plain `import Cryptodome` form even with a noqa).
    import importlib.util

    if importlib.util.find_spec("Cryptodome") is None:
        raise ImportError("Cryptodome not available (likely Pyodide)")
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

# Length cap on a fetched transaction's HEX — twice the 4 MB policy maximum the
# classifier refuses above. Applied to the spent transaction as well as the one
# asked for, before either is decoded.
_MAX_RAW_HEX_CHARS = 8_000_000


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
            payload = _inspect.inspect_script(value, network=_PAGE_NETWORK)
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


def _whole_number(name: str, value: object) -> int | dict | None:
    """*value* as a non-negative int, ``None`` for ``None``, or an ``_err`` dict.

    Arrives from JavaScript, so it is checked here rather than trusted: a JS number that is not
    a whole, non-negative integer is refused, not rounded.
    """
    if value is None:
        return None
    if isinstance(value, float) and value.is_integer():
        value = int(value)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return _err(f"{name} must be a whole number >= 0, got {value!r}", form="error")
    return value


def inspect_txid_with_raw(
    txid: str,
    raw_hex: str,
    attest_hashmark_limit: object = None,
    max_rows: object = None,
) -> dict:
    """Classify a transaction whose raw bytes JS already fetched.

    *attest_hashmark_limit*: check the signatures of only the first N HashMark records (see
    ``classify_raw_tx``). Both pages pass the number of records they draw, so the curve work one
    linked transaction can demand of a stranger's tab is bounded by what is shown.

    *max_rows*: list at most N entries of each list the transaction produces, and count the rest
    exactly under a ``*_not_listed`` key beside each list (see ``classify_raw_tx``). /inspect/
    passes the number of rows it draws, so the number of entries of each of those lists that
    crosses into JavaScript — and that the page then converts, draws and puts in its raw-JSON
    drawer — is bounded by it. The size of one entry is not (``classify_raw_tx`` says which
    entries can be large). ``None`` lists everything.

    The payload binding is NOT decided here: :func:`spent_output_bindings` does that, once the
    page has fetched the transactions the payload ``binding_candidates`` names.

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
    attest_hashmark_limit = _whole_number("attest_hashmark_limit", attest_hashmark_limit)
    if isinstance(attest_hashmark_limit, dict):
        return attest_hashmark_limit
    max_rows = _whole_number("max_rows", max_rows)
    if isinstance(max_rows, dict):
        return max_rows

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
    if len(raw_hex) > _MAX_RAW_HEX_CHARS:
        return _err(
            f"raw_hex too long ({len(raw_hex):,} chars); cap is {_MAX_RAW_HEX_CHARS:,}",
            form="error",
        )

    try:
        raw = bytes.fromhex(raw_hex)
    except ValueError as exc:
        return _err(f"raw_hex is not valid hex: {_safe_error(exc)}", form="error")

    try:
        payload = _inspect.classify_raw_tx(
            txid, raw, network=_PAGE_NETWORK, attest_hashmark_limit=attest_hashmark_limit, max_rows=max_rows
        )
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

    return {
        "ok": True,
        "form": "txid",
        "input": txid,
        "payload": _finish_payload(payload),
    }


def _finish_payload(payload: dict) -> dict:
    """What the page draws from a ``classify_raw_tx`` payload: its display warnings added, every
    string sanitised and capped. ONE step, for the first classification and for the one
    :func:`spent_output_bindings` redoes when the headline moves."""
    # Annotate metadata strings with homoglyph / script-mixing warnings.
    # The control-byte sanitizer runs in the next step, but it doesn't
    # catch a token deployer who names their token "USDC" using a
    # Cyrillic 'U' (U+0405) and a Cyrillic 'С' (U+0421) — visually
    # identical to Latin, but a different token.
    #
    # Two attack shapes get flagged:
    #
    #   - "mixed scripts" — Latin ASCII letters mixed with letters from
    #     another script. Classic per-character substitution attack.
    #   - "non-Latin script" — every Letter codepoint comes from a
    #     non-Latin script. Whole-word substitution: pure-Cyrillic
    #     "ВNВ" mimicking Latin "BNB". Doesn't mix scripts but still
    #     visually impersonates Latin to a Latin-default reader.
    #
    # Both surface as ``metadata.display_warnings[<field>]`` so the JS
    # renderer paints a warning band on the affected card.
    metadata = payload.get("metadata") if isinstance(payload, dict) else None
    if isinstance(metadata, dict):
        # SEEDED FROM THE CLASSIFIER, NOT OVERWRITING IT. `_inspect_core` now runs the
        # TR39 confusables skeleton check and puts its findings in this same key. This
        # block used to ASSIGN `display_warnings`, which would have silently replaced
        # the stronger check's results with this weaker one's on the browser path —
        # the same field name, two producers, last writer wins.
        #
        # The two are complementary and neither subsumes the other: TR39 catches
        # per-character Latin MIMICRY ("USDС" with a Cyrillic С) and deliberately
        # ignores wholly non-Latin names; the heuristic below also flags script
        # mixing and whole-word non-Latin, which is broader and noisier. Where both
        # fire on one field, the TR39 reason is kept — it is the more specific claim.
        warnings = dict(metadata.get("display_warnings") or {})
        for field_name in ("name", "ticker", "description"):
            field_value = metadata.get(field_name)
            if isinstance(field_value, str) and field_value:
                reason = _suspicious_reason(field_value)
                if reason:
                    warnings.setdefault(field_name, reason)
        # ``protocol`` is a list of CBOR-supplied values rendered to the
        # user as a comma-joined string. An attacker can put a homoglyph
        # in any element. Walk the list and flag the field if any entry
        # is suspicious.
        protocol = metadata.get("protocol")
        if isinstance(protocol, list):
            for entry in protocol:
                if isinstance(entry, str) and entry:
                    reason = _suspicious_reason(entry)
                    if reason:
                        warnings.setdefault("protocol", reason)
                        break
        if warnings:
            metadata["display_warnings"] = warnings

    return _sanitize_payload_strings(payload)


def spent_output_binding(txid: str, raw_hex: str, prev_raw_hex: object = "", prev_fetch_error: object = "") -> dict:
    """``payload_binding`` for the reveal *raw_hex* carries, against the transaction it spent.

    The page's SECOND step, after :func:`inspect_txid_with_raw` has classified the transaction and
    named ``metadata.input_outpoint``: the page fetches that outpoint's transaction and hands it
    here as *prev_raw_hex* — or, when the fetch was refused, unanswered, or answered with bytes
    that are not that transaction, hands ``""`` and says why in *prev_fetch_error*.

    It does NOT classify the transaction again. Re-running the whole classifier to change one
    field of its metadata was what this step used to cost; the answer comes from
    ``pyrxd.glyph.inspect.spent_output_binding``, which reads the attributed input's envelope, the
    one output it spent, and the reveal's own output scripts (for the ref that output's commit
    demands), and which the CLI's ``--fetch`` calls too. The spent transaction is
    hash-checked there against the txid in the outpoint before anything is read out of it.

    Returns ``{"ok": True, "binding": {...}}`` — ``binding`` is ``None`` when no input is
    attributed a payload — or the usual ``{"ok": False, ...}``. Never raises.
    """
    if not isinstance(txid, str) or not isinstance(raw_hex, str):
        return _err("txid and raw_hex must both be strings", form="error")
    # JavaScript's null arrives as None: the same "nothing here" as the empty string.
    prev_raw_hex = "" if prev_raw_hex is None else prev_raw_hex
    if not isinstance(prev_raw_hex, str):
        return _err("prev_raw_hex must be a string", form="error")
    prev_fetch_error = "" if prev_fetch_error is None else str(prev_fetch_error)
    raw_hex = raw_hex.strip()
    if len(raw_hex) > _MAX_RAW_HEX_CHARS:
        return _err(f"raw_hex too long ({len(raw_hex):,} chars); cap is {_MAX_RAW_HEX_CHARS:,}", form="error")
    try:
        raw = bytes.fromhex(raw_hex)
    except ValueError as exc:
        return _err(f"raw_hex is not valid hex: {_safe_error(exc)}", form="error")

    spent_raw, prev_fetch_error = _spent_answer(prev_raw_hex, prev_fetch_error)
    try:
        binding = _inspect.spent_output_binding(txid.strip().lower(), raw, spent_raw, spent_error=prev_fetch_error)
    except Exception as exc:
        return _err(_safe_error(exc), form="error")
    return {"ok": True, "binding": _sanitize_payload_strings(binding)}


def _spent_answer(prev_raw_hex: str, prev_fetch_error: str) -> tuple[bytes | None, str]:
    """``(the spent transaction's bytes, or None; why there are none)`` from what the page's fetch
    handed over: hex, or nothing and a reason."""
    text = prev_raw_hex.strip()
    if text:
        if len(text) > _MAX_RAW_HEX_CHARS:
            return None, f"the answer is {len(text):,} hex characters, larger than any transaction"
        try:
            return bytes.fromhex(text), prev_fetch_error
        except ValueError as exc:
            return None, f"the answer is not valid hex ({_safe_error(exc)})"
    return None, prev_fetch_error or "the page handed over no spent transaction and no reason"


def spent_output_bindings(
    txid: str,
    raw_hex: str,
    prevs_json: object = "{}",
    errors_json: object = "{}",
    attest_hashmark_limit: object = None,
    max_rows: object = None,
) -> dict:
    """``payload_binding`` for the reveal *raw_hex* carries, against every transaction the page
    fetched for its ``binding_candidates`` — and the headline those rank first.

    The page's SECOND step. :func:`inspect_txid_with_raw` names, in ``binding_candidates``, the
    outpoints of the minting payloads' inputs; the page fetches each and hands them here as
    ``prevs_json``, a JSON object of ``{outpoint: hex}``, with ``errors_json`` saying why for each
    it could not get. JSON strings, not JavaScript objects, so what crosses the bridge is text the
    way every other argument here is. ``pyrxd.glyph.inspect.spent_output_bindings`` hash-checks
    each and decides; the CLI's ``--fetch`` calls the same function.

    Returns ``{"ok": True, "binding": {...} | None}``, and — when that function says the
    classification must be redone (the headline moved to a bound payload, or another payload's
    row has a verdict to show) — ``"payload"``: the transaction classified again with the spent
    scripts, finished exactly as :func:`inspect_txid_with_raw` finishes its own, with *max_rows*
    and *attest_hashmark_limit* as the page passed there. Otherwise nothing is classified again.
    Or the usual ``{"ok": False, ...}``. Never raises.
    """
    import json

    if not isinstance(txid, str) or not isinstance(raw_hex, str):
        return _err("txid and raw_hex must both be strings", form="error")
    attest_hashmark_limit = _whole_number("attest_hashmark_limit", attest_hashmark_limit)
    if isinstance(attest_hashmark_limit, dict):
        return attest_hashmark_limit
    max_rows = _whole_number("max_rows", max_rows)
    if isinstance(max_rows, dict):
        return max_rows
    raw_hex = raw_hex.strip()
    if len(raw_hex) > _MAX_RAW_HEX_CHARS:
        return _err(f"raw_hex too long ({len(raw_hex):,} chars); cap is {_MAX_RAW_HEX_CHARS:,}", form="error")
    try:
        raw = bytes.fromhex(raw_hex)
    except ValueError as exc:
        return _err(f"raw_hex is not valid hex: {_safe_error(exc)}", form="error")
    try:
        prevs = json.loads(prevs_json) if isinstance(prevs_json, str) else None
        errors = json.loads(errors_json) if isinstance(errors_json, str) else None
    except ValueError as exc:
        return _err(f"prevs_json / errors_json is not JSON: {_safe_error(exc)}", form="error")
    if not isinstance(prevs, dict) or not isinstance(errors, dict):
        return _err("prevs_json and errors_json must each be a JSON object", form="error")

    spent: dict[str, bytes | None] = {}
    said: dict[str, str] = {}
    for outpoint in list(prevs) + [op for op in errors if op not in prevs]:
        hex_text = prevs.get(outpoint)
        spent[str(outpoint)], said[str(outpoint)] = _spent_answer(
            hex_text if isinstance(hex_text, str) else "", str(errors.get(outpoint) or "")
        )

    txid = txid.strip().lower()
    try:
        answer = _inspect.spent_output_bindings(txid, raw, spent, said)
        if answer is None:
            return {"ok": True, "binding": None}
        out = {"ok": True, "binding": _sanitize_payload_strings(answer["binding"])}
        if answer["reclassify"]:
            payload = _inspect.classify_raw_tx(
                txid,
                raw,
                network=_PAGE_NETWORK,
                spent_scripts=answer["spent_scripts"],
                attest_hashmark_limit=attest_hashmark_limit,
                max_rows=max_rows,
            )
            payload["metadata"]["payload_binding"] = answer["binding"]
            out["payload"] = _finish_payload(payload)
    except Exception as exc:
        return _err(_safe_error(exc), form="error")
    return out


# Whether a Letter codepoint is Latin-script (A-Z, a-z, plus Latin
# Extended ranges that legitimately occur in user-facing names like
# "Café", "naïve", "Zürich"). Python's stdlib doesn't expose the
# Unicode "script" property directly, but ``unicodedata.name()``
# returns a name string that always starts with the script's English
# label ("LATIN ...", "CYRILLIC ...", "GREEK ...", etc.) — we use that
# prefix as the script identifier. Cached per codepoint to amortise
# the name-lookup cost across long strings.
@functools.lru_cache(maxsize=4096)
def _is_latin_letter(cp: int) -> bool:
    try:
        name = unicodedata.name(chr(cp))
    except ValueError:
        return False
    return name.startswith("LATIN ")


def _suspicious_reason(s: str) -> str:
    """Return a short reason string if *s* might be a homoglyph spoof,
    or empty string if the input is benign.

    NFKC-normalise first so compatibility forms (full-width letters,
    fraction-slash, etc.) collapse to their canonical form before we
    check categories.

    Two attack shapes are caught:

    - **mixed scripts** — Latin ASCII letters alongside letters from
      another script. Per-character substitution: "USDC" with a
      Cyrillic 'U'.
    - **non-Latin script** — every Letter codepoint is non-Latin.
      Whole-word substitution: "ВNВ" mimicking Latin "BNB".

    Pure-Latin strings, pure-non-letter strings (digits / punctuation /
    emoji), and the empty string return "" (benign). Combining marks
    alone are sanitised away upstream by ``sanitize_display_string``;
    we only inspect Letter codepoints here.
    """
    if not isinstance(s, str) or not s:
        return ""
    normalised = unicodedata.normalize("NFKC", s)
    has_latin = False
    has_other_letter = False
    for ch in normalised:
        cp = ord(ch)
        cat = unicodedata.category(ch)
        # Only Letter categories matter for confusables. (Lu / Ll / Lt /
        # Lm / Lo). Symbols, punctuation, digits, and marks don't carry
        # script identity for this check.
        if not cat.startswith("L"):
            continue
        if _is_latin_letter(cp):
            has_latin = True
        else:
            has_other_letter = True
        if has_latin and has_other_letter:
            return "mixed scripts (possible homoglyph)"
    if has_other_letter and not has_latin:
        return "non-Latin script (verify by txid, not by visual name)"
    return ""


def _looks_suspicious(s: str) -> bool:
    """Backwards-compatible boolean wrapper around
    :func:`_suspicious_reason`. Kept for the existing test suite; new
    code should prefer ``_suspicious_reason`` so the actual reason
    surfaces to the user."""
    return bool(_suspicious_reason(s))


def _hint_for(form: str) -> str:
    """A one-line follow-up hint per failed-form."""
    return {
        "contract": (
            "Glyph contract ids are 72 hex characters: <32-byte txid in display order><4-byte vout in big endian>"
        ),
        "outpoint": ("Outpoints look like '<64-char-txid>:<vout-int>' — check your colon and length"),
        "script": (
            "Scripts are hex-encoded locking-script bytes. "
            "P2PKH is 25 bytes (50 hex chars); FT is 75 bytes (150 hex chars)."
        ),
        "txid": "",
    }.get(form, "")


# The page talks to ONE hard-coded mainnet ElectrumX endpoint
# (``ELECTRUMX_WSS_URL`` in inspect.js), so mainnet is the chain every result here
# was actually read from. Passed EXPLICITLY rather than left to the default,
# because a HashMark v2 signature covers the chain's genesis hash: the same bytes
# on another chain are a different statement and verify against a different key.
# If this page ever gains a network selector, this constant is what has to move
# with it, and an explicit argument is what makes that findable.
_PAGE_NETWORK = "mainnet"


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


# Hex-shaped fields don't get truncated — txids, refs, payload hashes,
# and addresses are full-fidelity primary keys; chopping them visually
# misleads the user into thinking a different identifier is in use.
# Field names enumerated explicitly so a future field doesn't sneak
# past the cap by being unexpectedly hex-shaped.
#
# Note: ``main`` is NOT in this list even though the Python side
# constructs it as a ``<media: {mime_type}, {N} bytes, sha256={hex}>``
# summary. The CBOR-supplied ``mime_type`` has no length cap upstream
# (``decode_payload`` doesn't constrain ``m["t"]``), so an attacker
# could put 64KB of mime_type into the constructed string. The
# embedded sha256 is fine to truncate at 200 chars — the user can read
# the full hash via the JSON drawer if needed.
_HEX_FIELDS_NEVER_TRUNCATED = frozenset(
    {
        "txid",
        "ref_txid",
        "ref_outpoint",
        "contract_ref_outpoint",
        "token_ref_outpoint",
        "outpoint",
        "owner_pkh",
        "payload_hash",
        "wire_hex",
        "input",
        # The script bytes themselves. They were chopped to 200 hex chars while
        # inspect.js told the reader the opposite — "the JSON drawer carries the
        # full bytes" — so the drawer, and the Copy JSON button, silently held a
        # prefix. The card printed the true byte count beside it, showing
        # "length: 258 bytes" above 100 bytes of hex.
        #
        # Newly material rather than merely untidy: `data_hex` is now the only
        # place a HashMark or `msg` record's raw bytes appear, and it is what the
        # UI points at ("not valid UTF-8 — see data_hex"). The row stays scannable
        # because inspect.js truncates for DISPLAY at 64 chars on its own; that is
        # the right layer for it, since only the display needs to be short.
        "hex",
        "data_hex",
        # dMint mint-claim scriptSig pushes — exact bytes are load-bearing
        # for verifying a covenant push against an off-chain re-derivation.
        "nonce_hex",
        "input_hash",
        "output_hash",
    }
)


def _sanitize_payload_strings(value, *, key=None):
    """Recursively walk a dict/list payload, sanitize and length-cap
    every string.

    Two transforms are applied:

    1. ``sanitize_display_string`` strips control / format / combining
       codepoints — defends against bidi overrides, ANSI escapes, ZWJ
       fakery in CBOR-derived names/tickers/descriptions.
    2. ``truncate_for_human`` caps the result at ``_HUMAN_STRING_CAP``
       (200 chars) — defends against attacker descriptions that would
       overflow the card and dominate the visual frame. Hex-shaped
       primary keys (txid, refs, owner_pkh, etc.) are NEVER truncated;
       chopping them visually misleads the user into thinking a
       different identifier is in use.

    The ``key`` keyword propagates the parent dict key down so the
    truncation rule can opt out for known hex fields.
    """
    if isinstance(value, str):
        sanitized = _inspect.sanitize_display_string(value)
        if key in _HEX_FIELDS_NEVER_TRUNCATED:
            return sanitized
        return _truncate(sanitized)
    if isinstance(value, dict):
        return {k: _sanitize_payload_strings(v, key=k) for k, v in value.items()}
    if isinstance(value, list):
        return [_sanitize_payload_strings(v, key=key) for v in value]
    if isinstance(value, tuple):
        return tuple(_sanitize_payload_strings(v, key=key) for v in value)
    return value


# ---------------------------------------------------------------------------
# W8 — the verdict view's two extra inputs: the BLOCK, and the FILE.
#
# Both are deliberately thin. Everything a reader could be misled by — how a
# height is derived from a confirmation count, what a digest match is allowed to
# mean, which hash a record actually names — is computed by the same pyrxd code
# the CLI runs, and this module only carries values across the bridge.
# ---------------------------------------------------------------------------

#: What the page asks of a mark's burial before it will call it anchored.
#:
#: ONE, and one means "it is in a block at all" — the boundary between a mark that
#: fixes a time and a mempool entry that fixes nothing. It is not a depth policy and
#: must not be read as one. ``resolve_mark_anchor`` deliberately ships no default
#: because, as the depth registry puts it, depth "buys reorg-resistance priced in that
#: chain's hashrate" and a shipped number is folklore — so this page does not invent
#: one either. It publishes the confirmation count as a FACT and says, on screen, that
#: the judgement of whether that is enough is the reader's.
_ANCHOR_FLOOR = 1

#: Who the anchor came from. The CLI compares this label against the source of the
#: name→glyph binding so one hostile endpoint cannot move both answers; this page has
#: only the one endpoint, so the label exists to SAY that rather than to imply
#: independence it does not have.
_ANCHOR_SOURCE = "the single ElectrumX endpoint this page is allowed to talk to"


def _run_sync(coro):
    """Run a coroutine that never actually suspends, without an event loop.

    Pyodide's main thread already has a running loop, so ``asyncio.run`` is not
    available here. ``resolve_mark_anchor`` has exactly one ``await``, on the
    ``fetch_verbose`` callable we supply — and ours returns a value the page has
    already fetched, so the coroutine runs to completion on the first ``send`` and
    raises ``StopIteration`` carrying the result.

    If it ever DOES suspend, that is a real change in the function's contract and
    this raises rather than returning a half-built anchor.
    """
    try:
        coro.send(None)
    except StopIteration as stop:
        return stop.value
    coro.close()
    raise RuntimeError(
        "resolve_mark_anchor suspended on an await this bridge cannot drive; "
        "the page fetches over its own WebSocket and has no event loop to yield to"
    )


#: Cap on the verbose reply the page may hand across. A confirmation depth and an
#: echoed txid are a few hundred bytes; anything approaching this is a server
#: answering a question nobody asked.
_MAX_VERBOSE_JSON_CHARS = 8_000_000


def mark_anchor(txid: str, verbose_json: str, tip_height: object) -> dict:
    """Where the mark's transaction sits in the chain, per the endpoint that was asked.

    *verbose_json* is the ``blockchain.transaction.get(txid, verbose=True)`` reply as a
    JSON **string** and *tip_height* the ``blockchain.headers.subscribe`` height, both
    fetched by the page. A string rather than a JS object because that makes the
    boundary one this module can define and test on its own terms, instead of one whose
    shape depends on how Pyodide happens to proxy a plain object today.
    Handing them to :func:`pyrxd.glyph.mark_anchor.resolve_mark_anchor` rather than
    reading ``confirmations`` in JS is the whole point: that function binds the echoed
    txid, refuses an unreadable depth instead of reading it as zero, derives the height
    as ``tip - confirmations + 1`` (measured: the verbose reply carries NEITHER
    ``height`` NOR ``blockheight``), and carries the caveat saying the height is the
    endpoint's claim and nothing here verified it.

    Never raises. A failure is a dict with ``resolved: False`` and the reason, because
    losing the block must not lose the record.
    """
    import json

    from pyrxd.glyph.mark_anchor import mark_anchor_dict, resolve_mark_anchor

    if not isinstance(verbose_json, str):
        verbose_json = str(verbose_json)
    if len(verbose_json) > _MAX_VERBOSE_JSON_CHARS:
        return {
            "resolved": False,
            "reason": f"the endpoint's reply is {len(verbose_json):,} chars, over the cap; refusing to parse it",
        }
    try:
        verbose = json.loads(verbose_json)
    except ValueError as exc:
        return {"resolved": False, "reason": _truncate(_inspect.sanitize_display_string(f"unreadable reply: {exc}"))}
    if not isinstance(verbose, dict):
        return {"resolved": False, "reason": "the endpoint's reply was not an object"}

    async def _fetch(_requested: str) -> dict:
        return verbose

    try:
        anchor = _run_sync(
            resolve_mark_anchor(
                txid=txid,
                fetch_verbose=_fetch,
                source=_ANCHOR_SOURCE,
                min_confirmations=_ANCHOR_FLOOR,
                tip_height=int(tip_height) if tip_height is not None else None,
            )
        )
    except Exception as exc:
        return {"resolved": False, "reason": _truncate(_inspect.sanitize_display_string(_safe_error(exc)))}

    # THE SHAPE IS `mark_anchor_dict`'s, not this module's. It was factored out so a
    # height never reaches a screen without the caveat that it is one endpoint's
    # unverified claim, and a page assembling its own dict of the same fields would be
    # the second display shape that helper exists to prevent.
    shape = mark_anchor_dict(anchor)

    # THREE KEYS DROPPED, DELIBERATELY, and this is the only place it happens.
    #
    # `provisional` and `deep_enough` are verdicts ON THE DEPTH, computed against
    # `min_confirmations` — and the floor this page passes is 1, which means "it is in a
    # block at all" and is NOT a depth policy. Rendering "deep_enough: true" from it
    # would turn "this is in a block" into "this is buried enough", a judgement nobody
    # here has made. `pyrxd verify` keeps all three because it REQUIRES the operator to
    # name a floor and then gates an exit code on it; a display with no such input must
    # not answer the question by default. `min_confirmations` goes with them, because
    # publishing the floor invites reading the two numbers against each other.
    #
    # Popped rather than never-built, so a field added to `mark_anchor_dict` later
    # arrives here automatically and only these three are ever silently absent.
    for dropped in ("provisional", "deep_enough", "min_confirmations"):
        shape.pop(dropped, None)
    shape["caveat"] = _inspect.sanitize_display_string(str(shape.get("caveat") or ""))
    return {
        "resolved": True,
        "txid": anchor.txid,
        **shape,
        "no_depth_policy": (
            "This page sets no confirmation-depth requirement: the count above is the fact, "
            "and how much burial is enough depends on what this mark is worth to you"
        ),
    }


def _recovered_key_bytes(result: object) -> bytes:
    """Turn what ``secp256k1-bridge.js`` returned into public key bytes, or raise.

    THE ONE PLACE THE BRIDGE'S RETURN SHAPE IS INTERPRETED, and it is here rather
    than inline in :func:`install_signature_backend` so that
    ``tests/test_signature_backend_differential.py`` — which reaches the same
    JavaScript over a subprocess instead of a Pyodide proxy — reads it through this
    function too. A second copy of this mapping is a second opinion about whether a
    stranger's mark is forged.

    The asymmetry lives in which exception comes out:

    * ``RecoveryUnavailable`` — we could not check. Becomes ``NOT CHECKED``.
    * ``ValueError`` — the curve says these bytes recover to nothing. Becomes
      ``DOES NOT VERIFY``, which is the same verdict coincurve's own refusal earns.

    Anything unrecognised fails toward ``RecoveryUnavailable``: a shape this build
    does not understand is ignorance, not evidence.
    """
    from pyrxd.script.hashmark import RecoveryUnavailable

    # A Pyodide `JsProxy` for a plain JS object answers `to_py`; a dict (the test's
    # transport, and any future one) is already there.
    if hasattr(result, "to_py"):
        result = result.to_py()
    if not isinstance(result, dict):
        raise RecoveryUnavailable(f"the curve bridge returned {type(result).__name__}, not a result object")

    if result.get("ok") is True:
        key_hex = result.get("publicKey")
        if not isinstance(key_hex, str):
            raise RecoveryUnavailable("the curve bridge reported success without a key")
        try:
            key = bytes.fromhex(key_hex)
        except ValueError as exc:
            raise RecoveryUnavailable(f"the curve bridge returned an unreadable key ({exc})") from exc
        # 33 compressed or 65 uncompressed. A length nothing on this curve produces
        # would hash160 to a perfectly well-formed wrong answer, so refuse it here
        # rather than let it become a verdict.
        if len(key) not in (33, 65):
            raise RecoveryUnavailable(f"the curve bridge returned a {len(key)}-byte key")
        return key

    kind = result.get("kind")
    reason = str(result.get("reason") or "no reason given")
    if kind == "no-key":
        raise ValueError(f"no key recovers from these bytes ({reason})")
    raise RecoveryUnavailable(f"the curve bridge refused the request ({kind}): {reason}")


def install_signature_backend(js_recover: object) -> bool:
    """Route ``verify_attestation``'s secp256k1 recovery through ``js_recover``.

    THE REASON THIS PAGE CAN CHECK A SIGNATURE AT ALL. pyrxd installs here with
    ``deps=False`` because most of its runtime dependencies have no pure-Python
    wheel, and ``coincurve`` is one of them — so until this is called, every mark on
    the public /verify/ page reports NOT CHECKED and the page's headline question
    goes unanswered. ``js_recover`` is ``recoverPublicKeySec1`` from
    ``secp256k1-bridge.js``, which the loader SHA-256 verifies before importing.

    Registering it is all it takes: :mod:`pyrxd.script.hashmark` prefers a registered
    backend over coincurve, so /inspect/ and /verify/ both get a real verdict from
    the one Python implementation the CLI uses — the canonical statement, the varint
    framing, low-S, hash160 and the comparison against the committed signer all stay
    where they already were.

    :returns: True once the backend is installed. Never raises: a page that could
        not install one must fall back to the honest NOT CHECKED it had before, not
        fail to load.
    """
    try:
        from pyrxd.script.hashmark import RecoveryUnavailable, recovery_backend, set_recovery_backend

        def _backend(message_hash: bytes, r: bytes, s: bytes, rec_id: int, compressed: bool) -> bytes:
            try:
                result = js_recover(message_hash.hex(), r.hex(), s.hex(), int(rec_id), bool(compressed))
            except Exception as exc:  # the JS call itself failed — not a verdict
                raise RecoveryUnavailable(f"the curve bridge could not be called ({_safe_error(exc)})") from exc
            return _recovered_key_bytes(result)

        set_recovery_backend(_backend)
        # ASK THE REGISTRY, do not assume. "the setter did not raise" and "a curve is
        # installed" are different facts, and the caller acts on the second: a False
        # here leaves both pages on the honest NOT CHECKED, while a True that was not
        # true would leave them waiting for verdicts that never come.
        return recovery_backend() is _backend
    except Exception:  # pragma: no cover - nothing here should raise; see the docstring
        return False


def file_check_plan(algorithm_id: object) -> dict:
    """Which hash to run over a chosen file, per the record's own header byte.

    Forwards to :func:`pyrxd.glyph.inspect.file_check_plan`. The page must NOT pick
    ``"sha256"`` for itself: the record names the algorithm, and a checking surface
    that chose its own would produce a well-formed, signature-verifying, completely
    false answer that nothing downstream could detect.
    """
    try:
        return _inspect.file_check_plan(int(algorithm_id) if algorithm_id is not None else None)
    except Exception as exc:
        return {"ok": False, "reason": _truncate(_inspect.sanitize_display_string(_safe_error(exc)))}


def judge_file_digest(expected_hex: object, computed_hex: object, algorithm: object = None) -> dict:
    """The verdict on a digest the page computed locally, in the record's own terms.

    The comparison is one line; the WORDS are not, and they are what a reader acts on.
    They live in :mod:`pyrxd.glyph._inspect_core` beside the attestation's, so the two
    verdicts on one screen come out of one vocabulary instead of two.
    """
    try:
        return _inspect.judge_file_digest(
            str(expected_hex) if expected_hex is not None else None,
            str(computed_hex) if computed_hex is not None else "",
            algorithm=str(algorithm) if algorithm else None,
        )
    except Exception as exc:
        return {
            "checked": False,
            "match": None,
            "status": "NOT CHECKED",
            "meaning": _truncate(_inspect.sanitize_display_string(_safe_error(exc))),
        }
