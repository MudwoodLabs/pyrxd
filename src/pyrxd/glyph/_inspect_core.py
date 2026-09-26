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
from collections.abc import Mapping, Sequence
from typing import cast

from ..hash import hash256
from ..script.hashmark import (
    RADIANT_MAINNET_GENESIS,
    HashMarkOutcome,
    algorithm_for,
    decode_hashmark,
    verify_attestation,
)
from ..script.message import MessageOutcome, decode_message
from ..security.errors import ValidationError
from ..security.types import Txid
from ..transaction.transaction import Transaction
from .relationships import delegate_burn_refs, verify_relationship_claims
from .types import GlyphProtocol

# --- The attestation verdict, in words, ONCE ---------------------------------
#
# Three surfaces render this verdict — ``pyrxd glyph inspect``'s terminal output,
# the browser panel at ``docs/inspect_static/inspect/``, and any SDK caller reading
# the payload — and each of them used to spell it itself. That is how the browser
# ended up with no branch at all for ``unverifiable``: the CLI grew one, the page
# did not, and nothing could notice because the two prose copies were unrelated
# strings in unrelated languages.
#
# So the words live here, beside the outcome they describe, and every surface reads
# them out of the payload. `status` is the headline a reader scans for; `meaning` is
# what that headline is allowed to be taken to mean, and is deliberately the WEAKER
# sentence in every case.
#
# THE ASYMMETRY THAT MATTERS, and the reason ``unverifiable`` is not a failure here:
# on the WRITE side a missing curve is a refusal, because funding a transaction needs
# the same curve that signs it and there is no honest way to proceed without it. On
# the READ side it is a MISSING CAPABILITY OF THE READER — the record is untouched and
# unjudged. Painting a red cross beside an honest signer's mark because the reader's
# browser has no secp256k1 would be the single worst thing either surface could do,
# so the withheld verdict says NOT CHECKED and says whose limitation it is.
_ATTESTATION_VERDICTS: dict[str, tuple[str, str]] = {
    "valid": ("VERIFIED", "recovers to the committed signer"),
    "invalid_signature": (
        "DOES NOT VERIFY",
        "the record is well-formed; its claim is not supported",
    ),
    "unverifiable": (
        "NOT CHECKED",
        "the record is well-formed; this is not a verdict on it",
    ),
    # "NO SIGNATURE", not "NOT ATTESTED" — `pyrxd verify` already shipped that spelling
    # and it is the plainer of the two for a reader who is not holding the spec. The
    # point of this table is that one record cannot be described two ways depending on
    # which surface you happen to be looking at, so where a spelling already exists it
    # wins over a new one.
    "not_attested": (
        "NO SIGNATURE",
        "a v1 record carries no signer, so it says WHEN and never WHO",
    ),
}

#: ``meaning`` is the READ-SURFACE elaboration — what `glyph inspect` and the browser
#: panel print under the status. ``pyrxd verify`` keeps its own reason strings, because
#: its context differs (it judges each record alone, names which record its verdict is
#: about, and quotes a failing record's detail). What must NEVER differ between surfaces
#: is the STATUS word, and that is what this table owns: the claim is shared, the
#: elaboration is local.
#:
#: What a reader is shown when the outcome is one this table has never heard of.
#: Fails toward "we do not know" rather than toward either verdict, because a new
#: outcome defaulting to VERIFIED is a forgery rendered as genuine and one
#: defaulting to DOES NOT VERIFY is an honest mark rendered as a lie.
_UNKNOWN_VERDICT = ("NOT CHECKED", "this build does not know how to read that outcome")


def _attestation_verdict(outcome: str) -> tuple[str, str]:
    """``(status, meaning)`` for an :class:`AttestationOutcome` value."""
    return _ATTESTATION_VERDICTS.get(outcome, _UNKNOWN_VERDICT)


# --- Length / shape constants ----------------------------------------------
#
# These mirror the values the CLI used previously (verbatim — the wire
# behaviour is unchanged across the move). The CLI re-imports them from
# here so a single change updates both surfaces.
_TXID_HEX_LEN = 64
_CONTRACT_HEX_LEN = 72
# The smallest script we classify. It was 46 hex (23 bytes), calibrated to P2SH —
# ``OP_HASH160 <20> OP_EQUAL`` — which was the smallest shape that existed before the
# OP_RETURN payload decoders. It is now an OP_RETURN data carrier: ``OP_RETURN`` plus
# a 3-byte marker plus a one-byte payload is 6 bytes / 12 hex, and a real short ``msg``
# is smaller than P2SH.
#
# The floor sits in ``_classify_input`` and runs BEFORE dispatch, so a short but
# perfectly valid pasted `msg` was refused with "could not classify input" even though
# ``_inspect_script`` decodes it correctly — a guard refusing valid work, and only on
# the pasted-script form, since ``--fetch`` calls the classifier per output with no
# floor. Lowering it only widens what reaches ``_inspect_script``; anything it cannot
# name still comes back ``unknown``.
_MIN_SCRIPT_HEX_LEN = 12
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

#: How many publisher-chosen entries one envelope may render before the rest are summarised.
#: An update envelope's KEY SET is chosen by whoever published the transaction, and nothing caps
#: it: a 256 KB payload of one-byte keys renders tens of thousands of lines, pushing the verified
#: facts above it off the operator's screen. The cap is on the count only - what is dropped is
#: always stated, because a silent truncation reads as "that was everything".
_HUMAN_ENTRY_CAP = 32

#: The widest integer an inspect payload carries AS A NUMBER. Anything wider is replaced by
#: ``<oversized integer: N bits>`` — the spelling ``decode_payload`` already uses for an
#: oversized ``attrs`` value — so every surface says what it withheld.
#:
#: WHY THIS EXISTS. CPython refuses to turn an integer of more than 4,300 decimal digits
#: into text (``ValueError``), and ``str()``, f-strings and ``json.dumps`` all go through
#: that conversion. CBOR carries arbitrary-precision integers (tag 2/3 bignums), so one
#: output or input a stranger published could make ``pyrxd glyph inspect`` exit with a
#: traceback instead of an answer — measured for a burn proof's ``amount``, a TIMELOCK's
#: ``unlock_at`` and every value of a mutable-glyph update envelope.
#:
#: WHY 1024 BITS. Nothing an honest payload carries is wider than 64 bits (values and
#: amounts are int64; heights and times are at most 40), and the 256-bit quantities a
#: chain does have — hashes, targets — are rendered as hex strings, not numbers. The
#: bound is set so that the widest number a renderer DERIVES from two bounded fields — the
#: dMint cap, ``max_height * reward`` — is at most 2048 bits (617 digits), under the
#: 640-digit floor CPython lets any process configure (``sys.int_info
#: .str_digits_check_threshold``). A bounded payload therefore renders under every
#: interpreter configuration, not only the default one.
#: ``tests/cli/test_glyph_inspect_hostile_integers.py`` pins that arithmetic, so the reason
#: cannot go stale in silence.
_MAX_RENDERED_INT_BITS = 1024

#: How deep :func:`_render_safe` walks before it stops and says so. Inspect's own payloads
#: are a few levels deep; an update envelope's values are whatever a publisher nested, and a
#: recursive walk must not let them choose the recursion depth. cbor2 6.1.4 happens to refuse
#: nesting past 400 (measured), but that is a dependency's default and the lockfile is not
#: committed, so the bound this walk relies on is its own.
_MAX_RENDER_DEPTH = 32


def _oversized_int_text(value: int) -> str:
    """The text that stands in for an integer too wide to render."""
    return f"<oversized integer: {value.bit_length()} bits>"


#: How many times :func:`_render_safe` will re-walk a container it has ALREADY rendered, before
#: every further repeat is replaced by a statement. A tree — which is what every payload this
#: module builds is — never repeats, so it never spends any of this; only a value that shares
#: structure does. A budget on ALL nodes would instead truncate honest output: a 1,000-output
#: transaction's payload is over 12,000 nodes.
_RENDER_REPEAT_BUDGET = 10_000

_CYCLE_TEXT = "<cycle: this value contains itself>"
_REPEAT_TEXT = f"<not rendered: shared structure repeated past {_RENDER_REPEAT_BUDGET} times>"


def _render_safe(value: object) -> object:
    """*value* with every integer wider than :data:`_MAX_RENDERED_INT_BITS` replaced by text.

    THE ONE BOUNDED FORMATTER both output modes use. The classifier's two entry points
    (:func:`_inspect_script`, :func:`_classify_raw_tx`) return their payload through this, so
    the CLI's human renderer, its ``--json`` output, the browser panel and an SDK caller all
    receive a payload in which no integer is too wide to print. It is applied to the WHOLE
    payload rather than to the fields known to be attacker-authored, because that list is
    exactly what went stale: the burn amount, the TIMELOCK ``unlock_at`` and the update
    envelope were three unrelated fields with the same defect.

    THE WALK IS BOUNDED IN EVERY DIRECTION AN INPUT CAN CHOOSE. Depth is capped at
    :data:`_MAX_RENDER_DEPTH`. A container already on the current path is a cycle, rendered as
    a fixed marker. A container reached a second time by another path costs one unit of
    :data:`_RENDER_REPEAT_BUDGET`, and past it renders as a marker. Without the last two, nine
    bytes of CBOR (``d8 1c 82 d8 1d 00 d8 1d 00``, a list containing itself twice) made this
    walk build 2**32 lists and die with ``MemoryError``. ``loads_chain_cbor`` now refuses such
    values at decode, so this is the second line, for values that did not come from there.

    Containers come back as their BASE type — a tuple stays a tuple, so it stays hashable for
    use as a key — because rebuilding a subclass (a ``namedtuple``, a ``defaultdict``) from an
    iterable is not a constructor call they all accept.
    """
    return _render_walk(value, 0, set(), set(), [_RENDER_REPEAT_BUDGET])


def _render_walk(value: object, depth: int, on_path: set[int], seen: set[int], repeats_left: list[int]) -> object:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value if value.bit_length() <= _MAX_RENDERED_INT_BITS else _oversized_int_text(value)
    if not isinstance(value, (dict, list, tuple, set, frozenset)):
        return value
    ident = id(value)
    if ident in on_path:
        return _CYCLE_TEXT
    if depth >= _MAX_RENDER_DEPTH:
        return f"<{type(value).__name__} nested more than {_MAX_RENDER_DEPTH} levels deep — not rendered>"
    # Empty containers are skipped: `()` and `frozenset()` are interned, so an honest payload
    # holding two of them would otherwise look like shared structure.
    if value and ident in seen:
        if repeats_left[0] <= 0:
            return _REPEAT_TEXT
        repeats_left[0] -= 1
    seen.add(ident)
    on_path.add(ident)
    try:
        if isinstance(value, dict):
            return {
                _render_walk(k, depth + 1, on_path, seen, repeats_left): _render_walk(
                    v, depth + 1, on_path, seen, repeats_left
                )
                for k, v in value.items()
            }
        items = [_render_walk(item, depth + 1, on_path, seen, repeats_left) for item in value]
    finally:
        on_path.discard(ident)
    if isinstance(value, tuple):
        return tuple(items)
    if isinstance(value, frozenset):
        return frozenset(items)
    return set(items) if isinstance(value, set) else items


def _display_text(value: object) -> str:
    """``str(value)`` for an arbitrary decoded CBOR value, bounded, and never ``ValueError``.

    :func:`_render_safe` bounds the integers it can SEE inside plain containers, and bounds the
    walk itself (depth, cycles, repeated structure), so the string built from its result is
    bounded by the value's distinct content. A CBOR value can also hide a bignum inside an object
    whose ``str()`` prints it — an unknown tag (``CBORTag(40404, <bignum>)``) or a tag-30 rational
    (``Fraction``) — so the conversion itself is guarded too, and what it could not render is
    named rather than dropped.
    """
    try:
        return str(_render_safe(value))
    except (ValueError, RecursionError):
        return f"<unrenderable {type(value).__name__}>"


# Unicode general categories that must NOT reach a terminal: control (Cc),
# format (Cf — includes BOM, bidi-overrides, ZWJ/ZWNJ, tag chars), unassigned
# (Cn), private-use (Co), line/paragraph separators (Zl/Zp), and combining
# marks (Mn/Me — overlay glyphs onto the previous char). This subsumes the
# explicit bidi-override / BOM allow-list the previous version maintained.
_UNICODE_STRIP_CATEGORIES = frozenset({"Cc", "Cf", "Cn", "Co", "Zl", "Zp", "Mn", "Me"})


def _sanitize_update_fields(fields: dict) -> dict:
    """Sanitise a partial-update CBOR map for display — KEYS as well as values.

    An update envelope's keys are chosen by whoever published the transaction, exactly like its
    values, and they land in terminal output beside verified facts. Sanitising only the values
    would leave the ANSI injection in the key.

    Nested one level, because that is where the interesting content is (`attrs.target`). Deeper
    structures are rendered through :func:`_display_text` and sanitised whole. That IS a walk —
    :func:`_render_safe` visits every nested value — and it is bounded by depth, by cycle
    detection and by a repeat budget, because a publisher chooses the nesting and the sharing.

    Every ``str()`` here is :func:`_display_text`, not the builtin. These values are raw CBOR,
    so any of them can be a bignum, and a bare ``str()`` of one raised ``ValueError`` out of the
    classifier itself — before either output mode ran — so one update envelope anywhere in a
    transaction made ``inspect --fetch`` exit with a traceback.
    """
    out: dict = {}
    for k, v in fields.items():
        key = _sanitize_display_string(_display_text(k))
        if isinstance(v, dict):
            out[key] = {
                _sanitize_display_string(_display_text(ik)): _sanitize_display_string(_display_text(iv))
                for ik, iv in v.items()
            }
        else:
            out[key] = _sanitize_display_string(_display_text(v))
    return out


def _utf16_order(text: str) -> bytes:
    """A sort key that orders strings as JavaScript's default ``Array.prototype.sort`` does: by
    UTF-16 code unit, which differs from Python's code-point order once a string has a character
    past U+FFFF."""
    return text.encode("utf-16-be", "surrogatepass")


def _drawn_update_fields(fields: dict) -> tuple[dict, dict]:
    """``(the fields a bounded caller draws, what it leaves out)`` for an update envelope.

    The same sanitised keys and values :func:`_sanitize_update_fields` gives, cut to what
    ``inspect.js`` draws of an update — at most :data:`_HUMAN_ENTRY_CAP` top-level fields other
    than ``attrs``, and of a dict-valued ``attrs`` its ``target`` plus :data:`_HUMAN_ENTRY_CAP`
    others — each set being the first in the order the page sorts them in, so the page draws the
    fields it would have drawn from the whole envelope. Any other dict-valued field keeps its
    first :data:`_HUMAN_ENTRY_CAP` entries in the same order. The second value counts what was
    left out, EXACTLY, over the sanitised keys (two raw keys that sanitise alike are one field,
    as in :func:`_sanitize_update_fields`): ``{"count": <top-level fields>, "within": {field:
    <entries of that dict-valued field>}}``, each part present only when something was left out,
    and ``{}`` when nothing was. Only the values kept are rendered.
    """
    by_key: dict[str, object] = {}
    for k, v in fields.items():
        by_key[_sanitize_display_string(_display_text(k))] = v  # the later value wins, as there

    def first(keys: dict, always: str | None) -> tuple[set[str], int]:
        """The keys drawn: *always* if present, and the first _HUMAN_ENTRY_CAP of the rest."""
        rest = sorted((key for key in keys if key != always), key=_utf16_order)
        kept = set(rest[:_HUMAN_ENTRY_CAP]) | ({always} if always in keys else set())
        return kept, max(0, len(rest) - _HUMAN_ENTRY_CAP)

    # Kept in the envelope's own order, so a payload with nothing to cut is the same dict, in the
    # same order, as `_sanitize_update_fields` gives — and the raw-JSON drawer the same text.
    out: dict = {}
    within: dict[str, int] = {}
    kept, top_left = first(by_key, "attrs")
    for key, value in by_key.items():
        if key not in kept:
            continue
        if not isinstance(value, dict):
            out[key] = _sanitize_display_string(_display_text(value))
            continue
        inner: dict[str, object] = {}
        for ik, iv in value.items():
            inner[_sanitize_display_string(_display_text(ik))] = iv
        inner_kept, inner_left = first(inner, "target" if key == "attrs" else None)
        out[key] = {ik: _sanitize_display_string(_display_text(iv)) for ik, iv in inner.items() if ik in inner_kept}
        if inner_left:
            within[key] = inner_left
    left: dict = {}
    if top_left:
        left["count"] = top_left
    if within:
        left["within"] = within
    return out, left


#: The lists one output row can carry, each with the key that counts what a bounded caller was not
#: sent of it. A script's author chooses how many refs it names — the review measured one 3.7 MB
#: output naming 100,000 distinct refs, which drew 300,042 elements — and these are the only
#: list-valued fields of any row: ``tests/web/test_inspect_page_is_bounded.py`` classifies every
#: shape the drift corpus holds and requires the list-valued fields it finds to be exactly these.
_ROW_LISTS = {"input_refs": "input_refs_not_listed", "referenced_refs": "referenced_refs_not_listed"}


def _drawn_row_lists(row: dict) -> None:
    """Cut each of a listed row's :data:`_ROW_LISTS` to its first :data:`_HUMAN_ENTRY_CAP`
    entries — the ones ``inspect.js`` draws — and count the rest, exactly, beside it as
    ``{"count": n}``. A list at or under the cap is left whole, with no count.

    An entry is one ref OPCODE in the script, not one distinct ref: a script pushing one ref 40
    times has 40 entries, and the count is of opcodes. Of the entries left out, the singleton
    pushes (0xd8) are also counted, as ``"singletons"``, when there are any, so that none is
    hidden inside the bare count."""
    from ..constants import OP_PUSHINPUTREFSINGLETON_BYTE

    singleton = f"0x{OP_PUSHINPUTREFSINGLETON_BYTE:02x}"  # the spelling `_ref_summary` gives an opcode
    for key, not_listed in _ROW_LISTS.items():
        entries = row.get(key)
        if isinstance(entries, list) and len(entries) > _HUMAN_ENTRY_CAP:
            row[key] = entries[:_HUMAN_ENTRY_CAP]
            row[not_listed] = {"count": len(entries) - _HUMAN_ENTRY_CAP}
            singletons = sum(1 for entry in entries[_HUMAN_ENTRY_CAP:] if entry.get("opcode") == singleton)
            if singletons:
                row[not_listed]["singletons"] = singletons


def _sanitize_display_string(s: object) -> str:
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

    NON-STRING INPUT IS STRINGIFIED, not passed through. ``None`` stays ``None`` (an absent
    field stays absent); anything else goes through :func:`_display_text` first, which is
    bounded and cannot raise ``ValueError``. It used to be returned unchanged, so a value this
    function's name promises is a safe string could be a 40,000-bit integer or a list that
    contains itself — and ``glyph inspect --wave-name`` / ``pyrxd verify --wave-name`` passed a
    WAVE update's ``attrs.target`` through it into ``json.dumps`` and the terminal, and crashed.
    """
    if s is None:
        return s
    if not isinstance(s, str):
        s = _display_text(s)
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


def _is_exact_timelock_script(hex_str: str) -> bool:
    """Does *hex_str* parse as an exact CLTV / CSV P2PKH template?

    The single disambiguator ``_classify_input`` is allowed to consult before
    claiming a 64-hex string as a txid. Kept as its own named predicate so the
    narrowness is auditable: it is the production parser, not a prefix test.
    """
    from ..script.timelock import parse_p2pkh_timelock_script

    try:
        script = bytes.fromhex(hex_str)
    except ValueError:  # pragma: no cover — caller has already checked the alphabet
        return False
    return parse_p2pkh_timelock_script(script) is not None


def _classify_input(s: str) -> tuple[str, str]:
    """Dispatch on input shape. Returns (form, normalised_value).

    form ∈ {"txid", "contract", "outpoint", "script"}.

    Auto-detect rules (unambiguous by length / content):
      * 64 hex → txid
      * 72 hex → contract
      * contains ":" → outpoint (validated downstream)
      * 46–20_000 even-length hex → script

    A bare 64-hex string is treated as a txid — that is what users paste from a
    block explorer — with ONE exception, below.

    The 64-hex collision
    --------------------

    A 32-byte locking script is also 64 hex, and one real shape lands exactly
    there: an absolute time-lock whose deadline is a wall-clock time. Any CLTV
    value in ``[LOCKTIME_THRESHOLD, 2**31)`` — every Unix deadline from 1985 to
    2038 — encodes as a minimal 4-byte push, giving
    ``05 bytes push + OP_CLTV + OP_DROP + 25-byte P2PKH tail = 32 bytes``. Those
    are the wall-clock HTLC refund legs, so the shape the inspector most needs
    to explain was the one shape it refused to look at: the CLI answered
    "this looks like a txid (64 hex chars)" and ``--fetch`` would have sent the
    script bytes to an ElectrumX server as a transaction id.

    So a 64-hex string that parses as an EXACT time-lock template is claimed as
    a script. The preference is deliberately narrow — ``parse_p2pkh_timelock_script``
    is not a heuristic: it pins the 25-byte P2PKH tail (``76 a9 14 … 88 ac``),
    the ``OP_DROP``, the CLTV/CSV opcode and a minimally-encoded value push, and
    returns ``None`` on any near miss. That is 7 bytes at fixed offsets plus a
    minimality check, so a real txid colliding with it is a ~2^-56 event, and it
    would have to be a txid whose bytes are a spendable time-lock script.
    Nothing wider is preferred: ``op_return`` would match any 64-hex string
    beginning ``6a``, which is 1 txid in 256.

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
        return ("script", lowered) if _is_exact_timelock_script(lowered) else ("txid", lowered)
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
        # Don't echo the raw input back — a CLI user who pasted bytes
        # containing ANSI escapes or bidi-overrides would otherwise see
        # those rendered to their terminal verbatim. The bare error
        # tells them what was wrong; they already know what they pasted.
        raise ValidationError("outpoint must be exactly one 'txid:vout'")
    txid_str, vout_str = s.split(":", 1)
    try:
        vout = int(vout_str, 10)
    except ValueError as exc:
        # Same defence: ``vout_str`` is whatever the user pasted after
        # the colon. Sanitise before embedding so attacker bytes can't
        # reach the terminal. The sanitiser strips control / format /
        # combining codepoints — exactly the surface that terminal
        # injection exploits.
        raise ValidationError(f"vout is not an integer: {_sanitize_display_string(vout_str)!r}") from exc
    ref = GlyphRef(txid=Txid(txid_str.lower()), vout=vout)
    return {
        "form": "outpoint",
        "txid": ref.txid,
        "vout": ref.vout,
        "outpoint": f"{ref.txid}:{ref.vout}",
        "wire_hex": ref.to_bytes().hex(),
    }


def _ref_summary(script: bytes) -> dict:
    """The OP_PUSHINPUTREF-family refs an unrecognised script carries — and,
    separately, the ones it merely names.

    Attached to ``type: "unknown"`` results so a shape the classifier cannot
    name is still not a black box: the one fact that matters most about an
    unknown Radiant script is whether it is **token-bearing**, because a
    ref-carrying UTXO fed into a wallet as plain funding gets burned as a fee
    input (docs/solutions/logic-errors/funding-utxo-byte-scan-dos.md).

    WALK the whole operand family, COLLECT only the push half. The walk must
    see all five operand-carrying opcodes or the program counter desynchronises
    (that is the bug :data:`pyrxd.glyph.script.REF_OPCODES` documents at
    length), but "does this output hold a token?" is answered by
    ``foundPushRefs`` alone — ``CScript::GetPushRefs``
    (``tests/vendor/radiant_core/script.cpp:586-607``) files 0xd0
    ``OP_PUSHINPUTREF`` and 0xd8 ``OP_PUSHINPUTREFSINGLETON`` there and files
    0xd1 / 0xd2 / 0xd3 into the *required* and *disallowed-sibling* sets
    instead. Those three are gates, not carriers: a covenant that
    ``OP_REQUIREINPUTREF``\\ s a credential (the idiom at
    :mod:`pyrxd.glyph.soulbound_covenant`) demands the ref be live somewhere in
    the spending transaction's inputs — it does not hold it, and spending such
    an output destroys nothing. Counting it as token-bearing turned every
    credential gate into a fake burn warning, which is the way to teach a
    reader to ignore the real one.

    Reported under ``referenced_refs`` rather than dropped: "this script names
    ref X" is true and useful, it is just not "this output holds ref X".

    Note the deliberate asymmetry with
    :func:`pyrxd.glyph.dmint.chain.is_token_bearing_script`, which keeps
    counting the whole family. That one decides whether a UTXO may be spent as
    a **fee input**, where over-refusing is free and under-refusing burns a
    token; this one *describes* a script to a reader, where a false positive
    costs credibility. Different question, different safe direction.

    Uses the shared consensus walk, so a ref byte sitting inside push-data is
    never counted. A script that will not decode reports
    ``token_bearing: null`` — unknown, not ``false`` — because a walk that
    cannot finish has not proven the absence of anything.
    """
    from ..constants import PUSH_REF_OPCODES
    from .script import TruncatedScriptError, iter_input_refs
    from .types import GlyphRef

    try:
        refs = list(iter_input_refs(script))
    except TruncatedScriptError:
        # B105 reads the "token" in the key name as a credential. It is a Glyph token.
        return {"token_bearing": None, "input_refs": [], "referenced_refs": []}  # nosec B105
    carried: list[dict] = []
    named: list[dict] = []
    for opcode, operand in refs:
        try:
            ref = GlyphRef.from_bytes(operand)
            outpoint = f"{ref.txid}:{ref.vout}"
        except ValidationError:  # pragma: no cover — 36 bytes always decode
            outpoint = ""
        row = {"opcode": f"0x{opcode:02x}", "ref_outpoint": outpoint}
        (carried if opcode in PUSH_REF_OPCODES else named).append(row)
    return {"token_bearing": bool(carried), "input_refs": carried, "referenced_refs": named}  # nosec B105


def _address_for(hash160_hex: str | None, network: str) -> str | None:
    """Base58check address for a recovered signer hash160, or None.

    Separate from the attestation itself because the address is a RE-ENCODING of the
    recovered key, not a second piece of evidence: it is the same fact in the form a
    human can compare against a wallet.
    """
    if not hash160_hex:
        return None
    from ..base58 import base58check_encode
    from ..constants import NETWORK_ADDRESS_PREFIX_DICT, Network

    try:
        prefix = NETWORK_ADDRESS_PREFIX_DICT[Network(network)]
    except (KeyError, ValueError):
        prefix = NETWORK_ADDRESS_PREFIX_DICT[Network.MAINNET]
    try:
        return base58check_encode(prefix + bytes.fromhex(hash160_hex))
    except ValueError:  # pragma: no cover - the hash160 came from our own recovery
        return None


# --- Checking a file against a record ----------------------------------------
#
# A mark commits to a DIGEST. "Is this the file?" is therefore answerable by anyone
# holding the file, with no network, no key and no permission — and the file itself
# never has to move. That is the whole of the check, and it is why the browser panel
# can offer it honestly: `pyrxd mark` promises ITS CONTENTS DO NOT GO ON CHAIN, and a
# checking surface that uploaded the file to answer would break that promise from the
# other end.
#
# The hashing happens in whatever surface holds the bytes (the browser's WebCrypto, the
# CLI's hashlib). What lives here is the part that must not be re-decided per surface:
# WHICH algorithm, and what a match is allowed to mean.


def _webcrypto_name(algorithm: str) -> str | None:
    """The WebCrypto spelling of a hashlib digest name, or ``None`` if there is none.

    DERIVED, not tabulated. ``hashlib`` spells the SHA-2 family ``sha256`` and
    SubtleCrypto spells it ``SHA-256``; a hand-kept map of the one entry that exists
    today would go stale the moment a second algorithm id is registered, and would go
    stale SILENTLY — the panel would fall back to whatever it had hardcoded and check
    the file against the wrong hash while every other field on screen stayed correct.

    Returning ``None`` rather than guessing is the point: SubtleCrypto implements a
    closed set, so an algorithm a record names and browsers cannot compute has to
    degrade with a reason.
    """
    import re

    match = re.fullmatch(r"sha(1|256|384|512)", algorithm or "")
    return f"SHA-{match.group(1)}" if match else None


def _file_check_plan(algorithm_id: int | None) -> dict:
    """How to hash a file so it can be compared against a record of this algorithm.

    ``algorithm_for`` is the authority on WHICH algorithm an id names — the same table
    the decoder read the record's header byte through, and the same one
    ``pyrxd.hashmark_tx.digest_file`` derives its hasher from. Nothing here re-spells
    "sha256"; a surface that did would have created a second source of truth for what a
    record CLAIMS versus what was actually hashed, and no downstream check could detect
    the disagreement.
    """
    if algorithm_id is None:
        return {"ok": False, "reason": "this record names no algorithm, so there is nothing to hash with"}
    try:
        algorithm = algorithm_for(algorithm_id)
    except ValidationError:
        return {
            "ok": False,
            "reason": (
                f"this record names algorithm id {algorithm_id:#04x}, which this build does not "
                f"implement — it may be newer than this build"
            ),
        }
    subtle = _webcrypto_name(algorithm)
    if subtle is None:
        return {
            "ok": False,
            "reason": f"{algorithm} is not one of the hashes a browser can compute (WebCrypto has a closed set)",
        }
    return {"ok": True, "algorithm": algorithm, "webcrypto_name": subtle}


def _judge_file_digest(expected_hex: str | None, computed_hex: str, *, algorithm: str | None = None) -> dict:
    """Compare a locally-computed digest against the one a record commits to.

    Returns the same ``status`` / ``meaning`` shape the attestation verdict uses, so a
    surface renders both through one component and cannot give them two different
    voices.

    ``meaning`` is the weaker sentence on purpose. A digest match says the bytes in
    front of you are the bytes the record commits to — it says nothing whatever about
    who wrote them, who owned them, or whether the signer had ever seen them. That
    claim belongs to the signature, and even the signature only reaches "this key had signed it by
    then" — not that its holder put it in that transaction.
    """
    name = algorithm or "the record's algorithm"
    if not isinstance(expected_hex, str) or not expected_hex:
        return {
            "checked": False,
            "match": None,
            "status": "NOT CHECKED",
            "meaning": "this record carries no digest to compare against",
        }
    computed = (computed_hex or "").strip().lower()
    if not computed:
        return {
            "checked": False,
            "match": None,
            "status": "NOT CHECKED",
            "meaning": "no digest was computed for the file",
        }
    if len(computed) != len(expected_hex):
        # A different width is not a mismatch verdict — it means the two values are not
        # comparable at all, and calling it "DOES NOT MATCH" would tell someone their
        # file is the wrong file when what actually happened is that the wrong hash ran.
        return {
            "checked": False,
            "match": None,
            "status": "NOT CHECKED",
            "meaning": (
                f"the digest computed here is {len(computed) // 2} bytes and the record's is "
                f"{len(expected_hex) // 2} — these were not produced by the same hash, so they "
                f"cannot be compared"
            ),
        }
    if computed != expected_hex.lower():
        return {
            "checked": True,
            "match": False,
            "status": "DOES NOT MATCH",
            "meaning": (
                "this file is not the file this record commits to — one byte different is enough, "
                "so an edited copy, a re-export or a different version all land here"
            ),
        }
    return {
        "checked": True,
        "match": True,
        "status": "MATCHES",
        "meaning": (
            f"this file's {name} is the digest in the record — the record commits to THESE bytes. "
            "It does not say who made them, who owns them, or that anything in them is true"
        ),
    }


#: The attestation outcome for a record whose signature was deliberately NOT checked, to bound
#: the work one transaction can demand. NOT an :class:`AttestationOutcome`: nothing about the
#: record decided it. It is the READER declining, so — like ``unverifiable`` — it is worded as
#: "not checked here" and never as a verdict on the record.
ATTESTATION_NOT_CHECKED_HERE = "not_checked_here"


def _attestation_not_checked_here(network: str) -> dict:
    # Function-local, like the attestation step's own import: the Pyodide import budget covers
    # what `pyrxd.glyph.inspect` loads at module import.
    from ..constants import genesis_hash_for

    status = _attestation_verdict("unverifiable")[0]  # the shared word for "not checked", not a new one
    return {
        "outcome": ATTESTATION_NOT_CHECKED_HERE,
        "status": status,
        "meaning": (
            "not checked here: only a limited number of records per transaction are checked, and "
            "this one is past that limit. It is not a verdict on the record"
        ),
        "recovered_hash160": None,
        "signer_address": None,
        "assumed_network": f"radiant-{network if genesis_hash_for(network) else 'mainnet'}",
        "detail": "",
    }


def _inspect_script(script_hex: str, *, network: str = "mainnet", attest: bool = True) -> dict:
    """Classify a single hex-encoded locking script. Returns a flat dict.

    ``attest=False`` decodes a HashMark record in full and SKIPS only its signature check, marking
    a signed record :data:`ATTESTATION_NOT_CHECKED_HERE` (a v1 record has no signature, and its
    NO SIGNATURE answer is free, so it is still given). Decoding is cheap; the check is a curve
    recovery, and in the browser that is JavaScript on the page's main thread. See
    :func:`_classify_raw_tx`'s ``attest_hashmark_limit``.

    The classifier has twenty-odd return statements, one per shape. Bounding the payload
    HERE, at the one door they all leave through, means a shape added later cannot forget
    to — see :func:`_render_safe`.
    """
    return cast(dict, _render_safe(_classify_script(script_hex, network=network, attest=attest)))


def _classify_script(script_hex: str, *, network: str, attest: bool = True, summary: bool = False) -> dict:
    """The classifier behind :func:`_inspect_script`; its payload is NOT yet render-safe.

    ``summary=True`` is for a row that is COUNTED and never drawn — an output past a page's
    display limit (see :func:`_classify_raw_tx`'s ``max_rows``). It decides ``type`` by the same
    branches in the same order, so the count by type is the one the full rows would give, and
    for a HashMark record it still decides the attestation outcome. The OP_RETURN branch skips
    the work that only feeds what a reader would see: decoders whose answer cannot change the
    type, text sanitising, address encoding. Every other branch is unchanged — it returns the
    same row, which the caller counts by type and discards.
    """
    from ..constants import REF_OPERAND_WIDTH
    from ..script.timelock import parse_p2pkh_timelock_script

    # Function-local for the same reason as the authority import below: the
    # Pyodide module budget covers what `pyrxd.glyph.inspect` loads at IMPORT,
    # and burn decoding is only needed once an output turns out to be one.
    from .burn import parse_burn_proof
    from .dmint import DmintState
    from .script import (
        MUTABLE_NFT_SCRIPT_RE,
        extract_owner_pkh_from_commit_script,
        extract_owner_pkh_from_ft_script,
        extract_owner_pkh_from_nft_script,
        extract_payload_hash_from_commit_script,
        extract_ref_from_ft_script,
        extract_ref_from_nft_script,
        is_authority_gated_script,
        is_commit_ft_script,
        is_commit_nft_script,
        is_delegate_token_script,
        is_ft_script,
        is_nft_script,
        parse_authority_gated_script,
        parse_dat_commit_script,
        parse_delegate_burn_script,
        parse_legacy_container_script,
        parse_mutable_nft_script,
        split_delegate_commit_prefix,
    )
    from .types import GlyphRef

    try:
        script = bytes.fromhex(script_hex)
    except ValueError as exc:
        raise ValidationError("script is not valid hex") from exc

    base = {"form": "script", "length": len(script), "hex": script_hex}

    # Plain P2PKH check first (cheapest, common).
    if len(script) == 25 and script[:3] == b"\x76\xa9\x14" and script[23:] == b"\x88\xac":
        return {**base, "type": "p2pkh", "owner_pkh": script[3:23].hex()}

    # P2SH — ``OP_HASH160 <20> OP_EQUAL``. Radiant Core's own ``Solver``
    # recognises this one (``TX_SCRIPTHASH``); the redeem script it commits to
    # is not on-chain until the output is spent, so there is nothing further to
    # report. The Gravity SPV maker covenant funds a P2SH output, which is how
    # this shape reaches the inspector in practice.
    if len(script) == 23 and script[:2] == b"\xa9\x14" and script[22:] == b"\x87":
        return {**base, "type": "p2sh", "script_hash": script[2:22].hex()}

    # OP_RETURN data output. ``\x6a`` is OP_RETURN; whatever follows is
    # an unspendable data carrier — used by some legacy Radiant tools
    # for protocol markers (Atomicals-shaped, non-Glyph). Surface the
    # data hex separately from the hex field so callers don't have to
    # re-strip the OP_RETURN byte. Length cap is the script's max
    # (already enforced upstream via _MAX_SCRIPT_HEX_LEN).
    if len(script) >= 1 and script[0] == 0x6A:
        # THE TYPE, DECIDED ONCE, for the full row and for a summary alike. Three decoders
        # refine a plain `op_return`, and when more than one accepts the bytes the most
        # specific wins: HashMark, then a Glyph burn proof, then the Photonic `msg`. Each is a
        # pure function of the script that returns rather than raises, so in a SUMMARY
        # (``summary=True``: a row counted past a page's display limit, never drawn) a decoder
        # whose answer cannot change the type is simply not run — the `msg` walk is most of
        # what a HashMark output costs. Everything else about the row is the same code.
        #
        # HashMark is a THIRD-PARTY OP_RETURN format on Radiant (MIT, spec at
        # github.com/cdonnachie/hashmark.rxd). Decoding it here is read-only and
        # additive: anything that is not one stays plain `op_return`, because a
        # scanner meets thousands of other protocols' data outputs and treating
        # them as errors buries the real ones.
        mark = decode_hashmark(script)
        # A Glyph BURN proof. Everything in it is operator CBOR — the ref it names, the
        # amount, the reason — so it is emitted under `claims` and the note says what is
        # missing to turn it into a verdict.
        proof = None if (summary and mark.ok) else parse_burn_proof(script)
        # The Photonic `msg` convention: OP_RETURN PUSH3 "msg" <push> <message>.
        # Measured on 20 consecutive mainnet blocks, 73 of 73 OP_RETURN outputs
        # carried this marker and nothing else did — it is the whole observed
        # population, and pyrxd already WRITES it. Reading it back turns the
        # commonest data output on the chain from an opaque blob into its text.
        msg = None if (summary and (mark.ok or proof is not None)) else decode_message(script)
        # Each type is a `{"type": ...}` literal, as in every other branch, so the drift
        # test's extraction of the types this classifier can emit still finds them.
        if mark.ok:
            typed = {"type": f"op_return-hashmark-v{mark.version}"}
        elif proof is not None:
            typed = {"type": "op_return-burn"}
        elif msg is not None and msg.ok:
            typed = {"type": "op_return-msg"}
        else:
            typed = {"type": "op_return"}

        out: dict = typed if summary else {**base, **typed, "data_hex": script[1:].hex()}
        if not summary:
            if msg is not None and msg.outcome is not MessageOutcome.NOT_MESSAGE:
                out["message"] = {
                    "outcome": msg.outcome.value,
                    # SANITISED here, at the display boundary. The message is arbitrary
                    # operator bytes and `repr` does not escape U+202E and friends; the
                    # decoder deliberately returns it unmangled so the raw bytes stay
                    # recoverable, and mangling belongs where it is shown.
                    "text": _sanitize_display_string(msg.text) if msg.text else None,
                    "is_utf8": msg.is_utf8,
                    "byte_length": len(msg.raw) if msg.raw else 0,
                    "detail": msg.detail,
                }
            if proof is not None:
                out["burn"] = {
                    "claims": {
                        "token_ref": _sanitize_display_string(proof.token_ref),
                        "action": _sanitize_display_string(proof.action),
                        "amount": proof.amount,
                        "reason": _sanitize_display_string(proof.reason) if proof.reason else "",
                    },
                    "note": (
                        "a burn proof is an OP_RETURN and anyone can write one about any token — "
                        "it is only a burn if this transaction also SPENT that token and no output "
                        "carries it; see verify_burn"
                    ),
                }
                # WITH its reason. `amount: null` alone reads as "the proof names no amount",
                # which is not what happened when it named one this reader refused to repeat.
                if proof.amount_withheld:
                    out["burn"]["amount_withheld"] = _sanitize_display_string(proof.amount_withheld)

        if mark.outcome is not HashMarkOutcome.NOT_HASHMARK:
            # A summary keeps only what its tally reads: the outcome, and below, the verdict.
            out["hashmark"] = (
                {"outcome": mark.outcome.value}
                if summary
                else {
                    "outcome": mark.outcome.value,
                    "version": mark.version,
                    "algorithm": mark.algorithm,
                    # THE ID, not only the name. Whoever re-hashes a local file to compare it
                    # against this digest has to run the algorithm the RECORD names, and
                    # `algorithm_for` is explicit that a caller spelling "sha256" itself has
                    # created a second source of truth for what was hashed. `digest_file` takes
                    # the id, so carrying it is what lets `pyrxd verify` stay on the one table.
                    # And it is the only way to name the algorithm of a record this build
                    # cannot read: `algorithm` is None for an `unknown_algorithm` outcome,
                    # so without the id the panel can say a record names something unknown
                    # and never say WHICH.
                    "algorithm_id": mark.algorithm_id,
                    "digest": mark.digest_hex,
                    # SANITISED, like every other display string on this renderer. The
                    # decoder now refuses a non-canonical label outright (spec 5.4), so
                    # this is defence in depth — but `msg` two branches up was sanitised
                    # and this was not, in the same function, which is how a label got to
                    # inject whole lines under "signature VERIFIED".
                    "label": _sanitize_display_string(mark.label) if mark.label else None,
                    "label_withheld": mark.label_withheld,
                    # v2 only, and NOT verified here — verifying needs secp256k1 and
                    # the chain the tx was found on. Well-formed is not believed.
                    "signer_hash160": mark.signer_hash160_hex,
                    # The SAME hash160, base58check-encoded — a re-encoding of a value the
                    # record itself holds, not a second piece of evidence, and emphatically
                    # not the RECOVERED key (that is `attestation.signer_address`, and the
                    # two are equal only when the signature verifies).
                    #
                    # It exists because the browser's normal outcome is `unverifiable`, where
                    # nothing is recovered and so no address was available at all — leaving a
                    # non-developer a 20-byte hex string to compare against a wallet that
                    # shows addresses. The honest answer to "who signed" when nothing was
                    # checked is "the record NAMES this key", and this is that answer in a
                    # form a person can act on.
                    "committed_signer_address": _address_for(mark.signer_hash160_hex, network),
                    "signature_unverified": mark.signature_hex,
                    "detail": mark.detail,
                }
            )
            if mark.ok:
                # ATTEST, now that we can. The signed statement includes the chain's
                # genesis hash, so THE SAME BYTES ON ANOTHER CHAIN ARE A DIFFERENT
                # STATEMENT and verify against a different key.
                #
                # §6.3 step 2 says to use the genesis of the chain the transaction was
                # actually found on. Mainnet was hardcoded, so `--network testnet
                # glyph inspect` attested against mainnet and announced
                # "assuming radiant-mainnet" — an answer to a question the user had
                # explicitly not asked.
                #
                # Mainnet remains the DEFAULT rather than an error, because a pasted
                # script genuinely carries no context and refusing to attest it would
                # be worse than assuming and saying so. The --fetch path knows the
                # chain it read from and now passes it.
                from ..constants import genesis_hash_for

                # An unknown network falls back to mainnet AND SAYS MAINNET. Reporting
                # the requested name beside a mainnet genesis would state an assumption
                # the code did not make, which is worse than the hardcoding this
                # replaces: the reader could not tell the verdict was against a
                # different chain.
                # Skipped only where there is a SIGNATURE to check. A v1 record carries none, and
                # its answer (NO SIGNATURE) costs nothing, so it is always given.
                if not attest and mark.signer_hash160_hex:
                    out["hashmark"]["attestation"] = _attestation_not_checked_here(network)
                    return out
                genesis = genesis_hash_for(network)
                assumed = network if genesis else "mainnet"
                att = verify_attestation(mark, network_genesis=genesis or RADIANT_MAINNET_GENESIS)
                status, meaning = _attestation_verdict(att.outcome.value)
                out["hashmark"]["attestation"] = {
                    "outcome": att.outcome.value,
                    # THE WORDS, from the one table above, so the terminal and the
                    # browser panel cannot say different things about the same record.
                    "status": status,
                    "meaning": meaning,
                    "recovered_hash160": att.recovered_hash160_hex,
                    # The address form of the recovered key. §7.6's sound statement
                    # LEADS with this — it is the only identity fact the mark itself
                    # carries. Anything a naming system adds is separate context.
                    # Not derived for a summary, which is counted and never shown.
                    "signer_address": None if summary else _address_for(att.recovered_hash160_hex, network),
                    "assumed_network": f"radiant-{assumed}",
                    "detail": att.detail,
                }
        return out

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

    # An authority-gated NFT: 101 bytes, the item's singleton behind an
    # OP_REQUIREINPUTREF on the issuer's authority ref. Without this branch it
    # reads as "unknown", and the note below is the part that matters — the gate
    # is strippable by the holder, so seeing one here says the item is gated NOW,
    # not that it was minted under that authority.
    if is_authority_gated_script(script_hex):
        gate_ref, item_ref, gate_pkh = parse_authority_gated_script(script)  # type: ignore[misc]
        return {
            **base,
            "type": "authority-gated-nft",
            "ref_txid": item_ref.txid,
            "ref_vout": item_ref.vout,
            "ref_outpoint": f"{item_ref.txid}:{item_ref.vout}",
            "owner_pkh": bytes(gate_pkh).hex(),
            "authority_ref": f"{gate_ref.txid}:{gate_ref.vout}",
            "note": (
                "gated on this authority NOW — the holder can transfer to a plain NFT script and "
                "drop the gate, so this is not proof it was MINTED under that authority; read the "
                "genesis transaction for that"
            ),
        }

    # A delegate token is 63 bytes of <ref opcode> <ref> OP_DROP + P2PKH — the
    # SAME shape as the NFT singleton above, differing only in the opcode
    # (0xd0 vs 0xd8). Without this branch it falls through to "unknown", and a
    # holder inspecting their own wallet cannot tell a mint authorisation from
    # an unrecognised output. It is token-bearing: spending it as ordinary
    # funding destroys the delegate.
    if is_delegate_token_script(script_hex):
        ref = GlyphRef.from_bytes(script[1 : 1 + REF_OPERAND_WIDTH])
        return {
            **base,
            "type": "delegate-token",
            "ref_txid": ref.txid,
            "ref_vout": ref.vout,
            "ref_outpoint": f"{ref.txid}:{ref.vout}",
            "owner_pkh": script[41:61].hex(),
            "delegate_base_ref": f"{ref.txid}:{ref.vout}",
        }

    burned = parse_delegate_burn_script(script)
    if burned is not None:
        burned_ref = GlyphRef.from_bytes(burned)
        return {
            **base,
            "type": "delegate-burn",
            "spendable": False,
            "ref_txid": burned_ref.txid,
            "ref_vout": burned_ref.vout,
            "ref_outpoint": f"{burned_ref.txid}:{burned_ref.vout}",
            "delegate_base_ref": f"{burned_ref.txid}:{burned_ref.vout}",
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

    parsed_legacy = parse_legacy_container_script(script)
    if parsed_legacy is not None:
        container_ref, child_ref, pkh = parsed_legacy
        return {
            **base,
            "type": "container-legacy",
            "spendable": False,
            "ref_txid": container_ref.txid,
            "ref_vout": container_ref.vout,
            "ref_outpoint": f"{container_ref.txid}:{container_ref.vout}",
            "child_ref_outpoint": f"{child_ref.txid}:{child_ref.vout}",
            "owner_pkh": bytes(pkh).hex(),
            "note": (
                "pre-0.15.0 CONTAINER-with-child-ref output. PERMANENTLY UNSPENDABLE: OP_PUSHINPUTREF "
                "leaves the child ref on the stack, so the P2PKH tail hashes the ref and OP_EQUALVERIFY "
                "always fails. The child NFT's singleton ref was consumed to create it and cannot be "
                "re-minted. Collection membership now lives in the envelope's 'in' field."
            ),
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

    # DAT commit: no OP_REFTYPE_OUTPUT block, so its reveal mints nothing. It is
    # checked BEFORE the NFT/FT commit branches only for readability — the three
    # regexes are disjoint, and the test suite pins that they are.
    parsed_dat = parse_dat_commit_script(script)
    if parsed_dat is not None:
        dat_hash, dat_pkh = parsed_dat
        _delegate_ref, _core = split_delegate_commit_prefix(script)
        row = {
            **base,
            "type": "commit-dat",
            "payload_hash": dat_hash.hex(),
            "owner_pkh": bytes(dat_pkh).hex(),
            "note": "a DAT reveal creates no token — the payload in its scriptSig is the whole point",
        }
        if _delegate_ref is not None:
            row["delegate_base_ref"] = f"{_delegate_ref.txid}:{_delegate_ref.vout}"
        return row

    if is_commit_nft_script(script_hex):
        # `split_delegate_commit_prefix` recovers the base ref from ALL THREE commit
        # types, but only the DAT branch used to emit it — the one commit type whose
        # reveal mints nothing. So a 131-byte delegate-bound NFT commit, whose reveal
        # the covenant REJECTS without a burn output naming that base, rendered
        # identically to a plain 75-byte one on both surfaces.
        _dnft, _ = split_delegate_commit_prefix(script)
        row = {
            **base,
            "type": "commit-nft",
            "payload_hash": extract_payload_hash_from_commit_script(script).hex(),
            "owner_pkh": bytes(extract_owner_pkh_from_commit_script(script)).hex(),
        }
        if _dnft is not None:
            row["delegate_base_ref"] = f"{_dnft.txid}:{_dnft.vout}"
        return row

    if is_commit_ft_script(script_hex):
        _dft, _ = split_delegate_commit_prefix(script)
        row = {
            **base,
            "type": "commit-ft",
            "payload_hash": extract_payload_hash_from_commit_script(script).hex(),
            "owner_pkh": bytes(extract_owner_pkh_from_commit_script(script)).hex(),
        }
        if _dft is not None:
            row["delegate_base_ref"] = f"{_dft.txid}:{_dft.vout}"
        return row

    # Time-locked P2PKH (CLTV absolute / CSV relative). Exact template parse
    # against pyrxd.script.timelock's builders — these are the HTLC refund
    # outputs, so the person inspecting one is usually the person who cannot
    # spend it yet and wants to know when they can.
    timelock = parse_p2pkh_timelock_script(script)
    if timelock is not None:
        row = {
            **base,
            "type": f"p2pkh-{timelock.kind}",
            "owner_pkh": timelock.owner_pkh.hex(),
            "locktime_value": timelock.value,
            "locktime_basis": timelock.basis,
            "locktime_units": timelock.units,
        }
        if timelock.kind == "csv":
            row["relative_lock_disabled"] = timelock.relative_lock_disabled
        else:
            # The encoded CLTV value is the floor on the SPENDING TX's
            # nLockTime, not a height at which the output becomes spendable —
            # those differ by one and the difference is the whole answer to
            # "when can I spend this?".  ``IsFinalTx``
            # (Radiant-Core src/consensus/tx_verify.cpp at the vendored pin
            # 45e0aa4 / v3.1.2) returns final only when
            # ``lockTime < lockTimeLimit``, where ``lockTimeLimit`` is the
            # height (or time) of the block CONTAINING the spend — see
            # ``ContextualCheckTransactionForCurrentBlock``
            # (tests/vendor/radiant_core/validation.cpp:3969-3975) for the
            # "height of the block *being* evaluated" convention.  Strictly
            # greater, so the first block that can carry the spend is
            # ``units + 1``.
            #
            # Derived HERE, on the Python side, so the CLI, the --json output
            # and the browser renderer cannot disagree about it: the browser
            # inspect tool is a pure renderer by design and must never
            # re-derive a consensus fact of its own.
            row["locktime_earliest"] = timelock.units + 1
        return row

    # dMint contract is variable-length and parser-only. It MUST be tried
    # before the soulbound fallbacks below: a dMint contract script (V1 and V2)
    # binds a singleton ref AND carries a self-replication-or-burn structure,
    # so it trips every marker ``classify_soulbound`` looks for. Same for the
    # mutable-NFT shape, matched further above. Ordering is what keeps those
    # from being reported as soulbound.
    try:
        state = DmintState.from_script(script)
    except ValidationError:
        pass
    else:
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

    return _classify_self_replicating(script, base)


def _classify_self_replicating(script: bytes, base: dict) -> dict:
    """Soulbound / self-replication fallbacks, then ``unknown``.

    Two tiers, deliberately kept apart because they carry different amounts of
    certainty and collapsing them would overstate the weaker one:

    ``soulbound-covenant``
        An **exact** round-trip against one of pyrxd's two soulbound builders
        (:func:`~pyrxd.glyph.soulbound_covenant.parse_soulbound_nft_covenant`).
        The parameters are recovered and the builder re-run; the bytes match or
        they do not.

    ``self-replicating-covenant``
        The semantic markers ``classify_soulbound`` looks for are present — the
        script binds a singleton ref and contains a self-replication equality
        (or code-script-hash count) — but the bytes are not a shape pyrxd
        builds. That is a true statement about the structure and a useful one,
        but it is NOT "this is soulbound": container and vault covenants
        self-replicate too. The label says what was observed and the note says
        what it does not prove.

    Neither tier proves the covenant is *correct* or that it is enforceable for
    the token a caller cares about — that needs the on-chain differential, not
    a locking script.
    """
    from .soulbound_covenant import parse_soulbound_nft_covenant
    from .soulbound_detect import Transferability, classify_soulbound

    parsed = parse_soulbound_nft_covenant(script)
    if parsed is not None:
        ref, owner_pkh, variant = parsed
        detected = classify_soulbound(script)
        return {
            **base,
            "type": "soulbound-covenant",
            "variant": variant,
            "transferability": detected.transferability.value,
            "bound_ref_txid": ref.txid,
            "bound_ref_vout": ref.vout,
            "bound_ref_outpoint": f"{ref.txid}:{ref.vout}",
            "owner_pkh": owner_pkh.hex(),
            "has_self_replication": detected.has_self_replication,
            "has_burn_branch": detected.has_burn_branch,
            "note": (
                "exact match against pyrxd's soulbound covenant builder. The lock permits only a "
                "self-clone or a burn, so it is non-transferable AT CONSENSUS for whatever singleton "
                "the bound ref names. It does NOT verify that ref names a live Glyph singleton, that "
                "the singleton is actually held here, or that the covenant is free of defects — the "
                "covenant is a pre-external-audit prototype."
            ),
        }

    detected = classify_soulbound(script)
    if detected.transferability is Transferability.SOULBOUND_COVENANT:
        row = {
            **base,
            # NO ``transferability`` key on this tier, deliberately. The whole
            # point of the two-tier split is to withhold the soulbound claim
            # from a marker-only match — and ``transferability:
            # "soulbound_covenant"`` IS that claim, stated in the one field a
            # machine consumer reads. The caveat lives in ``note``, which no
            # machine consumer reads. A JSON reader that keys on
            # ``transferability`` now sees the key absent for this tier and
            # gets no verdict at all, which is the honest answer; the markers
            # it *is* entitled to are ``has_self_replication`` /
            # ``has_burn_branch`` right below.
            "type": "self-replicating-covenant",
            "has_self_replication": detected.has_self_replication,
            "has_burn_branch": detected.has_burn_branch,
            "note": (
                "structural marker match only: the script binds a singleton ref and contains a "
                "self-replication-or-burn constraint. That is NOT proof it is a soulbound token — "
                "container and vault covenants replicate themselves too, and the bytes do not match "
                "any covenant pyrxd builds. Read the script before trusting it as a credential."
            ),
            **_ref_summary(script),
        }
        if detected.bound_ref is not None:
            from .types import GlyphRef

            ref = GlyphRef.from_bytes(detected.bound_ref)
            row["bound_ref_outpoint"] = f"{ref.txid}:{ref.vout}"
        return row

    return {**base, "type": "unknown", **_ref_summary(script)}


def _confusable_warnings(metadata) -> dict[str, str]:
    """Fields whose text mimics Latin characters, per the TR39 skeleton check.

    A name in a script with no Latin look-alike letters is not flagged: "トークン",
    "中文" and "한국" pass. But ``looks_confusable_with_latin`` judges each character on
    its own, so a whole word in Cyrillic, Greek, Hebrew or Arabic IS flagged ("москва",
    "σοφία", "שלום", "مرحبا"), mimicry or not. A warning that fires on every legitimate
    token in those scripts is the false positive that trains a reader to ignore the real
    one, which this repo names as a hazard elsewhere; it is a known limit, not the intent.

    Returns ``{}`` when nothing is suspicious, so a caller can treat presence as
    the signal and absence as silence.
    """
    from .confusables import looks_confusable_with_latin

    out: dict[str, str] = {}
    for field in ("name", "ticker", "description"):
        value = getattr(metadata, field, "") or ""
        if value and looks_confusable_with_latin(value):
            out[field] = "characters that mimic Latin letters (possible look-alike name)"
    return out


def _classify_metadata_protocol(metadata) -> str:
    """Return the highest-specificity Glyph-protocol classification label.

    Pure, self-contained mirror of
    :func:`pyrxd.glyph.wave.classify_glyph_metadata`, duplicated here on
    purpose: ``wave.py`` is **not** import-pure (its module-level
    ``WaveResolverError`` definition pulls in ``pyrxd.network.rxindexer``,
    which transitively drags ``aiohttp`` / ``websockets`` / ``coincurve``).
    Importing it — even lazily — would defeat this module's Pyodide
    no-heavy-deps contract (see the module docstring). The two functions
    must stay in sync; the shared classification rules are exercised by the
    test suite against both.

    Operates on a parsed :class:`~pyrxd.glyph.types.GlyphMetadata` so the
    WAVE case can require an ``attrs.name`` (legacy top-level-name WAVE
    tokens exist on-chain but RXinDexer won't index them, so they classify
    as their underlying ``mut``). PRESENT, not resolvable: a pyrxd ≤0.24.0
    claim carries a qualified ``attrs.name`` RXinDexer does not index, and it
    still classifies as ``wave`` here, as it does in ``wave.py``.

    Ordering is highest-specificity-first; TIMELOCK is checked before
    ENCRYPTED because TIMELOCK *requires* ENCRYPTED (see the protocol rules
    in :mod:`~pyrxd.glyph.types`), so a timelocked token always carries both.
    """
    p = set(metadata.protocol)
    has_wave_name = bool(metadata.attrs and metadata.attrs.get("name"))
    if GlyphProtocol.WAVE in p and has_wave_name:
        return "wave"
    if GlyphProtocol.CONTAINER in p:
        return "container"
    # ...OR the `type` STRING, which is what the chain actually carries (#578).
    #
    # GlyphProtocol.CONTAINER (7) is the spec'd form and no mainnet token uses it.
    # All four containers on Radiant mainnet declare themselves with `type:
    # "container"` on an ordinary NFT/MUT protocol set, so the branch above was
    # dead code and every container classified as "nft" or "mut".
    #
    # Verified against the chain, not inferred: the "BTC" container
    # (ref 5558395540...c2ab:0, reveal 57c4d660...dfb1) decodes to `p = (2,)` with
    # `type = 'container'`. The indexer agrees — it reports token_type CONTAINER
    # for exactly these four and exposes no protocol field, so its label is derived
    # from the same string.
    #
    # This is a DECLARATION, like the protocol array itself: `type` is operator CBOR
    # and nothing on chain enforces it. Both forms are claims about what a token is;
    # neither is a proof, and the ecosystem treats this one as the classification.
    if (metadata.token_type or "").strip().lower() == "container":
        return "container"
    if GlyphProtocol.AUTHORITY in p:
        return "authority"
    if GlyphProtocol.TIMELOCK in p:
        return "timelock"
    if GlyphProtocol.ENCRYPTED in p:
        return "encrypted"
    if GlyphProtocol.DMINT in p:
        return "dmint"
    if GlyphProtocol.MUT in p:
        return "mut"
    if GlyphProtocol.DAT in p:
        return "dat"
    if GlyphProtocol.FT in p:
        return "ft"
    if GlyphProtocol.NFT in p:
        return "nft"
    return "unknown"


#: The ``payload_binding`` states that say a node would REJECT the transaction as shown: its
#: attributed input fails the commit it spends. Such a transaction is not one the chain accepted,
#: so whatever its envelope names is unattributed. Both renderers flag exactly these.
PAYLOAD_BINDING_WARNING_STATES: frozenset[str] = frozenset({"mismatch", "commit-unsatisfied"})


def _commit_obligation(spent_script: bytes) -> tuple[str, bytes, int | None] | None:
    """``(kind, payload_hash, required_ref_type)`` if *spent_script* is a Glyph commit, else ``None``.

    The three commit templates pyrxd and Photonic build (``packages/lib/src/script.ts``:
    ``nftCommitScript``, ``ftCommitScript``, ``datCommitScript``), bare or behind a delegate prefix:

    * ``"nft"`` — ``OP_REFTYPE_OUTPUT OP_2 OP_NUMEQUALVERIFY``: the spending transaction must
      create the commit's own outpoint as a SINGLETON ref. ``required_ref_type`` is 2.
    * ``"ft"`` — the same with ``OP_1``: as a NORMAL ref, and not as a singleton. 1.
    * ``"dat"`` — no ref check at all: a DAT reveal creates nothing. ``None``.

    The ref-type operand is matched as exactly ``OP_2`` or ``OP_1``
    (:data:`~pyrxd.glyph.script.COMMIT_SCRIPT_RE`). A commit with ``OP_0`` there demands that its
    ref appear in NO output — it mints nothing — and reading one as a commit is how a decoy
    placed first read ``bound``.

    WHICH DAT FORMS. The ones the two builders emit, read from their source rather than from
    samples: Photonic's ``datCommitScript`` at ``becf41a7`` (unchanged since it was added in
    ``36d8d34``, 2024-04-05) and pyrxd's :func:`~pyrxd.glyph.script.build_dat_commit_locking_script`
    both build ``OP_HASH256 <h> OP_EQUALVERIFY "dat" OP_EQUALVERIFY "gly" OP_EQUALVERIFY`` + P2PKH,
    70 bytes, or 126 behind a delegate prefix. Mainnet also carries a 65-byte form with no ``"dat"``
    push (``77df45a9…1b22:0``), which neither builder emits and whose builder is not known here.
    It is NOT recognised: the templates here are the ones the builders are known to emit, not
    ones inferred from samples. :func:`_payload_binding` says only that it is unrecognised, never
    that nobody committed.
    """
    from .script import (
        extract_payload_hash_from_commit_script,
        is_commit_ft_script,
        is_commit_nft_script,
        parse_dat_commit_script,
    )

    dat = parse_dat_commit_script(spent_script)
    if dat is not None:
        return "dat", dat[0], None
    script_hex = spent_script.hex()
    if is_commit_nft_script(script_hex):
        return "nft", extract_payload_hash_from_commit_script(spent_script), 2
    if is_commit_ft_script(script_hex):
        return "ft", extract_payload_hash_from_commit_script(spent_script), 1
    return None


def _output_ref_type(output_scripts: Sequence[bytes], wire_ref: bytes) -> tuple[int, list[int], list[int]]:
    """What ``OP_REFTYPE_OUTPUT`` answers for *wire_ref* in a transaction with these outputs.

    Returns ``(ref_type, singleton_outputs, normal_outputs)``. Mirrors Radiant Core
    ``ScriptExecutionContext::getRefTypeOutput`` (``src/script/script_execution_context.h``): 2 if
    any output pushes the ref with ``OP_PUSHINPUTREFSINGLETON``, else 1 if any pushes it with
    ``OP_PUSHINPUTREF``, else 0. The sets it reads are filled by ``CScript::GetPushRefs`` over
    EVERY output, walking the opcode stream — so this walks it too
    (:func:`~pyrxd.glyph.script.iter_input_refs`), and a ``0xd8`` byte inside pushed data is not a
    ref. An output whose script does not decode is one ``GetPushRefs`` refuses, which makes the
    whole transaction invalid; it is counted as carrying nothing, which can only move a verdict
    away from ``bound``.

    Only scripts that contain the 36 bytes are walked: an operand is those bytes, contiguous, so a
    script without them cannot carry the ref, and a large transaction costs a byte search.
    """
    from ..constants import OP_PUSHINPUTREF_BYTE, OP_PUSHINPUTREFSINGLETON_BYTE
    from .script import TruncatedScriptError, iter_input_refs

    singleton: list[int] = []
    normal: list[int] = []
    for idx, script in enumerate(output_scripts):
        if wire_ref not in script:
            continue
        try:
            ops = {op for op, operand in iter_input_refs(script) if operand == wire_ref}
        except TruncatedScriptError:
            continue
        if OP_PUSHINPUTREFSINGLETON_BYTE in ops:
            singleton.append(idx)
        if OP_PUSHINPUTREF_BYTE in ops:
            normal.append(idx)
    return (2 if singleton else 1 if normal else 0), singleton, normal


def _payload_binding(
    metadata_cbor: bytes | None,
    spent_script: bytes | None,
    spent_outpoint: str | None,
    output_scripts: Sequence[bytes],
) -> dict:
    """Is the payload shown the one a commit bound — and to WHAT did it bind it?

    A commit output's locking script carries ``sha256d(envelope CBOR)`` as its ``payload_hash``.
    The headline payload is chosen from the inputs' envelopes (:func:`_reveal_attribution`: the
    first whose outpoint the outputs mint, else the first at all), so the name, attrs and creator
    shown to a human need not be the ones any commit committed to. This says whether one did.

    WHAT EACH STATE ESTABLISHES, AND NO MORE:

    ``bound``
        The attributed input spent an NFT or FT commit whose ``payload_hash`` is
        ``sha256d`` of exactly the envelope shown, AND this transaction's outputs carry that
        commit's outpoint with the ref type the commit demands (``first_ref_output`` and
        ``ref_output_count`` say where, and the reason names up to three). So the
        payload is the one committed to for the token those outputs carry. It is NOT a statement
        about the transaction's other outputs: a reveal that mints two tokens from two commits is
        ``bound`` for whichever input is attributed, and only for its own token — which is why
        the reason names the outputs. Nor does it say a node would accept the transaction: it
        checks no signature, not the delegate burn a delegate-prefixed commit also demands, and
        not the rest of the reference rules — a singleton beside a normal push of the same ref
        reads ``bound`` here, and a node refuses it (``bad-txns-…-reference-operations``, measured
        by the round-2 review of #743).
    ``bound-no-token``
        The same hash equality against a DAT commit. A DAT commit demands no ref, so the payload
        is bound as DATA and describes no output here — whatever protocol it declares. It is kept
        apart from ``bound`` because a DAT commit is a commit that mints nothing, placed first
        exactly as a decoy would be.
    ``mismatch``
        The spent commit committed to a different payload. A node rejects that spend: the commit's
        ``OP_HASH256 <payload_hash> OP_EQUALVERIFY`` hashes the top stack item, and with
        ``SIGPUSHONLY`` and ``CLEANSTACK`` set for block connection
        (``tests/vendor/radiant_core/validation.cpp``) the commit input's scriptSig is exactly
        ``<sig> <pubkey> "gly" [dat] <payload>`` — a valid signature and pubkey are never the
        3-byte marker — so the payload these readers select is the item the commit hashes. A
        mismatch is therefore never a transaction the chain accepted: it is bytes that were never
        mined (pasted raw, or served for a txid no block contains).
    ``commit-unsatisfied``
        The hash matches, and the transaction does not create the commit's ref as the commit
        demands. A node rejects that spend too, for the ``OP_REFTYPE_OUTPUT`` check.
    ``not-a-commit``
        The attributed input spent a script that is none of the commit templates pyrxd recognises
        (:func:`_commit_obligation`). That is ALL it says. It is not evidence that nobody committed
        to the envelope: the mainnet DAT reveal ``e5c67100…be5d`` spends a 65-byte hash-lock
        neither builder emits (``77df45a9…1b22:0``) whose ``payload_hash`` is its envelope's, and
        it reads this (``tests/fixtures/dat_65_byte_commit_mainnet.json``).
    ``unchecked``
        The spent script (or the envelope's bytes) was not available.

    This is deliberately a REPORT, not a refusal. The classifier is network-free, so the spent
    script is only present when a fetching caller supplied it; a verdict that silently means "I
    could not check" is the thing being fixed, so every state is named.

    *output_scripts* is EVERY output of the transaction — what ``OP_REFTYPE_OUTPUT`` reads —
    not a listing that ``only_vout`` or ``max_rows`` has cut. It is required, so no caller can
    reach ``bound`` without the outputs having been looked at.
    """
    if spent_script is None:
        return {
            "state": "unchecked",
            "reason": "the spent output of the attributed input was not supplied, so the "
            "payload was not checked against the commit that committed to it",
        }
    commit = _commit_obligation(spent_script)
    if commit is None:
        return {
            "state": "not-a-commit",
            "reason": "the output the attributed input spent is not a commit template pyrxd recognises",
        }
    kind, expected, required = commit
    if metadata_cbor is None:
        return {
            "state": "unchecked",
            "commit": kind,
            "reason": "the envelope CBOR was not recoverable for hashing",
        }
    if hash256(metadata_cbor) != expected:
        return {
            "state": "mismatch",
            "commit": kind,
            "reason": "THE SPENT COMMIT COMMITTED TO A DIFFERENT PAYLOAD than the envelope shown here. "
            "A node rejects that spend, so the chain never accepted this transaction — treat this "
            "metadata as unattributed",
        }
    if required is None:
        return {
            "state": "bound-no-token",
            "commit": kind,
            "reason": "the spent DAT commit committed to exactly this payload. A DAT commit creates no "
            "token, so this payload describes no output of this transaction, whatever protocol it declares",
        }
    if spent_outpoint is None:
        return {
            "state": "unchecked",
            "commit": kind,
            "reason": "the attributed input names no outpoint, so the ref its commit demands was not "
            "looked for in the outputs",
        }
    prev_txid, _, vout = spent_outpoint.rpartition(":")
    wire_ref = bytes.fromhex(prev_txid)[::-1] + int(vout).to_bytes(4, "little")
    found, singleton, normal = _output_ref_type(output_scripts, wire_ref)
    wanted = "a singleton" if required == 2 else "a normal ref"
    if found != required:
        carried = {0: "no output carries it", 1: "it is only a normal ref", 2: "it is a singleton"}
        return {
            "state": "commit-unsatisfied",
            "commit": kind,
            "reason": f"the spent {kind.upper()} commit committed to this payload but demands its outpoint "
            f"as {wanted} in an output: {carried[found]}. A node rejects that spend — treat this "
            "metadata as unattributed",
        }
    at = singleton if required == 2 else normal
    where = f"output {at[0]}" if len(at) == 1 else f"outputs {', '.join(map(str, at[:3]))}"
    if len(at) > 3:
        where += f" and {len(at) - 3:,} more"
    # Two scalars rather than a list of indices: an FT reveal can carry its ref in every one of
    # 100,000 outputs, and a list that long is what every other list here is cut for. The first
    # three are in the reason, which is what both renderers draw.
    return {
        "state": "bound",
        "commit": kind,
        "reason": f"the spent {kind.upper()} commit committed to exactly this payload, and this transaction "
        f"creates its ref as {wanted} at {where}: that token's payload, not every output's",
        "first_ref_output": at[0],
        "ref_output_count": len(at),
    }


# --- The spent transaction, fetched: ONE definition for every surface that fetches it --------
#
# `_payload_binding` answers "was not supplied" when it is handed no spent script — true for a
# caller that never fetched the spent transaction, and FALSE for one that asked, was answered,
# and could not use the answer. Both fetching surfaces (the CLI's `--fetch` and the /inspect/
# page) used to fall back to that sentence on every failure, including a server that answered
# with a different transaction. They now both call `_spent_output_binding`, so they cannot say
# different things about the same fetch.

#: The spent transaction was asked for and nothing usable came back: the server refused, could
#: not be reached, or answered with bytes that are not that transaction. ``detail`` says which.
SPENT_TX_NOT_OBTAINED = (
    "the spent transaction was asked for and nothing usable came back, so the payload was not "
    "checked against the commit that committed to it"
)
#: The spent transaction's bytes arrived and could not stand in for the output this input spent.
SPENT_TX_UNUSABLE = (
    "the spent transaction was supplied but could not be used, so the payload was not checked "
    "against the commit that committed to it"
)


class _SpentTxUnusable(Exception):
    """The spent transaction's bytes cannot stand in for the output spent. ``str()`` says why."""


def _bound_to_txid(txid_hex: str, raw: bytes) -> Txid:
    """``txid_hex`` as a :class:`Txid`, once *raw* is proven to be that transaction's bytes.

    THE SERVER-HONESTY CHECK lives here: ``hash256(raw)[::-1].hex() == txid_hex``, so a hostile
    source cannot hand back some OTHER transaction. The txid a transaction is known by is the
    hash of its own bytes, so binding the answer to the question needs no parser. Raises
    ``ValidationError``.
    """
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
    return txid


def _checked_transaction(txid_hex: str, raw: bytes) -> tuple[Txid, Transaction]:
    """``raw`` parsed whole, after :func:`_bound_to_txid`. Raises ``ValidationError``."""
    txid = _bound_to_txid(txid_hex, raw)
    tx = Transaction.from_hex(bytes(raw))
    if tx is None:
        raise ValidationError("could not parse the raw transaction bytes")

    if len(tx.inputs) > _MAX_INPUT_COUNT or len(tx.outputs) > _MAX_OUTPUT_COUNT:
        raise ValidationError(
            f"transaction structure exceeds inspect's safety caps (inputs={len(tx.inputs)}, outputs={len(tx.outputs)})"
        )
    return txid, tx


def _checked_inputs(txid_hex: str, raw: bytes) -> list:
    """The INPUTS of *raw*, after :func:`_bound_to_txid` — without building a single output.

    For a caller that needs only the inputs — the spent-output binding reads one input's envelope
    (and the output SCRIPTS, via :func:`_checked_inputs_and_output_spans`, not output objects), and
    a transaction's outputs can be 4 MB of it. The inputs come first on the wire (version,
    input count, inputs), and each is read by ``TransactionInput.from_hex``, the reader
    ``Transaction.from_reader`` uses for them; ``tests/web/test_inspect_spent_tx_is_checked.py``
    pins the result equal to ``Transaction.from_hex(raw).inputs``.

    THE REST OF THE BYTES ARE WALKED, NOT TRUSTED. This is public
    (``pyrxd.glyph.inspect.spent_output_binding`` reaches it), so it cannot lean on a caller
    having parsed the transaction first: it used to stop after the inputs, and answered ``bound``
    for bytes with trailing garbage, a missing outputs section, or an output count of 2**64 - 1,
    all of which ``Transaction.from_hex`` refuses. So after the inputs it walks the outputs the
    way ``Transaction.from_reader`` reads them — the count, and for each output its 8-byte value,
    its script length and exactly that many script bytes — then the locktime, and requires the
    walk to end on the last byte, as ``from_hex`` does. The script bytes are skipped, not copied,
    and no output object is built. It refuses what a whole parse refuses, and the output-count
    cap :func:`_checked_transaction` applies; the same test file pins that against
    ``Transaction.from_hex`` on malformed and well-formed bytes alike. Raises ``ValidationError``.
    """
    return _checked_inputs_and_output_spans(txid_hex, raw)[0]


def _checked_inputs_and_output_spans(txid_hex: str, raw: bytes) -> tuple[list, list[tuple[int, int]]]:
    """:func:`_checked_inputs`, and the ``(start, end)`` of every output SCRIPT within *raw*.

    The spans are where the walk already steps over each script, so recording them builds no
    output and copies no byte. :func:`_spent_output_binding` needs the scripts themselves — a
    commit binds a payload to a token only if the reveal's outputs carry the commit's ref, and
    ``OP_REFTYPE_OUTPUT`` reads every output — and slices them out of *raw* by these spans.
    """
    from ..transaction.transaction_input import TransactionInput
    from ..utils import Reader

    _bound_to_txid(txid_hex, raw)
    data = bytes(raw)
    reader = Reader(data)
    try:
        version = reader.read_uint32_le()
        count = reader.read_var_int_num()
        if version is None or count is None:
            raise ValidationError("could not parse the raw transaction bytes")
        if count > _MAX_INPUT_COUNT:
            raise ValidationError(f"transaction structure exceeds inspect's safety caps (inputs={count})")
        inputs = []
        for _ in range(count):
            inp = TransactionInput.from_hex(reader)
            if inp is None:
                raise ValidationError("could not parse the raw transaction bytes")
            inputs.append(inp)
        spans = _walk_outputs_to_the_end(reader, len(data))
    except ValidationError:
        raise
    except Exception as exc:  # a non-canonical or truncated varint, and anything else about the bytes
        raise ValidationError("could not parse the raw transaction bytes") from exc
    return inputs, spans


def _walk_outputs_to_the_end(reader, total: int) -> list[tuple[int, int]]:
    """Walk the outputs and locktime of a transaction whose inputs *reader* has just read, to its
    last byte. ``Transaction.from_reader``'s layout; raises ``ValidationError`` where it fails.
    Returns each output script's ``(start, end)`` offsets, in output order."""
    unparsable = "could not parse the raw transaction bytes"
    count = reader.read_var_int_num()
    if count is None:
        raise ValidationError(unparsable)
    if count > _MAX_OUTPUT_COUNT:
        raise ValidationError(f"transaction structure exceeds inspect's safety caps (outputs={count})")
    spans: list[tuple[int, int]] = []
    for _ in range(count):
        if reader.read_exact(8) is None:  # the value
            raise ValidationError(unparsable)
        length = reader.read_var_int_num()
        if length is None:
            raise ValidationError(unparsable)
        at = reader.tell()
        if length > total - at:  # an over-claiming script length: a whole parse refuses it too
            raise ValidationError(unparsable)
        reader.seek(at + length)
        spans.append((at, at + length))
    if reader.read_uint32_le() is None:  # the locktime
        raise ValidationError(unparsable)
    if not reader.eof():
        raise ValidationError(f"{unparsable}: {total - reader.tell()} byte(s) after the locktime")
    return spans


def _minting_inputs(inputs: Sequence, output_scripts: Sequence[bytes]) -> set[int]:
    """The indices of the inputs whose OUTPOINT this transaction's outputs push as a ref.

    A ref is created from the outpoint an input spends, and only by the transaction spending it,
    so these are the tokens this transaction MINTS — counted from what the outputs carry, not from
    how many envelopes the inputs push. An envelope on an input that is in no output mints nothing:
    a DAT reveal, or a decoy spending a commit whose ``OP_REFTYPE_OUTPUT OP_0`` demands its ref be
    in NO output (a node accepts that transaction).

    Pushed means ``OP_PUSHINPUTREF``/``OP_PUSHINPUTREFSINGLETON`` found by the consensus opcode walk,
    as in :func:`_output_ref_type`. A script is walked only if some ``0xd0``/``0xd8`` byte in it is
    followed by the 36 bytes of one of these outpoints, so the cost is a byte search over the
    outputs plus a walk of the few that could match. A script that does not decode contributes
    nothing, and the refs a partial walk saw before failing are discarded with it.
    """
    from ..constants import PUSH_REF_OPCODES
    from .script import TruncatedScriptError, iter_input_refs

    by_ref: dict[bytes, int] = {}
    for idx, inp in enumerate(inputs):
        if inp.source_txid:
            wire = bytes.fromhex(inp.source_txid)[::-1] + int(inp.source_output_index).to_bytes(4, "little")
            by_ref.setdefault(wire, idx)
    minted: set[int] = set()
    if not by_ref:
        return minted
    for script in output_scripts:
        if not _may_push_one_of(script, by_ref):
            continue
        found: set[int] = set()
        try:
            for op, operand in iter_input_refs(script):
                if op in PUSH_REF_OPCODES and bytes(operand) in by_ref:
                    found.add(by_ref[bytes(operand)])
        except TruncatedScriptError:
            continue
        minted |= found
    return minted


def _may_push_one_of(script: bytes, refs: Mapping[bytes, int]) -> bool:
    """Is some ``0xd0``/``0xd8`` byte in *script* followed by one of *refs*? A cheap superset of
    "pushes one of them": a byte inside pushed data can match too, and the walk decides."""
    for marker in (b"\xd0", b"\xd8"):
        at = script.find(marker)
        while at != -1:
            if script[at + 1 : at + 37] in refs:
                return True
            at = script.find(marker, at + 1)
    return False


#: At most this many payload inputs have their spent transaction fetched to decide the headline
#: (:func:`_binding_candidates`). Each is one round trip, and nothing else bounds how many inputs
#: of one transaction mint.
_MAX_BINDING_FETCHES = 8


def _outpoint_of(inp) -> str | None:
    return f"{inp.source_txid}:{inp.source_output_index}" if inp.source_txid else None


def _row_binding_warning(state: str, any_bound: bool) -> bool:
    """Is another payload's binding *state* one to flag? The warning states always; and
    ``not-a-commit`` when some payload in the same transaction IS bound — the decoy's signature.

    Only other payloads' rows: the headline cannot be ``not-a-commit`` beside a bound payload,
    because a bound payload always mints and so always outranks it (:func:`_reveal_attribution`).
    """
    return state in PAYLOAD_BINDING_WARNING_STATES or (state == "not-a-commit" and any_bound)


def _headline_rank(
    idx: int, scriptsig: bytes, inputs: Sequence, inspector, output_scripts: Sequence[bytes], spent_scripts
) -> int:
    """0 if the payload on input *idx* reads ``bound``, 1 if it spent a commit pyrxd recognises, 2
    otherwise — including when its spent script is not known, which is every input in a
    network-free classification."""
    spent = spent_scripts.get(idx)
    if spent is None:
        return 2
    cbor = inspector.extract_reveal_cbor(scriptsig)
    if _payload_binding(cbor, spent, _outpoint_of(inputs[idx]), output_scripts)["state"] == "bound":
        return 0
    return 1 if _commit_obligation(spent) is not None else 2


def _reveal_attribution(
    inputs: Sequence,
    scriptsigs: list[bytes],
    inspector,
    minting: set[int],
    output_scripts: Sequence[bytes] = (),
    spent_scripts: Mapping[int, bytes] | None = None,
) -> tuple | None:
    """``(input_index, metadata, envelope_cbor, spent_outpoint)`` for the reveal the readers
    attribute, or ``None``. The one rule both the classifier and the spent-binding check use.

    WHICH PAYLOAD IS THE HEADLINE, in order of preference:

    1. among the payloads whose input's outpoint the outputs push as a ref (*minting*, from
       :func:`_minting_inputs`), the first that reads ``bound``;
    2. then the first of those that spent a commit pyrxd recognises;
    3. then the first of those at all;
    4. and only if no payload mints, the first decodable payload.

    1 and 2 need the spent scripts (*spent_scripts*, by input index), which only a fetching
    caller has; without them neither applies and the rule is round 2's. It was the
    first decodable payload, full stop, so an envelope placed first on an input that mints nothing
    headlined over the token the transaction really minted (#743 round 2). Then the first MINTING
    payload, so a payload placed first on an input that mints and was never committed to —
    ``OP_2DROP`` + P2PKH, with an output pushing that input's own outpoint, which a node accepts
    (round 3, case K) — headlined over the bound one beside it. A reveal that mints nothing (DAT)
    is read as it always was. :meth:`GlyphInspector.find_reveal_metadata` keeps its first-wins rule.
    """
    spent_scripts = spent_scripts or {}
    # No input past this one can outrank a minting payload already found: only a spent script
    # lifts a payload above rank 2.
    last_ranked = max(spent_scripts, default=-1)
    first = None
    best = None  # (rank, input index, metadata)
    for idx, scriptsig in enumerate(scriptsigs):
        if first is not None and idx not in minting:
            continue  # only a minting payload can displace the first one
        if best is not None and idx > last_ranked:
            break
        metadata = inspector.extract_reveal_metadata(scriptsig)
        if metadata is None:
            continue
        if first is None:
            first = (idx, metadata)
        if idx not in minting:
            continue
        rank = _headline_rank(idx, scriptsig, inputs, inspector, output_scripts, spent_scripts)
        if best is None or rank < best[0]:
            best = (rank, idx, metadata)
        if rank == 0:
            break  # bound, and the first bound one: nothing can outrank it
    found = (best[1], best[2]) if best is not None else first
    if found is None:
        return None
    input_idx, metadata = found
    cbor = inspector.extract_reveal_cbor(scriptsigs[input_idx]) if scriptsigs else None
    return input_idx, metadata, cbor, _outpoint_of(inputs[input_idx])


def _binding_candidates(inputs: Sequence, scriptsigs: list[bytes], inspector, minting: set[int]) -> list[str]:
    """The outpoints a fetching caller should fetch to settle the headline and its binding.

    The minting payloads' inputs, in order, at most :data:`_MAX_BINDING_FETCHES` of them — the
    only payloads :func:`_reveal_attribution` can rank on a spent script — or, when no payload
    mints, the first payload's. The first entry is always the network-free headline's, so a
    reveal minting one glyph costs the one round trip it always did.
    """
    out: list[str] = []
    first: str | None = None
    for idx, scriptsig in enumerate(scriptsigs):
        if len(out) >= _MAX_BINDING_FETCHES:
            break
        if first is not None and idx not in minting:
            continue
        if inspector.extract_reveal_metadata(scriptsig) is None:
            continue
        outpoint = _outpoint_of(inputs[idx])
        if outpoint is None:
            continue
        if first is None:
            first = outpoint
        if idx in minting:
            out.append(outpoint)
    return out or ([first] if first is not None else [])


def _spent_script(outpoint: str, spent_raw: bytes) -> bytes:
    """The locking script *outpoint* names, read out of *spent_raw* once it is proven to be
    that transaction. Raises :class:`_SpentTxUnusable` with the reason."""
    prev_txid, _, vout_str = outpoint.rpartition(":")
    if not spent_raw:
        raise _SpentTxUnusable("it is empty")
    if len(spent_raw) > _MAX_RAW_TX_BYTES:
        raise _SpentTxUnusable(f"it is {len(spent_raw):,} bytes, larger than any transaction")
    got = hash256(bytes(spent_raw))[::-1].hex()
    if got != prev_txid.lower():
        raise _SpentTxUnusable(f"it is not the transaction this input spent: it hashes to {got}")
    prev_tx = Transaction.from_hex(bytes(spent_raw))
    if prev_tx is None:
        raise _SpentTxUnusable("it does not parse as a transaction")
    vout = int(vout_str)
    if not 0 <= vout < len(prev_tx.outputs):
        raise _SpentTxUnusable(f"it has no output {vout} ({len(prev_tx.outputs)} output(s))")
    return bytes(prev_tx.outputs[vout].locking_script.serialize())


def _spent_output_binding(txid_hex: str, raw: bytes, spent_raw: bytes | None, *, spent_error: str = "") -> dict | None:
    """``payload_binding`` for the reveal in *raw*, from what fetching its spent transaction gave.

    *spent_raw* is the transaction the attributed input spent, or ``None`` when the fetch failed,
    in which case *spent_error* says why. Returns ``None`` when no input is attributed a payload
    (there is nothing to bind); otherwise the same dict :func:`_classify_raw_tx` would put under
    ``metadata.payload_binding`` if handed that input's spent script — any state
    :func:`_payload_binding` itself returns — or ``unchecked`` with a ``detail`` that says what
    went wrong. Never "was not supplied": this is only called by a caller that asked.

    Costs a hash of *raw*, a parse of its inputs and a walk of its outputs that builds none of
    them (see :func:`_checked_inputs_and_output_spans`), and a parse of *spent_raw*, and no
    classification of anything: the binding reads the attributed input's envelope, the one output
    it spent, and — to see whether this transaction creates the ref that output's commit demands —
    the reveal's own output scripts, sliced out of *raw* and walked only where they contain that
    ref's bytes. ``tests/web/test_inspect_spent_tx_is_checked.py`` pins it equal to a full
    re-classification.

    Raises ``ValidationError`` only for *raw* itself (bound to *txid_hex* by the same check
    :func:`_classify_raw_tx` makes); everything about the spent transaction is reported.

    The one-prevout form of :func:`_spent_output_bindings`, for the network-free headline: handed
    only that input's spent transaction, the ranking in :func:`_reveal_attribution` cannot move
    the headline, so this answers for exactly the input it always did.
    """
    from .inspector import GlyphInspector

    inputs, spans = _checked_inputs_and_output_spans(txid_hex, raw)
    scriptsigs = [bytes(inp.unlocking_script.serialize()) for inp in inputs]
    data = bytes(raw)
    output_scripts = [data[start:end] for start, end in spans]
    attributed = _reveal_attribution(inputs, scriptsigs, GlyphInspector(), _minting_inputs(inputs, output_scripts))
    if attributed is None or attributed[3] is None:
        return None
    outpoint = attributed[3]
    answer = _spent_output_bindings(txid_hex, raw, {outpoint: spent_raw}, {outpoint: spent_error})
    return None if answer is None else answer["binding"]


def _said(text: str) -> str:
    """What went wrong with a fetch may quote a server, and it lands in terminal output and on a
    page: sanitised and capped."""
    return _truncate_for_human(_sanitize_display_string(text))


def _spent_output_bindings(
    txid_hex: str, raw: bytes, spent: Mapping[str, bytes | None], errors: Mapping[str, str] | None = None
) -> dict | None:
    """The headline and its ``payload_binding``, from the spent transactions of the inputs
    :func:`_binding_candidates` named.

    *spent* maps each fetched outpoint to its transaction's bytes, or to ``None`` when the fetch
    failed — *errors* then says why. Each is hash-checked against the txid in its outpoint before
    anything is read from it; an outpoint that no input of *raw* spends is ignored.

    Returns ``None`` when no input carries a payload, else::

        {"input_index": the headline, per :func:`_reveal_attribution` given the spent scripts,
         "moved": whether that differs from the network-free headline,
         "binding": its payload_binding — as _classify_raw_tx would give it, or ``unchecked`` with
                    a ``detail`` when its own fetch failed; with ``unsettled`` saying so when it
                    is not ``bound`` and another minting payload went unchecked,
         "spent_scripts": {input index: the locking script it spent},
         "rows": {input index: {"state", "detail"?}} for every OTHER minting payload —
                 ``unchecked`` with the reason where its fetch failed or was never made,
         "past_cap": how many of those were past the fetch limit,
         "reclassify": whether a caller must classify again with ``spent_scripts`` — the
                       headline moved, or another minting payload has a row verdict to show.}

    :func:`_apply_bindings` writes it into a classification.

    Classifies no output and checks no signature. Raises ``ValidationError`` only for *raw* itself.
    """
    from .inspector import GlyphInspector

    inputs, spans = _checked_inputs_and_output_spans(txid_hex, raw)
    scriptsigs = [bytes(inp.unlocking_script.serialize()) for inp in inputs]
    data = bytes(raw)
    output_scripts = [data[start:end] for start, end in spans]
    inspector = GlyphInspector()
    minting = _minting_inputs(inputs, output_scripts)
    network_free = _reveal_attribution(inputs, scriptsigs, inspector, minting)
    if network_free is None or network_free[3] is None:
        return None

    by_outpoint = {op: idx for idx, inp in enumerate(inputs) if (op := _outpoint_of(inp)) is not None}
    spent_scripts: dict[int, bytes] = {}
    problems: dict[int, dict] = {}
    taken = 0
    for outpoint, spent_raw in spent.items():
        idx = by_outpoint.get(outpoint)
        if idx is None:
            continue
        taken += 1
        if taken > _MAX_BINDING_FETCHES:  # the number `_binding_candidates` ever names: no more is read
            break
        if spent_raw is None:
            why = (errors or {}).get(outpoint) or "no reason given"
            problems[idx] = {"state": "unchecked", "reason": SPENT_TX_NOT_OBTAINED, "detail": _said(why)}
            continue
        try:
            spent_scripts[idx] = _spent_script(outpoint, spent_raw)
        except _SpentTxUnusable as exc:
            problems[idx] = {"state": "unchecked", "reason": SPENT_TX_UNUSABLE, "detail": _said(str(exc))}
        except Exception as exc:  # anything else about the bytes: the same honest state, with what went wrong
            detail = _said(str(exc) or type(exc).__name__)
            problems[idx] = {"state": "unchecked", "reason": SPENT_TX_UNUSABLE, "detail": detail}

    attributed = _reveal_attribution(inputs, scriptsigs, inspector, minting, output_scripts, spent_scripts)
    if attributed is None:  # not reachable: the same payloads decode, only their order changed
        return None
    idx, _metadata, cbor, outpoint = attributed
    if idx in spent_scripts:
        binding = _payload_binding(cbor, spent_scripts[idx], outpoint, output_scripts)
    else:
        binding = problems.get(idx) or _payload_binding(cbor, None, outpoint, output_scripts)

    # EVERY OTHER MINTING PAYLOAD GETS A VERDICT, and a check that did not happen says so (#743
    # round 4). Only rows with a spent script used to get one, so a commit the server refused, one
    # it answered with another transaction for, and one past the fetch limit all showed nothing —
    # and a decoy kept the headline with no sign that the check that could have moved it had not
    # run.
    payload_inputs = _minting_payload_inputs(inputs, scriptsigs, inspector, minting)
    asked_for = set(payload_inputs[:_MAX_BINDING_FETCHES])
    rows: dict[int, dict] = {}
    for i in payload_inputs:
        if i == idx:
            continue
        if i in spent_scripts:
            state = _payload_binding(
                inspector.extract_reveal_cbor(scriptsigs[i]), spent_scripts[i], _outpoint_of(inputs[i]), output_scripts
            )["state"]
            rows[i] = {"state": state}
        elif i in problems:
            rows[i] = {"state": "unchecked", "detail": problems[i]["detail"], "why": "failed"}
        elif i in asked_for:
            rows[i] = {"state": "unchecked", "detail": "its commit was not fetched", "why": "not asked"}
        else:
            detail = f"not checked: past the limit of {_MAX_BINDING_FETCHES} commits fetched for one transaction"
            rows[i] = {"state": "unchecked", "detail": detail, "why": "past the limit"}
    past_cap = sum(1 for r in rows.values() if r.get("why") == "past the limit")

    # AND THE HEADLINE SAYS SO, when it is not bound and some other minting payload went unchecked:
    # a bound one among those would head the card instead, so this headline is not the answer.
    unchecked = [r["why"] for r in rows.values() if r["state"] == "unchecked"]
    if binding["state"] != "bound" and unchecked:
        parts = [
            f"{unchecked.count(why)} {said}"
            for why, said in (
                ("failed", "could not be fetched"),
                ("past the limit", f"past the limit of {_MAX_BINDING_FETCHES}"),
                ("not asked", "not fetched"),
            )
            if unchecked.count(why)
        ]
        binding = {
            **binding,
            "unsettled": f"{len(unchecked)} other minting payload(s) went unchecked ({', '.join(parts)}); a bound "
            "one among them would head this card instead, so this headline is not settled",
        }
    moved = idx != network_free[0]
    return {
        "input_index": idx,
        "moved": moved,
        "binding": binding,
        "spent_scripts": spent_scripts,
        "rows": {i: {k: v for k, v in r.items() if k != "why"} for i, r in rows.items()},
        "past_cap": past_cap,
        # WHEN A CALLER MUST CLASSIFY AGAIN, with `spent_scripts`: the headline moved, or another
        # payload has a row verdict to show. Otherwise the binding is the one field that changes.
        # One decision, read by the CLI and by the page's glue.
        "reclassify": moved or bool(rows),
    }


def _minting_payload_inputs(inputs: Sequence, scriptsigs: list[bytes], inspector, minting: set[int]) -> list[int]:
    """The minting inputs that carry a decodable payload, in input order — the ones
    :func:`_binding_candidates` fetches the first :data:`_MAX_BINDING_FETCHES` of."""
    return [
        idx
        for idx in sorted(minting)
        if idx < len(scriptsigs)
        and _outpoint_of(inputs[idx]) is not None
        and inspector.extract_reveal_metadata(scriptsigs[idx]) is not None
    ]


def _apply_bindings(payload: dict, answer: dict) -> dict:
    """Write what :func:`_spent_output_bindings` found into a classification of the same
    transaction: the headline's ``payload_binding``, each other minting payload's row verdict, and
    how many went unchecked past the fetch limit. ONE step, for the CLI's ``--fetch`` and the
    page's glue, so the two cannot draw the same fetches differently."""
    metadata = payload.get("metadata") if isinstance(payload, dict) else None
    if not metadata:
        return payload
    metadata["payload_binding"] = answer["binding"]
    rows = answer.get("rows") or {}
    any_bound = answer["binding"]["state"] == "bound" or any(r["state"] == "bound" for r in rows.values())
    for row in payload.get("metadata_inputs") or []:
        verdict = rows.get(row["input_index"])
        if verdict is None:
            continue
        row["binding_state"] = verdict["state"]
        row["binding_warning"] = _row_binding_warning(verdict["state"], any_bound)
        if verdict.get("detail"):
            row["binding_detail"] = verdict["detail"]
    if answer.get("past_cap"):
        metadata["bindings_past_cap"] = {"count": answer["past_cap"], "cap": _MAX_BINDING_FETCHES}
    return payload


def _classify_with_bindings(txid_hex: str, raw: bytes, answer: dict, **classify_kwargs) -> dict:
    """:func:`_classify_raw_tx` again, with the spent scripts *answer* holds, and
    :func:`_apply_bindings` — what a fetching caller shows when ``answer["reclassify"]``."""
    payload = _classify_raw_tx(txid_hex, raw, spent_scripts=answer["spent_scripts"], **classify_kwargs)
    return _apply_bindings(payload, answer)


# --- Counting what a bounded caller does not list --------------------------------------------

#: The word for a HashMark record whose signature was not checked because it was past the
#: checking limit — the reader declining, which is not the curve failing to load (NOT CHECKED).
NOT_CHECKED_HERE_WORD = "not checked here"


def _hashmark_tally_word(hm: dict) -> str:
    """The status word a HashMark record's panel leads with, for counting records not drawn.

    The same words the panel prints: a record that is not readable is named by its decode
    outcome (``appendMarkVerdict`` upper-cases it), a readable one by its attestation's
    ``status`` from :data:`_ATTESTATION_VERDICTS` — except that a record past the checking
    limit is :data:`NOT_CHECKED_HERE_WORD`, so a count cannot fold it into a total that reads
    as clean. ``tests/web/test_inspect_page_is_bounded.py`` pins these against the panel.
    """
    outcome = hm.get("outcome")
    if outcome != "ok":
        return str(outcome or "").upper().replace("_", " ") or "NOT CHECKED"
    att = hm.get("attestation") or {}
    if att.get("outcome") == ATTESTATION_NOT_CHECKED_HERE:
        return NOT_CHECKED_HERE_WORD
    return att.get("status") or "NOT CHECKED"


def _count(tally: dict, key: str) -> None:
    tally[key] = tally.get(key, 0) + 1


class _OutputShape:
    """What every output of a transaction is, for a caller describing it from a cut listing.

    A count of each output type, and for the dMint contract outputs the first one's vout, height
    and max_height and whether ALL of them carry one token_ref, one reward and one max_height. The
    page's transaction-shape banner states exactly these (``_detectTxShape`` in ``inspect.js``).
    When nothing was cut the page works them out from the rows instead (``_outputShape``), and
    there it sees an integer wider than :data:`_MAX_RENDERED_INT_BITS` only as the text that
    replaced it: where every row holds the same such text for a field, it answers "cannot tell" rather
    than the agreement this class computes. A field compared must be present on every row to
    agree, as the banner's own comparison requires: a field absent everywhere does not agree by
    having nothing to compare.

    COMPARED AS THE CLASSIFIER'S OWN VALUES, for a listed row as for a counted one: the caller
    notes every row BEFORE :func:`_render_safe` replaces an integer wider than
    :data:`_MAX_RENDERED_INT_BITS` with text. So two rewards that differ past 2**53, or past the
    width at which the payload carries text instead of a number, still differ, and two equal ones
    still agree. The listed rows used to be noted after that replacement and the counted ones
    before it, so 150 contracts sharing one 1,101-bit reward read "not all equal", and two with
    different 1,101-bit rewards read "agree".
    """

    _COMPARED = ("token_ref_outpoint", "reward", "max_height")

    def __init__(self) -> None:
        self.by_type: dict[str, int] = {}
        self.dmint_count = 0
        self.dmint_first: dict = {}
        self.dmint_same = dict.fromkeys(self._COMPARED, True)

    def note(self, vout: int, row: dict) -> None:
        kind = str(row.get("type", "unknown"))
        _count(self.by_type, kind)
        if kind != "dmint":
            return
        self.dmint_count += 1
        if self.dmint_count == 1:
            self.dmint_first = {"vout": vout, "height": row.get("height"), "max_height": row.get("max_height")}
            self.dmint_first.update({f"cmp_{f}": row.get(f) for f in self._COMPARED})
        for field in self._COMPARED:
            value = row.get(field)
            self.dmint_same[field] = (
                self.dmint_same[field] and value is not None and value == self.dmint_first[f"cmp_{field}"]
            )

    def as_payload(self) -> dict:
        out: dict = {"by_type": dict(self.by_type)}
        if self.dmint_count:
            out["dmint"] = {
                "count": self.dmint_count,
                "first_vout": self.dmint_first["vout"],
                "first_height": self.dmint_first["height"],
                "first_max_height": self.dmint_first["max_height"],
                "same_token_ref": self.dmint_same["token_ref_outpoint"],
                "same_reward": self.dmint_same["reward"],
                "same_max_height": self.dmint_same["max_height"],
            }
        return out


def _classify_raw_tx(
    txid_hex: str,
    raw: bytes,
    *,
    only_vout: int | None = None,
    network: str = "mainnet",
    delegated_refs: Mapping[bytes, Sequence[bytes]] | None = None,
    spent_scripts: Mapping[int, bytes] | None = None,
    attest_hashmark_limit: int | None = None,
    max_rows: int | None = None,
) -> dict:
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
    * Use ``GlyphInspector.extract_reveal_metadata`` (already swallows
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
    :param attest_hashmark_limit: check the signatures of the first N HashMark records only;
        later ones are decoded and marked :data:`ATTESTATION_NOT_CHECKED_HERE`. ``None`` (the
        default, and what every CLI path passes) checks every record.
    :param max_rows: list at most this many entries of each list the transaction produces —
        ``outputs``, ``glyph_envelopes``, the other payloads in ``metadata_inputs`` (the headline
        payload's own entry is always listed), and ``metadata.relationships`` and
        ``metadata.delegate_burns`` — and COUNT the rest, exactly, under a ``*_not_listed`` key
        beside each list. When outputs are cut, ``output_shape`` also says what EVERY output is:
        a count by type and, for dMint contract outputs, the facts the page's shape banner states
        (see :class:`_OutputShape`). ``None`` (the default, and what every CLI path passes) lists
        everything and adds none of these keys.

    WHAT ``max_rows`` BOUNDS, AND WHAT IT DOES NOT. An output past the limit is classified in
    SUMMARY (see :func:`_classify_script`): its type, and for a HashMark record the status word
    its panel would show, are decided by the same code as a listed row's and counted, and the
    rest of what the classifier returned for it is dropped — it never becomes a row, and it is
    not in the payload. So the NUMBER of entries in each of those lists is bounded by
    ``max_rows``, and so is the number of update envelopes; each of those carries only the fields
    the page draws — :data:`_HUMAN_ENTRY_CAP` top-level fields other than ``attrs``, and ``attrs``
    itself; ``attrs.target`` and :data:`_HUMAN_ENTRY_CAP` other ``attrs`` entries;
    :data:`_HUMAN_ENTRY_CAP` entries of any other map-valued field (:func:`_drawn_update_fields`).
    A listed output row's refs are cut too: at most :data:`_HUMAN_ENTRY_CAP` of ``input_refs`` and of
    ``referenced_refs``, with the rest counted beside each (:func:`_drawn_row_lists`). The SIZE of
    one entry is otherwise not bounded by ``max_rows``: a listed output row carries its script's
    hex whole, and the headline payload carries its whole ``protocol`` list, whose VALUES
    ``GlyphMetadata`` holds to the known protocol numbers and whose LENGTH it does not bound — one
    256 KB envelope repeating a number decodes to about 262,000 entries. Only the transaction's own
    bytes bound those. What also still grows with the transaction is parsing it and the per-entry
    work behind the exact counts: each output's type and refs, each input's envelope and payload,
    each relationship claim's verdict.

    THE WORK ONE TRANSACTION CAN DEMAND IS BOUNDED HERE, not only what gets drawn. Nothing
    limits how many HashMark outputs a transaction carries — about 26,000 signed records fit
    under the 4 MB cap — and every one cost a curve recovery before a page could draw anything,
    which in the browser is JavaScript on the main thread. A caller that renders a bounded number
    of records passes that number, and pays for no more checks than it shows.

    BYTE-IDENTICAL RECORDS SHARE ONE CHECK, with or without a limit. An attestation is a function
    of the record's bytes and the network, both fixed here, so a copy of a record already checked
    gets that record's answer (its own copy of it) without a second recovery. That is exact, not
    an approximation, and it is what lets a limited caller still say something true about copies
    past its limit.
    """
    import copy

    from .inspector import GlyphInspector

    for name, value in (("attest_hashmark_limit", attest_hashmark_limit), ("max_rows", max_rows)):
        if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value < 0):
            raise ValidationError(f"{name} must be a non-negative int or None, got {value!r}")

    txid, tx = _checked_transaction(txid_hex, raw)

    output_rows: list[dict] = []
    enumerated = list(enumerate(tx.outputs))
    if only_vout is not None:
        if not (0 <= only_vout < len(tx.outputs)):
            raise ValidationError(f"vout {only_vout} is out of range (transaction has {len(tx.outputs)} output(s))")
        enumerated = [(only_vout, tx.outputs[only_vout])]

    checked: dict[bytes, dict] = {}  # record bytes -> the attestation computed for them
    hashmark_rows = 0
    # What is counted rather than listed. Filled only past `max_rows`.
    outputs_by_type: dict[str, int] = {}
    marks_by_status: dict[str, int] = {}
    unlisted_vouts: list[int] = []
    # What EVERY output is, listed or not — see `output_shape` below. Noted at exactly the points
    # a row is committed to the listing or to `outputs_by_type`, so its counts are theirs summed.
    shape = _OutputShape()
    for position, (idx, out) in enumerate(enumerated):
        listed = max_rows is None or position < max_rows
        try:
            script_bytes = bytes(out.locking_script.serialize())
            known = checked.get(script_bytes)
            within = attest_hashmark_limit is None or hashmark_rows < attest_hashmark_limit
            attest = within and known is None
            if listed:
                # What `_inspect_script` returns, in its two steps, because `shape` must see the
                # first: the classifier's values, however wide (see `_OutputShape`).
                classified = _classify_script(script_bytes.hex(), network=network, attest=attest)
                if max_rows is not None:
                    _drawn_row_lists(classified)  # before the render walk, which would visit every ref
                row = cast(dict, _render_safe(classified))
            else:
                row = classified = _classify_script(script_bytes.hex(), network=network, attest=attest, summary=True)
            hm = row.get("hashmark")
            if hm is not None:
                hashmark_rows += 1
                att = hm.get("attestation")
                # Copied for a listed row, whose dict is handed to the caller; a summary's is
                # read once, for its status word, and dropped.
                if att is not None and known is not None:
                    hm["attestation"] = copy.deepcopy(known) if listed else known
                elif att is not None and att.get("outcome") != ATTESTATION_NOT_CHECKED_HERE:
                    checked[script_bytes] = copy.deepcopy(att) if listed else att
            if not listed:
                _count(outputs_by_type, str(row.get("type", "unknown")))
                shape.note(idx, classified)
                if hm is not None:
                    _count(marks_by_status, _hashmark_tally_word(hm))
                unlisted_vouts.append(idx)
                continue
            row.pop("form", None)  # always "script" — redundant inside a tx listing
            row["vout"] = idx
            row["satoshis"] = out.satoshis
            output_rows.append(row)
            shape.note(idx, classified)
        except Exception as exc:  # defensive: any classifier crash → unknown row
            if not listed:
                _count(outputs_by_type, "error")
                shape.note(idx, {"type": "error"})
                unlisted_vouts.append(idx)
                continue
            output_rows.append(
                {
                    "vout": idx,
                    "type": "error",
                    "error": type(exc).__name__,
                    "satoshis": out.satoshis,
                }
            )
            shape.note(idx, output_rows[-1])

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
    # EVERY output, whatever `only_vout` and `max_rows` list: which inputs this transaction mints
    # from, `payload_binding` (what `OP_REFTYPE_OUTPUT` would answer) and the relationship
    # verdicts (what consensus backs) are all questions about the whole transaction.
    output_scripts = [bytes(o.locking_script.serialize()) for o in tx.outputs]
    minting = _minting_inputs(tx.inputs, output_scripts)
    # The spent scripts a fetching caller supplied rank the minting payloads (bound first); with
    # none, the headline is the network-free one. Keys that are not a valid input are ignored.
    known_spent = {i: s for i, s in (spent_scripts or {}).items() if isinstance(i, int) and 0 <= i < len(tx.inputs)}
    attributed = _reveal_attribution(tx.inputs, scriptsigs, inspector, minting, output_scripts, known_spent)
    found = None if attributed is None else (attributed[0], attributed[1])

    # dMint mint-claim scriptSig: if vin[0] is a dMint mint claim (4 canonical
    # pushes — nonce, inputHash, outputHash, OP_0), decode it for display.
    # NOT raised; returns None for non-mint inputs (P2PKH funding inputs,
    # plain RXD spends, reveal scriptSigs, etc.). The V1/V2 distinction
    # falls out of the nonce push width (4 vs 8 bytes).
    mint_scriptsig: dict | None = None
    if scriptsigs:
        mint_scriptsig = inspector.parse_mint_scriptsig(scriptsigs[0])
    # EVERY input's payload, not just the first (#577).
    #
    # `find_reveal_metadata` returns the FIRST decodable scriptSig and that single
    # payload was reported as the transaction's metadata. Multi-glyph reveals are
    # real and not rare on mainnet — one observed reveal mints 35 refs from 36
    # inputs — so 34 of those refs were being shown another token's name,
    # description and media.
    #
    # The full per-input payload is not duplicated here; each entry carries enough
    # to see WHICH input a name belongs to, and `metadata.input_index` already says
    # which one the headline payload came from. What was missing was any signal
    # that other payloads existed at all.
    #
    # WHAT IS MINTED IS COUNTED FROM THE OUTPUTS, not from the envelopes (#743 round 2). Each entry
    # says whether the transaction creates a ref from that input's outpoint (`mints`), and
    # `of_n_minted` counts those. They used to be one number: an envelope on an input that mints
    # nothing — a decoy whose commit demands that its ref be in NO output, in a transaction a node
    # accepts — made both surfaces say "1 of 2 glyphs minted here" where one was.
    metadata_inputs: list[dict] = []
    read_by_reveal_reader: set[int] = set()  # every input `extract_reveal_metadata` decoded
    payload_count = 0
    minted_count = 0
    others_listed = 0
    others_not_listed = 0
    others_not_listed_minting = 0
    for idx, ss in enumerate(scriptsigs):
        m = inspector.extract_reveal_metadata(ss)
        if m is None:
            continue
        read_by_reveal_reader.add(idx)
        payload_count += 1
        minted_count += idx in minting
        # The headline payload's own entry is always listed; the OTHERS are what a reader has
        # no other way to learn about, and they are what `max_rows` bounds.
        if found is None or idx != found[0]:
            if max_rows is not None and others_listed >= max_rows:
                others_not_listed += 1
                others_not_listed_minting += idx in minting
                continue
            others_listed += 1
        metadata_inputs.append(
            {
                "input_index": idx,
                "classification": _classify_metadata_protocol(m),
                "name": _sanitize_display_string(m.name) if m.name else "",
                "ticker": _sanitize_display_string(m.ticker) if m.ticker else "",
                "mints": idx in minting,
            }
        )
    # WHAT THE OTHER PAYLOADS' COMMITS SAY is not written here: a row's verdict needs what the
    # fetches found — including the ones that failed or never happened — and only
    # `_spent_output_bindings` has that. `_apply_bindings` writes the rows, for both surfaces.
    # A GLYPH ENVELOPE THAT IS NOT A REVEAL. `find_reveal_metadata` answers only "is there a full
    # token payload here", and returns None both for "no glyph" and for "a glyph I could not
    # read" — so a mutable-glyph UPDATE transaction inspected as nothing at all. Measured on
    # mainnet (`custodian-gate-x7f3.rxd`): three of its four transactions carry the `gly` marker
    # and this path rendered one, while the two that MOVED where the name points rendered blank.
    #
    # Reported for every input, not just the first, and an envelope that neither reader accepts
    # is reported as UNREADABLE rather than omitted — "I cannot read this" and "there is nothing
    # here" are opposite facts and the blind one is the more reassuring.
    glyph_envelopes: list[dict] = []
    envelopes_by_kind: dict[str, int] = {}  # past `max_rows`: counted by the kind each would show
    for idx, ss in enumerate(scriptsigs):
        env = inspector.classify_glyph_scriptsig(ss)
        if env is None:
            continue
        if env.kind == "payload" and idx in read_by_reveal_reader:
            # Skipped when the REVEAL READER read it too: it is the headline payload or one of the
            # other glyphs above, so it is rendered and the two readers agree about it.
            #
            # `payload_unrendered` below is for the case where they DO NOT: this classifier sees a
            # full payload and `extract_reveal_metadata` returns nothing, so neither the metadata
            # block nor the other-glyphs list shows it. It was added (#665) when the reveal reader
            # had its own push walker that stopped at `OP_0`; the same change gave both readers one
            # walker and one marker rule, and no byte string is known today on which they
            # disagree. It stays because a later change to either reader could bring the
            # disagreement back, and a reveal rendered as nothing is the failure this surface
            # exists to prevent.
            #
            # This skip used to test `found[0] == idx` — the HEADLINE input only — so every other
            # payload of a multi-glyph reveal, listed under "other glyphs" as read, was also
            # reported here as a payload "the reveal reader did not return". On the mainnet GLYPH
            # deploy reveal (b965b32d…9dd6) that described input 33 both ways.
            continue
        if max_rows is not None and len(glyph_envelopes) >= max_rows:
            _count(envelopes_by_kind, "payload_unrendered" if env.kind == "payload" else env.kind)
            continue
        if env.kind == "payload":
            glyph_envelopes.append(
                {
                    "input_index": idx,
                    "kind": "payload_unrendered",
                    "reason": _sanitize_display_string(
                        "this input carries a full glyph payload that the reveal reader did not "
                        "return — the two readers disagree about these bytes"
                    ),
                }
            )
            continue
        entry: dict = {"input_index": idx, "kind": env.kind}
        if env.kind == "update":
            # Attacker-authored CBOR landing in terminal output: same sanitisation rule as every
            # other indexer/chain string here, applied to keys AND values.
            if max_rows is None:
                entry["fields"] = _sanitize_update_fields(env.fields or {})
            else:
                # A bounded caller draws _HUMAN_ENTRY_CAP fields at the top level and of each map,
                # besides `attrs` and `attrs.target` (`_drawn_update_fields` says exactly which), and
                # an update's key set is the publisher's to choose: carrying all of them was 21,000 fields per
                # envelope in the review's measurement. So it gets what it draws, and counts.
                entry["fields"], fields_not_listed = _drawn_update_fields(env.fields or {})
                if fields_not_listed:
                    entry["fields_not_listed"] = fields_not_listed
        else:
            entry["reason"] = _sanitize_display_string(env.reason)
        glyph_envelopes.append(entry)

    metadata_payload: dict | None = None
    if attributed is not None:
        input_idx, metadata, _cbor, _outpoint = attributed
        # WHAT THIS ATTRIBUTION IS WORTH. Reported for every inspect, because
        # "I did not check" and "I checked and it held" are opposite facts and the
        # silent one reads as the reassuring one.
        metadata_payload = {
            "input_index": input_idx,
            # THE OUTPOINT THAT WOULD SETTLE IT. The classifier is network-free by
            # design, so `payload_binding` can only read `unchecked` unless someone
            # fetches this. Naming it is what makes the check REACHABLE from outside
            # this module — the CLI's --fetch path and the browser page both resolve
            # it from here — and it is also the outpoint a human would go and look
            # at by hand.
            "input_outpoint": _outpoint,
            # Does this transaction create a ref from that outpoint — mint the token this payload
            # would describe? Read off the outputs; `payload_binding` says what the commit adds.
            "mints": input_idx in minting,
            "payload_binding": _payload_binding(_cbor, known_spent.get(input_idx), _outpoint, output_scripts),
            "protocol": [_sanitize_display_string(str(p)) for p in metadata.protocol],
            # Human-friendly highest-specificity protocol label (e.g. "wave",
            # "container", "timelock", "authority", "dat"). Computed from the
            # real GlyphMetadata so the WAVE case can require an attrs.name
            # (present, not proven resolvable — see _classify_metadata_protocol).
            # The label is drawn from a fixed internal vocabulary,
            # not user-controllable CBOR text, so no sanitization is needed.
            "classification": _classify_metadata_protocol(metadata),
            "name": _sanitize_display_string(metadata.name) if metadata.name else "",
            "ticker": _sanitize_display_string(metadata.ticker) if metadata.ticker else "",
            "description": _sanitize_display_string(metadata.description) if metadata.description else "",
            "decimals": metadata.decimals,
            # TR39 confusables. `docs/concepts/glyph-inspect-tool.md` has described
            # this as a live protection — "a Cyrillic-spoofed USDC is flagged with a
            # warning banner before the user sees the rendered metadata" — while
            # `looks_confusable_with_latin` had NO PRODUCTION CALLER anywhere: a
            # definition, a facade re-export, and tests. The CLI performed no
            # confusables check at all, and the browser page used a weaker
            # script-mixing heuristic that fires on any all-non-Latin name.
            #
            # Computed here rather than in either renderer so both surfaces get it
            # from one place. Sanitization strips control and bidi codepoints; it
            # cannot help with a Cyrillic "С" that simply LOOKS like "C".
        }
        # RELATIONSHIP CLAIMS, WITH THEIR VERDICT (#591). `in` and `by` are
        # operator-supplied CBOR — anyone can name any collection — so the claim is
        # never surfaced without whether the transaction was authorised to carry it.
        # Consensus's subset rule makes that checkable from this transaction alone:
        # a ref in an output carried by one of the THREE subset-checked opcodes
        # (`INPUT_BACKED_REF_OPCODES`) must be backed by an input ref, so a claimed
        # parent appearing under one of those means the transaction spent it. The
        # other two operand-carrying opcodes prove nothing and are discarded — see
        # `output_ref_operands`.
        rel = verify_relationship_claims(metadata, output_scripts, delegated_refs=delegated_refs)
        if rel:
            listed_rel = rel if max_rows is None else rel[:max_rows]
            metadata_payload["relationships"] = [
                {
                    "kind": v.kind.value,
                    "ref": f"{v.ref.txid}:{v.ref.vout}",
                    "ok": v.ok,
                    "basis": v.basis.value,
                    "reason": v.reason,
                }
                for v in listed_rel
            ]
            if len(listed_rel) < len(rel):
                # Counted by everything a claim's verdict line is drawn from, so the words a
                # reader is given for the rest are the words each claim would have been given.
                groups: dict[tuple, int] = {}
                for v in rel[len(listed_rel) :]:
                    key = (v.kind.value, v.ok, v.basis.value)
                    groups[key] = groups.get(key, 0) + 1
                metadata_payload["relationships_not_listed"] = {
                    "count": len(rel) - len(listed_rel),
                    "groups": [
                        {"kind": kind, "ok": ok, "basis": basis, "count": n} for (kind, ok, basis), n in groups.items()
                    ],
                }
        # A claim may instead be authorised by a DELEGATE, which this function
        # cannot resolve: it is handed a pre-fetched transaction and has no way
        # to fetch the base whose refs the burn points at. So report what is
        # visible rather than letting "unbacked" stand as the whole story — an
        # UNBACKED verdict beside a burned base ref means "not resolved here",
        # not "forged", and a reader who cannot see the second fact will draw
        # the wrong conclusion from the first.
        from .types import GlyphRef

        burns = delegate_burn_refs(output_scripts)
        if burns:
            all_burns = sorted(f"{GlyphRef.from_bytes(b).txid}:{GlyphRef.from_bytes(b).vout}" for b in burns)
            metadata_payload["delegate_burns"] = all_burns if max_rows is None else all_burns[:max_rows]
            if len(metadata_payload["delegate_burns"]) < len(all_burns):
                metadata_payload["delegate_burns_not_listed"] = {
                    "count": len(all_burns) - len(metadata_payload["delegate_burns"])
                }

        # ABSENCE IS SILENCE, matching `glue.py`, which sets this key only when it has
        # something to say. Emitting an empty dict unconditionally made "flagged" and
        # "checked and clean" indistinguishable to a caller testing for the key — and
        # the browser drift guard caught exactly that the moment the two branches met.
        confusables = _confusable_warnings(metadata)
        if confusables:
            metadata_payload["display_warnings"] = confusables
        # TIMELOCK: say WHEN it opens, not just that it is one (#556). `classification` already
        # reported "timelock"; the field that answers the holder's actual question — can I read
        # this yet — was decoded nowhere until now.
        #
        # NO UNLOCKED/LOCKED VERDICT IS EMITTED HERE. `is_unlocked` needs the caller's view of the
        # chain (a tip height for mode="block", a timestamp for mode="time"), and this function is
        # given neither. Printing a verdict computed from a clock this process happens to have
        # would be a guess presented as a fact — the CLI supplies the tip and renders the verdict.
        # `hint` is operator-supplied CBOR text and is sanitised like every other display string.
        if metadata.timelock is not None:
            tl = metadata.timelock
            metadata_payload["timelock"] = {
                "mode": _sanitize_display_string(str(tl.mode)),
                "unlock_at": tl.unlock_at,
                "cek_hash": _sanitize_display_string(tl.cek_hash),
                "hint": _sanitize_display_string(tl.hint) if tl.hint else "",
            }
        # Imported HERE, not at module scope. `pyrxd.glyph.inspect` is loaded in
        # the browser under Pyodide and `test_inspect_imports_pyodide_clean`
        # holds it to a module budget; authority decoding is not needed to
        # import the facade, only to classify a token that declares it.
        from .authority import is_authority, is_authority_expired, read_authority_attrs, validate_authority

        # AUTHORITY: report the issuer and permissions, and say what they are.
        # The classifier already labelled this "authority"; that label is a
        # protocol MARKER, which anyone can write. Everything here is likewise
        # operator CBOR, so it is emitted under `claims` and paired with the
        # metadata problems `validate_authority` found — an authority whose
        # issuer is missing or whose expiry does not parse still classifies as
        # one, and a reader shown only the label would not know.
        if is_authority(metadata):
            attrs = read_authority_attrs(metadata)
            problems = validate_authority(metadata)
            authority_payload: dict = {
                "claims": {
                    "issuer": _sanitize_display_string(attrs.issuer) if attrs else "",
                    "scope": _sanitize_display_string(attrs.scope) if attrs and attrs.scope else "",
                    "permissions": [_sanitize_display_string(p) for p in (attrs.permissions if attrs else ())],
                    "expires": _sanitize_display_string(attrs.expires) if attrs and attrs.expires else "",
                    "revocable": attrs.revocable if attrs else True,
                },
                "expired": is_authority_expired(metadata),
            }
            if problems:
                # SANITISED LIKE EVERY SIBLING IN `claims`. `validate_authority` embeds the raw
                # attacker-chosen `expires` with `!r`, and `repr()` escapes format characters but
                # NOT combining marks — measured, 40 of them survive a repr that strips the bidi
                # override beside them. This was the one field in the block that skipped the
                # sanitiser, harmless only because nothing rendered it; rendering it makes that
                # live, so it is fixed in the same change.
                authority_payload["problems"] = [
                    _truncate_for_human(_sanitize_display_string(str(p))) for p in problems
                ]
            metadata_payload["authority"] = authority_payload

        if metadata.main is not None:
            from ..hash import sha256

            metadata_payload["main"] = (
                f"<media: {_sanitize_display_string(metadata.main.mime_type)}, "
                f"{len(metadata.main.data)} bytes, "
                f"sha256={sha256(metadata.main.data).hex()}>"
            )

    if metadata_payload is not None and payload_count > 1:
        # Say it on the headline payload too. A caller reading only `metadata` must
        # not be able to mistake one glyph's fields for the transaction's.
        metadata_payload["of_n_payloads"] = payload_count
        # ...and how many of those this transaction MINTS, which is not the same number.
        metadata_payload["of_n_minted"] = minted_count

    payload = {
        "form": "txid",
        "txid": str(txid),
        "byte_length": len(raw),
        "input_count": len(tx.inputs),
        "output_count": len(tx.outputs),
        "outputs": output_rows,
        "metadata": metadata_payload,
        # Glyph envelopes that are NOT full payloads: updates, and envelopes that
        # could not be read. Empty list when the transaction carries neither.
        "glyph_envelopes": glyph_envelopes,
        "metadata_inputs": metadata_inputs,
        "mint_scriptsig": mint_scriptsig,
    }
    # WHAT A FETCHING CALLER SHOULD FETCH to settle the headline: the spent transactions of the
    # minting payloads' inputs, at most `_MAX_BINDING_FETCHES` (`_binding_candidates`). Both the
    # CLI's `--fetch` and the page read this list, so they ask for the same outpoints.
    if metadata_payload is not None:
        payload["binding_candidates"] = _binding_candidates(tx.inputs, scriptsigs, inspector, minting)
    # WHAT WAS COUNTED AND NOT LISTED, beside each list, only when something was. Every count is
    # of what the classifier decided about each entry left out — never inferred from position.
    if unlisted_vouts:
        payload["outputs_not_listed"] = {
            "count": len(unlisted_vouts),
            "first_vout": unlisted_vouts[0],
            "last_vout": unlisted_vouts[-1],
            "by_type": outputs_by_type,
            "hashmark_by_status": marks_by_status,
            # Past the CHECKING limit: its own number, because it is the one that says a
            # record that does not verify could be among them.
            "not_checked_here": marks_by_status.get(NOT_CHECKED_HERE_WORD, 0),
        }
        # WHAT THE WHOLE TRANSACTION IS, for a caller that describes it from a cut listing. The
        # page's shape banner used to count `outputs` — at most `max_rows` of them — and so told a
        # reader a 151-output dMint deploy "creates 100 dMint contract UTXOs", and that a
        # 121-output FT deploy commit whose commit-nft sat at vout 120 "does not" carry one.
        # Every figure here is over every output this call enumerated, from the same rows the
        # counts above come from. Not emitted for an `only_vout` listing, which enumerates one
        # output and so could not say anything about the rest.
        if only_vout is None:
            payload["output_shape"] = shape.as_payload()
    if envelopes_by_kind:
        payload["glyph_envelopes_not_listed"] = {
            "count": sum(envelopes_by_kind.values()),
            "by_kind": envelopes_by_kind,
        }
    if others_not_listed:
        payload["metadata_inputs_not_listed"] = {"count": others_not_listed, "minting": others_not_listed_minting}
    # Bounded as a whole, like `_inspect_script`'s payload: the output rows already are, but
    # `metadata` carries reveal-envelope integers of its own — a TIMELOCK's `unlock_at` is
    # `int(...)` of raw CBOR with no width limit — and so will whatever field is added next.
    return cast(dict, _render_safe(payload))
