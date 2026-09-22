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
#: its context differs (it aggregates across every record in a transaction and quotes the
#: failing one's detail). What must NEVER differ between surfaces is the STATUS word, and
#: that is what this table owns: the claim is shared, the elaboration is local.
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


def _render_safe(value: object, _depth: int = 0) -> object:
    """*value* with every integer wider than :data:`_MAX_RENDERED_INT_BITS` replaced by text.

    THE ONE BOUNDED FORMATTER both output modes use. The classifier's two entry points
    (:func:`_inspect_script`, :func:`_classify_raw_tx`) return their payload through this, so
    the CLI's human renderer, its ``--json`` output, the browser panel and an SDK caller all
    receive a payload in which no integer is too wide to print. It is applied to the WHOLE
    payload rather than to the fields known to be attacker-authored, because that list is
    exactly what went stale: the burn amount, the TIMELOCK ``unlock_at`` and the update
    envelope were three unrelated fields with the same defect.

    Containers come back as their BASE type — a tuple stays a tuple, so it stays hashable for
    use as a key — because rebuilding a subclass (a ``namedtuple``, a ``defaultdict``) from an
    iterable is not a constructor call they all accept. Anything nested past
    :data:`_MAX_RENDER_DEPTH` is replaced by a statement that it was not walked.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value if value.bit_length() <= _MAX_RENDERED_INT_BITS else _oversized_int_text(value)
    if isinstance(value, (dict, list, tuple, set, frozenset)):
        if _depth >= _MAX_RENDER_DEPTH:
            return f"<{type(value).__name__} nested more than {_MAX_RENDER_DEPTH} levels deep — not rendered>"
        if isinstance(value, dict):
            return {_render_safe(k, _depth + 1): _render_safe(v, _depth + 1) for k, v in value.items()}
        items = [_render_safe(item, _depth + 1) for item in value]
        if isinstance(value, tuple):
            return tuple(items)
        if isinstance(value, frozenset):
            return frozenset(items)
        return set(items) if isinstance(value, set) else items
    return value


def _display_text(value: object) -> str:
    """``str(value)`` for an arbitrary decoded CBOR value, without ever raising.

    :func:`_render_safe` bounds the integers it can SEE, inside plain containers. A CBOR
    value can also hide one inside an object whose ``str()`` prints it — an unknown tag
    (``CBORTag(40404, <bignum>)``) or a tag-30 rational (``Fraction``) — so the conversion
    itself is guarded too, and what it could not render is named rather than dropped.
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
    structures are rendered as their repr and sanitised whole rather than walked — an attacker
    choosing the nesting depth should not choose how much work this does.

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
    claim belongs to the signature, and even the signature only reaches key custody.
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


def _inspect_script(script_hex: str, *, network: str = "mainnet") -> dict:
    """Classify a single hex-encoded locking script. Returns a flat dict.

    The classifier has twenty-odd return statements, one per shape. Bounding the payload
    HERE, at the one door they all leave through, means a shape added later cannot forget
    to — see :func:`_render_safe`.
    """
    return cast(dict, _render_safe(_classify_script(script_hex, network=network)))


def _classify_script(script_hex: str, *, network: str) -> dict:
    """The classifier behind :func:`_inspect_script`; its payload is NOT yet render-safe."""
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
        out = {
            **base,
            "type": "op_return",
            "data_hex": script[1:].hex(),
        }
        # HashMark is a THIRD-PARTY OP_RETURN format on Radiant (MIT, spec at
        # github.com/cdonnachie/hashmark.rxd). Decoding it here is read-only and
        # additive: anything that is not one stays plain `op_return`, because a
        # scanner meets thousands of other protocols' data outputs and treating
        # them as errors buries the real ones.
        # The Photonic `msg` convention: OP_RETURN PUSH3 "msg" <push> <message>.
        # Measured on 20 consecutive mainnet blocks, 73 of 73 OP_RETURN outputs
        # carried this marker and nothing else did — it is the whole observed
        # population, and pyrxd already WRITES it. Reading it back turns the
        # commonest data output on the chain from an opaque blob into its text.
        msg = decode_message(script)
        if msg.outcome is not MessageOutcome.NOT_MESSAGE:
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
            if msg.ok:
                out["type"] = "op_return-msg"

        # A Glyph BURN proof. Refines `op_return` the way the message and
        # HashMark decoders do. Everything in it is operator CBOR — the ref it
        # names, the amount, the reason — so it is emitted under `claims` and
        # the note says what is missing to turn it into a verdict.
        proof = parse_burn_proof(script)
        if proof is not None:
            out["type"] = "op_return-burn"
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

        mark = decode_hashmark(script)
        if mark.outcome is not HashMarkOutcome.NOT_HASHMARK:
            out["hashmark"] = {
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
            if mark.ok:
                out["type"] = f"op_return-hashmark-v{mark.version}"
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
                    "signer_address": _address_for(att.recovered_hash160_hex, network),
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

    Only reports MIMICRY. A name in a wholly non-Latin script is not flagged —
    ``looks_confusable_with_latin`` says so explicitly, listing "トークン" and "中文"
    among its non-flagged examples. That distinction is the point: a warning that
    fires on every legitimate Japanese token is the false positive that trains a
    reader to ignore the real one, which this repo names as a hazard elsewhere.

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
    WAVE case can require a resolvable ``attrs.name`` (legacy top-level-name
    WAVE tokens exist on-chain but RXinDexer won't index them, so they
    classify as their underlying ``mut``).

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


def _payload_binding(metadata_cbor: bytes | None, spent_script: bytes | None) -> dict:
    """Did the commit this input spent actually commit to THIS payload?

    A commit output's locking script carries ``sha256d(envelope CBOR)`` as its
    ``payload_hash``. Nothing checked the reveal's envelope against it, and both
    readers take the FIRST ``gly`` push in the FIRST input that decodes — so the
    name, attrs and creator shown to a human need not be the ones the commit
    committed to. Demonstrated at library level: inputs ``[decoy, real]`` attribute
    the decoy; ``[real, decoy]`` attribute the real one. Whichever is first wins.

    On the commit input itself a second envelope is unreachable — ``CLEANSTACK``
    and ``SIGPUSHONLY`` are set unconditionally for block connection
    (``tests/vendor/radiant_core/validation.cpp``), and the commit script's stack
    arithmetic is fixed. The vector is a SECOND input whose locking script consumes
    the extra items, placed first.

    This is deliberately a REPORT, not a refusal. The classifier is network-free,
    so the spent script is only present when a fetching caller supplied it; a
    verdict that silently means "I could not check" is the thing being fixed, so
    every state is named. ``mismatch`` is the one that matters.
    """
    from .script import extract_payload_hash_from_commit_script

    if spent_script is None:
        return {
            "state": "unchecked",
            "reason": "the spent output of the attributed input was not supplied, so the "
            "payload was not checked against the commit that committed to it",
        }
    try:
        expected = extract_payload_hash_from_commit_script(spent_script)
    except (ValidationError, ValueError, IndexError):
        return {
            "state": "not-a-commit",
            "reason": "the attributed input did not spend a commit output, so no payload hash "
            "binds this envelope to anything",
        }
    if metadata_cbor is None:
        return {
            "state": "unchecked",
            "reason": "the envelope CBOR was not recoverable for hashing",
        }
    actual = hash256(metadata_cbor)
    if actual == expected:
        return {"state": "bound", "reason": "the spent commit committed to exactly this payload"}
    return {
        "state": "mismatch",
        "reason": "THE SPENT COMMIT COMMITTED TO A DIFFERENT PAYLOAD than the envelope shown "
        "here — treat this metadata as unattributed",
    }


def _classify_raw_tx(
    txid_hex: str,
    raw: bytes,
    *,
    only_vout: int | None = None,
    network: str = "mainnet",
    delegated_refs: Mapping[bytes, Sequence[bytes]] | None = None,
    spent_scripts: Mapping[int, bytes] | None = None,
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
            row = _inspect_script(script_bytes.hex(), network=network)
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

    # dMint mint-claim scriptSig: if vin[0] is a dMint mint claim (4 canonical
    # pushes — nonce, inputHash, outputHash, OP_0), decode it for display.
    # NOT raised; returns None for non-mint inputs (P2PKH funding inputs,
    # plain RXD spends, reveal scriptSigs, etc.). The V1/V2 distinction
    # falls out of the nonce push width (4 vs 8 bytes).
    mint_scriptsig: dict | None = None
    if scriptsigs:
        mint_scriptsig = inspector.parse_mint_scriptsig(scriptsigs[0])
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
    for idx, ss in enumerate(scriptsigs):
        env = inspector.classify_glyph_scriptsig(ss)
        if env is None:
            continue
        if env.kind == "payload":
            # ONLY when the OTHER reader actually rendered it. `find_reveal_metadata` walks
            # `_parse_reveal_scriptsig`, which was NOT unified with `_walk_pushes` - it breaks on
            # `OP_0` where the new walker treats it as an empty push. So for a push-only scriptSig
            # with one leading zero byte, classify sees a payload, extract sees nothing, and
            # skipping here on the assumption that the metadata block will render it meant a glyph
            # reveal rendered as NOTHING AT ALL - the blindness this whole surface exists to end,
            # reintroduced one layer up. When the two disagree, say so rather than trusting either.
            if found is not None and found[0] == idx:
                continue
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
            entry["fields"] = _sanitize_update_fields(env.fields or {})
        else:
            entry["reason"] = _sanitize_display_string(env.reason)
        glyph_envelopes.append(entry)

    metadata_payload: dict | None = None
    if found is not None:
        input_idx, metadata = found
        # WHAT THIS ATTRIBUTION IS WORTH. Reported for every inspect, because
        # "I did not check" and "I checked and it held" are opposite facts and the
        # silent one reads as the reassuring one.
        _cbor = inspector.extract_reveal_cbor(scriptsigs[input_idx]) if scriptsigs else None
        _src = tx.inputs[input_idx]
        metadata_payload = {
            "input_index": input_idx,
            # THE OUTPOINT THAT WOULD SETTLE IT. The classifier is network-free by
            # design, so `payload_binding` can only read `unchecked` unless someone
            # fetches this. Naming it is what makes the check REACHABLE from outside
            # this module — the CLI's --fetch path and the browser page both resolve
            # it from here — and it is also the outpoint a human would go and look
            # at by hand.
            "input_outpoint": (f"{_src.source_txid}:{_src.source_output_index}" if _src.source_txid else None),
            "payload_binding": _payload_binding(_cbor, (spent_scripts or {}).get(input_idx)),
            "protocol": [_sanitize_display_string(str(p)) for p in metadata.protocol],
            # Human-friendly highest-specificity protocol label (e.g. "wave",
            # "container", "timelock", "authority", "dat"). Computed from the
            # real GlyphMetadata so the WAVE case can require a resolvable
            # attrs.name. The label is drawn from a fixed internal vocabulary,
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
        output_scripts = [bytes(o.locking_script.serialize()) for o in tx.outputs]
        rel = verify_relationship_claims(metadata, output_scripts, delegated_refs=delegated_refs)
        if rel:
            metadata_payload["relationships"] = [
                {
                    "kind": v.kind.value,
                    "ref": f"{v.ref.txid}:{v.ref.vout}",
                    "ok": v.ok,
                    "basis": v.basis.value,
                    "reason": v.reason,
                }
                for v in rel
            ]
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
            metadata_payload["delegate_burns"] = sorted(
                f"{GlyphRef.from_bytes(b).txid}:{GlyphRef.from_bytes(b).vout}" for b in burns
            )

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
    metadata_inputs: list[dict] = []
    for idx, ss in enumerate(scriptsigs):
        m = inspector.extract_reveal_metadata(ss)
        if m is None:
            continue
        metadata_inputs.append(
            {
                "input_index": idx,
                "classification": _classify_metadata_protocol(m),
                "name": _sanitize_display_string(m.name) if m.name else "",
                "ticker": _sanitize_display_string(m.ticker) if m.ticker else "",
            }
        )
    if metadata_payload is not None and len(metadata_inputs) > 1:
        # Say it on the headline payload too. A caller reading only `metadata` must
        # not be able to mistake one glyph's fields for the transaction's.
        metadata_payload["of_n_payloads"] = len(metadata_inputs)

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
    # Bounded as a whole, like `_inspect_script`'s payload: the output rows already are, but
    # `metadata` carries reveal-envelope integers of its own — a TIMELOCK's `unlock_at` is
    # `int(...)` of raw CBOR with no width limit — and so will whatever field is added next.
    return cast(dict, _render_safe(payload))
