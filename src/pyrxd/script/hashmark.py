"""Read and write HashMark records — a THIRD-PARTY ``OP_RETURN`` format on Radiant.

HashMark records a file's digest on chain so anyone can later prove the file
existed no later than the block that confirmed the transaction. It is not ours:
the protocol and its reference implementation are by a Radiant contributor,
MIT-licensed, and specified in ``HASHMARK_PROTOCOL.md`` at
https://github.com/cdonnachie/hashmark.rxd — written, in its own words, "so that
a developer with no access to the HashMark codebase can implement a complete,
independent verifier".

This module is that independent implementation. The decoder
(:func:`decode_hashmark`) was written from ``HASHMARK_PROTOCOL.md`` ALONE,
without reading the reference source, and :func:`encode_hashmark` was written
the same way — that independence is what makes
``tests/test_hashmark_mainnet_vectors.py`` (his writer, our reader) and
``tests/test_hashmark_encoder.py`` (our writer, his reader) a real
cross-implementation proof rather than pyrxd agreeing with pyrxd. The upstream
commit both were read against is pinned in
``tests/fixtures/hashmark_upstream_pin.json``; do not read
``packages/protocol/src/encode.ts`` while changing the encoder.

pyrxd writes **v2 only**. v1 carries no signature, so a v1 mark says WHEN and
never WHO; reading v1 stays supported because the chain already has v1 records
on it.

**What a HashMark does not prove.** The spec makes this normative for any UI
built on it, and repeating it here is deliberate — a decoder that returns a
record without the caveat invites exactly the wrong reading. A mark proves that
*someone knew this digest no later than the confirmed block containing this
transaction*. It does NOT establish authorship (anyone can hash a file they did
not write), ownership, originality (two people can mark the same file; earliest
is earliest, not rightful), the truth of the contents, or legal validity. A v2
signature identifies the key that made the statement — never the author.

**Decoding is not attestation.** A v2 record carries a signer and a signature,
and this module does NOT verify that signature: verifying it needs secp256k1 and
the chain the transaction was found on. A record that decodes is well-formed,
not yet believed. :attr:`HashMarkRecord.signature` is returned unverified and
must be labelled as such by any caller that surfaces it.
"""

from __future__ import annotations

import unicodedata
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, NoReturn

from ..constants import GENESIS_BLOCK_HASHES, OpCode
from ..security.errors import ValidationError
from .script import data_pushes_after_op_return

if TYPE_CHECKING:  # pragma: no cover - import only for the annotation
    from ..keys import PrivateKey

__all__ = [
    "HASHMARK_MAGIC",
    "RADIANT_MAINNET_GENESIS",
    "AttestationOutcome",
    "AttestationResult",
    "HashMarkOutcome",
    "HashMarkRecord",
    "RecoveryUnavailable",
    "algorithm_for",
    "canonical_statement",
    "canonicalize_label",
    "decode_hashmark",
    "encode_hashmark",
    "max_label_bytes",
    "recovery_backend",
    "set_recovery_backend",
    "verify_attestation",
]

#: The exact ASCII bytes every record opens with. Compared as BYTES, never as a
#: decoded string — a decoded comparison invites encoding-dependent equality.
HASHMARK_MAGIC = b"HASHMARK"

#: algorithmId -> (name, digest length). Ids 0x00 and 0x02..0xFF are unassigned.
#: The digest length comes from THIS table, never from the push length, which is
#: what stops a truncated digest being accepted at the wrong width.
_ALGORITHMS: dict[int, tuple[str, int]] = {0x01: ("sha256", 32)}

_OP_RETURN = OpCode.OP_RETURN.value[0] if hasattr(OpCode.OP_RETURN, "value") else 0x6A


#: Codepoints §5.4 REJECTS in a label, as ranges and singletons.
#:
#: C0 and DEL smuggle line breaks and terminal escapes past a human reviewer; C1
#: is still acted on by real terminals; U+2028/2029 are genuine line separators;
#: and the bidi marks, overrides and isolates reorder rendered text with no line
#: break at all. U+200C ZWNJ and U+200D ZWJ are deliberately NOT rejected — they
#: are joiners, and rejecting them would refuse legitimate text in several
#: scripts.
_LABEL_REJECTED_RANGES: tuple[tuple[int, int], ...] = (
    (0x00, 0x1F),  # C0
    (0x7F, 0x9F),  # DEL + C1
    (0x2028, 0x2029),  # line / paragraph separator
    (0x202A, 0x202E),  # bidi embeddings and overrides
    (0x2066, 0x2069),  # bidi isolates
)
_LABEL_REJECTED_CHARS: frozenset[int] = frozenset({0x061C, 0x200B, 0x200E, 0x200F, 0xFEFF})


def _label_defect(label: str) -> str | None:
    """Why this label is not canonical per §5.4, or None if it is fine.

    CANONICALISATION RUNS ONE WAY. A decoder must never trim or normalise a label
    it has read — it rejects or withholds a non-canonical one. Silently fixing it
    would mean the string shown is not the string signed.
    """
    for ch in label:
        cp = ord(ch)
        if cp in _LABEL_REJECTED_CHARS or any(lo <= cp <= hi for lo, hi in _LABEL_REJECTED_RANGES):
            return f"contains U+{cp:04X}"
    if label != label.strip():
        return "has leading or trailing whitespace"
    if unicodedata.normalize("NFC", label) != label:
        return "is not Unicode NFC"
    return None


class HashMarkOutcome(Enum):
    """Why a decode ended, kept as four distinct outcomes rather than a bool.

    The spec argues each separation has "cost someone a wrong answer somewhere",
    and the reasoning is worth preserving:

    * ``NOT_HASHMARK`` vs ``INVALID`` — a block scanner meets thousands of other
      protocols' ``OP_RETURN`` outputs. Treating them as errors buries the real
      ones.
    * ``UNKNOWN_VERSION`` vs ``INVALID`` — a record from the future is not
      corrupt. Calling it malformed would make every later version look like
      damage.
    * ``UNKNOWN_ALGORITHM`` vs ``INVALID`` — likewise: unimplemented, not broken.
    """

    OK = "ok"
    NOT_HASHMARK = "not_hashmark"
    INVALID = "invalid"
    UNKNOWN_VERSION = "unknown_version"
    UNKNOWN_ALGORITHM = "unknown_algorithm"


@dataclass(frozen=True)
class HashMarkRecord:
    """A decoded record. ``outcome`` is always checked FIRST — every other field
    is meaningful only when it is :attr:`HashMarkOutcome.OK`."""

    outcome: HashMarkOutcome
    version: int | None = None
    algorithm_id: int | None = None
    algorithm: str | None = None
    #: Lowercase hex, always. The spec requires uppercase be REJECTED rather
    #: than normalised, so a digest has exactly one accepted spelling.
    digest_hex: str | None = None
    label: str | None = None
    #: v1 only: why the label was withheld from display, per §5.4. The record stays
    #: valid — a v1 label is not signed and forms no part of any claim, so a
    #: dangerous one can misrepresent itself on screen but not a statement.
    #: Invalidating would discard timestamp evidence to fix a rendering problem.
    label_withheld: str | None = None
    #: v2 only: hash160 of the key that signed. NOT verified here.
    signer_hash160_hex: str | None = None
    #: v2 only: 65-byte compact recoverable signature. NOT verified here.
    signature_hex: str | None = None
    detail: str | None = None

    @property
    def ok(self) -> bool:
        return self.outcome is HashMarkOutcome.OK


#: v1's label cap is a flat number in the spec (§5.4).
_V1_LABEL_CAP = 128

#: The whole-record ceiling both versions share, in bytes (§5.4, §7).
_MAX_RECORD_BYTES = 223


def _encoded_push_size(n: int) -> int:
    """Bytes a push of *n* payload bytes occupies, minimally encoded (§4.1)."""
    return 1 + n if n <= 75 else 2 + n if n <= 255 else 3 + n


def _max_label_bytes(digest_len: int) -> int:
    """The v2 label cap for a given digest length — DERIVED, per §5.4.

    v2 spends 87 bytes on the signer and signature, so the label gets whatever is
    left of the 223-byte record ceiling. For sha256 that is 88.

    This was hardcoded to 223 — the whole-RECORD ceiling, mistaken for the label's
    share of it. It was unreachable only because the push walker refused every
    ``OP_PUSHDATA1``, so no label above 75 bytes could arrive at all; fixing the
    walker in the same commit is what makes getting this right load-bearing.

    Computed rather than tabulated so that registering a longer digest shrinks the
    label automatically, instead of silently producing records that stop relaying.
    """
    fixed = (
        1  # OP_RETURN
        + _encoded_push_size(8)  # magic
        + _encoded_push_size(2)  # header
        + _encoded_push_size(digest_len)
        + _encoded_push_size(20)  # signer hash160
        + _encoded_push_size(65)  # recoverable signature
    )
    # Largest L whose own push still fits. Solved directly rather than by search:
    # the label push costs 1 + L up to 75, then 2 + L.
    room = _MAX_RECORD_BYTES - fixed
    return room - 1 if room - 1 <= 75 else room - 2


def decode_hashmark(script: bytes) -> HashMarkRecord:
    """Decode a ``scriptPubKey`` as a HashMark record.

    Never returns a partial or best-effort result — the outcome is one of the
    five in :class:`HashMarkOutcome`, and a caller must branch on it.
    """
    if not script or script[0] != _OP_RETURN:
        return HashMarkRecord(HashMarkOutcome.NOT_HASHMARK)

    # HashMark 4.1: every record has exactly one valid serialization, so a
    # non-minimal push makes this not-a-HashMark rather than a HashMark to repair.
    pushes = data_pushes_after_op_return(script, require_minimal=True)
    if pushes is None or not pushes or pushes[0] != HASHMARK_MAGIC:
        return HashMarkRecord(HashMarkOutcome.NOT_HASHMARK)

    # Past the magic the output CLAIMS to be a HashMark, so every remaining
    # failure is a genuine defect rather than another protocol's output.
    if len(pushes) < 3 or len(pushes[1]) != 2:
        return HashMarkRecord(HashMarkOutcome.INVALID, detail="header push is not exactly 2 bytes")

    version, algorithm_id = pushes[1][0], pushes[1][1]
    if version not in (1, 2):
        return HashMarkRecord(
            HashMarkOutcome.UNKNOWN_VERSION, version=version, detail=f"version {version} not implemented"
        )
    if algorithm_id not in _ALGORITHMS:
        return HashMarkRecord(
            HashMarkOutcome.UNKNOWN_ALGORITHM,
            version=version,
            algorithm_id=algorithm_id,
            detail=f"algorithm id {algorithm_id:#04x} not implemented",
        )

    name, digest_len = _ALGORITHMS[algorithm_id]
    digest = pushes[2]
    if len(digest) != digest_len:
        return HashMarkRecord(
            HashMarkOutcome.INVALID,
            version=version,
            algorithm_id=algorithm_id,
            detail=f"{name} digest is {len(digest)} bytes, expected {digest_len}",
        )

    expected = (3, 4) if version == 1 else (5, 6)
    if len(pushes) not in expected:
        return HashMarkRecord(
            HashMarkOutcome.INVALID,
            version=version,
            algorithm_id=algorithm_id,
            detail=f"v{version} takes {' or '.join(map(str, expected))} pushes, found {len(pushes)}",
        )

    signer_hex = signature_hex = None
    if version == 2:
        signer, signature = pushes[3], pushes[4]
        if len(signer) != 20:
            return HashMarkRecord(
                HashMarkOutcome.INVALID, version=version, detail=f"signer is {len(signer)} bytes, expected 20"
            )
        if len(signature) != 65:
            return HashMarkRecord(
                HashMarkOutcome.INVALID, version=version, detail=f"signature is {len(signature)} bytes, expected 65"
            )
        signer_hex, signature_hex = signer.hex(), signature.hex()

    label = None
    label_withheld: str | None = None
    if len(pushes) == expected[1]:
        raw = pushes[-1]
        cap = _V1_LABEL_CAP if version == 1 else _max_label_bytes(len(digest))
        if not raw or len(raw) > cap:
            return HashMarkRecord(
                HashMarkOutcome.INVALID, version=version, detail=f"label is {len(raw)} bytes, expected 1..{cap}"
            )
        try:
            label = raw.decode("utf-8")
        except UnicodeDecodeError:
            return HashMarkRecord(HashMarkOutcome.INVALID, version=version, detail="label is not valid UTF-8")

        # §5.4, and the split is version-dependent on purpose.
        defect = _label_defect(label)
        if defect is not None:
            if version == 2:
                # The label is INSIDE the signed statement, so a non-canonical label
                # is not the label that was signed. The record is invalid.
                return HashMarkRecord(HashMarkOutcome.INVALID, version=version, detail=f"label {defect} (spec 5.4)")
            # v1: the label is not signed and forms no part of any claim, so a
            # dangerous one can misrepresent itself on screen but not a statement.
            # Withhold it and keep the record — invalidating would throw away
            # timestamp evidence to fix a rendering problem.
            label_withheld, label = f"label {defect} (spec 5.4)", None

    return HashMarkRecord(
        HashMarkOutcome.OK,
        version=version,
        algorithm_id=algorithm_id,
        algorithm=name,
        digest_hex=digest.hex(),  # .hex() is lowercase; the one accepted spelling
        label=label,
        label_withheld=label_withheld,
        signer_hash160_hex=signer_hex,
        signature_hex=signature_hex,
    )


# ---------------------------------------------------------------------------
# Attestation — SEPARATE from decoding, deliberately.
#
# The spec keeps these apart and says why: "a record that decodes is well-formed,
# not yet believed". An invalid signature is not a malformed record — the bytes
# were fine and the CLAIM does not hold — and reporting it as malformed sends
# whoever is debugging it after the wrong problem.
# ---------------------------------------------------------------------------

#: Radiant mainnet genesis, RPC/display byte order. Part of the SIGNED statement,
#: and NOT carried by the record — it is the verified context the transaction was
#: found in. The same record bytes on another chain make a different statement and
#: will not verify there, which is intended.
RADIANT_MAINNET_GENESIS = "0000000065d8ed5d8be28d6876b3ffb660ac2a6c0ca59e437e1f7a6f4e003fb4"

#: secp256k1 group order, for the range checks in §5.6.
_SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


class RecoveryUnavailable(Exception):
    """A registered recovery backend could not run — NOT a verdict on the signature.

    The distinction is the whole reason this exception exists. Everything else that
    goes wrong during recovery is a statement about the BYTES ("r is not the
    x-coordinate of any point"), and becomes ``INVALID_SIGNATURE``. This one is a
    statement about the MACHINE, and becomes ``UNVERIFIABLE`` — "not checked here",
    which is what a reader must be told when an honest mark met a broken verifier.
    """


#: What :func:`set_recovery_backend` accepts, and the only secp256k1 operation a
#: HashMark verifier needs: recover the public key from an ECDSA signature.
#:
#: ``(message_hash, r, s, rec_id, compressed) -> bytes``
#:
#: * ``message_hash`` — 32 bytes, ALREADY hashed. This is the ECDSA ``z``, i.e.
#:   ``hash256(text_digest(statement))``. A backend must not hash it again.
#: * ``r``, ``s`` — 32 bytes each, big-endian. Range and low-S checks have already
#:   run; a backend is arithmetic, not policy.
#: * ``rec_id`` — 0..3, derived from the signature header.
#: * ``compressed`` — whether to return the 33-byte SEC1 form. This decides the
#:   bytes the signer's hash160 was taken over, so it is the caller's to choose.
#:
#: Returns the SEC1 public key. Raises :class:`RecoveryUnavailable` if it could not
#: run at all; any other exception is read as "these bytes recover to nothing".
RecoveryBackend = Callable[[bytes, bytes, bytes, int, bool], bytes]

#: The registered backend, or ``None`` for "use coincurve".
#:
#: WHY A MODULE-LEVEL REGISTRY rather than a parameter threaded through callers.
#: The environment that needs this is the browser: pyrxd installs under Pyodide with
#: ``deps=False`` and ``coincurve`` has no pure-Python wheel, so every mark on the
#: public /verify/ page read NOT CHECKED. A parameter would have to be passed by
#: every surface that inspects a mark, and the surface that forgets is the one that
#: quietly goes on saying "not checked" while looking finished. Registering once at
#: page boot means /inspect/, /verify/ and anything added later get the real verdict
#: without anyone remembering to ask for it.
#:
#: It is deliberately NOT a fallback-when-coincurve-is-missing: a registered backend
#: wins outright, so a test can pin one implementation against the other over the
#: same records. Nothing in ``src/`` calls the setter — ``tests/
#: test_signature_backend_differential.py`` asserts that by name, and separately that
#: importing every shipped module leaves this ``None`` — which catches a registration made
#: at import time without naming the setter, e.g. a direct assignment to this variable.
#: Neither catches such an assignment inside a function that runs later. So the CLI and SDK
#: keep using coincurve and this value keeps being ``None`` everywhere but the browser.
_recovery_backend: RecoveryBackend | None = None


def set_recovery_backend(backend: RecoveryBackend | None) -> None:
    """Register (or clear, with ``None``) the secp256k1 recovery this module uses.

    For environments with no ``coincurve``. See :data:`RecoveryBackend` for the
    contract, and :data:`_recovery_backend` for why this is a registry.
    """
    global _recovery_backend
    if backend is not None and not callable(backend):
        raise ValidationError("a recovery backend must be callable")
    _recovery_backend = backend


def recovery_backend() -> RecoveryBackend | None:
    """The currently registered backend, or ``None`` when coincurve is in use."""
    return _recovery_backend


#: Why ``pyrxd.keys`` (and so coincurve) could not be imported, once an import has been
#: tried and has failed; ``None`` until then.
#:
#: REMEMBERED, SO THE IMPORT IS ATTEMPTED ONCE. A failed import leaves nothing in
#: ``sys.modules``, so Python retries it in full on every call — and under Pyodide, where
#: coincurve has no wheel, that re-compiled ``pyrxd/keys.py`` for every record. Measured
#: under Pyodide 0.26.4 in Node (not a browser), with no curve registered: 500 v1 records
#: took 2.73 s and compiled it 500 times. The answer cannot change within a process that
#: has no coincurve, so it is asked once. Tests that hide coincurve reset this around
#: themselves.
_secp256k1_import_failure: str | None = None


def _coincurve_backend() -> RecoveryBackend | str:
    """coincurve's recovery as a :data:`RecoveryBackend`, or the reason it is unavailable."""
    global _secp256k1_import_failure
    if _secp256k1_import_failure is not None:
        return _secp256k1_import_failure
    try:
        from ..keys import recover_public_key
    except ImportError as exc:  # pragma: no cover - exercised via a meta-path block
        _secp256k1_import_failure = str(exc)
        return _secp256k1_import_failure

    def backend(message_hash: bytes, r_b: bytes, s_b: bytes, rid: int, is_compressed: bool) -> bytes:
        # `hasher=None` because the caller has already applied `hash256`. Byte-identical to
        # the older `hasher=hash256` form over the preimage — coincurve applies the hasher
        # itself and this just applies it one line earlier, so BOTH backends receive the same
        # ECDSA `z` and the two paths differ in nothing but the curve arithmetic.
        return recover_public_key(r_b + s_b + bytes([rid]), message_hash, hasher=None).serialize(
            compressed=is_compressed
        )

    return backend


class AttestationOutcome(Enum):
    """Whether a decoded v2 record's signature actually holds."""

    VALID = "valid"
    INVALID_SIGNATURE = "invalid_signature"
    #: v1 carries no signer, so there is nothing to attest. Not a failure — v1
    #: never claimed to say WHO, only WHEN.
    NOT_ATTESTED = "not_attested"
    #: secp256k1 is not available here, so the signature could not be checked.
    #: NOT a verdict on the record: it is well-formed and undecided. §6 separates
    #: decoding from attestation for exactly this reason — "verifying a v2
    #: signature additionally needs secp256k1 … which a decoder in a
    #: dependency-free library will not have".
    UNVERIFIABLE = "unverifiable"


@dataclass(frozen=True)
class AttestationResult:
    outcome: AttestationOutcome
    #: hash160 of the key recovered from the signature, when recovery succeeded.
    recovered_hash160_hex: str | None = None
    detail: str | None = None

    @property
    def valid(self) -> bool:
        return self.outcome is AttestationOutcome.VALID


def _json_string(value: str) -> str:
    r"""Escape per §5.6: a quote becomes \\" and a backslash \\\\; everything else is
    emitted as raw UTF-8, never as a \\uXXXX escape.

    Hand-rolled rather than ``json.dumps`` on purpose — the stdlib escapes
    non-ASCII to ``\\uXXXX`` by default, which would change the signed bytes for
    any label containing an accent or an emoji.
    """
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _statement_field_defect(record: HashMarkRecord, network_genesis: object) -> str | None:
    """Why *record* cannot be turned into a §5.6 statement, or ``None`` if it can.

    Only TYPES are checked — whether each field is the kind of value the statement is built
    from. Whether the values are RIGHT is the signature's job, and a wrong value simply fails to
    verify. The point is that a hand-built record with a field of the wrong type gets one of
    :func:`verify_attestation`'s outcomes instead of a ``TypeError`` / ``AttributeError``.
    """
    algorithm_id = record.algorithm_id
    # `bool` is an `int`, and `f"{True:02x}"` is "01": a record claiming algorithm `True` would
    # otherwise be verified as algorithm 1. Not a header byte, so not a statement.
    if not isinstance(algorithm_id, int) or isinstance(algorithm_id, bool) or not 0 <= algorithm_id <= 0xFF:
        return f"algorithm id {algorithm_id!r} is not a header byte, so no statement can be built from this record"
    for name in ("digest_hex", "signer_hash160_hex"):
        if not isinstance(getattr(record, name), str):
            return f"{name} is {type(getattr(record, name)).__name__}, not a hex string"
    if record.label is not None and not isinstance(record.label, str):
        return f"label is {type(record.label).__name__}, not a string"
    if not isinstance(network_genesis, str):
        return f"network_genesis is {type(network_genesis).__name__}, not a genesis hash string"
    return None


def _public_key_shape_defect(public_key: object, *, compressed: bool) -> str | None:
    """What is wrong with a recovery backend's return, or ``None`` if it is a SEC1 key of the asked form.

    Length and prefix only — SEC1's own framing: 33 bytes led by 0x02/0x03 when *compressed*,
    65 bytes led by 0x04 when not. It does NOT check the point is on the curve; that is
    arithmetic, and the backend is the arithmetic. What it does rule out is a backend ignoring
    the ``compressed`` flag, or returning bytes that are not framed as a key at all.
    """
    if not isinstance(public_key, (bytes, bytearray)):
        return f"{type(public_key).__name__}, not bytes"
    want_len, want_prefixes = (33, (0x02, 0x03)) if compressed else (65, (0x04,))
    form = "compressed" if compressed else "uncompressed"
    if len(public_key) != want_len:
        return f"a {len(public_key)}-byte value where a {want_len}-byte {form} SEC1 key was asked for"
    if public_key[0] not in want_prefixes:
        return f"a value led by 0x{public_key[0]:02x}, which does not frame a {form} SEC1 key"
    return None


def _require_signable_genesis(network_genesis: object, *, allow_unknown_genesis: bool = False) -> str:
    """*network_genesis*, if a v2 statement may be SIGNED against it — otherwise raise.

    THIS IS THE WRITE SIDE ONLY. :func:`verify_attestation` takes whatever genesis its caller
    has, because a reader checks a record against the chain it was found on and cannot choose.
    A WRITER chooses, and a wrong choice is permanent: the statement is signed, published, and
    — because the genesis is not carried by the record — verifies against nothing but the exact
    string it was signed with, which no verifier on a real chain will supply.
    The encoder's own sign-then-verify cannot see it either, since it verifies against the same
    wrong string it signed. ``"mainnet"``, the mainnet hash in reversed (internal) byte order,
    the same hash in uppercase, and ``""`` all used to be signed and self-attest VALID.

    Two rules, from §5.6 ("``network`` is the chain's genesis hash in RPC/display byte order,
    64 lowercase hex ... A network whose genesis hash is unknown cannot be attested to at all"):

    * **The spelling** — exactly 64 lowercase hex characters. Refused, never normalised: a caller
      who passed uppercase has the value from somewhere this code cannot see, and lowercasing it
      would sign a string they did not pass.
    * **The chain** — one pyrxd ships a genesis for (mainnet, testnet, regtest), unless the caller
      passes ``allow_unknown_genesis=True``. That is for a chain pyrxd has no constant for (a
      private fork); it relaxes ONLY this rule, never the spelling.
    """
    if (
        not isinstance(network_genesis, str)
        or len(network_genesis) != 64
        or any(c not in "0123456789abcdef" for c in network_genesis)
    ):
        raise ValidationError(
            f"network_genesis must be the chain's genesis hash as 64 lowercase hex characters in "
            f"RPC/display byte order (spec 5.6), got {network_genesis!r} — a network NAME or an "
            f"uppercase spelling is a different statement from the one a verifier checks, so the "
            f"mark would never verify"
        )
    if allow_unknown_genesis or network_genesis in GENESIS_BLOCK_HASHES.values():
        return network_genesis
    reversed_hex = bytes.fromhex(network_genesis)[::-1].hex()
    for name, genesis in GENESIS_BLOCK_HASHES.items():
        if reversed_hex == genesis:
            raise ValidationError(
                f"network_genesis is the {name} genesis hash in INTERNAL (reversed) byte order; "
                f"the signed statement uses RPC/display order, {genesis} (spec 5.6)"
            )
    raise ValidationError(
        f"network_genesis {network_genesis} is not the genesis of any chain pyrxd knows "
        f"({', '.join(sorted(GENESIS_BLOCK_HASHES))}); a statement signed for it cannot be checked by "
        f"anyone on those chains. Pass allow_unknown_genesis=True only if you really are publishing "
        f"on another chain."
    )


def canonical_statement(record: HashMarkRecord, *, network_genesis: str = RADIANT_MAINNET_GENESIS) -> str:
    """The exact single-line JSON a v2 signature covers (§5.6).

    Fixed key order, no insignificant whitespace, and ``label`` OMITTED ENTIRELY
    when absent rather than included as an empty string — a different statement,
    and therefore a different signature.
    """
    if record.version != 2:
        raise ValidationError("only a v2 record carries a signed statement")
    parts = [
        f'"v":{_json_string("HashMark/v2")}',
        f'"network":{_json_string(network_genesis)}',
        f'"signerHash160":{_json_string(record.signer_hash160_hex or "")}',
        # The header byte as two lowercase hex digits, never a name: names acquire
        # aliases (sha256 / SHA-256 / sha-256) and a signature must not depend on
        # which spelling was in fashion.
        f'"algorithmId":{_json_string(f"{record.algorithm_id:02x}")}',
        f'"digest":{_json_string(record.digest_hex or "")}',
    ]
    if record.label is not None:
        parts.append(f'"label":{_json_string(record.label)}')
    return "{" + ",".join(parts) + "}"


def verify_attestation(record: HashMarkRecord, *, network_genesis: str = RADIANT_MAINNET_GENESIS) -> AttestationResult:
    """Recover the signer from a v2 signature and require it to match the commitment.

    The signer hash160 is committed TWICE — in the record and inside the signed
    statement — and both are required. Without a value fixed in advance to compare
    against, recovery is circular and proves nothing: an attacker would simply
    write whatever hash their chosen signature recovers to.

    Needs the chain's genesis hash, which is why this is not part of decoding: a
    dependency-free decoder does not have it, and the same bytes on another chain
    are a different statement.
    """
    from ..hash import hash160, hash256
    from ..utils import text_digest

    # secp256k1 lives behind `pyrxd.keys`, which imports `coincurve` at module top.
    # The browser inspect page runs pyrxd under Pyodide and installs only micropip
    # and pycryptodome, so this import RAISES there — and it used to raise straight
    # out of this function, which meant a HashMark output did not classify AT ALL in
    # the browser: the per-output try in `_inspect_core` caught it and the row
    # degraded to `type=error`. Verified by blocking `coincurve` with a meta-path
    # finder and calling `_inspect_script` on a real v2 record.
    #
    # §6 already says what should happen: "Decoding and attestation are SEPARATE
    # steps with separate outcomes. Decoding needs only these bytes; verifying a v2
    # signature additionally needs secp256k1 … which a decoder in a dependency-free
    # library will not have. A record that decodes is well-formed, not yet believed."
    #
    # So a missing curve is UNVERIFIABLE — the digest, label and signer still reach
    # the reader, and only the verdict is withheld, with the reason. Reporting
    # INVALID_SIGNATURE here would be far worse: it would tell a reader a genuine
    # mark's claim does not hold, on the strength of a missing dependency.
    # THE ANSWERS THAT NEED NO CURVE COME FIRST. A record that did not decode, and a v1
    # record, are decided by their bytes alone. They used to be decided AFTER the curve was
    # looked up — so with no backend and no coincurve every v1 record re-attempted the
    # import and came back NOT CHECKED, when the true answer (NO SIGNATURE) needs nothing.
    if not record.ok:
        return AttestationResult(AttestationOutcome.INVALID_SIGNATURE, detail="record did not decode")
    if record.version != 2 or not record.signature_hex or not record.signer_hash160_hex:
        return AttestationResult(AttestationOutcome.NOT_ATTESTED, detail="v1 record carries no signer")

    # A REGISTERED BACKEND WINS, and when there is one the coincurve import is not
    # attempted at all — under Pyodide it would only raise. See `set_recovery_backend`.
    backend = _recovery_backend if _recovery_backend is not None else _coincurve_backend()
    if isinstance(backend, str):
        return AttestationResult(
            AttestationOutcome.UNVERIFIABLE,
            detail=f"secp256k1 unavailable here, so the signature was not checked ({backend})",
        )

    # §6.3 step 3 makes "65 bytes" part of VERIFYING, not only of decoding, and this
    # function is public API: `decode_hashmark` enforces the length, but a caller doing
    # offline verification builds a `HashMarkRecord` from stored fields and reaches here
    # directly. Without the check a 33-byte value slices to an EMPTY s, which is int 0 —
    # a wrong-but-typed answer rather than a refusal — and malformed hex escaped as an
    # uncaught ValueError instead of one of this function's own outcomes.
    if not isinstance(record.signature_hex, str):
        return AttestationResult(
            AttestationOutcome.INVALID_SIGNATURE,
            detail=f"signature_hex is {type(record.signature_hex).__name__}, not a hex string",
        )
    try:
        sig = bytes.fromhex(record.signature_hex)
    except ValueError:
        return AttestationResult(AttestationOutcome.INVALID_SIGNATURE, detail="signature is not valid hex")
    if len(sig) != 65:
        return AttestationResult(
            AttestationOutcome.INVALID_SIGNATURE, detail=f"signature is {len(sig)} bytes, expected 65"
        )
    header, r_bytes, s_bytes = sig[0], sig[1:33], sig[33:65]

    # §5.6: header is 27 + recoveryId, +4 when the key is compressed; 27..34.
    if not 27 <= header <= 34:
        return AttestationResult(AttestationOutcome.INVALID_SIGNATURE, detail=f"header {header} outside 27..34")
    rec_id = (header - 27) & 3

    r, s_val = int.from_bytes(r_bytes, "big"), int.from_bytes(s_bytes, "big")
    if not 1 <= r < _SECP256K1_N:
        return AttestationResult(AttestationOutcome.INVALID_SIGNATURE, detail="r out of range")
    # LOW-S IS MANDATORY. It removes the s versus n-s malleability so a verifier
    # has one accepted form. It does NOT make signatures unique — a different
    # nonce yields different bytes for the same key and message — so an
    # attestation is identified by its statement and recovered signer, never by
    # these bytes.
    if not 1 <= s_val <= _SECP256K1_N // 2:
        return AttestationResult(AttestationOutcome.INVALID_SIGNATURE, detail="s is not low-S")

    # A HAND-BUILT RECORD GETS A VERDICT, NOT A TRACEBACK. `decode_hashmark` never produces a
    # field of the wrong type, but this function is public and an offline verifier builds the
    # record from stored fields: `algorithm_id=None` reached `f"{None:02x}"` in
    # `canonical_statement` and raised TypeError out of a function whose whole contract is
    # "return one of four outcomes". Checked HERE, where the statement is built — after §6.3's
    # signature checks, so a record whose signature is malformed is still told that first.
    field_defect = _statement_field_defect(record, network_genesis)
    if field_defect is not None:
        return AttestationResult(AttestationOutcome.INVALID_SIGNATURE, detail=field_defect)
    statement = canonical_statement(record, network_genesis=network_genesis)
    # §5.6: the header's +4 says the signer's hash160 was taken over the COMPRESSED
    # form. It selects how the recovered key is serialised before hashing; it is not
    # an input to the recovery, and swapping the two produces a wrong hash160 and a
    # confident DOES NOT VERIFY on an honest mark.
    compressed = header >= 31
    message = text_digest(statement)
    # ONE CALL SITE FOR BOTH CURVES. coincurve and a registered backend reach this
    # through the same signature, the same arguments and the same exception mapping,
    # so the only thing that can differ between the CLI and the browser is the
    # arithmetic itself — which is what `tests/test_signature_backend_differential.py`
    # pins. A second call shape here would be a second set of edges to get wrong.
    #
    # The backend is handed the ECDSA `z`, not the preimage: a backend that is not
    # coincurve has no `hasher=` argument to be told about, and "already hashed" is
    # the one thing about this call a JavaScript implementation can get wrong in a
    # way that still returns a key.
    try:
        public_key = backend(hash256(message), r_bytes, s_bytes, rec_id, compressed)
    except RecoveryUnavailable as exc:
        # NOT a verdict. The backend could not run; the record is untouched by that,
        # and telling a reader an honest mark's claim does not hold on the strength of
        # a broken verifier is the worst outcome this function has.
        return AttestationResult(
            AttestationOutcome.UNVERIFIABLE,
            detail=f"the signature was not checked here: {exc}",
        )
    except Exception as exc:
        return AttestationResult(AttestationOutcome.INVALID_SIGNATURE, detail=f"recovery failed: {exc}")

    # THE BACKEND'S ANSWER IS CHECKED HERE, NOT TRUSTED. A registered backend is process-global
    # and wins over coincurve, and the only thing this function does with its return is hash it
    # — so ANY 33 bytes whose hash160 equals the committed signer used to make the record VALID,
    # whether or not they were a public key, and whether or not they were in the form `compressed`
    # asked for. The glue that installs the browser's backend checks the length too; this is the
    # same rule at the one place every backend's answer passes, including one that forgot.
    #
    # A wrong SHAPE is a broken verifier, never a verdict on the record: a correct backend always
    # returns the form it was asked for, so the honest reading is "not checked here". Reporting
    # INVALID_SIGNATURE would accuse an honest signer on the strength of a bad backend.
    shape_defect = _public_key_shape_defect(public_key, compressed=compressed)
    if shape_defect is not None:
        return AttestationResult(
            AttestationOutcome.UNVERIFIABLE,
            detail=f"the signature was not checked here: the recovery backend returned {shape_defect}",
        )
    recovered = hash160(bytes(public_key)).hex()

    if recovered != record.signer_hash160_hex:
        return AttestationResult(
            AttestationOutcome.INVALID_SIGNATURE,
            recovered_hash160_hex=recovered,
            detail="recovered key does not match the committed signer",
        )
    return AttestationResult(AttestationOutcome.VALID, recovered_hash160_hex=recovered)


# ---------------------------------------------------------------------------
# Encoding — the WRITE side.
#
# Written from HASHMARK_PROTOCOL.md alone, like the decoder above, and for the
# same reason: `tests/test_hashmark_encoder.py` runs the reference TypeScript
# decoder over records this function produced, and that proof is worth nothing
# if both sides came from the same reading of the same source. The upstream
# commit is pinned in `tests/fixtures/hashmark_upstream_pin.json`.
#
# A spec that moves under a decoder is a quiet problem. A spec that moves under
# an ENCODER puts wrong bytes on chain under someone's signature, permanently.
# ---------------------------------------------------------------------------

#: The only version pyrxd writes (§4). See the module docstring for why not v1.
_ENCODER_VERSION = 2


def max_label_bytes(algorithm_id: int = 0x01) -> int:
    """The v2 label cap in BYTES for *algorithm_id*, derived per §5.4 (88 for sha256).

    Public because it is a number a caller has to show a user BEFORE they type a
    label — "up to 88 bytes" is useful, "your label was rejected" after the fact
    is not. Derived from the record ceiling rather than tabulated, so registering
    a longer digest shrinks the label visibly instead of silently producing
    records that stop relaying.
    """
    if algorithm_id not in _ALGORITHMS:
        raise ValidationError(f"algorithm id {algorithm_id:#04x} is not implemented")
    return _max_label_bytes(_ALGORITHMS[algorithm_id][1])


def algorithm_for(algorithm_id: int = 0x01) -> str:
    """The hash algorithm *algorithm_id* names (§5.3), or raise if unimplemented.

    Public because whoever is about to mark a file has to run the right hash over it,
    and the only authority on which one that is is the table the encoder writes into the
    record's header byte. A caller that spells ``"sha256"`` itself has created a second
    source of truth for what a record CLAIMS versus what was actually hashed, and
    nothing downstream can detect the disagreement: both halves are well-formed, the
    signature verifies, and the record is simply false.

    The name is the one :mod:`hashlib` knows, which is what makes
    :func:`pyrxd.hashmark_tx.digest_file` able to derive its hasher from the id rather
    than from a second table.
    """
    if algorithm_id not in _ALGORITHMS:
        raise ValidationError(f"algorithm id {algorithm_id:#04x} is not implemented")
    return _ALGORITHMS[algorithm_id][0]


def canonicalize_label(label: str) -> str:
    """The canonical spelling of *label* per §5.4 — trimmed and NFC — or raise.

    §5.4 makes this an encoder obligation: "Encoders must trim leading and
    trailing whitespace and normalize to Unicode NFC before measuring, signing
    and writing, and must show the user the resulting canonical label, because
    that is what will be published."

    It is DELIBERATELY not folded into :func:`encode_hashmark`, which refuses a
    non-canonical label instead. A library function cannot "show the user"
    anything, and in v2 the label is inside the signed statement — so an encoder
    that silently trimmed would sign a string its caller never saw. Splitting it
    means the transformation happens where a human can be shown the result, and
    the signing path only ever handles a label that is already final.

    Rejected codepoints (§5.4's table) are refused BEFORE trimming rather than
    after. Python's ``str.strip()`` treats U+2028 and U+2029 as whitespace, so
    trimming first would silently swallow a line separator sitting at either
    end — a codepoint the spec lists precisely because it hides what is
    rendered. Refusing costs a caller one edit; swallowing costs a reader the
    truth.
    """
    for ch in label:
        cp = ord(ch)
        if cp in _LABEL_REJECTED_CHARS or any(lo <= cp <= hi for lo, hi in _LABEL_REJECTED_RANGES):
            return _raise_label(f"contains U+{cp:04X}")
    canonical = unicodedata.normalize("NFC", label.strip())
    if not canonical:
        # A label that trims away to nothing is not a label. §5.4: "An empty
        # label is not representable. Omit the push entirely rather than writing
        # a zero-length one." Returning "" here would hand a caller a string to
        # show the user and then refuse it one call later, which reads as a bug
        # in the encoder rather than as an answer about the label.
        raise ValidationError(
            "label is only whitespace, so its canonical form is empty and not "
            "representable (spec 5.4) — omit the label instead"
        )
    # Belt: the decoder's own predicate is the authority on what "canonical"
    # means, so assert against IT rather than trusting that the two steps above
    # are the whole of §5.4. If someone adds a rule to `_label_defect` and not
    # here, this raises instead of writing a label the decoder will reject.
    defect = _label_defect(canonical)
    if defect is not None:
        return _raise_label(f"{defect}, and canonicalising did not fix it")
    return canonical


def _raise_label(defect: str) -> NoReturn:
    raise ValidationError(f"label {defect} (HashMark 5.4)")


def _minimal_push(data: bytes) -> bytes:
    """One minimally-encoded data push (§4.1), never ``OP_0``.

    ``encode_data_push`` returns ``OP_0`` for an empty payload, which §4.1
    explicitly rejects — it would give a field a second spelling. No HashMark
    field is ever empty (an absent label is no push at all, not a zero-length
    one), so an empty payload here is a bug in the caller, and refusing it is
    what stops that bug reaching the one thing §4.1 exists to guarantee: every
    record has exactly one valid serialization.
    """
    from ..utils import encode_data_push

    if not data:
        raise ValidationError("a HashMark push is never empty (spec 4.1 rejects OP_0)")
    return encode_data_push(data)


def encode_hashmark(
    digest: bytes,
    private_key: PrivateKey,
    *,
    label: str | None = None,
    algorithm_id: int = 0x01,
    network_genesis: str = RADIANT_MAINNET_GENESIS,
    allow_unknown_genesis: bool = False,
) -> bytes:
    """Build a signed v2 HashMark ``scriptPubKey`` committing to *digest*.

    :param digest: the raw digest bytes. Its length must equal the width
        *algorithm_id* declares (§5.3) — a 31-byte sha256 digest is refused
        here, not padded.
    :param private_key: the key that makes the statement. Its ``compressed``
        flag drives BOTH the committed ``hash160`` and the signature header's
        compression bit; they are read from one local so they cannot diverge,
        because a record whose header disagrees with its commitment recovers a
        different key and can never verify.
    :param label: an optional public caption, already canonical — pass it
        through :func:`canonicalize_label` first and show the user the result.
    :param network_genesis: the genesis hash of the chain this will be
        broadcast to, in RPC/display order. It is NOT carried by the record: it
        is part of the signed statement, so the same bytes on another chain make
        a different statement and will not verify there (§5.6, §2.10). Defaulting
        to mainnet is deliberate — a testnet mark must be an explicit act. Must be
        64 lowercase hex and the genesis of a chain pyrxd knows; see
        :func:`_require_signable_genesis` for why each is refused rather than signed.
    :param allow_unknown_genesis: sign for a well-formed genesis pyrxd has no
        constant for (a chain other than mainnet, testnet or regtest). Relaxes the
        known-chain rule only, never the spelling.

    The label is **permanently public** and the signature permanently links this
    mark to that key and to every other mark it signed (§5.4, §14.1). A caller
    with a user in front of it must say so before this is broadcast.
    """
    # FIRST, before anything is signed. The sign-then-verify below cannot catch a wrong
    # genesis: it verifies against the same string it signed, so it is circular for exactly
    # this field.
    _require_signable_genesis(network_genesis, allow_unknown_genesis=allow_unknown_genesis)
    if algorithm_id not in _ALGORITHMS:
        raise ValidationError(f"algorithm id {algorithm_id:#04x} is not implemented")
    algorithm, digest_len = _ALGORITHMS[algorithm_id]
    if len(digest) != digest_len:
        raise ValidationError(f"{algorithm} digest is {len(digest)} bytes, expected {digest_len} (spec 5.3)")

    if label is not None:
        # §5.4: an empty label is not representable. Omitting the push is the
        # spec's answer, but doing that silently would publish an unlabelled
        # mark to a caller who believes they labelled it — and in v2 the absent
        # label is a DIFFERENT signed statement. So refuse and say so.
        if not label:
            raise ValidationError("an empty label is not representable (spec 5.4) — omit the label instead")
        defect = _label_defect(label)
        if defect is not None:
            raise ValidationError(
                f"label {defect} (spec 5.4) — canonicalize_label() gives the spelling that can be signed"
            )
        cap = _max_label_bytes(digest_len)
        encoded_label = label.encode("utf-8")
        if len(encoded_label) > cap:
            # Bytes, not characters: §5.4's own example is a 43-character emoji
            # string that occupies 172 bytes.
            raise ValidationError(
                f"label is {len(encoded_label)} UTF-8 bytes, over the {cap}-byte cap for "
                f"{algorithm} (spec 5.4); it is {len(label)} characters"
            )

    # ORDER IS FORCED. The signed statement contains the signer hash160 (§5.5:
    # committed twice, in the record and inside the statement), so the key's
    # hash must exist before the statement, and the statement before the
    # signature that goes in the record.
    compressed = private_key.compressed
    signer = private_key.public_key().hash160(compressed)
    unsigned = HashMarkRecord(
        HashMarkOutcome.OK,
        version=_ENCODER_VERSION,
        algorithm_id=algorithm_id,
        algorithm=algorithm,
        digest_hex=digest.hex(),  # .hex() is lowercase; §5.3's one accepted spelling
        label=label,
        signer_hash160_hex=signer.hex(),
    )
    signature = _sign_statement(
        canonical_statement(unsigned, network_genesis=network_genesis), private_key, compressed=compressed
    )

    record = HashMarkRecord(
        HashMarkOutcome.OK,
        version=unsigned.version,
        algorithm_id=unsigned.algorithm_id,
        algorithm=unsigned.algorithm,
        digest_hex=unsigned.digest_hex,
        label=unsigned.label,
        signer_hash160_hex=unsigned.signer_hash160_hex,
        signature_hex=signature.hex(),
    )

    # SIGN, THEN VERIFY — through the very function a stranger will run (§6.3),
    # not a re-derivation of it. Everything above is one-way: a wrong recovery
    # id, a header whose compression bit disagrees with the committed hash, a
    # curve that stopped normalising s. None of those raises, all of them
    # produce a well-formed record whose claim does not hold, and on chain that
    # is permanent. The check costs one key recovery.
    attested = verify_attestation(record, network_genesis=network_genesis)
    if not attested.valid:
        raise ValidationError(
            f"refusing to emit a record whose own signature does not verify: "
            f"{attested.outcome.value} ({attested.detail})"
        )

    script = bytes([_OP_RETURN]) + b"".join(
        _minimal_push(push)
        for push in (
            HASHMARK_MAGIC,
            bytes([_ENCODER_VERSION, algorithm_id]),
            digest,
            signer,
            signature,
            *([label.encode("utf-8")] if label is not None else []),
        )
    )

    # §3.2: the whole-record ceiling, checked over the ASSEMBLED bytes. The label
    # cap above is derived from this number, so for sha256 this cannot fire on a
    # label that passed — but it is the one place every field's cost is actually
    # summed, so a future algorithm or field lands here rather than on a node.
    if len(script) > _MAX_RECORD_BYTES:
        raise ValidationError(f"record is {len(script)} bytes, over the {_MAX_RECORD_BYTES}-byte ceiling (spec 3.2)")
    return script


def _sign_statement(statement: str, private_key: PrivateKey, *, compressed: bool) -> bytes:
    """The 65-byte ``header || r || s`` of §5.6 over *statement*.

    ``stringify_ecdsa_recoverable`` is the one place in pyrxd that knows the
    header byte is ``27 + recoveryId (+4 if compressed)``; it happens to emit
    base64, which §5.6 does not use, so the base64 is undone rather than the
    header arithmetic re-typed here. Two spellings of that byte is exactly how
    an encoder and a verifier drift apart.
    """
    from base64 import b64decode

    from ..utils import stringify_ecdsa_recoverable, text_digest

    signature = b64decode(stringify_ecdsa_recoverable(private_key.sign_recoverable(text_digest(statement)), compressed))
    if len(signature) != 65:  # pragma: no cover - structurally impossible, asserted anyway
        raise ValidationError(f"signature is {len(signature)} bytes, expected 65 (spec 5.6)")

    # §5.6's own range rules, applied to what we are about to WRITE. libsecp256k1
    # normalises s, so honest signatures already satisfy this — which is the
    # point: if it ever fires, the curve binding changed under us and the record
    # would be rejected by every conforming verifier.
    header, r, s = signature[0], int.from_bytes(signature[1:33], "big"), int.from_bytes(signature[33:65], "big")
    if not 27 <= header <= 34:
        raise ValidationError(f"signature header {header} outside 27..34 (spec 5.6)")
    if not 1 <= r < _SECP256K1_N:
        raise ValidationError("signature r out of range (spec 5.6)")
    if not 1 <= s <= _SECP256K1_N // 2:
        raise ValidationError("signature is not low-S (spec 5.6) — every conforming verifier would reject it")
    return signature
