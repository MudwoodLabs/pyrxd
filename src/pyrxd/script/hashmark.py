"""Decode HashMark records — a THIRD-PARTY ``OP_RETURN`` format on Radiant.

HashMark records a file's digest on chain so anyone can later prove the file
existed no later than the block that confirmed the transaction. It is not ours:
the protocol and its reference implementation are by a Radiant contributor,
MIT-licensed, and specified in ``HASHMARK_PROTOCOL.md`` at
https://github.com/cdonnachie/hashmark.rxd — written, in its own words, "so that
a developer with no access to the HashMark codebase can implement a complete,
independent verifier".

This module is that independent implementation, for the READ side only. pyrxd
never writes a HashMark.

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
from dataclasses import dataclass
from enum import Enum

from ..constants import OpCode
from ..security.errors import ValidationError
from .script import data_pushes_after_op_return

__all__ = [
    "HASHMARK_MAGIC",
    "RADIANT_MAINNET_GENESIS",
    "AttestationOutcome",
    "AttestationResult",
    "HashMarkOutcome",
    "HashMarkRecord",
    "canonical_statement",
    "decode_hashmark",
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


class AttestationOutcome(Enum):
    """Whether a decoded v2 record's signature actually holds."""

    VALID = "valid"
    INVALID_SIGNATURE = "invalid_signature"
    #: v1 carries no signer, so there is nothing to attest. Not a failure — v1
    #: never claimed to say WHO, only WHEN.
    NOT_ATTESTED = "not_attested"


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
    from ..keys import recover_public_key
    from ..utils import text_digest

    if not record.ok:
        return AttestationResult(AttestationOutcome.INVALID_SIGNATURE, detail="record did not decode")
    if record.version != 2 or not record.signature_hex or not record.signer_hash160_hex:
        return AttestationResult(AttestationOutcome.NOT_ATTESTED, detail="v1 record carries no signer")

    # §6.3 step 3 makes "65 bytes" part of VERIFYING, not only of decoding, and this
    # function is public API: `decode_hashmark` enforces the length, but a caller doing
    # offline verification builds a `HashMarkRecord` from stored fields and reaches here
    # directly. Without the check a 33-byte value slices to an EMPTY s, which is int 0 —
    # a wrong-but-typed answer rather than a refusal — and malformed hex escaped as an
    # uncaught ValueError instead of one of this function's own outcomes.
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

    statement = canonical_statement(record, network_genesis=network_genesis)
    try:
        pub = recover_public_key(r_bytes + s_bytes + bytes([rec_id]), text_digest(statement), hasher=hash256)
        recovered = hash160(pub.serialize(compressed=header >= 31)).hex()
    except Exception as exc:
        return AttestationResult(AttestationOutcome.INVALID_SIGNATURE, detail=f"recovery failed: {exc}")

    if recovered != record.signer_hash160_hex:
        return AttestationResult(
            AttestationOutcome.INVALID_SIGNATURE,
            recovered_hash160_hex=recovered,
            detail="recovered key does not match the committed signer",
        )
    return AttestationResult(AttestationOutcome.VALID, recovered_hash160_hex=recovered)
