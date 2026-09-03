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
    #: v2 only: hash160 of the key that signed. NOT verified here.
    signer_hash160_hex: str | None = None
    #: v2 only: 65-byte compact recoverable signature. NOT verified here.
    signature_hex: str | None = None
    detail: str | None = None

    @property
    def ok(self) -> bool:
        return self.outcome is HashMarkOutcome.OK


def decode_hashmark(script: bytes) -> HashMarkRecord:
    """Decode a ``scriptPubKey`` as a HashMark record.

    Never returns a partial or best-effort result — the outcome is one of the
    five in :class:`HashMarkOutcome`, and a caller must branch on it.
    """
    if not script or script[0] != _OP_RETURN:
        return HashMarkRecord(HashMarkOutcome.NOT_HASHMARK)

    pushes = data_pushes_after_op_return(script)
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
    if len(pushes) == expected[1]:
        raw = pushes[-1]
        cap = 128 if version == 1 else 223
        if not raw or len(raw) > cap:
            return HashMarkRecord(
                HashMarkOutcome.INVALID, version=version, detail=f"label is {len(raw)} bytes, expected 1..{cap}"
            )
        try:
            label = raw.decode("utf-8")
        except UnicodeDecodeError:
            return HashMarkRecord(HashMarkOutcome.INVALID, version=version, detail="label is not valid UTF-8")

    return HashMarkRecord(
        HashMarkOutcome.OK,
        version=version,
        algorithm_id=algorithm_id,
        algorithm=name,
        digest_hex=digest.hex(),  # .hex() is lowercase; the one accepted spelling
        label=label,
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

    sig = bytes.fromhex(record.signature_hex)
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
