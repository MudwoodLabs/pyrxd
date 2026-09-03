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
from .script import Script

__all__ = [
    "HASHMARK_MAGIC",
    "HashMarkOutcome",
    "HashMarkRecord",
    "decode_hashmark",
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


def _pushes(script: bytes) -> list[bytes] | None:
    """Every push after the leading ``OP_RETURN``, or None if the script is not
    cleanly push-only from offset 1.

    Returns None rather than raising: at this point no magic has been seen, so
    the output has not yet claimed to be a HashMark and a parse failure means
    "some other protocol", not "a broken HashMark".
    """
    # allow_malformed: a truncated push must set truncated_at rather than raise.
    # The spec is explicit that a bad push BEFORE the magic is NOT_HASHMARK — no
    # HashMark claim has been made yet — and the inspector's contract allows only
    # ValidationError to escape. Raising here did both wrong; the fuzzer caught it.
    parsed = Script(script[1:], allow_malformed=True)
    if parsed.truncated_at is not None:
        return None
    out: list[bytes] = []
    for chunk in parsed.chunks:
        op = chunk.op[0] if isinstance(chunk.op, bytes) else chunk.op
        if op > 0x4B:  # not a direct/PUSHDATA data push
            return None
        out.append(chunk.data or b"")
    return out


def decode_hashmark(script: bytes) -> HashMarkRecord:
    """Decode a ``scriptPubKey`` as a HashMark record.

    Never returns a partial or best-effort result — the outcome is one of the
    five in :class:`HashMarkOutcome`, and a caller must branch on it.
    """
    if not script or script[0] != _OP_RETURN:
        return HashMarkRecord(HashMarkOutcome.NOT_HASHMARK)

    pushes = _pushes(script)
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
