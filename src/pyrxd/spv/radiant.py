"""Radiant header and merkle-branch primitives — beside the Bitcoin ones, not replacing them.

Everything else in :mod:`pyrxd.spv` is **Bitcoin**: :func:`pyrxd.spv.pow.verify_header_pow` hashes
a header with SHA-256d, which is Bitcoin's block hash. Radiant's block hash, and the hash its
proof-of-work is judged on, is a double **SHA-512/256** (:func:`pyrxd.hash.radiant_block_hash`).
Measured on real mainnet headers 460,570-460,574: every one meets its own nBits target under
SHA-512/256d, and none does under SHA-256d. Feeding a Radiant header to the Bitcoin check refuses
every honest header; feeding a Bitcoin header here does the same. The two are deliberately separate
functions, and this module does not touch the Bitcoin path.

What IS shared: a Radiant block's TRANSACTION merkle tree is SHA-256d over txids, exactly like
Bitcoin's (folding a live ``blockchain.transaction.get_merkle`` branch from the txid reproduced
``header[36:68]`` for two real mainnet marks on both shipped servers), so
:func:`pyrxd.spv.merkle.verify_tx_in_block` is reused for inclusion as-is.

What this module does NOT do: it does not check that an nBits value is the one Radiant's
difficulty algorithm requires at that height. Radiant retargets every block (17 consecutive
mainnet headers carry 17 distinct nBits), and its difficulty algorithm is not vendored here, so
each header is checked only against ITS OWN stated target. A caller that needs more than "this
header cost about ``2**256 / target`` hash evaluations" must bound the target itself — see
:mod:`pyrxd.glyph.mark_block`, which does so with a floor.

Import-light on purpose (stdlib, :mod:`pyrxd.hash`, :mod:`pyrxd.security`): the browser pages run
under Pyodide, where ``pyrxd.network`` cannot be imported.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from pyrxd.hash import radiant_block_hash
from pyrxd.security.errors import NetworkError, SpvVerificationError, ValidationError
from pyrxd.security.json_guards import hex_str, merkle_branch, nonneg_int
from pyrxd.security.types import BlockHeight, Nbits

__all__ = [
    "MAX_BLOCK_HEADERS_PER_CALL",
    "MAX_MERKLE_DEPTH",
    "RADIANT_HEADER_LEN",
    "TxMerkleBranch",
    "block_headers_from_reply",
    "coinbase_branch_from_reply",
    "merkle_branch_from_reply",
    "radiant_header_prev_hash",
    "radiant_header_target",
    "radiant_header_work",
    "verify_radiant_header_pow",
]

RADIANT_HEADER_LEN = 80

#: Deepest tx merkle branch accepted: 2**32 transactions in one block. A bound, not a model —
#: it exists so a server cannot hand a verifier an unbounded list to hash.
MAX_MERKLE_DEPTH = 32

#: ElectrumX's ``blockchain.block.headers`` serves at most this many headers per call.
MAX_BLOCK_HEADERS_PER_CALL = 2016

_HEX64 = re.compile(r"\A[0-9a-fA-F]{64}\Z")
_HEX_DIGITS = re.compile(r"\A[0-9a-fA-F]*\Z")


def _require_header(header: Any) -> bytes:
    if not isinstance(header, (bytes, bytearray)) or len(header) != RADIANT_HEADER_LEN:
        raise ValidationError(f"a Radiant block header is exactly {RADIANT_HEADER_LEN} bytes")
    return bytes(header)


def radiant_header_prev_hash(header: bytes) -> str:
    """The previous block's hash that *header* commits to, in display (big-endian) hex."""
    return _require_header(header)[4:36][::-1].hex()


def _require_pow_limit(pow_limit: Any) -> int:
    if not isinstance(pow_limit, int) or isinstance(pow_limit, bool) or not 0 < pow_limit < (1 << 256):
        raise ValidationError("pow_limit must be an int in 1..2**256-1")
    return pow_limit


def radiant_header_target(header: bytes, *, pow_limit: int | None = None) -> int:
    """The target *header*'s own nBits states, as an integer.

    With no *pow_limit* (the default, and what the HashMark pages and ``pyrxd verify`` use), the
    nBits encoding is validated with :class:`pyrxd.security.types.Nbits` first (refuses a zero
    mantissa, the sign bit, and an exponent above ``0x1d``). Raises ``ValidationError`` for a
    malformed nBits or a target that decodes to zero.

    With a *pow_limit* (a network's ``consensus.powLimit``, from
    :mod:`pyrxd.gravity.funding_spv`), the decode follows Radiant Core's own rule instead:
    ``arith_uint256::SetCompact``'s negative and overflow tests, then ``CheckProofOfWork``'s
    ``bnTarget == 0 || bnTarget > powLimit`` refusal (both inherited from Bitcoin Core; ``pow.cpp``
    and ``arith_uint256.cpp`` are not vendored). The exponent cap above cannot be used there:
    regtest's own genesis states ``0x207fffff`` (``tests/vendor/radiant_core/chainparams.cpp``),
    which that cap refuses although Radiant Core accepts it.
    """
    raw = _require_header(header)[72:76]
    exponent = raw[3]
    mantissa = int.from_bytes(raw[0:3], "little")
    if pow_limit is None:
        Nbits(raw)
    else:
        _require_pow_limit(pow_limit)
        word = mantissa & 0x007FFFFF
        if word != 0 and mantissa & 0x00800000:
            raise ValidationError("nBits states a negative target")
        if word != 0 and (exponent > 34 or (word > 0xFF and exponent > 33) or (word > 0xFFFF and exponent > 32)):
            raise ValidationError("nBits overflows a 256-bit target")
        mantissa = word
    if exponent <= 3:
        target = mantissa >> (8 * (3 - exponent))
    else:
        target = mantissa << (8 * (exponent - 3))
    if target == 0:
        raise ValidationError("nBits decodes to a zero target")
    if pow_limit is not None and target > pow_limit:
        raise ValidationError("nBits states a target above this network's proof-of-work limit")
    return target


def radiant_header_work(header: bytes, *, pow_limit: int | None = None) -> int:
    """Expected hash evaluations to find a header at *header*'s own target: ``2**256 // (target+1)``.

    The same quantity Bitcoin Core's ``GetBlockProof`` computes. It is the work the header's own
    nBits CLAIMS; only :func:`verify_radiant_header_pow` shows the header actually meets it.
    *pow_limit* is as for :func:`radiant_header_target`.
    """
    return (1 << 256) // (radiant_header_target(header, pow_limit=pow_limit) + 1)


def verify_radiant_header_pow(header: bytes, *, pow_limit: int | None = None) -> str:
    """Check *header*'s SHA-512/256d hash is at or below its own nBits target.

    Returns the block hash in display hex. Raises ``ValidationError`` for a header that is not 80
    bytes or carries a malformed nBits, and ``SpvVerificationError`` when the hash is above the
    target. ``hash <= target`` passes: that is Bitcoin Core's ``CheckProofOfWork`` rule, which
    Radiant Core inherits (assumed from lineage; ``pow.cpp`` is not vendored). Equality has
    probability about 2**-56 at today's mainnet difficulty, so the choice changes nothing in practice.

    Proves only that the header cost about :func:`radiant_header_work` hash evaluations. It does not
    prove the nBits is the value Radiant's rules require, nor that the header is on any chain.
    *pow_limit* is as for :func:`radiant_header_target`.
    """
    target = radiant_header_target(header, pow_limit=pow_limit)
    block_hash = radiant_block_hash(_require_header(header))
    if int(block_hash, 16) > target:
        raise SpvVerificationError("Radiant header proof-of-work invalid: hash is above its nBits target")
    return block_hash


@dataclass(frozen=True)
class TxMerkleBranch:
    """A transaction's merkle branch as ElectrumX's ``blockchain.transaction.get_merkle`` gives it.

    ``branch`` holds the sibling hashes from the leaf upward, in display (big-endian) hex, one per
    tree level; ``pos`` is the transaction's index in the block. Construction validates the SHAPE
    only: each sibling is 32 bytes of hex, ``len(branch) <= MAX_MERKLE_DEPTH``, and
    ``0 <= pos < 2**len(branch)`` — a larger ``pos`` does not name a leaf of a tree that deep; it
    ALIASES a smaller one (``pos = 2**depth`` walks the coinbase's branch). Whether the branch
    leads to any particular header's merkle root is not checked here.

    ``pos == 0`` (the coinbase) is a well-formed branch and is accepted; refusing it is a policy
    for the verifier that consumes it, not a property of the shape.
    """

    block_height: int
    branch: tuple[str, ...]
    pos: int

    def __post_init__(self) -> None:
        h = self.block_height
        if not isinstance(h, int) or isinstance(h, bool) or h < 0 or h > BlockHeight.MAX:
            raise ValidationError(f"merkle block_height must be an int in 0..{BlockHeight.MAX}")
        if not isinstance(self.branch, tuple):
            raise ValidationError("merkle branch must be a tuple of hashes")
        if len(self.branch) > MAX_MERKLE_DEPTH:
            raise ValidationError(f"merkle branch deeper than {MAX_MERKLE_DEPTH} levels")
        for i, sibling in enumerate(self.branch):
            if not isinstance(sibling, str) or not _HEX64.match(sibling):
                raise ValidationError(f"merkle branch entry {i} is not a 32-byte hex hash")
        p = self.pos
        if not isinstance(p, int) or isinstance(p, bool) or p < 0:
            raise ValidationError("merkle pos must be a non-negative int")
        if p >> len(self.branch):
            raise ValidationError(
                f"merkle pos {p} is out of range for a branch of depth {len(self.branch)} "
                "(it would alias another leaf's branch)"
            )

    @classmethod
    def from_electrumx(cls, result: Any) -> TxMerkleBranch:
        """Parse a raw ``blockchain.transaction.get_merkle`` result. Raises ``ValidationError``."""
        if not isinstance(result, dict):
            raise ValidationError(f"merkle reply must be an object, got {type(result).__name__}")
        try:
            height = result["block_height"]
            branch = result["merkle"]
            pos = result["pos"]
        except KeyError as exc:
            raise ValidationError(f"merkle reply is missing {exc.args[0]!r}") from None
        if not isinstance(branch, list):
            raise ValidationError(f"merkle branch must be a list, got {type(branch).__name__}")
        if len(branch) > MAX_MERKLE_DEPTH:
            raise ValidationError(f"merkle branch deeper than {MAX_MERKLE_DEPTH} levels")
        normalised = tuple(s.lower() if isinstance(s, str) else s for s in branch)
        return cls(block_height=height, branch=normalised, pos=pos)


# ── ElectrumX replies, read ONCE ─────────────────────────────────────────────────────────────
#
# The three RPCs a block proof needs, read here rather than inside ``ElectrumXClient``, because two
# callers read them: the client (``pyrxd verify``) and the browser pages' ``glue.verify_mark_block``,
# which cannot import ``pyrxd.network`` under Pyodide. One reader means a malformed reply is refused
# with the same words on both surfaces, so the reason a reader sees for "not verified" is the same
# sentence whichever of them asked. Each raises ``NetworkError`` — a fact about the server's reply.


def merkle_branch_from_reply(result: Any, height: int) -> TxMerkleBranch:
    """A ``blockchain.transaction.get_merkle`` reply for block *height*, shape-validated.

    Raises ``NetworkError`` for a malformed reply, or a proof for another block than *height*:
    ElectrumX echoes ``block_height``, and without binding it the server chooses which block it
    proves inclusion in. Not checked against any header here.
    """
    # ElectrumX returns {"block_height": N, "merkle": [...], "pos": N}
    if not isinstance(result, dict):
        raise NetworkError("Unexpected response type for transaction merkle")
    try:
        # `merkle` had NO type check: a JSON string passed through as "the branch", and
        # iterating "deadbeef" yields eight one-character "hashes". `pos` had no sign check
        # and both int() calls could raise OverflowError on a JSON `Infinity` — a class
        # absent from the tuple below, so it escaped past every `except NetworkError`.
        block_height = BlockHeight(nonneg_int(result["block_height"]))
        merkle_hashes: list[str] = merkle_branch(result["merkle"])
        pos: int = nonneg_int(result["pos"])
        branch = TxMerkleBranch(
            block_height=int(block_height),
            branch=tuple(h.lower() for h in merkle_hashes),
            pos=pos,
        )
    except (KeyError, TypeError, ValueError, OverflowError, ValidationError):
        raise NetworkError("Malformed merkle response from server") from None
    if branch.block_height != int(height):
        raise NetworkError(
            f"merkle proof is for block {branch.block_height}, not the requested {int(height)}; fail-closed"
        )
    return branch


def block_headers_from_reply(result: Any, count: int) -> list[bytes]:
    """A ``blockchain.block.headers`` reply to a request for *count* headers, as 80-byte headers.

    The server answers ``{"count": n, "hex": ..., "max": ...}``; ``n`` may be SMALLER than asked
    when the range runs past its tip, and that is honest, so fewer headers come back. Refused, with
    ``NetworkError``: a reply that is not an object, an echoed ``count`` that is not a non-negative
    int or is larger than asked, a ``hex`` that is not a string of hex digits exactly ``160 * n``
    long. What the headers say (linkage, proof-of-work) is not checked here.
    """
    if not isinstance(result, dict):
        raise NetworkError("Unexpected response type for block headers")
    try:
        served = nonneg_int(result.get("count"))
    except (TypeError, ValueError, OverflowError):
        raise NetworkError("Malformed block headers response: no usable count") from None
    if served > count:
        raise NetworkError(f"server returned {served} block headers when {count} were asked for; fail-closed")
    hex_blob = result.get("hex")
    if not isinstance(hex_blob, str) or len(hex_blob) != 160 * served or not _HEX_DIGITS.match(hex_blob):
        raise NetworkError(f"Malformed block headers response: hex is not {served} 80-byte headers")
    raw = bytes.fromhex(hex_blob)
    return [raw[i * 80 : (i + 1) * 80] for i in range(served)]


def coinbase_branch_from_reply(result: Any) -> dict[str, Any]:
    """A ``blockchain.transaction.id_from_pos(height, pos, true)`` reply, shape-validated.

    Returns ``{"tx_hash": <64 lowercase hex>, "merkle": [<64 lowercase hex>, ...]}``. Raises
    ``NetworkError`` for a reply that is not an object, a ``tx_hash`` that is not 32 bytes of hex,
    or a ``merkle`` that is not a list of at most :data:`MAX_MERKLE_DEPTH` 32-byte hex hashes. Not
    checked against any header here.
    """
    if not isinstance(result, dict):
        raise NetworkError("Unexpected response type for transaction id_from_pos")
    try:
        tx_hash = hex_str(result["tx_hash"], nbytes=32)
        branch = merkle_branch(result["merkle"])
    except (KeyError, TypeError, ValueError):
        raise NetworkError("Malformed id_from_pos response from server") from None
    if len(branch) > MAX_MERKLE_DEPTH:
        raise NetworkError(f"id_from_pos merkle branch is deeper than {MAX_MERKLE_DEPTH} levels; fail-closed")
    return {"tx_hash": tx_hash.lower(), "merkle": [h.lower() for h in branch]}
