"""SpvProof aggregate and SpvProofBuilder.

An ``SpvProof`` is only constructible via ``SpvProofBuilder.build()``, which
runs every verifier before returning. The builder requires a complete
``CovenantParams`` up front -- this is the audit 05-F-2 / F-3 fix: SPV
proofs are always bound to the specific covenant they'll satisfy.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from pyrxd.security.errors import SpvVerificationError, ValidationError

from .chain import verify_chain
from .merkle import build_branch, compute_root, extract_merkle_root, verify_tx_in_block
from .payment import P2PKH, P2SH, P2TR, P2WPKH, verify_payment
from .pow import hash256
from .witness import strip_witness

__all__ = ["CovenantParams", "SpvProof", "SpvProofBuilder"]

_BUILDER_TOKEN = object()  # unforgeable sentinel; SpvProof.__post_init__ checks for it

_VALID_RECEIVE_TYPES = frozenset({P2PKH, P2WPKH, P2SH, P2TR})


def _read_varint(buf: bytes, pos: int) -> tuple[int, int]:
    """Read a Bitcoin CompactSize varint at ``pos``; return (value, next_pos)."""
    if pos >= len(buf):
        raise SpvVerificationError("varint read past end of tx")
    first = buf[pos]
    if first < 0xFD:
        return first, pos + 1
    if first == 0xFD:
        if pos + 3 > len(buf):
            raise SpvVerificationError("truncated 2-byte varint")
        return int.from_bytes(buf[pos + 1 : pos + 3], "little"), pos + 3
    if first == 0xFE:
        if pos + 5 > len(buf):
            raise SpvVerificationError("truncated 4-byte varint")
        return int.from_bytes(buf[pos + 1 : pos + 5], "little"), pos + 5
    if pos + 9 > len(buf):
        raise SpvVerificationError("truncated 8-byte varint")
    return int.from_bytes(buf[pos + 1 : pos + 9], "little"), pos + 9


def _output_offsets(stripped_tx: bytes) -> set[int]:
    """Parse a witness-stripped tx and return the byte offset of every output.

    AUDIT 2026-05-24 C-PARSER-2 fix: ``verify_payment`` validates only the bytes
    at a caller-supplied ``output_offset`` and never confirms that offset is a
    real output boundary. A caller could point it into an input scriptSig holding
    a forged payment-shaped blob. This walk lets ``build()`` require the offset to
    be the genuine start of one of the tx's outputs.
    """
    pos = 4  # skip version
    n_in, pos = _read_varint(stripped_tx, pos)
    for _ in range(n_in):
        pos += 36  # prevout (txid 32 + vout 4)
        script_len, pos = _read_varint(stripped_tx, pos)
        pos += script_len + 4  # scriptSig + sequence
        if pos > len(stripped_tx):
            raise SpvVerificationError("input parse ran past end of tx")
    n_out, pos = _read_varint(stripped_tx, pos)
    offsets: set[int] = set()
    for _ in range(n_out):
        offsets.add(pos)
        pos += 8  # value
        script_len, pos = _read_varint(stripped_tx, pos)
        pos += script_len
        if pos > len(stripped_tx):
            raise SpvVerificationError("output parse ran past end of tx")
    # pos must now sit exactly on the 4-byte nLockTime trailer.
    if pos != len(stripped_tx) - 4:
        raise SpvVerificationError(
            f"tx structure parse ended at {pos}, expected {len(stripped_tx) - 4} (len-4)"
        )
    return offsets


@dataclass(frozen=True)
class CovenantParams:
    """Full parameter set committed by the Maker into the covenant.

    ``SpvProofBuilder`` cannot be constructed without all of these. This is
    the audit 05-F-2 / F-3 fix: every proof is bound to the covenant it
    satisfies.
    """

    btc_receive_hash: bytes  # 20 bytes (p2pkh/p2wpkh/p2sh) or 32 bytes (p2tr)
    btc_receive_type: str  # one of P2PKH / P2WPKH / P2SH / P2TR
    btc_satoshis: int  # minimum payment in satoshis, must be > 0
    chain_anchor: bytes  # 32-byte LE prevHash of h1 (audit 05-F-3)
    anchor_height: int  # block height of the anchor block
    merkle_depth: int  # expected Merkle branch depth (audit 05-F-8)

    def __post_init__(self) -> None:
        if self.btc_receive_type not in _VALID_RECEIVE_TYPES:
            raise ValidationError(f"unknown btc_receive_type: {self.btc_receive_type!r}")
        if not isinstance(self.btc_satoshis, int) or isinstance(self.btc_satoshis, bool):
            raise ValidationError("btc_satoshis must be int")
        if self.btc_satoshis <= 0:
            raise ValidationError("btc_satoshis must be > 0")
        if not isinstance(self.chain_anchor, (bytes, bytearray)):
            raise ValidationError("chain_anchor must be bytes")
        if len(self.chain_anchor) != 32:
            raise ValidationError("chain_anchor must be 32 bytes")
        if not isinstance(self.anchor_height, int) or isinstance(self.anchor_height, bool):
            raise ValidationError("anchor_height must be int")
        if self.anchor_height < 0:
            raise ValidationError("anchor_height must be >= 0")
        if not isinstance(self.merkle_depth, int) or isinstance(self.merkle_depth, bool):
            raise ValidationError("merkle_depth must be int")
        if self.merkle_depth < 1 or self.merkle_depth > 32:
            raise ValidationError("merkle_depth must be 1..32")
        expected_hash_len = 32 if self.btc_receive_type == P2TR else 20
        if not isinstance(self.btc_receive_hash, (bytes, bytearray)):
            raise ValidationError("btc_receive_hash must be bytes")
        if len(self.btc_receive_hash) != expected_hash_len:
            raise ValidationError(f"{self.btc_receive_type} receive_hash must be {expected_hash_len} bytes")


@dataclass(frozen=True)
class SpvProof:
    """A fully-verified SPV proof.

    Immutable. The only way to obtain one is via ``SpvProofBuilder.build()``,
    which runs every verifier before returning. Carries a reference to its
    ``CovenantParams`` so downstream finalize-tx builders can confirm that the
    proof was built for the right covenant.
    """

    txid: str  # BE hex display form
    raw_tx: bytes  # witness-stripped bytes
    headers: list[bytes]  # N * 80 bytes
    branch: bytes  # N*33-byte covenant wire format
    pos: int  # tx position within the block (>= 1)
    output_offset: int  # byte offset of payment output in raw_tx
    covenant_params: CovenantParams  # binds proof to a specific covenant

    # Private construction guard — must be _BUILDER_TOKEN, supplied only by
    # SpvProofBuilder.build(). Direct dataclass construction is rejected.
    _token: object = field(default=None, repr=False, compare=False, hash=False)

    def __post_init__(self) -> None:
        if self._token is not _BUILDER_TOKEN:
            raise TypeError(
                "SpvProof must be constructed via SpvProofBuilder.build(), "
                "not directly. Direct construction bypasses SPV verification."
            )


class SpvProofBuilder:
    """Build and verify an SPV proof against a specific covenant's parameters.

    Construction requires the full ``CovenantParams`` (audit 05-F-2 / F-3 fix).
    The ``build`` method runs every verifier and refuses to return partially
    verified proofs: if any check fails, ``SpvVerificationError`` is raised.
    """

    def __init__(self, covenant_params: CovenantParams) -> None:
        self._params = covenant_params

    def build(
        self,
        txid_be: str,
        raw_tx_hex: str,
        headers_hex: list[str],
        merkle_be: list[str],
        pos: int,
        output_offset: int,
    ) -> SpvProof:
        """Verify every SPV-proof component and return an ``SpvProof``.

        Verification order:
            1. Strip witness; stripped raw tx length > 64 (Merkle forgery defense).
            2. ``hash256(stripped_raw_tx) == txid`` (tx integrity).
            3. PoW + chain link for every header (anchor-bound).
            4. Merkle inclusion (with depth binding + coinbase guard).
            5. Payment output correct (hash + type + value threshold).

        Raises:
            SpvVerificationError: on any failure. Never returns a partial proof.
        """
        params = self._params

        # Audit 05-F-9: fail fast on coinbase position before any expensive work.
        # (The full check is also re-asserted inside verify_tx_in_block.)
        if pos == 0:
            raise SpvVerificationError("pos=0 is the coinbase tx - cannot be used as payment proof")
        if pos < 0:
            raise ValidationError("pos must be non-negative")

        # Step 1: parse and strip witness.
        raw_tx = bytes.fromhex(raw_tx_hex)
        stripped = strip_witness(raw_tx)

        # Audit 02-F-1: 64-byte Merkle forgery defense on the stripped tx.
        if len(stripped) <= 64:
            raise SpvVerificationError("stripped raw_tx must be > 64 bytes (Merkle forgery defense)")

        # Step 2: verify hash256(stripped) == txid.
        computed_txid_le = hash256(stripped)
        claimed_txid_le = bytes.fromhex(txid_be)[::-1]
        if computed_txid_le != claimed_txid_le:
            raise SpvVerificationError("hash256(raw_tx) does not match txid")

        # Step 3: parse and verify headers + chain anchor.
        headers = [bytes.fromhex(h) for h in headers_hex]
        verify_chain(headers, chain_anchor=params.chain_anchor)

        # Step 4: build branch and verify Merkle inclusion.
        branch = build_branch(merkle_be, pos)

        # Find which header in the chain contains the tx (flexible anchor:
        # tx may land anywhere in h1..hN).
        matching_header: bytes | None = None
        for header in headers:
            root = extract_merkle_root(header)
            computed = compute_root(txid_be, branch)
            if computed == root:
                matching_header = header
                break

        if matching_header is None:
            raise SpvVerificationError("tx Merkle root does not match any provided header")

        # Run the full inclusion check (also re-asserts coinbase guard, depth
        # binding, and tx<->txid hash match).
        verify_tx_in_block(
            raw_tx=stripped,
            txid_be_hex=txid_be,
            branch=branch,
            pos=pos,
            header=matching_header,
            expected_depth=params.merkle_depth,
        )

        # Step 5: verify payment output.
        # AUDIT 2026-05-24 C-PARSER-2 fix: confirm output_offset is the genuine
        # start of one of the tx's outputs before trusting verify_payment's
        # structural check there (defeats a forged payment planted in a scriptSig).
        if output_offset not in _output_offsets(stripped):
            raise SpvVerificationError(
                f"output_offset {output_offset} is not a real output boundary"
            )
        verify_payment(
            raw_tx=stripped,
            output_offset=output_offset,
            expected_hash=params.btc_receive_hash,
            output_type=params.btc_receive_type,
            min_satoshis=params.btc_satoshis,
        )

        return SpvProof(
            txid=txid_be,
            raw_tx=stripped,
            headers=headers,
            branch=branch,
            pos=pos,
            output_offset=output_offset,
            covenant_params=params,
            _token=_BUILDER_TOKEN,
        )
