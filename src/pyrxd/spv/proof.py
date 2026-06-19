"""SpvProof aggregate and SpvProofBuilder.

An ``SpvProof`` is only constructible via ``SpvProofBuilder.build()``, which
runs every verifier before returning. The builder requires a complete
``CovenantParams`` up front -- this is the audit 05-F-2 / F-3 fix: SPV
proofs are always bound to the specific covenant they'll satisfy.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from pyrxd.security.errors import SpvVerificationError, ValidationError
from pyrxd.security.types import Nbits

from .chain import verify_chain
from .merkle import build_branch, compute_root, extract_merkle_root, verify_tx_in_block
from .payment import P2PKH, P2SH, P2TR, P2WPKH, verify_payment
from .pow import hash256
from .witness import strip_witness

__all__ = [
    "CovenantParams",
    "SpvProof",
    "SpvProofBuilder",
    "require_spv_sole_authority_cleared",
]

_BUILDER_TOKEN = object()  # unforgeable sentinel; SpvProof.__post_init__ checks for it

_VALID_RECEIVE_TYPES = frozenset({P2PKH, P2WPKH, P2SH, P2TR})

# Isolated test chains carry no real value, so the SPV primitive may run as a sole
# release authority on them without an audit opt-in.
_SPV_AUDIT_CLEARED_NETWORKS = frozenset({"regtest", "testnet", "testnet3", "testnet4", "signet"})


def require_spv_sole_authority_cleared(network: str, *, audit_cleared: bool) -> None:
    """Retained for backward-compatibility; no longer blocks.

    The cross-chain swap stack is unaudited — callers handling real value should
    verify it themselves. Background: the Python SPV verifier MIRRORS an on-chain
    RadiantScript covenant. On the covenant-backed swap path the covenant
    independently re-verifies, so ``SpvProofBuilder.build()`` is a client-side
    check. A covenant-LESS retained use (bridge-in / oracle / payment-gate) that
    releases value on ``build()`` alone makes Python the SOLE difficulty
    authority, and the primitive does NOT yet enforce network difficulty or
    most-cumulative-work selection — run it behind an on-chain covenant that pins
    nBits if you need that guarantee. As of 0.9.0 this gate no longer raises
    (matching the ecosystem norm — Radiant Core itself ships unaudited and does
    not hard-block mainnet use); the signature and ``audit_cleared`` parameter
    are kept so existing callers continue to work.
    """
    return None


def _read_varint(buf: bytes, pos: int) -> tuple[int, int]:
    """Read a Bitcoin CompactSize varint at ``pos``; return (value, next_pos)."""
    if pos >= len(buf):
        raise SpvVerificationError("varint read past end of tx")
    first = buf[pos]
    if first < 0xFD:
        return first, pos + 1
    # Audit 2026-05-29 F-15: reject non-canonical (overlong) CompactSize — these
    # are rejected by Bitcoin consensus at deserialization and read as a single
    # byte by the covenant; accepting them diverges from both.
    if first == 0xFD:
        if pos + 3 > len(buf):
            raise SpvVerificationError("truncated 2-byte varint")
        value = int.from_bytes(buf[pos + 1 : pos + 3], "little")
        if value < 0xFD:
            raise SpvVerificationError(f"non-canonical varint: 0xFD prefix encodes {value} (< 0xFD)")
        return value, pos + 3
    if first == 0xFE:
        if pos + 5 > len(buf):
            raise SpvVerificationError("truncated 4-byte varint")
        value = int.from_bytes(buf[pos + 1 : pos + 5], "little")
        if value <= 0xFFFF:
            raise SpvVerificationError(f"non-canonical varint: 0xFE prefix encodes {value} (<= 0xFFFF)")
        return value, pos + 5
    if pos + 9 > len(buf):
        raise SpvVerificationError("truncated 8-byte varint")
    value = int.from_bytes(buf[pos + 1 : pos + 9], "little")
    if value <= 0xFFFFFFFF:
        raise SpvVerificationError(f"non-canonical varint: 0xFF prefix encodes {value} (<= 0xFFFFFFFF)")
    return value, pos + 9


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
        raise SpvVerificationError(f"tx structure parse ended at {pos}, expected {len(stripped_tx) - 4} (len-4)")
    return offsets


# The any-wallet covenant reads each input's scriptSig length as a SINGLE byte
# and decodes it with OP_BIN2NUM (signed CScriptNum). A length >= 0x80 (128)
# decodes NEGATIVE, so the covenant's `require(ssl >= 0)` guard ScriptFails on
# ANY funding tx with an input scriptSig of 128..252 bytes (rigorous audit R2,
# 2026-05-24). Native-segwit inputs have an EMPTY scriptSig and legacy P2PKH is
# ~107 B, so those are safe; P2SH multisig (~250 B) / inscription reveals are not.
_COVENANT_MAX_INPUT_SCRIPTSIG_LEN = 127


def _first_input_is_null_outpoint(stripped_tx: bytes) -> bool:
    """Return True if the tx's first input spends the null outpoint.

    A coinbase tx's sole input has prevout txid == 32 zero bytes and
    vout == 0xFFFFFFFF. AUDIT 2026-05-29 F-04: the ``pos == 0`` coinbase guard
    was bypassable via pos aliasing (``pos = k * 2**depth`` reproduces the
    coinbase branch). This structural check rejects the coinbase regardless of
    the claimed ``pos``. Non-raising: returns False on any parse problem and
    lets the canonical structural walk (``_output_offsets``) report the error.
    """
    try:
        _, p = _read_varint(stripped_tx, 4)  # skip version, read n_in -> p at input[0]
    except SpvVerificationError:
        return False
    if p + 36 > len(stripped_tx):
        return False
    return stripped_tx[p : p + 32] == b"\x00" * 32 and stripped_tx[p + 32 : p + 36] == b"\xff\xff\xff\xff"


def _max_input_scriptsig_len(stripped_tx: bytes) -> int:
    """Return the largest input scriptSig length in a witness-stripped tx."""
    pos = 4  # skip version
    n_in, pos = _read_varint(stripped_tx, pos)
    longest = 0
    for _ in range(n_in):
        pos += 36  # prevout
        script_len, pos = _read_varint(stripped_tx, pos)
        longest = max(longest, script_len)
        pos += script_len + 4  # scriptSig + sequence
        if pos > len(stripped_tx):
            raise SpvVerificationError("input parse ran past end of tx")
    return longest


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
    # Audit 2026-05-29 F-01/F-03: the wire nBits the covenant pins. When set,
    # build() enforces every header's nBits matches (mirrors the covenant's
    # nBits ∈ {expectedNBits, expectedNBitsNext} check). None disables the check
    # — UNSAFE for any sole-authority (covenant-less) use; the deprecated swap is
    # protected only by the on-chain covenant's own pin.
    expected_nbits: bytes | None = None  # 4-byte wire nBits, or None
    expected_nbits_next: bytes | None = None  # optional 2nd accepted value (retarget window)

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
        # Audit 2026-05-29 F-01/F-03/F-27: validate the optional nBits pin. Run it
        # through the Nbits trust-boundary type so a malformed/easier-than-0x1d
        # value is rejected here (the covenant tolerates exponent up to 0x20; we
        # cap at 0x1d so Python never honors a target the covenant accepts but
        # that is easier than well-formed difficulty-1).
        for label, nb in (("expected_nbits", self.expected_nbits), ("expected_nbits_next", self.expected_nbits_next)):
            if nb is None:
                continue
            if not isinstance(nb, (bytes, bytearray)):
                raise ValidationError(f"{label} must be bytes")
            if len(nb) != 4:
                raise ValidationError(f"{label} must be 4 bytes (wire nBits)")
            Nbits(bytes(nb))  # raises ValidationError on malformed nBits
        if self.expected_nbits_next is not None and self.expected_nbits is None:
            raise ValidationError("expected_nbits_next set without expected_nbits")
        # Audit 2026-05-29 F-24: store immutable copies so a caller mutating a
        # passed-in bytearray after construction cannot alter the frozen params.
        object.__setattr__(self, "btc_receive_hash", bytes(self.btc_receive_hash))
        object.__setattr__(self, "chain_anchor", bytes(self.chain_anchor))
        if self.expected_nbits is not None:
            object.__setattr__(self, "expected_nbits", bytes(self.expected_nbits))
        if self.expected_nbits_next is not None:
            object.__setattr__(self, "expected_nbits_next", bytes(self.expected_nbits_next))


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

    @classmethod
    def for_sole_authority(
        cls,
        covenant_params: CovenantParams,
        *,
        network: str,
        audit_cleared: bool = False,
    ) -> SpvProofBuilder:
        """Construct a builder for a covenant-LESS sole-authority use, gated.

        Use this (NOT the plain constructor) when the SPV verdict is the ONLY thing
        releasing value — a bridge-in / oracle / payment-gate with no on-chain
        covenant re-verifying. It runs :func:`require_spv_sole_authority_cleared`,
        which as of 0.9.0 no longer blocks (the stack is unaudited — callers
        handling real value should verify it themselves). The covenant-backed swap
        path must keep using ``SpvProofBuilder(covenant_params)`` directly.
        """
        require_spv_sole_authority_cleared(network, audit_cleared=audit_cleared)
        return cls(covenant_params)

    def build(
        self,
        txid_be: str,
        raw_tx_hex: str,
        headers_hex: list[str],
        merkle_be: list[str],
        pos: int,
        output_offset: int,
        tx_block_height: int | None = None,
    ) -> SpvProof:
        """Verify every SPV-proof component and return an ``SpvProof``.

        Verification order:
            1. Strip witness; stripped raw tx length > 64 (Merkle forgery defense).
            2. ``hash256(stripped_raw_tx) == txid`` (tx integrity).
            3. PoW + chain link for every header (anchor-bound).
            4. Merkle inclusion (with depth binding + coinbase guard).
            5. Payment output correct (hash + type + value threshold).

        Args:
            tx_block_height: Optional Bitcoin block height of the tx. When provided
                (audit 2026-05-29 F-18), the Merkle root is pinned to the SPECIFIC
                header at index ``tx_block_height - anchor_height - 1`` in the
                anchor-chained sequence, instead of accepting a root that matches
                ANY fetched header. Production ``finalize()`` always supplies it;
                this binds the Merkle proof's block to the resolved height so a
                malicious data source cannot route a proof for one block against an
                unrelated header it also supplied. ``None`` keeps the weaker
                flexible-anchor search (tx may land in any of h1..hN).

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

        # Audit 2026-05-29 F-04: structural coinbase reject, independent of pos.
        # The pos==0 guard alone was bypassable (pos = k*2**depth aliases the
        # coinbase branch); a coinbase is identifiable by its null-outpoint first
        # input regardless of the claimed position.
        # NOTE (audit F-26): this coinbase exclusion is PYTHON-ONLY — the deployed
        # covenant has no in-script coinbase guard, so it is NOT consensus-enforced.
        # It is the safe direction (Python stricter than the covenant): a coinbase
        # paying the covenant's btcReceiveHash is not a realistic taker flow.
        if _first_input_is_null_outpoint(stripped):
            raise SpvVerificationError("coinbase tx (null prevout) cannot be used as payment proof")

        # Rigorous audit R2 (2026-05-24): the any-wallet covenant rejects a funding
        # tx whose any input scriptSig is >= 128 B (its single-byte signed length
        # read decodes negative -> the covenant's `ssl >= 0` guard ScriptFails).
        # NOTE (audit F-12): the 127-byte limit models the ANY-WALLET covenant.
        # The deployed default (MakerCovenantFlat12x20) is NARROWER — it accepts a
        # scriptSig length of only {0, 23} — and the production finalize path enforces
        # that via gravity/trade.py::_find_output_zero_offset, not this guard. This
        # check is the conservative superset for a covenant-bound reusable caller.
        # Refuse to build a proof the covenant would reject on-chain — otherwise
        # the taker broadcasts BTC against a proof that can never settle and, on the
        # no-refund SPV-oracle path, can LOSE the BTC. Run AFTER the txid match so a
        # genuine tx is being parsed; a structurally odd tx that still matched its
        # txid will be caught by the output-boundary walk below, so we only raise
        # here for the specific scriptSig-too-long reason.
        try:
            longest_ss = _max_input_scriptsig_len(stripped)
        except SpvVerificationError:
            longest_ss = 0  # leave structural rejection to _output_offsets (step 5)
        if longest_ss > _COVENANT_MAX_INPUT_SCRIPTSIG_LEN:
            raise SpvVerificationError(
                f"funding tx has an input scriptSig of {longest_ss} bytes; the any-wallet "
                f"covenant only accepts inputs with scriptSig <= {_COVENANT_MAX_INPUT_SCRIPTSIG_LEN} bytes "
                "(signed single-byte length read). Pay from a native-segwit (empty scriptSig) "
                "or legacy P2PKH input, not P2SH/multisig, or the covenant will reject the proof."
            )

        # Step 3: parse and verify headers + chain anchor + committed nBits pin.
        headers = [bytes.fromhex(h) for h in headers_hex]
        verify_chain(
            headers,
            chain_anchor=params.chain_anchor,
            expected_nbits=params.expected_nbits,
            expected_nbits_next=params.expected_nbits_next,
        )

        # Step 4: build branch and verify Merkle inclusion.
        branch = build_branch(merkle_be, pos)
        computed_root = compute_root(txid_be, branch)

        # Audit 2026-05-29 F-18: bind the Merkle proof to the SPECIFIC height-
        # identified header rather than accepting a root that matches ANY fetched
        # header. verify_chain has already proven headers[0].prevHash == chain_anchor
        # and the contiguous linkage, so header index i is block anchor_height+1+i.
        matching_header: bytes | None = None
        if tx_block_height is not None:
            expected_index = tx_block_height - params.anchor_height - 1
            if not (0 <= expected_index < len(headers)):
                raise SpvVerificationError(
                    f"tx_block_height {tx_block_height} maps to header index {expected_index}, "
                    f"out of range for the {len(headers)} anchored headers "
                    f"(anchor_height {params.anchor_height})"
                )
            matching_header = headers[expected_index]
            if computed_root != extract_merkle_root(matching_header):
                raise SpvVerificationError(
                    f"Merkle root does not match the header at the claimed block height {tx_block_height} "
                    "(merkle proof not bound to the resolved block)"
                )
        else:
            # Flexible-anchor fallback (no height supplied): find which header in the
            # chain contains the tx. WEAKER — accepts a root matching any fetched
            # header. Production finalize() always supplies tx_block_height (F-18).
            for header in headers:
                if computed_root == extract_merkle_root(header):
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
            raise SpvVerificationError(f"output_offset {output_offset} is not a real output boundary")
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
