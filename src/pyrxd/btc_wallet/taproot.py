"""BTC-side Taproot HTLC for the Gravity atomic cross-chain swap.

This is the Bitcoin counter-chain leg of the ``MAKER_SECRET_TAKER_LOCKS_BTC_FIRST``
atomic swap (see ``docs/plans/2026-05-24-feat-gravity-taproot-htlc-atomic-swap-plan.md``).
The taker funds a single P2TR (``bc1p…``) output whose Tapscript tree carries two
leaves:

* **claim leaf** — ``OP_SHA256 <H> OP_EQUALVERIFY <claimPubkey_xonly> OP_CHECKSIG``.
  The maker spends this with the SHA256 *preimage* ``p`` and a Schnorr signature,
  taking the BTC and — crucially — **revealing ``p`` directly in the witness**. The
  Bitcoin witness IS the cross-chain reveal channel, so we commit to ``p`` directly
  (``OP_SHA256 <H>``), NOT Boltz's ``OP_HASH160(SHA256(p))`` which would only expose
  ``H``.
* **refund leaf** — ``<refundPubkey_xonly> OP_CHECKSIGVERIFY <timeout> OP_CSV``.
  The taker recovers the BTC unilaterally after a relative timelock (BIP68/112 CSV),
  matching the Radiant side's ``tx.age`` relative timelock. CLTV-absolute is the
  documented fallback (see plan §"two corrections").

Construction follows BIP341 (Taproot) and BIP340 (Schnorr). The internal key is a
*provable* NUMS point (verifiably unspendable), so a colluding maker cannot
key-path-spend the BTC without revealing ``p`` — that would silently break
atomicity.

Design rules (house style)
--------------------------
* Frozen dataclasses; ``__post_init__`` raises ``ValidationError``; byte-length
  asserts at every boundary.
* External byte inputs are normalised to immutable ``bytes`` at the boundary — the
  repo previously had a guard that rejected ``bytearray``; ``_as_bytes`` prevents
  that class of bug.
* The preimage ``p`` is never persisted. Callers that model it in memory should use
  ``security.secrets.SecretBytes`` semantics; this module only ever takes ``p`` as a
  transient argument to ``build_claim_tx`` / scrapes it from a witness.
* ``sign_schnorr`` aux_rand is a REQUIRED argument (no default) — an un-defaultable
  nonce-randomizer is how BIP340 nonce reuse is prevented.
* No ``assert`` in ``src/`` — all invariants raise.
"""

from __future__ import annotations

import hashlib
import os
import struct
from dataclasses import dataclass
from enum import Enum

from pyrxd.security.errors import ValidationError

from .keys import _bech32_encode

__all__ = [
    "LEAF_VERSION_TAPSCRIPT",
    "NUMS_INTERNAL_KEY_XONLY",
    "BtcHtlc",
    "BtcHtlcLocator",
    "BtcOutpoint",
    "BtcSpendFields",
    "ScriptTree",
    "TimeUnit",
    "Timelock",
    "btc_input_outpoints_from_raw",
    "btc_spend_fields_from_raw",
    "btc_txid_from_raw",
    "build_claim_tx",
    "build_htlc",
    "build_refund_tx",
    "claim_leaf_script",
    "control_block",
    "nums_point_is_unspendable",
    "refund_leaf_script",
    "scrape_secret",
    "tagged_hash",
    "taproot_output_key",
]

# BIP341 tapscript leaf version.
LEAF_VERSION_TAPSCRIPT = 0xC0

# BIP341 SIGHASH_DEFAULT (== SIGHASH_ALL semantics, but produces a 64-byte sig).
SIGHASH_DEFAULT = 0x00
SIGHASH_ALL = 0x01
SIGHASH_NONE = 0x02
SIGHASH_SINGLE = 0x03
SIGHASH_ANYONECANPAY = 0x80

# secp256k1 field prime — used to assert the NUMS x-coordinate is a valid field
# element (and to confirm provability of the lift).
_SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

# --- Provable NUMS internal key (BIP341, "nothing up my sleeve") ---------------
# The canonical BIP341 unspendable internal key. The BIP publishes the point
#     H = lift_x(0x50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0)
# constructed (per the BIP's own text) "in a way that nobody knows the discrete
# logarithm" — it is the standard NUMS point every Taproot library uses. The
# x-only encoding is the 32-byte x-coordinate below. Using a NUMS internal key
# makes the output key-path-UNSPENDABLE: with no known scalar d such that d*G == H,
# no party (not even a colluding maker) can produce a key-path signature, so the
# ONLY way to move the BTC is a script-path spend — which on the claim leaf forces
# the preimage ``p`` into the witness, preserving cross-chain atomicity.
#
# Provability here is "this is the published public constant" (auditable, fixed,
# discrete-log unknown to all), NOT a runtime-derived SHA256 — claiming a SHA256
# derivation that does not actually reproduce this constant would be dishonest.
NUMS_INTERNAL_KEY_XONLY = bytes.fromhex("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")


# ---------------------------------------------------------------------------
# Byte-boundary normalisation
# ---------------------------------------------------------------------------


def _as_bytes(value: object, *, name: str, length: int | None = None) -> bytes:
    """Normalise an external byte input to immutable ``bytes`` and length-check it.

    Accepts ``bytes`` or ``bytearray`` (the prior bug: a guard rejected
    ``bytearray``); rejects everything else. Returns an immutable copy.
    """
    if not isinstance(value, (bytes, bytearray)):
        raise ValidationError(f"{name} must be bytes, got {type(value).__name__}")
    b = bytes(value)
    if length is not None and len(b) != length:
        raise ValidationError(f"{name} must be {length} bytes, got {len(b)}")
    return b


# ---------------------------------------------------------------------------
# BIP341 tagged hashes
# ---------------------------------------------------------------------------


def tagged_hash(tag: str, msg: bytes) -> bytes:
    """BIP340/341 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || msg)."""
    tag_hash = hashlib.sha256(tag.encode("ascii")).digest()
    return hashlib.sha256(tag_hash + tag_hash + msg).digest()


def _tagged_taphash(domain: str, msg: bytes) -> bytes:
    return tagged_hash(domain, msg)


# ---------------------------------------------------------------------------
# Script-encoding helpers (minimal Bitcoin script serialization)
# ---------------------------------------------------------------------------


def _push_data(data: bytes) -> bytes:
    """Encode a single data push using the minimal opcode.

    Only covers the lengths the HTLC needs (1..75 use the direct length byte;
    76..255 use OP_PUSHDATA1). 32-byte pushes (H, x-only pubkeys) take the
    direct-length form.
    """
    n = len(data)
    if n == 0:
        return b"\x00"  # OP_0 / empty push
    if n <= 75:
        return bytes([n]) + data
    if n <= 255:
        return b"\x4c" + bytes([n]) + data
    raise ValidationError(f"_push_data: length {n} not supported by HTLC scripts")


def _push_minimal_int(value: int) -> bytes:
    """Push a non-negative integer using minimal CScriptNum encoding.

    Used for the CSV timeout operand. 1..16 use OP_1..OP_16; 0 uses OP_0;
    larger values use a little-endian sign-magnitude push (BIP68 timeout
    values are small, but we encode generally for any positive value).
    """
    if value < 0:
        raise ValidationError("timeout operand must be non-negative")
    if value == 0:
        return b"\x00"  # OP_0
    if 1 <= value <= 16:
        return bytes([0x50 + value])  # OP_1 .. OP_16
    # CScriptNum: little-endian, drop sign handling for positive values; if the
    # top byte has its high bit set, append a 0x00 so it is not read as negative.
    out = bytearray()
    v = value
    while v:
        out.append(v & 0xFF)
        v >>= 8
    if out[-1] & 0x80:
        out.append(0x00)
    return _push_data(bytes(out))


# Script opcodes used by the HTLC leaves.
_OP_SHA256 = b"\xa8"
_OP_EQUALVERIFY = b"\x88"
_OP_CHECKSIG = b"\xac"
_OP_CHECKSIGVERIFY = b"\xad"
_OP_CSV = b"\xb2"  # OP_CHECKSEQUENCEVERIFY (BIP112)
_OP_DROP = b"\x75"


# ---------------------------------------------------------------------------
# Timelock type
# ---------------------------------------------------------------------------


class TimeUnit(Enum):
    """The unit a :class:`Timelock` is measured in.

    The whole cross-chain safety invariant (``t_BTC - t_RXD >= margin``) rides on
    comparing like units; mixing blocks and seconds without conversion is a
    fail-closed error, not a silent coercion.
    """

    BLOCKS = "blocks"
    SECONDS = "seconds"


# BIP68 relative-timelock encoding constants.
_BIP68_SEQUENCE_LOCKTIME_DISABLE_FLAG = 1 << 31
_BIP68_SEQUENCE_LOCKTIME_TYPE_FLAG = 1 << 22  # set => seconds (512s granularity)
_BIP68_SEQUENCE_LOCKTIME_MASK = 0x0000FFFF
_BIP68_SECONDS_GRANULARITY = 512


@dataclass(frozen=True)
class Timelock:
    """A unit-tagged relative timelock (BIP68/112 CSV)."""

    value: int
    unit: TimeUnit

    def __post_init__(self) -> None:
        if not isinstance(self.value, int) or isinstance(self.value, bool):
            raise ValidationError("Timelock.value must be int")
        if self.value < 0:
            raise ValidationError("Timelock.value must be >= 0")
        if not isinstance(self.unit, TimeUnit):
            raise ValidationError("Timelock.unit must be a TimeUnit")
        if self.unit is TimeUnit.BLOCKS and self.value > _BIP68_SEQUENCE_LOCKTIME_MASK:
            raise ValidationError(f"Timelock blocks must fit in 16 bits (<= {_BIP68_SEQUENCE_LOCKTIME_MASK})")
        if self.unit is TimeUnit.SECONDS:
            units = self.value // _BIP68_SECONDS_GRANULARITY
            if units > _BIP68_SEQUENCE_LOCKTIME_MASK:
                raise ValidationError("Timelock seconds too large to encode in BIP68 nSequence")

    def csv_script_operand(self) -> int:
        """Return the integer that the CSV leaf pushes (matches nSequence encoding).

        The value compared by OP_CSV is the nSequence value masked to its
        relative-locktime bits, so the script operand equals
        :meth:`to_nsequence` for the same lock.
        """
        return self.to_nsequence()

    def to_nsequence(self) -> int:
        """Encode this relative timelock as a BIP68 nSequence value."""
        if self.unit is TimeUnit.BLOCKS:
            return self.value & _BIP68_SEQUENCE_LOCKTIME_MASK
        units = self.value // _BIP68_SECONDS_GRANULARITY
        return _BIP68_SEQUENCE_LOCKTIME_TYPE_FLAG | (units & _BIP68_SEQUENCE_LOCKTIME_MASK)

    def normalize_to(self, unit: TimeUnit, *, block_interval_s: float) -> Timelock:
        """Return an equivalent ``Timelock`` in ``unit``.

        ``block_interval_s`` is the assumed seconds-per-block used for conversion
        (caller supplies a measured value for mainnet; estimates are test-only).
        Conversion is floor-based; the margin check must account for the rounding.
        """
        if block_interval_s <= 0:
            raise ValidationError("block_interval_s must be > 0")
        if unit is self.unit:
            return self
        if self.unit is TimeUnit.BLOCKS and unit is TimeUnit.SECONDS:
            return Timelock(int(self.value * block_interval_s), TimeUnit.SECONDS)
        # SECONDS -> BLOCKS
        return Timelock(int(self.value // block_interval_s), TimeUnit.BLOCKS)


# ---------------------------------------------------------------------------
# Tapscript leaf builders
# ---------------------------------------------------------------------------


def claim_leaf_script(hashlock: bytes, claim_pubkey_xonly: bytes) -> bytes:
    """Build the claim leaf: ``OP_SHA256 <H> OP_EQUALVERIFY <claimPk> OP_CHECKSIG``.

    Commits to the SHA256 *preimage* directly so the spending witness pushes the
    real ``p`` (the cross-chain reveal channel).
    """
    h = _as_bytes(hashlock, name="hashlock", length=32)
    pk = _as_bytes(claim_pubkey_xonly, name="claim_pubkey_xonly", length=32)
    return _OP_SHA256 + _push_data(h) + _OP_EQUALVERIFY + _push_data(pk) + _OP_CHECKSIG


def refund_leaf_script(refund_pubkey_xonly: bytes, timeout: Timelock) -> bytes:
    """Build the refund leaf: ``<timeout> OP_CSV OP_DROP <refundPk> OP_CHECKSIG``.

    The timelock gate runs FIRST: OP_CHECKSEQUENCEVERIFY (BIP112) is verify-but-
    don't-pop (like OP_CLTV), so OP_DROP clears the operand it leaves behind. Then
    a value-leaving OP_CHECKSIG terminates the script with exactly one truthy item
    — the BIP342 cleanstack rule requires the tapscript to end with a single true.

    The earlier ordering (``<pk> OP_CHECKSIGVERIFY <timeout> OP_CSV OP_DROP``) was
    broken: CHECKSIGVERIFY drains the stack, then OP_DROP empties it, so the script
    ends with ZERO items and every spend fails "Stack size must be exactly one after
    execution". This is the canonical BOLT-3 / Boltz refund ordering (timelock first,
    OP_CHECKSIG last). NOTE: changing this leaf changes the taptree → the HTLC
    address; HTLCs built before this fix are refund-unspendable (claim-only).
    """
    pk = _as_bytes(refund_pubkey_xonly, name="refund_pubkey_xonly", length=32)
    if not isinstance(timeout, Timelock):
        raise ValidationError("timeout must be a Timelock")
    return _push_minimal_int(timeout.csv_script_operand()) + _OP_CSV + _OP_DROP + _push_data(pk) + _OP_CHECKSIG


def tapleaf_hash(script: bytes, leaf_version: int = LEAF_VERSION_TAPSCRIPT) -> bytes:
    """BIP341 TapLeaf hash: tagged_hash("TapLeaf", leaf_version || compact_size(script) || script)."""
    s = _as_bytes(script, name="script")
    return _tagged_taphash("TapLeaf", bytes([leaf_version]) + _compact_size(len(s)) + s)


def tapbranch_hash(a: bytes, b: bytes) -> bytes:
    """BIP341 TapBranch hash: tagged_hash("TapBranch", min(a,b) || max(a,b))."""
    a = _as_bytes(a, name="branch-left", length=32)
    b = _as_bytes(b, name="branch-right", length=32)
    lo, hi = (a, b) if a <= b else (b, a)
    return _tagged_taphash("TapBranch", lo + hi)


def _compact_size(n: int) -> bytes:
    """Bitcoin compact-size (varint) encoding."""
    if n < 0:
        raise ValidationError("compact_size cannot be negative")
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


# ---------------------------------------------------------------------------
# Script tree (2-leaf taptree)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ScriptTree:
    """A 2-leaf Tapscript tree (claim leaf + refund leaf).

    Holds the leaf scripts and their (cached) leaf hashes + merkle root, so the
    durable swap state never has to re-derive (and risk mis-deriving) the tree.
    """

    claim_script: bytes
    refund_script: bytes
    leaf_version: int = LEAF_VERSION_TAPSCRIPT

    def __post_init__(self) -> None:
        object.__setattr__(self, "claim_script", _as_bytes(self.claim_script, name="claim_script"))
        object.__setattr__(self, "refund_script", _as_bytes(self.refund_script, name="refund_script"))
        if self.leaf_version & 1:
            raise ValidationError("leaf_version low bit must be 0 (parity is carried by the control block)")

    @property
    def claim_leaf_hash(self) -> bytes:
        return tapleaf_hash(self.claim_script, self.leaf_version)

    @property
    def refund_leaf_hash(self) -> bytes:
        return tapleaf_hash(self.refund_script, self.leaf_version)

    @property
    def merkle_root(self) -> bytes:
        return tapbranch_hash(self.claim_leaf_hash, self.refund_leaf_hash)

    def sibling_for(self, which: str) -> bytes:
        """Return the merkle-path sibling hash for the named leaf ("claim"|"refund")."""
        if which == "claim":
            return self.refund_leaf_hash
        if which == "refund":
            return self.claim_leaf_hash
        raise ValidationError(f"unknown leaf {which!r}")

    def script_for(self, which: str) -> bytes:
        if which == "claim":
            return self.claim_script
        if which == "refund":
            return self.refund_script
        raise ValidationError(f"unknown leaf {which!r}")


# ---------------------------------------------------------------------------
# TapTweak / output key / control block
# ---------------------------------------------------------------------------


def _taproot_tweak_point(internal_key_xonly: bytes, merkle_root: bytes) -> tuple[bytes, int]:
    """Return (output_key_xonly, output_parity) for a BIP341 tweak by merkle root.

    parity is 0 if the tweaked output point has even Y, 1 if odd. This is the bit
    that goes into the control block — it must NOT inherit keys.py's hardcoded
    even-parity assumption.
    """
    import coincurve

    ik = _as_bytes(internal_key_xonly, name="internal_key_xonly", length=32)
    mr = _as_bytes(merkle_root, name="merkle_root", length=32)
    tweak = _tagged_taphash("TapTweak", ik + mr)
    # Lift the internal x-only key to the even-Y point (BIP340 lift_x), then add
    # tweak*G. coincurve.PublicKey(b"\x02"+x) selects the even-Y lift.
    internal_point = coincurve.PublicKey(b"\x02" + ik)
    output_point = internal_point.add(tweak)
    compressed = output_point.format(compressed=True)  # 33 bytes: 0x02/0x03 || x
    parity = compressed[0] - 0x02  # 0x02 -> 0 (even), 0x03 -> 1 (odd)
    return compressed[1:], parity


def taproot_output_key(internal_key_xonly: bytes, merkle_root: bytes) -> bytes:
    """Return the 32-byte tweaked P2TR output key."""
    out, _parity = _taproot_tweak_point(internal_key_xonly, merkle_root)
    return out


def control_block(
    internal_key_xonly: bytes,
    merkle_root: bytes,
    sibling_hash: bytes,
    *,
    leaf_version: int = LEAF_VERSION_TAPSCRIPT,
) -> bytes:
    """Build a BIP341 control block for a 2-leaf tree.

    Layout: ``(leaf_version | parity) || internal_key_xonly || sibling_hash``
    (1 + 32 + 32 = 65 bytes). ``parity`` is the parity of the tweaked OUTPUT key,
    computed here from the merkle-root tweak — never assumed even.
    """
    ik = _as_bytes(internal_key_xonly, name="internal_key_xonly", length=32)
    sib = _as_bytes(sibling_hash, name="sibling_hash", length=32)
    _out, parity = _taproot_tweak_point(ik, merkle_root)
    first = (leaf_version & 0xFE) | (parity & 1)
    cb = bytes([first]) + ik + sib
    if len(cb) != 65:
        raise ValidationError(f"control block must be 65 bytes for a 2-leaf tree, got {len(cb)}")
    return cb


# ---------------------------------------------------------------------------
# NUMS provability
# ---------------------------------------------------------------------------


def nums_point_is_unspendable(internal_key_xonly: bytes) -> bool:
    """Return True if ``internal_key_xonly`` is the canonical BIP341 NUMS point.

    "Unspendable" means key-path-unspendable: this is the published NUMS constant
    whose discrete logarithm is unknown to everyone, so no party can produce a
    key-path Schnorr signature. The point must also be a valid curve point (lift_x
    succeeds), so the reason there is no key-path spend is "no known scalar", not
    "not a point at all".
    """
    ik = _as_bytes(internal_key_xonly, name="internal_key_xonly", length=32)
    if ik != NUMS_INTERNAL_KEY_XONLY:
        return False
    x = int.from_bytes(ik, "big")
    if x >= _SECP256K1_P:
        return False
    # Must lift to a valid point (y^2 = x^3 + 7 has a solution) so that "no key path
    # spend" is the reason, not "not a point at all".
    import coincurve

    try:
        coincurve.PublicKey(b"\x02" + ik)
    except Exception:
        return False
    return True


# ---------------------------------------------------------------------------
# Concrete types: outpoint + locator (durable retained state)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BtcOutpoint:
    """A funding outpoint (txid big-endian hex as shown by explorers, + vout)."""

    txid: str
    vout: int

    def __post_init__(self) -> None:
        if not isinstance(self.txid, str) or len(self.txid) != 64:
            raise ValidationError("BtcOutpoint.txid must be 64-char hex")
        try:
            bytes.fromhex(self.txid)
        except ValueError:
            raise ValidationError("BtcOutpoint.txid must be hex") from None
        if not isinstance(self.vout, int) or isinstance(self.vout, bool) or self.vout < 0:
            raise ValidationError("BtcOutpoint.vout must be a non-negative int")

    def prevout_bytes(self) -> bytes:
        """Serialise as the 36-byte wire outpoint (txid LE || vout LE)."""
        return bytes.fromhex(self.txid)[::-1] + struct.pack("<I", self.vout)

    def to_dict(self) -> dict:
        return {"txid": self.txid, "vout": self.vout}

    @classmethod
    def from_dict(cls, d: dict) -> BtcOutpoint:
        return cls(txid=str(d["txid"]), vout=int(d["vout"]))


@dataclass(frozen=True)
class BtcHtlcLocator:
    """The FULL durable retained state for a funded BTC HTLC.

    This is NOT opaque — it is everything required to later claim or refund the
    output. Persisting a reduced form (e.g. only the privkey) strands the BTC,
    because the script-path spend needs the whole Tapscript tree + control block.
    """

    funding_outpoint: BtcOutpoint
    script_tree: ScriptTree
    control_block_claim: bytes
    control_block_refund: bytes
    internal_key: bytes
    amount_sats: int
    network: str = "bc"

    def __post_init__(self) -> None:
        if not isinstance(self.funding_outpoint, BtcOutpoint):
            raise ValidationError("funding_outpoint must be a BtcOutpoint")
        if not isinstance(self.script_tree, ScriptTree):
            raise ValidationError("script_tree must be a ScriptTree")
        object.__setattr__(
            self, "control_block_claim", _as_bytes(self.control_block_claim, name="control_block_claim", length=65)
        )
        object.__setattr__(
            self, "control_block_refund", _as_bytes(self.control_block_refund, name="control_block_refund", length=65)
        )
        object.__setattr__(self, "internal_key", _as_bytes(self.internal_key, name="internal_key", length=32))
        if not isinstance(self.amount_sats, int) or isinstance(self.amount_sats, bool) or self.amount_sats <= 0:
            raise ValidationError("amount_sats must be a positive int")
        if not isinstance(self.network, str) or not self.network:
            raise ValidationError("network must be a non-empty string")

    @property
    def output_key(self) -> bytes:
        return taproot_output_key(self.internal_key, self.script_tree.merkle_root)

    @property
    def scriptpubkey(self) -> bytes:
        """The P2TR scriptPubKey: OP_1 <32-byte output key>."""
        return b"\x51\x20" + self.output_key

    @property
    def address(self) -> str:
        return _bech32_encode(self.network, 1, self.output_key)

    def to_dict(self) -> dict:
        """JSON/hex-serialisable form — NEVER contains the preimage ``p``."""
        return {
            "funding_outpoint": self.funding_outpoint.to_dict(),
            "claim_script": self.script_tree.claim_script.hex(),
            "refund_script": self.script_tree.refund_script.hex(),
            "leaf_version": self.script_tree.leaf_version,
            "control_block_claim": self.control_block_claim.hex(),
            "control_block_refund": self.control_block_refund.hex(),
            "internal_key": self.internal_key.hex(),
            "amount_sats": self.amount_sats,
            "network": self.network,
        }

    @classmethod
    def from_dict(cls, d: dict) -> BtcHtlcLocator:
        tree = ScriptTree(
            claim_script=bytes.fromhex(d["claim_script"]),
            refund_script=bytes.fromhex(d["refund_script"]),
            leaf_version=int(d.get("leaf_version", LEAF_VERSION_TAPSCRIPT)),
        )
        return cls(
            funding_outpoint=BtcOutpoint.from_dict(d["funding_outpoint"]),
            script_tree=tree,
            control_block_claim=bytes.fromhex(d["control_block_claim"]),
            control_block_refund=bytes.fromhex(d["control_block_refund"]),
            internal_key=bytes.fromhex(d["internal_key"]),
            amount_sats=int(d["amount_sats"]),
            network=str(d.get("network", "bc")),
        )


# ---------------------------------------------------------------------------
# HTLC assembly
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BtcHtlc:
    """The HTLC funding artifact, before a UTXO funds it.

    Carries the script tree, control blocks for each leaf, the NUMS internal key,
    and the derived funding address/scriptPubKey. ``with_funding`` produces a
    :class:`BtcHtlcLocator` once the funding outpoint + amount are known.
    """

    script_tree: ScriptTree
    internal_key: bytes
    control_block_claim: bytes
    control_block_refund: bytes
    network: str

    @property
    def output_key(self) -> bytes:
        return taproot_output_key(self.internal_key, self.script_tree.merkle_root)

    @property
    def scriptpubkey(self) -> bytes:
        return b"\x51\x20" + self.output_key

    @property
    def address(self) -> str:
        return _bech32_encode(self.network, 1, self.output_key)

    def with_funding(self, outpoint: BtcOutpoint, amount_sats: int) -> BtcHtlcLocator:
        return BtcHtlcLocator(
            funding_outpoint=outpoint,
            script_tree=self.script_tree,
            control_block_claim=self.control_block_claim,
            control_block_refund=self.control_block_refund,
            internal_key=self.internal_key,
            amount_sats=amount_sats,
            network=self.network,
        )


def build_htlc(
    *,
    hashlock: bytes,
    claim_pubkey_xonly: bytes,
    refund_pubkey_xonly: bytes,
    timeout: Timelock,
    internal_key_xonly: bytes = NUMS_INTERNAL_KEY_XONLY,
    network: str = "bc",
) -> BtcHtlc:
    """Construct the BTC Taproot HTLC (funding address + control blocks).

    The default internal key is the provable NUMS point — every spend is
    script-path, so a colluding maker cannot key-path-spend without revealing ``p``.
    """
    hashlock = _as_bytes(hashlock, name="hashlock", length=32)
    internal_key_xonly = _as_bytes(internal_key_xonly, name="internal_key_xonly", length=32)
    claim_script = claim_leaf_script(hashlock, claim_pubkey_xonly)
    refund_script = refund_leaf_script(refund_pubkey_xonly, timeout)
    tree = ScriptTree(claim_script=claim_script, refund_script=refund_script)
    mr = tree.merkle_root
    cb_claim = control_block(internal_key_xonly, mr, tree.sibling_for("claim"))
    cb_refund = control_block(internal_key_xonly, mr, tree.sibling_for("refund"))
    return BtcHtlc(
        script_tree=tree,
        internal_key=internal_key_xonly,
        control_block_claim=cb_claim,
        control_block_refund=cb_refund,
        network=network,
    )


# ---------------------------------------------------------------------------
# BIP341 sighash (script-path) + BIP340 signing
# ---------------------------------------------------------------------------


def _hash256(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def taproot_sighash(
    *,
    tx_version: int,
    locktime: int,
    inputs: list[tuple[bytes, int]],  # (txid_le||vout_le 36B prevout, nSequence)
    input_index: int,
    spent_outputs: list[tuple[int, bytes]],  # (amount_sats, scriptPubKey) per input
    outputs: list[tuple[int, bytes]],  # (amount_sats, scriptPubKey)
    hash_type: int = SIGHASH_DEFAULT,
    tapleaf_hash_value: bytes | None = None,
    annex: bytes | None = None,
) -> bytes:
    """BIP341 signature hash.

    Computes the key-path sighash by default; pass ``tapleaf_hash_value`` for a
    script-path spend (adds the tapleaf || keyversion || codeseparator extension).
    Only SIGHASH_DEFAULT / ALL / NONE / SINGLE (optionally ANYONECANPAY) are
    supported — the subset the HTLC needs.
    """
    if input_index < 0 or input_index >= len(inputs):
        raise ValidationError("input_index out of range")
    if len(spent_outputs) != len(inputs):
        raise ValidationError("spent_outputs length must equal inputs length")

    output_type = hash_type & 0x03
    anyonecanpay = bool(hash_type & SIGHASH_ANYONECANPAY)
    if output_type not in (SIGHASH_DEFAULT, SIGHASH_ALL, SIGHASH_NONE, SIGHASH_SINGLE):
        raise ValidationError(f"unsupported sighash output type: {hash_type:#x}")

    prevouts = b"".join(prevout for prevout, _seq in inputs)
    amounts = b"".join(struct.pack("<q", amt) for amt, _spk in spent_outputs)
    scriptpubkeys = b"".join(_compact_size(len(spk)) + spk for _amt, spk in spent_outputs)
    sequences = b"".join(struct.pack("<I", seq) for _prevout, seq in inputs)

    ss = bytearray()
    ss += b"\x00"  # epoch
    ss += bytes([hash_type])
    ss += struct.pack("<i", tx_version)
    ss += struct.pack("<I", locktime)

    if not anyonecanpay:
        ss += hashlib.sha256(prevouts).digest()
        ss += hashlib.sha256(amounts).digest()
        ss += hashlib.sha256(scriptpubkeys).digest()
        ss += hashlib.sha256(sequences).digest()

    if output_type in (SIGHASH_DEFAULT, SIGHASH_ALL):
        all_outputs = b"".join(struct.pack("<q", amt) + _compact_size(len(spk)) + spk for amt, spk in outputs)
        ss += hashlib.sha256(all_outputs).digest()

    # spend_type: bit0 = annex present; bit1 = script-path (tapleaf present)
    annex_present = annex is not None
    spend_type = (1 if annex_present else 0) | (2 if tapleaf_hash_value is not None else 0)
    ss += bytes([spend_type])

    if anyonecanpay:
        prevout, seq = inputs[input_index]
        amt, spk = spent_outputs[input_index]
        ss += prevout
        ss += struct.pack("<q", amt)
        ss += _compact_size(len(spk)) + spk
        ss += struct.pack("<I", seq)
    else:
        ss += struct.pack("<I", input_index)

    if annex_present:
        annex_bytes = _as_bytes(annex, name="annex")
        ss += hashlib.sha256(_compact_size(len(annex_bytes)) + annex_bytes).digest()

    if output_type == SIGHASH_SINGLE:
        if input_index >= len(outputs):
            raise ValidationError("SIGHASH_SINGLE: no matching output")
        amt, spk = outputs[input_index]
        ss += hashlib.sha256(struct.pack("<q", amt) + _compact_size(len(spk)) + spk).digest()

    if tapleaf_hash_value is not None:
        ss += _as_bytes(tapleaf_hash_value, name="tapleaf_hash", length=32)
        ss += b"\x00"  # key version
        ss += struct.pack("<I", 0xFFFFFFFF)  # codeseparator position (none)

    return _tagged_taphash("TapSighash", bytes(ss))


def sign_schnorr(privkey_bytes: bytes, msg32: bytes, *, aux_rand: bytes) -> bytes:
    """BIP340 Schnorr sign ``msg32`` with ``privkey_bytes``.

    ``aux_rand`` is REQUIRED (no default) — passing fresh ``os.urandom(32)`` per
    signature is how nonce reuse is prevented; making it un-defaultable forces the
    caller to think about it.
    """
    import coincurve

    sk = _as_bytes(privkey_bytes, name="privkey_bytes", length=32)
    msg = _as_bytes(msg32, name="msg32", length=32)
    ar = _as_bytes(aux_rand, name="aux_rand", length=32)
    return coincurve.PrivateKey(sk).sign_schnorr(msg, ar)


def fresh_aux_rand() -> bytes:
    """Return 32 bytes of OS CSPRNG, for use as ``aux_rand``."""
    return os.urandom(32)


# ---------------------------------------------------------------------------
# Spend builders (script-path)
# ---------------------------------------------------------------------------


def _serialize_witness(items: list[bytes]) -> bytes:
    out = _compact_size(len(items))
    for it in items:
        out += _compact_size(len(it)) + it
    return out


def _build_spend_tx(
    *,
    locator: BtcHtlcLocator,
    witness_items_after_sig: list[bytes],
    sign_privkey: bytes,
    leaf: str,
    to_scriptpubkey: bytes,
    out_amount_sats: int,
    nsequence: int,
    locktime: int,
    aux_rand: bytes,
    hash_type: int = SIGHASH_DEFAULT,
) -> bytes:
    """Shared script-path spend assembler.

    Builds a single-input, single-output v2 tx spending the HTLC, signs the
    chosen leaf, and returns the full segwit serialization. The witness is
    ``[<sig>, *witness_items_after_sig, <leaf_script>, <control_block>]``.
    """
    tx_version = 2
    prevout = locator.funding_outpoint.prevout_bytes()
    inputs = [(prevout, nsequence)]
    spent = [(locator.amount_sats, locator.scriptpubkey)]
    outputs = [(out_amount_sats, to_scriptpubkey)]
    leaf_script = locator.script_tree.script_for(leaf)
    leaf_hash = tapleaf_hash(leaf_script, locator.script_tree.leaf_version)

    sighash = taproot_sighash(
        tx_version=tx_version,
        locktime=locktime,
        inputs=inputs,
        input_index=0,
        spent_outputs=spent,
        outputs=outputs,
        hash_type=hash_type,
        tapleaf_hash_value=leaf_hash,
    )
    sig = sign_schnorr(sign_privkey, sighash, aux_rand=aux_rand)
    # SIGHASH_DEFAULT => 64-byte sig with no trailing hash-type byte.
    sig_witness = sig if hash_type == SIGHASH_DEFAULT else sig + bytes([hash_type])

    control = locator.control_block_claim if leaf == "claim" else locator.control_block_refund
    witness = [sig_witness, *witness_items_after_sig, leaf_script, control]

    version_b = struct.pack("<i", tx_version)
    locktime_b = struct.pack("<I", locktime)
    input_b = prevout + b"\x00" + struct.pack("<I", nsequence)  # empty scriptSig
    inputs_section = _compact_size(1) + input_b
    out_b = struct.pack("<q", out_amount_sats) + _compact_size(len(to_scriptpubkey)) + to_scriptpubkey
    outputs_section = _compact_size(1) + out_b
    witness_section = _serialize_witness(witness)

    return version_b + b"\x00\x01" + inputs_section + outputs_section + witness_section + locktime_b


def build_claim_tx(
    *,
    locator: BtcHtlcLocator,
    preimage: bytes,
    claim_privkey: bytes,
    to_scriptpubkey: bytes,
    fee_sats: int,
    aux_rand: bytes,
) -> bytes:
    """Build the maker's claim tx (spends the claim leaf, reveals ``p``).

    Witness: ``<sig> <preimage> <claim_script> <control_block>``.
    """
    p = _as_bytes(preimage, name="preimage", length=32)
    # Defensive: the preimage must actually open the hashlock embedded in the leaf.
    if hashlib.sha256(p).digest() not in locator.script_tree.claim_script:
        raise ValidationError("preimage does not match the claim leaf hashlock")
    out_amount = locator.amount_sats - fee_sats
    if out_amount <= 0:
        raise ValidationError("fee >= amount; output would be non-positive")
    return _build_spend_tx(
        locator=locator,
        witness_items_after_sig=[p],
        sign_privkey=claim_privkey,
        leaf="claim",
        to_scriptpubkey=_as_bytes(to_scriptpubkey, name="to_scriptpubkey"),
        out_amount_sats=out_amount,
        nsequence=0xFFFFFFFD,  # RBF-enabled, no relative lock on the claim leg
        locktime=0,
        aux_rand=aux_rand,
    )


def build_refund_tx(
    *,
    locator: BtcHtlcLocator,
    refund_privkey: bytes,
    timeout: Timelock,
    to_scriptpubkey: bytes,
    fee_sats: int,
    aux_rand: bytes,
) -> bytes:
    """Build the taker's pre-signed refund tx (spends the refund leaf via CSV).

    v2 tx with nSequence encoding the relative timelock per BIP68; witness is
    ``<sig> <refund_script> <control_block>`` (the refund leaf has no preimage).
    """
    if not isinstance(timeout, Timelock):
        raise ValidationError("timeout must be a Timelock")
    out_amount = locator.amount_sats - fee_sats
    if out_amount <= 0:
        raise ValidationError("fee >= amount; output would be non-positive")
    return _build_spend_tx(
        locator=locator,
        witness_items_after_sig=[],
        sign_privkey=refund_privkey,
        leaf="refund",
        to_scriptpubkey=_as_bytes(to_scriptpubkey, name="to_scriptpubkey"),
        out_amount_sats=out_amount,
        nsequence=timeout.to_nsequence(),  # BIP68: enables the relative lock
        locktime=0,
        aux_rand=aux_rand,
    )


# ---------------------------------------------------------------------------
# Secret scraping (swap-semantics; lives here per the plan's note that it can
# sit in a separate function — kept module-local but logically swap-layer)
# ---------------------------------------------------------------------------


def btc_txid_from_raw(raw_tx: bytes) -> str:
    """Compute a BTC transaction's canonical txid (big-endian hex) from raw bytes.

    The txid is ``hash256(non-witness serialization)[::-1]`` — i.e. the tx WITHOUT the
    segwit marker/flag and witness section. This is the reorg gate's
    ``txid_of``: on mainnet there is no node to ``decoderawtransaction``, so the taker
    must derive the txid of the exact bytes ``p`` was scraped from. SERIALIZE, don't
    trust — the gated txid must be that of THIS tx, never a counterparty-supplied id.

    FAIL-CLOSED: raises :class:`ValidationError` on ANY structural problem. A wrong
    txid that doesn't exist on-chain reads 0 confs (fail-closed at the gate); a SILENT
    wrong txid from a partial parse is the danger, so we never return a half-parsed
    result. Handles both legacy (no marker/flag) and segwit txs.
    """
    b = bytes(raw_tx)
    n = len(b)
    pos = 0

    def take(k: int) -> bytes:
        nonlocal pos
        if k < 0 or pos + k > n:
            raise ValidationError("btc_txid_from_raw: truncated transaction")
        out = b[pos : pos + k]
        pos += k
        return out

    def take_compact() -> tuple[int, bytes]:
        """Read a CompactSize; return (value, the exact bytes consumed)."""
        first = take(1)
        v = first[0]
        if v < 0xFD:
            return v, first
        size = {0xFD: 2, 0xFE: 4, 0xFF: 8}[v]
        rest = take(size)
        return int.from_bytes(rest, "little"), first + rest

    version = take(4)
    # Segwit marker/flag? Peek; only 0x00 0x01 is the segwit signal.
    is_segwit = pos + 2 <= n and b[pos] == 0x00 and b[pos + 1] == 0x01
    if is_segwit:
        take(2)  # consume marker+flag (excluded from the txid)

    # --- inputs section (re-serialised verbatim into the txid preimage) ---
    n_in, n_in_b = take_compact()
    if n_in == 0 or n_in > 100_000:
        raise ValidationError("btc_txid_from_raw: bad input count")
    vin = bytearray(n_in_b)
    for _ in range(n_in):
        vin += take(36)  # prevout (txid + vout)
        slen, slen_b = take_compact()
        vin += slen_b
        if slen > n:
            raise ValidationError("btc_txid_from_raw: scriptSig length out of range")
        vin += take(slen)
        vin += take(4)  # sequence

    # --- outputs section ---
    n_out, n_out_b = take_compact()
    if n_out > 100_000:
        raise ValidationError("btc_txid_from_raw: bad output count")
    vout = bytearray(n_out_b)
    for _ in range(n_out):
        vout += take(8)  # value
        slen, slen_b = take_compact()
        vout += slen_b
        if slen > n:
            raise ValidationError("btc_txid_from_raw: scriptPubKey length out of range")
        vout += take(slen)

    # --- witness section (parsed only to SKIP it; excluded from the txid) ---
    if is_segwit:
        for _ in range(n_in):
            n_items, _ = take_compact()
            if n_items > 100_000:
                raise ValidationError("btc_txid_from_raw: bad witness item count")
            for _ in range(n_items):
                ilen, _ = take_compact()
                if ilen > n:
                    raise ValidationError("btc_txid_from_raw: witness item length out of range")
                take(ilen)

    locktime = take(4)
    if pos != n:
        raise ValidationError("btc_txid_from_raw: trailing bytes after locktime")

    non_witness = version + bytes(vin) + bytes(vout) + locktime
    return _hash256(non_witness)[::-1].hex()


@dataclass(frozen=True)
class BtcSpendFields:
    """Serialize-don't-trust binding fields of a BTC tx, for the watchtower to bind a pre-signed refund
    against the swap record: each input's 36-byte wire prevout (``txid LE || vout LE``) + nSequence, and
    each output's ``(value_sats, scriptPubKey_bytes)``. The witness (where a refund carries the schnorr
    sig — never ``p``) is parsed only to validate structure, not returned."""

    input_prevouts: tuple[bytes, ...]
    input_sequences: tuple[int, ...]
    outputs: tuple[tuple[int, bytes], ...]


def btc_spend_fields_from_raw(raw_tx: bytes) -> BtcSpendFields:
    """Parse a BTC tx's binding fields, FAIL-CLOSED, handling segwit and legacy — the exact same
    SERIALIZE-don't-trust walk as :func:`btc_txid_from_raw`, never returning a half-parsed result.

    Used by the v2 autonomous-refund executor to bind a pre-signed refund blob to the swap: the input
    prevout must equal the funding outpoint, the input nSequence must equal ``terms.t_btc.to_nsequence()``,
    and the output ``(value, scriptPubKey)`` must satisfy the cap + the operator's pinned refund address.
    """
    b = bytes(raw_tx)
    n = len(b)
    pos = 0

    def take(k: int) -> bytes:
        nonlocal pos
        if k < 0 or pos + k > n:
            raise ValidationError("btc_spend_fields_from_raw: truncated transaction")
        out = b[pos : pos + k]
        pos += k
        return out

    def take_compact() -> int:
        first = take(1)[0]
        if first < 0xFD:
            return first
        return int.from_bytes(take({0xFD: 2, 0xFE: 4, 0xFF: 8}[first]), "little")

    take(4)  # version
    is_segwit = pos + 2 <= n and b[pos] == 0x00 and b[pos + 1] == 0x01
    if is_segwit:
        take(2)  # marker+flag
    n_in = take_compact()
    if n_in == 0 or n_in > 100_000:
        raise ValidationError("btc_spend_fields_from_raw: bad input count")
    prevouts: list[bytes] = []
    sequences: list[int] = []
    for _ in range(n_in):
        prevouts.append(take(36))
        slen = take_compact()
        if slen > n:
            raise ValidationError("btc_spend_fields_from_raw: scriptSig length out of range")
        take(slen)
        sequences.append(int.from_bytes(take(4), "little"))
    n_out = take_compact()
    if n_out == 0 or n_out > 100_000:
        raise ValidationError("btc_spend_fields_from_raw: bad output count")
    outputs: list[tuple[int, bytes]] = []
    for _ in range(n_out):
        value = int.from_bytes(take(8), "little")
        slen = take_compact()
        if slen > n:
            raise ValidationError("btc_spend_fields_from_raw: scriptPubKey length out of range")
        outputs.append((value, bytes(take(slen))))
    if is_segwit:
        for _ in range(n_in):
            n_items = take_compact()
            if n_items > 100_000:
                raise ValidationError("btc_spend_fields_from_raw: bad witness item count")
            for _ in range(n_items):
                ilen = take_compact()
                if ilen > n:
                    raise ValidationError("btc_spend_fields_from_raw: witness item length out of range")
                take(ilen)
    take(4)  # locktime
    if pos != n:
        raise ValidationError("btc_spend_fields_from_raw: trailing bytes after locktime")
    return BtcSpendFields(tuple(prevouts), tuple(sequences), tuple(outputs))


def btc_input_outpoints_from_raw(raw_tx: bytes) -> list[bytes]:
    """Return the 36-byte wire prevout (txid LE || vout LE) of every input.

    Provenance check for a scraped preimage: the caller verifies the claim tx it
    scraped ``p`` from actually spends THIS swap's funding outpoint
    (compare against :meth:`BtcOutpoint.prevout_bytes`), so a counterparty-supplied
    tx for a DIFFERENT swap — even one that happens to share ``H`` — cannot be used
    to claim this swap's asset. Matches by exact 36-byte prevout, never by offset.

    Parses ONLY the input section (all that the prevouts need); fail-closed on any
    structural problem, the same SERIALIZE-don't-trust discipline as
    :func:`btc_txid_from_raw`. Handles legacy and segwit txs.
    """
    b = bytes(raw_tx)
    n = len(b)
    pos = 0

    def take(k: int) -> bytes:
        nonlocal pos
        if k < 0 or pos + k > n:
            raise ValidationError("btc_input_outpoints_from_raw: truncated transaction")
        out = b[pos : pos + k]
        pos += k
        return out

    def take_compact() -> int:
        first = take(1)[0]
        if first < 0xFD:
            return first
        return int.from_bytes(take({0xFD: 2, 0xFE: 4, 0xFF: 8}[first]), "little")

    take(4)  # version
    if pos + 2 <= n and b[pos] == 0x00 and b[pos + 1] == 0x01:
        take(2)  # segwit marker+flag
    n_in = take_compact()
    if n_in == 0 or n_in > 100_000:
        raise ValidationError("btc_input_outpoints_from_raw: bad input count")
    prevouts: list[bytes] = []
    for _ in range(n_in):
        prevouts.append(take(36))  # prevout: txid (LE) + vout (LE)
        slen = take_compact()
        if slen > n:
            raise ValidationError("btc_input_outpoints_from_raw: scriptSig length out of range")
        take(slen)
        take(4)  # sequence
    return prevouts


def _iter_witness_stack(claim_tx_bytes: bytes) -> list[list[bytes]]:
    """Parse a segwit tx and return the witness stack for each input.

    Tolerant by design: returns ``[]`` (or partial) on any structural problem
    rather than raising, so ``scrape_secret`` can never index-error on an
    adversarial witness (the C-PARSER lesson — match by content, never offset).
    """
    b = bytes(claim_tx_bytes)
    pos = 0
    n = len(b)

    def read(k: int) -> bytes | None:
        nonlocal pos
        if pos + k > n:
            return None
        out = b[pos : pos + k]
        pos += k
        return out

    def read_compact() -> int | None:
        nonlocal pos
        first = read(1)
        if first is None:
            return None
        v = first[0]
        if v < 0xFD:
            return v
        size = {0xFD: 2, 0xFE: 4, 0xFF: 8}[v]
        raw = read(size)
        if raw is None:
            return None
        return int.from_bytes(raw, "little")

    if read(4) is None:  # version
        return []
    marker_flag = read(2)
    if marker_flag is None or marker_flag[0] != 0x00 or marker_flag[1] != 0x01:
        # Not a segwit tx (no witness to scrape).
        return []

    n_in = read_compact()
    if n_in is None or n_in == 0 or n_in > 100_000:
        return []
    for _ in range(n_in):
        if read(36) is None:  # prevout
            return []
        slen = read_compact()
        if slen is None or slen > n:
            return []
        if slen and read(slen) is None:
            return []
        if read(4) is None:  # sequence
            return []

    n_out = read_compact()
    if n_out is None or n_out > 100_000:
        return []
    for _ in range(n_out):
        if read(8) is None:  # value
            return []
        slen = read_compact()
        if slen is None or slen > n:
            return []
        if slen and read(slen) is None:
            return []

    stacks: list[list[bytes]] = []
    for _ in range(n_in):
        n_items = read_compact()
        if n_items is None or n_items > 100_000:
            return stacks
        stack: list[bytes] = []
        for _ in range(n_items):
            ilen = read_compact()
            if ilen is None or ilen > n:
                return stacks
            item = read(ilen) if ilen else b""
            if item is None:
                return stacks
            stack.append(item)
        stacks.append(stack)
    return stacks


def scrape_secret(claim_tx_bytes: bytes, hashlock: bytes) -> bytes:
    """Extract the preimage ``p`` from a claim tx by matching ``sha256(p)==H``.

    Matches over EVERY witness push of EVERY input — never by positional offset
    (the C-PARSER lesson). Returns the 32-byte preimage. Raises ``ValidationError``
    if no witness push hashes to ``H`` (e.g. this is a refund tx, or the wrong tx).

    The hashlock disambiguates which swap this tx belongs to; the caller should
    pair it with the funding outpoint when multiple swaps share an ``H``.
    """
    h = _as_bytes(hashlock, name="hashlock", length=32)
    tx = _as_bytes(claim_tx_bytes, name="claim_tx_bytes")
    for stack in _iter_witness_stack(tx):
        for item in stack:
            if len(item) == 32 and hashlib.sha256(item).digest() == h:
                return item
    raise ValidationError("no witness push hashes to the hashlock (not a claim tx for this swap)")
