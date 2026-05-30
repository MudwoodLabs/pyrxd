"""Gravity protocol data types.

``GravityOffer`` captures all parameters a Maker commits into a MakerOffer
covenant (both Bitcoin-side and Radiant-side).  The result dataclasses
(``ClaimResult``, ``FinalizeResult``, ``ForfeitResult``) carry the outputs of
the three transaction builders.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from pyrxd.security.errors import ValidationError

__all__ = [
    "MIN_CLAIM_DEADLINE",
    "MIN_DEADLINE_FROM_NOW_HOURS",
    "CancelResult",
    "ClaimResult",
    "FinalizeResult",
    "ForfeitResult",
    "GravityOffer",
    "MakerOfferResult",
]

# Minimum claimDeadline accepted by the covenant generator: 2025-01-01 00:00:00 UTC
MIN_CLAIM_DEADLINE = 1735686400

# Minimum hours from *now* we require before allowing a new offer
MIN_DEADLINE_FROM_NOW_HOURS = 24


@dataclass(frozen=True)
class GravityOffer:
    """All parameters a Maker commits into a MakerOffer covenant.

    Mirrors ``CovenantParams`` in ``pyrxd.spv.proof`` but adds Radiant-side
    fields and the two precomputed redeem scripts.
    """

    # Bitcoin-side fields
    btc_receive_hash: bytes  # 20 bytes (p2pkh/p2wpkh/p2sh) or 32 bytes (p2tr)
    btc_receive_type: str  # "p2pkh" | "p2wpkh" | "p2sh" | "p2tr"
    btc_satoshis: int  # minimum BTC payment in satoshis
    chain_anchor: bytes  # 32-byte LE prevHash of BTC h1
    anchor_height: int  # BTC block height of anchor
    merkle_depth: int  # expected Merkle branch depth

    # Radiant-side fields
    taker_radiant_pkh: bytes  # 20-byte PKH of Taker's Radiant address
    claim_deadline: int  # Unix timestamp; forfeit opens after this
    photons_offered: int  # RXD photons locked in covenant

    # Covenant bytecode (hex)
    offer_redeem_hex: str  # MakerOffer full locking script hex
    claimed_redeem_hex: str  # MakerClaimed full locking script hex
    expected_code_hash_hex: str  # hash256(P2SH_scriptPubKey(claimed_redeem)); enforced in build_claim_tx

    # Audit 2026-05-29 F-02/F-03: the wire nBits the covenant pins. Logically a
    # Bitcoin-side field, but placed last to satisfy dataclass default ordering
    # (the fields above have no defaults). ``build_gravity_offer`` always
    # populates these; ``finalize()`` threads them into ``CovenantParams`` so the
    # Python SPV verifier mirrors the covenant's nBits pin and refuses a proof the
    # covenant would reject (Direction-A fund-stranding on the no-refund path).
    expected_nbits: bytes | None = None  # 4-byte wire nBits, or None (legacy offers)
    expected_nbits_next: bytes | None = None  # optional 2nd accepted value (retarget window)

    def __post_init__(self) -> None:
        if self.btc_receive_type not in ("p2pkh", "p2wpkh", "p2sh", "p2tr"):
            raise ValidationError(f"unknown btc_receive_type: {self.btc_receive_type!r}")
        if self.btc_satoshis <= 0:
            raise ValidationError("btc_satoshis must be > 0")
        if len(self.chain_anchor) != 32:
            raise ValidationError("chain_anchor must be 32 bytes")
        if len(self.taker_radiant_pkh) != 20:
            raise ValidationError("taker_radiant_pkh must be 20 bytes")
        if self.claim_deadline < MIN_CLAIM_DEADLINE:
            raise ValidationError(
                f"claim_deadline {self.claim_deadline} is before minimum ({MIN_CLAIM_DEADLINE} = 2025-01-01)"
            )
        if self.claim_deadline > 0xFFFFFFFF:
            raise ValidationError(
                f"claim_deadline {self.claim_deadline} exceeds uint32 max (4294967295). "
                "nLockTime is a 4-byte field; a deadline above this cannot be encoded "
                "and build_forfeit_tx would raise OverflowError, locking funds permanently."
            )
        if self.photons_offered <= 0:
            raise ValidationError("photons_offered must be > 0")
        for label, nb in (("expected_nbits", self.expected_nbits), ("expected_nbits_next", self.expected_nbits_next)):
            if nb is None:
                continue
            if len(nb) != 4:
                raise ValidationError(f"{label} must be 4 bytes (wire nBits); got {len(nb)}")
            # Audit 2026-05-29 F-27: validate well-formedness on the data carrier
            # too (not only at build/verify) so a hand-built offer can't carry a
            # malformed / easier-than-0x1d nBits the covenant would reject.
            from pyrxd.security.types import Nbits

            Nbits(bytes(nb))

    def validate_deadline_from_now(self, accept_short_deadline: bool = False) -> None:
        """Check that ``claim_deadline`` is at least ``MIN_DEADLINE_FROM_NOW_HOURS`` from now.

        Raises ``ValidationError`` unless *accept_short_deadline* is ``True``
        (audit 04-S1 guard: Taker needs time to confirm BTC + build SPV proof +
        finalize on Radiant).
        """
        now = int(time.time())
        min_deadline = now + MIN_DEADLINE_FROM_NOW_HOURS * 3600
        if self.claim_deadline < min_deadline and not accept_short_deadline:
            raise ValidationError(
                f"claim_deadline is less than {MIN_DEADLINE_FROM_NOW_HOURS}h from now. "
                "Taker needs time to confirm BTC + build SPV proof + finalize on Radiant. "
                "Pass accept_short_deadline=True to override (NOT recommended)."
            )


@dataclass
class MakerOfferResult:
    """Output of :func:`build_maker_offer_tx` — the MakerOffer funding tx."""

    tx_hex: str
    txid: str
    tx_size: int
    offer_p2sh: str  # Radiant P2SH address of the MakerOffer UTXO
    fee_sats: int
    output_photons: int  # photons locked in the MakerOffer P2SH output


@dataclass
class CancelResult:
    tx_hex: str
    txid: str
    tx_size: int
    fee_sats: int
    output_photons: int


@dataclass
class ClaimResult:
    tx_hex: str
    txid: str
    tx_size: int
    offer_p2sh: str
    claimed_p2sh: str
    fee_sats: int
    output_photons: int


@dataclass
class FinalizeResult:
    tx_hex: str
    txid: str
    tx_size: int
    fee_sats: int
    output_photons: int


@dataclass
class ForfeitResult:
    tx_hex: str
    txid: str
    tx_size: int
    fee_sats: int
    output_photons: int
