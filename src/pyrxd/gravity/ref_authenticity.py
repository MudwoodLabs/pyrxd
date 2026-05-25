"""Mandatory pre-payment REF-authenticity gate (consensus cannot do this).

Rigorous audit R1 (2026-05-24), PROVEN on a live Radiant Core 2.3.0 regtest:
Radiant consensus auto-inserts every spent input's outpoint into the singleton
ref set (``validation.h:1046-1049``), and ``validatePushRefRule`` only requires
output singleton-refs ⊆ input-refs. So an ``OP_PUSHINPUTREFSINGLETON <REF>``
output is consensus-valid whenever ``REF`` equals the outpoint of ANY input the
funder spends — the singleton need NOT be a genuinely-minted Glyph NFT. A node
accepted and mined a covenant bearing a singleton whose REF was a plain wallet
UTXO (no ``gly`` envelope, no genesis reveal).

Consequence: a malicious maker can advertise a real one-of-one and fund the swap
covenant with a worthless self-crafted singleton. Finalize settles correctly to
the taker, who pays BTC and receives a ``d8<ref>`` output no indexer recognizes
as the advertised asset. **The covenant cannot self-verify mint provenance.**

The ONLY defense is off-chain: before paying BTC, the taker must confirm that
``REF`` resolves on a trusted indexer to the genuine reveal of the advertised
asset (genesis outpoint, payload hash, ``gly`` marker). This module makes that
check explicit, fail-closed, and reusable by BOTH swap constructions (the
SPV-oracle ``GravityTrade`` path and the HTLC ``SwapCoordinator`` path). It is a
HARD GATE — never optimistic-pass, never skippable for an FT/NFT swap.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from pyrxd.security.errors import ValidationError

__all__ = ["RefAuthenticityIndexer", "verify_ref_authenticity"]


@runtime_checkable
class RefAuthenticityIndexer(Protocol):
    """The minimal indexer surface needed to verify a genesis REF is real.

    Implementations resolve a genesis-outpoint ref to its on-chain reveal and
    report whether it is a genuinely-minted Glyph asset. ``verify_ref`` MUST
    raise (not return False optimistically) if the indexer cannot reach a
    definitive answer — the caller treats any non-True / any exception as
    fail-closed.
    """

    def verify_ref(self, genesis_ref: bytes) -> bool:
        """Return True iff ``genesis_ref`` resolves to a genuine Glyph reveal."""
        ...


def verify_ref_authenticity(
    indexer: RefAuthenticityIndexer,
    genesis_ref: bytes,
    *,
    asset_variant: str,
) -> None:
    """Hard pre-payment gate: confirm the covenant's REF is a real minted asset.

    Call this BEFORE the taker pays any BTC for an FT/NFT swap. Plain-RXD swaps
    carry no ref and are skipped. Fails closed on EVERY uncertain outcome:
    indexer unreachable, indexer says not-authentic, or a malformed ref.

    Args:
        indexer: a trusted :class:`RefAuthenticityIndexer`. A lying or
            attacker-controlled indexer defeats this gate — the taker must use an
            indexer they trust (ideally cross-checked against a second source).
        genesis_ref: the 36-byte genesis outpoint ref baked into the covenant.
        asset_variant: "rxd" | "ft" | "nft". Only ft/nft carry a ref to verify.

    Raises:
        ValidationError: if the ref is not provably authentic. The caller MUST
            NOT pay BTC when this raises.
    """
    if asset_variant not in ("rxd", "ft", "nft"):
        raise ValidationError(f"unknown asset_variant {asset_variant!r}")
    if asset_variant == "rxd":
        # Plain RXD photons carry no singleton/FT ref — nothing to authenticate.
        if genesis_ref:
            raise ValidationError("rxd swaps must not carry a genesis_ref")
        return

    if not isinstance(genesis_ref, (bytes, bytearray)) or len(genesis_ref) == 0:
        raise ValidationError(f"{asset_variant} swap requires a non-empty genesis_ref to authenticate")
    if not isinstance(indexer, RefAuthenticityIndexer):
        raise ValidationError("indexer does not implement verify_ref — cannot authenticate REF; fail-closed")

    try:
        authentic = indexer.verify_ref(bytes(genesis_ref))
    except Exception as exc:  # indexer unreachable/lagging/error => fail-closed.
        raise ValidationError(
            f"indexer could not verify REF authenticity ({exc}); fail-closed — do NOT pay BTC. "
            "Consensus does NOT enforce mint provenance (rigorous audit R1)."
        ) from exc

    if authentic is not True:
        raise ValidationError(
            "genesis REF did not resolve to a genuine minted asset on the trusted indexer. "
            "The covenant's singleton may be a forged/self-crafted ref (rigorous audit R1: "
            "consensus enforces ref uniqueness, NOT mint provenance). Do NOT pay BTC."
        )
