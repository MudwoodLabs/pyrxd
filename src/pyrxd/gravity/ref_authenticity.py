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
asset. This module makes that check explicit, fail-closed, and reusable by BOTH
swap constructions (the SPV-oracle ``GravityTrade`` path and the HTLC
``SwapCoordinator`` path). It is a HARD GATE — never optimistic-pass, never
skippable for an FT/NFT swap.

The gate enforces **five bindings** on the resolved reveal (T7 plan D2):

  (a) the resolved token's **genesis outpoint == the advertised ``genesis_ref``**
      (an FT/NFT ref is the GENESIS outpoint, NOT the reveal txid — conflating
      the two would make the binding silently never match);
  (b) a ``gly`` envelope marker is present (it is a real Glyph reveal, not a
      bare singleton);
  (c) the reveal's **payload hash** matches the advertised one (when the taker
      agreed to a specific payload);
  (d) it is the **specific advertised asset** — binding (a) carries this: the
      genesis outpoint uniquely names the asset, so ``ref == genesis_outpoint``
      IS "this exact asset", not merely "a genuine glyph";
  (e) the genesis tx has **≥ ``min_confirmations``** confirmations — a shallow
      genesis can be reorged out after the taker pays, retroactively voiding the
      provenance the taker relied on.

Async note (T7 plan D2): the indexer adapter (``glyph.get_token``) is async, so
``resolve_ref`` and ``verify_ref_authenticity`` are ``async def``. A *sync* gate
calling the async indexer would receive an un-awaited coroutine — which is
truthy — and **fail OPEN**, the exact catastrophe this gate exists to prevent.
Callers MUST ``await`` it; a non-awaited coroutine cannot satisfy the gate.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from pyrxd.security.errors import ValidationError

__all__ = ["RefAuthenticityIndexer", "ResolvedRef", "verify_ref_authenticity"]


@dataclass(frozen=True)
class ResolvedRef:
    """A trusted indexer's resolution of a genesis ref to its on-chain reveal.

    This is the inspectable surface the gate binds against — the gate does NOT
    trust a bare boolean from the indexer; it re-checks each field against what
    the taker agreed to. A real adapter populates this from the indexer's
    ``glyph.get_token`` response (``ref_outpoint``/``payload_hash``/confirmations
    + a decoded ``gly`` marker); a test fake constructs it directly.

    Attributes
    ----------
    genesis_outpoint:
        The 36-byte genesis outpoint (txid||vout) the indexer says this token was
        minted at. Binding (a)/(d): MUST equal the advertised ``genesis_ref``.
    has_gly_marker:
        True iff the reveal carries a ``gly`` envelope (binding (b)). A bare
        singleton on a plain wallet UTXO has none — the exact R1 forgery.
    payload_hash:
        The reveal's payload-commitment hash (binding (c)), or ``b""`` if the
        indexer did not supply one.
    confirmations:
        Confirmations on the genesis tx (binding (e)). A negative/None value is
        treated as fail-closed by the gate.
    """

    genesis_outpoint: bytes
    has_gly_marker: bool
    payload_hash: bytes
    confirmations: int


@runtime_checkable
class RefAuthenticityIndexer(Protocol):
    """The minimal indexer surface needed to verify a genesis REF is real.

    Implementations resolve a genesis-outpoint ref to its on-chain reveal as a
    :class:`ResolvedRef`. ``resolve_ref`` is **async** (the underlying
    ``glyph.get_token`` RPC is async) and MUST raise (not return ``None``
    optimistically) when the indexer cannot reach a definitive answer — the
    caller treats ``None``, any missing/invalid field, or any exception as
    fail-closed. Returning ``None`` means "no such token" (also fail-closed).
    """

    async def resolve_ref(self, genesis_ref: bytes) -> ResolvedRef | None:
        """Resolve ``genesis_ref`` to its reveal, or ``None`` if unknown."""
        ...


async def verify_ref_authenticity(
    indexer: RefAuthenticityIndexer,
    genesis_ref: bytes,
    *,
    asset_variant: str,
    min_confirmations: int,
    expected_payload_hash: bytes | None = None,
) -> None:
    """Hard pre-payment gate: confirm the covenant's REF is a real minted asset.

    ``await`` this BEFORE the taker pays any BTC for an FT/NFT swap. Plain-RXD
    swaps carry no ref and are skipped. Enforces the five bindings (a)-(e)
    documented at module level and fails closed on EVERY uncertain outcome:
    indexer unreachable/error, ``None`` (unknown token), a missing/invalid
    field, genesis-outpoint ≠ ref, absent ``gly`` marker, payload mismatch, or a
    genesis shallower than ``min_confirmations``.

    Args:
        indexer: a trusted :class:`RefAuthenticityIndexer`. A lying or
            attacker-controlled indexer defeats this gate — the taker must use an
            indexer they trust (the audit-gated track adds SPV/multi-source
            cross-checking; a single indexer is a SPOF, see T7 plan D3).
        genesis_ref: the 36-byte genesis outpoint ref baked into the covenant.
            This IS the advertised asset's identity (binding d).
        asset_variant: "rxd" | "ft" | "nft". Only ft/nft carry a ref to verify.
        min_confirmations: required confirmations on the genesis tx (binding e).
            Must be a non-negative int.
        expected_payload_hash: if the taker agreed to a specific payload, the
            reveal's payload hash MUST match it (binding c). ``None`` skips this
            single binding (the others still apply).

    Raises:
        ValidationError: if the ref is not provably the advertised authentic
            asset. The caller MUST NOT pay the counter-leg (BTC or ETH) when this raises.
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
    ref = bytes(genesis_ref)
    if not isinstance(min_confirmations, int) or isinstance(min_confirmations, bool) or min_confirmations < 0:
        raise ValidationError("min_confirmations must be a non-negative int (fail-closed)")
    if expected_payload_hash is not None and not isinstance(expected_payload_hash, (bytes, bytearray)):
        raise ValidationError("expected_payload_hash must be bytes or None")
    if not isinstance(indexer, RefAuthenticityIndexer):
        raise ValidationError("indexer does not implement resolve_ref — cannot authenticate REF; fail-closed")

    try:
        resolved = await indexer.resolve_ref(ref)
    except Exception as exc:  # indexer unreachable/lagging/error => fail-closed.
        raise ValidationError(
            f"indexer could not resolve REF ({exc}); fail-closed — do NOT pay the counter-leg. "
            "Consensus does NOT enforce mint provenance (rigorous audit R1)."
        ) from exc

    # None => unknown token. Type-check the result so a malformed adapter (or a
    # mis-typed fake, or an un-awaited coroutine slipping through) fails closed
    # rather than passing on a truthy non-ResolvedRef object.
    if resolved is None:
        raise ValidationError(
            "indexer returned no token for REF — it does not resolve to a minted asset. "
            "The covenant's singleton may be a forged/self-crafted ref (rigorous audit R1). Do NOT pay the counter-leg."
        )
    if not isinstance(resolved, ResolvedRef):
        raise ValidationError(
            f"indexer returned {type(resolved).__name__}, not a ResolvedRef; fail-closed. "
            "(A sync gate calling the async indexer would leak an un-awaited coroutine here — fail-open guard.)"
        )

    # Binding (a)/(d): the genesis outpoint must equal the advertised ref. The
    # ref IS the asset identity, so this rejects a genuine-but-different glyph.
    if not isinstance(resolved.genesis_outpoint, (bytes, bytearray)) or bytes(resolved.genesis_outpoint) != ref:
        raise ValidationError(
            "resolved token's genesis outpoint does not equal the advertised REF — wrong/forged asset. "
            "(REF is the genesis outpoint, NOT the reveal txid.) Do NOT pay the counter-leg."
        )

    # Binding (b): a real Glyph reveal carries a `gly` envelope marker.
    if resolved.has_gly_marker is not True:
        raise ValidationError(
            "resolved REF carries no `gly` envelope marker — it is a bare singleton, not a minted Glyph "
            "(the exact R1 forgery). Do NOT pay the counter-leg."
        )

    # Binding (c): payload commitment, when the taker agreed to a specific one.
    if expected_payload_hash is not None and (
        not isinstance(resolved.payload_hash, (bytes, bytearray))
        or bytes(resolved.payload_hash) != bytes(expected_payload_hash)
    ):
        raise ValidationError(
            "resolved REF payload hash does not match the advertised payload — wrong asset content. Do NOT pay the counter-leg."
        )

    # Binding (e): the genesis must be deep enough that a reorg cannot void it.
    confs = resolved.confirmations
    if not isinstance(confs, int) or isinstance(confs, bool) or confs < min_confirmations:
        raise ValidationError(
            f"genesis tx has {confs} confirmations < required {min_confirmations}; a shallow genesis can be "
            "reorged out after payment, voiding provenance. Do NOT pay the counter-leg."
        )
