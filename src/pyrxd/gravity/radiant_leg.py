"""Concrete Radiant covenant leg for the Gravity Taproot-HTLC atomic swap.

This is the production ``radiant_leg`` the
:class:`pyrxd.gravity.swap_coordinator.SwapCoordinator` drives (the coordinator
tests use a duck-typed fake; this is the real object). It composes:

* :mod:`pyrxd.gravity.htlc_covenant` — the funded covenant SPK builders;
* :mod:`pyrxd.gravity.htlc_spend` — the claim (preimage) / refund (CSV) TX builders;
* a :class:`RadiantChainIO` over :class:`pyrxd.network.electrumx.ElectrumXClient`
  for broadcast + confirmation polling + reading the funded covenant value;
* a :class:`SeenStore` (in-memory) for H-freshness.

Plus a :class:`RxinDexerRefAdapter` that resolves a genesis ref to a
:class:`pyrxd.gravity.ref_authenticity.ResolvedRef` via the RXinDexer
``glyph.get_token`` RPC, so the coordinator's pre-lock REF-authenticity gate has a
real backend.

Design notes (T7 plan D5/D6, reviewed)
--------------------------------------
* ``RadiantChainIO`` is a thin helper (broadcast + wait_confirmations + read UTXO),
  NOT unified with :class:`pyrxd.gravity.trade.GravityTrade` — that drives the
  *different* SPV-oracle finalize swap.
* The leg holds the party's own Radiant pkhs (taker + maker) so it can build the
  covenant and the spend holder outputs. ``expected_covenant_scriptpubkey`` builds
  the covenant from the negotiated terms and **asserts the resulting
  ``hash256(holder)`` binds equal the terms' ``taker_dest_hash``/``maker_dest_hash``**
  — fail-closed if the leg's configured pkhs don't produce the covenant the terms
  committed to (a wrong-key/wrong-party guard).
* ``carrier_value`` (the funded covenant output value) is read from the on-chain
  UTXO, never self-reported.
* **AUDIT GATE:** reuses :func:`pyrxd.btc_wallet.htlc_leg.require_audit_cleared` —
  the leg refuses to construct for a value-bearing network without the explicit
  opt-in (the always-succeeding fakes hide the one-sided-loss surface).
* ``SeenStore`` is an in-memory ``set`` for this milestone (a SQLite durable store
  is deferred to the audit-gated track; a blocking ``sqlite3`` call would stall the
  async loop). The duck-typed ``has_seen``/``mark_seen`` shape lets a durable store
  drop in later.
"""

from __future__ import annotations

import logging
from typing import Protocol, runtime_checkable

from pyrxd.btc_wallet.htlc_leg import require_audit_cleared
from pyrxd.btc_wallet.taproot import TimeUnit
from pyrxd.glyph.types import GlyphRef
from pyrxd.gravity.htlc_covenant import (
    HtlcCovenant,
    build_htlc_covenant_ft,
    build_htlc_covenant_nft,
    build_htlc_covenant_rxd,
)
from pyrxd.gravity.htlc_spend import FeeInput, build_htlc_claim_tx, build_htlc_refund_tx
from pyrxd.gravity.ref_authenticity import ResolvedRef
from pyrxd.gravity.swap_state import NegotiatedTerms, SwapRecord
from pyrxd.security.errors import NetworkError, ValidationError
from pyrxd.security.types import Hex20

__all__ = [
    "FeeUtxoSource",
    "RadiantBroadcaster",
    "RadiantChainIO",
    "RadiantCovenantLeg",
    "RxinDexerRefAdapter",
    "SeenStore",
]

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- SeenStore


class SeenStore:
    """In-memory H-freshness store (the coordinator's ``reserve``/``has_seen``).

    Records every hashlock H the coordinator has committed to funding, so a reused
    H is rejected for BOTH reasons: economic (free-option replay) and cross-swap
    preimage replay. ``reserve(H)`` is the authoritative atomic test-and-set the
    coordinator calls PRE-broadcast; ``has_seen`` is a read-only advisory probe
    (the pre-lock gate's cheap early-reject), never the binding decision.

    NON-DURABLE (``durable = False``): a plain ``set``, so freshness does NOT
    survive a restart or a second process. That is acceptable only for a
    single-process, single-shot run that mints a fresh H per swap (the dust
    runbook); the coordinator's construct-time guard refuses this store on a
    value-bearing network unless the operator passes
    ``CoordinatorConfig(accept_nondurable_seen=True)``. A durable replacement
    (SQLite ``INSERT OR IGNORE`` keyed on H, declaring ``durable = True``) is
    deferred to the external-audit track; it MUST stay non-blocking
    (``asyncio.to_thread`` behind an async ``reserve``) and fsync the reservation
    BEFORE the BTC broadcast. The method shape is duck-compatible so that durable
    store drops in unchanged.
    """

    durable = False

    def __init__(self) -> None:
        self._seen: set[bytes] = set()

    def reserve(self, hashlock: bytes) -> bool:
        """Atomically record H if unseen; True if freshly reserved, else False.

        Atomic on the single-threaded event loop precisely because there is no
        ``await`` between the membership test and the add.
        """
        h = bytes(hashlock)
        if h in self._seen:
            return False
        self._seen.add(h)
        return True

    def has_seen(self, hashlock: bytes) -> bool:
        return bytes(hashlock) in self._seen

    def mark_seen(self, hashlock: bytes) -> None:
        # Retained as an unused primitive for the roundtrip test + back-compat; the
        # coordinator's authoritative consume is reserve() (atomic, pre-broadcast).
        self._seen.add(bytes(hashlock))


# --------------------------------------------------------------------------- chain IO


@runtime_checkable
class RadiantBroadcaster(Protocol):
    """Submit a raw Radiant tx; idempotent on an already-known tx."""

    async def broadcast(self, raw_tx: bytes) -> str:  # pragma: no cover - Protocol
        ...


class RadiantChainIO:
    """Thin chain helper over an ``ElectrumXClient``-like object.

    Provides exactly what the leg needs: broadcast, confirmation depth, and the
    on-chain value of a covenant output. NOT unified with ``GravityTrade`` (that
    drives the SPV-oracle finalize swap, a different protocol).

    The injected ``client`` must expose ``broadcast(raw)->txid``,
    ``get_transaction_verbose(txid)->dict`` (with ``confirmations``), and
    ``get_utxos(script_hash)->list`` (records with ``tx_hash``/``tx_pos``/``value``).
    """

    def __init__(self, client) -> None:
        for m in ("broadcast", "get_transaction_verbose", "get_utxos"):
            if not hasattr(client, m):
                raise ValidationError(f"RadiantChainIO client must provide {m}()")
        self._client = client

    async def broadcast(self, raw_tx: bytes) -> str:
        if not isinstance(raw_tx, (bytes, bytearray)) or len(raw_tx) == 0:
            raise ValidationError("raw_tx must be non-empty bytes")
        try:
            return str(await self._client.broadcast(bytes(raw_tx)))
        except Exception as exc:
            msg = str(exc).lower()
            if "already" in msg and ("known" in msg or "mempool" in msg or "chain" in msg):
                # Idempotent: the node already has it. Re-derive nothing; the caller
                # tracks the txid from the builder. Surface a sentinel for the leg.
                raise _AlreadyKnown() from exc
            raise NetworkError(f"radiant broadcast failed: {exc}") from exc

    async def confirmations(self, txid: str) -> int:
        info = await self._client.get_transaction_verbose(txid)
        if not isinstance(info, dict):
            raise NetworkError("get_transaction_verbose did not return a dict")
        return int(info.get("confirmations", 0) or 0)

    async def find_covenant_utxo(self, spk: bytes, *, expected_value: int | None = None) -> tuple[str, int, int]:
        """Locate the funded covenant UTXO for ``spk`` -> ``(outpoint, value, height)``.

        Scans the UTXO set of the covenant scriptPubKey (ElectrumX script-hash =
        ``sha256(spk)`` reversed). The covenant funds exactly one output, so there
        is one matching UTXO; if ``expected_value`` is given, the match must equal it
        (a wrong value is a mis-funded covenant -> fail-closed). The returned value
        is the ON-CHAIN value, never a self-report.
        """
        import hashlib

        script_hash = hashlib.sha256(bytes(spk)).digest()[::-1]
        utxos = await self._client.get_utxos(script_hash)
        if not utxos:
            raise NetworkError("no UTXO found for the covenant scriptPubKey (not yet funded / wrong SPK)")
        if expected_value is not None:
            utxos = [u for u in utxos if int(u.value) == int(expected_value)]
            if not utxos:
                raise NetworkError("no covenant UTXO matches the expected carrier value; fail-closed")
        if len(utxos) > 1:
            raise NetworkError(f"ambiguous covenant UTXO set ({len(utxos)} candidates); fail-closed")
        u = utxos[0]
        return f"{u.tx_hash}:{u.tx_pos}", int(u.value), int(u.height)


class _AlreadyKnown(Exception):
    """Internal sentinel: a broadcast hit an already-known tx (idempotent success)."""


# --------------------------------------------------------------------------- ref adapter


class RxinDexerRefAdapter:
    """Resolve a genesis ref to a :class:`ResolvedRef` via RXinDexer ``glyph.get_token``.

    Implements the ``RefAuthenticityIndexer`` protocol the pre-lock gate awaits.
    Maps the indexer's token dict to the inspectable fields the gate binds:

    * **genesis_outpoint** — from the token's ``ref_outpoint`` (``txid:vout``),
      re-encoded to the 36-byte wire ref so it compares equal to the advertised
      ``genesis_ref``. (``glyph.get_token`` only returns genuinely-minted Glyph
      tokens, so a resolvable token IS a ``gly`` reveal — see ``has_gly_marker``.)
    * **has_gly_marker** — ``True`` whenever the indexer returned a token dict for
      the ref (the indexer only indexes real ``gly`` envelopes). A bare wallet-UTXO
      singleton (the R1 forgery) resolves to ``None`` and the gate fails closed.
    * **payload_hash** — from ``payload_hash`` (bytes), or ``b""`` if absent.
    * **confirmations** — read separately from the genesis tx via ``chain_io``
      (``glyph.get_token`` does not carry confs).

    NOTE (T7 plan D3): a single indexer is a SPOF, and decoding a token dict is NOT
    SPV authenticity (no Merkle/header binding). For the regtest milestone the local
    node is ground truth; SPV-bound / multi-source cross-checking is the audit-gated
    track. This adapter is the single-indexer regtest backend.
    """

    def __init__(self, indexer, chain_io: RadiantChainIO) -> None:
        if not hasattr(indexer, "glyph_get_token"):
            raise ValidationError("indexer must provide glyph_get_token()")
        if not isinstance(chain_io, RadiantChainIO):
            raise ValidationError("chain_io must be a RadiantChainIO")
        self._indexer = indexer
        self._chain_io = chain_io

    async def resolve_ref(self, genesis_ref: bytes) -> ResolvedRef | None:
        ref = GlyphRef.from_bytes(bytes(genesis_ref))  # raises on malformed -> gate fail-closed
        token = await self._indexer.glyph_get_token(f"{ref.txid}:{ref.vout}")
        if token is None:
            return None  # unknown token -> the gate fails closed (R1 forgery)
        if not isinstance(token, dict):
            raise NetworkError(f"glyph_get_token returned {type(token).__name__}, expected dict|None")

        resolved_outpoint = self._genesis_outpoint(token, ref)
        payload_hash = self._payload_hash(token)
        confs = await self._chain_io.confirmations(ref.txid)
        return ResolvedRef(
            genesis_outpoint=resolved_outpoint,
            has_gly_marker=True,  # glyph.get_token only resolves real gly reveals
            payload_hash=payload_hash,
            confirmations=confs,
        )

    @staticmethod
    def _genesis_outpoint(token: dict, queried: GlyphRef) -> bytes:
        """Re-encode the token's reported genesis outpoint to the 36-byte wire ref.

        Prefers an explicit ``ref_outpoint`` (``txid:vout``); falls back to
        ``ref_txid``+``ref_vout``. If the indexer reports neither, we cannot bind
        provenance -> return a value that will NOT equal the advertised ref, so the
        gate's genesis-outpoint==ref binding fails closed.
        """
        outpoint = token.get("ref_outpoint")
        if isinstance(outpoint, str) and outpoint.count(":") == 1:
            txid, vout_s = outpoint.split(":")
            try:
                return GlyphRef(txid=txid, vout=int(vout_s)).to_bytes()
            except (ValidationError, ValueError):
                return b"\x00" * 36
        txid = token.get("ref_txid")
        vout = token.get("ref_vout")
        if isinstance(txid, str) and isinstance(vout, int):
            try:
                return GlyphRef(txid=txid, vout=vout).to_bytes()
            except (ValidationError, ValueError):
                return b"\x00" * 36
        # No outpoint reported -> cannot confirm it equals the advertised ref.
        return b"\x00" * 36

    @staticmethod
    def _payload_hash(token: dict) -> bytes:
        ph = token.get("payload_hash")
        if isinstance(ph, str):
            try:
                return bytes.fromhex(ph)
            except ValueError:
                return b""
        if isinstance(ph, (bytes, bytearray)):
            return bytes(ph)
        return b""


# --------------------------------------------------------------------------- fee source


@runtime_checkable
class FeeUtxoSource(Protocol):
    """Supplies a plain-RXD fee UTXO (+ its WIF) for a covenant spend."""

    def next_fee_input(self) -> FeeInput:  # pragma: no cover - Protocol
        ...


# --------------------------------------------------------------------------- the leg


class RadiantCovenantLeg:
    """The concrete Radiant ``radiant_leg`` (HTLC covenant claim/refund).

    Parameters
    ----------
    network:
        Radiant network tag (regtest test chains bypass the audit gate).
    taker_pkh / maker_pkh:
        The taker (claim) and maker (refund) Radiant holder pubkey-hashes. The
        covenant binds ``hash256(holder(pkh))``; these must reproduce the terms'
        ``taker_dest_hash``/``maker_dest_hash`` (asserted in
        :meth:`expected_covenant_scriptpubkey`).
    chain_io:
        A :class:`RadiantChainIO` (broadcast + confirmations + UTXO value).
    fee_source:
        A :class:`FeeUtxoSource` supplying the fee input for each spend.
    min_confirmations:
        Confirmations required before the funded covenant value is trusted.
    audit_cleared:
        Explicit opt-in for a value-bearing ``network`` (see
        :func:`pyrxd.btc_wallet.htlc_leg.require_audit_cleared`).
    """

    def __init__(
        self,
        *,
        network: str,
        taker_pkh: bytes,
        maker_pkh: bytes,
        chain_io: RadiantChainIO,
        fee_source: FeeUtxoSource,
        min_confirmations: int = 1,
        audit_cleared: bool = False,
    ) -> None:
        require_audit_cleared(network, audit_cleared=audit_cleared)
        if not isinstance(chain_io, RadiantChainIO):
            raise ValidationError("chain_io must be a RadiantChainIO")
        if not isinstance(fee_source, FeeUtxoSource):
            raise ValidationError("fee_source must implement next_fee_input()")
        if not isinstance(min_confirmations, int) or isinstance(min_confirmations, bool) or min_confirmations < 0:
            raise ValidationError("min_confirmations must be a non-negative int")
        self.network = network
        self.taker_pkh = bytes(Hex20(taker_pkh))
        self.maker_pkh = bytes(Hex20(maker_pkh))
        self.chain_io = chain_io
        self.fee_source = fee_source
        self.min_confirmations = min_confirmations

    # -- covenant construction (binds the leg's pkhs to the terms) ----------
    def _build_covenant(self, terms: NegotiatedTerms) -> HtlcCovenant:
        if not isinstance(terms, NegotiatedTerms):
            raise ValidationError("terms must be a NegotiatedTerms")
        # F-002 (belt-and-suspenders; NegotiatedTerms already enforces this): the
        # covenant CSV operand is a BIP68 BLOCK count with no SECONDS path on this
        # leg, so terms.t_rxd.value is used raw as refund_csv. Refuse a non-BLOCKS
        # t_rxd fail-closed rather than silently coercing it.
        if terms.t_rxd.unit is not TimeUnit.BLOCKS:
            raise ValidationError("Radiant leg requires a BLOCKS t_rxd (no SECONDS CSV encoding); fail-closed")
        variant = terms.asset_variant
        if variant == "rxd":
            cov = build_htlc_covenant_rxd(
                amount=terms.radiant_amount,
                taker_pkh=self.taker_pkh,
                maker_pkh=self.maker_pkh,
                hashlock=terms.hashlock,
                refund_csv=terms.t_rxd.value,
            )
        else:
            ref = GlyphRef.from_bytes(terms.genesis_ref)
            if variant == "ft":
                cov = build_htlc_covenant_ft(
                    genesis_txid=ref.txid,
                    genesis_vout=ref.vout,
                    amount=terms.radiant_amount,
                    taker_pkh=self.taker_pkh,
                    maker_pkh=self.maker_pkh,
                    hashlock=terms.hashlock,
                    refund_csv=terms.t_rxd.value,
                )
            elif variant == "nft":
                cov = build_htlc_covenant_nft(
                    genesis_txid=ref.txid,
                    genesis_vout=ref.vout,
                    nft_carrier_value=terms.radiant_amount,
                    taker_pkh=self.taker_pkh,
                    maker_pkh=self.maker_pkh,
                    hashlock=terms.hashlock,
                    refund_csv=terms.t_rxd.value,
                )
            else:  # pragma: no cover - NegotiatedTerms already constrains the variant
                raise ValidationError(f"unsupported asset_variant {variant!r}")

        # Bind the leg's configured pkhs to what the terms committed: the covenant's
        # hash256(holder) MUST equal the negotiated dest hashes, else the leg is
        # configured for the wrong party/keys — fail closed before any spend.
        if cov.expected_taker_hash != terms.taker_dest_hash:
            raise ValidationError("covenant taker hash != terms.taker_dest_hash (wrong taker pkh?); fail-closed")
        if cov.expected_maker_hash != terms.maker_dest_hash:
            raise ValidationError("covenant maker hash != terms.maker_dest_hash (wrong maker pkh?); fail-closed")
        return cov

    async def expected_covenant_scriptpubkey(self, terms: NegotiatedTerms) -> bytes:
        """The covenant SPK the on-chain lock must equal (built from the terms)."""
        return self._build_covenant(terms).funded_spk

    async def covenant_outpoint(self, terms: NegotiatedTerms) -> str:
        """Locate the funded covenant UTXO ``txid:vout`` by scanning its SPK's UTXO set.

        The maker locks the asset into the covenant SPK (a pure function of the
        terms); the leg finds that single funded UTXO on-chain via ElectrumX. The
        carrier value is bound to ``terms.radiant_amount`` so a mis-funded covenant
        fails closed.
        """
        cov = self._build_covenant(terms)
        outpoint, _value, _height = await self.chain_io.find_covenant_utxo(
            cov.funded_spk, expected_value=terms.radiant_amount
        )
        return outpoint

    # -- spends -------------------------------------------------------------
    async def _resolve_covenant(self, record: SwapRecord) -> tuple[HtlcCovenant, str, int]:
        """Build the covenant, locate its funded UTXO, conf-gate it, return value.

        Reads the on-chain value (never a self-report) and rejects a covenant
        shallower than ``min_confirmations`` so a reorg cannot un-fund it mid-spend.
        """
        cov = self._build_covenant(record.terms)
        outpoint, value, _height = await self.chain_io.find_covenant_utxo(
            cov.funded_spk, expected_value=record.terms.radiant_amount
        )
        txid = outpoint.split(":")[0]
        confs = await self.chain_io.confirmations(txid)
        if confs < self.min_confirmations:
            raise NetworkError(
                f"covenant has {confs} confirmations < required {self.min_confirmations}; not yet spendable"
            )
        if (
            value <= 0
        ):  # pragma: no cover - defense-in-depth; find_covenant_utxo already pins value>0 via expected_value
            raise NetworkError("covenant output value is non-positive; fail-closed")
        return cov, outpoint, value

    async def claim_asset(self, record: SwapRecord, preimage: bytes) -> str:
        """Build + broadcast the TAKER's claim spend (reveals ``p``). Returns the txid."""
        if not isinstance(record, SwapRecord):
            raise ValidationError("record must be a SwapRecord")
        cov, outpoint, carrier = await self._resolve_covenant(record)
        tx = build_htlc_claim_tx(
            covenant=cov,
            covenant_outpoint=outpoint,
            carrier_value=carrier,
            preimage=bytes(preimage),
            fee=self.fee_source.next_fee_input(),
        )
        return await self._broadcast(tx)

    async def refund_asset(self, record: SwapRecord) -> str:
        """Build + broadcast the MAKER's CSV refund spend. Returns the txid."""
        if not isinstance(record, SwapRecord):
            raise ValidationError("record must be a SwapRecord")
        cov, outpoint, carrier = await self._resolve_covenant(record)
        tx = build_htlc_refund_tx(
            covenant=cov,
            covenant_outpoint=outpoint,
            carrier_value=carrier,
            fee=self.fee_source.next_fee_input(),
        )
        return await self._broadcast(tx)

    async def _broadcast(self, tx) -> str:
        raw = tx.serialize()
        try:
            return await self.chain_io.broadcast(raw)
        except _AlreadyKnown:
            # Idempotent: the node already has this exact tx -> its txid is authoritative.
            return tx.txid()
