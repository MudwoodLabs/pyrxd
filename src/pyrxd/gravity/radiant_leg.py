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

import contextlib
import logging
from typing import Protocol, runtime_checkable

from pyrxd.btc_wallet.htlc_leg import require_audit_cleared
from pyrxd.btc_wallet.taproot import TimeUnit
from pyrxd.glyph.types import GlyphRef
from pyrxd.gravity.fee_policy import (
    DEFAULT_RADIANT_DEADLINE_FEE_POLICY,
    DeadlineFeePolicy,
    assert_fee_covers,
)
from pyrxd.gravity.htlc_covenant import (
    HtlcCovenant,
    build_htlc_covenant_ft,
    build_htlc_covenant_nft,
    build_htlc_covenant_rxd,
)
from pyrxd.gravity.htlc_spend import FeeInput, build_htlc_claim_tx, build_htlc_refund_tx
from pyrxd.gravity.ref_authenticity import ResolvedRef
from pyrxd.gravity.swap_state import NegotiatedTerms, SwapRecord
from pyrxd.network._guards import finite_int
from pyrxd.security.errors import InsufficientFundsError, NetworkError, ValidationError
from pyrxd.security.types import Hex20

_LOG = logging.getLogger(__name__)

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
        # This is the RXD covenant leg's confirmation gate, and it was a bare
        # `int(info.get("confirmations", 0) or 0)`: a string "999999" coerced to a depth, and a
        # JSON `Infinity` raised OverflowError — not a NetworkError, so it escaped every
        # `except NetworkError` on a value-moving path as a bare traceback. The `or 0` keeps a
        # present-but-falsy value reading as depth 0, which is the fail-closed direction.
        raw = info.get("confirmations", 0) or 0
        try:
            depth = finite_int(raw)
        except ValueError as exc:
            raise NetworkError("node reported an unreadable confirmation depth; fail-closed") from exc
        return depth if depth > 0 else 0

    async def find_covenant_utxo(
        self, spk: bytes, *, expected_value: int | None = None, pin_outpoint: str | None = None
    ) -> tuple[str, int, int]:
        """Locate the funded covenant UTXO for ``spk`` -> ``(outpoint, value, height)``.

        Scans the UTXO set of the covenant scriptPubKey (ElectrumX script-hash =
        ``sha256(spk)`` reversed). The covenant funds exactly one output, so there
        is one matching UTXO; if ``expected_value`` is given, the match must equal it
        (a wrong value is a mis-funded covenant -> fail-closed). The returned value
        is the ON-CHAIN value, never a self-report.
        """
        import hashlib

        # A script-hash-keyed client (e.g. SshTrRadiantClient via scantxoutset) can only
        # resolve a script_hash back to its SPK from a registry; an UNregistered covenant
        # SPK scans EMPTY and is misread as "not funded / already spent". A fresh per-swap
        # claim leg (sidecar_leg_resolver) never pre-registers, so register the SPK we are
        # about to scan here — idempotent, and a no-op for clients without register_spk.
        register = getattr(self._client, "register_spk", None)
        if callable(register):
            register(bytes(spk))
        script_hash = hashlib.sha256(bytes(spk)).digest()[::-1]
        utxos = await self._client.get_utxos(script_hash)
        if not utxos:
            raise NetworkError("no UTXO found for the covenant scriptPubKey (not yet funded / wrong SPK)")
        if expected_value is not None:
            utxos = [u for u in utxos if int(u.value) == int(expected_value)]
            if not utxos:
                raise NetworkError("no covenant UTXO matches the expected carrier value; fail-closed")
        if pin_outpoint is not None:
            # PIN, do not re-discover. The covenant scriptPubKey is a pure function of PUBLIC
            # negotiated terms, so anyone can pay it — and a second payment of the same value makes
            # this scan ambiguous. Refusing on ambiguity then denies the spend, which turns a
            # payment anyone can make into a permanent block on the taker's claim while the maker
            # waits out the CSV and refunds. Once the funded outpoint is known there is nothing to
            # discover: select it and ignore the noise. The value filter above still applies to it,
            # so a record pointing at a wrong-value output is still refused.
            picked = [u for u in utxos if f"{u.tx_hash}:{u.tx_pos}" == pin_outpoint]
            if not picked:
                raise NetworkError(
                    f"the recorded covenant outpoint {pin_outpoint} is not in this scriptPubKey's "
                    "live UTXO set — it has been spent, reorged out, or the record is wrong; "
                    "fail-closed"
                )
            utxos = picked
        if len(utxos) > 1:
            # SELECT, do not refuse. Refusing here was still the attack: the pin's only WRITER
            # comes through this discovery path, so poisoning the address BEFORE the outpoint is
            # recorded stopped the pin from ever being written — and every later spend then ran
            # unpinned, back to the original brick. A refusal that can be triggered by anyone
            # paying a public address is a denial, not a defence.
            #
            # Deterministic rule: the EARLIEST-confirmed match. The honest funding necessarily
            # precedes any poison (the address is only interesting once it is funded), and both
            # parties derive the same answer from the same chain, which a "deepest" or "first
            # returned" rule would not guarantee across differing UTXO orderings. Height 0 means
            # unconfirmed, which sorts last — a mempool output must never displace a mined one.
            utxos = sorted(utxos, key=lambda u: (int(u.height) if int(u.height) > 0 else 1 << 62, u.tx_hash, u.tx_pos))
            _LOG.warning(
                "covenant scriptPubKey has %d matching UTXOs; selecting the earliest-confirmed "
                "(%s:%d at height %s). Extra payments to a covenant address are anyone's to make "
                "and must not block the spend.",
                len(utxos),
                utxos[0].tx_hash,
                utxos[0].tx_pos,
                utxos[0].height,
            )
        u = utxos[0]
        return f"{u.tx_hash}:{u.tx_pos}", int(u.value), int(u.height)

    async def covenant_unspent_incl_mempool(self, outpoint: str) -> bool | None:
        """Mempool-AWARE liveness of a covenant outpoint — the complement to
        ``find_covenant_utxo``'s mempool-BLIND scantxoutset scan.

        ``True`` = unspent considering the mempool; ``False`` = spent (confirmed OR by a
        PENDING mempool tx); ``None`` = the client cannot answer (the caller keeps its own
        idempotency guard). Lets the autonomous claim executor treat a covenant already spent
        IN THE MEMPOOL as claimed — killing the per-tick re-carve drain WITHOUT a durable
        cross-restart store and WITHOUT the SeenStore's eviction blind spot (a truly-unspent
        covenant, e.g. after a claim is evicted by a reorg, correctly re-fires).
        """
        fn = getattr(self._client, "txout_unspent_incl_mempool", None)
        if not callable(fn):
            return None
        txid, _sep, vout = outpoint.partition(":")
        if not _sep or not vout.isdigit():
            raise ValidationError(f"bad covenant outpoint {outpoint!r}")
        return bool(await fn(txid, int(vout)))


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

        RXinDexer's ``glyph.get_token`` reports the genesis outpoint under
        ``glyph_id`` (``txid:vout``), alongside ``txid``+``vout`` and an
        ``is_reveal`` flag (verified against a live regtest RXinDexer 2026-06-01:
        a genuine reveal resolves with ``glyph_id == queried`` and
        ``is_reveal=True``; the commit outpoint and bare wallet UTXOs resolve to
        ``None``). We also accept the legacy ``ref_outpoint`` / ``ref_txid`` +
        ``ref_vout`` field names as fallbacks for other indexer builds.

        The token must be a genesis REVEAL for the outpoint to be a genesis: a
        transfer UTXO would report the genesis under ``glyph_id`` but is itself a
        different outpoint than ``queried``, so the gate's
        ``genesis_outpoint == advertised_ref`` binding would (correctly) reject it.
        If the indexer reports no resolvable outpoint, we return a value that will
        NOT equal the advertised ref, so the binding fails closed.
        """
        # RXinDexer native: glyph_id == "txid:vout" of the genesis reveal.
        glyph_id = token.get("glyph_id")
        if isinstance(glyph_id, str) and glyph_id.count(":") == 1:
            txid, vout_s = glyph_id.split(":")
            try:
                return GlyphRef(txid=txid, vout=int(vout_s)).to_bytes()
            except (ValidationError, ValueError):
                return b"\x00" * 36
        # RXinDexer native: separate txid + vout fields.
        txid = token.get("txid")
        vout = token.get("vout")
        if isinstance(txid, str) and isinstance(vout, int) and not isinstance(vout, bool):
            try:
                return GlyphRef(txid=txid, vout=vout).to_bytes()
            except (ValidationError, ValueError):
                return b"\x00" * 36
        # Legacy/alternate indexer field names.
        outpoint = token.get("ref_outpoint")
        if isinstance(outpoint, str) and outpoint.count(":") == 1:
            txid, vout_s = outpoint.split(":")
            try:
                return GlyphRef(txid=txid, vout=int(vout_s)).to_bytes()
            except (ValidationError, ValueError):
                return b"\x00" * 36
        rtxid = token.get("ref_txid")
        rvout = token.get("ref_vout")
        if isinstance(rtxid, str) and isinstance(rvout, int) and not isinstance(rvout, bool):
            try:
                return GlyphRef(txid=rtxid, vout=rvout).to_bytes()
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
    fee_policy:
        The :class:`~pyrxd.gravity.fee_policy.DeadlineFeePolicy` the pre-broadcast
        affordability gate enforces. Defaults to the reference node's advertised
        0.10 RXD/kB effective relay rate; pass an explicit policy when the node this
        leg broadcasts to advertises a different ``effective_minrelaytxfee``.
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
        fee_policy: DeadlineFeePolicy | None = None,
    ) -> None:
        require_audit_cleared(network, audit_cleared=audit_cleared)
        if not isinstance(chain_io, RadiantChainIO):
            raise ValidationError("chain_io must be a RadiantChainIO")
        if not isinstance(fee_source, FeeUtxoSource):
            raise ValidationError("fee_source must implement next_fee_input()")
        if not isinstance(min_confirmations, int) or isinstance(min_confirmations, bool) or min_confirmations < 0:
            raise ValidationError("min_confirmations must be a non-negative int")
        if fee_policy is not None and not isinstance(fee_policy, DeadlineFeePolicy):
            raise ValidationError("fee_policy must be a DeadlineFeePolicy or None")
        self.fee_policy = fee_policy or DEFAULT_RADIANT_DEADLINE_FEE_POLICY
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

    async def verify_maker_asset_funded(
        self, terms: NegotiatedTerms, *, min_confirmations: int | None = None
    ) -> tuple[str, int, int]:
        """TAKER-side fail-closed gate: is the MAKER's asset really locked, at the agreed value,
        buried deep enough, before the taker funds the counter leg? Returns
        ``(outpoint, value_photons, confirmations)``; RAISES on anything else — the taker MUST NOT
        lock BTC/ETH if this raises. The Radiant twin of
        :meth:`pyrxd.btc_wallet.htlc_leg.BitcoinTaprootLeg.verify_counterparty_funded`.

        WHY: ``docs/htlc-handshake-wire-format.md`` HZ-1 states it normatively — *"a taker MUST NOT
        fund the counter leg until it has confirmed the maker's asset lock on chain, at the agreed
        scriptPubKey, for the agreed value, at a depth the taker chose."* Nothing else in the
        handshake gives the taker that. The BTC claim leaf is ``<H> … <makerClaimPk> OP_CHECKSIG``
        with no precondition that the asset was ever locked, and the maker holds both ``p`` and the
        claim key from the moment it publishes the envelope. So a maker that locks NOTHING and
        simply waits can sweep the taker's HTLC the instant it appears: the taker's loss is the
        full ``btc_sats``, and the FSM's nominal "taker locks first" ordering is bookkeeping, not
        a safety guarantee.

        What is checked, all fail-closed:

        1. the covenant scriptPubKey is **re-derived here from the taker's own ``terms``**
           (:meth:`_build_covenant` — amount, H, ``t_rxd`` CSV, both dest hashes, the asset REF),
           never taken from anything the maker advertises;
        2. that exact SPK holds a funded UTXO, and its ON-CHAIN value equals
           ``terms.radiant_amount`` — an unfunded SPK, a mis-valued one, and an ambiguous UTXO set
           all raise (:meth:`RadiantChainIO.find_covenant_utxo`);
        3. the funding is buried ``min_confirmations`` deep. "Funded" alone is NOT enough:
           ElectrumX ``listunspent`` includes MEMPOOL outputs, so a maker can fund with a
           replaceable transaction, wait for the taker's lock, then double-spend the funding away
           — it still claims the counter leg with ``p`` while the vanished covenant leaves the
           taker nothing to claim. ``None`` uses this leg's configured ``min_confirmations``; the
           coordinator passes the policy's RXD burial depth for a real-value swap.
        """
        cov = self._build_covenant(terms)
        required = self.min_confirmations if min_confirmations is None else int(min_confirmations)
        if not isinstance(required, int) or isinstance(required, bool) or required < 0:
            raise ValidationError("min_confirmations must be a non-negative int or None")
        outpoint, value, _height = await self.chain_io.find_covenant_utxo(
            cov.funded_spk, expected_value=terms.radiant_amount
        )
        confs = await self.chain_io.confirmations(outpoint.split(":")[0])
        if not isinstance(confs, int) or isinstance(confs, bool) or confs < 0:
            raise NetworkError("confirmations reader returned a non-negative-int depth; fail-closed")
        if confs < required:
            raise NetworkError(
                f"the maker's Radiant covenant funding {outpoint} has {confs} confirmation(s) < the required "
                f"{required}: a shallow/mempool funding is reorgable and can be double-spent away after the "
                "counter leg is locked. Wait for it to bury, then retry."
            )
        return outpoint, int(value), confs

    # -- spends -------------------------------------------------------------
    async def _resolve_covenant(self, record: SwapRecord) -> tuple[HtlcCovenant, str, int, int]:
        """Build the covenant, locate its funded UTXO, conf-gate it, return value + depth.

        Reads the on-chain value (never a self-report) and rejects a covenant
        shallower than ``min_confirmations`` so a reorg cannot un-fund it mid-spend.
        The confirmation depth is returned alongside because the claim path needs it
        to compute blocks-to-deadline (the covenant's CSV refund branch opens at
        ``confirmations >= refund_csv``) — re-reading it would be a second network
        round-trip for a number we already have.
        """
        cov = self._build_covenant(record.terms)
        # Pin to the outpoint recorded when the covenant was revalidated. Re-deriving it by scan
        # would let anyone brick this spend by paying the covenant SPK a second time.
        outpoint, value, _height = await self.chain_io.find_covenant_utxo(
            cov.funded_spk,
            expected_value=record.terms.radiant_amount,
            pin_outpoint=record.radiant_covenant_outpoint,
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
        return cov, outpoint, value, confs

    @contextlib.contextmanager
    def _unspent_on_failure(self, fee: FeeInput):
        """Report a dispensed fee input back to the source when the spend never gets built.

        The fee input must be dispensed BEFORE the transaction can be built (its value and
        script are inputs to the build), and the build can refuse: ``build_htlc_*_tx`` and
        :meth:`_assert_affordable` both raise :class:`InsufficientFundsError` when the
        dispensed input cannot clear the node's relay floor. Nothing reaches a node on that
        path and no fee is paid — but the source had already committed the input and charged
        its cumulative cap, so a run of refusals ate the operator's budget and left a funded
        pool that could no longer dispense the one input large enough to work (audit B3).

        Everything inside this block is strictly pre-broadcast, so a raise here provably means
        the input was never spent. The broadcast itself is deliberately OUTSIDE the block: once
        bytes are handed to a node the input may well be spent, and crediting it back then
        would under-count real spend against the cap.

        The report is duck-typed and optional — a plain ``FeeUtxoSource`` (only
        ``next_fee_input``) keeps working unchanged, it just does not get the credit.
        """
        try:
            yield
        except BaseException:
            release = getattr(self.fee_source, "release_unspent", None)
            if callable(release):
                try:
                    release(fee)
                except Exception:
                    logger.warning(
                        "could not return the unspent fee input %s:%s to the pool after a refused build",
                        fee.txid,
                        fee.vout,
                    )
            raise

    def _assert_affordable(self, tx, fee: FeeInput, *, blocks_to_deadline: int | None, kind: str) -> None:
        """PRE-BROADCAST affordability gate (gap-closure A1) — refuse, and PAGE, rather
        than emit a time-critical spend that cannot be repaired.

        Radiant has no RBF and no CPFP (see :mod:`pyrxd.gravity.fee_policy`), so a
        transaction broadcast below the effective relay floor is not merely slow — it is
        unfixable, and it squats on its own inputs until mempool expiry (8h). If the
        deadline falls inside that window the asset is simply lost to the counterparty's
        refund. Failing loudly here is strictly better than that outcome.

        Sized against ``len(tx.serialize())`` — the exact wire bytes, not an estimate.
        The whole fee input is the miner fee (single-output covenant, no change).
        """
        try:
            target = assert_fee_covers(
                fee_value=fee.value,
                size_bytes=len(tx.serialize()),
                policy=self.fee_policy,
                blocks_to_deadline=blocks_to_deadline,
                what=f"HTLC covenant {kind} (pre-broadcast gate)",
            )
            # Above the node's floor but below the urgency TARGET: broadcast anyway (the
            # node accepts it, and refusing would hand the asset to the counterparty's
            # refund) but page — the operator should fund a larger pool before the next
            # deadline-critical spend.
            if fee.value < target:
                logger.warning(
                    "Radiant covenant %s on %s clears the relay floor but is below the "
                    "urgency target (%d < %d photons, blocks_to_deadline=%s) — broadcasting, "
                    "but inclusion may be slow; fund a larger fee input",
                    kind,
                    self.network,
                    fee.value,
                    target,
                    blocks_to_deadline,
                )
        except InsufficientFundsError as exc:
            # PAGE: an operator has to fund a larger fee input before this spend can go
            # out, and on the claim path the clock to the counterparty's refund is running.
            logger.error(
                "REFUSING to broadcast the Radiant covenant %s on %s: %s (blocks_to_deadline=%s)",
                kind,
                self.network,
                exc,
                blocks_to_deadline,
            )
            raise

    async def claim_asset(self, record: SwapRecord, preimage: bytes) -> str:
        """Build + broadcast the TAKER's claim spend (reveals ``p``). Returns the txid.

        Fee-sized against the DEADLINE: the maker's CSV refund branch opens once the
        covenant is ``t_rxd`` confirmations deep, so ``t_rxd - confirmations`` is the
        number of Radiant blocks in which this claim must be *mined*, not merely
        broadcast. The pre-broadcast gate refuses (and pages) if the dispensed fee input
        cannot meet that requirement — there is no post-broadcast remedy on Radiant.
        """
        if not isinstance(record, SwapRecord):
            raise ValidationError("record must be a SwapRecord")
        cov, outpoint, carrier, confs = await self._resolve_covenant(record)
        # The covenant CSV is a BIP68 BLOCK count (_build_covenant refuses any other
        # unit), so this subtraction is in Radiant blocks. Clamped at 0: a deadline
        # already passed takes the maximum urgency premium, never a negative one.
        blocks_to_deadline = max(0, record.terms.t_rxd.value - confs)
        fee = self.fee_source.next_fee_input()
        with self._unspent_on_failure(fee):
            tx = build_htlc_claim_tx(
                covenant=cov,
                covenant_outpoint=outpoint,
                carrier_value=carrier,
                preimage=bytes(preimage),
                fee=fee,
                fee_policy=self.fee_policy,
            )
            self._assert_affordable(tx, fee, blocks_to_deadline=blocks_to_deadline, kind="claim")
        return await self._broadcast(tx)

    async def rebroadcast_claim_if_evicted(self, record: SwapRecord, preimage: bytes) -> str | None:
        """Re-broadcast the taker's claim if it has fallen out of the mempool. Returns the new txid,
        or None when nothing needed doing.

        WHY THIS EXISTS. A non-BIP68-final refund is rejected from the mempool
        (Radiant Core ``validation.cpp:724-728``), so the maker CANNOT pre-broadcast and a claim
        already sitting in the mempool at CSV maturity wins the race. The whole safety of the claim
        window therefore rests on the claim STAYING there — and Radiant has no RBF and no CPFP, so
        a claim that is evicted cannot be bumped back in. Mempool expiry is about eight hours.

        The coordinator broadcast the claim and advanced straight to a completed state, so an
        eviction was invisible: the maker's refund became valid at maturity, confirmed, and took
        both legs while the swap's own record said it had finished.

        Single-shot on purpose — no loop, no clock. The caller drives it on whatever tick it
        already has, which keeps this testable and keeps clock ownership where the rest of the
        module puts it.

        Returns None when the covenant is already spent (our claim is in the mempool or mined —
        nothing to do) and when the source ABSTAINS, because an unknown answer must not be treated
        as "evicted" and turned into a duplicate broadcast.
        """
        _cov, outpoint, _carrier, _confs = await self._resolve_covenant(record)
        unspent = await self.chain_io.covenant_unspent_incl_mempool(outpoint)
        if unspent is None:
            _LOG.warning(
                "could not determine whether the covenant %s is still unspent; NOT re-broadcasting "
                "(an unknown answer is not an eviction, and a duplicate broadcast is its own risk)",
                outpoint,
            )
            return None
        if not unspent:
            return None  # spent or in the mempool — the claim is alive
        _LOG.warning(
            "covenant %s is unspent again: the claim has been evicted or reorged out. Re-broadcasting "
            "— with no RBF and no CPFP this is the ONLY way back into the mempool, and the maker's "
            "refund becomes valid at CSV maturity.",
            outpoint,
        )
        return await self.claim_asset(record, preimage)

    async def refund_asset(self, record: SwapRecord) -> str:
        """Build + broadcast the MAKER's CSV refund spend. Returns the txid.

        P3 maturity self-check: the covenant's CSV refund leaf is only spendable once the covenant UTXO
        is buried ``t_rxd`` deep (the BIP68 relative-block timelock the covenant was built with:
        ``refund_csv=t_rxd.value``, mature at ``confirmations >= t_rxd.value``). Refuse a non-final
        refund HERE rather than emit a tx a node rejects — under a deadline-pinning mempool "rely on
        node rejection" is fragile — with an exact "needs N confirmations, has M" message a block-based
        poller retries on. This guards EVERY ``refund_asset`` caller (``mutual_refund``,
        ``maybe_refund_asset_on_maker_stall``) at the leg, complementing the coordinator-side height
        check in ``maybe_refund_asset_on_maker_stall``. (The CLAIM branch has no CSV, so ``claim_asset``
        is intentionally NOT gated this way.)
        """
        if not isinstance(record, SwapRecord):
            raise ValidationError("record must be a SwapRecord")
        cov, outpoint, carrier, _confs = await self._resolve_covenant(record)
        required_csv = record.terms.t_rxd.value
        confs = await self.chain_io.confirmations(outpoint.split(":")[0])
        if confs < required_csv:
            raise NetworkError(
                f"covenant CSV refund is not yet mature: needs {required_csv} confirmations, has {confs} "
                f"({required_csv - confs} block(s) to go) — refusing to broadcast a non-final refund "
                "(P3 maturity self-check); poll and retry at maturity rather than relying on node rejection."
            )
        fee = self.fee_source.next_fee_input()
        with self._unspent_on_failure(fee):
            tx = build_htlc_refund_tx(
                covenant=cov,
                covenant_outpoint=outpoint,
                carrier_value=carrier,
                fee=fee,
                fee_policy=self.fee_policy,
            )
            # blocks_to_deadline=None (the plain relay floor, no urgency premium): unlike the
            # claim, the CSV refund has no closing window. It only becomes broadcastable AT
            # maturity and stays valid indefinitely thereafter — the competing claim branch
            # needs p, which on this path the counterparty has not revealed. A premium here
            # would burn fee for urgency that does not exist. The floor itself still binds.
            self._assert_affordable(tx, fee, blocks_to_deadline=None, kind="refund")
        return await self._broadcast(tx)

    async def _broadcast(self, tx) -> str:
        raw = tx.serialize()
        try:
            return await self.chain_io.broadcast(raw)
        except _AlreadyKnown:
            # Idempotent: the node already has this exact tx -> its txid is authoritative.
            return tx.txid()
