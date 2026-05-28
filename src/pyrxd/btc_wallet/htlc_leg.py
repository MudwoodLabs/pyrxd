"""Concrete BTC HTLC leg for the Gravity Taproot-HTLC atomic swap.

This is the real ``btc_leg`` the :class:`pyrxd.gravity.swap_coordinator.SwapCoordinator`
drives (the coordinator tests use duck-typed fakes; this is the production object).
It wraps the proven primitives in :mod:`pyrxd.btc_wallet.taproot`
(``build_htlc``/``build_claim_tx``/``build_refund_tx``/``scrape_secret``) and
:mod:`pyrxd.btc_wallet.payment` (``build_payment_tx``) and adds the network edges
the coordinator needs: a broadcast adapter and a confirmation/amount reader.

Design (T7 plan D4/D5/D6, reviewed)
-----------------------------------
* ``BtcBroadcaster`` is a **separate Protocol** (``async broadcast``) composed into
  the leg — broadcast is NOT added to the read-only ``BtcDataSource`` ABC. Broadcast
  is **idempotent**: a node that already has the tx ("txn-already-known", "already
  in block chain", "already in mempool") is treated as SUCCESS, not an error, so a
  retry after a crash between broadcast and persist does not double-fund.
* The funded amount in the returned :class:`BtcHtlcLocator` is read back from the
  **on-chain output**, not self-reported — a P2TR scriptPubKey commits to the
  taptree, not the value, so the amount must be confirmed against the chain (the
  coordinator's amount-binding guard is the only layer that catches a mis-funded
  HTLC, and it must bind a real number).
* ``derive_funding_scriptpubkey``/``promised_funding_scriptpubkey``/``scrape_secret``
  are SYNC (pure, no chain). ``fund``/``claim``/``refund`` are ASYNC (broadcast).
* **AUDIT GATE (enforced in code):** :func:`require_audit_cleared` RAISES if a
  non-regtest/non-signet network is selected without an explicit ``audit_cleared``
  opt-in. A docstring-only warning is insufficient — a value-moving path guarded
  only by prose will eventually run on mainnet. The leg refuses to construct for
  mainnet until the external audit clears the leg trust boundary.
"""

from __future__ import annotations

import logging
from typing import Protocol, runtime_checkable

from pyrxd.btc_wallet import taproot as t
from pyrxd.btc_wallet.keys import BtcKeypair
from pyrxd.btc_wallet.payment import BtcUtxo, build_payment_tx
from pyrxd.security.errors import NetworkError, ValidationError
from pyrxd.security.types import Txid

__all__ = [
    "AUDIT_CLEARED_NETWORKS",
    "BitcoinCoreBroadcaster",
    "BitcoinTaprootLeg",
    "BtcBroadcaster",
    "BtcFundingReader",
    "require_audit_cleared",
]

logger = logging.getLogger(__name__)

# Networks that NEVER require the audit opt-in — isolated test chains that cannot
# move real value. Everything else (mainnet "bc", and any value-bearing network)
# requires an explicit audit-cleared opt-in.
AUDIT_CLEARED_NETWORKS: frozenset[str] = frozenset({"bcrt", "regtest", "tb", "signet"})

# Broadcast responses that mean "the node already has this tx" — idempotent
# success, NOT an error (a crash-recovery retry must not be treated as a failure).
_ALREADY_KNOWN_MARKERS: tuple[str, ...] = (
    "txn-already-known",
    "transaction already in block chain",
    "already in block chain",
    "already in mempool",
    "txn-already-in-mempool",
)


def require_audit_cleared(network: str, *, audit_cleared: bool) -> None:
    """Fail-closed gate: refuse a value-bearing network without an audit opt-in.

    Modeled on :class:`pyrxd.gravity.swap_coordinator.MarginPolicy`'s
    ``require_measured`` discipline — a value-moving path must not be runnable on a
    real chain by accident. Isolated test chains (``AUDIT_CLEARED_NETWORKS``) are
    always allowed; any other network RAISES unless ``audit_cleared=True`` is
    explicitly passed (which the operator may only set after an independent external
    audit clears the leg trust boundary).

    Raises:
        ValidationError: for a value-bearing network without the explicit opt-in.
    """
    if not isinstance(network, str) or not network:
        raise ValidationError("network must be a non-empty string")
    if network in AUDIT_CLEARED_NETWORKS:
        return
    if audit_cleared is not True:
        raise ValidationError(
            f"network {network!r} is value-bearing and the HTLC leg is NOT cleared for it: "
            "the always-succeeding test fakes hide the one-sided-loss surface, so a real-value "
            "swap MUST wait for an independent external audit of the leg trust boundary. "
            "Pass audit_cleared=True only after that audit clears (T7 plan AUDIT GATE)."
        )


@runtime_checkable
class BtcBroadcaster(Protocol):
    """Submit a raw BTC tx to the network. Composed into the leg (not on the ABC).

    ``broadcast`` MUST be idempotent: if the node already knows the tx, return its
    txid as success rather than raising — a crash-recovery retry re-broadcasts the
    same tx and must not be treated as a failure.
    """

    async def broadcast(self, raw_tx: bytes) -> str:
        """Broadcast ``raw_tx``; return the broadcast txid (BE hex)."""
        ...


@runtime_checkable
class BtcFundingReader(Protocol):
    """Read BTC chain state the HTLC leg needs: funding amount, confirmation depth,
    and the canonical txid of a raw tx.

    Duck-typed over a ``BtcDataSource``-like object. ``read_output_amount_sats``
    returns the value of ``(txid, vout)`` as committed on-chain (NOT a self-report),
    enforcing ``min_confirmations`` (raise/fail-closed if shallower).
    ``confirmations`` is the symmetric confirmation-depth reader (mirrors
    ``RadiantChainIO.confirmations``) the reorg gate consumes. ``txid_of`` resolves a
    raw tx's canonical txid VIA THE NODE — never a local segwit parse (see the reorg
    gate plan; the gated txid must be that of the exact bytes ``p`` was scraped from).
    """

    async def read_output_amount_sats(self, txid: str, vout: int, *, min_confirmations: int) -> int:
        """Return the on-chain satoshi value of ``(txid, vout)`` at >= min_confirmations."""
        ...

    async def confirmations(self, txid: str) -> int:
        """Return the confirmation depth of ``txid`` (0 if unconfirmed/unknown)."""
        ...

    async def txid_of(self, raw_tx: bytes) -> str:
        """Resolve ``raw_tx``'s canonical txid via the node (NOT a local parse)."""
        ...


class BitcoinCoreBroadcaster:
    """``BtcBroadcaster`` backed by a Bitcoin Core ``sendrawtransaction`` RPC.

    Intended for the regtest milestone (a local node). Reuses the injected
    ``rpc(method, params)`` coroutine so it shares transport/auth with a
    ``BitcoinCoreRpcSource`` rather than opening a second session. Idempotent: an
    "already known" node response is mapped to the tx's own txid as success.
    """

    def __init__(self, rpc) -> None:
        if not callable(rpc):
            raise ValidationError("rpc must be an async callable rpc(method, params)")
        self._rpc = rpc

    async def broadcast(self, raw_tx: bytes) -> str:
        if not isinstance(raw_tx, (bytes, bytearray)) or len(raw_tx) == 0:
            raise ValidationError("raw_tx must be non-empty bytes")
        raw = bytes(raw_tx)
        try:
            result = await self._rpc("sendrawtransaction", [raw.hex()])
        except Exception as exc:
            msg = str(exc).lower()
            if any(marker in msg for marker in _ALREADY_KNOWN_MARKERS):
                # Idempotent: the node already has it. Ask the node (authoritative)
                # for the canonical txid rather than re-deriving it from raw bytes
                # locally — segwit txid = hash256(non-witness), and the node already
                # has a correct parser, so we don't ship a second one here.
                return await self._txid_via_node(raw)
            raise NetworkError(f"sendrawtransaction failed: {exc}") from exc
        if not isinstance(result, str):
            raise NetworkError("sendrawtransaction did not return a txid")
        return str(result)

    async def _txid_via_node(self, raw: bytes) -> str:
        """Resolve the canonical txid of an already-known raw tx via the node."""
        decoded = await self._rpc("decoderawtransaction", [raw.hex()])
        if not isinstance(decoded, dict) or not isinstance(decoded.get("txid"), str):
            raise NetworkError("decoderawtransaction did not return a txid for an already-known tx")
        return str(decoded["txid"])


class BitcoinTaprootLeg:
    """The concrete BTC HTLC leg (the production ``btc_leg``).

    Parameters
    ----------
    network:
        BTC network prefix ("bcrt" regtest, "tb" testnet/signet, "bc" mainnet).
    taker_keypair / funding_utxo:
        The taker's wallet key + the single UTXO that funds the HTLC (one input is
        the covenant structural constraint of ``build_payment_tx``). ``funding_utxo``
        must hold ``btc_sats + fee_sats`` (plus dust slack for change).
    broadcaster:
        A :class:`BtcBroadcaster` (idempotent).
    funding_reader:
        A :class:`BtcFundingReader` — reads the funded amount from the chain.
    refund_to_scriptpubkey / claim_to_scriptpubkey:
        Where the refund (taker) and claim (maker) spends pay out.
    fee_sats:
        Flat fee for the funding/claim/refund txs (regtest milestone; a fee
        estimator is a later refinement).
    min_confirmations:
        Confirmations required before the on-chain funded amount is trusted.
    audit_cleared:
        Explicit opt-in for a value-bearing ``network`` (see
        :func:`require_audit_cleared`). Ignored for isolated test chains.
    """

    def __init__(
        self,
        *,
        network: str,
        taker_keypair: BtcKeypair,
        funding_utxo: BtcUtxo,
        maker_claim_pubkey_xonly: bytes,
        broadcaster: BtcBroadcaster,
        funding_reader: BtcFundingReader,
        refund_to_scriptpubkey: bytes,
        claim_to_scriptpubkey: bytes,
        fee_sats: int = 500,
        min_confirmations: int = 1,
        funding_input_type: str = "p2wpkh",
        maker_claim_privkey: bytes | None = None,
        audit_cleared: bool = False,
        fund_confirm_poll_s: float = 0.0,
        fund_confirm_timeout_s: float = 0.0,
    ) -> None:
        require_audit_cleared(network, audit_cleared=audit_cleared)
        if not isinstance(taker_keypair, BtcKeypair):
            raise ValidationError("taker_keypair must be a BtcKeypair")
        if not isinstance(funding_utxo, BtcUtxo):
            raise ValidationError("funding_utxo must be a BtcUtxo")
        if not isinstance(broadcaster, BtcBroadcaster):
            raise ValidationError("broadcaster must implement BtcBroadcaster.broadcast")
        if not isinstance(funding_reader, BtcFundingReader):
            raise ValidationError("funding_reader must implement BtcFundingReader.read_output_amount_sats")
        if not isinstance(fee_sats, int) or isinstance(fee_sats, bool) or fee_sats <= 0:
            raise ValidationError("fee_sats must be a positive int")
        if not isinstance(min_confirmations, int) or isinstance(min_confirmations, bool) or min_confirmations < 0:
            raise ValidationError("min_confirmations must be a non-negative int")
        if fund_confirm_poll_s < 0 or fund_confirm_timeout_s < 0:
            raise ValidationError("fund_confirm_poll_s/fund_confirm_timeout_s must be non-negative")
        self.network = network
        self.taker_keypair = taker_keypair
        self.funding_utxo = funding_utxo
        self.maker_claim_pubkey_xonly = t._as_bytes(
            maker_claim_pubkey_xonly, name="maker_claim_pubkey_xonly", length=32
        )
        self.broadcaster = broadcaster
        self.funding_reader = funding_reader
        self.refund_to_scriptpubkey = bytes(refund_to_scriptpubkey)
        self.claim_to_scriptpubkey = bytes(claim_to_scriptpubkey)
        self.fee_sats = fee_sats
        self.min_confirmations = min_confirmations
        self.funding_input_type = funding_input_type
        # When the funding tx is broadcast by THIS leg (mainnet has no on-demand
        # mining), the post-broadcast on-chain readback can't be satisfied for ~1
        # block. If a poll interval is set, fund() waits up to the timeout for the tx
        # to reach min_confirmations instead of failing instantly. 0 = no poll (the
        # historical regtest behaviour, where the test mines between broadcast/read).
        self.fund_confirm_poll_s = float(fund_confirm_poll_s)
        self.fund_confirm_timeout_s = float(fund_confirm_timeout_s)
        # Optional: only a MAKER-role leg holds the claim key. Held in-memory only,
        # never persisted (it is the maker's spending key for the claim leaf).
        self._maker_claim_privkey = (
            t._as_bytes(maker_claim_privkey, name="maker_claim_privkey", length=32)
            if maker_claim_privkey is not None
            else None
        )

    # -- pure HTLC derivation (sync) ----------------------------------------
    def _htlc(self, terms) -> t.BtcHtlc:
        """Re-derive the HTLC funding artifact from the negotiated terms.

        The taker is the refund party; the maker holds the claim key. The terms
        carry both x-only keys, so the HTLC is reconstructable for any spend.
        """
        return t.build_htlc(
            hashlock=terms.hashlock,
            claim_pubkey_xonly=terms.btc_claim_pubkey_xonly,
            refund_pubkey_xonly=terms.btc_refund_pubkey_xonly,
            timeout=terms.t_btc,
            network=self.network,
        )

    def derive_funding_scriptpubkey(self, terms) -> bytes:
        """The funding SPK the taker independently re-derives from the terms."""
        return self._htlc(terms).scriptpubkey

    def promised_funding_scriptpubkey(self, terms) -> bytes:
        """The funding SPK the maker promised.

        For the HTLC there is no separate maker-side derivation — the SPK is a pure
        function of the negotiated terms, so the promised SPK equals the re-derived
        one. (The pre-lock gate's equality check still runs; a divergence here would
        signal a terms/derivation bug.)
        """
        return self._htlc(terms).scriptpubkey

    def scrape_secret(self, claim_tx_bytes: bytes, hashlock: bytes) -> bytes:
        """Scrape ``p`` from the maker's claim tx witness (pure; by sha256==H)."""
        return t.scrape_secret(claim_tx_bytes, hashlock)

    # -- reorg gate: confirmation depth of the maker's claim (async) --------
    async def confirmations_of_claim(self, claim_tx_bytes: bytes) -> int:
        """Confirmation depth of the maker's BTC claim tx (the reorg gate's input).

        The txid is resolved VIA THE NODE from the exact ``claim_tx_bytes`` ``p`` was
        scraped from (never a local segwit parse) — so an attacker can't reveal ``p``
        in a shallow tx while pointing the gate at a deep unrelated tx. Fail-closed:
        any read/derivation error propagates (the coordinator then refuses to claim).
        """
        if not isinstance(claim_tx_bytes, (bytes, bytearray)) or len(claim_tx_bytes) == 0:
            raise ValidationError("claim_tx_bytes must be non-empty bytes")
        # Derive the txid LOCALLY from the exact bytes p was scraped from (serialize,
        # don't trust): the reorg gate must read confs of THIS tx, never a
        # counterparty-supplied id (a maker could reveal p in a shallow tx and point a
        # trusted txid at a deep unrelated one — fail-OPEN). btc_txid_from_raw is
        # fail-closed; a mis-derived txid reads 0 confs at the gate, never a false depth.
        txid = t.btc_txid_from_raw(bytes(claim_tx_bytes))
        confs = await self.funding_reader.confirmations(txid)
        if not isinstance(confs, int) or isinstance(confs, bool) or confs < 0:
            raise NetworkError("confirmations reader returned a non-negative-int depth; fail-closed")
        return confs

    # -- chain-touching (async) ---------------------------------------------
    async def fund(self, terms) -> t.BtcHtlcLocator:
        """Fund the HTLC P2TR address from the taker's UTXO; return the locator.

        Build → idempotent-broadcast → read the funded amount back from the chain
        (D4: the amount is the ON-CHAIN value, never a self-report). The funding tx
        pays output 0 to the HTLC address; change (if any) returns to the taker.
        """
        htlc = self._htlc(terms)
        # build_payment_tx pays a hash + type; for P2TR the "hash" is the 32-byte
        # output key (taproot output) — exactly htlc.output_key.
        payment = build_payment_tx(
            self.taker_keypair,
            self.funding_utxo,
            to_hash=htlc.output_key,
            to_type="p2tr",
            amount_sats=terms.btc_sats,
            fee_sats=self.fee_sats,
            input_type=self.funding_input_type,
        )
        broadcast_txid = await self.broadcaster.broadcast(bytes.fromhex(payment.tx_hex))
        # The broadcaster's idempotent path returns the SAME txid build_payment_tx
        # computed; bind to the builder's txid (authoritative for the outpoint).
        funding_txid = Txid(payment.txid)
        if broadcast_txid != str(funding_txid):
            raise NetworkError(
                f"broadcast txid {broadcast_txid} != built funding txid {funding_txid}; refusing to proceed"
            )
        outpoint = t.BtcOutpoint(txid=str(funding_txid), vout=0)
        # D4: read the funded amount from the on-chain output, not the builder.
        # On a chain we can't mine on demand (mainnet/signet), the just-broadcast tx
        # has 0 confs, so poll for min_confirmations when configured; otherwise read
        # once (regtest mines between broadcast and read).
        on_chain_amount = await self._read_funded_amount_sats(str(funding_txid), 0)
        if not isinstance(on_chain_amount, int) or isinstance(on_chain_amount, bool) or on_chain_amount <= 0:
            raise NetworkError("funding reader returned a non-positive on-chain amount; fail-closed")
        return htlc.with_funding(outpoint, on_chain_amount)

    async def _read_funded_amount_sats(self, funding_txid: str, vout: int) -> int:
        """Read the on-chain funded amount, polling for min_confirmations if configured.

        ``read_output_amount_sats`` is fail-closed: it RAISES until the tx reaches
        min_confirmations. On regtest a block is mined between broadcast and read, so a
        single call works. On a chain without on-demand mining the just-broadcast tx is
        0-conf, so when ``fund_confirm_poll_s`` is set this retries on that specific
        "needs N confs" NetworkError until the deadline, then gives up (still
        fail-closed — it re-raises the last error rather than returning an unconfirmed
        amount). Any OTHER error (bad vout, malformed tx) propagates immediately.
        """
        import asyncio
        import time as _time

        if self.fund_confirm_poll_s <= 0:
            return await self.funding_reader.read_output_amount_sats(
                funding_txid, vout, min_confirmations=self.min_confirmations
            )
        deadline = _time.monotonic() + self.fund_confirm_timeout_s
        while True:
            try:
                return await self.funding_reader.read_output_amount_sats(
                    funding_txid, vout, min_confirmations=self.min_confirmations
                )
            except NetworkError as exc:
                # Only retry the "not enough confirmations yet" case; everything else
                # (OOB vout, malformed value) is a real fault — fail closed now.
                if "confirmations, required" not in str(exc):
                    raise
                if _time.monotonic() >= deadline:
                    raise
                logging.getLogger(__name__).info(
                    "fund(): %s — waiting %.0fs for funding tx to confirm",
                    exc,
                    self.fund_confirm_poll_s,
                )
                await asyncio.sleep(self.fund_confirm_poll_s)

    async def claim(self, locator: t.BtcHtlcLocator, preimage: bytes) -> str:
        """Build + idempotently broadcast the maker's claim tx (reveals ``p``).

        Only a MAKER-role leg (constructed with ``maker_claim_privkey``) can do this
        — the claim spend uses the maker's claim-leaf key. A taker-role leg without
        that key fail-closes. ``build_claim_tx`` re-verifies ``sha256(p)`` opens the
        leaf hashlock before signing.
        """
        if self._maker_claim_privkey is None:
            raise ValidationError(
                "BitcoinTaprootLeg.claim requires a maker_claim_privkey; this leg is taker-role "
                "(holds only the refund key). Construct a maker-role leg to claim."
            )
        if not isinstance(locator, t.BtcHtlcLocator):
            raise ValidationError("locator must be a BtcHtlcLocator")
        raw = t.build_claim_tx(
            locator=locator,
            preimage=bytes(preimage),
            claim_privkey=self._maker_claim_privkey,
            to_scriptpubkey=self.claim_to_scriptpubkey,
            fee_sats=self.fee_sats,
            aux_rand=t.fresh_aux_rand(),
        )
        return await self.broadcaster.broadcast(raw)

    async def refund(self, locator: t.BtcHtlcLocator, timeout: t.Timelock) -> str:
        """Build + idempotently broadcast the taker's CSV refund tx. Returns the txid.

        The refund leaf spends via the taker's refund key (held by this leg) after
        the relative timelock matures. Idempotent broadcast tolerates a retry.
        """
        if not isinstance(locator, t.BtcHtlcLocator):
            raise ValidationError("locator must be a BtcHtlcLocator")
        if not isinstance(timeout, t.Timelock):
            raise ValidationError("timeout must be a Timelock")
        raw = t.build_refund_tx(
            locator=locator,
            refund_privkey=self.taker_keypair._privkey.unsafe_raw_bytes(),
            timeout=timeout,
            to_scriptpubkey=self.refund_to_scriptpubkey,
            fee_sats=self.fee_sats,
            aux_rand=t.fresh_aux_rand(),
        )
        return await self.broadcaster.broadcast(raw)
