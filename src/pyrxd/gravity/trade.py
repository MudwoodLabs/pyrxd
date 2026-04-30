"""High-level GravityTrade orchestrator.

Wraps the Phase 3a primitive builders into a single async class that steps
through the full four-step Maker↔Taker swap:

    1. Maker posts an offer   → broadcast MakerOffer tx on Radiant
    2. Taker claims the offer → broadcast MakerClaimed tx on Radiant
    3. Taker pays BTC         → build + broadcast BTC payment tx
    4. Taker finalizes        → fetch SPV proof, verify, broadcast finalize tx

``GravityTrade`` is deliberately **opinionated**: it always runs every
verifier and never offers a "skip verification" shortcut. The primitive layer
(``build_finalize_tx``, ``SpvProofBuilder``) can still be called directly for
testing or advanced use cases where the caller has already verified externally.

Security notes
--------------
* SPV proof verification uses ``SpvProofBuilder`` with full ``CovenantParams``,
  which binds the proof to the specific covenant (audit 05-F-2 / F-3).
* ``finalize()`` calls ``SpvProofBuilder.build()``; a partial proof can never
  reach ``build_finalize_tx``.
* ``claim()`` calls ``build_claim_tx`` which independently re-checks the
  code hash before signing (audit 05-F-13).
* Poll-based confirmation waits use a configurable timeout to prevent
  unbounded blocking.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass

from pyrxd.network.bitcoin import BtcDataSource
from pyrxd.network.electrumx import ElectrumXClient
from pyrxd.security.errors import NetworkError, ValidationError
from pyrxd.security.secrets import PrivateKeyMaterial
from pyrxd.security.types import BlockHeight, Txid
from pyrxd.spv.proof import CovenantParams, SpvProofBuilder
from pyrxd.spv.witness import strip_witness

from .transactions import build_claim_tx, build_finalize_tx
from .types import ClaimResult, FinalizeResult, GravityOffer

__all__ = [
    "ConfirmationStatus",
    "GravityTrade",
    "TradeConfig",
]

logger = logging.getLogger(__name__)

# Seconds between confirmation polls
_DEFAULT_POLL_INTERVAL = 60
# Maximum poll attempts before timeout (default 2 hours at 60s interval)
_DEFAULT_MAX_POLLS = 120


@dataclass(frozen=True)
class TradeConfig:
    """Tunable parameters for GravityTrade.

    Attributes
    ----------
    min_btc_confirmations:
        Minimum on-chain BTC confirmations before finalizing. Default 6.
    poll_interval_seconds:
        Seconds between confirmation polls. Default 60.
    max_poll_attempts:
        Maximum number of polls before ``wait_confirmations`` raises
        ``NetworkError``. Default 120 (= 2 hours at 60s).
    accept_short_deadline:
        If ``True``, suppress the 24h deadline guard (audit 04-S1).
        Only for testing — do NOT set in production.
    deadline_warning_seconds:
        Emit a WARNING log in ``finalize()`` when the Maker's claim deadline
        is less than this many seconds away. Default 7200 (2 hours). Set to 0
        to disable. Takers should finalize immediately if this fires (audit
        04-S1 forfeit race).
    """

    min_btc_confirmations: int = 6
    poll_interval_seconds: float = _DEFAULT_POLL_INTERVAL
    max_poll_attempts: int = _DEFAULT_MAX_POLLS
    accept_short_deadline: bool = False
    deadline_warning_seconds: int = 7200

    def __post_init__(self) -> None:
        if self.deadline_warning_seconds < 0:
            raise ValidationError("deadline_warning_seconds must be >= 0")
        if self.min_btc_confirmations < 1:
            raise ValidationError("min_btc_confirmations must be >= 1")
        if self.poll_interval_seconds <= 0:
            raise ValidationError("poll_interval_seconds must be > 0")
        if self.max_poll_attempts < 1:
            raise ValidationError("max_poll_attempts must be >= 1")


@dataclass
class ConfirmationStatus:
    """Status returned by :meth:`GravityTrade.wait_confirmations`."""

    txid: str
    confirmations: int
    confirmed: bool
    block_height: int | None


class GravityTrade:
    """Orchestrate a complete Gravity BTC↔RXD atomic swap.

    Parameters
    ----------
    radiant_network:
        Connected :class:`~pyrxd.network.electrumx.ElectrumXClient` for
        Radiant chain operations (broadcast, fetch tx/block).
    bitcoin_source:
        A :class:`~pyrxd.network.bitcoin.BtcDataSource` for Bitcoin chain
        data (tx fetch, Merkle proof, block headers).
    config:
        Optional :class:`TradeConfig`. Uses defaults if not provided.

    Examples
    --------
    Typical Taker flow::

        async with ElectrumXClient(["wss://electrumx.example.com"]) as rxd:
            trade = GravityTrade(radiant_network=rxd, bitcoin_source=btc_src)
            claim = await trade.claim(
                offer=offer,
                offer_txid="...",
                offer_vout=0,
                offer_photons=10_000_000,
                fee_sats=1000,
                taker_privkey=privkey,
            )
            btc_txid = "..."  # broadcast BTC payment externally
            status = await trade.wait_confirmations(btc_txid)
            result = await trade.finalize(
                btc_txid=btc_txid,
                offer=offer,
                claimed_txid=claim.txid,
                claimed_vout=0,
                claimed_photons=claim.output_photons,
                taker_address="...",
                fee_sats=1000,
            )
    """

    def __init__(
        self,
        *,
        radiant_network: ElectrumXClient,
        bitcoin_source: BtcDataSource,
        config: TradeConfig | None = None,
    ) -> None:
        self._rxd = radiant_network
        self._btc = bitcoin_source
        self._cfg = config or TradeConfig()

    # ------------------------------------------------------------------
    # Step 2: Taker claims the MakerOffer → creates MakerClaimed UTXO
    # ------------------------------------------------------------------

    async def claim(
        self,
        offer: GravityOffer,
        offer_txid: str,
        offer_vout: int,
        offer_photons: int,
        fee_sats: int,
        taker_privkey: PrivateKeyMaterial,
    ) -> ClaimResult:
        """Spend the MakerOffer UTXO, creating a MakerClaimed UTXO.

        Broadcasts the claim transaction to the Radiant network and returns
        a :class:`~pyrxd.gravity.types.ClaimResult`.

        The claim transaction requires Taker's signature (audit 04-S3).
        ``build_claim_tx`` independently verifies the code hash before signing
        (audit 05-F-13).

        Parameters
        ----------
        offer:
            The ``GravityOffer`` posted by the Maker.
        offer_txid:
            Radiant txid of the MakerOffer funding output.
        offer_vout:
            Output index of the MakerOffer UTXO.
        offer_photons:
            Value of the MakerOffer UTXO in photons.
        fee_sats:
            Radiant miner fee in photons.
        taker_privkey:
            Taker's secp256k1 private key.
        """
        result = build_claim_tx(
            offer=offer,
            funding_txid=offer_txid,
            funding_vout=offer_vout,
            funding_photons=offer_photons,
            fee_sats=fee_sats,
            taker_privkey=taker_privkey,
            accept_short_deadline=self._cfg.accept_short_deadline,
        )
        await self._broadcast_radiant(result.tx_hex)
        logger.info("claim tx broadcast: %s", result.txid)
        return result

    # ------------------------------------------------------------------
    # Step 3 helper: poll Bitcoin for confirmations
    # ------------------------------------------------------------------

    async def wait_confirmations(
        self,
        btc_txid: str,
        min_confirmations: int | None = None,
    ) -> ConfirmationStatus:
        """Poll Bitcoin until *btc_txid* reaches the required confirmations.

        Parameters
        ----------
        btc_txid:
            Bitcoin transaction ID (64 hex chars, big-endian).
        min_confirmations:
            Override ``config.min_btc_confirmations`` for this call.

        Returns
        -------
        ConfirmationStatus
            Always has ``confirmed=True`` on return (raises on timeout).

        Raises
        ------
        NetworkError
            If polling exceeds ``config.max_poll_attempts``.
        ValidationError
            If *btc_txid* is not a valid 64-char hex string.
        """
        min_conf = min_confirmations if min_confirmations is not None else self._cfg.min_btc_confirmations
        validated_txid = Txid(btc_txid)

        for attempt in range(self._cfg.max_poll_attempts):
            await self._btc.get_tip_height()
            try:
                await self._btc.get_raw_tx(validated_txid, min_confirmations=0)
            except NetworkError:
                # Tx not yet visible in mempool — keep polling
                if attempt + 1 < self._cfg.max_poll_attempts:
                    await asyncio.sleep(self._cfg.poll_interval_seconds)
                    continue
                raise NetworkError(f"BTC tx {btc_txid[:16]}… not found after {self._cfg.max_poll_attempts} polls")

            # Estimate confirmations from tip height minus tx block height.
            # BtcDataSource.get_raw_tx with min_confirmations=0 returns mempool
            # txs too; we need to determine confirmed height separately.
            # We use get_tip_height vs get_tx_block_height via a minimal approach:
            # try fetching with increasing min_conf until we know it's confirmed.
            try:
                _ = await self._btc.get_raw_tx(validated_txid, min_confirmations=min_conf)
                # Success means it has at least min_conf confirmations.
                return ConfirmationStatus(
                    txid=btc_txid,
                    confirmations=min_conf,
                    confirmed=True,
                    block_height=None,  # exact height requires additional lookup
                )
            except NetworkError:
                pass  # Not yet confirmed to required depth — keep polling

            if attempt + 1 < self._cfg.max_poll_attempts:
                logger.debug(
                    "BTC tx %s... waiting for %d confirmations (poll %d/%d)",
                    btc_txid[:16],
                    min_conf,
                    attempt + 1,
                    self._cfg.max_poll_attempts,
                )
                await asyncio.sleep(self._cfg.poll_interval_seconds)

        raise NetworkError(
            f"BTC tx {btc_txid[:16]}… did not reach {min_conf} confirmations "
            f"after {self._cfg.max_poll_attempts} polls "
            f"({self._cfg.max_poll_attempts * self._cfg.poll_interval_seconds / 3600:.1f}h)"
        )

    # ------------------------------------------------------------------
    # Step 4: Build SPV proof and broadcast finalize tx on Radiant
    # ------------------------------------------------------------------

    async def finalize(
        self,
        btc_txid: str,
        offer: GravityOffer,
        claimed_txid: str,
        claimed_vout: int,
        claimed_photons: int,
        taker_address: str,
        fee_sats: int,
        btc_tx_height: int | None = None,
    ) -> FinalizeResult:
        """Fetch the BTC SPV proof, verify it, and broadcast the finalize tx.

        This method always runs the full ``SpvProofBuilder`` verifier chain —
        there is no way to bypass verification at this level.

        Parameters
        ----------
        btc_txid:
            Bitcoin transaction ID of the Taker's BTC payment.
        offer:
            The ``GravityOffer`` originally posted by the Maker. Used to
            construct ``CovenantParams`` for SPV proof verification.
        claimed_txid:
            Radiant txid of the MakerClaimed UTXO (output of ``claim()``).
        claimed_vout:
            Output index of the MakerClaimed UTXO.
        claimed_photons:
            Value of the MakerClaimed UTXO in photons.
        taker_address:
            Taker's Radiant P2PKH address to receive the photons.
        fee_sats:
            Radiant miner fee in photons.
        btc_tx_height:
            Optional: Bitcoin block height where *btc_txid* was confirmed.
            If not provided, the orchestrator will determine it automatically.

        Raises
        ------
        SpvVerificationError
            If any SPV verifier rejects the proof.
        NetworkError
            On any network failure fetching BTC data.
        ValidationError
            On any parameter format error.
        """
        validated_btc_txid = Txid(btc_txid)

        # Determine the tx block height if not supplied.
        height = await self._resolve_btc_tx_height(validated_btc_txid, btc_tx_height)

        # Warn if the Maker's claim deadline is approaching (audit 04-S1 forfeit race).
        # The Maker can call forfeit() once block.time >= claimDeadline, so Takers
        # must finalize before the Maker races them after the deadline.
        if self._cfg.deadline_warning_seconds > 0 and hasattr(offer, "claim_deadline"):
            remaining = offer.claim_deadline - int(time.time())
            if 0 < remaining < self._cfg.deadline_warning_seconds:
                logger.warning(
                    "URGENT: Gravity claim deadline in %ds (<%dh). "
                    "Finalize immediately — Maker can race forfeit() after deadline. "
                    "offer.claim_deadline=%d",
                    remaining,
                    self._cfg.deadline_warning_seconds // 3600,
                    offer.claim_deadline,
                )
            elif remaining <= 0:
                logger.warning(
                    "Gravity claim deadline has PASSED (%ds ago). "
                    "Maker may have already called forfeit(). "
                    "offer.claim_deadline=%d",
                    -remaining,
                    offer.claim_deadline,
                )

        # Fetch raw BTC tx and Merkle proof from the Bitcoin data source.
        raw_tx = await self._btc.get_raw_tx(validated_btc_txid, min_confirmations=self._cfg.min_btc_confirmations)
        merkle_hashes, pos = await self._btc.get_merkle_proof(validated_btc_txid, height)

        # Fetch the chain of BTC block headers from anchor to tx block.
        # The anchor_height in the offer is the block *before* h1; we need
        # headers from anchor_height+1 up through (and including) the tx block.
        start_height = BlockHeight(offer.anchor_height + 1)
        count = int(height) - offer.anchor_height
        if count < 1:
            raise ValidationError(f"btc_tx_height {int(height)} must be > anchor_height {offer.anchor_height}")
        if count > offer.merkle_depth + 100:
            # Sanity check: don't fetch an absurd number of headers.
            raise ValidationError(f"header chain too long ({count}); check anchor_height and btc_tx_height")

        headers_raw: list[bytes] = await self._btc.get_header_chain(start_height, count)
        if not headers_raw:
            raise NetworkError("BTC source returned empty header chain")
        headers_hex = [h.hex() for h in headers_raw]

        # Determine the payment output offset in the raw tx.
        # We strip witness first (covenant needs non-witness txid), then
        # determine output[0] offset for the single-input segwit layout.
        stripped = strip_witness(bytes(raw_tx))
        output_offset = _find_output_zero_offset(stripped)

        # Build CovenantParams from the offer fields (these are the values the
        # Maker committed to in the covenant; the proof must match them exactly).
        covenant_params = CovenantParams(
            btc_receive_hash=offer.btc_receive_hash,
            btc_receive_type=offer.btc_receive_type,
            btc_satoshis=offer.btc_satoshis,
            chain_anchor=offer.chain_anchor,
            anchor_height=offer.anchor_height,
            merkle_depth=offer.merkle_depth,
        )

        # Run full SPV verification — this is the mandatory gate.
        builder = SpvProofBuilder(covenant_params)
        spv_proof = builder.build(
            txid_be=btc_txid,
            raw_tx_hex=stripped.hex(),
            headers_hex=headers_hex,
            merkle_be=merkle_hashes,
            pos=pos,
            output_offset=output_offset,
        )

        # Build and broadcast the finalize tx.
        # Pass the offer's photons_offered as the covenant's output floor so
        # build_finalize_tx can catch a funding shortfall before burning fees.
        result = build_finalize_tx(
            spv_proof=spv_proof,
            claimed_redeem_hex=offer.claimed_redeem_hex,
            funding_txid=claimed_txid,
            funding_vout=claimed_vout,
            funding_photons=claimed_photons,
            to_address=taker_address,
            fee_sats=fee_sats,
            minimum_output_photons=offer.photons_offered,
        )
        await self._broadcast_radiant(result.tx_hex)
        logger.info("finalize tx broadcast: %s", result.txid)
        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _broadcast_radiant(self, tx_hex: str) -> str:
        """Broadcast a raw Radiant transaction and return its txid."""
        raw = bytes.fromhex(tx_hex)
        txid = await self._rxd.broadcast(raw)
        return str(txid)

    async def _resolve_btc_tx_height(self, txid: Txid, provided_height: int | None) -> BlockHeight:
        """Return *provided_height* as ``BlockHeight``, or fetch it from the source."""
        if provided_height is not None:
            return BlockHeight(provided_height)

        return await self._btc.get_tx_block_height(txid)


def _find_output_zero_offset(stripped_raw_tx: bytes) -> int:
    """Return the byte offset of output[0] in a witness-stripped raw tx.

    Handles native-segwit (P2WPKH / P2WPKH) and P2SH-P2WPKH input layouts:
      - Native segwit (empty scriptSig): output[0] starts at byte 46.
        4 version + 1 input count varint + 36 outpoint + 1 scriptSig len (0)
        + 4 sequence = 46; then 1 output count varint, then output[0].
      - P2SH-P2WPKH (23-byte scriptSig): output[0] starts at byte 69.
        4 + 1 + 36 + 1 + 23 + 4 = 69; + 1 output count varint.

    Raises ``ValidationError`` if the layout does not match either format.
    """
    tx = stripped_raw_tx

    # version (4) + input count varint
    pos = 4
    if pos >= len(tx):
        raise ValidationError("tx too short: missing input count")
    input_count = tx[pos]
    pos += 1

    if input_count != 1:
        raise ValidationError(f"Gravity covenant requires exactly 1 input; got {input_count}")

    # outpoint (36 bytes)
    pos += 36
    if pos >= len(tx):
        raise ValidationError("tx too short: missing scriptSig length")

    scriptsig_len_byte = tx[pos]
    pos += 1
    if scriptsig_len_byte == 0:
        # Native segwit (P2WPKH / P2TR): empty scriptSig
        pass
    elif scriptsig_len_byte == 23:
        # P2SH-P2WPKH: 23-byte push of the P2WPKH redeem script
        pos += 23
    else:
        raise ValidationError(
            f"Unsupported scriptSig length {scriptsig_len_byte}; expected 0 (native segwit) or 23 (P2SH-P2WPKH)"
        )

    # sequence (4 bytes)
    pos += 4

    # output count varint
    if pos >= len(tx):
        raise ValidationError("tx too short: missing output count")
    output_count = tx[pos]
    pos += 1

    if output_count < 1:
        raise ValidationError("tx has no outputs")

    return pos
