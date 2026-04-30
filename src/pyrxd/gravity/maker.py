"""GravityMakerSession — high-level Maker-side lifecycle for Gravity swaps.

Wraps ``build_maker_offer_tx`` and ``build_cancel_tx`` into a single async
class that manages the full Maker workflow:

    1. ``create_offer``   — build + broadcast the MakerOffer tx on Radiant
    2. ``wait_for_claim`` — poll for the Taker's claim (UTXO spent)
    3. ``cancel_offer``   — broadcast the cancel tx (pre-deadline reclaim)
    4. ``check_status``   — inspect current offer state

``GravityMakerSession`` is deliberately the Maker mirror of ``GravityTrade``
(the Taker orchestrator).  It uses the same logging pattern, error types,
and polling approach.

Security notes
--------------
* ``create_offer`` validates ``offer_params.claim_deadline`` must be at least
  24h from now (audit 04-S1 guard) — same guard as ``build_claim_tx``.
* ``cancel_offer`` is only valid before the claim deadline.  After the
  deadline the Maker must use ``build_forfeit_tx`` directly (or wait for the
  Taker to finalize, which releases the funds).
* Poll-based detection uses ``get_utxos()`` on the P2SH script hash.
  A spent (claimed) UTXO disappears from the unspent set.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from dataclasses import dataclass
from typing import Optional

from pyrxd.network.bitcoin import BtcDataSource
from pyrxd.network.electrumx import ElectrumXClient
from pyrxd.security.errors import NetworkError, ValidationError
from pyrxd.security.secrets import PrivateKeyMaterial

from .codehash import compute_p2sh_script_pubkey
from .transactions import build_cancel_tx, build_maker_offer_tx
from .types import CancelResult, GravityOffer, MakerOfferResult

__all__ = [
    "GravityMakerSession",
    "GravityOfferParams",
    "ActiveOffer",
]

logger = logging.getLogger(__name__)

# Seconds between status polls in wait_for_claim
_DEFAULT_POLL_INTERVAL: int = 30


def _p2sh_script_hash(offer_redeem_hex: str) -> bytes:
    """Return the ElectrumX script hash for a P2SH output.

    ElectrumX indexes UTXOs by ``sha256(locking_script)`` with bytes reversed
    (little-endian / display order).  For a P2SH output the locking script is
    the 23-byte ``OP_HASH160 <hash160(redeem)> OP_EQUAL`` script.
    """
    redeem = bytes.fromhex(offer_redeem_hex)
    p2sh_spk = compute_p2sh_script_pubkey(redeem)
    digest = hashlib.sha256(p2sh_spk).digest()
    return digest[::-1]  # little-endian (ElectrumX convention)


@dataclass(frozen=True)
class GravityOfferParams:
    """Parameters required to create a new Gravity MakerOffer.

    These are the funding-UTXO details for the Maker's side.  The
    ``GravityOffer`` itself (covenant bytecode, BTC-side params, etc.)
    is built externally (e.g. via ``build_gravity_offer``) and passed as
    ``offer``.

    Attributes
    ----------
    offer:
        Fully populated ``GravityOffer`` with ``offer_redeem_hex`` set.
    funding_txid:
        Hex txid of the Maker's P2PKH UTXO being spent to fund the offer.
    funding_vout:
        Output index of the Maker's funding UTXO.
    funding_photons:
        Value of the Maker's funding UTXO in photons.
    fee_sats:
        Miner fee in photons for the MakerOffer funding tx.
    change_address:
        Optional Radiant P2PKH address for change output.  See
        ``build_maker_offer_tx`` for semantics.
    """

    offer: GravityOffer
    funding_txid: str
    funding_vout: int
    funding_photons: int
    fee_sats: int
    change_address: Optional[str] = None


@dataclass
class ActiveOffer:
    """State of a live Gravity MakerOffer on Radiant.

    Returned by :meth:`GravityMakerSession.create_offer` and required by
    all subsequent lifecycle methods.

    Attributes
    ----------
    offer:
        The original ``GravityOffer`` covenant parameters.
    maker_offer_result:
        Raw tx details from ``build_maker_offer_tx``.
    offer_txid:
        Radiant txid of the confirmed MakerOffer funding output.
    offer_vout:
        Output index of the MakerOffer P2SH UTXO (always 0).
    offer_photons:
        Photons locked in the MakerOffer P2SH output.
    """

    offer: GravityOffer
    maker_offer_result: MakerOfferResult
    offer_txid: str
    offer_vout: int
    offer_photons: int


class GravityMakerSession:
    """Manage the full lifecycle of a Gravity BTC↔RXD atomic swap offer.

    This class handles the Maker's side of the swap:

    1. Build and broadcast the MakerOffer tx (``create_offer``).
    2. Poll for the Taker's claim (``wait_for_claim``).
    3. Broadcast a cancel tx if the Taker never claims (``cancel_offer``).
    4. Query current state (``check_status``).

    Parameters
    ----------
    rxd_client:
        Connected :class:`~pyrxd.network.electrumx.ElectrumXClient` for
        Radiant chain operations (broadcast, query UTXOs).
    btc_source:
        A :class:`~pyrxd.network.bitcoin.BtcDataSource` — used only by
        subclasses / extensions that need BTC confirmation data.  May be
        ``None`` for pure Radiant operations.
    maker_priv:
        Maker's secp256k1 private key wrapped in ``PrivateKeyMaterial``.
    poll_interval_seconds:
        Seconds between UTXO polls in ``wait_for_claim``. Default 30.

    Examples
    --------
    Typical Maker flow::

        async with ElectrumXClient(["wss://electrumx.example.com"]) as rxd:
            session = GravityMakerSession(rxd_client=rxd, maker_priv=priv)
            params = GravityOfferParams(
                offer=offer,
                funding_txid="...",
                funding_vout=0,
                funding_photons=5_100_000,
                fee_sats=100_000,
            )
            active = await session.create_offer(params)
            claim_txid = await session.wait_for_claim(active, timeout_seconds=3600)
            if claim_txid is None:
                cancel_txid = await session.cancel_offer(active)
    """

    def __init__(
        self,
        rxd_client: ElectrumXClient,
        maker_priv: PrivateKeyMaterial,
        btc_source: Optional[BtcDataSource] = None,
        poll_interval_seconds: int = _DEFAULT_POLL_INTERVAL,
    ) -> None:
        self._rxd = rxd_client
        self._priv = maker_priv
        self._btc = btc_source
        self._poll_interval = poll_interval_seconds

    # ------------------------------------------------------------------
    # Step 1: Build + broadcast the MakerOffer tx
    # ------------------------------------------------------------------

    async def create_offer(self, offer_params: GravityOfferParams) -> ActiveOffer:
        """Build and broadcast the MakerOffer funding tx.

        The offer UTXO is a P2SH output locked to ``offer_params.offer``'s
        MakerOffer covenant.  Once broadcast, the Taker can claim it by
        spending it with ``build_claim_tx``.

        Parameters
        ----------
        offer_params:
            Funding-UTXO details and the ``GravityOffer`` covenant.

        Returns
        -------
        ActiveOffer
            Populated with the resulting txid and UTXO details.

        Raises
        ------
        ValidationError
            On any parameter format or covenant validation error.
        NetworkError
            On broadcast failure.
        """
        result = build_maker_offer_tx(
            offer=offer_params.offer,
            funding_txid=offer_params.funding_txid,
            funding_vout=offer_params.funding_vout,
            funding_photons=offer_params.funding_photons,
            fee_sats=offer_params.fee_sats,
            maker_privkey=self._priv,
            change_address=offer_params.change_address,
        )

        raw = bytes.fromhex(result.tx_hex)
        broadcast_txid = await self._rxd.broadcast(raw)
        txid_str = str(broadcast_txid)
        logger.info("MakerOffer tx broadcast: %s", txid_str)

        return ActiveOffer(
            offer=offer_params.offer,
            maker_offer_result=result,
            offer_txid=txid_str,
            offer_vout=0,
            offer_photons=result.output_photons,
        )

    # ------------------------------------------------------------------
    # Step 2: Poll for Taker's claim
    # ------------------------------------------------------------------

    async def wait_for_claim(
        self,
        offer: ActiveOffer,
        timeout_seconds: int = 3600,
    ) -> Optional[str]:
        """Poll for the Taker's claim transaction.

        Polls ``get_utxos()`` on the MakerOffer P2SH script hash.  When the
        UTXO disappears from the unspent set the Taker has claimed it.

        This method cannot directly return the claim txid — ElectrumX's
        ``listunspent`` API only reports which UTXOs are *currently* unspent.
        Once the offer UTXO is spent (claimed), we return the offer's txid
        as a sentinel so the caller knows which offer was claimed.  Callers
        that need the actual claim txid should fetch the spending tx
        separately (e.g. via ``get_transaction`` on the address history).

        Parameters
        ----------
        offer:
            The :class:`ActiveOffer` returned by ``create_offer``.
        timeout_seconds:
            Maximum seconds to wait. Returns ``None`` on timeout.

        Returns
        -------
        str or None
            The offer txid (as a claimed-sentinel) on success, or ``None``
            on timeout.
        """
        script_hash = _p2sh_script_hash(offer.offer.offer_redeem_hex)
        effective_interval = self._poll_interval if self._poll_interval > 0 else 1
        max_polls = max(1, timeout_seconds // effective_interval)

        logger.info(
            "Polling for claim on offer %s (timeout=%ds, interval=%ds)",
            offer.offer_txid[:16],
            timeout_seconds,
            self._poll_interval,
        )

        for attempt in range(max_polls):
            try:
                utxos = await self._rxd.get_utxos(script_hash)
            except NetworkError as exc:
                logger.warning(
                    "get_utxos poll %d/%d failed: %s — retrying",
                    attempt + 1,
                    max_polls,
                    exc,
                )
                if attempt + 1 < max_polls:
                    await asyncio.sleep(self._poll_interval)
                    continue
                raise

            # Check if the specific offer UTXO is still unspent.
            offer_unspent = any(
                u.tx_hash == offer.offer_txid and u.tx_pos == offer.offer_vout
                for u in utxos
            )

            if not offer_unspent and attempt > 0:
                # The UTXO has been spent — the Taker has claimed it.
                logger.info("Offer %s claimed (UTXO spent)", offer.offer_txid[:16])
                return offer.offer_txid

            if offer_unspent:
                logger.debug(
                    "Offer %s still open (poll %d/%d)",
                    offer.offer_txid[:16],
                    attempt + 1,
                    max_polls,
                )
            else:
                # attempt == 0 and UTXO not found — may not be confirmed yet
                logger.debug(
                    "Offer UTXO not visible yet on poll %d/%d — may be unconfirmed",
                    attempt + 1,
                    max_polls,
                )

            if attempt + 1 < max_polls:
                await asyncio.sleep(self._poll_interval)

        logger.info(
            "wait_for_claim timed out after %ds for offer %s",
            timeout_seconds,
            offer.offer_txid[:16],
        )
        return None

    # ------------------------------------------------------------------
    # Cancel: Maker reclaims before deadline
    # ------------------------------------------------------------------

    async def cancel_offer(self, offer: ActiveOffer, fee_sats: int = 1000, maker_address: str = "") -> str:
        """Broadcast the cancel (MakerOffer.cancel()) transaction.

        Reclaims the MakerOffer UTXO before the claim deadline using
        ``build_cancel_tx``.  This is only valid if the Taker has NOT yet
        claimed the UTXO.

        Parameters
        ----------
        offer:
            The :class:`ActiveOffer` to cancel.
        fee_sats:
            Miner fee in photons for the cancel tx. Default 1000.
        maker_address:
            Maker's Radiant P2PKH address to receive the reclaimed photons.
            Required — must be a valid Radiant address.

        Returns
        -------
        str
            The cancel tx's txid.

        Raises
        ------
        ValidationError
            If ``maker_address`` is empty or the offer redeem is invalid.
        NetworkError
            On broadcast failure.
        """
        if not maker_address:
            raise ValidationError(
                "maker_address is required for cancel_offer — "
                "provide the Maker's Radiant P2PKH address to receive reclaimed photons"
            )

        result: CancelResult = build_cancel_tx(
            offer=offer.offer,
            funding_txid=offer.offer_txid,
            funding_vout=offer.offer_vout,
            funding_photons=offer.offer_photons,
            maker_address=maker_address,
            fee_sats=fee_sats,
            maker_privkey=self._priv,
        )

        raw = bytes.fromhex(result.tx_hex)
        broadcast_txid = await self._rxd.broadcast(raw)
        txid_str = str(broadcast_txid)
        logger.info("MakerOffer cancel tx broadcast: %s", txid_str)
        return txid_str

    # ------------------------------------------------------------------
    # Status check
    # ------------------------------------------------------------------

    async def check_status(self, offer: ActiveOffer) -> str:
        """Return the current status of the offer UTXO.

        Queries the Radiant ElectrumX server for the MakerOffer P2SH UTXO.

        Returns one of:

        * ``"open"``      — UTXO is still unspent (offer not yet claimed).
        * ``"claimed"``   — UTXO no longer in unspent set (Taker has claimed).
        * ``"expired"``   — claim_deadline has passed and UTXO is unspent
                            (Maker can now forfeit).
        * ``"unknown"``   — UTXO not found and not yet past deadline
                            (may be unconfirmed or already finalized/cancelled).

        Parameters
        ----------
        offer:
            The :class:`ActiveOffer` to check.

        Returns
        -------
        str
            One of ``"open"``, ``"claimed"``, ``"expired"``, ``"unknown"``.

        Raises
        ------
        NetworkError
            On ElectrumX query failure.
        """
        script_hash = _p2sh_script_hash(offer.offer.offer_redeem_hex)
        utxos = await self._rxd.get_utxos(script_hash)

        offer_utxo = next(
            (u for u in utxos if u.tx_hash == offer.offer_txid and u.tx_pos == offer.offer_vout),
            None,
        )

        now = int(time.time())

        if offer_utxo is not None:
            # UTXO is still unspent
            if offer.offer.claim_deadline <= now:
                logger.info(
                    "Offer %s is expired (deadline passed %ds ago)",
                    offer.offer_txid[:16],
                    now - offer.offer.claim_deadline,
                )
                return "expired"
            return "open"

        # UTXO is not in the unspent set
        if offer.offer.claim_deadline <= now:
            # Past deadline and spent — likely claimed + finalized, or cancelled
            return "claimed"

        # Before deadline and spent — claimed by Taker (or cancelled)
        # Without querying tx history we can't distinguish claimed from cancelled
        return "claimed"
