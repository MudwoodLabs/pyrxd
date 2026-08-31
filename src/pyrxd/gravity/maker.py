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
import math
import time
from collections.abc import Callable
from dataclasses import dataclass

from pyrxd.network.bitcoin import BtcDataSource
from pyrxd.network.electrumx import ElectrumXClient
from pyrxd.security.errors import NetworkError, ValidationError
from pyrxd.security.secrets import PrivateKeyMaterial

from .codehash import compute_p2sh_script_pubkey
from .fee_policy import DeadlineFeePolicy
from .transactions import build_cancel_tx, build_maker_offer_tx
from .types import CancelResult, GravityOffer, MakerOfferResult

__all__ = [
    "ActiveOffer",
    "GravityMakerSession",
    "GravityOfferParams",
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
    change_address: str | None = None


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
    fee_policy:
        Min-relay rate every transaction this session builds is sized and checked
        against. Defaults to
        :data:`~pyrxd.gravity.fee_policy.DEFAULT_RADIANT_DEADLINE_FEE_POLICY` (mainnet).
        **Set this on regtest**, whose node advertises a tenth of the mainnet floor —
        without it the high-level API has no way to reach the escape hatch the
        builders already accept.

    Examples
    --------
    Typical Maker flow::

        async with ElectrumXClient(["wss://electrumx.example.com"]) as rxd:
            session = GravityMakerSession(rxd_client=rxd, maker_priv=priv)
            params = GravityOfferParams(
                offer=offer,
                funding_txid="...",
                funding_vout=0,
                funding_photons=12_000_000,
                fee_sats=2_500_000,  # ~250-byte funding tx at the 10_000 photons/byte floor
            )
            active = await session.create_offer(params)
            claim_txid = await session.wait_for_claim(active, timeout_seconds=3600)
            if claim_txid is None:
                # fee omitted: sized from the cancel tx's own measured bytes.
                cancel_txid = await session.cancel_offer(active, maker_address=maker_addr)
    """

    def __init__(
        self,
        rxd_client: ElectrumXClient,
        maker_priv: PrivateKeyMaterial,
        btc_source: BtcDataSource | None = None,
        poll_interval_seconds: int = _DEFAULT_POLL_INTERVAL,
        fee_policy: DeadlineFeePolicy | None = None,
    ) -> None:
        self._rxd = rxd_client
        self._priv = maker_priv
        self._btc = btc_source
        self._poll_interval = poll_interval_seconds
        self._fee_policy = fee_policy

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
            fee_policy=self._fee_policy,
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
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> str | None:
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
            Maximum seconds to wait, as WALL-CLOCK seconds. Returns ``None`` on timeout.
        clock:
            Monotonic-ish time source. Injectable so the timeout branch is reachable in a
            test without sleeping — the same shape ``pyrxd.network.confirm`` uses, and for
            the same reason: a fake ``sleep`` does not advance a real clock.

        Returns
        -------
        str or None
            The offer txid (as a claimed-sentinel) on success, or ``None``
            on timeout.
        """
        script_hash = _p2sh_script_hash(offer.offer.offer_redeem_hex)
        # A DEADLINE, not a poll count (#475). Deriving `max_polls = timeout // interval` and
        # looping that many times measures polls, not time: every network round trip inside the
        # loop is unbudgeted, so the real bound is `max_polls * (interval + latency)`. At the
        # shipped defaults (interval 30 s, timeout 3600 s => 120 polls) a 1 s per-iteration
        # latency overruns by 120 s, and 3 s by 360 s — 10%. This is the same defect the
        # confirmation waits carried before 0.20.0, so it takes the same fix.
        if not isinstance(timeout_seconds, (int, float)) or isinstance(timeout_seconds, bool):
            raise ValidationError("timeout_seconds must be a number")
        if not math.isfinite(timeout_seconds) or timeout_seconds < 0:
            raise ValidationError(f"timeout_seconds must be finite and >= 0, got {timeout_seconds!r}")
        effective_interval = self._poll_interval if self._poll_interval > 0 else 1
        started = clock()
        deadline = started + float(timeout_seconds)

        logger.info(
            "Polling for claim on offer %s (timeout=%ds, interval=%ds)",
            offer.offer_txid[:16],
            timeout_seconds,
            self._poll_interval,
        )

        attempt = 0
        last_error: NetworkError | None = None
        while True:
            # Do not START a poll we cannot afford. The poll's own duration is unknowable in
            # advance, so the honest bound is deadline + ONE poll — not the deadline exactly.
            # What changed is that the overrun no longer ACCUMULATES: the old loop paid it 120
            # times over at the shipped defaults.
            if attempt and clock() >= deadline:
                if last_error is not None:
                    # A dead endpoint is NOT "no claim happened". Returning None here would tell
                    # the maker the taker never claimed, when the truth is we could not see. The
                    # pre-deadline `raise` in the retry lane below is unreachable once the sleep
                    # lands exactly on the deadline, so the error is carried out to here.
                    raise last_error
                break
            attempt += 1
            try:
                utxos = await self._rxd.get_utxos(script_hash)
            except NetworkError as exc:
                logger.warning("get_utxos poll %d failed: %s — retrying", attempt, exc)
                last_error = exc
                # The poll happened BEFORE this sleep, so an unclamped sleep runs past the
                # deadline rather than up to it. Re-read the clock: the failing read itself
                # consumed time, which is the whole point of the change.
                remaining = deadline - clock()
                if remaining <= 0:
                    raise
                await asyncio.sleep(min(effective_interval, remaining))
                continue

            last_error = None  # a successful read clears it; only a FAILING tail should raise
            # Check if the specific offer UTXO is still unspent.
            offer_unspent = any(u.tx_hash == offer.offer_txid and u.tx_pos == offer.offer_vout for u in utxos)

            # `attempt > 1` (was `> 0`): an offer UTXO missing from the FIRST poll is ambiguous —
            # not yet indexed reads identically to already spent — so the first observation is
            # treated as "not visible yet" rather than as a claim. Renumbered with the loop, which
            # now counts from 1; the guard is unchanged in meaning.
            if not offer_unspent and attempt > 1:
                # The UTXO has been spent — the Taker has claimed it.
                logger.info("Offer %s claimed (UTXO spent)", offer.offer_txid[:16])
                return offer.offer_txid

            if offer_unspent:
                logger.debug("Offer %s still open (poll %d)", offer.offer_txid[:16], attempt)
            else:
                # First poll and the UTXO is not there — may simply not be indexed yet.
                logger.debug("Offer UTXO not visible yet on poll %d — may be unconfirmed", attempt)

            remaining = deadline - clock()
            if remaining <= 0:
                break
            await asyncio.sleep(min(effective_interval, remaining))

        logger.info(
            "wait_for_claim timed out after %.1fs (budget %ss, %d polls) for offer %s",
            clock() - started,
            timeout_seconds,
            attempt,
            offer.offer_txid[:16],
        )
        return None

    # ------------------------------------------------------------------
    # Cancel: Maker reclaims before deadline
    # ------------------------------------------------------------------

    async def cancel_offer(
        self,
        offer: ActiveOffer,
        fee_sats: int | None = None,
        maker_address: str = "",
        fee_policy: DeadlineFeePolicy | None = None,
    ) -> str:
        """Broadcast the cancel (MakerOffer.cancel()) transaction.

        Reclaims the MakerOffer UTXO before the claim deadline using
        ``build_cancel_tx``.  This is only valid if the Taker has NOT yet
        claimed the UTXO.

        Parameters
        ----------
        offer:
            The :class:`ActiveOffer` to cancel.
        fee_sats:
            Miner fee in photons for the cancel tx. ``None`` (the default) sizes it
            from the assembled transaction's own bytes at the relay floor — the only
            correct default, because the cancel scriptSig carries the whole MakerOffer
            redeem script and its size therefore varies per offer. This parameter
            previously defaulted to ``1000``, ~2,840x under the floor for a 285-byte
            cancel, which made the documented ``cancel_offer(active)`` flow raise on
            first use and left the Maker with no revocation path.
        maker_address:
            Maker's Radiant P2PKH address to receive the reclaimed photons.
            Required — must be a valid Radiant address.
        fee_policy:
            Per-call override of the session's policy. Set on regtest, which advertises
            a tenth of the mainnet relay floor.

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
            fee_policy=fee_policy or self._fee_policy,
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
