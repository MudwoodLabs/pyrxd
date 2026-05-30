"""EthLeg — the gravity-layer counter-chain adapter over EthHtlcContractLeg.

Wraps the web3-backed :class:`pyrxd.eth_wallet.htlc_leg.EthHtlcContractLeg` (the chain-native
ETH HTLC) in the SwapCoordinator's duck-typed *counter leg* interface — the same surface the
proven ``BitcoinTaprootLeg`` exposes (derive/promised funding target, ``fund``, ``claim``,
``refund``, ``scrape_secret``, ``locked_amount``, ``.network``) plus the finality verdict — so
the mature coordinator can drive an ETH↔RXD swap with the RXD leg + FSM + reorg gate unchanged.

Two ETH-specific realities the adapter encodes (re-audit §9 + B1):

* **No pre-fund scriptPubKey.** A BTC P2TR funding address is a pure function of the terms, so
  the coordinator's step-4 derive==promised gate binds the funding target before the lock. An
  ETH HTLC contract does not exist until ``fund()`` deploys it, so there is nothing to derive
  pre-fund. ``derive``/``promised`` return the same deterministic terms commitment (the gate
  passes trivially) and the REAL binding is :meth:`EthHtlcContractLeg.verify_funded`, run
  inside :meth:`fund` POST-deploy (eth_getCode logic + immutables-by-getter == terms + balance
  == amount) before the maker is told to lock RXD.
* **Absolute timeout, wei amount.** The ETH refund deadline is an absolute unix timestamp (a
  per-swap negotiation input carried by this leg), not a relative timelock; the funded amount
  is wei. ``locked_amount`` returns wei (the coordinator binds it to ``terms.value_amount``);
  ``refund`` ignores the relative ``Timelock`` the coordinator passes (the timeout is the
  contract immutable in the locator).
"""

from __future__ import annotations

import hashlib

from pyrxd.btc_wallet.htlc_leg import require_audit_cleared
from pyrxd.eth_wallet.htlc_leg import EthHtlcContractLeg
from pyrxd.eth_wallet.locator import EthHtlcLocator
from pyrxd.gravity.finality import CounterClaimFinality
from pyrxd.security.errors import ValidationError

__all__ = ["EthLeg"]


class EthLeg:
    """Coordinator-shaped ETH counter leg.

    Parameters
    ----------
    contract_leg:
        The web3-backed :class:`EthHtlcContractLeg` (already holding the rpc + signing key +
        artifact + chain id).
    network:
        Network tag (e.g. ``"sepolia"``, ``"anvil"``, ``"mainnet"``). Read by the coordinator's
        ``_leg_is_value_bearing`` gate, and gated by ``require_audit_cleared``.
    claim_to / refund_to:
        The maker's ETH address (receives ETH on ``claim(p)``) and the taker's ETH address
        (receives ETH on ``refund()``). These live on the leg, not in ``NegotiatedTerms``.
    eth_timeout_unix_s:
        The absolute negotiated ETH refund deadline (the contract immutable ``timeout``).
    audit_cleared:
        Fail-closed audit gate (same discipline as the BTC leg): a non-test network refuses to
        run unless an external audit of the ETH bridge has cleared it and this is set True.
    """

    def __init__(
        self,
        *,
        contract_leg: EthHtlcContractLeg,
        network: str,
        claim_to: str,
        refund_to: str,
        eth_timeout_unix_s: int,
        audit_cleared: bool = False,
    ) -> None:
        if not isinstance(contract_leg, EthHtlcContractLeg):
            raise ValidationError("contract_leg must be an EthHtlcContractLeg")
        if not isinstance(network, str) or not network:
            raise ValidationError("network must be a non-empty str")
        if not isinstance(eth_timeout_unix_s, int) or isinstance(eth_timeout_unix_s, bool) or eth_timeout_unix_s <= 0:
            raise ValidationError("eth_timeout_unix_s must be a positive int (absolute unix deadline)")
        require_audit_cleared(network, audit_cleared=audit_cleared)
        self._leg = contract_leg
        self.network = network  # _leg_is_value_bearing reads getattr(leg, "network")
        self._claim_to = claim_to
        self._refund_to = refund_to
        self._eth_timeout_unix_s = int(eth_timeout_unix_s)

    # -- funding target (the coordinator's pre-lock derive==promised gate) --------------
    #
    # ETH has no pre-fund scriptPubKey, so both sides return the same deterministic terms
    # commitment (the gate passes) and the real binding is verify_funded() post-deploy in fund().

    def derive_funding_scriptpubkey(self, terms) -> bytes:
        return self._commitment(terms)

    def promised_funding_scriptpubkey(self, terms) -> bytes:
        return self._commitment(terms)

    def _commitment(self, terms) -> bytes:
        return hashlib.sha256(
            b"eth-htlc-funding-commitment-v1"
            + bytes(terms.hashlock)
            + self._claim_to.encode()
            + self._refund_to.encode()
            + self._eth_timeout_unix_s.to_bytes(8, "big")
            + int(terms.value_amount).to_bytes(32, "big")
        ).digest()

    def locked_amount(self, locator: EthHtlcLocator) -> int:
        """The funded amount the coordinator binds to ``terms.value_amount`` — wei for ETH."""
        return locator.amount_wei

    # -- fund / claim / refund -----------------------------------------------------------

    async def fund(self, terms) -> EthHtlcLocator:
        """Deploy + fund the ETH HTLC from the negotiated terms, then run the post-deploy
        binding gate (verify_funded) BEFORE returning — so the coordinator never tells the
        maker to lock RXD against a wrong/attacker/under-funded contract."""
        # Consistency (audit HIGH-1): the leg's absolute deadline MUST equal the negotiated
        # term the coordinator's cross-clock ordering gate validated — otherwise the leg could
        # deploy a contract with a deadline the gate never checked. Fail closed on a mismatch.
        terms_timeout = getattr(terms, "eth_timeout_unix_s", None)
        if terms_timeout is not None and int(terms_timeout) != self._eth_timeout_unix_s:
            raise ValidationError(
                f"terms.eth_timeout_unix_s ({terms_timeout}) != this leg's eth_timeout_unix_s "
                f"({self._eth_timeout_unix_s}); the validated deadline and the deployed deadline must agree"
            )
        locator = await self._leg.fund(
            hashlock=bytes(terms.hashlock),
            claimant=self._claim_to,
            refundee=self._refund_to,
            timeout=self._eth_timeout_unix_s,
            amount_wei=int(terms.value_amount),
        )
        await self._leg.verify_funded(locator, expected_amount_wei=int(terms.value_amount))
        return locator

    async def claim(self, locator: EthHtlcLocator, preimage: bytes) -> str:
        return await self._leg.claim(locator, preimage)

    async def refund(self, locator: EthHtlcLocator, timeout=None) -> str:
        # The ETH timeout is the contract immutable carried by the locator; the relative
        # Timelock the coordinator passes (BTC-shaped) is intentionally ignored.
        return await self._leg.refund(locator)

    # -- secret recovery + finality ------------------------------------------------------

    def scrape_secret(self, claim_artifacts: list[bytes], hashlock: bytes) -> bytes:
        """Recover ``p`` from the maker's ETH claim — fail-closed by ``sha256 == H`` over the
        candidate blobs (calldata + log data) the caller fetched via :meth:`fetch_claim_artifacts`.
        Pure (no network), mirroring the BTC leg's pure witness scrape."""
        return self._leg.recover_secret(claim_artifacts, hashlock)

    async def fetch_claim_artifacts(self, tx_hash: str) -> list[bytes]:
        """Fetch the candidate byte blobs (claim calldata + receipt log data) for
        :meth:`scrape_secret`. Works on a reverted-but-mined claim too."""
        return await self._leg.fetch_claim_artifacts(tx_hash)

    async def assert_claim_provenance(self, tx_hash: str, *, contract_address: str, preimage: bytes) -> None:
        """Provenance gate (R6) — the ETH analogue of the BTC funding-outpoint check: the
        claim tx must target THIS swap's HTLC contract instance and emit the revealed secret
        ``p`` from it (``tx.to`` + a successful receipt + a ``Claimed(p)`` log from the
        contract). Binds the SECRET ``p``, not the public ``H``. Fail-closed; see
        :meth:`EthHtlcContractLeg.assert_claim_provenance`."""
        await self._leg.assert_claim_provenance(tx_hash, contract_address=contract_address, preimage=preimage)

    async def claim_finality_verdict(self, tx_hash: str) -> CounterClaimFinality:
        """The point-in-time ETH finality verdict (FINAL once at/under the ``finalized``
        checkpoint, else NOT_YET_FINAL_LIVE) the reorg gate consumes."""
        return await self._leg.claim_finality_verdict(tx_hash)
