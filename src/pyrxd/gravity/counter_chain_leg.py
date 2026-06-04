"""CounterChainLeg — the abstract interface a swap counter-chain backend must implement.

The Gravity coordinator drives a chain-NEUTRAL atomic-swap FSM against two legs: the
Radiant covenant leg (the asset side) and a *counter-chain* leg (the value side). Two
counter-chain backends are now PROVEN — the BTC Taproot-HTLC (mainnet) and the ETH
Solidity-HTLC (Sepolia) — so the abstraction is extracted from two real shapes rather
than guessed from one (the BTC plan deliberately deferred it until this point).

This ABC is the documented contract. It is defined as an :class:`abc.ABC` to match the
repo's existing multi-backend idiom (``network.bitcoin.BtcDataSource(ABC)``) and so the
coordinator's fail-closed ``isinstance`` discipline applies; the gravity tree is not in
the typed (mypy) path, so a structural ``typing.Protocol`` would buy nothing here.

SCOPE NOTE (honest): the proven BTC path consumes module functions in
``btc_wallet.taproot`` via a duck-typed surface (see the coordinator + its test fakes),
NOT a ``BitcoinTaprootLeg`` class — that class does not exist yet. Rewiring the
mainnet-proven coordinator + migrating the durable ``SwapRecord.btc_locator`` to a
chain-tagged ``counterchain_locator`` union is the larger, riskier half of this work and
is deferred to a dedicated, separately-tested change (it must not be done casually on
mainnet-proven code). This file captures the INTERFACE now so both real legs have a named
target and the seam is documented; adopting it in the coordinator is the follow-up.

The two real implementations and how they realise each method:

  derive_expected_funding / verify the on-chain funding matches the negotiated terms
    BTC: compare the derived P2TR scriptPubKey to the promised one (pure, off the terms).
    ETH: read the deployed contract's runtime logic (immutable slots masked) + immutables
         via getters + funded balance, all == negotiated (``verify_funded``).
  fund(terms) -> CounterChainLocator
    BTC: fund the P2TR HTLC -> BtcHtlcLocator.
    ETH: deploy+fund the EthHtlc contract (returns the locator only after status==1)
         -> EthHtlcLocator.
  claim(locator, preimage)
    BTC: broadcast the claim tx (preimage in the witness).
    ETH: call claim(preimage) (preimage in calldata + a Claimed event); private inclusion
         on mainnet.
  refund(locator)            # timeout is carried by the locator
    BTC: broadcast the CSV refund (v2/nSequence). ETH: call refund() after timeout.
  recover_secret(claim_artifact, hashlock) -> bytes
    Both: match sha256(candidate)==H over ALL candidate windows, never by offset
    (the C-PARSER discipline). BTC artifact = claim-tx bytes (witness pushes); ETH
    artifact = fetched calldata + event-log data (incl. a reverted-but-mined claim).
  is_final(tx_or_locator) -> bool
    BTC: confirmation depth. ETH: at/under the `finalized` checkpoint. Finality is
    irreducibly chain-specific, so it is a leg concern (not the coordinator reading a
    single RPC) — this is the one method the BTC-only design could hand-wave and a
    second chain cannot.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

__all__ = ["CounterChainLeg"]


class CounterChainLeg(ABC):
    """Abstract counter-chain HTLC leg (BTC Taproot / ETH contract / future chains).

    Implementations hold their own signing key material (as the repo's
    :class:`PrivateKeyMaterial`, never plaintext) and a chain RPC client. ``locator`` is a
    chain-specific durable record (``BtcHtlcLocator`` / ``EthHtlcLocator``) carrying no
    secret. ``claim_artifact`` is chain-specific opaque bytes/handle the leg knows how to
    read the preimage from. All methods fail closed (raise) rather than silently pass.
    """

    @abstractmethod
    async def fund(self, terms: Any) -> Any:
        """Lock the counter-chain value into a fresh HTLC; return its durable locator.

        MUST NOT return a locator until the funding is confirmed/irreversible enough that
        treating the leg as "locked" is safe (e.g. ETH waits for the deploy tx status==1).
        """

    @abstractmethod
    async def verify_funded(self, locator: Any, *, expected_amount_wei: int) -> None:
        """Pre-asset-lock gate: assert the on-chain HTLC matches the negotiated terms
        (program logic + hashlock + recipients + timeout + funded amount). Raise on any
        mismatch — the asset side MUST NOT be locked against an unverified counter-chain
        HTLC (defends 'taker funded an attacker/under-funded contract')."""

    @abstractmethod
    async def claim(self, locator: Any, preimage: bytes) -> Any:
        """Claim the counter-chain value with the preimage (revealing it on that chain)."""

    @abstractmethod
    async def refund(self, locator: Any) -> Any:
        """Reclaim the counter-chain value after the locator's timeout. Unilateral (no
        counterparty signature). The relative/absolute timeout is carried by ``locator``."""

    @abstractmethod
    def recover_secret(self, claim_artifact: Any, hashlock: bytes) -> bytes:
        """Recover the preimage ``p`` (sha256(p)==hashlock) from a claim artifact, matching
        over ALL candidate windows by hash (never by offset). Fail closed if absent."""

    @abstractmethod
    async def is_final(self, tx_or_locator: Any) -> bool:
        """True once the referenced claim/lock is final on the counter-chain (BTC depth /
        ETH `finalized`). The asset side MUST NOT be treated as irreversibly settled until
        the counter-chain claim is final (a pre-finality reorg could un-reveal ``p``)."""
