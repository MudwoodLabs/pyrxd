"""Ethereum counter-chain leg for Gravity cross-chain atomic swaps (native ETH).

The ETH backend mirrors the proven BTC Taproot-HTLC leg: it locks/claims/refunds a
hashlocked, timelocked position whose secret ``p`` (``H = sha256(p)``) is shared with
the Radiant covenant. The Radiant side is unchanged — it only requires
``sha256(preimage) == H`` + a relative-timelock refund — so the ETH leg is a drop-in
counter-chain backend.

This package is split so the SECURITY-CRITICAL parsing is testable with no network and
no web3 dependency:

* ``secret`` — pure ``recover_secret`` (scan every 32-byte window by ``sha256==H``,
  never by offset; the C-PARSER discipline carried over from the BTC witness scraper);
  handles calldata AND event-log data, including a reverted-but-mined claim.
* ``locator`` — the durable ``EthHtlcLocator`` (chainId + contract address + immutables);
  JSON round-trip, no secret.
* ``htlc_leg`` (added with the network layer) — the web3-backed leg wiring
  (deploy/claim/refund/is_final), used only against a live RPC (Sepolia/​mainnet).

Honest scope: the contract + this leg are DESIGNED-AND-UNPROVEN until the Sepolia
end-to-end proof. External audit of the Solidity contract + cross-chain atomicity is a
hard gate before any real-value use.
"""

from __future__ import annotations

from .locator import EthHtlcLocator
from .secret import recover_secret

__all__ = ["EthHtlcLocator", "recover_secret"]
