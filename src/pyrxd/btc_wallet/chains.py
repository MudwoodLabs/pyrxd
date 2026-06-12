"""Bitcoin-family (PoW-depth) counter-chain registry — the per-chain safety knobs.

The mirror of :mod:`pyrxd.eth_wallet.chains` for the swap coordinator's *PoW-depth*
family. The Taproot-HTLC leg machinery (:mod:`pyrxd.btc_wallet.taproot`) is
chain-agnostic across BIP341-activating Bitcoin-family chains: the same P2TR HTLC,
claim/refund builders, preimage scrape, and BIP68 CSV semantics were proven byte-for-
byte on Litecoin 0.21.5.5 regtest consensus (claim accepted, wrong-preimage rejected
with the identical witness-program-mismatch reason, premature refund ``non-BIP68-final``,
matured refund accepted) — so adding a Bitcoin-family chain does NOT touch the
coordinator. ``NegotiatedTerms.counter_chain`` stays ``"btc"`` (it names the PoW-depth
*family*); the concrete chain is pinned by the leg/locator ``network`` tag (the bech32
HRP), exactly as an EVM swap pins its chain by EIP-155 chain id.

What IS chain-specific — and safety-critical:

* ``block_interval_s`` — sizes every blocks↔seconds conversion in
  :class:`~pyrxd.gravity.swap_coordinator.MarginPolicy` (cross-clock margins, the
  proactive-refund window, reorg-depth reserves). Litecoin's 2.5-minute target means an
  N-block margin is 4x less wall-clock than the same N on Bitcoin — pass the right
  interval or every timing safety margin silently shrinks.
* **Confirmation depth must be value-scaled PER CHAIN.** Depth buys reorg-resistance
  priced in that chain's hashrate; "6 confirmations" folklore transfers across chains
  even less than it transfers across values. A real-value run needs a measured
  ``MarginPolicy.measured(...)`` with depths sized to the target chain's cost-to-reorg —
  this registry deliberately does NOT ship depth defaults.
* The mainnet data sources: the bundled funding-reader/broadcaster backends
  (``network/bitcoin.py``) are Bitcoin-mainnet-specific; a Litecoin deployment supplies
  its own reader/broadcaster (the regtest harness drives the node RPC directly).

Every mainnet ``network`` tag here is value-bearing and stays behind the leg's
``audit_cleared`` gate; the regtest/testnet tags are in ``AUDIT_CLEARED_NETWORKS``
(isolated, no-value chains).
"""

from __future__ import annotations

from dataclasses import dataclass

from pyrxd.security.errors import ValidationError

__all__ = ["KNOWN_POW_CHAINS", "PowChain", "pow_chain_by_network"]


@dataclass(frozen=True)
class PowChain:
    """One Bitcoin-family counter chain the Taproot-HTLC leg can run against.

    ``network`` / ``testnet_network`` / ``regtest_network`` are the bech32 HRPs —
    the tag the leg, the locator, and the audit gates all key on.
    ``block_interval_s`` seeds ``MarginPolicy(block_interval_s=...)``.
    """

    name: str
    network: str
    testnet_network: str
    regtest_network: str
    block_interval_s: float

    def __post_init__(self) -> None:
        for label, tag in (
            ("network", self.network),
            ("testnet_network", self.testnet_network),
            ("regtest_network", self.regtest_network),
        ):
            if not isinstance(tag, str) or not tag:
                raise ValidationError(f"PowChain.{label} must be a non-empty str")
        if (
            not isinstance(self.block_interval_s, (int, float))
            or isinstance(self.block_interval_s, bool)
            or self.block_interval_s <= 0
        ):
            raise ValidationError("PowChain.block_interval_s must be a positive number")


KNOWN_POW_CHAINS: dict[str, PowChain] = {
    # Bitcoin — 10-minute target interval.
    "bitcoin": PowChain(
        name="bitcoin", network="bc", testnet_network="tb", regtest_network="bcrt", block_interval_s=600.0
    ),
    # Litecoin — 2.5-minute target interval. Taproot active since the MWEB upgrade
    # (Litecoin Core 0.21.x; active from genesis on regtest — measured 2026-06-12 on
    # the official v0.21.5.5 binary, see docker/litecoin-regtest.Dockerfile).
    "litecoin": PowChain(
        name="litecoin", network="ltc", testnet_network="tltc", regtest_network="rltc", block_interval_s=150.0
    ),
}


def pow_chain_by_network(network: str) -> PowChain:
    """Look up a known chain by ANY of its network tags (mainnet/testnet/regtest HRP);
    raises for an unknown tag (fail-closed — an unknown chain has no vetted block
    interval, so refuse rather than guess)."""
    for chain in KNOWN_POW_CHAINS.values():
        if network in (chain.network, chain.testnet_network, chain.regtest_network):
            return chain
    raise ValidationError(
        f"unknown Bitcoin-family network tag {network!r}: no vetted block interval. Add it to "
        "KNOWN_POW_CHAINS with a sourced block_interval_s, or construct MarginPolicy with an "
        "explicitly chosen block_interval_s."
    )
