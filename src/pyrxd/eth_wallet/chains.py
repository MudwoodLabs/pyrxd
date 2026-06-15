"""EVM counter-chain registry — the per-chain safety knobs for the finalized-checkpoint leg.

The swap coordinator treats every non-BTC counter leg as a *finalized-checkpoint* (EVM)
chain: the proven ``EthLeg`` + ``EthHtlc.sol`` machinery is chain-id-agnostic (the same
contract bytecode and ``finalized``-tag reads work on any EVM-equivalent chain), so adding
an EVM chain does NOT touch the coordinator. What IS chain-specific — and safety-critical
for an atomic swap — is **how long the ``finalized`` tag lags the tip**, which sizes
``MarginPolicy.eth_finalization_window_s`` (the reorg gate's finalization reserve).

This module is that knowledge, written down once with provenance, instead of a magic
number per harness.

Window discipline (matches the existing codebase split):

* ``finalization_window_s`` is the **steady-state** lag of the ``finalized`` tag. Stalls
  (L1 inactivity leak, batcher outage) are budgeted SEPARATELY via
  ``CrossClockMargin.eth_finality_stall_tolerance_s`` — do not inflate the window to cover
  them.
* Ethereum L1: finality = 2 epochs = 768 s steady-state (Casper FFG). The 768 s floor is
  enforced by :class:`~pyrxd.gravity.swap_coordinator.MarginPolicy`.
* Base (OP-stack L2): an L2 block is ``finalized`` once the batch containing it sits in a
  FINALIZED L1 block — i.e. batch-posting cadence (~1 min on Base) + L1 inclusion + the
  same 2-epoch L1 finality. Steady-state ≈ 15 min; the entry below uses 900 s (CHOSEN/
  ESTIMATED). HONEST WORST CASE: the OP-stack *sequencing window* permits a batch to land
  up to **12 hours** late (and a chain that misses it can reorg that far) — a swap
  operator must size ``eth_finality_stall_tolerance_s`` (and therefore the RXD timelock)
  for the stall they are willing to survive, exactly as for an L1 finality stall.
  Sources: Base "Transaction Finality" docs; OP-stack batcher/configurability specs
  (https://docs.base.org/base-chain/network-information/transaction-finality,
  https://specs.optimism.io/protocol/configurability.html).
* Optimism (OP-stack L2): the SAME stack as Base, identical finalized-tag semantics; 900 s
  steady-state (observed ~15-20 min), 12 h sequencing-window worst case budgeted separately.
  Source: https://docs.optimism.io/app-developers/transactions/statuses
* Arbitrum One (Nitro optimistic rollup): finalized = L2 block whose Sequencer batch sits in a
  FINALIZED L1 block (Ethereum-anchored hard finality). ~10-20 min steady-state -> 1200 s. WORST
  CASE: the sequencer force-inclusion delay (``maxTimeVariation``) is ~24 h (vs OP-stack 12 h) — a
  liveness stall of the finalized tag, budgeted via ``eth_finality_stall_tolerance_s``; NOT the
  ~6.4 d withdrawal dispute window (irrelevant to reorg safety).
  Source: https://docs.arbitrum.io/how-arbitrum-works/transaction-lifecycle
* Linea (zk / validity rollup): finalized = L2 block whose validity PROOF is verified in a
  finalized L1 block (Ethereum-anchored). Proof-cadence-dominated: official MEDIAN hard finality
  ~1 h 40 (6000 s), documented to "never exceed 16 h" — that tail goes to the stall budget, not
  the steady window. Source: https://docs.linea.build (finality).

Deliberately NOT in the registry — **Polygon PoS** (chain_id 137): it does not fit this model.
Its ``finalized`` tag is Polygon's OWN validator-set "milestone" finality (Heimdall / CometBFT,
~5 s), NOT Ethereum-anchored — Polygon PoS is a commit-chain/sidechain that checkpoints to
Ethereum for withdrawal proofs but does not inherit Ethereum finality block-by-block. So the
768 s floor misrepresents it in BOTH directions: it finalizes far faster than 768 s (via its own
~5 s consensus), and that finality is secured by Polygon's stake, not Ethereum's. Treating it as
"just another EVM chain" would silently swap the trust model an atomic-swap operator relies on; a
Polygon-PoS swap needs an explicit, separately-justified finality model (a reorg depth in
Polygon's own security terms), not this Ethereum-anchored window. ``evm_chain_by_id(137)`` fails
closed. (A 2025-09-10 faulty-milestone incident delayed Polygon finality ~15 min-1 h, resolved
only by an emergency hard fork — a validator-set liveness risk with no Ethereum analogue.)

The ``network`` tag feeds the existing fail-closed gates unchanged: any tag not in
``AUDIT_CLEARED_NETWORKS`` (only isolated test chains are) is value-bearing and refuses to
run without the explicit post-audit ``audit_cleared=True`` opt-in — so every chain here,
including the testnets, stays behind the audit gate by construction.
"""

from __future__ import annotations

from dataclasses import dataclass

from pyrxd.security.errors import ValidationError

__all__ = ["KNOWN_EVM_CHAINS", "EvmChain", "evm_chain_by_id"]

# Keep in sync with MarginPolicy._MIN_ETH_FINALIZATION_WINDOW_S (the consensus-derived
# 2-epoch floor); re-declared here so registry entries fail fast at import time.
_FLOOR_S = 768


@dataclass(frozen=True)
class EvmChain:
    """One EVM-equivalent counter chain the ETH leg machinery can run against.

    ``chain_id`` pins the chain everywhere it matters: ``EthRpc(expected_chain_id=...)``
    refuses a node on the wrong chain, ``EthHtlcContractLeg(chain_id=...)`` signs with
    EIP-155 replay protection, and the durable ``EthHtlcLocator`` records it.
    ``network`` is the tag ``EthLeg(network=...)`` reads for the value-bearing/audit
    gates. ``finalization_window_s`` seeds ``MarginPolicy.eth_finalization_window_s``.
    """

    name: str
    chain_id: int
    network: str
    finalization_window_s: int

    def __post_init__(self) -> None:
        if not isinstance(self.chain_id, int) or isinstance(self.chain_id, bool) or self.chain_id <= 0:
            raise ValidationError("EvmChain.chain_id must be a positive int")
        if not isinstance(self.network, str) or not self.network:
            raise ValidationError("EvmChain.network must be a non-empty str")
        if (
            not isinstance(self.finalization_window_s, int)
            or isinstance(self.finalization_window_s, bool)
            or self.finalization_window_s < _FLOOR_S
        ):
            raise ValidationError(
                f"EvmChain.finalization_window_s must be an int >= {_FLOOR_S} "
                "(an L2 cannot finalize faster than the L1 checkpoint it settles to)"
            )


KNOWN_EVM_CHAINS: dict[str, EvmChain] = {
    # Ethereum L1 — finality = 2 epochs (Casper FFG), 768 s steady-state.
    "ethereum": EvmChain(name="ethereum", chain_id=1, network="mainnet", finalization_window_s=768),
    "sepolia": EvmChain(name="sepolia", chain_id=11155111, network="sepolia", finalization_window_s=768),
    # Base (OP-stack L2) — finalized = batch in a finalized L1 block. 900 s CHOSEN/ESTIMATED
    # steady-state (batch cadence + L1 inclusion + 768 s L1 finality); see module docstring
    # for the 12 h sequencing-window worst case and where to budget it.
    "base": EvmChain(name="base", chain_id=8453, network="base", finalization_window_s=900),
    "base-sepolia": EvmChain(name="base-sepolia", chain_id=84532, network="base-sepolia", finalization_window_s=900),
    # Optimism (OP-stack L2) — the SAME stack as Base, identical finalized-tag semantics
    # (finalized = batch in a finalized L1 block). 900 s matches Base's CHOSEN steady-state;
    # observed steady lag ~15-20 min, the 12 h sequencing-window worst case budgeted separately.
    "optimism": EvmChain(name="optimism", chain_id=10, network="optimism", finalization_window_s=900),
    "optimism-sepolia": EvmChain(
        name="optimism-sepolia", chain_id=11155420, network="optimism-sepolia", finalization_window_s=900
    ),
    # Arbitrum One (Nitro optimistic rollup) — finalized = L2 block whose Sequencer batch sits in
    # a FINALIZED L1 block (Ethereum-anchored "hard finality"). Steady-state ~10-20 min -> 1200 s
    # (upper end of the cited range); the ~24 h sequencer force-inclusion (maxTimeVariation) worst
    # case is a liveness stall, budgeted separately. NOT the ~6.4 d withdrawal dispute window.
    "arbitrum-one": EvmChain(name="arbitrum-one", chain_id=42161, network="arbitrum-one", finalization_window_s=1200),
    "arbitrum-sepolia": EvmChain(
        name="arbitrum-sepolia", chain_id=421614, network="arbitrum-sepolia", finalization_window_s=1200
    ),
    # Linea (zk / validity rollup) — finalized = L2 block whose validity PROOF is verified in a
    # finalized L1 block (Ethereum-anchored). Proof-cadence-dominated: 6000 s ~= the official
    # MEDIAN hard finality (~1 h 40); the documented up-to-16 h tail is budgeted separately.
    "linea": EvmChain(name="linea", chain_id=59144, network="linea", finalization_window_s=6000),
    "linea-sepolia": EvmChain(
        name="linea-sepolia", chain_id=59141, network="linea-sepolia", finalization_window_s=6000
    ),
}


def evm_chain_by_id(chain_id: int) -> EvmChain:
    """Look up a known chain by EIP-155 chain id; raises for an unknown one (fail-closed —
    an unknown chain has no vetted finalization window, so refuse rather than guess)."""
    for chain in KNOWN_EVM_CHAINS.values():
        if chain.chain_id == chain_id:
            return chain
    raise ValidationError(
        f"unknown EVM chain id {chain_id!r}: no vetted finalization window. Add it to "
        "KNOWN_EVM_CHAINS with a sourced finalization_window_s, or construct MarginPolicy "
        "with an explicitly chosen eth_finalization_window_s."
    )
