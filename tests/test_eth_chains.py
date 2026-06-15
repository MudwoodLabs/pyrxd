"""Unit tests for the EVM counter-chain registry (pyrxd.eth_wallet.chains).

The registry is the one Base-specific safety knob (Tier 2.3): per-chain finalization
windows for the finalized-checkpoint leg. These tests pin the registry's integrity
invariants and the fail-closed unknown-chain behaviour; the live-chain proof is
``tests/test_eth_leg_anvil_integration.py::test_full_lifecycle_on_base_chain_id``.
"""

from __future__ import annotations

import pytest

from pyrxd.eth_wallet.chains import KNOWN_EVM_CHAINS, EvmChain, evm_chain_by_id
from pyrxd.security.errors import ValidationError


def test_registry_integrity():
    # Unique chain ids, names match keys, every entry respects the 2-epoch L1 floor.
    ids = [c.chain_id for c in KNOWN_EVM_CHAINS.values()]
    assert len(ids) == len(set(ids)), "duplicate chain ids in KNOWN_EVM_CHAINS"
    for key, chain in KNOWN_EVM_CHAINS.items():
        assert chain.name == key
        assert chain.finalization_window_s >= 768
        assert chain.network


def test_base_entries_present_with_l2_window():
    base = KNOWN_EVM_CHAINS["base"]
    base_sepolia = KNOWN_EVM_CHAINS["base-sepolia"]
    assert (base.chain_id, base_sepolia.chain_id) == (8453, 84532)
    # An OP-stack L2 finalizes by settling to L1, so its steady-state window must be
    # at least the L1 window (batch posting + L1 finality can only ADD lag).
    assert base.finalization_window_s >= KNOWN_EVM_CHAINS["ethereum"].finalization_window_s
    assert base_sepolia.finalization_window_s >= KNOWN_EVM_CHAINS["sepolia"].finalization_window_s


def test_lookup_by_id_and_unknown_fails_closed():
    assert evm_chain_by_id(8453) is KNOWN_EVM_CHAINS["base"]
    assert evm_chain_by_id(1) is KNOWN_EVM_CHAINS["ethereum"]
    with pytest.raises(ValidationError, match="unknown EVM chain id"):
        evm_chain_by_id(999_999)


def test_evm_chain_validation_rejects_sub_floor_window():
    with pytest.raises(ValidationError, match="finalization_window_s"):
        EvmChain(name="x", chain_id=42, network="x", finalization_window_s=767)
    with pytest.raises(ValidationError, match="chain_id"):
        EvmChain(name="x", chain_id=0, network="x", finalization_window_s=900)
    with pytest.raises(ValidationError, match="network"):
        EvmChain(name="x", chain_id=42, network="", finalization_window_s=900)


def test_no_registry_network_is_audit_exempt():
    # Every registry network tag must stay behind the audit gate: none may appear in
    # AUDIT_CLEARED_NETWORKS (which is reserved for isolated, no-value test chains).
    from pyrxd.btc_wallet.htlc_leg import AUDIT_CLEARED_NETWORKS

    for chain in KNOWN_EVM_CHAINS.values():
        assert chain.network not in AUDIT_CLEARED_NETWORKS, chain.name


def test_optimism_arbitrum_linea_entries_present():
    # The A6 additions: OP-stack (= Base), Arbitrum Nitro, Linea zk — all Ethereum-anchored
    # rollups, so each (mainnet + testnet) respects the L1 floor with a sourced window.
    expected = {
        "optimism": (10, 900),
        "optimism-sepolia": (11155420, 900),
        "arbitrum-one": (42161, 1200),
        "arbitrum-sepolia": (421614, 1200),
        "linea": (59144, 6000),
        "linea-sepolia": (59141, 6000),
    }
    eth_window = KNOWN_EVM_CHAINS["ethereum"].finalization_window_s
    for key, (cid, window) in expected.items():
        c = KNOWN_EVM_CHAINS[key]
        assert (c.chain_id, c.finalization_window_s) == (cid, window), key
        assert evm_chain_by_id(cid) is c
        # an L2 cannot finalize faster than the L1 checkpoint it settles to
        assert c.finalization_window_s >= eth_window, key


def test_polygon_pos_deliberately_excluded():
    # Polygon PoS (137) / Amoy (80002): a commit-chain/sidechain with its OWN validator-set
    # milestone finality (Heimdall/CometBFT), NOT Ethereum-anchored — it does NOT fit this
    # registry's finalized-checkpoint model (see the module docstring). Its absence is
    # intentional; the lookup must fail closed rather than silently treat a sidechain as a
    # rollup with an Ethereum-anchored window.
    assert not any(c.chain_id == 137 for c in KNOWN_EVM_CHAINS.values())
    for sidechain_id in (137, 80002):
        with pytest.raises(ValidationError, match="unknown EVM chain id"):
            evm_chain_by_id(sidechain_id)


def test_floor_matches_margin_policy_floor():
    """Audit follow-up: _FLOOR_S re-declares the canonical _MIN_ETH_FINALIZATION_WINDOW_S with a
    'keep in sync' comment — enforce that invariant so a future floor bump in one file can't leave
    the registry validating against a stale (looser) floor."""
    from pyrxd.eth_wallet.chains import _FLOOR_S
    from pyrxd.gravity.swap_coordinator import _MIN_ETH_FINALIZATION_WINDOW_S

    assert _FLOOR_S == _MIN_ETH_FINALIZATION_WINDOW_S
