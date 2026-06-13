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


def test_floor_matches_margin_policy_floor():
    """Audit follow-up: _FLOOR_S re-declares the canonical _MIN_ETH_FINALIZATION_WINDOW_S with a
    'keep in sync' comment — enforce that invariant so a future floor bump in one file can't leave
    the registry validating against a stale (looser) floor."""
    from pyrxd.eth_wallet.chains import _FLOOR_S
    from pyrxd.gravity.swap_coordinator import _MIN_ETH_FINALIZATION_WINDOW_S

    assert _FLOOR_S == _MIN_ETH_FINALIZATION_WINDOW_S
