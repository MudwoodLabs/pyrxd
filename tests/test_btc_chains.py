"""Unit tests for the Bitcoin-family counter-chain registry (pyrxd.btc_wallet.chains).

The registry is the chain-specific safety knob for the PoW-depth family (Tier 2.3):
per-chain block intervals that size every blocks↔seconds margin conversion. The live
consensus proofs are the LTC variants of the regtest suites
(``BTC_FAMILY_CHAIN=ltc tests/test_btc_htlc_regtest_e2e.py`` and
``XCHAIN_BTC_FAMILY=ltc tests/test_xchain_swap_regtest_e2e.py``).
"""

from __future__ import annotations

import pytest

from pyrxd.btc_wallet.chains import KNOWN_POW_CHAINS, PowChain, pow_chain_by_network
from pyrxd.security.errors import ValidationError


def test_registry_integrity():
    tags: list[str] = []
    for key, chain in KNOWN_POW_CHAINS.items():
        assert chain.name == key
        assert chain.block_interval_s > 0
        tags.extend((chain.network, chain.testnet_network, chain.regtest_network))
    assert len(tags) == len(set(tags)), "network tags must be globally unique across chains"


def test_bitcoin_and_litecoin_entries():
    btc = KNOWN_POW_CHAINS["bitcoin"]
    ltc = KNOWN_POW_CHAINS["litecoin"]
    assert (btc.network, btc.regtest_network, btc.block_interval_s) == ("bc", "bcrt", 600.0)
    assert (ltc.network, ltc.regtest_network, ltc.block_interval_s) == ("ltc", "rltc", 150.0)


def test_lookup_by_any_tag_and_unknown_fails_closed():
    assert pow_chain_by_network("bc") is KNOWN_POW_CHAINS["bitcoin"]
    assert pow_chain_by_network("rltc") is KNOWN_POW_CHAINS["litecoin"]
    assert pow_chain_by_network("tltc") is KNOWN_POW_CHAINS["litecoin"]
    with pytest.raises(ValidationError, match="unknown Bitcoin-family network"):
        pow_chain_by_network("doge")


def test_powchain_validation():
    with pytest.raises(ValidationError, match="block_interval_s"):
        PowChain(name="x", network="x", testnet_network="tx", regtest_network="rx", block_interval_s=0)
    with pytest.raises(ValidationError, match="network"):
        PowChain(name="x", network="", testnet_network="tx", regtest_network="rx", block_interval_s=60)


def test_test_networks_are_audit_exempt_and_mainnets_are_not():
    # The regtest/testnet tags must be in AUDIT_CLEARED_NETWORKS (isolated, no value);
    # the mainnet tags must NOT be (value-bearing → audit gate applies).
    from pyrxd.btc_wallet.htlc_leg import AUDIT_CLEARED_NETWORKS

    for chain in KNOWN_POW_CHAINS.values():
        assert chain.regtest_network in AUDIT_CLEARED_NETWORKS, chain.name
        assert chain.testnet_network in AUDIT_CLEARED_NETWORKS, chain.name
        assert chain.network not in AUDIT_CLEARED_NETWORKS, chain.name
