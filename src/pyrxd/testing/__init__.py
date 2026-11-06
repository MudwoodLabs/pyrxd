"""Test helpers for projects built on pyrxd.

Write tests against a real, throwaway Radiant regtest node::

    # conftest.py
    pytest_plugins = ["pyrxd.testing.pytest_plugin"]

    # test_something.py
    async def test_mint(regtest_client, regtest_wallet, tmp_path):
        ...

The fixtures (``regtest_node``, ``regtest_client``, ``regtest_wallet``,
``regtest_wallet_factory``) live in :mod:`pyrxd.testing.pytest_plugin`, which needs pytest.
This package itself does not import pytest, so the helpers below also work outside a test
run. Prerequisites: docker, and the node image built once with ``pyrxd regtest setup``.
"""

from __future__ import annotations

from .regtest import (
    DEFAULT_WALLET_FUNDING_RXD,
    PHOTONS_PER_RXD,
    RegtestClient,
    RegtestUnavailable,
    RegtestWallet,
    node_relay_floor_photons_per_kb,
    start_test_node,
)

__all__ = [
    "DEFAULT_WALLET_FUNDING_RXD",
    "PHOTONS_PER_RXD",
    "RegtestClient",
    "RegtestUnavailable",
    "RegtestWallet",
    "node_relay_floor_photons_per_kb",
    "start_test_node",
]
