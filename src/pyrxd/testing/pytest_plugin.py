"""pytest fixtures for testing against a throwaway Radiant regtest node.

Enable them in a project's ``conftest.py``::

    pytest_plugins = ["pyrxd.testing.pytest_plugin"]

They are opt-in on purpose (no ``pytest11`` entry point), so installing pyrxd never adds
fixtures or a docker dependency to an unrelated test run.

Fixtures:

``regtest_node`` (session)
    A fresh :class:`~pyrxd.devnet.RegtestNode` with a mature coinbase, in its own
    container. Removed when the session ends. One chain is shared by every test in the
    session; isolation comes from each test getting its own wallet.
``regtest_client``
    A :class:`~pyrxd.testing.RegtestClient` that mines a block after each broadcast.
``regtest_wallet``
    A :class:`~pyrxd.testing.RegtestWallet` on a new key, funded with
    :data:`~pyrxd.testing.DEFAULT_WALLET_FUNDING_RXD` RXD.
``regtest_wallet_factory``
    ``factory(amount_rxd=...)`` for a test that needs more than one wallet.

When docker or the node image is missing, the fixtures **fail** the test with the command
that fixes it rather than skipping it. A skipped chain test reports green, and a starter
project whose only test silently skipped would look like it worked.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator

import pytest

from ..devnet import DevnetError, RegtestNode
from .regtest import DEFAULT_WALLET_FUNDING_RXD, RegtestClient, RegtestWallet, start_test_node


@pytest.fixture(scope="session")
def regtest_node() -> Iterator[RegtestNode]:
    try:
        node = start_test_node()
    except DevnetError as exc:
        pytest.fail(f"pyrxd.testing could not start a regtest node: {exc}", pytrace=False)
    try:
        yield node
    finally:
        node.stop()


@pytest.fixture
def regtest_client(regtest_node: RegtestNode) -> RegtestClient:
    return RegtestClient(regtest_node)


@pytest.fixture
def regtest_wallet_factory(regtest_node: RegtestNode) -> Callable[..., RegtestWallet]:
    def make(amount_rxd: float = DEFAULT_WALLET_FUNDING_RXD) -> RegtestWallet:
        return RegtestWallet.funded(regtest_node, amount_rxd)

    return make


@pytest.fixture
def regtest_wallet(regtest_wallet_factory: Callable[..., RegtestWallet]) -> RegtestWallet:
    return regtest_wallet_factory()
