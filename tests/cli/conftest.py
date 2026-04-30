"""Shared CLI test fixtures: tmp wallet dir, mocked ElectrumX, fake config."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from click.testing import CliRunner

from pyrxd.cli.config import Config
from pyrxd.cli.context import CliContext


@pytest.fixture
def runner() -> CliRunner:
    """Click CliRunner with the standard isolated filesystem trick available."""
    return CliRunner()


@pytest.fixture
def tmp_wallet_path(tmp_path: Path) -> Path:
    """Path under tmp_path where the wallet should be saved."""
    return tmp_path / "wallet.dat"


@pytest.fixture
def fake_config(tmp_wallet_path: Path) -> Config:
    """A Config that points at the tmp wallet path."""
    return Config(
        network="mainnet",
        electrumx="wss://example-test/",
        fee_rate=10_000,
        wallet_path=tmp_wallet_path,
    )


@pytest.fixture
def fake_client_factory():
    """Return a callable that builds a fresh AsyncMock ElectrumXClient.

    Each test can override individual methods (e.g. .get_balance,
    .broadcast) on the returned mock.
    """

    def _factory():
        client = MagicMock()
        client.get_history = AsyncMock(return_value=[])
        client.get_utxos = AsyncMock(return_value=[])
        client.get_balance = AsyncMock(return_value=(0, 0))
        client.broadcast = AsyncMock(return_value="ab" * 32)
        # Async context manager.
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=None)
        return client

    return _factory


@pytest.fixture
def cli_context(fake_config: Config, tmp_wallet_path: Path, fake_client_factory) -> CliContext:
    """A CliContext wired for offline testing."""
    return CliContext(
        config=fake_config,
        network="mainnet",
        electrumx_url=fake_config.electrumx,
        fee_rate=fake_config.fee_rate,
        wallet_path=tmp_wallet_path,
        output_mode="human",
        client_factory=fake_client_factory,
    )
