"""Wiring tests for scripts/watchtower_run.py::_build_rxd_source — the RXD source assembly.

Verifies that the runner composes a fail-closed multi-source quorum (and flips ``rxd_corroborated``)
only when >= quorum independent RXD sources are actually wired, and stays single-source /
low-corroboration otherwise. ElectrumX connections are mocked (no network); the ssh-tr node reader
constructs without connecting, so it is exercised for real.
"""

from __future__ import annotations

import contextlib
import sys
from pathlib import Path

import pytest

from pyrxd.gravity.watch import ElectrumRxdChainSource, MultiSourceRxdChainSource

_SCRIPTS = str(Path(__file__).resolve().parent.parent / "scripts")
if _SCRIPTS not in sys.path:
    sys.path.insert(0, _SCRIPTS)

import watchtower_run as w


class _FakeElectrumX:
    """Async-context-manager stand-in for ElectrumXClient (no real wss connect)."""

    def __init__(self, urls, **_kw):
        self.urls = urls

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_a):
        return False


@pytest.fixture(autouse=True)
def _patch_electrumx(monkeypatch):
    monkeypatch.setattr(w, "ElectrumXClient", _FakeElectrumX)


async def _build(*argv):
    args = w._parse_args(["--records-dir", "/tmp/x", *argv])
    async with contextlib.AsyncExitStack() as stack:
        return await w._build_rxd_source(args, stack)


async def test_two_electrumx_urls_compose_corroborated_quorum():
    src, corr = await _build("--rxd-electrumx-url", "wss://a", "--rxd-electrumx-url", "wss://b")
    assert isinstance(src, MultiSourceRxdChainSource)
    assert corr is True


async def test_defaults_to_public_endpoints_when_none_given():
    # electrumx backend (default) with no URL → the two verified public endpoints → 2-of-2 corroborated.
    src, corr = await _build()
    assert isinstance(src, MultiSourceRxdChainSource)
    assert corr is True


async def test_single_source_stays_low_corroboration():
    src, corr = await _build("--rxd-electrumx-url", "wss://only")
    assert isinstance(src, ElectrumRxdChainSource)
    assert corr is False


async def test_include_node_combines_with_electrumx_for_quorum():
    # the operator's own node + one public ElectrumX = 2 independent sources → corroborated.
    src, corr = await _build("--rxd-electrumx-url", "wss://a", "--rxd-include-node")
    assert isinstance(src, MultiSourceRxdChainSource)
    assert corr is True


async def test_ssh_only_is_single_source():
    # node-only run (no electrumx default added) → single source, low-corroboration.
    src, corr = await _build("--rxd-backend", "ssh-tr")
    assert isinstance(src, ElectrumRxdChainSource)
    assert corr is False


async def test_quorum_above_wired_sources_fails_loud():
    # 2 sources but --rxd-quorum 3 → a clean SystemExit (fail-loud), never silently weakened/raw-raised.
    with pytest.raises(SystemExit):
        await _build("--rxd-electrumx-url", "wss://a", "--rxd-electrumx-url", "wss://b", "--rxd-quorum", "3")


async def test_dedup_identical_urls_collapses_to_single_source():
    # the same endpoint twice is NOT two independent sources → collapses to one → not corroborated.
    src, corr = await _build("--rxd-electrumx-url", "wss://dup", "--rxd-electrumx-url", "wss://dup")
    assert isinstance(src, ElectrumRxdChainSource)
    assert corr is False
