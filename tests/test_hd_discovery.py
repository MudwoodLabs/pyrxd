"""Tests for hd.discovery — multi-path account discovery for wallet recovery.

The derivation-correctness anchor lives in test_hd_wallet.py
(TestCoinTypeKwarg.EXPECTED_0 is verified end-to-end against Photonic). These
tests assert the *discovery* layer on top: that scanning across coin types and
accounts finds funds wherever they actually landed, reports the right path,
and fails loud on a network error rather than misreporting "empty".
"""

from __future__ import annotations

import asyncio

import pytest

from pyrxd.hd.discovery import (
    DEFAULT_ACCOUNTS,
    DEFAULT_COIN_TYPES,
    DiscoveryReport,
    coin_type_label,
    discover,
)
from pyrxd.hd.wallet import HdWallet

# Reuse the canonical test mnemonic + the mock client from the wallet tests.
from tests.test_hd_wallet import MNEMONIC, _mock_client


def _addr(coin_type: int, account: int, change: int, index: int) -> str:
    """Derive the address the wallet would produce at this exact path."""
    w = HdWallet.from_mnemonic(MNEMONIC, account=account, coin_type=coin_type)
    return w._derive_address(change, index)


def _run(coro) -> DiscoveryReport:
    return asyncio.run(coro)


class TestDiscover:
    def test_finds_funds_on_legacy_coin_type_0(self):
        # Funds landed on the Photonic/Chainbow legacy path (coin type 0,
        # account 0, receive index 0) — the headline recovery scenario.
        funded = _addr(0, 0, 0, 0)
        client = _mock_client(
            history_map={funded: [{"tx_hash": "ab" * 32, "height": 800000}]},
            balance_map={funded: (1_234_567, 0)},
        )
        report = _run(discover(client, MNEMONIC))

        assert report.found
        assert report.total_confirmed == 1_234_567
        assert report.total == 1_234_567
        assert report.hits[0].total == 1_234_567
        assert len(report.hits) == 1
        hit = report.hits[0]
        assert hit.coin_type == 0
        assert hit.account == 0
        assert hit.path == "m/44'/0'/0'/0/0"
        assert hit.address == funded

    def test_finds_funds_on_change_chain(self):
        # A used internal (change=1) address must be discovered too — a common
        # blind spot, since funds often rest on a change output.
        funded = _addr(512, 0, 1, 3)
        client = _mock_client(
            history_map={funded: [{"tx_hash": "cd" * 32, "height": 810000}]},
            balance_map={funded: (500, 100)},
        )
        report = _run(discover(client, MNEMONIC))

        assert report.found
        hit = next(h for h in report.hits if h.address == funded)
        assert hit.change == 1
        assert hit.index == 3
        assert hit.path == "m/44'/512'/0'/1/3"
        assert hit.confirmed == 500
        assert hit.unconfirmed == 100

    def test_finds_funds_on_nonzero_account(self):
        funded = _addr(0, 1, 0, 0)
        client = _mock_client(
            history_map={funded: [{"tx_hash": "ef" * 32, "height": 805000}]},
            balance_map={funded: (42, 0)},
        )
        report = _run(discover(client, MNEMONIC))
        hit = next(h for h in report.hits if h.address == funded)
        assert hit.account == 1
        assert hit.coin_type == 0

    def test_split_across_two_coin_types_reports_both(self):
        a = _addr(0, 0, 0, 0)
        b = _addr(512, 0, 0, 0)
        client = _mock_client(
            history_map={
                a: [{"tx_hash": "11" * 32, "height": 1}],
                b: [{"tx_hash": "22" * 32, "height": 2}],
            },
            balance_map={a: (100, 0), b: (900, 0)},
        )
        report = _run(discover(client, MNEMONIC))

        coin_types = {h.coin_type for h in report.hits}
        assert coin_types == {0, 512}
        assert report.total_confirmed == 1000
        # Largest balance sorts first.
        assert report.hits[0].coin_type == 512

    def test_zero_hits_when_no_history(self):
        client = _mock_client()  # every address returns empty history
        report = _run(discover(client, MNEMONIC))
        assert not report.found
        assert report.hits == []
        assert report.total_confirmed == 0
        assert report.total_unconfirmed == 0

    def test_scanned_covers_all_pairs(self):
        client = _mock_client()
        report = _run(discover(client, MNEMONIC))
        expected = {(ct, acct) for ct in DEFAULT_COIN_TYPES for acct in DEFAULT_ACCOUNTS}
        assert set(report.scanned) == expected

    def test_custom_ranges_are_honoured(self):
        funded = _addr(236, 0, 0, 0)
        client = _mock_client(
            history_map={funded: [{"tx_hash": "33" * 32, "height": 1}]},
            balance_map={funded: (7, 0)},
        )
        # Restrict to a single coin type / account — should still find it,
        # and should not scan the others.
        report = _run(discover(client, MNEMONIC, coin_types=[236], accounts=[0]))
        assert report.scanned == [(236, 0)]
        assert report.found
        assert report.hits[0].coin_type == 236

    def test_network_error_propagates_not_swallowed(self):
        # A recovery tool must never report "empty" when a scan actually
        # failed. refresh() re-raises on network error; discover must not eat it.
        client = _mock_client()

        async def _boom(_script_hash):
            raise ConnectionError("electrumx down mid-scan")

        client.get_history = _boom

        with pytest.raises(ConnectionError):
            _run(discover(client, MNEMONIC))

    def test_mnemonic_not_in_report(self):
        # No seed material should be reachable through the returned report.
        funded = _addr(0, 0, 0, 0)
        client = _mock_client(
            history_map={funded: [{"tx_hash": "44" * 32, "height": 1}]},
            balance_map={funded: (1, 0)},
        )
        report = _run(discover(client, MNEMONIC))
        assert MNEMONIC not in repr(report)
        for word in MNEMONIC.split():
            # The mnemonic words must not leak via any hit field.
            assert all(word not in h.address for h in report.hits)


class TestCoinTypeLabel:
    def test_known_labels(self):
        assert "Chainbow" in coin_type_label(0)
        assert "SLIP-0044" in coin_type_label(512)
        assert "pyrxd" in coin_type_label(236)

    def test_unknown_label_is_graceful(self):
        assert "999" in coin_type_label(999)
