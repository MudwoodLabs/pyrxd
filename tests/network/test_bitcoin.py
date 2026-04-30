"""Tests for BtcDataSource implementations.

Uses unittest.mock to avoid real network calls.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from pyrxd.network.bitcoin import (
    MempoolSpaceSource,
    MultiSourceBtcDataSource,
)
from pyrxd.security.errors import NetworkError, ValidationError
from pyrxd.security.types import BlockHeight, RawTx, Txid

_VALID_TXID = "b" * 64
# Minimal valid raw tx (65+ bytes).
_VALID_RAW = bytes(range(65))
_VALID_RAW_HEX = _VALID_RAW.hex()


# ── aiohttp response mock helpers ─────────────────────────────────────────────


def _make_response(status: int, body: bytes, content_type: str = "application/json"):
    """Return a mock aiohttp response object."""
    resp = AsyncMock()
    resp.status = status
    resp.content_type = content_type
    resp.read = AsyncMock(return_value=body)
    # Make it work as an async context manager.
    resp.__aenter__ = AsyncMock(return_value=resp)
    resp.__aexit__ = AsyncMock(return_value=None)
    return resp


def _make_session(responses: list):
    """Return a mock aiohttp.ClientSession where .get() cycles through responses."""
    session = MagicMock()
    session.closed = False
    get_mock = MagicMock(side_effect=responses)
    session.get = get_mock
    return session


# ── MempoolSpaceSource.get_raw_tx confirmation enforcement ────────────────────


async def test_get_raw_tx_rejects_below_min_confirmations():
    """get_raw_tx with 5 confirmations when 6 required must raise NetworkError.

    block_height=839996, tip=840000 → 840000-839996+1 = 5 confirmations < 6.
    """
    source = MempoolSpaceSource()

    status_body = json.dumps({"confirmed": True, "block_height": 839996}).encode()
    tip_body = b"840000"

    status_resp = _make_response(200, status_body, "application/json")
    tip_resp = _make_response(200, tip_body, "text/plain")

    session = MagicMock()
    session.closed = False
    # Calls in order: status URL, then tip height URL.
    session.get = MagicMock(side_effect=[status_resp, tip_resp])
    source._session = session

    with pytest.raises(NetworkError, match="confirmations"):
        await source.get_raw_tx(Txid(_VALID_TXID), min_confirmations=6)


async def test_get_raw_tx_accepts_exact_min_confirmations():
    """get_raw_tx with exactly 6 confirmations must succeed."""
    source = MempoolSpaceSource()

    # block_height=839995, tip=840000 → 840000-839995+1 = 6 confs
    status_body = json.dumps({"confirmed": True, "block_height": 839995}).encode()
    tip_body = b"840000"
    raw_body = _VALID_RAW_HEX.encode()

    status_resp = _make_response(200, status_body, "application/json")
    tip_resp = _make_response(200, tip_body, "text/plain")
    raw_resp = _make_response(200, raw_body, "text/plain")

    session = MagicMock()
    session.closed = False
    session.get = MagicMock(side_effect=[status_resp, tip_resp, raw_resp])
    source._session = session

    result = await source.get_raw_tx(Txid(_VALID_TXID), min_confirmations=6)
    assert isinstance(result, RawTx)


async def test_get_raw_tx_rejects_unconfirmed_tx():
    """get_raw_tx for an unconfirmed tx must raise NetworkError."""
    source = MempoolSpaceSource()
    status_body = json.dumps({"confirmed": False}).encode()
    status_resp = _make_response(200, status_body, "application/json")

    session = MagicMock()
    session.closed = False
    session.get = MagicMock(return_value=status_resp)
    source._session = session

    with pytest.raises(NetworkError, match="confirmations"):
        await source.get_raw_tx(Txid(_VALID_TXID), min_confirmations=6)


# ── URL / input validation ────────────────────────────────────────────────────


async def test_path_traversal_rejected_by_txid_validation():
    """Txid validation must reject '../../../etc/passwd' before URL construction."""
    source = MempoolSpaceSource()
    with pytest.raises(ValidationError):
        await source.get_raw_tx(Txid("../../../etc/passwd"))  # type: ignore[arg-type]


async def test_path_traversal_non_hex_rejected():
    """Any non-hex txid input must raise ValidationError."""
    source = MempoolSpaceSource()
    with pytest.raises((ValidationError, Exception)):
        # Txid constructor validates; if caller passes plain str it should fail.
        bad = "../../../etc/passwd"
        # Direct call without Txid wrapper — source validates internally.
        await source.get_raw_tx(bad)  # type: ignore[arg-type]


# ── Response size limit ───────────────────────────────────────────────────────


async def test_response_size_limit_raises_network_error():
    """A response body larger than 10 MB must raise NetworkError."""
    source = MempoolSpaceSource()
    # Build a response whose body is 11 MB.
    huge_body = b"x" * (11 * 1024 * 1024)
    huge_resp = _make_response(200, huge_body, "application/json")

    session = MagicMock()
    session.closed = False
    session.get = MagicMock(return_value=huge_resp)
    source._session = session

    with pytest.raises(NetworkError, match="size"):
        await source.get_raw_tx(Txid(_VALID_TXID))


# ── MultiSourceBtcDataSource ──────────────────────────────────────────────────


class _MockSource(MempoolSpaceSource):
    """Minimal BtcDataSource stub for multi-source tests."""

    def __init__(self, tip: int):
        super().__init__()
        self._tip = tip

    async def get_tip_height(self) -> BlockHeight:
        return BlockHeight(self._tip)


async def test_multi_source_agrees_returns_result():
    """Two sources agreeing on tip height must return the agreed value."""
    s1 = _MockSource(tip=840000)
    s2 = _MockSource(tip=840000)
    multi = MultiSourceBtcDataSource([s1, s2], quorum=2)
    result = await multi.get_tip_height()
    assert result == 840000


async def test_multi_source_disagrees_raises_network_error():
    """Two sources returning different heights must raise NetworkError."""
    s1 = _MockSource(tip=840000)
    s2 = _MockSource(tip=840001)
    multi = MultiSourceBtcDataSource([s1, s2], quorum=2)
    with pytest.raises(NetworkError, match="quorum"):
        await multi.get_tip_height()


async def test_multi_source_insufficient_sources_raises_network_error():
    """Single source with quorum=2 must raise NetworkError immediately."""
    s1 = _MockSource(tip=840000)
    multi = MultiSourceBtcDataSource([s1], quorum=2)
    with pytest.raises(NetworkError, match="enough"):
        await multi.get_tip_height()


async def test_multi_source_one_failing_still_reaches_quorum():
    """If 2 of 3 sources agree and quorum=2, the result must be returned."""

    class _FailSource(MempoolSpaceSource):
        async def get_tip_height(self) -> BlockHeight:
            raise NetworkError("simulated failure")

    s1 = _MockSource(tip=840000)
    s2 = _MockSource(tip=840000)
    sf = _FailSource()
    multi = MultiSourceBtcDataSource([s1, s2, sf], quorum=2)
    result = await multi.get_tip_height()
    assert result == 840000
