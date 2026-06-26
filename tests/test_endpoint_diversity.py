"""Tests for the BTC quorum endpoint-diversity guard.

A quorum of same-host endpoints is FALSE corroboration — one hostile/buggy host satisfies the whole
"quorum" — so the effective quorum must be bounded by the number of DISTINCT hosts.
"""

from __future__ import annotations

import logging

import pytest

from pyrxd.network.bitcoin import MultiSourceBtcFundingReader, count_distinct_hosts, endpoint_host
from pyrxd.security.errors import ValidationError


def test_endpoint_host_parses_hostname():
    assert endpoint_host("https://mempool.space/api") == "mempool.space"
    assert endpoint_host("wss://x.example.com:50022") == "x.example.com"
    assert endpoint_host("HTTPS://Mempool.Space/api") == "mempool.space"
    assert endpoint_host("") is None
    assert endpoint_host(None) is None  # type: ignore[arg-type]


def test_count_distinct_hosts():
    # same host, different paths → ONE distinct source
    assert count_distinct_hosts(["https://mempool.space/api", "https://mempool.space/signet/api"]) == 1
    # genuinely independent hosts → TWO
    assert count_distinct_hosts(["https://mempool.space/api", "https://blockstream.info/api"]) == 2
    # unparseable tokens count as one distinct source each (we can't prove they collide)
    assert count_distinct_hosts(["", "   "]) == 2


def test_default_mainnet_endpoints_are_independent():
    # Regression guard for the SHIPPED turnkey quorum: it must carry >= the default 2-of-3 in distinct
    # hosts, so adding a same-host endpoint to DEFAULT_MAINNET_ENDPOINTS fails CI.
    assert count_distinct_hosts(MultiSourceBtcFundingReader.DEFAULT_MAINNET_ENDPOINTS) >= 2


def test_from_endpoints_fails_closed_on_same_host_quorum():
    # Default: insufficient host diversity FAILS CLOSED rather than silently clamping the quorum to 1
    # (a log-only clamp could arm single-source above-dust custody — the F-17 SPOF).
    with pytest.raises(ValidationError, match="fails closed"):
        MultiSourceBtcFundingReader.from_endpoints(
            ["https://mempool.space/api", "https://mempool.space/signet/api"], quorum=2
        )


def test_from_endpoints_clamps_same_host_quorum_with_opt_in(caplog):
    # Explicit opt-in (mirrors --accept-single-source): clamp to the distinct-host count + warn loudly.
    with caplog.at_level(logging.WARNING):
        r = MultiSourceBtcFundingReader.from_endpoints(
            ["https://mempool.space/api", "https://mempool.space/signet/api"],
            quorum=2,
            allow_insufficient_diversity=True,
        )
    assert r._quorum == 1  # 2 URLs but only 1 distinct host → clamped under the explicit opt-in
    assert "false corroboration" in caplog.text


def test_from_endpoints_keeps_distinct_host_quorum():
    r = MultiSourceBtcFundingReader.from_endpoints(
        ["https://mempool.space/api", "https://blockstream.info/api"], quorum=2
    )
    assert r._quorum == 2


def test_from_endpoints_rejects_empty():
    with pytest.raises(ValidationError):
        MultiSourceBtcFundingReader.from_endpoints([], quorum=2)
