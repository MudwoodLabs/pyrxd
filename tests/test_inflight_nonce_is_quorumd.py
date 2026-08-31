"""The in-flight guard reads every endpoint, not one (#504 item 2).

Where the advisory file lock is absent — two hosts, a shared mount, a container restart with a
different mount, a copied keys directory — this read is the ONLY thing between a resume and a
double-fund. A single lagging or load-balanced provider defeats it: this host sees
`pending == latest`, computes the full shortfall, and sends an ADDITIVE transfer while the other
host's push is still pending. Both mine.

The aggregation is conservative TOWARD REFUSING, not toward the smaller number: MAX pending, MIN
latest, so `pending > latest` fires as readily as the fleet allows.
"""

from __future__ import annotations

import asyncio

import pytest

from pyrxd.eth_wallet.erc20_leg import _inflight_nonce_window
from pyrxd.eth_wallet.multi_rpc import MultiSourceEthRpc
from pyrxd.security.errors import NetworkError


class _Source:
    def __init__(self, pending: int, latest: int, *, chain_id: int = 1) -> None:
        self._p, self._l = pending, latest
        self.chain_id = chain_id

    async def get_transaction_count(self, address: str, block: str = "pending") -> int:
        return self._p if block == "pending" else self._l


def _rpc(*sources, min_agreeing: int = 2) -> MultiSourceEthRpc:
    return MultiSourceEthRpc(list(sources), min_agreeing=min_agreeing)


class TestTheAggregationRefusesRatherThanUnderReports:
    def test_a_LAGGING_endpoint_cannot_hide_an_in_flight_push(self) -> None:
        """The attack this exists for, with the fixture that actually reproduces it.

        Host A's push is in flight. One endpoint has SEEN it (pending 8, latest 7); a lagging one
        has not, so it reports pending == latest == 7 — the reading that tells this host nothing
        is in flight. MAX pending (8) against MIN latest (7) must still fire.

        My first version gave both endpoints pending=8, so min and max agreed and the test passed
        under a planted `combine=min`. A fixture where the two aggregations coincide cannot test
        which one is used.
        """
        seen = _Source(pending=8, latest=7)
        lagging = _Source(pending=7, latest=7)
        rpc = _rpc(seen, lagging)
        pending, latest = asyncio.run(rpc.inflight_nonce_window("0xabc"))
        assert (pending, latest) == (8, 7)
        assert pending > latest, "a lagging endpoint hid an in-flight transaction"

    def test_pending_takes_the_MAX(self) -> None:
        rpc = _rpc(_Source(pending=5, latest=5), _Source(pending=9, latest=5))
        assert asyncio.run(rpc.inflight_nonce_window("0xabc"))[0] == 9

    def test_latest_takes_the_MIN(self) -> None:
        rpc = _rpc(_Source(pending=9, latest=9), _Source(pending=9, latest=4))
        assert asyncio.run(rpc.inflight_nonce_window("0xabc"))[1] == 4

    def test_agreement_is_left_alone(self) -> None:
        """Honest path. A guard that refuses valid work is a bug: when the fleet agrees nothing is
        in flight, the window must say so and the resume must proceed."""
        rpc = _rpc(_Source(pending=7, latest=7), _Source(pending=7, latest=7))
        pending, latest = asyncio.run(rpc.inflight_nonce_window("0xabc"))
        assert pending == latest == 7
        assert not pending > latest

    def test_below_quorum_refuses_rather_than_guessing(self) -> None:
        class _Dead:
            chain_id = 1

            async def get_transaction_count(self, address, block="pending"):
                raise NetworkError("down")

        rpc = _rpc(_Source(pending=7, latest=7), _Dead(), min_agreeing=2)
        with pytest.raises(NetworkError, match="quorum"):
            asyncio.run(rpc.inflight_nonce_window("0xabc"))


class TestTheLegUsesIt:
    """Reachability: a quorum'd read nothing calls is not a fix."""

    def test_the_leg_prefers_the_window_when_the_rpc_offers_one(self) -> None:
        calls: list[str] = []

        class _Rpc:
            async def inflight_nonce_window(self, sender):
                calls.append("window")
                return (11, 9)

            async def get_transaction_count(self, sender, block="pending"):
                calls.append(f"single:{block}")
                return 0

        assert asyncio.run(_inflight_nonce_window(_Rpc(), "0xabc")) == (11, 9)
        assert calls == ["window"], "it fell back to the single-source read"

    def test_a_single_source_rpc_still_works_unchanged(self) -> None:
        """Duck-typed on purpose. This is a guard being strengthened where the fleet allows, not a
        new requirement — every existing fake and single-endpoint deployment keeps working."""
        calls: list[str] = []

        class _Legacy:
            async def get_transaction_count(self, sender, block="pending"):
                calls.append(block)
                return 4 if block == "pending" else 3

        assert asyncio.run(_inflight_nonce_window(_Legacy(), "0xabc")) == (4, 3)
        assert calls == ["pending", "latest"]


def test_the_BUILD_time_nonce_read_stays_primary_only() -> None:
    """The two uses want opposite things and must not be merged.

    Building needs the BROADCASTING endpoint's mempool view — another endpoint's nonce produces a
    transaction against state that endpoint does not have. Quorum'ing this one would be a bug, so
    the docstring's promise is pinned.
    """
    import inspect

    src = inspect.getsource(MultiSourceEthRpc.get_transaction_count)
    assert "PRIMARY only" in src
    assert "return await self.primary.get_transaction_count" in src
