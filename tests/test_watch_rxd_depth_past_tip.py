"""One RXD source must not quiet the near-t_rxd page by pushing the covenant's lock height below 0 (Mythos B-1).

The observer derives the lock height as ``tip - depth + 1`` from the MIN tip and the MAX depth across RXD
sources, and dropped a height below 0 as "unread". One source got there by over-reporting the covenant's
depth or by under-reporting its tip. At BOTH_LOCKED the unread branch watches on the counter-leg clock (BTC
refund maturity, or the ETH timeout), so where honest sources paged ``both_locked_refund_due`` the tower was
silent. Such a height is now shifted up with the tip, keeping the ``depth`` blocks between them.

decide() reads only the blocks between the two heights, so the invariant pinned here is that one lying source
never makes that span SHORTER than the honest one (later t_rxd, a claim gate reading SAFE), in every quorum
shape: all answering, exactly ``quorum`` answering (where the tip is the minimum), and 2-of-2. These drive the
production ``MultiSourceRxdChainSource`` and ``ChainObserver``, with the liar first and last.
"""

from __future__ import annotations

import pytest

from pyrxd.gravity.swap_state import SwapState
from pyrxd.gravity.watch.adapters import MultiSourceRxdChainSource
from pyrxd.gravity.watch.decide import Intent, decide
from pyrxd.gravity.watch.quorum import ChainObserver
from pyrxd.security.errors import NetworkError
from pyrxd.security.units import ChainHeight, Confirmations
from tests._source_hosts import distinct_host
from tests.test_watch_btc_spender_classification import BURIAL, COV_CONFS, T_RXD, TIP, _Tower
from tests.test_watch_btc_spender_classification import _policy as _btc_policy
from tests.test_watch_eth_disposition_table import _EthTower
from tests.test_watch_eth_disposition_table import _policy as _eth_policy

LOCKED_AT = TIP - COV_CONFS + 1
NEAR = LOCKED_AT + T_RXD - 3  # inside the safety window, before t_rxd opens
HONEST_DEPTH = NEAR - LOCKED_AT + 1


class _RxdSource:
    def __init__(self, *, tip: int = NEAR, depth: int | None = HONEST_DEPTH, down: bool = False) -> None:
        self.source_key = distinct_host()
        self.tip = tip
        self.depth = depth
        self.down = down

    async def tip_height(self) -> ChainHeight:
        if self.down:
            raise NetworkError("source down")
        return ChainHeight(self.tip)

    async def covenant_confirmations(self, outpoint: str) -> Confirmations | None:
        if self.down:
            raise NetworkError("source down")
        return None if self.depth is None else Confirmations(self.depth)


#: How one source lies. ``deep`` and ``low_tip`` push ``tip - depth + 1`` below 0 (B-1); the others are the
#: same liar's in-range moves, which must not shorten the span either.
LIES = {
    "deep": {"depth": 10 * NEAR},
    "low_tip": {"tip": 1},
    "low_tip_unseen": {"tip": 1, "depth": None},
    "mid_tip_unseen": {"tip": NEAR - 100, "depth": None},
    "high_tip_shallow": {"tip": 10 * NEAR, "depth": 1},
}

#: (number of sources, quorum, index of a source that is down or None)
SHAPES = {"3of3_q2": (3, 2, None), "2of3_up_q2": (3, 2, 1), "2of2": (2, 2, None)}


def _rxd(shape: str, liar: int | None = None, lie: str = "deep") -> MultiSourceRxdChainSource:
    n, quorum, down = SHAPES[shape]
    sources = []
    for i in range(n):
        kw = dict(LIES[lie]) if i == liar else {}
        sources.append(_RxdSource(down=(i == down), **kw))
    return MultiSourceRxdChainSource(sources, quorum=quorum)


def _liars(shape: str) -> list[int]:
    n, _q, down = SHAPES[shape]
    return [i for i in (0, n - 1) if i != down]


async def _btc(tmp_path, rxd):
    w = _Tower(tmp_path, state=SwapState.BOTH_LOCKED)
    observer = ChainObserver(btc=w.observer._btc, rxd=rxd, btc_burial_blocks=BURIAL)
    obs = await observer.observe(w.swap_id, w.record())
    return obs, decide(record=w.record(), observations=obs, policy=_btc_policy(), safety_window_blocks=6)


async def _eth(tmp_path, rxd):
    w = _EthTower(tmp_path, state=SwapState.BOTH_LOCKED)
    w.chain.head = 40  # before the ETH timeout (block 50): the unread branch would WATCH here
    observer = ChainObserver(eth=w.observer._eth, rxd=rxd, clock=lambda: float(w.chain.ts(w.chain.head)))
    obs = await observer.observe("e1", w.record())
    return obs, decide(record=w.record(), observations=obs, policy=_eth_policy(), safety_window_blocks=6)


def _span(obs) -> int:
    return int(obs.now_rxd_height) - int(obs.asset_locked_at_height)


@pytest.mark.parametrize("lie", sorted(LIES))
@pytest.mark.parametrize("shape", sorted(SHAPES))
@pytest.mark.parametrize("leg", [_btc, _eth], ids=["btc", "eth"])
async def test_one_lying_rxd_source_never_shortens_the_span_or_quiets_the_page(tmp_path, leg, shape, lie):
    honest_obs, honest = await leg(tmp_path / "honest", _rxd(shape))
    assert honest.intent is Intent.PAGE_REFUND and honest.situation == "both_locked_refund_due", honest.reason
    for liar in _liars(shape):
        obs, d = await leg(tmp_path / f"liar{liar}", _rxd(shape, liar, lie))
        assert obs.asset_locked_at_height is not None, (liar, obs)
        assert _span(obs) >= _span(honest_obs), (liar, obs)
        assert d.intent is Intent.PAGE_REFUND, (liar, d.reason)
        if _span(obs) == _span(honest_obs):
            assert (d.intent, d.situation, d.urgent) == (honest.intent, honest.situation, honest.urgent), liar


async def test_an_over_reported_depth_keeps_its_blocks(tmp_path):
    """The deep lie reads as the deepest in-range depth would: locked at 0, the tip shifted to keep the span."""
    obs, _ = await _btc(tmp_path, _rxd("3of3_q2", 0, "deep"))
    assert (obs.asset_locked_at_height, obs.now_rxd_height) == (0, 10 * NEAR - 1)
