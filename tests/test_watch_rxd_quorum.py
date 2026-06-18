"""Unit tests for ``MultiSourceRxdChainSource`` — the RXD multi-source quorum reader.

RXD reads were single-source (every observation flagged low-corroboration). This reader
composes >= quorum INDEPENDENT sources so a lone lagging/lying/down source can't drive a
decision. The tests pin the asymmetric covenant safety direction — the crux of the design:

  * "asset LOCKED" is believed on ANY one source (refusing to refund is the safe error);
  * "asset NOT locked" (which ENABLES an autonomous refund) requires >= quorum *reachable*
    sources to corroborate the absence — a down source must never masquerade as "not locked".
"""

from __future__ import annotations

import pytest

from pyrxd.gravity.watch import MultiSourceRxdChainSource
from pyrxd.security.errors import NetworkError, ValidationError

_OUTPOINT = "ab" * 32 + ":0"


class _FakeRxd:
    """A fake ``RxdChainSource``. ``tip`` is the height; ``covenant`` is the covenant
    confirmations (``None`` == not seen). ``tip_fails`` makes the source unreachable;
    ``cov_fails`` makes only the covenant lookup raise (node up, lookup errored)."""

    def __init__(
        self, tip: int = 100, covenant: int | None = None, *, tip_fails: bool = False, cov_fails: bool = False
    ):
        self._tip = tip
        self._cov = covenant
        self._tip_fails = tip_fails
        self._cov_fails = cov_fails

    async def tip_height(self) -> int:
        if self._tip_fails:
            raise NetworkError("rxd source down")
        return self._tip

    async def covenant_confirmations(self, outpoint: str) -> int | None:
        if self._cov_fails:
            raise NetworkError("covenant lookup failed")
        return self._cov


def test_quorum_construction_validates():
    with pytest.raises(ValidationError):
        MultiSourceRxdChainSource([_FakeRxd()], quorum=2)  # fewer sources than quorum
    with pytest.raises(ValidationError):
        MultiSourceRxdChainSource([_FakeRxd(), _FakeRxd()], quorum=0)


# --- tip_height: conservative min, fail-closed below quorum ---


async def test_tip_height_returns_minimum():
    src = MultiSourceRxdChainSource([_FakeRxd(tip=100), _FakeRxd(tip=99), _FakeRxd(tip=101)], quorum=2)
    assert await src.tip_height() == 99  # most-pessimistic source wins (defeats an over-reporter)


async def test_tip_height_tolerates_one_down_at_quorum():
    src = MultiSourceRxdChainSource([_FakeRxd(tip=100), _FakeRxd(tip=100), _FakeRxd(tip_fails=True)], quorum=2)
    assert await src.tip_height() == 100  # 2 of 3 responded, quorum met


async def test_tip_height_fails_closed_below_quorum():
    src = MultiSourceRxdChainSource([_FakeRxd(tip=100), _FakeRxd(tip_fails=True), _FakeRxd(tip_fails=True)], quorum=2)
    with pytest.raises(NetworkError):
        await src.tip_height()  # only 1 responded < quorum 2


# --- covenant_confirmations: the asymmetric safety direction ---


async def test_covenant_locked_believed_on_any_single_source():
    # Two sources say "absent", one sees it locked → LOCKED wins (refusing to refund is safe).
    src = MultiSourceRxdChainSource([_FakeRxd(covenant=5), _FakeRxd(covenant=None), _FakeRxd(covenant=None)], quorum=2)
    assert await src.covenant_confirmations(_OUTPOINT) == 5


async def test_covenant_locked_returns_conservative_max_depth():
    # HIGH-2: the depth feeds the autonomous CLAIM gate (blocks_left = t_rxd − cov_confs + 1), where a
    # SMALLER cov_confs reads SAFE. So MAX — not min — is the fail-closed direction: a single source
    # under-reporting depth (here 5) must NOT drag the gate toward a premature claim; the deepest
    # sighting (8) wins.
    src = MultiSourceRxdChainSource([_FakeRxd(covenant=8), _FakeRxd(covenant=5), _FakeRxd(covenant=None)], quorum=2)
    assert await src.covenant_confirmations(_OUTPOINT) == 8


async def test_covenant_under_reporting_source_cannot_lower_the_depth():
    # A lone lagging/lying source reporting a tiny depth cannot make the claim gate read SAFE early.
    src = MultiSourceRxdChainSource([_FakeRxd(covenant=1), _FakeRxd(covenant=20), _FakeRxd(covenant=None)], quorum=2)
    assert await src.covenant_confirmations(_OUTPOINT) == 20


async def test_covenant_not_locked_only_on_corroborated_absence():
    # All reachable, none sees the covenant → corroborated NOT locked → None (refund-eligible).
    src = MultiSourceRxdChainSource(
        [_FakeRxd(covenant=None), _FakeRxd(covenant=None), _FakeRxd(covenant=None)], quorum=2
    )
    assert await src.covenant_confirmations(_OUTPOINT) is None


async def test_covenant_down_source_cannot_vote_absent():
    # THE trap: a down source must never look like "asset not locked". One source reachable-and-absent,
    # the other unreachable → only 1 reachable < quorum 2 → fail-closed (NOT None), so no wrongful refund.
    src = MultiSourceRxdChainSource([_FakeRxd(covenant=None), _FakeRxd(tip_fails=True)], quorum=2)
    with pytest.raises(NetworkError):
        await src.covenant_confirmations(_OUTPOINT)


async def test_covenant_locked_even_when_other_source_down():
    # One source sees it locked, the other is down → still LOCKED (a sighting is believed on any source).
    src = MultiSourceRxdChainSource([_FakeRxd(covenant=7), _FakeRxd(tip_fails=True)], quorum=2)
    assert await src.covenant_confirmations(_OUTPOINT) == 7


async def test_covenant_live_node_with_lookup_error_counts_as_absent():
    # Node reachable (tip OK) but the covenant lookup errors → that source maps to "absent"; with
    # quorum reachable sources all absent, the result is a corroborated NOT-locked.
    src = MultiSourceRxdChainSource(
        [_FakeRxd(cov_fails=True), _FakeRxd(covenant=None), _FakeRxd(covenant=None)], quorum=2
    )
    assert await src.covenant_confirmations(_OUTPOINT) is None
