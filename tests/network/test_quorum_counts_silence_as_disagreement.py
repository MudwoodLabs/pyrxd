"""A source that did not answer must never be counted as agreeing.

`MultiSourceBtcDataSource` is exported public API — the class an embedder builds
to verify BTC facts against several endpoints during an atomic swap. Seven
fund-critical reads route through ``_require_quorum`` (block hash, header,
header chain, **raw transaction**, tx height, output script type, **merkle
proof**), and ``get_tip_height`` decides how buried a transaction looks.

The rule used to be "the largest group of at least `quorum` sources wins",
counted over the sources that RESPONDED. That closed a real bug — a colluding
pair could previously veto three honest sources by making the count ambiguous —
but it opened a worse one, because an attacker does not have to out-argue an
endpoint it can simply make unreachable. Public endpoints rate-limit; a
partition is indistinguishable from an outage. Measured against the pre-fix
source: **three lying sources out of seven, at the default quorum of 2, had
their forged value returned once two honest endpoints were down.**

The rule now requires the winning group to outvote every source that did not
back it, the silent ones included. `quorum` remains the availability gate — that
many must answer — but it no longer decides the value.

Both directions are pinned here. A guard that refuses valid work is its own
fund-safety bug on a chain with neither RBF nor CPFP, so every refusal case
below is paired with an honest case that must still succeed.
"""

from __future__ import annotations

import asyncio

import pytest

from pyrxd.network.bitcoin import MultiSourceBtcDataSource
from pyrxd.security.errors import NetworkError

HONEST = b"HONEST_TX_BYTES"
FORGED = b"FORGED_TX_BYTES"


def _multi(n_sources: int, quorum: int) -> MultiSourceBtcDataSource:
    """A bare instance; these tests drive the counting rule directly."""
    m = MultiSourceBtcDataSource.__new__(MultiSourceBtcDataSource)
    m._sources = [object()] * n_sources
    m.sources = m._sources
    m._quorum = quorum
    m.quorum = quorum
    return m


class _Src:
    def __init__(self, value: object) -> None:
        self._value = value

    async def get_tip_height(self) -> int:
        if isinstance(self._value, Exception):
            raise self._value
        return int(self._value)


def _tip(values: list[object], quorum: int) -> int:
    m = _multi(len(values), quorum)
    m._sources = [_Src(v) for v in values]
    m.sources = m._sources
    m._check_quorum_possible = lambda: None  # type: ignore[method-assign]

    async def gather(factory):  # type: ignore[no-untyped-def]
        return await asyncio.gather(*[factory(s) for s in m._sources], return_exceptions=True)

    m._gather_results = gather  # type: ignore[method-assign]
    return int(asyncio.run(m.get_tip_height()))


class TestSilenceIsNotCorroboration:
    """The regression, on the deterministic reads."""

    def test_a_minority_cannot_win_by_making_honest_sources_unreachable(self) -> None:
        """The measured attack: 3 liars of 7 at quorum=2, 2 honest endpoints down.

        The liars are the largest group *among responders* (3 beats 2) and clear
        the quorum, so the pre-fix rule handed back ``FORGED``. They are still a
        minority of the seven sources the operator configured, and the two that
        said nothing are not evidence for them.
        """
        down = NetworkError("endpoint unreachable")
        results = [FORGED, FORGED, FORGED, HONEST, HONEST, down, down]

        with pytest.raises(NetworkError, match="not a majority"):
            _multi(7, 2)._require_quorum(results, bytes)

    def test_two_liars_beat_five_honest_sources_that_refuse(self) -> None:
        """Honest sources that decline a read raise, so they were counted as absent.

        A source asked for a transaction it cannot serve raises rather than
        returning bytes — so on the pre-fix rule, two lying sources were the only
        group with an answer and won regardless of how many honest sources
        disagreed by refusing.
        """
        refused = NetworkError("tx not found at this depth")
        results = [FORGED, FORGED, *([refused] * 5)]

        with pytest.raises(NetworkError, match="not a majority"):
            _multi(7, 2)._require_quorum(results, bytes)

    @pytest.mark.parametrize(
        ("results", "quorum", "n"),
        [
            ([HONEST, HONEST, HONEST, FORGED, FORGED], 2, 5),
            ([HONEST, HONEST, HONEST, NetworkError("down"), NetworkError("down")], 2, 5),
            ([HONEST] * 5, 2, 5),
            ([HONEST] * 4 + [FORGED], 2, 5),
        ],
        ids=["outvotes-liars", "majority-up-rest-down", "unanimous", "one-liar"],
    )
    def test_an_honest_majority_is_still_served(self, results: list[object], quorum: int, n: int) -> None:
        """The paired half: the fix must not turn into 'refuse everything'."""
        assert _multi(n, quorum)._require_quorum(results, bytes) == HONEST


class TestTipHeightIsAlsoMajorityOfConfigured:
    def test_inflation_by_a_minority_is_refused_even_with_sources_down(self) -> None:
        down = NetworkError("endpoint unreachable")
        got = _tip([999_999, 999_999, 999_999, 900_000, 900_000, down, down], quorum=2)
        assert got == 900_000, "three inflating sources of seven must not move the tip"

    def test_a_quorum_equal_to_every_source_no_longer_inverts(self) -> None:
        """Raising quorum used to make deflation EASIER, not harder.

        At five sources with ``quorum=5`` the answer was ``heights[4]`` — the
        minimum — so a single source reporting 0 returned 0. That is the exact
        ``min()`` failure the majority rule was written to avoid, reappearing in
        the configuration an operator would pick for *more* assurance.
        """
        assert _tip([900_000, 900_000, 900_000, 900_000, 0], quorum=5) == 900_000

    def test_a_stuck_minority_cannot_stall_the_wait(self) -> None:
        assert _tip([900_000, 900_000, 900_000, 0, 0], quorum=2) == 900_000

    def test_honest_one_block_skew_is_still_tolerated(self) -> None:
        """The bug the majority rule was introduced to fix must stay fixed."""
        assert _tip([900_001, 900_000, 900_000], quorum=1) == 900_000

    def test_a_majority_answering_is_enough(self) -> None:
        down = NetworkError("endpoint unreachable")
        assert _tip([900_000, 900_000, 900_000, down, down], quorum=2) == 900_000

    def test_too_few_responders_to_establish_a_majority_fails_closed(self) -> None:
        down = NetworkError("endpoint unreachable")
        with pytest.raises(NetworkError, match="majority of the configured sources"):
            _tip([900_000, 900_000, down, down, down], quorum=2)
