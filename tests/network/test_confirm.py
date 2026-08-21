"""Tests for pyrxd.network.confirm.wait_for_confirmation.

The point of the extraction: the CLI's ``_wait_for_tx`` derived its deadline from
``asyncio.get_event_loop().time()``, so injecting a fake ``sleep`` did not advance the
clock and the timeout branch could not be reached without sleeping for real. Every test
here runs in zero wall-clock time because both seams are injected.
"""

from __future__ import annotations

import pytest

from pyrxd.network.confirm import (
    DEFAULT_CONFIRMATION_TIMEOUT_S,
    DEFAULT_POLL_INTERVAL_S,
    wait_for_confirmation,
)
from pyrxd.security.errors import (
    ConfirmationTimeoutError,
    InsufficientConfirmationsError,
    NetworkError,
    PolicyRejection,
    ValidationError,
)

_TXID = "ab" * 32


class _Reader:
    """Duck-typed stand-in for ElectrumXClient.get_transaction_verbose."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = 0

    async def get_transaction_verbose(self, txid):
        self.calls += 1
        item = self._responses[min(self.calls - 1, len(self._responses) - 1)]
        if isinstance(item, Exception):
            raise item
        return item


class _FakeClock:
    """A clock the test advances by hand, one step per read after the first."""

    def __init__(self, step: float = 0.0):
        self.now = 0.0
        self.step = step

    def __call__(self) -> float:
        value = self.now
        self.now += self.step
        return value


def _sleeps():
    recorded: list[float] = []

    async def _sleep(seconds: float) -> None:
        recorded.append(seconds)

    return recorded, _sleep


class TestHappyPath:
    async def test_returns_depth_on_first_poll(self) -> None:
        reader = _Reader([{"confirmations": 3}])
        recorded, sleep = _sleeps()

        depth = await wait_for_confirmation(reader, _TXID, sleep=sleep, clock=_FakeClock())

        assert depth == 3
        assert reader.calls == 1
        assert recorded == [], "must not sleep once the tx is already confirmed"

    async def test_polls_until_confirmed(self) -> None:
        reader = _Reader([{"confirmations": 0}, {"confirmations": 0}, {"confirmations": 1}])
        recorded, sleep = _sleeps()

        depth = await wait_for_confirmation(reader, _TXID, interval_s=7.5, sleep=sleep, clock=_FakeClock())

        assert depth == 1
        assert reader.calls == 3
        assert recorded == [7.5, 7.5], "interval_s is what gets slept, not a hard-coded 10.0"

    async def test_min_confirmations_above_one_is_respected(self) -> None:
        reader = _Reader([{"confirmations": 2}, {"confirmations": 6}])
        _recorded, sleep = _sleeps()

        depth = await wait_for_confirmation(reader, _TXID, min_confirmations=6, sleep=sleep, clock=_FakeClock())

        assert depth == 6
        assert reader.calls == 2

    async def test_network_error_is_swallowed_and_polling_continues(self) -> None:
        # Right after a broadcast the tx is routinely not yet visible to the server.
        reader = _Reader([NetworkError("no such mempool transaction"), {"confirmations": 1}])
        _recorded, sleep = _sleeps()

        assert await wait_for_confirmation(reader, _TXID, sleep=sleep, clock=_FakeClock()) == 1
        assert reader.calls == 2


class TestTimeoutBranch:
    """Previously unreachable: the injected clock is what makes these possible."""

    async def test_timeout_raises_confirmation_timeout_error(self) -> None:
        reader = _Reader([{"confirmations": 0}])
        _recorded, sleep = _sleeps()
        clock = _FakeClock(step=600.0)  # start=0, then 600, 1200, 1800 → trips at 1800

        with pytest.raises(ConfirmationTimeoutError) as ei:
            await wait_for_confirmation(reader, _TXID, timeout_s=1800.0, sleep=sleep, clock=clock)

        assert ei.value.txid == _TXID
        assert ei.value.have == 0
        assert ei.value.required == 1
        assert ei.value.waited_s >= 1800.0
        assert ei.value.reason.startswith("timeout")

    async def test_timeout_is_not_a_bare_network_error(self) -> None:
        # A timeout means "shallow, go look at the explorer", which is a different
        # operator response from "the transport is broken" — the whole reason
        # InsufficientConfirmationsError exists.
        reader = _Reader([{"confirmations": 0}])
        _recorded, sleep = _sleeps()

        with pytest.raises(InsufficientConfirmationsError):
            await wait_for_confirmation(reader, _TXID, timeout_s=10.0, sleep=sleep, clock=_FakeClock(step=100.0))

    async def test_timeout_names_the_last_transport_error(self) -> None:
        # A persistently broken transport must be diagnosable, not reported as a bare
        # "did not confirm".
        reader = _Reader([NetworkError("connection lost")])
        _recorded, sleep = _sleeps()

        with pytest.raises(ConfirmationTimeoutError) as ei:
            await wait_for_confirmation(reader, _TXID, timeout_s=10.0, sleep=sleep, clock=_FakeClock(step=100.0))

        assert "connection lost" in str(ei.value)

    async def test_max_iterations_bounds_a_frozen_clock(self) -> None:
        # A clock that never advances never times out — max_iterations is the backstop
        # so a test (or a wedged deployment) terminates instead of spinning forever.
        reader = _Reader([{"confirmations": 0}])
        recorded, sleep = _sleeps()

        with pytest.raises(ConfirmationTimeoutError) as ei:
            await wait_for_confirmation(reader, _TXID, sleep=sleep, clock=_FakeClock(step=0.0), max_iterations=4)

        assert reader.calls == 4
        assert recorded == [DEFAULT_POLL_INTERVAL_S] * 3
        assert ei.value.reason.startswith("max_iterations=4")

    async def test_exhausting_max_iterations_never_reports_success(self) -> None:
        # Fail-closed: giving up must raise, never return a depth the caller could
        # mistake for confirmation.
        reader = _Reader([{"confirmations": 0}])
        _recorded, sleep = _sleeps()

        with pytest.raises(ConfirmationTimeoutError):
            await wait_for_confirmation(reader, _TXID, sleep=sleep, clock=_FakeClock(), max_iterations=1)


class TestUntrustedResponses:
    """The server response is untrusted input; a bad shape must read as 'keep waiting'."""

    @pytest.mark.parametrize(
        "payload",
        [
            "not a dict",
            None,
            {},
            {"confirmations": "6"},
            {"confirmations": True},
            {"confirmations": -5},
            {"confirmations": None},
        ],
    )
    async def test_bad_shapes_never_satisfy_the_threshold(self, payload) -> None:
        reader = _Reader([payload])
        _recorded, sleep = _sleeps()

        with pytest.raises(ConfirmationTimeoutError) as ei:
            await wait_for_confirmation(reader, _TXID, sleep=sleep, clock=_FakeClock(), max_iterations=1)

        assert ei.value.have == 0

    async def test_float_depth_is_floored_not_rejected(self) -> None:
        reader = _Reader([{"confirmations": 2.9}])
        _recorded, sleep = _sleeps()

        assert await wait_for_confirmation(reader, _TXID, min_confirmations=2, sleep=sleep) == 2

    async def test_policy_rejection_from_the_reader_does_not_break_the_loop(self) -> None:
        # PolicyRejection is a NetworkError, so it is treated as a failed poll rather
        # than escaping the wait.
        reader = _Reader([PolicyRejection("node rejected the transaction (code 1)"), {"confirmations": 1}])
        _recorded, sleep = _sleeps()

        assert await wait_for_confirmation(reader, _TXID, sleep=sleep, clock=_FakeClock()) == 1


class TestArgumentValidation:
    @pytest.mark.parametrize(
        "kwargs",
        [
            {"min_confirmations": 0},
            {"min_confirmations": 1.5},
            {"min_confirmations": True},
            {"interval_s": -1},
            {"interval_s": "10"},
            {"interval_s": True},
            {"timeout_s": 0},
            {"timeout_s": -1},
            {"timeout_s": True},
            {"max_iterations": -1},
            {"max_iterations": 1.5},
        ],
    )
    async def test_rejects_nonsense(self, kwargs) -> None:
        with pytest.raises(ValidationError):
            await wait_for_confirmation(_Reader([{"confirmations": 1}]), _TXID, **kwargs)

    async def test_rejects_a_malformed_txid(self) -> None:
        # Txid() is the trust-boundary check; a bad id must fail before any polling.
        reader = _Reader([{"confirmations": 1}])
        with pytest.raises(ValidationError):
            await wait_for_confirmation(reader, "not-a-txid")
        assert reader.calls == 0

    def test_defaults_match_the_cli_behaviour_they_replaced(self) -> None:
        assert DEFAULT_POLL_INTERVAL_S == 10.0
        assert DEFAULT_CONFIRMATION_TIMEOUT_S == 1800.0


#
# Non-finite depth from a hostile/broken server
#
# json.loads ACCEPTS the non-standard literals Infinity/-Infinity/NaN. int(inf) raises
# OverflowError and int(nan) raises ValueError — neither is a NetworkError, so before the
# guard these escaped the fail-closed contract and surfaced as a bare traceback. On the
# mint path that happens AFTER the commit is already broadcast on-chain.
#
import json as _json
import math as _math

import pytest as _pytest

from pyrxd.network.confirm import _confirmations_of


@_pytest.mark.parametrize("literal", ["1e999", "-1e999", "NaN", "Infinity", "-Infinity"])
def test_non_finite_confirmations_are_treated_as_zero_depth(literal):
    """A non-finite depth must read as 'no confirmations', never raise."""
    info = _json.loads(f'{{"confirmations": {literal}}}')
    raw = info["confirmations"]
    assert isinstance(raw, float) and not _math.isfinite(raw), "precondition: json really parsed it"

    assert _confirmations_of(info) == 0


def test_finite_depths_still_work():
    assert _confirmations_of({"confirmations": 3}) == 3
    assert _confirmations_of({"confirmations": 2.9}) == 2
    assert _confirmations_of({"confirmations": -5}) == 0
    assert _confirmations_of({"confirmations": True}) == 0


class TestTheSleepNeverOvershootsTheDeadline:
    """The poll happens before the sleep, so a plain ``sleep(interval_s)`` makes the wait
    run to the next interval boundary rather than to ``timeout_s``.

    Measured before the fix: ``timeout_s=0.2, interval_s=3.0`` raised after 3.00s — a 15x
    overshoot. A units slip (milliseconds where seconds are meant) turns that into hours,
    on a wait that is holding a Glyph commit: a hashlock with no owner-only spend path.

    These use a clock advanced by the amount actually slept, rather than the module's
    step-per-read ``_FakeClock``, because the fix reads the clock inside the sleep
    expression — a fixture that advances per read would measure the fixture.
    """

    @staticmethod
    def _run(timeout_s: float, interval_s: float):
        import asyncio

        now = [0.0]
        slept: list[float] = []

        async def _sleep(seconds: float) -> None:
            slept.append(round(seconds, 6))
            now[0] += seconds

        reader = _Reader([{"confirmations": 0}])
        with pytest.raises(ConfirmationTimeoutError):
            asyncio.run(
                wait_for_confirmation(
                    reader,
                    "ab" * 32,
                    min_confirmations=1,
                    timeout_s=timeout_s,
                    interval_s=interval_s,
                    sleep=_sleep,
                    clock=lambda: now[0],
                )
            )
        return slept, now[0]

    @pytest.mark.parametrize(
        "timeout_s, interval_s, expected",
        [
            (0.2, 3.0, [0.2]),  # the pathological case: one clamped sleep, not a 15x overshoot
            (25.0, 10.0, [10.0, 10.0, 5.0]),  # uneven: only the LAST sleep is shortened
            (30.0, 10.0, [10.0, 10.0, 10.0]),  # even division: untouched
        ],
    )
    def test_the_sleeps_are_clamped_to_the_time_remaining(self, timeout_s, interval_s, expected):
        slept, elapsed = self._run(timeout_s, interval_s)
        assert slept == expected
        assert elapsed <= timeout_s, f"waited {elapsed} against a {timeout_s} deadline"

    def test_an_interval_longer_than_the_timeout_still_polls_once(self):
        """Clamping must not turn a short timeout into a wait that never asks the node.

        The poll precedes the sleep, so at least one real query happens before the
        deadline — the caller learns the transaction's state rather than only that time
        ran out.
        """
        reader = _Reader([{"confirmations": 0}])
        import asyncio

        now = [0.0]

        async def _sleep(seconds: float) -> None:
            now[0] += seconds

        with pytest.raises(ConfirmationTimeoutError):
            asyncio.run(
                wait_for_confirmation(
                    reader,
                    "ab" * 32,
                    min_confirmations=1,
                    timeout_s=0.05,
                    interval_s=99.0,
                    sleep=_sleep,
                    clock=lambda: now[0],
                )
            )
        assert reader.calls >= 1, "the node was never asked"


class TestTheBoundsMustBeFinite:
    """`nan <= 0` and `inf <= 0` are both False, so a bare range check lets both through —
    and every one of them makes this loop unbounded.

    Measured against a counting fake before the fix, all three ran past a 400-iteration
    cap: `timeout_s=nan` (the deadline test is always False), `timeout_s=inf` (the deadline
    never arrives), and `interval_s=nan` (`asyncio.sleep(nan)` never returns).

    The deadline clamp made the `nan` case sharper, not safer: `min(interval_s, max(0.0,
    nan - elapsed))` collapses to `sleep(0.0)`, turning a slow unbounded loop into a
    full-rate one. A bound that is not finite is not a bound.

    `GlyphMinter` and `GlyphClient` grew their own finiteness checks first. This is the
    primitive they wrap, it is `__all__`-exported, and it was still accepting exactly what
    they had learned to refuse.
    """

    @pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf")])
    def test_a_non_finite_timeout_is_refused(self, bad: float) -> None:
        import asyncio

        with pytest.raises(ValidationError, match="timeout_s"):
            asyncio.run(wait_for_confirmation(_Reader([{"confirmations": 0}]), "ab" * 32, timeout_s=bad))

    @pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf")])
    def test_a_non_finite_interval_is_refused(self, bad: float) -> None:
        import asyncio

        with pytest.raises(ValidationError, match="interval_s"):
            asyncio.run(wait_for_confirmation(_Reader([{"confirmations": 0}]), "ab" * 32, interval_s=bad))

    def test_zero_interval_is_still_accepted_here(self) -> None:
        """The primitive keeps allowing 0 — it is the low-level seam and `max_iterations`
        bounds it. `GlyphMinter` refuses 0 separately, because there it is a busy loop
        with nothing to stop it. The two layers disagree on purpose."""
        import asyncio

        with pytest.raises(ConfirmationTimeoutError):
            asyncio.run(
                wait_for_confirmation(_Reader([{"confirmations": 0}]), "ab" * 32, interval_s=0, max_iterations=2)
            )
