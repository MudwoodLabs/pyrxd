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
