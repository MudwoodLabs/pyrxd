"""Confirmation polling with every time seam injected.

``wait_for_confirmation`` is the library-side replacement for the CLI's private
``_wait_for_tx``. That helper hard-coded its poll interval and derived its deadline
from ``asyncio.get_event_loop().time()``, which made the timeout branch untestable:
injecting a fake ``sleep`` does not advance the event loop's clock, so the deadline
never arrives and the test either hangs or has to sleep for real.

Both seams are injected here — ``sleep`` **and** ``clock`` — plus ``max_iterations``
as a hard loop bound, matching the house pattern in
:func:`pyrxd.gravity.watch.daemon.run_loop` and
:func:`pyrxd.gravity.watch.heartbeat.run_monitor`. A test supplies a clock that jumps
and reaches the timeout branch deterministically in zero wall-clock time.

This module raises **library** exceptions only. The CLI's ``NetworkBoundaryError`` is a
``click.ClickException`` subclass; leaking it out of library code would make the SDK
unusable outside click and would drag a CLI dependency into the network layer. Callers
that want CLI formatting catch :class:`~pyrxd.security.errors.ConfirmationTimeoutError`
and translate at the boundary.
"""

from __future__ import annotations

import asyncio
import logging
import math
import time
from collections.abc import Awaitable, Callable
from typing import Any

from ..security.errors import ConfirmationTimeoutError, NetworkError, ValidationError
from ..security.types import Txid

__all__ = [
    "DEFAULT_CONFIRMATION_TIMEOUT_S",
    "DEFAULT_POLL_INTERVAL_S",
    "wait_for_confirmation",
]

logger = logging.getLogger(__name__)

# Radiant blocks target ~5 minutes (`nPowTargetSpacing = 5 * 60`,
# Radiant-Core/src/chainparams.cpp:117 @ v3.1.2 — mainnet; testnet, scalenet and
# regtest use the same 300s); a 10s poll is well inside one block and matches
# the interval the CLI has always used.
DEFAULT_POLL_INTERVAL_S: float = 10.0
DEFAULT_CONFIRMATION_TIMEOUT_S: float = 1800.0


# These live HERE, not in the callers that wrap this function.
#
# Three layers validated the same wait parameters with three sets of rules, added by
# three different review rounds, and they drifted: the constructors refused a value
# this primitive accepted, and vice versa. The mechanical cause was direction —
# `network/` cannot import from `glyph/`, so the shared rule sitting in `glyph/mint.py`
# was structurally unreachable from the module that most needed it.
#
# One implementation, per-layer policy: callers pass the bounds they mean. The
# primitive allows a zero interval (it is the low-level seam, and a test injecting a
# fake `sleep` wants no delay) provided `max_iterations` bounds it; the Glyph
# constructors demand a millisecond floor, because there nothing bounds a busy loop.
# Those two rules differ on purpose, and now differ in ONE place that says so.

#: Floor on a confirmation poll interval. 1ms still allows 1,000 polls/second — orders
#: faster than any node needs — while excluding the denormal-sized values that make the
#: wait a busy loop rather than a poll.
_MIN_WAIT_INTERVAL_S: float = 0.001

#: Ceiling on a confirmation timeout. One year. Anything longer is a units slip, and the
#: failure mode of an effectively-unbounded wait is an unrevealed commit — a hashlock with
#: no owner-only spend path.
_MAX_WAIT_TIMEOUT_S: float = 365.0 * 24 * 60 * 60


def _assert_finite_number(value: object, *, what: str) -> float:
    """The half every layer agrees on: it must be a real, finite number.

    Split out because the layers genuinely disagree about the REST. This primitive accepts
    a zero interval (bounded by `max_iterations`); the Glyph constructors do not. Forcing
    one predicate on both would be the wrong kind of sharing — but the finiteness rule is
    the part that actually drifted, and it now has one implementation.
    """
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise ValidationError(f"{what} must be a number")
    if isinstance(value, float) and not math.isfinite(value):
        raise ValidationError(f"{what} must be finite, got {value}")
    return float(value)


def _assert_positive_finite(
    value: object, *, what: str, minimum: float | None = None, maximum: float | None = None
) -> None:
    """A wait parameter must be a real, positive, FINITE number of seconds.

    `> 0` alone is not enough, and the gap is not academic: ``nan <= 0`` and ``inf <= 0``
    are both False, so both sail through a bare positivity check. ``asyncio.sleep(nan)``
    and ``asyncio.sleep(inf)`` never return (measured: still sleeping after 1.5s), and with
    ``timeout_s=nan`` the loop's ``elapsed >= timeout_s`` is always False while
    ``max_iterations`` defaults to None — so the wait is unbounded in both directions.

    A reveal that never returns AND never raises leaves an on-chain commit that is a
    hashlock with no owner-only spend path: the exact stranding these guards exist to
    prevent, reached by the one input class the guards did not name.

    ``network/confirm.py`` already applies ``math.isfinite`` to numbers coming off the
    wire. This is the same rule applied to numbers coming from the caller, in one place so
    the two constructors cannot drift apart.
    """
    _assert_finite_number(value, what=what)
    assert isinstance(value, (int, float))  # narrowed by the check above
    if value <= 0:
        raise ValidationError(f"{what} must be > 0")
    # Bound the range, not just the two IEEE spellings of "no bound".
    #
    # Refusing `inf` and accepting `1e308` is theatre: a wait of 1e308 seconds is the
    # never-returns case under a different name. And refusing `0` while accepting
    # `5e-324` is the same busy loop — measured at 254,728 polls/second, against a
    # docstring that cites 715,000/s as the hazard. The guard was written against the two
    # literals a reviewer named rather than against the behaviour they exemplify.
    #
    # The floor is per-poll, so 1ms still permits 1,000 polls/second — far faster than any
    # node needs, and well below the 0.25s this project uses on regtest. The ceiling is a
    # year: a mint that waits longer than that is a units error, not a patient caller.
    if minimum is not None and value < minimum:
        raise ValidationError(
            f"{what} must be >= {minimum}s — a shorter poll is a busy loop against the node, not a faster confirmation"
        )
    if maximum is not None and value > maximum:
        raise ValidationError(
            f"{what} must be <= {maximum}s; a longer wait is a units error, and a wait "
            f"that never ends holds an unrevealed commit"
        )


def _confirmations_of(info: Any) -> int:
    """Read the confirmation depth out of a ``get_transaction_verbose`` response.

    Fail-closed: anything that is not a dict with a non-negative integral
    ``confirmations`` reads as 0 (i.e. "keep waiting"), never as confirmed. The
    server response is untrusted input — a string, a float, or a negative number
    must not be coerced into a depth that satisfies the caller's threshold.
    """
    if not isinstance(info, dict):
        return 0
    raw = info.get("confirmations", 0)
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        return 0
    # Non-finite guard: json.loads ACCEPTS the non-standard literals Infinity/-Infinity/NaN,
    # so a hostile or broken server can return `{"confirmations": 1e999}` -> float('inf').
    # int(inf) raises OverflowError and int(nan) raises ValueError — neither is a NetworkError,
    # so without this they escape the caller's fail-closed handling and surface as a bare
    # traceback. On the mint path that happens AFTER the commit is already on-chain.
    if isinstance(raw, float) and not math.isfinite(raw):
        return 0
    depth = int(raw)
    return depth if depth > 0 else 0


async def wait_for_confirmation(
    client: Any,
    txid: str | Txid,
    *,
    min_confirmations: int = 1,
    interval_s: float = DEFAULT_POLL_INTERVAL_S,
    timeout_s: float = DEFAULT_CONFIRMATION_TIMEOUT_S,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    clock: Callable[[], float] = time.monotonic,
    max_iterations: int | None = None,
) -> int:
    """Poll ``client`` until ``txid`` has at least ``min_confirmations``.

    Returns the observed confirmation depth. Raises
    :class:`~pyrxd.security.errors.ConfirmationTimeoutError` — a
    :class:`~pyrxd.security.errors.InsufficientConfirmationsError`, therefore a
    :class:`~pyrxd.security.errors.NetworkError` — if the deadline or
    ``max_iterations`` is reached first.

    A :class:`~pyrxd.security.errors.NetworkError` from a single poll is **swallowed**
    and the loop continues: right after a broadcast the tx is routinely not yet visible
    to the server, and that read fails. The last such error is remembered and named in
    the timeout message, so a persistently broken transport is still diagnosable rather
    than being reported as a bare "did not confirm". (The pre-extraction helper claimed
    in its docstring to "re-raise on persistent network failure" — it never did; this
    documents and preserves the real, correct behaviour.)

    Args:
        client: anything exposing ``async get_transaction_verbose(Txid) -> dict``
            (e.g. :class:`~pyrxd.network.electrumx.ElectrumXClient`). Duck-typed on
            purpose so tests and alternative readers need no adapter class.
        txid: transaction to watch.
        min_confirmations: depth required before returning. Must be >= 1.
        interval_s: seconds between polls, passed to ``sleep``.
        timeout_s: give up once ``clock()`` has advanced this far past the start.
        sleep: awaitable sleep — inject to run without real time.
        clock: monotonic-ish time source — inject to reach the timeout branch. It is
            read once at entry, then twice per iteration (the deadline test and the sleep clamp); a clock that never advances
            never times out, which is why ``max_iterations`` exists.
        max_iterations: hard bound on poll count. ``None`` = unbounded (the
            production default). Exhausting it raises the same timeout error with
            ``reason="max_iterations"`` — fail-closed, never a silent "confirmed".
    """
    if not isinstance(min_confirmations, int) or isinstance(min_confirmations, bool) or min_confirmations < 1:
        raise ValidationError("wait_for_confirmation min_confirmations must be an int >= 1")
    # Finite, not merely in-range. `nan <= 0` and `inf <= 0` are both False, so a bare
    # bound lets both through, and every one of them makes this loop unbounded:
    #   timeout_s=nan  -> `elapsed >= timeout_s` is always False
    #   timeout_s=inf  -> the deadline never arrives
    #   interval_s=nan -> `asyncio.sleep(nan)` never returns
    # `max_iterations` defaults to None, so nothing else stops it.
    #
    # This belongs HERE, in the primitive, not only in the callers that wrap it. Both
    # `GlyphMinter` and `GlyphClient` gained their own finiteness checks first, which
    # protected their own paths and left this one — a public, `__all__`-exported function
    # — accepting exactly what they had learned to refuse.
    #
    # The deadline clamp below made the `nan` case sharper rather than safer: with
    # `timeout_s=nan` the clamp collapses to `sleep(0.0)`, turning a slow unbounded loop
    # into a full-rate one. A bound that is not finite is not a bound.
    _assert_finite_number(interval_s, what="wait_for_confirmation interval_s")
    if interval_s < 0:
        raise ValidationError("wait_for_confirmation interval_s must be >= 0")
    if interval_s < _MIN_WAIT_INTERVAL_S and max_iterations is None:
        # A zero interval is a busy loop, not a fast poll: measured at 644,164 polls per
        # second against the node, sustained for the whole timeout. It is allowed here —
        # this is the low-level seam, and a test injecting a fake `sleep` legitimately
        # wants no delay — but only when something BOUNDS it.
        #
        # The docstring used to say `max_iterations` bounds it. That was true only if the
        # caller passed one, and it defaults to None, so the sentence described an opt-in
        # as if it were a default. Requiring them together makes the sentence true.
        raise ValidationError(
            f"wait_for_confirmation interval_s below {_MIN_WAIT_INTERVAL_S}s requires "
            "max_iterations — an unbounded sub-millisecond poll is a busy loop against the "
            "node, not a faster confirmation"
        )
    _assert_positive_finite(timeout_s, what="wait_for_confirmation timeout_s", maximum=_MAX_WAIT_TIMEOUT_S)
    if max_iterations is not None and (not isinstance(max_iterations, int) or max_iterations < 0):
        raise ValidationError("wait_for_confirmation max_iterations must be a non-negative int or None")

    watched = Txid(str(txid))
    start = clock()
    iterations = 0
    depth = 0
    last_error: str | None = None

    while True:
        try:
            info = await client.get_transaction_verbose(watched)
            depth = _confirmations_of(info)
            if depth >= min_confirmations:
                return depth
        except NetworkError as exc:
            # Not yet relayed / not yet indexed is the common case straight after a
            # broadcast. Keep the reason for the timeout message instead of dropping it.
            last_error = str(exc)
            logger.debug("confirmation poll for %s failed (continuing): %s", watched, last_error)

        iterations += 1
        elapsed = clock() - start
        if elapsed >= timeout_s:
            raise ConfirmationTimeoutError(
                txid=str(watched),
                have=depth,
                required=min_confirmations,
                waited_s=elapsed,
                reason=f"timeout{'' if last_error is None else f' (last poll error: {last_error})'}",
            )
        if max_iterations is not None and iterations >= max_iterations:
            raise ConfirmationTimeoutError(
                txid=str(watched),
                have=depth,
                required=min_confirmations,
                waited_s=elapsed,
                reason=f"max_iterations={max_iterations}"
                + ("" if last_error is None else f" (last poll error: {last_error})"),
            )
        # Never sleep past the deadline. The poll happens before the sleep, so a plain
        # `sleep(interval_s)` makes the wait run to the next interval boundary rather than
        # to `timeout_s`: measured at `timeout_s=0.2, interval_s=3.0`, the timeout fired
        # after 3.00s — a 15x overshoot. A units slip (ms where seconds are meant) turns
        # that into hours, twice per mint, on a wait that is holding a hashlock commit.
        await sleep(min(interval_s, max(0.0, timeout_s - (clock() - start))))
