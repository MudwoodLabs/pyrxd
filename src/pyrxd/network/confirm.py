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
    if (
        not isinstance(interval_s, (int, float))
        or isinstance(interval_s, bool)
        or (isinstance(interval_s, float) and not math.isfinite(interval_s))
        or interval_s < 0
    ):
        raise ValidationError("wait_for_confirmation interval_s must be a finite number >= 0")
    if (
        not isinstance(timeout_s, (int, float))
        or isinstance(timeout_s, bool)
        or (isinstance(timeout_s, float) and not math.isfinite(timeout_s))
        or timeout_s <= 0
    ):
        raise ValidationError("wait_for_confirmation timeout_s must be a finite number > 0")
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
