"""Boot-time timing-safety checks for the watchtower — pure, no chain reads.

The tower's correctness rests on a few timing relationships configured across two separate processes
(the tower and the dead-man's-switch) with no built-in cross-check. :func:`preflight_timing` recomputes
those relationships from the loaded config and returns the problems, so the operational entrypoint can
**fail fast** on a footgun config instead of false-paging (or paging too late) in production.

See ``docs/runbooks/watchtower-operations.md`` for the operational context of each check.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class TimingProblem:
    """One config-timing problem. ``severity`` is ``"error"`` (refuse to start) or ``"warning"``."""

    severity: str
    message: str


def preflight_timing(
    *,
    poll_interval_s: float,
    tick_timeout_s: float,
    safety_window_blocks: int,
    rxd_block_interval_s: float,
    deadman_max_silence_s: float | None = None,
) -> list[TimingProblem]:
    """Return the timing-safety problems in this watchtower config (empty == clean).

    Checks (all config-only — no chain reads):

    * ``poll_interval_s`` / ``tick_timeout_s`` are positive.
    * **Heartbeat-vs-watchdog (footgun #1).** The tower refreshes the heartbeat once per poll; if the
      poll interval is at or beyond the dead-man's-switch window, the heartbeat is stale by the time the
      watchdog looks and it false-pages CRITICAL every cycle. ``error`` at ``>=``; ``warning`` past half.
    * **Tick-vs-safety-window (footgun #2).** A tick that can run as long as the safety window pages
      *after* the window it was meant to protect. ``warning`` when ``tick_timeout_s`` reaches that window.

    The caller refuses to start on any ``error`` and logs each ``warning``.
    """
    problems: list[TimingProblem] = []

    if poll_interval_s <= 0:
        problems.append(TimingProblem("error", f"poll-interval-s must be > 0 (got {poll_interval_s})"))
    if tick_timeout_s <= 0:
        problems.append(TimingProblem("error", f"tick-timeout-s must be > 0 (got {tick_timeout_s})"))

    if deadman_max_silence_s is not None:
        if poll_interval_s >= deadman_max_silence_s:
            problems.append(
                TimingProblem(
                    "error",
                    f"poll-interval-s ({poll_interval_s}s) >= dead-man's-switch max-silence-s "
                    f"({deadman_max_silence_s}s): the watchdog will false-page CRITICAL every cycle "
                    "(the heartbeat is stale before it is checked). Lower the poll interval or widen "
                    "max-silence.",
                )
            )
        elif poll_interval_s * 2 >= deadman_max_silence_s:
            problems.append(
                TimingProblem(
                    "warning",
                    f"poll-interval-s ({poll_interval_s}s) is more than half the dead-man's-switch "
                    f"max-silence-s ({deadman_max_silence_s}s): a single missed/slow tick can false-page. "
                    "Widen the margin (e.g. poll 30s, max-silence 180s).",
                )
            )

    window_s = safety_window_blocks * rxd_block_interval_s
    if window_s > 0 and tick_timeout_s >= window_s:
        problems.append(
            TimingProblem(
                "warning",
                f"tick-timeout-s ({tick_timeout_s}s) >= the safety window ({safety_window_blocks} blk x "
                f"{rxd_block_interval_s}s = {window_s}s): a slow tick can page AFTER the window it is "
                "meant to protect. Lower the tick budget or widen --safety-window-blocks.",
            )
        )

    return problems
