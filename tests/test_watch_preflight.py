"""Tests for the watchtower boot-time timing-safety preflight (pure, no chain reads)."""

from __future__ import annotations

from pyrxd.gravity.watch.preflight import TimingProblem, preflight_timing


def _sev(problems: list[TimingProblem]) -> set[str]:
    return {p.severity for p in problems}


def test_clean_config_has_no_problems():
    # poll 30s, deadman 180s (6x margin), tick 120s, window 6*300=1800s.
    assert (
        preflight_timing(
            poll_interval_s=30.0,
            tick_timeout_s=120.0,
            safety_window_blocks=6,
            rxd_block_interval_s=300.0,
            deadman_max_silence_s=180.0,
        )
        == []
    )


def test_poll_at_or_above_max_silence_is_an_error():
    problems = preflight_timing(
        poll_interval_s=200.0,
        tick_timeout_s=120.0,
        safety_window_blocks=6,
        rxd_block_interval_s=300.0,
        deadman_max_silence_s=180.0,
    )
    assert "error" in _sev(problems)
    assert any("false-page CRITICAL every cycle" in p.message for p in problems)


def test_poll_past_half_max_silence_is_a_warning_not_error():
    problems = preflight_timing(
        poll_interval_s=100.0,  # > 90 (half of 180), < 180
        tick_timeout_s=120.0,
        safety_window_blocks=6,
        rxd_block_interval_s=300.0,
        deadman_max_silence_s=180.0,
    )
    assert _sev(problems) == {"warning"}
    assert any("more than half" in p.message for p in problems)


def test_nonpositive_poll_is_an_error():
    problems = preflight_timing(
        poll_interval_s=0.0,
        tick_timeout_s=120.0,
        safety_window_blocks=6,
        rxd_block_interval_s=300.0,
    )
    assert any(p.severity == "error" and "poll-interval-s must be > 0" in p.message for p in problems)


def test_tick_budget_exceeding_safety_window_is_a_warning():
    # tick 2000s vs window 6*300=1800s.
    problems = preflight_timing(
        poll_interval_s=30.0,
        tick_timeout_s=2000.0,
        safety_window_blocks=6,
        rxd_block_interval_s=300.0,
        deadman_max_silence_s=180.0,
    )
    assert _sev(problems) == {"warning"}
    assert any("page AFTER the window" in p.message for p in problems)


def test_deadman_none_skips_the_heartbeat_checks():
    # No deadman cross-check supplied → the poll-vs-max-silence checks don't fire.
    problems = preflight_timing(
        poll_interval_s=999.0,
        tick_timeout_s=120.0,
        safety_window_blocks=6,
        rxd_block_interval_s=300.0,
        deadman_max_silence_s=None,
    )
    assert all("max-silence" not in p.message for p in problems)


def test_a_tick_budget_that_overruns_the_deadman_window_warns():
    """poll 60 s passes the poll-vs-window checks (120 < 180), but its default 240 s tick budget lets a
    tick that never times out beat 300 s after the last one, so the dead-man's-switch pages the tower DOWN."""
    problems = preflight_timing(
        poll_interval_s=60.0,
        tick_timeout_s=240.0,
        safety_window_blocks=6,
        rxd_block_interval_s=300.0,
        deadman_max_silence_s=180.0,
    )
    assert [p.severity for p in problems] == ["warning"]
    assert "false-pages the tower DOWN" in problems[0].message


def test_a_tick_budget_just_inside_the_deadman_window_is_clean():
    """Honest path, at the boundary the warning draws: 35 s poll with its default 140 s budget beats 175 s apart."""
    assert (
        preflight_timing(
            poll_interval_s=35.0,
            tick_timeout_s=140.0,
            safety_window_blocks=6,
            rxd_block_interval_s=300.0,
            deadman_max_silence_s=180.0,
        )
        == []
    )
    edge = preflight_timing(
        poll_interval_s=36.0,
        tick_timeout_s=144.0,
        safety_window_blocks=6,
        rxd_block_interval_s=300.0,
        deadman_max_silence_s=180.0,
    )
    assert [p.severity for p in edge] == ["warning"]


def test_a_nan_value_is_an_error_not_a_pass():
    """argparse's float takes "nan", and every comparison with NaN is False, so it used to pass every check."""
    base = {
        "poll_interval_s": 30.0,
        "tick_timeout_s": 120.0,
        "safety_window_blocks": 6,
        "rxd_block_interval_s": 300.0,
        "deadman_max_silence_s": 180.0,
    }
    for key in ("poll_interval_s", "tick_timeout_s", "rxd_block_interval_s", "deadman_max_silence_s"):
        for bad in (float("nan"), float("inf")):
            problems = preflight_timing(**{**base, key: bad})
            assert _sev(problems) == {"error"}, (key, bad)
            assert "finite" in problems[0].message
