"""Tests for the dust-swap ops shared helpers (scripts/_dust_swap_shared.py).

These are SCRIPT-LEVEL helpers used by the value-moving dust swap runner + resume.
Test coverage is focused on the unit-testable functions (the deadline validator and
the atomic mode-0o600 writer); the helper classes are exercised by integration test
paths (live runs against regtest / mainnet, recorded in the dust report).
"""

from __future__ import annotations

import math
import os
import sys
from pathlib import Path

import pytest

# scripts/ isn't a package; insert it on sys.path so we can import the shared module.
_SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(_SCRIPTS))
from _dust_swap_shared import (
    atomic_write_mode_600,
    validated_resume_deadline_s,
)

# --------------------------------------------------------------------------- validated_resume_deadline_s


class TestValidatedResumeDeadline:
    """The deadline that bounds the resume / forward-run WAIT-for-claim-confirmation
    loop. MUST stay strictly inside t_rxd — a deadline LONGER than t_rxd allows the
    asset to be forfeited before the deadline fires. Found by sec-sentinel H-1 +
    red-team #3 residual on 44707a3."""

    def test_returns_upper_bound_when_operator_value_is_none(self) -> None:
        # 20 RXD blocks × 300s = 6000s; safety_factor 0.5 -> upper_bound 3000s.
        assert validated_resume_deadline_s(
            operator_value=None, t_rxd_blocks=20, rxd_block_interval_s=300.0
        ) == pytest.approx(3000.0)

    def test_floor_kicks_in_for_tiny_t_rxd(self) -> None:
        # 1 block × 60s = 60s; 0.5× -> 30s. Below floor_s default 600 -> floor wins.
        assert validated_resume_deadline_s(
            operator_value=None, t_rxd_blocks=1, rxd_block_interval_s=60.0
        ) == pytest.approx(600.0)

    def test_accepts_operator_value_within_bound(self) -> None:
        # upper_bound = 3000; operator_value = 1500 is within.
        assert validated_resume_deadline_s(
            operator_value=1500.0, t_rxd_blocks=20, rxd_block_interval_s=300.0
        ) == pytest.approx(1500.0)

    def test_caps_operator_value_at_upper_bound(self, capsys: pytest.CaptureFixture) -> None:
        # The pre-fix default was 14400s (4h) vs upper_bound 3000s (50min). The cap
        # is the whole point of the fix.
        result = validated_resume_deadline_s(operator_value=14400.0, t_rxd_blocks=20, rxd_block_interval_s=300.0)
        assert result == pytest.approx(3000.0)
        # Warn loudly so the operator sees what happened.
        captured = capsys.readouterr()
        assert "exceeds the safe upper bound" in captured.out

    def test_rejects_infinity(self) -> None:
        # `--resume-deadline-s inf` would silently re-enable the unbounded loop the
        # deadline fix was designed to close. MUST raise.
        with pytest.raises(SystemExit, match="finite positive"):
            validated_resume_deadline_s(operator_value=math.inf, t_rxd_blocks=20, rxd_block_interval_s=300.0)

    def test_rejects_negative_infinity(self) -> None:
        with pytest.raises(SystemExit, match="finite positive"):
            validated_resume_deadline_s(operator_value=-math.inf, t_rxd_blocks=20, rxd_block_interval_s=300.0)

    def test_rejects_nan(self) -> None:
        # `time.monotonic() >= nan` is always False per IEEE 754 — would loop forever.
        with pytest.raises(SystemExit, match="finite positive"):
            validated_resume_deadline_s(operator_value=math.nan, t_rxd_blocks=20, rxd_block_interval_s=300.0)

    def test_rejects_zero(self) -> None:
        with pytest.raises(SystemExit, match="finite positive"):
            validated_resume_deadline_s(operator_value=0.0, t_rxd_blocks=20, rxd_block_interval_s=300.0)

    def test_rejects_negative_value(self) -> None:
        with pytest.raises(SystemExit, match="finite positive"):
            validated_resume_deadline_s(operator_value=-1.0, t_rxd_blocks=20, rxd_block_interval_s=300.0)

    def test_default_for_real_run_params(self) -> None:
        """Smoke-test the values the actual dust scripts use under typical config."""
        # t_rxd_blocks=20, rxd_block_interval_s=300 -> 6000s window -> 3000s deadline.
        # That's 50 minutes, well INSIDE the 100-minute t_rxd refund window. Compare
        # to the pre-fix default of 14400s (4h, 240% of t_rxd — broken).
        deadline = validated_resume_deadline_s(operator_value=None, t_rxd_blocks=20, rxd_block_interval_s=300.0)
        t_rxd_seconds = 20 * 300
        assert deadline < t_rxd_seconds, "deadline must be STRICTLY inside t_rxd window"


# --------------------------------------------------------------------------- atomic_write_mode_600


class TestAtomicWriteMode600:
    """The keys-file write. Must be mode 0o600 from the moment of inode creation —
    a write-then-chmod race exposes the file at umask-default mode for microseconds
    (red-team finding on cbd5fc0)."""

    def test_writes_at_mode_0o600(self, tmp_path: Path) -> None:
        target = tmp_path / "secret.json"
        atomic_write_mode_600(target, '{"k": "v"}')
        mode = os.stat(target).st_mode & 0o777
        assert mode == 0o600, f"expected mode 0o600, got {oct(mode)}"
        assert target.read_text() == '{"k": "v"}'

    def test_refuses_existing_file(self, tmp_path: Path) -> None:
        # O_EXCL: the safety property is "fail rather than silently overwrite or follow
        # a pre-placed symlink". Callers that need replace semantics unlink first.
        target = tmp_path / "exists.json"
        target.write_text("preexisting")
        with pytest.raises(FileExistsError):
            atomic_write_mode_600(target, '{"k": "v"}')

    def test_cleans_up_on_serialisation_error(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """If the write fails mid-flight, no half-written file is left behind."""
        target = tmp_path / "half.json"
        # Inject a write failure via a content object whose .write raises mid-string.
        # Simplest: monkey-patch os.fdopen to return a sentinel that raises on write.

        class _BadFile:
            def write(self, _s: str) -> int:
                raise OSError("simulated mid-write failure")

            def flush(self) -> None:
                pass

            def fileno(self) -> int:
                return -1

            def __enter__(self) -> _BadFile:
                return self

            def __exit__(self, *_a: object) -> None:
                pass

        original_fdopen = os.fdopen

        def fake_fdopen(fd: int, mode: str):
            # Close the real fd so the inode is on disk (then we'll see if cleanup unlinks).
            original_fdopen(fd, mode).close()
            return _BadFile()

        monkeypatch.setattr(os, "fdopen", fake_fdopen)
        with pytest.raises(OSError, match="simulated"):
            atomic_write_mode_600(target, "anything")
        assert not target.exists(), "half-written file should have been unlinked"
