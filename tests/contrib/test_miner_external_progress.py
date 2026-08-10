"""Tests for the external-miner stderr progress-frame extension (B3).

Follow-up to #361: the dMint ETA work streamed live hashrate/ETA for the
BUNDLED miner (in-process), but a genuinely external ``--miner-cmd``
binary had no way to report progress -- the JSON-over-stdio protocol
carried no progress frames. This extends the protocol (see
``pyrxd.contrib.miner.protocol.MineProgress`` / ``parse_progress_line``,
and their unit tests in ``test_miner_protocol.py``) and the consumer side
in ``mine_solution_external`` (``src/pyrxd/glyph/dmint/miner.py``).

These are behavioral/integration tests against real subprocesses, using
small Python stub miners -- the same pattern
``test_miner_external_integration.py`` and ``test_dmint_v1_mint.py`` use
for the pre-existing exhaustion/success paths.

Five things pinned here, matching the plan's test list:

1. An old miner that emits no progress frames still works (both with and
   without ``progress=`` requested) -- silence stays valid.
2. A progress frame updates the caller's display (the callback fires with
   live, in-order values).
3. A flood of progress frames is bounded -- both the reader's own memory
   (direct unit tests against ``_ExternalMinerProgressReader``) and the
   caller-facing callback invocation count (end to end).
4. A progress frame -- even one carrying a nonce-shaped payload -- can
   never be mistaken for a solution: it lives on a stream
   (``mine_solution_external``'s result parser never reads) and its
   parser can only ever produce an ``(attempts, elapsed_s)`` pair.
5. A miner that exits immediately is reported as a failure
   (``ValidationError``), never as nonce-space exhaustion
   (``MaxAttemptsError``) -- the external-path equivalent of the
   parallel-miner immediate-death bug ``_assert_workers_completed``
   guards against.
"""

from __future__ import annotations

import json
import stat
import sys
import textwrap
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from pyrxd.glyph.dmint import mine_solution_external
from pyrxd.glyph.dmint.miner import (
    _PROGRESS_LINE_MAX_BYTES,
    _ExternalMinerProgressReader,
    _parse_external_progress_frame,
)
from pyrxd.security.errors import MaxAttemptsError, ValidationError

_PREIMAGE = b"\x00" * 64
_TARGET = 1
# A digest that passes verify_sha256d_solution against _PREIMAGE/_TARGET
# via the same hashlib-patch trick test_dmint_v1_mint.py uses -- lets the
# success-path tests exercise a REAL accepted nonce, not just a rejection.
_FAKE_VALID_HASH = b"\x00\x00\x00\x00" + (0).to_bytes(8, "big") + b"\xff" * 20


def _write_stub(tmp_path: Path, body: str) -> list[str]:
    """Write an executable python3 stub miner script; return its miner_argv."""
    path = tmp_path / "stub_miner.py"
    path.write_text("#!/usr/bin/env python3\n" + textwrap.dedent(body))
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return [sys.executable, str(path)]


def _mine_with_fake_verify(**kwargs):
    """Call mine_solution_external with hashlib patched so _FAKE_VALID_HASH's
    nonce verifies -- shared by the success-path tests below."""
    with patch("pyrxd.glyph.dmint.miner.hashlib") as mock_hashlib:
        mock_hashlib.sha256.return_value.digest.return_value = _FAKE_VALID_HASH
        return mine_solution_external(preimage=_PREIMAGE, target=_TARGET, **kwargs)


# ---------------------------------------------------------------------------
# 1. Old miner (no progress frames) still works
# ---------------------------------------------------------------------------


class TestOldMinerStaysSilentAndStillWorks:
    def test_no_progress_kwarg_unchanged_behavior(self, tmp_path):
        """The default (progress=None) path: no behavior change at all."""
        miner_argv = _write_stub(
            tmp_path,
            """
            import sys, json
            sys.stdin.read()
            sys.stdout.write(json.dumps({"nonce_hex": "deadbeef", "attempts": 1, "elapsed_s": 0.01}))
            """,
        )
        result = _mine_with_fake_verify(miner_argv=miner_argv, nonce_width=4, timeout_s=10)
        assert result.nonce == bytes.fromhex("deadbeef")

    def test_progress_requested_but_miner_never_emits_a_frame(self, tmp_path):
        """A caller CAN pass progress= even against a miner that has never
        heard of progress frames -- it just never gets called. Silence is
        valid on both sides of this extension."""
        miner_argv = _write_stub(
            tmp_path,
            """
            import sys, json
            sys.stdin.read()
            sys.stdout.write(json.dumps({"nonce_hex": "deadbeef", "attempts": 1, "elapsed_s": 0.01}))
            """,
        )
        calls: list[tuple[int, float]] = []
        result = _mine_with_fake_verify(
            miner_argv=miner_argv,
            nonce_width=4,
            timeout_s=10,
            progress=lambda a, e: calls.append((a, e)),
            progress_interval_s=0.01,
        )
        assert result.nonce == bytes.fromhex("deadbeef")
        assert calls == []


# ---------------------------------------------------------------------------
# 2. A progress frame updates the display
# ---------------------------------------------------------------------------


class TestProgressFrameUpdatesTheCallback:
    def test_callback_receives_live_in_order_updates(self, tmp_path):
        miner_argv = _write_stub(
            tmp_path,
            """
            import sys, json, time
            sys.stdin.read()
            for i in range(6):
                sys.stderr.write(json.dumps({"progress": {"attempts": i * 500, "elapsed_s": i * 0.05}}) + "\\n")
                sys.stderr.flush()
                time.sleep(0.05)
            sys.stdout.write(json.dumps({"nonce_hex": "deadbeef", "attempts": 3000, "elapsed_s": 0.3}))
            """,
        )
        calls: list[tuple[int, float]] = []
        result = _mine_with_fake_verify(
            miner_argv=miner_argv,
            nonce_width=4,
            timeout_s=10,
            progress=lambda a, e: calls.append((a, e)),
            progress_interval_s=0.01,
        )
        assert result.nonce == bytes.fromhex("deadbeef")
        assert len(calls) >= 1, "expected at least one live progress update over a 300ms grind"
        emitted_attempts = {i * 500 for i in range(6)}
        observed_attempts = [a for a, _ in calls]
        for attempts in observed_attempts:
            assert attempts in emitted_attempts
        # Monotonic: the poll loop always reads the MOST RECENT frame, so
        # what the callback observes can never regress.
        assert observed_attempts == sorted(observed_attempts)


# ---------------------------------------------------------------------------
# 3. A flood of progress frames is bounded
# ---------------------------------------------------------------------------


class TestFloodIsBounded:
    """End-to-end: the caller-facing callback invocation count stays
    bounded against a flood, even though the miner writes far more lines
    than that. The reader's own memory bound is pinned directly by
    TestProgressReaderMemoryBound below."""

    def test_flood_completes_without_hanging_and_callback_stays_bounded(self, tmp_path):
        miner_argv = _write_stub(
            tmp_path,
            """
            import sys, json
            sys.stdin.read()
            for i in range(20000):
                sys.stderr.write(json.dumps({"progress": {"attempts": i, "elapsed_s": 0.0}}) + "\\n")
            sys.stdout.write(json.dumps({"nonce_hex": "deadbeef", "attempts": 20000, "elapsed_s": 0.1}))
            """,
        )
        calls: list[tuple[int, float]] = []
        started = time.monotonic()
        result = _mine_with_fake_verify(
            miner_argv=miner_argv,
            nonce_width=4,
            timeout_s=5,
            progress=lambda a, e: calls.append((a, e)),
            progress_interval_s=0.05,
        )
        elapsed = time.monotonic() - started
        assert result.nonce == bytes.fromhex("deadbeef")
        assert elapsed < 5, "flood should not have run into the timeout"
        # 20,000 frames were written; the callback is rate-limited by the
        # poll cadence, not by frame count -- nowhere near 20,000 calls.
        assert len(calls) < 200


class TestProgressReaderMemoryBound:
    """Direct tests of the internal bounded reader -- the actual O(1)
    memory guarantee, independent of subprocess/OS-pipe timing.

    _ExternalMinerProgressReader retains at most ONE parsed frame (new
    ones overwrite old, never accumulate) and caps a single unterminated
    "line" at _PROGRESS_LINE_MAX_BYTES, dropping and resynchronizing at
    the next newline rather than growing without bound.
    """

    def test_oversize_line_is_dropped_and_reader_resyncs(self):
        import os

        read_fd, write_fd = os.pipe()
        stream = os.fdopen(read_fd, "rb")
        reader = _ExternalMinerProgressReader(stream)
        reader.start()
        try:
            with os.fdopen(write_fd, "wb") as w:
                # A single "line" several times the cap, with no newline
                # for a long stretch -- must never be accumulated whole.
                w.write(b"x" * (_PROGRESS_LINE_MAX_BYTES * 4))
                w.write(b"\n")  # resync point
                good = json.dumps({"progress": {"attempts": 42, "elapsed_s": 1.0}}).encode() + b"\n"
                w.write(good)
            reader.join(timeout=2.0)
            assert reader.latest() == (42, 1.0)
        finally:
            stream.close()

    def test_fifty_thousand_frames_only_the_latest_is_retained(self):
        import os

        read_fd, write_fd = os.pipe()
        stream = os.fdopen(read_fd, "rb")
        reader = _ExternalMinerProgressReader(stream)
        reader.start()
        try:
            with os.fdopen(write_fd, "wb") as w:
                for i in range(50_000):
                    w.write(json.dumps({"progress": {"attempts": i, "elapsed_s": 0.0}}).encode() + b"\n")
            reader.join(timeout=10.0)
            # Retained state is a single (int, float) tuple -- not a list
            # of 50,000 frames -- regardless of how many were written.
            assert reader.latest() == (49_999, 0.0)
        finally:
            stream.close()


# ---------------------------------------------------------------------------
# 4. A progress frame can never be mistaken for a solution
# ---------------------------------------------------------------------------


class TestParseExternalProgressFrameStructural:
    """_parse_external_progress_frame can only ever return an
    (int, float) pair or None -- there is no return path that could carry
    a nonce, structurally, regardless of what the input JSON contains."""

    def test_valid_frame(self):
        line = json.dumps({"progress": {"attempts": 5, "elapsed_s": 1.25}}).encode()
        assert _parse_external_progress_frame(line) == (5, 1.25)

    def test_nonce_shaped_payload_without_progress_wrapper_is_not_a_frame(self):
        """A line shaped exactly like MineSuccess's wire format (what a
        buggy or hostile miner might write to stderr instead of stdout)
        has no "progress" key -- it is simply not a progress frame."""
        line = json.dumps({"nonce_hex": "deadbeef", "attempts": 1, "elapsed_s": 0.1}).encode()
        assert _parse_external_progress_frame(line) is None

    def test_progress_frame_with_smuggled_nonce_field_yields_only_the_pair(self):
        """Even a well-formed progress frame that ALSO carries a sibling
        nonce_hex key can only ever produce the (attempts, elapsed_s)
        tuple -- there is no code path that extracts a nonce from it."""
        line = json.dumps(
            {
                "progress": {"attempts": 7, "elapsed_s": 0.2},
                "nonce_hex": "deadbeef",
            }
        ).encode()
        assert _parse_external_progress_frame(line) == (7, 0.2)


class TestProgressChannelCannotForgeAResult:
    """End to end: a miner writes a full solution-shaped JSON object to
    STDERR (the wrong stream) while stdout honestly reports exhaustion.
    The result must come from stdout only."""

    def test_stderr_solution_shaped_line_is_ignored_stdout_exhaustion_wins(self, tmp_path):
        miner_argv = _write_stub(
            tmp_path,
            """
            import sys, json
            sys.stdin.read()
            sys.stderr.write(json.dumps({"nonce_hex": "deadbeef", "attempts": 999999, "elapsed_s": 999.0}) + "\\n")
            sys.stderr.flush()
            sys.stdout.write(json.dumps({"exhausted": True}))
            sys.exit(2)
            """,
        )
        calls: list[tuple[int, float]] = []
        with pytest.raises(MaxAttemptsError, match="exhausted"):
            mine_solution_external(
                preimage=_PREIMAGE,
                target=_TARGET,
                miner_argv=miner_argv,
                nonce_width=4,
                timeout_s=10,
                progress=lambda a, e: calls.append((a, e)),
                progress_interval_s=0.01,
            )
        # The stderr line never matched the {"progress": {...}} shape
        # either, so it never even reached the callback.
        assert calls == []


# ---------------------------------------------------------------------------
# 5. Immediate death is reported as failure, not exhaustion
# ---------------------------------------------------------------------------


class TestImmediateDeathIsFailureNotExhaustion:
    """The external-path equivalent of the parallel-miner immediate-death
    bug: a miner that dies before doing anything must never be reported
    as having exhausted the nonce space (that would send the caller off
    to reroll and grind again for nothing)."""

    def test_immediate_crash_without_progress(self, tmp_path):
        miner_argv = _write_stub(tmp_path, "import sys\nsys.stdin.read()\nsys.exit(1)\n")
        with pytest.raises(ValidationError, match="exited with code 1"):
            mine_solution_external(
                preimage=_PREIMAGE, target=_TARGET, miner_argv=miner_argv, nonce_width=4, timeout_s=10
            )

    def test_immediate_crash_with_progress_requested(self, tmp_path):
        """Same crash, but now the caller opted into the streaming
        (Popen-based) path -- must not be misreported as exhaustion
        there either."""
        miner_argv = _write_stub(tmp_path, "import sys\nsys.stdin.read()\nsys.exit(1)\n")
        calls: list[tuple[int, float]] = []
        with pytest.raises(ValidationError, match="exited with code 1"):
            mine_solution_external(
                preimage=_PREIMAGE,
                target=_TARGET,
                miner_argv=miner_argv,
                nonce_width=4,
                timeout_s=10,
                progress=lambda a, e: calls.append((a, e)),
                progress_interval_s=0.01,
            )
        assert calls == []

    def test_immediate_exit_zero_empty_stdout_with_progress_requested(self, tmp_path):
        """Exit 0 but no response at all is a malformed miner, not a
        completed sweep."""
        miner_argv = _write_stub(tmp_path, "import sys\nsys.stdin.read()\n")
        with pytest.raises(ValidationError, match="non-JSON"):
            mine_solution_external(
                preimage=_PREIMAGE,
                target=_TARGET,
                miner_argv=miner_argv,
                nonce_width=4,
                timeout_s=10,
                progress=lambda a, e: None,
                progress_interval_s=0.01,
            )


# ---------------------------------------------------------------------------
# A raising progress callback is the supported deadline idiom
# ---------------------------------------------------------------------------


class _Deadline(Exception):
    pass


class TestRaisingProgressCallbackPropagatesAndTerminatesSubprocess:
    def test_callback_raising_stops_the_grind_early(self, tmp_path):
        """Mirrors mine_solution / parallel.mine: a raising progress
        callback is the supported way to impose a deadline. The
        subprocess must be terminated (not left running for the full
        grind), which this test observes indirectly: the miner's script
        would run for ~5s if left alone (100 * 0.05s sleeps), but the
        call returns almost immediately because the first progress frame
        raises."""
        miner_argv = _write_stub(
            tmp_path,
            """
            import sys, time, json
            sys.stdin.read()
            for i in range(100):
                sys.stderr.write(json.dumps({"progress": {"attempts": i, "elapsed_s": i * 0.05}}) + "\\n")
                sys.stderr.flush()
                time.sleep(0.05)
            sys.stdout.write(json.dumps({"nonce_hex": "deadbeef", "attempts": 1, "elapsed_s": 0.1}))
            """,
        )

        def _raise_immediately(attempts: int, elapsed_s: float) -> None:
            raise _Deadline("stop")

        started = time.monotonic()
        with pytest.raises(_Deadline):
            mine_solution_external(
                preimage=_PREIMAGE,
                target=_TARGET,
                miner_argv=miner_argv,
                nonce_width=4,
                timeout_s=10,
                progress=_raise_immediately,
                progress_interval_s=0.01,
            )
        elapsed = time.monotonic() - started
        # The full grind would take ~5s; a deadline raised on the first
        # observed frame must cut it off in well under a second.
        assert elapsed < 2.0, f"expected an early cutoff, took {elapsed:.2f}s"
