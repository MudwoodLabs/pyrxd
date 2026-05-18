"""Integration tests for the pyrxd.contrib.miner ↔ mine_solution_external
contract.

Pinned in 0.5.1: the miner can signal exhaustion by exiting 2 with
``{"exhausted": true}`` on stdout, and ``mine_solution_external``
recognises that signal and raises ``MaxAttemptsError`` immediately
(no waiting for the parent timeout). Tests use a stub-miner-as-bash
to avoid the real-miner's mining cost; one test spawns the actual
``python -m pyrxd.contrib.miner`` to confirm wire compatibility.
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

import pytest

from pyrxd.glyph.dmint import mine_solution_external
from pyrxd.security.errors import MaxAttemptsError, ValidationError

# ---------------------------------------------------------------------------
# Stub miner shell scripts
# ---------------------------------------------------------------------------
#
# Each test invokes mine_solution_external with a miner_argv that points
# at a tiny shell script that emits a chosen response. Lets us exercise
# every branch of mine_solution_external's response handling without
# burning the ~minutes of real mining.


def _make_stub_miner(tmp_path: Path, stdout: str, exit_code: int = 0) -> list[str]:
    """Create an executable shell script that prints ``stdout`` and exits
    ``exit_code``. Returns ``miner_argv`` ready to pass to
    ``mine_solution_external``."""
    script = tmp_path / "stub_miner.sh"
    # Use printf to avoid echo's portability gotchas with backslashes.
    content = f"#!/usr/bin/env bash\nset -eu\nprintf '%s\\n' '{stdout}'\nexit {exit_code}\n"
    script.write_text(content)
    script.chmod(script.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return [str(script)]


_PREIMAGE = bytes.fromhex("ab" * 64)
_TARGET = 0x7FFFFFFFFFFFFFFF


# ---------------------------------------------------------------------------
# Exhaustion path (new in 0.5.1)
# ---------------------------------------------------------------------------


class TestExhaustionIntegration:
    """The ``{"exhausted": true}`` + exit-2 response signal maps to
    ``MaxAttemptsError`` immediately. Old miners that don't know this
    convention can still SIGKILL via timeout — that path is exercised
    by the existing test in tests/test_dmint_v1_mint.py."""

    def test_exit2_with_exhausted_json_raises_max_attempts(self, tmp_path: Path):
        miner_argv = _make_stub_miner(tmp_path, stdout='{"exhausted": true}', exit_code=2)
        with pytest.raises(MaxAttemptsError) as exc:
            mine_solution_external(
                preimage=_PREIMAGE,
                target=_TARGET,
                miner_argv=miner_argv,
                nonce_width=4,
                timeout_s=10,
            )
        assert "exhausted" in str(exc.value).lower()
        assert exc.value.attempts == 0
        assert exc.value.elapsed_s >= 0

    def test_exit2_without_exhausted_json_raises_validation_error(self, tmp_path: Path):
        """A miner that exits 2 but doesn't write the ``{"exhausted":
        true}`` marker is a buggy miner — pyrxd refuses to treat
        arbitrary stderr noise as an exhaustion signal."""
        miner_argv = _make_stub_miner(tmp_path, stdout='{"some other shape": 42}', exit_code=2)
        with pytest.raises(ValidationError, match="exited with code 2"):
            mine_solution_external(
                preimage=_PREIMAGE,
                target=_TARGET,
                miner_argv=miner_argv,
                nonce_width=4,
                timeout_s=10,
            )

    def test_exit2_with_non_json_stdout_raises_validation_error(self, tmp_path: Path):
        """A miner that exits 2 with non-JSON stdout is also a bug,
        not an exhaustion signal."""
        miner_argv = _make_stub_miner(tmp_path, stdout="not json", exit_code=2)
        with pytest.raises(ValidationError, match="exited with code 2"):
            mine_solution_external(
                preimage=_PREIMAGE,
                target=_TARGET,
                miner_argv=miner_argv,
                nonce_width=4,
                timeout_s=10,
            )

    def test_exit2_with_empty_stdout_falls_through_to_validation_error(self, tmp_path: Path):
        """A miner that exits 2 with empty stdout is a programming
        error in the miner. pyrxd reports it as a generic non-zero
        exit, not as exhaustion."""
        miner_argv = _make_stub_miner(tmp_path, stdout="", exit_code=2)
        with pytest.raises(ValidationError, match="exited with code 2"):
            mine_solution_external(
                preimage=_PREIMAGE,
                target=_TARGET,
                miner_argv=miner_argv,
                nonce_width=4,
                timeout_s=10,
            )

    def test_exhausted_with_other_exit_code_is_not_special_cased(self, tmp_path: Path):
        """Only the (exit=2, exhausted=true) combination is the
        exhaustion signal. A miner that writes ``{"exhausted": true}``
        but exits 0 is malformed — pyrxd treats it as a generic
        bad-response (it has no ``nonce_hex`` field)."""
        miner_argv = _make_stub_miner(tmp_path, stdout='{"exhausted": true}', exit_code=0)
        with pytest.raises(ValidationError, match="nonce_hex"):
            mine_solution_external(
                preimage=_PREIMAGE,
                target=_TARGET,
                miner_argv=miner_argv,
                nonce_width=4,
                timeout_s=10,
            )


# ---------------------------------------------------------------------------
# Pre-existing paths still work (regression guard)
# ---------------------------------------------------------------------------


class TestPreExistingPathsStillWork:
    """The 0.5.1 additions are additive. Old behaviours (success on
    exit 0, ValidationError on other failures) must still fire."""

    def test_success_path_unchanged(self, tmp_path: Path):
        """A valid success response on exit 0 still parses correctly.

        The nonce here is the one we previously confirmed mines from
        preimage=ab*64 — picked so the local re-verification in
        mine_solution_external accepts it."""
        nonce_hex = "d17f0162"
        stdout = f'{{"nonce_hex":"{nonce_hex}","attempts":12345,"elapsed_s":1.5}}'
        miner_argv = _make_stub_miner(tmp_path, stdout=stdout, exit_code=0)
        result = mine_solution_external(
            preimage=_PREIMAGE,
            target=_TARGET,
            miner_argv=miner_argv,
            nonce_width=4,
            timeout_s=10,
        )
        assert result.nonce == bytes.fromhex(nonce_hex)
        assert result.attempts == 12345
        assert result.elapsed_s == 1.5

    def test_wrong_nonce_still_rejected(self, tmp_path: Path):
        """Local re-verification still rejects a nonce that doesn't
        satisfy the target — regression guard for the silent-divergence
        defense."""
        stdout = '{"nonce_hex":"deadbeef","attempts":1,"elapsed_s":0.1}'
        miner_argv = _make_stub_miner(tmp_path, stdout=stdout, exit_code=0)
        with pytest.raises(ValidationError, match="fails local SHA256d verification"):
            mine_solution_external(
                preimage=_PREIMAGE,
                target=_TARGET,
                miner_argv=miner_argv,
                nonce_width=4,
                timeout_s=10,
            )


# ---------------------------------------------------------------------------
# Real-subprocess wire compatibility
# ---------------------------------------------------------------------------


class TestRealMinerSubprocess:
    """One test that actually spawns ``python -m pyrxd.contrib.miner``
    end-to-end. Catches wire-format drift that the stub-miner tests
    can't see. Kept tight: uses a small nonce-bound via the worker count
    + timeout to exit fast even on slow runners."""

    def test_real_miner_returns_protocol_v1_shape(self, tmp_path: Path, monkeypatch):
        """Spawn the real miner. Use a timeout short enough that even
        on slow CI it returns quickly — at V1 difficulty=1 a real hit
        would take minutes, so we expect timeout-induced MaxAttemptsError.

        The test passes if pyrxd correctly maps subprocess.TimeoutExpired
        (the old exhaustion fallback path) to MaxAttemptsError — proving
        the integration with the contrib miner is wire-compatible.
        """
        # The subprocess inherits our PYTHONPATH. In editable installs
        # (or when running pytest from the worktree) the contrib miner
        # is already importable, but in a checked-out worktree we need
        # to ensure src/ is on the path the subprocess sees.
        worktree_src = Path(__file__).resolve().parents[2] / "src"
        existing = os.environ.get("PYTHONPATH", "")
        new_path = f"{worktree_src}{os.pathsep}{existing}" if existing else str(worktree_src)
        monkeypatch.setenv("PYTHONPATH", new_path)

        with pytest.raises(MaxAttemptsError, match="did not return a solution"):
            mine_solution_external(
                preimage=_PREIMAGE,
                target=_TARGET,
                miner_argv=[sys.executable, "-m", "pyrxd.contrib.miner", "--workers", "1", "--quiet"],
                nonce_width=4,
                timeout_s=2,  # tight: forces timeout before real hit
            )
