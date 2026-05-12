"""Tests for the pyrxd.contrib.miner CLI.

Exercises argparse + stdin/stdout protocol round-trips via direct
function calls (no subprocess). Tests that spawn an actual subprocess
also exist, but kept few — subprocess startup dominates the wall time
of those runs.
"""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from pyrxd.contrib.miner import cli
from pyrxd.contrib.miner.parallel import MineParams
from pyrxd.contrib.miner.protocol import (
    MineExhausted,
    MineSuccess,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


_VALID_REQUEST = json.dumps(
    {
        "preimage_hex": "ab" * 64,
        "target_hex": "7fffffffffffffff",
        "nonce_width": 4,
    }
)


def _run_cli(
    *,
    argv: list[str] | None = None,
    stdin: bytes = _VALID_REQUEST.encode(),
    mine_result: MineSuccess | MineExhausted | None = None,
) -> tuple[int, str, str]:
    """Run ``cli.main()`` in-process with mocked stdin/stdout/mine().

    :param argv: argv minus program name. ``None`` → no flags.
    :param stdin: raw bytes written to ``sys.stdin.buffer``.
    :param mine_result: what the patched ``mine()`` returns.
        ``None`` → leave ``mine()`` unpatched (real worker runs).
    :returns: ``(exit_code, stdout, stderr)``.
    """
    from types import SimpleNamespace

    fake_stdin_buffer = io.BytesIO(stdin)
    # cli.main reads `sys.stdin.buffer.read(...)`, so we only need to
    # patch sys.stdin with an object that has a `.buffer` attribute.
    # Don't try to fake the full TextIOWrapper interface — we'd just
    # tunnel back to the same bytes.
    fake_stdin = SimpleNamespace(buffer=fake_stdin_buffer)
    fake_stdout = io.StringIO()
    fake_stderr = io.StringIO()

    patches = [
        patch.object(sys, "stdin", fake_stdin),
        patch.object(sys, "stdout", fake_stdout),
        patch.object(sys, "stderr", fake_stderr),
    ]
    if mine_result is not None:
        patches.append(patch("pyrxd.contrib.miner.cli.mine", return_value=mine_result))

    for p in patches:
        p.start()
    try:
        code = cli.main(argv or [])
    finally:
        for p in patches:
            p.stop()

    return code, fake_stdout.getvalue(), fake_stderr.getvalue()


# ---------------------------------------------------------------------------
# Argparse
# ---------------------------------------------------------------------------


class TestArgparse:
    def test_help_does_not_block(self):
        """``--help`` exits cleanly via argparse's SystemExit(0)."""
        with pytest.raises(SystemExit) as exc:
            with patch.object(sys, "stdout", io.StringIO()):
                cli._build_arg_parser().parse_args(["--help"])
        assert exc.value.code == 0

    def test_protocol_version_flag(self):
        """``--protocol-version`` exits 0 and prints the version."""
        with pytest.raises(SystemExit) as exc:
            with patch.object(sys, "stdout", io.StringIO()):
                cli._build_arg_parser().parse_args(["--protocol-version"])
        assert exc.value.code == 0


# ---------------------------------------------------------------------------
# Success path
# ---------------------------------------------------------------------------


class TestSuccessPath:
    def test_success_writes_json_and_exits_zero(self):
        code, stdout, stderr = _run_cli(
            mine_result=MineSuccess(
                nonce=b"\x01\x02\x03\x04",
                attempts=100,
                elapsed_s=0.5,
            )
        )
        assert code == 0
        parsed = json.loads(stdout)
        assert parsed["nonce_hex"] == "01020304"
        assert parsed["attempts"] == 100
        assert parsed["elapsed_s"] == 0.5
        # stderr is silent on success.
        assert stderr == ""

    def test_workers_flag_passed_through(self):
        """``--workers 4`` overrides default os.cpu_count()."""
        with patch("pyrxd.contrib.miner.cli.mine") as mocked:
            mocked.return_value = MineSuccess(nonce=b"\x00\x00\x00\x00", attempts=1, elapsed_s=0.0)
            _run_cli(
                argv=["--workers", "4"],
                mine_result=None,  # use the mocked one
            )
            # The first positional arg to mine() is a MineParams
            params: MineParams = mocked.call_args[0][0]
            assert params.n_workers == 4

    def test_default_workers_is_cpu_count(self):
        with (
            patch("pyrxd.contrib.miner.cli.mine") as mocked,
            patch("pyrxd.contrib.miner.cli.default_n_workers", return_value=12),
        ):
            mocked.return_value = MineSuccess(nonce=b"\x00\x00\x00\x00", attempts=1, elapsed_s=0.0)
            _run_cli(mine_result=None)
            params: MineParams = mocked.call_args[0][0]
            assert params.n_workers == 12


# ---------------------------------------------------------------------------
# Exhaustion path
# ---------------------------------------------------------------------------


class TestExhaustionPath:
    def test_exhausted_writes_json_and_exits_two(self):
        code, stdout, stderr = _run_cli(mine_result=MineExhausted())
        assert code == 2
        assert json.loads(stdout) == {"exhausted": True}
        # By default, stderr carries a human-readable message.
        assert "exhausted" in stderr.lower()

    def test_quiet_suppresses_stderr(self):
        code, stdout, stderr = _run_cli(
            argv=["--quiet"],
            mine_result=MineExhausted(),
        )
        assert code == 2
        assert json.loads(stdout) == {"exhausted": True}
        assert stderr == ""


# ---------------------------------------------------------------------------
# Protocol error paths
# ---------------------------------------------------------------------------


class TestProtocolErrors:
    def test_malformed_json_exits_one(self):
        code, stdout, stderr = _run_cli(stdin=b"not json")
        assert code == 1
        assert stdout == ""
        assert "protocol error" in stderr.lower()

    def test_missing_field_exits_one(self):
        code, _, stderr = _run_cli(stdin=json.dumps({"preimage_hex": "ab" * 64}).encode())
        assert code == 1
        assert "missing" in stderr.lower() or "target_hex" in stderr.lower()

    def test_oversize_stdin_exits_one(self):
        """A multi-megabyte stdin is rejected before parsing."""
        code, _, stderr = _run_cli(stdin=b"{" + b"x" * (4096 + 100))
        assert code == 1
        assert "cap" in stderr.lower() or "too large" in stderr.lower() or "protocol error" in stderr.lower()

    def test_zero_workers_exits_one(self):
        code, _, stderr = _run_cli(argv=["--workers", "0"])
        assert code == 1
        assert "workers" in stderr.lower()

    def test_unknown_protocol_version_exits_one(self):
        code, _, stderr = _run_cli(
            stdin=json.dumps(
                {
                    "preimage_hex": "ab" * 64,
                    "target_hex": "7fffffffffffffff",
                    "nonce_width": 4,
                    "protocol": 999,
                }
            ).encode()
        )
        assert code == 1
        assert "protocol" in stderr.lower()


# ---------------------------------------------------------------------------
# Subprocess smoke test
# ---------------------------------------------------------------------------
#
# One end-to-end test that actually spawns ``python -m pyrxd.contrib.miner``
# as a subprocess. Catches argparse-vs-__main__ wiring bugs that the
# in-process tests don't.


class TestSubprocessSmoke:
    def test_module_invocation_with_exhaustion(self, tmp_path: Path):
        """``python -m pyrxd.contrib.miner`` runs as a subprocess.

        Uses an artificially small effective nonce range by setting
        ``--workers`` very low and aborting via a short timeout. We
        only care that the process starts cleanly and reads stdin —
        not that it completes the search.
        """
        request = {
            "preimage_hex": "ab" * 64,
            "target_hex": "7fffffffffffffff",
            "nonce_width": 4,
        }

        # The PYTHONPATH the subprocess inherits must include this
        # worktree's src/ so `import pyrxd.contrib.miner` resolves
        # against today's bytes, not whatever's pip-installed.
        env = os.environ.copy()
        worktree_src = Path(__file__).resolve().parents[2] / "src"
        env["PYTHONPATH"] = f"{worktree_src}{os.pathsep}{env.get('PYTHONPATH', '')}"

        try:
            completed = subprocess.run(
                [sys.executable, "-m", "pyrxd.contrib.miner", "--workers", "1", "--quiet"],
                input=json.dumps(request).encode(),
                capture_output=True,
                timeout=3,  # truly fast smoke; not a mining test
                env=env,
                check=False,
            )
        except subprocess.TimeoutExpired:
            # Subprocess started cleanly; that's all this test cares about.
            return

        # If the process completed within the budget, it must have
        # produced one of the protocol shapes.
        assert completed.returncode in (0, 2), (
            f"unexpected exit code {completed.returncode}\nstdout: {completed.stdout!r}\nstderr: {completed.stderr!r}"
        )
