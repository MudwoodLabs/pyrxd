"""``tests/_dmint_miner.py``: the one place the node-backed dMint suites get their miner from.

The nightly job sets ``DMINT_MINER_CMD`` to the native grinder; everywhere else it is unset and
the suites grind with the bundled Python miner, exactly as before. Both halves are exercised here
through the call the suites make — ``mine_solution_dispatch(..., miner_argv=dmint_miner_argv())``
over the whole nonce space, no test-only flags — against real difficulty-1 solutions that sit
low enough in the nonce space for either miner to reach in about a second.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from _dmint_miner import dmint_mine_timeout_s, dmint_miner_argv, dmint_miner_label

from pyrxd.glyph.dmint import MAX_SHA256D_TARGET, mine_solution_dispatch, verify_sha256d_solution

# The only nonces in [0, 2**22) whose digest has four zero bytes, for each preimage — checked
# exhaustively with hashlib when these were found (2026-09-23) — and each a real solution at the
# difficulty-1 target. A miner sweeping from 0 therefore has exactly one right answer.
_LOW = {
    4: (
        "5c44c82ec713f362d254ecae0cd2d0d3658eff127aa3ce6ef48a2448c493312f"
        "a5e18198ed89e6dd2421ba203b6af3f2e05d9a75fbaa50358f38de198e9e2b9a",
        1_789_294,
    ),
    8: (
        "8c92802933e6297b8e38b86bb05e772b6298c92a0c038229747fd84c42a17e72"
        "3cd2bbc043b69d0fd7564d805dd9f48e69b19b26c58c63582a077b0f4e4f0c8f",
        1_229_941,
    ),
}
_BUNDLED = [sys.executable, "-m", "pyrxd.contrib.miner"]


@pytest.fixture
def clean_env(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    for name in ("DMINT_MINER_CMD", "DMINT_MINE_WORKERS", "DMINT_MINE_TIMEOUT_S"):
        monkeypatch.delenv(name, raising=False)
    # The bundled miner is started as `python -m pyrxd.contrib.miner`: make sure the child
    # imports this checkout's pyrxd, as tests/contrib/test_miner_external_integration.py does.
    src = str(Path(__file__).resolve().parents[2] / "src")
    existing = os.environ.get("PYTHONPATH", "")
    monkeypatch.setenv("PYTHONPATH", f"{src}{os.pathsep}{existing}" if existing else src)
    return monkeypatch


def test_unset_is_the_bundled_python_miner_the_suites_always_used(clean_env: pytest.MonkeyPatch) -> None:
    argv = dmint_miner_argv()
    assert argv == _BUNDLED  # the literal argv all three suites hard-coded before this helper
    assert dmint_miner_label(argv) == "bundled Python miner"
    assert dmint_mine_timeout_s(1800) == 1800.0


def test_workers_and_timeout_come_from_the_environment(clean_env: pytest.MonkeyPatch, grinder: str) -> None:
    clean_env.setenv("DMINT_MINE_WORKERS", "3")
    clean_env.setenv("DMINT_MINE_TIMEOUT_S", "90")
    assert dmint_miner_argv() == [*_BUNDLED, "--workers", "3"]
    clean_env.setenv("DMINT_MINER_CMD", grinder)
    assert dmint_miner_argv() == [grinder, "--workers", "3"]
    assert dmint_miner_label(dmint_miner_argv()) == "sha256d-grind"
    assert dmint_mine_timeout_s(1800) == 90.0


def test_a_miner_command_that_cannot_run_is_an_error_not_a_fallback(
    clean_env: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    clean_env.setenv("DMINT_MINER_CMD", str(tmp_path / "no-such-grinder"))
    with pytest.raises(RuntimeError, match="Unset DMINT_MINER_CMD"):
        dmint_miner_argv()
    not_executable = tmp_path / "grinder.txt"
    not_executable.write_text("")
    clean_env.setenv("DMINT_MINER_CMD", str(not_executable))
    with pytest.raises(RuntimeError, match="not an executable file"):
        dmint_miner_argv()


@pytest.mark.parametrize("width", [4, 8])
@pytest.mark.parametrize("choice", ["fallback", "native"])
def test_either_choice_mines_a_real_solution_through_the_suites_call(
    clean_env: pytest.MonkeyPatch, grinder: str, choice: str, width: int
) -> None:
    preimage_hex, nonce_int = _LOW[width]
    preimage = bytes.fromhex(preimage_hex)
    want = nonce_int.to_bytes(width, "little")
    assert verify_sha256d_solution(preimage, want, MAX_SHA256D_TARGET, nonce_width=width)

    clean_env.setenv("DMINT_MINE_WORKERS", "2")
    if choice == "native":
        clean_env.setenv("DMINT_MINER_CMD", grinder)
    argv = dmint_miner_argv()
    assert (argv[0] == grinder) is (choice == "native")

    result = mine_solution_dispatch(
        preimage, target=MAX_SHA256D_TARGET, nonce_width=width, miner_argv=argv, timeout_s=120
    )
    assert result.nonce == want
