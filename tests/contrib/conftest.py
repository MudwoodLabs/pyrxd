"""Fixtures shared by the contrib-miner tests."""

from __future__ import annotations

import os

import pytest

from pyrxd.contrib.miner.native import build, find_compiler


@pytest.fixture(scope="session")
def grinder(tmp_path_factory: pytest.TempPathFactory) -> str:
    """The native grinder, built once per session from the shipped C source by the shipped build
    helper (which refuses a binary that fails its SHA-256 self-test).

    Skips on a machine with no C compiler, but FAILS in CI (the ``CI`` variable GitHub Actions
    sets), so a runner that lost its compiler cannot turn these tests into silent skips.
    """
    if find_compiler() is None:
        if os.environ.get("CI"):
            pytest.fail("no C compiler on a CI runner: the native grinder's tests must run in CI, not skip")
        pytest.skip("no C compiler found (cc/gcc/clang): the native grinder's tests need one")
    return str(build(tmp_path_factory.mktemp("native-grinder") / "sha256d-grind"))
