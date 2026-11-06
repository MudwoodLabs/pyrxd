"""The starter project's own test passes on a real regtest node, and fails when it should.

``pyrxd new`` promises a project whose ``pytest`` passes before the developer writes
anything. This module renders that project, runs its test suite in a separate pytest
process (so it loads ``pyrxd.testing.pytest_plugin`` exactly as a user's project does) and
reads the verdict. The second test plants a wrong ``mint.py`` that mints the NFT to some
other key and requires the generated test to FAIL, so the template's test is shown to check
ownership on chain rather than only to run.

Each run starts its own ``pyrxd-test-<random>`` container through the fixtures and removes
it at the end, so it never collides with another module's node.

Needs docker and the image from ``pyrxd regtest setup``. Opt-in with ``RADIANT_REGTEST=1``;
runs in ``.github/workflows/integration.yml`` (``regtest-core``) and ``task test-regtest``.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from pyrxd.devnet import RegtestNode
from pyrxd.starter import package_name_for, render_project, write_project

pytestmark = pytest.mark.integration

_PROJECT = "starter-e2e"

# The planted defect: the same mint, but the NFT goes to a key the test's wallet does not
# hold. Everything else (fees, funding, confirmation) is honest, so only the ownership
# assertion can catch it.
_WRONG_OWNER_MINT = """\
from __future__ import annotations

from pathlib import Path
from typing import Any

from pyrxd.glyph import GlyphMetadata, GlyphProtocol
from pyrxd.glyph.mint import GlyphMinter, JsonFilePendingStore, MintResult
from pyrxd.keys import PrivateKey


async def mint_nft(client: Any, wallet: Any, pending_dir: Path, *, name: str, description: str = "") -> MintResult:
    minter = GlyphMinter(client, wallet, JsonFilePendingStore(pending_dir))
    metadata = GlyphMetadata(protocol=[GlyphProtocol.NFT], name=name, description=description)
    stranger = PrivateKey().public_key().hash160()
    return await minter.mint_nft(metadata, owner_pkh=stranger)
"""


@pytest.fixture(scope="module")
def runnable() -> None:
    if not os.environ.get("RADIANT_REGTEST"):
        pytest.skip("RADIANT_REGTEST not set (opt-in for the live regtest e2e)")
    if shutil.which("docker") is None:
        pytest.skip("docker not available")
    if subprocess.run(["docker", "image", "inspect", RegtestNode.IMAGE], capture_output=True).returncode != 0:
        pytest.skip(f"{RegtestNode.IMAGE} image not available")


def _run_generated_suite(project: Path) -> subprocess.CompletedProcess[str]:
    # The console-script pytest that sits beside this interpreter, not `python -m pytest`,
    # which would put the project root on sys.path where a user's run would not.
    pytest_bin = Path(sys.executable).with_name("pytest")
    env = {k: v for k, v in os.environ.items() if k not in ("PYTEST_ADDOPTS", "PYTEST_XDIST_WORKER")}
    return subprocess.run(
        [str(pytest_bin), "-q", "-p", "no:cacheprovider", "-rA"],
        cwd=project,
        env=env,
        capture_output=True,
        text=True,
        timeout=600,
    )


def _outcome(proc: subprocess.CompletedProcess[str]) -> dict[str, int]:
    tail = proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else ""
    return {kind: int(n) for n, kind in re.findall(r"(\d+) (passed|failed|error|errors|skipped)", tail)}


def test_generated_project_test_passes_on_a_real_node(runnable, tmp_path):
    project = write_project(_PROJECT, tmp_path / _PROJECT)
    proc = _run_generated_suite(project)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert _outcome(proc) == {"passed": 1}, proc.stdout


def test_generated_project_test_fails_when_the_nft_goes_to_someone_else(runnable, tmp_path):
    mint_path = f"src/{package_name_for(_PROJECT)}/mint.py"
    assert mint_path in render_project(_PROJECT)  # the override replaces the real file
    project = write_project(_PROJECT, tmp_path / _PROJECT, overrides={mint_path: _WRONG_OWNER_MINT})
    proc = _run_generated_suite(project)
    assert _outcome(proc) == {"failed": 1}, proc.stdout + proc.stderr
    assert "76a914" in proc.stdout and "endswith" in proc.stdout, proc.stdout  # failed on the owner check
