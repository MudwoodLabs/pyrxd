"""The declared extras must match what the code actually imports.

Regression tests for #476. Five runtime errors instructed users to "install the eth extra"
while ``pyproject.toml`` had no ``[project.optional-dependencies]`` section at all, so
``pip install 'pyrxd[eth]'`` warned "does not provide the extra 'eth'", installed nothing, and
the subsequent import failed telling the user to do the thing that had just no-opped.

These are source/metadata assertions rather than install tests on purpose: the defect is a
MISSING DECLARATION, so what needs pinning is that the declaration cannot drift away from the
imports again. A real clean-venv install is the manual verification recorded in the PR.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import tomllib

_ROOT = Path(__file__).resolve().parent.parent
_PYPROJECT = _ROOT / "pyproject.toml"
_ETH_DIR = _ROOT / "src" / "pyrxd" / "eth_wallet"

#: Distribution names for the packages the eth modules import directly. ``eth_abi`` is NOT here:
#: nothing under ``eth_wallet/`` imports it today (web3 uses it internally, which is web3's
#: business, not ours).
_IMPORT_TO_DIST = {"web3": "web3", "eth_account": "eth-account", "eth_keys": "eth-keys"}


def _extras() -> dict[str, list[str]]:
    with _PYPROJECT.open("rb") as f:
        return tomllib.load(f)["project"].get("optional-dependencies", {})


def _dist_names(reqs: list[str]) -> set[str]:
    return {re.split(r"[<>=!~\[ ]", r, maxsplit=1)[0].strip().lower() for r in reqs}


def test_the_eth_extra_exists() -> None:
    """The whole bug in one assertion: the errors advertised an extra that was never declared."""
    assert "eth" in _extras(), (
        "no 'eth' extra declared, yet eth_wallet tells users to run pip install 'pyrxd[eth]' — "
        "that command would warn 'does not provide the extra' and install nothing"
    )


def test_every_directly_imported_eth_package_is_declared() -> None:
    """Transitive availability is not a declaration.

    ``eth_keys`` is the live example: web3 7.16.0 declares ``eth-account>=0.13.6`` but NOT
    ``eth-keys``, which arrives via eth-account. ``keys.py`` imports it directly, so before #476
    that import rested on two levels of transitive luck and no version constraint anywhere.
    """
    declared = _dist_names(_extras()["eth"])
    source = "\n".join(p.read_text() for p in _ETH_DIR.glob("*.py"))

    for module, dist in _IMPORT_TO_DIST.items():
        if re.search(rf"^\s*(?:from|import)\s+{module}\b", source, re.M):
            assert dist in declared, (
                f"eth_wallet imports {module} directly but {dist} is not in the eth extra; "
                "relying on it arriving transitively is how eth-keys was undeclared"
            )


def test_the_extra_does_not_claim_runtime_dependencies() -> None:
    """aiohttp is a required runtime dep, so pointing at the extra for it was bad advice —
    following it would leave the user exactly where they started."""
    with _PYPROJECT.open("rb") as f:
        data = tomllib.load(f)
    runtime = _dist_names(data["project"]["dependencies"])
    overlap = _dist_names(_extras()["eth"]) & runtime
    assert not overlap, f"the eth extra re-declares runtime dependencies: {sorted(overlap)}"


@pytest.mark.parametrize("path", sorted(p.name for p in _ETH_DIR.glob("*.py")))
def test_no_module_advertises_the_extra_for_a_runtime_dependency(path: str) -> None:
    """``private_submit.py`` told users to install the extra when aiohttp was missing. aiohttp is
    a runtime dependency (`pyproject.toml`), so the extra could never supply it."""
    source = (_ETH_DIR / path).read_text()
    for line in source.splitlines():
        if "pyrxd[eth]" in line and "aiohttp" in line:
            pytest.fail(f"{path}: points at the eth extra for aiohttp, a runtime dependency: {line.strip()}")
