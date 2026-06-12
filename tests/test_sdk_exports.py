"""Guards the top-level ``pyrxd`` SDK surface for the cross-chain swap primitive.

The Tier-2 packaging goal (docs/ROADMAP.md): the proven HTLC cross-chain swap is
embeddable from a clean top-level import. These tests pin that the names resolve via
the PEP 562 lazy ``__getattr__`` and that the headline import doesn't eagerly pull the
optional ``web3`` dependency (the same import-graph discipline the package docstring
documents for the browser inspect tool).
"""

from __future__ import annotations

import subprocess
import sys

import pytest

_CROSS_CHAIN_EXPORTS = [
    "SwapCoordinator",
    "CoordinatorConfig",
    "MarginPolicy",
    "generate_secret",
    "NegotiatedTerms",
    "SwapRecord",
    "SwapState",
    "CounterChainLeg",
    "RadiantCovenantLeg",
    "EthLeg",
]


@pytest.mark.parametrize("name", _CROSS_CHAIN_EXPORTS)
def test_cross_chain_primitive_is_importable_from_top_level(name):
    import pyrxd

    assert name in pyrxd.__all__, f"{name} missing from pyrxd.__all__"
    assert getattr(pyrxd, name) is not None


def test_importing_pyrxd_does_not_eagerly_load_web3():
    # `import pyrxd` must stay light: web3 is an optional dep and only the ETH leg needs
    # it. Lazy exports must not drag it in at package-import time. Checked in a clean
    # subprocess so we never mutate this interpreter's sys.modules (popping web3 here
    # would contaminate other suites that mock it).
    code = "import sys; import pyrxd; sys.exit(1 if 'web3' in sys.modules else 0)"
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert result.returncode == 0, f"importing pyrxd eagerly loaded web3 (should be lazy)\n{result.stderr}"
