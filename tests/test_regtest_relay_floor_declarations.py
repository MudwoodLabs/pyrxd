"""Every regtest node the test tree starts must declare its relay floor, and the
set that declares a floor BELOW mainnet's must be exactly the set the docs name.

This guard exists because the docs and the code disagreed. ``CHANGELOG.md`` named
three suites deliberately held at the legacy 0.01 RXD/kB floor while
``CONTRIBUTING.md`` said one of them "is the one place that does" — and the code
was the one telling the truth. A contributor reading CONTRIBUTING would have
concluded that two live suites were running below the floor by accident.

The rule the tree actually follows: a default ``radiantd -regtest`` advertises
0.01 RXD/kB, a TENTH of mainnet, while every pyrxd builder sizes fees at the
mainnet rate — so on a default node a transaction one or two bytes short of its
own rate is accepted anyway and the node cannot contradict the builder. That is
how ``build_nft_transfer_tx`` shipped under-fee'ing ~25% of NFT transfers for four
releases with green regtest suites. So no node may INHERIT a floor: each declares
one explicitly, and the few that declare a lower one are enumerated here.

Adding a suite that starts a node below the mainnet floor is a deliberate act.
This test makes it one: the new module has to be added to ``SUB_FLOOR_MODULES``
below AND named in CONTRIBUTING.md, with the reason written down.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
TESTS = REPO_ROOT / "tests"

#: Radiant MAINNET's relay floor in RXD/kB — the rate every pyrxd builder sizes to.
MAINNET_FLOOR_RXD_PER_KB = 0.10

#: The ONLY test modules allowed to start a Radiant node below the mainnet floor.
#: Each proves orderbook / covenant / cross-chain-sequencing *semantics*, and each
#: has carriers sized around its own fee constants (one asserts an on-chain
#: remainder against ``8_000_000 - _FEE``). Their builders' fee floors are proved
#: at the MAINNET floor in ``test_fee_floor_boundary_regtest_e2e.py`` and
#: ``test_remaining_builder_floors_regtest_e2e.py``, so nothing is left unproven.
SUB_FLOOR_MODULES = frozenset(
    {
        "test_rswp_regtest_e2e.py",
        "test_xchain_swap_regtest_e2e.py",
        "test_xchain_eth_swap_regtest_e2e.py",
    }
)


def _module_string_constants(tree: ast.Module) -> dict[str, str]:
    """Module-level ``NAME = "literal"`` assignments."""
    out: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name):
                    out[tgt.id] = node.value.value
        elif (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            out[node.target.id] = node.value.value
    return out


def _parsed() -> dict[str, tuple[ast.Module, dict[str, str]]]:
    parsed: dict[str, tuple[ast.Module, dict[str, str]]] = {}
    for path in sorted(TESTS.glob("*.py")):
        tree = ast.parse(path.read_text(), filename=str(path))
        parsed[path.name] = (tree, _module_string_constants(tree))
    return parsed


def _declared_floors(name: str, tree: ast.Module, local: dict[str, str], shared: dict[str, str]) -> list[float]:
    """Every relay floor (RXD/kB) this module starts a node at, as a float.

    Handles the two spellings the tree uses: the ``-minrelaytxfee={CONST}``
    f-string passed to ``docker run``, and the ``min_relay_rxd_per_kb=`` keyword
    on the shared ``_RegtestNode`` fixture. A name is resolved against the
    module's own constants first, then against every other test module's (the
    ETH suite imports its floor from the BTC one).
    """
    floors: list[float] = []

    def resolve(node: ast.expr) -> str | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.Name):
            return local.get(node.id, shared.get(node.id))
        return None

    for node in ast.walk(tree):
        # `f"-minrelaytxfee={RATE}"`
        if isinstance(node, ast.JoinedStr):
            parts = node.values
            for i, part in enumerate(parts):
                if not (isinstance(part, ast.Constant) and isinstance(part.value, str)):
                    continue
                if not part.value.endswith("-minrelaytxfee="):
                    continue
                if i + 1 >= len(parts) or not isinstance(parts[i + 1], ast.FormattedValue):
                    continue
                val = resolve(parts[i + 1].value)  # type: ignore[attr-defined]
                if val is not None:
                    floors.append(float(val))
        # `min_relay_rxd_per_kb="0.01"` on the shared fixture
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg == "min_relay_rxd_per_kb":
                    val = resolve(kw.value)
                    if val is not None:
                        floors.append(float(val))
    return floors


def test_only_the_documented_suites_run_below_the_mainnet_floor() -> None:
    parsed = _parsed()
    shared = {k: v for _, consts in parsed.values() for k, v in consts.items()}

    sub_floor: dict[str, list[float]] = {}
    for name, (tree, local) in parsed.items():
        floors = _declared_floors(name, tree, local, shared)
        below = [f for f in floors if f < MAINNET_FLOOR_RXD_PER_KB]
        if below:
            sub_floor[name] = below

    assert set(sub_floor) == set(SUB_FLOOR_MODULES), (
        "the set of suites starting a node BELOW mainnet's relay floor has changed.\n"
        f"  found:    {sorted(sub_floor)}\n"
        f"  expected: {sorted(SUB_FLOOR_MODULES)}\n"
        "A node below the floor cannot contradict a builder that under-fees, which is how "
        "build_nft_transfer_tx shipped broken for four releases. If this is deliberate, add the "
        "module to SUB_FLOOR_MODULES here AND name it in CONTRIBUTING.md with the reason."
    )


@pytest.mark.parametrize("module", sorted(SUB_FLOOR_MODULES))
def test_contributing_names_every_sub_floor_suite(module: str) -> None:
    """CONTRIBUTING.md must name each one — it used to claim there was only one."""
    text = (REPO_ROOT / "CONTRIBUTING.md").read_text()
    assert module in text, (
        f"CONTRIBUTING.md does not mention {module}, which starts a node below the mainnet "
        "relay floor. A contributor reading it would take that suite's lower floor for an accident."
    )


def test_contributing_does_not_claim_a_single_sub_floor_suite() -> None:
    """The specific wrong sentence, pinned so it cannot come back."""
    text = (REPO_ROOT / "CONTRIBUTING.md").read_text()
    assert "is the one place that does" not in text, (
        "CONTRIBUTING.md claims one suite is 'the one place' that lowers the relay floor. "
        f"There are {len(SUB_FLOOR_MODULES)}: {sorted(SUB_FLOOR_MODULES)}."
    )
