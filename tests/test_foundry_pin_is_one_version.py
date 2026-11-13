"""Every workflow step that installs Foundry installs the same anvil, by an exact version.

The per-PR anvil step in ``regtest-core`` and the nightly ``nightly-cross-chain`` step each pin
``foundry-rs/foundry-toolchain``'s ``version``. An unpinned or ``stable`` version let anvil float
once and the ERC-20 lifecycle step failed every night until #840. With two pins, one could be
bumped and not the other, and the per-PR lane would then prove something about a different anvil
than the nightly one. The set of steps is read from the workflow files, not typed here.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

_WORKFLOW_DIR = Path(__file__).resolve().parent.parent / ".github" / "workflows"
_ACTION = "foundry-rs/foundry-toolchain@"


def _foundry_steps() -> list[tuple[str, str, dict]]:
    found = []
    for path in sorted([*_WORKFLOW_DIR.glob("*.yml"), *_WORKFLOW_DIR.glob("*.yaml")]):
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for job_id, job in (doc.get("jobs") or {}).items():
            for step in job.get("steps") or []:
                if str(step.get("uses", "")).startswith(_ACTION):
                    found.append((f"{path.name}:{job_id}", step["uses"], step.get("with") or {}))
    return found


def test_foundry_is_installed_by_more_than_one_job() -> None:
    """Non-vacuity: the per-PR job and the nightly job both install it."""
    jobs = {where for where, _uses, _with in _foundry_steps()}
    assert {"integration.yml:regtest-core", "integration.yml:nightly-cross-chain"} <= jobs, jobs


def test_every_foundry_install_pins_one_exact_anvil_version() -> None:
    steps = _foundry_steps()
    versions = {where: str(w.get("version", "")) for where, _uses, w in steps}
    for where, version in versions.items():
        assert re.fullmatch(r"v\d+\.\d+\.\d+", version), f"{where}: version {version!r} is not an exact release"
    assert len(set(versions.values())) == 1, versions


def test_every_foundry_install_uses_the_same_hash_pinned_installer() -> None:
    uses = {where: u for where, u, _w in _foundry_steps()}
    for where, u in uses.items():
        assert re.fullmatch(re.escape(_ACTION) + r"[0-9a-f]{40}", u), f"{where}: {u!r} is not pinned by commit"
    assert len(set(uses.values())) == 1, uses
