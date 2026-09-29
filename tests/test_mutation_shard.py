"""`scripts/mutation_shard.py` must split a module's mutants into shards that cover it exactly once.

A shard that dropped mutants would report a module as scored while part of it never ran; two
shards that overlapped would double-count. Neither shows up in a kill rate. So this runs the real
`cosmic-ray init` on a real module and checks the shards against the session it wrote, then
checks that `cr-report` — which is what `scripts/mutation_test.sh` reads its counts from —
reports the shard's size as the total, so no mutant outside the shard is counted as a kill.
"""

from __future__ import annotations

import os
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "scripts"))
from mutation_shard import shard

_MODULE = "src/pyrxd/compactsize.py"


def _tool(name: str) -> str:
    path = shutil.which(name, path=f"{Path(sys.executable).parent}{os.pathsep}{os.environ.get('PATH', '')}")
    assert path, f"{name} not found; it is in the dev dependency group (poetry install)"
    return path


@pytest.fixture(scope="module")
def fresh_session(tmp_path_factory: pytest.TempPathFactory) -> Path:
    d = tmp_path_factory.mktemp("cr")
    cfg = d / "cr.toml"
    cfg.write_text(
        f'[cosmic-ray]\nmodule-path = "{_MODULE}"\ntimeout = 10\nexcluded-modules = []\n'
        'test-command = "true"\n\n[cosmic-ray.distributor]\nname = "local"\n'
    )
    sess = d / "full.sqlite"
    subprocess.run([_tool("cosmic-ray"), "init", str(cfg), str(sess)], cwd=_ROOT, check=True, capture_output=True)
    return sess


def _specs(sess: Path) -> set[tuple[str, int]]:
    con = sqlite3.connect(sess)
    try:
        return set(con.execute("SELECT operator_name, occurrence FROM mutation_specs"))
    finally:
        con.close()


def test_the_shards_partition_the_module(fresh_session: Path, tmp_path: Path) -> None:
    full = _specs(fresh_session)
    assert len(full) > 50, f"only {len(full)} mutants in {_MODULE}; pick a bigger module for this test"
    parts = []
    for k in range(1, 4):
        s = tmp_path / f"s{k}.sqlite"
        shutil.copy(fresh_session, s)
        kept, total = shard(str(s), k, 3)
        assert total == len(full)
        parts.append(_specs(s))
        assert kept == len(parts[-1])
    assert set().union(*parts) == full, "a mutant is in no shard, so it would never run"
    assert sum(map(len, parts)) == len(full), "a mutant is in two shards, so it would be scored twice"
    sizes = sorted(map(len, parts))
    assert sizes[-1] - sizes[0] <= 1, f"unbalanced shards: {sizes}"


def test_cr_report_counts_only_the_shard(fresh_session: Path, tmp_path: Path) -> None:
    """The production reader. `mutation_test.sh` greps `total jobs:` out of `cr-report`."""
    s = tmp_path / "s.sqlite"
    shutil.copy(fresh_session, s)
    kept, total = shard(str(s), 2, 4)
    out = subprocess.run([_tool("cr-report"), str(s)], capture_output=True, text=True, check=True).stdout
    assert f"total jobs: {kept}" in out, out[-300:]
    assert kept < total


def test_a_session_with_results_is_refused(fresh_session: Path, tmp_path: Path) -> None:
    """Sharding after mutants ran would delete their results; the resume path must never do it."""
    s = tmp_path / "s.sqlite"
    shutil.copy(fresh_session, s)
    con = sqlite3.connect(s)
    job = con.execute("SELECT job_id FROM work_items LIMIT 1").fetchone()[0]
    con.execute(
        "INSERT INTO work_results (worker_outcome, output, test_outcome, diff, job_id) VALUES (?, ?, ?, ?, ?)",
        ("normal", "", "survived", "", job),
    )
    con.commit()
    con.close()
    before = _specs(s)
    with pytest.raises(ValueError, match="already has 1 results"):
        shard(str(s), 1, 2)
    assert _specs(s) == before


@pytest.mark.parametrize(("index", "count"), [(0, 3), (4, 3), (1, 1)])
def test_an_index_outside_the_shards_is_refused(fresh_session: Path, tmp_path: Path, index: int, count: int) -> None:
    s = tmp_path / "s.sqlite"
    shutil.copy(fresh_session, s)
    with pytest.raises(ValueError, match="is not a shard"):
        shard(str(s), index, count)
    assert _specs(s) == _specs(fresh_session)


def test_the_script_refuses_a_shard_for_a_group_that_is_not_sharded() -> None:
    """Ignoring MUTATION_SHARD would run the whole group under a job named for one slice. The
    refusal happens before any baseline or mutation, so this is cheap to run for real."""
    path = f"{Path(sys.executable).parent}{os.pathsep}{os.environ.get('PATH', '')}"
    env = {**os.environ, "MUTATION_SHARD": "1", "PATH": path}
    r = subprocess.run(
        ["bash", str(_ROOT / "scripts" / "mutation_test.sh"), "ethtimelock"],
        cwd=_ROOT,
        env=env,
        capture_output=True,
        text=True,
    )
    assert r.returncode == 2, (r.returncode, r.stdout[-300:], r.stderr[-300:])
    assert "has 1 shard(s)" in r.stderr
