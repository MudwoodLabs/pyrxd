"""`scripts/mutation_shard.py` must split a module's mutants into shards that cover it exactly once.

A shard that dropped mutants would report a module as scored while part of it never ran; two
shards that overlapped would double-count. Neither shows up in a kill rate. So this runs the real
`cosmic-ray init` on a real module and checks the shards against the session it wrote, then
checks that `cr-report` — which is what `scripts/mutation_test.sh` reads its counts from —
reports the shard's size as the total, so no mutant outside the shard is counted as a kill.
"""

from __future__ import annotations

import os
import re
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "scripts"))
from mutation_shard import shard
from mutation_shard_scores import combine

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


def _init(d: Path) -> Path:
    """One `cosmic-ray init` of `_MODULE` into its own directory, as one CI job does."""
    d.mkdir(parents=True, exist_ok=True)
    cfg = d / "cr.toml"
    cfg.write_text(
        f'[cosmic-ray]\nmodule-path = "{_MODULE}"\ntimeout = 10\nexcluded-modules = []\n'
        'test-command = "true"\n\n[cosmic-ray.distributor]\nname = "local"\n'
    )
    sess = d / "s.sqlite"
    subprocess.run([_tool("cosmic-ray"), "init", str(cfg), str(sess)], cwd=_ROOT, check=True, capture_output=True)
    return sess


def _job_ids(sess: Path) -> set[str]:
    con = sqlite3.connect(sess)
    try:
        return {r[0] for r in con.execute("SELECT job_id FROM work_items")}
    finally:
        con.close()


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


def test_shards_cut_from_SEPARATE_inits_still_partition_the_module(fresh_session: Path, tmp_path: Path) -> None:
    """What CI actually does. Each shard is its own job, so each runs its OWN `cosmic-ray init` and
    cuts its shard from that — no two shards ever see the same session. The test above copies one
    session, which cannot show that separate inits order the mutants the same way.

    cosmic-ray gives every job a fresh random `job_id` on each init, so the shard order must not
    depend on it: `mutation_shard.py` orders by source position, operator and occurrence, and
    `(operator, occurrence)` is unique within a module. Compared on that key, not on job ids."""
    full = _specs(fresh_session)
    n = 3
    sessions = [_init(tmp_path / f"job{k}") for k in range(1, n + 1)]
    ids = [_job_ids(s) for s in sessions]
    # Non-vacuity: these really are separate inits. Were the job ids shared, this would be the
    # copied-session test again and would prove nothing new.
    assert all(not (ids[0] & other) for other in ids[1:]), "the inits share job ids; they are not independent"
    parts = []
    for k, sess in enumerate(sessions, start=1):
        assert _specs(sess) == full, "a fresh init produced a different mutant set; the premise is gone"
        kept, total = shard(str(sess), k, n)
        assert total == len(full)
        parts.append(_specs(sess))
        assert kept == len(parts[-1])
    assert set().union(*parts) == full, "a mutant is in no shard, so it would never run"
    assert sum(map(len, parts)) == len(full), "a mutant is in two shards, so it would be scored twice"


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


# --- combining shard scores (scripts/mutation_shard_scores.py) ---------------------------------


def _script_formats() -> tuple[str, str]:
    """The two per-module printf formats in mutation_test.sh, as Python %-formats."""
    body = (_ROOT / "scripts" / "mutation_test.sh").read_text(encoding="utf-8")
    fmts = re.findall(r"printf '(  %-28s %4d[^']*)'", body)
    done = [f for f in fmts if " mutants " in f]
    part = [f for f in fmts if " RAN " in f]
    assert len(done) == 1 and len(part) == 1, fmts
    assert 'echo "== group: $g${sfx:+ ($sfx)} =="' in body and 'sfx=".shard${SHARD}of' in body
    return done[0].replace("\\n", ""), part[0].replace("\\n", "")


def _shard_log(k: int, n: int, rows: list[tuple[str, int, int, int | None]]) -> str:
    """A shard job's log, printed with the script's own formats. rows: (module, total, killed, ran)
    where ran=None means the module finished."""
    done, part = _script_formats()
    lines = [f"== group: cryptohash (.shard{k}of{n}) =="]
    for mod, total, killed, ran in rows:
        if ran is None:
            lines.append(done % (mod, total, killed, total - killed, killed * 100 // total, 60))
        else:
            lines.append(part % (mod, ran, total, killed, ran - killed, killed * 100 // ran, 60))
    return "\n".join(lines) + "\n"


def test_shard_scores_SUM_rather_than_average() -> None:
    """Killed 10/20, 11/20 and 1/19: the module is 22 killed of 59. The result is the two sums, so
    a combiner that averaged the shard percentages (36.8% here, against the true 37.3%) has no
    way to return it. The second module's name is longer than the script's `%-28s` field, as
    `transaction/transaction_preimage` really is, so the parse cannot rely on the padding."""
    logs = [
        _shard_log(1, 3, [("hash", 20, 10, None), ("transaction/transaction_preimage", 7, 7, None)]),
        _shard_log(2, 3, [("hash", 20, 11, None), ("transaction/transaction_preimage", 7, 0, None)]),
        _shard_log(3, 3, [("hash", 19, 1, None), ("transaction/transaction_preimage", 6, 6, None)]),
    ]
    got = combine(logs)
    assert got == {"cryptohash": {"hash": (22, 59), "transaction/transaction_preimage": (13, 20)}}


def test_shard_scores_refuse_a_missing_or_INCOMPLETE_shard() -> None:
    full = [_shard_log(k, 3, [("hash", 20, 10, None)]) for k in (1, 2, 3)]
    assert combine(full) == {"cryptohash": {"hash": (30, 60)}}  # honest path
    with pytest.raises(ValueError, match=r"no log for shard\(s\) \[2\] of 3"):
        combine([full[0], full[2]])
    cut = _shard_log(2, 3, [("hash", 20, 4, 9)])
    with pytest.raises(ValueError, match=r"INCOMPLETE in shard\(s\) \[2\]"):
        combine([full[0], cut, full[2]])
    cancelled = _shard_log(2, 3, [])  # cancelled before it printed the module's line
    with pytest.raises(ValueError, match=r"has no result in shard\(s\) \[2\]"):
        combine([full[0], cancelled, full[2]])
