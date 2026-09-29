"""A mutation group that no job runs measures nothing.

`scripts/mutation_test.sh` defines the groups; `.github/workflows/mutation.yml` decides which ones
actually execute weekly. Those two lists are maintained by hand in different files, and on
2026-08-27 they diverged: `ethleg` and `ethtimelock` were added to the script — module lists, test
lists, timeouts, `VALUE_GROUPS` — verified to run locally, and committed, while the workflow matrix
still named only the original seven. The subsystem with the worst mutation score in the codebase
had a group defined for it that CI would never invoke.

That is the same defect this codebase keeps producing in other forms: a capability with no caller.
It has appeared as a timelock sizer nothing called, a `--eth-key-file` flag no document used, a
909-line test file the harness did not list, and a coverage exemption whose stated reason had
become false. This test closes the mutation-harness instance of it.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# NOTE: this module used to open with ``pytest.importorskip("yaml")``, which made every
# check below conditional on a dependency none of them use — the matrix is parsed by
# `scripts/mutation_groups.py` in a subprocess and returned as JSON, and the workflow is
# read as text. A whole file of guards that can silently not run is the failure mode
# these guards exist to catch, so the import is gone.

_ROOT = Path(__file__).resolve().parent.parent
_SCRIPT = _ROOT / "scripts" / "mutation_test.sh"
_WORKFLOW = _ROOT / ".github" / "workflows" / "mutation.yml"


def _script_groups() -> set[str]:
    """Every group `group_files()` can resolve — the source of truth for what exists.

    `[a-z0-9_]+`, not `[a-z]+`: a group named with a digit or underscore (`spv2`, `eth_leg`)
    would be invisible to this parser while matching `group_files()` itself — the same blind
    spot `scripts/derive_mutation_test_lists.py`'s parser had, until both were widened together.
    `test_the_derivation_and_this_guard_parse_the_same_group_names` below pins that they stay in
    sync.
    """
    body = _SCRIPT.read_text()
    start = body.index("group_files()")
    end = body.index("}", body.index("case", start))
    return set(re.findall(r"^\s{4}([a-z0-9_]+)\)", body[start:end], re.M))


def _meta_groups() -> set[str]:
    """Groups reachable through the CONSENSUS/VALUE aggregates."""
    body = _SCRIPT.read_text()
    out: set[str] = set()
    for name in ("CONSENSUS_GROUPS", "VALUE_GROUPS"):
        m = re.search(rf'^{name}="([^"]+)"', body, re.M)
        assert m, f"{name} not found in {_SCRIPT.name}"
        out |= set(m.group(1).split())
    return out


def _consensus_groups() -> set[str]:
    """CONSENSUS_GROUPS as the shell script declares it."""
    m = re.search(r'^CONSENSUS_GROUPS="([^"]+)"', _SCRIPT.read_text(), re.M)
    assert m, "CONSENSUS_GROUPS not found in scripts/mutation_test.sh"
    return set(m.group(1).split())


def _value_groups() -> set[str]:
    body = _SCRIPT.read_text()
    m = re.search(r'^VALUE_GROUPS="([^"]+)"', body, re.M)
    assert m, "VALUE_GROUPS not found"
    return set(m.group(1).split())


def _matrix() -> list[dict[str, str]]:
    """The workflow's job list — obtained by running the generator the workflow runs."""
    import json
    import subprocess

    out = subprocess.run(
        [sys.executable, str(_ROOT / "scripts" / "mutation_groups.py")],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return json.loads(out)["include"]


def _matrix_groups() -> set[str]:
    """What the workflow will actually run."""
    return {e["group"] for e in _matrix()}


def test_every_VALUE_group_is_RUN_weekly_by_the_workflow() -> None:
    """Now true BY CONSTRUCTION — the generator reads VALUE_GROUPS — so this is a regression guard
    on the derivation rather than on a hand-copied list. It fails if someone reintroduces a literal
    matrix, which is what drifted before: `mint` and `glyphscript` unrun for long enough that the
    dispatch description still said "all six value groups" when there were nine."""
    unrun = _value_groups() - _matrix_groups()
    assert not unrun, f"value groups the generator does not emit: {sorted(unrun)}"


def test_every_CONSENSUS_group_is_RUN_weekly_by_the_workflow() -> None:
    """The mirror of the VALUE check above, and it was missing for as long as the gap existed.

    `scripts/mutation_groups.py` derived the matrix from VALUE_GROUPS alone, so spv, script,
    transaction and dmint — the groups that mutate consensus-critical modules — were reachable
    only by typing the name. `dmint` mutates covenant bytes where a wrong byte bricks a
    contract permanently, and nothing scheduled had ever mutated it.

    The previous fix for this class DERIVED the matrix instead of restating it, which is right;
    it just derived it from one of the two aggregates. Asserting only the VALUE half is what
    let the other half stay invisible, so both halves are asserted now.
    """
    unrun = _consensus_groups() - _matrix_groups()
    assert not unrun, f"CONSENSUS groups defined but never run weekly: {sorted(unrun)}"


def test_the_workflow_DERIVES_the_matrix_and_does_not_restate_it() -> None:
    """The structural point. A literal `group: [...]` list is a second statement of a fact that
    already lives in scripts/mutation_test.sh, and two statements of one fact drift — which is how
    four groups came to be defined and never run. Deriving it makes that unrepresentable."""
    wf = (_ROOT / ".github" / "workflows" / "mutation.yml").read_text()
    assert "fromJSON(needs.discover.outputs.matrix)" in wf, (
        "the workflow no longer consumes the derived matrix; a hand-typed group list will drift "
        "from VALUE_GROUPS exactly as it did before"
    )
    assert "scripts/mutation_groups.py" in wf, "the discovery job no longer runs the generator"


def test_every_group_is_reachable_through_a_META_group() -> None:
    """`task mutate all` expands CONSENSUS + VALUE. A group in neither is invisible to it — which
    is what hid `keys`, the module set holding secrets, base58 and BIP32 derivation."""
    orphaned = _script_groups() - _meta_groups()
    assert not orphaned, (
        f"groups reachable only by exact name, not via CONSENSUS_GROUPS/VALUE_GROUPS: "
        f"{sorted(orphaned)}. `task mutate all` would skip them."
    )


def _derived_groups() -> set[str]:
    """Every group name `scripts/derive_mutation_test_lists.py` sees, by actually RUNNING it —
    not by re-typing its regex here, which would just be a second hand-kept copy that could drift
    from the real one exactly as the two regexes already had.

    It needs a coverage.py sqlite database to open; a real one records real test executions this
    guard does not need, so a schema-only, all-empty one is created instead — the derivation only
    consults `file`/`context`/`arc` for their COLUMNS, and an empty `arc` table simply means every
    module gets no coverage-ranked tests, which is irrelevant to what this test checks: the SET OF
    GROUP NAMES the derivation's parser extracts from `scripts/mutation_test.sh`, which is exactly
    the top-level keys of its JSON output (see the unconditional `out[g] = {...}` in that file).
    """
    import json
    import sqlite3
    import subprocess
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        db_path = str(Path(d) / "empty-coverage.sqlite")
        conn = sqlite3.connect(db_path)
        conn.execute("CREATE TABLE file (id INTEGER, path TEXT)")
        conn.execute("CREATE TABLE context (id INTEGER, context TEXT)")
        conn.execute("CREATE TABLE arc (file_id INTEGER, context_id INTEGER, tono INTEGER)")
        conn.commit()
        conn.close()
        r = subprocess.run(
            [sys.executable, str(_ROOT / "scripts" / "derive_mutation_test_lists.py"), db_path, str(_ROOT), "14"],
            capture_output=True,
            text=True,
            check=True,
        )
        return set(json.loads(r.stdout).keys())


def test_the_derivation_and_this_guard_parse_the_same_group_names() -> None:
    """`scripts/derive_mutation_test_lists.py` and this file's `_script_groups()` each parse
    `scripts/mutation_test.sh`'s `group_files()` case statement with their OWN regex, and until
    both were widened together, a group named with a digit or underscore (`spv2`, `eth_leg`) was
    invisible to BOTH — the mechanism built to catch a gap shared the exact gap it existed to
    catch. Run the real derivation (rather than re-implementing its regex here) and assert its
    group names match this file's independent parse, so the two cannot silently drift apart
    again — whichever one is right, a difference means one of them stopped seeing a group."""
    derived = _derived_groups()
    wired = _script_groups()
    assert derived, "the derivation produced no groups at all — it is broken, not empty by design"
    assert derived == wired, (
        f"derive_mutation_test_lists.py and _script_groups() disagree on what groups exist: "
        f"only in the deriver: {sorted(derived - wired)}; only in _script_groups(): "
        f"{sorted(wired - derived)}"
    )


def test_a_threshold_names_a_group_that_exists() -> None:
    """The generator refuses to emit a floor for a group that is not in VALUE_GROUPS, because a
    `MUTATION_MIN_KILL_PCT` attached to a name nothing matches is silently no-op: the group runs
    report-only while looking gated."""
    import subprocess

    r = subprocess.run(
        [sys.executable, str(_ROOT / "scripts" / "mutation_groups.py")],
        capture_output=True,
        text=True,
    )
    assert r.returncode == 0, f"the generator refuses to emit: {r.stderr.strip()}"
    import json

    floored = [e for e in json.loads(r.stdout)["include"] if "min_kill" in e]
    assert floored, "no job carries a kill floor; ethleg and ethtimelock should"
    for entry in floored:
        assert entry["group"] in _matrix_groups()
        assert str(entry["min_kill"]).isdigit()


def _script_shards() -> dict[str, int]:
    """`group_shards()` as the script declares it, parsed here independently of the generator."""
    body = _SCRIPT.read_text()
    start = body.index("group_shards() {")
    block = body[start : body.index("\n}\n", start)]
    return {g: int(n) for g, n in re.findall(r'^\s+([a-z0-9_]+)\)\s+echo "(\d+)" ;;', block, re.M)}


def test_every_shard_of_a_sharded_group_is_a_job_and_every_job_name_is_unique() -> None:
    """A sharded group is N jobs. If the generator emitted fewer, the missing shards' mutants
    would never run while every job that did run went green. Job names also name the artifacts,
    and a duplicate would make the second upload fail."""
    shards = _script_shards()
    assert shards, "group_shards() lists no group; the parse broke (inspectcore and inspectcli are sharded)"
    jobs = _matrix()
    names = [e["name"] for e in jobs]
    assert len(names) == len(set(names)), f"duplicate job names: {sorted(n for n in names if names.count(n) > 1)}"
    for group, n in shards.items():
        got = sorted(int(e["shard"]) for e in jobs if e["group"] == group)
        assert got == list(range(1, n + 1)), f"{group}: group_shards says {n}, the matrix runs shards {got}"
    unsharded = [e for e in jobs if e["group"] not in shards]
    assert unsharded and all("shard" not in e and e["name"] == e["group"] for e in unsharded)


#: Groups split out of one parent because the parent did not fit the workflow's 330-minute job
#: timeout: parent -> children. REVIEWED, not derived — which group a split came from is history,
#: not something the script can express. The test below pins that each child still runs its
#: parent's exact test command, so a split only ever moves modules between jobs and never changes
#: what a module is tested against.
_SPLIT_FROM: dict[str, tuple[str, ...]] = {
    "transaction": ("txpreimage",),
    "dmint": ("dmintchain", "dmintminer"),
    "verdicts": ("mutchain", "waveverdicts"),
    "covenants": ("htlccovenant", "radiantleg", "rswpcovenant"),
    "gravitycore": ("gravitystate", "gravitymaker", "gravitylegs"),
    "cryptoprim": ("cryptokeys", "cryptosec", "cryptoutils", "cryptohash"),
    "glyphverify": ("glyphscan", "glyphinspector", "waverules", "inspectcore"),
    "wire": ("hashmark", "wiretx"),
}


def _group_settings(groups: list[str]) -> dict[str, tuple[str, str, str]]:
    """group -> (tests, timeout, marker), by RUNNING the script's own three functions in bash.

    Evaluated rather than regex-parsed, so a child that differs only in `$GAPS` placement, or
    that falls through to a `*)` default its parent does not, is seen exactly as the script
    would build its cosmic-ray test command."""
    import subprocess

    body = _SCRIPT.read_text(encoding="utf-8")
    parts = [re.search(r"^GAPS=.*$", body, re.M).group(0)]  # type: ignore[union-attr]
    for fn in ("group_tests", "group_timeout", "group_marker"):
        start = body.index(f"{fn}() {{")
        parts.append(body[start : body.index("\n}\n", start) + 3])
    parts.append(
        'for g in "$@"; do printf \'%s\\t%s\\t%s\\t%s\\n\' "$g" "$(group_tests "$g")" "$(group_timeout "$g")" "$(group_marker "$g")"; done'
    )
    out = subprocess.run(["bash", "-c", "\n".join(parts), "bash", *groups], capture_output=True, text=True, check=True)
    rows = [line.split("\t") for line in out.stdout.splitlines()]
    return {g: (t, to, mk) for g, t, to, mk in rows}


def test_a_split_group_keeps_its_parents_exact_test_command() -> None:
    """A child with a shorter test list would score its modules against less than before, and
    the lower kill rate would read as a finding about the code rather than about the split. The
    marker matters as much: the consensus groups run WITHOUT `-m 'not integration'`, so a
    consensus child that fell through to the default marker would run a different suite."""
    families = [(p, c) for p, kids in _SPLIT_FROM.items() for c in kids]
    settings = _group_settings(sorted({g for pair in families for g in pair}))
    assert len(settings) == len({g for pair in families for g in pair}), "bash evaluated fewer groups than asked"
    for parent, child in families:
        assert settings[parent][0].startswith("tests/"), f"{parent}: group_tests is empty; the evaluation broke"
        assert settings[child] == settings[parent], (
            f"{child} was split from {parent} but its (tests, timeout, marker) differ:\n"
            f"  {parent}: {settings[parent]}\n  {child}: {settings[child]}"
        )
    groups = _script_groups()
    stale = sorted({g for pair in families for g in pair} - groups)
    assert not stale, f"_SPLIT_FROM names groups the script no longer defines: {stale}"


def test_the_split_check_fires_on_a_child_with_a_different_marker() -> None:
    """Plant: `txpreimage` is a consensus child, so it must share `transaction`'s empty marker.
    Evaluated through the same function the test above uses, with the arm dropped from the
    marker case, which is exactly the edit a future split could forget."""
    body = _SCRIPT.read_text(encoding="utf-8")
    assert "|txpreimage|" in body, "txpreimage is no longer in group_marker's consensus arm; update this plant"
    import subprocess

    start = body.index("group_marker() {")
    fn = body[start : body.index("\n}\n", start) + 3].replace("|txpreimage|", "|")
    out = subprocess.run(
        ["bash", "-c", fn + '\nprintf "[%s][%s]" "$(group_marker transaction)" "$(group_marker txpreimage)"'],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    assert out == "[][-m 'not integration']", out


def test_no_module_is_mutated_by_two_groups() -> None:
    """A split that copied a module into a child without removing it from the parent would run
    it twice (twice the minutes) and report two scores for one file. Derived from group_files()."""
    body = _SCRIPT.read_text(encoding="utf-8")
    start = body.index("group_files() {")
    block = body[start : body.index("\n}\n", start)]
    owner: dict[str, list[str]] = {}
    for g, mods in re.findall(r'^\s{4}([a-z0-9_]+)\)\s+echo "([^"]*)" ;;', block, re.M):
        for m in mods.split():
            owner.setdefault(m, []).append(g)
    assert len(owner) > 100, f"only {len(owner)} modules parsed from group_files(); the parse broke"
    dup = {m: gs for m, gs in owner.items() if len(gs) > 1}
    assert not dup, f"modules mutated by more than one group: {dup}"


def test_the_mutate_step_passes_the_shard_and_names_its_files_by_job() -> None:
    """The shard index reaches the script only through the step's env, and two shards of one
    group share `matrix.group` — so a log or artifact named by group would collide."""
    wf = _WORKFLOW.read_text()
    assert "MUTATION_SHARD: ${{ matrix.shard }}" in wf
    assert "matrix.group }}.log" not in wf and "name: mutation-${{ matrix.group }}" not in wf
    assert 'tee "mutation-${MATRIX_NAME}.log"' in wf


def test_the_how_to_page_LISTS_every_group_a_reader_can_run() -> None:
    """The third statement of the same fact — and the one a reader acts on.

    `scripts/mutation_test.sh` defines the groups, `.github/workflows/mutation.yml`
    schedules them (derived, above), and `docs/how-to/mutation-testing.md` is what
    somebody reads before typing `task mutate <something>`. That page's runnable list was
    hand-typed, so it drifted exactly as the workflow matrix had: it offered eight
    `task mutate` lines and called them "the eight value-moving groups" while
    `VALUE_GROUPS` held twelve. `glyphscript`, `keys`, `ethleg` and `ethtimelock` were
    undocumented — `glyphscript` while the same page carried a "Baseline results"
    section for it.

    A group nobody knows to run is as unmeasured as one no job invokes.
    """
    doc = _ROOT / "docs" / "how-to" / "mutation-testing.md"
    body = doc.read_text()
    documented = set(re.findall(r"^poetry run task mutate ([a-z0-9_]+)", body, re.M))
    expected = _script_groups()
    assert expected, "no groups parsed from mutation_test.sh — the derivation broke, not the doc"

    missing = expected - documented
    assert not missing, (
        f"{doc.relative_to(_ROOT)} does not tell a reader these groups exist: {sorted(missing)}. "
        "They are defined in scripts/mutation_test.sh and runnable today."
    )

    # The other direction: a documented `task mutate <name>` the script cannot resolve
    # exits 2 with "unknown group", so a reader following the page hits an error.
    invented = documented - expected - {"all", "consensus", "value"}
    assert not invented, f"{doc.relative_to(_ROOT)} documents groups the script rejects: {sorted(invented)}"

    # The prose count is a fourth statement of the same fact, and it is the one that read
    # "eight" against twelve for four groups' worth of drift.
    # `[a-z-]+`, with the hyphen: the count passed fourteen and the spellings became compound
    # ("twenty-three"), which `[a-z]+` cannot match — so the guard reported "the page no longer
    # states how many" when the page stated it perfectly well. A pattern that stops matching as
    # the thing it guards grows is a guard with an expiry date.
    stated = re.search(r"the ([a-z-]+) value-moving groups", body)
    assert stated, "the page no longer states how many value-moving groups there are"
    words = {
        8: "eight",
        9: "nine",
        10: "ten",
        11: "eleven",
        12: "twelve",
        13: "thirteen",
        14: "fourteen",
        15: "fifteen",
        16: "sixteen",
        17: "seventeen",
        18: "eighteen",
        19: "nineteen",
        20: "twenty",
        21: "twenty-one",
        22: "twenty-two",
        23: "twenty-three",
        24: "twenty-four",
        25: "twenty-five",
        26: "twenty-six",
        27: "twenty-seven",
        28: "twenty-eight",
        29: "twenty-nine",
        30: "thirty",
        31: "thirty-one",
        32: "thirty-two",
        33: "thirty-three",
        34: "thirty-four",
        35: "thirty-five",
        36: "thirty-six",
        37: "thirty-seven",
        38: "thirty-eight",
        39: "thirty-nine",
        40: "forty",
        41: "forty-one",
        42: "forty-two",
        43: "forty-three",
        44: "forty-four",
        45: "forty-five",
        46: "forty-six",
        47: "forty-seven",
        48: "forty-eight",
        49: "forty-nine",
        50: "fifty",
    }
    want = words.get(len(_value_groups()))
    assert want is not None, f"add a spelling for {len(_value_groups())} to this test"
    assert stated.group(1) == want, (
        f"the page says '{stated.group(1)} value-moving groups'; VALUE_GROUPS holds {len(_value_groups())} ({want})"
    )


def test_every_mutated_module_runs_its_own_dedicated_test() -> None:
    """A group's test list must include each module's OWN test file, if one exists.

    THE FAILURE THIS CATCHES COST EIGHTEEN HOURS OF COMPUTE. The ten newest groups had their test
    lists derived by counting how many of the group's modules each test file imports and taking
    the top N. That ranking is exactly backwards for relevance: a single-purpose test like
    `test_glyph_royalty.py` imports ONE module and scores 1, while a broad one like
    `test_fuzz_parsers.py` imports five and scores 5 — so the cap dropped precisely the tests that
    constrain a module best. 27 modules lost their own test that way.

    The results looked like devastating coverage findings and were measurement artifacts:
    `hash` scored 0% killed over 1,400 mutants because `tests/test_hash.py` never ran;
    `glyph/royalty` and `glyph/credential_binding` scored 0% for the same reason. A mutation score
    is only a statement about the tests you actually ran.

    Derived, not hand-kept: the pairing is "a test whose filename stem contains the module's leaf
    name", computed from the tree. A module with no such file is not an error — plenty are covered
    only by broader suites — this asserts that where a dedicated test EXISTS, it is in the list.
    """
    mods, tests = {}, {}
    for line in _SCRIPT.read_text(encoding="utf-8").split("\n"):
        m = re.match(r'\s*([a-z0-9_]+)\)\s+echo "([^"]*)" ;;', line)
        if not m:
            continue
        items = m.group(2).split()
        if not items or all(re.fullmatch(r"[\d.]+", i) for i in items):
            continue
        (tests if items[0].startswith("tests/") else mods)[m.group(1)] = items

    assert mods, "no module lists parsed — the derivation broke, not the script"
    test_files = {p.as_posix() for p in (_ROOT / "tests").rglob("test_*.py")}
    assert len(test_files) > 100, f"only {len(test_files)} test files found — the scan is wrong"

    missing = []
    for group, modules in mods.items():
        listed = set(tests.get(group, ()))
        for module in modules:
            parts = module.split("/")
            leaf = parts[-1]
            wanted = (
                {f"tests/test_{leaf}.py"}
                if len(parts) == 1
                else {
                    f"tests/test_{'_'.join(parts[:-1])}_{leaf}.py",
                    f"tests/{'/'.join(parts[:-1])}/test_{leaf}.py",
                    f"tests/test_{parts[-2]}_{leaf}.py",
                }
            )
            dedicated = {t.replace(f"{_ROOT.as_posix()}/", "") for t in test_files} & wanted
            if dedicated and not (dedicated & listed):
                missing.append(f"{group}: {module} (has {sorted(dedicated)[0]})")

    assert not missing, (
        "these mutation groups do not run the module's own test file, so the module is mutated "
        "against tests that were never written for it — a low kill rate would be an artifact, not "
        "a finding:\n  " + "\n  ".join(sorted(missing))
    )


def test_every_test_file_a_group_names_actually_EXISTS() -> None:
    """`tests/test_htlc_spend.py` was deleted by #518 and stayed in the `script` and `transaction`
    lists for four months. Nothing said so: every other guard here checks that GROUPS line up with
    each other, and none checked that the paths resolve to files on disk.

    It fails closed rather than silently — `pytest` answers a missing path with **exit 4, a usage
    error, even when real files are named alongside it**, so the harness's clean-suite baseline
    refuses the group. That is the right direction (cosmic-ray reads a non-zero exit as "mutant
    killed", so a collectable-but-red list would have scored 100% and been a complete fiction) but
    it is only discovered by trying to run the group, and these two had not been run since.

    Derived from the script, so a new group is covered the moment it is added."""
    gaps_m = re.search(r'^GAPS="([^"]*)"', _SCRIPT.read_text(encoding="utf-8"), re.M)
    assert gaps_m, "GAPS is no longer a simple double-quoted assignment; this expansion is stale"
    expansions = {"$GAPS": gaps_m.group(1).split()}

    missing: list[str] = []
    checked = 0
    for line in _SCRIPT.read_text(encoding="utf-8").split("\n"):
        m = re.match(r'\s*([a-z0-9_]+)\)\s+echo "(tests/[^"]*)" ;;', line)
        if not m:
            continue
        group = m.group(1)
        for token in m.group(2).split():
            for path in expansions.get(token, [token]):
                if not path.startswith("tests/"):
                    continue
                checked += 1
                if not (_ROOT / path).exists():
                    missing.append(f"{group}: {path}")

    # Non-vacuity: if the parse stops matching, "no missing files" must not read as success.
    assert checked > 100, (
        f"only {checked} test paths parsed out of scripts/mutation_test.sh — the case-line regex "
        "has stopped matching and this guard is passing over nothing"
    )
    assert not missing, (
        "these mutation groups name test files that do not exist, so `pytest` exits 4 and the "
        "group cannot run at all:\n  " + "\n  ".join(sorted(missing))
    )


def _declared_mutation_targets() -> dict[str, set[str]]:
    """test file -> modules it declares via a module-level ``MUTATION_TARGETS`` list."""
    import ast

    out: dict[str, set[str]] = {}
    for path in sorted((_ROOT / "tests").rglob("test_*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, SyntaxError):  # pragma: no cover - unreadable test file
            continue
        for node in tree.body:  # module level only
            if not isinstance(node, ast.Assign):
                continue
            if not any(isinstance(t, ast.Name) and t.id == "MUTATION_TARGETS" for t in node.targets):
                continue
            if isinstance(node.value, ast.List | ast.Tuple | ast.Set):
                mods = {e.value for e in node.value.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)}
                if mods:
                    out[path.relative_to(_ROOT).as_posix()] = mods
    return out


def test_a_declared_mutation_target_names_a_module_that_EXISTS() -> None:
    """``MUTATION_TARGETS`` exists because neither derivation signal can see some tests: one
    named after a function, whose coverage is unremarkable because a weaker test already runs
    the same lines. Coverage cannot observe assertions, so such a test must declare itself.

    A declaration pointing at a module that was renamed or deleted is a check that has
    silently stopped running — the deriver would add the test to no group at all."""
    declared = _declared_mutation_targets()
    assert declared, (
        "no test declares MUTATION_TARGETS any more. Either the convention was removed (then "
        "delete this guard and the deriver's scanner) or the declarations were lost."
    )
    bad = [
        f"{test} -> {mod}"
        for test, mods in declared.items()
        for mod in sorted(mods)
        if not (_ROOT / "src" / "pyrxd" / f"{mod}.py").exists()
    ]
    assert not bad, "MUTATION_TARGETS naming modules that do not exist:\n  " + "\n  ".join(bad)


def test_a_declared_test_actually_REACHES_a_mutation_group() -> None:
    """The other direction. Declaring a target is pointless if the module belongs to no group,
    or if the regenerated lists were never applied to the script — the declaration would look
    like protection while changing nothing."""
    declared = _declared_mutation_targets()
    script = _SCRIPT.read_text(encoding="utf-8")
    missing = [f"{test} (declares {sorted(mods)})" for test, mods in declared.items() if test not in script]
    assert not missing, (
        "these tests declare MUTATION_TARGETS but no group's test list names them, so the "
        "declaration does nothing. Re-run scripts/derive_mutation_test_lists.py and apply the "
        "result to scripts/mutation_test.sh:\n  " + "\n  ".join(missing)
    )


def _group_test_lists() -> dict[str, list[str]]:
    """group -> its test list, as `group_tests()` echoes it, with `$GAPS` expanded."""
    body = _SCRIPT.read_text(encoding="utf-8")
    gaps_m = re.search(r'^GAPS="([^"]*)"', body, re.M)
    assert gaps_m, "GAPS is no longer a simple double-quoted assignment; this expansion is stale"
    out: dict[str, list[str]] = {}
    for line in body.split("\n"):
        m = re.match(r'\s*([a-z0-9_]+)\)\s+echo "(tests/[^"]*)" ;;', line)
        if m:
            items: list[str] = []
            for token in m.group(2).split():
                items.extend(gaps_m.group(1).split() if token == "$GAPS" else [token])
            out[m.group(1)] = items
    return out


def _conftest_dir_of(path: str) -> str | None:
    """The nearest directory below `tests/` that holds a conftest.py and contains `path`
    (a file, or a directory argument such as `tests/security/`), else None.

    DERIVED from the tree: a conftest.py added to `tests/security/` tomorrow puts every list
    that splits `tests/security/*` in scope at once, which is exactly when they would break."""
    p = Path(path.rstrip("/"))
    for d in [p, *p.parents]:
        if d.as_posix() in ("tests", "."):
            return None
        if (_ROOT / d / "conftest.py").exists():
            return d.as_posix()
    return None


def _conftest_splits(tests: list[str]) -> list[str]:
    """Directories whose files do not form ONE contiguous run in `tests`."""
    split: list[str] = []
    seen_closed: set[str] = set()
    previous: str | None = None
    for t in tests:
        d = _conftest_dir_of(t)
        if d != previous and previous is not None:
            seen_closed.add(previous)
        if d is not None and d in seen_closed and d not in split:
            split.append(d)
        previous = d
    return split


def test_files_under_a_conftest_directory_stay_CONTIGUOUS_in_every_group() -> None:
    """The rule was already written down, twice, and the lists broke it anyway.

    `scripts/mutation_test.sh` and docs/how-to/mutation-testing.md both say `tests/cli/*` must
    stay contiguous: pytest 9.1.1, given `tests/cli/a.py tests/test_b.py tests/cli/c.py`, stops
    applying `tests/cli/conftest.py` to `c.py`, so its `runner` fixture is "not found". The
    `glyphverify` list split `test_glyph_inspect_cmds.py` from `test_glyph_cmds.py` (76 errors)
    and `walletcore` split three tests/cli files (8 errors in `test_swap_book_cmds.py`). Both
    baselines went red, the harness refused both groups, and weekly run 35710549260 reported
    them green for a second, unrelated reason (the workflow step lost the exit code to `tee`).
    Neither group had produced a score. Prose rules do not run; this does.

    Only directories that HAVE a conftest.py are held to it, since that is the mechanism;
    `tests/security/` and `tests/network/` are split in several lists today and are harmless
    until one of them grows a conftest, at which point this fails for them too.
    """
    lists = _group_test_lists()
    assert len(lists) > 20, f"only {len(lists)} test lists parsed — the case-line regex stopped matching"

    # Non-vacuity: at least one group must put 2+ files from one conftest directory in its list,
    # or this passes because there was nothing that could be split.
    from collections import Counter

    multi = [
        g for g, tests in lists.items() if any(n >= 2 for d, n in Counter(map(_conftest_dir_of, tests)).items() if d)
    ]
    assert multi, "no group names two files from one conftest directory — this guard is checking nothing"

    bad = {g: split for g, tests in lists.items() if (split := _conftest_splits(tests))}
    assert not bad, (
        "these groups split a conftest directory across their test list, so pytest drops that "
        "conftest for the later files and the clean-suite baseline goes red (the group then never "
        f"runs): {bad}. Move each directory's files into one contiguous run, last."
    )


def test_the_contiguity_check_fires_on_the_list_that_broke_glyphverify() -> None:
    """Plant: the pre-fix `glyphverify` ordering, tests/cli split by a top-level file."""
    old = [
        "tests/test_inspect_script_shapes.py",
        "tests/cli/test_glyph_inspect_cmds.py",
        "tests/test_inspect_core_classification.py",
        "tests/cli/test_glyph_cmds.py",
    ]
    assert _conftest_splits(old) == ["tests/cli"]
    # Honest path: the same files, contiguous, are fine wherever the run sits.
    assert _conftest_splits([old[0], old[2], old[1], old[3]]) == []
    assert _conftest_splits([old[1], old[3], old[0], old[2]]) == []
