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

import pathlib
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
    """Every group `group_files()` can resolve — the source of truth for what exists."""
    body = _SCRIPT.read_text()
    start = body.index("group_files()")
    end = body.index("}", body.index("case", start))
    return set(re.findall(r"^\s{4}([a-z]+)\)", body[start:end], re.M))


def _meta_groups() -> set[str]:
    """Groups reachable through the CONSENSUS/VALUE aggregates."""
    body = _SCRIPT.read_text()
    out: set[str] = set()
    for name in ("CONSENSUS_GROUPS", "VALUE_GROUPS"):
        m = re.search(rf'^{name}="([^"]+)"', body, re.M)
        assert m, f"{name} not found in {_SCRIPT.name}"
        out |= set(m.group(1).split())
    return out


def _value_groups() -> set[str]:
    body = _SCRIPT.read_text()
    m = re.search(r'^VALUE_GROUPS="([^"]+)"', body, re.M)
    assert m, "VALUE_GROUPS not found"
    return set(m.group(1).split())


def _matrix_groups() -> set[str]:
    """What the workflow will actually run — obtained by running the generator the workflow runs."""
    import json
    import subprocess

    out = subprocess.run(
        [sys.executable, str(_ROOT / "scripts" / "mutation_groups.py")],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return set(json.loads(out)["group"])


def test_every_VALUE_group_is_RUN_weekly_by_the_workflow() -> None:
    """Now true BY CONSTRUCTION — the generator reads VALUE_GROUPS — so this is a regression guard
    on the derivation rather than on a hand-copied list. It fails if someone reintroduces a literal
    matrix, which is what drifted before: `mint` and `glyphscript` unrun for long enough that the
    dispatch description still said "all six value groups" when there were nine."""
    unrun = _value_groups() - _matrix_groups()
    assert not unrun, f"value groups the generator does not emit: {sorted(unrun)}"


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

    for entry in json.loads(r.stdout)["include"]:
        assert entry["group"] in _matrix_groups()
        assert str(entry["min_kill"]).isdigit()


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
    documented = set(re.findall(r"^poetry run task mutate ([a-z]+)", body, re.M))
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
        m = re.match(r'\s*([a-z]+)\)\s+echo "([^"]*)" ;;', line)
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
