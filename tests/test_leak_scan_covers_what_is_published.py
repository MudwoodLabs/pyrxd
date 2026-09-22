"""The leak scanner has to see what a push PUBLISHES, not only what is checked out.

``scripts/check-no-private-links.py`` ran in no GitHub workflow — only ``task ci`` and the
opt-in pre-push hook, which ignored the refs git hands it — and it read the WORKING TREE. So
all of these passed:

* a leak committed and then removed in a later commit — it is in every clone's history;
* a file staged with a leak and then cleaned in the working tree — the index copy is what
  ``git commit`` records;
* ``git push origin other-branch`` while a clean branch is checked out;
* any file with one non-UTF-8 byte — it raised on decode and was skipped;
* any path with a non-ASCII byte — ``git ls-files`` C-quoted it and the quoted string named
  no file.

Every case runs the REAL script (and the real hook, and the real workflow steps) as a
subprocess against a THROWAWAY repo in ``tmp_path``, the way ``test_git_hooks_work_from_a_worktree``
does — never against this checkout.

THE FIXTURES ARE BUILT AT RUNTIME. This file is itself scanned by the tree scan in CI; a
literal routable ``user@<ip>`` in it would fail the build. The documentation addresses in the
honest-path controls ARE literal, because the scanner allows them by design.
"""

from __future__ import annotations

import importlib.util
import os
import pathlib
import shutil
import subprocess
import sys

import pytest

# A HARD import, deliberately — not `pytest.importorskip`. PyYAML arrives with `bandit`, a declared
# dependency-group member that requires it; if it ever stops arriving, collection fails loudly
# instead of every workflow check below skipping in silence.
import yaml

_REPO = pathlib.Path(__file__).resolve().parent.parent
_SCANNER = _REPO / "scripts" / "check-no-private-links.py"
_HOOK = _REPO / "scripts" / "git-hooks" / "pre-push"
_WORKFLOW = _REPO / ".github" / "workflows" / "leak-scan.yml"

#: 240.0.0.0/4 is reserved and routes nowhere, so this names no one's machine. The scanner's
#: `_is_routable` excludes only private, loopback, link-local and documentation ranges, so it
#: counts this one routable — `test_the_leak_fixture_is_one_the_scanner_calls_routable` pins
#: that, so a change there fails with its reason instead of making every test below vacuous.
_ROUTABLE_IP = ".".join(str(octet) for octet in (240, 0, 0, 42))
_SSH_LEAK = "deploy" + "@" + _ROUTABLE_IP
_USERNAME = "exampleuser"
_HOME_LEAK = "/" + "/".join(("home", _USERNAME, "notes.md"))
_ZERO = "0" * 40


def _env(**extra: str) -> dict[str, str]:
    """A git environment that ignores the developer's config, and CI's redaction switch."""
    env = {k: v for k, v in os.environ.items() if k != "GITHUB_ACTIONS"}
    env.update(
        GIT_CONFIG_GLOBAL="/dev/null",
        GIT_CONFIG_SYSTEM="/dev/null",
        GIT_AUTHOR_NAME="t",
        GIT_AUTHOR_EMAIL="t@example.invalid",
        GIT_COMMITTER_NAME="t",
        GIT_COMMITTER_EMAIL="t@example.invalid",
    )
    env.update(extra)
    return env


def _git(repo: pathlib.Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=repo, env=_env(), capture_output=True, text=True, check=True
    ).stdout.strip()


def _write(repo: pathlib.Path, files: dict[str, str | bytes]) -> None:
    for name, content in files.items():
        path = repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content if isinstance(content, bytes) else content.encode())


def _commit(repo: pathlib.Path, files: dict[str, str | bytes], message: str) -> str:
    _write(repo, files)
    _git(repo, "add", "--", *files)
    _git(repo, "commit", "-qm", message)
    return _git(repo, "rev-parse", "HEAD")


def _scan(repo: pathlib.Path, *args: str, **env: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(_SCANNER), *args], cwd=repo, env=_env(**env), capture_output=True, text=True
    )


@pytest.fixture
def repo(tmp_path: pathlib.Path) -> pathlib.Path:
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    _commit(root, {"README.md": "a clean repository\n"}, "clean")
    return root


def _leaky_files() -> dict[str, str]:
    return {"deploy.sh": f"ssh {_SSH_LEAK} uptime\n", "guide.md": f"see\n\nnotes in {_HOME_LEAK}\n"}


# ────────────────────────────────────────────────────────────── the fixture itself ──


def test_the_leak_fixture_is_one_the_scanner_calls_routable() -> None:
    spec = importlib.util.spec_from_file_location("check_no_private_links", _SCANNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # Registered first: `@dataclass` resolves the module's postponed annotations through
    # `sys.modules[cls.__module__]`, so an unregistered module fails to import at all.
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(spec.name, None)
    assert module._is_routable(_ROUTABLE_IP), "pick another fixture address: the scanner no longer flags this one"
    assert module.find_ssh_targets(f"ssh {_SSH_LEAK}") == [_SSH_LEAK]


def test_a_leak_in_the_tree_is_found_with_its_line(repo) -> None:
    """The control for everything below: the tree scan catches a plain committed leak."""
    _commit(repo, _leaky_files(), "leak")
    proc = _scan(repo)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "deploy.sh:1" in proc.stderr and "guide.md:3" in proc.stderr
    # Unredacted by default (outside CI): the developer sees what matched.
    assert _SSH_LEAK in proc.stderr and _HOME_LEAK in proc.stderr


# ───────────────────────────────────────────────────────────────── history ──


def test_a_leak_that_exists_only_in_history_is_caught_by_the_range_scan(repo) -> None:
    base = _git(repo, "rev-parse", "HEAD")
    _commit(repo, _leaky_files(), "leak")
    _git(repo, "rm", "-q", "deploy.sh", "guide.md")
    _git(repo, "commit", "-qm", "remove it again")

    tree = _scan(repo)
    assert tree.returncode == 0, "control: the tree is clean now, so the tree scan must pass"

    history = _scan(repo, "--no-tree", "--range", f"{base}..HEAD")
    assert history.returncode == 1, history.stdout + history.stderr
    leak_commit = _git(repo, "rev-parse", "HEAD~1")[:12]
    assert f"{leak_commit} deploy.sh:1" in history.stderr
    assert f"{leak_commit} guide.md:3" in history.stderr
    assert "2 commit(s)" in history.stdout


def test_a_leak_added_only_by_a_merge_is_caught(repo) -> None:
    """A line written while resolving a merge exists in no other commit. `git log -p`
    shows merges no patch at all unless asked, so without `-m` this passed."""
    base = _git(repo, "rev-parse", "HEAD")
    _git(repo, "checkout", "-qb", "side")
    _commit(repo, {"side.txt": "side\n"}, "side")
    _git(repo, "checkout", "-q", "main")
    _commit(repo, {"main.txt": "main\n"}, "main")
    _git(repo, "merge", "-q", "--no-ff", "--no-commit", "side")
    _write(repo, {"deploy.sh": f"ssh {_SSH_LEAK}\n"})
    _git(repo, "add", "deploy.sh")
    _git(repo, "commit", "-qm", "merge side")
    _git(repo, "rm", "-q", "deploy.sh")
    _git(repo, "commit", "-qm", "remove it again")

    # The later removal shows it as a REMOVED line; what must not exist is an ADDED one.
    for sha in _git(repo, "rev-list", "--no-merges", f"{base}..HEAD").split():
        assert f"+ssh {_SSH_LEAK}" not in _git(repo, "show", sha), "fixture: the leak must be added by the merge only"
    assert _scan(repo).returncode == 0, "control: the tree is clean"
    proc = _scan(repo, "--no-tree", "--range", f"{base}..HEAD")
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "deploy.sh:1" in proc.stderr


# ─────────────────────────────────────────────────────────── the index copy ──


def test_a_leak_staged_and_then_cleaned_in_the_working_tree_is_caught(repo) -> None:
    _commit(repo, {"guide.md": "clean\n"}, "doc")
    _write(repo, {"guide.md": f"clean\n{_HOME_LEAK}\n"})
    _git(repo, "add", "guide.md")
    _write(repo, {"guide.md": "clean\n"})  # the working tree is clean; the index is not

    proc = _scan(repo)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "guide.md:2 (staged version)" in proc.stderr

    _git(repo, "add", "guide.md")
    assert _scan(repo).returncode == 0, "control: once the clean copy is staged, nothing is left"


def test_an_unstaged_leak_in_the_working_tree_is_still_caught(repo) -> None:
    """The behaviour the scan always had, kept: the working tree is what `commit -a` records."""
    _commit(repo, {"guide.md": "clean\n"}, "doc")
    _write(repo, {"guide.md": f"{_HOME_LEAK}\n"})
    proc = _scan(repo)
    assert proc.returncode == 1 and "guide.md:1" in proc.stderr and "staged" not in proc.stderr


# ─────────────────────────────────────────────────── bytes the scan could not read ──


def test_a_non_utf8_byte_does_not_hide_a_leak(repo) -> None:
    _commit(
        repo,
        {
            "tools/deploy.sh": b"# \xff\xfe latin-1 residue\nssh " + _SSH_LEAK.encode() + b"\n",
            "notes.md": b"caf\xe9\n" + _HOME_LEAK.encode() + b"\n",
        },
        "non-utf8",
    )
    tree = _scan(repo)
    assert tree.returncode == 1, tree.stdout + tree.stderr
    assert "tools/deploy.sh:2" in tree.stderr and "notes.md:2" in tree.stderr
    history = _scan(repo, "--no-tree", "--range", "HEAD~1..HEAD")
    assert history.returncode == 1 and "tools/deploy.sh:2" in history.stderr


def test_a_nul_byte_does_not_hide_a_leak_from_the_range_scan(repo) -> None:
    """git calls a file with a NUL byte binary and prints no lines for it unless told `-a`."""
    _commit(repo, {"blob.dat": b"\x00\x01header\nssh " + _SSH_LEAK.encode() + b"\n"}, "binary-looking")
    assert _scan(repo).returncode == 1
    history = _scan(repo, "--no-tree", "--range", "HEAD~1..HEAD")
    assert history.returncode == 1 and "blob.dat:2" in history.stderr


def test_a_path_git_would_quote_is_still_read(repo) -> None:
    """`git ls-files` without -z prints `"caf\\303\\251 notes.md"` — a name no file has."""
    name = "café notes.md"
    _commit(repo, {name: f"{_HOME_LEAK}\n"}, "non-ascii name")
    assert '"' in _git(repo, "-c", "core.quotePath=true", "ls-files"), "fixture: git must quote this path"
    tree = _scan(repo)
    assert tree.returncode == 1, tree.stdout + tree.stderr
    assert f"{name}:1" in tree.stderr
    history = _scan(repo, "--no-tree", "--range", "HEAD~1..HEAD")
    assert history.returncode == 1 and f"{name}:1" in history.stderr


def test_an_unreadable_file_is_listed_not_skipped(repo) -> None:
    """A tracked path whose working-tree copy is now a DIRECTORY: unreadable for every user,
    root included, so this needs no skip (and every skip in this suite must be declared)."""
    _commit(repo, {"notes.txt": "clean\n"}, "doc")
    (repo / "notes.txt").unlink()
    (repo / "notes.txt").mkdir()
    proc = _scan(repo)
    assert "could not be read" in proc.stderr, proc.stdout + proc.stderr
    assert "notes.txt: working-tree copy: IsADirectoryError" in proc.stderr
    # Its index copy was still read; a listing is a warning, not a leak.
    assert proc.returncode == 0


# ───────────────────────────────────────────── links and names, both scans ──


def test_a_link_into_a_gitignored_path_is_caught_including_a_quoted_one(repo) -> None:
    """`git check-ignore` C-quotes an unusual path in its OUTPUT too, so without `-z` the
    answer for `private/café.md` never equalled the question and the link passed."""
    _commit(repo, {".gitignore": "private/\n"}, "ignore private/")
    base = _git(repo, "rev-parse", "HEAD")
    _commit(repo, {"docs/index.md": "[plan](../private/plan.md)\n\n[menu](../private/café.md)\n"}, "links")
    for proc in (_scan(repo), _scan(repo, "--no-tree", "--range", f"{base}..HEAD")):
        assert proc.returncode == 1, proc.stdout + proc.stderr
        assert "docs/index.md:1" in proc.stderr and "docs/index.md:3" in proc.stderr
        assert "resolves to: private/café.md (gitignored)" in proc.stderr


def test_a_private_name_is_caught_only_where_the_local_list_exists(repo) -> None:
    base = _git(repo, "rev-parse", "HEAD")
    _commit(repo, {"docs/thanks.md": "credit to the Frobnicator team\n"}, "thanks")
    without = _scan(repo)
    assert without.returncode == 0
    assert "private-name check NOT run" in without.stdout, "an absent list must be SAID, not implied"

    (repo / ".private-names").write_text("# local only\nfrobnicator\n")
    for proc in (_scan(repo), _scan(repo, "--no-tree", "--range", f"{base}..HEAD")):
        assert proc.returncode == 1, proc.stdout + proc.stderr
        assert "docs/thanks.md:1" in proc.stderr and "private-name check NOT run" not in proc.stdout
    redacted = _scan(repo, "--redact")
    assert "docs/thanks.md:1: private-name" in redacted.stderr and "Frobnicator" not in redacted.stderr


# ─────────────────────────────────────────────────────────── honest content ──


def test_honest_examples_are_not_flagged_by_either_scan(repo) -> None:
    base = _git(repo, "rev-parse", "HEAD")
    _commit(
        repo,
        {
            "docs/example.md": (
                "ssh admin@192.0.2.10 uptime\n"  # RFC 5737 documentation range
                "git clone git@github.com:owner/repo.git\n"
                "ssh <user>@<ip> uptime\n"
                "config lives in ~/.pyrxd/config.toml\n"
                "clone into /home/<user>/apps or /tmp/scratch\n"
            ),
            "tools/run.py": 'HOSTS = ["ops@198.51.100.7", "ops@203.0.113.9", "root@10.0.0.5", "me@127.0.0.1"]\n',
        },
        "honest examples",
    )
    tree = _scan(repo)
    assert tree.returncode == 0, tree.stdout + tree.stderr
    history = _scan(repo, "--no-tree", "--range", f"{base}..HEAD")
    assert history.returncode == 0, history.stdout + history.stderr
    assert "1 commit(s), 6 added line(s), 0 finding(s)" in history.stdout


# ───────────────────────────────────────────────────────────────── redaction ──


@pytest.mark.parametrize("how", ["flag", "github-actions-env"])
def test_redacted_output_names_the_place_and_the_check_and_nothing_else(repo, how) -> None:
    base = _git(repo, "rev-parse", "HEAD")
    _commit(repo, _leaky_files(), "leak")
    args, env = (["--redact"], {}) if how == "flag" else ([], {"GITHUB_ACTIONS": "true"})
    for extra in ([], ["--no-tree", "--range", f"{base}..HEAD"]):
        proc = _scan(repo, *args, *extra, **env)
        out = proc.stdout + proc.stderr
        assert proc.returncode == 1
        assert "deploy.sh:1: ssh-target" in out and "guide.md:3: home-path" in out
        assert _ROUTABLE_IP not in out and _USERNAME not in out, out


# ─────────────────────────────────────────────────────────── invocation ──


@pytest.mark.parametrize(
    "args",
    [
        ["--no-tree"],  # scans nothing
        ["--range", "HEAD --output=/dev/null"],  # an option that is not commit selection
        ["--range", "no-such-revision..HEAD"],
    ],
)
def test_an_invocation_that_cannot_scan_is_exit_2(repo, args) -> None:
    assert _scan(repo, *args).returncode == 2


def test_a_diff_the_parser_does_not_understand_fails_closed(monkeypatch) -> None:
    """Lines the range scan cannot parse are lines it did not scan: exit 2, never a clean 0.
    Fed straight to the parser, because real `git log -U0` never emits either shape."""
    spec = importlib.util.spec_from_file_location("check_no_private_links_parser", _SCANNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(spec.name, None)
    head = b"commit " + b"a" * 40 + b"\n\ndiff --git a/x.md b/x.md\n--- a/x.md\n+++ b/x.md\n@@ -0,0 +1,2 @@\n+one\n"
    # An unknown line inside the hunk WITH a valid line after it, so the counts still come
    # out even if the unknown one is quietly skipped; and output that simply STOPS one line
    # short (no trailing newline, so no empty last line to trip the first branch instead).
    for output in (head + b"?two\n+three\n", head[:-1]):
        monkeypatch.setattr(module, "_git", lambda *_a, _o=output, **_k: _o)
        with pytest.raises(SystemExit) as exc:
            list(module.iter_added_blocks(pathlib.Path("."), ["HEAD"]))
        assert exc.value.code == 2


# ─────────────────────────────────────────────────────────── the pre-push hook ──


@pytest.fixture
def hook_env(repo: pathlib.Path, tmp_path: pathlib.Path) -> dict[str, str]:
    """The throwaway repo carries the real scanner (untracked), and PATH carries a `task`
    stub, so the hook's `task ci-fast` passes and what is tested is its own range scan."""
    (repo / "scripts").mkdir()
    shutil.copy(_SCANNER, repo / "scripts" / "check-no-private-links.py")
    stub_bin = tmp_path / "bin"
    stub_bin.mkdir()
    (stub_bin / "task").write_text("#!/bin/sh\nexit 0\n")
    (stub_bin / "task").chmod(0o755)
    (stub_bin / "python3").symlink_to(sys.executable)
    return _env(PATH=f"{stub_bin}:{os.environ['PATH']}")


def _push(repo: pathlib.Path, env: dict[str, str], *lines: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(_HOOK), "origin", "git@example.invalid:owner/repo.git"],
        cwd=repo,
        env=env,
        input="".join(line + "\n" for line in lines),
        capture_output=True,
        text=True,
    )


def test_the_hook_scans_a_pushed_branch_that_is_not_checked_out(repo, hook_env) -> None:
    main = _git(repo, "rev-parse", "HEAD")
    _git(repo, "checkout", "-qb", "feature")
    feature = _commit(repo, _leaky_files(), "leak")
    _git(repo, "checkout", "-q", "main")
    assert _scan(repo).returncode == 0, "control: the checked-out branch is clean"

    new_ref = _push(repo, hook_env, f"refs/heads/feature {feature} refs/heads/feature {_ZERO}")
    assert new_ref.returncode == 1, new_ref.stdout + new_ref.stderr
    assert "a pushed commit adds a leak" in new_ref.stdout

    existing_ref = _push(repo, hook_env, f"refs/heads/feature {feature} refs/heads/feature {main}")
    assert existing_ref.returncode == 1, existing_ref.stdout + existing_ref.stderr

    clean = _push(repo, hook_env, f"refs/heads/main {main} refs/heads/main {_ZERO}")
    assert clean.returncode == 0, clean.stdout + clean.stderr
    assert "1 pushed ref(s) scanned" in clean.stdout


def test_the_hook_scans_history_not_just_the_tip(repo, hook_env) -> None:
    main = _git(repo, "rev-parse", "HEAD")
    _commit(repo, _leaky_files(), "leak")
    _git(repo, "rm", "-q", "deploy.sh", "guide.md")
    _git(repo, "commit", "-qm", "remove it again")
    tip = _git(repo, "rev-parse", "HEAD")
    proc = _push(repo, hook_env, f"refs/heads/main {tip} refs/heads/main {main}")
    assert proc.returncode == 1, proc.stdout + proc.stderr


def test_the_hook_falls_back_when_the_remote_tip_is_not_local(repo, hook_env) -> None:
    """Someone else pushed since the last fetch: `<remote_sha>..` cannot be computed."""
    feature = _commit(repo, _leaky_files(), "leak")
    proc = _push(repo, hook_env, f"refs/heads/main {feature} refs/heads/main {'ab' * 20}")
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "--not --remotes" in proc.stdout


def test_a_deletion_publishes_nothing_and_passes(repo, hook_env) -> None:
    proc = _push(repo, hook_env, f"(delete) {_ZERO} refs/heads/gone {'cd' * 20}")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "0 pushed ref(s) scanned" in proc.stdout


# ─────────────────────────────────────────────────────────── the CI workflow ──


def _workflow() -> dict:
    return yaml.safe_load(_WORKFLOW.read_text())


def _steps() -> list[dict]:
    return _workflow()["jobs"]["leak-scan"]["steps"]


def test_the_workflow_runs_on_every_pull_request_and_push() -> None:
    """No `branches:` and no `paths-ignore:`. A stacked PR into a non-main base, and a
    docs-only PR, are exactly the ones a filtered trigger would skip in silence."""
    # PyYAML reads the bare key `on` as the boolean True.
    triggers = _workflow().get("on", _workflow().get(True))
    assert set(triggers) >= {"pull_request", "push"}
    for event in ("pull_request", "push"):
        config = triggers[event] or {}
        assert not {"branches", "branches-ignore", "paths", "paths-ignore", "tags"} & set(config), (event, config)


def test_the_workflow_is_read_only_and_fetches_history() -> None:
    wf = _workflow()
    assert wf["permissions"] == {"contents": "read"}
    checkout = next(s for s in _steps() if str(s.get("uses", "")).startswith("actions/checkout@"))
    assert checkout["with"]["fetch-depth"] == 0


def test_every_scan_in_the_workflow_is_redacted() -> None:
    scans = [s["run"] for s in _steps() if "check-no-private-links.py" in s.get("run", "")]
    assert len(scans) >= 2, "the tree scan and the range scan steps were not found"
    for run in scans:
        for line in run.splitlines():
            if "check-no-private-links.py" in line and "python3" in line:
                assert "--redact" in line, line


def _step_named(fragment: str) -> dict:
    return next(s for s in _steps() if fragment in s.get("name", ""))


def _run_step(step: dict, *, cwd: pathlib.Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["bash", "-c", step["run"]], cwd=cwd, env=env, capture_output=True, text=True)


def test_the_workflow_self_test_step_passes_against_the_real_scanner(tmp_path) -> None:
    """The step's own shell, executed. It is what makes a scanner that silently does nothing
    turn the job red, so it must itself be seen to pass for the right reason."""
    step = _step_named("Self-test")
    proc = _run_step(
        step,
        cwd=tmp_path,
        env=_env(GITHUB_ACTIONS="true", RUNNER_TEMP=str(tmp_path), GITHUB_WORKSPACE=str(_REPO)),
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "self-test exits: tree-with-leak=1 tree-cleaned=0 history-range=1" in proc.stdout
    assert "LEAK-SCAN SELF-TEST PASSED" in proc.stdout


def test_the_workflow_self_test_fails_when_the_scanner_does_nothing(tmp_path) -> None:
    """The failure the self-test exists for: a scanner that exits 0 on everything."""
    workspace = tmp_path / "workspace"
    (workspace / "scripts").mkdir(parents=True)
    (workspace / "scripts" / "check-no-private-links.py").write_text("import sys\nsys.exit(0)\n")
    proc = _run_step(
        _step_named("Self-test"),
        cwd=tmp_path,
        env=_env(GITHUB_ACTIONS="true", RUNNER_TEMP=str(tmp_path), GITHUB_WORKSPACE=str(workspace)),
    )
    assert proc.returncode == 1 and "::error::leak-scan self-test" in proc.stdout


def test_the_workflow_range_step_scans_the_pull_requests_commits(repo, hook_env) -> None:
    """The step's own shell, with the event fields a pull_request carries."""
    base = _git(repo, "rev-parse", "HEAD")
    _commit(repo, _leaky_files(), "leak")
    _git(repo, "rm", "-q", "deploy.sh", "guide.md")
    head = _commit(repo, {"README.md": "still clean\n"}, "remove it again")
    step = _step_named("Scan every line")
    event = {"GITHUB_ACTIONS": "true", "EVENT": "pull_request", "PR_BASE": base, "PR_HEAD": head}
    proc = _run_step(step, cwd=repo, env={**hook_env, **event})
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "deploy.sh:1: ssh-target" in proc.stderr

    missing = _run_step(step, cwd=repo, env={**hook_env, **event, "PR_BASE": "ab" * 20})
    assert missing.returncode == 1 and "is not in the checkout" in missing.stdout
