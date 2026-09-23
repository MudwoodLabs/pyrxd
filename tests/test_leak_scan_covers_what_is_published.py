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
import json
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


def _push(
    repo: pathlib.Path, env: dict[str, str], *lines: str, remote: str = "origin"
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(_HOOK), remote, "git@example.invalid:owner/repo.git"],
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
    assert "self-test exits: tree-with-leak=1 tree-cleaned=0 history-range=1 commit-message=1" in proc.stdout
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
    _write_baseline(repo, [])
    step = _step_named("Scan what this PR or push publishes")
    event = {"GITHUB_ACTIONS": "true", "EVENT": "pull_request", "PR_BASE": base, "PR_HEAD": head}
    proc = _run_step(step, cwd=repo, env={**hook_env, **event})
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "deploy.sh:1: ssh-target" in proc.stderr

    missing = _run_step(step, cwd=repo, env={**hook_env, **event, "PR_BASE": "ab" * 20})
    assert missing.returncode == 1 and "is not in the checkout" in missing.stdout


# ───────────────────────────────────────────── what a commit publishes besides lines ──


def test_a_leak_in_a_commit_message_is_caught(repo) -> None:
    """A squash-merge's message is the PR body, and it is published like the diff."""
    base = _git(repo, "rev-parse", "HEAD")
    _write(repo, {"a.txt": "ok\n"})
    _git(repo, "add", "a.txt")
    _git(repo, "commit", "-qm", "fix deploy", "-m", f"was run as: ssh {_SSH_LEAK} restart")
    assert _scan(repo).returncode == 0, "control: the tree is clean"
    proc = _scan(repo, "--no-tree", "--range", f"{base}..HEAD")
    assert proc.returncode == 1, proc.stdout + proc.stderr
    sha = _git(repo, "rev-parse", "HEAD")[:12]
    assert f"{sha} (commit message):3" in proc.stderr
    redacted = _scan(repo, "--redact", "--no-tree", "--range", f"{base}..HEAD")
    assert f"{sha} (commit message):3: ssh-target" in redacted.stderr
    assert _ROUTABLE_IP not in redacted.stdout + redacted.stderr


@pytest.mark.parametrize("content", ["x\n", ""], ids=["with-content", "empty"])
def test_a_leak_in_a_file_name_is_caught_by_both_scans(repo, content) -> None:
    """An EMPTY new file has no hunk and no `+++` header, so a patch parser never saw its name."""
    base = _git(repo, "rev-parse", "HEAD")
    name = f"logs/ssh-{_SSH_LEAK}.log"
    _commit(repo, {name: content}, "add a log")
    for proc in (_scan(repo), _scan(repo, "--no-tree", "--range", f"{base}..HEAD")):
        assert proc.returncode == 1, proc.stdout + proc.stderr
        assert f"{name} (a file name)" in proc.stderr
    redacted = _scan(repo, "--redact", "--no-tree", "--range", f"{base}..HEAD")
    # The location IS the leak here, so the redacted report names a digest of it.
    assert "(a file name, sha256:" in redacted.stderr and ": ssh-target" in redacted.stderr
    assert _ROUTABLE_IP not in redacted.stdout + redacted.stderr


def test_an_annotated_tag_message_and_a_tag_name_are_caught(repo) -> None:
    _git(repo, "tag", "-a", "v0.0.1", "-m", f"deployed via {_SSH_LEAK}")
    _git(repo, "tag", f"built-on-{_ROUTABLE_IP.replace('.', '-')}")  # a clean lightweight tag
    _git(repo, "tag", f"deploy@{_ROUTABLE_IP}")  # a lightweight tag whose NAME leaks
    annotated = _scan(repo, "--no-tree", "--tag", "refs/tags/v0.0.1")
    assert annotated.returncode == 1 and "(tag message of refs/tags/v0.0.1):1" in annotated.stderr
    named = _scan(repo, "--redact", "--no-tree", "--tag", f"refs/tags/deploy@{_ROUTABLE_IP}")
    assert named.returncode == 1 and "(a tag name, sha256:" in named.stderr
    assert _ROUTABLE_IP not in named.stdout + named.stderr
    clean = _scan(repo, "--no-tree", "--tag", f"refs/tags/built-on-{_ROUTABLE_IP.replace('.', '-')}")
    assert clean.returncode == 0, clean.stdout + clean.stderr


# ─────────────────────────────────────────────────────── scope and encodings ──


@pytest.mark.parametrize("name", ["settings.py", "deploy.yml", "conf.toml", "run.sh"])
def test_a_home_path_in_any_text_file_is_caught(repo, name) -> None:
    base = _git(repo, "rev-parse", "HEAD")
    _commit(repo, {name: f"data = '{_HOME_LEAK}'\n"}, "config")
    for proc in (_scan(repo), _scan(repo, "--no-tree", "--range", f"{base}..HEAD")):
        assert proc.returncode == 1 and f"{name}:1" in proc.stderr, proc.stdout + proc.stderr


def test_the_non_personal_home_exemption_is_pinned(repo) -> None:
    """An exemption is a claim; pinning its MEMBERSHIP means any change is re-read, not inherited."""
    spec = importlib.util.spec_from_file_location("check_no_private_links_scope", _SCANNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(spec.name, None)
    assert frozenset({"pyodide"}) == module._NON_PERSONAL_HOMES
    _commit(repo, {"shared.js": 'fs.writeFile("/home/pyodide/glue.py", src);\n'}, "pyodide")
    assert _scan(repo).returncode == 0


@pytest.mark.parametrize(
    ("name", "text"),
    [("deploy.ps1", f"ssh {_SSH_LEAK}\r\n"), ("notes.md", f"see {_HOME_LEAK}\r\n")],
)
@pytest.mark.parametrize("encoding", ["utf-16", "utf-16-le", "utf-16-be"])
def test_a_utf16_file_does_not_hide_a_leak(repo, name, text, encoding) -> None:
    """UTF-16 gives every ASCII character a zero byte, so read as UTF-8 it was noise."""
    base = _git(repo, "rev-parse", "HEAD")
    _commit(repo, {name: ("first line\r\n" + text).encode(encoding)}, "utf-16")
    for proc in (_scan(repo), _scan(repo, "--no-tree", "--range", f"{base}..HEAD")):
        assert proc.returncode == 1 and f"{name}:2" in proc.stderr, proc.stdout + proc.stderr


def test_a_utf16_leak_added_mid_file_is_caught_by_the_range_scan(repo) -> None:
    """The range scan sees a UTF-16 file as runs of added lines split at `0a` bytes, so a run
    can start on the second byte of a character — which is why both alignments are read."""
    lines = [f"line {i}\r\n" for i in range(5)]
    _commit(repo, {"notes.ps1": "".join(lines).encode("utf-16-le")}, "clean")
    base = _git(repo, "rev-parse", "HEAD")
    lines.insert(3, f"ssh {_SSH_LEAK}\r\n")
    _commit(repo, {"notes.ps1": "".join(lines).encode("utf-16-le")}, "leak mid-file")
    proc = _scan(repo, "--no-tree", "--range", f"{base}..HEAD")
    assert proc.returncode == 1, proc.stdout + proc.stderr


def test_a_utf16_run_starting_mid_character_is_realigned(repo) -> None:
    """The case the second byte alignment exists for. An ASCII leak in such a run happens to read
    correctly as the OTHER endianness, so the test above passes without it; a name past U+00FF
    does not. Only a private name can be one, so this uses a local `.private-names` list."""
    (repo / ".private-names").write_text("\u03a9mega-\u0444\n")  # Omega and Cyrillic ef: past Latin-1
    lines = [f"line {i}\r\n" for i in range(5)]
    _commit(repo, {"notes.md": "".join(lines).encode("utf-16-le")}, "clean")
    base = _git(repo, "rev-parse", "HEAD")
    lines.insert(3, "credit to \u03a9mega-\u0444\r\n")
    _commit(repo, {"notes.md": "".join(lines).encode("utf-16-le")}, "name mid-file")
    proc = _scan(repo, "--no-tree", "--range", f"{base}..HEAD")
    assert proc.returncode == 1 and "notes.md:4" in proc.stderr, proc.stdout + proc.stderr


# ───────────────────────────────────────────────────────────────── the baseline ──


def _write_baseline(repo: pathlib.Path, entries: list[str], commit: str | None = None) -> pathlib.Path:
    path = repo / "scripts" / "leak-scan-baseline.json"
    path.parent.mkdir(exist_ok=True)
    path.write_text(json.dumps({"meta": {"commit": commit or _git(repo, "rev-parse", "HEAD")}, "entries": entries}))
    return path


def _historical_leak(repo: pathlib.Path) -> tuple[str, str]:
    """A leak committed and removed: ``(commit before it, commit after its removal)``."""
    before = _git(repo, "rev-parse", "HEAD")
    _commit(repo, _leaky_files(), "leak")
    _git(repo, "rm", "-q", "deploy.sh", "guide.md")
    _git(repo, "commit", "-qm", "remove it again")
    return before, _git(repo, "rev-parse", "HEAD")


def test_the_baseline_suppresses_exactly_the_known_findings(repo, tmp_path) -> None:
    _before, after = _historical_leak(repo)
    baseline = tmp_path / "baseline.json"
    wrote = _scan(repo, "--no-tree", "--range", after, "--write-baseline", str(baseline))
    assert wrote.returncode == 0 and "wrote 2 baseline" in wrote.stdout, wrote.stdout + wrote.stderr
    assert _scan(repo, "--no-tree", "--range", "HEAD").returncode == 1, "control: without it, history fails"

    known = _scan(repo, "--no-tree", "--range", "HEAD", "--baseline", str(baseline))
    assert known.returncode == 0, known.stdout + known.stderr
    assert "2 known historical finding(s) suppressed by the baseline" in known.stdout

    # The SAME file, path and check in a NEW commit is a new finding: the key is the commit.
    _commit(repo, _leaky_files(), "the same leak again")
    again = _scan(repo, "--no-tree", "--range", "HEAD", "--baseline", str(baseline))
    assert again.returncode == 1 and "deploy.sh:1" in again.stderr


def test_the_baseline_check_is_exact_in_both_directions(repo, tmp_path) -> None:
    _before, after = _historical_leak(repo)
    baseline = tmp_path / "baseline.json"
    _scan(repo, "--no-tree", "--range", after, "--write-baseline", str(baseline))
    exact = _scan(repo, "--check-baseline", str(baseline))
    assert exact.returncode == 0 and "0 finding(s) not listed, 0 entr(ies) matching nothing" in exact.stdout

    document = json.loads(baseline.read_text())
    assert document["meta"]["commit"] == after
    for label, entries in (
        ("an entry that matches nothing", [*document["entries"], "ab" * 32]),
        ("a finding that is not listed", document["entries"][1:]),
    ):
        edited = tmp_path / f"{label}.json"
        edited.write_text(json.dumps({**document, "entries": entries}))
        proc = _scan(repo, "--check-baseline", str(edited))
        assert proc.returncode == 1, (label, proc.stdout)


def test_the_committed_baseline_holds_digests_not_locations() -> None:
    """The file is public. A readable list of where the old leaks are would be an index to them."""
    document = json.loads((_REPO / "scripts" / "leak-scan-baseline.json").read_text())
    assert len(document["meta"]["commit"]) == 40
    assert document["meta"]["entries"] == len(document["entries"]) > 0
    assert all(len(e) == 64 and set(e) <= set("0123456789abcdef") for e in document["entries"])


# ──────────────────────────────────────────────── the hook refuses no honest push ──


def test_a_push_to_a_second_remote_does_not_rescan_what_another_remote_has(repo, hook_env) -> None:
    """The history `origin` already has is not rescanned when pushing to a fork that has no
    tracking refs — it was refusing honest pushes over findings published long ago."""
    _historical_leak(repo)
    _git(repo, "update-ref", "refs/remotes/origin/main", "HEAD")
    _git(repo, "remote", "add", "fork", "git@example.invalid:someone/fork.git")  # no tracking refs
    clean = _commit(repo, {"new.txt": "clean\n"}, "new work")
    proc = _push(repo, hook_env, f"refs/heads/main {clean} refs/heads/main {_ZERO}", remote="fork")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "1 commit(s)" in proc.stdout

    leaky = _commit(repo, {"more.sh": f"ssh {_SSH_LEAK}\n"}, "new leak")
    assert _push(repo, hook_env, f"refs/heads/main {leaky} refs/heads/main {_ZERO}", remote="fork").returncode == 1


def test_a_locally_tagged_unpushed_leak_is_still_scanned(repo, hook_env) -> None:
    """Why the hook excludes `--remotes` and NOT `--tags`: a tag made locally and never pushed
    would otherwise hide the commits under it from the push that publishes them."""
    _git(repo, "update-ref", "refs/remotes/origin/main", "HEAD")
    leaky = _commit(repo, {"deploy.sh": f"ssh {_SSH_LEAK}\n"}, "leak")
    _git(repo, "tag", "local-only", leaky)
    proc = _push(repo, hook_env, f"refs/heads/main {leaky} refs/heads/main {_ZERO}")
    assert proc.returncode == 1, proc.stdout + proc.stderr


def test_a_pushed_tag_is_scanned_for_its_message(repo, hook_env) -> None:
    _git(repo, "update-ref", "refs/remotes/origin/main", "HEAD")
    _git(repo, "tag", "-a", "v1", "-m", f"released from {_HOME_LEAK}")
    tag = _git(repo, "rev-parse", "refs/tags/v1")
    proc = _push(repo, hook_env, f"refs/tags/v1 {tag} refs/tags/v1 {_ZERO}")
    assert proc.returncode == 1 and "(tag message of refs/tags/v1)" in proc.stderr, proc.stdout + proc.stderr


def test_the_hook_runs_the_scanner_beside_it_not_the_checked_out_one(repo, hook_env, tmp_path) -> None:
    """A worktree branched before the scanner learned --range carries a scanner that refuses
    those arguments. Run through a SYMLINK, the way the installer installs the hook."""
    (repo / "scripts" / "check-no-private-links.py").write_text(
        "import sys\nprint('an old scanner: unrecognized arguments', file=sys.stderr)\nsys.exit(2)\n"
    )
    installed = tmp_path / "hooks" / "pre-push"
    installed.parent.mkdir()
    installed.symlink_to(_HOOK)
    clean = _git(repo, "rev-parse", "HEAD")
    proc = subprocess.run(
        ["bash", str(installed), "origin", "git@example.invalid:owner/repo.git"],
        cwd=repo,
        env=hook_env,
        input=f"refs/heads/main {clean} refs/heads/main {_ZERO}\n",
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "old scanner" not in proc.stderr


# ─────────────────────────────────────────────────────────── the workflow, again ──


def test_a_force_push_to_the_default_branch_scans_the_new_history(repo, hook_env) -> None:
    """`after --not origin/<default>` is EMPTY by construction for a push to the default branch
    itself, so a force-push there scanned nothing. It now scans the new tip's whole history,
    with the baseline suppressing exactly the known historical findings."""
    _before, after = _historical_leak(repo)
    baseline = _write_baseline(repo, [])
    _scan(repo, "--no-tree", "--range", after, "--write-baseline", str(baseline))
    step = _step_named("Scan what this PR or push publishes")
    event = {
        "GITHUB_ACTIONS": "true",
        "EVENT": "push",
        "PUSH_BEFORE": "ab" * 20,  # the overwritten tip: gone from the checkout
        "PUSH_AFTER": after,
        "PUSH_REF": "refs/heads/main",
    }
    clean = _run_step(step, cwd=repo, env={**hook_env, **event})
    assert clean.returncode == 0, clean.stdout + clean.stderr
    assert "range: " + after in clean.stdout and "known historical finding(s) suppressed" in clean.stdout

    leaky = _commit(repo, {"new.sh": f"ssh {_SSH_LEAK}\n"}, "rewritten history, new leak")
    proc = _run_step(step, cwd=repo, env={**hook_env, **event, "PUSH_AFTER": leaky})
    assert proc.returncode == 1 and "new.sh:1: ssh-target" in proc.stderr, proc.stdout + proc.stderr


def test_push_runs_are_never_cancelled_or_displaced() -> None:
    concurrency = _workflow()["concurrency"]
    group = concurrency["group"]
    assert "github.sha" in group and "github.ref" in group, group
    assert "pull_request.number" in group
    assert concurrency["cancel-in-progress"] == "${{ github.event_name == 'pull_request' }}"


def test_the_workflow_pins_the_baseline_against_full_history() -> None:
    runs = [s.get("run", "") for s in _steps()]
    assert any("--check-baseline scripts/leak-scan-baseline.json" in run for run in runs)
    checkout = next(s for s in _steps() if str(s.get("uses", "")).startswith("actions/checkout@"))
    assert checkout["with"]["fetch-depth"] == 0, "the pin rescans history a shallow clone does not have"
