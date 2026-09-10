"""The repo asks agents to work in linked worktrees, and its own git tooling could not.

Two instances of one blindness, both found by hitting them:

* ``scripts/git-hooks/pre-push`` located the venv with ``git rev-parse --show-toplevel``, which is
  the CURRENT worktree. A linked worktree has no ``.venv`` — it lives in the main checkout — so
  every push made from one aborted with a bare "task not found".
* ``scripts/install-git-hooks.sh`` targeted ``${REPO_ROOT}/.git/hooks``. In a linked worktree
  ``.git`` is a FILE pointing at the real repo, not a directory, so the installer refused with
  "are you inside the pyrxd git repo?" — from inside the repo.

``--git-common-dir`` answers both: it resolves to the one shared git directory from any worktree.

RUN AGAINST A THROWAWAY REPO, never this one. The installer writes into a hooks directory; pointed
at the developer's own checkout it would rewrite their live hooks from a test run. The fixture
builds a tiny repo, copies the two scripts in, and adds a real linked worktree to it.
"""

from __future__ import annotations

import os
import pathlib
import shutil
import subprocess

import pytest

_REPO = pathlib.Path(__file__).resolve().parent.parent
_SCRIPTS = _REPO / "scripts"


def _git(*args: str, cwd: pathlib.Path) -> str:
    env = {
        **os.environ,
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@example.invalid",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.invalid",
    }
    return subprocess.run(["git", *args], cwd=cwd, env=env, capture_output=True, text=True, check=True).stdout.strip()


@pytest.fixture
def sandbox(tmp_path: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path]:
    """``(main checkout, linked worktree)`` of a throwaway repo carrying the real scripts."""
    main = tmp_path / "main"
    main.mkdir()
    _git("init", "-q", "-b", "main", cwd=main)
    shutil.copytree(_SCRIPTS, main / "scripts")
    _git("add", "-A", cwd=main)
    _git("commit", "-qm", "scripts", cwd=main)

    linked = tmp_path / "linked"
    _git("worktree", "add", "-q", str(linked), "-b", "wt", cwd=main)

    # THE VENV IS CREATED AFTER THE WORKTREE, AND NEVER COMMITTED. `.venv` is gitignored in the
    # real repo, so it exists only in the checkout that built it. An earlier version of this
    # fixture committed the stub, which checked it out into the linked worktree too — the exact
    # situation the code under test cannot be in, and the fixture's own assertion below caught it.
    (main / ".venv" / "bin").mkdir(parents=True)
    stub = main / ".venv" / "bin" / "task"
    stub.write_text("#!/bin/sh\nexit 0\n")
    stub.chmod(0o755)
    assert (linked / ".git").is_file(), "a linked worktree's .git must be a file for this to test"
    assert not (linked / ".venv").exists(), "the linked worktree must not have its own venv"
    return main, linked


def test_the_installer_runs_from_a_linked_worktree(sandbox) -> None:
    main, linked = sandbox
    proc = subprocess.run(
        ["bash", str(linked / "scripts" / "install-git-hooks.sh")],
        cwd=linked,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, f"installer failed from a worktree:\n{proc.stdout}\n{proc.stderr}"

    installed = main / ".git" / "hooks" / "pre-push"
    assert installed.exists(), "the hook did not land in the shared hooks directory"
    assert not (linked / ".git" / "hooks").exists(), "a per-worktree hooks dir was created"


def test_the_installed_hook_outlives_the_worktree_it_was_installed_from(sandbox) -> None:
    """The symlink must point at the MAIN checkout. Pointing it into the worktree works until
    that worktree is removed, then leaves a dangling hook for EVERY checkout — silently
    disabling the pre-push checks repo-wide, which is worse than the failure being fixed."""
    main, linked = sandbox
    subprocess.run(
        ["bash", str(linked / "scripts" / "install-git-hooks.sh")],
        cwd=linked,
        capture_output=True,
        text=True,
        check=True,
    )

    installed = main / ".git" / "hooks" / "pre-push"
    target = pathlib.Path(os.path.realpath(installed))
    assert linked not in target.parents, f"the shared hook points into the worktree: {target}"

    _git("worktree", "remove", "--force", str(linked), cwd=main)
    assert installed.exists() and target.exists(), "the hook dangled once the worktree was removed"


def test_the_hook_finds_the_venv_from_a_linked_worktree(sandbox) -> None:
    """The failure that started this: `task` is in the main checkout's venv, not the worktree's."""
    main, linked = sandbox
    hook = linked / "scripts" / "git-hooks" / "pre-push"
    block = (
        "\n".join(line for line in hook.read_text().split("\n") if not line.startswith("#"))
        .split("if ! command -v task")[1]
        .split("say ")[0]
    )

    probe = f"""
set -euo pipefail
export PATH="/usr/bin:/bin"
if ! command -v task{block}
command -v task || echo NOTFOUND
"""
    out = subprocess.run(["bash", "-c", probe], cwd=linked, capture_output=True, text=True)
    assert "NOTFOUND" not in out.stdout, (
        f"the hook could not find the venv from a linked worktree:\n{out.stdout}\n{out.stderr}"
    )
    assert str(main) in out.stdout, f"resolved somewhere unexpected: {out.stdout!r}"
