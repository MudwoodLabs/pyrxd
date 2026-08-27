"""Ops scripts write real keys to disk. The files they choose must not be attacker-reachable.

`0cf3ceb` fixed a symlink clobber in the dMint runner's state file and shipped with no test, which
is how the same weakness survived in a second form: `O_NOFOLLOW` answers "is this a symlink" and
says nothing about "did another user create this ordinary file". `O_CREAT` leaves an EXISTING
file's mode alone, so a pre-placed world-readable file at a fixed, predictable path passes the open
and then receives the carve UTXOs' WIFs.

Driven through the scripts' own `_save`/`_load`, with the state path redirected into a temp
directory, so these exercise the real code rather than a restatement of it.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest

_SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"


@pytest.fixture(scope="module")
def dmint():
    sys.path.insert(0, str(_SCRIPTS))
    try:
        spec = importlib.util.spec_from_file_location("dmint_state", _SCRIPTS / "dmint_v2_mainnet_run.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    finally:
        sys.path.remove(str(_SCRIPTS))


@pytest.fixture
def state(dmint, tmp_path, monkeypatch):
    p = tmp_path / "state.json"
    monkeypatch.setattr(dmint, "_STATE", str(p))
    return p


class TestThePathItself:
    def test_the_state_does_not_live_in_a_world_writable_directory(self, dmint) -> None:
        """The precondition, removed rather than defended against. Every attack below needs the
        attacker to create or replace a file at a path they can predict AND write."""
        assert not dmint._STATE.startswith("/tmp"), (
            f"run state is at {dmint._STATE}; a fixed path in a world-writable directory can be "
            "pre-created by another user, and this file holds real keys"
        )


class TestTheRoundTripStillWorks:
    """Paired with every refusal. An ops script that cannot persist its state cannot resume, and
    the dMint run this protects mints on RXD mainnet."""

    def test_save_then_load_returns_what_was_written(self, dmint, state) -> None:
        dmint._save({"stage": "deployed", "key": "ab" * 32})
        assert dmint._load() == {"stage": "deployed", "key": "ab" * 32}

    def test_the_file_it_creates_is_private(self, dmint, state) -> None:
        dmint._save({"stage": "deployed"})
        assert state.stat().st_mode & 0o077 == 0, oct(state.stat().st_mode)

    def test_it_can_be_REWRITTEN_as_the_run_progresses(self, dmint, state) -> None:
        """Why this is not simply `atomic_write_mode_600`: that helper is O_EXCL and create-only,
        and this state is updated at each stage."""
        dmint._save({"stage": "deployed"})
        dmint._save({"stage": "minted"})
        assert dmint._load()["stage"] == "minted"

    def test_it_creates_its_own_directory(self, dmint, tmp_path, monkeypatch) -> None:
        monkeypatch.setattr(dmint, "_STATE", str(tmp_path / "nested" / "deep" / "state.json"))
        dmint._save({"stage": "deployed"})
        assert dmint._load()["stage"] == "deployed"


class TestWhatItRefuses:
    def test_a_symlink_is_refused_on_WRITE(self, dmint, state, tmp_path) -> None:
        """The original finding: O_CREAT|O_TRUNC followed a pre-placed symlink and truncated
        whatever it pointed at, and the symlink survived so the attack repeated."""
        victim = tmp_path / "victim.txt"
        victim.write_text("important")
        Path(state).symlink_to(victim)
        with pytest.raises(OSError):
            dmint._save({"stage": "deployed"})
        assert victim.read_text() == "important", "the victim file was truncated through a symlink"

    def test_a_symlink_is_refused_on_READ(self, dmint, state, tmp_path) -> None:
        """The more dangerous half: substituting the WIFs and outpoints the run then acts on."""
        planted = tmp_path / "planted.json"
        planted.write_text(json.dumps({"stage": "deployed", "key": "ff" * 32}))
        Path(state).symlink_to(planted)
        with pytest.raises(OSError):
            dmint._load()

    def test_a_PRE_CREATED_world_readable_file_does_not_receive_the_keys(self, dmint, state) -> None:
        """What O_NOFOLLOW alone did not cover. No symlink is involved: an ordinary file at the
        predictable path, mode 666, created before the run. O_CREAT does not re-apply the mode to
        an existing file, so the open succeeds and the keys land somewhere readable."""
        state.write_text("")
        state.chmod(0o666)
        with pytest.raises(SystemExit, match="accessible to other users"):
            dmint._save({"stage": "deployed", "key": "ab" * 32})
        assert "ab" * 32 not in state.read_text(), "keys were written into a world-readable file"

    def test_a_PRE_PLANTED_world_readable_file_is_not_READ_either(self, dmint, state) -> None:
        """The read side of the same precondition: state another user can rewrite chooses which
        UTXOs and keys the run acts on."""
        state.write_text(json.dumps({"stage": "deployed", "key": "ff" * 32}))
        state.chmod(0o644)
        with pytest.raises(SystemExit, match="accessible to other users"):
            dmint._load()

    def test_a_non_regular_file_is_refused_without_HANGING(self, dmint, state) -> None:
        """Opening a FIFO for reading blocks until a writer appears. Without O_NONBLOCK this does
        not fail — it never returns, and an ops run wedges with no message. Guarded by SIGALRM
        because "the suite never finishes" is a far worse signal than an assertion."""
        import signal

        os.mkfifo(state, 0o600)

        def _blocked(_sig, _frame):
            raise AssertionError(
                "opening the state file BLOCKED — O_NONBLOCK is missing, so a FIFO at this path "
                "wedges the run instead of being refused"
            )

        old = signal.signal(signal.SIGALRM, _blocked)
        signal.setitimer(signal.ITIMER_REAL, 5.0)
        try:
            with pytest.raises((SystemExit, OSError)):
                dmint._load()
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, old)
