"""A signing key belongs in a file the process opens, not in the argument vector.

`--eth-key-hex` puts a live private key where every local user can read it — `ps` shows the full
argument vector for the life of the process — and where the shell keeps it afterwards. The file
flag existed to fix that and had **no callers**: it was defined on one runner, and every document
and every other ETH runner still showed `--eth-key-hex`. A safer option nobody is pointed at is
not a mitigation, so the loader is shared and the flags are defined once for all three runners.

The loader is driven here through the runners' real argument parsing, not by calling it directly.
"""

from __future__ import annotations

import importlib.util
import os
import stat
import sys
from pathlib import Path

import pytest

_SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
_KEY = "ab" * 32


def _load(name: str):
    sys.path.insert(0, str(_SCRIPTS))
    try:
        spec = importlib.util.spec_from_file_location(f"{name}_under_test", _SCRIPTS / f"{name}.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    finally:
        sys.path.remove(str(_SCRIPTS))


@pytest.fixture(scope="module")
def shared():
    return _load("_dust_swap_shared")


@pytest.fixture
def keyfile(tmp_path: Path) -> Path:
    p = tmp_path / "eth.key"
    p.write_text(_KEY)
    p.chmod(0o600)
    return p


def _args(shared, **kw):
    import argparse

    ns = argparse.Namespace(eth_key_file="", eth_key_hex="")
    for k, v in kw.items():
        setattr(ns, k, v)
    shared.resolve_eth_key_file(ns)
    return ns


class TestTheHonestPath:
    """Paired with every refusal below. A loader that refuses a correct key file has replaced a
    disclosure risk with an inability to run, and a swap that cannot sign cannot refund either."""

    def test_a_mode_600_file_owned_by_the_caller_is_READ(self, shared, keyfile: Path) -> None:
        assert _args(shared, eth_key_file=str(keyfile)).eth_key_hex == _KEY

    def test_trailing_whitespace_and_a_newline_are_tolerated(self, shared, tmp_path: Path) -> None:
        """`printf` and `echo >` differ by exactly one byte, and an operator mid-swap should not
        lose a run to it. The key is hex, so surrounding whitespace cannot be significant."""
        p = tmp_path / "k"
        p.write_text(f"  {_KEY}\n")
        p.chmod(0o600)
        assert _args(shared, eth_key_file=str(p)).eth_key_hex == _KEY

    def test_the_hex_flag_still_works_for_throwaway_keys(self, shared) -> None:
        assert _args(shared, eth_key_hex="00" * 32).eth_key_hex == "00" * 32


class TestWhatItRefuses:
    def test_a_group_or_world_readable_file(self, shared, keyfile: Path) -> None:
        keyfile.chmod(0o644)
        with pytest.raises(SystemExit, match="readable by other users"):
            _args(shared, eth_key_file=str(keyfile))

    def test_a_symlink_standing_in_for_the_key_file(self, shared, tmp_path: Path, keyfile: Path) -> None:
        """O_NOFOLLOW. The mode and owner of a symlink say nothing about its target."""
        link = tmp_path / "link.key"
        link.symlink_to(keyfile)
        with pytest.raises(SystemExit, match="cannot open"):
            _args(shared, eth_key_file=str(link))

    def test_a_non_regular_file(self, shared, tmp_path: Path) -> None:
        """A FIFO passes a mode check and is not a key file. It must also not HANG the open —
        opening a FIFO for reading blocks until a writer appears, and O_NONBLOCK is what turns an
        indefinite wait into a message.

        Guarded by SIGALRM rather than left to hang: removing O_NONBLOCK makes this test block
        forever, and "the suite never finishes" is a far worse signal than a failed assertion —
        especially in CI, where it looks like infrastructure trouble rather than a defect.
        """
        import signal

        fifo = tmp_path / "k.fifo"
        os.mkfifo(fifo, 0o600)

        def _blocked(_sig, _frame):
            raise AssertionError(
                "opening the key file BLOCKED — O_NONBLOCK is missing, so a FIFO (or any path "
                "with no writer) hangs the runner instead of being refused"
            )

        old = signal.signal(signal.SIGALRM, _blocked)
        signal.setitimer(signal.ITIMER_REAL, 5.0)
        try:
            with pytest.raises(SystemExit, match="not a regular file"):
                _args(shared, eth_key_file=str(fifo))
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, old)

    def test_both_flags_at_once(self, shared, keyfile: Path) -> None:
        """Silently preferring one would make it unclear which key signed."""
        with pytest.raises(SystemExit, match="not both"):
            _args(shared, eth_key_file=str(keyfile), eth_key_hex="00" * 32)

    def test_a_missing_file_names_the_path(self, shared, tmp_path: Path) -> None:
        with pytest.raises(SystemExit, match="cannot open"):
            _args(shared, eth_key_file=str(tmp_path / "nope"))


class TestTheCheckIsOnTheDescriptorItReads:
    def test_the_mode_is_read_from_the_OPEN_descriptor(self, shared) -> None:
        """Structural half: `stat()` then `read_text()` checks one file and reads another, so the
        implementation must go through fd-based calls and never through the path-based ones.

        Checked against the AST, not the text. A first version of this scanned the source for
        `.stat()` and matched the DOCSTRING that explains the race, so it failed on a correct
        implementation. A test a comment can break is a test a comment can also satisfy.

        WHAT CAN SATISFY THIS CHECK WITHOUT THE PROPERTY HOLDING — a token-presence scan sees
        WHICH functions are called, not WHICH DESCRIPTOR each acts on:
          1. fstat fd1, then `os.open` the path AGAIN and `os.read` fd2 — the exact TOCTOU this
             loader exists to prevent, with every required token present and every banned token
             absent. CLOSED by the race test below, which swaps the file at the path the instant
             the first open returns: any second pathname resolution reads the planted decoy and
             the content assertion fails.
          2. fstat some OTHER descriptor entirely and read the real one — right tokens, check
             inspects the wrong file. CLOSED by pairing: `TestWhatItRefuses` proves a 0644 key
             file is REFUSED, which an implementation whose fstat looks at an unrelated
             (well-permissioned) fd cannot do.
        """
        import ast

        tree = ast.parse((_SCRIPTS / "_dust_swap_shared.py").read_text())
        fn = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "read_own_private_file")
        calls = {n.func.attr for n in ast.walk(fn) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}
        assert "fstat" in calls, "the mode must come from the descriptor, not from the path"
        assert "read" in calls, "the bytes must come from the same descriptor that was checked"
        assert "stat" not in calls, "a path-based stat() re-introduces the race"
        assert "read_text" not in calls, "read_text() opens the path a second time"
        assert "open" in calls, "the file must be opened by descriptor"

    def test_a_swap_of_the_path_at_the_open_boundary_cannot_change_what_is_read(
        self, shared, tmp_path: Path, monkeypatch
    ) -> None:
        """Behavioral half: STAGE the race instead of hoping to lose it. The moment the loader's
        first `os.open` of the key path returns, this test atomically renames a different
        (equally well-permissioned, so nothing refuses) key file over that path. A correct
        implementation holds a descriptor pinned to the ORIGINAL inode — fstat and read both act
        on it, and the swap changes nothing. Any implementation that touches the PATHNAME a
        second time after the check (a re-open, a `read_text`, a second `os.open` for the read)
        gets the decoy, and the assertion on the returned key catches it.

        This is the assertion the AST test above cannot make: not "the right functions appear"
        but "the bytes returned came from the same descriptor that was permission-checked".
        """
        victim = tmp_path / "eth.key"
        victim.write_text(_KEY)
        victim.chmod(0o600)
        decoy = tmp_path / "decoy.key"
        decoy.write_text("cd" * 32)  # a VALID key, mode 600, same owner: a re-open succeeds quietly
        decoy.chmod(0o600)

        real_open = os.open
        swaps = {"count": 0}

        def racing_open(path, flags, *args, **kwargs):
            fd = real_open(path, flags, *args, **kwargs)
            if str(path) == str(victim) and swaps["count"] == 0:
                swaps["count"] = 1
                os.rename(decoy, victim)  # atomic: the path now names a different file
            return fd

        monkeypatch.setattr(os, "open", racing_open)
        ns = _args(shared, eth_key_file=str(victim))
        assert swaps["count"] == 1, "the loader never opened the key path — this test raced nothing"
        assert ns.eth_key_hex == _KEY, (
            "the loader returned the DECOY key: something re-resolved the pathname after the "
            "descriptor was opened and checked, which is exactly the check-one-file-read-another "
            "race the fd discipline exists to prevent"
        )


class TestEveryEthRunnerOffersIt:
    """The finding was not that the flag was wrong — it was that it existed on one script while
    the documented two-host flow, the one a real two-party run uses, still took a key on argv."""

    @pytest.mark.parametrize("script", ["eth_swap_run", "eth_swap_two_host", "eth_swap_grief_run"])
    def test_the_flag_is_accepted_and_resolves(self, script: str, keyfile: Path) -> None:
        mod = _load(script)
        src = (_SCRIPTS / f"{script}.py").read_text()
        assert "add_eth_key_arguments(ap)" in src, f"{script} defines its own key flags"
        assert "resolve_eth_key_file(args)" in src, f"{script} parses the flag but never resolves it"
        assert mod is not None

    def test_no_doc_still_shows_a_key_on_the_command_line(self) -> None:
        """The reachability half, as a test. `--eth-key-hex <something>` in a how-to is an
        instruction to leak a key, and it is how the safer flag came to have no callers."""
        import re

        docs = Path(__file__).resolve().parent.parent / "docs"
        offenders = [
            f"{p.relative_to(docs.parent)}:{i}"
            for p in docs.rglob("*.md")
            if "brainstorms" not in p.parts and "plans" not in p.parts
            for i, line in enumerate(p.read_text().splitlines(), 1)
            if re.search(r"--eth-key-hex\s+\S", line)
        ]
        assert not offenders, f"docs still pass a key on the command line: {offenders}"


def test_the_recovery_file_gets_the_same_treatment(shared, tmp_path: Path) -> None:
    """It holds the preimage and both RXD keys — everything needed to steer a resume — and was
    read with a plain `read_text()`, so on a shared directory another account could plant one and
    choose the covenant a resume rebuilt."""
    p = tmp_path / "rec.json"
    p.write_text('{"ok": 1}')
    p.chmod(0o600)
    assert shared.read_own_private_file(p, what="swap state") == '{"ok": 1}'
    p.chmod(0o666)
    with pytest.raises(SystemExit, match="readable by other users"):
        shared.read_own_private_file(p, what="swap state")
    assert stat.S_ISREG(p.stat().st_mode)
