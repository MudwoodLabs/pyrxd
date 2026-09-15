"""Three residuals from the adversarial RE-REVIEW of the TIMELOCK write-side fixes.

Every one of them is a fix that was correct on the path it was written for and absent, false
or advisory on the path beside it — the shape this repo keeps hitting: the branch you did not
build for is the one that ships broken.

1. **The judged-height display reached nobody on any unattended path.** ``confirm_action``
   returned ``True`` on ``ctx.yes`` *before* echoing the summary, so ``--yes`` skipped the
   disclosure along with the question — and ``--json`` REQUIRES ``--yes`` for a destructive op
   (:meth:`~pyrxd.cli.context.CliContext.is_destructive_mode_safe`), so the automated reveal the
   field was added for was the one run that never saw it. The shipped test pinned the line under
   ``--dry-run``, which takes a different print branch entirely and never reaches the prompt.
2. **``*** EARLY REVEAL: 0 seconds short of the unlock point`` for a lock the gate could not
   evaluate.** ``spec_unlock_remaining`` returns 0 both for an expired lock and for one it cannot
   judge, so the 0 was a default, not a measurement — and it read as "you are exactly on time"
   one line under ``chain says: (the gate could not evaluate it)``. The units word was wrong too:
   it is picked by ``mode == "block"``, and every mode that lands here is by definition not that.
3. **The three output files were never fsynced before the commit relayed.** The ordering fix
   reasoned about the PROCESS dying; against the HOST dying, ordering alone is advisory, because
   a buffered write is still only page cache when the commit goes out. Its test read the file
   back out of that same cache and so could not see it.

The pairing rule applies throughout: a mint cannot be amended and a published CEK is public
forever, so a refusal that lands on honest work costs as much as the bug. Each refusal below has
an honest-path test beside it.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from click.testing import CliRunner

from pyrxd.cli.context import CliContext
from pyrxd.cli.glyph_timelock_cmds import _reveal_lines, _write_new_file
from pyrxd.cli.prompts import confirm_action
from pyrxd.glyph.payload import decode_payload, encode_payload
from pyrxd.glyph.timelock_reveal_tx import build_timelock_reveal, plan_timelock_reveal
from pyrxd.security.errors import NetworkError
from tests.test_timelock_irreversible_paths_are_gated_and_visible import (
    TOKEN_REF,
    UNLOCK_AT,
    _off_chain,
    _RevealHarness,
    _seal,
)

#: A tip far past ``UNLOCK_AT``, so the gate reports itself satisfied and the ``*** EARLY
#: REVEAL`` banner stays silent. That is the hostile-endpoint scenario exactly: the ONLY thing
#: on the screen that could contradict a lying server is the reading itself.
TIP = 812_340

FEE_RATE = 10_000


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def _reveal(
    runner,
    tmp_path,
    monkeypatch,
    *,
    build=None,
    metadata=None,
    cek=None,
    tip: int = TIP,
    top=(),
    extra=(),
    broadcast=None,
):
    """Drive the real ``pyrxd glyph timelock-reveal`` against a node reporting *tip*.

    ``top`` are the group-level flags (``--yes`` / ``--json`` / ``--quiet``) — the whole point
    of these tests is which of them still show the operator the number that decided.
    """
    import pyrxd.cli.glyph_timelock_cmds as gtc
    from pyrxd.cli.main import cli

    h = _RevealHarness(tip=tip)
    if broadcast is not None:
        h.client.broadcast = broadcast
    cek_file = tmp_path / "cek.hex"
    cek_file.write_text((build.cek if build is not None else cek).hex())
    fetched = metadata if metadata is not None else decode_payload(encode_payload(build.metadata)[0])

    monkeypatch.setattr(gtc, "_load_wallet", lambda ctx, **kw: h.wallet)
    monkeypatch.setattr(CliContext, "make_client", lambda self: h.client)

    async def _fetch(self, ref):
        return fetched

    monkeypatch.setattr(gtc.GlyphScanner, "fetch_metadata", _fetch)
    result = runner.invoke(
        cli,
        [
            "--wallet",
            str(tmp_path / "w.dat"),
            *top,
            "glyph",
            "timelock-reveal",
            TOKEN_REF,
            "--cek-file",
            str(cek_file),
            *extra,
        ],
    )
    return result, h


def _mint_paths(tmp_path, files=None):
    return files or {
        "cek": tmp_path / "cek.hex",
        "ct": tmp_path / "ct.json",
        "env": tmp_path / "envelope.cbor",
    }


def _run_mint(runner, tmp_path, monkeypatch, *, inner, paths, on_load_wallet=None):
    """Drive the real ``pyrxd glyph timelock-mint`` with the network stubbed out at *inner*.

    ``on_load_wallet`` fires where the real hidden-mnemonic prompt would block: after the
    up-front existence check on the three output paths and before anything is written. That is
    the TOCTOU window, and it is minutes wide in a real run.
    """
    import pyrxd.cli.glyph_cmds as gc
    import pyrxd.cli.glyph_timelock_cmds as gtc
    from pyrxd.cli.main import cli

    content = tmp_path / "secret.txt"
    content.write_text("the reserve price is 1000 RXD")

    def _load(ctx, **kw):
        if on_load_wallet is not None:
            on_load_wallet()
        return MagicMock()

    monkeypatch.setattr(gtc, "_load_wallet", _load)
    monkeypatch.setattr(gc, "_mint_nft_inner", inner)
    monkeypatch.setattr(
        "pyrxd.cli.context.CliContext.make_client",
        lambda self: MagicMock(__aenter__=AsyncMock(return_value=MagicMock()), __aexit__=AsyncMock()),
    )
    return runner.invoke(
        cli,
        [
            "--wallet",
            str(tmp_path / "w.dat"),
            "--yes",
            "glyph",
            "timelock-mint",
            "--content",
            str(content),
            "--name",
            "Sealed Lot",
            "--unlock-at",
            str(UNLOCK_AT),
            "--cek-out",
            str(paths["cek"]),
            "--ciphertext-out",
            str(paths["ct"]),
            "--envelope-out",
            str(paths["env"]),
        ],
    )


# ---------------------------------------------------------------------------
# 1. The clock that decided reaches the operator on every path that can broadcast
# ---------------------------------------------------------------------------


class TestTheUnattendedRevealAlsoShowsTheClockThatDecided:
    """``--yes`` means "do not ask me". It had come to mean "do not tell me" as well.

    The reveal summary is the only place ``chain says`` is ever rendered, and that number — a
    tip height from an ElectrumX server nothing in this SDK authenticates — is what decides
    whether a decryption key becomes public forever. A server overstating it gets a permanent
    early reveal past a gate reporting itself satisfied, with the ``*** EARLY REVEAL`` banner
    silent because by its own arithmetic the lock HAS expired. Under ``--yes`` the operator was
    shown neither the reading before the broadcast nor, in human mode, after it.

    None of this closes the AUTHENTICATION gap; it closes the visibility one, on the paths the
    first fix missed. Refusing ``--yes`` outright was the other option and is the wrong one: the
    docstrings say plainly that JSON mode is where an automated reveal runs, and a reveal
    refused after the auction closes costs the holder as much as one published early.
    """

    def test_the_yes_path_prints_the_reading_and_the_target(self, runner, tmp_path, monkeypatch) -> None:
        build = _seal()  # opens at UNLOCK_AT; the node claims TIP, far past it
        result, h = _reveal(runner, tmp_path, monkeypatch, build=build, top=["--yes"])
        assert result.exit_code == 0, result.output
        assert len(h.broadcast_calls) == 1, "the honest --yes reveal must still go out"
        assert "chain says" in result.output
        assert f"{TIP:,}" in result.output, "the number that decided this must be on screen"
        assert "unverified" in result.output, "and must not be presented as the chain's own word"
        assert f"{UNLOCK_AT:,}" in result.output, "one number alone is not a comparison"

    def test_it_is_printed_BEFORE_the_broadcast_not_by_the_receipt(self, runner, tmp_path, monkeypatch) -> None:
        """The receipt could show the same string and protect nothing.

        Ordering is the entire property: the window this has to survive is the one where the
        operator could still hit Ctrl-C. Proved by making the broadcast fail — with no receipt
        printed at all, anything still on screen was printed before the key left the process.
        """
        build = _seal()

        async def _explode(raw: bytes) -> str:
            raise NetworkError("the node went away")

        result, _h = _reveal(runner, tmp_path, monkeypatch, build=build, top=["--yes"], broadcast=_explode)
        assert result.exit_code != 0, "the scenario requires the broadcast to fail"
        assert "Timelock revealed" not in result.output, "no receipt was printed, so this is the prompt's output"
        assert "chain says" in result.output
        assert f"{TIP:,}" in result.output

    def test_json_keeps_stdout_parseable_and_puts_the_evidence_on_stderr(self, runner, tmp_path, monkeypatch) -> None:
        """``--json --yes`` is the automated reveal. Its stdout is a contract with a program.

        So the disclosure goes to stderr, where a person watching the run sees it and a
        ``json.loads`` of stdout does not choke on it. Both halves are asserted, because
        printing it to stdout would "fix" the visibility finding by breaking every scripted
        caller — a fix that refuses valid work.
        """
        build = _seal()
        result, h = _reveal(runner, tmp_path, monkeypatch, build=build, top=["--yes", "--json"])
        assert result.exit_code == 0, result.output
        assert len(h.broadcast_calls) == 1

        payload = json.loads(result.stdout)  # stdout alone, and it must still parse
        assert payload["judged_at"] == TIP
        assert payload["broadcast"] is True

        assert "chain says" in result.stderr, "the deciding number reached nobody before the broadcast"
        assert f"{TIP:,}" in result.stderr
        assert "chain says" not in result.stdout, "and it must not be what breaks the JSON"

    def test_quiet_keeps_stdout_to_the_one_field_it_promises(self, runner, tmp_path, monkeypatch) -> None:
        """``--quiet`` prints exactly the txid, for ``$(pyrxd ... )``. Same split as ``--json``."""
        from pyrxd.transaction.transaction import Transaction

        build = _seal()
        result, h = _reveal(runner, tmp_path, monkeypatch, build=build, top=["--yes", "--quiet"])
        assert result.exit_code == 0, result.output
        assert len(h.broadcast_calls) == 1
        broadcast_txid = Transaction.from_hex(h.broadcast_calls[0].hex()).txid()
        assert result.stdout == f"{broadcast_txid}\n", "quiet mode's stdout is a contract with $( )"
        assert "chain says" in result.stderr
        assert f"{TIP:,}" in result.stderr

    def test_the_human_receipt_records_the_reading_too(self, runner, tmp_path, monkeypatch) -> None:
        """The JSON payload has carried ``judged_at`` since the field existed; the human receipt
        recorded nothing, so an operator who later suspected the endpoint had no way to find out
        what it had claimed. Too late to disagree with — which is why the prompt above matters
        more — but it is the only record the run leaves behind."""
        build = _seal()
        result, _ = _reveal(runner, tmp_path, monkeypatch, build=build, top=["--yes"])
        receipt = result.output.split("Timelock revealed")[1]
        assert "chain said" in receipt
        assert f"{TIP:,}" in receipt
        assert f"{UNLOCK_AT:,}" in receipt

    def test_the_INTERACTIVE_reveal_is_unchanged(self, runner, tmp_path, monkeypatch) -> None:
        """The paired honest path for the branch this touched. Declining still aborts and
        broadcasts nothing; the summary still lands on stdout, where it always was."""
        build = _seal()
        import pyrxd.cli.glyph_timelock_cmds as gtc
        from pyrxd.cli.main import cli

        h = _RevealHarness(tip=TIP)
        cek_file = tmp_path / "cek.hex"
        cek_file.write_text(build.cek.hex())
        fetched = decode_payload(encode_payload(build.metadata)[0])
        monkeypatch.setattr(gtc, "_load_wallet", lambda ctx, **kw: h.wallet)
        monkeypatch.setattr(CliContext, "make_client", lambda self: h.client)

        async def _fetch(self, ref):
            return fetched

        monkeypatch.setattr(gtc.GlyphScanner, "fetch_metadata", _fetch)
        args = [
            "--wallet",
            str(tmp_path / "w.dat"),
            "glyph",
            "timelock-reveal",
            TOKEN_REF,
            "--cek-file",
            str(cek_file),
        ]

        declined = runner.invoke(cli, args, input="n\n")
        assert declined.exit_code == 1
        assert "aborted by user" in declined.output
        assert "chain says" in declined.stdout, "the interactive summary still goes to stdout"
        assert h.broadcast_calls == [], "a declined prompt broadcast something"

        accepted = runner.invoke(cli, args, input="y\n")
        assert accepted.exit_code == 0, accepted.output
        assert len(h.broadcast_calls) == 1, "and confirming must still publish"


class TestTheAutoConfirmDisclosureIsWholeAndStreamCorrect:
    """The funnel itself, over every summary line and every output mode.

    Asserting "``chain says`` appears" in one command proves one line of one summary. Every
    ``_confirm_or_abort`` caller in the CLI — mint, transfer, swap, sweep, send, reveal — goes
    through this one function, so the property worth pinning is that ``--yes`` emits *all* of
    what it was handed, whatever that is, on the stream the mode requires. The expected set is
    derived from the input rather than typed out, so a summary that grows cannot leave this
    check passing over a stale list.
    """

    @pytest.mark.parametrize(
        ("mode", "on_stderr"),
        [("human", False), ("json", True), ("quiet", True)],
    )
    def test_every_line_is_emitted_on_the_right_stream(self, mode: str, on_stderr: bool) -> None:
        import click

        from pyrxd.cli.config import Config

        summary = [f"line {i}: {os.urandom(8).hex()}" for i in range(5)]
        ctx = CliContext(config=Config(), yes=True, output_mode=mode)

        @click.command()
        def cmd() -> None:
            assert confirm_action(list(summary), ctx=ctx) is True

        result = CliRunner().invoke(cmd, [])
        assert result.exit_code == 0, result.output
        wanted = result.stderr if on_stderr else result.stdout
        unwanted = result.stdout if on_stderr else result.stderr
        assert summary, "non-vacuity: an empty summary would satisfy the loop below trivially"
        for line in summary:
            assert line in wanted, f"{line!r} never reached the operator in {mode} mode"
            assert line not in unwanted, f"{line!r} went to the stream a machine reads in {mode} mode"

    def test_json_without_yes_is_still_refused_rather_than_auto_confirmed(self) -> None:
        """The other branch. ``--json`` alone must not be talked into proceeding by the new echo:
        it returns False and the caller aborts, exactly as before."""
        import click

        from pyrxd.cli.config import Config

        ctx = CliContext(config=Config(), yes=False, output_mode="json")

        @click.command()
        def cmd() -> None:
            assert confirm_action(["never shown"], ctx=ctx) is False

        result = CliRunner().invoke(cmd, [])
        assert result.exit_code == 0, result.output
        assert "never shown" not in result.output


# ---------------------------------------------------------------------------
# 2. A banner that does not report a measurement nobody took
# ---------------------------------------------------------------------------


class TestTheEarlyRevealBannerDoesNotInventADistance:
    """ "0 seconds short of the unlock point" was printed for a lock the gate had, one line
    earlier, said it could not evaluate.

    ``spec_unlock_remaining`` returns 0 for an unjudgeable lock exactly as it does for an
    expired one, so on this branch the number is a default rather than a reading — and "0 short"
    is not a hedge, it is the strongest possible claim: you are exactly on time. Nothing else on
    that prompt is false, which is what makes this one dangerous; it inherits the authority of
    the verified lines around it.
    """

    def test_an_unjudgeable_lock_reports_UNKNOWN_not_zero(self, runner, tmp_path, monkeypatch) -> None:
        cek = os.urandom(32)
        md = _off_chain([2, 8, 9], cek=cek, unlock_at=5, mode="BLOCK")
        result, h = _reveal(
            runner, tmp_path, monkeypatch, metadata=md, cek=cek, tip=10, extra=["--dry-run", "--allow-early"]
        )
        assert result.exit_code == 0, result.output
        assert "EARLY REVEAL" in result.output, "the banner must still shout"
        assert "UNKNOWN" in result.output
        assert "0 seconds" not in result.output, "the sentence that read as 'exactly on time'"
        assert "0 blocks" not in result.output, "and the same lie with the units word corrected"
        assert "Publishing now ends the timelock permanently, for everyone." in result.output
        assert h.broadcast_calls == []

    def test_a_JUDGEABLE_early_reveal_still_reports_the_real_distance(self, runner, tmp_path, monkeypatch) -> None:
        """The paired honest path. The distance is the operator's last chance to notice they are
        opening the wrong lot, so replacing a real number with a hedge would be its own defect."""
        build = _seal()
        result, h = _reveal(
            runner,
            tmp_path,
            monkeypatch,
            build=build,
            tip=UNLOCK_AT - 3,
            extra=["--dry-run", "--allow-early"],
        )
        assert result.exit_code == 0, result.output
        assert "EARLY REVEAL: 3 blocks short of" in result.output
        assert "UNKNOWN" not in result.output
        assert h.broadcast_calls == []

    def test_a_time_mode_early_reveal_still_counts_in_seconds(self, runner, tmp_path, monkeypatch) -> None:
        """The other judgeable branch — the units word is chosen there and nowhere else."""
        build = _seal(mode="time", unlock_at=1_700_000_060)  # the harness header says 1_700_000_000
        result, h = _reveal(runner, tmp_path, monkeypatch, build=build, extra=["--dry-run", "--allow-early"])
        assert result.exit_code == 0, result.output
        assert "EARLY REVEAL: 60 seconds short of" in result.output
        assert h.broadcast_calls == []

    def test_the_banner_keys_on_EVALUABILITY_not_on_the_mode_string(self, tmp_path) -> None:
        """The instance the fix was NOT built from.

        The demonstrated defect was a mode of ``'BLOCK'``, and a fix keyed on
        ``mode not in ("block", "time")`` would pass that test while still printing a
        manufactured 0 for the other way ``judged_at`` goes None: a well-formed ``block`` lock
        judged with no clock at all. ``plan_timelock_reveal``'s own signature defaults
        ``current_block`` to ``None``, so that plan is one an SDK caller gets by omitting an
        argument. It does not arise through the CLI, which always reads a tip — this pins the
        predicate's scope, not a reachable CLI state.
        """
        import asyncio

        cek = os.urandom(32)
        md = _off_chain([2, 8, 9], cek=cek, unlock_at=UNLOCK_AT, mode="block")
        plan = plan_timelock_reveal(md, token_ref=TOKEN_REF, cek=cek, allow_early=True)
        assert plan.mode == "block", "the fixture's whole point: a mode the SDK CAN judge"
        assert plan.judged_at is None, "...judged with no clock, so there was no reading"
        assert plan.remaining == 0, "...and `remaining` defaulted to 0, which is the trap"

        h = _RevealHarness(tip=TIP)
        build = asyncio.run(build_timelock_reveal(h.wallet, plan, client=h.client, fee_rate=FEE_RATE))
        lines = "\n".join(_reveal_lines(build, network="mainnet", fee_rate=FEE_RATE))
        assert "UNKNOWN" in lines
        assert "0 blocks short" not in lines
        assert "0 seconds short" not in lines

    def test_the_prompt_and_the_receipt_describe_the_clock_identically(self, runner, tmp_path, monkeypatch) -> None:
        """Two elements on one screen describing the same quantity. They are rendered from one
        function so they cannot drift; this is the assertion that notices if that stops being
        true."""
        build = _seal()
        result, _ = _reveal(runner, tmp_path, monkeypatch, build=build, top=["--yes"])
        prompt, receipt = result.output.split("Timelock revealed")
        phrase = f"{TIP:,} (block, as reported by the node — unverified)"
        assert phrase in prompt
        assert phrase in receipt


# ---------------------------------------------------------------------------
# 3. The files are durable, and exclusive, before the commit relays
# ---------------------------------------------------------------------------


class _FsyncSpy:
    """Records the inode of everything fsynced, and passes the call through.

    Inodes rather than paths because ``os.fsync`` is handed a descriptor: comparing
    ``os.fstat(fd).st_ino`` against ``os.stat(path).st_ino`` afterwards identifies exactly which
    files were flushed without guessing at ``/proc``.
    """

    def __init__(self) -> None:
        self._real = os.fsync
        self.synced: list[tuple[int, int]] = []

    def __call__(self, fd: int) -> None:
        st = os.fstat(fd)
        self.synced.append((st.st_dev, st.st_ino))
        self._real(fd)

    def key(self, path) -> tuple[int, int]:
        st = os.stat(path)
        return (st.st_dev, st.st_ino)


class TestTheMintsOnlyKeyIsDurableBeforeTheCommitRelays:
    """``timelock-mint`` writes the key, the ciphertext and the envelope, then broadcasts a
    commit within milliseconds and blocks for 10+ minutes waiting for it.

    Ordering the writes first defeats a kill; it does not defeat a power cut, because a buffered
    write is still nothing but page cache when the commit relays. The outcome is the one the
    ordering exists to prevent — a confirmed commit whose only key is gone — and the existing
    test cannot see it, because it reads the file back out of the same cache that would have
    been lost.
    """

    def _mint(self, runner, tmp_path, monkeypatch, *, inner, files=None, on_load_wallet=None):
        self.paths = _mint_paths(tmp_path, files)
        return _run_mint(runner, tmp_path, monkeypatch, inner=inner, paths=self.paths, on_load_wallet=on_load_wallet)

    def test_all_three_files_AND_their_directory_are_fsynced_before_the_broadcast(
        self, runner, tmp_path, monkeypatch
    ) -> None:
        """The directory entry as well as the bytes. ``fsync`` on a file says nothing on POSIX
        about the entry that names it, and under ext4's delayed allocation a brand-new file can
        come back absent — or present and zero-length — from a crash whose data was flushed."""
        spy = _FsyncSpy()
        monkeypatch.setattr(os, "fsync", spy)
        at_broadcast: dict[str, list[tuple[int, int]]] = {}

        async def _inner(ctx, wallet, metadata, client):
            at_broadcast["synced"] = list(spy.synced)
            return {"commit_txid": "aa" * 32, "reveal_txid": "bb" * 32, "ref": TOKEN_REF, "owner_address": "x"}

        result = self._mint(runner, tmp_path, monkeypatch, inner=_inner)
        assert result.exit_code == 0, result.output

        flushed = at_broadcast["synced"]
        assert flushed, "non-vacuity: nothing at all was fsynced, so the loop below proves nothing"
        for key in ("cek", "ct", "env"):
            assert spy.key(self.paths[key]) in flushed, (
                f"{key} was still only in the page cache when the commit went out"
            )
        assert spy.key(tmp_path) in flushed, "the directory entry naming the three files was never flushed"

    def test_a_file_that_appears_DURING_the_prompt_is_not_clobbered(self, runner, tmp_path, monkeypatch) -> None:
        """The up-front existence check is a TOCTOU race, and the window is minutes wide.

        ``timelock-mint`` checks all three paths, then loads the wallet — a hidden mnemonic
        prompt — then builds, then confirms, and only then writes. A second mint finishing in
        that window used to be silently truncated by ``Path.write_text``: the ciphertext and the
        envelope had no ``O_EXCL``, only the key did. Simulated here by creating the file inside
        the wallet load, which is exactly where the real window opens.
        """
        foreign = b'{"another token": "its only ciphertext"}'

        def _appears() -> None:
            self.paths["ct"].write_bytes(foreign)

        async def _inner(ctx, wallet, metadata, client):  # pragma: no cover - must not be reached
            raise AssertionError("the mint broadcast a commit after clobbering another token's file")

        result = self._mint(runner, tmp_path, monkeypatch, inner=_inner, on_load_wallet=_appears)
        assert result.exit_code == 1
        assert "nothing was broadcast" in result.output
        assert self.paths["ct"].read_bytes() == foreign, "another token's ciphertext was overwritten"

    def test_an_envelope_that_appears_DURING_the_prompt_is_not_clobbered_either(
        self, runner, tmp_path, monkeypatch
    ) -> None:
        """Both directions of the gap, not only the one it was demonstrated on. Without the
        envelope bytes a commit that confirms while its reveal does not is unspendable forever,
        so this file is no less final than the key."""
        foreign = b"another token's envelope"

        def _appears() -> None:
            self.paths["env"].write_bytes(foreign)

        async def _inner(ctx, wallet, metadata, client):  # pragma: no cover - must not be reached
            raise AssertionError("the mint broadcast a commit after clobbering another token's file")

        result = self._mint(runner, tmp_path, monkeypatch, inner=_inner, on_load_wallet=_appears)
        assert result.exit_code == 1
        assert "nothing was broadcast" in result.output
        assert self.paths["env"].read_bytes() == foreign

    def test_the_ORDINARY_mint_writes_all_three_intact(self, runner, tmp_path, monkeypatch) -> None:
        """The paired honest path for three refusals and two fsyncs per file. A mint into an
        empty directory must still complete, with the key at 0600 and the envelope byte-identical
        to the CBOR the commit hashed — a durability fix that corrupted what it flushed would be
        worse than the bug."""
        captured: dict[str, bytes] = {}

        async def _inner(ctx, wallet, metadata, client):
            captured["cbor"] = encode_payload(metadata)[0]
            return {"commit_txid": "aa" * 32, "reveal_txid": "bb" * 32, "ref": TOKEN_REF, "owner_address": "x"}

        result = self._mint(runner, tmp_path, monkeypatch, inner=_inner)
        assert result.exit_code == 0, result.output
        assert self.paths["env"].read_bytes() == captured["cbor"]
        assert oct(self.paths["cek"].stat().st_mode)[-3:] == "600"
        assert len(bytes.fromhex(self.paths["cek"].read_text().strip())) == 32
        assert json.loads(self.paths["ct"].read_text())["chunks"], "the ciphertext file is not an empty shell"


class TestDurabilityDoesNotBecomeARefusal:
    """The honest-path pair for the fsyncs, and the defect the first draft of them had.

    Not every host can flush a directory entry — Windows has no directory descriptor, and
    ``fsync`` on one raises on some network filesystems. The first version of ``_fsync_dir``
    let that propagate, which the caller turns into "nothing was broadcast": an otherwise
    perfectly good mint, refused over a call the host was never going to honour, on the one
    command in this SDK that cannot be re-run. A guard that refuses valid work is a bug, and
    this is what it would have looked like.

    The FILE fsync keeps the opposite treatment, and that is asserted too — it failing means
    the bytes may not be on disk at all, and broadcasting on top of that is the whole finding.
    """

    @staticmethod
    async def _ok_mint(ctx, wallet, metadata, client):
        return {"commit_txid": "aa" * 32, "reveal_txid": "bb" * 32, "ref": TOKEN_REF, "owner_address": "x"}

    def test_a_host_that_cannot_fsync_a_DIRECTORY_still_mints(self, runner, tmp_path, monkeypatch) -> None:
        """Run through the real command, not through ``_write_new_file`` — the claim in the name
        is about a mint completing, and a unit call cannot make it."""
        import stat as stat_mod

        real_fsync = os.fsync

        def _no_dir_fsync(fd: int) -> None:
            if stat_mod.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError(22, "Invalid argument")  # what some network filesystems do
            real_fsync(fd)

        monkeypatch.setattr(os, "fsync", _no_dir_fsync)
        paths = _mint_paths(tmp_path)
        result = _run_mint(runner, tmp_path, monkeypatch, inner=self._ok_mint, paths=paths)
        assert result.exit_code == 0, result.output
        assert len(bytes.fromhex(paths["cek"].read_text().strip())) == 32
        assert paths["env"].read_bytes(), "the envelope is written even where the entry cannot be flushed"

    def test_a_host_with_no_directory_DESCRIPTOR_still_mints(self, runner, tmp_path, monkeypatch) -> None:
        """The Windows shape: ``os.open`` on a directory raises rather than fsync doing so."""
        real_open = os.open

        def _no_dir_open(path, flags, mode=0o600, **kw):
            if os.path.isdir(path):
                raise PermissionError(13, "Permission denied")
            return real_open(path, flags, mode, **kw)

        monkeypatch.setattr(os, "open", _no_dir_open)
        paths = _mint_paths(tmp_path)
        result = _run_mint(runner, tmp_path, monkeypatch, inner=self._ok_mint, paths=paths)
        assert result.exit_code == 0, result.output
        assert len(bytes.fromhex(paths["cek"].read_text().strip())) == 32

    def test_a_FILE_fsync_failure_STOPS_the_mint(self, runner, tmp_path, monkeypatch) -> None:
        """The other side of the asymmetry, and the reason it is not "swallow everything".

        A file fsync failing means the bytes may not be on disk at all, which is the whole
        guarantee — so it propagates, and the commit is never broadcast.
        """
        import stat as stat_mod

        real_fsync = os.fsync

        def _no_file_fsync(fd: int) -> None:
            if stat_mod.S_ISREG(os.fstat(fd).st_mode):
                raise OSError(5, "Input/output error")
            real_fsync(fd)

        monkeypatch.setattr(os, "fsync", _no_file_fsync)

        async def _inner(ctx, wallet, metadata, client):  # pragma: no cover - must not be reached
            raise AssertionError("a commit was broadcast for a key that may not be on disk")

        paths = _mint_paths(tmp_path)
        result = _run_mint(runner, tmp_path, monkeypatch, inner=_inner, paths=paths)
        assert result.exit_code == 1
        assert "nothing was broadcast" in result.output


class TestTheDurableWriterItself:
    """``_write_new_file`` is the funnel all three outputs now cross, so its own edges matter."""

    def test_a_RELATIVE_path_syncs_the_directory_it_is_actually_in(self, runner, tmp_path, monkeypatch) -> None:
        """``Path("cek.hex").parent`` is ``Path(".")``, not the empty string — the branch every
        test above skips by passing an absolute ``tmp_path``, and the one an operator typing
        ``--cek-out cek.hex`` takes."""
        with runner.isolated_filesystem(temp_dir=tmp_path):
            spy = _FsyncSpy()
            monkeypatch.setattr(os, "fsync", spy)
            _write_new_file(Path("cek.hex"), b"secret", mode=0o600)
            assert spy.key("cek.hex") in spy.synced
            assert spy.key(".") in spy.synced, "the directory entry for a relative path was not flushed"

    def test_it_refuses_rather_than_truncating(self, tmp_path) -> None:
        target = tmp_path / "k.hex"
        target.write_bytes(b"the previous mint's only key")
        with pytest.raises(FileExistsError):
            _write_new_file(target, b"clobber", mode=0o600)
        assert target.read_bytes() == b"the previous mint's only key"

    def test_the_mode_is_set_at_CREATION_not_by_a_later_chmod(self, tmp_path, monkeypatch) -> None:
        """Between an ``open`` and a ``chmod`` there is a window in which a key sits
        world-readable, and on a shared host that window is the vulnerability.

        The final mode cannot see it. A later ``chmod`` reaches the same final mode, so a test
        asserting only ``stat()`` passes on the defect — planting exactly that (create 0666,
        chmod 0600) left an earlier version of this test green. What is checked instead is the
        mode the descriptor was CREATED with, and that no ``chmod`` happens at all.
        """
        opens: list[tuple[str, int]] = []
        real_open = os.open

        def _spy_open(path, flags, mode=0o600, **kw):
            opens.append((str(path), mode))
            return real_open(path, flags, mode, **kw)

        def _no_chmod(*a, **k):
            pytest.fail("the mode was applied after creation, leaving a world-readable window")

        monkeypatch.setattr(os, "open", _spy_open)
        monkeypatch.setattr(os, "chmod", _no_chmod)

        target = tmp_path / "k.hex"
        _write_new_file(target, b"secret", mode=0o600)

        created = [m for p, m in opens if p == str(target)]
        assert created == [0o600], f"created with {[oct(m) for m in created]}, not 0o600"
        assert oct(target.stat().st_mode)[-3:] == "600"
        assert target.read_bytes() == b"secret"
