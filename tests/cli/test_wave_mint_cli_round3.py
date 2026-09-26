"""``glyph mint-nft`` / ``resume-mint``, PR #742 round 3.

1. Success says what was established. "Confirmed" is one server's word (#736), so a finished
   mint says the server REPORTS the reveal confirmed, where the commit's record is kept, and the
   command that reveals the commit again through another server if an explorer does not show
   the reveal. ``--json`` carries the same as fields.
2. The treasury exception. Only the mint's own recovery command — built from this process's
   argv — may name a treasury other than the published one. Every command printed from a
   record read off disk (every ``resume-mint`` text, the pending-name check, the network
   refusal) shows the placeholder.
3. Lane D F1 on ``3cb57e27``: the pending-name check and the network refusal printed ONE
   command carrying the record's fee choice, so a record edited from ``decline`` to ``pay`` (or
   with its fee keys deleted, which v3 allows) printed a paying command, and running it paid.
   A record read from disk now gets both choices, pay and decline.
4. Lane D F2 on ``3cb57e27``: archiving could fail after a confirmed reveal (``done/`` a regular
   file: exit 1), and when ``done/`` was a symbolic link the ``chmod`` followed it and changed a
   foreign directory to 0700. ``done/`` is now checked with ``lstat`` before anything is
   broadcast, never chmodded through a link, and a failure after the reveal is reported as
   success with a note.

The fake chain and wallet are ``test_wave_registration_fee_cli.py``'s.
"""

from __future__ import annotations

import json
import os
import pathlib
import shlex
import stat
from collections.abc import Callable
from typing import Any

import pytest
from click.testing import CliRunner

from pyrxd.cli.main import cli
from pyrxd.constants import Network
from pyrxd.keys import PrivateKey
from pyrxd.script.type import P2PKH

from .test_wave_mint_cli_round2 import _archived, _said, _use, _WithholdsTheReveal
from .test_wave_registration_fee_cli import (
    _DECLINE,
    _PAY,
    _TREASURY_SCRIPT,
    _Chain,
    _command,
    _global,
    _mint,
    _no_wait,
    _record_path,
    _resume,
    _run_printed,
    _scripts,
    _store,
    _timed_out_mint,
    _tx,
    _wave_metadata_file,
    _wire,
    reveal_envelope,
)

_ANOTHER = "<another-server-url>"
_POSIX = pytest.mark.skipif(os.name != "posix", reason="file modes and symbolic links as POSIX has them")


def _printed_commands(result: Any) -> list[str]:
    """Every backticked ``pyrxd ... resume-mint <txid> ...`` command in the output — not the bare
    ``pyrxd glyph resume-mint`` that a timeout's hint names."""
    return [c for c in _said(result).split("`")[1::2] if c.startswith("pyrxd ") and "resume-mint " in c]


def _other_server_command(tmp_path: pathlib.Path, txid: str, *extra: str, network: str = "mainnet") -> str:
    wallet = str((tmp_path / "w.dat").absolute())
    return shlex.join(
        [
            "pyrxd",
            "--electrumx",
            _ANOTHER,
            "--network",
            network,
            "--wallet",
            wallet,
            "glyph",
            "resume-mint",
            txid,
            *extra,
        ]
    )


def _human(tmp_path: pathlib.Path, *args: str, network: str = "mainnet") -> Any:
    return CliRunner().invoke(cli, [*_global(tmp_path, network=network, mode=("--yes",)), *args])


# ───────────────────── (1) success says the server REPORTS it, and how to recover ──


class TestSuccessSaysWhatTheServerReported:
    def test_mint_nft_says_the_server_reports_it_and_where_the_record_is(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("HOME", str(tmp_path))  # the record path is shown home-relative (#737)
        chain, _wallet = _wire(monkeypatch)
        result = _human(tmp_path, "glyph", "mint-nft", str(_wave_metadata_file(tmp_path, "abcde")))
        assert result.exit_code == 0, result.output
        txid = str(_tx(chain.broadcasts[0]).txid())
        reveal_txid = str(_tx(chain.broadcasts[1]).txid())
        said = _said(result)
        assert "The server reports the reveal confirmed." in said
        assert "NFT minted" not in said
        assert (
            f"The commit's record is kept at ~/pending-mints/done/{txid}.json. If a block explorer does not show "
            f"the reveal {reveal_txid}, reveal the commit again through another server:" in said
        )
        assert (
            f"pyrxd --electrumx '{_ANOTHER}' --network mainnet --wallet ~/w.dat glyph resume-mint {txid} {_PAY}" in said
        )
        assert _archived(tmp_path, txid).exists()

    def test_json_carries_the_same_as_fields(self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _chain, _wallet = _wire(monkeypatch)
        result = _mint(tmp_path, "abcde")
        assert result.exit_code == 0, result.output
        doc = json.loads(result.stdout)  # machine-readable: the whole of stdout is one document
        txid = doc["commit_txid"]
        assert doc["reveal_confirmed"] == "reported by the server; not independently verified"
        assert doc["record"] == str(_archived(tmp_path, txid))  # absolute: a program opens it
        assert doc["record_archive_error"] is None and doc["recover_note"] is None
        assert doc["recover_if_not_mined"] == _other_server_command(tmp_path, txid, _PAY)

    def test_the_printed_recovery_finishes_a_reveal_the_server_withheld(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The success output's command, run against another (honest) server, reveals the commit
        a lying server reported revealed."""
        chain, _wallet = _wire(monkeypatch)
        liar = _WithholdsTheReveal(chain)
        _use(monkeypatch, liar)
        fooled = _mint(tmp_path, "abcde")
        assert fooled.exit_code == 0, fooled.output
        doc = json.loads(fooled.stdout)
        assert liar.withheld and len(chain.broadcasts) == 1  # only the commit reached the chain
        _use(monkeypatch, chain)
        finished = _run_printed(tmp_path, doc["recover_if_not_mined"].replace(_ANOTHER, "ssl://honest.example:50002"))
        assert finished.exit_code == 0, finished.output
        reveal = _tx(chain.broadcasts[1])
        assert (reveal.inputs[0].source_txid, reveal.inputs[0].source_output_index) == (doc["commit_txid"], 0)
        assert _scripts(reveal).count(_TREASURY_SCRIPT) == 1

    def test_resume_mint_says_it_too(self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
        chain, _wallet = _wire(monkeypatch)
        txid = _timed_out_mint(tmp_path, monkeypatch, chain)
        result = _human(tmp_path, "glyph", "resume-mint", txid, _PAY)
        assert result.exit_code == 0, result.output
        said = _said(result)
        assert "The server reports the reveal confirmed." in said and "NFT minted" not in said
        assert f"The commit's record is kept at {_archived(tmp_path, txid)}." in said
        assert _other_server_command(tmp_path, txid, _PAY) in said

    def test_timelock_mint_says_it_too(self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from tests.test_timelock_irreversible_paths_are_gated_and_visible import _REPORTED, TOKEN_REF
        from tests.test_timelock_reveal_evidence_and_durability import _run_mint

        async def _inner(ctx: Any, wallet: Any, metadata: Any, client: Any) -> dict:
            return {"commit_txid": "aa" * 32, "reveal_txid": "bb" * 32, "ref": TOKEN_REF, "owner_address": "x"} | (
                _REPORTED
            )

        paths = {"cek": tmp_path / "cek.hex", "ct": tmp_path / "ct.json", "env": tmp_path / "envelope.cbor"}
        result = _run_mint(CliRunner(), tmp_path, monkeypatch, inner=_inner, paths=paths)
        assert result.exit_code == 0, result.output
        said = _said(result)
        assert "The server reports the timelocked NFT's reveal confirmed." in said
        assert "Timelocked NFT minted" not in said
        assert f"The commit's record is kept at {_REPORTED['record']}" in said
        assert _REPORTED["recover_if_not_mined"] in said


# ───────── (2) only the mint's own command names a treasury it was given ──


class TestOnlyTheMintsOwnCommandNamesATypedTreasury:
    def test_the_mint_time_command_names_it_and_finishes_in_one_step(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        chain, _wallet = _wire(monkeypatch)
        treasury = PrivateKey().public_key().address(network=Network.TESTNET)
        chain.confirmations = 0
        _no_wait(monkeypatch)
        stopped = _mint(tmp_path, "abcde", "--wave-treasury", treasury, network="regtest")
        assert stopped.exit_code == 2
        txid = json.loads(stopped.stdout)["commit_txid"]
        pays = _command(tmp_path, txid, "--wave-treasury", treasury, network="regtest")
        # "To reveal this one, run `<pays>`", then the "if the name is taken" decline.
        assert _printed_commands(stopped) == [pays, _command(tmp_path, txid, _DECLINE, network="regtest")]
        assert "<ADDRESS>" not in stopped.output
        chain.confirmations = 1
        done = _run_printed(tmp_path, pays)
        assert done.exit_code == 0, done.output
        assert _scripts(_tx(chain.broadcasts[1]))[1] == P2PKH().lock(treasury).serialize()

    def test_mint_time_success_names_it(self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _chain, _wallet = _wire(monkeypatch)
        treasury = PrivateKey().public_key().address(network=Network.TESTNET)
        minted = _mint(tmp_path, "abcde", "--wave-treasury", treasury, network="regtest")
        assert minted.exit_code == 0, minted.output
        doc = json.loads(minted.stdout)
        assert doc["recover_if_not_mined"] == _other_server_command(
            tmp_path, doc["commit_txid"], "--wave-treasury", treasury, network="regtest"
        )
        assert doc["recover_note"] is None

    def test_resume_time_success_does_not(self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
        chain, _wallet = _wire(monkeypatch)
        treasury = PrivateKey().public_key().address(network=Network.TESTNET)
        txid = _timed_out_mint(tmp_path, monkeypatch, chain, "--wave-treasury", treasury, network="regtest")
        resumed = _resume(tmp_path, txid, "--wave-treasury", treasury, network="regtest")
        assert resumed.exit_code == 0, resumed.output
        doc = json.loads(resumed.stdout)
        assert doc["recover_if_not_mined"] == _other_server_command(
            tmp_path, txid, "--wave-treasury", "<ADDRESS>", network="regtest"
        )
        assert "Replace <ADDRESS> with the treasury address you gave the mint's --wave-treasury" in doc["recover_note"]

    def test_with_an_edited_record_no_resume_refusal_prints_a_treasury(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The record's treasury is edited to X. Whatever resume-mint is told, nothing it prints
        carries X, or the treasury the mint was given: only the placeholder. (Naming X on the
        command line yourself is the operator's choice, and is honoured.)"""
        chain, _wallet = _wire(monkeypatch)
        treasury = PrivateKey().public_key().address(network=Network.TESTNET)
        edited = PrivateKey().public_key().address(network=Network.TESTNET)
        txid = _timed_out_mint(tmp_path, monkeypatch, chain, "--wave-treasury", treasury, network="regtest")
        path = _record_path(tmp_path, txid)
        path.write_text(path.read_text().replace(treasury, edited))
        seen_placeholder = False
        for stated in (("--wave-treasury", treasury), (_PAY,), ()):
            refused = _resume(tmp_path, txid, *stated, network="regtest")
            assert refused.exit_code == 1 and len(chain.broadcasts) == 1, (stated, refused.output)
            assert edited not in refused.output, stated
            for command in _printed_commands(refused):
                assert edited not in command and treasury not in command, (stated, command)
                seen_placeholder |= "'<ADDRESS>'" in command
        assert seen_placeholder

    def test_a_resume_that_stops_prints_the_placeholder(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """resume-mint's own recovery text comes from a record: the placeholder, never the address."""
        chain, _wallet = _wire(monkeypatch)
        treasury = PrivateKey().public_key().address(network=Network.TESTNET)
        txid = _timed_out_mint(tmp_path, monkeypatch, chain, "--wave-treasury", treasury, network="regtest")
        chain.unconfirmed_from = 1  # the reveal is accepted and never mined
        stopped = _resume(tmp_path, txid, "--wave-treasury", treasury, network="regtest")
        assert stopped.exit_code == 2, stopped.output
        doc = json.loads(stopped.stdout)
        assert doc["recover"] == _command(tmp_path, txid, "--wave-treasury", "<ADDRESS>", network="regtest")
        for command in _printed_commands(stopped):
            assert treasury not in command


# ──────── (3) lane D F1: a record read from disk never prints ONE fee choice ──


def _drop(d: dict, *keys: str) -> None:
    for key in keys:
        del d[key]


_EDITS: dict[str, Callable[[dict], None]] = {
    "decline-edited-to-pay": lambda d: d.update(wave_fee="pay", wave_treasury=None),
    "fee-keys-deleted": lambda d: _drop(d, "wave_fee", "wave_treasury"),
}


def _declined_then_edited(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch, chain: _Chain, edit: str) -> str:
    """Lane D's setup: a mint that declined the fee, timed out, and its record edited after."""
    txid = _timed_out_mint(tmp_path, monkeypatch, chain, _DECLINE)
    path = _record_path(tmp_path, txid)
    d = json.loads(path.read_text())
    assert d["schema_version"] == 3 and d["wave_fee"] == "decline"
    _EDITS[edit](d)
    path.write_text(json.dumps(d))
    return txid


def _assert_both_choices(result: Any, tmp_path: pathlib.Path, txid: str) -> None:
    pay, decline = _command(tmp_path, txid, _PAY), _command(tmp_path, txid, _DECLINE)
    assert sorted(_printed_commands(result)) == sorted([pay, decline]), _said(result)
    assert f"to pay the published WAVE treasury: `{pay}`; to reveal without paying: `{decline}`" in _said(result)


class TestARecordReadFromDiskGetsBothFeeChoices:
    @pytest.mark.parametrize("edit", sorted(_EDITS))
    def test_the_pending_name_refusal(self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch, edit: str) -> None:
        chain, _wallet = _wire(monkeypatch)
        txid = _declined_then_edited(tmp_path, monkeypatch, chain, edit)
        again = _mint(tmp_path, "abcde")
        assert again.exit_code == 1 and len(chain.broadcasts) == 1
        assert "already has an unrevealed commit for the WAVE name abcde.rxd" in _said(again)
        _assert_both_choices(again, tmp_path, txid)

    @pytest.mark.parametrize("edit", sorted(_EDITS))
    def test_the_network_refusal(self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch, edit: str) -> None:
        chain, _wallet = _wire(monkeypatch)
        txid = _declined_then_edited(tmp_path, monkeypatch, chain, edit)
        wrong = _resume(tmp_path, txid, _DECLINE, network="regtest")
        assert wrong.exit_code == 1 and len(chain.broadcasts) == 1
        assert f"the record for {txid} is for mainnet, and this run is on regtest" in _said(wrong)
        _assert_both_choices(wrong, tmp_path, txid)

    def test_an_unedited_declined_record_is_offered_only_the_decline(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Honest path: a declining command pays nothing, and the paying one would be refused
        against a record that says the mint declined."""
        chain, _wallet = _wire(monkeypatch)
        txid = _timed_out_mint(tmp_path, monkeypatch, chain, _DECLINE)
        again = _mint(tmp_path, "abcde")
        assert again.exit_code == 1
        assert _printed_commands(again) == [_command(tmp_path, txid, _DECLINE)]
        done = _run_printed(tmp_path, _printed_commands(again)[0])
        assert done.exit_code == 0, done.output
        assert _TREASURY_SCRIPT not in _scripts(_tx(chain.broadcasts[1]))


# ─── (4) lane D F2: done/ is checked before anything is broadcast, never chmodded through a link ──


#: The foreign directory's mode: anything but the archive's 0700, so a chmod through a link shows,
#: with no group or world bits (CodeQL's overly-permissive-file rule flags any, even in a test).
_FOREIGN_MODE = 0o500


def _foreign(tmp_path: pathlib.Path) -> pathlib.Path:
    """A directory that is not pyrxd's, at :data:`_FOREIGN_MODE`."""
    foreign = tmp_path / "somebody-elses"
    foreign.mkdir()
    os.chmod(foreign, _FOREIGN_MODE)
    return foreign


def _spoil(tmp_path: pathlib.Path, shape: str) -> pathlib.Path | None:
    """Make ``pending-mints/done`` a regular file or a link to a foreign directory; the foreign one."""
    done = tmp_path / "pending-mints" / "done"
    done.parent.mkdir(exist_ok=True, mode=0o700)
    if shape == "file":
        done.write_text("not a directory")
        return None
    foreign = _foreign(tmp_path)
    done.symlink_to(foreign, target_is_directory=True)
    return foreign


def _assert_untouched(foreign: pathlib.Path | None) -> None:
    if foreign is not None:
        assert stat.S_IMODE(foreign.stat().st_mode) == _FOREIGN_MODE
        assert list(foreign.iterdir()) == []


_PROBLEM = {"file": "exists and is not a directory", "symlink": "is a symbolic link"}


@_POSIX
class TestAnUnusableArchiveIsRefusedBeforeAnyBroadcast:
    @pytest.mark.parametrize("shape", ["file", "symlink"])
    def test_mint_nft_refuses_before_the_commit(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch, shape: str
    ) -> None:
        chain, _wallet = _wire(monkeypatch)
        foreign = _spoil(tmp_path, shape)
        result = _mint(tmp_path, "abcde")
        assert result.exit_code == 1 and chain.broadcasts == []
        said = _said(result)
        assert "is unusable — NOT broadcasting the commit" in said and _PROBLEM[shape] in said
        _assert_untouched(foreign)

    @pytest.mark.parametrize("shape", ["file", "symlink"])
    def test_resume_mint_refuses_before_the_reveal_and_goes_ahead_once_it_is_moved(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch, shape: str
    ) -> None:
        chain, _wallet = _wire(monkeypatch)
        txid = _timed_out_mint(tmp_path, monkeypatch, chain)
        foreign = _spoil(tmp_path, shape)
        polls: list[str] = []
        chain.on_poll = polls.append
        refused = _resume(tmp_path, txid, _PAY)
        chain.on_poll = None
        assert refused.exit_code == 1 and len(chain.broadcasts) == 1
        assert polls == []  # refused up front, before waiting on the commit
        assert "is unusable — NOT broadcasting the reveal" in _said(refused) and _PROBLEM[shape] in _said(refused)
        assert _record_path(tmp_path, txid).exists()
        _assert_untouched(foreign)
        (tmp_path / "pending-mints" / "done").unlink()
        finished = _resume(tmp_path, txid, _PAY)
        assert finished.exit_code == 0, finished.output
        assert _archived(tmp_path, txid).exists()

    def test_a_done_that_goes_bad_while_the_commit_confirms_stops_the_reveal(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The mint waits 10+ minutes for its commit: the archive is looked at again before the
        reveal, and a refusal there keeps the record and names the recovery."""
        chain, _wallet = _wire(monkeypatch)

        def _spoil_during_the_commit_wait(_txid: str) -> None:
            if not (tmp_path / "pending-mints" / "done").exists():
                _spoil(tmp_path, "file")

        chain.on_poll = _spoil_during_the_commit_wait
        result = _mint(tmp_path, "abcde")
        assert result.exit_code == 1 and len(chain.broadcasts) == 1
        txid = str(_tx(chain.broadcasts[0]).txid())
        said = _said(result)
        assert "is unusable — NOT broadcasting the reveal" in said
        assert f"resume-mint {txid}" in said  # the commit's recovery is added
        assert _record_path(tmp_path, txid).exists()


@_POSIX
class TestAnArchiveThatFailsAfterTheRevealIsNotAFailure:
    @staticmethod
    def _spoil_after_the_reveal(chain: _Chain, tmp_path: pathlib.Path, shape: str) -> dict:
        """``done/`` goes bad after the pre-broadcast checks: while the reveal is awaited."""
        made: dict = {}

        def _hook(_txid: str) -> None:
            if len(chain.broadcasts) == 2 and "done" not in made:
                made["done"] = True
                made["foreign"] = _spoil(tmp_path, shape)

        chain.on_poll = _hook
        return made

    @pytest.mark.parametrize("shape", ["file", "symlink"])
    def test_json(self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch, shape: str) -> None:
        chain, _wallet = _wire(monkeypatch)
        made = self._spoil_after_the_reveal(chain, tmp_path, shape)
        result = _mint(tmp_path, "abcde")
        assert result.exit_code == 0, result.output
        assert made  # the spoiler ran, after the reveal
        doc = json.loads(result.stdout)
        txid = doc["commit_txid"]
        live = _record_path(tmp_path, txid)
        assert doc["record"] == str(live) and live.exists()
        assert _PROBLEM[shape] in doc["record_archive_error"]
        _assert_untouched(made["foreign"])

    @pytest.mark.parametrize("shape", ["file", "symlink"])
    def test_human(self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch, shape: str) -> None:
        chain, _wallet = _wire(monkeypatch)
        made = self._spoil_after_the_reveal(chain, tmp_path, shape)
        result = _human(tmp_path, "glyph", "mint-nft", str(_wave_metadata_file(tmp_path, "abcde")))
        assert result.exit_code == 0, result.output
        txid = str(_tx(chain.broadcasts[0]).txid())
        said = _said(result)
        assert "The server reports the reveal confirmed." in said
        assert f"The commit's record is kept at {_record_path(tmp_path, txid)}." in said
        assert "(The record was not moved to the archive" in said and _PROBLEM[shape] in said
        _assert_untouched(made["foreign"])

    def test_resume_mint(self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
        chain, _wallet = _wire(monkeypatch)
        txid = _timed_out_mint(tmp_path, monkeypatch, chain)
        made = self._spoil_after_the_reveal(chain, tmp_path, "symlink")
        result = _resume(tmp_path, txid, _PAY)
        assert result.exit_code == 0, result.output
        doc = json.loads(result.stdout)
        assert doc["record"] == str(_record_path(tmp_path, txid)) and "symbolic link" in doc["record_archive_error"]
        _assert_untouched(made["foreign"])

    def test_resume_mint_finding_the_commit_already_revealed(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        chain, _wallet = _wire(monkeypatch)
        txid = _timed_out_mint(tmp_path, monkeypatch, chain)
        spender = chain.spend((txid, 0), unlocking=reveal_envelope(_store(tmp_path).load(txid).cbor_bytes))

        def _hook(_txid: str) -> None:
            if not (tmp_path / "pending-mints" / "done").exists():
                _spoil(tmp_path, "file")

        chain.on_poll = _hook
        result = _resume(tmp_path, txid, _PAY)
        assert result.exit_code == 1  # nothing to recover, as before
        said = _said(result)
        assert f"is already revealed, by {spender}" in said
        assert f"the record is kept at {_record_path(tmp_path, txid)} (it could not be archived:" in said
        assert _record_path(tmp_path, txid).exists()
