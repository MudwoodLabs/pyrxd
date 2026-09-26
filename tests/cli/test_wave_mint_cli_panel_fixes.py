"""``pyrxd glyph mint-nft`` / ``resume-mint``: the 0.25.0 pre-release panel's findings, #736 and #737.

Each class is one finding, named in its docstring, with the refusal it adds AND the honest path
it must leave working. Driven through the real click command over the fake chain and wallet of
``test_wave_registration_fee_cli.py`` (a UTXO set that broadcasts really spend, and
``wave.check_available`` answered through the real ``WaveResolver``); what the indexer would do
with a reveal is graded by RXinDexer's own pinned code (``tests/rxindexer_oracle.py``).
"""

from __future__ import annotations

import json
import os
import pathlib
import shlex
from typing import Any

import pytest
from click.testing import CliRunner

from pyrxd.cli import glyph_cmds, glyph_helpers, prompts
from pyrxd.cli.main import cli
from pyrxd.constants import Network
from pyrxd.glyph.wave_rules import WAVE_TREASURY_ADDRESS
from pyrxd.keys import PrivateKey
from pyrxd.script.type import P2PKH
from pyrxd.security.errors import NetworkError
from tests import rxindexer_oracle as oracle

from .test_wave_registration_fee_cli import (
    _TREASURY_SCRIPT,
    _assert_recovery,
    _Chain,
    _command,
    _edit_record,
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
)


def _said(result: Any) -> str:
    return " ".join(result.output.split())


def _capture_prompts(monkeypatch: pytest.MonkeyPatch, on_prompt: Any = None) -> list[list[str]]:
    """Answer every confirmation prompt "yes", keeping what each one showed."""
    seen: list[list[str]] = []

    def _confirm(summary: list[str], *, ctx: Any, prompt_text: str = "Proceed?") -> bool:
        seen.append(list(summary))
        if on_prompt is not None:
            on_prompt(len(seen))
        return True

    monkeypatch.setattr(glyph_helpers, "confirm_action", _confirm)
    return seen


def _stopped_mint(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch, chain: _Chain, *extra: str, **kw: Any):
    """A WAVE mint whose commit did not confirm in time: ``(txid, result)``; the chain then confirms."""
    chain.confirmations = 0
    _no_wait(monkeypatch)
    result = _mint(tmp_path, kw.pop("label", "abcde"), *extra, **kw)
    assert result.exit_code == 2, result.output
    assert len(chain.broadcasts) == 1
    chain.confirmations = 1
    return str(_tx(chain.broadcasts[0]).txid()), result


# ─────────────────────────────── D-L1: the record's treasury is not taken on its word ──


class TestAnEditedTreasuryIsNotPaidOnTheRecordsWord:
    """resume-mint returned the record's ``wave_treasury`` unchecked: an edited record sent the
    whole fee to another address (10 RXD to it, 0 to the treasury), and the reveal prompt did not
    say it was not the published treasury."""

    @pytest.mark.parametrize("mode", [("--json", "--yes"), ("--yes",)], ids=["json", "human"])
    def test_a_bare_resume_refuses_a_treasury_the_command_line_does_not_name(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch, mode: tuple[str, ...]
    ) -> None:
        chain, _wallet = _wire(monkeypatch)
        txid = _timed_out_mint(tmp_path, monkeypatch, chain)  # pays the PUBLISHED treasury
        assert _store(tmp_path).load(txid).wave_treasury is None
        other = PrivateKey().address()
        _edit_record(tmp_path, txid, wave_treasury=other)

        result = CliRunner().invoke(cli, [*_global(tmp_path, mode=mode), "glyph", "resume-mint", txid])
        assert result.exit_code == 1, result.output
        assert len(chain.broadcasts) == 1  # the commit; nothing paid anywhere
        said = _said(result)
        assert (
            f"the record pays the WAVE registration fee to {other}, which is NOT the published WAVE treasury — "
            "resume-mint pays it only if this command names it too" in said
        )
        # It does not steer the operator into paying it: it says which command would, and which pays nothing.
        assert "If it is not, the record was changed after the mint: do not pay it." in said
        assert f"`{_command(tmp_path, txid, '--no-wave-registration-fee')}`" in said
        assert _store(tmp_path).list_pending() == [txid]

    def test_naming_it_pays_it_and_the_reveal_prompt_says_it_is_not_the_published_treasury(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The honest path: the treasury the operator named to the mint, named again, is paid — and
        the reveal prompt carries the same marker the mint's summary does."""
        chain, _wallet = _wire(monkeypatch)
        treasury = PrivateKey().public_key().address(network=Network.TESTNET)
        txid = _timed_out_mint(tmp_path, monkeypatch, chain, "--wave-treasury", treasury, network="regtest")
        seen = _capture_prompts(monkeypatch)
        result = CliRunner().invoke(
            cli,
            [*_global(tmp_path, network="regtest", mode=()), "glyph", "resume-mint", txid, "--wave-treasury", treasury],
        )
        assert result.exit_code == 0, result.output
        reveal = _tx(chain.broadcasts[1])
        assert reveal.outputs[1].locking_script.serialize() == P2PKH().lock(treasury).serialize()
        [fee_line] = [line for line in seen[-1] if "WAVE fee:" in line]
        assert fee_line == (
            f"    WAVE fee:      10 RXD (1,000,000,000 photons) to {treasury} (vout 1)  (NOT the published WAVE treasury)"
        )

    def test_the_published_treasury_is_not_marked(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _chain, _wallet = _wire(monkeypatch)
        seen = _capture_prompts(monkeypatch)
        result = _mint(tmp_path, "abcde", mode=())
        assert result.exit_code == 0, result.output
        [fee_line] = [line for line in seen[1] if "WAVE fee:" in line]
        assert fee_line == f"    WAVE fee:      10 RXD (1,000,000,000 photons) to {WAVE_TREASURY_ADDRESS} (vout 1)"


# ──────────────────────────── D-L2: asked again after the prompt, before the broadcast ──


class TestTheNameIsAskedAgainAfterTheRevealPrompt:
    """The availability check ran before the reveal prompt and never again: a name registered
    while the prompt waited was paid for, and RXinDexer's own claim path recorded the reveal as a
    DUPLICATE (panel probe A)."""

    def test_a_name_taken_while_the_prompt_waits_is_not_paid_for(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        chain, _wallet = _wire(monkeypatch)

        def _taken_during_the_reveal_prompt(n: int) -> None:
            if n == 2:  # someone else's claim for abcde confirms while this prompt is on screen
                chain.answers = [{"available": False, "ref": "ff" * 32 + "_0", "name": "abcde"}]

        seen = _capture_prompts(monkeypatch, _taken_during_the_reveal_prompt)
        result = _mint(tmp_path, "abcde", mode=())
        assert result.exit_code == 1, result.output
        assert len(seen) == 2 and "    name free:     yes (the indexer says it is free)" in seen[1]
        assert len(chain.broadcasts) == 1  # the commit, and no reveal
        assert chain.asked == [["abcde"]] * 3
        commit = _tx(chain.broadcasts[0])
        txid = str(commit.txid())
        assert "the WAVE name abcde.rxd is registered now — NOT paying the registration fee" in _said(result)
        _assert_recovery(result, tmp_path, txid, commit.outputs[0].satoshis, wave="abcde")

    def test_a_name_still_free_after_the_prompt_is_paid_for_and_registers(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        chain, _wallet = _wire(monkeypatch)
        seen = _capture_prompts(monkeypatch)
        result = _mint(tmp_path, "abcde", mode=())
        assert result.exit_code == 0, result.output
        assert len(seen) == 2 and chain.asked == [["abcde"]] * 3
        reveal = _tx(chain.broadcasts[1])
        assert _scripts(reveal).count(_TREASURY_SCRIPT) == 1
        assert oracle.registers(oracle.to_upstream_tx(reveal)) == oracle.Verdict("abcde.rxd", True)

    def test_resume_mint_asks_again_after_its_prompt_too(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        chain, _wallet = _wire(monkeypatch)
        txid = _timed_out_mint(tmp_path, monkeypatch, chain)
        assert chain.asked == [["abcde"]]

        def _taken_during_the_reveal_prompt(n: int) -> None:
            chain.answers = [{"available": False, "name": "abcde"}]

        _capture_prompts(monkeypatch, _taken_during_the_reveal_prompt)
        result = CliRunner().invoke(cli, [*_global(tmp_path, mode=()), "glyph", "resume-mint", txid])
        assert result.exit_code == 1, result.output
        assert len(chain.broadcasts) == 1 and chain.asked == [["abcde"]] * 3
        assert "registered now — NOT paying" in _said(result)
        assert _store(tmp_path).list_pending() == [txid]


# ─────────────────────────── D-L3: naming the published treasury is naming the default ──


class TestNamingThePublishedTreasuryIsTheDefault:
    def test_resume_mint_accepts_the_published_treasury_named_explicitly(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Refused before, with "the record pays 1Grwk…; this run names 1Grwk…"."""
        chain, _wallet = _wire(monkeypatch)
        txid = _timed_out_mint(tmp_path, monkeypatch, chain)
        result = _resume(tmp_path, txid, "--wave-treasury", WAVE_TREASURY_ADDRESS)
        assert result.exit_code == 0, result.output
        assert _scripts(_tx(chain.broadcasts[1])).count(_TREASURY_SCRIPT) == 1

    def test_another_treasury_is_still_refused_and_the_message_does_not_contradict_itself(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        chain, _wallet = _wire(monkeypatch)
        txid = _timed_out_mint(tmp_path, monkeypatch, chain)
        other = PrivateKey().address()
        result = _resume(tmp_path, txid, "--wave-treasury", other)
        assert result.exit_code == 1 and len(chain.broadcasts) == 1
        said = _said(result)
        assert f"the record pays {WAVE_TREASURY_ADDRESS}; this run names {other}" in said
        assert f"this run names {WAVE_TREASURY_ADDRESS}" not in said


# ───────────────────── E-L2: a value the server disputes blames neither side outright ──


class TestAValueTheServerDisputesKeepsTheRecovery:
    def test_a_server_that_misreports_the_commit_value_is_named_and_the_recovery_kept(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Only the server's number changes. It used to say the untouched record "is not the one
        glyph mint-nft wrote" and drop the resume command."""
        chain, _wallet = _wire(monkeypatch)
        txid = _timed_out_mint(tmp_path, monkeypatch, chain)
        before = _record_path(tmp_path, txid).read_text()
        script, value = chain.utxos[(txid, 0)]
        chain.utxos[(txid, 0)] = (script, value - 1)
        result = _resume(tmp_path, txid)
        assert result.exit_code == 1 and len(chain.broadcasts) == 1
        said = _said(result)
        assert "The record or the server is wrong" in said
        assert "retry against another server (--electrumx <URL>)" in said
        assert "is not the one glyph mint-nft wrote" not in said
        # Both numbers, stated as what each side says — and the recovery, which it used to drop.
        assert f"Its record says it holds {value:,} photons (" in said
        assert f"; the server lists {value - 1:,} photons." in said
        assert f"was broadcast and holds {value:,} photons" not in said  # the record's number, not asserted
        assert f"To reveal this one, run `{_command(tmp_path, txid)}`" in said
        assert _record_path(tmp_path, txid).read_text() == before
        assert json.loads(result.stdout)["commit_txid"] == txid


# ─────────────────────────── D-I1: a second commit for a name already pending is refused ──


class TestASecondCommitForAPendingNameIsRefused:
    def test_a_second_mint_of_the_same_name_is_refused_while_the_first_is_unrevealed(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        chain, _wallet = _wire(monkeypatch)
        txid = _timed_out_mint(tmp_path, monkeypatch, chain)
        second = _mint(tmp_path, "abcde")
        assert second.exit_code == 1, second.output
        assert len(chain.broadcasts) == 1  # no second commit
        said = _said(second)
        assert (
            "this wallet already has an unrevealed commit for the WAVE name abcde.rxd — refusing to commit again"
            in said
        )
        assert f"records the commit {txid}:0" in said
        assert f"`{_command(tmp_path, txid)}`" in said
        assert "--ignore-pending-mint" in said and "Nothing was broadcast." in said
        assert chain.asked == [["abcde"]]  # refused before the indexer was asked again

    def test_the_override_commits_again(self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
        chain, _wallet = _wire(monkeypatch)
        _timed_out_mint(tmp_path, monkeypatch, chain)
        second = _mint(tmp_path, "abcde", "--ignore-pending-mint")
        assert second.exit_code == 0, second.output
        assert len(chain.broadcasts) == 3  # commit A, commit B, reveal B

    def test_a_pending_record_for_another_name_does_not_block(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        chain, _wallet = _wire(monkeypatch)
        _timed_out_mint(tmp_path, monkeypatch, chain)  # abcde
        other = _mint(tmp_path, "abcdf")
        assert other.exit_code == 0, other.output

    def test_a_plain_nft_is_not_checked(self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
        chain, _wallet = _wire(monkeypatch)
        _timed_out_mint(tmp_path, monkeypatch, chain)
        meta = tmp_path / "nft.json"
        meta.write_text(json.dumps({"protocol": ["NFT"], "name": "plain"}))
        result = CliRunner().invoke(cli, [*_global(tmp_path), "glyph", "mint-nft", str(meta)])
        assert result.exit_code == 0, result.output

    def test_an_unreadable_record_does_not_block(self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _chain, _wallet = _wire(monkeypatch)
        (tmp_path / "pending-mints").mkdir()
        (tmp_path / "pending-mints" / ("cd" * 32 + ".json")).write_text("{not json")
        (tmp_path / "pending-mints" / "notes.json").write_text("{}")
        result = _mint(tmp_path, "abcde")
        assert result.exit_code == 0, result.output

    def test_no_pending_directory_is_created_by_the_check(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _chain, _wallet = _wire(monkeypatch, available=[{"available": False}])  # refused before the commit
        assert _mint(tmp_path, "abcde").exit_code == 1
        assert not (tmp_path / "pending-mints").exists()


# ──────────────── D-I2: an unverified mint's choice survives into its printed recovery ──


class TestTheUnverifiedChoiceSurvivesRecovery:
    def test_the_printed_recover_repeats_it_and_runs_as_printed(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        chain, _wallet = _wire(monkeypatch, available=[NetworkError("no indexer")])
        txid, stopped = _stopped_mint(tmp_path, monkeypatch, chain, "--allow-unverified-wave-name")
        doc = json.loads(stopped.stdout)
        assert doc["recover"] == _command(tmp_path, txid, "--allow-unverified-wave-name")
        # Declining pays nothing and checks nothing, so it has no use for the flag.
        assert doc["recover_without_wave_fee"] == _command(tmp_path, txid, "--no-wave-registration-fee")
        recovered = _run_printed(tmp_path, doc["recover"])
        assert recovered.exit_code == 0, recovered.output
        assert _scripts(_tx(chain.broadcasts[1])).count(_TREASURY_SCRIPT) == 1
        assert json.loads(recovered.stdout)["wave_registration"]["name_available"].startswith("NOT VERIFIED")

    def test_a_verified_mint_does_not_gain_it(self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
        chain, _wallet = _wire(monkeypatch)
        txid, stopped = _stopped_mint(tmp_path, monkeypatch, chain)
        assert json.loads(stopped.stdout)["recover"] == _command(tmp_path, txid)

    def test_a_resume_refused_for_want_of_an_answer_offers_the_flag_as_well_as_the_decline(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        chain, _wallet = _wire(monkeypatch, available=[{"available": True}, NetworkError("gone")])
        txid = _timed_out_mint(tmp_path, monkeypatch, chain)
        result = _resume(tmp_path, txid)
        assert result.exit_code == 1 and len(chain.broadcasts) == 1
        said = _said(result)
        assert "could not confirm the WAVE name abcde.rxd is still available — NOT paying" in said
        assert (
            f"`{_command(tmp_path, txid, '--allow-unverified-wave-name')}` — if the name is already registered, "
            "the registration fee buys nothing" in said
        )
        assert f"`{_command(tmp_path, txid, '--no-wave-registration-fee')}`" in said


# ───────────────────── #736: a spend the server invents does not delete the record ──


class TestOnlyARealRevealDeletesTheRecord:
    def test_a_spend_that_does_not_push_the_committed_payload_keeps_the_record(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#736's measurement: the server hides commit:0 and reports a transaction at a height
        that spends it with an empty unlocking script. It hashes to its txid; it could never have
        been valid — the commit output is a hashlock over the payload."""
        chain, _wallet = _wire(monkeypatch)
        txid = _timed_out_mint(tmp_path, monkeypatch, chain)
        invented = chain.spend((txid, 0))
        result = _resume(tmp_path, txid)
        assert result.exit_code == 2, result.output
        said = _said(result)
        assert f"the server lists the commit {txid}:0 neither as unspent nor as spent — the record is kept" in said
        assert invented not in said
        assert _store(tmp_path).list_pending() == [txid]

    def test_bytes_served_under_another_txid_are_not_that_transaction(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The re-hash. The real reveal sits in the mempool; the server ALSO lists a txid at a
        height and serves the real reveal's bytes under it. Believed, that "confirmed" spend
        deletes the record while the only real reveal is unconfirmed."""
        chain, _wallet = _wire(monkeypatch)
        _no_wait(monkeypatch)
        chain.unconfirmed_from = 1  # the reveal is accepted and not mined
        stopped = _mint(tmp_path, "abcde")
        assert stopped.exit_code == 2 and len(chain.broadcasts) == 2
        txid, reveal_txid = (str(_tx(raw).txid()) for raw in chain.broadcasts)
        forged = "ee" * 32
        real_history, real_get = chain.get_history, chain.get_transaction

        async def _history(script_hash: Any) -> list[dict]:
            return [{"tx_hash": forged, "height": 7}, *await real_history(script_hash)]

        async def _get(txid_: Any) -> bytes:
            return chain.txs[reveal_txid] if str(txid_) == forged else await real_get(txid_)

        monkeypatch.setattr(chain, "get_history", _history)
        monkeypatch.setattr(chain, "get_transaction", _get)
        result = _resume(tmp_path, txid)
        assert result.exit_code == 2, result.output
        said = _said(result)
        assert f"the reveal {reveal_txid} was broadcast and has not confirmed yet" in said
        assert forged not in said
        assert _store(tmp_path).list_pending() == [txid]

    def test_the_real_reveal_still_deletes_it(self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """The honest half, end to end: mint-nft's own reveal, left unconfirmed, then mined."""
        chain, _wallet = _wire(monkeypatch)
        _no_wait(monkeypatch)
        chain.unconfirmed_from = 1
        assert _mint(tmp_path, "abcde").exit_code == 2
        txid, reveal_txid = (str(_tx(raw).txid()) for raw in chain.broadcasts)
        chain.unconfirmed.discard(reveal_txid)
        done = _resume(tmp_path, txid)
        assert done.exit_code == 1
        assert f"is already revealed, by {reveal_txid}" in done.stderr
        assert _store(tmp_path).list_pending() == []


# ─────────────── #737: the printed command names no home directory, and runs as printed ──


class TestThePrintedCommandIsPortable:
    def test_a_wallet_under_home_is_shown_home_relative_and_the_command_runs(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("HOME", str(tmp_path))
        chain, _wallet = _wire(monkeypatch)
        txid, stopped = _stopped_mint(tmp_path, monkeypatch, chain)
        doc = json.loads(stopped.stdout)
        assert doc["recover"] == f"pyrxd --network mainnet --wallet ~/w.dat glyph resume-mint {txid}"
        assert str(tmp_path) not in doc["recover"] + doc["recover_without_wave_fee"]
        assert "its record is saved in ~/pending-mints." in _said(stopped)
        # shlex keeps "~/w.dat" literal, as a quoted ~ would reach pyrxd; --wallet expands it.
        recovered = _run_printed(tmp_path, doc["recover"])
        assert recovered.exit_code == 0, recovered.output
        assert _store(tmp_path).list_pending() == []

    @pytest.mark.parametrize("with_passphrase", [True, False], ids=["passphrase", "no-passphrase"])
    def test_a_passphrase_wallet_is_told_to_prompt_for_it_and_it_is_never_printed(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch, with_passphrase: bool
    ) -> None:
        """Through the REAL wallet loader, which is what records that a passphrase was used; only
        the prompts and the decryption are replaced."""
        chain, wallet = _wire(monkeypatch)
        secret = "passphrase-" + os.urandom(6).hex()
        (tmp_path / "w.dat").write_bytes(b"not read: HdWallet.load is replaced")
        opened_with: list[str] = []

        def _load(path: Any, mnemonic: str, passphrase: str) -> Any:
            opened_with.append(passphrase)
            return wallet

        monkeypatch.setattr(prompts, "prompt_mnemonic_input", lambda: "abandon " * 11 + "about")
        monkeypatch.setattr(prompts, "prompt_passphrase_input", lambda optional=True: secret)
        monkeypatch.setattr(prompts.HdWallet, "load", staticmethod(_load))
        monkeypatch.setattr(glyph_cmds, "_load_wallet", prompts._load_wallet)

        flag = ("--passphrase",) if with_passphrase else ()
        txid, stopped = _stopped_mint(tmp_path, monkeypatch, chain, *flag)
        doc = json.loads(stopped.stdout)
        assert doc["recover"] == _command(tmp_path, txid, *flag)
        assert doc["recover_without_wave_fee"] == _command(tmp_path, txid, *flag, "--no-wave-registration-fee")
        assert secret not in stopped.output
        assert ("prompts for this wallet's BIP39 passphrase, which is not printed" in _said(stopped)) is with_passphrase

        recovered = _run_printed(tmp_path, doc["recover"])
        assert recovered.exit_code == 0, recovered.output
        assert opened_with == [secret, secret] if with_passphrase else opened_with == ["", ""]

    def test_an_electrumx_named_on_the_command_line_is_carried(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        chain, _wallet = _wire(monkeypatch)
        chain.confirmations = 0
        _no_wait(monkeypatch)
        url = "wss://electrumx.example.invalid:50022"
        meta = _wave_metadata_file(tmp_path, "abcde")
        stopped = CliRunner().invoke(cli, ["--electrumx", url, *_global(tmp_path), "glyph", "mint-nft", str(meta)])
        assert stopped.exit_code == 2, stopped.output
        txid = str(_tx(chain.broadcasts[-1]).txid())
        wallet = str((tmp_path / "w.dat").absolute())
        expected = shlex.join(
            ["pyrxd", "--electrumx", url, "--network", "mainnet", "--wallet", wallet, "glyph", "resume-mint", txid]
        )
        assert json.loads(stopped.stdout)["recover"] == expected

    def test_a_password_in_the_electrumx_url_is_not_printed(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        chain, _wallet = _wire(monkeypatch)
        chain.confirmations = 0
        _no_wait(monkeypatch)
        url = "wss://operator:hunter2-" + os.urandom(4).hex() + "@electrumx.example.invalid:50022"
        meta = _wave_metadata_file(tmp_path, "abcde")
        stopped = CliRunner().invoke(cli, ["--electrumx", url, *_global(tmp_path), "glyph", "mint-nft", str(meta)])
        assert stopped.exit_code == 2, stopped.output
        recover = json.loads(stopped.stdout)["recover"]
        argv = shlex.split(recover)
        assert argv[argv.index("--electrumx") + 1] == "wss://operator:<password>@electrumx.example.invalid:50022"
        password = url.split(":")[2].split("@")[0]
        assert password.startswith("hunter2-") and password not in stopped.output

    def test_an_electrumx_from_the_environment_is_not_repeated(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The same shell still has it; only what the operator typed is repeated."""
        chain, _wallet = _wire(monkeypatch)
        monkeypatch.setenv("PYRXD_ELECTRUMX", "wss://electrumx.example.invalid:50022")
        txid, stopped = _stopped_mint(tmp_path, monkeypatch, chain)
        assert json.loads(stopped.stdout)["recover"] == _command(tmp_path, txid)
