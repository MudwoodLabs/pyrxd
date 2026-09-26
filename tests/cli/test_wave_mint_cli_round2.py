"""``glyph mint-nft`` / ``resume-mint``, PR #742 round 2: lane D's re-review of ``defd2ff8``.

Each class is one of lane D's attacks, reproduced through the real click command, with the
honest path it must leave working:

1. #736 by two routes that round 1 did not close — a spend forged with a junk signature and the
   RIGHT payload, and a genuine reveal echoed but never relayed, then reported confirmed. Both
   used to delete the record while the commit was unspent. Now no record is ever deleted: it is
   archived to ``pending-mints/done/``, and ``resume-mint`` against an honest server finds it and
   finishes the mint.
2. The record's word deciding money: an edit from ``decline`` to ``pay`` made a bare resume pay
   100 RXD, and a refusal printed a ready-to-run command paying an edited treasury. Now the fee
   choice is stated on the command line, the record only cross-checks it, and no printed command
   pays a treasury other than the published one.
3. The pending-name check reading another network's record: a regtest record for ``abcde``
   refused a mainnet mint of ``abcde``. Records now carry their network.

The fake chain and wallet are ``test_wave_registration_fee_cli.py``'s; the liars below wrap that
chain and change only the answers named.
"""

from __future__ import annotations

import json
import os
import pathlib
import stat
from typing import Any

import pytest
from click.testing import CliRunner

from pyrxd.cli import glyph_cmds
from pyrxd.cli.main import cli
from pyrxd.constants import Network
from pyrxd.glyph.inspector import GlyphInspector
from pyrxd.glyph.mint import PendingMint
from pyrxd.keys import PrivateKey
from pyrxd.network.electrumx import script_hash_for_script
from pyrxd.script.script import Script
from pyrxd.security.errors import ValidationError
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput

from .test_wave_registration_fee_cli import (
    _DECLINE,
    _PAY,
    _TREASURY_SCRIPT,
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
    _wire,
    reveal_envelope,
)


def _said(result: Any) -> str:
    return " ".join(result.output.split())


def _archived(tmp_path: pathlib.Path, txid: str) -> pathlib.Path:
    return tmp_path / "pending-mints" / "done" / f"{txid}.json"


def _use(monkeypatch: pytest.MonkeyPatch, server: Any) -> None:
    """Every command from here on talks to ``server``."""
    monkeypatch.setattr(glyph_cmds.CliContext, "make_client", lambda self: server)


class _Liar:
    """``chain`` with some answers replaced; everything else is the chain's."""

    def __init__(self, chain: _Chain) -> None:
        self.chain = chain

    async def __aenter__(self) -> _Liar:
        return self

    async def __aexit__(self, *exc: object) -> bool:
        return False

    def __getattr__(self, name: str) -> Any:
        return getattr(self.chain, name)


class _ForgesASpend(_Liar):
    """Hides ``commit:0`` and reports a transaction at a height that spends it and pushes the exact
    payload — with a junk signature. It hashes to its own txid. Lane D built one by matching the
    commit's payload hash from the label it was sent in wave.check_available; here it is handed
    the payload, which is the capability that matters."""

    def __init__(self, chain: _Chain, commit_txid: str, commit_script: bytes, cbor: bytes) -> None:
        super().__init__(chain)
        self.commit = (commit_txid, 0)
        self.commit_script_hash = bytes(script_hash_for_script(commit_script))
        inp = TransactionInput(
            source_txid=commit_txid, source_output_index=0, unlocking_script=Script(reveal_envelope(cbor))
        )
        forged = Transaction(tx_inputs=[inp], tx_outputs=[TransactionOutput(Script(b"\x6a"), 0)])
        self.forged_raw = bytes(forged.serialize())
        self.forged_txid = str(forged.txid())

    async def get_utxos(self, script_hash: Any) -> list:
        return [u for u in await self.chain.get_utxos(script_hash) if (u.tx_hash, u.tx_pos) != self.commit]

    async def get_history(self, script_hash: Any) -> list[dict]:
        history = await self.chain.get_history(script_hash)
        if bytes(script_hash) == self.commit_script_hash:
            history = [*history, {"tx_hash": self.forged_txid, "height": 5}]
        return history

    async def get_transaction(self, txid: Any) -> bytes:
        return self.forged_raw if str(txid) == self.forged_txid else await self.chain.get_transaction(txid)


class _WithholdsTheReveal(_Liar):
    """Echoes a reveal's txid without relaying it, then reports it confirmed."""

    def __init__(self, chain: _Chain) -> None:
        super().__init__(chain)
        self.withheld: list[str] = []

    async def broadcast(self, raw: bytes) -> str:
        tx = _tx(bytes(raw))
        if any(GlyphInspector().extract_reveal_cbor(i.unlocking_script.serialize()) for i in tx.inputs):
            self.withheld.append(str(tx.txid()))
            return str(tx.txid())
        return await self.chain.broadcast(raw)

    async def get_transaction_verbose(self, txid: Any) -> dict:
        if str(txid) in self.withheld:
            return {"confirmations": 1}
        return await self.chain.get_transaction_verbose(txid)


# ─────────────────────── (1) #736: no server's word deletes a record; resume finds it ──


class TestNoServerWordDeletesARecord:
    def test_a_spend_forged_with_the_right_payload_archives_and_an_honest_server_finishes(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        chain, _wallet = _wire(monkeypatch)
        txid = _timed_out_mint(tmp_path, monkeypatch, chain)
        record = _store(tmp_path).load(txid)
        liar = _ForgesASpend(chain, txid, record.commit_script, record.cbor_bytes)
        _use(monkeypatch, liar)
        fooled = _resume(tmp_path, txid, _PAY)
        assert fooled.exit_code == 1 and f"is already revealed, by {liar.forged_txid}" in fooled.stderr
        assert (txid, 0) in chain.utxos  # the commit is still unspent on chain
        # Before round 2 the record was gone here. It is archived instead:
        assert _store(tmp_path).list_pending() == [] and _archived(tmp_path, txid).exists()
        assert "run this command again against another server (--electrumx)" in _said(fooled)

        _use(monkeypatch, chain)  # an honest server
        finished = _resume(tmp_path, txid, _PAY)
        assert finished.exit_code == 0, finished.output
        reveal = _tx(chain.broadcasts[1])
        assert (reveal.inputs[0].source_txid, reveal.inputs[0].source_output_index) == (txid, 0)
        assert _scripts(reveal).count(_TREASURY_SCRIPT) == 1
        assert _store(tmp_path).list_pending() == [] and _archived(tmp_path, txid).exists()

    @pytest.mark.parametrize("first", ["mint-nft", "resume-mint"])
    def test_a_reveal_echoed_but_never_relayed_archives_and_an_honest_server_finishes(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch, first: str
    ) -> None:
        chain, _wallet = _wire(monkeypatch)
        liar = _WithholdsTheReveal(chain)
        if first == "mint-nft":
            _use(monkeypatch, liar)
            fooled = _mint(tmp_path, "abcde")
            txid = str(_tx(chain.broadcasts[0]).txid())
        else:
            txid = _timed_out_mint(tmp_path, monkeypatch, chain)
            _use(monkeypatch, liar)
            fooled = _resume(tmp_path, txid, _PAY)
        # The liar reported the reveal confirmed, so the command "succeeded"...
        assert fooled.exit_code == 0, fooled.output
        assert liar.withheld and len(chain.broadcasts) == 1  # ...and only the commit is on chain
        assert (txid, 0) in chain.utxos
        assert _store(tmp_path).list_pending() == [] and _archived(tmp_path, txid).exists()

        _use(monkeypatch, chain)
        finished = _resume(tmp_path, txid, _PAY)
        assert finished.exit_code == 0, finished.output
        assert len(chain.broadcasts) == 2 and (txid, 0) not in chain.utxos
        assert _scripts(_tx(chain.broadcasts[1])).count(_TREASURY_SCRIPT) == 1

    def test_an_honest_mint_archives_its_record_and_the_next_mint_is_not_refused(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        chain, _wallet = _wire(monkeypatch)
        first = _mint(tmp_path, "abcde")
        assert first.exit_code == 0, first.output
        txid = str(_tx(chain.broadcasts[0]).txid())
        archived = _archived(tmp_path, txid)
        assert _store(tmp_path).list_pending() == [] and archived.exists()
        if os.name == "posix":
            assert stat.S_IMODE(archived.stat().st_mode) == 0o600
            assert stat.S_IMODE(archived.parent.stat().st_mode) == 0o700
        assert PendingMint.from_dict(json.loads(archived.read_text())).commit_txid == txid
        second = _mint(tmp_path, "abcdf")
        assert second.exit_code == 0, second.output

    def test_a_txid_with_no_record_anywhere_says_where_it_looked(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _chain, _wallet = _wire(monkeypatch)
        result = _resume(tmp_path, "ab" * 32, _PAY)
        assert result.exit_code == 1
        said = _said(result)
        assert f"no pending mint recorded for {'ab' * 32}" in said
        assert str(tmp_path / "pending-mints" / "done") in said


# ────────────────── (2) the record's word never decides a money question ──


class TestTheRecordNeverDecidesMoney:
    def test_a_decline_edited_to_pay_pays_nothing_without_a_stated_choice(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Lane D: a 3-character name (100 RXD) minted with --no-wave-registration-fee; the record
        edited to pay; a bare resume-mint paid. Now it is refused, and the command the mint
        printed still declines."""
        chain, _wallet = _wire(monkeypatch)
        chain.confirmations = 0
        _no_wait(monkeypatch)
        # MINIMAL metadata, as lane D used: its commit's reveal-fee slack also covers a reveal with
        # the fee's input and output, so no balance gate stands in for the fix. (With the fuller
        # metadata file the other tests use, defd2ff8 refused this for its balance instead — a
        # refusal for the wrong reason.) On defd2ff8 this bare resume paid 10,000,000,000 photons.
        meta = tmp_path / "abc.json"
        meta.write_text(json.dumps({"protocol": ["NFT", "MUT", "WAVE"], "attrs": {"name": "abc"}}))
        stopped = CliRunner().invoke(cli, [*_global(tmp_path), "glyph", "mint-nft", str(meta), _DECLINE])
        assert stopped.exit_code == 2
        doc = json.loads(stopped.stdout)
        txid = doc["commit_txid"]
        chain.confirmations = 1
        _edit_record(tmp_path, txid, wave_fee="pay", wave_treasury=None)

        bare = _resume(tmp_path, txid)
        assert bare.exit_code == 1 and len(chain.broadcasts) == 1
        assert "resume-mint needs the WAVE registration fee choice for abc.rxd on its command line" in _said(bare)

        declined = _run_printed(tmp_path, doc["recover"])  # the command the mint printed
        assert declined.exit_code == 0, declined.output
        assert _TREASURY_SCRIPT not in _scripts(_tx(chain.broadcasts[1]))

    @pytest.mark.parametrize("choice", ["pay", "decline"])
    def test_the_command_printed_at_mint_time_finishes_in_one_step(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch, choice: str
    ) -> None:
        chain, _wallet = _wire(monkeypatch)
        chain.confirmations = 0
        _no_wait(monkeypatch)
        stopped = _mint(tmp_path, "abcde", *([_DECLINE] if choice == "decline" else []))
        assert stopped.exit_code == 2
        doc = json.loads(stopped.stdout)
        assert doc["recover"].endswith(_PAY if choice == "pay" else _DECLINE)
        chain.confirmations = 1
        done = _run_printed(tmp_path, doc["recover"])
        assert done.exit_code == 0, done.output
        paid = _scripts(_tx(chain.broadcasts[1])).count(_TREASURY_SCRIPT)
        assert paid == (1 if choice == "pay" else 0)

    def test_no_output_prints_a_paying_command_for_an_edited_treasury(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Lane D ran the command round 1's refusal printed, and it paid the edited address.
        Every command this refusal prints either declines or pays the published treasury, or
        leaves the address for the operator to type."""
        chain, _wallet = _wire(monkeypatch)
        txid = _timed_out_mint(tmp_path, monkeypatch, chain)
        other = PrivateKey().address()
        _edit_record(tmp_path, txid, wave_treasury=other)
        for stated in ((), (_PAY,)):
            refused = _resume(tmp_path, txid, *stated)
            assert refused.exit_code == 1
            said = _said(refused)
            commands = [c for c in said.split("`")[1::2] if c.startswith("pyrxd ")]
            assert commands, said
            for command in commands:
                assert other not in command
                ran = _run_printed(tmp_path, command)
                if ran.exit_code == 0:
                    # Only a declining command can run as printed here: the record no longer
                    # agrees with a paying one.
                    assert _DECLINE in command
                    assert _TREASURY_SCRIPT not in _scripts(_tx(chain.broadcasts[-1]))
                    return
        raise AssertionError("no printed command finished the mint")


# ──────────────────── (3) records carry their network; the check filters on it ──


class TestRecordsCarryTheirNetwork:
    def test_a_regtest_record_does_not_refuse_a_mainnet_mint_of_the_same_name(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        chain, _wallet = _wire(monkeypatch)
        treasury = PrivateKey().public_key().address(network=Network.TESTNET)
        txid = _timed_out_mint(tmp_path, monkeypatch, chain, "--wave-treasury", treasury, network="regtest")
        assert _store(tmp_path).load(txid).network == "regtest"
        mainnet = _mint(tmp_path, "abcde")
        assert mainnet.exit_code == 0, mainnet.output
        regtest = _mint(tmp_path, "abcde", "--wave-treasury", treasury, network="regtest")
        assert regtest.exit_code == 1
        assert "already has an unrevealed commit for the WAVE name abcde.rxd" in _said(regtest)

    def test_resume_on_the_wrong_network_is_refused_and_names_the_right_one(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        chain, _wallet = _wire(monkeypatch)
        treasury = PrivateKey().public_key().address(network=Network.TESTNET)
        txid = _timed_out_mint(tmp_path, monkeypatch, chain, "--wave-treasury", treasury, network="regtest")
        wrong = _resume(tmp_path, txid, _DECLINE)  # mainnet
        assert wrong.exit_code == 1 and len(chain.broadcasts) == 1
        said = _said(wrong)
        assert f"the record for {txid} is for regtest, and this run is on mainnet" in said
        assert f"`{_command(tmp_path, txid, '--wave-treasury', '<ADDRESS>', network='regtest')}`" in said
        right = _resume(tmp_path, txid, _DECLINE, network="regtest")
        assert right.exit_code == 0, right.output

    def test_a_record_written_before_records_had_a_network_is_counted_and_says_so(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No network is known, so it is counted on every network (overridable), the refusal says
        why, and it resumes on the network it is run on."""
        chain, _wallet = _wire(monkeypatch)
        txid = _timed_out_mint(tmp_path, monkeypatch, chain)
        d = json.loads(_record_path(tmp_path, txid).read_text())
        del d["network"]
        d["schema_version"] = 2
        _record_path(tmp_path, txid).write_text(json.dumps(d))
        assert _store(tmp_path).load(txid).network is None

        again = _mint(tmp_path, "abcde")
        assert again.exit_code == 1
        assert f"The record for {txid} does not say which network its commit is on" in _said(again)
        resumed = _resume(tmp_path, txid, _PAY)
        assert resumed.exit_code == 0, resumed.output


class TestThePendingMintRecordCarriesItsNetwork:
    def _record(self, **kw: Any) -> PendingMint:
        from pyrxd.glyph.builder import CommitParams, GlyphBuilder
        from pyrxd.glyph.types import GlyphMetadata, GlyphProtocol
        from pyrxd.security.types import Hex20

        key = PrivateKey()
        pkh = Hex20(key.public_key().hash160())
        commit = GlyphBuilder().prepare_commit(
            CommitParams(
                metadata=GlyphMetadata(protocol=[GlyphProtocol.NFT], name="plain"),
                owner_pkh=pkh,
                change_pkh=pkh,
                funding_satoshis=0,
            )
        )
        base = dict(
            commit_txid="ab" * 32,
            commit_vout=0,
            commit_value=10_000,
            commit_script=commit.commit_script,
            cbor_bytes=commit.cbor_bytes,
            owner_pkh=bytes(pkh),
            is_nft=True,
            carrier_value=546,
            fee_rate=10_000,
            funding_address=key.address(),
        )
        base.update(kw)
        return PendingMint(**base)

    def test_version_3_round_trips_the_network(self) -> None:
        record = self._record(network="regtest")
        d = record.to_dict()
        assert (d["schema_version"], d["network"]) == (3, "regtest")
        assert PendingMint.from_dict(d) == record

    def test_a_record_without_one_is_written_as_before(self) -> None:
        assert "network" not in self._record().to_dict() and self._record().to_dict()["schema_version"] == 1

    @pytest.mark.parametrize(
        ("change", "message"),
        [
            ({"schema_version": 1}, "carries a network it cannot hold"),
            ({"network": None}, "must be one of"),
            ({"network": "REGTEST"}, "must be one of"),
        ],
    )
    def test_a_record_that_misstates_it_is_refused(self, change: dict, message: str) -> None:
        d = self._record(network="regtest").to_dict()
        d.update(change)
        with pytest.raises(ValidationError, match=message):
            PendingMint.from_dict(d)

    def test_version_3_must_carry_it(self) -> None:
        d = self._record(network="mainnet").to_dict()
        del d["network"]
        with pytest.raises(ValidationError, match="is missing its network"):
            PendingMint.from_dict(d)


# ─────────────── (5) nothing says a name is free: "no confirmed registration" ──


def test_the_mint_output_claims_no_confirmed_registration_not_a_free_name(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RXinDexer answers wave.check_available from mined blocks only, so a claim still in the
    mempool is invisible to it; "free" overstated that (lane D round 2, info)."""
    _chain, _wallet = _wire(monkeypatch)
    result = _mint(tmp_path, "abcde")
    assert result.exit_code == 0, result.output
    said = _said(result)
    assert "registered: none confirmed (the indexer does not see a claim that is not yet mined)" in said
    assert "says it is free" not in said and "name free:" not in said
    wave = json.loads(result.stdout)["wave_registration"]
    assert wave["name_available"] == "none confirmed (the indexer does not see a claim that is not yet mined)"


def test_the_cli_store_archives_even_when_asked_to_delete(tmp_path: pathlib.Path) -> None:
    """No second door: ``delete`` on the store ``_pending_store`` hands out moves the record to
    ``done/``, so code in the CLI that "deletes" a record cannot lose it."""
    from pyrxd.cli.config import Config

    ctx = glyph_cmds.CliContext(config=Config(), wallet_path=tmp_path / "w.dat")
    store = glyph_cmds._pending_store(ctx)
    record = TestThePendingMintRecordCarriesItsNetwork()._record(network="mainnet")
    store.save(record)
    store.delete(record.commit_txid)
    assert store.list_pending() == [] and store.list_archived() == [record.commit_txid]
    assert store.load_archived(record.commit_txid) == record
    store.restore(record.commit_txid)
    assert store.list_pending() == [record.commit_txid] and store.list_archived() == []
