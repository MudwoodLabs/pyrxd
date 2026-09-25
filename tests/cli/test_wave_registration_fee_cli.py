"""``pyrxd glyph mint-nft`` and ``resume-mint`` paying the WAVE registration fee: the CLI half.

Driven through the REAL click command (``cli``) with two fakes at the network boundary and
nothing else replaced:

- ``_Chain`` stands in for ElectrumX. It keeps a UTXO set: a broadcast spends its inputs (and
  is refused, like a node, if one is missing) and adds its outputs, so "is the fee's funding
  input still unspent?" is answered from what the transactions did, not from a canned value.
  ``wave.check_available`` is answered through ``call_extension`` exactly as the RXinDexer
  extension answers it (a dict with an ``available`` boolean), so the real
  :class:`~pyrxd.glyph.wave.WaveResolver` and ``RxinDexerClient`` parse it.
- ``_Wallet`` lists whatever the chain holds for its one key.

The library half (the price, the treasury, the estimator, the balance gate) is
``tests/test_wave_registration_fee.py``; the regtest half, against a real node,
``tests/test_wave_registration_fee_regtest_e2e.py``.
"""

from __future__ import annotations

import functools
import json
import os
import pathlib
import shlex
from collections.abc import Callable
from typing import Any

import pytest
from click.testing import CliRunner

from pyrxd.cli import glyph_cmds
from pyrxd.cli.main import cli
from pyrxd.constants import Network
from pyrxd.glyph.inspector import GlyphInspector
from pyrxd.glyph.mint import JsonFilePendingStore
from pyrxd.glyph.script import build_nft_locking_script
from pyrxd.glyph.types import GlyphRef
from pyrxd.glyph.wave_rules import WAVE_TREASURY_ADDRESS, wave_registered_label
from pyrxd.keys import PrivateKey
from pyrxd.network import confirm
from pyrxd.network.electrumx import UtxoRecord, script_hash_for_script
from pyrxd.script.script import Script
from pyrxd.script.type import P2PKH
from pyrxd.security.errors import NetworkError, PolicyRejection
from pyrxd.security.types import Hex20, Txid
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput

TARGET = "1BoatSLRHtKNngkdXEeobR76b53LETtpyT"
#: ``WAVE_TREASURY_ADDRESS_DEFAULT`` (RXinDexer ``wave_index.py:65``) as a script, spelled out:
#: OP_DUP OP_HASH160 <adfbf871…> OP_EQUALVERIFY OP_CHECKSIG, the bytes mainnet claim
#: ``f644794b…`` paid at vout 2.
_TREASURY_SCRIPT = bytes.fromhex("76a914adfbf871b5084e8108dd95309451dbcdc88c405a88ac")
#: The tiers, spelled out rather than computed by the function under test.
_PRICE = {"abcd": 5_000_000_000, "abcde": 1_000_000_000, "custodian-gate-x7f3": 500_000_000}
_FEE_RATE = 10_000  # the default relay floor, photons per byte


# ───────────────────────────────────────────────────────── the network boundary ──


class _Chain:
    """ElectrumX, as far as ``mint-nft`` and ``resume-mint`` use it, over a real UTXO set."""

    def __init__(self, *, available: list[Any] | None = None) -> None:
        self.txs: dict[str, bytes] = {}
        self.utxos: dict[tuple[str, int], tuple[bytes, int]] = {}
        self.broadcasts: list[bytes] = []
        self.confirmations = 1
        #: One answer per ``wave.check_available`` call; the last one repeats. An Exception
        #: instance is raised instead of returned.
        self.answers: list[Any] = [{"available": True}] if available is None else available
        self.asked: list[list[Any]] = []
        #: Called with (index, raw) before each broadcast is accepted; may raise.
        self.before_broadcast: Callable[[int, bytes], None] | None = None
        #: Called with the txid on every confirmation poll; may raise.
        self.on_poll: Callable[[str], None] | None = None
        #: Accepted but not yet mined: 0 confirmations, height 0 in history.
        self.unconfirmed: set[str] = set()
        #: Broadcasts from this index on stay unconfirmed (None: every broadcast confirms).
        self.unconfirmed_from: int | None = None
        #: Outpoints the server leaves out of get_utxos although they are unspent.
        self.hidden: set[tuple[str, int]] = set()
        #: txid -> the scripts of the outputs its inputs spent (for get_history).
        self.spent_scripts: dict[str, list[bytes]] = {}

    async def __aenter__(self) -> _Chain:
        return self

    async def __aexit__(self, *exc: object) -> bool:
        return False

    def fund(self, script: bytes, value: int) -> UtxoRecord:
        """A confirmed transaction paying ``value`` to ``script`` at vout 1 (vout 0 is a unique
        OP_RETURN, so two fundings never share a txid)."""
        tx = Transaction(
            tx_inputs=[],
            tx_outputs=[
                TransactionOutput(Script(b"\x6a\x20" + os.urandom(32)), 0),
                TransactionOutput(Script(script), value),
            ],
        )
        self._accept(tx, bytes(tx.serialize()))
        return UtxoRecord(tx_hash=str(tx.txid()), tx_pos=1, value=value, height=100)

    def _accept(self, tx: Transaction, raw: bytes) -> str:
        txid = str(tx.txid())
        spent = []
        for i in tx.inputs:
            spent.append(self.utxos.pop((i.source_txid, i.source_output_index))[0])
        self.spent_scripts[txid] = spent
        for n, out in enumerate(tx.outputs):
            self.utxos[(txid, n)] = (out.locking_script.serialize(), out.satoshis)
        self.txs[txid] = raw
        return txid

    async def broadcast(self, raw: bytes) -> str:
        raw = bytes(raw)
        if self.before_broadcast is not None:
            self.before_broadcast(len(self.broadcasts), raw)
        tx = Transaction.from_hex(raw)
        missing = [
            f"{i.source_txid}:{i.source_output_index}"
            for i in tx.inputs
            if (i.source_txid, i.source_output_index) not in self.utxos
        ]
        if missing:
            raise NetworkError(f"missing inputs: {missing}")  # what a node says
        if self.unconfirmed_from is not None and len(self.broadcasts) >= self.unconfirmed_from:
            self.unconfirmed.add(str(tx.txid()))
        self.broadcasts.append(raw)
        return self._accept(tx, raw)

    def spend(self, outpoint: tuple[str, int], *, confirmed: bool = True) -> str:
        """Another transaction spends ``outpoint`` (a reveal made elsewhere, say)."""
        inp = TransactionInput(source_txid=outpoint[0], source_output_index=outpoint[1])
        tx = Transaction(tx_inputs=[inp], tx_outputs=[TransactionOutput(Script(b"\x6a"), 0)])
        txid = self._accept(tx, bytes(tx.serialize()))
        if not confirmed:
            self.unconfirmed.add(txid)
        return txid

    async def get_history(self, script_hash: Any) -> list[dict]:
        def _touches(txid: str) -> bool:
            outs = [o.locking_script.serialize() for o in _tx(self.txs[txid]).outputs]
            return any(bytes(script_hash_for_script(s)) == bytes(script_hash) for s in outs + self.spent_scripts[txid])

        return [
            {"tx_hash": txid, "height": 0 if txid in self.unconfirmed else 1} for txid in self.txs if _touches(txid)
        ]

    async def get_transaction(self, txid: Any) -> bytes:
        try:
            return self.txs[str(txid)]
        except KeyError:
            raise NetworkError(f"no such transaction {txid}") from None

    async def get_transaction_verbose(self, txid: Any) -> dict:
        if self.on_poll is not None:
            self.on_poll(str(txid))
        known = str(txid) in self.txs and str(txid) not in self.unconfirmed
        return {"confirmations": self.confirmations if known else 0}

    async def get_utxos(self, script_hash: Any) -> list[UtxoRecord]:
        return [
            UtxoRecord(tx_hash=txid, tx_pos=vout, value=value, height=100)
            for (txid, vout), (script, value) in self.utxos.items()
            if bytes(script_hash_for_script(script)) == bytes(script_hash) and (txid, vout) not in self.hidden
        ]

    async def call_extension(self, method: str, params: list[Any]) -> Any:
        assert method == "wave.check_available", method
        self.asked.append(list(params))
        answer = self.answers[min(len(self.asked) - 1, len(self.answers) - 1)]
        if isinstance(answer, BaseException):
            raise answer
        return answer


class _Wallet:
    """One key; its spendable set is whatever the chain holds for it."""

    def __init__(self, key: PrivateKey, chain: _Chain) -> None:
        self.key = key
        self.chain = chain
        self.address = key.address()
        self.script = P2PKH().lock(self.address).serialize()

    async def collect_spendable(self, client: object) -> list:
        return [(u, self.address, self.key) for u in await self.chain.get_utxos(script_hash_for_script(self.script))]

    def privkey_for_address(self, address: str) -> PrivateKey:
        if address != self.address:
            from pyrxd.security.errors import ValidationError

            raise ValidationError(f"{address} is not in this wallet")
        return self.key


def _wire(
    monkeypatch: pytest.MonkeyPatch, *, available: list[Any] | None = None, funding: int = 20_000_000_000
) -> tuple[_Chain, _Wallet]:
    for var in ("PYRXD_NETWORK", "PYRXD_ELECTRUMX", "PYRXD_FEE_RATE", "PYRXD_WALLET_PATH"):
        monkeypatch.delenv(var, raising=False)  # hermetic: the fee rate is the default relay floor
    chain = _Chain(available=available)
    wallet = _Wallet(PrivateKey(), chain)
    if funding:
        chain.fund(wallet.script, funding)
    monkeypatch.setattr(glyph_cmds, "_load_wallet", lambda ctx, **kw: wallet)
    monkeypatch.setattr(glyph_cmds.CliContext, "make_client", lambda self: chain)
    return chain, wallet


def _wave_metadata_file(tmp_path: pathlib.Path, label: str) -> pathlib.Path:
    """A metadata.json that registers ``label``.rxd, in the file format ``mint-nft`` reads."""
    path = tmp_path / f"{label}.json"
    path.write_text(
        json.dumps(
            {
                "protocol": ["NFT", "MUT", "WAVE"],
                "name": f"{label}.rxd",
                "token_type": "wave_name",
                "attrs": {"name": label, "domain": "rxd", "target": TARGET, "target_type": "address"},
            }
        )
    )
    return path


def _global(
    tmp_path: pathlib.Path, *, network: str = "mainnet", mode: tuple[str, ...] = ("--json", "--yes")
) -> list[str]:
    # --config at a path that does not exist: defaults only, never the developer's own file.
    return ["--config", str(tmp_path / "absent.toml"), "--network", network, "--wallet", str(tmp_path / "w.dat"), *mode]


def _mint(
    tmp_path: pathlib.Path,
    label: str,
    *extra: str,
    network: str = "mainnet",
    mode: tuple[str, ...] = ("--json", "--yes"),
    input: str | None = None,
) -> Any:
    args = [
        *_global(tmp_path, network=network, mode=mode),
        "glyph",
        "mint-nft",
        str(_wave_metadata_file(tmp_path, label)),
    ]
    return CliRunner().invoke(cli, [*args, *extra], input=input)


def _resume(tmp_path: pathlib.Path, txid: str, *extra: str, network: str = "mainnet") -> Any:
    return CliRunner().invoke(cli, [*_global(tmp_path, network=network), "glyph", "resume-mint", txid, *extra])


def _store(tmp_path: pathlib.Path) -> JsonFilePendingStore:
    return JsonFilePendingStore(tmp_path / "pending-mints")


def _tx(raw: bytes) -> Transaction:
    tx = Transaction.from_hex(raw)
    assert tx is not None
    return tx


def _outpoints(tx: Transaction) -> list[tuple[str, int]]:
    return [(i.source_txid, i.source_output_index) for i in tx.inputs]


def _scripts(tx: Transaction) -> list[bytes]:
    return [o.locking_script.serialize() for o in tx.outputs]


def _miner_fee(chain: _Chain, tx: Transaction) -> int:
    spent = 0
    for i in tx.inputs:
        spent += _tx(chain.txs[i.source_txid]).outputs[i.source_output_index].satoshis
    return spent - sum(o.satoshis for o in tx.outputs)


# ─────────────────────────────────────────────── (1) the shape of what is paid ──


class TestTheFeeIsFundedAtRevealTimeFromAWalletInput:
    @pytest.mark.parametrize("label", ["abcd", "custodian-gate-x7f3"])
    def test_the_reveal_spends_the_commit_and_its_change_and_pays_the_treasury_at_vout_1(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch, label: str
    ) -> None:
        chain, wallet = _wire(monkeypatch)
        result = _mint(tmp_path, label)
        assert result.exit_code == 0, result.output
        commit, reveal = (_tx(raw) for raw in chain.broadcasts)
        commit_txid = str(commit.txid())
        price = _PRICE[label]

        # The commit carries what it carried before: the carrier and the reveal's miner fee.
        # Nothing for the registration fee is locked in it.
        assert len(commit.outputs) == 2
        assert commit.outputs[0].satoshis < price
        assert commit.outputs[1].locking_script.serialize() == wallet.script  # change, to the wallet

        # The reveal: the commit output, and the commit's change as the wallet input that pays.
        assert _outpoints(reveal) == [(commit_txid, 0), (commit_txid, 1)]
        assert len(reveal.inputs[1].unlocking_script.serialize()) < 110  # a plain P2PKH unlock
        # [NFT carrier, the fee, change]: Photonic's order, minus the mutable contract.
        assert reveal.outputs[0].satoshis == 546
        assert (reveal.outputs[1].locking_script.serialize(), reveal.outputs[1].satoshis) == (_TREASURY_SCRIPT, price)
        assert _scripts(reveal).count(_TREASURY_SCRIPT) == 1
        assert reveal.outputs[2].locking_script.serialize() == wallet.script and reveal.outputs[2].satoshis > 0
        # It balances at the relay floor, and what the fee input held beyond the fee came back.
        assert _miner_fee(chain, reveal) >= len(reveal.serialize()) * _FEE_RATE
        assert reveal.outputs[2].satoshis > commit.outputs[1].satoshis - price - commit.outputs[0].satoshis
        # The name the indexer would register is the one paid for.
        cbor = GlyphInspector().extract_reveal_cbor(reveal.inputs[0].unlocking_script.serialize())
        assert wave_registered_label(cbor) == label
        # Done: the record is gone.
        assert _store(tmp_path).list_pending() == []

    def test_the_json_and_the_disclosure_name_the_fee_the_treasury_and_the_input(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        chain, _wallet = _wire(monkeypatch)
        result = _mint(tmp_path, "abcde")
        assert result.exit_code == 0, result.output
        commit_txid = str(_tx(chain.broadcasts[0]).txid())
        payload = json.loads(result.stdout)
        assert payload["wave_registration"] == {
            "name": "abcde.rxd",
            "fee_paid": True,
            "fee": {
                "name": "abcde.rxd",
                "photons": 1_000_000_000,
                "rxd": "10",
                "treasury": WAVE_TREASURY_ADDRESS,
                "published_treasury": True,
                "locking_script": _TREASURY_SCRIPT.hex(),
            },
            "fee_vout": 1,
            "fee_input": f"{commit_txid}:1",
            "name_available": "yes (the indexer says it is free)",
        }
        # --yes still discloses; --json sends the disclosure to stderr. Both confirmations.
        err = result.stderr
        assert "WAVE registration fee" in err and "10.00000000 RXD" in err and WAVE_TREASURY_ADDRESS in err
        assert "from a wallet input (not the commit)" in err
        assert f"fee input:     {commit_txid}:1" in err
        assert "total cost:" in err and "+ WAVE registration fee)" in err
        assert "WAVE fee:      10 RXD (1,000,000,000 photons) to " + WAVE_TREASURY_ADDRESS in err

    def test_the_disclosed_treasury_is_the_one_paid(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """P3: a confirmation that printed the published treasury while the reveal paid another
        would be a lie the user cannot see through."""
        chain, _wallet = _wire(monkeypatch)
        treasury = PrivateKey().public_key().address(network=Network.TESTNET)
        result = _mint(tmp_path, "abcde", "--wave-treasury", treasury, network="regtest")
        assert result.exit_code == 0, result.output
        reveal = _tx(chain.broadcasts[1])
        assert reveal.outputs[1].locking_script.serialize() == P2PKH().lock(treasury).serialize()
        assert f"treasury:      {treasury}  (NOT the published WAVE treasury)" in result.stderr
        assert WAVE_TREASURY_ADDRESS not in result.stderr

    def test_the_opt_out_reveals_from_the_commit_alone_and_says_so(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        chain, _wallet = _wire(monkeypatch)
        result = _mint(tmp_path, "abcde", "--no-wave-registration-fee")
        assert result.exit_code == 0, result.output
        commit, reveal = (_tx(raw) for raw in chain.broadcasts)
        assert _outpoints(reveal) == [(str(commit.txid()), 0)]
        assert _TREASURY_SCRIPT not in _scripts(reveal) and len(reveal.outputs) == 2
        wave = json.loads(result.stdout)["wave_registration"]
        assert (wave["fee_paid"], wave["fee"], wave["fee_input"]) == (False, None, None)
        assert "NOT PAID" in result.stderr and "renewing it" in result.stderr

    def test_a_plain_nft_asks_no_indexer_and_pays_nothing(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        chain, _wallet = _wire(monkeypatch)
        meta = tmp_path / "nft.json"
        meta.write_text(json.dumps({"protocol": ["NFT"], "name": "plain"}))
        result = CliRunner().invoke(cli, [*_global(tmp_path), "glyph", "mint-nft", str(meta)])
        assert result.exit_code == 0, result.output
        assert "wave_registration" not in json.loads(result.stdout)
        reveal = _tx(chain.broadcasts[1])
        assert len(reveal.inputs) == 1 and len(reveal.outputs) == 2  # commit -> NFT + change
        assert chain.asked == []

    @pytest.mark.parametrize("network", ["regtest", "testnet"])
    def test_off_mainnet_it_needs_a_treasury_or_the_opt_out(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch, network: str
    ) -> None:
        chain, _wallet = _wire(monkeypatch)
        result = _mint(tmp_path, "abcde", network=network)
        assert result.exit_code != 0
        assert f"no WAVE treasury is published for {network}" in result.output
        assert chain.broadcasts == []

    def test_a_token_utxo_is_never_the_funding_even_when_it_is_the_largest(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The commit's change pays the fee, so the commit's funding must be plain RXD. The
        selector checks the on-chain script; mint-nft used to pick the largest UTXO by value."""
        chain, wallet = _wire(monkeypatch, funding=0)
        pkh = Hex20(wallet.key.public_key().hash160())
        token = chain.fund(build_nft_locking_script(pkh, GlyphRef(txid=Txid("cd" * 32), vout=0)), 90_000_000_000)
        plain = chain.fund(wallet.script, 20_000_000_000)

        # The wallet reports the token UTXO as its own (a wallet scans by address), and it is
        # the largest one.
        async def _both(client: object) -> list:
            return [
                (
                    UtxoRecord(tx_hash=token.tx_hash, tx_pos=1, value=token.value, height=100),
                    wallet.address,
                    wallet.key,
                ),
                (plain, wallet.address, wallet.key),
            ]

        monkeypatch.setattr(wallet, "collect_spendable", _both)
        result = _mint(tmp_path, "abcde")
        assert result.exit_code == 0, result.output
        assert _outpoints(_tx(chain.broadcasts[0])) == [(plain.tx_hash, 1)]
        assert (token.tx_hash, 1) in chain.utxos  # the token is untouched


# ──────────────────────────────────────────────────── (2) is the name free? ──


_UNANSWERED = [
    pytest.param(NetworkError("connection refused"), id="unreachable"),
    pytest.param({"available": False, "error": "invalid name"}, id="error-dict"),
    pytest.param({"available": "yes"}, id="not-a-bool"),
    pytest.param([True], id="not-a-dict"),
    pytest.param(RuntimeError("-32601 unknown method"), id="no-extension"),
]


class TestTheNameMustBeFree:
    def test_the_label_the_indexer_is_asked_about_is_the_bare_one_before_the_commit_and_the_reveal(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        chain, _wallet = _wire(monkeypatch)
        assert _mint(tmp_path, "abcde").exit_code == 0
        assert chain.asked == [["abcde"], ["abcde"]]

    def test_a_taken_name_is_refused_before_anything_is_broadcast(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        chain, _wallet = _wire(monkeypatch, available=[{"available": False, "ref": "ab" * 32 + "_0", "name": "abcde"}])
        result = _mint(tmp_path, "abcde")
        assert result.exit_code == 1
        assert "the WAVE name abcde.rxd is already registered" in result.stderr
        assert "Nothing was broadcast." in result.stderr
        assert chain.broadcasts == [] and _store(tmp_path).list_pending() == []

    @pytest.mark.parametrize("answer", _UNANSWERED)
    def test_an_unverifiable_name_is_refused_without_the_flag(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch, answer: Any
    ) -> None:
        chain, _wallet = _wire(monkeypatch, available=[answer])
        result = _mint(tmp_path, "abcde")
        assert result.exit_code == 1
        assert "could not confirm the WAVE name abcde.rxd is available" in result.stderr
        assert "--allow-unverified-wave-name" in result.stderr and "buys nothing" in result.stderr
        assert chain.broadcasts == []

    @pytest.mark.parametrize("answer", _UNANSWERED)
    def test_an_unverifiable_name_goes_ahead_with_the_flag_and_says_so(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch, answer: Any
    ) -> None:
        chain, _wallet = _wire(monkeypatch, available=[answer])
        result = _mint(tmp_path, "abcde", "--allow-unverified-wave-name")
        assert result.exit_code == 0, result.output
        assert _scripts(_tx(chain.broadcasts[1])).count(_TREASURY_SCRIPT) == 1
        assert json.loads(result.stdout)["wave_registration"]["name_available"].startswith("NOT VERIFIED")
        assert "NOT VERIFIED (--allow-unverified-wave-name): if it is taken, the fee buys nothing" in result.stderr

    def test_the_flag_help_says_the_fee_may_buy_nothing(self) -> None:
        for command in ("mint-nft", "resume-mint"):
            out = CliRunner().invoke(cli, ["glyph", command, "--help"]).output
            flat = " ".join(out.split())
            assert "--allow-unverified-wave-name" in flat and "registration fee buys NOTHING" in flat

    def test_a_name_taken_between_commit_and_reveal_is_not_paid_for(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        chain, _wallet = _wire(monkeypatch, available=[{"available": True}, {"available": False, "name": "abcde"}])
        result = _mint(tmp_path, "abcde")
        assert result.exit_code == 1
        assert len(chain.broadcasts) == 1  # the commit, and no reveal
        commit = _tx(chain.broadcasts[0])
        txid = str(commit.txid())
        assert "the WAVE name abcde.rxd is registered now — NOT paying the registration fee" in result.stderr
        _assert_recovery(result, tmp_path, txid, commit.outputs[0].satoshis, wave="abcde")

        # The recovery it printed works: the commit is revealed with no fee, from the commit alone.
        chain.answers = [{"available": False}]
        recovered = _resume(tmp_path, txid, "--no-wave-registration-fee")
        assert recovered.exit_code == 0, recovered.output
        reveal = _tx(chain.broadcasts[1])
        assert _outpoints(reveal) == [(txid, 0)]
        assert _TREASURY_SCRIPT not in _scripts(reveal)
        assert json.loads(recovered.stdout)["wave_registration"]["fee_paid"] is False
        assert _store(tmp_path).list_pending() == []

    def test_an_unverifiable_name_after_the_commit_is_not_paid_for_without_the_flag(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        chain, _wallet = _wire(monkeypatch, available=[{"available": True}, NetworkError("gone")])
        result = _mint(tmp_path, "abcde")
        assert result.exit_code == 1 and len(chain.broadcasts) == 1
        assert "could not confirm the WAVE name abcde.rxd is still available — NOT paying" in result.stderr
        commit = _tx(chain.broadcasts[0])
        _assert_recovery(result, tmp_path, str(commit.txid()), commit.outputs[0].satoshis, wave="abcde")

    def test_resume_mint_pays_only_if_the_name_is_still_free(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        chain, _wallet = _wire(monkeypatch, available=[{"available": True}, {"available": False}])
        first = _mint(tmp_path, "abcde")
        txid = str(_tx(chain.broadcasts[0]).txid())
        assert first.exit_code == 1
        again = _resume(tmp_path, txid)  # still taken
        assert again.exit_code == 1 and "NOT paying" in again.stderr and len(chain.broadcasts) == 1
        assert f"resume-mint {txid} --no-wave-registration-fee" in again.stderr


# ─────────────────────────────── (3) every exit after the commit names the recovery ──


def _command(tmp_path: pathlib.Path, txid: str, *extra: str, network: str = "mainnet") -> str:
    """The resume command the CLI must print: the globals that find the record, then the choice."""
    wallet = str((tmp_path / "w.dat").absolute())
    return shlex.join(["pyrxd", "--network", network, "--wallet", wallet, "glyph", "resume-mint", txid, *extra])


def _assert_recovery(
    result: Any, tmp_path: pathlib.Path, txid: str, value: int, *, wave: str | None, declined: bool = False
) -> None:
    """The commit txid, what it holds, where the record is and how to finish — never "re-run"."""
    said = " ".join(result.output.split())
    assert f"The commit {txid}:0 was broadcast and holds {value:,} photons" in said
    assert f"its record is saved in {tmp_path / 'pending-mints'}" in said
    resume = _command(tmp_path, txid, *(["--no-wave-registration-fee"] if declined else []))
    assert (
        f"Do not re-run the mint command: that commits, and spends, again. To reveal this one, run `{resume}`." in said
    )
    assert "nothing is stranded" not in said
    assert "re-run with the inputs" not in said
    if wave is None:
        assert "--no-wave-registration-fee" not in said
    elif declined:
        # M2: the mint's opt-out is repeated, never replaced by the paying default.
        assert (
            f"This mint declined the WAVE registration fee for {wave}.rxd, and that command keeps that choice" in said
        )
        assert "pays the registration fee from a wallet input only if" not in said
    else:
        # Pay only if the name is still free; otherwise reveal without the fee.
        assert (
            f"resume-mint checks {wave}.rxd is still free and pays the registration fee from a wallet input only if it is"
            in said
        )
        assert f"`{_command(tmp_path, txid, '--no-wave-registration-fee')}`" in said
    record = _store(tmp_path).load(txid)
    assert (record.commit_txid, record.commit_value) == (txid, value)


def _no_wait(monkeypatch: pytest.MonkeyPatch) -> None:
    """The real waiter, bounded to one poll with no sleep, so a timeout is reachable in a test."""

    async def _no_sleep(_s: float) -> None:
        return None

    monkeypatch.setattr(
        glyph_cmds,
        "wait_for_confirmation",
        functools.partial(confirm.wait_for_confirmation, max_iterations=1, sleep=_no_sleep),
    )


def _declined(chain: _Chain, monkeypatch: pytest.MonkeyPatch) -> dict:
    return {"mode": (), "input": "y\nn\n"}  # yes to the commit, no to the reveal


def _reveal_broadcast_fails(chain: _Chain, monkeypatch: pytest.MonkeyPatch) -> dict:
    def _fail(n: int, raw: bytes) -> None:
        if n == 1:
            raise NetworkError("the server hung up")

    chain.before_broadcast = _fail
    return {}


def _times_out(chain: _Chain, monkeypatch: pytest.MonkeyPatch) -> dict:
    chain.confirmations = 0
    _no_wait(monkeypatch)
    return {}


def _interrupted(chain: _Chain, monkeypatch: pytest.MonkeyPatch) -> dict:
    def _ctrl_c(txid: str) -> None:
        raise KeyboardInterrupt

    chain.on_poll = _ctrl_c
    return {}


def _crashes(chain: _Chain, monkeypatch: pytest.MonkeyPatch) -> dict:
    def _boom(txid: str) -> None:
        raise RuntimeError("an unexpected failure")

    chain.on_poll = _boom
    return {}


def _funding_spent(chain: _Chain, monkeypatch: pytest.MonkeyPatch) -> dict:
    """The commit's change — the fee's funding input — is spent by something else before the reveal."""

    def _spend_change(txid: str) -> None:
        chain.utxos.pop((txid, 1), None)

    chain.on_poll = _spend_change
    return {}


_EXITS: dict[str, tuple[Callable[[_Chain, pytest.MonkeyPatch], dict], str, int]] = {
    "declined": (_declined, "the reveal was not broadcast: aborted by user", 1),
    "reveal-network-error": (_reveal_broadcast_fails, "a server stopped answering after the commit was broadcast", 2),
    "timeout": (_times_out, "timed out waiting for confirmation", 2),
    "ctrl-c": (_interrupted, "interrupted after the commit was broadcast", 1),
    "crash": (_crashes, "interrupted after the commit was broadcast", 1),
    "funding-spent": (_funding_spent, "is spent or not visible — NOT paying", 1),
}


class TestEveryExitAfterTheCommitNamesTheRecovery:
    @pytest.mark.parametrize(
        ("exit_name", "label"),
        [pytest.param(e, "abcde", id=f"wave-{e}") for e in sorted(_EXITS)]
        # A plain NFT's reveal has no wallet input, so it has no funding input to lose.
        + [pytest.param(e, None, id=f"plain-{e}") for e in sorted(_EXITS) if e != "funding-spent"],
    )
    def test_the_commit_its_value_its_record_and_how_to_finish(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch, exit_name: str, label: str | None
    ) -> None:
        setup, headline, code = _EXITS[exit_name]
        chain, _wallet = _wire(monkeypatch)
        kw = setup(chain, monkeypatch)
        if label is None:
            meta = tmp_path / "nft.json"
            meta.write_text(json.dumps({"protocol": ["NFT"], "name": "plain"}))
            args = [*_global(tmp_path, mode=kw.get("mode", ("--json", "--yes"))), "glyph", "mint-nft", str(meta)]
            result = CliRunner().invoke(cli, args, input=kw.get("input"))
        else:
            result = _mint(tmp_path, label, mode=kw.get("mode", ("--json", "--yes")), input=kw.get("input"))
        assert result.exit_code == code, result.output
        assert len(chain.broadcasts) == 1  # the commit, and no reveal
        commit = _tx(chain.broadcasts[0])
        assert headline in " ".join(result.output.split())
        _assert_recovery(result, tmp_path, str(commit.txid()), commit.outputs[0].satoshis, wave=label)

    def test_in_json_mode_the_recovery_is_on_stdout_too(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Errors go to stderr; a script reading stdout used to get nothing to act on."""
        chain, _wallet = _wire(monkeypatch)
        _reveal_broadcast_fails(chain, monkeypatch)
        result = _mint(tmp_path, "abcde")
        assert result.exit_code == 2
        txid = str(_tx(chain.broadcasts[0]).txid())
        doc = json.loads(result.stdout)
        assert doc == {
            "status": "commit_broadcast_reveal_not_done",
            "commit_txid": txid,
            "commit_vout": 0,
            "commit_value": _tx(chain.broadcasts[0]).outputs[0].satoshis,
            "reveal_txid": None,
            "pending_record": str(tmp_path / "pending-mints" / f"{txid}.json"),
            "wave_name": "abcde.rxd",
            "wave_fee": "pay",
            "recover": _command(tmp_path, txid),
            "recover_without_wave_fee": _command(tmp_path, txid, "--no-wave-registration-fee"),
        }

    @pytest.mark.parametrize("mode", [("--json", "--yes"), ("--yes",)], ids=["json", "human"])
    def test_a_failed_commit_broadcast_says_it_may_have_relayed_and_what_to_do_either_way(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch, mode: tuple[str, ...]
    ) -> None:
        """A server can drop the connection after relaying. "Check the server is reachable"
        invites a second mint that commits, and spends, again."""
        chain, _wallet = _wire(monkeypatch)

        def _hang_up(n: int, raw: bytes) -> None:
            if n == 0:
                raise NetworkError("connection reset")

        chain.before_broadcast = _hang_up
        result = _mint(tmp_path, "abcde", mode=mode)
        assert result.exit_code == 2 and chain.broadcasts == []
        [txid] = _store(tmp_path).list_pending()
        said = " ".join(result.output.split())
        assert "the commit broadcast failed, and the commit may or may not have reached the network" in said
        assert f"look up {txid} on a block explorer before running anything else" in said
        assert f"`{_command(tmp_path, txid)}`" in said
        assert f"If it never appears, nothing was spent: delete {tmp_path / 'pending-mints' / (txid + '.json')}" in said
        if mode[0] == "--json":
            assert json.loads(result.stdout)["status"] == "commit_broadcast_failed_may_have_relayed"

    def test_the_record_exists_before_the_commit_is_broadcast(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        chain, _wallet = _wire(monkeypatch)
        seen: list[list[str]] = []
        chain.before_broadcast = lambda n, raw: seen.append(_store(tmp_path).list_pending()) if n == 0 else None
        assert _mint(tmp_path, "abcde").exit_code == 0
        assert seen == [[str(_tx(chain.broadcasts[0]).txid())]]

    def test_the_timeout_text_is_conditional_on_the_name_and_true(self) -> None:
        """M1 and H2 in the text every command that waits shares."""
        import asyncio

        from pyrxd.cli.errors import NetworkBoundaryError

        class _Never:
            async def get_transaction_verbose(self, txid: Any) -> dict:
                return {"confirmations": 0}

        with pytest.raises(NetworkBoundaryError) as exc:
            asyncio.run(glyph_cmds._wait_for_tx(_Never(), "ab" * 32, timeout_s=0.02, interval_s=0.01))
        fix = " ".join(str(exc.value.fix).split())
        assert "nothing is stranded" not in fix
        assert "do not simply re-run the command: that would commit, and spend, again" in fix
        assert "print, with this error, the exact `pyrxd glyph resume-mint` command" in fix
        assert "only source" not in fix
        assert "If it declined the fee, build with pay_registration_fee=False" in fix
        assert "ONLY if WaveResolver.check_available says the name is still free" in fix
        assert "build with pay_registration_fee=False" in fix


# ──────────────────────────────────────────────────────────── (4) resume-mint ──


class TestResumeMint:
    def test_after_a_timeout_it_reveals_and_pays_from_a_plain_wallet_utxo(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        chain, wallet = _wire(monkeypatch)
        chain.confirmations = 0
        _no_wait(monkeypatch)
        assert _mint(tmp_path, "abcde").exit_code == 2
        commit = _tx(chain.broadcasts[0])
        txid = str(commit.txid())

        chain.confirmations = 1
        result = _resume(tmp_path, txid)
        assert result.exit_code == 0, result.output
        reveal = _tx(chain.broadcasts[1])
        # The commit, then a plain wallet UTXO (here the commit's change, which the wallet now
        # holds) — never the commit output as the fee's source.
        assert _outpoints(reveal)[0] == (txid, 0)
        assert len(reveal.inputs) == 2 and _outpoints(reveal)[1] != (txid, 0)
        fee_in = reveal.inputs[1]
        assert chain.txs[fee_in.source_txid]
        assert (
            _tx(chain.txs[fee_in.source_txid]).outputs[fee_in.source_output_index].locking_script.serialize()
            == wallet.script
        )
        assert (reveal.outputs[1].locking_script.serialize(), reveal.outputs[1].satoshis) == (
            _TREASURY_SCRIPT,
            1_000_000_000,
        )
        assert _store(tmp_path).list_pending() == []

    def test_a_commit_spent_by_a_confirmed_transaction_has_nothing_to_recover(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        chain, _wallet = _wire(monkeypatch)
        txid = _timed_out_mint(tmp_path, monkeypatch, chain)
        spender = chain.spend((txid, 0))  # revealed elsewhere, and mined
        result = _resume(tmp_path, txid)
        assert result.exit_code == 1
        assert f"the commit {txid}:0 is already revealed, by {spender}" in result.stderr
        assert "Do not re-run the mint" not in result.stderr  # not pointed at a recovery that finds nothing
        assert _store(tmp_path).list_pending() == []
        assert len(chain.broadcasts) == 1

    def test_no_record_is_a_clear_refusal(self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
        chain, _wallet = _wire(monkeypatch)
        result = _resume(tmp_path, "ab" * 32)
        assert result.exit_code == 1 and f"no pending mint recorded for {'ab' * 32}" in result.stderr
        assert chain.broadcasts == []

    def test_another_wallet_cannot_reveal_it(self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
        chain, _wallet = _wire(monkeypatch)
        chain.confirmations = 0
        _no_wait(monkeypatch)
        _mint(tmp_path, "abcde")
        txid = str(_tx(chain.broadcasts[0]).txid())
        other = _Wallet(PrivateKey(), chain)
        monkeypatch.setattr(glyph_cmds, "_load_wallet", lambda ctx, **kw: other)
        result = _resume(tmp_path, txid)
        assert result.exit_code == 1 and "this wallet cannot reveal that commit" in result.stderr
        assert len(chain.broadcasts) == 1

    def test_no_plain_utxo_for_the_fee_stops_before_paying(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        chain, _wallet = _wire(monkeypatch)
        chain.confirmations = 0
        _no_wait(monkeypatch)
        _mint(tmp_path, "abcde")
        commit = _tx(chain.broadcasts[0])
        txid = str(commit.txid())
        chain.utxos.pop((txid, 1))  # the wallet spent its change elsewhere; nothing else holds 10 RXD
        chain.confirmations = 1
        result = _resume(tmp_path, txid)
        assert result.exit_code == 1 and len(chain.broadcasts) == 1
        assert "no plain-RXD wallet UTXO holds the 10 RXD WAVE registration fee for abcde.rxd" in result.stderr
        _assert_recovery(result, tmp_path, txid, commit.outputs[0].satoshis, wave="abcde")


# ─────────────────────── (5) resume-mint trusts nothing it reads (round 3: M1-M3, L1, L2) ──


def _timed_out_mint(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch, chain: _Chain, *extra: str, **kw: Any
) -> str:
    """A WAVE mint whose commit did not confirm in time: exit 2, one broadcast, the record on disk.
    The chain then confirms, so the next resume-mint finds the commit mined."""
    chain.confirmations = 0
    _no_wait(monkeypatch)
    result = _mint(tmp_path, kw.pop("label", "abcde"), *extra, **kw)
    assert result.exit_code == 2, result.output
    assert len(chain.broadcasts) == 1
    chain.confirmations = 1
    return str(_tx(chain.broadcasts[0]).txid())


def _record_path(tmp_path: pathlib.Path, txid: str) -> pathlib.Path:
    return tmp_path / "pending-mints" / f"{txid}.json"


def _edit_record(tmp_path: pathlib.Path, txid: str, **changes: Any) -> None:
    path = _record_path(tmp_path, txid)
    d = json.loads(path.read_text())
    d.update(changes)
    path.write_text(json.dumps(d))


def _run_printed(tmp_path: pathlib.Path, command: str) -> Any:
    """Run a command the CLI printed, exactly, behind the hermetic config and --json --yes."""
    argv = shlex.split(command)
    assert argv[0] == "pyrxd"
    return CliRunner().invoke(cli, ["--config", str(tmp_path / "absent.toml"), "--json", "--yes", *argv[1:]])


def _spent_value(chain: _Chain, inp: Any) -> int:
    return _tx(chain.txs[inp.source_txid]).outputs[inp.source_output_index].satoshis


class TestResumeMintReadsTheRecordWithSuspicion:
    """L1 and N15: the record must be this txid's, reproduce its commit script from this
    wallet, mint to this wallet, and agree with the chain about the commit's value."""

    def test_a_record_filed_under_another_txid_is_refused(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        chain, _wallet = _wire(monkeypatch)
        txid = _timed_out_mint(tmp_path, monkeypatch, chain)
        other = "cd" * 32
        _record_path(tmp_path, other).write_text(_record_path(tmp_path, txid).read_text())
        result = _resume(tmp_path, other)
        assert result.exit_code == 1 and len(chain.broadcasts) == 1
        assert f"the record for {other} does not match: commit_txid" in result.stderr

    def test_a_record_that_mints_to_someone_else_is_refused(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """owner_pkh is not part of the commit script, so the script check alone passes it."""
        chain, _wallet = _wire(monkeypatch)
        txid = _timed_out_mint(tmp_path, monkeypatch, chain)
        _edit_record(tmp_path, txid, owner_pkh=PrivateKey().public_key().hash160().hex())
        result = _resume(tmp_path, txid)
        assert result.exit_code == 1 and len(chain.broadcasts) == 1
        assert f"the record for {txid} does not match: owner_pkh" in result.stderr

    def test_a_commit_value_the_chain_does_not_list_is_refused(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        chain, _wallet = _wire(monkeypatch)
        txid = _timed_out_mint(tmp_path, monkeypatch, chain)
        on_chain = chain.utxos[(txid, 0)][1]
        _edit_record(tmp_path, txid, commit_value=on_chain + 1_000_000)
        result = _resume(tmp_path, txid)
        assert result.exit_code == 1 and len(chain.broadcasts) == 1
        said = " ".join(result.output.split())
        assert f"the record for {txid} does not match: commit_value" in said
        assert f"the server lists {on_chain:,}" in said

    def test_a_payload_that_does_not_reproduce_the_commit_script_is_refused(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """N15: the commit script is re-derived from the stored payload and this wallet's key."""
        import cbor2

        chain, _wallet = _wire(monkeypatch)
        txid = _timed_out_mint(tmp_path, monkeypatch, chain)
        claim = cbor2.loads(_store(tmp_path).load(txid).cbor_bytes)
        claim["attrs"]["target"] = PrivateKey().public_key().address()  # still a valid claim for abcde
        _edit_record(tmp_path, txid, cbor_bytes=cbor2.dumps(claim).hex())
        result = _resume(tmp_path, txid)
        assert result.exit_code == 1 and len(chain.broadcasts) == 1
        assert "does not reproduce its commit script" in " ".join(result.output.split())

    def test_the_honest_record_still_reveals(self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """The other half of every refusal above: the untouched record goes through."""
        chain, _wallet = _wire(monkeypatch)
        txid = _timed_out_mint(tmp_path, monkeypatch, chain)
        assert _resume(tmp_path, txid).exit_code == 0
        assert len(chain.broadcasts) == 2 and _store(tmp_path).list_pending() == []


class TestResumeMintNeverOverpays:
    """M1: a record's fee_rate is read off disk. Signing at 10,000,000 (the per-kB constant)
    paid 58.1 RXD to miners, taken from the wallet's largest plain UTXO."""

    @pytest.mark.parametrize("rate", [10_000_000, 5_000], ids=["per-kB-as-per-byte", "below-the-floor"])
    def test_a_fee_rate_outside_the_relay_band_is_refused_before_signing(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch, rate: int
    ) -> None:
        chain, _wallet = _wire(monkeypatch)
        txid = _timed_out_mint(tmp_path, monkeypatch, chain)
        _edit_record(tmp_path, txid, fee_rate=rate)
        result = _resume(tmp_path, txid)
        assert result.exit_code == 1 and len(chain.broadcasts) == 1
        said = " ".join(result.output.split())
        assert (
            f"the commit's record asks for a reveal fee rate of {rate:,} photons/byte — refusing to sign at it" in said
        )
        assert str(_record_path(tmp_path, txid)) in said
        assert _store(tmp_path).list_pending() == [txid]

    def test_a_rate_the_commit_was_not_sized_for_is_not_paid_by_the_wallet(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """M1(b): 100,000 photons/byte is inside the band (10x the floor), but the commit was
        sized at 10,000. The difference would come out of the wallet input, which pays only the
        registration fee and its own change."""
        chain, _wallet = _wire(monkeypatch)
        txid = _timed_out_mint(tmp_path, monkeypatch, chain)
        _edit_record(tmp_path, txid, fee_rate=100_000)
        result = _resume(tmp_path, txid)
        assert result.exit_code == 1 and len(chain.broadcasts) == 1
        assert "so the wallet input would pay the miner" in " ".join(result.output.split())

    def test_the_reveal_fee_comes_out_of_the_commit(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The honest half, measured: the wallet input pays the registration fee and gets the rest back."""
        chain, _wallet = _wire(monkeypatch)
        txid = _timed_out_mint(tmp_path, monkeypatch, chain)
        assert _resume(tmp_path, txid).exit_code == 0
        reveal = _tx(chain.broadcasts[1])
        commit_in, fee_in = (_spent_value(chain, i) for i in reveal.inputs)
        nft, fee_out, change = (o.satoshis for o in reveal.outputs)
        assert fee_out == 1_000_000_000
        assert change >= fee_in - fee_out
        assert commit_in >= nft + _miner_fee(chain, reveal)


class TestAnOptOutSurvivesRecovery:
    """M2: after `mint-nft --no-wave-registration-fee`, every exit and the JSON `recover`
    field used to recommend a plain `resume-mint`, which pays by default. Running it paid
    10 RXD the user had declined."""

    def test_the_printed_command_and_recover_keep_the_decline(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        chain, _wallet = _wire(monkeypatch)
        chain.confirmations = 0
        _no_wait(monkeypatch)
        result = _mint(tmp_path, "abcde", "--no-wave-registration-fee")
        assert result.exit_code == 2
        txid = str(_tx(chain.broadcasts[0]).txid())
        commit_value = _tx(chain.broadcasts[0]).outputs[0].satoshis
        _assert_recovery(result, tmp_path, txid, commit_value, wave="abcde", declined=True)
        doc = json.loads(result.stdout)
        assert doc["wave_fee"] == "decline"
        assert doc["recover"] == _command(tmp_path, txid, "--no-wave-registration-fee")
        assert doc["recover_without_wave_fee"] is None
        assert _store(tmp_path).load(txid).wave_fee == "decline"

        chain.confirmations = 1
        recovered = _run_printed(tmp_path, doc["recover"])
        assert recovered.exit_code == 0, recovered.output
        reveal = _tx(chain.broadcasts[1])
        assert _outpoints(reveal) == [(txid, 0)] and _TREASURY_SCRIPT not in _scripts(reveal)
        assert json.loads(recovered.stdout)["wave_registration"]["fee_paid"] is False

    def test_the_command_in_the_human_text_keeps_the_decline_too(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        chain, _wallet = _wire(monkeypatch)
        chain.confirmations = 0
        _no_wait(monkeypatch)
        result = _mint(tmp_path, "abcde", "--no-wave-registration-fee", mode=("--yes",))
        assert result.exit_code == 2
        txid = str(_tx(chain.broadcasts[0]).txid())
        said = " ".join(result.output.split())
        printed = said.split("To reveal this one, run `", 1)[1].split("`", 1)[0]
        assert printed == _command(tmp_path, txid, "--no-wave-registration-fee")
        chain.confirmations = 1
        recovered = _run_printed(tmp_path, printed)
        assert recovered.exit_code == 0, recovered.output
        assert _TREASURY_SCRIPT not in _scripts(_tx(chain.broadcasts[1]))

    def test_the_stored_decline_holds_even_for_a_bare_resume(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        chain, _wallet = _wire(monkeypatch)
        txid = _timed_out_mint(tmp_path, monkeypatch, chain, "--no-wave-registration-fee")
        bare = _resume(tmp_path, txid)
        assert bare.exit_code == 0, bare.output
        assert _TREASURY_SCRIPT not in _scripts(_tx(chain.broadcasts[1]))

    @pytest.mark.parametrize(
        "flags", [("--wave-registration-fee",), ("--wave-treasury", WAVE_TREASURY_ADDRESS)], ids=["pay", "treasury"]
    )
    def test_resume_mint_will_not_pay_what_the_mint_declined(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch, flags: tuple[str, ...]
    ) -> None:
        chain, _wallet = _wire(monkeypatch)
        txid = _timed_out_mint(tmp_path, monkeypatch, chain, "--no-wave-registration-fee")
        result = _resume(tmp_path, txid, *flags)
        assert result.exit_code == 1 and len(chain.broadcasts) == 1
        assert "resume-mint will not pay what the mint declined" in " ".join(result.output.split())

    def test_a_named_treasury_is_repeated_and_honoured(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        chain, _wallet = _wire(monkeypatch)
        treasury = PrivateKey().public_key().address(network=Network.TESTNET)
        chain.confirmations = 0
        _no_wait(monkeypatch)
        result = _mint(tmp_path, "abcde", "--wave-treasury", treasury, network="regtest")
        assert result.exit_code == 2
        txid = str(_tx(chain.broadcasts[0]).txid())
        doc = json.loads(result.stdout)
        assert doc["recover"] == _command(tmp_path, txid, "--wave-treasury", treasury, network="regtest")
        other = PrivateKey().public_key().address(network=Network.TESTNET)
        chain.confirmations = 1
        refused = _resume(tmp_path, txid, "--wave-treasury", other, network="regtest")
        assert refused.exit_code == 1 and "--wave-treasury is not the treasury the mint chose" in refused.stderr
        recovered = _run_printed(tmp_path, doc["recover"])
        assert recovered.exit_code == 0, recovered.output
        assert _tx(chain.broadcasts[1]).outputs[1].locking_script.serialize() == P2PKH().lock(treasury).serialize()

    def test_a_taken_name_with_a_named_treasury_recovers_without_the_fee(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The printed "if the name is taken" command, for a mint that named a treasury. Found by
        the regtest e2e: the declining run kept the recorded treasury and was refused for it."""
        chain, _wallet = _wire(monkeypatch, available=[{"available": True}, {"available": False}])
        treasury = PrivateKey().public_key().address(network=Network.TESTNET)
        stopped = _mint(tmp_path, "abcde", "--wave-treasury", treasury, network="regtest")
        assert stopped.exit_code == 1 and len(chain.broadcasts) == 1
        doc = json.loads(stopped.stdout)
        txid = doc["commit_txid"]
        assert doc["recover_without_wave_fee"] == _command(
            tmp_path, txid, "--no-wave-registration-fee", network="regtest"
        )
        recovered = _run_printed(tmp_path, doc["recover_without_wave_fee"])
        assert recovered.exit_code == 0, recovered.output
        reveal = _tx(chain.broadcasts[1])
        assert _outpoints(reveal) == [(txid, 0)]
        assert P2PKH().lock(treasury).serialize() not in _scripts(reveal)

    def test_a_record_without_a_choice_needs_the_flag_said(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A registering record that does not say (not written by mint-nft) is not guessed at."""
        chain, _wallet = _wire(monkeypatch)
        txid = _timed_out_mint(tmp_path, monkeypatch, chain)
        d = json.loads(_record_path(tmp_path, txid).read_text())
        del d["wave_fee"], d["wave_treasury"]
        d["schema_version"] = 1
        _record_path(tmp_path, txid).write_text(json.dumps(d))
        refused = _resume(tmp_path, txid)
        assert refused.exit_code == 1 and len(chain.broadcasts) == 1
        assert "does not say whether the WAVE registration fee is paid" in " ".join(refused.output.split())
        declined = _resume(tmp_path, txid, "--no-wave-registration-fee")
        assert declined.exit_code == 0, declined.output
        assert _TREASURY_SCRIPT not in _scripts(_tx(chain.broadcasts[1]))


class TestTheRecordIsDeletedOnlyOnPositiveEvidence:
    """M3: an empty unspent list is not evidence the commit was spent. And the record outlives
    the reveal's broadcast until the reveal confirms."""

    def test_an_empty_unspent_list_keeps_the_record(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        chain, _wallet = _wire(monkeypatch)
        txid = _timed_out_mint(tmp_path, monkeypatch, chain)
        chain.hidden.add((txid, 0))  # unspent on chain; the server lists nothing
        result = _resume(tmp_path, txid)
        assert result.exit_code == 2 and len(chain.broadcasts) == 1
        said = " ".join(result.output.split())
        assert f"the server lists the commit {txid}:0 neither as unspent nor as spent — the record is kept" in said
        assert _store(tmp_path).list_pending() == [txid]
        assert json.loads(result.stdout)["commit_txid"] == txid  # --json: the document is on stdout too

    def test_the_record_is_kept_until_the_reveal_confirms(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        chain, _wallet = _wire(monkeypatch)
        _no_wait(monkeypatch)
        chain.unconfirmed_from = 1  # the reveal is accepted and not mined
        result = _mint(tmp_path, "abcde")
        assert result.exit_code == 2 and len(chain.broadcasts) == 2
        txid, reveal_txid = (str(_tx(raw).txid()) for raw in chain.broadcasts)
        said = " ".join(result.output.split())
        assert f"the reveal {reveal_txid} was broadcast and has not confirmed yet" in said
        assert f"The reveal {reveal_txid} of the commit {txid}:0 was broadcast" in said
        assert _store(tmp_path).list_pending() == [txid]
        doc = json.loads(result.stdout)
        assert (doc["status"], doc["reveal_txid"]) == ("reveal_broadcast_not_confirmed", reveal_txid)

        # Still in the mempool: resume-mint finds it, waits, and keeps the record.
        waiting = _resume(tmp_path, txid)
        assert waiting.exit_code == 2 and _store(tmp_path).list_pending() == [txid]
        assert f"the reveal {reveal_txid} was broadcast and has not confirmed yet" in " ".join(waiting.output.split())
        assert len(chain.broadcasts) == 2
        # Mined: resume-mint finds the confirmed reveal and only then deletes the record.
        chain.unconfirmed.discard(reveal_txid)
        done = _resume(tmp_path, txid)
        assert f"is already revealed, by {reveal_txid}" in done.stderr
        assert _store(tmp_path).list_pending() == [] and len(chain.broadcasts) == 2


class TestExitsTheBroadcastsThemselvesCanTake:
    """L2: Ctrl-C while the commit is in flight, and a node refusing the reveal."""

    def test_ctrl_c_during_the_commit_broadcast_says_it_may_have_relayed(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        chain, _wallet = _wire(monkeypatch)

        def _ctrl_c(n: int, raw: bytes) -> None:
            if n == 0:
                raise KeyboardInterrupt

        chain.before_broadcast = _ctrl_c
        result = _mint(tmp_path, "abcde")
        assert result.exit_code == 1
        [txid] = _store(tmp_path).list_pending()
        said = " ".join(result.stderr.split())
        assert "interrupted while the commit was being broadcast: it may or may not have reached the network" in said
        assert f"look up {txid} on a block explorer" in said and f"`{_command(tmp_path, txid)}`" in said

    def test_a_node_refusing_the_reveal_is_named_as_a_refusal(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        chain, _wallet = _wire(monkeypatch)

        def _refuse(n: int, raw: bytes) -> None:
            if n == 1:
                raise PolicyRejection("min relay fee not met", code=1, reason="min relay fee not met")

        chain.before_broadcast = _refuse
        result = _mint(tmp_path, "abcde")
        assert result.exit_code == 2 and len(chain.broadcasts) == 1
        said = " ".join(result.output.split())
        assert "the node rejected the reveal transaction — nothing was spent by it" in said
        assert "a server stopped answering" not in said
        commit = _tx(chain.broadcasts[0])
        _assert_recovery(result, tmp_path, str(commit.txid()), commit.outputs[0].satoshis, wave="abcde")


class TestResumeMintPaysFromPlainRxdOnly:
    def test_the_fee_input_is_never_a_token(self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """N1: resume-mint picks its fee input by on-chain script, like mint-nft's funding."""
        chain, wallet = _wire(monkeypatch)
        txid = _timed_out_mint(tmp_path, monkeypatch, chain)
        chain.utxos.pop((txid, 1))  # the commit's change is gone; two other candidates remain
        pkh = Hex20(wallet.key.public_key().hash160())
        token = chain.fund(build_nft_locking_script(pkh, GlyphRef(txid=Txid("cd" * 32), vout=0)), 90_000_000_000)
        plain = chain.fund(wallet.script, 20_000_000_000)

        async def _both(client: object) -> list:
            return [(token, wallet.address, wallet.key), (plain, wallet.address, wallet.key)]

        monkeypatch.setattr(wallet, "collect_spendable", _both)
        result = _resume(tmp_path, txid)
        assert result.exit_code == 0, result.output
        assert _outpoints(_tx(chain.broadcasts[1]))[1] == (plain.tx_hash, 1)
        assert (token.tx_hash, 1) in chain.utxos
