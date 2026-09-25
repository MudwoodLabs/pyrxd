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
from pyrxd.security.errors import NetworkError
from pyrxd.security.types import Hex20, Txid
from pyrxd.transaction.transaction import Transaction
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
        for i in tx.inputs:
            self.utxos.pop((i.source_txid, i.source_output_index))
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
        self.broadcasts.append(raw)
        return self._accept(tx, raw)

    async def get_transaction(self, txid: Any) -> bytes:
        try:
            return self.txs[str(txid)]
        except KeyError:
            raise NetworkError(f"no such transaction {txid}") from None

    async def get_transaction_verbose(self, txid: Any) -> dict:
        if self.on_poll is not None:
            self.on_poll(str(txid))
        return {"confirmations": self.confirmations if str(txid) in self.txs else 0}

    async def get_utxos(self, script_hash: Any) -> list[UtxoRecord]:
        return [
            UtxoRecord(tx_hash=txid, tx_pos=vout, value=value, height=100)
            for (txid, vout), (script, value) in self.utxos.items()
            if bytes(script_hash_for_script(script)) == bytes(script_hash)
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


def _assert_recovery(result: Any, tmp_path: pathlib.Path, txid: str, value: int, *, wave: str | None) -> None:
    """The commit txid, what it holds, where the record is and how to finish — never "re-run"."""
    said = " ".join(result.output.split())
    assert f"The commit {txid}:0 was broadcast and holds {value:,} photons" in said
    assert f"its record is saved in {tmp_path / 'pending-mints'}" in said
    assert (
        f"Do not re-run the mint command: that commits, and spends, again. To reveal this one, run "
        f"`pyrxd glyph resume-mint {txid}`." in said
    )
    assert "nothing is stranded" not in said
    assert "re-run with the inputs" not in said
    if wave is None:
        assert "--no-wave-registration-fee" not in said
    else:
        # M1: pay only if the name is still free; otherwise reveal without the fee.
        assert (
            f"resume-mint checks {wave}.rxd is still free and pays the registration fee from a wallet input only if it is"
            in said
        )
        assert f"`pyrxd glyph resume-mint {txid} --no-wave-registration-fee`" in said
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
            "pending_record": str(tmp_path / "pending-mints" / f"{txid}.json"),
            "wave_name": "abcde.rxd",
            "recover": f"pyrxd glyph resume-mint {txid}",
            "recover_without_wave_fee": f"pyrxd glyph resume-mint {txid} --no-wave-registration-fee",
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
        assert f"`pyrxd glyph resume-mint {txid}`" in said
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
        assert f"pyrxd glyph resume-mint {'ab' * 32}" in fix
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

    def test_a_commit_that_is_already_spent_has_nothing_to_recover(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        chain, _wallet = _wire(monkeypatch)
        chain.confirmations = 0
        _no_wait(monkeypatch)
        _mint(tmp_path, "abcde")
        txid = str(_tx(chain.broadcasts[0]).txid())
        chain.utxos.pop((txid, 0))  # revealed elsewhere
        chain.confirmations = 1
        result = _resume(tmp_path, txid)
        assert result.exit_code == 1
        assert f"the commit {txid}:0 is already spent" in result.stderr
        assert "Do not re-run the mint" not in result.stderr  # not pointed at a recovery that finds nothing
        assert _store(tmp_path).list_pending() == []

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
