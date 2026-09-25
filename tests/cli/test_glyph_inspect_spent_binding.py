"""``pyrxd glyph inspect <txid> --fetch`` says what happened to the spent transaction it asked for.

The CLI resolves ``payload_binding`` by fetching the commit the reveal's attributed input spent.
Every failure of that fetch used to fall through to the classifier's own sentence — the spent
output "was not supplied" — including when the server ANSWERED, with a different transaction,
which ``ElectrumXClient.get_transaction`` refuses by hash. The /inspect/ page, which sends readers
to this command, had just been fixed to say what happened; the command still did not.

Both now ask ONE function, ``_inspect_core._spent_output_binding``, so they cannot say different
things about the same fetch. These tests reach it the way a user does: through the real
``ElectrumXClient`` — its hash check included — with only the transport faked (``_call``, plus
the connect/close that would open a socket).
"""

from __future__ import annotations

import asyncio
import importlib.util
import os
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner

_GLUE = Path(__file__).resolve().parents[2] / "docs" / "inspect_static" / "inspect" / "glue.py"


def _tx(outputs, inputs):
    from pyrxd.script.script import Script
    from pyrxd.transaction.transaction import Transaction
    from pyrxd.transaction.transaction_input import TransactionInput
    from pyrxd.transaction.transaction_output import TransactionOutput

    tx = Transaction(tx_inputs=[], tx_outputs=[TransactionOutput(Script(s), v) for s, v in outputs])
    ins = []
    for source_txid, vout, unlocking in inputs:
        inp = TransactionInput(source_txid=source_txid, source_output_index=vout)
        inp.unlocking_script = Script(unlocking)
        ins.append(inp)
    tx.inputs = ins
    return tx


def _world():
    """(reveal, the real commit it spent, a FORGED transaction the server answers with instead)."""
    from pyrxd.glyph.payload import build_reveal_scriptsig_suffix, encode_payload
    from pyrxd.glyph.script import build_commit_locking_script, build_nft_locking_script
    from pyrxd.glyph.types import GlyphMetadata, GlyphProtocol, GlyphRef
    from pyrxd.hash import hash256
    from pyrxd.security.types import Hex20

    cbor, _ = encode_payload(GlyphMetadata(protocol=[GlyphProtocol.NFT], name="honest"))
    commit = _tx(
        [(build_commit_locking_script(hash256(cbor), Hex20(os.urandom(20)), is_nft=True), 1000)],
        [("cd" * 32, 0, b"\x00")],
    )
    unlocking = b"\x47" + b"\x00" * 71 + b"\x21" + b"\x02" * 33 + build_reveal_scriptsig_suffix(cbor)
    # The singleton the commit demands: without it no node accepts the reveal, and the binding says
    # so rather than `bound`.
    minted = build_nft_locking_script(Hex20(os.urandom(20)), GlyphRef(txid=commit.txid(), vout=0))
    reveal = _tx([(minted, 1)], [(commit.txid(), 0, unlocking)])
    forged = _tx([(b"\x6a" + b"\x00" * 80, 0)], [("ee" * 32, 0, b"\x00")])
    return reveal, commit, forged


@pytest.fixture
def transport(monkeypatch):
    """A REAL ``ElectrumXClient`` whose wire answers from a table. Only the transport is fake:
    ``get_transaction``'s own hex decoding and hash check run as shipped."""
    from pyrxd.network.electrumx import ElectrumXClient
    from pyrxd.security.errors import NetworkError

    table: dict[str, object] = {}

    async def _call(self, method, params):
        assert method == "blockchain.transaction.get", method
        answer = table.get(params[0])
        if answer is None:
            raise NetworkError("ElectrumX RPC error: No such mempool or blockchain transaction")
        if isinstance(answer, Exception):
            raise answer
        return answer

    async def _nothing(self, *a, **kw):
        return None

    monkeypatch.setattr(ElectrumXClient, "_call", _call)
    monkeypatch.setattr(ElectrumXClient, "_ensure_connected", _nothing)
    monkeypatch.setattr(ElectrumXClient, "close", _nothing)
    return table


def _client():
    from pyrxd.network.electrumx import ElectrumXClient

    return ElectrumXClient(["wss://electrumx.invalid:50022"])


def _fetch(txid: str) -> dict:
    from pyrxd.cli.glyph_inspect import _inspect_txid_inner

    return asyncio.run(_inspect_txid_inner(_client(), txid))


def _glue():
    spec = importlib.util.spec_from_file_location("pyrxd_inspect_glue_cli_binding", _GLUE)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["pyrxd_inspect_glue_cli_binding"] = module
    spec.loader.exec_module(module)
    return module


class TestTheCliSaysWhatHappenedToTheSpentTransaction:
    def test_the_real_commit_binds(self, transport) -> None:
        """The honest path through the real client, and the neighbour of every case below."""
        reveal, commit, _forged = _world()
        transport.update({reveal.txid(): reveal.serialize().hex(), commit.txid(): commit.serialize().hex()})
        assert _fetch(reveal.txid())["metadata"]["payload_binding"] == {
            "state": "bound",
            "commit": "nft",
            "reason": "the spent NFT commit committed to exactly this payload, and this transaction creates its "
            "ref as a singleton at output 0: that token's payload, not every output's",
            "first_ref_output": 0,
            "ref_output_count": 1,
        }

    def test_a_server_answering_with_another_transaction_is_not_called_not_supplied(self, transport) -> None:
        """The review's case: asked for the commit, the server
        answers with a different transaction. The client refuses it by hash; the verdict used to
        say the spent output "was not supplied"."""
        from pyrxd.glyph._inspect_core import SPENT_TX_NOT_OBTAINED

        reveal, commit, forged = _world()
        transport.update({reveal.txid(): reveal.serialize().hex(), commit.txid(): forged.serialize().hex()})
        binding = _fetch(reveal.txid())["metadata"]["payload_binding"]
        assert binding["state"] == "unchecked"
        assert binding["reason"] == SPENT_TX_NOT_OBTAINED
        assert "was not supplied" not in binding["reason"]
        assert "hash is not the requested txid" in binding["detail"], binding

    def test_a_server_that_does_not_have_it_is_said_too(self, transport) -> None:
        from pyrxd.glyph._inspect_core import SPENT_TX_NOT_OBTAINED

        reveal, _commit, _forged = _world()
        transport.update({reveal.txid(): reveal.serialize().hex()})
        binding = _fetch(reveal.txid())["metadata"]["payload_binding"]
        assert binding["reason"] == SPENT_TX_NOT_OBTAINED
        assert "No such mempool or blockchain transaction" in binding["detail"]

    def test_the_cli_and_the_page_say_the_same_thing_about_the_same_fetch(self, transport) -> None:
        """ONE definition: the page hands the same refusal to the same function and gets the same
        state and reason — only the detail differs, because each quotes its own fetcher."""
        reveal, commit, forged = _world()
        transport.update({reveal.txid(): reveal.serialize().hex(), commit.txid(): forged.serialize().hex()})
        cli = _fetch(reveal.txid())["metadata"]["payload_binding"]
        page_said = f"the server's answer is not the transaction asked for: it hashes to {forged.txid()}"
        page = _glue().spent_output_binding(reveal.txid(), reveal.serialize().hex(), "", page_said)["binding"]
        assert (cli["state"], cli["reason"]) == (page["state"], page["reason"])
        assert page["detail"] == page_said

    def test_the_command_prints_why(self, transport, monkeypatch, tmp_path) -> None:
        """The human output, which a reader sent here from the page actually reads."""
        from pyrxd.cli.context import CliContext
        from pyrxd.cli.main import cli

        reveal, commit, forged = _world()
        transport.update({reveal.txid(): reveal.serialize().hex(), commit.txid(): forged.serialize().hex()})
        monkeypatch.setattr(CliContext, "make_client", lambda self: _client())
        result = CliRunner().invoke(
            cli,
            [
                "--wallet",
                str(tmp_path / "w"),
                "--config",
                str(tmp_path / "c.toml"),
                "glyph",
                "inspect",
                reveal.txid(),
                "--fetch",
            ],
        )
        assert result.exit_code == 0, result.output
        assert "payload_binding=unchecked — the spent transaction was asked for and nothing usable came back" in (
            result.output
        )
        assert "    why: server returned a transaction whose hash is not the requested txid" in result.output
        assert "was not supplied" not in result.output
