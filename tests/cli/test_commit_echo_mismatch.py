"""A mismatched broadcast echo during a glyph mint or deploy names a recovery that exists (#786 review).

Since #780 ``ElectrumXClient.broadcast`` raises ``BroadcastEchoMismatch`` when the server's reply
names some other txid. The transaction may have relayed, and for a COMMIT that matters: a commit is
a hashlock with no owner-only spend path, so a relayed commit whose reveal is never built is value
gone. These tests check what each command then tells its user, through the root ``cli``:

- ``mint-nft`` saved its pending record before the commit broadcast, so ``resume-mint`` finishes it;
  ``--json`` mode prints the machine-readable recovery document on stdout, as it did before #780,
  and nothing calls the mismatch an interruption.
- ``deploy-ft`` and ``deploy-dmint`` keep no record, so the error names the SDK rebuild with the
  LOCALLY computed commit txid and says ``resume-mint`` cannot help.

The client is a real ``ElectrumXClient`` — its ``broadcast``, and the echo check in it, are the shipped
code. Only its wire (``_call``) is faked: a broadcast is applied to the in-memory chain the other
mint tests use, and the reply is a lie on the broadcasts listed in ``lie_on``.
"""

from __future__ import annotations

import json
import pathlib
from typing import Any

import pytest
from click.testing import CliRunner

from pyrxd.cli import glyph_cmds
from pyrxd.cli.main import cli
from pyrxd.keys import PrivateKey
from pyrxd.network.electrumx import ElectrumXClient
from tests.cli.test_claim_dmint_locktime import _write_dmint_meta
from tests.cli.test_wave_registration_fee_cli import _Chain, _command, _global, _store, _tx, _wire

_LIE = "ee" * 32


class _Echoing(ElectrumXClient):
    """The shipped ``ElectrumXClient.broadcast`` over :class:`_Chain`; reads are the chain's."""

    def __init__(self, chain: _Chain, *, lie_on: set[int]) -> None:
        super().__init__(["wss://fake.invalid/"])
        self.chain = chain
        self.lie_on = lie_on
        self.sent = 0

    async def __aenter__(self) -> _Echoing:
        return self

    async def __aexit__(self, *exc: object) -> bool:
        return False

    async def _ensure_connected(self) -> None:
        return None

    async def _call(self, method: str, params: list[Any]) -> Any:
        assert method == "blockchain.transaction.broadcast", method
        n, self.sent = self.sent, self.sent + 1
        txid = await self.chain.broadcast(bytes.fromhex(params[0]))  # it relays
        return _LIE if n in self.lie_on else txid

    async def get_history(self, script_hash: Any) -> list[dict]:
        return await self.chain.get_history(script_hash)

    async def get_transaction(self, txid: Any) -> bytes:
        return await self.chain.get_transaction(txid)

    async def get_transaction_verbose(self, txid: Any) -> dict:
        return await self.chain.get_transaction_verbose(txid)

    async def get_utxos(self, script_hash: Any) -> list:
        return await self.chain.get_utxos(script_hash)


def _lying(monkeypatch: pytest.MonkeyPatch, *, lie_on: set[int]) -> _Chain:
    chain, _wallet = _wire(monkeypatch)
    monkeypatch.setattr(glyph_cmds.CliContext, "make_client", lambda self: _Echoing(chain, lie_on=lie_on))
    return chain


def _said(result) -> str:
    return " ".join(result.output.split())


def _mint_plain_nft(tmp_path: pathlib.Path, mode: tuple[str, ...]):
    meta = tmp_path / "nft.json"
    meta.write_text(json.dumps({"protocol": ["NFT"], "name": "plain"}))
    return CliRunner().invoke(cli, [*_global(tmp_path, mode=mode), "glyph", "mint-nft", str(meta)])


# --------------------------------------------------------------------------- mint-nft


class TestMintNftCommitEcho:
    @pytest.mark.parametrize("mode", [("--json", "--yes"), ("--yes",)], ids=["json", "human"])
    def test_a_lying_commit_echo_stops_with_the_record_and_how_to_finish(self, tmp_path, monkeypatch, mode) -> None:
        chain = _lying(monkeypatch, lie_on={0})
        result = _mint_plain_nft(tmp_path, mode)

        assert result.exit_code == 1, result.output
        assert len(chain.broadcasts) == 1, "the commit, and no reveal"
        commit = _tx(chain.broadcasts[0])
        local = str(commit.txid())
        said = _said(result)
        assert "different transaction id than the commit we signed" in said
        assert "may or may not have reached the network" in said
        assert f"look up {local} on a block explorer before running anything else" in said
        assert f"`{_command(tmp_path, local)}`" in said, "the resume-mint recovery, under the LOCAL txid"
        assert "interrupted" not in said, "a wrong echo is not an interruption"
        assert _store(tmp_path).list_pending() == [local]
        if mode[0] == "--json":
            doc = json.loads(result.stdout)
            assert doc["status"] == "commit_broadcast_failed_may_have_relayed"
            assert doc["commit_txid"] == local
            assert doc["recover"] == _command(tmp_path, local)

    def test_resume_mint_then_finishes_the_relayed_commit(self, tmp_path, monkeypatch) -> None:
        chain = _lying(monkeypatch, lie_on={0})
        assert _mint_plain_nft(tmp_path, ("--json", "--yes")).exit_code == 1
        [local] = _store(tmp_path).list_pending()

        monkeypatch.setattr(glyph_cmds.CliContext, "make_client", lambda self: _Echoing(chain, lie_on=set()))
        resumed = CliRunner().invoke(cli, [*_global(tmp_path), "glyph", "resume-mint", local])
        assert resumed.exit_code == 0, resumed.output
        reveal = _tx(chain.broadcasts[1])
        assert reveal.inputs[0].source_txid == local, "the reveal spends the commit that relayed"

    def test_a_lying_reveal_echo_says_the_reveal_may_be_out(self, tmp_path, monkeypatch) -> None:
        chain = _lying(monkeypatch, lie_on={1})
        result = _mint_plain_nft(tmp_path, ("--json", "--yes"))

        assert result.exit_code == 1, result.output
        assert len(chain.broadcasts) == 2
        reveal_local = str(_tx(chain.broadcasts[1]).txid())
        said = _said(result)
        assert "different transaction id than the one we signed" in said
        assert f"check {reveal_local} on an explorer" in said
        assert "interrupted" not in said
        doc = json.loads(result.stdout)
        assert doc["status"] == "reveal_broadcast_not_confirmed"
        assert doc["reveal_txid"] == reveal_local, "the reveal's LOCAL txid, never the echo"

    def test_an_honest_echo_still_mints(self, tmp_path, monkeypatch) -> None:
        chain = _lying(monkeypatch, lie_on=set())
        result = _mint_plain_nft(tmp_path, ("--json", "--yes"))
        assert result.exit_code == 0, result.output
        assert len(chain.broadcasts) == 2


# --------------------------------------------------------------------------- deploy-ft / deploy-dmint


def _deploy_ft(tmp_path: pathlib.Path, treasury: str):
    meta = tmp_path / "ft.json"
    meta.write_text(json.dumps({"protocol": ["FT"], "name": "t", "ticker": "TT"}))
    args = ["glyph", "deploy-ft", str(meta), "--supply", "1000", "--treasury", treasury]
    return CliRunner().invoke(cli, [*_global(tmp_path), *args])


def _deploy_dmint(tmp_path: pathlib.Path):
    meta = _write_dmint_meta(tmp_path / "dmint.json")
    args = ["glyph", "deploy-dmint", str(meta), "--max-height", "100", "--reward", "1000"]
    return CliRunner().invoke(cli, [*_global(tmp_path), *args])


class TestDeployCommitEcho:
    def test_deploy_ft_names_the_sdk_rebuild_under_the_local_txid(self, tmp_path, monkeypatch) -> None:
        chain = _lying(monkeypatch, lie_on={0})
        treasury = PrivateKey()
        result = _deploy_ft(tmp_path, treasury.address())

        assert result.exit_code == 1, result.output
        assert len(chain.broadcasts) == 1, "stopped at the commit"
        commit = _tx(chain.broadcasts[0])
        local = str(commit.txid())
        said = _said(result)
        assert "different transaction id than the commit we signed" in said
        assert f"look up {local} on a block explorer" in said
        assert f"commit_txid={local} (never the echoed id)" in said
        assert "GlyphBuilder().prepare_ft_deploy_reveal(" in said
        assert f"commit_value={commit.outputs[0].satoshis}" in said
        assert f"premine_pkh={treasury.public_key().hash160().hex()}, premine_amount=1000" in said
        assert "`glyph resume-mint` cannot reveal it" in said

    def test_deploy_dmint_names_the_sdk_rebuild_under_the_local_txid(self, tmp_path, monkeypatch) -> None:
        chain = _lying(monkeypatch, lie_on={0})
        result = _deploy_dmint(tmp_path)

        assert result.exit_code == 1, result.output
        assert len(chain.broadcasts) == 1, "stopped at the commit"
        commit = _tx(chain.broadcasts[0])
        local = str(commit.txid())
        said = _said(result)
        assert "different transaction id than the commit we signed" in said
        assert f"commit_txid={local} (never the echoed id)" in said
        assert ".build_reveal_outputs(" in said
        assert f"(the hashlock, {commit.outputs[0].satoshis} photons)" in said
        assert "`glyph resume-mint` cannot reveal it" in said

    def test_honest_echoes_still_deploy(self, tmp_path, monkeypatch) -> None:
        chain = _lying(monkeypatch, lie_on=set())
        assert _deploy_ft(tmp_path, PrivateKey().address()).exit_code == 0
        assert _deploy_dmint(tmp_path).exit_code == 0
        assert len(chain.broadcasts) == 4
