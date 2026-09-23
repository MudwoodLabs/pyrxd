"""``claim-dmint`` on a contract whose next mint is its last.

The shipped CLI builds every claim through ``build_dmint_mint_tx``, so it picks the final mint
up from the builder without a branch of its own. What it adds is what the operator is told: the
pre-grind summary says the claim will burn the contract, and the result (human and ``--json``)
reports the final mint from the transaction actually built. The wallet, the ElectrumX client,
the contract read and the PoW grind are stubbed exactly as in ``test_claim_dmint_locktime``; the
builder and the command run for real, and what is asserted is the transaction broadcast.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from pyrxd.cli import glyph_cmds
from pyrxd.cli.main import cli
from pyrxd.glyph.dmint import (
    DaaMode,
    DmintContractUtxo,
    DmintDeployParams,
    DmintMinerFundingUtxo,
    DmintState,
    build_dmint_contract_script,
    build_dmint_v1_contract_script,
)
from pyrxd.glyph.dmint.types import MAX_SHA256D_TARGET
from pyrxd.glyph.types import GlyphRef
from pyrxd.keys import PrivateKey
from pyrxd.transaction.transaction import Transaction

from .test_claim_dmint_locktime import _Net

_CONTRACT_REF = GlyphRef(txid="ab" * 32, vout=1)
_TOKEN_REF = GlyphRef(txid="cd" * 32, vout=0)
_BURN = b"\xd8" + _CONTRACT_REF.to_bytes() + b"\x6a"


def _v2(height: int, max_height: int) -> DmintContractUtxo:
    params = DmintDeployParams(
        contract_ref=_CONTRACT_REF,
        token_ref=_TOKEN_REF,
        max_height=max_height,
        reward=1000,
        difficulty=1,
        daa_mode=DaaMode.FIXED,
        height=height,
        last_time=1 << 30,
    )
    spk = build_dmint_contract_script(params)
    return DmintContractUtxo(txid="ab" * 32, vout=0, value=1, script=spk, state=DmintState.from_script(spk))


def _v1(height: int, max_height: int) -> DmintContractUtxo:
    spk = build_dmint_v1_contract_script(
        height=height,
        contract_ref=_CONTRACT_REF,
        token_ref=_TOKEN_REF,
        max_height=max_height,
        reward=1000,
        target=MAX_SHA256D_TARGET,
    )
    return DmintContractUtxo(txid="ab" * 32, vout=0, value=1, script=spk, state=DmintState.from_script(spk))


def _claim(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, contract: DmintContractUtxo, *flags: str):
    net = _Net()
    key = PrivateKey()  # fresh random key; never hand-written material
    pkh = bytes(key.public_key().hash160())
    funding = DmintMinerFundingUtxo(
        txid="ef" * 32, vout=0, value=50_000_000, script=b"\x76\xa9\x14" + pkh + b"\x88\xac"
    )
    grinds: list[int] = []

    async def _fake_prepare(ctx, wallet, contract_arg, token_ref_arg, reward_address, client):
        return contract, funding, key, pkh

    def _fake_grind(preimage: bytes, target: int, **kw: object) -> bytes:
        grinds.append(target)
        return b"\x00" * int(kw["nonce_width"])  # the nonce is not the subject: no covenant runs here

    monkeypatch.setattr(glyph_cmds, "_load_wallet", lambda ctx, **kw: object())
    monkeypatch.setattr(glyph_cmds.CliContext, "make_client", lambda self: net)
    monkeypatch.setattr(glyph_cmds, "_claim_prepare", _fake_prepare)
    monkeypatch.setattr(glyph_cmds, "_mine_bundled_parallel", _fake_grind)
    argv = ["--wallet", str(tmp_path / "w.dat"), *flags, "--yes", "glyph", "claim-dmint", "--no-progress"]
    result = CliRunner().invoke(cli, [*argv, "--contract", "ab" * 32 + ":0"])
    assert result.exit_code == 0, result.output
    assert len(grinds) == 1 and len(net.broadcasts) == 1
    return result, Transaction.from_hex(net.broadcasts[0].hex())


_KINDS = pytest.mark.parametrize("make", [_v1, _v2], ids=["V1", "V2"])


class TestClaimDmintFinalMint:
    @_KINDS
    def test_the_final_claim_broadcasts_the_burn_and_says_so(
        self, make, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        result, tx = _claim(tmp_path, monkeypatch, make(1, 2))
        assert tx.outputs[0].locking_script.script == _BURN and tx.outputs[0].satoshis == 0
        assert tx.outputs[1].satoshis == 1000  # the FT reward
        assert "final mint:  height 2 is this contract's last" in result.output  # the pre-grind summary
        assert "the final mint: height 2 of 2" in result.output
        assert "contract now at height" not in result.output

    @_KINDS
    def test_json_reports_the_final_mint_from_the_transaction(
        self, make, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        result, tx = _claim(tmp_path, monkeypatch, make(1, 2), "--json")
        payload = json.loads(result.stdout)
        assert payload["final_mint"] is True and payload["new_height"] == 2
        assert payload["txid"] == tx.txid()

    @_KINDS
    def test_the_honest_neighbour_recreates_the_contract(
        self, make, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        result, tx = _claim(tmp_path, monkeypatch, make(0, 2), "--json")
        assert json.loads(result.stdout)["final_mint"] is False
        recreated = DmintState.from_script(tx.outputs[0].locking_script.script)
        assert (recreated.height, recreated.max_height) == (1, 2) and tx.outputs[0].satoshis == 1
        human, _tx = _claim(tmp_path, monkeypatch, make(0, 2))
        assert "final mint" not in human.output and "contract now at height 1" in human.output
