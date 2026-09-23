"""``claim-dmint`` on a contract whose next mint is its last.

The shipped CLI builds every claim through ``build_dmint_mint_tx``, so it picks the final mint
up from the builder without a branch of its own. What it adds is what the operator is told: the
pre-grind summary says the claim will burn the contract, and the result (human and ``--json``)
reports the final mint from the transaction actually built. The wallet, the ElectrumX client,
the contract read and the PoW grind are stubbed exactly as in ``test_claim_dmint_locktime``; the
builder and the command run for real, and what is asserted is the transaction broadcast.
"""

from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path

import pytest
from click.testing import CliRunner

from pyrxd.cli import glyph_cmds, glyph_estimate, glyph_helpers
from pyrxd.cli.errors import UserError
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


def _v2(height: int, max_height: int, daa_mode: DaaMode = DaaMode.FIXED, **fields: int) -> DmintContractUtxo:
    params = DmintDeployParams(
        contract_ref=_CONTRACT_REF,
        token_ref=_TOKEN_REF,
        max_height=max_height,
        reward=1000,
        difficulty=1,
        daa_mode=daa_mode,
        height=height,
        last_time=1 << 30,
    )
    # A contract another deployer wrote: set after construction, so it keeps modelling that
    # contract whatever bounds the deploy parameters come to enforce.
    for name, value in fields.items():
        object.__setattr__(params, name, value)
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
    result, net, grinds = _invoke(tmp_path, monkeypatch, contract, *flags)
    assert result.exit_code == 0, result.output
    assert len(grinds) == 1 and len(net.broadcasts) == 1
    return result, Transaction.from_hex(net.broadcasts[0].hex())


def _invoke(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, contract: DmintContractUtxo, *flags: str):
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
    return result, net, grinds


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


class TestClaimDmintStillRefusesWhatPartBCannotEvaluate:
    """Part B runs on the final mint too. A final claim whose retarget the contract cannot
    evaluate is refused before the grind, and nothing is broadcast; the honest final claim of
    the same kind of contract goes through."""

    @pytest.mark.parametrize(
        ("fields", "why"),
        [
            ({"target_time": 2**63 - 1}, r"OP_MUL \(excess \* RADIX\) would leave the int64 range"),
            ({"last_time": 0}, "can no longer be minted"),
        ],
        ids=["retarget-leaves-int64", "unreadable-state-lastTime"],
    )
    def test_the_final_claim_is_refused_before_any_grind(
        self, fields, why, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        contract = _v2(1, 2, DaaMode.ASERT, **fields)
        assert contract.state.next_mint_is_final
        result, net, grinds = _invoke(tmp_path, monkeypatch, contract)
        assert result.exit_code != 0, result.output
        assert grinds == [] and net.broadcasts == []
        assert "could not build a valid mint" in result.output
        assert re.search(why, result.output), result.output

    def test_the_honest_final_claim_of_the_same_contract_broadcasts_the_burn(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        result, tx = _claim(tmp_path, monkeypatch, _v2(1, 2, DaaMode.ASERT), "--json")
        assert json.loads(result.stdout)["final_mint"] is True
        assert tx.outputs[0].locking_script.script == _BURN and tx.outputs[0].satoshis == 0


# ---------------------------------------------------------------------------------------------
# After the final mint: the contract outpoint names a burn, and the commands say so
# ---------------------------------------------------------------------------------------------

_MAINNET = {
    m["txid"]: m
    for m in json.loads((Path(__file__).parent.parent / "fixtures" / "dmint_v1_final_mints_mainnet.json").read_text())[
        "mints"
    ]
}
_CROW_FINAL = "7c7ba54e06d022698488be37c3c1cf3b90dc942878a1fc264fc147a0dd6aaa0a"  # output 0: the burn
_CROW_BEFORE = "b1a7c712a17c2173d7caaf532509a10fe40aa3c265928be48ebdd2ac72165415"  # output 0: the contract it burned


class _Chain:
    """Serves the real mainnet transactions in tests/fixtures/dmint_v1_final_mints_mainnet.json."""

    async def __aenter__(self) -> _Chain:
        return self

    async def __aexit__(self, *exc: object) -> bool:
        return False

    async def get_transaction(self, txid: object) -> bytes:
        return bytes.fromhex(_MAINNET[str(txid)]["raw"])


def _run_against_the_chain(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, *args: str):
    grinds: list[int] = []
    monkeypatch.setattr(glyph_cmds, "_load_wallet", lambda ctx, **kw: object())
    monkeypatch.setattr(glyph_cmds.CliContext, "make_client", lambda self: _Chain())
    monkeypatch.setattr(glyph_cmds, "_mine_bundled_parallel", lambda *a, **k: grinds.append(1))
    result = CliRunner().invoke(cli, ["--wallet", str(tmp_path / "w.dat"), "--yes", "glyph", *args])
    return result, grinds


class TestAfterTheFinalMint:
    @pytest.mark.parametrize(
        "command",
        [["claim-dmint", "--no-progress"], ["dmint-estimate", "--hash-rate", "1e6"]],
        ids=["claim-dmint", "dmint-estimate"],
    )
    def test_the_burned_outpoint_is_named_as_a_burn(self, command, monkeypatch, tmp_path: Path) -> None:
        result, grinds = _run_against_the_chain(monkeypatch, tmp_path, *command, "--contract", f"{_CROW_FINAL}:0")
        assert result.exit_code == 1, result.output
        assert grinds == []
        assert "is a burned singleton (d8 <ref> 6a)" in result.output
        assert "minted to its max_height and can be minted no" in result.output
        assert "is not a dMint contract" not in result.output

    def test_the_contract_it_burned_still_reads_as_a_contract(self) -> None:
        """The honest neighbour: the outpoint the final mint spent is a live contract to the same
        helper (it was, until that mint), one mint from its end."""
        utxo = asyncio.run(glyph_helpers._fetch_dmint_contract(_Chain(), _CROW_BEFORE, 0))
        assert utxo.state.is_v1 and utxo.state.next_mint_is_final

    def test_any_other_output_is_still_not_a_dmint_contract(self) -> None:
        with pytest.raises(UserError) as info:
            asyncio.run(glyph_helpers._fetch_dmint_contract(_Chain(), _CROW_FINAL, 3))  # the change
        assert "is not a dMint contract" in info.value.message


class TestDmintEstimateSaysWhenTheNextClaimIsTheLast:
    @pytest.mark.parametrize("height", [0, 1])
    def test_the_note_and_the_json_field(self, height: int, monkeypatch, tmp_path: Path) -> None:
        contract = _v1(height, 2)
        monkeypatch.setattr(glyph_estimate, "_fetch_contract", lambda *a, **k: contract)
        base = ["--wallet", str(tmp_path / "w.dat")]
        tail = ["glyph", "dmint-estimate", "--contract", f"{'ab' * 32}:0", "--hash-rate", "1e6"]
        human = CliRunner().invoke(cli, [*base, *tail])
        as_json = CliRunner().invoke(cli, [*base, "--json", *tail])
        assert human.exit_code == 0 and as_json.exit_code == 0, human.output + as_json.output
        final = height == 1
        assert ("the next claim is this contract's final mint (height 2)" in human.output) is final
        assert json.loads(as_json.stdout)["contract"]["next_mint_is_final"] is final
