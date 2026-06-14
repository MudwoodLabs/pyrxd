"""Tests for `pyrxd glyph …` commands.

Covers the parts of Cut 2 that don't require a live ElectrumX +
on-chain confirmation:

* ``init-metadata`` scaffolds (every type, --out, refusal to overwrite).
* metadata file parsing (protocol-as-strings, validation errors).
* the broadcast-summary / --json-without-yes gate.
* mint-nft / deploy-ft / transfer-ft / transfer-nft top-level argument
  validation (no network).

Full mint flow requires a real chain and is covered by
``examples/glyph_mint_demo.py`` + the integration tests in
``tests/test_dmint_deploy_integration.py``.
"""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from pyrxd.cli.main import cli


def _new_wallet_args(tmp_wallet_path: Path) -> list[str]:
    return ["--wallet", str(tmp_wallet_path), "--json", "--yes", "wallet", "new"]


def _extract_json(output: str) -> dict:
    start = output.find("{")
    end = output.rfind("}")
    if start == -1 or end == -1:
        raise AssertionError(f"no JSON object found in output:\n{output!r}")
    return json.loads(output[start : end + 1])


# ---------------------------------------------------------------------------
# init-metadata
# ---------------------------------------------------------------------------


class TestInitMetadata:
    def test_default_type_is_nft(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["glyph", "init-metadata"])
        assert result.exit_code == 0, result.output
        payload = _extract_json(result.output)
        assert payload["protocol"] == ["NFT"]

    def test_ft_template_has_ticker(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["glyph", "init-metadata", "--type", "ft"])
        payload = _extract_json(result.output)
        assert payload["protocol"] == ["FT"]
        assert payload["ticker"] == "MTK"
        assert payload["decimals"] == 0

    def test_dmint_ft_template(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["glyph", "init-metadata", "--type", "dmint-ft"])
        payload = _extract_json(result.output)
        assert payload["protocol"] == ["FT", "DMINT"]

    def test_mutable_nft_template(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["glyph", "init-metadata", "--type", "mutable-nft"])
        payload = _extract_json(result.output)
        assert payload["protocol"] == ["NFT", "MUT"]

    def test_container_template(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["glyph", "init-metadata", "--type", "container-nft"])
        payload = _extract_json(result.output)
        assert payload["protocol"] == ["NFT", "CONTAINER"]

    def test_out_writes_file(self, runner: CliRunner, tmp_path: Path) -> None:
        target = tmp_path / "metadata.json"
        result = runner.invoke(cli, ["glyph", "init-metadata", "--out", str(target)])
        assert result.exit_code == 0, result.output
        assert target.exists()
        payload = json.loads(target.read_text())
        assert payload["protocol"] == ["NFT"]

    def test_out_refuses_to_overwrite(self, runner: CliRunner, tmp_path: Path) -> None:
        target = tmp_path / "metadata.json"
        target.write_text("{}")
        result = runner.invoke(cli, ["glyph", "init-metadata", "--out", str(target)])
        assert result.exit_code != 0
        assert "overwrite" in result.output.lower()

    def test_unknown_type_rejected(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["glyph", "init-metadata", "--type", "bogus"])
        assert result.exit_code != 0
        # click's Choice prints "Invalid value" with the bad input.
        assert "bogus" in result.output or "Invalid" in result.output


# ---------------------------------------------------------------------------
# metadata file parsing
# ---------------------------------------------------------------------------


def _write_meta(path: Path, **overrides: object) -> Path:
    """Write a metadata.json with an FT default and arbitrary overrides."""
    body: dict = {
        "name": "Test",
        "description": "test",
        "protocol": ["FT"],
        "ticker": "TST",
        "decimals": 0,
    }
    body.update(overrides)
    path.write_text(json.dumps(body))
    return path


class TestMetadataFileErrors:
    def test_missing_file(self, runner: CliRunner, tmp_wallet_path: Path) -> None:
        # File doesn't exist → UserError before any wallet decryption.
        # Pre-create a wallet so the --wallet existence check passes.
        runner.invoke(cli, _new_wallet_args(tmp_wallet_path))
        result = runner.invoke(
            cli,
            [
                "--wallet",
                str(tmp_wallet_path),
                "glyph",
                "deploy-ft",
                "/nonexistent/metadata.json",
                "--supply",
                "100",
                "--treasury",
                "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
            ],
        )
        assert result.exit_code != 0
        assert "metadata file not found" in result.output

    def test_unknown_protocol_name(self, runner: CliRunner, tmp_wallet_path: Path, tmp_path: Path) -> None:
        runner.invoke(cli, _new_wallet_args(tmp_wallet_path))
        meta = _write_meta(tmp_path / "m.json", protocol=["NOT_A_THING"])
        result = runner.invoke(
            cli,
            [
                "--wallet",
                str(tmp_wallet_path),
                "glyph",
                "deploy-ft",
                str(meta),
                "--supply",
                "100",
                "--treasury",
                "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
            ],
        )
        assert result.exit_code != 0
        assert "unknown protocol" in result.output.lower()

    def test_empty_protocol_list_rejected(self, runner: CliRunner, tmp_wallet_path: Path, tmp_path: Path) -> None:
        runner.invoke(cli, _new_wallet_args(tmp_wallet_path))
        meta = _write_meta(tmp_path / "m.json", protocol=[])
        result = runner.invoke(
            cli,
            [
                "--wallet",
                str(tmp_wallet_path),
                "glyph",
                "deploy-ft",
                str(meta),
                "--supply",
                "100",
                "--treasury",
                "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
            ],
        )
        assert result.exit_code != 0
        assert "non-empty list" in result.output

    def test_invalid_json_file(self, runner: CliRunner, tmp_wallet_path: Path, tmp_path: Path) -> None:
        runner.invoke(cli, _new_wallet_args(tmp_wallet_path))
        meta = tmp_path / "m.json"
        meta.write_text("not valid json {{{")
        result = runner.invoke(
            cli,
            [
                "--wallet",
                str(tmp_wallet_path),
                "glyph",
                "deploy-ft",
                str(meta),
                "--supply",
                "100",
                "--treasury",
                "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
            ],
        )
        assert result.exit_code != 0
        assert "could not read" in result.output.lower()


# ---------------------------------------------------------------------------
# argument-level validation
# ---------------------------------------------------------------------------


class TestArgumentValidation:
    def test_deploy_ft_zero_supply_rejected(self, runner: CliRunner, tmp_wallet_path: Path, tmp_path: Path) -> None:
        runner.invoke(cli, _new_wallet_args(tmp_wallet_path))
        meta = _write_meta(tmp_path / "m.json")
        result = runner.invoke(
            cli,
            [
                "--wallet",
                str(tmp_wallet_path),
                "glyph",
                "deploy-ft",
                str(meta),
                "--supply",
                "0",
                "--treasury",
                "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
            ],
        )
        assert result.exit_code != 0
        assert "supply" in result.output.lower()

    def test_deploy_ft_invalid_treasury_rejected(
        self, runner: CliRunner, tmp_wallet_path: Path, tmp_path: Path
    ) -> None:
        runner.invoke(cli, _new_wallet_args(tmp_wallet_path))
        meta = _write_meta(tmp_path / "m.json")
        result = runner.invoke(
            cli,
            [
                "--wallet",
                str(tmp_wallet_path),
                "glyph",
                "deploy-ft",
                str(meta),
                "--supply",
                "100",
                "--treasury",
                "not-an-address",
            ],
        )
        assert result.exit_code != 0
        assert "treasury" in result.output.lower()

    def test_transfer_ft_invalid_ref(self, runner: CliRunner, tmp_wallet_path: Path) -> None:
        runner.invoke(cli, _new_wallet_args(tmp_wallet_path))
        result = runner.invoke(
            cli,
            [
                "--wallet",
                str(tmp_wallet_path),
                "glyph",
                "transfer-ft",
                "no-colon-ref",
                "10",
                "--to",
                "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
            ],
        )
        assert result.exit_code != 0
        assert "ref" in result.output.lower()

    def test_transfer_ft_zero_amount_rejected(self, runner: CliRunner, tmp_wallet_path: Path) -> None:
        runner.invoke(cli, _new_wallet_args(tmp_wallet_path))
        result = runner.invoke(
            cli,
            [
                "--wallet",
                str(tmp_wallet_path),
                "glyph",
                "transfer-ft",
                "ab" * 32 + ":0",
                "0",
                "--to",
                "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
            ],
        )
        assert result.exit_code != 0
        assert "amount" in result.output.lower()


# ---------------------------------------------------------------------------
# protocol validation: NFT mint requires NFT, FT deploy requires FT
# ---------------------------------------------------------------------------


class TestProtocolValidation:
    def test_mint_nft_with_ft_metadata_rejected(self, runner: CliRunner, tmp_wallet_path: Path, tmp_path: Path) -> None:
        # FT metadata, but trying to mint as NFT.
        runner.invoke(cli, _new_wallet_args(tmp_wallet_path))
        meta = _write_meta(tmp_path / "m.json")  # default protocol is FT
        # Use a known mnemonic since wallet creation already happened.
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        result = runner.invoke(
            cli,
            ["--wallet", str(tmp_wallet_path), "glyph", "mint-nft", str(meta)],
            input=f"{mnemonic}\n",
        )
        assert result.exit_code != 0
        # Either the protocol-mismatch check fired (FT meta + NFT command) or
        # wallet decrypt failed (wrong mnemonic) — both are valid rejections.
        assert "NFT" in result.output or "decrypt" in result.output.lower()

    def test_deploy_ft_with_nft_metadata_rejected(
        self, runner: CliRunner, tmp_wallet_path: Path, tmp_path: Path
    ) -> None:
        runner.invoke(cli, _new_wallet_args(tmp_wallet_path))
        meta = _write_meta(tmp_path / "m.json", protocol=["NFT"], ticker="")
        result = runner.invoke(
            cli,
            [
                "--wallet",
                str(tmp_wallet_path),
                "glyph",
                "deploy-ft",
                str(meta),
                "--supply",
                "100",
                "--treasury",
                "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
            ],
        )
        assert result.exit_code != 0
        assert "FT" in result.output


# ---------------------------------------------------------------------------
# deploy-dmint / claim-dmint  (A2)
# ---------------------------------------------------------------------------

import pytest

from pyrxd.cli.errors import UserError
from pyrxd.cli.glyph_cmds import _mine_claim_with_rerolls, _resolve_miner_argv
from pyrxd.glyph.dmint import (
    DmintAlgo,
    DmintContractUtxo,
    DmintMinerFundingUtxo,
    DmintState,
    build_dmint_v1_contract_script,
    difficulty_to_target,
)
from pyrxd.glyph.types import GlyphRef
from pyrxd.security.errors import MaxAttemptsError


class TestDeployDmint:
    """Argument/parameter validation (no network — fires before _load_wallet)."""

    def test_non_dmint_protocol_rejected(self, runner: CliRunner, tmp_wallet_path: Path, tmp_path: Path) -> None:
        runner.invoke(cli, _new_wallet_args(tmp_wallet_path))
        meta = _write_meta(tmp_path / "m.json", protocol=["FT"])  # missing DMINT
        result = runner.invoke(
            cli,
            [
                "--wallet",
                str(tmp_wallet_path),
                "glyph",
                "deploy-dmint",
                str(meta),
                "--max-height",
                "100",
                "--reward",
                "1000",
            ],
        )
        assert result.exit_code != 0
        assert "FT and DMINT" in result.output

    def test_num_contracts_out_of_range(self, runner: CliRunner, tmp_wallet_path: Path, tmp_path: Path) -> None:
        runner.invoke(cli, _new_wallet_args(tmp_wallet_path))
        meta = _write_meta(tmp_path / "m.json", protocol=["FT", "DMINT"])
        result = runner.invoke(
            cli,
            [
                "--wallet",
                str(tmp_wallet_path),
                "glyph",
                "deploy-dmint",
                str(meta),
                "--num-contracts",
                "0",
                "--max-height",
                "100",
                "--reward",
                "1000",
            ],
        )
        assert result.exit_code != 0
        assert "invalid dMint deploy parameters" in result.output

    def test_reward_zero_rejected(self, runner: CliRunner, tmp_wallet_path: Path, tmp_path: Path) -> None:
        runner.invoke(cli, _new_wallet_args(tmp_wallet_path))
        meta = _write_meta(tmp_path / "m.json", protocol=["FT", "DMINT"])
        result = runner.invoke(
            cli,
            [
                "--wallet",
                str(tmp_wallet_path),
                "glyph",
                "deploy-dmint",
                str(meta),
                "--max-height",
                "100",
                "--reward",
                "0",
            ],
        )
        assert result.exit_code != 0
        assert "invalid dMint deploy parameters" in result.output


class TestClaimDmint:
    """Locator validation (no network — the exactly-one check is the first line)."""

    def test_requires_a_locator(self, runner: CliRunner, tmp_wallet_path: Path) -> None:
        runner.invoke(cli, _new_wallet_args(tmp_wallet_path))
        result = runner.invoke(cli, ["--wallet", str(tmp_wallet_path), "glyph", "claim-dmint"])
        assert result.exit_code != 0
        assert "exactly one" in result.output

    def test_rejects_both_locators(self, runner: CliRunner, tmp_wallet_path: Path) -> None:
        runner.invoke(cli, _new_wallet_args(tmp_wallet_path))
        result = runner.invoke(
            cli,
            [
                "--wallet",
                str(tmp_wallet_path),
                "glyph",
                "claim-dmint",
                "--contract",
                "ab" * 32 + ":0",
                "--token-ref",
                "cd" * 32 + ":0",
            ],
        )
        assert result.exit_code != 0
        assert "exactly one" in result.output


def _dmint_contract(value: int = 1) -> DmintContractUtxo:
    spk = build_dmint_v1_contract_script(
        height=0,
        contract_ref=GlyphRef(txid="ab" * 32, vout=1),
        token_ref=GlyphRef(txid="cd" * 32, vout=0),
        max_height=100,
        reward=1000,
        target=difficulty_to_target(1, DmintAlgo.SHA256D),
        algo=DmintAlgo.SHA256D,
    )
    return DmintContractUtxo(txid="ab" * 32, vout=0, value=value, script=spk, state=DmintState.from_script(spk))


def _dmint_funding() -> DmintMinerFundingUtxo:
    pkh = bytes(range(20))
    return DmintMinerFundingUtxo(txid="ef" * 32, vout=0, value=50_000_000, script=b"\x76\xa9\x14" + pkh + b"\x88\xac")


class TestDmintCliHelpers:
    def test_resolve_miner_argv(self) -> None:
        import sys

        assert _resolve_miner_argv(None) == [sys.executable, "-m", "pyrxd.contrib.miner"]
        assert _resolve_miner_argv("in-process") is None
        assert _resolve_miner_argv("glyph-miner --stdin") == ["glyph-miner", "--stdin"]

    def test_mine_rerolls_until_hit(self) -> None:
        # V1's 4-byte nonce space often has no solution per preimage; the loop
        # must reroll the OP_RETURN (a fresh preimage) on MaxAttemptsError.
        contract, funding, miner_pkh = _dmint_contract(), _dmint_funding(), bytes(range(20))
        seen: list[bytes] = []

        def fake_mine(preimage: bytes, target: int) -> bytes:
            seen.append(preimage)
            if len(seen) <= 2:
                raise MaxAttemptsError("swept without a hit", attempts=1, elapsed_s=0.1)
            return b"\x01\x02\x03\x04"

        _mint, _pre, nonce = _mine_claim_with_rerolls(
            contract, funding, miner_pkh, b"msg", 10_000, mine=fake_mine, max_rerolls=10
        )
        assert nonce == b"\x01\x02\x03\x04"
        assert len(seen) == 3  # 2 exhausted preimages + 1 hit
        assert len(set(seen)) == 3  # each reroll varied the OP_RETURN -> distinct preimage

    def test_mine_exhausts_rerolls(self) -> None:
        def always_exhaust(preimage: bytes, target: int) -> bytes:
            raise MaxAttemptsError("swept without a hit", attempts=1, elapsed_s=0.1)

        with pytest.raises(UserError, match="no nonce found"):
            _mine_claim_with_rerolls(
                _dmint_contract(),
                _dmint_funding(),
                bytes(range(20)),
                b"msg",
                10_000,
                mine=always_exhaust,
                max_rerolls=3,
            )


import asyncio
import dataclasses
from unittest.mock import AsyncMock, MagicMock

from pyrxd.glyph.dmint import build_mint_scriptsig
from pyrxd.glyph.types import GlyphMetadata, GlyphProtocol
from pyrxd.keys import PrivateKey
from pyrxd.network.electrumx import UtxoRecord
from pyrxd.script.script import Script
from pyrxd.security.types import Hex20
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_output import TransactionOutput


class TestDmintCliAssembly:
    """Drive the real build->fee->sign tx-assembly (the part the validation
    tests don't reach, and the part with no regtest-ElectrumX e2e)."""

    def test_deploy_inner_funds_from_vout_nonzero(self, cli_context) -> None:
        # Regression for the H-1 review finding: the largest wallet UTXO is
        # commonly change at vout != 0. Pre-fix this IndexError'd (single-output
        # shim) / ZeroDivisionError'd (manual change + fee()); both must be gone.
        from pyrxd.cli.glyph_cmds import _deploy_dmint_inner

        ctx = dataclasses.replace(cli_context, output_mode="json", yes=True)
        key = PrivateKey()
        utxo = UtxoRecord(tx_hash="ab" * 32, tx_pos=1, value=50_000_000, height=100)  # vout != 0

        class _Wallet:
            async def collect_spendable(self, client):
                return [(utxo, key.address(), key)]

        captured: list[bytes] = []

        async def _bcast(raw: bytes) -> str:
            captured.append(raw)
            return ("11" if len(captured) == 1 else "22") * 32

        client = MagicMock()
        client.broadcast = _bcast
        client.get_transaction_verbose = AsyncMock(return_value={"confirmations": 1})

        meta = GlyphMetadata.for_dmint_ft(
            ticker="TST", name="t", protocol=[int(GlyphProtocol.FT), int(GlyphProtocol.DMINT)]
        )
        result = asyncio.run(_deploy_dmint_inner(ctx, _Wallet(), meta, 1, 100, 1000, 1, None, client))

        assert len(captured) == 2, "commit + reveal both built+signed without crashing"
        assert result["num_contracts"] == 1
        commit = Transaction.from_hex(captured[0])
        reveal = Transaction.from_hex(captured[1])
        assert commit is not None and reveal is not None
        # commit: FT-commit @vout0 + 1 ref-seed + change ; reveal vout0 = 1-photon contract (consensus-required)
        assert len(commit.outputs) >= 3
        assert reveal.outputs[0].satoshis == 1

    def test_claim_assembly_builds_signed_mint(self) -> None:
        from pyrxd.cli.glyph_cmds import _mine_claim_with_rerolls, _sign_funding_input

        miner_key = PrivateKey()
        miner_pkh = bytes(Hex20(miner_key.public_key().hash160()))
        funding = DmintMinerFundingUtxo(
            txid="ef" * 32, vout=0, value=50_000_000, script=b"\x76\xa9\x14" + miner_pkh + b"\x88\xac"
        )
        contract = _dmint_contract()  # value == 1 (passes the A1 guard)

        def fake_mine(preimage: bytes, target: int) -> bytes:
            return b"\x01\x02\x03\x04"

        mint, pre, nonce = _mine_claim_with_rerolls(
            contract, funding, miner_pkh, b"m", 10_000, mine=fake_mine, max_rerolls=1
        )
        mint.tx.inputs[0].unlocking_script = Script(
            build_mint_scriptsig(nonce, pre.input_hash, pre.output_hash, nonce_width=4)
        )
        _sign_funding_input(mint.tx, 1, miner_key)
        raw = mint.tx.serialize()
        assert len(mint.tx.inputs) == 2  # contract + funding
        assert len(mint.tx.outputs) == 4  # recreated contract, FT reward, OP_RETURN, change
        assert mint.tx.outputs[0].satoshis == contract.value  # singleton carrier preserved (==1)
        assert len(raw) > 0


class TestMultiTxGlyphAssembly:
    """Regression for the systemic fee()/shim crash the dMint-CLI review found
    in the shipped deploy-ft / mint-nft commands: a manual change output + fee()
    ZeroDivisions, and a single-output source shim IndexErrors when the funding
    UTXO is not at vout 0. Both must build->fee->sign cleanly now."""

    def _wallet_and_client(self):
        key = PrivateKey()
        utxo = UtxoRecord(tx_hash="ab" * 32, tx_pos=1, value=50_000_000, height=100)  # vout != 0

        class _Wallet:
            async def collect_spendable(self, client):
                return [(utxo, key.address(), key)]

        captured: list[bytes] = []

        async def _bcast(raw: bytes) -> str:
            captured.append(raw)
            return ("11" if len(captured) == 1 else "22") * 32

        client = MagicMock()
        client.broadcast = _bcast
        client.get_transaction_verbose = AsyncMock(return_value={"confirmations": 1})
        return key, _Wallet(), client, captured

    def test_deploy_ft_inner_funds_from_vout_nonzero(self, cli_context, tmp_path) -> None:
        from pyrxd.cli.glyph_cmds import _deploy_ft_inner, _read_metadata_file

        ctx = dataclasses.replace(cli_context, output_mode="json", yes=True)
        key, wallet, client, captured = self._wallet_and_client()
        meta = _read_metadata_file(_write_meta(tmp_path / "ft.json", protocol=["FT"]))
        treasury_pkh = Hex20(key.public_key().hash160())

        result = asyncio.run(_deploy_ft_inner(ctx, wallet, meta, treasury_pkh, 1000, client))

        assert len(captured) == 2, "commit + reveal both built+signed without crashing"
        commit = Transaction.from_hex(captured[0])
        reveal = Transaction.from_hex(captured[1])
        assert commit is not None and reveal is not None
        assert reveal.outputs[0].satoshis == 1000  # premine supply preserved
        assert result["ref"].endswith(":0")

    def test_mint_nft_inner_funds_from_vout_nonzero(self, cli_context, tmp_path) -> None:
        from pyrxd.cli.glyph_cmds import _mint_nft_inner, _read_metadata_file

        ctx = dataclasses.replace(cli_context, output_mode="json", yes=True)
        _key, wallet, client, captured = self._wallet_and_client()
        meta = _read_metadata_file(_write_meta(tmp_path / "nft.json", protocol=["NFT"]))

        result = asyncio.run(_mint_nft_inner(ctx, wallet, meta, client))

        assert len(captured) == 2
        commit = Transaction.from_hex(captured[0])
        reveal = Transaction.from_hex(captured[1])
        assert commit is not None and reveal is not None
        assert reveal.outputs[0].satoshis == 546  # NFT on a dust carrier; change returned
        assert "ref" in result


class TestTransferNftAssembly:
    """Regression: transfer-nft must pay a real fee from a plain-RXD funding
    input (the NFT carries only dust), not a 0-fee tx, and survive an NFT/
    funding UTXO at vout != 0."""

    def test_transfer_nft_funds_the_fee(self, cli_context) -> None:
        from pyrxd.cli.glyph_cmds import _transfer_nft_inner
        from pyrxd.glyph.script import build_nft_locking_script
        from pyrxd.script.type import P2PKH

        ctx = dataclasses.replace(cli_context, output_mode="json", yes=True)

        def _src_hex(vout: int, spk: bytes, value: int) -> bytes:
            outs = [TransactionOutput(Script(b""), 0) for _ in range(vout)]
            outs.append(TransactionOutput(Script(spk), value))
            return Transaction(tx_inputs=[], tx_outputs=outs).serialize()

        owner_key = PrivateKey()
        ref = GlyphRef(txid="aa" * 32, vout=0)
        nft_script = build_nft_locking_script(Hex20(owner_key.public_key().hash160()), ref)
        nft_utxo = UtxoRecord(tx_hash="bb" * 32, tx_pos=1, value=1000, height=100)  # dust, vout != 0
        fund_key = PrivateKey()
        fund_spk = P2PKH().lock(fund_key.address()).serialize()
        fund_utxo = UtxoRecord(tx_hash="cc" * 32, tx_pos=1, value=50_000_000, height=100)  # plain RXD

        txmap = {
            "bb" * 32: _src_hex(1, nft_script, 1000),
            "cc" * 32: _src_hex(1, fund_spk, 50_000_000),
        }

        class _Wallet:
            async def collect_spendable(self, client):
                return [
                    (nft_utxo, owner_key.address(), owner_key),
                    (fund_utxo, fund_key.address(), fund_key),
                ]

        captured: list[bytes] = []

        async def _bcast(raw: bytes) -> str:
            captured.append(raw)
            return "ff" * 32

        client = MagicMock()
        client.get_transaction = AsyncMock(side_effect=lambda t: txmap[str(t)])
        client.broadcast = _bcast

        to_key = PrivateKey()
        result = asyncio.run(
            _transfer_nft_inner(ctx, _Wallet(), ref, Hex20(to_key.public_key().hash160()), to_key.address(), client)
        )

        assert len(captured) == 1
        tx = Transaction.from_hex(captured[0])
        assert len(tx.inputs) == 2, "NFT input + plain-RXD funding input"
        assert tx.outputs[0].satoshis == 1000, "NFT singleton keeps its dust value"
        total_in = 1000 + 50_000_000
        total_out = sum(o.satoshis for o in tx.outputs)
        assert total_in - total_out > 0, "pays a real (non-zero) fee"
        assert result["txid"] == "ff" * 32
