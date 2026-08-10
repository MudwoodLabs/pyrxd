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
from pyrxd.cli.glyph_cmds import _mine_claim_with_rerolls, _resolve_miner_choice
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

    def _premine_args(self, wallet: Path, meta: Path, *extra: str) -> list[str]:
        return [
            "--wallet",
            str(wallet),
            "glyph",
            "deploy-dmint",
            str(meta),
            "--max-height",
            "100",
            "--reward",
            "1000",
            *extra,
        ]

    def test_premine_below_one_rejected(self, runner: CliRunner, tmp_wallet_path: Path, tmp_path: Path) -> None:
        runner.invoke(cli, _new_wallet_args(tmp_wallet_path))
        meta = _write_meta(tmp_path / "m.json", protocol=["FT", "DMINT"])
        result = runner.invoke(cli, self._premine_args(tmp_wallet_path, meta, "--premine", "0"))
        assert result.exit_code != 0
        assert "--premine must be >= 1" in result.output

    def test_premine_to_without_premine_rejected(
        self, runner: CliRunner, tmp_wallet_path: Path, tmp_path: Path
    ) -> None:
        # Silently dropping the premine because the amount was omitted would only
        # show up as a missing treasury after the deploy is irreversibly on chain.
        runner.invoke(cli, _new_wallet_args(tmp_wallet_path))
        meta = _write_meta(tmp_path / "m.json", protocol=["FT", "DMINT"])
        result = runner.invoke(
            cli, self._premine_args(tmp_wallet_path, meta, "--premine-to", "1BoatSLRHtKNngkdXEeobR76b53LETtpyT")
        )
        assert result.exit_code != 0
        assert "--premine-to was given without --premine" in result.output

    def test_premine_to_invalid_address_rejected(
        self, runner: CliRunner, tmp_wallet_path: Path, tmp_path: Path
    ) -> None:
        runner.invoke(cli, _new_wallet_args(tmp_wallet_path))
        meta = _write_meta(tmp_path / "m.json", protocol=["FT", "DMINT"])
        result = runner.invoke(
            cli, self._premine_args(tmp_wallet_path, meta, "--premine", "1000", "--premine-to", "not-an-address")
        )
        assert result.exit_code != 0
        assert "invalid --premine-to address" in result.output


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
    def test_resolve_miner_choice(self) -> None:
        # The default is now the bundled parallel miner run IN THIS PROCESS
        # (it used to be the same miner spawned as a subprocess): identical
        # workers, hashing and full nonce-space sweep, but the parent can read
        # the shared attempts counter and stream live hash rate + ETA.
        assert _resolve_miner_choice(None) == ("parallel", None)
        assert _resolve_miner_choice("in-process") == ("sequential", None)
        assert _resolve_miner_choice("glyph-miner --stdin") == ("external", ["glyph-miner", "--stdin"])

    def test_bundled_miner_is_still_reachable_over_the_wire_protocol(self) -> None:
        """Subprocess isolation stays available — it is just no longer the default."""
        import sys

        kind, argv = _resolve_miner_choice(f"{sys.executable} -m pyrxd.contrib.miner")
        assert kind == "external"
        assert argv == [sys.executable, "-m", "pyrxd.contrib.miner"]

    def test_bundled_parallel_returns_the_winning_nonce(self, monkeypatch) -> None:
        from pyrxd.cli import glyph_cmds
        from pyrxd.contrib.miner import parallel
        from pyrxd.contrib.miner.protocol import MineSuccess

        seen: dict = {}

        def fake_mine(params, *, progress=None, **kwargs):
            seen["params"] = params
            seen["progress"] = progress
            return MineSuccess(nonce=b"\x01\x02\x03\x04", attempts=99, elapsed_s=1.0)

        monkeypatch.setattr(parallel, "mine", fake_mine)
        nonce = glyph_cmds._mine_bundled_parallel(
            b"\xab" * 64, 1234, nonce_width=4, workers=3, progress=lambda a, e: None
        )
        assert nonce == b"\x01\x02\x03\x04"
        assert seen["params"].n_workers == 3
        assert seen["params"].nonce_max == 2**32, "must sweep the whole V1 nonce space"
        assert seen["progress"] is not None, "the progress hook must reach the miner"

    def test_bundled_parallel_exhaustion_raises_max_attempts(self, monkeypatch) -> None:
        from pyrxd.cli import glyph_cmds
        from pyrxd.contrib.miner import parallel
        from pyrxd.contrib.miner.protocol import MineExhausted

        monkeypatch.setattr(parallel, "mine", lambda *a, **k: MineExhausted())
        with pytest.raises(MaxAttemptsError, match="without a solution"):
            glyph_cmds._mine_bundled_parallel(b"\xab" * 64, 1, nonce_width=8, workers=1, progress=None)

    def test_bundled_parallel_worker_failure_becomes_a_user_error(self, monkeypatch) -> None:
        """A worker that never ran is a setup problem, not "no solution"."""
        from pyrxd.cli import glyph_cmds
        from pyrxd.contrib.miner import parallel

        def boom(*_a, **_k):
            raise RuntimeError("worker(s) exited abnormally")

        monkeypatch.setattr(parallel, "mine", boom)
        with pytest.raises(UserError, match="could not run its workers") as exc:
            glyph_cmds._mine_bundled_parallel(b"\xab" * 64, 1, nonce_width=4, workers=2, progress=None)
        assert "in-process" in (exc.value.fix or "")

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
from pyrxd.security.errors import ConfirmationTimeoutError, InsufficientFundsError
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
        from pyrxd.glyph.builder import DmintV1DeployParams
        from pyrxd.security.types import Hex20

        params = DmintV1DeployParams(
            metadata=meta,
            owner_pkh=Hex20(b"\x00" * 20),
            num_contracts=1,
            max_height=100,
            reward_photons=1000,
            difficulty=1,
            op_return_msg=None,
        )
        result = asyncio.run(_deploy_dmint_inner(ctx, _Wallet(), params, client))

        assert len(captured) == 2, "commit + reveal both built+signed without crashing"
        assert result["num_contracts"] == 1
        commit = Transaction.from_hex(captured[0])
        reveal = Transaction.from_hex(captured[1])
        assert commit is not None and reveal is not None
        # commit: FT-commit @vout0 + 1 ref-seed + change ; reveal vout0 = 1-photon contract (consensus-required)
        assert len(commit.outputs) >= 3
        assert reveal.outputs[0].satoshis == 1

    def test_deploy_inner_emits_premine_output(self, cli_context) -> None:
        """A premine adds one FT output after the contracts, sized and funded.

        The commit must carry the premine photons forward — the reveal has no
        other funding input, so under-sizing commit:0 would strand a confirmed
        commit with an unfundable reveal.
        """
        from pyrxd.cli.glyph_cmds import _deploy_dmint_inner
        from pyrxd.glyph.builder import DmintV1DeployParams
        from pyrxd.glyph.script import build_ft_locking_script
        from pyrxd.glyph.types import GlyphRef

        premine = 7_000_000
        ctx = dataclasses.replace(cli_context, output_mode="json", yes=True)
        key = PrivateKey()
        utxo = UtxoRecord(tx_hash="ab" * 32, tx_pos=0, value=500_000_000, height=100)

        class _Wallet:
            async def collect_spendable(self, client):
                return [(utxo, key.address(), key)]

        captured: list[bytes] = []
        commit_txid = "11" * 32

        async def _bcast(raw: bytes) -> str:
            captured.append(raw)
            return commit_txid if len(captured) == 1 else "22" * 32

        client = MagicMock()
        client.broadcast = _bcast
        client.get_transaction_verbose = AsyncMock(return_value={"confirmations": 1})

        meta = GlyphMetadata.for_dmint_ft(
            ticker="TST", name="t", protocol=[int(GlyphProtocol.FT), int(GlyphProtocol.DMINT)]
        )
        params = DmintV1DeployParams(
            metadata=meta,
            owner_pkh=Hex20(b"\x00" * 20),
            num_contracts=2,
            max_height=100,
            reward_photons=1000,
            difficulty=1,
            premine_amount=premine,
        )
        result = asyncio.run(_deploy_dmint_inner(ctx, _Wallet(), params, client))

        reveal = Transaction.from_hex(captured[1])
        assert reveal is not None
        # vout 0..1 contracts (1 photon each), vout 2 premine, vout 3 change.
        assert [o.satoshis for o in reveal.outputs[:3]] == [1, 1, premine]
        owner_pkh = Hex20(key.public_key().hash160())
        assert reveal.outputs[2].locking_script.script == build_ft_locking_script(
            owner_pkh, GlyphRef(txid=commit_txid, vout=0)
        )
        # Change is still positive: commit:0 was sized to cover premine + fee.
        assert reveal.outputs[3].satoshis > 0

        assert result["premine"] == premine
        assert result["premine_outpoint"] == f"{'22' * 32}:2"
        assert result["mineable_supply"] == 1000 * 100 * 2
        assert result["total_supply"] == 1000 * 100 * 2 + premine

    def test_deploy_inner_premine_absent_by_default(self, cli_context) -> None:
        from pyrxd.cli.glyph_cmds import _deploy_dmint_inner
        from pyrxd.glyph.builder import DmintV1DeployParams

        ctx = dataclasses.replace(cli_context, output_mode="json", yes=True)
        key = PrivateKey()
        utxo = UtxoRecord(tx_hash="ab" * 32, tx_pos=0, value=50_000_000, height=100)

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
        result = asyncio.run(
            _deploy_dmint_inner(
                ctx,
                _Wallet(),
                DmintV1DeployParams(
                    metadata=meta,
                    owner_pkh=Hex20(b"\x00" * 20),
                    num_contracts=1,
                    max_height=100,
                    reward_photons=1000,
                    difficulty=1,
                ),
                client,
            )
        )
        reveal = Transaction.from_hex(captured[1])
        assert reveal is not None
        assert len(reveal.outputs) == 2  # contract + change, no premine
        assert result["premine"] == 0
        assert result["premine_outpoint"] is None
        assert result["total_supply"] == result["mineable_supply"]

    @pytest.mark.parametrize("v2", [False, True])
    @pytest.mark.parametrize("num_contracts", [1, 2, 5, 20])
    @pytest.mark.parametrize("premine", [None, 7_000_000])
    def test_reveal_size_estimate_is_an_upper_bound(self, cli_context, v2, num_contracts, premine) -> None:
        """The reveal-size estimate must never come in UNDER the real transaction.

        ``commit0_value`` is derived from it and the reveal has no funding input of
        its own, so an under-estimate strands a confirmed commit behind a reveal
        that cannot pay its fee. The old flat ``n * 260 + 400`` formula was short
        for every V1 deploy with 2+ contracts and for every V2 deploy — this
        parametrisation is exactly the grid that caught it.
        """
        from pyrxd.cli.glyph_cmds import _deploy_dmint_inner, _estimate_dmint_reveal_bytes
        from pyrxd.glyph.builder import DmintV1DeployParams, DmintV2DeployParams, GlyphBuilder

        ctx = dataclasses.replace(cli_context, output_mode="json", yes=True)
        key = PrivateKey()
        utxo = UtxoRecord(tx_hash="ab" * 32, tx_pos=0, value=1_000_000_000_000, height=100)

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
            ticker="TST",
            name="sizing",
            description="d" * 60,
            protocol=[int(GlyphProtocol.FT), int(GlyphProtocol.DMINT)],
        )
        cls = DmintV2DeployParams if v2 else DmintV1DeployParams
        params = cls(
            metadata=meta,
            owner_pkh=Hex20(b"\x00" * 20),
            num_contracts=num_contracts,
            max_height=100,
            reward_photons=1000,
            difficulty=1,
            premine_amount=premine,
        )
        asyncio.run(_deploy_dmint_inner(ctx, _Wallet(), params, client))

        sizing = GlyphBuilder().prepare_dmint_deploy(params)
        estimate = _estimate_dmint_reveal_bytes(
            contract_scripts=sizing.placeholder_contract_scripts,
            cbor_len=len(sizing.cbor_bytes),
            premine=bool(premine),
            op_return_len=0,
        )
        actual = len(captured[1])
        assert estimate >= actual, f"reveal size estimate {estimate} UNDER the real {actual} bytes"
        # ...and not so loose that the deploy burns the surplus as fee. The change
        # output surviving fee() is the observable proof the surplus comes back.
        assert estimate <= actual * 1.10 + 64, f"estimate {estimate} is wastefully above {actual}"
        reveal = Transaction.from_hex(captured[1])
        assert reveal is not None
        expected_outputs = num_contracts + (1 if premine else 0) + 1  # + change
        assert len(reveal.outputs) == expected_outputs, "change output was dropped — the reveal underpaid"

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

    def test_deploy_ft_ref_is_commit_outpoint_not_reveal(self, cli_context, tmp_path) -> None:
        """The reported ref must be the ref actually embedded in the reveal script.

        Regression: the CLI reported the REVEAL txid while the builder embeds the
        COMMIT outpoint, so `transfer-ft` -- which matches on the *extracted* ref --
        could never resolve a token `deploy-ft` had just reported.
        """
        from pyrxd.cli.glyph_cmds import _deploy_ft_inner, _read_metadata_file
        from pyrxd.glyph.script import extract_ref_from_ft_script

        ctx = dataclasses.replace(cli_context, output_mode="json", yes=True)
        key, wallet, client, captured = self._wallet_and_client()
        meta = _read_metadata_file(_write_meta(tmp_path / "ft.json", protocol=["FT"]))
        treasury_pkh = Hex20(key.public_key().hash160())

        result = asyncio.run(_deploy_ft_inner(ctx, wallet, meta, treasury_pkh, 1000, client))

        reveal = Transaction.from_hex(captured[1])
        on_chain = extract_ref_from_ft_script(reveal.outputs[0].locking_script.serialize())
        assert result["ref"] == f"{on_chain.txid}:{on_chain.vout}"
        assert result["ref"].startswith(result["commit_txid"])
        assert not result["ref"].startswith(result["reveal_txid"])

    def test_mint_nft_ref_is_commit_outpoint_not_reveal(self, cli_context, tmp_path) -> None:
        """Same regression on the NFT path, which `transfer-nft` matches on."""
        from pyrxd.cli.glyph_cmds import _mint_nft_inner, _read_metadata_file
        from pyrxd.glyph.script import extract_ref_from_nft_script

        ctx = dataclasses.replace(cli_context, output_mode="json", yes=True)
        _key, wallet, client, captured = self._wallet_and_client()
        meta = _read_metadata_file(_write_meta(tmp_path / "nft.json", protocol=["NFT"]))
        result = asyncio.run(_mint_nft_inner(ctx, wallet, meta, client))

        reveal = Transaction.from_hex(captured[1])
        on_chain = extract_ref_from_nft_script(reveal.outputs[0].locking_script.serialize())
        assert result["ref"] == f"{on_chain.txid}:{on_chain.vout}"
        assert result["ref"].startswith(result["commit_txid"])
        assert not result["ref"].startswith(result["reveal_txid"])

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


class TestDmintV2CliPaths:
    """V2 deploy/claim CLI wiring (#219) — pure helpers + the version-agnostic deploy inner."""

    def test_parse_schedule_converts_difficulty_to_target(self):
        from pyrxd.cli.glyph_cmds import _parse_schedule
        from pyrxd.glyph.dmint import MAX_SHA256D_TARGET

        out = _parse_schedule("[[100, 4], [1000, 8]]")
        assert out == ((100, MAX_SHA256D_TARGET // 4), (1000, MAX_SHA256D_TARGET // 8))

    def test_parse_schedule_rejects_bad_json(self):
        from pyrxd.cli.errors import UserError
        from pyrxd.cli.glyph_cmds import _parse_schedule

        with pytest.raises(UserError, match="not valid JSON"):
            _parse_schedule("[[100, 4]")

    def test_parse_schedule_rejects_bad_shape(self):
        from pyrxd.cli.errors import UserError
        from pyrxd.cli.glyph_cmds import _parse_schedule

        with pytest.raises(UserError, match="height, difficulty"):
            _parse_schedule("[[100, 4, 9]]")

    def test_parse_schedule_red_team_edges(self):
        # Red-team #219: difficulty→target=0, bad/non-ascending heights, >10, bool, empty.
        from pyrxd.cli.errors import UserError
        from pyrxd.cli.glyph_cmds import _parse_schedule

        cases = {
            "[[100, 99999999999999999999999]]": "yields target 0",  # huge difficulty → target 0
            "[[-5, 4]]": "height must be >= 0",
            "[[1000, 4], [100, 8]]": "strictly ascending",  # non-ascending
            "[[100, 4], [100, 8]]": "strictly ascending",  # duplicate height
            "[]": "at least one",  # empty
            "[[100, 0]]": "difficulty must be >= 1",
        }
        for arg, msg in cases.items():
            with pytest.raises(UserError, match=msg):
                _parse_schedule(arg)
        # >10 entries
        with pytest.raises(UserError, match="at most 10"):
            _parse_schedule(str([[i * 10, 4] for i in range(11)]))
        # JSON bool is a Python int subclass — must be rejected as a height/difficulty
        with pytest.raises(UserError, match="must be integers"):
            _parse_schedule("[[true, 4]]")

    def test_v2_claim_daa_kwargs_per_mode(self):
        from pyrxd.cli.glyph_cmds import _v2_claim_daa_kwargs
        from pyrxd.glyph.dmint import DaaMode

        assert _v2_claim_daa_kwargs(DaaMode.FIXED, 10, "4", None, 3600) == {}
        assert _v2_claim_daa_kwargs(DaaMode.LWMA, 10, "4", None, 3600) == {}
        assert _v2_claim_daa_kwargs(DaaMode.ASERT, 10, "4", None, 600) == {"half_life": 600}
        assert _v2_claim_daa_kwargs(DaaMode.EPOCH, 10, "8", None, 3600) == {
            "epoch_length": 10,
            "max_adjustment_log2": 3,
        }
        sched = _v2_claim_daa_kwargs(DaaMode.SCHEDULE, 10, "4", "[[5, 2]]", 3600)
        assert "schedule" in sched and sched["schedule"][0][0] == 5

    def test_v2_claim_schedule_requires_schedule_flag(self):
        from pyrxd.cli.errors import UserError
        from pyrxd.cli.glyph_cmds import _v2_claim_daa_kwargs
        from pyrxd.glyph.dmint import DaaMode

        with pytest.raises(UserError, match="requires --schedule"):
            _v2_claim_daa_kwargs(DaaMode.SCHEDULE, 10, "4", None, 3600)

    def test_deploy_inner_v2_epoch(self, cli_context) -> None:
        """`deploy-dmint --v2 --daa-mode epoch` is re-enabled (upstream overflow fix
        merged, Radiant-Core/Photonic-Wallet#2): the inner deploy builds + signs an
        EPOCH V2 contract. Difficulty >= 32768 (target <= 2^48)."""
        from pyrxd.cli.glyph_cmds import _deploy_dmint_inner
        from pyrxd.glyph.builder import DmintV2DeployParams
        from pyrxd.glyph.dmint import DaaMode
        from pyrxd.security.types import Hex20

        ctx = dataclasses.replace(cli_context, output_mode="json", yes=True)
        key = PrivateKey()
        utxo = UtxoRecord(tx_hash="ab" * 32, tx_pos=0, value=50_000_000, height=100)

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
            ticker="TV2", name="t", protocol=[int(GlyphProtocol.FT), int(GlyphProtocol.DMINT)]
        )
        params = DmintV2DeployParams(
            metadata=meta,
            owner_pkh=Hex20(b"\x00" * 20),
            num_contracts=1,
            max_height=100,
            reward_photons=1000,
            difficulty=32768,
            daa_mode=DaaMode.EPOCH,
            target_time=60,
            epoch_length=10,
            max_adjustment_log2=2,
        )
        result = asyncio.run(_deploy_dmint_inner(ctx, _Wallet(), params, client))
        assert len(captured) == 2
        assert result["version"] == "V2"
        assert result["daa_mode"] == "EPOCH"

    def test_deploy_inner_v2_lwma(self, cli_context) -> None:
        """The version-agnostic deploy inner produces a V2 (LWMA) contract: commit +
        reveal both build/sign, and the result is tagged V2/LWMA."""
        from pyrxd.cli.glyph_cmds import _deploy_dmint_inner
        from pyrxd.glyph.builder import DmintV2DeployParams
        from pyrxd.glyph.dmint import DaaMode
        from pyrxd.security.types import Hex20

        ctx = dataclasses.replace(cli_context, output_mode="json", yes=True)
        key = PrivateKey()
        utxo = UtxoRecord(tx_hash="ab" * 32, tx_pos=0, value=50_000_000, height=100)

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
            ticker="TV2", name="t", protocol=[int(GlyphProtocol.FT), int(GlyphProtocol.DMINT)]
        )
        params = DmintV2DeployParams(
            metadata=meta,
            owner_pkh=Hex20(b"\x00" * 20),
            num_contracts=1,
            max_height=100,
            reward_photons=1000,
            difficulty=10,
            daa_mode=DaaMode.LWMA,
            target_time=60,
        )
        result = asyncio.run(_deploy_dmint_inner(ctx, _Wallet(), params, client))
        assert len(captured) == 2
        assert result["version"] == "V2"
        assert result["daa_mode"] == "LWMA"


# ---------------------------------------------------------------------------
# C-1: the reveal fee scales with the CBOR payload and is paid out of the commit
# output. The guard must fire BEFORE the commit is broadcast — once the commit is
# on-chain, an unfundable reveal strands its value permanently.
# ---------------------------------------------------------------------------


class TestRevealFeeGuard:
    def _wallet_and_client(self, utxo_value: int = 50_000_000):
        key = PrivateKey()
        utxo = UtxoRecord(tx_hash="ab" * 32, tx_pos=1, value=utxo_value, height=100)

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

    def test_mint_nft_sizes_the_commit_from_the_real_reveal_estimate(self, cli_context, tmp_path) -> None:
        from pyrxd.cli.glyph_cmds import _mint_nft_inner, _read_metadata_file
        from pyrxd.glyph.fees import estimate_reveal_fee_for_metadata

        ctx = dataclasses.replace(cli_context, output_mode="json", yes=True)
        _key, wallet, client, captured = self._wallet_and_client(utxo_value=500_000_000)
        # Big enough that the historical flat 5,000,000-photon commit could not have
        # paid the reveal fee.
        meta = _read_metadata_file(_write_meta(tmp_path / "big.json", protocol=["NFT"], description="x" * 900))
        estimate = estimate_reveal_fee_for_metadata(meta, fee_rate=ctx.fee_rate)
        assert estimate.fee > 5_000_000, "fixture must exercise the C-1 regime"

        asyncio.run(_mint_nft_inner(ctx, wallet, meta, client))

        assert len(captured) == 2, "commit + reveal both broadcast"
        commit = Transaction.from_hex(captured[0])
        reveal = Transaction.from_hex(captured[1])
        commit_value = commit.outputs[0].satoshis
        assert commit_value >= 546 + estimate.fee, "commit must cover carrier + reveal fee"
        # The reveal actually pays a real fee and still returns change — i.e. it is a
        # transaction a node would accept, not one whose outputs exceed its input.
        reveal_out = sum(o.satoshis for o in reveal.outputs)
        assert reveal_out < commit_value
        assert commit_value - reveal_out >= estimate.fee

    def test_guard_fires_before_the_commit_is_broadcast(self, cli_context, tmp_path, monkeypatch) -> None:
        from pyrxd.cli import glyph_cmds
        from pyrxd.cli.glyph_cmds import _mint_nft_inner, _read_metadata_file

        ctx = dataclasses.replace(cli_context, output_mode="json", yes=True)
        _key, wallet, client, captured = self._wallet_and_client(utxo_value=500_000_000)
        meta = _read_metadata_file(_write_meta(tmp_path / "big.json", protocol=["NFT"], description="x" * 900))
        # Pin the commit value back to the historical flat 5,000,000 so the guard has
        # something to catch. This is exactly the pre-fix behaviour.
        monkeypatch.setattr(glyph_cmds, "_commit_value_for_reveal", lambda carrier, est: 5_000_000)

        with pytest.raises(UserError) as ei:
            asyncio.run(_mint_nft_inner(ctx, wallet, meta, client))

        assert captured == [], "NOTHING may be broadcast — that is the whole point"
        assert "cannot cover the reveal fee" in str(ei.value.message)
        assert "short by" in str(ei.value.cause)
        assert isinstance(ei.value.__cause__, InsufficientFundsError)

    def test_deploy_ft_guard_fires_before_the_commit_is_broadcast(self, cli_context, tmp_path, monkeypatch) -> None:
        from pyrxd.cli import glyph_cmds
        from pyrxd.cli.glyph_cmds import _deploy_ft_inner, _read_metadata_file

        ctx = dataclasses.replace(cli_context, output_mode="json", yes=True)
        key, wallet, client, captured = self._wallet_and_client(utxo_value=500_000_000)
        meta = _read_metadata_file(_write_meta(tmp_path / "bigft.json", protocol=["FT"], description="x" * 900))
        treasury_pkh = Hex20(key.public_key().hash160())
        monkeypatch.setattr(glyph_cmds, "_commit_value_for_reveal", lambda carrier, est: carrier + 5_000_000)

        with pytest.raises(UserError):
            asyncio.run(_deploy_ft_inner(ctx, wallet, meta, treasury_pkh, 1000, client))

        assert captured == []

    def test_deploy_ft_sizes_the_commit_from_the_real_reveal_estimate(self, cli_context, tmp_path) -> None:
        from pyrxd.cli.glyph_cmds import _deploy_ft_inner, _read_metadata_file
        from pyrxd.glyph.fees import estimate_reveal_fee_for_metadata

        ctx = dataclasses.replace(cli_context, output_mode="json", yes=True)
        key, wallet, client, captured = self._wallet_and_client(utxo_value=500_000_000)
        meta = _read_metadata_file(_write_meta(tmp_path / "bigft.json", protocol=["FT"], description="x" * 900))
        treasury_pkh = Hex20(key.public_key().hash160())
        estimate = estimate_reveal_fee_for_metadata(meta, fee_rate=ctx.fee_rate)

        asyncio.run(_deploy_ft_inner(ctx, wallet, meta, treasury_pkh, 1000, client))

        assert len(captured) == 2
        commit = Transaction.from_hex(captured[0])
        reveal = Transaction.from_hex(captured[1])
        # The whole supply sits on the reveal's vout[0], so none of it pays the fee.
        assert reveal.outputs[0].satoshis == 1000
        assert commit.outputs[0].satoshis >= 1000 + estimate.fee

    def test_small_metadata_keeps_the_historical_commit_overhead(self, cli_context, tmp_path) -> None:
        # The 5,000,000-photon floor is preserved for payloads that always fitted.
        from pyrxd.cli.glyph_cmds import _mint_nft_inner, _read_metadata_file

        ctx = dataclasses.replace(cli_context, output_mode="json", yes=True)
        _key, wallet, client, captured = self._wallet_and_client()
        meta = _read_metadata_file(_write_meta(tmp_path / "nft.json", protocol=["NFT"]))

        asyncio.run(_mint_nft_inner(ctx, wallet, meta, client))

        commit = Transaction.from_hex(captured[0])
        assert commit.outputs[0].satoshis == 546 + 5_000_000

    def test_reveal_fee_is_shown_in_the_confirmation_summary(self, cli_context, tmp_path, monkeypatch) -> None:
        # A human confirming a broadcast should see what the reveal will cost, since
        # it comes out of the value they are about to lock in the commit.
        from pyrxd.cli import glyph_cmds
        from pyrxd.cli.glyph_cmds import _mint_nft_inner, _read_metadata_file

        seen: list[str] = []
        monkeypatch.setattr(
            glyph_cmds,
            "_confirm_or_abort",
            lambda ctx, sections: seen.extend(line for sec in sections for line in sec.lines),
        )
        ctx = dataclasses.replace(cli_context, output_mode="json", yes=True)
        _key, wallet, client, _captured = self._wallet_and_client()
        meta = _read_metadata_file(_write_meta(tmp_path / "nft.json", protocol=["NFT"]))

        asyncio.run(_mint_nft_inner(ctx, wallet, meta, client))

        summary = "\n".join(seen)
        assert "reveal fee:" in summary
        assert "paid from commit value" in summary


class TestWaitForTxTranslation:
    """``_wait_for_tx`` is now a thin click-boundary wrapper; the polling lives in
    ``pyrxd.network.confirm`` where both time seams are injectable."""

    def test_library_timeout_becomes_a_network_boundary_error(self) -> None:
        from pyrxd.cli.errors import NetworkBoundaryError
        from pyrxd.cli.glyph_cmds import _wait_for_tx

        client = MagicMock()
        client.get_transaction_verbose = AsyncMock(return_value={"confirmations": 0})

        # timeout_s smaller than the 10s poll interval: the first elapsed check on the
        # real monotonic clock is already past it, so this terminates immediately.
        with pytest.raises(NetworkBoundaryError) as ei:
            asyncio.run(_wait_for_tx(client, "ab" * 32, timeout_s=1e-9))

        assert ei.value.exit_code == 2
        assert "timed out waiting for confirmation" in ei.value.message
        assert isinstance(ei.value.__cause__, ConfirmationTimeoutError)

    def test_returns_quietly_once_confirmed(self) -> None:
        from pyrxd.cli.glyph_cmds import _wait_for_tx

        client = MagicMock()
        client.get_transaction_verbose = AsyncMock(return_value={"confirmations": 1})
        assert asyncio.run(_wait_for_tx(client, "ab" * 32)) is None

    def test_does_not_leak_a_click_exception_out_of_the_library(self) -> None:
        # NetworkBoundaryError is a click.ClickException; library code must never
        # raise it. wait_for_confirmation raises the typed library error instead.
        import click

        from pyrxd.network.confirm import wait_for_confirmation

        client = MagicMock()
        client.get_transaction_verbose = AsyncMock(return_value={"confirmations": 0})

        with pytest.raises(ConfirmationTimeoutError) as ei:
            asyncio.run(wait_for_confirmation(client, "ab" * 32, timeout_s=1e-9))

        assert not isinstance(ei.value, click.ClickException)


class TestConfirmationTimeoutRecoveryHint:
    """A confirmation timeout can strand real value (the commit output has no
    owner-only spend path), so the hint must describe a recovery that exists. It used
    to say "re-run with COMMIT_TXID=<txid>" — a flag this CLI has never had."""

    def _timeout_error(self):
        from pyrxd.cli.errors import NetworkBoundaryError
        from pyrxd.cli.glyph_cmds import _wait_for_tx

        client = MagicMock()
        client.get_transaction_verbose = AsyncMock(return_value={"confirmations": 0})
        with pytest.raises(NetworkBoundaryError) as ei:
            asyncio.run(_wait_for_tx(client, "ab" * 32, timeout_s=1e-9))
        return ei.value

    def test_hint_names_no_flag_or_env_var_the_cli_does_not_have(self) -> None:
        fix = self._timeout_error().fix
        assert "COMMIT_TXID" not in fix
        assert "--resume" not in fix
        # Whatever it names must actually be reachable from the shipped CLI options.
        from pyrxd.cli.glyph_cmds import deploy_ft_cmd, mint_nft_cmd

        declared = {opt for cmd in (mint_nft_cmd, deploy_ft_cmd) for p in cmd.params for opt in getattr(p, "opts", ())}
        assert not any(word.startswith("--") and word not in declared for word in fix.split())

    def test_hint_points_at_the_sdk_call_that_exists(self) -> None:
        from pyrxd.glyph.builder import GlyphBuilder, RevealParams

        fix = self._timeout_error().fix
        assert "prepare_reveal" in fix
        assert hasattr(GlyphBuilder, "prepare_reveal")
        # Every keyword the hint spells out must be a real RevealParams field.
        named = {"commit_txid", "commit_vout", "commit_value", "cbor_bytes", "owner_pkh", "is_nft"}
        assert named <= set(RevealParams.__dataclass_fields__)
        assert all(f"{field}=" in fix for field in named)

    def test_the_recovery_it_describes_reconstructs_a_spendable_reveal(self, tmp_path) -> None:
        # Walk the documented path: re-read the SAME metadata file, re-encode, and check
        # the rebuilt reveal still satisfies the commit script's payload-hash covenant.
        from pyrxd.cli.glyph_cmds import _read_metadata_file
        from pyrxd.glyph.builder import CommitParams, GlyphBuilder, RevealParams
        from pyrxd.glyph.payload import encode_payload
        from pyrxd.keys import PrivateKey
        from pyrxd.security.types import Hex20

        path = _write_meta(tmp_path / "nft.json", protocol=["NFT"])
        key = PrivateKey()
        pkh = Hex20(key.public_key().hash160())
        builder = GlyphBuilder()
        commit = builder.prepare_commit(
            CommitParams(metadata=_read_metadata_file(path), owner_pkh=pkh, change_pkh=pkh, funding_satoshis=50_000_000)
        )
        embedded_payload_hash = commit.commit_script[2:34]  # OP_HASH256 PUSH32 <hash>

        # …later, in a fresh process, from the unmodified file:
        cbor_bytes, payload_hash = encode_payload(_read_metadata_file(path))
        assert payload_hash == embedded_payload_hash
        scripts = builder.prepare_reveal(
            RevealParams(
                commit_txid="ab" * 32,
                commit_vout=0,
                commit_value=5_000_000,
                cbor_bytes=cbor_bytes,
                owner_pkh=pkh,
                is_nft=True,
            )
        )
        # The suffix pushes exactly the CBOR the commit output's OP_HASH256 demands.
        assert cbor_bytes == commit.cbor_bytes
        assert cbor_bytes in scripts.scriptsig_suffix

    def test_an_edited_metadata_file_does_not_reconstruct_it(self, tmp_path) -> None:
        # Why the hint says "SAME unmodified metadata file": a different payload hashes
        # differently and the commit output becomes unspendable.
        from pyrxd.cli.glyph_cmds import _read_metadata_file
        from pyrxd.glyph.payload import encode_payload

        original = _read_metadata_file(_write_meta(tmp_path / "a.json", protocol=["NFT"]))
        edited = _read_metadata_file(_write_meta(tmp_path / "b.json", protocol=["NFT"], name="Edited"))
        assert encode_payload(original)[1] != encode_payload(edited)[1]
