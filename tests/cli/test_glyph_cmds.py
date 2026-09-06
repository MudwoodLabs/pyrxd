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
import re
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
        # Photonic's `type` value for a collection is the literal "container";
        # anything else renders the collection as a plain object there.
        assert payload["token_type"] == "container"

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


class TestMetadataDmintBlock:
    """A ``dmint`` block in metadata.json must reach the deploy-vs-declared guard.

    It did not. ``_read_metadata_file`` never passed ``dmint_params`` to
    ``GlyphMetadata``, so every CLI deploy emitted CBOR with no ``dmint`` object
    and ``_assert_declared_dmint_matches`` returned on its first line — the
    guard was unreachable from the only command that emits a premine. A
    metadata file declaring ``"premine": 999999999`` deployed with no premine at
    all and said nothing.
    """

    _DMINT_META = {
        "protocol": ["FT", "DMINT"],
        "dmint": {
            "algo": "sha256d",
            "numContracts": 1,
            "maxHeight": 10_000,
            "reward": 10,
            "premine": 999_999_999,
            "diff": 1,
        },
    }

    def _deploy_params(self, meta, **overrides):
        from pyrxd.glyph.builder import DmintV1DeployParams
        from pyrxd.security.types import Hex20

        kwargs = {
            "num_contracts": 1,
            "max_height": 10_000,
            "reward_photons": 10,
            "difficulty": 1,
            "premine_amount": None,
        }
        kwargs.update(overrides)
        return DmintV1DeployParams(metadata=meta, owner_pkh=Hex20(bytes(20)), **kwargs)

    def test_dmint_block_is_parsed_into_metadata(self, tmp_path: Path) -> None:
        from pyrxd.cli.glyph_cmds import _read_metadata_file

        meta = _read_metadata_file(_write_meta(tmp_path / "d.json", **self._DMINT_META))
        assert meta.dmint_params is not None
        assert meta.dmint_params.premine == 999_999_999
        assert meta.dmint_params.max_height == 10_000
        assert meta.dmint_params.reward == 10

    def test_declared_premine_now_refuses_a_deploy_that_emits_none(self, tmp_path: Path) -> None:
        """The audit's exact case: previously ACCEPTED."""
        from pyrxd.cli.glyph_cmds import _read_metadata_file
        from pyrxd.glyph.builder import GlyphBuilder
        from pyrxd.security.errors import ValidationError

        meta = _read_metadata_file(_write_meta(tmp_path / "d.json", **self._DMINT_META))
        with pytest.raises(ValidationError, match="dmint.premine"):
            GlyphBuilder().prepare_dmint_deploy(self._deploy_params(meta))

    def test_declared_supply_now_refuses_a_deploy_that_mints_more(self, tmp_path: Path) -> None:
        """100,000 advertised vs 70,368,735,789,056,250 actually mintable."""
        from pyrxd.cli.glyph_cmds import _read_metadata_file
        from pyrxd.glyph.builder import GlyphBuilder
        from pyrxd.security.errors import ValidationError

        body = dict(self._DMINT_META)
        body["dmint"] = {**self._DMINT_META["dmint"], "premine": 0}
        meta = _read_metadata_file(_write_meta(tmp_path / "d.json", **body))
        with pytest.raises(ValidationError, match="dmint.reward"):
            GlyphBuilder().prepare_dmint_deploy(
                self._deploy_params(
                    meta,
                    reward_photons=16_777_215,
                    max_height=16_777_215,
                    num_contracts=250,
                )
            )

    def test_a_truthful_declaration_deploys(self, tmp_path: Path) -> None:
        from pyrxd.cli.glyph_cmds import _read_metadata_file
        from pyrxd.glyph.builder import GlyphBuilder

        body = dict(self._DMINT_META)
        body["dmint"] = {**self._DMINT_META["dmint"], "premine": 500}
        meta = _read_metadata_file(_write_meta(tmp_path / "d.json", **body))
        result = GlyphBuilder().prepare_dmint_deploy(self._deploy_params(meta, premine_amount=500))
        assert result.premine_amount == 500

    def test_metadata_without_a_dmint_block_still_deploys(self, tmp_path: Path) -> None:
        """Declaring the block stays optional — nothing advertised, nothing to check."""
        from pyrxd.cli.glyph_cmds import _read_metadata_file
        from pyrxd.glyph.builder import GlyphBuilder

        meta = _read_metadata_file(_write_meta(tmp_path / "d.json", protocol=["FT", "DMINT"]))
        assert meta.dmint_params is None
        assert GlyphBuilder().prepare_dmint_deploy(self._deploy_params(meta)) is not None

    def test_algo_accepts_a_name_or_an_int(self, tmp_path: Path) -> None:
        from pyrxd.cli.glyph_cmds import _read_metadata_file

        body = dict(self._DMINT_META)
        body["dmint"] = {**self._DMINT_META["dmint"], "algo": 1}
        by_int = _read_metadata_file(_write_meta(tmp_path / "i.json", **body))
        body["dmint"] = {**self._DMINT_META["dmint"], "algo": "blake3"}
        by_name = _read_metadata_file(_write_meta(tmp_path / "n.json", **body))
        assert by_int.dmint_params is not None and by_name.dmint_params is not None
        assert by_int.dmint_params.algo == by_name.dmint_params.algo

    def test_unknown_algo_name_is_a_user_error(self, tmp_path: Path) -> None:
        from pyrxd.cli.errors import UserError
        from pyrxd.cli.glyph_cmds import _read_metadata_file

        body = dict(self._DMINT_META)
        body["dmint"] = {**self._DMINT_META["dmint"], "algo": "scrypt"}
        with pytest.raises(UserError, match="dmint.algo"):
            _read_metadata_file(_write_meta(tmp_path / "bad.json", **body))

    def test_non_object_dmint_is_a_user_error(self, tmp_path: Path) -> None:
        from pyrxd.cli.errors import UserError
        from pyrxd.cli.glyph_cmds import _read_metadata_file

        with pytest.raises(UserError, match="metadata.dmint must be a JSON object"):
            _read_metadata_file(_write_meta(tmp_path / "bad.json", protocol=["FT", "DMINT"], dmint=[1, 2, 3]))

    def test_malformed_dmint_block_is_a_user_error(self, tmp_path: Path) -> None:
        from pyrxd.cli.errors import UserError
        from pyrxd.cli.glyph_cmds import _read_metadata_file

        with pytest.raises(UserError, match="metadata.dmint failed validation"):
            _read_metadata_file(
                _write_meta(tmp_path / "bad.json", protocol=["FT", "DMINT"], dmint={"maxHeight": 10, "reward": 1})
            )


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
import pathlib
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
            # Lie on the COMMIT, tell the truth on the REVEAL. The commit helper warns and
            # carries on by design, so a lie there is a legitimate thing to exercise; the
            # reveal helper now RAISES, because outpoints the user spends against are built
            # from that txid. These fakes echoed constants for both, which is why nothing
            # noticed the reveal was never verified.
            from pyrxd.transaction.transaction import Transaction

            if len(captured) == 1:
                return "11" * 32
            return Transaction.from_hex(raw.hex()).txid()

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

        # LIE on the commit broadcast, truthfully echo everything after it.
        #
        # An honest echo here proves nothing: code that trusts the server and code that
        # derives the txid locally both pass, because the two values agree. The lie is
        # the whole point of the fixture — it is what fails if `_local_commit_txid` is
        # ever reverted to `str(echoed)`.
        COMMIT_LIE = "de" * 32

        async def _bcast(raw: bytes) -> str:
            from pyrxd.transaction.transaction import Transaction

            captured.append(raw)
            if len(captured) == 1:
                return COMMIT_LIE
            return Transaction.from_hex(raw.hex()).txid()

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

        commit_txid = Transaction.from_hex(captured[0]).txid()
        # The derived txid wins over the server's reply, and the reveal is built against
        # the REAL commit — not the lie. If either regresses, the token's ref points at a
        # transaction that does not exist and the commit becomes unspendable.
        assert commit_txid != COMMIT_LIE
        assert result["commit_txid"] == commit_txid
        reveal = Transaction.from_hex(captured[1])
        assert reveal is not None
        assert str(reveal.inputs[0].source_txid) == commit_txid
        # vout 0..1 contracts (1 photon each), vout 2 premine, vout 3 change.
        assert [o.satoshis for o in reveal.outputs[:3]] == [1, 1, premine]
        owner_pkh = Hex20(key.public_key().hash160())
        assert reveal.outputs[2].locking_script.script == build_ft_locking_script(
            owner_pkh, GlyphRef(txid=commit_txid, vout=0)
        )
        # Change is still positive: commit:0 was sized to cover premine + fee.
        assert reveal.outputs[3].satoshis > 0

        assert result["premine"] == premine
        # Derived from the reveal we actually broadcast, not from a constant the fake
        # used to echo — the CLI no longer takes the server's word for a txid.
        assert result["premine_outpoint"] == f"{reveal.txid()}:2"
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
            # Lie on the COMMIT, tell the truth on the REVEAL. The commit helper warns and
            # carries on by design, so a lie there is a legitimate thing to exercise; the
            # reveal helper now RAISES, because outpoints the user spends against are built
            # from that txid. These fakes echoed constants for both, which is why nothing
            # noticed the reveal was never verified.
            from pyrxd.transaction.transaction import Transaction

            if len(captured) == 1:
                return "11" * 32
            return Transaction.from_hex(raw.hex()).txid()

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
            # Lie on the COMMIT, tell the truth on the REVEAL. The commit helper warns and
            # carries on by design, so a lie there is a legitimate thing to exercise; the
            # reveal helper now RAISES, because outpoints the user spends against are built
            # from that txid. These fakes echoed constants for both, which is why nothing
            # noticed the reveal was never verified.
            from pyrxd.transaction.transaction import Transaction

            if len(captured) == 1:
                return "11" * 32
            return Transaction.from_hex(raw.hex()).txid()

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
            # Lie on the COMMIT, tell the truth on the REVEAL. The commit helper warns and
            # carries on by design, so a lie there is a legitimate thing to exercise; the
            # reveal helper now RAISES, because outpoints the user spends against are built
            # from that txid. These fakes echoed constants for both, which is why nothing
            # noticed the reveal was never verified.
            from pyrxd.transaction.transaction import Transaction

            if len(captured) == 1:
                return "11" * 32
            return Transaction.from_hex(raw.hex()).txid()

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
            # Echo the txid of what we were actually sent. A constant here models a
            # server that lies about which transaction it relayed, which the CLI now
            # refuses — see `BroadcastEchoMismatch`.
            from pyrxd.transaction.transaction import Transaction

            return Transaction.from_hex(raw.hex()).txid()

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
        assert result["txid"] == tx.txid(), "reports the txid of the bytes it broadcast"


def _run_transfer_nft(cli_context, *, fund_value: int) -> tuple[list[bytes], object]:
    """Drive ``_transfer_nft_inner`` once over FRESH keys. Returns (broadcast bytes, result).

    Fresh keys every call on purpose. Signing is RFC 6979, so whether a *given*
    transaction underpays is a fixed property of it, not a flake — a fixed-key fixture
    signs one message forever and can never see a defect that lands on a quarter of
    real sends. The property below therefore redraws.
    """
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
    nft_utxo = UtxoRecord(tx_hash="bb" * 32, tx_pos=1, value=1000, height=100)
    fund_key = PrivateKey()
    fund_spk = P2PKH().lock(fund_key.address()).serialize()
    fund_utxo = UtxoRecord(tx_hash="cc" * 32, tx_pos=1, value=fund_value, height=100)

    txmap = {"bb" * 32: _src_hex(1, nft_script, 1000), "cc" * 32: _src_hex(1, fund_spk, fund_value)}

    class _Wallet:
        async def collect_spendable(self, client):
            return [(nft_utxo, owner_key.address(), owner_key), (fund_utxo, fund_key.address(), fund_key)]

    captured: list[bytes] = []

    async def _bcast(raw: bytes) -> str:
        captured.append(raw)
        from pyrxd.transaction.transaction import Transaction

        return Transaction.from_hex(raw.hex()).txid()

    client = MagicMock()
    client.get_transaction = AsyncMock(side_effect=lambda t: txmap[str(t)])
    client.broadcast = _bcast

    to_key = PrivateKey()
    result = asyncio.run(
        _transfer_nft_inner(ctx, _Wallet(), ref, Hex20(to_key.public_key().hash160()), to_key.address(), client)
    )
    return captured, result


class TestTransferNftPaysTheRelayFloor:
    """FS-1. ``transfer-nft`` signed and broadcast transactions below Radiant's relay floor.

    ``needed=100_000`` was a flat literal that never multiplied by ``ctx.fee_rate``, so it
    could not cover a ~377-byte transfer at *any* rate at or above the floor — raising the
    rate widened the gap. When funding fell short, ``Transaction.fee()`` silently dropped
    the change output rather than failing, converting the shortfall into "the whole UTXO
    is the fee", and the CLI signed and broadcast the result. Measured on this fixture
    before the fix, at the CLI's default 10_000 photons/byte::

        funding=  100000  size=377B  fee=  100000  floor=3770000  -> REJECTED BY EVERY NODE
        funding= 1000000  size=376B  fee= 1000000  floor=3760000  -> REJECTED BY EVERY NODE
        funding= 3000000  size=378B  fee= 3000000  floor=3780000  -> REJECTED BY EVERY NODE
        40/40 fresh-key builds at funding=1_000_000 broadcast below the floor

    Radiant has neither RBF nor CPFP, so such a broadcast cannot be bumped or replaced.
    """

    #: Draws per property case. Roughly a third of DISTINCT sends land on the wrong side
    #: of a signature-length shortfall, so 40 puts the chance of a sweep seeing none at
    #: ~1e-7; the whole class still runs in about a second.
    ROUNDS = 40

    def test_a_funding_utxo_that_cannot_pay_the_floor_is_refused_not_broadcast(self, cli_context) -> None:
        """The case the old bar admitted: 1_000_000 photons, 41x under a ~3.78M requirement."""
        from pyrxd.cli.errors import UserError

        for _ in range(self.ROUNDS):
            with pytest.raises(UserError, match="no plain-RXD UTXO large enough"):
                _run_transfer_nft(cli_context, fund_value=1_000_000)

    def test_every_build_that_is_returned_pays_for_its_own_signed_bytes(self, cli_context) -> None:
        """The property, swept across the funding range the old bar accepted.

        For every funding value the command either refuses (no broadcast) or returns a
        transaction whose fee covers ``min_relay_fee`` of its FINAL SIGNED length. There
        is no third outcome — and "signed and broadcast anyway" was the only outcome
        before the fix for everything under ~3.78M.
        """
        from pyrxd.cli.errors import UserError
        from pyrxd.fee_sizing import min_relay_fee

        relayed = 0
        for value in (100_000, 1_000_000, 3_000_000, 3_779_999, 3_780_000, 4_200_000, 50_000_000):
            for _ in range(6):
                try:
                    captured, result = _run_transfer_nft(cli_context, fund_value=value)
                except UserError:
                    continue  # refused before signing: the safe outcome
                assert len(captured) == 1
                raw = captured[0]
                assert result["fee"] >= min_relay_fee(len(raw)), (
                    f"broadcast {len(raw)} B paying {result['fee']} photons, below the "
                    f"{min_relay_fee(len(raw))} photon floor, from a {value} photon funding UTXO"
                )
                relayed += 1
        assert relayed > 0, "every case refused — the property is vacuous"

    def test_the_bar_does_not_refuse_a_utxo_that_would_have_relayed(self, cli_context) -> None:
        """The other half: a guard that refuses a legitimate action is its own bug.

        At EXACTLY the bar the build must go through, over fresh keys — the no-change
        shape (``Transaction.fee()`` drops change it cannot fund) is the smallest
        transaction this command can produce, so sizing the bar against the two-output
        shape would refuse funding that in fact relays.
        """
        from pyrxd.fee_sizing import min_relay_fee
        from pyrxd.glyph.script import build_nft_locking_script
        from pyrxd.glyph.transfer import nft_transfer_funding_bar as _nft_transfer_funding_bar

        locking = build_nft_locking_script(Hex20(PrivateKey().public_key().hash160()), GlyphRef(txid="aa" * 32, vout=0))
        bar = _nft_transfer_funding_bar(locking, cli_context.fee_rate)
        for _ in range(self.ROUNDS):
            captured, result = _run_transfer_nft(cli_context, fund_value=bar)
            assert result["fee"] >= min_relay_fee(len(captured[0]))

    def test_the_bar_scales_with_the_fee_rate(self, cli_context) -> None:
        """The defining property the flat literal lacked: it multiplies by the rate."""
        from pyrxd.glyph.script import build_nft_locking_script
        from pyrxd.glyph.transfer import nft_transfer_funding_bar as _nft_transfer_funding_bar

        locking = build_nft_locking_script(Hex20(PrivateKey().public_key().hash160()), GlyphRef(txid="aa" * 32, vout=0))
        at_floor = _nft_transfer_funding_bar(locking, 10_000)
        assert _nft_transfer_funding_bar(locking, 20_000) == 2 * at_floor
        assert at_floor > 100_000, "the bar this replaced was a flat 100_000 photons"

    def test_a_node_rejection_is_not_reported_as_an_unreachable_server(
        self, runner, tmp_wallet_path, monkeypatch
    ) -> None:
        """``PolicyRejection`` subclasses ``NetworkError``, so a node VERDICT was being
        relabelled "could not reach ElectrumX — check that <url> is reachable", sending
        the operator to debug connectivity for a transaction the node had evaluated."""
        import pyrxd.cli.glyph_cmds as gc
        from pyrxd.security.errors import PolicyRejection

        runner.invoke(cli, _new_wallet_args(tmp_wallet_path))
        monkeypatch.setattr(gc, "_load_wallet", lambda ctx, **kw: object())

        async def _boom(*_a, **_k):
            raise PolicyRejection("66: min relay fee not met", code=1, reason="min relay fee not met")

        monkeypatch.setattr(gc, "_transfer_nft_inner", _boom)
        result = runner.invoke(
            cli,
            [
                "--wallet",
                str(tmp_wallet_path),
                "--yes",
                "glyph",
                "transfer-nft",
                f"{'aa' * 32}:0",
                "--to",
                PrivateKey().address(),
            ],
        )
        assert "could not reach ElectrumX" not in result.output, result.output
        assert "the node rejected the NFT transfer" in result.output, result.output
        assert "min relay fee not met" in result.output, result.output
        assert result.exit_code == 1, result.output


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
            # Lie on the COMMIT, tell the truth on the REVEAL. The commit helper warns and
            # carries on by design, so a lie there is a legitimate thing to exercise; the
            # reveal helper now RAISES, because outpoints the user spends against are built
            # from that txid. These fakes echoed constants for both, which is why nothing
            # noticed the reveal was never verified.
            from pyrxd.transaction.transaction import Transaction

            if len(captured) == 1:
                return "11" * 32
            return Transaction.from_hex(raw.hex()).txid()

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
            # Lie on the COMMIT, tell the truth on the REVEAL. The commit helper warns and
            # carries on by design, so a lie there is a legitimate thing to exercise; the
            # reveal helper now RAISES, because outpoints the user spends against are built
            # from that txid. These fakes echoed constants for both, which is why nothing
            # noticed the reveal was never verified.
            from pyrxd.transaction.transaction import Transaction

            if len(captured) == 1:
                return "11" * 32
            return Transaction.from_hex(raw.hex()).txid()

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
            # Lie on the COMMIT, tell the truth on the REVEAL. The commit helper warns and
            # carries on by design, so a lie there is a legitimate thing to exercise; the
            # reveal helper now RAISES, because outpoints the user spends against are built
            # from that txid. These fakes echoed constants for both, which is why nothing
            # noticed the reveal was never verified.
            from pyrxd.transaction.transaction import Transaction

            if len(captured) == 1:
                return "11" * 32
            return Transaction.from_hex(raw.hex()).txid()

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
        #
        # Derived from the `glyph` group rather than a hand-typed tuple of two commands. This
        # hint is raised by `_wait_for_tx`, which `mint-nft`, `deploy-ft` AND `timelock-mint`
        # (through `_mint_nft_inner`) all reach — so a tuple naming two of them was structural
        # about the words and hand-kept about the scope, and it failed the moment the hint
        # started naming an option on the third. `glyph_group.commands` is the set the CLI
        # itself publishes; it cannot fall behind a command that was registered on it.
        from pyrxd.cli.glyph_cmds import glyph_group

        assert glyph_group.commands, "the group is empty, so this check would pass vacuously"
        declared = {opt for cmd in glyph_group.commands.values() for p in cmd.params for opt in getattr(p, "opts", ())}
        # Extracted by pattern, not by whitespace splitting: `--envelope-out` inside backticks,
        # or an option followed by a comma, is still an option this hint is telling someone to
        # type, and a splitter that skips it lets an unreachable flag through unnoticed.
        named = set(re.findall(r"--[a-z0-9][a-z0-9-]*", fix))
        assert named, "the hint names no CLI option at all — this check has stopped running"
        assert not named - declared

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


class TestTransferFtAllowOverpayIsWiredThrough:
    """``--allow-overpay`` must reach the guard, not just parse.

    Two fee bounds refuse rather than warn on this path: the rate ceiling, and the
    check that the fee matches the signed bytes. Neither should ever refuse an
    ordinary transfer — measured 0 refusals over 3,600+ builds at 2-10 inputs and
    1-9x the floor rate — but Radiant has neither RBF nor CPFP, so a bound an
    operator cannot override can cost the funds it was protecting. The flag existed
    on ``GlyphClient`` and had no CLI surface at all until this change.

    A flag that parses but does not reach the thing it names is worse than no flag,
    because it reads as an escape hatch while being a dead end. So these assert on
    the value that arrives at the library call.
    """

    def _capture(self, monkeypatch):
        """Replace the library build with a recorder; return the kwargs seen."""
        import dataclasses

        from pyrxd.cli import glyph_cmds
        from pyrxd.glyph.types import GlyphRef
        from pyrxd.security.types import Hex20

        seen: dict = {}

        class _Build:
            fee = 1_000

            def __init__(self) -> None:
                from pyrxd.script.script import Script
                from pyrxd.transaction.transaction import Transaction
                from pyrxd.transaction.transaction_output import TransactionOutput

                self.tx = Transaction(tx_inputs=[], tx_outputs=[TransactionOutput(Script(b""), 0)])

            def serialize(self) -> bytes:
                # Real serialized bytes, not filler: the CLI now derives the txid from
                # what it broadcast, so an unparseable payload no longer round-trips.
                return self.tx.serialize()

        async def _fake_build(wallet, ref, amount, to_pkh, *, client, fee_rate, allow_overpay=False):
            seen["allow_overpay"] = allow_overpay
            return _Build()

        monkeypatch.setattr(glyph_cmds, "lib_build_ft_transfer", _fake_build)
        monkeypatch.setattr(glyph_cmds, "_confirm_or_abort", lambda *a, **k: None)
        return seen, dataclasses, GlyphRef, Hex20

    def _drive(self, cli_context, monkeypatch, *, allow_overpay):
        import asyncio
        import dataclasses
        from unittest.mock import MagicMock

        from pyrxd.cli.glyph_cmds import _transfer_ft_inner
        from pyrxd.glyph.types import GlyphRef
        from pyrxd.security.types import Hex20

        seen, *_ = self._capture(monkeypatch)
        ctx = dataclasses.replace(cli_context, output_mode="json", yes=True)
        client = MagicMock()

        # Must echo what it is handed; a constant now trips the echo-mismatch guard.
        async def _echo(raw: bytes) -> str:
            from pyrxd.transaction.transaction import Transaction

            return Transaction.from_hex(raw.hex()).txid()

        client.broadcast = _echo

        asyncio.run(
            _transfer_ft_inner(
                ctx,
                object(),
                GlyphRef(txid="aa" * 32, vout=0),
                250,
                Hex20(bytes(20)),
                "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
                client,
                allow_overpay=allow_overpay,
            )
        )
        return seen

    def test_default_is_off(self, cli_context, monkeypatch) -> None:
        assert self._drive(cli_context, monkeypatch, allow_overpay=False)["allow_overpay"] is False

    def test_the_flag_reaches_the_build(self, cli_context, monkeypatch) -> None:
        assert self._drive(cli_context, monkeypatch, allow_overpay=True)["allow_overpay"] is True

    def test_the_cli_accepts_the_flag(self, runner: CliRunner, tmp_wallet_path: Path) -> None:
        """It is a real option, not silently swallowed by click as an argument."""
        runner.invoke(cli, _new_wallet_args(tmp_wallet_path))
        result = runner.invoke(
            cli,
            ["--wallet", str(tmp_wallet_path), "glyph", "transfer-ft", "--help"],
        )
        assert result.exit_code == 0
        assert "--allow-overpay" in result.output

    def test_an_overpay_refusal_names_the_flag_rather_than_telling_you_to_add_rxd(
        self, cli_context, monkeypatch
    ) -> None:
        """The remedy has to match the problem.

        A fee-bound refusal and a funding shortfall are different failures. The
        generic branch says "fund the wallet with a little plain RXD", which for a
        build refused for paying too MUCH points in the opposite direction.
        """
        import asyncio
        import dataclasses
        from unittest.mock import MagicMock

        from pyrxd.cli import glyph_cmds
        from pyrxd.cli.errors import UserError
        from pyrxd.glyph.types import GlyphRef
        from pyrxd.security.errors import ValidationError
        from pyrxd.security.types import Hex20

        async def _refuse(*a, **k):
            raise ValidationError(
                "refusing to broadcast: the fee exceeds what this transaction's size demands by "
                "9,000,000 photons, past the 120,546 allowed for sizing slack. "
                "Pass allow_overpay=True to accept it."
            )

        monkeypatch.setattr(glyph_cmds, "lib_build_ft_transfer", _refuse)
        ctx = dataclasses.replace(cli_context, output_mode="json", yes=True)

        with pytest.raises(UserError) as exc:
            asyncio.run(
                glyph_cmds._transfer_ft_inner(
                    ctx,
                    object(),
                    GlyphRef(txid="aa" * 32, vout=0),
                    250,
                    Hex20(bytes(20)),
                    "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
                    MagicMock(),
                )
            )
        rendered = str(exc.value) + str(getattr(exc.value, "fix", ""))
        assert "--allow-overpay" in rendered
        assert "plain RXD" not in rendered, "that is the remedy for the opposite problem"


class TestTerminalBroadcastsRaiseRatherThanWarn:
    """Three adversarial lanes independently flagged the same line: ``airdrop-ft``
    reported its txid through the mint-commit helper, which warns and carries on.

    The commit helper warns for a reason that is specific to a commit — there is a reveal
    still to come, and the caller needs the locally derived txid to build it. An airdrop
    is terminal. A warning on a non-tty run is no warning at all, and ``--json`` would
    have reported success for tokens that never moved, to the widest blast radius of the
    three paths: N recipients in one transaction.
    """

    TERMINAL = ("_transfer_ft_inner", "_airdrop_ft_inner", "_transfer_nft_inner")

    @staticmethod
    def _body(name: str) -> str:
        import ast
        import inspect

        from pyrxd.cli import glyph_cmds

        tree = ast.parse(inspect.getsource(glyph_cmds))
        for node in ast.walk(tree):
            if isinstance(node, ast.AsyncFunctionDef | ast.FunctionDef) and node.name == name:
                return ast.dump(node)
        raise AssertionError(f"{name} not found — rename it and this guard silently stops guarding")

    @pytest.mark.parametrize("fn", TERMINAL)
    def test_a_terminal_broadcast_verifies_its_txid_strictly(self, fn: str) -> None:
        body = self._body(fn)
        assert "_confirmed_txid" in body, f"{fn} must verify its broadcast txid by raising"
        assert "_local_commit_txid" not in body, (
            f"{fn} is terminal — the warn-and-continue commit helper is the wrong one here"
        )

    def test_the_commit_helper_is_still_used_where_a_phase_follows(self) -> None:
        """The counterpart: a commit legitimately warns, because the reveal still needs
        the derived txid whatever the server said."""
        import inspect

        from pyrxd.cli import glyph_cmds

        assert "_local_commit_txid" in inspect.getsource(glyph_cmds.__dict__["_deploy_dmint_inner"])


class TestTheCommitTxidHelperCannotStrandACommit:
    """``Transaction.from_hex`` returns ``None`` rather than raising, and this helper runs
    AFTER the broadcast. Letting that ``None`` reach ``.txid()`` raised ``AttributeError``
    between the broadcast and the line that prints the txid — so the commit was on chain
    and the user was never told its id. That is precisely the stranding the helper exists
    to prevent, reproduced inside the helper.
    """

    @pytest.mark.parametrize("unparseable", [b"", b"\x01\x02\x03", "zz"])
    def test_an_unparseable_commit_still_hands_back_the_echo(self, unparseable) -> None:
        from pyrxd.cli.errors import UserError
        from pyrxd.cli.glyph_cmds import _local_commit_txid

        echoed = "ab" * 32
        with pytest.raises(UserError) as exc:
            _local_commit_txid(unparseable, echoed)

        rendered = exc.value.format_message()
        assert echoed in rendered, "the echoed txid is the only handle left on a relayed commit"
        assert "explorer" in rendered
        # The advice must name a recovery that EXISTS. An earlier version sent the user to
        # a "PendingMint record still in the store"; this CLI has no PendingStore at all,
        # so that was fiction on a path where the commit is an unspendable hashlock unless
        # the reveal carries byte-identical CBOR. `_wait_for_tx` had this bug once and its
        # docstring calls it "the worst possible answer".
        assert "prepare_reveal" in rendered
        assert "store" not in rendered.lower(), "names a recovery this CLI does not have"

    def test_the_cli_really_has_no_pending_store_to_point_at(self) -> None:
        """The premise behind the assertion above, checked rather than assumed."""
        import ast

        import pyrxd.cli

        # `rglob`, not `pkgutil.iter_modules`: the latter never yields `__init__` and does
        # not descend into subpackages, so it would skip files silently. A guard with a
        # hole in its own enumeration is the defect it exists to catch.
        files = sorted(pathlib.Path(pyrxd.cli.__path__[0]).rglob("*.py"))
        assert len(files) > 1, "enumeration found almost nothing — this would pass vacuously"

        offenders = []
        for path in files:
            for node in ast.walk(ast.parse(path.read_text())):
                # An IMPORT, not the mere word — the comment explaining this very absence
                # says "PendingStore", and a substring check would trip over its own
                # explanation. Both import forms count: `import pyrxd.glyph.mint` followed
                # by `mint.JsonFilePendingStore(...)` would slip past an ImportFrom check.
                if isinstance(node, ast.ImportFrom) and any(a.name.endswith("PendingStore") for a in node.names):
                    offenders.append(path.name)
                if isinstance(node, ast.Import) and any(a.name.endswith("glyph.mint") for a in node.names):
                    offenders.append(path.name)
        assert not offenders, f"the CLI now reaches a PendingStore ({offenders}) — revisit the advice"


class TestALyingRevealEchoIsRefused:
    """The CLI hardened its COMMIT txid and left the REVEAL trusting the server.

    That asymmetry was easy to miss because the token's own ref is safe either way — it
    is the COMMIT outpoint, embedded in the reveal's locking script — so the most
    load-bearing identifier on the page never depended on the echo. What did depend on it
    was ``deploy-dmint``'s ``contracts`` list and ``premine_outpoint``: outpoints miners
    grind against and the owner later spends, minted straight from the server's reply.
    """

    @staticmethod
    def _client(captured: list[bytes], reveal_lie: str):
        async def _bcast(raw: bytes) -> str:
            from pyrxd.transaction.transaction import Transaction

            captured.append(raw)
            if len(captured) == 1:
                return Transaction.from_hex(raw.hex()).txid()
            return reveal_lie

        client = MagicMock()
        client.broadcast = _bcast
        client.get_transaction_verbose = AsyncMock(return_value={"confirmations": 1})
        return client

    def test_deploy_dmint_refuses_outpoints_built_on_a_lie(self, cli_context) -> None:
        from pyrxd.cli.errors import UserError
        from pyrxd.cli.glyph_cmds import _deploy_dmint_inner
        from pyrxd.glyph.builder import DmintV1DeployParams

        lie = "ee" * 32
        key = PrivateKey()
        utxo = UtxoRecord(tx_hash="ab" * 32, tx_pos=0, value=500_000_000, height=100)

        class _Wallet:
            async def collect_spendable(self, client):
                return [(utxo, key.address(), key)]

        captured: list[bytes] = []
        ctx = dataclasses.replace(cli_context, output_mode="json", yes=True)
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
            premine_amount=7_000_000,
        )

        with pytest.raises(UserError) as exc:
            asyncio.run(_deploy_dmint_inner(ctx, _Wallet(), params, self._client(captured, lie)))

        rendered = exc.value.format_message()
        # The user is pointed at the txid we derived, and told not to build on the echo.
        assert str(Transaction.from_hex(captured[1]).txid()) in rendered
        assert "do not use the echoed id" in rendered.lower()
        assert "explorer" in rendered


class TestDeployFtPinsItsTreasury:
    """``deploy-ft --treasury`` receives the ENTIRE premined supply and was the one
    destination in this CLI with no network pin.

    Every sibling has one — ``transfer-ft``, ``transfer-nft``, each airdrop recipient —
    each added after the same reasoning: ``address_to_public_key_hash`` decodes a testnet
    address into a valid-looking 20-byte PKH, so the deploy would have built, confirmed,
    and locked the whole supply to a script no mainnet key can spend. There is no refund
    path and no RBF. This path carries more value than any of the ones already pinned, and
    it was missed because nobody compared them side by side.
    """

    @staticmethod
    def _testnet_address() -> str:
        """``PublicKey.address()`` defaults to mainnet and does NOT read the key's own
        network field, so this must be passed explicitly or the test asserts nothing."""
        from pyrxd.constants import Network

        return PrivateKey().public_key().address(network=Network.TESTNET)

    def _invoke(self, runner: CliRunner, wallet: Path, tmp_path: Path, treasury: str):
        return runner.invoke(
            cli,
            [
                "--wallet",
                str(wallet),
                "glyph",
                "deploy-ft",
                str(_write_meta(tmp_path / "ft.json")),
                "--supply",
                "1000",
                "--treasury",
                treasury,
            ],
        )

    def test_a_testnet_treasury_is_refused_on_mainnet(
        self, runner: CliRunner, tmp_wallet_path: Path, tmp_path: Path
    ) -> None:
        runner.invoke(cli, _new_wallet_args(tmp_wallet_path))
        result = self._invoke(runner, tmp_wallet_path, tmp_path, self._testnet_address())
        assert result.exit_code != 0
        assert "not a valid mainnet radiant p2pkh address" in result.output.lower()

    def test_a_mainnet_treasury_gets_past_the_pin(
        self, runner: CliRunner, tmp_wallet_path: Path, tmp_path: Path
    ) -> None:
        """The other half: the guard must not refuse the address it exists to accept.

        This stops before any broadcast — it only has to get past the pin, so whatever it
        fails on later, it must not be the address.
        """
        runner.invoke(cli, _new_wallet_args(tmp_wallet_path))
        result = self._invoke(runner, tmp_wallet_path, tmp_path, PrivateKey().public_key().address())
        assert "not a valid mainnet radiant p2pkh address" not in result.output.lower()


class TestThePinWorksOnEveryNetworkTheCliAccepts:
    """``Network(ctx.network)`` raised a bare ``ValueError`` on regtest.

    ``Network`` has only MAINNET and TESTNET; ``--network`` also accepts ``regtest``. So
    every pinned command died with an unhandled traceback on the one network the project's
    own developer onramp (``pyrxd regtest``) is built around — a guard refusing the
    workflow shipped to newcomers. Regtest addresses carry testnet's version byte, so
    that is what they are pinned against.
    """

    @staticmethod
    def _addr(network: str) -> str:
        from pyrxd.constants import Network

        if network == "mainnet":
            return PrivateKey().public_key().address()
        return PrivateKey().public_key().address(network=Network.TESTNET)

    @pytest.mark.parametrize("network", ["mainnet", "testnet", "regtest"])
    def test_a_matching_address_is_accepted(
        self, runner: CliRunner, tmp_wallet_path: Path, tmp_path: Path, network: str
    ) -> None:
        runner.invoke(cli, _new_wallet_args(tmp_wallet_path))
        result = runner.invoke(
            cli,
            [
                "--wallet",
                str(tmp_wallet_path),
                "--network",
                network,
                "glyph",
                "deploy-ft",
                str(_write_meta(tmp_path / "ft.json")),
                "--supply",
                "1000",
                "--treasury",
                self._addr(network),
            ],
        )
        # CliRunner puts an unhandled exception in `result.exception`, NOT in `output`, so
        # asserting on the text alone passed even while the command was crashing. Check the
        # exception itself, or this pins nothing.
        assert not isinstance(result.exception, ValueError), f"the pin crashed: {result.exception}"
        assert "p2pkh address" not in result.output.lower(), f"a legitimate {network} address was refused on {network}"

    @pytest.mark.parametrize("network", ["mainnet", "testnet", "regtest"])
    def test_a_foreign_address_is_still_refused(
        self, runner: CliRunner, tmp_wallet_path: Path, tmp_path: Path, network: str
    ) -> None:
        """The guard must keep guarding on every network, not just stop crashing."""
        foreign = self._addr("testnet" if network == "mainnet" else "mainnet")
        runner.invoke(cli, _new_wallet_args(tmp_wallet_path))
        result = runner.invoke(
            cli,
            [
                "--wallet",
                str(tmp_wallet_path),
                "--network",
                network,
                "glyph",
                "deploy-ft",
                str(_write_meta(tmp_path / "ft.json")),
                "--supply",
                "1000",
                "--treasury",
                foreign,
            ],
        )
        assert result.exit_code != 0
        assert "p2pkh address" in result.output.lower()


class TestTheCliWaitPollsAtAnIntervalItChose:
    """`_wait_for_tx` is the CLI's own confirmation wait, and it was the FOURTH sibling
    missed in this cycle.

    `GlyphMinter._reveal` has two `wait_for_confirmation` calls and both were given an
    `interval_s`. This one — serving `mint-nft`, `deploy-ft` and `deploy-dmint` — was not,
    so the CLI mint paths still slept the 10s default with no way to change it. That is
    precisely the regtest caller the new `poll_interval_s` docstring names, and the
    quickstart the project ships targets regtest.

    The lesson, four for four now: when a call is duplicated, grep for every site before
    calling the fix done. An anchor written against one of them will silently miss the rest.
    """

    def test_every_mint_command_passes_an_interval(self) -> None:
        """Structural, and deliberately so — it is the check that would have caught this.

        A behavioural test on one command proves that command; this proves there is no
        fifth sibling hiding behind a default.
        """
        import ast
        import inspect

        from pyrxd.cli import glyph_cmds

        tree = ast.parse(inspect.getsource(glyph_cmds))
        calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and getattr(n.func, "id", "") == "_wait_for_tx"]
        assert len(calls) >= 3, f"expected the three mint commands, found {len(calls)}"
        missing = [c.lineno for c in calls if not any(k.arg == "interval_s" for k in c.keywords)]
        assert not missing, f"_wait_for_tx called without interval_s at lines {missing}"

    @pytest.mark.parametrize("network, expected", [("mainnet", 10.0), ("testnet", 10.0), ("regtest", 0.25)])
    def test_the_interval_is_derived_from_the_network(self, network: str, expected: float) -> None:
        from pyrxd.cli.config import Config
        from pyrxd.cli.context import CliContext
        from pyrxd.cli.glyph_cmds import _poll_interval_for

        assert _poll_interval_for(CliContext(config=Config(), network=network)) == expected

    def test_the_wrapper_forwards_what_it_was_given(self) -> None:
        """The value has to survive the wrapper, not just be computed."""
        import asyncio

        import pyrxd.cli.glyph_cmds as gc

        seen: list[float | None] = []
        real = gc.wait_for_confirmation

        async def _spy(*a, **kw):
            seen.append(kw.get("interval_s"))
            return 1

        gc.wait_for_confirmation = _spy
        try:
            asyncio.run(gc._wait_for_tx(MagicMock(), "ab" * 32, interval_s=0.125))
        finally:
            gc.wait_for_confirmation = real
        assert seen == [0.125], f"the wrapper dropped the interval: {seen}"
