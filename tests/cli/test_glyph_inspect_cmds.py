"""Tests for `pyrxd glyph inspect` — offline classifier subcommand.

Covers all four input forms (txid, contract id, outpoint, script hex), all
three output modes (human / json / quiet), and dispatch / validation errors.
Network-fetch path (`--fetch`) lands in PR-C and is intentionally absent.
"""

from __future__ import annotations

import json

from click.testing import CliRunner

from pyrxd.cli.main import cli
from pyrxd.glyph.dmint import DmintDeployParams, build_dmint_contract_script
from pyrxd.glyph.script import (
    build_commit_locking_script,
    build_ft_locking_script,
    build_mutable_nft_script,
    build_nft_locking_script,
)
from pyrxd.glyph.types import GlyphRef
from pyrxd.security.types import Hex20, Txid

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_KNOWN_TXID = "b" * 64
_KNOWN_REF = GlyphRef(txid=Txid(_KNOWN_TXID), vout=4)
_KNOWN_PKH_BYTES = bytes(range(20))
_KNOWN_PKH = Hex20(_KNOWN_PKH_BYTES)

# RBG-style real contract id (display order txid + BE vout=4).
_RBG_CONTRACT = "b45dc453befb589aff8bfd76af0b994615b37eda094f48c380eb31deaf96a2a800000004"
_RBG_TXID = "b45dc453befb589aff8bfd76af0b994615b37eda094f48c380eb31deaf96a2a8"


def _ft_script() -> bytes:
    return build_ft_locking_script(_KNOWN_PKH, _KNOWN_REF)


def _nft_script() -> bytes:
    return build_nft_locking_script(_KNOWN_PKH, _KNOWN_REF)


def _commit_nft_script() -> bytes:
    return build_commit_locking_script(bytes(range(32)), _KNOWN_PKH, is_nft=True)


def _commit_ft_script() -> bytes:
    return build_commit_locking_script(bytes(range(32)), _KNOWN_PKH, is_nft=False)


def _mutable_script() -> bytes:
    return build_mutable_nft_script(_KNOWN_REF, bytes(range(32)))


def _dmint_contract_script() -> bytes:
    params = DmintDeployParams(
        contract_ref=GlyphRef(txid="aa" * 32, vout=1),
        token_ref=GlyphRef(txid="bb" * 32, vout=0),
        max_height=1000,
        reward=100,
        difficulty=10,
    )
    return build_dmint_contract_script(params)


def _p2pkh_script() -> bytes:
    return b"\x76\xa9\x14" + bytes(range(20)) + b"\x88\xac"


# ---------------------------------------------------------------------------
# Dispatch — _classify_input via the CLI surface
# ---------------------------------------------------------------------------


class TestInspectDispatch:
    def test_64_hex_is_treated_as_txid(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["glyph", "inspect", "a" * 64])
        # txid form errors with "use --fetch" until PR-C lands.
        assert result.exit_code != 0
        assert "txid" in result.output.lower()
        assert "fetch" in result.output.lower()

    def test_72_hex_is_treated_as_contract(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["glyph", "inspect", _RBG_CONTRACT])
        assert result.exit_code == 0, result.output
        assert _RBG_TXID in result.output
        # Vout=4 (BE-decoded from "00000004").
        assert "vout:     4" in result.output

    def test_outpoint_with_colon(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["glyph", "inspect", "ab" * 32 + ":7"])
        assert result.exit_code == 0, result.output
        assert ":7" in result.output

    def test_script_hex(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["glyph", "inspect", _p2pkh_script().hex()])
        assert result.exit_code == 0, result.output
        assert "type: p2pkh" in result.output

    def test_empty_input_is_user_error(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["glyph", "inspect", ""])
        assert result.exit_code != 0

    def test_garbage_short_input(self, runner: CliRunner) -> None:
        # 10 chars, valid hex, but below script-min — neither txid nor contract.
        result = runner.invoke(cli, ["glyph", "inspect", "deadbeef00"])
        assert result.exit_code != 0
        assert "could not classify" in result.output.lower()

    def test_non_hex_garbage(self, runner: CliRunner) -> None:
        # 64 chars, but contains 'g' so not hex → falls through to "could not classify".
        result = runner.invoke(cli, ["glyph", "inspect", "g" * 64])
        assert result.exit_code != 0
        assert "could not classify" in result.output.lower()


# ---------------------------------------------------------------------------
# Contract id form
# ---------------------------------------------------------------------------


class TestInspectContract:
    def test_contract_id_human_decodes_real_world(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["glyph", "inspect", _RBG_CONTRACT])
        assert result.exit_code == 0
        assert _RBG_TXID in result.output
        assert "Wire form" in result.output  # surfaces both display + wire forms

    def test_contract_id_json(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["--json", "--yes", "glyph", "inspect", _RBG_CONTRACT])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["form"] == "contract"
        assert payload["txid"] == _RBG_TXID
        assert payload["vout"] == 4
        assert payload["outpoint"] == f"{_RBG_TXID}:4"
        # Wire hex must be 36 bytes / 72 chars and end in vout LE = 04 00 00 00.
        assert len(payload["wire_hex"]) == 72
        assert payload["wire_hex"].endswith("04000000")

    def test_contract_id_invalid_length_user_error(self, runner: CliRunner) -> None:
        # 70-char hex — valid hex, but neither 64 (txid) nor 72 (contract) nor
        # >=script-min as an even number that isn't a meaningful script — falls
        # through script-form path because length is in [50, 20000].
        # So this becomes a "script" form test rather than a contract-form test;
        # use a dedicated contract validator entry.
        # We exercise contract validation by giving 72 chars of valid-shape hex
        # but with broken content downstream — handled by from_contract_hex.
        # Instead, test that 72 non-hex chars fail at dispatch.
        result = runner.invoke(cli, ["glyph", "inspect", "z" * 72])
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# Outpoint form
# ---------------------------------------------------------------------------


class TestInspectOutpoint:
    def test_outpoint_human(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["glyph", "inspect", "cd" * 32 + ":9"])
        assert result.exit_code == 0
        assert "vout:     9" in result.output
        assert "Wire form" in result.output

    def test_outpoint_json(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["--json", "--yes", "glyph", "inspect", "ef" * 32 + ":42"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["form"] == "outpoint"
        assert payload["txid"] == "ef" * 32
        assert payload["vout"] == 42

    def test_outpoint_quiet_returns_canonical_outpoint(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["--quiet", "glyph", "inspect", "ab" * 32 + ":3"])
        assert result.exit_code == 0
        assert result.output.strip() == ("ab" * 32) + ":3"

    def test_outpoint_too_many_colons(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["glyph", "inspect", "ab" * 32 + ":3:4"])
        assert result.exit_code != 0

    def test_outpoint_non_int_vout(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["glyph", "inspect", "ab" * 32 + ":notavout"])
        assert result.exit_code != 0
        assert "vout" in result.output.lower()

    def test_outpoint_bad_txid_length(self, runner: CliRunner) -> None:
        # 31-byte txid (62 chars) — Txid validates length.
        result = runner.invoke(cli, ["glyph", "inspect", "ab" * 31 + ":0"])
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# Script-hex form
# ---------------------------------------------------------------------------


class TestInspectScriptHex:
    def test_classifies_p2pkh(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["glyph", "inspect", _p2pkh_script().hex()])
        assert result.exit_code == 0
        assert "type: p2pkh" in result.output
        assert "owner_pkh" in result.output

    def test_classifies_nft(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["glyph", "inspect", _nft_script().hex()])
        assert result.exit_code == 0
        assert "type: nft" in result.output
        assert f"{_KNOWN_TXID}:4" in result.output

    def test_classifies_ft(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["glyph", "inspect", _ft_script().hex()])
        assert result.exit_code == 0
        assert "type: ft" in result.output

    def test_classifies_mutable(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["glyph", "inspect", _mutable_script().hex()])
        assert result.exit_code == 0
        assert "type: mut" in result.output
        assert "payload_hash" in result.output

    def test_classifies_commit_nft(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["glyph", "inspect", _commit_nft_script().hex()])
        assert result.exit_code == 0
        assert "type: commit-nft" in result.output

    def test_classifies_commit_ft_distinctly(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["glyph", "inspect", _commit_ft_script().hex()])
        assert result.exit_code == 0
        assert "type: commit-ft" in result.output

    def test_classifies_dmint_contract(self, runner: CliRunner) -> None:
        """The headline diagnostic — dMint contracts must be distinguishable."""
        result = runner.invoke(cli, ["glyph", "inspect", _dmint_contract_script().hex()])
        assert result.exit_code == 0
        assert "type: dmint" in result.output
        assert "contract_ref" in result.output
        assert "token_ref" in result.output
        assert "height" in result.output

    def test_unknown_script_does_not_crash(self, runner: CliRunner) -> None:
        # 50 hex chars (25 bytes) of garbage that isn't P2PKH or any glyph form.
        result = runner.invoke(cli, ["glyph", "inspect", "de" * 25])
        assert result.exit_code == 0
        assert "type: unknown" in result.output

    def test_invalid_hex_user_error(self, runner: CliRunner) -> None:
        # Even-length string that's in the script-len range but not valid hex.
        # Length 60, contains 'z' — falls through dispatch as garbage.
        result = runner.invoke(cli, ["glyph", "inspect", "zz" * 30])
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# Output modes
# ---------------------------------------------------------------------------


class TestInspectOutputModes:
    def test_json_emits_valid_object_for_script(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["--json", "--yes", "glyph", "inspect", _ft_script().hex()])
        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert payload["form"] == "script"
        assert payload["type"] == "ft"
        assert payload["ref_outpoint"] == f"{_KNOWN_TXID}:4"
        assert payload["owner_pkh"] == _KNOWN_PKH_BYTES.hex()

    def test_json_works_without_yes_for_inspect(self, runner: CliRunner) -> None:
        """`inspect` is read-only — `--json` must NOT require `--yes`."""
        result = runner.invoke(cli, ["--json", "glyph", "inspect", _ft_script().hex()])
        # inspect doesn't broadcast, so the destructive-mode-safe gate doesn't apply
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["type"] == "ft"

    def test_quiet_script_returns_type(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["--quiet", "glyph", "inspect", _ft_script().hex()])
        assert result.exit_code == 0
        assert result.output.strip() == "ft"

    def test_quiet_contract_returns_outpoint(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["--quiet", "glyph", "inspect", _RBG_CONTRACT])
        assert result.exit_code == 0
        assert result.output.strip() == f"{_RBG_TXID}:4"
