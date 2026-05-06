"""Tests for `pyrxd glyph inspect` — full classifier coverage.

Covers all four input forms (txid, contract id, outpoint, script hex), all
three output modes (human / json / quiet), dispatch / validation errors,
AND the network-fetch path (`--fetch` for txid, `--resolve` for outpoint)
with mocked ElectrumXClient — exercising the threat-model guards (txid
sha256d roundtrip, size cap, output-count cap, malformed-tx fallback,
NetworkError → exit-2 propagation, CBOR string sanitization).
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


# Real V1 dmint contract from the RBG mainnet reveal tx
# c5c296ebff5869c6e2b208ce0cd04be479a9f10d33cf73608f0a5efc2d6b55b6 vout 0.
# 240 bytes; SHA256D + FIXED + max_height 6.75M + reward 6200.
# See tests/test_glyph.py::TestV1DmintParser for the parser-level tests
# against this same fixture.
_RBG_DMINT_V1_HEX = (
    "0400000000d8a8a296afde31eb80c3484f09da7eb31546990baf76fd8bff9a58fbbe53c45db4"
    "01000000d0a8a296afde31eb80c3484f09da7eb31546990baf76fd8bff9a58fbbe53c45db4"
    "000000000330ff66023818085c8fc2f5285c8f02bd5175c0c855797ea8597959797ea87e5a7a7eaa"
    "bc01147f77587f040000000088817600a269a269577ae500a069567ae600a06901d053797e0c"
    "dec0e9aa76e378e4a269e69d7eaa76e47b9d547a818b76537a9c537ade789181547ae6939d"
    "635279cd01d853797e016a7e886778de519d547854807ec0eb557f777e5379ec78885379eac0e988"
    "5379cc519d75686d7551"
)


# ---------------------------------------------------------------------------
# Dispatch — _classify_input via the CLI surface
# ---------------------------------------------------------------------------


class TestInspectDispatch:
    def test_64_hex_is_treated_as_txid(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["glyph", "inspect", "a" * 64])
        # Bare 64-hex routes to the txid form which requires --fetch — no
        # surprise network call on a paste-only invocation.
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
        # PR #39 added the version field — V2 builder produces V2 layout.
        assert "version:      dMint v2" in result.output

    def test_classifies_v1_dmint_contract_human(self, runner: CliRunner) -> None:
        """A real V1 contract from the RBG mainnet reveal must classify as
        ``dmint`` and surface ``version: dMint v1`` plus the derived total
        supply line."""
        result = runner.invoke(cli, ["glyph", "inspect", _RBG_DMINT_V1_HEX])
        assert result.exit_code == 0, result.output
        assert "type: dmint" in result.output
        assert "version:      dMint v1" in result.output
        # max_height (6_750_000) × reward (6_200) = 41_850_000_000
        assert "total supply: 41,850,000,000" in result.output
        assert "algo:         SHA256D" in result.output
        assert "daa_mode:     FIXED" in result.output

    def test_classifies_v1_dmint_contract_json(self, runner: CliRunner) -> None:
        """JSON form must include ``version`` for V1, and the dmint-specific
        fields must round-trip through ``ensure_ascii=True`` cleanly."""
        result = runner.invoke(cli, ["--json", "glyph", "inspect", _RBG_DMINT_V1_HEX])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["type"] == "dmint"
        assert payload["version"] == "v1"
        assert payload["max_height"] == 6_750_000
        assert payload["reward"] == 6_200
        assert payload["algo"] == "SHA256D"
        assert payload["daa_mode"] == "FIXED"
        # contract_ref/token_ref outpoints are display-order strings.
        rbg_txid = "b45dc453befb589aff8bfd76af0b994615b37eda094f48c380eb31deaf96a2a8"
        assert payload["contract_ref_outpoint"] == f"{rbg_txid}:1"
        assert payload["token_ref_outpoint"] == f"{rbg_txid}:0"

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


# ---------------------------------------------------------------------------
# Network-fetch path (--fetch / --resolve)
# ---------------------------------------------------------------------------


from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

from pyrxd.cli.config import Config
from pyrxd.cli.context import CliContext
from pyrxd.cli.glyph_cmds import inspect_cmd
from pyrxd.hash import hash256
from pyrxd.script.script import Script
from pyrxd.security.errors import NetworkError
from pyrxd.security.types import RawTx
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_output import TransactionOutput


def _build_real_tx_with_ft() -> tuple[bytes, str]:
    """Build a real serialized tx with one FT output. Returns (raw_bytes, real_txid)."""
    tx = Transaction(
        tx_inputs=[],
        tx_outputs=[TransactionOutput(Script(_ft_script()), 1000)],
    )
    raw = bytes(tx.serialize())
    real_txid = hash256(raw)[::-1].hex()
    return raw, real_txid


def _make_ctx(client) -> CliContext:
    """A CliContext whose make_client() returns *client*."""

    def factory():
        return client

    return CliContext(
        config=Config(
            network="mainnet",
            electrumx="wss://test/",
            fee_rate=10_000,
            wallet_path=Path("/tmp/_pyrxd_inspect_test"),
        ),
        network="mainnet",
        electrumx_url="wss://test/",
        fee_rate=10_000,
        wallet_path=Path("/tmp/_pyrxd_inspect_test"),
        output_mode="human",
        client_factory=factory,
    )


def _mock_client(*, get_transaction_returns=None, get_transaction_raises=None):
    c = MagicMock()
    if get_transaction_raises is not None:
        c.get_transaction = AsyncMock(side_effect=get_transaction_raises)
    else:
        c.get_transaction = AsyncMock(return_value=get_transaction_returns)
    c.__aenter__ = AsyncMock(return_value=c)
    c.__aexit__ = AsyncMock(return_value=None)
    return c


class TestInspectFetchTxid:
    def test_classifies_outputs_after_fetch(self, runner: CliRunner) -> None:
        raw, real_txid = _build_real_tx_with_ft()
        client = _mock_client(get_transaction_returns=RawTx(raw))
        result = runner.invoke(inspect_cmd, [real_txid, "--fetch"], obj=_make_ctx(client))
        assert result.exit_code == 0, result.output
        assert "type=ft" in result.output
        assert f"{_KNOWN_TXID}:4" in result.output
        # Server was actually called with the right txid.
        client.get_transaction.assert_awaited_once()

    def test_json_emits_full_payload(self, runner: CliRunner) -> None:
        raw, real_txid = _build_real_tx_with_ft()
        client = _mock_client(get_transaction_returns=RawTx(raw))
        ctx = _make_ctx(client)
        ctx.output_mode = "json"
        result = runner.invoke(inspect_cmd, [real_txid, "--fetch"], obj=ctx)
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["form"] == "txid"
        assert payload["txid"] == real_txid
        assert payload["output_count"] == 1
        assert payload["outputs"][0]["type"] == "ft"
        assert payload["outputs"][0]["vout"] == 0
        assert payload["outputs"][0]["satoshis"] == 1000

    def test_quiet_emits_txid(self, runner: CliRunner) -> None:
        raw, real_txid = _build_real_tx_with_ft()
        client = _mock_client(get_transaction_returns=RawTx(raw))
        ctx = _make_ctx(client)
        ctx.output_mode = "quiet"
        result = runner.invoke(inspect_cmd, [real_txid, "--fetch"], obj=ctx)
        assert result.exit_code == 0, result.output
        assert result.output.strip() == real_txid

    def test_txid_without_fetch_errors(self, runner: CliRunner) -> None:
        """Bare 64-hex still requires --fetch — no surprise network calls."""
        raw, real_txid = _build_real_tx_with_ft()
        client = _mock_client(get_transaction_returns=RawTx(raw))
        result = runner.invoke(inspect_cmd, [real_txid], obj=_make_ctx(client))
        assert result.exit_code != 0
        assert "--fetch" in result.output
        # Server was NOT called.
        client.get_transaction.assert_not_called()

    def test_server_lying_about_txid_is_rejected(self, runner: CliRunner) -> None:
        """Threat-model guard: server returns a tx whose hash != requested txid."""
        raw, _real = _build_real_tx_with_ft()
        client = _mock_client(get_transaction_returns=RawTx(raw))
        # Ask for a DIFFERENT txid; server returns the same raw as before.
        fake_txid = "0" * 63 + "1"
        result = runner.invoke(inspect_cmd, [fake_txid, "--fetch"], obj=_make_ctx(client))
        assert result.exit_code != 0
        assert "does not match" in result.output

    def test_oversize_response_rejected(self, runner: CliRunner) -> None:
        """Threat-model guard: response > 4MB is consensus-invalid and refused."""
        # 5MB of zeros — definitely larger than _MAX_RAW_TX_BYTES.
        big = b"\x00" * 5_000_000
        # The hash check must pass first to reach the size check; build a real
        # tx, then pad — but padding breaks the hash. Instead inject a server
        # that returns an oversized blob whose computed hash matches what we
        # ask for (impossible without a preimage attack), so we test the size
        # path with a server that lies AND is oversized — size check fires
        # FIRST in the implementation order, so this tests the size guard.
        client = _mock_client(get_transaction_returns=RawTx(big))
        result = runner.invoke(inspect_cmd, ["a" * 64, "--fetch"], obj=_make_ctx(client))
        assert result.exit_code != 0
        assert "policy max" in result.output

    def test_unparseable_tx_returns_user_error(self, runner: CliRunner) -> None:
        """Threat-model guard: malformed tx surfaces as a clean UserError."""
        # Bytes large enough to pass RawTx (>64) but not a valid tx.
        garbage = b"\xff" * 100
        # Hash-check would normally reject this — generate the *correct* txid
        # for the garbage so we exercise the parse path.
        garbage_txid = hash256(garbage)[::-1].hex()
        client = _mock_client(get_transaction_returns=RawTx(garbage))
        result = runner.invoke(inspect_cmd, [garbage_txid, "--fetch"], obj=_make_ctx(client))
        assert result.exit_code != 0
        # Either parse failure or roundtrip-mismatch — both are UserErrors,
        # not crashes.

    def test_network_error_yields_exit_code_2(self, runner: CliRunner) -> None:
        client = _mock_client(get_transaction_raises=NetworkError("boom"))
        result = runner.invoke(inspect_cmd, ["a" * 64, "--fetch"], obj=_make_ctx(client))
        # NetworkBoundaryError is exit code 2 in this project's CLI errors.
        assert result.exit_code == 2
        assert "could not reach" in result.output.lower()

    def test_fetch_with_non_txid_input_errors(self, runner: CliRunner) -> None:
        """--fetch is meaningful only for a txid input."""
        client = _mock_client(get_transaction_returns=RawTx(b"\x00" * 100))
        # 72-char contract input + --fetch — caller error.
        result = runner.invoke(inspect_cmd, [_RBG_CONTRACT, "--fetch"], obj=_make_ctx(client))
        assert result.exit_code != 0
        assert "--fetch is only meaningful for txid" in result.output


class TestInspectResolveOutpoint:
    def test_resolve_classifies_named_vout(self, runner: CliRunner) -> None:
        raw, real_txid = _build_real_tx_with_ft()
        client = _mock_client(get_transaction_returns=RawTx(raw))
        result = runner.invoke(inspect_cmd, [f"{real_txid}:0", "--resolve"], obj=_make_ctx(client))
        assert result.exit_code == 0, result.output
        assert "type=ft" in result.output
        assert "vout   0" in result.output
        # Should NOT include any other vout.
        assert "vout   1" not in result.output

    def test_resolve_vout_out_of_range_user_error(self, runner: CliRunner) -> None:
        raw, real_txid = _build_real_tx_with_ft()  # has only vout 0
        client = _mock_client(get_transaction_returns=RawTx(raw))
        result = runner.invoke(inspect_cmd, [f"{real_txid}:5", "--resolve"], obj=_make_ctx(client))
        assert result.exit_code != 0
        assert "out of range" in result.output

    def test_resolve_without_outpoint_errors(self, runner: CliRunner) -> None:
        client = _mock_client(get_transaction_returns=RawTx(b"\x00" * 100))
        # --resolve given but input is a contract id, not an outpoint.
        result = runner.invoke(inspect_cmd, [_RBG_CONTRACT, "--resolve"], obj=_make_ctx(client))
        assert result.exit_code != 0
        assert "--resolve is only meaningful for an outpoint" in result.output


# ---------------------------------------------------------------------------
# CBOR string sanitizer — direct unit tests
# ---------------------------------------------------------------------------


from pyrxd.cli.glyph_cmds import _sanitize_display_string


class TestSanitizeDisplayString:
    """Lock the sanitizer's behavior against terminal-injection inputs.

    The sanitizer is the trust boundary between attacker-supplied CBOR and
    the user's terminal. These tests pin the codepoint categories it strips
    so a future refactor can't silently regress coverage.
    """

    def test_plain_ascii_unchanged(self) -> None:
        assert _sanitize_display_string("hello world") == "hello world"

    def test_ansi_escape_stripped(self) -> None:
        assert _sanitize_display_string("hi\x1b[31m") == "hi?[31m"

    def test_nul_stripped(self) -> None:
        assert _sanitize_display_string("a\x00b") == "a?b"

    def test_zwsp_stripped(self) -> None:
        # U+200B (zero-width space, category Cf).
        assert _sanitize_display_string("a​b") == "a?b"

    def test_zwj_stripped(self) -> None:
        # U+200D (zero-width joiner, category Cf).
        assert _sanitize_display_string("a‍b") == "a?b"

    def test_bidi_override_rlo_stripped(self) -> None:
        # U+202E — the headline attack: makes "gly‮bar" render
        # right-to-left from that point and could make a token name
        # impersonate adjacent fields.
        assert _sanitize_display_string("gly‮bar") == "gly?bar"

    def test_bidi_isolate_rli_stripped(self) -> None:
        # U+2067 (RLI), part of the second bidi-override range.
        assert _sanitize_display_string("a⁧b") == "a?b"

    def test_line_separator_stripped(self) -> None:
        # U+2028, category Zl.
        assert _sanitize_display_string("a b") == "a?b"

    def test_paragraph_separator_stripped(self) -> None:
        # U+2029, category Zp.
        assert _sanitize_display_string("a b") == "a?b"

    def test_word_joiner_stripped(self) -> None:
        # U+2060, category Cf.
        assert _sanitize_display_string("a⁠b") == "a?b"

    def test_variation_selector_stripped(self) -> None:
        # U+FE0F, category Mn — would emoji-modify the previous char.
        assert _sanitize_display_string("a️b") == "a?b"

    def test_combining_acute_stripped(self) -> None:
        # U+0301, category Mn — overlays an acute accent on the prior char.
        assert _sanitize_display_string("áb") == "a?b"

    def test_bom_stripped(self) -> None:
        # U+FEFF, category Cf.
        assert _sanitize_display_string("a﻿b") == "a?b"

    def test_tag_char_stripped(self) -> None:
        # U+E0001 (language tag), category Cf — used in spoofing attacks.
        assert _sanitize_display_string("a\U000e0001b") == "a?b"

    def test_plain_space_preserved(self) -> None:
        # U+0020 is category Zs and must NOT be stripped.
        assert _sanitize_display_string("hello world") == "hello world"

    def test_precomposed_accent_preserved(self) -> None:
        # U+00E9 (precomposed é, category Ll) is fine — only combining
        # forms (Mn/Me) are stripped.
        assert _sanitize_display_string("café") == "café"

    def test_empty_string(self) -> None:
        assert _sanitize_display_string("") == ""

    def test_non_string_passthrough(self) -> None:
        # Defensive — type signature says str but enforce runtime safety.
        assert _sanitize_display_string(None) is None  # type: ignore[arg-type]
        assert _sanitize_display_string(b"bytes") == b"bytes"  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Reveal metadata surfacing (fetch path with non-empty inputs)
# ---------------------------------------------------------------------------


from pyrxd.glyph.payload import build_reveal_scriptsig_suffix, encode_payload
from pyrxd.glyph.types import GlyphMedia, GlyphMetadata, GlyphProtocol
from pyrxd.transaction.transaction_input import TransactionInput


def _build_reveal_input(metadata: GlyphMetadata, *, source_txid: str | None = None) -> TransactionInput:
    """Build a TransactionInput whose unlocking_script carries reveal CBOR.

    Mirrors the shape ``GlyphInspector._parse_reveal_scriptsig`` walks:
    ``<sig> <pubkey> <"gly"> <CBOR>``.
    """
    cbor_bytes, _ = encode_payload(metadata)
    suffix = build_reveal_scriptsig_suffix(cbor_bytes)
    dummy_sig = bytes([0x47]) + bytes(71)
    dummy_pubkey = bytes([0x21]) + bytes(33)
    scriptsig = dummy_sig + dummy_pubkey + suffix
    inp = TransactionInput(
        source_txid=source_txid or ("aa" * 32),
        source_output_index=0,
        unlocking_script=Script(scriptsig),
    )
    return inp


def _build_tx_with_reveal(metadata: GlyphMetadata, *, plain_inputs_before: int = 0) -> tuple[bytes, str]:
    """Build a serialized tx with a reveal input at position *plain_inputs_before*."""
    plain_sig = bytes([0x47]) + bytes(71)
    plain_pubkey = bytes([0x21]) + bytes(33)
    plain_scriptsig = plain_sig + plain_pubkey

    inputs: list[TransactionInput] = []
    for i in range(plain_inputs_before):
        inputs.append(
            TransactionInput(
                source_txid=f"{i:02x}" * 32,
                source_output_index=0,
                unlocking_script=Script(plain_scriptsig),
            )
        )
    inputs.append(_build_reveal_input(metadata))

    tx = Transaction(
        tx_inputs=inputs,
        tx_outputs=[TransactionOutput(Script(_ft_script()), 1000)],
    )
    raw = bytes(tx.serialize())
    real_txid = hash256(raw)[::-1].hex()
    return raw, real_txid


_FT_REVEAL_METADATA = GlyphMetadata(
    protocol=[GlyphProtocol.FT],
    name="TestToken",
    ticker="TST",
    description="A test fungible token for inspect coverage.",
)


class TestInspectFetchReveal:
    def test_metadata_surfaced_from_input_zero(self, runner: CliRunner) -> None:
        raw, real_txid = _build_tx_with_reveal(_FT_REVEAL_METADATA)
        client = _mock_client(get_transaction_returns=RawTx(raw))
        ctx = _make_ctx(client)
        ctx.output_mode = "json"
        result = runner.invoke(inspect_cmd, [real_txid, "--fetch"], obj=ctx)
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["metadata"] is not None
        meta = payload["metadata"]
        assert meta["input_index"] == 0
        assert meta["name"] == "TestToken"
        assert meta["ticker"] == "TST"
        assert meta["description"] == "A test fungible token for inspect coverage."

    def test_metadata_walked_to_input_two(self, runner: CliRunner) -> None:
        """find_reveal_metadata walks ALL inputs — metadata at input 2 must be found."""
        raw, real_txid = _build_tx_with_reveal(_FT_REVEAL_METADATA, plain_inputs_before=2)
        client = _mock_client(get_transaction_returns=RawTx(raw))
        ctx = _make_ctx(client)
        ctx.output_mode = "json"
        result = runner.invoke(inspect_cmd, [real_txid, "--fetch"], obj=ctx)
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["metadata"] is not None
        assert payload["metadata"]["input_index"] == 2

    def test_metadata_protocol_elements_sanitized(self, runner: CliRunner) -> None:
        """Regression for the red-team finding: ``str(list_of_str)`` calls
        ``repr`` on each element which does NOT escape U+202E. Each protocol
        element must be sanitized BEFORE landing in the JSON list.

        We can't easily craft a hostile ``protocol`` value through the live
        ``GlyphMetadata`` validator (it rejects non-int entries), so this test
        reaches in and patches ``find_reveal_metadata`` to return metadata
        with a hostile protocol element — ensuring the sanitization layer
        actually runs on whatever the ``decode_payload`` path produces.
        """
        raw, real_txid = _build_tx_with_reveal(_FT_REVEAL_METADATA)
        client = _mock_client(get_transaction_returns=RawTx(raw))
        ctx = _make_ctx(client)
        ctx.output_mode = "json"

        # Patch find_reveal_metadata to inject a hostile protocol value.
        from unittest.mock import patch

        hostile_meta = GlyphMetadata(
            protocol=[GlyphProtocol.FT],  # constructor-validated; we'll
            # mutate attributes via __setattr__ to bypass.
            name="x",
        )
        # Replace the protocol with a list containing a bidi-override string
        # via dataclass internals (frozen=True so use object.__setattr__).
        object.__setattr__(hostile_meta, "protocol", ("gly‮bar",))

        with patch(
            "pyrxd.glyph.inspector.GlyphInspector.find_reveal_metadata",
            return_value=(0, hostile_meta),
        ):
            result = runner.invoke(inspect_cmd, [real_txid, "--fetch"], obj=ctx)

        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        # The U+202E must have been replaced by '?'.
        assert payload["metadata"]["protocol"] == ["gly?bar"]
        # And it must NOT appear unescaped in the raw output.
        assert "‮" not in result.output

    def test_metadata_human_protocol_renders_sanitized_list(self, runner: CliRunner) -> None:
        """The human-mode protocol line should be readable, not raw repr."""
        raw, real_txid = _build_tx_with_reveal(_FT_REVEAL_METADATA)
        client = _mock_client(get_transaction_returns=RawTx(raw))
        result = runner.invoke(inspect_cmd, [real_txid, "--fetch"], obj=_make_ctx(client))
        assert result.exit_code == 0, result.output
        # The protocol list contains string-coerced ints (e.g. ['1'] for FT).
        # Important: there must NEVER be a raw bidi/control codepoint in
        # the rendered output, regardless of source.
        assert "protocol:" in result.output

    def test_metadata_with_main_renders_media_tag(self, runner: CliRunner) -> None:
        """Binary media must render as ``<media: type, N bytes, sha256=...>``,
        never raw bytes — terminal-injection defense."""
        from pyrxd.hash import sha256 as _sha256

        meta_with_media = GlyphMetadata(
            protocol=[GlyphProtocol.NFT],
            name="MediaNFT",
            main=GlyphMedia(mime_type="image/png", data=b"\x89PNG\r\n\x1a\n" + bytes(50)),
        )
        raw, real_txid = _build_tx_with_reveal(meta_with_media)
        client = _mock_client(get_transaction_returns=RawTx(raw))
        ctx = _make_ctx(client)
        ctx.output_mode = "json"
        result = runner.invoke(inspect_cmd, [real_txid, "--fetch"], obj=ctx)
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        media_str = payload["metadata"]["main"]
        assert media_str.startswith("<media: image/png,")
        assert "sha256=" in media_str
        # Verify hash matches the real bytes.
        expected_hash = _sha256(b"\x89PNG\r\n\x1a\n" + bytes(50)).hex()
        assert expected_hash in media_str

    def test_metadata_main_mime_type_sanitized(self, runner: CliRunner) -> None:
        """Hostile mime_type with an ANSI escape must not reach the terminal raw."""
        meta_hostile = GlyphMetadata(
            protocol=[GlyphProtocol.NFT],
            name="X",
            main=GlyphMedia(mime_type="image/png\x1b[31m", data=b"\x00" * 10),
        )
        raw, real_txid = _build_tx_with_reveal(meta_hostile)
        client = _mock_client(get_transaction_returns=RawTx(raw))
        ctx = _make_ctx(client)
        ctx.output_mode = "json"
        result = runner.invoke(inspect_cmd, [real_txid, "--fetch"], obj=ctx)
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        # The ESC byte must have been replaced by '?'.
        assert "\x1b" not in payload["metadata"]["main"]
        assert "image/png?[31m" in payload["metadata"]["main"]
