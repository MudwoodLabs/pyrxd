"""Tests for the read-only ``pyrxd swap status`` CLI verb (no network in the offline path)."""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from pyrxd.cli.main import cli
from pyrxd.cli.swap_cmds import classify_covenant, electrumx_script_hash, parse_recovery_file
from pyrxd.network.electrumx import script_hash_for_address
from pyrxd.script import P2PKH

# A fake P2PKH-ish covenant SPK (the parser/classifier are SPK-agnostic) and a recognizable secret
# we assert is NEVER echoed.
_COV_SPK = "76a914" + "11" * 20 + "88ac"
_SECRET = "THIS_IS_A_SECRET_WIF_DO_NOT_PRINT"


def _btc_file(tmp_path):
    p = tmp_path / ".gravity_dust_run_keys.json"
    p.write_text(
        json.dumps(
            {
                "stage": "dust",
                "btc_network": "bc",
                "rxd_network": "bc",
                "hashlock_H": "ab" * 32,
                "preimage_p_hex": "cd" * 32,
                "taker_rxd_wif": _SECRET,
                "rxd_covenant_spk": _COV_SPK,
                "t_btc_blocks": 30,
                "t_rxd_blocks": 20,
                "btc_htlc_address": "bc1qexample",
            }
        )
    )
    return p


def _eth_file(tmp_path):
    p = tmp_path / ".eth_swap_run_keys.json"
    p.write_text(
        json.dumps(
            {
                "stage": "sepolia-dust",
                "eth_chain": "sepolia",
                "rxd_network": "bc",
                "hashlock_H": "ef" * 32,
                "preimage_p_hex": "12" * 32,
                "eth_key_hex": _SECRET,
                "rxd_covenant_spk": _COV_SPK,
                "t_rxd_blocks": 60,
                "eth_timeout_unix_s": 1780686598,
                "eth_amount_wei": 100000000000000,
                "asset_variant": "nft",
                "asset_genesis_ref": "ab" * 32 + ":0",
            }
        )
    )
    return p


# --------------------------------------------------------------------------- parse


def test_parse_btc_recovery_file(tmp_path):
    f = parse_recovery_file(_btc_file(tmp_path))
    assert f.counter_chain == "btc"
    assert f.asset_variant == "rxd"  # BTC dust files omit asset_variant → default rxd
    assert f.t_rxd_blocks == 20
    assert f.t_btc_blocks == 30
    assert f.btc_htlc_address == "bc1qexample"
    assert f.has_preimage is True
    assert f.has_keys is True


def test_parse_eth_recovery_file(tmp_path):
    f = parse_recovery_file(_eth_file(tmp_path))
    assert f.counter_chain == "eth"
    assert f.asset_variant == "nft"
    assert f.t_rxd_blocks == 60
    assert f.eth_chain == "sepolia"
    assert f.eth_timeout_unix_s == 1780686598


def test_parse_rejects_non_swap_file(tmp_path):
    p = tmp_path / "nope.json"
    p.write_text(json.dumps({"hello": "world"}))
    with pytest.raises(ValueError, match="not a swap recovery file"):
        parse_recovery_file(p)


# --------------------------------------------------------------------------- classify


def test_classify_not_found():
    sit, _ = classify_covenant(covenant_state="not_found", funding_height=None, now_height=None, t_rxd_blocks=20)
    assert sit == "NOT_FUNDED"


def test_classify_spent():
    sit, _ = classify_covenant(covenant_state="spent", funding_height=None, now_height=None, t_rxd_blocks=20)
    assert sit == "SETTLED"


def test_classify_live_locked():
    # funded@100, now 105, t_rxd 20 → refund opens at 120, 15 blocks away → LOCKED
    sit, action = classify_covenant(covenant_state="live", funding_height=100, now_height=105, t_rxd_blocks=20)
    assert sit == "LOCKED"
    assert "120" in action and "15 blocks" in action


def test_classify_live_refund_open():
    # funded@100, now 125, t_rxd 20 → refund opened at 120 (past) → REFUND_OPEN
    sit, action = classify_covenant(covenant_state="live", funding_height=100, now_height=125, t_rxd_blocks=20)
    assert sit == "REFUND_OPEN"
    assert "IMMEDIATELY" in action


# --------------------------------------------------------------------------- script hash


def test_electrumx_script_hash_matches_library_for_p2pkh():
    # Cross-check the raw-SPK script hash against the library's address script hash for the same P2PKH.
    addr = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"
    spk = P2PKH().lock(addr)
    spk_hex = spk.serialize().hex() if hasattr(spk, "serialize") else bytes(spk).hex()
    assert electrumx_script_hash(spk_hex) == bytes(script_hash_for_address(addr)).hex()


# --------------------------------------------------------------------------- CLI (offline, no network)


def test_cli_status_offline_json_no_secret_leak(tmp_path):
    res = CliRunner().invoke(cli, ["--json", "swap", "status", "--swap-file", str(_btc_file(tmp_path))])
    assert res.exit_code == 0, res.output
    payload = json.loads(res.output)
    assert payload["counter_chain"] == "btc"
    assert payload["t_rxd_blocks"] == 20
    assert payload["holds_secrets"] is True
    assert "chain" not in payload  # no --check-chain → no live read
    assert _SECRET not in res.output  # never echo key material


def test_cli_status_offline_human_warns_on_secrets(tmp_path):
    res = CliRunner().invoke(cli, ["swap", "status", "--swap-file", str(_eth_file(tmp_path))])
    assert res.exit_code == 0, res.output
    assert "ETH↔RXD" in res.output
    assert "mode 0600" in res.output  # the hygiene warning
    assert _SECRET not in res.output


def test_cli_status_rejects_garbage_file(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{not json")
    res = CliRunner().invoke(cli, ["swap", "status", "--swap-file", str(p)])
    assert res.exit_code != 0
    assert "could not parse swap file" in res.output


def test_cli_status_human_sanitizes_terminal_escapes(tmp_path):
    # CLI-1: a hand-supplied recovery file must not be able to inject ANSI/control sequences into the
    # operator's terminal via the default (human) output. A crafted field carrying ESC[2J (clear screen)
    # + fake "settled" guidance must be rendered as visible \x.. escapes, never as raw control bytes.
    p = tmp_path / ".gravity_dust_run_keys.json"
    inject = "\x1b[2J\x1b[H situation: SETTLED — no action needed"
    p.write_text(
        json.dumps(
            {
                "stage": inject,
                "rxd_network": "bc",
                "hashlock_H": "ab" * 32,
                "rxd_covenant_spk": _COV_SPK,
                "t_rxd_blocks": 20,
            }
        )
    )
    res = CliRunner().invoke(cli, ["swap", "status", "--swap-file", str(p)])
    assert res.exit_code == 0, res.output
    assert "\x1b" not in res.output  # no raw ESC reaches the terminal
    assert "\\x1b" in res.output  # it is shown as a visible escape instead
