"""CLI tests for the cold toolkit: ``swap recover-preimage`` / ``build-claim`` / ``build-refund``.

Every chain read is a fake whose ``broadcast`` raises, so "these commands never
broadcast" is asserted at runtime and not merely by inspection. The recovery file used
throughout carries a recognisable ``preimage_p_hex`` and WIFs that must never appear in
any output.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest
from click.testing import CliRunner

from pyrxd.btc_wallet.taproot import btc_txid_from_raw
from pyrxd.cli import swap_cmds, swap_recovery_cmds
from pyrxd.cli.config import Config
from pyrxd.cli.context import CliContext
from pyrxd.cli.main import cli
from pyrxd.cli.swap_recovery import CounterLegStatus, electrumx_script_hash
from pyrxd.gravity.htlc_covenant import build_htlc_covenant_rxd
from pyrxd.keys import PrivateKey
from pyrxd.network.electrumx import UtxoRecord

from .test_swap_recovery import FOREIGN_FUNDING, OUR_FUNDING, P, _claim_tx, _refund_tx

H = hashlib.sha256(P).digest()
FILE_PREIMAGE = "de" * 32  # the recovery file's own copy — never a legitimate source
FEE_VALUE = 5_000_000
ETH_CONTRACT = "0xAbCd000000000000000000000000000000000001"


class _NoBroadcastClient:
    """Fake ElectrumX. ``broadcast`` detonates — the cold path must never reach it."""

    def __init__(self, utxos: dict[str, list[UtxoRecord]], tip: int) -> None:
        self._utxos = utxos
        self._tip = tip

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return None

    async def get_utxos(self, sh):
        return self._utxos.get(sh, [])

    async def get_tip_height(self):
        return self._tip

    async def get_history(self, sh):
        return []

    async def broadcast(self, raw):  # pragma: no cover - asserted never to run
        raise AssertionError("the cold recovery toolkit must never broadcast")


@pytest.fixture
def swap(tmp_path: Path):
    """A complete, self-consistent cold-recovery scenario."""
    taker, maker, fee_key = PrivateKey(), PrivateKey(), PrivateKey()
    cov = build_htlc_covenant_rxd(
        amount=100_000,
        taker_pkh=bytes(taker.public_key().hash160()),
        maker_pkh=bytes(maker.public_key().hash160()),
        hashlock=H,
        refund_csv=20,
    )
    keys = tmp_path / "keys.json"
    keys.write_text(
        json.dumps(
            {
                "stage": "dust",
                "btc_network": "bc",
                "rxd_network": "bc",
                "hashlock_H": H.hex(),
                "preimage_p_hex": FILE_PREIMAGE,
                "taker_rxd_wif": taker.wif(),
                "maker_rxd_wif": maker.wif(),
                "rxd_covenant_spk": cov.funded_spk.hex(),
                "t_btc_blocks": 30,
                "t_rxd_blocks": 20,
                "btc_htlc_address": "bc1qexample",
            }
        )
    )
    # Both counterparties' WIFs live in this file. The fee-key file below has been
    # chmod 0600 since it was written; this one was not — the same asymmetry the
    # library had, mirrored in the fixture. Later `swap["keys"].write_text(...)`
    # rewrites truncate in place and inherit this mode.
    keys.chmod(0o600)
    fee_file = tmp_path / "fee.wif"
    fee_file.write_text(fee_key.wif())
    fee_file.chmod(0o600)
    fee_spk = b"\x76\xa9\x14" + bytes(fee_key.public_key().hash160()) + b"\x88\xac"
    return {
        "cov": cov,
        "keys": keys,
        "fee_file": fee_file,
        "fee_key": fee_key,
        "taker": taker,
        "cov_sh": electrumx_script_hash(cov.funded_spk),
        "fee_sh": electrumx_script_hash(fee_spk),
    }


def _client(swap, *, confirmations: int = 5):
    tip = 100 + confirmations - 1
    return _NoBroadcastClient(
        {
            swap["cov_sh"]: [UtxoRecord(tx_hash="ab" * 32, tx_pos=0, value=100_000, height=100)],
            swap["fee_sh"]: [UtxoRecord(tx_hash="cd" * 32, tx_pos=1, value=FEE_VALUE, height=90)],
        },
        tip=tip,
    )


def _ctx(client=None, *, output_mode: str = "human") -> CliContext:
    path = Path("/tmp/_pyrxd_cold_recovery_test")
    return CliContext(
        config=Config(network="mainnet", electrumx="wss://test/", fee_rate=10_000, wallet_path=path),
        network="mainnet",
        electrumx_url="wss://test/",
        wallet_path=path,
        output_mode=output_mode,
        yes=True,
        client_factory=(lambda: client) if client is not None else None,
    )


# --------------------------------------------------------------------------- recover-preimage


def _invoke(args: list[str], ctx: CliContext):
    """Invoke the ``swap`` group directly.

    The top-level ``cli`` callback REPLACES ``ctx.obj`` with a context it builds from the
    global flags, so an injected client/output-mode only survives when the group is
    entered directly — the same pattern as ``tests/cli/test_swap_covenant_cmds.py``.
    """
    return CliRunner().invoke(swap_cmds.swap_group, args, obj=ctx)


def _recover(swap, *extra, output_mode: str = "human"):
    return _invoke(["recover-preimage", "--swap-file", str(swap["keys"]), *extra], _ctx(output_mode=output_mode))


def test_offline_recovery_prints_the_chain_scraped_preimage(swap) -> None:
    res = _recover(swap, "--claim-tx-hex", _claim_tx().hex(), "--btc-funding-outpoint", f"{OUR_FUNDING.txid}:1")
    assert res.exit_code == 0, res.output
    assert P.hex() in res.output
    assert "provenance checks that PASSED" in res.output
    assert FILE_PREIMAGE not in res.output  # the file's copy is never a source


def test_offline_recovery_without_the_funding_outpoint_is_refused(swap) -> None:
    res = _recover(swap, "--claim-tx-hex", _claim_tx().hex())
    assert res.exit_code == 1
    assert "requires --btc-funding-outpoint" in res.output
    assert "provenance is mandatory offline too" in res.output
    assert P.hex() not in res.output


def test_a_foreign_claim_sharing_the_hashlock_is_refused_and_leaks_nothing(swap) -> None:
    foreign = _claim_tx(outpoint=FOREIGN_FUNDING)
    res = _recover(swap, "--claim-tx-hex", foreign.hex(), "--btc-funding-outpoint", f"{OUR_FUNDING.txid}:1")
    assert res.exit_code == 1
    assert "REFUSED on provenance" in res.output
    assert P.hex() not in res.output


def test_a_refund_reports_no_preimage_yet(swap) -> None:
    res = _recover(swap, "--claim-tx-hex", _refund_tx().hex(), "--btc-funding-outpoint", f"{OUR_FUNDING.txid}:1")
    assert res.exit_code == 1
    assert "no preimage has been revealed yet" in res.output


def test_recovery_json_marks_that_nothing_was_broadcast(swap) -> None:
    res = _recover(
        swap,
        "--claim-tx-hex",
        _claim_tx().hex(),
        "--btc-funding-outpoint",
        f"{OUR_FUNDING.txid}:1",
        output_mode="json",
    )
    assert res.exit_code == 0, res.output
    payload = json.loads(res.output)
    assert payload["preimage_hex"] == P.hex()
    assert payload["broadcast"] is False
    assert len(payload["provenance_checks"]) == 3


def test_recovery_quiet_mode_prints_only_the_preimage(swap) -> None:
    res = _recover(
        swap,
        "--claim-tx-hex",
        _claim_tx().hex(),
        "--btc-funding-outpoint",
        f"{OUR_FUNDING.txid}:1",
        output_mode="quiet",
    )
    assert res.exit_code == 0, res.output
    assert res.output.strip() == P.hex()


def test_recovery_needs_the_funding_outpoint_a_legacy_file_never_persisted(swap) -> None:
    res = _recover(swap)
    assert res.exit_code == 1
    assert "not in the recovery file" in res.output
    assert "--btc-funding-outpoint" in res.output


def test_recovery_uses_the_funding_outpoint_when_the_harness_persisted_it(swap) -> None:
    # The harness change (scripts/dust_swap_run.py now merges `btc_funding_outpoint` in
    # after funding) means the operator no longer has to supply it by hand.
    doc = json.loads(swap["keys"].read_text())
    doc["btc_funding_outpoint"] = f"{OUR_FUNDING.txid}:1"
    swap["keys"].write_text(json.dumps(doc))
    res = _recover(swap, "--claim-tx-hex", _claim_tx().hex())
    assert res.exit_code == 0, res.output
    assert P.hex() in res.output


def test_recovery_rejects_non_hex_claim_bytes(swap) -> None:
    res = _recover(swap, "--claim-tx-hex", "zzz", "--btc-funding-outpoint", f"{OUR_FUNDING.txid}:1")
    assert res.exit_code == 1
    assert "not valid hex" in res.output


def test_recovery_rejects_both_offline_sources_at_once(swap, tmp_path: Path) -> None:
    f = tmp_path / "raw.hex"
    f.write_text(_claim_tx().hex())
    res = _recover(swap, "--claim-tx-hex", _claim_tx().hex(), "--claim-tx-file", str(f))
    assert res.exit_code == 1
    assert "only one of" in res.output


def test_recovery_reads_the_claim_hex_from_a_file(swap, tmp_path: Path) -> None:
    f = tmp_path / "raw.hex"
    f.write_text(_claim_tx().hex() + "\n")
    res = _recover(swap, "--claim-tx-file", str(f), "--btc-funding-outpoint", f"{OUR_FUNDING.txid}:1")
    assert res.exit_code == 0, res.output
    assert P.hex() in res.output


def test_recovery_rejects_a_non_swap_file(tmp_path: Path) -> None:
    p = tmp_path / "nope.json"
    p.write_text("{not json")
    res = _invoke(["recover-preimage", "--swap-file", str(p)], _ctx())
    assert res.exit_code == 1
    assert "could not parse the swap recovery file" in res.output


# --------------------------------------------------------------------------- build-claim


def _build(swap, verb: str, *extra, client=None, output_mode: str = "human"):
    return _invoke(
        [verb, "--swap-file", str(swap["keys"]), "--fee-wif-file", str(swap["fee_file"]), *extra],
        _ctx(client if client is not None else _client(swap), output_mode=output_mode),
    )


def test_build_claim_prints_hex_plus_the_fee_and_deadline_context(swap) -> None:
    res = _build(swap, "build-claim", "--preimage", P.hex())
    assert res.exit_code == 0, res.output
    assert "BUILT, NOT BROADCAST" in res.output
    assert "relay floor" in res.output and "target" in res.output
    assert "TAKER holder script" in res.output
    assert "no RBF and no CPFP" in res.output
    # The printed hex must be the real, decodable transaction.
    raw_line = next(ln for ln in res.output.splitlines() if len(ln.strip()) > 200 and " " not in ln.strip())
    assert bytes.fromhex(raw_line.strip())
    # No secret ever reaches the terminal.
    assert FILE_PREIMAGE not in res.output
    assert swap["fee_key"].wif() not in res.output
    assert swap["taker"].wif() not in res.output


def test_build_claim_never_borrows_the_refunds_csv_maturity_wording(swap) -> None:
    # The claim branch has NO timelock: the covenant's CSV depth is the DEADLINE for this
    # spend, not a gate on it. Printing "immature — a node will reject this" on a claim
    # would make an operator hesitate at precisely the moment they must act.
    res = _build(swap, "build-claim", "--preimage", P.hex())
    assert res.exit_code == 0, res.output
    assert "NOT MATURE" not in res.output
    assert "IMMATURE" not in res.output
    assert "must be MINED, not merely broadcast" in res.output
    assert "the maker's CSV refund branch opens at 20" in res.output


def test_build_claim_past_the_deadline_warns_that_it_is_racing_the_refund(swap) -> None:
    res = _build(swap, "build-claim", "--preimage", P.hex(), client=_client(swap, confirmations=25))
    assert res.exit_code == 0, res.output
    assert "REFUND WINDOW IS ALREADY OPEN" in res.output
    assert "still valid and worth sending" in res.output


def test_build_claim_json_reports_floor_target_and_no_broadcast(swap) -> None:
    res = _build(swap, "build-claim", "--preimage", P.hex(), output_mode="json")
    assert res.exit_code == 0, res.output
    payload = json.loads(res.output)
    assert payload["kind"] == "claim"
    assert payload["broadcast"] is False
    assert payload["fee_photons"] == FEE_VALUE
    assert payload["clears_floor"] is True
    assert payload["blocks_to_deadline"] == 15  # t_rxd 20 - 5 confirmations
    assert payload["csv_required"] == 20 and payload["csv_confirmations"] == 5


def test_build_claim_quiet_mode_prints_only_the_raw_hex(swap) -> None:
    res = _build(swap, "build-claim", "--preimage", P.hex(), output_mode="quiet")
    assert res.exit_code == 0, res.output
    assert bytes.fromhex(res.output.strip())


def test_build_claim_rejects_a_preimage_that_does_not_open_the_lock(swap) -> None:
    res = _build(swap, "build-claim", "--preimage", "00" * 32)
    assert res.exit_code == 1
    assert "does not hash to the covenant hashlock" in res.output


def test_build_claim_rejects_a_malformed_preimage(swap) -> None:
    assert "not valid hex" in _build(swap, "build-claim", "--preimage", "zz").output
    assert "must be 32 bytes" in _build(swap, "build-claim", "--preimage", "aa").output


def test_build_claim_refuses_when_the_rebuilt_covenant_is_not_the_persisted_one(swap) -> None:
    res = _build(swap, "build-claim", "--preimage", P.hex(), "--taker-pkh", "11" * 20)
    assert res.exit_code == 1
    assert "does not match the one in the recovery file" in res.output


def test_build_claim_needs_a_fee_key(swap) -> None:
    res = _invoke(["build-claim", "--swap-file", str(swap["keys"]), "--preimage", P.hex()], _ctx(_client(swap)))
    assert res.exit_code == 1
    assert "no fee key supplied" in res.output


def test_build_claim_reports_a_fee_pool_that_cannot_clear_the_floor(swap) -> None:
    thin = _NoBroadcastClient(
        {
            swap["cov_sh"]: [UtxoRecord(tx_hash="ab" * 32, tx_pos=0, value=100_000, height=100)],
            swap["fee_sh"]: [UtxoRecord(tx_hash="cd" * 32, tx_pos=1, value=900, height=90)],
        },
        tip=104,
    )
    res = _build(swap, "build-claim", "--preimage", P.hex(), client=thin)
    assert res.exit_code == 1
    assert "no fee input clears the relay floor" in res.output


def test_build_claim_honours_an_explicit_relay_rate(swap) -> None:
    res = _build(swap, "build-claim", "--preimage", P.hex(), "--relay-fee-rxd-per-kb", "0.10", output_mode="json")
    assert res.exit_code == 0, res.output
    assert json.loads(res.output)["relay_floor_photons"] > 0


def test_build_claim_rejects_an_under_floor_relay_rate_without_the_optout(swap) -> None:
    res = _build(swap, "build-claim", "--preimage", P.hex(), "--relay-fee-rxd-per-kb", "0.0000001")
    assert res.exit_code == 1
    assert "invalid --relay-fee-rxd-per-kb" in res.output


def test_build_claim_uses_the_persisted_covenant_amount(swap) -> None:
    # `rxd_covenant_amount` is the field the harnesses now persist. It must be USED (the
    # SPK check would fail if a wrong value were taken) and it must win over the
    # derived-from-carrier default.
    doc = json.loads(swap["keys"].read_text())
    doc["rxd_covenant_amount"] = 100_000
    swap["keys"].write_text(json.dumps(doc))
    assert _build(swap, "build-claim", "--preimage", P.hex()).exit_code == 0

    doc["rxd_covenant_amount"] = 42  # a wrong persisted amount must be caught, not ignored
    swap["keys"].write_text(json.dumps(doc))
    res = _build(swap, "build-claim", "--preimage", P.hex())
    assert res.exit_code == 1
    assert "does not match the one in the recovery file" in res.output


def test_build_claim_reports_an_unfunded_covenant_plainly(swap) -> None:
    empty = _NoBroadcastClient({swap["fee_sh"]: [UtxoRecord("cd" * 32, 1, FEE_VALUE, 90)]}, tip=104)
    res = _build(swap, "build-claim", "--preimage", P.hex(), client=empty)
    assert res.exit_code == 1
    assert "never funded" in res.output


# --------------------------------------------------------------------------- build-refund


def test_build_refund_refuses_an_immature_csv(swap) -> None:
    res = _build(swap, "build-refund")
    assert res.exit_code == 1
    assert "not yet mature" in res.output
    assert "--allow-immature" in res.output


def test_build_refund_can_be_prebuilt_before_maturity(swap) -> None:
    res = _build(swap, "build-refund", "--allow-immature", output_mode="json")
    assert res.exit_code == 0, res.output
    payload = json.loads(res.output)
    assert payload["kind"] == "refund"
    assert payload["csv_mature"] is False
    assert payload["blocks_to_deadline"] is None
    assert payload["target_photons"] == payload["relay_floor_photons"]  # no premium on a refund


def test_build_refund_warns_loudly_in_human_mode_while_immature(swap) -> None:
    res = _build(swap, "build-refund", "--allow-immature")
    assert res.exit_code == 0, res.output
    assert "THE CSV IS NOT MATURE" in res.output


def test_build_refund_at_maturity_pays_the_maker(swap) -> None:
    res = _build(swap, "build-refund", client=_client(swap, confirmations=25), output_mode="json")
    assert res.exit_code == 0, res.output
    payload = json.loads(res.output)
    assert payload["csv_mature"] is True
    assert payload["outputs"][0]["scriptpubkey_hex"] == swap["cov"].maker_holder_script.hex()


def _two_utxo_client(swap, *, confirmations: int):
    return _NoBroadcastClient(
        {
            swap["cov_sh"]: [UtxoRecord(tx_hash="ab" * 32, tx_pos=0, value=100_000, height=100)],
            swap["fee_sh"]: [
                UtxoRecord(tx_hash="11" * 32, tx_pos=0, value=4_000_000, height=90),
                UtxoRecord(tx_hash="22" * 32, tx_pos=0, value=9_000_000, height=90),
            ],
        },
        tip=100 + confirmations - 1,
    )


def _chosen_fee(res) -> int:
    return json.loads(res.output)["fee_photons"]


def test_fee_selection_buys_urgency_only_where_urgency_exists(swap) -> None:
    """The whole fee input is burned, so over-selecting is money spent, not headroom kept.

    A claim near its deadline should reach for the larger input; the same claim far from
    the deadline, and a refund at ANY depth (a CSV refund has no closing window), should
    take the smaller one.
    """
    far = _build(
        swap, "build-claim", "--preimage", P.hex(), client=_two_utxo_client(swap, confirmations=5), output_mode="json"
    )
    near = _build(
        swap, "build-claim", "--preimage", P.hex(), client=_two_utxo_client(swap, confirmations=18), output_mode="json"
    )
    refund = _build(swap, "build-refund", client=_two_utxo_client(swap, confirmations=25), output_mode="json")
    assert _chosen_fee(far) == 4_000_000
    assert _chosen_fee(near) == 9_000_000
    assert _chosen_fee(refund) == 4_000_000


def test_neither_builder_ever_calls_broadcast(swap) -> None:
    # _NoBroadcastClient.broadcast raises AssertionError; a clean exit proves it was
    # never reached on either path.
    assert _build(swap, "build-claim", "--preimage", P.hex()).exit_code == 0
    assert _build(swap, "build-refund", client=_client(swap, confirmations=25)).exit_code == 0


# --------------------------------------------------------------------------- status counter-leg


def _status(swap, *extra, client=None, output_mode: str = "human"):
    return _invoke(
        ["status", "--swap-file", str(swap["keys"]), "--check-chain", *extra],
        _ctx(client if client is not None else _client(swap), output_mode=output_mode),
    )


def test_status_reports_not_checked_with_the_reason_when_no_counter_leg_locator(swap) -> None:
    res = _status(swap)
    assert res.exit_code == 0, res.output
    assert "Counter-leg (BTC): NOT_CHECKED" in res.output
    assert "only printed it to the console" in res.output


def test_status_json_carries_the_counter_leg_block(swap) -> None:
    res = _status(swap, output_mode="json")
    assert res.exit_code == 0, res.output
    counter = json.loads(res.output)["counter_leg"]
    assert counter["state"] == "NOT_CHECKED"
    assert counter["preimage_available"] is False


def test_status_surfaces_a_revealed_preimage_without_printing_it(swap, monkeypatch) -> None:
    raw = _claim_tx()
    monkeypatch.setattr(
        swap_cmds,
        "read_counter_leg",
        AsyncMock(
            return_value=CounterLegStatus(
                chain="btc",
                state="CLAIMED_PREIMAGE_REVEALED",
                reason="the counterparty CLAIMED and the preimage p is now PUBLIC on BTC.",
                claim_txid=btc_txid_from_raw(raw),
                preimage_available=True,
            )
        ),
    )
    res = _status(swap, "--btc-funding-outpoint", f"{OUR_FUNDING.txid}:1")
    assert res.exit_code == 0, res.output
    assert "CLAIMED_PREIMAGE_REVEALED" in res.output
    assert "recover-preimage" in res.output
    assert P.hex() not in res.output  # status never prints p


def test_status_sanitizes_terminal_escapes_from_a_counter_leg_reason(swap, monkeypatch) -> None:
    monkeypatch.setattr(
        swap_cmds,
        "read_counter_leg",
        AsyncMock(
            return_value=CounterLegStatus(
                chain="btc", state="ERROR", reason="\x1b[2J\x1b[H all clear, no action needed"
            )
        ),
    )
    res = _status(swap)
    assert res.exit_code == 0, res.output
    assert "\x1b" not in res.output
    assert "\\x1b" in res.output


def test_status_survives_a_counter_leg_read_failure(swap, monkeypatch) -> None:
    monkeypatch.setattr(swap_cmds, "read_counter_leg", AsyncMock(side_effect=RuntimeError("explorer down")))
    res = _status(swap)
    assert res.exit_code == 0, res.output
    assert "Counter-leg (BTC): ERROR" in res.output
    assert "explorer down" in res.output
    assert "situation" in res.output  # the covenant verdict still made it out


def test_status_without_check_chain_does_not_read_the_counter_leg(swap) -> None:
    res = _invoke(["status", "--swap-file", str(swap["keys"])], _ctx(output_mode="json"))
    assert res.exit_code == 0, res.output
    assert "counter_leg" not in json.loads(res.output)


def test_the_swap_group_still_advertises_the_three_cold_verbs() -> None:
    out = CliRunner().invoke(cli, ["swap", "--help"]).output
    for verb in ("recover-preimage", "build-claim", "build-refund"):
        assert verb in out


# --------------------------------------------------------------------------- online recovery paths


class _Session:
    """A stand-in aiohttp session: it is only ever entered and exited."""

    closed = False

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return None


@pytest.fixture
def no_real_http(monkeypatch):
    monkeypatch.setattr(swap_recovery_cmds, "open_http_session", AsyncMock(return_value=_Session()))


def test_online_btc_recovery_fetches_verifies_and_prints(swap, monkeypatch, no_real_http) -> None:
    raw = _claim_tx()
    monkeypatch.setattr(
        swap_recovery_cmds,
        "fetch_btc_claim_bytes",
        AsyncMock(return_value=(True, btc_txid_from_raw(raw), raw)),
    )
    res = _recover(swap, "--btc-funding-outpoint", f"{OUR_FUNDING.txid}:1")
    assert res.exit_code == 0, res.output
    assert P.hex() in res.output


def test_online_btc_recovery_reports_an_unspent_htlc(swap, monkeypatch, no_real_http) -> None:
    monkeypatch.setattr(swap_recovery_cmds, "fetch_btc_claim_bytes", AsyncMock(return_value=(False, None, None)))
    res = _recover(swap, "--btc-funding-outpoint", f"{OUR_FUNDING.txid}:1")
    assert res.exit_code == 1
    assert "UNSPENT" in res.output


def test_online_btc_recovery_refuses_unverifiable_bytes(swap, monkeypatch, no_real_http) -> None:
    # Spent, but the explorer cannot serve the transaction: proceeding would mean
    # trusting a txid nobody re-derived.
    monkeypatch.setattr(swap_recovery_cmds, "fetch_btc_claim_bytes", AsyncMock(return_value=(True, "cc" * 32, None)))
    res = _recover(swap, "--btc-funding-outpoint", f"{OUR_FUNDING.txid}:1")
    assert res.exit_code == 1
    assert "not retrievable" in res.output


def _eth_swap(swap):
    doc = json.loads(swap["keys"].read_text())
    doc.pop("btc_network", None)
    doc["eth_chain"] = "sepolia"
    doc["eth_timeout_unix_s"] = 1780686598
    swap["keys"].write_text(json.dumps(doc))
    return swap


def test_online_eth_recovery_fetches_verifies_and_prints(swap, monkeypatch, no_real_http) -> None:
    monkeypatch.setattr(
        swap_recovery_cmds,
        "fetch_eth_claim_artifacts",
        AsyncMock(return_value=({"hash": "0xfeed", "to": ETH_CONTRACT, "input": "0x" + P.hex()}, [])),
    )
    res = _recover(_eth_swap(swap), "--eth-contract", ETH_CONTRACT, "--eth-rpc-url", "http://x")
    assert res.exit_code == 0, res.output
    assert P.hex() in res.output


def test_online_eth_recovery_reports_no_claim_activity(swap, monkeypatch, no_real_http) -> None:
    monkeypatch.setattr(swap_recovery_cmds, "fetch_eth_claim_artifacts", AsyncMock(return_value=(None, [])))
    res = _recover(_eth_swap(swap), "--eth-contract", ETH_CONTRACT, "--eth-rpc-url", "http://x")
    assert res.exit_code == 1
    assert "no retrievable claim activity" in res.output


def test_eth_recovery_needs_a_contract_and_an_rpc_url(swap) -> None:
    res = _recover(_eth_swap(swap))
    assert res.exit_code == 1
    assert "--eth-contract" in res.output
    assert "eth_swap_two_host" in res.output


def test_a_network_failure_is_a_network_boundary_error_not_a_crash(swap, monkeypatch, no_real_http) -> None:
    monkeypatch.setattr(
        swap_recovery_cmds, "fetch_btc_claim_bytes", AsyncMock(side_effect=OSError("connection refused"))
    )
    res = _recover(swap, "--btc-funding-outpoint", f"{OUR_FUNDING.txid}:1")
    assert res.exit_code == 2  # NetworkBoundaryError
    assert "a chain read failed" in res.output
    assert "nothing was broadcast" in res.output


def test_a_malformed_funding_outpoint_is_a_clean_user_error(swap) -> None:
    res = _recover(swap, "--claim-tx-hex", _claim_tx().hex(), "--btc-funding-outpoint", "not-an-outpoint")
    assert res.exit_code == 1
    assert "preimage recovery failed" in res.output


def test_a_non_hex_hashlock_in_the_file_is_a_clean_user_error(swap) -> None:
    doc = json.loads(swap["keys"].read_text())
    doc["hashlock_H"] = "zz" * 32
    swap["keys"].write_text(json.dumps(doc))
    res = _recover(swap, "--claim-tx-hex", _claim_tx().hex(), "--btc-funding-outpoint", f"{OUR_FUNDING.txid}:1")
    assert res.exit_code == 1
    assert "hashlock_H is not hex" in res.output


def test_a_short_hashlock_in_the_file_is_a_clean_user_error(swap) -> None:
    doc = json.loads(swap["keys"].read_text())
    doc["hashlock_H"] = "ab"
    swap["keys"].write_text(json.dumps(doc))
    res = _recover(swap, "--claim-tx-hex", _claim_tx().hex(), "--btc-funding-outpoint", f"{OUR_FUNDING.txid}:1")
    assert res.exit_code == 1
    assert "must be 32 bytes" in res.output


def test_an_unreadable_fee_key_file_is_a_clean_user_error(swap, tmp_path: Path) -> None:
    world_readable = tmp_path / "loose.wif"
    world_readable.write_text(swap["fee_key"].wif())
    world_readable.chmod(0o644)
    res = _invoke(
        [
            "build-claim",
            "--swap-file",
            str(swap["keys"]),
            "--preimage",
            P.hex(),
            "--fee-wif-file",
            str(world_readable),
        ],
        _ctx(_client(swap)),
    )
    assert res.exit_code == 1
    assert "could not read the fee key" in res.output


def test_an_explicit_covenant_amount_flag_wins_over_everything(swap) -> None:
    doc = json.loads(swap["keys"].read_text())
    doc["rxd_covenant_amount"] = 42  # wrong; the flag must override it
    swap["keys"].write_text(json.dumps(doc))
    res = _build(swap, "build-claim", "--preimage", P.hex(), "--covenant-amount", "100000")
    assert res.exit_code == 0, res.output


def test_an_ft_swap_falls_back_to_the_persisted_token_amount(swap) -> None:
    # For FT the covenant parameter is the TOKEN amount, which the carrier value does not
    # encode — so the derivation has to read asset_ft_amount rather than the funded value.
    doc = json.loads(swap["keys"].read_text())
    doc["asset_variant"] = "ft"
    doc["asset_ft_amount"] = 500
    doc["asset_genesis_ref"] = "ab" * 32 + ":0"
    swap["keys"].write_text(json.dumps(doc))
    res = _build(swap, "build-claim", "--preimage", P.hex())
    # It gets far enough to rebuild an FT covenant, then fails the SPK match (this fixture
    # is an RXD swap) — which is exactly the fail-closed behaviour, not an amount error.
    assert res.exit_code == 1
    assert "does not match the one in the recovery file" in res.output


def test_an_ft_swap_without_a_persisted_amount_asks_for_the_flag(swap) -> None:
    doc = json.loads(swap["keys"].read_text())
    doc["asset_variant"] = "ft"
    swap["keys"].write_text(json.dumps(doc))
    res = _build(swap, "build-claim", "--preimage", P.hex())
    assert res.exit_code == 1
    assert "--covenant-amount" in res.output


# --------------------------------------------------------------------------- the RENDERED remedy
#
# The mode refusal from ``load_recovery_json`` is the one error here that carries a
# command the operator has to run, and ``_load`` renders it through
# ``sanitize_terminal(str(exc), max_len=…)``, which truncates from the right. Measured
# at the previous ``max_len=200`` with a ``/tmp`` path: a 446-character message became
# 200 characters and the workable ``install -m 600 …`` suggestion (index 238) was cut
# off entirely, so the operator was shown ONLY the ``chmod`` that cannot succeed.
#
# The existing coverage asserted on ``str(exc.value)`` — the message the library builds,
# not the one the CLI prints — which is exactly why it passed while the CLI was a dead
# end. These assert on what is actually rendered.


@pytest.mark.skipif(os.geteuid() == 0, reason="root can chmod a 0444 file, so the unrunnable-remedy case cannot arise")
def test_the_CLI_PRINTS_a_remedy_the_operator_can_actually_run(swap, tmp_path: Path) -> None:
    archived = tmp_path / "archived"
    archived.mkdir()
    keys = archived / "keys.json"
    keys.write_text(swap["keys"].read_text())
    keys.chmod(0o444)
    archived.chmod(0o555)  # no unlink/rename either — the read-only-media shape
    try:
        res = _invoke(
            ["build-claim", "--swap-file", str(keys), "--fee-wif-file", str(swap["fee_file"]), "--preimage", P.hex()],
            _ctx(_client(swap)),
        )
    finally:
        archived.chmod(0o755)
    assert res.exit_code == 1
    assert "could not parse the swap recovery file" in res.output
    assert "install -m 600" in res.output, f"the runnable remedy was truncated away:\n{res.output}"
    assert str(keys) in res.output  # and it names the file, so it is copy-pasteable


@pytest.mark.skipif(os.geteuid() == 0, reason="root can chmod a 0444 file, so the unrunnable-remedy case cannot arise")
def test_the_runnable_remedy_survives_even_a_hard_truncation(swap, tmp_path: Path) -> None:
    """Ordering, not just the raised limit. ``install -m 600`` leads the hint, so a
    future caller that picks a smaller ``max_len`` loses the explanation and keeps the
    command — the failure mode this had was the other way round."""
    from pyrxd.cli.format import sanitize_terminal
    from pyrxd.cli.swap_recovery import load_recovery_json
    from pyrxd.security.errors import ValidationError

    archived = tmp_path / "archived2"
    archived.mkdir()
    keys = archived / "keys.json"
    keys.write_text(swap["keys"].read_text())
    keys.chmod(0o444)
    archived.chmod(0o555)
    try:
        with pytest.raises(ValidationError) as exc:
            load_recovery_json(keys)
    finally:
        archived.chmod(0o755)
    message = str(exc.value)
    assert "install -m 600" in sanitize_terminal(message, max_len=200)
    assert message.index("install -m 600") < message.index("cannot succeed")


# --------------------------------------------------------------------------- the counter-leg verdict must be TRUE
#
# Everything below runs the REAL commands, the REAL counter-leg readers and the REAL
# Esplora GET helpers (`mempool_space_outspend` / `mempool_space_tx_hex`). Only the
# network is fake: an aiohttp-shaped session answering canned JSON, and the ElectrumX
# client the covenant read goes through.

_ESPLORA = "https://esplora.example/api/key-DO-NOT-PRINT"


class _EsploraResponse:
    def __init__(self, body: Any, status: int = 200) -> None:
        self._body = body
        self.status = status

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return None

    def raise_for_status(self) -> None:
        if self.status >= 400:
            raise OSError(f"HTTP {self.status}")

    async def json(self):
        return self._body

    async def text(self):
        return self._body if isinstance(self._body, str) else json.dumps(self._body)


class _FakeEsplora:
    """An aiohttp-shaped session over canned Esplora answers. GET only — nothing else exists."""

    def __init__(self, outspend: Any, tx_hex: dict[str, str] | None = None) -> None:
        self._outspend = outspend
        self._tx_hex = tx_hex or {}
        self.urls: list[str] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return None

    def get(self, url: str, timeout: Any = None) -> _EsploraResponse:
        self.urls.append(url)
        if "/outspend/" in url:
            return _EsploraResponse(self._outspend)
        txid = url.rsplit("/", 2)[-2]
        if url.endswith("/hex") and txid in self._tx_hex:
            return _EsploraResponse(self._tx_hex[txid])
        return _EsploraResponse("", status=404)


def _serve(monkeypatch, session: _FakeEsplora) -> _FakeEsplora:
    """Route BOTH commands' HTTP through *session* (each module holds its own reference)."""
    from pyrxd.cli import swap_recovery

    monkeypatch.setattr(swap_recovery, "open_http_session", AsyncMock(return_value=session))
    monkeypatch.setattr(swap_recovery_cmds, "open_http_session", AsyncMock(return_value=session))
    return session


class _SpentCovenantClient(_NoBroadcastClient):
    """ElectrumX for a covenant that WAS funded and is now spent: no UTXO, some history."""

    def __init__(self, cov_sh: str, tip: int) -> None:
        super().__init__({}, tip=tip)
        self._cov_sh = cov_sh

    async def get_history(self, sh):
        return [{"tx_hash": "ef" * 32, "height": 100}] if sh == self._cov_sh else []


_OUTPOINT = f"{OUR_FUNDING.txid}:{OUR_FUNDING.vout}"

#: An explorer that says SPENT but does not say by what. Each one used to read as UNSPENT.
_SPENT_SPENDER_UNKNOWN = [
    pytest.param({"spent": True}, id="spender-missing"),
    pytest.param({"spent": True, "txid": "zz" * 32}, id="spender-not-hex"),
    pytest.param({"spent": True, "txid": "ab" * 31}, id="spender-short"),
    pytest.param({"spent": True, "txid": None}, id="spender-null"),
]


def _checked_status(swap, *extra, client=None, output_mode: str = "human"):
    return _status(
        swap,
        "--btc-funding-outpoint",
        _OUTPOINT,
        "--btc-api-url",
        _ESPLORA,
        *extra,
        client=client,
        output_mode=output_mode,
    )


@pytest.mark.parametrize("outspend", _SPENT_SPENDER_UNKNOWN)
def test_status_spent_with_an_unknown_spender_is_an_error_never_unspent(swap, monkeypatch, outspend) -> None:
    esplora = _serve(monkeypatch, _FakeEsplora(outspend))
    res = _checked_status(swap)
    assert res.exit_code == 0, res.output
    assert "Counter-leg (BTC): ERROR" in res.output
    assert "Counter-leg (BTC): LOCKED" not in res.output
    assert "UNSPENT" not in res.output
    assert "has not claimed" not in res.output
    assert "SPENT but gave no well-formed spending txid" in res.output
    # No spender, so nothing was fetched by txid — the refusal is not a fetch failure.
    assert not any(u.endswith("/hex") for u in esplora.urls)


@pytest.mark.parametrize("outspend", _SPENT_SPENDER_UNKNOWN)
def test_recover_preimage_spent_with_an_unknown_spender_is_an_error_never_unspent(swap, monkeypatch, outspend) -> None:
    _serve(monkeypatch, _FakeEsplora(outspend))
    res = _recover(swap, "--btc-funding-outpoint", _OUTPOINT, "--btc-api-url", _ESPLORA)
    assert res.exit_code == 2, res.output  # NetworkBoundaryError: inconclusive, not "not revealed"
    assert "inconclusive" in res.output
    assert "UNSPENT" not in res.output
    assert "no preimage has been revealed yet" not in res.output
    assert P.hex() not in res.output


def test_an_honest_unspent_answer_still_reads_unspent_and_names_its_one_source(swap, monkeypatch) -> None:
    _serve(monkeypatch, _FakeEsplora({"spent": False}))
    res = _checked_status(swap)
    assert res.exit_code == 0, res.output
    assert "Counter-leg (BTC): LOCKED" in res.output
    assert "esplora.example reports the BTC funding outpoint" in res.output
    assert "UNSPENT" in res.output
    assert "one server's answer" in res.output
    assert "DO-NOT-PRINT" not in res.output  # the host only, never a path that may carry a key

    rec = _recover(swap, "--btc-funding-outpoint", _OUTPOINT, "--btc-api-url", _ESPLORA)
    assert rec.exit_code == 1, rec.output
    assert "no preimage has been revealed yet" in rec.output
    assert "esplora.example reports" in rec.output
    assert "UNSPENT" in rec.output
    assert "DO-NOT-PRINT" not in rec.output


def test_a_maker_refunded_covenant_with_the_counter_leg_locked_says_refund(swap, monkeypatch) -> None:
    """The covenant is spent (the maker's CSV refund) and the taker's BTC is still in the HTLC.

    This used to print SETTLED "... no further action" directly above a Counter-leg row
    reading LOCKED — and the BTC claim branch has no timelock, so a maker holding p can
    sweep that BTC whenever it likes."""
    _serve(monkeypatch, _FakeEsplora({"spent": False}))
    client = _SpentCovenantClient(swap["cov_sh"], tip=130)
    res = _checked_status(swap, client=client)
    assert res.exit_code == 0, res.output
    assert "covenant SPENT" in res.output
    assert "Counter-leg (BTC): LOCKED" in res.output
    assert "no further action" not in res.output.lower()
    assert "SETTLED" not in res.output
    assert "refund it now" in res.output
    # It used to name `scripts/btc_swap_two_host.py --role taker --phase abort` here: a command
    # that needs that harness's envelope.json + taker_funding.json + its own secret file, none of
    # which a dust-run recovery file comes with, and a scripts/ directory a pip install lacks.
    assert "--phase abort" not in res.output
    assert "two_host" not in res.output
    assert "pyrxd has no command that refunds the BTC leg" in res.output
    assert "scripts/dust_swap_run.py, which wrote this file" in res.output
    assert "30 BTC blocks after the HTLC funding confirmed" in res.output
    assert "NO timelock" in res.output

    js = _checked_status(swap, client=_SpentCovenantClient(swap["cov_sh"], tip=130), output_mode="json")
    assert json.loads(js.output)["situation"] == "COUNTER_LEG_LOCKED"


def test_a_spent_covenant_with_the_counter_leg_unchecked_does_not_claim_settled(swap) -> None:
    res = _status(swap, client=_SpentCovenantClient(swap["cov_sh"], tip=130))  # no counter-leg locator
    assert res.exit_code == 0, res.output
    assert "Counter-leg (BTC): NOT_CHECKED" in res.output
    assert "no further action" not in res.output.lower()
    assert "SETTLED" not in res.output
    assert "does NOT mean the swap is over" in res.output


def test_both_legs_spent_still_reads_settled(swap, monkeypatch) -> None:
    raw = _claim_tx()
    spender = btc_txid_from_raw(raw)
    _serve(monkeypatch, _FakeEsplora({"spent": True, "txid": spender}, tx_hex={spender: raw.hex()}))
    res = _checked_status(swap, client=_SpentCovenantClient(swap["cov_sh"], tip=130))
    assert res.exit_code == 0, res.output
    assert "Counter-leg (BTC): CLAIMED_PREIMAGE_REVEALED" in res.output
    assert "situation  : SETTLED" in res.output
    assert "No further action" in res.output
    # SETTLED rests on the explorer's word that the leg is spent; the text says whose, as LOCKED does.
    assert "esplora.example reports the BTC leg claimed with p" in res.output
    assert "one server's answer" in res.output
    assert "DO-NOT-PRINT" not in res.output
    assert P.hex() not in res.output  # status still never prints p


def test_a_settled_swap_on_a_refunded_counter_leg_names_the_one_server_that_said_so(swap, monkeypatch) -> None:
    raw = _refund_tx()
    spender = btc_txid_from_raw(raw)
    _serve(monkeypatch, _FakeEsplora({"spent": True, "txid": spender}, tx_hex={spender: raw.hex()}))
    res = _checked_status(swap, client=_SpentCovenantClient(swap["cov_sh"], tip=130))
    assert res.exit_code == 0, res.output
    assert "Counter-leg (BTC): SPENT_NO_PREIMAGE" in res.output
    assert "situation  : SETTLED" in res.output
    assert "esplora.example reports the BTC leg spent by a transaction that reveals no preimage" in res.output
    assert "one server's answer, not a verified fact" in res.output
    assert "DO-NOT-PRINT" not in res.output

    js = _checked_status(swap, client=_SpentCovenantClient(swap["cov_sh"], tip=130), output_mode="json")
    doc = json.loads(js.output)
    assert doc["counter_leg"]["source"] == "esplora.example"
    assert "esplora.example reports" in doc["chain"]["next_action"]


# --------------------------------------------------------------------------- refund advice, per writer
#
# Each recovery-file shape `swap status` accepts, as its writer emits it (fields read from the
# scripts, not invented), driven through the real CLI to the COVENANT_SPENT advice. None of these
# writers has a phase that refunds only the counter-leg, so none may be told to run one.

_ETH_REFUND_TO = "0x" + "ab" * 20
_FAR_PAST_TS = 1_000_000_000  # 2001
_FAR_FUTURE_TS = 4_000_000_000  # 2096


def _writer_record(swap, shape: str) -> dict[str, Any]:
    base = {
        "hashlock_H": H.hex(),
        "rxd_covenant_spk": swap["cov"].funded_spk.hex(),
        "t_rxd_blocks": 20,
        "rxd_network": "bc",
        "taker_rxd_wif": swap["taker"].wif(),
    }
    if shape == "dust_swap_run":
        return {
            **base,
            "stage": "dust",
            "btc_network": "bc",
            "taker_btc_wif": PrivateKey().wif(),
            "btc_refund_payout_spk": "0014" + "22" * 20,
            "t_btc_blocks": 30,
            "btc_htlc_address": "bc1qexample",
        }
    if shape == "eth_swap_run":
        return {
            **base,
            "stage": "sepolia-dust",
            "eth_chain": "sepolia",
            "eth_chain_id": 11155111,
            "eth_refund_to": _ETH_REFUND_TO,
            "eth_timeout_unix_s": _FAR_FUTURE_TS,
        }
    if shape == "eth_swap_grief_run":
        # The grief run writes NO `eth_chain`; its ETH swap used to be classified BTC.
        return {
            **base,
            "scenario": "grief-S1",
            "eth_refund_to": _ETH_REFUND_TO,
            "eth_timeout_unix_s": _FAR_PAST_TS,
            "eth_amount_wei": 10**14,
        }
    assert shape == "unknown"
    return base


@pytest.mark.parametrize(
    ("shape", "chain", "expected"),
    [
        (
            "dust_swap_run",
            "BTC",
            [
                "scripts/dust_swap_run.py, which wrote this file, has no phase that refunds only that leg",
                "opens 30 BTC blocks after the HTLC funding confirmed",
                "this file holds the refund key as `taker_btc_wif`",
                "NO timelock",
            ],
        ),
        (
            "eth_swap_run",
            "ETH",
            [
                "scripts/eth_swap_run.py, which wrote this file, has no phase that refunds only that leg",
                f"refund() opens at unix time {_FAR_FUTURE_TS} (2096-10-02 07:06:40 UTC; still ahead)",
                f"`eth_refund_to` = {_ETH_REFUND_TO}",
            ],
        ),
        (
            "eth_swap_grief_run",
            "ETH",
            [
                "scripts/eth_swap_grief_run.py, which wrote this file, has no phase that refunds only that leg",
                f"refund() opens at unix time {_FAR_PAST_TS} (2001-09-09 01:46:40 UTC; already passed)",
                f"`eth_refund_to` = {_ETH_REFUND_TO}",
            ],
        ),
        (
            "unknown",
            "BTC",
            [
                "this file matches none of the in-tree harnesses, so pyrxd cannot name the tool that wrote it",
                "which this file does not record",
                "Refund it with the tool that funded it.",
            ],
        ),
    ],
)
def test_the_counter_leg_refund_advice_is_runnable_or_says_plainly_there_is_none(swap, shape, chain, expected) -> None:
    swap["keys"].write_text(json.dumps(_writer_record(swap, shape)))
    res = _status(swap, client=_SpentCovenantClient(swap["cov_sh"], tip=130))
    assert res.exit_code == 0, res.output
    assert f"Counter-leg ({chain}): NOT_CHECKED" in res.output
    assert "situation  : COVENANT_SPENT" in res.output
    assert f"pyrxd has no command that refunds the {chain} leg" in res.output
    assert f"Your {chain} stays locked until refunded" in res.output
    for fragment in expected:
        assert fragment in res.output, fragment
    # Never a command that cannot run from this file. (Scoped to the advice line: the
    # NOT_CHECKED reason below it mentions eth_swap_two_host.py as history, not as advice.)
    (action,) = [ln for ln in res.output.splitlines() if ln.startswith("  next action:")]
    assert "--phase" not in action
    assert "two_host" not in action


def _two_host_local_file(tmp_path: Path, harness: str, role: str) -> Path:
    """A two-host ``--local-out`` file, with the fields that harness's intro/envelope phase writes."""
    if harness == "btc" and role == "taker":
        doc = {
            "role": "taker",
            "taker_rxd_wif": PrivateKey().wif(),
            "taker_pkh_hex": "11" * 20,
            "taker_btc_refund_wif": PrivateKey().wif(),
            "taker_btc_refund_xonly_hex": "22" * 32,
        }
    elif harness == "btc":
        doc = {
            "role": "maker",
            "hashlock_H_hex": H.hex(),
            "maker_rxd_wif": PrivateKey().wif(),
            "maker_pkh_hex": "11" * 20,
            "taker_pkh_hex": "33" * 20,
            "maker_btc_claim_privkey_hex": os.urandom(32).hex(),
            "btc_claim_xonly_hex": "44" * 32,
            "taker_btc_refund_xonly_hex": "22" * 32,
            "covenant_spk_hex": "c4" * 40,
        }
    elif role == "taker":
        doc = {
            "role": "taker",
            "taker_rxd_wif": PrivateKey().wif(),
            "taker_pkh_hex": "11" * 20,
            "eth_key_hex": os.urandom(32).hex(),
            "eth_taker_refund_addr": _ETH_REFUND_TO,
        }
    else:
        doc = {
            "role": "maker",
            "hashlock_H_hex": H.hex(),
            "maker_rxd_wif": PrivateKey().wif(),
            "maker_pkh_hex": "11" * 20,
            "taker_pkh_hex": "33" * 20,
            "eth_key_hex": os.urandom(32).hex(),
            "eth_maker_claim_addr": "0x" + "cd" * 20,
            "eth_taker_refund_addr": _ETH_REFUND_TO,
            "eth_timeout_unix_s": _FAR_FUTURE_TS,
            "covenant_spk_hex": "c4" * 40,
        }
    path = tmp_path / f".{harness}_{role}_local.json"
    path.write_text(json.dumps(doc))
    path.chmod(0o600)
    return path


def _status_of(path: Path):
    return _invoke(["status", "--swap-file", str(path)], _ctx())


@pytest.mark.parametrize("harness", ["btc", "eth"])
def test_a_two_host_taker_file_is_pointed_at_that_harnesss_own_abort_phase(tmp_path, harness) -> None:
    path = _two_host_local_file(tmp_path, harness, "taker")
    res = _status_of(path)
    assert res.exit_code != 0
    out = " ".join(res.output.split())  # click wraps nothing, but be robust to it
    script = f"{harness}_swap_two_host.py"
    assert f"TAKER's local secret file from scripts/{script}" in out
    assert "--role taker --phase abort --io DIR" in out
    assert f"--local-out {path}" in out
    assert "must hold envelope.json and taker_funding.json" in out
    # Run from this checkout the script is really there, and the command names it by that path.
    here = swap_cmds._in_tree_script(script)
    assert here is not None and here.is_file()
    assert f"python {here} --role taker --phase abort" in out


@pytest.mark.parametrize("harness", ["btc", "eth"])
def test_a_two_host_maker_file_is_pointed_at_the_makers_recovery_phases(tmp_path, harness) -> None:
    res = _status_of(_two_host_local_file(tmp_path, harness, "maker"))
    assert res.exit_code != 0
    out = " ".join(res.output.split())
    assert f"MAKER's local secret file from scripts/{harness}_swap_two_host.py" in out
    assert "--role maker --phase abort" in out
    assert "--phase refund" in out
    assert "--role taker" not in out


def test_on_a_pip_install_the_two_host_advice_says_where_the_script_is_not(tmp_path, monkeypatch) -> None:
    """``scripts/`` ships in the sdist only. Without it, never present the path as runnable HERE."""
    monkeypatch.setattr(swap_cmds, "_in_tree_script", lambda name: None)
    res = _status_of(_two_host_local_file(tmp_path, "btc", "taker"))
    assert res.exit_code != 0
    out = " ".join(res.output.split())
    assert "not part of pyrxd as installed here" in out
    assert "from the source checkout you ran the swap from" in out
    assert "from the source tree at" not in out


def test_the_status_block_count_is_the_legs_own_figure(swap) -> None:
    """``claim_asset`` sizes its fee against ``t_rxd - confirmations``; the status screen
    used to print ``funding_height + t_rxd - tip``, one block more than that."""
    from pyrxd.gravity.radiant_leg import blocks_to_claim_deadline

    res = _status(swap, client=_client(swap, confirmations=5), output_mode="json")
    assert res.exit_code == 0, res.output
    chain = json.loads(res.output)["chain"]
    assert chain["depth"] == 5
    # The known answer, from the fixture: t_rxd 20, 5 confirmations deep.
    assert chain["blocks_to_refund"] == 15
    assert chain["blocks_to_refund"] == blocks_to_claim_deadline(20, chain["depth"])

    human = _status(swap, client=_client(swap, confirmations=5))
    assert "15 block(s) remain" in human.output
    assert "16 block" not in human.output
