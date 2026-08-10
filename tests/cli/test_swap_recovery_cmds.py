"""CLI tests for the cold toolkit: ``swap recover-preimage`` / ``build-claim`` / ``build-refund``.

Every chain read is a fake whose ``broadcast`` raises, so "these commands never
broadcast" is asserted at runtime and not merely by inspection. The recovery file used
throughout carries a recognisable ``preimage_p_hex`` and WIFs that must never appear in
any output.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
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
    assert "is UNSPENT" in res.output


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
