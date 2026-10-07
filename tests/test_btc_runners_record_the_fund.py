"""The BTC runners must persist the swap record, and resume an interrupted fund from it.

``SwapCoordinator.taker_funds_btc`` records the BTC funding transaction before broadcasting it and
refuses a value-bearing BTC fund without a persist hook (see test_btc_fund_interrupted_resume.py,
which proves the coordinator behaviour against the real BitcoinTaprootLeg). That record is only
worth anything if the runners write it and read it back. These tests pin the runner side:

* every shipped script that calls ``taker_funds_btc`` constructs its coordinator with ``persist=``
  (the set is DERIVED from the scripts, not listed);
* ``btc_swap_two_host``'s taker fund phase resumes THIS swap's interrupted fund from the record file
  instead of building a new one, and takes the forward path otherwise;
* ``dust_swap_resume`` reads the funding txid from the record when the operator does not pass it.

The two-host test drives the real ``taker_phase_fund`` with spies at the coordinator boundary: what
is under test here is the runner's choice of entry point, not the coordinator behind it.
"""

from __future__ import annotations

import ast
import asyncio
import dataclasses
from pathlib import Path

import pytest

from pyrxd.btc_wallet import taproot as bt
from pyrxd.btc_wallet.keys import generate_keypair
from pyrxd.btc_wallet.payment import BtcUtxo, build_payment_tx
from pyrxd.gravity.record_sink import JsonFileRecordSink
from pyrxd.gravity.swap_state import SwapRecord, SwapState
from tests import test_two_host_recovery_phases as H

_SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"


def _coordinator_calls(tree: ast.AST) -> list[ast.Call]:
    return [
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.Call) and getattr(n.func, "id", getattr(n.func, "attr", None)) == "SwapCoordinator"
    ]


def test_every_script_that_funds_btc_builds_its_coordinator_with_a_persist_hook():
    funding_scripts = []
    for path in sorted(_SCRIPTS.glob("*.py")):
        src = path.read_text()
        if ".taker_funds_btc(" not in src:
            continue
        funding_scripts.append(path.name)
        calls = _coordinator_calls(ast.parse(src))
        assert calls, f"{path.name} funds through a coordinator it never constructs?"
        for call in calls:
            assert "persist" in {k.arg for k in call.keywords}, (
                f"{path.name}:{call.lineno} builds a SwapCoordinator without persist= but funds BTC; a value-"
                "bearing fund is refused without it, and a failed readback leaves nothing to resume from"
            )
    # Non-vacuity: the BTC and ETH runners all fund. If this finds fewer, the scan is broken.
    assert {"dust_swap_run.py", "btc_swap_two_host.py", "eth_swap_run.py"} <= set(funding_scripts), funding_scripts


def _signed_funding_tx_hex(terms) -> str:
    """A real signed transaction (any one parses); the record checks structure, not ownership."""
    kp = generate_keypair("bcrt")
    payment = build_payment_tx(
        kp,
        BtcUtxo(txid="cd" * 32, vout=0, value=terms.btc_sats * 3),
        to_hash=b"\x11" * 32,
        to_type="p2tr",
        amount_sats=terms.btc_sats,
        fee_sats=1_000,
    )
    return payment.tx_hex


def _taker_fund_harness(btc_mod, tmp_path, monkeypatch):
    args, terms, _io = H._btc_scenario(btc_mod, tmp_path, role="taker", with_funding=False, phase="fund")
    args = H._with_fee(args)
    args.btc_funding_txid, args.btc_funding_vout, args.btc_funding_value = "ef" * 32, 0, 300_000
    H._wire_btc(btc_mod, monkeypatch)

    async def _verified(coord, terms, *, now_unix_s):
        return ("ab" * 32 + ":0", terms.radiant_amount, 6)

    monkeypatch.setattr(btc_mod, "_taker_verify_rxd_funding", _verified)
    called: list[str] = []
    htlc = bt.build_htlc(
        hashlock=terms.hashlock,
        claim_pubkey_xonly=terms.btc_claim_pubkey_xonly,
        refund_pubkey_xonly=terms.btc_refund_pubkey_xonly,
        timeout=terms.t_btc,
        network="bcrt",
    )
    locked = htlc.with_funding(bt.BtcOutpoint("aa" * 32, 0), terms.btc_sats)

    async def _forward(self, terms, *, now_unix_s=None):
        called.append("taker_funds_btc")
        return self.record.with_counter_lock(locked).with_state(SwapState.BTC_LOCKED)

    async def _resume(self, terms, *, sink, now_unix_s):
        called.append("resume_interrupted_fund")
        assert sink.path == Path(args.local_out + ".swaprec.json")
        return self.record.with_counter_lock(locked).with_state(SwapState.BTC_LOCKED)

    monkeypatch.setattr(btc_mod.SwapCoordinator, "taker_funds_btc", _forward)
    monkeypatch.setattr(btc_mod.SwapCoordinator, "resume_interrupted_fund", _resume)
    return args, terms, called


def test_the_two_host_taker_resumes_this_swaps_interrupted_fund_from_the_record(tmp_path, monkeypatch):
    btc_mod = H._load("btc_swap_two_host")
    args, terms, called = _taker_fund_harness(btc_mod, tmp_path, monkeypatch)
    pending = SwapRecord(state=SwapState.NEGOTIATED, terms=terms, pending_btc_funding_tx=_signed_funding_tx_hex(terms))
    asyncio.run(JsonFileRecordSink(args.local_out + ".swaprec.json")(pending))
    asyncio.run(btc_mod.taker_phase_fund(args))
    assert called == ["resume_interrupted_fund"]


def test_the_two_host_taker_funds_forward_when_there_is_no_interrupted_fund(tmp_path, monkeypatch):
    btc_mod = H._load("btc_swap_two_host")
    args, _terms, called = _taker_fund_harness(btc_mod, tmp_path, monkeypatch)
    asyncio.run(btc_mod.taker_phase_fund(args))
    assert called == ["taker_funds_btc"]


def test_the_two_host_coordinator_writes_the_record_beside_the_run_keys(tmp_path):
    btc_mod = H._load("btc_swap_two_host")
    sink = btc_mod._record_sink(str(tmp_path / "run.json"))
    assert sink.path == Path(str(tmp_path / "run.json") + ".swaprec.json")


class TestDustResumeReadsTheTxidFromTheRecord:
    def _mod(self):
        return H._load("dust_swap_resume")

    def _terms(self, tmp_path, monkeypatch):
        btc_mod = H._load("btc_swap_two_host")
        _args, terms, _io = H._btc_scenario(btc_mod, tmp_path, role="taker", with_funding=False)
        return terms

    def test_a_pending_fund(self, tmp_path, monkeypatch):
        terms = self._terms(tmp_path, monkeypatch)
        keys = str(tmp_path / "keys.json")
        rec = SwapRecord(state=SwapState.NEGOTIATED, terms=terms, pending_btc_funding_tx=_signed_funding_tx_hex(terms))
        asyncio.run(JsonFileRecordSink(keys + ".swaprec.json")(rec))
        assert self._mod()._funding_txid_from_record(keys) == rec.pending_btc_funding_txid

    def test_a_completed_fund(self, tmp_path, monkeypatch):
        terms = self._terms(tmp_path, monkeypatch)
        keys = str(tmp_path / "keys.json")
        htlc = bt.build_htlc(
            hashlock=terms.hashlock,
            claim_pubkey_xonly=terms.btc_claim_pubkey_xonly,
            refund_pubkey_xonly=terms.btc_refund_pubkey_xonly,
            timeout=terms.t_btc,
            network="bcrt",
        )
        rec = dataclasses.replace(
            SwapRecord(state=SwapState.NEGOTIATED, terms=terms).with_counter_lock(
                htlc.with_funding(bt.BtcOutpoint("aa" * 32, 0), terms.btc_sats)
            ),
            state=SwapState.BTC_LOCKED,
        )
        asyncio.run(JsonFileRecordSink(keys + ".swaprec.json")(rec))
        assert self._mod()._funding_txid_from_record(keys) == "aa" * 32

    def test_no_record_is_refused_not_guessed(self, tmp_path):
        with pytest.raises(SystemExit, match="no swap record"):
            self._mod()._funding_txid_from_record(str(tmp_path / "keys.json"))
