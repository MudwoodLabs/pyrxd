"""CI guard for scripts/swap_run_verify.py — the two-party-adversarial-run chain-re-derivation verifier.

The script ships its own exhaustive offline ``--self-check`` (truth table, secret/independence guards, RXD +
BTC + ETH leg dispositions, end-to-end verdicts, lucky-pass margin). This test runs that self-check under
pytest so a regression in the verifier fails CI, plus a few direct assertions on the load-bearing pure
functions (the atomicity truth table must never score a one-sided outcome as a pass).
"""

from __future__ import annotations

import sys
from pathlib import Path

_SCRIPTS = str(Path(__file__).resolve().parent.parent / "scripts")
if _SCRIPTS not in sys.path:
    sys.path.insert(0, _SCRIPTS)

import swap_run_verify as v


def test_self_check_passes():
    assert v._self_check() == 0


def _m() -> v.RunManifest:
    return v.RunManifest(
        swap_id="t",
        asset_variant="rxd",
        counter_chain="btc",
        honest_party="taker",
        h_hex="11" * 32,
        taker_pkh_hex="22" * 20,
        maker_pkh_hex="33" * 20,
        rxd_amount=1000,
        refund_csv=48,
        covenant_funding=v.Outpoint("ab" * 32, 0),
        counter_funding=v.Outpoint("cd" * 32, 0),
    )


def test_truth_table_one_sided_is_never_pass():
    m = _m()
    # free-option: maker holds both legs -> the taker is robbed.
    r = v.atomicity_verdict(m, v.AssetLeg.MAKER_REFUNDED, v.CounterLeg.MAKER_CLAIMED, None, None)
    assert r.verdict is v.Verdict.FAIL_ONE_SIDED
    # the mirror: taker holds both legs -> the maker is robbed.
    r2 = v.atomicity_verdict(m, v.AssetLeg.TAKER_CLAIMED, v.CounterLeg.TAKER_REFUNDED, None, None)
    assert r2.verdict is v.Verdict.FAIL_ONE_SIDED
    # an unspent leg is PENDING, never a PASS.
    r3 = v.atomicity_verdict(m, v.AssetLeg.TAKER_CLAIMED, v.CounterLeg.PENDING, None, None)
    assert r3.verdict is v.Verdict.PENDING


def test_both_complete_and_both_unwind_are_pass():
    m = _m()
    assert (
        v.atomicity_verdict(m, v.AssetLeg.TAKER_CLAIMED, v.CounterLeg.MAKER_CLAIMED, None, None).verdict
        is v.Verdict.PASS
    )
    assert (
        v.atomicity_verdict(m, v.AssetLeg.MAKER_REFUNDED, v.CounterLeg.TAKER_REFUNDED, None, None).verdict
        is v.Verdict.PASS
    )


def test_secret_guard_rejects_leaked_key():
    import pytest

    with pytest.raises(ValueError):
        v.assert_no_secrets({"steps": [{"taker_rxd_wif": "L1.."}]}, what="journal")


def test_independence_guard_rejects_shared_endpoint():
    import pytest

    with pytest.raises(ValueError):
        v.assert_independent_endpoints(["https://x.example/api"], ("https://x.example/api",))
