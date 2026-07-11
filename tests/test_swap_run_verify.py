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


# ─────────────────── audit follow-ups: asset-leg provenance + value gates ───────────────────

from pyrxd.script.script import Script
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput


def _rxd_tx(out_spk: bytes, value: int = 1000, spend_txid: str = "ab" * 32) -> bytes:
    """A synthetic RXD tx whose single input spends spend_txid:0 and whose output[0] is out_spk."""
    tx = Transaction()
    tx.add_input(TransactionInput(source_txid=spend_txid, source_output_index=0, unlocking_script=Script(b"")))
    tx.add_output(TransactionOutput(locking_script=Script(out_spk), satoshis=value))
    return tx.serialize()


def test_asset_leg_rejects_decoy_that_does_not_spend_the_covenant():
    """Audit C1 (CRITICAL): the free-option false-PASS. A spend paying the taker holder but NOT consuming
    the covenant outpoint must be ANOMALOUS, not TAKER_CLAIMED — otherwise a genuine one-sided loss (maker
    refunds the asset AND claims the counter) scores PASS by citing a decoy txid."""
    m = _m()  # covenant_funding = ab*32:0
    funded, taker_holder, _maker_holder = v.rxd_expected_scripts(m)
    funding = _rxd_tx(funded)
    honest_claim = _rxd_tx(taker_holder, spend_txid="ab" * 32)  # spends the covenant
    decoy = _rxd_tx(taker_holder, spend_txid="00" * 32)  # pays taker, does NOT spend the covenant

    assert v.verify_asset_leg(m, funding, honest_claim)[0] is v.AssetLeg.TAKER_CLAIMED
    assert v.verify_asset_leg(m, funding, decoy)[0] is v.AssetLeg.ANOMALOUS

    # End-to-end: the decoy can no longer flip a real one-sided loss to PASS.
    p = b"\xab" * 32
    m2 = v.RunManifest(
        swap_id="t2",
        asset_variant="rxd",
        counter_chain="btc",
        honest_party="taker",
        h_hex=v._sha256(p).hex(),
        taker_pkh_hex="22" * 20,
        maker_pkh_hex="33" * 20,
        rxd_amount=1000,
        refund_csv=48,
        covenant_funding=v.Outpoint("ab" * 32, 0),
        counter_funding=v.Outpoint("cd" * 32, 0),
    )
    f2, t2_holder, m2_holder = v.rxd_expected_scripts(m2)
    btc_claim = v._btc_claim_stub(m2, p)  # maker claimed the counter (revealed p)
    real_refund = _rxd_tx(m2_holder, spend_txid="ab" * 32)  # asset really refunded to the maker
    assert v.run_verify(m2, _rxd_tx(f2), real_refund, btc_claim).verdict is v.Verdict.FAIL_ONE_SIDED
    decoy_claim = _rxd_tx(t2_holder, spend_txid="00" * 32)  # decoy paying the taker
    assert v.run_verify(m2, _rxd_tx(f2), decoy_claim, btc_claim).verdict is not v.Verdict.PASS


def test_asset_leg_value_integrity_is_verdict_affecting():
    """Audit F-B3: under-funded covenant and short-changed payout are ANOMALOUS, not note-only warnings."""
    m = _m()
    funded, taker_holder, _ = v.rxd_expected_scripts(m)  # m.rxd_amount == 1000
    claim = _rxd_tx(taker_holder, spend_txid="ab" * 32)
    assert v.verify_asset_leg(m, _rxd_tx(funded, value=500), claim)[0] is v.AssetLeg.ANOMALOUS  # under-funded
    short = _rxd_tx(taker_holder, value=900, spend_txid="ab" * 32)
    assert v.verify_asset_leg(m, _rxd_tx(funded, 1000), short)[0] is v.AssetLeg.ANOMALOUS  # short-changed


def test_assert_no_secrets_hardening():
    """Audit MED-2: named private-key fields and WIF-shaped values are caught; a clean journal full of
    64-hex txids is NOT a false positive (a raw preimage is shape-identical to a txid, so it is guarded by
    key name, never by a hex value scan)."""
    import pytest

    for doc in (
        {"maker_private_key": "x"},
        {"xprv": "x"},
        {"account_priv_key": "x"},
        {"note": "5Kb8kLf9zgWQnogidDA76MzPL6TsZZY36hWXMssSzNydYXYB9KF"},
    ):
        with pytest.raises(ValueError):
            v.assert_no_secrets(doc, what="journal")
    # clean journal: 64-hex txids everywhere must pass.
    v.assert_no_secrets(
        {"steps": [{"txid": "cd" * 32, "spend_txid": "ab" * 32, "state": "COMPLETED", "height": 444076}]},
        what="journal",
    )


def test_eth_creation_bytecode_pin_matches_fixture():
    """Audit HIGH: the ETH recipient binding pins the deployed contract to the canonical EthHtlc CREATION
    bytecode. If the fixture is recompiled without updating the pin, this fails CI (drift guard) — a stale
    pin would reject the real contract, a stale fixture would let a look-alike pass."""
    import hashlib
    import json

    fixture = json.loads((Path(__file__).resolve().parent.parent / "tests/fixtures/EthHtlc.json").read_text())
    creation = bytes.fromhex(fixture["bytecode"][2:] if fixture["bytecode"].startswith("0x") else fixture["bytecode"])
    assert hashlib.sha256(creation).digest() == v._ETH_HTLC_CREATION_SHA256


def test_pass_unverified_downgrade_is_distinct():
    """Audit HIGH (H-2): a both-complete PASS whose counter CLAIM was not recipient/value-verified must be a
    DISTINCT verdict, not a clean PASS that automation conflates with a fully-checked one."""
    p = b"\xcd" * 32
    m2 = v.RunManifest(
        swap_id="u",
        asset_variant="rxd",
        counter_chain="btc",
        honest_party="taker",
        h_hex=v._sha256(p).hex(),
        taker_pkh_hex="22" * 20,
        maker_pkh_hex="33" * 20,
        rxd_amount=1000,
        refund_csv=48,
        covenant_funding=v.Outpoint("ab" * 32, 0),
        counter_funding=v.Outpoint("cd" * 32, 0),
    )
    f2, t2_holder, _ = v.rxd_expected_scripts(m2)
    btc_claim = v._btc_claim_stub(m2, p)
    res = v.run_verify(m2, _rxd_tx(f2), _rxd_tx(t2_holder, spend_txid="ab" * 32), btc_claim)
    assert res.verdict is v.Verdict.PASS_UNVERIFIED
    assert res.checks["counter_fully_verified"] is False


def test_secret_guard_lists_are_in_parity():
    """Audit MEDIUM (M-d): the three _SECRET_FORBIDDEN_KEYS copies (verifier + both two-host harnesses) must
    stay a superset of the core private-material markers, and the two harness copies must be identical, so a
    fix to one can't silently leave the others weaker."""
    import btc_swap_two_host as btc
    import eth_swap_two_host as eth

    assert btc._SECRET_FORBIDDEN_KEYS == eth._SECRET_FORBIDDEN_KEYS
    core = {"priv", "secret", "wif", "preimage", "seed", "mnemonic", "entropy", "xprv"}
    for markers in (set(v._SECRET_FORBIDDEN_KEYS), set(btc._SECRET_FORBIDDEN_KEYS)):
        assert core <= markers
    # the "priv" marker closes the class the enumerated list missed.
    for bad in ("private_key", "priv_key", "privatekey", "master_entropy"):
        assert any(mark in bad for mark in btc._SECRET_FORBIDDEN_KEYS)
