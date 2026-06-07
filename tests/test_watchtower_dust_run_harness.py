"""Unit tests for the Go-gated dust-run harness (scripts/watchtower_dust_run.py).

These are the regression guard for the stranded-dust incident: an HTLC was funded whose refund could
not be reconstructed (the maker x-only pubkey was never persisted). The harness now REFUSES to print a
funding address unless a refund rebuilds purely from the on-disk state, so these tests assert the gate
(``_self_test``) fail-closes on every way the state could be incomplete/corrupt, and that the artifacts
the harness produces (SwapRecord + pre-signed sidecar) satisfy ALL of the production executor's binds.

No docker here — the consensus proof (real bitcoind broadcast) is the integration test
``test_xchain_swap_regtest_e2e.py::TestWatchtowerDustHarnessRegtest``.
"""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest

from pyrxd.btc_wallet import taproot as t
from pyrxd.gravity.swap_state import SwapRecord
from pyrxd.gravity.watch import Decision, ExecOutcome, PresignedRefund, RefundExecutor
from pyrxd.gravity.watch.decide import Intent
from pyrxd.security.errors import ValidationError

_SCRIPTS = str(Path(__file__).resolve().parent.parent / "scripts")
if _SCRIPTS not in sys.path:
    sys.path.insert(0, _SCRIPTS)

import watchtower_dust_run as harness

# A standard P2WPKH refund scriptPubKey for tests. The MAINNET run uses 2000 sats / t_btc=2 / t_rxd=1,
# so the unit tests exercise that exact config.
_REFUND_SPK_HEX = "0014" + "11" * 20
_RUN = dict(btc_sats=2000, t_btc=2, t_rxd=1, network="bcrt")


def _setup(tmp_path: Path, **overrides) -> Path:
    """Run `setup` and return the state-file path (the self-test gate runs inside)."""
    state = tmp_path / "run.state.json"
    cfg = {**_RUN, **overrides}
    rc = harness.main(
        [
            "setup",
            "--state-file",
            str(state),
            "--swap-id",
            overrides.get("swap_id", "dust1"),
            "--network",
            cfg["network"],
            "--btc-sats",
            str(cfg["btc_sats"]),
            "--t-btc",
            str(cfg["t_btc"]),
            "--t-rxd",
            str(cfg["t_rxd"]),
            "--refund-spk",
            overrides.get("refund_spk", _REFUND_SPK_HEX),
        ]
    )
    assert rc == 0
    return state


class _FakeBroadcaster:
    """Satisfies the BtcBroadcaster protocol without a node — records the bytes it would send."""

    def __init__(self) -> None:
        self.calls: list[bytes] = []

    async def broadcast(self, raw_tx: bytes) -> str:
        self.calls.append(bytes(raw_tx))
        return t.btc_txid_from_raw(raw_tx)


def test_setup_passes_self_test_and_persists_the_full_reconstruction_set(tmp_path):
    state_path = _setup(tmp_path)
    s = json.loads(state_path.read_text())
    # The field whose loss stranded the prior dust MUST now be persisted.
    assert s["maker_claim_pubkey_xonly"] and len(bytes.fromhex(s["maker_claim_pubkey_xonly"])) == 32
    assert s["taker_refund_privkey"] and s["htlc_address"].startswith("bcrt1p")
    # File is 0600 (custody-sensitive — holds the key controlling the dust).
    assert (state_path.stat().st_mode & 0o777) == 0o600


def test_reconstruct_is_keyless_from_disk_and_matches_persisted_address(tmp_path):
    s = json.loads(_setup(tmp_path).read_text())
    htlc = harness.reconstruct_htlc(s)  # pure: builds the address/SPK with no in-memory carry-over
    assert htlc.address == s["htlc_address"]
    assert htlc.scriptpubkey.hex() == s["htlc_spk"]


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(lambda s: s.update(maker_claim_pubkey_xonly="11" * 32), id="wrong_maker_pubkey"),
        pytest.param(lambda s: s.update(htlc_address=s["htlc_address"][:-4] + "aaaa"), id="tampered_address"),
        pytest.param(lambda s: s.update(refund_spk=""), id="empty_refund_spk"),
        pytest.param(lambda s: s.update(refund_spk="6a04deadbeef"), id="op_return_refund_spk"),
        pytest.param(lambda s: s.update(t_btc_blocks=s["t_btc_blocks"] + 1), id="timelock_drift"),
    ],
)
def test_self_test_fails_closed_on_incomplete_or_corrupt_state(tmp_path, mutate):
    good = json.loads(_setup(tmp_path).read_text())
    bad = copy.deepcopy(good)
    mutate(bad)
    bad_path = tmp_path / "bad.state.json"
    bad_path.write_text(json.dumps(bad))
    with pytest.raises((ValidationError, Exception)):
        harness._self_test(bad_path)


def test_setup_refuses_a_nonstandard_refund_spk(tmp_path):
    with pytest.raises(SystemExit):
        _setup(tmp_path, refund_spk="dead")  # not a standard spendable scriptPubKey
    # and a half-baked state must NOT be left behind to be funded
    assert not (tmp_path / "run.state.json").exists()


def test_setup_refuses_when_t_btc_not_longer_than_t_rxd(tmp_path):
    with pytest.raises(SystemExit):
        _setup(tmp_path, t_btc=2, t_rxd=2)


async def test_harness_artifacts_satisfy_every_executor_bind(tmp_path):
    """In-process proof (no docker): the SwapRecord + sidecar the harness produces are reconstructed
    from disk and ACCEPTED by the production RefundExecutor — every bind (prevout, nSequence CSV, pinned
    SPK, cap, value) holds, so the keyless tower would broadcast them."""
    s = json.loads(_setup(tmp_path).read_text())
    outpoint = t.BtcOutpoint("aa" * 32, 0)  # a stand-in funded outpoint

    # The two on-disk artifacts, built from the persisted state alone.
    record = harness.build_record(s, outpoint)
    raw = harness.build_refund_from_state(s, outpoint, fee_sats=300)
    (tmp_path / "dust1.refund.json").write_text(json.dumps(PresignedRefund(raw_tx=raw, swap_id="dust1").to_dict()))

    # The record round-trips through the production serialization and still binds.
    record = SwapRecord.from_dict(record.to_dict())
    assert record.btc_locator is not None and record.btc_locator.network == "bcrt"

    ex = RefundExecutor(
        broadcaster=_FakeBroadcaster(),
        blobs_dir=tmp_path,
        network="bcrt",
        cap_sats=_RUN["btc_sats"],
        refund_spk=bytes.fromhex(_REFUND_SPK_HEX),
        accept_single_source=True,
    )
    decision = Decision(
        Intent.PAGE_REFUND,
        reason="matured BTC refund due (maker never locked)",
        recommended_action="taker_refund_btc",
        autonomous_btc_refund=True,
        low_corroboration=True,
    )
    out = await ex.execute("dust1", record, decision)
    assert out is ExecOutcome.BROADCAST, "the harness's record+sidecar must satisfy every executor bind"


def _record(state_path: Path, records_dir: Path, *, txid: str = "aa" * 32, vout: int = 0, sats: int = 2000) -> int:
    return harness.main(
        [
            "record",
            "--state-file",
            str(state_path),
            "--funding-txid",
            txid,
            "--funding-vout",
            str(vout),
            "--funding-sats",
            str(sats),
            "--records-dir",
            str(records_dir),
        ]
    )


def test_record_refuses_post_setup_taptree_drift(tmp_path):
    # The skeptic-found gap: the reconstruct-from-disk gate ran ONLY at setup. After setup, corrupting the
    # persisted t_btc makes the rebuilt taptree differ from the FUNDED address/SPK; `record` must fail
    # closed rather than write a SwapRecord that strands the dust on an unspendable refund.
    state_path = _setup(tmp_path)
    records = tmp_path / "records"
    records.mkdir()
    s = json.loads(state_path.read_text())
    s["t_btc_blocks"] += 1
    state_path.write_text(json.dumps(s))
    with pytest.raises(SystemExit):
        _record(state_path, records)
    assert not (records / "dust1.json").exists()


def test_presign_refuses_after_post_record_drift(tmp_path):
    # presign re-checks drift too (defense in depth): a record written from good state, then a drifted
    # state, must not yield a signed-but-unspendable refund.
    state_path = _setup(tmp_path)
    records = tmp_path / "records"
    records.mkdir()
    assert _record(state_path, records) == 0
    s = json.loads(state_path.read_text())
    s["t_btc_blocks"] += 1
    state_path.write_text(json.dumps(s))
    with pytest.raises(SystemExit):
        harness.main(["presign", "--state-file", str(state_path), "--records-dir", str(records), "--fee-sats", "300"])


def test_presign_refuses_sub_dust_refund_output(tmp_path):
    # A fat-fingered fee that leaves a sub-dust output would be non-relayable; reject at presign (fail-loud
    # at setup time, not silently at broadcast).
    state_path = _setup(tmp_path)  # 2000 sats
    records = tmp_path / "records"
    records.mkdir()
    assert _record(state_path, records) == 0
    with pytest.raises(SystemExit):
        harness.main(["presign", "--state-file", str(state_path), "--records-dir", str(records), "--fee-sats", "1999"])
    # a sane fee (output well above the 546-sat dust floor) succeeds
    assert (
        harness.main(["presign", "--state-file", str(state_path), "--records-dir", str(records), "--fee-sats", "300"])
        == 0
    )
    assert (records / "dust1.refund.json").is_file()


def test_state_file_stays_0600_through_record_and_presign(tmp_path):
    # The atomic 0600 write must hold the key file private across every rewrite (no TOCTOU widening).
    state_path = _setup(tmp_path)
    records = tmp_path / "records"
    records.mkdir()
    assert _record(state_path, records) == 0
    assert (state_path.stat().st_mode & 0o777) == 0o600
    assert (
        harness.main(["presign", "--state-file", str(state_path), "--records-dir", str(records), "--fee-sats", "300"])
        == 0
    )
    assert (state_path.stat().st_mode & 0o777) == 0o600
