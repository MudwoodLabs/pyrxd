"""Tests for the per-leg claim-finality verdict (gravity.finality) + the ETH producer.

The gate-side behaviour (verdict → SAFE/WAIT/SQUEEZED) is covered in test_swap_coordinator;
here we cover the verdict type itself and the ETH leg's verdict producer (with a fake RPC).
"""

from __future__ import annotations

import pytest

from pyrxd.eth_wallet.htlc_leg import EthHtlcContractLeg
from pyrxd.gravity.finality import CounterClaimFinality, CounterClaimState, FinalityStallTracker
from pyrxd.security.errors import ValidationError
from pyrxd.security.secrets import PrivateKeyMaterial

# ─────────────────────────────────────────────────── verdict type ──


def test_from_btc_depth_final_and_not_final():
    v = CounterClaimFinality.from_btc_depth(6, 6)
    assert v.state is CounterClaimState.FINAL
    assert v.confirmations == 6 and v.required_depth == 6
    assert v.remaining_positive is False  # 6 - 6 == 0

    v2 = CounterClaimFinality.from_btc_depth(1, 6)
    assert v2.state is CounterClaimState.NOT_YET_FINAL_LIVE
    assert v2.remaining_positive is True  # 6 - 1 > 0


def test_from_btc_depth_validation():
    with pytest.raises(ValidationError):
        CounterClaimFinality.from_btc_depth(-1, 6)
    with pytest.raises(ValidationError):
        CounterClaimFinality.from_btc_depth(1, -1)
    with pytest.raises(ValidationError):
        CounterClaimFinality.from_btc_depth(True, 6)  # bool is not an int here


def test_eth_style_verdict_has_no_depth_and_reserves_full_window():
    v = CounterClaimFinality(state=CounterClaimState.NOT_YET_FINAL_LIVE)
    assert v.confirmations is None and v.required_depth is None
    assert v.remaining_positive is True  # absent depth → reserve the full window


def test_verdict_rejects_bad_fields():
    with pytest.raises(ValidationError):
        CounterClaimFinality(state="final")  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        CounterClaimFinality(state=CounterClaimState.FINAL, confirmations=-1)


# ─────────────────────────────────────────── ETH producer (fake RPC) ──


class _FakeRpc:
    def __init__(self, *, status=1, block=None, finalized=0):
        self._status, self._block, self._finalized = status, block, finalized

    async def wait_receipt(self, tx_hash):
        return {"status": self._status, "blockNumber": self._block}

    async def finalized_block_number(self):
        return self._finalized


def _leg(rpc):
    return EthHtlcContractLeg(
        rpc=rpc,
        signing_key=PrivateKeyMaterial.generate(),
        chain_id=11155111,
        artifact={"abi": [], "bytecode": "0x00", "runtime_bytecode": "0x00"},
    )


async def test_eth_verdict_final():
    leg = _leg(_FakeRpc(status=1, block=100, finalized=120))  # block <= finalized
    assert (await leg.claim_finality_verdict("0xabc")).state is CounterClaimState.FINAL


async def test_eth_verdict_reverted_is_not_final():
    leg = _leg(_FakeRpc(status=0, block=100, finalized=120))
    assert (await leg.claim_finality_verdict("0xabc")).state is CounterClaimState.NOT_YET_FINAL_LIVE


async def test_eth_verdict_not_yet_final():
    leg = _leg(_FakeRpc(status=1, block=200, finalized=120))  # block > finalized
    assert (await leg.claim_finality_verdict("0xabc")).state is CounterClaimState.NOT_YET_FINAL_LIVE


async def test_eth_verdict_point_in_time_never_emits_stall():
    # The point-in-time producer never returns COUNTER_CHAIN_NOT_FINALIZING: a non-advancing
    # `finalized` over a single observation is normal (post-Merge finalizes at epoch
    # boundaries, ~6.4 min), not a stall. Detecting a genuine non-finality stall — finalized
    # stuck for >= a patience window — is the coordinator polling loop's job (Phase-3 wiring).
    leg = _leg(_FakeRpc(status=1, block=200, finalized=120))  # not final; finalized "stuck"
    v = await leg.claim_finality_verdict("0xabc")
    assert v.state is CounterClaimState.NOT_YET_FINAL_LIVE


# ─────────────────────────────────────────────── RF-06 stall tracker ──


def test_stall_tracker_healthy_finalization_never_stalls():
    """Finalized advancing each epoch → never declares a stall, even over a long run."""
    t = FinalityStallTracker()
    head, fin = 1000, 800
    for _ in range(50):
        head += 32  # one epoch of head progress
        fin += 32  # finalized keeps pace (healthy)
        assert t.observe(head_block=head, finalized_block=fin) is False


def test_stall_tracker_declares_after_patience_with_wide_gap():
    """Finalized frozen while the head climbs past the patience window AND the gap exceeds the
    normal lag → stall declared. Mirrors the live Sepolia incident."""
    t = FinalityStallTracker()  # patience 128 slots, max-normal-lag 96 slots
    fin = 5000
    # First sample establishes the frozen-finalized run at head 5100 (gap 100).
    assert t.observe(head_block=5100, finalized_block=fin) is False
    # Head climbs while finalized stays put. Not yet enough head progress / gap.
    assert t.observe(head_block=5150, finalized_block=fin) is False  # progress 50 < 128
    # Head now 128+ past run start AND gap > 96 → STALL.
    assert t.observe(head_block=5100 + 130, finalized_block=fin) is True


def test_stall_tracker_resets_when_finality_resumes():
    """A fresh finalized value clears the stall (finality is advancing again → live)."""
    t = FinalityStallTracker()
    fin = 7000
    t.observe(head_block=7100, finalized_block=fin)
    assert t.observe(head_block=7100 + 200, finalized_block=fin) is True  # stalled
    # finalized jumps forward → reset, no longer stalled
    assert t.observe(head_block=7400, finalized_block=fin + 64) is False


def test_stall_tracker_needs_BOTH_progress_and_gap():
    """A frozen finalized with lots of head progress but a SMALL gap (e.g. finalized just barely
    behind a slow head) must NOT trip — guards against false positives on a healthy slow epoch."""
    t = FinalityStallTracker()
    fin = 9000
    t.observe(head_block=9010, finalized_block=fin)  # gap only 10
    # Even with huge head progress, the live gap (head-finalized) stays <= 96 here only if head
    # stays close; push head far → gap grows, so to isolate the gap guard, keep gap small:
    # finalized frozen, head advances by 200 but we keep checking — gap becomes 210 > 96, so this
    # WOULD trip. Instead assert the gap guard via a separate tracker with a huge max_normal_lag.
    t2 = FinalityStallTracker(patience_slots=64, max_normal_lag_slots=10_000)
    f2 = 1000
    t2.observe(head_block=1010, finalized_block=f2)
    assert t2.observe(head_block=1010 + 200, finalized_block=f2) is False  # progress ok, gap <= 10000


def test_stall_tracker_verdict_upgrades_not_final_to_not_finalizing():
    """verdict() upgrades NOT_YET_FINAL_LIVE → COUNTER_CHAIN_NOT_FINALIZING on a stall, but
    leaves FINAL untouched."""
    t = FinalityStallTracker()
    fin = 4000
    pit_live = CounterClaimFinality(state=CounterClaimState.NOT_YET_FINAL_LIVE)
    t.verdict(pit_live, head_block=4100, finalized_block=fin)  # establish run
    # below patience → unchanged
    v = t.verdict(pit_live, head_block=4150, finalized_block=fin)
    assert v.state is CounterClaimState.NOT_YET_FINAL_LIVE
    # past patience + gap → upgraded to NOT_FINALIZING (gate will SQUEEZE)
    v = t.verdict(pit_live, head_block=4100 + 130, finalized_block=fin)
    assert v.state is CounterClaimState.COUNTER_CHAIN_NOT_FINALIZING
    # FINAL is always returned unchanged, no matter the stall state
    pit_final = CounterClaimFinality(state=CounterClaimState.FINAL)
    assert t.verdict(pit_final, head_block=4100 + 200, finalized_block=fin).state is CounterClaimState.FINAL


def test_stall_tracker_validates_input():
    t = FinalityStallTracker()
    with pytest.raises(ValidationError):
        t.observe(head_block=-1, finalized_block=0)
    with pytest.raises(ValidationError):
        t.observe(head_block=100, finalized_block=200)  # finalized > head
    with pytest.raises(ValidationError):
        FinalityStallTracker(patience_slots=0)
