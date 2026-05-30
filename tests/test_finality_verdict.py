"""Tests for the per-leg claim-finality verdict (gravity.finality) + the ETH producer.

The gate-side behaviour (verdict → SAFE/WAIT/SQUEEZED) is covered in test_swap_coordinator;
here we cover the verdict type itself and the ETH leg's verdict producer (with a fake RPC).
"""

from __future__ import annotations

import pytest

from pyrxd.eth_wallet.htlc_leg import EthHtlcContractLeg
from pyrxd.gravity.finality import CounterClaimFinality, CounterClaimState
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
