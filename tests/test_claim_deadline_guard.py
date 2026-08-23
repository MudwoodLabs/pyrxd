"""A claim must not be broadcast without room to be included before the HTLC timeout.

Found in round 4 by two independent reviewers. `claim` reverts once `block.timestamp >= timeout`,
and **a reverted transaction is still mined with the preimage in its calldata** — the codebase's
own `fetch_claim_artifacts` scrapes `p` from exactly such a transaction. So a late claim does not
merely fail; it publishes the secret for nothing, and the counterparty then refunds this leg *and*
takes the other one with the `p` it just read.

`refund()` has had the mirror-image maturity guard all along. `claim()` — the more dangerous
direction — had none, and on the mainnet-recommended private path there is no `eth_call` preflight
to catch the revert either, because the preflight would itself leak `p` to the provider.
"""

from __future__ import annotations

import asyncio
import json
import os
import pathlib

import pytest

pytest.importorskip("web3", reason="needs the eth extra: pip install 'pyrxd[eth]'")

from pyrxd.eth_wallet.htlc_leg import CLAIM_INCLUSION_BUDGET_S, EthHtlcContractLeg
from pyrxd.eth_wallet.locator import EthHtlcLocator
from pyrxd.security.errors import PreRevealAbort
from pyrxd.security.secrets import PrivateKeyMaterial

_ART = json.loads((pathlib.Path(__file__).parent / "fixtures" / "EthHtlc.json").read_text())
_TIMEOUT = 1_800_000_000


def _leg(now_ts: int, *, sent: list):
    class _Built(dict):
        pass

    class _Fn:
        async def build_transaction(self, tx):
            return _Built(tx)

    class _Fns:
        def claim(self, *a, **k):
            return _Fn()

    class _Contract:
        functions = _Fns()

    class _Eth:
        def contract(self, *a, **k):
            return _Contract()

        async def get_block(self, _which):
            return {"timestamp": now_ts}

    class _W3:
        eth = _Eth()

    class _Rpc:
        w3 = _W3()

        async def assert_chain(self):
            return None

    leg = EthHtlcContractLeg(rpc=_Rpc(), signing_key=PrivateKeyMaterial(os.urandom(32)), chain_id=1, artifact=_ART)

    async def _base_tx(*a, **k):
        return {}

    async def _sign_and_send(*a, **k):
        sent.append(True)  # the reveal — must never happen when the guard fires
        return "0x" + "ab" * 32

    leg._base_tx = _base_tx
    leg._sign_and_send = _sign_and_send
    return leg


def _locator() -> EthHtlcLocator:
    return EthHtlcLocator(
        chain_id=1,
        contract_address="0x" + "11" * 20,
        deploy_tx_hash="0x" + "22" * 32,
        hashlock="0x" + "33" * 32,
        claimant="0x" + "44" * 20,
        refundee="0x" + "55" * 20,
        timeout=_TIMEOUT,
        amount_wei=10**15,
    )


class TestALateClaimIsRefusedBeforeItCanLeakThePreimage:
    @pytest.mark.parametrize(
        ("label", "now"),
        [
            ("already past the timeout", _TIMEOUT + 10),
            ("exactly at the timeout", _TIMEOUT),
            ("inside the inclusion budget", _TIMEOUT - CLAIM_INCLUSION_BUDGET_S + 1),
        ],
    )
    def test_it_refuses_and_broadcasts_NOTHING(self, label: str, now: int) -> None:
        sent: list = []
        leg = _leg(now, sent=sent)
        with pytest.raises(PreRevealAbort, match="head-room|timeout"):
            asyncio.run(leg.claim(_locator(), b"\x11" * 32))
        assert not sent, f"{label}: the preimage was broadcast anyway"

    def test_the_refusal_preserves_the_preimage(self) -> None:
        """PreRevealAbort, not ValidationError: nothing was sent, so the caller must keep `p` —
        there is still a refund to coordinate and a retry is meaningless but harmless."""
        leg = _leg(_TIMEOUT - 1, sent=[])
        with pytest.raises(PreRevealAbort):
            asyncio.run(leg.claim(_locator(), b"\x11" * 32))

    def test_a_claim_with_room_to_spare_proceeds(self) -> None:
        """The honest path. A guard that refuses valid work is a bug, and the overwhelmingly common
        case is a claim made with hours left."""
        sent: list = []
        leg = _leg(_TIMEOUT - 3600, sent=sent)
        assert asyncio.run(leg.claim(_locator(), b"\x11" * 32))
        assert sent == [True], "a timely claim must still broadcast"

    def test_the_budget_is_several_blocks_not_a_token_gesture(self) -> None:
        assert CLAIM_INCLUSION_BUDGET_S >= 60, "must survive a fee spike, not just one block"
