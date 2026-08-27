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
import time

import pytest

pytest.importorskip("web3", reason="needs the eth extra: pip install 'pyrxd[eth]'")

from pyrxd.eth_wallet.htlc_leg import (
    CLAIM_BASEFEE_HEADROOM,
    CLAIM_INCLUSION_BUDGET_S,
    EthHtlcContractLeg,
)
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

        write_w3 = w3  # the fake builds transactions against the same object it reads from

        async def latest_block_timestamp(self):
            return int((await self.w3.eth.get_block("latest"))["timestamp"])

        async def latest_block_timestamp_min(self):
            # The multi-source class aggregates this the other way for the staleness and
            # refund-maturity guards; one endpoint has one answer, so the fake mirrors it.
            return await self.latest_block_timestamp()

        async def latest_block_timestamp_quorum(self):
            # The staleness abort reads the QUORUM-th head: MIN lets one lagging endpoint
            # declare a healthy chain halted, MAX lets one liar hide a real halt. A single
            # source has one answer, so all three coincide here.
            return await self.latest_block_timestamp()

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


def _locator(timeout: int = _TIMEOUT) -> EthHtlcLocator:
    return EthHtlcLocator(
        chain_id=1,
        contract_address="0x" + "11" * 20,
        deploy_tx_hash="0x" + "22" * 32,
        hashlock="0x" + "33" * 32,
        claimant="0x" + "44" * 20,
        refundee="0x" + "55" * 20,
        timeout=timeout,
        amount_wei=10**15,
    )


class TestALateClaimIsRefusedBeforeItCanLeakThePreimage:
    @pytest.mark.parametrize(
        ("label", "now"),
        [
            ("already past the timeout", _TIMEOUT + 10),
            ("exactly at the timeout", _TIMEOUT),
            ("inside the inclusion budget", _TIMEOUT - CLAIM_INCLUSION_BUDGET_S + 1),
            # Pins the operator as `>=`, not `>`. Every case above refuses under either
            # spelling; only exact equality can tell them apart. An off-by-one here is a
            # claim broadcast with zero head-room — the leak this guard exists to stop.
            ("exactly at the edge of the budget", _TIMEOUT - CLAIM_INCLUSION_BUDGET_S),
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

    def test_one_second_of_head_room_is_still_ENOUGH(self) -> None:
        """The other side of the boundary. Paired with the exact-equality case above, this is what
        keeps the guard from creeping into refusing honest work: the instant there is any head-room
        at all, the claim goes. A guard that refuses valid work is a bug."""
        sent: list = []
        leg = _leg(_TIMEOUT - CLAIM_INCLUSION_BUDGET_S - 1, sent=sent)
        assert asyncio.run(leg.claim(_locator(), b"\x11" * 32))
        assert sent == [True], "a claim with head-room to spare must not be refused"

    def test_the_budget_is_several_blocks_not_a_token_gesture(self) -> None:
        assert CLAIM_INCLUSION_BUDGET_S >= 60, "must survive a fee spike, not just one block"


class TestALaggingProviderCannotMakeTheGuardPass:
    """Round 5. The guard read `now` from ONE source — the chain head — and a stale head
    UNDER-reports now, which is precisely the direction that makes the guard pass when it should
    refuse. A provider load-balanced onto a node minutes behind, or any of the L2s in the token
    registry during a sequencer halt, made the guard inert in the exact case it was written for.
    """

    def test_a_stale_head_is_refused_rather_than_trusted(self) -> None:
        """The head is an hour behind wall clock. Nothing can be concluded about inclusion from
        it, so the claim must not be built — and nothing may be broadcast."""
        sent: list = []
        leg = _leg(int(time.time()) - 3600, sent=sent)
        loc = _locator(timeout=int(time.time()) + 86_400)
        with pytest.raises(PreRevealAbort, match="stale"):
            asyncio.run(leg.claim(loc, b"\x11" * 32))
        assert not sent, "a claim was broadcast against a head too stale to reason about"

    def test_the_ORIGINAL_attack_a_stale_head_hiding_an_imminent_deadline(self) -> None:
        """The finding in full. Real time is 10s from the timeout — far inside the budget — but
        the provider reports a head from an hour ago, which under the old single-source read
        cleared the check with an apparent 3600s to spare. Broadcasting here mines after the
        timeout, reverts, and leaves `p` in the calldata for the counterparty to scrape."""
        sent: list = []
        now = int(time.time())
        leg = _leg(now - 3600, sent=sent)
        with pytest.raises(PreRevealAbort):
            asyncio.run(leg.claim(_locator(timeout=now + 10), b"\x11" * 32))
        assert not sent, "the preimage was published against an already-expired HTLC"

    def test_a_HEALTHY_head_a_few_seconds_behind_still_claims(self) -> None:
        """A guard that refuses valid work is a bug. A head is ALWAYS a little behind wall clock —
        one block time, ~12s on L1 — and that must remain ordinary, not an error."""
        sent: list = []
        now = int(time.time())
        leg = _leg(now - 12, sent=sent)
        assert asyncio.run(leg.claim(_locator(timeout=now + 86_400), b"\x11" * 32))
        assert sent == [True], "an ordinary one-block-old head must not refuse a healthy claim"


class TestTheFeeCeilingCoversTheWindowTheGuardAuthorises:
    """Round 5, second independent mechanism against the same guard. The guard authorised
    broadcasting with 96s (8 blocks) of head-room while every tx was priced at `2*base + tip`.
    Basefee may rise 12.5%/block, and 1.125**6 = 2.03 — so the fee ceiling expired after 72s,
    leaving a 24s window in which the claim is broadcast but cannot be included. The taker then
    refunds at the timeout, the claim mines, reverts, and publishes `p`.
    """

    def test_the_headroom_multiplier_covers_the_full_budget(self) -> None:
        assert CLAIM_BASEFEE_HEADROOM >= 1.125 ** (CLAIM_INCLUSION_BUDGET_S / 12), (
            "the fee ceiling must survive max-rate basefee growth for the whole window the "
            "deadline guard is willing to authorise, or the two have drifted apart again"
        )

    def test_a_claim_is_priced_above_the_nodes_default_ceiling(self) -> None:
        """Behavioural, not arithmetic. Drives the REAL `_base_tx` (the harness above stubs it out,
        which would make a fee assertion vacuous) and reads the ceiling off the built claim."""
        cap: list = []
        now = int(time.time())
        leg = _fee_leg(now - 12, cap)
        asyncio.run(leg.claim(_locator(timeout=now + 86_400), b"\x11" * 32))
        assert cap, "no transaction was built"
        assert cap[0]["maxFeePerGas"] > _BASE * 2 + _TIP, (
            f"claim priced at {cap[0]['maxFeePerGas']}, no better than the node's "
            f"{_BASE * 2 + _TIP} default — the raised ceiling never reached the transaction"
        )
        assert cap[0]["maxPriorityFeePerGas"] == _TIP, "the TIP must not be inflated, only basefee"

    def test_a_NON_deadline_tx_is_not_overpriced(self) -> None:
        """Only `claim` has a deadline. Raising the ceiling everywhere would make every refund and
        deploy overpay for a window it does not have — a fix that costs money is still a bug."""
        cap: list = []
        leg = _fee_leg(int(time.time()), cap)
        asyncio.run(leg._base_tx(gas=100_000))
        assert cap == [], "no claim was built"
        tx = asyncio.run(leg._base_tx(gas=100_000))
        assert tx["maxFeePerGas"] == _BASE * 2 + _TIP, "a deadline-free tx must keep the node's price"


_BASE, _TIP = 1_000_000_000, 1_000_000_000


def _fee_leg(now_ts: int, cap: list):
    """A leg that runs the REAL `_base_tx`, so fee assertions are not vacuous. Only the RPC reads
    and the final send are stubbed; everything between is production code."""

    class _Built(dict):
        pass

    class _Fn:
        async def build_transaction(self, tx):
            cap.append(tx)
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

        write_w3 = w3  # the fake builds transactions against the same object it reads from

        async def latest_block_timestamp(self):
            return int((await self.w3.eth.get_block("latest"))["timestamp"])

        async def latest_block_timestamp_min(self):
            # The multi-source class aggregates this the other way for the staleness and
            # refund-maturity guards; one endpoint has one answer, so the fake mirrors it.
            return await self.latest_block_timestamp()

        async def latest_block_timestamp_quorum(self):
            # The staleness abort reads the QUORUM-th head: MIN lets one lagging endpoint
            # declare a healthy chain halted, MAX lets one liar hide a real halt. A single
            # source has one answer, so all three coincide here.
            return await self.latest_block_timestamp()

        async def assert_chain(self):
            return None

        async def fee_fields(self):
            return {"maxPriorityFeePerGas": _TIP, "maxFeePerGas": _BASE * 2 + _TIP}

        async def get_transaction_count(self, _addr, block="pending"):
            return 0

    leg = EthHtlcContractLeg(rpc=_Rpc(), signing_key=PrivateKeyMaterial(os.urandom(32)), chain_id=1, artifact=_ART)

    async def _sign_and_send(*a, **k):
        return "0x" + "ab" * 32

    leg._sign_and_send = _sign_and_send
    return leg


class TestTheDeadlineGuardAndTheStalenessAbortReadDIFFERENTHeads:
    """Two checks, opposite conservative directions, and for a while one shared value.

    Routing both through the MIN accessor made the deadline guard read the most LAGGING endpoint —
    the one whose answer makes a late claim look early. That is the direction that leaks the
    preimage into a transaction that cannot be mined in time. The staleness abort wants the
    opposite, so the two cannot share a number.

    Driven through `claim()` rather than by scanning the source, so a reformat does not break it
    and a comment cannot satisfy it.
    """

    @staticmethod
    def _split(*, quorum_ts: int, late_ts: int, sent: list):
        """A leg whose endpoints DISAGREE: `latest_block_timestamp` sees `late_ts`, the quorum-th
        head is `quorum_ts`. Real spread, not an exotic attack — one lagging replica does this."""
        leg = _leg(quorum_ts, sent=sent)

        async def _late():
            return late_ts

        async def _quorum():
            return quorum_ts

        leg._rpc.latest_block_timestamp = _late
        leg._rpc.latest_block_timestamp_quorum = _quorum
        return leg

    def test_a_LAGGING_endpoint_cannot_talk_the_guard_past_the_deadline(self) -> None:
        """The regression. The freshest head is seconds from the timeout, so the claim cannot be
        mined in time and must be refused. A guard reading the quorum-th (or minimum) head sees
        hours of room and reveals the preimage for nothing."""
        sent: list = []
        leg = self._split(quorum_ts=_TIMEOUT - 100_000, late_ts=_TIMEOUT - 10, sent=sent)
        with pytest.raises(PreRevealAbort):
            asyncio.run(leg.claim(_locator(), os.urandom(32)))
        assert sent == [], "the preimage was broadcast into a window that had already closed"

    def test_the_same_spread_with_room_to_spare_still_CLAIMS(self) -> None:
        """The honest-path pair. Endpoints disagreeing is normal, and a guard that refuses whenever
        they do would strand every claim — the failure mode being traded away, not accepted."""
        sent: list = []
        leg = self._split(quorum_ts=_TIMEOUT - 200_000, late_ts=_TIMEOUT - 100_000, sent=sent)
        asyncio.run(leg.claim(_locator(), os.urandom(32)))
        assert sent == [True], "an ordinary endpoint spread blocked an honest claim"
