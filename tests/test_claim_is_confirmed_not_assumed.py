"""A broadcast claim is not a successful claim.

`send_raw` and a Flashbots `submit_raw` both return on SUBMISSION — no receipt, no status. The
claim path returned that hash as success, so a transaction that REVERTED was reported as a
completed claim: the coordinator advanced to SECRET_REVEALED, zeroized the preimage and persisted.

The failure mode is the worst one available. A reverted claim is still MINED with `p` in its
calldata — this codebase's own `fetch_claim_artifacts` scrapes `p` from exactly such a
transaction — so the secret is public, the counterparty can take the other leg, this side
collected nothing, and its own state machine believes the swap succeeded.

The claim deadline guard removes the most likely cause (no inclusion head-room). It does not
remove the class: a fee spike, a reorg, an unexpected revert or a gas underestimate all still land
here. Confirmation is the other half of that fix.
"""

from __future__ import annotations

import asyncio
import json
import os
import pathlib
import time

import pytest

pytest.importorskip("web3", reason="needs the eth extra: pip install 'pyrxd[eth]'")

from pyrxd.eth_wallet.htlc_leg import EthHtlcContractLeg
from pyrxd.eth_wallet.locator import EthHtlcLocator
from pyrxd.security.errors import ClaimNotConfirmed, NetworkError
from pyrxd.security.secrets import PrivateKeyMaterial

_ART = json.loads((pathlib.Path(__file__).parent / "fixtures" / "EthHtlc.json").read_text())
_CONTRACT = "0x" + "11" * 20
_P = b"\x11" * 32


def _locator() -> EthHtlcLocator:
    return EthHtlcLocator(
        chain_id=1,
        contract_address=_CONTRACT,
        deploy_tx_hash="0x" + "22" * 32,
        hashlock="0x" + "33" * 32,
        claimant="0x" + "44" * 20,
        refundee="0x" + "55" * 20,
        timeout=int(time.time()) + 86_400,
        amount_wei=10**15,
    )


def _leg(receipt, *, sent: list):
    """`receipt` is the dict wait_receipt returns, or an Exception to raise."""

    class _Fn:
        async def build_transaction(self, tx):
            return dict(tx)

    class _Fns:
        def claim(self, *a, **k):
            return _Fn()

    class _Contract:
        functions = _Fns()

    class _Eth:
        def contract(self, *a, **k):
            return _Contract()

        async def get_block(self, _w):
            return {"timestamp": int(time.time())}

    class _W3:
        eth = _Eth()

    class _Rpc:
        w3 = _W3()

        # The write path is a SEPARATE accessor: a multi-source RPC has no single `w3` to
        # sign against, so `w3` raises there and `write_w3` returns the primary's. One
        # source means they are the same object here.
        write_w3 = w3

        async def latest_block_timestamp(self):
            # The deadline guard reads the LATEST head any endpoint admits to; the staleness abort
            # reads the QUORUM-th. One source has one answer, so all three coincide here. `claim`
            # used to reach through `w3.eth.get_block` directly, which a multi-source RPC cannot serve.
            return int((await self.w3.eth.get_block("latest"))["timestamp"])

        async def latest_block_timestamp_quorum(self):
            return await self.latest_block_timestamp()

        async def latest_block_timestamp_min(self):
            return await self.latest_block_timestamp()

        async def assert_chain(self):
            return None

        async def wait_receipt(self, tx_hash, **_k):
            if isinstance(receipt, Exception):
                raise receipt
            return receipt

    leg = EthHtlcContractLeg(rpc=_Rpc(), signing_key=PrivateKeyMaterial(os.urandom(32)), chain_id=1, artifact=_ART)

    async def _base_tx(*a, **k):
        return {}

    async def _sign_and_send(*a, **k):
        sent.append(True)
        return "0x" + "ab" * 32

    leg._base_tx = _base_tx
    leg._sign_and_send = _sign_and_send
    return leg


def _good_receipt() -> dict:
    return {"status": 1, "logs": [{"address": _CONTRACT, "topics": [], "data": "0x" + _P.hex()}]}


class TestASubmittedClaimIsNotASuccessfulClaim:
    def test_a_REVERTED_claim_is_not_reported_as_success(self) -> None:
        """status == 0. The tx mined, so `p` is public — but nothing was collected."""
        sent: list = []
        leg = _leg({"status": 0, "logs": []}, sent=sent)
        with pytest.raises(ClaimNotConfirmed):
            asyncio.run(leg.claim(_locator(), _P))
        assert sent == [True], "the tx really was broadcast; this is a post-reveal failure"

    def test_a_claim_with_NO_Claimed_log_is_not_reported_as_success(self) -> None:
        """status == 1 but our contract emitted nothing — not our claim, or not a claim at all."""
        leg = _leg({"status": 1, "logs": []}, sent=[])
        with pytest.raises(ClaimNotConfirmed):
            asyncio.run(leg.claim(_locator(), _P))

    def test_a_Claimed_log_from_ANOTHER_contract_does_not_count(self) -> None:
        """A cross-swap claim reusing the same H emits from a DIFFERENT per-swap contract."""
        other = {"status": 1, "logs": [{"address": "0x" + "99" * 20, "topics": [], "data": "0x" + _P.hex()}]}
        leg = _leg(other, sent=[])
        with pytest.raises(ClaimNotConfirmed):
            asyncio.run(leg.claim(_locator(), _P))

    def test_an_UNCONFIRMED_claim_is_not_reported_as_success(self) -> None:
        """No receipt before the deadline. The outcome is unknown, which is not success — and on
        the private path a dropped bundle looks exactly like this."""
        leg = _leg(NetworkError("wait_for_transaction_receipt failed: timeout"), sent=[])
        with pytest.raises(ClaimNotConfirmed):
            asyncio.run(leg.claim(_locator(), _P))

    def test_the_failure_carries_the_TX_HASH(self) -> None:
        """The only handle an operator has on a claim that may be public but did not pay. Without
        it there is nothing to investigate, and the swap cannot be resolved by hand."""
        leg = _leg({"status": 0, "logs": []}, sent=[])
        with pytest.raises(ClaimNotConfirmed) as ei:
            asyncio.run(leg.claim(_locator(), _P))
        assert ei.value.tx_hash == "0x" + "ab" * 32

    def test_a_GENUINELY_successful_claim_still_returns_its_hash(self) -> None:
        """The honest path. A guard that refuses valid work is a bug: a real claim — status 1 with
        a Claimed(p) log from this swap's own contract — must still succeed and return the hash."""
        sent: list = []
        leg = _leg(_good_receipt(), sent=sent)
        assert asyncio.run(leg.claim(_locator(), _P)) == "0x" + "ab" * 32
        assert sent == [True]
