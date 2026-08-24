"""A deployed HTLC must be referenced by the durable record before value moves into it.

`taker_funds_btc` persists an intent record before broadcasting, and its comment says that record
"knows WHERE the HTLC address is". That is true for BTC — a P2TR funding address is derived from
terms before anything is broadcast — and it was false for ETH, where a CREATE address depends on
the deployer's nonce and does not exist until the deploy receipt returns.

The ERC-20 path makes it worst, because funding is TWO transactions: deploy, then a plain
`transfer`. A crash after the push but before the locator is returned left real USDC in a contract
whose only reference was an exception string. `refund()` recovers it after the timeout — but only
for an operator who still knows the address, and reconstructing a CREATE address by hand is not a
recovery procedure.

The leg now awaits `on_deploy(address)` as soon as the deploy confirms and, for the token leg,
strictly BEFORE the tokens are pushed.
"""

from __future__ import annotations

import asyncio
import json
import os
import pathlib
import time

import pytest

pytest.importorskip("web3", reason="needs the eth extra: pip install 'pyrxd[eth]'")

from pyrxd.eth_wallet.erc20_leg import Erc20HtlcLeg
from pyrxd.eth_wallet.locator import PendingDeploy
from pyrxd.eth_wallet.tokens import token_for
from pyrxd.security.errors import NetworkError, ValidationError
from pyrxd.security.secrets import PrivateKeyMaterial

_ART = json.loads((pathlib.Path(__file__).parent / "fixtures" / "Erc20Htlc.json").read_text())
_DEPLOYED = "0x" + "77" * 20
_USDC = token_for("USDC", 1)


def _leg(*, push_fails: bool = False, order: list, initial_held: int = 0):
    """A token leg whose deploy always succeeds; the push may fail.

    `initial_held` is what the HTLC already holds — 0 for a fresh deploy, non-zero to model a
    resume after a push whose receipt was lost. The balance TRACKS the push, because a fake that
    reports a constant balance cannot tell "already funded" from "not funded yet", which is the
    exact distinction the resume path turns on.
    """
    state = {"held": int(initial_held), "sent": []}

    class _Call:
        def __init__(self, v):
            self._v = v

        async def call(self, *a, **k):
            return self._v

    class _Fns:
        def transfer(self, _to, amount):
            class _B:
                async def build_transaction(self_b, tx):
                    state["pending_transfer"] = int(amount)
                    return dict(tx)

            return _B()

        def symbol(self, *a, **k):
            return _Call("USDC")

        def decimals(self, *a, **k):
            return _Call(6)

        def balanceOf(self, *a, **k):
            return _Call(state["held"])

    class _Ctor:
        async def build_transaction(self, tx):
            return dict(tx)

    class _Contract:
        functions = _Fns()

        def constructor(self, *a, **k):
            return _Ctor()

    class _Eth:
        def contract(self, *a, **k):
            return _Contract()

    class _W3:
        eth = _Eth()

    class _Rpc:
        w3 = _W3()

        async def assert_chain(self):
            return None

        async def fee_fields(self):
            return {"maxPriorityFeePerGas": 1, "maxFeePerGas": 3}

        async def get_transaction_count(self, _a):
            return 0

        async def wait_receipt(self, tx_hash, **_k):
            if tx_hash == "0xdeploy":
                return {"status": 1, "contractAddress": _DEPLOYED, "logs": []}
            if push_fails:
                return {"status": 0, "logs": []}
            state["held"] += state.pop("pending_transfer", 0)
            return {"status": 1, "logs": []}

    leg = Erc20HtlcLeg(
        token=_USDC, rpc=_Rpc(), signing_key=PrivateKeyMaterial(os.urandom(32)), chain_id=1, artifact=_ART
    )

    sends = {"n": 0}

    async def _sign_and_send(*a, **k):
        sends["n"] += 1
        if sends["n"] == 1 and initial_held == 0 and "resumed" not in state:
            return "0xdeploy"
        order.append("tokens-pushed")
        state["sent"].append(state.get("pending_transfer"))
        return "0xpush"

    leg._sign_and_send = _sign_and_send
    leg._test_state = state
    return leg


def _fund(leg, on_deploy, resume_from=None):
    return asyncio.run(
        leg.fund(
            resume_from=resume_from,
            hashlock=b"\x33" * 32,
            claimant="0x" + "44" * 20,
            refundee="0x" + "55" * 20,
            timeout=int(time.time()) + 86_400,
            amount_wei=12_345_678,
            on_deploy=on_deploy,
        )
    )


class TestTheAddressIsDurableBeforeTheTokensMove:
    def test_on_deploy_fires_BEFORE_the_token_push(self) -> None:
        """The ordering IS the fix. Persisting after the push leaves a window in which real value
        sits in a contract nothing references — exactly the case being closed."""
        order: list = []

        async def _remember(addr: str, tx: str) -> None:
            order.append(f"persisted:{addr}")
            assert tx == "0xdeploy", "the deploy tx hash must ride along; a resume needs it"

        _fund(_leg(push_fails=False, order=order), _remember)
        assert order == [f"persisted:{_DEPLOYED}", "tokens-pushed"], order

    def test_a_FAILED_push_still_leaves_the_address_recorded(self) -> None:
        """The crash-consistency case. The push reverts, `fund` raises and returns no locator —
        but the operator must still hold the address, because the contract exists and a later
        retry or refund needs somewhere to point."""
        seen: list = []

        async def _remember(addr: str, tx: str) -> None:
            seen.append(addr)

        with pytest.raises(NetworkError):
            _fund(_leg(push_fails=True, order=[]), _remember)
        assert seen == [_DEPLOYED], "the deployed address was lost when the push failed"

    def test_a_caller_that_cannot_PERSIST_stops_before_the_tokens_move(self) -> None:
        """If the record cannot be written, pushing would create precisely the untracked value
        this exists to prevent. Awaiting the hook — rather than firing and forgetting — is what
        makes the failure stop the push."""
        order: list = []

        async def _broken(_addr: str, _tx: str) -> None:
            raise NetworkError("record store unavailable")

        with pytest.raises(NetworkError, match="record store unavailable"):
            _fund(_leg(push_fails=False, order=order), _broken)
        assert "tokens-pushed" not in order, "tokens were pushed despite the address not being durable"

    def test_fund_without_a_hook_still_works(self) -> None:
        """A guard that refuses valid work is a bug: `on_deploy` is optional, and a caller that
        passes nothing keeps the previous behaviour."""
        order: list = []
        loc = _fund(_leg(push_fails=False, order=order), None)
        assert loc.contract_address.lower() == _DEPLOYED.lower()
        assert order == ["tokens-pushed"]


_AMOUNT = 12_345_678
_PENDING = PendingDeploy(address=_DEPLOYED, deploy_tx_hash="0xdeploy")


def _stub_verify(leg, order: list):
    """Record that the immutable check ran, and WHEN. `verify_funded` needs a full node fake
    (get_code plus every immutable getter); the point being pinned here is the ORDER and the
    waiver, both of which a recording stub captures exactly. That it genuinely refuses is pinned
    separately by `test_a_resume_REFUSES_a_contract_that_is_not_this_swap`."""

    async def _v(locator, *, expected_amount_wei, **_k):
        order.append(f"verified:{locator.contract_address.lower()}:{expected_amount_wei}")

    leg.verify_funded = _v
    return leg


class TestResumeCompletesTheFundInsteadOfStartingASecondOne:
    """The retry half of the crash story. `reserve(H)` commits before the broadcast, so after a
    mid-fund crash a plain retry is refused forever — and the only knob an operator had was calling
    `fund` again, which DEPLOYS A SECOND CONTRACT and pushes a second full amount.
    """

    def test_a_resume_does_not_deploy_a_second_contract(self) -> None:
        order: list = []
        leg = _leg(order=order)
        leg._test_state["resumed"] = True
        _stub_verify(leg, order)
        loc = _fund(leg, None, resume_from=_PENDING)
        assert loc.contract_address.lower() == _DEPLOYED.lower(), "resume funded a different contract"
        # Verified first, then exactly one push, and NO deploy.
        assert order == [f"verified:{_DEPLOYED.lower()}:0", "tokens-pushed"], order

    def test_a_resume_after_a_LOST_RECEIPT_sends_nothing(self) -> None:
        """The push landed; the process died before seeing the receipt. Re-sending the full amount
        on that reading is the double-fund this exists to prevent — the tokens are already there,
        so the correct action is to send NOTHING and bind the locator."""
        order: list = []
        leg = _leg(order=order, initial_held=_AMOUNT)
        _stub_verify(leg, order)
        loc = _fund(leg, None, resume_from=_PENDING)
        assert "tokens-pushed" not in order, f"a fully funded HTLC was topped up again: {order}"
        assert loc.amount_wei == _AMOUNT

    def test_a_resume_after_a_PARTIAL_fund_sends_only_the_shortfall(self) -> None:
        """Nothing in this protocol guarantees the balance is all-or-nothing — anyone can send
        tokens to the address. Send the difference, not the whole amount again."""
        order: list = []
        leg = _leg(order=order, initial_held=_AMOUNT - 1_000_000)
        leg._test_state["resumed"] = True
        _stub_verify(leg, order)
        _fund(leg, None, resume_from=_PENDING)
        assert leg._test_state["sent"] == [1_000_000], (
            f"resume sent {leg._test_state['sent']} instead of just the 1,000,000 shortfall"
        )

    def test_a_resume_REFUSES_a_contract_that_is_not_this_swap(self) -> None:
        """A resume is driven by a durable record. Sending tokens to an address out of a record
        without re-deriving what that address actually IS would let a corrupted or tampered record
        redirect the funds anywhere. The immutables are verified before anything is sent."""
        order: list = []
        leg = _leg(order=order)
        leg._test_state["resumed"] = True

        async def _wrong(*_a, **_k):
            raise ValidationError("on-chain hashlock != negotiated hashlock")

        leg.verify_funded = _wrong
        with pytest.raises(ValidationError):
            _fund(leg, None, resume_from=_PENDING)
        assert order == [], "tokens were sent to a contract that was never verified as ours"

    def test_the_immutables_are_verified_with_the_BALANCE_REQUIREMENT_WAIVED(self) -> None:
        """`expected_amount_wei=0` is the whole trick: a half-finished fund is legitimately allowed
        to be short, so the balance is the ONE check a resume must waive — and every other check
        (hashlock, claimant, refundee, timeout, token, runtime code) must still run. Waiving more
        would let a resume send tokens to a contract that is not this swap."""
        order: list = []
        leg = _leg(order=order)
        leg._test_state["resumed"] = True
        _stub_verify(leg, order)
        _fund(leg, None, resume_from=_PENDING)
        verified = [e for e in order if e.startswith("verified:")]
        assert verified == [f"verified:{_DEPLOYED.lower()}:0"], verified
        assert order.index(verified[0]) < order.index("tokens-pushed"), "verified AFTER sending tokens"
