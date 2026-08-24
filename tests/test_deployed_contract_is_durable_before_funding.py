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
#: Evaluated ONCE so the fake's on-chain immutable and the value `_fund` sends agree; computing
#: `time.time()` at each call made them differ and the real immutable bind refused, correctly.
_FUND_TIMEOUT = int(time.time()) + 86_400


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
            timeout=_FUND_TIMEOUT,
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

    async def _v(locator, *, expected_amount_wei, require_balance=True, **_k):
        assert require_balance is False, "a resume must waive the balance floor, and only that"
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
        assert order == [f"verified:{_DEPLOYED.lower()}:{_AMOUNT}", "tokens-pushed"], order

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
        # The REAL negotiated amount, not 0. Round 6: passing 0 to mean "waive the balance" also
        # inverted the contract's `amount` immutable bind, so every resume raised before a token
        # moved. The amount is now asserted and only the balance floor is waived.
        assert verified == [f"verified:{_DEPLOYED.lower()}:{_AMOUNT}"], verified
        assert order.index(verified[0]) < order.index("tokens-pushed"), "verified AFTER sending tokens"


# ---------------------------------------------------------------------------
# The gap that let two CRITICALs through round 6: every resume test above stubs
# `verify_funded`, so none of them ever ran the check that makes a resume safe. These drive the
# REAL method against a fake node serving real immutables.
# ---------------------------------------------------------------------------

_CLAIMANT = "0x" + "44" * 20
_REFUNDEE = "0x" + "55" * 20
_TIMEOUT = _FUND_TIMEOUT


def _real_verify_leg(*, on_chain: dict, held: int, order: list):
    """A leg whose `verify_funded` is the PRODUCTION one, backed by a node fake serving the
    contract's immutables. `on_chain` overrides let a test deploy a contract that is NOT this
    swap's and watch the real check refuse it."""
    imm = {
        "hashlock": b"\x33" * 32,
        "claimant": _CLAIMANT,
        "refundee": _REFUNDEE,
        "timeout": _TIMEOUT,
        "amount": _AMOUNT,
        "token": _USDC.address,
        **on_chain,
    }
    state = {"held": int(held)}

    class _Call:
        def __init__(self, v):
            self._v = v

        async def call(self, *a, **k):
            return self._v

    class _Fns:
        def hashlock(self, *a, **k):
            return _Call(imm["hashlock"])

        def claimant(self, *a, **k):
            return _Call(imm["claimant"])

        def refundee(self, *a, **k):
            return _Call(imm["refundee"])

        def timeout(self, *a, **k):
            return _Call(imm["timeout"])

        def amount(self, *a, **k):
            return _Call(imm["amount"])

        def token(self, *a, **k):
            return _Call(imm["token"])

        def balanceOf(self, *a, **k):
            return _Call(state["held"])

        def symbol(self, *a, **k):
            return _Call("USDC")

        def decimals(self, *a, **k):
            return _Call(6)

        def transfer(self, _to, amount):
            class _B:
                async def build_transaction(self_b, tx):
                    state["pending"] = int(amount)
                    return dict(tx)

            return _B()

    class _Contract:
        functions = _Fns()

    class _Eth:
        def contract(self, *a, **k):
            return _Contract()

    class _W3:
        eth = _Eth()

    class _Rpc:
        w3 = _W3()

        async def assert_chain(self):
            return None

        async def get_code(self, address, *a, **k):
            # Address-AWARE. The HTLC carries the committed runtime bytecode (the parent compares
            # it and refuses a mismatch); the claimant and refundee are EOAs and must return empty,
            # or the recipient-policy check refuses them as contracts.
            if str(address).lower() == _DEPLOYED.lower():
                return bytes.fromhex(_ART["runtime_bytecode"].removeprefix("0x"))
            return b""

        async def get_balance(self, *a, **k):
            # NATIVE ether balance. Zero for a token HTLC, which is why the token leg passes 0 to
            # the parent's balance assertion and makes the real one against the token itself.
            return 0

        async def fee_fields(self):
            return {"maxPriorityFeePerGas": 1, "maxFeePerGas": 3}

        async def get_transaction_count(self, _a):
            return 0

        async def wait_receipt(self, *a, **k):
            state["held"] += state.pop("pending", 0)
            return {"status": 1, "logs": []}

    leg = Erc20HtlcLeg(
        token=_USDC, rpc=_Rpc(), signing_key=PrivateKeyMaterial(os.urandom(32)), chain_id=1, artifact=_ART
    )

    async def _sign_and_send(*a, **k):
        order.append("tokens-pushed")
        return "0xpush"

    leg._sign_and_send = _sign_and_send
    return leg


class TestTheRealVerifyFundedRunsOnResume:
    def test_a_resume_against_a_GENUINE_contract_completes(self) -> None:
        """The check every earlier resume test stubbed away. Round 6 found `expected_amount_wei=0`
        also inverted the contract's `amount` IMMUTABLE bind — always non-zero — so every resume
        raised before a token moved and the feature was dead. Nothing caught it because no test
        ran the real method."""
        order: list = []
        leg = _real_verify_leg(on_chain={}, held=0, order=order)
        loc = _fund(leg, None, resume_from=_PENDING)
        assert order == ["tokens-pushed"]
        assert loc.contract_address.lower() == _DEPLOYED.lower()

    @pytest.mark.parametrize(
        ("label", "override"),
        [
            ("a different hashlock", {"hashlock": b"\x99" * 32}),
            ("a different claimant", {"claimant": "0x" + "99" * 20}),
            ("a different refundee", {"refundee": "0x" + "99" * 20}),
            ("a different timeout", {"timeout": _TIMEOUT + 1}),
            ("a different amount", {"amount": _AMOUNT + 1}),
        ],
    )
    def test_a_resume_REFUSES_a_contract_whose_immutables_differ(self, label: str, override: dict) -> None:
        """The real safety property, against the real check: a record pointing at a contract that
        is not this swap must not receive tokens. The AMOUNT case is the one the broken waiver
        would have silently skipped had it been waived instead of asserted."""
        order: list = []
        leg = _real_verify_leg(on_chain=override, held=0, order=order)
        with pytest.raises(ValidationError):
            _fund(leg, None, resume_from=_PENDING)
        assert order == [], f"{label}: tokens were sent to a contract that is not this swap"

    def test_the_balance_floor_is_the_ONLY_thing_the_resume_waives(self) -> None:
        """A half-finished fund is legitimately short, so the balance must be waived — and nothing
        else may be. Holding zero must still resume; that is what `require_balance=False` buys."""
        order: list = []
        leg = _real_verify_leg(on_chain={}, held=0, order=order)
        assert _fund(leg, None, resume_from=_PENDING) is not None
        assert order == ["tokens-pushed"]
