"""The pre-reveal freeze gate must FAIL CLOSED.

Found by security review of this branch. The gate exists to stop a party publishing the preimage
into a freeze — once it is public the counterparty takes the other leg, so a wrong "not frozen" is
a one-sided loss with no recovery. The first version caught every exception and returned ``False``,
so an unreachable or rate-limited RPC reported "safe": a fail-OPEN in the one gate that prevents an
unrecoverable outcome, firing exactly when the caller is already in trouble.
"""

from __future__ import annotations

import asyncio

import pytest

from pyrxd.eth_wallet.erc20 import assert_not_frozen_before_reveal, is_blacklisted
from pyrxd.eth_wallet.tokens import Erc20Token, token_for
from pyrxd.security.errors import NetworkError

pytest.importorskip("web3", reason="needs the eth extra: pip install 'pyrxd[eth]'")

_USDC = token_for("USDC", 1)
_ADDR = "0x" + "11" * 20


class _Broken:
    """An RPC that is down / throttled / returning garbage."""

    def __init__(self, exc: Exception) -> None:
        self._exc = exc
        outer = self

        class _Call:
            async def call(self, *a, **k):
                raise outer._exc

        class _Fns:
            def isBlacklisted(self, *a, **k):
                return _Call()

        class _Contract:
            functions = _Fns()

        class _Eth:
            def contract(self, *a, **k):
                return _Contract()

        class _W3:
            eth = _Eth()

        self.w3 = _W3()


@pytest.mark.parametrize(
    "exc",
    [
        NetworkError("connection refused"),
        Exception("429 Too Many Requests"),
        ValueError("could not decode result"),
        TimeoutError("read timed out"),
    ],
    ids=["unreachable", "rate-limited", "garbage", "timeout"],
)
class TestAnUnanswerableReadIsNotASafeAnswer:
    def test_is_blacklisted_raises_rather_than_reporting_not_frozen(self, exc: Exception) -> None:
        with pytest.raises(NetworkError, match="could not determine"):
            asyncio.run(is_blacklisted(_Broken(exc), _USDC, _ADDR))

    def test_the_gate_refuses_so_the_caller_does_not_reveal(self, exc: Exception) -> None:
        """The consequence that matters: the caller must not proceed to publish the preimage."""
        with pytest.raises(NetworkError):
            asyncio.run(
                assert_not_frozen_before_reveal(
                    _Broken(exc), _USDC, htlc_address="0x" + "22" * 20, parties={"claimant": _ADDR}
                )
            )


class TestCapabilityIsPinnedNotProbed:
    """Whether a token CAN freeze is registry data, not the result of a call that might fail.
    Probing is what made "no such function" and "could not reach the chain" indistinguishable."""

    def test_a_non_freezable_token_needs_no_call_at_all(self) -> None:
        frozen = asyncio.run(
            is_blacklisted(_Broken(NetworkError("would explode if called")), _no_blacklist_token(), _ADDR)
        )
        assert frozen is False, "a token that cannot freeze cannot freeze this swap"

    def test_usdc_is_pinned_as_freezable(self) -> None:
        assert _USDC.has_blacklist is True

    def test_the_default_is_freezable_so_a_new_entry_fails_safe(self) -> None:
        """A registry entry added without thinking about it should be treated as freezable —
        the conservative direction, since assuming otherwise skips the check entirely."""
        t = Erc20Token("TEST", "0x" + "ab" * 20, 6, 1)
        assert t.has_blacklist is True


def _no_blacklist_token() -> Erc20Token:
    return Erc20Token("NOFREEZE", "0x" + "cd" * 20, 18, 1, has_blacklist=False)


class TestTheContractAddressCannotBeOmitted:
    """The freeze that strands funds permanently is the CONTRACT's, not a party's — a frozen
    counterparty is still recoverable by refund. Making it a required parameter rather than a dict
    entry means a caller cannot run the gate while silently skipping the case that matters most."""

    def test_it_is_a_required_argument(self) -> None:
        import inspect

        params = inspect.signature(assert_not_frozen_before_reveal).parameters
        assert "htlc_address" in params
        assert params["htlc_address"].default is inspect.Parameter.empty, "must not be optional"

    def test_an_empty_contract_address_is_refused(self) -> None:
        with pytest.raises(Exception, match="htlc_address is required"):
            asyncio.run(assert_not_frozen_before_reveal(_Broken(Exception()), _USDC, htlc_address=""))


class TestTheGateIsActuallyINVOKEDNotMerelyAvailable:
    """The gate was defined and called NOWHERE in production for a full review cycle.

    That is the same shipped-but-unreachable failure as #468 and as the critical bug this branch
    already shipped once: a mechanism that exists, is tested, and is never reached by the path it
    protects. Availability is not protection. These assert INVOCATION.
    """

    def test_claim_runs_the_gate_before_delegating(self) -> None:
        import inspect

        from pyrxd.eth_wallet.erc20_leg import Erc20HtlcLeg

        src = inspect.getsource(Erc20HtlcLeg.claim)
        gate_at = src.index("assert_not_frozen_before_reveal")
        claim_at = src.index("super().claim(")
        assert gate_at < claim_at, "the gate must run BEFORE the reveal, not after"

    def test_the_gate_is_reached_from_a_production_module_not_only_tests(self) -> None:
        """A grep-shaped assertion on purpose: the defect was that only tests referenced it."""
        import pathlib

        src_root = pathlib.Path(__file__).resolve().parent.parent / "src"
        callers = [
            p.name
            for p in src_root.rglob("*.py")
            if "assert_not_frozen_before_reveal(" in p.read_text() and p.name != "erc20.py"
        ]
        assert callers, "no production module calls the freeze gate — it protects nothing"

    def test_the_contract_address_is_what_gets_checked(self) -> None:
        """The freeze with no way out is the CONTRACT's; a frozen party is still refundable."""
        import inspect

        from pyrxd.eth_wallet.erc20_leg import Erc20HtlcLeg

        src = inspect.getsource(Erc20HtlcLeg.claim)
        assert "htlc_address=locator.contract_address" in src


class TestTheGateRefusesBEHAVIOURALLYNotJustInSource:
    """A source-text assertion would pass on `if False: await gate(...)`. These drive the real
    method and assert the outcome, which is the property the name claims."""

    @staticmethod
    def _leg(frozen: bool, held: int = 12_345_678):
        import os

        from pyrxd.eth_wallet.erc20_leg import Erc20HtlcLeg
        from pyrxd.security.secrets import PrivateKeyMaterial

        class _Call:
            def __init__(self, v):
                self._v = v

            async def call(self, *a, **k):
                return self._v

        class _Fns:
            def isBlacklisted(self, *a, **k):
                return _Call(frozen)

            def balanceOf(self, *a, **k):
                return _Call(held)

            def decimals(self, *a, **k):
                return _Call(6)

        class _Contract:
            functions = _Fns()

        class _Eth:
            def contract(self, *a, **k):
                return _Contract()

        class _W3:
            eth = _Eth()

        class _Rpc:
            w3 = _W3()

        import json
        import pathlib

        art = json.loads((pathlib.Path(__file__).parent / "fixtures" / "Erc20Htlc.json").read_text())
        return Erc20HtlcLeg(
            token=_USDC, rpc=_Rpc(), signing_key=PrivateKeyMaterial(os.urandom(32)), chain_id=1, artifact=art
        )

    @staticmethod
    def _locator():
        from pyrxd.eth_wallet.locator import Erc20HtlcLocator

        return Erc20HtlcLocator(
            chain_id=1,
            contract_address="0x" + "11" * 20,
            deploy_tx_hash="0x" + "22" * 32,
            hashlock="0x" + "33" * 32,
            claimant="0x" + "44" * 20,
            refundee="0x" + "55" * 20,
            timeout=1_800_000_000,
            amount_wei=12_345_678,
            token_address=_USDC.address,
        )

    def test_a_frozen_address_makes_claim_RAISE_and_never_broadcast(self) -> None:
        from pyrxd.security.errors import ValidationError

        leg = self._leg(frozen=True)
        with pytest.raises(ValidationError, match="refusing to reveal the preimage"):
            asyncio.run(leg.claim(self._locator(), b"\x00" * 32))

    def test_an_underfunded_contract_makes_claim_RAISE_before_the_freeze_read(self) -> None:
        """The on-chain Underfunded revert does NOT keep the preimage secret — a reverted tx is
        still mined and `p` is in its calldata. Refusing to BUILD the claim is the real defence."""
        from pyrxd.security.errors import ValidationError

        leg = self._leg(frozen=False, held=1)
        with pytest.raises(ValidationError, match="refusing to build a claim"):
            asyncio.run(leg.claim(self._locator(), b"\x00" * 32))
