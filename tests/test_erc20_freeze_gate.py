"""The pre-reveal freeze gate must FAIL CLOSED.

Found by security review of this branch. The gate exists to stop a party publishing the preimage
into a freeze — once it is public the counterparty takes the other leg, so a wrong "not frozen" is
a one-sided loss with no recovery. The first version caught every exception and returned ``False``,
so an unreachable or rate-limited RPC reported "safe": a fail-OPEN in the one gate that prevents an
unrecoverable outcome, firing exactly when the caller is already in trouble.
"""

from __future__ import annotations

import asyncio
import time

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
        self.write_w3 = self.w3

    async def latest_block_timestamp(self):
        return int(time.time())

    async def latest_block_timestamp_min(self):
        # The multi-source class aggregates this the other way for the staleness and
        # refund-maturity guards; one endpoint has one answer, so the fake mirrors it.
        return await self.latest_block_timestamp()

    async def latest_block_timestamp_quorum(self):
        # The staleness abort reads the QUORUM-th head: MIN lets one lagging endpoint
        # declare a healthy chain halted, MAX lets one liar hide a real halt. A single
        # source has one answer, so all three coincide here.
        return await self.latest_block_timestamp()


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

            write_w3 = w3

            async def latest_block_timestamp(self):
                return int(time.time())

            async def latest_block_timestamp_min(self):
                # The multi-source class aggregates this the other way for the staleness and
                # refund-maturity guards; one endpoint has one answer, so the fake mirrors it.
                return await self.latest_block_timestamp()

            async def latest_block_timestamp_quorum(self):
                # The staleness abort reads the QUORUM-th head: MIN lets one lagging endpoint
                # declare a healthy chain halted, MAX lets one liar hide a real halt. A single
                # source has one answer, so all three coincide here.
                return await self.latest_block_timestamp()

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
        """PreRevealAbort, not ValidationError. The verdict comes from a SINGLE unauthenticated
        read at the tip — `is_blacklisted` defends a failing provider, not a lying one — so a
        hostile or misconfigured RPC answering `true` once must not destroy the only copy of the
        secret. Blacklists are reversible too, so "the swap cannot complete" is not durable."""
        from pyrxd.security.errors import PreRevealAbort

        leg = self._leg(frozen=True)
        with pytest.raises(PreRevealAbort, match="refusing to reveal"):
            asyncio.run(leg.claim(self._locator(), _PREIMAGE))

    def test_an_underfunded_contract_makes_claim_RAISE_before_the_freeze_read(self) -> None:
        """The on-chain Underfunded revert does NOT keep the preimage secret — a reverted tx is
        still mined and `p` is in its calldata. Refusing to BUILD the claim is the real defence."""
        from pyrxd.security.errors import PreRevealAbort

        leg = self._leg(frozen=False, held=1)
        with pytest.raises(PreRevealAbort, match="refusing to build a claim"):
            asyncio.run(leg.claim(self._locator(), _PREIMAGE))

    def test_the_balance_check_runs_BEFORE_the_freeze_read_even_when_both_would_fire(self) -> None:
        """The case above cannot actually pin the ordering: with `frozen=False` the freeze read
        raises nothing, so it reads identically whether it ran first or second. Make BOTH
        conditions true and the message names which check owns the refusal. Ordering matters
        because the balance read is local and free while the freeze read costs two RPC round
        trips against a provider that may be lying or down."""
        from pyrxd.security.errors import PreRevealAbort

        leg = self._leg(frozen=True, held=1)
        with pytest.raises(PreRevealAbort, match="refusing to build a claim"):
            asyncio.run(leg.claim(self._locator(), _PREIMAGE))

    def test_the_underfunded_refusal_PRESERVES_the_preimage(self) -> None:
        """The sibling lane of #479. Round 2 made a transport failure keep the secret but left this
        value lane raising ValidationError, so a lagging provider's stale balance destroyed a
        still-secret preimage. Nothing is broadcast here, so it must be retryable — and keeping p
        costs nothing even when the contract really is short: the maker simply does not claim."""
        from pyrxd.security.errors import PreRevealAbort, ValidationError

        leg = self._leg(frozen=False, held=1)
        with pytest.raises(PreRevealAbort) as exc:
            asyncio.run(leg.claim(self._locator(), _PREIMAGE))
        assert not isinstance(exc.value, ValidationError), (
            "a ValidationError here would make the coordinator zeroize a preimage that never left the process"
        )


class TestTheContractAddressCannotBeDisplacedByACallerKey:
    """`{"htlc contract": htlc_address, **parties}` let a caller passing that same key OVERWRITE
    the mandatory address — silently defeating the guarantee that it cannot be omitted. Nothing
    does that today; the point is that nothing would have noticed."""

    def test_a_colliding_party_key_does_not_replace_the_htlc_address(self) -> None:
        frozen_addr = "0x" + "de" * 20
        checked: list[str] = []

        class _Recorder:
            class w3:
                class eth:
                    @staticmethod
                    def contract(*a, **k):
                        class _C:
                            class functions:
                                @staticmethod
                                def isBlacklisted(addr):
                                    checked.append(addr)

                                    class _Call:
                                        async def call(self, *a, **k):
                                            return addr == frozen_addr

                                    return _Call()

                        return _C()

        with pytest.raises(Exception):
            asyncio.run(
                assert_not_frozen_before_reveal(
                    _Recorder(),
                    _USDC,
                    htlc_address=frozen_addr,
                    parties={"htlc contract": "0x" + "aa" * 20},  # tries to displace it
                )
            )
        assert frozen_addr in checked, "the real HTLC address must still be checked"


#: A NON-ZERO preimage. `assert_claim_provenance` confirms a claim by substring-matching p over
#: the log's topics+data, so a p of 32 zero bytes is satisfied by ANY zero-padded log word — a
#: receipt carrying no Claimed event at all still "confirms". Demonstrated: 64 zero bytes confirm
#: under an all-zero p and correctly refuse under this one. The honest-path assertion here is the
#: only place the ERC-20 claim runs end to end offline, so it must be falsifiable.
_PREIMAGE = bytes.fromhex("11" * 32)
_HTLC = "0x" + "11" * 20
_CLAIMANT = "0x" + "44" * 20
_REFUNDEE = "0x" + "55" * 20


def _freeze_locator():
    from pyrxd.eth_wallet.locator import Erc20HtlcLocator

    return Erc20HtlcLocator(
        chain_id=1,
        contract_address=_HTLC,
        deploy_tx_hash="0x" + "22" * 32,
        hashlock="0x" + "33" * 32,
        claimant=_CLAIMANT,
        refundee=_REFUNDEE,
        timeout=int(time.time()) + 86_400,
        amount_wei=12_345_678,
        token_address=_USDC.address,
    )


def _leg_with_frozen(*, frozen_addrs: set, held: int = 12_345_678):
    """A leg whose blacklist answers PER ADDRESS, and whose claim can actually complete.

    The older `_leg` above answers the same `frozen` for every address, so it cannot express
    "the refundee is frozen and nobody else" — which is the whole round-5 question.
    """
    import json
    import os
    import pathlib

    from pyrxd.eth_wallet.erc20_leg import Erc20HtlcLeg
    from pyrxd.security.secrets import PrivateKeyMaterial

    lowered = {a.lower() for a in frozen_addrs}

    class _Call:
        def __init__(self, v):
            self._v = v

        async def call(self, *a, **k):
            return self._v

    class _Fns:
        def isBlacklisted(self, addr, *a, **k):
            return _Call(str(addr).lower() in lowered)

        def balanceOf(self, *a, **k):
            return _Call(held)

        def decimals(self, *a, **k):
            return _Call(6)

        def claim(self, *a, **k):
            class _B:
                async def build_transaction(self_b, tx):
                    return dict(tx)

            return _B()

    class _Contract:
        functions = _Fns()

    class _Eth:
        def contract(self, *a, **k):
            return _Contract()

        async def get_block(self, _which):
            return {"timestamp": int(time.time())}

    class _W3:
        eth = _Eth()

    class _Rpc:
        w3 = _W3()

        write_w3 = w3

        async def latest_block_timestamp(self):
            return int(time.time())

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

        async def wait_receipt(self, tx_hash, **_k):
            # `claim` CONFIRMS before reporting success: status == 1 plus a Claimed(p) log from
            # this swap's own contract. Without this the honest-path test below fails as
            # "unconfirmed" — a reason that has nothing to do with the freeze gate it is about.
            return {
                "status": 1,
                "logs": [{"address": _HTLC, "topics": [], "data": "0x" + _PREIMAGE.hex()}],
            }

        async def fee_fields(self):
            return {"maxPriorityFeePerGas": 1, "maxFeePerGas": 3}

        async def get_transaction_count(self, _a, block="pending"):
            return 0

    art = json.loads((pathlib.Path(__file__).parent / "fixtures" / "Erc20Htlc.json").read_text())
    leg = Erc20HtlcLeg(
        token=_USDC, rpc=_Rpc(), signing_key=PrivateKeyMaterial(os.urandom(32)), chain_id=1, artifact=art
    )

    async def _sign_and_send(*a, **k):
        return "0x" + "ab" * 32

    leg._sign_and_send = _sign_and_send
    return leg


class TestTheGateDoesNotVetoAClaimOnAnAddressThatCannotAffectIt:
    """Round 5, flagged independently by two reviewers. `claim` sweeps to the CLAIMANT. The
    refundee is touched only by `refund()`, so a frozen refundee cannot make a claim revert —
    yet the gate refused on it, which is both a guard refusing valid work and a free veto handed
    to the counterparty: a taker sanctioned after funding could kill the maker's only path to
    USDC it had already earned.
    """

    def test_a_frozen_REFUNDEE_does_not_block_the_makers_claim(self) -> None:
        leg = _leg_with_frozen(frozen_addrs={_REFUNDEE})
        assert asyncio.run(leg.claim(_freeze_locator(), _PREIMAGE)), (
            "a frozen refundee cannot make a claim revert, so refusing the claim forfeits "
            "USDC the maker has already earned"
        )

    def test_a_frozen_CLAIMANT_still_blocks_the_claim(self) -> None:
        """The other half. Narrowing the gate must not disarm it: the claimant is the address the
        payout actually reaches, so a freeze there really would revert the sweep."""
        from pyrxd.security.errors import PreRevealAbort

        leg = _leg_with_frozen(frozen_addrs={_CLAIMANT})
        with pytest.raises(PreRevealAbort, match="refusing to reveal"):
            asyncio.run(leg.claim(_freeze_locator(), _PREIMAGE))

    def test_a_frozen_HTLC_CONTRACT_still_blocks_the_claim(self) -> None:
        """The measured worst case: freezing the contract strands the funds permanently — claim
        AND refund both revert, with no timeout to rescue them."""
        from pyrxd.security.errors import PreRevealAbort

        leg = _leg_with_frozen(frozen_addrs={_HTLC})
        with pytest.raises(PreRevealAbort, match="refusing to reveal"):
            asyncio.run(leg.claim(_freeze_locator(), _PREIMAGE))
