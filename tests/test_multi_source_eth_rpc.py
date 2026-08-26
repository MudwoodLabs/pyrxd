"""Quorum reads across independent EVM endpoints.

Every EVM read the swap depends on used to rest on one endpoint's word — the freeze gate's own
docstring said it "defends a FAILING provider, not a LYING one". This is the ETH analogue of
``MultiSourceBtcFundingReader``, and the tests below are organised around the two things that go
wrong: an endpoint that LIES, and an endpoint that LAGS.

The lagging case is not hypothetical for this stack. `erc20_leg.claim` already carries a comment
about a load-balanced provider serving a lagging node, returning a stale low balance, refusing a
claim and killing the secret "for a reading that was simply out of date".

Every refusal is paired with the honest path, because a quorum that refuses working endpoints is a
worse outage than the single-source read it replaced.
"""

from __future__ import annotations

import asyncio
import pathlib

import pytest

from pyrxd.eth_wallet.erc20 import assert_not_frozen_before_funding, balance_of, is_blacklisted
from pyrxd.eth_wallet.multi_rpc import MultiSourceEthRpc, read_contract
from pyrxd.eth_wallet.tokens import token_for
from pyrxd.security.errors import NetworkError, ValidationError

pytest.importorskip("web3", reason="needs the eth extra: pip install 'pyrxd[eth]'")

_USDT = token_for("USDT", 1)  # blacklist_fn == "isBlackListed"
_USDC = token_for("USDC", 1)  # blacklist_fn == "isBlacklisted"
_WHO = "0x" + "11" * 20
_HTLC = "0x" + "77" * 20


class _Source:
    """One endpoint with dictated answers. `down=True` makes every read raise."""

    def __init__(
        self, *, balance=0, frozen=(), decimals=6, finalized=100, head=110, down=False, head_ts=1_700_000_000
    ) -> None:
        self.balance, self.decimals = balance, decimals
        self.frozen = {a.lower() for a in frozen}
        self.finalized, self.head, self.down = finalized, head, down
        self.head_ts = head_ts
        self.writes: list[str] = []
        outer = self

        class _Call:
            def __init__(self, v):
                self._v = v

            async def call(self, *a, **k):
                if outer.down:
                    raise NetworkError("endpoint down")
                return self._v

        class _Fns:
            def balanceOf(self, _who):
                return _Call(outer.balance)

            def decimals(self):
                return _Call(outer.decimals)

            def isBlackListed(self, who):
                return _Call(who.lower() in outer.frozen)

            def isBlacklisted(self, who):
                return _Call(who.lower() in outer.frozen)

        class _Contract:
            functions = _Fns()

        class _Eth:
            def contract(self, *a, **k):
                return _Contract()

        class _W3:
            eth = _Eth()

        self.w3 = _W3()

    async def _guard(self):
        if self.down:
            raise NetworkError("endpoint down")

    async def assert_chain(self):
        await self._guard()

    async def finalized_block_number(self):
        await self._guard()
        return self.finalized

    async def block_number(self):
        await self._guard()
        return self.head

    async def get_balance(self, _a, _b=None):
        await self._guard()
        return self.balance

    async def get_code(self, _a, _b=None):
        await self._guard()
        return b"\x60" * 4 if not self.down else b""

    async def canonical_block_hash(self, n):
        await self._guard()
        return bytes([n % 256]) * 32

    async def get_transaction_count(self, _a, block="pending"):
        self.writes.append(f"nonce:{block}")
        return 7

    async def send_raw(self, _raw):
        self.writes.append("send_raw")
        return "0xsent"

    async def fee_fields(self):
        self.writes.append("fee_fields")
        return {"maxFeePerGas": 3}

    async def latest_block_timestamp(self):
        await self._guard()
        return self.head_ts

    @property
    def write_w3(self):
        return self.w3

    async def close(self):
        return None


def _run(coro):
    return asyncio.run(coro)


class TestItRefusesToPretendToBeAQuorum:
    def test_one_source_is_not_a_quorum(self) -> None:
        with pytest.raises(ValidationError, match="at least 2 sources"):
            MultiSourceEthRpc([_Source()])

    def test_a_quorum_larger_than_the_source_count_is_refused_up_front(self) -> None:
        """It would fail closed on every read — better to say so at construction than to look
        configured and refuse everything at swap time."""
        with pytest.raises(ValidationError, match="can never be reached"):
            MultiSourceEthRpc([_Source(), _Source()], min_agreeing=3)

    def test_min_agreeing_of_one_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="single-source with extra steps"):
            MultiSourceEthRpc([_Source(), _Source()], min_agreeing=1)

    def test_w3_RAISES_rather_than_quietly_serving_one_endpoint(self) -> None:
        """The single most important line in the class. Returning the primary's w3 would leave
        every unconverted contract read working, against one endpoint, on an object advertising a
        quorum — a false guarantee that breaks nothing and so is never noticed."""
        rpc = MultiSourceEthRpc([_Source(), _Source()])
        with pytest.raises(ValidationError, match="read_contract"):
            _ = rpc.w3


class TestDisagreementIsARefusalNotAVote:
    def test_an_identity_read_refuses_when_endpoints_disagree(self) -> None:
        rpc = MultiSourceEthRpc([_Source(decimals=6), _Source(decimals=18), _Source(decimals=6)])
        with pytest.raises(NetworkError, match="disagree"):
            _run(read_contract(rpc, lambda r: r.w3.eth.contract().functions.decimals().call(), label="decimals()"))

    def test_it_does_NOT_take_the_majority(self) -> None:
        """2-of-3 agreeing on 6 looks like a majority for 6. It is also exactly what one lying
        endpoint produces, and there is no way to tell which from here — so refuse."""
        rpc = MultiSourceEthRpc([_Source(decimals=6), _Source(decimals=6), _Source(decimals=18)])
        with pytest.raises(NetworkError, match="disagree"):
            _run(read_contract(rpc, lambda r: r.w3.eth.contract().functions.decimals().call(), label="decimals()"))

    def test_agreement_passes_through_unchanged(self) -> None:
        rpc = MultiSourceEthRpc([_Source(decimals=6), _Source(decimals=6)])
        got = _run(read_contract(rpc, lambda r: r.w3.eth.contract().functions.decimals().call(), label="d"))
        assert got == 6

    def test_canonical_block_hash_is_an_identity_read(self) -> None:
        """Endpoints disagreeing on a block hash are on different forks — the exact condition the
        reorg gate exists to refuse."""
        a, b = _Source(), _Source()
        rpc = MultiSourceEthRpc([a, b])
        assert _run(rpc.canonical_block_hash(5)) == bytes([5]) * 32
        b.canonical_block_hash = lambda n: _done(b"\xff" * 32)
        with pytest.raises(NetworkError, match="disagree"):
            _run(rpc.canonical_block_hash(5))


def _done(v):
    async def _c():
        return v

    return _c()


class TestMagnitudeReadsTakeTheConservativeAnswer:
    def test_a_balance_takes_the_MINIMUM(self) -> None:
        """A lagging endpoint can then only under-report and refuse a swap — never over-credit one
        into a reveal, which is the direction with no recovery."""
        rpc = MultiSourceEthRpc([_Source(balance=1_000_000), _Source(balance=0)])
        assert _run(balance_of(rpc, _USDT, _HTLC)) == 0

    def test_finalized_height_takes_the_MINIMUM(self) -> None:
        rpc = MultiSourceEthRpc([_Source(finalized=100), _Source(finalized=90)])
        assert _run(rpc.finalized_block_number()) == 90

    def test_head_takes_the_MINIMUM_so_the_finalized_gt_head_check_is_strictest(self) -> None:
        rpc = MultiSourceEthRpc([_Source(head=110), _Source(head=105)])
        assert _run(rpc.block_number()) == 105

    def test_the_honest_path_reports_the_real_balance(self) -> None:
        """The pair for the MIN test: a quorum that always returned 0 would pass it."""
        rpc = MultiSourceEthRpc([_Source(balance=1_000_000), _Source(balance=1_000_000)])
        assert _run(balance_of(rpc, _USDT, _HTLC)) == 1_000_000


class TestTheFreezeReadLeansTheOtherWay:
    def test_ONE_endpoint_reporting_frozen_is_enough_to_refuse(self) -> None:
        """`any`, not majority. The dangerous answer is "not frozen": believing it costs the
        preimage, and no timeout recovers a frozen contract. Believing a false "frozen" costs a
        swap that both sides can still refund."""
        rpc = MultiSourceEthRpc([_Source(frozen=(_WHO,)), _Source(), _Source()])
        assert _run(is_blacklisted(rpc, _USDT, _WHO)) is True

    def test_nobody_reporting_frozen_still_lets_an_honest_swap_through(self) -> None:
        rpc = MultiSourceEthRpc([_Source(), _Source(), _Source()])
        assert _run(is_blacklisted(rpc, _USDT, _WHO)) is False

    def test_the_per_token_predicate_name_still_applies_per_source(self) -> None:
        """USDC answers `isBlacklisted`; L1 USDT answers `isBlackListed`. Fanning out must not
        collapse that back to one hard-coded spelling."""
        rpc = MultiSourceEthRpc([_Source(frozen=(_WHO,)), _Source(frozen=(_WHO,))])
        assert _run(is_blacklisted(rpc, _USDC, _WHO)) is True
        assert _run(is_blacklisted(rpc, _USDT, _WHO)) is True


class TestBelowQuorumIsAnError:
    def test_a_dead_endpoint_does_not_silently_shrink_the_quorum(self) -> None:
        """ "Two of three agreed" and "the only one that answered said so" are different facts."""
        rpc = MultiSourceEthRpc([_Source(balance=5), _Source(down=True), _Source(down=True)])
        with pytest.raises(NetworkError, match="quorum is 2"):
            _run(balance_of(rpc, _USDT, _HTLC))

    def test_exactly_quorum_is_enough(self) -> None:
        """The honest-path pair: one endpoint down out of three must NOT stop a swap."""
        rpc = MultiSourceEthRpc([_Source(balance=5), _Source(balance=5), _Source(down=True)])
        assert _run(balance_of(rpc, _USDT, _HTLC)) == 5

    def test_an_UNREACHABLE_source_does_not_abort_a_swap_above_quorum(self) -> None:
        """Liveness, learned mid-swap. The first version awaited every source unconditionally, so
        one rate-limited public endpoint aborted `verify_funded` with real value already locked in
        the HTLC. An endpoint that cannot be reached also cannot lie, and if it returns on a
        different chain every identity read refuses on the disagreement."""
        rpc = MultiSourceEthRpc([_Source(), _Source(), _Source(down=True)])
        _run(rpc.assert_chain())

    def test_a_WRONG_CHAIN_source_is_still_fatal_even_above_quorum(self) -> None:
        """The safety half, and it must not be softened by the liveness fix: a quorum spanning two
        chains is not a weaker guarantee, it is a meaningless one."""
        good, bad = _Source(), _Source()

        async def _wrong():
            raise ValidationError("RPC chain_id 8453 != expected 1 (wrong network)")

        bad.assert_chain = _wrong
        rpc = MultiSourceEthRpc([good, _Source(), bad])
        with pytest.raises(ValidationError, match="wrong network"):
            _run(rpc.assert_chain())

    def test_assert_chain_requires_EVERY_source_not_a_quorum(self) -> None:
        """A quorum spanning two different chains is not a weaker guarantee, it is a meaningless
        one — the same reasoning the ElectrumX failover layer uses."""
        rpc = MultiSourceEthRpc([_Source(), _Source(down=True)])
        with pytest.raises(NetworkError):
            _run(rpc.assert_chain())


class TestWritesAndTipStateStayOnOneEndpoint:
    def test_the_nonce_comes_from_the_endpoint_that_will_broadcast(self) -> None:
        a, b = _Source(), _Source()
        rpc = MultiSourceEthRpc([a, b])
        _run(rpc.get_transaction_count(_WHO))
        assert a.writes and not b.writes, "a nonce from another endpoint's mempool builds on state it lacks"

    def test_broadcast_goes_to_one_endpoint_only(self) -> None:
        a, b = _Source(), _Source()
        rpc = MultiSourceEthRpc([a, b])
        _run(rpc.send_raw(b"\x01"))
        assert a.writes == ["send_raw"] and b.writes == []


class TestItIsReachedFromTheProductionGatesNotOnlyDirectly:
    """Reachability. A quorum class exercised only by direct calls proves the mechanism, not that
    any swap decision actually consults it."""

    def test_the_PRE_FUND_gate_refuses_when_one_endpoint_sees_a_freeze(self) -> None:
        rpc = MultiSourceEthRpc([_Source(), _Source(frozen=(_WHO,))])
        with pytest.raises(ValidationError, match="refusing to fund"):
            _run(
                assert_not_frozen_before_funding(
                    rpc, _USDT, claimant="0x" + "44" * 20, refundee=_WHO, htlc_address=None
                )
            )

    def test_the_same_gate_passes_when_every_endpoint_agrees_nobody_is_frozen(self) -> None:
        rpc = MultiSourceEthRpc([_Source(), _Source()])
        _run(assert_not_frozen_before_funding(rpc, _USDT, claimant="0x" + "44" * 20, refundee=_WHO, htlc_address=_HTLC))

    def test_a_LYING_endpoint_cannot_report_a_contract_funded(self) -> None:
        """The scenario this whole module exists for. One endpoint claims the HTLC holds the full
        amount; the other sees it empty. MIN refuses, so the maker never reveals against a
        contract that was never funded."""
        rpc = MultiSourceEthRpc([_Source(balance=12_345_678), _Source(balance=0)])
        assert _run(balance_of(rpc, _USDT, _HTLC)) == 0


class TestItIsActuallyUSABLEByTheLegs:
    """The gap that nearly shipped.

    The first version of this class made `w3` fatal to stop a read going single-source, and the
    quorum tests all passed — because they called `balance_of` and the freeze gate directly. Not
    one of them constructed a leg. `fund()` and `claim()` reach the rpc for tx building and for the
    deadline guard's head timestamp, so passing a MultiSourceEthRpc to a leg would have raised
    immediately: a quorum class that no swap could actually use.
    """

    def test_it_offers_everything_EthRpc_does_except_the_one_thing_it_refuses(self) -> None:
        """Drop-in means drop-in. `w3` is the single deliberate exception, and it is replaced by
        `write_w3` rather than simply removed."""
        from pyrxd.eth_wallet.rpc import EthRpc

        expected = {n for n in dir(EthRpc) if not n.startswith("_")}
        actual = {n for n in dir(MultiSourceEthRpc) if not n.startswith("_")}
        missing = expected - actual
        assert not missing, f"MultiSourceEthRpc cannot stand in for EthRpc; missing {sorted(missing)}"
        assert "write_w3" in actual, "the write path needs a name that is not `w3`"

    def test_NO_production_code_reads_state_through_a_bare_rpc_w3(self) -> None:
        """The invariant `w3`-raises exists to enforce, pinned where it can actually be checked.

        A source-level assertion rather than a behavioural one, because the failure it prevents is
        a call site that was never converted — and an unconverted call site is, by definition, one
        no test exercises.

        It looks for exactly `self._rpc.w3`, the one shape that is dangerous *quietly*. A helper
        taking an `rpc` parameter (like `erc20._contract`) is fine: it uses whatever it is handed,
        which is the per-source rpc from a `read_contract` lambda — and if someone ever hands it
        `self._rpc` directly, `MultiSourceEthRpc.w3` raises. That case fails loudly, so it does not
        need a grep. This one would not.
        """
        offenders = []
        for path in sorted(pathlib.Path("src/pyrxd").rglob("*.py")):
            if path.name == "multi_rpc.py":
                continue
            for i, line in enumerate(path.read_text().splitlines(), 1):
                if "self._rpc.w3" in line:
                    offenders.append(f"{path}:{i}: {line.strip()}")
        assert not offenders, "route these through read_contract (reads) or write_w3 (writes):\n" + "\n".join(offenders)

    def test_a_leg_CONSTRUCTS_and_reads_through_a_multi_source_rpc(self) -> None:
        """Reachability through the real class, not a protocol check."""
        import json as _json
        import os as _os

        from pyrxd.eth_wallet.erc20_leg import Erc20HtlcLeg
        from pyrxd.security.secrets import PrivateKeyMaterial

        artifact = _json.loads(pathlib.Path("tests/fixtures/Erc20Htlc.json").read_text())
        rpc = MultiSourceEthRpc([_Source(balance=5), _Source(balance=9)])
        leg = Erc20HtlcLeg(
            token=_USDT, rpc=rpc, signing_key=PrivateKeyMaterial(_os.urandom(32)), chain_id=1, artifact=artifact
        )
        # A read through the leg's own rpc: quorum applies, and MIN is what comes back.
        assert _run(balance_of(leg._rpc, _USDT, _HTLC)) == 5
        # And the write path is reachable rather than fatal.
        assert leg._rpc.write_w3 is not None

    def test_the_claim_deadline_guard_can_read_a_head_timestamp(self) -> None:
        """`claim()` consults the head before revealing. Under the first design this raised, which
        would have made every multi-source claim impossible."""
        rpc = MultiSourceEthRpc([_Source(), _Source()])
        assert _run(rpc.latest_block_timestamp()) == 1_700_000_000

    def test_the_head_timestamp_takes_the_MAX_not_the_min(self) -> None:
        """Opposite direction from every other magnitude read here, and deliberately. A lagging
        endpoint reports an EARLIER head, which is what makes the deadline guard pass when it
        should refuse — so the latest any endpoint admits to is the conservative one."""
        rpc = MultiSourceEthRpc([_Source(head_ts=1_700_000_000), _Source(head_ts=1_700_000_600)])
        assert _run(rpc.latest_block_timestamp()) == 1_700_000_600
