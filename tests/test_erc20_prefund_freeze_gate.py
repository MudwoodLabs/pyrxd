"""The pre-FUND freeze gate: refuse to pay into a position that cannot be exited.

The reveal gate (`tests/test_erc20_freeze_gate.py`) protects the moment the preimage becomes
public. It deliberately does NOT check the refundee, because a `claim` never touches the refundee
and refusing there would hand the counterparty a free unilateral veto.

That left the refundee checked in no code path at all, while three documents described a "pre-fund
gate" that had never been written. `refund()` PAYS the refundee, so a frozen refundee makes it
revert: funding a leg in that state buys a position with no exit, and if the counterparty simply
never claims, the tokens stay in the contract for good.

Every refusal below is paired with the honest path through the same code, because a gate that
refuses real funding is a worse bug than the one it prevents — nothing here is retryable once the
counterparty has walked away.
"""

from __future__ import annotations

import asyncio
import os

import pytest

from pyrxd.eth_wallet.erc20 import assert_not_frozen_before_funding
from pyrxd.eth_wallet.tokens import token_for
from pyrxd.security.errors import NetworkError, ValidationError
from pyrxd.security.secrets import PrivateKeyMaterial

pytest.importorskip("web3", reason="needs the eth extra: pip install 'pyrxd[eth]'")

from tests.test_deployed_contract_is_durable_before_funding import (
    _DEPLOYED,
    _PENDING,
    _fresh_deploy_address,
    _fund,
    _leg,
    _stub_verify,
)

_USDC = token_for("USDC", 1)
_BASE_USDT = token_for("USDT", 8453)  # has_blacklist=False, positively established
_CLAIMANT = "0x" + "44" * 20
_REFUNDEE = "0x" + "55" * 20
_HTLC = "0x" + "77" * 20


class _Rpc:
    """Answers the freeze predicate for a fixed frozen set, and counts the reads."""

    def __init__(self, frozen: tuple[str, ...] = (), raises: Exception | None = None) -> None:
        self.frozen = {a.lower() for a in frozen}
        self.reads: list[str] = []
        outer = self

        class _Call:
            def __init__(self, addr):
                self._addr = addr

            async def call(self, *a, **k):
                outer.reads.append(self._addr)
                if raises is not None:
                    raise raises
                return self._addr.lower() in outer.frozen

        class _Fns:
            def isBlacklisted(self, addr, *a, **k):
                return _Call(addr)

        class _Contract:
            functions = _Fns()

        class _Eth:
            def contract(self, *a, **k):
                return _Contract()

        class _W3:
            eth = _Eth()

        self.w3 = _W3()


def _gate(rpc, *, htlc=_HTLC, claimant=_CLAIMANT, refundee=_REFUNDEE, token=_USDC):
    return asyncio.run(
        assert_not_frozen_before_funding(rpc, token, claimant=claimant, refundee=refundee, htlc_address=htlc)
    )


class TestTheAddressNothingElseChecked:
    def test_a_frozen_REFUNDEE_is_refused(self) -> None:
        """The whole reason this gate exists. The reveal gate ignores the refundee by design."""
        with pytest.raises(ValidationError, match="refusing to fund") as exc:
            _gate(_Rpc(frozen=(_REFUNDEE,)))
        assert "refundee" in str(exc.value)
        assert _REFUNDEE in str(exc.value), "name the address so the operator can act on it"

    def test_the_message_says_WHY_a_frozen_refundee_matters(self) -> None:
        """A refusal an operator cannot act on gets overridden. It must say what breaks."""
        with pytest.raises(ValidationError) as exc:
            _gate(_Rpc(frozen=(_REFUNDEE,)))
        text = str(exc.value)
        assert "refund()" in text
        assert "NO TOKENS HAVE MOVED" in text, "say what is still recoverable"
        # And do NOT claim nothing was spent. This gate also runs from the push site, where the
        # deploy gas is already gone; a message promising "nothing has been spent" is simply false
        # there, and an operator who notices one false clause stops believing the rest.
        assert "Nothing has been spent" not in text


class TestTheOtherTwoAddresses:
    def test_a_frozen_CLAIMANT_is_refused(self) -> None:
        """Not a loss — refund still works — but a deploy, a transfer and a whole timelock spent
        on a swap that could never have completed."""
        with pytest.raises(ValidationError, match="claimant"):
            _gate(_Rpc(frozen=(_CLAIMANT,)))

    def test_a_frozen_CONTRACT_is_refused_and_named_FIRST(self) -> None:
        """The unrecoverable one: a frozen HTLC reverts claim AND refund. When several addresses
        are frozen the report must lead with the one that has no recovery."""
        with pytest.raises(ValidationError) as exc:
            _gate(_Rpc(frozen=(_HTLC, _CLAIMANT, _REFUNDEE)))
        text = str(exc.value)
        assert text.index("htlc contract") < text.index("claimant") < text.index("refundee")

    def test_before_the_deploy_there_is_no_contract_to_check(self) -> None:
        """`htlc_address=None` is the pre-deploy window, and is REQUIRED rather than defaulted so
        that passing nothing is impossible and passing None is a decision."""
        rpc = _Rpc()
        _gate(rpc, htlc=None)
        assert rpc.reads == [_CLAIMANT, _REFUNDEE], "only the parties exist yet"
        with pytest.raises(TypeError):
            asyncio.run(assert_not_frozen_before_funding(_Rpc(), _USDC, claimant=_CLAIMANT, refundee=_REFUNDEE))


class TestItFailsClosed:
    @pytest.mark.parametrize(
        "exc",
        [NetworkError("connection refused"), Exception("429 Too Many Requests"), ValueError("garbage")],
    )
    def test_an_unreadable_answer_RAISES_rather_than_meaning_not_frozen(self, exc) -> None:
        with pytest.raises(NetworkError, match="could not determine"):
            _gate(_Rpc(raises=exc))

    def test_the_unreadable_message_does_not_assume_a_preimage(self) -> None:
        """This text is shared with the reveal gate. It used to say the caller was about to publish
        the preimage, which is simply untrue on the funding path — and a wrong diagnosis sends an
        operator looking in the wrong place."""
        with pytest.raises(NetworkError) as exc:
            _gate(_Rpc(raises=Exception("boom")))
        assert "funding the contract" in str(exc.value)

    @pytest.mark.parametrize("missing", ["claimant", "refundee"])
    def test_an_empty_party_address_is_refused_not_skipped(self, missing) -> None:
        kwargs = {"claimant": _CLAIMANT, "refundee": _REFUNDEE, missing: ""}
        with pytest.raises(ValidationError, match="required by the pre-fund freeze gate"):
            _gate(_Rpc(), **kwargs)


class TestTheHonestPath:
    def test_nobody_frozen_is_allowed_through(self) -> None:
        """The pair for every refusal above. A gate that refused everything would pass them all."""
        rpc = _Rpc()
        _gate(rpc)
        assert rpc.reads == [_HTLC, _CLAIMANT, _REFUNDEE]

    def test_a_token_that_CANNOT_freeze_costs_no_rpc_call_at_all(self) -> None:
        """Base USDT is pinned has_blacklist=False on positive evidence. Adding three reads per
        fund for a token with no blacklist would be latency bought with nothing."""
        rpc = _Rpc()
        _gate(rpc, token=_BASE_USDT)
        assert rpc.reads == []


class TestItIsReachedFromFundNotOnlyFromTests:
    """The reachability requirement. A gate exercised only by direct calls proves the mechanism
    and not that anything invokes it — which is exactly how the reveal gate sat unreachable from
    production for a full review cycle."""

    def test_a_fresh_fund_REFUSES_before_it_spends_deploy_gas(self) -> None:
        """`on_deploy` is the witness, NOT the order list.

        The first version of this test asserted `order == []`. That passes whether or not the
        deploy ran, because the fake only records the PUSH — so deleting the pre-deploy gate
        entirely left it green. `on_deploy` is awaited once the deploy receipt confirms, which
        makes it the only signal here that distinguishes "refused early" from "refused late".
        """
        order: list[str] = []
        deployed: list[str] = []

        async def _on_deploy(address, tx_hash):
            deployed.append(address)

        leg = _leg(order=order, frozen=(_REFUNDEE,))
        with pytest.raises(ValidationError, match="refusing to fund"):
            _fund(leg, on_deploy=_on_deploy)
        assert deployed == [], "a frozen refundee must be caught BEFORE the deploy spends gas"
        assert order == [], "and obviously before any tokens move"

    def test_a_fresh_fund_with_nobody_frozen_still_completes(self) -> None:
        """The honest-path pair: the deploy runs AND the tokens move."""
        order: list[str] = []
        deployed: list[str] = []

        async def _on_deploy(address, tx_hash):
            deployed.append(address)

        leg = _leg(order=order)
        _fund(leg, on_deploy=_on_deploy)
        # The address a fresh deploy reports is CREATE(sender, nonce), not a fixture constant —
        # the leg derives it now rather than believing the receipt.
        assert deployed == [leg._test_state["deployed"]]
        assert "tokens-pushed" in order

    def test_a_RESUME_with_nothing_left_to_send_is_NOT_blocked(self) -> None:
        """The honest-path case that the first version of this gate broke.

        A resume whose push already landed has nothing left to send and nothing left to risk — it
        is calling `fund` only to recover its locator. Refusing it because the refundee is frozen
        would leave a taker whose tokens ARE already in the contract unable to record the fund that
        completed, while un-funding precisely nothing. The gate refuses only when something is
        about to be SENT, which is the same scoping the in-flight guard uses.
        """
        order: list[str] = []
        leg = _leg(order=order, initial_held=12_345_678, frozen=(_REFUNDEE, _DEPLOYED))
        _stub_verify(leg, order)
        locator = _fund(leg, None, resume_from=_PENDING)
        assert locator.contract_address.lower() == _DEPLOYED.lower()
        assert "tokens-pushed" not in order, "there was nothing to send in the first place"

    def test_a_RESUME_that_DOES_still_owe_tokens_is_blocked(self) -> None:
        """The pair for the test above — the same frozen contract, the only difference being that
        this resume still has value to move. Without both, 'refuses when it matters' and 'never
        refuses' look identical."""
        order: list[str] = []
        leg = _leg(order=order, initial_held=1, frozen=(_DEPLOYED,))
        _stub_verify(leg, order)
        with pytest.raises(ValidationError, match="htlc contract"):
            _fund(leg, None, resume_from=_PENDING)
        assert "tokens-pushed" not in order

    def test_the_push_is_gated_on_the_CONTRACT_being_unfrozen(self) -> None:
        """The load-bearing call site. The pre-deploy check cannot name a contract that does not
        exist yet, so this is the only thing standing between a fund and a permanently frozen
        HTLC — and on a resume the contract may have been frozen while we were away."""
        order: list[str] = []
        # Freeze the address this leg will ACTUALLY deploy to. Passing a fixture constant froze an
        # address unrelated to the HTLC and the test still passed, because the fake reported that
        # constant as the contract — the gate was being handed its own answer.
        key = PrivateKeyMaterial(os.urandom(32))
        leg = _leg(order=order, frozen=(_fresh_deploy_address(key),), key=key)
        with pytest.raises(ValidationError, match="htlc contract"):
            _fund(leg, on_deploy=None)
        assert "tokens-pushed" not in order, "no tokens moved into the frozen contract"
