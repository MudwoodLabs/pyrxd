"""#486: the maker's verification of a taker-funded token HTLC never asked about a freeze.

`assert_not_frozen_before_funding` guards the FUNDER's own paths (`fund`, `_push_and_bind`) and
`assert_not_frozen_before_reveal` guards the moment `p` goes public. Between them sat the maker's
`verify_funded`, which binds the contract to the negotiated terms in a dozen ways and never asked
the one question that decides whether the leg can pay anyone at all.

#486 framed this as protecting the maker's LOCK, and that premise is stale: the maker locks RXD
FIRST (the HZ-1 ordering, see `EthLeg.verify_counterparty_funded`), so the covenant is already
committed by the time any of this runs. What the check actually buys is EARLIER NOTICE — without
it the maker first learns at claim time, after sitting out the finality gates.

Every refusal below is paired with the honest path through the same method, because a gate that
refuses a swap which could still complete is a worse bug than the one it prevents.
"""

from __future__ import annotations

import asyncio
import os

import pytest

from pyrxd.eth_wallet import erc20_leg as _mod
from pyrxd.eth_wallet.erc20_leg import Erc20HtlcLeg
from pyrxd.eth_wallet.htlc_leg import EthHtlcContractLeg
from pyrxd.eth_wallet.locator import Erc20HtlcLocator
from pyrxd.eth_wallet.tokens import token_for
from pyrxd.security.errors import ValidationError
from pyrxd.security.secrets import PrivateKeyMaterial

pytest.importorskip("web3", reason="needs the eth extra: pip install 'pyrxd[eth]'")

from tests.test_deployed_contract_is_durable_before_funding import _ART

_USDC = token_for("USDC", 1)
_CONTRACT = "0x" + "77" * 20
_CLAIMANT = "0x" + "44" * 20
_REFUNDEE = "0x" + "55" * 20
_AMOUNT = 12_345_678


def _locator() -> Erc20HtlcLocator:
    return Erc20HtlcLocator(
        chain_id=1,
        contract_address=_CONTRACT,
        deploy_tx_hash="0x" + "ab" * 32,
        hashlock="0x" + "33" * 32,
        claimant=_CLAIMANT,
        refundee=_REFUNDEE,
        timeout=2_000_000_000,
        amount_wei=_AMOUNT,
        token_address=_USDC.address,
    )


def _verify(monkeypatch, *, frozen: tuple[str, ...] = ()) -> None:
    """Run the REAL `Erc20HtlcLeg.verify_funded`, with only the reads before the freeze check stubbed.

    The point is that the check runs as part of that method — a test calling `is_blacklisted`
    directly would prove the predicate and say nothing about whether the maker's path consults it.
    """
    frozen_set = {a.lower() for a in frozen}
    reads: list[str] = []

    async def _noop_super(self, locator, **k):
        return None

    async def _read_contract(rpc, call, *, label):
        return _USDC.address if ".token()" in label else _AMOUNT

    async def _balance_of(*a, **k):
        return _AMOUNT

    async def _is_blacklisted(rpc, token, addr):
        reads.append(addr)
        return addr.lower() in frozen_set

    monkeypatch.setattr(EthHtlcContractLeg, "verify_funded", _noop_super)
    monkeypatch.setattr(_mod, "assert_token_matches_chain", lambda *a, **k: asyncio.sleep(0))
    monkeypatch.setattr(_mod, "read_contract", _read_contract)
    monkeypatch.setattr(_mod, "balance_of", _balance_of)
    monkeypatch.setattr(_mod, "is_blacklisted", _is_blacklisted)

    leg = Erc20HtlcLeg(
        token=_USDC, rpc=object(), signing_key=PrivateKeyMaterial(os.urandom(32)), chain_id=1, artifact=_ART
    )
    asyncio.run(leg.verify_funded(_locator(), expected_amount_wei=_AMOUNT))
    return reads


class TestTheMakerNowLearnsBeforeItWaits:
    def test_a_frozen_CONTRACT_is_refused(self, monkeypatch) -> None:
        """The unrecoverable case: freezing the contract reverts claim() AND refund(), with no
        timeout that rescues the tokens."""
        with pytest.raises(ValidationError, match="refusing to verify") as exc:
            _verify(monkeypatch, frozen=(_CONTRACT,))
        assert "htlc contract" in str(exc.value)
        assert _CONTRACT in str(exc.value), "name the address so an operator can act on it"

    def test_a_frozen_CLAIMANT_is_refused(self, monkeypatch) -> None:
        """#486's title case: the maker's own payout address. A frozen claimant cannot receive a
        claim at all, so the swap could only ever end in the counterparty's refund."""
        with pytest.raises(ValidationError, match="refusing to verify") as exc:
            _verify(monkeypatch, frozen=(_CLAIMANT,))
        assert "claimant" in str(exc.value)


class TestItDoesNotRefuseWorkThatCanStillComplete:
    """The half that makes the guard safe to ship."""

    def test_an_unfrozen_leg_verifies(self, monkeypatch) -> None:
        reads = _verify(monkeypatch)
        assert reads, "the honest path must still CONSULT the freeze predicate, not skip it"

    def test_a_frozen_REFUNDEE_alone_still_verifies(self, monkeypatch) -> None:
        """Deliberate. A claim never touches the refundee, so this swap can still complete happily.
        Refusing would hand the counterparty a free unilateral veto — the same reasoning that keeps
        the refundee out of the pre-reveal gate. It is the pre-FUND gate's job, where a dead refund
        path is the funder's own risk to weigh."""
        _verify(monkeypatch, frozen=(_REFUNDEE,))

    def test_the_refundee_is_never_even_read(self, monkeypatch) -> None:
        """Stronger than the above: pins WHICH addresses the gate consults, so a later edit that
        adds the refundee back has to change this test and state why."""
        reads = [a.lower() for a in _verify(monkeypatch)]
        assert _REFUNDEE.lower() not in reads
        assert {_CONTRACT.lower(), _CLAIMANT.lower()} <= set(reads)
