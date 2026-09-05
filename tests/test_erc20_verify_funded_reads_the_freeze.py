"""#486: the maker's verification of a taker-built token HTLC never asked about a freeze.

`assert_not_frozen_before_funding` guards the FUNDER's own paths (`fund`, `_push_and_bind`);
`assert_not_frozen_before_reveal` guards the moment `p` goes public. Between them sat the maker's
`verify_counterparty_funded`, which binds a counterparty-deployed contract to the negotiated terms
a dozen ways and never asked the one question that decides whether the leg can pay anyone at all.

#486 framed this as protecting the maker's LOCK. That premise is stale: the maker locks RXD FIRST
(the HZ-1 ordering, documented on `verify_counterparty_funded` itself), so the covenant is already
committed when this runs. What the check buys is EARLIER NOTICE — without it the maker first learns
at claim time, after sitting out the finality gates.

PLACEMENT was itself a defect and is pinned below. The check first went into
`Erc20HtlcLeg.verify_funded`, which `fund` and `_push_and_bind` also call, having already run the
pre-fund freeze gate — so it was redundant there and, because the predicate fails CLOSED on an
unreadable answer, it added a fresh way for a RESUME to abort over a question already answered.
Two honest-path tests in `test_eoa_recipient_policy.py` failed and said so.

Every refusal is paired with the honest path through the same method: a gate that refuses a swap
which could still complete is a worse bug than the one it prevents.
"""

from __future__ import annotations

import asyncio
import os

import pytest

from pyrxd.eth_wallet.tokens import token_for
from pyrxd.gravity import eth_leg as _mod
from pyrxd.security.errors import ValidationError
from pyrxd.security.secrets import PrivateKeyMaterial

pytest.importorskip("web3", reason="needs the eth extra: pip install 'pyrxd[eth]'")

from pyrxd.eth_wallet.erc20_leg import Erc20HtlcLeg
from pyrxd.eth_wallet.locator import Erc20HtlcLocator
from pyrxd.gravity.eth_leg import EthLeg
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


class _Terms:
    value_amount = _AMOUNT
    token_address = _USDC.address


def _verify(monkeypatch, *, frozen: tuple[str, ...] = (), native: bool = False) -> list[str]:
    """Drive the REAL `EthLeg.verify_counterparty_funded`, stubbing only the binds BEFORE the check.

    Reaching the production entry point is the point. A test calling `is_blacklisted` directly
    proves the predicate and says nothing about whether the maker's path consults it — which was
    exactly the state of affairs #486 describes.
    """
    frozen_set = {a.lower() for a in frozen}
    reads: list[str] = []

    async def _is_blacklisted(rpc, token, addr):
        reads.append(addr)
        return addr.lower() in frozen_set

    monkeypatch.setattr(_mod, "is_blacklisted", _is_blacklisted)

    inner = Erc20HtlcLeg(
        token=_USDC, rpc=object(), signing_key=PrivateKeyMaterial(os.urandom(32)), chain_id=1, artifact=_ART
    )
    if native:
        # A native-ETH leg has no `token`, and no issuer who could freeze anything.
        monkeypatch.delattr(type(inner), "token", raising=False)
        monkeypatch.setattr(inner, "token", None, raising=False)

    leg = EthLeg(
        contract_leg=inner,
        network="anvil",
        claim_to=_CLAIMANT,
        refund_to=_REFUNDEE,
        eth_timeout_unix_s=2_000_000_000,
    )

    async def _noop_verify(locator, **k):
        return None

    monkeypatch.setattr(inner, "verify_funded", _noop_verify)
    monkeypatch.setattr(leg, "expected_locator", lambda terms, *, contract_address: _locator())

    asyncio.run(leg.verify_counterparty_funded(_CONTRACT, _Terms()))
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

    def test_the_refusal_tells_the_maker_what_to_do(self, monkeypatch) -> None:
        """A verdict an operator cannot act on has not reached a human. The maker's move here is
        the CSV refund of its own covenant, not a retry."""
        with pytest.raises(ValidationError) as exc:
            _verify(monkeypatch, frozen=(_CONTRACT,))
        assert "refund its own covenant" in str(exc.value)
        assert "NOTHING HAS MOVED" in str(exc.value)


class TestItDoesNotRefuseWorkThatCanStillComplete:
    """The half that makes the guard safe to ship."""

    def test_an_unfrozen_leg_verifies(self, monkeypatch) -> None:
        reads = _verify(monkeypatch)
        assert reads, "the honest path must still CONSULT the freeze predicate, not skip it"

    def test_a_frozen_REFUNDEE_alone_still_verifies(self, monkeypatch) -> None:
        """Deliberate. A claim never touches the refundee, so this swap can still complete happily.
        Refusing would hand the counterparty a free unilateral veto — the same reasoning that keeps
        the refundee out of the pre-reveal gate. It stays the pre-FUND gate's business, where a dead
        refund path is the funder's own risk to weigh."""
        _verify(monkeypatch, frozen=(_REFUNDEE,))

    def test_the_refundee_is_never_even_read(self, monkeypatch) -> None:
        """Stronger than the above: pins WHICH addresses the gate consults, so a later edit adding
        the refundee back has to change this test and say why."""
        reads = [a.lower() for a in _verify(monkeypatch)]
        assert _REFUNDEE.lower() not in reads
        assert {_CONTRACT.lower(), _CLAIMANT.lower()} <= set(reads)

    def test_a_NATIVE_eth_leg_reads_nothing(self, monkeypatch) -> None:
        """No issuer, no freeze. A native leg must not pay for a token-only question — and must not
        fail closed on an RPC that has no `isBlacklisted` to answer with."""
        assert _verify(monkeypatch, native=True) == []
