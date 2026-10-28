"""#850 PR C: ``Erc20Htlc.refund`` is callable by the refundee or the deployer only (design D1(c)).

The contract gained a ``deployer`` immutable (``msg.sender`` of the constructor) and ``refund``
reverts ``NotRefunder`` for any other caller. Without it a third party could refund a contract
holding a first small part of a push, set ``settled``, and strand the rest of the push for good.

Python follows in four places, each pinned here with its honest path:

* the locator carries ``deployer`` (absent in older records, and then verifying fails closed);
* the taker's own locator names its own key, and the exact runtime compare binds the slot;
* the maker derives the deployer from the chain (:meth:`Erc20HtlcLeg.derive_deployer`): the
  contract's ``deployer()`` is a candidate, accepted only when CREATE from it at one of its nonces
  is the contract's address;
* the leg's ``refund`` refuses, before signing, a key the contract would refuse.

The behaviour against the real contract is in the Anvil suite (``test_eth_leg_anvil_integration.py``).
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

import pytest

pytest.importorskip("web3", reason="needs the eth extra: pip install 'pyrxd[eth]'")

from pyrxd.eth_wallet import erc20_leg as erc20_leg_mod
from pyrxd.eth_wallet.erc20_leg import Erc20HtlcLeg, _create_address
from pyrxd.eth_wallet.htlc_leg import _REFUND_REVERTS, EthHtlcContractLeg
from pyrxd.eth_wallet.keys import derive_address
from pyrxd.eth_wallet.locator import Erc20HtlcLocator
from pyrxd.eth_wallet.tokens import Erc20Token
from pyrxd.gravity.eth_leg import EthLeg
from pyrxd.security.errors import NetworkError, ValidationError
from pyrxd.security.secrets import PrivateKeyMaterial

_ARTIFACT = json.loads((Path(__file__).parent / "fixtures" / "Erc20Htlc.json").read_text())
_SOURCE = (Path(__file__).resolve().parent.parent / "contracts" / "Erc20Htlc.sol").read_text()
_TOKEN = Erc20Token("TKN", "0x" + "70" * 20, 6, 31337, has_blacklist=False)
_TIMEOUT = 2_000_000_000
_CLAIMANT = "0x" + "44" * 20
_REFUNDEE = "0x" + "55" * 20


def _key() -> PrivateKeyMaterial:
    return PrivateKeyMaterial(os.urandom(32))


def _leg(rpc=None, key=None) -> Erc20HtlcLeg:
    return Erc20HtlcLeg(token=_TOKEN, rpc=rpc, signing_key=key or _key(), chain_id=31337, artifact=_ARTIFACT)


def _locator(*, deployer: str | None, contract: str = "0x" + "c0" * 20) -> Erc20HtlcLocator:
    return Erc20HtlcLocator(
        chain_id=31337,
        contract_address=contract,
        deploy_tx_hash="0x" + "11" * 32,
        hashlock="0x" + "22" * 32,
        claimant=_CLAIMANT,
        refundee=_REFUNDEE,
        timeout=_TIMEOUT,
        amount_wei=1_000_000,
        token_address=_TOKEN.address,
        deployer=deployer,
    )


# ── the contract and the artifact ───────────────────────────────────────────────────────────────


def test_the_artifact_has_a_deployer_immutable_and_the_NotRefunder_error() -> None:
    """Derived from the artifact: the name map holds ``deployer``, it has at least one runtime copy,
    and the ABI carries the getter and the error the leg names."""
    names = _ARTIFACT["immutable_names"]
    ids = [i for i, n in names.items() if n == "deployer"]
    assert len(ids) == 1, names
    assert _ARTIFACT["immutableReferences"][ids[0]], "the deployer immutable has no runtime copy"
    abi = {(e["type"], e.get("name")) for e in _ARTIFACT["abi"]}
    assert ("function", "deployer") in abi and ("error", "NotRefunder") in abi
    assert "NotRefunder" in _REFUND_REVERTS


def test_the_source_checks_the_caller_after_the_clock_and_before_the_balance() -> None:
    """The order the leg's refund mirrors: settled, the timeout, the caller, the balance. Read from
    the source, so a reordering there fails here."""
    body = _SOURCE[_SOURCE.index("function refund()") :]
    body = body[: body.index("\n    }\n")]
    order = [body.index(s) for s in ("AlreadySettled", "NotYetExpired", "NotRefunder", "NothingToRefund")]
    assert order == sorted(order), body
    assert "msg.sender != refundee && msg.sender != deployer" in body
    assert "deployer = msg.sender;" in _SOURCE


# ── the locator ─────────────────────────────────────────────────────────────────────────────────


def test_the_locator_round_trips_its_deployer_lower_cased() -> None:
    who = derive_address(_key())
    loc = _locator(deployer=who)
    assert loc.deployer == who.lower()
    d = loc.to_dict()
    assert d["deployer"] == who.lower()
    assert Erc20HtlcLocator.from_dict(d) == loc


def test_a_record_written_before_the_field_loads_with_no_deployer() -> None:
    """Honest path for old records: a dict without the key loads, and writes back without it."""
    d = _locator(deployer=derive_address(_key())).to_dict()
    del d["deployer"]
    loc = Erc20HtlcLocator.from_dict(d)
    assert loc.deployer is None
    assert "deployer" not in loc.to_dict()


@pytest.mark.parametrize("bad", ["0x" + "ab" * 19, "ab" * 20, "0x" + "zz" * 20, 7])
def test_a_malformed_deployer_is_refused(bad) -> None:
    with pytest.raises(ValidationError, match="deployer"):
        _locator(deployer=bad)


# ── the exact runtime compare binds the slot ────────────────────────────────────────────────────


def test_the_taker_locator_names_its_own_key() -> None:
    key = _key()
    leg = _leg(key=key)
    loc = leg._locator_for(
        address="0x" + "c0" * 20,
        deploy_hash="0x" + "11" * 32,
        hashlock=b"\x22" * 32,
        claimant=_CLAIMANT,
        refundee=_REFUNDEE,
        timeout=_TIMEOUT,
        amount_wei=1_000_000,
    )
    assert loc.deployer == derive_address(key).lower()


def test_every_deployer_copy_holds_the_derived_deployer() -> None:
    who = derive_address(_key())
    runtime = _leg()._expected_runtime(_locator(deployer=who))
    word = b"\x00" * 12 + bytes.fromhex(who[2:])
    ref_id = next(i for i, n in _ARTIFACT["immutable_names"].items() if n == "deployer")
    copies = _ARTIFACT["immutableReferences"][ref_id]
    assert copies
    for ref in copies:
        assert runtime[ref["start"] : ref["start"] + 32] == word


def test_a_locator_with_no_deployer_fails_closed_rather_than_masking_the_slot() -> None:
    with pytest.raises(ValidationError, match=r"immutable 'deployer' .* has no negotiated value"):
        _leg()._expected_runtime(_locator(deployer=None))


# ── the maker derives the deployer from the chain ───────────────────────────────────────────────


class _Endpoint:
    """One endpoint: the contract's ``deployer()`` answer and the candidate's transaction count."""

    def __init__(self, candidate: str, count) -> None:
        self.candidate = candidate
        self.count = count
        self.getter_blocks: list[object] = []
        endpoint = self

        class _Call:
            async def call(self, block_identifier=None):
                endpoint.getter_blocks.append(block_identifier)
                return endpoint.candidate

        class _Fns:
            def deployer(self):
                return _Call()

        class _Eth:
            def contract(self, *_a, **_k):
                return type("C", (), {"functions": _Fns()})()

        self.w3 = type("W3", (), {"eth": _Eth()})()

    async def get_transaction_count(self, who, block):
        assert who == self.candidate and block == "latest"
        if isinstance(self.count, Exception):
            raise self.count
        return self.count


class _Fleet:
    """Several endpoints as the leg sees them: ``sources``, and an identity quorum for contract reads."""

    def __init__(self, endpoints) -> None:
        self.sources = endpoints

    async def eth_call_quorum(self, make_call, *, label, combine=None):
        answers = [await make_call(e) for e in self.sources]
        if len(set(answers)) != 1:
            raise NetworkError(f"{label}: endpoints disagree")
        return answers[0]


def _derive(rpc, contract, **kw) -> str:
    return asyncio.run(_leg(rpc).derive_deployer(contract, **kw))


def test_the_creator_is_derived_and_the_getter_read_is_pinned_to_the_block() -> None:
    who = derive_address(_key())
    contract = _create_address(who, 5)
    ep = _Endpoint(who, 9)
    derived = _derive(ep, contract, block_identifier="finalized")
    assert derived.lower() == who.lower() and derived != contract
    assert ep.getter_blocks == ["finalized"]


@pytest.mark.parametrize("nonce", [0, 1, 0x7F, 0x80, 0xFFFF, 0x10000])
def test_every_rlp_width_of_the_nonce_is_found(nonce) -> None:
    """The search's own RLP encoding agrees with ``_create_address`` at each width boundary."""
    who = derive_address(_key())
    assert _derive(_Endpoint(who, nonce + 1), _create_address(who, nonce)).lower() == who.lower()


def test_a_getter_naming_an_account_that_did_not_create_the_address_is_refused() -> None:
    """A contract whose creation code was not ours can name anyone in ``deployer()``. The name is a
    candidate: no nonce of it creates this address, so it is refused."""
    who, creator = derive_address(_key()), derive_address(_key())
    with pytest.raises(ValidationError, match="no nonce of that account"):
        _derive(_Endpoint(who, 50), _create_address(creator, 5))


def test_a_lagging_endpoint_cannot_hide_the_nonce() -> None:
    """The count is the MAX over every endpoint: one reporting a count below the deploy's nonce
    does not make the honest contract unverifiable."""
    who = derive_address(_key())
    fleet = _Fleet([_Endpoint(who, 3), _Endpoint(who, 9), _Endpoint(who, 9)])
    assert _derive(fleet, _create_address(who, 5)).lower() == who.lower()


def test_an_endpoint_that_does_not_answer_leaves_the_deployer_unknown() -> None:
    who = derive_address(_key())
    fleet = _Fleet([_Endpoint(who, 9), _Endpoint(who, NetworkError("down"))])
    with pytest.raises(NetworkError, match="did not answer"):
        _derive(fleet, _create_address(who, 5))


def test_endpoints_disagreeing_on_the_candidate_is_not_resolved_by_one_of_them() -> None:
    who, other = derive_address(_key()), derive_address(_key())
    fleet = _Fleet([_Endpoint(who, 9), _Endpoint(other, 9)])
    with pytest.raises(NetworkError, match="disagree"):
        _derive(fleet, _create_address(who, 5))


def test_the_search_is_bounded_to_the_latest_nonces(monkeypatch) -> None:
    monkeypatch.setattr(erc20_leg_mod, "DEPLOYER_NONCE_SEARCH", 10)
    who = derive_address(_key())
    # Inside the window (nonces 90..99 of a count of 100): found.
    assert _derive(_Endpoint(who, 100), _create_address(who, 90)).lower() == who.lower()
    # One below it: refused, and the message says the search was partial.
    with pytest.raises(ValidationError, match="its latest 10 nonces"):
        _derive(_Endpoint(who, 100), _create_address(who, 89))


# ── the maker's verify uses the derived deployer ────────────────────────────────────────────────


class _Terms:
    value_amount = 1_000_000
    token_address = _TOKEN.address
    hashlock = b"\x22" * 32
    eth_timeout_unix_s = _TIMEOUT


def _eth_leg(inner) -> EthLeg:
    return EthLeg(
        contract_leg=inner, network="anvil", claim_to=_CLAIMANT, refund_to=_REFUNDEE, eth_timeout_unix_s=_TIMEOUT
    )


def test_the_maker_verifies_against_the_deployer_derived_at_the_pinned_block(monkeypatch) -> None:
    who = derive_address(_key())
    inner = _leg()
    seen: dict = {}

    async def _derive_deployer(contract, *, block_identifier=None):
        seen["derive"] = (contract, block_identifier)
        return who

    async def _verify(locator, **kw):
        seen["verified"] = (locator, kw)

    monkeypatch.setattr(inner, "derive_deployer", _derive_deployer)
    monkeypatch.setattr(inner, "verify_funded", _verify)
    monkeypatch.setattr(erc20_leg_mod, "balance_of", None)  # nothing past the binds is read here

    async def _not_frozen(*_a, **_k):
        return False

    import pyrxd.gravity.eth_leg as eth_leg_mod

    monkeypatch.setattr(eth_leg_mod, "is_blacklisted", _not_frozen)
    out = asyncio.run(
        _eth_leg(inner).verify_counterparty_funded("0x" + "c0" * 20, _Terms(), block_identifier="finalized")
    )
    assert seen["derive"] == ("0x" + "c0" * 20, "finalized")
    assert seen["verified"][0].deployer == who.lower() == out.deployer
    assert seen["verified"][1]["block_identifier"] == "finalized"


def test_a_failed_derivation_refuses_before_anything_is_verified(monkeypatch) -> None:
    inner = _leg()
    calls = []

    async def _derive_deployer(contract, *, block_identifier=None):
        raise ValidationError("deployer() refused: CREATE matched no nonce below 9")

    async def _verify(locator, **kw):
        calls.append(locator)

    monkeypatch.setattr(inner, "derive_deployer", _derive_deployer)
    monkeypatch.setattr(inner, "verify_funded", _verify)
    with pytest.raises(ValidationError, match="matched no nonce"):
        asyncio.run(_eth_leg(inner).verify_counterparty_funded("0x" + "c0" * 20, _Terms()))
    assert calls == []


def test_a_native_leg_refuses_a_deployer() -> None:
    native = EthHtlcContractLeg(
        rpc=None,
        signing_key=_key(),
        chain_id=31337,
        artifact=json.loads((Path(__file__).parent / "fixtures" / "EthHtlc.json").read_text()),
    )

    class _NativeTerms:
        value_amount = 1
        hashlock = b"\x22" * 32

    with pytest.raises(ValidationError, match="no deployer immutable"):
        _eth_leg(native).expected_locator(_NativeTerms(), contract_address="0x" + "c0" * 20, deployer=_REFUNDEE)


# ── the leg's refund refuses a key the contract would refuse ────────────────────────────────────


class _Rpc:
    async def assert_chain(self) -> None:
        return None

    async def latest_block_timestamp_min(self) -> int:
        return _TIMEOUT


@pytest.fixture()
def refund_rig(monkeypatch):
    sent: list = []

    async def _settled_word(self, locator, block_identifier):
        return b"\x00" * 32

    async def _balance_of(rpc, token, owner, block_identifier=None, *, combine=min):
        return 5

    async def _parent_refund(self, locator, **kw):
        sent.append(locator)
        return "0x" + "ee" * 32

    monkeypatch.setattr(Erc20HtlcLeg, "_settled_word", _settled_word)
    monkeypatch.setattr(erc20_leg_mod, "balance_of", _balance_of)
    monkeypatch.setattr(EthHtlcContractLeg, "refund", _parent_refund)
    return sent


def test_a_third_party_key_is_refused_before_anything_is_signed(refund_rig) -> None:
    key = _key()
    loc = _locator(deployer=derive_address(_key()))
    with pytest.raises(ValidationError, match="NotRefunder") as e:
        asyncio.run(_leg(_Rpc(), key=key).refund(loc))
    assert refund_rig == []
    assert "Nothing was sent" in str(e.value) and derive_address(key).lower() in str(e.value)


def test_the_deployer_key_reaches_the_refund(refund_rig) -> None:
    key = _key()
    asyncio.run(_leg(_Rpc(), key=key).refund(_locator(deployer=derive_address(key))))
    assert len(refund_rig) == 1


def test_the_refundee_key_reaches_the_refund(refund_rig) -> None:
    key = _key()
    loc = Erc20HtlcLocator.from_dict(
        {**_locator(deployer=derive_address(_key())).to_dict(), "refundee": derive_address(key)}
    )
    asyncio.run(_leg(_Rpc(), key=key).refund(loc))
    assert len(refund_rig) == 1


def test_a_record_without_a_deployer_skips_the_pre_check(refund_rig) -> None:
    """A contract built before the rule lets any account refund; the leg does not invent a refusal."""
    asyncio.run(_leg(_Rpc()).refund(_locator(deployer=None)))
    assert len(refund_rig) == 1
