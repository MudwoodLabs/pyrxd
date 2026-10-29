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
# The artifact's runtime with its immutable slots as built (zero): the shape a deployed one has.
_RUNTIME = bytes.fromhex(_ARTIFACT["runtime_bytecode"][2:])


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

    def __init__(self, candidate, count, *, code: bytes | None = None) -> None:
        self.candidate = candidate
        self.count = count
        self.code = _RUNTIME if code is None else code
        self.getter_blocks: list[object] = []
        self.code_blocks: list[object] = []
        self.count_blocks: list[object] = []
        endpoint = self

        class _Call:
            async def call(self, block_identifier=None):
                endpoint.getter_blocks.append(block_identifier)
                if isinstance(endpoint.candidate, Exception):
                    raise endpoint.candidate
                return endpoint.candidate

        class _Fns:
            def deployer(self):
                return _Call()

        class _Eth:
            def contract(self, *_a, **_k):
                return type("C", (), {"functions": _Fns()})()

        self.w3 = type("W3", (), {"eth": _Eth()})()

    head = 120
    finalized = 100

    async def block_number(self):
        return self.head

    async def finalized_block_number(self):
        return self.finalized

    async def get_code(self, address, block_identifier=None):
        self.code_blocks.append(block_identifier)
        return self.code

    async def get_transaction_count(self, who, block):
        assert who == self.candidate
        self.count_blocks.append(block)
        if callable(self.count):
            return self.count(block)
        if isinstance(self.count, Exception):
            raise self.count
        return self.count


class _Fleet:
    """Several endpoints as the leg sees them: ``sources``, and an identity quorum for contract reads."""

    def __init__(self, endpoints) -> None:
        self.sources = endpoints

    async def block_number(self):
        return min(e.head for e in self.sources)

    async def finalized_block_number(self):
        return min(e.finalized for e in self.sources)

    async def get_code(self, address, block_identifier=None):
        return await self.sources[0].get_code(address, block_identifier)

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
    # The tag is resolved once, to the finalized block number, and every read is pinned to it.
    assert ep.getter_blocks == ep.count_blocks == ep.code_blocks == [ep.finalized]


@pytest.mark.parametrize("nonce", [0, 1, 0x7F, 0x80, 0xFFFF, 0x10000])
def test_every_rlp_width_of_the_nonce_is_found(nonce) -> None:
    """The search's own RLP encoding agrees with ``_create_address`` at each width boundary."""
    who = derive_address(_key())
    assert _derive(_Endpoint(who, nonce + 1), _create_address(who, nonce)).lower() == who.lower()


def test_a_getter_naming_an_account_that_did_not_create_the_address_is_refused() -> None:
    """A contract whose creation code was not ours can name anyone in ``deployer()``. The name is a
    candidate: no nonce of it creates this address, so it is refused."""
    who, creator = derive_address(_key()), derive_address(_key())
    with pytest.raises(ValidationError, match="not created the way an Erc20Htlc deploy creates one"):
        _derive(_Endpoint(who, 50), _create_address(creator, 5))


def test_a_lagging_endpoint_cannot_hide_the_nonce() -> None:
    """Each endpoint opens its own window: one reporting a count below the deploy's nonce does not
    make the honest contract unverifiable."""
    who = derive_address(_key())
    fleet = _Fleet([_Endpoint(who, 3), _Endpoint(who, 9), _Endpoint(who, 9)])
    assert _derive(fleet, _create_address(who, 5)).lower() == who.lower()


@pytest.mark.parametrize("liar_index", [0, 2], ids=["primary", "later"])
def test_an_OVER_reporting_endpoint_cannot_move_the_window_off_the_nonce(liar_index) -> None:
    """Review MED-1. With a MAX over the counts, one endpoint reporting 10**9 moved the only window
    past the deploy's nonce and an honest contract was refused, blaming the taker. Each count now
    opens its own window and a hit in any is accepted. The primary is tested as the liar too."""
    who = derive_address(_key())
    eps = [_Endpoint(who, 9), _Endpoint(who, 9), _Endpoint(who, 9)]
    eps[liar_index].count = 10**9
    assert _derive(_Fleet(eps), _create_address(who, 5)).lower() == who.lower()


def test_a_silent_endpoint_does_not_stop_a_hit_in_another_window() -> None:
    """Review MED-2: an endpoint that does not answer contributes no window; it does not stall a
    derivation another endpoint's window settles."""
    who = derive_address(_key())
    fleet = _Fleet([_Endpoint(who, NetworkError("429")), _Endpoint(who, 9)])
    assert _derive(fleet, _create_address(who, 5)).lower() == who.lower()


def test_no_hit_with_a_silent_endpoint_is_unknown_not_a_refusal() -> None:
    """The silent endpoint may hold the window that matches, so no hit is retryable, never a verdict."""
    who, creator = derive_address(_key()), derive_address(_key())
    fleet = _Fleet([_Endpoint(who, 9), _Endpoint(who, NetworkError("down"))])
    with pytest.raises(NetworkError, match="did not report") as e:
        _derive(fleet, _create_address(creator, 5))
    assert not isinstance(e.value, ValidationError)


def test_the_count_is_read_at_the_block_the_code_was_read_at() -> None:
    """Mythos 20261028T100731 LOW-2, and its re-review F1. The count was read at ``latest`` while the
    code was read at the pinned block; then at the same TAG, which a load balancer resolves again per
    request. Either way a lagging backend's count sat below the deploy's nonce and refused an honest
    contract for good. The tag is now resolved to one block number, where the deploy is mined. Here
    any tag reaches the lagging backend (count 5); only the number reaches the current one."""
    who = derive_address(_key())
    ep = _Endpoint(who, lambda block: 9 if isinstance(block, int) else 5)
    for tag in ("finalized", "latest", None):
        ep.count_blocks.clear()
        assert _derive(ep, _create_address(who, 5), block_identifier=tag).lower() == who.lower()
        assert ep.count_blocks and all(isinstance(b, int) for b in ep.count_blocks)


def test_latest_is_the_highest_head_so_a_lagging_endpoint_cannot_hide_a_fresh_deploy() -> None:
    """Re-review 2 of the Mythos fixes: resolving ``latest`` to the fleet's LOWEST head read a deploy
    mined in the newest block as empty code at every endpoint, a permanent refusal. It is the highest
    head; an endpoint that cannot say its head is left out, and none at all is unknown."""
    who = derive_address(_key())
    eps = [_Endpoint(who, 9), _Endpoint(who, 9), _Endpoint(who, 9)]
    eps[0].head, eps[1].head = 119, 121

    async def _down():
        raise NetworkError("down")

    eps[2].block_number = _down
    assert _derive(_Fleet(eps), _create_address(who, 5)).lower() == who.lower()
    assert eps[0].code_blocks == [121] and eps[0].count_blocks == [121]
    for e in eps:
        e.block_number = _down
    with pytest.raises(NetworkError, match="no endpoint reported its head block"):
        _derive(_Fleet(eps), _create_address(who, 5))


def test_a_key_busier_than_the_search_is_refused_without_blaming_the_taker(monkeypatch) -> None:
    """Mythos 20261028T100731 LOW-1. When a window stops short of nonce 0 the deploy may lie further
    back, so the refusal names the bound and does not call the contract a wrong one. When every window
    reaches nonce 0 the miss is proven, and the refusal says so."""
    monkeypatch.setattr(erc20_leg_mod, "DEPLOYER_NONCE_SEARCH", 10)
    who = derive_address(_key())
    with pytest.raises(ValidationError, match="more than 10 transactions since it deployed it") as busy:
        _derive(_Endpoint(who, 100), _create_address(who, 5))
    assert "not created the way" not in str(busy.value)
    with pytest.raises(ValidationError, match="not created the way an Erc20Htlc deploy creates one") as proven:
        _derive(_Endpoint(who, 10), _create_address(derive_address(_key()), 5))
    assert "more than 10" not in str(proven.value)


def test_endpoints_disagreeing_on_the_candidate_is_not_resolved_by_one_of_them() -> None:
    who, other = derive_address(_key()), derive_address(_key())
    fleet = _Fleet([_Endpoint(who, 9), _Endpoint(other, 9)])
    with pytest.raises(NetworkError, match="disagree"):
        _derive(fleet, _create_address(who, 5))


def test_the_search_is_bounded_below_each_count(monkeypatch) -> None:
    monkeypatch.setattr(erc20_leg_mod, "DEPLOYER_NONCE_SEARCH", 10)
    who = derive_address(_key())
    # Inside the window (nonces 90..99 of a count of 100): found.
    assert _derive(_Endpoint(who, 100), _create_address(who, 90)).lower() == who.lower()
    # One below it: refused, and the message names the window searched.
    with pytest.raises(ValidationError, match=r"\[90, 100\)"):
        _derive(_Endpoint(who, 100), _create_address(who, 89))


def test_no_code_at_the_block_says_not_yet_finalized_and_reads_no_getter() -> None:
    """Review MED-3: at 'finalized' before the deploy buries there is no code. That is said as such
    (a ValidationError the coordinator handles), and the getter is never called."""
    who = derive_address(_key())
    ep = _Endpoint(who, 9, code=b"")
    with pytest.raises(ValidationError, match="NOT YET FINALIZED"):
        _derive(ep, _create_address(who, 5), block_identifier="finalized")
    assert ep.code_blocks == [ep.finalized] and ep.getter_blocks == []


def test_a_contract_without_a_working_getter_is_a_typed_refusal() -> None:
    """A contract with no ``deployer()`` (an old artifact, or another contract) makes web3 raise a
    decoding error; it is refused as a ValidationError, not let out as a raw exception."""
    who = derive_address(_key())
    with pytest.raises(ValidationError, match="no working deployer"):
        _derive(_Endpoint(RuntimeError("could not decode output"), 9), _create_address(who, 5))


def _getter_failing_fleet(code: bytes) -> _Fleet:
    """Every endpoint's getter fails, and the quorum says so the way the real fleet does: as an outage."""

    class _OutageFleet(_Fleet):
        async def eth_call_quorum(self, make_call, *, label, combine=None):
            try:
                return await super().eth_call_quorum(make_call, label=label, combine=combine)
            except Exception as exc:
                raise NetworkError(f"{label}: only 0 of {len(self.sources)} endpoints answered") from exc

    return _OutageFleet([_Endpoint(RuntimeError("could not decode output"), 9, code=code) for _ in range(2)])


def test_a_fleet_refuses_code_that_is_not_this_build_rather_than_reporting_an_outage() -> None:
    """Re-review MED-1. Every endpoint failed the getter on another contract (the native EthHtlc
    here), which the real fleet reports as a retryable NetworkError. The shape check refuses it as a
    wrong contract first, and no getter is read."""
    native = json.loads((Path(__file__).parent / "fixtures" / "EthHtlc.json").read_text())
    fleet = _getter_failing_fleet(bytes.fromhex(native["runtime_bytecode"][2:]))
    with pytest.raises(ValidationError, match="not this build's Erc20Htlc"):
        _derive(fleet, "0x" + "c0" * 20)
    assert all(e.getter_blocks == [] for e in fleet.sources)


def test_one_byte_outside_the_slots_is_not_this_build_but_any_slot_contents_are() -> None:
    """The honest side of the shape check: it ignores every immutable slot (a real deploy fills them),
    and nothing else. A changed logic byte is refused; a changed slot byte reaches the getter."""
    refs = _ARTIFACT["immutableReferences"]
    slot_bytes = {r["start"] + i for offs in refs.values() for r in offs for i in range(r["length"])}
    logic = next(i for i in range(len(_RUNTIME)) if i not in slot_bytes)
    forged = bytearray(_RUNTIME)
    forged[logic] ^= 0xFF
    with pytest.raises(ValidationError, match="not this build's Erc20Htlc"):
        _derive(_getter_failing_fleet(bytes(forged)), "0x" + "c0" * 20)
    filled = bytearray(_RUNTIME)
    for i in slot_bytes:
        filled[i] = 0xAB
    with pytest.raises(NetworkError, match="only 0 of 2"):
        _derive(_getter_failing_fleet(bytes(filled)), "0x" + "c0" * 20)


@pytest.mark.parametrize("absurd", [2**64, 2**400, -1])
def test_a_count_no_nonce_can_have_is_no_answer(absurd) -> None:
    """Re-review LOW-2. A count of 2**400 made the RLP encoder raise a raw ValueError on a miss. A
    count outside [0, 2**64) now counts as no answer: a miss is the typed retryable NetworkError,
    and an honest endpoint beside the liar still derives the creator."""
    who, creator = derive_address(_key()), derive_address(_key())
    with pytest.raises(NetworkError, match="1 of 2 endpoints did not report"):
        _derive(_Fleet([_Endpoint(who, absurd), _Endpoint(who, 9)]), _create_address(creator, 5))
    assert _derive(_Fleet([_Endpoint(who, absurd), _Endpoint(who, 9)]), _create_address(who, 5)).lower() == who.lower()


def test_a_resume_whose_derivation_fails_is_still_gated_by_verify_funded(monkeypatch) -> None:
    """Re-review LOW-3. The resume's deployer check is diagnosis only: when derivation fails it must
    not refuse, and it must not skip the gate either. ``verify_funded`` runs and its refusal stands."""
    from pyrxd.eth_wallet.locator import PendingDeploy

    leg = _leg(_Rpc())
    seen = []

    async def _derive_deployer(contract, *, block_identifier=None):
        raise NetworkError("every endpoint down")

    async def _verify(locator, **k):
        seen.append(locator.deployer)
        raise ValidationError("runtime does not match the expected bytecode")

    async def _ok(*a, **k):
        return None

    monkeypatch.setattr(leg, "derive_deployer", _derive_deployer)
    monkeypatch.setattr(leg, "verify_funded", _verify)
    monkeypatch.setattr(erc20_leg_mod, "assert_token_matches_chain", _ok)
    with pytest.raises(ValidationError, match="runtime does not match"):
        asyncio.run(
            leg.fund(
                hashlock=b"\x22" * 32,
                claimant=_CLAIMANT,
                refundee=_REFUNDEE,
                timeout=_TIMEOUT,
                amount_wei=1,
                resume_from=PendingDeploy(address="0x" + "c0" * 20, deploy_tx_hash="0x" + "11" * 32),
            )
        )
    assert seen == [leg._account_address().lower()]


def test_resume_of_a_contract_another_key_deployed_says_so_and_sends_nothing(monkeypatch) -> None:
    """Review LOW-4: the resume names the real deployer instead of letting the runtime compare call
    the operator's own contract a wrong one."""
    from pyrxd.eth_wallet.locator import PendingDeploy

    other = derive_address(_key())
    leg = _leg(_Rpc())
    sent = []

    async def _derive_deployer(contract, *, block_identifier=None):
        return other

    async def _verify(*a, **k):
        sent.append("verify")

    async def _ok(*a, **k):
        return None

    monkeypatch.setattr(leg, "derive_deployer", _derive_deployer)
    monkeypatch.setattr(leg, "verify_funded", _verify)
    monkeypatch.setattr(erc20_leg_mod, "assert_token_matches_chain", _ok)
    with pytest.raises(ValidationError, match="Resume with the key that deployed it"):
        asyncio.run(
            leg.fund(
                hashlock=b"\x22" * 32,
                claimant=_CLAIMANT,
                refundee=_REFUNDEE,
                timeout=_TIMEOUT,
                amount_wei=1,
                resume_from=PendingDeploy(address="0x" + "c0" * 20, deploy_tx_hash="0x" + "11" * 32),
            )
        )
    assert sent == []


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
