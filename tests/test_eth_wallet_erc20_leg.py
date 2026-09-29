"""Boundaries of the ERC-20 HTLC leg (`eth_wallet/erc20_leg.py`) that no test pinned.

From the 2026-09-29 `ethleg` mutation run. The token leg wraps the audited native leg, and most of
its own decisions were exercised only on one side of their boundary: an over-funded contract, a
token address that sorts BELOW the pinned one, a token on a chain id LOWER than the leg's, a fee
field that is zero rather than absent. Each test below is the side nobody had taken.

No network: the rpc is a local fake that serves the HTLC's immutables, the token's `decimals()` and
`balanceOf()`, and the code/balance reads of the inherited native checks.
"""

from __future__ import annotations

import json
import os
import pathlib
import types

import pytest

pytest.importorskip("web3")

from pyrxd.eth_wallet import erc20_leg as el
from pyrxd.eth_wallet.erc20_leg import Erc20HtlcLeg, _create_address, _fee_fields_of
from pyrxd.eth_wallet.htlc_leg import EthHtlcContractLeg
from pyrxd.eth_wallet.locator import Erc20HtlcLocator
from pyrxd.eth_wallet.tokens import token_for
from pyrxd.security.errors import NetworkError, PreRevealAbort, ValidationError
from pyrxd.security.secrets import PrivateKeyMaterial

_ART = json.loads((pathlib.Path(__file__).parent / "fixtures" / "Erc20Htlc.json").read_text())
_USDC = token_for("USDC", 1)  # 0xa0b8...eb48
_CONTRACT = "0x" + "77" * 20
_AMOUNT = 12_345_678


def _leg(rpc=None, *, token=_USDC, chain_id: int = 1) -> Erc20HtlcLeg:
    return Erc20HtlcLeg(
        token=token,
        rpc=rpc or object(),
        signing_key=PrivateKeyMaterial(os.urandom(32)),
        chain_id=chain_id,
        artifact=_ART,
    )


def _locator(**over) -> Erc20HtlcLocator:
    base = dict(
        chain_id=1,
        contract_address=_CONTRACT,
        deploy_tx_hash="0x" + "ab" * 32,
        hashlock="0x" + "33" * 32,
        claimant="0x" + "44" * 20,
        refundee="0x" + "55" * 20,
        timeout=2_000_000_000,
        amount_wei=_AMOUNT,
        token_address=_USDC.address,
    )
    base.update(over)
    return Erc20HtlcLocator(**base)


class _Rpc:
    """Serves one correctly-deployed token HTLC. Override any answer by keyword."""

    def __init__(self, loc: Erc20HtlcLocator, **answers) -> None:
        from web3 import Web3

        self.values = {
            "hashlock": loc.hashlock_bytes,
            "claimant": Web3.to_checksum_address(loc.claimant),
            "refundee": Web3.to_checksum_address(loc.refundee),
            "timeout": loc.timeout,
            "token": Web3.to_checksum_address(_USDC.address),
            "amount": loc.amount_wei,
            "decimals": _USDC.decimals,
            "balanceOf": loc.amount_wei,
        }
        self.values.update(answers)
        self.reads: list[tuple[str, object]] = []
        rpc = self

        class _Call:
            def __init__(self, name):
                self.name = name

            async def call(self, *, block_identifier):
                rpc.reads.append((self.name, block_identifier))
                v = rpc.values[self.name]
                if isinstance(v, Exception):
                    raise v
                return v

        class _Fns:
            def __getattr__(self, name):
                return lambda *_a: _Call(name)

        self.w3 = types.SimpleNamespace(
            eth=types.SimpleNamespace(contract=lambda **_k: types.SimpleNamespace(functions=_Fns()))
        )

    async def assert_chain(self):
        return None

    async def get_code(self, address, block_identifier=None):
        return b"\x60\x00" if address.lower() == _CONTRACT else b""

    async def get_balance(self, address, block_identifier=None):
        return 0  # a token HTLC holds no ETH, which is why the parent is asked for >= 0


def _verifying(rpc) -> Erc20HtlcLeg:
    leg = _leg(rpc)
    leg._runtime_code_matches = lambda code: True  # the artifact compare has its own tests
    return leg


# ── verify_funded ───────────────────────────────────────────────────────────────────────────────


async def test_over_funding_is_accepted_and_under_funding_is_refused():
    loc = _locator()
    await _verifying(_Rpc(loc, balanceOf=_AMOUNT + 1)).verify_funded(loc, expected_amount_wei=_AMOUNT)
    await _verifying(_Rpc(loc)).verify_funded(loc, expected_amount_wei=_AMOUNT)
    with pytest.raises(ValidationError, match="under-funded"):
        await _verifying(_Rpc(loc, balanceOf=_AMOUNT - 1)).verify_funded(loc, expected_amount_wei=_AMOUNT)


@pytest.mark.parametrize("other", ["0x" + "00" * 20, "0x" + "ff" * 20])
async def test_a_locator_in_ANY_other_token_is_refused(other):
    # Both orderings: a mismatch must not depend on which address sorts first.
    loc = _locator(token_address=other)
    with pytest.raises(ValidationError, match="locator is denominated in"):
        await _verifying(_Rpc(loc)).verify_funded(loc, expected_amount_wei=_AMOUNT)


@pytest.mark.parametrize("other", ["0x" + "00" * 20, "0x" + "ff" * 20])
async def test_an_htlc_holding_ANY_other_token_is_refused(other):
    loc = _locator()
    with pytest.raises(ValidationError, match="is denominated in"):
        await _verifying(_Rpc(loc, token=other)).verify_funded(loc, expected_amount_wei=_AMOUNT)


async def test_an_htlc_constructed_for_another_amount_is_refused():
    loc = _locator()
    with pytest.raises(ValidationError, match="stored amount is 12345679"):
        await _verifying(_Rpc(loc, amount=_AMOUNT + 1)).verify_funded(loc, expected_amount_wei=_AMOUNT)


@pytest.mark.parametrize(("pin", "want"), [(None, "latest"), ("finalized", "finalized")])
async def test_the_token_and_amount_immutables_are_read_at_the_pinned_checkpoint(pin, want):
    loc = _locator()
    rpc = _Rpc(loc)
    await _verifying(rpc).verify_funded(loc, expected_amount_wei=_AMOUNT, block_identifier=pin)
    assert {b for n, b in rpc.reads if n in ("token", "amount", "balanceOf", "decimals")} == {want}


# ── the pre-reveal balance re-read in claim ─────────────────────────────────────────────────────


@pytest.fixture
def reveal_stubbed(monkeypatch):
    """Stop at the parent's claim: these tests are about the token leg's own precondition."""
    reached: list = []

    async def _parent_claim(self, locator, preimage):
        reached.append(locator)
        return "0x" + "cd" * 32

    async def _no_freeze(*_a, **_k):
        return None

    monkeypatch.setattr(EthHtlcContractLeg, "claim", _parent_claim)
    monkeypatch.setattr(el, "assert_not_frozen_before_reveal", _no_freeze)
    return reached


async def test_claim_proceeds_when_the_htlc_holds_MORE_than_promised(reveal_stubbed):
    loc = _locator()
    await _leg(_Rpc(loc, balanceOf=_AMOUNT + 1)).claim(loc, b"\x01" * 32)
    assert reveal_stubbed == [loc]


async def test_claim_is_refused_before_broadcast_when_the_htlc_holds_less(reveal_stubbed):
    loc = _locator()
    with pytest.raises(PreRevealAbort, match="less than the 12345678 promised"):
        await _leg(_Rpc(loc, balanceOf=_AMOUNT - 1)).claim(loc, b"\x01" * 32)
    assert reveal_stubbed == []


async def test_a_balance_read_that_fails_keeps_the_preimage(reveal_stubbed):
    # PreRevealAbort tells the caller nothing was sent; a bare transport error would not.
    loc = _locator()
    with pytest.raises(PreRevealAbort, match="could not read the funded balance"):
        await _leg(_Rpc(loc, balanceOf=ConnectionError("reset"))).claim(loc, b"\x01" * 32)
    assert reveal_stubbed == []


# ── construction and fund inputs ────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(("token_chain", "leg_chain"), [(8453, 1), (1, 8453)])
def test_a_token_on_ANY_other_chain_is_refused(token_chain, leg_chain):
    with pytest.raises(ValidationError, match="pinned to chain id"):
        _leg(token=token_for("USDC", token_chain), chain_id=leg_chain)


class _Reached(Exception):
    """Raised by the fake rpc's first call: proof that input validation let the call through."""


class _StopAtChain:
    async def assert_chain(self):
        raise _Reached


_FUND = dict(claimant="0x" + "44" * 20, refundee="0x" + "55" * 20, timeout=2_000_000_000)


@pytest.mark.parametrize("hashlock", [bytes(31), bytes(33), "33" * 32])
async def test_fund_refuses_a_hashlock_that_is_not_32_bytes(hashlock):
    with pytest.raises(ValidationError, match="hashlock must be 32 bytes"):
        await _leg(_StopAtChain()).fund(hashlock=hashlock, amount_wei=1, **_FUND)


@pytest.mark.parametrize("amount", [0, -1, True, 1.0, "1"])
async def test_fund_refuses_an_amount_that_is_not_a_positive_int(amount):
    with pytest.raises(ValidationError, match="must be a positive int"):
        await _leg(_StopAtChain()).fund(hashlock=bytes(32), amount_wei=amount, **_FUND)


async def test_fund_accepts_a_one_base_unit_amount():
    with pytest.raises(_Reached):
        await _leg(_StopAtChain()).fund(hashlock=bytes(32), amount_wei=1, **_FUND)


def test_the_locator_producer_prefixes_a_bare_hash_exactly_once():
    leg = _leg()
    kw = dict(
        address=_CONTRACT,
        hashlock=b"\x33" * 32,
        claimant="0x" + "44" * 20,
        refundee="0x" + "55" * 20,
        timeout=2_000_000_000,
        amount_wei=_AMOUNT,
    )
    assert leg._locator_for(deploy_hash="0x" + "ab" * 32, **kw).deploy_tx_hash == "0x" + "ab" * 32
    assert leg._locator_for(deploy_hash="ab" * 32, **kw).deploy_tx_hash == "0x" + "ab" * 32


# ── fee fields of a pending push, and the CREATE address ────────────────────────────────────────


def test_zero_fee_fields_are_present_not_missing():
    assert _fee_fields_of({"maxFeePerGas": 0, "maxPriorityFeePerGas": 0}) == {
        "maxFeePerGas": 0,
        "maxPriorityFeePerGas": 0,
    }
    with pytest.raises(NetworkError, match="missing maxPriorityFeePerGas"):
        _fee_fields_of({"maxFeePerGas": 5, "gasPrice": 5})


@pytest.mark.parametrize("nonce", [0, 1, 0x7F, 0x80, 0xFF, 0x100, 0xFFFF, 2**32, 2**56 + 3])
def test_create_address_matches_keccak_of_the_rlp_package_encoding(nonce):
    rlp = pytest.importorskip("rlp")
    from eth_utils import keccak, to_checksum_address

    sender = "0x" + os.urandom(20).hex()
    assert _create_address(sender, nonce) == to_checksum_address(
        keccak(rlp.encode([bytes.fromhex(sender[2:]), nonce]))[12:]
    )


@pytest.mark.parametrize("n", [19, 21])
def test_create_address_refuses_a_sender_that_is_not_20_bytes(n):
    with pytest.raises(ValidationError, match=f"got {n}"):
        _create_address("0x" + "ab" * n, 1)


# ── _push_and_bind: what is sent, and when a resume must refuse to send ─────────────────────────
#
# Driven directly: the fund() wrappers around it have their own tests, and these are about the
# arithmetic of `shortfall = amount - held` against the nonce window, which decides whether a
# resume can fund the HTLC twice.


class _PushRpc:
    """Token balance, nonce window and push receipt, all dictated. Records every transfer."""

    def __init__(self, *, held, pending=0, latest=0, landed=None, push_status=1, statusless=False):
        self.held, self.pending, self.latest = held, pending, latest
        self.landed = landed
        self.push_status, self.statusless = push_status, statusless
        self.transfers: list[int] = []
        rpc = self

        class _Call:
            def __init__(self, v):
                self.v = v

            async def call(self, *, block_identifier=None):
                return self.v

        class _Built:
            def __init__(self, amount):
                self.amount = amount

            async def build_transaction(self, tx):
                rpc.transfers.append(self.amount)
                return {**tx, "amount": self.amount}

        class _Fns:
            def balanceOf(self, _who):
                # The balance TRACKS the push; `landed` overrides it to model a token that
                # delivers more or less than it was asked to.
                if rpc.transfers and rpc.landed is not None:
                    return _Call(rpc.landed)
                return _Call(rpc.held + sum(rpc.transfers))

            def isBlacklisted(self, _who):
                return _Call(False)

            def transfer(self, _to, amount):
                return _Built(amount)

        eth = types.SimpleNamespace(contract=lambda **_k: types.SimpleNamespace(functions=_Fns()))
        self.w3 = self.write_w3 = types.SimpleNamespace(eth=eth)

    async def get_transaction_count(self, _addr, block="pending"):
        return self.pending if block == "pending" else self.latest

    async def fee_fields(self):
        return {"maxFeePerGas": 3, "maxPriorityFeePerGas": 1}

    async def get_transaction(self, _h):
        # The push already pending at the pinned nonce, priced well above today's estimate.
        return {"nonce": 7, "maxFeePerGas": 100, "maxPriorityFeePerGas": 10}

    async def wait_receipt(self, _h, **_k):
        return {"logs": []} if self.statusless else {"status": self.push_status, "logs": []}


def _push(rpc, *, resuming, amount=100, push_nonce=None, push_tx_hash=None, on_push_hash=None):
    from web3 import Web3

    leg = _leg(rpc)
    sent: list = []

    async def _send(built, *, on_signed=None, **_k):
        h = "0x" + "fe" * 32
        if on_signed is not None:
            await on_signed(h)
        sent.append(built)
        return h

    leg._sign_and_send = _send
    coro = leg._push_and_bind(
        resuming=resuming,
        push_nonce=push_nonce,
        push_tx_hash=push_tx_hash,
        on_push_nonce=None,
        on_push_hash=on_push_hash,
        web3=__import__("web3"),
        address=Web3.to_checksum_address(_CONTRACT),
        deploy_hash="0x" + "ab" * 32,
        hashlock=b"\x33" * 32,
        claimant="0x" + "44" * 20,
        refundee="0x" + "55" * 20,
        timeout=2_000_000_000,
        amount_wei=amount,
    )
    return coro, sent


async def test_a_resume_one_unit_short_with_a_tx_in_flight_refuses_to_send():
    rpc = _PushRpc(held=99, pending=4, latest=3)
    coro, sent = _push(rpc, resuming=True)
    with pytest.raises(NetworkError, match=r"1 transaction\(s\) .* still in flight"):
        await coro
    assert sent == []


@pytest.mark.parametrize("held", [100, 150])
async def test_a_resume_with_nothing_left_to_send_completes_even_with_a_stuck_tx(held):
    # Fully (or over-) funded: the push whose receipt was lost has MINED. Refusing here strands a
    # taker whose fund completed, behind a stuck transaction that may never clear.
    rpc = _PushRpc(held=held, pending=9, latest=3)
    coro, sent = _push(rpc, resuming=True)
    loc = await coro
    assert sent == [] and rpc.transfers == []
    assert loc.amount_wei == 100


async def test_a_pending_nonce_BELOW_latest_is_not_transactions_in_flight():
    rpc = _PushRpc(held=0, pending=2, latest=3)
    coro, _ = _push(rpc, resuming=True)
    await coro
    assert rpc.transfers == [100]


async def test_a_consumed_push_pin_is_refused_one_unit_short():
    rpc = _PushRpc(held=99, latest=8)
    coro, sent = _push(rpc, resuming=True, push_nonce=7)
    with pytest.raises(NetworkError, match="pinned push nonce 7 has already been consumed"):
        await coro
    assert sent == []


@pytest.mark.parametrize("held", [100, 150])
async def test_a_consumed_pin_does_not_matter_once_nothing_is_left_to_send(held):
    rpc = _PushRpc(held=held, latest=8)
    coro, sent = _push(rpc, resuming=True, push_nonce=7)
    await coro
    assert sent == []


async def test_a_pin_still_at_the_settled_nonce_is_used_not_refused():
    rpc = _PushRpc(held=40, pending=7, latest=7)
    coro, sent = _push(rpc, resuming=True, push_nonce=7)
    await coro
    assert rpc.transfers == [60] and sent[0]["nonce"] == 7


async def test_a_fresh_fund_sends_exactly_the_shortfall_even_when_it_is_one_unit():
    rpc = _PushRpc(held=0)
    coro, _ = _push(rpc, resuming=False, amount=1)
    await coro
    assert rpc.transfers == [1]


async def test_an_over_funded_htlc_is_never_sent_a_negative_transfer():
    rpc = _PushRpc(held=150)
    coro, sent = _push(rpc, resuming=False)
    await coro
    assert sent == [] and rpc.transfers == []


async def test_the_push_hash_is_recorded_with_its_nonce_before_the_broadcast():
    recorded = []

    async def _record(nonce, h):
        recorded.append((nonce, h))

    rpc = _PushRpc(held=0, pending=5, latest=5)
    coro, _ = _push(rpc, resuming=False, on_push_hash=_record)
    await coro
    assert recorded == [(5, "0x" + "fe" * 32)]


@pytest.mark.parametrize("kw", [{"push_status": 0}, {"statusless": True}])
async def test_a_reverted_or_statusless_push_is_a_failure(kw):
    coro, _ = _push(_PushRpc(held=0, **kw), resuming=False)
    with pytest.raises(NetworkError, match="token transfer into .* reverted"):
        await coro


async def test_an_over_delivering_token_is_accepted_and_an_under_delivering_one_is_not():
    coro, _ = _push(_PushRpc(held=0, landed=101), resuming=False)
    await coro
    coro, _ = _push(_PushRpc(held=0, landed=99), resuming=False)
    with pytest.raises(ValidationError, match="push landed 99 base units"):
        await coro


# ── _deploy: the receipt ────────────────────────────────────────────────────────────────────────


def _deploying_leg(*, status=1, statusless=False, lie=None):
    from pyrxd.eth_wallet.keys import derive_address

    key = PrivateKeyMaterial(os.urandom(32))
    sender = derive_address(key)

    class _Ctor:
        async def build_transaction(self, tx):
            return dict(tx)

    class _Rpc:
        write_w3 = types.SimpleNamespace(
            eth=types.SimpleNamespace(contract=lambda **_k: types.SimpleNamespace(constructor=lambda *a: _Ctor()))
        )

        async def fee_fields(self):
            return {"maxFeePerGas": 3, "maxPriorityFeePerGas": 1}

        async def get_transaction_count(self, _a, block="pending"):
            return 4

        async def wait_receipt(self, _h, **_k):
            r = {"contractAddress": lie or _create_address(sender, 4)}
            if not statusless:
                r["status"] = status
            return r

    leg = Erc20HtlcLeg(token=_USDC, rpc=_Rpc(), signing_key=key, chain_id=1, artifact=_ART)

    async def _send(built, *, preflight=True, **_k):
        assert preflight is False
        return "0x" + "de" * 32

    leg._sign_and_send = _send
    return leg, sender


def _deploy(leg):
    return leg._deploy(
        web3=__import__("web3"),
        hashlock=b"\x33" * 32,
        claimant="0x" + "44" * 20,
        refundee="0x" + "55" * 20,
        timeout=2_000_000_000,
        amount_wei=_AMOUNT,
        on_deploy=None,
    )


async def test_deploy_returns_the_derived_address():
    leg, sender = _deploying_leg()
    assert await _deploy(leg) == (_create_address(sender, 4), "0x" + "de" * 32)


@pytest.mark.parametrize("kw", [{"status": 0}, {"status": 2}, {"statusless": True}])
async def test_deploy_refuses_any_receipt_status_but_one(kw):
    leg, _ = _deploying_leg(**kw)
    with pytest.raises(NetworkError, match="deploy reverted"):
        await _deploy(leg)


@pytest.mark.parametrize("lie", ["0x" + "00" * 20, "0x" + "ff" * 20])
async def test_deploy_refuses_a_receipt_naming_ANY_other_address(lie):
    leg, _ = _deploying_leg(lie=lie)
    with pytest.raises(ValidationError, match="deploy receipt names contract"):
        await _deploy(leg)


async def test_a_resume_REPLACES_its_own_pending_push_above_that_pushs_price():
    # latest at the pin and pending one past it: the only thing in flight is our own push, so
    # re-sending at the pinned nonce cannot double-fund; it must outbid what is pending.
    rpc = _PushRpc(held=0, pending=8, latest=7)
    coro, sent = _push(rpc, resuming=True, push_nonce=7, push_tx_hash="0x" + "ee" * 32)
    await coro
    (built,) = sent
    assert built["nonce"] == 7
    assert built["maxFeePerGas"] > 100 and built["maxPriorityFeePerGas"] > 10


async def test_without_the_durable_push_hash_the_same_state_is_refused():
    rpc = _PushRpc(held=0, pending=8, latest=7)
    coro, sent = _push(rpc, resuming=True, push_nonce=7, push_tx_hash=None)
    with pytest.raises(NetworkError, match="still in flight"):
        await coro
    assert sent == []


async def test_an_htlc_constructed_for_LESS_than_negotiated_is_refused():
    loc = _locator()
    with pytest.raises(ValidationError, match="stored amount is 12345677"):
        await _verifying(_Rpc(loc, amount=_AMOUNT - 1)).verify_funded(loc, expected_amount_wei=_AMOUNT)


async def test_the_amount_bind_compares_values_not_int_objects():
    # web3 decodes a fresh int for every call; an identity comparison would refuse every contract.
    loc = _locator(amount_wei=10**12)
    rpc = _Rpc(loc, amount=int(str(10**12)), balanceOf=int(str(10**12)))
    await _verifying(rpc).verify_funded(loc, expected_amount_wei=int(str(10**12)))
