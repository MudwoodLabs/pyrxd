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


async def _unsettled_storage(*_a, **_k) -> bytes:
    """`eth_getStorageAt` for an HTLC whose `settled` flag (slot 0) is clear — every honest one."""
    return b"\x00" * 32


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
            eth=types.SimpleNamespace(
                contract=lambda **_k: types.SimpleNamespace(functions=_Fns()), get_storage_at=_unsettled_storage
            )
        )

    async def assert_chain(self):
        return None

    async def get_code(self, address, block_identifier=None):
        return b"\x60\x00" if address.lower() == _CONTRACT else b""

    async def get_balance(self, address, block_identifier=None):
        return 0  # a token HTLC holds no ETH, which is why the parent is asked for >= 0


def _verifying(rpc) -> Erc20HtlcLeg:
    leg = _leg(rpc)
    leg._expected_runtime = lambda loc: b"\x60\x00"  # the artifact compare has its own tests
    return leg


# ── verify_funded ───────────────────────────────────────────────────────────────────────────────


async def test_over_funding_is_accepted_and_under_funding_is_refused():
    loc = _locator()
    await _verifying(_Rpc(loc, balanceOf=_AMOUNT + 1)).verify_funded(loc, expected_amount_wei=_AMOUNT)
    await _verifying(_Rpc(loc)).verify_funded(loc, expected_amount_wei=_AMOUNT)
    with pytest.raises(ValidationError, match="under-funded"):
        await _verifying(_Rpc(loc, balanceOf=_AMOUNT - 1)).verify_funded(loc, expected_amount_wei=_AMOUNT)


async def test_a_NEGATIVE_eth_balance_from_the_node_is_refused():
    # A token HTLC holds no ETH, so the inherited balance floor is 0 — and a node reporting less
    # than that is not describing a real contract. The balance is an untrusted RPC answer.
    loc = _locator()
    rpc = _Rpc(loc)

    async def _negative(address, block_identifier=None):
        return -1

    rpc.get_balance = _negative
    with pytest.raises(ValidationError, match=r"funded balance -1 wei < negotiated 0 wei"):
        await _verifying(rpc).verify_funded(loc, expected_amount_wei=_AMOUNT)


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


# ── fund: what is sent, and when a resume must refuse to send ──────────────────────────────────
#
# Driven through `fund()`, fresh or resumed (`resume_from`), so each case takes the path a real
# caller takes: the decimals cross-check, the freeze gates, the deploy, the resume's immutable
# re-verification, and then the arithmetic of `shortfall = amount - held` against the nonce
# window, which decides whether a resume can fund the HTLC twice. Signing is stubbed (it has its
# own tests), and so is the runtime-code compare, as in `_verifying`.

_HASHLOCK = b"\x33" * 32
_DEPLOY_HASH = "0x" + "de" * 32
_PUSH_HASH = "0x" + "fe" * 32


class _PushRpc:
    """Everything `fund()` reads, all dictated. Records every transfer and every deploy.

    `held` is the HTLC's token balance before the push; `pending`/`latest` the sender's nonces
    (the deploy and the push are both built at `pending`). `window`, when given, is installed as
    the multi-source `inflight_nonce_window` read.
    """

    def __init__(
        self,
        *,
        held,
        pending=0,
        latest=0,
        landed=None,
        push_status=1,
        statusless=False,
        deploy_status=1,
        deploy_statusless=False,
        lie=None,
        window=None,
    ):
        from web3 import Web3

        self.held, self.pending, self.latest = held, pending, latest
        self.landed = landed
        self.push_status, self.statusless = push_status, statusless
        self.deploy_status, self.deploy_statusless, self.lie = deploy_status, deploy_statusless, lie
        if window is not None:
            self.inflight_nonce_window = window
        self.transfers: list[int] = []
        self.deploys: list[dict] = []
        self.deployer: str | None = None  # the leg's own address; `_push` sets it
        self.amount: int | None = None  # the negotiated amount; `_push` sets it
        rpc = self

        def _immutable(name):
            return {
                "hashlock": _HASHLOCK,
                "claimant": Web3.to_checksum_address(_FUND["claimant"]),
                "refundee": Web3.to_checksum_address(_FUND["refundee"]),
                "timeout": _FUND["timeout"],
                "token": Web3.to_checksum_address(_USDC.address),
                "amount": rpc.amount,
            }[name]

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

        class _Ctor:
            async def build_transaction(self, tx):
                return dict(tx)

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

            def decimals(self):
                return _Call(_USDC.decimals)

            def __getattr__(self, name):  # the HTLC's immutable getters, read on a resume
                return lambda: _Call(_immutable(name))

        def _contract(**_k):
            return types.SimpleNamespace(functions=_Fns(), constructor=lambda *_a: _Ctor())

        eth = types.SimpleNamespace(contract=_contract, get_storage_at=_unsettled_storage)
        self.w3 = self.write_w3 = types.SimpleNamespace(eth=eth)

    async def assert_chain(self):
        return None

    async def get_code(self, address, block_identifier=None):
        return b"\x60\x00" if address.lower() == _CONTRACT else b""

    async def get_balance(self, address, block_identifier=None):
        return 0

    async def get_transaction_count(self, _addr, block="pending"):
        return self.pending if block == "pending" else self.latest

    async def fee_fields(self):
        return {"maxFeePerGas": 3, "maxPriorityFeePerGas": 1}

    async def get_transaction(self, _h):
        # The push already pending at the pinned nonce, priced well above today's estimate.
        return {"nonce": 7, "maxFeePerGas": 100, "maxPriorityFeePerGas": 10}

    async def wait_receipt(self, h, **_k):
        if h == _DEPLOY_HASH:
            r = {"contractAddress": self.lie or _create_address(self.deployer, self.pending)}
            if not self.deploy_statusless:
                r["status"] = self.deploy_status
            return r
        return {"logs": []} if self.statusless else {"status": self.push_status, "logs": []}


def _push(rpc, *, resuming, amount=100, push_nonce=None, push_tx_hash=None, on_push_hash=None):
    """`fund()`: a resume of the HTLC at `_CONTRACT`, or a fresh deploy. Returns the coroutine and
    the list of TOKEN PUSHES signed; the deploy, if any, lands on `rpc.deploys`."""
    from pyrxd.eth_wallet.keys import derive_address
    from pyrxd.eth_wallet.locator import PendingDeploy

    key = PrivateKeyMaterial(os.urandom(32))
    leg = Erc20HtlcLeg(token=_USDC, rpc=rpc, signing_key=key, chain_id=1, artifact=_ART)
    leg._expected_runtime = lambda loc: b"\x60\x00"  # the artifact compare has its own tests
    rpc.deployer, rpc.amount = derive_address(key), amount
    sent: list = []

    async def _send(built, *, preflight=True, on_signed=None, **_k):
        if preflight is False:  # only the deploy skips the eth_call preflight: it has no `to`
            rpc.deploys.append(built)
            return _DEPLOY_HASH
        if on_signed is not None:
            await on_signed(_PUSH_HASH)
        sent.append(built)
        return _PUSH_HASH

    leg._sign_and_send = _send
    resume = PendingDeploy(address=_CONTRACT, deploy_tx_hash="0x" + "ab" * 32) if resuming else None
    coro = leg.fund(
        hashlock=_HASHLOCK,
        amount_wei=amount,
        resume_from=resume,
        push_nonce=push_nonce,
        push_tx_hash=push_tx_hash,
        on_push_hash=on_push_hash,
        **_FUND,
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


async def _window_unreadable(sender):
    """A multi-source `inflight_nonce_window` whose endpoints cannot be read or do not agree."""
    raise NetworkError("inflight nonce window: no quorum of endpoints answered")


async def test_a_fresh_fund_completes_when_the_nonce_window_cannot_be_read():
    # A fresh HTLC was created by the deploy that just confirmed, so nothing can be in flight TO
    # it and the window is never consulted. Reading it anyway would let one failed quorum read
    # abort a fund AFTER the deploy had spent gas.
    rpc = _PushRpc(held=0, window=_window_unreadable)
    coro, sent = _push(rpc, resuming=False)
    loc = await coro
    assert rpc.transfers == [100] and len(sent) == 1
    assert loc.amount_wei == 100


@pytest.mark.parametrize("held", [100, 150])
async def test_a_resume_with_nothing_left_to_send_completes_when_the_window_cannot_be_read(held):
    # Fully or over-funded: nothing will be sent, so the window cannot change the outcome and a
    # failed read of it must not strand a taker whose fund already completed.
    rpc = _PushRpc(held=held, window=_window_unreadable)
    coro, sent = _push(rpc, resuming=True)
    loc = await coro
    assert sent == [] and rpc.transfers == []
    assert loc.amount_wei == 100


async def test_a_resume_that_must_send_refuses_when_the_window_cannot_be_read():
    # The refusal pair: here the window IS the guard, so an unreadable one fails closed.
    rpc = _PushRpc(held=99, window=_window_unreadable)
    coro, sent = _push(rpc, resuming=True)
    with pytest.raises(NetworkError, match="no quorum of endpoints answered"):
        await coro
    assert sent == [] and rpc.transfers == []


async def test_the_deploy_and_the_push_are_signed_with_their_gas_limits():
    # The limits are fields of the signed transactions, so changing either changes what is
    # broadcast. (The source records the deploy at 450,657 gas, measured on Anvil 2026-10-07.)
    rpc = _PushRpc(held=0)
    coro, sent = _push(rpc, resuming=False)
    await coro
    ((deploy,), (push,)) = rpc.deploys, sent
    assert deploy["gas"] == 800_000
    assert push["gas"] == 100_000


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


@pytest.mark.parametrize("kw", [{"push_status": 0}, {"push_status": 2}, {"statusless": True}])
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


# ── fund: the deploy receipt ────────────────────────────────────────────────────────────────────


async def test_deploy_returns_the_derived_address():
    rpc = _PushRpc(held=0, pending=4)
    coro, _ = _push(rpc, resuming=False)
    loc = await coro
    assert loc.contract_address.lower() == _create_address(rpc.deployer, 4).lower()
    assert loc.deploy_tx_hash == _DEPLOY_HASH


@pytest.mark.parametrize("kw", [{"deploy_status": 0}, {"deploy_status": 2}, {"deploy_statusless": True}])
async def test_deploy_refuses_any_receipt_status_but_one(kw):
    rpc = _PushRpc(held=0, **kw)
    coro, sent = _push(rpc, resuming=False)
    with pytest.raises(NetworkError, match="deploy reverted"):
        await coro
    assert sent == [] and rpc.transfers == []


@pytest.mark.parametrize("lie", ["0x" + "00" * 20, "0x" + "ff" * 20])
async def test_deploy_refuses_a_receipt_naming_ANY_other_address(lie):
    rpc = _PushRpc(held=0, lie=lie)
    coro, sent = _push(rpc, resuming=False)
    with pytest.raises(ValidationError, match="deploy receipt names contract"):
        await coro
    assert sent == [] and rpc.transfers == []


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
