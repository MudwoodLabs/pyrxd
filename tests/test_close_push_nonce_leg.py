"""The leg and rpc pieces of closing a token push's nonce (#850 PR 7a, design §2.7).

``EthHtlcContractLeg.close_nonce`` signs a 0-value transfer from the leg's key to itself at one
nonce, records it before the broadcast, and refuses unless the broadcasting endpoint's latest count
is exactly that nonce. ``EthRpc.erc20_balance_of`` is the per-endpoint balance read the disposition
reader uses, and ``EthLeg.counter_disposition`` hands the reader the token and the push key.
The signing is real; the rpc is a recorder.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
import rlp
from eth_utils import keccak

from pyrxd.eth_wallet.events import function_selector
from pyrxd.eth_wallet.htlc_leg import CLOSE_NONCE_GAS, EthHtlcContractLeg
from pyrxd.eth_wallet.keys import derive_address
from pyrxd.eth_wallet.locator import Erc20HtlcLocator, EthHtlcLocator
from pyrxd.eth_wallet.rpc import EthRpc
from pyrxd.security.errors import NetworkError, ValidationError
from pyrxd.security.secrets import PrivateKeyMaterial

_ARTIFACT = json.loads((Path(__file__).parent / "fixtures" / "EthHtlc.json").read_text())
_CHAIN = 31337


class _Rpc:
    expected_chain_id = _CHAIN

    def __init__(self, latest: int) -> None:
        self.latest = latest
        self.events: list[str] = []
        self.sent: list[bytes] = []

    async def assert_chain(self) -> None:
        return None

    async def get_transaction_count(self, address: str, block="pending") -> int:
        return self.latest if block == "latest" else self.latest + 3  # pending ignored by close_nonce

    async def fee_fields(self) -> dict:
        return {"maxFeePerGas": 2_000_000_000, "maxPriorityFeePerGas": 1_000_000_000}

    async def send_raw(self, raw: bytes) -> str:
        self.events.append("send")
        self.sent.append(bytes(raw))
        return "0x" + keccak(bytes(raw)).hex()


def _leg(latest: int) -> tuple[EthHtlcContractLeg, _Rpc, str]:
    key = PrivateKeyMaterial(os.urandom(32))
    rpc = _Rpc(latest)
    return EthHtlcContractLeg(rpc=rpc, signing_key=key, chain_id=_CHAIN, artifact=_ARTIFACT), rpc, derive_address(key)


def _decode(raw: bytes) -> dict:
    assert raw[0] == 2, "an EIP-1559 transaction"
    chain_id, nonce, _tip, _fee, gas, to, value, data, _al, _v, _r, _s = rlp.decode(raw[1:])
    return {
        "chainId": int.from_bytes(chain_id, "big"),
        "nonce": int.from_bytes(nonce, "big"),
        "gas": int.from_bytes(gas, "big"),
        "to": "0x" + bytes(to).hex(),
        "value": int.from_bytes(value, "big"),
        "data": bytes(data),
    }


async def test_close_nonce_sends_a_zero_value_transfer_to_itself_at_that_nonce():
    leg, rpc, addr = _leg(latest=7)
    seen = []

    async def on_signed(tx_hash, nonce):
        rpc.events.append("recorded")
        seen.append((tx_hash, nonce))

    tx_hash = await leg.close_nonce(7, on_signed=on_signed)
    assert rpc.events == ["recorded", "send"], "recorded BEFORE the broadcast (design §2.8)"
    assert seen == [(tx_hash, 7)]
    tx = _decode(rpc.sent[0])
    assert tx == {"chainId": _CHAIN, "nonce": 7, "gas": CLOSE_NONCE_GAS, "to": addr.lower(), "value": 0, "data": b""}
    assert tx_hash == "0x" + keccak(rpc.sent[0]).hex()


@pytest.mark.parametrize(("latest", "why"), [(8, "already consumed"), (6, "below nonce")])
async def test_close_nonce_signs_nothing_unless_latest_is_exactly_the_nonce(latest, why):
    leg, rpc, _addr = _leg(latest=latest)
    called = []

    async def on_signed(tx_hash, nonce):
        called.append(tx_hash)

    with pytest.raises(NetworkError, match=why):
        await leg.close_nonce(7, on_signed=on_signed)
    assert called == [] and rpc.sent == []


async def test_a_record_that_fails_stops_the_close():
    leg, rpc, _addr = _leg(latest=7)

    async def on_signed(tx_hash, nonce):
        raise OSError("disk full")

    with pytest.raises(OSError):
        await leg.close_nonce(7, on_signed=on_signed)
    assert rpc.sent == []


@pytest.mark.parametrize("nonce", [-1, True, "7"])
async def test_a_bad_nonce_is_refused(nonce):
    leg, rpc, _addr = _leg(latest=7)
    with pytest.raises(ValidationError):
        await leg.close_nonce(nonce)
    assert rpc.sent == []


# --------------------------------------------------------------------------- the balance read


class _Eth:
    def __init__(self, answer):
        self.answer = answer
        self.calls: list[tuple[dict, object]] = []

    async def call(self, tx, block_identifier):
        self.calls.append((tx, block_identifier))
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer


class _W3:
    def __init__(self, answer):
        self.eth = _Eth(answer)

    @staticmethod
    def to_checksum_address(a):
        from web3 import Web3

        return Web3.to_checksum_address(a)


def _rpc_with(answer) -> tuple[EthRpc, _W3]:
    rpc = EthRpc("http://127.0.0.1:8545", expected_chain_id=_CHAIN)
    w3 = _W3(answer)
    rpc._w3 = w3
    return rpc, w3


async def test_erc20_balance_of_is_balanceOf_owner_at_the_block():
    rpc, w3 = _rpc_with((1234).to_bytes(32, "big"))
    owner, token = "0x" + "c0" * 20, "0x" + "70" * 20
    assert await rpc.erc20_balance_of(token, owner, 90) == 1234
    ((tx, block),) = w3.eth.calls
    assert block == 90 and tx["to"].lower() == token
    assert tx["data"] == "0x" + (function_selector("balanceOf(address)") + bytes(12) + bytes.fromhex("c0" * 20)).hex()
    assert function_selector("balanceOf(address)").hex() == "70a08231"  # the well-known selector


@pytest.mark.parametrize("answer", [b"\x00" * 31, b"\x00" * 64, RuntimeError("missing trie node")])
async def test_erc20_balance_of_never_reads_a_failure_as_zero(answer):
    rpc, _w3 = _rpc_with(answer)
    with pytest.raises(NetworkError):
        await rpc.erc20_balance_of("0x" + "70" * 20, "0x" + "c0" * 20, 90)


# --------------------------------------------------------------------------- EthLeg wiring


def _loc(**extra):
    base = {
        "chain_id": _CHAIN,
        "contract_address": "0x" + "c0" * 20,
        "deploy_tx_hash": "0x" + "11" * 32,
        "hashlock": "0x" + "22" * 32,
        "claimant": "0x" + "44" * 20,
        "refundee": "0x" + "55" * 20,
        "timeout": 1_800_000_000,
        "amount_wei": 1_000_000,
    }
    return Erc20HtlcLocator(**base, **extra) if extra else EthHtlcLocator(**base)


@pytest.mark.parametrize("token", [True, False])
async def test_eth_leg_reads_a_token_contract_with_its_token_and_push_key(monkeypatch, token):
    from pyrxd.eth_wallet import disposition
    from pyrxd.gravity.eth_leg import EthLeg

    leg, _rpc, addr = _leg(latest=0)
    adapter = EthLeg(
        contract_leg=leg,
        network="mainnet",
        claim_to="0x" + "44" * 20,
        refund_to="0x" + "55" * 20,
        eth_timeout_unix_s=1_800_000_000,
    )
    captured = {}

    async def fake_read(rpc, locator, **kwargs):
        captured.update(kwargs)
        return "read"

    monkeypatch.setattr(disposition, "read_counter_disposition", fake_read)
    locator = _loc(token_address="0x" + "70" * 20) if token else _loc()
    assert await adapter.counter_disposition(locator, push_nonce_bound=7) == "read"
    if token:
        assert captured["token_address"] == "0x" + "70" * 20
        assert captured["funding_account"] == addr and captured["push_nonce_bound"] == 7
    else:
        assert captured["token_address"] is None and captured["funding_account"] is None
        assert captured["push_nonce_bound"] is None


async def test_the_multi_source_balance_read_is_an_identity_read():
    from pyrxd.eth_wallet.multi_rpc import MultiSourceEthRpc
    from pyrxd.security.errors import RxdSdkError
    from tests._fake_evm_chain import CONTRACT, TOKEN, FakeEvmChain, FakeEvmEndpoint

    chain = FakeEvmChain(preimage=os.urandom(32), timeout=0, token_balances={5: 42})
    agree = MultiSourceEthRpc([FakeEvmEndpoint(chain), FakeEvmEndpoint(chain)])
    assert await agree.erc20_balance_of(TOKEN, CONTRACT, 50) == 42
    disagree = MultiSourceEthRpc([FakeEvmEndpoint(chain), FakeEvmEndpoint(chain, lie_balance=0)])
    with pytest.raises(RxdSdkError):
        await disagree.erc20_balance_of(TOKEN, CONTRACT, 50)
