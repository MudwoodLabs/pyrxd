"""The chain id a leg SIGNS with must be the chain its rpc is pinned to.

``assert_chain`` holds the ENDPOINT to the rpc's ``expected_chain_id``. Nothing held the LEG's
``chain_id`` to that same value, so ``EthHtlcContractLeg(rpc=EthRpc(sepolia, expected_chain_id=
11155111), chain_id=1)`` passed ``assert_chain`` and signed for chain 1 before the node could object.
The refusal lives in ``_sign_tx`` — the one
function every transaction the legs send is signed in — so it holds for fund, push, claim and
refund alike.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import os
import pathlib

import pytest

pytest.importorskip("web3", reason="needs the eth extra: pip install 'pyrxd[eth]'")

import pyrxd.eth_wallet as eth_wallet_pkg
from pyrxd.eth_wallet.htlc_leg import EthHtlcContractLeg
from pyrxd.eth_wallet.multi_rpc import MultiSourceEthRpc
from pyrxd.eth_wallet.rpc import EthRpc
from pyrxd.security.errors import ValidationError
from pyrxd.security.secrets import PrivateKeyMaterial

_ART = json.loads((pathlib.Path(__file__).parent / "fixtures" / "EthHtlc.json").read_text())
_CLAIMANT = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
_REFUNDEE = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

#: Never contacted: every test here refuses (or signs) before any request. A port nothing listens
#: on makes an accidental request fail loudly rather than reach something.
_DEAD_URL = "http://127.0.0.1:9/"


def _tx(chain_id: int) -> dict:
    return {
        "to": "0x" + "11" * 20,
        "value": 0,
        "gas": 21_000,
        "maxFeePerGas": 2 * 10**9,
        "maxPriorityFeePerGas": 10**9,
        "nonce": 0,
        "chainId": chain_id,
        "data": "0x",
    }


def _leg(rpc, chain_id: int) -> EthHtlcContractLeg:
    return EthHtlcContractLeg(rpc=rpc, signing_key=PrivateKeyMaterial(os.urandom(32)), chain_id=chain_id, artifact=_ART)


def test_a_leg_signing_for_another_chain_than_its_REAL_EthRpc_is_refused():
    """Through the shipped rpc class, not a fake: the property the check reads is the real one."""
    leg = _leg(EthRpc(_DEAD_URL, expected_chain_id=11155111), chain_id=1)
    with pytest.raises(ValidationError, match="signs for chain 1 but its rpc is pinned to chain 11155111"):
        leg._sign_tx(_tx(1))


def test_the_matching_pair_signs():
    """The honest path: same chain on both sides signs, with the leg's id in the signed bytes."""
    from eth_account.typed_transactions import TypedTransaction
    from hexbytes import HexBytes

    leg = _leg(EthRpc(_DEAD_URL, expected_chain_id=11155111), chain_id=11155111)
    raw, tx_hash = leg._sign_tx(_tx(11155111))
    assert TypedTransaction.from_bytes(HexBytes(raw)).as_dict()["chainId"] == 11155111
    assert tx_hash.startswith("0x")


def test_a_transaction_carrying_another_chainId_than_the_leg_is_refused():
    leg = _leg(EthRpc(_DEAD_URL, expected_chain_id=1), chain_id=1)
    with pytest.raises(ValidationError, match="chainId 5 is not this leg's chain_id 1"):
        leg._sign_tx(_tx(5))


class _SpyRpc:
    """Enough of an rpc for ``fund`` to reach the signer; records whether bytes were sent."""

    def __init__(self, expected_chain_id: int) -> None:
        self.expected_chain_id = expected_chain_id
        self.sent: list[bytes] = []
        real = EthRpc(_DEAD_URL, expected_chain_id=expected_chain_id)
        self.write_w3 = real.w3  # builds the deploy tx locally; never sends through it

    async def assert_chain(self):  # the endpoint IS on the rpc's chain — that is the trap
        return None

    async def fee_fields(self):
        return {"maxFeePerGas": 2 * 10**9, "maxPriorityFeePerGas": 10**9}

    async def get_transaction_count(self, *_a, **_k):
        return 0

    async def send_raw(self, raw: bytes) -> str:  # pragma: no cover - reaching it is the failure
        self.sent.append(raw)
        raise AssertionError("signed bytes reached the provider")


def test_fund_refuses_BEFORE_any_signed_bytes_reach_the_provider():
    """``fund`` on a chain-1 leg over a Sepolia-pinned rpc: nothing is signed or sent."""
    rpc = _SpyRpc(expected_chain_id=11155111)
    leg = _leg(rpc, chain_id=1)
    persisted: list[str] = []

    async def on_deploy(addr, h):  # pragma: no cover - the refusal comes before signing
        persisted.append(h)

    with pytest.raises(ValidationError, match="its rpc is pinned to chain 11155111"):
        asyncio.run(
            leg.fund(
                hashlock=os.urandom(32),
                claimant=_CLAIMANT,
                refundee=_REFUNDEE,
                timeout=4_000_000_000,
                amount_wei=10**15,
                on_deploy=on_deploy,
            )
        )
    assert rpc.sent == [] and persisted == []


# ── MultiSourceEthRpc: one chain, declared ──────────────────────────────────────────────────────


def test_a_multi_source_rpc_spanning_two_chains_is_refused():
    """Each source's assert_chain checks only its own id, so mixed pins used to pass silently."""
    a = EthRpc("http://a.example/", expected_chain_id=1)
    b = EthRpc("http://b.example/", expected_chain_id=11155111)
    with pytest.raises(ValidationError, match="pinned to different chains"):
        MultiSourceEthRpc([a, b])


def test_a_multi_source_rpc_on_one_chain_declares_it_and_the_leg_checks_it():
    rpc = MultiSourceEthRpc(
        [EthRpc("http://a.example/", expected_chain_id=1), EthRpc("http://b.example/", expected_chain_id=1)]
    )
    assert rpc.expected_chain_id == 1
    with pytest.raises(ValidationError, match="signs for chain 5 but its rpc is pinned to chain 1"):
        _leg(rpc, chain_id=5)._sign_tx(_tx(5))
    raw, _h = _leg(rpc, chain_id=1)._sign_tx(_tx(1))
    assert raw


def test_every_shipped_rpc_class_declares_its_chain():
    """``_sign_tx`` cannot cross-check an rpc that declares no ``expected_chain_id`` (a duck-typed
    stand-in). That leniency must never cover a SHIPPED rpc, so the set is derived: every class in
    ``pyrxd.eth_wallet`` with an ``assert_chain`` method must expose ``expected_chain_id``."""
    import importlib
    import pkgutil

    classes = set()
    for mod_info in pkgutil.iter_modules(eth_wallet_pkg.__path__):
        mod = importlib.import_module(f"pyrxd.eth_wallet.{mod_info.name}")
        for _name, cls in inspect.getmembers(mod, inspect.isclass):
            if cls.__module__ == mod.__name__ and callable(getattr(cls, "assert_chain", None)):
                classes.add(cls)
    assert {EthRpc, MultiSourceEthRpc} <= classes, classes  # non-vacuity: the known two are found
    missing = [
        c.__name__ for c in classes if not isinstance(inspect.getattr_static(c, "expected_chain_id", None), property)
    ]
    assert not missing, f"rpc classes with no expected_chain_id property: {missing}"
