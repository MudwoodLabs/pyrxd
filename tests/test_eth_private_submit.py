"""Tests for the optional private-inclusion (Flashbots) transport for the ETH claim.

The claim is the one tx that reveals p; an injected ``private_submitter`` keeps it off the public
mempool. We verify the routing (claim → submitter when present; public fallback when absent; only
the claim is private) with a fake submitter + fake rpc, and the FlashbotsSubmitter's input guards.
No real relay is contacted.
"""

from __future__ import annotations

import pytest

from pyrxd.eth_wallet.htlc_leg import EthHtlcContractLeg
from pyrxd.eth_wallet.locator import EthHtlcLocator
from pyrxd.eth_wallet.private_submit import FlashbotsSubmitter, PrivateSubmitter
from pyrxd.security.errors import ValidationError
from pyrxd.security.secrets import PrivateKeyMaterial

pytest.importorskip("web3")
pytest.importorskip("eth_account")

_ARTIFACT = {
    "abi": [{"type": "function", "name": "claim", "inputs": [{"type": "bytes32"}]}],
    "bytecode": "0x00",
    "runtime_bytecode": "0x00",
}


class _FakeSubmitter:
    """Records the raw tx it was handed and returns a sentinel private tx hash."""

    def __init__(self):
        self.calls: list[bytes] = []

    async def submit_raw(self, raw_tx: bytes) -> str:
        self.calls.append(bytes(raw_tx))
        return "0x" + "ab" * 32


class _FakeRpc:
    """Minimal rpc that records send_raw and serves the bits claim() touches."""

    def __init__(self):
        self.public_sends: list[bytes] = []

        class _W3Eth:
            def contract(self_inner, address, abi):
                class _Fns:
                    def claim(self_fns, preimage):
                        class _Built:
                            async def build_transaction(self_b, base):
                                return {**base, "to": address, "data": "0x"}

                        return _Built()

                class _C:
                    functions = _Fns()

                return _C()

        class _W3:
            eth = _W3Eth()

        self.w3 = _W3()

    async def assert_chain(self):
        return None

    async def preflight(self, tx):
        return None

    async def fee_fields(self):
        return {"maxFeePerGas": 1, "maxPriorityFeePerGas": 1}

    async def get_transaction_count(self, addr):
        return 0

    async def send_raw(self, raw_tx):
        self.public_sends.append(bytes(raw_tx))
        return "0x" + "cd" * 32


def _locator():
    return EthHtlcLocator(
        chain_id=11155111,
        contract_address="0x" + "11" * 20,
        deploy_tx_hash="0x" + "00" * 32,
        hashlock="0x" + "22" * 32,
        claimant="0x" + "33" * 20,
        refundee="0x" + "44" * 20,
        timeout=10_000,
        amount_wei=10**14,
    )


def _leg(rpc, *, submitter=None):
    return EthHtlcContractLeg(
        rpc=rpc,
        signing_key=PrivateKeyMaterial.generate(),
        chain_id=11155111,
        artifact=_ARTIFACT,
        private_submitter=submitter,
    )


# ──────────────────────────────────────────────── routing ──


async def test_claim_routes_through_private_submitter_when_injected():
    rpc, sub = _FakeRpc(), _FakeSubmitter()
    leg = _leg(rpc, submitter=sub)
    tx_hash = await leg.claim(_locator(), b"\x01" * 32)
    assert tx_hash == "0x" + "ab" * 32  # came from the private submitter
    assert len(sub.calls) == 1  # the claim went private
    assert rpc.public_sends == []  # NOT the public mempool


async def test_claim_falls_back_to_public_when_no_submitter():
    rpc = _FakeRpc()
    leg = _leg(rpc, submitter=None)
    tx_hash = await leg.claim(_locator(), b"\x01" * 32)
    assert tx_hash == "0x" + "cd" * 32  # public send_raw
    assert len(rpc.public_sends) == 1


async def test_ctor_rejects_bad_submitter():
    with pytest.raises(ValidationError, match="submit_raw"):
        EthHtlcContractLeg(
            rpc=_FakeRpc(),
            signing_key=PrivateKeyMaterial.generate(),
            chain_id=11155111,
            artifact=_ARTIFACT,
            private_submitter=object(),  # no submit_raw
        )


def test_fake_submitter_satisfies_protocol():
    assert isinstance(_FakeSubmitter(), PrivateSubmitter)


# ──────────────────────────────────────────────── FlashbotsSubmitter guards ──


def test_flashbots_submitter_validates_inputs():
    key = PrivateKeyMaterial.generate()
    with pytest.raises(ValidationError, match="relay_url"):
        FlashbotsSubmitter(relay_url="ftp://bad", auth_key=key)
    with pytest.raises(ValidationError, match="auth_key"):
        FlashbotsSubmitter(relay_url="https://rpc.flashbots.net/fast", auth_key=object())  # type: ignore[arg-type]
    with pytest.raises(ValidationError, match="timeout_s"):
        FlashbotsSubmitter(relay_url="https://rpc.flashbots.net/fast", auth_key=key, timeout_s=0)


async def test_flashbots_submitter_rejects_empty_raw():
    s = FlashbotsSubmitter(relay_url="https://rpc.flashbots.net/fast", auth_key=PrivateKeyMaterial.generate())
    with pytest.raises(ValidationError, match="raw_tx"):
        await s.submit_raw(b"")


def test_flashbots_submitter_builds_auth_header():
    # The X-Flashbots-Signature header is "<addr>:0x<sig>" — verify it forms without a relay call.
    s = FlashbotsSubmitter(relay_url="https://rpc.flashbots.net/fast", auth_key=PrivateKeyMaterial.generate())
    header = s._sign_header('{"jsonrpc":"2.0"}')
    addr, _, sig = header.partition(":")
    assert addr.startswith("0x") and len(addr) == 42
    assert sig.startswith("0x") and len(sig) == 132  # 65-byte sig hex
