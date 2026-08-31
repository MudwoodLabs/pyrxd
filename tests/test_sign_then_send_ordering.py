"""The REAL `_sign_and_send`: the handle is recorded between signing and sending (#502 item 2).

Every existing test of this area replaces `_sign_and_send` with a stub, so none of them can see
what the production method does — planting "skip the persist" and "swallow a failing persist" in it
leaves all 57 of them green. These drive the real one against a fake RPC.

The hash is knowable before the broadcast because a signed transaction's hash is keccak of its own
bytes. That is what makes a pre-broadcast persist possible at all, and it is why the
deploy-to-persist gap was ACCEPTED rather than forced.
"""

from __future__ import annotations

import asyncio
import os

import pytest

from pyrxd.eth_wallet.htlc_leg import EthHtlcContractLeg
from pyrxd.security.errors import NetworkError
from pyrxd.security.secrets import PrivateKeyMaterial

pytest.importorskip("web3")

_TX = {
    "to": "0x" + "11" * 20,
    "value": 1,
    "gas": 21_000,
    "maxFeePerGas": 2_000_000_000,
    "maxPriorityFeePerGas": 1_000_000_000,
    "nonce": 7,
    "chainId": 1,
    "data": b"",
}


class _Rpc:
    def __init__(self) -> None:
        self.order: list[str] = []
        self.sent: list[bytes] = []

    async def preflight(self, tx) -> None:
        self.order.append("preflight")

    async def send_raw(self, raw: bytes) -> str:
        self.order.append("send")
        self.sent.append(raw)
        from eth_utils import keccak

        return "0x" + keccak(raw).hex()


def _leg(rpc: _Rpc) -> EthHtlcContractLeg:
    leg = object.__new__(EthHtlcContractLeg)
    leg._rpc = rpc
    leg._key = PrivateKeyMaterial(os.urandom(32))
    leg._private_submitter = None
    return leg


def test_the_hash_is_known_before_the_broadcast() -> None:
    """`_sign_tx` returns it. Without this the persist cannot precede the send, which is what made
    the gap look unavoidable."""
    rpc = _Rpc()
    raw, tx_hash = _leg(rpc)._sign_tx(dict(_TX))
    assert rpc.order == [], "signing must not touch the network"
    assert isinstance(raw, bytes) and raw
    assert len(tx_hash) == 66 and tx_hash.startswith("0x")


def test_on_signed_fires_BEFORE_send_raw() -> None:
    rpc = _Rpc()
    leg = _leg(rpc)

    async def _persist(h: str) -> None:
        rpc.order.append("persist")

    asyncio.run(leg._sign_and_send(dict(_TX), preflight=False, on_signed=_persist))
    assert rpc.order == ["persist", "send"], rpc.order


def test_a_raising_on_signed_PREVENTS_the_broadcast() -> None:
    """The property the ordering exists for: if the handle cannot be recorded, nothing is sent, so
    there is no untracked contract and a retry costs nothing."""
    rpc = _Rpc()
    leg = _leg(rpc)

    async def _broken(h: str) -> None:
        raise NetworkError("read-only filesystem")

    with pytest.raises(NetworkError, match="read-only filesystem"):
        asyncio.run(leg._sign_and_send(dict(_TX), preflight=False, on_signed=_broken))
    assert rpc.sent == [], "it broadcast anyway after failing to record the handle"


def test_the_hash_handed_to_on_signed_is_the_one_returned() -> None:
    """A handle recorded against a different hash than the transaction that was actually sent
    would be worse than none — it would point at nothing while looking authoritative."""
    rpc = _Rpc()
    leg = _leg(rpc)
    seen: list[str] = []

    async def _persist(h: str) -> None:
        seen.append(h)

    got = asyncio.run(leg._sign_and_send(dict(_TX), preflight=False, on_signed=_persist))
    assert seen == [got]


def test_a_node_echoing_a_DIFFERENT_hash_is_refused() -> None:
    """We signed the bytes, so we know the hash. Being told otherwise means the node did not
    broadcast what we gave it — the broadcast-echo distrust rule from 0.19.0."""

    class _Lying(_Rpc):
        async def send_raw(self, raw: bytes) -> str:
            self.order.append("send")
            self.sent.append(raw)
            return "0x" + "ff" * 32

    with pytest.raises(NetworkError, match="keccak"):
        asyncio.run(_leg(_Lying())._sign_and_send(dict(_TX), preflight=False))


def test_no_on_signed_still_works() -> None:
    """Honest path: every other caller passes nothing and must be unaffected."""
    rpc = _Rpc()
    got = asyncio.run(_leg(rpc)._sign_and_send(dict(_TX), preflight=False))
    assert rpc.order == ["send"]
    assert len(got) == 66
