"""A deployed HTLC must be referenced by the durable record before value moves into it.

`taker_funds_btc` persists an intent record before broadcasting, and its comment says that record
"knows WHERE the HTLC address is". That is true for BTC — a P2TR funding address is derived from
terms before anything is broadcast — and it was false for ETH, where a CREATE address depends on
the deployer's nonce and does not exist until the deploy receipt returns.

The ERC-20 path makes it worst, because funding is TWO transactions: deploy, then a plain
`transfer`. A crash after the push but before the locator is returned left real USDC in a contract
whose only reference was an exception string. `refund()` recovers it after the timeout — but only
for an operator who still knows the address, and reconstructing a CREATE address by hand is not a
recovery procedure.

The leg now awaits `on_deploy(address)` as soon as the deploy confirms and, for the token leg,
strictly BEFORE the tokens are pushed.
"""

from __future__ import annotations

import asyncio
import json
import os
import pathlib
import time

import pytest

pytest.importorskip("web3", reason="needs the eth extra: pip install 'pyrxd[eth]'")

from pyrxd.eth_wallet.erc20_leg import Erc20HtlcLeg
from pyrxd.eth_wallet.tokens import token_for
from pyrxd.security.errors import NetworkError
from pyrxd.security.secrets import PrivateKeyMaterial

_ART = json.loads((pathlib.Path(__file__).parent / "fixtures" / "Erc20Htlc.json").read_text())
_DEPLOYED = "0x" + "77" * 20
_USDC = token_for("USDC", 1)


def _leg(*, push_fails: bool, order: list):
    """A token leg whose deploy always succeeds; the push may fail. `order` records the sequence
    of externally-visible events so the ORDERING can be asserted, not just the calls."""

    class _Call:
        def __init__(self, v):
            self._v = v

        async def call(self, *a, **k):
            return self._v

    class _Fns:
        def transfer(self, *a, **k):
            class _B:
                async def build_transaction(self_b, tx):
                    return dict(tx)

            return _B()

        def symbol(self, *a, **k):
            return _Call("USDC")

        def decimals(self, *a, **k):
            return _Call(6)

        def balanceOf(self, *a, **k):
            return _Call(12_345_678)

    class _Ctor:
        async def build_transaction(self, tx):
            return dict(tx)

    class _Contract:
        functions = _Fns()

        def constructor(self, *a, **k):
            return _Ctor()

    class _Eth:
        def contract(self, *a, **k):
            return _Contract()

    class _W3:
        eth = _Eth()

    class _Rpc:
        w3 = _W3()

        async def assert_chain(self):
            return None

        async def fee_fields(self):
            return {"maxPriorityFeePerGas": 1, "maxFeePerGas": 3}

        async def get_transaction_count(self, _a):
            return 0

        async def wait_receipt(self, tx_hash, **_k):
            if tx_hash == "0xdeploy":
                return {"status": 1, "contractAddress": _DEPLOYED, "logs": []}
            return {"status": 0 if push_fails else 1, "logs": []}

    leg = Erc20HtlcLeg(
        token=_USDC, rpc=_Rpc(), signing_key=PrivateKeyMaterial(os.urandom(32)), chain_id=1, artifact=_ART
    )

    sends = {"n": 0}

    async def _sign_and_send(*a, **k):
        sends["n"] += 1
        if sends["n"] == 1:
            return "0xdeploy"
        order.append("tokens-pushed")
        return "0xpush"

    leg._sign_and_send = _sign_and_send
    return leg


def _fund(leg, on_deploy):
    return asyncio.run(
        leg.fund(
            hashlock=b"\x33" * 32,
            claimant="0x" + "44" * 20,
            refundee="0x" + "55" * 20,
            timeout=int(time.time()) + 86_400,
            amount_wei=12_345_678,
            on_deploy=on_deploy,
        )
    )


class TestTheAddressIsDurableBeforeTheTokensMove:
    def test_on_deploy_fires_BEFORE_the_token_push(self) -> None:
        """The ordering IS the fix. Persisting after the push leaves a window in which real value
        sits in a contract nothing references — exactly the case being closed."""
        order: list = []

        async def _remember(addr: str) -> None:
            order.append(f"persisted:{addr}")

        _fund(_leg(push_fails=False, order=order), _remember)
        assert order == [f"persisted:{_DEPLOYED}", "tokens-pushed"], order

    def test_a_FAILED_push_still_leaves_the_address_recorded(self) -> None:
        """The crash-consistency case. The push reverts, `fund` raises and returns no locator —
        but the operator must still hold the address, because the contract exists and a later
        retry or refund needs somewhere to point."""
        seen: list = []

        async def _remember(addr: str) -> None:
            seen.append(addr)

        with pytest.raises(NetworkError):
            _fund(_leg(push_fails=True, order=[]), _remember)
        assert seen == [_DEPLOYED], "the deployed address was lost when the push failed"

    def test_a_caller_that_cannot_PERSIST_stops_before_the_tokens_move(self) -> None:
        """If the record cannot be written, pushing would create precisely the untracked value
        this exists to prevent. Awaiting the hook — rather than firing and forgetting — is what
        makes the failure stop the push."""
        order: list = []

        async def _broken(_addr: str) -> None:
            raise NetworkError("record store unavailable")

        with pytest.raises(NetworkError, match="record store unavailable"):
            _fund(_leg(push_fails=False, order=order), _broken)
        assert "tokens-pushed" not in order, "tokens were pushed despite the address not being durable"

    def test_fund_without_a_hook_still_works(self) -> None:
        """A guard that refuses valid work is a bug: `on_deploy` is optional, and a caller that
        passes nothing keeps the previous behaviour."""
        order: list = []
        loc = _fund(_leg(push_fails=False, order=order), None)
        assert loc.contract_address.lower() == _DEPLOYED.lower()
        assert order == ["tokens-pushed"]
