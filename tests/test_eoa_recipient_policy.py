"""Who may RECEIVE a payout — driven behaviourally, not asserted from source.

A test-integrity audit found the delegation policy pinned only by a signature default and by
source-substring checks, one of which was **vacuously true** (it asserted the absence of a
parameter name that had already been renamed away, so it could never fail). These drive the real
`verify_funded` to the recipient check and observe the outcome.

The policy under test:

* **native leg** — pays with an ETH send, which EXECUTES the recipient's code. Any code is
  refused, delegation designators included: a delegate that reverts on receive locks the funds.
* **token leg** — pays with an ERC-20 sweep, which calls the TOKEN and never the recipient. An
  EIP-7702 delegated EOA is fine. An arbitrary CONTRACT is still refused, because the finding was
  about delegated EOAs and the fix must not outgrow it.
"""

from __future__ import annotations

import asyncio
import json
import os
import pathlib

import pytest

pytest.importorskip("web3", reason="needs the eth extra: pip install 'pyrxd[eth]'")

from pyrxd.eth_wallet.erc20_leg import Erc20HtlcLeg
from pyrxd.eth_wallet.htlc_leg import EthHtlcContractLeg
from pyrxd.eth_wallet.locator import Erc20HtlcLocator, EthHtlcLocator
from pyrxd.eth_wallet.tokens import token_for
from pyrxd.security.errors import ValidationError
from pyrxd.security.secrets import PrivateKeyMaterial

_FIX = pathlib.Path(__file__).parent / "fixtures"
_NATIVE_ART = json.loads((_FIX / "EthHtlc.json").read_text())
_TOKEN_ART = json.loads((_FIX / "Erc20Htlc.json").read_text())

_HTLC = "0x" + "11" * 20
_CLAIMANT = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
_REFUNDEE = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
_HASHLOCK = "0x" + "33" * 32
_TIMEOUT = 1_800_000_000
_AMOUNT = 12_345_678

DELEGATION = b"\xef\x01\x00" + b"\x11" * 20  # exactly 23 bytes — a 7702 EOA
CONTRACT = b"\x60\x80\x60\x40" * 10  # ordinary bytecode


def _rpc(artifact: dict, recipient_code: bytes, *, token_balance: int = _AMOUNT):
    """An RPC that gets `verify_funded` all the way to the recipient check and no further."""
    runtime = bytes.fromhex(artifact["runtime_bytecode"].removeprefix("0x"))

    class _Call:
        def __init__(self, v):
            self._v = v

        async def call(self, *a, **k):
            return self._v

    class _Fns:
        def hashlock(self):
            return _Call(bytes.fromhex(_HASHLOCK[2:]))

        def claimant(self):
            return _Call(_CLAIMANT)

        def refundee(self):
            return _Call(_REFUNDEE)

        def timeout(self):
            return _Call(_TIMEOUT)

        def token(self):
            return _Call(token_for("USDC", 1).address)

        def amount(self):
            return _Call(_AMOUNT)

        def balanceOf(self, *a, **k):
            return _Call(token_balance)

        def decimals(self):
            return _Call(6)

    class _Contract:
        functions = _Fns()

    class _Eth:
        def contract(self, *a, **k):
            return _Contract()

    class _W3:
        eth = _Eth()

    class _Rpc:
        w3 = _W3()

        # The write path is a SEPARATE accessor: a multi-source RPC has no single `w3` to
        # sign against, so `w3` raises there and `write_w3` returns the primary's. One
        # source means they are the same object here.
        write_w3 = w3

        async def latest_block_timestamp(self):
            # The deadline guard reads the LATEST head any endpoint admits to; the staleness abort
            # reads the QUORUM-th. One source has one answer, so all three coincide here. `claim`
            # used to reach through `w3.eth.get_block` directly, which a multi-source RPC cannot serve.
            return int((await self.w3.eth.get_block("latest"))["timestamp"])

        async def latest_block_timestamp_quorum(self):
            return await self.latest_block_timestamp()

        async def latest_block_timestamp_min(self):
            return await self.latest_block_timestamp()

        async def assert_chain(self):
            return None

        async def get_code(self, addr, block_identifier=None):
            return runtime if addr == _HTLC else recipient_code

        async def get_balance(self, *a, **k):
            return 0

    return _Rpc()


def _native_locator() -> EthHtlcLocator:
    return EthHtlcLocator(
        chain_id=1,
        contract_address=_HTLC,
        deploy_tx_hash="0x" + "22" * 32,
        hashlock=_HASHLOCK,
        claimant=_CLAIMANT,
        refundee=_REFUNDEE,
        timeout=_TIMEOUT,
        amount_wei=_AMOUNT,
    )


def _token_locator() -> Erc20HtlcLocator:
    return Erc20HtlcLocator(
        chain_id=1,
        contract_address=_HTLC,
        deploy_tx_hash="0x" + "22" * 32,
        hashlock=_HASHLOCK,
        claimant=_CLAIMANT,
        refundee=_REFUNDEE,
        timeout=_TIMEOUT,
        amount_wei=_AMOUNT,
        token_address=token_for("USDC", 1).address,
    )


def _key() -> PrivateKeyMaterial:
    return PrivateKeyMaterial(os.urandom(32))


class TestTheNativeLegRefusesAnyRecipientCode:
    """It pays with an ETH send, so the recipient's code runs. A delegate that reverts on receive
    would lock the funds — which is why delegation designators are refused here too."""

    def test_a_delegated_eoa_is_refused_and_the_message_says_why(self) -> None:
        leg = EthHtlcContractLeg(
            rpc=_rpc(_NATIVE_ART, DELEGATION), signing_key=_key(), chain_id=1, artifact=_NATIVE_ART
        )
        with pytest.raises(ValidationError, match="EIP-7702"):
            asyncio.run(leg.verify_funded(_native_locator(), expected_amount_wei=0))

    def test_an_ordinary_contract_is_refused(self) -> None:
        leg = EthHtlcContractLeg(rpc=_rpc(_NATIVE_ART, CONTRACT), signing_key=_key(), chain_id=1, artifact=_NATIVE_ART)
        with pytest.raises(ValidationError, match="not an EOA"):
            asyncio.run(leg.verify_funded(_native_locator(), expected_amount_wei=0))

    def test_a_plain_eoa_passes(self) -> None:
        """The honest path — a guard that refuses valid work is a bug."""
        leg = EthHtlcContractLeg(rpc=_rpc(_NATIVE_ART, b""), signing_key=_key(), chain_id=1, artifact=_NATIVE_ART)
        asyncio.run(leg.verify_funded(_native_locator(), expected_amount_wei=0))


class TestTheTokenLegAdmitsDelegatesButNotContracts:
    """It pays with an ERC-20 sweep, which never executes the recipient's code."""

    def _leg(self, recipient_code: bytes) -> Erc20HtlcLeg:
        return Erc20HtlcLeg(
            token=token_for("USDC", 1),
            rpc=_rpc(_TOKEN_ART, recipient_code),
            signing_key=_key(),
            chain_id=1,
            artifact=_TOKEN_ART,
        )

    def test_a_delegated_eoa_is_ACCEPTED(self) -> None:
        """The #478 fix, driven rather than grepped."""
        asyncio.run(self._leg(DELEGATION).verify_funded(_token_locator(), expected_amount_wei=_AMOUNT))

    def test_an_arbitrary_contract_is_STILL_refused(self) -> None:
        """The fix must not outgrow the finding. This is the case a vacuous source assertion
        claimed to cover and did not: dropping the `delegated` condition from the loop would admit
        any contract, and nothing would have noticed."""
        with pytest.raises(ValidationError, match="not an EOA"):
            asyncio.run(self._leg(CONTRACT).verify_funded(_token_locator(), expected_amount_wei=_AMOUNT))

    def test_a_plain_eoa_passes(self) -> None:
        asyncio.run(self._leg(b"").verify_funded(_token_locator(), expected_amount_wei=_AMOUNT))


class TestTheFundGuardRefusesAnAssetMismatchBeforeAnyBroadcast:
    """`EthLeg.fund`'s asset cross-check had NO test at all, despite its own comment calling it
    load-bearing: without it a token leg on native terms deploys and pushes real USDC, and the
    mismatch surfaces only at `SwapRecord.__post_init__` — after the tokens sit in an HTLC the
    counterparty can claim. "A post-mortem is not a gate."

    It must refuse before any network call, so these assert with an RPC that explodes if touched.
    """

    @staticmethod
    def _adapter(*, token_leg: bool):
        from pyrxd.gravity.eth_leg import EthLeg

        class _Exploding:
            def __getattr__(self, name):  # pragma: no cover - must never be reached
                raise AssertionError(f"the guard let execution reach the network ({name})")

        art = _TOKEN_ART if token_leg else _NATIVE_ART
        kw = dict(rpc=_Exploding(), signing_key=_key(), chain_id=1, artifact=art)
        leg = Erc20HtlcLeg(token=token_for("USDC", 1), **kw) if token_leg else EthHtlcContractLeg(**kw)
        return EthLeg(
            contract_leg=leg,
            network="mainnet",
            claim_to=_CLAIMANT,
            refund_to=_REFUNDEE,
            eth_timeout_unix_s=_TIMEOUT,
        )

    @staticmethod
    def _terms(token_address: str):
        import hashlib

        from pyrxd.gravity import swap_state as t
        from pyrxd.gravity.swap_state import NegotiatedTerms

        return NegotiatedTerms(
            hashlock=hashlib.sha256(b"x").digest(),
            btc_sats=100_000,
            radiant_amount=1_000,
            t_btc=t.Timelock(144, t.TimeUnit.BLOCKS),
            t_rxd=t.Timelock(72, t.TimeUnit.BLOCKS),
            asset_variant="rxd",
            genesis_ref=b"",
            taker_dest_hash=b"\x11" * 32,
            maker_dest_hash=b"\x22" * 32,
            btc_claim_pubkey_xonly=b"\x00" * 32,
            btc_refund_pubkey_xonly=b"\x00" * 32,
            counter_chain="eth",
            value_amount=_AMOUNT,
            eth_timeout_unix_s=_TIMEOUT,
            token_address=token_address,
        )

    def test_a_token_leg_with_NATIVE_terms_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="asset mismatch before funding"):
            asyncio.run(self._adapter(token_leg=True).fund(self._terms("")))

    def test_a_native_leg_with_TOKEN_terms_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="asset mismatch before funding"):
            asyncio.run(self._adapter(token_leg=False).fund(self._terms(token_for("USDC", 1).address)))

    def test_a_token_leg_with_a_DIFFERENT_token_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="asset mismatch before funding"):
            asyncio.run(self._adapter(token_leg=True).fund(self._terms("0x" + "99" * 20)))
