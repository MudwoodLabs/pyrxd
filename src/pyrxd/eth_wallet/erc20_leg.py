"""ERC-20 (USDC) counter-chain leg — the token sibling of :class:`EthHtlcContractLeg`.

**A subclass, not a fork, and not an edit.** The native leg has moved real value on mainnet, so
this adds behaviour without changing a line of it: only ``fund`` and ``verify_funded`` are
overridden. ``claim``, ``refund``, ``fetch_claim_artifacts``, ``assert_claim_provenance``,
``is_final`` and ``claim_finality_verdict`` are inherited **unchanged**, which works because
``Erc20Htlc.sol`` was deliberately given the same ``claim(bytes32)`` / ``refund()`` signatures and
the same ``Claimed(bytes32)`` event with the preimage un-indexed. Secret recovery therefore needs
no token-specific code at all.

**What genuinely differs is funding.** A payable constructor holds ETH; it cannot pull a token,
because ``transferFrom`` needs an allowance granted to an address that does not exist until the
deploy lands. So funding is two transactions — deploy, then a plain ``transfer`` — and
"deployed" stops implying "funded". Nothing in the protocol relied on that implication: the
coordinator already documents that an HTLC address commits to immutables, not to the funded
balance, and it is the explicit amount bind that catches a wrong amount.
"""

from __future__ import annotations

from typing import Any

from ..security.errors import NetworkError, ValidationError
from .erc20 import assert_token_matches_chain, balance_of
from .htlc_leg import EthHtlcContractLeg, _require_web3
from .locator import EthHtlcLocator
from .tokens import Erc20Token

#: Measured on a mainnet fork against the real USDC proxy (block 25,815,805): a `transfer` into a
#: fresh contract address costs 43,664 gas — the expensive case, because it writes a previously
#: zero balance slot. 100k is generous headroom; you pay gasUsed, not the limit.
_TOKEN_TRANSFER_GAS = 100_000

#: ``transfer(address,uint256)`` only. :mod:`pyrxd.eth_wallet.erc20` is deliberately read-only,
#: so the ONE write this design performs lives here, next to the code that performs it. There is
#: no ``approve`` in either module because the design has no allowances.
_TRANSFER_ABI = [
    {
        "name": "transfer",
        "type": "function",
        "stateMutability": "nonpayable",
        "inputs": [{"name": "to", "type": "address"}, {"name": "value", "type": "uint256"}],
        "outputs": [{"name": "", "type": "bool"}],
    }
]


class Erc20HtlcLeg(EthHtlcContractLeg):
    """Counter-chain leg holding an ERC-20 rather than native ETH.

    ``artifact`` must be the **Erc20Htlc** artifact, whose constructor takes ``token`` and
    ``amount`` in addition to the four the native one takes.
    """

    def __init__(self, *, token: Erc20Token, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        if not isinstance(token, Erc20Token):
            raise ValidationError("token must be an Erc20Token from the pinned registry")
        if token.chain_id != self._chain_id:
            raise ValidationError(
                f"token {token.symbol} is pinned to chain id {token.chain_id} but this leg runs on "
                f"{self._chain_id}. A token address means nothing without its chain — the same "
                "string is a different asset elsewhere."
            )
        self._token = token

    @property
    def token(self) -> Erc20Token:
        return self._token

    async def fund(
        self, *, hashlock: bytes, claimant: str, refundee: str, timeout: int, amount_wei: int
    ) -> EthHtlcLocator:
        """Deploy the HTLC, push the tokens into it, and only then return a locator.

        ``amount_wei`` is the ABC's parameter name and is retained so this stays substitutable for
        the native leg — but the VALUE is in the token's **base units** (USDC has 6 decimals, not
        18). The name is the ABC's, the unit is the token's; the durable record disambiguates by
        locator type, not by this argument.

        **Returning only after the tokens land is the contract, not an optimisation.** The ABC
        promises a funded locator, and the counterparty's ``verify_funded`` is what protects them.
        A crash between the two transactions therefore never yields a locator: either the tokens
        are still in the funder's wallet (crashed before the push) or they sit in an abandoned
        contract recoverable by ``refund`` after the timeout (crashed after it). Neither strands
        value, but the *resume* path — completing the push to the same address rather than
        redeploying, and re-reading the balance before re-sending so a lost receipt cannot
        double-fund — belongs to the coordinator and is not implemented here.
        """
        if not isinstance(hashlock, (bytes, bytearray)) or len(hashlock) != 32:
            raise ValidationError("hashlock must be 32 bytes")
        if not isinstance(amount_wei, int) or isinstance(amount_wei, bool) or amount_wei <= 0:
            raise ValidationError("amount (token base units) must be a positive int")

        web3 = _require_web3()
        await self._rpc.assert_chain()
        # Refuse before spending gas if the pinned decimals disagree with the live contract: at
        # these scales the difference is a factor of 10^12 in everything that follows.
        await assert_token_matches_chain(self._rpc, self._token)

        checksum = web3.Web3.to_checksum_address
        c = self._rpc.w3.eth.contract(abi=self._artifact["abi"], bytecode=self._artifact["bytecode"])
        ctor = c.constructor(
            bytes(hashlock),
            checksum(claimant),
            checksum(refundee),
            int(timeout),
            checksum(self._token.address),
            int(amount_wei),
        )
        # Deploy measured at 412,786 on a mainnet fork; the inherited 800k limit covers it.
        deploy_tx = await self._base_tx(gas=800_000)
        built = await ctor.build_transaction(deploy_tx)
        deploy_hash = await self._sign_and_send(built, preflight=False)
        receipt = await self._rpc.wait_receipt(deploy_hash)
        if int(receipt.get("status", 0)) != 1:
            raise NetworkError(f"Erc20Htlc deploy reverted (status != 1): {deploy_hash}")
        address = checksum(receipt["contractAddress"])

        # --- second transaction: push the tokens in. No approve, no transferFrom. ---
        token_c = self._rpc.w3.eth.contract(address=checksum(self._token.address), abi=_TRANSFER_ABI)
        push_tx = await self._base_tx(gas=_TOKEN_TRANSFER_GAS)
        push_built = await token_c.functions.transfer(address, int(amount_wei)).build_transaction(push_tx)
        push_hash = await self._sign_and_send(push_built)
        push_receipt = await self._rpc.wait_receipt(push_hash)
        if int(push_receipt.get("status", 0)) != 1:
            raise NetworkError(
                f"token transfer into {address} reverted (status != 1): {push_hash}. The HTLC is "
                "deployed but UNFUNDED; it holds nothing, and the tokens are still in the sender's "
                "wallet."
            )

        # Confirm from chain state rather than trusting the receipt: a fee-on-transfer or otherwise
        # non-standard token can succeed while delivering less than it was asked to.
        landed = await balance_of(self._rpc, self._token, address)
        if landed < int(amount_wei):
            raise ValidationError(
                f"push landed {landed} base units of {self._token.symbol} but {amount_wei} was "
                f"required — the HTLC at {address} is under-funded. Refund after the timeout."
            )

        return EthHtlcLocator(
            chain_id=self._chain_id,
            contract_address=address,
            deploy_tx_hash=deploy_hash if deploy_hash.startswith("0x") else "0x" + deploy_hash,
            hashlock="0x" + bytes(hashlock).hex(),
            claimant=checksum(claimant),
            refundee=checksum(refundee),
            timeout=int(timeout),
            amount_wei=int(amount_wei),
        )

    async def verify_funded(
        self, locator: EthHtlcLocator, *, expected_amount_wei: int, block_identifier: Any = None
    ) -> None:
        """Every check the native leg makes, then the TOKEN balance instead of the ETH balance.

        Delegating the shared half keeps the runtime-code check, the immutable binding and the
        EOA-only recipient checks identical to the audited native path — but the parent compares
        ``eth_getBalance``, which for a token HTLC is 0 and always would be. So the parent's
        balance assertion is satisfied with 0 and the real assertion is made here.

        Kept as a LOWER bound, exactly as the native leg does: anyone can send tokens to the
        contract, so an ``== expected`` check would be griefable into a permanent verify failure.
        Over-funding is safe because claim/refund sweep the whole balance to the winner.
        """
        await super().verify_funded(locator, expected_amount_wei=0, block_identifier=block_identifier)
        await assert_token_matches_chain(self._rpc, self._token, block_identifier)

        web3 = _require_web3()
        on_chain_token = await (
            self._rpc.w3.eth.contract(address=locator.contract_address, abi=self._artifact["abi"])
            .functions.token()
            .call(block_identifier="latest" if block_identifier is None else block_identifier)
        )
        if web3.Web3.to_checksum_address(on_chain_token) != web3.Web3.to_checksum_address(self._token.address):
            raise ValidationError(
                f"the HTLC at {locator.contract_address} is denominated in {on_chain_token}, not the "
                f"negotiated {self._token.symbol} at {self._token.address}. Refusing: this is how a "
                "counterparty is handed an asset they did not price."
            )

        held = await balance_of(self._rpc, self._token, locator.contract_address, block_identifier)
        if held < expected_amount_wei:
            raise ValidationError(
                f"funded {self._token.symbol} balance {held} < negotiated {expected_amount_wei} "
                "base units (under-funded)"
            )
