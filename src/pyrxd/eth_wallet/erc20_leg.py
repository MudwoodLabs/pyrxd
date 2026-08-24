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

from ..security.errors import NetworkError, PreRevealAbort, ValidationError
from .erc20 import assert_not_frozen_before_reveal, assert_token_matches_chain, balance_of
from .htlc_leg import EthHtlcContractLeg, _require_web3
from .locator import Erc20HtlcLocator, EthHtlcLocator
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

        # Erc20HtlcLocator, NOT the parent. Returning the parent here made the whole chain-tag
        # mechanism dead on the write side: the record would serialise as `chain: "eth"` carrying
        # 6-decimal base units in a field every reader treats as wei — the 10^12 error the tag
        # exists to prevent, as the DEFAULT behaviour of a real token swap. Caught by review, not
        # by tests, because the tests built locators by hand and nothing exercised this producer.
        return Erc20HtlcLocator(
            chain_id=self._chain_id,
            contract_address=address,
            deploy_tx_hash=deploy_hash if deploy_hash.startswith("0x") else "0x" + deploy_hash,
            hashlock="0x" + bytes(hashlock).hex(),
            claimant=checksum(claimant),
            refundee=checksum(refundee),
            timeout=int(timeout),
            amount_wei=int(amount_wei),
            token_address=self._token.address,
        )

    async def claim(self, locator: EthHtlcLocator, preimage: bytes) -> str:
        """Check the freeze gate, then claim exactly as the native leg does.

        **The gate lives HERE because this is the reveal.** Broadcasting ``claim(preimage)`` puts
        the secret in public calldata, and from that instant the counterparty can take the other
        leg — so a freeze discovered afterwards is a one-sided loss with no recovery. A gate the
        caller has to remember to invoke is a gate that gets skipped: it was defined and called
        nowhere for a whole review cycle, which is the same shipped-but-unreachable failure as
        #468. Putting it in front of the dangerous action makes it unskippable rather than
        merely available.

        The contract address is checked alongside both parties, because that is the freeze with
        no way out: measured on a mainnet fork, freezing the HTLC makes ``claim`` AND ``refund``
        revert permanently, so no timeout rescues it.

        The claim itself is the parent's, unchanged — this adds a precondition, not a different
        settlement path.
        """
        # Re-read the funded balance at the TIP before building a claim. `verify_funded` ran
        # earlier and at a finalized checkpoint, which is the right place for the immutables — but
        # the contract's balance is what decides whether this claim pays, and the on-chain
        # `Underfunded` revert does NOT keep the preimage secret: a reverted transaction is still
        # mined and `p` is still in its calldata. So the last defence is refusing to BUILD the
        # claim, not the contract refusing to honour it. This also closes the private-submission
        # path, where the parent deliberately skips its eth_call preflight.
        # These are the extra reads this leg adds before a reveal, and they are exactly why #479
        # bites here first: three or four more chances for a transport blip to raise. Reported as
        # PreRevealAbort so the caller knows nothing was sent and keeps the preimage.
        try:
            held = await balance_of(self._rpc, self._token, locator.contract_address)
        except Exception as exc:
            raise PreRevealAbort(f"could not read the funded balance before revealing: {exc}") from exc
        if held < locator.amount_base_units:
            # PreRevealAbort, not ValidationError: this refusal is PRE-BROADCAST, so the preimage
            # is still secret and the caller must not discard it. Round 2 fixed the transport-error
            # lane of #479 and left this value lane behind — a load-balanced provider serving a
            # lagging node returns a stale low balance, the claim is refused, and the secret dies
            # for a reading that was simply out of date. Keeping p costs nothing even when the
            # contract really is short: the maker just does not claim, and both sides refund.
            raise PreRevealAbort(
                f"refusing to build a claim: the HTLC holds {held} base units of "
                f"{self._token.symbol}, less than the {locator.amount_base_units} promised. "
                "Broadcasting would publish the preimage in calldata for a payout that reverts, "
                "letting the counterparty take the other leg for nothing. Nothing was sent, so the "
                "preimage is still secret and this is retryable."
            )
        try:
            # Claimant ONLY — not the refundee. A `claim` sweeps the HTLC to the CLAIMANT; the
            # refundee is touched solely by `refund()`, so a frozen refundee cannot make this
            # claim revert. Round 4 rewrote this list without questioning its membership and round
            # 5 caught it from two directions at once: refusing here is a guard refusing valid
            # work, and worse, it hands the counterparty a free unilateral veto — a taker who
            # becomes sanctioned after funding kills the maker's only path to the USDC it has
            # already earned, for nothing. The refundee belongs in the pre-FUND gate, where a
            # freeze really would strand the refund.
            await assert_not_frozen_before_reveal(
                self._rpc,
                self._token,
                htlc_address=locator.contract_address,
                parties={"claimant": locator.claimant},
            )
        except NetworkError as exc:
            # Could not TELL whether anything is frozen. Nothing was sent, so the preimage is
            # still secret and a retry can complete the swap — do not let the caller destroy it.
            raise PreRevealAbort(f"could not check freeze status before revealing: {exc}") from exc
        except ValidationError as exc:
            # An address really IS frozen — but that verdict comes from a SINGLE, unauthenticated
            # read at the tip, and `is_blacklisted` documents itself as defending a failing
            # provider rather than a lying one. Round 3's own argument for the balance lane applies
            # verbatim and was inverted here: a hostile or misconfigured RPC answering `true` once
            # would destroy the only copy of the secret. Blacklists are also reversible, so
            # "the swap cannot complete" is not even durable. Nothing was sent, so keep `p` and let
            # the operator decide; it is memory-only and never persisted, so retention costs
            # nothing.
            raise PreRevealAbort(f"refusing to reveal: {exc}") from exc
        return await super().claim(locator, preimage)

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
        # Refuse a native locator outright. Without this the amount below would be compared in the
        # right unit while the PERSISTED record said "eth" — the producer bug this check now makes
        # unrepresentable rather than merely fixed.
        if not isinstance(locator, Erc20HtlcLocator):
            raise ValidationError(
                f"a token leg requires an Erc20HtlcLocator, got {type(locator).__name__}: a native "
                "locator would persist this swap as chain 'eth' with the amount in the token's base "
                "units, which every reader would take for wei"
            )
        if locator.token_address != self._token.address:
            raise ValidationError(
                f"locator is denominated in {locator.token_address}, not the negotiated "
                f"{self._token.symbol} at {self._token.address}"
            )
        # This leg's payout is an ERC-20 sweep, which calls the TOKEN and never the recipient, so a
        # recipient that would revert on receive has nothing to revert. That makes EIP-7702
        # delegated EOAs — ordinary EOAs, increasingly common — safe to pay here, where the native
        # leg must still refuse them (#478). Every other parent check still runs: runtime code, the
        # immutable binds, the chain assertion.
        await super().verify_funded(
            locator,
            expected_amount_wei=0,
            block_identifier=block_identifier,
            # Admit EIP-7702 delegated EOAs — ordinary EOAs this leg can pay, because an ERC-20
            # sweep calls the token and never the recipient. Arbitrary CONTRACT recipients stay
            # refused: the finding was about delegated EOAs, and a fix should not outgrow it.
            allow_delegated_eoa_recipients=True,
        )
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

        # Bind the contract's OWN amount immutable too. The balance check below is the real
        # protection under sweep semantics, but binding this costs one call and would catch a
        # counterparty deploying a look-alike whose stored amount disagrees with the negotiation —
        # and it stops being merely defensive the moment the contract's payout stops being a sweep.
        on_chain_amount = int(
            await self._rpc.w3.eth.contract(address=locator.contract_address, abi=self._artifact["abi"])
            .functions.amount()
            .call(block_identifier="latest" if block_identifier is None else block_identifier)
        )
        if on_chain_amount != expected_amount_wei:
            raise ValidationError(
                f"the HTLC's stored amount is {on_chain_amount} base units, not the negotiated {expected_amount_wei}"
            )

        held = await balance_of(self._rpc, self._token, locator.contract_address, block_identifier)
        if held < expected_amount_wei:
            raise ValidationError(
                f"funded {self._token.symbol} balance {held} < negotiated {expected_amount_wei} "
                "base units (under-funded)"
            )
