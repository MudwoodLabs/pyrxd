"""ERC-20 (USDC) counter-chain leg — the token sibling of :class:`EthHtlcContractLeg`.

**A subclass, not a fork, and not an edit.** The native leg has moved real value on mainnet, so
this adds behaviour without changing a line of it. ``refund``, ``fetch_claim_artifacts``,
``assert_claim_provenance``, ``is_final`` and ``claim_finality_verdict`` are inherited
**unchanged**, which works because ``Erc20Htlc.sol`` was deliberately given the same
``claim(bytes32)`` / ``refund()`` signatures and the same ``Claimed(bytes32)`` event with the
preimage un-indexed. Secret recovery therefore needs no token-specific code at all.

``fund``, ``verify_funded`` AND ``claim`` are overridden. An earlier version of this paragraph said
``claim`` was inherited unchanged; it is not, and the difference matters to anyone reading this to
decide how much of the audited native reveal path applies. The override adds two PRE-REVEAL gates —
a funded-balance re-read and the issuer-freeze check — both of which exist because broadcasting
``claim(preimage)`` publishes the secret, and a token leg can be short or frozen in ways the native
leg cannot. It delegates to ``super().claim`` for the broadcast itself.

**What genuinely differs is funding.** A payable constructor holds ETH; it cannot pull a token,
because ``transferFrom`` needs an allowance granted to an address that does not exist until the
deploy lands. So funding is two transactions — deploy, then a plain ``transfer`` — and
"deployed" stops implying "funded". Nothing in the protocol relied on that implication: the
coordinator already documents that an HTLC address commits to immutables, not to the funded
balance, and it is the explicit amount bind that catches a wrong amount.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from ..security.errors import NetworkError, PreRevealAbort, ValidationError
from ..security.reveal import watching_for_reveal
from .erc20 import (
    assert_not_frozen_before_funding,
    assert_not_frozen_before_reveal,
    assert_token_matches_chain,
    balance_of,
)
from .htlc_leg import EthHtlcContractLeg, _require_web3
from .locator import Erc20HtlcLocator, EthHtlcLocator, PendingDeploy, normalise_tx_hash
from .multi_rpc import read_contract
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


def _create_address(sender: str, nonce: int) -> str:
    """The CREATE address for ``sender`` at ``nonce`` — keccak(rlp([sender, nonce]))[12:].

    Derivable from two values the deployer already holds, which is why trusting an endpoint to
    report it was never necessary. Minimal RLP: a 20-byte address is a 0x94-prefixed string, and
    the nonce is either the empty string (0), a single byte below 0x80, or a length-prefixed
    big-endian integer.
    """
    from eth_utils import keccak, to_checksum_address

    addr = bytes.fromhex(sender[2:] if sender.startswith("0x") else sender)
    if len(addr) != 20:
        raise ValidationError(f"sender must be a 20-byte address, got {len(addr)}")
    if nonce == 0:
        n = b"\x80"
    elif nonce < 0x80:
        n = bytes([nonce])
    else:
        b = nonce.to_bytes((nonce.bit_length() + 7) // 8, "big")
        n = bytes([0x80 + len(b)]) + b
    payload = b"\x94" + addr + n
    return to_checksum_address(keccak(bytes([0xC0 + len(payload)]) + payload)[12:])


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
        self,
        *,
        hashlock: bytes,
        claimant: str,
        refundee: str,
        timeout: int,
        amount_wei: int,
        on_deploy: Callable[[str, str], Awaitable[None]] | None = None,
        resume_from: PendingDeploy | None = None,
        push_nonce: int | None = None,
        on_push_nonce: Callable[[int], Awaitable[None]] | None = None,
    ) -> EthHtlcLocator:
        """Deploy the HTLC, push the tokens into it, and only then return a locator.

        ``amount_wei`` is the ABC's parameter name and is retained so this stays substitutable for
        the native leg — but the VALUE is in the token's **base units** (USDC has 6 decimals, not
        18). The name is the ABC's, the unit is the token's; the durable record disambiguates by
        locator type, not by this argument.

        **Returning only after the tokens land is the contract, not an optimisation.** The ABC
        promises a funded locator, and the counterparty's ``verify_funded`` is what protects them.
        A crash between the two transactions never yields a locator: either the tokens are still
        in the funder's wallet (crashed before the push) or they sit in an abandoned contract
        recoverable by ``refund`` after the timeout (crashed after it).

        ``refund`` can only recover the second case if the operator still KNOWS THE ADDRESS, and
        a CREATE address depends on the deployer's nonce — it appears nowhere until this deploy
        receipt returns. Saying the value is "recoverable" while its only reference was an
        exception string was not true in any operational sense. ``on_deploy`` is awaited with the
        deployed address after the deploy CONFIRMS and strictly BEFORE the token push, so the
        caller can make it durable first; the coordinator passes a hook that writes it to the
        swap record. A caller that passes nothing keeps the old behaviour.

        ``resume_from`` completes a fund that was interrupted, using the contract already deployed
        instead of deploying a second one. Two things make that safe, and both are load-bearing:

        * The existing contract's IMMUTABLES are verified against these arguments before anything
          is sent to it. A resume is driven by a durable record, and sending tokens to an address
          out of a record without re-deriving what it actually is would let a corrupted or
          tampered record redirect the funds anywhere.
        * The balance already there is READ FIRST and only the shortfall is sent. A lost receipt —
          the push landed but the process died before seeing it — is indistinguishable from a push
          that never happened, and re-sending the full amount on that reading would double-fund.
          Reading the chain makes the two cases the same case.
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
        if resume_from is not None:
            address = checksum(resume_from.address)
            deploy_hash = resume_from.deploy_tx_hash
            # PROVE it is ours before sending anything to it. `verify_funded` runs the full
            # immutable binding (hashlock, claimant, refundee, timeout, token, AMOUNT) plus the
            # runtime-code and recipient checks; `require_balance=False` waives the balance floor
            # and nothing else, because a half-finished fund is legitimately short.
            #
            # It previously passed `expected_amount_wei=0` to mean "waive the balance". That was
            # wrong and made the resume DEAD: the same parameter also binds the contract's `amount`
            # IMMUTABLE, which is the positive negotiated amount and can never equal 0, so every
            # resume raised before a token moved. The amount bind is exactly the check a resume
            # most needs — it proves the deployed contract was constructed for THIS price — so it
            # must be asserted, not waived. One parameter serving two checks is what hid this.
            await self.verify_funded(
                self._locator_for(
                    address=address,
                    deploy_hash=deploy_hash,
                    hashlock=hashlock,
                    claimant=checksum(claimant),
                    refundee=checksum(refundee),
                    timeout=timeout,
                    amount_wei=amount_wei,
                ),
                expected_amount_wei=int(amount_wei),
                require_balance=False,
            )
        else:
            # THE FRESH-FUND BRANCH ONLY, and that scoping is the whole subtlety. This is the CHEAP
            # copy of the gate — it cannot name the contract, because on a fresh fund the contract
            # does not exist until the deploy below — and it is here so a doomed swap costs nothing
            # rather than a 412k-gas deploy. The load-bearing copy runs in `_push_and_bind`, inside
            # the branch that actually moves tokens.
            #
            # A first version ran before this `if`, on RESUMES too, passing the known contract
            # address. That refused honest work: a resume whose push already landed has nothing
            # left to send and nothing left to risk — it is calling `fund` only to recover its
            # locator. Refusing it because the refundee was frozen would leave a taker whose tokens
            # ARE in the contract unable to record the fund that completed, while un-funding
            # nothing. Same reasoning, and the same scoping, as the in-flight guard below: refuse
            # only when something is about to be SENT.
            await assert_not_frozen_before_funding(
                self._rpc,
                self._token,
                claimant=checksum(claimant),
                refundee=checksum(refundee),
                htlc_address=None,
            )
            address, deploy_hash = await self._deploy(
                web3=web3,
                hashlock=hashlock,
                claimant=claimant,
                refundee=refundee,
                timeout=timeout,
                amount_wei=amount_wei,
                on_deploy=on_deploy,
            )
        return await self._push_and_bind(
            resuming=resume_from is not None,
            push_nonce=push_nonce,
            on_push_nonce=on_push_nonce,
            web3=web3,
            address=address,
            deploy_hash=deploy_hash,
            hashlock=hashlock,
            claimant=claimant,
            refundee=refundee,
            timeout=timeout,
            amount_wei=amount_wei,
        )

    async def _deploy(self, *, web3, hashlock, claimant, refundee, timeout, amount_wei, on_deploy):
        """Deploy a fresh HTLC and report it before any value moves. Returns (address, tx hash)."""
        checksum = web3.Web3.to_checksum_address
        c = self._rpc.write_w3.eth.contract(abi=self._artifact["abi"], bytecode=self._artifact["bytecode"])
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
        # DERIVE the address; do not accept the endpoint's word for it. A CREATE address is
        # keccak(rlp([sender, nonce]))[12:] — both inputs are ours, so this needs no second
        # endpoint and no trust at all.
        #
        # This is the one read that decides WHERE THE TOKENS GO, and it was the last single-source
        # read on the funding path: `wait_receipt` is primary-only by design, and the quorum'd
        # `get_transaction_receipt` is never called during a fund. A lying or MITM'd primary that
        # altered only `contractAddress` redirected the entire counter leg — and every downstream
        # check still passed, because the tokens really were at the address it named.
        derived = _create_address(self._account_address(), int(built["nonce"]))
        reported = checksum(receipt["contractAddress"])
        if derived != reported:
            raise ValidationError(
                f"deploy receipt names contract {reported} but CREATE from {self._account_address()} "
                f"at nonce {int(built['nonce'])} is {derived}. Refusing: this is the read that "
                "decides where the tokens go, and it is derivable rather than trusted."
            )
        address = derived

        # Make the address durable BEFORE the tokens move. This is the only ordering that helps:
        # after the push, a crash leaves real value in a contract whose address was never written
        # down. Awaited, not fire-and-forget — if the caller cannot persist it, we must not push.
        if on_deploy is not None:
            await on_deploy(address, normalise_tx_hash(deploy_hash))
        return address, deploy_hash

    async def _push_and_bind(
        self,
        *,
        resuming,
        push_nonce,
        on_push_nonce,
        web3,
        address,
        deploy_hash,
        hashlock,
        claimant,
        refundee,
        timeout,
        amount_wei,
    ):
        """Top the HTLC up to the promised amount and return its locator."""
        checksum = web3.Web3.to_checksum_address
        # READ FIRST. What is already there decides what to send: on a fresh deploy this is 0 and
        # the shortfall is the whole amount, while on a resume it may be anything from 0 to the
        # full amount (a push whose receipt was lost). Sending `amount_wei` unconditionally would
        # double-fund exactly the case a resume exists to handle.
        # MAX here, and ONLY here. Everywhere else this balance is compared against a floor, where
        # MIN is conservative. This site SUBTRACTS it (`shortfall = amount - held`), which inverts
        # the direction: an under-reported balance OVER-computes what must be sent. One lagging
        # replica reporting 0 against a fully-funded HTLC yields a shortfall of the whole amount and
        # a second full transfer — which `claim` then sweeps entirely to the counterparty. The nonce
        # pin catches it when one exists; the direction should not depend on that.
        held = await balance_of(self._rpc, self._token, address, combine=max)
        # A balance read at `latest` CANNOT see a transfer still sitting in the mempool, while the
        # nonce used to build the next one comes from `pending` — so a resume inside the receipt
        # wait would read 0, compute the full shortfall, and send a SECOND transfer at the next
        # nonce. Both mine; the HTLC ends up holding twice the negotiated amount, and claim sweeps
        # the whole balance to the counterparty. "Reading the chain collapses the two cases into
        # one" was true only for a push that had already mined. If this sender has anything in
        # flight, the balance is not yet a fact and nothing may be sent against it.
        shortfall = int(amount_wei) - int(held)
        # RESUME ONLY, and only when something is actually about to be SENT. Two scopings, each
        # closing a way this refused honest work:
        #
        # * On a fresh deploy the address was created by the transaction that just confirmed, so no
        #   transfer to it can be in flight — the hazard is structurally impossible, and refusing
        #   would abort a legitimate fund AFTER the deploy had spent gas and consumed H.
        # * When the shortfall is already zero the push whose receipt was lost has MINED and there
        #   is nothing left to send. Refusing there strands a taker whose fund actually completed:
        #   its USDC is claimable with `p` while its own coordinator will not acknowledge the fund,
        #   and a stuck transaction on that key keeps `pending != latest` indefinitely.
        #
        # The rationale — "sending against this reading could fund the HTLC twice" — only bites
        # when something is being sent.
        sender = self._account_address()
        # STOLEN-PIN CHECK FIRST — it is the more specific diagnosis. Running it after the
        # in-flight guard let that guard fire on the same state and report a NEGATIVE count of
        # in-flight transactions, hiding the real cause.
        if resuming and shortfall > 0 and push_nonce is not None:
            settled = await self._rpc.get_transaction_count(self._account_address(), "latest")
            if settled > int(push_nonce):
                raise NetworkError(
                    f"the pinned push nonce {push_nonce} has already been consumed by another "
                    f"transaction from this key (its settled nonce is {settled}) and the HTLC "
                    f"still holds {held} of {amount_wei}. Re-pinning cannot be done safely: two "
                    "resumers could pick different nonces and both land, funding the HTLC twice. "
                    "Use a funding key dedicated to one swap. Refund after the timeout."
                )

        # `pending > latest`, NOT `!=`. A pending nonce BELOW the settled one is not "transactions
        # in flight" — it means our view of the account is stale or the pinned slot was consumed by
        # something else, and reporting `pending - latest` there printed a NEGATIVE count while
        # masking the real diagnosis below.
        _check_inflight = resuming and shortfall > 0
        pending_nonce = await self._rpc.get_transaction_count(sender, "pending") if _check_inflight else 0
        latest_nonce = await self._rpc.get_transaction_count(sender, "latest") if _check_inflight else 0
        if resuming and shortfall > 0 and pending_nonce > latest_nonce:
            raise NetworkError(
                f"{pending_nonce - latest_nonce} transaction(s) from {sender} are still in flight "
                f"(nonce pending={pending_nonce}, latest={latest_nonce}), so the HTLC balance "
                f"{held} is not settled. One of them may be the token push for this very swap; "
                "sending against this reading could fund the HTLC twice. Wait for them to mine."
            )
        if shortfall > 0:
            # THE GUARD, and it sits INSIDE the branch that moves the value rather than beside it.
            # `address` is known by now, which the pre-deploy check could not assume, and it is the
            # address whose freeze has no recovery at all — a frozen HTLC reverts claim AND refund.
            # Scoped to `shortfall > 0` deliberately: when there is nothing left to send there is
            # nothing to protect, and refusing a resume whose push already landed would strand a
            # taker whose fund actually completed.
            await assert_not_frozen_before_funding(
                self._rpc,
                self._token,
                claimant=checksum(claimant),
                refundee=checksum(refundee),
                htlc_address=address,
            )
            # --- push the tokens in. No approve, no transferFrom. ---
            token_c = self._rpc.write_w3.eth.contract(address=checksum(self._token.address), abi=_TRANSFER_ABI)
            push_tx = await self._base_tx(gas=_TOKEN_TRANSFER_GAS)
            # PIN THE NONCE, and reuse the pin on every retry. Measured on 2026-08-24: a second
            # transaction at an already-used nonce is rejected — "nonce too low" once mined,
            # "transaction already imported" while pending. That rejection is what delivers the
            # value exactly once, and being a property of the chain it holds across hosts,
            # filesystems and a copied keys directory, unlike the `flock`.
            #
            # WHAT THIS DOES NOT DO, corrected (#515). This used to add that a higher-priced
            # transaction "REPLACES rather than adds — so ... a resume racing its own still-pending
            # push, deliver[s] the value exactly once". The replacement half is never reached:
            #
            #   1. the in-flight guard above refuses whenever `pending > latest`, which IS the
            #      racing-its-own-push case, so the resume stops before building anything; and
            #   2. even reaching it, this rebuild would not be a valid replacement. EIP-1559 needs
            #      BOTH `maxFeePerGas` and `maxPriorityFeePerGas` raised (geth: >= 10%), and
            #      `_base_tx`'s `basefee_headroom` scales only the basefee share and explicitly
            #      "never the tip". An equal-tip resend is what produced the measured
            #      "transaction already imported".
            #
            # Exactly-once here is the chain REJECTING the duplicate, not this code replacing it.
            # A real bumped-replacement path also needs the push tx HASH to be durable so the
            # pending transaction's fees can be read back; only `pending_push_nonce` is persisted
            # today. See #515 before claiming replacement anywhere.
            #
            # The pin must be DURABLE before the broadcast or a retry cannot reuse it, which is the
            # whole mechanism. See the design note under docs/solutions/design-decisions/.
            if push_nonce is not None:
                push_tx = {**push_tx, "nonce": int(push_nonce)}
            elif on_push_nonce is not None:
                await on_push_nonce(int(push_tx["nonce"]))
            push_built = await token_c.functions.transfer(address, shortfall).build_transaction(push_tx)
            push_hash = await self._sign_and_send(push_built)
            push_receipt = await self._rpc.wait_receipt(push_hash)
            if int(push_receipt.get("status", 0)) != 1:
                raise NetworkError(
                    f"token transfer into {address} reverted (status != 1): {push_hash}. The HTLC "
                    f"holds {held} base units and needed {shortfall} more; the remainder is still "
                    "in the sender's wallet."
                )

        # Confirm from chain state rather than trusting the receipt: a fee-on-transfer or otherwise
        # non-standard token can succeed while delivering less than it was asked to.
        # QUORUM-th, not MIN. This asks "did enough actually arrive", and the threat it exists for
        # is a fee-on-transfer token that under-delivers — which every endpoint reports alike. MIN
        # instead let ONE lagging replica declare a correctly funded HTLC short and abort the
        # taker's own swap, stranding the tokens until the timeout. The counterparty verifies this
        # independently before locking, so erring toward refusal here buys nothing it does not
        # already have.
        from pyrxd.eth_wallet.multi_rpc import quorum_combiner

        landed = await balance_of(self._rpc, self._token, address, combine=quorum_combiner(self._rpc))
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
        return self._locator_for(
            address=address,
            deploy_hash=deploy_hash,
            hashlock=hashlock,
            claimant=checksum(claimant),
            refundee=checksum(refundee),
            timeout=timeout,
            amount_wei=amount_wei,
        )

    def _locator_for(self, *, address, deploy_hash, hashlock, claimant, refundee, timeout, amount_wei):
        """The single producer of this leg's locator.

        `Erc20HtlcLocator`, NOT the parent. Returning the parent made the whole chain-tag mechanism
        dead on the write side: the record serialised as `chain: "eth"` carrying 6-decimal base
        units in a field every reader treats as wei — the 10^12 error the tag exists to prevent, as
        the DEFAULT behaviour of a real token swap. It was caught by review, not by tests, because
        the tests built locators by hand and nothing exercised the producer. Keeping ONE producer
        is what stops the resume path from becoming a second place to get this wrong.
        """
        return Erc20HtlcLocator(
            chain_id=self._chain_id,
            contract_address=address,
            deploy_tx_hash=deploy_hash if deploy_hash.startswith("0x") else "0x" + deploy_hash,
            hashlock="0x" + bytes(hashlock).hex(),
            claimant=claimant,
            refundee=refundee,
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
        watching_for_reveal()  # this leg's extra pre-reveal reads run before super().claim (#480)
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
        self,
        locator: EthHtlcLocator,
        *,
        expected_amount_wei: int,
        block_identifier: Any = None,
        require_balance: bool = True,
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
        _bid = "latest" if block_identifier is None else block_identifier

        def _htlc_immutable(name: str):
            # Rebuilt per endpoint so a multi-source rpc gets a real quorum rather than one
            # endpoint's word. Identity reads: which asset the contract holds, and how much it
            # was constructed for, are not quantities to average.
            def _call(r):
                c = r.w3.eth.contract(address=locator.contract_address, abi=self._artifact["abi"])
                return getattr(c.functions, name)().call(block_identifier=_bid)

            return _call

        on_chain_token = await read_contract(
            self._rpc, _htlc_immutable("token"), label=f"{locator.contract_address}.token()"
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
            await read_contract(self._rpc, _htlc_immutable("amount"), label=f"{locator.contract_address}.amount()")
        )
        if on_chain_amount != expected_amount_wei:
            raise ValidationError(
                f"the HTLC's stored amount is {on_chain_amount} base units, not the negotiated {expected_amount_wei}"
            )

        held = await balance_of(self._rpc, self._token, locator.contract_address, block_identifier)
        if require_balance and held < expected_amount_wei:
            raise ValidationError(
                f"funded {self._token.symbol} balance {held} < negotiated {expected_amount_wei} "
                "base units (under-funded)"
            )
