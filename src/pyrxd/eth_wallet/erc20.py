"""Minimal ERC-20 reads for the token counter-leg.

Deliberately small: this is not a general token library. It exposes exactly what the swap needs
— the funded balance, a decimals cross-check, and the blacklist status that decides whether it is
still safe to publish the preimage.

**No write helpers, and no `approve` anywhere.** The HTLC is funded by a plain ``transfer`` to the
per-swap contract address, so no allowance is ever created. That removes the approve race, the
dangling-allowance cleanup, and the reset-to-zero dance non-standard tokens require — a whole
class of bugs that simply cannot occur in a design with no allowances.
"""

from __future__ import annotations

from typing import Any

from ..security.errors import NetworkError, ValidationError
from .htlc_leg import _require_web3
from .tokens import Erc20Token

#: The reads this module performs, plus ``symbol()`` — which nothing calls today and is kept
#: only so an operator-facing tool can identify a token without a second ABI. A trimmed ABI is a safety property, not tidiness:
#: nothing here can accidentally call a mutating function that is not in the list.
ERC20_READ_ABI: list[dict[str, Any]] = [
    {
        "name": "balanceOf",
        "type": "function",
        "stateMutability": "view",
        "inputs": [{"name": "account", "type": "address"}],
        "outputs": [{"name": "", "type": "uint256"}],
    },
    {
        "name": "decimals",
        "type": "function",
        "stateMutability": "view",
        "inputs": [],
        "outputs": [{"name": "", "type": "uint8"}],
    },
    {
        "name": "symbol",
        "type": "function",
        "stateMutability": "view",
        "inputs": [],
        "outputs": [{"name": "", "type": "string"}],
    },
]


def _freeze_abi(token: Erc20Token) -> list[dict[str, Any]]:
    """The freeze predicate, named as THIS issuer named it.

    Not a shared constant, because issuers disagree and the spellings are mutually exclusive —
    measured against the live contracts, USDC answers ``isBlacklisted`` and reverts
    ``isBlackListed``, and USDT does the exact reverse. A single hardcoded name turned the gate
    into a permanent refusal on whichever token it was not written for.

    The name is validated as a Solidity identifier when the token is constructed, so nothing
    free-form reaches the ABI.
    """
    return [
        {
            "name": token.blacklist_fn,
            "type": "function",
            "stateMutability": "view",
            "inputs": [{"name": "account", "type": "address"}],
            "outputs": [{"name": "", "type": "bool"}],
        }
    ]


def _contract(rpc: Any, token: Erc20Token, *, abi: list[dict[str, Any]] | None = None) -> Any:
    web3 = _require_web3()
    return rpc.w3.eth.contract(
        address=web3.Web3.to_checksum_address(token.address), abi=abi if abi is not None else ERC20_READ_ABI
    )


async def balance_of(rpc: Any, token: Erc20Token, owner: str, block_identifier: Any = None) -> int:
    """Token balance of ``owner``, in the token's BASE UNITS.

    Pin ``block_identifier`` to the same checkpoint as the rest of a verification pass. Reading the
    balance at the reorg-able tip while the contract's immutables were read at ``finalized`` would
    let a reorg show funding the finalized state does not have.
    """
    bid = "latest" if block_identifier is None else block_identifier
    try:
        return int(await _contract(rpc, token).functions.balanceOf(owner).call(block_identifier=bid))
    except Exception as exc:  # transport failures are transient by nature
        raise NetworkError(f"could not read {token.symbol} balance of {owner}: {exc}") from exc


async def assert_token_matches_chain(rpc: Any, token: Erc20Token, block_identifier: Any = None) -> None:
    """Cross-check the pinned decimals against the live contract; refuse on disagreement.

    Neither source is trustworthy alone. A pinned constant cannot notice a proxy upgrade — USDC is
    a ``FiatTokenProxy`` whose admin can change all token logic — and a runtime-only read has
    nothing to disagree with, so a malicious or wrong-address token can simply assert whatever it
    likes. Holding both and refusing on mismatch means a wrong pin is caught by the chain and a
    changed chain is caught by the pin.

    A 6-vs-18 disagreement is a 10^12 error in the funded amount, so this refuses rather than
    warns, and it runs at swap start rather than at build time.
    """
    bid = "latest" if block_identifier is None else block_identifier
    try:
        on_chain = int(await _contract(rpc, token).functions.decimals().call(block_identifier=bid))
    except Exception as exc:
        raise NetworkError(f"could not read decimals() for {token.symbol} at {token.address}: {exc}") from exc
    if on_chain != token.decimals:
        raise ValidationError(
            f"{token.symbol} at {token.address} reports decimals={on_chain} but the pinned registry "
            f"says {token.decimals}. Refusing: at these scales the difference is a factor of "
            f"10^{abs(on_chain - token.decimals)} in every amount. Either the pin is wrong for this "
            "chain, or the token proxy was upgraded."
        )


async def is_blacklisted(rpc: Any, token: Erc20Token, address: str) -> bool:
    """Whether ``address`` is frozen by the issuer, read at the **TIP**.

    Deliberately NOT read at a finalized checkpoint, unlike every other verification in this
    stack. A checkpoint lags fresh freezes by minutes, and a freeze that landed since the
    checkpoint is exactly the one this call exists to catch.

    **Raises rather than guessing.** An earlier version caught every exception and returned
    ``False``, so an unreachable, rate-limited or garbage-returning RPC reported "not frozen" —
    a fail-OPEN in the one gate that prevents an unrecoverable loss, and one that fires precisely
    when the caller is already in trouble. Whether the token *can* freeze is now pinned in the
    registry rather than inferred from a call that might fail, so there is no failure mode left to
    confuse with an answer: either we read the flag, or we raise.

    **This defends a FAILING provider, not a LYING one.** The read is single-source. A hostile or
    compromised RPC that returns ``False`` for a genuinely frozen address is not caught here, and
    this gate guards the one unrecoverable outcome — a frozen HTLC bricks claim *and* refund. That
    residual is the same single-provider trust the finality path documents, and a multi-source
    quorum is the fix if this corridor ever carries real value.
    """
    if not token.has_blacklist:
        # Pinned capability, not a probe: a token that cannot freeze cannot freeze this swap.
        return False
    try:
        contract = _contract(rpc, token, abi=_freeze_abi(token))
        fn = getattr(contract.functions, token.blacklist_fn)
        return bool(await fn(address).call(block_identifier="latest"))
    except Exception as exc:
        raise NetworkError(
            f"could not determine whether {address} is frozen by {token.symbol}: {exc}. Refusing to "
            "treat an unanswerable question as a safe answer: acting on a wrong 'not frozen' is "
            "unrecoverable, whether that act is funding the contract or publishing the preimage."
        ) from exc


async def assert_not_frozen_before_funding(
    rpc: Any,
    token: Erc20Token,
    *,
    claimant: str,
    refundee: str,
    htlc_address: str | None,
) -> None:
    """The pre-FUND gate. Refuse to pay into a position that cannot be exited.

    :func:`assert_not_frozen_before_reveal` protects the moment the preimage becomes public. This
    one protects the earlier moment nothing was watching at all: **paying in**. They check
    different addresses on purpose, because a different transfer is at risk in each.

    * The **refundee** is why this function exists, and why it is a required argument rather than
      an entry in a dict. A ``claim`` never touches the refundee, so the reveal gate deliberately
      ignores it — correctly, since refusing there would block honest work and hand the
      counterparty a free unilateral veto. But ``refund()`` *pays* the refundee, and a frozen
      refundee makes it revert. Funding a leg whose refundee is already frozen buys a position
      with no exit: if the counterparty simply never claims, the tokens stay in the contract for
      good. Until this gate existed that case was checked in **no** code path — the docs claimed
      a "pre-fund gate" that had never been written.
    * The **claimant**, if frozen, cannot receive a ``claim`` at all, so the swap can only end in
      a refund. Nothing is lost, but a deploy, a transfer and a full timelock are spent on a swap
      that could never have completed.
    * The **HTLC contract**, once it exists, is the unrecoverable case — freezing it reverts
      ``claim`` *and* ``refund``, with no timeout that rescues the tokens. ``htlc_address`` is
      ``None`` only in the window before the contract is deployed. It is a REQUIRED keyword so
      that omitting it is impossible and passing ``None`` is a decision someone made.

    This is a **narrower** promise than the reveal gate makes. It reads the tip once; a freeze
    landing between this check and the transfer is unmitigated, exactly as check-then-reveal is
    itself a race. It removes the case where the freeze was already there and nobody looked.

    Raises:
        NetworkError: the freeze status could not be READ — never treated as "not frozen".
        ValidationError: an address is frozen; do not fund.
    """
    for role, addr in (("claimant", claimant), ("refundee", refundee)):
        if not isinstance(addr, str) or not addr:
            raise ValidationError(f"{role} address is required by the pre-fund freeze gate")
    # Ordered so the report names the unrecoverable address first when several are frozen.
    checks = [] if htlc_address is None else [("htlc contract", htlc_address)]
    checks += [("claimant", claimant), ("refundee", refundee)]
    frozen = [f"{role} ({addr})" for role, addr in checks if await is_blacklisted(rpc, token, addr)]
    if not frozen:
        return
    raise ValidationError(
        f"refusing to fund: {', '.join(frozen)} is frozen by the {token.symbol} issuer. "
        "A frozen refundee cannot be paid by refund(), and a frozen contract can be paid by "
        "neither refund() nor claim() — so tokens sent now may never come back. NO TOKENS HAVE "
        "MOVED; this gate always runs before the transfer. (On a fresh fund the deploy gas may "
        "already be spent — that is the cost of finding out, and it is not the value at risk.) "
        "Renegotiate with an unfrozen address, or use a token whose issuer cannot freeze."
    )


async def assert_not_frozen_before_reveal(
    rpc: Any,
    token: Erc20Token,
    *,
    htlc_address: str,
    parties: dict[str, str] | None = None,
) -> None:
    """The pre-reveal gate. Refuse to publish the preimage into a freeze.

    Call this immediately before the action that makes the preimage public. Once it is public the
    counterparty can take their leg, so a freeze landing after that point is a one-sided loss with
    no recovery; before it, abandoning the swap costs only fees.

    ``htlc_address`` is a REQUIRED, separate parameter rather than an entry in a free-form dict.
    It is the most dangerous address to miss: measured against the real USDC contract on a mainnet
    fork, freezing the CONTRACT strands the funds permanently — ``claim`` reverts *and* ``refund``
    reverts, with no timeout to rescue them. A caller who passed only the two party addresses used
    to skip that case while appearing to run the gate; now it cannot be omitted.

    This narrows the window; it does not close it. Check-then-reveal is itself a race, and a freeze
    landing after the reveal is unmitigated by construction. It is a seatbelt, not a fix, and the
    residual belongs in the disclosure rather than in a claim that the corridor is trustless.

    Raises:
        NetworkError: the freeze status could not be READ. Deliberately not treated as "not
            frozen" — see :func:`is_blacklisted`.
        ValidationError: some address is frozen; do not reveal.
    """
    if not isinstance(htlc_address, str) or not htlc_address:
        raise ValidationError("htlc_address is required: it is the freeze that cannot be refunded")
    # Pairs, not a dict merge. `{"htlc contract": htlc_address, **parties}` let a caller passing
    # that same key OVERWRITE the mandatory address — silently defeating the guarantee two
    # paragraphs above that it cannot be omitted. Nothing does that today; the point is that it
    # would not have been noticed.
    checks = [("htlc contract", htlc_address), *sorted((parties or {}).items())]
    frozen = [f"{role} ({addr})" for role, addr in checks if await is_blacklisted(rpc, token, addr)]
    if frozen:
        raise ValidationError(
            f"refusing to reveal the preimage: {', '.join(frozen)} is frozen by the {token.symbol} "
            "issuer. Revealing now would let the counterparty take their leg while this one cannot "
            "be claimed or refunded. Abandon the swap and refund after the timeout."
        )
