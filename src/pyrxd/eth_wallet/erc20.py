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

#: Only the four reads this module performs. A trimmed ABI is a safety property, not tidiness:
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
        "name": "isBlacklisted",
        "type": "function",
        "stateMutability": "view",
        "inputs": [{"name": "account", "type": "address"}],
        "outputs": [{"name": "", "type": "bool"}],
    },
    {
        "name": "symbol",
        "type": "function",
        "stateMutability": "view",
        "inputs": [],
        "outputs": [{"name": "", "type": "string"}],
    },
]


def _contract(rpc: Any, token: Erc20Token) -> Any:
    web3 = _require_web3()
    return rpc.w3.eth.contract(address=web3.Web3.to_checksum_address(token.address), abi=ERC20_READ_ABI)


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
        return bool(await _contract(rpc, token).functions.isBlacklisted(address).call(block_identifier="latest"))
    except Exception as exc:
        raise NetworkError(
            f"could not determine whether {address} is frozen by {token.symbol}: {exc}. Refusing to "
            "treat an unanswerable question as a safe answer — publishing the preimage on this "
            "assumption is unrecoverable if it is wrong."
        ) from exc


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
    checks = {"htlc contract": htlc_address, **(parties or {})}
    frozen = [f"{role} ({addr})" for role, addr in checks.items() if await is_blacklisted(rpc, token, addr)]
    if frozen:
        raise ValidationError(
            f"refusing to reveal the preimage: {', '.join(frozen)} is frozen by the {token.symbol} "
            "issuer. Revealing now would let the counterparty take their leg while this one cannot "
            "be claimed or refunded. Abandon the swap and refund after the timeout."
        )
