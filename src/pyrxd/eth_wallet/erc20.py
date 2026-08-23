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
    checkpoint is exactly the one this call exists to catch. Reading stale here would defeat the
    entire purpose.

    Tokens without a blacklist simply do not have this function; a revert is reported as
    "not blacklisted" rather than an error, because a token that cannot freeze cannot freeze this
    swap either.
    """
    try:
        return bool(await _contract(rpc, token).functions.isBlacklisted(address).call(block_identifier="latest"))
    except Exception:  # includes "function does not exist" on non-freezable tokens
        return False


async def assert_not_frozen_before_reveal(rpc: Any, token: Erc20Token, *, addresses: dict[str, str]) -> None:
    """The pre-reveal gate. Refuse to publish the preimage into a freeze.

    Call this immediately before the action that makes the preimage public. Once it is public the
    counterparty can take their leg, so a freeze landing after that point is a one-sided loss with
    no recovery; before it, abandoning the swap costs only fees.

    ``addresses`` maps a role name to an address and **must include the HTLC contract itself**, not
    just the two parties. Measured against the real USDC contract on a mainnet fork: freezing the
    contract address strands the funds permanently — ``claim`` reverts *and* ``refund`` reverts, so
    no timeout rescues it.

    This narrows the window; it does not close it. Check-then-reveal is itself a race, and a freeze
    landing after the reveal is unmitigated by construction. It is a seatbelt, not a fix, and the
    residual belongs in the disclosure rather than in a claim that the corridor is trustless.
    """
    frozen = [f"{role} ({addr})" for role, addr in addresses.items() if await is_blacklisted(rpc, token, addr)]
    if frozen:
        raise ValidationError(
            f"refusing to reveal the preimage: {', '.join(frozen)} is frozen by the {token.symbol} "
            "issuer. Revealing now would let the counterparty take their leg while this one cannot "
            "be claimed or refunded. Abandon the swap and refund after the timeout."
        )
