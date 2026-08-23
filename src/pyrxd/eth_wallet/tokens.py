"""Pinned ERC-20 token registry for the EVM counter-leg.

**Addresses are pinned, never resolved by symbol.** Several chains carry both Circle-issued
*native* USDC and a *bridged* ``USDC.e`` minted by a bridge rather than by Circle. They are
distinct contracts with distinct liquidity, and locking the wrong one means the counterparty
receives an asset they did not price. Symbol lookup cannot tell them apart — both say "USDC" —
so this module hard-codes Circle's published addresses per chain id and refuses everything else.

**Decimals are pinned AND verified at runtime.** USDC is 6 decimals where ETH is 18, so a mixup
is a silent 10^12 error. Neither source alone is sufficient: a pinned constant cannot notice a
proxy upgrade, and a runtime-only read has nothing to cross-check against and can be lied to by a
malicious token. Pinning here and asserting against ``decimals()`` at swap start gives each one
something to disagree with — see :func:`assert_token_matches_chain`.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..security.errors import ValidationError

#: Bridged variants, refused BY ADDRESS so a mistake is a named refusal rather than a silent
#: wrong-asset lock. Not Circle-issued; distinct liquidity. Linea is deliberately absent — its
#: bridged USDC.e was upgraded IN PLACE to native USDC at the same address, so that address is
#: now legitimate.
#:
#: Why address-pinning rather than symbol lookup, measured rather than assumed (2026-08-23,
#: read live off each chain): the bridged contracts report ``symbol="USDC"`` and ``decimals=6``
#: — metadata IDENTICAL to Circle's. Nothing in a token's own self-description distinguishes
#: them, so any resolution by symbol would silently pick the wrong asset. The address is the
#: only discriminator, which is why it is the thing that is pinned.
_BRIDGED_LOOKALIKES: dict[str, str] = {
    "0xff970a61a04b1ca14834a43f5de4533ebddb5cc8": "Arbitrum One USDC.e (bridged, not Circle-issued)",
    "0x7f5c764cbc14f9669b88837ca1490cca17c31607": "Optimism USDC.e (bridged, not Circle-issued)",
}


@dataclass(frozen=True)
class Erc20Token:
    """One pinned ERC-20 on one specific chain.

    :param symbol:   display only — never used to resolve an address.
    :param address:  the contract, lowercase hex. THE identity of the asset.
    :param decimals: pinned; cross-checked against the chain at swap start.
    :param chain_id: EIP-155 chain id. A token address means nothing without it — the same
                     string is a different asset on a different chain.
    """

    symbol: str
    address: str
    decimals: int
    chain_id: int
    #: Whether the issuer can freeze addresses. PINNED, not probed: probing means a call that can
    #: fail, and a failed probe is indistinguishable from "not frozen" unless the caller is very
    #: careful — which is exactly the fail-open this field removes. USDC (FiatToken) can freeze.
    has_blacklist: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.address, str) or not self.address.startswith("0x") or len(self.address) != 42:
            raise ValidationError(f"Erc20Token.address must be 0x + 40 hex chars, got {self.address!r}")
        object.__setattr__(self, "address", self.address.lower())
        if not isinstance(self.decimals, int) or isinstance(self.decimals, bool) or not 0 <= self.decimals <= 36:
            raise ValidationError("Erc20Token.decimals must be an int in 0..36")
        if not isinstance(self.chain_id, int) or isinstance(self.chain_id, bool) or self.chain_id <= 0:
            raise ValidationError("Erc20Token.chain_id must be a positive int")

    def base_units(self, whole: str) -> int:
        """Convert a decimal string like ``"12.345678"`` to base units, exactly.

        Takes a **str**, not a float: ``12.345678`` is not representable in binary floating point,
        and a swap amount that is off by one base unit fails the counterparty's funded-amount bind.
        Refuses more precision than the token has rather than rounding it away silently — losing
        the tail is how a caller ends up funding less than they negotiated.
        """
        if not isinstance(whole, str):
            raise ValidationError("base_units takes a decimal STRING; a float cannot represent it exactly")
        text = whole.strip()
        neg = text.startswith("-")
        if neg:
            raise ValidationError("base_units refuses a negative amount")
        int_part, _, frac_part = text.partition(".")
        if not int_part.isdigit() or (frac_part and not frac_part.isdigit()):
            raise ValidationError(f"not a decimal amount: {whole!r}")
        if len(frac_part) > self.decimals:
            raise ValidationError(
                f"{whole!r} has {len(frac_part)} decimal places but {self.symbol} has "
                f"{self.decimals}; refusing rather than truncating a value you meant to send"
            )
        return int(int_part) * 10**self.decimals + int((frac_part or "0").ljust(self.decimals, "0"))


#: Native Circle-issued USDC, keyed by chain id. Source: Circle's own published list
#: (https://developers.circle.com/stablecoins/usdc-contract-addresses), fetched 2026-08-22.
#: VERIFIED 2026-08-23 by reading ``symbol()`` and ``decimals()`` off each chain directly: all
#: nine resolve to a live contract reporting USDC / 6. The doc was not taken on trust.
KNOWN_TOKENS: dict[tuple[str, int], Erc20Token] = {
    ("USDC", 1): Erc20Token("USDC", "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", 6, 1),
    ("USDC", 11155111): Erc20Token("USDC", "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238", 6, 11155111),
    ("USDC", 8453): Erc20Token("USDC", "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", 6, 8453),
    ("USDC", 84532): Erc20Token("USDC", "0x036CbD53842c5426634e7929541eC2318f3dCF7e", 6, 84532),
    ("USDC", 10): Erc20Token("USDC", "0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85", 6, 10),
    ("USDC", 11155420): Erc20Token("USDC", "0x5fd84259d66Cd46123540766Be93DFE6D43130D7", 6, 11155420),
    ("USDC", 42161): Erc20Token("USDC", "0xaf88d065e77c8cC2239327C5EDb3A432268e5831", 6, 42161),
    ("USDC", 421614): Erc20Token("USDC", "0x75faf114eafb1BDbe2F0316DF893fd58CE46AA4d", 6, 421614),
    ("USDC", 59144): Erc20Token("USDC", "0x176211869cA2b568f2A7D4EE941E073a821EE1ff", 6, 59144),
}


def token_for(symbol: str, chain_id: int) -> Erc20Token:
    """The pinned token for ``symbol`` on ``chain_id``; raises for an unknown pair.

    Fail-closed on purpose: an unpinned address is an asset nobody vetted, and the failure mode
    of guessing is locking funds in a token the counterparty did not agree to accept.
    """
    try:
        return KNOWN_TOKENS[(symbol.upper(), chain_id)]
    except KeyError:
        known = sorted({s for s, _ in KNOWN_TOKENS})
        raise ValidationError(
            f"no pinned {symbol!r} on chain id {chain_id}. Known symbols: {known}. Addresses are "
            "pinned per chain from the issuer's own list and never resolved by symbol, because "
            "bridged look-alikes share the symbol and are a different asset."
        ) from None


def token_by_address(address: str, chain_id: int) -> Erc20Token:
    """Reverse lookup, refusing bridged look-alikes by name rather than with a bare 'unknown'."""
    if not isinstance(address, str):
        raise ValidationError("token address must be a str")
    key = address.lower()
    if key in _BRIDGED_LOOKALIKES:
        raise ValidationError(
            f"{address} is {_BRIDGED_LOOKALIKES[key]} — a different contract from Circle's native "
            "USDC, with its own liquidity. Locking it would hand the counterparty an asset they "
            "did not price. Use the native address for this chain."
        )
    for token in KNOWN_TOKENS.values():
        if token.address == key and token.chain_id == chain_id:
            return token
    raise ValidationError(f"no pinned token at {address} on chain id {chain_id}")
