"""Durable locator for a funded ETH HTLC — the ETH sibling of ``BtcHtlcLocator``.

Captures everything needed to claim or refund a deployed+funded ``EthHtlc`` contract,
and to re-derive/verify it independently. Like the BTC locator it carries NO secret
(only the hashlock ``H``); losing it strands the ETH the same way losing the BTC locator
strands the BTC, so it is JSON-serialisable for crash-recovery.

The locator is also the funding-verification anchor: ``claimant``/``refundee``/``timeout``
/``hashlock`` are the contract immutables the taker's pre-fund gate reads back on-chain
(via view calls / decoded constructor args) and compares to the negotiated terms before
the maker is told to lock RXD.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import ClassVar

from pyrxd.security.errors import ValidationError

__all__ = ["Erc20HtlcLocator", "EthHtlcLocator", "PendingDeploy", "check_hex_addr", "normalise_tx_hash"]


#: The ONLY accepted spelling of an EVM address anywhere in this package. Anchored, ASCII-only.
#:
#: `bytes.fromhex` is NOT a substitute and was the round-5 hole: it silently skips ASCII
#: whitespace, so "0x" + "ab"*19 + "  " passed the length check (42 chars) AND the hex round-trip
#: while decoding to NINETEEN bytes. The failure was then deferred to `to_checksum_address` at
#: first on-chain use — far from the construction that introduced it, and for the field that IS
#: the identity of the asset being swapped. Three modules had independently copied that check.
_HEX_ADDR_RE = re.compile(r"0x[0-9a-fA-F]{40}\Z")


def normalise_tx_hash(val: str) -> str:
    """`0x`-prefix a transaction hash, idempotently.

    A node may return a hash with or without the prefix, and the two writers of the durable deploy
    handle disagreed about it: the locator producer normalised, while the record hook passed it
    straight through to a field that REQUIRES the prefix. Reading the code, that looked cosmetic.
    On a real chain it raised mid-fund, AFTER the contract was deployed — the first defect this
    corridor's end-to-end run caught that nine rounds of review did not.
    """
    if not isinstance(val, str) or not val:
        raise ValidationError("transaction hash must be a non-empty string")
    return val if val.startswith("0x") else "0x" + val


def check_hex_addr(name: str, val: str) -> str:
    """Validate an EVM address strictly, or raise :class:`ValidationError`.

    Canonical for the whole package — `tokens.Erc20Token` and `swap_state.NegotiatedTerms` both
    call this rather than keeping their own copy, so a hole can only ever exist in one place.
    """
    if not isinstance(val, str):
        raise ValidationError(f"{name} must be a 0x-prefixed 20-byte hex address")
    if not _HEX_ADDR_RE.fullmatch(val):
        raise ValidationError(f"{name} must be a 0x-prefixed 20-byte hex address, got {val!r}")
    return val


def _check_hex_addr(name: str, val: str) -> str:
    return check_hex_addr(name, val)


@dataclass(frozen=True)
class PendingDeploy:
    """An HTLC that exists on chain but is not yet an accepted funded locator.

    The handle a resume needs, and the smallest thing that makes one possible. A CREATE address
    depends on the deployer's nonce, so it is unknowable until the deploy receipt returns; the
    deploy tx hash is equally unrecoverable afterwards and the watchtower's claim-status path reads
    it. Persisting both is what turns "value on chain that nothing references" into "a fund that
    can be completed".
    """

    address: str
    deploy_tx_hash: str

    def __post_init__(self) -> None:
        check_hex_addr("PendingDeploy.address", self.address)
        if not isinstance(self.deploy_tx_hash, str) or not self.deploy_tx_hash.startswith("0x"):
            raise ValidationError("PendingDeploy.deploy_tx_hash must be a 0x-prefixed hex hash")
        object.__setattr__(self, "address", self.address.lower())


@dataclass(frozen=True)
class EthHtlcLocator:
    """Durable retained state for a funded ETH HTLC (must NOT be lost — strands ETH).

    Attributes
    ----------
    chain_id:
        EIP-155 chain id (Sepolia = 11155111, mainnet = 1). Pins which network this
        locator belongs to; a claim/refund built for the wrong chain is rejected by the
        node via EIP-155 signing, and the leg refuses a chain_id mismatch up front.
    contract_address:
        The deployed ``EthHtlc`` instance (deploy-per-swap).
    deploy_tx_hash:
        The funding/deploy tx hash (the contract is funded in its payable constructor).
    hashlock:
        ``H = sha256(p)`` (hex, 0x-prefixed, 32 bytes). The ONLY secret-derived value
        here; ``p`` itself is never stored.
    claimant:
        Maker address — receives ETH on ``claim(p)``.
    refundee:
        Taker address — receives ETH on ``refund()`` after ``timeout``.
    timeout:
        Absolute unix deadline (matches the contract immutable).
    amount_wei:
        The funded value (verified == negotiated before the maker reveals p).
    """

    #: The wire tag this locator serialises under inside ``counterchain_locator``.
    #: ``SwapRecord.to_dict`` reads THIS rather than branching on the type, so a new locator
    #: variant carries its own tag and cannot be silently mis-serialised by a missing branch —
    #: which for a token locator would mean an older reader interpreting base units as wei.
    CHAIN_TAG: ClassVar[str] = "eth"

    chain_id: int
    contract_address: str
    deploy_tx_hash: str
    hashlock: str
    claimant: str
    refundee: str
    timeout: int
    amount_wei: int

    def __post_init__(self) -> None:
        if not isinstance(self.chain_id, int) or isinstance(self.chain_id, bool) or self.chain_id <= 0:
            raise ValidationError("chain_id must be a positive int")
        _check_hex_addr("contract_address", self.contract_address)
        _check_hex_addr("claimant", self.claimant)
        _check_hex_addr("refundee", self.refundee)
        if not isinstance(self.deploy_tx_hash, str) or not self.deploy_tx_hash.startswith("0x"):
            raise ValidationError("deploy_tx_hash must be a 0x-prefixed hex hash")
        if not isinstance(self.hashlock, str) or not self.hashlock.startswith("0x") or len(self.hashlock) != 66:
            raise ValidationError("hashlock must be a 0x-prefixed 32-byte hex string")
        try:
            bytes.fromhex(self.hashlock[2:])
        except ValueError as exc:
            raise ValidationError("hashlock is not valid hex") from exc
        for name, val in (("timeout", self.timeout), ("amount_wei", self.amount_wei)):
            if not isinstance(val, int) or isinstance(val, bool) or val < 0:
                raise ValidationError(f"{name} must be a non-negative int")
        if self.amount_wei == 0:
            raise ValidationError("amount_wei must be > 0 (the contract rejects a zero-value deploy)")

    @property
    def hashlock_bytes(self) -> bytes:
        return bytes.fromhex(self.hashlock[2:])

    def to_dict(self) -> dict:
        """JSON-serialisable; contains NO preimage (only the hashlock)."""
        return {
            "chain_id": self.chain_id,
            "contract_address": self.contract_address,
            "deploy_tx_hash": self.deploy_tx_hash,
            "hashlock": self.hashlock,
            "claimant": self.claimant,
            "refundee": self.refundee,
            "timeout": self.timeout,
            "amount_wei": self.amount_wei,
        }

    @classmethod
    def from_dict(cls, d: dict) -> EthHtlcLocator:
        try:
            return cls(
                chain_id=d["chain_id"],
                contract_address=d["contract_address"],
                deploy_tx_hash=d["deploy_tx_hash"],
                hashlock=d["hashlock"],
                claimant=d["claimant"],
                refundee=d["refundee"],
                timeout=d["timeout"],
                amount_wei=d["amount_wei"],
            )
        except KeyError as exc:
            raise ValidationError(f"EthHtlcLocator.from_dict missing key: {exc}") from exc


@dataclass(frozen=True)
class Erc20HtlcLocator(EthHtlcLocator):
    """Durable retained state for a funded **ERC-20** HTLC.

    **A subclass on purpose.** Six of the seven ``isinstance(..., EthHtlcLocator)`` sites in the
    coordinator are settlement and finality paths — claim provenance, secret scraping, finality
    verdicts — and every one of them applies to a token swap unchanged, for the same reason
    :class:`~pyrxd.eth_wallet.erc20_leg.Erc20HtlcLeg` could inherit them: the contract keeps the
    same ``claim(bytes32)``/``refund()`` shape and the same un-indexed ``Claimed`` event. Making
    this a separate type would have required editing all seven and risked missing one.

    The seventh site is serialisation, and it is handled by :attr:`CHAIN_TAG` rather than by
    isinstance ordering — see the note there. That matters: had ``to_dict`` kept branching on the
    type, a subclass would have serialised as ``chain: "eth"`` and an older binary would have read
    the ``amount`` field, denominated in USDC's 6 decimals, as **wei**. A 10^12 error, arriving
    through the very mechanism meant to prevent it.

    ``amount_wei`` is inherited and carries the amount in the token's **BASE UNITS** — the field
    name is the parent's, the unit is the token's. Prefer :attr:`amount_base_units` when reading;
    the unit is unambiguous from the TYPE, which is the discriminator that matters.
    """

    CHAIN_TAG: ClassVar[str] = "eth-erc20"

    token_address: str = ""

    def __post_init__(self) -> None:
        super().__post_init__()
        if not self.token_address:
            raise ValidationError(
                "Erc20HtlcLocator.token_address is required — a token amount without the token it "
                "is denominated in is not interpretable"
            )
        _check_hex_addr("token_address", self.token_address)
        object.__setattr__(self, "token_address", self.token_address.lower())

    @property
    def amount_base_units(self) -> int:
        """The amount in the TOKEN's base units. USDC has 6 decimals, not 18."""
        return self.amount_wei

    def to_dict(self) -> dict:
        d = super().to_dict()
        d["token_address"] = self.token_address
        return d

    @classmethod
    def from_dict(cls, d: dict) -> Erc20HtlcLocator:
        try:
            return cls(
                chain_id=d["chain_id"],
                contract_address=d["contract_address"],
                deploy_tx_hash=d["deploy_tx_hash"],
                hashlock=d["hashlock"],
                claimant=d["claimant"],
                refundee=d["refundee"],
                timeout=d["timeout"],
                amount_wei=d["amount_wei"],
                token_address=d["token_address"],
            )
        except KeyError as exc:
            raise ValidationError(f"Erc20HtlcLocator.from_dict missing field: {exc}") from exc
