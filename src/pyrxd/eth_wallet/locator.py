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

from dataclasses import dataclass

from pyrxd.security.errors import ValidationError

__all__ = ["EthHtlcLocator"]


def _check_hex_addr(name: str, val: str) -> str:
    if not isinstance(val, str) or not val.startswith("0x") or len(val) != 42:
        raise ValidationError(f"{name} must be a 0x-prefixed 20-byte hex address")
    try:
        bytes.fromhex(val[2:])
    except ValueError as exc:
        raise ValidationError(f"{name} is not valid hex") from exc
    return val


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
        The funded value (verified == negotiated before the maker locks RXD).
    """

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
