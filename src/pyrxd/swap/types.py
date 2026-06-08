"""Value types for the same-chain partial-transaction swap API.

A swap moves two assets atomically inside one transaction using
``SIGHASH_SINGLE | ANYONECANPAY`` signature-level atomicity (see
:mod:`pyrxd.swap.partial`). These dataclasses describe *what* is being
traded; they carry no key material and are safe to serialize and send
over any transport (the offer envelope is JSON-able via ``to_dict``).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from ..glyph.types import GlyphRef
from ..security.errors import ValidationError
from ..security.types import Txid

AssetKind = Literal["rxd", "ft"]


@dataclass(frozen=True)
class Asset:
    """One side of a trade: plain RXD, or a Glyph fungible token.

    ``amount`` is in photons. For an FT this is also the token-unit count
    (Radiant convention: 1 photon = 1 FT unit). ``ref`` is the FT's
    genesis/commit outpoint (the permanent token identity) and is required
    for — and only for — ``kind == "ft"``.
    """

    kind: AssetKind
    amount: int
    ref: GlyphRef | None = None

    def __post_init__(self) -> None:
        if self.amount <= 0:
            raise ValidationError(f"asset amount must be positive, got {self.amount}")
        if self.kind == "ft" and self.ref is None:
            raise ValidationError("an FT asset requires a genesis ref")
        if self.kind == "rxd" and self.ref is not None:
            raise ValidationError("a plain RXD asset must not carry a ref")

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "amount": self.amount,
            "ref": None if self.ref is None else {"txid": str(self.ref.txid), "vout": self.ref.vout},
        }

    @classmethod
    def from_dict(cls, d: dict) -> Asset:
        ref_d = d.get("ref")
        ref = None if ref_d is None else GlyphRef(txid=Txid(str(ref_d["txid"])), vout=int(ref_d["vout"]))
        return cls(kind=d["kind"], amount=int(d["amount"]), ref=ref)


@dataclass(frozen=True)
class SwapTerms:
    """The trade as the maker states it: maker gives ``give``, receives ``receive``.

    From the taker's seat this reads in reverse — the taker receives
    ``give`` and pays ``receive``. The terms are a human-readable
    cross-check; the maker's signature on the partial tx is what actually
    enforces them (see :func:`pyrxd.swap.partial.accept_offer`).
    """

    give: Asset
    receive: Asset

    def to_dict(self) -> dict:
        return {"give": self.give.to_dict(), "receive": self.receive.to_dict()}

    @classmethod
    def from_dict(cls, d: dict) -> SwapTerms:
        return cls(give=Asset.from_dict(d["give"]), receive=Asset.from_dict(d["receive"]))


@dataclass(frozen=True)
class SwapOffer:
    """A maker's signed partial transaction plus everything a taker needs to verify it.

    Transport-agnostic. ``partial_tx_hex`` holds the maker's input
    (signed ``SINGLE|ANYONECANPAY``) and output[0] (what the maker wants
    to receive). ``give_source_tx_hex`` is the *full* previous transaction
    that funds the maker's input, so the taker can read the maker's real
    given-asset value/script from the chain rather than trusting the
    declared ``terms`` — and confirm it hashes to the input's outpoint.
    """

    partial_tx_hex: str
    give_source_tx_hex: str
    give_vout: int
    terms: SwapTerms

    def to_dict(self) -> dict:
        return {
            "partial_tx_hex": self.partial_tx_hex,
            "give_source_tx_hex": self.give_source_tx_hex,
            "give_vout": self.give_vout,
            "terms": self.terms.to_dict(),
        }

    @classmethod
    def from_dict(cls, d: dict) -> SwapOffer:
        return cls(
            partial_tx_hex=str(d["partial_tx_hex"]),
            give_source_tx_hex=str(d["give_source_tx_hex"]),
            give_vout=int(d["give_vout"]),
            terms=SwapTerms.from_dict(d["terms"]),
        )
