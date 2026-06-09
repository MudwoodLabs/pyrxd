"""Wire types for the signing-agent protocol.

The CLI (watch-only) builds an unsigned transaction and a
:class:`SigningRequest` describing which inputs the agent must sign (with
their derivation coords + full source tx so the agent can verify the
prevout itself) and which outputs are change (claims the agent re-derives
and verifies). The agent returns a :class:`SignedResult`.

Everything here is plain data — JSON-serializable for the socket layer,
and carries no key material.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..constants import SIGHASH


@dataclass(frozen=True)
class InputToSign:
    """One input the agent must sign.

    ``source_tx_hex`` is the FULL previous transaction; the agent verifies
    it hashes to the input's outpoint and reads the real prevout
    value/script from it — it never trusts values embedded in the unsigned
    tx (prevout-authenticity, C1). ``change``/``index`` are the BIP44
    chain/index the agent derives the signing key from.
    """

    input_index: int
    change: int
    index: int
    source_tx_hex: str
    sighash: int = int(SIGHASH.ALL_FORKID)

    def to_dict(self) -> dict:
        return {
            "input_index": self.input_index,
            "change": self.change,
            "index": self.index,
            "source_tx_hex": self.source_tx_hex,
            "sighash": self.sighash,
        }

    @classmethod
    def from_dict(cls, d: dict) -> InputToSign:
        return cls(
            input_index=int(d["input_index"]),
            change=int(d["change"]),
            index=int(d["index"]),
            source_tx_hex=str(d["source_tx_hex"]),
            sighash=int(d.get("sighash", int(SIGHASH.ALL_FORKID))),
        )


@dataclass(frozen=True)
class ChangeClaim:
    """A claim that output ``output_index`` is change to the wallet's own
    ``change``/``index`` key. The agent VERIFIES it by re-deriving that
    address — a false claim (hiding an external payee as "change") fails
    verification and the spend is rejected."""

    output_index: int
    change: int
    index: int

    def to_dict(self) -> dict:
        return {"output_index": self.output_index, "change": self.change, "index": self.index}

    @classmethod
    def from_dict(cls, d: dict) -> ChangeClaim:
        return cls(output_index=int(d["output_index"]), change=int(d["change"]), index=int(d["index"]))


@dataclass(frozen=True)
class SigningRequest:
    """An unsigned tx plus everything the agent needs to verify and sign it."""

    unsigned_tx_hex: str
    inputs: tuple[InputToSign, ...]
    change_claims: tuple[ChangeClaim, ...] = ()

    def to_dict(self) -> dict:
        return {
            "unsigned_tx_hex": self.unsigned_tx_hex,
            "inputs": [i.to_dict() for i in self.inputs],
            "change_claims": [c.to_dict() for c in self.change_claims],
        }

    @classmethod
    def from_dict(cls, d: dict) -> SigningRequest:
        return cls(
            unsigned_tx_hex=str(d["unsigned_tx_hex"]),
            inputs=tuple(InputToSign.from_dict(i) for i in d["inputs"]),
            change_claims=tuple(ChangeClaim.from_dict(c) for c in d.get("change_claims", [])),
        )


@dataclass(frozen=True)
class ExternalOutput:
    """A non-change output (a real payee), shown to the user before signing."""

    output_index: int
    dest: str  # human-displayable destination (address/pkh/script summary)
    amount: int


@dataclass(frozen=True)
class SpendSummary:
    """What the agent is about to sign — handed to the confirmation gate.

    Derived entirely from the *verified* tx (prevouts checked, change
    claims re-derived), never from caller-asserted free-form values.
    """

    external_outputs: tuple[ExternalOutput, ...]
    total_external: int
    change_total: int
    input_total: int
    fee: int
    sighash_flags: tuple[int, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class SignedResult:
    """The agent's response: a fully-signed, broadcast-ready transaction.

    Carries a transaction only — never key material (enforced invariant).
    """

    signed_tx_hex: str

    def to_dict(self) -> dict:
        return {"signed_tx_hex": self.signed_tx_hex}

    @classmethod
    def from_dict(cls, d: dict) -> SignedResult:
        return cls(signed_tx_hex=str(d["signed_tx_hex"]))
