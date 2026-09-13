"""Glyph BURN (protocol 6): the explicit burn proof, and what it proves.

A burn proof is an ``OP_RETURN`` output declaring that a token was destroyed::

    OP_RETURN <"gly"> <0x02> <0x06> <CBOR {v, p, action, token_ref, amount?, reason?}>

Mirrors Photonic Wallet's ``packages/lib/src/burn.ts``. The version and marker
are one-byte PUSHES, not ``OP_2``/``OP_6``: Photonic's parser reads
``chunks[n].buf``, which an opcode chunk does not have, so a minimal push would
produce a proof it cannot read.

WHAT A BURN PROOF IS NOT
========================

It is an ``OP_RETURN``. Anyone can write one, about any token, in a transaction
that never held it. It costs a dust output and proves nothing on its own — the
CBOR is operator text exactly like ``in`` and ``by``.

Radiant DOES permit burning: the FT conservation epilogue is ``>=``, not ``==``,
and an NFT singleton may simply not be re-created. But permitting it is not
recording it, and the chain has no opcode that says "this was deliberate". That
gap is what the proof fills, and it fills it with a claim.

So :func:`verify_burn` reports a BASIS rather than a boolean:

* the ref is absent from the transaction's outputs — checkable from the
  transaction alone, and genuinely rules out "it was forwarded here";
* the transaction actually SPENT an output carrying the ref — the part that
  makes it a burn rather than an assertion about someone else's token. It needs
  the spent outputs' scripts, which live in earlier transactions, so the caller
  fetches them and passes them in.

Photonic's ``validateBurn`` checked only the first of those, plus the magic
bytes, at ``becf41a`` — a transaction that never touched a token passed it.
Reported as M27; if a later Photonic requires the spent scripts too, this
paragraph is history rather than a live difference, and the two agree.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum

import cbor2

from ..security.errors import ValidationError
from .payload import GLY_MARKER, _encode_payload_push
from .script import TruncatedScriptError, script_carries_ref
from .types import GlyphProtocol, GlyphRef

_log = logging.getLogger(__name__)

__all__ = [
    "BURN_MARKER_BYTE",
    "BURN_PROOF_VERSION",
    "BurnBasis",
    "BurnProof",
    "BurnVerdict",
    "build_burn_proof_script",
    "parse_burn_proof",
    "verify_burn",
]

#: Envelope version byte carried by a burn proof (Photonic ``burn.ts:74``).
BURN_PROOF_VERSION = 0x02
#: The BURN protocol marker, as its own push (Photonic ``burn.ts:75``).
BURN_MARKER_BYTE = int(GlyphProtocol.BURN)  # 6

#: Same cap the payload decoder applies. A burn proof is parsed from an
#: arbitrary chain output, so an unbounded CBOR decode here is a DoS surface —
#: which is the reason Photonic caps it too (its audit note H13).
_MAX_PROOF_CBOR_BYTES = 8_192


@dataclass(frozen=True)
class BurnProof:
    """The decoded contents of a burn proof. Operator-supplied throughout."""

    token_ref: str
    action: str = "burn"
    version: int = 2
    protocol: tuple[int, ...] = (int(GlyphProtocol.BURN),)
    amount: int | None = None
    reason: str | None = None


class BurnBasis(Enum):
    """What a burn verdict rests on."""

    #: The transaction spent an output carrying the ref AND no output carries
    #: it. This is a burn.
    SPENT_AND_ABSENT = "spent-and-absent"
    #: The claim does not stand.
    NONE = "none"


@dataclass(frozen=True)
class BurnVerdict:
    ok: bool
    basis: BurnBasis
    reason: str
    proof: BurnProof | None = None


def build_burn_proof_script(
    token_ref: GlyphRef,
    *,
    amount: int | None = None,
    burn_reason: str | None = None,
) -> bytes:
    """Build the ``OP_RETURN`` burn-proof output script.

    Give this output 0 photons: it is unspendable, and any value on it is
    destroyed along with the token.

    :param token_ref: the token being burned.
    :param amount: units burned, for a fungible token. Omitted for an NFT.
    :param burn_reason: free text recorded in the proof. Operator-supplied and
        displayed, so treat it as untrusted on read.
    :raises ValidationError: *amount* is negative, or the encoded proof exceeds
        the CBOR cap.
    """
    if amount is not None and amount < 0:
        raise ValidationError(f"burn amount must be >= 0, got {amount}")
    proof: dict[str, object] = {
        "v": BURN_PROOF_VERSION,
        "p": [BURN_MARKER_BYTE],
        "action": "burn",
        "token_ref": f"{token_ref.txid}:{token_ref.vout}",
    }
    if amount is not None:
        proof["amount"] = amount
    if burn_reason:
        proof["reason"] = burn_reason

    encoded = cbor2.dumps(proof, canonical=True)
    if len(encoded) > _MAX_PROOF_CBOR_BYTES:
        raise ValidationError(
            f"burn proof CBOR is {len(encoded)} bytes, over the {_MAX_PROOF_CBOR_BYTES}-byte cap — "
            "shorten `burn_reason`"
        )
    return (
        b"\x6a"  # OP_RETURN
        + b"\x03"
        + GLY_MARKER  # PUSH 3 "gly"
        + bytes([1, BURN_PROOF_VERSION])  # PUSH 1 <version>
        + bytes([1, BURN_MARKER_BYTE])  # PUSH 1 <BURN>
        + _encode_payload_push(encoded)
    )


def _is_int(value: object) -> bool:
    """A real integer — NOT a bool, which `isinstance(x, int)` accepts."""
    return isinstance(value, int) and not isinstance(value, bool)


def parse_burn_proof(script: bytes) -> BurnProof | None:
    """Decode a burn-proof output, or ``None`` if *script* is not one.

    Returns ``None`` rather than raising for every malformed shape: this runs
    over arbitrary chain outputs, most of which are not burn proofs, and a
    transaction carrying one unreadable output must still be inspectable.
    """
    if not script or script[0] != 0x6A:
        return None
    pos = 1
    chunks: list[bytes] = []
    while pos < len(script) and len(chunks) < 4:
        op = script[pos]
        if op <= 75:
            size, start = op, pos + 1
        elif op == 0x4C and pos + 1 < len(script):
            size, start = script[pos + 1], pos + 2
        elif op == 0x4D and pos + 2 < len(script):
            size, start = int.from_bytes(script[pos + 1 : pos + 3], "little"), pos + 3
        else:
            return None
        if start + size > len(script):
            return None
        chunks.append(script[start : start + size])
        pos = start + size
    if len(chunks) < 4:
        return None
    magic, version, marker, payload = chunks[0], chunks[1], chunks[2], chunks[3]
    if magic != GLY_MARKER or version != bytes([BURN_PROOF_VERSION]) or marker != bytes([BURN_MARKER_BYTE]):
        return None
    if len(payload) > _MAX_PROOF_CBOR_BYTES:
        return None
    try:
        d = cbor2.loads(payload)
    except Exception:
        return None
    if not isinstance(d, dict) or not isinstance(d.get("token_ref"), str):
        return None
    # Bound to locals before narrowing: `d.get(...)` called twice is two
    # lookups AND two unrelated values as far as a type checker is concerned,
    # so the isinstance() guard on the first does not narrow the second.
    protocol = d.get("p")
    amount = d.get("amount")
    action = d.get("action")
    # NOT `version`: that name is already the envelope's version BYTE from the
    # chunk unpack above. These are two different versions — the push byte the
    # script carries, and the `v` field inside the CBOR — and giving them one
    # name reads as if the second checked the first.
    cbor_version = d.get("v")
    reason = d.get("reason")
    token_ref = d["token_ref"]
    return BurnProof(
        token_ref=token_ref if isinstance(token_ref, str) else "",
        action=action if isinstance(action, str) else "",
        # `not isinstance(_, bool)` throughout: in Python `isinstance(True, int)`
        # is True, so a CBOR `true` was decoding into a version, a protocol entry
        # and an amount, and `_inspect_core` then emitted `"amount": true`.
        version=cbor_version if _is_int(cbor_version) else 0,
        protocol=tuple(x for x in protocol if _is_int(x)) if isinstance(protocol, (list, tuple)) else (),
        amount=amount if _is_int(amount) else None,
        reason=reason if isinstance(reason, str) else None,
    )


def _carries(scripts: list[bytes], wire_ref: bytes) -> bool:
    """True if any script CARRIES *wire_ref* — pushes it, not merely names it.

    THE OPCODE SET IS THE WHOLE SECURITY PROPERTY HERE. ``iter_input_refs``
    yields all five operand-carrying opcodes, and only ``OP_PUSHINPUTREF``
    (``0xd0``) and ``OP_PUSHINPUTREFSINGLETON`` (``0xd8``) mean the output holds
    the token. ``OP_DISALLOWPUSHINPUTREF`` (``0xd2``) and
    ``...SIBLING`` (``0xd3``) are LOCAL ASSERTIONS: consensus never asks whether
    an input carried them, so anyone can name any ref with one for the price of
    an output (:data:`~pyrxd.constants.INPUT_BACKED_REF_OPCODES`).
    ``OP_REQUIREINPUTREF`` (``0xd1``) is a requirement, not possession.

    Walking the wide set broke this function in BOTH directions:

    * on the spent side it forged a burn — an attacker creates
      ``0xd2 <victim_ref> OP_DROP <P2PKH>``, spends it alongside a burn proof
      naming the victim's live NFT, and got ``SPENT_AND_ABSENT, valid=True``
      for a token they never held;
    * on the output side a stray ``0xd2`` mention would read as the token
      surviving, refusing an honest burn.

    :mod:`pyrxd.glyph.relationships` records the identical defect —
    "the verifier ... originally used the widest one and reported forged
    collection membership as VERIFIED". This is that bug, made a second time,
    in a second module.
    """
    for script in scripts:
        try:
            if script_carries_ref(script, wire_ref):
                return True
        except TruncatedScriptError as exc:
            # An unwalkable script cannot be shown to carry the ref, and must
            # not make an honest burn read as a survival. Logged, not swallowed:
            # a burn that reads valid because an output would not parse is a
            # different fact from one that reads valid because the ref is gone.
            _log.debug("verify_burn: skipping unwalkable script: %s", exc)
            continue
    return False


def _ref_spellings(ref: GlyphRef) -> frozenset[str]:
    """Every spelling of *ref* a burn proof may legitimately use.

    TWO IMPLEMENTATIONS, TWO SPELLINGS. pyrxd writes ``"<txid>:<vout>"``. Photonic writes
    ``Outpoint.toString()`` — the txid hex followed by the vout as 8 hex digits, big-endian, with
    no separator — and it does so on BOTH sides: ``createBurnProof`` builds the proof that way
    (``packages/lib/src/burn.ts``) and ``validateBurn`` normalises through
    ``Outpoint.fromString(...).toString()`` before comparing. Nothing in either project emits the
    other's form.

    So a `verify_burn` that matched only the colon form refused every burn proof Photonic has ever
    written, and said so in a sentence that was itself false: "the burn proof names X, not Y" —
    when the proof named the same token, spelled the way the other implementation spells it.

    Matching both is safe because the mapping is injective in each direction: a 72-hex string and
    a colon string cannot collide, and each decodes to exactly one outpoint.
    """
    return frozenset(
        {
            f"{ref.txid}:{ref.vout}",
            f"{ref.txid}{ref.vout.to_bytes(4, 'big').hex()}",
        }
    )


def verify_burn(
    output_scripts: list[bytes],
    token_ref: GlyphRef,
    spent_output_scripts: list[bytes],
) -> BurnVerdict:
    """Check a burn claim against what the transaction actually did.

    :param output_scripts: every output script of the burning transaction.
    :param token_ref: the token the caller is asking about.
    :param spent_output_scripts: the locking scripts of the outputs this
        transaction SPENT. They live in earlier transactions, so the caller
        fetches them.

        **Required, deliberately.** It was optional, and omitting it returned
        ``ok=False`` for a genuine burn — a function called ``verify_burn``
        answering False about a real burn is the most surprising thing an API
        can do. Absence from the outputs alone is a condition every unrelated
        transaction on the chain satisfies, so there is no useful verdict to
        give without this. Requiring it means the weak answer cannot arise:
        either you have the evidence, or you cannot ask. Pass ``[]`` only if you
        genuinely mean "this transaction spent nothing relevant", which is a
        refusal.

    An ``ok`` verdict never means "the owner intended this"; it means the token
    is gone and something recorded that it was meant to be.
    """
    wire = token_ref.to_bytes()
    # Select the proof that names THIS token, not the first parseable one. A
    # transaction burning A and B carries two proofs; taking the first reported
    # B as "the proof names A, not B" — refusing an honest batch burn.
    wanted = _ref_spellings(token_ref)
    proofs = [p for p in (parse_burn_proof(script) for script in output_scripts) if p is not None]
    proof = next((p for p in proofs if p.token_ref in wanted), None) or (proofs[0] if proofs else None)
    if proof is None:
        return BurnVerdict(ok=False, basis=BurnBasis.NONE, reason="no burn proof output found")
    if proof.token_ref not in wanted:
        return BurnVerdict(
            ok=False,
            basis=BurnBasis.NONE,
            reason=f"the burn proof names {proof.token_ref}, not {token_ref.txid}:{token_ref.vout}",
            proof=proof,
        )
    if _carries(output_scripts, wire):
        return BurnVerdict(
            ok=False,
            basis=BurnBasis.NONE,
            reason="an output still carries the token ref — it was forwarded, not burned",
            proof=proof,
        )
    if not _carries(spent_output_scripts, wire):
        return BurnVerdict(
            ok=False,
            basis=BurnBasis.NONE,
            reason="this transaction spent nothing carrying the token ref — the proof is about someone else's token",
            proof=proof,
        )
    return BurnVerdict(
        ok=True,
        basis=BurnBasis.SPENT_AND_ABSENT,
        reason="the transaction spent an output carrying the ref and no output carries it",
        proof=proof,
    )
