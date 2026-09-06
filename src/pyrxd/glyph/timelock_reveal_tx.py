"""Glyph TIMELOCK reveal-transaction primitives (Photonic-compatible).

Mirrors Photonic Wallet's ``packages/lib/src/reveal.ts`` for the
*proof* / *script* layer: the OP_RETURN script bytes that go *inside* a
reveal tx, plus parser + validator counterparts.

It also carries the two pieces above that layer, which Photonic has no
counterpart for because a wallet holds them in its UI:
:func:`plan_timelock_reveal`, the gate that checks a CEK against the
token's on-chain commitment and refuses an early reveal, and
:func:`build_timelock_reveal`, which wraps a checked plan in a funded,
signed transaction. They live here so that the only way to obtain
publishable bytes is through the gate — see ``plan_timelock_reveal``'s
docstring for why that ordering is the point rather than a convenience.

On-chain OP_RETURN format::

    OP_RETURN <gly> <0x02> <0x09> <CBOR(RevealProof)>

where:

- ``<gly>`` = 3-byte ASCII magic (``676c79``)
- ``0x02`` = REVEAL_VERSION (matches Photonic's burn-proof pattern)
- ``0x09`` = REVEAL_MARKER (also the GLYPH_TIMELOCK protocol id)
- CBOR proof = a 6- or 7-key map (the 7th is the optional ``hint``)

RevealProof shape::

    {
      "v": 2,
      "p": [9],
      "action": "reveal",
      "token_ref": "<txid>:<vout>",
      "cek": "<32-byte CEK as 64-hex lowercase>",
      "cek_hash": "sha256:<32-byte hash as 64-hex lowercase>",
      "hint": "<optional human note>",
    }

CBOR byte-equivalence note: pyrxd uses ``cbor2`` which produces
canonical CBOR (shortest map-length encoding). Photonic's ``cbor-x``
library uses a fixed 2-byte map-length header. Both are spec-valid CBOR;
both decode to the same dict. **pyrxd's emit may produce different bytes
than Photonic's emit for the same logical reveal proof, but pyrxd's
parser accepts both.** For an indexer or wallet doing semantic
validation of the reveal proof, this distinction is invisible.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import cbor2

from ..constants import OpCode
from ..security.errors import ValidationError
from ..utils import encode_pushdata
from .timelock import (
    _protocols_and_spec,
    compute_cek_hash,
    parse_cek_hash,
    spec_is_unlocked,
    spec_unlock_remaining,
    verify_cek_reveal,
)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ..transaction.transaction import Transaction
    from .encrypted_content import EncryptedContentStub
    from .types import GlyphMetadata

    #: Either shape of Glyph mint metadata — see :func:`pyrxd.glyph.timelock._protocols_and_spec`.
    TimelockMetadata = EncryptedContentStub | GlyphMetadata

#: Magic bytes prefix on every Glyph OP_RETURN output. "gly" in ASCII.
GLYPH_MAGIC_BYTES = bytes.fromhex("676c79")

#: Version byte. Matches Photonic's REVEAL_VERSION = 0x02.
REVEAL_VERSION = 0x02

#: Marker byte. Equals GLYPH_TIMELOCK protocol id (9).
REVEAL_MARKER = 0x09

#: Required action string in the CBOR proof.
REVEAL_ACTION = "reveal"

#: Regex enforcing "txid:vout" form for token_ref.
_TOKEN_REF_RE = re.compile(r"^[0-9a-fA-F]{64}:[0-9]+$")


@dataclass(frozen=True)
class RevealProof:
    """Parsed reveal proof, mirroring Photonic's ``RevealProof`` type."""

    v: int  # always REVEAL_VERSION = 2
    p: list[int]  # always [REVEAL_MARKER] = [9]
    action: str  # always "reveal"
    token_ref: str  # "txid:vout"
    cek: str  # 64-hex
    cek_hash: str  # "sha256:<hex>"
    hint: str = ""

    def to_dict(self) -> dict:
        d: dict = {
            "v": self.v,
            "p": list(self.p),
            "action": self.action,
            "token_ref": self.token_ref,
            "cek": self.cek,
            "cek_hash": self.cek_hash,
        }
        if self.hint:
            d["hint"] = self.hint
        return d

    @classmethod
    def from_dict(cls, d: dict) -> RevealProof:
        return cls(
            v=int(d["v"]),
            p=[int(x) for x in d["p"]],
            action=str(d["action"]),
            token_ref=str(d["token_ref"]),
            cek=str(d["cek"]),
            cek_hash=str(d["cek_hash"]),
            hint=str(d.get("hint", "")),
        )


# ──────────────────────────────────────────────────── proof construction ──


def create_reveal_proof(
    token_ref: str,
    cek: bytes,
    *,
    hint: str = "",
    cek_hash_override: str | None = None,
) -> tuple[bytes, RevealProof]:
    """Build the OP_RETURN script bytes + the structured RevealProof.

    Matches Photonic's ``createRevealProof`` signature/behavior:

    - ``token_ref`` must be ``"<64-hex txid>:<vout>"`` form
    - ``cek`` must be exactly 32 bytes
    - ``cek_hash_override``, if provided, must equal ``sha256(cek)`` —
      otherwise raises. Useful when the caller wants to surface a
      pre-known commitment string in error messages.

    Returns ``(script_bytes, proof)`` where:
    - ``script_bytes`` is the full OP_RETURN script ready to put as a
      0-value output in the reveal tx
    - ``proof`` is the structured :class:`RevealProof` for introspection

    See module docstring for the CBOR byte-equivalence caveat: pyrxd's
    encoder produces canonical CBOR which differs in byte layout from
    Photonic's cbor-x encoder. Both are spec-valid; both round-trip via
    :func:`parse_reveal_proof_script`.
    """
    if len(cek) != 32:
        raise ValueError(f"CEK must be 32 bytes, got {len(cek)}")
    if not _TOKEN_REF_RE.fullmatch(token_ref):
        raise ValueError(f"token_ref must be 'txid:vout' (64 hex + ':' + decimal), got {token_ref!r}")

    cek_hex = cek.hex()
    computed_hash_hex = compute_cek_hash(cek).hex()
    if cek_hash_override:
        normalized = cek_hash_override.replace("sha256:", "").replace("SHA256:", "").lower()
        if normalized != computed_hash_hex:
            raise ValueError(
                f"CEK does not match provided cek_hash_override (expected {normalized!r}, got {computed_hash_hex!r})"
            )
        cek_hash_str = cek_hash_override if cek_hash_override.lower().startswith("sha256:") else f"sha256:{normalized}"
    else:
        cek_hash_str = f"sha256:{computed_hash_hex}"

    proof = RevealProof(
        v=REVEAL_VERSION,
        p=[REVEAL_MARKER],
        action=REVEAL_ACTION,
        token_ref=token_ref,
        cek=cek_hex,
        cek_hash=cek_hash_str,
        hint=hint,
    )

    encoded_proof = cbor2.dumps(proof.to_dict())

    script = (
        OpCode.OP_RETURN
        + encode_pushdata(GLYPH_MAGIC_BYTES, minimal_push=False)
        + encode_pushdata(bytes([REVEAL_VERSION]), minimal_push=False)
        + encode_pushdata(bytes([REVEAL_MARKER]), minimal_push=False)
        + encode_pushdata(encoded_proof, minimal_push=False)
    )
    return script, proof


# ──────────────────────────────────────────────────── proof parsing ──


def _walk_pushdata(script: bytes) -> list[bytes]:
    """Yield each pushed item from a pure-push script.

    Returns ``[]`` if the script contains any non-push opcode in the middle
    of where pushes should be. Skips a leading OP_RETURN (0x6a) if present.
    """
    pos = 0
    items: list[bytes] = []
    n = len(script)

    # Skip leading OP_RETURN if present.
    if pos < n and script[pos] == 0x6A:
        pos += 1

    while pos < n:
        op = script[pos]
        pos += 1

        if op == 0x00:
            items.append(b"")
            continue
        if 1 <= op <= 75:
            end = pos + op
            if end > n:
                return []
            items.append(script[pos:end])
            pos = end
            continue
        if op == 0x4C:  # PUSHDATA1
            if pos + 1 > n:
                return []
            length = script[pos]
            pos += 1
            end = pos + length
            if end > n:
                return []
            items.append(script[pos:end])
            pos = end
            continue
        if op == 0x4D:  # PUSHDATA2
            if pos + 2 > n:
                return []
            length = int.from_bytes(script[pos : pos + 2], "little")
            pos += 2
            end = pos + length
            if end > n:
                return []
            items.append(script[pos:end])
            pos = end
            continue
        if op == 0x4E:  # PUSHDATA4
            if pos + 4 > n:
                return []
            length = int.from_bytes(script[pos : pos + 4], "little")
            pos += 4
            end = pos + length
            if end > n:
                return []
            items.append(script[pos:end])
            pos = end
            continue
        # Any other opcode in a pure-push context → not a reveal-proof script.
        return []
    return items


def parse_reveal_proof_script(script: bytes) -> RevealProof | None:
    """Parse a reveal-proof OP_RETURN script. Returns ``None`` if the
    script is not a well-formed Glyph TIMELOCK reveal proof.

    Decodes the bridge fixture's ``op_return_script_hex`` correctly
    (verified via the test ``test_parse_photonic_reveal_script``).
    """
    if not script or script[0] != 0x6A:
        return None

    items = _walk_pushdata(script)
    # Expect 4 items: magic + version + marker + CBOR
    if len(items) != 4:
        return None
    magic, ver, marker, cbor_bytes = items
    if magic != GLYPH_MAGIC_BYTES:
        return None
    if len(ver) != 1 or ver[0] != REVEAL_VERSION:
        return None
    if len(marker) != 1 or marker[0] != REVEAL_MARKER:
        return None

    try:
        decoded = cbor2.loads(cbor_bytes)
    except Exception:
        return None
    if not isinstance(decoded, dict):
        return None

    # Required fields with type checks.
    try:
        if decoded.get("action") != REVEAL_ACTION:
            return None
        if not isinstance(decoded.get("token_ref"), str):
            return None
        if not isinstance(decoded.get("cek"), str):
            return None
        if not isinstance(decoded.get("cek_hash"), str):
            return None
        return RevealProof.from_dict(decoded)
    except Exception:
        return None


# ──────────────────────────────────────────────────── validation ──


@dataclass(frozen=True)
class RevealValidation:
    """Result of :func:`validate_reveal_proof`.

    - ``valid``: True iff every check passed
    - ``error``: short human-readable failure reason if ``valid`` is False
    - ``proof``: the parsed proof if it was at least well-formed (so the
      caller can introspect malformed-but-decodable proofs)
    """

    valid: bool
    error: str = ""
    proof: RevealProof | None = None


def validate_reveal_proof(
    proof: RevealProof,
    *,
    expected_token_ref: str,
    expected_cek_hash: str | None = None,
) -> RevealValidation:
    """Validate a parsed reveal proof's correctness.

    Checks performed:
      1. ``action == "reveal"`` (re-checked even though the parser already did)
      2. ``token_ref == expected_token_ref``
      3. ``sha256(cek) == cek_hash`` (self-consistency — proves the CEK
         the proof publishes actually hashes to the commitment in the
         proof itself)
      4. If ``expected_cek_hash`` is provided, ``cek_hash`` matches it
         (this is the on-chain commitment from the original mint)

    Returns :class:`RevealValidation` with ``valid=True`` on success.
    """
    if proof.action != REVEAL_ACTION:
        return RevealValidation(valid=False, error=f"action must be {REVEAL_ACTION!r}", proof=proof)

    if proof.token_ref != expected_token_ref:
        return RevealValidation(
            valid=False,
            error=f"token_ref mismatch: expected {expected_token_ref!r}, got {proof.token_ref!r}",
            proof=proof,
        )

    # Self-consistency: sha256(cek) == cek_hash
    try:
        cek_bytes = bytes.fromhex(proof.cek)
    except ValueError:
        return RevealValidation(valid=False, error="cek is not valid hex", proof=proof)
    if len(cek_bytes) != 32:
        return RevealValidation(
            valid=False,
            error=f"cek must decode to 32 bytes, got {len(cek_bytes)}",
            proof=proof,
        )

    actual_hash_hex = compute_cek_hash(cek_bytes).hex()
    try:
        claimed_hash_bytes = parse_cek_hash(proof.cek_hash)
    except ValueError as exc:
        return RevealValidation(
            valid=False,
            error=f"cek_hash malformed: {exc}",
            proof=proof,
        )
    if actual_hash_hex != claimed_hash_bytes.hex():
        return RevealValidation(
            valid=False,
            error=f"cek_hash self-consistency failed: sha256(cek)={actual_hash_hex} "
            f"but proof.cek_hash claims {claimed_hash_bytes.hex()}",
            proof=proof,
        )

    # Cross-check against the on-chain commitment.
    if expected_cek_hash is not None:
        try:
            expected_bytes = parse_cek_hash(expected_cek_hash)
        except ValueError as exc:
            return RevealValidation(
                valid=False,
                error=f"expected_cek_hash malformed: {exc}",
                proof=proof,
            )
        if actual_hash_hex != expected_bytes.hex():
            return RevealValidation(
                valid=False,
                error=f"cek does not match on-chain commitment: expected {expected_bytes.hex()}, got {actual_hash_hex}",
                proof=proof,
            )

    return RevealValidation(valid=True, proof=proof)


# ──────────────────────────────────────────── the reveal gate ──


class CekCommitmentMismatch(ValidationError):
    """The CEK offered for publication is not the one this token committed to.

    A :class:`~pyrxd.security.errors.ValidationError`, so it lands with everything else
    raised BEFORE a broadcast. Publishing the wrong key is worse than publishing nothing:
    the reveal is spent, the payload stays unreadable forever, and there is no second
    reveal to correct it.
    """


class TimelockNotExpired(ValidationError):
    """Refusing to publish the CEK before ``unlock_at``.

    Revealing early does not fail — it *works*, and destroys the only property the token
    exists to provide. It cannot be undone: the key is on a public chain.
    """


@dataclass(frozen=True)
class TimelockRevealPlan:
    """Exactly what a reveal would publish, and the checks it already passed.

    Produced by :func:`plan_timelock_reveal`, which raises rather than returning a plan
    that would be wrong to broadcast — so holding one of these means the CEK matched the
    on-chain commitment and (unless ``early_override`` is set) the timelock has expired.

    ``cek`` is not a field. It is in ``proof.cek`` because that IS the published payload,
    and hiding it in a structure whose whole purpose is to show the operator what goes on
    chain would be theatre.
    """

    token_ref: str
    op_return_script: bytes
    proof: RevealProof
    #: The ``"sha256:<hex>"`` the mint committed to, and what ``cek`` was checked against.
    commitment: str
    mode: str
    unlock_at: int
    #: ``True`` when the caller's clock says the lock has expired.
    unlocked: bool
    #: Blocks (mode ``"block"``) or seconds (mode ``"time"``) still to go. 0 when unlocked.
    remaining: int
    #: ``True`` when this plan was built for a still-locked token because the operator
    #: passed ``allow_early``. Carried so the confirmation prompt can say so.
    early_override: bool = False
    #: THE CLOCK READING THE GATE ACTUALLY COMPARED AGAINST — the tip height for a
    #: ``"block"`` lock, the tip header's unix timestamp for a ``"time"`` one, and ``None``
    #: when no clock for this spec's mode was supplied.
    #:
    #: Carried because the number that decides whether a key becomes public was, until this
    #: field existed, never shown to anyone. ``GlyphClient.plan_timelock_reveal`` takes it
    #: from an ElectrumX server, which no part of this SDK authenticates: nothing checks the
    #: proof of work behind the height, links the header to a known one, or asks a second
    #: endpoint. A server that overstates the tip therefore decides an irreversible
    #: publication, and a server that lags refuses an honest holder — and neither shows up in
    #: ``unlocked`` alone. An operator who can see "tip 812,340" against "opens at 900,000"
    #: can notice; one shown only "opens at 900,000" cannot.
    judged_at: int | None = None


def plan_timelock_reveal(
    metadata: TimelockMetadata,
    *,
    token_ref: str,
    cek: bytes,
    current_block: int | None = None,
    current_time: int | None = None,
    hint: str = "",
    allow_early: bool = False,
) -> TimelockRevealPlan:
    """Check a reveal against the token that is being revealed, then build its script.

    **This is the only supported way to produce a publishable reveal script.**
    :func:`create_reveal_proof` builds a proof from a CEK and a ref alone; it cannot check
    either against the token, because it is never given the token. That is the whole gap:
    both permanent mistakes on this path are invisible to a function that only sees the key.

    * A CEK that is not the one committed to. ``create_reveal_proof`` happily emits a
      self-consistent proof for any 32 bytes — ``sha256(cek) == proof.cek_hash`` holds for
      the wrong key just as well as the right one. Only the mint's ``crypto.timelock``
      says which key was right, so the comparison has to happen where the metadata is.
    * A reveal published before ``unlock_at``, which does not fail. It succeeds, and the
      sealed content is public years early.

    So the checks are here, in the function that returns the bytes, rather than beside it in
    a caller that has to remember them. Every entry point that can broadcast a reveal —
    ``GlyphClient.build_timelock_reveal``, ``GlyphClient.reveal_timelock`` and
    ``pyrxd glyph timelock-reveal`` — goes through this, and none of them takes a
    pre-built script.

    The script this returns is then parsed back with :func:`parse_reveal_proof_script` and
    run through :func:`validate_reveal_proof` against the same commitment, so what is
    checked is the bytes that will actually be published rather than the object they were
    built from.

    Args:
        metadata: the token's mint metadata — either shape (see
            :func:`pyrxd.glyph.timelock._protocols_and_spec`). ``decode_payload`` on the
            mint's CBOR gives you one; ``build_timelock_mint`` gives you the other.
        token_ref: ``"<64-hex txid>:<vout>"`` of the token being revealed.
        cek: the 32-byte key to publish.
        current_block: chain tip, for a ``mode="block"`` lock.
        current_time: unix seconds, for a ``mode="time"`` lock.
        hint: optional operator note carried in the proof.
        allow_early: publish anyway, before ``unlock_at``. The refusal exists because the
            mistake is unrepairable, not because early reveal is never wanted — a seller
            who decides to open a sealed lot early has honest work to do here. It must be
            asked for explicitly, and the returned plan records that it was.

    Raises:
        TimelockNotExpired: the lock has not expired (or cannot be judged, because the
            clock for its mode was not supplied) and ``allow_early`` is False.
        CekCommitmentMismatch: ``sha256(cek)`` is not the token's committed hash.
        ~pyrxd.security.errors.ValidationError: the metadata carries no timelock spec to
            check against, the commitment it carries is not a readable ``"sha256:<hex>"``
            (which a third-party mint can be — the decoder stores that string raw), or the
            proof this function built does not validate.
    """
    protocols, spec = _protocols_and_spec(metadata)
    if spec is None:
        raise ValidationError(
            "this metadata carries no crypto.timelock, so there is no commitment to check a "
            "CEK against. Revealing against it would publish a key nothing on chain can "
            f"verify. Protocol markers: {list(protocols)!r}"
        )

    # CHECK THE KEY FIRST, before the clock. Both refusals matter, but a wrong CEK is the
    # one an operator cannot detect from the output — an early reveal at least publishes a
    # key that works.
    #
    # `spec.cek_hash` came off a chain and `TimelockSpec.from_dict` stores it as whatever
    # string was there — the decoder is deliberately permissive about third-party bytes. So
    # `parse_cek_hash` inside `verify_cek_reveal` can raise a bare ValueError on a token
    # nobody in this project minted, and a bare ValueError is not in the set the CLI catches:
    # the operator got a traceback where a refusal belonged. Nothing is broadcast either way,
    # so this is liveness, not fund safety — but a traceback tells them nothing about which
    # of their two files was wrong.
    #
    # The commitment is parsed on its own rather than inside `verify_cek_reveal`, so that the
    # message can say which of the two inputs was wrong. Wrapping the whole comparison caught
    # the short-CEK ValueError from `compute_cek_hash` as well and reported it as a malformed
    # on-chain commitment — a sentence about the token, produced by a fault in the operator's
    # key file, which is the worst possible steer at this prompt.
    try:
        expected_hash = parse_cek_hash(spec.cek_hash)
    except ValueError as exc:
        raise ValidationError(
            f"this token's on-chain commitment is not a readable sha256 hash ({spec.cek_hash!r}): "
            f"{exc}. No key can be checked against it, so no reveal can be built — pyrxd did not "
            "mint this token, and whatever tool did wrote a commitment in a shape the Glyph "
            "spec does not define."
        ) from exc
    if len(cek) != 32:
        raise ValidationError(
            f"a Glyph CEK is 32 bytes and this one is {len(cek)}. Nothing was checked against the "
            "token's commitment, because a key of the wrong length cannot be the one it committed "
            "to — load the key file this token's mint wrote."
        )
    if not verify_cek_reveal(cek, expected_hash):
        raise CekCommitmentMismatch(
            "this CEK does not match the token's on-chain commitment "
            f"({spec.cek_hash}). Publishing it would spend the reveal and leave the payload "
            "permanently unreadable — the commitment cannot be changed and there is no "
            "second reveal. Check that you loaded the CEK saved for THIS token."
        )

    # JUDGE THE LOCK FROM `spec`, NOT FROM THE PROTOCOL MARKER. `is_unlocked` answers a
    # different question — "is this token's content readable" — and for a token with no
    # TIMELOCK marker its honest answer is True, because nothing is sealed. Asking it here
    # made the gate fail OPEN on the one shape that matters: an envelope carrying
    # `crypto.timelock` while omitting 9 from `p` got past the `spec is None` check above,
    # came back unlocked=True from a marker that was not there, and published the key with
    # `early_override` False — so the CLI's `*** EARLY REVEAL` banner, keyed on that same
    # boolean, stayed silent too. `decode_payload` builds exactly that object: it fills
    # `timelock` from `d["crypto"]["timelock"]` without consulting `d["p"]` at all.
    #
    # It does NOT refuse the marker-less shape. A holder of a token some other tool minted
    # has honest work to do here once its unlock_at has passed, and refusing them would be
    # its own defect. The spec is simply what gets judged.
    unlocked = spec_is_unlocked(spec, current_block=current_block, current_time=current_time)
    remaining = spec_unlock_remaining(spec, current_block=current_block, current_time=current_time)
    supplied = current_block if spec.mode == "block" else current_time if spec.mode == "time" else None
    if not unlocked and not allow_early:
        if spec.mode not in ("block", "time"):
            # Not "no current_time was supplied" — that message names a fix that does not
            # exist for this token and sends the operator looking for a clock they already
            # passed. The mode is the problem.
            detail = (
                f"its mode {spec.mode!r} is not one this SDK can judge (the Glyph spec "
                "defines 'block' and 'time'), so the lock cannot be evaluated at all"
            )
        elif supplied is None:
            clock = "current_block" if spec.mode == "block" else "current_time"
            detail = f"no {clock} was supplied, so the lock cannot be judged"
        else:
            detail = (
                f"{remaining:,} {'blocks' if spec.mode == 'block' else 'seconds'} remaining (clock read: {supplied:,})"
            )
        raise TimelockNotExpired(
            f"this token unlocks at {spec.unlock_at} ({spec.mode}) and {detail}. Publishing "
            "the CEK now destroys the timelock permanently — it is on a public chain the "
            "moment the transaction relays. Pass allow_early=True (CLI: --allow-early) if "
            "that is genuinely what you want."
        )

    script, _proof = create_reveal_proof(token_ref, cek, hint=hint, cek_hash_override=spec.cek_hash)

    # Re-parse and validate THE BYTES, not the object they came from. `create_reveal_proof`
    # returns both; checking the object would prove the dataclass agrees with itself, which
    # nothing has ever doubted. What matters is that the script an indexer will read decodes
    # to a proof that validates against this token's commitment.
    reparsed = parse_reveal_proof_script(script)
    if reparsed is None:  # pragma: no cover - unreachable unless the encoder breaks
        raise ValidationError(
            "the reveal script this build produced does not parse back as a reveal proof; "
            "refusing to broadcast bytes we cannot read ourselves"
        )
    verdict = validate_reveal_proof(reparsed, expected_token_ref=token_ref, expected_cek_hash=spec.cek_hash)
    if not verdict.valid:  # pragma: no cover - unreachable unless the encoder breaks
        raise ValidationError(f"the reveal proof this build produced does not validate: {verdict.error}")

    return TimelockRevealPlan(
        token_ref=token_ref,
        op_return_script=script,
        proof=reparsed,
        commitment=spec.cek_hash,
        mode=spec.mode,
        unlock_at=spec.unlock_at,
        unlocked=unlocked,
        remaining=remaining,
        early_override=not unlocked,
        judged_at=supplied,
    )


# ─────────────────────────────────────── the reveal transaction ──


#: Modelled bytes of a reveal transaction WITHOUT its OP_RETURN script, that script's length
#: varint, and any change output.
#:
#: ``4`` version + ``1`` input count + (``36`` outpoint + ``1`` script varint + ``107``
#: unlocking script + ``4`` sequence) + ``1`` output count + ``8`` value + ``4`` locktime
#: = **166**. ``107`` is :meth:`P2PKH.unlock`'s ``estimated_unlocking_byte_length`` and is an
#: upper bound on this template (the real script is 105-107 B), so this models the largest
#: transaction the builder can produce.
TIMELOCK_REVEAL_MODELLED_BYTES = 166


def timelock_reveal_funding_bar(op_return_script: bytes, fee_rate: int) -> int:
    """Photons a plain-RXD UTXO must hold to fund one reveal, at *fee_rate*.

    Modelled on the **no-change** shape, for the reason
    :func:`pyrxd.glyph.transfer.nft_transfer_funding_bar` documents: ``Transaction.fee``
    drops the change output when the funding cannot also cover it, so the smallest UTXO
    that works is the one paying for the ONE-output transaction. Sizing against the larger
    shape refuses funding that would in fact relay.

    A reveal's OP_RETURN is large by data-carrier standards — 263 B with no hint, more with
    one — so its length varint is sized here rather than assumed to be one byte.
    """
    from ..fee_sizing import required_fee

    script_len = len(op_return_script)
    len_varint = 1 if script_len < 0xFD else 3
    return required_fee(TIMELOCK_REVEAL_MODELLED_BYTES + len_varint + script_len, fee_rate)


@dataclass(frozen=True)
class TimelockRevealBuild:
    """A signed, un-broadcast reveal transaction.

    :param tx: the signed transaction
    :param fee: photons paid, from the plain-RXD funding input
    :param plan: the checked :class:`TimelockRevealPlan` these bytes were built from —
        carried so a confirmation prompt can show what is about to become public without
        re-deriving it
    :param from_address: the wallet address that funded the reveal
    :param has_change: ``False`` when the whole funding UTXO became the fee
    """

    tx: Transaction
    fee: int
    plan: TimelockRevealPlan
    from_address: str
    has_change: bool

    def serialize(self) -> bytes:
        """Raw transaction bytes, ready for ``await client.broadcast(...)``."""
        return bytes(self.tx.serialize())


async def build_timelock_reveal(
    wallet: Any,
    plan: TimelockRevealPlan,
    *,
    client: Any,
    fee_rate: int,
    allow_overpay: bool = False,
    allow_below_relay_floor: bool = False,
) -> TimelockRevealBuild:
    """Wrap a checked reveal plan in a funded, signed transaction. Does not broadcast.

    Takes a :class:`TimelockRevealPlan`, never a raw script. That is the whole reason the
    argument is typed this way: a plan can only come from :func:`plan_timelock_reveal`, so
    the CEK-against-commitment check and the unlock gate are already behind any transaction
    this function can produce. A ``script: bytes`` parameter would have let a caller skip
    both and still get signed bytes back.

    The reveal publishes data, not value: output 0 is the OP_RETURN at value 0 and the fee
    comes from one plain-RXD input, with change returning to the funding address.
    :func:`~pyrxd.glyph.transfer.find_plain_rxd_utxo` verifies each candidate's **on-chain**
    script is a bare P2PKH, so a token-bearing UTXO is never spent here — burning an NFT to
    publish a key about a different token would be a memorable way to close this issue.

    Raises:
        ~pyrxd.security.errors.InsufficientFundsError: no plain-RXD UTXO large enough.
            Raised before anything is signed.
        ~pyrxd.security.errors.ValidationError: the fee rate is out of bounds, or the signed
            transaction does not pay for its own size.
    """
    from ..fee_models import SatoshisPerKilobyte
    from ..fee_sizing import assert_fee_rate_clears_relay_floor, assert_pays_for_its_size
    from ..script.script import Script
    from ..script.type import P2PKH
    from ..transaction.transaction import Transaction
    from ..transaction.transaction_input import TransactionInput
    from ..transaction.transaction_output import TransactionOutput
    from .transfer import NoFeeFundingError, find_plain_rxd_utxo

    assert_fee_rate_clears_relay_floor(
        fee_rate,
        what="build_timelock_reveal",
        allow_overpay=allow_overpay,
        allow_below_relay_floor=allow_below_relay_floor,
        error_type=ValidationError,
    )

    script = plan.op_return_script
    needed = timelock_reveal_funding_bar(script, fee_rate)
    triples = await wallet.collect_spendable(client)
    fund = await find_plain_rxd_utxo(triples, client, exclude=set(), needed=needed)
    if fund is None:
        raise NoFeeFundingError(
            f"no plain-RXD UTXO large enough to fund the timelock reveal — need at least "
            f"{needed:,} photons on a single non-token UTXO (~{TIMELOCK_REVEAL_MODELLED_BYTES + len(script)} B "
            f"at {fee_rate:,} photons/B). The reveal carries a {len(script)}-byte OP_RETURN."
        )
    fund_utxo, fund_addr, fund_key = fund
    fund_spk = P2PKH().lock(fund_addr)

    def _shim(vout: int, locking: Script, value: int, txid: str) -> Transaction:
        """A stand-in parent tx so preimage computation can index ``outputs[vout]``.

        Same shim as :func:`pyrxd.glyph.transfer.build_nft_transfer` uses, and for the same
        reason: only the txid and the output at ``vout`` are real.
        """
        outs = [TransactionOutput(Script(b""), 0) for _ in range(vout)]
        outs.append(TransactionOutput(locking, value))
        src = Transaction(tx_inputs=[], tx_outputs=outs)
        src.txid = lambda: txid  # type: ignore[method-assign]
        return src

    fund_input = TransactionInput(
        source_transaction=_shim(fund_utxo.tx_pos, fund_spk, fund_utxo.value, fund_utxo.tx_hash),
        source_txid=fund_utxo.tx_hash,
        source_output_index=fund_utxo.tx_pos,
        unlocking_script_template=P2PKH().unlock(fund_key),
    )
    fund_input.satoshis = fund_utxo.value
    fund_input.locking_script = fund_spk

    tx = Transaction(
        tx_inputs=[fund_input],
        tx_outputs=[
            TransactionOutput(Script(script), 0),  # the reveal proof — value 0, unspendable
            TransactionOutput(fund_spk, 0, change=True),
        ],
    )
    tx.fee(SatoshisPerKilobyte(fee_rate * 1000))  # type: ignore[no-untyped-call]
    tx.sign()

    raw = tx.serialize()
    fee_paid = tx.get_fee()
    assert_pays_for_its_size(
        size_bytes=len(raw),
        fee_paid=fee_paid,
        fee_rate=fee_rate,
        what="the timelock reveal",
        error_type=ValidationError,
    )
    return TimelockRevealBuild(
        tx=tx,
        fee=fee_paid,
        plan=plan,
        from_address=fund_addr,
        has_change=len(tx.outputs) > 1,
    )


__all__ = [
    "GLYPH_MAGIC_BYTES",
    "REVEAL_ACTION",
    "REVEAL_MARKER",
    "REVEAL_VERSION",
    "TIMELOCK_REVEAL_MODELLED_BYTES",
    "CekCommitmentMismatch",
    "RevealProof",
    "RevealValidation",
    "TimelockNotExpired",
    "TimelockRevealBuild",
    "TimelockRevealPlan",
    "build_timelock_reveal",
    "create_reveal_proof",
    "parse_reveal_proof_script",
    "plan_timelock_reveal",
    "timelock_reveal_funding_bar",
    "validate_reveal_proof",
]
