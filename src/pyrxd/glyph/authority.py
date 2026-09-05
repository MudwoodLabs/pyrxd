"""Glyph AUTHORITY (protocol 10): issuer tokens, and what they actually prove.

An authority token is an ordinary NFT carrying the ``10`` marker and an ``attrs``
object naming its issuer, scope, permissions and expiry. Mirrors Photonic
Wallet's ``packages/lib/src/authority.ts``.

TWO DIFFERENT QUESTIONS, AND THEY HAVE DIFFERENT STRENGTHS
==========================================================

Everything in this module exists to keep these apart, because conflating them is
how an unverified assertion gets rendered as a fact.

**1. Was this item MINTED under authority X?** Consensus-enforced, if the item
was minted with :func:`~pyrxd.glyph.script.build_authority_gated_nft_script`.
Radiant refuses to create that output unless the transaction held the authority
ref, so the answer is carried by the item's genesis transaction and cannot be
forged. :func:`verify_authority_gate` asks it.

The catch, measured in ``tests/test_authority_regtest_e2e.py``: the holder can
transfer the item to a plain NFT script and the gate is gone, same ref, no
permission needed. So the question must be asked of the item's **genesis**
output, never its current one. An "is it gated?" check on a live UTXO is
defeatable by whoever holds it.

**2. Does this item CLAIM authority X?** An operator assertion in the ``by``
field, and nothing more, until something backs it. Photonic's
``verifyAuthorityChain`` matches ``by`` against a candidate authority's ref —
which its own comments record as an audit fix over an earlier version that
accepted any authority at all. The fixed version is still only a string match:
a forger who writes a real issuer's ref into their own ``by`` passes it.

pyrxd does not ship that shape. :func:`verify_authority_claim` takes the
relationship verdicts from :mod:`pyrxd.glyph.relationships` and refuses to
report an issuer for a claim nothing authorised — the same rule that module
applies to collection membership, for the same reason.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum

from ..security.errors import ValidationError
from .relationships import RelationshipBacking, RelationshipKind, RelationshipVerdict
from .script import parse_authority_gated_script
from .types import GlyphMetadata, GlyphProtocol, GlyphRef

__all__ = [
    "AuthorityAttrs",
    "AuthorityBasis",
    "AuthorityVerdict",
    "build_authority_metadata",
    "has_permission",
    "is_authority",
    "is_authority_expired",
    "read_authority_attrs",
    "validate_authority",
    "verify_authority_claim",
    "verify_authority_gate",
]


@dataclass(frozen=True)
class AuthorityAttrs:
    """The ``attrs`` payload of an authority token.

    Field names match Photonic's ``AuthorityMetadata`` so the two read each
    other's tokens.
    """

    issuer: str
    scope: str | None = None
    permissions: tuple[str, ...] = ()
    expires: str | None = None
    revocable: bool = True

    def to_attrs(self) -> dict:
        """The CBOR ``attrs`` map. Absent optionals are omitted, not nulled.

        A key present with a null value and a key that is absent are different
        bytes and hash differently, and Photonic omits — so emitting ``None``
        would produce an envelope its reader treats as a different token.
        """
        out: dict[str, object] = {"issuer": self.issuer, "revocable": self.revocable}
        if self.scope is not None:
            out["scope"] = self.scope
        if self.permissions:
            out["permissions"] = list(self.permissions)
        if self.expires is not None:
            out["expires"] = self.expires
        return out


class AuthorityBasis(Enum):
    """What a positive authority verdict actually rests on."""

    #: The item's GENESIS output was authority-gated, so consensus refused to
    #: create it without the authority ref among that transaction's inputs.
    GATE = "gate"
    #: The item declares the authority in ``by`` AND that claim is backed — the
    #: minting transaction was authorised to carry the authority's ref.
    BACKED_CLAIM = "backed-claim"
    #: Nothing established it.
    NONE = "none"


@dataclass(frozen=True)
class AuthorityVerdict:
    valid: bool
    basis: AuthorityBasis
    reason: str
    authority_ref: GlyphRef | None = None


def build_authority_metadata(
    issuer: str,
    *,
    name: str = "Authority Token",
    scope: str | None = None,
    permissions: Sequence[str] = (),
    expires: str | None = None,
    revocable: bool = True,
    description: str = "",
) -> GlyphMetadata:
    """Build an authority token's metadata (``p = [NFT, AUTHORITY]``).

    Mirrors Photonic ``createAuthority``. Mint it like any NFT; it becomes an
    authority by the ``10`` marker, not by a special script.

    :param issuer: the issuing identity — an address or pubkey. Required and
        non-empty: an authority naming no issuer says nothing about who is
        vouching, and :func:`validate_authority` rejects it on read.
    :param expires: ISO-8601 timestamp. A value without a timezone is read as
        UTC by :func:`is_authority_expired`.
    :raises ValidationError: *issuer* is empty, or *expires* is unparseable —
        caught here rather than at read time, because a mint is irreversible and
        an unparseable expiry silently reads as "never expires".
    """
    if not issuer or not issuer.strip():
        raise ValidationError("authority issuer is required — an authority naming no issuer vouches for nothing")
    if expires is not None:
        _parse_expiry(expires, on_error="raise")
    attrs = AuthorityAttrs(
        issuer=issuer,
        scope=scope,
        permissions=tuple(permissions),
        expires=expires,
        revocable=revocable,
    )
    return GlyphMetadata(
        protocol=[GlyphProtocol.NFT, GlyphProtocol.AUTHORITY],
        name=name,
        description=description,
        # Both ruff (S106) and bandit (B106) read a literal assigned to a
        # `*_token*` keyword as a credential. `token_type` is the Glyph
        # envelope's `type` string — a classification, not a secret.
        token_type="authority",  # noqa: S106  # nosec B106
        attrs=attrs.to_attrs(),
    )


def is_authority(metadata: GlyphMetadata | None) -> bool:
    """Return True if *metadata* declares the AUTHORITY marker.

    A DECLARATION, like every protocol marker: nothing on chain enforces it.
    """
    return metadata is not None and GlyphProtocol.AUTHORITY in (metadata.protocol or ())


def read_authority_attrs(metadata: GlyphMetadata | None) -> AuthorityAttrs | None:
    """Decode an authority token's ``attrs``, or ``None`` if it has none.

    Wrong-typed fields are dropped to their defaults rather than raising: this
    reads third-party tokens, and one bad field must not make the rest
    unreadable. Use :func:`validate_authority` to find out what was wrong.
    """
    if metadata is None or not isinstance(getattr(metadata, "attrs", None), dict):
        return None
    a = metadata.attrs
    issuer = a.get("issuer")
    perms = a.get("permissions")
    revocable = a.get("revocable")
    return AuthorityAttrs(
        issuer=issuer if isinstance(issuer, str) else "",
        scope=a.get("scope") if isinstance(a.get("scope"), str) else None,
        permissions=tuple(p for p in perms if isinstance(p, str)) if isinstance(perms, (list, tuple)) else (),
        expires=a.get("expires") if isinstance(a.get("expires"), str) else None,
        # Photonic defaults revocable to true; only an explicit false is false.
        revocable=revocable is not False,
    )


def validate_authority(metadata: GlyphMetadata | None) -> list[str]:
    """Return the problems with an authority token's metadata; ``[]`` if sound.

    Mirrors Photonic ``validateAuthority``. Reports rather than raises — this
    runs over tokens other people minted, and the caller decides what an
    imperfect one means.
    """
    errors: list[str] = []
    if metadata is None:
        return ["no metadata"]
    protocol = metadata.protocol or ()
    if GlyphProtocol.AUTHORITY not in protocol:
        errors.append(
            f"protocol {list(protocol)!r} does not include GlyphProtocol.AUTHORITY ({GlyphProtocol.AUTHORITY})"
        )
    if GlyphProtocol.NFT not in protocol:
        errors.append("an authority must be an NFT — a fungible authority would be divisible")
    if not isinstance(getattr(metadata, "attrs", None), dict):
        errors.append("missing attrs object")
        return errors
    # NOT an assert: `python -O` strips those, so a type narrowing written that
    # way is absent in exactly the build where a surprise would matter.
    attrs = read_authority_attrs(metadata)
    if attrs is None:  # pragma: no cover - unreachable, attrs is a dict above
        errors.append("attrs could not be decoded")
        return errors
    if not attrs.issuer:
        errors.append("issuer is required")
    if attrs.expires is not None and _parse_expiry(attrs.expires, on_error="none") is None:
        errors.append(f"expires {attrs.expires!r} is not a parseable ISO-8601 timestamp")
    return errors


def _parse_expiry(value: str, *, on_error: str) -> datetime | None:
    """Parse an ISO-8601 expiry. Naive values are read as UTC."""
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError) as exc:
        if on_error == "raise":
            raise ValidationError(f"expires {value!r} is not a parseable ISO-8601 timestamp") from exc
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def is_authority_expired(metadata: GlyphMetadata | None, *, now: datetime | None = None) -> bool:
    """Return True if the authority has an expiry and it has passed.

    An UNPARSEABLE expiry returns ``False`` — not expired — which is the same
    answer Photonic gives, and it is the dangerous direction, so
    :func:`build_authority_metadata` refuses to mint one and
    :func:`validate_authority` reports it. Check validity before trusting this.
    """
    attrs = read_authority_attrs(metadata)
    if attrs is None or attrs.expires is None:
        return False
    expiry = _parse_expiry(attrs.expires, on_error="none")
    if expiry is None:
        return False
    return expiry < (now or datetime.now(UTC))


def has_permission(metadata: GlyphMetadata | None, permission: str) -> bool:
    """Return True if the authority lists *permission*.

    Says nothing about whether the authority is valid, unexpired, or genuinely
    held — only what its metadata lists.
    """
    attrs = read_authority_attrs(metadata)
    return attrs is not None and permission in attrs.permissions


def verify_authority_gate(genesis_output_script: bytes, authority_ref: GlyphRef) -> AuthorityVerdict:
    """Was this item minted under *authority_ref*? The consensus-backed question.

    *genesis_output_script* must be the item's output script **as it was created**
    — from the reveal transaction that minted it, not from wherever the item
    lives now. Measured on a node
    (``tests/test_authority_regtest_e2e.py``): a holder can transfer a gated item
    to a plain NFT script unilaterally, keeping the ref and losing the gate. Ask
    this of a current UTXO and a holder can make the answer whatever they like.

    A positive verdict means Radiant refused to create that output unless the
    minting transaction's input ref set contained *authority_ref* — i.e. the
    minter held the authority token. It does NOT mean the authority is still
    valid, unexpired, or unrevoked; those are metadata questions.
    """
    parsed = parse_authority_gated_script(genesis_output_script)
    if parsed is None:
        return AuthorityVerdict(
            valid=False,
            basis=AuthorityBasis.NONE,
            reason="the genesis output is not an authority-gated script",
        )
    gate_ref, _item_ref, _pkh = parsed
    if gate_ref != authority_ref:
        return AuthorityVerdict(
            valid=False,
            basis=AuthorityBasis.NONE,
            reason=(
                f"the genesis output is gated on {gate_ref.txid}:{gate_ref.vout}, "
                f"not on {authority_ref.txid}:{authority_ref.vout}"
            ),
            authority_ref=gate_ref,
        )
    return AuthorityVerdict(
        valid=True,
        basis=AuthorityBasis.GATE,
        reason="consensus refused to create this output without the authority ref among the inputs",
        authority_ref=gate_ref,
    )


def verify_authority_claim(
    authority_ref: GlyphRef,
    verdicts: Sequence[RelationshipVerdict],
) -> AuthorityVerdict:
    """Does the item's ``by`` claim on *authority_ref* stand up?

    Deliberately takes VERDICTS rather than metadata. Photonic's
    ``verifyAuthorityChain`` matches the ``by`` field against a candidate
    authority's ref and reports success on a string match — so a forger who
    writes a real issuer's ref into their own ``by`` passes it. ``by`` is an
    operator assertion; only :func:`~pyrxd.glyph.relationships.verify_relationship_claims`
    can say whether anything authorised it.

    Pass the verdicts that function returned for the item's reveal transaction.
    An UNBACKED author claim is reported as unproven, not as an issuer.
    """
    for verdict in verdicts:
        if verdict.kind is not RelationshipKind.AUTHOR or verdict.ref != authority_ref:
            continue
        if not verdict.backed:
            return AuthorityVerdict(
                valid=False,
                basis=AuthorityBasis.NONE,
                reason=(
                    "the item declares this authority in `by`, but nothing authorised the claim — "
                    "anyone can write any ref there"
                ),
                authority_ref=authority_ref,
            )
        how = (
            "the reveal spent the authority itself"
            if verdict.backing is RelationshipBacking.DIRECT
            else ("a delegate whose base held the authority was burned by the reveal")
        )
        return AuthorityVerdict(
            valid=True,
            basis=AuthorityBasis.BACKED_CLAIM,
            reason=f"the `by` claim is backed: {how}",
            authority_ref=authority_ref,
        )
    return AuthorityVerdict(
        valid=False,
        basis=AuthorityBasis.NONE,
        reason=f"the item makes no `by` claim on {authority_ref.txid}:{authority_ref.vout}",
        authority_ref=authority_ref,
    )
