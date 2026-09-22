"""WAVE name protocol helpers — Photonic-compatible shape.

WAVE is the on-chain naming protocol used on Radiant mainnet. The canonical
shape (matching `Photonic Wallet's wave.ts` and what `RXinDexer` and other
indexers parse) carries the name in a nested ``attrs`` dict:

.. code-block:: json

    {
        "p": [2, 5, 11],
        "attrs": {
            "name": "alice.rxd",
            "domain": "rxd",
            "target": "<radiant_address>",
            "target_type": "address"
        }
    }

This module provides :func:`build_wave_metadata` to construct
``GlyphMetadata`` with this shape, and :class:`WaveAttrs` to parse it back
from on-chain CBOR.

Legacy pyrxd WAVE tokens stored the name as a top-level ``name`` field —
the validator in :meth:`GlyphBuilder.prepare_wave_reveal` accepts both for
backwards compatibility, but only the canonical shape is indexed by
RXinDexer.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final

if TYPE_CHECKING:
    from ..constants import Network

from ..network._guards import finite_int
from ..security.errors import ValidationError
from .types import GlyphMetadata, GlyphProtocol

if TYPE_CHECKING:
    from ..network.electrumx import ElectrumXClient
    from ..network.rxindexer import RxinDexerClient


SCHEME_ADDRESS: Final = "address"
"""``target_type`` value for plain Radiant addresses."""


def _optional_int(value: object) -> int | None:
    """Read an optional integer attr, or refuse it. Never silently drop.

    ACCEPTS A DIGIT STRING, because that is the form the mint reader ALWAYS produces.
    `GlyphMetadata.attrs` is `dict[str, str]` (`payload.py`'s `_decode_attrs` stringifies every
    value), so a mint's CBOR integer `expires` reaches this function as `'1850743929'`. Demanding
    an `int` therefore refused every real mainnet WAVE mint: `wave_attrs_from_metadata` returned
    `None` and `classify_glyph_metadata` fell through to `'mut'`, so a WAVE name stopped being a
    WAVE name through the public facade - strictly worse than the dropped field this was added to
    fix, because the whole record was lost rather than one key.

    The fact that falsifies the int-only rule is written down twice in this same change - in
    `mutable_chain.fold_chain`'s docstring and in the fold decision record, both noting that the
    two readers disagree on value TYPE. It was applied to the fold and not here.

    A bool is still refused explicitly: `isinstance(True, int)` is True in Python, so `expires:
    true` would otherwise be carried as 1 - a timestamp in 1970.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        raise ValidationError(f"WAVE attrs 'expires' must be a number, got {type(value).__name__}")
    if isinstance(value, int):
        return value
    # A WHOLE FLOAT IS AN INT HERE, because it already is everywhere else in this codebase:
    # `network._guards.finite_int` accepts `1850743929.0` and refuses `1.5`, Infinity and NaN,
    # and CBOR can carry any of them. Refusing a whole float only here made one field stricter
    # than the rule the rest of the SDK applies to numbers off the wire, for no stated reason.
    if isinstance(value, float):
        try:
            return finite_int(value)
        except ValueError as exc:
            raise ValidationError(f"WAVE attrs 'expires' is not a whole number: {exc}") from exc
    # Only a plain non-negative decimal string: the stringified form of an integer, and nothing
    # that `int()` would otherwise accept (whitespace, signs, underscores, unicode digits).
    if isinstance(value, str) and value.isascii() and value.isdigit():
        return int(value)
    raise ValidationError(f"WAVE attrs 'expires' must be a number or its decimal string, got {type(value).__name__}")


@dataclass(frozen=True)
class WaveAttrs:
    """Parsed WAVE attrs dict, mirroring the on-chain Photonic shape."""

    name: str
    domain: str
    target: str
    target_type: str = SCHEME_ADDRESS
    #: CBOR ``attrs.expires``, when the record carried one.
    #:
    #: MODELLED BECAUSE IT WAS BEING DROPPED. `from_dict` read four keys and ignored the rest, so
    #: a real mainnet record round-tripped `[domain, expires, name, target, target_type]` back out
    #: as `[domain, name, target, target_type]` - silently, and for the one field that decides
    #: whether a name was even held at a given time.
    #:
    #: NOT AUTHORITATIVE, and callers must not read it as an expiry. Photonic states in its own
    #: source that "the indexer is the authority on renewals ... the attrs.expires written here is
    #: display-level": real expiry follows from treasury payments this type never sees. It is
    #: carried so a round trip is lossless, not so anything can be concluded from it.
    expires: int | None = None

    def to_dict(self) -> dict[str, object]:
        """Serialize as the CBOR ``attrs`` dict.

        ``expires`` is emitted ONLY when set, so a record that never carried one still mints the
        exact four-key map it always did - adding a field to this type must not change the bytes
        pyrxd publishes for callers that never asked for it.
        """
        d: dict[str, object] = {
            "name": self.name,
            "domain": self.domain,
            "target": self.target,
            "target_type": self.target_type,
        }
        if self.expires is not None:
            d["expires"] = self.expires
        return d

    @classmethod
    def from_dict(cls, d: dict) -> WaveAttrs:
        """Parse from a CBOR ``attrs`` dict; rejects missing required fields."""
        required = ("name", "domain", "target")
        missing = [k for k in required if k not in d]
        if missing:
            raise ValidationError(f"WAVE attrs missing required fields: {missing}")
        return cls(
            name=str(d["name"]),
            domain=str(d["domain"]),
            target=str(d["target"]),
            target_type=str(d.get("target_type", SCHEME_ADDRESS)),
            # Refused rather than coerced when unusable: `int("soon")` raises, and silently
            # dropping it would reintroduce exactly the loss this field was added to stop.
            expires=_optional_int(d.get("expires")),
        )


def split_qualified_name(qualified: str) -> tuple[str, str]:
    """Split ``"alice.rxd"`` into ``("alice", "rxd")``.

    Names with no domain (e.g. ``"alice"``) default to domain ``"rxd"`` —
    matching Photonic's behavior. Names with multiple dots use the LAST dot
    as the domain separator (so ``"foo.bar.rxd"`` is ``("foo.bar", "rxd")``).
    """
    if "." not in qualified:
        return qualified, "rxd"
    label, _, domain = qualified.rpartition(".")
    if not label or not domain:
        raise ValidationError(
            f"qualified name {qualified!r} has empty label or domain — expected 'name.domain' (e.g. 'alice.rxd')"
        )
    return label, domain


def validate_wave_text(text: str, *, field: str = "WAVE label", allow_confusable: bool = False) -> None:
    """Refuse WAVE text that is empty, unprintable, over-long, or impersonating Latin.

    THE ONE PLACE THIS RULE LIVES. It was written out twice — here and in
    :meth:`GlyphBuilder.prepare_wave_reveal` — with the same three clauses and the same
    wrong error message, which said "printable ASCII" while :meth:`str.isprintable` accepts
    any printable Unicode. Two copies of a rule is how one of them gets a check the other
    does not; the homograph clause below is exactly that check.

    ON THE HOMOGRAPH CLAUSE. ``looks_confusable_with_latin`` has shipped since before
    v0.18.0 and was wired into the INSPECT path only — a reader was told a name mimics Latin
    letters, while the mint path that creates such a name accepted it without comment. For a
    name registry that asymmetry is backwards: refusing to create a spoof is worth more than
    labelling one after it is on-chain and someone else owns it.

    It flags impersonation, NOT non-Latin script. ``"トークン"``, ``"中文"``, ``"Café"``,
    ``"Łódź"`` and ``"Œuf"`` all pass; ``"casіno"`` (Cyrillic і), ``"USDС"`` (Cyrillic С),
    ``"𝐔𝐒𝐃𝐂"`` (Mathematical Bold) and a string carrying a bidi override do not. Set
    ``allow_confusable=True`` to mint one deliberately — a registrar reclaiming a spoof of
    its own brand is honest work, and a guard that cannot be overridden becomes a reason to
    route around the guard.
    """
    if not text or not text.isprintable() or len(text) > 255:
        raise ValidationError(f"{field} {text!r} must be non-empty, printable, and at most 255 characters")
    if allow_confusable:
        return
    # Lazy: confusables.py carries a vendored TR39 table, and wave metadata is built in
    # contexts (the Pyodide inspect build) that should not pay for it unless they mint.
    from .confusables import looks_confusable_with_latin

    if looks_confusable_with_latin(text):
        raise ValidationError(
            f"{field} {text!r} contains characters that mimic Latin letters, so it can be "
            f"mistaken on sight for a different name. Pass allow_confusable=True if this is "
            f"deliberate."
        )


def build_wave_metadata(
    *,
    qualified_name: str,
    target: str,
    target_type: str = SCHEME_ADDRESS,
    description: str = "",
    allow_confusable: bool = False,
) -> GlyphMetadata:
    """Construct a Photonic-compatible WAVE :class:`GlyphMetadata`.

    :param qualified_name: e.g. ``"alice.rxd"`` — split into name + domain.
    :param target: the address (or other identifier) the name resolves to.
    :param target_type: ``"address"`` by default; other values are reserved
        for future schemas (e.g. ``"cross_chain"``).
    :param description: optional human-readable description; stored as
        top-level ``desc`` in CBOR (NOT inside ``attrs``).

    The returned metadata has protocol ``[NFT, MUT, WAVE]`` and an ``attrs``
    dict matching the Photonic on-chain shape — pass it through
    :func:`encode_payload` and then :meth:`GlyphBuilder.prepare_wave_reveal`
    to construct the actual reveal transaction.

    The top-level ``name`` field on :class:`GlyphMetadata` is intentionally
    left empty: validation in ``prepare_wave_reveal`` prefers ``attrs.name``,
    and emitting both would create ambiguity if they ever disagree.
    """
    label, domain = split_qualified_name(qualified_name)
    validate_wave_text(label, field="WAVE label", allow_confusable=allow_confusable)
    validate_wave_text(domain, field="WAVE domain", allow_confusable=allow_confusable)
    if not target:
        raise ValidationError("WAVE target must not be empty")

    attrs = WaveAttrs(
        name=qualified_name,
        domain=domain,
        target=target,
        target_type=target_type,
    )
    return GlyphMetadata(
        protocol=[GlyphProtocol.NFT, GlyphProtocol.MUT, GlyphProtocol.WAVE],
        attrs=attrs.to_dict(),
        description=description,
    )


def extract_wave_attrs(cbor_data: dict) -> WaveAttrs | None:
    """Pull :class:`WaveAttrs` out of a decoded CBOR payload, if present.

    Returns ``None`` for non-WAVE payloads or WAVE payloads using only the
    legacy top-level ``name`` shape (those exist on-chain but RXinDexer
    won't index them).
    """
    protocol = cbor_data.get("p", [])
    if GlyphProtocol.WAVE not in protocol:
        return None
    attrs = cbor_data.get("attrs")
    if not isinstance(attrs, dict) or not attrs.get("name"):
        return None
    try:
        return WaveAttrs.from_dict(attrs)
    except ValidationError:
        return None


def wave_attrs_from_metadata(metadata: GlyphMetadata) -> WaveAttrs | None:
    """Convenience wrapper: extract :class:`WaveAttrs` from a parsed
    :class:`GlyphMetadata` (typically from
    :meth:`GlyphInspector.extract_reveal_metadata`).

    Returns ``None`` for non-WAVE metadata or legacy-shape WAVE without
    ``attrs.name`` (which RXinDexer cannot index).
    """
    if GlyphProtocol.WAVE not in metadata.protocol:
        return None
    if not metadata.attrs or not metadata.attrs.get("name"):
        return None
    try:
        return WaveAttrs.from_dict(metadata.attrs)
    except ValidationError:
        return None


def _import_rxindexer_error_base() -> type[Exception]:
    """Get the RxinDexerError base class without triggering an import cycle.

    Done at module load (not lazy) because the WaveResolverError class
    statement that uses it needs the class object NOW. Network module
    importing the glyph module is fine; the cycle would only matter if
    network imported back from glyph (it doesn't).
    """
    from ..network.rxindexer import RxinDexerError

    return RxinDexerError


WaveResolverError = type(
    "WaveResolverError",
    (_import_rxindexer_error_base(),),
    {
        "__doc__": "Raised when a WAVE name resolution call fails for any reason. "
        "Subclass of RxinDexerError — catch either to handle indexer failures."
    },
)


class WaveNameNotFound(WaveResolverError):
    """Raised when the requested name does not exist in the indexer."""


class WaveResolver:
    """High-level WAVE name resolver — composes :class:`RxinDexerClient`.

    Accepts either an :class:`ElectrumXClient` (auto-wraps in
    :class:`RxinDexerClient`) or an existing :class:`RxinDexerClient`. The
    latter is preferred when you have other indexer use cases (Glyph
    metadata lookups, Swap state, etc.) so the same client is shared.

    All methods raise :class:`WaveResolverError` (a subclass of
    :class:`RxinDexerError`) on transport / parse failures. Name-not-found
    raises :class:`WaveNameNotFound` so callers can distinguish "does not
    exist" from "indexer is down".
    """

    def __init__(self, client: ElectrumXClient | RxinDexerClient):
        # Lazy import keeps glyph/wave usable without pulling in the network
        # stack for callers that only build/parse metadata.
        from ..network.rxindexer import RxinDexerClient

        if isinstance(client, RxinDexerClient):
            self.client = client
        else:
            self.client = RxinDexerClient(client)

    async def resolve(self, name: str) -> WaveRecord:
        """Look up a qualified WAVE name (e.g. ``"alice.rxd"``).

        Raises :class:`WaveNameNotFound` if the name is not registered.
        Raises :class:`WaveResolverError` on transport / parse failures.

        THE INDEXER WANTS THE LABEL, NOT THE QUALIFIED NAME. RXinDexer's ``resolve()`` runs
        ``validate_wave_name`` before anything else, and ``.`` is not in its ``WAVE_CHARS``, so
        ``"alice.rxd"`` is answered with ``{"error": "Invalid character: ."}`` — measured against
        the public ``electrumx.radiantcore.org`` indexer 2026-09-16 and confirmed in
        ``electrumx/server/wave_index.py`` upstream. This method sent the qualified name, so it
        never resolved a real name against the canonical indexer. The label is sent now, and an
        ``error`` key in the answer is raised rather than parsed as a record.
        """
        label, _domain = split_qualified_name(name)
        try:
            result = await self.client.wave_resolve(label.strip().lower())
        except Exception as exc:
            raise WaveResolverError(f"wave.resolve({name!r}) failed: {exc}") from exc
        if result is None:
            raise WaveNameNotFound(name)
        if isinstance(result, dict) and "error" in result and "name" not in result:
            raise WaveResolverError(f"wave.resolve({name!r}) was refused by the indexer: {result['error']}")
        return WaveRecord.from_indexer_response(result)

    async def check_available(self, name: str) -> bool:
        """Return True if `name` is not yet registered.

        SENDS THE LABEL, NOT THE QUALIFIED NAME — the same rule :meth:`resolve` documents.
        ``resolve`` was corrected in #695 and this twin was left sending ``"alice.rxd"``, which
        ``validate_wave_name`` refuses; the refusal came back as an ``{"error": ...}`` dict,
        which the client then reported as *available*. Fixing one caller of a shared rule and
        not the other is how that gap survived.
        """
        label, _domain = split_qualified_name(name)
        try:
            return await self.client.wave_check_available(label.strip().lower())
        except Exception as exc:
            raise WaveResolverError(f"wave.check_available({name!r}) failed: {exc}") from exc

    async def reverse_lookup(self, address: str) -> list[str]:
        """Return the list of WAVE names that resolve to `address`."""
        try:
            return await self.client.wave_reverse_lookup(address)
        except Exception as exc:
            raise WaveResolverError(f"wave.reverse_lookup({address!r}) failed: {exc}") from exc

    async def stats(self) -> dict[str, Any]:
        """Return indexer-level stats — useful for health checks."""
        try:
            stats = await self.client.wave_stats()
        except Exception as exc:
            raise WaveResolverError(f"wave.stats failed: {exc}") from exc
        return stats.raw or {}


@dataclass(frozen=True)
class WaveRecord:
    """A full WAVE registration, as returned by ``wave.resolve``.

    The exact response shape from RXinDexer is documented at
    https://github.com/Radiant-Core/RXinDexer; this class normalizes the
    minimum fields a swap coordinator needs.
    """

    name: str  # e.g. "alice.rxd"
    target: str  # the address (or other identifier) the name resolves to
    target_type: str  # typically "address"
    claim_txid: str  # the on-chain registration tx
    block_height: int  # height at which the name was first claimed
    #: The indexer's ref string, verbatim (RXinDexer: ``"<reveal_txid>_0"``). A WAVE ref is the
    #: REVEAL outpoint — upstream's own comment: "a WAVE ref is the *reveal* outpoint
    #: (reveal_txid:0)" — so its txid is the mint a mutable-chain walk starts from.
    ref: str = ""
    #: Lifecycle as the indexer reports it: ``"active"``, ``"grace"``, or absent. A lapsed name
    #: does not resolve at all (the indexer returns ``None``), so this is never ``"expired"`` here.
    status: str = ""

    @property
    def reveal_txid(self) -> str:
        """The txid half of ``ref``, or ``""`` if the indexer gave no usable ref.

        Accepts ``txid_vout`` (RXinDexer) and ``txid:vout``. Anything that is not 64 hex
        characters before the separator is reported as absent rather than passed on to a
        network fetch that would then fail somewhere less legible.
        """
        head = self.ref.replace(":", "_").split("_", 1)[0].strip().lower()
        if len(head) == 64 and all(c in "0123456789abcdef" for c in head):
            return head
        return ""

    @classmethod
    def from_indexer_response(cls, data: dict[str, Any]) -> WaveRecord:
        """Build a WaveRecord from the JSON-RPC response.

        Tolerant of field naming — RXinDexer's response wraps things in
        ``attrs`` or surfaces them top-level depending on version. Tries
        both shapes before erroring.

        Measured shape from the public indexer, 2026-09-16::

            {"name": "custodian-gate-x7f3", "ref": "<reveal_txid>_0", "target": "14Xm…",
             "zone": {"address": "14Xm…"}, "owner": "<11-byte hashX hex>", "available": false,
             "canonical": true, "has_duplicates": false, "expires": 1850744391, "status": "active"}

        ``name`` comes back as the bare label; it is re-qualified here so callers see the same
        ``alice.rxd`` they asked for. ``claim_txid`` falls back to the ref's txid, which IS the
        registration transaction.
        """
        if not isinstance(data, dict):
            raise WaveResolverError(f"expected dict, got {type(data).__name__}")
        # Some indexer versions wrap the data under "attrs".
        attrs = data.get("attrs") if isinstance(data.get("attrs"), dict) else data
        try:
            name = str(attrs["name"])
            if "." not in name:
                name = f"{name}.rxd"
            ref = str(data.get("ref") or "")
            ref_txid = ref.replace(":", "_").split("_", 1)[0] if ref else ""
            return cls(
                name=name,
                target=str(attrs["target"]),
                target_type=str(attrs.get("target_type", SCHEME_ADDRESS)),
                claim_txid=str(data.get("claim_txid") or data.get("txid") or ref_txid or ""),
                block_height=int(data.get("block_height") or data.get("height") or 0),
                ref=ref,
                status=str(data.get("status") or ""),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise WaveResolverError(f"could not parse indexer response: {exc}") from exc


async def wave_names_for_hash160(client, pubkey_hash160: bytes, *, network: Network | None = None) -> list[str]:
    """WAVE names owned by the address a public-key hash encodes.

    The bridge between a KEY and a NAME: a hash160 is what a P2PKH address
    encodes, and WAVE resolves names to addresses, so the reverse lookup answers
    "which names does the holder of this key own".

    Written for HashMark v2 attestation — a verified signer is a hash160, and the
    question a recipient actually has is "was this recorded by company.rxd?" — but
    nothing here is HashMark-specific.

    CALLERS MUST ONLY PASS A KEY THEY HAVE VERIFIED. Resolving an unproven signer
    would dress a claim up as an identity, which is precisely the failure the
    signature check exists to prevent. See
    :func:`pyrxd.script.hashmark.verify_attestation`.
    """
    from ..base58 import base58check_encode
    from ..constants import NETWORK_ADDRESS_PREFIX_DICT, Network

    if len(pubkey_hash160) != 20:
        raise ValidationError(f"pubkey_hash160 must be 20 bytes, got {len(pubkey_hash160)}")
    address = base58check_encode(NETWORK_ADDRESS_PREFIX_DICT[network or Network.MAINNET] + pubkey_hash160)
    return await WaveResolver(client).reverse_lookup(address)


def classify_glyph_metadata(metadata: GlyphMetadata) -> str:
    """Return the highest-specificity protocol classification for a metadata payload.

    Examples:
        ``[NFT, MUT, WAVE]`` → ``"wave"`` (when attrs.name present)
        ``[NFT, MUT, WAVE]`` without attrs.name → ``"mut"`` (legacy, won't resolve)
        ``[NFT, MUT, CONTAINER]`` → ``"container"``
        ``[NFT, MUT]`` → ``"mut"``
        ``[NFT, AUTHORITY]`` → ``"authority"``
        ``[NFT, ENCRYPTED, TIMELOCK]`` → ``"timelock"``
        ``[NFT, ENCRYPTED]`` → ``"encrypted"``
        ``[NFT]`` → ``"nft"``
        ``[FT, DMINT]`` → ``"dmint"``
        ``[FT]`` → ``"ft"``
        ``[DAT]`` → ``"dat"``

    The string mirrors :attr:`GlyphOutput.glyph_type` values where applicable,
    with extensions for the metadata-only types that scripts alone can't
    distinguish (WAVE/CONTAINER/ENCRYPTED/TIMELOCK/AUTHORITY share script
    templates with MUT/NFT, and DAT is data-only).

    Ordering is highest-specificity-first: TIMELOCK is checked before
    ENCRYPTED (TIMELOCK *requires* ENCRYPTED per the protocol rules in
    :mod:`~pyrxd.glyph.types`, so a timelocked token always carries both).
    """
    p = set(metadata.protocol)
    if GlyphProtocol.WAVE in p and wave_attrs_from_metadata(metadata) is not None:
        return "wave"
    if GlyphProtocol.CONTAINER in p:
        return "container"
    # ...or the `type` STRING, which is the form the chain actually carries (#578).
    # Kept in step with the deliberate mirror of this function in
    # `_inspect_core._classify_metadata_protocol`; see the note there.
    if (metadata.token_type or "").strip().lower() == "container":
        return "container"
    if GlyphProtocol.AUTHORITY in p:
        return "authority"
    if GlyphProtocol.TIMELOCK in p:
        return "timelock"
    if GlyphProtocol.ENCRYPTED in p:
        return "encrypted"
    if GlyphProtocol.DMINT in p:
        return "dmint"
    if GlyphProtocol.MUT in p:
        return "mut"
    if GlyphProtocol.DAT in p:
        return "dat"
    if GlyphProtocol.FT in p:
        return "ft"
    if GlyphProtocol.NFT in p:
        return "nft"
    return "unknown"
