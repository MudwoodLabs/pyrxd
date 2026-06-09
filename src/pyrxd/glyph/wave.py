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

from ..security.errors import ValidationError
from .types import GlyphMetadata, GlyphProtocol

if TYPE_CHECKING:
    from ..network.electrumx import ElectrumXClient
    from ..network.rxindexer import RxinDexerClient


SCHEME_ADDRESS: Final = "address"
"""``target_type`` value for plain Radiant addresses."""


@dataclass(frozen=True)
class WaveAttrs:
    """Parsed WAVE attrs dict, mirroring the on-chain Photonic shape."""

    name: str
    domain: str
    target: str
    target_type: str = SCHEME_ADDRESS

    def to_dict(self) -> dict[str, str]:
        """Serialize as the CBOR ``attrs`` dict."""
        return {
            "name": self.name,
            "domain": self.domain,
            "target": self.target,
            "target_type": self.target_type,
        }

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


def build_wave_metadata(
    *,
    qualified_name: str,
    target: str,
    target_type: str = SCHEME_ADDRESS,
    description: str = "",
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
    if not label or not label.isprintable() or len(label) > 255:
        raise ValidationError(f"WAVE label {label!r} must be non-empty printable ASCII, max 255 chars")
    if not domain or not domain.isprintable() or len(domain) > 255:
        raise ValidationError(f"WAVE domain {domain!r} must be non-empty printable ASCII, max 255 chars")
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
        """
        try:
            result = await self.client.wave_resolve(name)
        except Exception as exc:
            raise WaveResolverError(f"wave.resolve({name!r}) failed: {exc}") from exc
        if result is None:
            raise WaveNameNotFound(name)
        return WaveRecord.from_indexer_response(result)

    async def check_available(self, name: str) -> bool:
        """Return True if `name` is not yet registered."""
        try:
            return await self.client.wave_check_available(name)
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

    @classmethod
    def from_indexer_response(cls, data: dict[str, Any]) -> WaveRecord:
        """Build a WaveRecord from the JSON-RPC response.

        Tolerant of field naming — RXinDexer's response wraps things in
        ``attrs`` or surfaces them top-level depending on version. Tries
        both shapes before erroring.
        """
        if not isinstance(data, dict):
            raise WaveResolverError(f"expected dict, got {type(data).__name__}")
        # Some indexer versions wrap the data under "attrs".
        attrs = data.get("attrs") if isinstance(data.get("attrs"), dict) else data
        try:
            return cls(
                name=str(attrs["name"]),
                target=str(attrs["target"]),
                target_type=str(attrs.get("target_type", SCHEME_ADDRESS)),
                claim_txid=str(data.get("claim_txid") or data.get("txid") or ""),
                block_height=int(data.get("block_height") or data.get("height") or 0),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise WaveResolverError(f"could not parse indexer response: {exc}") from exc


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
