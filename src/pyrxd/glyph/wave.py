"""WAVE name protocol helpers — Photonic-compatible shape.

WAVE is the on-chain naming protocol used on Radiant mainnet. A claim's shape is
the one Photonic Wallet builds (``createWaveNameMetadata``,
``packages/lib/src/wave.ts`` at Radiant-Core/Photonic-Wallet ``becf41a7``, lines
71-109): the QUALIFIED name at the top level, and the BARE LABEL in ``attrs.name``
with its domain in ``attrs.domain``:

.. code-block:: json

    {
        "v": 2,
        "p": [2, 5, 11],
        "name": "alice.rxd",
        "type": "wave_name",
        "attrs": {
            "name": "alice",
            "domain": "rxd",
            "target": "<radiant_address>",
            "target_type": "address"
        }
    }

RXinDexer (``electrumx/server/wave_index.py``) registers the claim from
``attrs.name``, and ``validate_wave_name`` refuses any character outside
``a-z 0-9 -``. The rule every claim pyrxd writes must meet lives in
:mod:`pyrxd.glyph.wave_rules`.

WHAT IS PROVED ABOUT THIS SHAPE, and what is not
(``tests/test_wave_claim_registers_with_the_indexer.py``): the FIELD SET and values
:func:`build_wave_metadata` writes are those of Photonic's ``createWaveNameMetadata``, and
its bytes equal those of mainnet claim ``f644794b…``, which the public indexer resolves.
That claim was NOT encoded by Photonic's own path: it is canonical CBOR (short map headers,
sorted keys) with no ``desc``, while Photonic's ``cbor-x`` ``encode`` writes 16-bit map
headers in object order and its register page always sets ``desc``.

THREE SHAPES A READER MAY MEET, and has to tell apart:

- Photonic's, above. Registered by the indexer's live claim path.
- pyrxd through 0.24.0 (#728): ``attrs.name`` carried the QUALIFIED name
  (``"alice.rxd"``) and the top-level ``name`` was empty. By RXinDexer's source such a
  claim is skipped without an error, because ``validate_wave_name`` refuses the ``.`` —
  read from source; no pyrxd-built claim has been checked against a live indexer.
  :class:`WaveAttrs` still parses them, verbatim; pyrxd refuses to write a new one.
- Older pyrxd, with only a top-level ``name``. The indexer's LIVE claim path skips it (no
  ``attrs.name``); only its one-time backfill of an empty index would register it.
  :func:`extract_wave_attrs` returns ``None`` for it, and pyrxd refuses to write one.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final

if TYPE_CHECKING:
    from ..constants import Network

from ..network._guards import finite_int
from ..security.errors import ValidationError
from .types import GlyphMetadata, GlyphProtocol
from .wave_rules import WAVE_ROOT_DOMAIN, parse_wave_name

if TYPE_CHECKING:
    from ..network.electrumx import ElectrumXClient
    from ..network.rxindexer import RxinDexerClient


SCHEME_ADDRESS: Final = "address"
"""``target_type`` value for plain Radiant addresses."""

WAVE_NAME_TYPE: Final = "wave_name"
"""The top-level ``type`` Photonic writes on a WAVE claim (``createWaveNameMetadata``)."""


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
    """Parsed WAVE attrs dict, mirroring the on-chain Photonic shape.

    ``name`` is carried VERBATIM, not normalised. On a Photonic claim, and on one pyrxd
    builds now, it is the bare label (``"alice"``) and ``domain`` holds the rest. On a claim
    pyrxd built through 0.24.0 it is the qualified name (``"alice.rxd"``), which RXinDexer
    does not index (see the module docstring). A reader that appends ``domain`` must check
    for a ``.`` first, or it prints ``alice.rxd.rxd`` for the older shape.
    """

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
    """Split ``"alice.rxd"`` into ``("alice", "rxd")``, for LOOKUPS.

    Names with no domain (e.g. ``"alice"``) default to domain ``"rxd"``. Names with
    multiple dots use the LAST dot as the domain separator (so ``"foo.bar.rxd"`` is
    ``("foo.bar", "rxd")``) — which is NOT how Photonic splits (it takes the first dot),
    so this is not used to BUILD a claim: :func:`build_wave_metadata` and
    :meth:`GlyphBuilder.prepare_wave_reveal` use
    :func:`~pyrxd.glyph.wave_rules.parse_wave_name`, which refuses any name that is not
    ``<label>.rxd``. Here, a dotted label reaches the indexer as-is and is refused there.
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
    expires: int | None = None,
) -> GlyphMetadata:
    """Construct a WAVE claim's :class:`GlyphMetadata` with Photonic's fields.

    :param qualified_name: ``"<label>.rxd"``, or a bare ``"<label>"``, which means the same.
        The label must meet the rule in :mod:`pyrxd.glyph.wave_rules` — 3-63 characters of
        lowercase ``a-z``, ``0-9`` and ``-``, no leading or trailing ``-``, and ``--`` only in an
        ``xn--`` punycode label — and the domain must be exactly ``rxd``. Anything else is
        refused here, because the indexer would decline the claim after it had confirmed.
    :param target: the address (or other identifier) the name resolves to.
    :param target_type: ``"address"`` by default; other values are reserved
        for future schemas (e.g. ``"cross_chain"``).
    :param description: optional human-readable description; stored as
        top-level ``desc`` in CBOR (NOT inside ``attrs``).
    :param expires: optional unix-seconds ``attrs.expires``. Photonic always writes one
        (``now + 2 years``); pyrxd writes it only when given, so the bytes do not depend on
        the clock. It is display-level on both sides: RXinDexer stamps the real term from
        the registration BLOCK time and ignores this field for expiry.

    The fields are those of Photonic's ``createWaveNameMetadata`` (``v`` 2, protocol
    ``[NFT, MUT, WAVE]``, top-level ``name`` = the qualified name, ``type`` =
    ``"wave_name"``, ``attrs`` = bare label, domain, target, target type). Pass the result
    to :meth:`GlyphBuilder.prepare_commit` and then :meth:`GlyphBuilder.prepare_wave_reveal`.

    THE LABEL GOES IN ``attrs.name``, NOT THE QUALIFIED NAME. Through 0.24.0 this function
    wrote ``attrs.name = "alice.rxd"`` and left the top level empty. RXinDexer registers a
    claim from ``attrs.name`` and its ``validate_wave_name`` refuses the ``.``, so by the
    indexer's source no claim this function built was registered (#728; read from source,
    not observed against a live indexer).

    There is no homograph option. The label rule is ASCII-only, so a NON-ASCII look-alike
    label is refused by construction; a non-ASCII name is written as its ``xn--`` punycode.
    An all-ASCII look-alike (``paypa1``) is not refused, and #698's check did not refuse one
    either.
    """
    label = parse_wave_name(qualified_name)
    if not target:
        raise ValidationError("WAVE target must not be empty")
    if expires is not None and (isinstance(expires, bool) or not isinstance(expires, int) or expires < 0):
        raise ValidationError(f"WAVE expires must be a non-negative int (unix seconds), got {expires!r}")

    attrs = WaveAttrs(
        name=label,
        domain=WAVE_ROOT_DOMAIN,
        target=target,
        target_type=target_type,
        expires=expires,
    )
    return GlyphMetadata(
        v=2,
        protocol=[GlyphProtocol.NFT, GlyphProtocol.MUT, GlyphProtocol.WAVE],
        name=f"{label}.{WAVE_ROOT_DOMAIN}",
        token_type=WAVE_NAME_TYPE,
        attrs=attrs.to_dict(),
        description=description,
    )


def extract_wave_attrs(cbor_data: dict) -> WaveAttrs | None:
    """Pull :class:`WaveAttrs` out of a decoded CBOR payload, if present.

    Returns ``None`` for non-WAVE payloads or WAVE payloads using only the
    legacy top-level ``name`` shape (those exist on-chain but RXinDexer
    won't index them). A pyrxd ≤0.24.0 claim, whose ``attrs.name`` is the qualified
    name, IS returned, with ``name`` verbatim — see :class:`WaveAttrs`.
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
    ``attrs.name`` (which RXinDexer cannot index). Like :func:`extract_wave_attrs`, it
    returns a pyrxd ≤0.24.0 claim's qualified ``attrs.name`` verbatim.
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
        ``[NFT, MUT, WAVE]`` → ``"wave"`` (when attrs.name present — including a
            pyrxd ≤0.24.0 claim whose qualified attrs.name RXinDexer does not index)
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
