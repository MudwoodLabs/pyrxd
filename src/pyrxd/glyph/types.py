from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import IntEnum
from typing import TYPE_CHECKING, Optional

from pyrxd.security.errors import ValidationError
from pyrxd.security.types import Hex20, Hex32, Txid

if TYPE_CHECKING:
    from .dmint import DmintCborPayload


class GlyphProtocol(IntEnum):
    FT = 1           # Fungible token
    NFT = 2          # Non-fungible singleton
    DAT = 3          # Data storage
    DMINT = 4        # dMint (combined with FT: [1, 4])
    MUT = 5          # Mutable
    BURN = 6         # Explicit burn
    CONTAINER = 7    # Collection
    ENCRYPTED = 8    # Encrypted content
    TIMELOCK = 9     # Timelocked reveal (requires ENCRYPTED)
    AUTHORITY = 10   # Issuer authority
    WAVE = 11        # On-chain naming


@dataclass(frozen=True)
class GlyphRef:
    """36-byte Glyph reference: txid (reversed LE) + vout (4-byte LE)."""

    txid: Txid   # hex txid (not reversed)
    vout: int    # output index

    def __post_init__(self) -> None:
        if self.vout < 0 or self.vout > 0xFFFFFFFF:
            raise ValidationError("vout must be 0..2^32-1")

    def to_bytes(self) -> bytes:
        """Encode as 36-byte wire format: txid_reversed + vout_le."""
        return bytes.fromhex(self.txid)[::-1] + struct.pack('<I', self.vout)

    @classmethod
    def from_bytes(cls, data: bytes) -> GlyphRef:
        """Parse 36-byte wire format."""
        if len(data) != 36:
            raise ValidationError(f"GlyphRef must be 36 bytes, got {len(data)}")
        txid = data[:32][::-1].hex()
        vout = struct.unpack('<I', data[32:])[0]
        return cls(txid=Txid(txid), vout=vout)


@dataclass(frozen=True)
class GlyphMedia:
    mime_type: str  # e.g. "image/webp"
    data: bytes     # raw binary

    def __post_init__(self) -> None:
        if not self.mime_type or '/' not in self.mime_type:
            raise ValidationError("Invalid MIME type")
        if len(self.data) > 100_000:  # 100KB limit for on-chain media
            raise ValidationError("On-chain media too large (max 100KB)")


_VALID_PROTOCOL_VALUES = frozenset(p.value for p in GlyphProtocol)
_IMAGE_SHA256_RE = None  # lazy-compiled below


# ---------------------------------------------------------------------------
# V2 sub-objects (mirror of GlyphV2* types in Photonic Wallet v2metadata.ts)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class GlyphCreator:
    """Creator identity and optional ECDSA signature over the metadata commit hash.

    pubkey: 33-byte compressed secp256k1 pubkey, hex-encoded.
    sig:    DER-encoded ECDSA signature, hex-encoded (empty string = unsigned).
    algo:   Signing algorithm identifier string.
    """
    pubkey: str
    sig: str = ""
    algo: str = "ecdsa-secp256k1"

    def __post_init__(self) -> None:
        import re
        if not re.fullmatch(r'0[23][0-9a-f]{64}', self.pubkey.lower()):
            raise ValidationError(
                "creator.pubkey must be a 33-byte compressed secp256k1 pubkey "
                "(02 or 03 prefix, 66 hex chars)"
            )
        if self.sig and not re.fullmatch(r'[0-9a-f]+', self.sig.lower()):
            raise ValidationError("creator.sig must be hex-encoded DER bytes or empty string")

    def to_cbor_dict(self) -> dict:
        d: dict = {"pubkey": self.pubkey}
        if self.sig:
            d["sig"] = self.sig
        if self.algo != "ecdsa-secp256k1":
            d["algo"] = self.algo
        return d

    @classmethod
    def from_cbor_dict(cls, d: dict) -> "GlyphCreator":
        if isinstance(d, str):
            # Simple string form: just a pubkey with no sig
            return cls(pubkey=d)
        return cls(
            pubkey=str(d.get("pubkey", "")),
            sig=str(d.get("sig", "")),
            algo=str(d.get("algo", "ecdsa-secp256k1")),
        )


@dataclass(frozen=True)
class GlyphRoyalty:
    """On-chain royalty hint for secondary-market wallets.

    bps:      Basis points (100 = 1%, 500 = 5%, max 10000 = 100%).
    address:  Radiant address to receive royalty payments.
    enforced: Whether wallets should enforce this royalty.
    minimum:  Minimum royalty amount in photons (0 = no minimum).
    splits:   Optional list of (address, bps) pairs for royalty splitting.
              The sum of split bps should equal the top-level bps.
    """
    bps: int
    address: str
    enforced: bool = False
    minimum: int = 0
    splits: tuple[tuple[str, int], ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not (0 <= self.bps <= 10_000):
            raise ValidationError(f"royalty.bps must be 0..10000, got {self.bps}")
        if not self.address:
            raise ValidationError("royalty.address is required")
        if self.minimum < 0:
            raise ValidationError("royalty.minimum must be >= 0")
        if self.splits:
            for addr, split_bps in self.splits:
                if not (0 <= split_bps <= 10_000):
                    raise ValidationError(
                        f"royalty split bps must be 0..10000, got {split_bps} for '{addr}'"
                    )
            split_total = sum(b for _, b in self.splits)
            if split_total > self.bps:
                raise ValidationError(
                    f"royalty splits sum ({split_total} bps) exceeds total bps ({self.bps})"
                )

    def to_cbor_dict(self) -> dict:
        d: dict = {
            "enforced": self.enforced,
            "bps": self.bps,
            "address": self.address,
        }
        if self.minimum:
            d["minimum"] = self.minimum
        if self.splits:
            d["splits"] = [{"address": a, "bps": b} for a, b in self.splits]
        return d

    @classmethod
    def from_cbor_dict(cls, d: dict) -> "GlyphRoyalty":
        splits_raw = d.get("splits", [])
        splits = tuple(
            (str(s["address"]), int(s["bps"]))
            for s in splits_raw
            if isinstance(s, dict)
        )
        return cls(
            bps=int(d["bps"]),
            address=str(d["address"]),
            enforced=bool(d.get("enforced", False)),
            minimum=int(d.get("minimum", 0)),
            splits=splits,
        )


@dataclass(frozen=True)
class GlyphPolicy:
    """Token behaviour policy flags."""
    renderable: Optional[bool] = None   # wallets may display/render this token
    executable: Optional[bool] = None  # token contains executable content
    nsfw: Optional[bool] = None         # not safe for work
    transferable: Optional[bool] = None # False = soulbound (non-transferable)

    def to_cbor_dict(self) -> dict:
        d: dict = {}
        if self.renderable is not None:
            d["renderable"] = self.renderable
        if self.executable is not None:
            d["executable"] = self.executable
        if self.nsfw is not None:
            d["nsfw"] = self.nsfw
        if self.transferable is not None:
            d["transferable"] = self.transferable
        return d

    @classmethod
    def from_cbor_dict(cls, d: dict) -> "GlyphPolicy":
        def _opt_bool(key: str) -> Optional[bool]:
            v = d.get(key)
            return bool(v) if v is not None else None
        return cls(
            renderable=_opt_bool("renderable"),
            executable=_opt_bool("executable"),
            nsfw=_opt_bool("nsfw"),
            transferable=_opt_bool("transferable"),
        )


@dataclass(frozen=True)
class GlyphRights:
    """Licensing and attribution information."""
    license: str = ""      # SPDX identifier or URL (e.g. "CC-BY-4.0")
    terms: str = ""        # Human-readable license terms
    attribution: str = ""  # Required attribution text

    def to_cbor_dict(self) -> dict:
        d: dict = {}
        if self.license:
            d["license"] = self.license
        if self.terms:
            d["terms"] = self.terms
        if self.attribution:
            d["attribution"] = self.attribution
        return d

    @classmethod
    def from_cbor_dict(cls, d: dict) -> "GlyphRights":
        return cls(
            license=str(d.get("license", "")),
            terms=str(d.get("terms", "")),
            attribution=str(d.get("attribution", "")),
        )


@dataclass(frozen=True)
class GlyphMetadata:
    """CBOR payload for a Glyph token."""

    protocol: list[int]                           # e.g. [2] for NFT, [1] for FT, [1,4] for dMint FT
    name: str = ""
    ticker: str = ""                              # FT only
    description: str = ""
    token_type: str = ""                          # NFT type tag
    main: Optional[GlyphMedia] = None
    attrs: dict[str, str] = field(default_factory=dict)
    loc: str = ""                                 # IPFS or external URI
    loc_hash: str = ""                            # integrity hash
    decimals: int = 0                             # FT decimals (display only — consensus is 1 photon = 1 unit)
    image_url: str = ""                           # HTTPS URL for token display image
    image_ipfs: str = ""                          # IPFS CID (ipfs://... form)
    image_sha256: str = ""                        # hex SHA256 of image bytes — lets clients verify hosted image wasn't swapped
    v: Optional[int] = None                       # Glyph version (None=V1, 2=V2); indexers use this to select parser
    dmint_params: Optional["DmintCborPayload"] = None  # V2 dMint config object; required when GlyphProtocol.DMINT in protocol
    creator: Optional[GlyphCreator] = None        # V2 creator identity + optional ECDSA signature
    royalty: Optional[GlyphRoyalty] = None        # V2 royalty hint for secondary markets
    policy: Optional[GlyphPolicy] = None          # V2 behaviour flags (soulbound, nsfw, etc.)
    rights: Optional[GlyphRights] = None          # V2 licensing and attribution
    created: str = ""                             # V2 ISO8601 creation timestamp
    commit_outpoint: str = ""                     # V2 txid:vout of the commit UTXO

    def __post_init__(self) -> None:
        import re
        # protocol must be a non-empty list (or tuple) of known GlyphProtocol int values.
        # Coerce to tuple immediately so the stored value is immutable even though
        # frozen=True only prevents field reassignment, not in-place list mutation.
        if not isinstance(self.protocol, (list, tuple)):
            raise ValidationError(
                f"protocol must be a list[int], got {type(self.protocol).__name__!r}. "
                "Example: [GlyphProtocol.FT, GlyphProtocol.DMINT] or [1, 4]."
            )
        # Store as tuple for immutability (frozen dataclass prevents reassignment
        # but not list.append / list.pop on a mutable list field).
        object.__setattr__(self, 'protocol', tuple(self.protocol))
        if not self.protocol:
            raise ValidationError(
                "protocol list must not be empty. "
                "Use e.g. [GlyphProtocol.FT] or [GlyphProtocol.NFT]."
            )
        for p in self.protocol:
            if not isinstance(p, int) or isinstance(p, bool):
                raise ValidationError(
                    f"protocol values must be int, got {type(p).__name__!r}: {p!r}"
                )
            if p not in _VALID_PROTOCOL_VALUES:
                raise ValidationError(
                    f"Unknown protocol value {p!r}. "
                    f"Valid values: {sorted(_VALID_PROTOCOL_VALUES)} (see GlyphProtocol)."
                )
        # Protocol combination rules (mirrors Photonic Wallet protocols.ts §3.5).
        # FT and NFT are mutually exclusive base types.
        if GlyphProtocol.FT in self.protocol and GlyphProtocol.NFT in self.protocol:
            raise ValidationError(
                "FT (1) and NFT (2) are mutually exclusive protocol markers."
            )
        # Each extension protocol has at least one required co-protocol.
        _REQUIREMENTS: dict[int, list[int]] = {
            GlyphProtocol.DMINT:     [GlyphProtocol.FT],
            GlyphProtocol.MUT:       [GlyphProtocol.NFT],
            GlyphProtocol.CONTAINER: [GlyphProtocol.NFT],
            GlyphProtocol.ENCRYPTED: [GlyphProtocol.NFT],
            GlyphProtocol.TIMELOCK:  [GlyphProtocol.ENCRYPTED],
            GlyphProtocol.AUTHORITY: [GlyphProtocol.NFT],
            GlyphProtocol.WAVE:      [GlyphProtocol.NFT, GlyphProtocol.MUT],
        }
        for ext, required in _REQUIREMENTS.items():
            if ext in self.protocol:
                missing = [r for r in required if r not in self.protocol]
                if missing:
                    names = ", ".join(GlyphProtocol(r).name for r in missing)
                    raise ValidationError(
                        f"protocol {GlyphProtocol(ext).name} ({ext}) requires "
                        f"{names} to also be present."
                    )
        # decimals must be in a sane display range.
        if not isinstance(self.decimals, int) or isinstance(self.decimals, bool):
            raise ValidationError(f"decimals must be int, got {type(self.decimals).__name__!r}")
        if not (0 <= self.decimals <= 18):
            raise ValidationError(
                f"decimals must be 0..18 (display precision); got {self.decimals}. "
                "Negative decimals produce 10x display errors; > 18 is not meaningful."
            )
        # image_sha256 must be exactly 64 lowercase hex chars if provided.
        if self.image_sha256:
            if not re.fullmatch(r"[0-9a-f]{64}", self.image_sha256):
                raise ValidationError(
                    f"image_sha256 must be 64 lowercase hex chars (SHA-256), "
                    f"got {len(self.image_sha256)!r} chars: {self.image_sha256[:16]!r}..."
                )

    def to_cbor_dict(self) -> dict:
        """Build the dict that gets CBOR-encoded (excluding 'gly' marker)."""
        d: dict = {}
        if self.v is not None:
            d["v"] = self.v
        d["p"] = list(self.protocol)
        if self.name:
            d["name"] = self.name
        if self.ticker:
            d["ticker"] = self.ticker
        if self.description:
            d["desc"] = self.description
        if self.token_type:
            d["type"] = self.token_type
        if self.main:
            d["main"] = {"t": self.main.mime_type, "b": self.main.data}
        if self.attrs:
            d["attrs"] = self.attrs
        if self.loc:
            d["loc"] = self.loc
        if self.loc_hash:
            d["loc_hash"] = self.loc_hash
        if self.decimals:
            d["decimals"] = self.decimals
        if self.image_url:
            d["image"] = self.image_url
        if self.image_ipfs:
            d["image_ipfs"] = self.image_ipfs
        if self.image_sha256:
            d["image_sha256"] = self.image_sha256
        if self.dmint_params is not None:
            d["dmint"] = self.dmint_params.to_cbor_dict()
        if self.creator is not None:
            d["creator"] = self.creator.to_cbor_dict()
        if self.royalty is not None:
            d["royalty"] = self.royalty.to_cbor_dict()
        if self.policy is not None:
            policy_d = self.policy.to_cbor_dict()
            if policy_d:
                d["policy"] = policy_d
        if self.rights is not None:
            rights_d = self.rights.to_cbor_dict()
            if rights_d:
                d["rights"] = rights_d
        if self.created:
            d["created"] = self.created
        if self.commit_outpoint:
            d["commit_outpoint"] = self.commit_outpoint
        return d

    @classmethod
    def for_dmint_ft(
        cls,
        ticker: str,
        name: str,
        decimals: int = 0,
        description: str = "",
        image_url: str = "",
        image_ipfs: str = "",
        image_sha256: str = "",
        protocol: Optional[list[int]] = None,
        dmint_params: Optional["DmintCborPayload"] = None,
    ) -> "GlyphMetadata":
        """Construct GlyphMetadata for a dMint-marked FT deploy.

        Pass ``dmint_params`` (a ``DmintCborPayload``) to embed the dMint
        configuration object in the token metadata. Indexers and wallets use
        this to display mining parameters without parsing the contract script.

        Sets ``v=2`` automatically when ``dmint_params`` is provided.
        """
        v = 2 if dmint_params is not None else None
        return cls(
            protocol=protocol if protocol is not None else [GlyphProtocol.FT, GlyphProtocol.DMINT],
            ticker=ticker,
            name=name,
            decimals=decimals,
            description=description,
            image_url=image_url,
            image_ipfs=image_ipfs,
            image_sha256=image_sha256,
            v=v,
            dmint_params=dmint_params,
        )


@dataclass(frozen=True)
class GlyphNft:
    """A minted or transferable NFT Glyph."""

    ref: GlyphRef
    owner_pkh: Hex20    # 20-byte P2PKH hash of current owner
    metadata: GlyphMetadata


@dataclass(frozen=True)
class GlyphFt:
    """A minted or transferable FT Glyph."""

    ref: GlyphRef
    owner_pkh: Hex20
    amount: int         # in photons (Radiant satoshi equivalent)
    metadata: GlyphMetadata
