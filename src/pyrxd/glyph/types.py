from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import IntEnum
from typing import TYPE_CHECKING

from pyrxd.security.errors import ValidationError
from pyrxd.security.types import Hex20, Txid

if TYPE_CHECKING:
    # Imported only for type checking; at runtime PEP 563 makes the annotation
    # a string. .dmint imports from .types, so a runtime import here would
    # create a cycle.
    from .dmint import DmintCborPayload

    # .encrypted_content is a leaf today (it imports nothing from this package), so a runtime
    # import would not cycle — but this file's convention is annotation-only for intra-package
    # types, and a leaf can grow an import later.
    from .encrypted_content import CryptoMetadata, EncryptionMetadata, TimelockSpec


class GlyphProtocol(IntEnum):
    FT = 1  # Fungible token
    NFT = 2  # Non-fungible singleton
    DAT = 3  # Data storage
    DMINT = 4  # dMint (combined with FT: [1, 4])
    MUT = 5  # Mutable
    BURN = 6  # Explicit burn
    CONTAINER = 7  # Collection
    ENCRYPTED = 8  # Encrypted content
    TIMELOCK = 9  # Timelocked reveal (requires ENCRYPTED)
    AUTHORITY = 10  # Issuer authority
    WAVE = 11  # On-chain naming


@dataclass(frozen=True)
class GlyphRef:
    """36-byte Glyph reference: txid (reversed LE) + vout (4-byte LE)."""

    txid: Txid  # hex txid (not reversed)
    vout: int  # output index

    def __post_init__(self) -> None:
        if self.vout < 0 or self.vout > 0xFFFFFFFF:
            raise ValidationError("vout must be 0..2^32-1")

    def to_bytes(self) -> bytes:
        """Encode as 36-byte wire format: txid_reversed + vout_le."""
        return bytes.fromhex(self.txid)[::-1] + struct.pack("<I", self.vout)

    @classmethod
    def from_bytes(cls, data: bytes) -> GlyphRef:
        """Parse 36-byte wire format."""
        if len(data) != 36:
            raise ValidationError(f"GlyphRef must be 36 bytes, got {len(data)}")
        txid = data[:32][::-1].hex()
        vout = struct.unpack("<I", data[32:])[0]
        return cls(txid=Txid(txid), vout=vout)

    @classmethod
    def from_contract_hex(cls, contract_hex: str) -> GlyphRef:
        """Parse a 72-char contract id string as displayed in Radiant explorers.

        The Glyph contract id concatenates the display-order txid (64 hex
        chars) with the big-endian-encoded vout (8 hex chars). Both halves
        are written in human-readable order so the whole string reads
        naturally — the trailing ``00000004`` decodes to ``4``::

            b45dc453befb589a...c380eb31deaf96a2a8 00000004
            └────────── txid (display order) ───┘ └─ vout BE ─┘  (= 4)

        Equivalent forms:

        * ``from_contract_hex("b45dc4...a2a800000004")``
        * ``GlyphRef(txid=Txid("b45dc4...a2a8"), vout=4)``

        .. warning::

           This is the **explorer / UI display form**, not the on-chain
           wire form. :meth:`from_bytes` parses the wire form used inside
           locking scripts, where the txid bytes are reversed *and* the
           vout is encoded little-endian. If you have raw bytes pulled out
           of a script, use :meth:`from_bytes`. Use this method only when
           you have a contract id in the form a Radiant explorer or wallet
           UI shows it. Mixing them will silently produce a wrong-vout ref.
        """
        if not isinstance(contract_hex, str):
            raise ValidationError(f"contract_hex must be str, got {type(contract_hex).__name__!r}")
        if len(contract_hex) != 72:
            raise ValidationError(
                f"contract_hex must be 72 hex chars (32-byte txid + 4-byte vout), got {len(contract_hex)}"
            )
        try:
            vout_bytes = bytes.fromhex(contract_hex[64:])
        except ValueError as exc:
            raise ValidationError("contract_hex contains non-hex characters") from exc
        txid = contract_hex[:64]
        vout = int.from_bytes(vout_bytes, "big")
        return cls(txid=Txid(txid), vout=vout)


@dataclass(frozen=True)
class GlyphMedia:
    mime_type: str  # e.g. "image/webp"
    data: bytes  # raw binary

    # Real IANA-registered MIME types top out around 75 chars; 256 is
    # generous and leaves room for parameters (``; charset=…``) while
    # bounding the expansion vector for display strings constructed
    # from this field downstream. The CBOR decoder applies the same
    # cap — this is defence-in-depth so direct constructor callers
    # (tests, future SDK paths) get the same guarantee.
    _MAX_MIME_TYPE_CHARS = 256

    def __post_init__(self) -> None:
        if not self.mime_type or "/" not in self.mime_type:
            raise ValidationError("Invalid MIME type")
        if len(self.mime_type) > self._MAX_MIME_TYPE_CHARS:
            raise ValidationError(f"MIME type too long: {len(self.mime_type)} > {self._MAX_MIME_TYPE_CHARS}")
        # NO SIZE CAP HERE. This used to refuse data over 100 KB, and the only
        # code that ever constructs a GlyphMedia is the DECODER (payload.py) —
        # so a write-side policy limit fired exclusively when reading somebody
        # else's token off the chain, and took the whole payload down with it:
        # `GlyphInspector.extract_reveal_metadata` catches Exception and returns
        # None, so the user saw "metadata: NONE" rather than a size refusal.
        #
        # Measured on live mainnet: 6 of 25 sampled `gly` payloads were refused
        # by pyrxd and decoded fine by an independent verifier; four of the six
        # were webp images of 153,650 / 178,608 / 236,726 bytes.
        #
        # It also contradicted the real bound. `_MAX_CBOR_PAYLOAD_BYTES` (256 KB)
        # was deliberately raised to admit a genuine 65,569-byte payload, and this
        # inner cap made that headroom unreachable for any media-bearing token.
        # The 256 KB payload cap is the DoS bound, and it is on the encode path
        # where a policy limit belongs.


_VALID_PROTOCOL_VALUES = frozenset(p.value for p in GlyphProtocol)


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

        if not re.fullmatch(r"0[23][0-9a-f]{64}", self.pubkey.lower()):
            raise ValidationError(
                "creator.pubkey must be a 33-byte compressed secp256k1 pubkey (02 or 03 prefix, 66 hex chars)"
            )
        if self.sig and not re.fullmatch(r"[0-9a-f]+", self.sig.lower()):
            raise ValidationError("creator.sig must be hex-encoded DER bytes or empty string")

    def to_cbor_dict(self) -> dict:
        d: dict = {"pubkey": self.pubkey}
        if self.sig:
            d["sig"] = self.sig
        if self.algo != "ecdsa-secp256k1":
            d["algo"] = self.algo
        return d

    @classmethod
    def from_cbor_dict(cls, d: dict) -> GlyphCreator:
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
                    raise ValidationError(f"royalty split bps must be 0..10000, got {split_bps} for '{addr}'")
            split_total = sum(b for _, b in self.splits)
            if split_total > self.bps:
                raise ValidationError(f"royalty splits sum ({split_total} bps) exceeds total bps ({self.bps})")

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
    def from_cbor_dict(cls, d: dict) -> GlyphRoyalty:
        splits_raw = d.get("splits", [])
        splits = tuple((str(s["address"]), int(s["bps"])) for s in splits_raw if isinstance(s, dict))
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

    renderable: bool | None = None  # wallets may display/render this token
    executable: bool | None = None  # token contains executable content
    nsfw: bool | None = None  # not safe for work
    transferable: bool | None = None  # False = soulbound (non-transferable)

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
    def from_cbor_dict(cls, d: dict) -> GlyphPolicy:
        def _opt_bool(key: str) -> bool | None:
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

    license: str = ""  # SPDX identifier or URL (e.g. "CC-BY-4.0")
    terms: str = ""  # Human-readable license terms
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
    def from_cbor_dict(cls, d: dict) -> GlyphRights:
        return cls(
            license=str(d.get("license", "")),
            terms=str(d.get("terms", "")),
            attribution=str(d.get("attribution", "")),
        )


@dataclass(frozen=True)
class GlyphMetadata:
    """CBOR payload for a Glyph token."""

    protocol: list[int]  # e.g. [2] for NFT, [1] for FT, [1,4] for dMint FT
    name: str = ""
    ticker: str = ""  # FT only
    description: str = ""
    token_type: str = ""  # NFT type tag
    main: GlyphMedia | None = None
    attrs: dict[str, str] = field(default_factory=dict)
    loc: str = ""  # IPFS or external URI
    loc_hash: str = ""  # integrity hash
    decimals: int = 0  # FT decimals (display only — consensus is 1 photon = 1 unit)
    image_url: str = ""  # HTTPS URL for token display image
    image_ipfs: str = ""  # IPFS CID (ipfs://... form)
    image_sha256: str = ""  # hex SHA256 of image bytes — lets clients verify hosted image wasn't swapped
    v: int | None = None  # Glyph version (None=V1, 2=V2); indexers use this to select parser
    dmint_params: DmintCborPayload | None = (
        None  # V2 dMint config object; required when GlyphProtocol.DMINT in protocol
    )
    creator: GlyphCreator | None = None  # V2 creator identity + optional ECDSA signature
    royalty: GlyphRoyalty | None = None  # V2 royalty hint for secondary markets
    policy: GlyphPolicy | None = None  # V2 behaviour flags (soulbound, nsfw, etc.)
    rights: GlyphRights | None = None  # V2 licensing and attribution
    created: str = ""  # V2 ISO8601 creation timestamp
    commit_outpoint: str = ""  # V2 txid:vout of the commit UTXO
    # CBOR ``crypto.timelock`` — WHEN an encrypted payload becomes readable (#556).
    #
    # The decoder dropped this. pyrxd would classify a token as TIMELOCK and then discard the
    # only field that says when it unlocks, so `glyph.timelock.is_unlocked` and
    # `get_unlock_remaining` had nothing to be called WITH — which is why they had no caller.
    # The unreachability was a parser gap, not a missing convenience method.
    #
    # Only the timelock spec is carried, not the whole `crypto` block: the wraps and the key
    # format are mint-side concerns, and surfacing per-recipient key material through the
    # inspect path is not something to do incidentally.
    timelock: TimelockSpec | None = None
    # CBOR ``crypto`` and the ENCRYPTED form of ``main`` — the WRITE side of the same block
    # ``timelock`` above reads (#556).
    #
    # These exist because the encoder could not carry a commitment at all. ``to_cbor_dict``
    # emitted no ``crypto`` key under any circumstance, so a mint declaring
    # ``p = [NFT, ENCRYPTED, TIMELOCK]`` went on chain with no ``crypto.cek_hash`` and no
    # ``crypto.timelock`` — a token that SAYS it is sealed while carrying nothing a reveal
    # could ever be checked against. That is not a missing convenience: the CEK commitment is
    # the only thing that makes a published key verifiable, and a mint cannot be repaired.
    #
    # ``encrypted_main`` is a SECOND spelling of ``main`` rather than a widening of it, because
    # the two are different shapes on the wire. An ordinary glyph's ``main`` is
    # ``{"t": mime, "b": bytes}`` (:class:`GlyphMedia`); an encrypted glyph's is Photonic's
    # ``{"type", "hash", "enc", "size", "chunks", "scheme"}``
    # (:class:`~pyrxd.glyph.encrypted_content.EncryptionMetadata`), which describes the
    # PLAINTEXT that was encrypted while the ciphertext itself lives off chain. Only one of the
    # two may be set; ``__post_init__`` refuses both.
    #
    # WRITE-SIDE ONLY, deliberately asymmetric with the decoder: ``decode_payload`` fills
    # ``timelock`` and leaves these ``None``. The per-recipient wraps in ``crypto.recipients``
    # are key material, and surfacing them through the inspect path is not something to do
    # incidentally — the note on ``timelock`` above records that decision. A caller that needs
    # the exact bytes a token was decoded from has ``source_cbor``.
    encrypted_main: EncryptionMetadata | None = None
    crypto: CryptoMetadata | None = None
    # The EXACT CBOR these fields were decoded from, when they came off a chain.
    #
    # Carried because decoding is LOSSY and creator-signature verification is not
    # allowed to be. `_cbor_str` drops a wrong-typed field to "" rather than raising,
    # which is right for display — Photonic mints `loc` as an INTEGER on mainnet and
    # refusing those tokens showed the user "metadata: NONE". But re-encoding the
    # decoded object and checking a signature over THAT reports an honest,
    # correctly-signed token as a forgery, because the bytes the creator signed are
    # not the bytes we rebuilt. Verification reads these instead.
    #
    # compare=False: two tokens with identical fields are the same token regardless of
    # which one arrived over a wire, and every existing equality assertion stays true.
    source_cbor: bytes | None = field(default=None, compare=False, repr=False)
    # CBOR ``in`` — the CONTAINER(s) this token is a member of. Membership points
    # CHILD -> PARENT and lives here, in the envelope, because it cannot live in
    # the locking script: an output may not carry a ref that a *sibling* output
    # holds as an ``OP_PUSHINPUTREFSINGLETON``, so a script-level link to a live
    # NFT is rejected by consensus. See the CONTAINER section of
    # ``docs/reference/glyph-token-protocol-spec.md``.
    container_refs: tuple[GlyphRef, ...] = ()
    # CBOR ``by`` — the author / user token(s) that issued this one. Same shape,
    # same (advisory) enforcement story as ``container_refs``.
    author_refs: tuple[GlyphRef, ...] = ()

    @property
    def is_container(self) -> bool:
        """True when this envelope marks the token itself as a CONTAINER.

        Either declaration counts. `GlyphProtocol.CONTAINER` (7) is the spec'd
        form and NO mainnet token uses it — all four containers on Radiant
        mainnet declare `type: "container"` on an ordinary NFT/MUT protocol set,
        so a protocol-only test was False for every real container (#578).

        Verified on chain: the "BTC" container (reveal 57c4d660...dfb1) decodes
        to `p = (2,)` with `type = 'container'`.

        Both are DECLARATIONS — `type` is operator CBOR and nothing on chain
        enforces it, exactly as nothing enforces the protocol array.
        """
        return GlyphProtocol.CONTAINER in self.protocol or (self.token_type or "").strip().lower() == "container"

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
        object.__setattr__(self, "protocol", tuple(self.protocol))
        if not self.protocol:
            raise ValidationError(
                "protocol list must not be empty. Use e.g. [GlyphProtocol.FT] or [GlyphProtocol.NFT]."
            )
        for p in self.protocol:
            if not isinstance(p, int) or isinstance(p, bool):
                raise ValidationError(f"protocol values must be int, got {type(p).__name__!r}: {p!r}")
            if p not in _VALID_PROTOCOL_VALUES:
                raise ValidationError(
                    f"Unknown protocol value {p!r}. Valid values: {sorted(_VALID_PROTOCOL_VALUES)} (see GlyphProtocol)."
                )
        # Protocol combination rules (mirrors Photonic Wallet protocols.ts §3.5).
        # FT and NFT are mutually exclusive base types.
        if GlyphProtocol.FT in self.protocol and GlyphProtocol.NFT in self.protocol:
            raise ValidationError("FT (1) and NFT (2) are mutually exclusive protocol markers.")
        # Each extension protocol has at least one required co-protocol.
        _REQUIREMENTS: dict[int, list[int]] = {
            GlyphProtocol.DMINT: [GlyphProtocol.FT],
            GlyphProtocol.MUT: [GlyphProtocol.NFT],
            GlyphProtocol.CONTAINER: [GlyphProtocol.NFT],
            GlyphProtocol.ENCRYPTED: [GlyphProtocol.NFT],
            GlyphProtocol.TIMELOCK: [GlyphProtocol.ENCRYPTED],
            GlyphProtocol.AUTHORITY: [GlyphProtocol.NFT],
            GlyphProtocol.WAVE: [GlyphProtocol.NFT, GlyphProtocol.MUT],
        }
        for ext, required in _REQUIREMENTS.items():
            if ext in self.protocol:
                missing = [r for r in required if r not in self.protocol]
                if missing:
                    names = ", ".join(GlyphProtocol(r).name for r in missing)
                    raise ValidationError(
                        f"protocol {GlyphProtocol(ext).name} ({ext}) requires {names} to also be present."
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
        if self.image_sha256 and not re.fullmatch(r"[0-9a-f]{64}", self.image_sha256):
            raise ValidationError(
                f"image_sha256 must be 64 lowercase hex chars (SHA-256), "
                f"got {len(self.image_sha256)!r} chars: {self.image_sha256[:16]!r}..."
            )
        # Relationship refs: accept any sequence, store an immutable tuple (same
        # reason as ``protocol`` above — frozen=True does not stop list mutation).
        for _fname in ("container_refs", "author_refs"):
            value = getattr(self, _fname)
            if isinstance(value, GlyphRef):
                raise ValidationError(f"{_fname} must be a sequence of GlyphRef, not a bare GlyphRef")
            if not isinstance(value, (list, tuple)):
                raise ValidationError(f"{_fname} must be a sequence of GlyphRef, got {type(value).__name__!r}")
            for r in value:
                if not isinstance(r, GlyphRef):
                    raise ValidationError(f"{_fname} entries must be GlyphRef, got {type(r).__name__!r}: {r!r}")
            object.__setattr__(self, _fname, tuple(value))
        # ``main`` and ``encrypted_main`` both encode to the CBOR key ``main``, so setting
        # both is not an over-specification the encoder can resolve — one of the two would be
        # dropped silently, and which one depends on statement order in ``to_cbor_dict``. For
        # an encrypted mint the dropped field decides whether the token carries the plaintext
        # hash a recipient needs to decrypt, so it is refused here rather than resolved.
        #
        # Nothing else about the encrypted block is required here on purpose. A metadata
        # object carrying TIMELOCK with no ``crypto`` is still constructible, because
        # ``decode_payload`` builds exactly that for every timelocked token it reads off the
        # chain: the decoder must stay permissive on third-party data. The mint path is where
        # a missing commitment is fatal, and :func:`pyrxd.glyph.timelock.build_timelock_mint`
        # is the entry point that makes it unrepresentable there.
        if self.main is not None and self.encrypted_main is not None:
            raise ValidationError(
                "main and encrypted_main both encode to the CBOR 'main' key — set one. "
                "Use `main` for an ordinary glyph (mime type + embedded bytes) and "
                "`encrypted_main` for an ENCRYPTED one (plaintext hash + AEAD scheme)."
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
        if self.encrypted_main is not None:
            # Photonic's shape, not GlyphMedia's — see the field comment. ``__post_init__``
            # has already refused the case where both are set, so this cannot overwrite.
            d["main"] = self.encrypted_main.to_dict()
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
        if self.crypto is not None:
            # The commitment, the key format and (when the mint wraps to recipients) the
            # per-recipient wraps. ``crypto.timelock`` inside it is what
            # :func:`pyrxd.glyph.payload.decode_payload` reads back and what
            # :func:`pyrxd.glyph.timelock_reveal_tx.plan_timelock_reveal` checks a published
            # CEK against — so this line is the reason a reveal is verifiable at all.
            d["crypto"] = self.crypto.to_dict()
        if self.created:
            d["created"] = self.created
        if self.commit_outpoint:
            d["commit_outpoint"] = self.commit_outpoint
        # ``in`` / ``by`` carry 36-byte refs in the SAME wire form the locking
        # script uses (txid reversed || vout LE) — that is what makes Photonic's
        # ``filterRels`` able to compare a claimed ``in`` entry against the refs
        # it parsed out of the reveal's output scripts. Encoded as plain CBOR
        # byte strings; see :func:`pyrxd.glyph.payload.decode_payload` for the
        # tag-64 asymmetry on the decode side.
        if self.container_refs:
            d["in"] = [r.to_bytes() for r in self.container_refs]
        if self.author_refs:
            d["by"] = [r.to_bytes() for r in self.author_refs]
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
        protocol: list[int] | None = None,
        dmint_params: DmintCborPayload | None = None,
    ) -> GlyphMetadata:
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
    """A minted or transferable NFT Glyph.

    A **CONTAINER** (collection) is an ordinary ``GlyphNft`` — same 63-byte
    locking script, same transfer path. Use :attr:`is_container` to tell one
    apart and :attr:`container_refs` to read which collection(s) *this* token
    declares membership in.
    """

    ref: GlyphRef
    owner_pkh: Hex20  # 20-byte P2PKH hash of current owner
    # ``None`` when the reveal could not be located (see GlyphScanner) — the
    # token is still real, only its envelope is unavailable.
    metadata: GlyphMetadata | None

    @property
    def is_container(self) -> bool:
        """True when this token is itself a CONTAINER (envelope marker ``7``).

        ``False`` when the metadata could not be resolved — absence of evidence.
        A caller that must distinguish "not a container" from "unknown" should
        check ``metadata is None`` first.
        """
        return self.metadata is not None and self.metadata.is_container

    @property
    def container_refs(self) -> tuple[GlyphRef, ...]:
        """Containers this token declares membership in (envelope ``in`` field).

        Advisory: nothing on chain binds a token to a container. What makes a
        claim checkable is that the container's ref also appears among the
        refs of the reveal transaction's outputs — see
        :meth:`pyrxd.glyph.builder.GlyphBuilder.prepare_container_child_reveal`.
        """
        return () if self.metadata is None else self.metadata.container_refs

    @property
    def author_refs(self) -> tuple[GlyphRef, ...]:
        """Author / issuer tokens this token declares (envelope ``by`` field)."""
        return () if self.metadata is None else self.metadata.author_refs


@dataclass(frozen=True)
class GlyphFt:
    """A minted or transferable FT Glyph."""

    ref: GlyphRef
    owner_pkh: Hex20
    amount: int  # in photons (Radiant satoshi equivalent)
    # ``None`` when the reveal could not be located — same contract as GlyphNft.
    metadata: GlyphMetadata | None
