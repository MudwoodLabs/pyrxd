"""Gravity Protocol covenant parameter substitution and code hash computation.

Ports ``extract_p2sh_code_hash.js`` from gravity-rxd-prototype to Python.
Bundles pre-compiled covenant artifact JSONs (compiled with rxdc 0.1.0) so
callers don't need the RadiantScript compiler toolchain at runtime.

Typical usage
-------------
::

    from pyrxd.gravity.covenant import CovenantArtifact, build_gravity_offer
    from pyrxd.gravity.types import GravityOffer

    # Build a GravityOffer with real covenant redeem scripts
    offer = build_gravity_offer(
        maker_pkh=b"\\xaa" * 20,
        maker_pk=bytes.fromhex("02" + "bb" * 32),
        taker_pk=bytes.fromhex("02" + "cc" * 32),
        taker_radiant_pkh=b"\\xdd" * 20,
        btc_receive_hash=b"\\xee" * 20,
        btc_receive_type="p2wpkh",
        btc_satoshis=100_000,
        btc_chain_anchor=bytes(32),
        expected_nbits=bytes.fromhex("ffff001d"),
        anchor_height=800_000,
        merkle_depth=12,
        claim_deadline=int(time.time()) + 48 * 3600,
        photons_offered=10_000_000,
    )
"""

from __future__ import annotations

import json
import re
import time
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pyrxd.gravity.codehash import (
    compute_p2sh_code_hash,
)
from pyrxd.security.errors import ValidationError

__all__ = [
    "CovenantArtifact",
    "build_gravity_offer",
    "validate_claim_deadline",
]

_ARTIFACTS_DIR = Path(__file__).parent / "artifacts"

# ---------------------------------------------------------------------------
# Deny-lists (ported from extract_p2sh_code_hash.js)
# ---------------------------------------------------------------------------

_BANNED_NAMES: dict[str, str] = {
    "MakerOfferSimple": "skips Taker signature on claim — audit 04 S3 (grief vector)",
    "MakerClaimedStub": "finalize() has no SPV check — any party could drain the UTXO",
    "MakerClaimed": "hand-written reference; use generator output",
    "MakerCovenant6x12": "pre-Phase-4 covenant — no nBits bound, no structural constraint. Regenerate.",
    "MakerCovenantFlat6x12": "pre-Phase-4 covenant — no nBits bound, no structural constraint. Regenerate.",
    "VerifyPayment": "standalone primitive, not a deployable covenant",
}

# SHA-256 of raw hex template string (matching JS behavior: sha256 of the
# template text with placeholders still present).
_BANNED_BYTECODE_SHA256: dict[str, str] = {
    "9f74b48de165cfc376a2af8da4754341587f22d7b3674429d63dba4f6379309e": "maker_claimed_stub (no SPV check)",
    "cba74986f7dd2288deb02541e285263d4237147fdd8f37644592131c26fdd769": "maker_covenant_6x12 (pre-Phase-4, no nBits bound)",
    "6f2f4121791daf4eff9a80545a995eaaebe894b6d05370968b606cd11fc190a8": "maker_covenant_flat_6x12 (pre-Phase-4, no nBits bound)",
    "a65fba4ed3b0e11ab7f5fb09e9a20f3cd1183edfcc3d49215ea3df8e996fbb61": "maker_offer_simple (no Taker sig on claim — audit 04 S3)",
    "6264437431d7335add9e111242b996e1db9cdcb0551d935b7313fb6395a46c61": "verify_payment (standalone primitive, not deployable)",
}

_MIN_DEADLINE_DELTA = 24 * 3600  # 24 hours in seconds


# ---------------------------------------------------------------------------
# Script integer encoding (Bitcoin scriptnum / CScriptNum)
# ---------------------------------------------------------------------------


def _encode_int_push(n: int) -> bytes:
    """Encode an integer as a minimal Bitcoin script push."""
    if n == 0:
        return bytes([0x00])
    if 1 <= n <= 16:
        return bytes([0x50 + n])
    neg = n < 0
    v = abs(n)
    out: list[int] = []
    while v > 0:
        out.append(v & 0xFF)
        v >>= 8
    if out[-1] & 0x80:
        out.append(0x80 if neg else 0x00)
    elif neg:
        out[-1] |= 0x80
    body = bytes(out)
    return bytes([len(body)]) + body


def _encode_bytes_push(hex_val: str) -> bytes:
    """Encode a hex string value as a minimal script data push."""
    b = bytes.fromhex(hex_val)
    n = len(b)
    if n <= 75:
        return bytes([n]) + b
    elif n <= 255:
        return b"\x4c" + bytes([n]) + b  # OP_PUSHDATA1
    elif n <= 65535:
        return b"\x4d" + n.to_bytes(2, "little") + b  # OP_PUSHDATA2
    else:
        raise ValidationError(f"_encode_bytes_push: data too large ({n} bytes)")


# ---------------------------------------------------------------------------
# CovenantArtifact
# ---------------------------------------------------------------------------


@dataclass
class CovenantArtifact:
    """A loaded, pre-compiled covenant artifact with parameter substitution."""

    contract: str
    hex_template: str  # bytecode with <param> placeholders
    abi: list[dict]  # ABI entries from the artifact JSON

    @classmethod
    def load(cls, name: str, *, allow_legacy: bool = False) -> CovenantArtifact:
        """
        Load a bundled artifact by stem name (without ``.artifact.json``).

        Available artifacts:
        - ``maker_offer``
        - ``maker_covenant_6x12_p2wpkh``
        - ``maker_covenant_flat_6x12_p2wpkh``
        - ``maker_covenant_trade``
        """
        # Reject names containing path separators or traversal sequences.
        # We also resolve and assert containment after joining, as defense-in-depth.
        import re as _re

        if not _re.fullmatch(r"[A-Za-z0-9_\-]+", name):
            raise ValidationError(
                f"Artifact name {name!r} contains invalid characters. "
                "Only alphanumeric, underscore, and hyphen are allowed."
            )
        path = _ARTIFACTS_DIR / f"{name}.artifact.json"
        resolved = path.resolve()
        artifacts_resolved = _ARTIFACTS_DIR.resolve()
        if not str(resolved).startswith(str(artifacts_resolved) + "/"):
            raise ValidationError(f"Artifact name {name!r} resolves outside the bundled artifacts directory.")
        if not path.exists():
            available = sorted(p.stem.removesuffix(".artifact") for p in _ARTIFACTS_DIR.glob("*.artifact.json"))
            raise FileNotFoundError(f"Artifact '{name}' not found in bundled artifacts. Available: {available}")
        return cls.from_json(path.read_text(), allow_legacy=allow_legacy)

    @classmethod
    def from_json(cls, json_text: str, *, allow_legacy: bool = False) -> CovenantArtifact:
        """Load from raw artifact JSON (e.g. from a custom compiled artifact)."""
        import hashlib

        data = json.loads(json_text)
        contract = data.get("contract", "")
        hex_template = data.get("hex", "")

        # Check deny-lists
        banned_name = _BANNED_NAMES.get(contract)
        template_sha = hashlib.sha256(hex_template.encode()).hexdigest()
        banned_bytes = _BANNED_BYTECODE_SHA256.get(template_sha)

        if banned_name or banned_bytes:
            reason = banned_name or banned_bytes
            if not allow_legacy:
                raise ValidationError(
                    f"Artifact '{contract}' is on the deny-list: {reason}. "
                    "Use a current generator output. Pass allow_legacy=True for research only."
                )
            warnings.warn(
                f"Loading deny-listed artifact '{contract}' with allow_legacy=True: {reason}. "
                "This artifact is unsafe for production use.",
                stacklevel=3,
            )

        return cls(
            contract=contract,
            hex_template=hex_template,
            abi=data.get("abi", []),
        )

    def constructor_params(self) -> list[dict]:
        """Return the constructor ABI params in declaration order."""
        for entry in self.abi:
            if entry.get("type") == "constructor":
                return entry.get("params", [])
        return []

    def substitute(self, params: dict[str, Any]) -> bytes:
        """
        Substitute constructor params into the hex template.

        Returns the full redeem script bytes. Raises ``ValidationError`` if
        any required param is missing, any placeholder remains unfilled, or
        any fixed-width typed param (``Ripemd160`` / ``Sha256`` / ``PubKey``)
        has the wrong byte length — these would silently encode as the wrong
        push and produce an on-chain-rejected covenant.

        Values:
        - ``int`` params: pass Python ``int``
        - ``bytes``/``Ripemd160``/``Sha256``/``PubKey`` params: pass hex string
        """
        # Expected lengths in bytes for fixed-width typed params.
        _FIXED_LENGTHS = {
            "Ripemd160": 20,
            "Sha256": 32,
            "PubKey": 33,
        }

        result = self.hex_template
        # Sort by descending placeholder length to prevent prefix collisions:
        # e.g. substituting <expectedNBits> before <expectedNBitsNext> would
        # corrupt the longer placeholder since the shorter name is a prefix.
        for p in sorted(self.constructor_params(), key=lambda x: -len(x["name"])):
            name = p["name"]
            ptype = p["type"]
            placeholder = f"<{name}>"
            if placeholder not in result:
                continue
            val = params.get(name)
            if val is None:
                raise ValidationError(f"Missing required constructor param: '{name}'")

            if ptype == "int":
                encoded = _encode_int_push(int(val)).hex()
            else:
                hex_val = str(val)
                # Reject malformed hex early — bytes.fromhex would silently
                # accept 'odd-length' in some paths; enforce here.
                if len(hex_val) % 2 != 0:
                    raise ValidationError(f"param {name!r}: hex value has odd length ({len(hex_val)} chars)")
                byte_len = len(hex_val) // 2
                expected_len = _FIXED_LENGTHS.get(ptype)
                if expected_len is not None and byte_len != expected_len:
                    raise ValidationError(
                        f"param {name!r} of type {ptype} must be {expected_len} bytes "
                        f"(got {byte_len}). A wrong-length push silently corrupts the "
                        "redeem script and produces an on-chain-rejected covenant."
                    )
                if byte_len == 0:
                    raise ValidationError(
                        f"param {name!r}: empty value is not allowed (would encode as OP_0, "
                        "silently corrupting the covenant)."
                    )
                encoded = _encode_bytes_push(hex_val).hex()

            result = result.replace(placeholder, encoded)

        unfilled = re.findall(r"<\w+>", result)
        if unfilled:
            raise ValidationError(f"Unfilled placeholders remain: {unfilled}")

        return bytes.fromhex(result)


# ---------------------------------------------------------------------------
# Deadline validation (S1 guard — audit 04)
# ---------------------------------------------------------------------------


def validate_claim_deadline(
    claim_deadline: int,
    *,
    min_future_seconds: int = _MIN_DEADLINE_DELTA,
    bypass: bool = False,
) -> None:
    """
    Raise ``ValidationError`` if ``claim_deadline`` is not at least
    ``min_future_seconds`` from now (default: 24h).

    This is the Python port of the S1 check in ``extract_p2sh_code_hash.js``
    (audit 04 finding S1: a short deadline lets Maker race-snipe Taker's claim).

    :param bypass: Only set True for test harnesses **you** control. Never
                   set because a counterparty asked you to.
    """
    now = int(time.time())
    min_future = now + min_future_seconds
    if claim_deadline < min_future:
        short = min_future - claim_deadline
        if not bypass:
            raise ValidationError(
                f"claim_deadline={claim_deadline} is {short}s short of now+{min_future_seconds}s. "
                "A near-past/present deadline lets the Maker race-snipe the Taker's claim "
                "(audit 04 finding S1). Pass bypass=True only for test harnesses you control."
            )


# ---------------------------------------------------------------------------
# High-level factory: build_gravity_offer
# ---------------------------------------------------------------------------


def build_gravity_offer(
    maker_pkh: bytes,  # 20-byte Radiant PKH of the Maker
    maker_pk: bytes,  # 33-byte compressed pubkey of the Maker
    taker_pk: bytes,  # 33-byte compressed pubkey of the Taker
    taker_radiant_pkh: bytes,  # 20-byte Radiant PKH of the Taker
    btc_receive_hash: bytes,  # 20B (p2pkh/p2wpkh/p2sh) or 32B (p2tr) BTC dest
    btc_receive_type: str,  # "p2pkh" | "p2wpkh" | "p2sh" | "p2tr"
    btc_satoshis: int,
    btc_chain_anchor: bytes,  # 32-byte LE prevHash of BTC anchor block
    expected_nbits: bytes,  # 4-byte LE nBits of expected BTC difficulty
    anchor_height: int,
    merkle_depth: int,
    claim_deadline: int,  # Unix timestamp; must be at least 24h from now
    photons_offered: int,
    expected_nbits_next: bytes | None = None,  # if None, same as expected_nbits
    accept_short_deadline: bool = False,
    covenant_artifact_name: str = "maker_covenant_flat_12x20_sentinel_all",
    offer_artifact_name: str = "maker_offer",
) -> Any:
    """
    Build a :class:`~pyrxd.gravity.types.GravityOffer` with real covenant
    redeem scripts generated from the bundled artifacts.

    This is the top-level entry point for Maker-side offer construction.
    Internally it:

    1. Validates the claim deadline (S1 guard).
    2. Loads the MakerClaimed covenant artifact and substitutes code-section params.
    3. Computes ``expectedClaimedCodeHash = hash256(P2SH_scriptPubKey)`` from
       the substituted redeem script.
    4. Loads the MakerOffer artifact and substitutes its params (including the
       code hash from step 3).
    5. Returns a :class:`GravityOffer` with both redeem scripts populated.

    :param accept_short_deadline: Override the 24h deadline guard. Set True
        only for test harnesses you control — never because a counterparty asks.
    :param covenant_artifact_name: Override the MakerClaimed artifact stem.
    :param offer_artifact_name: Override the MakerOffer artifact stem.
    """
    from pyrxd.gravity.types import GravityOffer

    # Validate deadline (S1 guard)
    validate_claim_deadline(claim_deadline, bypass=accept_short_deadline)

    # Structural param validation — catch wrong-length bytes early, before we
    # silently embed corrupted pushes into the redeem script and compute a
    # code hash that will be rejected on-chain (wasting the Maker's funding
    # fee and burning a txid).
    if len(maker_pkh) != 20:
        raise ValidationError(f"maker_pkh must be 20 bytes (Radiant PKH); got {len(maker_pkh)}")
    if len(maker_pk) != 33:
        raise ValidationError(f"maker_pk must be 33 bytes (compressed secp256k1 pubkey); got {len(maker_pk)}")
    if len(taker_pk) != 33:
        raise ValidationError(f"taker_pk must be 33 bytes (compressed secp256k1 pubkey); got {len(taker_pk)}")
    if len(taker_radiant_pkh) != 20:
        raise ValidationError(f"taker_radiant_pkh must be 20 bytes; got {len(taker_radiant_pkh)}")
    expected_btc_hash_len = 32 if btc_receive_type == "p2tr" else 20
    if len(btc_receive_hash) != expected_btc_hash_len:
        raise ValidationError(
            f"btc_receive_hash for {btc_receive_type!r} must be "
            f"{expected_btc_hash_len} bytes; got {len(btc_receive_hash)}"
        )
    if len(btc_chain_anchor) != 32:
        raise ValidationError(f"btc_chain_anchor must be 32 bytes (BTC block hash); got {len(btc_chain_anchor)}")
    if len(expected_nbits) != 4:
        raise ValidationError(f"expected_nbits must be 4 bytes (LE nBits); got {len(expected_nbits)}")
    if btc_satoshis <= 0:
        raise ValidationError(
            f"btc_satoshis must be > 0; got {btc_satoshis}. Negative or zero "
            "values would encode as OP_0 / a negative scriptnum in the covenant, "
            "producing a redeem that cannot be satisfied by any BTC payment."
        )
    if photons_offered <= 0:
        raise ValidationError(f"photons_offered must be > 0; got {photons_offered}")

    if expected_nbits_next is None:
        expected_nbits_next = expected_nbits
    elif len(expected_nbits_next) != 4:
        raise ValidationError(f"expected_nbits_next must be 4 bytes; got {len(expected_nbits_next)}")

    # 1. Substitute MakerClaimed code-section params (state params excluded —
    #    takerRadiantPkh and claimDeadline are in the state section, not the
    #    code section, so the code hash is the same for all takers).
    claimed_artifact = CovenantArtifact.load(covenant_artifact_name)
    claimed_params: dict[str, Any] = {
        "makerPkh": maker_pkh.hex(),
        "btcReceiveHash": btc_receive_hash.hex(),
        "btcSatoshis": btc_satoshis,
        "btcChainAnchor": btc_chain_anchor.hex(),
        "expectedNBits": expected_nbits.hex(),
        "totalPhotonsInOutput": photons_offered,
    }
    # The state-separated artifact (maker_covenant_6x12_p2wpkh) does NOT have
    # expectedNBitsNext, takerRadiantPkh, or claimDeadline in the code section.
    # Flat artifacts bake some or all of those into the code section; different
    # flat artifacts pick different subsets (e.g. flat_6x12 omits
    # expectedNBitsNext). Inspect the constructor ABI and supply each flat-only
    # param only if it actually appears — avoids relying on which
    # ValidationError fires first (substitute raises "Missing required
    # constructor param" before "Unfilled placeholders").
    _VALID_BTC_RECEIVE_TYPES = {"p2pkh": 0, "p2wpkh": 1, "p2sh": 2, "p2tr": 3}
    if btc_receive_type not in _VALID_BTC_RECEIVE_TYPES:
        raise ValidationError(
            f"btc_receive_type must be one of {list(_VALID_BTC_RECEIVE_TYPES)}; got {btc_receive_type!r}"
        )
    ctor_param_names = {p["name"] for p in claimed_artifact.constructor_params()}
    _btc_type_int = _VALID_BTC_RECEIVE_TYPES[btc_receive_type]
    flat_extras = {
        "takerRadiantPkh": taker_radiant_pkh.hex(),
        "expectedNBitsNext": expected_nbits_next.hex(),
        "claimDeadline": claim_deadline,
        "btcReceiveType": _btc_type_int,
    }
    for name, value in flat_extras.items():
        if name in ctor_param_names:
            claimed_params[name] = value
    claimed_redeem = claimed_artifact.substitute(claimed_params)

    # 2. Compute expectedClaimedCodeHash
    expected_code_hash = compute_p2sh_code_hash(claimed_redeem)

    # 3. Substitute MakerOffer params
    offer_artifact = CovenantArtifact.load(offer_artifact_name)
    offer_params: dict[str, Any] = {
        "makerPk": maker_pk.hex(),
        "takerPk": taker_pk.hex(),
        "totalPhotonsInOutput": photons_offered,
        "expectedClaimedCodeHash": expected_code_hash.hex(),
    }
    offer_redeem = offer_artifact.substitute(offer_params)

    return GravityOffer(
        btc_receive_hash=btc_receive_hash,
        btc_receive_type=btc_receive_type,
        btc_satoshis=btc_satoshis,
        chain_anchor=btc_chain_anchor,
        anchor_height=anchor_height,
        merkle_depth=merkle_depth,
        taker_radiant_pkh=taker_radiant_pkh,
        claim_deadline=claim_deadline,
        photons_offered=photons_offered,
        offer_redeem_hex=offer_redeem.hex(),
        claimed_redeem_hex=claimed_redeem.hex(),
        expected_code_hash_hex=expected_code_hash.hex(),
    )
