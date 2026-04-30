"""Bitcoin keypair generation for the Gravity Taker.

Supports all 4 address formats required by the Gravity multi-type covenant:
P2PKH, P2WPKH, P2SH-P2WPKH, P2TR.

Networks
--------
The ``network`` parameter selects the bech32 HRP and the base58 version bytes
used for address and WIF serialization:

* ``"bc"`` — Bitcoin mainnet (default). bech32 HRP ``bc``, P2PKH version 0x00,
  P2SH version 0x05, WIF version 0x80.
* ``"tb"`` — Bitcoin testnet3 / signet. bech32 HRP ``tb``, P2PKH version 0x6F,
  P2SH version 0xC4, WIF version 0xEF.
* ``"bcrt"`` — Bitcoin regtest. bech32 HRP ``bcrt``, base58 versions + WIF
  match testnet.

Any other HRP string is accepted (treated as mainnet-equivalent base58
versions) so that custom / local networks can be used without a code change.

Design rules
------------
* Private key is stored in PrivateKeyMaterial — never leaks in repr/str.
* Uses secure_scalar_mod_n() for key generation (CSPRNG + rejection sampling).
* No assert in src/ — all invariants use explicit raises.
* unsafe_wif() is named 'unsafe' for grep-in-code-review visibility.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from pyrxd.security.errors import KeyMaterialError, ValidationError
from pyrxd.security.secrets import PrivateKeyMaterial, secure_scalar_mod_n

__all__ = ["BtcKeypair", "generate_keypair", "keypair_from_wif"]

# bech32 / bech32m character set
_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

# bech32 GF polynomial constants (BIP173)
_BECH32_GENERATOR = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]

# Checksum constants: bech32 uses 1, bech32m uses 0x2BC830A3 (BIP350)
_BECH32_CONST = 1
_BECH32M_CONST = 0x2BC830A3

# Base58 version bytes + WIF prefix per network.
# Testnet values per https://en.bitcoin.it/wiki/List_of_address_prefixes.
# Mainnet: P2PKH 0x00, P2SH 0x05, WIF 0x80
# Testnet/signet/regtest: P2PKH 0x6F, P2SH 0xC4, WIF 0xEF
_MAINNET_P2PKH = 0x00
_MAINNET_P2SH = 0x05
_MAINNET_WIF = 0x80
_TESTNET_P2PKH = 0x6F
_TESTNET_P2SH = 0xC4
_TESTNET_WIF = 0xEF

# Known HRPs for which we use testnet-style base58 version bytes.
_TESTNET_HRPS = frozenset({"tb", "bcrt"})


def _version_bytes_for(network: str) -> tuple[int, int, int]:
    """Return (p2pkh_version, p2sh_version, wif_version) for ``network``.

    Unknown HRPs fall back to mainnet versions; bech32 output is still produced
    with the supplied HRP. This keeps custom/local HRPs usable without a code
    change while giving correct values for the three well-known networks.
    """
    if network in _TESTNET_HRPS:
        return _TESTNET_P2PKH, _TESTNET_P2SH, _TESTNET_WIF
    return _MAINNET_P2PKH, _MAINNET_P2SH, _MAINNET_WIF


@dataclass
class BtcKeypair:
    """A Bitcoin keypair with addresses in all 4 Gravity-supported formats.

    Private key is stored as PrivateKeyMaterial (never logs/repr leaks).

    Attributes:
        network: bech32 HRP (``"bc"`` mainnet, ``"tb"`` testnet/signet,
            ``"bcrt"`` regtest, or any custom HRP). Defaults to ``"bc"``.
    """

    _privkey: PrivateKeyMaterial  # private — use with care
    pubkey_bytes: bytes  # 33-byte compressed pubkey

    # Per-format address info
    p2pkh_address: str
    p2wpkh_address: str
    p2sh_p2wpkh_address: str
    p2tr_address: str

    # 20-byte hashes (used for P2PKH, P2WPKH, P2SH-P2WPKH covenant params)
    pkh: bytes  # RIPEMD160(SHA256(pubkey)) — 20 bytes
    p2sh_hash: bytes  # RIPEMD160(SHA256(P2WPKH_redeem)) — 20 bytes

    # 32-byte x-only tweaked output key (used for P2TR covenant param)
    p2tr_output_key: bytes  # 32 bytes

    # Network / HRP used for all address + WIF serialization.
    network: str = "bc"

    def __repr__(self) -> str:
        return f"BtcKeypair(p2wpkh={self.p2wpkh_address!r})"

    def unsafe_wif(self) -> str:
        """Export WIF. Named 'unsafe' to be visible in code review.

        Uses the WIF version byte for ``self.network`` (0x80 for mainnet,
        0xEF for testnet/signet/regtest).
        """
        raw = self._privkey.unsafe_raw_bytes()
        _, _, wif_version = _version_bytes_for(self.network)
        # WIF: version + privkey(32) + 0x01 (compressed) + checksum(4)
        payload = bytes([wif_version]) + raw + b"\x01"
        checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
        return _base58check_encode(payload + checksum)


def generate_keypair(network: str = "bc") -> BtcKeypair:
    """Generate a fresh Bitcoin keypair using CSPRNG.

    Uses secure_scalar_mod_n() for the private key — explicit range check,
    rejection sampling, never Math.random().
    Matches JS btc_wallet.js::generateKeypair() audit-hardened version.

    Args:
        network: bech32 HRP for address serialization. ``"bc"`` (default) for
            mainnet, ``"tb"`` for testnet/signet, ``"bcrt"`` for regtest, or
            any custom HRP.
    """
    import coincurve  # noqa: PLC0415

    privkey_material = secure_scalar_mod_n()
    raw = privkey_material.unsafe_raw_bytes()
    privkey_obj = coincurve.PrivateKey(raw)
    pubkey_bytes = privkey_obj.public_key.format(compressed=True)  # 33 bytes
    return _build_keypair(privkey_material, pubkey_bytes, network=network)


def keypair_from_wif(wif: str, network: str = "bc") -> BtcKeypair:
    """Load keypair from WIF string (for testing/recovery).

    Args:
        wif: WIF-encoded private key.
        network: bech32 HRP for address serialization (see ``generate_keypair``).
            Note: this controls OUTPUT address/WIF encoding only; the input WIF
            is decoded regardless of its version byte.
    """
    import coincurve  # noqa: PLC0415

    privkey_material = PrivateKeyMaterial.from_wif(wif)
    raw = privkey_material.unsafe_raw_bytes()
    privkey_obj = coincurve.PrivateKey(raw)
    pubkey_bytes = privkey_obj.public_key.format(compressed=True)
    return _build_keypair(privkey_material, pubkey_bytes, network=network)


def _build_keypair(
    privkey_material: PrivateKeyMaterial,
    pubkey_bytes: bytes,
    network: str = "bc",
) -> BtcKeypair:
    """Internal: build BtcKeypair from validated privkey + pubkey bytes."""
    if len(pubkey_bytes) != 33:
        raise KeyMaterialError("pubkey_bytes must be 33 bytes (compressed)")
    if not isinstance(network, str) or not network:
        raise ValidationError("network must be a non-empty string")

    p2pkh_version, p2sh_version, _wif_version = _version_bytes_for(network)

    # PKH = RIPEMD160(SHA256(pubkey))
    pkh = _hash160(pubkey_bytes)

    # P2SH-P2WPKH redeem script: OP_0 <20-byte pkh>
    p2wpkh_redeem = b"\x00\x14" + pkh
    p2sh_hash = _hash160(p2wpkh_redeem)

    # P2TR: BIP341 key-path-only tweak on x-only pubkey
    x_only = pubkey_bytes[1:]  # drop parity byte
    p2tr_output_key = _taproot_tweak(x_only)

    return BtcKeypair(
        _privkey=privkey_material,
        pubkey_bytes=pubkey_bytes,
        pkh=pkh,
        p2sh_hash=p2sh_hash,
        p2tr_output_key=p2tr_output_key,
        p2pkh_address=_p2pkh_address(pkh, p2pkh_version),
        p2wpkh_address=_p2wpkh_address(pkh, network),
        p2sh_p2wpkh_address=_p2sh_address(p2sh_hash, p2sh_version),
        p2tr_address=_p2tr_address(p2tr_output_key, network),
        network=network,
    )


def _hash160(data: bytes) -> bytes:
    """RIPEMD160(SHA256(data)) — Bitcoin's hash160."""
    return hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()


def _taproot_tweak(x_only_pubkey: bytes) -> bytes:
    """BIP341 key-path tweak: tagged hash then add tweak*G to pubkey.

    tagged hash = SHA256(SHA256('TapTweak') || SHA256('TapTweak') || x_only_pubkey)
    """
    import coincurve  # noqa: PLC0415

    tag = b"TapTweak"
    tag_hash = hashlib.sha256(tag).digest()
    tweak = hashlib.sha256(tag_hash + tag_hash + x_only_pubkey).digest()

    # Reconstruct compressed pubkey (assume even parity = 0x02 prefix)
    compressed = b"\x02" + x_only_pubkey
    pub = coincurve.PublicKey(compressed)
    # tweaked = pubkey + tweak*G; raises on scalar overflow (prob ~2^-128)
    tweaked = pub.add(tweak)
    tweaked_bytes = tweaked.format(compressed=True)
    return tweaked_bytes[1:]  # x-only (32 bytes)


# ---------------------------------------------------------------------------
# Address encoding helpers
# ---------------------------------------------------------------------------


def _base58check_encode(payload_with_checksum: bytes) -> str:
    """Base58 encode a payload that already has its 4-byte checksum appended."""
    _B58 = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    data = payload_with_checksum
    # Count leading zero bytes
    pad = 0
    for b in data:
        if b == 0:
            pad += 1
        else:
            break
    num = int.from_bytes(data, "big")
    result = ""
    while num > 0:
        num, rem = divmod(num, 58)
        result = chr(_B58[rem]) + result
    return "1" * pad + result


def _p2pkh_address(pkh: bytes, version: int = _MAINNET_P2PKH) -> str:
    """Base58Check P2PKH for the given version byte (mainnet 0x00, testnet 0x6F)."""
    payload = bytes([version]) + pkh
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return _base58check_encode(payload + checksum)


def _p2wpkh_address(pkh: bytes, hrp: str = "bc") -> str:
    """P2WPKH bech32 for the given HRP (bc=mainnet, tb=testnet, bcrt=regtest)."""
    return _bech32_encode(hrp, 0, pkh)


def _p2sh_address(script_hash: bytes, version: int = _MAINNET_P2SH) -> str:
    """Base58Check P2SH for the given version byte (mainnet 0x05, testnet 0xC4)."""
    payload = bytes([version]) + script_hash
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return _base58check_encode(payload + checksum)


def _p2tr_address(output_key_32: bytes, hrp: str = "bc") -> str:
    """P2TR bech32m for the given HRP (bc=mainnet, tb=testnet, bcrt=regtest)."""
    return _bech32_encode(hrp, 1, output_key_32)  # witness version 1 = bech32m


# ---------------------------------------------------------------------------
# BIP173/BIP350 bech32/bech32m encode
# ---------------------------------------------------------------------------


def _bech32_polymod(values: list[int]) -> int:
    """Compute the bech32 checksum polynomial."""
    c = 1
    for v in values:
        c0 = c >> 25
        c = ((c & 0x1FFFFFF) << 5) ^ v
        for i, gen in enumerate(_BECH32_GENERATOR):
            if (c0 >> i) & 1:
                c ^= gen
    return c


def _bech32_hrp_expand(hrp: str) -> list[int]:
    """Expand the HRP into values for checksum computation."""
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _bech32_create_checksum(hrp: str, data: list[int], spec: int) -> list[int]:
    """Compute the 6-character checksum for a bech32/bech32m string."""
    values = _bech32_hrp_expand(hrp) + data
    polymod = _bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ spec
    return [(polymod >> (5 * (5 - i))) & 31 for i in range(6)]


def _convertbits(data: bytes, frombits: int, tobits: int) -> list[int]:
    """Convert between bit groupings (e.g. 8-bit bytes to 5-bit groups)."""
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = ((acc << frombits) | value) & 0x3FFFFFFF
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if bits:
        ret.append((acc << (tobits - bits)) & maxv)
    return ret


def _bech32_encode(hrp: str, witness_version: int, witness_program: bytes) -> str:
    """Encode a Bitcoin native SegWit address.

    Uses bech32 for witness version 0 (BIP173) and bech32m for version 1+
    (BIP350). On mainnet the encoded address starts with ``bc1q`` (v0) or
    ``bc1p`` (v1); on testnet ``tb1q`` / ``tb1p``.
    """
    spec = _BECH32M_CONST if witness_version > 0 else _BECH32_CONST
    data = _convertbits(witness_program, 8, 5)
    combined = [witness_version] + data
    checksum = _bech32_create_checksum(hrp, combined, spec)
    return hrp + "1" + "".join(_BECH32_CHARSET[d] for d in combined + checksum)
