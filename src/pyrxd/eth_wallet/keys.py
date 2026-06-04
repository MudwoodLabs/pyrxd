"""ETH key handling — wraps the repo's :class:`PrivateKeyMaterial`, never a plaintext key.

The signing key is held as :class:`pyrxd.security.secrets.PrivateKeyMaterial` (unpicklable,
zeroizable, raw bytes gated behind ``unsafe_raw_bytes()``) — NOT as an
``eth_account.LocalAccount`` (whose ``.key`` hands back a plaintext ``bytes`` private key,
which would escape the SDK-wide secret-handling discipline and repeat the weak-key
incident). The raw bytes are produced only at the signing call site and never persisted.

Address derivation needs keccak256 over the secp256k1 public key, which lives in the eth
stack (``eth-keys``/``eth-utils``); that import is deferred so this module — and the rest
of ``eth_wallet`` — loads with no Ethereum dependency installed. Only ``derive_address``
(and the web3-backed leg) require the eth deps; key generation/holding does not.
"""

from __future__ import annotations

from pyrxd.security.errors import ValidationError
from pyrxd.security.secrets import PrivateKeyMaterial

__all__ = ["derive_address", "generate_eth_key"]


def generate_eth_key() -> PrivateKeyMaterial:
    """A fresh CSPRNG ETH signing key as :class:`PrivateKeyMaterial`.

    CSPRNG only (``PrivateKeyMaterial.generate`` → ``os.urandom``). Never hand-write key
    material for a funded address (the weak-key lesson). The caller feeds
    ``key.unsafe_raw_bytes()`` to the signer at the call site and zeroizes when done.
    """
    return PrivateKeyMaterial.generate()


def derive_address(key: PrivateKeyMaterial) -> str:
    """Derive the 0x EIP-55-ish address from the private key material.

    Deferred eth-keys import so the package loads without Ethereum deps. Raises a clear
    error if the eth stack is absent (it is a Phase-3 network/runtime dependency).
    """
    if not isinstance(key, PrivateKeyMaterial):
        raise ValidationError("derive_address requires PrivateKeyMaterial")
    try:
        from eth_keys import keys as _eth_keys  # type: ignore
    except ImportError as exc:  # pragma: no cover - exercised only without eth deps
        raise ValidationError("derive_address needs the eth stack (eth-keys/web3); install the eth extra") from exc
    raw = key.unsafe_raw_bytes()
    try:
        pk = _eth_keys.PrivateKey(raw)
        return pk.public_key.to_checksum_address()
    finally:
        del raw
