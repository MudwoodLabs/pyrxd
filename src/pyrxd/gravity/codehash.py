"""P2SH code hash computation for Gravity covenant verification.

Port of ``reference/extract_p2sh_code_hash.js``.  Computes the
``expectedClaimedCodeHash`` that MakerOffer verifies on-chain.
"""

from __future__ import annotations

from pyrxd.hash import hash160, hash256
import hashlib

from pyrxd.hash import hash160 as _hash160
from pyrxd.security.errors import ValidationError

__all__ = [
    "compute_p2sh_address_from_redeem",
    "compute_p2sh_code_hash",
    "compute_p2sh_script_pubkey",
    "hash160",
    "hash256",
]


# Both RE-EXPORTED from :mod:`pyrxd.hash` rather than re-defined here. They stay
# in ``__all__`` because ``gravity/transactions.py`` and external callers import
# them from this module.
#
# ``hash160`` in particular MUST come from ``pyrxd.hash``: that module falls back
# to a pure-Python RIPEMD160 when OpenSSL refuses it, which is the default on
# OpenSSL 3 — Ubuntu 24.04, Debian 12, the python.org macOS builds, Pyodide. The
# direct ``hashlib.new("ripemd160", ...)`` that used to live here raised
# ``ValueError`` on every one of them, and this is the function that derives the
# P2SH scriptPubKey the Gravity claim path pays to.
def hash256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def hash160(data: bytes) -> bytes:
    """RIPEMD160(SHA256(data)).

    Delegates to :func:`pyrxd.hash.hash160`, which exists precisely to survive
    an OpenSSL 3 build with the legacy provider unloaded — the default on
    Ubuntu 24.04, Debian 12, the python.org macOS installer, and Pyodide/WASM.
    This called ``hashlib.new("ripemd160", ...)`` directly, walking past that
    fallback and raising ``ValueError`` on every such host. Not reproducible on
    a machine whose OpenSSL still exposes RIPEMD160, so it is a portability
    defect rather than a live one — but the value it feeds
    (``expectedClaimedCodeHash``) is what a Gravity covenant checks on chain,
    so the failure mode is "cannot build or verify an offer at all" on those
    platforms.
    """
    return _hash160(data)


def compute_p2sh_script_pubkey(redeem_script: bytes) -> bytes:
    """Build the 23-byte P2SH scriptPubKey for a given redeem script.

    ``OP_HASH160 <20B script-hash> OP_EQUAL``
    """
    script_hash = hash160(redeem_script)
    return b"\xa9\x14" + script_hash + b"\x87"


def compute_p2sh_code_hash(redeem_script: bytes) -> bytes:
    """Compute expectedClaimedCodeHash: ``hash256`` of the P2SH scriptPubKey.

    This is what MakerOffer checks on-chain::

        hash256(tx.outputs[0].codeScript) == expectedClaimedCodeHash

    For P2SH outputs the ``codeScript`` is the 23-byte
    ``OP_HASH160 <hash> OP_EQUAL`` scriptPubKey.

    Audit 05-F-13 fix: caller passes the claimed redeem script; we derive
    the hash independently rather than trusting a caller-supplied value.
    """
    if not redeem_script:
        raise ValidationError("redeem_script must not be empty")
    p2sh_spk = compute_p2sh_script_pubkey(redeem_script)
    return hash256(p2sh_spk)


def compute_p2sh_address_from_redeem(redeem_script: bytes) -> str:
    """Compute the Radiant P2SH address for a redeem script.

    Radiant uses the same P2SH encoding as Bitcoin mainnet (version byte 0x05).
    """
    from pyrxd.base58 import base58check_encode

    script_hash = hash160(redeem_script)
    payload = b"\x05" + script_hash
    return base58check_encode(payload)
