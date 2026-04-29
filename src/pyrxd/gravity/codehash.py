"""P2SH code hash computation for Gravity covenant verification.

Port of ``reference/extract_p2sh_code_hash.js``.  Computes the
``expectedClaimedCodeHash`` that MakerOffer verifies on-chain.
"""

from __future__ import annotations

import hashlib

from pyrxd.security.errors import ValidationError

__all__ = [
    "compute_p2sh_code_hash",
    "compute_p2sh_script_pubkey",
    "compute_p2sh_address_from_redeem",
    "hash256",
    "hash160",
]


def hash256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def hash160(data: bytes) -> bytes:
    return hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()


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
