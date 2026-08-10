"""base58 / base58check codec.

Decode failures raise :class:`~pyrxd.security.errors.Base58Error` and **never
echo the input, or anything decoded from it**. This module is the single
choke point through which every WIF, xprv, xpub, and address in the SDK is
parsed, and it cannot tell them apart: by the time a string reaches
:func:`b58_decode` there is no type information left saying "this one is
public". So it treats every input as secret. See ``Base58Error`` for the
concrete leak this closes.
"""

from __future__ import annotations

from .hash import hash256
from .security.errors import Base58Error

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _checksum(payload: bytes) -> bytes:
    return hash256(payload)[:4]


def b58_encode(payload: bytes) -> str:
    pad = 0
    for byte in payload:
        if byte == 0:
            pad += 1
        else:
            break
    prefix = "1" * pad
    num = int.from_bytes(payload, "big")
    result = ""
    while num > 0:
        num, remaining = divmod(num, 58)
        result = BASE58_ALPHABET[remaining] + result
    return prefix + result


def base58check_encode(payload: bytes) -> str:
    return b58_encode(payload + _checksum(payload))


def to_base58check(payload: bytes, prefix: bytes) -> str:
    """
    Converts a binary array into a base58check string with a checksum
    :param payload: The binary array to convert to base58check
    :param prefix: The prefix to add to the binary
    :return: The base58check string representation
    """
    return base58check_encode(prefix + payload)


def from_base58check(encoded: str, prefix_len: int = 1) -> (bytes, bytes):
    """
    Converts a base58check string into payload and prefix
    :param encoded: The base58check string to convert
    :param prefix_len: The byte length of the prefix
    :return: A tuple containing the prefix and the payload
    """
    payload = base58check_decode(encoded)
    return payload[:prefix_len], payload[prefix_len:]


def b58_decode(encoded: str) -> bytes:
    pad = 0
    for char in encoded:
        if char == "1":
            pad += 1
        else:
            break
    prefix = b"\x00" * pad
    num = 0
    try:
        for char in encoded:
            num *= 58
            num += BASE58_ALPHABET.index(char)
    except Exception:
        # `from None` so the offending string cannot resurface through
        # __cause__/__context__ in a traceback either. The message is static:
        # `encoded` may be a WIF or an xprv.
        raise Base58Error("invalid base58 encoding") from None
    # if num is 0 then (0).to_bytes will return b''
    return prefix + num.to_bytes((num.bit_length() + 7) // 8, "big")


def base58check_decode(encoded: str) -> bytes:
    decoded = b58_decode(encoded)
    payload = decoded[:-4]
    decoded_checksum = decoded[-4:]
    hash_checksum = _checksum(payload)
    if decoded_checksum != hash_checksum:
        # Neither checksum is reported. The trailing four bytes come straight out
        # of the caller's string and the computed four are hash256 over the
        # decoded payload — for a mistyped WIF that payload IS the private key,
        # so both are functions of key material and neither belongs in a message.
        raise Base58Error("unmatched base58 checksum")
    return payload
