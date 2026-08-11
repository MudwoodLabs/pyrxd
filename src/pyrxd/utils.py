from __future__ import annotations

import math
import re
import struct
from base64 import b64decode, b64encode
from contextlib import suppress
from io import BytesIO
from secrets import randbits
from typing import Literal

from .base58 import base58check_decode
from .compactsize import COMPACT_SIZE_MAX, PREFIX_WIDTHS, encode_compact_size, read_compact_size
from .constants import ADDRESS_PREFIX_NETWORK_DICT, NUMBER_BYTE_LENGTH, WIF_PREFIX_NETWORK_DICT, Network, OpCode
from .curve import curve
from .hash import hash256
from .security.errors import Base58Error, ValidationError


def unsigned_to_varint(num: int) -> bytes:
    """
    convert an unsigned int to varint.

    The encoding is :func:`pyrxd.compactsize.encode_compact_size`, which is also
    what the SDK's readers accept — that mutual property is the whole reason a
    non-minimal encoding is detectable. Only the out-of-range exception type is
    local: this function has raised ``OverflowError`` for its entire history and
    callers across ``transaction/`` catch it, so the range check stays here
    rather than surfacing the shared codec's ``ValidationError``.
    """
    if num < 0 or num > COMPACT_SIZE_MAX:
        raise OverflowError(f"can't convert {num} to varint")
    return encode_compact_size(num)


def unsigned_to_bytes(num: int, byteorder: Literal["big", "little"] = "big") -> bytes:
    """
    convert an unsigned int to the least number of bytes as possible.
    """
    return num.to_bytes(math.ceil(num.bit_length() / 8) or 1, byteorder)


def decode_address(address: str) -> tuple[bytes, Network]:
    """
    :returns: tuple (public_key_hash_bytes, network)
    """
    if not re.match(r"^[1mn][a-km-zA-HJ-NP-Z1-9]{24,33}$", address):
        # - a Bitcoin address is between 25 and 34 characters long;
        # - the address always starts with a 1, m, or n
        # - an address can contain all alphanumeric characters, with the exceptions of 0, O, I, and l.
        #
        # The rejected string is NOT echoed. An address is public, but this is the
        # branch a *non*-address takes, and the most likely non-address an operator
        # pastes into an address field is a WIF — which is exactly the shape this
        # regex rejects (starts with 5/K/L, 51-52 chars).
        raise Base58Error("invalid P2PKH address")
    decoded = base58check_decode(address)
    prefix = decoded[:1]
    network = ADDRESS_PREFIX_NETWORK_DICT.get(prefix)
    return decoded[1:], network


def validate_address(address: str, network: Network | None = None) -> bool:
    """
    :returns: True if address is a valid bitcoin legacy address (P2PKH)
    """
    with suppress(Exception):
        _, _network = decode_address(address)
        if network is not None:
            return _network == network
        return True
    return False


def address_to_public_key_hash(address: str) -> bytes:
    """
    :returns: convert P2PKH address to the corresponding public key hash
    """
    return decode_address(address)[0]


def decode_wif(wif: str) -> tuple[bytes, bool, Network]:
    """
    :returns: tuple (private_key_bytes, compressed, network)
    """
    decoded = base58check_decode(wif)
    prefix = decoded[:1]
    network = WIF_PREFIX_NETWORK_DICT.get(prefix)
    if not network:
        # The version byte is withheld too. It is only reachable for a WIF whose
        # checksum already verified — i.e. a real key — and this module's rule is
        # that nothing decoded from a WIF is interpolated into a message. The
        # network is readable from the WIF's own first character anyway
        # (5/K/L = mainnet, 9/c = testnet).
        raise Base58Error("unknown WIF network prefix")
    if len(wif) == 52 and decoded[-1] == 1:
        return decoded[1:-1], True, network
    return decoded[1:], False, network


def deserialize_ecdsa_der(signature: bytes) -> tuple[int, int]:
    """
    Deserialize ECDSA signature from bitcoin strict DER to (r, s).

    Strict-DER layout::

        30 <total_len> 02 <r_len> <r ...> 02 <s_len> <s ...>

    Length fields are cross-checked: ``total_len == 4 + r_len + s_len`` and
    ``len(signature) == 2 + total_len``. Both ``r`` and ``s`` are sliced from
    their declared offsets, never from the end of the buffer — earlier
    versions sliced ``s`` via ``signature[-s_len:]`` which silently accepted
    any trailing bytes when the declared lengths did not match the buffer
    size. That permitted attacker-chosen non-canonical encodings to
    round-trip to a valid ``(r, s)`` of the attacker's choosing.
    """
    try:
        if len(signature) < 8:
            raise ValueError("DER signature too short (min 8 bytes)")
        if signature[0] != 0x30:
            raise ValueError("expected DER sequence tag 0x30")

        total_len = int(signature[1])
        if total_len != len(signature) - 2:
            raise ValueError("DER length mismatch")

        # r
        if signature[2] != 0x02:
            raise ValueError("expected DER integer tag 0x02 for r")
        r_len = int(signature[3])
        if r_len == 0:
            raise ValueError("DER r length is zero")
        r_off = 4
        r_end = r_off + r_len
        if r_end + 2 > len(signature):
            raise ValueError("DER r overruns buffer")
        r = int.from_bytes(signature[r_off:r_end], "big")

        # s
        if signature[r_end] != 0x02:
            raise ValueError("expected DER integer tag 0x02 for s")
        s_len = int(signature[r_end + 1])
        if s_len == 0:
            raise ValueError("DER s length is zero")
        s_off = r_end + 2
        s_end = s_off + s_len
        if s_end != len(signature):
            raise ValueError("DER total length mismatch: r_len + s_len + 6 must equal len(signature)")
        s = int.from_bytes(signature[s_off:s_end], "big")

        return r, s
    except (ValueError, ValidationError):
        raise
    except Exception:
        # NEVER echo the signature. A signature made with a reused or leaked nonce ``k``
        # (the R-puzzle path in ``keys.PrivateKey._sign_custom_k`` produces exactly that
        # shape) plus the message hash recovers the private key, so ``r``/``s`` are key
        # material. This previously raised ``ValueError(f"invalid DER encoded
        # {signature.hex()}")`` — a bare ``ValueError``, so ``security.errors.redact``
        # never ran on it, and ``cli/main.py``'s catch-all prints ``cause: {exc}`` to
        # stderr. ``from None`` so it cannot resurface through ``__context__`` either.
        raise ValueError("invalid DER encoding") from None


def serialize_ecdsa_der(signature: tuple[int, int]) -> bytes:
    """
    serialize ECDSA signature (r, s) to bitcoin strict DER format
    """
    r, s = signature
    # enforce low s value
    if s > curve.n // 2:
        s = curve.n - s
    # r
    r_bytes = r.to_bytes(NUMBER_BYTE_LENGTH, "big").lstrip(b"\x00")
    if r_bytes[0] & 0x80:
        r_bytes = b"\x00" + r_bytes
    serialized = bytes([2, len(r_bytes)]) + r_bytes
    # s
    s_bytes = s.to_bytes(NUMBER_BYTE_LENGTH, "big").lstrip(b"\x00")
    if s_bytes[0] & 0x80:
        s_bytes = b"\x00" + s_bytes
    serialized += bytes([2, len(s_bytes)]) + s_bytes
    return bytes([0x30, len(serialized)]) + serialized


def deserialize_ecdsa_recoverable(signature: bytes) -> tuple[int, int, int]:
    """
    deserialize recoverable ECDSA signature from bytes to (r, s, recovery_id)
    """
    if len(signature) != 65:
        raise ValidationError("invalid length of recoverable ECDSA signature")
    rec_id = signature[-1]
    if not (0 <= rec_id <= 3):
        raise ValidationError(f"invalid recovery id {rec_id}")
    r = int.from_bytes(signature[:NUMBER_BYTE_LENGTH], "big")
    s = int.from_bytes(signature[NUMBER_BYTE_LENGTH:-1], "big")
    return r, s, rec_id


def serialize_ecdsa_recoverable(signature: tuple[int, int, int]) -> bytes:
    """
    serialize recoverable ECDSA signature from (r, s, recovery_id) to bytes
    """
    _r, _s, _rec_id = signature
    if not (0 <= _rec_id < 4):
        raise ValidationError(f"invalid recovery id {_rec_id}")
    r = _r.to_bytes(NUMBER_BYTE_LENGTH, "big")
    s = _s.to_bytes(NUMBER_BYTE_LENGTH, "big")
    rec_id = _rec_id.to_bytes(1, "big")
    return r + s + rec_id


def serialize_text(text: str) -> bytes:
    """
    serialize plain text to bytes in format: varint_length + text.utf-8
    """
    message: bytes = text.encode("utf-8")
    return unsigned_to_varint(len(message)) + message


def text_digest(text: str) -> bytes:
    """
    :returns: the digest of arbitrary text when signing with bitcoin private key
    """
    return serialize_text("Bitcoin Signed Message:\n") + serialize_text(text)


def stringify_ecdsa_recoverable(signature: bytes, compressed: bool = True) -> str:
    """stringify serialize recoverable ECDSA signature
    :param signature: serialized recoverable ECDSA signature in "r (32 bytes) + s (32 bytes) + recovery_id (1 byte)"
    :param compressed: True if used compressed public key
    :returns: stringified recoverable signature formatted in base64
    """
    _r, _s, recovery_id = deserialize_ecdsa_recoverable(signature)
    prefix: int = 27 + recovery_id + (4 if compressed else 0)
    signature: bytes = prefix.to_bytes(1, "big") + signature[:-1]
    return b64encode(signature).decode("ascii")


def unstringify_ecdsa_recoverable(signature: str) -> tuple[bytes, bool]:
    """
    :returns: (serialized_recoverable_signature, used_compressed_public_key)
    """
    serialized = b64decode(signature)
    if len(serialized) != 65:
        raise ValidationError("invalid length of recoverable ECDSA signature")
    prefix = serialized[0]
    if not (27 <= prefix < 35):
        raise ValidationError(f"invalid recoverable ECDSA signature prefix {prefix}")
    compressed = False
    if prefix >= 31:
        compressed = True
        prefix -= 4
    recovery_id = prefix - 27
    return serialized[1:] + recovery_id.to_bytes(1, "big"), compressed


def bytes_to_bits(octets: str | bytes) -> str:
    """
    convert bytes to binary 0/1 string
    """
    b: bytes = octets if isinstance(octets, bytes) else bytes.fromhex(octets)
    bits: str = bin(int.from_bytes(b, "big"))[2:]
    if len(bits) < len(b) * 8:
        bits = "0" * (len(b) * 8 - len(bits)) + bits
    return bits


def bits_to_bytes(bits: str) -> bytes:
    """
    convert binary 0/1 string to bytes
    """
    byte_length = math.ceil(len(bits) / 8) or 1
    return int(bits, 2).to_bytes(byte_length, byteorder="big")


def randbytes(length: int) -> bytes:
    """
    generate cryptographically secure random bytes
    """
    return randbits(length * 8).to_bytes(length, "big")


def get_pushdata_code(byte_length: int) -> bytes:
    """
    :returns: the corresponding PUSHDATA opcode according to the byte length of pushdata
    """
    if byte_length <= 0x4B:
        return byte_length.to_bytes(1, "little")
    elif byte_length <= 0xFF:
        # OP_PUSHDATA1
        return OpCode.OP_PUSHDATA1 + byte_length.to_bytes(1, "little")
    elif byte_length <= 0xFFFF:
        # OP_PUSHDATA2
        return OpCode.OP_PUSHDATA2 + byte_length.to_bytes(2, "little")
    elif byte_length <= 0xFFFFFFFF:
        # OP_PUSHDATA4
        return OpCode.OP_PUSHDATA4 + byte_length.to_bytes(4, "little")
    else:
        raise ValueError("data too long to encode in a PUSHDATA opcode")


def encode_pushdata(pushdata: bytes, minimal_push: bool = True) -> bytes:
    """encode pushdata with proper opcode
    https://github.com/bitcoin-sv/bitcoin-sv/blob/v1.0.10/src/script/interpreter.cpp#L310-L337
    :param pushdata: bytes you want to push onto the stack in bitcoin script
    :param minimal_push: if True then push data following the minimal push rule
    """
    if minimal_push:
        if pushdata == b"":
            return OpCode.OP_0
        if len(pushdata) == 1 and 1 <= pushdata[0] <= 16:
            return bytes([OpCode.OP_1[0] + pushdata[0] - 1])
        if len(pushdata) == 1 and pushdata[0] == 0x81:
            return OpCode.OP_1NEGATE
    else:
        # non-minimal push requires pushdata != b''
        if not pushdata:
            raise ValidationError("empty pushdata")
    return get_pushdata_code(len(pushdata)) + pushdata


def encode_data_push(data: bytes, *, max_len: int | None = None) -> bytes:
    """A length-prefixed data push, with NO minimal-integer folding.

    ``OP_0`` for empty data; otherwise the direct-length / ``OP_PUSHDATA1`` /
    ``OP_PUSHDATA2`` / ``OP_PUSHDATA4`` form for ``len(data)``.

    Distinct from :func:`encode_pushdata` in exactly one way, and it is the
    difference that matters: this NEVER folds a one-byte value into ``OP_1``..
    ``OP_16``. ``encode_data_push(b"\\x05")`` is ``01 05``; ``encode_pushdata``
    would give ``OP_5``. Covenant scriptSigs whose fields are read positionally
    depend on the un-folded form, so the two are not interchangeable and the
    choice is deliberate at each call site.

    ``max_len`` caps the payload. It exists because the five hand-written copies
    this replaced each carried a different ceiling — 255 in one, 65,535 in three,
    unbounded in one — and folding them into a single number would have loosened
    a guard somewhere. Passing the cap keeps every original limit intact and,
    unlike a limit buried inside five near-identical helpers, visible.
    """
    n = len(data)
    if max_len is not None and n > max_len:
        raise ValidationError(f"push data too large: {n} bytes exceeds the {max_len}-byte limit")
    if n == 0:
        return OpCode.OP_0
    return get_pushdata_code(n) + data


def encode_script_num(num: int) -> bytes:
    """A signed integer as CScriptNum BODY bytes — little-endian, sign in the MSB.

    No push opcode: this is the number, not the instruction that pushes it. That
    split is what lets the two different push policies in this SDK share one
    number encoding — :func:`encode_int` folds small values into ``OP_N``,
    while the RSWP order wire format must emit a direct push of the same bytes
    (Photonic's ``encodeScriptNum``). They previously carried a copy each.

    Zero encodes as ``b""``, matching Radiant's ``CScriptNum::serialize``: an
    empty stack element IS zero, which is why ``encode_pushdata(b"")`` yields
    ``OP_0`` and the round trip closes.
    """
    if num == 0:
        return b""
    negative: bool = num < 0
    octets: bytearray = bytearray(unsigned_to_bytes(-num if negative else num, "little"))
    # If the top bit of the most-significant byte is set it would be read as the
    # sign bit, so the magnitude needs one more byte to stay unambiguous.
    if octets[-1] & 0x80:
        octets += b"\x00"
    if negative:
        octets[-1] |= 0x80
    return bytes(octets)


def decode_script_num(octets: bytes) -> int:
    """The inverse of :func:`encode_script_num`.

    ``b""`` is zero. Does NOT enforce minimal encoding — callers parsing an
    attacker-supplied script that must be minimal should compare against
    ``encode_script_num(decode_script_num(b))`` themselves, which is a cheaper
    and more obvious check than a flag on this function.
    """
    if not octets:
        return 0
    magnitude = int.from_bytes(octets, "little")
    if octets[-1] & 0x80:  # negative: clear the sign bit out of the top byte
        magnitude &= ~(0x80 << (8 * (len(octets) - 1)))
        return -magnitude
    return magnitude


def encode_int(num: int) -> bytes:
    """
    encode a signed integer you want to push onto the stack in bitcoin script, following the minimal push rule
    """
    return encode_pushdata(encode_script_num(num))


def to_hex(byte_array: bytes) -> str:
    return byte_array.hex()


def to_bytes(msg: bytes | str, enc: str | None = None) -> bytes:
    """Converts various message formats into a bytes object."""
    if isinstance(msg, bytes):
        return msg

    if not msg:
        return b""

    if isinstance(msg, str):
        if enc == "hex":
            msg = "".join(filter(str.isalnum, msg))
            if len(msg) % 2 != 0:
                msg = "0" + msg
            try:
                return bytes(int(msg[i : i + 2], 16) for i in range(0, len(msg), 2))
            except ValueError:
                # CPython's message is ``invalid literal for int() with base 16: 'XY'`` —
                # two characters of whatever was handed in. Callers pass private-key hex
                # here, so those two characters are key material. Static message instead.
                raise ValueError("value is not valid hex") from None
        elif enc == "base64":
            import base64

            return base64.b64decode(msg)
        else:  # UTF-8 encoding
            return msg.encode("utf-8")

    return bytes(msg)


def to_utf8(arr: list[int]) -> str:
    """Converts an array of numbers to a UTF-8 encoded string."""
    return bytes(arr).decode("utf-8")


def encode(arr: list[int], enc: str | None = None) -> str | list[int]:
    """Encodes an array of numbers into a specified encoding ('hex' or 'utf8')."""
    if enc == "hex":
        return to_hex(bytes(arr))
    elif enc == "utf8":
        return to_utf8(arr)
    return arr


def to_base64(byte_array: list[int]) -> str:
    """Converts an array of bytes into a base64 encoded string."""
    import base64

    return base64.b64encode(bytes(byte_array)).decode("ascii")


base58chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def from_base58(str_: str) -> list[int]:
    """Converts a base58 string to a binary array.

    Rejection messages are static for the same reason as :mod:`pyrxd.base58`:
    this decoder cannot tell a WIF from an address, so it never echoes its input.
    """
    if not str_ or not isinstance(str_, str):
        raise Base58Error("expected a non-empty base58 string")
    if "0" in str_ or "I" in str_ or "O" in str_ or "l" in str_:
        raise Base58Error("invalid base58 character")

    lz = len(str_) - len(str_.lstrip("1"))
    psz = lz

    acc = 0
    for char in str_:
        acc = acc * 58 + base58chars.index(char)

    result = []
    while acc > 0:
        result.append(acc % 256)
        acc //= 256

    return [0] * psz + list(reversed(result))


def to_base58(bin_: list[int]) -> str:
    """Converts a binary array into a base58 string."""
    acc = 0
    for byte in bin_:
        acc = acc * 256 + byte

    result = ""
    while acc > 0:
        acc, mod = divmod(acc, 58)
        result = base58chars[mod] + result

    for byte in bin_:
        if byte == 0:
            result = "1" + result
        else:
            break

    return result


def to_base58_check(bin_: list[int], prefix: list[int] | None = None) -> str:
    """Converts a binary array into a base58check string with a checksum."""

    if prefix is None:
        prefix = [0]
    hash_ = hash256(bytes(prefix + bin_))
    return to_base58(prefix + bin_ + list(hash_[:4]))


def from_base58_check(str_: str, enc: str | None = None, prefix_length: int = 1):
    """Converts a base58check string into a binary array after validating the checksum."""
    bin_ = from_base58(str_)
    prefix = bin_[:prefix_length]
    data = bin_[prefix_length:-4]
    checksum = bin_[-4:]

    hash_ = hash256(bytes(prefix + data))
    if list(hash_[:4]) != checksum:
        raise Base58Error("invalid base58 checksum")

    if enc == "hex":
        prefix = to_hex(bytes(prefix))
        data = to_hex(bytes(data))

    return {"prefix": prefix, "data": data}


class Writer(BytesIO):
    def __init__(self):
        super().__init__()

    def write(self, buf: bytes) -> Writer:
        super().write(buf)
        return self

    def write_reverse(self, buf: bytes) -> Writer:
        super().write(buf[::-1])
        return self

    def write_uint8(self, n: int) -> Writer:
        self.write(struct.pack("B", n))
        return self

    def write_int8(self, n: int) -> Writer:
        self.write(struct.pack("b", n))
        return self

    def write_uint16_be(self, n: int) -> Writer:
        self.write(struct.pack(">H", n))
        return self

    def write_int16_be(self, n: int) -> Writer:
        self.write(struct.pack(">h", n))
        return self

    def write_uint16_le(self, n: int) -> Writer:
        self.write(struct.pack("<H", n))
        return self

    def write_int16_le(self, n: int) -> Writer:
        self.write(struct.pack("<h", n))
        return self

    def write_uint32_be(self, n: int) -> Writer:
        self.write(struct.pack(">I", n))
        return self

    def write_int32_be(self, n: int) -> Writer:
        self.write(struct.pack(">i", n))
        return self

    def write_uint32_le(self, n: int) -> Writer:
        self.write(struct.pack("<I", n))
        return self

    def write_int32_le(self, n: int) -> Writer:
        self.write(struct.pack("<i", n))
        return self

    def write_uint64_be(self, n: int) -> Writer:
        self.write(struct.pack(">Q", n))
        return self

    def write_uint64_le(self, n: int) -> Writer:
        self.write(struct.pack("<Q", n))
        return self

    def write_var_int_num(self, n: int) -> Writer:
        self.write(self.var_int_num(n))
        return self

    def to_bytes(self) -> bytes:
        return self.getvalue()

    @staticmethod
    def var_int_num(n: int) -> bytes:
        return unsigned_to_varint(n)


class Reader(BytesIO):
    def __init__(self, data: bytes):
        super().__init__(data)

    def eof(self) -> bool:
        return self.tell() >= len(self.getvalue())

    def read(self, length: int = None) -> bytes:
        result = super().read(length)
        return result if result else None

    def read_reverse(self, length: int = None) -> bytes:
        data = self.read(length)
        return data[::-1] if data else None

    def read_uint8(self) -> int | None:
        data = self.read(1)
        return data[0] if data else None

    def read_int8(self) -> int | None:
        data = self.read(1)
        return int.from_bytes(data, byteorder="big", signed=True) if data else None

    def read_uint16_be(self) -> int | None:
        data = self.read(2)
        return int.from_bytes(data, byteorder="big") if data else None

    def read_int16_be(self) -> int | None:
        data = self.read(2)
        return int.from_bytes(data, byteorder="big", signed=True) if data else None

    def read_uint16_le(self) -> int | None:
        data = self.read(2)
        return int.from_bytes(data, byteorder="little") if data else None

    def read_int16_le(self) -> int | None:
        data = self.read(2)
        return int.from_bytes(data, byteorder="little", signed=True) if data else None

    def read_uint32_be(self) -> int | None:
        data = self.read(4)
        return int.from_bytes(data, byteorder="big") if data else None

    def read_int32_be(self) -> int | None:
        data = self.read(4)
        return int.from_bytes(data, byteorder="big", signed=True) if data else None

    def read_uint32_le(self) -> int | None:
        data = self.read(4)
        return int.from_bytes(data, byteorder="little") if data else None

    def read_int32_le(self) -> int | None:
        data = self.read(4)
        return int.from_bytes(data, byteorder="little", signed=True) if data else None

    def read_var_int_num(self) -> int | None:
        """Read a Bitcoin CompactSize, refusing non-canonical and truncated encodings.

        Returns ``None`` only at true end of input (nothing left to read at all) —
        the contract ``Transaction.from_reader`` and ``from_beef`` test with
        ``if count is None``. That end-of-stream signal is the *only* thing this
        method adds over :func:`pyrxd.compactsize.read_compact_size`, which owns
        the consensus rule for the whole SDK (audit 2026-05-29 F-15). Two
        concrete consequences of the accepting behaviour this replaced:

        * A node rejects a non-minimal CompactSize at deserialization, so the SDK
          parsed transactions that can never exist on chain and reported them as
          valid.
        * ``Transaction.from_hex(blob).serialize()`` silently re-emitted the CANONICAL
          encoding, so it did not round-trip: an 87-byte blob whose input count was
          written ``fd 01 00`` came back as 85 different bytes, and ``txid()``
          returned the id of a transaction those bytes are not. Anything binding a
          txid to bytes it was handed was comparing against a value the bytes do not
          hash to.
        """
        first_byte = self.read(1)
        if not first_byte:
            return None
        width_and_floor = PREFIX_WIDTHS.get(first_byte[0])
        if width_and_floor is None:
            return first_byte[0]
        # Hand the shared reader exactly the bytes of this one field. Slicing the
        # field out (rather than passing the whole buffer with an offset) keeps
        # this O(1) per varint: ``BytesIO.getvalue()`` copies the entire buffer,
        # which would make parsing an n-input transaction quadratic.
        field = first_byte + (self.read(width_and_floor[0]) or b"")
        return read_compact_size(field, 0)[0]

    def read_var_int(self) -> bytes | None:
        """The CompactSize field at the cursor, as RAW BYTES, advancing past it.

        Deliberately NOT a decoder: it hands back whatever was written, including
        a non-canonical encoding, because its only job is to re-serialise a field
        verbatim. The width dispatch comes from
        :data:`pyrxd.compactsize.PREFIX_WIDTHS` so it cannot disagree with the
        decoder about how many bytes the field occupies — disagreeing about the
        LENGTH would desynchronise the caller's parse, which is a different and
        worse failure than tolerating an overlong value.
        """
        first_byte = self.read(1)
        if not first_byte:
            return None
        width_and_floor = PREFIX_WIDTHS.get(first_byte[0])
        if width_and_floor is None:
            return first_byte
        return first_byte + (self.read(width_and_floor[0]) or b"")

    def read_bytes(self, byte_length: int | None = None) -> bytes:
        result = self.read(byte_length)
        return result if result else b""

    def read_int(self, byte_length: int, byteorder: Literal["big", "little"] = "little") -> int | None:
        octets = self.read_bytes(byte_length)
        if not octets:
            return None
        return int.from_bytes(octets, byteorder=byteorder)


def reverse_hex_byte_order(hex_str: str):
    return bytes.fromhex(hex_str)[::-1].hex()
