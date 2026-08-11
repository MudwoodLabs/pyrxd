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
from .constants import ADDRESS_PREFIX_NETWORK_DICT, NUMBER_BYTE_LENGTH, WIF_PREFIX_NETWORK_DICT, Network, OpCode
from .curve import curve
from .security.errors import Base58Error, ValidationError


def unsigned_to_varint(num: int) -> bytes:
    """
    convert an unsigned int to varint.
    """
    if num < 0 or num > 0xFFFFFFFFFFFFFFFF:
        raise OverflowError(f"can't convert {num} to varint")
    if num <= 0xFC:
        return num.to_bytes(1, "little")
    elif num <= 0xFFFF:
        return b"\xfd" + num.to_bytes(2, "little")
    elif num <= 0xFFFFFFFF:
        return b"\xfe" + num.to_bytes(4, "little")
    else:
        return b"\xff" + num.to_bytes(8, "little")


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


#: Consensus bounds on a DER signature body, excluding the trailing sighash
#: byte. ``IsValidDERSignatureEncoding`` rejects anything outside them
#: (``src/script/sigencoding.cpp``); ``tests/test_consensus_parser_strictness.py``
#: re-derives both numbers from the vendored copy of that file.
DER_SIGNATURE_MIN_LENGTH: int = 8
DER_SIGNATURE_MAX_LENGTH: int = 72


def _check_der_integer(signature: bytes, start: int, length: int, name: str) -> None:
    """Apply the two canonical-integer rules ``IsValidDERSignatureEncoding`` applies.

    Both are consensus on Radiant, not stylistic: strict-DER encoding is
    enforced whenever any of ``SCRIPT_VERIFY_DERSIG``/``LOW_S``/``STRICTENC``
    is set, and a block is connected with LOW_S and STRICTENC always on
    (``GetNextBlockScriptFlags``). ``VerifyScript`` additionally ORs STRICTENC
    in because SIGHASH_FORKID is set, so there is no configuration of this
    chain in which they are optional.
    """
    if signature[start] & 0x80:
        raise ValueError(f"non-canonical DER: {name} is negative (high bit set on its first byte)")
    if length > 1 and signature[start] == 0x00 and not (signature[start + 1] & 0x80):
        raise ValueError(f"non-canonical DER: {name} has non-minimal zero padding")


def deserialize_ecdsa_der(signature: bytes, *, require_low_s: bool = True) -> tuple[int, int]:
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

    Beyond the length arithmetic this now applies every rule Radiant applies
    when it validates a signature, because a decoder that is more permissive
    than consensus reports "valid" for bytes no block can contain, and hands
    back an ``(r, s)`` that re-encodes to *different* bytes than it was given
    — a malleability and divergence hazard in one:

    * total size within ``[8, 72]`` (``IsValidDERSignatureEncoding``);
    * ``r`` and ``s`` positive and minimally encoded (BIP66, and consensus here
      via ``SCRIPT_VERIFY_STRICTENC``, which ``VerifyScript`` turns on for
      SIGHASH_FORKID — mandatory on this chain);
    * ``s <= n/2`` (``CPubKey::CheckLowS`` under ``SCRIPT_VERIFY_LOW_S``, set
      unconditionally for every connected block in ``GetNextBlockScriptFlags``).

    ``require_low_s=False`` is the deliberate, explicit escape hatch for
    inspecting a *foreign* signature — a pre-BIP146 Bitcoin history blob, or
    one produced by another chain's tooling. It relaxes only the low-S rule;
    the encoding rules are never relaxed, because a non-canonical encoding is
    invalid on every chain this SDK touches.
    """
    try:
        if len(signature) < DER_SIGNATURE_MIN_LENGTH:
            raise ValueError(f"DER signature too short (min {DER_SIGNATURE_MIN_LENGTH} bytes)")
        if len(signature) > DER_SIGNATURE_MAX_LENGTH:
            raise ValueError(f"DER signature too long (max {DER_SIGNATURE_MAX_LENGTH} bytes)")
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
        _check_der_integer(signature, r_off, r_len, "r")
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
        _check_der_integer(signature, s_off, s_len, "s")
        s = int.from_bytes(signature[s_off:s_end], "big")

        if require_low_s and s > curve.n // 2:
            raise ValueError(
                "non-canonical DER: high-S signature. SCRIPT_VERIFY_LOW_S is applied to every "
                "connected block, so its complement (n - s) is the only encoding that can confirm"
            )

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


def encode_int(num: int) -> bytes:
    """
    encode a signed integer you want to push onto the stack in bitcoin script, following the minimal push rule
    """
    if num == 0:
        return OpCode.OP_0
    negative: bool = num < 0
    octets: bytearray = bytearray(unsigned_to_bytes(-num if negative else num, "little"))
    if octets[-1] & 0x80:
        octets += b"\x00"
    if negative:
        octets[-1] |= 0x80
    return encode_pushdata(octets)


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
    import hashlib

    if prefix is None:
        prefix = [0]
    hash_ = hashlib.sha256(hashlib.sha256(bytes(prefix + bin_)).digest()).digest()
    return to_base58(prefix + bin_ + list(hash_[:4]))


def from_base58_check(str_: str, enc: str | None = None, prefix_length: int = 1):
    """Converts a base58check string into a binary array after validating the checksum."""
    bin_ = from_base58(str_)
    prefix = bin_[:prefix_length]
    data = bin_[prefix_length:-4]
    checksum = bin_[-4:]

    import hashlib

    hash_ = hashlib.sha256(hashlib.sha256(bytes(prefix + data)).digest()).digest()
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

    def read_exact(self, length: int) -> bytes | None:
        """Read exactly ``length`` bytes, or ``None`` if that many are not left.

        ``BytesIO.read(n)`` returns a SHORT buffer at end of input rather than
        erroring, and ``int.from_bytes`` happily zero-extends it — so a
        four-byte field with two bytes remaining used to decode as a perfectly
        plausible number instead of failing. Every fixed-width field in the
        transaction wire format (version, vout, sequence, locktime, satoshis)
        is exposed to that, and each one is load-bearing for a txid.
        """
        data = super().read(length)
        return data if data is not None and len(data) == length else None

    def read_reverse(self, length: int = None) -> bytes:
        data = self.read(length)
        return data[::-1] if data else None

    def read_uint8(self) -> int | None:
        data = self.read_exact(1)
        return data[0] if data else None

    def read_int8(self) -> int | None:
        data = self.read_exact(1)
        return int.from_bytes(data, byteorder="big", signed=True) if data else None

    def read_uint16_be(self) -> int | None:
        data = self.read_exact(2)
        return int.from_bytes(data, byteorder="big") if data else None

    def read_int16_be(self) -> int | None:
        data = self.read_exact(2)
        return int.from_bytes(data, byteorder="big", signed=True) if data else None

    def read_uint16_le(self) -> int | None:
        data = self.read_exact(2)
        return int.from_bytes(data, byteorder="little") if data else None

    def read_int16_le(self) -> int | None:
        data = self.read_exact(2)
        return int.from_bytes(data, byteorder="little", signed=True) if data else None

    def read_uint32_be(self) -> int | None:
        data = self.read_exact(4)
        return int.from_bytes(data, byteorder="big") if data else None

    def read_int32_be(self) -> int | None:
        data = self.read_exact(4)
        return int.from_bytes(data, byteorder="big", signed=True) if data else None

    def read_uint32_le(self) -> int | None:
        data = self.read_exact(4)
        return int.from_bytes(data, byteorder="little") if data else None

    def read_int32_le(self) -> int | None:
        data = self.read_exact(4)
        return int.from_bytes(data, byteorder="little", signed=True) if data else None

    #: CompactSize prefix -> (operand width, largest value the SHORTER encoding covers).
    #: A value at or below the floor means a shorter encoding existed, so this one is
    #: non-canonical. Mirrors ``spv/proof.py`` and ``spv/witness.py``.
    _VAR_INT_WIDTHS: dict[int, tuple[int, int]] = {0xFD: (2, 0xFC), 0xFE: (4, 0xFFFF), 0xFF: (8, 0xFFFFFFFF)}

    def read_var_int_num(self) -> int | None:
        """Read a Bitcoin CompactSize, refusing non-canonical and truncated encodings.

        Returns ``None`` only at true end of input (nothing left to read at all) —
        the contract ``Transaction.from_reader`` and ``from_beef`` test with
        ``if count is None``.

        Audit 2026-05-29 F-15, applied here to match ``spv/proof.py`` and
        ``spv/witness.py``. This copy sits under ``Transaction`` deserialization —
        every hostile-bytes parse in the SDK — and was the last one still accepting
        overlong encodings. Two concrete consequences of accepting them:

        * A node rejects a non-minimal CompactSize at deserialization, so the SDK
          parsed transactions that can never exist on chain and reported them as
          valid.
        * ``Transaction.from_hex(blob).serialize()`` silently re-emitted the CANONICAL
          encoding, so it did not round-trip: an 87-byte blob whose input count was
          written ``fd 01 00`` came back as 85 different bytes, and ``txid()``
          returned the id of a transaction those bytes are not. Anything binding a
          txid to bytes it was handed was comparing against a value the bytes do not
          hash to.

        Truncation is refused for the same reason it is in the SPV readers: an operand
        running off the end used to be zero-extended by ``int.from_bytes`` over a short
        read, so ``fd 01`` silently decoded as 1.
        """
        first_byte = self.read_uint8()
        if first_byte is None:
            return None
        if first_byte < 0xFD:
            return first_byte

        width, floor = self._VAR_INT_WIDTHS[first_byte]
        data = self.read(width)
        if data is None or len(data) != width:
            raise ValidationError(f"truncated {width}-byte varint")
        value = int.from_bytes(data, byteorder="little")
        if value <= floor:
            raise ValidationError(f"non-canonical varint: 0x{first_byte:02X} prefix encodes {value} (<= {floor})")
        return value

    def read_var_int(self) -> bytes | None:
        first_byte = self.read(1)
        if not first_byte:
            return None
        if first_byte[0] == 0xFD:
            return first_byte + (self.read(2) or b"")
        elif first_byte[0] == 0xFE:
            return first_byte + (self.read(4) or b"")
        elif first_byte[0] == 0xFF:
            return first_byte + (self.read(8) or b"")
        else:
            return first_byte

    def read_bytes(self, byte_length: int | None = None) -> bytes:
        result = self.read(byte_length)
        return result if result else b""

    def read_int(self, byte_length: int, byteorder: Literal["big", "little"] = "little") -> int | None:
        """Read a fixed-width integer, or ``None`` if the field is incomplete.

        Fails closed on a short read for the reason spelled out in
        :meth:`read_exact`: a partially-present field is not a smaller number,
        it is a truncated transaction.
        """
        octets = self.read_exact(byte_length)
        if not octets:
            return None
        return int.from_bytes(octets, byteorder=byteorder)


def reverse_hex_byte_order(hex_str: str):
    return bytes.fromhex(hex_str)[::-1].hex()
