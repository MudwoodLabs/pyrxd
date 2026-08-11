"""Byte-for-byte proof that consolidating the script encoders changed nothing.

The risk in replacing several local implementations with one shared one is not
that the shared one is wrong — it is that it is *subtly different*, and the
difference is then applied silently at every call site at once. A test asserting
the new code is self-consistent cannot see that; only a comparison against what
the code used to do can.

So each ``_reference_*`` below is a **verbatim copy of the implementation that
was deleted**, preserved here as an oracle. If the consolidated encoder disagrees
with its predecessor on any input, this file says so and names the input.

These references are frozen on purpose. They must NOT be "fixed" to track future
changes to the production encoders — that would delete the only record of what
the pre-consolidation behaviour was. If a deliberate behaviour change lands, the
reference stays and the test that compares against it is updated to state the
new expectation explicitly.
"""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from pyrxd.glyph import payload as glyph_payload
from pyrxd.glyph.dmint import builders as dmint_builders
from pyrxd.gravity import htlc_covenant, htlc_spend, swap_order, transactions
from pyrxd.gravity.htlc_covenant import _minimal_num_push, _scriptnum
from pyrxd.security.errors import ValidationError
from pyrxd.swap.rswp import wire as rswp_wire
from pyrxd.utils import decode_script_num, encode_data_push, encode_int, encode_script_num

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# The deleted implementations, verbatim
# ---------------------------------------------------------------------------


def _reference_scriptnum(n: int) -> bytes:
    """Was ``gravity/htlc_covenant.py::_scriptnum``."""
    if n == 0:
        return b""
    neg = n < 0
    n = abs(n)
    out = bytearray()
    while n:
        out.append(n & 0xFF)
        n >>= 8
    if out[-1] & 0x80:
        out.append(0x80 if neg else 0x00)
    elif neg:
        out[-1] |= 0x80
    return bytes(out)


def _reference_encode_int(num: int) -> bytes:
    """Was ``utils.py::encode_int`` (its own inline number encoding)."""
    if num == 0:
        return b"\x00"
    negative = num < 0
    magnitude = -num if negative else num
    octets = bytearray(magnitude.to_bytes((magnitude.bit_length() + 7) // 8 or 1, "little"))
    if octets[-1] & 0x80:
        octets += b"\x00"
    if negative:
        octets[-1] |= 0x80
    # ...then encode_pushdata(minimal_push=True)
    if len(octets) == 1 and 1 <= octets[0] <= 16:
        return bytes([0x51 + octets[0] - 1])
    if len(octets) == 1 and octets[0] == 0x81:
        return b"\x4f"
    return bytes([len(octets)]) + bytes(octets)


def _reference_push(b: bytes) -> bytes:
    """Was ``gravity/htlc_covenant.py::_push`` AND ``gravity/htlc_spend.py::_push``
    — the two were byte-identical, docstring included."""
    n = len(b)
    if n == 0:
        return b"\x00"
    if n <= 75:
        return bytes([n]) + b
    if n <= 255:
        return b"\x4c" + bytes([n]) + b
    if n <= 0xFFFF:
        return b"\x4d" + n.to_bytes(2, "little") + b
    raise ValidationError("push data exceeds 64 KB limit")


def _reference_push_data(data: bytes) -> bytes:
    """Was ``gravity/transactions.py::_push_data``."""
    n = len(data)
    if n == 0:
        return b"\x00"
    elif n <= 75:
        return bytes([n]) + data
    elif n <= 255:
        return b"\x4c" + bytes([n]) + data
    elif n <= 65535:
        return b"\x4d" + n.to_bytes(2, "little") + data
    else:
        raise ValidationError(f"push data too large: {n} bytes")


def _reference_scriptnum_push(n: int) -> bytes:
    """Was ``swap/rswp/wire.py::_scriptnum_push``."""
    if n == 0:
        return b"\x00"
    octets = bytearray()
    remaining = n
    while remaining > 0:
        octets.append(remaining & 0xFF)
        remaining >>= 8
    if octets[-1] & 0x80:
        octets.append(0x00)
    return bytes([len(octets)]) + bytes(octets)


def _reference_decode_scriptnum(data: bytes) -> int:
    """Was ``gravity/swap_order.py::_decode_scriptnum``."""
    if not data:
        return 0
    n = int.from_bytes(data, "little")
    if data[-1] & 0x80:
        n &= ~(0x80 << (8 * (len(data) - 1)))
        return -n
    return n


def _reference_push_minimal(n: int) -> bytes:
    """Was ``glyph/dmint/builders.py::_push_minimal``."""
    if n == 0:
        return b"\x00"
    if n == -1:
        return b"\x4f"
    if 1 <= n <= 16:
        return bytes([0x50 + n])
    negative = n < 0
    n = abs(n)
    result = []
    while n > 0:
        result.append(n & 0xFF)
        n >>= 8
    if result[-1] & 0x80:
        result.append(0x80 if negative else 0x00)
    elif negative:
        result[-1] |= 0x80
    payload = bytes(result)
    length = len(payload)
    if length < 0x4C:
        return bytes([length]) + payload
    if length <= 0xFF:
        return b"\x4c" + bytes([length]) + payload
    raise ValidationError(f"pushMinimal: number too large: {n}")


def _reference_push_minimal_int(n: int) -> bytes:
    """Was ``glyph/payload.py::_push_minimal_int`` (non-negative only)."""
    if n == 0:
        return b"\x00"
    if 1 <= n <= 16:
        return bytes([0x50 + n])
    result = []
    while n > 0:
        result.append(n & 0xFF)
        n >>= 8
    if result[-1] & 0x80:
        result.append(0x00)
    payload = bytes(result)
    length = len(payload)
    if length < 0x4C:
        return bytes([length]) + payload
    if length <= 0xFF:
        return b"\x4c" + bytes([length]) + payload
    raise ValidationError("_push_minimal_int: value too large")


# ---------------------------------------------------------------------------
# Number encoding
# ---------------------------------------------------------------------------

#: Values that exercise every branch: zero, the OP_N band, both sides of the
#: sign-bit padding boundary (0x7f/0x80), multi-byte carries, and negatives.
_NUMS = [
    0, 1, 2, 15, 16, 17, 126, 127, 128, 129, 255, 256, 32767, 32768, 65535, 65536,
    8388607, 8388608, 2147483647, 2147483648, 1 << 40,
    -1, -2, -15, -16, -17, -127, -128, -129, -255, -256, -32768, -65536, -(1 << 40),
]  # fmt: skip


class TestCScriptNumBody:
    @pytest.mark.parametrize("n", _NUMS)
    def test_shared_encoder_matches_the_htlc_covenant_original(self, n):
        assert encode_script_num(n) == _reference_scriptnum(n)

    @given(st.integers(min_value=-(2**63), max_value=2**63))
    def test_shared_encoder_matches_the_original_over_the_whole_range(self, n):
        assert encode_script_num(n) == _reference_scriptnum(n)

    @pytest.mark.parametrize("n", _NUMS)
    def test_the_htlc_covenant_helper_still_returns_the_same_bytes(self, n):
        """The production symbol, not just the shared one — this is the covenant
        parameter encoder, and F-001 was a non-minimal push bricking a covenant."""
        assert _scriptnum(n) == _reference_scriptnum(n)

    @pytest.mark.parametrize("n", _NUMS)
    def test_round_trip(self, n):
        assert decode_script_num(encode_script_num(n)) == n

    @given(st.integers(min_value=-(2**63), max_value=2**63))
    def test_round_trip_over_the_whole_range(self, n):
        assert decode_script_num(encode_script_num(n)) == n

    @pytest.mark.parametrize("n", _NUMS)
    def test_shared_decoder_matches_the_swap_order_original(self, n):
        body = _reference_scriptnum(n)
        assert decode_script_num(body) == _reference_decode_scriptnum(body)

    def test_zero_is_the_empty_element(self):
        """Radiant's ``CScriptNum::serialize`` returns nothing for zero, which is
        why ``encode_int(0)`` comes out as ``OP_0`` and not ``01 00``."""
        assert encode_script_num(0) == b""
        assert decode_script_num(b"") == 0


class TestMinimalIntPush:
    @pytest.mark.parametrize("n", _NUMS)
    def test_encode_int_is_unchanged(self, n):
        assert encode_int(n) == _reference_encode_int(n)

    @given(st.integers(min_value=-(2**48), max_value=2**48))
    def test_encode_int_is_unchanged_over_a_wide_range(self, n):
        assert encode_int(n) == _reference_encode_int(n)

    @pytest.mark.parametrize("n", [n for n in _NUMS if n >= 0])
    def test_the_covenant_minimal_push_is_unchanged(self, n):
        assert _minimal_num_push(n) == _reference_push_minimal(n)

    @pytest.mark.parametrize("n", _NUMS)
    def test_the_dmint_minimal_push_is_unchanged(self, n):
        assert dmint_builders._push_minimal(n) == _reference_push_minimal(n)

    @pytest.mark.parametrize("n", [n for n in _NUMS if n >= 0])
    def test_the_glyph_payload_index_push_is_unchanged(self, n):
        assert glyph_payload._push_minimal_int(n) == _reference_push_minimal_int(n)

    @pytest.mark.parametrize("n", [-1, -2, -100])
    def test_the_covenant_minimal_push_still_refuses_negatives(self, n):
        """A guard that predates the consolidation and must survive it."""
        with pytest.raises(ValidationError):
            _minimal_num_push(n)

    @pytest.mark.parametrize("bad", [True, False, 1.5, "3", None])
    def test_the_covenant_minimal_push_still_refuses_non_ints(self, bad):
        with pytest.raises(ValidationError):
            _minimal_num_push(bad)


class TestRswpScriptNumPushKeepsItsOwnPolicy:
    """The RSWP wire format must NOT fold small values into ``OP_N``.

    It is the clearest example of why the number encoding and the push policy are
    separate functions: this call site shares the former and deliberately differs
    on the latter, matching Photonic's ``encodeScriptNum``.
    """

    @pytest.mark.parametrize("n", [n for n in _NUMS if n >= 0])
    def test_unchanged(self, n):
        assert rswp_wire._scriptnum_push(n) == _reference_scriptnum_push(n)

    @pytest.mark.parametrize("n", [1, 5, 16])
    def test_small_values_stay_direct_pushes_not_op_n(self, n):
        assert rswp_wire._scriptnum_push(n) == bytes([1, n])
        assert encode_int(n) != rswp_wire._scriptnum_push(n), "encode_int folds to OP_N; the wire format must not"


# ---------------------------------------------------------------------------
# Data pushes
# ---------------------------------------------------------------------------

_PAYLOAD_LENGTHS = [0, 1, 2, 16, 74, 75, 76, 77, 254, 255, 256, 257, 1000, 65534, 65535]


class TestDataPush:
    @pytest.mark.parametrize("n", _PAYLOAD_LENGTHS)
    def test_shared_encoder_matches_the_gravity_original(self, n):
        data = bytes(range(256)) * (n // 256) + bytes(range(n % 256))
        assert encode_data_push(data, max_len=0xFFFF) == _reference_push(data)

    @pytest.mark.parametrize("n", _PAYLOAD_LENGTHS)
    def test_shared_encoder_matches_the_transactions_original(self, n):
        data = b"\x5a" * n
        assert encode_data_push(data, max_len=0xFFFF) == _reference_push_data(data)

    @pytest.mark.parametrize("n", _PAYLOAD_LENGTHS)
    def test_the_htlc_covenant_helper_is_unchanged(self, n):
        data = b"\x5a" * n
        assert htlc_covenant._push(data) == _reference_push(data)

    @pytest.mark.parametrize("n", _PAYLOAD_LENGTHS)
    def test_the_htlc_spend_helper_is_unchanged(self, n):
        data = b"\x5a" * n
        assert htlc_spend._push(data) == _reference_push(data)

    @pytest.mark.parametrize("n", _PAYLOAD_LENGTHS)
    def test_the_gravity_transactions_helper_is_unchanged(self, n):
        data = b"\x5a" * n
        assert transactions._push_data(data) == _reference_push_data(data)

    def test_a_one_byte_value_in_the_op_n_band_is_not_folded(self):
        """The one semantic difference from ``encode_pushdata``, pinned.

        Folding here would change the byte layout of every covenant scriptSig
        whose fields are read positionally.
        """
        assert encode_data_push(b"\x05") == b"\x01\x05"
        assert encode_int(5) == b"\x55"  # OP_5 — the other policy

    def test_empty_data_is_op_0(self):
        assert encode_data_push(b"") == b"\x00"

    @pytest.mark.parametrize("helper", [htlc_covenant._push, htlc_spend._push, transactions._push_data])
    def test_the_64kb_ceiling_survives_the_consolidation(self, helper):
        """Each site kept its own cap. A shared encoder with one ceiling would
        have quietly raised this one."""
        with pytest.raises(ValidationError):
            helper(b"\x00" * 0x10000)

    def test_max_len_is_optional_and_unbounded_when_omitted(self):
        """``dmint/builders`` had no ceiling; omitting ``max_len`` preserves that.

        65,536 bytes is one past the ``OP_PUSHDATA2`` range, so the encoder
        promotes to ``OP_PUSHDATA4`` rather than raising — which is exactly what
        ``_encode_data_push`` did.
        """
        assert encode_data_push(b"\x00" * 0x10000)[:1] == b"\x4e"


class TestDecodeScriptNum:
    @pytest.mark.parametrize("n", _NUMS)
    def test_the_swap_order_helper_is_unchanged(self, n):
        body = _reference_scriptnum(n)
        assert swap_order._decode_scriptnum(body) == _reference_decode_scriptnum(body)
