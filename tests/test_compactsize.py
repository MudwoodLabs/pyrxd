"""The CompactSize codec, and proof that every reader in the tree shares it.

The interesting tests here are not the codec's own round-trips — they are
:class:`TestEveryReaderAgrees`, which feeds the SAME hostile bytes to every
CompactSize reader in the SDK and requires them to reach the same verdict.
Four independent readers existed before this module; three rejected
non-minimal encodings and ``btc_wallet/taproot.py`` accepted them, and nothing
in the suite could notice.
"""

from __future__ import annotations

import pytest

from pyrxd.btc_wallet.taproot import _iter_witness_stack
from pyrxd.compactsize import COMPACT_SIZE_MAX, encode_compact_size, read_compact_size
from pyrxd.security.errors import SpvVerificationError, ValidationError
from pyrxd.spv.proof import _read_varint as _proof_varint
from pyrxd.spv.witness import _read_varint as _witness_varint
from pyrxd.utils import Reader

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# The codec itself
# ---------------------------------------------------------------------------


class TestCanonicalRoundTrip:
    @pytest.mark.parametrize(
        ("value", "encoded"),
        [
            (0, "00"),
            (1, "01"),
            (0xFC, "fc"),  # last single-byte value
            (0xFD, "fdfd00"),  # first 3-byte value
            (0xFFFF, "fdffff"),  # last 3-byte value
            (0x10000, "fe00000100"),  # first 5-byte value
            (0xFFFFFFFF, "feffffffff"),  # last 5-byte value
            (0x100000000, "ff0000000001000000"),  # first 9-byte value
            (COMPACT_SIZE_MAX, "ffffffffffffffffff"),
        ],
    )
    def test_boundary_values_encode_and_decode(self, value, encoded):
        """Every width boundary, in both directions.

        The boundaries are where a non-minimal encoder goes wrong, so they are
        pinned by hand rather than only property-tested.
        """
        assert encode_compact_size(value).hex() == encoded
        assert read_compact_size(bytes.fromhex(encoded)) == (value, len(encoded) // 2)

    @pytest.mark.parametrize("value", [0, 1, 0xFC, 0xFD, 0xFFFF, 0x10000, 0xFFFFFFFF, 0x100000000])
    def test_encoder_output_is_what_the_reader_calls_canonical(self, value):
        """The encoder can only emit encodings the reader accepts.

        If these two ever disagree the SDK would emit transactions it would
        itself refuse to parse.
        """
        assert read_compact_size(encode_compact_size(value)) == (value, len(encode_compact_size(value)))

    def test_read_returns_the_offset_after_the_field(self):
        buf = encode_compact_size(0xFFFF) + b"TRAILING"
        value, pos = read_compact_size(buf)
        assert value == 0xFFFF
        assert buf[pos:] == b"TRAILING"

    def test_read_honours_a_non_zero_start_offset(self):
        buf = b"\xde\xad" + encode_compact_size(300)
        assert read_compact_size(buf, 2) == (300, 5)


class TestRejections:
    @pytest.mark.parametrize(
        ("label", "raw"),
        [
            ("0xFD form holding a 1-byte value", "fd0100"),
            ("0xFD form holding its own floor", "fdfc00"),
            ("0xFE form holding a 2-byte value", "feffff0000"),
            ("0xFF form holding a 4-byte value", "ffffffffff00000000"),
        ],
    )
    def test_non_minimal_encodings_are_refused(self, label, raw):
        with pytest.raises(ValidationError, match="non-canonical"):
            read_compact_size(bytes.fromhex(raw))

    @pytest.mark.parametrize("raw", ["fd", "fd01", "fe010203", "ff01020304050607"])
    def test_truncated_operands_are_refused(self, raw):
        """``int.from_bytes`` zero-extends a short read; refusing is the only
        way ``fd 01`` does not silently decode as 1."""
        with pytest.raises(ValidationError, match="truncated"):
            read_compact_size(bytes.fromhex(raw))

    def test_read_past_end_is_refused(self):
        with pytest.raises(ValidationError, match="past end"):
            read_compact_size(b"", 0)

    def test_negative_offset_is_refused(self):
        with pytest.raises(ValidationError, match="negative"):
            read_compact_size(b"\x01", -1)

    @pytest.mark.parametrize("bad", [-1, COMPACT_SIZE_MAX + 1])
    def test_encoder_refuses_out_of_range(self, bad):
        with pytest.raises(ValidationError):
            encode_compact_size(bad)

    @pytest.mark.parametrize("bad", [True, 1.0, "1", None])
    def test_encoder_refuses_non_ints(self, bad):
        """``bool`` is an ``int`` subclass — ``encode_compact_size(True)``
        returning ``b"\\x01"`` would let a flag be serialised as a length."""
        with pytest.raises(ValidationError):
            encode_compact_size(bad)


# ---------------------------------------------------------------------------
# The point of the module: one answer, everywhere
# ---------------------------------------------------------------------------

#: ``fd 01 00`` — the value 1 written in the 3-byte form. Consensus rejects it at
#: deserialization, so no transaction containing it can exist on chain.
NON_MINIMAL_ONE = bytes.fromhex("fd0100")

_WITNESS_ITEM = bytes(range(32))


def _segwit_tx(input_count_field: bytes) -> bytes:
    """A one-in/one-out segwit tx whose INPUT COUNT uses ``input_count_field``.

    Everything else is canonical, so the only thing separating the minimal and
    non-minimal fixtures is the encoding under test.
    """
    return (
        bytes.fromhex("02000000")  # version
        + b"\x00\x01"  # segwit marker + flag
        + input_count_field  # <- the field under test
        + b"\x11" * 32
        + b"\x00\x00\x00\x00"  # prevout
        + b"\x00"  # empty scriptSig
        + b"\xff\xff\xff\xff"  # sequence
        + b"\x01"  # one output
        + (1000).to_bytes(8, "little")
        + b"\x00"  # value, empty scriptPubKey
        + b"\x01"  # witness: one stack item
        + bytes([len(_WITNESS_ITEM)])
        + _WITNESS_ITEM
        + b"\x00\x00\x00\x00"  # locktime
    )


class TestEveryReaderAgrees:
    """Feed one hostile encoding to every reader and require one verdict.

    Parameterised over readers rather than written out per reader, so a fifth
    reader is added to this list (and held to the rule) in one line.
    """

    def test_the_shared_reader_rejects_it(self):
        with pytest.raises(ValidationError):
            read_compact_size(NON_MINIMAL_ONE)

    def test_spv_proof_rejects_it(self):
        with pytest.raises(SpvVerificationError):
            _proof_varint(NON_MINIMAL_ONE, 0)

    def test_spv_witness_rejects_it(self):
        with pytest.raises(ValidationError):
            _witness_varint(NON_MINIMAL_ONE, 0)

    def test_transaction_reader_rejects_it(self):
        with pytest.raises(ValidationError):
            Reader(NON_MINIMAL_ONE).read_var_int_num()

    def test_the_taproot_witness_walker_rejects_it(self):
        """The fourth copy — it accepted non-minimal CompactSize until this module.

        ``_iter_witness_stack`` is deliberately non-raising (``scrape_secret``
        must never index-error on an adversarial witness), so its way of
        rejecting is to yield no stack at all. That is the correct outcome: a
        transaction with a non-minimal length prefix cannot be a real claim
        transaction, because no node would have relayed it.
        """
        assert _iter_witness_stack(_segwit_tx(b"\x01")) == [[_WITNESS_ITEM]], (
            "control: the canonical spelling of the same transaction must still parse"
        )
        assert _iter_witness_stack(_segwit_tx(NON_MINIMAL_ONE)) == []

    def test_every_reader_still_accepts_the_canonical_spelling(self):
        """The other half — a rule nobody can satisfy is not a rule."""
        canonical = encode_compact_size(1)
        assert read_compact_size(canonical) == (1, 1)
        assert _proof_varint(canonical, 0) == (1, 1)
        assert _witness_varint(canonical, 0) == (1, 1)
        assert Reader(canonical).read_var_int_num() == 1
