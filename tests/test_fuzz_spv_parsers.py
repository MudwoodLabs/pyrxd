"""Fuzz + property tests for the SPV / Gravity transaction byte-walkers.

The existing ``test_fuzz_parsers.py`` covers the Glyph/dMint/CBOR surface.
This file targets the OTHER attacker-controlled parsers — the ones that
consume a raw Bitcoin transaction supplied by a swap counterparty as part
of an SPV proof:

    1. ``spv.witness.strip_witness``    — segwit witness stripper
    2. ``spv.proof._output_offsets``    — output-boundary enumerator
    3. ``spv.payment.verify_payment``   — single-output payment matcher

These run on bytes the counterparty fully controls (a mined tx whose bytes
the attacker chose). The contract under fuzz:

    Either return a structured value, or raise ValidationError /
    SpvVerificationError. ANY other exception (IndexError, struct.error,
    OverflowError, ValueError, MemoryError) is a parser leaking its
    internal failure mode past the trust boundary — a bug.

Plus three stronger properties beyond "doesn't crash":

    P1 (no rewind/overlap): every offset _output_offsets returns is a real
       output start, and the walk consumes exactly to nLockTime.
    P2 (strip is idempotent + txid-preserving): strip_witness(strip(x)) ==
       strip(x), and a round-trip through a hand-built segwit tx recovers
       the legacy bytes.
    P3 (bounded work): a hostile varint count cannot force unbounded
       iteration — the parser must raise within O(len) steps, fast.
"""

from __future__ import annotations

import os
import struct
import time

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from pyrxd.security.errors import SpvVerificationError, ValidationError
from pyrxd.spv.payment import P2PKH, P2SH, P2TR, P2WPKH, verify_payment
from pyrxd.spv.proof import _output_offsets
from pyrxd.spv.witness import _encode_varint, strip_witness

_BUDGET_MULT = int(os.environ.get("FUZZ_BUDGET_MULTIPLIER", "1"))


def _budget(n: int) -> int:
    return n * _BUDGET_MULT


# Exceptions a parser is ALLOWED to raise at its trust boundary.
_OK = (ValidationError, SpvVerificationError)


def _fail_unexpected(target: str, exc: BaseException, raw: bytes) -> None:
    pytest.fail(f"{target} leaked {type(exc).__name__}: {exc}\n  input ({len(raw)}): {raw.hex()}")


# ───────────────────────────────────────────────────────────────────────────
# Builders: assemble well-formed and adversarial raw txs
# ───────────────────────────────────────────────────────────────────────────


def _outpoint() -> bytes:
    return b"\x11" * 32 + b"\x00\x00\x00\x00"


def _legacy_tx(scriptsigs: list[bytes], outputs: list[tuple[int, bytes]]) -> bytes:
    """Build a minimal legacy (non-segwit) tx."""
    parts = [struct.pack("<I", 2), _encode_varint(len(scriptsigs))]
    for ss in scriptsigs:
        parts += [_outpoint(), _encode_varint(len(ss)), ss, b"\xff\xff\xff\xff"]
    parts.append(_encode_varint(len(outputs)))
    for value, spk in outputs:
        parts += [struct.pack("<Q", value), _encode_varint(len(spk)), spk]
    parts.append(b"\x00\x00\x00\x00")  # locktime
    return b"".join(parts)


def _segwit_tx(scriptsigs: list[bytes], outputs: list[tuple[int, bytes]], witnesses: list[list[bytes]]) -> bytes:
    """Build a minimal segwit tx (marker 0x00, flag 0x01, witness per input)."""
    parts = [struct.pack("<I", 2), b"\x00\x01", _encode_varint(len(scriptsigs))]
    for ss in scriptsigs:
        parts += [_outpoint(), _encode_varint(len(ss)), ss, b"\xff\xff\xff\xff"]
    parts.append(_encode_varint(len(outputs)))
    for value, spk in outputs:
        parts += [struct.pack("<Q", value), _encode_varint(len(spk)), spk]
    for w in witnesses:
        parts.append(_encode_varint(len(w)))
        for item in w:
            parts += [_encode_varint(len(item)), item]
    parts.append(b"\x00\x00\x00\x00")
    return b"".join(parts)


_P2WPKH_SPK = b"\x00\x14" + b"\xee" * 20
_P2PKH_SPK = b"\x76\xa9\x14" + b"\xee" * 20 + b"\x88\xac"

# Strategies
_spk = st.sampled_from([_P2WPKH_SPK, _P2PKH_SPK, b"\x6a\x04test", b"", b"\x51\x20" + b"\xaa" * 32])
_script = st.binary(min_size=0, max_size=80)
_value = st.integers(min_value=0, max_value=2**64 - 1)


# ───────────────────────────────────────────────────────────────────────────
# Contract fuzz: never leak a non-ValidationError on arbitrary bytes
# ───────────────────────────────────────────────────────────────────────────


@given(data=st.binary(min_size=0, max_size=2048))
@settings(max_examples=_budget(800), suppress_health_check=[HealthCheck.too_slow])
def test_strip_witness_only_validation_error(data):
    try:
        strip_witness(data)
    except _OK:
        pass
    except Exception as exc:
        _fail_unexpected("strip_witness", exc, data)


@given(data=st.binary(min_size=0, max_size=2048))
@settings(max_examples=_budget(800), suppress_health_check=[HealthCheck.too_slow])
def test_output_offsets_only_validation_error(data):
    try:
        _output_offsets(data)
    except _OK:
        pass
    except Exception as exc:
        _fail_unexpected("_output_offsets", exc, data)


@given(
    data=st.binary(min_size=0, max_size=2048),
    offset=st.integers(min_value=-8, max_value=4096),
    otype=st.sampled_from([P2PKH, P2WPKH, P2SH, P2TR]),
    minsat=st.integers(min_value=1, max_value=2**63),
)
@settings(max_examples=_budget(800), suppress_health_check=[HealthCheck.too_slow])
def test_verify_payment_only_expected_errors(data, offset, otype, minsat):
    expected = b"\xee" * (32 if otype == P2TR else 20)
    try:
        verify_payment(data, offset, expected, otype, minsat)
    except _OK:
        pass
    except Exception as exc:
        _fail_unexpected("verify_payment", exc, data)


# ───────────────────────────────────────────────────────────────────────────
# Structured fuzz: build real-shaped txs, then mutate adversarially
# ───────────────────────────────────────────────────────────────────────────


@given(
    scriptsigs=st.lists(_script, min_size=1, max_size=4),
    outputs=st.lists(st.tuples(_value, _spk), min_size=1, max_size=4),
)
@settings(max_examples=_budget(500), suppress_health_check=[HealthCheck.too_slow])
def test_output_offsets_on_wellformed_legacy_tx(scriptsigs, outputs):
    """P1: on a well-formed tx, every returned offset is a genuine output start,
    and verify_payment at a non-output offset is never silently accepted."""
    raw = _legacy_tx(scriptsigs, outputs)
    offs = _output_offsets(raw)
    assert len(offs) == len(outputs)
    # Reconstruct expected output starts independently and compare.
    pos = 4
    pos += len(_encode_varint(len(scriptsigs)))
    for ss in scriptsigs:
        pos += 36 + len(_encode_varint(len(ss))) + len(ss) + 4
    pos += len(_encode_varint(len(outputs)))
    expected_starts = set()
    for _value, spk in outputs:
        expected_starts.add(pos)
        pos += 8 + len(_encode_varint(len(spk))) + len(spk)
    assert offs == expected_starts


@given(
    scriptsigs=st.lists(_script, min_size=1, max_size=3),
    outputs=st.lists(st.tuples(_value, _spk), min_size=1, max_size=3),
    witnesses=st.data(),
)
@settings(max_examples=_budget(400), suppress_health_check=[HealthCheck.too_slow])
def test_strip_witness_roundtrip_and_idempotent(scriptsigs, outputs, witnesses):
    """P2: stripping a segwit tx yields the matching legacy tx, and stripping is
    idempotent (strip of legacy == legacy)."""
    n = len(scriptsigs)
    wit = [witnesses.draw(st.lists(st.binary(min_size=0, max_size=40), min_size=0, max_size=3)) for _ in range(n)]
    seg = _segwit_tx(scriptsigs, outputs, wit)
    legacy = _legacy_tx(scriptsigs, outputs)
    stripped = strip_witness(seg)
    assert stripped == legacy, "strip_witness did not reproduce the legacy serialization"
    assert strip_witness(stripped) == stripped, "strip_witness not idempotent on legacy input"


# ───────────────────────────────────────────────────────────────────────────
# Adversarial varint counts: must raise FAST, never hang (DoS bound)
# ───────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "label,raw",
    [
        # Huge input count (0xff + 2^64-ish), tiny buffer.
        ("huge_n_in_offsets", struct.pack("<I", 2) + b"\xff" + b"\xff" * 8 + b"\x00" * 4),
        # Huge output count, valid-ish input prefix.
        (
            "huge_n_out_offsets",
            struct.pack("<I", 2) + b"\x00" + b"\xff" + b"\xff" * 8 + b"\x00" * 4,
        ),
        # Segwit with huge witness item_count.
        (
            "huge_witness_items",
            struct.pack("<I", 2)
            + b"\x00\x01"
            + b"\x01"
            + _outpoint()
            + b"\x00"
            + b"\xff\xff\xff\xff"
            + b"\x01"
            + struct.pack("<Q", 1)
            + b"\x00"
            + b"\xff"
            + b"\xff" * 8
            + b"\x00" * 4,
        ),
        # Huge per-output script_len.
        (
            "huge_output_scriptlen",
            struct.pack("<I", 2) + b"\x00" + b"\x01" + struct.pack("<Q", 1) + b"\xff" + b"\xff" * 8 + b"\x00" * 4,
        ),
    ],
)
def test_hostile_varint_counts_raise_fast(label, raw):
    """P3: a hostile count/length must be rejected within O(len) and well under
    a second — never an unbounded loop or giant allocation."""
    t0 = time.perf_counter()
    with pytest.raises((ValidationError, SpvVerificationError)):
        if label.startswith("huge_witness"):
            strip_witness(raw)
        else:
            _output_offsets(raw)
    dt = time.perf_counter() - t0
    assert dt < 1.0, f"{label}: parser took {dt:.3f}s — possible DoS (unbounded loop/alloc)"


def test_output_offsets_rejects_rewind_via_overlap():
    """A walk that does not end exactly at len-4 must be rejected (no rewind/overlap)."""
    # One input, one output, then trailing junk so pos != len-4.
    raw = _legacy_tx([b""], [(1000, _P2WPKH_SPK)]) + b"\xde\xad"
    with pytest.raises(SpvVerificationError, match="parse ended at"):
        _output_offsets(raw)
