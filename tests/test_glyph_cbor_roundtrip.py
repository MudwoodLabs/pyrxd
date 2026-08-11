"""Property corpus for the Glyph CBOR envelope: encode/decode round-trip,
canonical-form stability, and reveal-scriptSig push framing.

Three independent nets over ``pyrxd.glyph.payload``:

1. **Round-trip** — ``decode_payload(encode_payload(m)) == m`` for
   Hypothesis-generated ``GlyphMetadata`` across valid protocol combos,
   nested media, attrs, and dMint params. A field silently dropped or
   coerced on either side breaks equality.
2. **Canonical stability** — ``encode_payload`` promises RFC 8949
   canonical/deterministic form (module docstring): an indexer must be able
   to re-encode decoded metadata and reproduce the on-chain commit hash.
   Asserted with cbor2 directly (``loads`` → ``dumps(canonical=True)`` is
   byte-identical), never via pyrxd's own decoder.
3. **Envelope framing** — ``build_reveal_scriptsig_suffix`` must pick the
   push opcode by payload length (direct ≤75, PUSHDATA1 ≤255, PUSHDATA2
   ≤65535, PUSHDATA4 ≤256 KiB — the mainnet GLYPH reveal b965b32d…9dd6
   needed PUSHDATA4). Parsed back with a test-local script-chunk reader
   (same shape as the RXinDexer port in tests/test_cbor_cross_decoder.py),
   not with pyrxd's Script class.
"""

from __future__ import annotations

import os

import cbor2
import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from pyrxd.glyph.dmint.types import DaaMode, DmintAlgo, DmintCborPayload
from pyrxd.glyph.payload import (
    _MAX_CBOR_PAYLOAD_BYTES,
    build_reveal_scriptsig_suffix,
    decode_payload,
    encode_payload,
)
from pyrxd.glyph.types import GlyphMedia, GlyphMetadata, GlyphRef
from pyrxd.security.errors import ValidationError
from pyrxd.security.types import Txid

_BUDGET_MULT = int(os.environ.get("FUZZ_BUDGET_MULTIPLIER", "1"))


def _budget(n: int) -> int:
    return n * _BUDGET_MULT


# ═══════════════════════════════════════════════════════════════════════════════
# Strategies
# ═══════════════════════════════════════════════════════════════════════════════

# Valid protocol combinations per the Photonic protocols.ts §3.5 rules
# enforced in GlyphMetadata.__post_init__ (FT/NFT exclusive; extensions
# require their base co-protocols).
_PROTOCOL_COMBOS = [
    (1,),  # FT
    (2,),  # NFT
    (3,),  # DAT
    (1, 4),  # FT + DMINT
    (2, 5),  # NFT + MUT
    (2, 7),  # NFT + CONTAINER
    (2, 8),  # NFT + ENCRYPTED
    (2, 8, 9),  # NFT + ENCRYPTED + TIMELOCK
    (2, 10),  # NFT + AUTHORITY
    (2, 5, 11),  # NFT + MUT + WAVE
]

_text = st.text(max_size=32)
_hex64 = st.text(alphabet="0123456789abcdef", min_size=64, max_size=64)

_media = st.builds(
    GlyphMedia,
    mime_type=st.sampled_from(["image/webp", "image/png", "text/plain", "application/octet-stream"]),
    data=st.binary(min_size=0, max_size=64),
)


@st.composite
def _dmint_payload(draw) -> DmintCborPayload:
    daa_mode = draw(st.sampled_from(list(DaaMode)))
    # Fields that from_cbor_dict resets to defaults when absent must be
    # generated in their encoded-when-set shape, or equality is vacuous:
    # FIXED omits the whole daa object, so its dependents stay at defaults.
    if daa_mode == DaaMode.FIXED:
        target_block_time, half_life, window_size = 60, 0, 0
    else:
        target_block_time = draw(st.integers(min_value=1, max_value=86_400))
        half_life = draw(st.integers(min_value=1, max_value=10**6)) if daa_mode == DaaMode.ASERT else 0
        window_size = draw(st.integers(min_value=1, max_value=1000)) if daa_mode == DaaMode.LWMA else 0
    return DmintCborPayload(
        algo=draw(st.sampled_from(list(DmintAlgo))),
        num_contracts=draw(st.integers(min_value=1, max_value=64)),
        max_height=draw(st.integers(min_value=1, max_value=10**9)),
        reward=draw(st.integers(min_value=0, max_value=10**12)),
        premine=draw(st.integers(min_value=0, max_value=10**12)),
        diff=draw(st.integers(min_value=1, max_value=2**32)),
        daa_mode=daa_mode,
        target_block_time=target_block_time,
        half_life=half_life,
        window_size=window_size,
    )


_ref = st.builds(
    GlyphRef,
    txid=st.binary(min_size=32, max_size=32).map(lambda b: Txid(b.hex())),
    vout=st.integers(min_value=0, max_value=0xFFFFFFFF),
)
# ``in`` / ``by`` are lists of 36-byte wire refs. Kept short: the property under
# test is that each entry survives encode→decode intact, not that long lists do
# something different.
_rel_refs = st.lists(_ref, max_size=3).map(tuple)


@st.composite
def _metadata(draw) -> GlyphMetadata:
    protocol = draw(st.sampled_from(_PROTOCOL_COMBOS))
    dmint = draw(_dmint_payload()) if 4 in protocol else None
    return GlyphMetadata(
        container_refs=draw(_rel_refs),
        author_refs=draw(_rel_refs),
        protocol=list(protocol),
        name=draw(_text),
        ticker=draw(st.text(max_size=16)),
        description=draw(_text),
        token_type=draw(_text),
        main=draw(st.none() | _media),
        attrs=draw(st.dictionaries(st.text(min_size=1, max_size=16), st.text(max_size=16), max_size=8)),
        loc=draw(_text),
        loc_hash=draw(_text),
        decimals=draw(st.integers(min_value=0, max_value=18)),
        image_url=draw(_text),
        image_ipfs=draw(_text),
        image_sha256=draw(st.just("") | _hex64),
        v=draw(st.none() | st.just(2)),
        dmint_params=dmint,
        created=draw(_text),
        commit_outpoint=draw(_text),
    )


# ═══════════════════════════════════════════════════════════════════════════════
# 1. Round-trip
# ═══════════════════════════════════════════════════════════════════════════════


@given(m=_metadata())
@settings(max_examples=_budget(300), deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_encode_decode_roundtrip(m):
    cbor_bytes, payload_hash = encode_payload(m)
    assert len(payload_hash) == 32
    decoded = decode_payload(cbor_bytes)
    assert decoded == m, "decode(encode(m)) must reproduce every field of m"


# ═══════════════════════════════════════════════════════════════════════════════
# 2. Canonical form, checked against cbor2 directly
# ═══════════════════════════════════════════════════════════════════════════════


@given(m=_metadata())
@settings(max_examples=_budget(200), deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_encoding_is_canonical_fixed_point(m):
    """An independent decode→canonical-re-encode must be byte-identical:
    the property an indexer needs to verify a payload against its on-chain
    commit hash. Uses cbor2 alone — pyrxd's decoder is not in the loop."""
    cbor_bytes, _ = encode_payload(m)
    re_encoded = cbor2.dumps(cbor2.loads(cbor_bytes), canonical=True)
    assert re_encoded == cbor_bytes


@given(m=_metadata())
@settings(max_examples=_budget(100), deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_protocol_field_survives_as_int_list(m):
    """'p' must decode (via cbor2 alone) to the exact int list — indexers
    dispatch on it before any pyrxd code runs."""
    cbor_bytes, _ = encode_payload(m)
    raw = cbor2.loads(cbor_bytes)
    assert raw["p"] == list(m.protocol)
    assert all(type(p) is int for p in raw["p"])


# ═══════════════════════════════════════════════════════════════════════════════
# 3. Reveal scriptSig envelope framing
# ═══════════════════════════════════════════════════════════════════════════════


def _read_pushes(script: bytes) -> list[bytes]:
    """Test-local script-chunk reader (mirrors the RXinDexer port in
    tests/test_cbor_cross_decoder.py). Returns push payloads in order."""
    pushes = []
    i = 0
    while i < len(script):
        op = script[i]
        i += 1
        if 1 <= op <= 0x4B:
            pushes.append(script[i : i + op])
            i += op
        elif op == 0x4C:
            n = script[i]
            i += 1
            pushes.append(script[i : i + n])
            i += n
        elif op == 0x4D:
            n = int.from_bytes(script[i : i + 2], "little")
            i += 2
            pushes.append(script[i : i + n])
            i += n
        elif op == 0x4E:
            n = int.from_bytes(script[i : i + 4], "little")
            i += 4
            pushes.append(script[i : i + n])
            i += n
        else:
            raise AssertionError(f"unexpected opcode {op:#x} in reveal suffix")
    assert i == len(script), "suffix must parse exactly, no trailing bytes"
    return pushes


# Push-boundary lengths (the off-by-one cliffs) plus random interior sizes.
_boundary_lengths = st.sampled_from([1, 74, 75, 76, 255, 256, 65_535, 65_536, _MAX_CBOR_PAYLOAD_BYTES])
_interior_lengths = st.integers(min_value=1, max_value=4096)


@given(n=_boundary_lengths | _interior_lengths)
@settings(max_examples=_budget(150), deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_reveal_suffix_framing(n):
    payload = b"\xab" * n
    suffix = build_reveal_scriptsig_suffix(payload)
    pushes = _read_pushes(suffix)
    assert pushes == [b"gly", payload]
    # Opcode selection per spec: direct/PUSHDATA1/2/4 by length.
    op = suffix[4]  # byte after the 4-byte "\x03gly" marker push
    if n <= 75:
        assert op == n
    elif n <= 255:
        assert op == 0x4C
    elif n <= 65_535:
        assert op == 0x4D
    else:
        assert op == 0x4E


def test_reveal_suffix_rejects_oversize():
    with pytest.raises(ValidationError):
        build_reveal_scriptsig_suffix(b"\x00" * (_MAX_CBOR_PAYLOAD_BYTES + 1))
