"""Tests for Glyph V2 additions: protocol IDs 8-10, mutable NFT script, mutable scriptSig."""
from __future__ import annotations

import pytest

from pyrxd.glyph.payload import build_mutable_scriptsig, encode_payload
from pyrxd.glyph.script import (
    MUTABLE_NFT_SCRIPT_SIZE,
    _MUTABLE_NFT_BODY,
    build_mutable_nft_script,
    parse_mutable_nft_script,
)
from pyrxd.glyph.types import GlyphMetadata, GlyphProtocol, GlyphRef
from pyrxd.security.errors import ValidationError

_REF_A = GlyphRef(txid='aa' * 32, vout=1)
_HASH32 = bytes(range(32))


# ---------------------------------------------------------------------------
# Protocol IDs 8 / 9 / 10
# ---------------------------------------------------------------------------

def test_protocol_enum_values():
    assert GlyphProtocol.ENCRYPTED == 8
    assert GlyphProtocol.TIMELOCK == 9
    assert GlyphProtocol.AUTHORITY == 10


def test_encrypted_nft_valid():
    meta = GlyphMetadata(protocol=[GlyphProtocol.NFT, GlyphProtocol.ENCRYPTED], name="Encrypted NFT")
    assert GlyphProtocol.ENCRYPTED in meta.protocol


def test_timelock_requires_encrypted():
    with pytest.raises(ValidationError, match="TIMELOCK.*requires.*ENCRYPTED"):
        GlyphMetadata(protocol=[GlyphProtocol.NFT, GlyphProtocol.TIMELOCK], name="Bad")


def test_timelock_with_encrypted_valid():
    meta = GlyphMetadata(
        protocol=[GlyphProtocol.NFT, GlyphProtocol.ENCRYPTED, GlyphProtocol.TIMELOCK],
        name="Timelocked",
    )
    assert GlyphProtocol.TIMELOCK in meta.protocol


def test_authority_nft_valid():
    meta = GlyphMetadata(protocol=[GlyphProtocol.NFT, GlyphProtocol.AUTHORITY], name="Authority")
    assert GlyphProtocol.AUTHORITY in meta.protocol


def test_authority_requires_nft():
    with pytest.raises(ValidationError, match="AUTHORITY.*requires.*NFT"):
        GlyphMetadata(protocol=[GlyphProtocol.FT, GlyphProtocol.AUTHORITY], name="Bad")


def test_encrypted_requires_nft():
    with pytest.raises(ValidationError, match="ENCRYPTED.*requires.*NFT"):
        GlyphMetadata(protocol=[GlyphProtocol.FT, GlyphProtocol.ENCRYPTED], name="Bad")


# ---------------------------------------------------------------------------
# Protocol combination rules
# ---------------------------------------------------------------------------

def test_ft_and_nft_mutually_exclusive():
    with pytest.raises(ValidationError, match="mutually exclusive"):
        GlyphMetadata(protocol=[GlyphProtocol.FT, GlyphProtocol.NFT], name="Bad")


def test_mut_requires_nft():
    with pytest.raises(ValidationError, match="MUT.*requires.*NFT"):
        GlyphMetadata(protocol=[GlyphProtocol.FT, GlyphProtocol.MUT], name="Bad")


def test_container_requires_nft():
    with pytest.raises(ValidationError, match="CONTAINER.*requires.*NFT"):
        GlyphMetadata(protocol=[GlyphProtocol.FT, GlyphProtocol.CONTAINER], name="Bad")


def test_wave_requires_nft_and_mut():
    # WAVE without MUT → fails because WAVE requires [NFT, MUT]
    with pytest.raises(ValidationError, match="WAVE.*requires"):
        GlyphMetadata(protocol=[GlyphProtocol.NFT, GlyphProtocol.WAVE], name="Bad")
    # WAVE without NFT → MUT requirement also fires (MUT requires NFT)
    with pytest.raises(ValidationError, match="requires"):
        GlyphMetadata(protocol=[GlyphProtocol.FT, GlyphProtocol.MUT, GlyphProtocol.WAVE], name="Bad2")


def test_wave_valid():
    meta = GlyphMetadata(
        protocol=[GlyphProtocol.NFT, GlyphProtocol.MUT, GlyphProtocol.WAVE],
        name="wave.rxd",
    )
    assert GlyphProtocol.WAVE in meta.protocol


def test_dmint_requires_ft():
    with pytest.raises(ValidationError, match="DMINT.*requires.*FT"):
        GlyphMetadata(protocol=[GlyphProtocol.NFT, GlyphProtocol.DMINT], name="Bad")


# ---------------------------------------------------------------------------
# Mutable NFT output script
# ---------------------------------------------------------------------------

def test_mutable_nft_body_matches_photonic_reference():
    # Body hex derived from parseMutableScript regex in Photonic Wallet script.ts
    # with glyph magic bytes '676c79' substituted.
    REFERENCE = (
        '7601207f818c54807e5279e2547a0124957f7701247f75887cec7b7f7701457f75'
        '7801207ec0caa87e885279036d6f64876378eac0e98878ec01205579aa7e01757e'
        '8867527902736c8878cd01d852797e016a7e8778da009c9b6968547a03676c79886d6d51'
    )
    assert _MUTABLE_NFT_BODY.hex() == REFERENCE
    assert len(_MUTABLE_NFT_BODY) == 102


def test_mutable_nft_script_length():
    script = build_mutable_nft_script(_REF_A, _HASH32)
    assert len(script) == MUTABLE_NFT_SCRIPT_SIZE == 174


def test_mutable_nft_script_structure():
    script = build_mutable_nft_script(_REF_A, _HASH32)
    # Byte 0: PUSH 32
    assert script[0] == 0x20
    # Bytes 1..32: payload hash
    assert script[1:33] == _HASH32
    # Byte 33: OP_DROP
    assert script[33] == 0x75
    # Byte 34: OP_STATESEPARATOR
    assert script[34] == 0xbd
    # Byte 35: OP_PUSHINPUTREFSINGLETON
    assert script[35] == 0xd8
    # Bytes 36..71: mutable ref (36 bytes)
    assert script[36:72] == _REF_A.to_bytes()
    # Bytes 72..173: fixed body
    assert script[72:] == _MUTABLE_NFT_BODY


def test_mutable_nft_script_parse_round_trip():
    script = build_mutable_nft_script(_REF_A, _HASH32)
    result = parse_mutable_nft_script(script)
    assert result is not None
    ref, h = result
    assert ref == _REF_A
    assert h == _HASH32


def test_mutable_nft_script_parse_returns_none_for_garbage():
    assert parse_mutable_nft_script(b'\x00' * 175) is None
    assert parse_mutable_nft_script(b'\x00' * 63) is None
    assert parse_mutable_nft_script(b'') is None


def test_mutable_nft_script_wrong_hash_raises():
    with pytest.raises(ValidationError, match="32 bytes"):
        build_mutable_nft_script(_REF_A, b'\x00' * 31)


# ---------------------------------------------------------------------------
# Mutable scriptSig (mod / sl)
# ---------------------------------------------------------------------------

def _make_cbor() -> bytes:
    meta = GlyphMetadata(protocol=[GlyphProtocol.NFT, GlyphProtocol.MUT], name="Test")
    cbor_bytes, _ = encode_payload(meta)
    return cbor_bytes


def test_mutable_scriptsig_mod_structure():
    cbor = _make_cbor()
    sig = build_mutable_scriptsig("mod", cbor, 0, 1, 0, 1)
    # First 4 bytes: \x03 + b'gly'
    assert sig[:4] == b'\x03gly'
    # "mod" appears somewhere after cbor push
    assert b'mod' in sig


def test_mutable_scriptsig_sl_structure():
    cbor = _make_cbor()
    sig = build_mutable_scriptsig("sl", cbor, 0, 0, 0, 0)
    assert sig[:4] == b'\x03gly'
    assert b'sl' in sig


def test_mutable_scriptsig_invalid_operation():
    cbor = _make_cbor()
    with pytest.raises(ValidationError, match="'mod' or 'sl'"):
        build_mutable_scriptsig("burn", cbor, 0, 0, 0, 0)  # type: ignore[arg-type]


def test_mutable_scriptsig_indices_encoded():
    cbor = _make_cbor()
    # contract_output_index=5 → OP_5 = 0x55
    sig = build_mutable_scriptsig("mod", cbor, 5, 0, 0, 0)
    assert b'\x55' in sig  # OP_5


def test_mutable_scriptsig_cbor_pushed_correctly():
    cbor = _make_cbor()
    sig = build_mutable_scriptsig("mod", cbor, 0, 0, 0, 0)
    # CBOR length prefix must appear in scriptSig (small payload ≤ 75 → 1-byte length)
    cbor_len = len(cbor)
    assert cbor_len <= 75
    idx = sig.index(b'\x03gly') + 4
    assert sig[idx] == cbor_len
    assert sig[idx + 1: idx + 1 + cbor_len] == cbor
