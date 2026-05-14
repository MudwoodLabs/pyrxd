"""Fuzz tests for attacker-controlled parsers.

Complements ``test_property_based.py`` by targeting the inspect-tool
surface — the parsers that consume *fully attacker-supplied* input
arriving from a block explorer paste, an ElectrumX response, or a
hostile reveal scriptSig. Each test asserts the same contract:

    Either return a structured value, or raise ``ValidationError``.
    Any other exception type (``IndexError``, ``struct.error``,
    ``cbor2.CBORDecodeError``, ``ValueError``, ``TypeError``) is a
    bug — that is the parser leaking its internal failure mode past
    its trust boundary.

Hypothesis searches the input space; when it finds a counterexample
the test prints the offending bytes/hex so the fix is reproducible.

Targets:

    1. ``decode_payload(arbitrary bytes)``
       — CBOR decode boundary
    2. ``DmintState.from_script(arbitrary bytes)``
       — variable-length opcode walker
    3. ``GlyphInspector.extract_reveal_metadata(arbitrary bytes)``
       — push-data walker; documented contract is "never raises"
    4. ``GlyphInspector.find_glyphs(arbitrary scripts)``
       — script classifier dispatch
    5. ``_inspect_script(arbitrary hex)``
       — CLI/browser inspect dispatch
    6. ``_classify_input(arbitrary string)``
       — top-level inspect classifier
    7. ``GlyphRef.from_bytes`` / ``from_contract_hex``
       — fixed-shape ref decoders
    8. round-trip: ``build_mutable_scriptsig`` →
       ``_parse_reveal_scriptsig`` recovers the embedded CBOR
"""

from __future__ import annotations

import os

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from pyrxd.glyph._inspect_core import _classify_input, _inspect_script
from pyrxd.glyph.dmint import DmintState
from pyrxd.glyph.inspector import GlyphInspector
from pyrxd.glyph.payload import build_mutable_scriptsig, decode_payload
from pyrxd.glyph.types import GlyphRef
from pyrxd.security.errors import ValidationError

# Fuzz budget multiplier. CI default is 1; scripts/fuzz_deep.sh sets
# HYPOTHESIS_PROFILE=deep which (combined with FUZZ_BUDGET_MULTIPLIER) scales
# every per-test max_examples — Hypothesis's decorator @settings overrides
# the profile's max_examples, so we multiply the decorator value directly.
_BUDGET_MULT = int(os.environ.get("FUZZ_BUDGET_MULTIPLIER", "1"))


def _budget(n: int) -> int:
    return n * _BUDGET_MULT


def _fail_unexpected(target: str, exc: BaseException, raw: bytes | str) -> None:
    """Produce a test failure with enough context to reproduce the crash."""
    payload = raw.hex() if isinstance(raw, (bytes, bytearray)) else repr(raw)
    pytest.fail(f"{target} raised unexpected {type(exc).__name__}: {exc}\n  input ({len(raw)}): {payload}")


# ═══════════════════════════════════════════════════════════════════════════════
# 1. decode_payload — CBOR boundary
# ═══════════════════════════════════════════════════════════════════════════════


@given(data=st.binary(min_size=0, max_size=1024))
@settings(max_examples=_budget(400), suppress_health_check=[HealthCheck.too_slow])
def test_decode_payload_only_validation_error(data):
    """``decode_payload`` must convert every cbor2 / structural failure to
    ``ValidationError``. A bare ``cbor2.CBORDecodeError`` or ``TypeError``
    leaking out means a caller's ``except ValidationError`` will miss it,
    which is exactly the bug class that broke the inspect tool's browser
    flow before the boundary was hardened.
    """
    try:
        decode_payload(data)
    except ValidationError:
        pass
    except Exception as exc:
        _fail_unexpected("decode_payload", exc, data)


# Targeted: oversize payloads must be rejected with ValidationError before
# any cbor2 work — the size guard is the cheap-and-correct front line.
# Plain parametrize rather than @given because Hypothesis treats 64KB+ as
# unreasonably large to shrink.
@pytest.mark.parametrize("size", [65_537, 100_000, 1_000_000])
def test_decode_payload_oversize_rejected(size):
    with pytest.raises(ValidationError):
        decode_payload(b"\x00" * size)


# ═══════════════════════════════════════════════════════════════════════════════
# 2. DmintState.from_script — opcode walker
# ═══════════════════════════════════════════════════════════════════════════════


@given(data=st.binary(min_size=0, max_size=2_048))
@settings(max_examples=_budget(400), suppress_health_check=[HealthCheck.too_slow])
def test_dmint_from_script_only_validation_error(data):
    """``DmintState.from_script`` walks a variable-length opcode stream.
    Every truncation, opcode mismatch, and ref-decode failure must surface
    as ``ValidationError`` — never an ``IndexError``, ``struct.error``,
    or ``ValueError`` from the underlying byte slicing / int decoding.
    """
    try:
        DmintState.from_script(data)
    except ValidationError:
        pass
    except Exception as exc:
        _fail_unexpected("DmintState.from_script", exc, data)


# Bias toward the V2 prefix (``0x04 <4 bytes>``) so the fuzzer spends some
# of its budget inside the parser's deeper branches rather than bailing
# immediately on the first byte. Without this, most random inputs short-
# circuit at byte 0 and the deeper opcode walker stays uncovered.
@given(
    height_push=st.binary(min_size=4, max_size=4),
    tail=st.binary(min_size=0, max_size=512),
)
@settings(max_examples=_budget(200), suppress_health_check=[HealthCheck.too_slow])
def test_dmint_from_script_v2_prefix_only_validation_error(height_push, tail):
    data = b"\x04" + height_push + tail
    try:
        DmintState.from_script(data)
    except ValidationError:
        pass
    except Exception as exc:
        _fail_unexpected("DmintState.from_script (v2-prefix)", exc, data)


# ═══════════════════════════════════════════════════════════════════════════════
# 3. GlyphInspector.extract_reveal_metadata — push-data walker
# ═══════════════════════════════════════════════════════════════════════════════


@given(data=st.binary(min_size=0, max_size=1024))
@settings(max_examples=_budget(400), suppress_health_check=[HealthCheck.too_slow])
def test_extract_reveal_metadata_never_raises(data):
    """The wrapper documents "never raises" — it catches ``Exception``
    broadly because the inner push-data walker is unguarded against
    truncated OP_PUSHDATA1/2 length bytes. Verify the contract holds for
    every byte string."""
    inspector = GlyphInspector()
    try:
        result = inspector.extract_reveal_metadata(data)
    except Exception as exc:
        _fail_unexpected("extract_reveal_metadata", exc, data)
        return
    # When None, no recognisable gly-marker; otherwise a GlyphMetadata.
    assert result is None or hasattr(result, "protocol")


@given(scriptsigs=st.lists(st.binary(min_size=0, max_size=256), min_size=0, max_size=8))
@settings(max_examples=_budget(200), suppress_health_check=[HealthCheck.too_slow])
def test_find_reveal_metadata_never_raises(scriptsigs):
    """``find_reveal_metadata`` walks a list of scriptSigs; same contract."""
    inspector = GlyphInspector()
    try:
        result = inspector.find_reveal_metadata(scriptsigs)
    except Exception as exc:
        _fail_unexpected("find_reveal_metadata", exc, b"".join(scriptsigs))
        return
    assert result is None or (isinstance(result, tuple) and len(result) == 2 and isinstance(result[0], int))


# ═══════════════════════════════════════════════════════════════════════════════
# 4. GlyphInspector.find_glyphs — script classifier dispatch
# ═══════════════════════════════════════════════════════════════════════════════


@given(
    outputs=st.lists(
        st.tuples(
            st.integers(min_value=0, max_value=2_100_000_000_000_000),
            st.binary(min_size=0, max_size=512),
        ),
        min_size=0,
        max_size=8,
    )
)
@settings(max_examples=_budget(200), suppress_health_check=[HealthCheck.too_slow])
def test_find_glyphs_never_raises_on_arbitrary_scripts(outputs):
    """``find_glyphs`` must silently skip unrecognised scripts. A crash
    here would mean a single malformed output in an attacker-supplied tx
    aborts inspection of the whole transaction."""
    inspector = GlyphInspector()
    try:
        result = inspector.find_glyphs(outputs)
    except ValidationError:
        # find_glyphs is documented to *not* raise ValidationError — it
        # swallows them per-output. If one escapes, treat as failure too.
        joined = b"".join(s for _, s in outputs)
        pytest.fail(
            f"find_glyphs raised ValidationError (should be silently skipped) "
            f"on inputs {[(s, b.hex()) for s, b in outputs]}\n  joined={joined.hex()}"
        )
    except Exception as exc:
        joined = b"".join(s for _, s in outputs)
        _fail_unexpected("find_glyphs", exc, joined)
        return
    assert isinstance(result, list)


# ═══════════════════════════════════════════════════════════════════════════════
# 5. _inspect_script — top-level CLI/browser script dispatch
# ═══════════════════════════════════════════════════════════════════════════════


@given(
    script_hex=st.text(
        alphabet="0123456789abcdef",
        min_size=50,
        max_size=2_048,
    ).filter(lambda s: len(s) % 2 == 0)
)
@settings(max_examples=_budget(300), suppress_health_check=[HealthCheck.too_slow])
def test_inspect_script_only_validation_error(script_hex):
    """``_inspect_script`` runs the whole P2PKH / OP_RETURN / NFT / FT /
    mutable / commit-NFT / commit-FT / dMint dispatch. Every classifier
    must either claim the bytes or the function returns ``unknown`` —
    the only allowed exception is ``ValidationError`` (raised when the
    hex itself is malformed, which we exclude by construction here, but
    keep the assertion to document the contract)."""
    try:
        result = _inspect_script(script_hex)
    except ValidationError:
        return
    except Exception as exc:
        _fail_unexpected("_inspect_script", exc, script_hex)
        return
    assert isinstance(result, dict)
    assert "type" in result
    assert "length" in result


@given(
    # Use uppercase / mixed / odd-length / non-hex to exercise the front
    # door's hex validation branch.
    bad_hex=st.one_of(
        st.text(alphabet="0123456789ABCDEFXG", min_size=50, max_size=200),
        st.text(min_size=50, max_size=100),  # arbitrary unicode
    )
)
@settings(max_examples=_budget(200), suppress_health_check=[HealthCheck.too_slow])
def test_inspect_script_rejects_bad_hex_with_validation_error(bad_hex):
    """Anything that isn't valid lowercase hex must surface as
    ``ValidationError``, not a ``ValueError`` from ``bytes.fromhex``."""
    try:
        _inspect_script(bad_hex)
    except ValidationError:
        pass
    except Exception as exc:
        # Allow successful classification if Hypothesis happens to produce
        # all-lowercase even-length hex — only a non-ValidationError
        # exception is a bug.
        _fail_unexpected("_inspect_script (bad hex)", exc, bad_hex)


# ═══════════════════════════════════════════════════════════════════════════════
# 6. _classify_input — top-level inspect classifier
# ═══════════════════════════════════════════════════════════════════════════════


@given(s=st.text(min_size=0, max_size=400))
@settings(max_examples=_budget(400), suppress_health_check=[HealthCheck.too_slow])
def test_classify_input_only_validation_error(s):
    """``_classify_input`` is the entry point users hit when they paste
    *anything* into ``pyrxd glyph inspect``. It must classify or refuse
    cleanly — never raise a non-``ValidationError`` exception that would
    surface as an opaque traceback."""
    try:
        result = _classify_input(s)
    except ValidationError:
        return
    except Exception as exc:
        _fail_unexpected("_classify_input", exc, s)
        return
    assert isinstance(result, tuple) and len(result) == 2
    form, normalised = result
    assert form in {"txid", "contract", "outpoint", "script"}
    assert isinstance(normalised, str)


# ═══════════════════════════════════════════════════════════════════════════════
# 7. GlyphRef.from_bytes / from_contract_hex
# ═══════════════════════════════════════════════════════════════════════════════


@given(data=st.binary(min_size=0, max_size=128))
@settings(max_examples=_budget(200), suppress_health_check=[HealthCheck.too_slow])
def test_glyphref_from_bytes_only_validation_error(data):
    """``GlyphRef.from_bytes`` requires exactly 36 bytes. Anything else
    must raise ``ValidationError`` (the txid embedded inside is decoded
    via ``Txid()`` which itself raises ``ValidationError``)."""
    try:
        GlyphRef.from_bytes(data)
    except ValidationError:
        pass
    except Exception as exc:
        _fail_unexpected("GlyphRef.from_bytes", exc, data)


@given(s=st.text(min_size=0, max_size=200))
@settings(max_examples=_budget(300), suppress_health_check=[HealthCheck.too_slow])
def test_glyphref_from_contract_hex_only_validation_error(s):
    """``GlyphRef.from_contract_hex`` validates length and hex shape.
    Any non-72-char or non-hex input must raise ``ValidationError``,
    never ``ValueError`` from a deeper ``bytes.fromhex``."""
    try:
        GlyphRef.from_contract_hex(s)
    except ValidationError:
        pass
    except Exception as exc:
        _fail_unexpected("GlyphRef.from_contract_hex", exc, s)


# ═══════════════════════════════════════════════════════════════════════════════
# 8. Round-trip: build_mutable_scriptsig → push-data walker recovers CBOR
# ═══════════════════════════════════════════════════════════════════════════════


@given(
    cbor_bytes=st.binary(min_size=1, max_size=200),
    operation=st.sampled_from(["mod", "sl"]),
    contract_output_index=st.integers(min_value=0, max_value=1024),
    ref_hash_index=st.integers(min_value=0, max_value=1024),
    ref_index=st.integers(min_value=0, max_value=1024),
    token_output_index=st.integers(min_value=0, max_value=1024),
)
@settings(max_examples=_budget(200), suppress_health_check=[HealthCheck.too_slow])
def test_build_mutable_scriptsig_roundtrip_extracts_cbor(
    cbor_bytes,
    operation,
    contract_output_index,
    ref_hash_index,
    ref_index,
    token_output_index,
):
    """A mutable-NFT scriptSig built by ``build_mutable_scriptsig`` must
    feed back through the inspector's push-data walker and yield items
    whose 2nd entry is the original CBOR. The walker rejects malformed
    CBOR via ``decode_payload`` (returning ``None``); we don't require
    successful CBOR decode here — we require the walker to find the
    ``gly`` marker and try to decode the payload that follows. That tests
    the structural contract between builder and parser."""
    scriptsig = build_mutable_scriptsig(
        operation=operation,
        cbor_bytes=cbor_bytes,
        contract_output_index=contract_output_index,
        ref_hash_index=ref_hash_index,
        ref_index=ref_index,
        token_output_index=token_output_index,
    )

    inspector = GlyphInspector()
    # Walk the push-data manually so we can assert structural recovery
    # *without* requiring the random CBOR bytes to decode to a valid
    # GlyphMetadata. Mirrors the inspector's own walker.
    pos = 0
    items: list[bytes] = []
    while pos < len(scriptsig):
        op = scriptsig[pos]
        pos += 1
        if 1 <= op <= 75:
            items.append(scriptsig[pos : pos + op])
            pos += op
        elif op == 0x4C:
            n = scriptsig[pos]
            pos += 1
            items.append(scriptsig[pos : pos + n])
            pos += n
        elif op == 0x4D:
            n = int.from_bytes(scriptsig[pos : pos + 2], "little")
            pos += 2
            items.append(scriptsig[pos : pos + n])
            pos += n
        else:
            break

    assert b"gly" in items, "gly marker not found in built scriptsig"
    gly_idx = items.index(b"gly")
    assert gly_idx + 1 < len(items), "no item after gly marker"
    assert items[gly_idx + 1] == cbor_bytes, "cbor bytes not recovered"

    # And the public API contract: never raises.
    try:
        inspector.extract_reveal_metadata(scriptsig)
    except Exception as exc:
        _fail_unexpected("extract_reveal_metadata (round-trip)", exc, scriptsig)
