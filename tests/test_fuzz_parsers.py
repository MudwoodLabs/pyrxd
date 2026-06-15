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
    9. ``glyph.script`` classifiers + extractors
       — ``is_{nft,ft,commit,commit_nft,commit_ft}_script`` (hex),
       ``is_dmint_contract_script`` (bytes),
       ``extract_ref_from_{nft,ft}_script``,
       ``extract_owner_pkh_from_{nft,ft,commit}_script``,
       ``extract_payload_hash_from_commit_script``,
       ``parse_mutable_nft_script``
   10. ``glyph.script`` opcode-ref walkers
       — ``iter_input_refs`` / ``count_input_refs`` (raise only
       ``TruncatedScriptError``, a ``ValidationError`` subclass) and
       ``is_token_bearing_script`` (never raises; returns ``bool``)
   11. ``Transaction.from_hex`` — the ElectrumX/explorer tx decoder;
       suppresses all internal failures, so the contract is "returns
       ``None`` or a ``Transaction`` whose ``.serialize()`` round-trips,
       never raises".
"""

from __future__ import annotations

import os

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from pyrxd.glyph._inspect_core import _classify_input, _inspect_script
from pyrxd.glyph.dmint import DmintState
from pyrxd.glyph.dmint.chain import is_token_bearing_script
from pyrxd.glyph.inspector import GlyphInspector
from pyrxd.glyph.payload import build_mutable_scriptsig, decode_payload
from pyrxd.glyph.script import (
    count_input_refs,
    extract_owner_pkh_from_commit_script,
    extract_owner_pkh_from_ft_script,
    extract_owner_pkh_from_nft_script,
    extract_payload_hash_from_commit_script,
    extract_ref_from_ft_script,
    extract_ref_from_nft_script,
    is_commit_ft_script,
    is_commit_nft_script,
    is_commit_script,
    is_dmint_contract_script,
    is_ft_script,
    is_nft_script,
    iter_input_refs,
    parse_mutable_nft_script,
)
from pyrxd.glyph.types import GlyphRef
from pyrxd.security.errors import ValidationError
from pyrxd.transaction.transaction import Transaction

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
        # expected: parser converted a malformed input cleanly
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
        # expected: parser converted a malformed input cleanly
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
        # expected: parser converted a malformed input cleanly
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
        return  # unreachable (pytest.fail raises) — proves `result` is bound below
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
        # expected: parser rejected malformed hex at the boundary
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
        # expected: parser rejected malformed ref bytes at the boundary
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
        # expected: parser rejected malformed contract hex at the boundary
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


# ═══════════════════════════════════════════════════════════════════════════════
# 9. glyph.script classifiers + extractors
# ═══════════════════════════════════════════════════════════════════════════════
#
# These consume a locking script straight off a block explorer / ElectrumX
# response. The hex classifiers (``is_*_script``) take an attacker-supplied
# *string* and must answer ``bool`` without ever raising. The extractors take
# raw *bytes* and must either return the structured field or raise
# ``ValidationError`` — a leaked ``IndexError`` from a fixed-offset slice or a
# ``ValueError`` from ``bytes.fromhex`` would be the parser leaking its internal
# failure past the trust boundary.

# Hex-string classifiers: random hex (well-formed and not) plus the all-byte
# space via ``.hex()`` so the fuzzer reaches both the regex fast-path and the
# ``.lower()`` normaliser.
_HEX_CLASSIFIERS = [is_nft_script, is_ft_script, is_commit_script, is_commit_nft_script, is_commit_ft_script]


@given(
    s=st.one_of(
        st.text(alphabet="0123456789abcdefABCDEF", min_size=0, max_size=200),
        st.text(min_size=0, max_size=120),  # arbitrary unicode, incl. non-hex
        st.binary(min_size=0, max_size=100).map(lambda b: b.hex()),
    )
)
@settings(max_examples=_budget(400), suppress_health_check=[HealthCheck.too_slow])
def test_hex_script_classifiers_only_return_bool(s):
    """Every ``is_*_script`` hex classifier must answer ``bool`` for any
    string — well-formed hex, mixed case, unicode, or empty — and never
    raise. They are pure ``re.fullmatch`` predicates; a raised exception
    would mean a malformed paste aborts inspection instead of being
    classified ``unknown``."""
    for fn in _HEX_CLASSIFIERS:
        try:
            result = fn(s)
        except Exception as exc:
            _fail_unexpected(f"{fn.__name__}", exc, s)
            return
        assert isinstance(result, bool)


@given(data=st.binary(min_size=0, max_size=256))
@settings(max_examples=_budget(300), suppress_health_check=[HealthCheck.too_slow])
def test_is_dmint_contract_script_only_returns_bool(data):
    """``is_dmint_contract_script`` wraps ``DmintState.from_script`` and is
    documented to catch ``(ValidationError, struct.error, IndexError)`` and
    answer ``bool``. Any *other* exception leaking is a real bug — that's the
    defense-in-depth contract this fuzz pins down."""
    try:
        result = is_dmint_contract_script(data)
    except Exception as exc:
        _fail_unexpected("is_dmint_contract_script", exc, data)
        return
    assert isinstance(result, bool)


# Byte extractors. Bias the strategy so some inputs land on the exact lengths
# (63 for NFT, 75 for FT/commit) the parsers care about — otherwise nearly
# every random input bails on the length check and the fixed-offset slicing /
# ``Hex20`` / ``GlyphRef.from_bytes`` paths stay uncovered.
_extractor_bytes = st.one_of(
    st.binary(min_size=0, max_size=128),
    st.binary(min_size=63, max_size=63),
    st.binary(min_size=75, max_size=75),
    # Valid-prefix NFT (0xd8) / FT (…bdd0…) leads so deeper slices run.
    st.builds(lambda tail: b"\xd8" + tail, st.binary(min_size=62, max_size=62)),
    st.builds(
        lambda a, b: a + b"\xbd\xd0" + b,
        st.binary(min_size=25, max_size=25),
        st.binary(min_size=48, max_size=48),
    ),
)


@given(data=_extractor_bytes)
@settings(max_examples=_budget(400), suppress_health_check=[HealthCheck.too_slow])
def test_script_byte_extractors_only_validation_error(data):
    """Every fixed-offset extractor must return its field or raise
    ``ValidationError`` — never an ``IndexError`` from a slice past the end,
    a ``struct.error`` from a downstream decode, or a ``ValueError`` from
    ``Hex20`` / ``GlyphRef`` on adversarial bytes."""
    extractors = (
        extract_ref_from_nft_script,
        extract_ref_from_ft_script,
        extract_owner_pkh_from_nft_script,
        extract_owner_pkh_from_ft_script,
        extract_payload_hash_from_commit_script,
        extract_owner_pkh_from_commit_script,
    )
    for fn in extractors:
        try:
            fn(data)
        except ValidationError:
            # expected: parser rejected a non-matching script at the boundary
            pass
        except Exception as exc:
            _fail_unexpected(f"{fn.__name__}", exc, data)
            return


@given(data=st.binary(min_size=0, max_size=300))
@settings(max_examples=_budget(300), suppress_health_check=[HealthCheck.too_slow])
def test_parse_mutable_nft_script_never_raises(data):
    """``parse_mutable_nft_script`` is documented to return ``(ref, hash)`` or
    ``None``. It guards on the fixed script size before the only inner decode
    (``GlyphRef.from_bytes`` on an exactly-36-byte slice), so it must never
    raise on arbitrary bytes."""
    try:
        result = parse_mutable_nft_script(data)
    except Exception as exc:
        _fail_unexpected("parse_mutable_nft_script", exc, data)
        return
    assert result is None or (isinstance(result, tuple) and len(result) == 2 and isinstance(result[0], GlyphRef))


# ═══════════════════════════════════════════════════════════════════════════════
# 10. glyph.script opcode-ref walkers
# ═══════════════════════════════════════════════════════════════════════════════
#
# ``iter_input_refs`` / ``count_input_refs`` walk an opcode stream looking for
# the OP_PUSHINPUTREF family (0xd0..0xd8), each followed by a 36-byte operand.
# A truncated push must surface as ``TruncatedScriptError`` (a ``ValidationError``
# subclass) — never a bare ``IndexError`` from slicing past the end.
# ``is_token_bearing_script`` swallows that internally and answers ``bool``.

# Bias toward inputs that actually contain ref opcodes / push prefixes so the
# walker's deeper truncation branches get exercised, not just the bail-on-byte-0
# path. ``0x4c/0x4d/0x4e`` are PUSHDATA1/2/4 length prefixes.
_refish_byte = st.sampled_from([0xD0, 0xD4, 0xD8, 0x4C, 0x4D, 0x4E, 0x14, 0x00, 0xFF])


@given(
    data=st.one_of(
        st.binary(min_size=0, max_size=300),
        st.lists(_refish_byte, min_size=0, max_size=80).map(bytes),
    )
)
@settings(max_examples=_budget(500), suppress_health_check=[HealthCheck.too_slow])
def test_iter_input_refs_only_validation_error(data):
    """Walking arbitrary bytes must yield ``(opcode, 36-byte operand)`` tuples
    or raise ``TruncatedScriptError``/``ValidationError`` — never an
    ``IndexError`` / ``struct.error`` from an unguarded slice."""
    try:
        for op, operand in iter_input_refs(data):
            assert isinstance(op, int)
            assert isinstance(operand, (bytes, bytearray)) and len(operand) == 36
    except ValidationError:
        # TruncatedScriptError is a ValidationError subclass — expected.
        pass
    except Exception as exc:
        _fail_unexpected("iter_input_refs", exc, data)


@given(
    data=st.one_of(
        st.binary(min_size=0, max_size=300),
        st.lists(_refish_byte, min_size=0, max_size=80).map(bytes),
    )
)
@settings(max_examples=_budget(300), suppress_health_check=[HealthCheck.too_slow])
def test_count_input_refs_only_validation_error(data):
    """``count_input_refs`` aggregates the walker; same contract — a clean
    ``dict`` of ref→count or a ``ValidationError``, nothing else."""
    try:
        result = count_input_refs(data)
    except ValidationError:
        pass
    except Exception as exc:
        _fail_unexpected("count_input_refs", exc, data)
        return
    else:
        assert isinstance(result, dict)


@given(
    data=st.one_of(
        st.binary(min_size=0, max_size=300),
        st.lists(_refish_byte, min_size=0, max_size=80).map(bytes),
    )
)
@settings(max_examples=_budget(300), suppress_health_check=[HealthCheck.too_slow])
def test_is_token_bearing_script_never_raises(data):
    """``is_token_bearing_script`` must answer ``bool`` for any bytes — it
    catches ``TruncatedScriptError`` internally and treats a malformed script
    as token-bearing (fail-closed). A leaked exception is a bug."""
    try:
        result = is_token_bearing_script(data)
    except Exception as exc:
        _fail_unexpected("is_token_bearing_script", exc, data)
        return
    assert isinstance(result, bool)


# ═══════════════════════════════════════════════════════════════════════════════
# 11. Transaction.from_hex — ElectrumX / explorer raw-tx decoder
# ═══════════════════════════════════════════════════════════════════════════════
#
# This is the parser that consumes a raw transaction supplied by an ElectrumX
# server or pasted from a block explorer. It suppresses every internal failure
# (``contextlib.suppress(Exception)``), so its boundary contract is: return
# ``None`` or a ``Transaction`` — and if a ``Transaction``, ``.serialize()``
# must not crash. ``test_property_based.py`` round-trips *valid* txs through it;
# this fills the gap for *adversarial* bytes/hex it has never seen.


@given(
    stream=st.one_of(
        st.binary(min_size=0, max_size=1024),
        st.text(alphabet="0123456789abcdef", min_size=0, max_size=512).filter(lambda s: len(s) % 2 == 0),
        st.text(min_size=0, max_size=200),  # arbitrary unicode / non-hex
    )
)
@settings(max_examples=_budget(500), suppress_health_check=[HealthCheck.too_slow])
def test_transaction_from_hex_never_raises(stream):
    """``Transaction.from_hex`` must absorb every malformed input and return
    ``None`` rather than leak an exception, and any ``Transaction`` it does
    return must re-serialize without crashing."""
    try:
        tx = Transaction.from_hex(stream)
    except Exception as exc:
        _fail_unexpected("Transaction.from_hex", exc, stream)
        return
    if tx is not None:
        try:
            tx.serialize()
        except Exception as exc:
            _fail_unexpected("Transaction.from_hex(...).serialize()", exc, stream)
