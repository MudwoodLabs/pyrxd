"""Tests for the rarer-Glyph-protocol classification surfaced by the
pure inspect core (``pyrxd.glyph._inspect_core``).

Two layers:

1. Unit tests of ``_classify_metadata_protocol`` directly — the fast,
   high-value path. Covers every rarer protocol type from issue #135
   (DAT, CONTAINER, ENCRYPTED, TIMELOCK, AUTHORITY, WAVE) plus the
   highest-specificity ordering rules (TIMELOCK out-ranks ENCRYPTED;
   AUTHORITY/CONTAINER out-rank MUT; legacy WAVE without ``attrs.name``
   degrades to the underlying label).

2. One end-to-end test that builds a real reveal transaction and asserts
   ``_classify_raw_tx`` surfaces the ``classification`` key in its
   ``metadata`` payload — proving the wiring, not just the helper.

``_inspect_core`` must stay import-pure (no coincurve/websockets/aiohttp)
so its classifier is a self-contained mirror of
``pyrxd.glyph.wave.classify_glyph_metadata`` rather than an import of it;
``tests/test_glyph_wave.py`` exercises the wave-side twin against the same
rules so the two stay in sync.
"""

from __future__ import annotations

import pytest

from pyrxd.glyph._inspect_core import _classify_metadata_protocol, _classify_raw_tx
from pyrxd.glyph.payload import build_reveal_scriptsig_suffix, encode_payload
from pyrxd.glyph.types import GlyphMetadata, GlyphProtocol
from pyrxd.glyph.wave import build_wave_metadata
from pyrxd.hash import hash256
from pyrxd.script.script import Script
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput

ADDR = "1JsKDV4xV8FXZjLDLcLvLY1aWCKBKt8XnQ"


# ─────────────────────────────────── _classify_metadata_protocol (unit) ──


class TestClassifyMetadataProtocol:
    """Each rarer protocol type maps to its highest-specificity label.

    Construction respects the protocol-combination rules in ``types.py``
    (TIMELOCK requires ENCRYPTED; CONTAINER/ENCRYPTED/AUTHORITY require
    NFT; WAVE requires NFT+MUT) so the GlyphMetadata validator accepts the
    fixtures.
    """

    def test_dat(self):
        md = GlyphMetadata(protocol=[GlyphProtocol.DAT], name="d")
        assert _classify_metadata_protocol(md) == "dat"

    def test_container(self):
        md = GlyphMetadata(protocol=[GlyphProtocol.NFT, GlyphProtocol.CONTAINER], name="c")
        assert _classify_metadata_protocol(md) == "container"

    def test_encrypted(self):
        md = GlyphMetadata(protocol=[GlyphProtocol.NFT, GlyphProtocol.ENCRYPTED], name="e")
        assert _classify_metadata_protocol(md) == "encrypted"

    def test_timelock(self):
        md = GlyphMetadata(
            protocol=[GlyphProtocol.NFT, GlyphProtocol.ENCRYPTED, GlyphProtocol.TIMELOCK],
            name="t",
        )
        assert _classify_metadata_protocol(md) == "timelock"

    def test_timelock_outranks_encrypted(self):
        """TIMELOCK always carries ENCRYPTED — the more specific label wins."""
        md = GlyphMetadata(
            protocol=[GlyphProtocol.NFT, GlyphProtocol.ENCRYPTED, GlyphProtocol.TIMELOCK],
            name="t",
        )
        assert _classify_metadata_protocol(md) != "encrypted"

    def test_authority(self):
        md = GlyphMetadata(protocol=[GlyphProtocol.NFT, GlyphProtocol.AUTHORITY], name="a")
        assert _classify_metadata_protocol(md) == "authority"

    def test_authority_outranks_mut(self):
        md = GlyphMetadata(
            protocol=[GlyphProtocol.NFT, GlyphProtocol.MUT, GlyphProtocol.AUTHORITY],
            name="a",
        )
        assert _classify_metadata_protocol(md) == "authority"

    def test_wave(self):
        md = build_wave_metadata(qualified_name="alice.rxd", target=ADDR)
        assert _classify_metadata_protocol(md) == "wave"

    def test_legacy_wave_without_attrs_name_degrades_to_mut(self):
        """WAVE lacking a resolvable attrs.name is a plain mutable NFT to
        indexers — must not claim the 'wave' label."""
        md = GlyphMetadata(
            protocol=[GlyphProtocol.NFT, GlyphProtocol.MUT, GlyphProtocol.WAVE],
            name="legacy.rxd",
        )
        assert _classify_metadata_protocol(md) == "mut"

    # The common base types still classify correctly (regression guard for
    # the ordering edits).
    @pytest.mark.parametrize(
        ("protocol", "expected"),
        [
            ([GlyphProtocol.NFT], "nft"),
            ([GlyphProtocol.FT], "ft"),
            ([GlyphProtocol.NFT, GlyphProtocol.MUT], "mut"),
            ([GlyphProtocol.FT, GlyphProtocol.DMINT], "dmint"),
        ],
    )
    def test_base_types_unchanged(self, protocol, expected):
        md = GlyphMetadata(protocol=protocol, name="x", ticker="X")
        assert _classify_metadata_protocol(md) == expected


# ───────────────────────────── _classify_raw_tx classification wiring ──


def _build_reveal_tx(metadata: GlyphMetadata) -> tuple[bytes, str]:
    """Build a serialized tx whose vin[0] scriptSig embeds the reveal CBOR.

    Returns (raw_bytes, real_txid). The scriptSig is just the ``gly`` + CBOR
    suffix (sig/pubkey pushes are optional for the inspector's gly-marker
    walker, which scans for the marker anywhere in the pushes).
    """
    cbor_bytes, _ = encode_payload(metadata)
    scriptsig = build_reveal_scriptsig_suffix(cbor_bytes)
    tx = Transaction(
        tx_inputs=[
            TransactionInput(
                source_txid="a" * 64,
                source_output_index=0,
                unlocking_script=Script(scriptsig),
            )
        ],
        tx_outputs=[TransactionOutput(Script(b"\x6a"), 0)],  # bare OP_RETURN
    )
    raw = bytes(tx.serialize())
    real_txid = hash256(raw)[::-1].hex()
    return raw, real_txid


class TestClassifyRawTxSurfacesClassification:
    def test_classification_key_present_for_container(self):
        md = GlyphMetadata(protocol=[GlyphProtocol.NFT, GlyphProtocol.CONTAINER], name="c")
        raw, txid = _build_reveal_tx(md)
        result = _classify_raw_tx(txid, raw)
        assert result["metadata"] is not None
        assert result["metadata"]["classification"] == "container"

    def test_classification_key_for_timelock(self):
        md = GlyphMetadata(
            protocol=[GlyphProtocol.NFT, GlyphProtocol.ENCRYPTED, GlyphProtocol.TIMELOCK],
            name="t",
        )
        raw, txid = _build_reveal_tx(md)
        result = _classify_raw_tx(txid, raw)
        assert result["metadata"]["classification"] == "timelock"

    def test_classification_key_for_wave(self):
        md = build_wave_metadata(qualified_name="alice.rxd", target=ADDR)
        raw, txid = _build_reveal_tx(md)
        result = _classify_raw_tx(txid, raw)
        assert result["metadata"]["classification"] == "wave"

    @pytest.mark.parametrize(
        ("metadata", "expected"),
        [
            (GlyphMetadata(protocol=[GlyphProtocol.DAT], name="d"), "dat"),
            (GlyphMetadata(protocol=[GlyphProtocol.NFT, GlyphProtocol.ENCRYPTED], name="e"), "encrypted"),
            (GlyphMetadata(protocol=[GlyphProtocol.NFT, GlyphProtocol.AUTHORITY], name="a"), "authority"),
        ],
    )
    def test_classification_key_for_each_rarer_type(self, metadata, expected):
        raw, txid = _build_reveal_tx(metadata)
        result = _classify_raw_tx(txid, raw)
        assert result["metadata"]["classification"] == expected
