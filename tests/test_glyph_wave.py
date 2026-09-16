"""Tests for the WAVE name protocol helpers (Photonic-compatible shape)."""

from __future__ import annotations

import cbor2
import pytest

from pyrxd.glyph.payload import encode_payload
from pyrxd.glyph.types import GlyphMetadata, GlyphProtocol
from pyrxd.glyph.wave import (
    SCHEME_ADDRESS,
    WaveAttrs,
    build_wave_metadata,
    classify_glyph_metadata,
    extract_wave_attrs,
    split_qualified_name,
    wave_attrs_from_metadata,
)
from pyrxd.security.errors import ValidationError

# A REAL mainnet address (a WAVE target from the mainnet fixture), because `reverse_lookup` now
# decodes it to a scripthash. The previous value here had an INVALID base58 checksum and nothing
# noticed for as long as the address was forwarded verbatim — the old code never looked at it.
ADDR = "14XmXG3dSBWZUukGT3xzS9zxpiZ53vgx1i"


# ─────────────────────────────────────────────── split_qualified_name ──


class TestSplitQualifiedName:
    def test_simple_split(self):
        assert split_qualified_name("alice.rxd") == ("alice", "rxd")

    def test_no_dot_defaults_to_rxd(self):
        assert split_qualified_name("alice") == ("alice", "rxd")

    def test_multi_dot_uses_last(self):
        assert split_qualified_name("foo.bar.rxd") == ("foo.bar", "rxd")

    def test_empty_label_rejected(self):
        with pytest.raises(ValidationError, match="empty label"):
            split_qualified_name(".rxd")

    def test_empty_domain_rejected(self):
        with pytest.raises(ValidationError, match="empty label"):
            split_qualified_name("alice.")


# ─────────────────────────────────────────────── WaveAttrs ──


class TestWaveAttrs:
    def test_round_trip(self):
        a = WaveAttrs(name="alice.rxd", domain="rxd", target=ADDR)
        d = a.to_dict()
        assert d == {
            "name": "alice.rxd",
            "domain": "rxd",
            "target": ADDR,
            "target_type": SCHEME_ADDRESS,
        }
        assert WaveAttrs.from_dict(d) == a

    def test_default_target_type(self):
        a = WaveAttrs(name="x.rxd", domain="rxd", target=ADDR)
        assert a.target_type == "address"

    def test_from_dict_rejects_missing_name(self):
        with pytest.raises(ValidationError, match="missing required"):
            WaveAttrs.from_dict({"domain": "rxd", "target": ADDR})

    def test_from_dict_accepts_missing_target_type(self):
        a = WaveAttrs.from_dict({"name": "x", "domain": "rxd", "target": ADDR})
        assert a.target_type == "address"


# ─────────────────────────────────────────────── build_wave_metadata ──


class TestBuildWaveMetadata:
    def test_returns_metadata_with_correct_protocol(self):
        md = build_wave_metadata(qualified_name="alice.rxd", target=ADDR)
        assert GlyphProtocol.NFT in md.protocol
        assert GlyphProtocol.MUT in md.protocol
        assert GlyphProtocol.WAVE in md.protocol

    def test_attrs_match_photonic_shape(self):
        md = build_wave_metadata(qualified_name="alice.rxd", target=ADDR)
        assert md.attrs == {
            "name": "alice.rxd",
            "domain": "rxd",
            "target": ADDR,
            "target_type": "address",
        }

    def test_top_level_name_is_empty(self):
        """The canonical shape puts name in attrs.name, NOT top-level."""
        md = build_wave_metadata(qualified_name="alice.rxd", target=ADDR)
        assert md.name == ""

    def test_description_at_top_level(self):
        """Description is a regular Glyph field, NOT in attrs."""
        md = build_wave_metadata(
            qualified_name="alice.rxd",
            target=ADDR,
            description="my friend's address",
        )
        assert md.description == "my friend's address"
        assert "description" not in md.attrs
        assert "desc" not in md.attrs

    def test_round_trip_through_cbor(self):
        """Encode metadata to CBOR, decode, recover the WaveAttrs."""
        md = build_wave_metadata(qualified_name="alice.rxd", target=ADDR)
        cbor_bytes, _ = encode_payload(md)
        decoded = cbor2.loads(cbor_bytes)
        attrs = extract_wave_attrs(decoded)
        assert attrs is not None
        assert attrs.name == "alice.rxd"
        assert attrs.target == ADDR

    def test_no_domain_in_name_defaults_to_rxd(self):
        md = build_wave_metadata(qualified_name="alice", target=ADDR)
        assert md.attrs["domain"] == "rxd"
        assert md.attrs["name"] == "alice"

    def test_empty_target_rejected(self):
        with pytest.raises(ValidationError, match="target must not be empty"):
            build_wave_metadata(qualified_name="alice.rxd", target="")


# ─────────────────────────────────────────────── extract_wave_attrs ──


class TestExtractWaveAttrs:
    def test_extracts_canonical_shape(self):
        md = build_wave_metadata(qualified_name="alice.rxd", target=ADDR)
        cbor_bytes, _ = encode_payload(md)
        attrs = extract_wave_attrs(cbor2.loads(cbor_bytes))
        assert attrs is not None
        assert attrs.name == "alice.rxd"

    def test_returns_none_for_non_wave(self):
        md = GlyphMetadata(protocol=[GlyphProtocol.NFT], name="just-an-nft")
        cbor_bytes, _ = encode_payload(md)
        assert extract_wave_attrs(cbor2.loads(cbor_bytes)) is None

    def test_returns_none_for_legacy_wave_without_attrs(self):
        """Legacy pyrxd WAVE with only top-level name → not indexable."""
        md = GlyphMetadata(
            protocol=[GlyphProtocol.NFT, GlyphProtocol.MUT, GlyphProtocol.WAVE],
            name="legacy.rxd",
        )
        cbor_bytes, _ = encode_payload(md)
        assert extract_wave_attrs(cbor2.loads(cbor_bytes)) is None


# ─────────────────────────────────────────────── wave_attrs_from_metadata ──


class TestWaveAttrsFromMetadata:
    def test_extracts_from_built_metadata(self):
        md = build_wave_metadata(qualified_name="alice.rxd", target=ADDR)
        attrs = wave_attrs_from_metadata(md)
        assert attrs is not None
        assert attrs.name == "alice.rxd"

    def test_returns_none_for_plain_nft(self):
        md = GlyphMetadata(protocol=[GlyphProtocol.NFT], name="just-an-nft")
        assert wave_attrs_from_metadata(md) is None

    def test_returns_none_for_legacy_wave(self):
        md = GlyphMetadata(
            protocol=[GlyphProtocol.NFT, GlyphProtocol.MUT, GlyphProtocol.WAVE],
            name="legacy.rxd",
        )
        assert wave_attrs_from_metadata(md) is None


# ─────────────────────────────────────────────── classify_glyph_metadata ──


class TestClassifyGlyphMetadata:
    def test_wave(self):
        md = build_wave_metadata(qualified_name="alice.rxd", target=ADDR)
        assert classify_glyph_metadata(md) == "wave"

    def test_legacy_wave_classified_as_mut(self):
        """WAVE without attrs.name is just a mutable NFT in indexer terms."""
        md = GlyphMetadata(
            protocol=[GlyphProtocol.NFT, GlyphProtocol.MUT, GlyphProtocol.WAVE],
            name="legacy.rxd",
        )
        assert classify_glyph_metadata(md) == "mut"

    def test_nft(self):
        md = GlyphMetadata(protocol=[GlyphProtocol.NFT], name="x")
        assert classify_glyph_metadata(md) == "nft"

    def test_ft(self):
        md = GlyphMetadata(protocol=[GlyphProtocol.FT], ticker="X")
        assert classify_glyph_metadata(md) == "ft"

    def test_mut(self):
        md = GlyphMetadata(protocol=[GlyphProtocol.NFT, GlyphProtocol.MUT], name="m")
        assert classify_glyph_metadata(md) == "mut"

    def test_container(self):
        md = GlyphMetadata(protocol=[GlyphProtocol.NFT, GlyphProtocol.CONTAINER], name="c")
        assert classify_glyph_metadata(md) == "container"

    def test_encrypted(self):
        md = GlyphMetadata(protocol=[GlyphProtocol.NFT, GlyphProtocol.ENCRYPTED], name="e")
        assert classify_glyph_metadata(md) == "encrypted"

    def test_dat(self):
        md = GlyphMetadata(protocol=[GlyphProtocol.DAT], name="d")
        assert classify_glyph_metadata(md) == "dat"

    def test_authority(self):
        md = GlyphMetadata(protocol=[GlyphProtocol.NFT, GlyphProtocol.AUTHORITY], name="a")
        assert classify_glyph_metadata(md) == "authority"

    def test_timelock(self):
        # TIMELOCK requires ENCRYPTED (which requires NFT) per the protocol
        # rules in types.py — and must out-rank the bare "encrypted" label.
        md = GlyphMetadata(
            protocol=[GlyphProtocol.NFT, GlyphProtocol.ENCRYPTED, GlyphProtocol.TIMELOCK],
            name="t",
        )
        assert classify_glyph_metadata(md) == "timelock"

    def test_timelock_outranks_encrypted(self):
        """A token carrying both ENCRYPTED and TIMELOCK is the more specific
        'timelock', never the underlying 'encrypted'."""
        md = GlyphMetadata(
            protocol=[GlyphProtocol.NFT, GlyphProtocol.ENCRYPTED, GlyphProtocol.TIMELOCK],
            name="t",
        )
        assert classify_glyph_metadata(md) == "timelock"

    def test_authority_with_mut_outranks_mut(self):
        md = GlyphMetadata(
            protocol=[GlyphProtocol.NFT, GlyphProtocol.MUT, GlyphProtocol.AUTHORITY],
            name="a",
        )
        assert classify_glyph_metadata(md) == "authority"


# ─────────────────────────────────────────────── WaveResolver ──

from pyrxd.glyph.wave import (
    WaveNameNotFound,
    WaveRecord,
    WaveResolver,
    WaveResolverError,
)


class FakeElectrumXClient:
    """In-memory test double for ElectrumXClient.

    Records every `call_extension` invocation and returns canned responses.
    Auto-wrapped by WaveResolver via RxinDexerClient.
    """

    def __init__(self, responses: dict | None = None):
        self.responses = responses or {}
        self.calls: list[tuple[str, list]] = []

    async def call_extension(self, method: str, params: list | None = None):
        self.calls.append((method, params or []))
        if method not in self.responses:
            raise RuntimeError(f"no canned response for {method}")
        result = self.responses[method]
        if isinstance(result, Exception):
            raise result
        # Allow callables to inspect params.
        return result(params) if callable(result) else result


class TestWaveResolverResolve:
    async def test_returns_wave_record(self):
        client = FakeElectrumXClient(
            {
                "wave.resolve": {
                    "name": "alice.rxd",
                    "target": ADDR,
                    "target_type": "address",
                    "claim_txid": "ab" * 32,
                    "block_height": 425046,
                },
            }
        )
        resolver = WaveResolver(client)  # auto-wraps in RxinDexerClient
        rec = await resolver.resolve("alice.rxd")
        assert isinstance(rec, WaveRecord)
        assert rec.name == "alice.rxd"
        assert rec.target == ADDR
        assert rec.claim_txid == "ab" * 32
        assert rec.block_height == 425046

    async def test_accepts_attrs_wrapped_response(self):
        """RXinDexer wraps attributes under `attrs` in some response shapes."""
        client = FakeElectrumXClient(
            {
                "wave.resolve": {
                    "attrs": {"name": "bob.rxd", "target": ADDR, "target_type": "address"},
                    "txid": "cd" * 32,
                    "height": 500000,
                },
            }
        )
        resolver = WaveResolver(client)
        rec = await resolver.resolve("bob.rxd")
        assert rec.name == "bob.rxd"
        assert rec.target == ADDR
        assert rec.claim_txid == "cd" * 32
        assert rec.block_height == 500000

    async def test_none_response_raises_name_not_found(self):
        client = FakeElectrumXClient({"wave.resolve": None})
        resolver = WaveResolver(client)
        with pytest.raises(WaveNameNotFound):
            await resolver.resolve("ghost.rxd")

    async def test_transport_error_wrapped(self):
        client = FakeElectrumXClient({"wave.resolve": RuntimeError("network down")})
        resolver = WaveResolver(client)
        with pytest.raises(WaveResolverError, match="network down"):
            await resolver.resolve("alice.rxd")

    async def test_malformed_response_wrapped(self):
        client = FakeElectrumXClient({"wave.resolve": {"unexpected": "shape"}})
        resolver = WaveResolver(client)
        with pytest.raises(WaveResolverError):
            await resolver.resolve("alice.rxd")


class TestWaveResolverOther:
    """`wave.check_available` answers with a DICT, and these fixtures used to hand it a bool.

    Upstream's `check_available` (RXinDexer `electrumx/server/wave_index.py`) returns a mapping
    on every path: `{'available': True, 'name': ...}` when free, `{'available': False, 'ref':
    ..., 'name': ...}` when TAKEN, `{'available': False, 'error': ...}` when the name fails
    `validate_wave_name`. A bare `True`/`False` is a shape the server cannot emit, so the old
    fixtures proved the wrapper against a scenario that cannot occur — while the wrapper did
    `bool(result)`, which reports a TAKEN name as available. The fiction in the fixture and the
    defect in the code hid each other.
    """

    async def test_a_free_name_is_available(self):
        client = FakeElectrumXClient({"wave.check_available": {"available": True, "name": "new"}})
        resolver = WaveResolver(client)
        assert await resolver.check_available("new.rxd") is True

    async def test_a_taken_name_is_not_available(self):
        """The fail-open case: `bool({'available': False, ...})` is True, so the old code said
        a registered name was free — the one answer that lets a caller mint over someone else."""
        client = FakeElectrumXClient(
            {"wave.check_available": {"available": False, "ref": "ab" * 32 + "_0", "name": "taken"}}
        )
        resolver = WaveResolver(client)
        assert await resolver.check_available("taken.rxd") is False

    async def test_the_bare_label_is_sent_not_the_qualified_name(self):
        """`validate_wave_name` rejects `.`, so `"alice.rxd"` was answered with an error dict —
        which `bool()` then reported as available. `resolve` was fixed for this in #695; this
        twin was not."""
        client = FakeElectrumXClient({"wave.check_available": {"available": True, "name": "alice"}})
        resolver = WaveResolver(client)
        assert await resolver.check_available("Alice.RXD") is True
        assert client.calls == [("wave.check_available", ["alice"])]

    async def test_an_indexer_refusal_is_raised_not_reported_as_available(self):
        client = FakeElectrumXClient({"wave.check_available": {"available": False, "error": "Invalid character: ."}})
        resolver = WaveResolver(client)
        with pytest.raises(WaveResolverError, match="refused by the indexer"):
            await resolver.check_available("alice.rxd")

    async def test_an_unrecognised_shape_is_refused_rather_than_guessed(self):
        """Including the bool these tests used to pass: a shape we cannot read must not be
        coerced into an answer, because the coercion direction is fail-open."""
        for answer in (True, False, None, [], "yes", {"name": "alice"}):
            client = FakeElectrumXClient({"wave.check_available": answer})
            resolver = WaveResolver(client)
            with pytest.raises(WaveResolverError):
                await resolver.check_available("alice.rxd")

    async def test_reverse_lookup(self):
        """The indexer returns a list of DICTS keyed by owner scripthash — measured against the
        public `electrumx.radiantcore.org` indexer 2026-09-16 and confirmed in RXinDexer's
        `wave_index.py`. Names come back qualified; an `expired` entry is listed by the indexer
        so the owner sees it, but it no longer resolves and is dropped here."""
        from pyrxd.network.electrumx import script_hash_for_address

        client = FakeElectrumXClient(
            {
                "wave.reverse_lookup": [
                    {"ref": "ab" * 32 + "_0", "name": "alice", "full_name": "alice.rxd", "status": "active"},
                    {"ref": "cd" * 32 + "_0", "name": "old", "full_name": "old.rxd", "status": "expired"},
                    {"ref": "ef" * 32 + "_0", "name": "bare"},
                ],
            }
        )
        resolver = WaveResolver(client)
        names = await resolver.reverse_lookup(ADDR)
        assert names == ["alice.rxd", "bare.rxd"]
        # THE ARGUMENT IS A SCRIPTHASH, NOT THE ADDRESS. The address was forwarded verbatim before,
        # and the indexer answered "non-hexadecimal number found in fromhex() arg".
        assert client.calls == [("wave.reverse_lookup", [script_hash_for_address(ADDR).hex()])]

    async def test_reverse_lookup_still_accepts_bare_names(self):
        """An older indexer that returned plain strings keeps working."""
        client = FakeElectrumXClient({"wave.reverse_lookup": ["alice.rxd", "alice.dev"]})
        assert await WaveResolver(client).reverse_lookup(ADDR) == ["alice.rxd", "alice.dev"]

    async def test_reverse_lookup_refuses_an_error_answer(self):
        client = FakeElectrumXClient({"wave.reverse_lookup": {"error": "non-hexadecimal number found"}})
        with pytest.raises(WaveResolverError, match="refused"):
            await WaveResolver(client).reverse_lookup(ADDR)

    async def test_reverse_lookup_unexpected_shape(self):
        client = FakeElectrumXClient({"wave.reverse_lookup": "not a list"})
        resolver = WaveResolver(client)
        with pytest.raises(WaveResolverError, match="expected list"):
            await resolver.reverse_lookup(ADDR)

    async def test_stats(self):
        client = FakeElectrumXClient({"wave.stats": {"total_names": 1234, "tip_height": 500000}})
        resolver = WaveResolver(client)
        s = await resolver.stats()
        assert s["total_names"] == 1234

    async def test_passes_the_label_not_the_qualified_name_to_rpc(self):
        """RXinDexer's `resolve()` runs `validate_wave_name` first and `.` is not in its
        `WAVE_CHARS`: `"alice.rxd"` is answered `{"error": "Invalid character: ."}` (measured
        2026-09-16). The qualified name the caller uses must reach the server as its label."""
        client = FakeElectrumXClient({"wave.resolve": {"name": "alice", "target": ADDR}})
        resolver = WaveResolver(client)
        record = await resolver.resolve("alice.rxd")
        assert client.calls == [("wave.resolve", ["alice"])]
        assert record.name == "alice.rxd", "the bare label the indexer returns is re-qualified for the caller"

    async def test_resolve_refuses_an_error_answer_instead_of_parsing_it(self):
        client = FakeElectrumXClient({"wave.resolve": {"error": "Invalid character: ."}})
        with pytest.raises(WaveResolverError, match="refused"):
            await WaveResolver(client).resolve("alice.rxd")

    async def test_record_carries_the_ref_and_derives_the_reveal_txid(self):
        """`ref` is `<reveal_txid>_0` — the registration transaction, which is where a
        mutable-chain walk starts. It doubles as `claim_txid` when the indexer sends none."""
        client = FakeElectrumXClient(
            {"wave.resolve": {"name": "alice", "target": ADDR, "ref": "ab" * 32 + "_0", "status": "active"}}
        )
        record = await WaveResolver(client).resolve("alice.rxd")
        assert record.ref == "ab" * 32 + "_0"
        assert record.reveal_txid == "ab" * 32
        assert record.claim_txid == "ab" * 32
        assert record.status == "active"
        bad = WaveRecord(name="x.rxd", target=ADDR, target_type="address", claim_txid="", block_height=0, ref="junk_0")
        assert bad.reveal_txid == "", "an unusable ref is reported absent, not passed on to a fetch"

    async def test_accepts_rxindexer_client_directly(self):
        from pyrxd.network.rxindexer import RxinDexerClient

        electrumx = FakeElectrumXClient(
            {
                "wave.resolve": {"name": "alice.rxd", "target": ADDR},
            }
        )
        rxin = RxinDexerClient(electrumx)
        resolver = WaveResolver(rxin)
        rec = await resolver.resolve("alice.rxd")
        assert rec.name == "alice.rxd"
        # The same RxinDexerClient is reused (not double-wrapped).
        assert resolver.client is rxin


# ─────────────────────────────────────────────── RxinDexerClient ──

from pyrxd.network.rxindexer import (
    IndexerStats,
    RxinDexerClient,
    RxinDexerError,
)


class TestRxinDexerClient:
    async def test_glyph_get_token(self):
        client = FakeElectrumXClient(
            {
                "glyph.get_token": {"ref": "ab" * 32 + ":0", "type": "nft", "owner": ADDR},
            }
        )
        rxin = RxinDexerClient(client)
        result = await rxin.glyph_get_token("ab" * 32 + ":0")
        assert result["owner"] == ADDR
        assert client.calls == [("glyph.get_token", ["ab" * 32 + ":0"])]

    async def test_glyph_get_balance_unscoped(self):
        client = FakeElectrumXClient({"glyph.get_balance": {"FT1": 100, "FT2": 50}})
        rxin = RxinDexerClient(client)
        result = await rxin.glyph_get_balance(ADDR)
        assert result == {"FT1": 100, "FT2": 50}
        assert client.calls == [("glyph.get_balance", [ADDR])]

    async def test_glyph_get_balance_scoped(self):
        client = FakeElectrumXClient({"glyph.get_balance": 42})
        rxin = RxinDexerClient(client)
        result = await rxin.glyph_get_balance(ADDR, token_ref="ab" * 32 + ":0")
        assert result == 42
        assert client.calls == [("glyph.get_balance", [ADDR, "ab" * 32 + ":0"])]

    async def test_wave_stats_parses_response(self):
        client = FakeElectrumXClient(
            {
                "wave.stats": {"total_names": 1234, "tip_height": 500000, "extra": "ignored"},
            }
        )
        rxin = RxinDexerClient(client)
        stats = await rxin.wave_stats()
        assert isinstance(stats, IndexerStats)
        assert stats.total_names == 1234
        assert stats.tip_height == 500000
        assert stats.raw["extra"] == "ignored"

    async def test_error_wraps_transport_failure(self):
        client = FakeElectrumXClient({"wave.stats": ConnectionError("socket closed")})
        rxin = RxinDexerClient(client)
        with pytest.raises(RxinDexerError, match="socket closed"):
            await rxin.wave_stats()

    async def test_wave_get_subdomains_handles_none(self):
        client = FakeElectrumXClient({"wave.get_subdomains": None})
        rxin = RxinDexerClient(client)
        assert await rxin.wave_get_subdomains("parent.rxd") == []
