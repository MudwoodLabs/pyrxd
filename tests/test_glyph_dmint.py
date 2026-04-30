"""Tests for dMint-marked FT deploy support (pyrxd 0.2.0).

Covers:
- GlyphMetadata.for_dmint_ft convenience constructor
- decimals / image_* field round-trip through CBOR encode/decode
- build_commit_locking_script FT vs NFT refType byte (OP_1 vs OP_2)
- prepare_commit auto-derives refType from metadata.protocol
- prepare_ft_deploy_reveal returns correct 75-byte FT locking script + premine amount
"""

from __future__ import annotations

import pytest

from pyrxd.glyph.builder import (
    CommitParams,
    FtDeployRevealScripts,
    GlyphBuilder,
)
from pyrxd.glyph.payload import decode_payload, encode_payload
from pyrxd.glyph.script import (
    build_commit_locking_script,
    extract_owner_pkh_from_ft_script,
    extract_ref_from_ft_script,
)
from pyrxd.glyph.types import GlyphMetadata, GlyphProtocol
from pyrxd.security.errors import ValidationError
from pyrxd.security.types import Hex20

TREASURY_PKH = Hex20(b"\x11" * 20)
FUNDING_PKH = Hex20(b"\x22" * 20)


# --------------------------------------------------------------------------
# GlyphMetadata: new fields + for_dmint_ft constructor
# --------------------------------------------------------------------------


class TestGlyphMetadataDmintFields:
    def test_for_dmint_ft_defaults_protocol_to_ft_plus_dmint(self):
        meta = GlyphMetadata.for_dmint_ft(ticker="TST", name="Test Token")
        assert list(meta.protocol) == [GlyphProtocol.FT, GlyphProtocol.DMINT]
        assert meta.ticker == "TST"
        assert meta.name == "Test Token"
        assert meta.decimals == 0

    def test_for_dmint_ft_rejects_dmint_alone_protocol_override(self):
        """[4] alone is now blocked — prepare_reveal requires FT=1."""
        import pytest

        from pyrxd.security.errors import ValidationError

        with pytest.raises(ValidationError, match="requires FT"):
            GlyphMetadata.for_dmint_ft(
                ticker="TST",
                name="Test Token",
                protocol=[GlyphProtocol.DMINT],
            )

    def test_new_fields_round_trip_through_cbor(self):
        meta = GlyphMetadata.for_dmint_ft(
            ticker="TST",
            name="Test Token",
            decimals=0,
            description="Platform credits for pinball tournaments.",
            image_url="https://example.org/test-logo.png",
            image_ipfs="ipfs://bafybeigd...",
            image_sha256="abcd" * 16,  # 64 hex chars
        )
        cbor_bytes, _ = encode_payload(meta)
        decoded = decode_payload(cbor_bytes)

        assert decoded.ticker == "TST"
        assert decoded.name == "Test Token"
        assert decoded.decimals == 0
        assert decoded.description == "Platform credits for pinball tournaments."
        assert decoded.image_url == "https://example.org/test-logo.png"
        assert decoded.image_ipfs == "ipfs://bafybeigd..."
        assert decoded.image_sha256 == "abcd" * 16

    def test_decimals_omitted_from_cbor_when_zero(self):
        """decimals=0 is the default; leaving it out keeps payloads small."""
        meta = GlyphMetadata.for_dmint_ft(ticker="TST", name="Test Token")
        cbor_bytes, _ = encode_payload(meta)
        # CBOR dict should not include decimals key (encode uses `if self.decimals`)
        import cbor2

        d = cbor2.loads(cbor_bytes)
        assert "decimals" not in d

    def test_decimals_nonzero_included_in_cbor(self):
        meta = GlyphMetadata.for_dmint_ft(
            ticker="TST",
            name="Test Token",
            decimals=8,
        )
        cbor_bytes, _ = encode_payload(meta)
        import cbor2

        d = cbor2.loads(cbor_bytes)
        assert d["decimals"] == 8

    def test_image_fields_omitted_when_empty(self):
        meta = GlyphMetadata.for_dmint_ft(ticker="TST", name="Test Token")
        cbor_bytes, _ = encode_payload(meta)
        import cbor2

        d = cbor2.loads(cbor_bytes)
        assert "image" not in d
        assert "image_ipfs" not in d
        assert "image_sha256" not in d

    def test_backward_compat_old_metadata_still_decodes(self):
        """A pre-0.2 CBOR payload (no decimals/image fields) must still decode."""
        import cbor2

        old_cbor = cbor2.dumps({"p": [1, 4], "name": "TST", "ticker": "TST"})
        decoded = decode_payload(old_cbor)
        assert list(decoded.protocol) == [1, 4]
        assert decoded.name == "TST"
        assert decoded.ticker == "TST"
        # New fields get their defaults
        assert decoded.decimals == 0
        assert decoded.image_url == ""
        assert decoded.image_ipfs == ""
        assert decoded.image_sha256 == ""


# --------------------------------------------------------------------------
# build_commit_locking_script: FT vs NFT refType byte
# --------------------------------------------------------------------------


class TestCommitLockingScriptFtBranch:
    def test_nft_commit_has_op_2_refcheck(self):
        """Default is_nft=True emits OP_2 (SINGLETON=2) — backward-compatible."""
        script = build_commit_locking_script(bytes(32), TREASURY_PKH)
        # OP_REFTYPE_OUTPUT <OP_N> OP_NUMEQUALVERIFY sequence
        assert script[47:50] == b"\xda\x52\x9d"

    def test_ft_commit_has_op_1_refcheck(self):
        """is_nft=False emits OP_1 (NORMAL=1) — the 0.2.0 fix for FT minting."""
        script = build_commit_locking_script(bytes(32), TREASURY_PKH, is_nft=False)
        assert script[47:50] == b"\xda\x51\x9d"

    def test_ft_and_nft_commit_differ_by_exactly_one_byte(self):
        """The refType toggle is the single-byte difference between FT/NFT commits."""
        nft_script = build_commit_locking_script(bytes(32), TREASURY_PKH, is_nft=True)
        ft_script = build_commit_locking_script(bytes(32), TREASURY_PKH, is_nft=False)

        assert len(nft_script) == len(ft_script)
        diffs = [(i, a, b) for i, (a, b) in enumerate(zip(nft_script, ft_script)) if a != b]
        assert len(diffs) == 1
        offset, nft_byte, ft_byte = diffs[0]
        assert offset == 48  # the OP_N byte (0xda at 47, OP_N at 48)
        assert nft_byte == 0x52  # OP_2
        assert ft_byte == 0x51  # OP_1

    def test_commit_script_length_unchanged(self):
        """Both FT and NFT commits are the same fixed length — no refactor regression."""
        nft_script = build_commit_locking_script(bytes(32), TREASURY_PKH, is_nft=True)
        ft_script = build_commit_locking_script(bytes(32), TREASURY_PKH, is_nft=False)
        assert len(nft_script) == len(ft_script) == 75


# --------------------------------------------------------------------------
# prepare_commit: auto-derives is_nft from metadata.protocol
# --------------------------------------------------------------------------


class TestPrepareCommitRefTypeAutoDerivation:
    def test_nft_metadata_produces_nft_commit_script(self):
        builder = GlyphBuilder()
        meta = GlyphMetadata(protocol=[GlyphProtocol.NFT], name="TestNFT")
        result = builder.prepare_commit(
            CommitParams(
                metadata=meta,
                owner_pkh=FUNDING_PKH,
                change_pkh=FUNDING_PKH,
                funding_satoshis=1_000_000,
            )
        )
        # NFT commit: OP_2 at offset 46
        assert result.commit_script[48] == 0x52

    def test_ft_metadata_produces_ft_commit_script(self):
        builder = GlyphBuilder()
        meta = GlyphMetadata(protocol=[GlyphProtocol.FT], name="TestFT", ticker="TFT")
        result = builder.prepare_commit(
            CommitParams(
                metadata=meta,
                owner_pkh=FUNDING_PKH,
                change_pkh=FUNDING_PKH,
                funding_satoshis=1_000_000,
            )
        )
        # FT commit: OP_1 at offset 46
        assert result.commit_script[48] == 0x51

    def test_dmint_ft_metadata_produces_ft_commit_script(self):
        """[1, 4] should produce FT commit (NORMAL refType), not NFT."""
        builder = GlyphBuilder()
        meta = GlyphMetadata.for_dmint_ft(ticker="TST", name="Test Token")
        result = builder.prepare_commit(
            CommitParams(
                metadata=meta,
                owner_pkh=FUNDING_PKH,
                change_pkh=FUNDING_PKH,
                funding_satoshis=1_000_000,
            )
        )
        assert result.commit_script[48] == 0x51

    def test_dmint_only_metadata_raises_at_construction(self):
        """[4] alone is blocked at GlyphMetadata construction — prepare_reveal requires FT=1."""
        import pytest

        from pyrxd.security.errors import ValidationError

        with pytest.raises(ValidationError, match="requires FT"):
            GlyphMetadata(protocol=[GlyphProtocol.DMINT], name="TST")


# --------------------------------------------------------------------------
# prepare_ft_deploy_reveal: the convenience wrapper
# --------------------------------------------------------------------------


class TestPrepareFtDeployReveal:
    def _build_commit(self, builder: GlyphBuilder, protocol: list[int]):
        meta = GlyphMetadata(
            protocol=protocol,
            name="TST",
            ticker="TST",
            decimals=0,
        )
        return builder.prepare_commit(
            CommitParams(
                metadata=meta,
                owner_pkh=FUNDING_PKH,
                change_pkh=FUNDING_PKH,
                funding_satoshis=2_000_000_000,
            )
        )

    def test_returns_75_byte_ft_locking_script(self):
        builder = GlyphBuilder()
        commit = self._build_commit(builder, [GlyphProtocol.FT, GlyphProtocol.DMINT])
        result = builder.prepare_ft_deploy_reveal(
            commit_txid="ab" * 32,
            commit_vout=0,
            commit_value=1_000_001,
            cbor_bytes=commit.cbor_bytes,
            premine_pkh=TREASURY_PKH,
            premine_amount=1_000_000_000,
        )
        assert isinstance(result, FtDeployRevealScripts)
        assert len(result.locking_script) == 75

    def test_locking_script_carries_treasury_pkh(self):
        builder = GlyphBuilder()
        commit = self._build_commit(builder, [GlyphProtocol.FT, GlyphProtocol.DMINT])
        result = builder.prepare_ft_deploy_reveal(
            commit_txid="ab" * 32,
            commit_vout=0,
            commit_value=1_000_001,
            cbor_bytes=commit.cbor_bytes,
            premine_pkh=TREASURY_PKH,
            premine_amount=1_000_000_000,
        )
        assert extract_owner_pkh_from_ft_script(result.locking_script) == TREASURY_PKH

    def test_locking_script_ref_is_commit_outpoint(self):
        builder = GlyphBuilder()
        commit = self._build_commit(builder, [GlyphProtocol.FT, GlyphProtocol.DMINT])
        commit_txid = "ab" * 32
        result = builder.prepare_ft_deploy_reveal(
            commit_txid=commit_txid,
            commit_vout=0,
            commit_value=1_000_001,
            cbor_bytes=commit.cbor_bytes,
            premine_pkh=TREASURY_PKH,
            premine_amount=1_000_000_000,
        )
        ref = extract_ref_from_ft_script(result.locking_script)
        assert ref.txid == commit_txid
        assert ref.vout == 0

    def test_premine_amount_echoed_back(self):
        """The caller uses the echoed amount to set vout[0].value on the reveal tx."""
        builder = GlyphBuilder()
        commit = self._build_commit(builder, [GlyphProtocol.FT, GlyphProtocol.DMINT])
        result = builder.prepare_ft_deploy_reveal(
            commit_txid="ab" * 32,
            commit_vout=0,
            commit_value=1_000_001,
            cbor_bytes=commit.cbor_bytes,
            premine_pkh=TREASURY_PKH,
            premine_amount=1_000_000_000,
        )
        assert result.premine_amount == 1_000_000_000

    def test_rejects_negative_premine(self):
        builder = GlyphBuilder()
        commit = self._build_commit(builder, [GlyphProtocol.FT, GlyphProtocol.DMINT])
        with pytest.raises(ValidationError, match="non-negative"):
            builder.prepare_ft_deploy_reveal(
                commit_txid="ab" * 32,
                commit_vout=0,
                commit_value=1_000_001,
                cbor_bytes=commit.cbor_bytes,
                premine_pkh=TREASURY_PKH,
                premine_amount=-1,
            )

    def test_rejects_below_dust_premine(self):
        builder = GlyphBuilder()
        commit = self._build_commit(builder, [GlyphProtocol.FT, GlyphProtocol.DMINT])
        with pytest.raises(ValidationError, match="dust"):
            builder.prepare_ft_deploy_reveal(
                commit_txid="ab" * 32,
                commit_vout=0,
                commit_value=1_000_001,
                cbor_bytes=commit.cbor_bytes,
                premine_pkh=TREASURY_PKH,
                premine_amount=100,  # below 546 dust
            )

    @pytest.mark.parametrize(
        "premine_amount,should_pass",
        [
            (544, False),  # below dust
            (545, False),  # one-photon-below dust — must reject
            (546, True),  # exact dust limit — must accept
            (547, True),  # one-photon-above dust — must accept
            (1000, True),  # well above
        ],
    )
    def test_premine_dust_boundary_545_546_547(self, premine_amount, should_pass):
        """The dust limit is 546 photons. Test the exact boundary triple
        plus 544 (definitely-below) and 1000 (definitely-above) so a future
        off-by-one doesn't slip past.

        Prevents: the off-by-one that either (a) blocks a legitimate
        546-photon premine, or (b) accepts a below-dust premine that
        gets rejected by mempool relays after the deploy is partially
        broadcast.
        """
        builder = GlyphBuilder()
        commit = self._build_commit(builder, [GlyphProtocol.FT, GlyphProtocol.DMINT])
        if should_pass:
            result = builder.prepare_ft_deploy_reveal(
                commit_txid="ab" * 32,
                commit_vout=0,
                commit_value=premine_amount + 100_000,  # commit must cover premine + fee
                cbor_bytes=commit.cbor_bytes,
                premine_pkh=TREASURY_PKH,
                premine_amount=premine_amount,
            )
            assert result.premine_amount == premine_amount
            assert len(result.locking_script) == 75
        else:
            with pytest.raises(ValidationError, match="dust"):
                builder.prepare_ft_deploy_reveal(
                    commit_txid="ab" * 32,
                    commit_vout=0,
                    commit_value=premine_amount + 100_000,
                    cbor_bytes=commit.cbor_bytes,
                    premine_pkh=TREASURY_PKH,
                    premine_amount=premine_amount,
                )

    def test_scriptsig_suffix_carries_gly_marker(self):
        builder = GlyphBuilder()
        commit = self._build_commit(builder, [GlyphProtocol.FT, GlyphProtocol.DMINT])
        result = builder.prepare_ft_deploy_reveal(
            commit_txid="ab" * 32,
            commit_vout=0,
            commit_value=1_000_001,
            cbor_bytes=commit.cbor_bytes,
            premine_pkh=TREASURY_PKH,
            premine_amount=1_000_000_000,
        )
        # The suffix starts with the push of 'gly' (3-byte push + 'gly')
        assert result.scriptsig_suffix[:4] == b"\x03gly"

    def test_works_with_plain_ft_protocol_not_just_dmint(self):
        """pyrxd treats the dMint marker as caller-owned — plain FT premine works too."""
        builder = GlyphBuilder()
        commit = self._build_commit(builder, [GlyphProtocol.FT])
        result = builder.prepare_ft_deploy_reveal(
            commit_txid="ab" * 32,
            commit_vout=0,
            commit_value=1_000_001,
            cbor_bytes=commit.cbor_bytes,
            premine_pkh=TREASURY_PKH,
            premine_amount=1_000_000_000,
        )
        assert len(result.locking_script) == 75

    def test_large_supply_within_int64_bounds(self):
        """1B units at 1 photon = 1 unit is well within int64 — no overflow."""
        builder = GlyphBuilder()
        commit = self._build_commit(builder, [GlyphProtocol.FT, GlyphProtocol.DMINT])
        result = builder.prepare_ft_deploy_reveal(
            commit_txid="ab" * 32,
            commit_vout=0,
            commit_value=1_000_001,
            cbor_bytes=commit.cbor_bytes,
            premine_pkh=TREASURY_PKH,
            premine_amount=10_000_000_000_000,  # 10 trillion — far past our 1B target
        )
        assert result.premine_amount == 10_000_000_000_000
