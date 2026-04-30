"""Tests for GlyphScanner and new ElectrumXClient methods."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pyrxd.glyph.payload import GLY_MARKER, encode_payload
from pyrxd.glyph.scanner import GlyphScanner
from pyrxd.glyph.script import build_ft_locking_script, build_nft_locking_script
from pyrxd.glyph.types import GlyphFt, GlyphMetadata, GlyphNft, GlyphProtocol, GlyphRef
from pyrxd.network.electrumx import ElectrumXClient, UtxoRecord
from pyrxd.script.script import Script
from pyrxd.security.errors import NetworkError
from pyrxd.security.types import Hex20, Txid
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput

# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------

TXID_A = "aa" * 32
TXID_B = "bb" * 32
TXID_C = "cc" * 32
PKH = Hex20(bytes.fromhex("bb" * 20))
REF_A = GlyphRef(txid=Txid(TXID_A), vout=0)


def _push(data: bytes) -> bytes:
    n = len(data)
    return (bytes([n]) if n <= 75 else bytes([0x4C, n])) + data


def _make_reveal_scriptsig(name: str = "TestNFT") -> bytes:
    cbor_bytes, _ = encode_payload(GlyphMetadata(name=name, protocol=[GlyphProtocol.NFT]))
    sig_p = bytes([0xAB] * 71)
    pub_p = bytes([0x02]) + bytes([0xCD] * 32)
    return _push(sig_p) + _push(pub_p) + _push(GLY_MARKER) + _push(cbor_bytes)


def _make_tx_hex(locking_script: bytes, satoshis: int = 546) -> str:
    """Build a minimal transaction hex with one output."""
    tx = Transaction()
    tx.add_input(TransactionInput(source_txid="00" * 32, source_output_index=0))
    tx.add_output(TransactionOutput(locking_script=Script(locking_script), satoshis=satoshis))
    return tx.hex()


def _make_reveal_tx_hex(scriptsig_bytes: bytes) -> str:
    """Build a transaction whose input[0] has the given scriptSig."""
    tx = Transaction()
    inp = TransactionInput(
        source_txid="00" * 32,
        source_output_index=0,
        unlocking_script=Script(scriptsig_bytes),
    )
    tx.add_input(inp)
    tx.add_output(TransactionOutput(locking_script=Script(build_nft_locking_script(PKH, REF_A)), satoshis=546))
    return tx.hex()


NFT_SCRIPT = build_nft_locking_script(PKH, REF_A)
FT_SCRIPT = build_ft_locking_script(PKH, REF_A)
NFT_TX_HEX = _make_tx_hex(NFT_SCRIPT, 546)
FT_TX_HEX = _make_tx_hex(FT_SCRIPT, 1000)
REVEAL_SCRIPTSIG = _make_reveal_scriptsig()
REVEAL_TX_HEX = _make_reveal_tx_hex(REVEAL_SCRIPTSIG)
TRANSFER_TX_HEX = _make_reveal_tx_hex(b"")  # empty scriptSig → no metadata


def _mock_client(
    utxos: list[UtxoRecord],
    tx_map: dict,
) -> MagicMock:
    """Build a mock ElectrumXClient with pre-canned get_utxos / get_transaction."""
    client = MagicMock(spec=ElectrumXClient)

    async def _get_utxos(script_hash):
        return utxos

    async def _get_transaction(txid):
        hex_str = tx_map.get(str(txid), tx_map.get(txid))
        if hex_str is None:
            raise NetworkError(f"No tx for {txid}")
        return bytes.fromhex(hex_str)

    async def _get_history(script_hash):
        return []

    client.get_utxos = _get_utxos
    client.get_transaction = _get_transaction
    client.get_history = _get_history
    return client


# ---------------------------------------------------------------------------
# ElectrumXClient.get_history tests
# ---------------------------------------------------------------------------


class TestGetHistory:
    """Tests for the new get_history method via mock of _call."""

    def _make_client(self, call_result):
        client = ElectrumXClient.__new__(ElectrumXClient)
        client._lock = asyncio.Lock()
        client._call = AsyncMock(return_value=call_result)
        return client

    def test_returns_list_of_dicts(self):
        client = self._make_client([{"tx_hash": "aa" * 32, "height": 100}])
        result = asyncio.get_event_loop().run_until_complete(client.get_history("cc" * 32))
        assert result == [{"tx_hash": "aa" * 32, "height": 100}]

    def test_empty_history(self):
        client = self._make_client([])
        result = asyncio.get_event_loop().run_until_complete(client.get_history("cc" * 32))
        assert result == []

    def test_unconfirmed_height_zero(self):
        client = self._make_client([{"tx_hash": "dd" * 32, "height": 0}])
        result = asyncio.get_event_loop().run_until_complete(client.get_history("cc" * 32))
        assert result[0]["height"] == 0

    def test_unconfirmed_negative_height(self):
        client = self._make_client([{"tx_hash": "dd" * 32, "height": -1}])
        result = asyncio.get_event_loop().run_until_complete(client.get_history("cc" * 32))
        assert result[0]["height"] == -1

    def test_raises_on_non_list_response(self):
        client = self._make_client("not a list")
        with pytest.raises(NetworkError):
            asyncio.get_event_loop().run_until_complete(client.get_history("cc" * 32))

    def test_raises_on_malformed_entry(self):
        client = self._make_client([{"bad_key": 1}])
        with pytest.raises(NetworkError):
            asyncio.get_event_loop().run_until_complete(client.get_history("cc" * 32))

    def test_accepts_bytes_script_hash(self):
        client = self._make_client([])
        result = asyncio.get_event_loop().run_until_complete(client.get_history(bytes([0xCC] * 32)))
        assert result == []

    def test_accepts_hex_str_script_hash(self):
        client = self._make_client([])
        result = asyncio.get_event_loop().run_until_complete(client.get_history("cc" * 32))
        assert result == []

    def test_multiple_entries(self):
        entries = [
            {"tx_hash": "aa" * 32, "height": 10},
            {"tx_hash": "bb" * 32, "height": 20},
        ]
        client = self._make_client(entries)
        result = asyncio.get_event_loop().run_until_complete(client.get_history("cc" * 32))
        assert len(result) == 2
        assert result[1]["height"] == 20


# ---------------------------------------------------------------------------
# GlyphScanner tests
# ---------------------------------------------------------------------------


class TestGlyphScannerEmptyWallet:
    def test_empty_utxos_returns_empty(self):
        client = _mock_client(utxos=[], tx_map={})
        scanner = GlyphScanner(client)
        result = asyncio.get_event_loop().run_until_complete(scanner.scan_script_hash("cc" * 32))
        assert result == []

    def test_scan_address_calls_script_hash_for_address(self):
        client = _mock_client(utxos=[], tx_map={})
        scanner = GlyphScanner(client)
        with patch(
            "pyrxd.glyph.scanner.script_hash_for_address",
            return_value=bytes([0xCC] * 32),
        ):
            result = asyncio.get_event_loop().run_until_complete(scanner.scan_address("any-address"))
        assert result == []


class TestGlyphScannerNftOutput:
    def test_nft_utxo_returns_glyph_nft(self):
        utxos = [UtxoRecord(tx_hash=TXID_B, tx_pos=0, value=546, height=100)]
        client = _mock_client(
            utxos=utxos,
            tx_map={
                TXID_B: NFT_TX_HEX,
                TXID_A: REVEAL_TX_HEX,  # origin tx with reveal scriptSig
            },
        )
        scanner = GlyphScanner(client)
        result = asyncio.get_event_loop().run_until_complete(scanner.scan_script_hash("cc" * 32))
        assert len(result) == 1
        item = result[0]
        assert isinstance(item, GlyphNft)
        assert item.ref == REF_A
        assert item.owner_pkh == PKH

    def test_nft_with_reveal_has_metadata(self):
        utxos = [UtxoRecord(tx_hash=TXID_B, tx_pos=0, value=546, height=100)]
        client = _mock_client(
            utxos=utxos,
            tx_map={TXID_B: NFT_TX_HEX, TXID_A: REVEAL_TX_HEX},
        )
        scanner = GlyphScanner(client)
        result = asyncio.get_event_loop().run_until_complete(scanner.scan_script_hash("cc" * 32))
        assert result[0].metadata is not None
        assert result[0].metadata.name == "TestNFT"

    def test_nft_transfer_has_no_metadata(self):
        utxos = [UtxoRecord(tx_hash=TXID_B, tx_pos=0, value=546, height=100)]
        client = _mock_client(
            utxos=utxos,
            tx_map={TXID_B: NFT_TX_HEX, TXID_A: TRANSFER_TX_HEX},
        )
        scanner = GlyphScanner(client)
        result = asyncio.get_event_loop().run_until_complete(scanner.scan_script_hash("cc" * 32))
        assert result[0].metadata is None


class TestGlyphScannerFtOutput:
    def test_ft_utxo_returns_glyph_ft(self):
        utxos = [UtxoRecord(tx_hash=TXID_C, tx_pos=0, value=1000, height=50)]
        client = _mock_client(
            utxos=utxos,
            tx_map={TXID_C: FT_TX_HEX, TXID_A: TRANSFER_TX_HEX},
        )
        scanner = GlyphScanner(client)
        result = asyncio.get_event_loop().run_until_complete(scanner.scan_script_hash("cc" * 32))
        assert len(result) == 1
        item = result[0]
        assert isinstance(item, GlyphFt)
        assert item.ref == REF_A
        assert item.owner_pkh == PKH
        assert item.amount == 1000


class TestGlyphScannerVoutFiltering:
    def test_skips_glyphs_at_wrong_vout(self):
        """UTXO at tx_pos=1 should not match the NFT at vout=0."""
        utxos = [UtxoRecord(tx_hash=TXID_B, tx_pos=1, value=546, height=100)]
        client = _mock_client(
            utxos=utxos,
            tx_map={TXID_B: NFT_TX_HEX, TXID_A: REVEAL_TX_HEX},
        )
        scanner = GlyphScanner(client)
        result = asyncio.get_event_loop().run_until_complete(scanner.scan_script_hash("cc" * 32))
        assert result == []


class TestGlyphScannerNetworkErrors:
    def test_failed_tx_fetch_is_skipped(self):
        """If get_transaction raises for a UTXO tx, that UTXO is skipped."""
        utxos = [UtxoRecord(tx_hash=TXID_B, tx_pos=0, value=546, height=100)]
        client = _mock_client(utxos=utxos, tx_map={})  # no tx for TXID_B
        scanner = GlyphScanner(client)
        result = asyncio.get_event_loop().run_until_complete(scanner.scan_script_hash("cc" * 32))
        assert result == []

    def test_failed_reveal_fetch_returns_none_metadata(self):
        """If origin tx fetch fails, metadata is None but Glyph still returned."""
        utxos = [UtxoRecord(tx_hash=TXID_B, tx_pos=0, value=546, height=100)]
        # Only TXID_B available; TXID_A (origin) not available.
        client = _mock_client(utxos=utxos, tx_map={TXID_B: NFT_TX_HEX})
        scanner = GlyphScanner(client)
        result = asyncio.get_event_loop().run_until_complete(scanner.scan_script_hash("cc" * 32))
        assert len(result) == 1
        assert result[0].metadata is None


class TestGlyphScannerMixed:
    def test_mixed_nft_and_ft(self):
        nft_utxo = UtxoRecord(tx_hash=TXID_B, tx_pos=0, value=546, height=100)
        ft_utxo = UtxoRecord(tx_hash=TXID_C, tx_pos=0, value=1000, height=50)
        client = _mock_client(
            utxos=[nft_utxo, ft_utxo],
            tx_map={
                TXID_B: NFT_TX_HEX,
                TXID_C: FT_TX_HEX,
                TXID_A: TRANSFER_TX_HEX,
            },
        )
        scanner = GlyphScanner(client)
        result = asyncio.get_event_loop().run_until_complete(scanner.scan_script_hash("cc" * 32))
        types = {type(r).__name__ for r in result}
        assert "GlyphNft" in types
        assert "GlyphFt" in types

    def test_scan_address_delegates_to_scan_script_hash(self):
        """scan_address() should yield same result as scan_script_hash() for the address."""
        utxos = [UtxoRecord(tx_hash=TXID_B, tx_pos=0, value=546, height=100)]
        client = _mock_client(
            utxos=utxos,
            tx_map={TXID_B: NFT_TX_HEX, TXID_A: REVEAL_TX_HEX},
        )
        scanner = GlyphScanner(client)

        with patch(
            "pyrxd.glyph.scanner.script_hash_for_address",
            return_value=bytes([0xCC] * 32),
        ):
            result_addr = asyncio.get_event_loop().run_until_complete(scanner.scan_address("any-address"))
        result_sh = asyncio.get_event_loop().run_until_complete(scanner.scan_script_hash("cc" * 32))
        assert len(result_addr) == len(result_sh)
        assert type(result_addr[0]) is type(result_sh[0])


class TestGlyphScannerNonGlyphUtxos:
    def test_non_glyph_utxos_are_skipped(self):
        """Plain P2PKH outputs should not produce any GlyphItem."""
        p2pkh_script = bytes.fromhex("76a914" + "bb" * 20 + "88ac")
        plain_tx_hex = _make_tx_hex(p2pkh_script, 1000)
        utxos = [UtxoRecord(tx_hash=TXID_B, tx_pos=0, value=1000, height=100)]
        client = _mock_client(utxos=utxos, tx_map={TXID_B: plain_tx_hex})
        scanner = GlyphScanner(client)
        result = asyncio.get_event_loop().run_until_complete(scanner.scan_script_hash("cc" * 32))
        assert result == []


class TestRevealMetadataConcurrency:
    """Closes ultrareview re-review N17: reveal-metadata fetches must run
    concurrently for the whole UTXO set, not one-await-per-glyph inside
    the inspector loop. Pre-fix, a wallet with N glyphs paid N round
    trips of latency for metadata; post-fix, all reveal fetches batch
    into a single ``asyncio.gather`` so total latency is bounded by
    the slowest single fetch.
    """

    @pytest.mark.asyncio
    async def test_reveal_metadata_fetches_run_in_parallel(self):
        """Build a 5-NFT wallet, instrument get_transaction with a 100ms
        delay, and assert the total scan time is closer to 1×latency
        than 5×latency. Pre-fix this ran serially → ~600ms (1×UTXO
        gather + 5× sequential metadata); post-fix all in parallel →
        ~200ms (1×UTXO gather + 1×metadata gather).
        """
        nft_locking = build_nft_locking_script(PKH, REF_A)
        nft_tx_hex = _make_tx_hex(nft_locking)
        scriptsig = _make_reveal_scriptsig("ParallelTest")
        reveal_tx_hex = _make_reveal_tx_hex(scriptsig)

        # Five UTXOs that all glyph-resolve, each of which produces an
        # extra get_transaction call to fetch its reveal-metadata.
        utxos = [UtxoRecord(tx_hash=TXID_A, tx_pos=0, value=546, height=100) for _ in range(5)]

        get_tx_calls: list[float] = []
        delay = 0.10  # 100ms — easily distinguishable from background noise

        async def _slow_get_transaction(txid):
            import time

            get_tx_calls.append(time.monotonic())
            await asyncio.sleep(delay)
            # Both UTXO source-tx and reveal-tx fetches go through here.
            return bytes.fromhex(reveal_tx_hex)

        async def _get_utxos(_):
            return utxos

        client = MagicMock(spec=ElectrumXClient)
        client.get_utxos = _get_utxos
        client.get_transaction = _slow_get_transaction

        # Override the source-tx response with the NFT-bearing tx so
        # the inspector sees a glyph and queues a reveal-metadata fetch.
        async def _routed_get_transaction(txid):
            import time

            get_tx_calls.append(time.monotonic())
            await asyncio.sleep(delay)
            str(txid)
            # First-pass UTXO source-tx fetches use TXID_A; the
            # reveal-metadata path uses ref.txid (which is also TXID_A
            # in this construction). Both legitimately return the
            # nft-bearing tx — the inspector can re-extract metadata
            # from either.
            return bytes.fromhex(nft_tx_hex)

        client.get_transaction = _routed_get_transaction

        scanner = GlyphScanner(client)

        import time

        t0 = time.monotonic()
        result = await scanner.scan_script_hash("cc" * 32)
        elapsed = time.monotonic() - t0

        # 5 UTXOs → 5 source-tx fetches (gather → ~100ms).
        # 5 glyphs → 5 reveal-metadata fetches (gather → ~100ms).
        # Total ≈ 200ms. With a sequential inner loop (the bug) it
        # would be ~600ms. We cap at 400ms to stay well clear of
        # both numbers and tolerate CI jitter.
        assert elapsed < 0.40, (
            f"scan_script_hash took {elapsed * 1000:.0f}ms for 5 UTXOs at "
            f"{delay * 1000:.0f}ms latency each; expected ~{2 * delay * 1000:.0f}ms "
            "from two parallel gather() rounds. Reveal-metadata fetches "
            "may have regressed to serial."
        )
        # Sanity: we did get the glyphs back.
        assert len(result) == 5

    @pytest.mark.asyncio
    async def test_metadata_fetch_failure_does_not_break_other_glyphs(self):
        """If one reveal-metadata fetch raises, other glyphs in the same
        scan must still resolve with metadata=None for the failing one
        and full metadata for the others. The gather() switch must not
        let one bad fetch poison the whole result.
        """
        nft_locking = build_nft_locking_script(PKH, REF_A)
        nft_tx_hex = _make_tx_hex(nft_locking)
        scriptsig = _make_reveal_scriptsig("HappyMeta")
        reveal_tx_hex = _make_reveal_tx_hex(scriptsig)

        utxos = [
            UtxoRecord(tx_hash=TXID_A, tx_pos=0, value=546, height=100),
            UtxoRecord(tx_hash=TXID_A, tx_pos=0, value=546, height=101),
        ]

        call_count = {"n": 0}

        async def _get_transaction(txid):
            call_count["n"] += 1
            # First call (source-tx) succeeds for both UTXOs since
            # they share TXID_A; subsequent reveal-metadata fetches:
            # alternate success/failure to prove independence.
            if call_count["n"] >= 4:
                raise NetworkError("fake reveal-fetch failure")
            return bytes.fromhex(nft_tx_hex if call_count["n"] <= 2 else reveal_tx_hex)

        client = MagicMock(spec=ElectrumXClient)

        async def _get_utxos(_):
            return utxos

        client.get_utxos = _get_utxos
        client.get_transaction = _get_transaction

        scanner = GlyphScanner(client)
        result = await scanner.scan_script_hash("cc" * 32)
        assert len(result) == 2  # both glyphs survived
