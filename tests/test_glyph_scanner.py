"""Tests for GlyphScanner and new ElectrumXClient methods.

Fixture model — commit, reveal, transfer
----------------------------------------

These fixtures mirror what a Glyph mint actually looks like on chain, because
the scanner's metadata resolution depends on the distinction:

* the **commit** tx is funded by a plain P2PKH spend and pays to the commit
  script.  It carries **no** ``gly`` envelope anywhere;
* the **reveal** tx spends ``commit_txid:commit_vout`` and carries the
  ``gly`` + CBOR envelope in that input's scriptSig.  Its output is the
  NFT/FT locking script, which embeds the **commit** outpoint as the token's
  permanent ``ref``;
* a **transfer** spends the reveal's output and carries no envelope at all.

So ``ref.txid`` is the *commit* txid.  A fixture that puts the envelope in the
transaction named by ``ref.txid`` is modelling a chain that cannot exist.
"""

from __future__ import annotations

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pyrxd.glyph.payload import GLY_MARKER, encode_payload
from pyrxd.glyph.scanner import _MAX_REVEAL_CANDIDATES, GlyphScanner
from pyrxd.glyph.script import (
    build_commit_locking_script,
    build_ft_locking_script,
    build_nft_locking_script,
)
from pyrxd.glyph.types import GlyphFt, GlyphMetadata, GlyphNft, GlyphProtocol, GlyphRef
from pyrxd.network.electrumx import ElectrumXClient, UtxoRecord, script_hash_for_script
from pyrxd.script.script import Script
from pyrxd.security.errors import NetworkError
from pyrxd.security.types import Hex20, Txid
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput

# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------

TXID_COMMIT = "aa" * 32  # the NFT's ref.txid
TXID_REVEAL = "dd" * 32
TXID_TRANSFER = "bb" * 32
TXID_FT_COMMIT = "cc" * 32  # the FT's ref.txid
TXID_FT_REVEAL = "ee" * 32
TXID_FT_TRANSFER = "ff" * 32
TXID_FUNDING = "11" * 32  # what the commit txs spend
PKH = Hex20(bytes.fromhex("bb" * 20))


def _push(data: bytes) -> bytes:
    n = len(data)
    return (bytes([n]) if n <= 75 else bytes([0x4C, n])) + data


def _p2pkh_scriptsig() -> bytes:
    """A plain <sig> <pubkey> unlocking script — no Glyph envelope."""
    sig_p = bytes([0xAB] * 71)
    pub_p = bytes([0x02]) + bytes([0xCD] * 32)
    return _push(sig_p) + _push(pub_p)


def _tx(inputs: list[tuple[str, int, bytes]], outputs: list[tuple[bytes, int]]) -> str:
    """Serialise a transaction from ``(txid, vout, scriptSig)`` / ``(script, sats)``."""
    tx = Transaction()
    for source_txid, vout, scriptsig in inputs:
        tx.add_input(
            TransactionInput(
                source_txid=source_txid,
                source_output_index=vout,
                unlocking_script=Script(scriptsig),
            )
        )
    for locking_script, satoshis in outputs:
        tx.add_output(TransactionOutput(locking_script=Script(locking_script), satoshis=satoshis))
    return tx.hex()


class _Mint:
    """One realistic commit → reveal pair, plus the transfers that follow it."""

    def __init__(
        self,
        *,
        name: str,
        commit_txid: str,
        reveal_txid: str,
        is_nft: bool = True,
        satoshis: int = 546,
    ) -> None:
        protocol = [GlyphProtocol.NFT] if is_nft else [GlyphProtocol.FT]
        self.metadata = GlyphMetadata(name=name, protocol=protocol)
        cbor_bytes, payload_hash = encode_payload(self.metadata)
        self.ref = GlyphRef(txid=Txid(commit_txid), vout=0)
        self.commit_txid = commit_txid
        self.reveal_txid = reveal_txid
        self.satoshis = satoshis
        self.commit_script = build_commit_locking_script(payload_hash, PKH, is_nft=is_nft)
        self.lock = build_nft_locking_script(PKH, self.ref) if is_nft else build_ft_locking_script(PKH, self.ref)
        # Commit tx — plain funding spend in, commit script out. No envelope.
        self.commit_tx_hex = _tx(
            [(TXID_FUNDING, 3, _p2pkh_scriptsig())],
            [(self.commit_script, satoshis)],
        )
        # Reveal tx — spends the commit outpoint; envelope in that scriptSig.
        self.reveal_scriptsig = _p2pkh_scriptsig() + _push(GLY_MARKER) + _push(cbor_bytes)
        self.reveal_tx_hex = _tx(
            [(commit_txid, 0, self.reveal_scriptsig)],
            [(self.lock, satoshis)],
        )
        self.history = [
            {"tx_hash": commit_txid, "height": 100},
            {"tx_hash": reveal_txid, "height": 101},
        ]

    @property
    def commit_script_hash(self) -> str:
        return script_hash_for_script(self.commit_script).hex()

    def transfer_tx_hex(self, satoshis: int | None = None) -> str:
        """A later transfer: spends the reveal output, carries no envelope."""
        return _tx(
            [(self.reveal_txid, 0, _p2pkh_scriptsig())],
            [(self.lock, satoshis if satoshis is not None else self.satoshis)],
        )

    def decoy_tx_hex(self) -> str:
        """A tx paying the same commit script but NOT spending the ref outpoint."""
        return _tx([("22" * 32, 7, _p2pkh_scriptsig())], [(self.commit_script, self.satoshis)])


NFT_MINT = _Mint(name="TestNFT", commit_txid=TXID_COMMIT, reveal_txid=TXID_REVEAL)
FT_MINT = _Mint(
    name="TestFT",
    commit_txid=TXID_FT_COMMIT,
    reveal_txid=TXID_FT_REVEAL,
    is_nft=False,
    satoshis=1000,
)


def _chain(*mints: _Mint, drop: tuple[str, ...] = ()) -> tuple[dict, dict]:
    """Return ``(tx_map, history_map)`` for *mints*, minus any txid in *drop*."""
    tx_map: dict[str, str] = {}
    history_map: dict[str, list[dict]] = {}
    for mint in mints:
        tx_map[mint.commit_txid] = mint.commit_tx_hex
        tx_map[mint.reveal_txid] = mint.reveal_tx_hex
        history_map[mint.commit_script_hash] = mint.history
    for txid in drop:
        tx_map.pop(txid, None)
    return tx_map, history_map


def _new_calls() -> dict[str, list[str]]:
    return {"get_transaction": [], "get_history": []}


def _mock_client(
    utxos: list[UtxoRecord],
    tx_map: dict,
    history_map: dict | None = None,
    calls: dict | None = None,
) -> MagicMock:
    """Build a mock ElectrumXClient with pre-canned UTXO / tx / history data."""
    client = MagicMock(spec=ElectrumXClient)
    recorded = calls if calls is not None else _new_calls()

    async def _get_utxos(script_hash):
        return utxos

    async def _get_transaction(txid):
        recorded["get_transaction"].append(str(txid))
        hex_str = tx_map.get(str(txid), tx_map.get(txid))
        if hex_str is None:
            raise NetworkError(f"No tx for {txid}")
        return bytes.fromhex(hex_str)

    async def _get_history(script_hash):
        key = script_hash.hex() if hasattr(script_hash, "hex") else str(script_hash)
        recorded["get_history"].append(key)
        return list((history_map or {}).get(key, []))

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
        result = asyncio.run(client.get_history("cc" * 32))
        assert result == [{"tx_hash": "aa" * 32, "height": 100}]

    def test_empty_history(self):
        client = self._make_client([])
        result = asyncio.run(client.get_history("cc" * 32))
        assert result == []

    def test_unconfirmed_height_zero(self):
        client = self._make_client([{"tx_hash": "dd" * 32, "height": 0}])
        result = asyncio.run(client.get_history("cc" * 32))
        assert result[0]["height"] == 0

    def test_unconfirmed_negative_height(self):
        client = self._make_client([{"tx_hash": "dd" * 32, "height": -1}])
        result = asyncio.run(client.get_history("cc" * 32))
        assert result[0]["height"] == -1

    def test_raises_on_non_list_response(self):
        client = self._make_client("not a list")
        with pytest.raises(NetworkError):
            asyncio.run(client.get_history("cc" * 32))

    def test_raises_on_malformed_entry(self):
        client = self._make_client([{"bad_key": 1}])
        with pytest.raises(NetworkError):
            asyncio.run(client.get_history("cc" * 32))

    def test_accepts_bytes_script_hash(self):
        client = self._make_client([])
        result = asyncio.run(client.get_history(bytes([0xCC] * 32)))
        assert result == []

    def test_accepts_hex_str_script_hash(self):
        client = self._make_client([])
        result = asyncio.run(client.get_history("cc" * 32))
        assert result == []

    def test_multiple_entries(self):
        entries = [
            {"tx_hash": "aa" * 32, "height": 10},
            {"tx_hash": "bb" * 32, "height": 20},
        ]
        client = self._make_client(entries)
        result = asyncio.run(client.get_history("cc" * 32))
        assert len(result) == 2
        assert result[1]["height"] == 20


# ---------------------------------------------------------------------------
# script_hash_for_script
# ---------------------------------------------------------------------------


class TestScriptHashForScript:
    def test_matches_address_helper(self):
        """The address helper is the script helper applied to a P2PKH lock."""
        from pyrxd.script.type import P2PKH

        from pyrxd.network.electrumx import script_hash_for_address  # isort: skip

        address = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"
        assert script_hash_for_script(P2PKH().lock(address).serialize()) == script_hash_for_address(address)

    def test_is_reversed_sha256(self):
        from pyrxd.hash import sha256

        script = NFT_MINT.commit_script
        assert bytes(script_hash_for_script(script)) == sha256(script)[::-1]


# ---------------------------------------------------------------------------
# GlyphScanner tests
# ---------------------------------------------------------------------------


class TestGlyphScannerEmptyWallet:
    def test_empty_utxos_returns_empty(self):
        client = _mock_client(utxos=[], tx_map={})
        scanner = GlyphScanner(client)
        result = asyncio.run(scanner.scan_script_hash("cc" * 32))
        assert result == []

    def test_scan_address_calls_script_hash_for_address(self):
        client = _mock_client(utxos=[], tx_map={})
        scanner = GlyphScanner(client)
        with patch(
            "pyrxd.glyph.scanner.script_hash_for_address",
            return_value=bytes([0xCC] * 32),
        ):
            result = asyncio.run(scanner.scan_address("any-address"))
        assert result == []


class TestGlyphScannerNftOutput:
    def test_nft_utxo_returns_glyph_nft(self):
        tx_map, history = _chain(NFT_MINT)
        tx_map[TXID_TRANSFER] = NFT_MINT.transfer_tx_hex()
        utxos = [UtxoRecord(tx_hash=TXID_TRANSFER, tx_pos=0, value=546, height=100)]
        scanner = GlyphScanner(_mock_client(utxos, tx_map, history))
        result = asyncio.run(scanner.scan_script_hash("cc" * 32))
        assert len(result) == 1
        item = result[0]
        assert isinstance(item, GlyphNft)
        assert item.ref == NFT_MINT.ref
        assert item.owner_pkh == PKH

    def test_transferred_nft_resolves_metadata_from_the_reveal(self):
        """The held UTXO is a transfer; the envelope is two hops back.

        This is the regression case for the reveal-resolution bug: the
        scanner used to fetch ``ref.txid`` (the COMMIT) and read
        ``inputs[0]``, which on real chain data is a plain funding spend, so
        metadata came back ``None`` for every minted glyph.
        """
        tx_map, history = _chain(NFT_MINT)
        tx_map[TXID_TRANSFER] = NFT_MINT.transfer_tx_hex()
        utxos = [UtxoRecord(tx_hash=TXID_TRANSFER, tx_pos=0, value=546, height=100)]
        scanner = GlyphScanner(_mock_client(utxos, tx_map, history))
        result = asyncio.run(scanner.scan_script_hash("cc" * 32))
        assert result[0].metadata is not None
        assert result[0].metadata.name == "TestNFT"

    def test_freshly_minted_nft_resolves_without_a_history_lookup(self):
        """A not-yet-transferred glyph sits in the reveal tx itself.

        No chain lookup should be needed — the tx that produced the UTXO
        already spends the ref outpoint, so it *is* the reveal.
        """
        tx_map, history = _chain(NFT_MINT)
        utxos = [UtxoRecord(tx_hash=TXID_REVEAL, tx_pos=0, value=546, height=101)]
        calls = _new_calls()
        scanner = GlyphScanner(_mock_client(utxos, tx_map, history, calls))
        result = asyncio.run(scanner.scan_script_hash("cc" * 32))
        assert result[0].metadata is not None
        assert result[0].metadata.name == "TestNFT"
        assert calls["get_history"] == []
        assert calls["get_transaction"] == [TXID_REVEAL]

    def test_metadata_none_when_reveal_tx_unavailable(self):
        """A missing reveal costs the metadata, never the token itself."""
        tx_map, history = _chain(NFT_MINT, drop=(TXID_REVEAL,))
        tx_map[TXID_TRANSFER] = NFT_MINT.transfer_tx_hex()
        utxos = [UtxoRecord(tx_hash=TXID_TRANSFER, tx_pos=0, value=546, height=100)]
        scanner = GlyphScanner(_mock_client(utxos, tx_map, history))
        result = asyncio.run(scanner.scan_script_hash("cc" * 32))
        assert len(result) == 1
        assert result[0].metadata is None


class TestGlyphScannerFtOutput:
    def test_ft_utxo_returns_glyph_ft(self):
        tx_map, history = _chain(FT_MINT)
        tx_map[TXID_FT_TRANSFER] = FT_MINT.transfer_tx_hex()
        utxos = [UtxoRecord(tx_hash=TXID_FT_TRANSFER, tx_pos=0, value=1000, height=50)]
        scanner = GlyphScanner(_mock_client(utxos, tx_map, history))
        result = asyncio.run(scanner.scan_script_hash("cc" * 32))
        assert len(result) == 1
        item = result[0]
        assert isinstance(item, GlyphFt)
        assert item.ref == FT_MINT.ref
        assert item.owner_pkh == PKH
        assert item.amount == 1000

    def test_ft_metadata_resolves_from_the_reveal(self):
        tx_map, history = _chain(FT_MINT)
        tx_map[TXID_FT_TRANSFER] = FT_MINT.transfer_tx_hex()
        utxos = [UtxoRecord(tx_hash=TXID_FT_TRANSFER, tx_pos=0, value=1000, height=50)]
        scanner = GlyphScanner(_mock_client(utxos, tx_map, history))
        result = asyncio.run(scanner.scan_script_hash("cc" * 32))
        assert result[0].metadata is not None
        assert result[0].metadata.name == "TestFT"
        assert GlyphProtocol.FT in result[0].metadata.protocol

    def test_split_ft_resolves_metadata_once_for_all_utxos(self):
        """N UTXOs of one token cost one reveal resolution, not N."""
        tx_map, history = _chain(FT_MINT)
        tx_map[TXID_FT_TRANSFER] = FT_MINT.transfer_tx_hex()
        utxos = [UtxoRecord(tx_hash=TXID_FT_TRANSFER, tx_pos=0, value=1000, height=50 + i) for i in range(4)]
        calls = _new_calls()
        scanner = GlyphScanner(_mock_client(utxos, tx_map, history, calls))
        result = asyncio.run(scanner.scan_script_hash("cc" * 32))
        assert len(result) == 4
        assert all(r.metadata is not None and r.metadata.name == "TestFT" for r in result)
        assert len(calls["get_history"]) == 1


class TestGlyphScannerVoutFiltering:
    def test_skips_glyphs_at_wrong_vout(self):
        """UTXO at tx_pos=1 should not match the NFT at vout=0."""
        tx_map, history = _chain(NFT_MINT)
        tx_map[TXID_TRANSFER] = NFT_MINT.transfer_tx_hex()
        utxos = [UtxoRecord(tx_hash=TXID_TRANSFER, tx_pos=1, value=546, height=100)]
        scanner = GlyphScanner(_mock_client(utxos, tx_map, history))
        result = asyncio.run(scanner.scan_script_hash("cc" * 32))
        assert result == []


class TestGlyphScannerNetworkErrors:
    def test_failed_tx_fetch_is_skipped(self):
        """If get_transaction raises for a UTXO tx, that UTXO is skipped."""
        utxos = [UtxoRecord(tx_hash=TXID_TRANSFER, tx_pos=0, value=546, height=100)]
        scanner = GlyphScanner(_mock_client(utxos, tx_map={}))
        result = asyncio.run(scanner.scan_script_hash("cc" * 32))
        assert result == []

    def test_failed_commit_fetch_returns_none_metadata(self):
        """If the commit tx is unavailable, metadata is None but the Glyph stands."""
        tx_map, history = _chain(NFT_MINT, drop=(TXID_COMMIT,))
        tx_map[TXID_TRANSFER] = NFT_MINT.transfer_tx_hex()
        utxos = [UtxoRecord(tx_hash=TXID_TRANSFER, tx_pos=0, value=546, height=100)]
        scanner = GlyphScanner(_mock_client(utxos, tx_map, history))
        result = asyncio.run(scanner.scan_script_hash("cc" * 32))
        assert len(result) == 1
        assert result[0].metadata is None

    def test_empty_history_returns_none_metadata(self):
        """An indexer with no history for the commit output loses only metadata."""
        tx_map, _ = _chain(NFT_MINT)
        tx_map[TXID_TRANSFER] = NFT_MINT.transfer_tx_hex()
        utxos = [UtxoRecord(tx_hash=TXID_TRANSFER, tx_pos=0, value=546, height=100)]
        scanner = GlyphScanner(_mock_client(utxos, tx_map, history_map={}))
        result = asyncio.run(scanner.scan_script_hash("cc" * 32))
        assert len(result) == 1
        assert result[0].metadata is None


class TestGlyphScannerMixed:
    def test_mixed_nft_and_ft(self):
        tx_map, history = _chain(NFT_MINT, FT_MINT)
        tx_map[TXID_TRANSFER] = NFT_MINT.transfer_tx_hex()
        tx_map[TXID_FT_TRANSFER] = FT_MINT.transfer_tx_hex()
        utxos = [
            UtxoRecord(tx_hash=TXID_TRANSFER, tx_pos=0, value=546, height=100),
            UtxoRecord(tx_hash=TXID_FT_TRANSFER, tx_pos=0, value=1000, height=50),
        ]
        scanner = GlyphScanner(_mock_client(utxos, tx_map, history))
        result = asyncio.run(scanner.scan_script_hash("cc" * 32))
        types = {type(r).__name__ for r in result}
        assert "GlyphNft" in types
        assert "GlyphFt" in types
        assert {r.metadata.name for r in result} == {"TestNFT", "TestFT"}

    def test_scan_address_delegates_to_scan_script_hash(self):
        """scan_address() should yield same result as scan_script_hash() for the address."""
        tx_map, history = _chain(NFT_MINT)
        tx_map[TXID_TRANSFER] = NFT_MINT.transfer_tx_hex()
        utxos = [UtxoRecord(tx_hash=TXID_TRANSFER, tx_pos=0, value=546, height=100)]
        scanner = GlyphScanner(_mock_client(utxos, tx_map, history))

        with patch(
            "pyrxd.glyph.scanner.script_hash_for_address",
            return_value=bytes([0xCC] * 32),
        ):
            result_addr = asyncio.run(scanner.scan_address("any-address"))
        result_sh = asyncio.run(scanner.scan_script_hash("cc" * 32))
        assert len(result_addr) == len(result_sh)
        assert type(result_addr[0]) is type(result_sh[0])


class TestGlyphScannerNonGlyphUtxos:
    def test_non_glyph_utxos_are_skipped(self):
        """Plain P2PKH outputs should not produce any GlyphItem."""
        p2pkh_script = bytes.fromhex("76a914" + "bb" * 20 + "88ac")
        plain_tx_hex = _tx([(TXID_FUNDING, 0, _p2pkh_scriptsig())], [(p2pkh_script, 1000)])
        utxos = [UtxoRecord(tx_hash=TXID_TRANSFER, tx_pos=0, value=1000, height=100)]
        scanner = GlyphScanner(_mock_client(utxos, {TXID_TRANSFER: plain_tx_hex}))
        result = asyncio.run(scanner.scan_script_hash("cc" * 32))
        assert result == []


class TestRevealResolution:
    """The reveal is the tx that SPENDS ``ref.txid:ref.vout`` — not ``ref.txid``.

    ``ref`` comes out of the NFT/FT locking script and is the COMMIT outpoint
    (``GlyphBuilder.prepare_reveal`` puts it there).  The scanner used to fetch
    ``ref.txid`` and parse ``inputs[0]``, which is the commit's plain funding
    spend, so ``metadata`` was ``None`` for every real glyph.
    """

    def test_commit_tx_carries_no_envelope(self):
        """Fixture-reality check: the OLD lookup target has nothing to find."""
        from pyrxd.glyph.inspector import GlyphInspector

        commit_tx = Transaction.from_hex(bytes.fromhex(NFT_MINT.commit_tx_hex))
        assert commit_tx is not None
        scriptsigs = [i.unlocking_script.serialize() if i.unlocking_script else b"" for i in commit_tx.inputs]
        assert GlyphInspector().find_reveal_metadata(scriptsigs) is None
        # ...while the reveal — the tx that spends the commit outpoint — has it.
        reveal_tx = Transaction.from_hex(bytes.fromhex(NFT_MINT.reveal_tx_hex))
        assert reveal_tx is not None
        assert reveal_tx.inputs[0].source_txid == NFT_MINT.ref.txid
        assert reveal_tx.inputs[0].source_output_index == NFT_MINT.ref.vout
        found = GlyphInspector().find_reveal_metadata(
            [i.unlocking_script.serialize() if i.unlocking_script else b"" for i in reveal_tx.inputs]
        )
        assert found is not None
        assert found[1].name == "TestNFT"

    def test_history_is_queried_for_the_commit_output_script_hash(self):
        tx_map, history = _chain(NFT_MINT)
        tx_map[TXID_TRANSFER] = NFT_MINT.transfer_tx_hex()
        utxos = [UtxoRecord(tx_hash=TXID_TRANSFER, tx_pos=0, value=546, height=100)]
        calls = _new_calls()
        scanner = GlyphScanner(_mock_client(utxos, tx_map, history, calls))
        asyncio.run(scanner.scan_script_hash("cc" * 32))
        assert calls["get_history"] == [NFT_MINT.commit_script_hash]

    def test_decoys_in_history_are_ignored(self):
        """Only the entry whose input spends the ref outpoint is the reveal."""
        tx_map, history = _chain(NFT_MINT)
        tx_map[TXID_TRANSFER] = NFT_MINT.transfer_tx_hex()
        decoy_txid = "99" * 32
        tx_map[decoy_txid] = NFT_MINT.decoy_tx_hex()
        history[NFT_MINT.commit_script_hash] = [
            {"tx_hash": decoy_txid, "height": 99},
            {"tx_hash": TXID_COMMIT, "height": 100},
            {"tx_hash": TXID_REVEAL, "height": 101},
        ]
        utxos = [UtxoRecord(tx_hash=TXID_TRANSFER, tx_pos=0, value=546, height=100)]
        scanner = GlyphScanner(_mock_client(utxos, tx_map, history))
        result = asyncio.run(scanner.scan_script_hash("cc" * 32))
        assert result[0].metadata is not None
        assert result[0].metadata.name == "TestNFT"

    def test_candidate_fetches_are_bounded(self):
        """A padded history cannot make one glyph cost unbounded round trips."""
        tx_map, history = _chain(NFT_MINT)
        tx_map[TXID_TRANSFER] = NFT_MINT.transfer_tx_hex()
        decoys = []
        for i in range(_MAX_REVEAL_CANDIDATES + 5):
            txid = f"{i:02x}" * 32
            tx_map[txid] = NFT_MINT.decoy_tx_hex()
            decoys.append({"tx_hash": txid, "height": 99})
        history[NFT_MINT.commit_script_hash] = [
            {"tx_hash": TXID_COMMIT, "height": 100},
            *decoys,
            {"tx_hash": TXID_REVEAL, "height": 200},
        ]
        utxos = [UtxoRecord(tx_hash=TXID_TRANSFER, tx_pos=0, value=546, height=100)]
        calls = _new_calls()
        scanner = GlyphScanner(_mock_client(utxos, tx_map, history, calls))
        result = asyncio.run(scanner.scan_script_hash("cc" * 32))
        # The token still resolves; the metadata is given up rather than paying
        # for an unbounded walk.
        assert len(result) == 1
        assert result[0].metadata is None
        # 1 UTXO tx + 1 commit tx + at most _MAX_REVEAL_CANDIDATES candidates.
        assert len(calls["get_transaction"]) <= 2 + _MAX_REVEAL_CANDIDATES


class TestRevealMetadataConcurrency:
    """Closes ultrareview re-review N17: reveal-metadata resolution must run
    concurrently for the whole UTXO set, not one-await-per-glyph inside
    the inspector loop. Pre-fix, a wallet with N glyphs paid N round
    trips of latency for metadata; post-fix, all reveal lookups batch
    into a single ``asyncio.gather`` so total latency is bounded by
    the slowest single resolution.
    """

    @pytest.mark.asyncio
    async def test_reveal_metadata_lookups_run_in_parallel(self):
        """Five distinct tokens, each needing a two-hop reveal lookup.

        Parallel: 1 round of UTXO fetches + (commit fetch → history →
        reveal fetch) all overlapping ≈ 3×latency. Serial: 1 + 5×2
        ≈ 11×latency. The threshold sits between the two.
        """
        delay = 0.05
        mints = [
            _Mint(
                name=f"Parallel{i}",
                commit_txid=f"{0xA0 + i:02x}" * 32,
                reveal_txid=f"{0xB0 + i:02x}" * 32,
            )
            for i in range(5)
        ]
        tx_map, history_map = _chain(*mints)
        utxos = []
        for i, mint in enumerate(mints):
            transfer_txid = f"{0xC0 + i:02x}" * 32
            tx_map[transfer_txid] = mint.transfer_tx_hex()
            utxos.append(UtxoRecord(tx_hash=transfer_txid, tx_pos=0, value=546, height=100))

        base = _mock_client(utxos, tx_map, history_map)
        plain_get_transaction = base.get_transaction

        async def _slow_get_transaction(txid):
            await asyncio.sleep(delay)
            return await plain_get_transaction(txid)

        base.get_transaction = _slow_get_transaction

        scanner = GlyphScanner(base)
        t0 = time.monotonic()
        result = await scanner.scan_script_hash("cc" * 32)
        elapsed = time.monotonic() - t0

        assert len(result) == 5
        assert all(r.metadata is not None for r in result)
        assert elapsed < 6 * delay, (
            f"scan_script_hash took {elapsed * 1000:.0f}ms for 5 glyphs at "
            f"{delay * 1000:.0f}ms latency each; expected ~{3 * delay * 1000:.0f}ms "
            "from overlapping gather() rounds. Reveal resolution may have "
            "regressed to serial."
        )

    @pytest.mark.asyncio
    async def test_metadata_fetch_failure_does_not_break_other_glyphs(self):
        """If one reveal lookup fails, the other glyphs still resolve fully."""
        broken = _Mint(name="Broken", commit_txid="a1" * 32, reveal_txid="b1" * 32)
        tx_map, history_map = _chain(NFT_MINT, broken, drop=(broken.reveal_txid,))
        tx_map[TXID_TRANSFER] = NFT_MINT.transfer_tx_hex()
        broken_transfer = "c1" * 32
        tx_map[broken_transfer] = broken.transfer_tx_hex()
        utxos = [
            UtxoRecord(tx_hash=TXID_TRANSFER, tx_pos=0, value=546, height=100),
            UtxoRecord(tx_hash=broken_transfer, tx_pos=0, value=546, height=101),
        ]
        scanner = GlyphScanner(_mock_client(utxos, tx_map, history_map))
        result = await scanner.scan_script_hash("cc" * 32)
        assert len(result) == 2  # both glyphs survived
        by_ref = {r.ref: r for r in result}
        assert by_ref[NFT_MINT.ref].metadata is not None
        assert by_ref[broken.ref].metadata is None
