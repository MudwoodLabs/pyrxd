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
import collections
import logging
from unittest.mock import AsyncMock, MagicMock

import pytest

from pyrxd.base58 import base58check_encode
from pyrxd.glyph.payload import GLY_MARKER, encode_payload
from pyrxd.glyph.scanner import (
    _MAX_REVEAL_CANDIDATES,
    OWNED_TOKEN_SHAPES,
    GlyphScanner,
    owned_token_script_hashes,
)
from pyrxd.glyph.script import (
    build_commit_locking_script,
    build_ft_locking_script,
    build_nft_locking_script,
)
from pyrxd.glyph.types import GlyphFt, GlyphMetadata, GlyphNft, GlyphProtocol, GlyphRef
from pyrxd.network.electrumx import (
    ElectrumXClient,
    UtxoRecord,
    script_hash_for_address,
    script_hash_for_output,
    script_hash_for_script,
)
from pyrxd.script.script import Script
from pyrxd.security.errors import NetworkError, ServerInconsistencyError
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
        protocol: list[int] | None = None,
        container_refs: tuple[GlyphRef, ...] = (),
    ) -> None:
        if protocol is None:
            protocol = [GlyphProtocol.NFT] if is_nft else [GlyphProtocol.FT]
        self.metadata = GlyphMetadata(name=name, protocol=protocol, container_refs=container_refs)
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

# Where a Radiant ElectrumX lists PKH's outputs of each kind: the script with its refs zeroed.
# Every NFT one key owns is listed under SH_NFT, and every FT under SH_FT.
SH_NFT = script_hash_for_output(NFT_MINT.lock).hex()
SH_FT = script_hash_for_output(FT_MINT.lock).hex()
ADDRESS = base58check_encode(b"\x00" + PKH)  # PKH's mainnet P2PKH address


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
    return {"get_transaction": [], "get_history": [], "get_utxos": []}


def _mock_client(
    utxos: list[UtxoRecord] | dict[str, list[UtxoRecord]],
    tx_map: dict,
    history_map: dict | None = None,
    calls: dict | None = None,
) -> MagicMock:
    """Build a mock ElectrumXClient with pre-canned UTXO / tx / history data.

    *utxos* is either one listing, returned for every script hash asked about, or a map from
    script hash (hex) to the listing for that hash.
    """
    client = MagicMock(spec=ElectrumXClient)
    recorded = calls if calls is not None else _new_calls()

    async def _get_utxos(script_hash):
        key = script_hash.hex() if hasattr(script_hash, "hex") else str(script_hash)
        recorded["get_utxos"].append(key)
        if isinstance(utxos, dict):
            return list(utxos.get(key, []))
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

    def test_scan_address_reads_the_token_hashes_not_the_p2pkh_hash(self):
        """A Radiant ElectrumX lists an address's token outputs under their scripts with the refs
        zeroed, and its P2PKH hash lists only its plain outputs (measured on both public mainnet
        servers, 2026-09-29). Reading the P2PKH hash found no token on a real server."""
        calls = _new_calls()
        scanner = GlyphScanner(_mock_client(utxos=[], tx_map={}, calls=calls))
        result = asyncio.run(scanner.scan_address(ADDRESS))
        assert result == []
        assert sorted(calls["get_utxos"]) == sorted(sh.hex() for sh in owned_token_script_hashes(PKH))
        assert SH_NFT in calls["get_utxos"] and SH_FT in calls["get_utxos"]
        assert script_hash_for_address(ADDRESS).hex() not in calls["get_utxos"]


class TestGlyphScannerNftOutput:
    def test_nft_utxo_returns_glyph_nft(self):
        tx_map, history = _chain(NFT_MINT)
        tx_map[TXID_TRANSFER] = NFT_MINT.transfer_tx_hex()
        utxos = [UtxoRecord(tx_hash=TXID_TRANSFER, tx_pos=0, value=546, height=100)]
        scanner = GlyphScanner(_mock_client(utxos, tx_map, history))
        result = asyncio.run(scanner.scan_script_hash(SH_NFT))
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
        result = asyncio.run(scanner.scan_script_hash(SH_NFT))
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
        result = asyncio.run(scanner.scan_script_hash(SH_NFT))
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
        result = asyncio.run(scanner.scan_script_hash(SH_NFT))
        assert len(result) == 1
        assert result[0].metadata is None


class TestGlyphScannerContainers:
    """A collection is an ordinary NFT to the scanner — and that is the point.

    Nothing about the locking script says "container", here or in any other
    implementation, so the scanner surfaces container-ness and membership by
    joining the reveal envelope it already resolves onto the token.
    """

    CONTAINER_MINT = _Mint(
        name="TestCollection",
        commit_txid="a7" * 32,
        reveal_txid="b7" * 32,
        protocol=[GlyphProtocol.NFT, GlyphProtocol.CONTAINER],
    )
    MEMBER_MINT = _Mint(
        name="TestMember",
        commit_txid="c7" * 32,
        reveal_txid="d7" * 32,
        container_refs=(GlyphRef(txid=Txid("a7" * 32), vout=0),),
    )

    def _scan(self, mint: _Mint) -> GlyphNft:
        tx_map, history = _chain(mint)
        utxos = [UtxoRecord(tx_hash=mint.reveal_txid, tx_pos=0, value=546, height=101)]
        result = asyncio.run(GlyphScanner(_mock_client(utxos, tx_map, history)).scan_script_hash(SH_NFT))
        assert len(result) == 1
        return result[0]

    def test_container_is_returned_as_a_glyph_nft(self):
        item = self._scan(self.CONTAINER_MINT)
        assert isinstance(item, GlyphNft)
        assert item.ref == self.CONTAINER_MINT.ref

    def test_container_is_flagged(self):
        assert self._scan(self.CONTAINER_MINT).is_container is True

    def test_a_plain_nft_is_not_flagged_as_a_container(self):
        tx_map, history = _chain(NFT_MINT)
        utxos = [UtxoRecord(tx_hash=TXID_REVEAL, tx_pos=0, value=546, height=101)]
        result = asyncio.run(GlyphScanner(_mock_client(utxos, tx_map, history)).scan_script_hash(SH_NFT))
        assert result[0].is_container is False

    def test_member_surfaces_the_container_it_belongs_to(self):
        item = self._scan(self.MEMBER_MINT)
        assert item.container_refs == (self.CONTAINER_MINT.ref,)
        assert item.is_container is False

    def test_unresolved_metadata_leaves_membership_empty_not_broken(self):
        """A missing reveal must cost the membership, never the token."""
        tx_map, history = _chain(self.MEMBER_MINT, drop=(self.MEMBER_MINT.reveal_txid,))
        transfer_txid = "e7" * 32
        tx_map[transfer_txid] = self.MEMBER_MINT.transfer_tx_hex()
        utxos = [UtxoRecord(tx_hash=transfer_txid, tx_pos=0, value=546, height=102)]
        result = asyncio.run(GlyphScanner(_mock_client(utxos, tx_map, history)).scan_script_hash(SH_NFT))
        assert len(result) == 1
        assert result[0].metadata is None
        assert result[0].container_refs == ()

    def test_a_dead_legacy_container_output_is_skipped_with_a_warning(self, caplog):
        """The pre-0.15.0 100-byte output cannot be spent, so it must not come
        back as a transferable token — but a silent drop would leave the holder
        with no idea where their carrier photons went."""
        legacy_script = bytes([0xD0]) + GlyphRef(txid=Txid("f7" * 32), vout=2).to_bytes() + self.CONTAINER_MINT.lock
        legacy_txid = "aa" * 31 + "07"
        tx_map, history = _chain(self.CONTAINER_MINT)
        tx_map[legacy_txid] = _tx([(TXID_FUNDING, 0, _p2pkh_scriptsig())], [(legacy_script, 10_000)])
        utxos = [UtxoRecord(tx_hash=legacy_txid, tx_pos=0, value=10_000, height=103)]
        scanner = GlyphScanner(_mock_client(utxos, tx_map, history))
        with caplog.at_level(logging.WARNING):
            result = asyncio.run(scanner.scan_script_hash(script_hash_for_output(legacy_script).hex()))
        assert result == []
        assert "unspendable container-legacy" in caplog.text


class TestGlyphScannerFtOutput:
    def test_ft_utxo_returns_glyph_ft(self):
        tx_map, history = _chain(FT_MINT)
        tx_map[TXID_FT_TRANSFER] = FT_MINT.transfer_tx_hex()
        utxos = [UtxoRecord(tx_hash=TXID_FT_TRANSFER, tx_pos=0, value=1000, height=50)]
        scanner = GlyphScanner(_mock_client(utxos, tx_map, history))
        result = asyncio.run(scanner.scan_script_hash(SH_FT))
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
        result = asyncio.run(scanner.scan_script_hash(SH_FT))
        assert result[0].metadata is not None
        assert result[0].metadata.name == "TestFT"
        assert GlyphProtocol.FT in result[0].metadata.protocol

    def test_split_ft_resolves_metadata_once_for_all_utxos(self):
        """N UTXOs of one token cost one reveal resolution, not N."""
        tx_map, history = _chain(FT_MINT)
        tx_map[TXID_FT_TRANSFER] = FT_MINT.transfer_tx_hex()
        # Four outpoints. One outpoint listed four times is a server inconsistency (it would count
        # an FT four times), and is refused; see TestServerInconsistency.
        utxos = []
        for i in range(4):
            txid = f"{0xF0 + i:02x}" * 32
            tx_map[txid] = FT_MINT.transfer_tx_hex()
            utxos.append(UtxoRecord(tx_hash=txid, tx_pos=0, value=1000, height=50 + i))
        calls = _new_calls()
        scanner = GlyphScanner(_mock_client(utxos, tx_map, history, calls))
        result = asyncio.run(scanner.scan_script_hash(SH_FT))
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
        result = asyncio.run(scanner.scan_script_hash(SH_NFT))
        assert result == []


class TestGlyphScannerNetworkErrors:
    def test_failed_tx_fetch_is_skipped(self):
        """If get_transaction raises for a UTXO tx, that UTXO is skipped."""
        utxos = [UtxoRecord(tx_hash=TXID_TRANSFER, tx_pos=0, value=546, height=100)]
        scanner = GlyphScanner(_mock_client(utxos, tx_map={}))
        result = asyncio.run(scanner.scan_script_hash(SH_NFT))
        assert result == []

    def test_failed_tx_fetch_raises_when_strict(self):
        """``strict=True``, which ``pyrxd glyph list`` passes: the UTXO whose transaction could not
        be fetched fails the scan, instead of vanishing from an inventory shown as complete."""
        utxos = [UtxoRecord(tx_hash=TXID_TRANSFER, tx_pos=0, value=546, height=100)]
        scanner = GlyphScanner(_mock_client(utxos, tx_map={}))
        with pytest.raises(NetworkError, match="1 of 1 transaction reads failed"):
            asyncio.run(scanner.scan_script_hash(SH_NFT, strict=True))
        by_address = GlyphScanner(_mock_client({SH_NFT: utxos}, tx_map={}))
        with pytest.raises(NetworkError, match="1 of 1 transaction reads failed"):
            asyncio.run(by_address.scan_address(ADDRESS, strict=True))

    def test_strict_returns_a_token_whose_metadata_lookup_failed(self):
        """The honest half: strict is about the holding, not the name. The commit tx is missing,
        so the metadata lookup fails, and the token still comes back, with ``metadata=None``."""
        tx_map, history = _chain(NFT_MINT, drop=(TXID_COMMIT,))
        tx_map[TXID_TRANSFER] = NFT_MINT.transfer_tx_hex()
        utxos = [UtxoRecord(tx_hash=TXID_TRANSFER, tx_pos=0, value=546, height=100)]
        scanner = GlyphScanner(_mock_client(utxos, tx_map, history))
        result = asyncio.run(scanner.scan_script_hash(SH_NFT, strict=True))
        assert len(result) == 1
        assert result[0].metadata is None

    def test_failed_commit_fetch_returns_none_metadata(self):
        """If the commit tx is unavailable, metadata is None but the Glyph stands."""
        tx_map, history = _chain(NFT_MINT, drop=(TXID_COMMIT,))
        tx_map[TXID_TRANSFER] = NFT_MINT.transfer_tx_hex()
        utxos = [UtxoRecord(tx_hash=TXID_TRANSFER, tx_pos=0, value=546, height=100)]
        scanner = GlyphScanner(_mock_client(utxos, tx_map, history))
        result = asyncio.run(scanner.scan_script_hash(SH_NFT))
        assert len(result) == 1
        assert result[0].metadata is None

    def test_empty_history_returns_none_metadata(self):
        """An indexer with no history for the commit output loses only metadata."""
        tx_map, _ = _chain(NFT_MINT)
        tx_map[TXID_TRANSFER] = NFT_MINT.transfer_tx_hex()
        utxos = [UtxoRecord(tx_hash=TXID_TRANSFER, tx_pos=0, value=546, height=100)]
        scanner = GlyphScanner(_mock_client(utxos, tx_map, history_map={}))
        result = asyncio.run(scanner.scan_script_hash(SH_NFT))
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
        # Each listed where a Radiant ElectrumX lists it: the NFT under the address's NFT hash,
        # the FT under its FT hash.
        scanner = GlyphScanner(_mock_client({SH_NFT: utxos[:1], SH_FT: utxos[1:]}, tx_map, history))
        result = asyncio.run(scanner.scan_address(ADDRESS))
        types = {type(r).__name__ for r in result}
        assert "GlyphNft" in types
        assert "GlyphFt" in types
        assert {r.metadata.name for r in result} == {"TestNFT", "TestFT"}

    def test_scan_address_is_scan_script_hash_over_the_token_hashes(self):
        """scan_address() returns what scan_script_hash() returns for each of the address's hashes."""
        tx_map, history = _chain(NFT_MINT, FT_MINT)
        tx_map[TXID_TRANSFER] = NFT_MINT.transfer_tx_hex()
        tx_map[TXID_FT_TRANSFER] = FT_MINT.transfer_tx_hex()
        listing = {
            SH_NFT: [UtxoRecord(tx_hash=TXID_TRANSFER, tx_pos=0, value=546, height=100)],
            SH_FT: [UtxoRecord(tx_hash=TXID_FT_TRANSFER, tx_pos=0, value=1000, height=50)],
        }
        scanner = GlyphScanner(_mock_client(listing, tx_map, history))
        result_addr = asyncio.run(scanner.scan_address(ADDRESS))
        result_sh = [item for sh in (SH_NFT, SH_FT) for item in asyncio.run(scanner.scan_script_hash(sh))]
        assert result_addr == result_sh
        assert len(result_addr) == 2


class TestGlyphScannerNonGlyphUtxos:
    def test_non_glyph_utxos_are_skipped(self):
        """Plain P2PKH outputs should not produce any GlyphItem."""
        p2pkh_script = bytes.fromhex("76a914" + "bb" * 20 + "88ac")
        plain_tx_hex = _tx([(TXID_FUNDING, 0, _p2pkh_scriptsig())], [(p2pkh_script, 1000)])
        utxos = [UtxoRecord(tx_hash=TXID_TRANSFER, tx_pos=0, value=1000, height=100)]
        scanner = GlyphScanner(_mock_client(utxos, {TXID_TRANSFER: plain_tx_hex}))
        result = asyncio.run(scanner.scan_script_hash(script_hash_for_output(p2pkh_script).hex()))
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
        asyncio.run(scanner.scan_script_hash(SH_NFT))
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
        result = asyncio.run(scanner.scan_script_hash(SH_NFT))
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
        result = asyncio.run(scanner.scan_script_hash(SH_NFT))
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

        WHAT CHANGED AND WHY. This used to inject a 50 ms sleep per fetch and assert
        ``elapsed < 6 * delay``. That measures the MACHINE, not the code: the ideal parallel
        time is ~3x delay, so the threshold carried 150 ms of slack, and a loaded CI runner
        spent it — the assertion failed at 830 ms on a green branch whose only change was to a
        record sink. A check that fails for environmental reasons teaches people to re-run CI
        without reading it, which is worse than not having it.

        The property was never "it finishes quickly"; it was "the lookups OVERLAP". That is
        directly observable: count how many fetches are in flight at once. No clock, no
        threshold, and ``asyncio.sleep(0)`` — a bare yield — is enough for overlap to appear,
        so the test also drops from ~155 ms to ~2 ms.

        MEASURED PER PHASE, and that detail is load-bearing. A first version counted concurrency
        across ALL fetches and **passed against the planted regression**: serialising the reveal
        stage still leaves the earlier source-transaction ``gather`` fetching five at once, so
        the whole-set peak stays at 5 either way. Split by phase, the regression is unmistakable:

            shipped:  source=5  commit=5  reveal=5
            serial:   source=5  commit=1  reveal=1
        """
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

        # Derived from the fixture, not from hex prefixes: the phase a fetch belongs to is a
        # fact about which mint it names, and a prefix rule would silently mis-bucket if the
        # fixture's txids ever changed.
        commit_txids = {m.commit_txid for m in mints}
        reveal_txids = {m.reveal_txid for m in mints}

        base = _mock_client(utxos, tx_map, history_map)
        plain_get_transaction = base.get_transaction
        in_flight: collections.Counter[str] = collections.Counter()
        peak: collections.Counter[str] = collections.Counter()

        async def _tracking_get_transaction(txid):
            phase = "commit" if txid in commit_txids else "reveal" if txid in reveal_txids else "source"
            in_flight[phase] += 1
            peak[phase] = max(peak[phase], in_flight[phase])
            try:
                await asyncio.sleep(0)  # yield only — overlap, not duration, is the signal
                return await plain_get_transaction(txid)
            finally:
                in_flight[phase] -= 1

        base.get_transaction = _tracking_get_transaction

        scanner = GlyphScanner(base)
        result = await scanner.scan_script_hash(SH_NFT)

        assert len(result) == 5
        assert all(r.metadata is not None for r in result)
        assert peak["source"] >= 2, (
            "the source-transaction fetches did not overlap — the fixture is not exercising "
            "the batched path at all, so the reveal assertions below would prove nothing"
        )
        for phase in ("commit", "reveal"):
            assert peak[phase] >= 2, (
                f"{phase} lookups never overlapped (peak in flight: {peak[phase]}). "
                "Reveal resolution has regressed to one-await-per-glyph; it must batch into a "
                f"single gather() so latency is bounded by the slowest single resolution. "
                f"Peaks by phase: {dict(peak)}"
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
        result = await scanner.scan_script_hash(SH_NFT)
        assert len(result) == 2  # both glyphs survived
        by_ref = {r.ref: r for r in result}
        assert by_ref[NFT_MINT.ref].metadata is not None
        assert by_ref[broken.ref].metadata is None


# ---------------------------------------------------------------------------
# #782: what the server says is checked against the transaction it serves
# ---------------------------------------------------------------------------

OTHER_PKH = Hex20(bytes.fromhex("cc" * 20))  # another key's hash160
TXID_FOREIGN = "fa" * 32


def _one_output_tx(lock: bytes, satoshis: int) -> str:
    return _tx([(TXID_FUNDING, 9, _p2pkh_scriptsig())], [(lock, satoshis)])


class TestServerInconsistency:
    """``get_transaction`` binds the transaction to its txid, so what it says outranks the listing.

    Before #782 the scanner took a token's owner from the script without comparing it with the
    address, and an FT's amount from the server's UTXO record: a server listing another key's NFT
    under our address got it shown, and a 5,000-unit FT was shown as 999,999,999. Each refusal
    here has an honest-path twin below it.
    """

    @staticmethod
    def _foreign(kind: str) -> tuple[dict, dict, str]:
        """The server lists, under our *kind* hash, a *kind* output locked to another key."""
        mint = NFT_MINT if kind == "nft" else FT_MINT
        builder = build_nft_locking_script if kind == "nft" else build_ft_locking_script
        tx_map, history = _chain(mint)
        tx_map[TXID_FOREIGN] = _one_output_tx(builder(OTHER_PKH, mint.ref), 5_000)
        listing = {
            SH_NFT if kind == "nft" else SH_FT: [UtxoRecord(tx_hash=TXID_FOREIGN, tx_pos=0, value=5_000, height=1)]
        }
        return listing, tx_map, history

    @pytest.mark.parametrize("kind", ["nft", "ft"])
    def test_another_keys_token_is_a_server_inconsistency_when_strict(self, kind):
        listing, tx_map, history = self._foreign(kind)
        scanner = GlyphScanner(_mock_client(listing, tx_map, history))
        with pytest.raises(
            ServerInconsistencyError, match=f"server inconsistency: .* that {kind} output is owned by another key"
        ):
            asyncio.run(scanner.scan_address(ADDRESS, strict=True))

    @pytest.mark.parametrize("kind", ["nft", "ft"])
    def test_another_keys_token_is_left_out_by_default(self, kind, caplog):
        listing, tx_map, history = self._foreign(kind)
        scanner = GlyphScanner(_mock_client(listing, tx_map, history))
        with caplog.at_level(logging.WARNING):
            assert asyncio.run(scanner.scan_address(ADDRESS)) == []
        assert "owned by another key" in caplog.text

    def test_the_wallets_own_tokens_are_listed_when_strict(self):
        """The honest path: our NFT and FT, each under its own hash, both returned under strict."""
        tx_map, history = _chain(NFT_MINT, FT_MINT)
        tx_map[TXID_TRANSFER] = NFT_MINT.transfer_tx_hex()
        tx_map[TXID_FT_TRANSFER] = FT_MINT.transfer_tx_hex(satoshis=5_000)
        listing = {
            SH_NFT: [UtxoRecord(tx_hash=TXID_TRANSFER, tx_pos=0, value=546, height=1)],
            SH_FT: [UtxoRecord(tx_hash=TXID_FT_TRANSFER, tx_pos=0, value=5_000, height=1)],
        }
        result = asyncio.run(GlyphScanner(_mock_client(listing, tx_map, history)).scan_address(ADDRESS, strict=True))
        assert sorted((type(r).__name__, r.ref, getattr(r, "amount", 1)) for r in result) == [
            ("GlyphFt", FT_MINT.ref, 5_000),
            ("GlyphNft", NFT_MINT.ref, 1),
        ]
        assert all(r.owner_pkh == PKH for r in result)

    @pytest.mark.parametrize("value", [5_000, 999_999_999, 1])
    def test_an_fts_amount_is_what_the_transaction_pays(self, value, caplog):
        """The transaction pays 5,000; the server's record says *value*. 5,000 is shown either way,
        and a record that disagrees is logged. ``value=5_000`` is the honest record."""
        tx_map, history = _chain(FT_MINT)
        tx_map[TXID_FT_TRANSFER] = FT_MINT.transfer_tx_hex(satoshis=5_000)
        listing = {SH_FT: [UtxoRecord(tx_hash=TXID_FT_TRANSFER, tx_pos=0, value=value, height=1)]}
        with caplog.at_level(logging.WARNING):
            result = asyncio.run(
                GlyphScanner(_mock_client(listing, tx_map, history)).scan_address(ADDRESS, strict=True)
            )
        assert [r.amount for r in result] == [5_000]
        assert ("the transaction pays 5000" in caplog.text) is (value != 5_000)

    def test_an_output_not_at_the_scanned_hash_is_refused(self, caplog):
        """``scan_script_hash`` knows no owner, so only the hash can refuse another key's NFT."""
        listing, tx_map, history = self._foreign("nft")
        scanner = GlyphScanner(_mock_client(listing, tx_map, history))
        with pytest.raises(
            ServerInconsistencyError, match=f"is listed under script hash {SH_NFT}, but its output is not there"
        ):
            asyncio.run(scanner.scan_script_hash(SH_NFT, strict=True))
        with caplog.at_level(logging.WARNING):
            assert asyncio.run(scanner.scan_script_hash(SH_NFT)) == []
        assert "its output is not there" in caplog.text

    def test_a_plain_output_listed_under_a_token_hash_is_refused(self):
        """Not a token, so no owner to compare: the hash check is what refuses it."""
        p2pkh = bytes.fromhex("76a914") + PKH + bytes.fromhex("88ac")
        tx_map = {TXID_FOREIGN: _one_output_tx(p2pkh, 5_000)}
        listing = {SH_NFT: [UtxoRecord(tx_hash=TXID_FOREIGN, tx_pos=0, value=5_000, height=1)]}
        with pytest.raises(ServerInconsistencyError, match="its output is not there"):
            asyncio.run(GlyphScanner(_mock_client(listing, tx_map)).scan_address(ADDRESS, strict=True))

    @pytest.mark.parametrize(
        "script_hash",
        [SH_NFT, script_hash_for_script(NFT_MINT.lock).hex()],
        ids=["radiant-electrumx-zeroed-refs", "plain-electrumx-whole-script"],
    )
    def test_an_output_at_the_scanned_hash_is_listed(self, script_hash):
        """The honest path for the hash check, under both hashes a server can list an output by."""
        tx_map, history = _chain(NFT_MINT)
        listing = {script_hash: [UtxoRecord(tx_hash=TXID_REVEAL, tx_pos=0, value=546, height=1)]}
        result = asyncio.run(
            GlyphScanner(_mock_client(listing, tx_map, history)).scan_script_hash(script_hash, strict=True)
        )
        assert [r.ref for r in result] == [NFT_MINT.ref]

    def test_an_output_index_past_the_transaction_is_refused(self):
        tx_map, history = _chain(NFT_MINT)
        listing = {SH_NFT: [UtxoRecord(tx_hash=TXID_REVEAL, tx_pos=1, value=546, height=1)]}
        with pytest.raises(ServerInconsistencyError, match="has 1 output"):
            asyncio.run(GlyphScanner(_mock_client(listing, tx_map, history)).scan_script_hash(SH_NFT, strict=True))

    def test_an_outpoint_listed_twice_is_counted_once(self, caplog):
        """A duplicated FT outpoint would otherwise double the balance shown."""
        tx_map, history = _chain(FT_MINT)
        tx_map[TXID_FT_TRANSFER] = FT_MINT.transfer_tx_hex(satoshis=5_000)
        utxo = UtxoRecord(tx_hash=TXID_FT_TRANSFER, tx_pos=0, value=5_000, height=1)
        scanner = GlyphScanner(_mock_client({SH_FT: [utxo, utxo]}, tx_map, history))
        with pytest.raises(ServerInconsistencyError, match="is listed more than once"):
            asyncio.run(scanner.scan_address(ADDRESS, strict=True))
        with caplog.at_level(logging.WARNING):
            assert [r.amount for r in asyncio.run(scanner.scan_address(ADDRESS))] == [5_000]

    def test_a_transaction_that_does_not_parse_fails_a_strict_scan(self, caplog):
        """Was dropped silently even under strict (#782, minor)."""
        listing = {SH_NFT: [UtxoRecord(tx_hash=TXID_FOREIGN, tx_pos=0, value=546, height=1)]}
        scanner = GlyphScanner(_mock_client(listing, {TXID_FOREIGN: "0102"}))
        with pytest.raises(NetworkError, match="was fetched but does not parse"):
            asyncio.run(scanner.scan_address(ADDRESS, strict=True))
        with caplog.at_level(logging.WARNING):
            assert asyncio.run(scanner.scan_address(ADDRESS)) == []
        assert "Failed to parse tx" in caplog.text


class TestScriptHashForOutput:
    """The hash a Radiant ElectrumX lists an output under (RXinDexer ``Script.zero_refs``)."""

    # Mainnet 70218e2c4f76c066…:0, an NFT. Both public servers listed it under the zeroed-ref hash
    # and under neither the owner's P2PKH hash nor the hash of this script (probed 2026-09-29).
    MAINNET_NFT = bytes.fromhex(
        "d845a8ecaf4ab00a0c19ea26f19d259bdbea1538c89362fc04822224c9269c5a4c00000000"
        "7576a914d84b8c371ea11f051dfed9daae05c8dee24d9eba88ac"
    )

    def test_a_token_script_is_hashed_with_its_refs_zeroed(self):
        from pyrxd.hash import sha256

        zeroed = b"\xd8" + bytes(36) + self.MAINNET_NFT[37:]
        assert bytes(script_hash_for_output(self.MAINNET_NFT)) == sha256(zeroed)[::-1]
        assert script_hash_for_output(self.MAINNET_NFT) != script_hash_for_script(self.MAINNET_NFT)

    def test_the_hash_depends_on_the_owner_not_the_ref(self):
        other_ref = GlyphRef(txid=Txid("12" * 32), vout=3)
        assert script_hash_for_output(build_ft_locking_script(PKH, other_ref)) == script_hash_for_output(FT_MINT.lock)
        assert script_hash_for_output(build_ft_locking_script(OTHER_PKH, FT_MINT.ref)) != script_hash_for_output(
            FT_MINT.lock
        )

    @pytest.mark.parametrize(
        "script",
        [
            bytes.fromhex("76a914") + b"\xd8" * 20 + bytes.fromhex("88ac"),  # ref-range bytes inside a push
            b"\xd8" + bytes(range(36)) + b"\x75\x51",  # a ref, but no signature check
            b"\xd8\x00\x01",  # truncated ref operand
            NFT_MINT.commit_script,  # no ref at all
        ],
        ids=["push-data", "no-checksig", "truncated", "commit"],
    )
    def test_other_scripts_are_hashed_as_they_are(self, script):
        assert script_hash_for_output(script) == script_hash_for_script(script)


class TestOwnedTokenShapes:
    """``scan_address`` reads one hash per shape in ``OWNED_TOKEN_SHAPES``. A shape missing there
    is a token ``glyph list`` cannot see, so the set is checked against what ``find_glyphs`` emits."""

    # Pinned, not derived: the shapes that carry no owner key (a mutable-state output and a dMint
    # contract). Adding a shape to find_glyphs fails the test below until it is put in one set.
    OWNERLESS = frozenset({"mut", "dmint"})

    @staticmethod
    def _emitted_glyph_types() -> set[str]:
        import ast
        import inspect
        import textwrap

        from pyrxd.glyph import inspector

        tree = ast.parse(textwrap.dedent(inspect.getsource(inspector.GlyphInspector.find_glyphs)))
        return {
            kw.value.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            for kw in node.keywords
            if kw.arg == "glyph_type" and isinstance(kw.value, ast.Constant)
        }

    def test_every_owned_shape_find_glyphs_emits_is_read(self):
        emitted = self._emitted_glyph_types()
        assert "nft" in emitted and "ft" in emitted, f"the derivation found nothing real: {emitted}"
        assert emitted >= self.OWNERLESS
        assert set(OWNED_TOKEN_SHAPES) == emitted - self.OWNERLESS

    @pytest.mark.parametrize("glyph_type", sorted(OWNED_TOKEN_SHAPES))
    def test_each_template_is_the_shape_it_is_filed_under(self, glyph_type):
        from pyrxd.glyph.inspector import GlyphInspector

        found = GlyphInspector().find_glyphs([(1, OWNED_TOKEN_SHAPES[glyph_type](PKH))])
        assert [(g.glyph_type, g.owner_pkh) for g in found] == [(glyph_type, PKH)]
