"""GlyphScanner: resolve a Radiant address to its Glyph inventory.

Wires together GlyphInspector (pure parser), ElectrumXClient (network),
and the GlyphNft / GlyphFt types into a single async API.
"""
from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, List, Union

from ..network.electrumx import script_hash_for_address
from ..security.errors import NetworkError
from ..security.types import Hex32
from .inspector import GlyphInspector
from .script import (
    extract_owner_pkh_from_ft_script,
    extract_owner_pkh_from_nft_script,
)
from .types import GlyphFt, GlyphNft

if TYPE_CHECKING:
    from ..network.electrumx import ElectrumXClient

logger = logging.getLogger(__name__)

GlyphItem = Union[GlyphNft, GlyphFt]


class GlyphScanner:
    """Scan a Radiant address or script_hash for Glyph outputs.

    Parameters
    ----------
    client:
        An *already-connected* ElectrumXClient.  The scanner does not
        own the connection lifecycle; callers should use the client as a
        context manager and pass it in.
    """

    def __init__(self, client: "ElectrumXClient") -> None:
        self._client = client
        self._inspector = GlyphInspector()

    async def scan_address(self, address: str) -> List[GlyphItem]:
        """Return all Glyph outputs currently owned at *address*.

        Parameters
        ----------
        address:
            Base58Check-encoded P2PKH address.

        Returns
        -------
        List[GlyphNft | GlyphFt]
            Typed Glyph objects.  ``metadata`` is ``None`` for transfer
            outputs (no reveal scriptSig in the origin transaction).
        """
        sh = script_hash_for_address(address)
        return await self.scan_script_hash(sh)

    async def scan_script_hash(
        self, script_hash: "Hex32 | bytes | str"
    ) -> List[GlyphItem]:
        """Return all Glyph outputs for *script_hash*.

        Fetches UTXOs, raw transactions, and (where available) reveal
        transaction metadata, then constructs typed GlyphNft / GlyphFt
        objects.

        Concurrency: UTXO raw-tx fetches and reveal-metadata fetches both
        run in parallel via ``asyncio.gather``. Pre-fix (closes
        ultrareview re-review N17) the reveal-metadata path was inside
        the per-utxo loop and serialised one round-trip per glyph; for
        a 100-glyph wallet that meant ~100x the latency of the now-
        batched version.
        """
        from ..transaction.transaction import Transaction

        utxos = await self._client.get_utxos(script_hash)
        if not utxos:
            return []

        # Fetch all UTXO raw txs concurrently.
        raw_txs = await asyncio.gather(
            *[self._client.get_transaction(utxo.tx_hash) for utxo in utxos],
            return_exceptions=True,
        )

        # First pass: parse each UTXO's source tx, run the glyph inspector,
        # collect every (utxo, glyph) pair we'd want metadata for.
        # Two-pass split lets us issue all reveal-metadata fetches as a
        # single gather() instead of one-await-per-glyph.
        pending: List[tuple] = []  # (utxo, glyph)
        for utxo, raw in zip(utxos, raw_txs):
            if isinstance(raw, Exception):
                logger.warning("Failed to fetch tx %s: %s", utxo.tx_hash, raw)
                continue

            tx = Transaction.from_hex(bytes(raw))
            if tx is None:
                logger.warning("Failed to parse tx %s", utxo.tx_hash)
                continue

            output_pairs = [
                (out.satoshis, out.locking_script.serialize())
                for out in tx.outputs
            ]
            glyphs = self._inspector.find_glyphs(output_pairs)

            for g in glyphs:
                if g.vout != utxo.tx_pos:
                    continue
                pending.append((utxo, g))

        if not pending:
            return []

        # Reveal-metadata fetches batched concurrently (N17 fix). Each
        # entry's index maps 1:1 back to ``pending[i]`` so we can pair
        # them up below without sorting.
        metadatas = await asyncio.gather(
            *[self._fetch_reveal_metadata(g.ref.txid) for (_, g) in pending],
            return_exceptions=True,
        )

        results: List[GlyphItem] = []
        for (utxo, g), meta in zip(pending, metadatas):
            # _fetch_reveal_metadata catches its own exceptions and
            # returns None — but gather(return_exceptions=True) means a
            # truly unexpected error (TypeError, MemoryError) still
            # surfaces here as an Exception object instead of crashing
            # the whole scan.
            metadata = None if isinstance(meta, BaseException) else meta
            script = g.script

            try:
                if g.glyph_type == "nft":
                    pkh = extract_owner_pkh_from_nft_script(script)
                    results.append(
                        GlyphNft(ref=g.ref, owner_pkh=pkh, metadata=metadata)
                    )
                elif g.glyph_type == "ft":
                    pkh = extract_owner_pkh_from_ft_script(script)
                    results.append(
                        GlyphFt(
                            ref=g.ref,
                            owner_pkh=pkh,
                            amount=utxo.value,
                            metadata=metadata,
                        )
                    )
            except Exception as exc:
                logger.warning(
                    "Could not construct Glyph for %s vout %d: %s",
                    utxo.tx_hash, utxo.tx_pos, exc,
                )

        return results

    async def _fetch_reveal_metadata(self, origin_txid: str):  # type: ignore[return]
        """Fetch the origin tx and extract metadata from input[0] scriptSig.

        Returns None if this is a transfer (no GLY marker) or on any error.
        """
        from ..transaction.transaction import Transaction

        try:
            raw = await self._client.get_transaction(origin_txid)
        except (NetworkError, Exception):
            return None

        tx = Transaction.from_hex(bytes(raw))
        if tx is None or not tx.inputs:
            return None

        inp = tx.inputs[0]
        scriptsig = inp.unlocking_script.serialize() if inp.unlocking_script else b""
        return self._inspector.extract_reveal_metadata(scriptsig)
