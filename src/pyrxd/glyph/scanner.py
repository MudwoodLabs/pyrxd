"""GlyphScanner: resolve a Radiant address to its Glyph inventory.

Wires together GlyphInspector (pure parser), ElectrumXClient (network),
and the GlyphNft / GlyphFt types into a single async API.

Where the metadata lives
------------------------

A Glyph mint is two transactions, and the token's ``ref`` names the
*first* one::

    commit tx                         reveal tx (spends commit vout)
    ┌───────────────────────────┐     ┌────────────────────────────────┐
    │ in[0]: plain P2PKH funding│ ──▶ │ in[0] scriptSig:               │
    │ out[v]: commit script     │     │   <sig> <pubkey> "gly" <CBOR>  │◀── metadata
    │   (OP_HASH256 <payload>…) │     │ out[0]: NFT/FT lock            │
    └───────────────────────────┘     │   …0xd8 <ref = commit_txid:v>  │
              ▲                       └────────────────────────────────┘
              └──── ref points HERE, at the commit outpoint

So ``ref.txid`` is the commit txid, not the reveal txid, and fetching
``ref.txid`` and reading ``inputs[0]`` finds only the funding spend — no
envelope. The metadata is in whatever transaction **spends**
``ref.txid:ref.vout``. See :meth:`GlyphScanner._resolve_reveal_metadata`.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from ..network.electrumx import script_hash_for_address, script_hash_for_script
from ..security.types import Hex32
from .inspector import GlyphInspector
from .script import (
    extract_owner_pkh_from_ft_script,
    extract_owner_pkh_from_nft_script,
)
from .types import GlyphFt, GlyphNft

if TYPE_CHECKING:
    from ..network.electrumx import ElectrumXClient, UtxoRecord
    from ..transaction.transaction import Transaction
    from .inspector import GlyphOutput
    from .types import GlyphMetadata, GlyphRef

logger = logging.getLogger(__name__)

GlyphItem = GlyphNft | GlyphFt

# Upper bound on how many candidate transactions the scanner will fetch while
# searching a commit output's history for the reveal that spent it. A commit
# script embeds a per-token payload hash, so its script hash is effectively
# unique and its history is normally two entries (the commit, then the
# reveal). The cap bounds the work an adversarially padded history can cause.
_MAX_REVEAL_CANDIDATES = 20


def _input_index_spending(tx: Transaction, ref: GlyphRef) -> int | None:
    """Return the index of the input of *tx* that spends ``ref``, else ``None``.

    Both sides are compared in display (big-endian) txid order:
    ``TransactionInput.from_hex`` reverses the wire bytes on parse, and
    ``GlyphRef.from_bytes`` does the same for the 36-byte script operand.
    """
    want = str(ref.txid).lower()
    for idx, inp in enumerate(tx.inputs):
        source_txid = getattr(inp, "source_txid", None)
        if source_txid is None:
            continue
        if str(source_txid).lower() == want and inp.source_output_index == ref.vout:
            return idx
    return None


def _scriptsig(tx: Transaction, idx: int) -> bytes:
    inp = tx.inputs[idx]
    return inp.unlocking_script.serialize() if inp.unlocking_script else b""


class GlyphScanner:
    """Scan a Radiant address or script_hash for Glyph outputs.

    Parameters
    ----------
    client:
        An *already-connected* ElectrumXClient.  The scanner does not
        own the connection lifecycle; callers should use the client as a
        context manager and pass it in.
    """

    def __init__(self, client: ElectrumXClient) -> None:
        self._client = client
        self._inspector = GlyphInspector()

    async def scan_address(self, address: str) -> list[GlyphItem]:
        """Return all Glyph outputs currently owned at *address*.

        Parameters
        ----------
        address:
            Base58Check-encoded P2PKH address.

        Returns
        -------
        List[GlyphNft | GlyphFt]
            Typed Glyph objects.  ``metadata`` is ``None`` when the reveal
            transaction cannot be located or carries no readable envelope
            (see :meth:`_resolve_reveal_metadata`) — including transfer
            outputs whose commit-output history is unavailable.
        """
        sh = script_hash_for_address(address)
        return await self.scan_script_hash(sh)

    async def scan_script_hash(self, script_hash: Hex32 | bytes | str) -> list[GlyphItem]:
        """Return all Glyph outputs for *script_hash*.

        Fetches UTXOs, raw transactions, and (where available) reveal
        transaction metadata, then constructs typed GlyphNft / GlyphFt
        objects.

        Concurrency: UTXO raw-tx fetches and reveal-metadata resolutions
        both run in parallel via ``asyncio.gather``. Pre-fix (closes
        ultrareview re-review N17) the reveal-metadata path was inside
        the per-utxo loop and serialised one round-trip per glyph; for
        a 100-glyph wallet that meant ~100x the latency of the now-
        batched version. Metadata is resolved once per distinct ref, so
        an FT split across many UTXOs costs one resolution, not N.
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
        # collect every (utxo, glyph, source tx) triple we'd want metadata
        # for. Two-pass split lets us issue all reveal-metadata resolutions
        # as a single gather() instead of one-await-per-glyph; the source tx
        # is kept because it is often the reveal itself.
        pending: list[tuple[UtxoRecord, GlyphOutput, Transaction]] = []
        for utxo, raw in zip(utxos, raw_txs):
            if isinstance(raw, Exception):
                logger.warning("Failed to fetch tx %s: %s", utxo.tx_hash, raw)
                continue

            tx = Transaction.from_hex(bytes(raw))
            if tx is None:
                logger.warning("Failed to parse tx %s", utxo.tx_hash)
                continue

            output_pairs = [(out.satoshis, out.locking_script.serialize()) for out in tx.outputs]
            glyphs = self._inspector.find_glyphs(output_pairs)

            for g in glyphs:
                if g.vout != utxo.tx_pos:
                    continue
                pending.append((utxo, g, tx))

        if not pending:
            return []

        # One reveal-metadata resolution per distinct ref, all batched into a
        # single gather (N17 fix). Where several UTXOs share a ref, prefer a
        # source tx that actually spends the ref outpoint — that tx *is* the
        # reveal, which lets the resolver skip the chain lookup entirely.
        by_ref: dict[tuple[str, int], tuple[GlyphRef, Transaction]] = {}
        for _utxo, g, tx in pending:
            key = (str(g.ref.txid).lower(), g.ref.vout)
            if key not in by_ref or _input_index_spending(tx, g.ref) is not None:
                by_ref[key] = (g.ref, tx)

        keys = list(by_ref)
        resolved = await asyncio.gather(
            *[self._resolve_reveal_metadata(*by_ref[k]) for k in keys],
            return_exceptions=True,
        )
        # _resolve_reveal_metadata catches its own exceptions and returns
        # None — but gather(return_exceptions=True) means a truly unexpected
        # error (TypeError, MemoryError) still surfaces here as an Exception
        # object instead of crashing the whole scan.
        metadata_by_ref: dict[tuple[str, int], GlyphMetadata | None] = {
            k: (None if isinstance(m, BaseException) else m) for k, m in zip(keys, resolved)
        }

        results: list[GlyphItem] = []
        for utxo, g, _tx in pending:
            metadata = metadata_by_ref.get((str(g.ref.txid).lower(), g.ref.vout))
            script = g.script

            try:
                if g.glyph_type == "nft":
                    pkh = extract_owner_pkh_from_nft_script(script)
                    results.append(GlyphNft(ref=g.ref, owner_pkh=pkh, metadata=metadata))
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
                    utxo.tx_hash,
                    utxo.tx_pos,
                    exc,
                )

        return results

    async def _resolve_reveal_metadata(self, ref: GlyphRef, source_tx: Transaction) -> GlyphMetadata | None:
        """Resolve the Glyph metadata for the token identified by *ref*.

        ``ref`` is the token's genesis outpoint, which is the **commit**
        outpoint: :meth:`GlyphBuilder.prepare_reveal` embeds
        ``commit_txid:commit_vout`` into the reveal's locking script, and
        ``extract_ref_from_{nft,ft}_script`` reads it back out. The Glyph CBOR
        envelope is *not* in the commit transaction — a commit's inputs are
        plain funding spends. The envelope lives in the scriptSig of the input
        that **spends** ``ref.txid:ref.vout``, i.e. in the reveal transaction.

        Two resolution paths:

        1. *Fast* — if ``source_tx`` (the tx that produced the UTXO being
           scanned) itself spends ``ref``, then it is the reveal. True for any
           freshly minted, not-yet-transferred glyph. No extra round trip.
        2. *Chain lookup* — otherwise the UTXO came from a transfer, and the
           reveal is some earlier transaction. ElectrumX has no "what spent
           this outpoint?" RPC, so we take the long way round: fetch the
           commit tx, hash its output script, and ask
           ``blockchain.scripthash.get_history`` for the transactions touching
           it. The reveal is the entry (other than the commit itself) with an
           input spending ``ref``.

        Returns ``None`` if the reveal cannot be found or carries no
        recognisable envelope. Never raises — a metadata miss must not lose
        the token itself from the scan result.
        """
        idx = _input_index_spending(source_tx, ref)
        if idx is not None:
            return self._metadata_from_reveal(source_tx, idx)
        try:
            return await self._fetch_reveal_metadata(ref)
        except Exception as exc:  # network/parse failures are non-fatal
            logger.debug("Reveal lookup failed for %s:%d: %s", ref.txid, ref.vout, exc)
            return None

    async def _fetch_reveal_metadata(self, ref: GlyphRef) -> GlyphMetadata | None:
        """Find the tx that spent ``ref`` via commit-output history, and parse it."""
        from ..transaction.transaction import Transaction

        raw_commit = await self._client.get_transaction(ref.txid)
        commit_tx = Transaction.from_hex(bytes(raw_commit))
        if commit_tx is None or ref.vout >= len(commit_tx.outputs):
            return None

        commit_script = commit_tx.outputs[ref.vout].locking_script.serialize()
        history = await self._client.get_history(script_hash_for_script(commit_script))

        candidates = [
            str(entry["tx_hash"]) for entry in history if str(entry.get("tx_hash", "")).lower() != str(ref.txid).lower()
        ]
        if len(candidates) > _MAX_REVEAL_CANDIDATES:
            logger.warning(
                "Commit output %s:%d has %d spending candidates; only the first %d are checked",
                ref.txid,
                ref.vout,
                len(candidates),
                _MAX_REVEAL_CANDIDATES,
            )
        for txid in candidates[:_MAX_REVEAL_CANDIDATES]:
            try:
                raw = await self._client.get_transaction(txid)
            except Exception as exc:
                logger.debug("Could not fetch reveal candidate %s: %s", txid, exc)
                continue
            candidate = Transaction.from_hex(bytes(raw))
            if candidate is None:
                continue
            idx = _input_index_spending(candidate, ref)
            if idx is None:
                continue
            return self._metadata_from_reveal(candidate, idx)
        return None

    def _metadata_from_reveal(self, reveal_tx: Transaction, idx: int) -> GlyphMetadata | None:
        """Extract metadata from the reveal input at *idx*, else from any input.

        The commit script requires the spending input to push ``<CBOR> <"gly">``,
        so the envelope is on the input that spends the commit outpoint. The
        all-inputs fallback covers non-canonical reveals that put it elsewhere.
        """
        metadata = self._inspector.extract_reveal_metadata(_scriptsig(reveal_tx, idx))
        if metadata is not None:
            return metadata
        found = self._inspector.find_reveal_metadata([_scriptsig(reveal_tx, i) for i in range(len(reveal_tx.inputs))])
        return None if found is None else found[1]
