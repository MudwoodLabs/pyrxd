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
from collections.abc import Callable, Sequence
from typing import TYPE_CHECKING

from ..network.electrumx import _coerce_hex32, script_hash_for_output, script_hash_for_script
from ..security.errors import NetworkError, ServerInconsistencyError
from ..security.types import Hex20, Hex32
from ..utils import address_to_public_key_hash
from .inspector import GlyphInspector
from .script import (
    build_authority_gated_nft_script,
    build_delegate_token_script,
    build_ft_locking_script,
    build_nft_locking_script,
    extract_owner_pkh_from_ft_script,
    extract_owner_pkh_from_nft_script,
)
from .types import GlyphFt, GlyphNft, GlyphRef

if TYPE_CHECKING:
    from ..network.electrumx import ElectrumXClient, UtxoRecord
    from ..transaction.transaction import Transaction
    from .inspector import GlyphOutput
    from .types import GlyphMetadata

logger = logging.getLogger(__name__)

GlyphItem = GlyphNft | GlyphFt

# Any two distinct refs will do: the server zeroes refs before hashing (see
# ``script_hash_for_output``), so the hash of each shape below depends on the owner alone.
_REF_A = GlyphRef.from_bytes(b"\x01" * 36)
_REF_B = GlyphRef.from_bytes(b"\x02" * 36)

#: Every output shape ``GlyphInspector.find_glyphs`` reports with an owner, keyed by its
#: ``glyph_type``, as a builder of that shape for a given owner. A Radiant ElectrumX lists an
#: owner's outputs of one shape under one script hash, and it is NOT the owner's P2PKH hash, so
#: these are the hashes :meth:`GlyphScanner.scan_address` reads. ``mut`` and ``dmint`` outputs
#: have no owner key and are never returned as holdings, so they have no entry.
#: ``tests/test_glyph_scanner.py`` checks this set against the types ``find_glyphs`` emits.
OWNED_TOKEN_SHAPES: dict[str, Callable[[Hex20], bytes]] = {
    "nft": lambda pkh: build_nft_locking_script(pkh, _REF_A),
    "ft": lambda pkh: build_ft_locking_script(pkh, _REF_A),
    "authority-gated-nft": lambda pkh: build_authority_gated_nft_script(pkh, _REF_A, _REF_B),
    "delegate-token": lambda pkh: build_delegate_token_script(pkh, _REF_A),
    # The dead pre-0.15.0 shape has no builder: OP_PUSHINPUTREF <container> + the NFT singleton.
    "container-legacy": lambda pkh: b"\xd0" + _REF_B.to_bytes() + build_nft_locking_script(pkh, _REF_A),
}


def owned_token_script_hashes(owner_pkh: Hex20) -> tuple[Hex32, ...]:
    """The script hashes a Radiant ElectrumX lists *owner_pkh*'s token outputs under, one per shape."""
    return tuple(script_hash_for_output(build(owner_pkh)) for build in OWNED_TOKEN_SHAPES.values())


def _server_inconsistency(strict: bool, what: str) -> None:
    """Refuse a listing the server's own transaction contradicts: raise under *strict*, else log."""
    if strict:
        raise ServerInconsistencyError(
            f"server inconsistency: {what}. Refusing to list it, or to show this address's inventory as complete"
        )
    logger.warning("Server inconsistency: %s; left out of the result", what)


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

    async def scan_address(self, address: str, *, strict: bool = False) -> list[GlyphItem]:
        """Return all Glyph outputs currently owned at *address*.

        Reads the script hashes the address's token outputs are listed under
        (:func:`owned_token_script_hashes`), not its P2PKH hash: a Radiant
        ElectrumX lists a token output under its script with the refs zeroed,
        so the P2PKH hash lists the address's plain outputs only. A token the
        server lists here whose owner is not *address*'s key is refused as a
        server inconsistency, not returned.

        Parameters
        ----------
        address:
            Base58Check-encoded P2PKH address.
        strict:
            See :meth:`scan_script_hash`.

        Returns
        -------
        List[GlyphNft | GlyphFt]
            Typed Glyph objects.  ``metadata`` is ``None`` when the reveal
            transaction cannot be located or carries no readable envelope
            (see :meth:`_resolve_reveal_metadata`) — including transfer
            outputs whose commit-output history is unavailable.
        """
        owner = Hex20(address_to_public_key_hash(address))
        return await self._scan(owned_token_script_hashes(owner), owner_pkh=owner, strict=strict)

    async def scan_script_hash(self, script_hash: Hex32 | bytes | str, *, strict: bool = False) -> list[GlyphItem]:
        """Return all Glyph outputs for *script_hash*.

        Fetches UTXOs, raw transactions, and (where available) reveal
        transaction metadata, then constructs typed GlyphNft / GlyphFt
        objects.

        What the server says is checked against the transaction it serves,
        which ``get_transaction`` binds to the txid. A UTXO whose output is not
        at *script_hash* (or does not exist), or is listed twice, is a server
        inconsistency, and so is a token whose owner is not the address
        :meth:`scan_address` was asked about. An FT's amount is the output's
        value in that transaction, never the server's ``value``.

        A UTXO whose raw transaction cannot be fetched or parsed, or that is a
        server inconsistency, is logged and left out by default. For a failed
        read the result is then a lower bound on what the script hash holds;
        an inconsistent item was never shown to be held here. ``strict=True``
        raises :class:`NetworkError` instead; use it when the result is shown
        as everything held (``pyrxd glyph list`` does). A metadata lookup that
        fails does not count: it leaves the token in the result with
        ``metadata=None``.

        Concurrency: UTXO raw-tx fetches and reveal-metadata resolutions
        both run in parallel via ``asyncio.gather``. Pre-fix (closes
        ultrareview re-review N17) the reveal-metadata path was inside
        the per-utxo loop and serialised one round-trip per glyph; for
        a 100-glyph wallet that meant ~100x the latency of the now-
        batched version. Metadata is resolved once per distinct ref, so
        an FT split across many UTXOs costs one resolution, not N.
        """
        return await self._scan((_coerce_hex32(script_hash),), owner_pkh=None, strict=strict)

    async def _scan(self, script_hashes: Sequence[Hex32], *, owner_pkh: Hex20 | None, strict: bool) -> list[GlyphItem]:
        from ..transaction.transaction import Transaction

        listings = await asyncio.gather(*[self._client.get_utxos(sh) for sh in script_hashes])
        # Each UTXO with the script hash it was listed under, once per outpoint: a
        # server that lists an FT outpoint twice would otherwise count it twice.
        listed: list[tuple[UtxoRecord, bytes]] = []
        seen: set[tuple[str, int]] = set()
        for script_hash, utxos in zip(script_hashes, listings):
            for utxo in utxos:
                key = (str(utxo.tx_hash).lower(), utxo.tx_pos)
                if key in seen:
                    _server_inconsistency(strict, f"{utxo.tx_hash}:{utxo.tx_pos} is listed more than once")
                    continue
                seen.add(key)
                listed.append((utxo, bytes(script_hash)))
        if not listed:
            return []

        # Fetch all UTXO raw txs concurrently.
        raw_txs = await asyncio.gather(
            *[self._client.get_transaction(utxo.tx_hash) for utxo, _sh in listed],
            return_exceptions=True,
        )
        failed = [raw for raw in raw_txs if isinstance(raw, Exception)]
        if strict and failed:
            raise NetworkError(
                f"{len(failed)} of {len(listed)} transaction reads failed for this address's outputs; "
                "refusing to return an inventory that leaves them out"
            ) from failed[0]

        # First pass: parse each UTXO's source tx, check it against the listing,
        # run the glyph inspector, and collect every (utxo, glyph, source tx)
        # triple we'd want metadata for. Two-pass split lets us issue all
        # reveal-metadata resolutions as a single gather() instead of
        # one-await-per-glyph; the source tx is kept because it is often the
        # reveal itself, and because its output is where an FT's amount is read.
        pending: list[tuple[UtxoRecord, GlyphOutput, Transaction]] = []
        for (utxo, listed_under), raw in zip(listed, raw_txs):
            if isinstance(raw, Exception):
                logger.warning("Failed to fetch tx %s: %s", utxo.tx_hash, raw)
                continue

            tx = Transaction.from_hex(bytes(raw))
            if tx is None:
                if strict:
                    raise NetworkError(
                        f"transaction {utxo.tx_hash} was fetched but does not parse; "
                        "refusing to return an inventory that leaves it out"
                    )
                logger.warning("Failed to parse tx %s", utxo.tx_hash)
                continue

            outpoint = f"{utxo.tx_hash}:{utxo.tx_pos}"
            if utxo.tx_pos >= len(tx.outputs):
                _server_inconsistency(
                    strict, f"{outpoint} is listed, but that transaction has {len(tx.outputs)} output(s)"
                )
                continue
            output = tx.outputs[utxo.tx_pos]
            script = output.locking_script.serialize()

            output_pairs = [(out.satoshis, out.locking_script.serialize()) for out in tx.outputs]
            g = next((g for g in self._inspector.find_glyphs(output_pairs) if g.vout == utxo.tx_pos), None)

            # The owner first, so that a foreign token is named as one. The script-hash check
            # below refuses it too when scanning an address, since each hash read there binds
            # the owner; this one says why.
            if owner_pkh is not None and g is not None and g.owner_pkh is not None and g.owner_pkh != owner_pkh:
                _server_inconsistency(
                    strict,
                    f"{outpoint} is listed under this address, but that {g.glyph_type} output is owned by "
                    f"another key ({g.owner_pkh.hex()}, not {owner_pkh.hex()})",
                )
                continue
            # A server can list any outpoint. Plain ElectrumX hashes the script as it is, a
            # Radiant one with its refs zeroed; an output at neither is not at this hash.
            if listed_under not in (bytes(script_hash_for_output(script)), bytes(script_hash_for_script(script))):
                _server_inconsistency(
                    strict, f"{outpoint} is listed under script hash {listed_under.hex()}, but its output is not there"
                )
                continue
            if utxo.value != output.satoshis:
                logger.warning(
                    "Server reports %s as %d photons, but the transaction pays %d; using the transaction",
                    outpoint,
                    utxo.value,
                    output.satoshis,
                )

            if g is None:
                continue
            if not g.spendable:
                # A pre-0.15.0 container-with-child-ref output. It is not a
                # transferable token, so it must not come back as a GlyphNft
                # — but staying silent would leave the holder wondering
                # where their carrier photons went.
                logger.warning(
                    "Skipping unspendable %s output at %s:%d (container ref %s:%d, child ref %s:%d) — "
                    "see pyrxd.glyph.script.is_legacy_container_script",
                    g.glyph_type,
                    utxo.tx_hash,
                    utxo.tx_pos,
                    g.ref.txid,
                    g.ref.vout,
                    g.child_ref.txid if g.child_ref else "?",
                    g.child_ref.vout if g.child_ref else -1,
                )
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
        for utxo, g, tx in pending:
            metadata = metadata_by_ref.get((str(g.ref.txid).lower(), g.ref.vout))
            script = g.script

            try:
                if g.glyph_type == "nft":
                    pkh = extract_owner_pkh_from_nft_script(script)
                    results.append(GlyphNft(ref=g.ref, owner_pkh=pkh, metadata=metadata))
                elif g.glyph_type == "authority-gated-nft":
                    # A gated item IS an NFT its holder owns — same singleton ref,
                    # spendable, transferable (to a plain NFT script; keeping the
                    # gate needs the issuer). Returning it is the point: without
                    # this branch it fell through the dispatch below and vanished
                    # from holdings, exactly as it vanished from `find_glyphs`
                    # before that was fixed.
                    #
                    # `g.owner_pkh`, NOT `extract_owner_pkh_from_nft_script`: the
                    # gated script is 101 bytes with the pkh at a different offset,
                    # so the plain-NFT extractor would refuse it.
                    if g.owner_pkh is None:  # pragma: no cover - set by find_glyphs
                        raise ValueError("authority-gated output has no owner pkh")
                    results.append(GlyphNft(ref=g.ref, owner_pkh=g.owner_pkh, metadata=metadata))
                elif g.glyph_type == "delegate-token":
                    # NOT a GlyphNft — it is a mint authorisation, not a
                    # collectible, and handing it back as an NFT would invite a
                    # holder to transfer it like one. But it must not be SILENT
                    # either: they authorise mints against the base, so a holder
                    # counting them needs to know they are there.
                    logger.info(
                        "Holding a delegate token at %s:%d (base ref %s:%d) — a mint authorisation, "
                        "not a transferable token; it is not returned as a GlyphNft",
                        utxo.tx_hash,
                        utxo.tx_pos,
                        g.ref.txid,
                        g.ref.vout,
                    )
                elif g.glyph_type == "ft":
                    pkh = extract_owner_pkh_from_ft_script(script)
                    results.append(
                        GlyphFt(
                            ref=g.ref,
                            owner_pkh=pkh,
                            # From the transaction `get_transaction` bound to its txid,
                            # not the server's UTXO record: on Radiant an FT output's value
                            # IS its token amount, and the record is only the server's word.
                            amount=tx.outputs[utxo.tx_pos].satoshis,
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

    async def fetch_metadata(self, ref: GlyphRef) -> GlyphMetadata | None:
        """The mint envelope for ``ref``, read off the chain. ``None`` if it cannot be found.

        Public because a caller may want a token's own metadata without wanting its holder's
        whole inventory — ``pyrxd glyph timelock-reveal`` needs exactly this, and needs it
        from the CHAIN rather than from the operator: a CEK checked against a commitment the
        operator supplied proves only that they typed two matching things.

        Walks commit-output history to find the reveal that carried the envelope; see the
        module docstring for why ``ref.txid`` alone is not enough.
        """
        return await self._fetch_reveal_metadata(ref)

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
