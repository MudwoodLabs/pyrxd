"""Discover a mutable glyph's spend chain FROM THE CHAIN, one output at a time.

WHY THIS EXISTS. :func:`~pyrxd.glyph.mutable_chain.walk_mutable_chain` verifies a candidate set;
it does not produce one. The plan that built it assumed an index would supply the candidates, and
pyrxd has no index method that does — ``RxinDexerClient`` returns a token record, not a history.
So §7.6 form 2 was reachable only by a consumer with their own index, and the CLI could not wire it
without faking a caller that always degraded.

The chain can supply its own candidates. Every mutable output has a locking script; ElectrumX
indexes every output by the hash of that script; that scripthash's history is the transaction that
CREATED the output and the transaction that SPENT it. Follow the spender's mutable output and ask
again. Measured on Radiant mainnet 2026-09-16 for ``custodian-gate-x7f3.rxd`` against
``wss://electrumx.radiant4people.com:50022`` (tip 464826)::

    hop 0  f644794b:1  history=[f644794b@458585, 315b4630@458591]  unspent=[]
    hop 1  315b4630:1  history=[315b4630@458591, 3c7b43df@458601]  unspent=[]
    hop 2  3c7b43df:1  history=[3c7b43df@458601]                   unspent=[3c7b43df:1]
    -> 3 hops, 6 fetches, 2.8 s

Two things that measurement settled which the plan had only guessed at:

* The sibling ``2cee4847`` — in the NAME's index history, same block as a real update, never
  touching the token — does not appear at all. A mutable output's scripthash history holds the
  transactions that touch THAT OUTPUT, so discovery by scripthash is narrower than discovery by
  name, and the walker's ``excluded`` list is normally empty.
* Block heights ride along with every history entry — exactly the ``step_heights`` input
  ``judge_name_at_mark`` needs, which nothing else was supplying.

WHAT THIS DOES NOT DO. It decides nothing. The candidate set and the heights are returned to be
handed to ``walk_mutable_chain``, which re-verifies every spend link and the ref continuity, and
to ``judge_name_at_mark``, which enforces the source rules. Discovery is the hint; the walk is the
proof. The spend check performed here exists only to know which output to ask about next.

TWO SOURCES, STILL. ``walk_mutable_chain`` refuses ``complete=True`` when the candidates and the
tip proof came from one source, because one endpoint that omits the latest update AND certifies the
earlier tip produces a stale record with an empty reason. Discovering from the chain does not
change that: a scripthash history is still one server's claim about which transactions exist.
:func:`walk_discovered_chain` therefore takes a DISCOVERY client and a TIP client and labels them.
Handing it the same endpoint twice is allowed and degrades honestly — which is what a single-server
configuration should do, and is what the shipped default configuration is.

WHAT IS AND IS NOT A SERVER CLAIM HERE. Every transaction is fetched txid-bound (the bytes must hash
to the txid asked for), so the CONTENT of a transaction cannot be forged by either server. What a
server can lie about is EXISTENCE — which transactions are in a history — and SPENTNESS. The
two-source rule covers exactly those two, and nothing else needs covering.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Any

from pyrxd.security.errors import ValidationError

from .inspector import GlyphInspector
from .mutable_chain import MAX_CHAIN_STEPS, MutableChainWalk, _mut_output_for, walk_mutable_chain

#: Bound on transaction fetches across a whole discovery, following ``swap/rswp/tracker.py``'s
#: ``_MAX_HISTORY_FETCHES``: a hostile server can pad a scripthash history with confirmed-looking
#: entries that each cost a fetch. Hitting it is REPORTED (``capped=True``); the walker then sees a
#: prefix and cannot prove the tip, so the verdict degrades rather than truncating silently.
MAX_DISCOVERY_FETCHES = 256


def _outputs(tx: Any) -> list[tuple[int, bytes]]:
    return [(o.satoshis, bytes(o.locking_script.serialize())) for o in tx.outputs]


async def _fetch_bound(client: Any, txid: str) -> Any:
    """Fetch and parse ``txid``, refusing bytes that do not hash to it.

    The same check as ``swap/resolve.fetch_transaction``, re-stated here rather than imported so
    ``glyph`` does not depend on ``swap``. It is what makes the source of the bytes irrelevant.
    """
    from pyrxd.security.types import Txid
    from pyrxd.transaction.transaction import Transaction

    wanted = Txid(str(txid).lower())
    raw = await client.get_transaction(wanted)
    tx = Transaction.from_hex(bytes(raw))
    if tx is None:
        raise ValidationError(f"could not parse the transaction returned for {wanted}")
    if tx.txid() != str(wanted):
        raise ValidationError(f"server returned a transaction whose hash != requested txid ({wanted})")
    return tx


def cached_fetcher(client: Any) -> Callable[[str], Awaitable[Any]]:
    """A txid-bound ``fetch_tx`` that fetches each transaction at most once.

    ``walk_mutable_chain`` caches within one call; discovery and the walk are two calls over the
    same transactions, so the cache lives here and is handed to both.
    """
    seen: dict[str, Any] = {}

    async def fetch(txid: str) -> Any:
        key = str(txid).lower()
        if key not in seen:
            seen[key] = await _fetch_bound(client, key)
        return seen[key]

    return fetch


@dataclass(frozen=True)
class ChainDiscovery:
    """What one server said about which transactions touch this token's mutable outputs."""

    mint_txid: str
    #: Every transaction that appeared in any hop's scripthash history, other than the mint.
    #: A HINT for the walker, which decides membership itself.
    candidates: tuple[str, ...]
    #: txid -> block height, CONFIRMED entries only (ElectrumX reports 0 / -1 for mempool). The
    #: mint is included. An unconfirmed step is simply absent, and ``judge_name_at_mark`` treats
    #: an absent height as "cannot be placed" unless it is already known to be after the mark.
    heights: Mapping[str, int]
    #: Mutable outputs followed. Two hops means three chain steps.
    hops: int
    fetches: int
    #: ``MAX_DISCOVERY_FETCHES`` was hit. The candidate set is then a PREFIX and must not be read
    #: as the whole history; the walker's tip proof will fail on it, which is the point.
    capped: bool
    #: Why discovery stopped. Descriptive, for a human; the walker does not read it.
    stopped: str
    source: str


async def discover_mutable_chain(
    client: Any,
    mint_txid: str,
    *,
    source: str,
    fetch_tx: Callable[[str], Awaitable[Any]] | None = None,
    max_steps: int = MAX_CHAIN_STEPS,
    max_fetches: int = MAX_DISCOVERY_FETCHES,
) -> ChainDiscovery:
    """Follow the mutable output's scripthash history hop by hop and collect what it names.

    ``client`` needs ``get_transaction`` and ``get_history``. ``source`` labels it; the walker
    compares that label against the tip proof's.

    :raises ValidationError: when a server returns bytes that do not hash to the txid asked for.
        That is a lying or broken server, not a missing transaction, and it must not be
        swallowed into "the chain ends here".
    """
    from pyrxd.network.electrumx import script_hash_for_script

    if not isinstance(max_fetches, int) or isinstance(max_fetches, bool) or max_fetches < 1:
        raise ValidationError(f"max_fetches must be an int >= 1, got {max_fetches!r}")

    fetch = fetch_tx or cached_fetcher(client)
    inspector = GlyphInspector()
    fetches = 0

    async def _fetch(txid: str) -> Any:
        nonlocal fetches
        fetches += 1
        return await fetch(txid)

    mint_txid = mint_txid.lower()
    mint = await _fetch(mint_txid)
    found = _mut_output_for(inspector, _outputs(mint), None)
    candidates: list[str] = []
    heights: dict[str, int] = {}
    if found is None:
        return ChainDiscovery(
            mint_txid=mint_txid,
            candidates=(),
            heights={},
            hops=0,
            fetches=fetches,
            capped=False,
            stopped=f"{mint_txid} has no mutable output — nothing to follow",
            source=source,
        )
    cur_vout, ref, _payload_hash = found
    cur_txid = mint_txid
    cur_tx = mint

    hops = 0
    stopped = ""
    capped = False
    while True:
        script = bytes(cur_tx.outputs[cur_vout].locking_script.serialize())
        history = await client.get_history(script_hash_for_script(script))
        # Heights for EVERY entry, including the creator of this output (the mint on hop 0).
        # ElectrumX reports 0 or -1 for an unconfirmed transaction; those are left out rather
        # than stored as a height that would place them at the genesis block.
        for entry in history:
            txid = str(entry["tx_hash"]).lower()
            height = entry.get("height")
            if isinstance(height, int) and not isinstance(height, bool) and height > 0:
                heights.setdefault(txid, height)
            if txid != mint_txid and txid not in candidates:
                candidates.append(txid)

        if hops >= max_steps:
            stopped = f"stopped at the {max_steps}-hop cap — the chain may continue"
            break

        # Which entry SPENDS the current mutable output? A scripthash history also lists the
        # transaction that created the output (this one), and can list transactions that merely
        # pay to the same script. Only a spender advances the walk. This check is enough to
        # choose the next output to ask about; the walker re-does it with the ref check.
        spenders = []
        for entry in history:
            txid = str(entry["tx_hash"]).lower()
            if txid == cur_txid:
                continue
            if fetches >= max_fetches:
                capped = True
                break
            tx = await _fetch(txid)
            if any(
                str(getattr(i, "source_txid", "")).lower() == cur_txid and i.source_output_index == cur_vout
                for i in tx.inputs
            ):
                spenders.append((txid, tx))
        if capped:
            stopped = f"stopped at the {max_fetches}-fetch cap — the candidate set is a prefix"
            break
        if not spenders:
            stopped = "the current mutable output has no spender in history — this is the tip"
            break
        if len(spenders) > 1:
            # Two claimants for one outpoint. Consensus forbids it, so this is either a reorg
            # being read mid-flight or a server inventing a spend. Not resolvable here; the walker
            # reports the ambiguity and the verdict degrades. Both stay in the candidate set.
            stopped = f"{len(spenders)} transactions in history claim to spend {cur_txid}:{cur_vout}"
            break
        nxt_txid, nxt_tx = spenders[0]
        nxt = _mut_output_for(inspector, _outputs(nxt_tx), ref)
        if nxt is None:
            stopped = f"{nxt_txid} spends the mutable output and carries none for {ref} — the chain ends"
            break
        cur_txid, cur_tx, cur_vout = nxt_txid, nxt_tx, nxt[0]
        hops += 1

    return ChainDiscovery(
        mint_txid=mint_txid,
        candidates=tuple(candidates),
        heights=heights,
        hops=hops,
        fetches=fetches,
        capped=capped,
        stopped=stopped,
        source=source,
    )


def electrumx_tip_prover(
    client: Any, *, fetch_tx: Callable[[str], Awaitable[Any]]
) -> Callable[[str, int], Awaitable[bool | None]]:
    """An ``is_unspent(txid, vout)`` backed by ``blockchain.scripthash.listunspent``.

    ``True`` = that outpoint is in the script's unspent set; ``False`` = it is not; ``None`` =
    the server could not answer, which the walker reports as "the source could not say" rather
    than as either. The transaction whose output is checked is fetched txid-BOUND through
    ``fetch_tx``, so it does not matter which server the bytes came from — only the unspent
    claim is this server's.
    """
    from pyrxd.network.electrumx import script_hash_for_script
    from pyrxd.security.errors import NetworkError

    async def is_unspent(txid: str, vout: int) -> bool | None:
        try:
            tx = await fetch_tx(txid)
            script = bytes(tx.outputs[vout].locking_script.serialize())
            utxos = await client.get_utxos(script_hash_for_script(script))
        except (NetworkError, IndexError):
            return None
        want = str(txid).lower()
        return any(str(u.tx_hash).lower() == want and int(u.tx_pos) == int(vout) for u in utxos)

    return is_unspent


@dataclass(frozen=True)
class DiscoveredWalk:
    walk: MutableChainWalk
    discovery: ChainDiscovery


async def walk_discovered_chain(
    *,
    mint_txid: str,
    discovery_client: Any,
    tip_client: Any,
    discovery_source: str,
    tip_source: str,
    max_steps: int = MAX_CHAIN_STEPS,
    max_fetches: int = MAX_DISCOVERY_FETCHES,
) -> DiscoveredWalk:
    """Discover from one server, prove the tip on another, and walk.

    The two clients MAY be the same endpoint. The walk then reports ``complete=False`` with the
    source-conflict reason, because that is the truth of a single-server configuration: it cannot
    prove the history is whole. Give the two labels different values only when the endpoints
    really are different.
    """
    fetch = cached_fetcher(discovery_client)
    discovery = await discover_mutable_chain(
        discovery_client,
        mint_txid,
        source=discovery_source,
        fetch_tx=fetch,
        max_steps=max_steps,
        max_fetches=max_fetches,
    )
    walk = await walk_mutable_chain(
        mint_txid=discovery.mint_txid,
        candidates=discovery.candidates,
        fetch_tx=fetch,
        is_unspent=electrumx_tip_prover(tip_client, fetch_tx=fetch),
        candidate_source=discovery_source,
        tip_source=tip_source,
        max_steps=max_steps,
    )
    return DiscoveredWalk(walk=walk, discovery=discovery)


__all__ = [
    "MAX_DISCOVERY_FETCHES",
    "ChainDiscovery",
    "DiscoveredWalk",
    "cached_fetcher",
    "discover_mutable_chain",
    "electrumx_tip_prover",
    "walk_discovered_chain",
]
