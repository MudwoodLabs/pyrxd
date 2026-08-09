#!/usr/bin/env python3
"""Mint your first Glyph NFT on a local regtest chain — zero config.

Companion script for the 5-minute quickstart (``docs/tutorials/quickstart.md``).
It assumes a regtest node is already running::

    pyrxd regtest up

then mints a Glyph NFT end-to-end against it.

The mint itself is three lines, because :class:`~pyrxd.glyph.mint.GlyphMinter`
does it — the same code path ``examples/glyph_mint_demo.py`` uses on mainnet.
What is local to this file is only the *transport*: the minter is duck-typed on
its client and wallet, so the two small adapters below teach it to talk to
``pyrxd regtest`` instead of ElectrumX. That is the interesting part of this
example, and it is the only part.

    python examples/regtest_quickstart.py
"""

from __future__ import annotations

import asyncio
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from pyrxd.devnet import DevnetError, RegtestNode
from pyrxd.glyph import GlyphMetadata, GlyphProtocol
from pyrxd.glyph.mint import GlyphMinter, JsonFilePendingStore
from pyrxd.keys import PrivateKey
from pyrxd.network.electrumx import UtxoRecord

# Enough to cover the commit value the minter computes plus its fee. The minter
# refuses (before broadcasting anything) if the UTXO it finds is too small, so this
# only needs to be comfortably large.
NEED_PHOTONS = 20_000_000


class RegtestClient:
    """The client half of the minter's contract, over ``pyrxd regtest``.

    Two methods: broadcast a transaction, and report a transaction's confirmation
    depth. :func:`~pyrxd.network.confirm.wait_for_confirmation` polls the second one.
    """

    def __init__(self, node: RegtestNode) -> None:
        self.node = node

    async def broadcast(self, raw_tx: bytes) -> str:
        txid = str(self.node.cli("sendrawtransaction", raw_tx.hex()))
        # Regtest mines on demand — nothing else will produce a block, so the minter
        # would poll for a confirmation that never arrives. Mainnet transports do not
        # do this; the node does.
        self.node.mine(1)
        return txid

    async def get_transaction_verbose(self, txid: str) -> dict:
        result = self.node.cli("getrawtransaction", str(txid), "1")
        return result if isinstance(result, dict) else {}


class RegtestWallet:
    """The wallet half: fund a mint, and re-derive the reveal's signing key.

    Backed by the node's own dev wallet, so ``pyrxd regtest up`` is the only setup.
    """

    def __init__(self, node: RegtestNode) -> None:
        self.node = node

    async def collect_spendable(self, client: RegtestClient) -> list:
        unspent = self.node.cli("listunspent", "1", "9999999", wallet=True)
        if not isinstance(unspent, list):
            raise DevnetError("could not list regtest UTXOs")
        triples = []
        for u in unspent:
            value = round(u["amount"] * 1e8)
            utxo = UtxoRecord(tx_hash=u["txid"], tx_pos=u["vout"], value=value, height=1)
            triples.append((utxo, u["address"], self.privkey_for_address(u["address"])))
        return triples

    def privkey_for_address(self, address: str) -> PrivateKey:
        return PrivateKey(str(self.node.cli("dumpprivkey", address, wallet=True)))


async def main() -> None:
    node = RegtestNode()
    if not node.is_running():
        sys.exit("regtest node is not running. Start it first:\n    pyrxd regtest up")

    wallet = RegtestWallet(node)
    if not any(u.value >= NEED_PHOTONS for u, _, _ in await wallet.collect_spendable(RegtestClient(node))):
        sys.exit(f"no UTXO with at least {NEED_PHOTONS:,} photons — try `pyrxd regtest mine 10`")

    # The pending store is required, not optional: the commit output is a hashlock, so
    # losing its CBOR payload before the reveal would strand it permanently. On regtest
    # that costs nothing, but the API does not have a cheap mode — the habit is the point.
    store = JsonFilePendingStore(os.path.join(os.path.dirname(__file__), ".pending-mints"))
    minter = GlyphMinter(RegtestClient(node), wallet, store)

    metadata = GlyphMetadata(
        protocol=[GlyphProtocol.NFT],
        name="my-first-glyph",
        description="Minted on regtest via the pyrxd quickstart",
        token_type="quickstart",
        attrs={"minted_at": str(int(time.time()))},
    )

    pending = await minter.commit_nft(metadata)
    print(f"minting from {pending.funding_address}")
    print(f"commit:  {pending.commit_txid}  ({pending.commit_value:,} photons, confirmed)")
    result = await minter.reveal_nft(pending)
    print(f"reveal:  {result.reveal_txid}  (NFT carrier {result.carrier_value:,} photons, confirmed)")

    print()
    print("NFT minted on regtest.")
    print(f"  genesis ref: {result.ref.txid}:{result.ref.vout}   <- this is the token's permanent identity")
    print(f"  owner:       {pending.funding_address}")
    print()
    print("inspect it on the node:")
    print("  pyrxd regtest info")
    print(
        f"  docker exec {RegtestNode.CONTAINER} radiant-cli -regtest -rpcuser={RegtestNode.RPC_USER} "
        f"-rpcpassword={RegtestNode.RPC_PASSWORD} getrawtransaction {result.reveal_txid} 1"
    )


if __name__ == "__main__":
    asyncio.run(main())
