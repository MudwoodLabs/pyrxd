#!/usr/bin/env python3
"""Mint a Glyph NFT on Radiant mainnet with the high-level minter.

Two phases, either run back-to-back or resumed separately:

    commit  →  broadcast the hashlock output, persist the CBOR payload
    reveal  →  spend it, pushing that exact payload

:class:`~pyrxd.glyph.mint.GlyphMinter` owns the parts that used to live in this
file: UTXO selection, sizing the commit so the reveal can pay its own fee,
signing, the pre-broadcast fee guard, and confirmation polling.

The persistence is not optional decoration. The commit output is a hashlock with
no owner-only spend path, so losing the CBOR bytes between the two phases makes
it permanently unspendable — that is why ``JsonFilePendingStore`` is a required
constructor argument rather than a keyword you can forget.

Usage
-----
    GLYPH_WIF=<wif> python examples/glyph_mint_demo.py            # dry run
    DRY_RUN=0 GLYPH_WIF=<wif> python examples/glyph_mint_demo.py  # broadcast

    # Resume the reveal after a crash (the commit is already on-chain):
    DRY_RUN=0 COMMIT_TXID=<txid> GLYPH_WIF=<wif> python examples/glyph_mint_demo.py

Environment
-----------
    GLYPH_WIF     WIF private key for the minting wallet (required)
    DRY_RUN       Set to '0' to broadcast; anything else = dry run (default)
    ELECTRUMX_URL ElectrumX websocket URL (default: radiant4people mainnet)
    STORE_DIR     Where pending mints are kept (default: ~/.pyrxd/pending-mints)
    COMMIT_TXID   Resume: skip the commit and reveal this pending mint
"""

from __future__ import annotations

import asyncio
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from pyrxd.glyph import GlyphMetadata, GlyphProtocol
from pyrxd.glyph.fees import estimate_reveal_fee_for_metadata
from pyrxd.glyph.mint import GlyphMinter, JsonFilePendingStore
from pyrxd.keys import PrivateKey
from pyrxd.network.electrumx import ElectrumXClient, script_hash_for_address

DRY_RUN = os.environ.get("DRY_RUN", "1") != "0"
ELECTRUMX_URL = os.environ.get("ELECTRUMX_URL", "wss://electrumx.radiant4people.com:50022/")
GLYPH_WIF = os.environ.get("GLYPH_WIF", "")
STORE_DIR = os.environ.get("STORE_DIR", os.path.expanduser("~/.pyrxd/pending-mints"))
RESUME_COMMIT_TXID = os.environ.get("COMMIT_TXID", "")


class SingleKeyWallet:
    """The two methods :class:`GlyphMinter` needs, backed by one WIF key.

    A real application passes an :class:`~pyrxd.hd.wallet.HdWallet` here, which
    implements both already. This stand-in exists because the example is driven by a
    single ``GLYPH_WIF``, and it doubles as the spec for the wallet contract: fund the
    commit, and re-derive the reveal's signing key from the funding address.
    """

    def __init__(self, key: PrivateKey) -> None:
        self.key = key
        self.address = key.public_key().address()

    async def collect_spendable(self, client: ElectrumXClient) -> list:
        utxos = await client.get_utxos(script_hash_for_address(self.address))
        return [(u, self.address, self.key) for u in utxos]

    def privkey_for_address(self, address: str) -> PrivateKey:
        if address != self.address:
            raise ValueError(f"unknown address {address}")
        return self.key


async def main() -> None:
    if not GLYPH_WIF:
        sys.exit("ERROR: set GLYPH_WIF to a funded WIF private key")

    wallet = SingleKeyWallet(PrivateKey(GLYPH_WIF))
    store = JsonFilePendingStore(STORE_DIR)
    metadata = GlyphMetadata(
        protocol=[GlyphProtocol.NFT],
        name="pyrxd-sdk-mint-test",
        description="Glyph NFT minted via the pyrxd GlyphMinter facade",
        token_type="sdk-test",
        attrs={"minted_at": str(int(time.time()))},
    )

    print(f"minting from: {wallet.address}")
    print(f"pending store: {store.directory}")
    print(f"NFT name:      {metadata.name}")
    print(f"dry run:       {DRY_RUN}")

    if DRY_RUN:
        # Nothing is broadcast, so show the number that decides whether the mint is
        # affordable: the reveal carries the whole CBOR payload in its scriptSig, so its
        # fee scales with metadata size and is paid out of the commit output.
        estimate = estimate_reveal_fee_for_metadata(metadata)
        print()
        print(f"reveal size:  {estimate.size_bytes:,} bytes ({estimate.cbor_bytes_len:,} bytes of CBOR)")
        print(f"reveal fee:   {estimate.fee:,} photons at {estimate.fee_rate:,}/byte")
        print(f"commit needs: {estimate.required_commit_value(546):,} photons")
        print("\n[DRY RUN] nothing broadcast. Set DRY_RUN=0 to mint.")
        return

    async with ElectrumXClient([ELECTRUMX_URL]) as client:
        minter = GlyphMinter(client, wallet, store)

        if RESUME_COMMIT_TXID:
            pending = store.load(RESUME_COMMIT_TXID)
            print(f"\nresuming pending mint {pending.commit_txid}")
        else:
            pending = await minter.commit_nft(metadata)
            print(f"\ncommit broadcast: {pending.commit_txid}")
            print(f"  commit value:   {pending.commit_value:,} photons")
            print(f"  payload:        {len(pending.cbor_bytes):,} bytes of CBOR, persisted before broadcast")
            print("  waiting for confirmation (this can take 10+ minutes)...")

        result = await minter.reveal_nft(pending)

    print("\n=== NFT minted ===")
    print(f"  commit txid: {result.commit_txid}")
    print(f"  reveal txid: {result.reveal_txid}")
    print(f"  glyph ref:   {result.ref.txid}:{result.ref.vout}   <- permanent token identity")
    print(f"  reveal fee:  {result.reveal_fee:,} photons")
    print(f"  owner:       {wallet.address}")


if __name__ == "__main__":
    asyncio.run(main())
