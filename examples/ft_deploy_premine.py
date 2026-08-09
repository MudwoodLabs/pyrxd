#!/usr/bin/env python3
"""Deploy a plain-FT Glyph token with a full premine on Radiant mainnet.

The canonical "issue your own token" flow, driven by
:class:`~pyrxd.glyph.mint.GlyphMinter`:

    commit_ft  →  broadcast the hashlock output, persist the CBOR payload
    reveal_ft  →  spend it into one FT output carrying the entire supply

The **commit** outpoint becomes the permanent token ref — it is embedded in the
reveal's locking script and is what ``extract_ref_from_ft_script`` reads back.
Radiant convention is 1 photon = 1 FT unit, so ``PREMINE_AMOUNT`` is both the
integer supply and that output's value.

Commit sizing, the pre-broadcast fee guard, signing and confirmation polling all
live in the minter. The one thing worth knowing here: because the whole supply
sits on the reveal's token output, the commit has to cover the supply *plus* the
reveal fee, which is why a large premine needs a correspondingly large UTXO.

Usage
-----
    GLYPH_WIF=<wif> python examples/ft_deploy_premine.py            # dry run
    DRY_RUN=0 GLYPH_WIF=<wif> python examples/ft_deploy_premine.py  # broadcast

    # Resume the reveal after a crash (the commit is already on-chain):
    DRY_RUN=0 COMMIT_TXID=<txid> GLYPH_WIF=<wif> python examples/ft_deploy_premine.py

Environment
-----------
    GLYPH_WIF       WIF private key for the deploying wallet (required)
    DRY_RUN         Set to '0' to broadcast; anything else = dry run (default)
    ELECTRUMX_URL   ElectrumX websocket URL (default: radiant4people mainnet)
    STORE_DIR       Where pending mints are kept (default: ~/.pyrxd/pending-mints)
    COMMIT_TXID     Resume: skip the commit and reveal this pending mint
    TOKEN_NAME      Token name (default: MY-TOKEN)
    TOKEN_TICKER    Ticker, max 16 chars (default: MTK)
    PREMINE_AMOUNT  Integer supply in FT units/photons (default: 1_000_000)
"""

from __future__ import annotations

import asyncio
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from pyrxd.glyph import GlyphMetadata, GlyphProtocol
from pyrxd.glyph.fees import commit_value_for_reveal, estimate_reveal_fee_for_metadata
from pyrxd.glyph.mint import GlyphMinter, JsonFilePendingStore
from pyrxd.keys import PrivateKey
from pyrxd.network.electrumx import ElectrumXClient, script_hash_for_address

DRY_RUN = os.environ.get("DRY_RUN", "1") != "0"
ELECTRUMX_URL = os.environ.get("ELECTRUMX_URL", "wss://electrumx.radiant4people.com:50022/")
GLYPH_WIF = os.environ.get("GLYPH_WIF", "")
STORE_DIR = os.environ.get("STORE_DIR", os.path.expanduser("~/.pyrxd/pending-mints"))
RESUME_COMMIT_TXID = os.environ.get("COMMIT_TXID", "")
TOKEN_NAME = os.environ.get("TOKEN_NAME", "MY-TOKEN")
TOKEN_TICKER = os.environ.get("TOKEN_TICKER", "MTK")
PREMINE_AMOUNT = int(os.environ.get("PREMINE_AMOUNT", "1000000"))


class SingleKeyWallet:
    """The two methods :class:`GlyphMinter` needs, backed by one WIF key.

    A real application passes an :class:`~pyrxd.hd.wallet.HdWallet`, which implements
    both already. This stand-in exists because the example is driven by a single
    ``GLYPH_WIF``, and it doubles as the spec for the wallet contract: fund the commit,
    and re-derive the reveal's signing key from the funding address.
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
        protocol=[GlyphProtocol.FT],
        name=TOKEN_NAME,
        ticker=TOKEN_TICKER,
        description=f"{TOKEN_NAME} — issued via the pyrxd ft_deploy_premine example",
        attrs={"issued_at": str(int(time.time()))},
    )

    print(f"deployer:      {wallet.address}")
    print(f"pending store: {store.directory}")
    print(f"token:         {TOKEN_NAME} ({TOKEN_TICKER})")
    print(f"premine:       {PREMINE_AMOUNT:,} FT units")
    print(f"dry run:       {DRY_RUN}")

    if DRY_RUN:
        # The whole supply rides on the reveal's token output, so the commit must fund
        # the supply AND the reveal fee. Show both before anyone spends anything.
        estimate = estimate_reveal_fee_for_metadata(metadata)
        print()
        print(f"reveal size:  {estimate.size_bytes:,} bytes ({estimate.cbor_bytes_len:,} bytes of CBOR)")
        print(f"reveal fee:   {estimate.fee:,} photons at {estimate.fee_rate:,}/byte")
        print(f"commit value: {commit_value_for_reveal(PREMINE_AMOUNT, estimate):,} photons (supply + fee)")
        print("\n[DRY RUN] nothing broadcast. Set DRY_RUN=0 to deploy.")
        return

    async with ElectrumXClient([ELECTRUMX_URL]) as client:
        minter = GlyphMinter(client, wallet, store)

        if RESUME_COMMIT_TXID:
            pending = store.load(RESUME_COMMIT_TXID)
            print(f"\nresuming pending deploy {pending.commit_txid}")
        else:
            pending = await minter.commit_ft(metadata, supply=PREMINE_AMOUNT)
            print(f"\ncommit broadcast: {pending.commit_txid}")
            print(f"  commit value:   {pending.commit_value:,} photons")
            print(f"  payload:        {len(pending.cbor_bytes):,} bytes of CBOR, persisted before broadcast")
            print("  waiting for confirmation (this can take 10+ minutes)...")

        result = await minter.reveal_ft(pending)

    print("\n=== FT token deployed ===")
    print(f"  token:       {TOKEN_NAME} ({TOKEN_TICKER})")
    print(f"  supply:      {result.carrier_value:,} FT units")
    print(f"  token ref:   {result.ref.txid}:{result.ref.vout}   <- permanent token identity")
    print(f"  reveal txid: {result.reveal_txid}")
    print(f"  reveal fee:  {result.reveal_fee:,} photons")
    print(f"  owner:       {wallet.address}")


if __name__ == "__main__":
    asyncio.run(main())
