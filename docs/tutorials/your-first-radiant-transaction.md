# Your first Radiant transaction

You have just run `pip install pyrxd`. By the end of this page you
will have created an HD wallet, derived a receive address, scanned
the chain for spendable UTXOs, and built and signed a plain RXD
send transaction. Broadcast is gated behind explicit env-var
guards — you can complete the whole walkthrough without touching
mainnet, then flip one switch when you are ready.

This is a tutorial, not a reference. It tells you what to type and
what you should see. If you want the *why* — the 75-byte FT
script layout, why the dust threshold is 546 photons, what the
gap-limit scan actually does — those questions live on the
[concept pages](../concepts/index.md). Come back here when you
want to learn the next thing by doing it.

## What you will build

A confirmed, signed transaction sending `100_000` photons
(`0.001 RXD`) from a freshly created HD wallet to an address you
choose. The default path keeps the wallet empty — when you get to
"Step 5" you will see "no UTXOs" and the tutorial tells you how to
fund it. The signing and broadcast steps work the same whether the
wallet holds one UTXO or a hundred.

You will use:

- `pyrxd wallet new` — generate a BIP39 mnemonic + HD wallet file.
- `pyrxd address` — derive the next receive address.
- `pyrxd balance --refresh` — scan the chain for funded addresses.
- `pyrxd utxos` — list the spendable outputs.
- A short Python script — build, sign, and (optionally)
  broadcast the transaction. There is no `pyrxd send` CLI in
  0.5.0; sends drop into Python.

## Prerequisites

```shell
$ pip install pyrxd
$ pyrxd --version
pyrxd, version 0.5.0
```

You also need:

- A reachable ElectrumX server. The built-in default
  (`wss://electrumx.radiant4people.com:50022/`) works for mainnet
  out of the box. If you want to override it, set
  `PYRXD_ELECTRUMX` or pass `--electrumx URL` on every command.
- A Radiant address to send to. If you don't have one yet,
  create a second wallet at a different path
  (`--wallet ~/.pyrxd/wallet2.dat`) and use its address as the
  destination.

## Step 1 — Check your install

```shell
$ pyrxd setup
```

You should see something like:

```
pyrxd setup status:
  config:    /home/you/.pyrxd/config.toml (written with defaults)
  node:      127.0.0.1:7332 NOT reachable
  electrumx: wss://electrumx.radiant4people.com:50022/ reachable
  wallet:    /home/you/.pyrxd/wallet.dat (missing)

Next steps:
  1. create a wallet:  pyrxd wallet new
```

The `node NOT reachable` line is fine — you don't need a local
Radiant Core node for this tutorial. The `electrumx reachable`
line is the one that matters. If you see "NOT reachable" there,
fix it before continuing — every later step talks to ElectrumX.

## Step 2 — Create a wallet

```shell
$ pyrxd wallet new
```

`pyrxd` will print a 12-word BIP39 mnemonic, wait for you to press
Enter (so you can write it down on paper), then save an encrypted
wallet file to `~/.pyrxd/wallet.dat`. The output looks like:

```
┌────────────────────────────────────────────────────────────┐
│  abandon  ability  able     about    above    absent       │
│  absorb   abstract absurd   abuse    access   accident     │
└────────────────────────────────────────────────────────────┘

Press Enter once you have written it down …

Wallet saved to /home/you/.pyrxd/wallet.dat
First receive address: 1A2bC3...
```

The mnemonic is the only way to recover the wallet — `pyrxd`
does not store it for you, and the wallet file alone is not
enough to spend funds. Write it down. Do not screenshot it.

## Step 3 — See your first address

`pyrxd wallet new` already printed the first receive address.
You can re-derive it (and any future receive addresses) without
re-creating the wallet:

```shell
$ pyrxd address
```

```
1A2bC3...  (m/44'/512'/0'/0/0)
```

The path on the right is the BIP44 derivation path — chain `512`
is SLIP-0044's Radiant coin type. Every `pyrxd address` call
walks the external chain (`/0/i`) to find the first index with
no on-chain history, so calling it twice in a row will return
the same address until you actually receive on it. You will be
prompted for the mnemonic each time — that is by design;
`pyrxd` never stores the seed at rest unencrypted.

If you want this address machine-readable:

```shell
$ pyrxd --json address
{"address": "1A2bC3...", "path": "m/44'/512'/0'/0/0", "network": "mainnet"}
```

## Step 4 — Fund the wallet (optional, for real sends)

The rest of the tutorial works against an empty wallet — you
will just see "no UTXOs" at Step 5 and "Insufficient funds" if
you try to broadcast. If you want a real end-to-end send, you
need to put some photons at the address from Step 3.

Acceptable funding sources:

- A second wallet you already control.
- An exchange withdrawal to the Step 3 address.
- A small testnet-style amount from a fellow developer.

Send at least `2_500_000` photons (`0.025 RXD`) — that covers the
`100_000`-photon transfer plus headroom for the fee. The default
fee rate is `10_000` photons/byte (the current Radiant mainnet
relay minimum, hard-coded as
[`pyrxd.wallet.DEFAULT_FEE_RATE`](https://github.com/MudwoodLabs/pyrxd/blob/main/src/pyrxd/wallet.py)),
so a 1-input 2-output P2PKH tx runs about `2_250_000` photons of
fee on its own — yes, high by Bitcoin habits; it is what the
network requires to relay today.

Wait for at least one confirmation before moving on. ElectrumX
exposes unconfirmed outputs too, but `--refresh` is more useful
when the funding transaction has actually landed.

## Step 5 — Find the UTXOs

```shell
$ pyrxd balance --refresh
```

```
Network    mainnet
Confirmed  2,500,000 photons (0.02500000 RXD)
Pending    0 photons (0.00000000 RXD)
```

The `--refresh` flag is what runs the BIP44 gap-limit scan:
`pyrxd` walks both the external (`/0`) and internal (`/1`)
chains, stopping after 20 consecutive unused addresses, and
records which ones have on-chain history. Without `--refresh`
a freshly-created wallet shows zero balance even when funded,
because `pyrxd` has no record yet of which derived addresses to
query.

To see the individual outputs:

```shell
$ pyrxd utxos
txid                                                              vout  value     height  address
abc123…                                                              0  2500000  890123   1A2bC3…
```

If the table is empty, the wallet has no spendable outputs —
either it is unfunded, the funding transaction is still
unconfirmed, or your derivation path is wrong (the coin-type
defaults are explained on the [HD wallet API
page](../api/index.rst)).

## Step 6 — Build and sign the send in Python

The plain RXD send path is library-level in 0.5.0 — there is no
`pyrxd send` CLI. Drop into Python:

```python
# send_demo.py
from __future__ import annotations

import asyncio
import os
import sys

from pyrxd.hd.wallet import HdWallet
from pyrxd.network.electrumx import ElectrumXClient

DRY_RUN: bool = os.environ.get("DRY_RUN", "1") != "0"
I_UNDERSTAND: bool = (
    os.environ.get("I_UNDERSTAND_THIS_IS_REAL", "").strip().lower() == "yes"
)

WALLET_PATH = os.path.expanduser(os.environ.get("WALLET_PATH", "~/.pyrxd/wallet.dat"))
MNEMONIC = os.environ["MNEMONIC"]
RECIPIENT = os.environ["RECIPIENT"]
PHOTONS = int(os.environ.get("PHOTONS", "100000"))
ELECTRUMX_URL = os.environ.get(
    "ELECTRUMX_URL", "wss://electrumx.radiant4people.com:50022/"
)


async def main() -> None:
    if not DRY_RUN and not I_UNDERSTAND:
        print(
            "ERROR: DRY_RUN=0 requires I_UNDERSTAND_THIS_IS_REAL=yes "
            "(broadcasts a real mainnet tx).",
            file=sys.stderr,
        )
        sys.exit(2)

    wallet = HdWallet.load(WALLET_PATH, MNEMONIC)

    async with ElectrumXClient([ELECTRUMX_URL]) as client:
        await wallet.refresh(client)
        triples = await wallet.collect_spendable(client)
        if not triples:
            print("No spendable UTXOs — fund the wallet first.", file=sys.stderr)
            sys.exit(2)

        tx = wallet.build_send_tx(triples, RECIPIENT, PHOTONS)

        print(f"Tx built")
        print(f"  txid:    {tx.txid()}")
        print(f"  size:    {tx.byte_length()} bytes")
        print(f"  fee:     {tx.get_fee():,} photons")
        print(f"  inputs:  {len(tx.inputs)}")
        print(f"  outputs: {len(tx.outputs)}  "
              f"(recipient + {'change' if len(tx.outputs) == 2 else 'no change'})")
        print()
        print(f"Raw hex:\n{tx.hex()}")

        if DRY_RUN:
            print("\n[DRY RUN] Not broadcasting. Set DRY_RUN=0 to broadcast.")
            return

        print("\nBroadcasting…")
        txid = await client.broadcast(tx.serialize())
        print(f"Broadcast: {txid}")


if __name__ == "__main__":
    asyncio.run(main())
```

Note the API surface — these are the four calls you actually
need to know:

- `HdWallet.load(path, mnemonic)` — opens the encrypted wallet
  file. Raises if the mnemonic does not decrypt it.
- `await wallet.refresh(client)` — gap-limit scan; must run
  before `collect_spendable` on a freshly-loaded wallet.
- `await wallet.collect_spendable(client)` — returns
  `(utxo, address, privkey)` triples covering every UTXO across
  every used address.
- `wallet.build_send_tx(triples, to_address, photons)` — picks
  inputs greedily (largest-first), adds a change output if the
  remainder is above the 546-photon dust threshold, signs every
  input. Returns a fully signed `Transaction`. Fees default to
  `pyrxd.wallet.DEFAULT_FEE_RATE` (`10_000` photons/byte) — you
  can override with `fee_rate=` if you know what you are doing.

`build_send_tx` does the fee calculation as a two-pass build —
it signs a trial transaction to measure its size, then
re-signs over the final outputs with the correct change value.
You do not need to estimate fees yourself.

## Step 7 — Run it (dry run)

```shell
$ MNEMONIC="abandon ability able about ..." \
  RECIPIENT="1RecipientAddressHere..." \
  python send_demo.py
```

You should see:

```
Tx built
  txid:    7f3a8b…
  size:    225 bytes
  fee:     2,250,000 photons
  inputs:  1
  outputs: 2  (recipient + change)

Raw hex:
0100000001…

[DRY RUN] Not broadcasting. Set DRY_RUN=0 to broadcast.
```

The `txid` is real — it is the SHA256d of the signed transaction
bytes. If you broadcast this exact hex, that is the txid you
will see on the chain. Until you broadcast, no one knows the
transaction exists.

If you see `Insufficient funds for requested amount`, the wallet
does not hold enough photons. Either fund it (Step 4) or reduce
`PHOTONS`. Remember the recipient amount plus the fee must
both fit under your confirmed balance.

## Step 8 — Broadcast (only when you are ready)

The dry-run path is the one you should run first, every time,
forever. When you are sure the recipient, amount, and fee are
what you want, flip the two guards together:

```shell
$ DRY_RUN=0 \
  I_UNDERSTAND_THIS_IS_REAL=yes \
  MNEMONIC="abandon ability able about ..." \
  RECIPIENT="1RecipientAddressHere..." \
  python send_demo.py
```

Both env vars are required. `DRY_RUN=0` alone refuses to
broadcast — the script exits 2 with the
`I_UNDERSTAND_THIS_IS_REAL=yes` reminder. The same pattern is
used by every broadcast-capable example in
[`examples/`](https://github.com/MudwoodLabs/pyrxd/tree/main/examples)
(`dmint_v1_deploy_demo.py`, `glyph_mint_demo.py`,
`ft_transfer_demo.py`); copy it into your own scripts so a
typo or a stale shell variable cannot accidentally publish a
transaction.

On success:

```
Tx built
  txid:    7f3a8b…
  …

Broadcasting…
Broadcast: 7f3a8b…
```

The broadcast txid matches the locally-computed one — the
server returns the same hash you already saw, which is your
confirmation that the signed bytes reached the mempool intact.
Paste it into a Radiant explorer to watch the confirmation
land.

## What you just learned

You now know enough to:

- Create and load HD wallets via the CLI without ever touching
  the encrypted file directly.
- Use `--refresh` to discover funded addresses on an empty-state
  wallet, and `pyrxd utxos` to inspect them.
- Build, sign, and broadcast plain RXD sends from Python with
  the `HdWallet.build_send_tx(...)` two-pass fee path.
- Gate broadcast behind explicit env vars so a dry-run is the
  default and you cannot accidentally publish a transaction.

For the protocol-level "why" — what makes a Radiant FT
different from a plain UTXO, how dMint deploys spawn N parallel
mint contracts in one reveal, why the relay-fee floor is what
it is — keep reading on the
[concepts pages](../concepts/index.md). For deployment
playbooks (mint a Glyph NFT, deploy a fungible token, run a
Gravity swap), the
[`examples/`](https://github.com/MudwoodLabs/pyrxd/tree/main/examples)
directory ships runnable end-to-end scripts.
