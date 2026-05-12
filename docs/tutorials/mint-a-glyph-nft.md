# Mint a Glyph NFT

End-to-end: author metadata, build a commit transaction, wait for it to
confirm, build a reveal, and broadcast. By the time you finish this
page you will have a runnable script that mints a Glyph NFT on Radiant.

This tutorial uses a **synthetic key** so you can run every step
without a funded wallet on day one — the script will stop before
broadcasting and print the transactions instead. The last section
explains how to flip to a real wallet.

**Prerequisites**

- pyrxd 0.5.0 (`pip install "pyrxd>=0.5.0"`)
- Python 3.11+
- `websockets` (`pip install websockets`) — only needed if you actually
  fetch UTXOs or broadcast

If you have not yet built a first Radiant transaction with pyrxd, the
[examples directory](https://github.com/MudwoodLabs/pyrxd/tree/main/examples)
has shorter end-to-end demos that may be a gentler starting point. This
page assumes you can read a script that builds a `Transaction` from
inputs and outputs.

---

## What you are building

A Glyph NFT on Radiant is created by a **two-transaction commit + reveal
flow**:

1. **Commit tx.** Locks one output under a hash of the NFT's CBOR
   metadata payload. Nobody can tell what the NFT will be yet — only
   the hash is on-chain.
2. **Reveal tx.** Spends the commit output, pushing the CBOR payload
   into its scriptSig. The script verifies that the payload's hash
   matches the commitment, then produces a singleton NFT output bound
   to the new ref `(commit_txid, commit_vout)`.

That ref — `commit_txid:commit_vout` — is the NFT's permanent identity.

You can read more about the underlying script shape in the concept
page on
[V1 dMint deploys](../concepts/dmint-v1-deploy.md); the NFT commit
script is the same family of "gly hashlock" output, just with the
singleton (`OP_2`) ref-type marker instead of the FT marker (`OP_1`).

---

## Step 1 — Author the metadata

`GlyphMetadata` is a frozen dataclass. The only required field is
`protocol`; for a singleton NFT that is `[GlyphProtocol.NFT]`.

```python
from pyrxd.glyph import GlyphMetadata, GlyphProtocol

metadata = GlyphMetadata(
    protocol=[GlyphProtocol.NFT],
    name="pyrxd-tutorial-nft",
    description="My first Glyph NFT, minted with pyrxd",
    token_type="tutorial",
    attrs={"minted_by": "pyrxd-tutorial"},
)
```

To attach an inline image (or any other media payload), construct a
`GlyphMedia` and pass it as `main`:

```python
from pyrxd.glyph import GlyphMedia

with open("nft.webp", "rb") as f:
    image_bytes = f.read()

metadata = GlyphMetadata(
    protocol=[GlyphProtocol.NFT],
    name="pyrxd-tutorial-nft",
    description="My first Glyph NFT, minted with pyrxd",
    main=GlyphMedia(mime_type="image/webp", data=image_bytes),
)
```

On-chain media is capped at 100 KB; the constructor will raise
`ValidationError` if you exceed that. For larger media, use
`image_url=` (HTTPS) or `image_ipfs=` (IPFS CID) instead and let
wallets fetch the bytes off-chain.

---

## Step 2 — Build the commit transaction

The high-level Glyph API splits the work in two: `prepare_commit`
returns the **scripts and CBOR bytes** for the commit; you build the
actual `Transaction` that holds those scripts. This is intentional —
pyrxd never picks UTXOs for you, never signs without your explicit
key, and never broadcasts on its own.

For the tutorial we generate a fresh synthetic key. **This key holds
no real RXD.** If you ran the full flow on mainnet with this key, the
commit step would fail at the UTXO-selection stage because there is
nothing to spend. We will stop short of broadcasting.

```python
from pyrxd.glyph import GlyphBuilder
from pyrxd.glyph.builder import CommitParams
from pyrxd.keys import PrivateKey
from pyrxd.security.types import Hex20

# Synthetic key — generated locally, never funded.
private_key = PrivateKey()
pub = private_key.public_key()
address = pub.address()
pkh_bytes = pub.hash160()

print(f"Minting wallet: {address}")

builder = GlyphBuilder()
commit_result = builder.prepare_commit(
    CommitParams(
        metadata=metadata,
        owner_pkh=Hex20(pkh_bytes),
        change_pkh=Hex20(pkh_bytes),
        funding_satoshis=0,  # placeholder — fee comes from your fee model
    )
)

print(f"Commit payload hash: {commit_result.payload_hash.hex()}")
print(f"CBOR payload:        {commit_result.cbor_bytes.hex()}")
print(f"Commit script:       {commit_result.commit_script.hex()}")
```

`prepare_commit` returns a `CommitResult` with four fields:

- `commit_script` — the locking-script bytes for `vout[0]` of the
  commit tx (a "gly hashlock" output).
- `cbor_bytes` — the CBOR-encoded metadata. **Save these.** The reveal
  step needs the exact same bytes; if they differ by one byte the
  hash will not match and the reveal will be rejected.
- `payload_hash` — 32-byte hash committed into the commit script.
- `estimated_fee` — rough estimate (in photons) of what the commit tx
  will cost to broadcast.

You still have to build the actual `Transaction`. The full reference
implementation is in
[`examples/glyph_mint_demo.py`](https://github.com/MudwoodLabs/pyrxd/blob/main/examples/glyph_mint_demo.py)
— look for `build_commit_tx`. It:

1. Spends one or more P2PKH UTXOs from your address.
2. Creates `vout[0]` with `commit_result.commit_script` and a value
   large enough to cover the reveal fee plus the NFT dust output.
3. Sends change back to your address.
4. Signs with `private_key`.

A safe commit-output value rule of thumb is

```
commit_value = reveal_fee_estimate + 200_000  # photons
```

where `reveal_fee_estimate` ≈ `580 bytes * 10_500 photons/byte` ≈
6.1M photons. The 200k margin is headroom against the size of your
specific CBOR payload.

> **Why a margin?** The reveal-tx byte length depends on the size of
> `cbor_bytes`, which depends on what you put in your metadata. A
> minimal NFT (no `main` media) is around 580 bytes; an NFT with a
> 100 KB inline image will be much larger and need a proportionally
> larger commit output.

---

## Step 3 — Wait for commit confirmation

Once you broadcast the commit, wait for it to confirm before building
the reveal. Radiant's target block time is ~2 minutes, so 90 seconds
plus a fresh UTXO lookup is usually enough on mainnet:

```python
import asyncio

# After broadcasting commit_tx and getting commit_txid back from ElectrumX:
print(f"Commit tx broadcast: {commit_txid}")
print("Waiting 90s for the commit to confirm...")
await asyncio.sleep(90)
```

The demo script saves the commit txid, vout, and the exact CBOR
payload bytes to `/tmp/glyph_mint_resume.json` between the two phases.
Do something similar in your own script — if the reveal step crashes
you do not want to lose the CBOR bytes, because regenerating them from
`GlyphMetadata` will only match if every field is byte-equal.

For this tutorial — running with a synthetic key — there is nothing
on-chain to wait for. The script just prints what the commit *would*
look like and moves on.

---

## Step 4 — Build the reveal transaction

`prepare_reveal` returns the scripts; again, you build the
`Transaction`.

```python
from pyrxd.glyph.builder import RevealParams

reveal_scripts = builder.prepare_reveal(
    RevealParams(
        commit_txid=commit_txid,
        commit_vout=commit_vout,
        commit_value=commit_value,
        cbor_bytes=commit_result.cbor_bytes,
        owner_pkh=Hex20(pkh_bytes),
        is_nft=True,
    )
)

print(f"Locking script ({len(reveal_scripts.locking_script)} bytes): "
      f"{reveal_scripts.locking_script.hex()}")
print(f"ScriptSig suffix ({len(reveal_scripts.scriptsig_suffix)} bytes): "
      f"{reveal_scripts.scriptsig_suffix.hex()}")
```

`RevealScripts` has two fields:

- `locking_script` — the 63-byte singleton NFT script for `vout[0]`
  of the reveal tx. This is the script that *is* your NFT.
- `scriptsig_suffix` — the `'gly' + CBOR` portion of the input
  scriptSig. Your tx builder must prepend the standard
  P2PKH-style `signature + pubkey` pushes to this suffix to produce
  the final scriptSig.

The reveal tx itself spends the commit output (`vin[0]`) and produces
one NFT output. Again, the wiring lives in
[`examples/glyph_mint_demo.py`](https://github.com/MudwoodLabs/pyrxd/blob/main/examples/glyph_mint_demo.py)
— `build_reveal_tx` is the relevant helper.

> **`is_nft=True` is load-bearing.** `prepare_reveal` cross-checks
> this flag against the protocol field inside `cbor_bytes`. If the
> CBOR says `[FT]` but you pass `is_nft=True` it raises
> `ValidationError`. The check exists because a mismatch would silently
> produce an output that no wallet can classify.

---

## Step 5 — Broadcast (DRY_RUN by default)

Mirror the env-var guard from
[`examples/glyph_mint_demo.py`](https://github.com/MudwoodLabs/pyrxd/blob/main/examples/glyph_mint_demo.py):

```python
import os

DRY_RUN = os.environ.get("DRY_RUN", "1") != "0"

if DRY_RUN:
    print("[DRY RUN] Reveal tx not broadcast.")
    print(f"Reveal tx hex:\n{reveal_tx.hex()}")
else:
    # Only reached if the operator explicitly set DRY_RUN=0.
    result = await broadcast(reveal_tx.hex())
    print(f"Broadcast result: {result}")
```

The default is dry-run. You only broadcast if the operator goes out of
their way to set `DRY_RUN=0`. Treat any inversion of that default —
broadcasting by default and requiring opt-out — as a bug.

A second, stricter pattern the demo also uses for high-risk paths is
an `I_UNDERSTAND_THIS_IS_REAL` env var. For a tutorial NFT mint
`DRY_RUN=0` alone is enough, but the pattern is worth knowing about
when you graduate to scripts that move real value.

---

## The result

With `DRY_RUN=0` and a funded key, the script prints something like:

```
=== Glyph NFT minted successfully! ===
  Commit txid: <64-hex-chars>
  Reveal txid: <64-hex-chars>
  NFT ref:     <commit_txid>:0
  Owner:       <radiant-address>
```

The `NFT ref` is the permanent identity of your NFT. Any Radiant
wallet or indexer that scans the reveal tx will see a 63-byte
singleton output bound to that ref, owned by `<radiant-address>`.

---

## Switching to a real wallet

To run this for real, replace the synthetic-key line with a WIF you
control:

```python
import os
from pyrxd.keys import PrivateKey

wif = os.environ["GLYPH_WIF"]  # never hard-code a key
private_key = PrivateKey(wif)
```

Fund the address (`private_key.address()`) with at least ~7M photons
(enough for the commit output's reveal-fee headroom plus the commit's
own fee). Then run the demo end-to-end:

```bash
DRY_RUN=1 GLYPH_WIF=<your-wif> python mint_nft.py   # build only
DRY_RUN=0 GLYPH_WIF=<your-wif> python mint_nft.py   # broadcast
```

Start with `DRY_RUN=1` and read what gets printed. Only flip to
`DRY_RUN=0` once the commit script, CBOR bytes, and locking script
look right.

---

## What to read next

- The full runnable reference:
  [`examples/glyph_mint_demo.py`](https://github.com/MudwoodLabs/pyrxd/blob/main/examples/glyph_mint_demo.py).
  This tutorial omits the transaction-assembly plumbing (UTXO
  selection, fee computation, signing with a custom unlocking
  template); the demo shows all of it.
- [Radiant FTs are on-chain](../concepts/radiant-fts-are-on-chain.md) —
  not directly about NFTs, but the "the script bytes *are* the token"
  framing applies identically to NFT singletons.
- [V1 dMint deploys](../concepts/dmint-v1-deploy.md) — the commit /
  reveal shape generalises from one NFT to N parallel singleton
  contracts when the protocol is `[FT, DMINT]`.
