# Mint a Glyph FT

**Goal:** issue your own fungible token on Radiant mainnet, from zero to a
broadcastable reveal transaction, using pyrxd 0.5.0.

This tutorial walks the canonical two-transaction flow:

1. **Commit tx** — places the metadata-hashlock script on chain.
2. **Reveal tx** — spends the commit and emits a single 75-byte FT output
   carrying your entire premine supply. Its outpoint becomes the
   permanent token reference.

The runnable reference is
[`examples/ft_deploy_premine.py`](https://github.com/MudwoodLabs/pyrxd/tree/main/examples/ft_deploy_premine.py).
This page walks the same flow step-by-step. By default everything is a
dry run — no transaction is broadcast unless you explicitly opt in.

## Before you start

You should already be comfortable with the
[first-transaction tutorial](https://github.com/MudwoodLabs/pyrxd/tree/main/examples)
patterns: a funded WIF key, ElectrumX, fee math. If you've also minted
a Glyph NFT before, this is the same commit/reveal shape with two
differences:

- the protocol vector is `[FT]` (`[1]`), not `[NFT]` (`[2]`);
- the reveal output is the 75-byte FT lock instead of the 63-byte NFT
  singleton, and it carries a premine *amount* (photons) instead of a
  single 1-photon NFT token.

The 75-byte FT script shape and the consensus rules behind it are
explained in
[Radiant FTs are on-chain](../concepts/radiant-fts-are-on-chain.md) —
keep that page open in another tab. This tutorial does not re-derive the
script layout.

You will need:

- a WIF private key for a Radiant address holding enough RXD to cover
  the commit, the reveal, the premine, and fees;
- pyrxd 0.5.0 installed (`pip install pyrxd`);
- an ElectrumX endpoint (the example defaults to a public
  radiant4people node).

## Step 1: design the token

Decide three things up front. None of them can be changed after the
deploy:

| Field           | Example          | Notes                                                                                                 |
|-----------------|------------------|-------------------------------------------------------------------------------------------------------|
| `name`          | `"My Token"`     | Human-readable name, free-form string.                                                                |
| `ticker`        | `"MTK"`          | Ticker symbol; convention is uppercase, ≤16 chars.                                                    |
| `decimals`      | `0`              | **Display** precision only — consensus is always "1 photon = 1 FT unit." See note below.              |
| Premine amount  | `1_000_000`      | Integer FT units = photons in the reveal's FT output. Must be ≥ 546 (dust limit).                     |

```{note}
`decimals` is a display hint for wallets, not a consensus quantity.
Radiant's FT conservation rule operates on photons. A token with
`decimals=2` and a premine of `1_000_000` photons displays as
`10_000.00` units in supporting wallets but is still exactly
1,000,000 photons on chain.
```

## Step 2: build the metadata

`GlyphMetadata` is the payload that gets CBOR-encoded into the reveal
scriptSig. For a plain FT, the only required protocol marker is
`GlyphProtocol.FT`:

```python
import time
from pyrxd.glyph import GlyphMetadata, GlyphProtocol

metadata = GlyphMetadata(
    protocol=[GlyphProtocol.FT],   # [1] — plain fungible token
    name="My Token",
    ticker="MTK",
    description="My Token — issued via pyrxd",
    decimals=0,
    attrs={"issued_at": str(int(time.time()))},
)
```

```{important}
Set `protocol=[GlyphProtocol.FT]` for a plain FT. Use
`[GlyphProtocol.FT, GlyphProtocol.DMINT]` only if you want a dMint
distribution token (parallel mining contracts) — that flow is covered
in [V1 dMint deploys](../concepts/dmint-v1-deploy.md). Plain FTs and
dMint FTs share the 75-byte output shape but use different deploy
methods. This tutorial covers plain FT only.
```

## Step 3: derive the commit script

`GlyphBuilder.prepare_commit` takes the metadata plus the owner's PKH
(20-byte hash160 of the public key) and returns the commit locking
script, the CBOR bytes you'll need at reveal time, and the payload
hash committed into the script:

```python
from pyrxd.glyph import GlyphBuilder
from pyrxd.glyph.builder import CommitParams
from pyrxd.keys import PrivateKey
from pyrxd.security.types import Hex20

private_key = PrivateKey(GLYPH_WIF)            # your funded WIF
pub = private_key.public_key()
address = pub.address()
pkh = Hex20(pub.hash160())

builder = GlyphBuilder()
commit_result = builder.prepare_commit(
    CommitParams(
        metadata=metadata,
        owner_pkh=pkh,
        change_pkh=pkh,
        funding_satoshis=0,           # not load-bearing for plain FT
    )
)
# commit_result.commit_script — bytes; place at vout[0] of the commit tx
# commit_result.cbor_bytes    — bytes; save these for the reveal scriptSig
# commit_result.payload_hash  — bytes32; committed inside commit_script
```

`prepare_commit` reads `metadata.protocol`: because `NFT (2)` is **not**
in the list, the commit script is built as the FT-shaped commit
(`OP_1 / OP_NUMEQUALVERIFY` ref-count check) rather than the NFT
singleton shape.

```{warning}
Save `commit_result.cbor_bytes` somewhere durable before broadcasting
the commit. The reveal scriptSig has to push the *exact* same CBOR
bytes you committed to — regenerating from the metadata is fine for a
deterministic build, but the example script writes `cbor_hex` plus
`commit_txid` to `/tmp/ft_deploy_resume.json` so a crashed reveal can
be resumed without recomputing.
```

## Step 4: broadcast the commit tx

The commit tx is an ordinary spend of P2PKH UTXOs that produces two
outputs:

- `vout[0]` — `commit_result.commit_script` with a value large enough
  to cover the reveal's fee **and** the premine output. The reference
  example targets ≈ `(REVEAL_SIZE × MIN_FEE_RATE × 1.2) + PREMINE_AMOUNT
  + 200_000` photons for comfortable headroom.
- `vout[1]` — change back to your address as plain P2PKH.

Construction details (P2PKH unlock template, fee model,
`Transaction.sign()`) match the demo and are not specific to FT —
see `build_commit_tx` in
[`examples/ft_deploy_premine.py`](https://github.com/MudwoodLabs/pyrxd/tree/main/examples/ft_deploy_premine.py).

```{note}
**DRY_RUN by default.** The reference example sets
`DRY_RUN = os.environ.get("DRY_RUN", "1") != "0"`. The commit tx is
*built and signed* but is only broadcast when you set `DRY_RUN=0`.
This is deliberate — running a script that prints transaction hex is
safe; broadcasting requires explicit opt-in.
```

After broadcasting, wait for the commit to confirm before building the
reveal. The reference example sleeps 90 seconds; production code
should poll the node or wait for a block.

## Step 5: build the reveal

This is the only FT-specific call in the deploy. Pass the confirmed
commit outpoint, the CBOR bytes saved at commit time, the recipient
PKH (you, for a self-premine), and the integer premine amount:

```python
reveal_scripts = builder.prepare_ft_deploy_reveal(
    commit_txid=commit_txid,
    commit_vout=commit_vout,           # 0 in the reference shape
    commit_value=commit_value,         # photons in the commit output
    cbor_bytes=commit_result.cbor_bytes,
    premine_pkh=pkh,
    premine_amount=1_000_000,          # your token supply, in photons
)
# reveal_scripts.locking_script   — 75 bytes, the FT lock; goes at vout[0]
# reveal_scripts.scriptsig_suffix — 'gly' + CBOR; goes after sig + pubkey
# reveal_scripts.premine_amount   — set vout[0].value to exactly this
```

The returned `locking_script` is the canonical 75-byte FT shape:
P2PKH (25 bytes) → `OP_STATESEPARATOR` → `OP_PUSHINPUTREF <ref>` (38 bytes)
→ the 12-byte FT-CSH conservation epilogue `dec0e9aa76e378e4a269e69d`.
See [Radiant FTs are on-chain](../concepts/radiant-fts-are-on-chain.md)
for the byte-by-byte breakdown — the bytes `prepare_ft_deploy_reveal`
emits match that layout exactly.

```{warning}
`premine_amount < 546` is rejected at build time as below the dust
limit (most mempool policies refuse the reveal otherwise). If you
want a smaller supply, pick a different token model (NFT, or scale up
with `decimals`).
```

The reveal tx spends `vout[0]` of the commit and produces *one*
output — `vout[0]` carries the entire premine to `premine_pkh`. Its
outpoint `(reveal_txid, 0)` is the permanent token reference: every
future transfer of this FT will encode the same 36 bytes inside its
output script.

Two practical points the reference example handles for you:

- **scriptSig layout.** The reveal-input scriptSig is the normal
  P2PKH `<sig> <pubkey>` push pair followed by
  `scriptsig_suffix`. The example wraps this in
  `ft_reveal_unlock_template`.
- **Two-pass fee.** Because the FT output's value equals `premine_amount`
  exactly (1 photon = 1 FT unit), there is no change output to absorb
  fee imprecision. The example signs a trial tx, measures its byte
  length, computes the fee, and verifies
  `commit_value - premine_amount - fee >= 0` before signing the final
  tx.

## Step 6: broadcast and verify

With `DRY_RUN=0` and a confirmed commit, broadcast the reveal. On
acceptance you have:

- **Token ref:** `{reveal_txid}:0` — the 36-byte ref encoded into
  every FT UTXO of this token.
- **Supply:** exactly `premine_amount` photons, living at
  `reveal_scripts.locking_script` at the address derived from
  `premine_pkh`.

Sanity-check the result with the inspect tool:

```bash
$ pyrxd glyph inspect <reveal_txid> --fetch
Transaction: ...
  vout 0  type=ft     ref=<reveal_txid>:0  sats=1000000  (FT — full premine)
```

`type=ft` confirms the locking script matches the 75-byte FT shape and
its embedded ref points at itself — i.e. this is a freshly deployed
FT. Any wallet implementing the standard FT classifier
(`is_ft_script` + `extract_ref_from_ft_script`) will recognise it
without an indexer.

## What's next

- **Send some tokens.** Once the reveal confirms, you can transfer
  units of the token using `GlyphBuilder.build_ft_transfer_tx`. The
  load-bearing prerequisite — filtering wallet UTXOs to the correct
  75-byte FT shape *and* the right token ref — is explained at length
  in [Radiant FTs are on-chain](../concepts/radiant-fts-are-on-chain.md)
  and demonstrated end-to-end in
  [`examples/ft_transfer_demo.py`](https://github.com/MudwoodLabs/pyrxd/tree/main/examples/ft_transfer_demo.py).
- **Distribute by mining instead of premining.** If you want supply
  emitted by parallel proof-of-work contracts rather than handed to a
  single address up front, that's a *dMint* deploy
  (`protocol=[FT, DMINT]`) — see
  [V1 dMint deploys](../concepts/dmint-v1-deploy.md). It's a
  different builder method (`prepare_dmint_deploy`) and a three-tx
  flow, not the two-tx flow on this page.
- **Migrating from pyrxd 0.4.x?** Plain-FT deploy is unchanged in
  0.5.0; only the V1 dMint *mint* path has breaking signature
  changes. See [Migrate from 0.4 to 0.5](../how-to/migrate-0.4-to-0.5.md)
  if you have a custom miner.
