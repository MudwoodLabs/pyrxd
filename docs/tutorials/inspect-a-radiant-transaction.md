# Inspect a Radiant transaction in the browser

**Who this page is for:** anyone curious about pyrxd or the Radiant Glyph
protocol who wants to see what's actually inside a Radiant transaction
without installing anything. No Python, no wallet, no funded UTXOs.

Everything in this tutorial happens at
[https://mudwoodlabs.github.io/pyrxd/inspect/](https://mudwoodlabs.github.io/pyrxd/inspect/).
You paste a Radiant transaction id (txid), click a button, and the page
classifies what you pasted — FT transfer, dMint claim, Glyph deploy
reveal, plain RXD send — and decodes the structural fields.

The tool runs entirely in your browser. It loads pyrxd via Pyodide
(~12 MB, cached after the first visit), reads transactions over a
read-only WebSocket to a public ElectrumX server, and never sees a
private key. For the architecture behind that, see
[the inspect tool concept page](https://mudwoodlabs.github.io/pyrxd/concepts/glyph-inspect-tool.html).

By the end you will have decoded four kinds of inputs.

---

## Before you start

Open [https://mudwoodlabs.github.io/pyrxd/inspect/](https://mudwoodlabs.github.io/pyrxd/inspect/).

The first time you visit, the page shows a progress bar labelled
"Loading `pyrxd`" while it downloads Pyodide + the pyrxd wheel from
the CDN. On a typical connection this takes 10–20 seconds. Subsequent
visits are near-instant because the browser caches the runtime.

Once loaded you'll see:

- A textarea labelled **"Paste a Glyph contract id, outpoint, txid, or
  hex script"**.
- Three buttons under it: **Classify**, **Clear**, **Share link**.
- A "Try an example" row with chips you can click — leave those alone
  for this tutorial; we'll paste real mainnet txids instead.

If the page reports an error and won't load, refresh once. If it still
fails, file an issue with the error text — the inspect tool is meant
to be the friction-free entry point and a broken load is a bug.

---

## 1. Decode an FT transfer

The simplest case: someone sent a Glyph fungible token to someone else.
Radiant's Glyph FT model is unusual — the token *is* the UTXO, not a
metadata layer on top of a P2PKH output. The inspect tool surfaces the
75-byte FT-wrapped locking script directly.

Find any Glyph FT transfer txid from
[radiantexplorer.com](https://radiantexplorer.com) — open a recent
block, look for a transaction whose outputs aren't all plain P2PKH,
and copy its txid. Or pull a transfer from your own wallet if you
have RXD tokens.

1. Paste the txid into the textarea.
2. Click **Classify**.
3. The first card shows the txid and a **Fetch from network** button.
   Click it.

You'll see status flip from "fetching…" to "classifying…" to a
**Fetched transaction** card listing the input count, output count,
and a row per output. FT transfers render as rows badged `FT` with
fields like:

- `owner pkh` — the recipient's public-key hash.
- `ref` — the token's contract id; this is what identifies *which*
  FT was sent.

The tool will not show a top-level "shape" banner for an ordinary FT
transfer — the per-output rows tell the whole story. Banners only
appear when the tool recognises a higher-level shape like a deploy
or a mint claim.

```{note}
Each output row carries a small **structural-match qualifier** —
the badges (`FT`, `NFT`, `DMINT`, etc.) match by hex pattern, not by
cryptographic provenance. A custom locking script whose bytes happen
to fit the FT template would also classify as `FT`. The only safe
identifier is the `ref` outpoint, not the type badge alone.
```

---

## 2. Decode a dMint mint claim

A dMint *claim* is a Radiant transaction that consumes a parallel
dMint contract output, mines a PoW solution against the contract's
target, and emits a freshly-minted FT reward to the caller. The
shape is invariant across V1 deploys: four outputs in a fixed order.

We'll use pyrxd's own first successful mint, on 2026-05-11 — the
verification of the V1 mint scriptSig fix shipped in 0.5.0. The
txid is:

```
c9fdcd3488f3e396bec3ce0b766bb8070963e7e75bb513b8820b6663e469e530
```

1. Click **Clear** (or just overwrite the textarea).
2. Paste the txid above.
3. Click **Classify**, then click **Fetch from network**.

The **Fetched transaction** card now shows four outputs and a banner
that begins:

> *This is a dMint claim transaction (height N of 625000) — somebody
> spent the contract's previous output to mint themselves a token…*

The four output rows you should see:

| vout | badge        | what it is                                                          |
|-----:|--------------|---------------------------------------------------------------------|
| 0    | `DMINT`      | the contract's continuation UTXO at `height + 1`                    |
| 1    | `FT`         | the freshly-minted reward — 75-byte FT-wrapped script, not P2PKH    |
| 2    | `OP_RETURN`  | the literal message script whose `SHA256d` is pushed as `outputHash`|
| 3    | `P2PKH`      | RXD change back to the miner                                        |

Below the outputs, a section titled **dMint mint scriptSig (vin 0)**
shows the four pushes the miner placed on the input:

- `version (by nonce width)` — `v1` for this transaction.
- `nonce (LE)` — the 4-byte PoW solution.
- `input hash (SHA256d funding script)` — the literal hash of the
  funding input's locking script.
- `output hash (SHA256d OP_RETURN script)` — the literal hash of
  vout[2]'s script.

That last detail — those two hashes are literal `SHA256d` of scripts,
not halves of the PoW preimage — is exactly the bug that
[the 0.5.0 migration page](../how-to/migrate-0.4-to-0.5.md) describes.
The inspect tool's note under this section says so explicitly.

---

## 3. Decode a Glyph reveal

The dMint *deploy* is a two-transaction flow: a commit that opens an
FT-metadata hashlock and seeds N ref outputs, then a reveal that
spends the commit and creates N parallel singleton contract UTXOs
sharing one `tokenRef`. We'll inspect the reveal for the Glyph
Protocol (GLYPH) token itself — the canonical mainnet reference for
V1 dMint deploys. The deploy reveal txid is:

```
b965b32dba8628c339bc39a3369d0c46d645a77828aeb941904c77323bb99dd6
```

1. **Clear** and paste the txid.
2. **Classify**, then **Fetch from network**.

You'll see a banner that begins:

> *This is a dMint deploy reveal — creates 32 parallel dMint contract
> UTXOs, all sharing the same token_ref. Each contract can be mined
> from independently…*

The outputs list will be long. Skim it for the shape laid out in
[the V1 dMint deploys concept page](../concepts/dmint-v1-deploy.md):

- The first 32 rows are badged `DMINT` — these are the parallel
  contract UTXOs. Each carries `height: 0`, the same `token_ref`,
  a unique `contract_ref`, and the deploy-time `max_height: 625000`
  and `reward: 50000` (sats per mint).
- One row badged `FT` — the public-facing FT NFT singleton that
  every Glyph FT deploy carries.
- A final `P2PKH` row — RXD change to the deployer.

Above the outputs, a **Reveal metadata** section decodes the CBOR
body that the deploy reveal carried in its `vin[0]` scriptSig. You
should see:

- `protocol` — `1, 4` (FT + DMINT — this is what makes it a V1 dMint
  deploy rather than a plain FT).
- `name` — `Glyph Protocol`.
- `ticker` — `GLYPH`.
- `description` — `The first of its kind`.

Total supply for GLYPH is `32 contracts × 625,000 max_height ×
50,000 photons = 10⁹ photons` (10,000 GLYPH at 8 decimals). All of
those numbers are visible on this single card.

---

## 4. Optional: decode a plain RXD send

For contrast, paste any non-Glyph txid — a plain RXD payment between
two P2PKH addresses. Find one on
[radiantexplorer.com](https://radiantexplorer.com) by opening a
recent block and picking a transaction whose outputs are all plain
addresses (no token rows).

1. **Clear**, paste, **Classify**, **Fetch from network**.

The card shows just `P2PKH` rows and no top-level shape banner —
this is intentional. The inspect tool only surfaces a shape banner
when it recognises a Glyph-protocol pattern; an ordinary RXD send
has no protocol context to add and the rows speak for themselves.

That silence is informative. If you paste what you *think* is a
Glyph transfer and get no token rows, the transaction probably isn't
what you thought it was.

---

## What to do next

You've decoded four transaction shapes without installing anything.
Some directions from here:

- **Read [the V1 dMint deploys concept page](../concepts/dmint-v1-deploy.md)**
  to understand why the GLYPH reveal looks the way it does — the
  32 parallel contracts, the shared `tokenRef`, the byte layout of
  each contract UTXO.
- **Read [the migration guide](../how-to/migrate-0.4-to-0.5.md)** if
  you're building on pyrxd 0.5.0 and saw that the `mint scriptSig`
  pushes literal `SHA256d` of scripts. That detail is load-bearing.
- **Install pyrxd** with `pip install pyrxd` and run the demos in
  [`examples/`](https://github.com/MudwoodLabs/pyrxd/tree/main/examples).
  Once you have a funded address you can build, sign, and broadcast
  the same shapes you just inspected.
