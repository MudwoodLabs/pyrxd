# Mint from a V1 dMint contract on Radiant mainnet

End-to-end walkthrough of mining and claiming one mint from a live V1
dMint contract on Radiant mainnet, targeting Glyph Protocol (GLYPH).
By the end you will have:

1. Located an unspent GLYPH contract UTXO on chain using pyrxd.
2. Built and signed a four-output V1 mint transaction.
3. Mined a SHA256d PoW nonce that satisfies the contract's target.
4. Broadcast the transaction and confirmed it on chain.

This is the most advanced tutorial in the set — it touches the
network, costs real RXD, and is irreversible. Read it through once
before running any commands.

```{warning}
**This tutorial is mainnet-only and broadcasts a real transaction.**
There is no testnet path for V1 dMint contracts because every live
contract is on Radiant mainnet. A clean dry-run does not commit; the
broadcast step at the end does.
```

For the theory behind what a V1 dMint contract is and the byte-by-byte
shape of the mint transaction, see the
[V1 dMint deploys concept page](../concepts/dmint-v1-deploy.md). This
tutorial is hands-on; it assumes you have already skimmed that page or
are willing to follow along without it.

---

## Prerequisites

You need all of the following before you start. None of them are
optional.

- **pyrxd 0.5.0 installed** — `pip install pyrxd==0.5.0`. Earlier
  versions ship a different mint-path signature; see
  [the migration guide](../how-to/migrate-0.4-to-0.5.md) if you upgraded
  from 0.4.x.
- **A funded Radiant wallet.** You need the WIF private key for a
  Radiant address that holds at least one plain-RXD UTXO large enough
  to cover the contract's reward (50,000 photons for GLYPH) plus the
  transaction fee (≈10,000 photons at default rate) plus standard
  dust headroom. Funding a wallet is out of scope for this page.
- **An external miner binary.** The pure-Python `mine_solution`
  shipped in 0.5.0 is correct but sequential; on mainnet difficulty it
  takes minutes to hours single-threaded. Point `EXTERNAL_MINER` at a
  faster miner — the standalone
  [`glyph-miner`](https://github.com/RadiantBlockchain-Community/glyph-miner)
  C binary is the canonical choice. A bundled pure-Python parallel
  miner shipping as `pyrxd.contrib.miner` is planned for **0.5.1**;
  until then you must supply your own miner binary or accept the slow
  single-threaded path.
- **An ElectrumX endpoint.** The default,
  `wss://electrumx.radiant4people.com:50022/`, works without
  configuration. Override with the `ELECTRUMX_URL` env var if you run
  your own node.

---

## Step 0 — Check whether GLYPH contracts are still mineable

GLYPH was deployed on Radiant mainnet with **32 parallel singleton
contracts** (the deploy reveal txid is
`b965b32dba8628c339bc39a3369d0c46d645a77828aeb941904c77323bb99dd6`).
Each contract is independently mineable up to `max_height = 625,000`
mints, after which it is exhausted. Before you run any of the steps
below, **check how many of the 32 contracts still have unspent UTXOs**.

The fastest way is the browser-hosted inspect tool: open `/inspect/` on
the published docs (e.g. <https://pyrxd.readthedocs.io/inspect/>) and
paste the reveal txid. The tool fetches the reveal and reports each
contract's current height and remaining mints.

If you would rather use Python, `find_dmint_contract_utxos` (introduced
in 0.5.0) does the same walk programmatically:

```python
import asyncio
from pyrxd.glyph.dmint import find_dmint_contract_utxos
from pyrxd.glyph.types import GlyphRef
from pyrxd.network.electrumx import ElectrumXClient
from pyrxd.security.types import Txid

GLYPH_COMMIT_TXID = "a443d9df469692306f7a2566536b19ed7909d8bf264f5a01f5a9b171c7c3878b"
ELECTRUMX_URL = "wss://electrumx.radiant4people.com:50022/"

async def list_glyph_contracts() -> None:
    token_ref = GlyphRef(txid=Txid(GLYPH_COMMIT_TXID), vout=0)
    async with ElectrumXClient([ELECTRUMX_URL]) as client:
        # Walk-from-reveal path: pass only token_ref, no initial_state.
        # Returns only *fresh* contracts (height=0). Mined-from contracts
        # are filed as deferred work; see the concept page.
        contracts = await find_dmint_contract_utxos(client, token_ref=token_ref)
    print(f"Found {len(contracts)} fresh GLYPH contract UTXO(s).")
    for c in contracts:
        s = c.state
        print(
            f"  {c.txid}:{c.vout}  "
            f"height={s.height}/{s.max_height}  "
            f"reward={s.reward} photons"
        )

asyncio.run(list_glyph_contracts())
```

```{note}
**If the list comes back empty:** all 32 contracts may have been
fully mined out, or every fresh contract may have been spent into
its second mint already (`find_dmint_contract_utxos` returns
*fresh-only* in 0.5.0; following the spend chain forward to find
current heads is filed as deferred work). You can still walk through
the steps below to learn the API by pointing `CONTRACT_TXID` /
`CONTRACT_VOUT` at any V1 dMint reveal output — just don't expect the
broadcast step to succeed.
```

Pick any one entry from the list. Its `txid` and `vout` are the values
you will pass as `CONTRACT_TXID` and `CONTRACT_VOUT` in Step 3.

---

## Step 1 — Set up the funding wallet

The V1 mint transaction has two inputs:

1. **`vin[0]`** — the contract UTXO you picked above. The covenant
   carries 1 photon and is consumed-and-recreated by the mint.
2. **`vin[1]`** — a plain-RXD UTXO at *your* address. This input pays
   the reward output's 50,000 photons plus the transaction fee.

You provide `vin[1]` by exporting your wallet's WIF private key.
`find_dmint_funding_utxo` scans your address for an unspent plain-RXD
UTXO that covers the reward + fee and, critically, **excludes any
token-bearing UTXOs** using the same opcode-aware classifier the mint
builder enforces. Picking a token-bearing UTXO as a funding input would
silently destroy the token; the scan is the load-bearing defence.

You do not need to run this scan manually — the demo script in Step 3
calls `find_dmint_funding_utxo` for you. But if you want to confirm
your wallet has a qualifying UTXO before you mine, the call is:

```python
from pyrxd.glyph.dmint import find_dmint_funding_utxo
from pyrxd.keys import PrivateKey

miner_key = PrivateKey("<your WIF>")
miner_address = miner_key.public_key().address()

# Conservative bound: 50,000 reward + 10 MB headroom for fees.
needed = 50_000 + 10_000_000 + 546

async with ElectrumXClient([ELECTRUMX_URL]) as client:
    funding = await find_dmint_funding_utxo(client, miner_address, needed)
print(f"funding: {funding.txid}:{funding.vout} ({funding.value:,} photons)")
```

If the scan raises `InvalidFundingUtxoError`, top up the wallet with
plain-RXD (not FT, not NFT, not dMint) before continuing.

---

## Step 2 — Configure the external miner

The shipped path for fast mining in 0.5.0 is the `EXTERNAL_MINER` env
var, which delegates the nonce sweep to a separate process over a
small JSON-over-stdio protocol.

Install [`glyph-miner`](https://github.com/RadiantBlockchain-Community/glyph-miner)
(or any miner that speaks the same protocol — the wire shape is
documented in the docstring of
[`pyrxd.glyph.dmint.mine_solution_external`](https://github.com/MudwoodLabs/pyrxd/blob/main/src/pyrxd/glyph/dmint.py)).

Then export the variable. The value is the full command line pyrxd
should spawn, space-separated:

```bash
export EXTERNAL_MINER="/usr/local/bin/glyph-miner --stdin"
```

```{warning}
**Pin the miner binary's absolute path.** `mine_solution_external`
resolves `miner_argv[0]` via the OS at exec time, so a malicious binary
earlier in `$PATH` could intercept the call. Use an absolute path
(`/usr/local/bin/glyph-miner`, not `glyph-miner`), and verify the
binary's checksum against the upstream release before first use. The
preimage the miner sees encodes the contract ref and miner binding —
a malicious miner could leak it out-of-band, which the local nonce
re-verification cannot detect.
```

If `EXTERNAL_MINER` is unset, the demo falls back to
`mine_solution` (the sequential pure-Python miner). That is correct
but slow — expect 70+ minutes single-core at GLYPH's target. Use it
only if you cannot install a fast miner.

A bundled pure-Python parallel miner that uses `multiprocessing` to
sweep the V1 4-byte nonce space in ~2-3 minutes on a 32-core machine
is on track to ship as `pyrxd.contrib.miner` in **0.5.1**. Until then,
`EXTERNAL_MINER` is the only fast path.

---

## Step 3 — Dry-run the mint

Run the canonical end-to-end script,
[`examples/dmint_claim_demo.py`](https://github.com/MudwoodLabs/pyrxd/tree/main/examples/dmint_claim_demo.py),
with `DRY_RUN=1` (the default). The script will fetch the contract,
scan funding, build the unsigned tx, mine a nonce, splice it in, sign
the funding input, and print the raw transaction hex — but **not**
broadcast.

```bash
MINER_WIF="<your funded WIF>" \
CONTRACT_TXID="<txid from Step 0>" \
CONTRACT_VOUT="<vout from Step 0>" \
EXTERNAL_MINER="/usr/local/bin/glyph-miner --stdin" \
python examples/dmint_claim_demo.py
```

What it does, step by step, mirrors the same flow you would write by
hand:

1. **Fetch the contract UTXO** via `ElectrumXClient.get_transaction`
   and parse its state with `DmintState.from_script`. The script
   prints `height`, `max_height`, `reward`, and refuses to continue if
   the state is `is_v1=False` or `is_exhausted=True`.
2. **Scan for funding** via `find_dmint_funding_utxo`. Prints the
   chosen UTXO and its value.
3. **Build the unsigned tx** via `build_dmint_mint_tx` with a
   placeholder zero-nonce. The builder validates the four-output
   shape (contract carrier, FT reward, OP_RETURN msg, change) and
   computes the fee.
4. **Compute the PoW preimage and the two scriptSig hashes** via
   `build_dmint_v1_mint_preimage`. This is the helper that fixes the
   0.4.x covenant-rejection bug — the preimage the miner solves and
   the script hashes the covenant checks come from a single call, so
   they can't drift. The return is a `PowPreimageResult` carrying
   `preimage`, `input_hash`, and `output_hash`.
5. **Mine** via `mine_solution_external` (if `EXTERNAL_MINER` is set)
   or `mine_solution` (the sequential fallback). Both re-verify the
   returned nonce locally with `verify_sha256d_solution` before
   handing it back — a buggy or malicious miner that returns a wrong
   nonce raises `ValidationError` rather than embedding garbage in
   your transaction.
6. **Splice the scriptSig** with the real nonce + the two script
   hashes via `build_mint_scriptsig(nonce, input_hash, output_hash,
   nonce_width=4)`. The keyword-only `nonce_width` is `Literal[4, 8]`
   so a stray positional value is a type error rather than a silent
   V1/V2 confusion.
7. **Sign `vin[1]`** with a standard P2PKH unlocking script using your
   WIF.
8. **Print the raw tx hex.** In `DRY_RUN=1` mode the script stops
   here.

If the script prints `[DRY RUN] Tx not broadcast.` and a 200+ char
hex string, the build is good. Save the hex — if the broadcast in
Step 5 fails because the WebSocket dropped during the long mining
loop, you can replay it through any other broadcast path.

---

## Step 4 — Inspect the unsigned tx (optional but recommended)

Paste the raw tx hex from Step 3 into the browser inspect tool
(`/inspect/`). The structural-match qualifier will identify it as a
**V1 dMint claim** and break the four outputs down:

- `vout[0]` — the recreated contract UTXO at `height+1` (1 photon).
- `vout[1]` — the FT reward going to your miner pubkey hash (50,000
  photons for GLYPH).
- `vout[2]` — the `OP_RETURN` msg marker bound into the preimage.
- `vout[3]` — change back to your funding address.

If the shape doesn't match, do **not** broadcast. Re-read the
preceding steps and check that you fed `pow_result.input_hash` /
`pow_result.output_hash` (not `pow_result.preimage` halves) into
`build_mint_scriptsig`. Splitting the sources is the M1 covenant-
rejection footgun the 0.5.0 signature change exists to prevent — see
the [migration guide](../how-to/migrate-0.4-to-0.5.md) for the full
story.

---

## Step 5 — Broadcast

Once the dry-run looks clean, re-run with the broadcast handshake set:

```bash
DRY_RUN=0 \
I_UNDERSTAND_THIS_IS_REAL=yes \
MINER_WIF="<your funded WIF>" \
CONTRACT_TXID="<txid from Step 0>" \
CONTRACT_VOUT="<vout from Step 0>" \
EXTERNAL_MINER="/usr/local/bin/glyph-miner --stdin" \
python examples/dmint_claim_demo.py
```

Both env vars are required for the broadcast to happen. The script
refuses to broadcast unless `I_UNDERSTAND_THIS_IS_REAL=yes` is set
literally — this is a deliberate three-key handshake because a
mistaken `DRY_RUN=0` would otherwise be silently destructive.

On success the script prints:

```
✓ Broadcast result: <txid>
```

That txid is your mint. It will confirm in the next Radiant block;
your wallet will hold 50,000 new GLYPH-emission photons (= 0.0005
GLYPH at 8 decimals) at the funding address.

### If the broadcast fails

The two common failure modes:

- **Contract advanced under you.** Between the time you fetched the
  contract state and the time you broadcast, another miner claimed
  the same height. The covenant will reject your transaction. The
  script prints the rejection reason and exits with code 3; re-run
  the whole script (it will fetch the new contract tip and re-mine).
- **WebSocket dropped during the mining loop.** The mining sweep can
  take minutes; idle WebSocket connections can be closed by the
  server. The script opens a fresh `ElectrumXClient` just for the
  broadcast call to mitigate this, but if it still fails you have
  the raw tx hex from Step 3 — re-broadcast it through any other
  path (a different ElectrumX server, `radiant-cli sendrawtransaction`,
  etc.) without re-mining.

---

## What you have learned

You now know the end-to-end shape of a V1 dMint mint on Radiant
mainnet:

- How to locate unspent contract UTXOs with `find_dmint_contract_utxos`.
- How to pick a plain-RXD funding input safely with
  `find_dmint_funding_utxo`.
- How `build_dmint_v1_mint_preimage` ties the PoW preimage and the
  two scriptSig hashes together at the type level — the safety
  property the 0.5.0 signature change is built around.
- How the `EXTERNAL_MINER` JSON-over-stdio protocol delegates the
  nonce sweep without coupling pyrxd to GPU dependencies, and what
  the supply-chain caveats are.

For the protocol-level detail behind any of the above, see the
[V1 dMint deploys concept page](../concepts/dmint-v1-deploy.md). For
the runnable reference,
[`examples/dmint_claim_demo.py`](https://github.com/MudwoodLabs/pyrxd/tree/main/examples/dmint_claim_demo.py)
is the canonical script — every snippet on this page is a transcription
of one section of it.
