# How to issue and mine your own dMint token

**Who this page is for:** anyone who wants to launch a **permissionless,
PoW-mined fungible token** on Radiant and mine the first claim from it —
end to end, from the command line, on **testnet** (no real value at risk).
A dMint token has no central issuer: you deploy a contract that pays a fixed
FT reward to whoever finds a valid proof-of-work nonce, and anyone (including
you) mines claims from it until it's exhausted. This guide deploys with **no
premine** — every unit has to be mined. If you want an allocation issued
alongside the mineable supply, `--premine <photons>` adds one, and
`--premine-to <address>` chooses who gets it; see
[Premine](../concepts/dmint-v1-deploy.md#premine).

This is the issuance counterpart to
[Mint from a V1 dMint contract](../tutorials/mint-from-a-dmint-contract.md)
(which mines an *existing* mainnet contract via the library). Here you
deploy your *own* contract and mine it with two CLI commands. For the
byte-level theory, see the
[V1 dMint deploy concept page](../concepts/dmint-v1-deploy.md).

```{note}
Both commands broadcast real transactions, so they need a wallet and an
ElectrumX endpoint. Do this on **testnet** first (this guide) — deploying
your own contract is the one dMint flow that doesn't require mainnet.
Every broadcast is gated; see [the broadcast gate](#the-broadcast-gate).
```

---

## TL;DR — three commands

```bash
# 1. scaffold the token metadata
pyrxd glyph init-metadata --type dmint-ft --out token.json
# (edit token.json: set ticker, name, decimals)

# 2. deploy the contract (commit -> reveal); prints the token_ref + contract outpoints
pyrxd --network testnet glyph deploy-dmint token.json --max-height 100 --reward 1000

# 3. mine + claim one reward from a contract it printed
pyrxd --network testnet glyph claim-dmint --contract <REVEAL_TXID>:0
```

Step 2 genesises a **1-photon singleton** contract; step 3 PoW-mines a
nonce and pays you `--reward` photons of the FT. Repeat step 3 (you or
anyone) up to `--max-height` times.

---

## Prerequisites

- **pyrxd installed** — `pip install pyrxd` and a created wallet
  (`pyrxd wallet new`). See
  [your first Radiant transaction](../tutorials/your-first-radiant-transaction.md).
- **A funded testnet wallet + a testnet ElectrumX endpoint.** Follow
  [Use the public Radiant testnet](use-the-public-testnet.md) to run
  `radiantd -testnet`, point pyrxd at it, and get testnet coins. The
  examples below pass `--network testnet`; set `--electrumx wss://HOST:PORT`
  (or put it in your config) so pyrxd knows where to broadcast.
- A few thousand testnet photons in a single UTXO — the deploy funds the
  contract carriers + fees, and the claim funds the FT reward + fee.

---

## Step 1 — scaffold the metadata

```bash
pyrxd glyph init-metadata --type dmint-ft --out token.json
```

This writes a `dmint-ft` template with `"protocol": ["FT", "DMINT"]`
already set (a dMint deploy rejects anything else). Edit the file to set
your `ticker`, `name`, and `decimals`.

## Step 2 — deploy the contract

```bash
pyrxd --network testnet glyph deploy-dmint token.json \
    --max-height 100 \
    --reward 1000 \
    --num-contracts 1 \
    --difficulty 1
```

| Flag | Meaning |
|------|---------|
| `--max-height N` | claims allowed per contract (total supply = `reward × max-height × num-contracts`): 1–2^31 for V1, 1–2^63−1 for V2 |
| `--reward P` | photons of the FT paid per successful claim, up to Radiant's money supply (2.1×10^18) |
| `--num-contracts K` | parallel contracts to genesis (1–250); each is an independent mining lane |
| `--difficulty D` | initial PoW difficulty (1 = easiest; start here on testnet), up to 2^63−1 |

These upper bounds are the points past which a contract built from the value could never
be minted — a state number the covenant cannot read (wider than 8 bytes), a reward no
transaction can pay, or a difficulty whose target is 0 — and `deploy-dmint` refuses anything
outside them before it touches your wallet, naming the flag. They are the same for V1 and V2,
except that V1's `--max-height` stops at 2^31 (below).
`--target-time` (V2) is at most 0xFFFFFFFF seconds in the ASERT, LWMA and EPOCH modes, whose
retarget compares it with the gap between two timestamps that are each below 2^31 in any
mint the covenant accepts, so a larger value is a spacing no mint can meet. FIXED and SCHEDULE never read
it as a number; there it only has to fit pyrxd's 8-byte encoder (up to 2^63−1).

V1's `--max-height` stops at 2^31 because a V1 contract stores its height in 4 bytes: every
mint but the last writes the next height with `NUM2BIN(height + 1, 4)`, which cannot hold
2^31, so a contract with a larger `--max-height` would stop at height 2^31−1 with mints it can
never make. Mainnet has such V1 deploys (Photonic builds them). `claim-dmint` mints them like
any other up to height 2^31−1 and refuses the mint from there; `deploy-dmint` will not create
one.

### V1 vs V2 (adaptive difficulty)

`deploy-dmint` deploys **V1** by default — the established mainnet format,
fixed difficulty. Pass `--v2` for a V2 contract with a difficulty algorithm
(`--daa-mode fixed|asert|lwma|epoch|schedule`). V2 is consensus-validated on
regtest **and** Radiant mainnet; it requires an explicit `--v2` opt-in as the
newer format. Examples:

```bash
# LWMA adaptive difficulty (retargets every block)
pyrxd glyph deploy-dmint token.json --v2 --daa-mode lwma --target-time 60 --max-height 100 --reward 1000

# EPOCH (periodic retarget; difficulty >= 32768 so target <= 2^48)
pyrxd glyph deploy-dmint token.json --v2 --daa-mode epoch --epoch-length 2016 --max-adjustment 4 --difficulty 32768 --max-height 100 --reward 1000

# SCHEDULE (pre-baked difficulty curve: [height, difficulty] pairs)
pyrxd glyph deploy-dmint token.json --v2 --daa-mode schedule --schedule '[[100, 4], [1000, 8]]' --max-height 2000 --reward 1000
```

> **EPOCH note.** EPOCH was briefly disabled while its canonical Photonic
> bytecode had an int64-overflow that bricked the contract on-chain. That fix is
> now merged upstream ([`Radiant-Core/Photonic-Wallet#2`](https://github.com/Radiant-Core/Photonic-Wallet/pull/2)
> — divide-first with the target clamped to 2^48 on both sides of the retarget
> multiply) and pyrxd byte-matches it, so EPOCH deploy is re-enabled. EPOCH
> requires `--difficulty >= 32768` (the 2^48 target cap) and a `--target-time` at
> least the `--max-adjustment` factor (e.g. `>= 4` for the default `4`).

> **`--last-time` (ASERT and LWMA).** The deployed state carries a `lastTime`
> slot — the baseline the first retarget measures against — and those two modes
> read it as a script number on the very first mint. `deploy-dmint` stamps the
> deploy time by default, which is what Photonic's own deploy does, so you
> normally never pass `--last-time`. If you do pass it, it must be a real Unix
> timestamp: the state pushes it as a fixed four-byte value, and anything below
> 2^23 (including 0) is not a *minimally encoded* script number. MINIMALDATA is
> in Radiant's mandatory script-verify flags — consensus, not mempool policy —
> so such a contract aborts on its first retarget and can never be mined. The
> deploy is refused rather than built, because nothing can fix it once the
> reveal confirms. Values above `0x7FFFFFFF` are refused too.

`claim-dmint` auto-detects V1 vs V2 from the contract. For an **EPOCH** or
**SCHEDULE** V2 contract you must pass the same `--epoch-length`/`--max-adjustment`
or `--schedule` you deployed with (those parameters live in the contract code,
not the on-chain state) — the `claim with:` line `deploy-dmint` prints already
includes them. You do **not** need to pass `--half-life` for an ASERT contract:
the claim reads the baked half-life out of the contract's own bytecode. Pass it
only to assert what you expect — a value that disagrees with the baked one fails
fast, naming the baked value, before the PoW grind.

`--current-time` is the mint's locktime; leave it unset. It defaults to the
wall-clock time when the claim is built, which is what you want. If you do pass
it, pass a real Unix timestamp at or after the contract's `lastTime`. The claim
refuses, before any mining, a mint pyrxd will not build — for example one whose
contract can no longer be minted — and says why.

The command builds a **commit** transaction (an FT-commit hashlock plus
`K` ref-seed outputs), waits for it to confirm, then builds the
**reveal** that genesises the contracts. On success it prints the
`token_ref` and one outpoint per contract:

```text
dMint contract deployed!
  commit txid:  ab12…
  reveal txid:  cd34…
  token_ref:    ab12…:0
  contracts (1):
    cd34…:0
  total supply: 100000 photons

  claim with:   glyph claim-dmint --contract cd34…:0
```

Each contract output is exactly **1 photon** — that's a consensus
requirement of the covenant, not a quirk; pyrxd enforces it. Keep the
`token_ref` and the contract outpoints; they're how you (and anyone
else) mine the token.

## Step 3 — mine and claim a reward

```bash
pyrxd --network testnet glyph claim-dmint --contract cd34…:0
```

You can also pass `--token-ref ab12…:0` to auto-discover a live (un-exhausted)
contract for the token. The command:

1. fetches the contract and its current state,
2. funds the mint from your wallet (the FT reward + change go to
   `--reward-address`, defaulting to your largest-UTXO address),
3. **PoW-mines** a SHA256d nonce that satisfies the contract target,
4. splices the nonce into the spend, signs the funding input, and
   broadcasts.

On success it prints the mint txid; the contract is recreated at
`height + 1` for the next claim.

### Mining notes

- **Size the job first.** `pyrxd glyph dmint-estimate --contract <TXID>:<VOUT>`
  benchmarks this machine's SHA256d rate and prints the expected attempts
  and an ETA. It keeps them apart on purpose: the hash rate is MEASURED,
  the attempt counts are EXACT (`2**96 / target`), and every ETA is
  PROJECTED — the aggregate rate assumes linear scaling across workers,
  which is not measured. Add `--json` for the same split machine-readably.

  ```bash
  pyrxd glyph dmint-estimate --difficulty 1        # offline, no wallet needed
  ```

- **Read the ETA as a distribution, not a countdown.** Mining is
  memoryless: hashes already spent do not shorten what remains. That is
  why the output is a mean plus p50/p90/p99, and why the live progress
  during a claim does not tick down.

- **It uses the bundled parallel miner by default**, across your CPU
  cores, with live hash rate + remaining-time quantiles on **stderr**
  (`--no-progress` to silence, `--workers N` to change the pool). Point
  `--miner-cmd "/path/to/glyph-miner …"` at a GPU miner for seconds
  instead of minutes — whether you see live progress from it depends on
  the miner: the wire protocol carries OPTIONAL progress frames on
  stderr (see `docs/concepts/parallel-mining.md`), so an updated
  external miner streams the same way; an older one just stays silent
  until it finishes, which still works. `--miner-cmd in-process` forces
  the slow single-threaded miner.

- **V1's nonce is only 4 bytes**, so any single sweep has roughly a 39%
  chance of containing a valid nonce. `claim-dmint` handles this the way
  real miners do — it **rerolls** an internal field and re-mines on
  exhaustion (up to `--max-rerolls`). Rerolling does not change the
  estimate: the total attempts you need are the same whether they are
  spent in one sweep or ten. `--timeout` caps each individual grind.

- The signed mint hex is echoed to **stderr** before broadcast, so a
  dropped connection is recoverable (re-broadcast the hex).

(the-broadcast-gate)=
## The broadcast gate

Every broadcast (the commit, the reveal, and the mint) is shown and
confirmed first. In an interactive shell you get a `y/N` prompt; in
scripts, pass `--json --yes` to skip the prompt — `--json` **requires**
`--yes`, so a script can never broadcast unconfirmed. The claim confirms
**once, before** the multi-minute grind (all the value facts are known
then), so an unattended `--json` run fails fast rather than blocking on a
prompt after the mine.

---

## Going to mainnet

The same two commands run against mainnet — drop `--network testnet`
(mainnet is the default) and point `--electrumx` at a mainnet endpoint.
On mainnet the reward photons are a real Glyph FT and the transactions
cost real RXD, so deploy with the parameters you actually want and
double-check each confirmation prompt. To mine an *existing* mainnet
dMint token (e.g. GLYPH) rather than your own, see
[Mint from a V1 dMint contract](../tutorials/mint-from-a-dmint-contract.md).
