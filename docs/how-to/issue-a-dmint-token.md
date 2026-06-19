# How to issue and mine your own dMint token

**Who this page is for:** anyone who wants to launch a **permissionless,
PoW-mined fungible token** on Radiant and mine the first claim from it —
end to end, from the command line, on **testnet** (no real value at risk).
A dMint token has no premine and no central issuer: you deploy a contract
that pays a fixed FT reward to whoever finds a valid proof-of-work nonce,
and anyone (including you) mines claims from it until it's exhausted.

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
| `--max-height N` | claims allowed per contract (total supply = `reward × max-height × num-contracts`) |
| `--reward P` | photons of the FT paid per successful claim |
| `--num-contracts K` | parallel contracts to genesis (1–250); each is an independent mining lane |
| `--difficulty D` | initial PoW difficulty (1 = easiest; start here on testnet) |

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
> requires `--difficulty >= 32768` (the 2^48 target cap).

`claim-dmint` auto-detects V1 vs V2 from the contract. For an **EPOCH** or
**SCHEDULE** V2 contract you must pass the same `--epoch-length`/`--max-adjustment`
or `--schedule` you deployed with (those parameters live in the contract code,
not the on-chain state), plus `--current-time <ts>` if you want real
difficulty tracking (default 0 = always-final locktime).

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

- **It uses an external parallel miner by default** (`python -m
  pyrxd.contrib.miner`) across your CPU cores. At difficulty 1 a claim
  takes minutes; point `--miner-cmd "/path/to/glyph-miner …"` at a GPU
  miner for seconds. `--miner-cmd in-process` forces the slow pure-Python
  miner.
- **V1's nonce is only 4 bytes**, so any single attempt has roughly a 39%
  chance of containing a valid nonce. `claim-dmint` handles this the way
  real miners do — it **rerolls** an internal field and re-mines on
  exhaustion (up to `--max-rerolls`). If a sweep is too short, raise
  `--timeout`.
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
