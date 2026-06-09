# pyrxd examples — a guided path

Runnable scripts that exercise the pyrxd SDK end to end. Each file has a
module docstring with its full usage, environment variables, and safety
notes — read the header of any script before running it.

Every script can be run in place from the repo root, e.g.:

```sh
python examples/regtest_quickstart.py
```

## Safety labels

These labels appear next to each example below. They are derived from the
code (default `ELECTRUMX_URL`, `DRY_RUN` gating, `BTC_NETWORK`, etc.), not
from assumption.

- **no network** — pure in-process; builds/signs txs but never connects out.
- **regtest** — runs against a local throwaway chain (`pyrxd regtest up`); zero real value.
- **testnet** — broadcasts to public test networks (needs testnet coins); no mainnet value.
- **mainnet — real value** — touches Radiant/Bitcoin mainnet. Most are
  **safe-by-default** (`DRY_RUN=1` builds but does not broadcast); one is **not**.
- **pre-audit** — the cross-chain Gravity swap covenant has not had an external
  security audit. Do not use it with real funds.

---

## START HERE

### `regtest_quickstart.py` — regtest, zero real value
Mints a real Glyph NFT end-to-end on a **local regtest chain**. This is the
companion to the 5-minute quickstart: it pulls a funded UTXO from the dev
wallet, runs the two-phase commit/reveal via `GlyphBuilder`, broadcasts through
the node RPC, and mines to confirm. No ElectrumX, no mainnet, no real value.

Prerequisite: `pyrxd regtest up` (starts the local node + dev wallet).

→ Read [`../docs/tutorials/quickstart.md`](../docs/tutorials/quickstart.md) alongside this script.

---

## Keys / HD wallets

### `mnemonic_to_key.py` — no network
Derives Radiant keys and addresses from a BIP39 mnemonic, showing both the
high-level `HdWallet.from_mnemonic` path and the low-level
`bip44_derive_xprv_from_mnemonic` primitive. Uses Radiant's SLIP-0044 coin
type **512** (not Bitcoin's 0). Runs with a public test-vector mnemonic by
default — override with `MNEMONIC=...`. Offline; derives keys only, moves
nothing.

---

## Tokens (Glyph NFT / FT / dMint)

All of these target **Radiant mainnet** and are **safe-by-default**: `DRY_RUN`
defaults to `1`, so they build and print the raw transaction but do not
broadcast unless you explicitly set `DRY_RUN=0`. They require a funded
`*_WIF` key. The two that can spend real value on broadcast (dMint) add a
second guard, `I_UNDERSTAND_THIS_IS_REAL=yes`.

### `glyph_mint_demo.py` — mainnet — real value, `DRY_RUN=1` by default
Mints a Glyph **NFT** via the commit/reveal two-phase flow over ElectrumX.
Needs a funded `GLYPH_WIF` (~5M photons). Same tx-building logic as
`regtest_quickstart.py`, but against mainnet instead of a local node.
→ [`../docs/tutorials/mint-a-glyph-nft.md`](../docs/tutorials/mint-a-glyph-nft.md)

### `ft_deploy_premine.py` — mainnet — real value, `DRY_RUN=1` by default
Deploys a plain **fungible token (FT)** with a full premine — the "issue your
own token" flow. Commit → reveal; the reveal outpoint becomes the permanent
token ref. Needs a funded `GLYPH_WIF`.
→ [`../docs/tutorials/mint-a-glyph-ft.md`](../docs/tutorials/mint-a-glyph-ft.md)

### `ft_transfer_demo.py` — mainnet — real value, `DRY_RUN=1` by default
Sends FT tokens **you already own** to another address, with the correct
on-chain FT-UTXO filter (the step in-process unit tests hide). Needs
`SENDER_WIF`, `TOKEN_CONTRACT` or `TOKEN_REF`, `RECIPIENT_ADDR`, and `AMOUNT`.

### `dmint_v1_deploy_demo.py` — mainnet — real value, `DRY_RUN=1` + extra guard
Deploys a **V1 dMint** (permissionless-mint) token: N parallel contract UTXOs
that anyone can mine independently. Broadcasting requires **both** `DRY_RUN=0`
**and** `I_UNDERSTAND_THIS_IS_REAL=yes` (a deliberate footgun guard). Needs a
funded `GLYPH_WIF`.

### `dmint_claim_demo.py` — mainnet — real value, `DRY_RUN=1` + extra guard
Mines and claims a token from a **live V1 dMint contract** (e.g. RBG): spends
the contract UTXO, runs a PoW search, and pays the miner an FT reward.
Broadcasting requires `DRY_RUN=0` **and** `I_UNDERSTAND_THIS_IS_REAL=yes`.
Needs `MINER_WIF`, `CONTRACT_TXID`, `CONTRACT_VOUT`. Note: the pure-Python PoW
search can take tens of minutes to hours at live difficulty — set
`EXTERNAL_MINER` to delegate.
→ [`../docs/tutorials/mint-from-a-dmint-contract.md`](../docs/tutorials/mint-from-a-dmint-contract.md)

---

## Same-chain swaps

### `partial_swap_demo.py` — no network
End-to-end same-chain **partial-transaction swap** (`pyrxd.swap`): a maker's
FT traded for plain RXD. Synthesises both parties' source UTXOs in memory, so
it runs with **no node and no network** — it exercises the real swap API
(signing, conservation, maker-signature re-verification) but never broadcasts.
→ [`../docs/concepts/partial-tx-swaps.md`](../docs/concepts/partial-tx-swaps.md)

---

## Cross-chain / Gravity swaps (pre-audit)

The Gravity BTC↔RXD swap covenant is **pre-audit** — it has not cleared an
external security review. Treat all three scripts as reference material; do not
use them with real mainnet value.

### `gravity_swap_demo.py` — testnet, `DRY_RUN=1` by default — pre-audit
The safe entry point for Gravity. Walks every step of a BTC↔RXD swap against
**testnet** (Radiant + Bitcoin). `DRY_RUN=1` (default) builds and prints every
tx but broadcasts nothing; `DRY_RUN=0` broadcasts to live testnets (no mainnet
value).

### `gravity_live_test.py` — RXD mainnet reads + BTC testnet, `DRY_RUN=1` by default — pre-audit
Integration test driving the Gravity SDK against **live** networks: reads from
RXD **mainnet** ElectrumX and BTC **testnet**, building txs from real covenant
bytecode and running the SPV verifier on real BTC data. `DRY_RUN=0` broadcasts
the maker-offer tx on **RXD mainnet** (real photons); the BTC side never
broadcasts.

### `gravity_full_trade.py` — RXD mainnet (+ BTC mainnet default) — NO dry-run — pre-audit
The full offer → claim → finalize / forfeit / cancel state machine. **This
script has no `DRY_RUN` mode** — it broadcasts real transactions. The BTC side
defaults to **mainnet** (`BTC_NETWORK=bc`). As a guard, on mainnet it refuses to
run unless you set `I_UNDERSTAND_THIS_IS_REAL=yes`, acknowledging irreversible
value movement. Prefer `gravity_swap_demo.py` for a safe walkthrough.

---

## Documentation

- Quickstart tutorial: [`../docs/tutorials/quickstart.md`](../docs/tutorials/quickstart.md)
- Tutorials index: [`../docs/tutorials/index.md`](../docs/tutorials/index.md)
