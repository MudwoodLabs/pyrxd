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

## Cross-chain swaps (pre-audit)

pyrxd's cross-chain atomic swap is a **hash-timelock (HTLC) swap** driven by the
chain-neutral `pyrxd.SwapCoordinator` — trade RXD / a Glyph FT / a Glyph NFT
against BTC or ETH with no custodian. It is **pre-audit**: build and demo on
regtest/testnet, but do not move real value until the audit gate clears.

### `htlc_swap_demo.py` — no network — the current swap, START HERE
Builds the **Radiant asset leg of the current HTLC swap** end to end: the NFT
HTLC covenant, the taker's hashlock claim spend (reveals the secret), and the
maker's CSV refund spend — with the production builders, structurally validated,
no network. The on-ramp to the swap you should actually build.
→ [`../docs/how-to/build-a-cross-chain-swap.md`](../docs/how-to/build-a-cross-chain-swap.md)
For the full two-chain flow on a live regtest node, see
`tests/test_xchain_swap_regtest_e2e.py` (BTC↔RXD) and
`tests/test_xchain_eth_swap_regtest_e2e.py` (ETH↔RXD).

### Deprecated — the `gravity_*` SPV-oracle swap demos

> **Deprecated. Do not build on these.** The three `gravity_*` scripts demo the
> **retired SPV-oracle swap** construction, which is superseded by the HTLC swap
> above. Their any-wallet covenant parser has known, won't-fix security findings,
> and `gravity_full_trade.py` broadcasts real RXD mainnet value. They are kept
> only as reference for the **retained SPV verification primitive** (one-way
> bridge-in / oracle — which the HTLC swap structurally cannot replace). Why:
> [`../docs/solutions/design-decisions/spv-swap-deprecated-primitive-retained.md`](../docs/solutions/design-decisions/spv-swap-deprecated-primitive-retained.md).

- `gravity_swap_demo.py` — testnet, `DRY_RUN=1` by default — the safe SPV walkthrough.
- `gravity_live_test.py` — RXD mainnet reads + BTC testnet, `DRY_RUN=1` by default.
- `gravity_full_trade.py` — RXD mainnet, **no dry-run** (broadcasts real value;
  guarded by `I_UNDERSTAND_THIS_IS_REAL=yes`).

---

## Documentation

- Quickstart tutorial: [`../docs/tutorials/quickstart.md`](../docs/tutorials/quickstart.md)
- Tutorials index: [`../docs/tutorials/index.md`](../docs/tutorials/index.md)
