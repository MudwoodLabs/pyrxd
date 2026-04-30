# Scope decision: pyrxd stays narrow

**Date:** 2026-04-30
**Decision:** pyrxd is a Python library and a Glyph/Gravity-focused CLI. It does not bundle a node, replace `radiant-cli`, or ship as an all-in-one wallet product.
**Status:** accepted, baseline for v0.3 planning.

## Context

After publishing 0.2.0, two scope-expanding questions came up while planning the wallet/CLI work:

1. Should we contribute Glyph awareness to Radiant Core's C++ wallet upstream?
2. Should pyrxd ship as a complete all-in-one package — bundling a node, replacing `radiant-cli`, possibly shipping a TUI/GUI?

Both ideas have appeal. Both would change what pyrxd *is*. This doc records why neither was chosen for v0.3, and what conditions would justify revisiting them.

## Companion docs

- [`radiant-core-wallet-research.md`](radiant-core-wallet-research.md) — what `radiant-cli` already does and doesn't.
- [`wallet-cli-plan.md`](wallet-cli-plan.md) — the plan for the (now narrowed) pyrxd CLI.
- [`wallet-cli-decisions.md`](wallet-cli-decisions.md) — six implementation choices for the CLI.

## The "all-in-one package" option

### Four shapes it could take

**A. Bundle a node.** `pip install pyrxd[fullnode]` would install a Radiant Core binary as a dependency, manage it as a subprocess, fall back to ElectrumX if the user opts out.

**B. Replace radiant-cli.** Ship `pyrxd` as the canonical user-facing CLI for Radiant. It speaks to whatever node is running and adds everything `radiant-cli` lacks.

**C. Ship a desktop wallet.** Wrap pyrxd in a TUI (textual / urwid) or web UI. `pyrxd ui` launches a Photonic-Wallet-equivalent for the Python crowd.

**D. Onboarding wrapper.** Ship a `pyrxd setup` command that walks users through installing Radiant Core, configuring it, syncing it, getting an ElectrumX endpoint, etc. The library itself stays unchanged.

A, B, C are scope-expanding. D is opinionated UX without scope expansion.

### Pros of all-in-one

- **One product to onboard.** `pip install pyrxd && pyrxd setup` beats "install a node, then ElectrumX, then..."
- **Differentiation.** Most chains stratify into node + SDK + 4 wallets covering 60% each. A coherent developer experience is rare.
- **Better demos.** "Zero to minted Glyph NFT in 5 minutes" is hard with three tools, easy with one.
- **Sane defaults.** Owning the stack means you can set encrypted-by-default, mainnet warnings, fee estimation that works.

### Cons of all-in-one

- **Massive scope creep.** You're now responsible for "did the node sync?" and "why is bandwidth saturated?" That's a product, not a library.
- **Maintenance multiplies.** Every Radiant Core release can break bundling. Every OS has its own packaging story. ElectrumX has its own moving parts.
- **Inherited bugs.** When `radiant-cli` has a bug, your users hit it through `pyrxd` and blame you.
- **Audience split.** App developers want a clean library import. End users want a polished wallet. Trying to be both produces something mediocre at both.
- **Politics.** Replacing `radiant-cli` is "the Python person thinks they can do better than the official wallet." Even if technically friendly, optics matter.

### Ecosystem precedent

The pattern shows up across crypto:

- **Bitcoin.** `bitcoind` + thousands of independent wallets and SDKs. Nobody made an all-in-one. Ecosystem stratified.
- **Ethereum.** Geth/Erigon for nodes, web3.py / ethers for SDKs, MetaMask / Rabby for wallets. Lanes.
- **Cosmos / Polkadot / Cardano.** Each chain has node + SDK + several wallets. Stratified.
- **Solana — closest precedent that worked.** `solana` CLI does everything in one binary. But: it was built by the foundation with a paid team. Solo developers don't ship at that scope.
- **Stellar.** Several attempts at "complete experience" tools. Most got abandoned because scope creep killed them.

### Why we're not doing A, B, or C

- **6-month-to-2-year commitment.** A real all-in-one is full-time work for a year+.
- **pyrxd is at 0.2.** Premature to commit the next year of effort to a scope expansion before we know whether the library has users.
- **Owning the user vs. serving them.** All-in-one tools say "trust me, I'll handle everything." SDKs say "I'll be a great tool for one job; use other tools for other jobs." For an OSS library at 0.2 published today, *serve* is almost always right. Owning users is a startup move requiring marketing budget and full-time attention.

### What we are doing instead

Option D — opinionated onboarding without scope expansion.

A future `pyrxd setup` command that:

- Detects whether a Radiant Core node is running locally; if not, prints the install steps for the user's platform.
- Detects whether ElectrumX is configured; if not, lists known public servers.
- Creates a wallet on first run (with the proper Enter-gate flow from [wallet-cli-decisions.md](wallet-cli-decisions.md) §6).
- Documents the three install paths: node-required, ElectrumX-only, library-only.

Cost: a week. Benefit: 80% of the all-in-one UX win at 10% of the maintenance burden. We're not packaging Windows installers, we're not on the hook for Radiant Core 2.4 changing its config format. We're just helping users navigate the ecosystem they're already in.

## The "contribute to Radiant Core" option

### What it would mean

Add Glyph awareness to the **Radiant Core C++ wallet** ([github.com/RadiantBlockchain/radiantnode](https://github.com/RadiantBlockchain/radiantnode)). Specifically:

- Detect Glyph script patterns in `IsStandard()` / `IsSolvable()` so the wallet stops marking them `nonstandard`.
- Add new RPC handlers (`getglyphs`, `transferft`, etc.) — possibly a smaller scope: just teach `listunspent` to flag Glyph UTXOs without claiming spend support.
- Modify wallet UTXO indexing to track FT amounts and NFT refs.
- Update the `listunspent` schema, manage downstream tool compatibility.

### Pros

- Benefits everyone running a node, not just Python users.
- Glyph awareness in the node wallet is a genuine missing feature.
- Meaningful upstream contribution to the Radiant ecosystem.

### Cons

- **C++ in a Bitcoin-Core fork is high-bar.** Long review cycles, conservative maintainers, narrow merge windows.
- **Long latency.** Even on merge, it ships in a future Radiant Core release. Users have to upgrade. Months between merge and broad availability.
- **Premature lock-in.** The Glyph protocol still has experimental pieces (mutable NFT, dMint PoW). Putting those in a consensus-adjacent layer locks them in too early.
- **It doesn't replace pyrxd.** Even if upstream got Glyph wallet support six months from now, pyrxd is still the answer for non-node users (web apps, services, the no-50GB-sync case).

### Ecosystem precedent

This is well-established: protocols live in node consensus rules, but token-aware wallets live at the application layer.

- **SLP on BCH.** Bitcoin ABC / Bitcoin Cash Node never had SLP support. SLP awareness lived in Electron Cash, SLPDB, slpjs, etc. The protocol was application-layer.
- **Ordinals on Bitcoin.** Ord wallet, sparrow, magic-eden indexers. Bitcoin Core itself doesn't know about ordinals.
- **Token protocols generally.** Always application-layer wallets.

Glyph fits the same pattern. Photonic Wallet (TypeScript, browser) and pyrxd (Python, server) are application-layer implementations. That's the right architecture.

### Why we're not doing it now

- v0.3 has a clear narrow scope already.
- Glyph protocol experimental pieces aren't stable enough to lock into consensus-adjacent code.
- It would take months of C++ review cycles before users see the benefit.

### When we'd revisit

If 12 months from now pyrxd has stabilized and Glyph patterns are well-understood, **a future Radiant Core PR adding `IsStandard` recognition for Glyph FT and NFT scripts** could be a high-leverage contribution. That alone (without full token-aware UTXO indexing) would let `radiant-cli`'s `listunspent` show Glyph UTXOs as `solvable: true` and stop hiding them. ~200 lines, not a wholesale rewrite.

That's a v0.4-or-later side project, not a substitute for the v0.3 wallet/CLI work.

## What this means for v0.3

The plan stands as narrowed in [`radiant-core-wallet-research.md`](radiant-core-wallet-research.md):

- **In scope:** `pyrxd glyph *` subcommands, `pyrxd address`, `pyrxd balance`, `pyrxd wallet new`, `pyrxd wallet load`. Add `HdWallet.send()`. Add a `pyrxd setup` command later in v0.3 or v0.4.
- **Out of scope:** `pyrxd send` / `send-max` / `build-tx` / `broadcast` (use `radiant-cli` if you have a node; we'll add later if onboarding friction proves real). Bundling a node. Replacing `radiant-cli`. Shipping a TUI/GUI.
- **Tabled for later:** upstream Radiant Core PR for Glyph IsStandard recognition. Reconsider once Glyph protocol is stable.

## Conditions that would change this decision

Either of these in the next 12 months would justify revisiting:

1. **Adoption signal:** pyrxd has clear users who are blocked specifically by the lack of an all-in-one experience. Not "would be nicer" feedback — actual blockers.
2. **Resource change:** pyrxd transitions from a part-time project to a funded, multi-person effort. All-in-one scope is realistic with a team, unrealistic without.

If neither happens, the narrow scope stays right.

## Lessons recorded

- **Bundle decisions are about whether you're trying to own the user or serve the user.** All-in-one = own. Library + minimal CLI = serve. For OSS at 0.2, *serve* is almost always right.
- **Ecosystem precedent matters.** Application-layer token protocols stay in application-layer wallets across every chain. Glyph won't be the exception.
- **Scope creep kills OSS projects.** The cemetery is full of "all-in-one" tools that one developer started and couldn't sustain. Resist the temptation to expand into adjacent territory until the core is stable and adopted.
