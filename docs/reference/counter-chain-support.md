# Counter-chain and asset support

This page states exactly which **counter chains** and which **assets** the pyrxd
cross-chain swap stack can trade a Radiant asset against, and — separately — how much
proof stands behind each combination. It is a lookup table, not a recommendation:
"supported" here means *the code will build and drive that swap*, never *this has been
shown safe*.

**Security posture.** The cross-chain swap stack is **UNAUDITED**. No entry in any
table below changes that, including the mainnet-proven ones. The in-code audit gate
(`require_audit_cleared` in `src/pyrxd/btc_wallet/htlc_leg.py`) has been non-blocking
since 0.9.0 and is *advisory*: it will not stop you moving real value, and it is not a
substitute for an audit you commission yourself.

**Source of truth.** Every row is derived from the source and cites the file and symbol
that makes it true. Where a row claims an on-chain run, the artifact is named so you can
open it in an explorer rather than take this page's word for it. Combinations with no
run say **not run** — there are no inferred maturity levels here.

Narrative introduction: [Gravity](../concepts/gravity.md). Task instructions:
[How-to: build a cross-chain atomic swap](../how-to/build-a-cross-chain-swap.md). Proof
artifacts with explorer links: [showcase](../showcase.md).

## 1. What the two sides are

**The Radiant side** is one of three asset variants — `ASSET_VARIANTS` in
`src/pyrxd/gravity/swap_state.py`:

| Variant | Asset | Covenant builder |
|---|---|---|
| `rxd` | plain RXD | `build_htlc_covenant_rxd` |
| `ft` | a Glyph fungible token | `build_htlc_covenant_ft` |
| `nft` | a Glyph NFT (singleton) | `build_htlc_covenant_nft` |

**The counter side** is one of two *families* — `COUNTER_CHAINS` in the same module:

| Family tag | Meaning | Concrete chain pinned by |
|---|---|---|
| `"btc"` | PoW-depth chain (Bitcoin-family, BIP341 Taproot) | the bech32 HRP `network` tag |
| `"eth"` | finalized-checkpoint chain (EVM) | the EIP-155 chain id |

`counter_chain` names the **family**, not the chain: a Litecoin swap is still `"btc"`,
and a Base swap is still `"eth"`. The concrete chain — and with it the safety
parameters — comes from the registries in §3 and §4. An ERC-20 swap is also `"eth"`:
the token changes the *unit*, not the chain (`NegotiatedTerms.token_address` refuses any
other combination).

## 2. How to read the "highest proof reached" column

| Level | What was on the line | What it does **not** mean |
|---|---|---|
| **mainnet ↔ mainnet** | Real value on both chains, both legs settled on a public chain | Not an audit, and not an adversarial two-party proof — these were single-operator dust runs |
| **mainnet ↔ testnet** | Real value on the Radiant leg only; the counter leg was faucet value on a testnet | Nothing at all about that counter chain's mainnet |
| **fork + regtest** | The real counter-chain contract state, forked locally (anvil), against a Radiant regtest node | No transaction ever reached a public chain |
| **regtest** | Both sides on isolated local nodes, real node consensus on both | No real value, no public chain |
| **not run** | The chain/asset is wired, and fails closed if you get it wrong, but no run of any kind has exercised it | Not "broken" — unproven |

The regtest lanes marked below run in the **nightly** `nightly-cross-chain` and
`nightly-btc-family` jobs (`.github/workflows/integration.yml`), not on every push. The
mainnet-fork lanes are **not in CI at all** — they need an external archive RPC, so they
are a local gate someone has to choose to run.

The four **fork + regtest** rows were run green on 2026-08-25:
`tests/test_xchain_erc20_usdc_lifecycle_e2e.py`, 8 passed against an Ethereum L1 fork
(USDC and USDT on chain 1) and 8 passed against a Base fork (USDC and USDT on chain
8453). Every other row records the proof that exists in the repository, not a run.

Reproducing the Base lane needs an **archive** endpoint: anvil fetches state behind the
tip, and an endpoint that serves ordinary calls but refuses archive ones fails deep
inside the swap looking like a code bug rather than at startup. The suite header names
endpoints measured working.

## 3. Bitcoin-family counter chains (`counter_chain = "btc"`)

Registry: `KNOWN_POW_CHAINS` in `src/pyrxd/btc_wallet/chains.py`. The Taproot-HTLC leg
is chain-agnostic across the family, so adding a chain does not touch the coordinator;
what *is* chain-specific is the block interval, which sizes every blocks↔seconds safety
margin.

| Chain | Network tags (mainnet / testnet / regtest) | Block interval | Counter asset | Radiant asset | Highest proof reached |
|---|---|---|---|---|---|
| Bitcoin | `bc` / `tb` / `bcrt` | 600 s | BTC (native) | `rxd` | **mainnet ↔ mainnet** |
| Bitcoin | " | " | BTC (native) | `ft`, `nft` | not run |
| Litecoin | `ltc` / `tltc` / `rltc` | 150 s | LTC (native) | `rxd` | **regtest** (leg level; see below) |
| Litecoin | " | " | LTC (native) | `ft`, `nft` | not run |

**Evidence — Bitcoin mainnet ↔ Radiant mainnet.** One dust swap, both legs real value.
Re-read from the two chains on 2026-08-25 rather than taken from the run's own report:

- BTC claim `0e2ba620…3e8ef6e3` spends the P2TR HTLC
  `bc1p78e72e5gazcklekwtyy9j50cqv36mp43phcq9s9nu2xlsqxl84fq9vlh8d`; its witness carries
  the preimage `f683f50e…e3d854c2`.
- RXD claim `d9f8dee9…9a8f67db` spends the Radiant covenant output
  `c4882a6e…b248451b:0`; its `scriptSig` carries the **same** preimage, and it pays
  0.055 RXD to a plain P2PKH — the `rxd` variant, not a Glyph token.

Both transactions, with explorer links, are in the [showcase](../showcase.md). The same
corridor also runs as a whole-coordinator regtest e2e — Bitcoin Core and a Radiant node,
one coordinator — in the nightly `nightly-cross-chain` job
(`tests/test_xchain_swap_regtest_e2e.py`).

**Evidence — Litecoin.** Consensus level only, on two suites with different reach. The
leg-level HTLC suite runs against Litecoin Core v0.21.5.5 regtest in the nightly
`nightly-btc-family` job (`tests/test_btc_htlc_regtest_e2e.py` with
`BTC_FAMILY_CHAIN=ltc`, image built from `docker/litecoin-regtest.Dockerfile`): claim
accepted, wrong preimage rejected, premature refund `non-BIP68-final`, matured refund
accepted. The whole-coordinator e2e can also be pointed at Litecoin
(`tests/test_xchain_swap_regtest_e2e.py` with `XCHAIN_BTC_FAMILY=ltc`), but that variant
is local-only — it is not one of the CI lanes. Nothing has run on Litecoin mainnet or
testnet, and the bundled funding-reader/broadcaster backends
(`src/pyrxd/network/bitcoin.py`) are **Bitcoin-mainnet-specific**: a Litecoin deployment
supplies its own, as the regtest harness does.

**Confirmation depths are deliberately not shipped.** `KNOWN_POW_CHAINS` carries no
default depth. Depth buys reorg-resistance priced in that chain's hashrate, and "6
confirmations" folklore transfers across chains even less well than it transfers across
values — a real-value run needs a measured `MarginPolicy` sized to the target chain's
cost-to-reorg.

## 4. EVM counter chains, native ETH (`counter_chain = "eth"`, no token)

Registry: `KNOWN_EVM_CHAINS` in `src/pyrxd/eth_wallet/chains.py`. The window below is
the **steady-state lag of the `finalized` tag**, which seeds the reorg gate's
finalization reserve. Stalls are budgeted separately, in
`CrossClockMargin.eth_finality_stall_tolerance_s` — do not read the window as a worst
case. OP-stack chains permit a batch up to 12 h late, Arbitrum's sequencer
force-inclusion delay is ~24 h, and Linea's documented finality tail reaches 16 h.

| Chain | Chain id | `network` tag | Finalized-tag window | Highest proof reached |
|---|---|---|---|---|
| Ethereum | 1 | `mainnet` | 768 s | not run |
| Ethereum Sepolia | 11155111 | `sepolia` | 768 s | **mainnet ↔ testnet** (`rxd`, `ft`, `nft`) |
| Base | 8453 | `base` | 900 s | not run |
| Base Sepolia | 84532 | `base-sepolia` | 900 s | not run for native ETH (the Base Sepolia run in §5 was USDC) |
| Optimism | 10 | `optimism` | 900 s | not run |
| Optimism Sepolia | 11155420 | `optimism-sepolia` | 900 s | not run |
| Arbitrum One | 42161 | `arbitrum-one` | 1200 s | not run |
| Arbitrum Sepolia | 421614 | `arbitrum-sepolia` | 1200 s | not run |
| Linea | 59144 | `linea` | 6000 s | not run |
| Linea Sepolia | 59141 | `linea-sepolia` | 6000 s | not run |

**Evidence — Ethereum Sepolia ↔ Radiant mainnet.** Three dust runs, each with the
Radiant leg on **mainnet** and the ETH leg on the **Sepolia testnet**: plain RXD, a
Glyph NFT, and a Glyph FT. Claim transactions for both sides of each are listed in the
[showcase](../showcase.md). No swap has ever run on Ethereum **mainnet**.

**What the "not run" rows do have.** The coordinator e2e re-runs unchanged under another
chain id on a local anvil (`XCHAIN_ETH_CHAIN_ID=84532`,
`tests/test_xchain_eth_swap_regtest_e2e.py`) and the leg suite drives a full lifecycle
against a node presenting Base Sepolia's chain id
(`tests/test_eth_leg_anvil_integration.py`). That proves the leg machinery is
**chain-id-agnostic**. It does not touch the named chain, and says nothing about that
chain's finality behaviour, RPC providers, or fee market.

**Refused by design.** Two chains are excluded on the record rather than by omission,
and `evm_chain_by_id` fails closed for both:

- **Polygon PoS (137)** — its `finalized` tag is Polygon's own validator-set milestone
  finality, not Ethereum-anchored, so the Ethereum-derived window misrepresents it in
  both directions. A Polygon swap needs a finality model argued in Polygon's own
  security terms.
- **BNB Smart Chain (56)** — same reason: BSC's `finalized` tag is its own validator
  set's (Parlia + BEP-126), measured 0–2 s behind the tip against three independent
  endpoints on 2026-08-25. An Ethereum-anchored chain cannot finalize inside the 768 s
  L1 checkpoint, and inflating the window does not recover the difference — a longer
  wait buys more of BSC's security, never Ethereum's. **The blocker is the chain, not
  the token:** BSC USDT is unpinned as a consequence, and stays unpinned until that
  chain question is answered (see the BSC notes in `chains.py` and `tokens.py`).

Any chain id not in the registry is refused the same way: no vetted window, so no swap.

## 5. ERC-20 assets (`counter_chain = "eth"` with `token_address`)

Registry: `KNOWN_TOKENS` in `src/pyrxd/eth_wallet/tokens.py`, keyed by
`(symbol, chain_id)`. **Addresses are pinned, never resolved by symbol** — bridged
look-alikes report an identical `symbol` and `decimals` (measured, not assumed), so the
address is the only discriminator, and it is the thing that is pinned. A
`(symbol, chain id)` pair that is not in the table below is **refused**, not guessed
(`token_for`).

"Issuer can freeze" is the pinned `has_blacklist` capability, not a runtime probe: a
failed probe is indistinguishable from "not frozen", and that fail-open would sit on the
one gate guarding an unrecoverable loss.

| Token | Chain (id) | Pinned address | Decimals | Issuer can freeze? | Freeze predicate | Asset pin read off the live chain | Highest proof reached |
|---|---|---|---|---|---|---|---|
| USDC | Ethereum (1) | `0xA0b86991…3606eB48` | 6 | yes | `isBlacklisted` | 2026-08-23 | **fork + regtest** |
| USDC | Sepolia (11155111) | `0x1c7D4B19…379C7238` | 6 | yes | `isBlacklisted` | 2026-08-23 | not run |
| USDC | Base (8453) | `0x833589fC…bdA02913` | 6 | yes | `isBlacklisted` | 2026-08-23 | **fork + regtest** |
| USDC | Base Sepolia (84532) | `0x036CbD53…8f3dCF7e` | 6 | yes | `isBlacklisted` | 2026-08-23 | **mainnet ↔ testnet** |
| USDC | Optimism (10) | `0x0b2C639c…d097Ff85` | 6 | yes | `isBlacklisted` | 2026-08-23 | not run |
| USDC | Optimism Sepolia (11155420) | `0x5fd84259…D43130D7` | 6 | yes | `isBlacklisted` | 2026-08-23 | not run |
| USDC | Arbitrum One (42161) | `0xaf88d065…268e5831` | 6 | yes | `isBlacklisted` | 2026-08-23 | not run |
| USDC | Arbitrum Sepolia (421614) | `0x75faf114…CE46AA4d` | 6 | yes | `isBlacklisted` | 2026-08-23 | not run |
| USDC | Linea (59144) | `0x17621186…821EE1ff` | 6 | yes | `isBlacklisted` | 2026-08-23 | not run |
| USDT | Ethereum (1) | `0xdAC17F95…3D831ec7` | 6 | yes | `isBlackListed` | 2026-08-25 | **fork + regtest** |
| USDT | Optimism (10) | `0x94b008aA…8ce58e58` | 6 | **no** (established positively) | n/a | 2026-08-25 | not run |
| USDT | Base (8453) | `0xfde4C96c…a2699bb2` | 6 | **no** (established positively) | n/a | 2026-08-25 | **fork + regtest** |

All nine USDC entries are Circle's published native addresses, each confirmed by reading
`symbol()` and `decimals()` off the chain itself rather than trusting the published
list. Decimals are pinned **and** re-asserted against the chain at swap start
(`assert_token_matches_chain`): a pinned constant cannot notice a proxy upgrade, and a
runtime-only read has nothing to disagree with.

There is no Linea Sepolia USDC row: that chain is in `KNOWN_EVM_CHAINS`, no token is
pinned for it, so a token swap there is refused.

**The two freeze spellings are not interchangeable.** Measured against the live
contracts on 2026-08-25: USDC answers `isBlacklisted` and *reverts* on `isBlackListed`;
Tether's USDT is the exact reverse. A single hard-coded name made the gate revert on the
other token — which `is_blacklisted` correctly turns into a refusal, so the swap was not
unsafe, it was impossible. Carrying the predicate name per token is what makes a second
issuer representable at all.

**"No" is a positive finding, not a silent probe failure.** Optimism and Base USDT are
pinned `has_blacklist=False` on evidence: `l1Token()` returns Tether's real L1 USDT, so
these are the canonical bridge representations; neither is an EIP-1967 proxy
(implementation and admin slots empty); and an **opcode-aware** disassembly finds no
`DELEGATECALL`, `CALLCODE`, `SELFDESTRUCT` or `CREATE*`, so the contract cannot be
upgraded or replaced. (A naive byte scan reports `CALLCODE` — that byte is `PUSH`
immediate data. Absence of a byte is conclusive; presence is not.)

**Residual on those two, and it is not "no counterparty risk".** Burn is bridge-callable
against an arbitrary holder, and the L2 standard bridge is itself an upgradeable system
contract. That is bridge-governance risk rather than issuer discretion, it is a
different hazard from a freeze, and **the pre-reveal gate does not cover it** — the gate
only knows about freezes.

**Evidence — RXD mainnet ↔ USDC on Base Sepolia.** **One** dust run, 2026-08-25. The
Radiant leg carried real mainnet value; the USDC leg was **Base Sepolia testnet faucet
USDC**. This is *not* a both-sides-mainnet proof and must not be described as one.
Artifacts, re-read from both chains on 2026-08-25:

- Radiant **mainnet**: covenant funded at `421cfaeb…70577ef2:0` (1000 photons); claim
  `0bcedf65…00c6e542` spends it, with the preimage `d4260e5b…c4b0dd22` in its
  `scriptSig`.
- Base **Sepolia**: HTLC contract `0xEe54F9c4255d97A208bee0AB95369D04E4C318AE`; claim
  `0xe43c8414…2f16b3f6` (status success) emitted the **same** preimage in its event data
  and moved 1 000 000 base units — 1.000000 USDC — out of the HTLC. The token in that
  transfer log is `0x036cbd53…8f3dcf7e`, exactly the address this registry pins for USDC
  on chain 84532.

The same preimage on both chains is what makes it one atomic swap rather than two
payments. No ERC-20 swap has run on any EVM **mainnet**.

**Evidence — fork + regtest.** `tests/test_xchain_erc20_usdc_lifecycle_e2e.py` drives
the production `SwapCoordinator` from NEGOTIATED to COMPLETED, plus the refund and
crash-resume paths, against the **real** USDC and USDT contracts on an anvil fork of
Ethereum mainnet and a real Radiant covenant on a regtest node.
`tests/test_erc20_leg_fork_integration.py` covers the freeze gate, funding bounds, gas
and preimage recovery against the same real contracts. Both are opt-in
(`XCHAIN_ERC20_E2E=1` plus an archive RPC) and **neither is re-run by CI** — read this
level as *the proof exists and is reproducible on demand*, and reproduce it before you
rely on it. Selecting a Base fork
(`PYRXD_ETH_FORK_CHAIN_ID=8453`) is supported by that suite and is the only way to
exercise the `has_blacklist=False` branch of the pre-reveal gate; this page does not
record it as run.

## 6. Refused and deliberately unpinned assets

A missing token is usually a decision, not an omission. These refusals are the feature:
they turn a wrong-asset lock into a named error.

| Asset | Address | Why it is not usable |
|---|---|---|
| Arbitrum One **USDC.e** | `0xff970a61…bddb5cc8` | Bridged, not Circle-issued — a distinct contract with its own liquidity. Refused **by address**, with a message naming the native alternative (`_BRIDGED_LOOKALIKES`, `token_by_address`) |
| Optimism **USDC.e** | `0x7f5c764c…17c31607` | Same: a bridged look-alike, refused by address |
| Arbitrum One **"USDT"** | `0xfd086bc7…b69fcbb9` | Reports symbol `USD₮0` — the omnichain **USDT0** variant, a *different asset* from Tether's ERC-20. Listed among the look-alikes so a later attempt to pin it as USDT is refused by name rather than silently accepted |
| Linea **USDT** | `0xA2194392…2B93` | Deliberately **unpinned**: it *is* an EIP-1967 proxy with a populated admin slot, so the admin can swap in an implementation that freezes. "Cannot freeze today" is not the property worth pinning; "cannot be made to freeze" is |
| BNB Smart Chain **USDT** | `0x55d39832…7955` | Unpinned because of the **chain**, not the token (§4). Note for whoever pins it: it is **18 decimals**, where every token above is 6 — the first entry where the symbol alone is ambiguous by a factor of 10¹², which is what the `(symbol, chain_id)` key and the runtime decimals cross-check exist to catch |
| Polygon PoS, any asset | — | Chain refused; see §4 |
| Anything else | — | `token_for` fails closed: an unpinned address is an asset nobody vetted, and guessing ends with funds locked in a token the counterparty never agreed to accept |

**Linea USDC is *not* on this list, on purpose.** Linea's bridged `USDC.e` was upgraded
**in place** to native USDC at the same address, so `0x17621186…821EE1ff` is legitimate
and is pinned in §5.

## 7. Trust model: token corridors are weaker than native ETH

This is the most important section of the page, and it is not a maturity question — it
holds even where a corridor is fully proven.

Native ETH and BTC are held by the chain: once locked, **nobody** can stop a claim or a
refund, so the HTLC's promise — *if either party walks away, both can refund after their
timelock* — is unconditional. USDC, and any freezable token, is held by a contract whose
**issuer can freeze addresses**. The same sentence then ends with "…unless the issuer
intervenes", which converts an unconditional refund right into a conditional one and
puts a third party inside a two-party protocol.

Measured against the real USDC contract on a mainnet fork: freezing the *claimant* or
the *refundee* still leaves a recovery path, but freezing the **HTLC contract itself**
makes `claim` *and* `refund` revert — the funds are stranded **permanently**, with no
timeout to rescue them.

What the stack does about it, none of which is a fix:

1. **One fresh contract per swap**, so a contract freeze loses exactly one swap rather
   than every swap at once.
2. **A pre-reveal freeze gate inside `claim`** — not beside it — checking the HTLC
   contract *and* both parties at the chain **tip** immediately before the preimage is
   published (`assert_not_frozen_before_reveal` in `src/pyrxd/eth_wallet/erc20.py`,
   called from `Erc20HtlcLeg.claim`). It raises rather than guessing when the status
   cannot be read.
3. **A short funded window**, because exposure is the time the tokens sit in the
   contract — which cuts against the usual instinct to be generous with timelocks.

Accepted and unmitigated: check-then-reveal is a race the gate narrows but cannot close;
the freeze read is single-source, so it defends a *failing* RPC provider, not a *lying*
one; and USDC's proxy admin can change the token logic under you, where only a
`decimals` change would be caught.

Full analysis: [threat model](../threat-model.md) and
[the USDC corridor is issuer-trusted, not trustless](../solutions/design-decisions/usdc-corridor-is-issuer-trusted-not-trustless.md).
**Do not describe a token corridor as trustless.** Any user-facing description of it must
carry the issuer-trust caveat alongside the "swaps are unaudited" line.

## 8. Adding a counter chain or a token

Both registries fail closed, so the work is *stating the safety knob*, not writing a leg:

- **A Bitcoin-family chain** — add a `PowChain` to `KNOWN_POW_CHAINS` with a sourced
  `block_interval_s`, and supply a funding reader/broadcaster for it. The Taproot-HTLC
  leg and the coordinator are unchanged.
- **An EVM chain** — add an `EvmChain` to `KNOWN_EVM_CHAINS` with a **sourced**
  `finalization_window_s` (floor: `ETH_FINALIZATION_WINDOW_FLOOR_S`, 768 s — an L2
  cannot finalize faster than the L1 checkpoint it settles to), and say where the
  worst-case stall is budgeted. If the chain's `finalized` tag is not Ethereum-anchored,
  it does not belong in this registry at all.
- **A token** — add an `Erc20Token` to `KNOWN_TOKENS` with the issuer's published address
  for that chain id, `decimals` cross-checked by reading the live contract, and
  `has_blacklist` / `blacklist_fn` established **positively**. A probe that answers
  neither freeze spelling is not evidence a token cannot freeze; leave it unpinned until
  someone reads its admin surface.

Adding a row to a registry does not raise a maturity level. Update §3–§5 only when a run
actually happened, and name the artifact.
