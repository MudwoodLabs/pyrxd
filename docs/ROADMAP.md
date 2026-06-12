# pyrxd roadmap — recommended implementation order

_Written 2026-06-07; committed (sanitized for the public repo) 2026-06-11. Synthesizes the 24 plans in
`docs/plans/`, open issues (#123/#44/#10/#8), the CLI-fuzz PR, and two 2026-06-07 expert-panel reviews
(bridged-asset feasibility + swap-marketplace demand)._

**Status delta since 2026-06-07:** Tier 0.1 is done (#175 CLI fuzz and the FT↔ETH swap PR both merged);
3.2 HD multipath recovery shipped (#158); 3.3 dmint subpackage split shipped (#109); watchtower v2
(dust-capped BTC refund) + alert-only ETH watching shipped (see `src/pyrxd/gravity/watch/README.md`);
issue #123 is closed. Tier 0.2/0.3 and all of Tier 1 remain open.

## Framing (what this project actually is)

pyrxd is a **low-mcap, community-driven** project. The near-term goal is **to attract developers to build
on Radiant** — not to ship real-value production rails. Two consequences set the entire order:

1. **An external audit is a *future* item, not a gate on near-term work.** The audit only blocks
   *real-value mainnet* swaps. Devs build on **testnet/regtest, where there is no audit gate** — so the
   whole developer platform can be built and shipped now, with the audit deferred until there's budget
   and a production reason.
2. **Devs come for usable, documented, Radiant-*unique* primitives and a fast time-to-first-success** —
   not a production exchange. So developer experience (DX), packaged primitives, examples, and local
   testnet tooling rank *above* production features.

The panels' core lesson still holds, just re-pointed: **don't over-build speculative infrastructure —
ship usable primitives, see what devs actually build, support that.** The "demand" to validate is now
*developer* demand (adoption, forks, people building), measured by shipping + showcasing, not a
real-money market.

---

## TIER 0 — Clear the deck (days; cheap; do now)

| # | Item | Why |
|---|------|-----|
| 0.1 | ~~Merge/close in-flight PRs (FT↔ETH swap; **#175** CLI fuzz)~~ ✅ done | Don't carry open branches forward. |
| 0.2 | Cleanup: refund the orphaned ETH HTLC after timeout; retire the exposed test key | Hygiene; finish the FT-swap run cleanly. |
| 0.3 | **#44** security baseline (harden the 4 public repos) | Cheap, finishes a started sweep; a clean repo is itself a dev-attractor. |

## TIER 1 — The developer on-ramp (the new #1 — this is how you attract devs)

| # | Item | Why it's #1 |
|---|------|-------------|
| 1.1 | **Packaging + 5-minute quickstart + runnable examples.** `pip install pyrxd` → issue a Glyph FT/NFT, build a covenant, run a swap **on regtest** in <20 lines, each a copy-paste example. | **Time-to-first-success is the single biggest dev-attractor.** A dev who mints a token in 5 minutes stays; one who fights setup leaves. No audit, no real value — pure DX. |
| 1.2 | **One-command local regtest + a testnet faucet/guide.** | Where devs actually start. Frictionless iteration with zero real-value/audit concerns. The sandbox is the funnel. |
| 1.3 | **Clean, typed, documented SDK surface** for the primitives (Glyph tokens, covenants, SPV, swap legs) + an API reference. | Reduces integration friction; signals a maintained, buildable library. |
| 1.4 | **Showcase the differentiators.** Publish the cross-chain swap demos (live txids + the Discord post), an examples gallery, and a "what you can build on Radiant" page. | Proof + inspiration is what pulls builders in. The hard demos are already done — package and broadcast them. |

Sprint-level breakdown: `docs/plans/2026-06-07-sprint-tier1-dev-onramp.md`.

## TIER 2 — Package the Radiant-unique primitives as reusable, testnet-ready library features

These are the "wow, Radiant can do that?" capabilities. Shipped as **library + regtest/testnet**, they
attract devs **without the audit gate** (no real value moves).

| # | Item | Why here |
|---|------|----------|
| 2.1 | **Cross-chain atomic swap as a clean library primitive** (regtest/testnet-first): the coordinator + legs packaged for devs to embed. | The headline capability — trustless RXD/Glyph ↔ ETH proven live. As a *library* it's a magnet for cross-chain builders. |
| 2.2 | **#123 same-chain swap API** (SIGHASH_SINGLE\|ANYONECANPAY / RSWP builder — Glyph↔Glyph/RXD). | A composable Radiant-native building block; lower risk (same-chain, no counter-leg). |
| 2.3 | **Base + Bitcoin-family counter-legs as testnet capability** (Base native-ETH leg + Litecoin cheapest first; then USDC/DOGE/BCH). | "Swap RXD/Glyphs against ETH/USDC/BTC" is a headline that attracts cross-chain devs; on testnet it needs no audit. |
| 2.4 | **Token + covenant building blocks** documented as composable primitives (FT/NFT/dMint standards, the covenant builders, the REF gate). | The genuinely differentiated tech — native tokens + covenants on a UTXO chain — made easy to build on. |

## TIER 3 — Contributor & user quality (ongoing; makes the project healthy and adoptable)

| # | Item | Why |
|---|------|-----|
| 3.1 | **CLI hardening + UX**: ~~**#175/#10** fuzz~~ ✅, **#8** mnemonic re-entry / agent-unlock pattern. | A solid CLI is many devs' first touch. |
| 3.2 | ~~**HD wallet multipath recovery**~~ ✅ shipped (#158). | Wallet robustness; user trust. |
| 3.3 | ~~**dmint `dmint.py` subpackage split**~~ ✅ shipped (#109) + general refactors. | Contributor code-health — a clean codebase attracts contributors. |
| 3.4 | **Watchtower** (operator tooling; v1 + dust-capped v2 + alert-only ETH shipped; broader autonomy later). | Operational tooling for anyone running swaps. |
| 3.5 | **Docs depth + CONTRIBUTING + architecture overview.** | Lowers the barrier to *contributing*, not just consuming. |

## TIER 4 — Production / real-value / future (deferred: needs audit + budget + demand + legal)

| # | Item | Why deferred |
|---|------|--------------|
| 4.1 | **External security audit** of the swap trust boundary. | A *future* item — commission when there's budget and a real-value production reason. Until then, keep mainnet to deliberate dust demos. |
| 4.2 | **Real-value mainnet swaps / an RFQ desk / a real market.** | Audit-gated *and* demand-gated (the marketplace panel: start with a concierge test, mind the HTLC free-option). Not the near-term goal. |
| 4.3 | **A bridged stablecoin on Radiant** (federated-first; SPV-trustless later). | Demand-gated *and* regulated — build only once a native-asset economy needs a standing dollar; a regulated product needing a legal entity, not a covenant. |
| 4.4 | **Bridged-BTC research; NFT swap covenant; more counter-chains (Solana/Cosmos).** | Research-/capital-/demand-gated; pursue with a specific reason. |

---

## The spine in one line
**Clear the deck → build the developer on-ramp (DX + examples + local testnet + showcase) → package the
Radiant-unique primitives (swaps, tokens, covenants) as testnet-ready library features → keep the
codebase contributor-friendly → and defer all real-value/audited/regulated production (the RFQ market,
bridged assets, the audit itself) to the future, when adoption + budget justify it.**

The pivot from a production roadmap: **attract builders with great primitives on testnet now; the
audit and real-value rails come after there are devs and a reason to need them.**
