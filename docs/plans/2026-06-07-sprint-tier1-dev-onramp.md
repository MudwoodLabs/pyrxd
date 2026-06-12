---
title: Sprint — Tier 1 developer on-ramp (make pyrxd irresistible to a new dev)
type: sprint
date: 2026-06-07
status: sprint plan — expands ROADMAP.md Tier 1; testnet/regtest only, NO audit gate, NO real value
parent: docs/ROADMAP.md
---

# 🏃 Sprint: the developer on-ramp

## North Star (sprint Definition of Done)
A developer who has never touched Radiant can:
1. `pip install pyrxd`
2. run **one command** to get a funded local regtest chain
3. **mint a Glyph token and run a swap from a copy-paste quickstart**

…in **under 30 minutes**, entirely on regtest — no real value, no audit, no docker spelunking.
When a fresh clone + the quickstart achieves that (and CI proves it), the sprint is done.

## Grounded gaps (what's missing today)
- SDK public surface is **7 export lines** — the headline primitives (`SwapCoordinator`, covenant
  builders, SPV verify, keys) are buried in submodules.
- **No dev-facing regtest** — only the in-test `_RegtestNode` in `tests/test_htlc_regtest_e2e.py`.
- 9 `examples/` exist but are **scattered with no guided path**; `docs/tutorials/` is ~empty.
- Packaging is fine (`pyrxd` console script, v0.6.1); `docs/how-to/` guides are good — build on them.

## Tasks (sized S/M/L; sequence below)

### S1 · Curate the SDK public surface — **M**
Export the ~8 things a builder actually needs from a clean top level (extend `pyrxd/__init__.py` or add
a `pyrxd.sdk` namespace): `GlyphBuilder` (have), the covenant builders (`build_htlc_covenant_ft/nft/rxd`),
`SwapCoordinator` + the legs, `verify_ref_authenticity`, the SPV `verify_payment`, key/HD basics.
- **Acceptance:** `from pyrxd import <primitive>` gives a dev the headline capabilities without
  spelunking; each has a docstring; nothing private/internal leaks into the public namespace.

### S2 · One-command dev regtest + faucet — **M**  *(highest-leverage; the funnel)*
Promote the in-test `_RegtestNode` into a dev-facing helper: a `pyrxd.devnet` module + CLI verbs
(`pyrxd regtest up | down | mine <n> | fund <addr>`), wrapping the `radiant-core:v2.3.0` regtest docker
+ a mine-to-address faucet. Print connection info + a pre-funded key on `up`.
- **Acceptance:** one command → a running, funded regtest a dev can broadcast to; `down` cleans up;
  works on a fresh machine with only docker installed.

### S3 · The 5-minute quickstart — **M**  *(depends on S1 + S2)*
`docs/quickstart.md` + a single runnable `examples/quickstart.py`: pip install → `regtest up` → mint a
Glyph FT → transfer it → (stretch) a regtest swap. Copy-paste, end-to-end, **verified in CI**.
- **Acceptance:** a fresh clone + the quickstart hits the North Star in <30 min; a CI job runs it green.

### S4 · Audit + index the 9 existing examples — **M**
Make each `examples/*.py` runnable on regtest (or clearly labeled testnet/mainnet), add a header
(what it shows + how to run), and an `examples/README.md` index: *start here → quickstart; then tokens,
swaps, dmint, SPV.*
- **Acceptance:** every example runs or is clearly labeled; the index gives a guided path, not a pile.

### S5 · The showcase page — **S**
`docs/showcase.md` "What you can build on Radiant": the **live cross-chain swap demos** (real txids from
this week — BTC/NFT/FT ↔ ETH), native tokens, covenants, each linking to a runnable example.
- **Acceptance:** a link-rich, proof-backed page a dev lands on and thinks "I want to build this."

### S6 · API reference build — **S**  *(depends on S1)*
Ensure the curated surface has docstrings and the existing Sphinx setup (`docs/_build`) renders a clean
**API reference** for the public namespace; wire it into CI/publish.
- **Acceptance:** a buildable/hosted API ref covering the public SDK surface.

## Sequence
```
S1 (SDK surface) ─┐
                  ├─► S3 (quickstart) ─► S4 (examples) ─► S5 (showcase)
S2 (dev regtest) ─┘                                   └─► S6 (API ref, after S1)
```
Do **S1 + S2 in parallel first** (the foundation). S3 is the keystone (it's the North Star path). S4/S5/S6
build on top and can overlap.

## Why this order
**Time-to-first-success is the whole game** for dev attraction, and it's gated on two things a new dev
hits in minute one: *can I import the thing I want* (S1) and *can I run a chain to try it* (S2). The
quickstart (S3) is the single artifact that proves the North Star; examples/showcase/API-ref (S4–S6)
convert a curious visitor into a builder. None of it touches real value or the audit gate — it's pure
DX, shippable now by a low-mcap community team.

## Out of scope (deliberately)
Real-value mainnet, the RFQ market, the counter-leg *production* paths, bridged assets, the audit — all Tier 3/4.
This sprint is **only** the "make a new dev succeed on regtest in 30 minutes" funnel.
