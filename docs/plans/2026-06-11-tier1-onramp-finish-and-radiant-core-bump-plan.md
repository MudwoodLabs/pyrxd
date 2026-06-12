---
title: Tier-1 on-ramp — close the three remaining gaps + bump Radiant-Core to the latest release
type: plan
date: 2026-06-11
status: DONE — bump-now/measured chosen; v3.1.1 measured GREEN, all workstreams shipped (see Outcome)
parent: docs/ROADMAP.md → docs/plans/2026-06-07-sprint-tier1-dev-onramp.md
---

# Finish Tier 1 + update our Radiant-Core baseline

## Where Tier 1 actually stands (verified 2026-06-11)

PR #185 already shipped S1–S6. The North Star path **works end-to-end** — verified live this
session: `pyrxd regtest up` → `python examples/regtest_quickstart.py` minted a real Glyph NFT on
regtest (commit + reveal confirmed) → `pyrxd regtest down`. So Tier 1 is ~80% done. Three gaps remain.

## The discovery that reshapes this work

The dev-facing regtest needs a Docker image, `radiant-core:vX-amd64`. Two grounded facts:

1. **There is no committed Dockerfile.** The current `radiant-core:v2.3.0-amd64` was built ad-hoc
   outside the repo and never committed. A fresh dev — the whole point of the on-ramp — literally
   cannot obtain or build it. This is the real funnel leak (gap #1).
2. **We are three releases behind, across a major bump.** Latest Radiant-Core is **v3.1.1**
   (2026-06-10); we pin **v2.3.0** (April). Release-note findings (`gh release view`):
   - v3.0.0 — explicitly **non-consensus** (wallet/security hardening; HF activation: none).
   - v3.1.0 — introduces a **consensus soft fork** (`SCRIPT_SECURITY_UPGRADE`, incl. a
     `MAX_SCRIPT_STACK_MEMORY_USAGE` budget enforced as a consensus rule) **and a breaking RPC
     change** (`-rpcallowhost` now required when reaching RPC by hostname / compose service name).
   - v3.1.1 — moves `SCRIPT_SECURITY_UPGRADE` to activate **on regtest from genesis**.

   So bumping to v3.1.1 runs our consensus-validated covenant / SPV-differential suite under the
   **new** script rules. The stack-memory budget *could* reject a covenant that passed on v2.3.0.
   This is not a string change — it re-opens the regtest consensus validation. **The honest way to
   settle it is to measure it** (build the image, run the suite), not to assume either way.

   The v3.1.0 RPC break does **not** affect us: devnet reaches RPC via `docker exec radiant-cli`
   (bound to 127.0.0.1 inside the container), never over the network by hostname
   (`devnet.py:134-135`). Confirmed.

## Workstreams

### A — Committed, version-parameterized regtest Dockerfile  (foundation; low risk)
A `docker/regtest.Dockerfile` that fetches an **official Radiant-Core release binary**, verifies its
SHA256 against the release `SHA256SUMS.txt`, and wraps `radiantd`/`radiant-cli` in a small image.
- Base `ubuntu:22.04` (satisfies the binaries' Boost 1.74 + GLIBC 2.34 needs — measured via `ldd`/
  `objdump`; bullseye's glibc 2.31 is too old, bookworm's Boost 1.81 is wrong — 22.04 fits both).
  Runtime deps: `libboost-{chrono,thread,filesystem,system}1.74.0 libdb5.3++ libevent-2.1-7 libzmq5
  libminiupnpc17 libsodium23 libssl3`.
- `--build-arg RADIANT_VERSION=v3.1.1` so the image tracks "the latest release"; the SHA256 check
  pins integrity per version. We build from the official binary — no redistribution of someone
  else's binary by us.
- A `pyrxd regtest setup` (or `build`) verb + quickstart "Step 0" that builds the image, pointing
  devs to the latest Radiant-Core release. `regtest up`'s missing-image error becomes actionable
  ("run `pyrxd regtest setup`").
- Acceptance: a fresh machine with only docker + pip builds the image and `regtest up` succeeds.

### B — Bump the pinned baseline v2.3.0 → v3.1.1  (the "we need to update" part; gated on measurement)
1. Build the v3.1.1 image via Workstream A.
2. **Measure** the bump: run the consensus-sensitive suites against it —
   `test_spv_covenant_differential_deployed.py`, `test_htlc_regtest_e2e.py`,
   `test_soulbound_covenant_regtest.py`, `test_xchain_swap_regtest_e2e.py`,
   `test_xchain_eth_swap_regtest_e2e.py` (all `-m integration`). Confirm the `MakerCovenantFlat12x20`
   covenant still validates under `SCRIPT_SECURITY_UPGRADE` (stack-memory budget) and the nBits /
   CScriptNum / CSV / OP_OUTPUTBYTECODE semantics are unchanged.
3. If green → update the pin across `devnet.py` + ~15 test files + docs to `v3.1.1`. If a covenant
   now fails the stack budget → that is a real finding; stop and report (do not paper over it).
- Acceptance: the full integration suite is green on v3.1.1, OR a specific consensus-divergence
  finding is documented.

### C — CI verification of the North Star  (gap #2; depends on A)
A CI job (`integration`-gated) that builds the image via the Workstream-A Dockerfile, runs
`pyrxd regtest up` → the quickstart mint → asserts the NFT confirmed, then `down`. Closes the
sprint's stated DoD ("a CI job runs it green") so the quickstart can't rot. Likely a separate
workflow (needs docker; the default `test (3.12)` job stays fast and unit-only).

### D — Testnet faucet/guide  (gap #3; independent, low risk)
`docs/how-to/use-the-public-testnet.md`: point at the public Radiant testnet, the faucet(s), how to
get the binary from the latest release, and the same mint flow against testnet. Smallest item;
regtest already covers the core funnel, so this is the "graduate off regtest" step.

## Dependency order
```
A (Dockerfile) ─┬─► B (bump, measured) ─► repin everything to v3.1.1
                └─► C (CI North Star)
D (testnet guide) — independent, anytime
```

## The decision to make first (bump sequencing)
A and the pin interact. Two honest options:
- **Bump-now (measured):** build v3.1.1, run the consensus suite, and if green pin everything to
  v3.1.1 in this same effort. Devs + CI + tests all land on the latest, validated release.
  Risk: if the covenant fails the new stack budget, this effort grows a remediation tail.
- **Stage it:** ship A + C + D pinned to the **known-good v2.3.0** now (unblocks fresh devs + CI
  immediately, zero consensus risk), and do the v3.1.1 bump as its own follow-up with the full
  revalidation. Slower to "latest," but decouples the on-ramp from the consensus-revalidation risk.

Recommendation: **bump-now, but measured** — the suite run turns the risk into a fact within this
effort, and the user explicitly wants us current. Fall back to staging only if the measurement
surfaces a real divergence.

## Outcome (2026-06-11) — measured GREEN, all workstreams shipped

The bump risk was settled by measurement, not assumption. Built `radiant-core:v3.1.1-amd64`
from the committed Dockerfile and ran the consensus-sensitive suites against it:

- `test_spv_covenant_differential_regtest.py` — **21 passed** (nBits exponent ceiling, bin2num
  significant-bytes, OP_OUTPUTVALUE arity, sentinel direction, 20-level branch): the covenant's
  consensus semantics are **identical** under v3.1.1's `SCRIPT_SECURITY_UPGRADE`. (The soft fork's
  per-script stack budget is 64 MB per the v3.1.1 release notes; the covenant uses kilobytes —
  hence no rejection.)
- `test_htlc_regtest_e2e.py` + `test_soulbound_covenant_regtest.py` — **6 passed**.
- BTC↔RXD `test_xchain_swap_regtest_e2e.py` — **10 passed**.
- ETH↔RXD `test_xchain_eth_swap_regtest_e2e.py` — **7 passed** after fixing an *orthogonal*
  pre-existing breakage (the test predated #192's MEDIUM-1 guard and never set
  `accept_estimated_eth_margins=True`; not a bump regression).
- North Star (`pyrxd regtest up` → `examples/regtest_quickstart.py` → mint) — green on v3.1.1.

So → pinned everything to v3.1.1. Shipped: **A** committed `docker/regtest.Dockerfile` +
`pyrxd regtest setup` (embedded Dockerfile, drift-guard test); **B** the pin across `devnet.py` +
the regtest suites + dev-facing docs; **C** the `quickstart` CI job (build image → North Star →
RXD covenant consensus suites); **D** `docs/how-to/use-the-public-testnet.md` (honest: regtest is
the reliable path, testnet faucet verified best-effort — testnet faucet 502'd, mainnet faucet 200).
