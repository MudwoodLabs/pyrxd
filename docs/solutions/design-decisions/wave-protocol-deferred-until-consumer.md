---
title: WAVE name-claim protocol — deferred in pyrxd until a concrete consumer needs it
status: deferred
date: 2026-05-13
category: design-decisions
related_files:
  - src/pyrxd/glyph/builder.py (existing prepare_wave_reveal)
  - src/pyrxd/glyph/types.py (existing GlyphProtocol.WAVE)
  - src/pyrxd/glyph/inspector.py (gap — no WAVE branch)
---

## TL;DR

**WAVE is a Radiant naming primitive** (`alice.rxd` → wallet address).
pyrxd has ~80% of the building blocks already; full support is gated on
a real consumer surfacing. Until then, do not invest design effort.

## What WAVE actually is (verified 2026-05-13)

Two specs exist under the "WAVE" name:

| | Shape A (whitepaper) | Shape B (live) |
|---|---|---|
| Source | `RadiantBlockchain-Community/WAVE/wave.pdf` (REP-3011) | `Radiant-Core/Photonic-Wallet/packages/lib/src/wave.ts` |
| Tx shape | 38 outputs (1 claim NFT + 37 prefix-tree branches) | 2 outputs (vanilla mutable NFT — 63-byte singleton + 174-byte MUT contract) |
| Protocol id | n/a | CBOR `p: [2, 5, 11]` (NFT + MUT + WAVE) |
| Name storage | implicit in tree position | CBOR `attrs.{name, domain, target, target_type}` |
| Uniqueness | on-chain (prefix-tree covenant) | off-chain (RXinDexer picks first-confirmed) |
| Front-running | possible (no consensus rule) | mitigated (indexer skips mempool WAVE claims) |
| Mainnet status | **no contracts deployed** | live since block 425046, mainnet genesis `115e62d96f44402c448bf76d4ca403188733b902ab0b7703d9f36333178afda4_0` |

**Photonic Wallet emits shape B. Indexers (RXinDexer) recognize shape B.**
Shape A is paper-only. pyrxd should treat shape B as the protocol of
record; implementing shape A would produce a token nobody can resolve.

## What pyrxd already has

- `GlyphProtocol.WAVE = 11` (enum value).
- `GlyphBuilder.prepare_wave_reveal()` — delegates to `prepare_mutable_reveal()`,
  which is shape-B-compatible at the script level.
- Test fixtures in `tests/test_mut_container_wave_builders.py`.

## What pyrxd does NOT have

1. **A `WaveAttrs` CBOR shape** that matches Photonic's
   `attrs.{name, domain, target, target_type}`. Current
   `prepare_wave_reveal` only looks at the top-level CBOR ``name``
   field, not at ``attrs.name``. **This is the silent-divergence risk:**
   a pyrxd-minted WAVE token would have a name that RXinDexer cannot
   find, because the indexer reads from `attrs.name` per
   `RXinDexer/electrumx/server/wave_index.py`.
2. **Inspector classifier** for `p: [2, 5, 11]`. `GlyphInspector.find_glyphs`
   has no WAVE branch — WAVE tokens are currently classified as plain
   mutable NFTs.
3. **Resolver client.** `name → address` lookup requires RXinDexer's
   REST endpoint (`/wave/resolve/{name}`). pyrxd has no HTTP indexer
   client; only the ElectrumX socket client.
4. **Name validator.** Allowed character set is
   `^[a-z0-9]([a-z0-9-]{1,61}[a-z0-9])?$` (Photonic), 3–63 chars.
   No reserved-name policy on chain; pricing tiers exist in Photonic
   source but are advisory.

## Why deferred

pyrxd ships SDK primitives, not finished apps. The gating signal for
investing in WAVE is **one concrete pyrxd consumer that needs WAVE**:

1. **Resolution caller**: a wallet or pay-link tool that has to look up
   `alice.rxd` → address. Requires (3) above plus an RXinDexer client.
2. **Mint caller**: a tool that lets users claim names from pyrxd.
   Requires (1) and (2), plus a `WaveAttrs` byte-equivalence test
   against Photonic-emitted mainnet tokens.

Neither consumer exists today. Implementing WAVE pre-emptively risks:

- **Wire-format drift** with Photonic (the M1 covenant-rejection bug
  class — see `dmint-v1-mint-shape-mismatch.md` and
  `dmint-v1-mint-scriptsig-divergence.md`).
- **Locking pyrxd to one indexer** before alternatives exist.
- **Building shape A** (the whitepaper) by mistake, which nobody else
  implements.

## When to revisit

Trigger conditions, in priority order:

1. A downstream pyrxd consumer (`radiant-pay`, `radiant-ledger-app`,
   or similar) opens an issue asking for `resolve_wave_name(name) → address`.
2. The user (or another contributor) needs to mint a name from a
   pyrxd-based tool.
3. REP-3011 is finalised and converges shape A and shape B at the
   script level — would force a redesign anyway.

If (1) or (2): the right next step is `/workflows:brainstorm` against
the actual consumer's API needs, then a plan doc, then implementation.
Plan to add (1) `WaveAttrs` CBOR shape, (2) inspector classifier, and
(3) `WaveResolver` HTTP client as three small PRs, in that order.

If (3): redesign decision — likely a major-version bump.

## References

- Live Photonic source: `github.com/Radiant-Core/Photonic-Wallet/blob/main/packages/lib/src/wave.ts`
- RXinDexer wave index: `github.com/Radiant-Core/RXinDexer/blob/main/electrumx/server/wave_index.py`
- WAVE whitepaper (shape A): `github.com/RadiantBlockchain-Community/WAVE`
- Mainnet WAVE genesis: txid `115e62d96f44402c448bf76d4ca403188733b902ab0b7703d9f36333178afda4` vout 0, block 425046
- pyrxd existing wave builder: `src/pyrxd/glyph/builder.py` (search for `prepare_wave_reveal`)
