---
title: "Resolve a WAVE name at the mark's own block (HashMark §7.6 form 2)"
type: feat
date: 2026-09-09
status: BUILT (phases 0-4) — SDK surface only; CLI wiring is blocked on candidate enumeration
  and deliberately not faked (see Phase 4). A seven-reviewer security panel was run against the
  built stack afterwards and its findings folded in; every fix is pinned by a two-sided test
  (passes with the fix, fails with the defect planted back).
issue: 598
depends_on: 661
---

# Resolve a WAVE name at the mark's own block — §7.6 form 2

## Overview

A HashMark attestation proves **key custody**: content hash `H` was signed by key `K`. The question
a recipient actually has is *"who is K?"*, and WAVE maps `company.rxd` to an address. Today pyrxd
answers with a present-tense lookup and refuses the inference — `names_resolving_now`,
`point_in_time: false`, plus a caveat (form 1, #594, `cli/glyph_inspect.py:990-1009`).

Form 2 would answer the real question: **what did this name point at, and who held it, at the block
that carried the mark.**

The research for this plan changed its shape twice. Both changes are in §2 and §3, and they are the
reason this document exists rather than a task list.

---

## 1. Ground truth (measured 2026-09-09 against a live Radiant mainnet node + indexer)

Sample of 250 WAVE names. **7 have multi-transaction chains (~2.8%); 243 (97.2%) were minted and
never touched.** Longest chain: 4 transactions. All 22 transactions in those chains decode with
#661's reader; **zero `unreadable`**.

**Targets really move** — 5 of the 7 chains repoint:

| name | mint target | later target |
|---|---|---|
| `first-of-the-free.rxd` | `1CPfirXZ…` | `1JBj3rQNCUY4BkMeYrURMmf4V9nrW3G8kq` |
| `custodian-gate-x7f3.rxd` | `1CPfirXZ…` | `14XmXG3dSBWZUukGT3xzS9zxpiZ53vgx1i` |
| `xxl.rxd` | `162AELcX…` | `1PwiHEAf63tFF8JWJYrKrJjGmHgaLjHZp` |
| `vodica.rxd` | `162AELcX…` | `18NAq4RW15qPBX7JseaxpsG72yj5KyCQpf` |
| `arsen444354.rxd` | `162AELcX…` | `1NCZfUHnLEKZfjFqEZto3emffMcvQ3vM2Q` |

Four facts from that sample that constrain the design:

1. **The `expires`-omission case is the norm.** 4 of the 6 chains containing an update have an
   update whose `attrs` omits `expires` while the mint carried it. Replace-vs-merge changes the
   answer for *most* real names, not for a contrived one.
2. **Height alone cannot order a chain.** `ars.rxd` has **two update envelopes at the same height
   453133**. Both happen to carry the same target, so the ambiguity is currently harmless — but
   "the target in force at block N" is undefined if two updates share N. Ordering must come from
   the spend chain.
3. **Chains contain transactions with no envelope at all** (plain transfers) — `create.rxd` is mint
   plus two envelope-less transactions. "Transfer" must be a third outcome, distinct from both
   "update" and "unreadable".
4. **An update can leave the target unchanged** (`ars.rxd`). "No change" is not the same as "no
   updates", and both must resolve.

An indexer was separately observed serving `custodian-gate-x7f3.rxd`'s **mint-time** target after
two on-chain updates had moved it — §7.6's hazard in the present tense, on a live name.

---

## 2. The finding that reshapes this work: **there is no reference implementation of "state at
block N"**

The issue says the merge rule should be taken from Photonic's `wave.ts`. Read from Photonic-Wallet
`upstream/main` and verified directly:

- **`packages/lib/src/wave.ts` contains no update logic at all** — creation helpers only.
- The real semantics live in `packages/app/src/electrum/worker/NFT.ts` (`reconcileRefTrackedNfts`):
  `attrs: { ...g.attrs, ...attrs }` — a **shallow merge, `attrs` only, one level deep**.
- **Ordering is delegated to the indexer**: `const current = refResult[refResult.length - 1]`
  (`NFT.ts:410`) — the last element of `blockchain.ref.get`'s array. Not height, not a spend walk.
- Photonic reads **only the latest** mod envelope. Intermediate mods are never read. Its stored row
  is *mint-attrs ⊕ latest-mod-attrs* — path-dependent local accumulation, not a replay.
- Its **writer does the opposite**: a full snapshot that deliberately re-asserts `expires` so an
  update "doesn't drop the expires attr". Reader merges, writer replaces. The merge site is
  **untested upstream**.

**Consequence.** Photonic computes only *current* state, by a two-element merge, ordered by an
index. An N-element replay ordered by the spend chain is **stricter than the reference and is new
semantics**. This plan must own that rather than claim to be porting a rule.

Worth noting the tension: 4 of 6 observed chains contain an update omitting `expires`, which
Photonic's own writer says it never does. Real writers are not all current Photonic, and the
reader-merge is what rescues them.

### 2.1 `expires` cannot be answered from the envelopes at all

From `waveTarget.ts`, verified: *"The indexer is the authority on renewals: any tx that spends the
name's singleton and pays >= the name's registration price to the treasury extends the expiry…
The attrs.expires written here is **display-level** and mirrors that rule."*

So **"was this name expired at block N?" is not derivable from the CBOR chain.** It depends on
treasury payments this walk does not look at. Form 2 must either implement the treasury rule or
report expiry as `UNKNOWN`. It must not read `attrs.expires` and present it as the answer.

---

## 3. What does not exist in pyrxd today

Spot-verified against `main` @ `f110251`:

- **No multi-hop walker.** `dmint/chain.py:758`, `scanner.py:289` and `rswp/tracker.py:157` each
  follow **exactly one** spend hop. `dmint/chain.py:651-654` files "following the spend chain
  forward to locate the current head" as deferred work. This is that work.
- **No Radiant header/PoW/merkle verification.** `pyrxd.spv` is Bitcoin-only and says so
  (`spv/pow.py:23-29`). The pieces exist (`get_transaction_merkle`, `get_block_header`,
  `registry.block_hash_hex`, `merkle_path.MerklePath`) but nobody has joined them for Radiant.
- **No block height on the inspect path.** `_classify_raw_tx` takes `txid_hex` + `raw` and returns
  no height, blockhash or confirmations. Form 2's "at a past block" has nothing to attach to.
- **No "provisional below N confirmations" concept** anywhere in the repo.
- **`WaveAttrs` silently drops `expires`.** Measured: real attrs keys
  `[domain, expires, name, target, target_type]`; `WaveAttrs` round-trip
  `[domain, name, target, target_type]`. A fold built on it loses the field the merge rule turns on.
- **#661 half-landed.** `glyph_envelopes` is written in `_inspect_core.py` (938/950/1073) and read
  by **nothing**. Rendering the real update `315b4630…` through `_render_txid_human` gives
  `type=unknown` / `type=mut` / `type=p2pkh` — target absent, the word "update" absent. In the
  default terminal output an operator still sees nothing.
- **`GlyphMint` refuses WAVE and MUT** (`glyph/mint.py:207-226`): pyrxd cannot currently *create*
  the data it will read. The only working `mod` spend is hand-built in
  `tests/test_mut_wave_regtest_e2e.py`.

---

## 4. Design

### 4.1 The one-line rule

> **Index for discovery, chain for proof.** An index may supply the candidate set. The walker must
> verify the candidates form a spend chain rooted at the ref, and must prove it reached the tip.

This is exactly the shape `dmint/chain.py:779-784` already uses — a scripthash match is declared
insufficient and the parsed inputs are checked — and it is what §7.6 means by not taking an index's
word.

### 4.2 The pieces

```
resolve_name_to_ref(name)        -> (ref, provenance)      UNTRUSTED, index-sourced
walk_singleton_chain(ref)        -> ChainWalk              spend-linked, tip-proved
fold_to_height(walk, height)     -> RecordAtHeight         new semantics (see §2)
attest_name_at_block(mark, name) -> WaveIdentityVerdict    form 2, or degrade to form 1
```

### 4.3 The security properties, and where each is enforced

| # | Property | Enforced by |
|---|---|---|
| 1 | Unreadable ≠ absent | already in #661's `GlyphEnvelope.kind == "unreadable"`; the walk must **degrade** on it, never skip |
| 2 | A truncated history must not read as authoritative | **tip proof**: the last transaction's singleton output must be UNSPENT (`RadiantChainIO.covenant_unspent_incl_mempool`, node-backed). A gap ⇒ degrade |
| 3 | Ordering is not height | follow spend links; a singleton's spend chain is a total order, which resolves the same-height case in §1.2 |
| 4 | One hostile source must not move both answers | the mark's block must not come from whoever supplied the name→glyph binding |
| 5 | The honest path must stay cheap and correct | 97.2% of names have no chain to walk; that path must not regress |
| 6 | Attacker-authored text never reaches a terminal raw | `_sanitize_update_fields`, keys **and** values |
| 7 | Bounded work | an explicit cap on transactions walked, following `rswp/tracker.py:154`'s `_MAX_HISTORY_FETCHES`, with the disposition on hitting it stated |

### 4.4 The verdict type

The claim must be **structurally** narrow, not narrow by docstring (`docs/solutions/test-failures/
engineering-rules-stayed-prose-until-tests-made-them-executable.md`: a rule that lives in prose
decays). Sketch:

```python
# src/pyrxd/glyph/wave_history.py
@dataclass(frozen=True)
class WaveIdentityVerdict:
    form: int                      # 1 or 2 — never a bare bool
    ref: str                       # the glyph this is ABOUT. Always present.
    binding_source: str            # "index" — how name -> ref was obtained
    binding_verified: bool         # False until a first-confirmed rule is checked on chain
    target_at_height: str | None
    height: int | None
    provisional: bool              # within the reorg window
    expiry: str                    # "unknown" — see 2.1. NOT a timestamp.
    degraded_reason: str           # "" iff form == 2
```

`form` is an int rather than a bool so "verified" is never a single flag a caller can read
optimistically, and `expiry` is a string state rather than a number so nobody can compare it.

### 4.5 Degrade paths — every one lands on form 1 with a reason

| condition | outcome |
|---|---|
| pasted script (no block) | form 1 — "form 2 needs the mark's block" |
| name unresolvable / index down | form 1 — lookup reason attached, never raised |
| any envelope in the chain is `unreadable` | form 1 — **must not** be skipped |
| spend link missing between candidates | form 1 — "history has a gap" |
| tip not proved unspent | form 1 — "could not prove this is the latest state" |
| walk cap hit | form 1 — naming the cap |
| state at N inside the reorg window | form 2 with `provisional=True` |
| name expired at N | not answerable — `expiry="unknown"` (§2.1) |

---

## 5. Phases

### Phase 0 — finish #661 and unblock the fold (small, independently useful)

- **Render `glyph_envelopes` in human mode.** It currently reaches JSON only; an operator inspecting
  a WAVE update still sees nothing. Same defect class as the PR that introduced it.
- **Fix `WaveAttrs`' `expires` loss** — either carry the raw attrs map through the fold, or add the
  field and audit its callers.
- Deliverable: `pyrxd glyph inspect <update-txid>` names the new target in the default output.
- Test: the existing mainnet fixture, asserted through the human renderer, not just `_classify_raw_tx`.

### Phase 1 — the spend-chain walker  ✅ BUILT 2026-09-09

`src/pyrxd/glyph/mutable_chain.py` — `walk_mutable_chain`, modelled on `rswp/tracker.py` (cap +
confirmation discipline + a docstring saying what the walk does NOT prove) rather than on
`dmint/chain.py` (one hop, no cap).

**THE MODEL IN §4.2 WAS WRONG, and measuring corrected it.** The plan assumed the chain was the
index's history list ordered by spend links, with four member kinds including `transfer`. Measured
on `custodian-gate-x7f3.rxd`:

```
458585  f644794b  MINT    mut out 1     <- chain
458591  315b4630  UPDATE  mut out 1     <- chain   (spends f644794b:1)
458591  2cee4847  -       no mut out             (spends 315b4630:0 and :2 - siblings)
458601  3c7b43df  UPDATE  mut out 1     <- chain   (spends 315b4630:1)
```

`2cee4847` is in the index's history, shares a block with a real update, and is spent FROM by the
next real update — **and it never touches the token.** It is not a "transfer" member of the chain;
it is not in the chain at all. The walk follows **one mutable output at a time**, and everything
else is reported as `excluded`.

Two further invariants, both measured:

- **The ref is constant** across every mutable output in a chain (`78e25bdc…:1` from mint to tip).
  A step whose mutable output carries a different ref is a *contradiction* and raises — it would
  otherwise splice two tokens' histories together.
- **Height cannot order it**, confirmed twice: two of that name's transactions share height 458591,
  and `ars.rxd` has two update envelopes at one height.

`complete` is true only when every link verified **and** the tip is proved unspent. Everything else
returns the walked prefix with a reason — a truncated history is how a superseded value becomes
authoritative, so "I could not prove this is current" must never render as "this is current".

Verified by planting: `complete=True` without a tip proof (4 tests fail), taking the candidate list
as the chain (5 fail, including sibling exclusion), and dropping the ref check (the contradiction
test fails).

### Phase 2 — the fold  ✅ DECIDED 2026-09-09

**Decision: replay-merge — an update that omits a field leaves that field UNCHANGED.** Recorded in
`docs/solutions/design-decisions/wave-update-fold-omission-means-unchanged.md`.

The argument, not the preference: `filterAttrs` in Photonic drops `null`/`undefined` before
merging, so **deletion is not representable**. If omission meant *clear*, a field could be
destroyed only by accident and never on purpose — not a protocol anyone designs.

Measured: the two candidate rules disagree on **3 of the 7** real chains (`xxl.rxd`, `vodica.rxd`,
`arsen444354.rxd`), and **only on `expires`** — `target` is identical under both everywhere. So the
choice is about completeness, not about the answer form 2 gives today. Replay-merge also agrees
with *mint ⊕ latest* (what a freshly restored Photonic wallet computes) on **7 of 7**.

Three constraints the fold must carry, all measured:

1. **`attrs` only, one level, shallow.** Photonic never re-derives top-level mod fields from chain;
   folding them would invent state. All 22 observed envelopes carry `attrs` and nothing else, so a
   top-level field is unexpected and should be **reported**, not folded.
2. **Normalise value types.** `GlyphMetadata.attrs` is `dict[str, str]` (mint reader stringifies);
   `decode_update_payload` returns raw CBOR (native types). Merged naively, a field's type depends
   on which envelope last wrote it — and `str > int` raises in Python 3.
3. **Read envelopes directly, not via the inspect path.** `_classify_raw_tx`'s `metadata` carries no
   `attrs` at all: a WAVE mint's own target appears nowhere in its result. Tracked separately.

**Fixture ready**: `tests/fixtures/wave_fold_discriminating_chain_mainnet.json` (`xxl.rxd` — mint
with `expires`, transfer, update omitting it), with `tests/test_wave_fold_fixture_discriminates.py`
pinning that the two rules still disagree on it. A fold test over a chain where they agree would
pass whichever rule was implemented, including the rejected one.

**Code deferred to Phase 1's landing**: the fold has no production caller until the walker supplies
an ordered sequence, and a capability whose only references are its definition and its tests is not
finished.

### Phase 3 — the mark's block  ✅ BUILT 2026-09-09

`src/pyrxd/glyph/mark_anchor.py` — `resolve_mark_anchor`. `_classify_raw_tx` returns no height,
blockhash or confirmations at all, so this input did not exist.

**The confirmation floor question is answered by the repo's own doctrine, not by a new number.**
`btc_wallet/chains.py`: *"Confirmation depth must be value-scaled PER CHAIN … '6 confirmations'
folklore transfers across chains even less than it transfers across values"*, and that registry
"deliberately does NOT ship depth defaults". So `min_confirmations` is **required**, validated, and
has no default. `DEFAULT_MINT_CONFIRMATIONS = 1` is itself documented as "a conservative default
matching shipped behaviour, NOT because a rule was found requiring it".

**Radiant SPV is out of scope and declared, and merkle inclusion would NOT be a cheap middle.**
`pyrxd.spv` is Bitcoin (SHA-256d) and says so; `registry.block_hash_hex` can hash a Radiant header
but nothing checks its work or its place on the most-work chain. Fetching a merkle path and checking
it against a header the same endpoint supplied proves nothing against a hostile endpoint — with no
proof-of-work check, fabricating a header whose root commits to the transaction is free. It would
catch accidental inconsistency and look exactly like security. `UNVERIFIED_CAVEAT` rides on every
anchor and every verdict instead.

### Phase 4 — the identity statement  ✅ BUILT 2026-09-09 (SDK surface; CLI blocked)

`src/pyrxd/glyph/wave_identity.py` — `judge_name_at_mark`, pure, composing an anchor and a completed
walk. Verified end to end on the real chain:

```
mark at 458580  ->  form 1: "the name did not exist when the mark was made"
mark at 458586  ->  form 2: 1CPfirXZahPrTb93QouwBfKDoz1ykfcBb7
mark at 458595  ->  form 2: 14XmXG3dSBWZUukGT3xzS9zxpiZ53vgx1i
```

The verdict is **structurally** narrow: `form` is an int so no flag can be read optimistically,
`expiry` is a string state so nothing can compare it to a clock, `binding_verified` is False until
something checks the binding on chain.

**CLI wiring is BLOCKED, and not faked.** Form 2 needs the candidate set for a token's chain, and
pyrxd has no way to enumerate one — `RxinDexerClient` has `glyph_get_token` (a record) and no
history method. Wiring a caller that always degrades would be a caller-shaped wrapper around dead
code. The pieces are exported as consumer API (the route the reachability guard itself sanctions),
and a consumer with their own index can drive form 2 today.

The way to remove that dependency entirely: discover candidates from the chain rather than an index
— hash the current mutable output's script and ask `get_history` who spent it, one hop at a time,
which is exactly the shape `dmint/chain.py` already uses. Needs a live Radiant ElectrumX to verify,
so it is not built on assumption.

---

## 6. Risks

| risk | mitigation |
|---|---|
| **Form 2 reads as stronger than form 1 while being wrong** — the single biggest risk. Form 1's visible hedge protects users today | every degrade path lands on form 1 *with a reason*; `form` is an int, not a bool; ship Phase 0–2 behind the existing `--verify-wave` flag before making any identity claim |
| The fold invents a state that never existed on chain | §2 — choose explicitly, test on a fixture where the options differ, document the divergence |
| A stale/hostile index truncates history | tip proof (§4.3 #2) |
| Refusing honest names | 97.2% of names have no chain; an honest-path test is the first test written, per `feedback_a_guard_refusing_valid_work_is_a_bug` |
| pyrxd cannot create test data (`GlyphMint` refuses MUT) | drive everything from the real mainnet fixture; extend it from the other 6 chains rather than synthesising |
| Prose rules decaying | the verdict type carries the qualifiers as fields; docstring claims get executable checks |

---

## 7. Acceptance criteria

**Phase 0**
- [ ] `pyrxd glyph inspect` names the updated target in **default human output** for `315b4630…`
- [ ] `expires` survives whatever path the fold consumes
- [ ] Plant: revert the renderer branch ⇒ a test fails

**Phase 1**
- [ ] All 7 mainnet chains walk to a tip-proved head
- [ ] `ars.rxd`'s same-height updates are ordered by spend link, not height
- [ ] `create.rxd`'s envelope-less transactions classify as `transfer`, not `unreadable`
- [ ] Plant: remove the final transaction ⇒ the walk refuses (does not report the earlier target)
- [ ] Plant: corrupt one envelope ⇒ degrade with a reason, not a skip

**Phase 2**
- [ ] A fixture where replay-merge and snapshot differ, asserting the documented choice
- [ ] `expires` reported as `unknown`, never as a timestamp

**Phase 3**
- [ ] Height is bound to the requested txid (not merely echoed)
- [ ] `provisional` set below the stated floor, with the floor justified in the module docstring
- [ ] The verdict states that the height is the server's claim (no Radiant SPV in v1)

**Phase 4**
- [ ] Every degrade path lands on form 1 **with a reason**; asserted per path
- [ ] The form-1 shape and its placement remain exactly as `test_hashmark_wave_identity.py` pins
- [ ] No output claims authorship or location

---

## 8. Out of scope

- Radiant SPV (headers/PoW/merkle) — named in Phase 3 as a limitation, not silently omitted.
- The WAVE **first-confirmed uniqueness rule**. Until it is verified on chain, `binding_verified`
  stays `False` and the verdict names the ref rather than asserting "the name".
- Expiry (§2.1) — needs the treasury rule, which is indexer-side.
- Writing WAVE updates (`GlyphMint` refuses MUT). This plan is read-only.

---

## 9. References

**Internal**
- `cli/glyph_inspect.py:957-1009` — form 1 producer; `:990-1009` the shape; `:1000-1004` the
  hand-off comment naming form 2
- `glyph/inspector.py:58-83, 214-260, 331-407` — `GlyphEnvelope`, `classify_glyph_scriptsig`, walkers
- `glyph/payload.py:194-238` — `decode_update_payload`
- `glyph/_inspect_core.py:938-950, 1073` — `glyph_envelopes` (write-only today)
- `swap/rswp/tracker.py:154-230` — the better walker precedent (cap, confirmation gate, trust note)
- `glyph/dmint/chain.py:758-879` — one-hop walk + `_s2_verify_contract_utxos`; `:651-654` the
  deferred forward-walk
- `scanner.py:60-74` `_input_index_spending`; `swap/resolve.py:28-41` txid-bound fetch
- `tests/fixtures/wave_update_chain_mainnet.json` — the corpus
- `tests/test_mut_wave_regtest_e2e.py` — the only working `mod` spend, hand-built
- `docs/solutions/design-decisions/wave-protocol-deferred-until-consumer.md` — shape A vs B
- `docs/reference/glyph-token-protocol-spec.md:560-592` — MUT contract + `mod` scriptSig

**External (verified, not relayed)**
- Photonic-Wallet `upstream/main`: `packages/app/src/electrum/worker/NFT.ts` (the merge, ~548-563;
  ordering at :410), `packages/app/src/waveTarget.ts` (the `expires` disclaimer)

**Related**
- #598 (this), #661 (prerequisite, merged), #594 (form 1)
