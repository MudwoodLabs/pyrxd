# dMint V1 Deploy (M2) — Brainstorm

**Date:** 2026-05-08
**Status:** Brainstorm (pre-plan)
**Owner:** eric
**Builds on:** [`docs/brainstorms/2026-05-07-dmint-integration-brainstorm.md`](2026-05-07-dmint-integration-brainstorm.md) (the M1/M2/M3 split)
**M1 PR:** [#65](https://github.com/MudwoodLabs/pyrxd/pull/65) (V1 mint shipped; V1 builders, miner, helpers all public)

## What We're Building

V1 dMint deploy support in pyrxd. After M2, a developer can issue a
fresh V1 dMint token end-to-end: commit + reveal + N parallel contract
UTXOs at the same codescript-hash, in the byte format every ecosystem
tool (glyph-miner, RXinDexer, Photonic explorer) recognizes. Plus the
chain helper that lets the M1 mint demo find live contracts without
manual outpoint pasting.

## Why This Matters

`prepare_dmint_deploy` today emits V2 contracts and refuses to run
unless the caller passes `allow_v2_deploy=True`. That guard prevents
accidental footguns but also means **pyrxd cannot deploy a usable
dMint token at all** — V2 has no live mainnet instances, and no
ecosystem miner targets it. M2 closes the gap by letting pyrxd issue
V1 tokens that match what's already on-chain.

## What's Already Done (from M1)

These ship in PR #65 and M2 reuses them unchanged:

- `build_dmint_v1_state_script` — 6-item V1 state
- `build_dmint_v1_code_script` — 145-byte V1 epilogue with algo selector
- `build_dmint_v1_contract_script` — combined 241-byte contract output
- `build_dmint_v1_ft_output_script` — 75-byte P2PKH+tokenRef reward
  (mint-side, but the FT-shape primitive is shared)
- `is_token_bearing_script` — opcode-aware classifier
- `find_dmint_funding_utxo` — wallet scanner for plain-RXD funding
- The `_V1_ALGO_BYTE_TO_ENUM` mapping
- `DmintMinerFundingUtxo`, `DmintContractUtxo` dataclasses
- `DmintError` hierarchy

## What M2 Adds

**Three new pieces**, in order of size:

1. **Phase 2a — research** (no code; finishes when the exit criteria
   below are met):
   - Read Photonic Wallet's V1 deploy code in `packages/lib/src/mint.ts`
     and `packages/lib/src/script.ts` end-to-end
   - Walk forward from RBG's deploy commit `a443d9df…878b` on mainnet
     to find the actual reveal tx; decode it byte-by-byte
   - Document findings in a new `docs/dmint-research-photonic-deploy.md`
     or extend `dmint-research-mainnet.md` §6

   **Exit criteria** (Phase 2a is done when):
   - Commit-tx output layout captured byte-for-byte (vout count, value,
     ref-seed P2PKH structure)
   - Reveal-tx output layout captured byte-for-byte (vout count,
     contract output positions, FT premine if any, OP_RETURN if any)
   - CBOR `dmint:{...}` payload shape Photonic emits for V1 documented
     (which fields populated for V1 vs V2)
   - Per-contract `contractRef` derivation rule from commit ref-seed
     outpoints documented
   - At least one mainnet V1 deploy reveal saved as a fixture
     (hex-encoded), suitable for byte-equal assertions in Phase 2b

2. **`prepare_dmint_v1_deploy(params)`** — new public function in
   `builder.py`, parallel to V2's `prepare_dmint_deploy`. Returns
   commit + reveal + N parallel contract scripts. Reuses the M1 V1
   builders for the contract output.

3. **`find_dmint_contract_utxos(client, token_ref)`** — chain helper
   returning all live contract UTXOs for a token. Uses the codescript-
   hash listunspent primitive against ElectrumX. ~30 lines.

**Plus**: the `dmint-followup.md` stale banner rewrite that was
deferred to M2 also lands here. (The V1-default flip is in Key
Decisions.)

## Why This Approach

**Approach 1 (Research-first)**: spend ~1.5 hours on Phase 2a before
any code lands, so Phase 2b's tests are byte-equal against captured
canonical bytes from day one.

The M1 incident pattern was clear:
- Round 1 review caught a wrong V1 mint output shape (2 outputs vs
  mainnet's 4; plain P2PKH instead of FT-wrapped reward)
- Round 2 caught the funding-UTXO byte-scan DoS
- Round 4 caught a 1-byte fee underestimate causing 25% rejection rate

All three were "synthetic tests through pyrxd's own parser passed; the
spec said something different." The lesson, captured in
`docs/solutions/logic-errors/dmint-v1-mint-shape-mismatch.md`: **every
wire-format builder needs at least one byte-equal golden vector
against captured mainnet bytes**.

V1 deploy is the most byte-intricate part of the protocol (multi-
output commit, ref-seed derivation, parallel contract reveal, CBOR
metadata). It's exactly the surface most likely to bite us if we
infer instead of read. Per the project convention, Photonic's TS
source is the default reference for "what does the live ecosystem
expect" — deviate explicitly, with a documented reason, only when
Photonic is wrong.

Rejected:
- **Approach 2 (Implement-first)**: violates the M1 lesson. Almost
  certainly produces a wrong-bytes commit caught at the VPS tier or
  at first review — same shape as the M1 structural bugs.
- **Approach 3 (V1 deploy only, defer chain helper)**: the helper has
  two known consumers (M1 mint demo + M2 deploy verification); the
  architect-strategist review pulled `find_dmint_funding_utxo` forward
  into M1 closeout for exactly this reason. Shipping it with M2 lets
  the round-trip test be `deploy → list contracts → mint one`
  end-to-end without manual outpoint pasting.

## Key Decisions

1. **Multi-contract V1 from day one.** `num_contracts > 1` is the
   mainnet-canonical shape (RBG-class tokens have 7+ parallel contract
   UTXOs from one deploy). Shipping single-contract first would
   produce non-canonical tokens that need migration when multi-contract
   lands.

2. **Photonic TS source is the canonical reference.** Phase 2a reads
   `packages/lib/src/mint.ts` end-to-end before any V1-deploy code
   lands. Per the saved feedback memory.

3. **No `initial_pool_photons` for V1.** V1 contracts are singletons
   (1 photon each, perpetually). The miner's funding input pays
   reward + fee. V1 deploy params accept `num_contracts` instead;
   total photons committed at deploy = `num_contracts × 1` + premine
   + commit/reveal fees.

4. **Three-tier acceptance gate (same as M1):**
   - Synthetic: deploy V1 via pyrxd, parse back, mine one contract
     via M1 mint code — all unit tests
   - VPS testmempoolaccept: push the deploy commit + reveal to the
     existing radiant-cli node (harness reusable from
     `tests/test_dmint_deploy_integration.py`)
   - Real mainnet: actual fresh V1 deploy. Manual gate. Implies a
     "what's the token name" decision before broadcast.

5. **`find_dmint_contract_utxos` returns ALL live contracts (plural).**
   Caller picks one to mine. Matches what glyph-miner does. Minimal
   SDK opinion.

6. **`prepare_dmint_deploy` default flips to V1 when M2 lands.** V2
   keeps the `allow_v2_deploy=True` guard. The flip is the moment the
   M1 footgun mitigation can be relaxed: V1 deploy becomes the safe
   default; V2 stays as explicit opt-in. Spelled out here because
   the flip is the user-visible API change of M2 — anyone calling
   `prepare_dmint_deploy(...)` without args will get V1 behavior
   after M2 ships, V2 behavior before.

## What Phase 2a Should Capture

Concrete deliverable for the research phase, before Phase 2b code:

- Photonic's commit-tx output layout (vout count, ordering, ref-seed
  P2PKH structure, value of each ref-seed output)
- Photonic's reveal-tx output layout (vout count, contract output
  layout, where the FT premine output sits, where the OP_RETURN sits
  if any)
- The CBOR `dmint:{...}` payload shape Photonic emits for V1 deploys
  (which fields are populated for V1 vs V2)
- The contract-ref-derivation rule: how does each parallel contract's
  `contractRef` relate to the commit's ref-seed P2PKH outpoint?
- One byte-decoded mainnet V1 deploy reveal (RBG or another live
  token) saved as a fixture in `docs/dmint-research-photonic-deploy.md`
  for byte-equal testing in Phase 2b

## Out of Scope

Punted to M3 (deferred indefinitely):
- V2 deploy live-network proof
- V2 mint against pyrxd-deployed V2 tokens
- BLAKE3 / K12 algo support on the mint side
- EPOCH / SCHEDULE DAA modes

Out of scope, period:
- Native fast miner (always glyph-miner's job)
- Issuing a public mainnet token under the Mudwood Labs name (separate
  decision; not blocked by M2 code being ready)

## Open Questions

### Phase 2a will close these

These are unknowns *today* but Phase 2a's research closes them
mechanically — they are not decisions for the plan author.

- **OP_RETURN msg in the deploy reveal?** The mint trace includes
  one. Does Photonic emit one for the deploy too? The byte-by-byte
  reveal decode in Phase 2a settles it.

- **`contractRef` derivation rule.** How does each parallel contract's
  `contractRef` relate to its commit ref-seed P2PKH outpoint?
  Photonic's `mint.ts` and the byte-decoded reveal will show this
  exactly.

- **CBOR shape for V1 deploys.** V1 contracts have no DAA; does
  Photonic omit `daa`/`target_block_time`/`half_life`/`window_size`
  from the CBOR, or include them as null/zero? Read Photonic's
  payload builder.

### Plan-stage decisions

These survive Phase 2a and require a plan-author judgment call.

1. **Unified vs split deploy-params dataclasses.** Do V1 and V2 share
   `DmintFullDeployParams` with version-specific fields (current
   shape but bigger), or get separate `V1` / `V2` variants? The
   Pythonic-review and architect-strategist M1 reviews flagged the
   unified-but-polymorphic signature as a code smell; M2 is the
   natural place to fix it.

2. **V1 deploy public API: `target` or `difficulty`?** V1's contract
   builder takes `target` directly; V2 callers pass `difficulty`.
   Photonic's TS likely takes `difficulty` (Phase 2a confirms). For
   the public API: match Photonic for ecosystem parity, or keep
   `target` for consistency with the V1 internal builder?

3. **`find_dmint_contract_utxos` input shape.** `token_ref` (the
   token's deploy outpoint) or `contract_codescript_hash` (the
   precomputed scripthash ElectrumX listunspent uses)? Probably both
   — `token_ref` for the public API, internally compute the
   codescript-hash. Plan-author decision.

4. **Stale-doc banner timing.** `dmint-followup.md` got a banner in
   M1; the original brainstorm said full rewrite lands in M2. Confirm
   the rewrite is in scope here, or push to M2 closeout / a separate
   docs PR.

## References

### Internal
- [`docs/brainstorms/2026-05-07-dmint-integration-brainstorm.md`](2026-05-07-dmint-integration-brainstorm.md) — original M1/M2/M3 split
- [`docs/plans/2026-05-07-feat-dmint-v1-mint-and-reference-miner-plan.md`](../plans/2026-05-07-feat-dmint-v1-mint-and-reference-miner-plan.md) — M1 plan
- [`docs/solutions/logic-errors/dmint-v1-mint-shape-mismatch.md`](../solutions/logic-errors/dmint-v1-mint-shape-mismatch.md) — golden-vector lesson
- [`docs/solutions/logic-errors/dmint-v1-classifier-gap.md`](../solutions/logic-errors/dmint-v1-classifier-gap.md) — same anti-pattern, parser side
- [`docs/dmint-research-mainnet.md`](../dmint-research-mainnet.md) §2 (V1 layout), §4 (mint trace), §5 (deploy reveal not yet isolated)
- `src/pyrxd/glyph/builder.py:291` — V2's `prepare_dmint_deploy`
- `src/pyrxd/glyph/dmint.py:352-504` — M1 V1 builders (reused)
- `src/pyrxd/glyph/dmint.py:2156` — `find_dmint_funding_utxo` (the pattern to mirror)
- `tests/test_dmint_deploy_integration.py:355-545` — VPS testmempoolaccept harness (reusable for M2)

### External (Phase 2a reads)
- Photonic Wallet `packages/lib/src/mint.ts` (commit + reveal output planning)
- Photonic Wallet `packages/lib/src/script.ts` (V1 covenant bytecode)
- glyph-miner contract-discovery logic (sanity check on
  `find_dmint_contract_utxos` design)
