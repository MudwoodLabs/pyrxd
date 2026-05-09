---
title: "feat: dMint V1 deploy support"
type: feat
date: 2026-05-08
brainstorm: docs/brainstorms/2026-05-08-dmint-v1-deploy-m2-brainstorm.md
milestone: 2 of 3 (M1 V1 mint shipped via PR #65; M3 V2 deploy proof deferred)
---

# feat: dMint V1 deploy support (M2)

## Enhancement Summary

**Deepened on:** 2026-05-08 (two review passes)
**Round 1 reviewers:** security-sentinel, code-simplicity-reviewer,
pattern-recognition-specialist, learnings-researcher
**Round 2 reviewers (technical_review):** kieran-python-reviewer,
architecture-strategist

### Round-2 critical bugs caught (would have shipped broken)

1. **Bare-alias deprecation doesn't warn.** Original draft said
   `DmintFullDeployParams = DmintV2DeployParams` — but bare aliasing
   is just a name binding; no `DeprecationWarning` fires on
   construction, and the acceptance criterion "legacy alias raises
   DeprecationWarning" would have been unverifiable. Fixed: subclass
   with `__init__` warner.
2. **Same method name with different arity.** Both result types had
   `build_reveal_scripts(commit_txid, ...)` but V1's takes 1 arg,
   V2's takes 3. Polymorphic call-sites would TypeError at runtime.
   Fixed: V1 renamed to `build_reveal_outputs(commit_txid)`,
   different signatures get different names.
3. **Missing result-type deprecation alias.** Plan only kept
   `DmintFullDeployParams` as alias; `DmintDeployResult` rename had
   no alias, so `isinstance(result, DmintDeployResult)` callers
   would break silently. Fixed: both renames now have aliases.

### Round-2 Pythonic improvements

4. `@overload` stubs on `prepare_dmint_deploy` — gives static call-
   site type narrowing without runtime `isinstance` checks.
5. Result dataclasses are `@dataclass(frozen=True)` with
   `tuple[bytes, ...]` not `list[bytes]` — matches M1 precedent
   (`DmintMineResult`, `DmintState`, `DmintContractUtxo`).
6. New `DmintV1RevealScripts` frozen dataclass for V1's reveal-
   builder return type — mirrors `FtDeployRevealScripts` shape.
7. Dispatcher uses `match` + `typing.assert_never` instead of
   `isinstance` chain — exhaustiveness checked by mypy strict.
8. `find_dmint_contract_utxos` types its `client` param under
   `TYPE_CHECKING` — breaks the `Any`-propagation chain from M1.

### Round-2 architectural improvements

9. Acceptance criteria split into "PR-merge criteria" (synthetic +
   VPS) and "operational ship-it criteria" (real mainnet deploy).
   The mainnet gate is post-merge; bugs found there fix in M2.1.
10. `find_dmint_contract_utxos` carved out as parallelizable with
    Phase 2a — its inputs don't depend on Phase 2a research.
11. "M2.5" framing dropped; joint NFT+FT V1 deploy filed as
    deferred work without a milestone number.
12. V1 reveal sighash input value source clarified (FT commit value
    from caller's stored `commit_value`; ref-seeds always 1 photon).
13. `script_hash_for_script` helper inconsistency in files-to-modify
    list resolved — codescript-hash computed inline.

### Round-1 critical fix from pattern-recognition

The original plan cited `build_dmint_mint_tx` as precedent for "single
public function with version dispatch via `version` kwarg." **That
citation was wrong.** `build_dmint_mint_tx` dispatches on
`state.is_v1` (auto-detection from data), not a version kwarg. The
real pyrxd convention is **auto-detect on params shape**.

This cascades: split `DmintFullDeployParams` into sibling
`DmintV1DeployParams` and `DmintV2DeployParams` dataclasses; rename
the existing `DmintDeployResult` to `DmintV2DeployResult` and add
`DmintV1DeployResult` as its sibling; `prepare_dmint_deploy`
dispatches on the params type, no `version` kwarg. This is the same
architectural recommendation the M1 architect-strategist made about
the V1-only `funding_utxo` field — applied consistently in M2 instead
of repeating the smell.

### Round-1 other findings applied

1. **Security S1** — V2 self-test inventory step added to Phase 2b.1
   to prevent silent V1 downgrade after default flip.
2. **Security S2** — `find_dmint_contract_utxos` mirrors M1 round-4's
   `tx.txid() == u.tx_hash` defense; verifies returned UTXO's actual
   script byte-equals the expected codescript.
3. **Security S3** — `num_contracts` cap enforced as a construction-
   time validator on the dataclass, not runtime in the dispatcher.
4. **Security S4** — Multi-input signing must be atomic (build-then-
   sign-then-attach in three passes, never mid-loop attach).
5. **Simplicity** — Phase 2c "Acceptance Gating" deleted (duplicates
   Acceptance Criteria); `script_hash_for_script` helper inlined;
   `num_contracts` cap raised to 250 (real standardness ceiling) with
   citation; Phase 2b.4 OR-decision resolved to "example helper, no
   public signing module"; doc rewrite deferred to sibling PR.
6. **Learnings** — Mainnet-not-synthetic golden vectors clause;
   opcode-walker guidance for the Phase 2a.0 "snk" classification
   walk; hypothesis property test for dispatcher; Photonic-divergence
   section in research doc when mainnet disagrees with source.

### Findings deferred to coding-time

- Singular `find_dmint_contract_utxo(client, *, contract_ref)` wrapper
  alongside the plural — promote if a third caller materializes
- Whether to ship a `pyrxd.transaction.signing` module — wait until a
  third caller needs multi-input P2PKH signing
- Stronger token-name guardrails for the mainnet acceptance gate
  (ticker prefix, README note) — implementation-time decision

## Overview

Make pyrxd capable of issuing fresh V1 dMint **FT** tokens that the
rest of the Radiant ecosystem (glyph-miner, RXinDexer, Photonic
explorer) recognizes. After this milestone, a developer can deploy a
multi-contract V1 dMint FT token, find its live contracts on-chain,
and feed them to the M1 mint flow without manually pasting outpoints.

**Scope: FT-only.** Joint NFT+FT V1 deploys (which the mainnet "snk"
deploy may turn out to be; see Phase 2a.0) are out of scope and
filed as deferred work ("Joint NFT+FT V1 deploy") to be brainstormed
separately if real demand surfaces. Deliberately not numbered as
"M2.5" because that framing would imply scheduled work; this is a
ticket-stub, not a milestone.

M1 (V1 mint) already ships in [PR #65](https://github.com/MudwoodLabs/pyrxd/pull/65)
with public helpers M2 reuses unchanged: `find_dmint_funding_utxo`,
`is_token_bearing_script`, `build_dmint_v1_state_script`,
`build_dmint_v1_code_script`, `build_dmint_v1_contract_script`,
`build_dmint_v1_mint_preimage`, the `_V1_ALGO_BYTE_TO_ENUM` mapping,
the `DmintError` hierarchy, and `DmintCborPayload` (which already
omits the `daa` key when `daa_mode == FIXED` — so it produces V1-
correct CBOR as-is, no new class needed).

## Problem Statement

Three concrete gaps block deploying a usable dMint token via pyrxd:

1. **`prepare_dmint_deploy` only emits V2 contracts and refuses to
   run unless the caller passes `allow_v2_deploy=True`.** No live
   mainnet contracts are V2; no ecosystem miner targets V2; indexer
   behavior on V2 is empirically unknown. The function is effectively
   a no-op for users wanting to deploy a usable token.

2. **No way to find live contract UTXOs at the chain.** The M1 mint
   demo (`examples/dmint_claim_demo.py`) requires the user to look up
   the contract outpoint manually via a block explorer. Every M1+
   caller (mint, deploy verification, future tooling) needs this
   primitive.

3. **The Photonic Wallet V1 deploy bytes are not yet captured locally.**
   Per [`docs/dmint-research-mainnet.md`](../dmint-research-mainnet.md) §5:
   "Deploy reveal TX not yet isolated." pyrxd cannot byte-compare its
   output against on-chain truth; this is the same anti-pattern that
   produced four rounds of M1 review findings (see
   [`docs/solutions/logic-errors/dmint-v1-mint-shape-mismatch.md`](../solutions/logic-errors/dmint-v1-mint-shape-mismatch.md)).

## Proposed Solution

A two-phase milestone:

- **Phase 2a** (research, no code): close all byte-level unknowns
  about V1 deploy — Photonic source layout, mainnet reveal decode,
  reconciling the unexplained 35-output "snk" deploy commit.
- **Phase 2b** (implementation): land the V1 deploy code with byte-
  equal golden vectors against Phase 2a's findings; the chain-walking
  helper; and the API flip that makes V1 the default.

## Technical Approach

### Architecture

#### V1 deploy is structurally NOT parallel to V2

This is the load-bearing architectural finding from research that
the brainstorm did not anticipate:

| | V1 deploy (Photonic) | V2 deploy (existing pyrxd) |
|---|---|---|
| Tx count | **2** (commit + reveal) | **3** (commit + reveal + deploy) |
| Reveal output | N parallel contract UTXOs at vout[0..N-1] + optional FT premine at vout[N] | Token-ref FT UTXO only |
| Contract creation | In the reveal tx itself | In a separate deploy tx |
| Contract value | 1 photon each (singleton) | `initial_pool_photons` (running pool) |
| Funding | Reveal tx pays N×1 photons + premine + fee from caller-provided funding | Deploy tx pays `initial_pool_photons` |

This means M2's `prepare_dmint_deploy` cannot just swap the contract-
script builder. The whole tx-shape changes when V1 is selected.

#### Auto-dispatch on params type (corrected 2026-05-08)

Single public function `prepare_dmint_deploy(params, *, allow_v2_deploy=False)`
that **dispatches on the type of `params`** — `DmintV1DeployParams`
takes the V1 path, `DmintV2DeployParams` takes the V2 path. No
`version` kwarg.

This matches the established pyrxd dispatch pattern:
- `build_dmint_mint_tx` dispatches on `state.is_v1` (auto-detection
  from data, no version kwarg) at
  [`src/pyrxd/glyph/dmint.py:1721`](../../src/pyrxd/glyph/dmint.py#L1721)
- `DmintState.from_script` tries V2 then V1 (auto-detection) at
  [`src/pyrxd/glyph/dmint.py:1170`](../../src/pyrxd/glyph/dmint.py#L1170)

#### Sibling params + result dataclasses

Split `DmintFullDeployParams` into two unrelated dataclasses:

| Type | Used by | V1-only fields | V2-only fields |
|---|---|---|---|
| `DmintV1DeployParams` | V1 path | `num_contracts`, `op_return_msg` | — |
| `DmintV2DeployParams` (renamed from `DmintFullDeployParams`) | V2 path | — | `daa_mode`, `target_time`, `half_life`, `initial_pool_photons` |

Shared fields (`metadata`, `owner_pkh`, `max_height`, `reward_photons`,
`difficulty`, `premine_amount`, `contract_ref_placeholder`,
`token_ref_placeholder`, `algo`) live on both. No version-conditional
fields on a shared parent — each dataclass is honest about what it
accepts.

Same split for results: rename existing `DmintDeployResult` to
`DmintV2DeployResult`; add `DmintV1DeployResult` as its sibling. Both
are `@dataclass(frozen=True)` (matches `DmintMineResult` /
`DmintState` / `DmintContractUtxo` precedent at `dmint.py:724,1130,1490`).
Their deferred-builder methods have **distinct names** because
their signatures differ — V1's `build_reveal_outputs(commit_txid)`
(V1's reveal directly creates contract outputs) and V2's existing
`build_reveal_scripts(commit_txid, commit_vout, commit_value)`. Same
method name with different arity would TypeError on polymorphic
call-sites; better to be honest with two names.

#### Default-flip semantics

Before M2: `prepare_dmint_deploy(DmintFullDeployParams(...))` raises
`DmintError` unless `allow_v2_deploy=True`.

After M2:
- `prepare_dmint_deploy(DmintV1DeployParams(...))` → V1 path, succeeds
- `prepare_dmint_deploy(DmintV2DeployParams(...))` → V2 path, requires
  `allow_v2_deploy=True`, raises `DmintError` otherwise
- `prepare_dmint_deploy(DmintFullDeployParams(...))` (legacy alias)
  → kept as a `DeprecationWarning`-emitting alias for one release;
  alias points at `DmintV2DeployParams`. The alias removes after M2.1.

The "default flip" is therefore implicit in the params type the
caller constructs — there's no behavior change for an existing caller
who keeps calling with the old `DmintFullDeployParams` shape; they
get a deprecation warning and unchanged V2 semantics. New callers
construct `DmintV1DeployParams` to opt into V1.

#### Wire-format constraints from ecosystem interop

Three hard constraints from cross-tool research:

1. **Contracts MUST live at consecutive vouts** of the reveal tx
   (vout[0..N-1]). glyph-miner discovers parallel contracts by
   incrementing vout from `firstRef`; non-consecutive layout
   silently undercounts ([glyph-miner deployments.ts:207-219](file:///home/eric/apps/Pinball/glyph-miner/src/deployments.ts)).

2. **CBOR `p` must equal `[1, 4]`** (FT + DMINT markers); CBOR `v`
   field must be **omitted** for V1 (emitting `v: 2` would mis-
   classify as V2 in glyph-miner). Display fields `ticker`, `name`,
   optional `icon`/`main` are required for explorer rendering.

3. **Per-contract `contractRef[i] = LE-reversed (commit_txid, 1+i)`** —
   the LE-reversed outpoint of the i-th ref-seed P2PKH in the commit
   tx. All N contracts share `tokenRef = LE-reversed (commit_txid, 0)`.

### Implementation Phases

#### Phase 2a: Research (no code; finishes when exit criteria met)

**Phase 2a.0 — Reconcile the "snk" deploy discrepancy.** Research
flagged that mainnet RBG-class deploy commit `a443d9df…878b` has 35
outputs with two hashlock commits at vouts 0 and 33, while Photonic
source suggests `1 + N` outputs (FT-commit + N ref-seeds). Possibilities:
joint NFT+FT deploy (vout 0 = FT commit, vout 33 = NFT commit?), an
older Photonic version, or misread research. **Reconcile before
encoding any commit-tx logic.**

  Method: walk the commit's tx outputs in detail; classify each by
  script shape. **Use opcode-aware classification, not byte-substring
  scans** (per the funding-utxo-byte-scan-dos.md lesson — naive
  matchers misclassify P2PKH addresses whose hash bytes happen to
  contain marker opcodes). For each output, check opcode sequence:
  - Hashlock commit: `0x76 0xa9 0x14 <pkh-20> 0x88 0xac 0x6a <gly-magic-push>` (FT) or NFT variant
  - P2PKH ref-seed: `0x76 0xa9 0x14 <pkh-20> 0x88 0xac` exactly
  - Anything else: flag for inspection

  If two outputs are hashlock commits and 33 are ref-seed P2PKHs,
  that's a 33-contract deploy. If one is FT-commit, one is
  NFT-commit, and 33 are ref-seeds, that's a joint NFT+FT deploy and
  our V1-FT-only path is a simpler subset of the mainnet sample.

**Phase 2a.1 — Walk the deploy reveal on-chain.** From the commit
txid, use `client.get_history(commit_txid_scripthash)` or directly
look at txs that spend the commit's vouts to find the reveal. Fetch
its raw bytes. Decode byte-by-byte:
- vout count
- Each output script: classify (contract, FT premine, P2PKH change, OP_RETURN)
- Reveal scriptSigs (especially vout[0] of commit which carries the CBOR payload push)
- Decode the CBOR payload — record the exact field set Photonic emits

  Save findings in `docs/dmint-research-photonic-deploy.md` (new file)
  with hex fixtures suitable for byte-equal assertions.

**Phase 2a.2 — Confirm Photonic source where source is canonical.**
Re-clone or reach the Photonic Wallet repo if `/tmp/photonic-wallet/`
isn't available; specifically read:
- `packages/lib/src/mint.ts` — `createCommitOutputs`,
  `createRevealOutputs`, `revealDirect` for V1 deploy paths
- `packages/lib/src/script.ts` — `dMintScript` for V1 contract output
  byte construction
- `packages/lib/src/types.ts:68-78` — the literal `DmintPayload` type
  to settle the CBOR-shape question

  Cross-check Photonic source against Phase 2a.1's mainnet decode.
  Disagreements get resolved in favor of mainnet (live nodes are the
  ground truth). **Each disagreement must be recorded** in a
  "Photonic Divergence" section of the research doc, naming which
  Photonic file/line and value differ from mainnet, and the reason
  pyrxd will prefer mainnet. This prevents future review rounds from
  re-litigating the same discrepancies (per the
  feedback_photonic_canonical_reference.md memory: "deviate
  explicitly when Photonic isn't the best answer").

**Phase 2a exit criteria** (Phase 2a is done when ALL are met):
- [x] "snk" 35-output discrepancy reconciled with documented explanation
  (see `docs/dmint-research-photonic-deploy.md` §2: 1 FT-commit + 32 ref-seeds + 1 NFT-commit + 1 change)
- [x] At least one **mainnet** V1 deploy reveal saved as a hex fixture
  (`b965b32d…9dd6` reveal raw + `a443d9df…878b` commit raw — saved at
  `/tmp/dmint-m2-research/{commit,reveal}_raw.hex`; will be moved into
  the repo as a fixture during Phase 2b)
- [x] Commit-tx output layout documented byte-for-byte (vout count,
  ordering, ref-seed P2PKH structure, value of each output) — research doc §2
- [x] Reveal-tx output layout documented byte-for-byte (vout count,
  contract output positions, FT premine if any, OP_RETURN if any) — research doc §3
- [x] Photonic's V1 CBOR `dmint:{...}` payload shape confirmed
  (which fields populated, which omitted) — research doc §4: `p:[1,4]`,
  `ticker`, `name`, `desc`, `by`, `main`. **No `dmint:{...}` field
  exists** — dMint params live in the contract output scripts, not the
  CBOR.
- [x] Per-contract `contractRef` derivation rule confirmed against
  Photonic source AND a mainnet decode — `contractRef[i] =
  LE-reversed(commit_txid, vout=i+1)`, all 32 contracts in the GLYPH
  reveal verified
- [x] "Photonic Divergence" section exists in the research doc — §7
  documents 5 divergences (V1 contract output shape, premine,
  delegate-ref, algo+DAA, V1 vs V2 protocol vector)

#### Phase 2b: Implementation

**Phase 2b.1 — Library core**

Three coordinated changes in `src/pyrxd/glyph/builder.py`:

1. **Split params into sibling dataclasses**:
   - Rename existing `DmintFullDeployParams` → `DmintV2DeployParams`
   - Add new `DmintV1DeployParams` with V1-only fields:
     `num_contracts: int = 1` (range `[1, 250]`, validated at
     construction time via `__post_init__`; 250 is the standardness
     ceiling for tx size at typical V1 contract bytes), optional
     `op_return_msg: bytes | None = None`
   - Keep `DmintFullDeployParams` as a `DeprecationWarning`-emitting
     **subclass** of `DmintV2DeployParams` whose `__init__` calls
     `warnings.warn(...)` before delegating to `super().__init__(...)`.
     **Bare type aliasing (`DmintFullDeployParams = DmintV2DeployParams`)
     would NOT emit any warning at construction time** — the alias is
     just a name binding. The subclass-with-warner pattern is required
     for the deprecation acceptance test to pass. Removed in M2.1
     (target version v0.6, ~1-2 weeks per current cadence).
2. **Split results into sibling dataclasses**:
   - Rename existing `DmintDeployResult` → `DmintV2DeployResult`
   - Add `DmintDeployResult` as a `DeprecationWarning`-emitting
     subclass alias for the same one-release deprecation window
     (parallels the params-side alias; both renames need both sides)
   - Add new `DmintV1DeployResult` (`@dataclass(frozen=True)`)
     carrying: `commit_result` (CommitResult), `cbor_bytes`,
     `owner_pkh`, `premine_amount`, `num_contracts`,
     `placeholder_contract_scripts: tuple[bytes, ...]` (immutable;
     matches `DmintMineResult`/`DmintState`/`DmintContractUtxo`
     frozen-dataclass precedent at `dmint.py:724,1130,1490`), and a
     `build_reveal_outputs(commit_txid) -> DmintV1RevealScripts`
     deferred-builder method.
   - `DmintV1RevealScripts` (new `@dataclass(frozen=True)`):
     `contract_scripts: tuple[bytes, ...]` (length = `num_contracts`),
     `contract_value: int = 1`, `premine_script: bytes | None`,
     `premine_amount: int | None`, `op_return_script: bytes | None`.
     Mirrors `FtDeployRevealScripts` shape at `builder.py:80-92`.
   - **Method-name divergence resolved**: V1 uses
     `build_reveal_outputs(commit_txid)` (the V1 reveal directly
     creates the contract outputs, hence "outputs"); V2 keeps the
     existing `build_reveal_scripts(commit_txid, commit_vout, commit_value)`.
     Different method names with honest signatures — better than
     same name with different arity (which would TypeError on
     polymorphic call).
   - Also rename the existing `DmintV2DeployResult.build_reveal_scripts`
     callsites in test/example code if any used the polymorphic
     `result.build_reveal_scripts(...)` form expecting V1 semantics.
3. **Auto-dispatch in `prepare_dmint_deploy`**: function now takes
   `params: DmintV1DeployParams | DmintV2DeployParams` and uses
   structural pattern matching with `typing.assert_never` on the
   default arm:
   ```python
   match params:
       case DmintV1DeployParams():
           return _prepare_dmint_v1_deploy(params)
       case DmintV2DeployParams():
           if not allow_v2_deploy:
               raise DmintError(...)
           return _prepare_dmint_v2_deploy(params)
       case _:
           assert_never(params)
   ```
   Mypy strict gets exhaustiveness checking for free; "what if someone
   passes a third type" raises immediately. Legacy
   `DmintFullDeployParams` (subclass of `DmintV2DeployParams`) hits
   the second arm — V2 path with deprecation warning emitted at
   construction.

   **`@overload` stubs** for static call-site narrowing — without
   them, every caller writes `if isinstance(result, DmintV1DeployResult):`
   to use V1-specific fields:
   ```python
   @overload
   def prepare_dmint_deploy(
       params: DmintV1DeployParams, *, allow_v2_deploy: bool = ...
   ) -> DmintV1DeployResult: ...
   @overload
   def prepare_dmint_deploy(
       params: DmintV2DeployParams, *, allow_v2_deploy: bool = ...
   ) -> DmintV2DeployResult: ...
   def prepare_dmint_deploy(params, *, allow_v2_deploy=False): ...
   ```

In `src/pyrxd/glyph/dmint.py`:

4. **`find_dmint_contract_utxos(client, *, token_ref, initial_state=None, limit=None, min_confirmations=1) -> list[DmintContractUtxo]`** — public.

   **Why dual-call-shape:** Phase 2a research confirmed public ElectrumX
   (`electrumx.radiant4people.com:50022`) exposes neither `dmint.get_contracts`
   nor any `blockchain.ref.listunspent`-style RPC. The plan's original
   "compute codescript-hash inline, query directly" approach therefore
   only works when the caller already knows every state-item value (so
   the codescript can be reconstructed deterministically). Two distinct
   use cases need this helper:
   - **Just-deployed verification**: caller has the deploy params in
     hand, wants to confirm all N initial contract UTXOs exist on chain.
     Fast: one `get_utxos(scripthash)` per contract.
   - **Live-token discovery**: caller has only `token_ref` (e.g. the
     M1 mint demo wants to mine GLYPH). Slow path: walk from reveal,
     enumerate its contract outputs.

   The function picks the path based on whether `initial_state` is
   supplied:

   - **Shape A — fast path** (`initial_state: DmintV1ContractInitialState`
     supplied): for each `i in range(initial_state.num_contracts)`,
     compute `contractRef[i] = LE-reversed(commit_txid, i+1)` from
     `token_ref`'s txid component, build the contract codescript via
     M1's `build_dmint_v1_contract_script(...)`, compute its scripthash
     inline (`hashlib.sha256(codescript).digest()[::-1].hex()`),
     query `client.get_utxos(scripthash)`, and apply S2 cross-check.

   - **Shape B — fallback** (`initial_state` is `None`): parse
     `token_ref` to get `commit_txid`. Fetch the commit tx; compute
     scripthash of its `vout[0]` (the FT-commit hashlock). Call
     `client.get_history(scripthash)` — exactly two entries (commit
     + reveal). Take the second; that's the reveal txid. Fetch the
     reveal; for each output try `DmintState.from_script(script)`;
     if it parses as V1 AND `state.token_ref == token_ref`, build a
     `DmintContractUtxo`. Verify each is currently unspent via a
     scripthash-level `get_utxos` lookup. (Skip mined-from contracts
     in the first cut — the spend chain walk to find current heads
     is filed as deferred work; the M1 mint demo only needs fresh
     contracts, and the fresh state is what's directly on the reveal.)

   - **Per security S2 (BOTH shapes)**: for each candidate UTXO,
     fetch its source tx and verify `tx.txid() == u.tx_hash` AND
     `tx.outputs[u.tx_pos].locking_script.serialize() == script`.
     Mirrors M1 round-4's defense in `find_dmint_funding_utxo`. This
     defends against malicious / buggy ElectrumX servers.

   - `DmintV1ContractInitialState` is a small frozen dataclass with
     fields `num_contracts: int`, `reward_sats: int`, `max_height:
     int`, `target: int` — exactly the dMint params needed to rebuild
     a fresh-state contract script. Constructible directly or
     extractable via `.to_initial_state()` from
     `DmintV1DeployParams` / `DmintV1DeployResult`.

**V2 self-test inventory step (Security S1)**: BEFORE merging the
default-flip change, audit `tests/test_dmint_end_to_end.py` and
related V2 self-tests. Every `prepare_dmint_deploy(...)` call there
must explicitly use `DmintV2DeployParams` (or be migrated to
`DmintV1DeployParams` if that's the test's intent). A test passing
the legacy `DmintFullDeployParams` shape silently triggers the
deprecation warning and runs V2 — fine for one release, but the
inventory makes intent explicit.

**Phase 2b.2 — V1 deploy commit-tx output planning**

The V1 commit emits `vout[0]` = FT-shape Glyph commit (hash256(payload)
+ gly magic) + `vout[1..N]` = N P2PKH ref-seeds to owner_pkh, value 1
each. Reuses `build_commit_locking_script` from existing builder
infrastructure. The per-ref-seed P2PKH script: `OP_DUP OP_HASH160
<owner_pkh:20> OP_EQUALVERIFY OP_CHECKSIG`.

**Defensive runtime assertion**: `_prepare_dmint_v1_deploy` asserts
that the resulting reveal vout count equals
`num_contracts + (1 if premine else 0) + (1 if change else 0)` and
refuses to emit anything ambiguous (S7 mitigation — guards against
future joint NFT+FT support producing bytes the indexer interprets
ambiguously).

NOTE: Phase 2a.0 may reveal that the on-chain shape requires extra
hashlock commits (the "snk" 35-output discrepancy). If so, this
section gets revised — but the FT-only scope (Overview line) stays.

**Phase 2b.3 — V1 deploy reveal-tx output planning**

The reveal spends the commit's N+1 outputs:
- Input 0: vout[0] of commit (FT-shape Glyph commit) — scriptSig
  pushes the raw CBOR payload + `gly` magic
- Inputs 1..N: vout[1..N] of commit (P2PKH ref-seeds) — caller signs
  each with the owner key

**Sighash input values**: V1's `build_reveal_outputs(commit_txid)`
does NOT take `commit_value` (unlike V2's `build_reveal_scripts`)
because V1's input values are derivable from protocol constants:
- Input 0 (FT commit): the value at vout[0] of the commit tx, which
  the caller assembles deterministically (Phase 2b.2 commit-tx output
  planning specifies this exactly — it's the value the caller already
  paid into the commit). The signing helper either looks it up from
  the caller's stored `commit_value` parameter or accepts an explicit
  arg.
- Inputs 1..N (ref-seeds): always 1 photon (V1 protocol constant).

The signing helper signature is therefore
`_sign_p2pkh_inputs(tx, indices, private_key, *, input_values: list[int])` —
the helper takes per-input values for sighash construction, not just
indices. This keeps the public `build_reveal_outputs(commit_txid)`
signature clean while making sighash input values explicit at sign-
time.

Reveal outputs:
- vout[0..N-1]: N V1 contract UTXOs, value 1 photon each. Each built
  via `build_dmint_v1_contract_script(height=0, contract_ref=ref_seed_outpoint(i+1), token_ref=ft_commit_outpoint, max_height, reward, target, algo)`.
- vout[N] (optional): FT premine output, value `premine_amount`,
  script via `build_ft_locking_script(owner_pkh, token_ref)`.
- vout[N+1] (optional): change to owner_pkh, P2PKH.

**Phase 2b.4 — Multi-input signing helper (atomic)**

The reveal tx has N+1 inputs to sign. Add a private
`_sign_p2pkh_inputs(tx, indices, private_key)` helper to
`examples/dmint_deploy_demo.py` (mirrors M1's `_sign_p2pkh_input`).
Promote to `pyrxd.transaction.signing` only if a third caller
materializes — single-call YAGNI for now.

**Per security S4, signing must be atomic** — three-pass:
1. Build all N preimages first
2. Sign all N preimages
3. Attach all N unlocking scripts to the tx in one final pass

If any step fails, raise before mutating the tx. A loop that builds-
signs-attaches per input would leave a half-signed tx on partial
failure (key access failure, OOM, etc.); atomic three-pass avoids it.

**Phase 2b.5 — Demo + tests**

| File | Change |
|---|---|
| `examples/dmint_deploy_demo.py` | New manual demo (DRY_RUN=1 default, three-key handshake on broadcast). Modeled on `examples/dmint_claim_demo.py` and `examples/ft_deploy_premine.py`. Walks commit broadcast → wait → reveal broadcast → list contracts via `find_dmint_contract_utxos` → confirm. |
| `tests/test_dmint_v1_deploy.py` | New test file. Synthetic V1 deploy round-trip; **byte-equal golden vectors against Phase 2a mainnet fixtures (NOT synthetic-only — see Quality Gates)**; multi-contract enumeration via `find_dmint_contract_utxos`; legacy `DmintFullDeployParams` raises `DeprecationWarning`; cross-version sanity (V2 still works with explicit opt-in); pin test that `DmintCborPayload` does NOT emit `v` field (`assert "v" not in payload.to_cbor_dict()`); hypothesis property test on the V1/V2 dispatch behavior with arbitrary param-shape inputs. |
| `tests/test_dmint_deploy_integration.py` | Add V1 commit + reveal `testmempoolaccept` cases parallel to existing V2 cases. Reuses the existing inline `_rpc()` helper at line 511-525; gated by `RADIANT_INTEGRATION` env var. |

**Phase 2b.6 — Documentation (minimal in this PR)**

The full rewrite of `docs/dmint-followup.md` ships as a **separate
sibling PR** after M2 lands. M2's code PR includes only:

| File | Change |
|---|---|
| `docs/plans/2026-05-07-feat-dmint-v1-mint-and-reference-miner-plan.md` | Add a brief "M2 closeout" section noting which deferred items got pulled forward. |
| `prepare_dmint_deploy` docstring | Updated for the new dispatch + sibling params behavior. |
| `docs/dmint-followup.md` | Banner line update (still stale; full rewrite in sibling PR). |

(The sibling-PR pattern keeps the M2 code review surface focused on
code, not 100+ lines of doc rewriting.)

## Alternative Approaches Considered

### Alternative 1: Implement-first (rejected)

Skip Phase 2a's research, build V1 deploy from existing partial
research + glyph-miner inference, validate against the chain at the
VPS tier.

**Why rejected**: violates the M1-incident lesson. Round 1 of M1
review caught wrong V1 mint output shape; round 4 caught a fee
underestimate. Both were "synthetic tests through pyrxd's own parser
passed; the spec said something different." Phase 2a is the
preventive cost; without it, M2 has the same expected number of
review rounds as M1.

### Alternative 2: Two separate public functions (rejected)

`prepare_dmint_v1_deploy` + `prepare_dmint_v2_deploy` as separate
public functions instead of one function dispatching on params type.

**Why rejected**: would commit pyrxd to ALSO splitting
`build_dmint_mint_tx` in the same milestone (since M1 reviewers
flagged its polymorphic shape and recommended a split). That bigger
refactor wasn't in M2 scope. Auto-dispatch on params *type* is the
cheapest way to honor "honest signatures per version" without forcing
the mint-side split right now. The mint-side split can happen later
(or never) on its own merit.

### Alternative 4: Explicit `version: int` kwarg (rejected during deepen-plan review)

Original plan draft had `prepare_dmint_deploy(params, *, version=1)`
with single-shared-params and a runtime version field.

**Why rejected**: pattern-recognition review showed pyrxd's two prior
dispatch precedents (`build_dmint_mint_tx`, `DmintState.from_script`)
both use **auto-detection on data**, not version kwargs. Citing
`build_dmint_mint_tx` as kwarg-precedent was an outright error in the
original draft. Auto-dispatch on params type matches both prior
precedents and the architect-strategist's M1 recommendation that V1
and V2 should not share a polymorphic params class.

### Alternative 3: Defer `find_dmint_contract_utxos` (rejected)

Ship V1 deploy without the chain helper; manual outpoint lookup
continues.

**Why rejected**: architect-strategist M1 review pulled
`find_dmint_funding_utxo` forward into M1 for exactly this reason —
helpers with two known consumers belong with the first one. M2's
deploy verification + M1's mint demo both need contract discovery.
Punting again would repeat the anti-pattern.

## Acceptance Criteria

### Functional Requirements

#### Phase 2a (must complete before any code in Phase 2b)

- [x] `docs/dmint-research-photonic-deploy.md` exists and explains the
  35-output GLYPH deploy commit shape: 1 FT-commit + 32 ref-seeds + 1
  NFT-commit + 1 change (joint NFT+FT-style deploy with mint-fresh auth
  NFT chosen for pyrxd; forward-prior auth NFT documented as deferred)
- [x] At least one byte-decoded mainnet V1 deploy reveal saved as a
  hex fixture (`b965b32d…9dd6` raw bytes saved during research; will
  be moved into the repo as `tests/fixtures/dmint_v1_deploy_*.hex`
  during Phase 2b)
- [x] V1 commit-tx output layout documented byte-for-byte (research
  doc §2)
- [x] V1 reveal-tx output layout documented byte-for-byte (research
  doc §3)
- [x] V1 CBOR payload shape confirmed (research doc §4): `p:[1,4]`,
  `ticker`, `name`, `desc`, `by`, `main`. No `dmint:{...}` field; dMint
  params live in contract output scripts only.
- [x] Per-contract `contractRef` derivation rule confirmed against
  both Photonic source AND the mainnet decode (research doc §3.3 +
  §5)

#### Phase 2b — V1 deploy library

- [ ] `DmintV1DeployParams` (`@dataclass(frozen=True)`) public; V1-only
  fields (`num_contracts: int = 1`, optional `op_return_msg: bytes | None = None`);
  shared fields with `DmintV2DeployParams`
- [ ] `DmintV2DeployParams` (`@dataclass(frozen=True)`) renamed from
  `DmintFullDeployParams`; V2-only fields
- [ ] `DmintFullDeployParams` retained as a **subclass** of
  `DmintV2DeployParams` whose `__init__` calls `warnings.warn("...",
  DeprecationWarning, stacklevel=2)` then delegates to `super().__init__`.
  **Bare alias would not warn**; subclass-with-warner is required.
  Alias removes in M2.1 (target v0.6).
- [ ] `num_contracts` validated `[1, 250]` at construction time via
  `__post_init__`; out-of-range raises `ValidationError`. 250 is the
  standardness ceiling for V1 deploy reveal tx size.
- [ ] `prepare_dmint_deploy(params)` uses structural pattern matching
  with `typing.assert_never` on default arm:
  - `DmintV1DeployParams` → V1 path, succeeds without opt-in
  - `DmintV2DeployParams` (or legacy `DmintFullDeployParams`) → V2
    path, requires `allow_v2_deploy=True`, raises `DmintError`
    otherwise (legacy subclass also emits `DeprecationWarning` on
    construction)
- [ ] **`@overload` stubs** declare:
  `prepare_dmint_deploy(DmintV1DeployParams, ...) -> DmintV1DeployResult`
  and `prepare_dmint_deploy(DmintV2DeployParams, ...) -> DmintV2DeployResult`.
  Without these, mypy strict gives the call-site a union return type,
  forcing a runtime `isinstance` check just to use V1 fields.
- [ ] `DmintV1DeployResult` and `DmintV2DeployResult` (renamed from
  `DmintDeployResult`) sibling **frozen** dataclasses;
  `placeholder_contract_scripts: tuple[bytes, ...]` (immutable;
  matches `DmintMineResult`/`DmintState`/`DmintContractUtxo` precedent
  at `dmint.py:724,1130,1490`)
- [ ] `DmintDeployResult` retained as a `DeprecationWarning`-emitting
  subclass alias of `DmintV2DeployResult` for the same one-release
  deprecation window. Both renames need both aliases — a public
  caller doing `isinstance(result, DmintDeployResult)` would
  otherwise break silently.
- [ ] **Method-name divergence resolved**:
  `DmintV1DeployResult.build_reveal_outputs(commit_txid) -> DmintV1RevealScripts`
  (no `commit_vout`/`commit_value` — V1 commit layout is fixed: vout 0
  is FT-commit, vouts 1..N are 1-photon ref-seeds; values derive
  from these protocol constants).
  `DmintV2DeployResult.build_reveal_scripts(commit_txid, commit_vout, commit_value)`
  unchanged. Different names, honest signatures — better than same
  name with different arity.
- [ ] `DmintV1RevealScripts` (`@dataclass(frozen=True)`) public:
  `contract_scripts: tuple[bytes, ...]` (length = `num_contracts`),
  `contract_value: int = 1`, `premine_script: bytes | None`,
  `premine_amount: int | None`, `op_return_script: bytes | None`.
  Mirrors `FtDeployRevealScripts` shape at `builder.py:80-92`.
- [ ] V1 commit-tx output layout byte-equal against Phase 2a mainnet
  fixtures
- [ ] V1 reveal-tx output layout byte-equal against Phase 2a mainnet
  fixtures (per-contract bytes; premine bytes if present)
- [ ] CBOR payload byte-equal against Phase 2a fixture (`p: [1, 4]`,
  no `v` field, ticker/name present)
- [ ] **Pin test**: `assert "v" not in DmintCborPayload(...).to_cbor_dict()`
  for V1 (independent of byte-equal fixture; catches a future refactor
  that re-introduces `v`)
- [ ] **Defensive runtime assertion**: `_prepare_dmint_v1_deploy`
  refuses to emit a reveal tx whose vout count differs from
  `num_contracts + (1 if premine else 0) + (1 if change else 0)`

#### Phase 2b — Chain helper (parallelizable with Phase 2a)

This helper does NOT depend on Phase 2a's research findings — its
inputs are `(token_ref, codescript-hash)`, its filter logic uses the
already-shipped `is_v1=True` parser from M1, and its security-S2
cross-check mirrors `find_dmint_funding_utxo`'s pattern byte-for-byte.
It can be implemented in parallel with Phase 2a research.

- [ ] `find_dmint_contract_utxos(client: ElectrumXClient, *, token_ref: GlyphRef, limit: int | None = None, min_confirmations: int = 1) -> list[DmintContractUtxo]`
  exists in `pyrxd.glyph.dmint`, public. **Type the `client` param
  properly** (import `ElectrumXClient` under `if TYPE_CHECKING:`,
  matching the existing M1 wart in `find_dmint_funding_utxo` is
  acceptable but breaking the `Any`-propagation chain here is
  preferred).
- [ ] `limit is None or limit >= 1` validated; `limit=0` rejected
  (avoids confusion with "no limit")
- [ ] Filters out non-V1 contracts (parsed state where `is_v1=False`)
- [ ] Empty list returned when no contracts found (not an exception)
- [ ] **Per security S2**: for each candidate UTXO, verifies
  `tx.txid() == u.tx_hash` AND verifies `tx.outputs[u.tx_pos].locking_script.serialize()`
  byte-equals the expected codescript. Mirrors the M1 round-4 defense
  in `find_dmint_funding_utxo`.
- [ ] Covered by mock-client test (token-bearing skip, height filter,
  `limit` cap, `tx.txid()` cross-check fails on spoofed txid,
  empty list on no candidates)

#### Phase 2b — Multi-input signing

- [ ] Demo's `_sign_p2pkh_inputs(tx, indices, private_key)` helper
  signs atomically: builds all preimages first (pass 1), signs all
  (pass 2), attaches all (pass 3). Raises before mutating the tx if
  any step fails. **No mid-loop attach.**

#### Phase 2b — Default flip + test inventory

- [ ] **V2 self-test inventory complete**: every
  `prepare_dmint_deploy` call site in `tests/test_dmint_end_to_end.py`
  and adjacent test files audited; each call uses an explicit
  `DmintV1DeployParams` or `DmintV2DeployParams`. Tests passing the
  legacy `DmintFullDeployParams` accepted only with a comment
  documenting why (deprecation-warning regression test).
- [ ] Hypothesis property test on the dispatcher: arbitrary param-
  shape inputs are dispatched correctly; invalid params raise
  `ValidationError` or `DmintError`, never anything else.

(Non-Functional Requirements and Quality Gates were merged into the
PR-merge criteria above to avoid duplication — single source of truth
for "what gates the merge.")


### PR-merge criteria (synthetic + VPS)

These gate the M2 code PR merge. Must all pass before PR review can
approve. Don't require real RXD or on-chain artifacts.

- [ ] All synthetic V1 deploy tests pass under `pytest -m unit`
- [ ] Optional `pytest -m integration` path (gated by
  `RADIANT_INTEGRATION`) pushes V1 commit + reveal via SSH to VPS
  `testmempoolaccept`, expects `allowed=true` for commit and
  `allowed=false` for reveal (positive control)
- [ ] No regressions in existing dMint test suites (V1 mint, V2
  parser, V2 deploy)
- [ ] All Phase 2a exit criteria met (research-doc + fixtures
  exist; reviewed by user)
- [ ] All Phase 2b acceptance criteria met
- [ ] `task ci` passes locally; lint + format clean; mypy strict
  passes; bandit clean
- [ ] Code review pass (security-sentinel + red-team) catches no
  show-stoppers — same pattern as M1
- [ ] No private symbols imported by `examples/dmint_deploy_demo.py`
  (architect-strategist M1 pattern)

### Operational ship-it criteria (post-merge, separate gate)

These are NOT a PR-merge blocker. The M2 code PR can merge cleanly
once the PR-merge criteria above pass. The operational gate runs
**after merge** as part of the M2.0 release validation. Wire-format
bugs found here are fixed in M2.1.

- [ ] One fresh V1 dMint token deployed on mainnet via pyrxd, with
  a token name agreed in advance and documented in the M2 release
  note
- [ ] glyph-miner discovers the token via its `(firstRef, numContracts)`
  enumeration
- [ ] glyph-miner successfully mines at least one contract
- [ ] RXinDexer indexes the token (`token_type='dmint'`, ticker/name
  surfaced)
- [ ] Photonic Wallet explorer renders the token (deferred if
  Photonic-not-locally-inspectable)

## Success Metrics

- **Primary (PR-merge)**: M2 PR-merge criteria all green; CI clean.
- **Primary (operational)**: one confirmed V1 deploy on mainnet,
  mineable by glyph-miner (binary outcome). Lands in M2.0 release
  validation, not the PR.
- **Secondary**: synthetic V1 deploy tests stable on CI for 2+ weeks
  without flake.
- **Tertiary**: M2 closeout can mark `prepare_dmint_deploy` as the
  user-facing "deploy a dMint token" path with no caveats —
  removing the M1 footgun warning for V1.

## Dependencies & Prerequisites

- VPS Radiant node at `89.117.20.219` (existing, used by M1 deploy
  integration tests)
- ElectrumX mainnet endpoint for chain walking in Phase 2a
- Photonic Wallet TS source (re-clone if `/tmp/photonic-wallet/` is
  no longer cached)
- glyph-miner at `/home/eric/apps/Pinball/glyph-miner/` (already
  present from M1)
- RXinDexer at `/home/eric/apps/Pinball/RXinDexer/` (already present)

## Risk Analysis & Mitigation

### High

- **R1: Phase 2a discovers Photonic V1 deploy structure differs
  significantly from the brainstorm's assumption.** E.g. the "snk"
  35-output discrepancy points at a joint NFT+FT deploy pattern
  pyrxd doesn't currently support. Could expand M2 scope.
  - *Mitigation*: scope M2 explicitly as "FT-only V1 dMint deploy."
    Joint NFT+FT V1 deploys filed as deferred work (no milestone
    number; brainstorm separately if real demand emerges).

- **R2: glyph-miner refuses to mine pyrxd-deployed contracts** for a
  shape reason we missed. Manual acceptance gate fails.
  - *Mitigation*: Phase 2a includes reading glyph-miner's
    `parseDmintScript` ([glyph.ts:277-322](file:///home/eric/apps/Pinball/glyph-miner/src/glyph.ts))
    and asserting our contract output script byte-for-byte matches
    `V1_BYTECODE_PART_B`. Plus the consecutive-vouts requirement is
    a hard test gate.

- **R3: Mainnet RBG deploy reveal fundamentally different from
  Photonic source.** Implies upstream drift; pyrxd has to choose
  which to match.
  - *Mitigation*: match mainnet over source (live nodes are ground
    truth). Document the divergence in the research doc.

### Medium

- **R4: `num_contracts > 100` rejected by chain standardness.**
  Probably no real user wants 100+ contracts but the cap is
  defensive.
  - *Mitigation*: explicit `ValidationError` with link to docs about
    standardness limits.

- **R5: V1 default flip breaks an external pyrxd consumer who relied
  on the post-M1 V2-default behavior.**
  - *Mitigation* (downgraded from "alpha caveats" by deepen review):
    `DmintFullDeployParams` retained as a `DeprecationWarning`-
    emitting alias for `DmintV2DeployParams` for one release, then
    removed in M2.1. Plus M2 PR description with migration guidance
    + alpha caveat. Deprecation cycle is cheap; alpha-only mitigation
    silently switches contract types for any caller who didn't read
    the changelog.

### Low

- **R6: Reveal-tx N+1 inputs hit some signing-loop bug** that the
  M1 single-input demo didn't surface.
  - *Mitigation*: synthetic test exercises 5+ contracts so the
    multi-input loop is real, not vestigial.

## Resource Requirements

- 1 developer (eric), self-paced
- ~1 RXD for the manual mainnet acceptance gate (deploy commit +
  reveal fees + N×1 photon per contract; conservative budget)
- VPS access for testmempoolaccept (existing)

## Future Considerations

- **M3 (V2 deploy proof, deferred indefinitely)**: only revisit when
  someone wants V2's DAA features (ASERT/LWMA dynamic difficulty).
- **`prepare_dmint_v2_mint_tx` / `prepare_dmint_v1_mint_tx` split**:
  M1 reviewers flagged `build_dmint_mint_tx`'s polymorphic shape.
  Splitting is a separate refactor; not blocked by M2.
- **Joint NFT+FT V1 deploys**: only if R1 surfaces the pattern as
  ecosystem-canonical AND there's real demand.
- **Find dMint deploys (not contracts) on chain**: a `find_dmint_tokens(client)`
  helper that enumerates all live tokens. Probably scanner.py work.

## Documentation Plan

- [ ] `docs/dmint-research-photonic-deploy.md` (new, Phase 2a output)
- [ ] `docs/dmint-followup.md` (full rewrite, Phase 2b.6)
- [ ] `examples/dmint_deploy_demo.py` (new, modeled on
  `dmint_claim_demo.py`)
- [ ] `prepare_dmint_deploy` docstring rewrite to document the V1
  default + V2 opt-in behavior
- [ ] `find_dmint_contract_utxos` docstring with the M1
  `find_dmint_funding_utxo` shape

## SpecFlow gaps applied

Every critical gap from the SpecFlow analysis is addressed:

- **C1 (premine output placement)**: vout[N] of reveal, with
  `owner_pkh` as the recipient, controlled by `premine_amount` field
  on `DmintV1DeployParams`
- **C2 (V1 2-tx vs V2 3-tx)**: explicit Architecture-section
  Key Decision; sibling params + result dataclasses make the
  difference type-level visible
- **C3 (testmempoolaccept on N-output reveal)**: Phase 2b.5 test
  spec accepts any input-missing reject reason
- **C4 (`num_contracts` upper bound)**: `1 <= num_contracts <= 250`
  (real standardness ceiling, not a guess), enforced at construction
  time via `__post_init__`, raises `ValidationError`
- **I1 (stale-commit recovery)**: documented in
  `prepare_dmint_deploy` docstring as caller responsibility (verify
  N confirmations before calling `build_reveal_scripts`); matches M1
  contract
- **I2 (`find_dmint_contract_utxos` race + cap)**: `limit=` and
  `min_confirmations=` kwargs added; `tx.txid()` cross-check (S2)
- **I3 (Plan-stage decision: `target` vs `difficulty`)**: V1 deploy
  public API takes `difficulty: int` for ecosystem parity with
  Photonic; internal converter via existing `difficulty_to_target`
- **I4 (Plan-stage decision: `find_dmint_contract_utxos` input)**:
  takes `token_ref`, derives codescript-hash internally
- **Brainstorm Open Q #4 (banner timing)**: full rewrite of
  `dmint-followup.md` ships as a sibling PR after M2; M2's code PR
  includes only the banner update
- **N4 (`prepare_dmint_deploy` post-flip semantics)**: auto-dispatch
  on params type (`DmintV1DeployParams` vs `DmintV2DeployParams`),
  not a `version` kwarg. Default flip is implicit in which params
  type the caller constructs.

## References & Research

### Internal

- [`docs/brainstorms/2026-05-08-dmint-v1-deploy-m2-brainstorm.md`](../brainstorms/2026-05-08-dmint-v1-deploy-m2-brainstorm.md)
- [`docs/plans/2026-05-07-feat-dmint-v1-mint-and-reference-miner-plan.md`](2026-05-07-feat-dmint-v1-mint-and-reference-miner-plan.md) — M1 plan
- [`docs/dmint-research-mainnet.md`](../dmint-research-mainnet.md) §1-§5 (V1 layout, mint trace, deploy gap)
- [`docs/dmint-research-photonic.md`](../dmint-research-photonic.md) — Photonic source citations from M1 research
- [`docs/solutions/logic-errors/dmint-v1-mint-shape-mismatch.md`](../solutions/logic-errors/dmint-v1-mint-shape-mismatch.md) — golden-vector lesson
- [`docs/solutions/logic-errors/funding-utxo-byte-scan-dos.md`](../solutions/logic-errors/funding-utxo-byte-scan-dos.md) — opcode-aware classification lesson
- [`src/pyrxd/glyph/builder.py:291`](../../src/pyrxd/glyph/builder.py#L291) — V2 `prepare_dmint_deploy`
- [`src/pyrxd/glyph/dmint.py:352-504`](../../src/pyrxd/glyph/dmint.py#L352) — M1 V1 builders
- [`src/pyrxd/glyph/dmint.py:2156`](../../src/pyrxd/glyph/dmint.py#L2156) — `find_dmint_funding_utxo` (pattern to mirror)
- [`tests/test_dmint_deploy_integration.py:355-545`](../../tests/test_dmint_deploy_integration.py#L355) — VPS testmempoolaccept harness
- [Memory: Photonic is the canonical reference](file:///home/eric/.claude/projects/-home-eric-apps-pyrxd/memory/feedback_photonic_canonical_reference.md)

### External

- glyph-miner (MIT) at `/home/eric/apps/Pinball/glyph-miner/`:
  - `src/dmint-api.ts:309-342` — RXinDexer-driven discovery
  - `src/deployments.ts:90-98, 207-219` — fallback URL + per-token
    enumeration via consecutive vouts
  - `src/glyph.ts:103-105, 265, 277-322, 391-441` — V1 contract-script
    parser (the "what bytes glyph-miner actually checks")
- RXinDexer at `/home/eric/apps/Pinball/RXinDexer/`:
  - `indexer/parser.py:540-542` — auto-discovery via
    `detect_token_from_script`
  - `indexer/script_utils.py:262-373` — V1+V2 dMint contract parser
  - `indexer/script_utils.py:925-1006` — CBOR field extraction
- Photonic Wallet TS source (re-clone needed):
  - `packages/lib/src/mint.ts:200-217` — `createCommitOutputs`
  - `packages/lib/src/mint.ts:398-461` — `createRevealOutputs`
  - `packages/lib/src/mint.ts:406-408` — `contractRef` derivation
  - `packages/lib/src/types.ts:68-78` — `DmintPayload` type
  - `packages/lib/src/script.ts` — V1 covenant bytecode constants

### Files to be created

- `docs/dmint-research-photonic-deploy.md` (Phase 2a output)
- `examples/dmint_deploy_demo.py` (Phase 2b.5)
- `tests/test_dmint_v1_deploy.py` (Phase 2b.5)

### Files to be modified

- `src/pyrxd/glyph/builder.py` — split params into
  `DmintV1DeployParams` + `DmintV2DeployParams` (rename of existing
  `DmintFullDeployParams`); split results into `DmintV1DeployResult`
  + `DmintV2DeployResult` (rename of existing `DmintDeployResult`);
  add new `DmintV1RevealScripts`; `prepare_dmint_deploy` becomes a
  match-dispatcher with `@overload` stubs; `DmintFullDeployParams`
  and `DmintDeployResult` retained as `DeprecationWarning`-emitting
  subclasses for one release
- `src/pyrxd/glyph/dmint.py` — `find_dmint_contract_utxos` (the
  codescript-hash is computed inline; no separate helper)
- `tests/test_dmint_deploy_integration.py` — add V1 commit + reveal
  testmempoolaccept cases
- `docs/dmint-followup.md` — banner update only (full rewrite is a
  sibling PR)
- `docs/plans/2026-05-07-feat-dmint-v1-mint-and-reference-miner-plan.md` — M2 closeout note
