---
title: "feat: dMint V1 mint support + Python reference miner"
type: feat
date: 2026-05-07
brainstorm: docs/brainstorms/2026-05-07-dmint-integration-brainstorm.md
milestone: 1 of 3 (M2 = V1 deploy; M3 = V2 deploy, deferred indefinitely)
---

# feat: dMint V1 mint support + Python reference miner

## Enhancement Summary

**Deepened on:** 2026-05-07
**Reviewers consulted:** security-sentinel, kieran-python-reviewer,
performance-oracle, code-simplicity-reviewer, learnings-researcher
(fuzzing strategy + local-CI-parity)

### Key Changes Applied

1. **API surface tightened.** `mine_solution` is keyword-only past
   `target`, `nonce_width: Literal[4, 8]`, raises
   `MaxAttemptsExhausted` instead of returning `None`. `MineResult` is
   `frozen=True, slots=True`. Dropped `pow_hash` (recomputable) and
   `progress_cb` (no consumer).
2. **Speculative surface deferred to M2.** Cut `nonce_provider`
   parameter and JSON-shim subprocess protocol. Cut resume JSON and
   automatic stale-state retry from the demo script. M1 ships the
   minimum that delivers one accepted live mint.
3. **Performance estimate corrected.** Replaced "50,000 h/s / 95
   hours" with measured ≈1.75M h/s on modern CPU and labeled
   ESTIMATED. Real-mainnet mining is single-digit hours
   single-threaded, not days.
4. **Default `max_attempts = 600M`.** Bounded by default so a naïve
   call doesn't wedge for hours; callers can override.

### Reviewer Findings Not Adopted (and why)

- **Security: golden-vector cross-check between pyrxd and glyph-miner.**
  Strong recommendation, would protect against silent preimage drift.
  Not adopted in this pass — owner declined. Worth revisiting if a
  preimage drift bug ever ships.
- **Security: three-key broadcast handshake, fee-budget cap, 0600
  resume file.** Demo-script hardening. Not adopted — owner declined,
  and resume-file scope was cut entirely.
- **Learnings: hypothesis property test for V1 round-trip.** Fuzzing
  strategy explicitly motivated by the V1 classifier gap; one ~30 LOC
  property test would close the same hole for the new V1 builder.
  Not adopted in this pass.
- **Kieran: error-hierarchy placement (`DmintError(RxdSdkError)`
  parent).** Adopted in spirit — new errors inherit from `DmintError`
  per the surface-area list — but the implementation detail of where
  `DmintError` lives (`security/errors.py` vs `glyph/dmint_errors.py`)
  is a coding-time decision, not a plan-time one.

### Reviewer Conflicts Resolved

- **Kieran (richer API) vs Simplicity (cut surface).** Resolved by
  taking Simplicity's cuts on speculative extension points
  (`nonce_provider`, shim, retry, resume JSON) and Kieran's structure
  on what remains (`Literal`, frozen dataclass, exception over `None`).
- **`pow_hash` field on `MineResult`.** Both Kieran and Simplicity
  argued for removal. Removed.
- **`max_attempts` default.** Kieran said `None` is fine; Performance
  said default to a finite sentinel; Simplicity didn't care. Took
  Performance's recommendation (600M attempts ≈ minutes
  single-threaded).

### Technical-Review Pass (2026-05-07)

After the deepen-plan synthesis, ran architecture-strategist and
pattern-recognition-specialist reviewers. Findings applied:

1. **Funding-UTXO acceptance contradiction resolved.** The original
   plan said `build_dmint_mint_tx` raises `InvalidFundingUtxoError`,
   but the function only takes the contract input — funding UTXOs are
   assembled by callers. Moved the check (and the error) to the
   `examples/dmint_claim_demo.py` funding-input scan. Library raises
   only `ContractExhaustedError` and `PoolTooSmallError`.
2. **Naming drift fixed.** All new errors get the `...Error` suffix
   matching the codebase's universal convention
   (`MaxAttemptsExhausted` → `MaxAttemptsError`, etc.).
   `MineResult` → `DmintMineResult` matches the
   `Domain...Result` pattern.
3. **`DmintError` placement specified.** Lives in
   `src/pyrxd/security/errors.py` (not `glyph/dmint.py`) per the
   established layering rule that all `RxdSdkError` subclasses live
   in `security/errors.py`.
4. **V2-deploy mitigation upgraded** from docstring-only to docstring
   + runtime `DeprecationWarning`. Same scope, materially stronger —
   surfaces in CI logs, lets tests opt into
   `warnings.simplefilter("error")`.
5. **`slots=True` dropped** from `DmintMineResult`. Zero existing
   dataclasses in `src/` use it; single-instance precedent isn't
   worth the inconsistency.
6. **Implementation note added**: `mine_solution` calls
   `verify_sha256d_solution` per candidate rather than inlining its
   own hash check. Single source of truth — drift between
   mining-check and verifier-check was the V1 classifier-gap failure
   mode.
7. **Runtime `nonce_width` guard added** as acceptance criterion.
   `Literal[4, 8]` is type-checker-only; trust-boundary rule requires
   runtime validation regardless.

Findings deferred to coding-time (noted but not blocking):
- V1 branch should early-return rather than fall through V2's DAA
  update path
- `find_dmint_contract_utxo` library helper deferred to M2 when there's
  a second caller
- Naming choice `build_dmint_v1_code_script` vs
  `build_dmint_code_script_v1` — both have precedent; pick at coding
  time

## Overview

Make pyrxd capable of claiming tokens from existing mainnet V1 dMint
contracts (e.g. RBG), including a slow but correct Python reference
miner. After this milestone, a developer with a funded wallet can
broadcast a real V1 mint tx against a live contract and have it accepted
by the network.

Current state: pyrxd parses V1 contracts but [`build_dmint_mint_tx`
explicitly refuses them at dmint.py:1091](../../src/pyrxd/glyph/dmint.py#L1091),
because spending V1 through the V2 builder produces an output the V1
covenant rejects. All seven live mainnet contracts are V1 per
[docs/dmint-research-mainnet.md §2.3](../dmint-research-mainnet.md), so
the V2-only mint path is unusable on mainnet today.

## Problem Statement

Three concrete gaps block live-network use:

1. **No V1 mint builder.** `build_dmint_mint_tx` accepts only V2 state
   shapes. V1 needs a 4-byte nonce (vs V2's 8), a 6-item state script (vs
   V2's 10), and the V1 code epilogue (`_V1_EPILOGUE_PREFIX + algo +
   _V1_EPILOGUE_SUFFIX` at [dmint.py:562](../../src/pyrxd/glyph/dmint.py#L562)).

2. **No nonce-grinding loop.** [`verify_sha256d_solution`](../../src/pyrxd/glyph/dmint.py#L466)
   exists but only verifies; the only "find a nonce" loop in the codebase
   is the test-internal one at
   [tests/test_dmint_module.py:339](../../tests/test_dmint_module.py#L339).
   Library users have nothing to call.

3. **No live-network proof.** Tests broadcast `testmempoolaccept` but
   never confirm a tx clears mempool and gets mined. A bug in the
   covenant-spend path stays invisible until someone tries it for real.

## Proposed Solution

Three coordinated changes:

### A. Make `build_dmint_mint_tx` V1-aware

Branch on `state.is_v1` before the rejection at
[dmint.py:1091](../../src/pyrxd/glyph/dmint.py#L1091). The V1 branch:

- Builds the 6-item V1 state script: `height(4LE), contractRef,
  tokenRef, maxHeight, reward, target(8B fixed)` — no DAA fields.
- Reuses the V1 code epilogue verbatim from `_V1_EPILOGUE_PREFIX +
  bytes([algo_byte]) + _V1_EPILOGUE_SUFFIX`. Wrap as
  `build_dmint_v1_code_script(algo)`.
- Skips DAA target update (V1 is FIXED-only): `new_target = state.target`.
- Calls a parameterized scriptSig builder with `nonce_width=4`.

### B. Add `mine_solution` and parameterize the verifier

New library function in `src/pyrxd/glyph/dmint.py`:

```python
@dataclass(frozen=True)
class DmintMineResult:
    nonce: bytes
    attempts: int
    elapsed_s: float

# Lives in src/pyrxd/security/errors.py per existing layering rule
# (every RxdSdkError subclass lives there). DmintError is a new parent.
class DmintError(RxdSdkError): ...
class MaxAttemptsError(DmintError):
    """Raised by mine_solution when max_attempts is reached without a solution."""
    attempts: int
    elapsed_s: float

def mine_solution(
    preimage: bytes,                              # 64 B from build_pow_preimage
    target: int,
    *,
    algo: DmintAlgo = DmintAlgo.SHA256D,
    nonce_width: Literal[4, 8] = 4,               # 4 = V1, 8 = V2
    max_attempts: int = 600_000_000,              # ≈ minutes single-core
) -> DmintMineResult:
    ...
```

Sequential nonce sweep starting at 0. Algos other than SHA256D raise
`NotImplementedError`. `MaxAttemptsError` carries `attempts` and
`elapsed_s` for telemetry. The `nonce_width` parameter is keyword-only
and `Literal[4, 8]` for type-checker enforcement, **plus** a defensive
runtime `if nonce_width not in (4, 8): raise ValidationError(...)` at
the function entry — `Literal` is type-checker-only and pyrxd's
trust-boundary convention requires runtime validation regardless.

**Implementation note:** `mine_solution` calls `verify_sha256d_solution`
once per candidate nonce rather than inlining its own hash-check.
Single source of truth — drift between the mining check and the
verifier check was the failure mode in
[docs/solutions/logic-errors/dmint-v1-classifier-gap.md](../solutions/logic-errors/dmint-v1-classifier-gap.md).
Performance is "slow but correct" anyway; one extra Python call per
attempt is irrelevant compared to the hash itself.

**Naming convention:** Errors follow the codebase's universal `...Error`
suffix convention (`KeyMaterialError`, `CovenantError`, etc.). All M1
new errors: `MaxAttemptsError`, `InvalidFundingUtxoError`,
`ContractExhaustedError`, `PoolTooSmallError`. Result types follow the
domain-prefixed `Domain...Result` pattern (`DmintMintResult`,
`FtTransferResult`); the new `DmintMineResult` matches.

**Deferred to M2**: a `nonce_provider` parameter for external-miner
plug-in and the JSON-over-stdin shim. Users wanting fast mining today
run `glyph-miner` standalone, take the hex nonce, and pass it to a
separate finalize call. No real-world caller needs the iterator hook
yet — adding it before someone asks is YAGNI.

Generalize [`verify_sha256d_solution` at dmint.py:466](../../src/pyrxd/glyph/dmint.py#L466)
to take a keyword-only `nonce_width: Literal[4, 8] = 8` (preserves V2
default; new V1 callers pass `nonce_width=4`). Confirmed equivalence
with glyph-miner reference at
`/home/eric/apps/Pinball/glyph-miner/src/miner.ts:494-508`: target check
is `hash[0..4] == 0x00000000 AND be_u64(hash[4..12]) < target`.

### C. Synthetic-then-real acceptance proof

Two test surfaces:

1. **Synthetic V1 mint test** in `tests/test_dmint_v1_mint.py` (new): a
   `TestBuildDmintMintTxV1` class mirroring
   [`TestBuildDmintMintTx` at test_dmint_end_to_end.py:554](../../tests/test_dmint_end_to_end.py#L554),
   using a low-difficulty target so brute-force in pure Python finds a
   nonce in seconds. Asserts: scriptSig is 72 bytes, parses back as
   `is_v1=True`, the resulting contract output chains correctly to a
   second mint. Optional `RADIANT_INTEGRATION` path pushes the tx hex to
   the existing VPS for `testmempoolaccept`.

2. **Manual `examples/dmint_claim_demo.py`**: env-var-driven, modeled on
   [`examples/ft_deploy_premine.py`](../../examples/ft_deploy_premine.py).
   `DRY_RUN=1` default. On broadcast failure: print the failure and exit
   (the developer re-runs by hand). No resume JSON — the manual one-off
   nature of the script doesn't justify it, and a re-mine from a fresh
   contract-state query is correct anyway because the preimage is
   contractRef-bound and goes stale on chain advance. Polls
   confirmations after successful broadcast. **Manual acceptance gate**:
   at least one mint against a live RBG contract confirmed on-chain.

## Technical Considerations

### Architecture impacts

Surface area added to `pyrxd.glyph.dmint`:
- `mine_solution(preimage, target, *, algo, nonce_width, max_attempts) -> DmintMineResult` (new public API; raises `MaxAttemptsError`)
- `DmintMineResult` frozen dataclass (new public type)
- `build_dmint_v1_code_script(algo)` (new public helper, sibling of `build_dmint_code_script`)
- `verify_sha256d_solution(preimage, nonce, target, *, nonce_width=8)` (signature change — additive, default preserves V2 behavior)

Surface area added to `pyrxd.security.errors`:
- `DmintError(RxdSdkError)` (new parent class for dMint-domain errors)
- `MaxAttemptsError(DmintError)`
- `InvalidFundingUtxoError(DmintError)` — raised by the example demo when assembling funding inputs (see "Funding-UTXO sanity check" below)
- `ContractExhaustedError(DmintError)` — raised by `build_dmint_mint_tx` V1 branch
- `PoolTooSmallError(DmintError)` — raised by `build_dmint_mint_tx` V1 branch

`build_dmint_mint_tx` keeps its signature; the V1 branch is internal
and early-returns rather than falling through V2's DAA-target update
path.

### Funding-UTXO sanity check

Spending a token-bearing UTXO as fee silently destroys the token. The
funding-UTXO check must reject any input that carries an FT or dMint
ref envelope.

**Where the check lives:**
[`build_dmint_mint_tx`](../../src/pyrxd/glyph/dmint.py#L1019) only
takes the contract input — funding UTXOs are assembled by callers
(the example script, future wallet integrations). The check therefore
lives in `examples/dmint_claim_demo.py`'s funding-UTXO selection
loop, not in the library function. This matches the pattern at
[examples/ft_transfer_demo.py:163-167](../../examples/ft_transfer_demo.py#L163)
where `is_ft_script` is the example-side filter.

The library raises `InvalidFundingUtxoError` for callers who pass an
already-classified bad UTXO via a future expanded signature — but in
M1 the function signature is unchanged, so the only caller that
exercises the error path is the demo.

For each candidate funding UTXO, the demo:
1. Fetches the source tx
2. Classifies the locking script: `is_ft_script(script.hex())` and
   `DmintState.from_script(script)` must both return falsy
3. Skips with logged warning if either matches
4. Raises `InvalidFundingUtxoError` if no clean funding UTXOs remain

### Contract-exhaustion / pool-size validation

Before the miner loop, validate:
- `state.height < state.max_height` (otherwise raise `ContractExhausted`)
- `contract_pool >= state.reward + min_fee + dust_floor` (otherwise raise
  `PoolTooSmall`)

Both are deterministic from parsed state and ~430-byte tx size estimate.
Failing fast saves the developer minutes of mining only to discover the
contract can't be claimed.
[`tests/test_dmint_end_to_end.py:638` (`test_pool_too_small_raises`)](../../tests/test_dmint_end_to_end.py#L638)
already covers the V2 shape; add the V1 sibling case.

### Stale-state race in flow C

Between query-contract-state and broadcast, another miner can claim
height N first. The script's broadcast then fails because the spent
input is gone. `examples/dmint_claim_demo.py` handles this minimally:
print the broadcast failure (with the rejection reason if available)
and exit non-zero. The developer re-runs the script, which re-queries
state and re-mines from scratch. Re-using a stale preimage would be
wrong (contractRef-bound), so an automatic retry loop wouldn't help
even if it were worth the complexity.

### External miner integration (M2)

`mine_solution` is intentionally minimal in M1 — sequential nonce
sweep, no plug-in points. Users wanting fast mining today run
`glyph-miner` standalone, take the resulting hex nonce, and pass it to
the tx-finalize path manually. A typed `nonce_provider` parameter and
JSON shim protocol are M2 work, to be added when a real external-miner
caller exists.

### Performance implications

**ESTIMATED**: pure-Python sha256d via `hashlib` runs at roughly
1–2 million hashes/sec on a modern CPU core (measured ≈1.75M h/s on
i9-14900K by performance-oracle review; not yet measured on the
project test machine). At RBG's target `0x00da740da740da74` (~2^34
expected attempts), one mainnet claim is on the order of single-digit
hours single-threaded, not days. The "slow but correct" framing still
applies — anyone wanting to mine routinely uses `glyph-miner`. The
acceptance test will record the actual measured rate on its host.

The `max_attempts` default (600M ≈ minutes single-threaded) prevents a
naïve `mine_solution()` call from wedging for hours on real-mainnet
difficulty without explicit opt-in.

### Security considerations

- **Funding-UTXO check (above) is a security control**, not just
  ergonomics — silently spending FT UTXOs as fee is a token-burn bug.
- **No private-key handling changes.** The signing surface is the
  existing P2PKH path used by every other broadcaster. No new attack
  surface.
- **Mining is offline.** No network calls inside `mine_solution`. The
  preimage-target shim protocol is local-only (subprocess stdin/stdout),
  not a network endpoint.
- **License attribution.** glyph-miner is MIT (`/home/eric/apps/Pinball/glyph-miner/LICENSE`).
  pyrxd is Apache 2.0. Compatible. If specific algorithm code is ported
  (e.g. midstate-precompute pattern), preserve the MIT header per file
  or add to NOTICE. Not a legal opinion.

## Acceptance Criteria

### Functional

- [x] `build_dmint_mint_tx` accepts V1 contract states without raising
- [x] V1 path produces a 72-byte scriptSig (4B nonce + 32B inputHash + 32B outputHash + OP_0)
- [x] V1 mint tx parses back as `is_v1=True` via `DmintState.from_script`
- [x] Two consecutive V1 mints chain correctly (contract output of mint 1 is the contract input of mint 2)
- [x] `mine_solution(preimage, target, nonce_width=4)` returns a `DmintMineResult` whose nonce passes `verify_sha256d_solution`. **Tested via `hashlib.sha256` monkey-patch** — same pattern as `test_clamp_invariant_via_construction` in the existing V2 module tests. Discovered during implementation: dMint has a hard 32-bit leading-zero floor (`hash[0..4] == 0x00000000` is required regardless of `target`), so even the easiest possible dMint contract requires ~4B hash attempts to mine. End-to-end search in unit tests is impractical — would either skip or take ≈30 min single-core pure Python.
- [x] `mine_solution` raises `MaxAttemptsError` (with `attempts` and `elapsed_s` attributes) when `max_attempts` is reached without a solution
- [x] `mine_solution` raises `ValidationError` at runtime when `nonce_width not in (4, 8)` (Literal is type-checker-only)
- [x] An optional slow brute-force test (skipped on no-find, mirrors existing `test_brute_force_finds_valid` shape) confirms search loop integration with real `hashlib`
- [ ] `examples/dmint_claim_demo.py` raises `InvalidFundingUtxoError` when funding-UTXO scan finds no plain-RXD candidates (FT/dMint UTXOs are filtered out) — *deferred to Session C; demo script not in this session's scope*
- [x] `build_dmint_mint_tx` raises `ContractExhaustedError` when `height >= max_height`
- [x] `build_dmint_mint_tx` raises `PoolTooSmallError` when contract pool can't cover reward + fee + dust
- [x] **NEW**: `mine_solution_external(preimage, target, miner_argv, nonce_width)` delegates nonce search to a subprocess (e.g. glyph-miner), re-verifies the returned nonce locally, and raises `ValidationError` on miner-returned bad nonces. Added during implementation when user surfaced the GPU-mining use case as a real near-term need.

### Test requirements

- [x] New file `tests/test_dmint_v1_mint.py` with `TestBuildDmintMintTxV1` class (49 tests covering V1 builders, V1 mint dispatch, mine_solution, mine_solution_external, deploy DeprecationWarning)
- [x] All synthetic V1 mint tests pass under `pytest -m unit` — full suite 2592 passed, 10 skipped, 0 failed
- [ ] Optional `pytest -m integration` path pushes V1 mint tx via SSH to VPS `testmempoolaccept` (gated by `RADIANT_INTEGRATION` env var, same pattern as
  [test_dmint_deploy_integration.py:488](../../tests/test_dmint_deploy_integration.py#L488)) — *deferred to Session C/D*
- [x] No regressions in V2 mint path — existing `TestBuildDmintMintTx` continues to pass; updated `test_exhausted_contract_raises` and `test_pool_too_small_raises` to match the new typed-error class names (the V2 path now raises `ContractExhaustedError`/`PoolTooSmallError` for parity with V1)

### Manual acceptance (gate before declaring milestone shipped)

- [ ] One mint against a live V1 contract on mainnet (RBG target —
  contract at maxHeight 628,328, currently ~14% mined per
  [docs/dmint-research-mainnet.md §2.3](../dmint-research-mainnet.md))
  confirmed on-chain. Tx hash recorded in milestone close-out note.

### Documentation

- [x] `mine_solution` docstring includes a worked hex example
  (preimage in → nonce out → verifier passes)
- [ ] `examples/dmint_claim_demo.py` exists, env-var driven, `DRY_RUN=1` default — *deferred to Session C*
- [ ] `docs/dmint-followup.md` gets an "out of date — see code" warning
  at the top (full rewrite lands in Milestone 2) — *deferred to Session D*
- [x] `prepare_dmint_deploy` carries both a docstring warning AND a
  runtime `DeprecationWarning` for the V2-deploy footgun (see
  "Deploy-footgun mitigation in M1" below)
- [x] Test confirms the `DeprecationWarning` fires on
  `prepare_dmint_deploy` calls

## Success Metrics

- **Primary:** one confirmed live V1 mint tx (binary outcome).
- **Secondary:** synthetic V1 mint test stable on CI for 2+ weeks
  without flake.
- **Tertiary:** at least one external user (or the developer themselves
  via `glyph-miner`) plugs in the external-miner shim and produces a
  valid mint, confirming the JSON protocol is usable.

## Dependencies & Risks

### Dependencies

- VPS Radiant node at `89.117.20.219` for `testmempoolaccept`
  (existing — already used by deploy-integration tests).
- `glyph-miner` project at `/home/eric/apps/Pinball/glyph-miner` for
  the optional fast-mining path. Not a hard dependency for shipping
  M1, but a cross-check during real-mint testing.

### Risks

- **Stale `dmint-research-mainnet.md` open question on input/output
  hash construction** — RESOLVED by glyph-miner reference: each is
  `SHA256d(serialized_script)` of the miner's chosen funding-input
  script and OP_RETURN output script. Encoded in code now, not just
  the doc.
- **OP_RETURN "msg" output may or may not be covenant-required.**
  Photonic convention pushes `<6d7367 ("msg")> <message>` as vout[2]
  in the example mint trace at
  [docs/dmint-research-mainnet.md §4](../dmint-research-mainnet.md). The V1 covenant
  bytecode walk does not appear to enforce a specific OP_RETURN format,
  but this is unconfirmed. **Mitigation:** include the canonical "msg"
  OP_RETURN in our V1 mint to match what every observed mainnet mint
  does. If a future user wants to omit it, that's a separate
  experiment.
- **`testmempoolaccept` doesn't actually verify covenant satisfaction
  at mempool-acceptance time** — it verifies the script signature
  evaluates to true, which is exactly the covenant. So this concern is
  largely moot, but worth noting: a positive `testmempoolaccept` is
  strong evidence, not proof. Only a confirmed-on-chain tx is proof.
- **Race in flow C** — addressed by stale-state recovery in the demo
  script (above). Worst case: developer pays ~0.043 RXD in fees for a
  few attempts before the contract advances past them. Bounded.
- **ElectrumX has no `get_outpoint(txid, vout)` primitive.** Workaround:
  fetch raw tx via `get_transaction`, parse outputs. Adequate for M1.
  Add a typed primitive in a separate cleanup PR if it becomes painful.

## Out of Scope

Punted to Milestone 2 (V1 deploy):
- V1 deploy builders (`prepare_dmint_deploy` V1 path)
- Closing the deploy footgun (`prepare_dmint_deploy` currently always
  emits V2 with no opt-out — see "Deploy-footgun mitigation in M1"
  below for the minimal stop-gap M1 should ship)
- Cross-tool verification (glyph-miner mines the pyrxd-deployed token)
- Full rewrite of `docs/dmint-followup.md`
- Example `examples/dmint_deploy_demo.py`

Deferred to M3 (indefinite — only if/when someone wants V2's DAA
features):
- V2 deploy live-network proof
- BLAKE3 and K12 algorithms
- EPOCH and SCHEDULE DAA modes

Out of scope, period (always — that's `glyph-miner`'s job):
- Fast (C++/GPU) miner

Separate concern:
- A typed `get_outpoint(txid, vout)` ElectrumX primitive (separate PR if needed)

## Deploy-footgun mitigation in M1

Closing the V1 deploy gap is an M2 milestone, but M1 should not let
the gap get *worse*. Two layered guards on
[`prepare_dmint_deploy`](../../src/pyrxd/glyph/builder.py#L291) before
M1 ships:

1. **Docstring warning** at the top of `prepare_dmint_deploy`:

   > ⚠️ **This currently emits a V2 dMint contract.** No live mainnet
   > contracts are V2, no external miner (e.g. glyph-miner) targets V2,
   > and indexer behavior on V2 deploys is empirically unknown. If you
   > issue a token with this function today, nobody will be able to
   > mine it without bespoke tooling. V1 deploy support is M2; this
   > warning will be removed when `version="v1"` is the default.

2. **Runtime `DeprecationWarning`** raised at the entry of
   `prepare_dmint_deploy`. Surfaces in CI logs and lets tests opt into
   `warnings.simplefilter("error")` to catch accidental V2 issuance:

   ```python
   warnings.warn(
       "prepare_dmint_deploy currently emits V2 dMint contracts; "
       "no ecosystem miner targets V2. V1 deploy lands in M2. "
       "See docs/plans/2026-05-07-feat-dmint-v1-mint-and-reference-miner-plan.md",
       DeprecationWarning,
       stacklevel=2,
   )
   ```

The runtime warning is the load-bearing guard — docstrings get skipped,
warnings show up in logs. ~3 lines. Both removed when M2 ships
`version: Literal["v1", "v2"] = "v1"`.

Acceptance: both guards in place. Test confirms the
`DeprecationWarning` fires on `prepare_dmint_deploy` calls.

## References & Research

### Internal references

- [`docs/brainstorms/2026-05-07-dmint-integration-brainstorm.md`](../brainstorms/2026-05-07-dmint-integration-brainstorm.md) — feature scope decisions
- [`src/pyrxd/glyph/dmint.py`](../../src/pyrxd/glyph/dmint.py) (1268 L) —
  V1 fingerprint at [L562](../../src/pyrxd/glyph/dmint.py#L562),
  `_from_v1_script` at [L781](../../src/pyrxd/glyph/dmint.py#L781),
  `build_pow_preimage` at [L326](../../src/pyrxd/glyph/dmint.py#L326),
  `build_mint_scriptsig` at [L365](../../src/pyrxd/glyph/dmint.py#L365),
  `verify_sha256d_solution` at [L466](../../src/pyrxd/glyph/dmint.py#L466),
  `build_dmint_mint_tx` at [L1019](../../src/pyrxd/glyph/dmint.py#L1019),
  V1 reject at [L1091](../../src/pyrxd/glyph/dmint.py#L1091)
- [`src/pyrxd/glyph/builder.py:291`](../../src/pyrxd/glyph/builder.py#L291) — `prepare_dmint_deploy` (already ships)
- [`tests/test_dmint_end_to_end.py:554`](../../tests/test_dmint_end_to_end.py#L554) — `TestBuildDmintMintTx` (V2 template to mirror for V1)
- [`tests/test_dmint_module.py:339`](../../tests/test_dmint_module.py#L339) — low-difficulty mining template
- [`tests/test_dmint_deploy_integration.py:488`](../../tests/test_dmint_deploy_integration.py#L488) — VPS testmempoolaccept pattern
- [`examples/ft_deploy_premine.py`](../../examples/ft_deploy_premine.py) — env-var/DRY_RUN/resume pattern for the demo script
- [`examples/ft_transfer_demo.py`](../../examples/ft_transfer_demo.py) — `is_ft_script` precondition pattern
- [`docs/dmint-research-mainnet.md`](../dmint-research-mainnet.md) — live V1 contract decode + mint trace
- [`docs/dmint-research-photonic.md`](../dmint-research-photonic.md) — Photonic Wallet TS reference
- [`docs/solutions/logic-errors/dmint-v1-classifier-gap.md`](../solutions/logic-errors/dmint-v1-classifier-gap.md) — prior incident: V1 classifier gap exposed by RBG live test (drives the synthetic-then-real testing approach)

### External references

- `/home/eric/apps/Pinball/glyph-miner/` (MIT) — authoritative V1 mining algorithm
  - `src/pow.ts` L11–18 — preimage construction
  - `src/miner.ts` L283–311 — midstate precompute
  - `src/miner.ts` L494–508 — target check (BE)
  - `src/nonce.ts` L7–13 — V1=4B/V2=8B widths

### Files to be created

- `tests/test_dmint_v1_mint.py` — synthetic V1 mint test class
- `examples/dmint_claim_demo.py` — manual real-mint script

### Files to be modified

- `src/pyrxd/glyph/dmint.py` — V1 branch in `build_dmint_mint_tx`,
  `mine_solution`, parameterized verifier, V1 code-script helper
- `docs/dmint-followup.md` — top-of-file "stale" warning
