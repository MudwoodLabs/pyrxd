---
title: First real-mainnet V1 dMint deploy via pyrxd
type: plan
date: 2026-05-11
status: SHIPPED — deploy confirmed on chain
---

# First real-mainnet V1 dMint deploy via pyrxd

## Status: ✅ Shipped 2026-05-11

PXD token (a synthetic test token deployed from a throwaway wallet)
is the first real V1 dMint deploy via pyrxd. End-to-end verified
against the live Radiant mainnet.

| Artifact | Value |
|---|---|
| **Commit txid** | `1acbb42abce7a508612a8fed8a14ccb5d1f59a3e69434b7df37fb95944de8df5` |
| **Reveal txid** | `8eeb333943771991c2752abc78038365ecd76b1a24426f7a3212eea71b6a6564` |
| **Token ref** | `1acbb42a…8df5:0` |
| **Deployer** | `1MUamwwnkbqcry2kKJW21tFtYAEGLFXke3` (throwaway test wallet) |
| **Ticker / name / desc** | `PXD` / `pyrxd V1 demo` / `V1 dMint demo deploy via pyrxd` |
| **Protocol vector** | `p: [1, 4]` (no `v` field, no `dmint:{...}` sub-dict) |
| **num_contracts** | 4 |
| **max_height** | 100 |
| **reward_photons** | 1,000 |
| **difficulty** | 1 |
| **Total supply** | 400,000 photons (4 × 100 × 1,000) |
| **Total cost** | ~24.1M photons (commit 4.12M + reveal 19.98M) |

**Contracts at**: `8eeb3339…6564:0..3`, each at `height=0` (never mined).

**Demo bugs caught + fixed pre-deploy** (PR #66 commit `5b228a3`):

1. vin 0 locking_script was P2PKH instead of the 75-byte FT-commit
   hashlock — every live broadcast would have failed sighash
2. `commit_script` not threaded through `_build_reveal_tx`
3. `target_value` for commit funding was 500K photons (too small —
   would drop change to dust)
4. Resume path had no drift detection (changing env vars between
   commit and resume would silently produce an invalid reveal)

All four caught by code-audit + integration thinking BEFORE any
broadcast. Regression-locked by 4 new tests in
`tests/test_dmint_v1_deploy.py::TestDeployDemoRevealWiring`.

## Overview (historical — pre-deploy plan)

M2 (PR #66) shipped byte-equal validation of pyrxd's V1 deploy library
against the live GLYPH deploy (`a443d9df…878b` / `b965b32d…9dd6`). The
test suite proves the **scripts** the library emits are byte-identical
to chain truth. **We have not yet broadcast a deploy.** This plan
covers the end-to-end first live mainnet test.

The cost on RXD is trivial (a few thousand sats total); the value is
closing the loop: byte-equal-vs-chain → broadcast-and-it-confirms →
indexer-recognises-it → mineable → token-shows-up-in-explorer.

## Problem statement

What we know works today:

- Byte-equal V1 contract scripts (test pinned vs GLYPH vout 0).
- Byte-equal CBOR shape (`p:[1,4]`, no `v`, no `dmint:{...}`).
- `find_dmint_contract_utxos` against the live chain (returns 0 for
  GLYPH because every contract has advanced past initial state —
  but the chain walk + S2 cross-check itself works).
- Inspect tool reads the live GLYPH reveal end to end (PUSHDATA4 +
  CBOR cap + CBORTag unwrap fixes).

What we have NOT verified:

- That a tx assembled by our demo, signed by our key, broadcast to
  mainnet, will actually accept into mempool and confirm.
- That RXinDexer parses our deploy as a V1 dMint token.
- That an external miner (glyph-miner or our M1 demo) can mint from
  one of our contracts.
- That the token shows up on the Photonic explorer.

## Known issues to fix before broadcast

Two real bugs in the demo (`examples/dmint_v1_deploy_demo.py`) that
the byte-equal tests don't exercise because they don't sign or
serialize a full tx — they only check the contract output bytes:

### Bug 1: vin 0 locking script is wrong

The reveal's vin 0 spends the FT-commit hashlock (75-byte gly
script). The demo sets `inp0.locking_script = p2pkh_lock` instead of
the actual hashlock script. The sighash preimage is computed against
the locking script, so signing it against `p2pkh_lock` produces an
ECDSA signature that won't satisfy the embedded P2PKH at the tail of
the actual 75-byte script.

**Fix:** Thread the commit script through `_build_reveal_tx` and use
it for `inp0.locking_script` (and `inp0.source_transaction.outputs[0]`).

### Bug 2: commit script not passed through

`_build_reveal_tx` accepts `cbor_bytes` and `scriptsig_suffix` but not
the actual 75-byte commit script. Add a `commit_script: bytes`
parameter and pass `result.commit_result.commit_script` at the call
site.

Both bugs are demo-only — they don't affect the library code that
M2's tests cover. But they DO block live broadcast.

## Proposed Solution

### Phase 1 — fix the demo (no broadcast yet)

1. Add `commit_script: bytes` parameter to `_build_reveal_tx`.
2. At the demo call site, pass `result.commit_result.commit_script`.
3. In the reveal builder, set vin 0's `locking_script` to
   `Script(commit_script)` and its `source_transaction.outputs[0]`
   to `TransactionOutput(Script(commit_script), 1)`.
4. Run `DRY_RUN=1` with a synthetic test wallet — inspect the
   reveal tx hex via `pyrxd glyph inspect <hex> --raw`. The reveal
   should parse: N 241-byte contract outputs, one P2PKH change, no
   bad opcodes.

### Phase 2 — prep the test wallet

Either:
- **Option A (recommended):** Generate a fresh test wallet
  specifically for this deploy. Fund it with ~5,000 RXD (≈ $0.50 at
  RXD's current price; tiny by any measure). Burns the wallet after
  the test rather than mixing test artifacts with production funds.
- **Option B:** Reuse an existing dev wallet that already has plain
  RXD UTXOs. Faster but mixes the test deploy's tx history with
  other work.

Funding requirements (rough):
- Commit tx: ~300 bytes × 10K photons/byte = 3M photons fee +
  (1 + N) photons for outputs ≈ 3M + 5 = ~3M photons (~0.0003 RXD)
- Reveal tx: ~600 bytes for N=4 contracts + 1 change × 10K photons/
  byte ≈ 6M photons fee + N (=4) contract photons + change.

Total: comfortably under 50M photons. Funding with 1,000,000,000
photons (10 RXD) gives a wide margin.

### Phase 3 — token parameters

Demo defaults are fine for a first deploy:

| Field            | Default | Rationale                                                  |
|------------------|--------:|------------------------------------------------------------|
| `num_contracts`  |       4 | Small enough to verify each one in inspect / explorer      |
| `max_height`     |     100 | Lets us mine multiple times without exhausting             |
| `reward_photons` |   1,000 | 1 satoshi-level — clearly distinguishable                  |
| `difficulty`     |       1 | Easiest possible target → CPU-mineable in milliseconds     |
| Total supply     | 400,000 | 4 × 100 × 1,000 photons = 0.004 of the token @ 8 decimals  |

Token metadata:
- `ticker`: `PXD` (or some test-only ticker)
- `name`: `pyrxd V1 test`
- `description`: `First mainnet V1 dMint deploy via pyrxd`
- No `main` (no embedded image — keep CBOR body small for the first test)

### Phase 4 — dry-run

```bash
cd /home/eric/apps/pyrxd/.worktrees/feat/dmint-v1-deploy
DRY_RUN=1 GLYPH_WIF=<test-wif> \
  /home/eric/apps/pyrxd/.venv/bin/python examples/dmint_v1_deploy_demo.py
```

Expected output:
- Payload hash printed
- CBOR size printed (should be small — ~80 bytes for plain metadata)
- "Fetching UTXOs and filtering token-bearing..." → reports plain UTXO
- Commit tx hex printed + txid + size + fee
- Tells us to set `COMMIT_TXID=… COMMIT_VOUT=0 COMMIT_VALUE=1` to resume

Inspect the printed commit hex via `pyrxd glyph inspect <hex> --raw`
to verify:
- 1 + N + 1 = 6 outputs (for N=4): 1 FT-commit (75 bytes), 4 P2PKHs,
  1 change.
- vout 0 is a 75-byte hashlock starting `aa20…`.

### Phase 5 — commit broadcast

```bash
DRY_RUN=0 I_UNDERSTAND_THIS_IS_REAL=yes \
  GLYPH_WIF=<test-wif> \
  /home/eric/apps/pyrxd/.venv/bin/python examples/dmint_v1_deploy_demo.py
```

Demo:
- Builds commit
- Broadcasts commit
- Waits 90s for confirmation
- Builds reveal
- Broadcasts reveal

Acceptance gate: both txids confirm in a block within 5 minutes (or
re-run with explicit fee bump). If the commit confirms but reveal
fails, we still have the resume path (`COMMIT_TXID=…`) to debug
the reveal without re-broadcasting.

### Phase 6 — verification

Once both confirm:

1. **Library round-trip.** Run
   `pyrxd glyph inspect <reveal_txid> --fetch` and confirm:
   - 4 dMint contract outputs detected
   - CBOR metadata extracted: `protocol=[1, 4]`, `ticker=PXD`,
     `name=pyrxd V1 test`
   - No errors

2. **Chain helper.** Run
   `find_dmint_contract_utxos(client, token_ref=GlyphRef(txid=<commit_txid>, vout=0))`
   and confirm it returns 4 unspent contracts (Shape B walk-from-reveal).

3. **RXinDexer.** Wait for the indexer to ingest the block. Query
   for the token by its `tokenRef` (= `<commit_txid>:0`). It should
   appear as a V1 dMint deploy with our params.

4. **Mint one from a contract.** Use `examples/dmint_claim_demo.py`
   (M1's mint demo) against one of the 4 contracts. The demo asks
   for a `CONTRACT_TXID` and `CONTRACT_VOUT` — use our reveal txid
   + vout 0. Difficulty=1 → CPU mines instantly.

5. **Explorer check.** Open Photonic / Radiant block explorer.
   Search for our `tokenRef`. Token should be listed with the
   correct supply, name, ticker.

## Acceptance Criteria

- [x] Bug 1 + Bug 2 fixed in `examples/dmint_v1_deploy_demo.py`
      (PR #66 commit `5b228a3`; 4 regression tests added)
- [x] DRY_RUN output inspected and matches expected shape (1 commit-ft
      + 5 P2PKH, 411 bytes commit tx)
- [x] Commit tx broadcasts and confirms (`1acbb42a…8df5`, h=428049)
- [x] Reveal tx broadcasts and confirms (`8eeb3339…6564`, same block)
- [x] Inspect tool parses both txs end-to-end: 1× commit-ft + 5× p2pkh
      on commit; 4× dmint + 1× p2pkh on reveal; metadata `p:[1,4]`,
      ticker=PXD, name="pyrxd V1 demo", desc correct
- [x] `find_dmint_contract_utxos(token_ref=...)` returns 4 contracts
      (Shape B walk-from-reveal) — all at `height=0`, each with the
      right `contractRef[i]` and shared `tokenRef`
- [ ] RXinDexer recognises the deploy (out-of-band — depends on
      indexer ingest timing; not required for pyrxd-side acceptance)
- [ ] M1 mint demo successfully mints from one of the contracts
      (in progress — Python CPU miner running, ~40 min expected)
- [ ] Token shows up on a block explorer (out-of-band — explorer
      ingest timing)

## Failure modes & contingencies

| Symptom                                          | Likely cause                                              | Fix                                                                              |
|--------------------------------------------------|-----------------------------------------------------------|----------------------------------------------------------------------------------|
| Commit broadcast rejected (mempool)              | Fee too low or non-standard script                        | Inspect via `testmempoolaccept` on the dev node first                            |
| Reveal broadcast rejected: bad-script             | vin 0 locking script wrong (Bug 1 not fixed)              | Phase 1 — fix the demo                                                           |
| Reveal broadcast rejected: bad-sig               | Wrong sighash preimage or key                             | Verify `funding_pkh_lock` matches the deployer's address                         |
| RXinDexer ignores the deploy                     | CBOR shape wrong (`v` field present, `p` wrong)           | Test pin (`TestV1CborShape`) already guards this — but double-check raw CBOR     |
| Inspector doesn't find contract outputs          | State items in wrong order                                | Byte-equal golden vector guards this — investigate parser-side                   |
| Mining returns "not exhausted, but balance off"  | Reward emission shape mismatch                            | Compare mint preimage to M1 mainnet trace at `docs/dmint-research-mainnet.md`    |

## Out of scope for this first deploy

- Auth NFT in the deploy reveal (M2 demo omits this; future work)
- Premine FT output (deferred per Photonic divergence #2)
- Large CBOR body with embedded image (forces PUSHDATA4 — already
  tested via inspect-tool unit tests; not retesting on chain here)
- High-difficulty deploy (we want the test cheap and fast)
- Public token (we deliberately use a throwaway name + ticker)

## References

- M2 plan: `docs/plans/2026-05-08-feat-dmint-v1-deploy-plan.md`
- M2 research: `docs/dmint-research-photonic-deploy.md`
- M2 concept: `docs/concepts/dmint-v1-deploy.md`
- Demo: `examples/dmint_v1_deploy_demo.py`
- M1 mint demo: `examples/dmint_claim_demo.py`
- PR #66: https://github.com/MudwoodLabs/pyrxd/pull/66
