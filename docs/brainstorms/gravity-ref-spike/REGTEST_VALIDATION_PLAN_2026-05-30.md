I have everything I need. All key facts are source-verified: `SpvProofBuilder.build` requires `output_offset` and `tx_block_height`; `verify_chain`/`Nbits` caps exponent at 0x1d (types.py:203-204); the regtest harness reuses `_RegtestNode` + `_pay_to_spk`; `build_finalize_tx` does sentinel-padding and floor-enforcement; `build_gravity_offer` requires `anchor_height` + `merkle_depth` (spec JSON omitted these). Now writing the plan.

# Live-Regtest Validation Plan — Covenant Semantics the Differential Test Leaves Skipped

**Scope:** Resolve every skip-marked / `xfail` / "NOT modelled" question in `tests/test_spv_covenant_differential_deployed.py` against real Radiant consensus, using `testmempoolaccept` on an isolated `radiant-core:v2.3.0` regtest node. This is a **plan**, not an execution. No node is touched until the Go/No-Go checklist (§6) is approved.

---

## 1. Objective + venue

The differential test (`tests/test_spv_covenant_differential_deployed.py`) hand-ports a Python *model* of the deployed `MakerCovenantFlat12x20` and diffs it against the real Python SPV path (`verify_payment` / `verify_chain` / `verify_tx_in_block`). For four classes of question the model **deliberately refuses to predict accept/reject** (docstring lines 143-148; skips at 576-583 and 716-724; `xfail` at 651-665) because the answer depends on *consensus-level script semantics no Python code reproduces*: (a) `OP_BIN2NUM` on a 5–8 significant-byte value field (Radiant's `CScriptNum` element-size limit), (b) the nBits exponent ceiling 0x1e–0x20 the covenant tolerates but Python's `Nbits` rejects at `>0x1d` (`security/types.py:203-204`), (c) `OP_OUTPUTBYTECODE`/`OP_OUTPUTVALUE` index-0-only introspection arity on a multi-output finalize, (d) the empty-scriptSig and compile-time `claimDeadline` clamp on live consensus. The **only** way to resolve these is to run the actual script interpreter. **Regtest + `testmempoolaccept` is the correct venue** because it runs the *identical v2.3.0 consensus script interpreter* (same `radiant-core:v2.3.0-amd64` image already used by `tests/test_htlc_regtest_e2e.py`), is **free** (no value moves — `testmempoolaccept` validates the script and reports `allowed`/`reject-reason` without adding to the mempool or broadcasting), is **isolated** (a throwaway container with its own wallet/chain, torn down after), and lets us grind trivially-easy PoW headers (relaxed regtest target) to reach exponent and value classes that are economically impossible on mainnet. **This work NEVER touches a mainnet node.** The mainnet radiant-node on host `tr` is explicitly out of scope; the container's `start()` asserts `chain == "regtest"` before proceeding (`test_htlc_regtest_e2e.py:141`) and we will not relax that gate. Every tx we build is fed only to `testmempoolaccept`; we never call `sendrawtransaction` on anything carrying real value.

---

## 2. Setup

### 2.1 Reuse verbatim (no new code)

| Helper | Source | Role |
|---|---|---|
| `_RegtestNode` (`start`/`stop`/`cli`/`mine`/`accepts`) | `tests/test_htlc_regtest_e2e.py:66-147` | Self-managed isolated container; `accepts()` wraps `testmempoolaccept` (line 98-100). **Copy/import wholesale.** |
| `node` fixture + gating | `test_htlc_regtest_e2e.py:150-164` | `RADIANT_REGTEST=1` opt-in + docker-image-inspect skip + `pytest.mark.integration`. **Copy verbatim.** |
| `_pay_to_spk(node, dest_spk, amount)` | `test_htlc_regtest_e2e.py:194-248` | Funds **any** SPK at vout 0 and mines 1. Reusable for the Gravity claimed-P2SH **without modification** (it pays an arbitrary `dest_spk`). |
| `_fee_input` / `_src` / `_p2pkh_unlock` | `test_htlc_regtest_e2e.py:170-259` | Tx plumbing if a separate fee leg is wanted (not strictly needed — see 2.4). |
| `build_gravity_offer` | `src/pyrxd/gravity/covenant.py:328` | Produces the offer with `claimed_redeem_hex` + `expected_code_hash_hex`. |
| `compute_p2sh_script_pubkey` / `compute_p2sh_code_hash` | `src/pyrxd/gravity/codehash.py:30,39` | Derive the 23-byte P2SH SPK to fund, and the consistency check. |
| `build_finalize_tx` | `src/pyrxd/gravity/transactions.py:555` | Assembles the finalize scriptSig (`<h1..h12><padded_branch><rawTx>OP_0<redeem>`), does sentinel-padding (`:660-661`), enforces the photons floor (`:613`) and the PUSHDATA2 ceiling (`:626`). |
| `SpvProofBuilder(params).build(...)` | `src/pyrxd/spv/proof.py:315` | Builds + Python-verifies the `SpvProof`; signature requires `txid_be, raw_tx_hex, headers_hex, merkle_be, pos, output_offset, tx_block_height`. |
| `_grind_tx_into_block` | `test_spv_covenant_differential_deployed.py:589-617` | Grinds **one** relaxed header (nbits `ffff7f1d`, exp 0x1d, byte-29..31==0 gate) — the grinding *pattern* to extend. |

### 2.2 Helpers that MUST be written (these do not exist)

Grep confirms **no Gravity finalize test touches a live node** (no `testmempoolaccept`/`sendrawtransaction`/docker in `tests/test_gravity*.py` / `test_covenant.py` — all unit-level). The following are the new pieces:

1. **`_deploy_claimed_utxo(node, offer) -> (txid, vout, value)`** (~6 lines). Wraps a single `_pay_to_spk(node, compute_p2sh_script_pubkey(bytes.fromhex(offer.claimed_redeem_hex)), value)` call to create the `MakerClaimed` P2SH UTXO at vout 0, then `node.mine(1)`. **This is the single missing deploy primitive.** It is legal to shortcut past the offer→claim lifecycle because `finalize()` inspects only the *spending* tx (output-0 SPK/value introspection) + the scriptSig SPV data — it does **not** verify how the claimed UTXO was created. (One-time cross-check: also run the full lifecycle `build_maker_offer_tx`→`build_claim_tx` path once and assert the finalize verdict is identical, to prove the shortcut is faithful.)

2. **`_grind_anchored_chain(payment_spk, *, nbits, n_headers=12, real_depth=1) -> (SpvProof inputs)`** — generalizes `_grind_tx_into_block` from 1 header to a **12-header anchored chain**. For `h1`: `prevHash=anchor`, `merkleRoot=H(sib_le||txid_le)` for pos=1, grind nonce until `verify_header_pow` passes. For `h2..h12`: `prevHash=hash256(h_{i-1})`, reuse the merkle root, grind each for PoW. Regtest PoW is trivial (relaxed target), so 12 headers grind fast. The covenant's per-header loop needs all 12 to chain and each nBits ∈ {expectedNBits, expectedNBitsNext}. Feed into `SpvProofBuilder.build(txid_be, raw_hex, [h1..h12], [sib_be], pos=1, output_offset, tx_block_height=anchor_height+1)`. **This is the second missing piece** — the existing grinder only does one header.

3. **`_substitute_nbits_covenant(nbits_exp_byte) -> claimed_redeem_hex`** — for the nBits-ceiling cases ONLY: `CovenantArtifact.load("maker_covenant_flat_12x20_sentinel_all")._substitute(...)` directly with `expectedNBits`/`expectedNBitsNext` set to an exp-0x1e..0x21 value, **bypassing `build_gravity_offer`** (whose `_Nbits` guard at `covenant.py:486` rejects exp>0x1d and would refuse to even create the covenant). Required for §3 cases NB-1/NB-2.

> **Spec correction (load-bearing):** Several spec cases call `build_gravity_offer(...)` without `anchor_height` and `merkle_depth`. Both are **required positional params** (`covenant.py:338-339`). The harness must pass them (`anchor_height` = the regtest height the anchor sits at; `merkle_depth` = real branch depth, e.g. 1). This is a real wiring detail, not optional.

### 2.3 The reusable finalize-build path (every case routes through this)

For a given case shape `(raw_tx, headers, branch, value, ssl, output-shape, claimed_redeem)`:
`offer = build_gravity_offer(...)` (or `_substitute_nbits_covenant` for NB cases) → `claimed_spk = compute_p2sh_script_pubkey(...)` → `(txid,vout,val) = _deploy_claimed_utxo(...)` → `spv = _grind_anchored_chain(...)` → `fin = build_finalize_tx(spv, offer.claimed_redeem_hex, txid, vout, val, to_address, fee_sats=~1.5 RXD, minimum_output_photons=offer.photons_offered, header_slots=12, branch_slots=20)` → `res = node.accepts(fin.tx_hex)` → read `res["allowed"]` + `res.get("reject-reason")`.

### 2.4 Critical pinning constraints

- **`takerRadiantPkh` ↔ `to_address`:** the pkh passed to `build_gravity_offer` MUST equal `hash160(pubkey(to_address))` or the covenant's output-0 SPK `OP_EQUALVERIFY` fails (false reject). Derive both from one `PrivateKey`.
- **Fee/value sizing:** the claimed-spend tx is ~12 KB (≈11948 bytes, per the redeem ~10128 bytes); at regtest relayfee fund the claimed UTXO with `carrier = photons_offered + ≥2 RXD` so both the output-0 floor and the fee hold. `build_finalize_tx` draws the fee from the claimed UTXO itself (no separate fee leg needed).
- **Consistency assert before any node call:** `compute_p2sh_code_hash(claimed) == bytes.fromhex(offer.expected_code_hash_hex)` (`covenant.py:539`) — catches a bad-param derivation offline.

---

## 3. Cases — ordered by reachable value (8-byte BIN2NUM first)

`A` = Python ACCEPTS / covenant REJECTS (taker strands BTC on the no-refund path — the dangerous direction). `B` = covenant ACCEPTS / Python REJECTS (forged proof slips past review / wasted fee). Construction details abbreviated; full per-case shapes are in the spec JSON.

### Group V — value-read `OP_8 OP_SPLIT OP_DROP OP_BIN2NUM` (ASM tokens 9050-9054 P2PKH, replicated 9105/9149/9203). Un-skips `test_value_5_to_8_byte_bin2num_needs_regtest` (line 716).

| # | Construct | Python model | Covenant expected | `testmempoolaccept` assertion | Severity if diverges |
|---|---|---|---|---|---|
| **V-1** 5-sig-byte value | output-0 value = `4_294_967_296` (`0000000001000000`, just above 2³²), committed P2WPKH SPK to `btc_receive_hash`, `btc_satoshis=100_000` | ACCEPT (`payment.py:81` reads unsigned, bit-63 clear, ≥ threshold) | ACCEPT **if** Radiant uses 64-bit script ints | `allowed:true` expected. If `reject-reason` carries a `CScriptNum`/script-number-overflow → `allowed:false` = **Direction-A** | **HIGH** |
| **V-2** 7-sig-byte = MAX_MONEY | value = `2_100_000_000_000_000` (`0080c6a47e8d0300`, 21M BTC). Sub-variant (a) `btc_satoshis=100_000`; (b) `btc_satoshis=2_000_000_000_000_000` so **both** `OP_GREATERTHANOREQUAL` operands are 7-byte | ACCEPT both (Python compares Python ints; the threshold operand is **invisible** to Python) | ACCEPT both if ≤8-byte numeric | both `allowed:true` expected. Watch (b): if (a) passes but (b) reject-reasons with a numeric error → divergence is in the **comparison opcode** on a large committed threshold (high-value offer un-finalizable from birth) | **HIGH** |
| **V-3** committed-threshold operand size (second-order) | TWO covenants identical except `btc_satoshis`: (a) `100_000` (3-byte push), (b) `2_000_000_000_000_000` (7-byte push via `_encode_int_push`, `covenant.py:87-104`). SAME 7-byte-value payment into both | ACCEPT both (`build_gravity_offer` only checks `btc_satoshis>0`, `covenant.py:445-447`, no element-size cap) | ACCEPT both | (a) `allowed:true`, (b) `allowed:true` expected. If (b) `allowed:false` while (a) `allowed:true` → `build_gravity_offer` needs an upper-bound guard on `btc_satoshis`; **from-birth un-finalizable offer = maker self-grief stranding** | **HIGH** |
| **V-4** 8-sig-byte, bit-63 CLEAR | value = `0x7f00000000000000` (`000000000000007f`, max positive int64). Plus the `1<<63` (`0000000000000080`) **known-reject control** | ACCEPT `0x7f<<56`; REJECT `1<<63` (`payment.py:89` bit-63 guard) — clean split at the bit-63 boundary | ACCEPT `0x7f<<56` if 8 magnitude bytes permitted; REJECT `1<<63` | `0x7f<<56` `allowed:true`, `1<<63` `allowed:false` expected. If `0x7f<<56` rejects → 8-byte element over the covenant's number limit (refutes 64-bit assumption) | **MEDIUM** (8-byte value >> MAX_MONEY → unreachable on real chain; parity-hygiene only) |

> **Why V-1/V-2/V-3 are HIGH and V-4 is MEDIUM:** 5/6/7 significant bytes are **reachable** on the real anchored chain — 42.9 BTC (V-1) and 21M-BTC MAX_MONEY (V-2/V-3) are genuine high-value swaps/offers. An 8-byte value (V-4) exceeds MAX_MONEY ~4000× and cannot occur. **Divergence hypothesis for the whole group: suspected NO divergence** — the live mainnet dMint contract decodes an 8-byte target via `OP_8 OP_SPLIT` + `OP_GEQ` in production (`docs/dmint-research-mainnet.md:118-141`), proving Radiant raised the script-integer limit to 8 bytes/64-bit. If that assumption is **wrong** (legacy `nMaxNumSize=4` retained), V-1/V-2/V-3 are all Direction-A taker fund-loss.

### Group NB — per-header nBits exponent ceiling (ASM tokens 141-149: `OP_3 OP_GREATERTHANOREQUAL OP_VERIFY OP_DUP 20 OP_LESSTHANOREQUAL OP_VERIFY`; target rebuild via `OP_NUM2BIN` tokens 149-162). Un-skips `test_header_nbits_exponent_ceiling_divergence_needs_regtest` (line 576). **All NB covenants instantiated via `_substitute_nbits_covenant`, NOT `build_gravity_offer`** (its `_Nbits` guard, `covenant.py:486`, blocks exp>0x1d).

| # | Construct | Python model | Covenant expected | Assertion | Severity |
|---|---|---|---|---|---|
| **NB-1** exp 0x1e | 12-header chain, tip nBits LE `ffff7f1e` (mantissa `0x7fffff`, sign clear), grind trivially-easy PoW, real payment at pos≥1, 20-slot padded branch | REJECT at two layers: `build_gravity_offer` refuses (`covenant.py:486`); `verify_chain`→`Nbits` raises at `types.py:204`. Model `model_header_accepts` returns False for exp>29 (line 296-297) | ACCEPT (exp ≤ 0x20; right-pad zeros(0x20-0x1e)=2B, target fits 32B) | `allowed:true` = **confirmed Direction-B**. Confirm `verify_chain([...tip...], expected_nbits=ffff7f1e)` raises in Python — the gap IS the divergence | **HIGH** (low-difficulty-forgery surface; assert reachable only via artifact-substitution bypass, never `build_gravity_offer`) |
| **NB-2** exp 0x1f, 0x20, 0x21 boundary | three covenants, tips `ffff7f1f` / `ffff7f20` / `ffff7f21`. At 0x20: left-pad 29B + 3B mantissa = exactly 32B (the `OP_NUM2BIN`-to-0-length right-pad edge). 0x21 = over-ceiling negative control | REJECT all (Python `Nbits` rejects 0x1f/0x20/0x21 alike) | ACCEPT 0x1f + 0x20; REJECT 0x21 (`20 OP_LESSTHANOREQUAL OP_VERIFY` fires, tokens 146-148) | 0x1f `allowed:true`, 0x20 `allowed:true`, 0x21 `allowed:false` with script-eval reject. Pins **inclusive accept-band [0x1e..0x20] / first mutual reject at 0x21** — observed, not guessed | **HIGH** (covenant nBits-pin is the only difficulty defense; corroborates F-02 — `reject_low_difficulty` mandatory for covenant-less uses) |

### Group M — merkle 20-level walk + sentinel handling (per-level ASM 5633-5679: dir 0x00→`H(cur‖sib)`, dir 0x01→`H(sib‖cur)`, neither→NO-OP via double `OP_ENDIF`). Resolves the docstring "exact tolerated branch length" gap and the `xfail` at 651-665.

| # | Construct | Python model | Covenant expected | Assertion | Severity |
|---|---|---|---|---|---|
| **M-1** short branch padded to 20 | real_depth=1 (pos=1, one sibling), pad to 20 with nineteen `0x02`+32-zero sentinels (exactly what `build_finalize_tx:660-661` emits) | ACCEPT — production verifies on the UNPADDED depth-1 branch (`verify_tx_in_block`); model NO-OPs each 0x02 (line 318) | ACCEPT — 20-level walk NO-OPs the 19 sentinels, root matches header | `allowed:true` expected. **Negative control:** replace one sentinel dir byte 0x02→0x00 → `allowed:false` (root mismatch), proving it is specifically 0x02 that NO-OPs | **HIGH** |
| **M-2** full 20 real levels (no padding) | tx at a pos requiring 20 siblings, all 20 dir bytes ∈ {0,1}, real_depth==20 | ACCEPT (`compute_root` over 20 real levels = header root) | ACCEPT — confirms 20 is a genuine usable depth, not just a padding ceiling | `allowed:true` expected | **MEDIUM** |
| **M-3** misplaced sentinel (negative) | move a 0x02 sentinel into a REAL interior level, shift the genuine sibling to a trailing slot | REJECT (model NO-OPs the misplaced 0x02 → wrong root) | REJECT — wrong root vs header (root-compare ASM ~8866-8873) | `allowed:false` (root mismatch). Proves sentinels only safely NO-OP as **trailing** padding; cannot be abused to forge inclusion | **MEDIUM** |
| **M-4** over-depth (construction-time) | 21-real-level proof | REJECT at construction | n/a (never reaches node) | `build_finalize_tx` raises `ValidationError("Branch depth 21 exceeds covenant branch_slots=20")` (`transactions.py:658-659`) — no broadcast | **MEDIUM** |

### Group S — funding-tx structure + finalize arity + deadline (new live cases for docstring bullets 145-148).

| # | Construct | Python model | Covenant expected | Assertion | Severity |
|---|---|---|---|---|---|
| **S-1** empty-scriptSig happy path (**baseline**) | single-input funding tx, `rawTx[0x29]==0x00` (empty scriptSig → output_offset=46), output-0 committed P2WPKH `00 14 <maker20>` value 100_000 | ACCEPT (model line 328 `expect=True`; `_python_struct_and_payment_accepts` accepts) | ACCEPT | `allowed:true` **MUST hold** — if it fails, the covenant is non-functional for the native-segwit payment it is built around (every taker strands BTC). Pair with the ssl==0x17 segwit-shaped case (offset 69) as positive control | **CRITICAL** (Direction-A baseline; confirm FIRST — every other Direction-A reject is only trustworthy once this passes) |
| **S-2** multi-output finalize arity | hand-built spending tx `nOut=0x02`: output0 = correct taker P2PKH ≥ floor, output1 = arbitrary P2PKH/OP_RETURN. (`build_finalize_tx` hardcodes `_varint(1)`, `transactions.py:684` — needs hand-modification) | Not modelled (builder can't construct it; model parses only the inner BTC tx) | ACCEPT (index-0-only introspection, ASM 9234-9243; grep confirms ZERO `OP_*COUNT`/`NUMOUTPUTS`) | `allowed:true` expected = index-0-only / no arity guard. **Negative control:** `nOut=2` with output0 WRONG/underfunded → `allowed:false` (proves output-0 still binds, can't route payment to output1) | **MEDIUM** (Direction-B capability; dangerous only if value-conservation lets output1 drain — the control rules that out) |
| **S-3** compile-time `claimDeadline` clamp | ASM tokens 0-3 `$claimDeadline 949ec369 OP_GREATERTHANOREQUAL OP_VERIFY` where `0x69c39e94` LE = `1774427796`. LOW offer: `claim_deadline=1774427795` (`accept_short_deadline=True` to bypass the Python 24h floor); HIGH: `1774427796` exact + `+86400`. Build finalize (OP_0) AND forfeit (OP_1, `nLockTime`, also hits `$claimDeadline OP_CHECKLOCKTIMEVERIFY` token 9272) | Python has NO 1774427796 awareness (`validate_claim_deadline` only enforces now+24h, `covenant.py:276-301`) — predicts ACCEPT where covenant must REJECT LOW | LOW: REJECT at token 3 (both finalize+forfeit, before any branch). HIGH: finalize ACCEPT; forfeit ACCEPT once `nLockTime` mature | LOW `allowed:false` (OP_VERIFY reject); HIGH `1774427796` exact `allowed:true` (`≥` is inclusive); `1774427795` `allowed:false`. For forfeit, set offer deadline vs node `getblockchaininfo.mediantime`: below MTP → `allowed:true`; above → `allowed:false` ("non-final"/"Locktime requirement not satisfied") | **HIGH** (Direction-A: a now+24h-but-pre-1774427796 deadline — only on a back-dated/regtest clock — funds a covenant **no one can ever spend**, permanent stranding. Also confirm the floor is a fixed baked constant that does NOT auto-advance) |

### Cross-cutting positive control (run before trusting any reject)

Build the canonical happy-path finalize (S-1 shape + a clean exp≤0x1d 12-header chain + depth-1 padded branch) and assert `allowed:true`. This is the **core differential agreement** — the deployed covenant accepts exactly what the Python path accepts. Every Direction-A `allowed:false` result is only meaningful once this baseline is green.

---

## 4. Landing the results

**New file:** `tests/test_spv_covenant_differential_regtest.py`, gated identically to `test_htlc_regtest_e2e.py` (`pytestmark = pytest.mark.integration`; `RADIANT_REGTEST=1` opt-in; docker-image-inspect skip). Run: `RADIANT_REGTEST=1 pytest tests/test_spv_covenant_differential_regtest.py -m integration -s`.

**If a case CONFIRMS the predicted behaviour (agreement or the predicted Direction-B):**
- Replace the corresponding `@pytest.mark.skip` in `tests/test_spv_covenant_differential_deployed.py` with a real `@pytest.mark.integration` test in the new regtest file that asserts the observed verdict (e.g. NB-1/NB-2 assert covenant `allowed:true` + Python raises = pinned Direction-B accept-band `[0x1e..0x20]`; V-1/V-2/V-3 assert `allowed:true` = 64-bit-numeric agreement; S-1 asserts the CRITICAL baseline; M-1/M-2/M-3 assert the sentinel-NO-OP + reject-on-misplacement).
- In `test_spv_covenant_differential_deployed.py`, change the skip docstrings to point at the new regtest test as the live evidence and downgrade the "NOT modelled" bullets (lines 143-148) to "modelled-as-skip, confirmed live in `test_spv_covenant_differential_regtest.py::<case>`".
- Persist a `{case: {allowed, reject_reason}}` JSON artifact under `docs/brainstorms/gravity-ref-spike/` (e.g. `REGTEST_COVENANT_SEMANTICS_RESULTS.json`) as evidence — measured verdicts, not guesses.

**If a case REVEALS a divergence:**
- File it as a finding with: **Direction (A/B)**, **fund impact** (A = taker strands BTC on no-refund finalize / maker self-grief un-finalizable offer; B = forged-proof-past-review or wasted fee), the exact `reject-reason` string, the covenant gate that fired (mapped from ASM token), and the reproducing case in the regtest file.
- Direction-A findings (V-group numeric reject, S-1 baseline reject, S-3 stranding window) are **fund-loss** — pair each with a code fix: for V-3 an `_encode_int_push` element-size cap (≤ MAX_MONEY = 7 bytes) in `build_gravity_offer`; for S-3 confirm/port the 1774427796 absolute floor into `validate_claim_deadline` so the Python builder refuses an offer the covenant would brick. Land the fix + the now-passing regression test together.

---

## 5. Risks / gaps / effort

**Blockers:**
- **Missing deploy helper** (§2.2 #1): no existing helper funds a Gravity claimed-P2SH on a live node — must write `_deploy_claimed_utxo` (~6 lines wrapping `_pay_to_spk`). Low risk; `_pay_to_spk` already pays arbitrary SPKs.
- **Missing 12-header chain grinder** (§2.2 #2): the existing `_grind_tx_into_block` grinds only ONE header; the covenant ABI has 12 header slots. Must write `_grind_anchored_chain`. Medium risk — if a 12-header chain Python's `verify_chain` accepts is rejected by the covenant's per-header loop (or vice-versa), the entire finalize path is untestable; resolve by pinning the HAPPY chain to exp≤0x1d so both sides accept, isolating the nBits-ceiling divergence to NB-1/NB-2 only.
- **`_Nbits` bypass** (§2.2 #3): NB cases require `CovenantArtifact._substitute` directly (the high-level builder gates exp>0x1d). If the artifact `_substitute` API differs from assumed, NB-1/NB-2 need a small adapter.
- **`build_gravity_offer` required args:** the harness must supply `anchor_height` + `merkle_depth` (spec JSON omitted both; they are positional, `covenant.py:338-339`).
- **S-2 hand-modification:** `build_finalize_tx` hardcodes one output; the multi-output case needs a hand-built tx (no covenant signature, so txid recompute is the only adjustment).
- **Image availability:** `radiant-core:v2.3.0-amd64` must be present (`docker image inspect` gate skips cleanly if not).

**Rough effort (ESTIMATED, not measured):** harness scaffolding + 2 new helpers ≈ half a day; the ~13 parametrized case assertions ≈ half a day; total ~1 day to first green run, assuming the regtest image is present and the 12-header grind is fast (it is — relaxed target). Each case is fast (`testmempoolaccept` is sub-second; PoW grind is trivial on regtest).

**Stays deferred (NOT in this plan):** any mainnet run / real value; the SPV multi-source indexer; SeenStore durability; external audit (the hard gate before real value). This plan resolves *consensus-script semantics only* — it does not clear the swap for production.

---

## 6. Go/No-Go checklist (ordered; node-touching steps flagged)

All steps run against an **isolated regtest container only**; none broadcasts real value (`testmempoolaccept` validates without mempool insertion). Approve before execution.

| # | Step | Node-touching? |
|---|---|---|
| 0 | Write `tests/test_spv_covenant_differential_regtest.py` (copy `_RegtestNode` + `node` fixture + `_pay_to_spk`); write `_deploy_claimed_utxo`, `_grind_anchored_chain`, `_substitute_nbits_covenant` | No (code only) |
| 1 | `docker image inspect radiant-core:v2.3.0-amd64` — confirm present, else skip | **No** (inspect only) |
| 2 | `RADIANT_REGTEST=1 pytest ... -m integration -s` → fixture runs `_RegtestNode.start()`: `docker rm -f`; `docker run -d ... -regtest`; poll `getblockchaininfo` until `chain=='regtest'`; **assert `chain=='regtest'`** (NEVER mainnet); `createwallet gravity`; `getnewaddress`; `mine(101)` | **YES** — spins up + mines the isolated container |
| 3 | Sanity: `node.accepts("00")` returns `allowed:false` (proves the free `testmempoolaccept` path works, no broadcast) | **YES** (testmempoolaccept, free) |
| 4 | **Cross-cutting positive control** + **S-1 (CRITICAL baseline)**: deploy claimed UTXO (`_pay_to_spk` → 1 broadcast of a *throwaway regtest* funding tx + mine), grind happy chain, `node.accepts(finalize)` → assert `allowed:true` | **YES** (regtest-only funding broadcast + testmempoolaccept) |
| 5 | Group V (V-1→V-4), then NB (NB-1→NB-2), then M (M-1→M-4), then S-2/S-3 — each: deploy claimed UTXO, build finalize/forfeit, `node.accepts(...)`, record `{allowed, reject-reason}` | **YES** (all regtest; funding broadcasts + testmempoolaccept only) |
| 6 | Persist results JSON; map each verdict to agreement / Direction-A / Direction-B; un-skip confirmed cases or file divergence findings | No |
| 7 | `node.stop()` (`docker rm -f`) in the fixture `finally` — tear down the container | **YES** (teardown) |

**Hard guarantees:** mainnet radiant-node on `tr` is never contacted; the only broadcasts are to the throwaway regtest container (zero real value); every covenant verdict comes from `testmempoolaccept` (no mempool insertion); the container is removed on exit.

**Relevant file paths:** `tests/test_spv_covenant_differential_deployed.py` (skips to un-skip: lines 576-583, 716-724; xfail 651-665; "NOT modelled" 143-148), `tests/test_htlc_regtest_e2e.py` (`_RegtestNode` 66-147, fixture 150-164, `_pay_to_spk` 194-248), `src/pyrxd/gravity/transactions.py` (`build_finalize_tx` 555-695; sentinel pad 660-661; floor 613; over-depth 658-659), `src/pyrxd/gravity/covenant.py` (`build_gravity_offer` 328; `_encode_int_push` 87; `_Nbits` guard ~486; `validate_claim_deadline` 276), `src/pyrxd/gravity/codehash.py` (P2SH helpers 30-58), `src/pyrxd/spv/proof.py` (`SpvProofBuilder.build` 315), `src/pyrxd/security/types.py` (Nbits exp cap 203-204), `src/pyrxd/gravity/artifacts/maker_covenant_flat_12x20_sentinel_all.artifact.json` (covenant ABI/ASM ground truth). **New file to create:** `tests/test_spv_covenant_differential_regtest.py`.