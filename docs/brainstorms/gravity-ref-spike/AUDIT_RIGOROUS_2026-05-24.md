# Gravity swap — rigorous re-audit (2026-05-24)

Follow-up to the 8-reviewer panel re-audit. This pass applied four
higher-rigor techniques, each chosen to produce *evidence* rather than
opinion. Every finding below is tagged with its provenance and one of:

- **PROVEN-ON-CONSENSUS** — demonstrated against a live Radiant Core 2.3.0
  node (local regtest, isolated, never mainnet).
- **PROVEN-IN-SIM** — demonstrated against the faithful covenant ASM
  simulator (`rxd_sim.py`) and/or executable Python.
- **REFUTED** — a prior/panel finding shown NOT to be exploitable, with the
  reason.
- **CONFIRMED-BY-SOURCE** — verified by reading consensus/source, not executed.

> **Provenance rule applied throughout:** no number or "it's safe/broken"
> claim appears here unless it was queried, run, or read from a cited file.
> "Not measured" is stated where that is the honest answer.

## Techniques run

| # | Technique | Target | Result |
|---|---|---|---|
| 1 | Property-based fuzzing (Hypothesis, 12k examples/test at 15×) | `strip_witness`, `_output_offsets`, `verify_payment` | NO leaks; DoS bounds hold |
| 2 | Differential testing | Python SPV parser **vs** covenant ASM (`rxd_sim`) | 1 real divergence; 2 apparent ones refuted |
| 3 | Invariant formalization + reachability proof | HTLC swap FSM | 5 safety invariants proven |
| 4 | Live-consensus execution | Radiant regtest `testmempoolaccept` + broadcast | REF-authenticity gap proven on-chain |

Tooling verified present: Hypothesis 6.152, Atheris, `radiant-core:v2.3.0`
docker image (local regtest), `testmempoolaccept` on the node.

---

## PROVEN findings

### R1 — REF authenticity is not enforced by consensus (PROVEN-ON-CONSENSUS)
**Severity: HIGH (counterparty trust). The "one-of-one NFT" guarantee is
structural, not semantic.**

Radiant consensus (`Radiant-Core/src/validation.h:1046-1049`) auto-inserts
**every input's prevout outpoint** into `inputSingletonRefSet`. `validatePushRefRule`
(`:1063`) only requires output singleton-refs ⊆ input-refs. So a `d8<REF>`
output whose `REF` equals the outpoint of *any* UTXO the maker spends at
funding satisfies the singleton rule — the singleton need NOT be a genuinely
minted Glyph NFT.

**Proof (regtest, Radiant Core 2.3.0):** built a tx spending a plain wallet
UTXO, creating an output `OP_PUSHINPUTREFSINGLETON <that UTXO's outpoint>
OP_DROP <P2PKH>`. No `gly` envelope, no genesis reveal, no mint.
- `testmempoolaccept` → `allowed: true`
- `sendrawtransaction` → mined, txid `79711a9d16ff583b9953a7f05ef2daffcb91e8f9553d57a4b9723a8ed871a4f5`, 1 confirmation
- resulting UTXO scriptPubKey starts with `d8` (a valid singleton) on a **fake** ref.

**Impact:** a malicious maker advertises a real one-of-one, funds the covenant
with a worthless self-crafted singleton; finalize settles correctly to the
taker, who pays BTC and receives a `d8<ref>` output no Glyph indexer recognizes
as the advertised asset. The covenant cannot self-verify mint provenance.

**Defense (must be enforced, currently off-chain only):** the taker MUST verify,
BEFORE paying BTC, that `REF` resolves on a trusted indexer to the genuine
reveal (genesis txid:vout, payload hash, `gly` marker). `swap_coordinator.pre_btc_lock_check`
step 1 does call `indexer.verify_ref` and fails closed — but a taker who calls
the builders directly, or trusts a lying indexer, has no protection. Make the
indexer gate un-skippable; document that consensus provides NO backstop.

### R2 — Any-wallet covenant rejects payments from inputs with scriptSig ≥ 128 B (PROVEN-IN-SIM)
**Severity: MEDIUM (availability / taker-fund-loss footgun — NOT theft).**

The audit's `require(ssl >= 0 && ssl <= 252)` input-skip guard reads each
scriptSig length as a **single byte** then `OP_BIN2NUM` (signed CScriptNum). A
length byte ≥ 0x80 (128) decodes **negative**, so the `ssl >= 0` guard
ScriptFails on ANY funding tx with an input whose scriptSig is 128–252 bytes.

**Proof (differential, `rxd_sim` vs Python SDK):** the Python SDK accepts a
well-formed payment regardless of scriptSig size; the covenant sim rejects at
exactly **128 B** (boundary measured: accepts ≤127, rejects ≥128 — the
CScriptNum sign bit). Pinned in `tests/test_spv_covenant_differential.py`.

**Impact:** common BTC input types have ≥128 B scriptSigs — P2SH 2-of-3
multisig (~250 B), P2SH-wrapped redeem scripts, inscription reveals. A taker
paying from such a wallet builds an SPV proof the SDK accepts but the covenant
rejects on-chain. On the no-refund SPV-oracle path the BTC payment confirms and
the asset never releases → **the taker can lose the BTC.** Native-segwit (empty
scriptSig) and legacy P2PKH (~107 B) inputs are unaffected.

**Fix:** parse the scriptSig length as a real varint in the covenant (compare
the value, not the raw byte), OR have the SDK refuse to build a proof from a
funding tx with any ≥128 B-scriptSig input so the failure is caught off-chain
before the BTC is spent, AND document "pay from a native-segwit or P2PKH input."

---

## REFUTED (prior/panel findings shown non-exploitable)

### keys.py P2TR even-parity "bug" — REFUTED (prior turn)
BIP341 `lift_x` is defined as even-Y, so `b"\x02"+x` is the lift, not a guess;
proven spendable across both parities by reconstructing the tweaked secret.
Comment fixed; `test_taproot_tweak_is_spendable_both_parities`.

### Substring-preimage check (`taproot.py:854`) — REFUTED (PROVEN-IN-SIM)
`sha256(p) in claim_script` is a substring search. A false positive requires
`sha256(p)` to equal the 32-byte `pk` window or a push-boundary window — a
SHA256 preimage break. Verified: `H` appears exactly once in the leaf (offset
2). AND `build_claim_tx` is the **maker signing their own claim** — not a trust
boundary an adversary crosses. Not exploitable. (A precision improvement —
compare at the known offset — is reasonable hygiene, not a fix.)

### `scrape_secret` cross-swap selection — REFUTED
Shared `H` ⇒ shared `p` (collision resistance), so returning *the* preimage for
`H` is always the correct secret; there is no "wrong secret." The only real
risk is `H`-reuse, which is gated by `seen_store` freshness in
`pre_btc_lock_check` (16 coordinator tests cover it). Not a `scrape_secret` bug.

### Parser theft via signed-scriptLen rewind / unvalidated output_offset — REFUTED (PROVEN-IN-SIM + fuzz)
The prior-audit CRITICALs. 12k-example Hypothesis fuzzing of `strip_witness`,
`_output_offsets`, `verify_payment` found NO contract leaks; the differential
corpus confirms a forged maker-output blob planted in a scriptSig is rejected
by BOTH the SDK and the covenant. The audit guards hold.

---

## Formalized invariants (PROVEN by reachability over the real FSM)

`tests/test_swap_invariants.py` enumerates every simple path over the real
`_TRANSITION_TABLE` and proves:

- **I1 Atomicity of the taker win** — every path to `COMPLETED` passes through
  `SECRET_REVEALED`. No path lets the taker get the asset without the maker
  being able to claim the BTC. ⇒ no one-sided taker win.
- **I2 Bounded taker loss** — `ONE_SIDED_LOSS_TAKER` is reachable ONLY via
  `SECRET_REVEALED → ASSET_VULNERABLE` (taker offline AFTER reveal past t_rxd).
  Unreachable before the secret is out. **This is the precise, proven bound on
  the deadline-race risk the panel flagged: it cannot strand a diligent taker.**
- **I3 No pre-reveal deadlock** — every locked pre-reveal state can reach a
  refund terminal.
- **I4 Success/loss mutual exclusion** — `COMPLETED` and `ONE_SIDED_LOSS_TAKER`
  are distinct terminal sinks.
- **I5 Ordering** — `t_btc > t_rxd` (same unit) enforced at `NegotiatedTerms`
  construction (property-tested over the full int range).

---

## Confirmed-by-source (not executed; no PoC warranted)

- **Cross-layer N mismatch** (proof depth vs covenant header-slots) — enforced
  only in a `trade.py` docstring. Real robustness gap → fee-burn / weakened
  reorg-cost assumption on mismatch, but NOT an exploit (no value theft). Make
  `N` a `CovenantParams` field and assert equality. (Architecture finding.)
- **Cross-offer replay (H1)** — already EXPLOITED (`/tmp/exploit_h1_replay.py`,
  prior turn) and STRUCTURALLY FIXED (`build_gravity_offer_derived` +
  `gravity/receive.py`). Not re-opened here.

---

## What changed in the tree

New tests (all green, lint+format clean):
- `tests/test_fuzz_spv_parsers.py` — 10 fuzz/property tests on the SPV byte-walkers.
- `tests/test_swap_invariants.py` — 6 formal FSM safety-invariant proofs.
- `tests/test_spv_covenant_differential.py` — 16 differential cases incl. the
  pinned scriptSig≥128 B divergence + the exact-128 boundary.

## Expanded-testing follow-up (2026-05-25)

Cheap, repeatable hardening on top of the audit:

- **Differential fuzzing — 2,000,000 random adversarial txs, ZERO novel
  divergences.** Python SPV parser vs covenant ASM (`rxd_sim`) agree on
  payment-validity on every input except the known scriptSig≥128 B class
  (445k hits — the single divergence class, heavily exercised). No
  Python-REJECT/covenant-ACCEPT (the theft direction) found. Landed as a
  CI-budgeted regression (`test_differential_fuzz_no_novel_divergence`,
  scale with `DIFF_FUZZ_N`).
  - *Method note:* the known-class filter MUST use the production varint
    parser (`_max_input_scriptsig_len`). A naive single-byte read mis-classifies
    a ≥253 B scriptSig (multi-byte `0xfd` varint) and would hide a known-class
    case as "novel" — caught and fixed during this pass.
- **Atheris coverage-guided fuzz — 200,000 runs, 0 crashes** on the previously
  unfuzzed `_max_input_scriptsig_len` (R2 helper) and `verify_ref_authenticity`
  (R1 gate). Neither leaks a non-ValidationError past its trust boundary.
- **R1 re-confirmed on a fresh regtest node** via `testmempoolaccept`
  (`allowed: true`) — a fake-singleton whose REF is a plain wallet UTXO.
- **Mainnet free-check ruled out (method finding):** `testmempoolaccept` on the
  mainnet node short-circuits with `missing-inputs` BEFORE evaluating the
  singleton-ref / script rules, because the referenced input must already exist
  on-chain. So no covenant-spend or fake-singleton attack can be consensus-checked
  on mainnet without spending a real signed UTXO. Regtest (where we control real
  UTXOs and can deploy covenants freely) is the correct, zero-risk tool — and is
  strictly stronger than a mainnet `testmempoolaccept` for these classes.
- **R2 / forged-payment** remain proven-in-sim + by-source (CScriptNum) +
  now-backed by the 2M-case differential fuzz. A full any-wallet covenant deploy
  on regtest to spend-test them was judged disproportionate (the `rxd_sim` model
  mirrors the compiled ASM, and the fuzz exercises the same logic at scale).

## Honest limitations of THIS audit

- The REF-authenticity proof used a hand-built singleton tx, not the full fused
  Gravity covenant funded end-to-end — sufficient to prove the consensus rule,
  not a full swap settlement.
- Regtest ≠ mainnet policy. `testmempoolaccept` checks consensus + standard
  policy; mainnet relay policy (e.g. non-standard tx rejection) is a separate
  layer not exercised here.
- The covenant ASM was tested via `rxd_sim` (a faithful model), not by spending
  a live funded any-wallet covenant UTXO. R2's boundary is proven in-sim +
  by-source (CScriptNum), not by a live covenant spend.
- Fuzzing proves absence of *found* leaks within the budget, not absence of all
  leaks. No coverage-guided (Atheris) campaign was run — Hypothesis only.
