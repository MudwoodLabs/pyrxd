# Regtest Validation Results — Deployed Covenant Semantics (2026-05-30)

**What ran:** the 21-case V/NB/M/S matrix from `REGTEST_VALIDATION_PLAN_2026-05-30.md`,
executed against a real `radiant-core:v2.3.0` regtest node via `testmempoolaccept`
(`tests/test_spv_covenant_differential_regtest.py`, gated `@pytest.mark.integration` +
`RADIANT_REGTEST=1`). Every verdict below is **measured** on the live consensus script
interpreter — not modelled, not guessed. No mainnet node was touched; no covenant spend
was broadcast (`testmempoolaccept` validates the script without mempool insertion). PoW
headers were genuinely ground to a relaxed regtest target (machine evidence:
`REGTEST_COVENANT_SEMANTICS_RESULTS.json`).

## Outcome: every predicted verdict held — no covenant divergence, no fix required

| Group | Question (was skipped in the differential test) | Measured result |
|---|---|---|
| **V** (value `OP_8 OP_SPLIT OP_DROP OP_BIN2NUM`) | Does the covenant read 5–8 significant value bytes as a full number? | **64-bit numeric.** 5/7/8-byte values ACCEPT (≥ threshold, incl. 7-byte value vs 7-byte threshold, inclusive); bit-63-set decodes **negative** → REJECT (V-4ctrl); 7-byte value just below a 7-byte threshold → REJECT (V-5). **No Direction-A fund-loss.** |
| **NB** (per-header nBits exponent ceiling) | Does the covenant tolerate exp the Python `Nbits` rejects? | **Accept-band `[0x1e..0x20]` confirmed (Direction-B).** exp 0x1e/0x1f/0x20 ACCEPT; 0x21 REJECT. Corroborates F-02: `reject_low_difficulty` is mandatory for any covenant-less SPV use (bridge-in / oracle / gate). |
| **M** (20-level merkle + sentinel) | Sentinel (`0x02`) NO-OP semantics; tolerated branch length. | Trailing `0x02` sentinels NO-OP (M-1 pad → ACCEPT); 20 genuine levels verify (M-2); a `0x02` on a real level or a `0x00` on a pad slot breaks the root → REJECT (M-3, M-1neg); over-depth is a **builder-side** guard (M-4, the covenant reads 20 fixed slots). |
| **S** (structure / deadline) | Multi-output arity; `claimDeadline` floor. | Output-0-only introspection — a 2-output finalize ACCEPTS, underfunded output-0 REJECTS (S-2). The baked floor `1774427796` is enforced on-chain: below-floor REJECT, at-floor ACCEPT (inclusive), forfeit ACCEPT after maturity (S-3). |

Direction labels: **A** = Python accepts / covenant rejects (taker strands BTC — the
dangerous direction); **B** = covenant accepts / Python rejects (forged proof past review).

### Notable conclusions

- **The worst-case Group-V hypothesis is refuted.** The covenant is genuinely 64-bit; a
  high-value (5–7 significant byte) offer is *not* un-finalizable-from-birth. No fix.
- **S-3 `claimDeadline` floor is a latent-only concern.** The floor `1774427796` is
  already in the past, and Python's `validate_claim_deadline` `now+24h` guard is strictly
  tighter, so it subsumes the on-chain floor for any honest deadline. The Direction-A
  stranding window (a deadline ≥ now+24h but < floor) is only reachable by deliberately
  bypassing the Python guard (`accept_short_deadline=True`) on a back-dated clock — closed
  in practice. No active fund-loss; noted for the record.
- Every REJECT case is isolated by a **twin control** that flips exactly the targeted
  property (V-4/V-4ctrl: one value byte; M-1/M-1neg and M-2/M-3: one direction byte across
  the 11,950-byte tx; S-3 at/below floor: one deadline param), so the generic consensus
  `mandatory-script-verify-flag-failed (OP_VERIFY)` message is backed by a differential
  that pins the specific gate.

## Adversarial verification

After the matrix went green, 5 independent reviewers each tried to prove a green result was
a **false pass** (a test that passes while validating the wrong thing), reading the covenant
ASM artifact as ground truth, byte-diffing the twins, re-decoding the S-2 split tx through
the node, and mutation-testing the harness (`output_offset=999` → byte-identical finalize,
confirming `build_finalize_tx` packs-only). Verdict: **all-confirmed, zero medium/high
false-pass risks.** The LOW items they surfaced were evidence/rigor tightening — all closed
here (added V-5 threshold-width reject-twin; recorded the S-2 underfunded control;
clarified M-4 is a builder-side guard).

## Differential test follow-up

The two skip-marked questions in `tests/test_spv_covenant_differential_deployed.py`
(`test_value_5_to_8_byte_bin2num_needs_regtest`, `test_header_nbits_exponent_ceiling_divergence_needs_regtest`)
and the four "NOT modelled" docstring bullets now cite this live evidence as resolved.

**Reproduce:** `python tests/_regtest_grind_chains.py` (pre-grind the PoW chains once,
parallel) then `RADIANT_REGTEST=1 pytest tests/test_spv_covenant_differential_regtest.py -m integration`.
