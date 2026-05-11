---
title: V1 dMint mint tx shape mismatch — synthetic round-trip tests bypassed real-bytes mismatch
problem_type: logic_error
component: pyrxd.glyph.dmint (V1 mint builder)
symptoms:
  - All 49 V1 unit tests passed (round-trip through DmintState.from_script)
  - Plan acceptance criteria all checked off
  - Code review approved
  - Every tx pyrxd would have built was structurally invalid for the on-chain V1 covenant
  - The bug only became visible when a security/red-team review forced a comparison against real mainnet bytes
severity: high
date_solved: 2026-05-08
prs: [feat/dmint-v1-mint commits a3ee46e, 1a8d712]
tags: [dmint, v1, mint, builder, golden-vectors, covenant, mainnet, recurring-pattern]
related_files:
  - src/pyrxd/glyph/dmint.py
  - tests/test_dmint_v1_mint.py
  - docs/dmint-research-mainnet.md
related_solutions:
  - docs/solutions/logic-errors/dmint-v1-classifier-gap.md
---

## Symptom

The first V1 dMint mint implementation produced transactions that the
Radiant mainnet covenant would have rejected, but every synthetic
test passed. Specifically:

| Aspect | pyrxd built (broken) | Mainnet expects (per `docs/dmint-research-mainnet.md` §4) |
|---|---|---|
| Inputs | 1 (contract only) | 2 (contract + plain-RXD funding) |
| Outputs | 2 (contract recreate + plain P2PKH reward) | 3–4 (contract recreate + 75-byte FT-wrapped reward + optional OP_RETURN msg + change) |
| Contract output value | decremented by `reward + fee` per mint | preserved (singleton — RBG's is 1 photon) |
| Reward output script | plain 25-byte P2PKH | 75-byte P2PKH + OP_STATESEPARATOR + OP_PUSHINPUTREF tokenRef + 12-byte covenant fingerprint |

The whole synthetic test suite was green. Two hours of code review
approved the implementation. The plan's acceptance-criteria checklist
was complete. Every byte the implementation produced would have been
rejected by the network on first broadcast.

## Root Cause

Two distinct misunderstandings of the V1 covenant, neither of which the
synthetic tests could surface because **both the builder and the parser
live in `src/pyrxd/glyph/dmint.py`**. Round-trip tests of the form
`assert parser(builder(x)) == x` verify that pyrxd is internally
consistent with itself — they do not verify that pyrxd's output matches
what real Radiant nodes accept.

### Misunderstanding 1: contract output as value pool (V2 mental model)

V2 dMint contracts hold the running reward pool in the contract output
itself; each mint subtracts `reward` from the contract's value, and the
fee comes out of that same pool too. I carried this mental model into
the V1 builder.

V1 contracts are **singletons**. The RBG-class live mainnet contracts
all carry exactly 1 photon perpetually. The miner provides a
**separate plain-RXD funding input** that pays:
- The FT carrier value for the reward output (`state.reward` photons)
- The transaction fee
- The change back to the miner

Subtracting `reward + fee` from the contract output would produce a
covenant-rejected tx; in the (impossible) case it confirmed, every
mint would silently bleed the singleton's value to dust over a few
hundred mints.

### Misunderstanding 2: reward output as plain P2PKH

The V1 covenant's epilogue at offset 168 is:
```
OP_DUP OP_CODESCRIPTHASHVALUESUM_OUTPUTS OP_ROT OP_NUMEQUALVERIFY
```

This sums photons across all outputs whose codescript-hash matches a
specific value (computed from `OP_PUSHINPUTREF tokenRef + 12-byte
fingerprint`), and requires the total to equal `state.reward`. The
miner cannot satisfy this with a plain P2PKH reward output — there is
no FT codescript to sum.

The mainnet shape (decoded at `docs/dmint-research-mainnet.md`
§4 vout[1]):

```
76 a9 14 <miner_pkh:20> 88 ac        ← 25-byte P2PKH prologue
bd                                    ← OP_STATESEPARATOR
d0 <token_ref:36>                     ← OP_PUSHINPUTREF + 36-byte tokenRef
de c0 e9 aa 76 e3 78 e4 a2 69 e6 9d  ← 12-byte covenant fingerprint
                                      → 75 bytes total
```

## What Did NOT Catch It

- **49 unit tests** (all V1 builder/parser round-trips, mining loop, error paths)
- **~2 hours of code review** focused on type signatures and edge cases
- **Plan acceptance criteria** which verified shape, count, and byte length but never compared bytes against captured mainnet data
- **The prior incident at [`docs/solutions/logic-errors/dmint-v1-classifier-gap.md`](dmint-v1-classifier-gap.md)** which documented this same anti-pattern in reverse (parser missed real V1 because only V2 fixtures were tested) — should have been a yellow flag while writing the V1 builder

## What Did Catch It

A security-sentinel + red-team review pass after the M1 implementation
was committed. The red-team finding was unambiguous:

> *"every tx pyrxd builds for V1 minting is rejected by the network. If
> somehow accepted, the miner would receive plain RXD rather than FT
> tokens; the contract's tokenRef accounting breaks. Pool funds also get
> burned to fee. Until done, the V1 path should raise NotImplementedError,
> not return a DmintMintResult."*

The reviewer did what the unit tests didn't: walked the mainnet trace
in `docs/dmint-research-mainnet.md` §4 byte-by-byte against pyrxd's
output.

## The Fix

Commit `a3ee46e fix(glyph): correct V1 dMint mint-tx shape + harden
deploy guard + token-burn defense`:

1. **New `build_dmint_v1_ft_output_script(miner_pkh, token_ref)`** at
   [src/pyrxd/glyph/dmint.py:441-469](../../src/pyrxd/glyph/dmint.py#L441) producing
   the 75-byte FT shape:
   ```python
   if len(miner_pkh) != 20:
       raise ValidationError(f"miner_pkh must be 20 bytes, got {len(miner_pkh)}")
   p2pkh_prologue = b"\x76\xa9\x14" + miner_pkh + b"\x88\xac"
   return (
       p2pkh_prologue
       + _OP_STATESEPARATOR
       + b"\xd0"
       + token_ref.to_bytes()
       + _V1_FT_OUTPUT_EPILOGUE  # bytes.fromhex("dec0e9aa76e378e4a269e69d")
   )
   ```

2. **New `DmintMinerFundingUtxo` dataclass** at
   [src/pyrxd/glyph/dmint.py:1478](../../src/pyrxd/glyph/dmint.py#L1478) — the V1 mint
   path now requires a funding UTXO. Without it, raises
   `ValidationError("V1 mint requires a funding_utxo: V1 contracts are
   singletons (typically 1 photon) and the FT reward + tx fee come from
   a separate plain-RXD input.")`

3. **Rewritten `_build_dmint_v1_mint_tx`** at
   [src/pyrxd/glyph/dmint.py:1877](../../src/pyrxd/glyph/dmint.py#L1877) — produces
   the correct 3- or 4-output tx: contract recreate (value preserved) +
   75-byte FT-wrapped reward + optional OP_RETURN msg + change.

4. **The load-bearing test** —
   [`TestBuildDmintV1FtOutputScript::test_byte_equal_to_mainnet_vout1`](../../tests/test_dmint_v1_mint.py#L269)
   asserts byte-for-byte equality against the live mainnet
   `146a4d68…f3c` vout[1] decoded in §4 of the research doc:
   ```python
   _MAINNET_VOUT1_BYTES = bytes.fromhex(
       "76a914e9aa4adbe3a3f07887d67d9cedae324711f053ef88ac"  # 25-byte P2PKH prologue
       + "bd"                                                  # OP_STATESEPARATOR
       + "d08b87c3c771b1a9f5015a4f26bfd80979ed196b5366257a6f30929646dfd943a400000000"
       + "dec0e9aa76e378e4a269e69d"
   )

   def test_byte_equal_to_mainnet_vout1(self):
       script = build_dmint_v1_ft_output_script(self._MAINNET_PKH, self._MAINNET_TOKEN_REF)
       assert script == self._MAINNET_VOUT1_BYTES
   ```

5. **Singleton invariant** baked into
   [`test_consecutive_mints_chain_state`](../../tests/test_dmint_v1_mint.py#L600):
   `assert r1.tx.outputs[0].satoshis == utxo.value` — the
   covenant value-preservation rule the broken code violated is now a
   green-test gate.

## Prevention

### The rule

**Round-trip tests through your own parser do not validate against
on-chain truth.** When builder and parser live in the same module and
are tested only against each other (`assert parser(builder(x)) == x`),
both can harbor coordinated bugs invisible to the test suite.

### The required test pattern

For every protocol output that lands on-chain, ship at least one test
that asserts byte-equality against captured mainnet bytes. The test must:

- **Cite the source transaction** (txid, vout index, research doc reference)
- **Use real hex** captured directly from chain queries or research documents
- **Run first, not last** — the golden-vector test is the first check on
  a new builder, not a "polish" addition
- **Fail loudly** — a golden-vector test failure is an on-chain conformance
  regression, not a harness glitch

### Where this applies in pyrxd specifically

- ✅ **V1 dMint mint reward output** — covered by `test_byte_equal_to_mainnet_vout1`
- ⚠️ **V2 dMint deploy contract bytes** — no mainnet instance exists; gold
  vectors unavailable until a V2 contract appears on-chain
- ⚠️ **V2 mint tx outputs** — capture bytes immediately when the first V2
  mint lands
- ⚠️ **FT transfer output shapes** — should have golden vectors
- ⚠️ **Glyph NFT mint reveals** — should have golden vectors
- ⚠️ **Gravity covenant outputs** — should have golden vectors

Any new wire-format builder added to pyrxd going forward must include a
golden-vector test as part of its acceptance.

### Code-review checklist for builders

Flag and demand a golden-vector test if you see:

- A round-trip test of the form `assert parser(builder(x)) == x`
  without a parallel test against captured bytes
- Tests that round-trip pyrxd → pyrxd with no external ground truth
- Builder + parser landing in the same PR with no real-chain
  cross-check
- Test fixtures named only with synthetic prefixes (no `_MAINNET_`,
  `_CHAIN_`, or specific txid references)

## The Compounding Lesson

This is the **second time** this exact anti-pattern bit pyrxd's dMint
implementation:

| Incident | Direction | Caught by |
|---|---|---|
| [`dmint-v1-classifier-gap.md`](dmint-v1-classifier-gap.md) (PR #36/#39/#41) | Parser missed real V1 — only V2 fixtures tested | Live RBG inspection on mainnet |
| This incident (commit `a3ee46e`) | Builder produced wrong V1 shape — only round-trips through pyrxd's own parser tested | Manual security review forced byte-by-byte comparison |

Both were *coordinated bugs*: the test fixtures matched the buggy code
exactly because they were authored together. Without external ground
truth, no test can distinguish "internally consistent" from "actually
correct."

Treat this as a **recurring failure mode**, not a one-off lesson. The
correction baked into pyrxd's test layer (the
`test_byte_equal_to_mainnet_*` pattern) is the durable guard. Use it.

## References

- Fix commit: `a3ee46e fix(glyph): correct V1 dMint mint-tx shape + harden deploy guard + token-burn defense`
- Follow-up: `1a8d712 fix(glyph): opcode-aware funding scan + OP_RETURN msg marker + V2 default regression test`
- Mainnet trace: [`docs/dmint-research-mainnet.md`](../../dmint-research-mainnet.md) §4
- Prior incident: [`docs/solutions/logic-errors/dmint-v1-classifier-gap.md`](dmint-v1-classifier-gap.md)
- Plan: [`docs/plans/2026-05-07-feat-dmint-v1-mint-and-reference-miner-plan.md`](../../plans/2026-05-07-feat-dmint-v1-mint-and-reference-miner-plan.md)
