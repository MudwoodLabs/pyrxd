---
title: FT-in-covenant rejected — two independent consensus gates (phantom refs + codeScriptHash conservation)
category: logic-errors
component: gravity / glyph-ft / radiant-covenant
problem_type: logic_error
symptoms:
  - "bad-txns-inputs-outputs-invalid-transaction-reference-operations"
  - "mandatory-script-verify-flag-failed (Script failed an OP_NUMEQUALVERIFY operation)"
  - "FT funding tx rejected when funding a ref-bearing FT into a covenant"
  - "covenant settle/release of an FT fails conservation at spend time"
date: 2026-05-20
status: resolved (Radiant-only half proven on-chain; BTC/SPV gate is future work)
related_solutions:
  - logic-errors/funding-utxo-byte-scan-dos.md
  - logic-errors/dmint-v1-mint-shape-mismatch.md
  - logic-errors/dmint-v1-mint-scriptsig-divergence.md
  - design-decisions/spike-first-then-convergent-design-divergent-review-panels.md
verified_on_chain: true
---

# FT-in-covenant rejected — two independent consensus gates

When you try to fund a Radiant FT (fungible token) into a covenant, the
node rejects it — and the reject reason **changes** as you fix things,
because there are **two independent consensus gates**, not one. This doc
explains both and the covenant-prologue mechanism that satisfies them.
All claims marked "proven" were verified by `testmempoolaccept` /
`sendrawtransaction` on the live mainnet node.

## Symptom — the reject strings, in the order they surface

Funding a real FT into a bare ref-bearing covenant failed in two distinct
stages as each layer was fixed:

1. First: `bad-txns-inputs-outputs-invalid-transaction-reference-operations`
   (the reference-induction rule).
2. After fixing that + using the correct ref + adequate fee:
   `mandatory-script-verify-flag-failed (Script failed an OP_NUMEQUALVERIFY operation)`
   (the FT's own conservation epilogue).

Clearing the first is **necessary but not sufficient.** If you only know
about one gate, the second one looks like a regression.

## Root cause — Layer 1: phantom refs from the reference-induction rule

`ReferenceParser::validateTransactionReferenceOperations`
(`Radiant-Core/src/validation.h:991`) enforces that every push/require/
singleton ref in any OUTPUT appears in some INPUT. It extracts refs via
`CScript::GetPushRefs` (`src/script/script.cpp:555`), which **linearly
byte-scans the raw scriptPubKey** for ref opcodes (`0xd0` PUSHINPUTREF,
`0xd1` REQUIRE, `0xd2/0xd3` DISALLOW, `0xd8` PUSHINPUTREFSINGLETON),
skipping pushdata operands but otherwise **purely syntactic** — no
semantics.

A covenant that embeds the literal FT epilogue
(`…dec0e9aa76e378e4a269e69d`) as `OP_OUTPUTBYTECODE` comparison data has a
`0xd8` byte sitting in that raw data, which gets parsed as a real
`OP_PUSHINPUTREFSINGLETON` consuming the next 36 bytes as a **phantom
ref** that is in no input → reject.

**Fix:** never put FT-script bytes raw in the scriptPubKey. Compare a
**hash** instead — `hash256(output.lockingBytecode) == EXPECTED_*_FT_HASH`
— so the ref-opcode bytes only ever exist inside push-wrapped hash
operands the parser skips.

## Root cause — Layer 2: the FT's own codeScriptHashValueSum epilogue

The FT epilogue `dec0e9aa76e378e4a269e69d` contains
`OP_CODESCRIPTHASHVALUESUM_UTXOS` (`e3`) / `_OUTPUTS` (`e4`) +
`OP_NUMEQUALVERIFY` (`9d`), and it runs at spend time.
`getCodeScriptHashValueSumOutputs` (`src/script/interpreter.cpp:2215`)
sums photons of **outputs whose code-script HASH matches the FT's**.
Moving the FT into a foreign covenant output → outputs-sum 0 ≠
inputs-sum → fail. **An FT can only flow to outputs carrying its exact
code-script.** This is why "lock the FT into the covenant" is impossible,
no matter how you fix Layer 1.

## The key enabling fact (the crux)

`codeScriptHash` is computed in
`src/script/script_execution_context.h:275-285` over
`CScript(script.begin() + stateSeperatorByteIndex, script.end())` — i.e.
**the bytes from `OP_STATESEPARATOR` (`0xbd`) ONWARD ONLY.** The prologue
is **excluded** from the hash.

Therefore you can **replace the FT's standard P2PKH prologue with a
covenant condition** (mechanism "1a"), keep the `bd d0 <ref> dec0…`
epilogue intact, and a covenant-prologue FT input conserves against a
standard-P2PKH-prologue FT output **because they share the same
`codeScriptHash`**. `OP_STATESEPARATOR` is a NOP at execution
(`interpreter.cpp:1975`), so the prologue gating *and* the epilogue
conservation both run in sequence.

## Working solution — the covenant-prologue FT

The funded UTXO is:

```
<compiled covenant prologue> bd d0 <ref> dec0e9aa76e378e4a269e69d
```

The prologue is the swap logic; the appended `bd d0 <ref> dec0…` is the
FT identity. Rules:

- **Prologue must contain no bare `0xbd` in opcode position** (push-wrapped
  hash bytes are fine), so the epilogue's `bd` is the `codeScriptHash`
  boundary.
- **Output validation by hash-compare**, not embedded bytes (Layer-1
  guard).
- **Three hardening constraints:** `outputs.length == 1`,
  `refOutputCount(ref) == 1`, `refValueSum(ref) == AMOUNT`.
- **FT ref = GENESIS outpoint** (the commit/mint origin, persists across
  transfers), never the reveal/current UTXO txid.
- **Exactly two spend paths** (settle / forfeit-after-CLTV); **no
  Maker-only pre-deadline reclaim** (custody invariant).

```
function () {
    bytes36 ref = pushInputRef(REF);
    require(tx.outputs.length == 1);
    require(tx.outputs.refOutputCount(ref) == 1);
    require(tx.outputs.refValueSum(ref) == AMOUNT);
    // settle:  checkSig + hash256(outputs[0]) == EXPECTED_TAKER_FT_HASH
    // forfeit: makerSig + tx.time >= DEADLINE + hash256 == EXPECTED_MAKER_FT_HASH
}
```

(`docs/brainstorms/gravity-ref-spike/GravityFtPrologue.rxd`, 217-byte
funded script; builder `build_prologue_ft.py`.)

## On-chain proof (mainnet node, all real)

- **Leg A (broadcast):** standard FT `57296874…:0` → covenant-prologue FT,
  txid `22912a58…`. A standard-prologue FT input conserves into a
  covenant-prologue FT output.
- **Leg B (settle):** prologue-FT → standard taker FT,
  `testmempoolaccept "allowed": true`. Exercises sig + 3 hardening
  constraints + hash-compare + FT epilogue conservation.
- **4 negative cases all reject at the right constraint:** `extra_output`
  → `OP_NUMEQUALVERIFY` (output-count clamp); `wrong_taker` → false top
  stack (hash-compare); `short_amount` → `OP_NUMEQUALVERIFY`
  (`refValueSum==AMOUNT`); `cancel_attempt` (selector OP_2) →
  `OP_NUMEQUALVERIFY` (no third branch — the custody invariant holds).

**Proven on-chain:** the Radiant-only conservation + custody + hardening
half. **Designed but not yet built:** the BTC/SPV gate and SPV-reuse
binding — the settle path here is sig-gated only (it keeps the spike tx
well-formed). That cross-chain atomicity half is future work.

## Prevention & best practices

### 1. Pre-broadcast phantom-ref guard

Both gates fire on *byte content you didn't intend as an opcode*. Walk
every output `scriptPubKey` the way `GetPushRefs` does — opcode-aware,
skipping pushdata — and assert the ref set is **exactly** what you
intended.

Do **not** hand-port a fresh byte-walker. The walker at
`src/pyrxd/glyph/dmint/chain.py:494` (`is_token_bearing_script`) already
implements the correct traversal; extract a shared
`count_input_refs(script)` primitive from it rather than maintaining two
divergent walkers (a reserved `0xd4`–`0xd7` opcode is exactly how two
walkers drift).

```python
REF_OPCODES = {0xD0, 0xD1, 0xD2, 0xD3, 0xD8}

def walk_refs(script: bytes):
    pos, n = 0, len(script)
    while pos < n:
        op = script[pos]
        if op in REF_OPCODES:            # bare ref opcode — 36-byte operand
            yield op, script[pos + 1 : pos + 37]
            pos += 37
            continue
        if 0x01 <= op <= 0x4B:           # direct push: N == opcode value
            pos += 1 + op
        elif op == 0x4C:                 # PUSHDATA1
            pos += 2 + script[pos + 1]
        elif op == 0x4D:                 # PUSHDATA2
            pos += 3 + int.from_bytes(script[pos+1:pos+3], "little")
        elif op == 0x4E:                 # PUSHDATA4
            pos += 5 + int.from_bytes(script[pos+1:pos+5], "little")
        else:
            pos += 1                     # no-payload opcode

refs = [r for _, r in walk_refs(spk)]
assert refs.count(GENESIS_REF) == len(refs) and refs, f"phantom refs: {refs}"
```

### 2. Design rules for any FT-bearing covenant

- Never embed FT-script bytes raw — hash-compare instead.
- An FT cannot be held in a foreign covenant — gate the *spend path* and
  settle to the exact FT code-script.
- `codeScriptHash` = bytes from `OP_STATESEPARATOR` onward; the prologue
  must have no bare `0xbd` in opcode position.
- Always reference the **genesis** ref, never the reveal/current txid.

### 3. Test the negative cases on-chain

A passing settle proves only the happy path. **Every** hardening
constraint must be shown to *reject* its negative case via
`testmempoolaccept` against a real node — output-count clamp, exact
amount, single ref, wrong destination, and the no-cancel custody
invariant. Synthetic round-trips through your own parser are **not
sufficient**: this is the recurring dMint failure mode
([dmint-v1-mint-shape-mismatch.md](dmint-v1-mint-shape-mismatch.md),
[dmint-v1-mint-scriptsig-divergence.md](dmint-v1-mint-scriptsig-divergence.md))
— your decoder and the node's consensus rules can disagree, and only the
node is authoritative.

### Pre-ship checklist

- [ ] `walk_refs` over every output scriptPubKey; ref set is exactly the genesis ref
- [ ] No FT-script bytes embedded raw; all FT-shape comparisons go through `hash256`
- [ ] Prologue scanned for bare `0xbd` — none in opcode position
- [ ] FT settles to the exact FT code-script (not held in the covenant)
- [ ] Genesis ref used everywhere; no reveal/current txid
- [ ] Each hardening constraint has a `testmempoolaccept` test that **rejects** its negative case on a real node
- [ ] `count_input_refs` extracted and shared with `is_token_bearing_script` (one walker)

## Related

- [funding-utxo-byte-scan-dos.md](funding-utxo-byte-scan-dos.md) — the
  consumer/classifier-side **mirror** of Layer 1: a bare-byte deny-list
  false-rejects ~51% of honest P2PKH funding UTXOs. Same opcode-position-
  vs-byte-scan pitfall, opposite direction.
- [dmint-v1-mint-shape-mismatch.md](dmint-v1-mint-shape-mismatch.md),
  [dmint-v1-mint-scriptsig-divergence.md](dmint-v1-mint-scriptsig-divergence.md)
  — why synthetic round-trips don't catch this; test against real chain bytes.
- [spike-first-then-convergent-design-divergent-review-panels.md](../design-decisions/spike-first-then-convergent-design-divergent-review-panels.md)
  — the process that surfaced both gates and corrected the falsified plan.
- Plan: `docs/plans/2026-05-20-feat-gravity-ft-covenant-spend-path-plan.md`
  (Option A — covenant gates the FT spend-path). Supersedes the
  falsified `2026-05-19-feat-gravity-ref-bearing-covenant-plan.md`.
- Design + on-chain proof detail:
  `docs/brainstorms/2026-05-19-gravity-ref-covenant-design.md`.
- Consensus source: `Radiant-Core/src/validation.h:991`,
  `src/script/script.cpp:555`, `src/script/interpreter.cpp:1975` & `:2215`,
  `src/script/script_execution_context.h:275-285`.
