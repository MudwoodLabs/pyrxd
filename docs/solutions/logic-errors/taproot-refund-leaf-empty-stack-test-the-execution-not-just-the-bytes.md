---
title: "Taproot HTLC refund leaf ended with an empty stack — test leaf EXECUTION, not just bytes + signature"
category: logic-errors
component: gravity / btc-wallet / taproot-htlc
tags:
  - taproot
  - tapscript
  - htlc
  - bip342
  - cleanstack
  - op-checksig
  - op-checksigverify
  - op-csv
  - bip68
  - refund-leaf
  - test-gap
  - cross-chain
  - mainnet
date: 2026-05-24
severity: high
symptom: >
  Broadcasting the CSV-matured refund of a Taproot HTLC was rejected by Bitcoin
  consensus with `mempool-script-verify-flag-failed (Stack size must be exactly one
  after execution)`. The CSV timelock had matured (the rejection was NOT
  `non-BIP68-final`) and the signature was valid — the leaf script itself left the
  wrong number of items on the stack, so the refund path was unspendable.
root_cause: >
  The refund leaf was `<refundPk> OP_CHECKSIGVERIFY <timeout> OP_CSV OP_DROP`.
  OP_CHECKSIGVERIFY consumes the sig+pubkey and pushes nothing; OP_CSV is
  verify-but-don't-pop, then OP_DROP removes its operand — so the script ends with an
  EMPTY stack. BIP342 tapscript requires exactly ONE (truthy) element at the end. The
  tests asserted byte layout + signature validity but never EXECUTED the leaf, so the
  bug shipped.
---

# Taproot HTLC refund leaf left an empty stack — and the tests couldn't see it

## Symptom

The CSV-matured refund spend of a Taproot HTLC was rejected on mainnet:

```
mempool-script-verify-flag-failed (Stack size must be exactly one after execution)
```

Critically, this was **not** a `non-BIP68-final` timelock rejection — the 6-block
relative timelock had matured (premature attempts had earlier been correctly rejected
`non-BIP68-final`). The signature was valid. The **leaf script itself** failed the
BIP342 cleanstack rule.

## Root Cause

The refund leaf was built as:

```
<refundPk> OP_CHECKSIGVERIFY <timeout> OP_CSV OP_DROP
```

Trace the stack with the witness `[sig]`:

| step | stack |
|------|-------|
| start (witness) | `[sig]` |
| push `<refundPk>` | `[sig, refundPk]` |
| `OP_CHECKSIGVERIFY` (pops sig+pubkey, verifies, **pushes nothing**) | `[]` |
| push `<timeout>` | `[timeout]` |
| `OP_CHECKSEQUENCEVERIFY` (verify-but-**don't-pop**, like CLTV) | `[timeout]` |
| `OP_DROP` | `[]` |

Final stack is **empty**. BIP342 tapscript requires the script to end with **exactly one**
element, and it must be truthy. So every refund spend — regardless of signature or
timelock — failed `Stack size must be exactly one after execution`.

The author's instinct that a DROP was needed was *correct* (OP_CSV leaves its operand on
the stack — it's verify-only, identical to OP_CLTV), but the placement was wrong: putting
`OP_DROP` after a terminal `OP_CHECKSIGVERIFY` that had already drained the stack empties
it entirely. (The same `OP_CSV OP_DROP` pattern is right on the Radiant side because there
the sequence value is pushed *first* and the script continues with other checks — copying
that ordering verbatim into a BTC leaf that ends on the sig check is what broke it.)

## Solution

Reorder to the canonical BOLT-3 / Boltz ordering: **timelock gate first, value-leaving
`OP_CHECKSIG` last.**

```
<timeout> OP_CSV OP_DROP <refundPk> OP_CHECKSIG
```

Trace with `[sig]`:

| step | stack |
|------|-------|
| start | `[sig]` |
| push `<timeout>` | `[sig, timeout]` |
| `OP_CSV` (verify, don't pop) | `[sig, timeout]` |
| `OP_DROP` | `[sig]` |
| push `<refundPk>` | `[sig, refundPk]` |
| `OP_CHECKSIG` (pops both, **pushes 1**) | `[1]` |

Final stack `[1]` — exactly one truthy element. The last opcode MUST be `OP_CHECKSIG`
(not `OP_CHECKSIGVERIFY`), because the script needs to *leave* the boolean the cleanstack
rule wants.

**Address impact:** the leaf script feeds the tapleaf hash → merkle root → taptweak →
output key, so changing it **changes the HTLC address**. HTLCs funded against the old
(broken) leaf are refund-unspendable and recoverable only via the claim path. The fix
protects only HTLCs created after it.

Verified on mainnet: a fresh HTLC funded with the fixed leaf had its premature refund
rejected `non-BIP68-final` and its **matured refund accepted** (v2 tx, nSequence=6,
witness = sig + script + control-block, paying the taker after the 6-block CSV).

## The real lesson — test leaf EXECUTION, not just bytes + signature

The taproot test suite asserted:
- address/merkle derivation against official BIP341 vectors, and
- that the refund witness carried a valid Schnorr signature over the correct sighash.

It **never executed either leaf script through an interpreter, and never broadcast one.**
A stack-discipline bug (`OP_CHECKSIGVERIFY` vs `OP_CHECKSIG`, an off-by-one in stack
height) is *invisible* to a suite that only checks byte layout and signature crypto. The
test that pinned the refund leaf even asserted the buggy structure (`script[33]==0xad`,
OP_CHECKSIGVERIFY), locking the bug in.

A premature-refund rejection (`non-BIP68-final`) looked like proof the refund "worked" —
but it only proved the **timelock gate**, never that the **leaf executes to completion**.
Only the matured-refund on-chain broadcast exercised the full script, and that's what
caught it.

## Prevention

1. **Execute the script, don't just inspect it.** Add a test that runs each tapscript
   leaf through a real interpreter (`testmempoolaccept` against a node, or a local
   `VerifyScript` with the tapscript + CSV flags) and asserts it ends with exactly one
   truthy element. A cheap offline stand-in: a stack-height simulator that models each
   opcode's pop/push (CHECKSIG: −2 +1; CHECKSIGVERIFY: −2 +0; CSV: +0 verify-don't-pop;
   DROP: −1) and asserts the final height is 1 from a witness of `[sig]`.
2. **Prove both timelock directions on-chain**, not just the negative. A `non-BIP68-final`
   rejection proves the gate, not the script — broadcast the matured spend too.
3. **Terminal-opcode rule for tapscript leaves:** a leaf must end on a value-leaving
   opcode (`OP_CHECKSIG`, `OP_EQUAL`), never on a `*VERIFY` that drains the stack.
4. **Don't copy an opcode idiom across VMs without re-tracing the stack.** `OP_CSV
   OP_DROP` is correct on Radiant covenants (sequence pushed first, script continues) and
   wrong as the tail of a BTC leaf that ends on the sig check.

See also the related "prove the refund path actually fires on both chains" lesson in
[`../design-decisions/spv-oracle-swap-is-not-atomic-use-htlc.md`](../design-decisions/spv-oracle-swap-is-not-atomic-use-htlc.md)
and the covenant value-pin lesson
[`radiant-covenant-amount-pin-must-match-funded-carrier.md`](radiant-covenant-amount-pin-must-match-funded-carrier.md)
— both are the same meta-lesson: a working happy-path demo is not proof the safety/refund
path works; exercise it on-chain.
