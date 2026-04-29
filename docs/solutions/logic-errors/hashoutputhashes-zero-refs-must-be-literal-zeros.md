---
title: "hashOutputHashes: zero-ref refsHash must be b'\\x00'*32, not hash256(b'')"
problem_type: logic_error
component: pyrxd.gravity.transactions
symptom: "Signatures valid locally but rejected on-chain: mandatory-script-verify-flag-failed (code 16)"
root_cause: "refsHash for outputs with totalRefs==0 computed as hash256(b'') = 5df6e0e2... instead of literal 32 zero bytes; node and SDK compute different sighashes"
tags: [bip143, hashOutputHashes, radiant, sighash, signature-verification, cryptography]
related_files:
  - src/pyrxd/gravity/transactions.py
  - src/pyrxd/transaction/transaction_preimage.py
verified: true
verification_method: mainnet_broadcast
verification_txid: 1d3ef1a6bbd0d57881cb27a449f9914ea828b1a18d7fc3cf2fe6f41a698519e5
date: 2026-04-21
---

## Symptom

Every signature produced by `build_maker_offer_tx` (and any builder using `_sign_radiant_p2sh_input`) was rejected by the Radiant mainnet node with:

```
mandatory-script-verify-flag-failed (Signature must be zero for failed CHECK(MULTI)SIG operation) (code 16)
```

Local verification passed — `pub.verify(sig_der, sighash, hasher=None)` returned `True`. The pubkey matched the PKH in the UTXO. The transaction structure was correct.

## Root Cause

Radiant's BIP143 extension adds `hashOutputHashes` (field 8) before `hashOutputs` in the sighash preimage. For each output, the per-output summary is:

```
value (8 bytes LE) + hash256(scriptPubKey) (32 bytes) + totalRefs (4 bytes LE) + refsHash (32 bytes)
```

When `totalRefs == 0`, `refsHash` must be **literal 32 zero bytes** — a C++ `uint256` default-initialized to all zeros in the Radiant node source (`interpreter.cpp` + `transaction.h`). The SDK had:

```python
EMPTY_REFS_HASH = hash256(b"")  # = 5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456
```

`hash256(b"")` is **not** all zeros. It is the double-SHA256 of the empty byte string. Using it causes the SDK's sighash to differ from the node's, so the node's script interpreter rejects the signature even though it is cryptographically valid against the SDK's preimage.

The correct value (`_ZERO_REF = b"\x00" * 32`) was already present in `transaction_preimage.py`. Only the inline copy in `gravity/transactions.py` had the bug.

## Investigation

1. Confirmed tx structure correct: version=2, single P2PKH input, single P2SH output, locktime=0.
2. Extracted the raw rejected tx hex from the ElectrumX error response; decoded fields manually.
3. Recomputed the sighash locally from the decoded fields — `pub.verify(sig_der, local_sighash)` returned `True`, proving the signature was cryptographically valid against our preimage.
4. Concluded: node computes a different sighash. Pulled Radiant node C++ source to find the exact divergence.
5. Found `transaction.h` lines 441–489 (`RefHashDataSummary`): zero-ref outputs use `uint256()` (all zeros), not `Hash::hash256(Buffer.alloc(0))`.

## Fix

**`src/pyrxd/gravity/transactions.py`**

```python
# Before — WRONG
EMPTY_REFS_HASH = hash256(b"")

summary = (
    value.to_bytes(8, "little")
    + hash256(script)
    + (0).to_bytes(4, "little")  # totalRefs = 0
    + EMPTY_REFS_HASH            # 5df6e0e2... ← node uses 00000...000
)

# After — CORRECT
ZERO_REFS_HASH = b"\x00" * 32  # uint256 zero — per Radiant source, NOT hash256(b"")

summary = (
    value.to_bytes(8, "little")
    + hash256(script)
    + (0).to_bytes(4, "little")  # totalRefs = 0
    + ZERO_REFS_HASH             # 32 zero bytes ✓
)
```

The canonical implementation in `transaction_preimage.py` was already correct:

```python
_ZERO_REF = b"\x00" * 32  # line 10 — correct all along
```

## Verification

After applying the fix, the live broadcast succeeded on Radiant mainnet:

```
MakerOffer broadcast SUCCESS: 1d3ef1a6bbd0d57881cb27a449f9914ea828b1a18d7fc3cf2fe6f41a698519e5
```

## Prevention

### Never confuse "hash of empty" with "literal zero"

In Bitcoin-derived chains, hash trees and sighash preimages frequently use zero values as sentinels for empty/absent fields. These are **always** literal zero bytes (`b"\x00" * 32`), never `hash256(b"")`. The naming makes this tricky:

| Looks right | Actually is |
|---|---|
| `hash256(b"")` | `5df6e0e2...` — wrong |
| `b"\x00" * 32` | 32 zero bytes — correct |

When porting from C++, a field initialized as `uint256()` or `uint256S("0000...0000")` is always all zeros.

### Read the node source, not the README

Before implementing any fork's sighash variant, read `interpreter.cpp` (or equivalent) end to end. Especially check:
- The exact field order (Radiant inserts `hashOutputHashes` between `nSequence` and `hashOutputs`)
- How each per-output summary is constructed
- What value is used for absent/empty sub-fields

### Eliminate duplicate implementations

The correct value existed in `transaction_preimage.py` and the wrong value lived in the inline copy in `transactions.py`. If the algorithm had been imported rather than re-implemented, the bug could not exist in both places simultaneously.

### Validate against mainnet before deploying

Local `pub.verify(sig, sighash)` is not sufficient — it only proves the signature is consistent with your own preimage. The definitive test is broadcasting to the real network with a dust amount. Rejection with code 16 pinpoints a preimage mismatch.

### Test with external golden vectors

Unit tests that compute expected values using the same implementation they're testing will pass even when the implementation is wrong. Use sighash vectors extracted from confirmed mainnet transactions:

```python
def test_hashoutputhashes_zero_refs_uses_literal_zeros():
    """Regression: refsHash for zero-ref output must be b'\x00'*32, not hash256(b'')."""
    # Plain P2PKH output — no push refs
    script = bytes.fromhex("76a914" + "aa" * 20 + "88ac")
    value = 50_000
    outputs_serialized = value.to_bytes(8, "little") + bytes([len(script)]) + script

    result = _compute_hash_output_hashes(outputs_serialized)

    # If hash256(b"") were used, the result would be different — this catches the regression
    wrong = _compute_hash_output_hashes_with_empty_hash(outputs_serialized)
    assert result != wrong, "Implementation still uses hash256(b'') for zero-ref refsHash"
```

## Related

- [radiant-bip143-sighash-missing-field-and-stale-trial-signature.md](radiant-bip143-sighash-missing-field-and-stale-trial-signature.md) — prior fix: missing `hashOutputHashes` field entirely + stale trial signature bug
- Radiant node source: `radiant-node/src/script/interpreter.cpp:2596–2658`, `transaction.h:441–489`
