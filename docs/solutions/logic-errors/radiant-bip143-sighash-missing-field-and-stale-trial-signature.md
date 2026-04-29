---
title: "Radiant BIP143 missing hashOutputHashes field + two-pass signing object reuse"
slug: "radiant-bip143-sighash-missing-field-and-stale-trial-signature"
date: "2026-04-21"
type: logic-error
component: "pyrxd/transaction/transaction_preimage"
symptom: "Every transaction broadcast rejected with SCRIPT_VERIFY_NULLFAIL because the Python SDK generated Bitcoin-compatible BIP143 preimages missing Radiant's required hashOutputHashes field; a second bug in glyph_mint_demo silently reused a stale trial signature in the final reveal tx."
tags: [radiant, blockchain, bip143, preimage, sighash, signature, nft, glyph]
severity: critical
status: resolved
related_files:
  - src/pyrxd/transaction/transaction_preimage.py
  - examples/glyph_mint_demo.py
---

# Radiant BIP143: Missing hashOutputHashes + Stale Trial Signature

## Summary

Two bugs caused Glyph NFT mainnet reveal transactions to be rejected with
`mandatory-script-verify-flag-failed (Signature must be zero for failed CHECK(MULTI)SIG operation)`.

- **Bug 1 (critical, SDK-wide):** Radiant's BIP143 sighash preimage includes an extra field `hashOutputHashes` (32 bytes, field 8) that the Python SDK was not emitting. Every signature produced by the SDK was invalid on-chain.
- **Bug 2 (logic error, demo script):** `build_reveal_tx()` reused the same `TransactionInput` object across a trial tx and the final tx. After `trial_tx.sign()` set `reveal_input.unlocking_script`, the subsequent `tx.sign(bypass=True)` silently skipped re-signing, leaving a stale signature covering the wrong output amounts.

**Verified fix:** Simple P2PKH self-transfer broadcast confirmed after Bug 1 fix:
`0b227d63fc3099ffbcd38273c62ada688095bfdd88d6d39dd9bf719a14d40e0f`. All 510 tests pass.

---

## Root Cause Analysis

### Bug 1: Missing hashOutputHashes in Radiant BIP143 Preimage

Radiant extends Bitcoin SV's BIP143 sighash preimage with an additional field — `hashOutputHashes` — inserted as **field 8**, immediately before `hashOutputs`. Without it, the signing preimage does not match what Radiant nodes expect, causing transaction rejection.

The standard Bitcoin SV BIP143 preimage has 10 fields. Radiant adds an 11th field at position 8. For each output, this field commits to:
- The output's satoshi value (8-byte LE)
- `hash256` of the locking script
- Count of Radiant push-ref opcodes in the script (4-byte LE)
- `hash256` of all push-ref buffers (sorted and concatenated), or 32 zero bytes if none

`hashOutputHashes` is then `hash256` of the entire concatenated per-output blob. This binds signers to the ref-graph structure of outputs, not just their serialized bytes.

The Radiant-specific opcodes that carry ref data are:
- `OP_PUSHINPUTREF` (`0xd0`) — followed by exactly 36 bytes of ref data
- `OP_PUSHINPUTREFSINGLETON` (`0xd8`) — followed by exactly 36 bytes of ref data

Standard P2PKH outputs contain no such opcodes — their push-ref count is 0 and the 32-zero-byte sentinel is used — but the field must still be present and correctly computed.

**The diagnostic tell:** Signature is mathematically valid ECDSA (verifies locally), but every Radiant node rejects with NULLFAIL. If local verification passes but node rejects, the preimage field set is the suspect.

### Bug 2: Two-Pass Signing Bypass Causing Stale Signature Reuse

`build_reveal_tx()` uses a two-pass approach: sign a trial transaction to measure byte length, compute correct fee, then sign a final transaction with the real output value. The same `reveal_input` object was shared between both transactions.

After `trial_tx.sign()`, `reveal_input.unlocking_script` was set (non-None). When `tx.sign(bypass=True)` ran on the final tx, it checked:

```python
if tx_input.unlocking_script is None or not bypass:
    tx_input.unlocking_script = tx_input.unlocking_script_template.sign(self, i)
```

Since `unlocking_script` was not None and `bypass=True`, it **skipped re-signing**. The transaction was broadcast with a scriptSig committed to the trial output value, not the final output value. No exception — just a silently invalid signature.

---

## The Fixes

### Fix 1: `_get_push_refs()` — Scan script for Radiant ref opcodes

`src/pyrxd/transaction/transaction_preimage.py`

```python
_OP_PUSHINPUTREF = 0xd0
_OP_PUSHINPUTREFSINGLETON = 0xd8

def _get_push_refs(script_bytes: bytes) -> list:
    refs = {}
    i = 0
    while i < len(script_bytes):
        op = script_bytes[i]
        i += 1
        if op == _OP_PUSHINPUTREF or op == _OP_PUSHINPUTREFSINGLETON:
            ref = script_bytes[i:i+36]
            i += 36
            refs[ref.hex()] = ref
        elif 0x01 <= op <= 0x4b:
            i += op  # direct push: skip data bytes
        elif op == 0x4c:  # OP_PUSHDATA1
            n = script_bytes[i]; i += 1 + n
        elif op == 0x4d:  # OP_PUSHDATA2
            n = int.from_bytes(script_bytes[i:i+2], "little"); i += 2 + n
        elif op == 0x4e:  # OP_PUSHDATA4
            n = int.from_bytes(script_bytes[i:i+4], "little"); i += 4 + n
    return [refs[k] for k in sorted(refs.keys())]
```

The dict keyed by hex deduplicates refs. Sorting by hex key ensures deterministic ordering before hashing.

### Fix 2: `_compute_hash_output_hashes()` — Build the Radiant-specific field

`src/pyrxd/transaction/transaction_preimage.py`

```python
_ZERO_REF = b"\x00" * 32

def _compute_hash_output_hashes(outputs: List[TransactionOutput], index: int = None) -> bytes:
    buf = BytesIO()
    start = 0 if index is None else index
    end = (len(outputs) - 1) if index is None else index
    for i in range(start, end + 1):
        out = outputs[i]
        script_bytes = out.locking_script.serialize()
        buf.write(out.satoshis.to_bytes(8, "little"))
        buf.write(hash256(script_bytes))
        push_refs = _get_push_refs(script_bytes)
        buf.write(struct.pack("<I", len(push_refs)))
        if push_refs:
            buf.write(hash256(b"".join(push_refs)))
        else:
            buf.write(_ZERO_REF)
    return hash256(buf.getvalue())
```

The `index` parameter supports `SIGHASH_SINGLE` mode (hash only the output at the same position as the input being signed).

### Fix 3: Updated `_preimage()` field ordering

The `_preimage()` function now accepts `hash_output_hashes` as field 8, between `hash_sequence` (field 7) and `hash_outputs` (field 9):

```
 1. nVersion (4-byte LE)
 2. hashPrevouts (32-byte hash)
 3. hashSequence (32-byte hash)
 4. outpoint (32-byte hash + 4-byte LE)
 5. scriptCode (varint-length-prefixed)
 6. value of spent output (8-byte LE)
 7. nSequence (4-byte LE)
 8. hashOutputHashes (32-byte hash)  ← Radiant extension
 9. hashOutputs (32-byte hash)
10. nLocktime (4-byte LE)
11. sighash type (4-byte LE)
```

### Fix 4: `reveal_input.unlocking_script = None` before final tx

`examples/glyph_mint_demo.py`

```python
    trial_tx = Transaction(
        tx_inputs=[reveal_input],
        tx_outputs=[TransactionOutput(Script(nft_locking_script_bytes), trial_nft)],
    )
    trial_tx.sign()
    actual_size = trial_tx.byte_length()

    fee = actual_size * (MIN_FEE_RATE + 500)
    nft_value = commit_value - fee

    # Reset the unlocking script so sign() re-signs over the final outputs (not trial outputs)
    reveal_input.unlocking_script = None

    tx = Transaction(
        tx_inputs=[reveal_input],
        tx_outputs=[TransactionOutput(Script(nft_locking_script_bytes), nft_value)],
    )
    tx.sign()
```

Without this reset, `tx.sign(bypass=True)` finds `unlocking_script is not None` and silently skips signing.

---

## Detection

**Distinguishing wrong preimage from other CHECKSIG failures:**

| Symptom | Cause |
|---|---|
| Locally valid ECDSA, node rejects NULLFAIL | Wrong preimage field set |
| Signature doesn't verify at all | Wrong key |
| Different error code | Wrong sighash type byte |
| Rejected before script eval | Malformed DER encoding |
| Accepted by script, not relayed | Fee too low |

**How to compare Python preimage with radiantjs:**

1. Construct the same transaction in both SDKs (identical inputs, outputs, locktime, version)
2. Call the sighash preimage function for input index 0, `SIGHASH_ALL`, before hashing
3. Hex-encode both preimage byte strings
4. If lengths differ by exactly 32 bytes, a field is missing
5. Parse by offset to find the divergence point; the Radiant preimage is 264 bytes for a simple 1-in 1-out tx

---

## Prevention

### Test `_compute_hash_output_hashes()` Against a Known-Good Vector

```python
def test_hash_output_hashes_p2pkh():
    # Known fixture: two P2PKH outputs — expected value verified against radiantjs
    out1 = TransactionOutput(Script(bytes.fromhex("76a914" + "aa" * 20 + "88ac")), 100_000)
    out2 = TransactionOutput(Script(bytes.fromhex("76a914" + "bb" * 20 + "88ac")), 50_000)
    result = _compute_hash_output_hashes([out1, out2])
    assert result == bytes.fromhex("<known-good-hex-from-radiantjs>")
```

The expected value must be established by running matching radiantjs code and committed as a hardcoded test vector. Any preimage regression fails this test immediately.

### Prevent Stale-Signature Reuse

Three safe patterns for two-pass signing:

**Option A (used in this fix):** Reset `unlocking_script = None` on the shared input before the second tx.

**Option B:** Always call `tx.sign(bypass=False)` on the final tx to force re-signing regardless.

**Option C:** Create a fresh `TransactionInput` for the final tx instead of reusing the trial input object.

### Auditing Bitcoin-Derivative SDKs for Missing Consensus Fields

1. Read the node source (not SDK docs) for the exact preimage byte layout
2. Count total preimage length for a simple tx; compare against your SDK's output
3. Diff the field list against BIP143 — every addition is a potential bug
4. Verify against a reference implementation (radiantjs, node RPC), not your own SDK
5. Check all sighash type variants (SIGHASH_ALL, SIGHASH_SINGLE, SIGHASH_NONE)

### Red Flags

**Missing consensus fields:**
- SDK forked from Bitcoin/BCH without an explicit audit against the derivative chain's sighash spec
- Sighash function has no comment linking each field to a spec section
- Unit tests only check that output is 32 bytes or changes — not a known-good value
- No integration test that broadcasts to a node and asserts acceptance

**Stale-signature reuse:**
- `TransactionInput` is mutable and accumulates signing state
- `sign()` bypass logic is based on `unlocking_script is None` without checking which tx it was signed for
- Same input object passed to multiple transaction constructors without explicit copy
- No test constructs two transactions sharing an input and verifies both are independently valid

---

## Related

- `src/pyrxd/gravity/transactions.py` — `_sign_p2sh_input` documents the Radiant preimage layout inline; must stay in sync with `transaction_preimage.py` if the field set ever changes
- `src/pyrxd/btc_wallet/payment.py` — explicitly uses Bitcoin BIP143 (no `hashOutputHashes`); correct as-is
- Commit: `19a01de fix(preimage): add Radiant hashOutputHashes field to BIP143 sighash preimage`
