---
title: Bare-byte deny-list DoS — token-burn defense rejected ~51% of legitimate P2PKH miners
problem_type: logic_error
component: pyrxd.glyph.dmint (V1 funding-UTXO check)
symptoms:
  - First-pass token-burn defense in commit a3ee46e linear-scanned funding scripts for any byte in 0xd0-0xd8
  - P(reject) for random P2PKH = 1 - (247/256)^20 ≈ 0.511
  - Real ecosystem miners would have hit InvalidFundingUtxoError with a misleading "OP_PUSHINPUTREF-family" message on roughly half their funding addresses
  - Hand-written unit tests exercised only adversarially-shaped (token-bearing) scripts; never tested honest P2PKH with deny-range bytes in payload position
severity: high
date_solved: 2026-05-08
prs: [feat/dmint-v1-mint commits a3ee46e (introduced), 1a8d712 (fixed)]
tags: [dmint, v1, funding, deny-list, classification, byte-scan, opcode-stream, false-positive, dos]
related_files:
  - src/pyrxd/glyph/dmint.py
  - tests/test_dmint_v1_mint.py
related_solutions:
  - docs/solutions/logic-errors/dmint-v1-mint-shape-mismatch.md
---

## Symptom

While fixing the show-stopper "wrong V1 mint tx shape" bug
([dmint-v1-mint-shape-mismatch.md](dmint-v1-mint-shape-mismatch.md)),
the introduced funding-UTXO defense — meant to prevent silent
token-burn — was implemented as a bare-byte scan:

```python
# src/pyrxd/glyph/dmint.py at commit a3ee46e (the buggy version)
_FUNDING_REF_OPCODE_RANGE = range(0xD0, 0xD9)

def _funding_script_is_token_bearing(script: bytes) -> bool:
    return any(byte in _FUNDING_REF_OPCODE_RANGE for byte in script)
```

The check was called from
[`_build_dmint_v1_mint_tx`](../../src/pyrxd/glyph/dmint.py) and raised
`InvalidFundingUtxoError` if any byte in the script fell in the
0xD0–0xD8 range. P2PKH addresses contain a 20-byte raw payload hash;
the probability that at least one byte falls in that range is:

```
P(reject) = 1 - (247/256)^20 ≈ 0.511
```

So **~51% of honest miners using random P2PKH funding addresses would
have been rejected** with a misleading error message. The token-burn
defense was a 50% miner DoS in disguise.

## Root Cause

Bitcoin and Radiant scripts are an *opcode stream* where push opcodes
are followed by raw payload bytes that are **not opcodes**:

| Opcode | Effect |
|---|---|
| `0x01..0x4B` | Push the next N bytes (N = opcode value) |
| `0x4C` (PUSHDATA1) | Next byte is length, then push that many |
| `0x4D` (PUSHDATA2) | Next 2 bytes (LE) are length, then push |
| `0x4E` (PUSHDATA4) | Next 4 bytes (LE) are length, then push |
| Anything else | Single-byte opcode, no payload |

A bare-byte scan **cannot distinguish**:

- `0xD2` as the **opcode** OP_DISALLOWPUSHINPUTREF (a real token envelope marker)
- `0xD2` as the **7th byte of a 20-byte P2PKH hash payload** (innocent miner address)

The design assumption — *"OP_PUSHINPUTREF-family opcodes only appear in
token-bearing scripts"* — was correct. The implementation assumption —
*"any byte in 0xD0–0xD8 is an opcode"* — was wrong. It treated the
script as opaque bytes when it had to be parsed as an opcode stream.

## Why First-Round Tests Didn't Catch It

The unit tests for the deny-list were written by the feature author
(me). Two test cases:

```python
# Both fixtures put 0xD0 / 0xD8 in OPCODE position (as the first byte
# of an envelope). Both correctly rejected. Both told us nothing about
# the false-positive rate against honest P2PKH.

ft_script = b"\x76\xa9\x14" + bytes(20) + b"\x88\xac" + b"\xbd" + b"\xd0" + bytes(36) + ...
dmint_script = b"\xd8" + bytes(36) + b"\x76\xa9\x14" + bytes(20) + b"\x88\xac"
```

Neither test exercised a P2PKH with deny-range bytes in **payload
position**. The classifier appeared correct because the fixtures
matched the implementation's flawed mental model.

## What Did Catch It

The **second** red-team review pass (after the first round caught the
mint-tx-shape bug). The reviewer specifically constructed adversarial
inputs: a P2PKH script where all 20 payload bytes fell in the deny
range. The check rejected it, and the reviewer computed the false-positive
rate from first principles.

Quoting the red-team finding:

> *"The filter linear-scans for any byte in 0xd0..0xd8 anywhere in the
> script. A 25-byte P2PKH `76 a9 14 <PKH-20> 88 ac` contains the PKH as
> raw bytes, not a script literal; if any of the 20 PKH bytes lies in
> 0xd0..0xd8, the filter rejects the UTXO. P(reject) = 1 − (247/256)^20
> ≈ 51%. ~half of all miners using random P2PKH change addresses cannot
> mint."*

## The Trade-Off That Got Made

The first hardening commit traded a silent token-burn DoS (low
prevalence, high per-victim cost: lost tokens) for a loud miner DoS
(high prevalence, lower per-victim cost: blocked from minting). Both
are bad. The second one was caught only because the first review's fix
introduced new surface that invited a second review.

**Lesson**: fixing one problem rarely closes the file — it changes
which tests to write next. Plan for at least one follow-up review pass
on any non-trivial defensive code that lands.

## The Fix

Commit `1a8d712 fix(glyph): opcode-aware funding scan + OP_RETURN msg
marker + V2 default regression test`:

Replaced the bare-byte scan with an opcode-stream-aware walker.

[src/pyrxd/glyph/dmint.py:1513](../../src/pyrxd/glyph/dmint.py#L1513):

```python
def _funding_script_is_token_bearing(script: bytes) -> bool:
    """Return True if `script` uses any OP_PUSHINPUTREF-family opcode.

    Walks the script as an opcode stream: push opcodes (0x01..0x4e)
    consume their payload, and only the *opcode position* bytes are
    checked against the deny-list. A bare-byte scan would falsely flag
    any P2PKH whose 20-byte hash contains a 0xd0–0xd8 byte (~51% of
    random addresses), denying about half of honest miners.

    Truncated push fields are treated as token-bearing — a malformed
    script of ambiguous length should not be accepted as funding.
    """
    pos = 0
    n = len(script)
    while pos < n:
        op = script[pos]
        if op in _FUNDING_REF_OPCODE_RANGE:
            return True
        if 0x01 <= op <= 0x4B:           # direct push N bytes
            new_pos = 1 + pos + op
            if new_pos > n:
                return True              # truncated push → refuse
            pos = new_pos
            continue
        if op == 0x4C:                   # PUSHDATA1
            if pos + 1 >= n:
                return True
            length = script[pos + 1]
            new_pos = pos + 2 + length
            if new_pos > n:
                return True
            pos = new_pos
            continue
        if op == 0x4D:                   # PUSHDATA2 (LE)
            ...
        if op == 0x4E:                   # PUSHDATA4 (LE)
            ...
        pos += 1
    return False
```

### The regression test

[tests/test_dmint_v1_mint.py:497](../../tests/test_dmint_v1_mint.py#L497):

```python
def test_p2pkh_with_d_byte_in_hash_is_accepted(self):
    """A plain P2PKH whose 20-byte pkh contains a byte in 0xd0-0xd8 is
    a legitimate plain-RXD UTXO and must not be flagged as token-bearing.

    The previous byte-scan implementation would flag any P2PKH where any
    of the 20 hash bytes happened to fall in 0xd0-0xd8 — a ~51% false-
    positive rate against random P2PKH addresses."""
    utxo = _make_v1_contract_utxo()
    # Worst-case: every payload byte is in the deny range.
    hash_with_d_bytes = bytes([0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8] * 3)[:20]
    p2pkh = b"\x76\xa9\x14" + hash_with_d_bytes + b"\x88\xac"
    funding = DmintMinerFundingUtxo(txid="ff" * 32, vout=0, value=_FUNDING_VALUE, script=p2pkh)
    # Must succeed: opcode-stream-aware walker correctly identifies the
    # 0xd0-0xd8 bytes as PUSH(20) payload, not as opcodes.
    result = self._mint(utxo, funding_utxo=funding)
    assert isinstance(result, DmintMintResult)
```

Companion tests:
- [`test_p2sh_funding_utxo_is_accepted`](../../tests/test_dmint_v1_mint.py#L521) — same
  defense for P2SH funding scripts.
- [`test_truncated_pushdata_funding_is_rejected`](../../tests/test_dmint_v1_mint.py#L538) —
  malformed PUSHDATA1 with declared length > remaining bytes correctly refused.

## Prevention

### The rule

**Bare-byte scans cannot classify Bitcoin script. Every script-classification
check must walk the opcode stream and skip push payloads.**

This is fundamental to Bitcoin's script format, not a pyrxd quirk.
Byte 0xD2 is simultaneously OP_DISALLOWPUSHINPUTREF as an opcode AND a
perfectly valid byte inside push-data payload. Without parsing, you
cannot tell which is which.

### The canonical walker pattern

```python
pos = 0
while pos < len(script):
    op = script[pos]
    if 0x01 <= op <= 0x4B:
        # PUSH N — skip N bytes of payload (NOT opcodes)
        pos += 1 + op
    elif op == 0x4C:  # PUSHDATA1
        length = script[pos + 1]
        pos += 2 + length
    elif op == 0x4D:  # PUSHDATA2
        length = int.from_bytes(script[pos+1:pos+3], "little")
        pos += 3 + length
    elif op == 0x4E:  # PUSHDATA4
        length = int.from_bytes(script[pos+1:pos+5], "little")
        pos += 5 + length
    else:
        # Real opcode — apply your classification rule here
        pos += 1
```

Reference implementation: [src/pyrxd/glyph/dmint.py:1513](../../src/pyrxd/glyph/dmint.py#L1513).

### The deny-list trade-off general lesson

- "Safer to reject" is **only safer if your classifier is correct.**
- A misclassifying deny-list converts the DoS you're defending against
  into a different DoS (rejecting legitimate users).
- **Always quantify the false-positive rate before shipping.** Even a
  back-of-envelope estimate ("51% of random P2PKH") would have caught
  this in design review.
- For high-stakes denials (rejecting a UTXO that someone paid for),
  consider allow-list-by-shape instead of deny-list-by-substring.

### Adversarial test construction

The author-written unit tests for the deny-list passed because the
test author and implementation author shared the same flawed mental
model: "0xD0–0xD8 is what we're looking for, so test scripts that put
those bytes at the front."

The red-team review surfaced the bug by **deliberately constructing
adversarial inputs**: P2PKH where every byte of the payload was in the
deny range. That fixture is now baked into the test suite as
`test_p2pkh_with_d_byte_in_hash_is_accepted`.

**Rule**: when writing a deny-list classifier, deliberately construct
fixtures from the *allow* category that contain bytes from the *deny*
category in payload position. If the classifier rejects them, the
classifier is broken.

### Audit of existing pyrxd classifiers

Verified these are NOT vulnerable to this anti-pattern:

| Classifier | Implementation | Safe? |
|---|---|---|
| `is_ft_script` ([script.py:204](../../src/pyrxd/glyph/script.py#L204)) | `FT_SCRIPT_RE.fullmatch(script_hex.lower())` — regex `fullmatch` against the exact 75-byte FT shape | ✅ Yes — fullmatch on shape, not byte-substring |
| `is_dmint_contract_script` ([script.py:224](../../src/pyrxd/glyph/script.py#L224)) | Wraps `DmintState.from_script` — a typed parser that walks the state-script layout | ✅ Yes — full parser |
| `extract_ref_from_ft_script` ([script.py:265](../../src/pyrxd/glyph/script.py#L265)) | Extracts a 36-byte ref from offsets in a 75-byte FT script after `is_ft_script` returns True | ✅ Yes — gated by fullmatch |

No existing classifier in `pyrxd/glyph/` uses the bare-byte-scan
anti-pattern. Future classifiers must follow suit.

### Where this could regress

- Any future Glyph script classifier
- Any future Gravity covenant classifier
- Any future "is this UTXO safe to spend as fee" check (token-burn defense beyond dMint)

Add the canonical walker pattern to the next such function from day
one. Don't reinvent it as a byte-scan.

## References

- Buggy commit: `a3ee46e fix(glyph): correct V1 dMint mint-tx shape + harden deploy guard + token-burn defense`
- Fix commit: `1a8d712 fix(glyph): opcode-aware funding scan + OP_RETURN msg marker + V2 default regression test`
- Sibling incident: [`dmint-v1-mint-shape-mismatch.md`](dmint-v1-mint-shape-mismatch.md) — same review session, different lesson
- Plan: [`docs/plans/2026-05-07-feat-dmint-v1-mint-and-reference-miner-plan.md`](../../plans/2026-05-07-feat-dmint-v1-mint-and-reference-miner-plan.md)
