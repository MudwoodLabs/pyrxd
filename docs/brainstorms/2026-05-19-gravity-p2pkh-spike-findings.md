---
title: Gravity P2PKH support — current state is better than the docs claim
date: 2026-05-19
status: brainstorm
---

# Gravity P2PKH support — what's actually there

## TL;DR

A spike investigation into adding P2PKH support to Gravity found that
**the shipping sentinel covenant already handles all four Bitcoin
output types** (P2PKH, P2WPKH, P2SH, P2TR) via a `btcReceiveType`
parameter and an in-script four-way dispatch. The docs claim
P2PKH / P2SH / P2TR are unsupported; that claim is stale.

What's actually missing is end-to-end integration test coverage for
the three non-P2WPKH paths, plus a documentation update.

This is not a multi-week covenant compilation effort. It is a
~1-2 week test + doc update.

## What the docs say

[docs/concepts/gravity.md:117-122](../concepts/gravity.md#L117) shows:

| Output type | Address prefix | Status |
|---|---|---|
| **P2WPKH** (native segwit) | `bc1q...` | ✅ shipped |
| **P2PKH** (legacy) | `1...` | ❌ no covenant compiled yet |
| **P2SH** (wrapped segwit) | `3...` | ❌ no covenant compiled yet |
| **P2TR** (taproot) | `bc1p...` | ❌ no covenant compiled yet |

And shortly after:

> only `p2wpkh` has a deployable covenant in the artifacts directory

Both statements are stale.

## What the code actually does

### Discovery 1: the sentinel covenant dispatches on `btcReceiveType`

The shipping artifact
`src/pyrxd/gravity/artifacts/maker_covenant_flat_12x20_sentinel_all.artifact.json`
contains a four-way `OP_IF`/`OP_ELSE` chain in its asm:

```
$btcReceiveType OP_0 OP_NUMEQUAL OP_IF ... 88ac OP_EQUALVERIFY ... # P2PKH (type 0)
OP_ELSE $btcReceiveType OP_1 OP_NUMEQUAL OP_IF ... # P2WPKH (type 1)
OP_ELSE $btcReceiveType OP_2 OP_NUMEQUAL OP_IF ... # P2SH (type 2)
OP_ELSE $btcReceiveType OP_3 OP_NUMEQUALVERIFY ... # P2TR (type 3)
```

All four output-script prefix/suffix patterns are embedded literally
in the script (`76a914...88ac`, `0014`, `a914...87`, `5120`). The
covenant compares the BTC tx's output script bytes against the
type-specific expected pattern, with the hash provided as
`$btcReceiveHash` and the type provided as `$btcReceiveType`.

### Discovery 2: the Python factory routes the type parameter

[src/pyrxd/gravity/covenant.py:408-424](../../src/pyrxd/gravity/covenant.py#L408)
already maps `btc_receive_type` strings to integer constants and
substitutes them into the covenant template:

```python
_VALID_BTC_RECEIVE_TYPES = {"p2pkh": 0, "p2wpkh": 1, "p2sh": 2, "p2tr": 3}
...
flat_extras = {
    ...
    "btcReceiveType": _btc_type_int,
}
for name, value in flat_extras.items():
    if name in ctor_param_names:
        claimed_params[name] = value
```

`btc_receive_type='p2pkh'` substitutes type integer 0 into the
template. The resulting covenant compiles and produces a valid offer.

### Discovery 3: a passing unit test confirms all four types build

[tests/test_gravity.py:189](../../tests/test_gravity.py#L189) ships
`TestGravityOffer::test_all_btc_receive_types_accepted`:

```python
def test_all_btc_receive_types_accepted(self):
    for rt in ("p2pkh", "p2wpkh", "p2sh", "p2tr"):
        hash_len = 32 if rt == "p2tr" else 20
        offer = _make_gravity_offer(
            btc_receive_type=rt,
            btc_receive_hash=b"\x00" * hash_len,
        )
        assert offer.btc_receive_type == rt
```

Run today (2026-05-19):

```
tests/test_gravity.py::TestGravityOffer::test_all_btc_receive_types_accepted PASSED
```

### Discovery 4: the SPV verifier handles all four types

[src/pyrxd/spv/payment.py:18-40](../../src/pyrxd/spv/payment.py#L18)
ships `P2PKH`, `P2WPKH`, `P2SH`, `P2TR` as named constants with
their respective script-length and prefix/suffix patterns:

```python
_SCRIPT_PATTERNS = {
    P2PKH:  (b"\x76\xa9\x14", b"\x88\xac"),  # 3 + 20 + 2
    P2WPKH: (b"\x00\x14", b""),              # 2 + 20
    P2SH:   (b"\xa9\x14", b"\x87"),          # 2 + 20 + 1
    P2TR:   (b"\x51\x20", b""),              # 2 + 32
}
```

[tests/test_spv.py:470](../../tests/test_spv.py#L470)
`test_valid_p2pkh_output_accepted` exercises P2PKH payment
verification with a synthetic P2PKH output; the test passes.

## Why the docs are stale

Best guess: the gravity.md table was written relative to the *earlier*
covenant variants (the experimental `_p2wpkh`-suffixed family — see
the artifacts directory). Those were single-type. The current
sentinel-all covenant unified the dispatch, but the docs weren't
updated to reflect that consolidation.

The `_p2wpkh` suffix on those older artifacts is a historical naming
artifact, not an indication that the shipping `flat_12x20_sentinel_all`
is single-type.

## What's actually missing

A four-by-four matrix of "is this layer exercised end-to-end?":

| Layer | P2WPKH | P2PKH | P2SH | P2TR |
|---|---|---|---|---|
| Covenant artifact (substitute params) | ✅ tested | ✅ builds | ✅ builds | ✅ builds |
| Covenant validation (deny-list check) | ✅ | ✅ | ✅ | ✅ |
| SPV verifier (script parser) | ✅ tested | ✅ tested | ✅ tested | ✅ tested |
| Maker offer build | ✅ tested | ✅ tested | ✅ tested | ✅ tested |
| Maker fund-tx broadcast | ✅ mainnet | ⚠️ untested | ⚠️ untested | ⚠️ untested |
| Taker BTC payment + SPV proof | ✅ mainnet | ⚠️ untested | ⚠️ untested | ⚠️ untested |
| Finalize tx on Radiant | ✅ mainnet | ⚠️ untested | ⚠️ untested | ⚠️ untested |
| End-to-end test with recorded BTC blocks | ✅ | ❌ | ❌ | ❌ |
| Documentation in gravity.md | ✅ | ❌ wrong | ❌ wrong | ❌ wrong |

The gap is **end-to-end integration testing** and **documentation
update**. The on-chain mainnet validation for P2WPKH demonstrates the
covenant works correctly on the network; the same path should work for
the other three types, but it has never been *demonstrated* end-to-end
with recorded BTC blocks containing the relevant payment shape.

## Suggested next work

1. **Update `docs/concepts/gravity.md`** — fix the Axis 2 table and
   the "only p2wpkh has a deployable covenant" sentence to reflect
   that `flat_12x20_sentinel_all` supports all four types via the
   `btcReceiveType` parameter, and that what's missing is end-to-end
   test coverage for the three non-P2WPKH paths.
2. **Add an end-to-end P2PKH integration test** — use a recorded BTC
   block containing a P2PKH payment and exercise the full Maker-locks
   → Taker-pays → finalize flow against the covenant. Reuses the
   existing P2WPKH integration test pattern. Estimated ~150-300 LOC
   of test code.
3. **Mark P2PKH as `experimental` in any user-facing status** — not
   "production-ready" until the end-to-end test exists and a small
   mainnet exercise demonstrates the covenant accepts real P2PKH
   payments.
4. **Repeat for P2SH and P2TR** in subsequent work, in priority order
   based on actual demand. P2SH is likely the next-most-valuable
   because wrapped-segwit addresses are still common in older
   wallets; P2TR is the future-facing case.

## A diagnostic note

The "diagnose before patching" rule applied here:

- **Symptom** the docs reported: "P2PKH not supported in Gravity."
- **Assumed mechanism** (from gravity.md): "need to compile a separate
  P2PKH covenant variant."
- **Actual mechanism**: the covenant already supports all four types;
  what's missing is test coverage + a doc update.

The original framing — "compile a new variant" — would have been ~4-5
weeks of unnecessary work duplicating something the sentinel covenant
already does. Spike-testing before committing to the framing caught
this. The pattern generalizes: when a doc claims a capability is
missing and the work to add it looks substantial, check the *current*
code state before estimating effort against the doc.
