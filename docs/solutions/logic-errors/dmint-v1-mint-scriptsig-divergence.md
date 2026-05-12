---
title: V1 dMint mint scriptSig pushed preimage halves instead of script hashes — silent covenant divergence
problem_type: logic_error
component: pyrxd.glyph.dmint (V1 mint scriptSig builder + PoW preimage)
symptoms:
  - Python miner finds a "valid" nonce; broadcast fails with `mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation)`
  - ElectrumX surfaces the rejection as `code 1` and pyrxd reclassifies it as `NetworkError` ("ElectrumX connection lost"), masking the real cause
  - Every signed V1 mint tx pyrxd produced was rejected by the covenant — M1's V1 mint feature had never successfully spent a contract
  - Synthetic round-trip tests (`build_mint_scriptsig` ↔ `verify_sha256d_solution`) all passed
severity: critical
date_solved: 2026-05-11
prs: [feat/dmint-v1-deploy commit fixing build_pow_preimage / PowPreimageResult / build_mint_scriptsig]
tags: [dmint, v1, mint, scriptsig, covenant, mainnet, recurring-pattern, silent-divergence]
related_files:
  - src/pyrxd/glyph/dmint.py
  - tests/test_dmint_v1_mint.py
  - docs/dmint-research-mainnet.md
related_solutions:
  - docs/solutions/logic-errors/dmint-v1-mint-shape-mismatch.md
  - docs/solutions/logic-errors/dmint-v1-classifier-gap.md
---

## Symptom

Running `examples/dmint_claim_demo.py` with `DRY_RUN=0` against any
unspent V1 dMint contract: the local miner finds a nonce that satisfies
pyrxd's own `verify_sha256d_solution`, the tx signs cleanly, broadcast
returns:

```
mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation) (code 16)
```

The error was masked twice: ElectrumX wraps the policy rejection as
JSON-RPC `code 1`, and pyrxd's ElectrumX client classifies that as a
generic `NetworkError`. The demo reprinted it as `"BROADCAST FAILED:
ElectrumX connection lost"`. The actual cause was a **transaction-level
script-verify failure**, not network loss.

## Root Cause

The V1 covenant's PoW preimage (epilogue offsets 99–115, decoded in
`docs/dmint-research-mainnet.md` §3.5) is built from values pushed onto
the scriptSig:

```
PoW_preimage = H1 || H2 || nonce
  H1 = SHA256(OP_OUTPOINTTXHASH || contractRef_from_state)
  H2 = SHA256(scriptSig_inputHash || scriptSig_outputHash)
```

The on-chain canonical mint at `146a4d68…f3c` confirms the push
convention:

- `scriptSig_inputHash`  = `SHA256d(funding_input_locking_script)`
- `scriptSig_outputHash` = `SHA256d(vout[2]_OP_RETURN_locking_script)`

Both pushes are **the double-SHA256 of the corresponding script bytes**.

`pyrxd.glyph.dmint.build_pow_preimage` correctly computed the 64-byte
preimage. But `build_mint_scriptsig` then pushed the **two halves of
that preimage** as the scriptSig inputHash/outputHash:

```python
return (
    bytes([nonce_width]) + nonce
    + b"\x20" + preimage[:32]    # pushed H1, NOT SHA256d(input_script)
    + b"\x20" + preimage[32:]    # pushed H2, NOT SHA256d(output_script)
    + b"\x00"
)
```

The covenant then computed:

```
H2_covenant = SHA256(H1_push || H2_push)
            = SHA256(pyrxd_preimage)        # 64 bytes hashed
```

…which is not equal to pyrxd's `preimage[32..64]`. The actual preimage
the covenant hashed was `H1 || SHA256(pyrxd_preimage) || nonce`, while
pyrxd was searching for a nonce that satisfied `H1 || H2 || nonce`.
Pyrxd-valid nonces were systematically covenant-invalid.

## How It Went Undetected

Same root failure mode as
[`dmint-v1-mint-shape-mismatch.md`](dmint-v1-mint-shape-mismatch.md):

1. **The builder and verifier were tested against each other, not against
   chain truth.** `build_mint_scriptsig`, `build_pow_preimage`, and
   `verify_sha256d_solution` are self-consistent under the buggy mapping.
   Every round-trip test passed.
2. **No end-to-end broadcast test.** The pre-M2 V1 contracts on mainnet
   (RBG-class) were already drained or otherwise unminable in the M1
   review window; nobody attempted a live mine + broadcast.
3. **The chain helpers worked.** `find_dmint_contract_utxos` and the mint
   demo ran cleanly end-to-end *except for the rejected broadcast*, which
   the NetworkError reclassification hid.

This is the **second** instance in pyrxd's dMint history of synthetic
self-consistent tests masking a chain divergence. See the
"Recurring Pattern" section below.

## Working Solution

The scriptSig builder no longer derives pushes from the preimage. Both
the preimage and the scriptSig are computed from the raw scripts, with
the caller passing the script hashes explicitly:

```python
@dataclass(frozen=True)
class PowPreimageResult:
    preimage: bytes              # 64 bytes: H1 || H2
    input_script_hash: bytes     # SHA256d(funding_input_locking_script)
    output_script_hash: bytes    # SHA256d(vout[2]_OP_RETURN_locking_script)

def build_pow_preimage(
    txid_le: bytes,
    contract_ref_bytes: bytes,
    input_script: bytes,
    output_script: bytes,
) -> PowPreimageResult:
    H1 = sha256(txid_le + contract_ref_bytes)
    input_hash  = sha256d(input_script)
    output_hash = sha256d(output_script)
    H2 = sha256(input_hash + output_hash)
    return PowPreimageResult(H1 + H2, input_hash, output_hash)

def build_mint_scriptsig(
    nonce: bytes,
    input_script_hash: bytes,    # raw SHA256d(input_script)
    output_script_hash: bytes,   # raw SHA256d(output_script)
    *,
    nonce_width: int,
) -> bytes:
    return (
        bytes([nonce_width]) + nonce
        + b"\x20" + input_script_hash
        + b"\x20" + output_script_hash
        + b"\x00"
    )
```

The mint-tx assembler now threads `PowPreimageResult.input_script_hash`
/ `.output_script_hash` directly into `build_mint_scriptsig`. The
preimage is never used as a source of scriptSig push values.

## Prevention Strategies

### Golden-vector tests against real mainnet bytes (extended)

The
[`test_byte_equal_to_mainnet_vout1`](../../tests/test_dmint_v1_mint.py)
pattern from the prior incident is necessary but not sufficient: it
verified output shape, not scriptSig content. Add a parallel suite:

- **`TestCovenantShape`** — golden vectors for every chain-visible field
  the covenant inspects: scriptSig push layout, PoW preimage bytes for a
  known mainnet nonce, and the 64-byte preimage halves recomputed from
  the on-chain `inputHash` / `outputHash` pushes.
- **Each test cites a real txid + vin/vout index** and asserts byte-
  equality against captured chain data — not against pyrxd-generated
  fixtures.

### testmempoolaccept gate before merge

Any change to the V1 mint path must pass a `radiant-cli
testmempoolaccept` (or regtest broadcast) against a real or replayed
contract UTXO before the PR can merge. Self-consistent synthetic mining
is not acceptance.

### Don't reclassify policy rejections as network errors

`pyrxd`'s ElectrumX client must distinguish `code 1` (`message` contains
`script-verify` / `mandatory-`) from a connection drop. A
`PolicyRejection` exception type that carries the raw `bitcoind` message
would have surfaced this on the first broadcast attempt.

## The Recurring Pattern

This is the **second** time the same anti-pattern has shipped:

| Incident | What was wrong | Why tests missed it |
|---|---|---|
| [shape-mismatch](dmint-v1-mint-shape-mismatch.md) (2026-05-08) | V1 mint output count / reward script shape diverged from mainnet | Round-trip `parser(builder(x)) == x` through pyrxd's own parser |
| This incident (2026-05-11) | V1 mint scriptSig pushes diverged from what the covenant hashes | Round-trip `verify(build_preimage(build_scriptsig(x))) == ok` through pyrxd's own verifier |

Both follow the same form: **builder + verifier authored together, tested
against each other, no external ground truth.** Both bugs are invisible
to any test that consumes only pyrxd-produced bytes.

Treat this as the load-bearing rule of the dMint codebase: **a green
test suite that never compares to chain bytes is a green test suite that
hasn't been tested.** Every wire-format builder needs (a) a golden-vector
test against captured mainnet bytes, and (b) a testmempoolaccept gate
against a real or replayed UTXO.

## Mainnet Verification Evidence

Fix was validated by a live mainnet mint after merge:

- **txid:** `c9fdcd3488f3e396bec3ce0b766bb8070963e7e75bb513b8820b6663e469e530`
- **network:** Radiant mainnet
- **date:** 2026-05-11

Verify independently:

```bash
radiant-cli getrawtransaction \
  c9fdcd3488f3e396bec3ce0b766bb8070963e7e75bb513b8820b6663e469e530 1
```

The accepted scriptSig pushes match the on-chain `146a4d68…f3c`
convention: 32-byte `SHA256d(funding_input_script)` and 32-byte
`SHA256d(vout[2]_op_return_script)`, not preimage halves.

## References

- Prior incident: [`dmint-v1-mint-shape-mismatch.md`](dmint-v1-mint-shape-mismatch.md)
- Classifier-gap predecessor: [`dmint-v1-classifier-gap.md`](dmint-v1-classifier-gap.md)
- Mainnet trace: [`docs/dmint-research-mainnet.md`](../../dmint-research-mainnet.md) §3.5
- Validation txid: `c9fdcd3488f3e396bec3ce0b766bb8070963e7e75bb513b8820b6663e469e530`
