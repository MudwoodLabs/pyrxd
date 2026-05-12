# How to migrate from pyrxd 0.4.x to 0.5.0

**Who this page is for:** anyone who imports `build_pow_preimage`,
`build_mint_scriptsig`, or `build_dmint_v1_mint_preimage` from
`pyrxd.glyph.dmint`. If you only use the CLI, the higher-level
`GlyphBuilder` API, or the inspect tool, 0.5.0 is a drop-in upgrade and
you can stop reading here.

0.5.0 makes three signature changes to the V1 dMint mint path. They
are deliberately **hard breaks with loud errors** — no deprecation
shim, no compatibility wrapper — because the 0.4.x signatures could
silently produce on-chain-rejected transactions. The fix is documented
in [`docs/solutions/logic-errors/dmint-v1-mint-scriptsig-divergence.md`](../solutions/logic-errors/dmint-v1-mint-scriptsig-divergence.md);
this page is the user-facing migration table.

The new path is validated against two independent mainnet golden
vectors: the snk-token mint at
`146a4d688ba3fc1ea9588e406cc6104be2c9321738ea093d6db8e1b83581af3c`
(Photonic's reference) and pyrxd's own first successful mint at
`c9fdcd3488f3e396bec3ce0b766bb8070963e7e75bb513b8820b6663e469e530`
(2026-05-11, the fix verification).

---

## TL;DR — the three changes

| #   | Symbol                          | Before (0.4.x)                                       | After (0.5.0)                                                    |
| --- | ------------------------------- | ---------------------------------------------------- | ---------------------------------------------------------------- |
| 1   | `build_pow_preimage`            | returns `bytes` (64-byte preimage)                   | returns `PowPreimageResult(preimage, input_hash, output_hash)`   |
| 2   | `build_mint_scriptsig`          | `(nonce, preimage, *, nonce_width)`                  | `(nonce, input_hash, output_hash, *, nonce_width=8)`             |
| 3   | `build_dmint_v1_mint_preimage`  | returns `bytes`                                      | returns `PowPreimageResult`                                      |

The new `PowPreimageResult` is a frozen dataclass exported from
`pyrxd.glyph`. Calling any of the three with the old positional
arguments raises `TypeError` or `ValidationError` immediately — there
is no path where old-style code silently produces wrong bytes.

---

## Why the break

The V1 dMint covenant inspects two values pushed onto the mint
scriptSig: a 32-byte `inputHash` and a 32-byte `outputHash`. Each must
equal `SHA256d` of the corresponding script bytes (the funding-input
locking script and the `vout[2]` `OP_RETURN` script). The covenant
recomputes `SHA256(inputHash || outputHash)` on-chain and folds the
result into the PoW hash the miner solved.

In 0.4.x, `build_mint_scriptsig` accepted the 64-byte PoW preimage and
pushed its two 32-byte halves as `inputHash` and `outputHash`. But the
preimage's second half is already `SHA256(SHA256d(input_script) ||
SHA256d(output_script))` — not the raw script hashes the covenant
expects. The two builders were self-consistent (round-trip tests
passed), but every signed mint tx pyrxd produced was rejected by the
covenant with `mandatory-script-verify-flag-failed (code 16)`. The
rejection was further masked by pyrxd's ElectrumX client
reclassifying it as a generic `NetworkError`.

0.5.0 forces the two scriptSig pushes and the preimage to come from a
single helper call, with the script hashes returned alongside the
preimage. Splitting the sources is no longer possible at the type
level.

---

## Migration walkthrough

### 1. `build_pow_preimage` — new return type

**0.4.x:**

```python
from pyrxd.glyph.dmint import build_pow_preimage

preimage = build_pow_preimage(
    txid_le=txid_le,
    contract_ref_bytes=contract_ref,
    input_script=funding_locking_script,
    output_script=op_return_script,
)
# preimage: bytes (64 bytes)
```

**0.5.0:**

```python
from pyrxd.glyph.dmint import build_pow_preimage

result = build_pow_preimage(
    txid_le=txid_le,
    contract_ref_bytes=contract_ref,
    input_script=funding_locking_script,
    output_script=op_return_script,
)
# result: PowPreimageResult
# result.preimage:    bytes (64) — feed to mine_solution
# result.input_hash:  bytes (32) — push as scriptSig inputHash
# result.output_hash: bytes (32) — push as scriptSig outputHash
```

If you only need the preimage bytes (e.g. you compute the script
hashes elsewhere — which you almost certainly shouldn't, see "Why the
break" above), read `result.preimage`. The dataclass is frozen, so
`result.preimage` is the original `bytes` object — no copy cost.

### 2. `build_mint_scriptsig` — new signature

**0.4.x:**

```python
from pyrxd.glyph.dmint import build_mint_scriptsig

scriptsig = build_mint_scriptsig(
    nonce,          # 4 bytes for V1, 8 for V2
    preimage,       # 64-byte PoW preimage
    nonce_width=4,  # 4 → V1, 8 → V2
)
```

**0.5.0:**

```python
from pyrxd.glyph.dmint import build_mint_scriptsig

scriptsig = build_mint_scriptsig(
    nonce,                  # 4 bytes for V1, 8 for V2
    result.input_hash,      # from build_pow_preimage above
    result.output_hash,     # from build_pow_preimage above
    nonce_width=4,          # 4 → V1, 8 → V2 (default 8)
)
```

The two hashes **must** come from the same `build_pow_preimage` call
that produced the preimage the miner solved. Splitting the sources
across separate `sha256d(...)` calls is what produced the M1
covenant-rejection bug — feeding a `PowPreimageResult` through is the
only safe pattern.

`nonce_width` is keyword-only and typed `Literal[4, 8]`. A stray
positional value (e.g. `build_mint_scriptsig(nonce, h1, h2, 4)`)
raises a type error rather than silently confusing V1 and V2.

### 3. `build_dmint_v1_mint_preimage` — new return type

The V1-specific helper that builds the preimage directly from a
contract UTXO, funding UTXO, and unsigned tx (validating the
4-output mainnet-canonical shape) follows the same pattern.

**0.4.x:**

```python
from pyrxd.glyph.dmint import build_dmint_v1_mint_preimage

preimage = build_dmint_v1_mint_preimage(contract_utxo, funding_utxo, unsigned_tx)
# preimage: bytes (64 bytes)

# ... mine ...

scriptsig = build_mint_scriptsig(nonce, preimage, nonce_width=4)
```

**0.5.0:**

```python
from pyrxd.glyph.dmint import build_dmint_v1_mint_preimage

pow_result = build_dmint_v1_mint_preimage(contract_utxo, funding_utxo, unsigned_tx)
# pow_result: PowPreimageResult

# ... mine using pow_result.preimage ...

scriptsig = build_mint_scriptsig(
    nonce,
    pow_result.input_hash,
    pow_result.output_hash,
    nonce_width=4,
)
```

This is the canonical V1 mint path; `examples/dmint_claim_demo.py` is
the runnable reference.

---

## End-to-end V1 mint snippet (0.5.0)

The full mint loop, transcribed from
[`examples/dmint_claim_demo.py`](https://github.com/MudwoodLabs/pyrxd/tree/main/examples/dmint_claim_demo.py):

```python
from pyrxd.glyph.dmint import (
    build_dmint_v1_mint_preimage,
    build_mint_scriptsig,
    mine_solution,
)
from pyrxd.glyph.dmint import build_dmint_mint_tx  # builds the 4-output unsigned tx

# 1. Build the unsigned 4-output mint tx (vout[2] MUST be an OP_RETURN msg).
unsigned = build_dmint_mint_tx(
    contract_utxo=contract_utxo,
    funding_utxo=funding_utxo,
    op_return_msg=b"pyrxd mint",
    # ... other args ...
)

# 2. Compute the preimage + the two script hashes from the unsigned tx.
pow_result = build_dmint_v1_mint_preimage(contract_utxo, funding_utxo, unsigned)

# 3. Mine. `pow_result.preimage` is the 64-byte input to SHA256d.
#    mine_solution returns a DmintMineResult; unwrap .nonce.
mine_result = mine_solution(
    preimage=pow_result.preimage,
    target=contract_utxo.state.target,
    nonce_width=4,
)

# 4. Build the scriptSig — pushes MUST come from pow_result, not recomputed.
scriptsig = build_mint_scriptsig(
    mine_result.nonce,
    pow_result.input_hash,
    pow_result.output_hash,
    nonce_width=4,
)

# 5. Attach the scriptSig to vin[0], sign vin[1] (the funding input), broadcast.
```

---

## What happens if you don't migrate

Old-style calls produce a `TypeError` or `pyrxd.errors.ValidationError`
immediately at the call site. Neither error is silenced or downgraded,
and neither requires a broadcast to surface — pyrxd does not ship a
shim that would let 0.4.x code silently produce wrong bytes.

If you have a forked or vendored miner that wraps the 0.4.x signature,
the migration is mechanical:

1. Replace `preimage = build_pow_preimage(...)` with `result = build_pow_preimage(...)`.
2. Pass `result.preimage` everywhere you previously passed `preimage`.
3. Replace `build_mint_scriptsig(nonce, preimage, nonce_width=...)` with
   `build_mint_scriptsig(nonce, result.input_hash, result.output_hash, nonce_width=...)`.

There are no other public-API breaks in 0.5.0. The deploy-side
`prepare_dmint_deploy_v1` (and its `DmintV1DeployParams` /
`DmintV1DeployResult` types) are new additions — see
[V1 dMint deploys](../concepts/dmint-v1-deploy.md) for the deploy-side
concept page.

---

## References

- [CHANGELOG entry for 0.5.0](https://github.com/MudwoodLabs/pyrxd/blob/main/CHANGELOG.md)
- [V1 dMint deploys concept page](../concepts/dmint-v1-deploy.md)
- [Runnable V1 mint demo: `examples/dmint_claim_demo.py`](https://github.com/MudwoodLabs/pyrxd/tree/main/examples/dmint_claim_demo.py)
- [Mainnet golden-vector tests: `tests/test_dmint_v1_mint.py`](https://github.com/MudwoodLabs/pyrxd/tree/main/tests/test_dmint_v1_mint.py)
- Fix verification txid: `c9fdcd3488f3e396bec3ce0b766bb8070963e7e75bb513b8820b6663e469e530`
- Photonic reference txid: `146a4d688ba3fc1ea9588e406cc6104be2c9321738ea093d6db8e1b83581af3c`
