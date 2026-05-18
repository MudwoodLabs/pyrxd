# V1 dMint mint mechanics: claiming a contract UTXO

**Why this page exists:**
[V1 dMint deploys](dmint-v1-deploy.md) describes how a single reveal
transaction creates N parallel singleton contract UTXOs. That's the
*supply* side. This page covers the *claim* side: how a miner spends
one of those contract UTXOs to mint a reward — the canonical 4-output
transaction shape, the 72-byte scriptSig push convention, the 64-byte
PoW preimage layout, and the FT-conservation covenant check the V1
script enforces on the reward output.

If you want the incident background — the M1 bug where pyrxd's
scriptSig pushes diverged from the preimage and every signed mint was
silently rejected by the covenant — read
[`dmint-v1-mint-scriptsig-divergence.md`](../solutions/logic-errors/dmint-v1-mint-scriptsig-divergence.md).
This page is the protocol explainer; that page is the post-mortem.

---

## TL;DR

A V1 dMint mint is a **two-input, four-output transaction**. The
contract input is spent by a 72-byte scriptSig carrying a 4-byte
nonce and two 32-byte hashes. The script hashes are
`SHA256d(funding_input_locking_script)` and
`SHA256d(vout[2]_OP_RETURN_script)`, **not** the halves of the PoW
preimage — the covenant recomputes
`SHA256(input_hash || output_hash)` from those exact bytes and folds
the result into the PoW check. Diverging the scriptSig pushes from
the preimage is the recurring failure mode the M1 incident surfaced.

V1 vs V2 differs only in nonce width: V1 uses a 4-byte nonce
(`nonce_width=4`, 72-byte scriptSig), V2 uses 8 bytes (76-byte
scriptSig). The byte layout, FT-conservation check, and 4-output
shape are otherwise identical-by-construction in pyrxd's builder.
**No V2 dMint contracts exist on chain**, so V2 mint mechanics are
not field-verified — V1 is the only path with mainnet golden vectors
pinning it.

---

## Mainnet anchors

Two independent mints serve as the byte-equality witnesses pyrxd's
test suite pins against:

| Anchor                          | Txid                                                               | Notes                                                                 |
|---------------------------------|--------------------------------------------------------------------|-----------------------------------------------------------------------|
| snk (Photonic reference mint)   | `146a4d688ba3fc1ea9588e406cc6104be2c9321738ea093d6db8e1b83581af3c` | Canonical reference for the 72-byte scriptSig convention.             |
| pyrxd's first PXD mint          | `c9fdcd3488f3e396bec3ce0b766bb8070963e7e75bb513b8820b6663e469e530` | First successful mint after the M1 scriptSig-divergence fix (2026-05-11). |

Both are pinned in
[`tests/test_dmint_v1_mint.py`](../../tests/test_dmint_v1_mint.py)'s
`TestCovenantShape` suite — byte-equal assertions against captured
mainnet bytes, not against pyrxd-generated fixtures. The suite is
the load-bearing regression guard for the scriptSig + preimage
contract.

---

## The 4-output mint transaction shape

V1 mints have **two inputs** and a **four-output canonical shape**:

| vin / vout | bytes (approx) | role                                                                                  |
|-----------:|---------------:|---------------------------------------------------------------------------------------|
| vin[0]     |             72 | The contract UTXO being spent; unlocked by the V1 mint scriptSig (see next section).  |
| vin[1]     |          ~106  | Plain-RXD P2PKH funding input — pays the FT reward photons + tx fee.                  |
| vout[0]    |            241 | The re-created contract UTXO at `height+1`. Same 241-byte layout as the input, with the `height` field bumped. Singleton value preserved (typically 1 photon). |
| vout[1]    |             75 | FT-wrapped reward output, value = `state.reward` photons. Same 75-byte FT shape covered in [Radiant FTs are on-chain](radiant-fts-are-on-chain.md); embeds the miner's `pkh` and the contract's `tokenRef`. |
| vout[2]    |        variable | OP_RETURN message output. The covenant binds `outputHash` to `SHA256d(this script's bytes)`. The miner picks any message; the contract requires the output to exist with the chosen bytes. |
| vout[3]    |             25 | P2PKH change to the miner — `funding − reward − fee`.                                 |

The contract input value is **preserved across mints**. V1 contracts
are singletons (the on-chain reference deploys all use 1-photon
contract outputs), not a value pool — the reward photons come from
the funding input, not from the contract UTXO. See
[`_build_dmint_v1_mint_tx`](../../src/pyrxd/glyph/dmint.py) for the
builder's output assembly.

The 241-byte recreated contract layout (state + epilogue) is the same
shape covered in
[V1 dMint deploys](dmint-v1-deploy.md) under "Reveal tx output
shape"; only the 4-byte height field at the start of the state
changes between mints.

### vout[2] is canonical, not optional

pyrxd's V1 mint builder will produce a 3-output transaction (no
OP_RETURN) if `op_return_msg` is `None`. But the V1 preimage helper
[`build_dmint_v1_mint_preimage`](../../src/pyrxd/glyph/dmint.py)
**requires** `unsigned_tx.outputs[2]` to exist and to be an OP_RETURN
script (starts with `0x6a`). The covenant binds `outputHash` to that
specific position; building a 3-output mint produces a preimage with
nothing to anchor `outputHash` to, and a hand-rolled 4-output tx
with a non-OP_RETURN at vout[2] would silently bind the preimage to
the wrong bytes (covenant rejection after a successful mine).

In other words: the canonical V1 mint is the 4-output shape. The
3-output path exists in the builder API but is not the mainnet
convention and will not produce a mineable preimage through pyrxd's
public helpers.

---

## The 72-byte scriptSig push convention

The contract input's scriptSig is a fixed byte layout. The 4-byte
nonce variant (V1) totals 72 bytes; the 8-byte variant (V2) totals
76. Layout from
[`build_mint_scriptsig`](../../src/pyrxd/glyph/dmint.py):

```
┌── V1 mint scriptSig (72 bytes) ────────────────────────────────────┐
│ 04 <nonce:4B>        PUSH4 nonce            (5 bytes)              │
│ 20 <inputHash:32B>   PUSH32 inputHash       (33 bytes)             │
│ 20 <outputHash:32B>  PUSH32 outputHash      (33 bytes)             │
│ 00                   OP_0 (push empty)      (1 byte)               │
└────────────────────────────────────────────────────────────────────┘
```

where:

- `inputHash` = `SHA256d(funding_input_locking_script)` — the
  funding input at `vin[1]`, **not** the contract input.
- `outputHash` = `SHA256d(vout[2]_OP_RETURN_script)` — the script
  bytes of the OP_RETURN message output.
- The trailing `OP_0` (`0x00`) is required by the V1 epilogue; it
  pushes an empty item that the script consumes during the unlock
  sequence.

The V2 form is identical except the first byte is `0x08` and the
nonce is 8 bytes (76 bytes total). The single-byte switch
between layouts is why
[`build_mint_scriptsig`](../../src/pyrxd/glyph/dmint.py) takes a
keyword-only `nonce_width: Literal[4, 8]` argument — a stray
positional `4` is a type error rather than a silent V1/V2 confusion.

### The two hashes MUST come from the same source as the preimage

This is the load-bearing rule:

```python
pow_result = build_dmint_v1_mint_preimage(contract_utxo, funding_utxo, unsigned_tx)
# Mine using pow_result.preimage
nonce = mine_solution(pow_result.preimage, target, nonce_width=4)
# Build scriptSig from the SAME PowPreimageResult
scriptsig = build_mint_scriptsig(
    nonce, pow_result.input_hash, pow_result.output_hash, nonce_width=4,
)
```

The scriptSig's `inputHash` / `outputHash` are
[`PowPreimageResult.input_hash`](../../src/pyrxd/glyph/dmint.py) and
`.output_hash` from the same call that produced the preimage the
miner solved. Splitting the sources (recomputing the hashes
separately in two helpers) is exactly the silent-rejection failure
mode the M1 incident surfaced — the covenant computes
`SHA256(scriptSig_inputHash || scriptSig_outputHash)` from the
on-chain scriptSig bytes alone, so any divergence between the bytes
the miner solved and the bytes the scriptSig pushes produces
`mandatory-script-verify-flag-failed` after a successful mine. See
[`dmint-v1-mint-scriptsig-divergence.md`](../solutions/logic-errors/dmint-v1-mint-scriptsig-divergence.md)
for the full chain trace.

---

## The PoW preimage layout

The 64-byte preimage the miner SHA256d's against `target` is:

```
┌── 64-byte SHA256d preimage ───────────────────────────────────────┐
│ H1 = SHA256(txid_LE || contractRef)         (32 bytes)            │
│ H2 = SHA256(inputHash || outputHash)        (32 bytes)            │
└───────────────────────────────────────────────────────────────────┘
              │
              ▼  miner appends nonce, takes SHA256d
              │
              ▼  compares LE-int(result) < target
```

where:

- `txid_LE` = the contract input's outpoint txid, in little-endian
  (internal) byte order (32 bytes).
- `contractRef` = the contract's permanent 36-byte wire ref
  (`txid_LE_reversed || vout_LE_4B`), the same value embedded in
  the 241-byte contract state at deploy time.
- `inputHash` / `outputHash` are the two 32-byte `SHA256d` values
  the scriptSig also pushes (see previous section).

This is the exact layout
[`build_pow_preimage`](../../src/pyrxd/glyph/dmint.py) returns inside
[`PowPreimageResult`](../../src/pyrxd/glyph/dmint.py). The miner
appends the nonce, double-SHA256's the 68 bytes (64 preimage + 4
nonce for V1), and accepts the nonce when the little-endian integer
of the result is less than `target`.

The covenant then performs the same computation on chain: it pulls
`inputHash` and `outputHash` straight from the scriptSig pushes,
recomputes `H2 = SHA256(inputHash || outputHash)`, recomputes `H1`
from the input's outpoint and the contract ref stored in the
contract's state, and verifies the PoW hash. **Diverging the
preimage halves from the scriptSig pushes produces a covenant
rejection after a fully-successful mine** — the M1 failure mode.

The covenant also binds the preimage to:

1. **Which contract slot was claimed** (`H1` includes `contractRef`,
   so a nonce mined for contract A is not valid against contract B
   even within the same deploy's N parallel contracts).
2. **The miner's funding input** (`H2` includes
   `SHA256d(funding_script)`, so a miner cannot substitute a
   different funding source after finding a nonce — the funding
   input is committed to before mining begins).
3. **The OP_RETURN bytes at vout[2]** (`H2` includes
   `SHA256d(op_return_script)`, so the message bytes are committed
   to before mining; swapping them post-mine invalidates the
   preimage).

---

## The FT-conservation check on `vout[1]`

The V1 contract's 145-byte epilogue contains an
`OP_CODESCRIPTHASHVALUESUM_OUTPUTS` check that enforces FT
conservation on the reward. The fingerprint it hashes against is the
12-byte FT-CSH tail `dec0e9aa76e378e4a269e69d` (covered in
[Radiant FTs are on-chain](radiant-fts-are-on-chain.md)).

For the V1 mint, this means **`vout[1]` must be the 75-byte
FT-wrapped shape** (see the "75-byte FT layout" section of
[Radiant FTs are on-chain](radiant-fts-are-on-chain.md)):

```
76 a9 14 <miner_pkh:20> 88 ac    bd d0 <tokenRef:36>   de c0 e9 aa 76 e3 78 e4 a2 69 e6 9d
└── P2PKH (25 B) ──────────┘    └── ref (38 B) ───┘   └── FT-CSH fingerprint (12 B) ─┘
```

with:

- The miner's 20-byte `pkh` in the P2PKH section (so the miner
  controls the reward).
- The contract's `tokenRef` in the 36-byte
  `OP_PUSHINPUTREF`-bound ref section (binds the reward to the
  same FT the contract was deployed for).
- The 12-byte FT-CSH fingerprint that the covenant computes
  `SHA256(script)` against when summing FT-output values.
- The output value (`satoshis` field) exactly equal to
  `state.reward` photons — `1 photon = 1 FT unit` for Radiant FTs.

[`build_dmint_v1_ft_output_script`](../../src/pyrxd/glyph/dmint.py)
builds this exact shape. A plain 25-byte P2PKH at `vout[1]` fails
the covenant: the FT-CSH fingerprint isn't there to match, and the
conservation sum collapses to zero on the output side while the
input still claims the contract's reward.

This is the same shape — and the same builder — pyrxd uses for V2
reward outputs after the 0.5.0 R1 fix
(`build_dmint_v1_ft_output_script` is shared between V1 and V2 via
the `_PART_C` common section). V1 mints had this right since 0.4.0;
V2 was emitting plain P2PKH and would have been silently rejected
by every V2 contract on chain — caught pre-mainnet by the 0.5.0
red-team audit (the R1 finding in the 0.5.0 changelog).

---

## Footguns the library guards against

Patterns the V1 mint code rejects loudly rather than silently
producing a covenant-rejected broadcast:

1. **scriptSig pushes derived independently from the preimage.**
   `build_pow_preimage` returns a frozen
   [`PowPreimageResult`](../../src/pyrxd/glyph/dmint.py) carrying
   the preimage plus `.input_hash` / `.output_hash`. The scriptSig
   builder takes those same hashes — there is no public path that
   splits the preimage halves and the scriptSig pushes into two
   independent computations. This was the load-bearing M1 fix
   (0.5.0 breaking change to `build_mint_scriptsig`'s signature).

2. **Token-bearing funding UTXO.** A wallet that accidentally picks
   an FT, NFT, or dMint UTXO as `vin[1]` would destroy the token.
   `find_dmint_funding_utxo` and `_build_dmint_v1_mint_tx` both
   reject any funding input whose script contains an
   `OP_PUSHINPUTREF`-family opcode (`0xd0`–`0xd8`) via
   `is_token_bearing_script`. An opcode-aware classifier — not a
   byte-substring scan, which would misclassify legitimate P2PKH
   addresses with matching payload bytes.

3. **Missing OP_RETURN at vout[2].**
   [`build_dmint_v1_mint_preimage`](../../src/pyrxd/glyph/dmint.py)
   refuses to compute a preimage when `unsigned_tx.outputs[2]` is
   absent or doesn't start with `0x6a`. The covenant binds
   `outputHash` to that exact position; producing a preimage from a
   wrong-shape tx would waste the mining work.

4. **Synthetic-only validation.** Round-trip tests through pyrxd's
   own builder + verifier are not sufficient — both the M1
   scriptSig-divergence and the prior shape-mismatch incident
   shipped because builder + verifier were tested against each
   other rather than against captured chain bytes. The
   [`TestCovenantShape`](../../tests/test_dmint_v1_mint.py) suite
   pins against two independent mainnet golden vectors (`146a4d68…f3c`
   and `c9fdcd34…e530`) to break that loop.

5. **V2-shaped mints against V1 contracts (and vice versa).**
   `build_mint_scriptsig` takes `nonce_width` as a keyword-only
   `Literal[4, 8]` argument — a stray positional `4` produces a
   type error, and the wrong nonce width produces a length-validation
   error before any covenant logic runs. V1 contracts require
   `nonce_width=4`; the 8-byte default (V2) was preserved across
   the 0.5.0 breaking change for backwards compatibility with the
   pre-V1 default.

---

## End-to-end claim flow

The canonical V1 mint sequence
([`examples/dmint_claim_demo.py`](../../examples/dmint_claim_demo.py)):

```python
from pyrxd.glyph.dmint import (
    build_dmint_mint_tx,
    build_dmint_v1_mint_preimage,
    build_mint_scriptsig,
    find_dmint_funding_utxo,
    mine_solution,
)

# 1. Pick a contract UTXO (use find_dmint_contract_utxos against
#    the deploy reveal txid; see V1 dMint deploys page).
contract_utxo = ...

# 2. Find a plain-RXD funding UTXO at the miner's address.
funding_utxo = await find_dmint_funding_utxo(
    client, miner_address, needed=contract_utxo.state.reward + 10_000_000,
)

# 3. Build the unsigned 4-output tx with a placeholder nonce.
result = build_dmint_mint_tx(
    contract_utxo=contract_utxo,
    nonce=b"\x00" * 4,
    miner_pkh=miner_pkh,
    current_time=0,                          # V1 has no DAA
    funding_utxo=funding_utxo,
    op_return_msg=b"hello world",            # required for canonical 4-output shape
)

# 4. Compute the preimage AND the scriptSig hashes from the
#    now-finalised tx outputs — single source of truth.
pow_result = build_dmint_v1_mint_preimage(contract_utxo, funding_utxo, result.tx)

# 5. Mine.
nonce = mine_solution(pow_result.preimage, contract_utxo.state.target, nonce_width=4)

# 6. Splice the real scriptSig in. Same .input_hash / .output_hash
#    as the preimage was built from.
real_scriptsig = build_mint_scriptsig(
    nonce, pow_result.input_hash, pow_result.output_hash, nonce_width=4,
)
result.tx.inputs[0].unlocking_script = Script(real_scriptsig)

# 7. Sign the funding input (vin[1]) with the miner's key.
# 8. Broadcast.
```

The two-phase build (placeholder scriptSig, finalise outputs,
compute preimage, mine, splice real scriptSig) is unavoidable: the
preimage depends on the funding script and the OP_RETURN script,
both of which are output-side fields fixed before mining; the
scriptSig is the input-side field that mining produces. The
preimage helper takes the unsigned tx so this ordering is enforced
at the API level — you cannot ask for a preimage before the
outputs are finalised.
