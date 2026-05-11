# V1 dMint deploys: N parallel singleton contracts in one reveal

**Why this page exists:** "dMint" reads like "deploy one mint contract"
but every live mainnet V1 dMint deploy creates *many* contract UTXOs at
once — 32 for Radiant Glyph Protocol (GLYPH), 10 for some smaller
RBG-class tokens. Each contract is independently mineable, so claims
race in parallel. This page explains the deploy shape and the design
choices pyrxd's V1 deploy library makes, anchored to a real mainnet
reference.

---

## TL;DR

A V1 dMint deploy is a **2-tx flow** that emits **N parallel singleton
contracts** sharing one `tokenRef`:

1. **Commit tx** — opens a hashlock for the FT metadata + sets aside N
   1-photon ref-seed outputs (one per future contract).
2. **Reveal tx** — spends the commit, broadcasts the CBOR token body in
   `vin[0]`'s scriptSig, and creates N V1 dMint contract UTXOs at its
   outputs. Each contract has its own permanent `contractRef[i]` but
   they all share the same `tokenRef`.

The miner side is unchanged from a single-contract mint: any holder
picks one of the N contract UTXOs, finds a PoW nonce, spends it, and
re-creates it at `height+1` with the same `tokenRef`. Total supply is
`num_contracts × max_height × reward_photons`.

V2 dMint exists in Photonic Wallet's source but **no live mainnet
contracts are V2**, so pyrxd's `prepare_dmint_deploy` accepts V2 only
behind an explicit `allow_v2_deploy=True` opt-in. See [the Photonic
divergences section below](#photonic-divergences) for why this gate
exists.

---

## Reference deployment: Glyph Protocol (GLYPH)

The byte-by-byte chain truth this page is anchored to:

| Field                | Value                                                              |
|----------------------|--------------------------------------------------------------------|
| Deploy commit txid   | `a443d9df469692306f7a2566536b19ed7909d8bf264f5a01f5a9b171c7c3878b` |
| Deploy reveal txid   | `b965b32dba8628c339bc39a3369d0c46d645a77828aeb941904c77323bb99dd6` |
| Ticker / name        | `GLYPH` / `Glyph Protocol`                                         |
| Protocol vector      | `p: [1, 4]`  (FT + DMINT — no `v` field)                           |
| `num_contracts`      | 32                                                                 |
| `max_height`         | 625,000  (mints per contract)                                      |
| `reward_photons`     | 50,000   (sats per mint)                                           |
| Target               | `0x00da740da740da74` (sha256d)                                     |
| Total supply         | 32 × 625,000 × 50,000 = 10⁹ photons (10,000 GLYPH @ 8 decimals)    |

Full byte-by-byte decode lives at
[`docs/dmint-research-photonic-deploy.md`](../dmint-research-photonic-deploy.md).
pyrxd's M2 test suite includes a byte-equal golden vector pinned
against vout 0 of the reveal: feed identical params to
`prepare_dmint_deploy` → `build_reveal_outputs(commit_txid)` and the
output bytes match the on-chain UTXO exactly.

---

## Commit tx output shape (verified from chain)

The GLYPH commit has **35 outputs**, and pyrxd's V1 deploy demo mirrors
the load-bearing structure (skipping the optional auth NFT — see
[deferred work](#deferred-work)):

| vout       | bytes | role                                                                          |
|-----------:|------:|-------------------------------------------------------------------------------|
| 0          |    75 | gly hashlock (FT-commit; requires ≥1 ref output in reveal)                    |
| 1 … N      |    25 | bare P2PKH ref-seeds, one per parallel contract                               |
| N+1        |    75 | gly hashlock (NFT-commit; auth NFT — see [deferred work](#deferred-work))     |
| N+2        |    25 | P2PKH change                                                                  |

Each ref-seed is **exactly 1 photon**. Its outpoint becomes one
contract's permanent `contractRef[i] = (commit_txid, i+1)`. The
75-byte FT-commit + NFT-commit hashlocks follow the standard Photonic
`ftCommitScript`/`nftCommitScript` shape; the only difference between
them is the ref-count check at the tail (`OP_1 OP_NUMEQUALVERIFY` vs
`OP_2 OP_NUMEQUALVERIFY`).

---

## Reveal tx output shape

| vout       | bytes | role                                                            |
|-----------:|------:|-----------------------------------------------------------------|
| 0 … N-1    |   241 | V1 dMint contract UTXOs (state + epilogue), one per `contractRef[i]` |
| N          |    63 | FT NFT singleton (the public-facing token marker)               |
| N+1        |    63 | Auth NFT singleton (only present in the full forward-prior path)|
| N+2        |    25 | P2PKH change                                                    |

Every contract UTXO is the same 241-byte layout:

```
┌── state (96 bytes) ────────────────────────────────────────────┐
│ 04 <height-LE-4>              height       (5 bytes)           │
│ d8 <contractRef[i]-LE-36>     contract ref (37 bytes)          │
│ d0 <tokenRef-LE-36>           token ref    (37 bytes)          │
│ <push max_height>             max_height   (≤4 bytes)          │
│ <push reward>                 reward       (≤4 bytes)          │
│ 08 <target-LE-8>              target       (9 bytes)           │
└── bd OP_STATESEPARATOR ────────────────────────────────────────┤
│ 145-byte V1 epilogue (algo byte + FT-conservation + branch)    │
└────────────────────────────────────────────────────────────────┘
```

The epilogue is the same 145 bytes across every V1 mainnet deploy
except for one byte: the algo selector (`0xaa` for sha256d on every
live deploy seen to date). pyrxd's parser fingerprints on the
epilogue prefix + algo byte + epilogue suffix
([`_match_v1_epilogue`](../../src/pyrxd/glyph/dmint.py)).

---

## CBOR body in the reveal scriptSig

V1's `vin[0]` scriptSig carries the FT body as:

```
<DER-sig> <33-byte pubkey> "gly" <push opcode> <length> <CBOR map>
```

The CBOR map for V1 dMint has these fields (chain-truth GLYPH set):

```python
{
  "p":      [1, 4],                    # FT + DMINT — required, exact
  "ticker": "GLYPH",
  "name":   "Glyph Protocol",
  "desc":   "The first of its kind",
  "by":     [CBORTag(64, <36-byte NFT singleton ref>)],
  "main":   {"t": "image/png", "b": CBORTag(64, <PNG bytes>)},
}
```

Three things V1 deploys **must not** carry that V2 deploys do:

1. **No `v` field.** Indexers select V1 vs V2 parser from this key's
   presence. pyrxd enforces this at deploy-build time:

   ```python
   decoded = cbor2.loads(cbor_bytes)
   if "v" in decoded:
       raise ValidationError(...)
   ```

2. **No `dmint:{...}` sub-dict.** V2 carries deploy params
   (num_contracts, reward, target, algo, DAA mode) inside the CBOR.
   V1 encodes them **in the contract scripts** instead, so the CBOR
   is metadata-only.

3. **No `creator`/`royalty`/`policy`/`rights`/`created`/`commit_outpoint`
   fields** unless you explicitly want them — they were added in V2.

If the CBOR body has embedded media (a logo PNG, etc.) it can exceed
65 KB, which means the scriptSig push uses **OP_PUSHDATA4 (`0x4e`)**
— a tool walking scriptSig push stacks must handle 0x4e or it will
miss the gly marker that follows it. GLYPH's body is 65,569 bytes
including its 65 KB PNG, just above OP_PUSHDATA2's 65,535 limit.

---

## pyrxd's V1 deploy library surface

The M2 library deliverable is in
[`src/pyrxd/glyph/builder.py`](../../src/pyrxd/glyph/builder.py):

```python
from pyrxd.glyph import (
    GlyphBuilder, GlyphMetadata, GlyphProtocol,
    DmintV1DeployParams,
)

params = DmintV1DeployParams(
    metadata=GlyphMetadata(
        protocol=[GlyphProtocol.FT, GlyphProtocol.DMINT],   # [1, 4]
        name="My Token",
        ticker="TKN",
    ),
    owner_pkh=pkh,
    num_contracts=32,
    max_height=100,
    reward_photons=1_000,
    difficulty=10,
)

result = GlyphBuilder().prepare_dmint_deploy(params)        # V1 path — no opt-in needed

# Step 1: broadcast `result.commit_result.commit_script` in a tx
#         with N+2 outputs (FT-commit + N ref-seeds + change).

# Step 2: wait for commit confirmation, get its txid.

reveal = result.build_reveal_outputs(commit_txid)           # rebuilds the N contract scripts
# `reveal.contract_scripts` is a tuple[bytes, ...] of length N,
# each 241 bytes. Place these as the first N outputs of the reveal.
```

The dispatcher in `prepare_dmint_deploy` selects V1 vs V2 based on the
param type. Two `@overload` stubs narrow the return type at call
sites without a runtime `isinstance` check.

For an end-to-end example see
[`examples/dmint_v1_deploy_demo.py`](../../examples/dmint_v1_deploy_demo.py).
It DRY-RUNs by default; broadcasting requires the three-key handshake
(`DRY_RUN=0` + `I_UNDERSTAND_THIS_IS_REAL=yes` + real `GLYPH_WIF`).

---

## Photonic divergences

Photonic Wallet's master branch (`RadiantBlockchain-Community/photonic-wallet`)
is the canonical reference for the Glyph protocols — pyrxd matches its
shape wherever sensible. There are five places M2 deviates intentionally:

1. **V1 contract output layout.** Photonic's `dMintScript()` in master
   only emits the V2 10-state-item shape; V1 (the only mainnet format)
   is no longer reachable from there. pyrxd ships its own V1 builder
   matching the 9-item layout decoded from chain.
2. **Premine.** Photonic's `RevealDmintParams` supports a `premine`
   field that adds an FT output to the reveal. pyrxd accepts the field
   on the params dataclass but rejects it at build time with a clear
   "deferred work" error — the GLYPH reference deploy doesn't use it.
3. **Delegate-ref commits.** Photonic supports a delegate-ref prefix
   on commit scripts. pyrxd hardcodes `delegate=None` for V1.
4. **Algorithm + DAA.** Photonic accepts `algorithm` and `daaMode`
   args. V1 contracts on mainnet are always sha256d with no DAA, so
   pyrxd rejects anything else with a clear error.
5. **Protocol vector.** V1 uses `p: [1, 4]` without a `v` field;
   V2 uses `v: 1` plus `p: [2, 4]`. Indexers select parsers on this
   key, so emitting the wrong one produces a token no indexer recognises.

These are all documented in
[`docs/dmint-research-photonic-deploy.md`](../dmint-research-photonic-deploy.md) §7.

---

## Deferred work

The pyrxd M2 V1 deploy library does NOT yet cover:

- **Auth NFT in the deploy tx.** GLYPH's reveal includes a `vout[N+1]`
  containing a 63-byte NFT singleton — the "auth NFT" or "container
  NFT" that proves the deployer's identity. M2's demo skips this so
  the example stays focused on the dMint machinery. Adding it is
  straightforward (mint a fresh NFT in the same reveal, or forward-
  prior an existing one) and lands in a follow-up milestone.
- **Premine FT output.** See divergence #2 above.
- **Walking forward through mined-from contracts.** `find_dmint_contract_utxos`
  currently returns *fresh* contracts (height=0). Once a contract has
  been mined from at least once, its scripthash drifts and the helper
  skips it. A spend-chain walker to find current heads is filed as
  deferred work.

---

## Footguns the library guards against

These come from M1 + M2 institutional learnings (the
[`docs/solutions/logic-errors/`](../solutions/logic-errors/) compound
docs):

1. **Token-burn from accidental funding.** A wallet that picks a
   token-bearing UTXO as a funding input destroys the token. pyrxd's
   `find_dmint_funding_utxo` and the deploy demo's
   `_filter_plain_funding_utxos` both use an opcode-aware classifier
   (`is_token_bearing_script`) that rejects UTXOs whose script
   contains a `0xd0`–`0xd8` opcode. A naive byte-substring scan would
   misclassify ~51 % of legitimate P2PKH addresses; the opcode-aware
   walker only counts opcodes, not push payload bytes.

2. **V2-by-accident.** pyrxd's `prepare_dmint_deploy` refuses
   `DmintV2DeployParams` unless the caller explicitly passes
   `allow_v2_deploy=True`. No live miner targets V2; deploying V2
   produces a token nobody can mine.

3. **Synthetic-only validation.** Round-trip tests don't catch
   shape mismatches with mainnet. pyrxd pins V1 builders with
   byte-equal golden vectors against real GLYPH reveal bytes — see
   [`tests/test_dmint_v1_deploy.py::TestV1GoldenVectorGlyphPattern`](../../tests/test_dmint_v1_deploy.py).

4. **Hashlock reuse confusing "find the reveal".** A deployer who
   ran a failed attempt before the successful deploy will have
   multiple txs in their commit-vout-0 scripthash history. pyrxd's
   `find_dmint_contract_utxos` disambiguates by checking which
   candidate actually spends `commit_txid:0`, not by picking the
   first non-commit entry. See
   [`docs/solutions/logic-errors/dmint-deploy-reveal-hashlock-reuse.md`](../solutions/logic-errors/dmint-deploy-reveal-hashlock-reuse.md).
