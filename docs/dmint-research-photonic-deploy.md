# dMint V1 Deploy — Mainnet Truth + Photonic Divergence (2026-05-08)

Research notes for pyrxd's M2 (V1 deploy support). All on-chain data was
pulled directly from `wss://electrumx.radiant4people.com:50022/`; every hex
string and txid below was either copied out of that server's JSON-RPC
response or computed locally from those bytes.

**Verified facts** (everything below tagged "from chain") came from the
public RXD ElectrumX server. **Photonic source citations** point to
`RadiantBlockchain-Community/photonic-wallet@master` cloned to
`/tmp/photonic-wallet`. **Unverified assumptions** are called out where
they remain.

This doc is the Phase 2a deliverable for the M2 plan
(`docs/plans/2026-05-08-feat-dmint-v1-deploy-plan.md`). Phase 2b
(implementation) starts only after these findings are reviewed.

---

## 1. Reference deployment: Glyph Protocol (GLYPH)

The only mainnet V1 dMint deploy located so far is RBG's "Glyph Protocol"
deployment.

| Field | Value | Source |
|---|---|---|
| Deploy commit txid | `a443d9df469692306f7a2566536b19ed7909d8bf264f5a01f5a9b171c7c3878b` | from chain (h=228604) |
| Deploy reveal txid | `b965b32dba8628c339bc39a3369d0c46d645a77828aeb941904c77323bb99dd6` | from chain (h=228604) |
| Reveal raw size | 79,141 bytes | from chain |
| Reveal vin × vout | 36 × 35 | from chain |
| Token ticker | `GLYPH` | CBOR `ticker` field, vin 0 of reveal |
| Token name | `Glyph Protocol` | CBOR `name` field, vin 0 of reveal |
| Token description | `The first of its kind` | CBOR `desc` field, vin 0 of reveal |
| Protocol version | `p:[1,4]` | CBOR `p` field, vin 0 of reveal |
| numContracts | 32 | count of 241-byte contract outputs in reveal |
| maxHeight | 625,000 | bytes 80..82 of reveal vout 0 contract state (first 3-byte push after tokenRef) |
| reward (sats) | 50,000 | bytes 84..86 of reveal vout 0 contract state (second 3-byte push) |
| target (8 bytes BE) | `0x00da740da740da74` | bytes 88..95 of reveal vout 0 contract state |
| Total supply | 32 × 625,000 × 50,000 = 1,000,000,000,000 sats (10,000 GLYPH @ 8 decimals) | computed from above |
| Algorithm | sha256d (`OP_HASH256` / 0xaa) | epilogue PoW-hash opcode in vout 0 |
| DAA mode | none (jumps straight to cleanup) | epilogue body shape |

These match the M1 mint research at `docs/dmint-research-mainnet.md`
exactly — the seven contract UTXOs sampled there were 7 of these 32.

---

## 2. Deploy commit shape (verified from chain)

The deploy commit `a443d9df…878b` has **35 outputs**, 1448 bytes total
serialized:

| vout | bytes | type | role |
|---:|---:|---|---|
| 0 | 75 | gly hashlock (≥1 ref) | **FT commit** — preimage on `vin 0` of reveal carries the FT body (CBOR + image) |
| 1–32 | 25 each | bare P2PKH | **32 ref-seeds** (one sat each, all to the deployer's PKH) — each becomes the `contractRef[i]` of one of the 32 parallel dMint contract UTXOs |
| 33 | 75 | gly hashlock (≥2 refs) | **NFT commit** — preimage on `vin 33` of reveal would carry an NFT body, but in this deploy that path was skipped (see §6 below) |
| 34 | 25 | bare P2PKH | change |

### 2.1 The 75-byte hashlock shape

Both vout 0 and vout 33 follow the **Photonic `ftCommitScript`/`nftCommitScript`** pattern
(`/tmp/photonic-wallet/packages/lib/src/script.ts` lines 152–213):

```
OP_HASH256 <32-byte payload-hash> OP_EQUALVERIFY
PUSH(3) "gly" OP_EQUALVERIFY
OP_INPUTINDEX OP_OUTPOINTTXHASH OP_INPUTINDEX OP_OUTPOINTINDEX
OP_4 OP_NUM2BIN OP_CAT OP_REFTYPE_OUTPUT OP_<N> OP_NUMEQUALVERIFY
OP_DUP OP_HASH160 PUSH(20) <20-byte pkh> OP_EQUALVERIFY OP_CHECKSIG
```

The `OP_<N>` byte differs between FT and NFT:

- **FT commit (vout 0)**: `OP_1` (0x51) — require ≥1 ref output (the FT contract creation)
- **NFT commit (vout 33)**: `OP_2` (0x52) — require ≥2 ref outputs (singleton + mutable container)

### 2.2 No delegate-ref prefix

Both 75-byte scripts on this deploy commit start at offset 0 with `aa 20`
(`OP_HASH256` then PUSH(32)). Photonic's `addDelegateRefScript`
(`script.ts:138`) would prepend `OP_PUSHINPUTREF <ref> OP_DUP ...` at the
front — but those bytes are absent here. So this deploy did **not** use
delegate-funded commits. M2 should default `delegate=None` and treat
delegate-ref support as deferred work (M3+).

---

## 3. Deploy reveal shape (verified from chain)

Reveal `b965b32d…9dd6` has **36 inputs** and **35 outputs**:

### 3.1 Inputs

| vin | spends | role |
|---:|---|---|
| 0 | `a443d9df:0` (FT commit hashlock) | scriptSig (65,685 bytes) carries `<sig> <pubkey> <FT-preimage with CBOR+PNG>` |
| 1–32 | `a443d9df:1..32` (32 ref-seeds) | scriptSig is plain `<sig> <pubkey>` per P2PKH |
| 33 | `a443d9df:33` (NFT commit hashlock) | scriptSig (168 bytes) carries `<sig> <pubkey> <auth-NFT preimage>` — but the preimage CBOR is `{p:[2], loc:0, by:[<prior NFT singleton ref>]}`, see §6 |
| 34 | `6de766d7…3eaf:12` (prior mutable container NFT singleton, 63 bytes carrying `d8 874c3cce…d56a:0`) | brings the auth NFT identity in from a prior mint |
| 35 | `a443d9df:34` (change P2PKH) | funds the (large) reveal fee |

**Implication for M2:** the V1 deploy reveal needs to handle a
**heterogeneous input set** — non-trivial scriptSigs (vin 0, vin 33) plus
many P2PKH spends (vins 1–32, vin 35) plus an optional pre-existing
singleton spend (vin 34). The pyrxd builder must:

1. Sign inputs with different scriptSig shapes (preimage-revealing vs plain P2PKH).
2. Manage UTXO ordering so vin 0 = FT commit, vin 33 = NFT commit, vins 1–32 = ref-seeds in vout-order, change last.
3. Optionally accept a "pre-existing auth NFT singleton input" (vin 34 in this reveal). For pyrxd M2's first cut, we can omit this and require the auth NFT to be created freshly inside the deploy commit, which means using vout 33 of the commit as a true NFT commit with its own CBOR body. See §6 for the choice we make.

### 3.2 Outputs

| vout | bytes | role |
|---:|---:|---|
| 0–31 | 241 each | **32 V1 dMint contract UTXOs** (state + epilogue) — each with `contractRef[i] = a443d9df:<i+1>`, all sharing `tokenRef = a443d9df:0`. Identical to the M1-known V1 contract layout. |
| 32 | 63 | **FT NFT** (the public-facing token marker) — script `d8 <a443d9df:33-LE> 75 76a9 14 <pkh> 88ac`. Singleton ref points back to the **commit's NFT-commit hashlock outpoint**, which gives the token its on-chain identity. |
| 33 | 63 | **Auth/container NFT** (forwards prior identity) — script `d8 <874c3cce:0-LE> 75 76a9 14 <pkh> 88ac`. Singleton ref points to a **different earlier commit** (`874c3cce…d56a:0`, see §6). |
| 34 | 25 | change P2PKH (~45.87 RXD) |

### 3.3 Contract UTXO state breakdown (vout 0 of reveal)

Verified byte-for-byte from chain. The 96-byte state portion decomposes as:

```
[ 0..  4]  04 00 00 00 00                                                            height = 0  (LE-4 push)
[ 5.. 41]  d8 8b 87 c3 c7 71 b1 a9 f5 01 5a 4f 26 bf d8 09 79 ed 19 6b
           53 66 25 7a 6f 30 92 96 46 df d9 43 a4  01 00 00 00                       d8 + contractRef = a443d9df:1   (LE-reversed 32-byte txid + LE-4 vout)
[42.. 78]  d0 8b 87 c3 c7 71 b1 a9 f5 01 5a 4f 26 bf d8 09 79 ed 19 6b
           53 66 25 7a 6f 30 92 96 46 df d9 43 a4  00 00 00 00                       d0 + tokenRef    = a443d9df:0
[79.. 82]  03 68 89 09                                                               maxHeight = 625,000  (LE-3 push)
[83.. 86]  03 50 c3 00                                                               reward = 50,000  (LE-3 push)
[87.. 95]  08 74 da 40 a7 0d 74 da 00                                                target = 0x00da740da740da74  (LE-8 push)
```

Then byte 96 = `bd` (OP_STATESEPARATOR), and bytes 97..240 are the
145-byte V1 epilogue (sha256d, fixed difficulty, FT-wrapped reward).

This is **exactly** what `build_dmint_v1_contract_script` in M1 emits.
So pyrxd M2 just needs to call that builder once per contract output
in the reveal.

---

## 4. CBOR token body (vin 0 of reveal scriptSig)

**Format:** the FT commit preimage is structured as:

```
<DER-sig> <33-byte pubkey> "gly" <OP_PUSHDATA4> <length-LE-4> <CBOR-map>
```

For this deploy: payload was 65,569 bytes; CBOR map keys (canonical
order):

```python
{
  "p":      [1, 4],                              # protocol = V1 dMint FT  ← REQUIRED
  "ticker": "GLYPH",
  "name":   "Glyph Protocol",
  "desc":   "The first of its kind",
  "by":     [CBORTag(64, <36-byte NFT singleton ref>)],
  "main":   {"t": "image/png", "b": CBORTag(64, <PNG bytes>)},
}
```

**Critical for M2:**

1. The CBOR `p` field is `[1, 4]` (the integer pair "V1 dMint FT").
   pyrxd must emit this exact value for V1 deploys. It must NOT emit a
   `v` field (that's for V2).
2. **dMint parameters (numContracts, reward, maxHeight, target,
   algorithm, daa mode) are NOT in the CBOR.** They live entirely inside
   the contract output scripts. The CBOR is metadata-only.
3. `by` carries the 36-byte ref of the NFT that "owns" / authenticates
   this deploy. In this case it is the prior mutable container ref
   (`6ad5ce8c…4c87:0`), tagged with CBOR tag 64 so RXinDexer/Photonic
   recognize it as an outpoint, not opaque bytes.
4. `main` carries the project's display image. M2's first deploy can
   skip this (no image) — `main` is optional in Photonic.

### 4.1 Auth NFT body (vin 33 of reveal scriptSig)

```python
{
  "p":   [2],                                # protocol = V2 NFT
  "loc": 0,
  "by":  [CBORTag(64, <NFT singleton ref 874c3cce…d56a:0>)],
}
```

This is a tiny 33-byte CBOR map (auth NFT had no name/description/image
in this deploy). The `by` ref points at the **prior** Glyph commit
(`874c3cce…d56a:0` at h=227767), which itself was a Glyph NFT commit
that was revealed at a different time. So this isn't really a
"freshly-minted auth NFT" — it's a forwarding of an existing NFT.

For pyrxd M2: this is **deferred work**. The simpler path is to mint
the auth NFT freshly inside the same deploy reveal (using a normal
glyph NFT commit/reveal flow). See §6.

---

## 5. Photonic Wallet source (canonical reference)

The canonical TS source paths for V1 deploy:

| File | Lines | What it does |
|---|---|---|
| `packages/lib/src/mint.ts:175–217` | `createCommitOutputs(contract, deployMethod, params, payload, delegate?)` | Builds the commit-tx outputs given contract type ("ft"/"nft"/"dat") and deploy method ("direct"/"psbt"/"dmint"). For `ft` + `dmint`, appends `numContracts` 1-sat P2PKH ref-seeds after the initial gly hashlock. |
| `packages/lib/src/mint.ts:364–484` | `createRevealOutputs(creatorAddress, mint, deployMethod, deployParams)` | Builds the reveal-tx I/O. For `ft` + `dmint`, emits one `dMintScript(...)` output per contract, optional premine output, and consumes the `numContracts` ref-seeds from the commit. |
| `packages/lib/src/script.ts:152–182` | `ftCommitScript(address, payloadHash, delegateRef)` | The 75-byte gly hashlock shape (with optional delegate-ref prefix). |
| `packages/lib/src/script.ts:184–213` | `nftCommitScript(address, payloadHash, delegateRef)` | Same shape with `OP_2 OP_NUMEQUALVERIFY`. |
| `packages/lib/src/script.ts:704–766` | `dMintScript(...)` | **EMITS V2 ONLY** in current master — does not produce the V1 9-state-item layout. See §7. |
| `packages/lib/src/types.ts:62–78` | `DeployMethod`, `RevealDmintParams` | The shape of params M2 will closely mirror in `DmintV1DeployParams`. |
| `packages/lib/src/types.ts:90–`  | `DmintPayload` | V2-only schema (algo / daa / etc.); V1 has a much smaller surface. |

### 5.1 Photonic `RevealDmintParams` shape

```ts
type RevealDmintParams = {
  address: string;       // P2PKH owner of all ref-seeds + change
  difficulty: number;    // human-friendly difficulty (mapped to target via dMintDiffToTarget)
  numContracts: number;  // count of parallel contracts (32 for the GLYPH deploy)
  maxHeight: number;     // max mints per contract
  reward: number;        // sats per mint
  premine: number;       // optional premine sats (in addition to dMint contracts)
  algorithm?: string;    // V2 only — V1 ignores
  daaMode?: string;      // V2 only — V1 ignores
  daaParams?: any;       // V2 only — V1 ignores
};
```

For pyrxd M2 we drop the V2-only fields:

```python
@dataclass(frozen=True)
class DmintV1DeployParams:
    owner_address: Address          # PKH owner of ref-seeds + change
    num_contracts: int              # 1..256 (chain has examples up to 32)
    reward_sats: int                # per-mint reward, fits in 3 bytes (≤ 0xFFFFFF)
    max_height: int                 # max mints per contract, fits in 3 bytes
    target: int                     # 8-byte difficulty target
    ticker: str
    name: str
    description: str
    auth_nft_ref: bytes | None = None   # if None, mint auth NFT freshly in deploy
    main_image: bytes | None = None
    main_image_mime: str | None = None
```

(Final field naming and frozen-ness will match plan §3.1.)

---

## 6. Auth NFT decision: forward-prior vs mint-fresh

The on-chain GLYPH deploy uses **forward-prior**: vin 34 spends an
existing mutable-container NFT (`6de766d7:12`), and vout 33 of the
reveal re-emits the same singleton ref forward.

**Pros of forward-prior (the on-chain way):**

- Single tx, single signing pass.
- The "deployer" identity persists across multiple deploys (one auth NFT for many tokens).

**Cons:**

- Requires the deployer to already hold a mutable-container NFT.
- The reveal must include both the FT-commit preimage AND the NFT
  singleton input — heterogeneous scriptSig shapes.
- pyrxd doesn't currently have an NFT-mint flow that creates that
  initial container (M3 work).

**Pros of mint-fresh (the pyrxd M2 approach):**

- Self-contained: the deploy commit's vout 33 is a real NFT commit,
  and the reveal's vin 33 carries a genuine NFT-body CBOR.
- No prior NFT required.

**Cons:**

- Each deploy mints a new auth NFT — no "studio" identity reuse.
  Indexers will treat each deploy as having its own owner-NFT.

**Decision (pyrxd M2):** mint-fresh. Forward-prior is documented as
deferred work. RXinDexer accepts both shapes (it just looks at the
`by` ref in the FT body CBOR).

This means our deploy reveal is simpler than the on-chain example:

```
vin 0:    spend FT commit hashlock (CBOR FT body)
vin 1..N: spend N ref-seeds (P2PKH)
vin N+1:  spend NFT commit hashlock (CBOR NFT body, p:[2], by=<self>)
vin N+2:  spend change (P2PKH)

vout 0..N-1: N dMint contract UTXOs
vout N:      FT NFT (d8 <commit:0-LE> 75 P2PKH)
vout N+1:    auth NFT (d8 <commit:N+1-LE> 75 P2PKH)
vout N+2:    change
```

…where N = numContracts. Total commit vouts = N+3 (FT-commit, N seeds,
NFT-commit, change). Total reveal vouts = N+3 (N contracts, FT NFT,
auth NFT, change).

---

## 7. Photonic divergences (pyrxd-specific)

### 7.1 V1 contract output layout (RESOLVED IN M1)

`dMintScript()` in current photonic-wallet master only emits the V2
10-state-item shape. pyrxd M1 already implemented `build_dmint_v1_contract_script`
(in `pyrxd.glyph.dmint`) which emits the V1 9-state-item shape used on
mainnet. M2 will call this M1 builder.

### 7.2 Premine handling

Photonic supports an optional `premine: number` in `RevealDmintParams`.
The on-chain GLYPH deploy did not use a premine. **Decision (M2):**
skip premine support in the first cut — file as deferred work. Adds 1
output to the reveal if non-zero, no other complexity.

### 7.3 Delegate-ref commit prefix

Photonic supports `delegateRef` in commit scripts (a prefix like
`OP_PUSHINPUTREF <ref> OP_DUP ...`). The on-chain GLYPH deploy did
not use one. **Decision (M2):** `delegate=None` always; defer
delegate-ref support to a later milestone if anyone asks for it.

### 7.4 Algorithm + DAA mode

Photonic's `dMintScript` accepts `algorithm` and `daaMode` parameters
(for V2). V1 contracts have no DAA and only sha256d in practice.
**Decision (M2):** hardcode `algorithm = 'sha256d'`, no DAA. M1 also
made this choice.

### 7.5 V1 vs V2 protocol vector in CBOR

- V1: `p: [1, 4]` (no `v` field)
- V2: `v: 1, p: [2, 4]` (different keys)

M2 must emit `[1, 4]` and not include `v`. This was already the
plan's spec, now confirmed against chain truth.

---

## 8. Acceptance gates derived from this research

The plan §4 (Acceptance Criteria) already lists the three-tier gate
(synthetic → VPS testmempoolaccept → real mainnet). This research adds:

- **Synthetic vector**: build a tx with the same params as GLYPH
  (`numContracts=32`, `reward=625_000`, `maxHeight=50_000`,
  `target=0x00da740da740da74`) and assert that vout 0 of the reveal is
  byte-identical to the on-chain reveal's vout 0 (after substituting
  the test deployer's PKH and a placeholder commit txid). This is the
  strongest synthetic test we can write — **the chain itself is the
  oracle**.
- **VPS testmempoolaccept**: relay the deploy reveal in `dryrun` mode
  via `radiant-cli testmempoolaccept` against a regtest fork that's
  been synced past the V1 dMint activation height. Assert
  `allowed: true`.
- **Mainnet smoke**: deploy a small token (`numContracts=4`,
  `reward=1`, `maxHeight=10`, target high enough to allow CPU mining)
  to mainnet from a tiny test wallet; verify it appears in RXinDexer
  and that we can mint from at least one contract using the M1 mint
  builder.

---

## 9. Open questions remaining

1. **Reveal scriptSig stub size for fees.** The FT preimage push can be
   **arbitrarily large** (the GLYPH reveal carried a 65KB PNG). pyrxd's
   fee estimator must accept caller-provided body length and pad
   correctly. This is a builder-API design point for Phase 2b.
2. **Joint NFT+FT V1 deploy** — would it be useful to deploy an NFT
   and an FT together? Photonic supports it via `commitBatch`. Filed as
   deferred work; not needed for M2 acceptance.
3. **Resume after partial broadcast.** If the commit confirms but the
   reveal fails, we must be able to resume by signing only the reveal
   given the saved commit txid. Plan already calls for this; this
   research confirms the resume input shape: just the saved
   `commit_txid` and the `DmintV1DeployParams` is enough to deterministically
   reproduce the reveal.

---

## 10. Sources

### From chain (queried 2026-05-08 from `wss://electrumx.radiant4people.com:50022/`)

- Deploy commit `a443d9df…878b` raw bytes, vout count, all 35 scriptPubKey hexes — saved to `/tmp/dmint-m2-research/commit_raw.hex` + `commit_verbose.json` during research.
- Deploy reveal `b965b32d…9dd6` raw bytes, all 36 input prevouts + scriptSigs, all 35 output scripts — saved to `/tmp/dmint-m2-research/reveal_raw.hex` + `reveal_verbose.json`.
- Prior tx `874c3cce…d56a` (h=227767) — confirmed as a 3-vout Glyph NFT commit/reveal predecessor.
- Prior tx `6de766d7…3eaf` (h=228398) — confirmed as the 14-vin/14-vout mutable-container NFT mint that supplies vin 34 of the deploy reveal.

### From Photonic Wallet master (cloned to `/tmp/photonic-wallet`)

- `packages/lib/src/mint.ts:174–276` (commit builders) — read in full.
- `packages/lib/src/mint.ts:362–484` (reveal builder) — read in full.
- `packages/lib/src/script.ts:152–263` (commit/output script primitives) — read.
- `packages/lib/src/script.ts:704–766` (dMintScript — V2-only in master) — read.
- `packages/lib/src/types.ts:60–110` (`DeployMethod`, `RevealDmintParams`, `DmintPayload`) — read.

### From pyrxd M1 work (this branch's parent `feat/dmint-v1-mint`)

- `src/pyrxd/glyph/dmint.py` — `build_dmint_v1_contract_script`, `build_dmint_v1_state_script`, `build_dmint_v1_code_script`, `is_token_bearing_script`, `find_dmint_funding_utxo`. **All reused as-is by M2.**
- `docs/dmint-research-mainnet.md` §2–§5 — original V1 contract decode.
- `docs/dmint-research-photonic.md` — original Photonic source citations from M1.
- `docs/solutions/logic-errors/dmint-v1-mint-shape-mismatch.md` — institutional lesson #1.
- `docs/solutions/logic-errors/funding-utxo-byte-scan-dos.md` — institutional lesson #2 (opcode-aware classification).

---

## 11. Phase 2a exit checklist

Per plan §2.5, Phase 2a is complete when ALL six items below are true:

- [x] On-chain V1 deploy located, fetched, and decoded byte-by-byte.
- [x] Photonic source for `createCommitOutputs` + `createRevealOutputs` + `dMintScript` read in full and key divergences documented.
- [x] Auth NFT strategy decided (mint-fresh; forward-prior is deferred).
- [x] Premine + delegate-ref decisions documented (both deferred).
- [x] Acceptance-test inputs derived (golden synthetic vector parameters identified).
- [x] Open questions logged with decisions or "deferred" tags.

Phase 2a deliverable: this document. Ready to start Phase 2b.
