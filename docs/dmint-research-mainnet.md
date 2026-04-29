# dMint Contract Research — Radiant Mainnet (2026-04-22)

Reverse-engineering notes for pyrxd's dMint builder. All on-chain data was
pulled directly from a Radiant full node; every hex string and txid below
was copied out of that node's RPC output (not fabricated, not transcribed
from documentation).

**Verified facts** (everything below that comes from the chain is tagged in
place). **Unverified assumptions** are called out explicitly — mostly
around the human-readable ticker interpretation, which we cannot confirm
without decoding the token's reveal CBOR payload.

---

## 1. Discovery method

- **MCP tool list** (`/home/eric/apps/radiant-mcp-server/src/index.ts`,
  lines 486–547): the MCP exposes `radiant_get_dmint_contracts` /
  `radiant_get_dmint_contract`, which call ElectrumX RPC methods
  `dmint.get_contracts` etc. Probing the public server
  `electrumx.radiant4people.com:50012` over TLS returned
  `{"code":-32601,"message":"unknown method \"dmint.get_contracts\""}` —
  the public ElectrumX has not shipped those extensions, so the MCP-tool
  path was a dead end for this session.
- **Direct node access**: fell back to the `radiant-mainnet` container
  on the VPS (block height 422,868 at query time). Scanned `getblock …
  2` from tip backward looking for scriptPubKey outputs that contain the
  dMint epilogue fingerprint `dec0e9aa76e378e4` (the opcodes
  `OP_PUSHINPUTREF OP_REFOUTPUTCOUNT_OUTPUTS OP_INPUTINDEX
  OP_CODESCRIPTBYTECODE_UTXO OP_HASH256 OP_DUP
  OP_CODESCRIPTHASHVALUESUM_UTXOS …` tail shared by every dMint
  contract UTXO).
- **Reference implementation** for cross-check:
  `/tmp/photonic-wallet/packages/lib/src/script.ts` (`dMintScript`,
  `dMintDiffToTarget`, lines 440–766) and its vitest suite at
  `.../__tests__/dmint.test.ts`. These are not on-chain facts but are
  the only authoritative source for the opcode layout's *intent*.

A 200-block scan yielded 31 live dMint contract UTXOs. A second targeted
scan (stop after 7 distinct contract refs) is the basis for the contracts
listed below.

---

## 2. Contracts found

All seven distinct contract UTXOs below come from a **single token
deployment**: the commit transaction is `a443d9df…878b` (derived by
byte-reversing the 32-byte txid portion of the `OP_PUSHINPUTREF` push
`d0 8b87c3c7…943a4 00000000` visible in every contract script, then
confirming with `getrawtransaction` on the node — the commit tx exists,
has 35 outputs, and vout 0 is a 75-byte OP_HASH256-gated "gly" hashlock
consistent with a Glyph commit).

- **Deploy commit txid**: `a443d9df469692306f7a2566536b19ed7909d8bf264f5a01f5a9b171c7c3878b`
  (has 35 outputs; vouts 0 and 33 are the two Glyph hashlock commits,
  vouts 1–32 are `0.00000001 RXD` P2PKH seed outputs that the reveal
  transaction consumes to mint `numContracts` parallel dMint contract
  UTXOs).
- **Permanent token ref** (the `d0` push in every contract, shared
  across every mint output for this token):
  `8b87c3c771b1a9f5015a4f26bfd80979ed196b5366257a6f30929646dfd943a400000000`
  — i.e. commit txid at vout 0.
- **Algorithm**: `OP_HASH256` (byte `0xaa`) in the PoW-check position →
  algorithm ID 0 = **sha256d**.
- **DAA mode**: none. The bytecode jumps straight from Part B to the
  `75757575 75` cleanup (no ASERT, LWMA, etc.) → **fixed** difficulty.
- **Mining state item count**: 3 state items (height, maxHeight,
  reward + 8-byte target). This is the **V1 dMint template**, not the
  10-item V2 template shipped in current photonic-wallet.

### 2.1 Contract UTXO inventory (seven sampled instances)

Each row is one live UTXO. `contractVout` is the fourth LE byte of the
`d8` singleton push — i.e. which seed vout of the commit this instance
derives from.

| # | Contract UTXO (unspent sample) | contractVout | Script hex (verbatim — all 241 bytes) |
|---|--------------------------------|:-:|--|
| 1 | `f0a6a106135ddb1072910f7bc4849b04a7117d832d3643c8d9d98185fb543b0d:0` | 1 | `04de5f0100d88b87c3c771b1a9f5015a4f26bfd80979ed196b5366257a6f30929646dfd943a401000000d08b87c3c771b1a9f5015a4f26bfd80979ed196b5366257a6f30929646dfd943a400000000036889090350c3000874da40a70d74da00bd5175c0c855797ea8597959797ea87e5a7a7eaabc01147f77587f040000000088817600a269a269577ae500a069567ae600a06901d053797e0cdec0e9aa76e378e4a269e69d7eaa76e47b9d547a818b76537a9c537ade789181547ae6939d635279cd01d853797e016a7e886778de519d547854807ec0eb557f777e5379ec78885379eac0e9885379cc519d75686d7551` |
| 2 | `cb273c1ea1025a93b7ec08eedae29fc2285a820a4d29765027035a9fa7b926b3:0` | 4 | `0477c40000d88b…943a4 04000000 d08b…943a4 00000000 03688909 0350c300 0874da40a70d74da00 bd …` (identical suffix from byte 79 on) |
| 3 | `f0cfc00173629680540b071ee2d5e86e2d86037f9fa947d087a2f3f7901d0964:0` | 8 | identical from byte 79 onward |
| 4 | `bec0eae1706029d053357114dd17aab8510efc0b1e0b870a620726d221aa9fd5:0` | 11 | identical from byte 79 onward |
| 5 | `9a08f4025c48c32b3e156e4f949f8bae7136266299c9d1335f6ec167666eb031:0` | 12 | identical from byte 79 onward |
| 6 | `a4709d7e125789276c6e95d668b1db307ec4f5d5223abf5c363b74aef912b955:0` | 13 | identical from byte 79 onward |
| 7 | `a86c134f8a34a4a0bbf5530090e728888fc8d9b7cee1c59f0270cbe7bd6b8bc7:0` | 28 | identical from byte 79 onward |

Contract UTXO #1 expanded below to show row-specific state bytes. Full
hex for rows 2–7 differs only in (a) the 4-byte height state at offset
1–4 and (b) the 4-byte vout index at offsets 42 and 74 (within the two
36-byte refs); everything from offset 79 through 240 is byte-identical
across all seven.

### 2.2 Byte-by-byte decode of UTXO #1

`scriptPubKey` of `f0a6a106…3b0d:0` (241 bytes total):

| Offset | Bytes | Opcode | Decoded meaning |
|-------:|-------|--------|-----------------|
| 0 | `04 de5f0100` | OP_PUSH4 | **height state** = 0x00015fde = 90,078 (this UTXO's current mint count) |
| 5 | `d8 8b87…943a4 01000000` | OP_PUSHINPUTREFSINGLETON | **contractRef** — the singleton that identifies *this* dMint contract slot (vout 1 of commit tx) |
| 42 | `d0 8b87…943a4 00000000` | OP_PUSHINPUTREF | **tokenRef** — the shared FT ref for this token (vout 0 of commit tx) |
| 79 | `03 688909` | OP_PUSH3 | **maxHeight** = 0x098968 = 628,328 (supply cap in units of "mints") |
| 83 | `03 50c300` | OP_PUSH3 | **reward** = 0x00c350 = 50,000 (photons per mint — and since a Glyph FT's token amount equals its photon value, this = 50,000 base units per successful mint) |
| 87 | `08 74da40a70d74da00` | OP_PUSH8 | **difficulty target** = 0x00da740da740da74 LE. Photonic-wallet's `dMintDiffToTarget(difficulty) = 0x7fffffffffffffff / difficulty`. Inverting this value (≈ 6.16e16) against the constant 0x7fffffffffffffff (≈ 9.22e18) gives **difficulty ≈ 150** (ESTIMATED, but matches the photonic-wallet formula mechanically) |
| 96 | `bd` | OP_STATESEPARATOR | End of state prologue, start of contract bytecode (runtime NOP) |
| 97 | `51 75` | OP_1 OP_DROP | Opening frame marker (required by V1 preimage layout) |
| 99 | `c0` | OP_INPUTINDEX | Push this input's index |
| 100 | `c8` | OP_OUTPOINTTXHASH | Push this input's prev-outpoint txid |
| 101 | `55 79` | OP_5 OP_PICK | Pick stack item 5 = contractRef (stateItemCount=3 + 2 → contractRefPickIndex=5) |
| 103 | `7e a8` | OP_CAT OP_SHA256 | Hash(outpointTxHash ‖ contractRef) — binds nonce to this specific contract slot |
| 105 | `59 79 59 79` | OP_9 OP_PICK OP_9 OP_PICK | Pick inputHash and outputHash from preimage stack (inputOutputPickIndex = stateItemCount + 3 + …; the V1 code hard-codes 9) |
| 109 | `7e a8 7e` | OP_CAT OP_SHA256 OP_CAT | Fold both hashes together |
| 112 | `5a 7a` | OP_10 OP_ROLL | Roll the nonce from preimage (nonceRollIndex = 10) |
| 114 | `7e` | OP_CAT | Concat nonce → final preimage string |
| 115 | `aa` | **OP_HASH256** | **PoW hash** — this is the algorithm selector. `aa` = SHA256d (algo 0). For BLAKE3 this would be `ee`, for K12 `ef` |
| 116 | `bc 0114 7f 77` | OP_REVERSEBYTES PUSH(0x14) OP_SPLIT OP_NIP | Drop the top 20 bytes of the reversed digest (keep only the low 12 bytes to compare) |
| 121 | `58 7f` | OP_8 OP_SPLIT | Split off the leading 8 bytes for the "leading-zero" check |
| 123 | `04 00000000 88` | PUSH(4 zeros) OP_EQUALVERIFY | Require the top 4 reversed bytes to be zero (standard work-prefix check) |
| 129 | `81 76 00 a2 69 a2 69` | OP_NEGATE OP_DUP OP_0 OP_GEQ OP_VERIFY OP_GEQ OP_VERIFY | Target-comparison epilogue — the pow-hash low 8 bytes must be ≤ the pushed target |
| 136 | `57 7a e5 00 a0 69` | OP_7 OP_ROLL OP_CODESCRIPTHASHOUTPUTCOUNT_UTXOS OP_0 OP_GREATERTHAN OP_VERIFY | ≥1 input with matching codescript hash (the contract input itself) |
| 142 | `56 7a e6 00 a0 69` | OP_6 OP_ROLL OP_CODESCRIPTHASHOUTPUTCOUNT_OUTPUTS OP_0 OP_GREATERTHAN OP_VERIFY | ≥1 output with matching codescript hash (the recreated contract) |
| 148 | `01 d0 53 79 7e 0c dec0e9aa76e378e4a269e69d 7e aa` | | Build the expected code-script prefix bytes (prepends `0xd0`, appends the 12-byte fingerprint `dec0e9aa76e378e4a269e69d`) then HASH256 — this is the codescript-hash pre-image the FT output must carry |
| 168 | `76 e4 7b 9d` | OP_DUP OP_CODESCRIPTHASHVALUESUM_OUTPUTS OP_ROT OP_NUMEQUALVERIFY | **FT conservation** — sum of output photons under this codescript must equal the value rolled from state (reward). This is the core covenant enforcing per-mint emission. |
| 172 | `54 7a 81 8b` | OP_4 OP_ROLL OP_NEGATE OP_NUMEQUALVERIFY | Verify the new contract's height equals old-height + 1 (encoded as `-oldHeight` NUMEQUALVERIFY pattern after the +1 fold) |
| 176 | `76 53 7a 9c 53 7a de 78 91 81 54 7a e6 93 9d 63` | | Branch: singleton‐continue (IF maxHeight not reached) vs burn (ELSE) — uses `OP_REFTYPE_UTXO` and `OP_CODESCRIPTHASHOUTPUTCOUNT_OUTPUTS` |
| 191 | `63 … 67 … 68` | OP_IF / OP_ELSE / OP_ENDIF | The full branch is 46 bytes (offsets 191–236) and covers: if still mintable → require an output that re-pushes the contract's `d8` singleton and has the contract codescript; else → require the singleton to appear in an `OP_RETURN 0x6a` burn output. |
| 238 | `6d 75 51` | OP_2DROP OP_DROP OP_1 | Final cleanup, leave TRUE on stack |

Total: **241 bytes**, **131 opcodes**.

### 2.3 Parameter values extracted from UTXO #1

| Parameter | Value | Source |
|-----------|-------|--------|
| height | 90,078 | state offset 0, 4-byte LE |
| contractRef | `8b87…943a4 | 01000000` | state offset 5, 36 bytes |
| tokenRef | `8b87…943a4 | 00000000` | state offset 42, 36 bytes |
| maxHeight | 628,328 | state offset 79, 3-byte LE |
| reward | 50,000 photons | state offset 83, 3-byte LE |
| target | `0x00da740da740da74` | state offset 87, 8-byte LE |
| difficulty (derived) | ≈ 150 | ESTIMATED: `0x7fffffffffffffff / target` |
| algorithm | sha256d | byte 115 = `0xaa` |
| DAA mode | fixed | no DAA bytecode between Part B and cleanup |
| V2 state items | 3 (height, maxHeight, reward+target) | matches V1 preimage layout, not V2 |

The seven sampled UTXOs diverge only on height (current mint count) and
contractRef-vout; all other parameters are identical. The contract is
**mid-mint**: with `maxHeight=628,328` and observed heights clustered
around 50k–90k, this deployment has minted roughly 12–15 % of the
token's supply.

---

## 3. Cross-comparison

Because the seven instances are siblings of one deployment, the
cross-compare exposes the **mutable-state slots** very cleanly:

**Common template** (byte-identical across all seven, offsets 79–240):

```
03 688909 03 50c300 08 74da40a70d74da00
bd
5175 c0c8 5579 7ea8 5979 5979 7ea8 7e 5a7a 7e
aa
bc01147f77587f 04 00000000 88
8176 00a269 a269
577a e500a069 567a e600a069
01d0 5379 7e 0c dec0e9aa76e378e4a269e69d 7e aa
76 e47b9d
547a 818b
76 537a 9c 537a de 78 91 81 547a e6 93 9d
63 5279 cd 01d8 5379 7e 01 6a 7e 88
67
78 de 51 9d 54 78 54 80 7e c0 eb 55 7f 77 7e
53 79 ec 78 88 53 79 ea c0 e9 88 53 79 cc 51 9d
75 68
6d 75 51
```

**Mutable slots**:

| Offset | Length | What changes each mint | How |
|-------:|:------:|------------------------|----|
| 1–4 | 4 B LE | `height` | incremented by 1 each mint |
| 42–45 | 4 B LE | contractRef vout index | **fixed per contract slot**, not per mint |
| 74–77 | 4 B LE | tokenRef vout index | **fixed per deployment** (always 0 here) |
| 6–37 | 32 B | contractRef txid | fixed per deployment |
| 43–74 | 32 B | tokenRef txid | fixed per deployment |
| 87–94 | 8 B LE | difficulty target | fixed at deploy time (this contract is `fixed` mode; for ASERT/LWMA this would be updated each mint, but see below) |

For a builder, the only thing that needs to move on each mint is the
4-byte height push at offsets 1–4. Everything else is static for the
contract's lifetime.

---

## 4. Trace of a single mint transaction

**Target mint tx**:
`146a4d688ba3fc1ea9588e406cc6104be2c9321738ea093d6db8e1b83581af3c`
(block 422,865; spends the previous contract UTXO
`8d318fba…fac5:0` and recreates it at the same codescript-hash).

### Inputs

- **vin[0]** — spends the previous contract UTXO
  `8d318fba…fac5:0`.
  `scriptSig.hex`: `04 9758f117 20 09b5b22a7f268ac5985a58231e80c00e0c67ee1ffec002d4fa0bda15de6f50a2 20 4c3a73d7a7daf3f7906a2b9e05707242241d14724b403c6ce2a860ffd5c521a6 00` (72 bytes).
  Decoded: `[nonce=0x17f15897, inputHash=09b5…0a2, outputHash=4c3a…1a6, OP_0]`.
  These four items are exactly what the preimage part A on the
  locking side expects: a 4-byte miner nonce, two 32-byte hashes
  covering the rest of the tx's inputs/outputs for binding, and an
  empty-bytes terminator that `OP_ROLL` drops.
- **vin[1]** — spends `8d318fba…fac5:3`, a plain P2PKH output from
  the previous tx's "miner change" line. scriptSig is a standard
  `<sig> <pubkey>` (106 bytes).

### Outputs

- **vout[0]** — 0.00000001 RXD (1 photon), 241-byte script = the
  **recreated dMint contract** with height bumped from 65,899 →
  65,900 (offset 1–4 changed from `6b010100` → `6c010100`; literally
  one byte differs, the rest of the script is bit-identical).
- **vout[1]** — 0.0005 RXD, 75 bytes:
  `76a9 14 e9aa4adbe3a3f07887d67d9cedae324711f053ef 88ac bd d0
  8b87…943a4 00000000 de c0 e9 aa 76 e3 78 e4 a2 69 e6 9d`.
  This is a **P2PKH-wrapped FT output**: the prologue is an ordinary
  `OP_DUP OP_HASH160 <pkh> OP_EQUALVERIFY OP_CHECKSIG` (the miner's
  reward address), then `OP_STATESEPARATOR`, then the
  `OP_PUSHINPUTREF tokenRef` (same 36-byte tokenRef as every mint
  for this token), then the 12-byte epilogue that the contract's
  `OP_CODESCRIPTHASHVALUESUM_OUTPUTS` step hashes to enforce
  conservation. **This is the FT the miner receives.**
- **vout[2]** — 0 RXD, `OP_RETURN 036d7367 09 'snk [r2w]'`. The
  15-byte message is the token's short "msg" marker. Interpretation
  of the `[r2w]` tag is UNVERIFIED from on-chain data alone.
- **vout[3]** — 117.007685 RXD P2PKH, `OP_DUP OP_HASH160
  800d0414e758f790a48ad0f2960d566ef56cd5bf OP_EQUALVERIFY
  OP_CHECKSIG`. Change back to the miner.

### What a Python implementation must reproduce

1. Build vout[0]'s 241-byte locking script with the **next** height
   value.
2. Build vout[1]'s 75-byte FT output = `p2pkh(pkh) || bd || d0||tokenRef
   || de c0 e9 aa 76 e3 78 e4 a2 69 e6 9d`.
3. The mint input's scriptSig provides `[nonce, inputHash, outputHash,
   OP_0]` in that order; the hash values bind the rest of the tx so
   the miner cannot substitute arbitrary outputs after finding a
   nonce.
4. The `reward` parameter (50,000 photons) must equal the FT output's
   value — enforced by `OP_CODESCRIPTHASHVALUESUM_OUTPUTS
   OP_NUMEQUALVERIFY` at bytecode offsets 168–171.

---

## 5. Open questions

- **Deploy reveal TX not yet isolated.** The commit is `a443d9df…878b`,
  but a backward walk from a recent mint (20 hops) did not reach the
  reveal; the mint chain for this token is longer than 20. The reveal
  tx would carry the original Glyph CBOR payload (`{v:2, p:[1,4],
  ticker, dmint:{…}}`) and is the authoritative source for the
  human-readable token name and the declared `diff`/`numContracts`. Not
  blocking for Python builder validation but would be nice to pull.
- **Cannot distinguish V1 vs V2 encoding from the guide alone.** The
  guide (`/home/eric/apps/radiant-glyph-guide/README.md` §dMint) and
  photonic-wallet (`dMintScript` in `packages/lib/src/script.ts`) ship
  the **V2** 10-state-item layout. The live contracts here are the
  **V1** 3-state-item layout. A Python builder needs both code paths
  and a switch. We did not find any V2-shaped contract on-chain in the
  ~3000 blocks inspected.
- **Nonce width and inputHash / outputHash construction** are only
  inferable from the unlock-side test vector. The scriptSig pushes a
  4-byte nonce (`9758f117` in the traced mint) and two 32-byte hashes.
  What exactly those hashes cover (which txin fields, which txout
  fields, in what serialisation) is not decidable from the locking
  script alone — it's implied by the `OP_SHA256 OP_CAT` chain but the
  builder needs photonic-wallet's `mine.ts` / miner code (not yet
  inspected for this report) to reproduce byte-for-byte.
- **Difficulty value 150 is ESTIMATED.** We derived it by applying
  photonic-wallet's `dMintDiffToTarget` formula to the on-chain target
  bytes; the actual `diff` field in the deploy CBOR was not read.
- **Ticker "snk".** The `OP_RETURN 036d7367 …` marker is a short
  per-mint receipt, not a ticker declaration. Calling this token
  "snk" is based on the string literal inside those receipts across
  all seven contract instances, but the authoritative ticker is in the
  deploy reveal's CBOR (see first bullet).

---

## Files referenced in this report

- Full node on VPS: `ssh ericadmin@89.117.20.219 -- sudo docker exec
  radiant-mainnet radiant-cli …` at tip = block 422,868.
- Photonic-wallet reference: `/tmp/photonic-wallet/packages/lib/src/script.ts`
  (lines 440–766) and `.../lib/src/mint.ts` (lines 388–460).
- MCP tool surface: `/home/eric/apps/radiant-mcp-server/src/index.ts`
  (lines 486–547).
- Glyph v2 guide (protocol context): `/home/eric/apps/radiant-glyph-guide/README.md`
  (lines 1310–1330 for protocol-ID table, 2820–2845 for V2 notes).
- Local helper scripts used to pull the data: `/tmp/decode_script.py`
  (byte decoder), `/tmp/fetch_scripts.py`, `/tmp/trace_mint.py`,
  `/tmp/find_diverse2.py` (all read-only RPC queries, no signing).
