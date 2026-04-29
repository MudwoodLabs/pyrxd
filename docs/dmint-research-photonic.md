# dMint research — reverse-engineered from Photonic Wallet

**Date:** 2026-04-22
**Source:** `RadiantBlockchain-Community/photonic-wallet` (master, shallow clone to `/tmp/photonic-wallet`)
**Purpose:** concrete reference for implementing `GlyphProtocol.DMINT = 4` in pyrxd.

---

## 0. TL;DR — one sentence

Photonic Wallet's "dMint" is **PoW distributed minting**, not "one mint-contract spent-and-recreated per call by an authorized minter." It deploys one or more **PoW-gated mint contract UTXOs** that anyone can spend by solving a hash puzzle; each spend decrements an on-chain `height` counter, produces an FT reward output locked by the token's `tokenRef`, and re-creates the contract UTXO with the next height. No authorized-minter concept; no per-block rate cap — the rate limiter is **PoW difficulty**. This design matches REP-3010 (Glyph v2 dMint).

This differs from the mental model in the research prompt ("max_supply / per_block_cap / authorized_minter"). The closest mapping:
- max_supply ≈ `MAX_HEIGHT × REWARD × numContracts` (plus `premine`)
- per-block cap ≈ `numContracts` concurrent solvers (can all be spent in same block if difficulty allows)
- authorized_minter = **none** — anyone who solves PoW mints

If pyrxd needs an "authorized minter / rate-limited fungible issuance" primitive, that's a **different design** than what Photonic implements. I flag this explicitly in §8.

---

## 1. Repo structure

**Workspace:** pnpm monorepo, `packages/{lib,app,cli}`. dMint lives almost entirely in `packages/lib`; CLI has **no** dMint support (confirmed by `grep -in dmint packages/cli/` → zero hits, plus `packages/cli/src/schemas.ts:8: // dmint not fully implemented yet`).

**Files that matter:**

| Path | Role |
|---|---|
| `packages/lib/src/contracts/powmint.rxd` | CashScript source for the PoW mint contract (authoritative spec of the covenant) |
| `packages/lib/src/script.ts` lines 442–766 | `dMintScript()` builder + helpers (`dMintDiffToTarget`, `buildDmintPreimageBytecodePartA`, `buildV2BytecodePartB`, `buildAsertDaaBytecode`, `buildLinearDaaBytecode`, plus the V2 bytecode constants) |
| `packages/lib/src/mint.ts` lines 368–484 | `createRevealOutputs` — deploy-tx construction path (how contract UTXOs are created alongside the glyph FT reveal) |
| `packages/lib/src/mint.ts` lines 200–217 | Commit output layout for dMint (reserves N extra p2pkh UTXOs for ref sequencing) |
| `packages/lib/src/types.ts` | `RevealDmintParams`, `DmintPayload`, `DmintAlgorithmId`, `DaaModeId` |
| `packages/lib/src/protocols.ts` | `GLYPH_DMINT = 4`; `PROTOCOL_REQUIREMENTS[DMINT] = [FT]` |
| `packages/lib/src/__tests__/dmint.test.ts` | Validates script encoding; asserts `OP_9 PICK`, `OP_13 PICK OP_13 PICK`, `OP_14 ROLL` for the 10-state V2 preimage |

**Not here:** the actual PoW solver / nonce grinder. Photonic Wallet **deploys** dMint contracts; mining them is the job of the external `glyph-miner` project (see [radiantblockchain.org — Photonic & Glyph Miner announcement](https://x.com/RXD_Community/status/1803836670141186394)). The deploy-side is fully in this repo; the mint-spend side is not.

**Surprise:** the CashScript source (`powmint.rxd`) and the hand-written hex builder (`dMintScript`) must be kept in sync; the V2 hex embeds `OP_BLAKE3`/`OP_K12` (0xee, 0xef), which the `.rxd` source does not express (it only has `hash256`). The `.rxd` file is v1 legacy reference; the **source of truth for v2 is the hex in `script.ts`**.

---

## 2. Mint-contract locking script — byte layout

A deployed dMint contract UTXO's `scriptPubKey` is built as `stateScript || 0xbd || contractBytecode`. The `0xbd` is `OP_STATESEPARATOR`. The same code bytecode is used by all dMint contracts for a given (algorithm, daaMode); only the state section differs per contract (so `codeScriptHash` is a useful index).

### 2.1 State script (V2, 10 items — `script.ts` lines 745–758)

Pushed in this exact order (all as script data pushes):

| # | Item | Push encoding | Bytes | Mutable? |
|---|---|---|---|---|
| 0 | `height` | `push4bytes(n)` = `04 <uint32_LE>` | 5 | **YES** (increments each spend) |
| 1 | `contractRef` (36B outpoint) prefixed `0xd8` | `0x25` (37-byte push) + `d8` + `<36B ref>` = literal `25 d8 <36B>` | 38 | no |
| 2 | `tokenRef` (36B outpoint) prefixed `0xd0` | `0x25` (37-byte push) + `d0` + `<36B ref>` | 38 | no |
| 3 | `maxHeight` | `pushMinimal(n)` | 1–6 | no |
| 4 | `reward` (per solve) | `pushMinimal` | 1–6 | no |
| 5 | `algoId` (0=sha256d, 1=blake3, 2=k12) | `pushMinimal` | 1 | no |
| 6 | `daaId` (0=fixed, 1=epoch, 2=asert, 3=lwma, 4=schedule) | `pushMinimal` | 1 | no |
| 7 | `targetTime` (seconds/block) | `pushMinimal` | 1–6 | no |
| 8 | `lastTime` | `push4bytes` = `04 <uint32_LE>` | 5 | in some DAA modes |
| 9 | `target` (8-byte VmNumber) | `pushMinimal(bigint)` | 1–10 | in adaptive DAA modes |

**Important — why items 1 & 2 use `0xd8` / `0xd0` prefixes:** those are `OP_PUSHINPUTREFSINGLETON` (`0xd8`) and `OP_PUSHINPUTREF` (`0xd0`) opcodes. The whole 37-byte push is a **data push of the opcode + 36-byte outpoint**; those bytes will be interpreted as push-data inside the state script but the contract logic then **concatenates that 37-byte blob into the new state script on respend**, preserving the ref-declaration structure. This is the trick that makes the covenant work: ref opcodes appear in state-script as data, but they are copied verbatim into the rebuilt state and re-executed next time.

### 2.2 Separator

One byte: `0xbd` (`OP_STATESEPARATOR`).

### 2.3 Code bytecode — three concatenated parts

```
contractBytecode = PART_A  ||  powHashOp  ||  PART_B  ||  PART_C
```

where `PART_B = V2_B1 || V2_B2 || daaBytecode || V2_B4`.

#### PART A — preimage assembly (`buildDmintPreimageBytecodePartA`, lines 447–473)

With `stateItemCount = 10`, the indices are `contractRefPickIndex=9`, `inputOutputPickIndex=13`, `nonceRollIndex=14`.

Hex sequence:

```
51              OP_1                           (push 1 = `outputIndex` target pos — scriptSig pushes nonce, inputHash, outputHash, outputIndex; OP_1 here starts the "take output index" maneuver)
75              OP_DROP
c8              OP_OUTPOINTTXHASH              (pushes this UTXO's prev-txid)
59              OP_9                           (PICK index for contractRef)
79              OP_PICK
7e              OP_CAT                         (txHash || contractRef)
a8              OP_SHA256                      (= sha256(outpoint.txid || contractRef))
5d              OP_13                          (PICK index for inputHash)
79              OP_PICK
5d              OP_13                          (PICK index for outputHash — now one slot deeper after prior PICK)
79              OP_PICK
7e              OP_CAT                         (inputHash || outputHash)
a8              OP_SHA256                      (= sha256(inputHash || outputHash))
7e              OP_CAT                         (first-sha256 || second-sha256)
5e              OP_14                          (ROLL index for nonce — rolls nonce from bottom)
7a              OP_ROLL
7e              OP_CAT                         (full preimage: 32 + 32 + 4 = 68 bytes)
```

The `dmint.test.ts` test at line 384 asserts the ASM window:
```
OP_OUTPOINTTXHASH OP_9 OP_PICK ... OP_13 OP_PICK OP_13 OP_PICK ... OP_14 OP_ROLL
```

#### PoW hash opcode (1 byte, line 735–740)

| Algo | Opcode |
|---|---|
| sha256d | `0xaa` (`OP_HASH256`) |
| blake3 | `0xee` (`OP_BLAKE3`) |
| k12 | `0xef` (`OP_K12`) |

#### PART B.1 — hash → value extraction (line 616)

```
bc             OP_REVERSEBYTES
01 14          push 0x14 (= 20)
7f             OP_SPLIT         → [first20, last12]
77             OP_NIP           → drop first20 → stack top: last12
58             OP_8
7f             OP_SPLIT         → [next8, firstFour]
04 00000000    push 4-byte zero
88             OP_EQUALVERIFY   → require firstFour == 00000000
81             OP_NEGATE?  actually: here 81 is OP_NEGATE — but context suggests this is a stack ops. Looking at literal bytes 040000000088817600a269:
               04 00000000 = push <00000000>
               88 = OP_EQUALVERIFY
               81 = OP_NEGATE (...but used differently here)
               76 = OP_DUP
               00 = OP_0 / push empty
               a2 = OP_GREATERTHANOREQUAL
               69 = OP_VERIFY
               → "dup, push 0, ≥, VERIFY" = require value >= 0  (the next8 as signed int)
```

So B.1 byte-for-byte: `bc 01 14 7f 77 58 7f 04 00000000 88 81 76 00 a2 69` — reverse bytes, split off first 20, split next 8, require first-4-bytes-are-0, then require positive value.

#### PART B.2 — target check (line 618)

```
51  OP_1
79  OP_PICK     (pick target from state)
7c  OP_SWAP     ([value, target])
a2  OP_GREATERTHANOREQUAL   (target ≥ value)
69  OP_VERIFY
```

Hex: `51 79 7c a2 69`. Wait — checking order: contract requires `value <= target`, which is `target >= value`. With stack `[…, value]` after B.1, `OP_1 PICK` copies an element 1 deep = whatever was 2nd-to-top… Let me just trust `dmint.test.ts` which passes; the literal bytes are what matter.

**Literal:** `51797ca269`.

#### DAA bytecode — conditional, 0 bytes for `fixed`

For `asert` (`buildAsertDaaBytecode`, lines 627–666) — ~50 bytes of ops using `OP_TXLOCKTIME (c5)`, OP_SUB, OP_DIV, clamping, OP_LSHIFT/RSHIFT on target.

For `lwma` (Linear DAA, lines 668–685) — ~15 bytes, `new_target = old_target * time_delta / targetTime`, clamp ≥ 1.

For `fixed` / `epoch` / `schedule` — empty string (treated as fixed at the contract level; schedule would be enforced by the miner presumably).

#### PART B.4 — cleanup (line 620)

Hex: `7575757575` — five `OP_DROP` to pop the 5 V2 extras (target, lastTime, targetTime, daaMode, algoId) off the altstack/mainstack.

#### PART C — output validation (line 622)

**This is the covenant.** It's 177 bytes, partially hand-coded, literal:

```
a2 69                   (≥, VERIFY — residual)
57 7a e5 00 a0 69       OP_7 OP_ROLL OP_INPUTINDEX-something... require inputs.codeScriptCount(inputHash) > 0
56 7a e6 00 a0 69       OP_6 OP_ROLL ... require outputs.codeScriptCount(outputHash) > 0
01 d0 53 79 7e          push 0xd0 (OP_PUSHINPUTREF), OP_3 PICK tokenRef, OP_CAT → 0xd0||tokenRef
0c dec0e9aa76e378e4a269e69d 7e   push 12-byte FT code suffix, OP_CAT → full FT code script = d0||tokenRef||<suffix>
aa                      OP_HASH256 → rewardCSH
76                      OP_DUP
e4                      OP_CODESCRIPTHASHVALUESUM_OUTPUTS → sum of values in outputs with that CSH
7b                      OP_ROT
9d                      OP_NUMEQUALVERIFY   — require reward_sum == REWARD
54 7a 81 8b             OP_4 OP_ROLL OP_NEGATE OP_ADD1  (heightBytes → newHeight)
76 53 7a 9c             OP_DUP OP_3 PICK OP_NUMEQUAL
53 7a de 78 91 81       OP_3 PICK OP_CODESCRIPTHASHOUTPUTCOUNT... (finalMint boolean + refOutputCount calc)
54 7a e6 93 9d          OP_4 OP_ROLL OP_CODESCRIPTHASHOUTPUTCOUNT_OUTPUTS(rewardCSH) OP_ADD OP_NUMEQUALVERIFY
63                      OP_IF (finalMint branch)
  52 79 cd              OP_2 PICK OP_OUTPUTBYTECODE
  01 d8 53 79 7e        push 0xd8, OP_3 PICK contractRef, OP_CAT
  01 6a 7e              push 0x6a (OP_RETURN), OP_CAT
  88                    OP_EQUALVERIFY  — output[outputIndex].lockingBytecode == 0xd8||contractRef||6a (burn)
67                      OP_ELSE (normal branch, recreate contract)
  78 de 51 9d           OP_SWAP OP_CODESCRIPTHASHOUTPUTCOUNT ... == 1  (contractRef appears in exactly one output)
  54 78 54 80 7e        OP_4 ROLL newHeight, build 04||<4 bytes newHeight>
  c0 eb 55 7f 77        OP_INPUTINDEX OP_STATESCRIPTBYTECODE_UTXO OP_5 OP_SPLIT OP_NIP  — take everything after first 5 bytes of current state script
  7e                    OP_CAT   → newState = 04||<newHeight>||<rest of state>
  53 79 ec              OP_3 PICK OP_STATESCRIPTBYTECODE_OUTPUT
  78 88                 OP_SWAP OP_EQUALVERIFY  — output[outputIndex].stateScript == newState
  53 79 ea c0 e9 88     OP_3 PICK OP_CODESCRIPTBYTECODE_OUTPUT OP_INPUTINDEX OP_CODESCRIPTBYTECODE_UTXO OP_EQUALVERIFY  — code script unchanged
  53 79 cc 51 9d        OP_3 PICK OP_OUTPUTVALUE OP_1 OP_NUMEQUALVERIFY  — value == 1
  75 68                 OP_DROP OP_ENDIF
6d 75 51                OP_2DROP OP_DROP OP_1
```

**Literal hex** (the authoritative bytes Photonic ships):

```
a269577ae500a069567ae600a06901d053797e0cdec0e9aa76e378e4a269e69d7eaa76e47b9d547a818b76537a9c537ade789181547ae6939d635279cd01d853797e016a7e886778de519d547854807ec0eb557f777e5379ec78885379eac0e9885379cc519d75686d7551
```

My disassembly above is a best-effort walkthrough; **treat the literal hex as canonical** and the `powmint.rxd` CashScript as the semantic reference.

### 2.4 Mutable state slot

The **only** mutable byte-offset in the state script is item 0 (`height`), at the very start. Every spend:
1. Reads current `height` (4 LE bytes at offset 1, after the `0x04` push-length prefix).
2. Increments it to produce `newHeight`.
3. Builds `newState = 0x04 || <newHeight LE32> || <original state script bytes 5..end>`.
4. Asserts output's state script equals `newState`.

So the covenant only mutates `height`; everything else (refs, maxHeight, reward, algo, daa params, target) is frozen — including `target`, meaning in `fixed` DAA the difficulty never changes. For adaptive DAA (asert/lwma) the `target` is recomputed but since the state-script copy is `split(5)[1]` (preserves bytes 5..end verbatim), the **only way** `target` could actually mutate would be via a different rebuild formula. Looking at the literal C part: the rebuild uses `OP_5 SPLIT NIP` (byte 5 onward copied verbatim), so in Photonic's implementation **even asert/lwma DAA does not actually mutate the stored target** — the DAA bytecode computes a new value that's used *within* the current spend but isn't persisted. This may be a simplification; a full adaptive-DAA dMint would need to persist new target + lastTime. Flag for pyrxd authors: **audit this against REP-3010 before claiming asert/lwma DAA works end-to-end**.

---

## 3. Parameter encoding

| Parameter | Type | Encoding | Notes |
|---|---|---|---|
| `height` | uint32 | 4-byte LE, explicit `0x04` push prefix (`push4bytes`) | fixed width — covenant splits at byte 5 |
| `contractRef` | 36-byte outpoint | 37-byte push: `d8` + 36 bytes; raw bytes reversed-endian per `Outpoint.reverse()` | "NOTE: All ref inputs for script functions must be little-endian" (`script.ts:16`) |
| `tokenRef` | 36-byte outpoint | 37-byte push: `d0` + 36 bytes; little-endian | same |
| `maxHeight` | int | minimal push (OP_0..OP_16 or len-prefixed) | via `pushMinimal` |
| `reward` | int (photons) | minimal push | |
| `algoId` | byte | minimal push (OP_0..OP_2) | 0=sha256d, 1=blake3, 2=k12; higher (argon2, randomx) defined but not wired |
| `daaId` | byte | minimal push (OP_0..OP_4) | |
| `targetTime` | int (seconds) | minimal push | default 60 |
| `lastTime` | uint32 | 4-byte LE push | used by asert/lwma |
| `target` | bigint (signed VM number, ≤ `0x7fffffffffffffff`) | minimal VM-number push via libauth `bigIntToVmNumber` | `MAX_TARGET = 0x7fffffffffffffffn`, `target = MAX_TARGET / difficulty` |

An outpoint ref is `<32-byte txid>||<4-byte vout>` — reversed to little-endian on the way into the script. `Outpoint.reverse().ref()` is the canonical transform in Photonic (see `mint.ts:406-408`).

---

## 4. Deploy-tx construction

### 4.1 Two-phase commit/reveal

Glyph v2 tokens are deployed via **commit → reveal** (not dMint-specific; all glyphs work this way). The commit tx locks a small p2sh-ish output whose script includes `hash256(payload)` check + glyph magic `gly`. The reveal tx spends that commit UTXO, pushing the raw payload in the scriptSig so verifiers can hash it and confirm.

### 4.2 dMint-specific commit outputs (`mint.ts:203-209`)

When `deployMethod === "dmint"` and `contract === "ft"`:
- Commit tx emits the standard FT commit output at `vout[0]` (value 1).
- Then **N extra p2pkh outputs** (N = `numContracts`) at `vout[1..N]`, value 1 each. Each of these is a **ref seed** — spending it in the reveal tx creates a new input-ref that becomes a `contractRef`.

### 4.3 Reveal tx (`mint.ts:398-461`)

Inputs:
- `[0]` = commit UTXO (FT commit, scriptSig pushes the payload)
- `[1..N]` = the N p2pkh ref-seed UTXOs from the commit tx, spent with p2pkh signatures

Outputs (order matters):
- `[0..N-1]` = N dMint contract UTXOs, value 1 each, script = `dMintScript(height=0, contractRef=Outpoint(commit.txid, 1+i), tokenRef=Outpoint(commit.txid, 0), …)` — note `contractRef` is derived from each ref-seed input (vout offset = 1+i), and `tokenRef` is derived from the commit-UTXO vout 0.
- `[N]` (optional) = premine FT output with script = `ftScript(address, tokenRef)` and value = `premine`.

`Outpoint` is reversed (LE) before embedding — see `mint.ts:406-408`: `Outpoint.fromUTXO(txid, vout+1+i).reverse().ref()`.

### 4.4 Ref establishment

The `tokenRef` (the permanent FT identity) = reversed outpoint of the commit tx's vout 0, established the moment the reveal tx confirms (the FT commit output had no ref; the reveal creates the ref by pushing `OP_PUSHINPUTREF <tokenRef>` somewhere — in this case, indirectly, by having each dMint contract UTXO contain `0xd0 <tokenRef>` as state data that the covenant later replicates into the FT reward output).

Each `contractRef[i]` = reversed outpoint of commit tx's vout (1+i), "minted" by the reveal tx consuming that p2pkh output and creating output `i` with `OP_PUSHINPUTREFSINGLETON <contractRef[i]>` in its state.

**This is subtle:** the reveal tx doesn't explicitly push ref opcodes in *its own* output scripts — the ref opcodes live *inside state script pushes* (items 1 and 2 above). Radiant's ref machinery recognizes `d8<36B>` and `d0<36B>` as ref declarations wherever they appear in a script. Because `OP_STATESEPARATOR` divides state from code, and refs declared pre-separator still bind to the UTXO, this works.

---

## 5. Mint-spend tx construction (the "mining" transaction)

Photonic does **not** implement this (CLI has no dmint, app only deploys). Reconstructed from `powmint.rxd` + script layout:

### 5.1 scriptSig (consuming a dMint contract UTXO)

The contract's `function(...)` signature expects 4 args pushed in order (CashScript argument → stack is bottom-up, so scriptSig pushes in reverse of declaration... actually CashScript convention: scriptSig pushes **last-arg first**; but Photonic's preimage reconstruction in §2.3 PART A assumes stack bottom-to-top `nonce, inputHash, outputHash, outputIndex, <stateItems>, outpointTxHash` after `OP_OUTPOINTTXHASH`. That means the scriptSig pushes in order: `outputIndex`, `outputHash`, `inputHash`, `nonce` — so stack after scriptSig is `[outputIndex, outputHash, inputHash, nonce]` with nonce on top). Then when the locking script executes its 10 state-item pushes, all 10 items land on top; then `OP_OUTPOINTTXHASH` adds the 11th; then PART A picks/rolls to reassemble the preimage.

scriptSig pushes (bottom-to-top):
1. `<outputIndex>` — the vout index in this spend where the recreated contract UTXO lives
2. `<outputHash>` — a 32-byte hash referenced by `tx.outputs.codeScriptCount(outputHash) > 0` — this is the codeScriptHash of some expected output (likely the FT reward code-script hash; check against `powmint.rxd` line 33)
3. `<inputHash>` — codeScriptHash of some expected input (line 32)
4. `<nonce>` — 4 bytes

Looking again at `powmint.rxd` lines 31–33: `tx.inputs.codeScriptCount(inputHash) > 0` and `tx.outputs.codeScriptCount(outputHash) > 0` — the scriptSig lets the miner **pick which input's/output's code script hash** to hash into the PoW preimage. This is a degree of freedom that miners use to make their PoW work valid for a specific tx structure.

### 5.2 Output layout for a mint spend

- `output[outputIndex]` = recreated dMint contract UTXO with incremented `height`. Value = 1. Script = same code, state rebuilt by covenant check.
- One or more outputs with the **reward FT code-script** (`d0 || tokenRef || dec0e9aa76e378e4a269e69d`) totaling `reward` photons of value. These are the newly-minted FT outputs. The miner chooses the state-script prefix (e.g. their own p2pkh), making them the effective owner.
- On final mint (height+1 == maxHeight), instead of recreating the contract, output[outputIndex] = `0xd8 || contractRef || 0x6a` = OP_PUSHINPUTREFSINGLETON + ref + OP_RETURN (unspendable burn).

### 5.3 Single-tx, not commit/reveal

dMint spending is **one tx**: spend contract UTXO → produce FT reward + new contract UTXO. No commit/reveal on the mint path. Commit/reveal is only on initial **deploy**.

---

## 6. Covenant enforcement — which opcodes

Radiant-specific opcodes used by the PoW covenant:

| Opcode | Hex | Purpose |
|---|---|---|
| `OP_STATESEPARATOR` | `bd` | Separates mutable state from code-script hash |
| `OP_PUSHINPUTREF` | `d0` | Declares a "normal" ref (FT-style) |
| `OP_PUSHINPUTREFSINGLETON` | `d8` | Declares a "singleton" ref (NFT-style — the contract itself) |
| `OP_REQUIREINPUTREF` | `d1` | (Not in dMint, but used elsewhere) |
| `OP_STATESCRIPTBYTECODE_UTXO` | `eb` | Gets current input's state script |
| `OP_STATESCRIPTBYTECODE_OUTPUT` | `ec` | Gets an output's state script |
| `OP_CODESCRIPTBYTECODE_UTXO` | `e9` | Gets current input's code script |
| `OP_CODESCRIPTBYTECODE_OUTPUT` | `ea` | Gets an output's code script |
| `OP_OUTPUTBYTECODE` | `cd` | Gets full output locking bytecode |
| `OP_OUTPOINTTXHASH` | `c8` | Gets txid of this input's outpoint |
| `OP_CODESCRIPTHASHVALUESUM_OUTPUTS` | `e4` | Sum values of outputs matching a code-script hash |
| `OP_CODESCRIPTHASHOUTPUTCOUNT_OUTPUTS` | `e6` | Count outputs matching a code-script hash |
| `OP_REFOUTPUTCOUNT_OUTPUTS` | `de` | Count outputs that declare a given ref |
| `OP_TXLOCKTIME` | `c5` | Current tx's locktime (used by asert DAA as "currentTime") |
| `OP_BLAKE3` | `ee` | Blake3 hash (V2 hard fork) |
| `OP_K12` | `ef` | KangarooTwelve hash (V2 hard fork) |

The "spend-and-recreate" invariant is enforced by PART C (see §2.3) using:
- `OP_STATESCRIPTBYTECODE_OUTPUT` + `OP_EQUALVERIFY` — new state must equal computed `newState`
- `OP_CODESCRIPTBYTECODE_OUTPUT` vs `OP_CODESCRIPTBYTECODE_UTXO` + `OP_EQUALVERIFY` — code script frozen
- `OP_OUTPUTVALUE == 1` — UTXO dust value fixed
- `OP_REFOUTPUTCOUNT_OUTPUTS(contractRef) == 1` — singleton contract ref appears in exactly one output

For reward enforcement:
- `OP_CODESCRIPTHASHVALUESUM_OUTPUTS(rewardCSH) == REWARD` — exactly `REWARD` photons land in FT outputs
- `rewardCSH = hash256(d0 || tokenRef || dec0e9aa76e378e4a269e69d)` (computed in-script)

For final-mint burn:
- `tx.outputs[outputIndex].lockingBytecode == 0xd8 || contractRef || 0x6a` — contract burns itself to unspendable OP_RETURN output.

---

## 7. Gotchas & design decisions

1. **Ref endianness.** All refs in scripts are **little-endian** reversed outpoints (`script.ts:16` comment, `Outpoint.reverse()` calls everywhere). Python will need an `Outpoint.reverse_le()` helper. An Outpoint is `txid(32B) || vout(4B LE)` — but `txid` itself is typically displayed big-endian hex, so "reverse" means a full 36-byte reversal in some code paths. Trace carefully — Photonic's `Outpoint.ts` has both `reverse()` and `ref()` methods; check which is what.
2. **Minimal pushes are mandatory.** Test `hasNonMinimalDataPush` rejects any data push that should've been OP_0..OP_16. Use the exact `pushMinimal` logic (lines 419–436): OP_0 for 0, OP_1NEGATE for −1, OP_1..OP_16 for 1..16, else libauth `encodeDataPush(bigIntToVmNumber(n))`.
3. **VmNumber encoding** (for `target`, `maxHeight`, etc. when > 16): signed little-endian with sign bit in the high byte; length is minimal. Use a known-good BitcoinScript-number encoder. libauth's `bigIntToVmNumber` is reference.
4. **Fixed-width `height` is load-bearing.** The covenant does `OP_5 SPLIT NIP` to preserve bytes 5..end of the old state, so `height` MUST be pushed as exactly `04 <4 bytes LE>` (5 bytes total). Don't use `pushMinimal` for height.
5. **Same for `lastTime`** — also pushed as `push4bytes` for the same reason if DAA code reads it at a fixed offset. (Verify with a test roundtrip.)
6. **codeScriptHash calculation** (for rewardCSH): `hash256` in Radiant Script = SHA256(SHA256(x)), but Radiant also has a single-SHA256 variant in some contexts. The rewardCSH in the contract is `hash256(<ref-declaring FT code prefix>)`. In Python: `hashlib.sha256(hashlib.sha256(code_bytes).digest()).digest()`. See `script.ts:codeScriptHash()` line 409 which uses double-SHA256.
7. **`OP_BLAKE3` / `OP_K12` activation.** The Mint UI (line 1692) warns: "V2 hard fork, block 410,000. Contracts deployed before activation will not be mineable." Python builders should validate chain height before emitting blake3/k12 contracts on mainnet, or at least document the caveat.
8. **Script size.** With 10 state items, typical state script ≈ 100–130 bytes; code bytecode ≈ 250 bytes (fixed DAA) up to ~310 (asert). Total locking script well under the 10 kB standardness limit.
9. **Target packing.** `MAX_TARGET = 0x7fffffffffffffffn` (63-bit, since VmNumber is signed and must be positive). `target = MAX_TARGET // difficulty`. Pushed as a VmNumber (variable 1–8 bytes minimal).
10. **No authorized-minter field.** If you need gated minting, you'd layer a `OP_CHECKSIG` requirement on the contract — not present in Photonic's dMint. Consider whether your use case really needs PoW-dMint or a different primitive.
11. **"Mint contract destroyed" is NOT the same as "supply exhausted".** `maxHeight * reward` is the theoretical max per contract; if a miner never produces the final spend, some supply is orphaned. Premine is fully minted at deploy time (regardless of PoW).
12. **Batch deploy with `numContracts > 1`** multiplies effective mint rate. Each contract mines independently; all share the same `tokenRef` so their FT outputs are fungible.

---

## 8. Ready-to-port API sketch for pyrxd

```python
# pyrxd/glyph/dmint.py

from dataclasses import dataclass
from enum import IntEnum
from typing import Optional, Literal

class DmintAlgo(IntEnum):
    SHA256D = 0
    BLAKE3 = 1
    K12 = 2
    # 3 (Argon2Light) / 4 (RandomX) reserved; not wired in Photonic

class DaaMode(IntEnum):
    FIXED = 0
    EPOCH = 1
    ASERT = 2
    LWMA = 3
    SCHEDULE = 4

@dataclass
class DaaParams:
    target_block_time: int = 60
    half_life: Optional[int] = None       # asert
    window_size: Optional[int] = None     # lwma
    epoch_length: Optional[int] = None    # epoch
    max_adjustment: Optional[int] = None  # epoch
    schedule: Optional[list[tuple[int, int]]] = None  # [(height, difficulty), ...]

# ---- low-level script builder (deploy side) ----

def dmint_contract_locking_script(
    height: int,                  # usually 0 at deploy
    contract_ref: bytes,          # 36 bytes, LE outpoint
    token_ref: bytes,             # 36 bytes, LE outpoint
    max_height: int,
    reward: int,
    target: int,                  # = MAX_TARGET // difficulty, 1 <= target <= 0x7fffffffffffffff
    algo: DmintAlgo = DmintAlgo.SHA256D,
    daa_mode: DaaMode = DaaMode.FIXED,
    daa_params: Optional[DaaParams] = None,
    last_time: int = 0,
) -> bytes:
    """
    Build a dMint PoW-mint contract locking script per Glyph v2 (REP-3010).
    Port of Photonic Wallet's script.ts:dMintScript().
    Layout: <state 10 items> || OP_STATESEPARATOR(0xbd) || <code bytecode>
    """
    ...

def dmint_difficulty_to_target(difficulty: int) -> int:
    """MAX_TARGET // difficulty, where MAX_TARGET = 0x7fffffffffffffff."""
    return 0x7fffffffffffffff // difficulty

# ---- deploy tx orchestration (high level) ----

@dataclass
class DmintDeploySpec:
    num_contracts: int            # parallel PoW contracts (share tokenRef)
    max_height: int               # per-contract
    reward: int                   # photons per successful mint
    premine: int                  # photons minted directly at deploy
    difficulty: int               # used to derive target
    algo: DmintAlgo = DmintAlgo.SHA256D
    daa_mode: DaaMode = DaaMode.FIXED
    daa_params: Optional[DaaParams] = None

def build_dmint_deploy_reveal_tx(
    commit_utxo: Utxo,            # from commit phase
    ref_seed_utxos: list[Utxo],   # len == spec.num_contracts
    creator_address: str,
    spec: DmintDeploySpec,
    glyph_payload: bytes,         # CBOR-encoded SmartTokenPayload
    fee_utxos: list[Utxo],
    wif: str,
) -> Transaction:
    """
    Port of mint.ts:createRevealOutputs + revealDirect for dmint branch.
    Emits: [N dmint contracts, optional premine FT, optional change].
    """
    ...

# ---- mining / spend side (NOT in Photonic — must build from scratch) ----

@dataclass
class DmintSolution:
    nonce: bytes                  # 4 bytes
    input_hash: bytes             # 32 bytes (code-script-hash of an input)
    output_hash: bytes            # 32 bytes (code-script-hash of an output)
    output_index: int             # vout of the recreated contract UTXO

def solve_dmint_pow(
    contract_utxo: Utxo,
    target: int,
    algo: DmintAlgo,
    planned_input_hash: bytes,
    planned_output_hash: bytes,
    planned_output_index: int,
    max_iters: int = 2**32,
) -> Optional[DmintSolution]:
    """
    Grind nonce until:
        h = reverse(HASH(sha256(outpointTxHash || contractRef) ||
                        sha256(inputHash || outputHash) ||
                        nonce))
        h[20:24] == 00 00 00 00
        int(h[24:32] as signed LE) in [0, target]
    HASH is SHA256D / BLAKE3 / K12 per algo.
    """
    ...

def build_dmint_spend_tx(
    contract_utxo: Utxo,
    solution: DmintSolution,
    recipient_address: str,       # who gets the reward FT
    fee_utxos: list[Utxo],
    wif: str,
) -> Transaction:
    """
    Produce the 'mint' tx:
      in[0]  = contract_utxo, scriptSig = <outputIndex><outputHash><inputHash><nonce>
      out[outputIndex] = recreated contract (height+1) OR burn (0xd8||ref||0x6a) if final
      out[k] = FT reward to recipient, code-script = 0xd0||tokenRef||dec0e9aa76e378e4a269e69d,
               state-script = p2pkh(recipient), value = REWARD
      plus change
    """
    ...
```

**Open questions for pyrxd design:**
- Do you want *Photonic-style PoW dMint*, or *the gated-minter dMint sketched in the research prompt*? These are different primitives. Photonic = REP-3010 = what's deployed on mainnet today.
- Do you need on-chain adaptive DAA (asert/lwma)? Photonic's implementation may not actually persist updated `target` across spends (see §2.4 note). `fixed` mode is the safe default.
- Will pyrxd ship its own PoW solver (nonce grinder)? Photonic doesn't — it relies on the external `glyph-miner`. If you want a self-contained SDK, you'll need to port or reimplement that miner. Grinding sha256d at Python speed is ~200k H/s on a CPU — usable for tiny difficulty, useless above ~10^6.

---

## 9. What to read next (and what to not trust)

- **Trust:** `script.ts:dMintScript()`, `mint.ts:createRevealOutputs` dmint branch, `dmint.test.ts`.
- **Trust with caution:** `powmint.rxd` (V1 reference; missing blake3/k12; may drift from hex).
- **Do not trust:** my PART C byte-level disassembly above where it uses inline comments — the literal hex is authoritative; my comments are best-effort. Before writing a Python builder, disassemble the hex with a Radiant-aware disassembler and cross-check against `powmint.rxd` semantics.
- **Not in repo:** the PoW solver. Clone `https://github.com/Radiant-Core/glyph-miner` (or the community fork) for the nonce-grinding side.
- **Authoritative spec:** REP-3010 (Glyph v2 dMint) on radiantblockchain.org — should be consulted before shipping.

---

## Provenance note

All concrete byte sequences, opcode mappings, and line-number citations in this report come from reading:
- `/tmp/photonic-wallet/packages/lib/src/script.ts` (lines 1–766 read in full)
- `/tmp/photonic-wallet/packages/lib/src/contracts/powmint.rxd` (58 lines, full)
- `/tmp/photonic-wallet/packages/lib/src/mint.ts` (lines 1–484 read)
- `/tmp/photonic-wallet/packages/lib/src/types.ts` (full)
- `/tmp/photonic-wallet/packages/lib/src/protocols.ts` (full)
- `/tmp/photonic-wallet/packages/lib/src/__tests__/dmint.test.ts` (full)

Numbers / claims NOT verified by reading but stated as design intuition or per-Radiant-convention are flagged as "likely" / "presumably" in the text. **The "V2 hard fork block 410,000"** claim is read directly from the Mint.tsx UI string (line 1692). **The adaptive-DAA target-persistence gap** (§2.4, §7 point 1 under asert/lwma) is my reading of the covenant; a pyrxd implementer should independently verify by running `dMintScript` with `asert` params and stepping through PART C on paper.

---

## 9. Follow-up: all-at-once / premine mint feasibility

**TL;DR: Yes — Photonic's dMint *already* supports this. A `premine` field on the deploy tx creates an FT output holding any amount (up to and including full supply) in the issuer's wallet at deploy time, outside the covenant. You do not need to touch the PoW contract at all for a 100%-at-deploy model.**

### 9.1 The `premine` field is a first-class, unconstrained parameter

`packages/lib/src/types.ts:68-78` defines `RevealDmintParams` with `premine: number` as a required field. It lives alongside `maxHeight`, `reward`, `difficulty` — but the covenant never reads it. It is purely a reveal-tx output amount.

`packages/lib/src/mint.ts:430-439` is the entire implementation:

```ts
if (dmintParams.premine > 0) {
  outputs.push({
    script: ftScript(deployParams.address, tokenRef),
    value: dmintParams.premine,
  });
}
```

`ftScript(address, tokenRef)` is a **plain P2PKH-style FT output** carrying `tokenRef` — not a dMint contract output. The issuer's private key controls it immediately. There are no bounds checks on `premine` anywhere in `mint.ts` or `script.ts`: no `require(premine <= maxHeight * reward)`, no protocol-level supply cap. The deploy tx can attach `premine = 21_000_000_000` (or whatever the issuer wants) and it just works.

### 9.2 Recommended premine-only configuration

To get "mint 100% at deploy, zero PoW minting afterward," set on `RevealDmintParams`:

| field | value | why |
|---|---|---|
| `premine` | `TOTAL_SUPPLY` | all tokens land in issuer's wallet at deploy |
| `numContracts` | `1` | one orphan covenant; never spent |
| `maxHeight` | `1` | only valid spend is the `finalMint` burn path |
| `reward` | `0` | even if somehow spent, no new tokens emit |
| `difficulty` | `1` | irrelevant — contract UTXO just sits there |

The dMint covenant UTXO is still created at the same reveal tx (`mint.ts:402-425`) but **no one ever needs to spend it**. It sits at dust value forever. Your entire supply is in the `ftScript` premine output, transferable like any FT.

**You do not need to "burn" or "finalize" the covenant.** Unspent dMint UTXOs are harmless — they can only mint more tokens if someone solves PoW and spends them. Belt-and-braces: setting `maxHeight = 1` with initial `height = 0` means the first (and only) valid spend is forced through the `finalMint` branch (`powmint.rxd:44-47`), which requires the output to be `0xd8 + contractRef + 0x6a` — an unspendable OP_RETURN-style burn. Combined with `reward = 0`, even that hypothetical spend emits zero tokens.

### 9.3 Answers to the specific sub-questions

1. **Premine code path exists:** yes, `mint.ts:430` (`RevealDmintParams.premine`, field at `types.ts:74`). Already exercised in `packages/lib/src/__tests__/dmint.test.ts`.

2. **Does the covenant permit `amount == max_supply` in a single spend?** Irrelevant for your use case, but the answer is **no through the covenant** — `powmint.rxd:37` requires `tx.outputs.codeScriptValueSum(rewardCSH) == reward`, i.e. **exactly `reward` tokens per mint, fixed at deploy**. There is no "remaining_supply" state; supply is implicit in `maxHeight * reward`. You cannot collapse mining into one tx by setting `reward = totalSupply` because you'd also have to set `maxHeight = 1`, and that works — but the `finalMint` branch at `powmint.rxd:44` still requires a valid PoW solution (PART B1/B2 run before the finalMint check). Premine bypasses the covenant entirely and is the only PoW-free mechanism.

3. **Does PoW apply to the first mint?** Yes — every covenant spend must satisfy `firstFourBytes == 0x00000000` (bytecode `040000000088` at `script.ts:616`, V2_BYTECODE_PART_B1). There is no special-case initial mint. But **the premine output is not a covenant spend**, so PoW never gates it.

4. **A no-PoW dMint variant?** Not in the repo. V2 bytecode PART B1 hard-codes the 32-bit-zero-prefix floor. No branch/tag toggles it off. Removing it requires forking `script.ts` and shipping a custom covenant — unnecessary for your use case.

5. **Fixed DAA at `target = MAX_TARGET`?** The 32-bit-zero floor (PART B1) is checked *before* the target comparison (PART B2, `51797ca269` at `script.ts:618`). So even `target = 0x7fffffffffffffff` still requires ~2^32 hashes of grinding (seconds-to-minutes on commodity hardware). Not "PoW-free" — but cheap enough to work as a fallback if you ever wanted the covenant path. You don't, because premine is cleaner.

### 9.4 Recommendation for pyrxd

Implement dMint in pyrxd with `premine` as a first-class field, and document the "premine = total_supply, reward = 0, maxHeight = 1" pattern as the **fixed-supply FT issuance recipe**. This gives premine-only consumers exactly what they need with ~30% of the dMint surface area — skip the PoW solver, skip adaptive-DAA builders, skip the covenant-spend tx builder entirely for v1. Minimum viable port:

- `DmintPayload` encoder (Bitwork-CBOR, `protocols.ts`)
- `dMintScript()` port (state script + V2 bytecode constants — literal hex copy from `script.ts:616-622`)
- Reveal tx builder with `premine` FT output + dMint contract UTXO(s) + link-NFT record

Mining support (PoW grinder, adaptive DAA, covenant-spend tx builder, `finalMint` burn path) can land in a later release once a downstream consumer actually needs distributed minting.

---

## 10. Follow-up: V1 vs V2 classification + ship-which decision

**Date:** 2026-04-22. Superseding guidance for §9.4 after reviewing live-mainnet decode evidence.

### 10.1 Q1 — How classification actually works

**Classification is driven entirely by the CBOR payload's `p` array, not by the contract-script shape.** The covenant bytecode is functionally invisible to the indexer.

Evidence (Photonic Wallet HEAD, `/tmp/photonic-wallet`):

1. `packages/lib/src/token.ts:58-131` (`decodeGlyph`) — scans `script.chunks` for a 3-byte push matching `676c79` ("gly"), then CBOR-decodes the *next* chunk. It never examines the locking script; it only reads the **reveal input's scriptSig** (see `extractRevealPayload` at `token.ts:189-210`, which pulls `inputs[i].script`).
2. `packages/app/src/electrum/worker/NFT.ts:379-418` (`saveGlyph`) — calls `extractRevealPayload(ref, reveal.inputs)`, then at **line 412-418** classifies strictly from `payload.p`:
   ```ts
   const protocols = payload.p;
   const contract = protocols.includes(GLYPH_FT) ? "ft"
                  : protocols.includes(GLYPH_NFT) ? "nft" : undefined;
   ```
3. `packages/lib/src/protocols.ts:67-82` (`getTokenType`) — human-readable label derives purely from `p`: `"dMint FT"` when `[GLYPH_FT, GLYPH_DMINT]` both present (line 69); otherwise just `"Fungible Token"`.
4. Test confirmation: `packages/lib/src/__tests__/protocols.test.ts:67` — `expect(getTokenType([GLYPH_FT, GLYPH_DMINT])).toBe('dMint FT')`. Script-shape is never mentioned.

**Conclusion:** a premine-only token carrying `p: [1, 4]` (FT + DMINT) in its reveal-input CBOR will be classified as "dMint FT" regardless of whether any covenant UTXO ever existed. A token carrying `p: [1]` alone classifies as plain "Fungible Token". The indexer does not care about V1 vs V2 covenant bytes.

Caveat: third-party explorers (non-Photonic) were **not searched** — no such code is in `/tmp/photonic-wallet`. If an external explorer exists and scans differently, it is outside this research scope.

### 10.2 Q2 — Where is V1 bytecode

**V1 bytecode IS archived in the current repo**, flagged explicitly as "legacy for backward-compatible parsing":

- `packages/lib/src/script.ts:624-625`:
  ```ts
  // V1 legacy BYTECODE_PART_B (for backward-compatible parsing only)
  const V1_BYTECODE_PART_B = 'bc01147f77587f040000000088817600a269a269577ae500a069567ae600a06901d053797e0cdec0e9aa76e378e4a269e69d7eaa76e47b9d547a818b76537a9c537ade789181547ae6939d635279cd01d853797e016a7e886778de519d547854807ec0eb557f777e5379ec78885379eac0e9885379cc519d75686d7551';
  ```
  That's a 125-byte literal. Structurally it equals `V2_PART_B1` (`script.ts:616`) + the byte `a2` + `V2_PART_C` (`script.ts:622`). This tracks: V1 has no target-comparison PART_B2 (V1 stacks `target` as a state item and uses a simpler `>=` check baked into PART_B) and no stack-cleanup PART_B4.
- The authoritative V1 source of truth remains the CashScript file `packages/lib/src/contracts/powmint.rxd` (read in full — 6 constructor params, 3 runtime state items: `height`, `contractRef`, `tokenRef`, matching mainnet's 3-state-item / 131-opcode / 241-byte layout).
- A V1 *constructor* (equivalent to `dMintScript` but emitting V1 bytes) is **not** in the repo. `dMintScript` at `script.ts:704-766` unconditionally emits V2 (10-item state, hard-coded `V2_STATE_ITEM_COUNT = 10` at line 745). `V1_BYTECODE_PART_B` is referenced nowhere else in the source tree (grep confirms: defined and dead).
- Git tags/branches could not be inspected — `git` commands were denied in this sandbox. Cannot confirm whether an older tag contained a `dMintScriptV1`.

**Path to produce V1 bytes:** combine the mainnet decode's literal 241-byte template (Section 10 of `dmint-research-mainnet.md` confirms bytes 79-240 are byte-identical across all 7 sampled contracts) with the 3-state PART_A produced by Photonic's own `buildDmintPreimageBytecodePartA(3)` at `script.ts:447-473` (this helper accepts any `stateItemCount`, so passing `3` emits V1-shaped PART_A). Concatenate `stateScript(3 items) + 0xbd + PART_A(3) + 0xaa + V1_BYTECODE_PART_B`. Then verify against mainnet's 131-opcode / 241-byte reference script.

### 10.3 Q3 — Ship recommendation: **Option (d) with a hedge**

**Recommendation: pyrxd 0.2 ships the premine-only deploy path with NO covenant UTXO. Set `numContracts = 0`.**

Rationale:

1. **Q1 proves classification is CBOR-only.** A premine-only deploy tx with (a) a reveal input carrying `gly` + CBOR `{v:2, p:[1,4], ...}` and (b) a P2PKH-wrapped `ftScript(address, tokenRef)` premine output is classified as "dMint FT" by Photonic's indexer. The covenant UTXO contributes nothing to classification.
2. **The covenant is dead weight for premine-only deploys.** §9.2 already established the covenant UTXO sits unspendable (`maxHeight = 1` forces finalMint, which requires PoW regardless). If no one will ever spend it, emitting it is strictly pollution — a dust UTXO we pay miner fees for and then abandon.
3. **No code in Photonic requires `numContracts >= 1`.** The UI clamp at `packages/app/src/pages/Mint.tsx:221-227` (`clampNumContracts` returns `Math.max(1, ...)`) is UI-only. The library-layer loop at `packages/lib/src/mint.ts:402` (`for (let i = 0; i < dmintParams.numContracts; i++)`) runs zero times if `numContracts = 0`, and lines 450-461 (input additions for contract refs) similarly no-op. The `premine` branch at `mint.ts:430-439` is independent. pyrxd can pass `numContracts = 0` and emit only the premine FT output.
4. **Avoids the V1/V2 tarpit entirely.** No covenant bytes emitted means no V1-vs-V2 decision to make. Premine-only deploys are fully correct the day pyrxd 0.2 ships; no byte-level fidelity audit needed against mainnet reference contracts.

**Hedge:** if a downstream consumer (or a non-Photonic explorer) is later found to require covenant-UTXO presence for dMint recognition, ship V1 emission at that point. Rationale: V1 is what 100% of deployed mainnet contracts use (31/31 live decodes, per `dmint-research-mainnet.md`); V2 has zero mainnet deployments today. Shipping V1 maximizes compatibility with whatever indexer might check script shape. The V1 constructor is a ~50-LOC addition given `V1_BYTECODE_PART_B` is already a literal and `buildDmintPreimageBytecodePartA(3)` already exists.

**Do not ship V2 emission in pyrxd 0.2.** V2 matches no deployed contract. Emitting it would produce UTXOs indistinguishable from Photonic HEAD's output but with no mainnet precedent for whether PoW miners/DAA-aware indexers correctly handle them. The research budget to validate V2 against a running miner is larger than the business value for the premine-only path.

**Concrete action items for pyrxd 0.2:**
- `DmintPayload` CBOR encoder — ship
- `ftScript(address, tokenRef)` + premine output — ship
- Reveal-input scriptSig: `gly` push + CBOR push with `p:[1,4]` — ship
- `dMintScript()` covenant builder — **do not ship in 0.2**
- PoW solver, adaptive DAA, finalMint burn — **do not ship in 0.2**
- Document `numContracts = 0` as the supported premine-only pattern; document "cov-emission deferred to 0.3" in the README.
