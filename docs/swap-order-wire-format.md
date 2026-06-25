# Radiant on-chain swap order ("RSWP") wire format

**Date:** 2026-05-22. **Status:** confirmed from canonical source (Radiant-Core node parser + Photonic-Wallet producer + RXinDexer indexer), cross-checked against a Radiant-Core functional-test vector. Informs a future pyrxd swap-offer builder.

## Why this exists

Third-party RXD wallets that post to the on-chain swap orderbook (e.g. Orbital, Photonic) must sign their offered UTXO with `SIGHASH_SINGLE | ANYONECANPAY | FORKID`. Because `SINGLE` binds the signature to the one paired output *including its exact value*, the offered side must be a single UTXO of an exact amount — which is why those wallets do a "self-send" to mint a clean exact-amount UTXO before posting an offer. pyrxd's signing stack already supports `0xC3` (`SIGHASH.SINGLE_ANYONECANPAY_FORKID`, `src/pyrxd/constants.py:38`), so building/parsing these orders is a serializer job, not a crypto gap. This doc pins the byte format so a builder can be implemented without re-deriving it.

## Source authority

| Concern | Authoritative source |
|---|---|
| On-chain OP_RETURN layout & detection | Radiant-Core `src/index/swapindex.cpp:558-695` (the consensus-node parser — *defines* the format) |
| RPC field names/types (`getopenorders`) | Radiant-Core `src/rpc/swap.cpp:20-43, 608-618` |
| `price_terms` inner structure | Photonic-Wallet `packages/app/src/swapBroadcast.ts:300-403` (the actual on-chain producer) |
| `signature` content & sighash flags | Photonic-Wallet `packages/app/src/pages/Swap.tsx`, `packages/lib/src/transfer.tsx:208-228`, `tx.ts:44-70` |
| Sighash constants | Radiant-Core `src/script/sighashtype.h:14-18` |
| Test vector | Radiant-Core `test/functional/feature_swap.py:80-178` |

## Detection mechanism

A swap order is advertised by an **`OP_RETURN` output** whose first push is the 4 ASCII bytes `RSWP` (`52 53 57 50`). It is **not** a special script template, and the advertising transaction is otherwise an ordinary tx (it may be funded from any UTXO). "Open vs filled" is derived separately by the node tracking whether the offered UTXO is still unspent.

## v2 frame (current — Photonic emits only v2)

Pushes after `OP_RETURN`, in order (Radiant-Core `swapindex.cpp:594-659`):

| # | Field | Size / encoding | Notes |
|---|---|---|---|
| 1 | `"RSWP"` | 4 bytes ASCII | magic |
| 2 | `version` | 1 byte | `0x02` |
| 3 | `flags` | 1 byte | only `FLAG_HAS_WANT = 0x01` defined |
| 4 | `offeredType` | 1 byte | Photonic `ContractType` int; node stores verbatim |
| 5 | `termsType` | 1 byte | Photonic always emits `0x01` |
| 6 | `tokenID` | 32 bytes | see asset encoding below |
| 7 | `wantTokenID` | 32 bytes | **present iff `flags & 0x01`** |
| 8 | `offeredUTXOHash` | 32 bytes | reversed (little-endian internal) txid of offered UTXO |
| 9 | `offeredUTXOIndex` | minimal `CScriptNum` (≤4 bytes; `OP_0..OP_16` ok) | vout |
| 10..N-1 | `priceTerms` | one or more pushes, **concatenated** | see below |
| N | `signature` | final push | full scriptSig, see below |

Reassembly rule (`swapindex.cpp:642-659`): collect all remaining pushes into `tail`; require `len(tail) >= 2`; `price_terms = concat(tail[:-1])`, `signature = tail[-1]`.

(v1/legacy `version=0x01` has no flags/offeredType/termsType/wantTokenID and single-push price_terms+signature. Build against v2.)

## `price_terms` byte layout (Photonic `MultiTxOutV1`)

The node treats `price_terms` as **opaque bytes** (`HexStr(priceTerms)`). The real structure is imposed by the producer (Photonic) — a serialized list of the outputs the maker wants to receive:

```
price_terms := CompactSize(outputCount)
               || [ value(8 bytes LE) || CompactSize(scriptLen) || script ] * outputCount
```

- `value`: 8-byte **little-endian** uint64 (satoshis/photons).
- `scriptLen`: Bitcoin CompactSize/varint.
- `script`: raw scriptPubKey of the desired output (e.g. an FT/NFT/P2PKH script to the maker).
- Photonic currently always writes a single output.
- Reader fallback (`swapBroadcast.ts:359-371`): if MultiTxOutV1 parse fails, treat the blob as bare `value(8 LE) || script(rest)`.

## `signature` format & sighash

The `signature` push is **the entire unlocking scriptSig of input[0] of a partially-signed tx** (Photonic `Swap.tsx:655`), not a bare ECDSA sig:

```
signature := PUSH( DER_ECDSA_sig || sighashByte ) || PUSH( compressed_pubkey )
```

- **sighashByte = `0xC3` = `SIGHASH_SINGLE(0x03) | SIGHASH_FORKID(0x40) | SIGHASH_ANYONECANPAY(0x80)`.**
- `ANYONECANPAY` → signs only the maker's one offered input (taker adds their inputs).
- `SINGLE` → signs only the output at the same index as that input — the maker's single demanded output. **The demanded output value is bound into the signature, so it is exact by construction** (root cause of the self-send requirement).
- `FORKID` → Radiant/BCH-style (BIP143-style preimage with prevout value).
- With `SINGLE`, in the completion tx the maker's input index must equal the index of the maker's demanded output. Photonic builds the partial with offered-input and demand-output both at index 0.

## Field meanings

- `version`: `0x01` legacy, `0x02` current.
- `flags`: bit 0 `FLAG_HAS_WANT = 0x01` (presence of `wantTokenID`). No other bits defined.
- `offeredType`: Photonic `ContractType` enum int (verify mapping in Photonic `packages/app/src/types.ts` before assuming RXD=0/FT=1/NFT=2). Node assigns no meaning.
- `termsType`: selects `price_terms` interpretation; Photonic always `0x01` + MultiTxOutV1.

## Asset encoding (RXD-native vs Glyph token)

Frame is identical for both; asset identity lives in the 32-byte `tokenID`/`wantTokenID` and the embedded `price_terms` script (`assetToSwapTokenId`, `swapBroadcast.ts:405-416`):

- **RXD-native side:** `tokenID` = 32 zero bytes. When the *want* side is RXD, omit `wantTokenID` and clear `flags` bit 0.
- **Glyph-token side:** `tokenID` = `sha256( Outpoint.fromString(glyphRef).ref() )`, pushed **byte-reversed**.
- RPC `tokenid` is big-endian display hex; the on-chain push is little-endian internal bytes.

## ⚠️ Conflicts / pitfalls (read before implementing)

1. **`price_terms`: Photonic and RXinDexer DISAGREE.** RXinDexer (`electrumx/server/swap_index.py:462-517`) decodes `price_terms` as small price/amount integers keyed by `terms_type` — this is RXinDexer-local invention and produces **garbage against real Photonic-produced orders**. Follow **Photonic's MultiTxOutV1**; it is what is actually on chain and what the node round-trips. This is the one place the usual "Photonic is canonical" default and RXinDexer happen to be incompatible — and Photonic wins because it is the on-chain producer.
2. **`signature` is the full scriptSig**, not a bare signature, despite RPC help labeling it "Partial signature."
3. **`tokenID` derivation differs** between the node's functional test (bare reversed txid) and Photonic (`sha256(ref)` reversed). Node accepts either (opaque 32 bytes); use Photonic's `sha256(ref)` for orderbook interop.
4. **No `swap.get_orders` RPC exists.** Photonic queries the **node** (`getopenorders`, …). RXinDexer's ElectrumX methods are differently named (`swap.get_open_orders`, `swap.get_orderbook`, …) and a plain ElectrumX server returns `unknown method`.
5. `offeredUTXOIndex` uses minimal `CScriptNum` encoding.

## Verified test vector (Radiant-Core `feature_swap.py:80-178`)

An order with two price-term pushes `0102030405` + `060708090a` and signature `04050607` round-trips through `getopenorders` as `price_terms="0102030405060708090a"`, `signature="04050607"` — proving (a) price_terms = concatenation of middle pushes, (b) signature = final push, (c) on-chain pushes are little-endian/reversed while RPC reports big-endian display hex.

## Minimal build recipe for pyrxd (v2)

1. `tokenID` (offered): `sha256(genesis_ref_bytes)` for a Glyph token else 32×`0x00`; push reversed.
2. `wantTokenID`: same rule; omit + clear `flags` bit 0 if want side is RXD.
3. `flags = 0x01` iff `wantTokenID` present else `0x00`.
4. `offeredType` = ContractType int; `termsType = 0x01`.
5. `offeredUTXOHash` = reversed offered txid; `offeredUTXOIndex` = minimal CScriptNum.
6. `price_terms` = `CompactSize(1) || value(8 LE) || CompactSize(len(script)) || script` for the single demanded output.
7. Sign the offered UTXO with sighash `0xC3` (FORKID/BIP143 preimage); `signature` push = full P2PKH scriptSig `PUSH(der||0xC3) PUSH(pubkey)`.
8. Emit `OP_RETURN "RSWP" 0x02 flags offeredType termsType tokenID [wantTokenID] offeredUTXOHash offeredUTXOIndex priceTerms signature` as a value-0 output in any funded tx.

pyrxd already has the preimage + signing for `0xC3` (`src/pyrxd/transaction/transaction_preimage.py:190-235`, `src/pyrxd/script/type.py:78-85`, `src/pyrxd/constants.py:38`). Remaining work is the OP_RETURN/`MultiTxOutV1` serializer + a per-input sighash-aware offer builder.
