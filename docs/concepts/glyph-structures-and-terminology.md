# Understanding Glyph structures and terminology

The Glyph protocol uses several closely-related identifier types and
several output types that aren't always defined in user-facing
material. If you've ever pasted a "contract id" into a tool expecting
to see your token transfer and instead fetched the deploy transaction
— this page explains why.

## TL;DR

- A **token** has one `contract_id` (its identity on chain) and many
  **transfers** (each with its own `txid`). These are *different
  identifiers*. The contract id never changes; transfer txids are
  unique per send.
- The same bytes get displayed differently in different contexts:
  - **`txid`** (64 hex chars) — display form of a tx hash
  - **`outpoint`** (`txid:vout`) — identifies one output of a tx
  - **`GlyphRef`** (36 raw bytes) — wire format used inside scripts
  - **`contract_id`** (72 hex chars: 64 + 8) — wallet-facing display
    of a `GlyphRef` for a token's deploy outpoint
- Output **types** the inspector reports (`ft`, `nft`, `mut`,
  `commit-ft`, `commit-nft`, `dmint`, `p2pkh`) describe the locking
  script's *shape*, not the user's intent. The most common
  confusion: `commit-ft` and `commit-nft` are anchors for a token's
  metadata in the deploy transaction — **they are not separate token
  outputs**.

## Identifiers

Five distinct identifier forms appear in Glyph code, docs, wallets,
and the inspect tool. They look similar, refer to overlapping
things, and the same bytes appear in different display orders.

### `txid` — the hash of a transaction

The standard Bitcoin-family transaction id. A 32-byte SHA256d
displayed as 64 hex chars in **wallet/explorer order** (which is the
reverse of the on-wire byte order — Satoshi's original quirk).

Example (a real RBG mainnet deploy):

```
ac7f1f705086a3a4cb2a354bf778fe2da829a90372742db076f542398cc60ae4
```

A `txid` identifies one transaction. That transaction has one or
more outputs, each addressable by *vout index*.

### `outpoint` — `txid:vout`

`outpoint` identifies one specific output of one specific
transaction:

```
ac7f1f705086a3a4cb2a354bf778fe2da829a90372742db076f542398cc60ae4:0
```

The first output of the transaction above. Wallets and explorers
use this form when they need to point at one UTXO.

### `GlyphRef` — 36-byte wire format

Inside a Glyph locking script, the same outpoint is encoded as a
fixed 36-byte structure:

```
txid_bytes (32 bytes, little-endian)  ||  vout (4 bytes, little-endian)
```

The txid bytes are the *little-endian* (on-wire) order — the reverse
of the display order. The vout is a little-endian uint32.

In pyrxd this is the `GlyphRef` dataclass at
[`src/pyrxd/glyph/types.py`](https://github.com/MudwoodLabs/pyrxd/blob/main/src/pyrxd/glyph/types.py).
You'll see it appear inside `build_ft_locking_script`,
`build_nft_locking_script`, `build_dmint_v1_contract_script`, etc.
— anywhere the script needs to reference another on-chain output.

### `contract_id` — wallet-facing display form

When wallets and explorers need to display the GlyphRef for a
token's *deploy* outpoint (which uniquely identifies the token
itself), they format it as:

```
<txid in display order>  ||  <vout as 4-byte big-endian, hex>
```

72 hex chars total — 64 for the txid + 8 for the vout. The vout is
**big-endian** here (so leading zeros are visible), different from
the GlyphRef's wire form. A real example, the RBG token's contract
id:

```
b45dc453befb589aff8bfd76af0b994615b37eda094f48c380eb31deaf96a2a800000004
```

This decodes as: the FT deploy is at outpoint
`b45dc453…a2a8:4`. **The contract id identifies the token,** not
your holding of it. Every transfer of RBG carries this same `04`
ref in its FT output's locking script — the script is what makes
the UTXO an "RBG holding."

### `payload_hash` — sha256 of CBOR metadata

In the deploy transaction's commit output, the locking script
contains a 32-byte SHA256 of the metadata CBOR payload. The reveal
transaction's scriptSig then pushes the same CBOR bytes and the
covenant verifies the hash matches. This identifier appears mostly
in dMint covenant code and isn't usually pasted into tools.

## "Which identifier do I paste where?"

Quick reference for the inspect tool:

| You have… | Inspect tool accepts? | What it shows |
|---|---|---|
| A `txid` (64 hex) | ✓ Yes | Fetches the transaction and classifies every input/output |
| An `outpoint` (`txid:vout`) | ✓ Yes | Same as txid, with the specific output highlighted |
| A `contract_id` (72 hex) | ✓ Yes — but read on | Fetches the **deploy transaction**, not your transfer |
| A `GlyphRef` (72 hex without colon) | ✓ Yes — handled as contract_id | Same as above |
| Raw script hex | ✓ Yes | Decodes the script directly without fetching anything |

The trap is row 3 + 4. **Pasting the contract id fetches the deploy
transaction** — which has a wildly different output shape than a
plain transfer of the token. If your goal is "show me my recent
RBG transfer," paste **the transfer's `txid`**, not RBG's contract
id.

## Output types the inspector reports

These are *structural patterns* the inspector recognizes by
matching the locking script bytes against known shapes. They're
not semantic claims about what the user intended.

### `ft` — fungible-token-bearing output

A 75-byte locking script that carries a `GlyphRef` for the FT
contract. Spending this UTXO is what *transfers* the FT — the
contract bytes get re-emitted into the new output, and the
covenant enforces conservation (total FT amount in ≥ total FT
amount out).

See [Radiant FTs are on-chain](radiant-fts-are-on-chain.md) for
the byte-level layout. The conservation invariant is what
distinguishes a Radiant FT from "an NFT that says it's worth 100
units."

### `nft` — NFT singleton

A 63-byte locking script with a singleton ref. Spending this UTXO
moves the NFT to a new owner. The singleton property is enforced
by the covenant — the same ref cannot appear in two unspent
outputs simultaneously.

### `mut` — mutable contract output

The on-chain anchor for a contract whose metadata can be rotated
(modified or sold). Mutable contracts pair with an NFT or FT to
allow the issuer to update the metadata (`mod` operation) or
transfer issuance rights (`sl` operation) without changing the
contract id.

### `commit-ft` / `commit-nft` — deploy-time commits

**Not a separate token output.** These are anchor outputs in the
*deploy* transaction that commit to a hash of the metadata CBOR.
The reveal transaction spends them and produces the actual `ft`
or `nft` output(s) that carry the contract from that point on.

This is the most common source of inspect-tool confusion. If you
paste an FT's contract id, the inspector shows you the deploy tx,
which contains both a `commit-ft` *and* a `commit-nft` — making
it look like the deploy minted an NFT alongside the FT. It didn't:
the `commit-nft` is the mutable-NFT companion that holds the
contract's display name + image. See
[V1 dMint deploys](dmint-v1-deploy.md) for the deploy-shape walk.

### `dmint` — dMint contract output

A locking script that gates token-issuance behind proof-of-work.
Spending one of these UTXOs mints a new reward output (and
re-emits the contract if more issuance remains). See
[V1 dMint mint mechanics](v1-mint-mechanics.md) for the claim
transaction shape.

### `p2pkh` — plain Radiant address

A standard pay-to-public-key-hash output. May hold plain RXD, or
may serve as a Glyph protocol carrier (a P2PKH output can carry
ref bytes that the covenant recognizes — used by deploy commits
for the `ref-seed` outputs).

## Common transaction shapes

Walking through three real mainnet transactions on the RBG token
to make the identifier ↔ shape relationship concrete.

### FT deploy — the shape that confuses users

RBG's deploy reveal: txid
`b45dc453…a2a8`. **13 outputs**, in this order:

```
vout  0      1 photon       ft           — the genesis FT supply (carries the FT covenant ref)
vout  1      1 photon       nft          — the contract's mutable-companion NFT
vout  2      1 photon       commit-ft    — the FT metadata commit (anchored in deploy)
vout  3      1 photon       commit-nft   — the NFT metadata commit (anchored in deploy)
vout  4–11   1 photon each  p2pkh        — ref-seed outputs for parallel dMint contracts
vout  12     change         p2pkh        — deploy-cost change back to the deployer
```

Pasting `b45dc453…a2a8:4` (the contract id) into the inspector
fetches *this entire transaction* — explaining why a user worried
they had minted an NFT they didn't intend to. They hadn't; vout 1
+ vout 3 are the contract's metadata anchor, deployed by the
token's original creator. They were just looking at the wrong tx.

### FT transfer — the shape users usually mean

A typical RBG transfer: 2 or 3 outputs.

```
vout  0      1 photon       ft           — the recipient's holding (carries RBG's ref)
vout  1      change         p2pkh        — RXD change back to sender
```

The covenant takes care of conservation: if the sender's input had
amount = 1000 RBG and the recipient wants 100, the transfer would
emit *two* `ft` outputs (vout 0 = 100 to recipient, vout 1 = 900
back to sender) plus a `p2pkh` change for RXD. **Same ref bytes in
both `ft` outputs** — that's what makes them both RBG holdings.

If you want to see your transfer, paste the transfer's `txid`
(from your wallet's transaction history), not the token's contract
id.

### dMint claim — the shape miners produce

A V1 dMint mint transaction: 4 outputs.

```
vout  0      1 photon       dmint        — the re-emitted contract (lets the next miner claim too)
vout  1      reward         ft           — the miner's reward (carries the dMint contract's ref)
vout  2      0 photon       op_return    — the marker output ("msg" tag)
vout  3      change         p2pkh        — RXD change
```

See [V1 dMint mint mechanics](v1-mint-mechanics.md) for the
72-byte scriptSig + the canonical 4-output shape.

## Worked example

A real RBG holder pastes `b45dc453befb589aff8bfd76af0b994615b37eda094f48c380eb31deaf96a2a800000004` into the inspect tool:

1. The inspector parses the 72-hex string as a `contract_id` (= 64 hex txid + 8 hex BE vout).
2. The display txid is `b45dc453…a2a8`; the vout is `0x00000004` = **4**.
3. The inspector fetches transaction `b45dc453…a2a8` and shows its 13-output deploy shape.
4. The tx-shape banner (per [PR #61](https://github.com/MudwoodLabs/pyrxd/pull/61)) notes this is an FT deploy — explaining the `commit-nft` companion.

Same user, now wanting to see their *transfer* of RBG: pastes a
**transfer txid** (e.g. `ac7f1f70…0ae4`) instead. Now the inspector
fetches the 2-output transfer shape and shows the recipient's `ft`
holding + their own change.

The contract id is the token's *identity*; the transfer txid is one
*movement* of that token between holders. Both are valid pastes;
they show different things.

## See also

- [Radiant FTs are on-chain](radiant-fts-are-on-chain.md) — the
  byte-level layout of an `ft` locking script and the conservation
  rule.
- [V1 dMint deploys](dmint-v1-deploy.md) — why the deploy
  transaction has the unusual N+3-output shape.
- [V1 dMint mint mechanics](v1-mint-mechanics.md) — the dMint
  claim transaction shape.
- [Glyph inspect tool](glyph-inspect-tool.md) — structural-match
  semantics and what the inspector does NOT verify.
