# How to create a token collection (CONTAINER)

**Who this page is for:** you want a group of NFTs that wallets and explorers
show as one collection — an art series, a game's item set, a membership series.
On Radiant that is the **CONTAINER** protocol marker, `7`.

The short version:

| Piece | What it actually is |
|---|---|
| The collection | An ordinary NFT whose envelope's `p` list includes `7` |
| A member | An ordinary NFT whose envelope's `in` list names the collection's ref |
| The link | Metadata. Advisory. Checkable, not enforced. |

There is **no** container script, no container covenant, and nothing on chain
that binds a token to a collection. That is not a pyrxd limitation — see
[Why the link cannot live in the script](#why-the-link-cannot-live-in-the-script).

---

## 1. Mint the collection

A container is minted exactly like any other NFT. Add `CONTAINER` to the protocol
list; everything else is unchanged.

```python
from pyrxd.glyph.types import GlyphMetadata, GlyphProtocol

collection = GlyphMetadata(
    protocol=[GlyphProtocol.NFT, GlyphProtocol.CONTAINER],
    name="Kiln Series One",
    token_type="container",          # Photonic reads this string too
    description="Twelve pieces, fired 2026.",
)
```

From the CLI, `glyph init-metadata --type container-nft` writes that shape, and
`glyph mint-nft` mints it:

```console
$ pyrxd glyph init-metadata --type container-nft -o collection.json
$ pyrxd glyph mint-nft collection.json
```

The resulting locking script is the plain 63-byte NFT singleton. Keep the
collection's **genesis ref** (`txid:vout`, printed by the mint and by
`pyrxd glyph list --type nft`) — every member has to name it.

## 2. Mint a member

The member is an ordinary NFT whose metadata declares the collection:

```python
member = GlyphMetadata(
    protocol=[GlyphProtocol.NFT],
    name="Kiln Series One #1",
    container_refs=(collection_ref,),   # -> the Glyph `in` field
    author_refs=(artist_ref,),          # optional -> the Glyph `by` field
)
```

Then build the reveal with `GlyphBuilder.prepare_container_child_reveal` rather
than the plain reveal builder:

```python
scripts = builder.prepare_container_child_reveal(
    commit_txid,
    commit_vout,
    cbor_bytes,
    owner_pkh=member_owner_pkh,
    container_ref=collection_ref,
    container_owner_pkh=collection_owner_pkh,
)
```

It returns two locking scripts, and the reveal transaction must carry **both**:

| Input | | Output | Script |
|---|---|---|---|
| 0 | the commit outpoint | 0 | `scripts.nft_script` — the new member |
| 1 | **the collection's own UTXO** | 1 | `scripts.container_script` — the collection, re-created |

Plus whatever change you need. The collection is spent and immediately
re-created, byte for byte, at the same owner: it does not move and does not
change hands.

### Why spend the collection at all?

Because that is what makes the membership claim *checkable*. Anyone can write
`in: [<your collection ref>]` into their token's metadata — nothing stops them
(see [What is and isn't guaranteed](#what-is-and-isnt-guaranteed)). What a reader
can verify is whether the named ref also appears among the refs of the **outputs
of that token's own reveal transaction**. Spending and re-creating the collection
puts it there, and it is only possible for whoever controls the collection UTXO.

This is exactly the check Photonic Wallet's indexer applies (`filterRels`), so a
member minted this way shows up in the collection there too. A member minted
without it decodes fine and is dropped from the collection by any reader doing
the check.

`prepare_container_child_reveal` refuses to build anything if the envelope's `in`
list does not name the container you passed — a mismatch would otherwise surface
days later as "why isn't my token in the collection".

## 3. Read a collection back

`GlyphScanner` resolves each token's reveal envelope, so membership comes back
with the scan:

```python
tokens = await GlyphScanner(client).scan_address(address)

collections = [t for t in tokens if getattr(t, "is_container", False)]
members = [t for t in tokens if collection_ref in getattr(t, "container_refs", ())]
```

`GlyphNft.metadata` is `None` when the reveal could not be fetched; the
accessors return empty rather than raising, so absence of membership is not the
same as "not a member". Check `metadata is None` if you need to tell those apart.

## 4. Transfer a collection or a member

Both are NFTs:

```console
$ pyrxd glyph transfer-nft <REF> --to <ADDRESS>
```

Nothing special is required to preserve the collection. The member's `in` claim
lives in its reveal envelope, which no later transaction rewrites, and the
collection's ref does not change when it is transferred. Selling a collection
transfers the parent token; the members keep pointing at the same ref.

---

## What is and isn't guaranteed

| Claim | Reality |
|---|---|
| "This token is in collection X" | A **claim** in the token's own metadata. Anyone can make it about any collection. |
| "…and the collection's owner agreed" | Verifiable **only** by the output-ref check above. Do the check; don't trust the field alone. |
| "The collection has N members" | Not a thing on chain. Counting members means indexing every token that claims membership and checking each one. |
| "A member can't leave" | It never joined in any binding sense. Nothing can remove the claim either — the envelope is immutable. |
| "The collection can't be destroyed" | It can be burned like any NFT. Members then point at a ref with no live UTXO. |

If you need enforcement rather than convention — supply caps, membership that a
member cannot forge, revocation — that needs a purpose-built covenant, the same
way soulbound transfer restrictions do. See
[Covenant building blocks](../concepts/covenant-building-blocks.md).

## Why the link cannot live in the script

The obvious design is to put the collection's ref in the member's locking script
(or the member's ref in the collection's). Radiant consensus forbids both.

`OP_PUSHINPUTREFSINGLETON` — the `0xd8` opcode every NFT script starts with —
registers its ref as a **disallowed sibling** as well as a push ref. Within one
transaction, a ref pushed as a singleton by one output may not appear in *any*
other output. So a transaction that creates an output naming a live NFT's ref and
keeps that NFT alive is rejected outright:

```
bad-txns-inputs-outputs-invalid-transaction-reference-operations
```

The only accepted form **consumes** the named token's singleton, and a singleton
consumed that way can never be minted again. pyrxd shipped a builder that did
this from 0.9.0 to 0.14.0; it destroyed the child NFT and produced an output
nobody could spend. It was removed in 0.15.0 and now raises. If you hold one of
those 100-byte outputs, `pyrxd glyph inspect` will identify it — but it cannot be
recovered.

The full derivation, with the node reject reasons, is in
[the Glyph token protocol specification](../reference/glyph-token-protocol-spec.md)
§7.5 and §17.1.

## See also

- [Transfer a Glyph token](transfer-a-glyph-token.md)
- [Scan an address for Glyphs](scan-address-for-glyphs.md)
- [Glyph token protocol specification](../reference/glyph-token-protocol-spec.md) — §4.3 (`in` / `by`), §7.5 (CONTAINER)
- [Covenant building blocks](../concepts/covenant-building-blocks.md) — what a covenant can enforce that metadata cannot
