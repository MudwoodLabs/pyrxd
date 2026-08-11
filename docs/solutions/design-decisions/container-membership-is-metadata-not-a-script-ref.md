---
title: "Container membership is METADATA — a script-level parent/child ref is impossible on Radiant"
category: design-decisions
component: glyph / token-issuance
tags:
  - glyph
  - container
  - collection
  - consensus
  - singleton
  - photonic
  - fund-safety
date: 2026-08-10
severity: high
symptom: >
  `GlyphBuilder.prepare_container_reveal(child_ref=...)` shipped from 0.9.0 to 0.14.0
  and prefixed the NFT body with `OP_PUSHINPUTREF <child_ref>`, producing a 100-byte
  output that no pyrxd classifier matched and no builder could move. Completing the
  routing looked like a straightforward gap-fill. It was not: the output could not be
  spent by anyone, and creating one destroyed the child NFT permanently.
---

# Container membership is metadata, not a script-level ref

## The question

pyrxd could mint a CONTAINER token that its own scanner could not see and its own
transfer builder refused. Should the routing be completed — classifier, scanner,
transfer — or is the shape itself wrong?

## The answer

**The shape is wrong, and it cannot be made right.** The `child_ref` parameter was
removed in 0.15.0 (it now raises). A container is a **plain 63-byte NFT**;
membership lives in the *child's* envelope, in the Glyph `in` field. That is
Photonic Wallet's model, and it is the only model Radiant consensus permits.

## Evidence

Every row below was put to a **Radiant Core v3.1.1 regtest node** and the reject
reason recorded. Reproduce with `RADIANT_REGTEST=1 pytest
tests/test_container_regtest_e2e.py -m integration -s`.

### 1. The 100-byte output could not be spent — by anyone

`OP_PUSHINPUTREF` pushes its 36-byte ref and **nothing drops it**. The script is

```
d0 <child_ref:36>  d8 <container_ref:36> 75  76 a9 14 <pkh:20> 88 ac
```

so by the time `OP_DUP OP_HASH160` runs, the top of the stack is `child_ref`, not
the pubkey, and the comparison is `HASH160(child_ref) == <pkh>`. The failing item
is pushed by the **locking** script, so no scriptSig can influence it.

```
[case 4] legacy container spend reject-reason:
  16: mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation)
```

Photonic's analogous `delegateTokenScript` is `OP_PUSHINPUTREF <ref> OP_DROP` +
P2PKH (`packages/lib/src/script.ts`). The missing `0x75` is a one-byte bug — but
fixing it does not rescue the design, for the next reason.

### 2. Creating one destroyed the child NFT

`OP_PUSHINPUTREFSINGLETON` (`0xd8`) files its ref into **three** sets, not one
(`Radiant-Core/src/script/script.cpp:600-607`):

```cpp
} else if (opcode == OP_PUSHINPUTREFSINGLETON) {
    foundPushRefs.insert(refIdUint288);
    foundDisallowedSiblingRefs.insert(refIdUint288);   // <-- this one
    foundSingletonRefs.insert(refIdUint288);
}
```

`validateDisallowedSiblingsRefRule` (`src/validation.h:945-968`) then rejects any
transaction in which a singleton's ref appears in the push-ref set of a
**different** output. So the child cannot be re-created alongside the container
that names it:

```
[case 5] container + surviving child reject-reason:
  19: bad-txns-inputs-outputs-invalid-transaction-reference-operations-mempool
```

The only accepted form consumes the child and does not re-create it — and that is
irreversible, because a singleton ref re-enters `inputSingletonRefSet` only from
an input's `0xd8` push or an input outpoint (`src/validation.h:1046-1050`). Held
as a `0xd0` push, it is gone:

```
[case 6b] child re-mint reject-reason:
  19: bad-txns-inputs-outputs-invalid-transaction-reference-operations-mempool
```

**A caller who thought they were adding a token to a collection had burned it**,
and parked the carrier photons on an output nobody can spend.

### 3. The mirror design fails identically

Putting the *container's* ref in the *child's* script fails for the same sibling
rule: the child mint would have to spend and re-create the container, and the
container output would then hold a ref that the child output also carries. On
Radiant, **no output may reference a live NFT singleton held by a sibling
output.** There is no opcode arrangement that avoids this.

### 4. The FT route is closed too

Naming an FT's ref keeps the FT alive in principle (normal refs may be
duplicated), but the FT's own 12-byte epilogue requires the ref's output count to
equal the FT code-script-hash output count. A container output carrying the token
ref breaks that equality:

```
[case 5b] container naming a live FT reject-reason:
  16: mandatory-script-verify-flag-failed (Script failed an OP_NUMEQUALVERIFY operation)
```

### 5. Photonic never did this

Canonical Photonic has exactly one NFT script and no container variant:

```ts
export const nftScriptSize = 63;

export function nftScript(address: string, ref: string) {
  const script = Script.fromASM(`OP_PUSHINPUTREFSINGLETON ${ref} OP_DROP`)
    .add(Script.buildPublicKeyHashOut(address));
```

and `parseNftScript` is a fully anchored regex, so an extra ref would not parse.
Membership is written into the child's CBOR as `in: [<36-byte wire ref>]`
(`packages/app/src/pages/Mint.tsx`), and the *only* validation is
`filterRels` (`packages/app/src/electrum/worker/NFT.ts`): a claimed `in` ref is
dropped unless the same ref also appears among the refs of the reveal's output
scripts.

## What was built instead

- A container is an ordinary NFT with `7` in `p`. It classifies, scans and
  transfers through the existing NFT paths with no special case — which is what
  "containers work" actually required.
- `GlyphMetadata.container_refs` / `.author_refs` encode and decode `in` / `by`.
  (This also closed a real decode gap: `by` refs on mainnet tokens were being
  discarded.)
- `prepare_container_child_reveal` builds the two-output reveal — child NFT plus a
  byte-identical re-creation of the container UTXO — so the membership claim
  passes the `filterRels` check rather than being a bare assertion.
- `is_legacy_container_script` / `parse_legacy_container_script` identify the dead
  100-byte shape so a holder is told what it is instead of seeing `unknown`.

## The transferable lesson

**A gap in routing is not automatically a gap to be filled.** The task looked like
"three classifiers don't know about a shape". The shape was the bug, and only a
node could say so — reading the builder, the tests, and even the spec would not
have revealed either failure, because both live in consensus code the builder
never consults. When a token shape has never been put to a node, "no classifier
recognises it" is evidence about the shape, not about the classifiers.

## See also

- `docs/reference/glyph-token-protocol-spec.md` §7.5, §7.5.1, §17.1
- `docs/how-to/create-a-token-collection.md`
- `tests/test_container_regtest_e2e.py`
- [Royalties are advisory](royalties-are-advisory-not-consensus-enforced.md) — the
  same "metadata is a claim, not a guarantee" boundary
