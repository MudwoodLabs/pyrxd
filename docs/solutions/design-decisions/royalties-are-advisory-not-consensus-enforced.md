---
title: "Glyph royalties are ADVISORY — pay them honestly, never call them enforced"
category: design-decisions
component: glyph / token-issuance
tags:
  - glyph
  - royalty
  - covenant
  - consensus
  - photonic
  - honest-defaults
date: 2026-08-10
severity: medium
symptom: >
  GlyphRoyalty has been decoded from the Glyph envelope since 0.9.0 and never paid,
  and its `enforced: bool` field invites the reading that setting it makes the chain
  enforce something. Nothing in Radiant consensus, and nothing in any script pyrxd
  builds, requires a royalty output on a token transfer — so a "royalty-honouring
  transfer" built without settling that first would tell a creator they are being
  paid when the next wallet to touch the token can simply not pay them.
---

# Glyph royalties are advisory, not consensus-enforced

## The question

`GlyphRoyalty` has been decoded from the Glyph envelope since 0.9.0 and never
paid. Closing that gap needs an answer first: **is a royalty on a Radiant token
enforceable, or is it a convention?** Building a "royalty-honouring transfer"
without answering it risks shipping something that tells a creator they are
being paid when nothing guarantees it.

## The answer

**Advisory.** A royalty on an ordinary transfer is a social convention: a
compliant wallet honours it, a non-compliant one omits it, and the chain accepts
both.

It *can* be made binding on a **buyer**, by putting the token into a covenant
that only releases it against required outputs. It cannot be made binding on a
**holder**, because the holder chooses the transaction.

## Evidence

Checked, not assumed:

1. **The locking scripts do not constrain payments.**
   `build_nft_locking_script` (`src/pyrxd/glyph/script.py:127-133`) is
   `OP_PUSHINPUTREFSINGLETON <ref> OP_DROP` followed by a bare P2PKH tail — 63
   bytes, no output introspection. `build_ft_locking_script` (`:135-143`) is a
   bare P2PKH prefix plus a 12-byte conservation epilogue. Conservation
   constrains *how many units of the ref* may exist on the output side. It says
   nothing about where **value** goes, so it cannot require a payment to anybody.

2. **No shipped covenant references a royalty.** `grep -riE "royalt"` over
   `src/pyrxd/gravity`, `src/pyrxd/swap`, `src/pyrxd/script` and
   `src/pyrxd/glyph/dmint` returns zero hits. The only pyrxd covenant that
   constrains an output script at all is
   `src/pyrxd/glyph/soulbound_covenant.py`, an explicitly-labelled prototype
   that forbids transfer entirely rather than pricing it.

3. **pyrxd's own type already said so.** `GlyphRoyalty`
   (`src/pyrxd/glyph/types.py:171-180`) documents itself as an "on-chain royalty
   **hint** for secondary-market wallets", and its `enforced` field means
   "whether *wallets* should enforce this royalty" — not the chain.

4. **Photonic Wallet reaches the same structural conclusion.** Its royalty
   covenant (`packages/lib/src/royaltyCovenant.ts`, header comment) describes the
   lifecycle explicitly: *at rest* the NFT lives in the ordinary
   `nftScript(owner, ref)` — a P2PKH-gated singleton; enforcement exists only
   once a holder **voluntarily lists** it into `royaltySaleScript(...)`, where
   the seller's wallet bakes the payout amounts in as literals and a buyer can
   only spend the UTXO by paying them. That file's own "Honest scope" section
   records the two holes this leaves: it does not stop a malicious *seller*
   using non-wallet software from crafting a non-compliant listing, nor a holder
   gifting the token out of band with no sale.

5. **Photonic's non-covenant royalty layer is not wired in.**
   `packages/lib/src/royalty.ts` exports `nftRoyaltyScript`,
   `buildRoyaltyOutputs`, `calculateRoyalty` and `checkRoyaltyCompliance`;
   `grep -rn` across `packages/` shows every one of them referenced **only by
   its own unit test**. The same pattern as `soulbound.ts`, which pyrxd already
   documented as dead code. And where it does branch, it treats a non-enforced
   royalty as producing *no* outputs at all (`royalty.ts:191-193`), i.e.
   "advisory" is implemented as "never paid".

## What pyrxd does about it

Pay it honestly, and never imply more:

- `pyrxd.glyph.royalty` computes the payouts.
  `royalty_due = max(minimum, floor(sale_price * bps / 10_000))` — byte-for-byte
  Photonic's `calculateRoyalty`, so a pyrxd payment and a Photonic payment agree
  on the single-recipient path.
- `FtUtxoSet.build_airdrop_tx` takes an optional `royalty=` and **pays it by
  default** once supplied. `pay_royalty=False` is an explicit opt-out, and the
  decision is recorded in the result either way. A one-recipient airdrop is an
  ordinary transfer, so this covers the transfer case too.
- Payouts are plain 25-byte P2PKH outputs. They carry no ref, so they contribute
  to no conservation sum — which is why a royalty can ride on an FT transfer at
  all. Verified against a live `radiant-core:v3.1.1` regtest node in
  `tests/test_ft_airdrop_regtest_e2e.py`.
- The interface takes a **decoded `GlyphRoyalty`** — the creator's recorded
  terms — not loose `--royalty-address` / `--royalty-bps` flags. Letting the
  *payer* type in the terms would look like royalty support while protecting no
  creator; see "deliberately not built" below.
- The CLI's pre-broadcast metadata summary prints
  `(ADVISORY — recorded on chain, not enforced by consensus)` next to any
  royalty, at the moment a creator is still deciding.

Two deliberate deviations from Photonic on the `splits` path, both because
Photonic's version can pay the creator *less than the terms they recorded*:
`minimum` is honoured when splits are present (Photonic computes each split from
`sale_price` directly and never consults it), and the residue — flooring loss
plus any bps the splits do not cover — is routed to the top-level `address`
rather than dropped. The invariant is exact:
`sum(payout.photons) == royalty_due(...)`.

## Deliberately not built

- **A royalty listing covenant.** It is the only thing that would make a royalty
  binding, it is a new consensus-adjacent script surface, and it belongs behind
  the same external-audit gate as the rest of the covenant work. Photonic's
  design (seller-committed fixed amounts, no on-chain MUL/DIV) is the reference
  if and when it is built.
- **CLI `--sale-price` on `transfer-ft` / `transfer-nft`.** The terms would have
  to come from the person paying, which cannot protect a creator. Honouring a
  royalty from the CLI needs the creator's *recorded* terms, which means
  resolving a token's ref to its reveal transaction and decoding the envelope —
  a lookup pyrxd does not have yet. Until it does, the library takes a
  `GlyphRoyalty` and a marketplace built on pyrxd supplies it.
- **A royalty on `build_nft_transfer_tx` or `FtUtxoSet.build_transfer_tx`.**
  Neither has a plain-RXD input. The NFT builder takes exactly one input, the
  dust-carrying singleton; the FT transfer builder takes only token inputs,
  where every photon is already a unit. A royalty paid from either would come
  out of the token — burning units to pay a creator, which is not honouring
  anything. The first cut of this work did exactly that on the FT transfer path:
  a review measured a 5% royalty on a 1,000,000-photon sale costing the
  recipient 390,000 **units**. Both parameters were removed rather than papered
  over. Paying a royalty needs a funded builder, which is what
  `build_airdrop_tx` is.

## What would change this

A Radiant consensus rule that constrains payments — there is none, and adding
one is a hard fork. Short of that, the answer stays "advisory for transfers,
enforceable-on-the-buyer inside a listing covenant".
