---
title: RSWP same-chain swap primitive + on-chain orderbook — design
type: plan
date: 2026-07-05
status: Phase 0 design — revised after a divergent review panel (simplicity / security / python-shape, run independently in parallel); §"Panel revisions" records what changed and why
parent: docs/plans/2026-06-26-pyrxd-next-steps-brainstorm.md
---

# RSWP on-chain orderbook — design note

Implements the top RSWP cluster of the 2026-06-26 brainstorm: the **write side** of the
on-chain swap orderbook (pyrxd already ships the read/decode side in
`pyrxd/gravity/swap_order.py`). Everything here is **same-chain** (RXD ↔ Glyph FT on
Radiant); the cross-chain HTLC stack (`pyrxd.gravity`) is untouched.

## Sources of authority (all verified in-source for this note)

| Concern | Source checked |
|---|---|
| Frame layout + node acceptance rules | Radiant-Core `src/index/swapindex.cpp` (`WriteBlock` parser; v2 + legacy-v1 branches; swapindex present since the 2.0.0 initial release, so the pinned regtest binary `v3.1.1` serves `getopenorders*`) |
| Producer byte choices | Photonic-Wallet `packages/app/src/pages/Swap.tsx` → `buildSwapAdvertisementScript` + `encodeScriptNum` |
| `ContractType` enum | Photonic `packages/app/src/types.ts`: **RXD=0, NFT=1, FT=2, VAULT=3** — note this is *not* the RXD=0/FT=1/NFT=2 guess the wire-format doc warned about; verified here |
| `tokenID` derivation | Photonic `swapBroadcast.ts` → `assetToSwapTokenId`: `sha256(ref_le)` where `ref_le` is the 36-byte little-endian script-operand ref (== `GlyphRef.to_bytes()`), and the *digest is pushed byte-reversed* on chain |
| `price_terms` (MultiTxOutV1) | Photonic `swapBroadcast.ts` `encodeOutput`/`encodeCompactSize`; already mirrored by the pyrxd decoder |
| RSWP **v3** (expiry) + refund covenant | Photonic (MudwoodLabs fork) `docs/swap-offer-expiry-cancellation.md` §4 + `packages/lib/src/swapRefundCovenant.ts` — regtest-proven 2026-06-09 on the wallet side; Radiant-Core/RXinDexer v3 parsers NOT yet landed (a v3 advert is dropped by the current node parser, not misparsed) |
| Reference vector | `docs/swap-order-wire-format.md` (Radiant-Core `feature_swap.py` tail-reassembly vector) |

## What already exists / is reused (no re-derivation)

- **Decoder**: `pyrxd.gravity.swap_order.decode_rswp_order` (v2) + `parse_price_terms`.
  Stays the single canonical decoder; gets an **additive** v3 extension (below).
- **Maker partial-tx signing**: `pyrxd.swap.partial.create_offer` already builds exactly
  the PSRT the RSWP book needs — one input signed `SIGHASH_SINGLE|ANYONECANPAY|FORKID`
  (`0xC3`) committing to one output. The RSWP `signature` push **is** that input's full
  scriptSig.
- **Taker completion + verification**: `pyrxd.swap.partial.accept_offer` (outpoint/source
  verification, terms reconciliation, maker-sig re-verification pre/post, FT conservation,
  change). The RSWP take path is a **bridge** into it, not a re-implementation.
- **Regtest harness**: `pyrxd.devnet.RegtestNode` (docker, official release binary).

## Wire format (encoder rules — byte-compatible with Photonic, accepted by the node)

```
OP_RETURN "RSWP" <version:1> <flags:1> <offeredType:1> <termsType=0x01:1> <tokenID:32>
  [wantTokenID:32          if flags & 0x01]
  [expiry_height:4 LE      if flags & 0x02]      # v3 only
  <offeredUTXOHash:32> <offeredUTXOIndex> <priceTerms> <signature>
```

Encoder byte choices that are **load-bearing** (the node's parser is strict where the
pyrxd decoder is lenient — the encoder must satisfy the strictest consumer):

1. `version`, `flags`, `offeredType`, `termsType` are **1-byte direct data pushes**
   (`0x01 <b>`), never `OP_N`. The node requires `data.size() == 1`; `GetOp` on `OP_2`
   yields empty data, so an `OP_N`-encoded version byte makes the node **drop the order**.
2. `tokenID` / `wantTokenID`: `sha256(GlyphRef.to_bytes())` **pushed byte-reversed**;
   32 zero bytes for native RXD. When the want side is RXD: omit `wantTokenID`, clear
   flag bit 0 (Photonic behavior).
3. `offeredUTXOHash`: txid bytes reversed (internal LE order).
4. `offeredUTXOIndex`: `OP_0` when 0, else a minimal-CScriptNum direct push (matches
   Photonic `encodeScriptNum`; the node accepts both `CScriptNum` and `OP_N`, Photonic
   emits this form, so we byte-match Photonic).
5. `priceTerms`: **one** push of the MultiTxOutV1 blob
   (`CompactSize(count) || [value:8 LE || CompactSize(len) || script]*`). The node
   concatenates all middle pushes, but Photonic emits one — we byte-match Photonic.
6. `signature`: final push = the **entire scriptSig** of the maker's signed input
   (`PUSH(DER||0xC3) PUSH(pubkey)`), not a bare signature.
7. v3 only: `expiry_height` = 4-byte LE unsigned, inserted after `wantTokenID` /
   before the outpoint; `version=0x03`, flag `0x02`. v2 and v3 paths must be
   byte-for-byte identical apart from these two fields.

The advertisement is a value-0 OP_RETURN output in an otherwise ordinary funded tx.

## Covenant approach (the open design point — decision, REVISED by the panel)

**No new covenant is invented, and no covenant ships in this PR.**

- **v2 (this PR): no covenant.** The offered UTXO is a plain P2PKH/FT output owned by the
  maker. This is what the live mainnet book runs on; the current Radiant-Core swapindex
  **drops** v3 adverts, so v2 is the only interoperable posting format today.
  *Cancel = self-spend* of the offered UTXO (the only hard revocation in v2 — the
  `0xC3` signature has no expiry).
- **v3 write-side (CUT to a follow-up PR): Photonic's timelocked-refund covenant.**
  The original draft scoped posting into
  `OP_IF <inner> OP_ELSE <expiry> OP_CHECKLOCKTIMEVERIFY OP_DROP <inner> OP_ENDIF`
  (the MudwoodLabs Photonic Phase-2 design, wallet-side regtest-proven). The panel cut
  it, for reasons this note originally missed:
  1. *No deployed consumer can see a v3 advert* (the node drops them), so shipped
     write-side has zero interoperable users; the cross-repo parser rollout needs
     **frame vectors**, which the decode side supplies.
  2. *The "bridge into `accept_offer`" premise breaks*: a covenant prevout fails
     `_owner_pkh_of` / `_asset_of` / `_verify_owner_signature`, and the `OP_1` branch
     selector breaks the strict two-push scriptSig parser — v3 take is surgery on the
     battle-tested v2 primitives (asset/owner from the INNER script, BIP143 scriptCode
     = the FULL covenant SPK), deserving its own PR and red-team.
  3. *FT-in-covenant may be consensus-blocked* (the FT codeScript epilogue forbids
     foreign covenants — a known pyrxd finding; Photonic itself has only proven RXD
     on-chain). A v3 follow-up starts RXD-only.
  4. The follow-up must also address two covenant findings from the security pass:
     the refund tx is third-party **txid-malleable** via the unsigned branch selector
     (track refunds by outpoint-spent, never chain off an unconfirmed refund), and
     **expiry does not stop fills** (CLTV is valid-from; a post-expiry fill remains
     consensus-valid and binding — the maker must actively win the refund race).

**What this PR ships for v3:** additive decode support (`expiry_height`, strict
"version 3 iff flag 0x02" rule) + v3 frame conformance vectors, seeding the
Radiant-Core/RXinDexer parser rollout. The take path refuses any order carrying an
expiry, both because the covenant is unspendable by this code and because expiry
comparison (`tip >= expiry`, Photonic `isOfferExpiredByHeight`) belongs with the
covenant work.

## Module layout (additive)

```
src/pyrxd/swap/rswp/
    __init__.py    public surface (re-exports, incl. the gravity decoder names —
                   pyrxd.swap.rswp becomes the documented import home; the decoder
                   implementation stays in gravity/swap_order.py)
    wire.py        encode_price_terms / encode_rswp_order / swap_token_id
    orders.py      pure builders: create_rswp_order, prepare_offered_utxo,
                   build_advert_tx, order→SwapOffer bridge + take, cancel self-spend,
                   verify_offer_signature
    book.py        OrderbookClient over a named async OrderbookSource Protocol
                   (@runtime_checkable, fail-closed — house style, not a bare callable)
```

(The panel cut `covenant.py` with the v3 write-side, and cut the block-scan book
source — regtest e2e gets `-swapindex=1` via a one-line additive `RegtestNode.start`
extension instead. The RXinDexer `swap.*` adapter remains the practical second source,
already tracked as a follow-up.)

`pyrxd/gravity/swap_order.py` gets the **only** shared-code touch: additive v3 decode
(`expiry_height: int | None = None` appended to the frozen dataclass; `version in (2,3)`).
Every existing v2 test must pass unchanged — that is the equivalence proof.

## Flows

**Post (maker)**  
1. (optional) `prepare_offered_utxo` — exact-amount self-send, since `SINGLE` gives the
   whole UTXO.  
2. `create_rswp_order` — signs the offered input `0xC3` against the single demanded
   output (via the `create_offer` mechanics), derives token ids, returns the offer +
   the advert OP_RETURN script.  
3. `build_advert_tx` — wraps the advert in a funded tx (plain-RXD funding + change;
   FT funding is refused — it would strand token value). Broadcast both (the library
   never broadcasts by itself; regtest tests do).

**Take (taker)**  
1. Decode advert (`decode_rswp_order`), fetch + txid-verify the offered UTXO's source
   tx (`pyrxd.swap.resolve.fetch_transaction`).  
2. `rswp_order_to_swap_offer` bridge — the trust boundary; see the invariants below.
   Reconstructs the maker's partial tx from `(outpoint, signature push, demanded
   output)` with the **pinned tx shape** `nVersion=1, nLockTime=0,
   nSequence=0xFFFFFFFF` — these fields are inside the signed preimage but absent
   from the advert; the pinned values are simultaneously the pyrxd *and* radiantjs
   defaults (verified in radiantjs 1.9.6 `transaction.js` / `input.js`), so
   pyrxd- and Photonic-produced orders both reconstruct correctly, and any maker
   using a non-default shape fails signature verification fail-safe (refused, no
   fund risk).  
3. Existing `accept_offer` does signature re-verification (pre- and post-completion) +
   completion + conservation + change.

**Cancel (maker)**  
Self-spend of the offered UTXO (`build_cancel_tx`) — works for RXD and FT offers
(conservation returns the full token amount; plain-RXD funding covers the fee for an
FT cancel).

**Browse**  
`OrderbookClient` over one injectable `OrderbookSource` Protocol (the node swapindex
RPCs `getopenorders` / `getopenordersbywant`, plus `getrawtransaction` / `gettxout`).
Every index row is treated as HOSTILE: (a) decoded, (b) classified open/spent by
`gettxout` on the offered outpoint (a liveness *hint* — a lying "open" dies at fill
as a double-spend; a lying "spent" is censorship only), (c) source-tx fetched with
the computed-txid-equals-requested check, (d) run through the same bridge +
signature verification the take path uses — so *fillable* means exactly "what
`accept_offer` would accept". Rows that fail are returned with `problem` set, never
silently dropped.

## Security invariants (tested, not assumed; #6–#9 added by the security pass)

1. **Maker sig binds the trade**: tampering with the demanded output (value or script)
   or the offered outpoint invalidates the `0xC3` signature → `accept_offer` rejects
   (unit) and the node rejects (regtest).
2. **Single-winner**: the offered UTXO can be spent once. Double-take and
   cancel-vs-take races settle to exactly one confirmed spend (regtest).
3. **No replay**: after the offered UTXO is spent, rebroadcast of the completion (or a
   re-post of the same advert) cannot move funds (regtest).
4. **SINGLE index discipline**: maker input and demanded output are both at index 0 in
   the completion; the take path refuses orders whose MultiTxOutV1 has ≠ 1 output
   (indexes ≥ 1 would be *unsigned* demands — fillable but unenforceable; we decode
   them for display, refuse to take, and say why).
5. **Parser robustness**: the encoder round-trips through the decoder
   (property-based), and malformed frames/price-terms never crash.
6. **Sighash flag pinned to `0xC3`** (security finding F1): the flag byte rides in
   the *untrusted* signature push, and `0xC2` (`NONE|ANYONECANPAY|FORKID`) is the one
   flag that verifies both before AND after completion while committing to **no
   outputs** — an order that *looks* enforceable but whose demand is unbound.
   Enforced in the shared `_verify_owner_signature` (all existing swap suites pass —
   equivalence proof) and re-checked early in the bridge for a precise error.
7. **The advertisement's claims are verified against the chain** (python-shape pass):
   `token_id` / `want_token_id` / `offeredType` must match the REAL offered UTXO and
   demanded-output scripts — a lying advert is rejected at the bridge rather than
   surviving to display or completion (without this, the bridge's synthesized terms
   would make `accept_offer`'s terms reconciliation a tautology).
8. **Fillable = what `accept_offer` accepts** (F6): the book's fillability predicate
   runs the same bridge + signature verification as the take path, and demanded
   values are capped at MAX_MONEY (an unfundable 2⁶⁴-ish demand is not "fillable").
9. **Hostile index rows can't crash or spoof** (F7/F8): a negative/huge CScriptNum
   vout is rejected at the bridge before any `TransactionInput` is constructed, and
   the browse-time source-tx fetch recomputes the txid rather than trusting the
   indexer.

## Explicit design decisions (brainstorm left these open)

| # | Decision | Rationale |
|---|---|---|
| D1 | **v2 is the default posting format; v3 is opt-in experimental** | Current Radiant-Core swapindex drops v3 adverts; posting v3 by default would make orders invisible to the live book. Photonic gates v3 the same way (`SWAP_RESERVE_INTO_REFUND_COVENANT = false`). |
| D2 | `ContractType`: **RXD=0, NFT=1, FT=2** | Verified in Photonic `types.ts`; the wire-format doc explicitly warned against assuming FT=1/NFT=2. |
| D3 | `tokenID = sha256(36-byte LE ref)`, digest pushed reversed | Verified in `assetToSwapTokenId` (incl. its on-chain-verified comment); `GlyphRef.to_bytes()` already produces the LE ref. |
| D4 | **Adopt Photonic's refund covenant byte-for-byte; invent nothing** | It is regtest-proven, documented, and cross-repo coordination is already planned around it. A pyrxd-specific covenant would fork the book and add unaudited consensus-critical surface. |
| D5 | Encoder emits Photonic's exact byte choices (1-byte direct pushes; `OP_0`/minimal-CScriptNum vout; single priceTerms push) | The node parser is stricter than the pyrxd decoder; Photonic's output is the de-facto conformance target; byte-identity makes golden vectors meaningful. |
| D6 | Take path requires exactly one demanded output | `SIGHASH_SINGLE` signs only output[0]; extra demanded outputs are unenforceable — honoring them silently would let a malicious maker fake "demands" the signature doesn't back. |
| D7 | Take = bridge into the existing `accept_offer` | Reuses the battle-tested verification/conservation path instead of a parallel implementation that could drift. |
| D8 | Asset scope: RXD + Glyph FT (NFT decode/display only) | Matches `pyrxd.swap` v1 scope; NFT (singleton semantics) is its own brainstorm item and does not block the book. |
| D9 | Library + example first; `pyrxd swap post/fill/orders` CLI is a follow-up | Keeps this slice reviewable; the CLI is a thin wrapper once the library is proven. Library code never broadcasts on its own. |
| D10 | Orderbook client source: ONE injectable `OrderbookSource` Protocol (swapindex RPCs) | REVISED by panel: the block-scan fallback was cut — its stated justification (regtest independence) is void once `RegtestNode.start` grows an additive `extra_args`, and a block walk is impractical at mainnet scale anyway. The practical second source is the RXinDexer `swap.*` adapter (follow-up). |
| D11 | v3 decode goes into the existing canonical decoder (additive) | One decoder; two would drift. Existing v2 tests unchanged = equivalence proof. Strict rule: `version == 3` iff flag `0x02` (a mis-gated 4-byte push would otherwise be silently folded into `price_terms` by the greedy tail rule). |
| D12 | Expiry boundary: expired iff `tip_height >= expiry_height` | Mirrors Photonic `isOfferExpiredByHeight`; applies to the v3 follow-up (this PR refuses to take any order carrying an expiry). |
| D13 | v3 WRITE-side (covenant posting / refund / take) deferred to its own PR | Panel consensus (independent simplicity + python-shape findings): no deployed consumer parses v3, and the covenant breaks the `accept_offer`-bridge premise — it needs its own red-teamed change, starting RXD-only (FT-in-covenant consensus blocker). |
| D14 | Sighash flag pinned to `0xC3` inside the shared `_verify_owner_signature` | Security finding F1 (`0xC2` binds no outputs yet verifies pre- and post-completion). A shared-code touch, accepted deliberately: the maker input of the offer pattern is only ever `0xC3`, and every existing swap suite passes unchanged. |
| D15 | Reconstructed partial tx shape pinned to `nVersion=1, nLockTime=0, nSequence=0xFFFFFFFF` | Security finding F5: these preimage-committed fields are absent from the advert. The pinned values are the pyrxd AND radiantjs defaults (verified in radiantjs 1.9.6), so both producers reconstruct; anything else fails signature verification fail-safe. |
| D16 | Keep `getopenordersbywant` alongside `getopenorders` on the Protocol | Deviation from the simplicity pass's "one RPC + client filter": the want-side book cannot be client-filtered without enumerating every token's offer-side book. Two symmetrical one-line methods. |

## Test plan (trimmed by the simplicity pass: one regtest case per consensus
invariant — single-winner and no-replay are node double-spend semantics, not pyrxd
code paths; both *trade directions* stay, they exercise different classification paths)

- **Unit/property (`tests/test_rswp_wire.py`)**: Hypothesis round-trip
  encode→decode over the parameter space (v2/v3, RXD/FT both sides, vout ranges,
  multi-output price terms); targeted malformed-frame rejections (version/flag
  mismatch both ways, wrong push sizes); token-id derivation.
- **Flows unit (`tests/test_rswp_orders.py`)**: post/take/cancel builders pure-path;
  bridge → `accept_offer` end-to-end offline; the invariant list above as explicit
  cases (0xC2 flag, lying token ids, ≠1 demanded output, negative vout, MAX_MONEY
  cap, expiry refusal, tampered demanded output).
- **Conformance (`conformance/rswp-order-vectors.json` + re-derive test)**: frame
  vectors (v2 RXD↔FT, FT↔RXD, v3 with expiry), MultiTxOutV1 vectors, token-id
  vectors, the Radiant-Core functional-test reassembly vector. CI re-derives
  byte-for-byte (same shape as the dMint suite).
- **Regtest e2e (`tests/test_rswp_regtest_e2e.py`, `@pytest.mark.integration` +
  `RSWP_REGTEST=1`)**: happy path post→`getopenorders`-visible→take→settle, both
  directions (RXD→FT, FT→RXD); one double-take case; one cancel-then-take-rejected
  case; one tampered-completion-rejected case. `RegtestNode.start` gains additive
  `extra_args` for `-swapindex=1`.
- **Example**: `examples/rswp_orderbook_demo.py` against `pyrxd regtest` (offline).

## Panel revisions (what the divergent review changed)

Three reviewers (code-simplicity, security-sentinel, kieran-python) ran in parallel on
the first draft of this note, writing independently. Adopted: v3 write-side cut to a
follow-up PR (both simplicity and python-shape independently proved the
`accept_offer`-bridge premise false for covenant prevouts); block-scan book source cut;
`encode_rswp_advert` renamed `encode_rswp_order` to mirror the decoder; bare-callable
transport replaced with a named `@runtime_checkable` async Protocol; strict v3
version/flag decode rule; advertised-ids-vs-reality bridge check; sighash-flag pin
(F1); tx-shape pinning (F5); fillable-predicate parity + MAX_MONEY cap (F6);
negative-vout bridge rejection (F7); browse-time txid-verified fetch (F8); adversarial
regtest matrix reduced to one case per consensus invariant. Rejected (with reason):
collapsing `getopenordersbywant` into a client-side filter (D16 — not derivable
client-side); folding `wire.py` into `orders.py` (the encoder is the conformance-vector
target and the reviewer marked the split acceptable either way).

## Out of scope (tracked follow-ups)

RSWP v3 write-side (refund covenant, covenant-aware take, expiry enforcement — its own
red-teamed PR, RXD-only first; must address the refund-selector txid malleability and
the post-expiry fill race documented above), CLI (`swap post/fill/orders`),
market-maker quoting toolkit, maker lifecycle tracker, RXinDexer `swap.*` source
adapter, NFT take/post, atheris harness for the encoder.

## Addendum (2026-07-05, the v3 follow-up PR): shipped v3 write-side scope

The v3 write side shipped as its own PR per D13, RXD-only, in
`pyrxd/swap/rswp/covenant.py`: covenant build/parse byte-compatible with the
Photonic layout (`63 <inner> 67 <expiryPush> b1 75 <inner> 68`; strict
both-ways minimality on the expiry push; differing-branch forgeries parse as
not-a-covenant), `prepare_covenant_offer` / `create_covenant_order` (v3 advert;
the signature push stays the bare two-push scriptSig — the TAKER appends the
`OP_1` selector, Photonic convention), `take_covenant_order` (requires
`current_height`; refuses at `tip >= expiry`), `build_covenant_refund_tx`
(`nLockTime=expiry`, `nSequence=0xFFFFFFFE`, `OP_0`) and
`build_covenant_cancel_tx` (SWAP branch, any height). Consensus-proven on
regtest: fill-before-expiry, refund-rejected-early, refund-at-expiry,
cancel-before-expiry, and a DELIBERATE on-chain demonstration of the F3
selector txid-malleability (track covenant refunds by OUTPOINT, never txid).
The deployed swapindex drops v3 adverts — also asserted on regtest.

**One deviation from the python-shape review's recommendation**, recorded
here: instead of teaching `partial.py`'s classifiers to see through the
covenant (option (a), a narrow seam), the v3 take is its own small completion
path (option (b)). Rationale: with the RXD-only restriction there is NO token
conservation to replicate — the completion is one arithmetic check — while
option (a) would have changed the shared classifiers' behavior for every v2
and private-envelope caller (e.g. a covenant UTXO advertised as v2 would have
started classifying as plain RXD and produced consensus-invalid completions).
Zero shared-code changes; the v2 bridge still refuses covenant-held gives
exactly as before (regression-tested). The seam approach remains the right
call IF FT-in-covenant ever becomes possible — revisit then.

**Red-team result (pre-PR gate, security-sentinel):** NO fund-safety blocker.
The parser-ambiguity hunt came back clean (structural argument + a
200,000-covenant fuzz with adversarially seeded `0x67`/`0xb1 0x75` bytes in
the pkh: zero mis-parses); scriptCode/selector/preimage handling verified
sound; all v2↔v3 tool interactions fail closed. Four Low findings, ALL
applied with regression tests: L1 the v3 take now enforces the same
metadata-vs-reality + MAX_MONEY bounds as the v2 bridge (its parity claim is
now literally true); L2 covenant funding requires the full P2PKH shape incl.
the `88ac` suffix; L3 negative-fee guards on take/refund/cancel; L4 the
FT-demand post/take asymmetry is documented at the API (postable —
protocol-valid for covenant-aware external takers — but not yet fillable by
pyrxd; the maker's refund is unaffected).
