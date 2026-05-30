# Gravity FT↔BTC — first real cross-chain swap (2026-05-21)

A live, end-to-end Glyph **fungible-token ↔ Bitcoin** atomic swap, settled on
Radiant mainnet against a **real Bitcoin mainnet payment** verified by SPV.

## What happened

A maker offered 1,000 units of a Glyph FT (**GSWAP2**) for 10,000 sats of BTC.
A taker paid the BTC on Bitcoin mainnet; the Radiant covenant verified that
payment via an on-chain SPV proof (real BTC headers + Merkle inclusion) and
released the FT to the taker. No custodian, no bridge, no trusted relayer —
the covenant alone gates the release on proof of the Bitcoin payment.

## Verifiable transactions

**Radiant (Glyph FT side):**
- FT genesis (GSWAP2, 1,000 units): `3c0cf043c7d760fe9f821feeab1a7fae205f2aab8e9a6268e7d0125997b8b4ea:0`
  (reveal `eacc7c4f201fa6c29901f9f28342ff8521440fb801bd1be6e738c3a47a3d2859`)
- FT funded into the swap covenant: `9dab8c33199929447d5754e86909e420dc0b8d98d6f68065652c4b66ce3fb110`
- **Settlement (finalize, SPV-gated):** `04a2f1bfeacaf703b1dcacc59ef3d097d73f973cb12de0265c8133a6001bb789`
  — releases the 1,000 FT units to the taker.

**Bitcoin (payment side):**
- **Payment to the maker (10,000 sats, P2WPKH):**
  `d79f30dd7722c988b9debb2df4ff0fb32c3e8e61f29d395da0c3860b40d75294`
  confirmed in block **950,453**.
- Maker receive address: `bc1qdwz0n8l72x5eqzakkqsx42p7pdmepzyrgumwzk`

## What the covenant verified on-chain (Radiant consensus)

1. Chain-identity anchor: header h1's prevHash == a committed real mainnet
   block (950,452).
2. 12 real Bitcoin block headers (950,453–950,464), each with valid
   proof-of-work and chain-linking.
3. Merkle inclusion of the payment tx in block 950,453 (depth-13 tree,
   sentinel-padded to the covenant's 20-level capacity).
4. The payment output pays the maker's committed address for ≥ the required
   satoshis.
5. FT conservation + the swap hardening (single ref, exact amount, single
   output) + a hash-compare pinning the FT to the taker's address.

## Honest scope (what this does and does not show)

- **Real, not synthetic.** Real BTC moved on Bitcoin mainnet; the proof uses
  real headers/Merkle, verified by Radiant consensus (`testmempoolaccept` +
  broadcast).
- **Taker payment shape (current limitation).** This covenant variant requires
  the taker's BTC payment to be a single-input segwit tx (the conforming
  payment was built with pyrxd's `build_payment_tx`). An **any-wallet** variant
  (multi-input, change anywhere) is designed, prototyped, and integrated
  (compiles + passes static guards) but is **not yet proven on-chain or
  audited** — see the any-wallet design note. A production "pay from any
  wallet" claim depends on that work + an external audit of the BTC-tx parser.
- **Not yet audited.** This is spike/validation work. External audit of the
  covenant — especially the SPV parsing path — is a hard gate before any
  production/mainnet-product claim.

## Parameters that matter (operational lessons)

- The covenant's `btcChainAnchor` must be set **just before** the BTC payment,
  with a **wide header window (N)**, or the payment can land outside the
  provable window. (Set anchor = payment_block − 1 after the payment confirms.)
- The covenant's **Merkle depth (M) must exceed the real block's tree depth**
  (mainnet blocks routinely exceed depth 12). Use the sentinel M=20 variant.
- The wide-window covenant is ~10 KB, so funding it costs ~1 RXD — a real
  per-swap cost to weigh in production parameter choice.

---

## Any-wallet variant — multi-input BTC payment PROVEN on mainnet (2026-05-22)

The single-input limitation above is now lifted by the **any-wallet covenant**
(on-chain varint input-skip + output-scan), proven end-to-end on mainnet with
a **real multi-input Bitcoin payment** — the exact tx shape the single-input
covenant rejects.

**Positive (settled):**
- FT: **GSWAPAW** (1,000 units, genesis `537c86b69b039d87f2f4023806948d1fe01f945955289296087f0ee3b03e7858:0`)
- Multi-input BTC payment (**2 inputs**, output[0]=10,000 sats to the maker,
  output[1]=change): `0ae8365496f1eb20b4e1c82f115326b85133099854f1aa3839de2087a141dc6a`
  (block 950,541).
- Any-wallet covenant (N=12 headers, M=20 sentinel merkle, varint parser),
  anchor=block 950,540, funded `922f080f8f09515870ce6fc78e6122ae4e6b52b6e5ac2c7287072e047c21035e`.
- **Settlement (finalize over the multi-input proof):**
  `53ee763148f85c843f82b628706480395028522701e408ef4722a61ca5ad4616` — the
  covenant parsed a 2-input BTC tx, scanned its outputs, found the payment,
  and released the FT. A taker can pay from a normal multi-input wallet.

**Negative (rejected on-chain):** a real, in-block, Merkle-provable multi-input
tx that does NOT pay the maker, submitted as the proof, was **rejected** with
`mandatory-script-verify-flag-failed (OP_VERIFY)` — the parser's `require(found)`
fails because the output-scan finds no output paying `btcReceiveHash`. So the
parser verifies the payment is actually present, not merely that the tx parses.
(`validate_anywallet_parse.py` additionally covers wrong-hash and
insufficient-value rejection in the offset-logic mirror.)

**Still required before production:** generalize the output-type match to all
`btcReceiveType` (the current scan matches P2WPKH only), and an **external
audit of the BTC-tx parser** (the most security-critical covenant code) — the
hard gate. The any-wallet covenant is ~10.4 KB, so funding it costs ~1.05 RXD;
this size/fee is the cost of on-chain wallet-agnostic payment parsing.

**Both-chain artifacts (any-wallet swap):** Bitcoin payment `0ae83654…` (block
950,541); Radiant settlement `53ee7631…`. User BTC swept back (`ce90a7f9…`).

---

## NFT↔BTC variant — first NFT swap settled on mainnet (2026-05-23)

The covenant design extends from fungible tokens to **one-of-one Glyph NFTs**.
An NFT was minted, locked into an NFT swap covenant, and released to a taker
against a **real Bitcoin payment verified by SPV** — then the forfeit (reclaim)
path and a full set of negatives were proven.

### Why NFT ≠ FT (and why it's actually simpler)

An FT holder is welded to its *code-script* (the `codeScriptHashValueSum`
epilogue) — it cannot be moved into a foreign covenant; that was the original
FT blocker. An NFT is welded only to its *singleton ref*
(`OP_PUSHINPUTREFSINGLETON`, `0xd8`), so it **can be held directly in a
covenant**. The funded UTXO is the covenant bytecode itself, carrying
`d8<ref>` inside its body.

**The dominant security fact (verified from Radiant-Core source,
`validation.h:919-968`):** consensus only enforces *singleton-outputs ⊆
singleton-inputs* — it **permits burning the NFT** (zero output copies) and
never requires it to land on any particular output. So "exactly one output, to
the right destination" is enforced **solely by the covenant body**
(`outputs.length==1` + `refOutputCount(ref)==1` + a value pin +
hash-compare). There is no consensus backstop. For an irreversible one-of-one,
the covenant is the sole guarantor of conservation — strictly more load-bearing
than FT. (An earlier draft wrongly claimed consensus requires the singleton on
exactly one output; a security-focused divergent review caught it.)

### Verifiable transactions

**Radiant (NFT side):**
- NFT genesis (commit): `ff5c20f6c4445584a261764eefdeada0228bda632d704367c4b04659c58ee940:0`
  (reveal `217fca8405e4c925b79121741ef65fb328aa87b7762d9cbc3abeb4f9169fd263`)
- NFT funded into the swap covenant:
  `e10798b3c10b85c6f8c6b18fcd647481ad5b5abb333e2f224d2cea1708bde09f`
  (`testmempoolaccept` then broadcast — the first on-chain proof that an NFT
  singleton can be held in a covenant and its conservation accepted by
  consensus)
- **Settlement (finalize, SPV-gated):**
  `cb3f6d9cc0df2c6b179a26088a26b3aea6929ef0b2e72ab1a9166507255538cc`
  — releases the NFT to the taker.

**Bitcoin (payment side):**
- Payment to the maker (11,000 sats, P2WPKH):
  `092b331d0e352d1bad80c9cc1776d038bf29cd4a77809541d78b4a116249b388`,
  confirmed in block **950,763**.
- Covenant `btcChainAnchor` = block **950,762** (payment block − 1, set
  just-in-time per the operational lessons).

### What the covenant verified on-chain

1. Real-headers SPV proof: anchor (h1.prev == block 950,762), 12 real BTC
   headers (950,763–950,774) with valid PoW + chain-linking, Merkle inclusion
   of the payment (**real depth 13**, sentinel-padded to the covenant's M=20
   capacity — the depth that broke an earlier M=12 attempt).
2. The any-wallet BTC-tx parser (the payment was a 1-input / 2-output P2WPKH tx).
3. NFT singleton conservation: the ref carried from the covenant input to the
   taker NFT output.
4. NFT hardening: `outputs.length==1`, `refOutputCount(ref)==1`,
   `outputs[0].value == nftCarrierValue`, and a hash-compare pinning the NFT to
   the taker's standard 63-byte NFT script.

### Forfeit + negatives (a second NFT)

A second NFT (genesis `c6e0e6d9…:0`) was minted and locked into a covenant with
a past deadline.

- **Forfeit success (CLTV reclaim → maker):**
  `60d7cedd58720a50befc3c652b7760e95296b0942fe7c04f4e8f3e353fd1ca12`.
- **Five negatives — all rejected by consensus** (`testmempoolaccept`
  allowed=false), each for the precise reason:
  | Case | Rejection |
  |---|---|
  | burn (output not NFT-shaped) | `OP_NUMEQUALVERIFY` — `refOutputCount(ref)==1` (**covenant-only** guard) |
  | clone (two NFT outputs) | consensus `invalid-transaction-reference-operations` (singleton can't duplicate — consensus + covenant) |
  | wrong destination | false top stack — `hash256(output[0]) != expectedMakerNftHash` (**covenant-only**) |
  | wrong carrier value | `OP_NUMEQUALVERIFY` — `outputs[0].value != nftCarrierValue` |
  | pre-deadline reclaim | Locktime requirement not satisfied (CLTV) |

  The **burn** and **wrong-destination** cases are caught *only by the covenant
  body* — empirical confirmation that the covenant-only conservation holds with
  no consensus backstop.

### Honest scope (NFT)

- **Real, not synthetic.** Real BTC moved on Bitcoin mainnet; the SPV proof
  used real headers/Merkle, verified by Radiant consensus.
- **Proven on-chain:** the NFT prologue + singleton-conservation interaction,
  the finalize and forfeit paths, and the covenant-only negatives.
- **Not yet audited.** NFT irreversibility (no fungible make-whole) raises the
  bar: external audit of the SPV/BTC-tx parser is a hard gate before any
  production/mainnet-product claim, weightier than for FT because conservation
  is covenant-only.

### Incident: weak test key — real BTC lost (operator error, not the covenant)

During setup the maker/taker keys were hand-generated with
`PrivateKey(b'\x03'*31 + bytes([secrets.randbelow(255)+1]))` — only **254
possible private keys** (the maker BTC key was `0303…03ee`). A weak-key watcher
bot brute-forced it and **swept the 11,000-sat payment in the same block
(950,763)** it confirmed, to `bc1qfmkwac2g0e5aqv4j28jjjrf0485cs3rpp9ke7f` (not
ours). The funds are unrecoverable. The theft tx's witness pubkey matched the
maker key, confirming brute-force — **not** a covenant bug.

This was operator error in a throwaway command, fully orthogonal to the swap
mechanism (which performed exactly as designed). Production key generation
(`pyrxd.btc_wallet.keys.generate_keypair()`, CSPRNG + rejection sampling) was
never involved. Lesson recorded: never hand-write key material for any address
that will receive funds; always use the CSPRNG generator.

---

## Taproot-HTLC atomic swap — Radiant leg proven on mainnet (2026-05-24)

The atomic-swap redesign (the secure replacement for the SPV-oracle swap; see
DEADLINE_RACE_PANEL_2026-05-24.md + the plan 2026-05-24-feat-gravity-taproot-htlc-atomic-swap-plan.md).
This proves the **Radiant leg** — the hashlock `claim(preimage)` release and the
`tx.age` CSV `refund()` — on mainnet for all three swap asset types. The BTC-side
Taproot HTLC module (src/pyrxd/btc_wallet/taproot.py) is BIP341-vector-validated
but the **full cross-chain BTC↔RXD atomic swap (real BTC HTLC + secret-scrape)
is Phase 4 and NOT yet done.**

Shared secret: `H = sha256(p)` = the covenant hashlock; `claim(preimage)` reveals
`p` on-chain in the scriptSig (the cross-chain reveal channel). `refund()` is the
maker's `tx.age >= refundCsv` (BIP68) reclaim. Covenants: GravityHtlcCovenant
{Ft 222B, Nft 171B, Rxd 141B} — selector dispatch (claim=OP_0 / refund=OP_1),
OP_0 OP_OUTPUTBYTECODE OP_HASH256 destination pin.

### Verifiable transactions (Radiant mainnet)

**RXD↔BTC HTLC — 4/4 proven:**
- claim (correct preimage) → `428b14018342f65267a34c7a3cd26fe4eba5c97e66d6da633eb8446b992f1187`
- wrong-preimage claim → REJECTED `OP_EQUALVERIFY` (sha256(preimage)==hashlock)
- premature refund → REJECTED `Locktime requirement not satisfied` (CSV gate)
- matured refund (after 2 confs) → `9f008f50a00f8e5791c761cc0dd67e69d22d21dde1fbf6a36c8cd5dc07756ec9`

**FT↔BTC HTLC:**
- FT minted (genesis `678e3907…:0`, 1,000,000 units), funded into the covenant,
  claim (preimage) → `e75f4d8dd4303bb90fd0b94c26be19f00eef24bb2bc34b39fd6369a922cacda8`
  (FT released to taker; FT L1 ref-conservation + L2 codeScriptHashValueSum intact).

**NFT↔BTC HTLC:**
- NFT minted (genesis `5624089236…:0`), funded into the covenant,
  claim (preimage) → `8333e80bf3d36e728fb2c3bbddfdd937d0d70d999909ecb66facba98387ff318`
  (NFT released to taker; singleton conserved through the covenant).
- wrong-preimage claim → REJECTED `OP_EQUALVERIFY`.

### Honest scope of the FT/NFT refund

The FT and NFT **refund** routes (`tx.age` CSV + maker hash-compare) are present
and static-guard-verified in their compiled covenants, and are the **byte-identical
CSV mechanism proven on-chain by the RXD matured refund** (`9f008f50…`). They were
NOT separately broadcast: each would require minting a fresh 2nd asset (the first
mint is consumed by the claim covenant) to prove a mechanism that is identical to
the already-proven RXD refund. The premature-refund negative is proven (RXD). This
is a deliberate, recorded scope decision, not an omission.

### What this does and does NOT show

- **Proven on mainnet:** the Radiant leg of all 3 swap types — hashlock claim
  (with the preimage revealed on-chain) + CSV refund + the wrong-preimage and
  premature-refund negatives. The HTLC covenant machinery works under live consensus.
- **NOT done:** the full cross-chain atomic swap — a real Bitcoin Taproot HTLC
  funded on BTC mainnet, the secret revealed on one chain and scraped to claim the
  other, with the timelock-ordering margin enforced (Phase 4: coordinator + state
  machine + watchtower).
- **Hard gate:** external audit of the cross-chain atomicity + the parser/SPV path +
  the covenants — before any production/mainnet-product claim. NFT/RXD have no
  consensus conservation backstop (RXD especially), so the covenant body is the sole
  guarantor there.

Operational lessons applied: per-kB relay fee (0.10 RXD/kB on the tr node, size×rate);
minimal-pushed CSV operands; multi-function selector dispatch; hash-compare output pin;
CSPRNG keys only (no hand-written keys, per the prior weak-key incident).

---

## Phase 4b — FIRST FULL CROSS-CHAIN BTC↔RXD ATOMIC SWAP (mainnet, 2026-05-24)

This is the milestone Phases 1–3 could not show: **the two legs bound by one secret,
settled end-to-end on real chains.** Bitcoin **mainnet** Taproot HTLC ↔ Radiant
**mainnet** RXD covenant. The preimage revealed on the BTC chain was scraped from the
on-chain witness and used to claim the Radiant asset — atomicity demonstrated live.

Shared secret: `H = sha256(p)` = `e2caff98248059dc566c7ea10a32208132fefc984d0e80880a162ef509f1d21c`
(fresh CSPRNG; `p = f683f50e…e3d854c2`). Role: MAKER_SECRET_TAKER_LOCKS_BTC_FIRST.

### Happy path — COMPLETED (verifiable on both mainnets)

1. **Taker locks BTC** (P2TR HTLC, claim leaf `OP_SHA256 <H> OP_EQUALVERIFY <makerX> OP_CHECKSIG`,
   refund leaf `<takerX> OP_CHECKSIGVERIFY <6> OP_CSV`):
   funding tx **`30310df9375884bba726019008078731377ce18e6a75348934e769b76f28ffc3`** (vout 0, 2500 sats)
   → HTLC addr `bc1p78e72e5gazcklekwtyy9j50cqv36mp43phcq9s9nu2xlsqxl84fq9vlh8d`.
2. **Maker locks the RXD asset** in the 141-byte HTLC covenant (amount=100000 pin, selector
   dispatch, hash-compare dest pin): funding **`c4882a6eaecd7abacf2cb0125f7b619f2414618da63cd4f57f44f580b248451b`**
   (vout 0, 500000 photons carrier).
3. **Maker claims BTC** revealing `p` in the witness:
   BTC claim **`0e2ba620073b5bd08ddfa6d418912eff7705eaab947afdbe56040a833e8ef6e3`** (confirmed).
4. **Taker scrapes `p`** from the on-chain BTC claim witness (`taproot.scrape_secret`,
   matched by `sha256(p)==H` over every witness push — fetched from the network, not local)
   and **claims the RXD asset**:
   RXD claim **`d9f8dee91ba7a1f874b4003e44898beddc4fac00ea670920990ed4589a8f67db`** —
   covenant scriptSig = `20<p>00` (preimage + OP_0 selector), 0.055 RXD → taker
   `1GYMMrSqtjuybUQZZ35MwwWQa9yRM221bt`. The preimage in the RXD scriptSig is BYTE-IDENTICAL
   to the one in the BTC claim witness: the cross-chain binding, proven.

### Refund safety net (the atomicity guarantee for MUTUAL_REFUND / MAKER_STALLS)

The BTC CSV-refund leaf is what makes this atomic (vs the old non-atomic SPV-oracle swap):
- **Premature BTC refund → REJECTED `non-BIP68-final`** (mainnet mempool, consensus-enforced):
  refund-test HTLC funding `d0c32b60ebb72b9503eaa4a82dc720b1c96451d95cf45ff03a8fa3e8594ee759`
  (1500 sats); the v2/nSequence=6 refund tx is valid but rejected before the 6-block relative
  timelock matures. This is the consensus gate that lets the taker reclaim BTC if the maker
  never claims — and forbids reclaiming early.
- **Matured BTC refund → ACCEPTED on mainnet (with the FIXED leaf):**
  `e29e9b310baa829370780e40e8336bcc9b689f3af42a0b0a4f411e9199a48ffd`. The original
  refund leaf (`<pk> OP_CHECKSIGVERIFY <timeout> OP_CSV OP_DROP`) was BROKEN — it ended
  with an empty stack and every refund was rejected `Stack size must be exactly one
  after execution`. The fixed leaf (`<timeout> OP_CSV OP_DROP <pk> OP_CHECKSIG`) was
  funded into a fresh HTLC (`74f4a8f7ea4be98ddb7e826345f305763ae8e2c5fe4b88816e84d220a08cdac4:0`,
  600 sats), the premature refund was again rejected `non-BIP68-final`, and after the
  6-block CSV matured (funding block 950900 → tip 950906) the refund spent the HTLC via
  the refund leaf (v2, nSequence=6, witness = sig + script + control-block), paying 450
  sats to the taker. **The BTC refund path is now proven BOTH WAYS on mainnet:
  premature → rejected, matured → accepted.**
- The Radiant `tx.age`/CSV refund leg is byte-identical to the already-proven RXD matured
  refund `9f008f50a00f8e5791c761cc0dd67e69d22d21dde1fbf6a36c8cd5dc07756ec9` (Phase 3).

### Honest scope

- **PROVEN end-to-end on mainnet:** the full cross-chain atomic swap happy path (both legs,
  one secret, scrape-from-chain) + the BTC premature-refund consensus rejection.
- **A bug found + corrected mid-run (recorded for honesty):** the first covenant was built with
  `amount=50000000` but funded with only 100000 photons → `OP_OUTPUTVALUE >= 50M` made BOTH
  claim and refund unsatisfiable; 100000 photons (0.001 RXD) stranded at
  `7df1e7ef80c76710b11b8cbc977592b68948f51faef15651db4cd7d82e62e535:0`. Lesson: the covenant
  `amount` pin MUST equal (or be ≤) the actual funded carrier. The v2 covenant used a matching
  pin and claimed cleanly. **A working demo is not an audit; the amount/carrier coupling is
  exactly the kind of thing the external audit must cover.**
- **NOT yet shown:** the matured BTC refund broadcast (pending block maturity); a watchtower
  (Phase 5). External audit remains the HARD GATE before any production claim.

---

## Phase 4b (cont.) — ALL THREE asset types swapped cross-chain on mainnet + refund-leaf bug

Following the RXD swap above, the full cross-chain HTLC swap (real BTC Taproot HTLC ↔
Radiant covenant, preimage scraped off the BTC witness and used on Radiant) was proven
end-to-end on mainnet for **FT and NFT** as well — reusing the FT/NFT assets minted in
Phase 3 (re-funded from their prior-claim holder UTXOs into fresh HTLC covenants).

### Full cross-chain swaps — 3/3 happy paths (verifiable on both chains)

| Asset | BTC HTLC fund | BTC claim (reveals p) | Radiant asset claim (uses p) |
|---|---|---|---|
| **RXD** | `30310df9…f28ffc3:0` | `0e2ba620…3e8ef6e3` | `d9f8dee9…9a8f67db` |
| **FT** (1,000,000 units) | `67b205e2…3b7364bd:0` | `7f1bf6cd…4350bdc4` | `2e0a7ba9…eff79702` |
| **NFT** (singleton) | `e7f02c40…d2dc28dc:0` | `df970ff0…de9adc6c` | `a311de73…40e0842b` |

For each: the preimage `p` pushed in the Radiant claim scriptSig is **byte-identical**
to the `p` revealed in that swap's Bitcoin claim witness (independently scraped from the
network copy via `taproot.scrape_secret`, matched by `sha256(p)==H`). FT conservation
(L1 ref + L2 codeScriptHash) and NFT singleton conservation held through their covenants.

### BUG FOUND + FIXED: the BTC refund leaf was unspendable

The matured-refund proof (the *other* half of atomicity) surfaced a real bug. The BTC
refund leaf was built as `<refundPk> OP_CHECKSIGVERIFY <timeout> OP_CSV OP_DROP`. Tracing
the stack with witness `[sig]`: CHECKSIGVERIFY drains the stack to empty, then OP_CSV
(verify-don't-pop) + OP_DROP leaves it **empty** — so every refund spend is rejected by
Bitcoin consensus:

```
mempool-script-verify-flag-failed (Stack size must be exactly one after execution)
```

This is NOT a timelock failure — the CSV maturity gate *passed* (tip 950899 > the
6-block maturity of funding `d0c32b60…` at block 950892); the earlier `non-BIP68-final`
rejection had only proven the *timelock* gate, never that the leaf *executes*. The fix
(canonical BOLT-3 / Boltz ordering — timelock first, value-leaving OP_CHECKSIG last):

```
<timeout> OP_CSV OP_DROP <refundPk> OP_CHECKSIG     # ends with exactly one truthy item
```

Fixed in `src/pyrxd/btc_wallet/taproot.py::refund_leaf_script`. **This changes the
taptree → the HTLC address**, so HTLCs built before the fix are refund-unspendable
(claim-only) — but the swap HTLCs above were all *claimed*, so no funds were lost.

**Test-gap lesson:** the taproot suite asserted address-derivation (BIP341 vectors) and
signature crypto, but **never executed either leaf through an interpreter or broadcast** —
so this stack-discipline bug was invisible. The matured-refund on-chain test is what
caught it. A fresh HTLC `74f4a8f7…a08cdac4:0` was funded with the FIXED leaf to re-prove
the matured refund on-chain.

### Honest refund status (do NOT overclaim)
- **Radiant-side refund (tx.age/CSV):** PROVEN on mainnet (`9f008f50…`, Phase 3).
- **BTC-side premature refund:** REJECTED `non-BIP68-final` (timelock gate proven).
- **BTC-side matured refund:** PROVEN on mainnet with the FIXED leaf —
  `e29e9b310baa829370780e40e8336bcc9b689f3af42a0b0a4f411e9199a48ffd` (450 sats to the
  taker after the 6-block CSV). The original leaf was broken (empty-stack); the fix
  (`<timeout> OP_CSV OP_DROP <pk> OP_CHECKSIG`) settles. **The BTC refund path is now
  proven both ways (premature rejected, matured accepted).** External audit remains the
  hard gate before real value.

---

## ETH↔RXD atomic swap — FIRST cross-chain swap on a SECOND counter-chain (2026-05-25)

The Gravity atomic-swap primitive generalized beyond Bitcoin: the **first ETH↔RXD
cross-chain atomic swap**, Ethereum **Sepolia** testnet ↔ Radiant **mainnet**, settled
end-to-end. Same one-secret mechanism as BTC↔RXD; the counter-chain leg is a Solidity
HTLC instead of a Taproot tapscript. The Radiant covenant was UNCHANGED (it is
counterparty-chain-agnostic: `sha256(preimage)==H` + `tx.age` CSV).

Shared secret: `H = sha256(p)` = `0x7c5801e95fa158046651bed20abfd6dc0bc3f3fb2f62203c81e6e8fc33dc4aab`
(fresh CSPRNG; `p = daa041bf…81be0db8`). Role: MAKER_SECRET_TAKER_LOCKS_COUNTERCHAIN_FIRST.

### Happy path — COMPLETED (verifiable on both chains)

1. **Taker locks ETH FIRST** — deploys + funds the native-ETH HTLC contract on Sepolia
   (`EthHtlc.sol`: sha256-precompile hashlock, claim(preimage)/refund-after-timeout,
   CEI+settled, EOA-only recipients): contract
   **`0x35d07083A967c24B90873f3366BEf90dc3c46Caa`**, deploy tx
   **`0x5f1a8ca3817937d98ec134fd00ccf93aa6d0bc7d02a235bcaaeb6f61d3c90c85`** (0.001 ETH).
2. **Pre-RXD-lock gate PASSED** — the taker verified the on-chain contract's runtime
   logic (immutable slots masked) == the committed artifact AND the immutables read back
   via getters (hashlock/claimant/refundee/timeout) == the negotiated terms AND the
   funded balance == 0.001 ETH, before the maker locked RXD.
3. **Maker locks the RXD asset SECOND** — 141-byte RXD HTLC covenant (amount pin 5M ≤
   carrier 5.5M), funded **`12f93d6e4fe14983cf3a8ae17ce1144cfdc835f05b7babe93054280882965059:0`**
   (5,500,000 photons) on Radiant mainnet.
4. **Maker claims the ETH** revealing `p` in calldata + a `Claimed(p)` event:
   Sepolia claim **`0x30d06fe783054c98f25b4cb010e83e9b2d66ae22c069b4f9be802e24a0b2961e`**.
5. **Taker scrapes `p`** from the Sepolia claim (calldata + event-log data, matched by
   `sha256(candidate)==H` over every 32-byte window — the C-PARSER discipline; no offset
   parsing) and **claims the RXD asset**:
   RXD claim **`3704227cadcc3b4cf9ee1cd6ceb62219a9a1cc9a5cce9b7cb52bc709c91e26c8`** —
   covenant scriptSig = `20<p>00`, 0.105 RXD → taker `16bxKGPGq8dqpwwEGmt1F3wPHrFtkXcNPs`.
   The `p` in the RXD scriptSig is BYTE-IDENTICAL to the `p` revealed in the Sepolia ETH
   claim — the two legs welded across Ethereum and Radiant by one secret.

### What this shows / honest scope

- **PROVEN end-to-end:** the cross-chain atomic-swap primitive works on a SECOND
  counter-chain (Ethereum) with no change to the Radiant side — the same secret settles
  an EVM contract leg and the Radiant covenant leg. ETH was easier than BTC in the
  expected ways (sha256 precompile, `p` trivially read from calldata/event, no
  witness-scraping), and the new surface (a fund-custodying contract) carries the
  expected new risk.
- **NOT yet shown:** the ETH-side matured refund on-chain (the absolute-`block.timestamp`
  timeout + the relative-RXD-CSV ordering, with the `D` RXD-lock-deadline term, is
  designed in the plan; a deliberate MUTUAL_REFUND is the next exercise) and the
  reverted-but-mined `p`-leak path (covered by the pure tests, not yet on-chain).
- **Cross-net caveat:** this was Sepolia (resettable, weak finality) ↔ Radiant mainnet.
  Margins for any real-value ETH swap must come from MAINNET ETH finality (≥2 epochs),
  not Sepolia timing — the Phase-4a margin model (`require_measured=True`) enforces this.
- **HARD GATE:** external audit of `EthHtlc.sol` + the cross-chain atomicity before any
  real-value (mainnet ETH) use. A Sepolia proof-of-mechanism is not an audit.

Software: `contracts/EthHtlc.sol` (+ committed artifact), `src/pyrxd/eth_wallet/`
(secret/locator/keys/rpc/htlc_leg), harness `eth_sepolia_swap.py`. Per-leg margin-model
fix (ETH 12s vs RXD interval) landed first. Full suite 3208 green.

### ETH refund — proven BOTH WAYS on Sepolia (the MUTUAL_REFUND safety net)

A fresh HTLC (`0xE00B4d1E0597716B2380fDE648AbdC353D764d40`, 0.001 ETH, short +180s
timeout) where the maker deliberately never claims — proving the taker reclaims:

- **Premature refund → REVERTED on-chain** (status 0, contract `NotYetExpired`): tx
  `0x95058c3210d6f97b0aa9ec30167f045f21d113fd33aa9426b4547ea88324d0bd`, mined at block
  ts 1779694200 < timeout 1779694243. The `require(block.timestamp >= timeout)` gate
  forbids early reclaim.
- **Matured refund → SUCCEEDED** (status 1): tx
  `0xe45155220ba4663e22db773fd1cbb0e6fdc4182272135dfa39fb7e17b3262c43`, mined at block
  ts 1779694272 >= timeout; the HTLC contract balance dropped to 0 (drained to the taker
  `refundee`). Taker-unilateral — no maker signature.

So the ETH leg's atomicity safety net is proven: worst case is "both refund," never
one-sided loss. Combined with the happy path above, the ETH↔RXD swap is proven on both
the claim and refund branches (Sepolia), mirroring the BTC↔RXD both-ways proof.

**Lesson surfaced (recorded, not yet fixed):** the leg broadcast the premature refund
without an `eth_call` preflight, so it wasted gas on a guaranteed revert. Add a preflight
`eth_call` (or `estimate_gas`, which reverts on a would-fail tx) before broadcasting
claim/refund, to fail fast off-chain instead of burning gas on-chain. Not a safety bug
(the contract correctly rejected it); a gas-efficiency + UX fix for the leg.
