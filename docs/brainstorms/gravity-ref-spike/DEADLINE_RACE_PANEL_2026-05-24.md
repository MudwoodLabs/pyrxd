# Deadline-race expert panel — findings (2026-05-24)

Four independent reviewers (cross-chain security architect, Bitcoin
consensus/timelock expert, protocol-simplicity reviewer, adversarial
game-theorist), writing blind. They converged.

## The vulnerability

Taker pays BTC (irreversible) to the maker's plain address, then must land an
on-chain SPV proof in Radiant `finalize` before a wall-clock `claimDeadline`;
else the maker's permissionless CLTV `forfeit` reclaims the asset. If BTC blocks
are slow / the payment is mined late / the maker set a tight deadline, the taker
loses the BTC AND gets no asset. `finalize`/`forfeit` spend the same UTXO
(mutually exclusive); the danger is purely *which clock fires first*.

## THE ROOT CAUSE (most important finding)

**The irreversibility is on the Bitcoin side.** The BTC payment goes to a plain
address with **no refund path** — once sent it is gone no matter what Radiant
does. Therefore **no Radiant-side deadline change can give the taker recourse.**
The current design is a *one-directional SPV oracle*, NOT an atomic swap. Every
deadline-tuning option leaves this hole; only binding the two legs closes it.

Also: `tx.time` is `>=`-only (OP_CHECKLOCKTIMEVERIFY is a consensus "not-before"
lower bound; rxdc rejects `<`). An in-script upper-bound deadline is impossible.
So the "deadline" is really *the moment the maker's forfeit becomes spendable*,
not a cutoff on the taker.

## Option verdicts (unanimous)

| Option | Verdict | Reason |
|---|---|---|
| Maker-signature-gated forfeit | **REJECT — strictly worse** | Doesn't stop a malicious maker (signs anyway); introduces PERMANENT asset stranding if maker vanishes + an extortion lever. Removes the permissionless liveness backstop. |
| Bond / forfeit-delay | Supplementary only | Maker prices a bond below a unique NFT's subjective value (eats it, keeps BTC); a fixed delay never creates an upper bound. Delay (= wide deadline) is a free margin knob, keep it; bonds are YAGNI/redundant (SPV already proves payment). |
| Timestamp-based deadline | Necessary-not-sufficient AND must be work-based | A single header timestamp is miner-skewable **±2h** (the 2-hour future-time rule); median-of-N is bounded but needs majority-miner cooperation + lags ~1h. Worse: it re-times `finalize` only — `forfeit`'s clock is untouched, so the race just relocates. If judged on timestamps (not work) it also invites taker header-grinding. |
| **Confirmation-depth / cumulative-PoW maturity** | **Correct primitive for the BTC side** | Self-stretches under slow blocks (the exact failure mode); ZERO timestamp-skew surface; only defeatable by a real K-deep BTC reorg = the SPV assumption you already accept. Bitcoin headers carry no height, but the proof already proves cumulative work. |
| **CSV (relative timelock, in blocks) on forfeit** | **Correct primitive for the Radiant side** | Anchors forfeit-eligibility to the covenant UTXO's own confirmation depth (Radiant blocks since funding), immune to any Bitcoin clock and to absolute-time skew. (NEEDS source check: confirm Radiant enables OP_CHECKSEQUENCEVERIFY + BIP68/112 flag semantics.) |
| Client-side "don't pay until safe" precondition | Necessary, NOT sufficient | The covenant is immutable + params visible pre-payment, so the taker CAN refuse a too-tight window (defeats accidental slow-block grief). But BTC confirmation time has no finite upper bound and the maker controls the deadline → a malicious "future-but-unsatisfiable" deadline still wins on the tail. Cheapest first move; ship it, but it doesn't close the malicious-maker hole. |
| **HTLC / adaptor signatures (true atomic swap)** | **The only fix that ELIMINATES one-sided loss** | Binds both legs with a shared secret so worst case = "both refund," never "taker loses BTC." Requires the BTC payment to go into an HTLC output (with a taker refund branch), not a plain address. |

## Two load-bearing technical findings

1. **A naive hashlock HTLC is likely BROKEN across these chains:** Radiant uses
   SHA512/256d, Bitcoin uses SHA256d — a shared `hash(secret)` lock won't match
   on both sides. **Adaptor signatures** (secret = a scalar revealed by a
   signature, not a hashlock) are the correct primitive and sidestep the hash
   mismatch. NEEDS source check: rxdc adaptor-sig / Schnorr support is unverified.
2. **HTLC timelock ordering is a hard safety constraint:** the chain where the
   secret is revealed SECOND must have the LONGER timelock. Here the secret is
   revealed on Radiant (taker claims), then the maker uses it on Bitcoin → the
   **Bitcoin refund timelock must exceed the Radiant claim timelock** by a margin
   covering reorg depth + relay + congestion. The taker's client MUST verify this
   ordering before paying, or a malicious maker mis-sets it.

## Recommended end-states (panel consensus)

**Combination A — atomic (the real fix, larger work):**
adaptor-signature swap (BTC HTLC output with taker-refund branch) + client-side
timelock-ordering check (`t_BTC − t_RXD ≥ margin`, Bitcoin holds the longer
lock). No adversary strategy survives; worst case is mutual refund. Engineering
risk: BTC-side HTLC output, getting the secret to Radiant, adaptor-sig support.

**Combination B — non-atomic hardening (defensible fallback, keeps current shape):**
(1) confirmation-depth / cumulative-PoW maturity on `finalize` (work, not
timestamps) + (2) CSV relative-block lock on `forfeit` + (3) client-side P99-tail
margin check at pay-time. Reduces the race to a *symmetric* slow-block tail
(non-adversarial), drivable toward zero by margin width — but does NOT provably
eliminate one-sided loss, because the BTC payment still has no refund path.
Explicitly NOT maker-sig forfeit (regression).

## Honesty / open verifications before building either
- Radiant CSV/BIP68/112 parity (read interpreter.cpp CheckSequence + flags).
- What `tx.time` binds to in the Radiant interpreter (nLockTime vs MTP).
- rxdc adaptor-sig / Schnorr support (gates Combination A).
- Whether a median-of-N-timestamps or work-threshold fits the covenant's
  script-size budget (compile-test; the covenant is already ~8-11KB).
- The P99 margin is an ESTIMATE — derive from observed BTC inter-block data.

## The blunt takeaway
The Gravity swap as built is not atomic, and for an irreversible NFT that is the
dominant risk — bigger than the parser bugs already fixed. The honest options are
(A) build the adaptor-sig atomic swap, or (B) ship the work-maturity + CSV +
client-margin hardening AND document plainly that one-sided BTC loss on a
pathological tail remains possible because the BTC leg has no refund. Maker-sig
forfeit and bonds are not real fixes.

## Capability spike (2026-05-24, Radiant-Core + RadiantScript source) — corrects the panel

All source-cited (interpreter.cpp / transaction.h / tx_verify.cpp / policy.h /
RadiantScript Globals.ts + utils.ts + CashScript.g4):

- **CSV / relative timelock: SUPPORTED, first-class.** RadiantScript `tx.age`
  compiles to `OP_CHECKSEQUENCEVERIFY` (utils.ts:17); CSV is a real enabled
  opcode (interpreter.cpp:398), BIP68 enforced (tx_verify.cpp:65, v2 tx). Shipped
  examples exist. **The CSV-relative-forfeit leg needs NO asm.**
- **`tx.time` = CLTV vs spending-tx nLockTime** (Globals.ts:52, utils.ts:14).
  `>=` only (grammar CashScript.g4:89). `OP_TXLOCKTIME` exposes the raw value.
- **Schnorr + checkSig/checkDataSig: SUPPORTED** (interpreter.cpp:2710, 1162;
  language utils.ts:38,40). Adaptor swaps are buildable in the standard sense —
  the chain only verifies ordinary Schnorr sigs; the adaptor secret-leak is
  off-chain/wallet-side, exactly as on Bitcoin. No on-chain adaptor primitive
  (no EC point/scalar opcode), but none is needed.
- **CORRECTION to the panel's "naive hashlock HTLC is broken":** WRONG. Radiant
  has plain Bitcoin-compatible `OP_SHA256` (interpreter.cpp:1084) and
  RadiantScript `sha256`→`[OP_SHA256]` (utils.ts:45). A standard SHA256 hashlock
  matching a Bitcoin HTLC's `OP_SHA256(x)` IS expressible on the Radiant side.
  The SHA512/256d in project memory is Radiant's PoW/ref hashing, NOT a covenant
  constraint. So a plain hashlock HTLC works cross-chain; adaptor sigs are an
  optimization, not a requirement. This makes the atomic swap SIMPLER than feared.
- **CORRECTION on "work maturity":** a true cumulative-PoW *work* threshold is
  NOT natively expressible — script arithmetic is 64-bit-capped with
  overflow-reject (interpreter.cpp:276,945), no 256-bit math, no chainwork
  opcode. Maturity must be **confirmation-DEPTH** (chain-linked header count),
  not summed work. Reading a header's 4-byte timestamp via split+BIN2NUM works
  (signed-BIN2NUM caveat for post-2038 / high-bit timestamps).

**Both fix options are BUILDABLE.** (A) hashlock/adaptor atomic swap; (B)
confirmation-depth maturity + `tx.age` CSV forfeit. The CSV leg of (B) is the
cleanest asm-free piece on the platform.
