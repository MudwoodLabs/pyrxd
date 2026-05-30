# SPV verification pitfalls

**Who this page is for:** anyone implementing or reviewing a Bitcoin (or
Bitcoin-derived) SPV / light-client verifier — the layer that decides "is
this transaction really confirmed in the chain?" from a Merkle proof and a
block header, without running a full node.

This is the companion to [Verify an SPV proof](verify-an-spv-proof.md): that
page is the *how* (the recipe for calling pyrxd's verifier); this page is the
*why* — the non-obvious ways an SPV verifier stays insecure **even after** it
"checks the Merkle proof." Every item here came out of an adversarial review
of pyrxd's own SPV layer; the failure modes are generic, so the guidance
applies to any implementation (a wallet, an Electrum/light client, a bridge,
a re-write in another language).

## The one principle

Verifying a Merkle branch against a header's Merkle root is necessary but
buys you little on its own. It only moves trust from *"the server gave me the
transaction"* to *"the server gave me the header."* A malicious or lazy data
source can hand you a **self-consistent fake header plus a valid branch to a
fake transaction**, and the Merkle check passes clean.

Almost all of an SPV verifier's real security lives in the **header layer** —
proof-of-work, difficulty, and chain selection — not in the Merkle check.
Treat "the Merkle root matches" as the *last* step, not the *only* step.

Items below are ordered by impact for a **standalone** verifier (a wallet or
light client with no other backstop). A verifier that sits behind something
that already pins difficulty — an on-chain contract, a checkpointed header
set — can be weaker on items 1–2; everything else still applies.

---

## Header trust — where SPV actually lives

### 1. Difficulty needs a floor, not just per-header PoW

Checking that each header hashes below the target encoded in *its own*
`nBits` is close to meaningless on its own. An attacker mines a
**minimum-difficulty** chain (difficulty-1 — on the order of 2³² hashes per
header, sub-second on any ASIC) starting from a real recent block, embeds a
fake "payment" transaction, and produces a fully PoW-valid, self-consistent
inclusion proof for a few cents of compute.

Defenses, in order of importance:

- **Difficulty floor.** Reject any header whose target is *easier* than the
  real network difficulty at that height. This is the single most important
  check for a verifier with no other backstop.
- **Most-cumulative-work selection.** When choosing among candidate header
  chains, pick the one with the most total work — never the longest by count,
  and never just "the one the server sent."
- **Validate the `nBits` encoding itself** (exponent range, non-zero
  mantissa, canonical form) *before* computing a target, so a malformed
  difficulty field can't yield a bogus (e.g. all-zero) target.

### 2. Confirmation depth must be PoW burial, not a reported height

"6 confirmations" computed as `tip_height − tx_height` from two
server-reported integers is trivially spoofable: one lying or MITM'd source
under-reports the transaction's height (or over-reports the tip) and an
unburied, reorg-able transaction looks final. Derive burial from
**independently fetched, PoW-verified headers** — count real work stacked on
top of the block; don't subtract two numbers a server told you.

### 3. Bind the proof to one specific verified header

Don't accept "the computed root matches *some* header I fetched." Bind the
chain together end to end:

- the transaction's **txid ↔ its raw bytes** (hash the raw tx, check it
  equals the claimed txid),
- the **Merkle root ↔ the specific header** identified by the claimed height,
- that **header ↔ the verified chain** (its `prevHash` links to the previous
  verified header, back to a known anchor).

A gap anywhere in this chain lets a source route a valid branch to the wrong
block.

---

## Merkle-proof integrity

### 4. The 64-byte node ambiguity (CVE-2012-2459 family)

A "transaction" whose serialization is exactly **64 bytes** can be
byte-identical to an *internal* Merkle node (two concatenated 32-byte
hashes). An attacker can present an interior node as if it were a leaf and
forge an inclusion proof. **Reject any leaf whose raw transaction is ≤ 64
bytes** (real transactions are always larger), and always bind the leaf to
the actual txid.

### 5. Reject self-pairing / duplicate siblings

The other half of CVE-2012-2459: reject any step where the sibling hash
equals the current node. Cheap defense-in-depth, even when the root is
PoW-pinned.

### 6. Identify the coinbase structurally, not by position

A common rule is "position 0 is the coinbase, refuse it as a payment proof."
That guard is **bypassable**: the Merkle path is typically derived from only
the low *depth* bits of the position, so positions `2`, `4`, `8`, … (any
nonzero multiple of `2^depth`) produce the *identical* all-left branch as
position 0 and walk to the same root — while sailing past a `pos == 0` check.
Identify the coinbase by its **structure** instead: a coinbase's single input
spends the null outpoint (txid = 32 zero bytes, index = `0xffffffff`).

### 7. Bind the leaf position cryptographically

Root cause of #6: if you carry a position integer, reject any value with bits
set **beyond the branch depth** (`pos ≥ 2^depth`), or re-derive the position
from the branch directions. An unbound position is silently truncated and
aliases onto a lower one.

### 8. Treat direction bytes strictly

If your branch encoding tags each step with a direction byte, accept **only**
the canonical values (e.g. `0x00` / `0x01`). A lax reader that treats "any
nonzero byte" as one direction diverges from a strict one and invites
encoding ambiguity across implementations.

---

## Data source & confirmations

### 9. Quorum detects disagreement, not forgery

Querying N servers and requiring agreement is a useful **liveness / MITM**
defense — it catches a single rogue or unreachable server. It is **not** a
forgery or difficulty defense: N servers relaying the *same* self-consistent
low-difficulty fake chain all agree with each other. Don't let "we ask three
servers" stand in for header verification. Keep transport TLS on to block
passive MITM, but treat the **PoW / difficulty checks (items 1–3) as the real
backstop.**

---

## Parser parity — diverging from consensus

These matter most when **two layers parse the same bytes** — a verifier and
an on-chain contract, or two independent implementations cross-checking each
other. A parser that accepts inputs the consensus rules reject is usually a
liveness / fund-stranding risk rather than theft, but it is a real
divergence.

### 10. Reject non-canonical CompactSize varints

Bitcoin consensus rejects overlong `CompactSize` encodings (e.g. `0xfd 0x01
0x00` for the value 1). A lax parser that accepts them diverges from any
stricter consumer of the same transaction bytes. Enforce minimal encoding in
every varint reader, for both counts and inner length fields.

### 11. Watch signed-vs-unsigned on the 8-byte value

A transaction output's 8-byte value read as **unsigned** in one layer and as
a **signed** integer in another diverges for values with bit 63 set. Real
outputs never set bit 63 (consensus caps total money far below that), so this
is the safe direction — but reject `value ≥ 2⁶³` (or cap at the money supply)
for parity, and pin any wider-than-4-byte numeric reads against the exact
semantics of the other layer.

---

## API surface & testing

### 12. Don't ship a "does the root match?" helper that looks like a gate

A convenience function that only checks `merkle_root == header[offset:]` with
**no** PoW or anchor check is a footgun: someone wires it in later as the
value gate and silently drops all the header-layer security. Route every
*value* decision through the full PoW + anchor + binding path, and keep the
bare root-matcher out of the public surface (or clearly mark it "NOT a value
gate"). Same for a payment-matcher that accepts a blob at a caller-supplied
offset — make it safe by default.

### 13. Bound the work in proof parsing (DoS)

Attacker-controlled tree depth / proof length can blow up an unbounded or
recursive parser. Cap the tree height, length-cap claimed Merkle lists before
allocating, and prefer iterative walks over unmemoized recursion.

### 14. Differential-test the *whole* path against a second implementation

The highest-yield bug class is **"implementation A accepts what
implementation B rejects."** Two independent verifiers that agree across a
fuzz corpus is far stronger assurance than either alone. Crucially, fuzz the
**header / PoW / nBits / Merkle / anchor** path — not just the payment-output
parser, which is the easy part to cover and the least dangerous to get wrong.
Include: min-difficulty and wrong-`nBits` headers, broken chain links,
position-aliased coinbase branches, 64-byte leaves, non-canonical varints,
and direction bytes outside the canonical set.

---

## How pyrxd's verifier maps to these

pyrxd's SPV layer ([`pyrxd.spv`](../api/spv.rst)) implements these defenses;
[Verify an SPV proof](verify-an-spv-proof.md) is the calling recipe.

| Pitfall | Where pyrxd handles it |
| --- | --- |
| 1 — PoW per header | `verify_header_pow` (validates `nBits`, computes the target, MSB-first chunked compare) |
| 1 — difficulty floor / cumulative work | **deferred to the bound on-chain contract**, which pins `nBits`; a *standalone* consumer must add an explicit floor |
| 2 — burial | confirmation depth derived from independently-fetched headers; single-source depth is gated to low-value only |
| 3 — binding | `verify_chain` (per-header `prevHash` linkage + optional `chain_anchor`) plus the txid↔raw-tx bind in `verify_tx_in_block` |
| 4 — 64-byte leaf | `verify_tx_in_block` rejects `len(raw_tx) ≤ 64` |
| 6 — coinbase | structural + position guard in the proof builder |
| 14 — differential | `tests/test_spv*` plus a differential harness against the contract |

> **Note for standalone reuse.** pyrxd's verifier deliberately leans on its
> bound on-chain contract for the difficulty floor (item 1) and for
> above-dust confirmation depth (item 2). Anyone reusing the primitive
> *without* that contract in the trust path — a wallet, a bridge, an oracle —
> must enforce the difficulty floor and the PoW-burial check themselves.

---

## References

- [Verify an SPV proof](verify-an-spv-proof.md) — the calling recipe
- [`pyrxd.spv` API reference](../api/spv.rst)
- Source: [`src/pyrxd/spv/`](https://github.com/MudwoodLabs/pyrxd/tree/main/src/pyrxd/spv)
- [CVE-2012-2459](https://en.bitcoin.it/wiki/CVE-2012-2459) — the Merkle-tree
  duplicate-node vulnerability behind items 4–5
