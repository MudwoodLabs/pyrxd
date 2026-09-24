---
title: "The regtest node inherited a tenth of mainnet's relay floor, so the fee proofs were graded on a curve"
category: integration-issues
component: tooling / regtest harness (`_RegtestNode`, `pyrxd regtest`)
tags:
  - regtest
  - relay-fee
  - effective-minrelaytxfee
  - fee-sizing
  - test-harness
  - environment-parity
  - test-gap
  - no-rbf
  - no-cpfp
  - glyph
  - nft-transfer
  - integration-tests
date: 2026-08-11
severity: high
status: solved
symptom: >
  `GlyphBuilder.build_nft_transfer_tx` under-paid the mainnet relay floor in 24.9% of
  builds (746 of 3000 on fresh keys) and shipped that way through four releases with
  green regtest suites. The suites written to prove the builder works against a node
  broadcast the under-fee'd transactions happily, because a default `radiantd -regtest`
  advertises `effective_minrelaytxfee` 0.01 RXD/kB — one tenth of the rate every pyrxd
  builder sizes against. A one- or two-byte shortfall is invisible to a node charging a
  tenth of the built rate. The gap was not in those suites' assertions; it was in what
  the node they asked was able to say.
root_cause: >
  The harness inherited Radiant Core's regtest DEFAULT relay floor instead of declaring
  one, so every node-backed fee proof ran against a floor 10x more forgiving than
  production and "a real node accepted it" meant only "a lenient node accepted it".
  Compounding it, `getmempoolinfo` reports BOTH `minrelaytxfee` (the legacy rate) and
  `effective_minrelaytxfee` (the rate `AcceptToMemoryPool` applies), and the
  obvious-looking field name is the wrong one.
---

# The regtest node inherited a tenth of mainnet's relay floor

pyrxd's regtest nodes started with Radiant Core's default `minrelaytxfee` of 0.01 RXD/kB —
one tenth of mainnet's effective floor of 0.10 RXD/kB (10,000 photons per byte), which is
the rate every pyrxd builder sizes its fees against. Every node-backed fee proof in the
tree therefore ran against a floor ten times more forgiving than production, and "a real
node accepted it" meant only "a node charging a tenth of the built rate accepted it".

`GlyphBuilder.build_nft_transfer_tx` shipped for four releases under-paying that floor in
**24.9% of builds**: it sized its fee from the *trial* signing pass and never re-measured
the final transaction, whose DER signature can run one to two bytes longer. Its regtest
end-to-end suites broadcast those transactions without complaint.

The fix is not in the builder. It is in the harness **declaring** its floor instead of
inheriting one.

## Symptom

**What an engineer sees is nothing.** That is the symptom: green regtest suites, a builder
whose output a real Radiant node accepts and confirms, and a defect that reaches users.

It becomes visible only when the node is restarted at the mainnet floor. Against the
unfixed builder, 2 of 12 real NFT transfers were refused:

```
node getmempoolinfo: minrelaytxfee=0.1 effective=0.1
  #1: size=230B fee=2300000 required=2300000 -> ACCEPT
  #2: size=230B fee=2290000 required=2300000 -> REJECT[66: min relay fee not met]
```

On mainnet that reject is terminal. Radiant has neither RBF nor CPFP, so the NFT's own
UTXO is held until mempool expiry, 8 hours later.

## Root cause

Four things had to line up. Three are in the builder; the fourth is the node.

**1. Every fee-paying builder signs twice, over different messages.** The fee is part of
the output value, so the trial pass (output = full input value) and the final pass
(output = value − fee) sign different sighashes. A fee sized off the trial pass is a fee
sized for a transaction that no longer exists (`src/pyrxd/fee_sizing.py:5-13`).

**2. A DER signature is 69, 70, or 71 bytes** depending on leading zero bytes in `r` and
`s` — measured 17 / 1457 / 1526 over 3000 distinct messages (`src/pyrxd/fee_sizing.py:9-11`).
When the final signature is longer than the trial one, the transaction contains more bytes
than it paid for.

**3. RFC 6979 makes this a fixed property of a transaction, not a flake.** Signing is
deterministic, so the outcome is a function of `(key, txid, vout, recipient, amount)`. A
test that fixes all of those fixes the verdict. `tests/test_glyph_transfer.py` built one
transaction from a hard-coded `_ALICE_KEY_INT` with a fixed txid and value; it landed
safe, permanently and uselessly, while a quarter of *distinct* transfers were short. Had
the defect been stochastic, a single hard-coded case in CI would have caught it within a
day.

**4. The node could not contradict the builder anyway.** At 10x headroom a one-byte
shortfall is not merely tolerated — the transaction still pays roughly ten times the
node's floor.

All three layers agreed the builder was fine: the offline unit test (one frozen
transaction that happened to land safe), the builder's own fee assertion (checking the
trial size it had itself computed), and the live node (being overpaid tenfold). Nothing in
the stack was positioned to disagree.

## The fix

### Declare the floor, and make the node say it back

`_RegtestNode` (`tests/test_htlc_regtest_e2e.py`) now takes the floor as a constructor
parameter defaulting to mainnet's, passes it to `radiantd` as `-minrelaytxfee=`, and
**asserts the node advertises it back before the fixture yields**:

```python
if self.min_relay_rxd_per_kb is not None:
    asked = photons_per_kb_from_rxd_per_kb(float(self.min_relay_rxd_per_kb))
    advertised = self.relay_rate() * 1000
    assert advertised == asked, (
        f"node advertises effective_minrelaytxfee {advertised} photons/kB, "
        f"but was started at -minrelaytxfee={self.min_relay_rxd_per_kb} "
        f"({asked} photons/kB) — nothing proved against it means what it says"
    )
```

Configuring a flag and enforcing a policy are two different facts. Only the second binds,
so only the second is worth asserting.

### Read `effective_minrelaytxfee`, not `minrelaytxfee`

Radiant Core 2.0 raised the relay floor 10x behind a height gate, so the node carries two
rates at once — `LEGACY_MIN_RELAY_TX_FEE_PER_KB` and
`RADIANT_CORE_2_MIN_RELAY_TX_FEE_PER_KB` (`tests/vendor/radiant_core/policy.h:47,49`).
`AcceptToMemoryPool` charges the **effective** one (`tests/vendor/radiant_core/validation.cpp:779`).

`getmempoolinfo` reports both. The friendly-looking field is the one that is 10x too low,
and nothing downstream can tell you that you read the wrong number, because both are real
fields with real values.

> **This exact mistake had already landed once.** `DeadlineFeePolicy.protocol_floor_per_kb`
> — the bound meant to catch a lying or misconfigured node — was itself set to the legacy
> rate, 10x too low to catch anything real. Fixed in `86d114e`.

`tests/test_wallet_send_regtest_e2e.py` had been reading a third candidate,
`getnetworkinfo.relayfee`. The two agree on this node, which is exactly why the wrong one
could sit there unnoticed.

### The developer-facing node too

`src/pyrxd/devnet.py` (`pyrxd regtest`) got the same treatment, plus `-fallbackfee`: the
node's own wallet uses it when it has no fee estimates, which on a fresh regtest chain is
always, and `pyrxd regtest fund` goes through `sendtoaddress`. Raising `-minrelaytxfee`
without it leaves the node building transactions below the floor it is enforcing.

*A local chain that says yes to things mainnet says no to is worse than no local chain.*

### Suites that genuinely need a lower floor declare it

The invariant is not "every node runs at 0.10". It is the stronger and more useful **every
Radiant node the test tree starts declares its floor and verifies it; none inherits one.**
Suites keeping the legacy floor set it explicitly and assert it back, with the reason
written at the constant.

## What raising the floor exposed

**No production builder needed a change.** `git diff --stat 3c8729f^ 3c8729f -- src/`
returns exactly one file — `devnet.py`, the dev-node harness. Every builder already
defaulted to the mainnet floor.

Every failure was test scaffolding sized against a lenient node, and the cause was far
more concentrated than the failure count suggests: **14 suites failed in fixture setup on
one shared helper.** `_pay_to_spk` — the funding primitive the whole Radiant integration
tree is built on — hard-coded 1,000,000 photons against a 2,260,000 requirement on its own
226-byte transaction. The fix reads the rate off the node and re-measures the signed
transaction rather than raising the constant and hoping.

Genuinely separate breakages: dMint commit/reveal values too small to pay a mainnet-floor
fee out of; a Gravity maker-offer `_FEE` below the floor for its own ~190-byte offer; and
two FT "inflating output" negative controls whose `_RELAY_FEE_SATS * 10` computed a
**negative** change output once the constant rose. That last one is the sharpest: those
controls exist to prove the FT *conservation* rule refuses an inflated output, and an
under-funded one would have been refused for the fee instead — a green test proving
nothing.

## Why this is fund safety, not cosmetics

A sub-floor transaction on Bitcoin is an inconvenience; RBF replaces it or a CPFP child
drags it in. On Radiant it is neither.

- **No RBF.** `AcceptToMemoryPool` rejects any transaction conflicting with a mempool
  entry outright — it does not compare feerates, it returns `txn-mempool-conflict`
  (`tests/vendor/radiant_core/validation.cpp:667`, `:870`). Radiant ships DSProof: it
  treats a conflicting spend as *fraud to broadcast*, the opposite of replacement.
- **No CPFP.** Radiant Core v3.1.2 `src/miner.cpp:404` selects on `GetModifiedFeeRate()` — the transaction's own
  fee over its own size. A high-fee child cannot lift a low-fee parent into a block.
- **The window is 8 hours** (`DEFAULT_MEMPOOL_EXPIRY`, Radiant Core v3.1.2 `src/validation.h:82`).

So one byte short is not "confirms later". The UTXO is unspendable for eight hours, and if
the transaction was a time-critical HTLC claim or refund whose deadline falls inside that
window, **there is no remedy at all**.

And there is no margin to absorb it: the effective floor is 10,000 photons per byte
*exactly*, which is precisely the rate the builders default to.

## Prevention

**The principle:** a proof environment that differs from production *in the dimension
under test* proves nothing about that dimension. Not "less" — nothing. The same node was a
perfectly good oracle for script semantics, ref conservation and CSV finality on the very
same transactions. It was worthless only about the fee.

Three other defects in this repo share the shape — the test's own inputs were narrower
than production's, in the exact axis the bug lived on:

| Defect | The narrowing |
|---|---|
| Ref-walker mishandling `0xd1`–`0xd3` | The differential's generator was `st.sampled_from([b"\xd0", b"\xd8"])` — no generated script could contain the failing opcode, so production and reference shared the bug and the test reported green |
| NFT fee under-payment | One hard-coded key sampled a distribution exactly once |
| Whale UTXO blinding an address | A Bitcoin supply cap (2.1e15) applied to a Radiant read path where MAX_MONEY is 2.1e18 |

### Checklist — adding a node-backed test

1. Does the node get an explicit `-minrelaytxfee` rather than inheriting the default?
2. Does `start()` **assert** the advertised rate equals the one asked for, before yielding?
3. Is the field read `effective_minrelaytxfee` and not `minrelaytxfee`?
4. If the floor is below mainnet's, is the reason written at the constant?
5. Is the container name unique? `start()` does `docker rm -f` on its own name, so a shared
   name means two suites deleting each other's node mid-run.
6. Does at least one case assert on state read back from a **confirmed** transaction?
7. Is there a **negative control** — something this node demonstrably refuses — so
   "accepted" is not equally true of a node that accepts everything?

### Checklist — touching a fee-sizing path

8. Is the fee derived from the **final signed** transaction's measured bytes?
9. Is there an `assert_pays_for_its_size` / `assert_tx_pays_for_itself` call on it?
10. If a caller supplies `fee_rate`, is it gated by `assert_fee_rate_clears_relay_floor`?
    `required_fee` does **not** do this — it binds the caller's rate and nothing else.
11. If the rate crosses a trust boundary (config, RPC, operator flag), is
    `fee_never_below_relay_floor` used instead?
12. Is any new relay-floor number derived from `fee_sizing` rather than written as a fresh
    literal?
13. Does the change assume RBF or CPFP anywhere?

### Test shapes worth having

- **The premise, as a failable assertion.** Read the floor off the node, then build the
  same transaction paying exactly `size × floor` and one photon less. Require accept then
  reject, and require the reason to be `min relay fee not met` specifically. Without this
  pair, every "accepted" elsewhere is equally true of a node that rejects nothing.
- **A corpus, not an example.** Fresh key, ref and recipient per round, so each round signs
  a genuinely different message. Size the round count from the defect rate: at a 25%
  defect rate, 30 rounds miss it with probability ~1.8e-4, while 12 rounds would be a 3%
  spurious pass.
- **Read-back from a confirmed transaction.** Assert the fee the *chain* computes
  (`carrier − Σ vout`) equals the fee the builder reported. That is the only assertion
  that catches a builder lying about its own fee.
- **A vacuity guard on any differential.** Assert `rejected > 0`. Otherwise a green run
  proves only that the differential cannot detect what it exists to detect.
- **Landing exactly on the boundary is a search, not a solve.** Changing the fee re-signs
  the input and can move the DER length, which changes the size, which changes the floor;
  for roughly a quarter of keys the iteration is a two-cycle that never settles (measured
  98/400). Escape with a **size-neutral** redraw — vary `nLockTime` (4 bytes at every
  value, never enforced when every input carries `0xFFFFFFFF`) or the refund PKH (20 bytes
  at every value). Get this wrong and you get flakiness, not a wrong answer.

## Still open (as of 2026-08-11)

- **Four independent re-derivations of "read the node's rate"** now exist across the test
  tree. This is the same one-rule-many-copies shape that produced the worst defects in
  this repo, and the existing duplication guard cannot see it — it scans `src/` only.
- **No mechanical guard** that a new node-backed suite declares and asserts a floor. Three
  suites build their own `docker run … radiantd` outside `_RegtestNode`. A guard requiring
  any such argv to contain `-minrelaytxfee=` and assert on `effective_minrelaytxfee` would
  make the discipline enforced rather than documented.
- **Two property-test domains are still capped at Bitcoin's supply on Radiant paths**
  (`tests/test_property_based.py:126`, `tests/test_fuzz_parsers.py:248`). Raising them to
  `RADIANT_MAX_PHOTONS` closes the same shape mechanically.
- **The BTC harness does not declare-and-assert** the way the Radiant one now does; it
  reads the floor at use time instead. Defensible, but unmeasured against bitcoind's
  regtest default.

## See also

- `CONTRIBUTING.md` — "Node-backed tests (the integration lane)", the contributor-facing
  form of this rule
- `docs/threat-model.md` — S21, the canonical statement of why an under-fee'd
  time-critical spend is unrepairable
- `docs/solutions/logic-errors/taproot-refund-leaf-empty-stack-test-the-execution-not-just-the-bytes.md`
  — a prior instance of the same class: assertions that never exercised the thing they
  claimed to prove
- `src/pyrxd/fee_sizing.py` — the single home for "what fee must this transaction pay"
- PRs #402, #405, #414 (shipped in 0.16.0) and #416 (the harness fix and CI lane,
  unreleased at time of writing)
