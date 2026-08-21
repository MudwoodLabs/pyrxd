---
title: "The mint reveal judged the constructor's fee rate and spent the record's, so the overpay ceiling was unreachable on the default path"
category: logic-errors
component: "glyph / token-issuance (`GlyphMinter._reveal`, `PendingMint.from_dict`)"
tags:
  - glyph
  - mint
  - commit-reveal
  - fee-sizing
  - relay-fee
  - overpay-ceiling
  - fee-burn
  - fund-safety
  - unreachable-guard
  - persisted-state
  - deserialization
  - default-path
  - test-gap
  - mainnet
date: 2026-08-19
severity: high
status: solved
symptom: >
  A `GlyphMinter` reveal paid 2,600,000,000 photons (26 RXD) on a 260-byte transaction
  and reported success — no refusal, no warning, nothing in the output to read as wrong.
  The overpay ceiling that exists to stop exactly this had shipped one release earlier
  and was live in `GlyphMinter.__init__`; it simply never ran on the reveal. Every call
  `mint_nft` and `deploy_ft` make takes the path that waived it, so the guard was
  unreachable for ordinary callers while looking, from the constructor, like it was in
  force.
root_cause: >
  `__init__` judges `self._fee_rate`, but `_reveal` spends `pending.fee_rate` — a
  different number for any record loaded from disk or crossing instances — and it called
  `assert_fee_rate_clears_relay_floor(..., allow_overpay=allow_overpay or fee_rate is
  None, ...)`. `fee_rate` is None on every `mint_nft`/`deploy_ft` call, so the ceiling was
  waived on precisely the default path. Nothing downstream caught it:
  `assert_pays_for_its_size` returns as soon as `fee_paid >= required`, so it is a FLOOR
  check an overpay passes trivially. `PendingMint.from_dict` restores the stored rate
  checking only that it is a positive int, so a record written by a pyrxd predating the
  ceiling can carry a per-kB figure in a per-byte field, and records outlive the code
  that wrote them.
---

# The mint reveal judged one fee rate and spent another

Fixed in commit `8b04d8d` (PR #456, pyrxd 0.19.0), with follow-ons in `f1f1b7a` and
`0f5d421`.

## Symptom

`GlyphMinter.mint_nft` and `GlyphMinter.deploy_ft` would build, sign and broadcast a
reveal at whatever fee rate the `PendingMint` record carried, with no upper bound, no
refusal and no warning.

Measured on a record carrying `fee_rate=10_000_000` — the per-**kB** constant
`RADIANT_EFFECTIVE_MIN_RELAY_PHOTONS_PER_KB`
([`src/pyrxd/fee_sizing.py:116`](../../../src/pyrxd/fee_sizing.py)) pasted into a
per-**byte** field — and funded well enough to pay it: a 260-byte reveal paid
**2,600,000,000 photons (26 RXD)**, a 1000x overpay against the same transaction's
floor-rate fee. The reveal has a single output, so the whole difference left with the
miner. Radiant has neither RBF nor CPFP, so nothing about it was repairable.

An overpay ceiling did exist. `assert_fee_rate_clears_relay_floor` refuses any rate above
`MAX_FEE_OVERPAY_MULTIPLE × relay_floor_photons_per_byte()` = 10 × 10,000 = **100,000
photons/byte** ([`src/pyrxd/fee_sizing.py:396-398`](../../../src/pyrxd/fee_sizing.py)),
and the reveal called that gate on every path. It was simply told to skip the ceiling on
exactly the path the two one-call helpers take.

## Why nothing caught it

Three reasons, and they compound.

### The gate was told to waive itself

The reveal passed `allow_overpay=allow_overpay or fee_rate is None`, and `fee_rate` is
`None` on every call `mint_nft`/`deploy_ft` can make — neither helper exposes a
`fee_rate=` or an `allow_overpay=` argument at all
([`src/pyrxd/glyph/mint.py:861,875`](../../../src/pyrxd/glyph/mint.py)).

| Entry point | `allow_overpay` | `fee_rate` | `allow_overpay or fee_rate is None` | Ceiling judged? |
|---|---|---|---|---|
| `mint_nft(metadata)` | not exposed → `False` | not exposed → `None` | **True** | **no** |
| `deploy_ft(metadata, supply=…)` | not exposed → `False` | not exposed → `None` | **True** | **no** |
| `reveal_nft(pending)` | `False` | `None` | **True** | **no** |
| `reveal_nft(pending, fee_rate=N)` | `False` | `N` | False | yes |
| `reveal_nft(pending, allow_overpay=True)` | `True` | either | True | no (intended) |

Only a caller who re-priced the reveal by hand ever reached the ceiling. The default
path — the one the SDK documents and the CLI drives — never did.

### The premise behind the waiver was false

The comment justifying the waiver claimed the ceiling had already been judged at
construction. `__init__` does judge a rate
([`src/pyrxd/glyph/mint.py:703`](../../../src/pyrxd/glyph/mint.py)) — but it judges
`self._fee_rate`, and the reveal spends `pending.fee_rate`:

```python
# src/pyrxd/glyph/mint.py:1084
effective_rate = pending.fee_rate if fee_rate is None else fee_rate
```

Those are the same number only for a record minted and revealed by one live instance. For
any record that crossed instances — loaded off disk, resumed after a crash, or written by
a pyrxd predating the ceiling entirely — they are different numbers, and the second had
never been judged by anything. `from_dict` copies it straight off disk, and the only bound
it ever meets is the dataclass's positive-int check:

```python
# src/pyrxd/glyph/mint.py:337-338
if not isinstance(self.fee_rate, int) or isinstance(self.fee_rate, bool) or self.fee_rate <= 0:
    raise ValidationError("PendingMint.fee_rate must be a positive int")
```

The waiver was granted on exactly the path where the premise for granting it did not hold.

### Nothing downstream is an overpay check

The reveal's other guard returns the moment the fee covers the bytes:

```python
# src/pyrxd/fee_sizing.py:471-473
required = required_fee(size_bytes, fee_rate)
if fee_paid >= required:
    return required
```

It is a FLOOR check. A 1000x overpay passes it trivially — and it is fed `effective_rate`,
the same inflated number, so it asks whether a 26 RXD fee covers a 26 RXD requirement and
answers yes. `required_fee` deliberately does not lift or cap a caller's rate either.

**One layer made this look contained.** An ordinary commit is funded at an ordinary rate
and cannot afford an over-ceiling reveal, so the size check refuses first and no money
moves. That containment is a property of how that particular commit was funded, not of the
guard. During review, one adversarial reviewer concluded from exactly this that the bug was
contained everywhere; a second funded the commit to match the stored rate — the shape a
pre-ceiling pyrxd leaves behind — and measured the burn. Resolving that disagreement,
rather than accepting the reassuring answer, is what turned this from MEDIUM into a
fund-loss finding.

## Root cause

The rate was judged in one place and spent in another, and the two places read different
variables.

The previous round had moved the ceiling into `__init__` for a good reason: judging it only
at reveal time refuses *after* the irreversible action, leaving the caller with an on-chain
hashlock that has no owner-only spend path. But moving it there was treated as making the
reveal's own check redundant, and the reveal was edited to say so. That turned a
construction-time check on `self._fee_rate` into the sole authority over a number it never
sees — `pending.fee_rate` — on the only path the convenience API can take.

Secondarily, the gate ran *after* the money had been committed to the transaction. Before
the fix the fee was applied and the transaction signed twenty-five lines above the rate
gate. Judging a rate after spending it is a correct check in the wrong position: it can
only report on an act already performed.

## The fix

**The gate moved above the spend**, so the rate is judged before `fee()` and `sign()` see
it ([`src/pyrxd/glyph/mint.py:1127-1139`](../../../src/pyrxd/glyph/mint.py)):

```python
assert_fee_rate_clears_relay_floor(
    effective_rate,
    what="glyph reveal",
    allow_below_relay_floor=floor_opt_in,
    allow_overpay=allow_overpay,
    error_type=ValidationError,
)

reveal_tx.fee(SatoshisPerKilobyte(effective_rate * 1000))
reveal_tx.sign()
```

**The waiver is gone:**

```python
# before
allow_overpay=allow_overpay or fee_rate is None,
# after
allow_overpay=allow_overpay,
```

The rate is judged on both ends, every time, whatever its provenance — constructor
argument, caller override, or a number restored from a record written by an older pyrxd.
Both escape hatches stay the caller's and stay explicit, because a refusal with no way
through would convert "this reveal may not relay" into "this commit can never be revealed",
and the commit is a hashlock with no owner-only path.

### The fix then had to be fixed twice

This is the more reusable half of the story.

**The same gate refused honest work.** `assert_fee_rate_clears_relay_floor` judges *both*
ends, and the construction gate had no opt-out — so a regtest node, whose floor is a tenth
of mainnet's, could no longer construct a `GlyphMinter` at all at `fee_rate=1_000`. Commit
`f1f1b7a` made `allow_below_relay_floor` a constructor argument and carried it to the
reveal, so a minter built for a sub-floor chain can finish what it starts.

**The inheritance expression swallowed an explicit `False`.** The first attempt was
`allow_below_relay_floor or self._allow_below_relay_floor`, which overruled a caller who
deliberately re-asserted the floor for one reveal. The fix is a three-state sentinel
([`src/pyrxd/glyph/mint.py:1096`](../../../src/pyrxd/glyph/mint.py)):

```python
floor_opt_in = self._allow_below_relay_floor if allow_below_relay_floor is None else allow_below_relay_floor
```

`None` means "the caller said nothing"; `False` means `False`.

**The sentinel was not propagated to the facade.** `GlyphClient.reveal_nft` kept
`allow_below_relay_floor: bool = False` and forwarded it, which the minter now reads as a
deliberate override — so a client built with `allow_below_relay_floor=True` broadcast its
commit and was then refused its own reveal, stranding a hashlock. Fixed in `0f5d421`, with
a structural test pinning the two signatures together.

## Prevention

**1. Judge the value you will actually spend, not the one you were handed.** In order of
preference: validate at the point of use, on the exact expression that gets spent; if you
validate on load instead, validate the *restored* value — a `from_dict`/`parse` boundary is
a trust boundary, and `__post_init__` type checks are not bounds checks; treat
constructor-time validation as an addition, never a substitute. At review time, name the
variable each guard reads and the variable the irreversible operation writes. If they are
not the same expression, list every way they can diverge (persistence, another instance, an
older release) and say what covers each.

**2. A floor check is not a ceiling check, and the names do not tell you which.**
`assert_pays_for_its_size` enforces a **lower bound only** — an overpay satisfies it on the
first branch. `assert_fee_rate_clears_relay_floor` enforces **both** bounds on the *rate*,
before any bytes exist, and each opt-out skips only its own end. So a size check downstream
of an unbounded rate proves nothing about overpay. When you add a fee path, state in the
code which helper you called and which bound is therefore still unguarded.

**3. `override or state_flag` swallows an explicit `False`.** "This argument was omitted" is
not evidence the value is safe — here it was evidence nobody had checked it. Use a
`bool | None = None` sentinel and resolve with `default if flag is None else flag`. Changing
such a default obliges you to grep every forwarder **in the same commit** and pin the parity
with a signature test; skipping that is what stranded the commit above. Where an OR with
derived state is deliberate — `GlyphClient.__init__` uses
`allow_below_relay_floor or store is None`, because a transfer-only client has no mint path
— pin *both* branches with tests.

**4. Pair every refusal test with an honest-path test.** A two-ended check gets added for one
end, and the other end silently becomes mandatory. Per guard: one test that the dishonest
input is refused (with the message naming the caller's own parameter), one that the
legitimate input still succeeds *end to end* rather than merely constructing, and one that
each escape hatch opens only its own door. Before shipping any refusal, ask what the caller
does next — if the answer is "nothing, the commit is already broadcast", the refusal must be
paired with a reachable override or moved earlier than the irreversible act.

**5. Verify a guard's test by planting the mutant.** Two mutants that fully reverted the
previous round's headline fix passed 129 and 97 tests respectively: the guard shipped
correct and completely untested, and existed only as long as nobody edited it. A passing
suite is not evidence a guard is covered — the suite passed identically with the guard
deleted. The method: neutralise the guard in a way that reproduces the *original bug*, run
the suite, confirm RED **and read which test failed** (incidental coverage evaporates on the
next refactor), then restore and confirm green. Use `.venv/bin/pytest`, not
`python -m pytest`, which masks `from tests.X` import errors.

### Known gap

`glyph/mint.py` and `glyph/client.py` are in **no** mutation-testing group — the `glyph`
group is `glyph/ft glyph/builder` ([`scripts/mutation_test.sh:87`](../../../scripts/mutation_test.sh))
— and `test_glyph_mint_facade.py` appears nowhere in that script. The mint facade decides
how much value leaves and is currently outside the automated check that would have caught
this mechanically. Adding it is the durable version of item 5.

## Verification

Pinned by six tests in
[`tests/test_glyph_mint_facade.py:1016`](../../../tests/test_glyph_mint_facade.py), class
`TestTheRateIsJudgedWhereverItCameFrom`, using `OVER_CEILING = 10_000_000` and
`REGTEST_RATE = 1_000`:

- `test_an_over_ceiling_rate_cannot_construct_a_minter` — refused before a commit exists to
  be stranded.
- `test_a_regtest_rate_constructs_only_with_the_opt_in` — the guard-refusing-honest-work half.
- `test_the_opt_in_reaches_the_reveal_so_a_mint_can_finish` — the opt-in survives to the
  reveal rather than committing and then refusing.
- `test_an_over_ceiling_stored_rate_is_refused_at_reveal` (`:1069`) — the burn itself.
  Commits normally, then `dataclasses.replace(pending, fee_rate=10_000_000)` — the shape a
  pre-ceiling pyrxd leaves on disk — and asserts the record survives the refusal.
- `test_the_overpay_hatch_opens_the_door_it_claims_to` — asserts *discrimination*, not
  success: bare, the refusal names the ceiling; with `allow_overpay=True` the remaining
  refusal is a different, funding-shaped one. This fixture's commit cannot fund an
  over-ceiling reveal, which is precisely the incidental containment that misled a reviewer.
- `test_the_sub_floor_hatch_does_not_also_waive_the_ceiling` — the two ends stay independent.

Two adjacent classes pin the follow-ons: `TestTheCallersWordBeatsTheConstructors` (`:1136`)
and `TestTheFacadeDoesNotForwardAPhantomOverride`
([`tests/test_glyph_client_transfer.py:351`](../../../tests/test_glyph_client_transfer.py)),
whose `test_the_signature_matches_the_minter_it_forwards_to` (`:398`) asserts the facade's
default equals the minter's and is `None`.

Every test above was verified by planting the mutant it targets, watching the suite go red,
and restoring. The full suite measured 9,241 passing at the release commit; the three
classes named here re-run in isolation at `main` as **11 passed**.

## Related

- [`../integration-issues/regtest-node-inherited-a-tenth-of-mainnets-relay-floor.md`](../integration-issues/regtest-node-inherited-a-tenth-of-mainnets-relay-floor.md)
  — the other end of the same gate (under-payment from a forgiving test node). Its
  fee-sizing checklist item 10 — *"If a caller supplies `fee_rate`, is it gated by
  `assert_fee_rate_clears_relay_floor`?"* — is the rule this bug broke, and it is the source
  of the measured "regtest floor is a tenth of mainnet's" that `allow_below_relay_floor`
  exists to serve.
- [`funding-utxo-byte-scan-dos.md`](funding-utxo-byte-scan-dos.md) — the repo's canonical
  case of a fund-safety guard refusing legitimate input, the same shape as this fix's own
  two regressions.
- [`radiant-covenant-amount-pin-must-match-funded-carrier.md`](radiant-covenant-amount-pin-must-match-funded-carrier.md)
  — the reference stranded-UTXO case, where two phases disagreed about a value and left the
  carrier permanently unspendable.
- [`dmint-deploy-reveal-hashlock-reuse.md`](dmint-deploy-reveal-hashlock-reuse.md) —
  documents the commit hashlock script, with mainnet evidence that abandoned commit attempts
  really happen; the on-chain form of what "a refusal always keeps the record" protects.
- [`../design-decisions/capped-fee-source-rxd-autonomy-trust-boundary.md`](../design-decisions/capped-fee-source-rxd-autonomy-trust-boundary.md)
  — the same question on a different surface: bound the most a fee path can spend when every
  software check is wrong.
- [`../../threat-model.md`](../../threat-model.md) — S21, "Under-fee'd time-critical spend —
  the 8-hour irreversibility window", the in-repo statement that fee **pre-sizing** is the
  only control available.
- [`../../how-to/transfer-a-glyph-token.md`](../../how-to/transfer-a-glyph-token.md) — the
  transfer path whose ceiling 0.18.0 fixed; explains why an overpay with no change output is
  irreversible rather than merely wasteful.
- **CHANGELOG 0.18.0** — the closest prior art. It introduced the ceiling and fixed the
  **transfer** path, measuring `build_nft_transfer_tx` burning 23.1–23.3 RXD off a 228–230
  byte transfer at the same `fee_rate=10_000_000`. 0.19.0 fixes the **mint** path: same
  constant, same mistake class, a path the 0.18.0 gate never reached. That release also had
  to add a reachable override to its own new ceiling — the precedent that a new bound needs
  its escape hatch plumbed and tested in the same change.
- [MudwoodLabs/pyrxd#457](https://github.com/MudwoodLabs/pyrxd/issues/457) — the direct
  residual: `validated_fee_rate` still accepts `10_000_000` while the SDK refuses it, so the
  same burn is reachable through the CLI's own mint path.
- [MudwoodLabs/pyrxd#458](https://github.com/MudwoodLabs/pyrxd/issues/458) — the mirror gap:
  a client can now mint on a sub-floor chain but cannot transfer on one.
- [MudwoodLabs/pyrxd#459](https://github.com/MudwoodLabs/pyrxd/issues/459) — carries the
  sentinel lesson forward: any new facade forwarder must default `allow_below_relay_floor`
  to `None`, not `False`.
