---
title: "Radiant HTLC covenant amount-pin > funded carrier bricks the UTXO (both claim and refund unsatisfiable)"
category: logic-errors
component: gravity / radiant-covenant / htlc
tags:
  - radiant
  - covenant
  - htlc
  - atomic-swap
  - cross-chain
  - op-outputvalue
  - op-verify
  - amount-pin
  - carrier-mismatch
  - stranded-utxo
  - min-relay-fee-per-kb
  - bip68-csv
  - non-bip68-final
  - mainnet
  - taproot
date: 2026-05-24
severity: high
symptom: >
  Broadcasting the claim (and equally the refund) of a funded Radiant HTLC covenant
  failed with `mandatory-script-verify-flag-failed (Script failed an OP_VERIFY
  operation) (code 16)`. Neither branch could spend the UTXO, permanently stranding
  the carrier (100000 photons / 0.001 RXD).
root_cause: >
  The covenant body asserts `OP_0 OP_OUTPUTVALUE <amount> OP_GREATERTHANOREQUAL
  OP_VERIFY` on BOTH the claim and refund branches. It was built with an `amount`
  pin of 50,000,000 photons but the carrier output was funded with only 100,000
  photons, so out0 could never satisfy `>= amount`. Fix: build the covenant with
  `amount <= funded carrier`.
---

# Radiant HTLC covenant amount-pin must match (be ≤) the funded carrier

A build-time covenant constant (the `amount` pin baked into the script's
`OP_OUTPUTVALUE >= <amount> OP_VERIFY` guard) was decoupled from the runtime reality
(the actual photon value funded into the carrier output). Because the same value
guard sits on **both** the `claim` and `refund` dispatch branches, an over-large pin
doesn't just block one path — it renders the entire UTXO permanently unspendable,
silently converting locked funds into burned funds, with only a generic `OP_VERIFY`
failure as the broadcast-time signal.

## Symptom

A Radiant HTLC covenant (RXD variant, for the cross-chain atomic swap) was built and
funded, but **every** spend attempt failed — both the hashlock `claim` branch and the
`tx.age` CSV `refund` branch — with the same consensus rejection:

```
mandatory-script-verify-flag-failed (Script failed an OP_VERIFY operation) (code 16)
```

The covenant carrier (100,000 photons = 0.001 RXD) became permanently unspendable.

This was **not** a wrong-preimage or premature-CSV rejection (those have distinct
messages — `OP_EQUALVERIFY` and `Locktime requirement not satisfied`). It was an
unconditional `OP_VERIFY` failure that no spend witness could satisfy — the tell that
a guard is failing on *every* code path, not on the witness you supplied.

## Root Cause

The covenant was compiled with an `amount` pin of **50,000,000 photons** but the
covenant output was funded with only **100,000 photons**.

Both branches of the covenant ASM contain an identical output-value guard that checks
the value routed into output 0 against the compile-time `amount`:

```
OP_TXOUTPUTCOUNT OP_1 OP_NUMEQUALVERIFY
OP_DUP OP_0 OP_NUMEQUAL
OP_IF                                  # ---- claim branch (selector OP_0) ----
    OP_SWAP OP_SHA256 <H> OP_EQUALVERIFY
    OP_0 OP_OUTPUTVALUE <amount> OP_GREATERTHANOREQUAL OP_VERIFY   # <-- the trap
    OP_0 OP_OUTPUTBYTECODE OP_HASH256 <takerHash> OP_EQUAL OP_NIP
OP_ELSE                                # ---- refund branch (selector OP_1) ----
    OP_1 OP_NUMEQUALVERIFY
    <refundCsv> OP_CHECKSEQUENCEVERIFY OP_DROP
    OP_0 OP_OUTPUTVALUE <amount> OP_GREATERTHANOREQUAL OP_VERIFY   # <-- same trap
    OP_0 OP_OUTPUTBYTECODE OP_HASH256 <makerHash> OP_EQUAL
OP_ENDIF
```

The fatal sequence on **both** paths is:

```
OP_0 OP_OUTPUTVALUE <amount> OP_GREATERTHANOREQUAL OP_VERIFY
```

This requires `value(output[0]) >= amount`. Output 0 is funded from the covenant
carrier, so its value can be at most the carrier. With `amount` pinned at 50,000,000
and the carrier at 100,000, the predicate `100,000 >= 50,000,000` is **always false**,
so `OP_GREATERTHANOREQUAL` pushes 0 and the following `OP_VERIFY` aborts. Because the
guard sits on both the `OP_IF` (claim) and `OP_ELSE` (refund) branches, there is no
escape route — the UTXO is bricked.

The deeper cause is a **decoupling of two values that must be coupled**:

- `amount` is a **compile-time parameter** substituted into the script (see
  `_build_rxd` in
  [`docs/brainstorms/gravity-ref-spike/build_htlc_covenant_spk.py`](../../brainstorms/gravity-ref-spike/build_htlc_covenant_spk.py)):
  ```python
  amount = int(sys.argv[2])
  ...
  subs = {..., "amount": push(scriptnum(amount)).hex(), ...}
  for name, val in subs.items():
      spk_hex = spk_hex.replace(f"<{name}>", val)
  ```
- the **carrier value** is chosen independently at **funding time**, when the covenant
  SPK is placed into a real UTXO.

Nothing in the build or funding path enforced `amount <= carrier`. The builder happily
compiled `amount=50000000` into a script that was then funded with 100,000 photons,
producing a structurally valid but permanently unspendable covenant.

## Solution

The invariant: **`amount <= funded_carrier`**. The spend routes the carrier (plus any
surplus from extra fee inputs) into output 0, and the covenant requires
`output[0].value >= amount`. So the pin must never exceed what you actually fund.

1. **Choose the carrier you will fund first**, then pin `amount` at or below it. In the
   corrected run the carrier was 500,000 photons and `amount` was pinned to **100,000**
   (`100000 <= 500000`, comfortably satisfying the guard).

2. **Rebuild the covenant SPK** with the matching pin via the RXD variant builder:
   ```
   build_htlc_covenant_spk.py rxd <amount> <taker_wif> <maker_wif> <hashlock_hex> <refund_csv>
   ```
   with `<amount>` = 100000. `_build_rxd` substitutes `push(scriptnum(amount))` into the
   `<amount>` placeholder on both branches, producing the 141-byte RXD HTLC covenant.
   (The static guards still run: GUARD 1 asserts no bare `0xbd`, GUARD 2 asserts no
   input refs — native RXD has neither.)

3. **Fund a fresh covenant UTXO** with the new SPK. Do **not** attempt to reuse or
   rescue the old bricked UTXO — it is permanently unspendable.

4. **Claim**, supplying the preimage and the `OP_0` selector. The claim routed the full
   5,500,000 photons (carrier plus surplus from a separate fee input) into the single
   taker output. This passes `output[0].value (5.5M) >= amount (100k)`, satisfies the
   `OP_SHA256 <H> OP_EQUALVERIFY` hashlock and the
   `OP_OUTPUTBYTECODE OP_HASH256 <takerHash> OP_EQUAL` destination pin, and pays the fee
   from the separate input (not from output 0). Covenant scriptSig:
   ```
   20<p>00          # 32-byte preimage push, then OP_0 (claim selector)
   ```

Because the guard is `>=` (not `==`), **over-funding output 0 is always safe**; only
under-pinning relative to the carrier is required. The failure mode is pinning `amount`
*above* the carrier.

## Verification

The corrected covenant claimed cleanly on Radiant mainnet. The preimage `p` pushed in
the RXD claim scriptSig (`20<p>00`) is **byte-identical** to the preimage revealed in
the corresponding Bitcoin Taproot claim witness — confirming both the value-guard fix
and the cross-chain secret binding. (Reference txids are recorded in
[`docs/brainstorms/gravity-ref-spike/REAL_SWAP_RESULT.md`](../../brainstorms/gravity-ref-spike/REAL_SWAP_RESULT.md),
Phase 4b.)

On-chain check (confirms acceptance under live consensus):
```
radiant-cli getrawtransaction <claim_txid> 1
```
A confirmed result (non-null `blockhash` / `confirmations >= 1`) verifies the spend
succeeded. The bricked v1 covenant remains unspendable on both branches; its 100,000
photons are unrecoverable. The coupling of the covenant `amount` pin to the real
carrier value is exactly the class of bug the external audit must cover — **a working
demo is not an audit.**

## Prevention

### 1. Pre-funding assertion (parse the pin back out of the SPK)

Before broadcasting the funding tx, recover the `amount` literal from the *compiled*
covenant script and assert the carrier you are about to send is at least that large.
Don't trust the in-memory builder value — parse what actually got compiled into the
SPK, because that is what consensus enforces.

```python
def extract_value_pin(spk: bytes) -> int:
    """
    Recover the <amount> push feeding the value-conservation check
    OP_0 OP_OUTPUTVALUE <amount> OP_GREATERTHANOREQUAL OP_VERIFY.
    """
    ops = list(parse_script(spk))   # [(opcode, pushdata_or_None, offset), ...]
    for i, (op, data, _) in enumerate(ops):
        if op == OP_GREATERTHANOREQUAL and i + 1 < len(ops) and ops[i + 1][0] == OP_VERIFY:
            amount_push = ops[i - 1][1]  # OP_OUTPUTVALUE <amount> OP_GTE
            assert amount_push is not None, "expected a data push before OP_GREATERTHANOREQUAL"
            return int.from_bytes(amount_push, "little", signed=True)  # script-num decode
    raise ValueError("no value-conservation check found in covenant SPK")


def assert_fundable(spk: bytes, carrier_photons: int) -> None:
    pin = extract_value_pin(spk)
    if carrier_photons < pin:
        raise ValueError(
            f"UNFUNDABLE COVENANT: carrier {carrier_photons} < amount pin {pin}; "
            f"both claim and refund branches would fail OP_VERIFY and strand the carrier."
        )

# call site, immediately before signing/broadcasting the funding tx:
assert_fundable(covenant_spk, funding_output.value)
broadcast(funding_tx)
```

Decode the push as a script-num (little-endian, sign-magnitude), not a plain int. If
the check appears on both branches (as here), assert both occurrences match if the
builder ever allows asymmetric pins.

### 2. Spendability self-test (dry-run before funding real value)

After building the SPK and before committing real value, simulate a spend against a
synthetic UTXO whose value equals the *intended* carrier. This catches the stranding
bug at build time instead of after broadcast.

```python
def selftest_spendable(covenant_spk, intended_carrier, preimage, claim_key) -> None:
    synthetic_utxo = make_utxo(spk=covenant_spk, value=intended_carrier)
    claim_tx = build_htlc_claim(synthetic_utxo, preimage, claim_key, out0_value=intended_carrier)
    ok, err = run_script_interpreter(claim_tx, input_index=0, prevout=synthetic_utxo,
                                     flags=MANDATORY_VERIFY_FLAGS)
    if not ok:
        raise AssertionError(f"covenant not spendable with carrier {intended_carrier}: {err}")
    # repeat for the refund branch
```

`validate_htlc_covenant.py` already exists as a *static* guard (it checks SPK shape).
Extend it to accept a planned-carrier value and additionally assert
`amount_pin <= planned_carrier` for every value-conservation check on every branch —
turning a build-time shape check into a build-time *fundability* check.

### 3. Design note: compile-time pins vs runtime funding are a coupling hazard

Covenant value pins (`amount`), time pins (`deadline`), and sequence pins (`csv`) are
baked into the script at compile time but are only meaningful relative to values the
*runtime* supplies — the funded carrier, the actual height/MTP, the spending tx's
nSequence. Any parameter substituted into a script that is later compared against an
on-chain value is a coupling hazard: the script and the funding step can drift apart
silently, and the only feedback is `mandatory-script-verify-flag-failed` *after* the
money is locked.

Centralize the `(amount, carrier)` decision (and `(deadline, anchor)`,
`(csv, spend_nSequence)`) in ONE place — a single params object both the SPK compiler
and the funding-tx builder read from, so a mismatch is impossible to express:

```python
@dataclass(frozen=True)
class HtlcParams:
    amount_pin: int        # compiled into the SPK
    carrier: int           # funded into the covenant output
    deadline: int
    csv: int
    def __post_init__(self):
        if self.carrier < self.amount_pin:
            raise ValueError(f"carrier {self.carrier} < amount_pin {self.amount_pin}: unfundable")

spk  = compile_htlc_covenant(params)          # uses params.amount_pin
fund = build_funding_tx(spk, params.carrier)  # cannot diverge
```

### 4. Test case suggestion

```python
def test_underfunded_covenant_rejected_before_broadcast():
    spk = compile_htlc_covenant_raw(amount_pin=50_000_000)  # the buggy combo
    with pytest.raises(ValueError, match="UNFUNDABLE COVENANT"):
        assert_fundable(spk, carrier_photons=100_000)

def test_parsed_pin_matches_builder():
    spk = compile_htlc_covenant_raw(amount_pin=50_000_000)
    assert extract_value_pin(spk) == 50_000_000

def test_exact_funding_is_accepted():
    spk = compile_htlc_covenant_raw(amount_pin=100_000)
    assert_fundable(spk, carrier_photons=100_000)  # boundary: carrier == pin is OK
```

## Related Gotchas

- **Radiant min relay fee is per-kB, not flat.** Fee = `size_bytes * relayfee_per_kB / 1000`.
  With `relayfee = 0.10 RXD/kB`, a 342-byte tx needs at least
  `342 * 0.10 / 1000 = 0.0342 RXD = 3,420,000 photons` to relay; a funding tx sized at
  2.5M photons was rejected `min relay fee not met (code 66)`. Carrier sizing must leave
  headroom for this fee on the *spend* leg — a covenant funded at exactly the amount pin
  can be spendable by script yet unrelayable for lack of fee. Compute `size * rate`,
  never assume a flat per-tx fee.
- **BTC CSV refund is consensus-gated.** The refund leg's relative timelock is enforced
  at the tx level via BIP68 SequenceLocks (block-consensus, `ConnectBlock`), not merely
  by the `OP_CHECKSEQUENCEVERIFY` opcode. A refund broadcast before the CSV delay matures
  is rejected `non-BIP68-final` regardless of script flags — and the spending tx must be
  version >= 2 with the correct `nSequence` for the lock to be evaluated. Test the refund
  leg at/after maturity and assert the premature-refund rejection so a v1-tx or
  wrong-nSequence regression surfaces in CI rather than on-chain.

## Related Documentation

- [`docs/brainstorms/gravity-ref-spike/REAL_SWAP_RESULT.md`](../../brainstorms/gravity-ref-spike/REAL_SWAP_RESULT.md) —
  Phase 4b records the incident and the corrected v2 run.
- [`docs/brainstorms/gravity-ref-spike/build_htlc_covenant_spk.py`](../../brainstorms/gravity-ref-spike/build_htlc_covenant_spk.py) —
  `_build_rxd`: the `amount`/`OP_OUTPUTVALUE` substitution.
- [`docs/brainstorms/gravity-ref-spike/validate_htlc_covenant.py`](../../brainstorms/gravity-ref-spike/validate_htlc_covenant.py) —
  static guards for compiled HTLC covenants (does not yet check amount/carrier coupling).
- [`docs/brainstorms/gravity-ref-spike/build_htlc_claim.py`](../../brainstorms/gravity-ref-spike/build_htlc_claim.py) —
  the single-output + fee model and value pinning.
- [`docs/solutions/logic-errors/ft-in-covenant-two-consensus-gates.md`](ft-in-covenant-two-consensus-gates.md) —
  the FT conservation gates (`refValueSum == amount` plus the codeScriptHash epilogue);
  the FT variant has the same value-pin coupling concern.
