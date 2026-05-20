# How to handle Radiant's BIP143 sighash quirks

**Who this page is for:** anyone porting a sighash implementation from
Bitcoin, BCH, BSV, or another BIP143-style chain to Radiant. If you sign
transactions through pyrxd's high-level `Transaction.sign(...)` API,
**you do not need this page** — pyrxd computes the right preimage
internally. Read on only if you build preimages by hand (custom
unlocking templates, off-chain signers, a Rust/Go port of pyrxd's
sighash logic, etc.).

The two ways Radiant deviates from standard BIP143:

1. An extra **`hashOutputHashes`** commitment is inserted into the
   preimage immediately before `hashOutputs`.
2. That extra field scans each output's locking script for the
   Radiant-only **ref opcodes** (`OP_PUSHINPUTREF` `0xd0` and
   `OP_PUSHINPUTREFSINGLETON` `0xd8`) and folds them in.

Both quirks apply to **every** input, every sighash type — there is no
"ref-aware mode" switch. A standard P2PKH spend still uses the extended
preimage; the extra field just commits to ref counts of zero. Code
ported verbatim from Bitcoin or BCH will produce signatures Radiant
rejects.

---

## TL;DR — the preimage layout

Radiant's BIP143 preimage is Bitcoin SV's BIP143 with **one extra
32-byte field inserted before `hashOutputs`**:

```
 1. nVersion            (4-byte LE)
 2. hashPrevouts        (32-byte hash)
 3. hashSequence        (32-byte hash)
 4. outpoint            (32-byte hash + 4-byte LE)
 5. scriptCode          (varint-length-prefixed)
 6. value               (8-byte LE)
 7. nSequence           (4-byte LE)
 8. hashOutputHashes    (32-byte hash)   ← Radiant extension
 9. hashOutputs         (32-byte hash)
10. nLocktime           (4-byte LE)
11. sighashType         (4-byte LE)
```

Field 8 is the only structural difference. Fields 1–7 and 9–11 match
BIP143 byte-for-byte (see
[BIP143](https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki)).

The canonical Python implementation is in
[`src/pyrxd/transaction/transaction_preimage.py`](https://github.com/MudwoodLabs/pyrxd/tree/main/src/pyrxd/transaction/transaction_preimage.py),
function `_preimage`. The radiantjs reference is
`GetHashOutputHashes` in `lib/transaction/sighash.js`.

---

## What `hashOutputHashes` commits to

For each output `out_i` in scope (all outputs for `ALL`, just `out_i`
for `SINGLE`, none for `NONE`), pyrxd writes:

| Field                                          | Width            |
|------------------------------------------------|------------------|
| `out_i.value`                                  | 8-byte LE        |
| `hash256(out_i.locking_script)`                | 32 bytes         |
| `len(push_refs)`                               | 4-byte LE        |
| if `len > 0`: `hash256(concat(sorted push_refs))` <br> else: 32 zero bytes | 32 bytes         |

It then `hash256`'s the whole concatenation. The result is the 32-byte
`hashOutputHashes` field.

The `push_refs` list is built by scanning the locking script's bytes
for `OP_PUSHINPUTREF` (`0xd0`) and `OP_PUSHINPUTREFSINGLETON` (`0xd8`),
each followed by exactly 36 bytes of ref data. **Refs are sorted
ascending and deduplicated** before hashing — this matches radiantjs
consensus exactly and pyrxd's vectors are pinned against a confirmed
mainnet reveal. See `_compute_hash_output_hashes` and `_get_push_refs`
in `transaction_preimage.py`.

For a plain P2PKH output, `len(push_refs)` is 0 and the trailing
32 bytes are zero — but the field is still computed and still
contributes to the digest. Skipping it produces a different preimage
and the signature will not verify.

`SIGHASH` flag interactions match standard BIP143: for
`SIGHASH_SINGLE`, only `outputs[input_index]` is included; for
`SIGHASH_NONE`, the field is 32 zero bytes.

---

## The high-level path (use this unless you can't)

```python
from pyrxd.keys import PrivateKey
from pyrxd.script.type import P2PKH
from pyrxd.transaction.transaction import Transaction, TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput

pk = PrivateKey(...)

tx_in = TransactionInput(
    source_transaction=src_tx,
    source_output_index=0,
    unlocking_script_template=P2PKH().unlock(pk),
)
tx_out = TransactionOutput(P2PKH().lock(recipient_addr), 1_000)

tx = Transaction(tx_inputs=[tx_in], tx_outputs=[tx_out])
tx.fee()       # compute change
tx.sign()      # ← Radiant preimage handled internally
raw = tx.hex()
```

`Transaction.sign()` walks each input, delegates to its
`unlocking_script_template.sign(tx, input_index)`, which in turn calls
`tx.preimage(input_index)` to fetch the Radiant-extended preimage and
signs it. Built-in templates (`P2PKH`, `P2PK`, `BareMultisig`, the
dMint/Glyph unlockers in `pyrxd.script.type` and `pyrxd.glyph`) all
already handle field 8 correctly because they go through this single
path.

If your code path is `tx.sign()`, stop here.

---

## The low-level path (custom signers / off-chain ports)

When you need the raw preimage bytes — to sign in another language, to
serve a remote signer, or to build a custom unlocking template:

```python
from pyrxd.transaction.transaction import Transaction

# Build tx with inputs + outputs as usual; ensure each TransactionInput
# has source_txid, source_output_index, satoshis, locking_script, and
# sighash set. The .locking_script field of the input is the
# *previous output's* script — i.e. the scriptCode that goes into
# field 5 of the preimage.

preimage_bytes = tx.preimage(input_index)
# bytes, variable length — field 5 is varint-prefixed
```

`Transaction.preimage(index)` returns the full Radiant BIP143 preimage
for one input. Sign `hash256(preimage_bytes)` (or whatever your curve
wrapper expects) and assemble the unlocking script yourself.

For a one-shot computation outside a `Transaction` instance, the same
logic lives at module level as
`pyrxd.transaction.transaction_preimage.tx_preimage(input_index, inputs, outputs, tx_version, tx_locktime)`.
It returns the same bytes as `Transaction.preimage`.

The sighash type used in field 11 comes from
`tx.inputs[input_index].sighash`, defaulting to `SIGHASH.ALL_FORKID`
(`0x41`). The `FORKID` (`0x40`) bit is the Bitcoin Cash / SV / Radiant
replay-protection flag; sighash `0x01` (Bitcoin's `SIGHASH_ALL`) is not
a valid Radiant sighash and will be rejected by `SIGHASH.validate`.

---

## Common pitfalls when porting from BTC / BCH / BSV

### 1. Forgetting `hashOutputHashes` entirely

The classic symptom: signatures verify against your own preimage
function but every broadcast fails with
`mandatory-script-verify-flag-failed` and the node logs show
`Signature must be zero for failed CHECK(MULTI)SIG operation`. The
script evaluator computed a different sighash than your signer did,
because your preimage is 32 bytes shorter than Radiant's.

**Fix:** insert the 32-byte `hashOutputHashes` between
`nSequence` (field 7) and `hashOutputs` (field 9). Even for plain
P2PKH transactions with zero refs anywhere, the field is not optional.

### 2. Treating it as a "ref-aware mode" toggle

There is no separate code path for inputs whose locking script
contains an `OP_PUSHINPUTREF`. **All inputs use the same extended
preimage.** The ref scan happens over the *outputs* (committed inside
`hashOutputHashes`), not over the input being signed.

A common port mistake: "only insert `hashOutputHashes` when signing an
FT or NFT input." That produces sighash mismatches for every plain
RXD spend in a mixed wallet.

### 3. Wrong endianness on the ref count

The `len(push_refs)` count inside `hashOutputHashes` is a **4-byte
little-endian** integer (`struct.pack("<I", n)`), not a varint and not
big-endian. Getting this wrong on a P2PKH output (where `n == 0`)
silently works — all four bytes are zero either way — and then breaks
the moment any output in the tx carries a ref.

### 4. Hashing refs in script order instead of sorted+deduped

Refs are **sorted ascending by their 36 bytes and deduplicated** before
being concatenated and hashed. Hashing them in the order they appear
in the script produces a different `hashOutputHashes` whenever a
script contains two refs (e.g. multi-ref covenants, Gravity offers).

### 5. Forgetting to update field 5's varint prefix

Field 5 (`scriptCode`) is varint-length-prefixed. When the input's
locking script grows past 252 bytes — e.g. a 241-byte V1 dMint
contract spend, or a Gravity-class covenant — the varint prefix
transitions from 1 to 3 bytes. A signer that always writes a 1-byte
length will produce a malformed preimage. pyrxd uses
`Script.byte_length_varint()` to emit the correct prefix; ports
should match.

### 6. Signing twice through the bypass

Calling `tx.sign()` on a transaction whose input already has a
non-`None` `unlocking_script` is a no-op by default (`bypass=True`).
If you signed a trial transaction, mutated its outputs, and signed
again, the stale signature stays in place and the broadcast fails
mysteriously. Reset `tx_in.unlocking_script = None` between signings,
or pass `tx.sign(bypass=False)` — see
[`tests/test_preimage.py::TestTwoPassSigning`](https://github.com/MudwoodLabs/pyrxd/tree/main/tests/test_preimage.py)
for the canonical reproduction.

---

## How to verify a custom port against pyrxd

The cheapest sanity check is to construct the same transaction in
pyrxd and compare bytes:

```python
expected = tx.preimage(input_index).hex()
mine     = my_port.compute_preimage(...).hex()
assert mine == expected, (mine, expected)
```

For unit-level checks of the ref-scan and `hashOutputHashes`
computation in isolation, pyrxd ships pinned vectors generated from
radiantjs against the mainnet reveal tx
`dac1e2dfed64fbfd0f0fe6b925e144cfc32ef76803abc7a6a4058406d707b407` —
see `TestComputeHashOutputHashes` in
[`tests/test_preimage.py`](https://github.com/MudwoodLabs/pyrxd/tree/main/tests/test_preimage.py).
Reusing those hex constants is the fastest way to verify a port
without standing up a full transaction.

---

## References

- **BIP143** (the standard preimage Radiant extends):
  [bitcoin/bips#bip-0143](https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki)
- **pyrxd implementation**:
  [`src/pyrxd/transaction/transaction_preimage.py`](https://github.com/MudwoodLabs/pyrxd/tree/main/src/pyrxd/transaction/transaction_preimage.py)
  — `_preimage`, `_compute_hash_output_hashes`, `_get_push_refs`,
  `tx_preimage`.
- **High-level entry point**:
  [`Transaction.preimage`](https://github.com/MudwoodLabs/pyrxd/tree/main/src/pyrxd/transaction/transaction.py)
  and `Transaction.sign`.
- **radiantjs reference**: `GetHashOutputHashes` in
  `lib/transaction/sighash.js`
  ([RadiantBlockchain-Community/radiantjs](https://github.com/RadiantBlockchain-Community/radiantjs)).
- **Test vectors**: `tests/test_preimage.py` — pinned against mainnet
  reveal `dac1e2dfed64fbfd0f0fe6b925e144cfc32ef76803abc7a6a4058406d707b407`.
- **Ref opcodes in context**: the
  [Radiant FTs are on-chain](../concepts/radiant-fts-are-on-chain.md)
  concept page explains where `OP_PUSHINPUTREF` shows up in real
  output scripts.
