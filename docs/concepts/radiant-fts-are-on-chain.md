# Radiant FTs are on-chain (not metadata-on-P2PKH)

**Why this page exists:** people coming from Bitcoin tokens (Atomicals, Runes,
Ordinals) or Solana SPL often assume Radiant FTs work the same way — *plain
UTXOs with off-chain meaning assigned by an indexer*. That model is wrong for
Radiant. The script bytes **are** the token. This page explains the
difference and what it means in practice.

---

## TL;DR

A Radiant FT UTXO is a **75-byte locking script** with consensus-enforced
token semantics. There is no off-chain indexer required to know what it is or
how much it holds. Compare this to Atomicals / Runes / SPL tokens, where the
on-chain UTXO is a plain P2PKH and an external database tracks "this UTXO
holds 100 FOO."

---

## The two models, side by side

|                                | ❌ NOT how Radiant FTs work                | ✅ How Radiant FTs ACTUALLY work       |
|--------------------------------|--------------------------------------------|----------------------------------------|
| **Examples of this model**     | Atomicals (BTC), Runes, Ordinals, Solana SPL | **Radiant Glyph FTs**, BCH CashTokens, BSV STAS |
| **On-chain script**            | Plain P2PKH (25 bytes)                     | 75-byte FT lock script                 |
| **Token semantics enforced by**| Off-chain indexer rules                    | Consensus opcodes (`OP_PUSHINPUTREF` family) |
| **What "holds the token"**     | An indexer database row pointing at a UTXO | The UTXO's locking script bytes        |
| **Wallet without protocol support** | Sees plain RXD/BTC; can spend the token away by accident | Sees a 75-byte script it can't unlock without the matching key — token is safe |
| **Indexer goes down / disagrees** | Token "vanishes" (or worse, double-spend if indexer state diverges) | Doesn't matter — the chain is the source of truth |
| **Where is the token amount stored?** | In the indexer's database                  | The output's `satoshis` field. **1 photon = 1 token unit.** |

---

## The 75-byte FT layout

Every Radiant FT UTXO has this exact shape:

```
┌─ standard P2PKH (25 B) ─┐  ┌─ ref ──┐  ┌── FT-CSH epilogue (12 B) ─┐
│                         │  │        │  │                            │
76 a9 14 <pkh:20> 88 ac    bd d0 <ref:36>   de c0 e9 aa 76 e3 78 e4 a2 69 e6 9d
▲                         ▲       ▲             ▲
OP_DUP                    │       │             │
OP_HASH160                │       │             │
PUSH(20) <pkh>            │       │             │
OP_EQUALVERIFY            │       │             │
OP_CHECKSIG               │       │             │
                          │       │             │
                          │       │             Hashed by the dMint contract to enforce
                          │       │             conservation: sum(input ft) == sum(output ft).
                          │       │             This is the canonical "FT-CSH" fingerprint that
                          │       │             pyrxd's classifier matches.
                          │       │
                          │       OP_PUSHINPUTREF <36-byte wire ref>
                          │       (consensus opcode 0xd0; the ref is
                          │        txid_LE_reversed + vout_LE = 36 bytes)
                          │
                          OP_STATESEPARATOR (0xbd)
                          (marks the boundary between owner-spend logic
                           and FT-conservation logic)
```

The first 25 bytes are a perfectly normal P2PKH — that's why a key holder can
sign and spend the UTXO with a regular `<sig> <pubkey>` scriptSig. The next
38 bytes (`bd d0 <ref:36>`) bind the UTXO to a specific token via consensus.
The trailing 12 bytes are the conservation "fingerprint" — the dMint
contract hashes them as part of enforcing `sum(input ft) == sum(output ft)`.

**The ref is the token's permanent identity.** Every UTXO of the same FT
encodes the same 36 bytes there. Different tokens have different refs.

---

## The conservation rule

Every `OP_PUSHINPUTREF` (`0xd0`) ref appearing in any **output** script must
also appear in some **input** being spent. This is enforced at consensus
level by the Radiant node:

```
INPUTS                         OUTPUTS
──────                         ───────
[FT lock with ref=R]   ──→     [FT lock with ref=R]   ✓ ref R survives
                               [FT lock with ref=R]   ✓ R can split

[P2PKH only]           ──→     [FT lock with ref=R]   ✗ REJECTED
                                                        R never came from input
```

When the rule is violated, the node rejects the broadcast with:

```
bad-txns-inputs-outputs-invalid-transaction-reference-operations
```

**Refs cannot be conjured from thin air — only carried forward.**

This is why a transfer that funds itself from a plain P2PKH UTXO (regular
RXD) and tries to produce an FT output **always fails**. The output declares
"I carry ref R" but no input ever carried R. There's nothing wrong with the
signature or the math; the chain refuses on principle.

---

## Wallets at one address can hold mixed UTXOs

A typical Radiant wallet address holds **both** plain P2PKH UTXOs (regular
RXD for fees) and FT lock UTXOs (token balances). They are different shapes
at the same address:

```
Address ──┬── UTXO 1: P2PKH 25 bytes,     sats=39825 RXD     (RXD for fees)
          ├── UTXO 2: FT 75 bytes,         sats=5_749_199    (RBG token balance)
          ├── UTXO 3: P2PKH 25 bytes,      sats=1            (RXD dust)
          └── UTXO 4: FT 75 bytes (different ref), sats=100  (a different FT)
```

Same address, four UTXOs, four different shapes/meanings. Your wallet
scanner returns all of them. When transferring an FT, your code must filter
to:

1. UTXOs whose locking script is the 75-byte FT shape (`is_ft_script`)
2. AND whose embedded ref matches the token you want to transfer
   (`extract_ref_from_ft_script(...) == target_ref`)

**Skipping that filter does not help.** Feeding a P2PKH UTXO into pyrxd's
`FtUtxoSet` will produce a tx that violates the conservation rule above.
The script-shape check that rejects "Not a valid FT script" is correct —
it's protecting you from broadcasting a tx the network would reject.

---

## Implications for transfer code

The canonical pattern, also implemented in
[`examples/ft_transfer_demo.py`](../../examples/ft_transfer_demo.py):

```python
from pyrxd.glyph.script import is_ft_script, extract_ref_from_ft_script
from pyrxd.network.electrumx import script_hash_for_address
from pyrxd.security.types import Txid
from pyrxd.transaction.transaction import Transaction

ft_utxos = []
raw_utxos = await client.get_utxos(script_hash_for_address(my_address))
for u in raw_utxos:
    raw = await client.get_transaction(Txid(u.tx_hash))
    tx = Transaction.from_hex(bytes(raw))
    script = tx.outputs[u.tx_pos].locking_script.serialize()

    # Filter 1: must be a 75-byte FT lock (skip plain P2PKH RXD).
    if not is_ft_script(script.hex()):
        continue

    # Filter 2: must be the token we want (skip other FTs).
    if extract_ref_from_ft_script(script) != target_token_ref:
        continue

    # OK, this is a UTXO of the target FT.
    ft_utxos.append(FtUtxo(
        txid=u.tx_hash, vout=u.tx_pos, value=u.value,
        ft_amount=u.value,                # 1 photon = 1 FT unit
        ft_script=script,                 # bytes, 75 long
    ))

# Now feed ft_utxos into FtUtxoSet for transfer construction.
```

---

## How to verify a UTXO is "actually FT-bearing"

Use `pyrxd glyph inspect` against a tx to see exactly what each output is:

```bash
$ pyrxd glyph inspect <txid> --fetch
Transaction: ...
  vout 0  type=ft     ref=b45dc4...:0  sats=5         (FT — 5 RBG to recipient)
  vout 1  type=ft     ref=b45dc4...:0  sats=9990      (FT — 9990 RBG change)
  vout 2  type=p2pkh                    sats=39825 RXD (regular RXD change)
```

If a UTXO classifies as `type=p2pkh`, it is not an FT — the chain itself
will not let you spend it as one regardless of what an off-chain tool tells
you to do.

---

## Source-of-truth references

- **Consensus opcodes.** `OP_PUSHINPUTREF` (`0xd0`),
  `OP_PUSHINPUTREFSINGLETON` (`0xd8`), `OP_REQUIREINPUTREF` (`0xd1`),
  `OP_REFTYPE_OUTPUT` (`0xda`), `OP_STATESEPARATOR` (`0xbd`). These are
  Radiant-specific opcodes added by the node fork; they don't exist on
  Bitcoin or BCH.
- **Glyph protocol spec.** The 75-byte FT layout and the conservation
  fingerprint `dec0e9aa76e378e4a269e69d` are defined by the Glyph
  protocol (REP-3010 for V2 dMint).
- **Classifier code.** [`src/pyrxd/glyph/script.py`](../../src/pyrxd/glyph/script.py)
  has the regex (`FT_SCRIPT_RE`), constructor (`build_ft_locking_script`),
  predicate (`is_ft_script`), and extractors
  (`extract_ref_from_ft_script`, `extract_owner_pkh_from_ft_script`).
- **Live evidence.** Three independent on-chain witnesses confirm the
  75-byte form is the canonical FT shape: any FT premine output, any FT
  transfer output, any dMint reward output. Run
  `pyrxd glyph inspect <any-FT-tx-id> --fetch` to see the bytes yourself.

---

## When in doubt, trust the bytes

If a tool, chatbot, or doc tells you Radiant FTs are "P2PKH outputs with
metadata interpreted by an indexer," that tool is **describing a different
protocol** (Atomicals / Runes / Ordinals / SPL — all of which use that
model). Radiant is not that.

Three things you can always check yourself:

1. **The chain.** `pyrxd glyph inspect <txid> --fetch` will show you the
   exact byte shape of every output. FT outputs are 75 bytes; P2PKH is 25.
2. **The opcodes.** A 75-byte script with `bd d0` at offset 25-26 is an FT
   lock. A 25-byte script ending `88 ac` is plain P2PKH.
3. **The error.** If your transfer is rejected with
   `bad-txns-inputs-outputs-invalid-transaction-reference-operations`,
   you violated the conservation rule. There is no off-chain workaround.
