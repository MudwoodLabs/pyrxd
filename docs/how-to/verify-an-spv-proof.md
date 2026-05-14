# How to verify an SPV proof

**Who this page is for:** anyone who has a transaction's Merkle inclusion
proof and the 80-byte block header containing the Merkle root, and wants
to confirm the tx is actually in that block. pyrxd's SPV surface lives
in [`pyrxd.spv`](../api/spv.rst); this page is the recipe.

The primary primitive is **`pyrxd.spv.verify_tx_in_block`** — synchronous,
returns `None` on success, raises `SpvVerificationError` on any failure.
There is no `verify_spv_proof(...)` top-level function and no boolean
return: pyrxd's verifiers are *raise-on-failure* by design so a missed
exception cannot be silently downgraded to "valid."

---

## TL;DR — the recipe

You need four things:

1. **`raw_tx`** (`bytes`) — the witness-stripped serialization of the tx.
   Witness data is *not* covered by the Merkle root; pyrxd's
   [`strip_witness`](../api/spv.rst) handles segwit/taproot for you.
2. **`txid_be_hex`** (`str`) — the txid in big-endian display order
   (the form you see in block explorers).
3. **`branch`** (`bytes`) — the Merkle path in pyrxd's covenant wire
   format: `N * 33` bytes, each entry `[direction_byte][32B_sibling_LE]`.
   Build it from a mempool.space / Bitcoin Core / ElectrumX response
   with [`build_branch`](../api/spv.rst).
4. **`header`** (`bytes`) — the 80-byte block header containing the
   Merkle root.

Plus the leaf position `pos` (the tx's index in the block, where `0`
is the coinbase).

```python
from pyrxd.spv import build_branch, strip_witness, verify_tx_in_block
from pyrxd.security.errors import SpvVerificationError, ValidationError

# 1. Strip witness — required for the txid to round-trip.
raw_tx = strip_witness(full_raw_tx)

# 2. Convert sibling hashes from BE display order to pyrxd's wire format.
branch = build_branch(merkle_be_hashes, pos)

# 3. Verify. Raises on any failure; returns None on success.
try:
    verify_tx_in_block(
        raw_tx=raw_tx,
        txid_be_hex=txid_be_hex,
        branch=branch,
        pos=pos,
        header=header_80_bytes,
        # Optional: bind the proof to a known depth (audit defense).
        expected_depth=None,
    )
    print("tx is included in the block")
except SpvVerificationError as exc:
    print(f"proof rejected: {exc}")
except ValidationError as exc:
    print(f"malformed input: {exc}")
```

That's the whole recipe. The rest of this page explains the moving
parts and the failure modes.

---

## What `verify_tx_in_block` actually checks

From [`src/pyrxd/spv/merkle.py`](https://github.com/MudwoodLabs/pyrxd/tree/main/src/pyrxd/spv/merkle.py),
the function runs four defenses in order:

| #   | Check                                          | Raises                                            |
| --- | ---------------------------------------------- | ------------------------------------------------- |
| 1   | `len(raw_tx) > 64`                             | `SpvVerificationError` (64-byte Merkle forgery)   |
| 2   | `pos != 0`                                     | `SpvVerificationError` (coinbase guard)           |
| 3   | `len(branch) % 33 == 0` (and depth match if `expected_depth` given) | `ValidationError` / `SpvVerificationError` |
| 4   | `hash256(raw_tx) == txid` (parsed LE)          | `SpvVerificationError`                            |
| 5   | `compute_root(txid, branch) == header[36:68]`  | `SpvVerificationError`                            |

Each defense exists for a reason. The 64-byte length check rejects the
classic Merkle forgery where a crafted "transaction" is byte-identical
to an interior Merkle node. The `pos != 0` guard refuses to treat a
coinbase as a payment proof. The `expected_depth` argument lets you
bind the proof to a specific tree depth, blocking proofs that move the
leaf between blocks of different sizes.

`build_branch` and `compute_root` are also exported if you want to
build wire-format branches or walk a branch to a root yourself — see
[`pyrxd.spv` API reference](../api/spv.rst).

---

## Fetching the Merkle path you need

If you don't already have a Merkle path, ask the network for one.
pyrxd ships two routes.

### From an ElectrumX server

`ElectrumXClient.get_transaction_merkle(txid, height)` wraps the
`blockchain.transaction.get_merkle` JSON-RPC method and returns a
parsed `MerklePath`:

```python
from pyrxd.network.electrumx import ElectrumXClient
from pyrxd.security.types import BlockHeight, Txid

async with ElectrumXClient(["wss://your.electrumx.server:50002"]) as client:
    merkle_path = await client.get_transaction_merkle(
        Txid(txid_be_hex),
        BlockHeight(889_000),
    )
```

`MerklePath` is the BEEF-style proof object from
[`pyrxd.merkle_path`](https://github.com/MudwoodLabs/pyrxd/tree/main/src/pyrxd/merkle_path.py).
If you have a `ChainTracker` (which can fetch headers from a
`BtcDataSource` and check the Merkle root), `MerklePath.verify` gives
you a one-liner:

```python
from pyrxd.network.bitcoin import MempoolSpaceSource
from pyrxd.network.chaintracker import ChainTracker

tracker = ChainTracker(MempoolSpaceSource())
valid: bool = await merkle_path.verify(str(txid), tracker)
```

This path is `bool`-returning rather than raise-on-failure, because it
delegates the trust decision to the `ChainTracker`'s header source. If
you want the audit defenses listed above, run the proof through
`verify_tx_in_block` instead.

### From a `BtcDataSource` (mempool.space / blockstream)

The `BtcDataSource.get_merkle_proof` abstract method returns the raw
sibling-hash list and leaf position — feed those straight into
`build_branch`:

```python
from pyrxd.network.bitcoin import MempoolSpaceSource
from pyrxd.security.types import BlockHeight, Txid

source = MempoolSpaceSource()
merkle_be, pos = await source.get_merkle_proof(
    Txid(txid_be_hex),
    BlockHeight(889_000),
)
branch = build_branch(merkle_be, pos)
```

mempool.space and Bitcoin Core return sibling hashes in big-endian
display order; `build_branch` reverses them to the little-endian
encoding the covenant-format branch expects. You don't have to do that
yourself.

---

## Common failure modes

| Exception message                                                 | What went wrong                                                                                                  |
| ----------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| `raw_tx must be > 64 bytes (64-byte Merkle forgery defense)`      | The provided tx is too short. Real txs are always longer; this defense blocks a forged-leaf attack.              |
| `pos=0 is the coinbase tx - cannot be used as payment proof`      | You passed the coinbase. Pick any non-coinbase tx in the block instead.                                          |
| `branch length N not a multiple of 33`                            | Wrong wire format. Did you pass raw BE sibling hashes? Run them through `build_branch` first.                    |
| `branch depth N does not match expected M`                        | You set `expected_depth=M` but the branch has a different depth. Either drop the binding or fix the depth value. |
| `hash256(raw_tx) does not match txid`                             | The `raw_tx` and `txid_be_hex` disagree. Usually means witness wasn't stripped — call `strip_witness` first.     |
| `Merkle root mismatch: tx not in this block`                      | The proof walks to a root that isn't the one in `header[36:68]`. The proof is wrong, or you have the wrong block. |
| `header must be 80 bytes, got N`                                  | The header isn't 80 bytes. Block-header endpoints sometimes return JSON wrappers — pass only the raw 80-byte slice. |

All of these raise `SpvVerificationError` (a subclass of
`pyrxd.errors.RxdSdkError`) except the structural-input ones, which
raise `ValidationError`. Catch both if you want a single
proof-rejection handler.

---

## When you also need PoW + chain-anchor binding

`verify_tx_in_block` checks **Merkle inclusion only.** A valid Merkle
proof against a header you found on disk says nothing about whether
that header is on the real chain. For the full picture, pyrxd provides
two more verifiers in the same module:

- **`verify_header_pow(header)`** — single-header proof-of-work check
  (validates `nBits`, computes the target, compares against
  `hash256(header)`). Raises `SpvVerificationError` if PoW fails.
- **`verify_chain(headers, chain_anchor=...)`** — N-header chain
  walker. Verifies PoW for every header *and* that `headers[i].prevHash`
  links to `hash256(headers[i-1])`. An optional `chain_anchor` pins
  `headers[0].prevHash` to a known mainnet value, blocking testnet /
  alt-chain forgeries.

For a covenant-bound flow (e.g.
[Gravity](../concepts/gravity.md)), the canonical entry point is
**`SpvProofBuilder`**:

```python
from pyrxd.spv import CovenantParams, P2PKH, SpvProofBuilder

params = CovenantParams(
    btc_receive_hash=expected_pkh_20_bytes,
    btc_receive_type=P2PKH,
    btc_satoshis=10_000,
    chain_anchor=anchor_prevhash_32_bytes,
    anchor_height=889_000,
    merkle_depth=12,
)
proof = SpvProofBuilder(params).build(
    txid_be=txid_be_hex,
    raw_tx_hex=raw_tx_hex,
    headers_hex=[h1_hex, h2_hex, ...],  # consecutive 80-byte headers
    merkle_be=merkle_be_hashes,
    pos=pos,
    output_offset=output_byte_offset,
)
```

`SpvProofBuilder.build` runs witness-strip → tx-integrity → PoW + chain
link → Merkle inclusion (with depth binding) → payment-output check, in
that order. It returns an `SpvProof` only if every check passed; any
failure raises `SpvVerificationError`. The returned `SpvProof` is a
frozen dataclass and can only be constructed via `build()` — direct
dataclass instantiation is rejected at runtime. This is the proof type
you hand to downstream covenant builders.

---

## References

- [`pyrxd.spv` API reference](../api/spv.rst)
- [Gravity (cross-chain atomic swap concept)](../concepts/gravity.md)
- Source: [`src/pyrxd/spv/merkle.py`](https://github.com/MudwoodLabs/pyrxd/tree/main/src/pyrxd/spv/merkle.py),
  [`proof.py`](https://github.com/MudwoodLabs/pyrxd/tree/main/src/pyrxd/spv/proof.py),
  [`chain.py`](https://github.com/MudwoodLabs/pyrxd/tree/main/src/pyrxd/spv/chain.py),
  [`pow.py`](https://github.com/MudwoodLabs/pyrxd/tree/main/src/pyrxd/spv/pow.py)
- Tests with audit-finding coverage:
  [`tests/test_spv.py`](https://github.com/MudwoodLabs/pyrxd/tree/main/tests/test_spv.py)
