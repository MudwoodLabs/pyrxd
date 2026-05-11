---
title: "dMint deploy walk: hashlock-reuse confuses 'find the reveal'"
category: logic-errors
tags: [dmint, deploy, electrumx, scripthash-history, hashlock, walk-from-reveal]
module: dmint
symptom: "find_dmint_contract_utxos returns 0 UTXOs for a deploy that should have contracts, OR fetches a wrong tx as the 'deploy reveal'"
root_cause: "ElectrumX scripthash history returns ALL txs touching the scripthash. The FT-commit hashlock script can be reused across multiple failed deploy attempts (same payload-hash + same owner-PKH = same scripthash), so 'first non-commit history entry' is not the deploy reveal."
date: 2026-05-10
---

# dMint deploy walk: hashlock-reuse confuses "find the reveal"

## Symptom

`find_dmint_contract_utxos(client, token_ref=...)` (Shape B, walk-from-reveal)
returns 0 contract UTXOs for a deploy that is known to exist on chain, OR
returns S2 cross-check failures because the "reveal" txid the helper picked
doesn't actually contain V1 contract outputs.

## Root cause

The walk-from-reveal path computes the FT-commit hashlock's scripthash and
calls `client.get_history(scripthash)`. The intuition is "the hashlock
script is single-use; history will contain exactly the commit + the reveal."

That intuition is **wrong on Radiant mainnet**. The 75-byte hashlock script:

```
OP_HASH256 <32-byte payload-hash> OP_EQUALVERIFY
PUSH(3) "gly" OP_EQUALVERIFY
OP_INPUTINDEX OP_OUTPOINTTXHASH OP_INPUTINDEX OP_OUTPOINTINDEX
OP_4 OP_NUM2BIN OP_CAT OP_REFTYPE_OUTPUT OP_<N> OP_NUMEQUALVERIFY
OP_DUP OP_HASH160 PUSH(20) <pkh> OP_EQUALVERIFY OP_CHECKSIG
```

is deterministic given `(payload, N, pkh)`. If a deployer uploads the same
CBOR body twice (e.g. a failed earlier attempt followed by a real success),
both transactions emit the **identical** vout-0 script. ElectrumX hashes
the script bytes, so both attempts land on the same scripthash. `get_history`
returns all txs that ever touched that scripthash, in chronological order.

For Radiant Glyph Protocol (GLYPH), the scripthash for the FT-commit
hashlock has **4** history entries:

```
228398  d171b184…1597   ← earlier failed attempt (same script bytes)
228398  6de766d7…3eaf   ← spends d171b184:0 to refund
228604  a443d9df…878b   ← the real deploy commit
228604  b965b32d…9dd6   ← the real deploy reveal
```

A naive "first non-commit entry is the reveal" picks `d171b184…1597`, which
has 13 outputs that are P2PKHs — no V1 contracts. The helper either
returns 0 results or raises S2 mismatches.

## Working solution

Don't trust history ordering or "first non-commit". Among the candidates
in history, pick the one whose **inputs actually spend `commit_txid:0`**.
The real reveal is the only candidate that does:

```python
for entry in history:
    h_txid = entry["tx_hash"]
    if h_txid == commit_txid:
        continue
    cand_tx = Transaction.from_hex(bytes(await client.get_transaction(Txid(h_txid))))
    spends_commit_vout0 = any(
        ti.source_txid == commit_txid and ti.source_output_index == 0
        for ti in cand_tx.inputs
    )
    if spends_commit_vout0:
        reveal_txid = h_txid
        break
```

This costs one extra `get_transaction` per non-matching candidate, but the
candidate set is tiny (1–3 typically) so the round-trip cost is negligible
compared to the (already-required) reveal fetch.

## Prevention

- Always confirm chain-walking helpers with a **live mainnet smoke test**
  before merging. Unit tests with synthetic data won't catch this because
  the test author tends to make each synthetic tx self-consistent.
- For any "find the spending tx" pattern using scripthash history: confirm
  the candidate's inputs include the specific outpoint you care about.
- The same lesson applies in reverse: `blockchain.scripthash.get_history`
  is **coarse** — it returns scripts, not outpoints. Whenever a Radiant
  protocol asks "which tx spent this specific UTXO?", the answer requires
  per-candidate input inspection, not just scripthash history filtering.

## Tests

Test the disambiguation directly with a mock client that has multiple
non-commit candidates in history, only one of which spends the commit's
vout 0. See `tests/test_dmint_v1_deploy.py::TestWalkFromReveal::test_disambiguates_hashlock_reuse`
for the regression-locking fixture.

## Related

- `docs/solutions/logic-errors/dmint-v1-mint-shape-mismatch.md` — the M1
  lesson that golden vectors must come from real mainnet bytes; this M2
  lesson extends it: chain-walking helpers must also be verified against
  real mainnet history shapes, not just synthetic happy-path mocks.
- `docs/solutions/logic-errors/funding-utxo-byte-scan-dos.md` — the M1
  lesson that byte-substring scans of scripts misclassify; this M2 lesson
  is the same principle applied to *history* listings (coarse-grained
  scripthash queries collapse multiple unrelated spends).
- `docs/dmint-research-photonic-deploy.md` §3.1 — the on-chain decode that
  surfaced this issue (the GLYPH commit had 4 entries in its vout-0
  scripthash history, not 2).
