---
title: Gravity BCH support — spike findings
date: 2026-05-19
status: brainstorm
---

# Gravity BCH support — current state is better than expected

## TL;DR

A spike investigation into adding BCH support to Gravity found that
**the existing SPV verifier and Gravity covenant are already
chain-agnostic for SHA-256d UTXO chains**. The verifier doesn't
compute or validate difficulty — it accepts whatever nBits the maker
committed at offer time. BCH headers are byte-identical in structure
to BTC headers and use the same PoW. BCH has no segwit, so the
shipping P2PKH path (closed out in the previous spike's follow-up
commit) is the relevant one — and it's now end-to-end tested.

What's actually missing for BCH support is:

1. **Data-source compatibility verification** — confirm
   `MempoolSpaceSource(base_url="https://mempool.cash/api")` (or
   similar BCH explorer with mempool.space-shaped API) works
   end-to-end. Likely yes, but unverified.
2. **An end-to-end integration test** using recorded BCH headers
   and a BCH P2PKH payment, mirroring `TestGravityTradeP2PKH`.
3. **Documentation** explicitly stating BCH is a supported
   counterparty chain alongside BTC.
4. **Cashaddr ↔ hash160 helper** (probably small, maybe already
   exists in another library; users could decode externally).

**Revised effort estimate: ~1-2 weeks of alternating-week pyrxd time
(~5-10 hours of focused work)** — basically a copy of the BCH version
of the P2PKH spike-follow-up commit. The original plan budgeted 4-6
weeks; the same overestimation pattern as the P2PKH spike.

## What the spike found

### Discovery 1: the SPV verifier is chain-agnostic at the math layer

`src/pyrxd/spv/pow.py` performs:

1. SHA-256d hash of the 80-byte header
2. Comparison against a target derived from the header's own nBits
   field (bytes 72-76)
3. Rejection if `hash >= target`

There is **no consensus-style difficulty validation**. The verifier
does NOT check that nBits is "correct for the height" — it only
checks that the header satisfies the difficulty it claims. This is
deliberately chain-agnostic: BTC, BCH, BSV, and any other SHA-256d
chain all use this exact format.

`src/pyrxd/spv/chain.py` verifies header chain linkage (`prevHash`
in bytes 4-36 of each subsequent header matches `hash256` of the
previous). Identical structure across all SHA-256d chains.

The naming is BTC-flavored throughout the SPV module (docstrings,
type names like "Bitcoin SPV"), but the **logic** is universal.

### Discovery 2: difficulty algorithm differences don't matter to the verifier

BTC uses epoch-based retargeting (every 2,016 blocks). BCH uses
aserti3-2d (per-block adjustment, based on time since the last
retarget anchor). **Neither matters to the verifier.**

Why: the security model is that the **maker** commits to specific
`expected_nbits` (and optionally `expected_nbits_next`) values at
offer creation time. The covenant rejects any header whose nBits
doesn't match one of those two values. The verifier doesn't need to
know how the counterparty chain computes difficulty; it just needs
to confirm the maker's commitment.

```python
# from src/pyrxd/gravity/covenant.py:317
expected_nbits: bytes,           # 4-byte LE nBits of expected difficulty
expected_nbits_next: bytes | None = None,  # difficulty after a transition
```

For BCH, the maker just picks the current BCH nBits value at offer
time, possibly with `expected_nbits_next` set to handle an aserti3-2d
adjustment during the swap window. The covenant doesn't care that
BCH's adjustment is per-block instead of epoch-based.

The same generalization applies to any future SHA-256d chain or
soft-fork: nothing in the verifier or covenant needs to change.

### Discovery 3: witness stripping is a no-op for BCH

`src/pyrxd/spv/witness.py:strip_witness` returns the input unchanged
if there's no segwit marker (bytes 4 = 0x00). **BCH never had
segwit**, so every BCH tx is already legacy-serialized and bypasses
the stripping logic. No code change needed.

### Discovery 4: data-source abstraction is already chain-pluggable

`src/pyrxd/network/bitcoin.py` defines:

```python
class BtcDataSource(ABC):
    @abstractmethod
    async def get_tip_height(self) -> BlockHeight: ...
    @abstractmethod
    async def get_block_header_hex(self, height: BlockHeight) -> bytes: ...
    # ... etc.
```

with three concrete implementations:
- `MempoolSpaceSource(base_url=...)` — defaults to mempool.space but
  takes any compatible base URL
- `BlockstreamSource(base_url=...)` — defaults to blockstream.info
  but takes any compatible base URL
- `BitcoinCoreRpcSource` — works against any Bitcoin Core-style RPC
  (BCH's Bitcoin Cash Node has a compatible RPC surface)

mempool.cash uses a fork of mempool.space's API; its endpoint paths
should match. `MempoolSpaceSource(base_url="https://mempool.cash/api")`
or similar should work without code changes. **This is unverified;
the spike did not run live API calls. Verification is a Phase 2.1
deliverable.**

`MempoolSpaceSource.get_tx_output_script_type` maps API-reported
script types via:

```python
type_map = {
    "p2pkh": "p2pkh",
    "p2wpkh": "p2wpkh",  # never seen on BCH; harmless
    "p2sh": "p2sh",
    "p2tr": "p2tr",      # never seen on BCH; harmless
    "v0_p2wpkh": "p2wpkh",
    "v1_p2tr": "p2tr",
}
```

BCH responses will only return "p2pkh" or "p2sh" — both handled.

### Discovery 5: addresses are not a Gravity concern

The maker provides `btc_receive_hash` as raw bytes (20-byte hash160
for P2PKH/P2WPKH/P2SH, 32-byte for P2TR). The Gravity SDK does NOT
encode or decode the maker's counterparty-chain address. Address
encoding (base58 for BTC legacy, bech32 for BTC segwit, cashaddr for
BCH) is a wallet-side concern.

This means there's **no Gravity-side change needed** for cashaddr
support. A BCH user converts their cashaddr to hash160 in their
wallet and passes the hash160 to the SDK. Existing libraries
(`bitcash`, `cashaddress`, or hand-rolled) handle this trivially.

A nicety-feature would be to add a `pyrxd.address.cashaddr_to_hash160`
helper so callers don't need a separate library, but it's not
required for protocol-level BCH support.

## The chain-agnostic narrative is real

The deeper finding from these two spikes is that **the existing
Gravity stack was built more chain-agnostic than the docs let on.**
The output-type dispatch was unified into a single sentinel covenant
(P2PKH spike finding); the PoW verifier doesn't bake in BTC's
specific difficulty algorithm (this spike); the data-source layer
takes a configurable base URL (this spike). What looks like "BCH
support requires per-chain work" turns out to be "BCH support
requires testing the chain-agnostic code against BCH inputs."

This is good news both for BCH and for any future SHA-256d chain
(BSV, Bitcoin Gold's SHA-256d version, etc.). It is **not** good
news for non-SHA-256d chains (Litecoin/Dogecoin with Scrypt, ZEC
with Equihash) — those still need consensus extension or HTLC.

## What's actually missing for BCH support

A four-by-three matrix of "is this layer exercised for BCH?":

| Layer | BTC | BCH |
|---|---|---|
| Header PoW verification | ✅ mainnet | ✅ identical math; untested with BCH headers |
| Header chain linkage | ✅ mainnet | ✅ identical structure; untested |
| Merkle inclusion proof | ✅ mainnet | ✅ identical structure; untested |
| P2PKH payment verification | ✅ now tested (`TestGravityTradeP2PKH`) | ⚠️ untested with BCH-style txs |
| P2SH payment verification | ⚠️ unit-level only | ⚠️ unit-level only |
| Witness stripping (no-op for BCH) | n/a — segwit txs only | ✅ correctly no-ops on legacy txs |
| Covenant `btcReceiveType` dispatch | ✅ four-way | ✅ same dispatch, just used with type=0 |
| Data source (mempool.space-style API) | ✅ mempool.space | ⚠️ mempool.cash unverified |
| Data source (Bitcoin Core RPC) | ✅ btc-core | ⚠️ bch-node RPC unverified |
| Documentation as supported chain | ✅ docs/concepts/gravity.md | ❌ not mentioned |
| End-to-end integration test | ✅ `TestGravityTradeP2PKH` + others | ❌ none |
| Mainnet exercise | ✅ P2WPKH only | ❌ none |

## Suggested next work

The pattern from the P2PKH spike-followup commit applies almost
directly. Recommended sequence:

1. **Add a BCH end-to-end integration test** mirroring
   `TestGravityTradeP2PKH`. Use synthetic BCH-style P2PKH inputs.
   The fixture pattern (pre-mined PoW header with relaxed target,
   from `tests/fixtures/spv_synthetic_headers.json`) carries over;
   nothing about the fixture is BTC-specific. Test name:
   `TestGravityTradeBCH` in `tests/test_gravity_trade.py`.
2. **Add a small documentation update to `docs/concepts/gravity.md`**
   stating BCH is a supported counterparty chain. The Axis 2 table
   currently uses "Bitcoin" as if it were the only option; the doc
   should make explicit that the verifier is chain-agnostic for
   SHA-256d UTXO chains and BCH is the second supported one.
3. **Optional: add a `cashaddr_to_hash160` helper** if there's an
   ergonomic case for it. Defer to a follow-up if no immediate
   demand.
4. **Defer mainnet exercise** to Phase 3 — same as P2PKH/P2SH/P2TR
   mainnet exercise. Synthetic tests demonstrate code-level
   correctness; mainnet validation comes later.

What's **not** in scope:

- **Live API verification of mempool.cash**: defer to Phase 3 or
  to whoever actually needs to use it. The spike showed there's
  every reason to expect it to work; the test would be a 5-minute
  curl exercise when someone actually has a BCH integration use
  case.
- **BCH-specific difficulty validation**: the verifier doesn't do
  this for BTC either. Adding it would be a security upgrade for
  *both* chains, not a BCH-specific item, and belongs in a
  separate brainstorm.
- **Address encoding helpers**: nice-to-have, not required.

## A diagnostic note

The "diagnose before patching" rule applied here too:

- **Symptom** in the parent plan: "BCH support requires P2PKH
  covenants, chain-id parameter, BCH-specific tests."
- **Assumed mechanism**: each item is non-trivial; total estimate
  4-6 weeks.
- **Actual mechanism**: P2PKH already works (P2PKH spike); chain
  identification is a wallet-side concern (the SDK doesn't care
  which chain it's verifying); the only real new work is an
  integration test + a doc update.

Two spike investigations in a row have found that the parent
strategy plan overestimated the technical work by roughly 3-4×.
That's not a criticism of the original plan — it's the spike
pattern doing its job, exactly as the attack-plan brainstorm
predicted. The pattern is robust enough to expect it might apply
again in Phase 2.2 (HTLC hardening). When the next "this looks
like multi-week work" comes up, read the code first and estimate
after.

## Status

- BCH support spike: **complete; scope much smaller than parent
  plan assumed**.
- Suggested next pyrxd-side block: write the BCH integration test
  + add the doc update (~5-10 hours).
- The parent plan's Phase 2.1 budget shrinks substantially.
  Strategic implications (slack management, Phase 2.2 buffer)
  belong in the private strategy update, not here.
