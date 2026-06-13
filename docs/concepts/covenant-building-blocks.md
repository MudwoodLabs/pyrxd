# Covenant building blocks: tokens, covenants, and the REF gate as composable primitives

Radiant's genuinely differentiated capability is that a **UTXO's locking script can
inspect the transaction spending it** — output scripts, values, and induction-capable
token references (`refs`) — at consensus level. That lets you build *covenants*: outputs
that constrain what any future spend must look like, with no trusted server enforcing it.

pyrxd ships four covenant-grade building blocks, each proven against a real
`radiant-core` node and each usable on its own or composed with the others. This page is
the map; each section links the import, the contract, and the proof.

> **Pre-audit caveat (applies to all four).** These primitives are consensus-validated on
> regtest and several are proven on mainnet, but none has had an external security audit.
> Build and demo on regtest/testnet; do not gate real value on them yet.

## 1. HTLC covenants — lock RXD, an FT, or an NFT behind a hashlock + timelock

```python
from pyrxd import build_htlc_covenant_rxd, build_htlc_covenant_ft, build_htlc_covenant_nft
```

`pyrxd.gravity.htlc_covenant` builds the **funded covenant scriptPubKey** — the UTXO a
maker locks an asset into for an atomic swap. Two spend paths are baked into the script:
*claim* (present the preimage `p` of the negotiated hashlock; pays the taker's holder
script) and *refund* (after a consensus-enforced `OP_CHECKSEQUENCEVERIFY` maturity; pays
the maker). The three variants differ in how the asset binds:

| Variant | Asset binding |
|---|---|
| `build_htlc_covenant_rxd` | native RXD — no ref at all |
| `build_htlc_covenant_ft` | the FT's genesis ref + the FT `codeScriptHashValueSum` epilogue weld (token-amount conservation) |
| `build_htlc_covenant_nft` | the NFT singleton ref (`d8<ref>`) inside the compiled body |

The covenant pins `hash256(holder script)` for `output[0]`, so a claim/refund can only
pay the negotiated destination shape. Build-time guards run fail-closed: every push in
the assembled SPK is re-checked for `MINIMALDATA` minimality (a non-minimal push would
brick **both** spend branches on-chain — found the hard way, now impossible to ship).

**Proofs:** claim + CSV-refund proven on Radiant **mainnet** for all three variants;
consensus semantics (CSV maturity, holder-hash pinning, singleton conservation)
re-validated on the pinned regtest node in `tests/test_htlc_regtest_e2e.py`. These
covenants are exactly what `RadiantCovenantLeg` funds inside the
[cross-chain swap](../how-to/build-a-cross-chain-swap.md).

One consensus fact worth internalizing: **"exactly one NFT output" is covenant-enforced,
not consensus-enforced** — Radiant consensus permits *burning* a singleton (zero
carrying outputs). Any "the token must go somewhere" property is your covenant's job.

## 2. The soulbound NFT covenant — consensus-enforced non-transferability

```python
from pyrxd import build_soulbound_nft_covenant   # SoulboundNftCovenant result
```

`pyrxd.glyph.soulbound_covenant` builds an NFT whose locking script allows exactly two
futures: **recur into a byte-identical clone of itself** (same ref, same logic, same
immutable owner — enforced by `OP_INPUTINDEX OP_UTXOBYTECODE` vs `OP_0 OP_OUTPUTBYTECODE`
full-bytecode equality) **or be burned**. There is no transfer path; a clone with a
different owner is a different script and fails `OP_EQUALVERIFY` at consensus.

This matters because the ecosystem's existing "soulbound" support is **advisory only** —
an ordinary transferable NFT plus an off-chain check an honest wallet runs voluntarily.
A counterparty running its own software can move it freely. The covenant version is the
chain-side mechanism that makes a soulbound token usable as a *trust anchor* against an
adversarial counterparty (reputation, compliance, credentials). A covenant of this design
is live on mainnet; this builder's consensus behaviour (recur accepted / transfer
rejected / burn accepted) is pinned on the regtest node in
`tests/test_soulbound_covenant_regtest.py`.

## 3. The REF-authenticity gate — consensus enforces *uniqueness*, not *provenance*

```python
from pyrxd import verify_ref_authenticity   # async; RefAuthenticityIndexer/ResolvedRef in pyrxd.gravity
```

The sharpest lesson in the stack (audit finding R1, proven on a live node): a
consensus-valid singleton ref need **not** be a genuinely minted Glyph. Consensus only
requires output refs ⊆ input refs — a node will happily mine a covenant whose "NFT" ref
is a plain wallet outpoint. **A covenant cannot self-verify mint provenance.** Anyone
buying/swapping "the advertised asset" must resolve the ref off-chain.

`verify_ref_authenticity` makes that defense explicit and fail-closed: five bindings
against a trusted indexer's resolution — genesis outpoint == advertised ref (a ref is
the *genesis* outpoint, never the reveal txid), a real `gly` envelope, the agreed payload
hash, asset identity, and a minimum genesis confirmation depth (a shallow genesis can be
reorged out after you pay). It is `async` on purpose: a sync wrapper that forgot to await
the indexer would return a truthy coroutine and fail *open* — the exact catastrophe the
gate exists to prevent. The `SwapCoordinator` runs it as a hard pre-lock gate for every
FT/NFT swap.

## 4. Credential-bound swap gating — composing 2 + 3 into the swap

```python
from pyrxd.glyph.credential_binding import assert_soulbound_credential, verify_credential_binding
```

The blocks compose: a swap's `NegotiatedTerms.credential_ref` can require the
counterparty to hold a **soulbound credential** (block 2) whose authenticity is resolved
through the same indexer discipline as block 3 — giving an HTLC swap (block 1) a
consensus-anchored "only credentialed counterparties" gate. `tests/test_credential_binding.py`
pins the binding rules; the swap coordinator consumes it via `CredentialResolver`.

## Where everything lives

| Block | Import | Proof |
|---|---|---|
| HTLC covenants | `pyrxd` top level / `pyrxd.gravity.htlc_covenant` | mainnet claims + `test_htlc_regtest_e2e.py` |
| Soulbound covenant | `pyrxd` top level / `pyrxd.glyph.soulbound_covenant` | `test_soulbound_covenant_regtest.py` |
| REF gate | `pyrxd` top level / `pyrxd.gravity.ref_authenticity` | live-node R1 reproduction + unit suite |
| Credential binding | `pyrxd.glyph.credential_binding` | `test_credential_binding.py` |

Token *issuance* (the things these covenants hold) is covered by the tutorials:
[mint a Glyph FT](../tutorials/mint-a-glyph-ft.md),
[mint a Glyph NFT](../tutorials/mint-a-glyph-nft.md),
[dMint](../tutorials/mint-from-a-dmint-contract.md). The
[5-minute quickstart](../tutorials/quickstart.md) gives you a local chain to try all of
this on with zero real value.
