# Glossary

A flat, alphabetical lookup for Radiant and pyrxd vocabulary. Each entry
defines the term **as this codebase uses it**, not the general dictionary
sense — where pyrxd's meaning is narrower, stricter, or just different from
what you'd guess from Bitcoin/Ethereum experience, that's called out
explicitly. Entries are short on purpose: for the full story, follow the
citation into the source or the linked deep-dive page.

This page complements, rather than duplicates,
[troubleshooting common errors](../how-to/troubleshoot-common-errors.md)
(error text → cause → fix) and the concept pages linked throughout — read
those for depth; use this page to look something up mid-task.

---

## A

- **AUTHORITY** — a Glyph protocol type (`GlyphProtocol.AUTHORITY = 10`,
  [`src/pyrxd/glyph/types.py`](https://github.com/MudwoodLabs/pyrxd/blob/main/src/pyrxd/glyph/types.py))
  marking issuer-authority metadata. pyrxd **decodes and classifies** it
  (`_inspect_core.py`, `wave.py`) but ships no `prepare_authority_*` builder —
  you cannot mint one with pyrxd today.

## B

- **BIP32 / BIP39 / BIP44** — the three HD-wallet standards pyrxd implements
  directly: BIP32 (extended key derivation,
  [`src/pyrxd/hd/bip32.py`](https://github.com/MudwoodLabs/pyrxd/blob/main/src/pyrxd/hd/bip32.py)),
  BIP39 (mnemonic ↔ seed,
  [`src/pyrxd/hd/bip39.py`](https://github.com/MudwoodLabs/pyrxd/blob/main/src/pyrxd/hd/bip39.py)),
  BIP44 (the `m/44'/coin_type'/account'/change/index` path convention,
  [`src/pyrxd/hd/bip44.py`](https://github.com/MudwoodLabs/pyrxd/blob/main/src/pyrxd/hd/bip44.py)).
  See **coin_type** below for where Radiant wallets disagree on the path.
- **BURN** — a Glyph protocol type (`GlyphProtocol.BURN = 6`, `glyph/types.py`)
  for explicit token burns. Appears only in the enum and in covenant-script
  comments (`soulbound_covenant.py`) — **no burn builder exists** in pyrxd
  today; don't assume it's mintable.

## C

- **carrier value** — the photon amount sitting on a Glyph-bearing output. On
  a contract/anchor output (commit, dMint contract, mutable-companion NFT)
  it's a fixed minimal amount — Radiant consensus requires exactly 1 photon
  on these ([`docs/concepts/dmint-v1-deploy.md`](dmint-v1-deploy.md)). On an
  **FT** output the carrier value directly *is* the token amount: 1 photon =
  1 FT unit (see [Radiant FTs are on-chain](radiant-fts-are-on-chain.md)).
- **CBOR envelope** — the Glyph metadata wire format. pyrxd encodes it via
  `cbor2.dumps(..., canonical=True)` (RFC 8949 canonical form) and prepends a
  3-byte ASCII `"gly"` marker in the reveal scriptSig — the marker is *not*
  part of the CBOR bytes.
  ([`src/pyrxd/glyph/payload.py`](https://github.com/MudwoodLabs/pyrxd/blob/main/src/pyrxd/glyph/payload.py))
- **coin_type** — the third path element in BIP44
  (`m/44'/coin_type'/account'/...`). Radiant's ecosystem never agreed on one,
  so the **same seed produces different addresses in different wallets**.
  pyrxd's default is `512` (SLIP-0044), but three values are all live
  recovery paths:

  | coin_type | Used by |
  |---|---|
  | `0`   | Photonic ≤ v2.x (legacy), Electron-Radiant, Chainbow |
  | `512` | SLIP-0044 spec, Tangem, Photonic ≥ v3.0.0 |
  | `236` | pre-#14 pyrxd (BSV's coin type) |

  A zero balance after restoring a seed almost always means the wrong
  `coin_type` was derived, not lost funds — see
  [Recover funds across wallet paths](../how-to/recover-funds-across-wallet-paths.md).
- **commit / reveal** — the two-phase Glyph mint pattern. The **commit**
  transaction anchors a hash of the metadata CBOR on-chain; the **reveal**
  transaction spends the commit, pushes the actual CBOR bytes, and the
  covenant verifies the hash matches before producing the real `ft`/`nft`
  output. See [Glyph structures and terminology](glyph-structures-and-terminology.md)
  and [V1 dMint deploys](dmint-v1-deploy.md).
- **CONTAINER** — a Glyph protocol type (`GlyphProtocol.CONTAINER = 7`,
  `glyph/types.py`) for a collection. pyrxd ships a full builder,
  `prepare_container_reveal`.
- **contract_id** — the wallet-facing display form of a token's *deploy*
  outpoint: 64 hex chars (txid, display order) + 8 hex chars (vout,
  big-endian). **It identifies the token, not your holding of it** — pasting
  it into the inspect tool fetches the deploy transaction, not your
  transfer. See **genesis ref** and **outpoint** below, and
  [Glyph structures and terminology](glyph-structures-and-terminology.md)
  for the full identifier map (this is the single most common source of
  confusion in the protocol).
- **covenant** — a Radiant locking script that inspects the transaction
  spending it (output scripts, values, and refs) at consensus level, and so
  can constrain what any future spend must look like — with no trusted
  server enforcing it. pyrxd ships four covenant-grade primitives (HTLC
  RXD/FT/NFT, the soulbound NFT covenant, the REF-authenticity gate, and
  credential-bound swap gating); see
  [Covenant building blocks](covenant-building-blocks.md). All are
  regtest-validated and several mainnet-proven, but **none has had an
  external security audit** — build and demo, don't gate real value yet.
- **CSV refund** — the timeout branch of an HTLC covenant, gated by a
  consensus-enforced `OP_CHECKSEQUENCEVERIFY` on a relative-block count
  (`refund_csv`). Lets the funder reclaim the asset if the claim branch
  (preimage reveal) never happens.
  ([`src/pyrxd/gravity/htlc_covenant.py:371`](https://github.com/MudwoodLabs/pyrxd/blob/main/src/pyrxd/gravity/htlc_covenant.py))
  Radiant's CSV is block-consensus-enforced (`ConnectBlock`), but that
  safety rests on the *spending* transaction using v2 + `nSequence`
  correctly, not on the opcode alone.

## D

- **DAA modes** — the five difficulty-adjustment-algorithm modes a dMint V2
  contract can choose (`DaaMode` enum,
  [`src/pyrxd/glyph/dmint/types.py:90`](https://github.com/MudwoodLabs/pyrxd/blob/main/src/pyrxd/glyph/dmint/types.py)):
  `FIXED` (no retarget), `EPOCH` (retarget every N blocks, capped
  adjustment), `ASERT` (continuous retarget on a half-life), `LWMA` (linear
  weighted moving average), `SCHEDULE` (a baked ascending height→target
  table, max 10 entries). All five are byte-matched to canonical Photonic
  and mainnet-proven as of 0.9.0. **DAA modes are a V2-only concept** — V1
  dMint contracts (the only format that predates 0.9.0, and still the
  historically common one on mainnet) are always plain sha256d with no DAA
  at all. See [V1 dMint deploys](dmint-v1-deploy.md).
- **DAT** — a Glyph protocol type (`GlyphProtocol.DAT = 3`, `glyph/types.py`)
  for data storage. Like AUTHORITY, this is **decode/classify-only** in
  pyrxd — no builder ships for it.
- **dead-man's switch** — the independent watchtower process
  (`pyrxd-watchtower-deadman`) that watches the *tower's own* heartbeat file
  and pages the operator the instant it goes stale or absent. Answers "is
  the tower alive?" — a distinct question from **escalation monitor**
  below, which asks "is the operator alive?"
  ([`src/pyrxd/gravity/watch/deadman.py`](https://github.com/MudwoodLabs/pyrxd/blob/main/src/pyrxd/gravity/watch/deadman.py))
- **difficulty vs target** — **the sharpest trap in the dMint math; get this
  wrong and your ETA is off by 2³³.** A dMint PoW solution is valid iff a
  SHA256d digest's top 4 bytes are zero *and* the next 8 bytes (big-endian)
  are below `target`. Because `MAX_SHA256D_TARGET = 2**63 - 1 < 2**64`
  ([`src/pyrxd/glyph/dmint/types.py:63`](https://github.com/MudwoodLabs/pyrxd/blob/main/src/pyrxd/glyph/dmint/types.py)),
  that's exactly "the top **96** bits of the digest are below `target`" —
  the hit space is `2**96`, not `2**256`. So:
  - `p = target / 2**96`
  - **expected attempts** `= 2**96 / target`
  - `target_to_difficulty(target) = MAX_SHA256D_TARGET // target`
    ([`src/pyrxd/glyph/dmint/miner.py:385`](https://github.com/MudwoodLabs/pyrxd/blob/main/src/pyrxd/glyph/dmint/miner.py))
    is the **difficulty multiplier** — a completely different quantity.

  `MAX_SHA256D_TARGET / target` is low as an attempt estimate by a factor of
  `2**96 / MAX_SHA256D_TARGET ≈ 2**33`: at difficulty 1 it implies "1
  expected attempt" where the true mean is `2**33 ≈ 8.6 billion`. This is a
  documented, previously-real trap in this repo — see the warning docstring
  in [`src/pyrxd/glyph/dmint/estimate.py`](https://github.com/MudwoodLabs/pyrxd/blob/main/src/pyrxd/glyph/dmint/estimate.py)
  and `estimate_attempts()` for the corrected formula, with an executable
  cross-check in `tests/test_dmint_estimate.py`.
- **dMint contract** — a Radiant covenant output that gates fungible-token
  issuance behind proof-of-work: a miner spends the contract UTXO with a
  valid PoW solution, and the covenant re-emits the contract (if supply
  remains) plus a reward FT output. See
  [V1 dMint deploys](dmint-v1-deploy.md) and
  [V1 dMint mint mechanics](v1-mint-mechanics.md).
- **dust floor** — the historical flat minimum output value, **546 photons**
  (`DUST_THRESHOLD` / `DUST_LIMIT`,
  [`src/pyrxd/wallet.py:36`](https://github.com/MudwoodLabs/pyrxd/blob/main/src/pyrxd/wallet.py)).
  Still enforced as a cheap pre-check, but it is **not sufficient** for a
  time-critical HTLC spend: at Radiant's effective relay rate a ~266-byte
  claim needs on the order of 2,660,000 photons — about 4,900× the dust
  floor. See **min-relay fee** below and
  [threat-model.md S21](../threat-model.md).

## E

- **ENCRYPTED** — a Glyph protocol type (`GlyphProtocol.ENCRYPTED = 8`,
  `glyph/types.py`) for encrypted-content metadata, Photonic-compatible.
  pyrxd ships a dedicated module (`encrypted_content.py`) for the CBOR
  shape. See **TIMELOCK** below — TIMELOCK requires ENCRYPTED.
- **escalation monitor** — a third watchtower process
  (`pyrxd-watchtower-escalate`) that reads **`unacked_critical`** off the
  heartbeat and, once it has stayed nonzero past a time threshold, pages a
  *separate* channel from the tower's normal alerts. Answers "is the
  operator alive?" — fails closed on an absent, `-1`, or unrecognized
  heartbeat schema.
  ([`src/pyrxd/gravity/watch/escalation.py`](https://github.com/MudwoodLabs/pyrxd/blob/main/src/pyrxd/gravity/watch/escalation.py))

## F

- **FORKID** — the sighash flag bit `0x40` (`SIGHASH.FORKID`,
  [`src/pyrxd/constants.py:31`](https://github.com/MudwoodLabs/pyrxd/blob/main/src/pyrxd/constants.py)),
  combined into composite flags like `ALL_FORKID`, `SINGLE_ANYONECANPAY_FORKID`
  (RSWP's `0xC3`). Radiant's BIP143-style sighash requires it set; a
  signature computed without FORKID is simply invalid on Radiant.
- **free option** — the inherent economic property of the reveal-on-the-
  long-leg HTLC shape: once the maker claims the counter-leg (revealing the
  preimage `p`), *they* choose whether to also complete the Radiant leg or
  let it CSV-refund back to themselves at `t_rxd`, leaving the taker with
  **one-sided loss**. Documented as accepted residual risk in
  [threat-model.md S20](../threat-model.md) — "the inherent HTLC free
  option... not a pyrxd bug." Bounded (not eliminated) by the timelock
  margin, the reorg-finality gate, and value-scaled claim burial.
- **FT** — fungible token, one of the three Glyph token kinds
  (`GlyphProtocol.FT = 1`). A 75-byte locking script carrying a `GlyphRef`
  for the contract; spending it re-emits the contract with conservation
  enforced (amount in ≥ amount out). See
  [Radiant FTs are on-chain](radiant-fts-are-on-chain.md).

## G

- **gap limit** — how far pyrxd scans ahead for used addresses before
  stopping: **20 consecutive unused addresses** per chain (external and
  internal),
  [`_GAP_LIMIT = 20`](https://github.com/MudwoodLabs/pyrxd/blob/main/src/pyrxd/hd/wallet.py)
  in `src/pyrxd/hd/wallet.py`.
- **genesis ref** — a Glyph token's permanent on-chain identity: the
  **commit** outpoint, embedded directly in the reveal transaction's
  locking script (what `prepare_reveal` writes and what
  `extract_ref_from_{nft,ft}_script` reads back). **It is not the reveal
  txid.** This distinction shipped as a real bug: `glyph mint-nft` and
  `glyph deploy-ft` printed `<reveal_txid>:0` through 0.11.x, an identifier
  `transfer-nft` / `transfer-ft` could never resolve, because those commands
  look up tokens by the extracted (commit-outpoint) ref. Fixed in 0.12.0 —
  see the [CHANGELOG](https://github.com/MudwoodLabs/pyrxd/blob/main/CHANGELOG.md)
  `## [0.12.0]` entry "`glyph mint-nft` and `glyph deploy-ft` reported the
  wrong genesis ref." Any ref
  recorded from an older run should be re-read from the chain; the tokens
  themselves were always correctly formed. See also **contract_id** and
  **outpoint**, and
  [Glyph structures and terminology](glyph-structures-and-terminology.md)
  for the full identifier map.
- **GlyphRef** — the 36-byte wire encoding of a ref inside a locking script:
  reversed (little-endian, on-wire) 32-byte txid + 4-byte little-endian
  vout. The frozen dataclass lives at
  [`src/pyrxd/glyph/types.py:31`](https://github.com/MudwoodLabs/pyrxd/blob/main/src/pyrxd/glyph/types.py)
  (`txid`, `vout` fields; `to_bytes()` / `from_bytes()`). Contrast with
  **contract_id**, which is the same bytes in a different, human-readable
  display order.
- **griefing** — a counterparty who repeatedly opens swaps, lets the victim
  lock capital, then simply never locks their own leg. Nothing is stolen —
  it's pure inaction, so there's nothing to slash or even observe on-chain
  — but the victim's capital sits immobilized for the full timelock and
  they pay two on-chain fees for nothing. Documented as
  [threat-model.md S22](../threat-model.md), "Capital-lockup griefing — the
  accepted LIVENESS residual." **Deliberately not fixed with a bond or
  deposit** — see
  [the design decision](../solutions/design-decisions/griefing-is-a-liveness-residual-not-a-bond.md).
  pyrxd's swap stack defends *safety*, not *liveness*.

## H

- **hashlock** — the HTLC covenant's claim condition: a 32-byte value `H`
  such that presenting a `p` with `SHA256(p) == H` unlocks the claim branch.
  Field name `hashlock: bytes` throughout
  [`src/pyrxd/gravity/htlc_covenant.py`](https://github.com/MudwoodLabs/pyrxd/blob/main/src/pyrxd/gravity/htlc_covenant.py).
- **hashOutputHashes** — Radiant's one substantive deviation from Bitcoin
  SV's BIP143 sighash preimage: an extra 32-byte field inserted **before**
  `hashOutputs`, committing to each relevant output's value, script hash,
  and ref contents. This is what lets a covenant's spending signature
  commit to *other outputs'* refs, not just their scripts/values. See
  [Handle Radiant's BIP143 sighash quirks](../how-to/handle-radiant-bip143-quirks.md)
  and
  [`src/pyrxd/transaction/transaction_preimage.py:77`](https://github.com/MudwoodLabs/pyrxd/blob/main/src/pyrxd/transaction/transaction_preimage.py).

## I

- **induction** — Radiant consensus's requirement that any ref appearing in
  a transaction's **output** must also appear in one of its **inputs** — a
  ref must be "induced" forward before an output can carry it
  (`ReferenceParser::validateTransactionReferenceOperations` in
  Radiant-Core). The check is purely syntactic (byte-scans the raw locking
  script), which is why raw bytes that happen to look like a ref can
  trigger false "phantom ref" rejections. See
  [Covenant building blocks](covenant-building-blocks.md) ("induction-capable
  token references").

## M

- **margin** — see **t_btc / t_rxd** below; the minimum block gap between
  the two legs' timelocks that the swap coordinator enforces before the
  taker funds anything.
- **min-relay fee** — Radiant's relay policy is **per-kB, not flat**:
  `effective_minrelaytxfee` on the reference mainnet node is **0.10 RXD/kB**
  (the required fee is `ceil(size × rate / 1000)`,
  [`src/pyrxd/gravity/fee_policy.py:82`](https://github.com/MudwoodLabs/pyrxd/blob/main/src/pyrxd/gravity/fee_policy.py)).
  Critically, **Radiant supports neither RBF nor CPFP**: any mempool
  conflict is rejected outright (`txn-mempool-conflict`, no `bumpfee` RPC),
  and the miner selects purely on each transaction's own fee over its own
  size, so a high-fee child cannot rescue a low-fee parent. An under-fee'd
  time-critical claim or refund is therefore **unrepairable** — it squats
  on its inputs for up to `DEFAULT_MEMPOOL_EXPIRY` (8 hours) before they
  free up. Verified against `Radiant-Core` source and a live mainnet node;
  see [threat-model.md S21](../threat-model.md) for the full analysis and
  the pre-sizing control that exists instead.
- **MUT** — a Glyph protocol type (`GlyphProtocol.MUT = 5`, `glyph/types.py`)
  marking a mutable contract: metadata that can be rotated (`mod`) or whose
  issuance rights can be transferred (`sl`) without changing the
  `contract_id`. Full builder: `prepare_mutable_reveal`.

## N

- **NFKD normalization** — Unicode Normalization Form KD, which BIP39
  requires be applied to the mnemonic sentence and passphrase before they
  enter PBKDF2. pyrxd did **not** do this before 0.12.0; the fix is a
  **breaking change for wallets with a non-ASCII passphrase** — derived
  addresses change. Pass `normalize=False` to `HdWallet.load` /
  `from_mnemonic` / `discover` to recover the pre-0.12.0 seed and sweep to
  a conformant wallet; inert for ASCII passphrases (the overwhelmingly
  common case). See the
  [CHANGELOG](https://github.com/MudwoodLabs/pyrxd/blob/main/CHANGELOG.md)
  `## [0.12.0]` entry and
  [Recover funds across wallet paths](../how-to/recover-funds-across-wallet-paths.md).
  Code:
  [`src/pyrxd/hd/bip39.py:110`](https://github.com/MudwoodLabs/pyrxd/blob/main/src/pyrxd/hd/bip39.py).
- **NFT** — non-fungible singleton, one of the three Glyph token kinds
  (`GlyphProtocol.NFT = 2`). A 63-byte locking script with a singleton ref;
  the covenant enforces that the same ref cannot exist in two unspent
  outputs simultaneously.

## O

- **one-sided loss** — the swap outcome where the taker has funded their
  leg but the maker CSV-refunds the Radiant leg instead of completing —
  `SwapState.ONE_SIDED_LOSS_TAKER` in
  [`src/pyrxd/gravity/swap_state.py`](https://github.com/MudwoodLabs/pyrxd/blob/main/src/pyrxd/gravity/swap_state.py).
  The concrete result of the **free option** above being exercised.
- **`OP_PUSHINPUTREF`** and its variants — the opcode family Radiant adds
  for ref manipulation
  ([`src/pyrxd/constants.py:299`](https://github.com/MudwoodLabs/pyrxd/blob/main/src/pyrxd/constants.py)):
  `OP_PUSHINPUTREF` (`0xd0`, push a 36-byte ref and require it present in
  some input — what FTs use), `OP_REQUIREINPUTREF` (`0xd1`, assert a ref is
  present in an input without pushing it), `OP_DISALLOWPUSHINPUTREF` /
  `OP_DISALLOWPUSHINPUTREFSIBLING` (`0xd2`/`0xd3`, negative constraints),
  and `OP_PUSHINPUTREFSINGLETON` (`0xd8`, push a ref **and** assert
  singleton uniqueness — no other unspent output may carry the same ref;
  what NFTs use).
- **outpoint** — `txid:vout`; identifies one specific output of one
  specific transaction. See
  [Glyph structures and terminology](glyph-structures-and-terminology.md)
  for the full identifier walkthrough.

## P

- **photon** — the base (indivisible) unit of RXD. `1 RXD = 100,000,000
  photons`
  ([`PHOTONS_PER_RXD = 100_000_000`](https://github.com/MudwoodLabs/pyrxd/blob/main/src/pyrxd/gravity/fee_policy.py),
  `src/pyrxd/gravity/fee_policy.py:81`; the same ratio is used in
  `src/pyrxd/cli/format.py`). Radiant's equivalent of Bitcoin's satoshi.
- **PoW mint** — claiming a dMint contract by finding a valid
  proof-of-work solution. A V1 mint transaction's scriptSig carries a
  4-byte nonce plus two hashes that the covenant recombines and checks
  against the target — see **difficulty vs target** above and
  [V1 dMint mint mechanics](v1-mint-mechanics.md).
- **preimage `p`** — the 32-byte secret whose `SHA256(p)` equals a
  covenant's **hashlock**. Revealing `p` on one chain (in a witness, in
  calldata) is what lets it be scraped and reused to claim the paired leg
  on the other chain — the entire mechanism an HTLC atomic swap runs on.
- **premine** — an FT/dMint deploy where the entire declared supply is
  minted directly to the deployer's own output at `vout[0]` of the reveal,
  rather than released only through PoW mining. `pyrxd glyph deploy-ft`
  supports this; `premine_amount` sets that output's value 1:1 (1 photon =
  1 FT unit).

## R

- **ref / induction** — a "ref" is the 36-byte outpoint reference (see
  **GlyphRef**) embedded in a script via the `OP_PUSHINPUTREF` family. See
  **induction** above for the consensus rule governing where a ref may
  legally appear.
- **reroll** — in **V1** dMint mining, the OP_RETURN preimage field carries
  only a 4-byte nonce (a `2**32` search space), which at low difficulty can
  be exhausted with no hit. A "reroll" mutates that OP_RETURN field and
  restarts a fresh `2**32`-nonce sweep, up to a configurable
  `--max-rerolls` (default 40). Because attempts-to-first-hit is geometric
  (memoryless), partitioning the hash stream into `2**32`-chunks via reroll
  doesn't change the total-attempts distribution — it's a mechanical
  workaround for V1's narrow nonce field, not a different probability
  model. **V2's 8-byte nonce field doesn't need it.**
- **RSWP** — the on-chain swap-order wire format: an `OP_RETURN` output
  whose first push is the ASCII marker `RSWP`, not a special script
  template. pyrxd ships `pyrxd.swap.rswp` (post/take/cancel/browse). The
  orderbook is **experimental** and the swap stack remains **unaudited**.
  See [the RSWP wire format spec](../swap-order-wire-format.md).

## S

- **scripthash** — ElectrumX's addressing scheme for non-address scripts:
  reverse the raw locking script's SHA256 digest bytes, hex-encode. Needed
  for looking up the history of anything that isn't a plain P2PKH output —
  e.g. finding the reveal that spent a Glyph commit output.
  [`script_hash_for_script()`](https://github.com/MudwoodLabs/pyrxd/blob/main/src/pyrxd/network/electrumx.py)
  in `src/pyrxd/network/electrumx.py`.
- **SPV** — Simplified Payment Verification: proving a signed/broadcast
  transaction is actually included in a block, without running a full
  node. See
  [Verify an SPV proof](../how-to/verify-an-spv-proof.md) and
  [SPV verification pitfalls](../how-to/spv-verification-pitfalls.md) for
  the common ways to get this wrong.

## T

- **`t_btc` / `t_rxd`** — the two legs' timelocks in a cross-chain HTLC
  swap. `assert_timelock_margin(t_btc, t_rxd, policy)` enforces
  `t_btc - t_rxd >= margin` (both normalized to blocks) **before the taker
  funds anything**
  ([`src/pyrxd/gravity/swap_coordinator.py:475`](https://github.com/MudwoodLabs/pyrxd/blob/main/src/pyrxd/gravity/swap_coordinator.py)).
  The direction matters: it's what stops a maker from setting too-tight a
  BTC refund (or too-loose an RXD refund) and creates the race window a
  malicious maker could otherwise exploit. See
  [Build a cross-chain atomic swap](../how-to/build-a-cross-chain-swap.md).
- **TIMELOCK** — a Glyph protocol type (`GlyphProtocol.TIMELOCK = 9`,
  `glyph/types.py`, requires **ENCRYPTED**) for a timelocked reveal: the
  mint commits `sha256(content_encryption_key)` plus an unlock height, and
  a later reveal transaction publishes the key via OP_RETURN once that
  height passes.

## U

- **`unacked_critical`** — a field on the watchtower's heartbeat: the count
  of still-unacknowledged CRITICAL-severity pages (the tower keeps
  re-paging these until an operator ACKs them). This is exactly the signal
  the **escalation monitor** watches to decide whether the operator, not
  just the tower, is still alive.
  ([`src/pyrxd/gravity/watch/alerts.py`](https://github.com/MudwoodLabs/pyrxd/blob/main/src/pyrxd/gravity/watch/alerts.py))

## W

- **WAVE** — a Glyph protocol type (`GlyphProtocol.WAVE = 11`,
  `glyph/types.py`) for on-chain naming, Photonic-compatible. Requires
  `[NFT, MUT, WAVE]` together; pyrxd ships a dedicated `wave.py` module with
  a full `prepare_wave_reveal` builder.
- **watchtower** — the persistent monitoring loop
  (`pyrxd.gravity.watch`) that watches BTC and ETH counter-legs for
  in-flight swaps and pages an operator on anomalies. **Alert-only by
  default** — it holds no value key and never touches the preimage `p`
  unless separately armed (see the **free option** entry above for the one
  autonomous, keyless, dust-capped exception). See
  `src/pyrxd/gravity/watch/README.md`.
- **WIF** — Wallet Import Format, the base58check-encoded serialization of
  a single private key (network prefix + key bytes + optional compression
  flag byte). `PrivateKey.wif()` in
  [`src/pyrxd/keys.py:189`](https://github.com/MudwoodLabs/pyrxd/blob/main/src/pyrxd/keys.py).

## X

- **xprv / xpub** — BIP32 extended private/public keys (`Xprv` / `Xpub` in
  [`src/pyrxd/hd/bip32.py`](https://github.com/MudwoodLabs/pyrxd/blob/main/src/pyrxd/hd/bip32.py)).
  `pyrxd wallet export-xpub` prints the **account-level** xpub (at
  `m/44'/<coin_type>'/<account>'`) for watch-only address generation —
  never the seed, never a private key.

---

## See also

- [Glyph structures and terminology](glyph-structures-and-terminology.md) —
  the deep dive on `txid` / `outpoint` / `GlyphRef` / `contract_id` and the
  output-type shapes the inspect tool reports.
- [Covenant building blocks](covenant-building-blocks.md) — the four
  covenant-grade primitives as composable building blocks.
- [Troubleshoot common errors](../how-to/troubleshoot-common-errors.md) —
  error text → cause → fix, for when something has already gone wrong.
- [Recover funds across wallet paths](../how-to/recover-funds-across-wallet-paths.md) —
  the `coin_type` mismatch recovery recipe.
- [Broadcast a transaction](../how-to/broadcast-a-transaction.md) — common
  rejection strings, including the min-relay-fee one.
- [Threat model](../threat-model.md) — S20 (free option), S21 (min-relay
  fee / no RBF/CPFP), S22 (griefing), and the rest of the numbered threats
  referenced above.

If a term you needed isn't here, it's more likely an oversight than a
deliberate omission — open an
[issue](https://github.com/MudwoodLabs/pyrxd/issues).
