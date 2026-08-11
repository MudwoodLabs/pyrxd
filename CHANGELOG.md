# Changelog

All notable changes to pyrxd are documented here. Format based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Two consensus-level defects, both found by putting builders that had never seen a node to
a Radiant Core v3.1.1 regtest one.

### Fixed

- **`prepare_mutable_reveal` / `prepare_wave_reveal` emitted a reveal no node would accept.**
  Both output scripts carried the *same* 36-byte ref under `OP_PUSHINPUTREFSINGLETON`, and
  a transaction may not have two outputs claiming one singleton ref — `CScript::GetPushRefs`
  files a `0xd8` ref into `foundDisallowedSiblingRefs` as well as the push-ref set. Every MUT
  and WAVE reveal built as the docstring described was rejected with
  `bad-txns-inputs-outputs-invalid-transaction-reference-operations`, since 0.9.0. No MUT or
  WAVE token could be minted at all. Nothing was at risk of loss — the reveal never reached
  the chain and the commit output stayed spendable — but the two builders were unusable.

  The contract's own body settles what the right ref is: it recomputes the token ref as
  `mutable_ref.vout - 1` (`OP_DUP 20 OP_SPLIT OP_BIN2NUM OP_1SUB OP_4 OP_NUM2BIN OP_CAT`), so
  the pairing is chain arithmetic, not convention. `prepare_mutable_reveal` now gives the
  contract `commit_txid:(commit_vout + 1)` and returns it as `MutableRevealScripts.mutable_ref`.
  The reveal accordingly needs **two inputs** — the commit outpoint and a plain seed output one
  vout along, whose spend is what lets an output push the contract's ref. This matches Photonic
  Wallet (`packages/lib/src/mint.ts`). Node-proven end to end, including a `mod` mutation that
  installs a new payload hash: `tests/test_mut_wave_regtest_e2e.py`.

- **The BIP143 preimage's ref walker desynchronised on `OP_REQUIREINPUTREF`.**
  `hashOutputHashes` hashes each output's push-ref set, and `_get_push_refs` collected the
  right two opcodes (`0xd0`, `0xd8`) but walked only those two. `OP_REQUIREINPUTREF` (`0xd1`),
  `OP_DISALLOWPUSHINPUTREF` (`0xd2`) and `OP_DISALLOWPUSHINPUTREFSIBLING` (`0xd3`) carry a
  36-byte immediate operand as well (`GetScriptOp`); skipping one as a bare opcode resumed the
  walk inside the ref bytes and read them as opcodes. Measured over 2,000 random refs on a
  Photonic-shaped auth script, that produced the wrong ref set **1,606 times**, raised 20 times,
  and was accidentally right 374 times — so pyrxd could not reliably sign *any* transaction with
  an output carrying one of those three opcodes, and the node rejected it with
  `mandatory-script-verify-flag-failed (Signature must be zero for failed CHECK(MULTI)SIG
  operation)`. Nothing pyrxd itself builds emits them today, so no shipped path was affected;
  paying to a Photonic authority token, a delegate-burn output, or the auth-shaped token a MUT
  mutation requires was. The walker now consumes all five operands and collects two, from the
  single shared `pyrxd.constants.REF_OPERAND_OPCODES` that `pyrxd.glyph.script.REF_OPCODES` now
  aliases — one definition, two consumers.

### Added

- **Live-node consensus proofs for four builders that had none.** Each was covered only by
  offline tests, which re-hash a builder's own output and agree with it — a closed loop that
  cannot answer whether a node accepts the bytes. All four are now exercised against real
  regtest consensus, asserting on confirmed on-chain state rather than on return values, and
  every case carries a negative control whose rejection reason is asserted by name.

  - `tests/test_cold_recovery_regtest_e2e.py` — `build_cold_claim` / `build_cold_refund`
    (the offline swap-recovery toolkit shipped in 0.14.0). The claim is **mined**, spends the
    covenant, and pays the pinned taker holder script; redirecting `output[0]` at an attacker
    and substituting a wrong preimage are both refused. The CSV refund's **same bytes** are
    walked across the timelock boundary one block at a time — refused at 1 and 2
    confirmations, accepted at 3 — then mined, with `version == 2` and the covenant input's
    `nSequence` carrying the lock. A genuinely 0-conf covenant (funding invalidated back into
    the mempool) is refused, which is the audit-B5 fix measured against real chain state.
  - `tests/test_gravity_maker_offer_regtest_e2e.py` — `build_maker_offer_tx`. The offer
    transaction confirms, the mined output is byte-equal to `P2SH(offer_redeem)`, and the
    offer is then **taken** on chain by `build_claim_tx`. Controls: raising the offer output
    by one photon after signing, and a stranger attempting the take.
  - `tests/test_btc_payment_regtest_e2e.py` — `build_payment_tx` on bitcoind regtest. Both
    input types (P2WPKH and P2SH-P2WPKH) and all four destination types confirm; change
    returns to the sender's own script; sub-dust change is really swept into the fee (one
    output on chain). Controls: a payment amount raised by one satoshi after signing, and a
    wrapped-segwit UTXO spent as native.

  The Radiant relay floor is measured at the boundary rather than assumed: a fee input worth
  exactly `ceil(size x rate / 1000)` photons is accepted and one photon less is rejected with
  `min relay fee not met`, confirming `DeadlineFeePolicy.min_relay_fee` reproduces the node's
  own arithmetic against `GetTotalSize`. Because the fee value is part of the sighash, the
  boundary value is searched for — a fixed-point iteration can two-cycle between adjacent DER
  signature lengths.

### Documented

- **`build_maker_offer_tx` and `build_payment_tx` enforce no relay-fee floor**, unlike
  `pyrxd.gravity.htlc_spend`, which refuses to return an under-fee'd spend. Both take
  `fee_sats` on trust and return a fully-populated result — plausible `txid`, plausible
  accounting — for a transaction no node will relay. Measured: a 190-byte maker-offer
  transaction at `fee_sats=10_000` (the value the offline suite uses throughout) is rejected
  with `66: min relay fee not met` against a node floor of 190,000 photons, and 1,900,000
  photons at the reference mainnet node's effective rate. Radiant has neither RBF nor CPFP,
  so the funding UTXO is then stuck until the 8h mempool expiry. Both behaviours are now
  pinned by a test that says so; neither builder was changed.
Plain RXD sends — the most-used path in the SDK — had never been put to a node. Every test
covering `RxdWallet.build_send_tx` and `build_send_max_tx` asserted on the builder's own
return value, which is the one witness that cannot tell a working transaction from a
plausible-looking one. Handing them to a Radiant Core v3.1.1 regtest node found a defect in
both.

### Known issues

- **Both send builders can emit a transaction below the relay floor.** The fee is sized from
  a *trial* signing pass (`src/pyrxd/wallet.py:244-247` for `build_send_tx`,
  `295-302` for `build_send_max_tx`) and the final signed transaction is never re-measured.
  The final pass signs over different outputs, so it produces a different DER signature —
  71 or 72 bytes, split roughly evenly — and whenever the final signature is the longer one
  the transaction contains more bytes than its fee paid for.

  Measured over 2,000 builds per shape at the default rate: **27.1%** of one-input sends,
  **34.5%** of three-input sends and **31.6%** of two-input sweeps land short by at least one
  byte. `DEFAULT_FEE_RATE` is 10,000 photons/byte, which is *exactly* the mainnet relay floor,
  so on mainnet a shortfall of one byte is a rejection. A regtest node built at its own
  advertised floor refuses these with `66: min relay fee not met`.

  Radiant has neither RBF nor CPFP, so an underpaid transaction cannot be repaired — it is
  abandoned, or it holds its inputs until mempool expiry on any node whose floor let it in.
  `build_send_max_tx` is the worse case of the two: a sweep has no change output to absorb an
  adjustment, and the caller has been told this is their whole balance.

  Not fixed here. The fix is to re-measure after the final signing pass and rebuild if the
  size grew, which changes fee arithmetic and belongs in its own reviewed change. The
  invariant is recorded as a `strict=True` xfail
  (`test_every_send_pays_at_least_the_rate_it_was_built_for`) so a fix turns that test into a
  failure and the marker gets removed rather than outliving the bug.

### Tests

- **`tests/test_wallet_send_regtest_e2e.py`** — live-regtest consensus coverage for
  `build_send_tx` and `build_send_max_tx`, the two builders that had no node-level proof
  anywhere in the suite. Every assertion reads a *confirmed* transaction or the node's own
  UTXO set (`scantxoutset`), never the builder's return value. 15 passed, 1 xfailed.

  Proven: an ordinary send with change lands the requested amount and returns the rest;
  **the change output is spendable** (re-spent by a second builder call and confirmed — the
  0.15.0 CONTAINER defect was an unspendable output that looked perfect from Python);
  greedy selection spends exactly the coins it selected and leaves the rest unspent;
  `send_max` empties the source script's UTXO set with nothing stranded; the fee reported by
  the builder equals the fee the chain took at one, two and three inputs; sub-546 change is
  burned to fee as a *pyrxd policy* choice, and a 1-photon output relays, confirming
  `DUST_THRESHOLD` is a send policy and not a chain rule.

  Each case carries a negative control quoting the node's reject reason: an output mutated
  after signing →
  `16: mandatory-script-verify-flag-failed (Signature must be zero for failed CHECK(MULTI)SIG operation)`;
  re-signed outputs exceeding inputs → `16: bad-txns-in-belowout`; a stranger's key over the
  wallet's coin →
  `16: mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation)`;
  a below-floor fee → `66: min relay fee not met`.

  Opt-in like the other e2e suites (`@pytest.mark.integration` + `RADIANT_REGTEST=1`), reusing
  the throwaway-container fixture from `test_htlc_regtest_e2e`. Regtest only; moves no real
  value.
- `tests/test_mut_wave_regtest_e2e.py` — live-regtest consensus proof for the MUT and WAVE
  reveals: the rejected pre-fix shape, the ref arithmetic read off a confirmed transaction,
  discovery through `find_glyphs`, an NFT output spent onward, a `mod` mutation with two
  negative controls on the covenant's binds, the signing regression above, and WAVE name
  recovery from the confirmed envelope.
- `tests/test_ft_transfer_regtest_e2e.py` — live-regtest consensus proof for
  `FtUtxoSet.build_transfer_tx`: a 250-unit transfer out of a 100,000,000-unit holding
  delivering exactly 250 (the shape of the old balance-draining sizing bug), unit conservation,
  the recipient spending onward, the whole-balance boundary, an inflating transfer rejected by
  consensus, and the no-RXD-funding refusal.

## [0.15.0] — 2026-08-11

Collections work, and the feature that claimed to build them is gone.

`prepare_container_reveal(child_ref=...)` has shipped since 0.9.0. Put to a Radiant Core
v3.1.1 regtest node before building the routing it was missing, it turned out to have two
defects the Python side could not see:

- **The output could not be spent by anyone.** The ref push is never dropped, so the P2PKH
  tail's `OP_DUP OP_HASH160` operated on the ref instead of the pubkey. The failing item is
  pushed by the *locking* script, so no scriptSig can rescue it.
- **Creating one destroyed the child token, permanently.** `OP_PUSHINPUTREFSINGLETON` files
  its ref into `foundDisallowedSiblingRefs` as well as the push-ref set
  (`Radiant-Core/src/script/script.cpp:601-606`), so no other output of the same transaction
  may carry that ref. The only form the node accepts consumes the child without re-creating
  it.

Naming an FT instead fails the FT epilogue. So a **script-level link between a container and
a live token is impossible on Radiant** — not unimplemented, impossible — and anyone who
called that builder burned the token they were adding to a collection. The parameter now
raises, naming the reason and the replacement.

Collections instead use the model Photonic already uses: a container is an ordinary 63-byte
NFT, and membership lives in the child's envelope. That makes it classify, scan, and transfer
through code paths that already existed.

Also: the six cross-chain integration suites now fund the maker's covenant before the taker
locks, matching the taker-side gate added in 0.14.0 — all six run green against live regtest
nodes. `web3`, required by five of them and declared nowhere, is now a declared test
dependency. The external-audit scoping brief is current, and the threat model no longer
describes an advisory SPV control as if it enforced.

### Fixed

- **`web3` was required by five integration suites and declared nowhere**, so
  `tests/test_xchain_eth_*.py` ran only if a developer happened to have it installed and
  silently skipped otherwise. It is now declared in the `test` dependency group.

  Declaring it exposed a real conflict: every `web3` 7.x caps `websockets<16.0.0`, while
  pyrxd required `websockets>=16.1.1`. **The floor was not load-bearing.** 0.2.0 deliberately
  widened this same constraint to `>=15.0.1`, recording that pyrxd uses only the stable
  websockets API (`connect`/`send`/`recv`/`close`/`WebSocketException`) common to versions 13
  through 16, and that a narrow floor "locked out coexistence with libraries pinned to
  `websockets <=15.0.1`". A routine dependency-floor raise in #343 silently reverted that
  decision, and web3 became the library it locked out.

  The floor is restored to `>=15.0.1,<17.0.0`, now with the reason recorded in `pyproject.toml`
  so the next floor bump does not repeat it. This is not a security regression: both websockets
  advisories in OSV are fixed far below the floor (GHSA-6g87-ff9q-v847 in 5.0,
  GHSA-8ch4-58qp-g3mp in 9.1). Verified by installing pyrxd, `web3` 7.16.0 and
  `websockets` 15.0.1 into one environment — the combination resolves, all three import, and
  the network suite passes (235 tests).

### Removed

- **`GlyphBuilder.prepare_container_reveal(child_ref=...)` — breaking-class, fund-safety.**
  Passing `child_ref` now raises `ValidationError`. From 0.9.0 through 0.14.0 it prefixed the
  NFT body with `OP_PUSHINPUTREF <child_ref>` and produced a 100-byte output. That output was
  **permanently unspendable**: the ref push is never dropped, so the P2PKH tail ran
  `OP_DUP OP_HASH160` over the ref instead of the pubkey and `OP_EQUALVERIFY` failed for every
  possible scriptSig — the failing item comes from the *locking* script, so no unlock could
  change it. Worse, the only way to create one at all was to **consume the child NFT's
  singleton ref without re-creating it**: `OP_PUSHINPUTREFSINGLETON` registers its ref as a
  disallowed sibling, so the child cannot survive the transaction that names it, and a
  singleton consumed into a `0xd0` push never re-enters `inputSingletonRefSet` and can never
  be minted again. Building a "collection" this way silently destroyed the token being added
  to it and burned the carrier photons on the container.

  Both failures are proven against a Radiant Core v3.1.1 regtest node in
  `tests/test_container_regtest_e2e.py`, with the node's reject reasons recorded in
  §17.1 of the protocol specification. No mitigation is possible for an output already
  created this way — it cannot be spent. `is_legacy_container_script` /
  `parse_legacy_container_script` exist so such an output is *identified* rather than
  reported as `unknown`.

### Added

- **CONTAINER (collection) tokens work end to end.** A container is an ordinary NFT — the
  plain 63-byte singleton, container-ness carried by the `7` marker in the envelope — which
  is Photonic Wallet's model and what makes it routable by every existing code path: it is
  classified by `find_glyphs`, surfaced by `GlyphScanner`, and moved by `build_nft_transfer_tx`
  with no special case. `GlyphMinter.commit_nft` now accepts a CONTAINER instead of refusing
  it — it was listed as an unsupported reveal shape purely because of the removed child-ref
  prefix. (`pyrxd glyph mint-nft` builds through `GlyphBuilder` directly and never refused
  one; what changes there is that `glyph init-metadata --type container-nft` now writes
  Photonic's `type: "container"` rather than `"collection"`, which Photonic renders as a plain
  object.)
- **Collection membership in the envelope: `GlyphMetadata.container_refs` / `.author_refs`**,
  encoded as the Glyph `in` / `by` fields. Refs are 36-byte byte strings in the same wire form
  the locking script uses, which is what lets a reader check a claim; CBOR tag 64-wrapped
  entries are accepted on decode. This also closes a decode gap: `by` refs on real mainnet
  tokens were previously discarded.
- **`GlyphBuilder.prepare_container_child_reveal`** builds the reveal that mints a token into
  a collection — the child NFT plus a byte-identical re-creation of the container UTXO, so the
  container's ref appears among the reveal's output refs and the membership claim is
  checkable rather than merely asserted (the condition Photonic's indexer applies). It refuses
  an envelope whose `in` does not name the container.
- `GlyphNft.is_container` / `.container_refs` / `.author_refs`, and `GlyphMetadata.is_container`.
- `GlyphOutput.spendable` and `GlyphOutput.child_ref`; `_inspect_script` reports
  `type: "container-legacy"` with the reason it cannot be spent. `GlyphScanner` logs and skips
  such an output instead of returning it as a transferable token.
- Frozen golden vectors pinning the container locking script and the `in` envelope bytes, so
  the removed prefix cannot return unnoticed (`tests/test_golden_vectors.py`).

### Documentation

- **The threat model no longer claims the SPV sole-authority gate fails closed.**
  `require_spv_sole_authority_cleared` has returned unconditionally since 0.9.0 — a deliberate
  choice matching the project's posture that audit gates warn rather than hard-block. Three
  places still described it as enforcing, which is the more dangerous direction of drift for a
  document an external auditor reads: a covenant-less SPV use is restrained by documentation,
  not by code, and the caller carries that obligation. Gap #7 also predated
  `network/tls_pin.py`; TLS pinning now exists, opt-in and off by default, so the residual
  stands only for operators who have not configured pins.

### Fixed

- **The six `-m integration` cross-chain end-to-end suites now fund the maker's covenant before
  the taker locks, and pass.** 0.14.0 closed hazard **HZ-1** by making the taker verify the maker's
  Radiant covenant on chain before locking its counter leg, and recorded that these suites still
  used the pre-HZ-1 order and would have to be reordered — deferred at the time because they need
  live bitcoind/radiantd/anvil nodes and editing adversarial tests one cannot watch go red or green
  is its own failure mode. They have now been reordered *and run*.

  In every suite the maker's covenant is funded and mined first, so the taker's gate
  (`pre_btc_lock_check` step 5, re-run inside `taker_funds_btc`) runs against a genuinely funded,
  sufficiently-buried covenant instead of an empty scriptPubKey. This is the order
  `scripts/btc_swap_two_host.py` always used. The reorder is Radiant-height-neutral — neither the
  BTC nor the ETH counter leg mines Radiant blocks — so every CSV-maturity and window-closing
  computation in these tests is unchanged.

  Two adversarial scenarios changed shape, both toward a stronger assertion, neither weakened:

  - **S3 (hostile maker funds a decoy covenant)** now proves *two* independent layers: the pre-lock
    gate refuses to fund the ETH leg at all while only the decoy exists — so the taker locks nothing
    rather than locking and waiting out a timeout — and then, once the maker also funds the agreed
    covenant, `post_asset_lock_revalidate` still returns `PARAMS_MISMATCH` when the maker *reports*
    the decoy SPK.
  - **S6 (counterparty lies about having locked)** is now caught before the taker locks rather than
    after, so the lie costs the taker nothing at all. The later revalidate layer it used to exercise
    is still covered by S3 layer B and by `tests/test_swap_coordinator.py`.

  Every other scenario keeps its original premise: a maker that stalls, griefs, times a reveal
  against a closing window, or actively claims to publish `p` must still *lock its asset* — that was
  always true of a real attacker, and it is what makes those attacks griefs rather than outright
  theft.

- **Three pre-existing failures in those suites, unrelated to lock ordering**, surfaced once the
  suites could run far enough to reach them. All three predate this change and were invisible only
  because these suites sit outside default CI:

  - **A stale watchtower dedup assertion** in the BTC and ETH e2e suites required that a repeated
    `PAGE_CLAIM` *not* re-page. `DedupAlerter` has deliberately re-paged a CRITICAL situation on a
    tick-count backoff since #239 — so a single missed page cannot silently lose funds — and
    `tests/test_watch_alerts.py::test_critical_intent_repages_each_tick_by_default` asserts exactly
    that. The assertion was written in #168, before the behaviour existed; it now matches the
    contract.
  - **The real-RXinDexer Glyph suite never opted in to `accept_estimated_eth_margins`.** The
    MEDIUM-1 guard added in #192 refuses a value-bearing ETH counter leg under an estimated margin
    policy; the sibling ETH e2e was updated then, this suite was not, so it has failed at
    `SwapCoordinator` construction ever since — before reaching any swap step.
  - **`web3` is required by five of these suites but declared in no dependency group**, and the
    version that resolves (`web3` 7.16.0) caps `websockets<16.0.0` while pyrxd itself requires
    `websockets>=16.1.1`. The suites that only need anvil are unaffected, but the Glyph suite also
    drives pyrxd's ElectrumX client and fails to connect under the lower pin. Left undeclared here
    rather than papered over: the conflict is real and wants a dependency decision, not a test edit.
### Documentation

- **The external-audit scoping brief is brought current to 0.14.0**
  (`docs/security-audit-scope.md`). It had not been revised since 2026-06-20 (pre-0.10.0), so
  the residual register was missing threat-model **S21–S24** entirely and still described the
  threat model as "S1..S19 + R1". The revision reconciles the register against
  `docs/threat-model.md` (now S1..S24) and re-verifies every carried-forward claim against the
  code rather than against prior prose. Substantive corrections beyond the four new scenarios:

  - **Scope table updated for five releases of new attack surface**: both counterparty-funding
    gates in `SwapCoordinator`, `gravity/fee_policy.py`, the offline/cold recovery toolkit
    (`cli/swap_recovery.py`), the ElectrumX registry/failover/SPKI-pinning stack
    (`network/registry.py`, `failover.py`, `tls_pin.py`), `hd/descriptor.py`, the two-phase
    Glyph minter, FT airdrop + royalty, dMint deploy-with-premine, the RSWP orderbook, the
    handshake wire-format + Glyph protocol specs with their conformance vectors, and the
    watchtower entrypoints that now ship in the wheel.
  - **Stale register entries corrected against the code**: `KEY-COINTYPE-LOAD` (the load path
    now requires and pins the persisted coin type — was "open"), `GLYPH-DUAL-WALKER` (single
    consensus-correct `REF_OPCODES`, differential-locked — this was the live 0.14.0 panel
    finding), `GLYPH-PARSER-FUZZ` (atheris harnesses + a weekly lane exist — was "not yet
    fuzzed"), `NET-TLS-PINNING` (opt-in SPKI pinning shipped — TM gap #7 wording predates it),
    `WATCH-STALLTRACKER` (now wired per-swap in `watch/quorum.py`), `DMINT-V2-GOLDEN` (mainnet
    anchors now cover FT/NFT/commit/envelope/V1/V2-FIXED; LWMA deliberately unpinned), and
    `SPV-SOLE-AUTHORITY` (the sole-authority "gate" is an advisory no-op as of 0.9.0 — the
    covenant nBits pin is the defense; the threat model's "fails closed" wording is flagged as
    stale). The earlier "SBOM now ships" claim is corrected: generation silently failed from
    v0.9.0 through 0.11.1, and 0.11.2 was the first release to attach one.
  - **New sections an auditor needs**: what is and is not proven (the Radiant HTLC leg and
    dust-value cross-chain swaps are real; every run so far is single-operator — the two-party
    adversarial run has NOT happened); where internal review has actually found fund-safety
    bugs (the 0.14.0 eight-reviewer panel's four findings, all pre-existing, none in the
    release diff — diff review would not have found any of them); and the known-open items at
    0.14.0 (the six `-m integration` suites red pending the HZ-1 reordering, the unroutable
    CONTAINER-with-child-ref, the versionless handshake, lossy envelope decode, and the
    non-canonical creator-signature encoding) so the audit does not spend budget rediscovering
    them.

  `tests/test_residual_register_traceability.py` machine-checks that every code/test path the
  revised register cites exists.

- [Create a token collection](docs/how-to/create-a-token-collection.md) — new how-to.
- Glyph token protocol specification revised to revision 2: §7.5 rewritten (including *why*
  a script-level container→child link is impossible on Radiant), `in` / `by` documented in
  §4.3, §16.2 retired, and §17.1 added with the regtest reject reasons.

## [0.14.0] — 2026-08-10

Specifications, token issuance, and the security work that writing the specifications
caused.

The headline additions are ecosystem-facing: a **normative Glyph token protocol
specification**, a **cross-chain HTLC handshake wire format** with conformance vectors, and
**output-script descriptor export** for watch-only import. Alongside them, multi-recipient FT
airdrop, dMint deploy-with-premine, an offline swap-recovery toolkit, and an ElectrumX
registry with request-level failover and optional TLS pinning.

The larger part of this release is corrections, and most of them were found by writing the
specs and by an eight-reviewer pre-release audit rather than by ordinary review of the diff.
Several predate this release entirely:

- **`glyph transfer-ft` could send the wrong number of FT units** — up to the sender's whole
  balance. An FT output's value *is* its unit count, and the recipient output was sized from
  the inputs' RXD rather than from the requested amount. The first fix was a tripwire on one
  input shape and the loss was still reachable one photon either side of it; transfers are now
  sized from the amount by construction.
- **The ref-opcode walker diverged from Radiant consensus on `0xd4`–`0xd7`**, which carry no
  operand. It could report a phantom ref while the real one stayed invisible. Four walkers
  existed, split two-and-two on the correct opcode set; one of the wrong two backed a
  credential gate and could name an attacker as owner.
- **A malformed WIF was echoed back**, disclosing the key it failed to decode.
- **`pyrxd swap` fee'd every transaction at one-thousandth of the relay floor**, so RSWP
  orders could not relay — and a cancel that does not relay leaves the order takeable.

On the swap stack, both sides of the "did my counterparty actually fund their leg?" check now
live in the library rather than in an operator script: the maker's, and the taker's. Radiant
has neither RBF nor CPFP, so a transaction built below the relay floor cannot be repaired —
several fixes here exist because of that and not because of ordinary fee tuning.

The swap stack remains **experimental and UNAUDITED**. An external audit and a live two-party
adversarial run are still the hard gates before real value.

### Added

- **Cross-chain HTLC swap-handshake wire format — `docs/htlc-handshake-wire-format.md` plus
  `conformance/htlc-handshake-vectors.json`.** The swap *legs* were already specified by their
  chains; the negotiation that precedes them was not specified anywhere. It lived implicitly in
  `SwapCoordinator` and two operator harnesses, which meant a second implementation could
  reproduce every on-chain artifact and still be unable to complete a swap — it had no way to
  tell which fields cross the wire, which are local policy, which are consensus-binding, and
  which are decorative.

  The spec is derived from the implementation, not from a plan, and every normative statement is
  pinned to a `file:line` or a test. It covers the five artifacts that cross between the parties,
  the `NegotiatedTerms` JSON wire form field by field (including the omit-when-default rules a
  reader must apply, or it will reject every honest BTC handshake), the state transitions each
  message drives, and — the part that loses funds when it is wrong — the exact constraints on the
  hashlock, the per-leg timelock deltas, the destination bindings, and the funding and finality
  parameters. Two of those deserve naming here:

  - **The preimage is exactly 32 bytes**, and this is consensus-pinned on both legs
    (`OP_SIZE <0x20> OP_EQUALVERIFY` ahead of the hashlock check). The spec states the rule
    normatively and explains the vector it closes: a non-32-byte `p'` with `SHA256(p') = H`
    satisfies a naive hashlock check, so the maker's claim succeeds, but the 32-byte-only witness
    scrape silently finds nothing and the counterparty's asset strands until the CSV refund takes
    it. An implementer who treats the length as a convention walks straight into the bug this
    repo already fixed.
  - **The timelock direction is counterintuitive and load-bearing.** `t_btc − t_rxd >= margin`:
    the party who locks first holds the *longer* refund. Inverting it collapses the window in
    which the second claimer can act.

  A shipped conformance suite (51 checks) makes the spec executable rather than prose-only: five
  `terms` vectors across all three asset variants and both counter chains, three preimage-length
  vectors, and four margin verdicts, each republishing the two scriptPubKeys a counterparty
  independently re-derives. One vector pair is itself a finding — the `rxd`, `ft` and `nft`
  vectors derive the *identical* BTC funding address, because the taptree commits to nothing on
  the Radiant side. Verifying the counter leg tells you nothing about which asset you are buying.

  Writing the spec surfaced eight interop hazards, recorded in the document rather than smoothed
  over. The two with fund-loss consequence: the maker-side "did the taker fund the right HTLC for
  the right amount" check existed only in a script, not in the library, and `SwapCoordinator`
  explicitly declined to provide it for a BTC leg — an under-funded HTLC therefore paid the maker
  less than the agreed price, and the coordinator's own amount bind could not catch it because it
  runs on the honest taker's leg. (**HZ-3 is fixed in this same release** — see Security below;
  the hazard section now documents what the library enforces.) And the `schema` tag every envelope
  carries is written at four
  sites and read at none, while `NegotiatedTerms` has no version field and silently drops unknown
  keys — so there is no mechanism by which a receiver can detect that a sender meant something it
  does not understand. Safety consequently rests on the two re-derived scriptPubKey comparisons,
  not on the envelope; anything outside them is effectively unauthenticated.

  The document carries the swap stack's **UNAUDITED** status prominently and states that the
  stack defends safety, not liveness — capital-lockup griefing remains an accepted residual
  (threat model S22). A passing conformance run is a regression lock, not an assurance argument.
- **Output-script descriptor export — `wallet export-xpub --descriptor`, `HdWallet.descriptors()`,
  `pyrxd.hd.descriptor`.** A bare xpub leaves a watch-only consumer guessing two things: which
  script type to build, and which seed the key came from. A descriptor states both —
  `pkh([73c5da0a/44h/512h/0h]xpub6BmWw…/0/*)` — so the import is unambiguous.

  **Radiant Core rejects the checksummed form that Bitcoin Core requires.** The fork predates
  Bitcoin Core 0.18, so `src/script/descriptor.cpp` has no checksum machinery at all and the
  BIP380 `#xxxxxxxx` suffix reads as unparseable trailing input: `scantxoutset` answers
  `error code: -5, Invalid descriptor`. The default output therefore carries **no checksum**,
  which is what the only descriptor consumer in the Radiant ecosystem accepts. `--checksum`
  appends a real BIP380 checksum (the polymod, proven against the BIP's published
  `raw(deadbeef)#89f8spxm` vector) for Bitcoin-Core-lineage tools that demand one.

  Both chains are emitted, receive (`/0/*`) and change (`/1/*`). A watch-only import that takes
  only the receive descriptor does not report a smaller wallet — it reports a *wrong* balance
  that silently omits every change output, which after a few spends is most of the funds.

  The key-origin fingerprint is the **master** fingerprint, `hash160(master pubkey)[:4]`, exposed
  as `HdWallet.master_fingerprint()`. It is deliberately not `Xkey.fingerprint` on the account
  xpub, which is the BIP32 *parent* fingerprint (of `m/44'/<coin>'`, one level up) and differs for
  every account below depth 1. Using the parent there is the kind of bug that never surfaces in
  testing: the descriptor still derives every address correctly, so balances look right, and it
  only fails when a consumer tries to match the descriptor to a signing device.

  Hardened steps are written `h`, not `'`. Radiant Core accepts both (verified against a mainnet
  node), but a descriptor containing `'` cannot be pasted inside a shell's single quotes, and
  `radiant-cli` invocations are written exactly that way.

  Descriptor builders refuse any key that is not an xpub. This is not theoretical tidiness:
  `scantxoutset`'s own help documents the key as "an xpub/xprv", so the node would accept a
  descriptor carrying spending authority without complaint.

  The command's guidance was corrected while it was open: the previous "Safe to share with
  watch-only services" overstated the case. An xpub discloses every address the wallet will ever
  derive on both chains — a whole-history disclosure, permanent, and much larger than handing out
  one address. Both the `--help` text and the human-mode output now say so. See
  [Export a watch-only output-script descriptor](docs/how-to/export-a-watch-only-descriptor.md).

- **Multi-recipient FT airdrop — `glyph airdrop-ft`, `FtUtxoSet.build_airdrop_tx`,
  `GlyphBuilder.build_ft_airdrop_tx`.** One transaction paying N recipients, instead of N
  sequential transfers. The difference is not convenience: sequential transfers chain, each
  spending the previous one's change, so a failure partway leaves the set half-delivered with
  no way to tell which half from the token's ref alone. One transaction lands whole or not at
  all.

  Conservation goes through the existing path rather than around it — `select` for "do I hold
  enough", `FtUtxoSet.__init__` for the per-ref input check, and the same
  `ft_in - out == change` identity with `out = sum(amounts)`. No new code computes token
  amounts, so there is no new way to mint units.

  Two consequences of **1 photon = 1 FT unit** shape the builder, and getting the first one
  wrong in the first cut is what the regtest proof caught:

  - **A recipient's output value IS the units they receive**, so it is not a free parameter —
    it must equal the requested amount, not a dust constant.
  - **The fee therefore cannot come out of a token output**; doing so would silently burn
    units and short a recipient. It comes from plain-RXD `AirdropFunding` inputs, the same way
    `transfer-nft` already sources a separate input to move a dust-carrying singleton. Each
    funding UTXO carries its own key, so the RXD may live at a different wallet address from
    the token.

  The airdrop is correspondingly stricter than the single-recipient transfer about the inputs
  it will spend: it refuses an `FtUtxo` whose `value` and `ft_amount` disagree. On chain they
  are the same number, so a mismatch means the caller built the record from the wrong field —
  and it is not a modelling nuance here, it is a wrong transaction (`ft_amount > value`
  materialises more of the ref than the inputs carry and consensus rejects the broadcast;
  `ft_amount < value` routes the surplus photons to change or fee, burning units).
  `build_transfer_tx` still tolerates a mismatch because it does not size outputs from token
  amounts.

  Recipient outputs have a **1-photon** floor — the chain's actual rule
  (`GetDustThreshold` returns 1 unconditionally, `Radiant-Core/src/policy/policy.cpp:19-25`) —
  deliberately **not** 546, which would forbid airdropping 100 units of anything. `dust_limit`
  governs only the RXD change output's fold-to-fee threshold.

  The builder binds its fee floor to `gravity.fee_policy.RADIANT_EFFECTIVE_MIN_RELAY_PHOTONS_PER_KB`
  rather than restating it, and adds 2 bytes per input of sizing headroom before computing the
  fee: the trial and final passes sign different messages, so their DER signatures can differ
  in length and a fee sized purely off the trial can land *below* the rate it was built for.
  Radiant has neither RBF nor CPFP, so that transaction could not be repaired — it would hold
  its inputs until mempool expiry. The built transaction is re-checked against the rate before
  it is returned.

  **Proven on a node**, not just built: `tests/test_ft_airdrop_regtest_e2e.py` deploys a real
  FT and runs three recipients + change + ref-less P2PKH outputs past a live
  `radiant-core:v3.1.1` regtest node, confirms unit totals off the confirmed transaction, and
  carries a negative control — the same transaction with one recipient output inflated by a
  single unit is rejected with `mandatory-script-verify-flag-failed (Script failed an OP_VERIFY
  operation)`, which is the FT epilogue firing. A node that accepted everything could not have
  masqueraded as a pass.

- **Royalty payment — `pyrxd.glyph.royalty`, and `royalty=` on the FT airdrop builder.**
  `GlyphRoyalty` has been decoded from the Glyph envelope since 0.9.0 and never paid. It is
  paid now, and described accurately.

  **Royalties on Radiant are ADVISORY. They are not enforced by consensus.** This was
  established before any code was written, because getting it wrong would ship something that
  tells a creator they are being paid when nothing guarantees it. An FT lock's 12-byte epilogue
  enforces *ref conservation* — how many units may exist on the output side — and says nothing
  about where value goes; an NFT lock is a bare P2PKH behind a ref push. No covenant that ships
  in pyrxd references a royalty. Photonic Wallet reaches the same structural conclusion: in
  `royaltyCovenant.ts` the NFT at rest lives in the ordinary `nftScript`, enforcement exists
  only once a holder *voluntarily lists* it into a sale covenant, and that file's own "Honest
  scope" note records that it cannot stop a non-compliant seller or an out-of-band gift.
  Photonic's non-covenant `royalty.ts` layer is referenced only by its own unit tests. Full
  evidence in
  [`docs/solutions/design-decisions/royalties-are-advisory-not-consensus-enforced.md`](docs/solutions/design-decisions/royalties-are-advisory-not-consensus-enforced.md).

  So: `royalty_due = max(minimum, floor(sale_price * bps / 10_000))` — byte-for-byte Photonic's
  `calculateRoyalty`, so a pyrxd payment and a Photonic payment agree on the single-recipient
  path. Supplying a `royalty` to a builder **pays it by default**; `pay_royalty=False` is an
  explicit opt-out and the decision is recorded in the result either way. Payouts are plain
  25-byte P2PKH outputs, which carry no ref and therefore contribute to no conservation sum —
  the property that makes a royalty safe to bolt onto an FT transfer, now confirmed against a
  live node. Royalty addresses are finally *validated*: `GlyphRoyalty` only checks that the
  string is non-empty, so a typo used to survive minting and would have surfaced as a burned
  payment.

  Two deliberate deviations from Photonic on the `splits` path, both because its version can
  pay the creator less than the terms they recorded: `minimum` is honoured when splits are
  present (Photonic computes each split from `sale_price` directly and never consults it), and
  the residue — flooring loss plus any bps the splits do not cover — goes to the top-level
  `address` rather than being dropped. `sum(payouts) == royalty_due` exactly.

  Not built, deliberately: no `--sale-price` / `--royalty-address` CLI flags, because terms
  typed in by the person *paying* protect no creator — honouring a royalty from the CLI needs
  the creator's recorded terms, which means resolving a ref to its reveal transaction.

  And **no royalty on `build_nft_transfer_tx` or `FtUtxoSet.build_transfer_tx`**: neither has a
  plain-RXD input, so a royalty there could only be paid out of the token, burning units to pay
  a creator. The first cut of this work did exactly that on the FT transfer path — a pre-merge
  review measured a 5% royalty on a 1,000,000-photon sale costing the recipient **390,000
  units**. The parameter was removed rather than patched. A one-recipient `build_airdrop_tx`
  call is an ordinary transfer and can pay a royalty properly, because it is funded.

- **[`docs/concepts/glossary.md`](docs/concepts/glossary.md) — an A–Z glossary
  of Radiant and pyrxd vocabulary.** Deliberately excluded from the 0.12.0
  troubleshooting page as a separate item; this closes it. Roughly 50 terms
  across chain primitives (photon, ref/induction, `OP_PUSHINPUTREF` family,
  FORKID, `hashOutputHashes`, scripthash, dust floor, min-relay fee), Glyph
  (CBOR envelope, commit/reveal, the protocol-type enum, premine, carrier
  value), dMint (difficulty vs target, DAA modes, reroll), HTLC swaps
  (hashlock, `t_btc`/`t_rxd`/margin, the free option, griefing, RSWP, SPV,
  watchtower), and HD wallets (BIP32/39/44, `coin_type` 0/236/512, NFKD
  normalization, xprv/xpub, gap limit, WIF) — each grounded against the
  defining module or an existing doc rather than a general definition. Two
  entries record real shipped bugs this repo hit: the genesis-ref-vs-
  reveal-txid confusion (0.12.0) and the `MAX_SHA256D_TARGET / target`
  difficulty-multiplier-vs-expected-attempts trap (off by `2**33`).

- **dMint deploy-with-premine (V1 and V2) — `premine_amount` / `premine_pkh`, and
  `glyph deploy-dmint --premine`.** `GlyphBuilder.prepare_dmint_deploy` refused a premine at
  every entry point; that was the largest single deferral left in shipped code. A dMint deploy
  can now issue a fixed allocation alongside the mineable supply — a treasury, a fair-launch
  bootstrap, an airdrop float — in the same commit/reveal pair, instead of requiring a second,
  separate FT deploy under a different `tokenRef` that no miner's reward would ever be
  fungible with.

  The reveal gains exactly one output: the canonical 75-byte FT lock on `tokenRef`, byte-identical
  to the reward output a mint pays out (`build_dmint_v1_ft_output_script`), placed directly
  after the contract outputs. That position and shape are Photonic Wallet
  `createRevealOutputs` parity, and the shape is load-bearing: the premine pushes `tokenRef`
  with `OP_PUSHINPUTREF` (refType NORMAL), which is what the commit hashlock's
  `OP_REFTYPE_OUTPUT == OP_1` assert demands. Emitting it as a singleton would make the
  reveal unspendable. The contract carriers are untouched — still 1-photon singletons, which
  both covenants hardcode.

  **The premine is real photons the deployer funds**, not an accounting entry: 1 photon = 1 FT
  unit, so total issued supply becomes `reward × max_height × num_contracts + premine`. The CLI
  sizes the commit and the reveal fee for it, names it in the confirmation gate, and reports
  `premine`, `premine_outpoint`, `mineable_supply`, and `total_supply` in `--json`.
  `--premine-to` sends it elsewhere (default: the deploying wallet). If V2 metadata declares a
  `dmint.premine`, it must equal what the deploy emits — a token that mis-reports its own
  supply is refused rather than minted. The floor is 1 photon, not 546: Radiant-Core has no
  dust threshold at all (`GetDustThreshold` returns 1 satoshi, `IsDust` is `nValue <= 0` —
  `src/policy/policy.cpp:19-25`), which is also why every mainnet dMint contract sits at
  1 photon.

  Proven on a real `radiant-core` regtest node, not merely constructed
  (`tests/test_dmint_premine_regtest_e2e.py`, opt-in): for V1 **and** V2, the node accepts the
  premine reveal, the premined FT is spendable through the shipped
  `GlyphBuilder.build_ft_transfer_tx` path, and the contract still yields a PoW-mined claim
  afterwards — with a wrong-nonce negative control, so a node that accepted everything could
  not pass.

- **Offline / cold swap-recovery toolkit — `pyrxd swap recover-preimage`, `build-claim`,
  `build-refund`.** The human fallback for the page that the deadline-aware fee gate (below)
  now raises. Because Radiant has neither RBF nor CPFP, automation refuses to broadcast an
  unaffordable time-critical spend rather than emit one it can never repair; this is the
  other end of that page. An operator builds the covenant spend **cold**, reads every field,
  chooses the fee, and broadcasts it from their own node.

  **These commands are strictly read-only and never broadcast.** They print raw transaction
  hex — nothing more. That is the same posture `pyrxd swap status` already has, and it is
  what keeps the cold path outside the external swap audit gate. No broadcaster, coordinator,
  or key-holding leg is imported; a test asserts that at the source level, a second asserts no
  broadcast-shaped call exists on any path, and the chain fakes in the suite raise if their
  `broadcast` is ever reached.

  - **`swap recover-preimage`** scrapes the preimage `p` off the counter-chain (BTC witness or
    ETH calldata/log data) and re-verifies it. **Provenance is mandatory, including offline.**
    A scrape that accepts any 32-byte value hashing to `H` is a real vulnerability, not a
    convenience: two swaps can share a hashlock, so a transaction that merely *contains* a
    valid-looking `p` is not evidence that OUR counter-leg was claimed. Reusing the discipline
    proven in the watchtower's claim executor, the txid is re-derived from the fetched bytes
    and matched against the reported spender, the transaction must spend **our** funding
    outpoint (exact 36-byte wire prevout, never an offset), and only then is `p` scraped and
    independently re-verified. On Ethereum the equivalent bind is the per-swap-unique HTLC
    contract address: only calldata and logs bound to it are scanned. `--claim-tx-hex` /
    `--claim-tx-file` accept operator-supplied bytes for a fully offline run, and still
    require the funding outpoint.
  - **`p` is never read from the recovery file.** The harness JSON carries `preimage_p_hex`,
    but on a maker's host that copy may still be a **pre-reveal** secret — trusting it would
    manufacture a claim the operator is not yet entitled to make. Only the chain-scraped value
    is legitimate, and a chain-scraped `p` is already public, which is why printing *that* one
    is safe.
  - **`swap build-claim` / `swap build-refund`** rebuild the covenant from public parameters
    (fail-closed: the rebuilt scriptPubKey must equal the persisted one, so a wrong amount,
    pkh, or timelock cannot produce a spend of some other covenant) and print, beside the hex,
    the decoded output and who it pays, the fee, **the node's relay floor**, the
    **deadline-aware target** from `gravity.fee_policy`, and the CSV maturity state. The point
    is that a human sizes the fee deliberately. `build-refund` refuses an immature CSV by
    default; `--allow-immature` pre-builds it for broadcast at maturity.
  - **`swap status --check-chain` now also reads the counter-leg**, through that same
    provenance-checked path, so it can say the counterparty's claim has revealed `p` — the
    difference between "keep waiting" and "claim now", which the RXD covenant alone cannot
    show. It reports only that a preimage *is* recoverable; extracting it stays a separate,
    deliberate verb. With no locator or endpoint configured it reports `NOT_CHECKED` **with
    the reason** rather than failing, so a mid-incident operator still gets the covenant
    verdict.

- **ElectrumX server registry + request-level failover (`pyrxd.network.registry`,
  `pyrxd.network.failover`).** Until now there was exactly one hardcoded endpoint and racing
  happened only at *connect* time — once a socket was up, an endpoint that went away failed
  every wallet operation, and `ElectrumXClient._call`'s own docstring noted that "callers that
  want retry semantics should layer it above `_call`". Nothing did. `FailoverElectrumXClient`
  is that layer, strictly above the transport: it owns one client per endpoint and retries a
  failed call on the next one. Nothing was added to the reader loop, the id-correlation map,
  or `_call`.
  - **The shipped set is small and verified, not aspirational.** mainnet ships the two
    independent public servers (`electrumx.radiant4people.com:50022`,
    `electrumx.radiantcore.org`) that the watchtower already used, both re-confirmed live —
    same tip, both serving the mainnet genesis header. **testnet and regtest ship none**: no
    public Radiant testnet ElectrumX server was confirmed, and regtest is a local chain.
    Inventing a plausible host there would recreate the very bug fixed above.
  - **Node verdicts are never retried.** A `PolicyRejection` ("invalid", "underpriced",
    "dust") is an *answer*. Re-asking a different node is shopping for a server with laxer
    rules and it buries the reject reason.
  - **`call_extension` is not retried by default** — it reaches arbitrary indexer RPCs whose
    side effects this layer cannot know. Callers opt in per call with `idempotent=True`.
  - **`broadcast` IS retried, under stated conditions.** See *Upgrade notes* for the full
    argument; in short: the bytes are captured once so a retry can never be a *different*
    transaction, only transport failures trigger it, and a later endpoint answering
    "already known" is treated as success rather than a spurious failure for a transaction
    that is demonstrably on the network.
  - Configure with `electrumx_servers = [...]` (top level or per `[networks.<name>]`).
    Configuring a single endpoint keeps the previous single-server behaviour exactly.

- **Optional TLS SPKI pinning (`pyrxd.network.tls_pin`), off by default.** Ordinary TLS says
  "some CA vouches for this hostname", which a mis-issuing CA, a TLS-inspecting middlebox, or
  DNS hijack plus an ACME challenge all satisfy. Pinning the SHA-256 of the server's DER
  `SubjectPublicKeyInfo` closes that: a substituted server is refused before any RPC is sent.
  Format is the HPKP/`curl --pinnedpubkey` string (`sha256/<base64>`), so an operator can
  produce one with `openssl` (recipe in the module docstring). It is **opt-in** because a pin
  is a hard commitment to a key, and a routine operator key rotation would otherwise break
  every client at once and look exactly like an attack; a mismatch raises the new, distinct
  `TlsPinMismatchError` (a `NetworkError` subclass, so existing handlers still catch it) naming
  the observed pin so a rotation is a one-line config edit. A malformed pin is rejected at
  construction — a pin that silently fails to parse is a pin that silently does nothing.

- **External-miner progress frames (B3).** The dMint ETA work (#361) streamed live hashrate/ETA
  during a claim grind, but only for the bundled miner running in-process — a genuine external
  `--miner-cmd` binary got a static "no live progress" message, because the JSON-over-stdio
  protocol had no way to report progress. `mine_solution_external` now accepts a `progress=`
  callback: the miner MAY write zero or more optional lines to **stderr** while it searches
  (`{"progress": {"attempts": N, "elapsed_s": F}}`, one JSON object per line — see
  `docs/concepts/parallel-mining.md`). This needed no `protocol` version bump; it's purely
  additive on both sides — an old miner that has never heard of progress frames simply stays
  silent, and an old caller that never asks for progress is byte-for-byte unaffected (the
  no-progress path still uses the original single blocking `subprocess.run(...,
  stderr=subprocess.DEVNULL)` call, unchanged).

  Two things this had to get right, both load-bearing:

  - **The `stderr=DEVNULL` memory bound had to survive reading the stream instead of discarding
    it.** Opting into progress switches to a `Popen`-based reader
    (`_ExternalMinerProgressReader`) that retains only the single most-recently-parsed frame —
    a flood of a million lines costs CPU parsing JSON, never growing memory, because each new
    frame overwrites the last — and caps one unterminated "line" at 4096 bytes, dropping and
    resynchronizing at the next newline rather than accumulating an unbounded buffer against a
    miner that never emits `\n`.
  - **A progress frame can never be mistaken for a solution.** It lives on stderr, a stream the
    result parser never reads at all, and its parser (`_parse_external_progress_frame`) can only
    ever return an `(attempts, elapsed_s)` pair — there is no code path from a stderr line,
    however solution-shaped, to the nonce-verification logic.

  The bundled reference miner (`pyrxd.contrib.miner`) now emits these frames by default
  (`--quiet` suppresses them, same as the exhaustion message), demonstrating the extension
  end-to-end. Also confirmed while here: an external miner that exits immediately is reported
  as a failure (`ValidationError`), never as nonce-space exhaustion — the external-path
  equivalent of the parallel-miner immediate-death bug `_assert_workers_completed` guards
  against was already absent, and now has a regression test pinning it.

- **A normative specification of the Glyph token protocol —
  `docs/reference/glyph-token-protocol-spec.md`, in a new `Reference` section of the docs.**
  The protocol previously existed as code plus scattered prose; there was no single document a
  second implementation could build against. This one is precise enough to produce
  byte-identical envelopes, scripts, and refs: the CBOR envelope and its limits, the
  commit/reveal hashlock, ref derivation, every locking-script template with its opcode
  semantics spelled out, the validation rules in RFC 2119 terms, versioning, and a worked
  example anchored to the mainnet Glyph Protocol deploy (`a443d9df…878b` →
  `b965b32d…9dd6`) whose 65,569-byte CBOR body is already a checked-in fixture.

  It was derived from the source rather than from the existing docs, and that turned up four
  things worth knowing independently of the document:

  - **Canonical CBOR is a producer rule, not a validity rule.** pyrxd encodes with
    `canonical=True`, but the reference mainnet token does not: its map header is `b9 0006`
    where canonical form requires `a6`, and its keys are in insertion order. Re-encoding it
    canonically yields 65,565 bytes and a different payload hash. A verifier MUST therefore
    hash the bytes it received and MUST NOT reject a non-canonical envelope — decode-then-
    re-encode rejects the flagship mainnet token.
  - **FT conservation is `sum(in) >= sum(out)`, not `==`.** The epilogue opcode is `0xa2`
    (`OP_GREATERTHANOREQUAL`), so burning is permitted; the second check is that the number of
    outputs carrying the ref equals the number carrying the FT code-script hash. Several
    docstrings and one concept page said `==`; corrected below.
  - **The creator signature is computed over a non-canonical encoding** and covers pyrxd's
    decoded field set rather than the on-chain bytes, so adding an unknown top-level CBOR field
    does not invalidate it. Documented as a caveat, not changed — changing it would invalidate
    every existing signature.
  - **A CONTAINER built with a child ref is a 100-byte script no pyrxd classifier matches**;
    it reports as `unknown`, is skipped by `find_glyphs`, and cannot be transferred by
    `build_nft_transfer_tx`. Recorded in the spec's "underspecified" section.

  The spec also states plainly what is *not* enforceable: royalties, soulbound
  `policy.transferable`, container membership, `dmint.premine` consistency, and ref provenance
  are all advisory or off-chain concerns.

### Fixed

- **`pyrxd swap` fee'd every transaction at one-thousandth of Radiant's relay floor — the RSWP
  orderbook commands could not relay on mainnet.** Pre-existing, not a regression: the bug shipped
  with the orderbook CLI and every release since. `swap_book_cmds._estimate_fee` computed
  `(ctx.fee_rate * size + 999) // 1000`, treating `ctx.fee_rate` as photons per *kB*. It is photons
  per **byte** — `cli/config.py`'s `validated_fee_rate` enforces the relay floor in exactly those
  units, and every other call site in the tree agrees (`wallet.py` uses `size * fee_rate`,
  `glyph_cmds.py` converts *up* with `SatoshisPerKilobyte(fee_rate * 1000)`). Measured against the
  real `pyrxd.swap.rswp` builders at the default 10,000 photons/byte, comparing the fee the CLI paid
  to `ceil(size × effective_minrelaytxfee / 1000)` on the transaction's `GetTotalSize()`:

  ```
  command                        size   fee paid  required    verdict
  cancel v2 (RXD, self-funded)   192 B     6,000  1,920,000   320x short   WILL NOT RELAY
  post v2 (RXD give, RXD want)   426 B     4,500  4,260,000   947x short   WILL NOT RELAY
  post v2 (FT give, FT want)     512 B     4,500  5,120,000  1138x short   WILL NOT RELAY
  take v2 (FT demand, 2 fund)    740 B     8,300  7,400,000   892x short   WILL NOT RELAY
  ```

  Radiant has **neither RBF nor CPFP** (threat model S21; source lines cited in
  `gravity/fee_policy.py`), so such a transaction cannot be repaired by any means — it holds its
  inputs until the 8-hour mempool expiry. The fund-safety edge is `cancel`, which is the **only**
  hard revocation for a v2 order: a cancel that never relays leaves the order **still takeable at
  the original price** while the CLI prints a txid and reports success, so the maker stops watching
  an offer a counterparty can still accept.

  Two further defects surfaced while fixing the units, both of which would have re-created an
  under-fee by a different route once the ×1000 was corrected:

  - **The size model under-counted the transactions it was modelling.** `_TX_BASE_BYTES = 220` was
    smaller than the advert `OP_RETURN` alone (measured 226 B for an RXD/RXD order, 310 B for
    FT/FT, 314 B for a v3 covenant advert), and `_TX_PER_OUTPUT_BYTES = 40` could not cover a
    Glyph FT output (84 B). The modelled input/output counts were also fixed constants while
    `_MAX_FUNDING_INPUTS` is 8, so a wallet paying from 8 UTXOs built a 1,541-byte transaction
    against a 450-byte model — 3.4× under even with correct units.
  - **`_MIN_FEE_PHOTONS = 1_000` could never bind.** Three orders of magnitude below the floor for
    any real transaction, so it was not the safety net its placement in a `max()` implied.

  The fee is now sized from **the transaction's own serialized length**, not from a byte model:
  `_build_at_measured_fee` builds, measures `len(tx.serialize())` (plus 3 bytes per input of
  signature slack, the bound `glyph/ft.py` already measured for trial-vs-final DER length variance),
  and rebuilds if the seed was low. The size constants survive only to seed the first pass, which
  must pick funding before there is a transaction to measure; `_MIN_FEE_PHOTONS` is removed in
  favour of the size-derived floor. That floor is **bound to** `gravity.fee_policy`'s
  `DeadlineFeePolicy.min_relay_fee` rather than restated, so the swap CLI, the glyph builders and
  the HTLC stack cannot drift apart on what the node demands. A final `_assert_relayable` check
  refuses to hand back a sub-floor transaction rather than broadcasting one — including on the
  `--fee` path, which previously passed any operator-supplied number straight through. After the
  fix, every command clears the floor with 1.02×–1.43× headroom:

  ```
  command                        size   fee paid  floor      relays
  cancel v2 (RXD, self-funded)   192 B  2,500,000  1,920,000  yes (1.30x)
  cancel v2 (FT + fee funding)   422 B  4,290,000  4,220,000  yes (1.02x)
  post v2 (FT give, FT want)     511 B  6,580,000  5,110,000  yes (1.29x)
  take v2 (RXD demand, 1 fund)   407 B  5,800,000  4,070,000  yes (1.43x)
  ```

  Regression cover is `tests/cli/test_swap_fee_sizing.py` (29 tests), which asserts against the
  CLI's own surface — the fee printed in the confirmation summary versus the size of the bytes
  handed to `broadcast` — so the tests are expressible against the buggy code too. 28 of the 29
  fail on the pre-fix module. One existing fixture in `tests/cli/test_swap_covenant_cmds.py` was
  built on the buggy magnitude (a 1,000,000-photon offer commented "well above the estimated fee",
  which cannot in fact pay a ~1,920,000-photon cancel); it is re-funded rather than removed, with a
  note recording why the original number looked generous.

  **Operator note:** correct fees are ~1000× the previously-quoted ones, because the previous ones
  were wrong, not because anything got more expensive. At the relay floor a v2 order below roughly
  0.02 RXD can no longer pay for its own cancel from its own value and will draw a separate
  plain-RXD funding input; a wallet with no plain RXD will now be told so instead of building a
  transaction that could never confirm.

- **A refused (never-broadcast) covenant spend no longer charges the fee pool's cap**
  (`CappedFeeWalletSource.release_unspent`, `RadiantCovenantLeg._unspent_on_failure`). The fee input
  has to be dispensed *before* the transaction can be built — its value and script are inputs to the
  build — and the build refuses when that input cannot clear the node's deadline-aware relay floor.
  Nothing reached a node and no fee was paid, but the source had already committed the input and
  charged the cumulative cap. `watch/claim_executor.py` deliberately retries a `DECLINED` fee
  refusal on the next tick (correctly: the source is dispense-once, so the next dispense may be
  larger), so the refusals compounded. Measured on the pool shape an operator would actually
  configure — 7 × 500,000 + 1 × 20,000,000 photons, cap 20,000,000, floor ~2,670,000 for a 267-byte
  claim:

  ```
  FeePoolExhaustedError: capped fee cap reached: dispensing 20000000 photons would exceed
  total_cap_photons=20000000 (already dispensed 3500000). Fail-closed.
  ```

  Seven ticks broadcast nothing and burned 3,500,000 of the cap; the eighth could no longer reach
  the one input large enough to work. The covering UTXO was funded, unspent, and unreachable, and
  the asset ran out its deadline to the counterparty's CSV refund.

  The fix credits the cap back on any pre-broadcast failure, **without** rewinding the dispense-once
  cursor: no input can ever back two transactions, and a small head-of-line input cannot re-refuse
  forever while a covering input sits behind it. The broadcast itself is outside the guarded block —
  once bytes reach a node the input may well be spent, and crediting it then would under-count real
  spend against the cap. The report is duck-typed and optional, so a plain `FeeUtxoSource` keeps
  working. `docs/threat-model.md` **S21** claimed the executor "does not retry into a fee-pool
  drain"; that claim was wrong and has been corrected in place.
- **The cold recovery toolkit refuses an unbounded fee overpay** (`swap_recovery.select_fee_utxo`,
  `pyrxd swap build-claim` / `build-refund`). The covenant permits exactly one output, so there is no
  change and the **entire** fee input is paid to the miner. The selector picked the smallest UTXO at
  or above the target with no upper bound, so pointing the toolkit at an ordinary funded key holding
  a single 500 RXD UTXO burned **50,000,000,000 photons against a 2,660,000-photon target — 18,727×**
  — while the CLI printed that the fee "clears the deadline-aware TARGET". (`htlc_spend._check_carrier`
  claims to guard "a mistakenly-huge UTXO" but only ever checked the dust end.)

  A fee input above `10 ×` the requirement is now refused with an `OVERPAY` message naming the
  multiple and the ceiling; `--allow-overpay` burns it deliberately, and an explicitly named
  `--fee-utxo` is held to the same bar (naming a UTXO by hand is not consent to burn 500 RXD on a
  0.0266 RXD fee). The ceiling is a **multiple**, so a genuinely large requirement scales with it.
  `ColdSpend` gained `overpay_multiple` / `is_overpay`, and the human output now prints an OVERPAY
  verdict instead of a reassuring one.
- **`pyrxd swap build-claim` no longer builds against a 0-conf covenant.** ElectrumX `listunspent`
  returns mempool outputs, so `read_covenant_chain_state` resolved an unconfirmed covenant and the
  cold builders exited 0 against it. A spend of an unconfirmed parent dies with that parent, and
  with neither RBF nor CPFP its fee input then squats until the 8-hour mempool expiry — inside the
  `t_rxd` window the claim exists to beat. The automated path already enforced this
  (`radiant_leg._resolve_covenant`); the cold path now matches, with `--allow-unconfirmed` as the
  explicit override. `build-refund` is gated too: `--allow-immature` is about the CSV, not about the
  parent's existence on chain.
- **The external-miner stderr reader could grow without bound on a miner that never writes a
  newline.** `_ExternalMinerProgressReader` caps one physical line at `_PROGRESS_LINE_MAX_BYTES`
  (4 KiB) and its docstring promises that bound holds "however long the miner writes". The check
  was gated on `not skipping`, so the *first* overflow latched `skipping = True` and the cap was
  never evaluated again — the buffer then grew linearly with the stream until a newline arrived,
  which for a broken or hostile miner is never. Measured: **12,574,720 bytes** retained on
  12,582,912 bytes (12 MiB) of newline-free stderr.

  Latent until `0.13.0`, where the external path always ran `stderr=subprocess.DEVNULL`; the
  progress-frame extension now routes stderr through this reader (`miner.py:894-899`, reachable
  from `pyrxd glyph mine --miner-cmd`). The cap is now re-checked unconditionally, holding the
  buffer at `cap + one read chunk` for the whole of an unterminated line. Locked by
  `test_newline_free_flood_never_grows_the_buffer_past_the_cap`, with a companion test confirming
  the reader still resynchronizes at the first newline after a flood.

- **`glyph transfer-ft` could send the wrong number of FT units — up to the sender's entire
  balance.** Found while building the airdrop, in shipped code, not in the new work.

  `FtUtxoSet.build_transfer_tx` sizes the recipient's output as
  `rxd_in_total - fee - change_alloc`, not from `amount`. Under this module's original model —
  where `FtUtxo.value` and `FtUtxo.ft_amount` are documented as orthogonal — that is merely
  odd. On chain they are the same number: an FT's quantity **is** its output's `satoshis`
  (`docs/concepts/radiant-fts-are-on-chain.md`), which is exactly what the CLI constructs
  (`ft_amount = utxo.value`). Measured on a realistic holding — one 50,000,000-unit UTXO,
  `amount=250`, default fee rate:

  ```
  asked to send:                    250 units
  recipient output (units sent):    46,739,454
  change output (units kept):       546
  ```

  Not a rounding error — the sender's whole position, to a counterparty who asked for 250, with
  no error and no way back once confirmed. It stayed invisible because the offline test suite
  uses deliberately decoupled fixtures (`value=5_000_000, ft_amount=100`), and the one live
  regtest exercise of this path spent its balance **in full**, the single case where the two
  numbers agree.

  Three changes:
  - `glyph transfer-ft` now builds through `build_ft_airdrop_tx` with one recipient. That
    builder sizes each output from the units requested and pays the fee from a plain-RXD input,
    which is the only arrangement that can be correct. **The command now requires a little
    plain RXD**, exactly as `transfer-nft` already did — the token cannot pay its own fee
    without burning units.
  - `build_transfer_tx` **refuses** any input with `value == ft_amount` — i.e. what a real
    holding looks like — and names `build_airdrop_tx` in the error. It is kept for callers
    genuinely using the decoupled model, and should be folded into `build_airdrop_tx` and
    removed.
  - `tests/test_dmint_premine_regtest_e2e.py` moved to the airdrop path, so the live proof
    exercises the builder that is correct rather than the full-spend case that hid this.

- **That `value == ft_amount` tripwire was not a fix, and the fund loss was still reachable at
  ±1 photon.** A pre-release audit re-ran the original case against the guarded code:

  ```
  value == ft_amount      : refused (ValidationError)
  value == ft_amount + 1  : recipient = 46,749,455 units  (asked 250)   <- FUND LOSS
  value == ft_amount - 1  : recipient = 46,739,453 units  (asked 250)   <- FUND LOSS
  ```

  The guard fenced off one input shape and left `transfer_value = rxd_in_total - fee -
  change_alloc` exactly where it was. Enumerating the shapes someone thought of cannot make a
  wrong expression right, and the shape it did catch was the *only* one anybody had thought of.

  **`FtUtxoSet.build_transfer_tx` is now a single-recipient `build_airdrop_tx`** — one
  implementation, so the recipient output's value is `amount` by construction rather than by
  guard, for input shapes nobody predicted. It gains a `funding` parameter (as do
  `FtTransferParams` and `GlyphBuilder.build_ft_transfer_tx`); the `value != ft_amount` check
  that survives inside the airdrop builder is a fail-closed backstop against a caller who built
  `FtUtxo` from the wrong field, and correctness no longer rests on it.

  Pinned by a property/differential suite over a wide `(value, ft_amount, amount)` space
  (`tests/test_ft_transfer.py::TestRecipientAmountIsExact`, including a Hypothesis case over
  `ft_amount` up to 2**45 and every fee rate from the relay floor up): the recipient always
  receives exactly `amount`, `sum(ft_in) == sum(ft_out)`, and the delivered quantity is
  **byte-identical across a 45x range of funding sizes and fee rates** — the property the
  original bug violated. A further test asserts the transfer and a one-recipient airdrop
  serialise identically, so the two cannot drift apart again.

  **Breaking for library callers:** `build_transfer_tx` / `build_ft_transfer_tx` now raise
  without `funding` (previously they raised on every real FT holding anyway), reject a fee rate
  below Radiant's 10,000 photons/byte relay floor, and may emit a plain-RXD change output.

- **A `royalty` block in a metadata file was silently dropped.** `_read_metadata_file` never
  passed `royalty` to `GlyphMetadata`, so a creator could write a complete royalty block, mint,
  and end up with a token whose CBOR carried no royalty at all — with no warning, and nothing
  to notice afterwards except that no wallet ever showed one. Minting is one-way, so that was
  permanent for the token. It is parsed now, including `minimum`, `enforced` and `splits`, with
  every recipient address decoded before the mint rather than after. (This also means the
  manual `docs/red-team-checklist.md` step that asks an operator to confirm a royalty appears
  in the envelope can pass as written, which it could not before.)

  The CLI's pre-broadcast metadata summary now prints
  `(ADVISORY — recorded on chain, not enforced by consensus)` beneath any royalty, at the one
  moment a creator is still deciding.

  **Residual, found while fixing this and deliberately left in place:** the same loader still
  drops `creator`, `policy`, `rights` and `v`. `royalty` was fixed because B2 names it; the
  others are the same bug and need the same treatment. The most consequential is
  `policy.transferable: false` — a token a creator marked soulbound mints as freely
  transferable, silently. `docs/red-team-checklist.md` §5.1 now flags the `creator` step as a
  known-failing gap rather than leaving a red-teamer to conclude the summary is broken.

- **A `dmint` block in a metadata file was silently dropped too, which made the
  declared-vs-emitted supply guard unreachable from the only command that emits a premine.**
  `_assert_declared_premine_matches` exists to stop a token advertising a supply it does not
  mint. `_read_metadata_file` never set `dmint_params`, so every CLI `deploy-dmint` produced
  CBOR with no `dmint` object and the guard returned on its first line. Audit evidence: a
  metadata file declaring `"premine": 999999999` deployed against `--premine` unset was
  **accepted**.

  Worse, on the library path — where a caller *can* set `dmint_params` — only `premine` was
  reconciled. Supply is `reward * maxHeight * numContracts (+ premine)`, so checking one factor
  is not checking supply: metadata advertising `reward=10, maxHeight=10_000, numContracts=1`
  (100,000 total) deployed against the 3-byte ceilings genesises contracts minting
  **70,368,735,789,056,250** photons, a 7x10^11 divergence, with both premines 0 so the check
  passed.

  Two changes: `_read_metadata_file` parses an optional `dmint` block (CBOR field names;
  `algo` also accepts `"sha256d"`/`"blake3"`/`"k12"`), and the guard — now
  `_assert_declared_dmint_matches` — reconciles `premine`, `reward`, `maxHeight`,
  `numContracts`, `diff` and `algo`, reporting every mismatch in one exception rather than
  costing a re-broadcast commit per field. `daa` is deliberately not reconciled: V1 deploy
  params carry no DAA fields to compare against, and the mode changes how fast supply is
  issued, not how much. Declaring the block stays optional — a deploy that advertises nothing
  mis-advertises nothing.

- **`build_ft_airdrop_tx` appeared in no source document, and the one documented FT-transfer
  recipe always raised.** `examples/ft_transfer_demo.py` and the FT tutorial correctly set
  `ft_amount = u.value` — what a real on-chain FT looks like — and were therefore refused by the
  tripwire above on every input. The example now sources a plain-RXD funding UTXO (checking the
  on-chain script is a bare 25-byte P2PKH, so it can never spend a token to pay a fee) and reads
  the delivered quantity back off the built transaction before broadcasting rather than trusting
  that it equals `AMOUNT`. Verified by running it end to end against a stubbed node: 250 units
  requested, 250 delivered, 49,999,750 change, in a 507-byte 2-in/3-out transaction.
  `docs/how-to/transfer-a-glyph-token.md` gains a **From Python** section covering both builders.

- **A V1 dMint deploy could be refused because an integer in its payload happened to encode the
  bytes `61 76`.** The "V1 CBOR must not carry a `v` field" check searched the *serialised*
  payload for that pair — the CBOR encoding of the key `"v"` — which also matches the low two
  bytes of any integer whose value is `0x6176` (24,950), encoded `19 61 76`. A `reward: 24950`
  was enough. It asks the decoded map now. Found while adding the `dmint` block, which widened
  the surface.

- **`glyph deploy-dmint` under-sized the reveal fee, which could strand a confirmed commit.**
  The commit's vout 0 carries the only value the reveal ever gets, and it was sized from a flat
  `num_contracts × 260 + 400` byte estimate. Measured against the transaction the CLI actually
  builds, that estimate is short for **every V1 deploy with 2 or more contracts and for every
  V2 deploy** — it under-counts the per-contract ref-seed input and assumes a V1-sized 241-byte
  contract script when V2's is ~380. At `--num-contracts 50` the shortfall is ~6,600 bytes,
  i.e. the reveal is short by roughly 0.66 RXD of fee at the default rate. Because
  `Transaction.fee()` drops the change output rather than failing when the residual is too
  small, this surfaced as a silently over-paying reveal in the mild cases and an
  unbroadcastable one in the worst — after the commit was already confirmed and its value
  committed.

  The estimate is now computed from the real script bytes the builder produces (contract
  scripts, CBOR body length, premine and OP_RETURN outputs, worst-case push encodings), which
  is a tight upper bound — verified within 0.3–2% across V1/V2 × 1–50 contracts × premine
  on/off, with the change output now surviving in every case, so the surplus comes back to the
  deployer instead of going to the miner. A parametrised regression test asserts
  `estimate >= actual` over that same grid.

- **`--network` no longer selects a network while talking to a different chain
  (`Config.for_network`).** `for_network()` returned the **unchanged default endpoint**
  whenever the selected network had no `[networks.<name>]` block — and the default endpoint is
  mainnet's. On a stock config:

  ```
  --network regtest  -> network=regtest  electrumx=wss://electrumx.radiant4people.com:50022/   MAINNET
  --network testnet  -> network=testnet  electrumx=wss://electrumx.radiant4people.com:50022/   MAINNET
  ```

  A developer "testing on regtest" could broadcast a real transaction to mainnet while every
  status line said regtest. The fix has three parts:
  - **The top-level `electrumx` belongs to the top-level `network`, and nothing else.** It is
    no longer carried across a `--network` change. Resolution order is now: `--electrumx`
    flag → `[networks.N]` → the top-level endpoint *only when N is the config's own network* →
    pyrxd's shipped defaults for N.
  - **Fail closed when nothing resolves.** There is no guessing step. The resolved config
    carries a structured `EndpointGap` and every attempt to build a client raises it, naming
    the network, why the fallback was refused, the exact TOML table and key to add, the config
    file to add it to, and the one-off `--electrumx` escape. The failure is deferred to client
    construction (not config load) so offline commands — `wallet new`, the cold
    `swap build-refund`, `--help`, `setup` — still work on a machine with no endpoint for the
    selected network. Nothing that touches the network can proceed.
  - **The binding is verified, not merely declared.** New
    `ElectrumXClient.assert_chain(genesis_hash)` reads block 0 and compares the Radiant
    double-SHA-512/256 header hash against the expected genesis — mirroring
    `EthRpc.assert_chain`, which the ETH leg has had since it shipped. The failover client runs
    it once per endpoint before any read or broadcast, and a chain mismatch is **not** treated
    as a failover-able fault: it raises, because silently routing around a server that is on
    the wrong chain would hide both the misconfiguration and the attack. Genesis constants for
    all three networks were cross-checked against `Radiant-Core` @ `afdf57b1`
    `src/chainparams.cpp` **and** live nodes (mainnet against the reference node; testnet and
    regtest against a local `radiant-core:v3.1.1` container).

  `--network mainnet` is unchanged: same primary server, now with a second one behind it.

- **The swap harness recovery files now persist the locators the cold path needs.** All three
  gaps were verified against the writers: `scripts/dust_swap_run.py` printed the BTC HTLC
  funding outpoint but never wrote it; only `scripts/eth_swap_two_host.py` persisted the ETH
  contract address; and **no** writer persisted the covenant's `amount` parameter, which the
  covenant scriptPubKey is built from. The recovery file is written *before* funding so a
  crash cannot strand value, which is exactly why the post-funding locators were being lost —
  they existed only on the console. `scripts/_dust_swap_shared.py` gains
  `merge_into_mode_600()`, the atomic, still-owner-only update peer of the `O_EXCL`
  `atomic_write_mode_600()`, and the BTC/ETH runners use it to record
  `btc_funding_outpoint` / `eth_contract_address` / `rxd_covenant_amount`. The CLI reads them
  when present and accepts flags when they are not, so files written before this change
  still work.

### Security

- **The taker-side "did the maker actually lock the asset?" check now exists in the library**
  (`SwapCoordinator.taker_verify_asset_funding`, `RadiantCovenantLeg.verify_maker_asset_funded`).
  This closes hazard **HZ-1** of `docs/htlc-handshake-wire-format.md` — the mirror of HZ-3 above,
  and the cheaper attack, because the loss is the **whole** counter leg rather than a shortfall —
  and is recorded as threat-model **S24**.

  HZ-1 already stated the rule normatively: *"a taker MUST NOT fund the counter leg until it has
  confirmed the maker's asset lock on chain, at the agreed scriptPubKey, for the agreed value, at a
  depth the taker chose."* No library code enforced it. The check lived only in
  `scripts/btc_swap_two_host.py` and `scripts/eth_swap_two_host.py`, so any caller driving
  `SwapCoordinator` directly locked BTC (or ETH) against nothing. Driving the real coordinator
  against a chain where the covenant was never funded, on the pre-fix code:

  ```
  gate.ok=True | state=btc_locked | btc broadcasts=1 | radiant leg calls=[]
  ```

  `pre_btc_lock_check` returned `ok=True` and `taker_funds_btc` reached `BTC_LOCKED` having invoked
  **zero** methods on the Radiant leg — the library never read the Radiant chain. The maker holds
  both `p` and the BTC claim key from the moment it publishes the envelope, and the BTC claim leaf
  is `<H> OP_SHA256 OP_EQUALVERIFY <makerClaimPk> OP_CHECKSIG` with **no precondition that the asset
  was ever locked**, so a maker that locks nothing sweeps the taker's HTLC as soon as it appears.
  The taker's own refund does not open until `t_btc`. Loss: the full `btc_sats`.

  What the library now enforces, all fail-closed:

  - the covenant **scriptPubKey re-derived from the taker's own `terms`** (amount, `H`, the `t_rxd`
    CSV, both dest hashes, the asset REF) — never one the maker advertises — and a funded UTXO
    located at exactly that script;
  - the **on-chain value against `terms.radiant_amount` exactly**; an ambiguous UTXO set at that
    script refuses rather than picking one;
  - a **confirmation depth**. "Funded" alone is not enough: ElectrumX `listunspent` includes
    mempool outputs, so a maker can fund with a replaceable transaction, wait for the taker's lock,
    then double-spend the funding away — it still claims the counter leg with `p`, and the vanished
    covenant leaves the taker nothing to claim;
  - and the gate is **non-skippable**: it is step 5 of `pre_btc_lock_check`, and `taker_funds_btc`
    **re-runs** it immediately before the counter-leg broadcast, which is what closes the
    verify→lock TOCTOU. The re-run sits *before* the `SeenStore` reserve so the reserve keeps its
    "last step before the only broadcast" property and a refusal does not burn `H`.

  The depth pin reuses the existing policy knob: a real-value (`MarginPolicy.is_measured`) swap
  requires `rxd_claim_burial` confirmations on the covenant funding — the same depth the
  claim-finality gate requires of the taker's own Radiant claim — while an estimated/test policy
  defers to the leg's `min_confirmations` (the operator's `--taker-min-rxd-confs`). Same
  `is_measured` discipline as the ETH `finalized` pin and the maker-side BTC depth above.

  Both operator scripts now call the library version instead of carrying their own copy, so there is
  one implementation and no drift.

  **Breaking for direct `SwapCoordinator` callers, and for the `-m integration` suites.** A
  `radiant_leg` that does not implement `verify_maker_asset_funded` now fails the pre-lock gate
  closed (a leg that cannot be verified cannot be verified at all), and the maker's covenant must be
  funded and buried **before** `taker_funds_btc` is called. The six `-m integration` end-to-end
  suites still fund the covenant *after* that call — the pre-HZ-1 order the hazard names as unsafe —
  and must be reordered before they will pass. They are deselected from `task ci` and require live
  bitcoind/radiantd/anvil nodes, so that reordering is **not** included here and is a tracked
  follow-up rather than an unverified blind edit.
- **The ref-opcode walker diverged from Radiant consensus on `0xd4`–`0xd7`, and could report a
  phantom ref while dropping the real one.** `REF_OPCODES` was `frozenset(range(0xD0, 0xD9))` —
  the contiguous `0xd0`–`0xd8` range — and the walker advanced 37 bytes for every member.

  Radiant consensus consumes a 36-byte operand for exactly five opcodes: `OP_PUSHINPUTREF`
  `0xd0`, `OP_REQUIREINPUTREF` `0xd1`, `OP_DISALLOWPUSHINPUTREF` `0xd2`,
  `OP_DISALLOWPUSHINPUTREFSIBLING` `0xd3` and `OP_PUSHINPUTREFSINGLETON` `0xd8`
  (`GetScriptOp`, Radiant-Core `src/script/script.cpp:710-716`; `CScript::GetPushRefs`,
  `:586-590`). The four in between — `OP_REFHASHDATASUMMARY_UTXO`, `OP_REFHASHVALUESUM_UTXOS`,
  `OP_REFHASHDATASUMMARY_OUTPUT`, `OP_REFHASHVALUESUM_OUTPUTS` (`script.h:281-284`) — are
  operand-less stack operations that merely sit inside the same byte range.

  A `0xd4`–`0xd7` in opcode position therefore swallowed the following 36 bytes and desynchronized
  the walk. The failure mode is **layout-dependent**, which is what makes it dangerous: sometimes
  the walk resumes on a byte that is not a valid single-byte opcode and `TruncatedScriptError` is
  raised (fail-closed, merely wrong), and sometimes it resumes on one that is — `0x00` for any
  ref whose vout fits in one byte — and resynchronizes **silently**. Demonstrated on
  `[0xd4][0xd0][36-byte ref][P2PKH]`, where consensus sees one push-ref and the old walker
  reported a phantom ref shifted by one byte, with the real ref absent and no exception raised.

  This matters because `count_input_refs` / `is_token_bearing_script` classify **arbitrary chain
  scripts**, not just pyrxd's own: the dMint funding-UTXO guard (`glyph/dmint/chain.py`), the HTLC
  covenant phantom-ref guard (`gravity/htlc_covenant.py`) and the soulbound classifier
  (`glyph/soulbound_detect.py`) all build on them. A token-bearing UTXO misclassified as plain
  funding can be spent as a fee input, silently burning the token. pyrxd's own FT (75 B) and NFT
  (63 B) locking scripts contain no `0xd4`–`0xd7`, so simple pyrxd-generated tokens were never
  affected; the exposure is foreign covenants and any script using the REFHASH opcodes — which
  exist precisely for covenant use.

  A second walker had the same defect independently: `extract_owner_pkh`
  (`glyph/credential_binding.py`) hard-coded `0xD0 <= op <= 0xD8`. It backs the anti-rental
  credential gate, which compares the extracted owner against the swap's pinned payout. On a
  script where the consensus-correct walk finds two candidate pkhs and therefore refuses to name
  an owner (returns `None`, fail-closed), the old walk stepped clean over the first and
  confidently returned the second — a wrong owner presented as the right one. Both walkers now
  share the single `REF_OPCODES` constant, as do the two local copies in `htlc_covenant.py` and
  `soulbound_covenant.py` that already held the correct five-opcode set.

  Locked by `TestRefWalkerConsensusDifferential` (`tests/test_glyph.py`), which differentials the
  walker against a port of Radiant's `GetScriptOp` over every opcode `0xd0`–`0xd8` in varied
  positions plus a 3,000-script seeded sweep, and by three cases in `tests/test_credential_binding.py`.
  No conformance vector, golden fixture or existing test encoded the wrong behaviour: a sweep of
  1,285 hex blobs across `conformance/`, `tests/` and `src/pyrxd/` found zero whose ref-walk
  changes under the fix.

- **A token's royalty `minimum` was unbounded and paid by default, out of the funding inputs of
  whoever moved the token.** `GlyphRoyalty.minimum` only has to be `>= 0`; nothing at mint time
  and nothing on chain bounds it. `royalty_due` returned `max(minimum, pct)` with no ceiling, so
  a token declaring `minimum = 10**15` charged that against a plain transfer — a wallet that
  passed the royalty *because it was trying to be honest* paid it. Two bounds now:

  - **`royalty_due` is capped at `sale_price`.** A royalty larger than the consideration is not
    a royalty. `minimum` raises the payment toward the sale price and cannot raise it past.
    Behaviour change: a `minimum` with `sale_price = 0` now resolves to 0, which removes the
    flat-fee-on-a-gift reading the module used to document beside its own statement that "a gift
    has no price". That reading *was* the unbounded-spend path.
  - **`enforced` is honoured instead of ignored.** `pay_royalty` becomes three-way:
    `None` (the new default) pays iff `royalty.enforced`, `True` pays an advisory royalty
    anyway, `False` never pays. The flag is the creator's own statement about whether wallets
    should insist and it defaults to `False` everywhere a `GlyphRoyalty` is built; paying
    regardless spends the sender's photons on a payment the creator did not ask to be insisted
    on. Keeping the `True` override is what stops this collapsing into Photonic's behaviour,
    where "advisory" is implemented as "never paid".

  Royalties remain **advisory, not consensus-enforceable** — that is a documented design fact
  (`docs/solutions/design-decisions/royalties-are-advisory-not-consensus-enforced.md`) and
  nothing here changes it.

- **`glyph airdrop-ft` and `glyph transfer-ft` did not pin recipient addresses to the active
  network.** `address_to_public_key_hash` decodes any well-formed base58check P2PKH address and
  returns its hash160 whatever the version byte, so a testnet-prefixed address (`m…`/`n…`)
  pasted into a mainnet command produced a valid-looking PKH and an output locked to a script no
  mainnet key can spend. Tokens are not recoverable from that: no refund path, and no RBF to
  pull the transaction back. `wallet sweep` and `wallet send` have pinned the network for
  exactly this reason; both glyph paths now do the same. An airdrop file is where a stray line
  survives review, and it pays N recipients in one irreversible transaction.
- **A malformed WIF is no longer echoed back, disclosing the private key it failed to decode.**
  `pyrxd.base58.b58_decode` raised `ValueError(f"invalid base58 encoded {encoded}")`. `PrivateKey(wif)`
  reaches it through `decode_wif`, `swap recovery` reaches `PrivateKey(wif)` through `_pkh_from_wif`
  (both from an explicit `--wif` and from a `*_rxd_wif` field in a hand-edited recovery file), and
  the CLI error boundary prints `cause: {exc}` for anything that is not a `NetworkError`/`OSError`.

  So a WIF with **one** character outside the base58 alphabet — a line wrap, a stray space, an
  `O`/`I`/`l` typo — printed **51 of its 52 characters** to stderr, into terminal scrollback and
  into any pasted bug report. A few thousand checksum-verifiable candidates recover the key from
  that. Reproduced end to end; the regression suite
  (`tests/security/test_key_material_never_echoed.py`) measured 51/52 before the fix and 0/52 after.

  The fix is at the **source**, not at the call site, because the decoder cannot know what it was
  handed: by the time a string reaches `b58_decode` there is no type information left saying "this
  one is public". It now treats every input as secret and raises a new
  `pyrxd.security.errors.Base58Error` carrying a static message and `from None`, so the input cannot
  resurface through `__cause__` in a traceback either. Every other raise in the base58/keys/WIF path
  was audited for the same pattern and made static: the base58check **checksum mismatch** (which
  reported both the caller's trailing bytes and `hash256` over the decoded payload — for a mistyped
  WIF, that payload *is* the private key), `decode_address` (which echoed a WIF pasted into an
  address field verbatim), `decode_wif`'s unknown-version-byte branch, and the second, independent
  base58 implementation in `pyrxd.utils.from_base58`. The mistyped-xprv path through
  `Xkey.__init__` is closed by the same source fix.

  `Base58Error` subclasses **both** `ValidationError` and `ValueError`: `base58` raised a bare
  `ValueError` for the SDK's whole history and callers across the CLI, `hd`, and `gravity` still
  catch that, so the class widens rather than swaps.

- **A per-network `fee_rate` no longer bypasses the relay-floor guard.** `_validated_fee_rate` ran
  only in `load()`. `Config.for_network` applied `overrides.get("fee_rate")` from the
  `[networks.<net>]` table with no floor check at all — and `cli/main.py` routes **every**
  invocation through `for_network`. The guard added for the top-level key in `e0772e0` was therefore
  bypassable by moving the same value one table down: a top-level `fee_rate = 100` was correctly
  rejected, while

  ```toml
  network = "mainnet"
  [networks.mainnet]
  fee_rate = 100
  ```

  yielded `for_network("mainnet").fee_rate == 100` against a 10,000 photons/byte floor. Every
  mint/transfer/send then built ~100x under floor, and Radiant has **neither RBF nor CPFP**
  (threat-model S21), so those transactions cannot be bumped by any means and squat on their own
  inputs until mempool expiry (8h). The per-network value now goes through the same guard, the
  message names the `[networks.<net>]` table and the file rather than a top-level key that is not
  the one in force, and a non-integer value there is a typed `ValidationError` instead of a bare
  `int()` `ValueError` escaping the config boundary.

- **The network name is normalized and validated; an unknown one is refused.** `load()` took
  `PYRXD_NETWORK` / the config `network` key verbatim, with no `.lower()` and no membership test —
  the only check was a `strip()` truthiness test. `PYRXD_NETWORK=REGTEST` therefore produced a
  config whose network was the literal string `"REGTEST"`, and three things went wrong at once:
  the lowercase `[networks.regtest]` table never matched; `network == cfg.network` compared **equal**
  (both sides being the same env string), so the **top-level mainnet server list was inherited**; and
  `genesis_hash_for("REGTEST")` returned `None`, which made `FailoverElectrumXClient._client_for`
  skip `assert_chain` **entirely**.

  A run the operator believed was regtest talked to a mainnet server with the one check that would
  have caught it disabled. `--network REGTEST` was safe only by accident, because `click.Choice`
  lowercases it first. Names are now `strip().lower()`-normalized and checked against
  `KNOWN_NETWORKS` in both `load()` and `for_network()` (the latter because that is what the CLI
  always calls, and a library caller can build a `Config` without going through `load` at all), and
  `cli/main.py` reads the network back off the resolved config rather than reusing its raw input.

  Relatedly and independently: `FailoverElectrumXClient` now **fails closed** when
  `verify_chain=True` and the profile carries no genesis hash, instead of silently performing no
  chain check. A check that quietly turns itself off is worse than no check, because it is believed.
  Opting out requires the explicit `verify_chain=False`.

- **`_coerce_xpub` re-validates an `Xpub` instance instead of trusting its type.** The
  `Xpub`-instance branch returned `str(xpub)` with no re-validation while the string branch had an
  explicit raise. `Xkey.payload` is a plain mutable attribute and `Xkey.__str__` re-encodes it on
  every call, so an object that passed `Xpub.__init__` can afterwards be made to serialise an
  **xprv** (`xp = Xpub(str(acct)); xp.payload = master_xprv.payload`) — and the emitted descriptor
  would carry the wallet's spending key to wherever it was pasted. Not reachable from `src/` today;
  fixed anyway, because this is the boundary where a private key becomes a published string and the
  guard belongs there explicitly rather than resting on how every caller happens to construct its
  argument. The key body is now asserted to be a compressed public point (SEC1 prefix `0x02`/`0x03`),
  and the refusal message and its whole cause chain are checked to carry no part of the key.

- **`HdWallet.load_or_create(..., normalize=False)` refuses to create.** It silently **minted** a
  new wallet on the legacy unnormalized BIP39 seed when the path did not exist. That mode is a
  fund-recovery escape for pre-0.12.0 wallets with non-ASCII passphrases — there is nothing to
  recover at a path with no wallet on it, and the likeliest way to reach that branch is a typo in
  the path, which is exactly the failure `load_or_create` was split out of `load` to make visible.
  A wallet created that way derives from a seed no other BIP39 implementation reproduces. The load
  branch is unchanged.

- **`--fee-rate` is floor-checked, and its help text no longer says "per kB".** `wallet send` and
  `wallet sweep` validated only `> 0`, making the flag the one remaining path into a spend that
  could still set a rate the network will not relay (same no-RBF/no-CPFP consequence as above). The
  help said "photons per kB" while `hd/wallet.py` computes `fee = size * fee_rate` with size in
  **bytes** — understating the fee 1000x for anyone who read the help and did the arithmetic. Both
  now say "per BYTE" and both apply the relay floor, still before the mnemonic prompt.

- **`descriptor.verify_checksum` requires exactly one `#`.** `#` is a member of `INPUT_CHARSET`, so
  a doubly-checksummed string — `raw(deadbeef)#89f8spxm#4x0avkn4` — polymodded correctly and
  verified True, while Bitcoin Core's `descsum_check` rejects it and `descriptor_checksum` already
  refused to *create* one. Accepting what we will not emit, and what the consumer will not take, is
  the wrong half of that pair to be lenient in.

- **The maker-side "did the taker fund the right HTLC for the right amount?" check now exists in
  the library for a BTC counter leg** (`SwapCoordinator.maker_verify_counter_funding`,
  `BitcoinTaprootLeg.verify_counterparty_funded`). This closes hazard **HZ-3** of
  `docs/htlc-handshake-wire-format.md` — the BTC analogue of a gap fixed on the ETH side and
  labelled a red-team CRITICAL — and is recorded as threat-model **S23**.

  The swap runbook is taker-funds-the-counter-leg-first, maker-locks-the-asset-second, so the maker
  commits its own value against a leg the counterparty built. On BTC the coordinator previously
  **refused** to provide that check, on the stated grounds that "a BTC counter leg's funding target
  is pre-derivable and bound by the derive==promised gate". That reasoning was wrong twice over: the
  funding *address* is bound, but a P2TR scriptPubKey commits to the **taptree, not the output
  value**; and the amount bind that does exist lives inside `taker_funds_btc` — the *taker's own*
  method — which a hostile taker simply never calls, funding the freely-derivable HTLC address
  directly instead. A taker who funded the correct address short therefore passed every check in the
  handshake: the maker locked its asset, claimed the under-funded BTC (revealing `p`), and the taker
  claimed the full asset. The maker is paid less than the agreed price — a one-sided loss reachable
  in the intended two-party flow by anyone driving `SwapCoordinator` directly rather than the
  shipped operator script, which had its own copy of the check.

  What the library now enforces, all fail-closed:

  - the funding output's **scriptPubKey**, re-derived from the maker's own `terms` and compared
    against the real output read from the chain (never against the counterparty-supplied locator,
    every field of which is attacker-chosen — it can describe a correct HTLC tree while pointing the
    outpoint at a decoy the taker owns);
  - the **funded amount against `terms.value_amount` exactly**. Over-funding is rejected as well as
    under-funding, matching the existing taker-side bind: the claim leaf does not cap value, so an
    over-funded HTLC is a one-sided *taker* loss;
  - **confirmation depth**, and that the output is confirmed and unspent;
  - and the gate is **non-skippable**: `post_asset_lock_revalidate` refuses `BOTH_LOCKED` (the state
    that enables the `p` reveal) without a verified locator on the record, and **re-runs** the
    verification at asset-lock time, which is what closes the verify→lock TOCTOU — a reorg, or a
    taker who funds only after the maker looked, is caught there rather than after the asset moves.

  The depth pin reuses the existing policy knob rather than inventing a second notion of BTC
  finality: a real-value (`MarginPolicy.is_measured`) swap requires `btc_claim_reorg_depth`
  confirmations on the funding — PoW finality *is* a confirmation depth — while an estimated/test
  policy defers to the leg's `min_confirmations`. This mirrors the ETH gate's
  `block_identifier='finalized'` pin and the same `is_measured` discipline the N-floor and the
  cross-clock margin already use. **Operator note:** a mainnet run on a measured policy will now
  wait for that depth before the maker's asset lock is allowed to complete; the refusal is a
  retryable `InsufficientConfirmationsError` and leaves the record at `BTC_LOCKED`.

  `scripts/btc_swap_two_host.py` now calls the library version instead of carrying its own, so there
  is exactly one implementation. `MempoolSpaceFundingReader` and `MultiSourceBtcFundingReader` gained
  `read_confirmed_unspent_output` (Esplora status + tx + outspend, quorum'd in the multi-source case)
  so the check works where there is no local node; a reader that cannot answer it refuses the lock
  rather than proceeding.

  Adversarial coverage: `tests/test_btc_maker_counter_funding_adversarial.py` drives the real
  coordinator and the real `BitcoinTaprootLeg` against a hostile chain view — under-funded,
  over-funded, decoy scriptPubKey, insufficient depth, spent/unconfirmed, and verified-then-reorged.
  The under-funded case was confirmed to reach `BOTH_LOCKED` against a 70,000-sat HTLC on a
  100,000-sat swap before the fix.
- **A present-but-falsy `spent` no longer reads as UNSPENT** (`MempoolSpaceFundingReader.
  read_confirmed_unspent_output`). The guard was `bool(spend.get("spent", True))` with a comment
  claiming "missing/ambiguous -> treat as SPENT (fail-closed)", but the `True` default only covered
  a **missing** key: `{"spent": null}` — what an Esplora-shaped server emits for "no data" — and
  `{"spent": 0}` / `{"spent": ""}` / `{"spent": []}` all evaluated falsy and were read as unspent.
  `_MempoolHttpClient.outspend` only checked `"spent" in data`, so the null form passed the wire
  check too. Only the boolean `False` now means unspent; anything else refuses at both layers.

  This read backs the maker-side counter-funding gate added above, so a hostile or buggy source
  could present an already-swept HTLC output as live and the maker would lock its own asset against
  BTC that is already gone.
- **Fund-safety reads on the BTC path now survive a hostile server's non-finite numbers, and bind
  the transaction they were answered about.** `json.loads` accepts the non-standard `Infinity` /
  `NaN` literals, and `int(float('inf'))` raises `OverflowError` — which is not a `NetworkError` and
  was absent from the `(KeyError, IndexError, TypeError, ValueError)` fail-closed tuples, so a
  crafted response turned a value read into a bare traceback that escaped every `except
  NetworkError` on a value-moving path. (`network/confirm.py` already guarded this shape; the BTC
  reads did not.) Separately, `read_output_amount_sats` and `read_confirmed_unspent_output` never
  checked that `/tx/{txid}` echoed the txid they asked for, so a single malicious source could serve
  **another transaction's** favourable `(scriptPubKey, value)`. Both now refuse.
- **An "already known" broadcast rejection is honored only when a read-back confirms it**
  (`FailoverElectrumXClient.broadcast`). After a transport failure on one endpoint, a later endpoint
  answering RPC `-27` / `txn-already-known` was treated as success — so a hostile or broken
  secondary could make `broadcast` report a live transaction, and a live txid, for something no node
  ever accepted. The claim is now corroborated by asking that endpoint for the transaction and
  requiring the same bytes back; a node that cannot produce what it claims to hold is skipped like
  any other failure. Residual, stated plainly: an endpoint corroborates its own claim, so a fully
  hostile endpoint that both rejects with `-27` and echoes the bytes still passes — what this
  removes is the far cheaper failure of a `-27` backed by no transaction at all.
- **Deadline-aware fee sizing for time-critical HTLC spends.** The only fee guard on a
  Radiant covenant spend was a flat `if fee.value < 546: raise` — a Bitcoin dust floor. At
  the reference mainnet node's advertised `effective_minrelaytxfee` (0.10 RXD/kB) a covenant
  spend of a few hundred bytes needs on the order of **2,600,000 photons**, about **4,900×**
  that floor. Because the covenant enforces a single output there is no change, so the entire
  fee input is the miner fee — an under-sized fee UTXO produced a transaction no node would
  relay.

  This matters far more on Radiant than the same bug would on Bitcoin. **Radiant supports
  neither RBF nor CPFP** (verified against `Radiant-Core` @ `afdf57b1` and the live mainnet
  node): mempool conflicts are rejected outright (`txn-mempool-conflict`, no `bumpfee` RPC),
  and the miner selects on each transaction's *own* fee over its *own* size
  (`GetModifiedFeeRate()`), so a high-fee child cannot lift a low-fee parent. An under-fee'd
  time-critical claim or refund therefore **cannot be repaired by any means** — it squats on
  its own inputs until mempool expiry (`DEFAULT_MEMPOOL_EXPIRY` = **8 hours**). If the swap
  deadline falls inside that window, the asset is lost to the counterparty's refund. Fee
  pre-sizing is the only available control. (Conversely: BIP125 mempool *pinning* does not
  apply to Radiant, because nothing is replaceable.)

  New in this release:

  - **`pyrxd.gravity.fee_policy`** — a pure, injectable `DeadlineFeePolicy`.
    `min_relay_fee(size)` is the derivation `ceil(size × rate / 1000)`;
    `urgency_multiplier(blocks_to_deadline)` is a linear ramp above it inside a 6-block
    horizon (a documented **policy choice**, not a measured inclusion model — no Radiant
    fee/confirmation curve has been measured). The rate is a **parameter, not a constant**:
    `effective_minrelaytxfee` is node policy and moves, and
    `photons_per_kb_from_rxd_per_kb()` converts a `getmempoolinfo` reading directly.
  - **The relay floor is a gate; the urgency premium is only a TARGET.** `assert_fee_covers`
    raises **only** below `min_relay_fee(size)` — the node's real requirement — and otherwise
    *returns* the premium-inclusive `required_fee(...)` for the caller to log against and size
    its pool by. Gating on the premium would be a fund-loss bug, not a safety measure: the
    node would have accepted the transaction, refusing does not reduce the fee paid (the whole
    input is the miner fee on a single-output covenant), and on the claim path the
    counterparty's CSV refund then takes the asset. Because the premium *rises* as the
    deadline closes, a hard gate on it would refuse hardest exactly when claiming matters
    most — including `taker_claim_asset_from_vulnerable`, whose entire purpose is to race
    that deadline.
  - **`DeadlineFeePolicy` bounds its own injected rate.** In production the rate is read from
    a **node** (`getmempoolinfo`), so it crosses a trust boundary: a lying or misconfigured
    endpoint advertising, say, 0.00000001 RXD/kB would otherwise yield a "floor" of ~1
    photon/kB, thousands of times under the real requirement, and the resulting spend is
    unfixable for 8 hours. A rate below `protocol_floor_per_kb` is now refused at
    construction. That bound is **per-chain** (Radiant photons/kB vs Bitcoin sats/kB), and
    `allow_below_protocol_floor=True` is the explicit, greppable opt-out for regtest or a
    chain you control.
  - **`build_htlc_claim_tx` / `build_htlc_refund_tx`** now refuse to return a transaction
    below the relay floor, sized against `len(tx.serialize())` — the exact wire bytes,
    measured after signing, never an estimate. Both accept an optional `fee_policy`.
  - **`RadiantCovenantLeg`** computes the **deadline-aware** target immediately before
    broadcast. On the claim path blocks-to-deadline is `t_rxd − covenant confirmations` (the
    maker's CSV refund branch opens at that depth). Below the node's floor it refuses, logs at
    ERROR, and raises rather than emitting an unrepairable transaction. **Above the floor but
    below the urgency target it broadcasts and logs a WARNING** — inclusion may be slow, but a
    slow claim beats a claim that never goes out. Accepts an optional `fee_policy`.
  - **`watch/claim_executor.py`** maps a fee shortfall to `DECLINED` (which pages) with the
    exact shortfall, and **deliberately does not mark the swap seen**, so a later tick can
    still claim. `CappedFeeWalletSource` is dispense-once ("the returned UTXO is never
    returned again") and dispenses in pool order, so the next tick hands out a *different*,
    possibly larger input — a pool ordered small-first would otherwise have had its claim
    permanently disarmed by the first small dispense while covering inputs remained. Retry
    cost is bounded: the pool is capped and dispense-once, so its cursor advances at most one
    input per tick and cannot run past its own cap.
  - **`watch/executor.py`** (BTC pre-signed refund) declines a blob whose implied fee is not
    viable. Deliberately sized on a **lower bound** of the true vsize requirement, so it can
    never falsely refuse a refund the node would have accepted.
  - **No RBF or CPFP path was built, and none should be.** Both are absent from the chain;
    "just bump the fee" is Bitcoin semantics assumed onto a BCH-lineage chain. Recorded in
    `docs/threat-model.md` (**S21**) and `docs/runbooks/watchtower-operations.md`.

### Documentation

Three corrections from a pre-release audit, each verified against the code rather than restated.

- **`credential_ref` is off-chain policy, not a covenant binding** —
  `docs/htlc-handshake-wire-format.md` §4. The section claimed that because every negotiated
  Radiant parameter is substituted into the covenant bytecode, "this single byte-comparison
  revalidates all of them at once", and the `terms` table described `credential_ref` as a gate
  the taker must satisfy. `credential_ref` is the one exception, and a load-bearing one: no
  covenant builder takes a credential parameter (`gravity/htlc_covenant.py:391-419`), and the
  `btc-rxd-credential-gated` conformance vector's `covenant_scriptpubkey_hex` is **byte-identical**
  to plain `btc-rxd`. Enforcement is a pre-fund, off-chain check by whichever party runs it
  (`swap_coordinator.py:1241-1266`); nothing on chain stops an uncredentialed party who learns
  `p` and can produce the pinned holder script from claiming. §4 now carves the exception out
  explicitly, and the conformance suite **asserts** the SPK equality as the expected property
  (`test_credential_gating_does_not_change_the_covenant_spk`, plus a structural check that no
  builder has grown a credential parameter) instead of passing for the wrong reason — the gated
  vector previously re-derived correctly only because the builder was never told about the
  credential.

- **A measurably false claim about `decode_payload` removed** —
  `docs/reference/glyph-token-protocol-spec.md` §4.4. It stated the 100 KB `main.b` ceiling was
  enforced by the `GlyphMedia` constructor "but **not** by `decode_payload`… pyrxd decodes media
  it would refuse to construct". It does: `decode_payload` constructs a `GlyphMedia`
  (`glyph/payload.py:122`), so the cap in `glyph/types.py:116-117` fires. Measured — 100,000 bytes
  decodes, 100,001 raises `ValidationError`. The sentence is gone, the `main.b` case is added to
  §4.5's MUST-reject list, and both the boundary and a 150 KB body are now pinned by tests.

- **`genesis_ref` — what is actually enforced, and where** —
  `docs/htlc-handshake-wire-format.md`. The table said "Empty for `rxd`; 36 bytes for `ft`/`nft`"
  and cited `swap_state.py:339-341`, which only checks **non-emptiness**. The 36-byte length is
  caught later, fail-closed, at `htlc_covenant.py:194-195` — so a reader must not infer
  `len(genesis_ref) == 36` from `NegotiatedTerms` having accepted a document. And a non-empty
  `genesis_ref` on an `rxd` swap is accepted and silently ignored: it round-trips through the wire
  form and changes no derived value, so two `rxd` documents differing only there describe the same
  swap. A new sub-section states each case and where it is (or is not) checked, and three tests pin
  it. Documented rather than fixed — rejecting it would be a wire-format break.

- **The ref-opcode range corrected wherever it was stated as contiguous** —
  `docs/reference/glyph-token-protocol-spec.md` §2.2 (now carrying the full per-opcode table and
  the consensus citations), `docs/concepts/v1-mint-mechanics.md`, and the docstrings in
  `glyph/dmint/chain.py`. See the Security entry above.

### Upgrade notes

- **Operator-visible break: an unknown or mis-cased `network` name is now REFUSED at config
  load.** `PYRXD_NETWORK` and the config file's `network` key are `strip().lower()`-normalized
  and must be one of `mainnet` / `testnet` / `regtest`. `PYRXD_NETWORK=REGTEST` previously
  "worked" — by inheriting the top-level *mainnet* endpoint with the chain check silently
  disabled — and now resolves correctly to regtest; a typo such as `mainet` now fails with a
  message listing the known names instead of running against a chain it cannot verify.
  `PYRXD_NETWORK=` (empty) still means "unset" and falls through to the file/default.

- **Operator-visible break: a `[networks.<net>] fee_rate` below the relay floor is now REFUSED**,
  as a top-level `fee_rate` already was. If you carry a low per-network rate for a local regtest
  indexer, raise it to at least 10,000 photons/byte (the default) — a sub-floor transaction
  cannot be fee-bumped on Radiant and squats on its inputs until mempool expiry.

- **Operator-visible break: `wallet send --fee-rate` / `wallet sweep --fee-rate` now apply the
  same relay floor**, and their help text now correctly reads **photons per BYTE** (it said
  "per kB"; the code has always been per byte). The refusal happens before the mnemonic prompt.

- **Library break: `HdWallet.load_or_create(..., normalize=False)` on a path with no wallet file
  now raises `ValidationError` instead of creating one.** `normalize=False` is a recovery mode for
  pre-0.12.0 wallets; drop it to create a new wallet. The load branch is unchanged.

- **Library break: `FailoverElectrumXClient(profile)` with `verify_chain=True` (the default) now
  raises when `profile.genesis_hash is None`**, rather than skipping the chain check. Pass
  `verify_chain=False` to accept an unverified chain binding explicitly.

- **Library note: `pyrxd.base58` and `pyrxd.utils` decode failures now raise
  `pyrxd.security.errors.Base58Error`** with a static message that never contains the input.
  `Base58Error` subclasses both `ValidationError` and `ValueError`, so existing
  `except ValueError` and `except RxdSdkError` handlers keep working; only code matching on the
  *message text* needs updating.

- **Operator-visible break: `--network testnet` / `--network regtest` now REFUSE to run a
  network command unless you configure an endpoint for that network.** Previously they
  "worked" by using the mainnet server. Add to `~/.pyrxd/config.toml`:

  ```toml
  [networks.regtest]
  electrumx = "ws://127.0.0.1:50022/"
  allow_insecure = true          # required for plaintext ws://; regtest only
  ```

  or pass `--electrumx <url>` for a one-off run. The error message contains this snippet.
  `--network mainnet` needs no action.

- **`Config.electrumx` on a freshly `load()`-ed config is now `""` when nothing was
  configured, instead of the mainnet URL**, and `for_network()` takes a new keyword-only
  `electrumx_override`. Read endpoints from `Config.endpoints` (or `require_profile()`) after
  calling `for_network()`. Library users constructing `ElectrumXClient` directly are
  unaffected.

- **Broadcast retry semantics, stated explicitly.** `FailoverElectrumXClient.broadcast()`
  replays the *same serialised transaction* on the next endpoint after a **transport**
  failure. That is safe here for three reasons, and unsafe without them:
  1. The bytes are captured once, before the first attempt. The dangerous shape of this
     feature takes a *builder callback* and re-runs it — a rebuild can pick different UTXOs,
     a different fee, or a different signature, and broadcasting a different transaction that
     spends the same inputs is a double-spend attempt, not a retry. Radiant has **no RBF**
     (`src/validation.cpp:667` rejects any mempool conflict as `txn-mempool-conflict`), so a
     conflicting sibling cannot *replace* the original — but it can be the one that gets mined
     and strand the transaction the caller believes it sent. The signature is
     `broadcast(raw_tx: bytes)` precisely so the class cannot rebuild anything.
  2. The txid is a pure function of those bytes, so a retry cannot change the identity of what
     was sent, and a server returning a different txid is refused.
  3. Only transport failures trigger it. A node verdict is returned to the caller immediately.

  The failure this fixes is the **lost response** — the node accepted the transaction and the
  socket died before the reply. Retrying then is necessary, not merely safe: otherwise the
  caller reports failure for a live transaction. A later endpoint answering `txn-already-known`
  / `txn-already-in-mempool` / already-in-chain is therefore treated as success. On the *first*
  attempt that same rejection still raises unchanged — with no transport fault to explain it,
  "already known" is information worth surfacing.

- **Operator-visible break: a covenant claim/refund funded below the node's relay floor is now
  REFUSED at build time.** Previously it was built and broadcast, and then silently failed to
  confirm — which, given no RBF and no CPFP, was unrecoverable within the 8-hour mempool
  window. The refusal raises `InsufficientFundsError` (a `ValidationError` subclass, so
  existing `except ValidationError` handlers keep catching it) carrying
  `available` / `required` / `shortfall`, and the message names all three. `required` is the
  **relay floor**, not the urgency target — it is the number you must clear to get the spend
  relayed at all.
  **Action:** size fee UTXOs at **0.1–0.2 RXD** each rather than dust. If you target a node
  whose `effective_minrelaytxfee` differs from the 0.10 RXD/kB default, pass an explicit
  `fee_policy` instead of relying on the default.
- **Funding at the bare floor is not an error.** The urgency premium is a funding *target*.
  A spend that clears the floor but not the target still broadcasts; you get a WARNING and
  possibly a slower inclusion, never a refusal. Size the pool against
  `DeadlineFeePolicy.required_fee(size, blocks_to_deadline=0)` (3× the floor at defaults) if
  you want deadline-critical claims to carry headroom.
- The historical 546-photon dust floor is **retained** as a floor. It is now the cheap
  pre-check, not the requirement.
- **`DeadlineFeePolicy` now refuses a sub-floor `relay_fee_per_kb` at construction.** If you
  build a policy for a non-Radiant chain, pass that chain's own `protocol_floor_per_kb`
  (units are per-chain: photons/kB vs sats/kB) — `DEFAULT_BITCOIN_DEADLINE_FEE_POLICY`
  already does. For regtest or a chain you control, pass `allow_below_protocol_floor=True`.

## [0.13.0] — 2026-08-09

Feature release, and the follow-through on 0.12.0's security panel. Adds a **two-phase,
resumable Glyph mint** that makes the permanent-fund-loss window between commit and reveal
hard to fall into, and an **automatic second-channel escalation monitor** — the last open
piece of the watchtower's alerting chain. Alongside those, the remaining panel findings are
closed, including two the panel got subtly wrong (see `### Fixed`). No breaking-class
changes for an existing caller.

The cross-chain swap stack remains **unaudited** and the RSWP orderbook **experimental**.

### Upgrade notes

- **The watchtower heartbeat JSON gained `schema_version: 1`.** Additive, but a consumer
  asserting an exact key set will need updating. The escalation monitor refuses a payload
  shape it does not recognise, which is the point of the field.
- **`--ack-inbox` now refuses to start when the alerter cannot honour it.** Unreachable via
  the shipped `pyrxd-watchtower` (which always wires a `DedupAlerter`); it affects only
  programmatic callers assembling their own `Reconciler`. Previously that configuration
  silently destroyed every acknowledgement, so a refusal is strictly safer.
- **New console script `pyrxd-watchtower-escalate`** requires `--primary-webhook-url` (or an
  explicit `--allow-same-channel`) so that "escalate to a *distinct* channel" is enforced
  rather than assumed.

### Added

- **`pyrxd.glyph.mint` — a two-phase, resumable Glyph mint facade** (`GlyphMinter`).
  `commit_nft`/`reveal_nft` and `commit_ft`/`reveal_ft` are separable phases; `mint_nft`
  and `deploy_ft` compose each pair. The minter owns what every caller was
  re-implementing around `GlyphBuilder`: UTXO selection, sizing the commit so the reveal
  can pay its own fee, signing, the pre-broadcast fee guard, and confirmation polling.
  No new protocol code — the builders, `pyrxd.glyph.fees` and
  `pyrxd.network.wait_for_confirmation` already existed; this is the plumbing between
  them.
  - **Persistence is a required constructor argument, not an optional keyword.** The
    commit output is a hashlock (`OP_HASH256 <payload_hash> OP_EQUALVERIFY`) with no
    owner-only spend path, so losing the exact CBOR bytes between the commit and the
    reveal makes it **permanently unspendable**. An optional `persist=None` would default
    that fund-safety mechanism to OFF on the most discoverable method in the module.
    `JsonFilePendingStore` is the implementation; opting out means naming
    `UnsafeNullPendingStore`, which warns when constructed.
  - The `PendingMint` is written **before** the commit is broadcast — one `0600` file per
    record in a `0700` directory, `os.open`-created at mode (not `chmod`ed afterwards),
    `fsync`ed, `os.replace`d, then **read back and compared**. The read-back also runs in
    the minter, so it covers third-party stores whose `save` silently drops the record.
  - `PendingMint` carries `cbor_bytes` as **bytes** (hex only at the `to_dict` boundary),
    validates every field in `__post_init__`, and `from_dict` **rejects** an unrecognised
    `schema_version` rather than best-effort parsing a record that decides whether an
    output can be spent.
  - Before a reveal is built, the stored payload is re-hashed and the commit script
    rebuilt from it. A mismatch — tampered CBOR, a flipped NFT/FT flag, the wrong wallet —
    is refused instead of broadcast.
  - Protocol mixes whose reveal is a different shape (MUT, CONTAINER, WAVE, DMINT) are
    refused at commit time; committing to a reveal the facade cannot build would strand
    the output. Use `GlyphBuilder` directly for those.
  - Note on reproducibility: `encode_payload` is canonical CBOR, so identical metadata
    does re-encode to identical bytes. The bytes are stored because `GlyphMetadata`
    carries `created`/`commit_outpoint` and callers routinely stamp timestamps into
    `attrs`, so the metadata may not be reproducible in practice — not because the
    encoding is non-deterministic.
- **`pyrxd.glyph.mint.build_reveal_unlock_template`** — the Glyph reveal unlocking-script
  template, which existed in four copies (`pyrxd.cli.glyph_helpers` plus one in each of
  the three `examples/*.py` mint scripts). Each copy restated the estimated unlocking
  length that `pyrxd.glyph.fees` sizes the reveal fee from; a copy that drifted low would
  make the fee guard under-estimate and pass, stranding the commit.
- **`pyrxd.glyph.fees.commit_value_for_reveal`** (with `MIN_COMMIT_OVERHEAD` and
  `REVEAL_SIZE_SLACK_BYTES`) — promoted from a private helper in `pyrxd.cli.glyph_cmds`
  so the CLI and the new facade size commits from one function rather than two
  fund-safety constants free to drift apart.
- **`HdWallet.privkey_for_address`** — address → signing key via the recorded derivation
  path (one `ckd` chain, not a scan). The minter never persists key material, only the
  funding address, so the reveal has to re-derive the key that spends the commit.

- **Watchtower second-channel escalation monitor** (`pyrxd-watchtower-escalate`,
  `pyrxd.gravity.watch.escalation`). A third, separately-supervised process that reads the
  heartbeat's `unacked_critical` count and pages a **different** channel when a CRITICAL
  claim/squeeze page stays unacknowledged. The dead-man's-switch answers *is the tower alive?*;
  this answers *is the operator alive?* — the case the primary channel cannot report on itself
  (a muted app, a dead webhook receiver, a phone in a drawer). Previously the count was published
  but had no consumer: escalation was a manual, external step.
  - The threshold is measured in the **tower's** clock (deltas between beat `ts` values), not in
    monitor iterations — the monitor does not tick with the tower, so a tick-based threshold would
    fire at a wall-clock time that silently depended on the tower's poll interval.
  - `{first_unacked_ts, last_escalated_ts, fired}` is persisted `0600` beside the heartbeat
    (atomic tmp + `os.replace`), so a crash-restart loop cannot defer escalation indefinitely by
    rewinding an in-memory countdown.
  - Fail-closed reading of the count: an **absent** `unacked_critical` key refuses startup (it
    means the producer is not wired, which is not "zero"); the `-1` sentinel the tower writes when
    its count source raises **escalates immediately** (blind, not healthy); a **stale** beat does
    not escalate at all but emits one edge-triggered WARN, so the dead-man's-switch keeps sole
    ownership of the "tower is down" alarm and the escalation channel still proves it is alive.
  - Channel distinctness is **enforced**: the monitor refuses to start when its `--webhook-url`
    equals the tower's `--primary-webhook-url` (normalized compare) unless `--allow-same-channel`,
    and warns when the two merely share a host.
  - Recovery: an INFO page and a full state reset when the count returns to zero.
- **`schema_version` on the watchtower heartbeat JSON** (currently `1`). Purely additive —
  `heartbeat_age_s` and `DeadMansSwitch` read only `ts` — but it lets a consumer that interprets
  *more* than `ts` refuse a payload shape it does not know. The escalation monitor does exactly
  that. Upgrade the tower before the monitor.
- **`pyrxd.glyph.fees.measure_reveal_fee`** — measures a built reveal transaction
  instead of estimating one from shim scripts. Public because the independent
  pre-broadcast check is worth running from any commit/reveal flow, not just the CLI's.
- **`pyrxd.gravity.watch.AckingAlerter`** — a runtime-checkable protocol for an alerter
  that can consume operator acknowledgements. Deliberately separate from the
  reconciler's `Alerter` port, which does not need `ack` and should not require it of
  third-party alerters.

### Fixed

- **Flaky property test in `tests/test_eth_rxd_timelock.py`** (`test_converter_invariants_or_failclosed`,
  pre-existing and reproducible on released 0.12.0). The assertion `t.value * interval <= budget`
  failed by ~1e-11 s at `eth_timeout=54294, m4=4904, interval=1.1`. **The production function is
  unchanged** — `floor(budget / interval)` is the right, conservative choice. The failure is
  floating point on both sides of the comparison: the test recomputes the product as a double,
  *and* the production division itself rounds the true quotient (44899.999999999996) up to exactly
  44900.0, so `floor` returns one block above the exact floor. The combined overshoot is bounded
  by ~2 ULP of the budget (measured worst case: 1 ULP), against a real overshoot that would be at
  least one whole block — `interval` >= 1.0 s. The assertion now allows 8 ULP and explains why.

- **The watchtower's LOG heartbeat never saw the un-ACK'd CRITICAL count.** `run.py` wired
  `unacked_critical` into the *file* heartbeat but built `default_heartbeat` without it, so the
  log side fell back to its "not wired" `-1` forever: the tick line reported `unacked_critical=-1`
  next to a file heartbeat carrying the real count, and the ERROR-level escalation that fires on
  `unacked > 0` could never trigger (`-1` is not `> 0`).

The rest of this section is follow-ups to the eight-reviewer security panel run against
0.12.0. All MEDIUM; no fund-safety blocker among them. Each was re-verified against the
code before it was changed — one reviewer claim is corrected at the end rather than acted
on.

- **SDK exceptions are picklable again.** `ConfirmationTimeoutError` and its base
  `InsufficientConfirmationsError` take keyword-only arguments and derive `args` from
  them, so the `BaseException.__reduce__` default — which replays `args`
  *positionally* — raised `TypeError: __init__() takes 1 positional argument but 2 were
  given`. That broke `pickle`, `copy.copy`, and re-raising an SDK error across a
  `ProcessPoolExecutor` boundary, where the real failure was replaced by an opaque
  unpickling `TypeError`. `RxdSdkError.__reduce__` now rebuilds without replaying
  `args` through `__init__`, so **every** exception in the family round-trips —
  including any future keyword-only subclass. A parametrized test constructs every
  exported exception class by introspecting its signature and round-trips it, and fails
  loudly if a new constructor parameter appears that it does not know how to supply.
- **The reveal-fee guard is a real check, not a tautology.** `glyph mint-nft` and
  `glyph deploy-ft` sized the commit output from `estimate_reveal_fee` and then
  "verified" that same estimate with `check_reveal_funding` — but the commit value is
  `carrier + max(floor, estimate.fee + slack)`, so the check could never fail. It read
  as a fund-safety backstop and backed up nothing. Both commands now build the reveal
  transaction *before* broadcasting the commit (against a placeholder commit txid; a
  txid is 32 bytes whatever its value, so the size is identical) and measure the real
  thing with the new `pyrxd.glyph.fees.measure_reveal_fee`. The guard now fires if the
  estimator's shim — its prefix constant, locking-script sizes, or assumed output set —
  ever stops describing the transaction the CLI actually builds, which is the drift that
  would strand a commit output. The estimator itself was independently swept for
  under-estimates and found sound; this is about the *second* check being real.
- **`REVEAL_SIG_PREFIX_BYTES` has one definition.** `pyrxd.glyph.fees` defined `107` and
  `pyrxd.cli.glyph_helpers` hard-coded the same literal, with the fee module's comment
  naming the CLI-private helper as the source of truth — the wrong direction. Drift
  would have made the fee guard under-estimate *and* pass. The CLI now imports the
  constant.
- **The confirmation-timeout hint named a flag that does not exist.** It told the user
  to "re-run with `COMMIT_TXID=<txid>` to resume reveal". No such option or environment
  variable exists in the CLI — that spelling comes from the standalone `examples/*.py`
  demo scripts, which carry their own hard-coded metadata and cannot resume a CLI mint.
  Because the commit script has no owner-only spend path, a confirmation timeout can
  strand real value, so this sent a user with money at stake to a nonexistent recovery.
  The hint (and the matching section of the troubleshooting how-to) now describes the
  recovery that works: rebuild the reveal via `GlyphBuilder.prepare_reveal` from the
  same unmodified metadata file and the same wallet. Tests assert the hint names no
  undeclared flag and that the described procedure reconstructs a reveal satisfying the
  commit script's payload-hash covenant.
- **A hostile ElectrumX message no longer stalls the client's event loop.**
  `_sanitize_server_message` ran `splitlines()`, a per-character printability scan and a
  per-token `redact()` over the *entire* message before clipping the result to 200
  characters. Frames are capped at 10 MB and this runs on the receive-loop coroutine, so
  a large message blocked every other request in flight — measured **201 ms** on a 10 MB
  single-line message and 281 ms on 10 MB of short tokens, repeatable on every RPC
  error. The message is now clipped to 8 KiB *before* any of that work: the same two
  cases measure **0.2 ms** (~1000x). Sanitization semantics are unchanged — a
  parametrized test compares the output against the previous implementation verbatim for
  realistic messages, and a fragment left at the clip boundary is dropped rather than
  allowed to escape redaction.
- **The watchtower refuses `--ack-inbox` it cannot honour.** `Reconciler.alerter` is
  typed as the `Alerter` port, which declares `handle` and nothing else; `ack` belongs to
  `DedupAlerter`. The per-tick hook called `alerter.ack(...)` unconditionally, so with
  any other alerter it raised `AttributeError` inside a hook `run_loop` deliberately
  guards — the tower logged and kept running while `FileAckInbox.drain` had already
  claimed and deleted the inbox, destroying every acknowledgement in it, every tick. The
  shell now probes for the capability at startup (the same discipline already applied to
  `unacked_critical_count`) and refuses to start with a dead ACK path. Not reachable
  through the shipped `pyrxd-watchtower` entrypoint, which always wires a `DedupAlerter`;
  it bit programmatic callers assembling their own `Reconciler`.
- **`pyrxd.gravity.watch.run` passes `mypy --strict`** (14 errors → 0): missing
  annotations throughout, a `channels` list inferred as `list[LoggingAlertChannel]` that
  a `WebhookAlertChannel` could not join, and a `set.add()` return value used as a value
  in a dedup comprehension. CI's mypy scope is unchanged (`src/pyrxd/security/`) — this
  is a correctness cleanup, not a scope expansion.

## [0.12.0] — 2026-08-09

Correctness and hardening release. It fixes **four defects that could cost users funds or
strand assets**, closes a verified-exploitable local command-execution path in the watchtower,
and makes the watchtower installable for the first time. The cross-chain swap stack remains
**unaudited** and the RSWP orderbook **experimental** — an external audit and a genuine
two-party adversarial run are still the gates before real, adversarial value.

### ⚠ Breaking-class changes (read before upgrading)

Per [the versioning policy](docs/versioning-and-deprecation-policy.md), a `0.N → 0.N+1` minor may
carry breaking-class changes and must name them. These are they:

1. **BIP39 seeds change for non-ASCII passphrases.** Seeds are now NFKD-normalized, as BIP39
   requires. If you created a wallet with a passphrase containing non-ASCII characters, its
   derived addresses change and the wallet file no longer decrypts under the default path.
   **Your funds are reachable**: pass `normalize=False` to `HdWallet.load` / `from_mnemonic` /
   `discover` to derive the old seed and sweep to a conformant wallet. See
   [the recovery how-to](docs/how-to/recover-funds-across-wallet-paths.md). Inert for ASCII
   passphrases and for no passphrase, which is the overwhelmingly common case.
2. **`glyph mint-nft` and `glyph deploy-ft` report a different `ref`.** They now return the
   **commit** outpoint — the token's actual on-chain identity — instead of the reveal txid. Any
   ref you recorded from an earlier run is wrong and should be re-read from the chain. The tokens
   themselves were always correctly formed; only the reported identifier was wrong.
3. **The watchtower refuses configurations it previously accepted.** Secret and ACK-inbox files
   must be mode 0600 and owned by the running user; a symlinked secret file, a configured-but-empty
   secret, and an unauthenticated ACK inbox are all now refused. `--ssh-host` / `--ssh-container`
   no longer default to one operator's private infrastructure and are required when the ssh
   backend is selected. Existing deployments may need to `chmod 600` their files and add two flags.

### Added

- **`pyrxd.network.wait_for_confirmation`** — a public, testable confirmation poller
  with both time seams injected (`sleep` **and** `clock`, plus `max_iterations`),
  matching the pattern in `gravity.watch.daemon.run_loop` / `heartbeat.run_monitor`.
  It replaces the CLI's private `_wait_for_tx`, whose deadline came from
  `asyncio.get_event_loop().time()` — injecting a fake `sleep` did not advance that
  clock, so the timeout branch was unreachable in a test. It raises the typed
  `ConfirmationTimeoutError` rather than the CLI's click-based
  `NetworkBoundaryError`; `_wait_for_tx` is now just the click translation layer.

- **`pyrxd.network.electrumx.script_hash_for_script`** — derive an ElectrumX script
  hash from raw locking-script bytes. ElectrumX indexes *every* output, not just
  address-shaped ones, so this is what you need to ask for the history of a
  non-P2PKH script (the Glyph scanner uses it to find the reveal that spent a commit
  output). `script_hash_for_address` is now a thin wrapper over it.

- **`pyrxd.glyph.fees`** — reveal-size and reveal-fee estimation from the encoded CBOR
  payload (`estimate_reveal_fee`, `estimate_reveal_fee_for_metadata`,
  `check_reveal_funding`). The estimate runs the real `SatoshisPerKilobyte.compute_fee`
  over shim records rather than re-deriving the size arithmetic, so it cannot drift
  from the transaction the CLI then builds.

- **New typed errors** in `pyrxd.security.errors`: `InsufficientFundsError`
  (subclasses `ValidationError`, so every existing `except ValidationError` around the
  SDK's ~16 `"Insufficient funds…"` sites still catches it) and
  `ConfirmationTimeoutError` (subclasses `InsufficientConfirmationsError`, so a
  timeout stays distinguishable from a broken transport). `InsufficientConfirmationsError`,
  `PolicyRejection` and `FeePoolExhaustedError` were missing from the module's `__all__`
  and/or from `pyrxd.security`'s re-exports; all are exported now.
- **The HTLC watchtower's operational entrypoints are now pip-installable console
  scripts**: `pyrxd-watchtower`, `pyrxd-watchtower-deadman`, and `pyrxd-presign-refund`.
  Previously these lived under `scripts/`, which never ships in the wheel/sdist, so
  `pip install pyrxd` alone could not run them — a `[project.scripts]` entry point must
  resolve to importable package code. `watchtower_run.py`, `watchtower_deadman.py`,
  `watchtower_sshtr.py`, and `presign_refund.py` moved to `pyrxd.gravity.watch.{run,
  deadman, sshtr, presign}`; the old `scripts/` paths still work as thin back-compat
  shims (`python scripts/watchtower_run.py ...`, etc.). These are deliberately **separate
  console scripts, not `pyrxd` subcommands**: the tower's v2 refund path is a real
  (dust-capped, audit-gated) broadcaster, and the shipped `pyrxd` CLI has zero broadcast
  surface for the cross-chain stack by design.

### Security

- **The ssh-tr RXD reader's `ssh_host`/`container` constructor defaults are removed.**
  `SshTrRxdReader` shipped with `ssh_host="tr"` / `container="radiant-mainnet"` — one
  operator's private infrastructure hostname baked in as a default. Now that this reader
  ships in the public wheel (see Added, above), both are required keyword arguments with
  no default. The CLI's `--ssh-host` / `--ssh-container` flags are unaffected.
- **The watchtower dead-man's-switch's `--webhook-secret` is no longer inline-flag-only.**
  It previously accepted the HMAC secret only as a command-line argument, which is
  world-readable via `/proc/<pid>/cmdline` (`ps`) to any local user and captured in shell
  history. It now shares the tower's existing flag → 0600-file → env-var resolution
  (`--webhook-secret-file` / `PYRXD_WATCHTOWER_DEADMAN_WEBHOOK_SECRET`, and the same for
  `--webhook-auth-header` / `--webhook-auth-header-file`); the inline flag still works but
  logs a warning. The shared resolver also now verifies a secret file is mode `0600`
  before reading it (POSIX only), refusing a group/world-readable file rather than
  silently trusting it.

- **An empty webhook secret silently disabled HMAC signing.** `resolve_secret` returned
  `read_text().strip() or None`, and `WebhookAlertChannel` signs only `if self._secret`
  — so a truncated secret file, `--webhook-secret ""`, or
  `PYRXD_WATCHTOWER_WEBHOOK_SECRET=""` made the tower POST every page **unsigned**, with
  no warning. A *missing* secret file failed closed; an *empty* one failed open. A
  configured-but-empty secret (from any of the three sources) now raises. Leaving the
  secret entirely unconfigured still means "no HMAC" and is unchanged.

  **Operator impact:** a tower that was running with an emptied secret file or an empty
  env var now refuses to start instead of paging unsigned. Write a real secret, or drop
  the flag/env var.

- **The secret-file mode check followed symlinks and had a stat/read TOCTOU.** It called
  `Path.stat()` (which resolves symlinks), never checked `st_uid`, and then read the file
  through a *second*, unchecked lookup — so a 0600 symlink could point at a file the
  operator does not control, and the bytes read were not necessarily the bytes that
  passed the check. Credential files are now opened once with `O_NOFOLLOW | O_NONBLOCK`
  and validated by `fstat` **on that same descriptor**: regular file, mode `0600`, owned
  by the running uid, and read under a 64 KiB cap. A symlinked, foreign-owned, FIFO, or
  oversized secret file is refused. The gate stays POSIX-only — Windows/non-POSIX keeps
  the bounded read with no mode/owner enforcement rather than failing spuriously.

  **Operator impact:** a secret file reached through a symlink, or owned by a different
  user (e.g. root-owned, read by a non-root tower), now fails to start. Point the flag at
  the real file and `chown` it to the tower's user.

- **The pre-signed refund key file had no mode check at all.** `pyrxd-presign-refund
  --refund-key-file` read a 32-byte **private key** with no permission gate, while the
  same tower refused a group-readable *webhook secret*. It now goes through the same
  owner-only, no-symlink gate. **Operator impact:** a key file that is not `0600` (or is
  owned by another user) is now refused — `chmod 600` it.

- **The pre-signed refund sidecar was written non-atomically at the process umask.**
  `presign_refund` did `dest.write_text(...)` followed by `os.chmod(dest, 0o600)`, so this
  custody-sensitive artifact (a signed transaction paying the operator) existed
  world-readable at the ambient umask — typically `0644` — for the window in between, and
  a crash mid-write left a **truncated blob at the armed path** for the watchtower to
  load. It now uses the house convention (`mkstemp` + `fchmod(0o600)` + `fsync` +
  `os.replace`, as in `HdWallet.save`): the mode is set on the descriptor before any bytes
  exist, and the destination is only ever the complete file or the previous one.

- **The operator ACK inbox was an unauthenticated silencing channel.** Every line of
  `--ack-inbox` became a `DedupAlerter.ack(swap_id)`, which suppresses CRITICAL claim/squeeze
  **re-pages** and zeroes `unacked_critical` — the count an external monitor escalates on —
  and the file was read with no mode check, no owner check, no id validation, and an
  unbounded `read_text()`. Any local user who could write that path could quiet the tower
  during a claim race. `FileAckInbox.drain` now requires a `0600` regular file owned by the
  running uid (opened `O_NOFOLLOW | O_NONBLOCK`, validated by `fstat` on the same fd),
  caps the read at 64 KiB truncated to whole lines, drops ids that are not filename-shaped,
  and decodes with `errors="replace"` so one corrupt byte cannot destroy every pending ACK
  via the drain's `unlink`. A refused inbox fails closed **toward paging**: the claimed ids
  are dropped, an ERROR names the required `chmod`, and the CRITICAL pages keep firing.

  **Operator impact:** create the inbox owner-only —
  `install -m 600 /dev/null "$WATCHTOWER_ACKS"`. An inbox left at the default `0644` from
  `touch`/`echo >` is now refused and its ACKs are dropped (the tower keeps paging; it
  never goes quiet as a result of the refusal).

- **The watchtower entrypoints no longer raise bare `SystemExit` from library code.**
  `run.py`, `deadman.py`, `presign.py`, and `cli_secrets.py` moved out of `scripts/` and
  into the shipped package, where `raise SystemExit(...)` kills the process of any
  application that imports and calls them (`_build_rxd_source`, `_build_executor`,
  `_policy_from_args`, `resolve_secret`, `presign_refund`, ...). They now raise the typed
  `ValidationError`, and each module's `main()` is the single place that translates it to
  an exit code. **The observable CLI behavior is unchanged**: the same message on stderr
  and the same exit code 1; argparse's own usage errors still exit 2, and the timing
  preflight still exits 2.

### Fixed

- **A Glyph mint could strand the commit output on-chain when the metadata was large.**
  The reveal's scriptSig carries the entire CBOR payload, so the reveal's size — and
  its fee — scale with metadata size, and that fee is paid entirely out of the commit
  output. Both mint paths hard-coded a flat 5,000,000-photon commit value, which at the
  10,000 photons/**byte** minimum fee rate covers only about **230 bytes of CBOR**.
  Past that the reveal could not pay its own fee — and this was discovered only when
  the node rejected the reveal, *after* the commit was already broadcast, leaving its
  value in an output whose sole spending path could no longer be funded.
  `glyph mint-nft` and `glyph deploy-ft` now size the commit from the real reveal
  estimate and assert `commit_value >= carrier + reveal_fee` **before** broadcasting
  the commit, raising `InsufficientFundsError` (surfaced as a CLI `UserError`) that
  names the shortfall. The historical 5,000,000-photon overhead is kept as a floor, so
  small-metadata mints are unchanged.

- **Every ElectrumX RPC error was reported as a generic `NetworkError` with the
  server's message discarded**, which made `mandatory-script-verify-flag-failed`, dust
  and min-relay-fee rejections indistinguishable from a dropped socket — the masking
  that hid a dMint covenant-rejection bug for weeks. Node rejections now raise the
  typed `PolicyRejection` carrying a **sanitized** reason (first line only,
  non-printables stripped, long tokens run through `redact` — an ElectrumX reject
  reason has historically included the whole raw transaction hex — then clipped).
  Transport and protocol errors keep the original static description. `PolicyRejection`
  now also inherits from `NetworkError` alongside `CovenantError` so the ~30 existing
  `except NetworkError` handlers wrapping broadcasts do not silently stop catching
  rejections now that the class is actually raised.

- **`glyph mint-nft` and `glyph deploy-ft` reported the wrong genesis ref.** Both
  printed `<reveal_txid>:0`, but a Glyph token's permanent identity is its
  **commit** outpoint — that is what `prepare_reveal` embeds into the reveal's
  locking script, and what `extract_ref_from_{nft,ft}_script` reads back. Since
  `transfer-nft` / `transfer-ft` locate a token by the *extracted* ref, the
  identifier these commands printed could never be resolved by the commands meant
  to consume it. The ref is now the commit outpoint, matching the builders, the
  scanner, and `docs/tutorials/quickstart.md`.

  **Impact:** any ref recorded from a previous `mint-nft` / `deploy-ft` run is
  wrong and should be re-read from the chain — the token itself is unaffected and
  was always correctly formed on-chain; only the reported identifier was wrong.
  The commands' `commit_txid` / `reveal_txid` fields were, and remain, correct.

- **`GlyphScanner` returned `metadata=None` for every glyph on real chain data.**
  The scanner looked for the `gly` CBOR envelope in `inputs[0]` of the transaction
  named by `ref.txid` — but `ref` is the token's genesis outpoint, which is the
  **commit** outpoint (`prepare_reveal` embeds it into the reveal's locking script;
  `extract_ref_from_{nft,ft}_script` reads it back). A commit transaction's inputs
  are plain P2PKH funding spends and carry no envelope; the envelope is in the
  scriptSig of the input that *spends* `ref.txid:ref.vout`, i.e. in the **reveal**.
  Token discovery worked, so this failed silently: `pyrxd glyph list` showed every
  name as blank, and any `metadata.protocol` filter matched nothing. The bug dates
  to the scanner's introduction in 0.2.0 and was masked by test fixtures that put
  the envelope in `ref.txid` itself — a shape that cannot occur on chain.

  The scanner now resolves the reveal properly: if the UTXO's own source transaction
  spends the ref outpoint it *is* the reveal (freshly minted glyphs cost no extra
  round trip); otherwise the commit output's script hash is looked up via
  `blockchain.scripthash.get_history` and the transaction spending the ref is
  selected from it (ElectrumX has no "what spent this outpoint" RPC). Candidate
  fetches are capped so a padded history cannot cost unbounded round trips, and
  metadata is now resolved once per distinct `ref` rather than once per UTXO, so an
  FT split across many UTXOs no longer pays N lookups. `metadata` is still `None`
  when the reveal genuinely cannot be reached — a metadata miss never drops the
  token itself from the scan.

- **BIP39 seeds were derived without NFKD normalization** (`hd/bip39.py`). BIP39
  requires the mnemonic sentence and the passphrase to be NFKD-normalized before
  they enter PBKDF2. pyrxd hashed both raw, so two spellings a user cannot tell
  apart — `café` with a precomposed `U+00E9`, versus `e` + combining `U+0301` —
  derived **different seeds, and therefore entirely different wallets**. A wallet
  created this way is not reproducible by any conformant BIP39 implementation, so
  the funds in it could not be recovered in another wallet.

  **Who is affected:** only users who set a BIP39 passphrase containing non-ASCII
  characters not already in NFKD form. The fix is byte-for-byte inert for every
  ASCII passphrase (and for no passphrase at all), and both shipped wordlists
  (English, Chinese Simplified) are NFKD-stable, so the mnemonic side never
  diverged. Every existing derivation golden in the test suite is unchanged.

  **If you are affected:** pass `normalize=False` to `seed_from_mnemonic()`,
  `HdWallet.from_mnemonic()`, or `bip32_derive_xprv_from_mnemonic()` to reproduce
  the old seed and move the funds to a wallet derived the conformant way. That
  flag exists solely as a recovery path — it produces a wallet no other
  implementation can reproduce, and should not be used for new wallets.

- **The `normalize=False` fund-recovery escape was unreachable from the wallet
  persistence layer and the BIP44 helpers.** The BIP39 seed doubles as the wallet
  file's AES-GCM encryption key, so a wallet file saved by pre-0.11.3 pyrxd with a
  non-ASCII passphrase can only be decrypted by reproducing the old, unnormalized
  seed — but `HdWallet.load` / `load_or_create` had no way to request it and
  failed closed with a message pointing at the wrong causes ("wrong mnemonic,
  wrong passphrase, or ciphertext tampered"). Likewise `bip44_derive_xprv[s]_from_mnemonic`
  (and the deprecated `derive_xprv[s]_from_mnemonic` aliases) did not forward the
  flag, leaving the *default* derivation family with no route to the recovery
  mode, and `hd.discover` could only scan the conformant seed's paths. All of
  these now accept a keyword-only `normalize: bool = True`; the default behavior
  is byte-for-byte unchanged. The decrypt-failure message now names the legacy
  mode as a possibility — only when the supplied passphrase is actually changed
  by NFKD, so ASCII-passphrase users never see the noise — but the control flow
  stays fail-closed: pyrxd never silently retries with the other seed, so the
  legacy mode remains explicit opt-in. The recovery recipe (both symptoms and
  the sweep-off-the-legacy-seed procedure) is documented in
  `docs/how-to/recover-funds-across-wallet-paths.md`.

### Changed

- **The sdist is now a complete, auditable source release, and `check-manifest`
  actually guards it.** `check-manifest` has been a `test`-group dependency
  since early on, but had no `[tool.check-manifest]` config and no CI job
  invoking it, so it guarded nothing — running it found 511 git-tracked files
  missing from the sdist, including `CHANGELOG.md`, `SECURITY.md`,
  `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SUPPORT.md`, every `ci/*-pin.txt`
  hash-pin, and the entire `tests/`/`docs/`/`scripts/`/`examples/` trees. Added
  sdist-only `[tool.poetry] include` entries (via `format = ["sdist"]`, so the
  installed *wheel* is unchanged) for those plus `conformance/`, `docker/`, and
  `guides/`. Deliberately left out — and documented why in
  `[tool.check-manifest] ignore` — `.vscode/`, `.claude/`,
  `.pre-commit-config.yaml`, `.gitleaks.toml`, `.secrets.baseline` (editor/dev
  tooling, not source), and `docs/brainstorms/`, `docs/plans/`,
  `docs/_static/announce/` (working drafts and social-media collateral not
  curated for a release). `check-manifest` now runs in CI (`ci.yml`'s `test`
  job, once per push/PR rather than once per Python version) and in `task ci`.
### Added

- **dMint hash-rate benchmark + time-to-mint estimator.** New
  `pyrxd glyph dmint-estimate` and a matching SDK surface in
  `pyrxd.glyph.dmint` (`benchmark_sha256d`, `estimate_attempts`,
  `attempts_for_quantile`, `project_mint_eta`, `live_stats`). It answers
  "how long will this contract take me to mint?" and replaces the hardcoded
  "~1-2M h/s" guess that had been copied across `miner.py`,
  `contrib/miner/parallel.py`, and two concept docs.

  The three kinds of number are kept apart in the API, in the human output,
  and as separate top-level keys in `--json`:

  - **MEASURED** — the single-core SHA256d rate, benchmarked on the same
    `sha256(sha256(preimage + nonce))` chain the workers run (a test
    byte-matches the benchmark's first digest so a refactor cannot silently
    benchmark something else). During a grind, the *observed* aggregate rate.
  - **EXACT** — `p = target / 2**96` and `E[attempts] = 2**96 / target`,
    derived from the verifier predicate: `digest[:4] == 0` plus
    `int(digest[4:12]) < target` is exactly "the digest's top 96 bits are
    below the target", because the target is always under `2**64`. Plus
    p50/p90/p99 attempt counts.
  - **PROJECTED** — every ETA, and the `single-core × workers` aggregate
    rate they divide by. Cross-core scaling is *not* measured and real
    machines fall short of linear, so the projection reads high.

  Reported as a mean plus quantiles, never a countdown: mining is geometric
  and therefore memoryless, so hashes already spent do not shorten what
  remains. For the same reason V1's OP_RETURN rerolls do not perturb the
  estimate — chopping an i.i.d. hash stream into 2^32-nonce pieces leaves
  the total-attempts distribution unchanged.

  Note for anyone who has used `MAX_SHA256D_TARGET / target` as an expected
  attempt count: that is the *difficulty multiplier*
  (`target_to_difficulty`), low by a factor of ~`2**33`. At difficulty 1 it
  claims one expected attempt where the true mean is ~8.59 billion. The
  cross-check is pyrxd's own long-standing "~39% chance of a hit per V1
  sweep at difficulty 1" — which follows from the correct `p` and is now a
  unit test. The worked example in `mine_solution`'s docstring, which
  claimed a shifted target made the loop finish in milliseconds, made the
  same error and has been corrected: no target finishes fast, because the
  four-zero-byte prefix floors the mean at `2**33` attempts.

- **Live hash rate + ETA while `pyrxd glyph claim-dmint` mines.** Both
  in-process miners now take an optional `progress` callback
  (`callback(attempts, elapsed_s)`): `pyrxd.glyph.dmint.mine_solution` (and
  `mine_solution_dispatch` on its in-process branch) and
  `pyrxd.contrib.miner.parallel.mine`. The CLI renders it to **stderr** so
  stdout stays clean for `--json`; `--no-progress` silences it. In the
  parallel miner the workers publish their attempt counts at the *existing*
  65536-attempt poll checkpoint, and the parent's poll-join stays inside
  `_ensure_workers_terminated`, so the orphan-prevention guarantees are
  unchanged — including for a callback that raises, which is the supported
  way to impose a deadline. The regression suite for the original
  orphaned-worker leak passes unmodified, with a new case covering a SIGTERM
  that arrives while the parent is inside the progress-poll wait.

  **External `--miner-cmd` miners report no live progress.** The
  JSON-over-stdio wire protocol carries no progress frames and is
  deliberately not extended here (it would affect every third-party miner);
  the CLI says so and points at `dmint-estimate`. Tracked as a follow-up.

### Changed

- **`pyrxd glyph claim-dmint`'s default miner now runs in this process.**
  `--miner-cmd` unset previously spawned the bundled parallel miner as a
  subprocess (`python -m pyrxd.contrib.miner`); it now calls the same miner
  in-process. Same workers, same hashing, same full nonce-space sweep — the
  reason for that default was nonce-space coverage, which is unchanged — but
  the parent can now read the shared attempts counter and stream live
  progress. Workers are still `spawn`ed (not forked), so no wallet key
  material reaches them. Subprocess isolation remains available:
  `--miner-cmd "python -m pyrxd.contrib.miner"`.

  Two related adjustments: `--timeout` now caps a grind on *every* miner
  rather than only the external subprocess (same per-grind, reroll-on-expiry
  semantics as before), and `--workers N` sets the pool size.

- **`pyrxd.contrib.miner.parallel.mine` now raises instead of reporting a
  completed sweep when a worker dies.** A worker that exited abnormally never
  searched its slice, so `MineExhausted` was a lie — and an expensive one,
  since callers answer exhaustion by rerolling and grinding again. The
  failure this catches in practice: calling `mine()` from a `__main__`
  without an `if __name__ == "__main__":` guard, where the `spawn` start
  method makes every worker re-import it, re-enter `mine()`, and die in
  milliseconds. The CLI surfaces it with a fix hint.
### Documentation

- **New how-to: `docs/how-to/troubleshoot-common-errors.md`.** An "I got
  error X — what now?" index mapping concrete error strings and symptoms
  (a zero balance after wallet restore, `no single UTXO is large enough to
  fund the mint`, a reveal too large to fund its own fee, a stuck
  `claim-dmint`, a rejected broadcast, ElectrumX connection failures, the
  dMint v2 flag gate, and an FT/NFT silently counted as plain RXD) to their
  cause and a one-line fix, each cited to the file and line that raises it.

- **The sdist no longer packages gitignored build artifacts**, and `check-manifest` moved out
  of the local `task ci` chain into CI only. Poetry's `include` globs match the *filesystem*,
  not git, so `{ path = "docs/inspect_static" }` swept in the gitignored Pyodide wheels and any
  local `__pycache__` — un-reviewed binaries in a source release. A top-level `exclude` does not
  undo an explicit `include`, so the include is now narrowed to the tracked source extensions.
  For the same filesystem-vs-git reason, `check-manifest` fails on any working tree holding
  ordinary untracked scratch, which made `task ci` red during normal work; it now runs against
  CI's clean checkout where the check is unambiguous. Note a local `python -m build` on a dirty
  tree can still sweep untracked files into an sdist — releases are built by `publish.yml` from
  a clean checkout, so published artifacts are unaffected.

## [0.11.2] — 2026-08-07

Maintenance release. No functional, API, wire-format, or covenant-bytecode changes —
the shipped code is identical to 0.11.1 apart from one type-annotation reordering.
What changed is packaging metadata, dependency floors, and release tooling. The
cross-chain swap stack remains **unaudited** and the RSWP orderbook **experimental**.

### Changed

- **Runtime dependency floors raised** (visible in the wheel's `Requires-Dist`):
  `cryptography>=50.0.0` (was `>=49.0.0`, closing GHSA-g6cj-pr64-35w5),
  `aiohttp>=3.14.3` (was `>=3.14.1`), and `websockets>=16.1.1` (was `>=16.0`).
  Remaining constraints are unchanged — they are the literal PEP 508 expansion of the
  Poetry carets they replaced (#313, #327, #333, #339, #340, #341).
- **Runtime dependencies moved to PEP 621 `[project].dependencies`**, and dev/test/docs
  moved to PEP 735 `[dependency-groups]`. The built metadata and the
  `poetry install` set are unchanged; this only removes the last of the legacy
  `[tool.poetry.*]` dependency tables (#343, #344).
- **`[build-system].requires` raised to `poetry-core>=2.0.0`.** Building an sdist with a
  1.x poetry-core would silently produce a wheel with **no** `Requires-Dist`, since 1.x
  ignores `[project]` (#343).

### Fixed

- **CycloneDX SBOM generation has been silently failing on every release since the PEP 621
  migration** — no release back through v0.9.0 has an SBOM asset. `cyclonedx-py poetry`
  reads project metadata only from the legacy `[tool.poetry]` table with no PEP 621
  fallback, so it raised `KeyError: 'name'` on every run, masked by the step's
  `continue-on-error`. The publish workflow now uses `cyclonedx-py environment` against a
  fresh venv holding only the just-built wheel, with root-component metadata read from a
  `[tool.poetry]`-stripped copy of `pyproject.toml`. **0.11.2 is the first release to
  actually ship an SBOM** (#320).
- **The weekly atheris fuzz lane was broken** — the install step didn't work on Python
  3.12 and the SPV harness had bit-rotted against the current API. Both are repaired, so
  the scheduled lane runs again (#338).
- `EthRpc.get_logs`' `topics` annotation reordered to `list[str | list[str] | None] | None`
  for `ruff`/`mypy` union-ordering consistency. Type-checking only — no runtime behavior
  change (#342).

## [0.11.1] — 2026-07-14

Patch release. Fixes broken links on the PyPI project page.

### Fixed

- **README links 404 on PyPI.** All repo-relative Markdown links (`docs/...md`,
  `LICENSE`, `SECURITY.md`, `CHANGELOG.md`, `CONTRIBUTING.md`, `NOTICE`, `examples/...`)
  resolved fine on GitHub (which rewrites relative links against the repo) but 404'd on
  PyPI, which renders the README standalone against `pypi.org`. Every relative link is
  now an absolute URL — doc pages point at the published Sphinx site
  (`mudwoodlabs.github.io/pyrxd`), everything else points at the GitHub blob/tree view
  on `main`.

## [0.11.0] — 2026-07-11

Feature + swap-safety-hardening release. The headline is the **RSWP on-chain
orderbook** (the write side): an experimental swap-order subpackage and CLI for
posting/taking/cancelling/refunding orders through an on-chain covenant. Alongside it,
a full cycle of cross-chain HTLC swap-safety work — coordinator/leg refund-maturity
pre-checks, and extensive adversarial hardening of the two-party-adversarial-run tooling
(a chain-re-derivation verifier + two-host harnesses that live under `scripts/` and are
**not** part of the shipped wheel). Every addition is additive or opt-in; no breaking
API, wire-format, or covenant-bytecode changes. **The cross-chain swap stack remains
unaudited, and the RSWP orderbook is experimental — verify both yourself before moving
real value.**

### Added

- **RSWP on-chain orderbook (v3 covenant, experimental)** — the new `pyrxd.swap.rswp`
  subpackage: on-chain `reserve` / `post` / `take` / `cancel` / `refund` covenant flows
  (RXD, red-teamed), a maker offer lifecycle + fill-detection tracker, a pure
  market-maker quoting toolkit, and an (experimental) RXinDexer orderbook source adapter.
  Same-chain swaps gained FT-demand fills with per-ref conservation and NFT-singleton
  support (#276, #278, #279, #281, #282, #283, #284, #285).
- **`pyrxd swap orders | reserve | post | take | cancel | refund`** — CLI for the RSWP
  orderbook, sharing the existing `swap` command group (#277, #282).
- RSWP wire-format fuzz coverage, plus broader mutation / differential / conformance test
  hardening and a scheduled (weekly) fuzz CI lane (#275, #280).

### Changed

- **HTLC swap coordinator/leg safety.** A first-class `taker_observed_reveal` transition
  verifies an on-chain secret reveal (`sha256(p) == H` + per-swap provenance) before the
  FSM advances, removing a harness resume seam (#294). A role guard blocks a taker from
  calling the maker-side, self-stranding `maybe_refund_asset_on_maker_stall` (#292). BIP68
  CSV refund-maturity pre-checks were pushed into the RXD covenant, BTC, and ETH legs so a
  non-final refund is refused rather than left to node rejection under deadline pressure
  (#295, #296, #297, #301). "Not-yet-mature" now raises `NetworkError` (a transient,
  retryable condition) consistently across the coordinator and all legs (#301, #306, #308).
- `BitcoinCoreRpcSource` parses node BTC amounts with `parse_float=Decimal`, keeping the
  amount exact all the way into sat conversion (#308).
- **dMint V2 promoted from "Experimental" to "Working on mainnet today"** (closes #219). The
  implementation, a real mainnet deploy + PoW mint, and an on-chain adaptive-difficulty retarget
  were all proven and merged; the label now matches V1 — the same evidence class (node-consensus-
  validated + mainnet-proven), under the same blanket "unaudited primitives" caveat. The stale
  `allow_v2_deploy` opt-in note is dropped (that gate was removed in 0.9.0). *The cross-chain **swap**
  stack stays Experimental/unaudited — a different bar, gated on an external audit, not this cleanup.*

### Fixed

- RSWP audit follow-ups: a fill-tracker forgery gate, an order-book DoS bound, query/
  response correspondence, decoder parity with the encoder, and CLI take-consent (#289).

### Security

- The two-party-adversarial-run tooling (a chain-re-derivation verifier + two-host
  harnesses — **dev tooling under `scripts/`, not shipped in the wheel**) went through
  several adversarial red-team rounds. They found and fixed a CRITICAL asset-leg
  false-PASS (a decoy spend that paid the right party but never consumed the covenant
  outpoint, #288) and a series of subsequent false-PASS / counter-leg-binding gaps —
  confirmation-depth and independent spender-discovery gates, counter-leg value and
  recipient binding, ETH cross-source quorum, an ETH contract-code (creation-bytecode)
  pin, and a distinct `PASS_UNVERIFIED` verdict so an unverified pass can't be read as a
  clean one (#273, #300, #302, #303, #304, #305, #308). A taker RXD-funding depth gate
  refuses to lock the counter asset against an unconfirmed/reorgable covenant funding
  (#306).
- **A pre-release security panel over the RSWP orderbook found and fixed two HIGH
  fund-safety bugs** in the (experimental) order-construction layer before release (#310):
  `accept_offer` did not bound a `SIGHASH_SINGLE|ANYONECANPAY` offer's output count (a
  hand-delivered offer with an injected extra output could make a taker overpay), and a
  covenant order with an NFT demand silently degraded to a dust `P2PKH` (selling the
  reserved RXD for dust). Also: DoS bounds on the browse / tracker / covenant-parse paths,
  strict rejection of truncated pushes (an advert book-visibility divergence), and CLI
  hardening (terminal-escape sanitization, malformed-row resilience). The consensus-level
  covenant and the shipped HTLC coordinator/legs were reviewed **clean**.
- The two HIGH RSWP bugs above were found and fixed **pre-release**; no fund-loss issue
  survives this cycle. The cross-chain swap stack **remains unaudited** and the RSWP
  orderbook is **experimental** — verify both yourself before moving real value.

## [0.10.0] — 2026-06-26

Feature + audit-readiness release (vs 0.9.0's posture-only one). New read-only tooling
(swap-status CLI, RSWP order decoder), watchtower hardening, language-agnostic
cross-implementation conformance vectors, and a mutation-testing harness. Every addition
is additive or opt-in (default off); no breaking API changes. **The cross-chain swap
stack remains unaudited — verify it yourself before moving real value.**

### Added

- **`pyrxd swap status`** — read-only CLI to inspect a swap recovery file's on-chain
  covenant state (`NOT_FOUND` / `SETTLED` / `LOCKED` / `REFUND_OPEN`), with an optional
  `--check-chain`; never leaks secrets (#246).
- **RSWP on-chain swap-order decoder** — `pyrxd.gravity.swap_order.decode_rswp_order`
  decodes the v2 RSWP `OP_RETURN` wire format including Photonic `MultiTxOutV1`
  `price_terms`; the source-confirmed wire-format spec is now tracked (#265).
- **Cross-impl conformance vectors** — `conformance/dmint-v2-contract-vectors.json`,
  language-agnostic V2 dMint contract vectors across all five DAA modes (one
  mainnet-anchored), with a CI round-trip that keeps them honest (#264).
- **Watchtower endpoint-diversity guard** — `MultiSourceBtcFundingReader.from_endpoints`
  requires at least `quorum` *distinct hosts* and **fails closed** on insufficient
  diversity (with an explicit `allow_insufficient_diversity` opt-in for no-value test
  networks), so same-host endpoints can't masquerade as a real quorum (#260, #270).
- **Watchtower boot-time timing-safety preflight** — refuses to start on poll /
  dead-man's-switch / tick interval misconfigurations (#249).
- **Watchtower heartbeat leading indicators** — `squeezed`, `errored`, and
  `min_deadline_rxd_height` so a monitor sees trouble building before liveness is lost (#261).
- **Autonomous claim executor arming gate** — `enable_autonomous_mainnet_custody`
  (default off), with the as-is posture documented (#244).
- **Mutation-testing harness** — `task mutate` (cosmic-ray) measures mutant-kill coverage
  over the SPV verification core (run on demand, not wired into CI; fails on a broken run,
  with an opt-in `MUTATION_MIN_KILL_PCT` kill-threshold gate), plus SPV input-validation
  hardening **tests** that kill the surviving mutants it surfaced — closing test-coverage
  gaps, with no SPV source change required (#268, #270).
- dMint subpackage API reference (#243); operator backup/DR and watchtower operations
  runbooks (#247, #262); mutation-testing how-to (#268); a versioning & deprecation
  policy (#263).
- Audit-readiness tests: persistent Hypothesis counterexample corpus (#252), dMint V2
  mainnet golden vector (#251), residual-register traceability check (#259).

### Changed

- `MultiSourceBtcFundingReader.default_mainnet` now routes through the diversity-aware
  `from_endpoints` (no behavior change for the default three-distinct-host quorum) (#260).
- Restored the Python 3.10 / 3.11 / 3.12 CI test matrix (#248).

### Fixed

- Corrected a stale doc claim that RXinDexer mis-decodes RSWP `price_terms` — that was
  fixed upstream on 2026-06-01 (`Radiant-Core/RXinDexer`) (#266).
- Signing-agent how-to bare-path fix (#245); newcomer documentation gaps and stale
  indexes / source links (#242).

### Security

- Eight-reviewer security-panel hardening of the autonomous executor: a strict `bool`
  arming check (closing a fail-open), and the value cap reframed to waive dust only (#244).
- Internal pre-release red-team hardening (#270). No fund-loss issue was found; these harden
  paths that are not yet wired: the autonomous claim executor's fresh pre-broadcast re-assess
  now passes the per-record value-at-risk (so a value-scaled policy no longer silently
  declines every claim; ft/nft still fail closed); `pyrxd swap status` sanitizes
  terminal-control bytes from recovery-file fields; the watchtower webhook secret / auth
  header can be supplied via file or env var (off the process table); and the RSWP
  price-terms parser bounds the script length (no `OverflowError` escapes the decoder).
- Pinned the patched `msgpack >= 1.2.1` dev dependency (transitive via
  `pip-audit` → `cachecontrol`), resolving GHSA-6v7p-g79w-8964 — dev-scope, not shipped (#271).

## [0.9.0] — 2026-06-18

Posture + documentation release. pyrxd's maturity framing is now consistent
with the rest of the Radiant ecosystem: it is **open-source software provided
as-is, without warranty** (Apache 2.0), like Radiant Core itself — rather than singling
itself out as uniquely pre-audit. No new features; no breaking API changes.

### Changed

- **Audit gates are now advisory, not blocking.** The code-enforced gates that
  previously raised on value-bearing networks no longer hard-block mainnet /
  real-value use — pyrxd does what you tell it, consistent with running a Radiant
  node. `require_audit_cleared` and `require_spv_sole_authority_cleared` are
  retained as no-ops for backward compatibility (callers passing `audit_cleared=`
  are unaffected), and dMint V2 deploy no longer requires the `allow_v2_deploy`
  opt-in. **The cross-chain swap stack remains unaudited — verify it yourself
  before moving real value.**
- **Maturity language aligned to the standard open-source posture** across the
  README and docs (the Apache-2.0 "as-is, no warranty" disclaimer is the operative one).

### Documentation

- Tutorials refreshed and verified end-to-end on regtest. Fixes: a wallet-load
  crash in "your first Radiant transaction" (`str` → `Path`); the `GlyphMedia`
  import path; the FT **token ref is the commit outpoint** (not the reveal txid);
  the bundled parallel miner ships and is the default for `claim-dmint` (was
  documented as "bring your own"); stale `0.5.0` version pins → `0.8.0`; and the
  new `pyrxd wallet send` CLI is surfaced. The "inspect a transaction" supply
  math and output-badge counts corrected.

## [0.8.0] — 2026-06-18

Feature release on top of 0.7.0 — 56 commits. The headline is **full,
mainnet-proven dMint V2** (PoW distributed mint with adaptive difficulty).
Alongside, the **experimental, pre-audit** cross-chain swap + watchtower stack
advances (an autonomous asset-claim executor, more counter-chains, a CLI
signing agent) and a **CRITICAL** HTLC preimage fix lands.

No breaking changes to the stable public API — everything is additive and
existing import paths + CLI commands are unchanged. The cross-chain swap +
watchtower stack and dMint V2 **real-value** use remain **pre-external-audit**
and gated; this code is not for production until externally audited.

### Added

- **dMint V2 (PoW distributed mint) — full support, mainnet-proven.**
  `pyrxd glyph deploy-dmint --v2` + `claim-dmint` deploy and PoW-mine V2
  contracts with all five difficulty-adjustment modes
  (FIXED, ASERT, LWMA, EPOCH, SCHEDULE), byte-matched to canonical Photonic
  `dMintScript`. A first V2 deploy + PoW mint and an adaptive-difficulty
  retarget were confirmed on Radiant mainnet. V2 deploy is gated behind an
  explicit opt-in (pre-external-audit). (#206, #228, #232–#238)
- **Autonomous asset-claim executor** for the swap watchtower —
  dormant-by-construction, capped, value-vs-reorg-gated; arms a keyed RXD
  covenant claim only on an audit-cleared network. (#239)
- **More counter-chains:** Base and Litecoin, plus the
  Optimism / Arbitrum / Linea EVM registry. (#198, #200, #216)
- **CLI signing agent** (sign-on-behalf) with transient account-key
  derivation (no long-lived key residency). (#190, #191, #201)
- **RXD multi-source quorum** for the watchtower, clearing the single-source
  `low_corroboration` blocker. (#187)
- **Consensus-enforced soulbound covenants** + credential-bound swap gating.
  (#186)
- **High-level partial-transaction swap API** for same-chain trades. (#177)
- **`CappedFeeWalletSource`** — a structural spend ceiling for autonomous RXD
  fees. (#211)
- Tier-1 developer on-ramp: SDK swap primitive, regtest tooling, quickstart,
  a flagship RXD↔ETH cross-chain-swap tutorial, and expanded API reference.
  (#177, #185, #195, #196, #214, #215, #220, #226, #227)

### Fixed

- **HTLC preimage-length theft (CRITICAL).** The BTC claim leaf and all three
  Gravity HTLC covenants now consensus-pin the revealed preimage to exactly
  32 bytes (`OP_SIZE`); without it a non-32-byte `p'` could defeat the keyless
  secret-scrape and let a maker keep both legs. (#239)
- **dMint EPOCH/LWMA int64-overflow.** Found via differential testing (the
  on-chain retarget could exceed int64 and brick the contract), fixed upstream
  in canonical Photonic, and re-enabled here byte-matched to the merged fix.
  (#234, #238)
- dMint V1 + FIXED V2 validated on real Radiant consensus
  (`radiant-core` v3.1.1). (#195, #228)
- Cross-chain swap hardening across several audit rounds — value-scaled claim
  burial (fail-closed, dust opt-out), reorg-value guard, maker-stall →
  `mutual_refund` routing, durable seen-store default. (#189, #192, #193,
  #194, #210)
- CLI: a malformed path option now returns a clean usage error. (#188)

## [0.7.0] — 2026-06-07

Feature release on top of 0.6.x — 15 commits. The user-facing headline is a
**`wallet sweep`** command and **`setup --coin-type`**. Alongside, the
**experimental, pre-audit** cross-chain swap + watchtower stack advances:
ETH counter-leg watching (alert-only), FT/NFT↔ETH swap coverage, and a
**dormant, capped, keyless autonomous BTC refund** with a Go-gated dust-run
harness — see the dedicated section below; this code is still **not** for
production use until externally audited.

No breaking changes — everything is additive; existing public import paths
and CLI commands are unchanged.

### Added

- `pyrxd wallet sweep` — move the full balance from any single derived path
  to a destination address, for consolidating funds a recovery scan turned
  up on a non-default derivation (#161).
- `pyrxd setup --coin-type` — choose the HD derivation coin type at wallet
  init (e.g. `0` for Photonic/Chainbow compatibility) instead of the
  default; and `pyrxd inspect` now classifies rarer Glyph types (#174).

### Changed

- Internal: split the monolithic `glyph_cmds.py` (extracted `inspect` and
  shared helpers, de-duplicated `_load_wallet`). Public CLI unchanged (#167).

### Fixed

- `wallet sweep` now reports a clear, actionable error when the balance is
  dust (below the fee) instead of failing opaquely (#163).

### Tests

- Added a fuzz suite over the user-facing CLI surface, hardening argument
  parsing and command dispatch against malformed input (#175).

### Experimental — pre-audit, NOT for production

These components ship for testing and integration only. The cross-chain
atomic-swap and watchtower code has **not** cleared an external security
audit. Do not use it to move real value beyond throwaway amounts.

- **Watchtower — ETH counter-leg watching (alert-only v3)** — the watchtower
  now also watches RXD/Glyph↔ETH swaps via a production keyless
  `RpcEthChainSource` over a read-only ETH RPC, with a regtest end-to-end
  harness. It holds no keys and broadcasts nothing (#168, #170).
- **ETH↔RXD swap coverage** — FT (fungible-token)↔ETH and Glyph(NFT)↔ETH
  atomic-swap harnesses, with a mainnet REST REF-authenticity gate (#166,
  #169).
- **Watchtower v2 — dormant, capped, keyless autonomous BTC refund** — the
  first autonomous watchtower action: it broadcasts an operator-pre-signed
  BTC CSV refund when one is due and the operator is offline. Keyless (the
  daemon never holds a key — it re-sends pre-signed bytes), refund-only, and
  **dormant-by-construction** on a value-bearing network (no autonomy without
  an explicit, dust-capped opt-in). Adds a signet/testnet-capable runner and
  a Go-gated dust-run harness whose `setup` refuses to emit a funding address
  unless the refund provably reconstructs from on-disk state. Exercised on
  regtest and a mainnet dust run (#171, #172, #173).

### Docs

- Stuck-RXD recovery guide: pipx/venv install guidance (#162), an
  Electron-Wallet move option (#164), and a note that `recover --scan` takes
  a couple of minutes rather than hanging (#165).

## [0.6.1] — 2026-06-04

Patch release. Fixes the package version reported by the CLI and the
`pyrxd.__version__` attribute.

### Fixed

- `pyrxd --version` and `pyrxd.__version__` now report the actual installed
  version. `__version__` was a hardcoded string in `pyrxd/__init__.py` that
  was separate from `pyproject.toml`; it went stale and the 0.6.0 wheel
  shipped reporting `0.5.1`. `__version__` is now derived from the installed
  package metadata (`importlib.metadata.version`), so it tracks
  `pyproject.toml` automatically and cannot drift again.

## [0.6.0] — 2026-06-04

First release since 0.5.1 — 108 commits. The headline is **multi-path HD
wallet recovery**; alongside it ship WAVE + RXinDexer support, a
Photonic-compatible TIMELOCK protocol, a dmint subpackage refactor, and
broad SPV/parser hardening. This release also includes **experimental,
pre-audit cross-chain HTLC atomic-swap engines** (BTC↔RXD, ETH↔RXD) and a
swap watchtower — see the dedicated section below; these are not for
production use until externally audited.

No breaking changes to the stable public API: everything is additive, and
the dmint subpackage split preserved existing `pyrxd.glyph` /
`pyrxd.glyph.dmint` import paths.

### Added

#### HD wallet — multi-path recovery / account discovery

- `pyrxd wallet recover --scan` — read a BIP39 mnemonic and scan every
  `coin_type × account` pair across both BIP44 chains, reporting which
  derived addresses actually hold on-chain history and balance. Solves the
  "balance shows on the explorer but my wallet says empty" problem that
  arises because different wallets derive different addresses from the same
  seed — coin type `0` (legacy / Photonic ≤ v2 / Chainbow), `512`
  (SLIP-0044), `236` (older pyrxd). Read-only by design: it never signs or
  broadcasts; the mnemonic is prompted with hidden input and is never
  echoed, stored, or transmitted — only derived addresses (as scripthashes)
  reach the network. `--coin-types` and `--accounts` widen or narrow the
  search; `--json` for machine output.
- `pyrxd.hd.discovery` — public `discover()`, `DiscoveryReport`,
  `DiscoveryHit`, and `coin_type_label`, with `DEFAULT_COIN_TYPES =
  (0, 512, 236)` and `DEFAULT_ACCOUNTS = (0, 1, 2)` as the single source of
  truth for the default search space.

#### Glyph — WAVE + RXinDexer client

- `pyrxd.glyph.wave` — Photonic-compatible WAVE CBOR encoding plus
  `RxinDexerClient` for indexer-backed queries (#102).

#### Glyph — Photonic-compatible TIMELOCK protocol (REP-3009)

- TIMELOCK token-protocol support (`pyrxd.glyph.timelock`,
  `timelock_reveal_tx`) compatible with Photonic's REP-3009 (#106).

#### Glyph — mainnet golden vectors

- Wire-format builders pinned to real on-chain bytes: CBOR payload (#125),
  commit-script FT + NFT (#126), NFT locking script (#127).

### Changed

- `pyrxd.glyph.dmint` is now a four-submodule subpackage, split from the
  former monolithic `dmint.py` (#109). Public import paths are unchanged.
- Glyph parsing: extracted a shared input-ref opcode walker and added
  `PolicyRejection` (#107); de-duplicated `hashOutputHashes` and hardened
  output parsing (#124).

### Fixed

- Miner: parallel-miner workers are now terminated on every exit path,
  fixing orphaned multiprocessing workers left behind on early exit (#116).

### Security

- SPV primitives: red-team hardening plus swap-coordinator / data-source
  follow-ups (#138); secure-by-default and further hardening covering
  findings F-02/F-09/F-12/F-16/F-17/F-26 (#142); live-regtest consensus
  validation of deployed covenant semantics across the V/NB/M/S matrix
  (#143).
- Fixed a transitive `idna` DoS via a batched dependency update (#144).
- Defense-in-depth secret scanning (trufflehog, #118) and tightened CI
  token scopes + CodeQL security-extended (#157).

### Performance

- ~52× faster SPV-related tests by pre-mining synthetic-block PoW headers
  (#108); halved the CI test job via header-grind memoization and
  dependency caching (#140).

### Experimental — pre-audit, NOT for production

These components ship for testing and integration only. The cross-chain
atomic-swap and watchtower code has **not** cleared an external security
audit. Do not use it to move real value beyond throwaway amounts.

- **Gravity BTC↔RXD HTLC atomic-swap engine** — async coordinator, BTC and
  Radiant legs, a five-binding REF gate, and a reorg-finality gate;
  exercised on regtest and a dust mainnet run (#137).
- **ETH↔RXD HTLC atomic swap** — ETH leg and coordinator integration;
  red-team-fixed but pre-audit (#155).
- **HTLC swap watchtower v1** — alert-only, BTC-first; holds no keys and
  never broadcasts (#156).

### Dependencies & tooling

- Batched Dependabot updates across the cycle (#144, #146, #150, #153, and
  others); dev tooling moved to mypy `^2.1.0` (#150) and sphinx `^8`
  (#115). Added a manual Combine-PRs workflow (#154). Python support is
  unchanged: `>=3.10,<4.0`.

### Docs

- New tutorials (your first transaction #87, mint from a V1 dMint contract
  #85, inspect a transaction in the browser #82), how-to guides (broadcast
  a transaction #83, scan an address for Glyphs #84, BIP143 sighash quirks
  #86, verify an SPV proof #88, SPV verification pitfalls #139), and
  concept explainers (Glyph structures #121, V1 dMint mechanics #77,
  external miner protocol #78).

## [0.5.1] — 2026-05-13

Audit follow-ups + new SDK primitives. No breaking changes; everything
new is additive. Closes the four golden-vector recommendations from
the 0.5.0 pattern-recognition audit and ships the time-lock builders
+ parallel miner that were deferred at 0.5.0 cut.

### Added

#### Time-lock script primitives

- `pyrxd.script.timelock` — new module with canonical Bitcoin/Radiant
  time-lock locking scripts:
  - `build_p2pkh_with_cltv_script(pkh, locktime)` — P2PKH gated by
    absolute time-lock (BIP-65 `OP_CHECKLOCKTIMEVERIFY`).
  - `build_p2pkh_with_csv_script(pkh, sequence)` — P2PKH gated by
    relative time-lock (BIP-112 `OP_CHECKSEQUENCEVERIFY`).
  - `build_csv_sequence(units, kind)` — encodes a (blocks |
    512-second intervals) pair into the BIP-112 stack/`nSequence`
    integer form.
  - `CsvKind.BLOCKS` / `CsvKind.TIME_512_SECONDS` — kind enum.
  - `LOCKTIME_THRESHOLD = 500_000_000` — height-vs-Unix-time boundary.
- Validation rejects out-of-range locktime/sequence, the BIP-112
  disable bit (would silently make the lock a no-op), and wrong-size
  PKH. 20 tests cover minimal-int push behaviour, sign-pad edge cases,
  bit-22 encoding, and the cross-invariant that CLTV and CSV shapes
  differ only at the verify opcode.
- **Scope: locking scripts only.** Threading `nLockTime` /
  `nSequence` through transaction construction (and the unlocking
  `ScriptTemplate` that consumes signatures) is deferred until a
  concrete pyrxd consumer needs it.

#### Unified miner entrypoint

- `mine_solution_dispatch(preimage, target, *, miner_argv=None, ...)`
  — single entrypoint that routes to in-process `mine_solution`
  when `miner_argv is None`, otherwise to `mine_solution_external`
  for a subprocess miner. Callers no longer have to branch on miner
  availability themselves. Exported from `pyrxd.glyph`.

#### Parallel pure-Python miner

- `pyrxd.contrib.miner` — multi-process parallel miner that scales
  the existing pure-Python mining loop across CPU cores using the
  JSON-over-stdio external-miner protocol. No compiled extensions;
  useful when a faster C/Rust miner isn't available.

#### Mainnet golden-vector test infrastructure

- Four new test classes pin every wire-format builder against real
  on-chain bytes — the strongest interop assertion an SDK can carry:
  - `TestFtLockingScriptMainnetGolden` (`tests/test_dmint_module.py`)
    — 75-byte FT script vs RBG transfer `ac7f1f70…0ae4`.
  - `TestNftLockingScriptMainnetGolden` (`tests/test_glyph.py`)
    — 63-byte NFT singleton vs Glyph NFT `27390efa…be7e`.
  - `TestCommitLockingScriptMainnetGolden`
    (`tests/test_glyph_dmint.py`) — 75-byte commit script, both FT
    and NFT branches, vs the GLYPH deploy `a443d9df…878b`.
  - `TestCborPayloadMainnetGolden` (`tests/test_glyph.py`) — full
    65,569-byte CBOR reveal payload incl. embedded PNG, vs GLYPH
    reveal `b965b32d…9dd6` (fixture:
    `tests/fixtures/glyph_reveal_cbor.bin`). Pins
    `sha256d(payload) == commit_hash` linkage, decoder shape, and
    `OP_PUSHDATA4` framing for payloads >65,535 bytes.

#### V2 quarantine markers

- `V2UnvalidatedWarning` — new `UserWarning` subclass; emitted by
  every V2 dMint entry point. Silenceable with
  `warnings.simplefilter("ignore", V2UnvalidatedWarning)`; escalable
  to error with `warnings.simplefilter("error",
  V2UnvalidatedWarning)` in CI. No V2 dMint contract has been
  deployed to Radiant mainnet as of 0.5.1; the V2 code paths are
  byte-equivalent-by-construction to V1 where they share bytecode
  but have never been exercised against live consensus.
- `build_dmint_v2_mint_preimage(...)` — V2 PoW preimage helper that
  mirrors the V1 helper. Carries `V2UnvalidatedWarning`.

#### Documentation

- Migration guide: `docs/how-to/migrate-0.4-to-0.5.md`.
- New tutorials: mint a Glyph NFT, mint a Glyph FT, mint from a V1
  dMint contract on Radiant mainnet, inspect any Radiant transaction
  in the browser, your first Radiant transaction.
- New how-tos: scan an address for Glyphs, broadcast a Radiant
  transaction, handle Radiant's BIP143 sighash quirks, verify an SPV
  proof.
- New concepts pages: V1 dMint mint mechanics, V1 dMint deploy,
  external miner protocol (JSON-over-stdio subprocess contract),
  Glyph inspect tool (structural match, not semantic correctness).
- Design decision:
  `docs/solutions/design-decisions/wave-protocol-deferred-until-consumer.md`
  — WAVE name-claim protocol deferred until a concrete pyrxd
  consumer needs it.

### Changed

- CI: cancel in-flight runs on push to the same branch / PR. Roughly
  halves per-PR Actions minute spend.
- CI: hash-pin `poetry==2.3.4` and `ruff==0.15.12` via
  `pip-compile --generate-hashes` lock files under `ci/`. Each
  workflow that previously ran `pip install poetry==2.3.4` now runs
  `pip install -r ci/poetry-pin.txt --require-hashes`. Closes 3 of
  the 5 open OpenSSF Scorecard / CodeQL `PinnedDependenciesID`
  alerts (the remaining 2 are on the docs build's editable
  `pip install -e .`, which physically cannot be hash-pinned).
  See `ci/README.md` for the bump workflow.

### Fixed

- CodeQL note-severity alerts cleared: replaced the bare `import`
  availability probe in `docs/inspect_static/inspect/glue.py` with
  `importlib.util.find_spec` (closes `py/unused-import`); switched
  internal re-exports in `src/pyrxd/glyph/builder.py` and
  `src/pyrxd/cli/glyph_cmds.py` to PEP 484 explicit `X as X` form
  (CodeQL doesn't honour `# noqa: F401` on those — the explicit
  re-export form does close the alert); added unreachable
  `raise AssertionError("unreachable: pytest.skip raises")` after
  `pytest.skip` in `tests/test_ripemd160_fallback.py` (closes
  `py/mixed-returns`).

### Security

- The 0.5.0 pre-release multi-reviewer audit's deferred items
  (V2 quarantine, mainnet golden vectors for FT/NFT/commit/CBOR,
  CodeQL note cleanup) are closed by this release. No new formal
  audit was run for 0.5.1; changes are additive on top of audited
  0.5.0 code and each touches a single area (script primitives,
  test fixtures, CI config) with high in-PR review coverage.

## [0.5.0] — 2026-05-11

### Added

#### dMint V1 deploy (M2)

- `prepare_dmint_deploy_v1` — full V1 dMint deploy support. Builds the
  commit + reveal scripts for the mainnet-canonical "one reveal,
  many parallel contract UTXOs" shape that every live dMint token
  (RBG, snk, etc.) uses. Pinned against Photonic-Wallet's reference
  layout (`docs/dmint-research-photonic-deploy.md` §2/§3).
- `DmintV1DeployParams` / `DmintV1DeployResult` / `DmintV1ContractInitialState`
  — typed inputs/outputs for the V1 deploy flow.
- `find_dmint_contract_utxos` — chain helper that walks ElectrumX to
  enumerate the N unspent contract UTXOs from a V1 deploy reveal txid.
- `examples/dmint_v1_deploy_demo.py` — end-to-end runnable V1 deploy
  demo with resume support, commit/reveal atomic signing, and
  param-drift defense on the resume file.
- Live-validation: deploy reveal at
  `8eeb333943771991c2752abc78038365ecd76b1a24426f7a3212eea71b6a6564`
  (2026-05-11) produced 4 unspent contracts and was classified
  correctly by the inspect tool.

#### dMint V1 mint scriptSig — golden-vector pinning

- `PowPreimageResult` dataclass — frozen record of
  `(preimage, input_hash, output_hash)` returned by
  `build_pow_preimage`. Forces miners + scriptSig assembly to feed
  from a single byte source, structurally preventing the recurring
  builder-vs-covenant divergence pattern.
- `TestCovenantShape` regression suite — pins the V1 mint scriptSig
  convention against the mainnet snk token mint
  `146a4d688ba3fc1ea9588e406cc6104be2c9321738ea093d6db8e1b83581af3c`
  AND pyrxd's own first successful mint
  `c9fdcd3488f3e396bec3ce0b766bb8070963e7e75bb513b8820b6663e469e530`.
  Two independent mainnet golden vectors.
- `TestFtLockingScriptBuilderCrossEquality` — byte-equality test
  between the two FT-output builders in `pyrxd.glyph.script` and
  `pyrxd.glyph.dmint` (red-team finding R2 from the 0.5.0 pre-release
  audit).

#### CBOR reveal scriptSig

- `build_reveal_scriptsig_suffix` now supports `OP_PUSHDATA4` for
  payloads above 65,535 bytes (up to a 256 KB hard cap). The mainnet
  GLYPH reveal at `b965b32d…9dd6` used 65,569 bytes via PUSHDATA4 —
  pyrxd would have refused to build that shape under the previous
  PUSHDATA2-only cap. Red-team finding R3.

#### Inspect tool

- V1 mint scriptSig parsing — decode + display the 4 canonical
  pushes (nonce, inputHash, outputHash, OP_0). V1 vs V2 distinguished
  by nonce width (4 vs 8 bytes).
- V1 deploy commit/reveal shape detection in the browser inspector.

#### Public-API exports (`pyrxd.glyph`)

- `PowPreimageResult`, `build_dmint_v1_mint_preimage`,
  `build_dmint_v1_ft_output_script` now exported from `pyrxd.glyph`
  for direct import and type annotation.

### Changed (breaking)

- **`build_pow_preimage(...)`** now returns
  `PowPreimageResult(preimage, input_hash, output_hash)` instead of
  the raw 64-byte preimage. Migration:
  ```python
  # before (0.4.0):
  preimage = build_pow_preimage(txid_le, ref, in_script, out_script)
  # after (0.5.0):
  result = build_pow_preimage(txid_le, ref, in_script, out_script)
  preimage = result.preimage  # if you only need the bytes
  ```
- **`build_mint_scriptsig(nonce, preimage, *, nonce_width)`** is now
  `build_mint_scriptsig(nonce, input_hash, output_hash, *, nonce_width)`.
  The two 32-byte hashes MUST come from the same `build_pow_preimage`
  call that produced the mined preimage. Splitting the sources caused
  the M1 covenant-rejection incident — see
  `docs/solutions/logic-errors/dmint-v1-mint-scriptsig-divergence.md`.
- **`build_dmint_v1_mint_preimage(...)`** now returns
  `PowPreimageResult` instead of bytes. Callers feed `.preimage` to
  the miner and `.input_hash`/`.output_hash` to `build_mint_scriptsig`.
- No backward-compatible shim — the old signature could silently
  produce on-chain-rejected transactions, so a hard break with loud
  `TypeError` / `ValidationError` is safer than a deprecation path.

### Fixed

- **CRITICAL (latent): V2 mint reward output was emitting a 25-byte
  plain P2PKH; the V2 covenant requires a 75-byte FT-wrapped reward.**
  Every V2 mint would have been rejected by the network with
  `mandatory-script-verify-flag-failed` once a V2 contract existed on
  chain. No V2 contracts exist yet, so the bug was caught pre-mainnet
  during the 0.5.0 red-team audit (finding R1). V2 reward now uses
  the same `build_dmint_v1_ft_output_script` as V1 — the
  FT-conservation fingerprint `dec0e9aa76e378e4a269e69d` is shared
  via `_PART_C` between V1 and V2.
- **CRITICAL (M1 follow-up): V1 mint scriptSig pushed the wrong
  values.** The original M1 (shipped in 0.4.0 via PR #65) had
  `build_mint_scriptsig` pushing the PoW preimage halves into the
  scriptSig instead of the raw `SHA256d(funding_script)` and
  `SHA256d(OP_RETURN_script)` the covenant expects. Every successful
  mine was rejected by the on-chain covenant; M1 had never
  successfully spent a contract. Fix verified on Radiant mainnet at
  txid `c9fdcd3488f3e396bec3ce0b766bb8070963e7e75bb513b8820b6663e469e530`.
  See `docs/solutions/logic-errors/dmint-v1-mint-scriptsig-divergence.md`.

### Security

- The 0.5.0 pre-release audit was run by 8 independent specialised
  reviewers (security, red-team chain-conformance, data-integrity,
  Python code-quality, simplicity, architecture, performance,
  pattern-recognition). Two CRITICAL findings (R1 + the M1 scriptSig
  bug) and two HIGH findings (R2 cross-builder drift risk, R3
  PUSHDATA4 capability gap) were addressed pre-tag. Medium/low
  findings tracked for 0.5.1.

### Migration notes

Public API consumers must update three call sites:
1. `build_pow_preimage(...)` — use `.preimage` attribute on the
   returned `PowPreimageResult` if you only need the 64 bytes.
2. `build_mint_scriptsig(nonce, preimage, ...)` →
   `build_mint_scriptsig(nonce, result.input_hash, result.output_hash, ...)`.
3. `build_dmint_v1_mint_preimage(...)` — same `.preimage` pattern.

The library raises loud `TypeError` / `ValidationError` immediately
on old-style calls — there is no silent-failure migration path.


## [0.4.0] — 2026-05-07

### Added

#### Glyph inspect — CLI

- `pyrxd glyph inspect` — offline classifier for any Glyph input
  (script hex, txid, outpoint, contract id). Always emits a
  "structural pattern match" qualifier so users understand the tool
  classifies on-chain shapes, not protocol-level semantic
  correctness.
- `pyrxd glyph inspect --fetch` — txid lookup via the configured
  ElectrumX server; full transaction structure with per-output
  classification.
- V1 dMint contract parsing — the actual mainnet format observed
  during RBG live testing. V2 also supported for future-compat.
- Locked against a real RBG transfer fixture so the classifier is
  pinned to mainnet behaviour, not synthetic vectors.

#### Glyph inspect — browser-hosted (GitHub Pages)

- New static tool at `docs/inspect_static/inspect/` (live at the
  Pages site under `/inspect/`). Loads pyrxd via Pyodide and runs
  the inspect classifier entirely in-browser — no server, no key
  material, no transaction broadcast.
- Inputs: raw script hex, txid (auto-fetches via ElectrumX
  WebSocket), outpoint, contract id.
- Tx-shape banner explaining what kind of transaction the user is
  looking at: FT deploy, NFT deploy, dMint contract deploy, dMint
  claim (with height / max_height), Glyph burn, mutable contract
  update. Plain RXD sends and ordinary transfers render with no
  banner.
- Per-output structural-match qualifier on every classified script
  type (ft, nft, mut, dmint, commit-ft, commit-nft, op_return)
  spelling out exactly what the pattern match does **not**
  verify — never claims semantic correctness.
- OP_RETURN data carriers classified explicitly with `data_hex`
  split out from the leading opcode.

#### Glyph protocol

- `GlyphRef.from_contract_hex` — parse explorer-style contract ids
  in the standard hex form.
- `is_dmint_script` / `extract_*_from_dmint_script` — first-class
  dMint contract recognition alongside the existing FT/NFT/MUT
  helpers.
- TR39 confusables / homoglyph detector
  (`pyrxd.glyph.confusables`) — flags Latin-spoofed token names and
  symbols against the Unicode TR39 confusables data. Skeleton +
  `is_latin_lookalike` helpers for inspecting hostile glyph
  metadata.

#### Hash

- Pure-Python RIPEMD160 fallback. OpenSSL 3 distros (and Pyodide)
  ship without a built-in RIPEMD160 provider; the fallback keeps
  pyrxd working out of the box on those environments. Selected at
  import time; OpenSSL is preferred when available.

### Security

- All browser-hosted inspect install artifacts (Pyodide loader,
  pyrxd wheel, micropip wheels, vendored cbor2 wheel) verified by
  SHA-256 before `micropip.install`. Loader uses Subresource
  Integrity. Mismatch aborts install loudly rather than falling
  through.
- Vendored `cbor2==5.4.6` wheel served same-origin. cbor2 6.x
  ships C-only; pinning to the last pure-Python release closes a
  Pyodide install path that depended on PyPI staying reachable
  and unchanged.
- `micropip.install(..., deps=False)` for pyrxd to avoid
  transitive metadata fetches during browser bootstrap.
- `pyrxd/__init__.py`, `pyrxd/glyph/__init__.py`, and
  `pyrxd/curve.py` rewritten to use lazy PEP 562 `__getattr__`
  re-exports. Importing `pyrxd.glyph.inspect` no longer drags in
  `coincurve`, `aiohttp`, or `websockets` — both a Pyodide
  enabler and a startup-cost win for narrow callers.
- Manifest filename validated as a bare basename (rejects path
  traversal, dot-only names, and URL-encoded separators) before
  use. CSP no longer allows PyPI as a script source. CLI outpoint
  rendering sanitized against terminal control-character
  injection. Manifest emit hardened against shell heredoc
  injection.
- CBOR `mime_type` field capped at 256 chars at parse time —
  bounds an otherwise-unbounded user-controlled string before it
  reaches metadata renderers.

### Fixed

- `pyrxd glyph inspect transfer-ft` previously passed bytes where
  hex string was expected; corrected.
- Python 3.10 compatibility for the CLI: `tomli` fallback for
  `tomllib` (3.11+).
- `_select_ripemd160` exception handling widened so OpenSSL
  variants raising `ValueError` (not just the documented
  `UnsupportedDigestmodError`) fall through to the pure-Python
  implementation cleanly.

### Documentation

- `docs/solutions/runtime-errors/dmint-v1-classifier-gap.md`
  written from the live RBG test that surfaced the V1/V2 split.
- `docs/research/glyphs-on-radiant.md` — explains why Radiant FTs
  are on-chain (not just metadata), with fuzzing strategy.

### Tooling

- Poetry version pinned in CI workflows.
- OSSF Scorecard residual-risk decisions documented.
- PyPI publishing automated via Trusted Publishing (no long-lived
  tokens).

## [0.3.0] — 2026-05-04

### Breaking changes

- **Default BIP44 coin type is now 512 (Radiant per SLIP-0044), not 236
  (Bitcoin SV).** Wallets created with 0.2.0 derive at
  `m/44'/236'/0'/...`; the same mnemonic in 0.3.0 derives at
  `m/44'/512'/0'/...` and produces different addresses. To recover funds
  from a 0.2.0 install, set
  `RXD_PY_SDK_BIP44_DERIVATION_PATH="m/44'/236'/0'"`, or pass
  `coin_type=236` to `HdWallet` (see new per-instance kwarg below). See
  `docs/research/wallet-derivation-paths.md` for the full migration
  story.

### Added

#### CLI

- New `pyrxd` console script (`pip install pyrxd` registers it on PATH).
- `pyrxd wallet new | load | info | export-xpub` — create, validate, and
  inspect HD wallets; account-level xpub export for watch-only use.
- `pyrxd address` / `pyrxd balance` / `pyrxd utxos` — bare query
  commands for address derivation, balance, and UTXO listing.
- `pyrxd glyph` subcommand group — Glyph protocol operations.
- `pyrxd setup` — onboarding walkthrough; probes node + ElectrumX
  reachability and wallet presence, writes default config.
- Global flags: `--network`, `--electrumx`, `--wallet`, `--config`,
  `--json`, `--quiet`, `--no-color`, `--yes`, `--debug`.
- Typed CLI errors (`UserError`, `NetworkBoundaryError`,
  `WalletDecryptError`) with stable exit codes and a static decrypt
  message that never echoes user input.

#### HD wallet

- `HdWallet(coin_type=...)` per-instance kwarg overrides the default
  derivation path without touching env state.
- `HdWallet.send` / `HdWallet.send_max` — key-aware UTXO collection and
  signed-transaction construction.
- Load-time path validation against the wallet record's stored
  derivation path.

> ⚠️ **Downgrade hazard introduced here.** Once 0.3.0 writes a wallet
> file with a `coin_type` annotation, downgrading to a pre-0.3.0 version
> and re-saving the wallet corrupts the stored `coin_type` while leaving
> derived keys unchanged. A subsequent upgrade will fail `load()` validation.
> Funds are recoverable from the mnemonic but require manual re-creation
> of the wallet file. **Pin all machines to the same pyrxd version.**
> See the README "Upgrading" section for details.

#### Documentation

- `docs/research/wallet-derivation-paths.md` — public research doc on
  the five-way derivation path fragmentation across the Radiant wallet
  ecosystem with verified source links.
- `docs/solutions/` convention established for searchable
  problem/solution documentation.
- README user-risk disclaimer above Status section.
- Documentation moved from Read the Docs to GitHub Pages
  (https://mudwoodlabs.github.io/pyrxd/).

### Fixed

- `HdWallet` previously ignored the
  `RXD_PY_SDK_BIP44_DERIVATION_PATH` env override. Now respected.
- Cyclic imports between `cli.main` and the four CLI subcommand modules
  resolved by registering subcommands explicitly via
  `cli.add_command()`.
- `pyrxd glyph` broadcast summary now surfaces metadata fields.
- BIP39 empty-passphrase defaults annotated to silence false-positive
  bandit findings.

### Security

- All 16 GitHub Actions pinned to commit SHAs (no floating tags).
- Explicit minimum `permissions` declared in CI and lint workflows.
- OSSF Scorecard and OSV Scanner workflows added.
- CodeQL static analysis workflow added.
- Threat model + red-team checklist documented.
- `--json` mnemonic exposure warning documented.
- bandit added to `task lint` so security findings fail locally before
  CI.

### Tooling

- `task ci` aggregate task + versioned pre-push git hook
  (`scripts/git-hooks/pre-push`) + installer for local CI parity.
- `scripts/check-no-private-links.py` — link checker that prevents
  tracked docs from referencing gitignored design docs.
- ruff replaces flake8 + black for lint and format.
- Dependabot version updates landed: `actions/checkout` → 6.0.2,
  `actions/deploy-pages` → 5.0.0, `actions/upload-pages-artifact` →
  5.0.0, `github/codeql-action` → 4.35.3, `click` → ^8.3, `bandit` →
  ^1.9.4, `pre-commit` → 4.6.0, `myst-parser` constraint refresh.
- `websockets` constraint widened to `>=15.0.1, <17.0.0` (was
  `^16.0.0`). pyrxd uses only stable websockets API
  (`connect`/`send`/`recv`/`close`/`WebSocketException`) common to
  versions 13 through 16, so the upper-bound floor was unnecessarily
  strict and locked out coexistence with libraries pinned to
  `websockets <=15.0.1` (e.g., `solana-py 0.36.x`).

## [0.2.0] — 2026-04-29

Initial public release.

### Features

#### Core

- Typed primitives at all SDK boundaries: `Hex32`, `Hex20`, `Txid`,
  `Satoshis`, `SecretBytes`, `RawTx`. Strings and untyped bytes are
  rejected at the constructor.
- `pyrxd.curve` — secp256k1 with `coincurve`, RFC 6979 deterministic
  signing, low-s normalization, DER encoding.
- `pyrxd.security` — typed errors, RNG, secret-bytes (libsodium-backed
  `SecretBytes` for memory hygiene).
- `pyrxd.crypto` — symmetric primitives.

#### Keys and HD wallets

- `PrivateKey` / `PublicKey` with WIF encoding/decoding and address
  derivation (P2PKH mainnet).
- BIP32 extended keys (`Xprv` / `Xpub`) with hardened/non-hardened
  derivation.
- BIP39 mnemonic generation and seed derivation.
- BIP44 derivation paths (`m/44'/236'/0'/...` for Radiant).
- `HdWallet` with persistent encrypted save/load (AES-CBC keyed by
  hash of the BIP39 seed) and BIP44 gap-limit address scanning.

#### Transactions and scripts

- `Transaction` / `TransactionInput` / `TransactionOutput` — Radiant tx
  construction, serialization, and txid computation.
- BIP143-style sighash with Radiant's additional `hashOutputHashes`
  field; literal-zero zero-refs in the refsHash component.
- `P2PKH` script template + `unlock(private_key)` for standard signing.
- Script primitives in `pyrxd.script` for custom locking/unlocking
  patterns.
- `SatoshisPerKilobyte` fee model.

#### Glyph protocol

- `GlyphBuilder` with `prepare_commit`, `prepare_reveal`,
  `prepare_ft_deploy_reveal`, `prepare_dmint_deploy`,
  `prepare_mutable_reveal`, `prepare_container_reveal`,
  `prepare_wave_reveal`.
- `GlyphMetadata` with V1 and V2 sub-objects (creator, royalty, policy,
  rights, image+image_ipfs+image_sha256). Canonical CBOR encoding.
- `GlyphInspector` — parse Glyph tokens from a transaction's outputs.
- `GlyphScanner` — query an address's UTXOs and return Glyph tokens
  with metadata.
- `FtUtxoSet` + `build_transfer_tx` — conservation-enforcing FT
  transfers; refuses to build a tx that would create or destroy
  fungible units.
- `DmintState.from_script` — parse a live dMint contract UTXO into a
  typed state object.
- `verify_sha256d_solution` — off-chain PoW verifier matching on-chain
  semantics.

#### Network

- `ElectrumXClient` — async WebSocket client for ElectrumX servers.
  Multi-URL failover, transparent reconnect, per-request id
  correlation.
- `get_balance`, `get_utxos`, `get_history`, `get_transaction`,
  `broadcast`, `get_merkle_proof`.
- `script_hash_for_address` — derive the ElectrumX script hash from a
  Radiant address.
- `BtcDataSource` — Bitcoin chain reader for cross-chain Gravity
  flows.

#### Gravity (cross-chain BTC↔RXD atomic swaps)

- `GravityMakerSession` — maker side of a sentinel-artifact-shaped
  atomic swap.
- Covenant artifacts in `pyrxd.gravity.artifacts` (sentinel and
  legacy variants).
- SPV-anchored claim and forfeit flows.

**Status:** mainnet-proven for the sentinel-artifact path. Other
covenant variants in this module are experimental.

#### SPV

- Block-header verification, merkle-proof verification, partial-merkle
  parsing.
- Header chain tip tracking.

#### Examples

- `examples/glyph_mint_demo.py` — end-to-end Glyph NFT mint.
- `examples/ft_deploy_premine.py` — FT deploy with full premine to
  one address.
- `examples/gravity_*.py` — Gravity Protocol cross-chain demos.

### Quality

- 2,000+ tests across unit, property-based (hypothesis), and
  integration suites.
- CBOR cross-decoder tests against an independent reference decoder
  (RXinDexer).
- Frozen golden vectors for CBOR encoding determinism and ECDSA
  RFC 6979 signing.
- `mypy --strict` clean on `src/`.
- `ruff` clean on the codebase.

### Documentation

- `docs/dmint-followup.md` — premine vs PoW dMint scope.
- `docs/dmint-research-photonic.md` — Photonic Wallet TS reverse
  engineering.
- `docs/dmint-research-mainnet.md` — decoded live mainnet dMint
  contracts.

### Known limitations

- **dMint PoW-based distributed FT mint not implemented.** Premine-at-deploy works via `prepare_ft_deploy_reveal`. PoW commit/reveal + ASERT/LWMA difficulty adjustment is documented as future work in `docs/dmint-followup.md`. Premine-only consumers do not need it.
- **Gravity covenant variants beyond sentinel-artifact** are
  experimental and have not been audited.
- **No third-party security audit yet.** Use at your own risk in
  production.

[0.3.0]: https://github.com/MudwoodLabs/pyrxd/releases/tag/v0.3.0
[0.2.0]: https://github.com/MudwoodLabs/pyrxd/releases/tag/v0.2.0
