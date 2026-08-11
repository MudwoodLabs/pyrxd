# pyrxd — external security audit scoping brief

**Status:** draft for commission · **Current as of:** 0.14.0 (2026-08-10) · **Frozen commit:**
_pin at commission time_ (do **not** audit a moving `main`) · **Companion docs:**
[`threat-model.md`](threat-model.md), [`../SECURITY.md`](../SECURITY.md),
[`concepts/architecture.md`](concepts/architecture.md),
[`reference/glyph-token-protocol-spec.md`](reference/glyph-token-protocol-spec.md),
[`htlc-handshake-wire-format.md`](htlc-handshake-wire-format.md).

This brief tells an external auditor **what to audit, what is deliberately out of scope, the
assumptions the code is allowed to make, where internal review has actually found bugs, and the
complete register of accepted/known residual risks** — consolidated from the threat model, the
design-decision notes, and the in-code residual notes so the audit reviews a *stated* boundary
rather than rediscovering it. pyrxd is open-source software, provided as-is under the
[LICENSE](../LICENSE); the cross-chain swap stack is **unaudited**, and this brief is the
deliverable that lets an independent review certify it.

As of 0.9.0 the library-wide `require_audit_cleared` / `require_spv_sole_authority_cleared` gates
are **advisory no-ops** (retained for backward compatibility — verified: `spv/proof.py`'s
`require_spv_sole_authority_cleared` returns `None` unconditionally) — pyrxd "does what you tell
it," consistent with running a Radiant node, and does **not** code-block mainnet/real-value use.
Real-value safety is therefore a documented operator responsibility, not a code-enforced default
(see `ASSUME-AS-IS-POSTURE` in §4). The one exception is the autonomous claim executor's
`enable_autonomous_mainnet_custody` (default off), which still affirmatively gates unattended
mainnet money-movement — and as of 0.14.0 that executor is additionally **unreachable from any
shipped entrypoint** (`gravity/watch/run.py` builds only the `RefundExecutor`; no arming flag
exists — `src/pyrxd/gravity/watch/README.md`).

## 0. How to use this brief

- Residuals carry **stable IDs** (e.g. `SWAP-R1`, `CAPFEE-ISOLATION`). Where a residual already
  had a legacy id (a threat-model `S#`/gap `#n`, a handshake-spec hazard `HZ-n`, or an in-code tag
  like `SEEN-1`, `MEDIUM-1`, `R1`, `F-01`), the legacy id is noted — the legacy numbering has
  known collisions (see §10).
- **Severity** is the *pre-mitigation* class; **Status** is `open` / `mitigated` (a control
  exists) / `accepted` (a conscious residual) / `deferred` (a feature not built) / `gate` (an
  affirmative opt-in that defaults the risk off until consciously enabled). NOTE: the legacy
  library-wide `require_audit_cleared` / `require_spv_sole_authority_cleared` "gates" are
  **advisory no-ops** as of 0.9.0 (posture-only, not fail-closed); the only live `gate` is the
  executor's `enable_autonomous_mainnet_custody`.
- §1 states what is and is not proven — read it before pricing the engagement.
- §7 records where internal review has actually found fund-safety bugs; §8 lists the known-open
  items so the audit does not spend budget rediscovering them.
- Start at §6 (priority targets) for where the return-on-review is highest.

## 1. What is and is not proven

Stated plainly, because the distinction prices the engagement:

- **Proven on consensus:** the Radiant HTLC leg (hashlock claim + CSV refund) is validated
  against real `radiant-core` nodes (regtest e2e: `tests/test_htlc_regtest_e2e.py`) and the
  Gravity SPV/covenant sentinel path is mainnet-proven ([`concepts/gravity.md`](concepts/gravity.md)).
  dMint V1 and V2 are node-consensus-validated and mainnet-proven (threat model, gap #13).
- **Run with real (dust) value:** full cross-chain BTC↔RXD and ETH↔RXD swaps have completed on
  mainnet/testnet with dust value, driven by the shipped `SwapCoordinator` and the two-host
  operator harnesses (CHANGELOG 0.11.0; `scripts/`).
- **NOT proven:** every run so far is **single-operator** — a plumbing proof, not an adversarial
  one (`src/pyrxd/gravity/watch/README.md`: "every run so far is single-operator (a plumbing
  proof, not adversarial safety)"). The live **two-party adversarial run has not happened**, and
  **no external security review of any part of this codebase has ever occurred** (threat model,
  gap #20). Chain-re-derivation verification tooling for such a run exists
  (`scripts/swap_run_verify.py`) but has only ever checked single-operator runs.
- Do not read "dust swap completed" as "swap stack is safe against a hostile counterparty." The
  project's own hard gate before non-dust value is the external audit this brief scopes **plus**
  a genuine two-party adversarial run.

## 2. Scope — what to audit

The audit-critical surface (ranked; per-module rationale in
[`concepts/architecture.md`](concepts/architecture.md)). Modules marked **(0.10–0.14)** are new
or substantially changed since this brief's previous revision (2026-06-20) — derived from
`git log v0.9.0..v0.14.0` and the CHANGELOG, not from memory:

| Area | Modules | Why critical |
|---|---|---|
| **Cross-chain swap covenant + coordinator** | `src/pyrxd/gravity/` — `htlc_covenant.py`, `htlc_spend.py`, `radiant_leg.py`, `swap_coordinator.py`, `swap_state.py`, `ref_authenticity.py`, `capped_fee_source.py`, `seen_store.py`, **(0.14)** `fee_policy.py` | The single most adversarial setting (hostile counterparty wants both legs). Covenant build/spend, the role/timelock invariant, the REF-authenticity gate, the fee-key trust boundary — and, new in 0.14.0, **both counterparty-funding gates**: the maker-side `maker_verify_counter_funding` (threat model S23) and the taker-side `taker_verify_asset_funding` (S24), each re-run at lock time to close the verify→lock TOCTOU (`swap_coordinator.py:1195,1331,1515,1671`). Fee sizing is itself fund-safety on this chain (S21 — no RBF, no CPFP). |
| **BTC + ETH counter-legs** | `src/pyrxd/btc_wallet/` (`htlc_leg.py` incl. `verify_counterparty_funded`, `taproot.py`, `chains.py`), `src/pyrxd/eth_wallet/` (`chains.py`, `locator.py`, `rpc.py`, `private_submit.py`), `src/pyrxd/gravity/eth_leg.py` | The Taproot-HTLC + Solidity-HTLC legs, per-chain finality/block-interval safety knobs, and the funded-output binding (scriptPubKey + exact value + depth) behind S23. |
| **HTLC handshake wire format** **(0.14)** | [`htlc-handshake-wire-format.md`](htlc-handshake-wire-format.md), `conformance/htlc-handshake-vectors.json` (51 checks), `gravity/swap_state.py` (`NegotiatedTerms`) | The negotiation that precedes the on-chain legs. Eight recorded interop hazards (HZ-1..HZ-8); **no version negotiation exists** (HZ-2 — see §8), so every safety property rests on the two independently re-derived scriptPubKey comparisons, not on the envelope. |
| **Offline/cold swap recovery** **(0.14)** | `src/pyrxd/cli/swap_recovery.py`, `cli/swap_recovery_cmds.py` | Builds time-critical claim/refund spends with no coordinator running. Fee-overpay ceiling (`select_fee_utxo:880` — the covenant permits one output, so the *whole* fee input is the miner fee) and the 0-conf-covenant-parent gate (`_assert_covenant_confirmed:1122`). |
| **RSWP on-chain orderbook (experimental)** **(0.11)** | `src/pyrxd/swap/` (`rswp/` — `covenant.py`, `orders.py`, `wire.py`, `book.py`, `tracker.py`), `gravity/swap_order.py`, `cli/swap_book_cmds.py` | Post/take/cancel/refund through an on-chain covenant. `cancel` is the **only** hard revocation for a v2 order, so under-fee'd cancels are a fund-safety edge (fixed 0.14.0, CHANGELOG). Internally red-teamed only (two HIGH fund-safety bugs found+fixed pre-release in 0.11.0). |
| **Watchtower** | `src/pyrxd/gravity/watch/` — `decide.py`, `reconciler.py`, `quorum.py`, `executor.py`, `claim_executor.py`, `adapters.py`, `eth_adapters.py`, `alerts.py`, `heartbeat.py`, **(0.12–0.13)** `run.py`, `deadman.py`, `presign.py`, `sshtr.py`, `escalation.py`, `preflight.py`, `cli_secrets.py` | Alert-only v1 + the dormant, dust-capped (10,000 sats — `executor.py:57`), keyless v2 BTC refund. `executor.py` is the only component that broadcasts. The entrypoints ship as console scripts since 0.12.0 (previously unshipped `scripts/`), which moved their credential/ACK-inbox handling inside the audit surface. `quorum.py` now holds a per-swap `FinalityStallTracker` for ETH and `adapters.py` a ≥2-source `MultiSourceRxdChainSource` (`:141`). |
| **SPV verification** | `src/pyrxd/spv/` — `chain.py`, `proof.py`, `pow.py`, `merkle.py`, `payment.py`, `witness.py` | One-way Bitcoin-proof verifier that gates covenant release. The nBits-pin-before-PoW defense. NOTE: `require_spv_sole_authority_cleared` is an advisory no-op (§4). |
| **Key material** | `src/pyrxd/hd/` (`wallet.py`, `bip32.py`, `bip39.py`, **(0.14)** `descriptor.py`), `src/pyrxd/security/` (`secrets.py`, `types.py`, `errors.py`), `src/pyrxd/keys.py`, `src/pyrxd/base58.py` | AES-256-GCM + scrypt wallet; `SecretBytes`; the agent's transient-xprv re-derivation; the persisted-coin-type pin (`wallet.py:577-608`); NFKD seed normalization + the `normalize=False` recovery escape (0.12.0); descriptor export (an xpub is a whole-history disclosure — the module says so); the static-message base58/WIF error path (0.14.0 — this is where a key-echo bug lived, §7). |
| **Signing agent** | `src/pyrxd/agent/` — `signer.py`, `confirm.py`, `daemon.py`, `hygiene.py` | The unlocked-wallet daemon (A11) on a `0600` socket; per-spend `/dev/tty` confirmation; prevout authenticity. |
| **Glyph / metadata / dMint** | `src/pyrxd/glyph/` — `script.py` (the consensus ref-opcode walker, `REF_OPCODES` at `:442`), `payload.py`, `types.py`, `scanner.py`, `creator.py`, `credential_binding.py`, `soulbound_covenant.py`, `soulbound_detect.py`, **(0.12–0.14)** `mint.py` (two-phase minter + `PendingStore` — losing the CBOR between commit and reveal strands the output permanently), `fees.py`, `ft.py` (airdrop + transfer — where a whole-balance fund-loss bug lived, §7), `royalty.py`, `dmint/` (`builders.py` incl. deploy-with-premine, `chain.py`, `miner.py`) | Attacker-facing parser surface + the token-issuance paths. Consensus parity of the ref walkers is load-bearing for **fee-input selection** (a token misclassified as plain funding is silently burned as fees) and for the credential gate. Normative spec: [`reference/glyph-token-protocol-spec.md`](reference/glyph-token-protocol-spec.md). |
| **Lying-server defenses** | `src/pyrxd/network/` — `electrumx.py`, `bitcoin.py`, **(0.14)** `registry.py`, `failover.py`, `tls_pin.py`, `confirm.py`, `rxindexer.py` | `wss`-only, response caps, per-id correlation, the multi-source BTC quorum; new in 0.14.0: the endpoint registry with genesis-hash chain binding (`assert_chain` — a chain mismatch is *not* failover-able), request-level failover with read-back-corroborated "already known" handling (`failover.py:361 _holds_tx`), and opt-in SPKI pinning (`tls_pin.py`, off by default deliberately). |

`SECURITY.md` lists the in-scope packages for *reports* (`pyrxd.curve|security|aes_cbc|crypto`,
`pyrxd.hd`, `pyrxd.transaction|script`, `pyrxd.glyph`, `pyrxd.gravity`, `pyrxd.network` —
verified against `SECURITY.md` at this commit). That list is **narrower than the audit surface
above** — it predates `pyrxd.spv`, `pyrxd.swap`, `pyrxd.btc_wallet`, `pyrxd.eth_wallet`,
`pyrxd.agent`, and `pyrxd.cli` as separate packages. For the audit, the table above is the
authoritative scope.

## 3. Out of scope

From the threat model's non-goals + `SECURITY.md`: coercion / $5-wrench, physical access to an
unlocked machine, compromised OS/firmware/hypervisor, silicon side-channels, quantum (secp256k1
is not PQ-safe), typosquats / wrong-binary, the user leaking the mnemonic through channels pyrxd
can't see, dependency vulnerabilities (report upstream), and future Radiant consensus bugs.
**Single-sig only** (no multisig). **The deprecated SPV-oracle *swap* covenant is out of scope**
(superseded by the HTLC swap; see `SPV-SWAP-R2`/`-FORGED`).

## 4. Load-bearing assumptions (stated up front)

The audit should accept or challenge these explicitly — the code's safety arguments rest on them.

- **`ASSUME-SINGLE-SOURCE` (gap #6).** RXD-side reads trust a single source by design:
  (a) the default ElectrumX endpoint for plain-RXD wallet ops — 0.14.0 added an endpoint
  *registry* with failover and per-endpoint genesis-hash chain verification
  (`network/registry.py`, `failover.py`), but failover is an **availability** mechanism, not a
  cross-checking quorum: whichever endpoint answers is trusted alone; (b) the single RXinDexer
  that resolves Glyph reads and backs `verify_ref_authenticity`; (c) the RXD-side reads behind
  the new swap gates — the taker-side asset-funding gate reads **one** ElectrumX endpoint
  (threat model S24 residual; there is no RXD analogue of `MultiSourceBtcFundingReader` on the
  leg side). Exception: the **watchtower's** RXD covenant-depth read *is* quorum'd
  (`MultiSourceRxdChainSource`, `watch/adapters.py:141`, ≥2 sources, fail-closed below quorum).
  Rationale: a *self-consistent* lie is byte-identical from every source, so a 2nd source — which
  only detects *disagreement* — has bounded value; the load-bearing defenses are the on-chain
  covenant pins (nBits, the REF-uniqueness consensus rule), not read-side quorum. Standing up a
  2nd independent RXD source for the leg-side reads is the right hardening **at first non-dust
  real value**.
- **`ASSUME-CAPFEE-ISOLATION`.** `CappedFeeWalletSource`'s structural ceiling is real **only if**
  the operator funds it from a key isolated from the main wallet (the class validates P2PKH +
  wif-control + the cap, but cannot verify key isolation). See `CAPFEE-ISOLATION`.
- **`ASSUME-AS-IS-POSTURE`** (was `ASSUME-PRE-AUDIT-GATE`). As of 0.9.0 the library-wide
  `require_audit_cleared` (`AUDIT_CLEARED_NETWORKS = {bcrt, regtest, tb, signet, rltc, tltc}`,
  `btc_wallet/htlc_leg.py:96`) and `require_spv_sole_authority_cleared` gates are **advisory
  no-ops** — verified at this commit: `spv/proof.py:38-54` documents "no longer blocks" and
  returns `None`. pyrxd "does what you tell it," like running a Radiant node: real-value safety
  is a documented operator responsibility, not a code-enforced default. An auditor should treat
  these as *posture documentation*, not a fail-closed property. NOTE: `threat-model.md`'s
  "Controls in place" table and gap #8 still describe this gate as "fails closed" — that wording
  predates the 0.9.0 demotion; the code is the arbiter. The single still-live affirmative gate is
  the executor's `enable_autonomous_mainnet_custody` (next item).
- **`ASSUME-WATCH-ALERT-ONLY`.** The watchtower core is **alert-only and keyless for the asset**;
  it never holds a value key and never touches `p` except to scrape the maker's already-public
  preimage. Two autonomous actions exist, both bounded: the v2 BTC refund (operator-pre-signed,
  dust-capped 10,000 sats — `watch/executor.py:57`) and the Radiant **claim executor**
  (`watch/claim_executor.py`). The claim executor is **keyless for the asset** (`output[0]`
  pinned to the taker holder PKH → cannot redirect the asset; a stolen *fee* key burns only dust
  fees), **dormant-by-construction** (needs a wired resolver + a per-swap covenant sidecar),
  **armed-by-exception** (`enable_autonomous_mainnet_custody`, default off) — and, verified at
  this commit, **not reachable from any shipped entrypoint**: `watch/run.py` constructs only the
  `RefundExecutor` and no arming flag exists (`watch/README.md` corrects its own earlier claim
  that one did). R1's closure therefore rests on **taker/operator liveness within `t_rxd`**; see
  `CAPFEE-TYPE-GATE` for the (recommended-not-enforced) fee-source cap.
- **`ASSUME-NO-FEE-BUMP` (TM S21).** Radiant supports **neither RBF nor CPFP** (verified against
  `Radiant-Core` source and a live mainnet node — citations inline in `threat-model.md` S21 and
  `gravity/fee_policy.py`). A transaction built below the node's effective relay floor cannot be
  repaired by any means and squats on its inputs for the 8-hour mempool expiry. Fee
  **pre-sizing** is the only control, which is why fee arithmetic is treated as fund-safety
  throughout this codebase (§7). An audit remediation of the form "bump the fee" is invalid on
  this chain.

## 5. Affirmative opt-in gates

These are the live seams that default value-bearing risk off unless an explicit opt-in is set —
the seams an audit would certify before they are enabled:

| Gate | Defaults off | Where |
|---|---|---|
| `enable_autonomous_mainnet_custody` | unattended mainnet asset-claim broadcast (additionally unreachable — no entrypoint arms it) | `gravity/watch/claim_executor.py`, `watch/run.py` |
| `require_measured` margins (`MEDIUM-1`) | a real-value ETH swap on *estimated* margins | `gravity/swap_coordinator.py` |
| value-scaled claim burial vs `accept_flat_burial` | a non-dust swap reorg-reversible at flat burial | `gravity/swap_coordinator.py` |
| durable seen-store default (was `accept_nondurable_seen`) | replay/free-option window across restart | `gravity/seen_store.py`, value harnesses |
| `claim_dust_ceiling` (autonomous claim) | non-dust autonomous RXD claim (raise = explicit per-value consent) | `gravity/watch/claim_executor.py` |
| `--allow-overpay` / `--allow-unconfirmed` (cold recovery) | burning a >10× fee input; building on a 0-conf covenant parent | `cli/swap_recovery.py` |
| TLS SPKI pins (named pins enable) | accepting any CA-vouched key for an ElectrumX endpoint | `network/tls_pin.py` |

> **Demoted (advisory no-ops as of 0.9.0, NOT fail-closed):** `require_audit_cleared` /
> `AUDIT_CLEARED_NETWORKS` (`btc_wallet/htlc_leg.py`, `gravity/radiant_leg.py`) and
> `require_spv_sole_authority_cleared` (`spv/proof.py`). These no longer block mainnet use — they
> are posture documentation only (see `ASSUME-AS-IS-POSTURE`). Do not certify them as fail-closed.

## 6. Priority targets (ranked by expected return)

1. **`gravity/` covenant + spend + the three money seams** — highest stakes, most complex.
   Focus: covenant param binding, sighash handling, the `R1` fake-singleton defense (`SWAP-R1`),
   the timelock/role invariant (`SWAP-TIMELOCK-INVARIANT`, `SWAP-MAKER-STALL`), value-scaled
   burial, and the three seams added since the last revision: **both counterparty-funding gates**
   (S23/S24 — can they be routed around? is the TOCTOU re-run airtight?) and the
   **deadline-aware fee path** (S21 — an under-fee here is unrepairable fund loss).
2. **`glyph/` token issuance + transfer arithmetic + walker consensus parity** — this is where
   the 0.14.0 panel found its fund-loss bugs (§7). Focus: any place an output value is computed
   (FT units *are* satoshis), the `REF_OPCODES` walk against Radiant's `GetScriptOp`, and the
   metadata→scriptPubKey path.
3. **`hd/wallet.py` save/load + the agent** — key material; the transient-xprv re-derivation
   (`AGENT-SAMEUID`/H1), prevout authenticity (`AGENT-REDIRECT`/C1), the NFKD/`normalize=False`
   recovery seam, and every error path that could echo input (§7 — one did).
4. **`spv/`** — the nBits-pin-before-PoW forgery defense and `SPV-SOLE-AUTHORITY` (F-01),
   remembering the gate is advisory (§4).
5. **The handshake wire format** — validate the hazard list (HZ-1..HZ-8) is complete; anything
   outside the two re-derived scriptPubKey comparisons is effectively unauthenticated (§8).
6. **`gravity/watch/`** — alert correctness, the co-fire `hold-that-loses` residual, credential
   handling in the now-shipped entrypoints, and the dormant autonomy gate before any future
   arming.

## 7. Where the bugs have actually lived — the internal-review record

This section exists because it tells an auditor where this codebase's defects concentrate, on
evidence rather than intuition. Source for all items: `CHANGELOG.md` (each entry there carries
the measurements and test citations).

**The 0.14.0 eight-reviewer pre-release panel found four fund-safety defects. All four were
pre-existing — none was in the release diff being reviewed.**

1. **`glyph transfer-ft` could send the sender's entire balance.** The recipient output was
   sized from the inputs' RXD (`rxd_in_total - fee - change_alloc`), not from the requested
   `amount` — on chain an FT's unit count *is* its output's satoshis. Measured: asked to send
   250 units, sent 46,739,454. The first fix was a tripwire on one input shape
   (`value == ft_amount`) — and the loss remained reachable **one photon either side** of it
   (measured at `±1`). The real fix makes the transfer a single-recipient airdrop, so the
   recipient's value is `amount` **by construction**, pinned by a property/differential suite
   (`tests/test_ft_transfer.py`).
2. **The ref-opcode walker diverged from Radiant consensus on `0xd4`–`0xd7`** (opcodes that
   carry no operand; consensus consumes a 36-byte operand for exactly five: `0xd0`–`0xd3`,
   `0xd8`). **Four** walkers existed in the tree, split two-and-two on the correct opcode set;
   one of the two wrong ones backed the anti-rental credential gate and could confidently name
   the wrong owner. The walk could report a phantom ref while the real one stayed invisible —
   and these classifiers decide whether a UTXO is safe to burn as a fee input. Fixed to a single
   shared `REF_OPCODES` (`glyph/script.py:442`), locked by a differential against a port of
   Radiant's `GetScriptOp` (`tests/test_glyph.py:1622 TestRefWalkerConsensusDifferential`).
3. **A malformed WIF was echoed back**, disclosing the key it failed to decode: one non-base58
   character printed 51 of 52 characters to stderr. Fixed at the *decoder* (every input treated
   as secret; static messages; `from None` cause suppression), because by the time a string
   reaches `b58_decode` nothing says "this one is public". Regression:
   `tests/security/test_key_material_never_echoed.py` (51/52 before, 0/52 after).
4. **`pyrxd swap` fee'd every RSWP transaction at one-thousandth of the relay floor** (photons
   per kB where the config value is per **byte**), so orders and — the fund-safety edge —
   **cancels** could not relay, while the CLI printed a txid and reported success. A cancel that
   never relays leaves the order takeable at the original price, and on this chain the
   transaction cannot be repaired (`ASSUME-NO-FEE-BUMP`). Fixed by sizing from the transaction's
   own serialized length (`tests/cli/test_swap_fee_sizing.py`, 29 tests, 28 of which fail on the
   pre-fix module).

**The honest lesson: reviewing the diff would not have found any of them.** All four were found
by re-deriving expected behaviour from chain rules and re-running old scenarios against current
code — unit/denomination seams (fees per byte vs per kB; FT units = satoshis), consensus-parity
seams (a hand-rolled walker vs `GetScriptOp`), secret-bearing error paths, and checks that
existed in only one copy or on only one side. Prior cycles show the same shape: 0.12.0 fixed
four fund-loss/stranding defects (flat commit sizing that stranded large-metadata mints; the
scanner returning `metadata=None` on all real chain data since 0.2.0; missing NFKD seed
normalization; wrong reported genesis ref) plus a verified-exploitable watchtower
command-execution path, and the 0.11.0 pre-release panel found two HIGH fund-safety bugs in the
RSWP order-construction layer. An audit should weight these seams accordingly.

## 8. Known-open items at 0.14.0

Stated so the auditor does not spend budget discovering them. Each is verified against `main` at
this commit, not against a plan:

1. **Six `-m integration` e2e suites are currently failing and need reordering** for the new
   taker-side gate: `tests/test_xchain_swap_regtest_e2e.py`,
   `tests/test_xchain_eth_swap_regtest_e2e.py`, `tests/test_xchain_eth_adversarial_e2e.py`,
   `tests/test_xchain_eth_active_adversary_e2e.py`,
   `tests/test_xchain_eth_glyph_real_rxindexer_e2e.py`,
   `tests/test_xchain_eth_tierb_isolated_e2e.py`. They still fund the covenant *after*
   `taker_funds_btc` (verified: `test_xchain_swap_regtest_e2e.py:525-531`) — the pre-HZ-1 order
   the hazard names as unsafe — so the fail-closed gate refuses them. They are opt-in
   (env-gated) and deselected from `task ci` (`pyproject.toml:432`, `-m 'not integration'`), so
   default CI is green; the reordering is a tracked follow-up (CHANGELOG 0.14.0).
2. **A CONTAINER output with a child ref is mintable but unroutable**: `prepare_container_reveal`
   (`glyph/builder.py:673`) builds a 100-byte script no pyrxd classifier matches —
   `GlyphInspector.find_glyphs` skips it and `build_nft_transfer_tx` refuses it (requires
   exactly 63 bytes). Container semantics beyond creation are undefined in this implementation
   (spec §16.2).
3. **The handshake has no version negotiation.** The envelope `schema` tag is written at four
   sites and read at none; `NegotiatedTerms` has **no version field** and `from_dict` silently
   drops unknown keys (`gravity/swap_state.py:398-415`; locked by
   `test_from_dict_silently_ignores_unknown_keys`). A receiver cannot detect that a sender meant
   something it does not understand; safety rests entirely on the two independently re-derived
   scriptPubKey comparisons (HZ-2, [`htlc-handshake-wire-format.md`](htlc-handshake-wire-format.md)).
4. **Envelope decode is lossy.** `decode_payload` drops any key it does not model (measured on
   the reference mainnet token: its `by` field is silently discarded), and decode-then-encode is
   **not** an identity — it MUST NOT be used to verify a payload against a commit hash (spec
   §16.1). Relatedly, the CLI metadata-file loader still drops `creator`, `policy`, `rights`,
   and `v` — most consequentially, `policy.transferable: false` mints as freely transferable,
   silently (recorded residual, CHANGELOG 0.14.0; `red-team-checklist.md` §5.1 flags the
   affected manual step as known-failing).
5. **Creator signatures are computed over a non-canonical encoding** (`glyph/creator.py:43` —
   `cbor2.dumps` without `canonical=True`, insertion-order dependent), and they attest to
   pyrxd's *decoded field set*, not the on-chain bytes: adding an unknown field to a signed
   payload does not invalidate the signature (spec §10.2–10.3). This **cannot be changed without
   invalidating every existing on-chain signature** — it is a permanent compatibility constraint
   to audit around, not an oversight awaiting a fix.

## 9. Residual register (consolidated, stable IDs)

Every accepted/known residual, deduplicated across the threat model, design notes, and code.
`(TM S#/gap#)` = also in the threat model (which now runs **S1..S24** and gaps **1–20**);
otherwise the residual lives only in a design note or code docstring (the brief's value-add —
these would otherwise be missed).

### 9.1 Swap / covenant
| ID | Sev | Status | Residual | Where / legacy id |
|---|---|---|---|---|
| `SWAP-R1` | critical | mitigated (gate) | Consensus enforces ref **uniqueness**, not **provenance** — a fake-singleton covenant is consensus-valid; `verify_ref_authenticity` is the *only* defense | `gravity/ref_authenticity.py` · R1 |
| `SWAP-COVENANT-BUGS` | critical | open | Gravity covenant variants "still being hardened" — the most concentrated risk in the codebase | TM S10 / gap #12 |
| `SWAP-FREEOPT` | high | accepted | Taker offline/censored across `[reveal, t_rxd]` → one-sided loss (HTLC free option). Bounded by margin + reorg gate + value-scaled burial; **not** eliminated | TM S20 / R1 |
| `SWAP-TIMELOCK-INVARIANT` | high | mitigated | `t_counter > t_rxd + margin` is client-enforced (`assert_timelock_margin`); a wrong client could route around it | `swap_coordinator.py` |
| `SWAP-MAKER-STALL` | high | mitigated | A stalling maker can take both legs unless the taker stops waiting / refunds proactively (C1) | `swap_coordinator.py` |
| `SWAP-BURIAL` | high | mitigated | Flat claim-burial bounds reorg *probability*, not reorg *cost vs value* (low-cap PoW); value-scaled burial now enforced | `swap_coordinator.py` · red-team 2026-06-12 HIGH |
| `SWAP-MARGIN-MEASURED` | high | gate | Default cross-chain margin is **estimated**; a real-value swap must use `MarginPolicy.measured(...)` | `swap_coordinator.py` |
| `SWAP-SEEN1` | high | mitigated | Non-durable seen-store loses H-freshness across restart/2nd process; durable SQLite store is now the harness default | `gravity/seen_store.py` · SEEN-1 |
| `SWAP-COUNTER-UNDERFUND` | high | mitigated | Hostile taker funds the correct counter-leg HTLC **short** (a P2TR SPK commits to the taptree, not the value; the amount bind lived in the taker's own method). Maker-side gate now binds SPK + exact value + depth on both chains and re-runs at asset-lock time. Residual: the gate is only as good as the chain source behind it (use quorum/local node at value), and the BTC arm has **not** been exercised in a live two-party run — only in `tests/test_btc_maker_counter_funding_adversarial.py` | `swap_coordinator.py`, `btc_wallet/htlc_leg.py`, `gravity/eth_leg.py` · TM S23 / HZ-3 |
| `SWAP-MAKER-NEVERLOCKS` | high | mitigated | Maker publishes the envelope, locks **nothing**, and sweeps the taker's counter leg with the `p` it has held all along (the BTC claim leaf has no asset-lock precondition; loss = the full counter leg). Taker-side gate now re-derives the covenant SPK from the taker's own terms, binds exact value + depth, and re-runs inside `taker_funds_btc`. Residual: reads a **single** ElectrumX endpoint (no RXD leg-side quorum reader exists); not exercised in a live two-party run — only in `tests/test_taker_asset_funding_gate_adversarial.py` | `swap_coordinator.py`, `gravity/radiant_leg.py` · TM S24 / HZ-1 |
| `SWAP-FEE-IRREVERSIBLE` | high | mitigated | Radiant has **no RBF and no CPFP**, so an under-fee'd time-critical spend is unrepairable for the 8-hour mempool expiry — inside a swap deadline that is a total loss to the counterparty's refund. Deadline-aware pre-sizing is the only control (`gravity/fee_policy.py`, `htlc_spend.py`, `radiant_leg.py:607 _assert_affordable`); a shortfall refuses + pages. Residual: the urgency premium is a **policy choice, not a measured inclusion model** (no Radiant fee/confirmation curve has been measured), and fee-source funding under a deadline remains an operator responsibility | TM S21 |
| `SWAP-GRIEF-LIVENESS` | medium | accepted | Capital-lockup griefing: a counterparty opens swaps and never locks its leg — nothing is lost, but the victim's capital is immobilised for the full timelock at ~zero attacker cost, and the attack is *inaction* (indistinguishable from flaky connectivity to every safety oracle). **The swap stack defends SAFETY, not LIVENESS.** A bond/deposit is deliberately not built (revisit trigger documented) | TM S22 · `solutions/design-decisions/griefing-is-a-liveness-residual-not-a-bond.md` |
| `SWAP-HANDSHAKE-NOVERSION` | medium | open | No version negotiation in the handshake (§8 item 3): unknown keys silently dropped, no version field; everything outside the two re-derived SPK comparisons is effectively unauthenticated | `gravity/swap_state.py` · HZ-2 |
| `SWAP-ETH-MARGIN` | medium | gate | Value-bearing ETH swap on estimated margins disables two ETH defenses unless consciously opted in | `swap_coordinator.py` · MEDIUM-1 |
| `SWAP-ETH-DEPLOY-VERIFY` | medium | mitigated | `EthLeg.verify_funded` necessarily runs *after* value is on-chain (no pre-image of funding) | `gravity/eth_leg.py` |
| `RSWP-EXPERIMENTAL` | high | open | The RSWP on-chain orderbook (v3 covenant write side + order lifecycle) is **experimental** and internally red-teamed only (0.11.0 pre-release panel: 2 HIGH found+fixed; 0.14.0: the fee-sizing fund-safety fix). `cancel` is the only hard revocation for a v2 order | `src/pyrxd/swap/rswp/`, `cli/swap_book_cmds.py` |

### 9.2 Capped fee source (autonomy trust boundary)
| ID | Sev | Status | Residual | Where |
|---|---|---|---|---|
| `CAPFEE-ISOLATION` | high | accepted | The structural ceiling holds only if the pool key is isolated from the main wallet — the class cannot verify this | `capped_fee_source.py` |
| `CAPFEE-TYPE-GATE` | high | accepted | `RadiantCovenantLeg` accepts any `FeeUtxoSource` (shape, not capped type). As-is posture decision (0.9.0+): `CappedFeeWalletSource` is **recommended, not enforced** — the library hands you the safe tool, it doesn't refuse your fee source. Blast radius of an uncapped key is fees-only (cannot redirect the asset); arming the autonomous path is the affirmative gate. | `radiant_leg.py`, `claim_executor.py` |
| `CAPFEE-MANUAL-REFILL` | medium | accepted | Pool refill must be a manual, audited op — never an auto top-up from the main wallet | `capped_fee_source.py` |
| `CAPFEE-FAILCLOSED-CALLER` | medium | accepted | The caller must treat `FeePoolExhaustedError` as fail-closed (no uncapped fallback). Since 0.14.0 the cap charges **spend, not dispense**: a refused (never-broadcast) build credits its charge back via `release_unspent` (`capped_fee_source.py:217`) *without* rewinding the dispense-once cursor — before that fix, retried fee refusals measurably drained a pool to exhaustion with the covering input unreachable (CHANGELOG 0.14.0) | `capped_fee_source.py`, `radiant_leg.py` |

### 9.3 Watchtower
| ID | Sev | Status | Residual | Where |
|---|---|---|---|---|
| `WATCH-AUTONOMY-GATE` | high | deferred | Autonomy beyond dust is audit-gated; the v2 BTC refund is dormant-by-construction + dust-capped (10,000 sats); the claim executor is additionally unreachable from any entrypoint | `watch/executor.py`, `watch/run.py` |
| `WATCH-TWO-PARTY` | high | open | No genuine two-party adversarial run — every run so far is single-operator (plumbing proof, not adversarial proof). Verifier tooling exists (`scripts/swap_run_verify.py`) but has only checked single-operator runs | `watch/README.md` |
| `WATCH-COFIRE` | medium | accepted | Below-quorum-inside-window can co-fire claim+refund into a "hold-that-loses" (accepted: hold + CRITICAL operator fallback) | `watch/README.md` |
| `WATCH-ETH-SINGLESRC` | medium | open | Single-source ETH detection/finality in the tower (no ETH quorum — `MultiSourceEthRpc` is the still-open analogue of the shipped RXD quorum) — can *delay* a page, never lose one | `watch/eth_adapters.py` |
| `WATCH-ETH-NOEVENT` | medium | accepted | An ETH HTLC that emits no event on `claim()` is undetectable by the tower | `watch/eth_adapters.py` |
| `WATCH-SEENSTORE-DUR` | low | open | Watchtower dedup / SeenStore durability across restarts | `watch/README.md` |
| `WATCH-STALLTRACKER` | low | mitigated | `FinalityStallTracker` is now held per-swap inside the tower's quorum observer for ETH (stateful across ticks; upgrades a stalled `NOT_YET_FINAL_LIVE`) — the former "not wired into the live tower" wording is superseded | `watch/quorum.py` |

### 9.4 SPV
| ID | Sev | Status | Residual | Where / legacy |
|---|---|---|---|---|
| `SPV-SOLE-AUTHORITY` | high | mitigated (covenant pin) | No most-cumulative-work selection / difficulty oracle; safe only behind a covenant nBits pin. NOTE: the `require_spv_sole_authority_cleared` "gate" is an advisory **no-op** as of 0.9.0 (`spv/proof.py:38-54`) — the covenant pin is the defense, not the gate; TM gap #8's "fails closed" wording is stale | `spv/chain.py`, `proof.py` · F-01 / TM gap #8 |
| `SPV-DIFFICULTY-FLOOR` | high | accepted | Offer-time difficulty floor + most-work selection deferred to the covenant pin | `spv/chain.py` · pitfalls how-to |
| `SPV-SINGLESOURCE-DEPTH` | medium | accepted | Single-source confirmation depth gated to low value; quorum only detects disagreement | `network/bitcoin.py` |
| `SPV-SWAP-R2` | medium | accepted | Deprecated SPV-oracle *swap* covenant accepts `scriptSig ≥ 128 B` (taker-fund-loss footgun) — won't-fix on the retired path | spv-swap-deprecated note · R2 |
| `SPV-SWAP-FORGED` | medium | accepted | Forged-payment-in-scriptSig in the deprecated swap parser — won't-fix on the retired path | spv-swap-deprecated note |

### 9.5 REF gate / indexer / network
| ID | Sev | Status | Residual | Where / legacy |
|---|---|---|---|---|
| `NET-SINGLE-SOURCE` | medium | accepted | Single-source RXD/REF reads (= `ASSUME-SINGLE-SOURCE`; the watchtower's RXD depth read is the quorum'd exception) | TM gap #6 |
| `REFGATE-TRANSPORT-PARITY` | high | mitigated | The REF gate's fail-closed property must hold across **both** the ElectrumX and the REST transports | `radiant_leg.py`, `network/rxindexer.py` |
| `REFGATE-SOURCE-SKEW` | medium | accepted | RXinDexer REST field/shape drift is brittle (fail-closed on drift) | `network/rxindexer.py` |
| `NET-ELECTRUMX-HISTORY` | low | open | A *consistently* lying ElectrumX can hide address history (privacy); multi-source *cross-checking* ElectrumX is still not implemented — the 0.14.0 registry/failover is availability + chain-identity (`assert_chain` genesis pin), not quorum | TM S9 · `network/registry.py`, `failover.py` |
| `NET-UTXO-VALUE` | low | accepted | A lying ElectrumX UTXO value → fee overpay / invalid tx (network-rejected), never direct theft | TM S8 |
| `NET-TLS-PINNING` | medium | mitigated (opt-in) | Optional SPKI pinning shipped 0.14.0 (`network/tls_pin.py`) — **off by default, deliberately** (an unannounced key rotation would break every pinned client; the module documents the rationale). Default posture remains system trust store, so CA compromise → TA4 unless the operator names pins. TM gap #7's "no certificate pinning" wording predates this module | `network/tls_pin.py` · TM gap #7 |
| `NET-FAILOVER-SELFCORROB` | low | accepted | An "already known" broadcast rejection is honored only after a read-back returns the same bytes — but the *same endpoint* corroborates its own claim, so a fully hostile endpoint that both rejects and echoes still passes; what this removes is a `-27` backed by no transaction at all (stated in the code/CHANGELOG) | `network/failover.py` |

### 9.6 Key material / wallet / agent
| ID | Sev | Status | Residual | Where / legacy |
|---|---|---|---|---|
| `KEY-SCROLLBACK` | high | accepted | Mnemonic in terminal scrollback — cannot clear portably | TM S2 |
| `AGENT-SAMEUID` | high | mitigated | Same-uid process abuses the unlocked agent — bounded by per-spend `/dev/tty` confirmation; the agent never returns key material | TM S18 / issue #8 / H1 |
| `KEY-COINTYPE-LOAD` | high | mitigated | Formerly: the load path did not validate persisted `coin_type`. Now: `coin_type` is a **required** wallet-file field (absence is a hard error), the persisted value passes the same validation gate as the kwarg path, a mismatched explicit kwarg refuses with a fix-it message, and the persisted value pins the derivation path (`hd/wallet.py:577-608`) — a module-default flip can no longer silently re-route a saved wallet | `hd/wallet.py` |
| `KEY-CLIPBOARD` | medium | open | No clipboard-hygiene warning after mnemonic display | TM S3 / gap #10 / issue #11 |
| `KEY-JSON-REDIRECT` | medium | accepted | `wallet new --json --yes \| tee` lands the mnemonic unencrypted — documentation, not enforcement | TM S1 |
| `AGENT-REDIRECT` | medium | mitigated | Agent tricked into fee-theft/redirect signature — bounded by prevout authenticity (C1) + `ALL\|FORKID`-only | TM S19 |
| `KEY-COINTYPE-DOWNGRADE` | medium | accepted | NEW→OLD→NEW coin-type downgrade can corrupt persisted `coin_type` | `solutions/design-decisions/coin-type-512-default-with-legacy-zero-recovery.md` |
| `KEY-NFKD-LEGACY` | medium | accepted | The `normalize=False` recovery escape (for pre-0.12.0 wallets with non-ASCII passphrases) derives a seed **no conformant BIP39 implementation reproduces**; it exists solely to sweep funds out. `load_or_create(normalize=False)` refuses to *create* (0.14.0), so the footgun is load-only | `hd/bip39.py`, `hd/wallet.py` |
| `KEY-XPUB-DISCLOSURE` | medium | accepted | A descriptor/xpub export is a **whole-history disclosure** — every address the wallet will ever derive, on both chains, permanently. Documented in the command's own help/output (0.14.0 corrected earlier "safe to share" wording); `_coerce_xpub` re-validates the key body is a public point at the emit boundary | `hd/descriptor.py` |
| `KEY-ZEROIZE` | low | accepted | Best-effort zeroization; the transient signing-key copy is irreducible (key must exist to sign) | TM gap #5 |
| `KEY-BRUTEFORCE` | low | mitigated | Offline brute-force of a leaked `wallet.dat` — scrypt n=2^14 + per-file salt + GCM tag | TM S4 |
| `KEY-WORLDREADABLE` | low | mitigated | World-readable `wallet.dat` post-restore — load-time mode check (POSIX only) | TM S5 |

### 9.7 Glyph / metadata / dMint
| ID | Sev | Status | Residual | Where / legacy |
|---|---|---|---|---|
| `GLYPH-OWNERPKH` | high | mitigated (CLI) | The CLI mint paths now derive `owner_pkh` from the funding wallet (not from the metadata file) and the pre-broadcast summary prints it — `owner_pkh: … (this wallet)` (`cli/glyph_cmds.py:446,719`). TM S7 / gap #9's "summary does not surface owner_pkh" wording predates this. The hostile-metadata residual has **moved**, not vanished: see `GLYPH-METADATA-DROPPED-FIELDS` | `cli/glyph_cmds.py` · TM S7 / gap #9 |
| `GLYPH-METADATA-DROPPED-FIELDS` | high | open | The CLI metadata-file loader silently drops `creator`, `policy`, `rights`, `v` (`royalty` and `dmint` were the same bug, fixed 0.14.0). Most consequential: `policy.transferable: false` — a token the creator marked soulbound mints freely transferable, with no warning, permanently | `cli/glyph_helpers.py` · CHANGELOG 0.14.0 residual |
| `GLYPH-ENVELOPE-LOSSY` | medium | accepted | `decode_payload` drops unknown keys; decode-then-encode is not an identity and MUST NOT verify a payload against a commit hash (measured on the reference mainnet token — its `by` field is discarded) | `glyph/payload.py` · spec §16.1 |
| `GLYPH-CREATOR-SIG-CANON` | medium | accepted | Creator signatures are computed over a **non-canonical**, insertion-order CBOR encoding (`glyph/creator.py:43`) and attest to the modelled field set, not the on-chain bytes (unknown fields do not invalidate). Unchangeable without invalidating every existing on-chain signature — a permanent compat constraint | `glyph/creator.py` · spec §10.2–10.3 |
| `GLYPH-CONTAINER-UNROUTABLE` | medium | open | A CONTAINER with a child ref is mintable but no classifier matches it: invisible to `find_glyphs`, refused by transfer (§8 item 2) | `glyph/builder.py`, `glyph/inspector.py` · spec §16.2 |
| `GLYPH-PARSER-FUZZ` | medium | mitigated (partial) | Formerly "not yet fuzzed". Coverage-guided atheris harnesses now exist for the attacker-facing parsers — `scripts/fuzz_atheris/` (`harness_decode_payload.py`, `harness_inspect_script.py`, `harness_classify_input.py`, `harness_extract_reveal_metadata.py`, `harness_dmint_from_script.py`, plus RSWP + SPV harnesses) — on a **weekly scheduled** CI lane (`.github/workflows/fuzz.yml`), not per-PR. TM gap #3's CLI-surface fuzzing (issue #10) remains open | `scripts/fuzz_atheris/harness_decode_payload.py` · TM gap #3 |
| `GLYPH-DUAL-WALKER` | medium | mitigated | Formerly: divergent opcode walkers could drift on reserved bytes. This is exactly the defect the 0.14.0 panel found live (§7 item 2 — four walkers, split two-and-two). All walkers now share the single consensus-correct `REF_OPCODES` (`glyph/script.py:442`), differential-locked against a port of Radiant's `GetScriptOp` (`tests/test_glyph.py`) | `glyph/script.py`, `glyph/credential_binding.py` · FT-covenant note |
| `GLYPH-MINT-STRAND` | medium | mitigated | The commit output is a hashlock with **no owner-only spend path**: losing the exact CBOR between commit and reveal strands it permanently. The two-phase minter makes persistence a *required* constructor argument (opting out means naming `UnsafeNullPendingStore`), writes-then-reads-back before broadcast, and re-hashes the stored payload before any reveal | `glyph/mint.py` · CHANGELOG 0.13.0 |
| `DMINT-V2-GOLDEN` | medium | mitigated | Mainnet golden anchors now cover the FT locking script, NFT locking script, commit script (both variants), envelope + reveal framing, dMint V1 contract + mint reward, and the V2 FIXED contract — each pinned byte-for-byte against a named mainnet transaction in CI (spec §17 anchor table; `tests/test_dmint_v2_mainnet_golden.py`). The mainnet **LWMA** deploy is deliberately NOT pinned: it is pre-fix bytecode (before the `OP_0 OP_MAX` timeDelta floor), so the post-fix LWMA path is covered by regenerated synthetic vectors + the regtest e2e | `tests/test_dmint_v2_mainnet_golden.py` · spec §17 |

### 9.8 Supply chain / process / deferred
| ID | Sev | Status | Residual | Where / legacy |
|---|---|---|---|---|
| `PROC-NO-AUDIT` | high | open | No external eyes — solo developer; an independent review is the natural next step for the swap stack (this brief scopes it) | TM gap #1 / #20 |
| `SUPPLY-COINCURVE` | critical | accepted | Backdoored `coincurve` release would compromise every signature; major-range pin + `pip-audit` only | TM S11 |
| `SUPPLY-NOPIN` | medium | accepted | No pinned transitive dep hashes — deliberate for a *library* | TM gap #15 |
| `SUPPLY-SBOM-GAP` | low | mitigated | Honesty correction to the earlier "SBOM now ships" claim: SBOM generation **silently failed on every release from v0.9.0 through 0.11.1** (masked by `continue-on-error`); 0.11.2 is the first release to actually attach one (CHANGELOG 0.11.2). PEP 740 attestations were unaffected. Releases in that range have no SBOM asset | `.github/workflows/publish.yml` · TM gap #16 |
| `SUPPLY-GPGTAG` | low | open | PEP 740 attestations ship; a gpg-signed git tag is still optional and not set up | TM gap #17 |
| `FT-COVENANT-SPV-UNBUILT` | medium | deferred | The FT-in-covenant SPV cross-chain settle path is sig-gated only; SPV fusion unbuilt | FT-covenant note |
| `WAVE-DEFERRED` | low | deferred | WAVE protocol deferred; a pyrxd-minted WAVE name would be unresolvable until a consumer exists | wave note |

## 10. Legacy-ID disambiguation (read before cross-referencing)

The pre-existing numbering has collisions the auditor will otherwise trip on:

- **"#8" had three meanings** — the duplicate is fixed in `threat-model.md`. **Gap #8** =
  `SPV-SOLE-AUTHORITY` (network); the CLI `owner_pkh` gap that previously *also* numbered `#8`
  is **gap #9** (`GLYPH-OWNERPKH`), and the "Known gaps" tail runs `1–20` uniquely; **GitHub
  issue #8** = the signing-agent feature (hardening **H1**), unrelated to either gap.
- **The threat model now runs S1..S24.** The 20th scenario, historically id'd "R1", is now
  first-class **S20**; S21–S24 were added 2026-08-09/10 (see the threat model's revision
  history). This brief's earlier "scenarios S1..S19 + R1" description is superseded.
- **"HZ-n" ids** come from [`htlc-handshake-wire-format.md`](htlc-handshake-wire-format.md)
  (HZ-1..HZ-8). Two were promoted to threat-model scenarios: **HZ-1 → S24**
  (`SWAP-MAKER-NEVERLOCKS`), **HZ-3 → S23** (`SWAP-COUNTER-UNDERFUND`). The rest remain
  documented hazards in that spec.
- **"R1" is overloaded** but consistent in meaning: the REF-authenticity / fake-singleton
  residual (`SWAP-R1`) and the maker free-option residual (`SWAP-FREEOPT`) both trace to "R1"
  in different docs; the watch package separately uses local `LOW-R2`/`LOW-R3` tags (unrelated).
- **"F-01" ≠ "F-001"**: `F-0x` are 2026-05-29 Bitcoin-SPV audit findings; other docs use `F-0xx`
  (gravity) and `pitfall #1..#14` (the SPV how-to) as independent local schemes.
- **"SeenStore" names two things**: the swap-coordinator `SeenStore`/`DurableSeenStore`
  (`SWAP-SEEN1`) and the watch-layer dedup durability (`WATCH-SEENSTORE-DUR`).
- **"B1/B2/B3, A1/A2, D1/D2"** in 0.13–0.14 commit subjects are internal backlog item ids, not
  finding ids.

## 11. The corpus — how to exercise the claims

- **Local CI:** `task ci` (ruff lint + bandit, format check, full pytest, 100% security-pkg +
  85% overall coverage, mypy on `pyrxd.security`, private-link check — `pyproject.toml`
  `[tool.taskipy.tasks]`). The default pytest run deselects `-m integration`
  (`pyproject.toml:432`).
- **Swap consensus on a real node** (opt-in, skips without docker/image):
  `RADIANT_REGTEST=1 pytest tests/test_htlc_regtest_e2e.py -m integration` (Radiant HTLC: claim,
  wrong-preimage, premature/matured CSV refund, the `R1` fake-singleton acceptance);
  `XCHAIN_REGTEST=1 pytest tests/test_xchain_swap_regtest_e2e.py -m integration` (full BTC↔RXD);
  `XCHAIN_ETH_REGTEST=1 pytest tests/test_xchain_eth_swap_regtest_e2e.py -m integration`
  (ETH↔RXD). **CAUTION:** the six cross-chain suites are currently red pending the HZ-1
  reordering (§8 item 1) — a failure there at this commit is expected, not a regression signal.
- **Red-team + adversarial suites:** `tests/test_gravity_red_team.py` (1,800 lines — `wc -l` at
  this commit) documents known covenant concerns; `tests/test_xchain_eth_adversarial_e2e.py`
  covers hostile-maker/taker scenarios; `tests/test_btc_maker_counter_funding_adversarial.py`
  (S23: under/over-funded, decoy SPK, shallow, spent, verified-then-reorged) and
  `tests/test_taker_asset_funding_gate_adversarial.py` (S24: never-funded, mis-valued, wrong
  script, 0-conf, TOCTOU) drive the real coordinator against hostile chain views.
- **Conformance vectors (language-agnostic, CI-checked):** `conformance/htlc-handshake-vectors.json`
  (51 checks — CHANGELOG 0.14.0), `conformance/dmint-v2-contract-vectors.json`,
  `conformance/rswp-order-vectors.json`, `conformance/bip44-derivation-vectors.json`.
- **Fuzz + mutation:** weekly scheduled atheris lane over `scripts/fuzz_atheris/harness_*.py`
  (`.github/workflows/fuzz.yml`, accumulated corpus); `task mutate` (cosmic-ray) for
  mutant-kill measurement.
- **Per-primitive:** `tests/test_capped_fee_source.py`, `tests/test_seen_store.py`,
  `tests/test_agent_signer.py`, `tests/cli/test_swap_fee_sizing.py`,
  `tests/test_ft_transfer.py` (the §7 property suite),
  `tests/security/test_key_material_never_echoed.py`, the SPV verifier + differential tests
  under `tests/`, and `tests/test_residual_register_traceability.py` — which machine-checks
  that every code/test path cited in **this document's** residual register exists.

## 12. References

- [`threat-model.md`](threat-model.md) — actors, scenarios `S1..S24`, controls, known gaps 1–20.
- [`../SECURITY.md`](../SECURITY.md) — report scope, disclosure SLA, supported versions.
- [`htlc-handshake-wire-format.md`](htlc-handshake-wire-format.md) — the negotiation-layer spec
  + hazards HZ-1..HZ-8 + conformance vectors.
- [`reference/glyph-token-protocol-spec.md`](reference/glyph-token-protocol-spec.md) — the
  normative Glyph spec; §9 (what consensus does NOT enforce), §16 (underspecified behaviour),
  §17 (mainnet provenance anchors).
- [`runbooks/incident-response.md`](runbooks/incident-response.md) — the internal handling flow.
- [`runbooks/watchtower-operations.md`](runbooks/watchtower-operations.md) — operating the tower,
  incl. the fee-sizing operator duties from S21.
- [`concepts/architecture.md`](concepts/architecture.md) — the L0–L4 module map + trust
  boundaries.
- [`how-to/spv-verification-pitfalls.md`](how-to/spv-verification-pitfalls.md) — the SPV pitfall
  catalogue.
- Design notes under [`solutions/design-decisions/`](solutions/design-decisions/) — the
  capped-fee trust boundary, the SPV-swap deprecation, the coin-type default, the
  griefing-is-liveness decision, royalties-are-advisory.
- `src/pyrxd/gravity/watch/README.md` — the watchtower's own v1/v2 posture + residuals.
- `CHANGELOG.md` — the 0.10.0–0.14.0 entries carry the measurements behind every §7 claim.

---

*Freeze the audited commit SHA in the header at commission time; re-run this brief's residual
inventory if `main` has moved materially since. This revision reconciled the register against
`threat-model.md` S1–S24 and re-verified every carried-forward code claim against `main` at
0.14.0 (2026-08-10).*
