# pyrxd — external security audit scoping brief

**Status:** draft for commission · **Frozen commit:** _pin at commission time_ (do **not**
audit a moving `main`) · **Companion docs:** [`threat-model.md`](threat-model.md),
[`../SECURITY.md`](../SECURITY.md), [`concepts/architecture.md`](concepts/architecture.md).

This brief tells an external auditor **what to audit, what is deliberately out of scope, the
assumptions the code is allowed to make, and the complete register of accepted/known residual
risks** — consolidated from the threat model, the design-decision notes, and the in-code
residual notes so the audit reviews a *stated* boundary rather than rediscovering it. pyrxd is
open-source software, provided as-is under the [LICENSE](../LICENSE); the cross-chain swap stack
is **unaudited**, and this brief is the deliverable that lets an independent review certify it.
As of 0.9.0 the library-wide `require_audit_cleared` / `require_spv_sole_authority_cleared` gates are
**advisory no-ops** (retained for backward compatibility) — pyrxd "does what you tell it," consistent
with running a Radiant node, and does **not** code-block mainnet/real-value use. Real-value safety is
therefore a documented operator responsibility, not a code-enforced default (see `ASSUME-AS-IS-POSTURE`
in §3). The one exception is the autonomous claim executor's `enable_autonomous_mainnet_custody`
(default off), which still affirmatively gates unattended mainnet money-movement.

## 0. How to use this brief

- Residuals carry **stable IDs** (e.g. `SWAP-R1`, `CAPFEE-ISOLATION`). Where a residual already
  had a legacy id (a threat-model `S#`/gap `#n`, or an in-code tag like `SEEN-1`, `MEDIUM-1`,
  `R1`, `F-01`), the legacy id is noted — the legacy numbering has known collisions (see §7).
- **Severity** is the *pre-mitigation* class; **Status** is `open` / `mitigated` (a control
  exists) / `accepted` (a conscious residual) / `deferred` (a feature not built) / `gate` (an
  affirmative opt-in that defaults the risk off until consciously enabled). NOTE: the legacy
  library-wide `require_audit_cleared` / `require_spv_sole_authority_cleared` "gates" are **advisory
  no-ops** as of 0.9.0 (posture-only, not fail-closed); the only live `gate` is the executor's
  `enable_autonomous_mainnet_custody`.
- Start at §5 (priority targets) for where the return-on-review is highest.

## 1. Scope — what to audit

The audit-critical surface (ranked; full per-module rationale in
[`concepts/architecture.md`](concepts/architecture.md)):

| Area | Modules | Why critical |
|---|---|---|
| **Cross-chain swap covenant** | `src/pyrxd/gravity/` — `htlc_covenant.py`, `htlc_spend.py`, `radiant_leg.py`, `swap_coordinator.py`, `ref_authenticity.py`, `capped_fee_source.py`, `seen_store.py` | The single most adversarial setting (hostile counterparty wants both legs). Covenant build/spend, the role/timelock invariant, the REF-authenticity gate, the fee-key trust boundary. |
| **BTC + ETH counter-legs** | `src/pyrxd/btc_wallet/` (`htlc_leg.py`, `taproot.py`, `chains.py`), `src/pyrxd/eth_wallet/` (`chains.py`, `locator.py`), `src/pyrxd/gravity/eth_leg.py` | The Taproot-HTLC + Solidity-HTLC legs, the `require_audit_cleared` gate + `AUDIT_CLEARED_NETWORKS`, the per-chain finality/block-interval safety knobs. |
| **Watchtower** | `src/pyrxd/gravity/watch/` — `decide.py`, `reconciler.py`, `quorum.py`, `executor.py`, `adapters.py`, `eth_adapters.py`, `alerts.py`, `heartbeat.py` | Alert-only v1 + the dormant, dust-capped, keyless v2 BTC refund. `executor.py` is the **only** component that broadcasts. |
| **SPV verification** | `src/pyrxd/spv/` — `chain.py`, `proof.py`, `pow.py`, `merkle.py`, `payment.py` | One-way Bitcoin-proof verifier that gates covenant release. The nBits-pin-before-PoW defense + `require_spv_sole_authority_cleared`. |
| **Key material** | `src/pyrxd/hd/wallet.py`, `src/pyrxd/security/` (`secrets.py`, `types.py`), `src/pyrxd/keys.py`, `src/pyrxd/hd/bip32.py` | AES-256-GCM + scrypt wallet; `SecretBytes`; the agent's transient-xprv re-derivation; coin-type derivation. |
| **Signing agent** | `src/pyrxd/agent/` — `signer.py`, `confirm.py`, `daemon.py`, `hygiene.py` | The unlocked-wallet daemon (A11) on a `0600` socket; per-spend `/dev/tty` confirmation; prevout authenticity. |
| **Glyph / metadata / dMint** | `src/pyrxd/glyph/` — `script.py`, `dmint.py`, `dmint/chain.py`, metadata→scriptPubKey path | Attacker-facing parser surface + the hostile-metadata `owner_pkh` trust path. |
| **Lying-server defenses** | `src/pyrxd/network/electrumx.py`, `src/pyrxd/network/bitcoin.py` | `wss`-only, response caps, per-id correlation, the multi-source BTC quorum. |

`SECURITY.md` lists the in-scope packages for *reports* (`pyrxd.curve|security|aes_cbc|crypto`,
`pyrxd.hd`, `pyrxd.transaction|script`, `pyrxd.glyph`, `pyrxd.gravity`, `pyrxd.network`).

## 2. Out of scope

From the threat model's non-goals + `SECURITY.md`: coercion / $5-wrench, physical access to an
unlocked machine, compromised OS/firmware/hypervisor, silicon side-channels, quantum (secp256k1
is not PQ-safe), typosquats / wrong-binary, the user leaking the mnemonic through channels pyrxd
can't see, dependency vulnerabilities (report upstream), and future Radiant consensus bugs.
**Single-sig only** (no multisig). **The deprecated SPV-oracle *swap* covenant is out of scope**
(superseded by the HTLC swap; see `SWAP-SPV-R2`/`-FORGED`).

## 3. Load-bearing assumptions (stated up front)

The audit should accept or challenge these explicitly — the code's safety arguments rest on them.

- **`ASSUME-SINGLE-SOURCE` (gap #6).** Three RXD-side reads trust a single source by design:
  (a) the default single ElectrumX endpoint for plain-RXD wallet ops; (b) the single RXinDexer
  that resolves Glyph reads and backs `verify_ref_authenticity`; (c) single-source RXD funding
  depth (dust only). Rationale: a *self-consistent* lie is byte-identical from every source, so a
  2nd source — which only detects *disagreement* — has bounded value; the load-bearing defenses
  are the on-chain covenant pins (nBits, the REF-uniqueness consensus rule), not read-side quorum.
  Standing up a 2nd independent RXD source is the right hardening **at first non-dust real value**.
- **`ASSUME-CAPFEE-ISOLATION`.** `CappedFeeWalletSource`'s structural ceiling is real **only if**
  the operator funds it from a key isolated from the main wallet (the class validates P2PKH +
  wif-control + the cap, but cannot verify key isolation). See `CAPFEE-ISOLATION`.
- **`ASSUME-AS-IS-POSTURE`** (was `ASSUME-PRE-AUDIT-GATE`). As of 0.9.0 the library-wide
  `require_audit_cleared` (`AUDIT_CLEARED_NETWORKS = {bcrt, regtest, tb, signet, rltc, tltc}`) and
  `require_spv_sole_authority_cleared` gates are **advisory no-ops** — they no longer block mainnet /
  real-value use (`spv/proof.py`, `btc_wallet/htlc_leg.py` both note "retained for backward-compatibility;
  no longer blocks"). pyrxd "does what you tell it," like running a Radiant node: real-value safety is a
  documented operator responsibility, not a code-enforced default. An auditor should treat these as
  *posture documentation*, not a fail-closed property. The single still-live affirmative gate is the
  executor's `enable_autonomous_mainnet_custody` (next item).
- **`ASSUME-WATCH-ALERT-ONLY`.** The watchtower core is **alert-only and keyless for the asset**; it
  never holds a value key and never touches `p` except to scrape the maker's already-public preimage.
  Two autonomous actions exist, both bounded: the v2 BTC refund (operator-pre-signed, dust-capped
  10 000 sats) and the Radiant **claim executor** (`watch/claim_executor.py`). The claim executor is
  **keyless for the asset** (`output[0]` pinned to the taker holder PKH → cannot redirect the asset;
  a stolen *fee* key burns only dust fees), **dormant-by-construction** (needs a wired resolver + a
  per-swap covenant sidecar), and **armed-by-exception** (`enable_autonomous_mainnet_custody`, default
  off, gates any value-bearing network). Autonomous RXD claim size is bounded by `claim_dust_ceiling`
  (a default the operator raises with explicit per-value consent; the blunt `accept_unbounded_reorg_risk`
  flag cannot cross it). R1's closure rests on **taker/operator liveness within `t_rxd`** for an un-armed
  or un-wired tower, and on the executor within the consented value bound for an armed one — there is no
  unattended asset-theft surface. See `CAPFEE-TYPE-GATE` for the (recommended-not-enforced) fee-source cap.

## 4. Affirmative opt-in gates

These are the live seams that default value-bearing risk off unless an explicit opt-in is set —
the seams an audit would certify before they are enabled:

| Gate | Defaults off | Where |
|---|---|---|
| `enable_autonomous_mainnet_custody` | unattended mainnet asset-claim broadcast | `gravity/watch/claim_executor.py` |
| `require_measured` margins (`MEDIUM-1`) | a real-value ETH swap on *estimated* margins | `gravity/swap_coordinator.py` |
| value-scaled claim burial vs `accept_flat_burial` | a non-dust swap reorg-reversible at flat burial | `gravity/swap_coordinator.py` |
| durable seen-store default (was `accept_nondurable_seen`) | replay/free-option window across restart | `gravity/seen_store.py`, value harnesses |
| `claim_dust_ceiling` (autonomous claim) | non-dust autonomous RXD claim (raise = explicit per-value consent) | `gravity/watch/claim_executor.py` |

> **Demoted (advisory no-ops as of 0.9.0, NOT fail-closed):** `require_audit_cleared` /
> `AUDIT_CLEARED_NETWORKS` (`btc_wallet/htlc_leg.py`, `gravity/radiant_leg.py`) and
> `require_spv_sole_authority_cleared` (`spv/proof.py`). These no longer block mainnet use — they are
> posture documentation only (see `ASSUME-AS-IS-POSTURE`). Do not certify them as fail-closed.

## 5. Priority targets (ranked by expected return)

1. **`gravity/` covenant + spend + REF gate** — highest stakes, most complex. Focus: covenant
   param binding, sighash handling, the `R1` fake-singleton defense (`SWAP-R1`), the timelock /
   role invariant (`SWAP-TIMELOCK-INVARIANT`, `SWAP-MAKER-STALL`), value-scaled burial.
2. **`hd/wallet.py` save/load + the agent** — key material; the transient-xprv re-derivation
   (`AGENT-SAMEUID`/H1) and prevout authenticity (`AGENT-REDIRECT`/C1).
3. **`spv/`** — the nBits-pin-before-PoW forgery defense and `SPV-SOLE-AUTHORITY` (F-01).
4. **`glyph/` parser + metadata path** — the attacker-facing parser surface (un-fuzzed) and the
   `owner_pkh` trust path (`GLYPH-OWNERPKH`/S7).
5. **`gravity/watch/`** — alert correctness, the co-fire `hold-that-loses` residual, and the
   dormant autonomy gate before any future arming.

## 6. Residual register (consolidated, stable IDs)

Every accepted/known residual, deduplicated across the threat model, design notes, and code.
`(TM S#/gap#)` = also in the threat model; otherwise the residual lives only in a design note or
code docstring (the brief's value-add — these would otherwise be missed).

### 6.1 Swap / covenant
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
| `SWAP-ETH-MARGIN` | medium | gate | Value-bearing ETH swap on estimated margins disables two ETH defenses unless consciously opted in | `swap_coordinator.py` · MEDIUM-1 |
| `SWAP-ETH-DEPLOY-VERIFY` | medium | mitigated | `EthLeg.verify_funded` necessarily runs *after* value is on-chain (no pre-image of funding) | `gravity/eth_leg.py` |

### 6.2 Capped fee source (autonomy trust boundary)
| ID | Sev | Status | Residual | Where |
|---|---|---|---|---|
| `CAPFEE-ISOLATION` | high | accepted | The structural ceiling holds only if the pool key is isolated from the main wallet — the class cannot verify this | `capped_fee_source.py` |
| `CAPFEE-TYPE-GATE` | high | accepted | `RadiantCovenantLeg` accepts any `FeeUtxoSource` (shape, not capped type). As-is posture decision (0.9.0+): `CappedFeeWalletSource` is **recommended, not enforced** — the library hands you the safe tool, it doesn't refuse your fee source. Blast radius of an uncapped key is fees-only (cannot redirect the asset); arming the autonomous path is the affirmative gate. | `radiant_leg.py`, `claim_executor.py` |
| `CAPFEE-MANUAL-REFILL` | medium | accepted | Pool refill must be a manual, audited op — never an auto top-up from the main wallet | `capped_fee_source.py` |
| `CAPFEE-FAILCLOSED-CALLER` | medium | accepted | The caller must treat `FeePoolExhaustedError` as fail-closed (no uncapped fallback) | `capped_fee_source.py` |

### 6.3 Watchtower
| ID | Sev | Status | Residual | Where |
|---|---|---|---|---|
| `WATCH-AUTONOMY-GATE` | high | deferred | Autonomy beyond dust is audit-gated; the v2 BTC refund is dormant-by-construction + dust-capped | `watch/executor.py` |
| `WATCH-TWO-PARTY` | high | open | No genuine two-party adversarial run — every run so far is single-operator (plumbing proof, not adversarial proof) | `watch/README.md` |
| `WATCH-COFIRE` | medium | accepted | Below-quorum-inside-window can co-fire claim+refund into a "hold-that-loses" (accepted: hold + CRITICAL operator fallback) | `watch/README.md` |
| `WATCH-ETH-SINGLESRC` | medium | open | Single-source ETH detection/finality (no ETH quorum) — can *delay* a page, never lose one | `watch/eth_adapters.py` |
| `WATCH-ETH-NOEVENT` | medium | accepted | An ETH HTLC that emits no event on `claim()` is undetectable by the tower | `watch/eth_adapters.py` |
| `WATCH-SEENSTORE-DUR` | low | open | Watchtower dedup / SeenStore durability across restarts | `watch/README.md` |
| `WATCH-STALLTRACKER` | low | open | `FinalityStallTracker` not wired into the live tower (point-in-time ETH finality only) | `watch/` |

### 6.4 SPV
| ID | Sev | Status | Residual | Where / legacy |
|---|---|---|---|---|
| `SPV-SOLE-AUTHORITY` | high | mitigated (gate) | No most-cumulative-work selection / difficulty oracle; safe only behind a covenant nBits pin (`require_spv_sole_authority_cleared`) | `spv/chain.py`, `proof.py` · F-01 / TM gap #8 |
| `SPV-DIFFICULTY-FLOOR` | high | accepted | Offer-time difficulty floor + most-work selection deferred to the covenant pin | `spv/` · pitfalls how-to |
| `SPV-SINGLESOURCE-DEPTH` | medium | accepted | Single-source confirmation depth gated to low value; quorum only detects disagreement | `network/bitcoin.py` |
| `SPV-SWAP-R2` | medium | accepted | Deprecated SPV-oracle *swap* covenant accepts `scriptSig ≥ 128 B` (taker-fund-loss footgun) — won't-fix on the retired path | spv-swap-deprecated note · R2 |
| `SPV-SWAP-FORGED` | medium | accepted | Forged-payment-in-scriptSig in the deprecated swap parser — won't-fix on the retired path | spv-swap-deprecated note |

### 6.5 REF gate / indexer / network
| ID | Sev | Status | Residual | Where / legacy |
|---|---|---|---|---|
| `NET-SINGLE-SOURCE` | medium | accepted | Single-source RXD/REF reads (= `ASSUME-SINGLE-SOURCE`) | TM gap #6 |
| `REFGATE-TRANSPORT-PARITY` | high | mitigated | The REF gate's fail-closed property must hold across **both** the ElectrumX and the REST transports | `radiant_leg.py`, REST adapter |
| `REFGATE-SOURCE-SKEW` | medium | accepted | RXinDexer REST field/shape drift is brittle (fail-closed on drift) | REST REF adapter |
| `NET-ELECTRUMX-HISTORY` | low | open | A *consistently* lying ElectrumX can hide address history (privacy); multi-source ElectrumX not implemented | TM S9 |
| `NET-UTXO-VALUE` | low | accepted | A lying ElectrumX UTXO value → fee overpay / invalid tx (network-rejected), never direct theft | TM S8 |
| `NET-TLS-PINNING` | medium | open | No certificate pinning for ElectrumX TLS (CA-compromise → TA4) | TM gap #7 |

### 6.6 Key material / wallet / agent
| ID | Sev | Status | Residual | Where / legacy |
|---|---|---|---|---|
| `KEY-SCROLLBACK` | high | accepted | Mnemonic in terminal scrollback — cannot clear portably | TM S2 |
| `AGENT-SAMEUID` | high | mitigated | Same-uid process abuses the unlocked agent — bounded by per-spend `/dev/tty` confirmation; the agent never returns key material | TM S18 / issue #8 / H1 |
| `KEY-COINTYPE-LOAD` | high | open | Wallet load path does not validate persisted `coin_type` against the active default — a silent flip could derive a wrong key | `hd/wallet.py`, `constants.py` |
| `KEY-CLIPBOARD` | medium | open | No clipboard-hygiene warning after mnemonic display | TM S3 / gap #10 / issue #11 |
| `KEY-JSON-REDIRECT` | medium | accepted | `wallet new --json --yes \| tee` lands the mnemonic unencrypted — documentation, not enforcement | TM S1 |
| `AGENT-REDIRECT` | medium | mitigated | Agent tricked into fee-theft/redirect signature — bounded by prevout authenticity (C1) + `ALL\|FORKID`-only | TM S19 |
| `KEY-COINTYPE-DOWNGRADE` | medium | accepted | NEW→OLD→NEW coin-type downgrade can corrupt persisted `coin_type` | coin-type design note |
| `KEY-ZEROIZE` | low | accepted | Best-effort zeroization; the transient signing-key copy is irreducible (key must exist to sign) | TM gap #5 |
| `KEY-BRUTEFORCE` | low | mitigated | Offline brute-force of a leaked `wallet.dat` — scrypt n=2^14 + per-file salt + GCM tag | TM S4 |
| `KEY-WORLDREADABLE` | low | mitigated | World-readable `wallet.dat` post-restore — load-time mode check (POSIX only) | TM S5 |

### 6.7 Glyph / metadata / dMint
| ID | Sev | Status | Residual | Where / legacy |
|---|---|---|---|---|
| `GLYPH-OWNERPKH` | high | open | Broadcast summary doesn't surface the resolved `owner_pkh` from a metadata file (hostile-metadata substitution) | TM S7 / gap #9 |
| `GLYPH-PARSER-FUZZ` | medium | open | Attacker-facing parser surface not yet fuzzed (hypothesis stage planned) | TM gap #3 / issue #10 |
| `GLYPH-DUAL-WALKER` | medium | open | Phantom-ref risk: two divergent opcode walkers can drift on reserved bytes | FT-covenant note |
| `DMINT-V2-GOLDEN` | medium | open | No mainnet golden vectors for V2 dMint / FT transfer / NFT mint. (V2 itself is now consensus-validated + mainnet-proven across all 5 DAA modes with `deploy-dmint --v2` / `claim-dmint` CLI — the former `DMINT-V2-UNVALIDATED` residual is superseded; only golden-vector pinning remains.) | dMint notes |

### 6.8 Supply chain / process / deferred
| ID | Sev | Status | Residual | Where / legacy |
|---|---|---|---|---|
| `PROC-NO-AUDIT` | high | open | No external eyes — solo developer; an independent review is the natural next step for the swap stack (this brief scopes it) | TM gap #1 / #20 |
| `SUPPLY-COINCURVE` | critical | accepted | Backdoored `coincurve` release would compromise every signature; major-range pin + `pip-audit` only | TM S11 |
| `SUPPLY-NOPIN` | medium | accepted | No pinned transitive dep hashes — deliberate for a *library* | TM gap #15 |
| `SUPPLY-GPGTAG` | low | open | PEP 740 attestations + SBOM now ship; a gpg-signed git tag is still optional | TM gap #17 |
| `FT-COVENANT-SPV-UNBUILT` | medium | deferred | The FT-in-covenant SPV cross-chain settle path is sig-gated only; SPV fusion unbuilt | FT-covenant note |
| `WAVE-DEFERRED` | low | deferred | WAVE protocol deferred; a pyrxd-minted WAVE name would be unresolvable until a consumer exists | wave note |

## 7. Legacy-ID disambiguation (read before cross-referencing)

The pre-existing numbering has collisions the auditor will otherwise trip on:

- **"#8" had three meanings** — the duplicate is now fixed in `threat-model.md` (same change as
  this brief). **Gap #8** = `SPV-SOLE-AUTHORITY` (network); the CLI `owner_pkh` gap that previously
  *also* numbered `#8` is now **gap #9** (`GLYPH-OWNERPKH`), and the rest of the "Known gaps" tail
  shifted `+1` to run `1–20` uniquely; **GitHub issue #8** = the signing-agent feature (hardening
  **H1**), unrelated to either gap.
- **"R1" is overloaded** but consistent in meaning: the REF-authenticity / fake-singleton residual
  (`SWAP-R1`) and the maker free-option residual (`SWAP-FREEOPT`) both trace to "R1" in different
  docs; the watch package separately uses local `LOW-R2`/`LOW-R3` tags (unrelated).
- **"F-01" ≠ "F-001"**: `F-0x` are 2026-05-29 Bitcoin-SPV audit findings; other docs use `F-0xx`
  (gravity) and `pitfall #1..#14` (the SPV how-to) as independent local schemes.
- **"SeenStore" names two things**: the swap-coordinator `SeenStore`/`DurableSeenStore`
  (`SWAP-SEEN1`) and the watch-layer dedup durability (`WATCH-SEENSTORE-DUR`).
- The 20th threat scenario is id'd **R1** (line ~300) rather than `S20`; this brief calls the
  swap-side residual `SWAP-FREEOPT` and the REF-authenticity one `SWAP-R1`.

## 8. The corpus — how to exercise the claims

- **Local CI:** `task ci` (lint, format, mypy on `pyrxd.security`, full pytest, 100% security-pkg
  + 85% overall coverage). Reproduces the GitHub gates one-for-one.
- **Swap consensus on a real node** (opt-in, skips without docker/image):
  `RADIANT_REGTEST=1 pytest tests/test_htlc_regtest_e2e.py -m integration` (Radiant HTLC: claim,
  wrong-preimage, premature/matured CSV refund, the `R1` fake-singleton acceptance);
  `XCHAIN_REGTEST=1 pytest tests/test_xchain_swap_regtest_e2e.py -m integration` (full BTC↔RXD);
  `XCHAIN_ETH_REGTEST=1 pytest tests/test_xchain_eth_swap_regtest_e2e.py -m integration` (ETH↔RXD).
- **Red-team suite:** `tests/test_gravity_red_team.py` (1500+ lines) documents known covenant
  concerns; `tests/test_xchain_eth_adversarial_e2e.py` covers hostile-maker/taker scenarios.
- **Per-primitive:** `tests/test_capped_fee_source.py`, `tests/test_seen_store.py`,
  `tests/test_agent_signer.py`, the SPV verifier + differential tests under `tests/`.

## 9. References

- [`threat-model.md`](threat-model.md) — actors, scenarios `S1..S19` + `R1`, controls, known gaps.
- [`../SECURITY.md`](../SECURITY.md) — report scope, disclosure SLA, supported versions.
- [`runbooks/incident-response.md`](runbooks/incident-response.md) — the internal handling flow.
- [`concepts/architecture.md`](concepts/architecture.md) — the L0–L4 module map + trust boundaries.
- [`how-to/spv-verification-pitfalls.md`](how-to/spv-verification-pitfalls.md) — the SPV pitfall catalogue.
- Design notes under [`solutions/design-decisions/`](solutions/design-decisions/) — the
  capped-fee trust boundary, the SPV-swap deprecation, the coin-type default.
- `src/pyrxd/gravity/watch/README.md` — the watchtower's own v1/v2 posture + residuals.

---

*Freeze the audited commit SHA in the header at commission time; re-run this brief's residual
inventory if `main` has moved materially since.*
