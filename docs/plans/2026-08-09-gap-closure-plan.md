# pyrxd — gap-closure plan (2026-08-09)

Status: WORKING DRAFT. Written after 0.13.0. **Correction (2026-08-10):** an earlier report said the
2026-06-26 Top-10 backlog was fully closed. Six of seven shipped — item 4 was researched but never
built, and is now folded into §A2.
Covers **everything still deferred**, sequenced, with explicit triggers for the parked items.

## Provenance — what is verified vs what is guessed

**Verified by reading/running the code on `main` @ 0.13.0**, not from docs:

| Claim | How checked |
|---|---|
| No CPFP/RBF/fee-bump anywhere in the swap stack | grep for `cpfp\|rbf\|bump_fee\|fee_bump` across `src/` — zero hits |
| No anti-griefing bond/deposit | grep for `griefing\|bond_sats\|deposit_sats` — zero hits |
| No offline cold refund/claim builder CLI | grep `build-refund\|build-claim` in `src/pyrxd/cli/` — zero hits |
| ETH multi-source quorum EXISTS | `MultiSourceEthRpc` present |
| dMint deploy-with-premine deferred | 10 raise/doc sites in `glyph/builder.py` |
| No royalty payment, airdrop, or CONTAINER collection mint | grep — royalty decoded only; others absent. **CORRECTED 2026-08-10:** the CONTAINER half was wrong — `GlyphBuilder.prepare_container_reveal` exists and is unit-tested, and the #379 glossary already said so. What is absent is the commit→reveal *orchestration*, shared with MUT/WAVE. See §B2. |
| No A–Z glossary page | `docs/how-to/`, `docs/concepts/` |

**NOT verified — every effort size below is ESTIMATED and unspiked.** This repo has a documented
history of doc-derived estimates running 3–4× high, and this session alone produced six wrong
claims sourced from plans and reviewers (see `feedback-verify-agent-and-doc-claims`). Treat sizes
as ordering hints, not commitments. (A1 was spiked before building — that spike inverted its whole
design, which is the argument for doing the same on anything sized L below.)

---

## 0. State of play

Six of the seven 2026-06-26 Top-10 items are shipped (item 4 was not — see §A2), as are both
hard-gate *harnesses*. Two releases went out (0.12.0, 0.13.0). Dependabot is at zero open alerts.
**A1 is DONE** (#369): the spike reshaped it, two independent Fable passes then caught a fund-loss
bug in the first cut, and the corrected version is on `main` @ `2a80628`. What remains
splits cleanly into: **three real fund-safety gaps that nobody is blocked on**, a pile of feature
and polish work, and two gates that need a person or a budget rather than code.

---

## 1. Track A — Fund-safety (do first; nothing external blocks these)

### A1. Deadline-aware fee sizing — **the priority** (RESHAPED BY SPIKE, 2026-08-09)

**The gap.** A timelock guarantees a refund becomes *mature*, not that it gets *mined*. An honest,
time-critical claim or refund that is under-fee'd can sit unconfirmed past its deadline. The
two-party run plan predicted a code gap here (NA-2b); there is no fee-bump path anywhere.

> **SPIKE RESULT — the original shape of this item was unbuildable.** It called for "RBF on the fee
> input, CPFP on the change/claim output". **Radiant supports neither.** Verified against
> `Radiant-Core` @ `afdf57b1` and the live mainnet node (Radiant Core 3.1.2, `EB256.0`):
>
> - **No RBF.** `src/validation.cpp:667` and `:856` reject any mempool conflict outright —
>   `txn-mempool-conflict`, `REJECT_DUPLICATE`. The only `bip125` string in the tree is a
>   **DEPRECATED** help label in `src/wallet/rpcwallet.cpp:1986`. No `bumpfee` RPC exists.
>   Radiant instead ships **DSProof** (double-spend *proofs*) — it treats a conflict as fraud to
>   broadcast, the opposite of replacement.
> - **No CPFP.** `getmempoolancestors`/`getmempooldescendants` exist and make it *look* supported,
>   but `src/miner.cpp:380` selects on `GetModifiedFeeRate()` = `(nFee + feeDelta) / vsize` — the
>   tx's OWN fee over its OWN size — and `break`s at `blockMinFeeRate`. The `backlog` queue is
>   purely topological ordering. **A high-fee child cannot lift a low-fee parent into a block.**
>
> **Consequences.** The BIP125 pinning attack (NA-2b) *does not apply* — an adversary cannot pin
> you with a low-fee replaceable tx, because nothing is replaceable. But the inverse risk is worse
> and was unnamed: **an under-fee'd honest time-critical tx cannot be fixed by any means.** It sits
> until mempool expiry — `DEFAULT_MEMPOOL_EXPIRY = 8` **hours** (`src/validation.h:82`) — before
> its inputs free for a rebuild. **If the deadline falls inside that window there is no remedy.**
>
> Fee pre-sizing is therefore not a nice-to-have; it is the ONLY control. pyrxd has none today:
> `btc_wallet/htlc_leg.py:81` is a flat `fee_sats: int = 500`, and no deadline-aware fee logic
> exists anywhere in `gravity/`.

**Revised shape** (smaller than the original, and prevention-only):

1. **Deadline-aware fee sizing at build time** — scale the claim/refund fee from
   blocks-remaining-to-deadline against the live `effective_minrelaytxfee` (0.10 RXD/kB on the
   reference node; `minrelaytxfee` 0.01).
2. **A pre-broadcast affordability gate** — refuse to broadcast a time-critical spend whose fee
   cannot plausibly make the deadline, and PAGE instead. Failing loudly beats an unfixable
   stuck transaction.
3. **Document the 8-hour irreversibility window** in the threat model and the watchtower runbook.
4. **Explicitly do NOT build RBF or CPFP paths** (see §8) — record why, so they are not
   re-proposed from Bitcoin habit.

**Effort ESTIMATED: M** (was L). Prevention only; there is no in-flight remedy to build.

### A2. Offline cold recovery toolkit — **DONE** (#374, `d876ce4`)
`swap build-refund` / `build-claim` taking a recovery file (+ preimage for claim) and **printing
raw hex, never broadcasting**, so an operator verifies outputs and broadcasts from their own node.
Read-only, so it sits outside the audit gate — the same posture `swap status` already holds.

**Merged with backlog item 4** (`swap recover-preimage` + counter-leg-aware `swap status`), which
was researched in the 2026-08-08 pass but **never built** — a records-correction: an earlier status
report claimed all seven Top-10 items shipped; six did. They are one piece of work because
`build-claim` needs a preimage and `recover-preimage` is what produces it; shipping the builder
alone would leave nothing to feed it.

Now MORE valuable than when first written: A1 established there is no RBF and no CPFP, so when
automation refuses to broadcast an unaffordable time-critical spend and pages, this is the only
remaining fallback — a human sizing the fee and broadcasting from their own node.

The security-critical part is the preimage scrape: it must reuse the provenance-checked pattern
(re-derive txid from fetched bytes, confirm the tx spends OUR outpoint, then verify
`sha256(p) == H`). A naive any-32-byte-push scrape is a real vulnerability. It must also never read
`preimage_p_hex` from the recovery file — that copy may still be a pre-reveal secret.
**Effort ESTIMATED: M.**

### A3. Anti-griefing — **DONE: analysed, residual ACCEPTED** (no bond built)
Repeated capital-lockup DoS costs an attacker almost nothing and **passes every safety oracle**,
because it is a liveness/economic attack, not a safety one. Options: a bond/deposit, or an explicit
written acceptance that the stack defends safety and not liveness. **Recommendation: write the
analysis first and probably accept the residual.** A bond changes the protocol and the UX for a
threat with no observed instance. **Effort ESTIMATED: S to document, L to build.**

**Outcome (2026-08-10):** analysed and accepted. Registered as threat-model **S22**; full reasoning
and the revisit trigger in
`docs/solutions/design-decisions/griefing-is-a-liveness-residual-not-a-bond.md`. The asymmetry is
structural — the taker locks first AND holds the longer timelock (`t_btc - t_rxd >= margin`), so the
party who commits first waits longest to get out, while the attacker's move is *inaction* and costs
them nothing. No safety oracle can see it, because nobody loses principal. A bond was rejected: it
prices a threat with no observed instance, needs adjudication (new consensus-adjacent surface on an
unaudited stack), and cannot distinguish malice from a stalled node. Mitigations are operational —
order the legs by trust, size `t_btc` deliberately, don't auto-accept from unknown counterparties.

---

## 2. Track B — Feature completeness

- **B1. dMint deploy-with-premine** (V1 + V2). The largest single deferral in shipped code —
  10 sites in `glyph/builder.py`. Design exists at `docs/dmint-research-photonic-deploy.md` §7.2.
  Distinct from FT premine, which works. **ESTIMATED: M.**
- **B2. Token issuance completeness** — royalty-honouring transfer (metadata is decoded but never
  *paid*), multi-recipient airdrop, `CONTAINER`-based collection mint (the enum exists, unused).
  **ESTIMATED: M each.**

  **Outcome (2026-08-10): two of three shipped; the CONTAINER item was mis-scoped and is
  re-specified below.**

  1. **Royalty — SHIPPED as an advisory payment path, not an enforcement mechanism.** The
     enforceability question was settled before any code: a royalty on an ordinary Radiant
     transfer is a **social convention**. FT/NFT locks are P2PKH-gated; the FT epilogue
     enforces ref *conservation*, never where value goes. No shipped covenant references a
     royalty. Photonic reaches the same structural conclusion — enforcement exists only inside
     a *voluntary* listing covenant, and its own header records that this stops neither a
     non-compliant seller nor an out-of-band gift. Full evidence:
     `docs/solutions/design-decisions/royalties-are-advisory-not-consensus-enforced.md`.
     Shipped: `pyrxd.glyph.royalty` (Photonic-parity arithmetic), `royalty=` on the FT
     airdrop builder paying by default with an explicit opt-out (a one-recipient airdrop is
     an ordinary transfer), and the `royalty` block of a metadata file — which the CLI had
     been **silently dropping**, so a royalty could not be recorded at mint time at all.
     Deliberately NOT on `build_transfer_tx` or `build_nft_transfer_tx`: neither has a
     plain-RXD input, so a royalty there would be paid out of the token itself.
  2. **Multi-recipient airdrop — SHIPPED.** `glyph airdrop-ft` / `FtUtxoSet.build_airdrop_tx`,
     proven against a live `radiant-core:v3.1.1` regtest node with a negative control.
  3. **CONTAINER collection mint — DEFERRED, and the description above is WRONG.** "the enum
     exists, unused" does not match the code: `GlyphBuilder.prepare_container_reveal`
     (`glyph/builder.py:622`) is a complete script-level builder with 10 unit tests
     (`tests/test_mut_container_wave_builders.py::TestPrepareContainerReveal`), the CLI
     ships a `container-nft` metadata template, and `docs/concepts/glossary.md` (added by
     #379) already says so — "pyrxd ships a full builder". The provenance table's row is
     likewise wrong on this point.

     **The actual gap is orchestration, not a builder**, and it is not CONTAINER-specific.
     `glyph/mint.py` lists `MUT`, `CONTAINER`, `WAVE` and `DMINT` in `_UNSUPPORTED_PROTOCOLS`
     (`:174-179`) because each has a reveal shape the single-output `GlyphMinter` facade
     cannot build; it refuses them with a clear error rather than stranding a commit, which is
     correct behaviour, not a bug. So today `glyph init-metadata --type container-nft` hands a
     user a template that `glyph mint-nft` will (safely) refuse.

     > **SPIKED 2026-08-15 — do not build the dispatch table. The refusal is correct.**
     >
     > The plan below assumed the difference is a *reveal shape*. For MUT/WAVE it is not.
     > `prepare_mutable_reveal`'s reveal takes a **second input** at
     > `commit_txid:(commit_vout + 1)`, so the **commit** must carry an ordinary output
     > there — the mutable contract's ref IS that outpoint, and the covenant recomputes
     > the token ref as `mutable_ref.vout - 1`, so the two refs can never be the same
     > (verified in `builder.py:706-750`, with the consensus rejection recorded against a
     > v3.1.1 node). `GlyphMinter`'s commit emits `[commit_output, change]`, and
     > `Transaction.fee()` drops a change output it cannot fund — so the seed would be
     > *sometimes* present. The commit is a hashlock with no owner-only spend path, so the
     > times it is absent strand the commit and its value permanently.
     >
     > Worse, there is no exit: pyrxd has **no builder for the `nftAuthScript` shape** a
     > later `mod`/`sl` operation needs (only reference in the tree is the docstring note
     > at `builder.py:752`; the working transaction exists as hand-spelled bytes in
     > `tests/test_mut_wave_regtest_e2e.py`). Minting a mutable token that pyrxd cannot
     > then mutate is a one-way door — the facade would be shipping the feature's name
     > without the feature.
     >
     > WAVE is separately parked on a consumer
     > (`docs/solutions/design-decisions/wave-protocol-deferred-until-consumer.md`).
     >
     > **DMINT is not in the same position.** `prepare_dmint_deploy` is complete and
     > consensus-proven — re-proven end to end on 2026-08-15 (V1 and V2, real PoW, at
     > mainnet's relay floor, `tests/test_dmint_premine_regtest_e2e.py`). Folding it into
     > the facade would be convenience, not capability, and it drives both phases itself.
     >
     > **What was done instead:** the refusal now states, per protocol, what the caller
     > must actually do — MUT/WAVE name the seed output, what stranding costs, and the
     > missing mutate builder; DMINT points at a supported path rather than apologising
     > for a wall. Two tests pin that guidance so it cannot flatten back into a shrug.
     >
     > **Un-parks when:** a builder for the `nftAuthScript` shape exists (so a minted MUT
     > can be mutated), AND the commit builder can guarantee a non-change seed output at
     > `commit_vout + 1`. Until both hold, the refusal is the fund-safe answer.

     **Concrete plan (SUPERSEDED — see the spike box above).** Build the commit→reveal
     orchestration once, for the whole class, rather than three times:
     - Extend `GlyphMinter` with a reveal-shape strategy so `_UNSUPPORTED_PROTOCOLS` becomes a
       dispatch table rather than a refusal list. `prepare_dmint_deploy` already proves the
       facade can carry a non-trivial shape — it just does so through a separate path.
     - CONTAINER's specific need is small: an optional `OP_PUSHINPUTREF <child_ref>` prefix on
       the NFT lock, plus fee sizing that accounts for those 37 extra bytes
       (`glyph/fees.py:estimate_reveal_fee` already takes `extra_output_script_sizes`).
     - Add `glyph mint-container --child-ref` (or a `--child-ref` option on `mint-nft`), and a
       collection-membership read path — a container is only useful if something can enumerate
       its members, which is an indexer question `RxinDexerClient` may or may not answer today.
       **Spike that before committing to a size.**
     - Prove on regtest that a node accepts a container reveal, and that the child ref survives
       a transfer of the container.
     The membership/read half is the unknown, and it is the reason this was not rushed in
     alongside the other two. **ESTIMATED: M, unspiked — treat as an ordering hint only.**
- **B3. External-miner progress frames** — ~~extend the JSON-over-stdio protocol so third-party
  miners can report live progress~~ — **ALREADY SHIPPED (verified 2026-08-15).** Added after
  0.13.0, which is why this plan (written at 0.13.0) still lists it.

  Everything the item asked for is present and tested:
  `MineProgress` + `parse_progress_line` in `contrib/miner/protocol.py`,
  `_ExternalMinerProgressReader` draining stderr under a bounded line/byte cap in
  `glyph/dmint/miner.py`, and the bundled miner emitting frames via `_make_progress_reporter`
  in `contrib/miner/cli.py`.

  The constraints were met, not worked around. Frames go to **stderr**, so stdout still carries
  exactly one authoritative response line and every pre-existing consumer is unaffected; the
  version stays `protocol=1` because the change is purely out-of-band; silence from an old miner
  is valid; and `parse_progress_line` fails **soft** (returns `None`) so a malformed or hostile
  progress line cannot abort a successful grind. The "stderr discarded to bound memory" defence
  survives as a bounded reader rather than a discard.

  Verified by running them, not by reading: 25 tests in
  `tests/contrib/test_miner_external_{integration,progress}.py`, including
  `test_real_miner_streams_progress_frames_before_timing_out`, which spawns a real
  `python -m pyrxd.contrib.miner` subprocess and asserts frames arrive from it.

---

## 3. Track C — Operational hardening

- **C1. ElectrumX server registry + request-level failover + optional TLS SPKI pinning.** Today:
  one hardcoded endpoint, racing only at connect time. A single unreachable endpoint is a hard
  outage for any wallet operation. **ESTIMATED: M.**
- **C2. Perf/scale characterisation** — a measured "max safe swaps per tick" ceiling for the
  watchtower. Previously judged low value because scale is not a binding constraint at current
  volume. **That reasoning still holds.** Do it only if someone actually runs a busy tower.

---

## 4. Track D — Docs & standards

- **D1. A–Z glossary** (deliberately excluded from the 0.12.0 troubleshooting page). The single
  highest-leverage remaining newcomer artifact. **ESTIMATED: S.**
- **D2. Normative Glyph spec + output-script-descriptor export + handshake spec.** Ecosystem-facing;
  the descriptor export in particular unblocks clean watch-only import in other wallets.
  **ESTIMATED: M each.**

---

## 5. Parked — with explicit triggers

Each of these is parked with a **named condition that un-parks it**. Absent the trigger, not doing
them is the correct decision, not neglect.

| Item | Trigger to start |
|---|---|
| Chaos / failure-injection drill | The watchtower runs against real value, OR a coordinated-failure incident occurs |
| Photonic-TS live differential | A Photonic behaviour divergence is observed in the wild |
| FORKID / CBOR differential | A sighash or envelope bug is suspected, or the auditor asks |
| Perf/scale characterisation (C2) | An operator watches >20 swaps on one tower |
| Anti-griefing bond (A3 build half) | An actual griefing incident, or an auditor flags it as blocking |

---

## 6. Blocked on a person or a budget — not on code

- **External security audit.** The hard gate on real, adversarial value. Everything shipped —
  residual register, golden vectors, fuzz corpus, `security-audit-scope.md`, conformance vectors —
  was preparation for it. **Needs commissioning + budget. This is the single most valuable
  remaining move and it is not an engineering task.**
- **Live two-party adversarial run.** The harnesses, the chain-re-derivation verifier, and the
  scenario matrix are all built. **Needs a second operator on a second machine.**
- **`FUNDING.yml`** — needs your GitHub Sponsors accounts.
- **SLIP-0044 / derivation-path outreach** — a REP plus wallet adoption, not a pyrxd PR.

---

## 7. Recommended sequence

1. **Spike A1** (Radiant replacement/mempool policy). Hours, and it determines A1's whole shape.
2. **A1** — deadline-aware fee escalation. The only remaining item that is *both* a genuine
   fund-loss vector *and* entirely within your control.
3. **A2** — cold builder CLI. Read-only, audit-gate-free, and it is the human fallback for when A1
   cannot get a transaction mined.
4. **D1** — glossary. Small, and it finishes the docs story started by the troubleshooting page.
5. **A3 (document)** — write the griefing analysis; accept the residual unless it argues otherwise.
6. Then **B1 / C1** as appetite allows.

In parallel and continuously: **pursue the audit**. It gates more value than every code item here
combined, and its lead time is measured in weeks.

---

## 8. What to explicitly NOT do now

- **Do not build RBF or CPFP fee-bump paths.** Radiant supports neither — verified against
  `Radiant-Core` @ `afdf57b1` and the live node (see the spike box in §A1). Conflicts are rejected
  outright (`txn-mempool-conflict`), and the miner selects on standalone `GetModifiedFeeRate()`, so
  a high-fee child cannot lift a low-fee parent. Any proposal to "just bump the fee" is Bitcoin
  semantics assumed onto a BCH-lineage chain. The remedy is pre-sizing, not escalation.
- **Do not build the anti-griefing bond** before writing the analysis (§A3). It changes the
  protocol and the UX for a threat with no observed instance.
- **Do not build a `pyrxd watch` click group.** A four-reviewer panel rejected it: it would put an
  audit-gated *broadcaster* into the shipped CLI, which today deliberately has zero broadcast
  surface for the cross-chain stack. Revisit only after the audit clears.
- **Do not build `install-units` / a systemd generator.** Same panel: config values interpolated
  into unit text is a newline-injection → root-RCE risk, to save writing ~30 lines of INI once.
- **Do not retarget the CLI mint flows onto `GlyphMinter`.** The CLI has two `_confirm_or_abort`
  broadcast gates that a facade owning the whole flow has nowhere to put; retargeting silently
  drops a safety default.
- **Do not chase the 4e-12 s timelock rounding** in production. `floor` is conservative to within
  ~2 ULP; a meaningful overshoot is a whole block (≥1 s). The assertion was the right fix.
- **Do not expand CI's mypy scope opportunistically.** Widen it deliberately, as its own change,
  with the failures triaged first.

---

## 9. One process note

Prefer **spike → build** over **plan → build** for anything sized L here. This session produced six
load-bearing claims from plans and reviewers that were wrong on contact with the code, including a
dependency that could not be installed, a "~3-line fix" that was 509 files, and a formula off by
2³³. A1 in particular should not be designed from Bitcoin's BIP125 semantics until Radiant's actual
policy is confirmed.
