# Dust mainnet BTC↔RXD HTLC atomic swap — execution report (2026-05-27)

**Outcome:** the first real-value cross-chain BTC↔RXD HTLC atomic swap executed
on mainnet, end-to-end, against the production `SwapCoordinator`. State machine
transitioned through NEGOTIATED → BTC_LOCKED → BOTH_LOCKED → SECRET_REVEALED →
**COMPLETED**. The preimage moved cross-chain on-chain; the Radiant covenant did
its consensus-level amount + destination pinning; the reorg gate enforced its
depth requirement before the asset claim. Dust scale, operator-supervised,
**audit gate deliberately crossed under `--i-accept-dust-loss`** — this is NOT a
product claim and does NOT substitute for the external audit.

This was done to:

1. exercise the recently-built T7 HTLC legs + MarginPolicy floor + local txid
   serializer + mainnet transports against real chains;
2. find the bugs that only surface against real chains (not regtest);
3. produce a recoverable, reproducible reference run.

It found **four** real bugs, all transport-layer (no consensus issue), all
fail-closed, none lost value. Each is documented and patched below.

## On-chain reality

All txids are real and verifiable.

### Run 2 — the completing swap

| step | chain | txid | direction | size | result |
|---|---|---|---|---|---|
| Taker funds (you → taker addr) | BTC | `d216b1e0...efef69` | 1,860 sats from your wallet → `bc1qd0rgp2f...` | — | confirmed block 951,326 |
| Taker locks BTC into HTLC | BTC | `c31f7a00...d25c3789` | 1,260 sats locked in `bc1px9xcs0g...` HTLC | 141 vB | confirmed block 951,327 |
| Maker locks RXD covenant | RXD | `9d52f02f...d68eb8f1` | 1,000 photons locked in covenant SPK | 340 B | confirmed RXD block 432,824 |
| Maker claims BTC, revealing `p` | BTC | `1c412e06...07ec62bc3` | 660 sats → `bc1qwd4an8...` (agent claim payout) | 141 vB | confirmed block 951,333 |
| Taker fee-carve | RXD | `092a5832...7e67dae095` | 4,000,000 photons → fee UTXO | 225 B | in mempool then confirmed |
| **Taker claims RXD covenant** | RXD | **`6cf66302c9...c0298b783`** | **1,000 photons → taker pkh** (the swap output) | 267 B | confirmed RXD (1 conf at write) |

The taker RXD claim consumed (covenant `9d52f02f:0` + fee-carve `092a5832:0`)
and paid exactly **1,000 photons** to the taker's pubkey-hash
(`76a91427cba93fa1010efa972534a15556b24bd231d25988ac`) — byte-for-byte the
covenant-pinned destination. That is the proof the Radiant leg's covenant
enforced amount + destination at consensus, not via the off-chain coordinator.

### Run 1 — the cancelled swap (recovered)

Run 1 crashed mid-fund (see Bug 1 below) AFTER the taker BTC funding tx hit
the chain and BEFORE the maker had revealed `p`. The preimage was lost (in-memory
only — Bug 2 below). The only safe path was the timelock CSV refund.

| step | txid | result |
|---|---|---|
| Taker funds | `45477065...8bdc9391` | confirmed 951,324 |
| HTLC funding (broadcast then harness crashed) | `8e3e66c4...c676213d` | confirmed 951,326 (1,260 sats stranded) |
| CSV refund (this run, after t_btc=27, 32 confs deep) | `2e6d68d5...74e632` | broadcast, in mempool: 660 sats → user |

### Final user receipts

| source | tx | sats to user |
|---|---|---|
| Run-1 CSV refund | `2e6d68d5...74e632` | 660 |
| Run-2 claim sweep | `2f33286c...5e25e49a8` | 410 |
| **Total back to user** | | **1,070 sats** |
| Plus RXD received | (covenant claim 6cf66302c9 vout 0) | **1,000 photons (taker pkh)** |

You funded 3,720 sats across both runs (1,860 × 2). Net BTC consumed by miners
across all funding/HTLC-fund/claim/refund/sweep txs: 2,650 sats. The "cost of
the experiment" was ~71% of the BTC at dust scale; that's the expected
dust-tax — at any reasonable trade size it amortises to single-digit basis points.

## Bugs found + fixed

### Bug 1 — `BitcoinTaprootLeg.fund` immediate post-broadcast readback (run-1 crasher)

`fund()` broadcasts the HTLC funding tx, then reads the on-chain amount back
with `min_confirmations=1`. On regtest the test mines a block between the two
operations; on mainnet the just-broadcast tx is 0-conf and the read raises
`NetworkError: tx has 0 confirmations, required 1` AFTER the broadcast already
succeeded → harness exits, BTC stranded in HTLC.

**Fixed:** added `fund_confirm_poll_s` / `fund_confirm_timeout_s` to the leg
constructor; `_read_funded_amount_sats` helper polls **only** on the
"confirmations, required" error and re-raises every other `NetworkError`
immediately (still fail-closed: a bad vout or malformed tx propagates). Default
poll=0 preserves the regtest path byte-identical. **3 regression tests** in
`tests/test_btc_htlc_leg.py` lock the behaviour in (`test_fund_polls_for_confirmation_when_configured`,
`test_fund_poll_times_out_still_fail_closed`, `test_fund_poll_does_not_swallow_other_errors`).
35/35 leg tests pass.

### Bug 2 — preimage `p` was in-memory only

The original "never persist `p`" rule assumed `p` lives in a different trust
domain than the WIFs. In single-operator dust runs the recovery keys file
already contains `maker_btc_wif` (the claim key) — total compromise — so
withholding `p` from the SAME file buys zero secrecy yet loses crash
resilience. Run 1's crash lost the in-memory `p` permanently, forcing the CSV
refund path.

**Fixed:** `dust_swap_run.py` now persists `preimage_p_hex` into the same mode-600
keys file (with a note documenting the trust-domain reasoning), verified with
`sha256(p) == hashlock_H` on load.

### Bug 3 — `radiant_mainnet_chainio.py` ssh argv quoting (run-2 first crasher)

The shim built ssh argv as discrete tokens (`["ssh", host, "docker", "exec",
container, "radiant-cli", "scantxoutset", "start", desc_json]`). ssh joins the
remote command tokens with **spaces** into one string and the remote login shell
re-parses it. The descriptor JSON `[{"desc": "raw(..)"}]` contains a space
after the colon → the remote shell word-splits it → `scantxoutset` sees a
malformed `action` arg → fail. Compact JSON (`separators=(",", ":")`) helped
but the `{` `}` `[` `]` `"` chars are still shell-special remotely.

**Fixed:** quote each remote token with `shlex.quote` before joining (and
collapse the JSON separators too). `get_utxos` now returns the covenant UTXO
correctly on `tr`; `getrawtransaction`/`getblockcount` still work. Verified by
direct shim invocation.

### Bug 4 — `carve_fee_input` hardcoded fee below mainnet relayfee

The fee-carve helper defaulted to 2,000,000 photons internal fee. The carve
tx is ~225 bytes; the `tr` node runs `relayfee=0.10 RXD/kB` → min fee
**2,250,000 photons**. The default was below the floor → `min relay fee not
met (code 66)` → covenant-spend fee-input carving fails → taker can't claim.

**Fixed:** bumped `carve_fee_input` default `fee_photons` to 4,000,000 (clears
the 2.25M floor with margin), docstring updated to call out the per-kB
relayfee math (so future callers don't repeat my "flat fee" mistake; matches
my own memory note `project_radiant_relay_fee_per_kb`).

### Bug 5 — `MempoolSpaceSource.get_raw_tx` refuses 0-conf txs (resume crasher)

The taker-claim poll loop in `dust_swap_resume.py` called
`get_raw_tx(claim_txid, min_confirmations=0)`, but `get_raw_tx` fail-closes
when `confirmed=False` regardless of `min_confirmations` — so a just-broadcast
maker claim can't be re-read from the chain immediately. Effectively
equivalent to the reorg-gate WAIT state.

**Fixed in the resume loop:** catch `NetworkError` matching "confirmations"
and treat it as WAIT (sleep + retry). The leg's own
`MempoolSpaceSource.get_raw_tx` was left untouched (its fail-closed semantics
are correct for the no-mempool-trust default; the resume's specific use case
is what should opt in to "wait if unconfirmed").

## Honest costs and caveats

* **Audit gate was deliberately crossed.** `audit_cleared=True` was set
  explicitly via `--i-accept-dust-loss`. The external audit remains the hard
  gate for any product claim; this run is a developer-supervised dust test, not
  a launch.
* **Single-operator setup.** The same process played both maker and taker; both
  sides' keys + the preimage all sit in the same mode-600 file. No counterparty
  adversary was modelled in this run — the swap's atomicity properties (the
  whole point of HTLC) were not stressed against a real counterparty here. The
  consensus-level enforcement on the RXD covenant (amount + destination
  pinning) IS exercised, since the covenant doesn't know or care which process
  spends it.
* **Reorg gate exercised; reorg itself was not.** The depth requirement was
  enforced (the taker waited until the maker's BTC claim was 2-deep), but no
  reorg was simulated against real mainnet — the regtest e2e covers that path
  separately.
* **Multi-source confirmation reader is still a SHOULD, not a MUST.** Run 2
  used a single mempool.space endpoint as the BTC depth oracle (the SPOF noted
  in `network/bitcoin.py`). Above dust, the runbook calls for multi-source
  corroboration before the RXD claim.
* **BTC fee market was very cheap (1–2 sat/vB).** Same code under fee
  pressure would need a larger `fee_sats` budget or RBF; this run did not
  exercise that.

## Files touched (uncommitted at write time)

* `src/pyrxd/btc_wallet/htlc_leg.py` — Bug 1 fix (poll on post-broadcast
  readback).
* `tests/test_btc_htlc_leg.py` — 3 regression tests for Bug 1.
* `scripts/dust_swap_run.py` — Bug 2 fix (persist `p`); plumb leg poll params;
  bump `--rxd-fee-photons` default.
* `scripts/radiant_mainnet_chainio.py` — Bug 3 fix (shlex.quote remote argv,
  compact JSON); Bug 4 fix (default `fee_photons` 4M).
* `scripts/dust_swap_resume.py` — NEW: load persisted state, drive coordinator
  from BTC_LOCKED → COMPLETED without re-broadcasting funded legs; treat
  unconfirmed-claim as WAIT (Bug 5).

## Test status

* `tests/test_btc_htlc_leg.py`: **35 passed** (incl. the 3 new regressions).
* Full repo CI not re-run after this session's edits — the leg fix is
  additive (new ctor kwargs default-off) so existing behaviour is unchanged;
  worth running `task ci` before commit.

## What's next (NOT part of this run)

* External audit (the hard gate for any value claim above dust).
* Above-dust + multi-source conf reader.
* RBF / aggressive fee escalation for high-fee-market conditions.
* Bug 5 reconsideration: the resume script's local catch is fine; if the
  fwd-runner ever needs to fetch the claim itself (vs the current
  `_CapturingBroadcaster` path), tighten there.
