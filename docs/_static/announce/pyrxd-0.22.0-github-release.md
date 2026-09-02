The published handshake spec, and the conformance vectors that shipped with it, taught the timelock ordering backwards.

## Read this first if you built against pyrxd's HTLC material

Every released pyrxd through 0.21.0 shipped `conformance/htlc-handshake-vectors.json` at schema `radiant-htlc-handshake/1`, and those vectors **accepted `t_btc=60 / t_rxd=20` and rejected `t_btc=20 / t_rxd=60`** — the correct ordering, published under the name `margin-inverted-ordering`.

The accepted layout is the one in which the maker refunds its own leg while `p` is still secret and *then* claims the counter leg with `p`, taking both, deterministically, with no recourse for the taker. The margin between the two deadlines was not a safety buffer in that arrangement; it was the width of the attack window.

The maker holds the preimage. It **locks** the Radiant leg and **claims** the counter leg, so the leg it locks must carry the **longer** refund window (Herlihy, *Atomic Cross-Chain Swaps*, [arXiv:1801.09515](https://arxiv.org/abs/1801.09515) §1). `t_rxd` must exceed `t_btc`, not the reverse.

An independent implementation that got the direction *right* would have run our vectors, failed, and been told — by a specification with a green test run behind it — to swap to the vulnerable layout. **If you implemented against any published pyrxd handshake material before 2026-09-02, re-derive your timelock ordering.** The vectors are regenerated from the builders and the schema is bumped to `/3` so the two files cannot be confused by version alone.

Five production runners built the exploitable ordering, and one of them **enforced it at the command line**, refusing honest input with "(BTC is the longer leg)" in the message. An operator following that refusal built the vulnerable layout.

## The margin was judged in raw block counts across two chains

Fixing the direction exposed a second defect underneath it. `t_btc` counts **Bitcoin** blocks (~600 s); `t_rxd` counts **Radiant** blocks (~300 s). The gate compared them one-for-one.

`t_rxd=180` "exceeds" `t_btc=144` by 36 raw blocks while being 15 h against 24 h in wall clock — the Radiant refund opening *nine hours before* the counter-leg deadline. Under the old direction that conflation was fail-safe; after the inversion it was fail-open, which is why it had never mattered before.

The relation is now in seconds, each leg multiplied by its own chain's block interval:

```
t_rxd · i_rxd  ≥  t_btc · i_btc  +  margin · i_btc
```

**Honest swaps need a longer Radiant leg than before.** At the nominal 600/300 that reduces to `t_rxd ≥ 2·t_btc + 2·margin`. Runner defaults changed accordingly, and the counter leg is now derived from one definition rather than hand-computed in each runner — three of them had computed `t_btc = t_rxd - margin - 4`, subtracting a Bitcoin-block margin from a Radiant-block count.

## The real-value guard that could never fire

`MarginPolicy.measured()` sets `require_measured=True` and then filled `rxd_block_interval_fast_s` with the nominal value, so the check *"real-value mode requires a MEASURED rxd_block_interval_fast_s"* was unreachable through the constructor operators are told to use. The shipped watchtower had no flag to supply it.

Reproduced on the shipped entry point: `pyrxd-watchtower --measured` reserved `ceil(768/300) = 3` Radiant blocks for the ETH finality window where the measured p10 of 36 s needs **22**. A seven-fold under-reserve on exactly the path the guard protects, and an under-reserved floor returns WAIT where there is no room left to wait.

`--rxd-block-interval-fast-s` now exists. A caller who has not measured the p10 passes the nominal value explicitly and knows the reserves are nominal, which is what the constructor's docstring had prescribed all along.

## A zero-block timelock is not a timelock

`build_p2pkh_with_csv_script` refused the *disable-bit* spelling of a no-op lock with an explicit error and accepted a **zero unit count** — the same lock — emitting `OP_0 OP_CSV OP_DROP` for a caller that asked to be time-locked. The output is spendable in its own funding block.

The floor now lives in the builder and **masks** rather than comparing: `build_csv_sequence(0, TIME_512_SECONDS)` is `0x400000`, non-zero and still a lock of zero, so a `< 1` guard would pass it. That asymmetry is how one spelling came to be refused for years while the other was not. `pyrxd.inspect` still classifies such scripts, because they can exist on-chain regardless of what this library will build.

## Four user-facing documents taught the superseded rule

The how-to, the tutorial, the dry-run guide and the security-audit-scope table all still stated `t_counterchain > t_rxd + margin` — one as a **MUST** directive for implementers, one as the invariant an external auditor would be told is enforced. The earlier sweep corrected the handshake spec and missed all four, because they spell the counter leg `t_counter` and the sweep searched for `t_btc`.

A scanner now covers `src/`, `scripts/`, `conformance/` and the published docs for both the lock order and the timelock direction, in both variable namings and both hyphen spellings.

## Still unaudited

The swap stack remains **UNAUDITED** and an external audit is still the hard gate before real value. This release fixes defects found by internal review and adversarial panels; that is not the same thing as having been audited, and nothing here should be read as saying otherwise.

Full detail, including upgrade notes and the boundary changes, is in [CHANGELOG.md](https://github.com/MudwoodLabs/pyrxd/blob/main/CHANGELOG.md).
