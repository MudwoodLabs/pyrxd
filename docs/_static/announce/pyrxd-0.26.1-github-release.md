A checkpoint-only release. **Upgrade to keep verifying new HashMarks:** 0.26.0 can prove a mark's block only up to block 471,744.

```
pip install --upgrade pyrxd
```

## Checkpoints refreshed to block 469,728

`pyrxd verify` and the verification pages link at most 4,032 headers past the newest checkpoint a release ships. This release ships checkpoint 469,728, so they can prove a mark's block up to block 473,760. For the CLI, the block plus its `--min-confirmations` must fit under that. The swap taker gate links at most 20,160, up to block 489,888.

All three default ElectrumX servers and the maintainer's Radiant Core node agreed on all 234 checkpoints at tip 470,597, and served every header of the last interval (467,712 to 469,728) byte for byte alike.

PROJECTED, not measured: at the nominal 300 s per block, the 3,163 blocks from tip 470,597 to block 473,760 take about 11 days, so this release's limit would be reached around 2026-10-18. Real block times vary. A mark past the limit is reported as not verifiable with this release's checkpoints, never as invalid.

## Correction to the 0.26.0 notes

The 0.26.0 notes said the RXD↔USDC/USDT end-to-end suite "passes again and runs nightly" (#824). It runs nightly, but the scheduled run has failed every night since: seeding the fork's token balance leaves 0, before any swap runs. It passed locally for #824 and has not yet passed in scheduled CI. Tracked in #835.

No library code changed except the checkpoint table. The full list is in [CHANGELOG.md](https://github.com/MudwoodLabs/pyrxd/blob/main/CHANGELOG.md).
