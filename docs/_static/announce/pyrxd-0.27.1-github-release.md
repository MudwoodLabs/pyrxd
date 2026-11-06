A checkpoint-only release. **Upgrade to keep verifying new HashMarks:** 0.27.0 can prove a mark's block only up to block 479,808.

```
pip install --upgrade pyrxd
```

## Checkpoints refreshed to block 477,792

`pyrxd verify` and the verification pages link at most 4,032 headers past the newest checkpoint a release ships. This release ships checkpoint 477,792, so they can prove a mark's block up to block 481,824. For the CLI, the mark's block plus `--min-confirmations` minus 1 must be at most that; `pyrxd headers sync` moves the CLI's limit forward by caching newer headers, and the pages do not use the cache. The swap taker gate links at most 20,160, up to block 497,952.

All three default ElectrumX servers and the maintainer's Radiant Core node agreed on all 238 checkpoints at tip 478,246 on 2026-11-02, and served every header of the last interval (475,776 to 477,792) byte for byte alike.

PROJECTED, not measured: at the nominal 300 s per block, the 3,578 blocks from tip 478,246 to block 481,824 take about 12.4 days, so this release's limit would be reached around 2026-11-14 or 2026-11-15. Real block times vary, and faster blocks bring that date forward. Past the limit, `pyrxd verify` reports a newer mark as `CONFIRMED` with the reason, and the pages show it as the server's word; neither reports it as invalid.

No library code changed except the checkpoint table. The full list is in [CHANGELOG.md](https://github.com/MudwoodLabs/pyrxd/blob/main/CHANGELOG.md).
