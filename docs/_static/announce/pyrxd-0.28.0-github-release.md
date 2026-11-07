A minor release with one breaking-class change to header verification. Read it before upgrading code that verifies HashMarks or caches headers.

```
pip install --upgrade pyrxd
```

## Changed (breaking): headers above a checkpoint must carry Radiant's difficulty

`pyrxd verify`, the verification pages and `pyrxd headers sync` now check every header above the newest shipped checkpoint against Radiant's difficulty rule. Its nBits must be exactly what Radiant Core's ASERT computes from the header below it (new `pyrxd.spv.asert`, a port of `src/pow.cpp` at Radiant-Core v3.1.2). A header that breaks the rule is `CONTRADICTED` at any depth and is never cached. Before, a server forging a confirmation on top of a real header could state a target 16 times easier than Radiant's. Results gain a `difficulty` step. The swap taker gate passes `difficulty_rule=False` for now, so its behaviour is unchanged. If Radiant changes its difficulty rule, honest headers above the change are reported `CONTRADICTED` until a pyrxd release ships the new rule.

## Added

- **`pyrxd new NAME`** writes a starter project: a Glyph mint, a test that runs it on a local regtest chain, a GitHub Actions workflow and a README. It depends on `pyrxd>=0.28.0,<0.29`.
- **`pyrxd.testing`**: public pytest fixtures (`regtest_node`, `regtest_wallet`, `regtest_client`) for testing against a real regtest node. The node enforces mainnet's relay floor.
- **The autonomous claim can ask a second operator before it takes a node rejection as final** (`RadiantChainIO(second_opinion=...)`). It is off by default.
- **Radiant Playground**, a docs page for learning pyrxd in the browser: https://mudwoodlabs.github.io/pyrxd/playground/. Its "Export as project" download needs this release, because the project it makes depends on `pyrxd.testing`.

## Checkpoints

This release ships the same checkpoint table as 0.27.1, with the newest checkpoint at block 477,792. So `pyrxd verify` and the pages can prove a mark's block up to block 481,824, and the swap taker gate up to block 497,952. On 2026-11-06, electrumx.radiantcore.org, electrumx.radiant4people.com, electrumx2.radiant4people.com and the maintainer's Radiant Core node all reported tip 479,388.

PROJECTED, not measured: at the nominal 300 s per block, the 2,436 blocks from 479,388 to 481,824 take about 8.5 days, so the limit would be reached around 2026-11-14 or 2026-11-15. A later checkpoint-only release will extend it. `pyrxd headers sync` moves the CLI's limit forward by caching newer headers; the pages do not use the cache.

The full list is in [CHANGELOG.md](https://github.com/MudwoodLabs/pyrxd/blob/main/CHANGELOG.md).
