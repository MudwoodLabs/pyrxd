This release fixes a HIGH-severity defect in the ETH/ERC-20 swap leg: a maker's check of the counterparty's deployed HTLC could be passed by a modified contract that pays someone else. **If you run ETH or ERC-20 swaps, upgrade before your next one.** It also makes the swap taker prove the maker's Radiant funding before locking, makes `pyrxd verify` and the verification pages prove a mark's block, and fixes several places where `swap status`, `swap recover-preimage` and error output reported something untrue or printed an endpoint's credentials. **Some changes are visible to scripts and operators.** They are listed below.

```
pip install --upgrade pyrxd          # or 'pyrxd[eth]' for the ETH/ERC-20 legs
```

## Security

- **ETH/ERC-20 HTLC counterparty check (HIGH, #798, advisory GHSA-44pc-4fv5-39hv). Affects 0.6.0 through 0.25.1.** `verify_funded` compared the counterparty's deployed runtime with the expected one using a compare that skipped every byte that was zero in the artifact. Solidity stores each `immutable` at several offsets, and a getter reads a different copy from the one `claim()` reads. A taker who deploys the ETH side could make the getters name the maker while `claim()` paid another address. The maker's check passed, the maker revealed the preimage, and the taker could take both legs. The check now places every negotiated immutable at every offset and requires exact byte equality. A per-PR test now runs the real `verify_funded` against forged copies (#821).
- **A settled ETH contract is refused (#821).** `verify_funded` refuses a contract whose `settled` flag is already set, since it cannot pay out. An ETH leg also refuses to sign for a chain other than the one its RPC is pinned to.
- **Status and recovery report what they know (#815, #820).** `swap status` no longer calls a BTC refund still in the mempool, one RPC's report of an ETH refund, or an empty ETH log read a finished or still-locked leg. It no longer tells a taker to keep waiting while the ETH preimage is already in the contract's logs. `status`, `build-claim` and `build-refund` identify the RXD covenant by its funding outpoint, not by any output at the covenant script.
- **Credentials stay out of output (#815, #821, #823).** A keyed RPC or ElectrumX URL no longer reaches error text, `--debug` tracebacks, `--json` output, watchtower pages or logs. pyrxd names an endpoint as `scheme://host:port`.

## The swap taker proves the maker's funding (#809, #817, #822)

The taker no longer takes one ElectrumX server's word that the maker's covenant exists before locking BTC or ETH. `SwapCoordinator` checks the funding transaction's merkle branch, links its block header to a checkpoint pyrxd ships, and requires a depth sized from the value at stake. By default, above 1,000 RXD, two operators must report the funding's depth. A swap the gate would refuse later is refused when the coordinator is built, before anyone locks. What stays the server's word, such as whether the covenant output is still unspent, is listed in the CHANGELOG.

## Verification proves the mark's block (#802, #804, #807)

`pyrxd verify` and the `/verify/` and `/inspect/` pages check the mark's merkle branch against the header for its height, and link that header to a shipped checkpoint. A verified block reports `VERIFIED` and the depth pyrxd proved. The checkpoint table was re-checked for this release against three public ElectrumX servers and the maintainer's own Radiant Core node. All four agreed on every entry.

## Also in this release

- The RXD↔USDC/USDT end-to-end suite, the only end-to-end run of the ERC-20 leg, passes again and runs nightly on forks of Ethereum and Base (#824).
- Sources are counted by operator, so two servers of one operator no longer corroborate each other (#801, #803).
- `GravityTrade`, the SPV-oracle swap, warns that it is ungated and deprecated. Use `SwapCoordinator` instead (#805).

## Behaviour changes

- **`pyrxd-watchtower`** exits 1 when it has fewer RXD sources of distinct operators than `--rxd-quorum`. `--accept-single-source` starts it anyway, but no longer arms autonomous refunds on single-source reads. That now needs `--auto-refund-on-single-source`.
- **Source counting:** endpoints that share an operator or a registered domain count once, and every loopback spelling is one source. A quorum given two of them raises `ValidationError`. `endpoint_host` and `count_distinct_hosts` are removed.
- **ETH/ERC-20 artifacts** must carry `immutableReferences` and `immutable_names`, or the leg is refused at construction.
- **Swap runner scripts** take `--rxd-ssh-host` and `--rxd-container` with no default, and need `--rxd-block-interval-fast-s`. NFT and FT swaps need `--value-at-risk-photons`.
- **`SwapCoordinator`** refuses a negotiated value-bearing swap without `MarginPolicy.rxd_block_interval_fast_s`. It also refuses one without a value at stake in any role but maker, and an ETH or ERC-20 swap without `now_unix_s`. A Radiant leg must serve `maker_funding_evidence`.
- **`swap status`** has new situations: `COVENANT_UNIDENTIFIED`, `COUNTER_LEG_REFUND_UNCONFIRMED`, `BOTH_SPENT_OUTCOME_UNKNOWN`, `MAKER_REFUNDED_AND_CLAIMED` and `TAKER_CLAIMED_AND_REFUNDED`. The ETH counter leg reports `UNKNOWN` or `REFUND_REPORTED_UNCONFIRMED` where it reported `LOCKED` or `SPENT_NO_PREIMAGE`. `--json` gains `chain.covenant_spend`. `chain.blocks_to_refund` is now `t_rxd - depth`, so 0 means the refund is valid now.
- **`swap recover-preimage`** exits 2 on an inconclusive read. It, `build-claim` and `build-refund` exit 2, not 4, on a network error or a reply that is not JSON.
- **`pyrxd verify`** reports `checks.block.state` as `VERIFIED`, where it reported `CONFIRMED`, when the block verifies. It exits 2 when the server's proof contradicts the height it reported.
- **Config:** an empty `electrumx_servers` entry is an error, and a refused configuration exits 1, not 4.

## Known limitation

`pyrxd verify` and the verification pages link at most 4,032 headers past the newest checkpoint this release ships (block 467,712), so they can prove a mark's block only up to about block 471,744. A newer mark reports `CONFIRMED` in `pyrxd verify`, with the reason, and the pages show it as the server's word.

PROJECTED, not measured: the tip was 469,235 on 2026-10-02. At the nominal 300 s per block, the remaining 2,509 blocks take about 8.7 days, so the limit would be reached around 2026-10-10 or 2026-10-11. Faster blocks bring that date forward. A 0.26.1 with a newer checkpoint is planned once one is deep enough to add ([#826](https://github.com/MudwoodLabs/pyrxd/issues/826)).

The full list is in [CHANGELOG.md](https://github.com/MudwoodLabs/pyrxd/blob/main/CHANGELOG.md).
