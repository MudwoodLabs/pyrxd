This release makes the swap coordinator and the watchtower act on what the chain shows about a swap's counter leg, rather than on what pyrxd itself broadcast. It also fixes a BTC fund that could leave real BTC untracked, restricts who can refund an `Erc20Htlc`, and closes several ways one faulty source could lower or silence a watchtower page. **Many changes are visible to operators and scripts, and swap records written by this release cannot be read by earlier ones.** They are listed below.

```
pip install --upgrade pyrxd          # or 'pyrxd[eth]' for the ETH/ERC-20 legs
```

## Upgrading

- **Swap records:** `SWAP_RECORD_SCHEMA_VERSION` is now 11 (0.26.1 wrote 2). This release reads records written by 0.26.1. A pyrxd before 0.27 refuses a record this release writes. Do not drive one swap with mixed pyrxd versions.
- **ETH counter-leg contracts:** the contracts are now built in this repo, optimized, and were revised before the external audit. Contracts deployed from the 0.26.1 artifacts are refused by this repo's swap runners and tests, which check a deployed contract byte for byte. The wheel ships no ETH artifact, so an application that injects its own is unaffected.
- **`Erc20Htlc.refund()`** can now be called only by the refundee or the deployer. Before, anyone could refund a matured contract, so a third party could refund one holding the first part of a token push and leave the rest of the push, arriving later, movable by nobody. `EthHtlc` is unchanged. **A contract already deployed from the 0.26.1 or earlier artifacts keeps the old rule, and upgrading does not change it:** push the full token amount before the contract matures, and do not push into a matured contract.

## Swaps follow the chain (#850)

On ETH and BTC swaps, `taker_refund_btc`, `mutual_refund` and `reconcile_counter_leg` read the counter leg's disposition from every configured source (`read_counter_disposition`, `read_btc_counter_disposition`) and move the record only on what the chain shows, not on our own refund's broadcast. A refund stays pending until it is final on chain. New, gated exits cover cases that had none: a taker can end a swap it never funded, an operator can end an ETH record on a counter-leg case with no automatic end once the chain is read, an empty expired ERC-20 contract can end the swap, and a maker's record ends on its own covenant refund. A multi-source BTC depth is now the depth a quorum of sources vouches for, not the minimum, so one source that under-reports no longer holds a buried claim at shallow.

## Watchtower

The watchtower reads the record's role, tells a taker's BTC refund from the maker's claim, and reads an ETH counter leg's disposition with the coordinator's reader. It checks records ended by earlier pyrxd versions once. Several fixes stop one faulty source (a failing, lagging, forked or lying endpoint, or one BTC or RXD source) from lowering or silencing a page, and an ACKed reconcile error now re-pages. ACK handling and escalation were fixed after a whole-component review.

## Also in this release

- **A BTC fund whose amount readback failed after its broadcast left real BTC locked and untracked (#841).** The funding transaction is now recorded before its broadcast, so a failed readback is resumable.
- **`pyrxd headers sync` and `pyrxd headers status`** keep a local cache of verified block headers, so `pyrxd verify` keeps verifying new marks between releases (#826).
- **ElectrumX:** a code-1 error on a read is a fault, not a transaction rejection, and failover asks the next server. `close()` closes its WebSocket, and concurrent first calls share one socket.
- **ETH:** a JSON-RPC error sent with HTTP 400 keeps its reason, so the log scan can tell a range-limit refusal and narrow the range instead of losing that endpoint. The narrowing stops at 1,000 blocks.
- **Wallet:** the gap-limit scan counts token-only addresses as used and has an upper bound (#787, #772).
- **Validators** no longer accept a value with a trailing newline (#769).

## Deprecated

- `CounterLegClaimedByCounterparty` and `CounterLegSettledUnverified` are no longer raised; they still import.
- `wave_identity.names_resolving_now` in `--verify-wave --json` output; use `names_held_now`.

## Known limitation

TODO(release): fill in from the checkpoint table that ships (newest checkpoint after #908), as the 0.26.0 notes did. State only the block numbers; a projected date must be labelled PROJECTED.

The full list, including every behaviour change, is in [CHANGELOG.md](https://github.com/MudwoodLabs/pyrxd/blob/main/CHANGELOG.md).
