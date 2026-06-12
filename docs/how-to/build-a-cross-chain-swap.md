# Build a cross-chain atomic swap (BTC/ETH ↔ RXD)

pyrxd ships a **trustless cross-chain atomic swap**: trade a Radiant asset (RXD, a
Glyph FT, or a Glyph NFT) against BTC or ETH with no custodian and no trusted third
party. It's a hash-timelock (HTLC) swap driven by a chain-neutral coordinator, proven
end-to-end on regtest and on small real-value mainnet/Sepolia runs.

> **PRE-AUDIT — regtest / testnet only.** This primitive has **not** had an external
> security audit. It's the right tool to build and demo cross-chain swaps on
> regtest/testnet, but **do not move real value** with it until the audit gate clears.
> An atomic swap's entire job is to be safe against a hostile counterparty; that
> property is what an audit certifies. See the swap coordinator's module docstring for
> the current residual-risk notes.

## The mental model

Two parties, two chains, one secret:

- The **maker** holds the Radiant asset and wants BTC/ETH. The **taker** holds BTC/ETH
  and wants the asset.
- The maker generates a 32-byte secret `p` and publishes `H = SHA256(p)`. The same `H`
  locks both legs; revealing `p` to claim one leg lets the counterparty claim the other.
- The coordinator drives a chain-neutral state machine over **two legs**: the **Radiant
  covenant leg** (the asset side) and a **counter-chain leg** (the BTC or ETH value side).

### The one safety invariant you must respect

```python
from pyrxd import SwapCoordinator
print(SwapCoordinator.__module__)  # the role invariant lives in swap_coordinator
```

`MAKER_SECRET_TAKER_LOCKS_BTC_FIRST` (a documented constant in
`pyrxd.gravity.swap_coordinator`) is the safety hinge — read it before you wire anything:

1. The **maker** generates `p`, publishes `H`.
2. The **taker** locks the counter-chain (BTC/ETH HTLC) **first**.
3. The **maker** locks the Radiant covenant **second**.
4. The **maker** claims the counter-chain **first**, revealing `p`.
5. The **taker** scrapes `p` and claims the Radiant asset **before its refund opens**.

The timelocks must satisfy **`t_counterchain > t_rxd + margin`**: the leg claimed
*second* (Radiant) carries the *shorter* refund window. The taker's client MUST verify
`t_counterchain − t_rxd ≥ margin` before funding, or refuse. The coordinator enforces
this fail-closed (`assert_timelock_margin`) — don't route around it.

## The pieces (all importable from the top level)

```python
from pyrxd import (
    SwapCoordinator,    # the chain-neutral orchestrator / FSM
    CoordinatorConfig,  # margins, durability + value-bearing opt-ins
    MarginPolicy,       # timelock margins; MarginPolicy.measured(...) for real value
    NegotiatedTerms,    # H, amounts, timeouts, destinations — the public envelope
    SwapRecord, SwapState,  # the durable swap record + its FSM states
    generate_secret,    # the maker's (p, H)
    RadiantCovenantLeg, # the asset (RXD/FT/NFT) leg
    EthLeg,             # the ETH counter-chain leg (Solidity HTLC)
    CounterChainLeg,    # the ABC every counter-chain backend implements
)
```

The coordinator is constructed with both legs plus its collaborators:

```python
coordinator = SwapCoordinator(
    record=SwapRecord(state=SwapState.NEGOTIATED, terms=terms),
    counter_leg=eth_leg,      # or btc_leg=... for the BTC Taproot-HTLC path
    radiant_leg=rxd_leg,
    indexer=indexer,          # resolves Glyph refs / reads RXD chain state
    seen_store=seen_store,    # dedup / replay durability across restarts
    config=CoordinatorConfig(margin_policy=MarginPolicy.measured(...)),
)
```

- **BTC counter-leg.** The proven BTC path consumes the Taproot-HTLC functions in
  `pyrxd.btc_wallet.taproot` through a duck-typed surface (there is no `BitcoinTaprootLeg`
  class yet — see `CounterChainLeg`'s scope note). Pass it as `btc_leg=`.
- **ETH counter-leg.** `EthLeg` wraps the Solidity `EthHtlc` contract via web3 (an optional
  dependency: `pip install pyrxd[eth]` or add `web3`).
- **`MarginPolicy.measured(...)` vs estimated.** A real-value swap MUST use a measured
  margin policy; the coordinator refuses a value-bearing swap on estimated margins unless
  you consciously opt in (`accept_estimated_eth_margins` / the dust-run hatches).

## Runnable references (start here — these actually execute)

Rather than a toy snippet that wouldn't run against real chains, embed from the proven,
maintained harnesses:

| What | Where |
|---|---|
| BTC ↔ RXD full swap on regtest (happy / mutual-refund / maker-stall / reorg-gate) | `tests/test_xchain_swap_regtest_e2e.py` |
| ETH ↔ RXD full swap on Anvil + regtest | `tests/test_xchain_eth_swap_regtest_e2e.py` |
| Two-party adversarial scenarios (hostile maker/taker, races) | `tests/test_xchain_eth_adversarial_e2e.py` |
| Operational driver (Sepolia + RXD, at-keyboard, dust) | `scripts/eth_swap_run.py` |

Run the regtest suites with a local node — see the
[quickstart](../tutorials/quickstart.md) for `pyrxd regtest setup` / `up`, plus an Anvil
binary (ETH) or a `bitcoin-core` regtest image (BTC):

```console
$ RADIANT_REGTEST=1 XCHAIN_REGTEST=1 pytest tests/test_xchain_swap_regtest_e2e.py -m integration
$ XCHAIN_ETH_REGTEST=1 pytest tests/test_xchain_eth_swap_regtest_e2e.py -m integration
```

## Adding another counter-chain

`CounterChainLeg` (`pyrxd.gravity.counter_chain_leg`) is the documented contract a new
backend implements: `derive_expected_funding` / `fund` / `claim` / `refund` /
`recover_secret` / `is_final`. The ABC was extracted from two *real* shapes (BTC Taproot +
ETH Solidity), so it reflects what a third chain actually needs — finality is a per-leg
concern, not a single RPC read. Adopting the ABC in the coordinator (the BTC path is still
duck-typed) and migrating the durable `SwapRecord` locator to a chain-tagged union is a
deliberate, separately-tested change on mainnet-proven code — read the ABC's scope note
before starting. New legs (e.g. Base native-ETH, Litecoin) are tracked in the roadmap.
