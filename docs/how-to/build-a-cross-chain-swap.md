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
- **Value-scaled claim burial.** Radiant is low-cap PoW, so a *flat* claim-burial depth
  bounds reorg probability, not reorg *cost vs. value* — a swap worth more than the marginal
  cost to reorg a few Radiant blocks is economically reversible. The coordinator therefore
  refuses a value-bearing Radiant swap unless you give `MarginPolicy` the economic inputs it
  scales burial from — `rxd_reorg_cost_per_block` (measured, photons/block) and
  `value_at_risk_photons` (the assessed economic value; for FT/NFT this is *not* the on-chain
  amount) — **or** set `accept_flat_burial=True` for a deliberate dust run. The reorg gate
  then requires the taker's claim to bury `max(rxd_claim_burial, ceil(value × factor / cost))`
  deep before it returns SAFE, so an attacker must out-spend the value to reverse it.

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

Two families are proven; adding a chain within either is a config change, while a new
family is a deliberate effort.

### EVM family — Base works today (no new code)

The proven `EthLeg` + `EthHtlc.sol` machinery is **chain-id-agnostic**: the same contract
bytecode, the same `finalized`-checkpoint reads, the same claim/refund/scrape paths run on
any EVM-equivalent chain. Base (an OP-stack L2) is the first packaged example — swap a
Radiant asset against **native ETH on Base** by changing three knobs, none of which touch
the coordinator:

```python
from pyrxd import KNOWN_EVM_CHAINS, EthLeg, MarginPolicy

base = KNOWN_EVM_CHAINS["base-sepolia"]          # or "base" (mainnet; audit-gated)

rpc = EthRpc("https://sepolia.base.org", expected_chain_id=base.chain_id)
contract_leg = EthHtlcContractLeg(rpc=rpc, signing_key=key, chain_id=base.chain_id, artifact=ARTIFACT)
eth_leg = EthLeg(contract_leg=contract_leg, network=base.network, ...)  # audit gate applies

policy = MarginPolicy(..., eth_finalization_window_s=base.finalization_window_s)
```

The chain is pinned at every layer: `EthRpc` refuses a node on the wrong chain id, the leg
signs EIP-155-bound transactions, and the durable locator records `chain_id`. The
negotiated `counter_chain` stays `"eth"` — it names the *finalized-checkpoint family*, and
the locator's chain id pins the concrete chain.

**The one genuinely chain-specific knob is finality.** `KNOWN_EVM_CHAINS`
(`pyrxd.eth_wallet.chains`) records a sourced `finalization_window_s` per chain: on Base, an
L2 block is `finalized` only once the batch containing it sits in a *finalized L1 block* —
batch cadence (~1 min) + L1 inclusion + 2 L1 epochs, ≈15 min steady-state. The honest worst
case is the OP-stack **12-hour sequencing window** (a batch may legally land that late);
budget stalls in `CrossClockMargin.eth_finality_stall_tolerance_s`, exactly as for an L1
finality stall — never by inflating the steady-state window. Provenance is cited in the
module docstring; `evm_chain_by_id` fails closed on a chain with no vetted window.

Proofs: `tests/test_eth_leg_anvil_integration.py::test_full_lifecycle_on_base_chain_id`
(full leg lifecycle on Base Sepolia's chain id) and the entire coordinator e2e re-run as
Base via `XCHAIN_ETH_CHAIN_ID=84532 XCHAIN_ETH_REGTEST=1 pytest
tests/test_xchain_eth_swap_regtest_e2e.py -m integration`.

### Bitcoin family — Litecoin works today (no coordinator change)

The Taproot-HTLC leg machinery is **chain-agnostic across BIP341-activating Bitcoin-family
chains**: the identical P2TR HTLC, claim/refund builders, preimage scrape, and BIP68 CSV
semantics were proven byte-for-byte on **Litecoin** regtest consensus (claim accepted,
wrong-preimage rejected with the same witness-program-mismatch reason, premature refund
`non-BIP68-final`, matured refund accepted — Litecoin Core 0.21.5.5, taproot active). Swap
a Radiant asset against LTC by changing three knobs, none of which touch the coordinator:

```python
from pyrxd import KNOWN_POW_CHAINS, MarginPolicy

ltc = KNOWN_POW_CHAINS["litecoin"]   # network "ltc" / testnet "tltc" / regtest "rltc"

kp = generate_keypair(ltc.regtest_network)            # bech32m, rltc1p… addresses
htlc = build_htlc(..., network=ltc.regtest_network)   # the SAME taproot builders
policy = MarginPolicy.estimated(block_interval_s=ltc.block_interval_s)  # 150 s, not 600
```

The negotiated `counter_chain` stays `"btc"` — it names the *PoW-depth family* — and the
concrete chain is pinned by the leg/locator `network` tag (the bech32 HRP), exactly as an
EVM swap pins its chain by chain id. **The one genuinely chain-specific safety knob is the
block interval** (`pyrxd.btc_wallet.chains`): Litecoin's 2.5-minute target means an N-block
margin is 4× less wall-clock than on Bitcoin, and the reorg gate's reserve math shifts
accordingly — pass the registry interval or every timing margin silently shrinks.
Two more honest caveats: confirmation **depth must be value-scaled per chain** (reorg
resistance is priced in that chain's hashrate — the registry deliberately ships no depth
defaults), and the bundled mainnet funding-reader/broadcaster backends are Bitcoin-specific
(a Litecoin deployment supplies its own; the regtest harness drives the node RPC directly).

Proofs: the BTC-leg consensus suite and the **entire coordinator e2e suite re-run as
Litecoin** via the chain knobs —
`BTC_FAMILY_CHAIN=ltc BTC_REGTEST=1 pytest tests/test_btc_htlc_regtest_e2e.py -m integration`
and `XCHAIN_BTC_FAMILY=ltc XCHAIN_REGTEST=1 pytest tests/test_xchain_swap_regtest_e2e.py -m
integration` (the node image builds from `docker/litecoin-regtest.Dockerfile`, wrapping the
official release binary). Mainnet `"ltc"` stays behind the audit gate like every
value-bearing network.

### A new chain family — the deliberate path

`CounterChainLeg` (`pyrxd.gravity.counter_chain_leg`) is the documented contract a new
backend implements: `derive_expected_funding` / `fund` / `claim` / `refund` /
`recover_secret` / `is_final`. The ABC was extracted from two *real* shapes (BTC Taproot +
ETH Solidity), so it reflects what a third chain actually needs — finality is a per-leg
concern, not a single RPC read. A chain outside both proven families means new consensus
semantics and new finality modelling; adopting the ABC in the coordinator (the BTC path is
still duck-typed) is a deliberate, separately-tested change on mainnet-proven code — read
the ABC's scope note before starting.
