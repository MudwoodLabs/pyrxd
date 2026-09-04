# Build a cross-chain atomic swap (BTC/ETH ↔ RXD)

pyrxd ships a **trustless cross-chain atomic swap**: trade a Radiant asset (RXD, a
Glyph FT, or a Glyph NFT) against BTC or ETH with no custodian and no trusted third
party. It's a hash-timelock (HTLC) swap driven by a chain-neutral coordinator, proven
end-to-end on regtest and on small real-value mainnet/Sepolia runs. The EVM counter-leg can
also settle in **USDC or USDT** rather than native ETH — the same HTLC, but a weaker trust
model, because a stablecoin issuer can freeze the asset; see *Settling the counter-leg in a
stablecoin* below before you use it.

> **New to this?** Start with the guided tutorial —
> [Trustless cross-chain swap: RXD ↔ ETH](../tutorials/cross-chain-swap.md) — which walks a full
> swap settling on local chains. This page is the reference for the pieces.

> **Unaudited — verify it yourself before moving real value.** This swap stack is
> open-source software, provided as-is (see the [LICENSE](../../LICENSE)). It's proven
> end-to-end on regtest/testnet and on small real-value runs, but has not had an external
> security audit. An atomic swap's whole job is to be safe against a hostile counterparty —
> review the construction against your own use before trusting it with value. See the swap
> coordinator's module docstring for the current residual-risk notes.

> **This is the HTLC swap — not the SPV-oracle one.** An earlier SPV-oracle swap covenant
> is **deprecated and superseded** by this HTLC construction (it was a non-atomic, weaker
> swap with known won't-fix parser findings). Build on the coordinator below; the
> `examples/gravity_*` scripts are SPV-oracle reference-only. See
> [the design decision](../solutions/design-decisions/spv-swap-deprecated-primitive-retained.md)
> for why, and `examples/htlc_swap_demo.py` for a runnable on-ramp to *this* path.

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
2. The **maker** locks the Radiant covenant **first**.
3. The **taker** locks the counter-chain (BTC/ETH HTLC) **second** — `taker_funds_btc`
   refuses until `pre_btc_lock_check` has read that covenant off the Radiant chain.
4. The **maker** claims the counter-chain **first**, revealing `p`.
5. The **taker** scrapes `p` and claims the Radiant asset **before its refund opens**.

The timelocks must satisfy, **in wall clock**:

**`t_rxd · i_rxd ≥ t_counterchain · i_counterchain + margin · i_counterchain`**

The maker holds `p`, **locks** the Radiant leg and **claims** the counter leg, so the leg it
*locks* carries the **longer** refund window and the leg it *claims* the shorter. The taker's
client MUST verify this before funding, or refuse. The coordinator enforces it fail-closed
(`assert_timelock_margin`) — don't route around it.

> **⚠ This page taught the opposite until 2026-09-02.** It gave the lock order as taker-first
> (superseded by HZ-1/#392) and the invariant as `t_counterchain > t_rxd + margin` in raw blocks
> — the layout in which the maker refunds its own leg while `p` is still secret and *then* claims
> the counter leg, taking both. **If you built against this page, re-derive your lock order and
> your timelock ordering.**

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

- **BTC counter-leg.** Use `BitcoinTaprootLeg` from `pyrxd.btc_wallet` — the concrete,
  exported production BTC leg, and what the proven regtest end-to-end drives. Pass it as
  `btc_leg=`.

  > This page previously said "there is no `BitcoinTaprootLeg` class yet" and sent readers
  > to hand-roll a duck-typed adapter over `pyrxd.btc_wallet.taproot` — on a fund-moving
  > surface, where a subtly different adapter is exactly the kind of thing that loses
  > money. The class exists (`btc_wallet/htlc_leg.py`), is exported from
  > `btc_wallet/__init__.py`, and is used by `tests/test_xchain_swap_regtest_e2e.py`.
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
| RXD ↔ USDC/USDT full swap (Radiant regtest + a forked-mainnet token) | `tests/test_xchain_erc20_usdc_lifecycle_e2e.py` |
| Two-party adversarial scenarios (hostile maker/taker, races) | `tests/test_xchain_eth_adversarial_e2e.py` |
| Operational driver (Sepolia + RXD, at-keyboard, dust) | `scripts/eth_swap_run.py` |

Run the regtest suites with a local node — see the
[quickstart](../tutorials/quickstart.md) for `pyrxd regtest setup` / `up`, plus an Anvil
binary (ETH) or a `bitcoin-core` regtest image (BTC):

```console
$ RADIANT_REGTEST=1 XCHAIN_REGTEST=1 pytest tests/test_xchain_swap_regtest_e2e.py -m integration
$ XCHAIN_ETH_REGTEST=1 pytest tests/test_xchain_eth_swap_regtest_e2e.py -m integration
```

## Settling the counter-leg in a stablecoin (USDC / USDT)

The EVM counter-leg can hold **USDC or USDT** instead of native ETH. The reason is pricing: a swap
is negotiated now and settles hours later, so an ETH-denominated counter-leg carries ETH/RXD
volatility across the entire timelock window, and whatever the pair does in between lands on one of
the two parties. A stablecoin leg removes that — the amount agreed is the amount that settles.

The protocol is unchanged. `Erc20Htlc.sol` was deliberately given the same `claim(bytes32)` /
`refund()` signatures and the same **un-indexed** `Claimed(bytes32)` event as the native contract,
so `Erc20HtlcLeg` subclasses `EthHtlcContractLeg` and inherits secret recovery, finality and the
refund path unchanged. Wiring it is one substitution:

```python
from pyrxd import EthLeg, KNOWN_EVM_CHAINS
from pyrxd.eth_wallet.erc20_leg import Erc20HtlcLeg
from pyrxd.eth_wallet.rpc import EthRpc
from pyrxd.eth_wallet.tokens import token_for

base = KNOWN_EVM_CHAINS["base-sepolia"]              # or "base" (mainnet; opt-in required)
usdc = token_for("USDC", base.chain_id)              # (symbol, chain id) → a PINNED address

rpc = EthRpc(url, expected_chain_id=base.chain_id)
contract_leg = Erc20HtlcLeg(token=usdc, rpc=rpc, signing_key=key, chain_id=base.chain_id,
                            artifact=ERC20_ARTIFACT)  # the Erc20Htlc artifact, not the native one
eth_leg = EthLeg(contract_leg=contract_leg, network=base.network, ...)
```

`scripts/eth_swap_run.py` exposes the same choice as `--counter-asset` (derived from the registry,
so a newly pinned symbol is selectable the day it lands) with `--token-amount` in base units.

Four things differ from the native leg, and each is a place to get it wrong:

- **The asset is an address, never a symbol.** `token_for(symbol, chain_id)` resolves from a pinned
  registry and refuses anything else. Several chains carry both Circle's native USDC and a bridged
  `USDC.e` that reports the identical `symbol()` and `decimals()` — verified by reading them off the
  chains on 2026-08-23 — so nothing in a token's self-description tells them apart. The bridged
  contracts are refused **by address**, named for what they are. USDC is pinned on Ethereum, Base,
  Optimism, Arbitrum One and Linea (and on the Sepolia testnet of all but Linea); USDT on Ethereum,
  Optimism and Base.
- **Amounts are base units, not wei.** USDC and USDT are 6-decimal; a 6-vs-18 mixup is a factor of
  10^12 in every amount. The decimals are pinned *and* cross-checked against the live contract at
  swap start, and the durable record carries its own `"eth-erc20"` chain tag so no reader can take
  base units for wei.
- **Funding is two transactions** — deploy, then a plain `transfer`. A payable constructor cannot
  pull a token, and there is no `approve` anywhere, so no allowance is ever created. "Deployed" no
  longer implies "funded"; the coordinator persists the deployed address the instant it confirms and
  strictly before the tokens move, so a crash mid-fund never leaves value at an address nobody
  recorded.
- **The terms name the token.** `NegotiatedTerms.token_address` binds the asset, and the leg refuses
  to fund or to build a locator if the terms and the leg disagree in either direction — before
  anything is broadcast.

### What you give up: the issuer

Native ETH is held by the EVM, and nobody can stop a transfer of it. USDC and USDT are held by
contracts whose issuer can **freeze an address**, which puts a third party inside a two-party
protocol.

It bites exactly where an HTLC is most exposed. Claiming one leg publishes the preimage, and from
that instant the counterparty can take the other. A freeze landing in that window means the
counterparty sweeps while the frozen party can neither claim nor refund — a one-sided loss.
**Atomicity on this corridor is conditional on the issuer not intervening.** On the native ETH leg
there is no such party, and the refund right is unconditional.

Two of these were executed on a mainnet fork against the real USDC contract with the live
blacklister impersonated; the rest follows from the token's own transfer rule and has not been
run. The distinction is kept because only the measured cells are evidence:

| what is frozen | `claim` | `refund` | recoverable? | source |
|---|---|---|---|---|
| the claimant | reverts | works | yes — refund after the timeout | `claim` **measured**; `refund` inferred |
| the refundee | works | reverts | yes — the claim still pays | inferred, not run |
| **the HTLC contract itself** | **reverts** | **reverts** | **NO — the funds are stranded permanently** | **both measured** |

The third row is the one that matters, and it is the one that was actually executed: no timeout
rescues it. The inferred cells follow because a blacklisted address cannot be a party to a USDC
transfer in either direction — sound reasoning, but reasoning.

What the code does about that — none of which is a fix:

- **A pre-reveal gate, inside `claim`.** Before it will build a claim, the leg reads freeze status
  **at the tip** for the HTLC contract address and the claimant — the two addresses a claim actually
  touches — and refuses if either is frozen. Nothing has been broadcast at that point, so the
  preimage is still secret and abandoning the swap costs only fees. The gate lives inside the
  dangerous operation rather than beside it, because a gate the caller must remember to invoke is a
  gate that eventually is not invoked. (The refundee is deliberately *not* checked here: a claim
  sweeps to the claimant and never touches the refundee, so a frozen refundee cannot make the claim
  revert, and refusing on it would hand the counterparty a free veto over value the claimant has
  already earned. The refundee is checked at the other end instead — see the next bullet.)
- **A pre-fund gate, before you pay in.** `refund()` pays the refundee, so funding a leg whose
  refundee is already frozen buys a position with no exit: if the counterparty never claims, the
  tokens stay in the contract for good. Before the deploy spends gas, and again inside the step
  that actually moves the tokens, the leg reads freeze status for the claimant, the refundee and —
  once it exists — the contract itself. It refuses only when something is about to be sent, so a
  resume whose push already landed can still recover its locator.
- **It narrows the window; it does not close it.** Check-then-reveal is itself a race. A freeze
  landing between the check and the broadcast — or at any point after the reveal — is unmitigated by
  construction. It is a seatbelt, not a fix.
- **An unreadable answer is a refusal, not a "no".** The freeze read raises rather than reporting
  "not frozen" when the RPC is down, throttled or returning garbage. It defends a *failing* provider,
  not a *lying* one: the read is single-source, so a hostile node claiming "not frozen" is uncaught.
- **One contract per swap.** Each swap gets a fresh `CREATE` address, so a contract freeze costs one
  swap rather than every open swap at once.
- **A short funded window is a safety property here** in a way it is not for native ETH — exposure is
  the time the tokens sit in the contract. That cuts against the usual instinct to be generous with
  timelocks.

**Two pinned tokens cannot freeze — and that is still not "no counterparty risk".** OP-stack bridged
USDT on Optimism (`0x94b008aA…`) and Base (`0xfde4C96c…`) has no blacklist under any spelling, and
that is established positively rather than inferred from a probe that found nothing: verified
2026-08-25, `l1Token()` returns Tether's real L1 USDT, neither contract is a proxy (both EIP-1967
slots empty), and an opcode-aware disassembly finds no `DELEGATECALL`, `CALLCODE`, `SELFDESTRUCT` or
`CREATE*` — so the code cannot be swapped out. The only privileged entry points are bridge-gated mint
and burn, and that is the residual: **burn is bridge-callable against an arbitrary holder, and the L2
bridge is itself an upgradeable system contract.** That is a different risk — bridge governance
rather than issuer discretion — not an absent one, and the pre-reveal gate does not cover it, because
it only knows about freezes. A token whose freeze surface could not be established that way stays
unpinned and `token_for` refuses it (Linea USDT is an upgradeable proxy with a populated admin slot;
"cannot freeze today" is not the property worth pinning).

The full analysis lives in the [threat model](../threat-model.md), and
[the design decision](../solutions/design-decisions/usdc-corridor-is-issuer-trusted-not-trustless.md)
records the residual as accepted. **Do not describe this corridor as trustless.**

### What has actually been proven

`tests/test_xchain_erc20_usdc_lifecycle_e2e.py` drives the production `SwapCoordinator` from
NEGOTIATED to COMPLETED — plus the refund path — with the Radiant leg on a regtest node and the token
leg on an **anvil mainnet fork**: the real token contract, its real blacklist, real 6-decimal
arithmetic. It re-runs against Base, which is what exercises the cannot-freeze branch of the
pre-reveal gate. `tests/test_erc20_leg_fork_integration.py` covers the leg itself the same way,
including a real claim inside the inherited gas budget.

Both need a fork RPC (`PYRXD_ETH_FORK_RPC`) and skip cleanly without one, so they are local/manual
gates rather than per-push CI. And **no real value has moved on a stablecoin mainnet**: the one dust
run so far paired a mainnet Radiant leg with **Base Sepolia testnet** USDC.

## Adding another counter-chain

Two families are proven; adding a chain within either is a config change, while a new
family is a deliberate effort.

### EVM family — Base, Optimism, Arbitrum, Linea work today (no new code)

The proven `EthLeg` + `EthHtlc.sol` machinery is **chain-id-agnostic**: the same contract
bytecode, the same `finalized`-checkpoint reads, the same claim/refund/scrape paths run on
any EVM-equivalent chain. Base (an OP-stack L2) is the first packaged example — swap a
Radiant asset against **native ETH on Base** by changing three knobs, none of which touch
the coordinator:

```python
from pyrxd import KNOWN_EVM_CHAINS, EthLeg, MarginPolicy
from pyrxd.eth_wallet.rpc import EthRpc
from pyrxd.eth_wallet.htlc_leg import EthHtlcContractLeg

base = KNOWN_EVM_CHAINS["base-sepolia"]          # or "base" (mainnet; opt-in required)

rpc = EthRpc("https://sepolia.base.org", expected_chain_id=base.chain_id)
contract_leg = EthHtlcContractLeg(rpc=rpc, signing_key=key, chain_id=base.chain_id, artifact=ARTIFACT)
eth_leg = EthLeg(contract_leg=contract_leg, network=base.network, ...)  # mainnet needs an opt-in

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

**The registry now ships more EVM chains** (mainnet + testnet each; mainnet behind an opt-in): **Optimism**
(`optimism`, same OP-stack as Base, 900 s), **Arbitrum One** (`arbitrum-one`, Nitro, 1200 s — ~24 h
sequencer force-inclusion worst case), and **Linea** (`linea`, a zk/validity rollup, 6000 s ≈ the
median hard finality, with a documented up-to-16 h tail). Each window is sourced per chain because
the finality *mechanism* differs (OP-stack batch cadence vs Arbitrum's vs zk proof cadence) even
though the leg code is identical. **Polygon PoS is deliberately *not* in the registry**: its
`finalized` tag is Polygon's own validator-set "milestone" finality (~5 s), **not** Ethereum-anchored
— it's a sidechain, so the Ethereum-finality assumption (and the ≥768 s floor) would misrepresent its
trust model. A Polygon-PoS swap would need a finality model justified in Polygon's *own* security
terms; `evm_chain_by_id(137)` fails closed so a sidechain is never silently treated as a rollup.

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
from pyrxd.btc_wallet.keys import generate_keypair
from pyrxd.btc_wallet.taproot import build_htlc

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
official release binary). Mainnet `"ltc"`, like every value-bearing network, requires the
explicit opt-in.

### A new chain family — the deliberate path

`CounterChainLeg` (`pyrxd.gravity.counter_chain_leg`) is the documented contract a new
backend implements: `derive_expected_funding` / `fund` / `claim` / `refund` /
`recover_secret` / `is_final`. The ABC was extracted from two *real* shapes (BTC Taproot +
ETH Solidity), so it reflects what a third chain actually needs — finality is a per-leg
concern, not a single RPC read. A chain outside both proven families means new consensus
semantics and new finality modelling; adopting the ABC in the coordinator (the BTC path is
still duck-typed) is a deliberate, separately-tested change on mainnet-proven code — read
the ABC's scope note before starting.
