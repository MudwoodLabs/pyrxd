# Trustless cross-chain swap: RXD ↔ ETH on local chains

Trade a Radiant asset for ETH with **no bridge, no custodian, and no trusted third party** —
and watch it settle end to end on chains running entirely on your own machine. This is the
flagship of what pyrxd's `gravity` module does: a hash-timelock (HTLC) atomic swap driven by a
chain-neutral coordinator.

> **Pre-audit — local/testnet only.** This primitive has **not** had an external security
> audit. It's the right tool to build and demo cross-chain swaps on regtest/testnet, but **do
> not move real value** with it until the audit gate clears. An atomic swap's whole job is to be
> safe against a hostile counterparty; that property is what an audit certifies.

## The idea in one breath

Two parties, two chains, **one secret**:

- The **maker** holds the Radiant asset and wants ETH. The **taker** holds ETH and wants the asset.
- The maker picks a random 32-byte secret `p` and publishes `H = SHA256(p)`. The **same `H`**
  locks both legs.
- Revealing `p` to claim *one* leg hands the counterparty the secret to claim the *other*. So
  either **both** legs settle, or **neither** does (after a timeout both refund). That's the
  atomicity — enforced by each chain's own consensus, not by anyone's good behaviour.

```
  one secret p,  H = SHA256(p),  locks BOTH legs:

      Radiant covenant  ◀──── same H ────▶  ETH HTLC
      (holds the asset)                     (holds the ETH)

  reveal p to claim one leg  →  the counterparty scrapes p and claims the other.
```

You'll do this twice: first see the on-chain pieces with **no setup at all**, then run a **full
swap** on local Anvil + a Radiant regtest node.

## Part 1 — see the building blocks (30 seconds, no setup)

The Radiant side of the swap is an on-chain **HTLC covenant**: it holds the asset and can be
spent two ways — the taker's **hashlock claim** (reveal `p`) or the maker's **CSV refund** (after
a timelock). Build a real one, with the real production builders, with no network:

```console
$ python examples/htlc_swap_demo.py
```

It generates `(p, H)`, builds an NFT HTLC covenant, and builds *both* spend paths — the claim
(which embeds `p`) and the timelocked refund — printing the maker/taker roles and the one safety
invariant you'll meet again below. Nothing connects out; it's pure construction. Read it
alongside [build a cross-chain swap](../how-to/build-a-cross-chain-swap.md), which catalogues the
pieces.

## Part 2 — run a full swap on local chains

Now the whole thing: a real `EthLeg` (deploying the real `EthHtlc` contract on a local **Anvil**) and a
real `RadiantCovenantLeg` (a **radiant-core regtest** node), driven through the production
`SwapCoordinator` from negotiated to **completed**. No real value moves — Anvil is a local devnet
with public deterministic keys, and the Radiant node is a throwaway regtest container.

### Prerequisites (one-time)

```console
$ pip install "pyrxd[eth]"          # the ETH leg needs web3
$ pyrxd regtest setup               # builds the radiant-core regtest image (downloads the
                                    # official release + verifies its checksum); same Step 0 as
                                    # the quickstart
$ curl -L https://foundry.paradigm.xyz | bash && foundryup   # installs `anvil`
```

(Need Docker on your PATH too — the regtest node runs in a container.)

### The flow, step by step

The coordinator is chain-neutral: it drives a state machine over **two legs** and never trusts a
counterparty's claims — every step re-verifies against on-chain truth. Here's the happy path
(the method names say `btc` for historical reasons; they drive whichever counter-leg you wired —
here, ETH):

```python
# build the covenant + the two real legs + the coordinator (see the e2e test for the full setup)
coord = SwapCoordinator(record=SwapRecord(state=SwapState.NEGOTIATED, terms=terms),
                        counter_leg=eth_leg, radiant_leg=rxd_leg, indexer=indexer,
                        seen_store=seen, config=config)

# 1. TAKER locks the ETH first — deploys + funds the EthHtlc on Anvil, bound to H.
rec = await coord.taker_funds_btc(terms)                 # NEGOTIATED → BTC_LOCKED

# 2. MAKER locks the asset second — funds the Radiant HTLC covenant; the taker re-validates the
#    covenant SPK, the Glyph ref, and the cross-clock timelock margin before trusting it.
rec = await coord.post_asset_lock_revalidate(cov.funded_spk)   # → BOTH_LOCKED

# 3. MAKER claims the ETH — revealing p on-chain (the EthHtlc emits Claimed(p)).
rec = await coord.maker_claims_btc(p)                    # → SECRET_REVEALED

# 4. TAKER scrapes p off the maker's ETH claim and claims the Radiant asset — but only once the
#    reorg-finality gate says the ETH claim is reorg-SAFE (see "why it's trustless" below).
rec = await coord.taker_scrape_and_claim_asset(claim_tx, ...)  # → COMPLETED
```

That's it — the secret revealed on one chain settles the other, and the asset covenant is spent.

### Watch it actually settle

The end-to-end proof is wired up and maintained as an integration test — it runs this exact flow
through the real coordinator, for **three asset kinds** (native RXD, a Glyph NFT, and a Glyph FT),
against a live local Anvil + regtest node:

```console
$ XCHAIN_ETH_REGTEST=1 pytest tests/test_xchain_eth_swap_regtest_e2e.py::TestEthRxdSwap \
      -m integration -s
...
tests/test_xchain_eth_swap_regtest_e2e.py ....
======================= 4 passed in ~7s =======================
```

Three trustless cross-chain swaps — RXD, an NFT, *and* an FT — plus the mutual-refund failure
path, settling on real local ETH + Radiant consensus in **under ten seconds**, no real value at
risk. The same file also runs the **alert-only watchtower** against the swap, proving it pages the
right action at the right moment (and never pages a claim against a not-yet-final ETH reveal).

> If a prerequisite is missing (Docker, the regtest image, `anvil`, or `web3`), the test **skips**
> rather than fails — so a green/ skipped result tells you exactly what's set up.

## Why it's trustless (the safety, briefly)

The swap never asks you to trust the counterparty — it leans on each chain's consensus plus three
rules the coordinator enforces fail-closed:

- **Ordering + timelock margin.** The taker locks ETH *first*, the maker locks the asset *second*,
  and the maker reveals `p` *first*. The leg claimed second (Radiant) carries the **shorter**
  refund window, so the taker always has time to scrape `p` and claim before its own refund opens.
  The coordinator refuses to proceed unless `t_counter > t_rxd + margin`.
- **The reorg-finality gate.** The taker doesn't claim the asset the instant `p` appears — it waits
  until the ETH claim is **reorg-safe** (post-Merge `finalized`-checkpoint final, *and* the
  Radiant claim buried deep enough that reversing it would cost more than the value at stake). A
  premature reveal returns `WAIT`/`SQUEEZED`, never a silent claim.
- **No counterparty inputs trusted.** Every step re-derives the covenant, re-checks the Glyph ref,
  and reads values from on-chain truth — never from what the other party asserts.

If the maker stalls (locks the asset but never reveals `p`), nobody is stuck: after the timelocks
mature, `mutual_refund` returns both legs to their owners.

## Next steps

- **The pieces, as reference:** [build a cross-chain swap](../how-to/build-a-cross-chain-swap.md)
  — the coordinator, the legs, `MarginPolicy`, and how to add another counter-chain.
- **Other chains, no new code:** the same machinery runs against **BTC** (Taproot-HTLC) and the
  **EVM family** — Base, Optimism, Arbitrum, Linea (`pyrxd.eth_wallet.chains`). Only the per-chain
  finality window changes.
- **Two operators, for real adversarial testing:**
  [run a two-host swap dry-run](../how-to/run-a-two-host-swap-dry-run.md) splits the swap across two
  separate operators exchanging only the public envelope — the genuine adversarial exercise.
- **Before any real value:** the external security audit is the hard gate. See `SECURITY.md`.
