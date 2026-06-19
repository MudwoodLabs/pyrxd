# Run a two-host ETH↔RXD swap dry-run

Every swap run shipped so far has been **single-process**: one program plays *both*
the maker and the taker, holding every key and the preimage `p` in one address space.
That proves the plumbing — the legs broadcast, the FSM advances — but it does **not**
exercise the one property an atomic swap exists for: safety against a *hostile,
untrusted counterparty*. As long as one process holds all the keys, the "counterparty
verification" steps are checking the program against itself.

This runbook drives `scripts/eth_swap_two_host.py`, which **splits the existing flow
across two operators on two hosts**. Each operator holds only their own keys and sees
only the **public negotiation envelope** (plus a couple of public locators), copied
between the hosts out-of-band. It is the first real exercise of untrusted-counterparty
verification — and it is the *prep* for a genuine two-party adversarial run, not the
run itself.

> **Regtest / testnet exercise — unaudited swap stack.** This is the same HTLC swap primitive
> described in [Build a cross-chain atomic swap](build-a-cross-chain-swap.md): open-source,
> provided as-is, and not externally audited — **verify it yourself before moving real value.**
> RXD runs on a Radiant **regtest** node; ETH runs on a local **anvil** or **Sepolia** (free
> testnet). This harness has no mainnet wiring — you pass `--audit-cleared` even to *name*
> Sepolia, an explicit opt-in for the value-bearing testnet. It's a two-party learning /
> validation exercise.

For the model behind the steps — the maker/taker roles, the `H = SHA256(p)` hashlock, and
the `t_counterchain > t_rxd + margin` safety invariant — read
[Build a cross-chain atomic swap](build-a-cross-chain-swap.md) first. This page is the
operational *how*; that page is the *why*.

## What stays local vs. what crosses between hosts

The whole point of the split is **key isolation**:

| Operator | Holds locally (NEVER copied to the other host) |
|---|---|
| **Maker** | the preimage `p`; the maker's RXD refund key; the maker's ETH claim key |
| **Taker** | the taker's RXD claim key; the taker's ETH funding key |

Each role persists its private state to a **mode-600 local file** (`--local-out`, default
`.<role>_local_secret.json` inside the io dir) that is *not* part of the exchange channel.

The **entire** cross-host surface is four JSON files copied out-of-band (scp, a USB stick,
a paste — anything; the harness never networks them itself). All four are **public**: the
preimage `p` is never serialised into any of them. The writer asserts this fail-closed —
it refuses to write a file whose keys look like a secret (`preimage`, `wif`, `secret`, …).

| # | File | Direction | Contents (all public) |
|---|---|---|---|
| 1 | `taker_intro.json` | taker → maker | the taker's RXD pubkey-hash + ETH addresses |
| 2 | `envelope.json` | maker → taker | the `NegotiatedTerms` (hashlock **H** only), the maker's public ETH/RXD payout config, and the funded covenant SPK |
| 3 | `taker_funding.json` | taker → maker | the funded ETH HTLC locator (`EthHtlcLocator` — carries H, never p) |
| 4 | `maker_claim.json` | maker → taker | the maker's ETH claim **tx hash** (the taker scrapes `p` from that tx **on-chain**, never from this file) |

## The envelope (`envelope.json`)

The envelope is `NegotiatedTerms.to_dict()` plus the maker's public payout config. Its
exact fields:

- `terms.hashlock` — **H = SHA256(p)** (the *only* secret-derived value; `p` is absent)
- `terms.btc_sats` / `terms.radiant_amount` — the RXD amount (photons)
- `terms.t_btc` / `terms.t_rxd` — the two refund timelocks (the margin invariant lives here)
- `terms.asset_variant` (`"rxd"`), `terms.genesis_ref` (empty for plain RXD)
- `terms.taker_dest_hash` / `terms.maker_dest_hash` — the covenant holder bindings
- `terms.counter_chain` (`"eth"`), `terms.value_amount` (wei), `terms.eth_timeout_unix_s`
- `maker_pkh_hex` — the maker's RXD pubkey-hash (public; needed to re-derive the covenant)
- `eth_maker_claim_addr` / `eth_taker_refund_addr` — the ETH payout addresses
- `eth_chain_id`, `rxd_network`, `covenant_spk_hex` — the SPK the maker will fund

There is **no preimage field** anywhere in the schema. The taker independently re-derives
the covenant SPK from the public terms and **refuses** to proceed if it does not match the
maker's advertised `covenant_spk_hex`.

## Before you start

- A **Radiant regtest** node reachable over ElectrumX/Fulcrum (`--rxd-electrumx-url`), with
  the covenant-funding and fee UTXOs in a regtest wallet. See the
  [quickstart](../tutorials/quickstart.md) for `pyrxd regtest setup` / `up`.
- An **ETH endpoint**: a local `anvil` (`--eth-chain-id 31337`) or **Sepolia**
  (`--eth-rpc-url …`, plus `--audit-cleared` to opt in to the value-bearing testnet run).
- Each operator funds their **own** regtest fee UTXO (the covenant output carries the asset
  and cannot also pay the miner fee). Pass it per role via
  `--fee-txid/--fee-vout/--fee-value/--fee-spk-hex/--fee-wif`. The WIF stays local — it is
  never written into an exchange file.
- A shared **io directory** (`--io`). On two real hosts this is a *per-host* directory; you
  copy the four files between them in the order below.

## Validate the seam first (no chain)

Before touching any chain, run the offline self-check. It exercises the security-critical
seam end-to-end: the maker assembles + serialises the envelope, the taker reads it back,
re-derives the covenant, runs the **independent** margin check, and the harness asserts `p`
never appears in any serialised artifact — and that the margin check *rejects* a hostile
too-tight envelope.

```console
$ python scripts/eth_swap_two_host.py --self-check
=== two-host swap PREP self-check (NO chain) ===
  [ok] envelope serialises H only — no p, no WIF
  [ok] the serialiser guard REJECTS a doc carrying a preimage/secret key
  [ok] taker re-derives the SAME covenant SPK from the envelope's public terms
  [ok] taker's INDEPENDENT timelock-margin check passes for honest terms
  [ok] taker REFUSES a hostile too-tight envelope
  SELF-CHECK PASSED …
```

## The two-host run, step by step

Each numbered step is one command on one host. Between steps, copy the named file to the
other host's io directory **in this order** — the next step refuses to run until its input
file is present.

The harness `confirm`s before **every** irreversible broadcast (type `broadcast` to
proceed; anything else aborts). `--yes` bypasses confirmation for an unattended run — use
it only when you know exactly what you are signing up for.

**1. Taker — publish intro.** The taker generates its own RXD + ETH keys, persists them
locally (mode 600), and publishes only the *public* half.

```console
taker$ python scripts/eth_swap_two_host.py --role taker --phase intro \
    --io ./swapdir \
    --eth-taker-addr 0x<taker-eth-addr> --eth-maker-addr 0x<maker-eth-addr> \
    --eth-key-hex <taker-eth-key>
# → writes taker_intro.json   (copy it to the maker's host)
```

**2. Maker — assemble + publish the envelope.** The maker generates `(p, H)`, reads
`taker_intro.json`, builds the covenant + terms, persists `p` to its *local* mode-600 file,
and publishes `envelope.json`. The maker prints the **covenant SPK to fund**.

```console
maker$ python scripts/eth_swap_two_host.py --role maker --phase envelope \
    --io ./swapdir \
    --eth-maker-addr 0x<maker-eth-addr> --eth-key-hex <maker-eth-key> \
    --rxd-photons 100000 --t-rxd-blocks 60 --margin-blocks 36
# → writes envelope.json   (copy it to the taker's host)
```

**3. Taker — verify the margin, fund the ETH HTLC, publish the locator.** The taker reads
the envelope, runs its **independent** `assert_timelock_margin` check (refusing if
`t_eth − t_rxd < margin`), re-derives the covenant SPK and checks it matches, then **funds
the ETH HTLC first** (claim pays the maker, refund pays the taker) and publishes the
funding locator.

```console
taker$ python scripts/eth_swap_two_host.py --role taker --phase fund \
    --io ./swapdir \
    --eth-rpc-url <sepolia-or-anvil> --eth-key-hex <taker-eth-key> --audit-cleared \
    --rxd-electrumx-url ws://<regtest-electrumx> \
    --fee-txid <…> --fee-vout <…> --fee-value <…> --fee-spk-hex <…> --fee-wif <…>
# → writes taker_funding.json   (copy it to the maker's host)
```

**4. Maker — verify the ETH HTLC, lock RXD, claim ETH (reveal p).** The maker verifies the
taker's on-chain ETH HTLC binds to terms (`claimant == maker`, `refundee == taker`, H,
timeout, funded) **before** locking anything. Then the maker funds the RXD covenant SPK on
regtest (the harness pauses for you to do this and confirm ≥ 1 conf), the coordinator
re-validates pinned to finality, and finally the maker **claims the ETH — revealing `p`
on-chain**. The claim tx hash is published.

```console
maker$ python scripts/eth_swap_two_host.py --role maker --phase lock-claim \
    --io ./swapdir \
    --eth-rpc-url <sepolia-or-anvil> --eth-key-hex <maker-eth-key> --audit-cleared \
    --rxd-electrumx-url ws://<regtest-electrumx>
# → writes maker_claim.json   (copy it to the taker's host)
```

**5. Taker — scrape p, claim the RXD covenant.** The taker reads the maker's claim tx hash,
**scrapes `p` from that transaction on-chain** (never from a file), runs the reorg-finality
gate, and claims the RXD covenant before its CSV refund window opens.

```console
taker$ python scripts/eth_swap_two_host.py --role taker --phase claim \
    --io ./swapdir \
    --eth-rpc-url <sepolia-or-anvil> --eth-key-hex <taker-eth-key> --audit-cleared \
    --rxd-electrumx-url ws://<regtest-electrumx> --asset-locked-at-height <rxd-height> \
    --fee-txid <…> --fee-vout <…> --fee-value <…> --fee-spk-hex <…> --fee-wif <…>
# → on SAFE: claims the covenant → COMPLETED (the swap is done)
```

## The safety checks you are actually exercising

- **The taker independently verifies the margin.** Step 3 runs `assert_timelock_margin`
  against the envelope alone, with the taker's *own* policy — a hostile maker who sets a
  too-tight RXD refund (or too-loose ETH timeout) is rejected *before* the taker funds.
- **The taker re-derives the covenant.** The taker never trusts the maker's advertised SPK;
  it rebuilds it from the public terms and refuses on a mismatch.
- **The maker verifies the counter-leg before locking.** Step 4 runs
  `maker_verify_counter_funding` (and re-runs it pinned to finality at RXD-lock time) — a
  hostile taker who deploys `claimant = self` or underfunds cannot make the honest maker
  lock the asset for nothing.
- **`p` only ever appears on-chain.** It crosses the seam exactly once — when the maker's
  ETH claim reveals it on Ethereum — and the taker reads it from there.

## Recovery (if the maker stalls)

If the maker locks RXD but never claims the ETH (a griefing / free-option attack), `p` is
never revealed. The correct recovery is **`mutual_refund` after BOTH timeouts elapse**:
the taker's ETH refunds to the taker and the RXD covenant CSV-refunds to the maker, so
neither side takes a one-sided loss. Do **not** walk away before both refunds confirm, and
do **not** use the maker-stall asset-refund primitive as the taker (it strands you — the
maker owns the RXD covenant in this runbook). This recovery driver is not yet wired into
this prep harness; until it is, recover manually with the coordinator surface described in
[Build a cross-chain atomic swap](build-a-cross-chain-swap.md).
