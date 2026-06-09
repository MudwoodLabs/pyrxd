# Same-chain partial-transaction swaps

**Audience:** developers building same-chain RXD ↔ token (or token ↔
token) trades with `pyrxd.swap` — e.g. a marketplace or an on-chain
order flow.

**Status:** the API is implemented and unit-tested (including adversarial
cases). Like every value-moving primitive in pyrxd, treat an external
audit as the gate before real-value, untrusted-counterparty use.

## What this is

A *partial-transaction swap* trades two assets atomically inside a
**single** transaction using signature-level atomicity. The maker signs
one input (the asset they give) committing to one output (the asset they
want back) with `SIGHASH_SINGLE | ANYONECANPAY`. The taker then adds
their own inputs and outputs to complete the trade and broadcasts.

Because both legs settle in one transaction, the swap is atomic: it
either confirms wholly or not at all. There is no escrow, no covenant,
and no second transaction.

```
maker input[0]  ── gives asset X ──┐         ┌── output[0]  maker receives asset Y  (SINGLE-committed)
                                   │   one    │
taker input[1+] ── funds Y + fee ──┤   tx     ├── output[1]  taker receives asset X
                                   │          ├── output[..] FT/RXD change to taker
                                   └──────────┘
```

## When to use it (vs Gravity)

| | `pyrxd.swap` (this) | [`pyrxd.gravity`](gravity.md) |
|---|---|---|
| Chains | **Same chain** (RXD ↔ RXD/token) | **Cross-chain** (RXD ↔ BTC/…) |
| Atomicity | One transaction, signature-level | HTLC (hashlock + timelock) or SPV-oracle |
| Counterparty | Maker + taker complete one tx | Two chains, two legs |

Use `pyrxd.swap` for trading assets that live on Radiant. Use Gravity
when the two assets live on different chains.

## Why it is safe

The maker's `SINGLE|ANYONECANPAY` signature is the enforcement — not the
declared terms. That signature commits to:

- the maker's **given** input: its outpoint, **value**, and locking
  script (so the given amount/asset can't be misrepresented), and
- **output[0]** only: the maker's **receive** asset and amount.

`ANYONECANPAY` lets the taker add inputs; `SINGLE` lets the taker add
outputs after index 0. Neither lets the taker alter what the maker gives
or receives without invalidating the signature.

`accept_offer` therefore, by construction:

1. reads the maker's **real** given asset from the source transaction
   (verified to hash to the input's outpoint) — never from the declared
   terms;
2. reconciles the real given/received assets against the stated
   `SwapTerms` and rejects on any mismatch;
3. **re-verifies the maker's signature** before and after completing the
   transaction;
4. derives the taker's received amount from the real given asset (there
   is no caller knob to get it wrong);
5. enforces token conservation per FT ref and returns RXD change to the
   taker.

This closes the classic footgun where a hand-rolled taker builds its
received-amount output from caller-supplied parameters and never checks
the maker's real prevout.

## Glyph FT specifics

Radiant FTs carry their amount as the output's photon value (1 photon =
1 FT unit) and their identity as a genesis ref embedded in the
[75-byte FT script](radiant-fts-are-on-chain.md). The swap API:

- treats an FT output's photons as its token amount;
- requires **ref continuity** — every FT ref in the outputs must be
  funded by an input of the same ref (the Radiant consensus rule), with
  surplus returned as FT change;
- enforces amount conservation per ref in the SDK (there is no consensus
  opcode that does this for plain transfers).

## Limitations (v1)

- **Whole-UTXO give.** The maker spends their entire given UTXO; `SINGLE`
  protects only output[0], so a maker-side change output would be
  unprotected. Pre-split the UTXO to sell a partial amount.
- **RXD and FT only.** NFTs (singletons) are out of scope.
- **Explicit fee.** `accept_offer(fee=…)` takes an absolute photon fee;
  the taker funds it.

## Minimal example

See [`examples/partial_swap_demo.py`](https://github.com/MudwoodLabs/pyrxd/blob/main/examples/partial_swap_demo.py)
for a runnable end-to-end demo (offer → transport → accept → verify),
covering an FT-for-RXD trade with conservation and change.

```python
from pyrxd.swap import Asset, FundingInput, SwapOffer, accept_offer, create_offer

# Maker: give an FT UTXO, want 800 RXD photons.
offer = create_offer(
    give_source_tx=maker_ft_source_tx,
    give_vout=0,
    maker_key=maker_key,
    receive=Asset("rxd", 800),
    maker_receive_pkh=maker_pkh,
)
payload = offer.to_dict()  # JSON-able; send over any transport

# Taker: verify + complete + sign.
tx = accept_offer(
    SwapOffer.from_dict(payload),
    funding=[FundingInput(taker_rxd_source_tx, 0, taker_key)],
    taker_receive_pkh=taker_pkh,
    taker_change_pkh=taker_pkh,
    fee=300,
)
raw = tx.serialize().hex()  # broadcast
```
