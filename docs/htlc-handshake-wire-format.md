# Cross-chain HTLC swap-handshake wire format

**Date:** 2026-08-10. **Status:** derived from the pyrxd implementation (not from a plan or a
prior doc); every normative statement below is pinned to a `file:line` or a test. Describes the
BTC↔RXD and ETH↔RXD atomic-swap negotiation as it is actually implemented.

> ## ⚠️ The stack this specifies is UNAUDITED
>
> pyrxd's cross-chain swap stack has **not had an external security audit**. It has been proven
> end-to-end on regtest and exercised with real value on mainnet, and it has survived several
> internal red-team passes — none of which is an audit. Writing this format down makes a second
> implementation *possible*; it does not make either implementation *safe*.
>
> This document is normative about **what the bytes are** and **what a receiver must check**. It
> is not an assurance argument. Where the code is weaker than a reader would assume, that is
> recorded here plainly rather than smoothed over — see the **Interop hazards** section,
> which is the most important section in this file.
>
> The stack defends **safety, not liveness**. See **Known residuals**.

## Why this exists

The swap *legs* are specified by their chains: a BIP341 Taproot HTLC on Bitcoin, a Solidity HTLC
on Ethereum, a Radiant covenant on RXD. The **negotiation that precedes them** was not specified
anywhere — it lived implicitly in `SwapCoordinator` plus a pair of operator harnesses. A second
implementation could reproduce the on-chain artifacts and still be unable to complete a swap with
pyrxd, because it could not tell which fields cross the wire, which are local policy, which are
binding, and which are decorative.

This document is the missing half. Its sibling
[`swap-order-wire-format.md`](swap-order-wire-format.md) covers the **on-chain RSWP orderbook
advertisement** — a different, unrelated format for a different, unrelated protocol (same-chain
`SIGHASH_SINGLE|ANYONECANPAY` offers). If you are looking for `OP_RETURN "RSWP"`, you want that
file. Nothing here appears on chain in an `OP_RETURN`; the handshake is an off-chain exchange of
JSON documents whose only on-chain shadow is the two scriptPubKeys both parties independently
re-derive from it.

## Source authority

| Concern | Authoritative source |
|---|---|
| The negotiated-terms object and its JSON wire form | `src/pyrxd/gravity/swap_state.py:242-415` (`NegotiatedTerms`) |
| The state machine every message drives | `src/pyrxd/gravity/swap_state.py:61-223` (13 states, 14 edges, `advance`) |
| The durable per-swap record and its schema version | `src/pyrxd/gravity/swap_state.py:39, 423-558` (`SwapRecord`) |
| Role invariant + timelock-margin rule | `src/pyrxd/gravity/swap_coordinator.py:98-109, 475-514` |
| Pre-fund validation gate (what a taker checks before locking) | `src/pyrxd/gravity/swap_coordinator.py:1195-1295` |
| Post-asset-lock revalidation (what a taker checks after the maker locks) | `src/pyrxd/gravity/swap_coordinator.py:1437-1490` |
| Preimage-length pin, BTC leg | `src/pyrxd/btc_wallet/taproot.py:281-303` (`claim_leaf_script`) |
| Preimage-length pin, Radiant leg | `src/pyrxd/gravity/artifacts/GravityHtlcCovenantRxd.artifact.json` (`OP_SWAP OP_SIZE 20 OP_EQUALVERIFY OP_SHA256 …`), and `src/pyrxd/gravity/htlc_spend.py:272-275` |
| Radiant covenant parameter binding | `src/pyrxd/gravity/htlc_covenant.py:180-200, 366-381, 487-516` |
| BTC counter-leg funding derivation | `src/pyrxd/btc_wallet/htlc_leg.py:336-362` |
| ETH counter-leg binding | `src/pyrxd/gravity/eth_leg.py:150-191`, `src/pyrxd/eth_wallet/locator.py:33-104` |
| Counter-leg locators (durable, JSON) | `src/pyrxd/btc_wallet/taproot.py:526-601`, `src/pyrxd/eth_wallet/locator.py:33-121` |
| The two shipped reference harnesses (the *de facto* handshake) | `scripts/btc_swap_two_host.py:42-59, 632-691`, `scripts/eth_swap_two_host.py:585-645` |
| Conformance vectors | `conformance/htlc-handshake-vectors.json`, guarded by `tests/test_htlc_handshake_conformance_vectors.py` |

## Roles, and the one invariant everything rests on

`swap_coordinator.py:98-109` names the invariant `MAKER_SECRET_TAKER_LOCKS_BTC_FIRST`:

- The **maker** holds the Radiant asset and wants the counter-chain value (BTC/ETH). The maker
  generates the secret `p`, publishes `H = SHA256(p)`, locks the asset, and **claims the counter
  leg first** — which is what reveals `p`.
- The **taker** holds the counter-chain value and wants the asset. The taker funds the counter-leg
  HTLC, then **claims the asset second** by scraping `p` off the maker's counter-chain claim.

Only the maker ever holds `p`. It is generated as 32 CSPRNG bytes
(`swap_coordinator.py:529`), wrapped in `SecretBytes`, and is **absent by construction** from every
serialisable type — `NegotiatedTerms`, `SwapRecord`, and both locators have no field for it
(`swap_state.py:16-19, 516-517`). The taker recovers `p` from the chain, never from a message.

## The handshake

Five artifacts cross between the two parties. Four are JSON documents; the fifth is an on-chain
transaction both sides observe. This is the entire cross-party surface — the harness docstring
states it as such (`scripts/btc_swap_two_host.py:42-50`).

| # | Message | Direction | Drives |
|---|---|---|---|
| 1 | `taker_intro` | taker → maker | (pre-FSM) |
| 2 | `envelope` | maker → taker | establishes `NEGOTIATED` |
| — | *maker funds the Radiant covenant on chain* | maker → chain | see **HZ-1** |
| 3 | `taker_funding` | taker → maker | `NEGOTIATED → BTC_LOCKED` |
| 4 | *maker locks/confirms the asset; taker revalidates* | — | `BTC_LOCKED → BOTH_LOCKED` or `→ PARAMS_MISMATCH` |
| 5 | `maker_claim` | maker → taker | `BOTH_LOCKED → SECRET_REVEALED` |

Message ordering is strict: a receiver MUST NOT accept message *n+1* before message *n*, and the
coordinator enforces this by refusing every step that is not valid from the current state
(`swap_coordinator.py:1352, 1456, 1573, 1636, 1705`).

### Envelope framing

Every message is a JSON object carrying a `schema` string:

```json
{ "schema": "btc_rxd_two_host_envelope_v1", "…": "…" }
```

| Value | Meaning |
|---|---|
| `btc_rxd_two_host_envelope_v1` | BTC counter leg (`scripts/btc_swap_two_host.py:680`) |
| `eth_rxd_two_host_envelope_v1` | ETH counter leg (`scripts/eth_swap_two_host.py:633`) |

**A conforming implementation MUST read `schema` and MUST refuse an unrecognised value**, exactly
as `gravity/watch/escalation.py:210-214` does for the watchtower heartbeat ("Refusing to guess at
the meaning of the fields"). Be aware that **the shipped harnesses do not do this** — see
**HZ-2**. The requirement is stated normatively here
because the alternative is a silent misparse of a future format.

`schema` is currently present only on `envelope`. Messages 1, 3 and 5 are bare objects. A
conforming implementation SHOULD tag all four with the same value and MUST tolerate its absence on
messages 1, 3 and 5 for compatibility with the shipped harnesses.

### 1. `taker_intro` (taker → maker)

The taker's public key material, so the maker can build the covenant and the taptree.

| Key | Type | Req. | Meaning |
|---|---|---|---|
| `taker_pkh_hex` | 40-hex | yes | Taker's Radiant pubkey-hash (20 bytes). Becomes `taker_dest_hash` via `holder_hash`. |
| `taker_btc_refund_xonly_hex` | 64-hex | BTC only | Taker's x-only key for the BTC refund leaf. |
| `eth_taker_refund_addr` | `0x`+40-hex | ETH only | Taker's address; becomes the contract's immutable `refundee`. |

Source: `scripts/btc_swap_two_host.py:435-439`, `scripts/eth_swap_two_host.py:637`.

### 2. `envelope` (maker → taker)

The core message. Carries `H` — never `p`.

| Key | Type | Req. | Binding? | Meaning |
|---|---|---|---|---|
| `schema` | string | yes | — | See framing above. |
| `terms` | object | yes | **yes** | The `NegotiatedTerms` wire form. Full table in **The `terms` object**. |
| `maker_pkh_hex` | 40-hex | yes | **yes** | Maker's Radiant pubkey-hash. Bound *transitively*: `hash256(holder(maker_pkh))` must equal `terms.maker_dest_hash`, which is baked into the covenant bytecode. |
| `covenant_spk_hex` | hex | yes | **yes** | The Radiant covenant scriptPubKey the maker will fund. The taker MUST re-derive it and compare. |
| `btc_maker_payout_spk_hex` | hex | BTC only | **no** | Where the maker sends its claimed BTC. **Advisory** — see **HZ-6**. |
| `eth_maker_claim_addr` | `0x`+40-hex | ETH only | **yes** | Becomes the contract's immutable `claimant`. Binding. |
| `eth_taker_refund_addr` | `0x`+40-hex | ETH only | **yes** | Echoed from `taker_intro`; becomes the immutable `refundee`. |
| `eth_chain_id` | int | ETH only | **not validated** | EIP-155 chain id. See **HZ-5**. |
| `btc_network` / `rxd_network` | string | yes | **not validated** | Network tags. See **HZ-5**. |

Source: `scripts/btc_swap_two_host.py:676-688`, `scripts/eth_swap_two_host.py:632-641`.

The maker MUST NOT place a private key, WIF, seed, or the preimage in this document. The harnesses
enforce this with a recursive key-name and WIF-shape scan before every write
(`scripts/btc_swap_two_host.py:118-160`); a conforming implementation SHOULD do the same, because
the failure mode is unrecoverable and silent.

### 3. `taker_funding` (taker → maker)

The funded counter-leg locator — everything needed to later claim or refund the output. Losing it
strands the funds (`taproot.py:527-532`), so it is durable state, not a transient message.

| Key | Type | Counter leg |
|---|---|---|
| `btc_locator` | object | BTC — a serialised `BtcHtlcLocator` |
| `eth_locator` | object | ETH — a serialised `EthHtlcLocator` |

`BtcHtlcLocator` (`taproot.py:572-584`): `funding_outpoint{txid,vout}`, `claim_script`,
`refund_script`, `leaf_version`, `control_block_claim`, `control_block_refund`, `internal_key`,
`amount_sats`, `network`.

`EthHtlcLocator` (`eth_wallet/locator.py:93-104`): `chain_id`, `contract_address`,
`deploy_tx_hash`, `hashlock`, `claimant`, `refundee`, `timeout`, `amount_wei`. Note the ETH
locator's `hashlock` is `0x`-prefixed (66 chars) while every hex field in `terms` is bare — a
serialiser that normalises one to the other will produce a rejected document
(`eth_wallet/locator.py:77-78`).

**A receiving maker MUST NOT trust any field of this document.** The taker controls every byte of
it and can, for example, describe a correct HTLC tree while pointing `funding_outpoint` at an
unrelated output it owns, or self-report an `amount_sats` the chain does not carry. The only safe
use is as a *pointer*: read the real output at that outpoint from a node and compare it against a
locally re-derived expectation. In this library that is
`SwapCoordinator.maker_verify_counter_funding`, which reads only the outpoint out of this document;
see **HZ-3** for what it binds and why the derivable funding *address* does not bind the *value*.

### 4. Asset lock and revalidation

Not a message: the maker funds the covenant on chain and the taker observes it. The taker MUST call
the equivalent of `post_asset_lock_revalidate` (`swap_coordinator.py:1437`), which recomputes the
expected covenant scriptPubKey from `terms` and compares it byte-for-byte against the observed one
(`:1462-1475`). Match ⇒ `BOTH_LOCKED`. Mismatch, **or an inability to recompute it**, ⇒
`PARAMS_MISMATCH` and the taker refunds the counter leg (`:1464-1469` — the unrecomputable case is
treated as a mismatch, which is the fail-closed direction).

Every negotiated Radiant parameter that is substituted into the covenant bytecode — `hashlock`,
`t_rxd`, `asset_variant`, `genesis_ref`, `radiant_amount`, `taker_dest_hash`, `maker_dest_hash` — is
revalidated by this single byte-comparison, because changing any of them changes the SPK.

**`credential_ref` is the exception, and it is a load-bearing one.** It is **not** substituted into
the covenant; no covenant builder takes a credential parameter
(`src/pyrxd/gravity/htlc_covenant.py:391-419`). A credential-gated swap and an ungated one with
otherwise identical terms produce a **byte-identical** covenant scriptPubKey — the published
`btc-rxd-credential-gated` and `btc-rxd` vectors in `conformance/htlc-handshake-vectors.json`
demonstrate exactly that, and `test_credential_gating_does_not_change_the_covenant_spk` asserts it.

The credential gate is therefore **off-chain policy, enforced before funding, by the party that
chooses to run it** — `pre_btc_lock_gate` (`swap_coordinator.py:1241-1266`) resolves the credential,
checks it is genuinely consensus-soulbound, and requires its owner to be the swap's pinned payout
(`taker_dest_hash`). It is fail-closed when a `credential_ref` is present (an unwired resolver, an
unresolvable ref, or an owner mismatch all abort), but it is a **pre-fund check, not a spending
condition**: nothing on chain stops an uncredentialed party who learns `p` and can produce the
pinned holder script from claiming. An implementer who treats the SPK byte-compare as binding the
gate has no gate at all.

### 5. `maker_claim` (maker → taker)

The maker's counter-chain claim, which reveals `p` on chain.

| Key | Type | Counter leg |
|---|---|---|
| `btc_claim_tx_hex` | hex | BTC — the raw claim transaction |
| `eth_claim_tx_hash` | `0x`-hex | ETH — the claim transaction hash |

Source: `scripts/btc_swap_two_host.py:762`, `scripts/eth_swap_two_host.py:711`.

This message is a **convenience pointer, not a channel**. `p` is public on chain the moment the
claim confirms; the taker can and should find it by watching the counter chain. A conforming taker
MUST verify, before acting on it (`swap_coordinator.py:1636-1656`):

1. `SHA256(scraped p) == terms.hashlock` — scraping is by hash over all candidate pushes, **never
   by byte offset** (`counter_chain_leg.py:93-95`);
2. **provenance** — BTC: the transaction spends *this swap's* funding outpoint
   (`swap_coordinator.py:1590-1612`); ETH: the transaction targets *this swap's* contract instance
   and emits `Claimed(p)` from it (`eth_leg.py:214-220`). Without this, a claim transaction from a
   different swap that happens to share `H` would be accepted.

## The `terms` object

The canonical wire form of `NegotiatedTerms`, produced by `to_dict` (`swap_state.py:370-395`) and
consumed by `from_dict` (`:397-415`). All hex is bare lowercase with no `0x` prefix.

| Key | Type | Req. | Constraint | Source |
|---|---|---|---|---|
| `hashlock` | 64-hex | **yes** | Exactly 32 bytes. `H = SHA256(p)`, **single** SHA256. | `swap_state.py:287`, `_b32` `:566-573` |
| `btc_sats` | int | **yes** | `> 0`. The counter-leg amount for a BTC swap. Vestigial but still required on an ETH swap. | `:288-289` |
| `radiant_amount` | int | **yes** | `> 0`. Photons (`rxd`), token units (`ft`), or carrier sats (`nft`). | `:290-291` |
| `t_btc` | `{value:int, unit:"blocks"\|"seconds"}` | **yes** | Counter-leg relative refund timelock. **Advisory on an ETH swap** — see **HZ-4**. | `:323-325` |
| `t_rxd` | `{value:int, unit:"blocks"}` | **yes** | Radiant relative refund timelock. **MUST be `blocks`** — the covenant CSV has no seconds encoding. Covenant additionally requires `1 ≤ value ≤ 0xFFFF`. | `:332-336`; `htlc_covenant.py:371-378` |
| `asset_variant` | `"rxd"\|"ft"\|"nft"` | **yes** | Selects the covenant template. | `:337-338` |
| `genesis_ref` | hex | **yes** | Reversed txid ‖ vout LE32. Produce **36 bytes** for `ft`/`nft` and **empty** for `rxd` — but see the enforcement note below; only part of that is checked at construction. | `:339-341`; `htlc_covenant.py:194-195` |
| `taker_dest_hash` | 64-hex | **yes** | 32 bytes = `hash256(taker holder script)` — **double** SHA256 of the *script*, not of the pkh. | `:342`; `htlc_covenant.py:180-200` |
| `maker_dest_hash` | 64-hex | **yes** | 32 bytes = `hash256(maker holder script)`. | `:343` |
| `btc_claim_pubkey_xonly` | 64-hex | **yes** | 32 bytes. Maker's key on the claim leaf. **MUST be 32 zero bytes on an ETH swap.** | `:347-361` |
| `btc_refund_pubkey_xonly` | 64-hex | **yes** | 32 bytes. Taker's key on the refund leaf. Same zero rule for ETH. | `:347-361` |
| `counter_chain` | `"btc"\|"eth"` | optional | **Default `"btc"`** when absent. | `:292-293, 411` |
| `value_amount` | int | conditional | Counter-leg amount in the counter chain's own unit. **Omitted when it equals `btc_sats`**; **MUST be present and > 0 on an ETH swap** (wei — the sats sentinel deliberately does not cross the unit boundary). | `:296-314, 389` |
| `eth_timeout_unix_s` | int | conditional | **Required on an ETH swap**, **forbidden on a BTC swap**. Absolute unix deadline; the contract immutable `timeout`. This is the *real* ETH counter-leg deadline. | `:315-322` |
| `credential_ref` | hex | optional | Empty or **exactly 36 bytes**. **Off-chain** soulbound-credential gate, checked before funding by `pre_btc_lock_gate`. It does **not** enter the covenant bytecode and is **not** covered by the §4 SPK byte-compare. | `:344-346`; `swap_coordinator.py:1241-1266` |

### `genesis_ref` — what is actually enforced, and where

The row above states the producer rule. The checks a *consumer* can rely on are narrower, and the
difference matters to anyone porting the validation:

| Case | Checked by | Behaviour |
|---|---|---|
| `ft`/`nft` with an **empty** `genesis_ref` | `NegotiatedTerms.__post_init__` (`swap_state.py:339-341`) | `ValidationError` at construction. This is a **non-emptiness** check only — it does not look at the length. |
| `ft`/`nft` with a **non-empty, non-36-byte** `genesis_ref` | `holder_hash` (`htlc_covenant.py:194-195`) | Constructs fine; raises `ValidationError` later, at covenant/holder-hash derivation. Fail-closed, but **deferred** — a conforming reader must not assume `len(genesis_ref) == 36` merely because `NegotiatedTerms` accepted the document. |
| `rxd` with a **non-empty** `genesis_ref` | nothing | **Accepted and silently ignored.** The `rxd` branch of `holder_hash` (`htlc_covenant.py:192-193`) returns before the length check, and the RXD covenant template carries no ref. The field round-trips through `to_dict` unchanged, so two `rxd` documents differing only in `genesis_ref` describe the same swap and derive the same covenant SPK. |

An implementation that wants the strict rule stated in the row must check it itself; pyrxd does not
reject an `rxd` swap that carries one.

### Omission and default rules — normative

`to_dict` emits the last four keys **only when they differ from the BTC defaults**
(`swap_state.py:385-394`), so an all-BTC document is byte-identical to the pre-ETH schema. A
conforming reader **MUST** apply these defaults for absent keys:

| Absent key | Default |
|---|---|
| `counter_chain` | `"btc"` |
| `value_amount` | `btc_sats` |
| `eth_timeout_unix_s` | `null` |
| `credential_ref` | empty |

An implementation that requires all keys to be present will reject every honest BTC handshake.
Locked by `test_optional_keys_are_omitted_exactly_when_default`.

### Worked example

A minimal BTC↔RXD `terms` object, from `conformance/htlc-handshake-vectors.json` (`btc-rxd`):

```json
{
  "hashlock": "c8cfe67f2d85148469f2998b7259d7cf356463c18a649c693e75f775a5259ddb",
  "btc_sats": 100000,
  "radiant_amount": 100000,
  "t_btc": { "value": 60, "unit": "blocks" },
  "t_rxd": { "value": 20, "unit": "blocks" },
  "asset_variant": "rxd",
  "genesis_ref": "",
  "taker_dest_hash": "…",
  "maker_dest_hash": "…",
  "btc_claim_pubkey_xonly": "3333…33",
  "btc_refund_pubkey_xonly": "4444…44"
}
```

## Safety-critical parameters

### Hashlock — SHA256, and the preimage is exactly 32 bytes

`H = SHA256(p)`, single SHA256, 32 bytes (`swap_coordinator.py:530`). Note that this is a
*different* hash from the dest hashes in the same object, which are `hash256` (double SHA256) —
mixing them produces an unspendable covenant.

**`p` MUST be exactly 32 bytes. This is not a convention; it is consensus-pinned on both legs.**

- BTC claim leaf: `OP_SIZE <0x20> OP_EQUALVERIFY OP_SHA256 <H> OP_EQUALVERIFY <claimPk> OP_CHECKSIG`
  (`taproot.py:281-303`). The leading three opcodes are the pin; the leaf hex begins `82 0120 88`.
- Radiant covenant claim branch: `OP_SWAP OP_SIZE 20 OP_EQUALVERIFY OP_SHA256 <hashlock>
  OP_EQUALVERIFY`, compiled into all three covenant artifacts.
- Builder-side, fail-closed before broadcast: `htlc_spend.py:272-273` (`len(preimage) != 32` ⇒
  raise) and `taproot.py:871`.

**Why the length rule is load-bearing.** A red-team pass found a preimage-length asset-theft vector
that this pin closes, and the fix comment states it directly (`taproot.py:287-290`): without the
`OP_SIZE` prefix, a malicious maker could reveal a non-32-byte `p'` with `SHA256(p') = H`. That `p'`
satisfies the hashlock, so the maker's claim succeeds — but the counterparty's witness scrape only
considers 32-byte candidates, so it silently finds nothing, never learns `p'`, and its covenant
strands until the maker's CSV refund takes it. The counterparty loses the asset having paid the
counter leg.

**A conforming implementation MUST**: pin the length in the script it builds (not only in the
builder), reject a non-32-byte `p` before broadcast, and — on the scraping side — reject rather
than accept a candidate of any other length. Silently skipping a wrong-length candidate is what
turns this into a loss. Push `0x20` *minimally* (`0120`): MINIMALDATA is a consensus rule on both
chains, and on the Radiant side a non-minimal push permanently bricks the covenant on **both**
branches — finding F-001, now guarded fail-closed at build time for values in `1..16`
(`htlc_covenant.py:268-333`, guard 3; the same reasoning on the BTC leaf at `taproot.py:287-290`).

The preimage MUST be fresh per swap and MUST come from a CSPRNG (`swap_coordinator.py:529`). `H`
reuse is separately rejected: the coordinator atomically reserves `H` in a seen-store immediately
**before** the funding broadcast, and a second funder of the same `H` is refused with nothing
broadcast (`swap_coordinator.py:1363-1375`).

### Timelock deltas — the direction is counterintuitive and inverting it loses funds

```
t_btc − t_rxd ≥ margin        (both normalised to blocks)
```

Enforced by `assert_timelock_margin` (`swap_coordinator.py:475`), in two steps:

- `swap_coordinator.py:506` — `if btc_blocks <= rxd_blocks: raise` (strict ordering)
- `swap_coordinator.py:510` — `if (btc_blocks - rxd_blocks) < margin_blocks: raise` (the margin)

**The invariant in words** (`swap_coordinator.py:106-108`): the leg claimed *second* (Radiant) has
the **SHORTER** refund window; the leg claimed *first* (the counter leg) holds the **LONGER** one.
The party who commits capital first therefore also waits longest to get it back — that asymmetry is
deliberate, and it is the direct cause of the accepted griefing residual (see
**Known residuals**).

**What breaks if it is inverted.** If `t_rxd ≥ t_btc`, the Radiant refund does not mature before the
counter-leg refund. The taker, who must claim the asset *after* the maker reveals `p`, can be left
with no window in which both "the maker has revealed" and "the maker's CSV refund has not yet
opened" hold — the maker refunds the asset out from under the pending claim while still holding a
claimable counter leg. The margin is the buffer that keeps that window open; it must cover the
counter-chain confirmation tail, the Radiant reorg depth, and the seconds↔blocks conversion slack
(`swap_coordinator.py:116-123`).

**Margin floor.** There is no protocol-mandated minimum. `margin` is **each party's own policy**,
not a negotiated field — the taker checks the maker's `terms` against the *taker's* margin and
refuses on failure (`scripts/btc_swap_two_host.py:451-457`). The shipped default is
`ESTIMATED_DEFAULT_MARGIN_BLOCKS = 36` (`swap_coordinator.py:132`), which is **labelled ESTIMATED
and is test-only**: a policy constructed with `require_measured=True` refuses to use it
(`:271-275`). A real-value swap MUST supply a margin measured from real block data
(`measure_margin_from_btc_block_times`, `:378-472`).

**Two traps.**

1. `NegotiatedTerms.__post_init__` compares `t_btc` and `t_rxd` only when they share a unit
   (`swap_state.py:364-368`). A `seconds`-tagged `t_btc` shorter than a `blocks` `t_rxd` **constructs
   without error**. Only the normalising `assert_timelock_margin` catches it. A conforming
   implementation MUST run the normalising check; the construction guard is defence in depth, not
   the safety check. Verified by `test_cross_unit_inversion_passes_construction_but_fails_the_margin_check`.
2. `t_rxd` MUST be `blocks`. A `seconds` value would be used raw as the covenant CSV operand and
   desynchronise the on-chain refund window from every off-chain gate; it is rejected at
   construction (`swap_state.py:332-336`).

### Leg addresses

There is no "address" field in `terms`. Destinations are bound in three different ways, and the
differences matter:

| Destination | How it is carried | Binding? |
|---|---|---|
| Radiant claim (pays the taker) | `terms.taker_dest_hash` = `hash256(taker holder script)` | **Consensus-bound** in the covenant; the claim's `output[0]` script must hash to it. |
| Radiant refund (pays the maker) | `terms.maker_dest_hash` | **Consensus-bound**, same mechanism. |
| BTC claim (pays the maker) | `envelope.btc_maker_payout_spk_hex` | **Not bound** — see **HZ-6**. |
| BTC refund (pays the taker) | not on the wire at all | Taker-local. Safe: it is the taker's own money returning. |
| ETH claim / refund | `envelope.eth_maker_claim_addr` / `eth_taker_refund_addr` | **Contract immutables**; verified on chain by the maker before it locks (`eth_leg.py:170-191`). |

The pkhs themselves are **not** in `terms` — only `hash256(holder(pkh))` is. The raw pkhs travel
separately, in `taker_intro.taker_pkh_hex` and `envelope.maker_pkh_hex`, so each side can rebuild
the covenant; they are bound only transitively, by recomputing
`holder_hash(pkh, variant=…, genesis_ref=…)` and comparing it to the dest hash baked into the
covenant bytecode (`htlc_covenant.py:180`; the same mechanism proves a credential's owner is the
payout recipient at `swap_coordinator.py:1257-1262`). A pkh that does not reproduce the dest hash
is rejected fail-closed when the leg builds the covenant (`radiant_leg.py:468-471`).
Holder-script layouts, from `htlc_covenant.py:168-177`:

| variant | holder script | bytes |
|---|---|---|
| `rxd` | `76a914 <pkh:20> 88ac` | 25 |
| `ft` | `76a914 <pkh:20> 88ac bd d0 <ref:36> dec0e9aa76e378e4a269e69d` | 75 |
| `nft` | `d8 <ref:36> 75 76a914 <pkh:20> 88ac` | 63 |

### Funding parameters

**The counter-leg amount is bound to the negotiated price after the lock, not before.** A P2TR
scriptPubKey commits to the taptree, not to the output value; an ETH contract address commits to
its immutables, not to its balance. So the funding-target check cannot catch a wrong amount, and a
separate check does: `funded != terms.value_amount ⇒ raise`
(`swap_coordinator.py:1389-1394`). Both under- and over-funding are rejected; over-funding is a
one-sided taker loss because the claim leaf does not cap value.

**The asset-leg amount is bound differently per variant** — and the three are not equivalent:

| variant | covenant pin on `output[0]` | Semantics |
|---|---|---|
| `rxd` | `OP_0 OP_OUTPUTVALUE <amount> OP_GREATERTHANOREQUAL OP_VERIFY` | **≥**, not equality |
| `nft` | `OP_0 OP_OUTPUTVALUE <nftCarrierValue> OP_NUMEQUALVERIFY` | exact carrier value |
| `ft` | `OP_REFVALUESUM_OUTPUTS <amount> OP_NUMEQUALVERIFY` | exact **token** sum; **no photon value is pinned at all** |

All three additionally pin `OP_TXOUTPUTCOUNT OP_1` (exactly one output) and the destination hash.
The leg re-reads the on-chain value rather than trusting a self-report, filtering the covenant UTXO
set on the expected value and failing closed on an ambiguous set (`radiant_leg.py:199-206`).

### Finality and confirmation-depth parameters

**None of these cross the wire.** Every depth, reorg, and confirmation parameter is per-party local
policy on `MarginPolicy` / `CoordinatorConfig`. Two conforming implementations can hold completely
different finality policies and still interoperate — each simply refuses at different moments. See
**HZ-7**.

The values a second implementation should know about:

| Parameter | Default | Nature | Source |
|---|---|---|---|
| `btc_claim_reorg_depth` | 6 blocks | **ESTIMATED**, test-only | `swap_coordinator.py:139, 195-197` |
| `rxd_claim_burial` | 6 blocks | **ESTIMATED**, test-only | `:144, 198-200` |
| **reorg-depth hard floor** | **2 blocks** | **not a knob** — rejected below this | `:150, 253-270` |
| **ETH finalization window floor** | **768 s** (2 post-Merge epochs) | **not a knob** | `:157, 292-304` |
| `min_ref_confirmations` | 6 | policy | `:898` |
| `min_credential_confirmations` | 6 | policy | `:917` |
| `RadiantCovenantLeg.min_confirmations` | **1** | policy — see **HZ-8** | `radiant_leg.py:400` |
| `maker_stall_safety_window_blocks` (`N`) | 6 | policy | `:893` |

The gate that consumes them, `assess_claim_finality` (`swap_coordinator.py:707`), returns
`SAFE` / `WAIT` / `SQUEEZED` and **never claims silently off a shallow reveal**. On a value-bearing
Radiant swap the coordinator additionally refuses to construct unless the burial is *value-scaled*
— `ceil(value × factor / reorg_cost_per_block)` — or the operator explicitly opts into a flat
burial for a dust run (`:1062-1077`). Both inputs are operator-supplied; there is no price or
hashrate feed in the stack.

### Fee policy

**No fee parameter crosses the wire.** `NegotiatedTerms` has no fee field, and `DeadlineFeePolicy`
has no `to_dict`/`from_dict` — it is only ever constructor-injected (`fee_policy.py:122-155`;
`radiant_leg.py:402`; `htlc_spend.py:255, 313`). Fees are node policy, not protocol.

This is worth stating explicitly because on Radiant it is unusually consequential: the chain
supports **neither RBF nor CPFP**, so an under-fee'd time-critical spend is not slow, it is
unrepairable for up to the 8-hour mempool expiry. Pre-sizing is the only control. See threat-model
[S21](threat-model.md).

## Interop hazards (read this before implementing)

These are the places where the protocol is underspecified, or where the code is weaker than its
own docstrings suggest. Each was found by reading the implementation against the spec being
written, not from a prior document. They are ordered by consequence.

### HZ-1: The shipped runbook inverts the documented lock order

`swap_state.py:151-152` and the `MAKER_SECRET_TAKER_LOCKS_BTC_FIRST` invariant both say the taker
funds the counter leg **first**. The shipped BTC runbook does the opposite: the maker funds the
Radiant covenant right after publishing the envelope (`scripts/btc_swap_two_host.py:690`), and the
taker verifies that funding is on chain **and buried** before locking any BTC
(`:503-533`). The FSM still records the taker's lock as the first transition.

The harness states its own reason (`:503-506`): *"a hostile maker who never locks RXD can wait for
our BTC HTLC and claim it with p → one-sided taker loss."* That is a correct reading of the scripts
— the BTC claim leaf is `<H> … <makerClaimPk> OP_CHECKSIG` with no precondition that the asset was
ever locked, and the maker holds both `p` and the claim key from the moment the envelope is
published. Consensus permits the claim; the FSM simply has no edge for it (from `BTC_LOCKED` the
only exits are `BOTH_LOCKED`, `ABORTED`, `PARAMS_MISMATCH` — `swap_state.py:156-160`), and
`maker_claims_btc` refuses it only for an *honest* maker driving its own coordinator
(`swap_coordinator.py:1573-1574`). A hostile maker does not use a coordinator.

**Normative:** a taker MUST NOT fund the counter leg until it has confirmed the maker's asset lock
on chain, at the agreed scriptPubKey, for the agreed value, at a depth the taker chose. The FSM's
nominal ordering is a bookkeeping order, not a safety guarantee. Do not read "taker locks first" as
permission to lock first.

**What the library enforces (added after this hazard was written).** The rule above was normative
and *unimplemented*: the check lived only in the two operator scripts, so a caller driving
`SwapCoordinator` directly got `pre_btc_lock_check(...) -> ok=True` and `taker_funds_btc(...) ->
BTC_LOCKED` having invoked **zero** methods on the Radiant leg. It is now step 5 of the gate:

- **`RadiantCovenantLeg.verify_maker_asset_funded(terms, *, min_confirmations=None)`** re-derives the
  covenant scriptPubKey from the **taker's own `terms`** (never anything the maker advertises),
  locates its funded UTXO, binds the **on-chain value to `terms.radiant_amount` exactly**, and
  requires a confirmation depth. "Funded" alone is not enough — ElectrumX `listunspent` includes
  mempool outputs, so a maker can fund with a replaceable transaction, wait for the lock, then
  double-spend the funding away.
- **`SwapCoordinator.taker_verify_asset_funding`** is the entry point, run inside
  `pre_btc_lock_check` and **re-run inside `taker_funds_btc`** immediately before the counter-leg
  broadcast — that re-run is what closes the verify→lock TOCTOU. It sits *before* the `SeenStore`
  reserve, so the reserve keeps its "last step before the only broadcast" property (TOCTOU-1) and a
  refusal does not burn `H`.
- **Depth pin from existing policy:** a real-value (`MarginPolicy.is_measured`) swap requires
  `rxd_claim_burial` confirmations — the same depth the claim-finality gate requires of the taker's
  own Radiant claim. An estimated/test policy defers to the leg's `min_confirmations`.
- **Fail-closed everywhere:** an unfunded SPK, a mis-valued or ambiguous covenant UTXO, a shallow
  funding, an unreachable node, and a `radiant_leg` that does not implement the read all refuse.

Both operator scripts now call the library rather than their own copy, so there is one
implementation. Threat model: [S24](threat-model.md). Tests:
`tests/test_taker_asset_funding_gate_adversarial.py`.

The FSM ordering is left as-is deliberately: it records *transitions*, and the safety requirement is
a precondition on the taker's transition, not a different edge. **Note for anyone driving the
coordinator:** the maker's covenant must be funded and buried before `taker_funds_btc` is called.
The `-m integration` end-to-end suites still fund the covenant *after* that call (the pre-HZ-1
order) and must be reordered before they will pass — see the CHANGELOG entry.

### HZ-2: The version tag is written but never read

The two envelope schema strings appear at exactly four sites, all of them **writes**
(`scripts/btc_swap_two_host.py:680, 826`; `scripts/eth_swap_two_host.py:633, 838` — the second of
each pair is the offline self-check fixture). No code path reads or validates the field: the taker
phases go straight to `env["terms"]`. Worse, `NegotiatedTerms` itself has **no version field at
all** — the only
`SWAP_RECORD_SCHEMA_VERSION` (`swap_state.py:39`) versions the *durable record*, and is emitted only
when the counter leg is ETH (`:530-535`).

Compounding it: `NegotiatedTerms.from_dict` reads named keys and **silently ignores anything else**
(`swap_state.py:397-415`; verified by `test_from_dict_silently_ignores_unknown_keys`). Combined with
the optional-key omission rules, a receiver cannot distinguish "the sender omitted this because it
holds the default" from "the sender is a newer version and meant something I cannot see."

**Consequence:** there is no mechanism by which a receiver can detect that a sender meant something
it does not understand. Every safety property therefore rests on the fields that are
**independently re-derived and byte-compared** — the BTC funding scriptPubKey and the Radiant
covenant scriptPubKey — and not on the envelope. Anything not covered by one of those two
comparisons is, in effect, unauthenticated.

**Normative:** validate `schema` and fail closed on an unknown value. If you extend `terms`, put
the new field inside one of the two re-derived commitments, or it is not binding.

### HZ-3: The maker-side BTC funding check — CLOSED in the library

> **Status: fixed.** This section previously documented an open hole. It now documents what the
> library enforces; the historical framing is kept because the *reasoning* that produced the hole is
> the part worth not repeating.

**What the hole was.** `SwapCoordinator.maker_verify_counter_funding` used to **refuse a BTC counter
leg outright**, on the stated grounds that "a BTC counter leg's funding target is a pure function of
terms, so the coordinator's `derive==promised` pre-fund gate + the funding reader already bind it."
That reasoning does not hold, for two reasons:

- the `derive==promised` gate runs on the **taker's** side, inside the taker's own funding step, so a
  hostile taker simply does not run it; and
- it is a tautology anyway — see **HZ-4b**.

The only BTC maker-side binding was `_maker_verify_btc_funding`, in a **script**
(`scripts/btc_swap_two_host.py`). So an implementation built against `pyrxd.gravity.SwapCoordinator`
alone had **no maker-side check that the taker funded the right HTLC with the right amount** on a
BTC swap. Two outcomes, both real:

- *Wrong/absent HTLC* → the maker locks the asset, cannot claim the BTC (its signature does not
  satisfy a taptree it did not expect), never reveals `p`; both sides refund at their timelocks.
  Capital lockup, no theft — the griefing residual, from the maker's side.
- *Correct HTLC, under-funded* → the maker locks the asset, claims the under-funded BTC (revealing
  `p`), and the taker claims the asset. **The maker is paid less than the agreed price.** A real,
  bounded, one-sided maker loss — and the coordinator's own amount bind does not catch it, because
  that check runs inside `taker_funds_btc`, i.e. on the honest taker's own leg. A P2TR scriptPubKey
  commits to the taptree, **not to the output value**, so every SPK-derivation check in the
  handshake passes on an HTLC funded short.

**What the library now enforces.** The check moved out of the script and into the library, with one
implementation:

- `BitcoinTaprootLeg.verify_counterparty_funded(funding_ref, terms, *, min_confirmations=None)` reads
  the output at the counterparty's advertised outpoint **authoritatively from the chain** (a
  confirmed, unspent output — a spent/unconfirmed/unknown one raises) and asserts, all fail-closed:
  its **scriptPubKey** equals the HTLC re-derived from the maker's own `terms`; its **value equals
  `terms.value_amount` exactly** (over-funding is rejected as well as under-funding, matching the
  taker-side bind — the claim leaf does not cap value, so an over-funded HTLC is a one-sided *taker*
  loss); and it is buried `min_confirmations` deep. The returned locator is rebuilt from the leg's
  own derivation, so nothing counterparty-supplied survives into the maker's claim.
- `SwapCoordinator.maker_verify_counter_funding` now **accepts a BTC counter leg** and dispatches to
  it. The one untrusted input the maker passes is the funding **outpoint** (a `BtcOutpoint`, a
  `BtcHtlcLocator` whose outpoint alone is read, or `"<txid>:<vout>"`).
- `SwapCoordinator.post_asset_lock_revalidate` makes it **non-skippable on both chains**: it requires
  a verified locator on the record and **re-runs** the verification at asset-lock time before it will
  advance to `BOTH_LOCKED` (the state that enables the `p` reveal). Re-running is what closes the
  verify→lock TOCTOU — a reorg, or a taker who funds only after the maker looked, is caught there.
- The depth pin reuses the policy's existing reorg knob rather than inventing a second notion of BTC
  finality: a real-value (`MarginPolicy.is_measured`) swap requires `btc_claim_reorg_depth`
  confirmations; an estimated/test policy defers to the leg's `min_confirmations`. This is the BTC
  analogue of the ETH gate's `block_identifier='finalized'` pin, and the same `is_measured`
  discipline the N-floor and the cross-clock margin already use. PoW finality *is* a depth (see
  `gravity/finality.py`).
- A funding reader that cannot report a confirmed output's scriptPubKey + value, a counter leg with
  no `verify_counterparty_funded`, a missing locator, and an unreachable node all **refuse the lock**.

Adversarial coverage: `tests/test_btc_maker_counter_funding_adversarial.py` (under-funded,
over-funded, decoy scriptPubKey, shallow, spent, verified-then-reorged, and the fail-closed plumbing).

**Normative (unchanged, and now what the library does):** before locking the asset on a BTC swap, a
maker MUST read the output at the taker's advertised outpoint from a node it trusts, and MUST assert
its scriptPubKey equals the locally re-derived HTLC scriptPubKey, its value equals
`terms.value_amount`, and it is unspent and buried to the maker's chosen depth. On any failure: do
not lock. A second implementer MUST NOT infer from "the BTC funding address is derivable from terms"
that the funding is therefore bound — the address is bound; the **value** is not.

### HZ-4: `t_btc` is required on an ETH swap and means nothing

On an ETH swap `t_btc` must still be supplied, must still be a `Timelock`, and must still exceed
`t_rxd` (`swap_state.py:323-325, 364-368`) — but the real deadline is the absolute
`eth_timeout_unix_s`, and the ETH leg **explicitly ignores** the relative timelock the coordinator
passes to `refund` (`eth_leg.py:196-199`). The pre-fund ordering gate correctly routes ETH swaps to
a different, cross-clock check (`swap_coordinator.py:1279-1282, 1297-1328`) rather than
`assert_timelock_margin`.

**Normative:** on an ETH swap, treat `t_btc` as a required placeholder with no on-chain meaning. Do
not derive a refund from it, and do not validate the ETH leg against it. Validate
`eth_timeout_unix_s`.

#### HZ-4b: The `derive==promised` gate is a tautology

Step 4 of the pre-fund gate compares `derive_funding_scriptpubkey(terms)` with
`promised_funding_scriptpubkey(terms)` (`swap_coordinator.py:1286-1293`), and the docstring calls
this "maker-**promised** params match the locally re-derived BTC funding SPK" (`:1210`). On both
shipped legs the two methods call the same function on the same input:

- BTC — `htlc_leg.py:350-362`, both return `self._htlc(terms).scriptpubkey`; the docstring at
  `:356-360` says so plainly ("there is no separate maker-side derivation").
- ETH — `eth_leg.py:90-94`, both return `self._commitment(terms)`, computed from the leg's *own*
  local `claim_to`/`refund_to`/`timeout`.

There is no independently-transmitted "promised scriptPubKey" anywhere in the handshake. The check
is a self-consistency assertion that would catch an internal derivation bug; it is **not** a
counterparty check. A second implementer who reads it as "the maker's claim is verified here" will
omit the checks that actually bind.

### HZ-5: Network identity is carried but never checked

`envelope` carries `btc_network`, `rxd_network` and (ETH) `eth_chain_id`
(`scripts/btc_swap_two_host.py:684-685`, `scripts/eth_swap_two_host.py:638-639`), but no reader
compares them to its own configuration — the taker phases read `maker_pkh_hex`,
`covenant_spk_hex` and the payout fields and nothing else. `terms` carries no network at all, and
`BtcHtlcLocator.network` defaults to `"bc"` (`taproot.py:540`).

This matters more than it looks, because **a P2TR scriptPubKey is network-independent**: the same
`terms` derive byte-identical funding output on mainnet, testnet and regtest — only the bech32 HRP
in the address differs. Two parties can therefore agree a complete, internally-consistent `terms`
object while operating on different networks. The failure is discovered only when one side cannot
find the other's funding, i.e. after at least one lock.

**Normative:** validate `btc_network` / `rxd_network` / `eth_chain_id` against local configuration
before acting on `terms`, and refuse on mismatch. Do not rely on the derived scriptPubKey to
distinguish networks; it cannot.

### HZ-6: The BTC payout SPK is advisory; the ETH one is binding

`envelope.btc_maker_payout_spk_hex` is **not committed to anywhere**. The BTC claim leaf is
`… <claimPk> OP_CHECKSIG` (`taproot.py:294-303`) — a bare signature check with no output
restriction, so the maker may send its claimed BTC anywhere. The field exists so each side can
construct its leg object; it is not a promise.

The ETH equivalents are the opposite: `claimant` and `refundee` are contract immutables, and the
maker verifies them on chain against its *own* expectation before locking (`eth_leg.py:150-191`).

**Normative:** do not treat `btc_maker_payout_spk_hex` as binding, and do not build a safety
argument on it.

### HZ-7: Finality policy is unnegotiated and unnegotiable

No confirmation depth, reorg depth, burial, or margin appears in any message. Each party applies
its own. This is a deliberate design choice — a counterparty-supplied safety parameter would be
worthless — but it has an interop consequence the handshake gives no way to express: two
conforming implementations can hold irreconcilable policies and discover it only as an unexplained
stall (one side waiting for depth the other considers unnecessary). There is no field in which to
say "I will require 6 confirmations", and no message with which to renegotiate.

**Normative:** publish your depth requirements out of band, and size `t_rxd`/`t_btc` for the
*counterparty's* worst plausible policy, not your own.

### HZ-8: The library default accepts a 1-confirmation covenant

`RadiantCovenantLeg(min_confirmations=1)` is the constructor default (`radiant_leg.py:400`). The
harness threads an operator flag into it and defaults that to 1 as well, with the flag's own help
text warning that real value must set it deep (`scripts/btc_swap_two_host.py:939-944`). A
shallow or mempool-only covenant funding is replaceable/reorgable: a maker who double-spends it
after the taker has locked strands the taker's counter leg.

**Normative:** set a depth appropriate to the value at risk. Do not ship the default.

## The state machine

The FSM is the pure, exhaustively-tested core: 13 states, 14 edges, in `swap_state.py:61-184`.
`advance(state, event)` raises on any undefined `(state, event)` pair and on any transition out of
a terminal state — an undefined edge is a bug, never a no-op (`:208-223`).

| From | Event | To | Driven by |
|---|---|---|---|
| `NEGOTIATED` | `TAKER_FUNDS_BTC` | `BTC_LOCKED` | message 3 |
| `NEGOTIATED` | `TAKER_NEVER_FUNDS` | `ABORTED` *(terminal)* | timeout |
| `BTC_LOCKED` | `MAKER_LOCKS_ASSET` | `BOTH_LOCKED` | step 4, SPK match |
| `BTC_LOCKED` | `MAKER_LOCKS_WRONG_PARAMS` | `PARAMS_MISMATCH` | step 4, SPK mismatch |
| `BTC_LOCKED` | `MAKER_NEVER_LOCKS_BTC_TIMEOUT` | `ABORTED` *(terminal)* | `t_btc` elapsed |
| `PARAMS_MISMATCH` | `TAKER_REFUNDS_BTC` | `ABORTED` *(terminal)* | taker refund |
| `BOTH_LOCKED` | `MAKER_CLAIMS_BTC_REVEALS_P` | `SECRET_REVEALED` | message 5 |
| `BOTH_LOCKED` | `MAKER_STALL_DETECTED` | `MAKER_STALLS` | stall trigger |
| `BOTH_LOCKED` | `BOTH_TIMEOUTS_ELAPSE` | `MUTUAL_REFUND` *(terminal)* | the safe failure |
| `MAKER_STALLS` | `TAKER_REFUNDS_ASSET_PROACTIVELY` | `ASSET_REFUNDED_TAKER_ACTS` *(terminal)* | maker-only primitive |
| `SECRET_REVEALED` | `TAKER_SCRAPES_P_CLAIMS_ASSET` | `COMPLETED` *(terminal)* | reorg gate `SAFE` |
| `SECRET_REVEALED` | `TAKER_OFFLINE_OR_PINNED` | `ASSET_VULNERABLE` | reorg gate `SQUEEZED` |
| `ASSET_VULNERABLE` | `TAKER_SCRAPES_P_CLAIMS_ASSET` | `COMPLETED` *(terminal)* | deliberate winner-take-all |
| `ASSET_VULNERABLE` | `MAKER_REFUNDS_ASSET_CSV` | `ONE_SIDED_LOSS_TAKER` *(terminal)* | the R1 residual |

Terminal states: `COMPLETED`, `MUTUAL_REFUND`, `ABORTED`, `ASSET_REFUNDED_TAKER_ACTS`,
`ONE_SIDED_LOSS_TAKER` (`swap_state.py:102-110`).

Notes a second implementation needs:

- The reorg gate's `WAIT` verdict is **not** a transition. The record stays `SECRET_REVEALED` and
  the caller retries; no state is stranded because the gate runs before any advance
  (`swap_coordinator.py:1733-1739`).
- `ASSET_REFUNDED_TAKER_ACTS` is reached by a **maker-only** primitive. The covenant's CSV refund
  pays the *maker* in both directions, so a taker that runs it gifts the asset back and destroys
  its only recourse; the coordinator forbids it for a `TAKER`-role instance
  (`swap_coordinator.py:1910-1915`). **The taker's stall recovery is `mutual_refund`.**
- Durable state MUST be persisted before an awaited broadcast and the post-broadcast write
  shielded from cancellation, or a retry double-funds (`swap_coordinator.py:1179-1192, 1358-1400`).

## Known residuals

This format does not close, and cannot close, the following. All are documented in
[`threat-model.md`](threat-model.md).

- **S22 — capital-lockup griefing. REAL and ACCEPTED.** A counterparty can repeatedly open swaps,
  let you lock capital, and simply never lock their own leg. You are made whole at your timelock;
  they spend nothing and never transact, so there is nothing to observe or slash. **pyrxd's swap
  stack defends SAFETY, not LIVENESS.** It will not let a counterparty take your funds; it will not
  stop one immobilising your capital for a timelock at near-zero cost. Do not read this document
  as promising griefing resistance. A bond was considered and deliberately not built — full
  reasoning and the revisit trigger in
  [`solutions/design-decisions/griefing-is-a-liveness-residual-not-a-bond.md`](solutions/design-decisions/griefing-is-a-liveness-residual-not-a-bond.md).
- **S20 — the HTLC free option. REAL and ACCEPTED.** If the taker is offline, pinned, or censored
  across the window from the maker's reveal to `t_rxd`, the maker CSV-refunds the asset and holds
  both legs. Bounded by the margin, the reorg gate, and the value-scaled burial; not eliminated. It
  is inherent to the reveal-on-the-long-leg shape, not a pyrxd defect.
- **S21 — under-fee'd time-critical spends are unrepairable.** Radiant has neither RBF nor CPFP, so
  a claim or refund below the effective relay floor cannot be bumped and squats on its own inputs
  for up to 8 hours. Fee pre-sizing is the only control, and it is local, not negotiated.
- **S10 — Gravity covenant bugs.** The threat model records this as the most concentrated risk in
  the codebase and an audit-recommended target.
- **No external audit.** The gate before relying on this for non-dust value is an external audit
  plus a genuine two-party adversarial run, not a passing conformance suite.

## Conformance vectors

`conformance/htlc-handshake-vectors.json` (`schema: "radiant-htlc-handshake/1"`), guarded by
`tests/test_htlc_handshake_conformance_vectors.py` — 51 checks over five `terms` vectors (rxd / ft
/ nft on BTC, rxd on ETH, and a credential-gated variant), three preimage-length vectors, and four
margin verdicts.

Each `terms` vector publishes the exact wire object plus the two artifacts a counterparty
independently re-derives from it: the BTC P2TR funding scriptPubKey (with its taptree leaf scripts
and address) and the Radiant covenant scriptPubKey. Build both from `terms` and byte-compare; that
is the whole interop test.

pyrxd is the reference **producer** here, so a green run is a regression lock, not independent
validation — and there is no mainnet-anchored vector yet (tracked follow-up). See
`conformance/README.md` for the suite conventions.

One published fact is worth reading before you build anything: the `btc-rxd`, `btc-ft` and
`btc-nft` vectors differ in `asset_variant`, `genesis_ref`, `radiant_amount` and both dest hashes,
and derive the **identical** BTC funding address. The BTC taptree commits to `H`, the two x-only
keys and `t_btc` — and to nothing at all on the Radiant side. Verifying the counter leg therefore
tells you nothing about which asset you are buying. Only the covenant scriptPubKey comparison does.
Locked by `test_btc_funding_spk_does_not_bind_the_asset_side`.

The preimage in the vectors is a fixed 32-byte ASCII string, deliberately not CSPRNG output, so
that no conformance file ever carries a value capable of opening a funded HTLC.
