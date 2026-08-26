---
title: The USDC corridor is issuer-trusted, not trustless — and must never be described otherwise
status: accepted residual
date: 2026-08-23
category: design-decisions
related_files:
  - src/pyrxd/eth_wallet/erc20_leg.py (the pre-reveal freeze gate, inside claim)
  - src/pyrxd/eth_wallet/erc20.py (is_blacklisted, assert_not_frozen_before_reveal)
  - pyrxd-eth-htlc contracts/src/Erc20Htlc.sol (the FREEZE note)
---

## TL;DR

RXD/Glyph ↔ USDC swaps use the same HTLC protocol as RXD ↔ ETH, but **not the same guarantee**.
Native ETH is held by the EVM; USDC is held by a contract whose issuer can freeze addresses. That
puts a third party inside a two-party protocol, and it is not fixable in code — only bounded and
disclosed. **Do not market this corridor as trustless.**

## The measured facts

Measured on a mainnet fork at block 25,815,805 against the real USDC proxy, impersonating the live
blacklister `0x0a06be16…78f9` (`pyrxd-eth-htlc` `test/Erc20HtlcSpike.t.sol`):

| what is frozen | claim | refund | recoverable? |
|---|---|---|---|
| the claimant | reverts | works | yes — refund after timeout |
| the refundee | works | reverts | yes — claim still pays |
| **the HTLC contract** | **reverts** | **reverts** | **NO — funds stranded permanently** |

The third row is the one that matters. No timeout rescues it. The funds are simply gone.

Context, not speculation: Circle has frozen roughly $110M across ~500 addresses, and the 2025
GENIUS Act *mandates* freeze capability for US issuers. This is a designed-in feature of the asset,
not a hypothetical.

## What the guarantee actually is

The native corridor's promise — *"if either party walks away, both can refund after their
timelock"* — holds unconditionally, because nobody can stop an ETH transfer.

The USDC corridor's promise is the same sentence **plus "…unless the issuer intervenes."** That is
strictly weaker, and the difference is not a rounding error: it converts an unconditional refund
right into a conditional one.

## What is done about it

Three things, none of which is a fix:

1. **Per-swap contracts.** One fresh CREATE address per swap, so a contract freeze loses exactly
   one swap. A shared multi-swap HTLC would be a single freeze-point for every swap at once — this
   is the security argument for the topology, and it is why the sibling repo's shared
   `HashedTimelock` was **not** adopted.
2. **A pre-reveal gate, inside `claim`.** Blacklist status for the contract and the **claimant**
   is checked at the **tip** immediately before the reveal. It lives inside the dangerous operation
   rather than beside it, because a gate a caller must remember to invoke eventually is not
   invoked — which is exactly what happened for a full review cycle.

   The **refundee is deliberately not checked here**, and an earlier revision of this page said it
   was. A `claim` sweeps the contract to the claimant; the refundee is touched only by `refund()`,
   so a frozen refundee cannot make the claim revert. Refusing on it would be a guard refusing
   valid work, and worse: it would hand the counterparty a free unilateral veto, since a taker who
   becomes sanctioned after funding could kill the maker's only route to tokens it had already
   earned. The refundee belongs in a pre-**fund** gate, where a freeze really would strand the
   refund — and no such gate exists yet.
3. **A short funded window.** Exposure is the time tokens sit in the contract, so a tighter timeout
   is a safety property here in a way it is not for native ETH. This cuts against the usual
   instinct to be generous with timelocks.

## What is NOT done, and is accepted

- **Check-then-reveal is a race.** The gate narrows the window; it cannot close it. A freeze
  landing between the check and the broadcast, or after it, is unmitigated by construction.
- **The freeze read is single-source.** It defends a *failing* provider — it raises rather than
  guessing — but not a *lying* one. A hostile RPC returning "not frozen" for a frozen address is
  uncaught. Multi-source quorum is the fix if this ever carries real value; it is the same
  single-provider residual the finality path already documents.
- **Proxy upgradeability.** USDC is a `FiatTokenProxy`; its admin can change all token logic. The
  pinned-decimals cross-check would catch a decimals change, nothing catches the rest.

## The rule this exists to enforce

Any user-facing description of this corridor — README, release notes, marketing, a talk — must
carry the issuer-trust caveat alongside the existing "swaps are unaudited" line. The corridor is
useful precisely because it needs no bridge, no custodian and no legal entity; that framing is
honest **only** while the freeze caveat travels with it.

Related: [`griefing-is-a-liveness-residual-not-a-bond.md`](griefing-is-a-liveness-residual-not-a-bond.md)
records a residual accepted on the same terms.
