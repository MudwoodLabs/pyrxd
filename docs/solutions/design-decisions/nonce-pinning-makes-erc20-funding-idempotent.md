---
title: Nonce pinning makes ERC-20 funding idempotent, but only on a dedicated funding key
date: 2026-08-24
status: measured
component: gravity/eth_wallet
---

# Nonce pinning makes ERC-20 funding idempotent — on a dedicated key

## Why this was investigated

The ERC-20 counter-leg funds in two transactions (deploy, then a plain `transfer`). A crash between
them leaves a contract that may hold real USDC, so a *resume* completes the push rather than
redeploying. Seven review rounds layered guards onto that resume: a `flock` mutex, a
reservation-divergence check, an in-flight mempool guard, an immutable re-bind.

Every one of those guards defends the same thing — **two pushes both landing**. The question was
whether the chain can provide that property directly, making the guards unnecessary rather than
merely correct.

## What was measured

Against `anvil --no-mining`, sending real transactions from a published anvil default key:

| Scenario | Node response | Value delivered |
|---|---|---|
| Two different pushes at the same pinned nonce, same gas price | second: `transaction already imported` | one |
| Same, second at 10x gas price | second accepted — it **replaces** the first | one |
| Re-send at the same nonce after it mined | `nonce too low` | one (1 ETH, not 2) |
| An **unrelated** tx from the same key takes the pinned nonce first | our push: `replacement transaction underpriced` | **ours never lands** |

A CREATE address is derivable from `(sender, nonce)` before broadcast, so pinning the *deploy* nonce
also removes the "address unknowable until the receipt" problem that forced a persist callback.

## The finding

**Idempotency holds.** Two resumers, or a resume racing its own still-pending push, cannot both
commit value: the nonce slot is exclusive, and whichever transaction wins it, exactly one mines.
This is a property of the chain, not of a lock — so it holds across hosts, across filesystems, and
across an operator who copies a keys directory. All the cases `flock` could not cover.

**But the pin can be stolen.** Any other transaction from the same key can take the pinned nonce.
When it mines, the pin is consumed; re-sending returns `nonce too low` forever and the fund wedges
permanently. Recovering means re-pinning to a fresh nonce — and two resumers re-pinning
independently can choose *different* nonces and both land, reintroducing the double-fund the pin
was meant to remove.

So nonce pinning does not eliminate coordination. It **relocates** it: from "coordinate every push"
to "coordinate only a re-pin", which happens only when the funding key is shared.

## Decision

Adopt nonce pinning as the primary mechanism, and require a **dedicated funding key** per swap so
the re-pin case cannot arise. A dedicated key is an operational requirement that is cheap to state
and mechanically checkable (the key's nonce should advance only through this swap's own
transactions).

Keep the existing `flock` and the in-flight guard as defence in depth rather than removing them.
They cost little, they are already tested, and they cover the single-host case if the dedicated-key
assumption is ever violated. Removing tested guards to rely on a newly-measured property would be
trading a known quantity for an unknown one.

## What this does NOT solve

- A shared funding key. The pin is stealable and the re-pin needs coordination the chain does not
  provide. Detect it (`latest_nonce` advanced past the pin while the balance is still short) and
  fail closed rather than re-pinning silently.
- The replacement-pricing rule. A resume that rebuilds at the same nonce with the same gas price is
  rejected as `already imported`. That is the CORRECT outcome — the original still stands — but it
  must be classified as success-in-progress, not as a failure.
