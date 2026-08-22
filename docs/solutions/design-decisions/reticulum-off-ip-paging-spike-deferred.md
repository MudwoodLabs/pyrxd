---
title: Watchtower paging over Reticulum — spike proven, deferred until a consumer needs it
status: deferred
date: 2026-08-21
category: design-decisions
archived_ref: spike/reticulum-alert-channel-v1
related_files:
  - src/pyrxd/gravity/watch/adapters.py (existing CompositeAlertChannel, Logging/Webhook channels)
  - src/pyrxd/gravity/watch/run.py (the daemon that would have to wire it — never did)
---

## TL;DR

**Reticulum is a transport that works without IP** (LoRa radio, serial, or tunnelled over
TCP). A spike added a watchtower alert channel over it and **proved it end to end**,
including a page crossing a non-IP link inside a network namespace with no localhost at
all. It was **not merged**. The capability is real; the need is not, and the deciding
argument is below.

The work is archived at tag **`spike/reticulum-alert-channel-v1`** (tip
`64c13b3`), PR #467 closed unmerged. Nothing in `main` imports it.

## Why it was deferred — the paging-vs-acting paradox

The watchtower pages an operator when a swap needs action before a deadline. Reticulum's
whole value is that the page arrives when IP is down.

**But if IP is down for the operator, they cannot broadcast the claim either.** The alert
and the action require the same network, so the page arrives and nothing can be done with
it. The scenario where it genuinely wins is narrow: the *monitoring host* is cut off while
the *operator* is not, with the radio bridging the two. That is a real topology, but the
cheaper answer is to run the watchtower somewhere with better uptime, and in the common
case (home WAN drops, operator holds a phone on cellular) the existing webhook channel
already reaches them.

Compounding it: `run.py` is **alert-only v1** and the stated direction is v2 autonomous.
The more autonomous the watchtower becomes, the less urgent paging the operator is at all —
the feature runs against its own roadmap.

## What it does genuinely add (recorded so the revival case is fair)

A **deadman that survives a WAN outage**: an operator learns the watchtower is alive but
isolated, which no IP-based channel can tell them. That is real. It is also small, and it
was the only benefit that survived review.

## What the spike proved, concretely

Worth keeping because it is the expensive half to re-derive:

- A `Page` reaches a Reticulum SINGLE destination over a real stack, two processes, nothing
  mocked below the channel — announce, identity recall, encryption, and the wire budget all
  exercised.
- **A page crosses a non-IP link.** Run under `unshare -rn` where the only interface is a
  DOWN loopback, two instances talk over a virtual serial pair (kernel ptys cross-wired by a
  pump thread). A real RNode is a serial device driven by the same `SerialInterface`, so what
  remained untested was the physical layer — the radio — not the software path.
- The probe **asserts its own premise and exits 2 if localhost is reachable**, because a green
  result from a namespace that quietly had networking would be worse than no test at all.
- Sending to a destination whose announce was never seen **raises** rather than silently
  dropping, so a retry happens once the announce lands.

## Three RNS API behaviours found by running it

None of these are documented prominently; each cost time:

1. **Dots are not allowed in app names.** `app_name="pyrxd"` with
   `aspects=("watchtower", "alert")` — not a dotted string.
2. **`Identity.recall()` returns `None` until an announce has been received.** A SINGLE
   destination is addressed by hash but encrypted to a public key learned from an announce,
   so a sender must genuinely receive one before it can encrypt anything. Any test that
   shares an identity in one process skips the step most likely to break in the field.
3. **`RNS.Reticulum()` is a per-process singleton.** Construct via
   `RNS.Reticulum.get_instance()` when one may already exist.

Wire budget: **465 bytes** of payload inside Reticulum's 500-byte MTU. A `Page` encodes well
inside it with the prose field truncated first.

## Cost side, honestly

~814 added lines plus an integration suite and a namespace probe, against a young dependency
with effectively one maintainer. Isolating it behind an optional extra
(`pyrxd[reticulum]`, `rns>=1.4.0,<2.0.0`) makes it **harmless**, not **valuable** — those are
different claims and the decision turned on not blurring them.

## What would trigger reviving it

Any one of:

- A watchtower operator who is not the author, deployed where connectivity is genuinely
  unreliable.
- A deployment where the monitoring host and the operator are on different networks by
  design, and the bridge matters.
- Demand for an off-IP transport elsewhere in the Radiant ecosystem, making the dependency
  earn its keep across more than one feature.

Absent those, this follows the same rule as
[`wave-protocol-deferred-until-consumer.md`](wave-protocol-deferred-until-consumer.md):
**the trigger to build is a concrete caller, not the idea being good.**

## Reviving it

`git checkout -b feat/reticulum spike/reticulum-alert-channel-v1`, then rebase onto `main`.
Note that the branch predates nothing important — it was cut from `a79d28a` — but it was
**never wired into the daemon**, which was tracked as its own issue and is the first thing
any revival must fix: `run.py` builds a `CompositeAlertChannel` from the Logging and Webhook
channels and hands it to `DedupAlerter`, so wiring is a flag plus one more channel in that
composite. Make it **fail loudly at startup** when the flag is set but the extra is missing,
following `_require_acking_alerter` in the same file, rather than silently no-opping.
