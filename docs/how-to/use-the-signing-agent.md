# How to use the local signing agent

**Who this page is for:** you're running several wallet commands in a session
and don't want to retype your mnemonic for each one — and you'd rather the seed
live in exactly one place you can see, not get re-entered at every prompt. The
`pyrxd agent` group unlocks the wallet **once** into a small foreground process;
the key never leaves it, and signing requests are served over a local socket.

```
unlock once  →  agent holds the seed  →  pyrxd wallet send … (signed by the agent)  →  lock
```

The seed is held in one process, is zeroized when you lock it (or on idle
timeout, or Ctrl-C), and every non-trivial spend is approved in the agent's own
terminal — not the terminal that asked for the signature.

---

## Start the agent

```console
$ pyrxd agent unlock
Mnemonic (input hidden):
Signing agent live on ~/.pyrxd/agent.sock — Ctrl-C to lock.
```

`unlock` prompts for the mnemonic once, then runs in the **foreground**, serving
signing requests on `<wallet dir>/agent.sock` (the socket sits next to the
wallet file, so `--wallet PATH` co-locates it). Leave this terminal open — spend
confirmations appear **here**, where you can see them. Press Ctrl-C to lock.

Two options worth knowing:

| Option | Default | What it does |
|---|---|---|
| `--idle-timeout SECONDS` | `900` | Auto-lock (zeroize the seed) after this many seconds with no activity. |
| `--auto-confirm-under PHOTONS` | `0` | Skip the keypress for spends whose total to external payees is **at or below** this. `0` = always confirm. Spends above the threshold **always** require a keypress. |

So `pyrxd agent unlock --auto-confirm-under 100000` waves through small payments
(≤ 100,000 photons) but still stops and asks before anything larger.

---

## Use it from another terminal

With the agent live, run wallet commands as usual in a **second** terminal —
they detect the agent automatically (no flag, no env var). Today this is wired
into `wallet send`:

```console
$ pyrxd wallet send --to 1Qq…recipient --amount 50000

  Send:
    to address:  1Qq…recipient
    amount:      0.0005 RXD
    network fee: …
    inputs:      1 UTXO(s)
    signed by:   agent

  Approve the spend in the agent's terminal to broadcast.
```

When the agent is live, `wallet send` builds the transaction **watch-only** from
the account xpub (no mnemonic prompt), hands it to the agent to sign, and the
**agent's terminal** shows the authoritative confirmation prompt. Approve it
there and the send broadcasts. If no agent is running, `wallet send` falls back
to the in-process path and prompts for the mnemonic as normal.

> **Scope, honestly:** the agent currently signs for `wallet send`. Other
> signing commands (token transfers, deploys) still prompt for the mnemonic
> in-process — the agent-backed path is being extended outward from `send`.

---

## Check and stop the agent

```console
$ pyrxd agent status
Signing agent is live on ~/.pyrxd/agent.sock

$ pyrxd agent lock
Agent locked and shut down.
```

`status` reports whether an agent is live on this wallet's socket; `lock` tells
a running agent to zeroize the seed and shut down. The seed is also zeroized
automatically on the idle timeout and on Ctrl-C in the agent's terminal.

---

## What the agent does and doesn't protect

- **The seed lives in one process.** Other commands talk to it over a local Unix
  socket and never receive key material — they get *signatures*, not the seed.
- **You approve spends where the key is.** The confirmation prompt is on the
  agent's terminal, so a command in another terminal (or a script) can't approve
  its own spend — a human at the agent has to. `--auto-confirm-under` is the one
  deliberate exception, bounded to small external payments.
- **It is not a hardware wallet or an HSM.** The key is in your machine's
  memory while unlocked. The agent reduces *re-entry* and *exposure surface*
  (one process, zeroized on lock/idle); it does not move the key off the host.
  Lock it when you're done.

---

## See also

- [Your first Radiant transaction](../tutorials/your-first-radiant-transaction.md)
  — the in-process `wallet send` flow the agent replaces.
- [Receive funds and check your balance](receive-and-check-balance.md) — the
  read-only commands need no agent and no mnemonic.
