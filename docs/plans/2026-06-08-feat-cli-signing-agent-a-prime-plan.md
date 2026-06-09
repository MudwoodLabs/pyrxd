---
title: "CLI signing agent (A′ — sign-on-behalf) for issue #8"
type: feat
date: 2026-06-08
status: plan
design: docs/brainstorms/2026-06-08-pyrxd-cli-signer-seam-design.md
review: divergent panel (architecture-strategist + code-simplicity-reviewer + kieran-python + security-sentinel), 2026-06-08
issue: "#8 — CLI: mnemonic re-entry per command — design an agent-process unlock pattern"
---

# ✨ feat: CLI signing agent (A′)

> **Scope decision (after a divergent review panel).** This is **Path A′**
> from the design doc: a **sign-on-behalf** agent. The daemon holds the
> wallet and signs; the key **never leaves it**. This is deliberately NOT
> Path A (a "seed-vending" agent — rejected: its socket hands back the
> whole seed, so any same-uid process drains the wallet with no
> confirmation) and NOT Path B (a generalized pluggable `Signer` seam —
> deferred until Ledger is actually scheduled). A′ is the smallest design
> that *actually improves custody* for #8.
>
> **Provenance.** Every file:line below was read during the design pass +
> the divergent panel (spike-based, not doc-derived). Effort is relative
> complexity (S/M/L), never fabricated hours. Nothing here is built yet.

---

## Overview

Today every wallet-touching pyrxd command prompts for the mnemonic,
decrypts the wallet **in the CLI process**, and signs there
(`cli/prompts.py:123-155` `_load_wallet` → `HdWallet.load` →
`collect_spendable`/`_build_utxo_input` → `P2PKH().unlock(privkey)` at
`script/type.py:77`). Issue #8 asks for an `ssh-agent`-style unlock so the
user types the mnemonic once per session.

**A′ = a local daemon that holds the unlocked wallet and signs on the
CLI's behalf.** The CLI becomes *watch-only*: it builds the unsigned
transaction from public material (addresses + account xpub), hands it to
the agent over a Unix socket, and gets back a **signed** transaction. The
seed/keys live only in the daemon — reaching the socket lets an attacker
*request* a signature (gated by per-spend confirmation), never *take* the
key.

This is strictly better custody than today (key no longer re-derived in
every short-lived CLI invocation) **and** the requested UX — but only if
the signing-side hardening (§ Load-bearing) ships with it. Without that
hardening it degrades to Path A's posture, so the hardening is not
optional.

## Problem Statement

- **UX:** mnemonic re-entry on every command (`docs/cli-security-backlog.md`).
- **Custody (the real prize):** the seed is decrypted into the CLI process
  on every command. A sign-on-behalf agent removes the key from the CLI
  entirely — *if* it doesn't just hand the key back.
- **Trap:** the obvious implementation (agent vends the seed) is the
  `ssh-agent` anti-pattern and improves nothing. The work is in making the
  agent **sign**, safely.

## Architecture (A′)

```
  pyrxd <cmd>                              pyrxd-agent (daemon)
  ───────────                              ────────────────────
  build unsigned tx (watch-only:           holds HdWallet in SecretBytes
   addresses + xpub, no keys)              (auto-lock timer)
        │  SigningRequest                          │
        │  {raw_tx, inputs:[{path,outpoint}], ─────▶ verify prevouts (C1)
        │   sighash}                                attribute outputs (H1)
        │                                           confirm w/ user (H2)
        │  SignedTx  ◀───────────────────────────── re-derive keys, sign
   broadcast                                        return signed tx
```

- **CLI side (watch-only):** build the tx exactly as today's
  `build_send_tx`/swap/glyph builders do, but parameterized so the signing
  step is deferred. The CLI needs only addresses + the account xpub (the
  agent vends the xpub on unlock; xpub is a privacy artifact, not a
  signing secret).
- **Agent side (signer):** holds the decrypted `HdWallet`; on a
  `SigningRequest` it re-derives the per-input keys (`_privkey_for`,
  `hd/wallet.py:739`), runs the § Load-bearing checks, signs, returns the
  signed tx.
- **Transport:** Unix domain socket at `~/.pyrxd/agent.sock` (`0700` dir,
  `0600` socket), `SO_PEERCRED` uid==owner.
- **Fallback:** if the socket is absent/locked, commands fall back to
  today's mnemonic prompt (typed `SignerUnavailableError`).

### Module layout (small — A′ is NOT the generalized seam)

```
src/pyrxd/agent/
  __init__.py
  protocol.py     # SigningRequest / SignedResult frames + (de)serialization
  daemon.py       # socket server, SO_PEERCRED, lifecycle, auto-lock
  signer.py       # holds HdWallet; verify → confirm → sign  (the brain)
  client.py       # CLI-side: is-agent-live? send request, get signed tx
  confirm.py      # interactive per-spend confirmation UI
src/pyrxd/cli/agent_cmds.py   # `pyrxd agent unlock|lock|status`
# edits: cli/prompts.py (_load_wallet routes to client when live);
#        hd/wallet.py (watch-only tx-build path that defers signing)
```

No `Signer` Protocol, no `KeyId` dataclass, no `unlock_with_signer`, no
template rewrite — those are Path B.

## What A′ deliberately does NOT do (and why that's safe)

- **No generalized `Signer` seam / Ledger backend.** Deferred to Path B,
  co-designed against two real backends when Ledger is scheduled. Building
  it now is speculative generality (simplicity review).
- **No gravity/HTLC agent signing.** Those hand-roll signing
  (`gravity/transactions.py:125-182`) and move real value behind the
  audit gate; routing them through the agent is out of scope for #8.
- **No remote/networked agent.** Local Unix socket only. (Windows: TCP
  loopback + token is a documented future variant, not v1.)
- **No seed vending.** The agent never returns key material — the core
  invariant, conformance-tested.

## Load-bearing safety properties (MUST ship with A′, not after)

These are the §4 hardening from the design doc; they are what separate A′
(secure) from A (not). Cutting any of them reduces A′ to A.

1. **Prevout authenticity (C1).** The preimage commits to each input's
   `satoshis`+`locking_script` (`transaction_preimage.py:133-135`), which
   today come from caller data (`transaction_input.py:32-34`,
   `hd/wallet.py:781-789`). The agent MUST independently establish them
   (require full source txs in the request and verify
   `hash256(src)[::-1]==outpoint.txid`, then read value/script from the
   real output) — never trust the request's claimed amounts. Defeats the
   fake-low-value → burn-to-fee theft.
2. **No blind signing + per-spend confirmation (H1/H2).** The agent parses
   the tx, attributes each output as change-to-own-derived-key vs
   external, and for non-trivial spends shows destinations/total/fee and
   requires a keypress. This is THE control, because same-uid processes
   pass `SO_PEERCRED` and can originate requests.
3. **Never return key material.** The socket exposes sign + xpub +
   address, never the seed/privkey. Conformance test asserts responses
   contain no 32-byte scalar matching the key.
4. **Display==sign atomicity (TOCTOU).** The agent computes the preimage,
   displays from *that* preimage, and signs *that* preimage — no
   display-then-resign of caller-resent bytes.
5. **Sighash is security-relevant.** Anything other than the expected
   `ALL|FORKID` on a normal spend requires confirmation. (Also avoids the
   `from_hex`-drops-sighash footgun, `transaction_input.py:58-87`: the
   agent sets sighash explicitly before signing, like `RPuzzle.unlock`.)
6. **Memory hygiene.** Seed in `SecretBytes` (`security/secrets.py:73`);
   `mlock` the pages, disable core dumps, `PR_SET_DUMPABLE 0`,
   `SIGTERM`/`SIGINT` handlers that `zeroize`. Honest limit: `SIGKILL`/
   crash cannot be scrubbed (document it).
7. **Socket auth:** `0700` dir **and** `0600` socket **and** `SO_PEERCRED`
   uid==owner (all three, not any one).

## Implementation Phases (complexity = ESTIMATED relative size)

### Phase 0 — Spike (S)
Prove two things against real code before building: (a) the CLI can build a
valid send tx from addresses+xpub with signing deferred (watch-only), and
(b) the agent, re-deriving keys from the held seed, produces **byte-
identical** signatures to today's in-CLI path. Gate the rest on this.

### Phase 1 — Watch-only tx-build path (M)
Refactor `hd/wallet.py` so tx construction (`build_send_tx:822`,
`_build_utxo_input:763`, `collect_spendable:791`) can run from public
material and emit `(unsigned_tx, [input coords: path + outpoint + source
tx])` without deriving private keys. Existing in-process signing stays the
default; this just adds the "stop before signing" seam internally.

### Phase 2 — Agent signer core, in-process (M–L)
`agent/signer.py` + `protocol.py`: holds `HdWallet`; consumes a
`SigningRequest`, re-derives keys, signs, returns the signed tx. Auto-lock
timer + `zeroize`. Fully unit-testable with no socket.

### Phase 3 — Signing-side hardening (M) — load-bearing §1-5
Prevout verification (C1), output attribution + confirmation (H1/H2),
never-return-key invariant, TOCTOU single-buffer, sighash policy. This is
the security heart; treat its tests as the acceptance gate.

### Phase 4 — Unix socket transport + auth + memory hygiene (M)
`agent/daemon.py` + `client.py`: framed request/response, `0700`/`0600`,
`SO_PEERCRED`, stale-socket cleanup, single-instance lock, `mlock`/
`PR_SET_DUMPABLE`/no-coredump/signal-zeroize (§6-7).

### Phase 5 — CLI surface + fallback (S–M)
`pyrxd agent unlock|lock|status`; `_load_wallet`/command signing routes to
the agent when live, falls back to the mnemonic prompt on
`SignerUnavailableError`. No behavior change when the agent is off.

### Phase 6 — Threat-model doc + test sweep (M)
The issue-#8 threat-model doc (contents below) + tests: socket perms,
auto-lock zeroize, prevout-lie rejection, confirmation gate (accept/
reject), fallback-when-down, concurrent clients, wrong-uid peer refusal.

## Deferred to Path B (Ledger / pluggable seam)
The generalized `Signer` Protocol + `KeyId` + `unlock_with_signer` +
template rewrite, plus a `LedgerSigner` (after a spike confirming the
device app parses Radiant BIP143 incl. ref-aware `hashOutputHashes`,
`transaction_preimage.py:66-92`). Co-design against the A′ agent + Ledger
together. See the design doc §2-§3.

## Alternatives Considered
- **Path A (seed-vending agent):** rejected — `ssh-agent` anti-pattern;
  socket hands back the whole seed, no confirmation, same-or-worse than
  today.
- **Status quo (prompt per command):** smallest resident-key footprint,
  but the UX cost #8 is about; loses to A′ on convenience and on
  long-session ergonomics.
- **rxdpy-signer (the sibling service):** different SDK (`rxdpy`), different
  altitude (intent/HTTP, multi-caller, web-tier). Out of scope; reuse its
  *patterns* (sealed-at-rest, hash-chained audit) for the agent's at-rest
  story only.

## Acceptance Criteria
Maps issue #8's criteria + the panel's mandatory additions:
- [ ] `pyrxd agent unlock` / `lock` / `status` subcommands.
- [ ] Wallet-touching commands use the agent when live; **fall back to the
      mnemonic prompt** when it isn't.
- [ ] The agent **signs on behalf** and **never returns key material**
      (conformance-tested).
- [ ] Prevout authenticity enforced (a request lying about an input's
      value is rejected) — test.
- [ ] Non-trivial spends require interactive confirmation showing
      attributed outputs/total/fee — test (accept + reject paths).
- [ ] Auto-lock zeroizes the seed after timeout — test.
- [ ] Socket: `0700` dir + `0600` socket + `SO_PEERCRED`; wrong-uid peer
      refused — test.
- [ ] Documented threat model + auth analysis (criterion #4).
- [ ] Byte-identical signatures vs the in-CLI path for the same tx (Phase
      0 invariant) — permanent regression test.

## Risks & Mitigations
- **Watch-only refactor churns the hot wallet path (Phase 1).** → keep
  in-CLI signing the default; gate on the Phase-0 byte-identical test.
- **Confirmation UX fatigue → users blind-confirm.** → amount thresholds
  (small spends below a cap skip the prompt within an unlock window);
  document that blind-confirm is out of the trust boundary.
- **Cross-platform (no AF_UNIX on Windows).** → v1 is POSIX; document the
  TCP-loopback+token variant as future, don't build it.
- **Crash leaves seed in memory.** → mlock/no-coredump/PR_SET_DUMPABLE;
  honestly document the SIGKILL limit.

## Dependencies
- Existing: `SecretBytes`/`PrivateKeyMaterial` (`security/secrets.py`),
  `HdWallet` (`hd/wallet.py`), the encrypted wallet loader.
- New stdlib only: `socket` (AF_UNIX, SO_PEERCRED), `ctypes`/`mlock`,
  `signal`, `prctl` via `ctypes` for `PR_SET_DUMPABLE`.

## Testing Strategy
Unit-test the signer brain (Phase 2-3) with no socket; integration-test the
daemon over a real socket in a tmp dir; property/adversarial tests for the
prevout-lie and confirmation paths; a permanent byte-identical regression
test vs in-CLI signing.

## Documentation Plan
- Threat-model doc (issue #8 criterion #4) MUST contain: socket auth +
  the same-uid admission; per-spend confirmation as the real control;
  prevout authenticity; TOCTOU single-buffer rule; memory hygiene + the
  SIGKILL limit; explicit non-goals (no blind-confirm defense, no digest
  signing, no seed vending).
- A how-to: "unlock once with the pyrxd agent."

## References (internal, file:line — verified during design)
- `src/pyrxd/cli/prompts.py:123-155` — `_load_wallet` (integration point)
- `src/pyrxd/hd/wallet.py:739,763,791,822` — key derivation + tx build
- `src/pyrxd/script/type.py:77` — `P2PKH.unlock` (today's in-CLI signing)
- `src/pyrxd/security/secrets.py:73` — `SecretBytes` (zeroize/unpicklable)
- `src/pyrxd/transaction/transaction_preimage.py:66-92,133-135` — preimage commits to prevout value/script + ref-aware field
- `src/pyrxd/transaction/transaction_input.py:32-34,58-87` — prevout from caller data; `from_hex` drops sighash
- `src/pyrxd/eth_wallet/htlc_leg.py:271-279` — `PrivateKeyMaterial` zeroize-after-use pattern to mirror
- `docs/cli-security-backlog.md` — the #8 spec
- `docs/brainstorms/2026-06-08-pyrxd-cli-signer-seam-design.md` — the design + panel findings
