# pyrxd defensive profile

This file tells reviewers which tier of review a change needs, what to execute, which invariants the tests hold,
and where accepted findings are tracked. The review skills read it instead of carrying pyrxd facts themselves.
It changes when a Tier 2 component, a harness command or an invariant changes.

## Tiers

| Tier | What runs | Trigger |
|---|---|---|
| 0: every push | `task ci` in CI (lint, format check, full suite with coverage, typecheck, private-link check) plus the per-push regtest lane in `.github/workflows/integration.yml` | Every push and PR |
| 0n: scheduled | `fuzz.yml` (weekly deep Hypothesis run, including the alert-path state machine), `mutation.yml` (weekly), the `nightly-*` jobs in `integration.yml`, `photonic-drift.yml`, `checkpoint-freshness.yml` | Schedule |
| 1: per PR | One hostile Opus review; a re-review of every fix round. Add a claims-versus-behaviour lens (treat each "never / always / every" as a hypothesis to falsify) when a Tier 2 module's docstrings or docs change | A PR that changes behaviour |
| 1p: release | The 8-reviewer panel (`.claude/skills/security-panel/SKILL.md`) on `<last tag>..origin/main` | Before every release |
| 2: pre-merge | A Mythos pass in the maintainer's sandbox, alongside the Opus review, never instead of it. Only the maintainer starts it | A PR touching a Tier 2 path below |
| 2p: release | The release Mythos pass, widened to the whole of each Tier 2 component that changed since the last tag and briefed with that component's register rows | Before every release |
| 2p: register | A whole-component Mythos pass outside the release cycle | A component reaches 3 or more open register rows |

Two rules keep Tier 2 small:

1. A fix round on a Mythos finding gets an Opus re-review, not another Mythos pass, unless the round changes
   the defect class or the fix touches a new trust boundary.
2. Build the Tier 0 harness for a component before spending Mythos runs on it, and brief Mythos with its command.

Not Tier 2: docs, tests, CLI output formatting and small refactors with no behaviour change. Those stop at Tier 1.

## Tier 2 paths

A PR is Tier 2 if it changes any of these. Paths are relative to `src/pyrxd/` unless they say otherwise.

| Component | Paths |
|---|---|
| Keys, secrets and signing | `keys.py`, `hd/`, `btc_wallet/keys.py`, `eth_wallet/keys.py`, `eth_wallet/secret.py`, `security/`, `crypto/`, `aes_cbc.py`, `wallet.py`, `agent/` (the signing agent), `cli/wallet_cmds.py` |
| Transactions and consensus scripts | `transaction/`, `script/`, `fee_sizing.py`, `fee_model.py`, `fee_models/` |
| Covenants and contract bytecode | `gravity/covenant.py`, `gravity/covenant_selection.py`, `gravity/htlc_covenant.py`, `gravity/htlc_spend.py`, `gravity/codehash.py`, `gravity/artifacts/`, `glyph/soulbound_covenant.py`, `glyph/timelock.py`, `swap/rswp/covenant.py`, and the contract artifacts `tests/fixtures/EthHtlc.json` and `tests/fixtures/Erc20Htlc.json` |
| Swap money paths and persisted swap state | `gravity/` outside `gravity/watch/` (coordinator, swap state, maker, trade, receive, legs, record sink, seen store, finality, reorg cost, fee policy), `btc_wallet/htlc_leg.py`, `btc_wallet/disposition.py`, `btc_wallet/payment.py`, `eth_wallet/` (legs, replacement, private submit, disposition), `swap/`, `cli/swap_cmds.py`, `cli/swap_recovery.py`, `cli/swap_recovery_cmds.py` |
| Watch tower | `gravity/watch/` (observer, `decide`, reconciler, alerter, heartbeat, escalation, executors) |
| Multi-source reads and SPV (trust boundaries) | `network/` (quorum depth, source identity, failover, TLS pinning, ElectrumX, RXinDexer, Bitcoin sources), `eth_wallet/multi_rpc.py`, `eth_wallet/events.py`, `eth_wallet/locator.py`, `spv/`, `gravity/funding_spv.py`, `gravity/ref_authenticity.py`, `glyph/authority.py` |
| Wire formats | `glyph/` builders and payloads (`payload.py`, `builder.py`, `mint.py`, `transfer.py`, `ft.py`, `dmint/`), `gravity/swap_order.py`, `swap/rswp/wire.py`, and the generated `conformance/htlc-handshake-vectors.json` and `docs/htlc-handshake-wire-format.md` |

A release range is always Tier 2p.

## Harness

Reviewers and Mythos should execute rather than read. Pin the commit first.

- Whole suite, offline: `poetry run task ci`. In a sandbox with no network, `pytest -q -p no:cacheprovider --no-cov tests/`
  runs the same tests without the coverage gate.
- Watch tower: `pytest -q -p no:cacheprovider --no-cov tests/ -k watch`. The fakes are `tests/_fake_btc_chain.py`,
  `tests/_fake_radiant_chain.py` and `tests/_fake_evm_chain.py`; they carry honest and lying sources.
- Alert-path sequences: `tests/test_watch_alert_path_state_machine.py` (Hypothesis `RuleBasedStateMachine`; scale it
  with `FUZZ_BUDGET_MULTIPLIER`, as `scripts/fuzz_deep.sh` does).
- Radiant consensus: `task test-regtest` after `pyrxd regtest setup`. A consensus question is settled on the node, not
  in Python.
- ETH legs: the anvil-backed tests need `anvil`. The nightly cross-chain job in `integration.yml` runs
  `tests/test_eth_leg_anvil_integration.py` and `tests/test_xchain_erc20_usdc_lifecycle_e2e.py`;
  `tests/test_erc20_leg_fork_integration.py` is operator-run (`CLAUDE.md`, "Regtest and node-backed tests").
- Mutation: `task mutate <group>` (cosmic-ray, `docs/how-to/mutation-testing.md`).

Mythos briefs name the component's harness command and its register rows, and ask the agent to plant defects to
check that a test it relies on actually fails.

## Invariants

The stateful and table tests encode these. A change that breaks one is a defect, not a design change, unless the
maintainer re-decides it.

Alert path (`tests/test_watch_alert_path_state_machine.py`):

- No silent CRITICAL: a CRITICAL situation pages on every tick it is live, unless the operator ACKed that situation
  while it was open. An ACK of one situation never silences another.
- An ACKed situation does not page again while it stays open, and an ACK binds only to an open CRITICAL.
- `unacked_critical_count` is 1 exactly when an open CRITICAL situation is un-ACKed.
- One faulty source cannot lower a page: the decision is at least as severe as the one the same tower takes over
  honest sources.
- The pre-signed refund is armed only when a quorum of sources reads the outpoint unspent, none names a claim, and
  fewer than a quorum name a refund of ours.
  A source that is down never counts as "unspent".

Sources and endpoints (`CLAUDE.md`, "Consensus, chains and units"):

- One endpoint must not choose what the others verify. A candidate that one source nominates is a claim, not the
  subject of the check. Test a lying primary that both adds a decoy and withholds the real item.
- A value that decides where funds go never comes from one endpoint without derivation. Sources are counted by
  operator, not by host (`network/source_identity.py`).
- A wait that rests on one source's nomination pages; it never stays silent.

Chain rules:

- The secret-holder's locked leg has the longest timelock, and the leg they claim the shortest.
- A relative timelock is enforced by the spending transaction's BIP68 fields, not by the covenant opcode alone.
- Script numbers are pushed minimally (MINIMALDATA is consensus).
- Only `0xd0` and `0xd8` mark an output as holding a ref (`glyph.script.script_carries_ref`).
- Fund-safety controls stay: dust caps, reorg and burial value scaling, seen-store durability, `MarginPolicy`
  validation.

Every refusal test has an honest-path twin, and every verified review finding lands a test, accepted ones too.

## Residual register

Accepted, deferred and unverified findings are tracked in a register the maintainer keeps outside this repo, one
row per residual with an owner and a re-check trigger. Rows describe weaknesses in shipped code, so they are
never copied into this repo, a PR, an issue or a commit message. A release or register Mythos pass is briefed with
the rows for its components and asked whether each still holds.

## Not built yet

These Tier 0 items from the agreed plan do not exist yet, so a reviewer should not assume they ran:

- A golden-matrix snapshot over role x state x chain x tip for the tower's decision.
- A scheduled job that replays the fake chains' answers against regtest nodes and diffs them.
