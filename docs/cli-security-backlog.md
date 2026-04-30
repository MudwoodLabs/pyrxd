# CLI security backlog (v0.3.x and later)

This file collects known limitations and follow-up work for the
`pyrxd` CLI security model. Items here are *not* known
vulnerabilities — they're either accepted-with-mitigations or
deferred enhancements. Promote to a tracked issue when work begins.

## Cut 1 status (closed)

- [x] `--debug` traceback wired up via `errors.set_debug` / `is_debug`,
  reads only from chained `__cause__`, never uses `capture_locals=True`.
  Tested in `tests/cli/test_wallet_cmds.py` — traceback is shown and
  the user's input never appears.
- [x] Mnemonic input normalized (`_normalize_mnemonic`) before hitting
  the BIP39 validator: collapses whitespace and strips ends, so users
  pasting from notes don't fail validation on benign formatting.
- [x] CLI catches both `ValidationError` *and* `ValueError` from
  wallet load (BIP39 wordlist failures previously surfaced raw).
- [x] Library `_load_existing` now wraps the post-decrypt JSON-walk
  in `try/except (KeyError, TypeError, ValueError)` so a malformed
  wallet file (impossible under AEAD, but defended anyway) raises a
  clean `ValidationError` instead of crashing with `KeyError`.
- [x] README documents the `--json --yes wallet new` mnemonic
  exposure trade-off and the responsibility on the user to ensure
  stdout consumers are themselves secure.

## Open / deferred to v0.3.x

### 1. Mnemonic re-entry per command (UX → security trade)

`pyrxd address`, `pyrxd balance` (and future query commands) each
prompt for the mnemonic. Running `pyrxd address` then `pyrxd balance`
back-to-back makes the user type the mnemonic twice. More typing
means more exposure (shoulder-surf, scrollback if the input ever does
echo).

Mitigation options:

* **In-memory session cache** (process-lifetime): store the decrypted
  `HdWallet` in a process-local cache. Doesn't help across separate
  invocations (the process exits between commands).
* **Agent process** with `~/.pyrxd/agent.sock`: like `ssh-agent`. A
  user runs `pyrxd agent unlock` once; subsequent commands talk to
  the agent over a Unix socket. The agent holds the decrypted seed
  (in `SecretBytes`) for a configurable timeout.

The agent path is correct but a non-trivial security surface — the
socket needs careful permission and authentication design. Defer
until we have a concrete user pain signal.

### 2. Mnemonic in command output snapshots / pytest tracebacks

`tests/cli/test_wallet_cmds.py` captures `result.output` (which
contains the freshly-generated mnemonic in JSON mode tests) for
follow-up assertions. If a downstream assertion fails, pytest's
traceback may include `result.output` content via the assertion
introspection.

This is low-risk in practice (the mnemonics are random per test run
and CI logs are private), but worth knowing. If we add a snapshot-
testing dep later that writes assertions to disk, this becomes a
concern.

Mitigation: never commit a snapshot file containing a real
mnemonic. The test fixtures use disposable mnemonics that have
never held funds.

### 3. `pyrxd setup` prompt UX (Cut 3)

The deferred `pyrxd setup` command will run interactive prompts.
Open question: should `setup` ever offer to *generate* a mnemonic
in JSON mode for scripted onboarding? My current lean is **no** —
the JSON path of `wallet new` already exists for that, and `setup`
should only orchestrate, not duplicate. Lock in this decision when
Cut 3 lands.

### 4. Fuzz testing the CLI

Hypothesis-style fuzzing of the CLI surface (random bytes piped to
`wallet load`, random values via env vars, random argument
combinations) hasn't been done. The Python library has property-
based tests via Hypothesis (`tests/test_property_based.py`); the
CLI does not.

Concrete first targets:

* `_normalize_mnemonic` against random Unicode / NUL / very-long
  inputs (must not crash, must not infinite-loop).
* `Config` loader against random byte sequences that *almost* parse
  as TOML.
* Click command surface fuzzed with `hypothesis-jsonschema` style
  random argument combinations.

This is a good first-time-contributor task once Cut 2/3 ships.

### 5. Mnemonic clipboard hygiene

Many users will copy/paste their mnemonic. The CLI doesn't do
anything special with the system clipboard, which means the
mnemonic may persist in clipboard managers (KDE Klipper, GNOME
clipboard history, third-party tools). We can't *prevent* this from
the CLI, but we could add a flag to `wallet new`:

* `pyrxd wallet new --no-paste-warning` to suppress.
* By default, after the Enter gate in interactive mode, print:
  > Some clipboard managers retain copy/paste history. If you
  > copied the mnemonic, clear your clipboard manager now.

Defer to v0.3.x; UX nicety.

### 6. Wallet file mode 0600 verification on load — DONE in v0.3 Cut 1

`HdWallet._load_existing()` now checks `path.stat().st_mode & 0o077`
before touching the seed; any group/world bits raise
`ValidationError` with the chmod-fix instruction. Skipped on
non-POSIX platforms (Windows reports dummy mode bits). Tested in
`tests/test_hd_wallet.py::TestSaveLoad::test_load_rejects_world_readable_wallet_file`.

## Out of scope (won't ever do)

* **Hardware wallet support in pyrxd CLI.** Belongs in a separate
  package (`pyrxd-hw` or similar). USB / HID protocols are a
  materially different security model.
* **Encrypted memory pages.** CPython doesn't expose mlock-style
  guarantees portably; `SecretBytes.zeroize()` is best-effort and
  documented as such.
* **Bypassing terminal echo via TTY ioctl.** `click.prompt(hide_input=True)`
  is sufficient. We don't try to clear scrollback, lock the terminal,
  or anything like that — those are user-environment concerns.
