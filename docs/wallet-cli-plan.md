# Wallet facade + CLI plan (v0.3)

**Status:** approved 2026-04-30. Implementation pending.
**Goal:** make pyrxd usable in 5 minutes from `pip install` to first Glyph mint without writing Python.

## Approved decisions

These are settled. Rationale is in [wallet-cli-decisions.md](wallet-cli-decisions.md).

| # | Decision | Choice |
|---|---|---|
| 1 | CLI library | **click** |
| 2 | Binary layout | one `pyrxd` binary with subcommands |
| 3 | `--json` and confirmation prompts | independent (`--json` errors without `--yes` for destructive ops) |
| 4 | Glyph metadata | file-only, with a `pyrxd glyph init-metadata` scaffold helper |
| 5 | Default network | mainnet, with confirmation prompts on every destructive action |
| 6 | Mnemonic display | stdout with an Enter gate; user is responsible for terminal hygiene |

## Scope: narrow and Glyph-focused

This plan is informed by [`radiant-core-wallet-research.md`](radiant-core-wallet-research.md) and [`scope-decision-2026-04-30.md`](scope-decision-2026-04-30.md). Summary:

- Radiant Core ships a complete Bitcoin-Core-style wallet (`sendtoaddress`, HD support, encryption, PSBT, multisig, etc.). Anyone running a node has those capabilities already.
- Radiant Core's wallet does **not** understand Glyph tokens. Glyph script outputs are classified `nonstandard`; `listunspent` returns no token metadata; `sendtoaddress` won't auto-spend a Glyph UTXO.
- pyrxd's value isn't a better plain-RXD wallet — it's the application-layer Glyph + Gravity tooling that doesn't exist in the node.

**In scope for v0.3:**
- `HdWallet.send()` / `send_max()` — close a real library API gap.
- A `pyrxd` CLI focused on **Glyph operations + minimal onboarding**, not a full wallet replacement.
- An onboarding flow (`pyrxd setup`) that helps users navigate the Radiant ecosystem without bundling its components.

**Out of scope for v0.3 (deferred or skipped):**
- `pyrxd send` / `send-max` / `build-tx` / `broadcast` — duplicates `radiant-cli sendtoaddress` for node users; doesn't move the needle for non-node users (they want Glyph features). May add later if onboarding friction is real.
- Bundling a Radiant Core node, replacing `radiant-cli`, shipping a TUI/GUI — see [`scope-decision-2026-04-30.md`](scope-decision-2026-04-30.md).
- Hardware wallet integration, multi-account beyond `account=0`, watch-only xpub mode, transaction history view, `pyrxd gravity *` subcommands. All v0.4+.

## What gets built

### Library layer

#### Net-new: nothing

`RxdWallet` already exists in `src/pyrxd/wallet.py` with `send`, `send_max`, `get_balance`, `get_utxos`. It works.

`HdWallet` exists in `src/pyrxd/hd/wallet.py` with derivation, gap-limit scanning, and encrypted save/load. It works.

`GlyphBuilder` and `FtUtxoSet` exist in `src/pyrxd/glyph/`. They work.

#### Single targeted edit: add `HdWallet.send()`

Add three methods to `HdWallet`:

```python
def build_send_tx(self, to_address, photons, *, fee_rate=None, change_strategy="next_internal") -> Transaction:
    """Offline: build the unsigned tx. No network calls."""

def build_send_max_tx(self, to_address, *, fee_rate=None) -> Transaction:
    """Offline: build the sweep tx. No network calls."""

async def send(self, to_address, photons, client, *, fee_rate=None) -> str:
    """Build, sign, broadcast. Returns broadcast txid."""

async def send_max(self, to_address, client, *, fee_rate=None) -> str:
    """Sweep entire wallet balance. Returns broadcast txid."""
```

These mirror the `RxdWallet` pattern. Internally:
- Collect spendable UTXOs across all known external + internal addresses (the existing `addresses` dict from `refresh()`).
- Look up the corresponding signing key for each UTXO via `_xprv.derive(change/index)`.
- Build inputs with `unlocking_script_template = P2PKH().unlock(privkey)`.
- Pick change address: next unused internal index by default (the existing scan tracks `internal_tip`).
- Compute fee with the existing two-pass pattern: trial-sign → measure bytes → rebuild with real change.
- Reset all input `unlocking_script` values between passes (the stale-signature pitfall documented in `tests/test_preimage.py`).

This is ~150 lines following the exact pattern in `RxdWallet`. No novel cryptography — multi-key UTXO assembly only.

The send code is purely additive; it doesn't touch any existing method. New code lives at the bottom of the class. Existing save/load/encryption/scan paths are not modified.

### CLI layer (all new)

Files under `src/pyrxd/cli/`:

```
src/pyrxd/cli/
  __init__.py          # package marker
  __main__.py          # `python -m pyrxd` entry; defers to main:cli
  main.py              # @click.group, top-level entry, global options
  context.py           # CliContext dataclass — holds network, fee_rate, json/quiet flags, wallet path, electrumx URL
  format.py            # output helpers: human/JSON/quiet modes, photon formatting, color
  errors.py            # CLI-side exception types + exit-code mapping
  prompts.py           # confirmation prompts, mnemonic display with Enter gate
  config.py            # ~/.pyrxd/config.toml read/write
  wallet_cmds.py       # @cli.group: wallet new, wallet load, wallet info, wallet export-xpub
  glyph_cmds.py        # @cli.group: glyph mint-nft, deploy-ft, transfer-ft, list, init-metadata
  query_cmds.py        # bare commands: address, balance, utxos
  setup_cmd.py         # `pyrxd setup` — onboarding flow
```

Tests under `tests/cli/`:

```
tests/cli/
  __init__.py
  conftest.py          # fixtures: tmp_path-based wallet dir, mocked ElectrumX, fake config
  test_main.py         # top-level: --help, --version, unknown subcommand, --json flag plumbing
  test_format.py       # snapshot tests for default/JSON/quiet output
  test_prompts.py      # mnemonic display gate, confirmation flow, --yes bypass
  test_config.py       # config.toml read/write, precedence (flags > env > config > defaults)
  test_wallet_cmds.py
  test_glyph_cmds.py
  test_query_cmds.py
  test_setup_cmd.py
```

### Tooling wire-up (small touches)

- `pyproject.toml`: add `[project.scripts]` entry for `pyrxd = "pyrxd.cli.main:cli"`. One section, no risk to anything else.
- `pyproject.toml`: add `click = "^8.1"` to `[tool.poetry.dependencies]`.
- `src/pyrxd/__init__.py`: re-export `RxdWallet` and `HdWallet` so `from pyrxd import RxdWallet` works.
- `README.md`: add a "CLI quick start" section after the existing Python quick start. Do not remove the Python examples.
- `docs/how-to/cli.md` (new): full CLI reference.

## Command surface

The `pyrxd` CLI is verb-first. Global flags apply to every subcommand.

### Global flags

```
--network {mainnet,testnet,regtest}   default: mainnet
--electrumx URL                       override; otherwise from config or built-in default
--wallet PATH                         path to encrypted HdWallet file (default: ~/.pyrxd/wallet.dat)
--json                                machine-readable output
--quiet                               suppress progress; print only the bare result
--no-color                            disable ANSI color
--config PATH                         alternate config file
--yes / -y                            skip confirmation prompts (required for `--json` on destructive ops)
```

### Wallet management

```
pyrxd wallet new [--mnemonic-words 12|24] [--passphrase-prompt]
    Generate a fresh BIP39 mnemonic + HdWallet. Prints mnemonic ONCE,
    waits for Enter, then saves the encrypted wallet to --wallet path.

pyrxd wallet load
    Validate that an existing wallet decrypts. Prompts for mnemonic
    (hidden via getpass).

pyrxd wallet info
    Print account index, address counts, last-used external/internal
    indices. No network.

pyrxd wallet export-xpub
    Print the account-level xpub (m/44'/236'/<account>') for watch-
    only use. No private key material.
```

### Address & balance (light wallet ops)

These exist not because pyrxd should replace `radiant-cli`, but because a user with no node still needs the basics to onboard. They're the minimum surface to go from "fresh install" to "I have an address and know my balance." Spending is intentionally not in this set — see scope notes above.

```
pyrxd address [--next | --index N] [--change]
    --next       (default) next unused external receive address
    --index N    deterministic index lookup
    --change     internal chain instead of external

pyrxd balance [--refresh]
    Print confirmed/unconfirmed photon balance across the wallet.
    --refresh first triggers a gap-limit scan via ElectrumX.

pyrxd utxos [--min-photons N] [--addr ADDRESS]
    List UTXOs (table or --json). Read-only diagnostic.
```

### Glyph operations

This is where pyrxd differentiates. None of these have node-wallet equivalents.

```
pyrxd glyph init-metadata [--type {nft,ft,dmint-ft,mutable,container}] [--out FILE]
    Scaffold a metadata.json template appropriate for the token type.
    Default writes to stdout; --out writes to a file.

pyrxd glyph mint-nft <metadata.json>
    Two-tx commit/reveal NFT mint. Polls confirmation between txs.
    Prompts for confirmation before each broadcast unless --yes.

pyrxd glyph deploy-ft <metadata.json> --supply N --treasury ADDRESS
    Deploy an FT premine. Single recipient receives the entire supply
    at vout[0] of the reveal tx.

pyrxd glyph transfer-ft <ref> <amount> --to ADDRESS
    Transfer FT units of <ref> (txid:vout) to ADDRESS. Builds a
    conservation-enforcing transfer via FtUtxoSet.

pyrxd glyph transfer-nft <ref> --to ADDRESS
    Transfer an NFT singleton.

pyrxd glyph list [--type {nft,ft}]
    Scan wallet addresses for Glyph holdings via GlyphScanner.
    Default human table; --json for scripting.
```

### Onboarding

```
pyrxd setup
    Interactive walkthrough:
      1. Detect Radiant Core node locally; if missing, print install steps.
      2. Detect ElectrumX in config; if missing, list known public servers.
      3. Detect a wallet in --wallet path; if missing, run `pyrxd wallet new`.
    Goal: takes a fresh install to "ready to mint a Glyph" in <5 minutes
    without bundling anything.
```

### Confirmation prompts

Every command that broadcasts (or builds-and-broadcasts) prints a summary and asks `y/N` before sending. The summary always shows:
- net amount out
- fee
- recipient
- change address
- network

Skip with `--yes`. With `--json` (machine-readable mode), `--yes` is **required** for destructive ops; otherwise the command exits with code 1 and prints `error: --json requires --yes for destructive operations`.

### Exit codes

```
0   success
1   user-error (bad input, file not found, insufficient funds, missing --yes in JSON mode)
2   network error (couldn't reach ElectrumX, broadcast rejected)
3   wallet decryption failed
4   unexpected error (bug — should not happen)
```

## Configuration

`~/.pyrxd/config.toml`, created on first run:

```toml
network = "mainnet"
electrumx = "wss://electrumx.radiant4people.com:50022/"
fee_rate = 10000          # photons/byte
wallet_path = "~/.pyrxd/wallet.dat"

[networks.testnet]
electrumx = "wss://testnet-electrumx.example.com/"
```

Precedence (highest wins): CLI flags > environment variables (`PYRXD_*`) > config file > built-in defaults.

Storage permissions: `~/.pyrxd/` is `0700`, `wallet.dat` is `0600`, matching the existing `HdWallet.save()` invariants.

## Mnemonic UX

`pyrxd wallet new`:

1. Generate the mnemonic with `secrets`-backed entropy (existing `from_mnemonic` path).
2. Print the mnemonic to stdout **once**, in a clearly-flagged box:
   ```
   ╔════════════════════════════════════════════════════════════╗
   ║ Recovery mnemonic — write this down, then never share it.  ║
   ║ pyrxd will NOT show this again.                            ║
   ╚════════════════════════════════════════════════════════════╝

   word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12

   Press Enter once you have written it down.
   ```
3. Wait for Enter.
4. Optionally prompt for a BIP39 passphrase (can be empty; never echoed).
5. Save the wallet to `--wallet` path with `0600` permissions.

`pyrxd wallet load`:

- Prompts for mnemonic (input hidden via `getpass`).
- Decrypts; on failure exits with code 3 and a generic message — never echoes the user's input.

The user is responsible for terminal hygiene (no shared screens, no `tee`/`grep` piping). We document this clearly. See [`wallet-cli-decisions.md`](wallet-cli-decisions.md) §6 for why we didn't go with a temp file.

## Output formats

Default output is human-readable, narrow-terminal-friendly:

```
$ pyrxd balance
Address     1A2b3c...xyz (next receive: 1X9y8z...abc)
Confirmed   1,234,567,890 photons (12.34567890 RXD)
Unconfirmed 0 photons
```

`--json` produces structured output for scripting:

```json
{
  "network": "mainnet",
  "address": "1A2b3c...",
  "next_receive": "1X9y8z...",
  "confirmed_photons": 1234567890,
  "unconfirmed_photons": 0
}
```

`--quiet` suppresses everything except the bare result of the command. For `pyrxd send` (when added) it prints the txid; for `pyrxd balance` it prints just the confirmed photon count.

## Error messages

The CLI is the user's first impression. Every error follows this pattern:

```
error: <short description>
  cause: <what went wrong, with sensitive values redacted>
  fix: <one-line concrete next step>
```

Example:

```
error: insufficient funds
  cause: requested 100,000,000 photons but wallet has 50,000,000 confirmed
  fix: try a smaller amount or wait for unconfirmed deposits to confirm
```

The library still raises typed exceptions (`ValidationError`, `NetworkError`, `KeyMaterialError`). The CLI catches them at the boundary and reformats. Raw Python tracebacks never reach the user unless they pass `--debug`.

## Testing strategy

- **Unit tests (most of the budget):** each command is a click callable. Tests use `click.testing.CliRunner` with a mocked `CliContext` (mocked ElectrumX, tmp_path-backed wallet dir, fake config). No network, no real keys, no real filesystem.
- **End-to-end fixture tests:** spawn the CLI as a subprocess against a fake ElectrumX server. Cover the happy path of `wallet new`, `wallet load`, `address`, `balance`, `glyph mint-nft`.
- **Snapshot tests for output formatting:** small fixtures, render in all three modes (default / `--json` / `--quiet`), compare to checked-in snapshot files. Catches accidental output changes early.
- **Coverage target:** 90%+ on `pyrxd/cli/`. This is what users see first; a regression here is highly visible.
- **Existing test suite:** all 2051 existing tests must still pass after `HdWallet.send()` is added.

## Phasing (three cuts, three PRs)

### Cut 1: foundation — first PR

The minimum viable CLI that demonstrates the architecture works end-to-end. Lands first; subsequent cuts can ship after it stabilizes.

In scope:
- `HdWallet.send()`, `send_max()`, `build_send_tx()`, `build_send_max_tx()` (library — used internally by glyph deploy-ft / transfer-ft for change handling).
- CLI infrastructure: `main.py`, `context.py`, `format.py`, `prompts.py`, `errors.py`, `config.py`.
- Subcommands: `wallet new`, `wallet load`, `wallet info`, `address`, `balance`.
- All tests for the above.
- `[project.scripts]` entry, `pyproject.toml` click dep, `__init__.py` re-exports.
- README CLI section, `docs/how-to/cli.md` skeleton.

Out of scope for Cut 1: glyph commands, utxos command, setup command, export-xpub.

### Cut 2: glyph commands — second PR

The differentiation. Adds:
- `glyph init-metadata`, `glyph mint-nft`, `glyph deploy-ft`, `glyph transfer-ft`, `glyph transfer-nft`, `glyph list`.
- All tests for the above.
- `docs/how-to/cli.md` glyph section.
- README example: "mint your first NFT" walkthrough.

### Cut 3: polish + onboarding — third PR

Quality-of-life additions:
- `pyrxd setup` interactive flow.
- `pyrxd utxos`, `pyrxd wallet export-xpub`.
- Shell completion script (click can generate it; ship it as `share/completion/pyrxd.bash`).
- Migration helper: detect `~/.pyrxd/` from older versions, upgrade format if needed.

Cuts can ship as separate PRs over multiple weeks. Cut 1 alone is releasable as v0.3.0; Cuts 2 and 3 land as v0.3.1 and v0.3.2 (or a single v0.3 release if all three are ready in time).

## Risk assessment

### Risks

1. **Click ergonomics turn out to feel heavy as the surface grows.** Mitigation: Cut 1 is the test. If subcommand modules feel cluttered, refactor before Cut 2.
2. **The `HdWallet.send()` edit introduces a regression.** Mitigation: pure additive code, all 2051 existing tests must stay green, plus new send-specific tests.
3. **Mnemonic display has a UX flaw on a platform we don't test (Windows? VS Code terminal?).** Mitigation: document the box-drawing fallback for terminals that can't render Unicode. Test on macOS/Linux/Windows in CI.
4. **Users miss the "this is Glyph-focused, not a full wallet" framing and ask "where's `pyrxd send`?"** Mitigation: `pyrxd --help` top-level message and README explicitly call this out. If the question becomes recurring after Cut 2, add a basic `pyrxd send` in v0.3.x.
5. **`pyrxd setup` interactive prompts surprise CI users.** Mitigation: every prompt has a non-interactive fallback (env var or flag); `pyrxd setup --no-interactive` skips and just emits a config file.

### What we're explicitly accepting

- Some users with nodes will install pyrxd and find it doesn't have `pyrxd send`. That's fine — they can use `radiant-cli sendtoaddress`. The README will say so.
- Users without nodes have to use `pyrxd glyph deploy-ft` (etc.) which internally handles RXD; they don't need `pyrxd send` because their flows are token-centric.
- Power-user features like multi-account, watch-only mode, hardware wallet, gravity subcommands are deferred to v0.4+.

## Estimated effort

- Cut 1: ~3-5 days of focused work. Most of the time is in formatting, error messages, and tests; the actual command logic is thin.
- Cut 2: ~3-5 days. Glyph subcommands are more complex (commit/reveal, two-tx flows, scan integration) but each maps directly to existing builder methods.
- Cut 3: ~2-3 days. Polish work; smaller scope per item.

Total: ~8-13 working days for the full v0.3 wallet/CLI release.

## Open implementation questions

These are details to settle while writing code, not show-stoppers:

1. **Click `Context.obj` vs. dataclass passed explicitly?** Click's idiom is `Context.obj`. Keeping a custom `CliContext` dataclass and passing it explicitly is more testable. **Lean: explicit dataclass, even if it costs a bit of click idiom.**

2. **How does `pyrxd setup` know if a Radiant Core node is "available"?** Probe `127.0.0.1:7332` (default RPC port) with a `getblockchaininfo` call? Look for `~/.radiant/`? **Lean: try the RPC probe with a 1s timeout; only fall back to filesystem hints if the user opts in.**

3. **Confirmation prompts in `--quiet` mode?** `--quiet` is for output. Prompts are user input. They're orthogonal — `--quiet` doesn't suppress prompts. Document this clearly.

4. **`pyrxd glyph init-metadata` output: pretty-printed or canonical?** Pretty-printed for human readability (this is a scaffold, not on-chain bytes). The actual on-chain CBOR encoding stays canonical.

5. **Where does `pyrxd glyph deploy-ft` get its funding UTXO?** Same wallet that signs the deploy. Sweep enough RXD via `HdWallet`'s utxo selection. Document the minimum funding requirement.

These get answered during Cut 1 implementation by writing the code.
