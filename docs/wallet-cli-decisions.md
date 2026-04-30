# Wallet CLI: approved decisions

**Status:** all six decisions approved 2026-04-30. Records the rationale for future contributors.

Companion to [`wallet-cli-plan.md`](wallet-cli-plan.md), [`radiant-core-wallet-research.md`](radiant-core-wallet-research.md), and [`scope-decision-2026-04-30.md`](scope-decision-2026-04-30.md).

This doc records *why* each choice was made, with the alternative laid out, so we don't relitigate them.

---

## 1. CLI library: `click` (vs. stdlib `argparse`)

**Approved: `click`.**

### Why
- 30%+ less plumbing code per subcommand. The plan has 12+ subcommands across 3 cuts; the boilerplate tax compounds.
- `click.testing.CliRunner` gives clean, in-process test invocations — no subprocess spawning needed for unit tests.
- Built-in `click.confirm`, `click.prompt(hide_input=True)`, `click.progressbar` — small but real wins for the wallet UX (mnemonic prompts, broadcast confirmations).
- Native shell completion generation (`pyrxd --install-completion bash|zsh|fish`).
- Maintained by Pallets (Flask team), well-trusted in the Python ecosystem. No notable security history.
- Two transitive deps: `colorama` (Windows ANSI shim) and historically `importlib_metadata` (no longer needed on 3.10+). Effectively one runtime dep.

### Why not `argparse`
- Zero new deps, but the security argument was overstated — `click`'s dep tree is small and well-maintained.
- More verbose to write, especially for nested subcommands.
- Plain `--help` output with no color or grouping.
- No built-in shell completion.

### Conditions to revisit
- A pinning-incompatible click 9.x release that requires significant rewrites. Unlikely; click has been stable since 7.x.
- A discovered security issue in click. We track upstream advisories.

---

## 2. Single `pyrxd` binary (vs. multiple binaries per concern)

**Approved: one `pyrxd` binary with subcommand verbs.**

### Why
- Modern CLI convention: `git`, `gh`, `kubectl`, `cargo`, `solana` — all single-binary with subcommand verbs.
- Easier discoverability: `pyrxd --help` lists every capability in one place.
- Cross-cutting global flags (`--network`, `--wallet`, `--json`) defined once.
- Simpler `[project.scripts]` config — one entry point.

### Why not multi-binary
- Theoretical smaller attack surface per binary. In practice, all the code lives in one wheel anyway.
- Marginally faster startup if each binary imports a subset of modules. ~50ms savings; not material for an interactive CLI.

### Conditions to revisit
- pyrxd grows multiple unrelated CLI personas (e.g. a node-operator binary + a developer-tools binary). At that point, `pyrxd-dev` and `pyrxd-ops` could be separate. Not v0.3.

---

## 3. `--json` and confirmation prompts: independent

**Approved: `--json` requires explicit `--yes` for destructive ops; otherwise `--json` errors.**

### Why
- "Quiet output" and "skip confirmation" are different user intents. A user piping to `jq` in a test environment has the first. A scripted production deploy with silent broadcast wants both.
- Conflating them would surprise one of those users; `--json` implying `--yes` is too easy to invoke accidentally with mainnet RXD.
- Pattern matches `gh pr merge --json` in GitHub CLI: format and consent are separate axes.

### Why not the alternatives
- `--json` implies `--yes` (auto-confirm): risky. Someone runs `pyrxd send <addr> 100000000 --json` expecting "give me JSON about whether this would work" and instead broadcasts.
- `--json` always asks (ignores prompts): unworkable. Most CI environments can't answer prompts; `--json` + CI workflows would be impossible.

### Conditions to revisit
- Strong user feedback that two flags is annoying. We could revisit by making `--yes` implicit only for non-broadcast commands (`pyrxd balance --json` is fine without `--yes`; `pyrxd send --json` requires it). The plan already has this nuance.

---

## 4. Glyph metadata input: file only, with scaffold helper

**Approved: `pyrxd glyph init-metadata` scaffolds a template; mint commands consume the file.**

### Why
- `GlyphMetadata` has ~20 fields including nested objects (creator, royalties, policy, rights). An inline-flag CLI for the full surface would be unmaintainable.
- Metadata is content the user authors carefully — a file matches that workflow (author once, version-control, mint).
- `init-metadata` removes the friction of writing a full metadata.json from scratch. The scaffold pre-fills sensible defaults appropriate to the token type.

### Why not inline flags
```
pyrxd glyph mint-nft --name "MyNFT" --description "..." --image-url "..." \
  --image-sha256 "..." --to <addr> --commit-fee-rate 10000
```
Already 6 flags, missing royalty/policy/rights. At least 12 more for full coverage. Fragile, hard to document, easy to typo.

### Why not hybrid (file + override flags)
- Doubles the doc surface.
- Precedence rules ("flag overrides file") become a thing users have to learn.
- Not a clear win over "edit the file" for the cases where users want different values.

### Conditions to revisit
- A specific common-case where a single flag would obviously help (e.g. `--to ADDRESS` ergonomically overriding the metadata's `owner_pkh`, since the recipient is more about the transaction than the metadata). We can add narrowly-scoped flags as needs prove out.

---

## 5. Default network: mainnet, with confirmation prompts

**Approved: mainnet by default; every destructive command prompts unless `--yes`.**

### Why
- Most users running `pip install pyrxd` are evaluating mainnet RXD.
- Forcing `--network mainnet` on every command is friction with no protection benefit — users memorize the flag immediately and the safety becomes theatrical.
- The real safety is the confirmation prompt + summary screen showing actual amount and network. That works regardless of default.
- Other Bitcoin-like CLIs (`bitcoin-cli`, `bcoin`) default to mainnet.

### Why not testnet default
- "Did I just send mainnet RXD by mistake?" is a real concern, but the answer is the prompt and summary, not the default network.
- Testnet-default trains users to type `--network mainnet` mechanically — at which point the safety is gone.

### Conditions to revisit
- A documented incident where the prompt failed and a user broadcast unintended mainnet RXD. We'd then strengthen the prompt logic, possibly add a per-network confirmation phrase ("type MAINNET to confirm"). Not the default flip.

---

## 6. Mnemonic display: stdout with Enter gate (vs. temp file)

**Approved: stdout with a clearly-flagged box, Enter gate, "will not be shown again" warning. Temp file rejected.**

### Why
- Simplest model. User sees mnemonic, presses Enter, moves on.
- No filesystem cleanup concerns, no tempfile attack surface.
- Composable with shell redirection if power user wants to write directly to a file via `>`.
- The display always-shows-once + Enter gate prevents accidental scrollback if the user is paying attention.

### Why not temp file
- Gives a feeling of safety without substance — the mnemonic still has to be displayed somewhere for the user to write down. The display happens on stdout regardless.
- Adds attack surface (file persists if `Ctrl-C` before unlink, page cache may keep contents after deletion, `/tmp` may be on tmpfs or disk depending on system).
- Doesn't prevent terminal scrollback / tmux / screen-share exposures any better than stdout does.

### Cons we accept
- Doesn't protect against terminal scrollback, tmux/screen buffers, or screen-sharing. We document this clearly: "do not run `pyrxd wallet new` in a shared terminal, in tmux without scrollback off, or while screen-sharing."

### Conditions to revisit
- A real-world incident where the scrollback exposure caused a key compromise. Mitigations would be: optional `--clear-scrollback` flag (best-effort `printf "\033c"`), or a confirmation prompt before display ("type CONTINUE to view mnemonic"). Not in v0.3.

---

## How these decisions interact

The six choices above produce a consistent product:

- **A modern Bitcoin-style CLI**, focused on Glyph operations.
- **Predictable scripting**: `--json` and `--yes` are independent and explicit.
- **Sane defaults**: mainnet, file-driven complex data, confirmation prompts for everything destructive.
- **Low dependency surface**: one new runtime dep (`click`), no node bundling, no UI bundling.
- **Testable**: click's `CliRunner` + dataclass-based context = clean unit tests.

The biggest single risk in this configuration is **decision 1** — if click's ergonomics feel heavy after Cut 1, we'd want to reconsider before Cut 2. The plan calls this out as an explicit checkpoint.

## What this doc deliberately doesn't cover

- The narrower **scope** of the CLI (Glyph-focused vs. full-wallet-replacement) — that's [`scope-decision-2026-04-30.md`](scope-decision-2026-04-30.md).
- The detailed **command surface** and **phasing** — that's in [`wallet-cli-plan.md`](wallet-cli-plan.md).
- The **research** that informed the scope decision — that's [`radiant-core-wallet-research.md`](radiant-core-wallet-research.md).

These four docs together make the v0.3 wallet/CLI plan complete: research → scope decision → implementation plan → implementation choices.
