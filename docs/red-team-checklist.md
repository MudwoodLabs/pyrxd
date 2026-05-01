# pyrxd red-team checklist

**Purpose:** a focused half-to-full-day adversarial review of the pyrxd v0.3 wallet/CLI surface. The threat model (`docs/threat-model.md`) describes what we *intend* to protect; this checklist exercises whether the implementation actually does.

**How to use it:**

1. Block out 4-8 hours. Treat it like a separate task, not part of feature work.
2. Open three terminals: one running `pyrxd` commands, one with `git` + `gh issue create`, one with a model (Sonnet recommended) for "what edge case am I missing on this section?"
3. Work through the sections in order. Each one has explicit commands, expected outcomes, and a "what to file" pattern.
4. **File a GitHub issue for everything weird, even if you're not sure it's a bug.** Better to overproduce issues and close them than to lose findings.
5. Mark items DONE as you go. Don't skip — the boring sections often surface things.

**What this checklist is NOT:**

- A pen-test. We're not trying to find zero-days; we're trying to surface footguns and broken-promises.
- A substitute for fuzz testing (issue #10) or a third-party audit.
- A one-time activity. Re-run before each minor release with the diff in mind.

---

## 0. Pre-flight (10 min)

- [ ] Pull latest main: `git pull origin main`
- [ ] Confirm full test suite green locally: `PYTHONPATH=src python -m pytest tests/ -q`
- [ ] Confirm ruff + bandit clean: `ruff check src tests examples && bandit -r src/ -c pyproject.toml --quiet`
- [ ] Build a fresh venv specifically for this session so module state can't bleed between commands
- [ ] Set `PYRXD_WALLET_PATH=/tmp/redteam-$(date +%s)/wallet.dat` so all wallet ops happen in a throwaway dir
- [ ] Have `gh issue create` ready (or open https://github.com/MudwoodLabs/pyrxd/issues/new in a browser)

---

## 1. Mnemonic exposure surface (60-90 min)

This is the highest-stakes section. The mnemonic is the master key; any path that exposes it is a finding.

### 1.1 Stdout / stderr leakage

- [ ] Run `pyrxd wallet new --json --yes` and check that the mnemonic appears in stdout (expected) and NOT in stderr.
- [ ] Run `pyrxd wallet new --json --yes 2>/dev/null` and confirm the mnemonic still emits to stdout.
- [ ] Run `pyrxd wallet new --json --yes >/dev/null` and confirm stderr is silent (no mnemonic on the unredirected stream).
- [ ] Run `pyrxd wallet new` (interactive) and confirm the mnemonic appears once, in the box, and waits for Enter.
- [ ] After the Enter, scroll up in the terminal — confirm the mnemonic is still visible (this is expected; we don't clear scrollback). File issue if the user has no warning about this.
- [ ] Run `pyrxd wallet new` then immediately `pyrxd wallet new` (second one should fail with "already exists"). Confirm the second invocation does NOT generate a new mnemonic and abort, only to leak it via stderr or anywhere else. The fast-fail before mnemonic generation is the safety property.

### 1.2 Failure-mode leakage

- [ ] Run `pyrxd wallet load` and enter a known-wrong mnemonic. Confirm the error message says "Could not decrypt" without echoing your input.
- [ ] Same with `--debug`. Confirm the traceback shows function names and source lines but never your input value.
- [ ] Try a mnemonic with only 11 words. Confirm rejection. Check that error doesn't echo the partial input.
- [ ] Try a mnemonic where one word is misspelled (e.g., `aboutt` instead of `about`). Confirm rejection. Check that error doesn't echo the misspelling.
- [ ] Try a mnemonic with leading/trailing whitespace. Should normalize and succeed (if the rest is valid).

### 1.3 Storage leakage

- [ ] Inspect `wallet.dat` after creation: `file /tmp/.../wallet.dat`. Confirm not human-readable (encrypted blob).
- [ ] Inspect with `xxd | head -5` or similar. Confirm no plaintext mnemonic words appear.
- [ ] `stat -c '%a' /tmp/.../wallet.dat` should show 600.
- [ ] `stat -c '%a' /tmp/.../` (the parent dir) — note the mode. If the test creates a wider parent, that's a finding for `pyrxd setup` defaults.
- [ ] After running `pyrxd address`, check `~/.bash_history` (or your shell equivalent). The command should be there but no mnemonic.
- [ ] Search for any tempfiles under `/tmp` containing mnemonic words after a `wallet new`: `grep -rl "abandon abandon" /tmp 2>/dev/null` (with whatever first two words you got). Should be nothing.

### 1.4 Network leakage

- [ ] Run `pyrxd balance --refresh` against a wallet, capture the websocket traffic with `tcpdump` or by pointing `--electrumx` at a logging mock. Confirm the mnemonic NEVER appears in any outbound bytes. (Only address derivations / script hashes should go over the wire.)
- [ ] Same for `pyrxd glyph list`.

### 1.5 Memory leakage (best-effort, hard to verify)

- [ ] Add a `print(repr(wallet))` somewhere temporarily and confirm the mnemonic / seed don't appear in the dataclass repr.
- [ ] Use `gc.get_objects()` after a `wallet new` and grep for known mnemonic words. (Will probably find them — `SecretBytes.zeroize()` is best-effort.) File a "doc / known-limit" issue rather than a fix issue.

**File issues for:** any path where the mnemonic shows up somewhere it shouldn't, including pytest output captures, logs, or response bodies.

---

## 2. Wallet file integrity & permissions (30-45 min)

### 2.1 File mode enforcement

- [ ] Create a wallet, then `chmod 0644 /tmp/.../wallet.dat`, then try `pyrxd wallet load`. Confirm explicit refusal with a chmod-fix message.
- [ ] Same with 0o755 and 0o777.
- [ ] Set 0o400 (read-only owner). Should still work — the check is for group/other read bits, not write bits.

### 2.2 Tampering

- [ ] Edit one byte in the middle of the encrypted ciphertext (`dd if=/dev/zero of=wallet.dat bs=1 count=1 seek=200 conv=notrunc`). Try to load. Should fail with "Could not decrypt" — AES-GCM tag check should catch this.
- [ ] Truncate the file to half its size. Try to load. Should fail with a clean error.
- [ ] Create an empty file, mode 0o600. Try to load. Should fail with "too short" or similar.
- [ ] Create a file with the v2 version byte but garbage afterwards. Should fail with decrypt error.

### 2.3 Atomic-write guarantees

- [ ] In one terminal, run `pyrxd wallet new` interactively to the Enter gate. Don't press Enter.
- [ ] In another terminal, check what's in `~/.pyrxd/`. Should be nothing yet (mnemonic-display happens before save).
- [ ] Press Enter to complete. Save happens. Now repeat the wallet new flow but Ctrl-C after the gate but before the save completes (small window). Check that no half-written wallet.dat exists.

### 2.4 Cross-platform

- [ ] (If you have access) Run on macOS — confirm mode-check still fires.
- [ ] (If you have access) Run on Windows / WSL — confirm the mode check is skipped (we documented this) and the wallet works.

**File issues for:** any path where wallet load succeeds with a file it shouldn't, or fails with a file it should accept.

---

## 3. CLI input fuzzing (manual fuzz, 30-45 min)

This is a sampler; full coverage is issue #10.

### 3.1 Mnemonic input

- [ ] Mnemonic with NUL bytes: `printf "abandon\x00abandon..." | pyrxd wallet load`
- [ ] Mnemonic >10MB (paste a wall of text). Should be rejected without crashing.
- [ ] Mnemonic with mixed-case (`Abandon Abandon ...`). Should normalize to lowercase via the BIP39 wordlist or fail cleanly.
- [ ] Mnemonic with non-ASCII bytes. Should be rejected without crashing.

### 3.2 Address arguments

- [ ] `pyrxd glyph deploy-ft meta.json --supply 1000 --treasury "$(python -c 'print("A"*1000)')"`. Should reject without crashing.
- [ ] Address with leading/trailing whitespace. Probably accepted — test what it does.
- [ ] Address with embedded null. Reject cleanly.

### 3.3 Numeric arguments

- [ ] `--supply -1`. Should reject.
- [ ] `--supply 0`. Should reject.
- [ ] `--supply 99999999999999999999999999999`. Click should reject as "not an int" or pyrxd should reject as out-of-range.
- [ ] `--fee-rate 0`, `--fee-rate -1`. Should reject (we already test this in unit tests).

### 3.4 Path arguments

- [ ] `--wallet "/etc/passwd"`. The load path will fail (mode check / not a wallet file). Confirm the error doesn't expose contents.
- [ ] `--wallet "../../../etc/passwd"`. Path traversal — should be rejected by file-existence check or by mode check.
- [ ] `--config /dev/zero`. Should fail cleanly, not hang reading infinite bytes.

### 3.5 Argument combinations

- [ ] `pyrxd --json --quiet wallet new`. Already rejected (mutually exclusive); confirm.
- [ ] `pyrxd --json wallet new` (no `--yes`). Already rejected; confirm.
- [ ] `pyrxd --json --yes wallet new --mnemonic-words 13`. Click rejects "13" as not in the choice list; confirm.
- [ ] All flags after the subcommand: `pyrxd wallet new --json --yes`. Click handles this; confirm output is clean.

**File issues for:** any input that crashes (uncaught traceback at exit code 4, not 1/2/3) or that produces an exit code that doesn't match the docs.

---

## 4. Network failure modes (45-60 min)

### 4.1 ElectrumX unreachable

- [ ] `pyrxd --electrumx wss://does-not-exist.example/ balance --refresh`. Should fail with NetworkError, exit code 2, fix-suggestion mentions the URL.
- [ ] `pyrxd --electrumx ws://localhost:50001/ balance` (insecure scheme without flag). Should reject before trying to connect.
- [ ] `pyrxd --electrumx http://example.com/ balance`. Wrong scheme. Should reject.
- [ ] Drop your network connection mid-`balance --refresh`. Confirm timeout, clean error.

### 4.2 ElectrumX returns garbage

This needs a mock; consider running `examples/`-style tests or building a `nc` listener. For a quick smoke test:

- [ ] In one terminal: `nc -l 50022` (or use openssl s_server for TLS). Send arbitrary bytes when `pyrxd` connects.
- [ ] In another: `pyrxd --electrumx ws://localhost:50022/ --network mainnet balance` (with `--allow-insecure`-equivalent if pyrxd had one — current code rejects `ws://` without a flag).
- [ ] Confirm pyrxd doesn't crash, hangs, or expose internals when given non-JSON-RPC bytes.

### 4.3 Slow / unresponsive ElectrumX

- [ ] Point pyrxd at a slow loopback that holds the connection open without responding. Confirm there's a timeout, not an indefinite hang.

### 4.4 Bitcoin data source (Gravity tangential)

- [ ] If you have credentials, point a Gravity flow at a deliberately-wrong `mempool.space` URL. Confirm clean error.

**File issues for:** crashes (exit code 4), indefinite hangs, or any error path that leaks an internal trace without `--debug`.

---

## 5. Glyph metadata trust (30 min)

Threat scenario S7 from the threat model. As-shipped, the broadcast summary now includes a `_metadata_summary` section, so verify it does what we want.

### 5.1 Metadata visibility in confirmation

- [ ] `pyrxd glyph init-metadata --type ft --out /tmp/ft.json`
- [ ] Edit the file: change `name` to "ATTACKER NFT", set `description` to something obvious.
- [ ] Run `pyrxd glyph deploy-ft /tmp/ft.json --supply 100 --treasury <some addr>` (use a fake-but-valid-shape addr if not testing on chain).
- [ ] At the confirmation prompt, confirm the "Metadata" section shows the modified name and description. Abort the broadcast.
- [ ] Repeat with a metadata file that has a `creator` block (manually added). Confirm `creator: pubkey=...` appears in the summary.
- [ ] Repeat with a `royalty` block. Confirm royalty bps and address appear, and any splits appear with their own bps.

### 5.2 Metadata that triggers validation errors

- [ ] Edit a metadata file to have `protocol: ["NFT", "FT"]`. Should reject (mutually exclusive).
- [ ] Edit `decimals: -1` or `decimals: 19`. Should reject (out of range).
- [ ] Edit `image_sha256: "not-hex"`. Should reject (not 64 lowercase hex).
- [ ] Edit `protocol: ["AUTHORITY"]` (no NFT). Should reject (AUTHORITY requires NFT).

### 5.3 Metadata size

- [ ] Create a metadata.json with a multi-megabyte `description`. Should be rejected at parse or at CBOR-encode time.
- [ ] Create a metadata.json with 100 attrs. Already capped at 64; confirm rejection.

**File issues for:** any metadata edit that gets through without showing in the summary, or any reject path that doesn't surface the metadata's offending field.

---

## 6. Confirmation prompts and abort behavior (15 min)

- [ ] `pyrxd glyph mint-nft meta.json` → at the confirmation prompt, type "n". Confirm clean abort with exit code 1, no broadcast.
- [ ] Same but Ctrl-C the prompt. Should be a clean abort.
- [ ] Same but pipe `echo "n" |` to skip interactivity. Confirm abort, no surprises.
- [ ] `pyrxd glyph mint-nft --json --yes meta.json` (no wallet present so it'll fail before broadcast anyway, but verify the `--yes` is accepted).

**File issues for:** any prompt that ignores the "n" answer, or that causes a partial-broadcast on Ctrl-C.

---

## 7. Setup command sanity (15 min)

- [ ] `pyrxd setup --no-interactive` on a fresh user account. Should write config without prompting.
- [ ] `pyrxd setup` on a system with no Radiant Core node. Status should show "node: NOT reachable" and provide ElectrumX as a next step.
- [ ] `pyrxd setup` on a system with Radiant Core running. Status should show "node: reachable."
- [ ] `pyrxd --quiet setup --no-interactive` should print "todo" or "ok" only.

**File issues for:** misleading status messages or next-steps that don't match the actual state.

---

## 8. Concurrent / race conditions (30 min)

- [ ] Run two `pyrxd wallet new` in parallel against the same `--wallet` path. Whoever wins should win cleanly; the loser should fail with "already exists" not corrupt state.
- [ ] Run `pyrxd balance --refresh` while another process is editing the same wallet's address dict (via `pyrxd address`, which adds an unused-receive entry). Confirm one of: success, clean error, no corruption.
- [ ] `pyrxd setup --no-interactive` twice in parallel. Should be idempotent.

**File issues for:** any data corruption observed, or any error message that misrepresents what happened.

---

## 9. Documentation / READMEclaims-vs-reality (15 min)

For each claim in README.md, confirm the actual command behaves as advertised:

- [ ] "Mnemonic shown ONCE — write it down" → confirm not shown again on subsequent runs.
- [ ] "ElectrumX async client with reconnect" → kill an established websocket, confirm pyrxd reconnects (or fails cleanly with a documented error).
- [ ] "RXD send / send-max" → both work via `RxdWallet` and `HdWallet`.
- [ ] "Glyph FT premine deploy via prepare_ft_deploy_reveal" → matches what the CLI's `glyph deploy-ft` does.
- [ ] "Encrypted persistence (HdWallet)" → file is encrypted, mode-checked, GCM-tagged.

**File issues for:** any documented capability that doesn't match the code.

---

## After the session

- [ ] Total issues filed: count them. Aim for at least 5; if you have zero, you didn't look hard enough.
- [ ] Triage: tag each as `bug`, `enhancement`, `documentation`, or `wontfix`.
- [ ] Update this checklist with any sections that turned out to be useless or any new sections you wished existed.
- [ ] Add a note in `CHANGELOG.md` (in the "Unreleased" section, if it exists, or just at the top): "Red-team review N issues filed YYYY-MM-DD."
- [ ] Re-run after fixes have landed; confirm the issues are actually closed by the fixes.

## Things this checklist deliberately doesn't cover

- **Cryptographic primitive review** — that's the audit territory. We trust `coincurve` and `Cryptodome`.
- **Gravity covenant correctness** — that's the highest-value audit target and needs more than a half-day red-team.
- **Side channels** — out of scope per the threat model.
- **Performance / DoS** — important but a different kind of session.

If a section here exposed something bigger than this checklist can address, file it as an issue and link to the relevant section of `docs/threat-model.md`.
