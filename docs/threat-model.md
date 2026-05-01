# pyrxd threat model

**Version:** 1.0 (draft)
**Last updated:** 2026-05-01
**Applies to:** pyrxd v0.3+ (library + CLI)

This document is the working threat model for pyrxd. It exists to:

1. Make explicit what pyrxd protects, and from whom.
2. Map every claimed protection to a concrete control in the codebase.
3. Surface gaps honestly so users, contributors, and (eventually) auditors can see what is and isn't covered.
4. Provide a starting point that an external security review can build on rather than recreate.

It is not a substitute for an independent third-party audit. The README states cryptographic primitives have not been independently audited; that remains true.

## Purpose & non-goals

### What pyrxd is

A Python SDK + CLI for the Radiant blockchain. It performs:

- Key generation, derivation, and signing (secp256k1, BIP32/39/44)
- Transaction construction, serialization, and signing
- Glyph token protocol operations (NFT mint, FT deploy, transfers)
- Gravity cross-chain BTC↔RXD atomic swaps
- SPV verification of Bitcoin transactions
- ElectrumX networking and Bitcoin data-source queries

### What pyrxd is NOT

- Not a hardware wallet integration
- Not a multi-signature coordination tool (single-sig only in v0.3)
- Not a node implementation (does not validate the chain itself; relies on ElectrumX)
- Not a custodial service or a smart-contract platform beyond what Radiant's consensus rules support

### Non-goals (explicit)

These are not protected by pyrxd controls:

- **Coercion attacks** (rubber-hose, $5 wrench attacks)
- **Physical attackers** with hands on the user's machine
- **Side-channel attacks at the silicon level** (Spectre/Meltdown class)
- **Compromise of the user's terminal emulator, OS, or hardware**
- **Compromise of the BIP39 wordlist file or scrypt KDF** (we trust upstream implementations)
- **Long-term post-quantum security** (secp256k1 itself is not post-quantum safe)

## Assets

Ranked roughly by value to an attacker:

| # | Asset | Form | Where it lives |
|---|-------|------|----------------|
| A1 | BIP39 mnemonic | 12 or 24 words | User's memory, paper, optionally encrypted in `wallet.dat` |
| A2 | BIP39 seed (PBKDF2 of A1) | 64 bytes | In-memory `SecretBytes` only; never persisted directly |
| A3 | Account-level xprv | base58check string | Derived in-memory from A2; never persisted |
| A4 | Per-address private keys | 32-byte scalar | Derived in-memory from A3; never persisted |
| A5 | Encrypted wallet file (`wallet.dat`) | AES-GCM-encrypted JSON | Disk at `~/.pyrxd/wallet.dat`, mode 0600 |
| A6 | Account-level xpub | base58check string | Watch-only-safe; can be exported via `wallet export-xpub` |
| A7 | An unsigned transaction | bytes | Transient; held in-memory during tx building |
| A8 | A signed transaction in flight | bytes | Transient; sent over wss to ElectrumX |
| A9 | UTXO ownership info | tuples (txid, vout, value, owner) | In-memory after `collect_spendable()`; on disk in `addresses` dict of wallet.dat |
| A10 | Network metadata (which addresses, balances, history) | observable on-chain | Public, but linkability matters for privacy |

Control surfaces target the upper rows; A6 is intentionally exportable; A10 is unavoidable on a public chain.

## Threat actors

### TA1: Local post-compromise malware

**Capabilities:** read process memory, read files in `$HOME` with user permissions, tamper with stdin/stdout, modify dependencies on next install, exfiltrate over network.

**Goals:** A1, A2, A4, A5.

**Reach:** Once present, can do almost anything. pyrxd's controls provide **defense in depth at best**, not prevention. Encrypted wallet file slows exfiltration; `SecretBytes.zeroize()` slightly reduces window; nothing makes a compromised host safe.

### TA2: Local non-malicious user (footgun)

**Capabilities:** the user themselves making mistakes — pasting mnemonics into chat, running `wallet new` while screen-sharing, copying to clipboard, leaving terminal scrollback.

**Goals:** Not adversarial; a victim of accident.

**Reach:** Heavy. Most reported real-world key losses come from this category. pyrxd's job is to make accidents harder.

### TA3: Network passive observer

**Capabilities:** sniff packets between user and ElectrumX/BTC data sources.

**Goals:** A10 (link addresses to user's IP), inputs/outputs for chain analytics.

**Reach:** Limited if `wss://` is enforced (TLS). pyrxd defaults to `wss` and rejects `ws://` without `allow_insecure=True`.

### TA4: Network active MITM

**Capabilities:** intercept and modify traffic. Possible against `ws://` (rejected by default) or against TLS with a CA compromise.

**Goals:** Substitute attacker addresses into broadcast txs, suppress balance/history results to confuse the wallet, force fee bumps.

**Reach:** Mostly mitigated by TLS but degrades to TA5 if the user is using a hostile ElectrumX.

### TA5: Hostile ElectrumX operator

**Capabilities:** The remote endpoint pyrxd connects to. Can lie about anything it returns: balances, UTXO sets, transaction confirmations, headers. Cannot forge signatures or steal private keys.

**Goals:** Selective service denial (refuse to broadcast a tx, drop history queries), inducing wallet to derive new addresses (privacy attack), trickery to lure UTXOs into a malformed tx (limited by client-side validation).

**Reach:** Significant for privacy, limited for theft. The default config uses one public ElectrumX server (`electrumx.radiant4people.com`) which is a single point of trust.

### TA6: Hostile Bitcoin data source

**Capabilities:** A `BtcDataSource` (mempool.space, blockstream.info, Bitcoin Core RPC) used by Gravity for SPV proofs. Can lie about BTC-side data.

**Goals:** Forge a "BTC was sent" proof that fools the RXD-side covenant into releasing funds.

**Reach:** Limited by `MultiSourceBtcDataSource` quorum check (Gravity uses k-of-n agreement) plus on-chain SPV verification of the proof itself. Single-source mode is documented as weaker.

### TA7: Hostile metadata file author

**Capabilities:** Crafts a `metadata.json` and convinces the user to mint/deploy from it.

**Goals:** Make the user broadcast a transaction that locks funds or tokens to an attacker key without the user noticing. Crash the CLI with malformed CBOR. Embed a malicious URL or script reference.

**Reach:** Real and underappreciated. The user types `pyrxd glyph mint-nft alice-token.json` and trusts that the resulting token belongs to *them*. If the file's `owner_pkh` is the attacker's, the NFT is the attacker's.

### TA8: Hostile counterparty (Gravity)

**Capabilities:** The other party in an atomic swap. Wants to take both legs of the trade.

**Goals:** Exploit covenant bugs, race conditions, or incorrect SPV verification to claim BTC and RXD without delivering their side.

**Reach:** Direct financial impact if a bug exists. This is the single most adversarial setting in pyrxd. Mitigated by the covenant tests in `tests/test_gravity_red_team.py` (1500+ lines), but the README flags Gravity as "still being hardened" and "covenant variants" as work in progress.

### TA9: Supply-chain attacker

**Capabilities:** Compromise a release of `coincurve`, `Cryptodome`, `click`, `cbor2`, `aiohttp`, `websockets`; typosquat `pyrxd` on PyPI; or compromise pyrxd's own release pipeline.

**Goals:** Inject signing-time backdoor, exfiltrate seeds via network, replace key derivation with attacker-controlled values.

**Reach:** Catastrophic if successful. pyrxd's defenses are limited to: small dep tree, `pip-audit` for known CVEs, signed PyPI uploads, and trust in upstream maintainers. We do not pin transitive deps.

## Trust boundaries

Listed roughly inside-out; each is a place where data changes from "untrusted" to "validated and used":

1. **CLI argv** → parsed by click, validated by command handlers. Click handles type coercion for `int`, `float`, `Path`, `Choice`. Custom validation (address shape, ref shape) is in command bodies.
2. **Stdin** → mnemonic and passphrase input via `click.prompt(hide_input=True)`. Normalized via `_normalize_mnemonic` (whitespace collapse). Validated by `bip39.validate_mnemonic`. Never logged.
3. **Configuration files** → `~/.pyrxd/config.toml` parsed by stdlib `tomllib`. Schema-checked by `Config` dataclass. Mode permissions on parent dir checked.
4. **Wallet file (`wallet.dat`)** → AES-GCM authenticated decryption; tag mismatch raises before any post-decrypt code runs. File mode checked (0o600 required) before read.
5. **Metadata files (`metadata.json`)** → JSON parsed with stdlib. Protocol names mapped to `GlyphProtocol` ints. Validated by `GlyphMetadata.__post_init__`. Cap on payload size enforced by `decode_payload`.
6. **Network: WebSocket frames from ElectrumX** → JSON-RPC framed, size-capped at 10 MB. Response correlation is per-id (concurrent calls don't swap responses). Hex/bytes results validated as typed values (`Txid`, `RawTx`, `Hex32`).
7. **Network: HTTP responses from Bitcoin data sources** → Content-type checked, size-capped, hex-decoded with explicit length. URL construction uses `urllib.parse.quote`.
8. **Library API surface (caller → pyrxd)** → typed validation at constructors: `Hex32`, `Hex20`, `Txid`, `Satoshis`, `Photons`, `BlockHeight`, `Nbits`, `SighashFlag` all reject malformed inputs at construction. `PrivateKey`, `PublicKey` validate input bytes/strings.
9. **Internal: pyrxd → coincurve / Cryptodome** → these libraries are the trust root for crypto primitives. We do not re-implement.

## Threat scenarios

Each scenario lists actor → action → asset → control(s) → residual risk.

### S1: Mnemonic exfiltration via JSON-mode redirect (TA2)

- **Action:** User runs `pyrxd wallet new --json --yes | tee mnemonic.txt` to "save" the output, mnemonic ends up unencrypted on disk.
- **Asset:** A1.
- **Control:** README documents the pitfall explicitly. The default (interactive) flow shows the mnemonic with an Enter gate — no shell-redirect exposure.
- **Residual risk:** User error remains possible. Mitigation is documentation, not enforcement. Documented at `README.md#security-scripting-wallet-new-with---json---yes`.

### S2: Mnemonic exposure via terminal scrollback (TA2)

- **Action:** User runs interactive `pyrxd wallet new` in tmux/screen with scrollback enabled.
- **Asset:** A1.
- **Control:** README documents that interactive display still has terminal-history risks. Enter gate slows down accidental copy.
- **Residual risk:** High. We cannot clear scrollback portably.

### S3: Mnemonic exposure via clipboard manager (TA2)

- **Action:** User copy-pastes the mnemonic from terminal display; clipboard manager retains history.
- **Asset:** A1.
- **Control:** None in v0.3.
- **Residual risk:** Real. Tracked as [issue #11](https://github.com/MudwoodLabs/pyrxd/issues/11) — add a clipboard-hygiene warning after the Enter gate.

### S4: Wallet decryption attempt with wrong mnemonic (TA1)

- **Action:** Attacker has wallet.dat (e.g., from backup leak). Tries to decrypt with random mnemonics.
- **Asset:** A5 → A1.
- **Controls:** scrypt KDF (n=2^14) imposes per-attempt CPU+memory cost; per-file salt prevents precomputed table reuse; AES-GCM tag detects all wrong guesses. Decrypt failure surfaces a single static message — never echoes attacker input.
- **Residual risk:** scrypt parameters are tuned for "BIP39 seed has 128+ bits of entropy" — they slow brute force but do not save a mnemonic that's been leaked elsewhere.

### S5: World-readable wallet file post-restore (TA1)

- **Action:** User restores wallet.dat via `cp` or `rsync`; file ends up at mode 0o644.
- **Asset:** A5.
- **Control:** Load-time mode check refuses to read a wallet file with group/other read bits and prints the chmod fix. Test: `tests/test_hd_wallet.py::test_load_rejects_world_readable_wallet_file`.
- **Residual risk:** macOS/Windows behavior may differ; check is gated to `os.name == "posix"`.

### S6: Stale signature attack via fee-pass interleave (architectural)

- **Action:** A bug in tx builder that signs trial outputs but builds final outputs differently. Attacker pays fee on user's trial-tx not their actual one.
- **Asset:** A4 + A8.
- **Control:** Two-pass fee algorithm explicitly resets `unlocking_script` between trial and final, then re-signs. Documented in `tests/test_preimage.py`. Tested in `RxdWallet` and `HdWallet` send/send_max paths.
- **Residual risk:** Any new tx-builder code path must follow the same pattern. Code review item.

### S7: Hostile metadata.json owner_pkh substitution (TA7)

- **Action:** User downloads `nft-metadata.json` from chat. The file contains the attacker's `owner_pkh` (or the metadata triggers a tx whose change goes to the attacker). User runs `pyrxd glyph mint-nft nft-metadata.json` and broadcasts.
- **Asset:** A8, indirectly the minted NFT.
- **Controls:**
  - Confirmation prompt before broadcast shows "funding utxo, funding value, commit value, network." This summary does NOT currently surface the embedded `owner_pkh` from the metadata.
  - `init-metadata` scaffolds a clean template that the user fills in themselves.
  - Out-of-band trust (user shouldn't run hostile files).
- **Residual risk:** Real. **Open finding:** the broadcast summary should display the resolved `owner_pkh` (and ASCII-render the address) before the user confirms. Tracked as a follow-up; will become an issue.

### S8: Hostile ElectrumX returns malformed UTXO record (TA5)

- **Action:** ElectrumX returns a UTXO with a value that doesn't match the on-chain truth. User signs a tx using that fake value.
- **Asset:** A4 (signs a misweighted tx).
- **Control:** None at the wallet layer; pyrxd does not independently re-fetch source-tx outputs to verify UTXO values for plain RXD sends. Gravity does this for BTC inputs via `MultiSourceBtcDataSource` quorum.
- **Residual risk:** Real but bounded. A lying ElectrumX can cause the user to overpay fees or build invalid txs (which the network rejects on broadcast — funds aren't lost, just confused). Cannot induce theft directly because the locking script is what controls the funds, and pyrxd builds locking scripts itself.

### S9: Hostile ElectrumX claims address is unused (TA5)

- **Action:** During gap-limit scan, ElectrumX returns empty `get_history` for an address that is actually funded. Wallet thinks address is unused; recommends it for next receive (or for change).
- **Asset:** A10 (privacy: linking sender to receiver).
- **Control:** Library N5 fix: `_scan_chain` re-raises `NetworkError` on lookup failure rather than silently treating as "unused." Re-using a known-funded address is impossible because the gap-limit logic stops at consecutive empty results, and each empty result is verified.
- **Residual risk:** A *consistently* lying ElectrumX could still hide history. Mitigation is network-layer source diversity (use multiple servers); not implemented for ElectrumX queries (only for BTC data sources). Tracked as a future enhancement — multi-source ElectrumX.

### S10: Hostile counterparty exploits a Gravity covenant bug (TA8)

- **Action:** Counterparty crafts a swap proposal that, if executed, leaves them with both legs.
- **Asset:** A8, real funds.
- **Controls:**
  - SPV verification of BTC proofs against header chain
  - Multi-source BtcDataSource quorum
  - Covenant code structurally derived from audited Photonic Wallet patterns
  - 1500+ lines of red-team tests in `test_gravity_red_team.py`
  - README explicit "experimental" flag on covenant variants
- **Residual risk:** Most concentrated risk in the codebase. Audit-recommended target.

### S11: Supply-chain compromise of `coincurve` (TA9)

- **Action:** Malicious `coincurve` release ships with backdoored signing.
- **Asset:** A4, every signature pyrxd produces.
- **Controls:** `pip-audit` in dev deps; `coincurve` is a high-attention package with multiple maintainers. We pin a major-version range, not a specific version.
- **Residual risk:** Catastrophic if exploited. Effective response would require upstream awareness or a security advisory, both of which we'd hear about via standard channels.

### S12: Typosquat of `pyrxd` itself (TA9)

- **Action:** Attacker publishes `py-rxd` or `pyrxd-tools` with malicious code; user installs the wrong package.
- **Asset:** Everything in the user's environment.
- **Control:** None (this is a PyPI registry concern). README links the canonical install path. `[project.urls]` in `pyproject.toml` points to the real repo.
- **Residual risk:** Outside pyrxd's control.

### S13: `--debug` traceback leaks frame locals (TA1, TA2)

- **Action:** User encounters a wallet decrypt failure with `--debug`; traceback is forwarded to a log aggregator that captures stderr; mnemonic local appears in the trace.
- **Asset:** A1.
- **Control:** `errors.CliError.show()` uses `traceback.format_exception(...)` only — never `capture_locals=True`. Source-line context contains variable names but never values. Tested in `test_debug_emits_traceback_on_decrypt_failure`: the user's exact input never appears in `result.output`.
- **Residual risk:** Source line text mentions `mnemonic` and `passphrase` as parameter names; an attacker reading the logs sees the *names* but not values. Acceptable.

### S14: Fee-rate flag set to 0 builds an unmineable tx (TA2)

- **Action:** User passes `--fee-rate 0` (currently rejected by validation) or somehow ends up with effectively-zero fee. Tx is built and broadcast; never confirms; funds appear stuck.
- **Asset:** A4 + A8 (operational, not theft).
- **Control:** `build_send_tx` and `build_send_max_tx` validate `fee_rate > 0`. Default fee rate of 10,000 photons/byte is the documented mainnet relay minimum.
- **Residual risk:** Low — if fee is below relay minimum, the network rejects on broadcast. Funds are not lost; user can rebuild with a higher fee.

### S15: Replay of a signed transaction (general)

- **Action:** Attacker re-broadcasts a signed tx the user already broadcast.
- **Asset:** A8 (already public, same tx confirms once).
- **Control:** Bitcoin/Radiant transactions are inherently non-replayable: they spend specific UTXOs, and once spent those UTXOs are gone. A re-broadcast either confirms the same tx (no-op) or is rejected as conflicting.
- **Residual risk:** None at this layer. Cross-chain Gravity introduces its own replay considerations, addressed by SPV-binding and counterparty-specific covenant params.

### S16: Race condition mid-`save()` corrupts wallet file (TA2 timing)

- **Action:** `wallet new` is interrupted (Ctrl-C, power loss) mid-write.
- **Asset:** A5.
- **Control:** Atomic write pattern: `mkstemp` → `fchmod 0o600` → write → `fsync` → `os.replace`. Either the old file remains intact, or the new fully-fsynced file does. No half-encrypted state.
- **Residual risk:** OS-level filesystem guarantees vary; we trust ext4/xfs/HFS+/APFS to honor `os.replace` atomicity.

### S17: Mnemonic in pytest result.output captured by failing assertion (TA1, hypothetical)

- **Action:** A test asserts on `result.output`, fails for an unrelated reason, pytest's traceback embeds the full output (including the mnemonic) in CI logs.
- **Asset:** A1 (synthetic — test mnemonics are random per run).
- **Control:** Tests use disposable mnemonics. CI logs are private.
- **Residual risk:** Low (synthetic mnemonics never hold real funds). Tracked as [issue #9](https://github.com/MudwoodLabs/pyrxd/issues/9).

## Controls in place

Cross-reference of controls and the threats they address:

| Control | Threats addressed | Code location |
|---------|-------------------|---------------|
| AES-256-GCM wallet encryption | S4, S5 | `src/pyrxd/hd/wallet.py:save/load` |
| scrypt KDF (n=2^14) | S4 | `src/pyrxd/hd/wallet.py:_derive_enc_key` |
| Mode 0o600 enforcement (save) | S1, S5 | `src/pyrxd/hd/wallet.py:save` (mkstemp + fchmod) |
| Mode 0o600 verification (load) | S5 | `src/pyrxd/hd/wallet.py:_load_existing` |
| Atomic write (mkstemp + replace) | S16 | `src/pyrxd/hd/wallet.py:save` |
| `SecretBytes` repr/copy/pickle disable | TA1 (post-compromise mitigation) | `src/pyrxd/security/secrets.py` |
| `SecretBytes.zeroize()` | TA1 (best-effort) | `src/pyrxd/security/secrets.py:zeroize` |
| `__hash__ = None` on key types | TA1 (no dict/set leakage) | `src/pyrxd/keys.py`, `src/pyrxd/security/secrets.py`, `src/pyrxd/hd/bip32.py` |
| `hmac.compare_digest` for key equality | side-channel timing | `src/pyrxd/keys.py:PrivateKey.__eq__`, `src/pyrxd/security/secrets.py:SecretBytes.__eq__` |
| RFC 6979 deterministic signatures | TA1 (no nonce reuse) | via `coincurve` |
| Low-s normalization | tx malleability | via `coincurve` |
| `wss://` enforced; `ws://` rejected | TA3, TA4 | `src/pyrxd/network/electrumx.py` URL validation |
| Response size cap (10 MB) | TA5 (memory DoS) | `src/pyrxd/network/electrumx.py`, `src/pyrxd/network/bitcoin.py` |
| Per-id JSON-RPC correlation | TA5 (response-swap race) | `src/pyrxd/network/electrumx.py:_pending` |
| Typed boundary validation (Hex32, Txid, etc.) | input validation everywhere | `src/pyrxd/security/types.py` |
| Mnemonic input via `click.prompt(hide_input=True)` | TA2 (echo prevention) | `src/pyrxd/cli/prompts.py` |
| Mnemonic display Enter gate | TA2 | `src/pyrxd/cli/prompts.py:show_mnemonic` |
| Mnemonic normalization before BIP39 validation | TA2 | `src/pyrxd/cli/prompts.py:_normalize_mnemonic` |
| `--json --yes` required for destructive ops | TA2 (footgun in scripts) | `src/pyrxd/cli/context.py:is_destructive_mode_safe` |
| Confirmation summary before broadcast | TA2, TA7 | `src/pyrxd/cli/glyph_cmds.py:_confirm_or_abort` |
| `--debug` traceback without `capture_locals` | S13 | `src/pyrxd/cli/errors.py:CliError.show` |
| Static "decrypt failed" message | TA1 (no input echo) | `src/pyrxd/hd/wallet.py:_load_existing`, CLI surface |
| Wallet save refuses overwrite | TA2 | `src/pyrxd/cli/wallet_cmds.py:wallet_new` |
| Library N5 fix: re-raise NetworkError on scan | S9 | `src/pyrxd/hd/wallet.py:_scan_chain` |
| Library N6 fix: load() raises FileNotFoundError | TA2 (no silent overwrite) | `src/pyrxd/hd/wallet.py:load` |
| Two-pass fee with unlock-script reset | S6 | `src/pyrxd/wallet.py`, `src/pyrxd/hd/wallet.py:build_send_tx` |
| Multi-source BtcDataSource quorum | TA6 | `src/pyrxd/network/bitcoin.py:MultiSourceBtcDataSource` |
| SPV verification (Gravity) | TA6, TA8 | `src/pyrxd/spv/`, `src/pyrxd/gravity/` |
| Gravity red-team test suite | TA8 | `tests/test_gravity_red_team.py` (1500+ lines) |
| CodeQL on every push | static analysis | `.github/workflows/codeql.yml` |
| Bandit on every push | security smells | `.github/workflows/ci.yml` |
| ruff lint + format | code hygiene | `.github/workflows/lint.yml` |
| `pip-audit` (dev dep) | known-CVE supply-chain | `pyproject.toml` |
| detect-secrets pre-commit | committed-secret prevention | `.pre-commit-config.yaml` |
| 100% coverage on `pyrxd.security` | ensures security primitives are exercised | CI coverage gate |
| 85% overall coverage | structural confidence | CI coverage gate |

## Known gaps

Honest list. These are not vulnerabilities; they're places where pyrxd's defense ends.

### Crypto / library

1. **No third-party crypto audit** of pyrxd's integration of underlying primitives.
2. **No formal verification of BIP32/39/44 vectors** beyond unit tests. Test vectors come from the BIP specs themselves.
3. **No fuzz testing of the CLI surface.** [Issue #10.](https://github.com/MudwoodLabs/pyrxd/issues/10)
4. **No timing-attack analysis** of pyrxd-internal comparisons beyond known-good `hmac.compare_digest` use.
5. **Memory zeroization is best-effort** — CPython does not guarantee secure memory.

### Network

6. **Single ElectrumX endpoint by default.** TA5 has unmitigated reach for plain RXD operations. Multi-source ElectrumX is not implemented; only Bitcoin data sources have quorum.
7. **No certificate pinning for ElectrumX TLS.** A CA compromise enables TA4. We rely on system trust store.

### CLI

8. **Broadcast summary doesn't show resolved `owner_pkh` from metadata files.** S7 residual risk. **Should be addressed before v0.3.0 release.**
9. **No clipboard hygiene warning.** S3 residual risk. [Issue #11.](https://github.com/MudwoodLabs/pyrxd/issues/11)
10. **Mnemonic re-entry per command** with no agent process. S2/S3 residual risk amplified by repetition. [Issue #8.](https://github.com/MudwoodLabs/pyrxd/issues/8)

### Protocol

11. **Gravity covenant variants flagged "still being hardened"** in README. TA8 is the highest-stakes attacker; this is the highest-priority audit target.
12. **dMint PoW path documented but not implemented.** Only premine FT works in v0.3.
13. **No multi-signature support.** Single-sig only; users wanting m-of-n must build it themselves.

### Supply chain

14. **No pinned transitive dependency hashes.** A compromised release of `coincurve`, `Cryptodome`, etc. would propagate. `pip-audit` catches known CVEs but not zero-days.
15. **No SBOM generation.** A signed software bill of materials would help downstream users verify what they got.
16. **Release signing not yet set up.** PyPI 2FA is on; release artifact signing (sigstore, gpg) is not.

### Process

17. **No formal incident response plan.** If a vulnerability is reported via `security@mudwoodlabs.com`, response is ad-hoc.
18. **No coordinated-disclosure SLA.** Researchers don't know what response time to expect.
19. **No external eyes.** Solo developer; nothing has been reviewed by anyone else.

## Out of scope (explicit non-coverage)

We do not protect against:

- Coercion / wrench attacks
- Physical access to an unlocked machine
- Compromised OS, firmware, BIOS, hypervisor
- Side channels at the silicon level
- Quantum computers (secp256k1 is not post-quantum safe; no chain currently is)
- User running the wrong binary (typosquats, malicious forks)
- User leaking the mnemonic via channels pyrxd doesn't see (photographing it, reading it aloud on a podcast, etc.)
- User running pyrxd in a hostile container that can read process memory
- Future Radiant consensus bugs that invalidate the protocol pyrxd implements

## For auditors and security researchers

If you have time and skill to look at pyrxd, here's where to start, ranked by expected return on investigation:

1. **Gravity covenant code** (`src/pyrxd/gravity/`) — highest stakes, most complex protocol code. Review focus: SPV proof construction, covenant param validation, sighash flag handling, edge cases in `tests/test_gravity_red_team.py` that document known concerns.

2. **Wallet file format and load path** (`src/pyrxd/hd/wallet.py:save/load`) — second-highest stakes (key material). Review focus: AEAD construction, mode-bit checks, malformed-JSON guards, the edge between "file decrypts" and "file is structurally valid wallet."

3. **Glyph script construction** (`src/pyrxd/glyph/`) — lower direct stakes (most attacks here are footguns, not theft) but the metadata-trust issue (S7) is real. Review focus: how `owner_pkh` propagates from CBOR to scriptPubKey to broadcast, and what the user actually sees before signing.

4. **CLI mnemonic handling** (`src/pyrxd/cli/wallet_cmds.py`, `src/pyrxd/cli/prompts.py`) — boring but easy to mess up. Review focus: every code path that touches the mnemonic string, and confirmation that none of them log, copy to dict-keyed structures, or serialize without `SecretBytes`.

5. **Network response parsing** (`src/pyrxd/network/electrumx.py`, `src/pyrxd/network/bitcoin.py`) — not where private keys live but where lying-server defenses live. Review focus: hex decoding, length checks, content-type validation, response-correlation race window.

If you find something, please report privately to `security@mudwoodlabs.com`. We don't pay bounties yet but credit researchers in `SECURITY.md` and in the changelog.

## Revision history

- **2026-05-01** v1.0 — initial threat model. Documents v0.3 surface (library + CLI + glyph commands).

Future revisions should bump the version, add an entry, and call out which sections changed.
