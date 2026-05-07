# Changelog

All notable changes to pyrxd are documented here. Format based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] — 2026-05-07

### Added

#### Glyph inspect — CLI

- `pyrxd glyph inspect` — offline classifier for any Glyph input
  (script hex, txid, outpoint, contract id). Always emits a
  "structural pattern match" qualifier so users understand the tool
  classifies on-chain shapes, not protocol-level semantic
  correctness.
- `pyrxd glyph inspect --fetch` — txid lookup via the configured
  ElectrumX server; full transaction structure with per-output
  classification.
- V1 dMint contract parsing — the actual mainnet format observed
  during RBG live testing. V2 also supported for future-compat.
- Locked against a real RBG transfer fixture so the classifier is
  pinned to mainnet behaviour, not synthetic vectors.

#### Glyph inspect — browser-hosted (GitHub Pages)

- New static tool at `docs/inspect_static/inspect/` (live at the
  Pages site under `/inspect/`). Loads pyrxd via Pyodide and runs
  the inspect classifier entirely in-browser — no server, no key
  material, no transaction broadcast.
- Inputs: raw script hex, txid (auto-fetches via ElectrumX
  WebSocket), outpoint, contract id.
- Tx-shape banner explaining what kind of transaction the user is
  looking at: FT deploy, NFT deploy, dMint contract deploy, dMint
  claim (with height / max_height), Glyph burn, mutable contract
  update. Plain RXD sends and ordinary transfers render with no
  banner.
- Per-output structural-match qualifier on every classified script
  type (ft, nft, mut, dmint, commit-ft, commit-nft, op_return)
  spelling out exactly what the pattern match does **not**
  verify — never claims semantic correctness.
- OP_RETURN data carriers classified explicitly with `data_hex`
  split out from the leading opcode.

#### Glyph protocol

- `GlyphRef.from_contract_hex` — parse explorer-style contract ids
  in the standard hex form.
- `is_dmint_script` / `extract_*_from_dmint_script` — first-class
  dMint contract recognition alongside the existing FT/NFT/MUT
  helpers.
- TR39 confusables / homoglyph detector
  (`pyrxd.glyph.confusables`) — flags Latin-spoofed token names and
  symbols against the Unicode TR39 confusables data. Skeleton +
  `is_latin_lookalike` helpers for inspecting hostile glyph
  metadata.

#### Hash

- Pure-Python RIPEMD160 fallback. OpenSSL 3 distros (and Pyodide)
  ship without a built-in RIPEMD160 provider; the fallback keeps
  pyrxd working out of the box on those environments. Selected at
  import time; OpenSSL is preferred when available.

### Security

- All browser-hosted inspect install artifacts (Pyodide loader,
  pyrxd wheel, micropip wheels, vendored cbor2 wheel) verified by
  SHA-256 before `micropip.install`. Loader uses Subresource
  Integrity. Mismatch aborts install loudly rather than falling
  through.
- Vendored `cbor2==5.4.6` wheel served same-origin. cbor2 6.x
  ships C-only; pinning to the last pure-Python release closes a
  Pyodide install path that depended on PyPI staying reachable
  and unchanged.
- `micropip.install(..., deps=False)` for pyrxd to avoid
  transitive metadata fetches during browser bootstrap.
- `pyrxd/__init__.py`, `pyrxd/glyph/__init__.py`, and
  `pyrxd/curve.py` rewritten to use lazy PEP 562 `__getattr__`
  re-exports. Importing `pyrxd.glyph.inspect` no longer drags in
  `coincurve`, `aiohttp`, or `websockets` — both a Pyodide
  enabler and a startup-cost win for narrow callers.
- Manifest filename validated as a bare basename (rejects path
  traversal, dot-only names, and URL-encoded separators) before
  use. CSP no longer allows PyPI as a script source. CLI outpoint
  rendering sanitized against terminal control-character
  injection. Manifest emit hardened against shell heredoc
  injection.
- CBOR `mime_type` field capped at 256 chars at parse time —
  bounds an otherwise-unbounded user-controlled string before it
  reaches metadata renderers.

### Fixed

- `pyrxd glyph inspect transfer-ft` previously passed bytes where
  hex string was expected; corrected.
- Python 3.10 compatibility for the CLI: `tomli` fallback for
  `tomllib` (3.11+).
- `_select_ripemd160` exception handling widened so OpenSSL
  variants raising `ValueError` (not just the documented
  `UnsupportedDigestmodError`) fall through to the pure-Python
  implementation cleanly.

### Documentation

- `docs/solutions/runtime-errors/dmint-v1-classifier-gap.md`
  written from the live RBG test that surfaced the V1/V2 split.
- `docs/research/glyphs-on-radiant.md` — explains why Radiant FTs
  are on-chain (not just metadata), with fuzzing strategy.

### Tooling

- Poetry version pinned in CI workflows.
- OSSF Scorecard residual-risk decisions documented.
- PyPI publishing automated via Trusted Publishing (no long-lived
  tokens).

## [0.3.0] — 2026-05-04

### Breaking changes

- **Default BIP44 coin type is now 512 (Radiant per SLIP-0044), not 236
  (Bitcoin SV).** Wallets created with 0.2.0 derive at
  `m/44'/236'/0'/...`; the same mnemonic in 0.3.0 derives at
  `m/44'/512'/0'/...` and produces different addresses. To recover funds
  from a 0.2.0 install, set
  `RXD_PY_SDK_BIP44_DERIVATION_PATH="m/44'/236'/0'"`, or pass
  `coin_type=236` to `HdWallet` (see new per-instance kwarg below). See
  `docs/research/wallet-derivation-paths.md` for the full migration
  story.

### Added

#### CLI

- New `pyrxd` console script (`pip install pyrxd` registers it on PATH).
- `pyrxd wallet new | load | info | export-xpub` — create, validate, and
  inspect HD wallets; account-level xpub export for watch-only use.
- `pyrxd address` / `pyrxd balance` / `pyrxd utxos` — bare query
  commands for address derivation, balance, and UTXO listing.
- `pyrxd glyph` subcommand group — Glyph protocol operations.
- `pyrxd setup` — onboarding walkthrough; probes node + ElectrumX
  reachability and wallet presence, writes default config.
- Global flags: `--network`, `--electrumx`, `--wallet`, `--config`,
  `--json`, `--quiet`, `--no-color`, `--yes`, `--debug`.
- Typed CLI errors (`UserError`, `NetworkBoundaryError`,
  `WalletDecryptError`) with stable exit codes and a static decrypt
  message that never echoes user input.

#### HD wallet

- `HdWallet(coin_type=...)` per-instance kwarg overrides the default
  derivation path without touching env state.
- `HdWallet.send` / `HdWallet.send_max` — key-aware UTXO collection and
  signed-transaction construction.
- Load-time path validation against the wallet record's stored
  derivation path.

#### Documentation

- `docs/research/wallet-derivation-paths.md` — public research doc on
  the five-way derivation path fragmentation across the Radiant wallet
  ecosystem with verified source links.
- `docs/solutions/` convention established for searchable
  problem/solution documentation.
- README user-risk disclaimer above Status section.
- Documentation moved from Read the Docs to GitHub Pages
  (https://mudwoodlabs.github.io/pyrxd/).

### Fixed

- `HdWallet` previously ignored the
  `RXD_PY_SDK_BIP44_DERIVATION_PATH` env override. Now respected.
- Cyclic imports between `cli.main` and the four CLI subcommand modules
  resolved by registering subcommands explicitly via
  `cli.add_command()`.
- `pyrxd glyph` broadcast summary now surfaces metadata fields.
- BIP39 empty-passphrase defaults annotated to silence false-positive
  bandit findings.

### Security

- All 16 GitHub Actions pinned to commit SHAs (no floating tags).
- Explicit minimum `permissions` declared in CI and lint workflows.
- OSSF Scorecard and OSV Scanner workflows added.
- CodeQL static analysis workflow added.
- Threat model + red-team checklist documented.
- `--json` mnemonic exposure warning documented.
- bandit added to `task lint` so security findings fail locally before
  CI.

### Tooling

- `task ci` aggregate task + versioned pre-push git hook
  (`scripts/git-hooks/pre-push`) + installer for local CI parity.
- `scripts/check-no-private-links.py` — link checker that prevents
  tracked docs from referencing gitignored design docs.
- ruff replaces flake8 + black for lint and format.
- Dependabot version updates landed: `actions/checkout` → 6.0.2,
  `actions/deploy-pages` → 5.0.0, `actions/upload-pages-artifact` →
  5.0.0, `github/codeql-action` → 4.35.3, `click` → ^8.3, `bandit` →
  ^1.9.4, `pre-commit` → 4.6.0, `myst-parser` constraint refresh.
- `websockets` constraint widened to `>=15.0.1, <17.0.0` (was
  `^16.0.0`). pyrxd uses only stable websockets API
  (`connect`/`send`/`recv`/`close`/`WebSocketException`) common to
  versions 13 through 16, so the upper-bound floor was unnecessarily
  strict and locked out coexistence with libraries pinned to
  `websockets <=15.0.1` (e.g., `solana-py 0.36.x`).

## [0.2.0] — 2026-04-29

Initial public release.

### Features

#### Core

- Typed primitives at all SDK boundaries: `Hex32`, `Hex20`, `Txid`,
  `Satoshis`, `SecretBytes`, `RawTx`. Strings and untyped bytes are
  rejected at the constructor.
- `pyrxd.curve` — secp256k1 with `coincurve`, RFC 6979 deterministic
  signing, low-s normalization, DER encoding.
- `pyrxd.security` — typed errors, RNG, secret-bytes (libsodium-backed
  `SecretBytes` for memory hygiene).
- `pyrxd.crypto` — symmetric primitives.

#### Keys and HD wallets

- `PrivateKey` / `PublicKey` with WIF encoding/decoding and address
  derivation (P2PKH mainnet).
- BIP32 extended keys (`Xprv` / `Xpub`) with hardened/non-hardened
  derivation.
- BIP39 mnemonic generation and seed derivation.
- BIP44 derivation paths (`m/44'/236'/0'/...` for Radiant).
- `HdWallet` with persistent encrypted save/load (AES-CBC keyed by
  hash of the BIP39 seed) and BIP44 gap-limit address scanning.

#### Transactions and scripts

- `Transaction` / `TransactionInput` / `TransactionOutput` — Radiant tx
  construction, serialization, and txid computation.
- BIP143-style sighash with Radiant's additional `hashOutputHashes`
  field; literal-zero zero-refs in the refsHash component.
- `P2PKH` script template + `unlock(private_key)` for standard signing.
- Script primitives in `pyrxd.script` for custom locking/unlocking
  patterns.
- `SatoshisPerKilobyte` fee model.

#### Glyph protocol

- `GlyphBuilder` with `prepare_commit`, `prepare_reveal`,
  `prepare_ft_deploy_reveal`, `prepare_dmint_deploy`,
  `prepare_mutable_reveal`, `prepare_container_reveal`,
  `prepare_wave_reveal`.
- `GlyphMetadata` with V1 and V2 sub-objects (creator, royalty, policy,
  rights, image+image_ipfs+image_sha256). Canonical CBOR encoding.
- `GlyphInspector` — parse Glyph tokens from a transaction's outputs.
- `GlyphScanner` — query an address's UTXOs and return Glyph tokens
  with metadata.
- `FtUtxoSet` + `build_transfer_tx` — conservation-enforcing FT
  transfers; refuses to build a tx that would create or destroy
  fungible units.
- `DmintState.from_script` — parse a live dMint contract UTXO into a
  typed state object.
- `verify_sha256d_solution` — off-chain PoW verifier matching on-chain
  semantics.

#### Network

- `ElectrumXClient` — async WebSocket client for ElectrumX servers.
  Multi-URL failover, transparent reconnect, per-request id
  correlation.
- `get_balance`, `get_utxos`, `get_history`, `get_transaction`,
  `broadcast`, `get_merkle_proof`.
- `script_hash_for_address` — derive the ElectrumX script hash from a
  Radiant address.
- `BtcDataSource` — Bitcoin chain reader for cross-chain Gravity
  flows.

#### Gravity (cross-chain BTC↔RXD atomic swaps)

- `GravityMakerSession` — maker side of a sentinel-artifact-shaped
  atomic swap.
- Covenant artifacts in `pyrxd.gravity.artifacts` (sentinel and
  legacy variants).
- SPV-anchored claim and forfeit flows.

**Status:** mainnet-proven for the sentinel-artifact path. Other
covenant variants in this module are experimental.

#### SPV

- Block-header verification, merkle-proof verification, partial-merkle
  parsing.
- Header chain tip tracking.

#### Examples

- `examples/glyph_mint_demo.py` — end-to-end Glyph NFT mint.
- `examples/ft_deploy_premine.py` — FT deploy with full premine to
  one address.
- `examples/gravity_*.py` — Gravity Protocol cross-chain demos.

### Quality

- 2,000+ tests across unit, property-based (hypothesis), and
  integration suites.
- CBOR cross-decoder tests against an independent reference decoder
  (RXinDexer).
- Frozen golden vectors for CBOR encoding determinism and ECDSA
  RFC 6979 signing.
- `mypy --strict` clean on `src/`.
- `ruff` clean on the codebase.

### Documentation

- `docs/dmint-followup.md` — premine vs PoW dMint scope.
- `docs/dmint-research-photonic.md` — Photonic Wallet TS reverse
  engineering.
- `docs/dmint-research-mainnet.md` — decoded live mainnet dMint
  contracts.

### Known limitations

- **dMint PoW-based distributed FT mint not implemented.** Premine-at-deploy works via `prepare_ft_deploy_reveal`. PoW commit/reveal + ASERT/LWMA difficulty adjustment is documented as future work in `docs/dmint-followup.md`. Premine-only consumers do not need it.
- **Gravity covenant variants beyond sentinel-artifact** are
  experimental and have not been audited.
- **No third-party security audit yet.** Use at your own risk in
  production.

[0.3.0]: https://github.com/MudwoodLabs/pyrxd/releases/tag/v0.3.0
[0.2.0]: https://github.com/MudwoodLabs/pyrxd/releases/tag/v0.2.0
