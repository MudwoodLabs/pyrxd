# Changelog

All notable changes to pyrxd are documented here. Format based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.1] — 2026-05-13

Audit follow-ups + new SDK primitives. No breaking changes; everything
new is additive. Closes the four golden-vector recommendations from
the 0.5.0 pattern-recognition audit and ships the time-lock builders
+ parallel miner that were deferred at 0.5.0 cut.

### Added

#### Time-lock script primitives

- `pyrxd.script.timelock` — new module with canonical Bitcoin/Radiant
  time-lock locking scripts:
  - `build_p2pkh_with_cltv_script(pkh, locktime)` — P2PKH gated by
    absolute time-lock (BIP-65 `OP_CHECKLOCKTIMEVERIFY`).
  - `build_p2pkh_with_csv_script(pkh, sequence)` — P2PKH gated by
    relative time-lock (BIP-112 `OP_CHECKSEQUENCEVERIFY`).
  - `build_csv_sequence(units, kind)` — encodes a (blocks |
    512-second intervals) pair into the BIP-112 stack/`nSequence`
    integer form.
  - `CsvKind.BLOCKS` / `CsvKind.TIME_512_SECONDS` — kind enum.
  - `LOCKTIME_THRESHOLD = 500_000_000` — height-vs-Unix-time boundary.
- Validation rejects out-of-range locktime/sequence, the BIP-112
  disable bit (would silently make the lock a no-op), and wrong-size
  PKH. 20 tests cover minimal-int push behaviour, sign-pad edge cases,
  bit-22 encoding, and the cross-invariant that CLTV and CSV shapes
  differ only at the verify opcode.
- **Scope: locking scripts only.** Threading `nLockTime` /
  `nSequence` through transaction construction (and the unlocking
  `ScriptTemplate` that consumes signatures) is deferred until a
  concrete pyrxd consumer needs it.

#### Unified miner entrypoint

- `mine_solution_dispatch(preimage, target, *, miner_argv=None, ...)`
  — single entrypoint that routes to in-process `mine_solution`
  when `miner_argv is None`, otherwise to `mine_solution_external`
  for a subprocess miner. Callers no longer have to branch on miner
  availability themselves. Exported from `pyrxd.glyph`.

#### Parallel pure-Python miner

- `pyrxd.contrib.miner` — multi-process parallel miner that scales
  the existing pure-Python mining loop across CPU cores using the
  JSON-over-stdio external-miner protocol. No compiled extensions;
  useful when a faster C/Rust miner isn't available.

#### Mainnet golden-vector test infrastructure

- Four new test classes pin every wire-format builder against real
  on-chain bytes — the strongest interop assertion an SDK can carry:
  - `TestFtLockingScriptMainnetGolden` (`tests/test_dmint_module.py`)
    — 75-byte FT script vs RBG transfer `ac7f1f70…0ae4`.
  - `TestNftLockingScriptMainnetGolden` (`tests/test_glyph.py`)
    — 63-byte NFT singleton vs Glyph NFT `27390efa…be7e`.
  - `TestCommitLockingScriptMainnetGolden`
    (`tests/test_glyph_dmint.py`) — 75-byte commit script, both FT
    and NFT branches, vs the GLYPH deploy `a443d9df…878b`.
  - `TestCborPayloadMainnetGolden` (`tests/test_glyph.py`) — full
    65,569-byte CBOR reveal payload incl. embedded PNG, vs GLYPH
    reveal `b965b32d…9dd6` (fixture:
    `tests/fixtures/glyph_reveal_cbor.bin`). Pins
    `sha256d(payload) == commit_hash` linkage, decoder shape, and
    `OP_PUSHDATA4` framing for payloads >65,535 bytes.

#### V2 quarantine markers

- `V2UnvalidatedWarning` — new `UserWarning` subclass; emitted by
  every V2 dMint entry point. Silenceable with
  `warnings.simplefilter("ignore", V2UnvalidatedWarning)`; escalable
  to error with `warnings.simplefilter("error",
  V2UnvalidatedWarning)` in CI. No V2 dMint contract has been
  deployed to Radiant mainnet as of 0.5.1; the V2 code paths are
  byte-equivalent-by-construction to V1 where they share bytecode
  but have never been exercised against live consensus.
- `build_dmint_v2_mint_preimage(...)` — V2 PoW preimage helper that
  mirrors the V1 helper. Carries `V2UnvalidatedWarning`.

#### Documentation

- Migration guide: `docs/how-to/migrate-0.4-to-0.5.md`.
- New tutorials: mint a Glyph NFT, mint a Glyph FT, mint from a V1
  dMint contract on Radiant mainnet, inspect any Radiant transaction
  in the browser, your first Radiant transaction.
- New how-tos: scan an address for Glyphs, broadcast a Radiant
  transaction, handle Radiant's BIP143 sighash quirks, verify an SPV
  proof.
- New concepts pages: V1 dMint mint mechanics, V1 dMint deploy,
  external miner protocol (JSON-over-stdio subprocess contract),
  Glyph inspect tool (structural match, not semantic correctness).
- Design decision:
  `docs/solutions/design-decisions/wave-protocol-deferred-until-consumer.md`
  — WAVE name-claim protocol deferred until a concrete pyrxd
  consumer needs it.

### Changed

- CI: cancel in-flight runs on push to the same branch / PR. Roughly
  halves per-PR Actions minute spend.
- CI: hash-pin `poetry==2.3.4` and `ruff==0.15.12` via
  `pip-compile --generate-hashes` lock files under `ci/`. Each
  workflow that previously ran `pip install poetry==2.3.4` now runs
  `pip install -r ci/poetry-pin.txt --require-hashes`. Closes 3 of
  the 5 open OpenSSF Scorecard / CodeQL `PinnedDependenciesID`
  alerts (the remaining 2 are on the docs build's editable
  `pip install -e .`, which physically cannot be hash-pinned).
  See `ci/README.md` for the bump workflow.

### Fixed

- CodeQL note-severity alerts cleared: replaced the bare `import`
  availability probe in `docs/inspect_static/inspect/glue.py` with
  `importlib.util.find_spec` (closes `py/unused-import`); switched
  internal re-exports in `src/pyrxd/glyph/builder.py` and
  `src/pyrxd/cli/glyph_cmds.py` to PEP 484 explicit `X as X` form
  (CodeQL doesn't honour `# noqa: F401` on those — the explicit
  re-export form does close the alert); added unreachable
  `raise AssertionError("unreachable: pytest.skip raises")` after
  `pytest.skip` in `tests/test_ripemd160_fallback.py` (closes
  `py/mixed-returns`).

### Security

- The 0.5.0 pre-release multi-reviewer audit's deferred items
  (V2 quarantine, mainnet golden vectors for FT/NFT/commit/CBOR,
  CodeQL note cleanup) are closed by this release. No new formal
  audit was run for 0.5.1; changes are additive on top of audited
  0.5.0 code and each touches a single area (script primitives,
  test fixtures, CI config) with high in-PR review coverage.

## [0.5.0] — 2026-05-11

### Added

#### dMint V1 deploy (M2)

- `prepare_dmint_deploy_v1` — full V1 dMint deploy support. Builds the
  commit + reveal scripts for the mainnet-canonical "one reveal,
  many parallel contract UTXOs" shape that every live dMint token
  (RBG, snk, etc.) uses. Pinned against Photonic-Wallet's reference
  layout (`docs/dmint-research-photonic-deploy.md` §2/§3).
- `DmintV1DeployParams` / `DmintV1DeployResult` / `DmintV1ContractInitialState`
  — typed inputs/outputs for the V1 deploy flow.
- `find_dmint_contract_utxos` — chain helper that walks ElectrumX to
  enumerate the N unspent contract UTXOs from a V1 deploy reveal txid.
- `examples/dmint_v1_deploy_demo.py` — end-to-end runnable V1 deploy
  demo with resume support, commit/reveal atomic signing, and
  param-drift defense on the resume file.
- Live-validation: deploy reveal at
  `8eeb333943771991c2752abc78038365ecd76b1a24426f7a3212eea71b6a6564`
  (2026-05-11) produced 4 unspent contracts and was classified
  correctly by the inspect tool.

#### dMint V1 mint scriptSig — golden-vector pinning

- `PowPreimageResult` dataclass — frozen record of
  `(preimage, input_hash, output_hash)` returned by
  `build_pow_preimage`. Forces miners + scriptSig assembly to feed
  from a single byte source, structurally preventing the recurring
  builder-vs-covenant divergence pattern.
- `TestCovenantShape` regression suite — pins the V1 mint scriptSig
  convention against the mainnet snk token mint
  `146a4d688ba3fc1ea9588e406cc6104be2c9321738ea093d6db8e1b83581af3c`
  AND pyrxd's own first successful mint
  `c9fdcd3488f3e396bec3ce0b766bb8070963e7e75bb513b8820b6663e469e530`.
  Two independent mainnet golden vectors.
- `TestFtLockingScriptBuilderCrossEquality` — byte-equality test
  between the two FT-output builders in `pyrxd.glyph.script` and
  `pyrxd.glyph.dmint` (red-team finding R2 from the 0.5.0 pre-release
  audit).

#### CBOR reveal scriptSig

- `build_reveal_scriptsig_suffix` now supports `OP_PUSHDATA4` for
  payloads above 65,535 bytes (up to a 256 KB hard cap). The mainnet
  GLYPH reveal at `b965b32d…9dd6` used 65,569 bytes via PUSHDATA4 —
  pyrxd would have refused to build that shape under the previous
  PUSHDATA2-only cap. Red-team finding R3.

#### Inspect tool

- V1 mint scriptSig parsing — decode + display the 4 canonical
  pushes (nonce, inputHash, outputHash, OP_0). V1 vs V2 distinguished
  by nonce width (4 vs 8 bytes).
- V1 deploy commit/reveal shape detection in the browser inspector.

#### Public-API exports (`pyrxd.glyph`)

- `PowPreimageResult`, `build_dmint_v1_mint_preimage`,
  `build_dmint_v1_ft_output_script` now exported from `pyrxd.glyph`
  for direct import and type annotation.

### Changed (breaking)

- **`build_pow_preimage(...)`** now returns
  `PowPreimageResult(preimage, input_hash, output_hash)` instead of
  the raw 64-byte preimage. Migration:
  ```python
  # before (0.4.0):
  preimage = build_pow_preimage(txid_le, ref, in_script, out_script)
  # after (0.5.0):
  result = build_pow_preimage(txid_le, ref, in_script, out_script)
  preimage = result.preimage  # if you only need the bytes
  ```
- **`build_mint_scriptsig(nonce, preimage, *, nonce_width)`** is now
  `build_mint_scriptsig(nonce, input_hash, output_hash, *, nonce_width)`.
  The two 32-byte hashes MUST come from the same `build_pow_preimage`
  call that produced the mined preimage. Splitting the sources caused
  the M1 covenant-rejection incident — see
  `docs/solutions/logic-errors/dmint-v1-mint-scriptsig-divergence.md`.
- **`build_dmint_v1_mint_preimage(...)`** now returns
  `PowPreimageResult` instead of bytes. Callers feed `.preimage` to
  the miner and `.input_hash`/`.output_hash` to `build_mint_scriptsig`.
- No backward-compatible shim — the old signature could silently
  produce on-chain-rejected transactions, so a hard break with loud
  `TypeError` / `ValidationError` is safer than a deprecation path.

### Fixed

- **CRITICAL (latent): V2 mint reward output was emitting a 25-byte
  plain P2PKH; the V2 covenant requires a 75-byte FT-wrapped reward.**
  Every V2 mint would have been rejected by the network with
  `mandatory-script-verify-flag-failed` once a V2 contract existed on
  chain. No V2 contracts exist yet, so the bug was caught pre-mainnet
  during the 0.5.0 red-team audit (finding R1). V2 reward now uses
  the same `build_dmint_v1_ft_output_script` as V1 — the
  FT-conservation fingerprint `dec0e9aa76e378e4a269e69d` is shared
  via `_PART_C` between V1 and V2.
- **CRITICAL (M1 follow-up): V1 mint scriptSig pushed the wrong
  values.** The original M1 (shipped in 0.4.0 via PR #65) had
  `build_mint_scriptsig` pushing the PoW preimage halves into the
  scriptSig instead of the raw `SHA256d(funding_script)` and
  `SHA256d(OP_RETURN_script)` the covenant expects. Every successful
  mine was rejected by the on-chain covenant; M1 had never
  successfully spent a contract. Fix verified on Radiant mainnet at
  txid `c9fdcd3488f3e396bec3ce0b766bb8070963e7e75bb513b8820b6663e469e530`.
  See `docs/solutions/logic-errors/dmint-v1-mint-scriptsig-divergence.md`.

### Security

- The 0.5.0 pre-release audit was run by 8 independent specialised
  reviewers (security, red-team chain-conformance, data-integrity,
  Python code-quality, simplicity, architecture, performance,
  pattern-recognition). Two CRITICAL findings (R1 + the M1 scriptSig
  bug) and two HIGH findings (R2 cross-builder drift risk, R3
  PUSHDATA4 capability gap) were addressed pre-tag. Medium/low
  findings tracked for 0.5.1.

### Migration notes

Public API consumers must update three call sites:
1. `build_pow_preimage(...)` — use `.preimage` attribute on the
   returned `PowPreimageResult` if you only need the 64 bytes.
2. `build_mint_scriptsig(nonce, preimage, ...)` →
   `build_mint_scriptsig(nonce, result.input_hash, result.output_hash, ...)`.
3. `build_dmint_v1_mint_preimage(...)` — same `.preimage` pattern.

The library raises loud `TypeError` / `ValidationError` immediately
on old-style calls — there is no silent-failure migration path.


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
