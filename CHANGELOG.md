# Changelog

All notable changes to pyrxd are documented here. Format based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

- `docs/threat-model.md` — threat model.
- `docs/tx-construction.md` — transaction construction reference.
- `docs/dmint-followup.md` — premine vs PoW dMint scope.
- `docs/dmint-research-photonic.md` — Photonic Wallet TS reverse
  engineering.
- `docs/dmint-research-mainnet.md` — decoded live mainnet dMint
  contracts.
- `docs/plans/` — feature plans.
- `docs/solutions/` — implementation notes for cross-cutting features.

### Known limitations

- **dMint PoW-based distributed FT mint not implemented.** Premine-at-deploy works via `prepare_ft_deploy_reveal`. PoW commit/reveal + ASERT/LWMA difficulty adjustment is documented as future work in `docs/dmint-followup.md`. Premine-only consumers do not need it.
- **Gravity covenant variants beyond sentinel-artifact** are
  experimental and have not been audited.
- **No third-party security audit yet.** Use at your own risk in
  production.

[0.2.0]: https://github.com/MudwoodLabs/pyrxd/releases/tag/v0.2.0
