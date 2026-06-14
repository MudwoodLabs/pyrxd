# Architecture & Module Map

## Orientation

`pyrxd` is a Python SDK + Click CLI for the **Radiant (RXD)** UTXO blockchain: transaction building with Radiant's BIP143/FORKID sighash, BIP-32/39/44 HD wallets, the on-chain **Glyph** token protocol (NFT / FT / dMint / mutable / WAVE), **Gravity** cross-chain HTLC atomic swaps (BTC-Taproot and ETH-Solidity counter-legs), same-chain partial-tx swaps, and a fail-closed **SPV** verifier — all over an untrusted ElectrumX / Esplora I/O layer. The codebase is **layered**: pure data + crypto primitives at the bottom, then chain I/O, then key custody, then the token / swap protocols, then the CLI. A cross-cutting `pyrxd.security` package (typed errors + secret wrappers + secure RNG) underpins every layer.

```
 ┌──────────────────────────────────────────────────────────────┐
 │ L4  CLI + tooling   cli/   contrib/miner/   devnet.py          │
 ├──────────────────────────────────────────────────────────────┤
 │ L3  protocols       glyph/ (+dmint/)   gravity/ (+watch/)      │
 │                     swap/   btc_wallet/   eth_wallet/          │
 ├──────────────────────────────────────────────────────────────┤
 │ L2  wallets+signing hd/      wallet.py    agent/               │
 ├──────────────────────────────────────────────────────────────┤
 │ L1  core tx + I/O   transaction/  script/  keys.py  spv/       │
 │                     network/  fee_models/  merkle_path.py      │
 ├──────────────────────────────────────────────────────────────┤
 │ L0  foundation      security/  constants.py  hash.py  curve.py │
 │  (cross-cutting)    utils.py  base58.py  aes_cbc.py  crypto/   │
 └──────────────────────────────────────────────────────────────┘
        lower layers never import higher ones (one-way)
```

See also the deeper concept pages: [`gravity.md`](gravity.md), [`partial-tx-swaps.md`](partial-tx-swaps.md), [`radiant-fts-are-on-chain.md`](radiant-fts-are-on-chain.md), [`dmint-v1-deploy.md`](dmint-v1-deploy.md), [`external-miner-protocol.md`](external-miner-protocol.md).

## The dependency rule

**Lower layers never import higher ones.** A primitive (`hash`, `constants`, `curve`) knows nothing about wallets; a wallet knows nothing about the CLI. Within and across subpackages this is enforced by two conventions:

1. **PEP 562 lazy `__getattr__` exports.** Package `__init__.py` files (`pyrxd/__init__.py`, `pyrxd/glyph/__init__.py`, `pyrxd/glyph/dmint/__init__.py`, `pyrxd/script/__init__.py`) map public names to `(module, attr)` and resolve them on first access. This keeps `import pyrxd` cheap and the import graph **minimal** — critically, the browser-hosted inspect tool (`pyrxd.glyph.inspect`) can run under Pyodide without transitively dragging in `coincurve` (no WASM wheel), `aiohttp`, or `websockets`. The same motive drives lazy *internal* imports, e.g. `curve.py` imports `coincurve` inside `curve_add`/`curve_multiply`, and `network/*` imports `btc_txid_from_raw` function-locally.

2. **One-way internal dependency graphs.** Subpackage `__init__` docstrings declare their layering. The canonical example is the dMint subpackage:

   ```
   pyrxd.glyph.dmint:   types ← builders ← chain ← miner   (strictly one-way)
   ```

   Two symbols were deliberately relocated to keep this acyclic: `_OP_STATESEPARATOR` lives in `types.py` (because `builders` needs it and `builders → chain` would cycle), and the `_V1_EPILOGUE_*` constants live in `builders.py` — `chain.py` re-exports both under their original names. Other examples: `script.py` (leaf) `←` `type.py`/`timelock.py`; `spv`: `pow` `←` `{chain, merkle, payment, witness}` `←` `proof`; `security`: `errors` `←` `types`/`secrets` `←` `rng`.

   One **intentional inversion** exists: the `CounterChainLeg` ABC + `CounterClaimFinality` verdict live in `pyrxd.gravity`, and `pyrxd.eth_wallet.htlc_leg` imports *up* into them — while `gravity` imports only `eth_wallet`'s pure leaves (`locator`, `secret`). This is documented in both packages.

## Subsystem map

### Layer 0 — Foundation (cross-cutting, pure data + crypto leaves)

| Subsystem | Path | Purpose | Public entrypoints | Depends on |
|---|---|---|---|---|
| `security` | `src/pyrxd/security/` | Exception hierarchy, secret-material wrappers, secure RNG, trust-boundary newtypes. Nothing here ever logs/prints raw key material. | `RxdSdkError`, `ValidationError`, `NetworkError`, `KeyMaterialError`, `SpvVerificationError`, `CovenantError`, `redact`; `Txid`/`Hex32`/`Hex20`/`Satoshis`/`Photons`/`Nbits`/`RawTx`/`SighashFlag`; `SecretBytes`, `PrivateKeyMaterial`, `secure_random_bytes` | none (base layer) |
| `constants` | `src/pyrxd/constants.py` | Radiant `OpCode` enum (full ref-opcode set), `SIGHASH` flags, `Network`, address/WIF/xkey prefixes, env-overridable tx defaults | `OpCode`, `SIGHASH`, `Network` | stdlib only |
| `hash` | `src/pyrxd/hash.py` | All hash primitives + self-contained pure-Python RIPEMD160 fallback (OpenSSL legacy-provider-unloaded / Pyodide) | `hash256`, `hash160`, `sha256`, `ripemd160`, `hmac_sha256`, `hmac_sha512` | stdlib only |
| `curve` | `src/pyrxd/curve.py` | secp256k1 params + EC group arithmetic; re-validates `on_curve` on every op | `curve`, `Point`, `curve_add`, `curve_multiply` | `constants`, `security` |
| `utils` | `src/pyrxd/utils.py` | Byte-serialization toolbox: `Reader`/`Writer`, varint, pushdata/int encoding, strict DER ser/de, address/WIF decode | `Reader`, `Writer`, `unsigned_to_varint`, `encode_pushdata`, `encode_int`, `serialize_ecdsa_der`, `deserialize_ecdsa_der`, `decode_wif`, `address_to_public_key_hash` | `base58`, `curve`, `constants`, `security` |
| `base58` + `aes_cbc` | `src/pyrxd/base58.py`, `aes_cbc.py` | Two leaf codecs: Base58Check (addresses/WIF/xkeys) and AES-256-CBC + PKCS#7 (used by ECIES in `keys.py`) | `base58check_encode/decode`, `to_base58check`, `from_base58check`, `aes_encrypt_with_iv`, `aes_decrypt_with_iv` | `hash` (base58); Cryptodome (aes_cbc) |
| `crypto` | `src/pyrxd/crypto/` | Photonic-compatible AEAD/KEM for Glyph v2: XChaCha20-Poly1305 (single + chunked-v1) and X25519+HKDF CEK wrapping. **No internal pyrxd deps** — pure leaf over external libs; `__init__` is empty (import `crypto.aead`/`crypto.kem` directly) | `encrypt_xchacha20_poly1305`, `decrypt_xchacha20_poly1305`, `encrypt_chunked`, `decrypt_chunked`, `wrap_cek_x25519`, `unwrap_cek_x25519`, `WrappedCEK` | Cryptodome, `cryptography` (X25519/HKDF) |

> Note: a second `list[int]`-based base58 impl mirroring the TS `@bsv` API also lives in `utils.py`; and two fee-import paths exist (`fee_model.py` ABC vs `fee_models/` package) — minor naming warts.

### Layer 1 — Core tx model, scripts, keys, fees, SPV, chain I/O

| Subsystem | Path | Purpose | Public entrypoints | Depends on |
|---|---|---|---|---|
| `transaction` | `src/pyrxd/transaction/` | Mutable UTXO tx model: serialize, sign orchestration, fee/change, txid/preimage, BEEF/EF codecs. **Radiant sighash** inserts field 8 `hashOutputHashes` (sorted+deduped 36-byte refs, consensus-required) before `hashOutputs` | `Transaction`, `TransactionInput`, `TransactionOutput`, `InsufficientFunds` | `script`, `fee_models`, `hash`, `merkle_path`, `utils`, `constants` |
| `script` | `src/pyrxd/script/` | `Script` ⇄ chunks/ASM, `ScriptTemplate` system (P2PKH/P2PK/OpReturn/BareMultisig/RPuzzle), BIP-65/112 timelock locking-script builders. PEP 562 lazy so `script.script` skips `keys`→`coincurve` | `Script`, `ScriptChunk`, `P2PKH`, `P2PK`, `OpReturn`, `BareMultisig`, `ScriptTemplate`, `build_p2pkh_with_cltv_script`, `build_p2pkh_with_csv_script`, `CsvKind` | `keys`, `hash`, `utils`, `constants`, `security` |
| `keys` | `src/pyrxd/keys.py` | secp256k1 key pairs over coincurve: address/WIF, ECDSA (low-s/recoverable), BIE1/ECIES, BRC-42 child derivation. Hardened: unhashable, no pickle/copy/repr of key bytes, `compare_digest` eq | `PrivateKey`, `PublicKey`, `recover_public_key`, `verify_signed_text` | `curve`, `hash`, `base58`, `aes_cbc`, `utils`, `constants`, `security` |
| `fee_models` | `src/pyrxd/fee_models/` (+ `fee_model.py`) | Pluggable fee computation; `SatoshisPerKilobyte` is the default; remainder routed to first change output (never leaked to miners) | `FeeModel`, `SatoshisPerKilobyte`, `DefaultFeeModel` | consumed by `transaction` |
| `merkle_path` | `src/pyrxd/merkle_path.py` | BSV/BRC-74 **BUMP** inclusion proof (top-level module) used by `Transaction.to_beef`/`from_beef`, `ElectrumXClient`, `ChainTracker`. Distinct from `spv/merkle.py` covenant-wire format | `MerklePath`, `MerklePath.from_hex`, `MerklePath.verify` | `hash`, `utils`, `network.chaintracker` (TYPE_CHECKING) |
| `spv` | `src/pyrxd/spv/` | Pure-CPU, fail-closed Bitcoin SPV: Merkle/PoW/payment, mirrors the on-chain covenant byte-for-byte. **Highest-risk layer.** Self-contained: depends only on `security`; does *not* import `network` | `SpvProofBuilder`, `SpvProof`, `CovenantParams`, `require_spv_sole_authority_cleared`, `verify_chain`, `verify_header_pow`, `verify_tx_in_block`, `build_branch`, `compute_root`, `hash256`, `strip_witness` | `security` only |
| `network` | `src/pyrxd/network/` | Untrusted chain-I/O boundary: ElectrumX WS (Radiant) + Esplora/Core HTTP (BTC), broadcast, confirmation depth, Merkle fetch, RXinDexer extension RPCs. Validates + fail-closes all responses; does *not* import `spv` | `ElectrumXClient`, `ChainTracker`, `BtcDataSource`, `MempoolSpaceSource`, `BlockstreamSource`, `BitcoinCoreRpcSource`, `MultiSourceBtcDataSource`, `MultiSourceBtcFundingReader`, `choose_funding_reader`, `UtxoRecord`, `script_hash_for_address`, `RxinDexerClient` | `security`, `hash`, `merkle_path`, `script.type` |

> `spv/payment.py` (`verify_payment`) is deliberately omitted from `spv/__init__.__all__` (audit F-09): it validates bytes at an offset, not a real output boundary — not a standalone value gate.

### Layer 2 — Wallets + signing

| Subsystem | Path | Purpose | Public entrypoints | Depends on |
|---|---|---|---|---|
| `hd` | `src/pyrxd/hd/` | BIP-39/32/44 HD wallet — the **key-custody core**. The only long-lived secret is the scrubbable 64-byte BIP39 seed; the account xprv is re-derived transiently per access (`_xprv` property) and never stored. Encrypted file v2 (scrypt + AES-256-GCM, atomic 0o600 write). Public signing seam (`account_xpub`/`privkey_for`/`derive_address`) keeps the agent off HdWallet privates. EAGER re-exports | `HdWallet` (`from_mnemonic`/`load`/`build_send_tx`/`send`/`zeroize`/…), `Xprv`, `Xpub`, `ckd`, `master_xprv_from_seed`, `seed_from_mnemonic`, `discover`, `DiscoveryReport`, `AddressRecord` | `keys`, `security`, `wallet` (fee consts + `greedy_select_count`), `network.electrumx`, `script.type`, `transaction`, `constants` |
| `wallet` | `src/pyrxd/wallet.py` | `RxdWallet` single-key facade for plain-RXD P2PKH sends; home of `DUST_THRESHOLD`/`DEFAULT_FEE_RATE` and the **shared** `greedy_select_count` (so RxdWallet / HdWallet / watch-only can't drift on coin choice). Two-pass fee build to avoid stale signatures | `RxdWallet`, `greedy_select_count`, `DUST_THRESHOLD`, `DEFAULT_FEE_RATE` | `keys`, `network.electrumx`, `script.type`, `transaction`, `security`, `utils` |
| `agent` | `src/pyrxd/agent/` | Sign-on-behalf local daemon: holds the unlocked `HdWallet` behind a Unix socket; CLI builds **watch-only** (from xpub), and *requests* a signature gated by per-spend `/dev/tty` confirmation. The cluster's trust boundary. EAGER `__init__` | `AgentSigner.sign`, `AgentDaemon`, `AgentClient`, `WatchOnlyTxBuilder`, `collect_watch_only_utxos`, `TtyConfirmer`, `agent_socket_path`, `SigningRequest`, `SignedResult`, `WatchOnlyUtxo` | `hd.wallet` (via public seam), `hd.bip32`, `wallet`, `network.electrumx`, `constants`, `script.type`, `transaction`, `security` |

### Layer 3 — Protocols (glyph, gravity, swap, counter-chain legs)

| Subsystem | Path | Purpose | Public entrypoints | Depends on |
|---|---|---|---|---|
| `glyph` (facade) | `src/pyrxd/glyph/__init__.py` | Single PEP 562 lazy surface (~70 names) for the whole Glyph API; import-light for the Pyodide inspect tool | `GlyphBuilder`, `GlyphScanner`, `GlyphInspector`, `GlyphMetadata`, `GlyphRef`, `GlyphProtocol`, `build_dmint_mint_tx`, `mine_solution`, `find_dmint_contract_utxos` | all glyph submodules (lazy), `network.rxindexer` |
| glyph types + payload | `glyph/types.py`, `payload.py` | Pure data: `GlyphProtocol` enum, 36-byte `GlyphRef`, metadata records, deterministic CBOR (canonical, RFC 8949) | `GlyphProtocol`, `GlyphRef`, `GlyphMetadata`, `encode_payload`, `decode_payload`, `build_mutable_scriptsig` | `security`, `cbor2`, `glyph.dmint` (TYPE_CHECKING cycle break) |
| glyph script | `glyph/script.py` | Build/classify consensus locking scripts: 63-byte NFT singleton (`OP_PUSHINPUTREFSINGLETON 0xd8`), 75-byte FT (`OP_PUSHINPUTREF 0xd0` + 12-byte CSH epilogue), commit hashlocks, mutable NFT | `build_nft_locking_script`, `build_ft_locking_script`, `build_commit_locking_script`, `build_mutable_nft_script`, `hash_payload`, `is_ft_script`, `is_nft_script`, `extract_ref_from_ft_script`, `iter_input_refs` | `security`, `glyph.types` |
| `GlyphBuilder` | `glyph/builder.py` | Primary user-facing unsigned-tx orchestrator: commit→reveal mint, FT/NFT transfer, 2-tx/3-tx dMint deploy (V2 refused unless `allow_v2_deploy=True`) | `GlyphBuilder`, `DmintV1DeployParams`/`Result`, `DmintV2DeployParams`/`Result`, `MutableRevealScripts`, `ContainerRevealScripts`, `FtTransferParams` | `glyph.script`/`payload`/`types`/`dmint`, `security`, `transaction` (lazy) |
| glyph FT | `glyph/ft.py` | Conservation-aware FT coin selection + transfer build; `sum(in ft_amount)==sum(out)`; must filter `is_ft_script` | `FtUtxo`, `FtUtxoSet`, `FtTransferResult` | `glyph.script`/`types`, `security` |
| glyph read path | `glyph/scanner.py`, `inspector.py`, `_inspect_core.py`, `inspect.py` | `GlyphInspector` (pure parser tx→typed Glyph), `GlyphScanner` (address→inventory; caller owns the client); `inspect.py` is the import-light Pyodide/CLI facade | `GlyphScanner`, `GlyphInspector`, `GlyphItem`, `scan_address`, `scan_script_hash` | `glyph.script`/`payload`/`types`/`dmint`, `network.electrumx`, `transaction` (lazy) |
| dMint | `glyph/dmint/` | Deterministic PoW mint contract. `types ← builders ← chain ← miner`. V1 = mainnet format; V2 spec-complete but quarantined (`V2UnvalidatedWarning`). Contract script, on-chain state parse, discovery, PoW loop, mint-tx assembly | `DmintDeployParams`, `DmintCborPayload`, `DmintState`, `DmintAlgo`, `DaaMode`, `build_dmint_v1_contract_script`, `find_dmint_contract_utxos`, `find_dmint_funding_utxo`, `build_pow_preimage`, `mine_solution`, `verify_sha256d_solution`, `build_dmint_mint_tx`, `build_mint_scriptsig` | `glyph.types`/`script`, `security`, `transaction`/`network` (lazy) |
| glyph aux | `glyph/creator.py`, `wave.py`, `soulbound_covenant.py`, `confusables.py`, `timelock.py`, `encrypted_content.py`, … | Optional extensions: V2 creator sigs, WAVE naming `[2,5,11]`, credential binding, encrypted/timelocked reveals, soulbound self-replication covenant, homograph defenses | `sign_metadata`, `verify_creator_signature`, `WaveResolver`, `WaveRecord`, `build_wave_metadata`, `classify_glyph_metadata` | `glyph.types`/`payload`/`script`/`dmint`, `network.rxindexer`, coincurve/Cryptodome |
| `gravity` (HTLC core) | `src/pyrxd/gravity/` | Chain-neutral HTLC swap engine: pure 13-state FSM + live `SwapCoordinator` driving a Radiant covenant asset leg against a pluggable counter-leg; REF / timelock-margin / reorg gates. Also a **legacy** SPV-oracle `GravityTrade` path kept alongside | `SwapCoordinator` (import from `pyrxd.gravity.swap_coordinator` — *not* re-exported), `advance`/`SwapState`/`SwapEvent`/`NegotiatedTerms`/`SwapRecord`, `MarginPolicy`, `assess_claim_finality`, `verify_ref_authenticity`, `build_htlc_covenant_{ft,nft,rxd}`, `RadiantCovenantLeg`, `SeenStore`, `GravityTrade` (legacy) | `btc_wallet`, `eth_wallet` (pure leaves), `security`, `network`, `glyph`, `spv`, `transaction`/`script`/`keys` |
| `gravity.watch` | `src/pyrxd/gravity/watch/` | Persistent reconciliation/alerting loop. v1 **alert-only** (holds no key); pure `decide`/`reconciler` reuse the coordinator's gate functions verbatim — a *driver*, not a second finality brain. One narrow keyless dust-only autonomous BTC-refund executor | `decide`/`Decision`/`Intent`/`Observations`, `Reconciler`, `ChainObserver`, `run_loop`, `Executor`/`NullExecutor`, `AlertChannel`/`DedupAlerter`/`Page` | `gravity`, `btc_wallet`, `network` |
| `swap` | `src/pyrxd/swap/` | Same-chain RXD/FT trades via `SIGHASH_SINGLE\|ANYONECANPAY` signature-level atomicity. Pure core (`partial`/`types`) imports no network; `resolve` isolates ElectrumX. Independent of `gravity` | `create_offer`, `accept_offer`, `FundingInput`, `Asset`/`AssetKind`/`SwapOffer`/`SwapTerms`, `fetch_funding_input`, `fetch_transaction` | `glyph` (FT script), `transaction`/`script`/`keys`, `network.electrumx` (deferred), `security` |
| `btc_wallet` | `src/pyrxd/btc_wallet/` | Bitcoin-family counter-leg: single P2TR HTLC (`OP_SHA256 <H>` claim leaf = p-reveal channel + CSV refund leaf), BIP341/340. Leaf relative to gravity. In-code mainnet audit gate | `BitcoinTaprootLeg`, `BitcoinCoreBroadcaster`, `require_audit_cleared`, `build_htlc`, `build_claim_tx`, `build_refund_tx`, `scrape_secret`, `BtcHtlc`, `Timelock`, `generate_keypair`, `build_payment_tx`, `validate_btc_address` | `security`, `spv` |
| `eth_wallet` | `src/pyrxd/eth_wallet/` | EVM counter-leg: hashlock+timelock Solidity HTLC, sha256 `p` shared with the unchanged Radiant covenant. web3/aiohttp imported lazily. Partial inversion: imports *up* into `gravity`'s `CounterChainLeg`/finality verdict | `EthHtlcLocator`, `recover_secret` (only eager exports; `EthHtlcContractLeg`/`rpc`/`private_submit` imported directly when web3 present) | `gravity` (UP — ABC + verdict), `security` |

> `recover_secret` (both btc/eth) scans **every** 32-byte calldata/log window by `sha256==H` (never by offset — the C-PARSER discipline) and treats a reverted-but-mined claim as not-claimed.

### Layer 4 — CLI + tooling

| Subsystem | Path | Purpose | Public entrypoints | Depends on |
|---|---|---|---|---|
| `cli` | `src/pyrxd/cli/` | Click command tree (`wallet`/`glyph`/`agent`/`query`/`regtest`/`setup`) on a shared `CliContext` + typed-error/exit-code boundary. Subcommand modules are registered by `main.py` via `cli.add_command()` (avoids a cyclic import) | `pyrxd.cli.main.run`, `pyrxd.cli.main.cli`, `pyrxd.cli.context.CliContext`; console scripts `pyrxd`, `python -m pyrxd` | `security`, `hd`/`wallet`, `glyph`, `agent`, `network.electrumx` (lazy), `devnet`, `utils`/`constants` |
| `contrib` (miner) | `src/pyrxd/contrib/miner/` | Multiprocessing pure-Python SHA256d reference miner satisfying the dMint external-miner protocol; ships as `pyrxd-miner`. **No semver promise** on its import surface — a CLI delivery vehicle | console script `pyrxd-miner`, `python -m pyrxd.contrib.miner` (invoked, not imported, by `dmint.mine_solution_external`) | `glyph.dmint` (verifier counterpart) |
| `devnet` | `src/pyrxd/devnet.py` | One-command regtest node over docker (mine mature coinbase, fund address). Regtest-only, 127.0.0.1-bound, fixed non-secret creds. Backs `pyrxd regtest` | `RegtestNode`, `DevKey` (driven by `cli.regtest_cmds`) | stdlib only (fixed `docker` argv) |

## Trust boundaries / what is pre-audit

Read this before depending on anything that moves real value.

| Boundary | Status | Honest caveat |
|---|---|---|
| **Gravity swaps** (`gravity/`, counter-legs, `eth_wallet`) | **Pre-external-audit, dust-only** | Every value-bearing network sits behind `require_audit_cleared` / `AUDIT_CLEARED_NETWORKS` (only regtest/signet/test chains auto-cleared). `require_measured` refuses estimated timelock margins; value-scaled reorg burial must be supplied or `accept_flat_burial=True` for dust. Residual free-option (reveal-on-long-leg) is *bounded, not eliminated*. `eth_wallet` is "designed-and-unproven" per its own docstring. |
| **SPV proof + REF reads** | Highest-risk; **single-source** | `spv/` is "the highest-risk layer: a forged SPV proof accepted here drains a Maker's RXD." The sole-authority gate fails closed on value-bearing networks unless `audit_cleared=True` (no network-difficulty / most-work enforcement yet — audit F-01). The Gravity `verify_ref_authenticity` gate is the *only* defense against a forged self-singleton (consensus can't verify mint provenance — proven on regtest, audit R1). RXD funding depth is single-source v1 (a SPOF accepted only for dust). |
| **Key material** | Scrubbable seed only | The one long-lived secret is the 64-byte BIP39 seed in `SecretBytes`; the account xprv is re-derived transiently and `zeroize()`/lock memsets it. `PrivateKey`/`Xprv` are unhashable, non-pickleable, redacted-repr, `compare_digest`-eq. The `agent` never hands out the key — only confirmed signatures (`TtyConfirmer` fails closed with no tty). |
| **Untrusted I/O** (`network/`) | Validated, fail-closed | `wss://` required by default; raw server responses never echoed in errors; returned tx bytes bound to the requested txid (F-004); confirmation depth floors unknown→0. |
| **`crypto/` decrypt** | Generic errors by design | Decrypt error messages never reveal which check failed or any input. Post-quantum ML-KEM is out of scope. |
| **`contrib.*`** | No API stability | Ships in the wheel but carries no semver promise on its import surface. |

There is **no `assert` in `src/`** for invariants — every safety check raises a typed `ValidationError`/`CovenantError` so `python -O` can't strip it.

## Where to add things

| I want to… | Touch | Notes |
|---|---|---|
| Add a CLI command | a `*_cmds.py` in `src/pyrxd/cli/`, then register it in `cli/main.py` via `cli.add_command()` | Don't import `cli` from the subcommand module (breaks the cycle). Respect the `--json/--yes` broadcast gate (`CliContext.is_destructive_mode_safe()`). |
| Add / classify a token script type | `src/pyrxd/glyph/script.py` (builder + regex classifier + extractor), then wire it in `glyph/builder.py` and the read path (`inspector.py`) | Keep length invariants (63/75-byte) and the input/output ref conservation rule. |
| Add a swap counter-chain | implement the `CounterChainLeg` ABC + `CounterClaimFinality` verdict (`gravity/counter_chain_leg.py`, `finality.py`) in a new `*_wallet/` package (model on `btc_wallet`/`eth_wallet`); add a chain registry + the in-code audit gate | New legs are duck-typed; import only `gravity`'s pure abstractions, never the coordinator. Default to dust-only behind `require_audit_cleared`. |
| Add a covenant / HTLC SPK | `gravity/htlc_covenant.py` + `htlc_spend.py` (swap HTLCs) or `glyph/*` (token covenants); mirror it in `spv/` if it must be SPV-verified | The SPV verifier must stay byte-for-byte with the on-chain script. See [`covenant-building-blocks.md`](covenant-building-blocks.md). |
| Add a fee model | subclass `FeeModel` in `src/pyrxd/fee_models/` | `Transaction.fee()` accepts a model, an int rate, or defaults to `SatoshisPerKilobyte`. |
| Add a dMint DAA mode or mining algo | `glyph/dmint/types.py` (`DaaMode`/`DmintAlgo`) + `glyph/dmint/miner.py` (target math + sweep) + `contrib/miner/` if external | Only `SHA256D` is implemented; BLAKE3/K12 raise `NotImplementedError`. Keep the `types ← builders ← chain ← miner` order acyclic. |
| Add an indexer / ElectrumX RPC | `src/pyrxd/network/rxindexer.py` (`call_extension` for `glyph.*`/`wave.*`/`swap.*`) or `network/electrumx.py` | Validate + fail-close every response before it crosses into the SDK. |
| Add a hash / codec primitive | `src/pyrxd/hash.py`, `base58.py`, or `utils.py` (Layer 0 leaves) | Keep these dependency-free (or hash-only) so higher layers can depend on them freely. |
| Wrap a new trust-boundary value | add a newtype in `src/pyrxd/security/types.py` (validate in `__new__`) | Subclass an immutable builtin; wrap external input ASAP, then treat as trusted downstream. |
