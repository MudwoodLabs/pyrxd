# BIP44 Derivation Path Fragmentation in the Radiant Ecosystem

**Date:** May 2026
**Status:** Public research finding; supports the pyrxd derivation path fix landing in this PR
**Methodology:** Direct inspection of public source code repositories

---

## Summary

The Radiant ecosystem has at least five different BIP44 derivation path implementations across major wallets and SDKs. Per the SatoshiLabs SLIP-0044 registry, Radiant's officially registered coin type is **512**. **Only Tangem (the hardware wallet) follows the spec.** Every Radiant-native software wallet checked uses coin type 0 (Bitcoin's number, presumably copy-pasted from upstream Bitcoin code). *Update 2026-09-16: that was true of the repository this document inspected, which had already stopped being the maintained one — Photonic Wallet v3.0.0 (2026-05-09) moved to coin type 512; see its section below.* The pyrxd Python SDK has historically used 236 (which is BSV's coin type, presumably copy-pasted from BSV-related code). Radiant Core (the node software) doesn't use BIP44 at all.

This fragmentation means a single BIP39 mnemonic produces **completely different addresses** depending on which wallet derives the keys. Users switching between wallets see "missing" funds because their addresses live on a different derivation path than the new wallet looks at. This is silent and confusing — there's no error message, just a zero balance where funds should be.

This PR (in pyrxd) fixes pyrxd's contribution to the problem by switching the default derivation path to the spec-correct `m/44'/512'/0'`. Users with existing pyrxd wallets at the old path can recover via the env var override. The fix aligns pyrxd with both the SLIP-0044 spec and Tangem's existing implementation.

---

## The official spec

Per the [SatoshiLabs SLIP-0044 registry](https://github.com/satoshilabs/slips/blob/master/slip-0044.md), Radiant's officially registered BIP44 coin type is `512` (`0x80000200`):

```
| 512        | 0x80000200                    | RXD     | Radiant                           |
```

This means the spec-correct BIP44 derivation path for Radiant is:

```
m/44'/512'/0'/0/0
```

Verified against the registry as of May 2026.

---

## What each major wallet actually uses

### Tangem (hardware wallet) — `m/44'/512'/0'/0/0` ✓ matches spec

Source: [BlockchainSdk/Common/Derivations/DerivationConfigV3.swift](https://github.com/tangem/blockchain-sdk-swift/blob/develop/BlockchainSdk/Common/Derivations/DerivationConfigV3.swift) (and V1, V2 — same path in all three)

```swift
case .radiant:
    return "m/44'/512'/0'/0/0"
```

**This is the only Radiant implementation found to follow the SLIP-0044 specification.** Tangem's `develop` branch contains a full Radiant integration. The same coin type 512 path appears in all three derivation config versions (V1, V2, V3), indicating a maintained, intentional choice.

The integration is on the `develop` branch and recent release branches; checking only `main` would miss it (an earlier draft of this research did exactly that and incorrectly claimed Tangem had no Radiant support — corrected after thorough branch search).

**Caveat about Glyph token support**: Tangem's Radiant integration handles plain RXD send/receive only. The integration code at [BlockchainSdk/Blockchains/Radiant/](https://github.com/tangem/blockchain-sdk-swift/tree/develop/BlockchainSdk/Blockchains/Radiant) contains:

- `RadiantWalletManager.swift`
- `RadiantTransactionBuilder.swift`
- `RadiantTransactionUtils.swift`
- `RadiantAddressService.swift`
- Domain types for unspent outputs and amounts

Searching all of these for "glyph", "token", "OP_RETURN", "FT", or "NFT" returned **zero matches**. Tangem's app does not parse Glyph protocol payloads. This means:

1. Tangem will display the underlying RXD photon value of a Glyph UTXO (typically 546 photons, the dust amount), but will not recognize the Glyph token itself
2. If a user attempts to send those photons via Tangem, the transaction would not preserve the Glyph protocol's required UTXO structure (OP_PUSHINPUTREF references, OP_RETURN payloads, etc.) and **the Glyph token would be destroyed**
3. **Tangem-derived addresses are currently unsafe destinations for Glyph tokens** — only for plain RXD

This is a serious safety concern for any user who might assume "hardware wallet support" implies "safe storage for everything on the chain." A separate ecosystem coordination effort to add Glyph protocol awareness to Tangem's Radiant integration would be valuable.

### Photonic Wallet — `m/44'/512'/0'/0/0` since v3.0.0; `m/44'/0'/0'/0/0` legacy

**Corrected 2026-09-16.** The May 2026 text below this note read `RadiantBlockchain-Community/photonic-wallet` (`master`), which hardcoded `m/44'/0'/0'/0/0` in `packages/app/src/keys.ts`. That repository had stopped moving on 2026-04-11; the maintained one is [`Radiant-Core/Photonic-Wallet`](https://github.com/Radiant-Core/Photonic-Wallet), and its v3.0.0 release (2026-05-09, `73df0e49`) moved new wallets to SLIP-0044 coin type **512**, with dual-path restore added 2026-05-12 (`b3a3af8f`): a restored wallet is derived at 512 first and falls back to 0 when the saved address matches the legacy path.

Source: [packages/lib/src/wallet.ts lines 39–68](https://github.com/Radiant-Core/Photonic-Wallet/blob/becf41a731e78ab98fdd88652527d7dda12784c6/packages/lib/src/wallet.ts#L39-L68) (constants and path template) and [packages/app/src/keys.ts](https://github.com/Radiant-Core/Photonic-Wallet/blob/becf41a731e78ab98fdd88652527d7dda12784c6/packages/app/src/keys.ts) (legacy detection), at `becf41a7`, the commit pyrxd pins in `tests/fixtures/photonic_upstream_pin.json`.

```typescript
export const RADIANT_COIN_TYPE = 512;
export const LEGACY_COIN_TYPE = 0;
export const DEFAULT_COIN_TYPE = RADIANT_COIN_TYPE;
// ...
derivationPath: `m/44'/${coinType}'/0'/0/0`,
swapDerivationPath: `m/44'/${coinType}'/0'/0/1`,
encryptionDerivationPath: `m/44'/${coinType}'/0'/2/0`,
```

Wallets created before v3.0.0 remain at **coin type 0**; pyrxd's `hd/discovery.py` scans coin types 0, 512 and 236, so a mnemonic from either Photonic generation is found on recovery.

### Electron-Radiant — `m/44'/0'/...`

Source: [electroncash/keystore.py line 744](https://github.com/RadiantBlockchain-Community/electron-radiant/blob/master/electroncash/keystore.py)

```python
def bip44_derivation(account_id):
    bip  = 44
    coin = 1 if networks.net.TESTNET else 0
    return "m/%d'/%d'/%d'" % (bip, coin, int(account_id))
```

Also uses **coin type 0** for mainnet. Inherited essentially unchanged from the Electron-Cash fork.

### Radiant Orbital Wallet — `m/44'/0'/0'/0/0`

Source: [src/utils/constants.ts lines 12-13](https://github.com/RadiantBlockchain-Community/radiant-orbital-wallet/blob/main/src/utils/constants.ts)

```typescript
export const DEFAULT_WALLET_PATH = "m/44'/0'/0'/0/0";
export const DEFAULT_IDENTITY_PATH = "m/44'/0'/0'/1/0";
```

Also **coin type 0**. Same pattern as Photonic.

### pyrxd SDK (this repo) — historically `m/44'/236'/0'/0/0`, now `m/44'/512'/0'/0/0`

The pyrxd README previously cited coin type 236 explicitly:

> Radiant uses BIP44 coin type 236, not 0 (Bitcoin). Code copied from Bitcoin examples that hardcodes m/44'/0'/0'/0/0 will derive the wrong addresses.

But coin type **236 is BitcoinSV's**, not Radiant's, per SLIP-0044:

```
| 236        | 0x800000ec                    | BSV     | BitcoinSV                         |
```

So pyrxd was using a different "wrong" path than the Radiant-native software wallets. Likely copied from BSV-related code at some point in pyrxd's lineage.

**This PR fixes that.** The default is now `m/44'/512'/0'`. Users with funds at the old path can recover by setting `RXD_PY_SDK_BIP44_DERIVATION_PATH=m/44'/236'/0'`.

### Radiant Node (Radiant Core) — `m/0'/0'/...` (legacy, not BIP44)

Source: [src/wallet/wallet.cpp lines 286-293](https://github.com/RadiantBlockchain-Community/radiant-node/blob/master/src/wallet/wallet.cpp)

```cpp
metadata.hdKeypath = "m/0'/1'/" +
metadata.hdKeypath = "m/0'/0'/" +
```

Radiant Core doesn't use BIP44 at all. It uses the older Bitcoin Core HD scheme (`m/0'/0'` for receive, `m/0'/1'` for change), inherited from its Bitcoin Cash / BSV codebase ancestry.

---

## The fragmentation matrix

| Source | Coin type | Full path | Spec-correct? | Glyph-aware? |
|---|---|---|---|---|
| **SLIP-0044 official spec** | 512 | `m/44'/512'/0'/0/0` | (defines spec) | n/a |
| **Tangem** (hardware) | **512** | `m/44'/512'/0'/0/0` | ✓ Yes | ✗ No |
| Photonic Wallet ≥ v3.0.0 (2026-05-09) | **512** (0 retained for pre-v3 wallets) | `m/44'/512'/0'/0/0` | ✓ Yes | ✓ Yes |
| Photonic Wallet < v3.0.0 | 0 | `m/44'/0'/0'/0/0` | ✗ No | ✓ Yes |
| Electron-Radiant | 0 | `m/44'/0'/0'/...` | ✗ No | partial |
| Radiant Orbital | 0 | `m/44'/0'/0'/0/0` | ✗ No | ✓ Yes |
| pyrxd SDK (after this PR) | 512 | `m/44'/512'/0'/0/0` | ✓ Yes | ✓ Yes |
| pyrxd SDK (before this PR) | 236 (BSV's) | `m/44'/236'/0'/0/0` | ✗ No | ✓ Yes |
| Radiant Core | n/a (not BIP44) | `m/0'/0'/...` | ✗ No | ✗ No |

**No two of these are interoperable from the same mnemonic** (other than pyrxd-after-this-PR, Tangem and Photonic ≥ v3.0.0, which all use 512). A user who created a wallet in pre-v3 Photonic and recovers into pyrxd at the default path alone would see zero balance — their funds live at coin type 0; `pyrxd.hd.discovery` exists to scan the other paths for exactly this case.

The split is even more painful than just "different paths": the only spec-compliant implementation (Tangem) is also the only one that doesn't understand Glyph tokens. The Glyph-aware implementations all use non-spec paths. After this PR, pyrxd is both spec-compliant AND Glyph-aware — the first implementation in the ecosystem to be both.

---

## Practical implications for users

1. **Cross-wallet recovery is broken by default.** A mnemonic from one wallet imported into another shows different addresses and zero balance. Users assume their funds are gone; they're actually at addresses the new wallet doesn't know to look at.

2. **The "right" path depends on where you've been holding funds**, not on the official spec. Most active users are on coin type 0 (whichever software wallet they happen to use). Tangem users are on 512.

3. **Manual derivation is the only safe migration path.** A user moving between wallets must derive their old wallet's address using the old wallet's specific path, then sweep funds to the new wallet's first receive address.

4. **Backups must include the derivation path**, not just the mnemonic. A mnemonic alone is insufficient for cross-wallet recovery in the current state of the ecosystem.

---

## What this PR fixes

This PR addresses the pyrxd-specific contribution to the problem:

1. **Default BIP44 path changed** from `m/44'/236'/0'` (BSV's coin type) to `m/44'/512'/0'` (Radiant's spec-correct coin type per SLIP-0044, matching Tangem's implementation).

2. **`HdWallet` now respects the env var override.** A pre-existing bug meant `HdWallet` ignored `RXD_PY_SDK_BIP44_DERIVATION_PATH` even though the low-level `bip44_derive_xprv_from_mnemonic` honored it. Fixed by parsing the central `BIP44_DERIVATION_PATH` constant at import time rather than hardcoding an internal `_COIN_TYPE` constant.

3. **Migration path documented.** Users with funds on the old path can recover by setting `RXD_PY_SDK_BIP44_DERIVATION_PATH=m/44'/236'/0'` before running any pyrxd command, sweeping funds to a new spec-correct address, then unsetting the env var.

4. **All hardcoded "236" references removed** from CLI commands, docstrings, examples, and README.

What this PR does **not** fix (those need separate ecosystem coordination):

- The software wallets (Photonic, Electron-Radiant, Orbital) still use coin type 0
- Tangem's lack of Glyph token awareness
- Radiant Core's non-BIP44 derivation
- Cross-wallet recovery tooling that lets users find funds regardless of which wallet originally derived them

---

## Recommendations for ecosystem coordination

The Tangem finding tilts the calculus toward coin type 512 as the canonical path:

- Tangem is shipping production hardware wallet support at coin type 512 *right now*
- Hardware wallet integration is far harder to change than software wallet code
- The practical answer is "have software wallets converge to where Tangem already is"
- pyrxd's switch to 512 in this PR is a concrete first step

Suggested next steps for the broader ecosystem:

1. **Software wallets migrate from coin type 0 to 512**, with backward-compat recovery so existing user funds at coin type 0 can still be swept. The migration is one-time pain for permanent ecosystem coherence.

2. **Publish a migration tool** that takes a mnemonic and derives addresses on all known paths (0, 236, 512), so users can find and sweep funds regardless of original wallet.

3. **Update wallet documentation everywhere** to specify the derivation path used, so future fragmentation is at least visible.

4. **Push for Tangem Glyph protocol support** as a separate workstream. Even with derivation paths aligned, Tangem is currently unsafe as a destination for Glyph tokens. Adding Glyph protocol awareness to [BlockchainSdk/Blockchains/Radiant/RadiantTransactionBuilder.swift](https://github.com/tangem/blockchain-sdk-swift/blob/develop/BlockchainSdk/Blockchains/Radiant/RadiantTransactionBuilder.swift) is the relevant integration target.

These are all out of scope for this PR but worth filing as separate issues against the relevant repos.

---

## Sources

All paths and code references verified via direct curl against public GitHub raw content, May 2026:

- [SLIP-0044 registry](https://github.com/satoshilabs/slips/blob/master/slip-0044.md)
- [Tangem blockchain-sdk-swift DerivationConfigV3.swift (develop branch)](https://github.com/tangem/blockchain-sdk-swift/blob/develop/BlockchainSdk/Common/Derivations/DerivationConfigV3.swift)
- [Tangem Radiant integration directory](https://github.com/tangem/blockchain-sdk-swift/tree/develop/BlockchainSdk/Blockchains/Radiant)
- [Photonic Wallet wallet.ts (coin types, path template)](https://github.com/Radiant-Core/Photonic-Wallet/blob/becf41a731e78ab98fdd88652527d7dda12784c6/packages/lib/src/wallet.ts#L39-L68) and [keys.ts (legacy detection)](https://github.com/Radiant-Core/Photonic-Wallet/blob/becf41a731e78ab98fdd88652527d7dda12784c6/packages/app/src/keys.ts) — Radiant-Core/Photonic-Wallet at `becf41a7`
- [Electron-Radiant keystore.py](https://github.com/RadiantBlockchain-Community/electron-radiant/blob/master/electroncash/keystore.py)
- [Radiant Orbital Wallet constants.ts](https://github.com/RadiantBlockchain-Community/radiant-orbital-wallet/blob/main/src/utils/constants.ts)
- [Radiant Core wallet.cpp](https://github.com/RadiantBlockchain-Community/radiant-node/blob/master/src/wallet/wallet.cpp)

## Methodological note

This investigation initially missed Tangem's Radiant support by checking only the `main` branch of `tangem/blockchain-sdk-swift` and finding zero matches for "radiant". A more thorough search of all branches found the integration on `develop` and on a feature branch. The corrected finding is that Tangem absolutely supports Radiant on the spec-correct path.

Anyone replicating this research should check `develop` and recent release branches in addition to default branches. The cost of a wrong negative claim ("X doesn't support Y") in this context is not just embarrassment — it's strategic decisions made on bad data.
