# Photonic interop vector generator

One-off Node.js bridge script that calls **Photonic Wallet's actual
encryption/timelock/reveal source files** with fixed inputs and dumps a JSON
fixture file used by pyrxd's TIMELOCK interop tests.

## Why this exists

pyrxd's `pyrxd.glyph.timelock` implementation must produce byte-identical
output to Photonic Wallet for the protocol to be interop-compatible. There
are two ways to validate that:

1. **Mainnet vector** — find a real Photonic-minted TIMELOCK Glyph on
   Radiant mainnet, parse it, decrypt it, assert byte-equality. **Not
   viable today** — no Photonic TIMELOCK tokens have been deployed to
   Radiant mainnet (verified 2026-05-18).
2. **Bridge script** — call Photonic's TypeScript primitives directly with
   fixed inputs, record their outputs, commit the fixture, assert pyrxd
   reproduces the same bytes. **This is that script.**

## What it covers

| Section | Photonic function called | Fixture key |
|---|---|---|
| XChaCha20-Poly1305 | `encryptXChaCha20Poly1305` | `xchacha20_poly1305` |
| HKDF-SHA256 | `deriveKeyHKDF` | `hkdf_sha256` |
| X25519 ECDH | `@noble/curves/ed25519` (Photonic's underlying lib) | `x25519` |
| Content hash | `hashContent` | `hash_content` |
| CEK hash commitment | `computeCEKHash` + the `sha256:<hex>` string format | `cek_hash_commitment` |
| Mint metadata (block mode) | `addTimelockToMetadata` | `timelock_metadata_block_mode` |
| Mint metadata (time mode + hint) | `addTimelockToMetadata` | `timelock_metadata_time_mode` |
| Reveal proof CBOR + OP_RETURN script | `createRevealProof` | `reveal_proof_block_mode`, `reveal_proof_time_mode`, `reveal_proof_with_hint` |

## What it does NOT cover

- **The on-chain reveal transaction wrapper.** pyrxd builds its own
  transactions; the bridge only generates the OP_RETURN *script* bytes
  that go into the reveal tx, not the wrapping tx.
- **The AAD Photonic's WALLET binds to a recipient wrap.** `gen-vectors.ts`
  does call the library's `wrapCEK` (classical X25519 only; pyrxd defers
  ML-KEM-768), but it supplies an AAD of its own choosing, and the library
  takes the AAD from its caller — so a library-level wrap vector cannot say
  what the app binds. That is `gen-app-path-vector.ts`, below.
- **`isUnlocked` / `getUnlockRemaining`** — these are pure-Python logic
  in pyrxd, no interop concern. Tested via in-package round-trip.

## The app-path recipient wrap (`gen-app-path-vector.ts`)

Calls `encryptContent` from `packages/app/src/encryptionService.ts` — the
function Photonic's mint screen calls — in recipient mode, and lets it compute
the wrap AAD itself (the UTF-8 text of `crypto.cek_hash`). Every
`crypto.getRandomValues` draw is served from a fixed queue with its length
checked, the run fails if a draw is left over, each draw's role (CEK, chunk
nonce, ephemeral key, wrap nonce, locator key) is checked against the output,
and Photonic's own `decryptContent` must open the result before anything is
printed. It needs no dependencies of its own; Photonic's modules resolve theirs
from the Photonic checkout.

```bash
PHOTONIC_ROOT=/abs/path/to/Photonic-Wallet \
PHOTONIC_COMMIT=$(git -C /abs/path/to/Photonic-Wallet rev-parse HEAD) \
  npx tsx gen-app-path-vector.ts
```

Paste the output into `tests/fixtures/photonic_timelock_vectors.json` under
`app_encrypt_content_recipient`. It regenerates byte-for-byte for a given
Photonic commit.

## Running

```bash
# 0. FIRST: check out a known UPSTREAM commit, and write it down.
#    This script reads the checkout's WORKING TREE. That checkout has an
#    `upstream` remote (Radiant-Core) and an `origin` fork remote, and it is
#    routinely left on a feature branch — measured 2026-09-07, its tree was
#    44 files and 5,941 deletions away from upstream/main in packages/lib/src.
#    Generating from that tree yields vectors that are not upstream's, and
#    nothing downstream would reveal it: the interop test would still pass,
#    proving only that pyrxd matches whatever tree happened to be checked out.
#
#      git -C ../../../../Photonic-Wallet fetch upstream
#      git -C ../../../../Photonic-Wallet checkout upstream/main
#      git -C ../../../../Photonic-Wallet rev-parse HEAD   # record this
#
#    Put that sha in the fixture's meta.photonic_commit, and make sure it
#    matches tests/fixtures/photonic_upstream_pin.json.
#
# 1. Confirm Photonic-Wallet is checked out at the expected location
#    (defaults to ../../../../Photonic-Wallet/packages/lib relative to
#    this script — adjust via PHOTONIC_LIB env var)
ls ~/path/to/Photonic-Wallet/packages/lib/src/encryption.ts

# 2. Install deps (one-time)
cd scripts/gen-photonic-vectors
npm install

# 3. Generate fixtures (commit the JSON output)
npm run gen > ../../tests/fixtures/photonic_timelock_vectors.json
```

## Determinism guarantee

All inputs are FIXED — no `Math.random()`, no system clock, no environment
state. The script must produce byte-identical output on every run for a
given Photonic version. If output changes, either:

- Photonic's spec changed (regenerate, review the diff, update the
  pyrxd implementation)
- Photonic's underlying crypto library changed in a non-backward-compatible
  way (rare, investigate)
- The bridge script itself was modified (intentional; bump the
  `generated_by` version)

## License

Apache-2.0, matching both pyrxd and Photonic-Wallet. This script extracts
data from Photonic's source code but does not redistribute it; the
generated fixtures are factual outputs not subject to copyright.
