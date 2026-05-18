/**
 * Photonic interop vector generator for pyrxd TIMELOCK tests.
 *
 * Imports Photonic Wallet's actual encryption/timelock/reveal source files
 * by relative path (so the fixtures are guaranteed to be Photonic's output,
 * not a re-implementation), calls each primitive with FIXED inputs, and
 * dumps a JSON fixture file pyrxd's Python tests load to assert byte-
 * equivalence.
 *
 * Scope: cryptographic primitives + CBOR proof payloads. Does NOT cover the
 * on-chain reveal *transaction* — pyrxd builds those with its own tx
 * builder; we only need byte-equivalence for the proof payload that goes
 * into the OP_RETURN, not the wrapping tx.
 *
 * Run with: PHOTONIC_LIB=/abs/path/to/Photonic-Wallet/packages/lib npm run gen > vectors.json
 *
 * The PHOTONIC_LIB env var defaults to ../../../../Photonic-Wallet/packages/lib
 * relative to this script, matching the layout of a typical dev checkout.
 */

import * as path from "node:path";
import * as fs from "node:fs";
import { fileURLToPath } from "node:url";

import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex } from "@noble/hashes/utils";
import { x25519 } from "@noble/curves/ed25519";

// --- Resolve Photonic path -------------------------------------------------

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PHOTONIC_LIB =
  process.env.PHOTONIC_LIB ??
  path.resolve(__dirname, "../../../../Photonic-Wallet/packages/lib");

const PHOTONIC_SRC = path.join(PHOTONIC_LIB, "src");
if (!fs.existsSync(PHOTONIC_SRC)) {
  console.error(`Photonic lib src not found at ${PHOTONIC_SRC}`);
  console.error("Set PHOTONIC_LIB to the absolute path of Photonic-Wallet/packages/lib");
  process.exit(2);
}

// Dynamic import via file:// URL to call Photonic's source directly.
const enc = await import(path.join(PHOTONIC_SRC, "encryption.ts"));
const tl = await import(path.join(PHOTONIC_SRC, "timelock.ts"));
const rv = await import(path.join(PHOTONIC_SRC, "reveal.ts"));

// --- Fixed inputs ----------------------------------------------------------

// 32-byte CEK with a deterministic pattern. Matches the fixture style in
// Photonic's __tests__ (`makeCEK = fill(0xab)`) but uses a less-uniform
// value so a "constant byte" bug doesn't pass.
const CEK = new Uint8Array(32);
for (let i = 0; i < 32; i++) CEK[i] = (i * 17 + 1) & 0xff;

// 24-byte nonce for XChaCha20-Poly1305 (also deterministic).
const NONCE_XCHACHA = new Uint8Array(24);
for (let i = 0; i < 24; i++) NONCE_XCHACHA[i] = (i * 31 + 7) & 0xff;

// Plaintexts of varying sizes to exercise chunking boundaries.
const PT_SMALL = new TextEncoder().encode("hello, photonic timelock interop");
const PT_LARGE = new Uint8Array(8192);
for (let i = 0; i < PT_LARGE.length; i++) PT_LARGE[i] = (i * 13 + 3) & 0xff;

// Optional AAD for AEAD vectors.
const AAD = new TextEncoder().encode("photonic-aad-v1");

// X25519 keypair from a deterministic seed.
const X25519_SK = new Uint8Array(32);
for (let i = 0; i < 32; i++) X25519_SK[i] = (i * 7 + 13) & 0xff;

// HKDF inputs.
const HKDF_IKM = new Uint8Array(48);
for (let i = 0; i < 48; i++) HKDF_IKM[i] = (i * 5 + 2) & 0xff;
const HKDF_SALT = new TextEncoder().encode("photonic-hkdf-salt-v1");
const HKDF_INFO = new TextEncoder().encode("photonic-hkdf-info-v1");

// Token-ref + timelock params for the reveal-proof vectors.
const TOKEN_REF = "a".repeat(64) + ":0";
const UNLOCK_AT_BLOCK = 425046;
const UNLOCK_AT_TIME = 1_700_000_000;
const HINT = "demo hint string";

// --- Helpers ---------------------------------------------------------------

const hex = (b: Uint8Array): string => bytesToHex(b);
const u8 = (b: Uint8Array | ArrayBuffer): Uint8Array =>
  b instanceof Uint8Array ? b : new Uint8Array(b);

// --- Vector generation -----------------------------------------------------

interface Vectors {
  meta: {
    generated_by: string;
    photonic_lib_path: string;
    generated_at: string;
    notes: string;
  };
  xchacha20_poly1305: object;
  chunked_aead_small: object;
  chunked_aead_large: object;
  hkdf_sha256: object;
  x25519: object;
  wrap_cek_x25519: object;
  hash_content: object;
  cek_hash_commitment: object;
  timelock_metadata_block_mode: object;
  timelock_metadata_time_mode: object;
  reveal_proof_block_mode: object;
  reveal_proof_time_mode: object;
  reveal_proof_with_hint: object;
}

const vectors: Vectors = {
  meta: {
    generated_by: "pyrxd-timelock bridge script (Photonic interop)",
    photonic_lib_path: PHOTONIC_LIB,
    generated_at: new Date().toISOString(),
    notes:
      "All vectors produced by calling Photonic's actual source files (not a " +
      "re-implementation). Inputs are deterministic; outputs are recorded for " +
      "pyrxd to assert byte-equality. Regenerate when Photonic's spec changes.",
  },

  // ----- 1. XChaCha20-Poly1305 (small + large plaintext, with AAD) -----
  xchacha20_poly1305: (() => {
    const small = enc.encryptXChaCha20Poly1305(PT_SMALL, CEK, NONCE_XCHACHA, AAD);
    const large = enc.encryptXChaCha20Poly1305(PT_LARGE, CEK, NONCE_XCHACHA, AAD);
    return {
      key: hex(CEK),
      nonce: hex(NONCE_XCHACHA),
      aad: hex(AAD),
      small: {
        plaintext: hex(PT_SMALL),
        ciphertext: hex(u8(small.ciphertext)),
      },
      large: {
        plaintext_sha256: hex(sha256(PT_LARGE)),
        plaintext_length: PT_LARGE.length,
        ciphertext_sha256: hex(sha256(u8(large.ciphertext))),
        ciphertext_length: large.ciphertext.byteLength,
      },
    };
  })(),

  // ----- 1b. Chunked AEAD (chunked-aead-v1 scheme) — Photonic encrypts with
  //          random per-chunk nonces; pyrxd test asserts it can DECRYPT and
  //          recover the original plaintext byte-for-byte. -----
  ...(((): { chunked_aead_small: object; chunked_aead_large: object; chunked_aead_multi: object } => {
    const PT_MULTI = new Uint8Array(80 * 1024); // 80 KB → ceil(80/32) = 3 chunks
    for (let i = 0; i < PT_MULTI.length; i++) PT_MULTI[i] = (i * 23 + 11) & 0xff;
    const smallChunked = enc.encryptChunked(PT_SMALL, CEK);
    const largeChunked = enc.encryptChunked(PT_LARGE, CEK);
    const multiChunked = enc.encryptChunked(PT_MULTI, CEK);
    const serializeChunks = (c: { chunks: Array<{ ciphertext: Uint8Array; nonce: Uint8Array }> }) =>
      c.chunks.map((ch) => ({
        nonce: hex(u8(ch.nonce)),
        ciphertext: hex(u8(ch.ciphertext)),
      }));
    return {
      chunked_aead_small: {
        key: hex(CEK),
        plaintext: hex(PT_SMALL),
        plaintext_hash: hex(u8(smallChunked.plaintextHash)),
        chunks: serializeChunks(smallChunked),
      },
      chunked_aead_large: {
        key: hex(CEK),
        plaintext_sha256: hex(sha256(PT_LARGE)),
        plaintext_length: PT_LARGE.length,
        plaintext_hash: hex(u8(largeChunked.plaintextHash)),
        chunks: serializeChunks(largeChunked),
      },
      chunked_aead_multi: {
        key: hex(CEK),
        plaintext_sha256: hex(sha256(PT_MULTI)),
        plaintext_length: PT_MULTI.length,
        plaintext_hash: hex(u8(multiChunked.plaintextHash)),
        chunks: serializeChunks(multiChunked),
      },
    };
  })()),

  // ----- 2. HKDF-SHA256 derivation -----
  hkdf_sha256: {
    ikm: hex(HKDF_IKM),
    salt: hex(HKDF_SALT),
    info: hex(HKDF_INFO),
    output_length: 32,
    derived: hex(enc.deriveKeyHKDF(HKDF_IKM, HKDF_SALT, HKDF_INFO, 32)),
  },

  // ----- 3. X25519 public-key derivation + ECDH (matches @noble/curves) -----
  x25519: (() => {
    // Photonic uses x25519 internally via @noble/curves. We derive the
    // pubkey here using noble directly because Photonic's encryption.ts
    // wraps it inside its hybrid-KEM construction (not as a standalone export).
    const pk = x25519.getPublicKey(X25519_SK);
    // Second key for ECDH demo.
    const X25519_SK2 = new Uint8Array(32);
    for (let i = 0; i < 32; i++) X25519_SK2[i] = (i * 11 + 5) & 0xff;
    const pk2 = x25519.getPublicKey(X25519_SK2);
    const shared = x25519.getSharedSecret(X25519_SK, pk2);
    return {
      sk_a: hex(X25519_SK),
      pk_a: hex(pk),
      sk_b: hex(X25519_SK2),
      pk_b: hex(pk2),
      shared_secret_a_to_b: hex(shared),
    };
  })(),

  // ----- 3b. Full wrapCEK (single-recipient X25519, no PQ) -----
  //          Pyrxd test asserts it can UNWRAP and recover the original CEK.
  //          Wrap output contains random ephemeral key + nonce; not byte-deterministic.
  ...((): { wrap_cek_x25519: object } => {
    // Recipient identity = the (sk_a, pk_a) keypair from the x25519 section.
    const recipientPk = x25519.getPublicKey(X25519_SK);
    const aad = new TextEncoder().encode("photonic-wrap-aad-test");
    const { wrappedCEK, ephemeral } = enc.wrapCEK(
      CEK,
      { x25519: recipientPk },
      aad,
    );
    return {
      wrap_cek_x25519: {
        notes:
          "Photonic-generated wrap. Pyrxd test unwraps with recipient_sk and " +
          "asserts the recovered CEK matches the original input. Wrap output " +
          "is not byte-deterministic (random ephemeral key + nonce).",
        recipient_sk: hex(X25519_SK),
        recipient_pk: hex(recipientPk),
        aad: hex(aad),
        original_cek: hex(CEK),
        wrapped_cek: hex(u8(wrappedCEK)),
        ephemeral_x25519_pub: hex(u8(ephemeral.x25519EphemeralPublicKey)),
      },
    };
  })(),

  // ----- 4. hashContent (the SHA256 used for content-integrity in Glyph v2) -----
  hash_content: {
    input: hex(PT_SMALL),
    output: hex(enc.hashContent(PT_SMALL)),
  },

  // ----- 5. CEK hash commitment (sha256:<hex>) — used in timelock CEK_HASH -----
  cek_hash_commitment: {
    cek: hex(CEK),
    cek_hash_bytes: hex(tl.computeCEKHash(CEK)),
    cek_hash_string: `sha256:${hex(tl.computeCEKHash(CEK))}`,
  },

  // ----- 6. addTimelockToMetadata (block mode) -----
  timelock_metadata_block_mode: (() => {
    // Build a minimal EncryptedContentStub manually that addTimelockToMetadata
    // accepts. Photonic's source signature requires fields we can populate
    // deterministically.
    const stub = {
      p: [2, 8] as number[], // NFT + ENCRYPTED
      type: "image/png",
      name: "Sealed Test #1",
      main: {
        type: "image/png",
        hash: "sha256:" + hex(sha256(PT_SMALL)),
        enc: "xchacha20poly1305" as const,
        size: PT_SMALL.length,
        chunks: 1,
        scheme: "chunked-aead-v1" as const,
      },
      crypto: {
        mode: "encrypted" as const,
        key_format: "wrapped" as const,
        cek_hash: `sha256:${hex(tl.computeCEKHash(CEK))}`,
      },
    };
    const result = tl.addTimelockToMetadata(stub, CEK, {
      mode: "block",
      unlockAt: UNLOCK_AT_BLOCK,
    });
    return {
      input_stub_protocols: stub.p,
      unlock_at: UNLOCK_AT_BLOCK,
      mode: "block",
      output_metadata: result.metadata,
      output_commitment: result.commitment,
    };
  })(),

  // ----- 7. addTimelockToMetadata (time mode) -----
  timelock_metadata_time_mode: (() => {
    const stub = {
      p: [2, 8] as number[],
      type: "application/octet-stream",
      name: "Sealed Test #2",
      main: {
        type: "application/octet-stream",
        hash: "sha256:" + hex(sha256(PT_LARGE)),
        enc: "xchacha20poly1305" as const,
        size: PT_LARGE.length,
        chunks: 1,
        scheme: "chunked-aead-v1" as const,
      },
      crypto: {
        mode: "encrypted" as const,
        key_format: "wrapped" as const,
        cek_hash: `sha256:${hex(tl.computeCEKHash(CEK))}`,
      },
    };
    const result = tl.addTimelockToMetadata(stub, CEK, {
      mode: "time",
      unlockAt: UNLOCK_AT_TIME,
      hint: HINT,
    });
    return {
      input_stub_protocols: stub.p,
      unlock_at: UNLOCK_AT_TIME,
      mode: "time",
      hint: HINT,
      output_metadata: result.metadata,
      output_commitment: result.commitment,
    };
  })(),

  // ----- 8. createRevealProof (no hint, block-derived) -----
  reveal_proof_block_mode: (() => {
    const { script, proof } = rv.createRevealProof(TOKEN_REF, CEK);
    return {
      token_ref: TOKEN_REF,
      cek: hex(CEK),
      proof, // includes v, p, action, token_ref, cek, cek_hash
      op_return_script_hex: script,
    };
  })(),

  // ----- 9. createRevealProof (with hint) -----
  reveal_proof_time_mode: (() => {
    // Note: createRevealProof doesn't take mode; mode lives in the mint's
    // timelock spec. The reveal proof itself just publishes the CEK +
    // (optional) hint.
    const { script, proof } = rv.createRevealProof(TOKEN_REF, CEK, {
      hint: HINT,
    });
    return {
      token_ref: TOKEN_REF,
      cek: hex(CEK),
      hint: HINT,
      proof,
      op_return_script_hex: script,
    };
  })(),

  // ----- 10. createRevealProof with explicit cek_hash override -----
  reveal_proof_with_hint: (() => {
    const explicitHash = `sha256:${hex(tl.computeCEKHash(CEK))}`;
    const { script, proof } = rv.createRevealProof(TOKEN_REF, CEK, {
      hint: HINT,
      cekHash: explicitHash,
    });
    return {
      token_ref: TOKEN_REF,
      cek: hex(CEK),
      hint: HINT,
      cek_hash_override: explicitHash,
      proof,
      op_return_script_hex: script,
    };
  })(),
};

// --- Output ----------------------------------------------------------------

// Print to stdout; caller redirects to fixture file.
console.log(JSON.stringify(vectors, null, 2));
