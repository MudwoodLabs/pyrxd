/**
 * The recipient-wrap vector, generated through Photonic's APP encryption service.
 *
 * gen-vectors.ts calls Photonic's LIBRARY primitives and hands them an AAD it chose itself, so
 * it cannot say what AAD the wallet actually binds a recipient wrap to. This script calls
 * `encryptContent` from `packages/app/src/encryptionService.ts` -- the function Photonic's mint
 * screen calls -- and lets it compute the AAD, so the vector records the app's choice rather
 * than ours. (It is the UTF-8 text of `crypto.cek_hash`, "sha256:<hex>".)
 *
 * Deterministic: every `crypto.getRandomValues` draw is served from a fixed queue, in order,
 * with its length checked, and the run fails if any draw is left over. Each draw's ROLE is then
 * checked against the output rather than assumed from reading the code.
 *
 * Run (Photonic checked out at a known upstream commit, dependencies installed):
 *   PHOTONIC_ROOT=/abs/path/to/Photonic-Wallet npx tsx gen-app-path-vector.ts
 * It prints an object with two keys, `app_encrypt_content_recipient` and
 * `app_encrypt_content_recipient_empty` (zero bytes of content); merge both into
 * tests/fixtures/photonic_timelock_vectors.json, setting PHOTONIC_COMMIT so each records it.
 */

import * as path from "node:path";
import * as fs from "node:fs";
import { createPrivateKey, createPublicKey } from "node:crypto";
import { registerHooks } from "node:module";
import { fileURLToPath, pathToFileURL } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PHOTONIC_ROOT = process.env.PHOTONIC_ROOT ?? path.resolve(__dirname, "../../../../Photonic-Wallet");
const LIB_SRC = path.join(PHOTONIC_ROOT, "packages", "lib", "src");
const SERVICE = path.join(PHOTONIC_ROOT, "packages", "app", "src", "encryptionService.ts");
if (!fs.existsSync(SERVICE)) {
  console.error(`encryptionService.ts not found at ${SERVICE}; set PHOTONIC_ROOT`);
  process.exit(2);
}

// The app imports its library as `@lib/<module>` (a Vite alias). Resolve it the same way.
registerHooks({
  resolve(specifier, context, next) {
    if (specifier.startsWith("@lib/")) {
      return next(pathToFileURL(path.join(LIB_SRC, `${specifier.slice(5)}.ts`)).href, context);
    }
    return next(specifier, context);
  },
});

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const fill = (n: number, mul: number, add: number) => Uint8Array.from({ length: n }, (_, i) => (i * mul + add) & 0xff);

// X25519 public key via node:crypto, so this script needs no dependency of its own.
function x25519Pub(sk: Uint8Array): Uint8Array {
  const der = Buffer.concat([Buffer.from("302e020100300506032b656e04220420", "hex"), Buffer.from(sk)]);
  const spki = createPublicKey(createPrivateKey({ key: der, format: "der", type: "pkcs8" })).export({
    format: "der",
    type: "spki",
  });
  return new Uint8Array(spki.subarray(spki.length - 32));
}

// Fixed inputs. The recipient is shared; each vector has its own plaintext and RNG draws.
const RECIPIENT_SK = fill(32, 29, 11);

type Draw = { role: string; bytes: Uint8Array };

let queue: Uint8Array[] = [];
(globalThis.crypto as any).getRandomValues = (arr: Uint8Array) => {
  const next = queue.shift();
  if (!next) throw new Error(`RNG queue exhausted (asked for ${arr.length})`);
  if (next.length !== arr.length) throw new Error(`RNG length mismatch: asked ${arr.length}, queued ${next.length}`);
  arr.set(next);
  return arr;
};

const svc = await import(SERVICE);

async function vector(name: string, plaintext: Uint8Array, draws: Draw[], notes: string) {
  queue = draws.map((d) => d.bytes);
  const res = await svc.encryptContent(plaintext, {
    mode: "recipient",
    recipientPublicKeys: [x25519Pub(RECIPIENT_SK)],
    contentType: "text/plain",
    name,
  });
  if (queue.length !== 0) throw new Error(`${name}: ${queue.length} RNG draw(s) unconsumed: the app's draw order changed`);
  if (res.metadata.main.chunks > 1) throw new Error(`${name}: role checks below cover at most one chunk`);

  // Check every draw's role against the output instead of trusting the order read from source.
  const rec = res.metadata.crypto.recipients;
  if (rec.length !== 1) throw new Error(`${name}: expected one recipient slot, got ${rec.length}`);
  const wrapped = Buffer.from(rec[0].wrapped_cek, "base64");
  const epk = Buffer.from(rec[0].epk, "base64");
  const enc = Buffer.from(res.encryptedContent);
  const actual: Record<string, string> = {
    cek: hex(res.cek),
    chunk_nonce_0: hex(enc.subarray(0, 24)),
    wrap_nonce: hex(wrapped.subarray(0, 24)),
    locator_key: hex(res.locatorKey),
  };
  for (const d of draws) {
    const ok =
      d.role === "ephemeral_x25519_priv" ? hex(epk) === hex(x25519Pub(d.bytes)) : actual[d.role] === hex(d.bytes);
    if (!ok) throw new Error(`${name}: RNG draw role '${d.role}' does not match the output`);
  }

  // The app's decryptContent (the step its unlock screen calls once it has the ciphertext) must
  // open its own output, or the vector records nothing useful.
  const opened = await svc.decryptContent(res.encryptedContent, { metadata: res.metadata, privateKey: RECIPIENT_SK });
  if (hex(opened) !== hex(plaintext)) throw new Error(`${name}: Photonic could not decrypt its own vector`);

  return {
    notes,
    photonic_commit: process.env.PHOTONIC_COMMIT ?? "UNRECORDED",
    recipient_sk: hex(RECIPIENT_SK),
    recipient_pk: hex(x25519Pub(RECIPIENT_SK)),
    plaintext: hex(plaintext),
    content_type: "text/plain",
    name,
    rng_draws: draws.map((d) => ({ role: d.role, hex: hex(d.bytes) })),
    metadata: res.metadata,
    encrypted_content: hex(res.encryptedContent),
  };
}

const COMMON_NOTES =
  "Generated by scripts/gen-photonic-vectors/gen-app-path-vector.ts through Photonic's APP " +
  "service (packages/app/src/encryptionService.ts encryptContent, recipient mode), which " +
  "computes the wrap AAD itself: the UTF-8 bytes of metadata.crypto.cek_hash. Every RNG " +
  "draw is recorded in order and checked against the output by role, so the vector " +
  "regenerates byte-for-byte. Photonic decrypted it through decryptContent before it was written.";

const withContent = await vector(
  "app-path-vector",
  new TextEncoder().encode("sealed bid: 4200 RXD (Photonic app-path wrap vector)"),
  [
    { role: "cek", bytes: fill(32, 7, 3) },
    { role: "chunk_nonce_0", bytes: fill(24, 13, 5) },
    { role: "ephemeral_x25519_priv", bytes: fill(32, 19, 23) },
    { role: "wrap_nonce", bytes: fill(24, 37, 41) },
    { role: "locator_key", bytes: fill(32, 43, 47) },
  ],
  COMMON_NOTES,
);

// Zero bytes of content: Photonic's encryptChunked does Math.ceil(0 / CHUNK_SIZE) = 0 chunks, so
// there is no chunk nonce to draw and main records {size: 0, chunks: 0}.
const empty = await vector(
  "app-path-vector-empty",
  new Uint8Array(0),
  [
    { role: "cek", bytes: fill(32, 11, 17) },
    { role: "ephemeral_x25519_priv", bytes: fill(32, 23, 29) },
    { role: "wrap_nonce", bytes: fill(24, 31, 37) },
    { role: "locator_key", bytes: fill(32, 41, 43) },
  ],
  COMMON_NOTES + " EMPTY content: Photonic records main {size: 0, chunks: 0} and no ciphertext bytes.",
);
if (empty.metadata.main.chunks !== 0 || empty.metadata.main.size !== 0 || empty.encrypted_content !== "") {
  throw new Error("expected Photonic to encode empty content as zero chunks and zero bytes");
}

console.log(
  JSON.stringify(
    { app_encrypt_content_recipient: withContent, app_encrypt_content_recipient_empty: empty },
    null,
    2,
  ),
);
