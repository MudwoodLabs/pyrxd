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
 * and paste the printed object into tests/fixtures/photonic_timelock_vectors.json under
 * `app_encrypt_content_recipient`, recording the commit in `photonic_commit`.
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

// Fixed inputs.
const RECIPIENT_SK = fill(32, 29, 11);
const PLAINTEXT = new TextEncoder().encode("sealed bid: 4200 RXD (Photonic app-path wrap vector)");
const DRAWS: { role: string; bytes: Uint8Array }[] = [
  { role: "cek", bytes: fill(32, 7, 3) },
  { role: "chunk_nonce_0", bytes: fill(24, 13, 5) },
  { role: "ephemeral_x25519_priv", bytes: fill(32, 19, 23) },
  { role: "wrap_nonce", bytes: fill(24, 37, 41) },
  { role: "locator_key", bytes: fill(32, 43, 47) },
];

const queue = DRAWS.map((d) => d.bytes);
(globalThis.crypto as any).getRandomValues = (arr: Uint8Array) => {
  const next = queue.shift();
  if (!next) throw new Error(`RNG queue exhausted (asked for ${arr.length})`);
  if (next.length !== arr.length) throw new Error(`RNG length mismatch: asked ${arr.length}, queued ${next.length}`);
  arr.set(next);
  return arr;
};

const svc = await import(SERVICE);
const res = await svc.encryptContent(PLAINTEXT, {
  mode: "recipient",
  recipientPublicKeys: [x25519Pub(RECIPIENT_SK)],
  contentType: "text/plain",
  name: "app-path-vector",
});
if (queue.length !== 0) throw new Error(`${queue.length} RNG draw(s) unconsumed: the app's draw order changed`);

// Check every draw's role against the output instead of trusting the order read from source.
const rec = res.metadata.crypto.recipients;
if (rec.length !== 1) throw new Error(`expected one recipient slot, got ${rec.length}`);
const wrapped = Buffer.from(rec[0].wrapped_cek, "base64");
const epk = Buffer.from(rec[0].epk, "base64");
const enc = Buffer.from(res.encryptedContent);
const roleChecks: [string, boolean][] = [
  ["cek", hex(res.cek) === hex(DRAWS[0].bytes)],
  ["chunk_nonce_0", hex(enc.subarray(0, 24)) === hex(DRAWS[1].bytes)],
  ["ephemeral_x25519_priv", hex(epk) === hex(x25519Pub(DRAWS[2].bytes))],
  ["wrap_nonce", hex(wrapped.subarray(0, 24)) === hex(DRAWS[3].bytes)],
  ["locator_key", hex(res.locatorKey) === hex(DRAWS[4].bytes)],
];
for (const [role, ok] of roleChecks) if (!ok) throw new Error(`RNG draw role '${role}' does not match the output`);

// The app's decryptContent (the step its unlock screen calls once it has the ciphertext) must
// open its own output, or the vector records nothing useful.
const opened = await svc.decryptContent(res.encryptedContent, { metadata: res.metadata, privateKey: RECIPIENT_SK });
if (hex(opened) !== hex(PLAINTEXT)) throw new Error("Photonic could not decrypt its own vector");

console.log(
  JSON.stringify(
    {
      notes:
        "Generated by scripts/gen-photonic-vectors/gen-app-path-vector.ts through Photonic's APP " +
        "service (packages/app/src/encryptionService.ts encryptContent, recipient mode), which " +
        "computes the wrap AAD itself: the UTF-8 bytes of metadata.crypto.cek_hash. Every RNG " +
        "draw is recorded in order and checked against the output by role, so the vector " +
        "regenerates byte-for-byte. Photonic decrypted it through decryptContent before it was written.",
      photonic_commit: process.env.PHOTONIC_COMMIT ?? "UNRECORDED",
      recipient_sk: hex(RECIPIENT_SK),
      recipient_pk: hex(x25519Pub(RECIPIENT_SK)),
      plaintext: hex(PLAINTEXT),
      content_type: "text/plain",
      name: "app-path-vector",
      rng_draws: DRAWS.map((d) => ({ role: d.role, hex: hex(d.bytes) })),
      metadata: res.metadata,
      encrypted_content: hex(res.encryptedContent),
    },
    null,
    2,
  ),
);
