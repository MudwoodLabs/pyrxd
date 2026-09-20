// secp256k1-bridge.js — the ONE curve operation this browser can do and Pyodide cannot.
//
// WHAT THIS IS FOR. `pyrxd.script.hashmark.verify_attestation` needs one thing from
// secp256k1: recover a public key from (message hash, r, s, recovery id). Everything
// else about a HashMark attestation — the canonical statement's byte-exact JSON, the
// varint framing of the Bitcoin-signed-message preimage, the double-SHA256, the
// low-S and range checks, hash160 of the recovered key, and the comparison against
// the hash160 the record commits to — stays in Python and runs here under Pyodide.
// pyrxd installs in this tab with `deps=False`, so `coincurve` is absent and that one
// curve operation is the ONLY missing piece.
//
// WHY NOT REIMPLEMENT THE WHOLE CHECK IN JAVASCRIPT, which is the obvious thing to do
// and is wrong. A second verifier in a second language is two implementations of a
// rule, and the rule has sharp edges that do not announce themselves when you get
// them wrong: `JSON.stringify` escapes `\n` and control characters where §5.6 emits
// raw UTF-8; the statement's length prefix is one byte below 253 and three bytes above
// it, so a JS port can verify every unlabelled mark and silently fail every labelled
// one; `header >= 31` chooses how the RECOVERED key is serialised before hashing, not
// how it is recovered. Each of those produces a confident wrong verdict about a
// stranger's mark. Keeping them in the one implementation the CLI already uses means
// the browser and `pyrxd verify` cannot disagree about them, because there is nothing
// to disagree with — and it narrows what a differential test has to cover to this
// file, which is the part that genuinely had to be written twice.
//
// THE ASYMMETRY, which is the whole design and must survive any edit here. This module
// reports exactly two things: a recovered key, or a refusal WITH ITS KIND.
//
//   { ok: true,  publicKey: "<hex>" }              the curve found a key
//   { ok: false, kind: "no-key",    reason: … }    the curve says these bytes recover
//                                                  to nothing — a real finding
//   { ok: false, kind: "bad-input", reason: … }    the caller handed us nonsense
//
// The Python side turns "no-key" into DOES NOT VERIFY and anything else into NOT
// CHECKED. If this module fails to LOAD at all, the page never registers a backend
// and `verify_attestation` returns UNVERIFIABLE by the path it already had — nobody
// has to remember to handle it. Painting an honest signer's mark red because a script
// did not load is the single worst thing this page could do, and the only way to keep
// that impossible is to never let a load failure reach a verdict.
//
// Trust boundary: nothing here touches the network, the DOM, or any publisher-chosen
// string. It takes five values, all of which Python derived from bytes it had already
// range-checked, and returns hex.

import { recoverPublicKey } from "./vendor/noble-secp256k1.js";

const HEX32 = /^[0-9a-f]{64}$/;

function bytesFromHex(hex, name, expectedBytes) {
  if (typeof hex !== "string" || !HEX32.test(hex) || hex.length !== expectedBytes * 2) {
    throw new Error(`${name} must be ${expectedBytes * 2} lowercase hex characters`);
  }
  const out = new Uint8Array(expectedBytes);
  for (let i = 0; i < expectedBytes; i += 1) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function toHex(bytes) {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

/**
 * Recover a secp256k1 public key.
 *
 * @param {string} messageHashHex 32 bytes, lowercase hex. ALREADY HASHED — this is the
 *   ECDSA `z`, which for a HashMark is sha256(sha256(preimage)). Python computes it;
 *   `prehash: false` below is what stops noble hashing it a second time, and getting
 *   that wrong would recover a key for a message nobody signed.
 * @param {string} rHex 32 bytes, lowercase hex.
 * @param {string} sHex 32 bytes, lowercase hex. Python has already enforced low-S;
 *   this module does not re-derive that rule, it just does the arithmetic.
 * @param {number} recId 0..3.
 * @param {boolean} compressed Whether to return the 33-byte SEC1 form. Python decides
 *   this from the signature header byte (`header >= 31`) because it is the form the
 *   signer's hash160 was taken over, not a property of the recovery.
 * @returns {{ok: true, publicKey: string} | {ok: false, kind: string, reason: string}}
 */
export function recoverPublicKeySec1(messageHashHex, rHex, sHex, recId, compressed) {
  let signature;
  let messageHash;
  try {
    messageHash = bytesFromHex(messageHashHex, "message hash", 32);
    const r = bytesFromHex(rHex, "r", 32);
    const s = bytesFromHex(sHex, "s", 32);
    if (!Number.isInteger(recId) || recId < 0 || recId > 3) {
      throw new Error("recovery id must be an integer 0..3");
    }
    if (typeof compressed !== "boolean") {
      throw new Error("compressed must be a boolean");
    }
    // noble's 'recovered' signature format is the recovery byte FIRST, then r‖s.
    // Measured, not assumed: the other order is rejected outright with "invalid
    // recovery id", which is the good kind of wrong — it cannot silently recover
    // the wrong key.
    signature = new Uint8Array(65);
    signature[0] = recId;
    signature.set(r, 1);
    signature.set(s, 33);
  } catch (err) {
    return { ok: false, kind: "bad-input", reason: String((err && err.message) || err) };
  }

  try {
    const pub = recoverPublicKey(signature, messageHash, {
      prehash: false,
      isCompressed: compressed,
    });
    return { ok: true, publicKey: toHex(pub) };
  } catch (err) {
    // The curve refused. That IS a finding about these bytes — a signature whose r
    // is not the x-coordinate of any point recovers to nothing — and it is the same
    // thing coincurve raises for, so both backends reach the same verdict.
    return { ok: false, kind: "no-key", reason: String((err && err.message) || err) };
  }
}
