// Drive the PUBLIC verify page's secp256k1 backend under Node, over a line protocol.
//
// WHAT THIS IS GUARDING, and why it is not a render harness. The other `.mjs` files
// here stub a DOM and check what the page SAYS. This one checks what the page
// COMPUTES: `docs/inspect_static/inspect/secp256k1-bridge.js` is the second
// implementation of a signature check in this repository, in a second language, and
// the first one — `pyrxd.script.hashmark.verify_attestation` via coincurve — is what
// `pyrxd verify` prints from. Two surfaces, one claim about a stranger's mark. If
// they can ever disagree, one of them is telling somebody the wrong thing about
// whether a signature holds.
//
// THE BRIDGE AND THE VENDORED CURVE ARE LOADED VERBATIM, by the same relative import
// the browser resolves. Nothing is re-implemented, re-exported or wrapped: a harness
// that recomputed the recovery itself, or that stubbed `@noble/secp256k1`, would
// prove the harness. `tests/test_signature_backend_differential.py` plants against
// this path precisely to show it is load-bearing.
//
// Contract:
//   node secp256k1_backend_harness.mjs
//   stdin:  one JSON object per line —
//           {"messageHash": hex32, "r": hex32, "s": hex32, "recId": 0..3,
//            "compressed": bool}
//   stdout: one JSON object per line — whatever `recoverPublicKeySec1` returned,
//           unmodified, or {"ok": false, "kind": "harness", "reason": …} if the
//           line itself could not be read. "harness" is deliberately a kind the
//           bridge never produces, so a Python-side failure to build a request is
//           never mistaken for a curve refusal.

import { createInterface } from "node:readline";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { pathToFileURL } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const BRIDGE = resolve(HERE, "../../docs/inspect_static/inspect/secp256k1-bridge.js");

const { recoverPublicKeySec1 } = await import(pathToFileURL(BRIDGE).href);
if (typeof recoverPublicKeySec1 !== "function") {
  throw new Error(`recoverPublicKeySec1 is not exported by ${BRIDGE}`);
}

const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });
for await (const line of rl) {
  const text = line.trim();
  if (!text) continue;
  let out;
  try {
    const req = JSON.parse(text);
    out = recoverPublicKeySec1(req.messageHash, req.r, req.s, req.recId, req.compressed);
  } catch (err) {
    out = { ok: false, kind: "harness", reason: String((err && err.message) || err) };
  }
  process.stdout.write(JSON.stringify(out) + "\n");
}
