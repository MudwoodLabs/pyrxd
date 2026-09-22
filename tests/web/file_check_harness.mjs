// Drive `hashFileWithRecordAlgorithm` (shared.js) against Node's REAL WebCrypto.
//
// WHY THIS EXISTS — a plant survived. `crypto.subtle.digest(plan.webcrypto_name, …)`
// was changed to `crypto.subtle.digest("SHA-256", …)` and the entire suite stayed
// green: 428 passed. The Python half is covered thoroughly (`file_check_plan` reads
// `algorithm_for`, and `test_hashmark_panel_verdict` pins that it must not spell an
// algorithm name itself) — but nothing anywhere EXECUTED the JavaScript that decides
// what to do with the plan. Both render harnesses stub `crypto: { subtle: {} }` and
// never reach this function.
//
// That is the exact defect the plan exists to prevent, shipped invisibly: a page that
// hashes with a hash the record does not name produces a well-formed, confident,
// completely wrong MATCHES or DOES NOT MATCH, and nothing downstream can detect it.
//
// WHAT IS REAL HERE: the function under test, loaded verbatim; Node's WebCrypto,
// doing the actual hashing; a real `File`; and a reference digest computed
// independently with `node:crypto` so the bytes are checked, not just the call.
//
// WHAT IS SHIMMED, and where the real thing IS exercised — because a mock that
// stands in for the subject proves the mock:
//
//   `fileCheckPlan`      shimmed. The real one is `pyrxd.glyph.inspect.file_check_plan`,
//                        Python, exercised directly by
//                        `test_hashmark_panel_verdict.TestTheHashComesFromTheRecordNotFromThePage`,
//                        and proved reachable from the page by
//                        `test_mark_anchor_bridge.test_every_bridge_is_bound_by_the_shared_boot`.
//   `judgeFileDigest`    shimmed, and its ARGUMENTS are what this harness reports —
//                        the property owned here is "what does the JS hand it", not
//                        "what does it decide". The deciding is Python's and is
//                        exercised by `test_hashmark_panel_verdict`'s
//                        `judge_file_digest` cases.
//
// So this file owns exactly one claim, and it is the one that was unguarded: the JS
// hashes with the algorithm THE PLAN NAMED and hands the record's digest and the
// computed one to the judge unchanged.
//
// THE FIXTURE USES SHA-512 ON PURPOSE. Under sha256 a hardcoded "SHA-256" and a
// plan-driven one produce identical bytes, and the test would pass for the wrong
// reason — the equal-values-hide-conflations trap. sha512 makes the two differ in
// length as well as content.
//
// Contract:
//   node file_check_harness.mjs [cases.json|-]
//   stdin: JSON — {"name": {"plan": {...}, "bytes": "<utf8 text>", "digest": "<hex>",
//                           "filename": "...", "size_override": <int|null>,
//                           "no_subtle": <bool>}}
//   stdout: JSON — {"name": {"ok", "reason", "algorithm", "computed", "expected",
//                            "requested": [...], "judged": {...},
//                            "reference": "<hex computed independently>"}}

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash, webcrypto } from "node:crypto";
import vm from "node:vm";

const HERE = dirname(fileURLToPath(import.meta.url));
const SHARED_JS = resolve(HERE, "../../docs/inspect_static/inspect/shared.js");

function makeSandbox(recorder, { noSubtle = false } = {}) {
  const sandbox = {
    console: { log() {}, warn() {}, error() {} },
    URL,
    TextDecoder,
    setTimeout,
    clearTimeout,
    fetch: () => Promise.reject(new Error("no network in the file-check harness")),
    WebSocket: class {},
    document: { getElementById: () => ({}), querySelectorAll: () => [], baseURI: "https://pyrxd.invalid/verify/" },
  };
  if (!noSubtle) {
    sandbox.crypto = {
      subtle: {
        // DELEGATES to Node's real WebCrypto. A stub that returned canned bytes
        // would let a wrong algorithm name through as long as the shape was right.
        digest: (algorithm, data) => {
          recorder.requested.push(algorithm);
          return webcrypto.subtle.digest(algorithm, data);
        },
      },
    };
  } else {
    // A page served over plain http:// from anything but localhost is not a secure
    // context and gets no WebCrypto at all.
    sandbox.crypto = {};
  }
  sandbox.window = sandbox;
  sandbox.globalThis = sandbox;
  return sandbox;
}

function loadShared(recorder, opts) {
  const sandbox = makeSandbox(recorder, opts);
  vm.createContext(sandbox);
  vm.runInContext(readFileSync(SHARED_JS, "utf8"), sandbox, { filename: SHARED_JS });
  if (typeof sandbox.hashFileWithRecordAlgorithm !== "function") {
    throw new Error(
      "hashFileWithRecordAlgorithm is not reachable after loading shared.js. It was a " +
      "top-level declaration in a classic script; if it moved into a block or the file " +
      "became an ES module, this harness needs updating — do NOT delete the guard."
    );
  }
  return sandbox;
}

async function runCase(spec) {
  const recorder = { requested: [], judged: null };
  const sandbox = loadShared(recorder, { noSubtle: spec.no_subtle === true });

  const bridges = {
    fileCheckPlan: () => spec.plan,
    judgeFileDigest: (expected, computed, algorithm) => {
      recorder.judged = { expected, computed, algorithm };
      return { checked: true, match: expected === computed, status: "(shimmed)", meaning: "(shimmed)" };
    },
  };

  const bytes = new TextEncoder().encode(spec.bytes ?? "");
  const file = new File([bytes], spec.filename || "chosen.bin");
  if (spec.size_override !== undefined && spec.size_override !== null) {
    Object.defineProperty(file, "size", { value: spec.size_override });
  }

  const hm = { algorithm: spec.record_algorithm || "sha512", algorithm_id: 0x99, digest: spec.digest || "" };
  const out = await sandbox.hashFileWithRecordAlgorithm(file, hm, bridges);

  // An INDEPENDENT reference, from node:crypto rather than from the code under test,
  // so the digest is checked against arithmetic this harness did itself.
  const nodeName = { "SHA-256": "sha256", "SHA-384": "sha384", "SHA-512": "sha512" }[
    (spec.plan && spec.plan.webcrypto_name) || ""
  ];
  const reference = nodeName ? createHash(nodeName).update(bytes).digest("hex") : null;

  return { ...out, requested: recorder.requested, judged: recorder.judged, reference };
}

async function main() {
  const payloadPath = process.argv[2];
  const raw = !payloadPath || payloadPath === "-" ? readFileSync(0, "utf8") : readFileSync(payloadPath, "utf8");
  const cases = JSON.parse(raw);
  const results = {};
  for (const [name, spec] of Object.entries(cases)) {
    results[name] = await runCase(spec);
  }
  process.stdout.write(JSON.stringify(results));
}

main().catch((err) => {
  process.stderr.write(String((err && err.stack) || err) + "\n");
  process.exit(1);
});
