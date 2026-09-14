// Drive inspect.js's ElectrumX fetch error path under Node against a stub
// WebSocket, to prove `stripControlChars` actually runs on both sibling
// error paths in `fetchRawTxFromElectrumx`'s "message" handler.
//
// Why this exists
// ----------------
//
// `stripControlChars` (docs/inspect_static/inspect/inspect.js) exists so a
// hostile ElectrumX server can't embed bidi overrides (U+202E) or zero-width
// characters into an error message and spoof what a human reads in the error
// card — textContent keeps this from being XSS, but it does nothing about
// visual spoofing. It was applied to the `frame.error` branch and NOT to the
// `JSON.parse` catch immediately above it, which builds
// `server returned non-JSON: ${err.message}` from a V8 SyntaxError that
// echoes a slice of the unparsed, attacker-controlled frame verbatim — and
// that path has FEWER preconditions to reach (no `id === 1` match needed).
// `stripControlChars` had exactly one call site and zero tests before this,
// so nothing proved either branch actually worked.
//
// Like inspect_render_harness.mjs, inspect.js is loaded VERBATIM in a Node
// `vm` context — not modified, not wrapped, not preprocessed. A guard that
// tests a rewritten copy of the file guards the rewrite.
//
// Contract:
//   node inspect_fetch_error_harness.mjs
//   stdout: JSON — {
//     "fromMalformedJson": "<rejection message from the JSON.parse catch>",
//     "fromFrameError":    "<rejection message from the frame.error branch>",
//     "stripControlCharsDirect": "<stripControlChars() called directly>"
//   }
//
// `fetchRawTxFromElectrumx`'s WebSocket construction, listener registration
// and settle() are all synchronous within the Promise executor (no `await`
// before them), so a stub WebSocket that records `addEventListener`
// callbacks and exposes a `dispatch()` method can drive both branches of the
// real "message" handler deterministically — no timers, no real sockets.

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

const HERE = dirname(fileURLToPath(import.meta.url));
const INSPECT_JS = resolve(HERE, "../../docs/inspect_static/inspect/inspect.js");

// Attacker-controlled bytes: U+202E (RIGHT-TO-LEFT OVERRIDE, the headline
// bidi-spoofing threat) and U+200B (ZERO WIDTH SPACE). Both are in
// `stripControlChars`'s `[\p{C}\p{M}]` class (Cf format / control category).
const BIDI = "‮";
const ZWSP = "​";

// A stub WebSocket the harness fully controls: records listeners by event
// type and lets the test dispatch a synthetic frame, standing in for bytes
// that arrived over the wire from a (possibly hostile) ElectrumX server.
class StubWebSocket {
  constructor(url) {
    this.url = url;
    this._listeners = {};
    StubWebSocket.lastInstance = this;
  }
  addEventListener(type, cb) {
    (this._listeners[type] ||= []).push(cb);
  }
  send() {
    /* request body is irrelevant to the error path under test */
  }
  close() {
    /* no real socket to close */
  }
  dispatch(type, ev) {
    for (const cb of this._listeners[type] || []) cb(ev);
  }
}

function makeSandbox() {
  // Minimal DOM: inspect.js's top level reads a handful of elements and
  // `document.baseURI` into module-scope consts. Nothing in this harness
  // calls a render function, so the elements never need real behaviour.
  const document = {
    getElementById: () => ({}),
    querySelectorAll: () => [],
    baseURI: "https://pyrxd.invalid/inspect/",
  };
  const sandbox = {
    document,
    console: { log() {}, warn() {}, error() {} },
    URL,
    TextDecoder,
    setTimeout,
    clearTimeout,
    WebSocket: StubWebSocket,
    // `boot()` runs at module load and bails out here (no `loadPyodide`),
    // exactly as inspect_render_harness.mjs relies on.
    fetch: () => Promise.reject(new Error("no network in the fetch-error harness")),
  };
  sandbox.window = sandbox;
  sandbox.globalThis = sandbox;
  return sandbox;
}

function loadModule() {
  const source = readFileSync(INSPECT_JS, "utf8");
  const sandbox = makeSandbox();
  vm.createContext(sandbox);
  vm.runInContext(source, sandbox, { filename: INSPECT_JS });
  for (const name of ["fetchRawTxFromElectrumx", "stripControlChars"]) {
    if (typeof sandbox[name] !== "function") {
      throw new Error(
        `${name} is not reachable after loading inspect.js. It was a top-level ` +
        `function declaration; if it moved into a block or a module scope, this ` +
        `harness needs updating — do NOT delete the guard.`
      );
    }
  }
  return sandbox;
}

// Drives one call to fetchRawTxFromElectrumx(), delivers `frameData` as the
// single WebSocket "message" frame, and returns the rejection's message.
// Throws if the fetch does not reject (a passing case would mean the attack
// payload was accepted as a valid, in-range hex result — not this test's
// scenario, and a sign the harness itself drifted from the real handler).
async function probeRejection(sandbox, frameData) {
  const promise = sandbox.fetchRawTxFromElectrumx("deadbeef".repeat(8));
  const ws = StubWebSocket.lastInstance;
  ws.dispatch("message", { data: frameData });
  try {
    await promise;
  } catch (err) {
    return err.message;
  }
  throw new Error("expected fetchRawTxFromElectrumx to reject, but it resolved");
}

async function main() {
  const sandbox = loadModule();

  // Branch 1: malformed JSON. The V8 SyntaxError this throws echoes a
  // slice of the offending text verbatim (confirmed against Node: a token
  // straddled by BIDI/ZWSP appears literally inside `err.message`, e.g.
  // `Unexpected token 'x', "xxxxx<ZWSP>yyyyy<BIDI>" is not valid JSON`).
  // This is the frame.error line's UNGUARDED sibling.
  const malformedFrame = `xxxxx${ZWSP}yyyyy${BIDI}`;
  const fromMalformedJson = await probeRejection(sandbox, malformedFrame);

  // Branch 2: well-formed JSON-RPC error frame with id===1 (the only id the
  // handler accepts) and an attacker-controlled `.error.message`. This is
  // the branch stripControlChars already guarded.
  const errorFrame = JSON.stringify({
    id: 1,
    error: { message: `boom ${BIDI}evil${ZWSP}` },
  });
  const fromFrameError = await probeRejection(sandbox, errorFrame);

  // Direct unit check of the sanitiser itself, independent of either call
  // site — pins the function's own behaviour.
  const stripControlCharsDirect = sandbox.stripControlChars(`gly${BIDI}bar${ZWSP}baz`);

  process.stdout.write(JSON.stringify({
    fromMalformedJson,
    fromFrameError,
    stripControlCharsDirect,
  }));
}

main().catch((err) => {
  process.stderr.write(String(err && err.stack || err) + "\n");
  process.exit(1);
});
