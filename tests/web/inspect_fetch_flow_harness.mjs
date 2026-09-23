// Drive /inspect/'s whole "Fetch from network" flow — `onFetchTxid` — under Node, against a
// stub ElectrumX server and a RECORDING classifier bridge.
//
// WHY THIS EXISTS. The page's second fetch (the commit a reveal spent) is where a lying
// server could make `payload_binding` read "bound" for a payload the real commit never
// committed to, and where a failed fetch was swallowed so the report said the spent output
// "was not supplied". Both halves of the fix live in JavaScript as much as in Python: the
// fetch helper must refuse an answer whose bytes do not hash to the txid asked for, and the
// page must hand Python the reason when it has no spent transaction to give. A test that
// called `glue.inspect_txid_with_raw` directly would prove the Python and assume the page —
// the shape of the defect this is guarding, where the server half was correct and nothing
// reached it.
//
// So this runs the page's own `onFetchTxid`, verbatim, and records exactly what it asks the
// server for and exactly what it hands the classifier. The Python side
// (`test_inspect_fetch_flow.py`) then REPLAYS those recorded arguments through the real
// `glue.py`, so the verdict asserted on is the one the real classifier gives for the real
// arguments the real page passed.
//
// shared.js and inspect.js are loaded VERBATIM in a `vm` context, in the order index.html
// loads them. The digest is Node's real WebCrypto, so the hash check that runs is the one
// the page runs.
//
// Contract:
//   node inspect_fetch_flow_harness.mjs < case.json
//   stdin:  {"txid": hex,
//            "server": {txid: {"hex": rawHex} | {"error": message}},  — anything not listed
//                      answers "No such mempool or blockchain transaction"
//            "glue_returns": [result, …]}  — what the recording bridge returns, call by call
//   stdout: {"requested": [txid, …],        — every raw-transaction fetch, in order
//            "glue_calls": [[arg, …], …],   — every call to the classifier bridge, verbatim
//            "rendered": "…",               — the result block's text, one node per line
//            "status": "…",                 — the fetch-row status text when it finished
//            "__constants__": {"max_rows_shown": n}}

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { webcrypto } from "node:crypto";
import vm from "node:vm";

const HERE = dirname(fileURLToPath(import.meta.url));
const SHARED_JS = resolve(HERE, "../../docs/inspect_static/inspect/shared.js");
const INSPECT_JS = resolve(HERE, "../../docs/inspect_static/inspect/inspect.js");

class StubText {
  constructor(text) {
    this.text = text;
  }
  get textContent() {
    return this.text;
  }
}

class StubElement {
  constructor(tag) {
    this.tag = tag;
    this.childNodes = [];
    this.attributes = {};
  }
  set textContent(value) {
    this.childNodes = [new StubText(String(value))];
  }
  get textContent() {
    return this.childNodes.map((c) => c.textContent).join("");
  }
  appendChild(child) {
    this.childNodes.push(child);
    return child;
  }
  replaceChildren(...children) {
    this.childNodes = children;
  }
  setAttribute(name, value) {
    this.attributes[name] = String(value);
  }
  getAttribute(name) {
    return Object.prototype.hasOwnProperty.call(this.attributes, name) ? this.attributes[name] : null;
  }
  addEventListener() {}
  focus() {}
}

function renderedLines(node) {
  const out = [];
  const walk = (n) => {
    if (n instanceof StubText) {
      out.push(n.text);
      return;
    }
    for (const child of n.childNodes) walk(child);
  };
  walk(node);
  return out.join("\n");
}

// One ElectrumX server, answering `blockchain.transaction.get` from a table. Each socket
// serves one request, as `electrumxRpc` uses it: open, one frame out, one frame back.
function makeServer(table, requested) {
  return class StubWebSocket {
    constructor() {
      this.listeners = {};
      setTimeout(() => this.dispatch("open", {}), 0);
    }
    addEventListener(type, cb) {
      (this.listeners[type] ||= []).push(cb);
    }
    dispatch(type, ev) {
      for (const cb of this.listeners[type] || []) cb(ev);
    }
    send(text) {
      const req = JSON.parse(text);
      if (req.method !== "blockchain.transaction.get" || req.params[1] !== false) {
        throw new Error(`the stub server only answers raw transaction fetches, got ${text}`);
      }
      const txid = req.params[0];
      requested.push(txid);
      const entry = table[txid];
      const frame = entry && typeof entry.hex === "string"
        ? { id: req.id, result: entry.hex }
        : { id: req.id, error: { message: (entry && entry.error) || "No such mempool or blockchain transaction" } };
      setTimeout(() => this.dispatch("message", { data: JSON.stringify(frame) }), 0);
    }
    close() {}
  };
}

async function main() {
  const spec = JSON.parse(readFileSync(0, "utf8"));
  const requested = [];
  const glueCalls = [];
  const document = {
    createElement: (tag) => new StubElement(tag),
    getElementById: () => new StubElement("div"),
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
    fetch: () => Promise.reject(new Error("no network in the fetch-flow harness")),
    crypto: { subtle: { digest: (algorithm, data) => webcrypto.subtle.digest(algorithm, data) } },
    WebSocket: makeServer(spec.server || {}, requested),
    navigator: {},
  };
  sandbox.window = sandbox;
  sandbox.globalThis = sandbox;
  vm.createContext(sandbox);
  vm.runInContext(readFileSync(SHARED_JS, "utf8"), sandbox, { filename: SHARED_JS });
  vm.runInContext(readFileSync(INSPECT_JS, "utf8"), sandbox, { filename: INSPECT_JS });
  if (typeof sandbox.onFetchTxid !== "function") {
    throw new Error(
      "onFetchTxid is not reachable after loading inspect.js. It was a top-level function " +
      "declaration; if it moved, this harness needs updating — do NOT delete the guard."
    );
  }

  // The recording bridge. `pyGlueFetch` is inspect.js's own top-level binding, which boot()
  // fills in a browser and leaves null here; it is set by name, the way the page reads it.
  const returns = spec.glue_returns || [];
  sandbox.__recorder__ = (...args) => {
    glueCalls.push(args);
    const canned = returns[glueCalls.length - 1];
    return canned !== undefined
      ? JSON.parse(JSON.stringify(canned))
      : { ok: false, form: "error", error: "harness: no canned classifier result for this call", hint: "" };
  };
  vm.runInContext("pyGlueFetch = __recorder__;", sandbox);

  const fetchBtn = new StubElement("button");
  const status = new StubElement("span");
  await sandbox.onFetchTxid(spec.txid, fetchBtn, status);

  const resultBlock = vm.runInContext("RESULT_BLOCK", sandbox);
  const constants = {
    max_rows_shown: vm.runInContext('typeof MAX_ROWS_SHOWN === "number" ? MAX_ROWS_SHOWN : null', sandbox),
  };
  process.stdout.write(JSON.stringify({
    requested,
    glue_calls: glueCalls,
    rendered: renderedLines(resultBlock),
    status: status.textContent,
    __constants__: constants,
  }));
}

main().catch((err) => {
  process.stderr.write(String((err && err.stack) || err) + "\n");
  process.exit(1);
});
