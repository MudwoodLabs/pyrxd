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
// server for and exactly what it hands each Python bridge — the classifier
// (`inspect_txid_with_raw`) and the binding step (`spent_output_binding`). Each bridge answers
// from a canned list, call by call. The Python side (`test_inspect_fetch_flow.py`) computes
// those answers with the REAL `glue.py` on the arguments the page really passed — replaying a
// first run's recorded arguments, then running again with the real answers and checking the
// page passed the same arguments — so what the page RENDERS is what it renders for the real
// classifier's real answer.
//
// shared.js and inspect.js are loaded VERBATIM in a `vm` context, in the order index.html
// loads them. The digest is Node's real WebCrypto, so the hash check that runs is the one
// the page runs.
//
// Contract:
//   node inspect_fetch_flow_harness.mjs < case.json
//   stdin:  {"txid": hex,
//            "server": {txid: {"hex": rawHex} | {"error": message, "code"?: n} | {"close": true}
//                             | {"frame": text}},  — anything not listed answers with the frame
//                      the public endpoint was measured to send for a transaction it does not
//                      have (NOT_FOUND_FRAME below). `close` closes the socket without
//                      answering; `frame` is sent verbatim instead of a JSON reply.
//            "glue_returns": [result, …],   — what the classifier bridge returns, call by call
//            "binding_returns": [result, …], — what the binding bridge returns, call by call
//            "anchor_returns"?: [anchor, …], — what the block-lookup bridge returns, call by call
//            "binding_throws"?: true,       — the binding bridge raises instead of answering
//            "interleave"?: "clear" | {"classify": {"text", "result"}}, — what the reader does
//                      while the fetch is still waiting on the server
//            "interleave_on_request"?: n} — do it when the server receives its n-th request
//                      (every method counted), instead of during the first fetch
//   stdout: {"requested": [txid, …],        — every raw-transaction fetch, in order
//            "glue_calls": [[arg, …], …],   — every call to the classifier bridge, verbatim
//            "binding_calls": [[arg, …], …], — every call to the binding bridge, verbatim
//            "anchor_calls": [[arg, …], …],  — every call to the block-lookup bridge, verbatim
//            "server_log": [[method, params], …], — every request the server received, in order
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

// What the public ElectrumX endpoint /inspect/ uses answered, measured 2026-09-23, for
// `blockchain.transaction.get` of a txid it does not have: ElectrumX's DAEMON_ERROR (2) wrapping
// the node's own -5.
const NOT_FOUND_ERROR = {
  code: 2,
  message:
    "daemon error: DaemonError({'code': -5, 'message': 'No such mempool or blockchain transaction. " +
    "Use gettransaction for wallet transactions.'})",
};

// One ElectrumX server, answering `blockchain.transaction.get` from a table. Each socket
// serves one request, as `electrumxRpc` uses it: open, one frame out, one frame back.
// `hooks.onRequest(n, req)` runs SYNCHRONOUSLY when the n-th request of the run arrives
// (1-based, every method counted), before it is answered — which is how a case interrupts the
// page at a particular wait. The block lookup's two calls are answered too: the verbose form
// of a transaction in the table (`[txid, true]`, with `hooks.confirmations`) and the tip.
function makeServer(table, requested, hooks) {
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
      hooks.count += 1;
      hooks.log.push([req.method, req.params]);
      if (hooks.onRequest) hooks.onRequest(hooks.count, req);
      if (req.method === "blockchain.headers.subscribe") {
        const frame = { id: req.id, result: { height: hooks.tip, hex: "" } };
        setTimeout(() => this.dispatch("message", { data: JSON.stringify(frame) }), 0);
        return;
      }
      if (req.method === "blockchain.transaction.get" && req.params[1] === true && table[req.params[0]]) {
        const frame = { id: req.id, result: { txid: req.params[0], confirmations: hooks.confirmations } };
        setTimeout(() => this.dispatch("message", { data: JSON.stringify(frame) }), 0);
        return;
      }
      if (req.method !== "blockchain.transaction.get" || req.params[1] !== false) {
        throw new Error(`the stub server only answers raw transaction fetches and the block lookup, got ${text}`);
      }
      const txid = req.params[0];
      requested.push(txid);
      const entry = table[txid];
      if (entry && entry.close) {
        setTimeout(() => this.dispatch("close", {}), 0);
        return;
      }
      if (entry && typeof entry.frame === "string") {
        setTimeout(() => this.dispatch("message", { data: entry.frame }), 0);
        return;
      }
      let frame;
      if (entry && typeof entry.hex === "string") {
        frame = { id: req.id, result: entry.hex };
      } else if (entry && typeof entry.error === "string") {
        frame = { id: req.id, error: entry.code === undefined ? { message: entry.error } : { code: entry.code, message: entry.error } };
      } else {
        frame = { id: req.id, error: NOT_FOUND_ERROR };
      }
      setTimeout(() => this.dispatch("message", { data: JSON.stringify(frame) }), 0);
    }
    close() {}
  };
}

async function main() {
  const spec = JSON.parse(readFileSync(0, "utf8"));
  const requested = [];
  const glueCalls = [];
  const bindingCalls = [];
  const anchorCalls = [];
  const hooks = { count: 0, log: [], onRequest: null, confirmations: spec.confirmations ?? 5, tip: spec.tip ?? 460572 };
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
    WebSocket: makeServer(spec.server || {}, requested, hooks),
    navigator: {},
    // Read by Clear and by a classification, which rewrite `?input=` in the address bar.
    location: { href: "https://pyrxd.invalid/inspect/", search: "" },
    history: { replaceState() {} },
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

  // The recording bridges. `pyGlueFetch` and `pySpentBinding` are inspect.js's own top-level
  // bindings, which boot() fills in a browser and leaves null here; they are set by name, the
  // way the page reads them. A call with no canned answer gets an error dict naming the
  // harness, so a test that forgot one cannot pass on the page's own error handling.
  const recorder = (calls, returns, what) => (...args) => {
    calls.push(args);
    const canned = returns[calls.length - 1];
    return canned !== undefined
      ? JSON.parse(JSON.stringify(canned))
      : { ok: false, form: "error", error: `harness: no canned ${what} for this call`, hint: "" };
  };
  sandbox.__recorder__ = recorder(glueCalls, spec.glue_returns || [], "classifier result");
  sandbox.__binding_recorder__ = spec.binding_throws
    ? (...args) => {
      // A bridge that RAISES rather than answering — the path that lands in onFetchTxid's
      // "bridge error" branch, which renders too and so is guarded too.
      bindingCalls.push(args);
      throw new Error("harness: the binding bridge raised");
    }
    : recorder(bindingCalls, spec.binding_returns || [], "binding result");
  // The block lookup's bridge (`glue.mark_anchor`). Its canned answers are the real glue's.
  sandbox.__anchor_recorder__ = recorder(anchorCalls, spec.anchor_returns || [], "anchor result");
  vm.runInContext(
    "pyGlueFetch = __recorder__; pySpentBinding = __binding_recorder__; pyMarkAnchor = __anchor_recorder__;",
    sandbox,
  );

  const fetchBtn = new StubElement("button");
  const status = new StubElement("span");
  // `interleave`: what the reader does WHILE the fetch is waiting on the server. "clear" presses
  // Clear; {"classify": {"text", "result"}} classifies another input, the offline bridge
  // answering with `result`.
  //
  // WHEN, by `interleave_on_request`: absent, it runs synchronously right after `onFetchTxid`
  // starts — during the FIRST fetch, before any answer can arrive (the stub server answers on a
  // later timer tick). A number n runs it the moment the server receives its n-th request, before
  // answering it — so a case can interrupt the page during the spent-transaction fetch, or during
  // the block lookup, instead of only ever during the first wait.
  const act = () => {
    if (spec.interleave === "clear") {
      sandbox.onClear();
    } else if (spec.interleave && spec.interleave.classify) {
      const { text, result } = spec.interleave.classify;
      sandbox.__classify__ = () => ({ toJs: () => JSON.parse(JSON.stringify(result)), destroy() {} });
      vm.runInContext(`pyGlue = __classify__; INPUT_BOX.value = ${JSON.stringify(text)};`, sandbox);
      sandbox.onClassify();
    } else {
      throw new Error(`unknown interleave ${JSON.stringify(spec.interleave)}`);
    }
  };
  let acted = false;
  if (spec.interleave && spec.interleave_on_request !== undefined) {
    hooks.onRequest = (n) => {
      if (n === spec.interleave_on_request) {
        acted = true;
        act();
      }
    };
  }
  const pending = sandbox.onFetchTxid(spec.txid, fetchBtn, status);
  if (spec.interleave && spec.interleave_on_request === undefined) {
    acted = true;
    act();
  }
  await pending;
  if (spec.interleave && !acted) {
    // A case that asked to interrupt at a request the page never made proves nothing.
    throw new Error(`the interleave never ran: the server saw ${hooks.count} request(s), not ${spec.interleave_on_request}`);
  }

  const resultBlock = vm.runInContext("RESULT_BLOCK", sandbox);
  const constants = {
    max_rows_shown: vm.runInContext('typeof MAX_ROWS_SHOWN === "number" ? MAX_ROWS_SHOWN : null', sandbox),
  };
  process.stdout.write(JSON.stringify({
    requested,
    glue_calls: glueCalls,
    binding_calls: bindingCalls,
    anchor_calls: anchorCalls,
    server_log: hooks.log,
    rendered: renderedLines(resultBlock),
    status: status.textContent,
    __constants__: constants,
  }));
}

main().catch((err) => {
  process.stderr.write(String((err && err.stack) || err) + "\n");
  process.exit(1);
});
