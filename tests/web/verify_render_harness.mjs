// Drive the PUBLIC verify page's renderer under Node against a stub DOM.
//
// Same technique, and the same reason, as `inspect_render_harness.mjs`: the page is
// a pure renderer over a dict the real Python classifier produced, so no
// classification rule is duplicated in JS — but PRESENTATION is where a reader's
// belief forms, and presentation drifts silently when nothing executes the file
// outside a browser.
//
// THIS PAGE'S PARTICULAR RISK, and why the guard is worth more here than on the
// inspector: /verify/ is written for someone who does not know what a HashMark is.
// The inspector's failure mode is a missing field a developer notices; this page's
// failure mode is a SENTENCE that claims more than the verdict above it supports,
// read by someone with no way to tell. Text is the product here.
//
// `shared.js` and `verify.js` are loaded VERBATIM in a `vm` context, in the order
// index.html loads them. Neither is modified, wrapped or preprocessed: a guard that
// tests a rewritten copy of the file guards the rewrite.
//
// Contract:
//   node verify_render_harness.mjs [cases.json|-]
//   stdin/file: JSON — {"name": {"result": {...}}, ...}
//               `result` is the whole dict `glue.run` / `glue.inspect_txid_with_raw`
//               returns, optionally with `payload.mark_anchor` attached the way
//               `lookUp` attaches it in production.
//               A case may also carry `choose_files: [{"input": k, "text": "..."}]`:
//               after rendering, the k-th file chooser on the page (document order)
//               is given a File of those bytes and its REAL `change` listener runs —
//               the one `answerIsThisYourFile` attached, closing over ITS record.
//               A case may instead carry `wire_error: {"message", "kind"?}` — a rejection built
//               here and handed to `lookupFailure` — or `wire_frame: "<text>"`: a server that
//               answers `blockchain.transaction.get` with exactly that frame, fetched through
//               shared.js's own `fetchRawTxFromElectrumx`, whose rejection is then handed to
//               `lookupFailure`. The second is the whole path a real error frame takes.
//               A case may instead carry `check: {"text", "raw": {txid: hex}, "run_returns",
//               "fetch_returns", "anchor_returns", "confirmations"?, "tip"?}` — the page's own
//               `onCheck` is run with `text` typed into the box, against a server answering
//               from `raw` and bridges answering from the canned lists; the output then also
//               carries `requested` (every server call) and `calls` (every bridge call).
//               `check` may also carry `blockhash` and `headers` ({height: hex}) for the block
//               lookup, `anchor_python` (an interpreter: the REAL glue.mark_anchor answers the
//               block lookup instead of `anchor_returns`) and `interleave_clear_on_request` (n).
//   stdout:     JSON — {"name": {"text": "…", "classes": [...], "statuses": [...],
//                                "panels": [...], "file_inputs": n, "judged": [...]}}
//               `text` is one text node per line, so the Python side can assert on
//               ORDER (index of one phrase against another) without a DOM query
//               language; `classes` is every class attribute in document order,
//               because the verdict's COLOUR is a claim that no text assertion sees.
//               `statuses` is the text of every `.verdict-status` in document order
//               (the headline WORD of each verdict block); `panels` is the text of
//               each `.mark` panel, so an assertion can be scoped to ONE record;
//               `judged` is every call the page made to the file judge.

import { readFileSync } from "node:fs";
import { webcrypto } from "node:crypto";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";
import { makeGlueSubprocessBridge } from "./glue_subprocess_bridge.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const SHARED_JS = resolve(HERE, "../../docs/inspect_static/inspect/shared.js");
const VERIFY_JS = resolve(HERE, "../../docs/inspect_static/verify/verify.js");
const GLUE_DIR = resolve(HERE, "../../docs/inspect_static/inspect");

// --- stub DOM ---------------------------------------------------------
//
// Faithful on the two behaviours the renderers depend on: assigning `textContent`
// REPLACES the children, and reading it concatenates the subtree.

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
    this.hidden = false;
    // KEPT, not discarded, so a case can fire the page's own listener. A no-op here
    // would leave every file chooser on the page inert under test.
    this.listeners = {};
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
  addEventListener(type, fn) {
    (this.listeners[type] = this.listeners[type] || []).push(fn);
  }
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

// Every `class` attribute in the rendered tree, in document order.
//
// `renderedLines` returns TEXT, and text is not the whole claim a page makes. The
// verdict blocks carry their meaning in a CLASS: `verdict-unchecked` is neutral,
// `verdict-bad` is the error colour. A change that rendered an honest, merely
// unchecked mark with `verdict-bad` would keep every text assertion green while
// painting the signer red — the one thing this page must never do.
function renderedClasses(node) {
  const out = [];
  const walk = (n) => {
    if (n instanceof StubText) return;
    // `el()` assigns `node.className` as a PROPERTY; it never calls setAttribute,
    // so reading only the attribute returns null for every element on the page.
    const cls = n.className || (n.getAttribute ? n.getAttribute("class") : null);
    if (cls) out.push(cls);
    for (const child of n.childNodes) walk(child);
  };
  walk(node);
  return out;
}

function classOf(n) {
  return n.className || (n.getAttribute ? n.getAttribute("class") : null) || "";
}

// Every element under `node`, in document order, that `keep` accepts.
function collect(node, keep) {
  const out = [];
  const walk = (n) => {
    if (n instanceof StubText) return;
    if (keep(n)) out.push(n);
    for (const child of n.childNodes) walk(child);
  };
  walk(node);
  return out;
}

const hasClass = (name) => (n) => classOf(n).split(/\s+/).includes(name);

function makeSandbox() {
  const document = {
    createElement: (tag) => new StubElement(tag),
    getElementById: () => new StubElement("div"),
    querySelectorAll: () => [],
    baseURI: "https://pyrxd.invalid/verify/",
  };
  const sandbox = {
    document,
    console: { log() {}, warn() {}, error() {} },
    URL,
    URLSearchParams,
    TextDecoder,
    setTimeout,
    clearTimeout,
    // `boot()` runs at module load and fails immediately: `bootPyrxdRuntime` throws
    // because `loadPyodide` is undefined here, verify.js catches it and calls
    // showError. No pending promise, no network.
    fetch: () => Promise.reject(new Error("no network in the verify render harness")),
    // REAL digest, from Node's WebCrypto, so a file chosen in a case is really hashed.
    // Nothing else on the page touches `crypto`.
    crypto: { subtle: { digest: (algorithm, data) => webcrypto.subtle.digest(algorithm, data) } },
    File,
    WebSocket: class {},
    navigator: {},
    location: { href: "https://pyrxd.invalid/verify/", search: "" },
    history: { replaceState() {} },
  };
  sandbox.window = sandbox;
  sandbox.globalThis = sandbox;
  return sandbox;
}

function loadRenderer() {
  const sandbox = makeSandbox();
  vm.createContext(sandbox);
  // shared.js FIRST, exactly as index.html loads it. Both are classic scripts, so
  // their top-level declarations land in the same context and verify.js resolves
  // `verdictClass`, `stripControlChars`, `hashmarkRecords`, `WHAT_A_MARK_PROVES`
  // and the rest by name — the same way the browser does.
  vm.runInContext(readFileSync(SHARED_JS, "utf8"), sandbox, { filename: SHARED_JS });
  vm.runInContext(readFileSync(VERIFY_JS, "utf8"), sandbox, { filename: VERIFY_JS });
  for (const name of ["renderReport", "verdictClass", "hashmarkRecords", "lookupFailure", "fetchRawTxFromElectrumx"]) {
    if (typeof sandbox[name] !== "function") {
      throw new Error(
        `${name} is not reachable after loading shared.js + verify.js. Both were ` +
        `top-level declarations in classic scripts; if either moved into a block or ` +
        `became an ES module, this harness needs updating — do NOT delete the guard.`
      );
    }
  }
  // A TOP-LEVEL `const` IS NOT A PROPERTY OF THE GLOBAL OBJECT. Function
  // declarations become `sandbox.name`; `const` and `let` land in the global
  // LEXICAL environment, which is shared across `runInContext` calls in one context
  // but invisible on the sandbox object. `sandbox.WHAT_A_MARK_PROVES` is therefore
  // `undefined` while the binding is perfectly reachable — the same asymmetry a
  // browser has, where verify.js resolves the name by scope lookup. Read it the way
  // the page does: by evaluating the name.
  const constants = vm.runInContext(
    "({ what_a_mark_proves: WHAT_A_MARK_PROVES, file_never_leaves: FILE_NEVER_LEAVES_THIS_MACHINE })",
    sandbox,
  );
  for (const [key, value] of Object.entries(constants)) {
    if (typeof value !== "string" || !value) {
      throw new Error(`${key} is not reachable from shared.js — do NOT delete the guard.`);
    }
  }
  // A NUMBER, read the same way, and TOLERANTLY: absent, it is reported as null for the
  // Python side to fail on, rather than taking every other case down with it.
  constants.max_mark_panels = vm.runInContext(
    'typeof MAX_MARK_PANELS === "number" ? MAX_MARK_PANELS : null',
    sandbox,
  );
  sandbox.__constants__ = constants;
  return sandbox;
}

// Choose files on the rendered page through its OWN listeners.
//
// `bridges` is verify.js's top-level binding, which `boot()` fills in the browser and
// leaves null here. It is set for the duration of the case: the PLAN is the real one,
// computed by Python and passed in with the case; the JUDGE is a recorder, because the
// property this owns is which digest the page hands it — which record's — and the
// deciding is Python's, tested elsewhere (`test_hashmark_panel_verdict`).
async function chooseFiles(renderer, node, spec) {
  const judged = [];
  renderer.__harnessBridges__ = {
    fileCheckPlan: () => spec.file_check_plan,
    judgeFileDigest: (expected, computed, algorithm) => {
      judged.push({ expected, computed, algorithm });
      const match = expected === computed;
      return { checked: true, match, status: match ? "MATCHES" : "DOES NOT MATCH", meaning: "(recorded by the harness)" };
    },
  };
  vm.runInContext("bridges = __harnessBridges__;", renderer);
  try {
    const inputs = collect(node, (n) => n.tag === "input" && n.type === "file");
    for (const choice of spec.choose_files) {
      const input = inputs[choice.input];
      if (!input) throw new Error(`there is no file chooser #${choice.input} (found ${inputs.length})`);
      input.files = [new File([new TextEncoder().encode(choice.text)], choice.name || "chosen.bin")];
      const handlers = input.listeners.change || [];
      if (handlers.length !== 1) throw new Error(`file chooser #${choice.input} has ${handlers.length} change listeners`);
      await handlers[0]();
    }
  } finally {
    vm.runInContext("bridges = null;", renderer);
  }
  return judged;
}

// A server that answers the one request with `frame`, verbatim — the socket shape
// `electrumxRpc` uses: open, one frame out, one frame back.
function frameServer(frame) {
  return class FrameWebSocket {
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
    send() {
      setTimeout(() => this.dispatch("message", { data: frame }), 0);
    }
    close() {}
  };
}

// A server that answers the three calls `lookUp` makes, from a table: the raw transaction
// (`blockchain.transaction.get [txid, false]`), its verbose form (`[txid, true]`, carrying a
// confirmation count), and the tip (`blockchain.headers.subscribe`). Every request is
// recorded, so a case can say which transaction the page actually asked for.
function tableServer(table, requested, onRequest) {
  return class TableWebSocket {
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
      requested.push([req.method, req.params]);
      if (onRequest) onRequest(requested.length, req);
      let frame;
      if (req.method === "blockchain.headers.subscribe") {
        frame = { id: req.id, result: { height: table.tip, hex: "" } };
      } else if (req.method === "blockchain.block.header") {
        // Served verbatim from the table, whatever it holds; any other height is refused the way
        // ElectrumX refuses a height past its index.
        const key = String(req.params[0]);
        const served = table.headers[key];
        // `{"hang": true}`: the request is never answered — the page's own timeout is what ends it.
        if (served && typeof served === "object" && served.hang) return;
        frame = Object.prototype.hasOwnProperty.call(table.headers, key)
          ? { id: req.id, result: served }
          : { id: req.id, error: { code: 1, message: `height ${key} out of range` } };
      } else if (req.method === "blockchain.transaction.get" && typeof table.raw[req.params[0]] === "string") {
        const verbose = { txid: req.params[0], confirmations: table.confirmations };
        if (table.blockhash !== undefined) verbose.blockhash = table.blockhash;
        frame = req.params[1] ? { id: req.id, result: verbose } : { id: req.id, result: table.raw[req.params[0]] };
      } else {
        frame = { id: req.id, error: { code: 2, message: "daemon error: No such mempool or blockchain transaction." } };
      }
      setTimeout(() => this.dispatch("message", { data: JSON.stringify(frame) }), 0);
    }
    close() {}
  };
}

// Drive the page's OWN `onCheck` — what the Check button runs — with `text` typed into the
// box. The three Python bridges are recorders answering from canned lists the Python side
// computed with the REAL `glue.py`; what is asserted is what the page asked the server for,
// what it handed each bridge, and what it drew.
async function driveCheck(renderer, spec) {
  const requested = [];
  const calls = { run: [], fetch: [], anchor: [] };
  const recorder = (bucket, returns) => (...args) => {
    calls[bucket].push(args);
    const canned = (returns || [])[calls[bucket].length - 1];
    if (canned === undefined) throw new Error(`harness: no canned ${bucket} answer for call ${calls[bucket].length}`);
    return JSON.parse(JSON.stringify(canned));
  };
  // `interleave_clear_on_request: n` — press Start over the moment the server receives its n-th
  // request, before it is answered: the reader moving on while the page is still waiting.
  let cleared = false;
  const onRequest = spec.interleave_clear_on_request === undefined
    ? null
    : (n) => {
      if (n === spec.interleave_clear_on_request) {
        cleared = true;
        renderer.onClear();
      }
    };
  renderer.WebSocket = tableServer(
    {
      raw: spec.raw || {},
      confirmations: spec.confirmations ?? 5,
      tip: spec.tip ?? 460572,
      blockhash: spec.blockhash,
      headers: spec.headers || {},
    },
    requested,
    onRequest,
  );
  renderer.__run__ = recorder("run", spec.run_returns);
  renderer.__fetch__ = recorder("fetch", spec.fetch_returns);
  // `anchor_python`: the REAL glue.mark_anchor answers the block lookup (glue_subprocess_bridge.mjs).
  renderer.__anchor__ = spec.anchor_python
    ? makeGlueSubprocessBridge(spec.anchor_python, GLUE_DIR, calls.anchor)
    : recorder("anchor", spec.anchor_returns);
  vm.runInContext(
    "pyRun = __run__; pyFetch = __fetch__; bridges = { markAnchor: __anchor__ }; " +
    `INPUT_BOX.value = ${JSON.stringify(spec.text)};`,
    renderer,
  );
  try {
    await renderer.onCheck();
  } finally {
    vm.runInContext("pyRun = null; pyFetch = null; bridges = null;", renderer);
  }
  if (onRequest && !cleared) {
    throw new Error(`the interleave never ran: the server saw ${requested.length} request(s)`);
  }
  const block = vm.runInContext("RESULT_BLOCK", renderer);
  return { node: block, requested, calls };
}

async function main() {
  const payloadPath = process.argv[2];
  const raw = !payloadPath || payloadPath === "-"
    ? readFileSync(0, "utf8")
    : readFileSync(payloadPath, "utf8");
  const cases = JSON.parse(raw);
  const renderer = loadRenderer();
  const results = {
    // Exported so the Python side can pin the shared sentences against the OTHER
    // page's copy without re-typing either of them here.
    __constants__: renderer.__constants__,
  };
  for (const [name, spec] of Object.entries(cases)) {
    // A case is EITHER a classification to render, or a wire failure to render —
    // and the second goes through `lookupFailure`, the production function that
    // turns a rejected ElectrumX promise into what the reader sees. Reaching the
    // page with a hand-built error dict would prove the renderer and leave the
    // translation, which is the half that was wrong, untested.
    let node;
    let checked = null;
    if (spec && spec.check) {
      checked = await driveCheck(renderer, spec.check);
      node = checked.node;
    } else if (spec && typeof spec.wire_frame === "string") {
      renderer.WebSocket = frameServer(spec.wire_frame);
      let rejection = null;
      try {
        await renderer.fetchRawTxFromElectrumx("ab".repeat(32));
      } catch (err) {
        rejection = err;
      }
      if (rejection === null) throw new Error(`case ${JSON.stringify(name)}: the frame did not reject`);
      node = renderer.renderReport(renderer.lookupFailure(rejection));
    } else if (spec && spec.wire_error) {
      const err = new Error(spec.wire_error.message || "");
      if (spec.wire_error.kind !== undefined) err.kind = spec.wire_error.kind;
      node = renderer.renderReport(renderer.lookupFailure(err));
    } else if (spec && spec.result) {
      node = renderer.renderReport(spec.result);
    } else {
      throw new Error(`case ${JSON.stringify(name)} has neither "result" nor "wire_error" — nothing to render`);
    }
    const judged = spec && spec.choose_files ? await chooseFiles(renderer, node, spec) : [];
    results[name] = {
      text: renderedLines(node),
      classes: renderedClasses(node),
      statuses: collect(node, hasClass("verdict-status")).map((n) => n.textContent),
      panels: collect(node, hasClass("mark")).map(renderedLines),
      file_inputs: collect(node, (n) => n.tag === "input" && n.type === "file").length,
      judged,
      ...(checked ? { requested: checked.requested, calls: checked.calls } : {}),
    };
  }
  process.stdout.write(JSON.stringify(results));
}

main().catch((err) => {
  process.stderr.write(String((err && err.stack) || err) + "\n");
  process.exit(1);
});
