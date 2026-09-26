// Drive the browser inspect renderer under Node against a stub DOM.
//
// `docs/inspect_static/inspect/inspect.js` is a pure renderer: it boots
// Pyodide, installs the real pyrxd wheel and calls `_inspect_script` through
// `glue.py`, so no classification rule is duplicated in JS. What CAN drift is
// PRESENTATION — and presentation is where a reader's belief forms. Two HIGH
// findings landed there silently (a CSV disable-bit warning that existed in
// the CLI and not the browser; a fetched-tx row that dropped nine fields
// including `note`), because nothing executed this file outside a browser.
//
// This harness is the missing execution path. It is deliberately NOT a
// classifier: it feeds payloads produced by the real Python classifier
// (`tests/web/test_inspect_js_render_drift.py` builds them from production
// builders) into the real render functions and returns the text they emit.
// Every assertion lives on the Python side.
//
// Contract:
//   node inspect_render_harness.mjs [payloads.json|-]
//   stdin/file: JSON — {"name": {"script": {...}, "row": {...}, "tx": {...},
//                                  "result": {...}, "row_opts": {...}}, ...}
//               each of the four RENDER keys optional; at least one required.
//               `result` is a whole glue result (`{ok, form, input, payload}`), drawn by
//               the page's own `renderResult` — card AND raw-JSON drawer — and answered
//               as `result_block` (its text), `result_block_elements`, and
//               `json_drawer_chars` (the length of the drawer's JSON text).
//               `row_opts` is not a render key: it is the optional second argument
//               to `renderOutputRow`, which carries facts about the TRANSACTION that
//               no output row can hold on its own — today the mark's block anchor.
//               `renderFetchedTxCard` supplies it in production; a case that omits
//               it gets the same "no block was looked up" degrade a caller would.
//               `json_drawer: true` beside a `result` also answers `json_drawer_text`
//               (the drawer's whole JSON text) and `json_drawer_copied` (what pressing
//               its Copy JSON button handed the clipboard, or null).
//   --bigint-key K: every object of the input whose ONLY key is K, holding a string of
//               decimal digits, arrives as that BigInt — the way Pyodide's `toJs` hands
//               the page a wide int. JSON has no BigInt, and a JSON number past 2**53 is
//               rounded by JSON.parse before any page code runs, so a caller that means
//               to reach the page's BigInt path marks those values; K is the caller's
//               own, chosen per run, so no payload text can take that form by accident.
//   stdout:     JSON — {"name": {"script_card": "…", "output_row": "…",
//                                "fetched_tx_card": "…"}}
//               where each value is the rendered text, one text node per line,
//               and a key is present only when its input payload was. A `tx` case
//               also reports `fetched_tx_card_elements` and
//               `fetched_tx_card_file_inputs` — how MUCH page one transaction built,
//               which no amount of text can show. `__constants__` carries the page's
//               own MAX_ROWS_SHOWN and PAYLOAD_BINDING_WARNING_STATES, read from
//               inspect.js rather than retyped.
//
// `tx` drives `renderFetchedTxCard`, which is where the TX-LEVEL prose lives:
// the shape banner (`_detectTxShape`) and the reveal-metadata block. Those are
// whole-transaction claims — "this is a burn", "N contracts share a token_ref",
// "the freshly-minted FT lives in a separate ft output" — and no per-output row
// can carry them, so nothing reached them until this key existed.
//
// inspect.js and shared.js are loaded VERBATIM in a `vm` context, in the order
// index.html loads them. Neither is modified, wrapped or preprocessed: a guard
// that tests a rewritten copy of the file guards the rewrite. The module's top level touches `document` and ends
// with `boot()`; boot's first statement is a `typeof loadPyodide !== "function"`
// bail-out, so with no `loadPyodide` in the context it calls `showError` and
// returns without a pending promise.

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

const HERE = dirname(fileURLToPath(import.meta.url));
const SHARED_JS = resolve(HERE, "../../docs/inspect_static/inspect/shared.js");
const INSPECT_JS = resolve(HERE, "../../docs/inspect_static/inspect/inspect.js");

// --- stub DOM ---------------------------------------------------------
//
// Faithful on the two behaviours the renderers actually depend on:
// assigning `textContent` REPLACES the children (renderers set it and then
// append, e.g. `kvWithWarning`), and reading it concatenates the subtree.

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
  // Kept, not dropped, so a case can press a button the page drew (the drawer's Copy JSON).
  addEventListener(type, listener) {
    (this.listeners[type] ||= []).push(listener);
  }
  focus() {}
}

// One text fragment per line. Keeps the output readable in a failure diff and
// lets the Python side assert on ORDER (index of one phrase vs another)
// without a DOM query language.
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
// painting the signer red — which is the one thing this page must never do.
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

// Every element in the rendered tree, and the file choosers among them. The size of the
// page is a property the text cannot show: 28,000 rows of the same words read as one row
// repeated, and a bound on the page is a bound on THIS number.
function countElements(node, pred) {
  if (node instanceof StubText) return 0;
  let n = pred(node) ? 1 : 0;
  for (const child of node.childNodes) n += countElements(child, pred);
  return n;
}

// The first element in document order that satisfies `pred`, or null.
function findFirst(node, pred) {
  if (node instanceof StubText) return null;
  if (pred(node)) return node;
  for (const child of node.childNodes) {
    const hit = findFirst(child, pred);
    if (hit) return hit;
  }
  return null;
}

function makeSandbox() {
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
    // Present but never reached: boot() bails before any of these because
    // `loadPyodide` is undefined in this context.
    fetch: () => Promise.reject(new Error("no network in the render harness")),
    crypto: { subtle: {} },
    WebSocket: class {},
    // What the Copy JSON button writes is kept in `__copied__`. The promise never settles, so the
    // button's "Copied" timer is never started and the harness exits when it is done.
    navigator: {
      clipboard: {
        writeText: (text) => {
          sandbox.__copied__ = String(text);
          return new Promise(() => {});
        },
      },
    },
  };
  sandbox.window = sandbox;
  sandbox.globalThis = sandbox;
  return sandbox;
}

function loadRenderer() {
  const sandbox = makeSandbox();
  vm.createContext(sandbox);
  // shared.js FIRST, exactly as index.html loads it. Both are classic scripts, so
  // their top-level declarations land in the same context and inspect.js resolves
  // `verdictClass`, `stripControlChars`, `hashFileWithRecordAlgorithm` and the rest
  // by name — the same way the browser does.
  vm.runInContext(readFileSync(SHARED_JS, "utf8"), sandbox, { filename: SHARED_JS });
  vm.runInContext(readFileSync(INSPECT_JS, "utf8"), sandbox, { filename: INSPECT_JS });
  for (const name of ["renderScriptCard", "renderOutputRow", "renderFetchedTxCard", "renderResult"]) {
    if (typeof sandbox[name] !== "function") {
      throw new Error(
        `${name} is not reachable after loading inspect.js. It was a top-level ` +
        `function declaration; if it moved into a block or a module scope, this ` +
        `harness needs updating — do NOT delete the guard.`
      );
    }
  }
  // A top-level `const` is not a property of the global object (see
  // verify_render_harness.mjs), so it is read the way the page reads it: by name.
  // Tolerantly — absent, it is null for the Python side to fail on.
  sandbox.__constants__ = {
    max_rows_shown: vm.runInContext(
      'typeof MAX_ROWS_SHOWN === "number" ? MAX_ROWS_SHOWN : null',
      sandbox,
    ),
    payload_binding_warning_states: vm.runInContext(
      "typeof PAYLOAD_BINDING_WARNING_STATES === 'undefined' ? null : [...PAYLOAD_BINDING_WARNING_STATES]",
      sandbox,
    ),
  };
  return sandbox;
}

// The BigInt a `--bigint-key` marker stands for; anything else is returned as it came.
function bigintReviver(key) {
  return (_name, value) => {
    if (value === null || typeof value !== "object" || Array.isArray(value)) return value;
    const keys = Object.keys(value);
    if (keys.length !== 1 || keys[0] !== key) return value;
    if (typeof value[key] !== "string" || !/^-?[0-9]+$/.test(value[key])) {
      throw new Error(`a --bigint-key marker holds ${JSON.stringify(value[key])}, not decimal digits`);
    }
    return BigInt(value[key]);
  };
}

function main() {
  const args = process.argv.slice(2);
  const keyAt = args.indexOf("--bigint-key");
  const bigintKey = keyAt >= 0 ? args.splice(keyAt, 2)[1] : null;
  if (keyAt >= 0 && !bigintKey) throw new Error("--bigint-key needs a key");
  const payloadPath = args[0];
  const raw = !payloadPath || payloadPath === "-"
    ? readFileSync(0, "utf8")
    : readFileSync(payloadPath, "utf8");
  const cases = bigintKey ? JSON.parse(raw, bigintReviver(bigintKey)) : JSON.parse(raw);
  const renderer = loadRenderer();
  const results = { __constants__: renderer.__constants__ };
  for (const [name, payloads] of Object.entries(cases)) {
    const out = {};
    // A key is rendered only when its payload is present, so a tx-level case
    // need not carry a fake script and vice versa. A case carrying NONE of them
    // is a typo in the caller, and returning `{}` for it would look like a
    // renderer that produced nothing — throw instead.
    if (payloads.script) {
      const card = renderer.renderScriptCard(payloads.script);
      out.script_card = renderedLines(card);
      out.script_card_classes = renderedClasses(card);
    }
    if (payloads.row) {
      const row = renderer.renderOutputRow(payloads.row, payloads.row_opts);
      out.output_row = renderedLines(row);
      out.output_row_classes = renderedClasses(row);
    }
    if (payloads.tx) {
      const tx = renderer.renderFetchedTxCard(payloads.tx);
      out.fetched_tx_card = renderedLines(tx);
      out.fetched_tx_card_classes = renderedClasses(tx);
      out.fetched_tx_card_elements = countElements(tx, () => true);
      out.fetched_tx_card_file_inputs = countElements(tx, (n) => n.tag === "input" && n.type === "file");
    }
    if (payloads.result) {
      // `RESULT_BLOCK` is inspect.js's own top-level const: the element renderResult fills.
      renderer.renderResult(payloads.result);
      const block = vm.runInContext("RESULT_BLOCK", renderer);
      out.result_block = renderedLines(block);
      out.result_block_elements = countElements(block, () => true);
      const pre = findFirst(block, (n) => n.className === "json-block");
      out.json_drawer_chars = pre ? pre.textContent.length : null;
      if (payloads.json_drawer) {
        out.json_drawer_text = pre ? pre.textContent : null;
        renderer.__copied__ = null;
        const copy = findFirst(block, (n) => n.className === "copy-json-btn");
        for (const listener of (copy && copy.listeners.click) || []) listener();
        out.json_drawer_copied = renderer.__copied__;
      }
    }
    if (Object.keys(out).length === 0) {
      throw new Error(
        `case ${JSON.stringify(name)} has none of "script", "row", "tx", "result" — nothing to render`
      );
    }
    if (payloads.json_drawer && !payloads.result) {
      throw new Error(
        `case ${JSON.stringify(name)} has "json_drawer" but no "result", so no drawer was drawn`
      );
    }
    // `row_opts` without a `row` renders nothing and silently proves nothing — the
    // caller meant to drive the output row and did not.
    if (payloads.row_opts && !payloads.row) {
      throw new Error(
        `case ${JSON.stringify(name)} has "row_opts" but no "row", so the options were never used`
      );
    }
    results[name] = out;
  }
  process.stdout.write(JSON.stringify(results));
}

main();
