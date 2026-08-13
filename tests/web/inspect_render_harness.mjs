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
//   stdin/file: JSON — {"name": {"script": {...}, "row": {...}}, ...}
//   stdout:     JSON — {"name": {"script_card": "…", "output_row": "…"}}
//               where each value is the rendered text, one text node per line.
//
// inspect.js is loaded VERBATIM in a `vm` context. It is not modified, not
// wrapped and not preprocessed: a guard that tests a rewritten copy of the
// file guards the rewrite. The module's top level touches `document` and ends
// with `boot()`; boot's first statement is a `typeof loadPyodide !== "function"`
// bail-out, so with no `loadPyodide` in the context it calls `showError` and
// returns without a pending promise.

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

const HERE = dirname(fileURLToPath(import.meta.url));
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
  };
  sandbox.window = sandbox;
  sandbox.globalThis = sandbox;
  return sandbox;
}

function loadRenderer() {
  const source = readFileSync(INSPECT_JS, "utf8");
  const sandbox = makeSandbox();
  vm.createContext(sandbox);
  vm.runInContext(source, sandbox, { filename: INSPECT_JS });
  for (const name of ["renderScriptCard", "renderOutputRow"]) {
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

function main() {
  const payloadPath = process.argv[2];
  const raw = !payloadPath || payloadPath === "-"
    ? readFileSync(0, "utf8")
    : readFileSync(payloadPath, "utf8");
  const cases = JSON.parse(raw);
  const renderer = loadRenderer();
  const results = {};
  for (const [name, payloads] of Object.entries(cases)) {
    results[name] = {
      script_card: renderedLines(renderer.renderScriptCard(payloads.script)),
      output_row: renderedLines(renderer.renderOutputRow(payloads.row)),
    };
  }
  process.stdout.write(JSON.stringify(results));
}

main();
