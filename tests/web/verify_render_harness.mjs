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
//   stdout:     JSON — {"name": {"text": "…", "classes": [...]}}
//               `text` is one text node per line, so the Python side can assert on
//               ORDER (index of one phrase against another) without a DOM query
//               language; `classes` is every class attribute in document order,
//               because the verdict's COLOUR is a claim that no text assertion sees.

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

const HERE = dirname(fileURLToPath(import.meta.url));
const SHARED_JS = resolve(HERE, "../../docs/inspect_static/inspect/shared.js");
const VERIFY_JS = resolve(HERE, "../../docs/inspect_static/verify/verify.js");

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
    crypto: { subtle: {} },
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
  for (const name of ["renderReport", "verdictClass", "hashmarkRecords", "lookupFailure"]) {
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
  sandbox.__constants__ = constants;
  return sandbox;
}

function main() {
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
    if (spec && spec.wire_error) {
      const err = new Error(spec.wire_error.message || "");
      if (spec.wire_error.kind !== undefined) err.kind = spec.wire_error.kind;
      node = renderer.renderReport(renderer.lookupFailure(err));
    } else if (spec && spec.result) {
      node = renderer.renderReport(spec.result);
    } else {
      throw new Error(`case ${JSON.stringify(name)} has neither "result" nor "wire_error" — nothing to render`);
    }
    results[name] = { text: renderedLines(node), classes: renderedClasses(node) };
  }
  process.stdout.write(JSON.stringify(results));
}

main();
