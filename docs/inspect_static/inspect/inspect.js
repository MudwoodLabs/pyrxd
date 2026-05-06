// inspect.js — pyrxd inspect tool: boot + classifier UI.
//
// Two phases:
//
//  1. Boot — load Pyodide, install the same-origin pyrxd wheel, and
//     load the Pyodide-side glue (`glue.py`). This phase ends when
//     `pyodide` and a callable `pyGlue` reference are stashed on
//     module-scope and the form is enabled.
//
//  2. Interactive — wire the paste box, classify button, share button,
//     clear button, and `?input=` URL hydration. Each classification
//     calls `pyGlue(text)`, which returns a JSON-serialisable dict the
//     renderer dispatches by `result.form`.
//
// Trust boundary:
//
//  Every string we write to the DOM goes through `textContent`. Never
//  `innerHTML`, never templated string concatenation into HTML. The
//  Python side has already sanitized any CBOR-derived strings before
//  they cross the bridge (see `glue.py`'s `_sanitize_payload_strings`),
//  but defence-in-depth: we double up at the render layer. If a future
//  payload field is added that the Python side somehow forgot, this
//  layer still keeps it inert.
//
// Why a CDN with SRI instead of vendoring Pyodide in the repo:
// vendoring ~12 MB of WASM blobs would inflate every clone forever and
// committing pre-built binaries muddies provenance. The CDN-with-SRI
// approach keeps the repo small and uses the browser's integrity check
// as the audit trail — if jsdelivr ever serves bytes that don't match
// the integrity hash in index.html, the browser refuses to execute.
// The SRI hash is pinned by scripts/refresh-pyodide.sh and changes only
// when a maintainer deliberately bumps the Pyodide version.

"use strict";

// ---------------------------------------------------------------------
// DOM handles
// ---------------------------------------------------------------------

const STATUS_BLOCK = document.getElementById("loading-status");
const PROGRESS = document.getElementById("load-progress");
const READY_BLOCK = document.getElementById("ready-content");
const VERSION_BLOCK = document.getElementById("version-block");
const ERROR_BLOCK = document.getElementById("error-content");
const ERROR_PRE = document.getElementById("error-block");
const BUILD_VERSION = document.getElementById("build-version");

// Classifier-UI handles (all live inside #ready-content; populated when
// boot finishes and #ready-content is unhidden).
const INPUT_BOX = document.getElementById("paste-input");
const CLASSIFY_BTN = document.getElementById("classify-btn");
const CLEAR_BTN = document.getElementById("clear-btn");
const SHARE_BTN = document.getElementById("share-btn");
const RESULT_BLOCK = document.getElementById("result-block");
const ONBOARDING = document.getElementById("onboarding");
const EXAMPLE_CHIPS = document.querySelectorAll(".example-chip");

// Same-origin URL where the pyrxd wheel is staged. Set by the docs.yml CI
// step that runs ``pip wheel -w docs/inspect_static/inspect/wheels --no-deps .``
// before ``sphinx-build``. The wheel's filename embeds the version, so we
// discover it at runtime via the `manifest.json` written next to it.
const WHEELS_BASE = new URL("./wheels/", document.baseURI).toString();
const WHEELS_MANIFEST = new URL("./manifest.json", WHEELS_BASE).toString();
const GLUE_URL = new URL("./glue.py", document.baseURI).toString();

// Module-scope handle to the Python `run` function once boot completes.
// Keeping this on the module rather than `window` avoids polluting the
// global namespace and keeps the surface explicit.
let pyGlue = null;

// ---------------------------------------------------------------------
// Status / error helpers
// ---------------------------------------------------------------------

function showError(message) {
  console.error(message);
  STATUS_BLOCK.hidden = true;
  ERROR_BLOCK.hidden = false;
  // textContent only — never innerHTML — to defend against XSS via injected
  // error strings (e.g. a hostile manifest.json with attacker bytes).
  ERROR_PRE.textContent = String(message);
}

function showReady(versionText, buildSha) {
  STATUS_BLOCK.hidden = true;
  READY_BLOCK.hidden = false;
  VERSION_BLOCK.textContent = versionText;
  if (buildSha) {
    BUILD_VERSION.textContent = `build: ${buildSha}`;
  }
}

function setProgress(pct) {
  if (PROGRESS) {
    PROGRESS.value = Math.max(0, Math.min(100, pct));
  }
}

// ---------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------

async function loadManifest() {
  setProgress(5);
  try {
    const resp = await fetch(WHEELS_MANIFEST, { cache: "no-cache" });
    if (!resp.ok) {
      throw new Error(`manifest HTTP ${resp.status}`);
    }
    return await resp.json();
  } catch (err) {
    throw new Error(
      `Could not load wheel manifest from ${WHEELS_MANIFEST}: ${err.message}. ` +
      `This usually means the docs CI step that builds the wheel failed.`
    );
  }
}

async function fetchGlueSource() {
  const resp = await fetch(GLUE_URL, { cache: "no-cache" });
  if (!resp.ok) {
    throw new Error(`glue.py HTTP ${resp.status}`);
  }
  return await resp.text();
}

async function boot() {
  if (typeof loadPyodide !== "function") {
    showError(
      "Pyodide failed to load. This is most often a Subresource Integrity " +
      "mismatch (the CDN served bytes that don't match the pinned SHA-384 " +
      "hash in index.html). Open the browser console for the underlying error."
    );
    return;
  }

  let manifest;
  try {
    manifest = await loadManifest();
  } catch (err) {
    showError(err.message);
    return;
  }

  setProgress(15);

  let pyodide;
  try {
    pyodide = await loadPyodide({
      indexURL: "https://cdn.jsdelivr.net/pyodide/v0.26.4/full/",
    });
  } catch (err) {
    showError(`Pyodide runtime failed to initialise: ${err.message}`);
    return;
  }

  setProgress(60);

  try {
    await pyodide.loadPackage(["micropip"]);
    const wheelURL = new URL(manifest.wheel, WHEELS_BASE).toString();
    await pyodide.runPythonAsync(`
import micropip
await micropip.install(${JSON.stringify(wheelURL)})
import pyrxd
`);
  } catch (err) {
    showError(`Could not install pyrxd from ${manifest.wheel}: ${err.message}`);
    return;
  }

  setProgress(85);

  // Read the installed pyrxd version back through the bridge.
  let versionText;
  try {
    const py = pyodide.runPython(`
import pyrxd
import sys
v = getattr(pyrxd, "__version__", "unknown")
f"pyrxd {v} loaded under Python {sys.version.split()[0]}"
`);
    versionText = String(py);
  } catch (err) {
    showError(`Could not read pyrxd.__version__: ${err.message}`);
    return;
  }

  // Load the Pyodide-side glue and grab a reference to its `run` function.
  // We fetch the source text and execute it under a synthetic module name
  // so any future `from pyrxd_inspect_glue import ...` would also resolve.
  try {
    const glueSrc = await fetchGlueSource();
    pyodide.FS.writeFile("/home/pyodide/glue.py", glueSrc);
    pyodide.runPython(`
import sys
sys.path.insert(0, "/home/pyodide")
import glue as _pyrxd_glue
`);
    pyGlue = pyodide.globals.get("_pyrxd_glue").run;
  } catch (err) {
    showError(`Could not load inspect glue: ${err.message}`);
    return;
  }

  setProgress(100);
  showReady(versionText, manifest.git_sha);
  enableForm();
  hydrateFromUrl();
}

// ---------------------------------------------------------------------
// Form enable/disable + event wiring
// ---------------------------------------------------------------------

function enableForm() {
  if (!INPUT_BOX) return;
  INPUT_BOX.disabled = false;
  CLASSIFY_BTN.disabled = false;
  CLEAR_BTN.disabled = false;
  SHARE_BTN.disabled = false;
  INPUT_BOX.focus();

  CLASSIFY_BTN.addEventListener("click", onClassify);
  CLEAR_BTN.addEventListener("click", onClear);
  SHARE_BTN.addEventListener("click", onShare);

  // Enter (without shift) submits.
  INPUT_BOX.addEventListener("keydown", (ev) => {
    if (ev.key === "Enter" && !ev.shiftKey) {
      ev.preventDefault();
      onClassify();
    }
  });

  // Example chips populate the box and immediately classify.
  EXAMPLE_CHIPS.forEach((chip) => {
    chip.addEventListener("click", () => {
      const value = chip.getAttribute("data-input") || "";
      INPUT_BOX.value = value;
      onClassify();
    });
  });
}

// ---------------------------------------------------------------------
// Classify / clear / share
// ---------------------------------------------------------------------

function onClassify() {
  if (!pyGlue) return;
  const text = (INPUT_BOX.value || "").trim();
  if (!text) {
    renderEmpty();
    return;
  }

  let result;
  try {
    // glue.run returns a Python dict; .toJs converts to a plain JS object
    // (dict_converter=Object.fromEntries collapses dict→Object instead of
    // the default Map, which is more ergonomic for property access).
    const pyResult = pyGlue(text);
    result = pyResult.toJs({ dict_converter: Object.fromEntries });
    pyResult.destroy();
  } catch (err) {
    // The Python side promises not to raise (every error becomes a
    // structured dict). If we still landed here, something escaped the
    // bridge — surface it visibly rather than silently failing.
    renderResult({
      ok: false,
      form: "error",
      error: `bridge error: ${err.message || err}`,
      hint: "",
    });
    return;
  }

  renderResult(result);
  updateUrlForInput(text);
}

function onClear() {
  INPUT_BOX.value = "";
  RESULT_BLOCK.hidden = true;
  RESULT_BLOCK.replaceChildren();
  if (ONBOARDING) ONBOARDING.hidden = false;
  // Drop ?input= from the URL but leave anything else (e.g. ?view=).
  const url = new URL(window.location.href);
  url.searchParams.delete("input");
  window.history.replaceState({}, "", url.toString());
  INPUT_BOX.focus();
}

function onShare() {
  // Copy the current URL (including ?input=) to the clipboard. Quiet
  // failure: clipboard APIs are best-effort and may be denied; the URL
  // is still in the address bar either way.
  const url = window.location.href;
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(url).then(
      () => flashShareConfirmation("Link copied"),
      () => flashShareConfirmation("Copy denied — URL is in the address bar")
    );
  } else {
    flashShareConfirmation("URL is in the address bar");
  }
}

function flashShareConfirmation(msg) {
  const original = SHARE_BTN.textContent;
  SHARE_BTN.textContent = msg;
  setTimeout(() => {
    SHARE_BTN.textContent = original;
  }, 1500);
}

function updateUrlForInput(text) {
  const url = new URL(window.location.href);
  url.searchParams.set("input", text);
  window.history.replaceState({}, "", url.toString());
}

function hydrateFromUrl() {
  const params = new URLSearchParams(window.location.search);
  const initial = params.get("input");
  if (initial && INPUT_BOX) {
    INPUT_BOX.value = initial;
    onClassify();
  }
}

// ---------------------------------------------------------------------
// Rendering — every DOM write is via textContent / createElement.
// No innerHTML anywhere. Type-specific renderers receive an already-
// sanitized payload (Python side stripped control / format / combining
// codepoints from every string) and produce a card.
// ---------------------------------------------------------------------

function renderEmpty() {
  RESULT_BLOCK.hidden = true;
  RESULT_BLOCK.replaceChildren();
  if (ONBOARDING) ONBOARDING.hidden = false;
}

function renderResult(result) {
  if (ONBOARDING) ONBOARDING.hidden = true;
  RESULT_BLOCK.hidden = false;
  RESULT_BLOCK.replaceChildren();

  if (!result || !result.ok) {
    RESULT_BLOCK.appendChild(renderErrorCard(result || {}));
    return;
  }

  const form = result.form;
  const payload = result.payload || {};

  let card;
  if (form === "txid") {
    card = renderTxidCard(payload);
  } else if (form === "contract") {
    card = renderContractCard(payload);
  } else if (form === "outpoint") {
    card = renderOutpointCard(payload);
  } else if (form === "script") {
    card = renderScriptCard(payload);
  } else {
    card = renderErrorCard({
      error: `Unknown form: ${form}`,
      hint: "",
    });
  }

  RESULT_BLOCK.appendChild(card);
  RESULT_BLOCK.appendChild(renderJsonDrawer(result));
}

// --- helpers shared by all renderers ---------------------------------

function el(tag, opts) {
  const node = document.createElement(tag);
  if (!opts) return node;
  if (opts.class) node.className = opts.class;
  if (opts.text !== undefined) node.textContent = String(opts.text);
  return node;
}

function kv(label, value, valueClass) {
  const row = el("div", { class: "kv-row" });
  row.appendChild(el("dt", { class: "kv-label", text: label }));
  const dd = el("dd", { class: valueClass ? `kv-value ${valueClass}` : "kv-value" });
  dd.textContent = value === null || value === undefined ? "—" : String(value);
  row.appendChild(dd);
  return row;
}

function badge(label, kind) {
  // Type badge (FT, NFT, MUT, DMINT, COMMIT, P2PKH, UNKNOWN). The CSS
  // class controls colour from the Okabe-Ito palette.
  const safeKind = String(kind || "unknown").toLowerCase().replace(/[^a-z0-9-]/g, "");
  const span = el("span", { class: `badge badge-${safeKind}`, text: label });
  return span;
}

function card(titleText, kind) {
  const wrapper = el("section", { class: "result-card" });
  const header = el("header", { class: "result-card-header" });
  header.appendChild(el("h2", { class: "result-card-title", text: titleText }));
  if (kind) header.appendChild(badge(kind.toUpperCase(), kind));
  wrapper.appendChild(header);
  return wrapper;
}

// --- per-form renderers ----------------------------------------------

function renderTxidCard(payload) {
  const wrapper = card("Transaction id", "txid");
  const dl = el("dl", { class: "kv-list" });
  dl.appendChild(kv("txid", payload.txid));
  dl.appendChild(kv("status", payload.needs_fetch ? "needs --fetch" : "ready"));
  wrapper.appendChild(dl);
  if (payload.message) {
    const note = el("p", { class: "card-note", text: payload.message });
    wrapper.appendChild(note);
  }
  return wrapper;
}

function renderContractCard(payload) {
  const wrapper = card("Glyph contract id", "contract");
  const dl = el("dl", { class: "kv-list" });
  dl.appendChild(kv("txid (display order)", payload.txid));
  dl.appendChild(kv("vout", payload.vout));
  if (payload.outpoint) {
    dl.appendChild(kv("outpoint", payload.outpoint));
  }
  if (payload.wire_hex) {
    dl.appendChild(kv("wire (36 bytes)", payload.wire_hex));
  }
  wrapper.appendChild(dl);
  wrapper.appendChild(el("p", {
    class: "card-note",
    text: "Contract ids identify a Glyph token by its mint outpoint. " +
          "The 32-byte txid is in display (big-endian) order; the 4-byte vout " +
          "is big-endian. Use the outpoint to look up the mint transaction.",
  }));
  return wrapper;
}

function renderOutpointCard(payload) {
  const wrapper = card("Outpoint", "outpoint");
  const dl = el("dl", { class: "kv-list" });
  dl.appendChild(kv("txid", payload.txid));
  dl.appendChild(kv("vout", payload.vout));
  if (payload.outpoint) dl.appendChild(kv("display", payload.outpoint));
  if (payload.wire_hex) dl.appendChild(kv("wire (36 bytes)", payload.wire_hex));
  wrapper.appendChild(dl);
  return wrapper;
}

function renderScriptCard(payload) {
  const type = String(payload.type || "unknown").toLowerCase();
  const titleMap = {
    ft: "Fungible-token locking script",
    nft: "NFT singleton locking script",
    mut: "Mutable contract output",
    dmint: "dMint contract output",
    "commit-ft": "FT commit script",
    "commit-nft": "NFT commit script",
    p2pkh: "P2PKH locking script",
    unknown: "Unrecognised script",
  };
  const wrapper = card(titleMap[type] || "Locking script", scriptBadgeKind(type));

  const dl = el("dl", { class: "kv-list" });
  dl.appendChild(kv("type", type));
  if (payload.length !== undefined) {
    dl.appendChild(kv("length", `${payload.length} bytes`));
  }
  if (payload.owner_pkh) dl.appendChild(kv("owner pkh (20 hex)", payload.owner_pkh));
  if (payload.ref_txid) dl.appendChild(kv("ref txid", payload.ref_txid));
  if (payload.ref_vout !== undefined) dl.appendChild(kv("ref vout", payload.ref_vout));
  if (payload.ref_outpoint) dl.appendChild(kv("ref outpoint", payload.ref_outpoint));
  if (payload.payload_hash) dl.appendChild(kv("payload hash (sha256)", payload.payload_hash));

  // dMint-specific fields
  if (payload.version) dl.appendChild(kv("dmint version", payload.version));
  if (payload.contract_ref_outpoint) {
    dl.appendChild(kv("contract ref", payload.contract_ref_outpoint));
  }
  if (payload.token_ref_outpoint) {
    dl.appendChild(kv("token ref", payload.token_ref_outpoint));
  }
  if (payload.height !== undefined) dl.appendChild(kv("height", payload.height));
  if (payload.max_height !== undefined) dl.appendChild(kv("max height", payload.max_height));
  if (payload.reward !== undefined) dl.appendChild(kv("reward", payload.reward));
  if (payload.algo) dl.appendChild(kv("algo", payload.algo));
  if (payload.daa_mode) dl.appendChild(kv("daa mode", payload.daa_mode));

  wrapper.appendChild(dl);

  if (type === "unknown") {
    wrapper.appendChild(el("p", {
      class: "card-note",
      text: "This doesn't match any known Glyph or P2PKH script template. " +
            "It may be a custom contract, a different protocol, or malformed bytes.",
    }));
  }

  return wrapper;
}

// Map a script `type` value (which may include a hyphen, e.g. "commit-ft")
// to a CSS-safe badge kind. Hyphenated commit variants share the
// `commit` badge colour.
function scriptBadgeKind(type) {
  if (type.startsWith("commit")) return "commit";
  return type;
}

function renderErrorCard(payload) {
  const wrapper = el("section", { class: "result-card result-card-error" });
  const header = el("header", { class: "result-card-header" });
  header.appendChild(el("h2", { class: "result-card-title", text: "Could not classify" }));
  header.appendChild(badge("ERROR", "unknown"));
  wrapper.appendChild(header);

  wrapper.appendChild(el("p", {
    class: "error-message",
    text: payload.error || "(no error message)",
  }));

  if (payload.hint) {
    wrapper.appendChild(el("p", { class: "error-hint", text: payload.hint }));
  }

  return wrapper;
}

// --- JSON drawer -----------------------------------------------------

function renderJsonDrawer(result) {
  const details = el("details", { class: "json-drawer" });
  details.appendChild(el("summary", { text: "Show raw JSON" }));

  const pre = el("pre", { class: "json-block" });
  pre.textContent = JSON.stringify(result, null, 2);
  details.appendChild(pre);

  const copyBtn = el("button", { class: "copy-json-btn", text: "Copy JSON" });
  copyBtn.type = "button";
  copyBtn.addEventListener("click", () => {
    const text = pre.textContent || "";
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(
        () => {
          const orig = copyBtn.textContent;
          copyBtn.textContent = "Copied";
          setTimeout(() => { copyBtn.textContent = orig; }, 1200);
        },
        () => {
          copyBtn.textContent = "Copy denied";
        }
      );
    }
  });
  details.appendChild(copyBtn);
  return details;
}

// ---------------------------------------------------------------------
// Kick off
// ---------------------------------------------------------------------

boot();
