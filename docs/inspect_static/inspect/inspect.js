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

// Module-scope handles to the Python entry points once boot completes.
// Keeping these on the module rather than `window` avoids polluting the
// global namespace and keeps the surface explicit.
let pyGlue = null;          // glue.run(text) -> dict
let pyGlueFetch = null;     // glue.inspect_txid_with_raw(txid, raw_hex) -> dict

// ElectrumX WebSocket endpoint. Hard-coded to the one URL the page's
// CSP whitelists in ``connect-src``. Changing this also requires
// updating the CSP meta-tag in index.html.
const ELECTRUMX_WSS_URL = "wss://electrumx.radiant4people.com:50022";

// Hard cap on a fetched transaction's hex length. Mirrors the cap
// glue.py applies on the Python side (8 MB hex = 4 MB binary, the
// Radiant policy maximum). Clipping in JS too means a hostile server
// can't make us spend memory holding a multi-gigabyte response while
// the Python guard rejects it.
const MAX_FETCHED_TX_HEX_LEN = 8_000_000;

// Per-fetch timeout. Real ElectrumX servers respond in <1s; 10 seconds
// is generous and bounds the worst case where the connection succeeds
// but the server hangs without responding.
const FETCH_TIMEOUT_MS = 10_000;

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

// Validate a filename field from manifest.json is a bare basename
// — not an absolute URL, not a path traversal, not a scheme. Defends
// against an attacker-poisoned manifest redirecting wheel installs
// to a CSP-allowed origin (e.g. PyPI hosts) where they've staged a
// hostile wheel. Audit finding HIGH-1.
function _assertSafeBasename(value, fieldName) {
  if (typeof value !== "string" || !value) {
    throw new Error(`manifest.${fieldName} missing or empty`);
  }
  // Reject any character that could change URL resolution: ``/`` and
  // ``\\`` for path traversal, ``:`` to defeat scheme prefixes (e.g.
  // ``data:``, ``https:``), ``?`` and ``#`` for query / fragment
  // tricks. Allowed alphabet matches the wheel-filename convention
  // (``pyrxd-0.3.0-py3-none-any.whl``: alphanumerics, ``.``, ``-``,
  // ``_``).
  if (!/^[A-Za-z0-9._-]+$/.test(value)) {
    throw new Error(
      `manifest.${fieldName}=${JSON.stringify(value)} is not a bare ` +
      `filename (allowed: alphanumerics, '.', '-', '_'). This is a ` +
      `defence against a poisoned manifest redirecting installs ` +
      `off-origin.`
    );
  }
}

// Validate a SHA-256 field from manifest.json is exactly 64 lowercase
// hex characters. Anything else is a deploy bug — better to fail loud
// than silently accept and skip the verify step downstream.
function _assertHexSha256(value, fieldName) {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) {
    throw new Error(
      `manifest.${fieldName} must be 64 lowercase hex chars (SHA-256), ` +
      `got ${JSON.stringify(value)}`
    );
  }
}

async function loadManifest() {
  setProgress(5);
  let manifest;
  try {
    const resp = await fetch(WHEELS_MANIFEST, { cache: "no-cache" });
    if (!resp.ok) {
      throw new Error(`manifest HTTP ${resp.status}`);
    }
    manifest = await resp.json();
  } catch (err) {
    throw new Error(
      `Could not load wheel manifest from ${WHEELS_MANIFEST}: ${err.message}. ` +
      `This usually means the docs CI step that builds the wheel failed.`
    );
  }
  // Validate the manifest fields the boot path will trust. If the
  // deploy ever produces a malformed or hostile manifest, fail closed
  // here rather than at the Python install step (where the failure
  // mode is harder to diagnose).
  _assertSafeBasename(manifest.wheel, "wheel");
  _assertHexSha256(manifest.wheel_sha256, "wheel_sha256");
  _assertSafeBasename(manifest.cbor2_wheel, "cbor2_wheel");
  _assertHexSha256(manifest.cbor2_sha256, "cbor2_sha256");
  _assertHexSha256(manifest.glue_sha256, "glue_sha256");
  return manifest;
}

// Fetch a same-origin URL, verify its SHA-256 against the expected
// hex digest, return the bytes. The hash is the trust boundary —
// even if the GitHub Pages deploy is compromised, a mismatch fails
// closed before any wheel byte reaches the Pyodide interpreter.
async function fetchAndVerify(url, expectedSha256, label) {
  const resp = await fetch(url, { cache: "no-cache" });
  if (!resp.ok) {
    throw new Error(`${label} HTTP ${resp.status}`);
  }
  const buffer = await resp.arrayBuffer();
  const hashBuffer = await crypto.subtle.digest("SHA-256", buffer);
  // Convert to lowercase hex.
  const hashArr = new Uint8Array(hashBuffer);
  let hashHex = "";
  for (const b of hashArr) {
    hashHex += b.toString(16).padStart(2, "0");
  }
  if (hashHex !== expectedSha256) {
    throw new Error(
      `${label} SHA-256 mismatch — expected ${expectedSha256}, ` +
      `got ${hashHex}. The deployed bytes don't match the manifest. ` +
      `This is the integrity check refusing to proceed; do NOT ` +
      `install the wheel by other means.`
    );
  }
  return buffer;
}

async function fetchGlueSource(expectedSha256) {
  const buffer = await fetchAndVerify(GLUE_URL, expectedSha256, "glue.py");
  return new TextDecoder("utf-8").decode(buffer);
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
    // Load Pyodide-bundled support packages first.
    //   - ``micropip`` — for installing the vendored wheels from FS.
    //   - ``pycryptodome`` — pyrxd imports ``Cryptodome.Cipher.AES`` in
    //     the encrypted-wallet path. The inspect tool doesn't actually
    //     reach that path, but the lazy ``__getattr__``s in pyrxd's
    //     package ``__init__``s might if a downstream caller touches
    //     it. Cheap to load preemptively (the glue.py shim aliases
    //     ``Cryptodome`` → ``Crypto`` so the import resolves).
    await pyodide.loadPackage(["micropip", "pycryptodome"]);

    // Both wheels are vendored same-origin (under /inspect/wheels/)
    // and SHA-256 pinned in manifest.json. Fetch each, verify the
    // hash with crypto.subtle.digest, write the bytes to Pyodide FS,
    // and install from there. This:
    //   - Closes the supply-chain gap from PyPI fetches (audit
    //     finding HIGH-1, MEDIUM-2, MEDIUM-3): no off-origin install
    //     paths remain, and CSP can drop ``pypi.org`` /
    //     ``files.pythonhosted.org``.
    //   - Defends against a poisoned manifest redirecting wheel
    //     installs to attacker-staged URLs: ``loadManifest`` already
    //     validates ``wheel`` / ``cbor2_wheel`` are bare basenames.
    //   - Defends against a compromised GitHub Pages deploy: even
    //     same-origin bytes are SHA-checked before micropip sees them.
    //
    // We use ``deps=False`` for the pyrxd wheel because its METADATA
    // declares five runtime deps (aiohttp, coincurve, base58,
    // pycryptodomex, websockets) for the full SDK surface; most have
    // no pure-Python wheels. The inspect tool needs none of them —
    // see ``tests/web/test_inspect_imports_pyodide_clean.py``.
    const cbor2URL = new URL(manifest.cbor2_wheel, WHEELS_BASE).toString();
    const cbor2Bytes = await fetchAndVerify(cbor2URL, manifest.cbor2_sha256, "cbor2 wheel");
    pyodide.FS.writeFile("/tmp/" + manifest.cbor2_wheel, new Uint8Array(cbor2Bytes));

    const pyrxdURL = new URL(manifest.wheel, WHEELS_BASE).toString();
    const pyrxdBytes = await fetchAndVerify(pyrxdURL, manifest.wheel_sha256, "pyrxd wheel");
    pyodide.FS.writeFile("/tmp/" + manifest.wheel, new Uint8Array(pyrxdBytes));

    await pyodide.runPythonAsync(`
import micropip
await micropip.install("emfs:/tmp/${manifest.cbor2_wheel}")
await micropip.install("emfs:/tmp/${manifest.wheel}", deps=False)
`);
  } catch (err) {
    showError(`Could not install pyrxd: ${err.message}`);
    return;
  }

  setProgress(85);

  // Load the Pyodide-side glue. The glue module installs the
  // Cryptodome→Crypto shim at import time and then imports pyrxd, so
  // pyrxd's import chain (which references Cryptodome.Cipher.AES via
  // aes_cbc) resolves cleanly. Both entry points come back as PyProxy
  // references stashed on the JS module.
  let versionText;
  try {
    const glueSrc = await fetchGlueSource(manifest.glue_sha256);
    pyodide.FS.writeFile("/home/pyodide/glue.py", glueSrc);
    pyodide.runPython(`
import sys
sys.path.insert(0, "/home/pyodide")
import glue as _pyrxd_glue
import pyrxd
_pyrxd_version_blob = (
    f"pyrxd {getattr(pyrxd, '__version__', 'unknown')} "
    f"loaded under Python {sys.version.split()[0]}"
)
`);
    pyGlue = pyodide.globals.get("_pyrxd_glue").run;
    pyGlueFetch = pyodide.globals.get("_pyrxd_glue").inspect_txid_with_raw;
    versionText = String(pyodide.globals.get("_pyrxd_version_blob"));
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
    // Fetched-tx payloads carry byte_length / output_count / etc.;
    // pre-fetch placeholder payloads carry needs_fetch=true. Pick the
    // richer card when the data's there.
    card = (payload && payload.byte_length !== undefined)
      ? renderFetchedTxCard(payload)
      : renderTxidCard(payload);
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

// Render a kv pair where the value carries a per-field warning (e.g.
// "mixed scripts (possible homoglyph)"). The value text remains
// unmodified — sanitisation already happened on the Python side and
// truncation on the recursive walker — but we attach a visible warning
// label and a CSS class so the user can't miss the suspicion.
function kvWithWarning(label, value, warningText) {
  const row = el("div", { class: "kv-row" });
  row.appendChild(el("dt", { class: "kv-label", text: label }));
  const dd = el("dd", { class: warningText ? "kv-value kv-warning" : "kv-value" });
  dd.textContent = value === null || value === undefined ? "—" : String(value);
  if (warningText) {
    const warning = el("div", { class: "kv-warning-note" });
    warning.textContent = `⚠ ${warningText}`;
    dd.appendChild(warning);
  }
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
  dl.appendChild(kv("status", payload.needs_fetch ? "ready to fetch" : "loaded"));
  wrapper.appendChild(dl);
  if (payload.message) {
    const note = el("p", { class: "card-note", text: payload.message });
    wrapper.appendChild(note);
  }

  if (payload.needs_fetch) {
    const actionRow = el("div", { class: "fetch-row" });
    const fetchBtn = el("button", {
      class: "fetch-btn",
      text: "Fetch from network",
    });
    fetchBtn.type = "button";
    const status = el("span", { class: "fetch-status" });
    actionRow.appendChild(fetchBtn);
    actionRow.appendChild(status);
    wrapper.appendChild(actionRow);

    fetchBtn.addEventListener("click", () => onFetchTxid(payload.txid, fetchBtn, status));
  }

  return wrapper;
}

function renderFetchedTxCard(payload) {
  const wrapper = card("Fetched transaction", "txid");
  const dl = el("dl", { class: "kv-list" });
  dl.appendChild(kv("txid", payload.txid));
  dl.appendChild(kv("size", `${payload.byte_length} bytes`));
  dl.appendChild(kv("inputs", payload.input_count));
  dl.appendChild(kv("outputs", payload.output_count));
  wrapper.appendChild(dl);

  // Per-output rows.
  const outputs = payload.outputs || [];
  if (outputs.length > 0) {
    wrapper.appendChild(el("h3", { class: "result-subhead", text: "Outputs" }));
    const outList = el("div", { class: "output-rows" });
    for (const row of outputs) {
      outList.appendChild(renderOutputRow(row));
    }
    wrapper.appendChild(outList);
  }

  // Reveal metadata (if present).
  const metadata = payload.metadata;
  if (metadata) {
    wrapper.appendChild(el("h3", { class: "result-subhead", text: "Reveal metadata" }));
    const mdl = el("dl", { class: "kv-list" });
    const warnings = (metadata && metadata.display_warnings) || {};
    mdl.appendChild(kv("input index", metadata.input_index));
    if (Array.isArray(metadata.protocol) && metadata.protocol.length > 0) {
      mdl.appendChild(kvWithWarning("protocol", metadata.protocol.join(", "), warnings.protocol));
    }
    if (metadata.name) mdl.appendChild(kvWithWarning("name", metadata.name, warnings.name));
    if (metadata.ticker) mdl.appendChild(kvWithWarning("ticker", metadata.ticker, warnings.ticker));
    if (metadata.description) mdl.appendChild(kvWithWarning("description", metadata.description, warnings.description));
    if (metadata.decimals !== undefined && metadata.decimals !== null) {
      mdl.appendChild(kv("decimals", metadata.decimals));
    }
    if (metadata.main) mdl.appendChild(kv("main", metadata.main));
    wrapper.appendChild(mdl);

    // Top-level warning banner if any field tripped a homoglyph flag.
    // The Python side sets metadata.display_warnings as a {field: reason}
    // dict; we surface it visibly so a user reading "USDC" can tell at a
    // glance whether the string is what it looks like. Two reason
    // shapes today: "mixed scripts" (per-character substitution like
    // Latin "USDC" with Cyrillic "С") and "non-Latin script"
    // (whole-word substitution like Cyrillic "ВТС" mimicking Latin
    // "BTC"). Both warrant a banner; the body text covers both shapes.
    if (Object.keys(warnings).length > 0) {
      const banner = el("p", { class: "warning-banner" });
      banner.textContent =
        "⚠ This token's metadata contains characters that visually mimic " +
        "Latin letters. Treat the displayed name, ticker, description, " +
        "and protocol fields with care — they may use letters from a " +
        "different alphabet (e.g. Cyrillic 'а' looks identical to Latin " +
        "'a'). The only reliable identifier for this token is the txid " +
        "above; verify by txid, not by visual name.";
      wrapper.appendChild(banner);
    }
  }

  return wrapper;
}

function renderOutputRow(row) {
  const type = String(row.type || "unknown").toLowerCase();
  const wrapper = el("section", { class: "output-row" });
  const head = el("header", { class: "output-row-head" });
  head.appendChild(el("span", { class: "output-vout", text: `vout ${row.vout}` }));
  head.appendChild(badge(type.toUpperCase(), scriptBadgeKind(type)));
  head.appendChild(el("span", { class: "output-sats", text: `${row.satoshis} sats` }));
  wrapper.appendChild(head);

  const dl = el("dl", { class: "kv-list" });
  if (row.owner_pkh) dl.appendChild(kv("owner pkh", row.owner_pkh));
  if (row.ref_outpoint) dl.appendChild(kv("ref", row.ref_outpoint));
  if (row.payload_hash) dl.appendChild(kv("payload hash", row.payload_hash));
  if (row.contract_ref_outpoint) dl.appendChild(kv("contract ref", row.contract_ref_outpoint));
  if (row.token_ref_outpoint) dl.appendChild(kv("token ref", row.token_ref_outpoint));
  if (row.height !== undefined) dl.appendChild(kv("height", row.height));
  if (row.max_height !== undefined) dl.appendChild(kv("max height", row.max_height));
  if (row.reward !== undefined) dl.appendChild(kv("reward", row.reward));
  if (row.algo) dl.appendChild(kv("algo", row.algo));
  if (row.daa_mode) dl.appendChild(kv("daa mode", row.daa_mode));
  if (row.version) dl.appendChild(kv("version", row.version));
  if (type === "error") {
    dl.appendChild(kv("error", row.error || "(unknown)"));
  }
  wrapper.appendChild(dl);
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
// WebSocket fetch — pulls raw bytes for a txid from the configured
// ElectrumX server. Returns a Promise<string> of the hex-encoded raw
// transaction or rejects with an Error on any failure mode.
//
// Wire protocol: ElectrumX uses JSON-RPC 2.0 over WebSocket with
// newline-delimited frames. We send one request, await the matching
// response by id, and close. No long-lived connection — this is a
// "fetch and forget" pattern, simpler than maintaining the kind of
// reader loop the Python ElectrumXClient uses.
// ---------------------------------------------------------------------

function fetchRawTxFromElectrumx(txid) {
  return new Promise((resolve, reject) => {
    let ws;
    try {
      ws = new WebSocket(ELECTRUMX_WSS_URL);
    } catch (err) {
      reject(new Error(`could not open WebSocket: ${err.message || err}`));
      return;
    }

    let settled = false;
    let timer = null;
    const settle = (fn, value) => {
      if (settled) return;
      settled = true;
      if (timer !== null) clearTimeout(timer);
      try { ws.close(); } catch { /* already closed */ }
      fn(value);
    };

    timer = setTimeout(() => {
      settle(reject, new Error(`timed out after ${FETCH_TIMEOUT_MS}ms`));
    }, FETCH_TIMEOUT_MS);

    ws.addEventListener("open", () => {
      const req = JSON.stringify({
        id: 1,
        method: "blockchain.transaction.get",
        params: [txid, false],
      });
      // ElectrumX expects newline-terminated frames.
      ws.send(req + "\n");
    });

    ws.addEventListener("message", (ev) => {
      // Cap raw frame size BEFORE JSON.parse so a hostile server
      // can't make us allocate a multi-GB string in the parser. The
      // hex cap below is a downstream sanity check on the parsed
      // result; this one is the actual memory guard.
      const data = typeof ev.data === "string" ? ev.data : "";
      if (data.length > MAX_FETCHED_TX_HEX_LEN + 4096) {
        settle(reject, new Error(
          `frame is ${data.length.toLocaleString()} chars; over the hex cap`
        ));
        return;
      }

      // NOTE: do not clearTimeout here. Mismatched-id frames are
      // silently discarded (see below), so we must keep the timer
      // armed until we actually settle. settle() clears the timer.
      let frame;
      try {
        frame = JSON.parse(data);
      } catch (err) {
        settle(reject, new Error(`server returned non-JSON: ${err.message}`));
        return;
      }
      if (frame.id !== 1) {
        // Unexpected id — discard and keep waiting (cheap defence
        // against a server that buffers other clients' responses).
        // The 10s timer keeps running, so an attacker drip-feeding
        // mismatched-id frames cannot hold the connection forever.
        return;
      }
      if (frame.error) {
        const rawMsg = (frame.error && frame.error.message) || JSON.stringify(frame.error);
        settle(reject, new Error(`server error: ${stripControlChars(rawMsg)}`));
        return;
      }
      const result = frame.result;
      if (typeof result !== "string") {
        settle(reject, new Error("server returned non-string result"));
        return;
      }
      if (result.length > MAX_FETCHED_TX_HEX_LEN) {
        settle(reject, new Error(
          `response is ${result.length.toLocaleString()} chars; cap is ` +
          `${MAX_FETCHED_TX_HEX_LEN.toLocaleString()}`
        ));
        return;
      }
      // Light hex sanity check — Python side does the real validation.
      if (!/^[0-9a-fA-F]*$/.test(result)) {
        settle(reject, new Error("server returned a non-hex string"));
        return;
      }
      settle(resolve, result);
    });

    ws.addEventListener("error", () => {
      settle(reject, new Error("WebSocket error connecting to ElectrumX"));
    });

    ws.addEventListener("close", () => {
      settle(reject, new Error("WebSocket closed before any response"));
    });
  });
}

// Strip control / format codepoints from server-supplied strings
// before they reach the DOM. textContent makes XSS impossible, but
// a hostile ElectrumX server could still embed bidi overrides or
// zero-width characters into an error message that would render
// visually misleading text inside the error card. Mirrors the
// Python side's _sanitize_display_string for messages that don't
// cross the bridge.
function stripControlChars(s) {
  if (typeof s !== "string") return String(s);
  // \p{C} = control + format + surrogate + private + unassigned.
  // \p{M} = combining marks. Both trimmed for parity with the
  // Python side's category list.
  return s.replace(/[\p{C}\p{M}]/gu, "?");
}

async function onFetchTxid(txid, fetchBtn, statusEl) {
  if (!pyGlueFetch) {
    statusEl.textContent = "(glue not ready)";
    return;
  }
  fetchBtn.disabled = true;
  statusEl.textContent = "fetching…";

  let rawHex;
  try {
    rawHex = await fetchRawTxFromElectrumx(txid);
  } catch (err) {
    fetchBtn.disabled = false;
    statusEl.textContent = "";
    renderResult({
      ok: false,
      form: "error",
      error: `fetch failed: ${err.message || err}`,
      hint:
        "Try again, check that wss://electrumx.radiant4people.com:50022 is " +
        "reachable, or use the CLI: pyrxd glyph inspect <txid> --fetch",
    });
    return;
  }

  statusEl.textContent = "classifying…";

  let result;
  try {
    const pyResult = pyGlueFetch(txid, rawHex);
    result = pyResult.toJs({ dict_converter: Object.fromEntries });
    pyResult.destroy();
  } catch (err) {
    fetchBtn.disabled = false;
    statusEl.textContent = "";
    renderResult({
      ok: false,
      form: "error",
      error: `bridge error: ${err.message || err}`,
      hint: "",
    });
    return;
  }

  renderResult(result);
}

// ---------------------------------------------------------------------
// Kick off
// ---------------------------------------------------------------------

boot();
