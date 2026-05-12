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
// hostile wheel.
//
// LOAD-BEARING INVARIANT: this function's regex is also the only
// guard between manifest.{wheel,cbor2_wheel} and:
//   - ``new URL(value, WHEELS_BASE)``  — absolute-URL escape
//   - ``"/tmp/" + value``              — Pyodide FS path-traversal escape
//   - ``"emfs:/tmp/" + value``         — Python-string interpolation
//     into ``runPythonAsync(`...`)``
// If the alphabet is ever widened to include ``/`` ``\`` ``:`` ``"`` ``\``
// ``$``, EACH of those sinks becomes a vulnerability simultaneously.
// Audit findings HIGH-1, NEW-1, NEW-2, NEW-5.
function _assertSafeBasename(value, fieldName) {
  if (typeof value !== "string" || !value) {
    throw new Error(`manifest.${fieldName} missing or empty`);
  }
  // Reject any character that could change URL resolution or escape
  // a string-concatenated path: ``/`` and ``\\`` for path traversal,
  // ``:`` to defeat scheme prefixes (``data:``, ``https:``), ``?``
  // and ``#`` for query / fragment tricks, ``"`` and ``\\`` to escape
  // Python-string interpolation. Allowed alphabet matches the
  // wheel-filename convention: ``pyrxd-0.3.0-py3-none-any.whl``.
  if (!/^[A-Za-z0-9._-]+$/.test(value)) {
    throw new Error(
      `manifest.${fieldName}=${JSON.stringify(value)} is not a bare ` +
      `filename (allowed: alphanumerics, '.', '-', '_'). This is a ` +
      `defence against a poisoned manifest redirecting installs ` +
      `off-origin.`
    );
  }
  // Explicit reject of dot-only names: ``.`` resolves to the current
  // directory under ``new URL`` and ``..`` to the parent. Fail-closed
  // here rather than relying on the downstream SHA-256 check to catch
  // a directory-listing fetch — defence in depth, audit finding NEW-1.
  if (/^\.+$/.test(value)) {
    throw new Error(
      `manifest.${fieldName}=${JSON.stringify(value)} is a dot-only ` +
      `path; rejecting to prevent directory traversal.`
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
    // Re-assert the basename invariant at the install site. ``loadManifest``
    // already validates these, but the FS path concat (``/tmp/${name}``)
    // and Python-string interpolation (``emfs:/tmp/${name}``) below are
    // load-bearing on the regex's alphabet — explicit defence in depth
    // against a future refactor that bypasses ``loadManifest``.
    _assertSafeBasename(manifest.cbor2_wheel, "cbor2_wheel");
    _assertSafeBasename(manifest.wheel, "wheel");

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

  // Tx-shape note. A user pasting an FT contract id (the canonical
  // identifier they'd see in a block explorer or wallet) often
  // expects to see "their transfer" but actually fetches the FT's
  // *deploy* tx — which has a distinctive shape (commit-ft + N
  // p2pkh + commit-nft + change). Recognising that shape and
  // surfacing what it is heads off the "wait, why did I mint an
  // NFT?" confusion. Same logic applies to NFT singletons,
  // mutable contracts, and dmint deploys.
  const shapeNote = _detectTxShape(payload);
  if (shapeNote) {
    wrapper.appendChild(el("p", { class: "tx-shape-note", text: shapeNote }));
  }

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

  // dMint mint-claim scriptSig (if present at vin[0]). Surfaces the four
  // canonical pushes — nonce, inputHash, outputHash, OP_0 sentinel —
  // and the V1/V2 hint that falls out of the nonce push width.
  const mintScriptsig = payload.mint_scriptsig;
  if (mintScriptsig) {
    wrapper.appendChild(el("h3", { class: "result-subhead", text: "dMint mint scriptSig (vin 0)" }));
    const mdl = el("dl", { class: "kv-list" });
    mdl.appendChild(kv("version (by nonce width)", mintScriptsig.version_hint || "?"));
    mdl.appendChild(kv("scriptSig length", `${mintScriptsig.scriptsig_length} bytes`));
    mdl.appendChild(kv("nonce (LE)", mintScriptsig.nonce_hex));
    mdl.appendChild(kv("input hash (SHA256d funding script)", mintScriptsig.input_hash));
    mdl.appendChild(kv("output hash (SHA256d OP_RETURN script)", mintScriptsig.output_hash));
    wrapper.appendChild(mdl);
    wrapper.appendChild(el("p", {
      class: "card-note",
      text: "The mint scriptSig pushes four items: the PoW nonce, the literal " +
            "SHA256d of the funding-input locking script, the literal SHA256d " +
            "of the OP_RETURN message script (at vout[2] in the canonical V1 " +
            "mint shape), and an OP_0 sentinel. The covenant recomputes " +
            "SHA256(inputHash || outputHash) from these literal pushes — they " +
            "are not preimage halves. V1 uses a 4-byte nonce (72-byte " +
            "scriptSig); V2 uses 8 bytes (76 bytes). V1 is verified on " +
            "Radiant mainnet against two pinned golden vectors (the public " +
            "snk-token mint 146a4d68…f3c and pyrxd's first successful mint " +
            "c9fdcd34…e530 of the PXD token, 2026-05-11); no V2 contract " +
            "has been observed on chain yet, so the V2 decode here is " +
            "structurally correct by construction but not field-verified.",
    }));
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
  if (row.data_hex !== undefined) {
    // OP_RETURN data — show truncated for long blobs to keep the
    // row scannable; the JSON drawer carries the full bytes.
    const data = row.data_hex || "(empty)";
    const truncated = data.length > 64 ? data.slice(0, 64) + "…" : data;
    dl.appendChild(kv("data (hex)", truncated));
  }
  if (type === "error") {
    dl.appendChild(kv("error", row.error || "(unknown)"));
  }
  wrapper.appendChild(dl);

  // Structural-match qualifier — parity with the CLI human renderer
  // (issue #53 / PR #58). The script classifier matches by hex
  // pattern, not by cryptographic provenance — a custom locking
  // script whose bytes happen to fit one of these templates would
  // also classify as ft/nft/mut/dmint/commit. The qualifier nudges
  // the user to verify by ref / outpoint, not by the type badge
  // alone.
  const qualifier = _structuralQualifierNote(type);
  if (qualifier) {
    wrapper.appendChild(el("p", { class: "structural-note", text: qualifier }));
  }
  return wrapper;
}

// Recognise common Glyph transaction shapes by their output type
// distribution and produce a one-paragraph explanation. Returns ""
// for shapes we don't have a specific story for (e.g. arbitrary
// mixed transfers). The goal is to head off "wait, why is there an
// NFT in my transfer?"-style confusion when a user pastes an FT
// contract id and gets the deploy tx back.
function _detectTxShape(payload) {
  const outputs = payload.outputs || [];
  const counts = {};
  for (const o of outputs) {
    const t = String(o.type || "").toLowerCase();
    counts[t] = (counts[t] || 0) + 1;
  }
  const has = (t) => (counts[t] || 0) > 0;
  const dmintOutput = outputs.find((o) => String(o.type).toLowerCase() === "dmint");

  // Burn — the explicit Glyph protocol marker (GlyphProtocol.BURN = 6)
  // appearing in the reveal-metadata's protocol list. A burn tx
  // consumes an FT/NFT input and signals "this token / NFT is
  // permanently destroyed" via the reveal CBOR. The tx may have no
  // ref-bearing outputs at all, or may have ones marked as burn-tagged.
  // We rely on the explicit marker rather than absence-of-outputs
  // because plain RXD sends also lack ref outputs.
  const protocol = ((payload.metadata || {}).protocol || []).map(String);
  if (protocol.includes("6") || protocol.some((p) => p.endsWith("BURN"))) {
    return (
      "This is a Glyph burn transaction — the deployer/holder signalled " +
      "that an FT or NFT is permanently destroyed. Tokens consumed by " +
      "this transaction are removed from circulation; subsequent " +
      "transfers cannot reference the burned ref. The reveal metadata " +
      "carries the BURN protocol marker (= 6)."
    );
  }

  // V1 dMint deploy COMMIT: 1 commit-ft + 1 commit-nft + N ref-seed
  // P2PKHs (one per parallel contract) + 1 P2PKH change. The mainnet
  // Glyph Protocol deploy (a443d9df…878b) had 1+1+32+1 = 35 outputs;
  // the GLYPH reveal (b965b32d…9dd6) consumed every ref-seed to create
  // 32 parallel dMint contract UTXOs. Heuristic: commit-ft + commit-nft
  // + at least 3 P2PKHs (a plain Glyph FT deploy normally has at most
  // 1–2 P2PKH outputs — change + maybe one initial-holder). The N
  // ref-seeds are 1-photon outputs but we don't have satoshis info per
  // type, so use count as the discriminator. See
  // docs/dmint-research-photonic-deploy.md §2 for the byte-by-byte
  // chain truth.
  if (has("commit-ft") && has("commit-nft") && (counts["p2pkh"] || 0) >= 3) {
    const refSeeds = (counts["p2pkh"] || 0) - 1; // subtract the 1 change
    return (
      `This is a V1 dMint deploy commit — the first half of a two-step ` +
      `permissionless-token deployment. The commit-ft output is the ` +
      `FT-hashlock for the token's metadata reveal; commit-nft is the ` +
      `auth-NFT hashlock; the remaining ${refSeeds} P2PKH outputs are ` +
      `1-photon ref-seeds, one per parallel dMint contract. The deploy ` +
      `reveal that follows will spend all of these to create the same ` +
      `number of parallel V1 dMint contract UTXOs. See ` +
      `docs/dmint-research-photonic-deploy.md for the on-chain shape.`
    );
  }

  // Glyph FT deploy: 1 commit-ft + 1+ ft (or p2pkh holding refs) + 1
  // commit-nft + RXD change. The commit-nft is the protocol-level
  // singleton that every FT deploy carries — NOT a separately-
  // mintable collectible.
  if (has("commit-ft") && has("commit-nft")) {
    return (
      "This is a Glyph FT deploy transaction — the on-chain event " +
      "that creates a new fungible token. The commit-ft output " +
      "anchors the token's metadata (name, ticker, supply); the " +
      "commit-nft output is the protocol-level singleton that every " +
      "Glyph FT deploy carries (it's the metadata authority, not a " +
      "separately-mintable NFT). The remaining outputs are the " +
      "initial token holders + RXD change to the deployer. To inspect " +
      "your own transfer of this token, paste your transfer txid — " +
      "not the FT contract id."
    );
  }

  // Glyph FT deploy without paired NFT (older / unusual): commit-ft
  // alone.
  if (has("commit-ft") && !has("commit-nft")) {
    return (
      "This transaction contains a commit-ft output — the on-chain " +
      "anchor for a Glyph FT's metadata. Most modern FT deploys also " +
      "carry a commit-nft singleton; this one does not. The remaining " +
      "outputs are the initial token holders + change."
    );
  }

  // Glyph NFT deploy: commit-nft without commit-ft.
  if (!has("commit-ft") && has("commit-nft")) {
    return (
      "This transaction contains a commit-nft output — the on-chain " +
      "anchor for a Glyph NFT or mutable contract. Use the inspect " +
      "tool's outpoint form on the singleton's outpoint to walk the " +
      "ref chain."
    );
  }

  // dMint deploy vs claim. The contract's ``height`` field starts at
  // 0 in the deploy and advances by 1 on each successful mint claim,
  // so we can distinguish from the output alone — no need to walk
  // inputs. The contract_ref + token_ref point to the deploy outpoint
  // either way.
  if (dmintOutput) {
    const dmintCount = counts["dmint"] || 0;
    if (dmintOutput.height === 0 || dmintOutput.height === "0") {
      // V1 deploy reveal: typically ships N parallel contracts in one
      // tx (mainnet GLYPH had 32). One-contract deploys are also valid;
      // distinguish in the banner so callers don't confuse a multi-
      // contract V1 deploy with a V2 single-contract deploy.
      const parallel =
        dmintCount > 1
          ? `${dmintCount} parallel dMint contract UTXOs, all sharing the ` +
            `same token_ref. Each contract can be mined from independently, ` +
            `so claims race in parallel — total supply is reward × ` +
            `max_height × ${dmintCount}. `
          : `a single dMint contract UTXO. `;
      return (
        `This is a dMint deploy reveal — creates ${parallel}` +
        `Subsequent transactions can spend any of these to claim a mint, ` +
        `incrementing that contract's height by 1. Anyone can mint until ` +
        `the contract reaches max_height.`
      );
    }
    // Canonical mint-tx shape (V1 and V2 — byte-identical post-R1
    // fix, 2026-05-11): 4 outputs — [0] dMint continuation, [1] minted
    // FT reward (75-byte FT-wrapped locking script, NOT plain P2PKH:
    //   bytes 0-24  P2PKH prologue  76 a9 14 <pkh:20> 88 ac
    //   byte    25  OP_STATESEPARATOR (bd)
    //   byte    26  OP_PUSHINPUTREF  (d0)
    //   bytes 27-62 tokenRef (36 bytes)
    //   bytes 63-74 covenant fingerprint dec0e9aa76e378e4a269e69d
    // ), [2] OP_RETURN message (the script whose SHA256d is pushed as
    // outputHash), [3] P2PKH change. V2 originally shipped a 25-byte
    // plain-P2PKH reward — fixed pre-mainnet-V2-deploy so V1 and V2
    // are byte-identical at vout[1]. The mint scriptSig at vin[0] is
    // decoded separately under "dMint mint scriptSig (vin 0)" above;
    // the V1/V2 distinction is the nonce-push width there (4 vs 8 B),
    // not the output layout here.
    const versionHint = (payload.mint_scriptsig || {}).version_hint;
    const versionNote = versionHint
      ? ` Mint scriptSig at vin[0] is ${versionHint} shape (${versionHint === "v1" ? "4-byte nonce, 72 bytes" : "8-byte nonce, 76 bytes"}); the 4-output shape is identical across V1 and V2 by construction, but only V1 has been observed on Radiant mainnet (no V2 contract has been deployed yet).`
      : "";
    return (
      `This is a dMint claim transaction (height ${dmintOutput.height} ` +
      `of ${dmintOutput.max_height}) — somebody spent the contract's ` +
      "previous output to mint themselves a token, and the contract " +
      "continues at the new dmint output. The freshly-minted FT lives " +
      "in a separate ft output in this same tx; the canonical mint tx " +
      "has 4 outputs: [0] dMint continuation, [1] 75-byte FT-wrapped " +
      "reward, [2] OP_RETURN message, [3] P2PKH change. V1 is verified " +
      "on mainnet against pinned golden vectors; V2 is byte-identical " +
      "by construction (R1 fix) but untested on chain. Inspect the " +
      "contract's deploy outpoint to see the original parameters." +
      versionNote
    );
  }

  // Mutable-contract update.
  if (has("mut")) {
    return (
      "This transaction contains a mutable contract output — a Glyph " +
      "NFT whose metadata can be rotated by spending this output with " +
      "a 'mod' or 'sl' operation."
    );
  }

  // FT-only transfer (no commit, no dmint). Common case: a token send.
  if (has("ft") && !has("commit-ft") && !has("commit-nft")) {
    return ""; // ordinary transfer; the rows speak for themselves
  }

  // NFT singleton transfer (no commit). Same shape — show no banner.
  if (has("nft") && !has("commit-nft")) {
    return "";
  }

  // Plain RXD transaction — only p2pkh outputs, no Glyph types. Common
  // enough that surfacing "this is just a regular send" is reassuring,
  // especially in contrast to deploy/claim/burn shapes above.
  if (Object.keys(counts).every((t) => t === "p2pkh")) {
    return ""; // plain RXD — no protocol context to add
  }

  return "";
}

// Return the structural-match qualifier for a script type, or empty
// string if none applies. Used by both ``renderOutputRow`` (per-output
// in a fetched-tx card) and ``renderScriptCard`` (when the user pastes
// a standalone script). Wording matches the CLI's
// ``_render_script_human`` for cross-tool consistency.
function _structuralQualifierNote(type) {
  const NOTES = {
    ft: "Structural pattern match: bytes match the FT script template; " +
        "does NOT verify the ref points to a valid Glyph contract.",
    nft: "Structural pattern match: bytes match the NFT script template; " +
        "does NOT verify the ref points to a valid Glyph contract.",
    mut: "Structural pattern match. The payload_hash is an opaque " +
        "commitment to off-chain CBOR — resolve via the reveal tx; the " +
        "tool cannot verify provenance of the ref locally.",
    "commit-ft": "Structural pattern match. The payload_hash is an opaque " +
        "commitment to the reveal-tx CBOR. A commit-ft output is the " +
        "FT contract's metadata anchor — present in every Glyph FT deploy.",
    "commit-nft": "Structural pattern match. The payload_hash is an opaque " +
        "commitment to the reveal-tx CBOR. A commit-nft output is the " +
        "NFT singleton anchor that every Glyph FT deploy carries " +
        "alongside its FT outputs — it's a protocol artifact, not a " +
        "separately-mintable collectible.",
    dmint: "Structural pattern match: does NOT verify the contract_ref " +
        "points to a valid mint chain or that the parameters match a " +
        "deployed token.",
    op_return: "OP_RETURN: an unspendable data carrier. Used by some " +
        "non-Glyph protocols (legacy Atomicals-style markers, " +
        "third-party tooling) to embed arbitrary bytes on-chain. " +
        "Does NOT carry value and is not part of the Glyph protocol.",
  };
  return NOTES[type] || "";
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
    op_return: "OP_RETURN data output",
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

  // OP_RETURN data carrier
  if (payload.data_hex !== undefined) {
    dl.appendChild(kv("data (hex)", payload.data_hex || "(empty)"));
  }

  wrapper.appendChild(dl);

  if (type === "unknown") {
    wrapper.appendChild(el("p", {
      class: "card-note",
      text: "This doesn't match any known Glyph or P2PKH script template. " +
            "It may be a custom contract, a different protocol, or malformed bytes.",
    }));
  }

  // Structural-match qualifier (issue #53 / PR #58). Same wording the
  // CLI's _render_script_human emits.
  const qualifier = _structuralQualifierNote(type);
  if (qualifier) {
    wrapper.appendChild(el("p", { class: "structural-note", text: qualifier }));
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
