// inspect.js — pyrxd inspect tool boot logic.
//
// PR-1 scope: load Pyodide, install the pyrxd wheel from the same-origin
// `wheels/` directory, import pyrxd, print the version. The classifier
// wiring lands in the next PR.
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

const STATUS_BLOCK = document.getElementById("loading-status");
const PROGRESS = document.getElementById("load-progress");
const READY_BLOCK = document.getElementById("ready-content");
const VERSION_BLOCK = document.getElementById("version-block");
const ERROR_BLOCK = document.getElementById("error-content");
const ERROR_PRE = document.getElementById("error-block");
const BUILD_VERSION = document.getElementById("build-version");

// Same-origin URL where the pyrxd wheel is staged. Set by the docs.yml CI
// step that runs ``pip wheel -w docs/inspect/wheels --no-deps .`` before
// ``sphinx-build``. The wheel's filename embeds the version, so we discover
// it at runtime via the `manifest.json` written next to it.
const WHEELS_BASE = new URL("./wheels/", document.baseURI).toString();
const WHEELS_MANIFEST = new URL("./manifest.json", WHEELS_BASE).toString();

// Show an error in the UI, hide the progress UI.
function showError(message) {
  console.error(message);
  STATUS_BLOCK.hidden = true;
  ERROR_BLOCK.hidden = false;
  // textContent only — never innerHTML — to defend against XSS via injected
  // error strings (e.g. a hostile manifest.json with attacker bytes).
  ERROR_PRE.textContent = String(message);
}

// Show the ready state with version info.
function showReady(versionText, buildSha) {
  STATUS_BLOCK.hidden = true;
  READY_BLOCK.hidden = false;
  VERSION_BLOCK.textContent = versionText;
  if (buildSha) {
    BUILD_VERSION.textContent = `build: ${buildSha}`;
  }
}

// Update the loading progress bar (0–100).
function setProgress(pct) {
  if (PROGRESS) {
    PROGRESS.value = Math.max(0, Math.min(100, pct));
  }
}

// Fetch the wheel manifest. CI writes a small JSON file describing the
// wheel filename and the source git SHA so the page can self-identify.
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

// Boot Pyodide and import pyrxd.
async function boot() {
  // Sanity-check that the Pyodide loader script ran (it adds `loadPyodide`
  // to window). If the SRI check failed, this symbol won't exist.
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
      // Tell Pyodide where to find its WASM/stdlib resources. Default points
      // back to the same CDN we loaded the loader from. Every sub-resource
      // also matches a published Pyodide release for this version.
      indexURL: "https://cdn.jsdelivr.net/pyodide/v0.26.4/full/",
    });
  } catch (err) {
    showError(`Pyodide runtime failed to initialise: ${err.message}`);
    return;
  }

  setProgress(70);

  // Install the same-origin pyrxd wheel via micropip. The wheel was built
  // from this commit by the docs CI step.
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

  setProgress(95);

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

  setProgress(100);
  showReady(versionText, manifest.git_sha);
}

// Kick off the boot sequence.
boot();
