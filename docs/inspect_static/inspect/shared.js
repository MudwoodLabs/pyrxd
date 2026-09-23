// shared.js — the parts of the browser surface that MORE THAN ONE page needs.
//
// Two pages now read HashMark records in a browser:
//
//   /inspect/ — the developer inspector. Classifies anything you paste, renders
//               every field a Glyph script can carry, and shows a mark's verdict
//               inside that.
//   /verify/  — the public one. One input, four questions, plain language, for a
//               stranger who was handed a transaction id and no context.
//
// They render COMPLETELY differently and that is the point: one is a diagnostic,
// the other is an evidence page. What they must NOT differ on is anything a reader
// could check one against the other — so everything in that category lives here,
// once, and both pages read it:
//
//   * the RUNTIME boot — manifest, SHA-256 pinning, Pyodide, the pyrxd wheel, glue.py;
//   * the ELECTRUMX wire — the socket loop and every guard on it;
//   * `stripControlChars` — the sanitiser for strings that never cross the Python bridge;
//   * `verdictClass` — the status word → colour mapping, which is the only place
//     either page decides what colour a verdict is painted;
//   * `hashFileWithRecordAlgorithm` — hashing a chosen file with the algorithm the
//     RECORD names, and handing the comparison to Python.
//
// NOTHING HERE DECIDES WHAT A VERDICT MEANS. Every sentence a reader acts on comes
// out of `pyrxd.glyph._inspect_core` through `glue.py` — the same code `pyrxd glyph
// inspect` and `pyrxd verify` print from. This file carries values and paints them.
//
// LOADING CONTRACT — read before moving anything in this file.
//
// This is a CLASSIC script, not a module, and every top-level `function` and `const`
// below is therefore reachable by name from the page script that loads after it (and
// from the Node `vm` harnesses in tests/web/, which load this file and then the page's
// file into one context). Both index.html files load it FIRST, with a plain
// `<script src="…/shared.js"></script>`; a classic script runs before any deferred
// module, so the bindings exist by the time a page script's top level runs.
//
// If this ever becomes an ES module, every harness under tests/web/ that loads this
// file breaks at once, and each says so in its own named error rather than silently
// testing nothing. Deliberately not a COUNT here: a number in a comment is recomputed
// by nobody, and the one this sentence used to carry was already wrong one commit
// after it was written. `grep -l shared.js tests/web/*.mjs` is the answer.

"use strict";

// ---------------------------------------------------------------------
// Constants shared by both pages
// ---------------------------------------------------------------------

// ElectrumX WebSocket endpoint. Hard-coded to the one URL both pages' CSP
// whitelists in ``connect-src``. Changing this also requires updating the
// CSP meta-tag in BOTH index.html files — and, because a HashMark v2
// signature covers the chain's genesis hash, `glue.py`'s `_PAGE_NETWORK`
// with it. The same bytes on another chain verify against a different key,
// so an endpoint change without a network change makes every page here
// report attestations against the wrong chain.
const ELECTRUMX_WSS_URL = "wss://electrumx.radiant4people.com:50022";

// Per-fetch timeout. Real ElectrumX servers respond in <1s; 10 seconds
// is generous and bounds the worst case where the connection succeeds
// but the server hangs without responding.
const FETCH_TIMEOUT_MS = 10_000;

// Hard cap on a fetched transaction's hex length. Mirrors the cap
// glue.py applies on the Python side (8 MB hex = 4 MB binary, the
// Radiant policy maximum). Clipping in JS too means a hostile server
// can't make us spend memory holding a multi-gigabyte response while
// the Python guard rejects it.
const MAX_FETCHED_TX_HEX_LEN = 8_000_000;

// Refuse to read a file bigger than this into memory. `crypto.subtle.digest` has no
// streaming form, so the whole file has to be resident; a multi-gigabyte pick would
// take the tab down instead of answering.
const MAX_FILE_CHECK_BYTES = 256 * 1024 * 1024;

// Pyodide's CDN base. It must name the SAME version as the SRI-pinned <script> tags
// in both index.html files, or a page fetches a matching pyodide.js and then pulls its
// WASM and stdlib from a different release. `scripts/refresh-pyodide.sh` updates all
// three and refuses to write a file its pattern did not match;
// `test_facade_smoke.py` derives the set of files that pin a version and checks both
// that the script covers every one and that they currently agree.
const PYODIDE_INDEX_URL = "https://cdn.jsdelivr.net/pyodide/v0.26.4/full/";

// ---------------------------------------------------------------------
// Manifest / integrity
// ---------------------------------------------------------------------

// Validate a filename field from manifest.json is a bare basename
// — not an absolute URL, not a path traversal, not a scheme. Defends
// against an attacker-poisoned manifest redirecting wheel installs
// to a CSP-allowed origin (e.g. PyPI hosts) where they've staged a
// hostile wheel.
//
// LOAD-BEARING INVARIANT: this function's regex is also the only
// guard between manifest.{wheel,cbor2_wheel} and:
//   - ``new URL(value, wheelsBase)``  — absolute-URL escape
//   - ``"/tmp/" + value``             — Pyodide FS path-traversal escape
//   - ``"emfs:/tmp/" + value``        — Python-string interpolation
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

async function loadManifest(manifestUrl) {
  let manifest;
  try {
    const resp = await fetch(manifestUrl, { cache: "no-cache" });
    if (!resp.ok) {
      throw new Error(`manifest HTTP ${resp.status}`);
    }
    manifest = await resp.json();
  } catch (err) {
    throw new Error(
      `Could not load wheel manifest from ${manifestUrl}: ${err.message}. ` +
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
  // THE CURVE DIGESTS ARE VALIDATED HERE, LOUDLY, and not left to fail inside
  // `installSignatureBackend`. That function swallows everything by design so a
  // missing curve can never produce a verdict — which means a manifest with no
  // digest for the curve would silently turn signature checking off for every
  // visitor and look completely normal. A broken docs build gets a page that
  // refuses to start and is fixed the same day; a page quietly reporting "not
  // checked" on every mark is the failure that sits for a year.
  _assertHexSha256(manifest.curve_sha256, "curve_sha256");
  _assertHexSha256(manifest.curve_bridge_sha256, "curve_bridge_sha256");
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

// ---------------------------------------------------------------------
// secp256k1 — the one thing pyrxd cannot do in this tab
// ---------------------------------------------------------------------

// Give the Python side a curve, so the signature check can actually run.
//
// WHAT WAS BROKEN. pyrxd installs here with `deps=False` (see the install block
// below for why), and `coincurve` is one of the five dependencies that skips.
// `verify_attestation` therefore returned UNVERIFIABLE for EVERY record, and both
// pages told every reader the signature "was NOT checked here". On /inspect/ that is
// a developer shrugging; on /verify/, whose entire purpose is letting a stranger
// check somebody's claim, it is the product not working.
//
// WHAT CROSSES INTO JAVASCRIPT, and it is deliberately one operation: recover a
// public key from (message hash, r, s, recovery id). The canonical statement's
// byte-exact JSON, the varint framing, the double-SHA256, low-S, hash160 and the
// comparison against the committed signer all stay in the one Python implementation
// `pyrxd verify` uses. See `secp256k1-bridge.js` for why that split is the whole
// point rather than a shortcut.
//
// FAILURE IS SILENT AND SAFE, BY CONSTRUCTION. Anything that goes wrong here —
// a SHA mismatch, a missing file, an old browser without dynamic `import()` — means
// no backend is registered, and `verify_attestation` returns the UNVERIFIABLE it
// returned before by exactly the path it already had. There is no branch in which a
// curve that failed to load can produce a FAILING verdict, because the code that
// would have to decide that never runs. Painting an honest signer's mark red because
// of a script missing from the READER's machine is the worst thing either page could
// do, and this is what makes it unrepresentable rather than merely avoided.
//
// WHAT THE SHA-256 CHECK IS AND IS NOT. The bytes are fetched and verified BEFORE
// the module is imported, so a deploy whose curve does not match what CI built is
// never executed. That is a deploy-integrity check — it catches drift and a
// tampered Pages deploy. It is NOT a sandbox: `script-src 'self'` is what bounds
// what can run here at all, and an origin serving hostile JavaScript is already
// serving this file. The provenance of the vendored bytes — which upstream release
// they are and how that was established — lives in
// `tests/fixtures/noble_secp256k1_upstream_pin.json` and is asserted in CI by
// `tests/test_noble_secp256k1_pin.py`, not at runtime.
//
// Returns { installed: bool, reason: string|null }. Never throws.
async function installCurveBackend(bridges, manifest, curveUrl) {
  if (!curveUrl) {
    return { installed: false, reason: "this page did not point at a curve bridge" };
  }
  try {
    const bridgeUrl = new URL(curveUrl, document.baseURI);
    const vendorUrl = new URL("./vendor/noble-secp256k1.js", bridgeUrl);
    // Verify BOTH, then import. Order matters: `import()` is what executes them.
    await fetchAndVerify(bridgeUrl.toString(), manifest.curve_bridge_sha256, "secp256k1 bridge");
    await fetchAndVerify(vendorUrl.toString(), manifest.curve_sha256, "vendored secp256k1");
    const module = await import(bridgeUrl.toString());
    if (typeof module.recoverPublicKeySec1 !== "function") {
      return { installed: false, reason: "the curve bridge exported no recoverPublicKeySec1" };
    }
    // `install_signature_backend` returns False rather than raising if anything on
    // the Python side goes wrong, for the same reason this function does.
    const ok = bridges.installSignatureBackend(module.recoverPublicKeySec1);
    return ok
      ? { installed: true, reason: null }
      : { installed: false, reason: "pyrxd would not register the curve backend" };
  } catch (err) {
    return { installed: false, reason: String((err && err.message) || err) };
  }
}

// ---------------------------------------------------------------------
// Boot — Pyodide, the pyrxd wheel, and the glue module's entry points
// ---------------------------------------------------------------------

// Bring up pyrxd inside this tab and return the bridge functions.
//
// Takes NO DOM handles and writes nothing to the page: progress is reported
// through `onProgress(pct)` and failure is an Error the caller renders however
// its own page renders errors. That split is why one boot can serve two pages
// whose loading screens look nothing alike.
//
// `wheelsBase`, `glueUrl` and `curveUrl` are absolute URLs the caller resolves
// against its own `document.baseURI`. /verify/ points ALL THREE at /inspect/'s
// copies on purpose: the wheel, the manifest, glue.py and the curve bridge are
// built and SHA-pinned once by the docs CI step, and a second copy would be a
// second thing to keep in step — and the one most likely to go stale is the one
// nobody is looking at. Here that would mean a public page checking strangers'
// signatures with a curve the developer tool had already replaced.
async function bootPyrxdRuntime(options) {
  const opts = options || {};
  const wheelsBase = opts.wheelsBase;
  const glueUrl = opts.glueUrl;
  const onProgress = typeof opts.onProgress === "function" ? opts.onProgress : () => {};

  if (typeof loadPyodide !== "function") {
    throw new Error(
      "Pyodide failed to load. This is most often a Subresource Integrity " +
      "mismatch (the CDN served bytes that don't match the pinned SHA-384 " +
      "hash in index.html). Open the browser console for the underlying error."
    );
  }

  onProgress(5);
  const manifest = await loadManifest(new URL("./manifest.json", wheelsBase).toString());

  onProgress(15);
  let pyodide;
  try {
    pyodide = await loadPyodide({ indexURL: PYODIDE_INDEX_URL });
  } catch (err) {
    throw new Error(`Pyodide runtime failed to initialise: ${err.message}`);
  }

  onProgress(60);
  try {
    // Load Pyodide-bundled support packages first.
    //   - ``micropip`` — for installing the vendored wheels from FS.
    //   - ``pycryptodome`` — pyrxd imports ``Cryptodome.Cipher.AES`` in
    //     the encrypted-wallet path. Neither page reaches it, but the
    //     lazy ``__getattr__``s in pyrxd's package ``__init__``s might
    //     if a downstream caller touches it. Cheap to load preemptively
    //     (the glue.py shim aliases ``Cryptodome`` → ``Crypto``).
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
    // no pure-Python wheels. Neither page needs them — see
    // ``tests/web/test_inspect_imports_pyodide_clean.py``.
    //
    // coincurve is one of the five, so there is no secp256k1 in the
    // Python interpreter here and `verify_attestation` would return
    // UNVERIFIABLE for every record. `installSignatureBackend` above
    // supplies the one curve operation it needs from vendored
    // JavaScript, which is why a signature check now runs in this tab.
    // When that install fails, UNVERIFIABLE is still what comes back
    // and it still means "not checked here".
    //
    // Re-assert the basename invariant at the install site. ``loadManifest``
    // already validates these, but the FS path concat (``/tmp/${name}``)
    // and Python-string interpolation (``emfs:/tmp/${name}``) below are
    // load-bearing on the regex's alphabet — explicit defence in depth
    // against a future refactor that bypasses ``loadManifest``.
    _assertSafeBasename(manifest.cbor2_wheel, "cbor2_wheel");
    _assertSafeBasename(manifest.wheel, "wheel");

    const cbor2URL = new URL(manifest.cbor2_wheel, wheelsBase).toString();
    const cbor2Bytes = await fetchAndVerify(cbor2URL, manifest.cbor2_sha256, "cbor2 wheel");
    pyodide.FS.writeFile("/tmp/" + manifest.cbor2_wheel, new Uint8Array(cbor2Bytes));

    const pyrxdURL = new URL(manifest.wheel, wheelsBase).toString();
    const pyrxdBytes = await fetchAndVerify(pyrxdURL, manifest.wheel_sha256, "pyrxd wheel");
    pyodide.FS.writeFile("/tmp/" + manifest.wheel, new Uint8Array(pyrxdBytes));

    await pyodide.runPythonAsync(`
import micropip
await micropip.install("emfs:/tmp/${manifest.cbor2_wheel}")
await micropip.install("emfs:/tmp/${manifest.wheel}", deps=False)
`);
  } catch (err) {
    throw new Error(`Could not install pyrxd: ${err.message}`);
  }

  onProgress(85);

  // Load the Pyodide-side glue. The glue module installs the
  // Cryptodome→Crypto shim at import time and then imports pyrxd, so
  // pyrxd's import chain (which references Cryptodome.Cipher.AES via
  // aes_cbc) resolves cleanly. Every entry point comes back as a PyProxy.
  let bridges;
  let versionText;
  let signatureCheck = { installed: false, reason: "the runtime did not finish loading" };
  try {
    const glueBuffer = await fetchAndVerify(glueUrl, manifest.glue_sha256, "glue.py");
    const glueSrc = new TextDecoder("utf-8").decode(glueBuffer);
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
    const glue = pyodide.globals.get("_pyrxd_glue");
    bridges = {
      run: glue.run,
      inspectTxidWithRaw: glue.inspect_txid_with_raw,
      markAnchor: glue.mark_anchor,
      fileCheckPlan: glue.file_check_plan,
      judgeFileDigest: glue.judge_file_digest,
      // Not a per-check bridge: called once, just below, to hand the Python side
      // a curve. It is bound here anyway so it is reached the same way every
      // other entry point is — `tests/web/test_mark_anchor_bridge.py` derives its
      // universe from glue.py's public functions, and a boot that called this one
      // off the module object would be the one glue function nothing could see.
      installSignatureBackend: glue.install_signature_backend,
    };
    versionText = String(pyodide.globals.get("_pyrxd_version_blob"));
    // AFTER the glue is importable and BEFORE the page is told it is ready, so the
    // first mark a reader checks already has a curve behind it. Not inside the try's
    // failure path: a curve that will not load must not stop the page loading.
    signatureCheck = await installCurveBackend(bridges, manifest, opts.curveUrl);
  } catch (err) {
    throw new Error(`Could not load inspect glue: ${err.message}`);
  }

  if (!signatureCheck.installed) {
    // Console only. The READER is told by the verdict itself, which says NOT CHECKED
    // and why, in words that come out of `_inspect_core` — a second explanation
    // written here could drift from it, and a banner about a library is not what
    // someone who was handed a transaction number came to read.
    console.warn(`signature checking is off in this tab: ${signatureCheck.reason}`);
  }

  onProgress(100);
  return { pyodide, bridges, versionText, gitSha: manifest.git_sha, signatureCheck };
}

// Convert a Pyodide return value to a plain JS object and release the proxy.
// Every bridge call goes through it so a forgotten `destroy()` cannot leak.
function fromPy(value) {
  if (!value || typeof value.toJs !== "function") return value;
  const plain = value.toJs({ dict_converter: Object.fromEntries });
  value.destroy();
  return plain;
}

// ---------------------------------------------------------------------
// WebSocket fetch — pulls data for a txid from the configured ElectrumX
// server. Returns a Promise of the JSON-RPC result or rejects with an
// Error on any failure mode.
//
// Wire protocol: ElectrumX uses JSON-RPC 2.0 over WebSocket with
// newline-delimited frames. We send one request, await the matching
// response by id, and close. No long-lived connection — this is a
// "fetch and forget" pattern, simpler than maintaining the kind of
// reader loop the Python ElectrumXClient uses.
// ---------------------------------------------------------------------

// WHY EVERY REJECTION CARRIES A `kind`.
//
// "The server has no such transaction" and "the server could not be reached" are
// DIFFERENT FACTS, and only one of them is about the transaction you asked for. They
// arrive here as the same rejected promise, and a caller that renders both the same
// way tells a reader to "try again in a moment" when the real answer is "that number
// is not a transaction" — the fallback-collapse this project has shipped before,
// where "no matches" and "the upstream is gone" were the same empty array.
//
// So the wire classifies what happened and the CALLER decides what to say:
//
//   "refused"     — the server answered, and its answer was an error. It is up and
//                   talking; it did not give back what was asked for.
//   "unreachable" — no answer at all: no socket, a timeout, or a close before a reply.
//   "malformed"   — an answer arrived and is not usable (non-JSON, over the cap, not hex).
//
// The message text is unchanged, so anything matching on it still works; `kind` is
// additive and a caller that ignores it behaves exactly as before.
function wireError(kind, message) {
  const err = new Error(message);
  err.kind = kind;
  return err;
}

// ONE request, ONE socket, ONE set of guards.
//
// The wire handling and the transaction-specific checks are deliberately NOT
// fused: the verdict view needs three calls over this loop
// (`blockchain.transaction.get` raw and verbose, and `blockchain.headers.subscribe`)
// and the public page needs the same three again. Copying the socket loop is how
// one copy ends up without the frame cap or without the id match, so the wire half
// is here and the per-method checks stay with their callers.
//
// Guards, all of them load-bearing: a frame-size cap applied BEFORE JSON.parse, a
// mismatched-id frame discarded WITHOUT disarming the timeout, the server's error
// text stripped of control characters before it can reach the DOM, and a hard
// timeout.
function electrumxRpc(method, params) {
  return new Promise((resolve, reject) => {
    let ws;
    try {
      ws = new WebSocket(ELECTRUMX_WSS_URL);
    } catch (err) {
      reject(wireError("unreachable", `could not open WebSocket: ${err.message || err}`));
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
      settle(reject, wireError("unreachable", `timed out after ${FETCH_TIMEOUT_MS}ms`));
    }, FETCH_TIMEOUT_MS);

    ws.addEventListener("open", () => {
      const req = JSON.stringify({ id: 1, method, params });
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
        settle(reject, wireError(
          "malformed",
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
        // err.message is a V8 SyntaxError that echoes a slice of the
        // unparsed frame verbatim — attacker-controlled up to ~20 chars.
        // Sanitise it the same way frame.error below is sanitised: this
        // path has strictly fewer preconditions to reach (no id===1
        // match needed), so it must not be the unguarded sibling.
        settle(reject, wireError(
          "malformed",
          `server returned non-JSON: ${stripControlChars(err.message)}`
        ));
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
        settle(reject, wireError("refused", `server error: ${stripControlChars(rawMsg)}`));
        return;
      }
      settle(resolve, frame.result);
    });

    ws.addEventListener("error", () => {
      settle(reject, wireError("unreachable", "WebSocket error connecting to ElectrumX"));
    });

    ws.addEventListener("close", () => {
      settle(reject, wireError("unreachable", "WebSocket closed before any response"));
    });
  });
}

// The raw transaction, hex, with the checks that are about THIS method's result
// rather than about the wire.
async function fetchRawTxFromElectrumx(txid) {
  const result = await electrumxRpc("blockchain.transaction.get", [txid, false]);
  if (typeof result !== "string") {
    throw wireError("malformed", "server returned non-string result");
  }
  if (result.length > MAX_FETCHED_TX_HEX_LEN) {
    throw wireError(
      "malformed",
      `response is ${result.length.toLocaleString()} chars; cap is ` +
      `${MAX_FETCHED_TX_HEX_LEN.toLocaleString()}`
    );
  }
  // Light hex sanity check — Python side does the real validation.
  if (!/^[0-9a-fA-F]*$/.test(result)) {
    throw wireError("malformed", "server returned a non-hex string");
  }
  return result;
}

// The BLOCK a mark sits in — two calls, and only worth making when a mark is present.
//
// The depth and the tip are FETCHED here and JUDGED in Python: `resolve_mark_anchor`
// binds the echoed txid (so a server cannot answer about a different transaction),
// refuses an unreadable confirmation count instead of reading it as zero, and derives
// the height as `tip - confirmations + 1` — measured, because the verbose reply
// carries neither `height` nor `blockheight` on either shipped public server.
//
// Never throws. Losing the block must not lose the record, so a failure comes back
// as a `resolved: false` shape with its reason and the page renders that.
async function resolveMarkAnchor(markAnchorBridge, txid) {
  if (!markAnchorBridge) {
    return { resolved: false, reason: "the pyrxd runtime is not ready on this page yet" };
  }
  try {
    const [verbose, tipFrame] = await Promise.all([
      electrumxRpc("blockchain.transaction.get", [txid, true]),
      electrumxRpc("blockchain.headers.subscribe", []),
    ]);
    const tip = tipFrame && typeof tipFrame === "object" ? tipFrame.height : null;
    return fromPy(markAnchorBridge(txid, JSON.stringify(verbose), tip === undefined ? null : tip));
  } catch (err) {
    return {
      resolved: false,
      reason: `could not read the block: ${stripControlChars(String((err && err.message) || err))}`,
    };
  }
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

// ---------------------------------------------------------------------
// The verdict's COLOUR — the only place either page decides one
// ---------------------------------------------------------------------

// Presentational ONLY: status word -> CSS class. It maps to a colour, never to a
// sentence, which is why an unrecognised status lands on the neutral class rather
// than on either verdict — a new outcome rendered green is a forgery shown as
// genuine, and one rendered red is an honest mark shown as a lie.
//
// `verdict-unchecked` IS STILL THE IMPORTANT ONE, even though it is no longer the
// browser's normal case. `verify_attestation` returns UNVERIFIABLE when it has no
// secp256k1, and pyrxd installs here with `deps=False` so coincurve is absent —
// `installSignatureBackend` supplies a vendored curve instead, and when it does the
// verdict is a real VERIFIED or DOES NOT VERIFY. When it does NOT (a SHA mismatch,
// a blocked file, a browser with no dynamic import), UNVERIFIABLE comes back and
// must stay NEUTRAL: painting an honest signer's mark with the error colour because
// the READER's machine could not load a library is the single worst thing either of
// these pages could do, so "not checked" says whose limitation it is and judges
// nobody.
function verdictClass(status) {
  if (status === "VERIFIED" || status === "MATCHES") return "verdict-ok";
  // A MALFORMED RECORD IS NOT A NEUTRAL ONE. `/verify/` calls it RECORD DOES NOT DECODE
  // (the word `pyrxd verify` uses, and fails its verdict on); `/inspect/` shows the
  // decoder's own outcome name, INVALID. Both were grey, the colour of "not checked", so
  // one extra defect in a forged record's bytes moved it from the error colour here to
  // the neutral one. An unknown VERSION or ALGORITHM stays grey: that record is from the
  // future, not broken.
  if (
    status === "DOES NOT VERIFY" ||
    status === "DOES NOT MATCH" ||
    status === "RECORD DOES NOT DECODE" ||
    status === "INVALID"
  ) {
    return "verdict-bad";
  }
  return "verdict-unchecked";
}

// ---------------------------------------------------------------------
// The two sentences that are CLAIMS, kept in one copy
// ---------------------------------------------------------------------

// THE RISKIEST TEXT ON EITHER PAGE. It sits under a verified result and says what
// that result MEANS, so it inherits the authority of the verdict above it while
// asserting something no code checked. Both pages print it, and printing it twice
// from two string literals is how one of them eventually says something stronger
// than the other about the same record.
//
// It is deliberately the weaker sentence. A signature reaches this: the holder of that
// key made this statement, by the block that carries it. NOT that they put it in that
// block — the statement does not bind the transaction, so a genuine record can be
// copied into anyone's. Not authorship, not ownership, not originality, not location,
// and nothing at all about whether the marked content is true.
const WHAT_A_MARK_PROVES =
  "What a mark proves: someone knew this digest no later than the block that " +
  "confirms it. A verified signature adds that the key had signed it by then — not " +
  "that the key's holder put it in that block: a signed record can be copied into " +
  "anyone's transaction. It is not authorship, not ownership, not originality, not " +
  "location, and says nothing about whether the contents are true.";

// A PROMISE, which is the other kind of prose that must not drift between surfaces:
// it is the sentence a reader relies on when deciding whether to point this page at
// a private file. Both pages make it, from here.
const FILE_NEVER_LEAVES_THIS_MACHINE =
  "The file is read inside your browser and never leaves this machine: nothing is " +
  "uploaded, and nothing about it is sent to the network.";

// ---------------------------------------------------------------------
// The file check — hashed HERE, in this tab, with the algorithm the
// RECORD names, and JUDGED in Python
// ---------------------------------------------------------------------

// A shell command that does the same job when this page cannot. Derived from the
// record's own algorithm name, because `sha256sum` is only right for records that
// say sha256.
function fileCheckFallback(algorithm) {
  return `Run \`${algorithm}sum <file>\` in a shell and compare the digest above by eye.`;
}

// Hash `file` and return the verdict, or a degrade with a reason.
//
// Two things this deliberately does NOT do, and both are the point:
//
//   * IT DOES NOT PICK A HASH. `file_check_plan` reads the record's own
//     `algorithm_id` through `pyrxd.script.hashmark.algorithm_for`. A surface that
//     hardcoded "sha256" would produce a well-formed, confident, wrong answer for
//     any other algorithm, and nothing downstream could detect it.
//   * IT DOES NOT DECIDE WHAT A MATCH MEANS. `judge_file_digest` returns the same
//     `status`/`meaning` shape the attestation verdict uses, from the same module,
//     so the two verdicts on one screen come out of one vocabulary. One line of
//     `===` here would have been a third opinion on what "this is the file" is
//     allowed to mean — including the width case, where two digests of different
//     lengths are NOT a mismatch and saying so would tell someone their file is
//     wrong when what actually happened is that the wrong hash ran.
//
// Returns either:
//   { ok: false, reason, algorithm }                   — nothing was hashed, and why
//   { ok: true, algorithm, computed, expected, verdict } — verdict is Python's dict
async function hashFileWithRecordAlgorithm(file, hm, bridges) {
  const nominal = (hm && hm.algorithm) || "the record's algorithm";
  if (!bridges || !bridges.fileCheckPlan || !bridges.judgeFileDigest) {
    return { ok: false, reason: "the pyrxd runtime is not ready on this page yet", algorithm: nominal };
  }

  let plan;
  try {
    plan = fromPy(bridges.fileCheckPlan(hm.algorithm_id));
  } catch (err) {
    return {
      ok: false,
      reason: `bridge error: ${stripControlChars(String((err && err.message) || err))}`,
      algorithm: nominal,
    };
  }
  if (!plan || !plan.ok) {
    return {
      ok: false,
      reason: (plan && plan.reason) || "this record's algorithm is unavailable here",
      algorithm: nominal,
    };
  }

  if (!(typeof crypto !== "undefined" && crypto.subtle && typeof crypto.subtle.digest === "function")) {
    // A page served over plain http:// from anything but localhost is not a secure
    // context and gets no WebCrypto at all. Saying so beats a silent dead control.
    return {
      ok: false,
      reason:
        "this browser exposes no WebCrypto digest here, which usually means the page is " +
        "not in a secure context (plain http:// from somewhere other than localhost)",
      algorithm: plan.algorithm,
    };
  }
  if (file.size > MAX_FILE_CHECK_BYTES) {
    return {
      ok: false,
      reason:
        `${file.size.toLocaleString()} bytes is more than this page reads into memory ` +
        `(${MAX_FILE_CHECK_BYTES.toLocaleString()}) — there is no streaming digest in the browser`,
      algorithm: plan.algorithm,
    };
  }

  let computed;
  try {
    const buffer = await file.arrayBuffer();
    const digest = new Uint8Array(await crypto.subtle.digest(plan.webcrypto_name, buffer));
    let hex = "";
    for (const b of digest) hex += b.toString(16).padStart(2, "0");
    computed = hex;
  } catch (err) {
    return {
      ok: false,
      reason: `could not read or hash the file: ${stripControlChars(String((err && err.message) || err))}`,
      algorithm: plan.algorithm,
    };
  }

  let verdict;
  try {
    verdict = fromPy(bridges.judgeFileDigest(hm.digest, computed, plan.algorithm));
  } catch (err) {
    return {
      ok: false,
      reason: `bridge error: ${stripControlChars(String((err && err.message) || err))}`,
      algorithm: plan.algorithm,
    };
  }
  return { ok: true, algorithm: plan.algorithm, computed, expected: hm.digest, verdict };
}

// Does this classification carry a HashMark anywhere? Both shapes: a pasted script
// puts one at the top level, a fetched transaction one per output.
function carriesAMark(result) {
  const payload = result && result.payload;
  if (!payload) return false;
  if (payload.hashmark) return true;
  return Array.isArray(payload.outputs) && payload.outputs.some((row) => row && row.hashmark);
}

// Every HashMark record in a classification, in BOTH shapes it comes in.
//
// The JS twin of `pyrxd.cli.glyph_inspect.hashmark_records`, and it exists for the
// same reason that one does: three callers had open-coded the same two lines and one
// of them attached nothing at all and never said why. Kept in step by
// `tests/web/test_verify_page.py::TestTheTwoShapeWalkersAgree`, which runs both over
// the same payloads.
function hashmarkRecords(payload) {
  if (!payload) return [];
  if (payload.hashmark) return [{ vout: null, hashmark: payload.hashmark }];
  if (!Array.isArray(payload.outputs)) return [];
  return payload.outputs
    .filter((row) => row && row.hashmark)
    .map((row) => ({ vout: row.vout, hashmark: row.hashmark }));
}
