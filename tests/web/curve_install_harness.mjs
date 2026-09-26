// EXECUTE `installCurveBackend` — the boot step no other harness reaches.
//
// WHY THIS EXISTS, and it is a hole that was found by planting rather than by reading.
// The render harnesses here load `shared.js` to check what the pages SAY: they stub
// `fetch` to reject and `crypto.subtle` to `{}`, and `boot()` fails on the first line.
// So every line of the curve install was covered by TEXT assertions and executed by
// nothing. The plant that proved it: swap the two SHA-256 digests
// (`manifest.curve_sha256` against `manifest.curve_bridge_sha256`). Every real page
// then fails its integrity check, no backend installs, and every mark in every browser
// silently goes back to reading NOT CHECKED — with 480 tests still green, because the
// swap changes no string any of them looks at.
//
// WHAT IS REAL HERE, because a harness that stubs the thing it verifies proves the stub:
//
//   * `shared.js` — loaded verbatim, not rewritten.
//   * `secp256k1-bridge.js` and `vendor/noble-secp256k1.js` — read from disk at the URLs
//     the browser resolves, and executed from the bytes the page verified, through
//     Node's real dynamic import.
//   * `crypto.subtle.digest` — Node's WebCrypto. The SHA-256 comparison that decides
//     whether the curve is trusted is the genuine article, which is what makes the
//     swapped-digest plant fail here.
//   * the manifest — supplied by the caller, computed the way `docs.yml` computes it.
//
// Two stand-ins, both TRANSPORT and neither the subject:
//
//   * `fetch` reads the same files from disk that the server would serve, and COUNTS
//     every request, per URL.
//   * `URL.createObjectURL` turns the page's `Blob` into a `data:` URL carrying the same
//     bytes and the same type. Node's module loader will not import a `blob:` URL; it
//     will import a `data:` one, and a `data:` module — exactly like a `blob:` one in a
//     browser — cannot resolve a relative import. So a page that handed the loader the
//     verified bytes but left the bridge's `./vendor/…` import in place fails here the
//     way it would fail in Chromium.
//
// THE SECOND DOWNLOAD (`--tamper-second-download`). The defect this exists for: the page
// verified one download of the curve and executed another, because `import(url)` fetched
// the file again. In a browser a reviewer served the SECOND request for the bridge with
// tampered bytes, and a forged mark rendered VERIFIED. Here the module loader is the only
// thing that could make that second request, so in this mode a loader hook answers any
// load of a file under /inspect/ with a module that records that it ran and returns a
// WRONG key. The page's own `fetch` still gets the genuine bytes. A page that executes
// what it verified never reaches the hook.
//
// `--bridge <path>` serves that file in place of the real bridge — for the refusal
// cases, where the manifest is computed over the substitute, so the digest check passes
// and what is under test is what happens next.
//
// Contract:
//   node curve_install_harness.mjs <manifest.json path> [--tamper-second-download] [--bridge <path>]
//   stdout: JSON — {"installed": bool, "reason": string|null, "received": bool,
//                   "recovered": "<hex>"|null, "fetches": {url: count},
//                   "second_download_ran": [url, …], "module_urls": n, "revoked": n}
//     `received` is whether the boot handed a function to the Python bridge; `recovered`
//     is that function run over a known-answer vector, so "installed" cannot mean "a
//     truthy value was passed along". `second_download_ran` lists every module that the
//     loader fetched for itself and then EXECUTED — it must be empty.

import { readFile } from "node:fs/promises";
import { register } from "node:module";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import vm from "node:vm";

const HERE = dirname(fileURLToPath(import.meta.url));
const INSPECT_DIR = resolve(HERE, "../../docs/inspect_static/inspect");
const SHARED_JS = resolve(INSPECT_DIR, "shared.js");
// A `file:` base rather than an `https:` one, for one reason: Node's ESM loader refuses
// any other scheme, so the page's own `import()` could not run at all. What is under test
// — `new URL(curveUrl, document.baseURI)`, and the library's `./vendor/…` resolved against
// the bridge's URL — resolves identically either way; only the scheme differs, and the scheme is the part
// a browser supplies. The page source is untouched.
const PAGE_BASE = pathToFileURL(resolve(INSPECT_DIR, "../verify") + "/").href;

// A known-answer vector, so a backend that installs but computes nothing is caught too.
// The real mainnet mark a1a86ab4…5916: its signed statement's hash256, r, s, recovery id
// 0, compressed, and the 33-byte key that must come back.
const KNOWN = {
  messageHash: "a3ba2888d6ffb162513e6ff5857c9ae1242cbf3a7c88e33d35baec39c10c45b7",
  r: "750d18df9ab44ba66ced01285a5a067b9ebf7c8ff6b32dddb40cc276c5e98d4c",
  s: "2054937e44a40d7628d80cafdd6a372b0aae8f8bb31dbb4d975273a23e8c9771",
  recId: 0,
  compressed: true,
};

const args = process.argv.slice(2);
const manifestPath = args[0];
if (!manifestPath) throw new Error("usage: curve_install_harness.mjs <manifest.json> [--tamper-second-download] [--bridge <path>]");
const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
const tamperSecondDownload = args.includes("--tamper-second-download");
const bridgeOverride = args.includes("--bridge") ? resolve(args[args.indexOf("--bridge") + 1]) : null;
const BRIDGE_FILE = resolve(INSPECT_DIR, "secp256k1-bridge.js");

if (tamperSecondDownload) {
  // Runs on the loader's own thread, so it can only answer loads — what it reports, it
  // reports by the module it returns recording itself on the main thread's global when it
  // RUNS. That is the fact under test: not "was it fetched" but "did it execute".
  const inspectPrefix = pathToFileURL(INSPECT_DIR).href + "/";
  const hook = `
    export async function load(url, context, nextLoad) {
      if (url.startsWith(${JSON.stringify(inspectPrefix)})) {
        return {
          format: "module",
          shortCircuit: true,
          source:
            "globalThis.__SECOND_DOWNLOAD_RAN__ = (globalThis.__SECOND_DOWNLOAD_RAN__ || []).concat([import.meta.url]);" +
            "export function recoverPublicKeySec1() { return { ok: true, publicKey: '02' + 'ee'.repeat(32) }; }" +
            "export function recoverPublicKey() { return new Uint8Array(33).fill(0xee); }",
        };
      }
      return nextLoad(url, context);
    }`;
  register("data:text/javascript," + encodeURIComponent(hook));
}

// Map the URL the page asked for back onto the file a server would serve for it, and
// REFUSE anything outside /inspect/. A harness that happily served whatever path it was
// handed would pass just as well if the page pointed its integrity check at one file and
// its import at another.
function fileFor(url) {
  const path = fileURLToPath(url);
  if (!path.startsWith(INSPECT_DIR + "/")) {
    throw new Error(`the page asked for ${path}, which is not under ${INSPECT_DIR}`);
  }
  return bridgeOverride && path === BRIDGE_FILE ? bridgeOverride : path;
}

let received = null;
const fetches = {};

// `Blob` that keeps its bytes readable synchronously, because `createObjectURL` is
// synchronous and Node's `Blob` only gives its bytes back through a promise. Still a real
// `Blob` — the page constructs it exactly as it would in a browser.
class PageBlob extends Blob {
  constructor(parts = [], options = {}) {
    super(parts, options);
    this.harnessBytes = Buffer.concat(parts.map((part) => {
      if (typeof part === "string") return Buffer.from(part, "utf8");
      if (part instanceof ArrayBuffer) return Buffer.from(new Uint8Array(part));
      if (ArrayBuffer.isView(part)) return Buffer.from(part.buffer, part.byteOffset, part.byteLength);
      throw new Error(`the harness's Blob does not know how to read a ${typeof part} part`);
    }));
  }
}

let moduleUrls = 0;
let revoked = 0;
// The page's `URL`, with the two static methods it uses to hand bytes to the loader.
class PageURL extends URL {
  static createObjectURL(blob) {
    if (!(blob instanceof PageBlob)) throw new Error("createObjectURL was given something that is not the page's Blob");
    moduleUrls += 1;
    return `data:${blob.type};base64,${blob.harnessBytes.toString("base64")}`;
  }
  static revokeObjectURL() {
    revoked += 1;
  }
}

const sandbox = {
  console: { log() {}, warn() {}, error() {} },
  URL: PageURL,
  Blob: PageBlob,
  URLSearchParams,
  TextDecoder,
  TextEncoder,
  setTimeout,
  clearTimeout,
  // REAL WebCrypto. The integrity check is the subject of this harness.
  crypto: globalThis.crypto,
  // The transport, and only the transport — counted.
  fetch: async (url) => {
    const key = String(url);
    fetches[key] = (fetches[key] || 0) + 1;
    const bytes = await readFile(fileFor(key));
    return {
      ok: true,
      status: 200,
      arrayBuffer: async () => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength),
    };
  },
  document: { baseURI: PAGE_BASE, createElement: () => ({}), getElementById: () => null, querySelectorAll: () => [] },
  WebSocket: class {},
  navigator: {},
  location: { href: PAGE_BASE, search: "" },
  history: { replaceState() {} },
};
sandbox.window = sandbox;
sandbox.globalThis = sandbox;
vm.createContext(sandbox);

vm.runInContext(await readFile(SHARED_JS, "utf8"), sandbox, {
  filename: SHARED_JS,
  // Let the page's own `import()` of the verified bytes run through Node's real loader.
  // Without this the dynamic import throws and every run reports a failed install for a
  // reason that has nothing to do with the code under test.
  importModuleDynamically: vm.constants.USE_MAIN_CONTEXT_DEFAULT_LOADER,
});

if (typeof sandbox.installCurveBackend !== "function") {
  throw new Error(
    "installCurveBackend is not reachable after loading shared.js. It was a top-level " +
    "declaration in a classic script; if it moved into a block or the file became an ES " +
    "module, this harness needs updating — do NOT delete the guard."
  );
}

// Stand in for the Pyodide bridge. `install_signature_backend` returns a Python bool;
// returning `true` here matches the success case, and capturing the argument is what
// lets the caller check a working curve arrived rather than merely a truthy result.
const bridges = {
  installSignatureBackend: (fn) => {
    received = fn;
    return true;
  },
};

// The page resolves the curve against `document.baseURI`, exactly as verify.js does.
const curveUrl = new URL("../inspect/secp256k1-bridge.js", PAGE_BASE).toString();
const result = await sandbox.installCurveBackend(bridges, manifest, curveUrl);

let recovered = null;
if (typeof received === "function") {
  const out = received(KNOWN.messageHash, KNOWN.r, KNOWN.s, KNOWN.recId, KNOWN.compressed);
  recovered = out && out.ok ? out.publicKey : `refused: ${out && out.kind}`;
}

process.stdout.write(
  JSON.stringify({
    installed: result.installed,
    reason: result.reason,
    received: typeof received === "function",
    recovered,
    fetches,
    second_download_ran: globalThis.__SECOND_DOWNLOAD_RAN__ || [],
    module_urls: moduleUrls,
    revoked,
  }) + "\n"
);
