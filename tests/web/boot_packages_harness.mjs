// EXECUTE `bootPyrxdRuntime` against a recording stand-in for Pyodide, and report every
// package the boot asks Pyodide for — by whatever route it asks.
//
// WHY THIS EXISTS (#757, round 2). The first guard against the boot re-loading Pyodide's
// OpenSSL scanned `shared.js` for a literal list passed to `loadPackage(...)`. A review
// planted two doors it could not see, and both passed every test in tests/web:
//   * `loadPyodide({ indexURL, packages: ["hashlib"] })` — confirmed real in Chromium: the
//     OpenSSL zips were fetched and `hashlib.sha256` became OpenSSL's;
//   * `const BOOT_PKGS = [...]; loadPackage(BOOT_PKGS)` — a variable, not a literal.
// Reading the source for one spelling of one call cannot see the others. Running the boot
// and recording what it ASKED FOR can: a name reaches Pyodide only through a call, and the
// stand-in is what receives the call.
//
// WHAT IS REAL: `shared.js`, loaded verbatim (or the copy named by `--shared`, which is how
// the planted doors are replayed); `glue.py`, `secp256k1-bridge.js` and the vendored curve,
// read from disk and SHA-checked by the page's own `fetchAndVerify` against a manifest this
// harness computes the way `docs.yml` does; Node's WebCrypto.
//
// WHAT IS STOOD IN, and why that is not the subject:
//   * Pyodide itself. Every call the boot makes on it is RECORDED, with its arguments. The
//     methods the boot is known to use are modelled; ANY OTHER property it touches is
//     recorded as `unknown` and answered with a recording function, so a new route (say,
//     `pyimport("micropip").install(...)`) shows up as an unmodelled call rather than
//     passing silently.
//   * The two wheels. They are not on disk in CI (the docs build makes them), so fixed
//     placeholder bytes are served with a manifest digest computed over those bytes. Nothing
//     installs them: the stand-in only records the Python that would.
//   * `URL.createObjectURL` is absent, so the curve install reports "not installed" — which
//     the boot tolerates by design — and the boot carries on to the end.
//
// Contract:
//   node boot_packages_harness.mjs [--shared <path to a shared.js variant>] [--hashing-report <json>]
//     --hashing-report: what the stand-in glue's `hashing_backend` returns, as a dict the page
//     converts with `toJs` — so the footer plumbing (readHashingBackend, buildLine) runs for real.
//   stdout (last line): JSON {
//     "finished": bool, "error": string|null, "progress": [n, …],
//     "loadPyodideOptions": [{…}, …]   (JSON-able part of each options object),
//     "loadPackage": [args, …]          (first argument of each call, as passed),
//     "loadPackagesFromImports": [args, …],
//     "python": [source, …]             (everything handed to runPython / runPythonAsync),
//     "unknown": [{"path": "...", "args": [...]}, …],
//     "fetches": [url, …],
//     "hashing": {…} (the runtime's report), "footer": "…" (buildLine(runtime))
//   }

import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

const HERE = dirname(fileURLToPath(import.meta.url));
const STATIC = resolve(HERE, "../../docs/inspect_static");
const INSPECT_DIR = resolve(STATIC, "inspect");

const args = process.argv.slice(2);
const sharedPath = args.includes("--shared") ? resolve(args[args.indexOf("--shared") + 1]) : resolve(INSPECT_DIR, "shared.js");
const hashingReport = args.includes("--hashing-report") ? JSON.parse(args[args.indexOf("--hashing-report") + 1]) : null;

const PAGE_BASE = "https://pages.invalid/verify/";
const WHEEL = "pyrxd-0.0.0-py3-none-any.whl";
const CBOR2 = "cbor2-5.4.6-py3-none-any.whl";
const placeholder = (name) => Buffer.from(`placeholder bytes for ${name}; never installed\n`, "utf8");
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

const manifest = {
  wheel: WHEEL,
  wheel_sha256: sha256(placeholder(WHEEL)),
  cbor2_wheel: CBOR2,
  cbor2_sha256: sha256(placeholder(CBOR2)),
  glue_sha256: sha256(await readFile(resolve(INSPECT_DIR, "glue.py"))),
  curve_sha256: sha256(await readFile(resolve(INSPECT_DIR, "vendor/noble-secp256k1.js"))),
  curve_bridge_sha256: sha256(await readFile(resolve(INSPECT_DIR, "secp256k1-bridge.js"))),
  git_sha: "0000000",
  git_sha_full: "0".repeat(40),
};

const record = {
  finished: false,
  error: null,
  progress: [],
  loadPyodideOptions: [],
  loadPackage: [],
  loadPackagesFromImports: [],
  python: [],
  unknown: [],
  fetches: [],
  hashing: null,
  footer: null,
};

// Answer a same-origin URL the way GitHub Pages would, and REFUSE anything else — the boot
// fetching from somewhere this harness does not know about is itself worth failing on.
async function bytesFor(url) {
  const u = new URL(url);
  if (u.origin !== new URL(PAGE_BASE).origin) throw new Error(`the boot fetched off-origin: ${url}`);
  if (u.pathname === "/inspect/wheels/manifest.json") return Buffer.from(JSON.stringify(manifest), "utf8");
  if (u.pathname === `/inspect/wheels/${WHEEL}`) return placeholder(WHEEL);
  if (u.pathname === `/inspect/wheels/${CBOR2}`) return placeholder(CBOR2);
  const path = resolve(STATIC, "." + u.pathname);
  if (!path.startsWith(INSPECT_DIR + "/")) throw new Error(`the boot fetched ${u.pathname}, outside /inspect/`);
  return readFile(path);
}

const jsonable = (value) => {
  try {
    return JSON.parse(JSON.stringify(value === undefined ? null : value));
  } catch (_) {
    return String(value);
  }
};

// Anything the boot touches that is not modelled below: recorded, and answered with a
// function that records its own calls and returns another such recorder, so a chain like
// `pyodide.pyimport("micropip").install("x")` is recorded in full.
function recorder(path) {
  const fn = function (...callArgs) {
    record.unknown.push({ path: `${path}()`, args: jsonable(callArgs) });
    return recorder(`${path}()`);
  };
  return new Proxy(fn, {
    get(target, prop) {
      if (typeof prop === "symbol" || prop === "then") return undefined;
      record.unknown.push({ path: `${path}.${String(prop)}`, args: null });
      return recorder(`${path}.${String(prop)}`);
    },
  });
}

// A PyProxy-shaped dict: `fromPy` converts it with `toJs` and then `destroy`s it, as it would a real one.
const pyDict = (obj) => ({ toJs: () => ({ ...obj }), destroy: () => undefined });
const glueModule = new Proxy(
  {},
  {
    get: (_t, prop) => {
      if (typeof prop === "symbol" || prop === "then") return undefined;
      if (prop === "hashing_backend" && hashingReport) return () => pyDict(hashingReport);
      return () => null;
    },
  },
);

const modelled = {
  loadPackage: async (names) => {
    record.loadPackage.push(jsonable(names));
    return [];
  },
  loadPackagesFromImports: async (code) => {
    record.loadPackagesFromImports.push(jsonable(code));
    return [];
  },
  runPython: (code) => {
    record.python.push(String(code));
    return undefined;
  },
  runPythonAsync: async (code) => {
    record.python.push(String(code));
    return undefined;
  },
  FS: { writeFile: () => undefined },
  globals: {
    get: (name) => (name === "_pyrxd_glue" ? glueModule : `stand-in value for ${name}`),
  },
};

const fakePyodide = new Proxy(modelled, {
  get(target, prop) {
    if (typeof prop === "symbol" || prop === "then") return undefined;
    if (Object.prototype.hasOwnProperty.call(target, prop)) return target[prop];
    record.unknown.push({ path: `pyodide.${String(prop)}`, args: null });
    return recorder(`pyodide.${String(prop)}`);
  },
});

const sandbox = {
  console: { log() {}, warn() {}, error() {} },
  URL,
  Blob,
  URLSearchParams,
  TextDecoder,
  TextEncoder,
  setTimeout,
  clearTimeout,
  crypto: globalThis.crypto,
  fetch: async (url) => {
    const key = String(url);
    record.fetches.push(key);
    const bytes = await bytesFor(key);
    return {
      ok: true,
      status: 200,
      json: async () => JSON.parse(bytes.toString("utf8")),
      arrayBuffer: async () => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength),
    };
  },
  loadPyodide: async (options) => {
    record.loadPyodideOptions.push(jsonable(options));
    return fakePyodide;
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
vm.runInContext(await readFile(sharedPath, "utf8"), sandbox, { filename: sharedPath });

if (typeof sandbox.bootPyrxdRuntime !== "function") {
  throw new Error(`${sharedPath} defines no bootPyrxdRuntime — this harness is broken, not the page`);
}

try {
  // The URLs /verify/ passes (verify.js), resolved the same way.
  const runtime = await sandbox.bootPyrxdRuntime({
    wheelsBase: new URL("../inspect/wheels/", PAGE_BASE).toString(),
    glueUrl: new URL("../inspect/glue.py", PAGE_BASE).toString(),
    curveUrl: new URL("../inspect/secp256k1-bridge.js", PAGE_BASE).toString(),
    onProgress: (pct) => record.progress.push(pct),
  });
  record.finished = true;
  record.hashing = jsonable(runtime.hashing);
  record.footer = sandbox.buildLine(runtime);
} catch (err) {
  record.error = String((err && err.message) || err);
}

process.stdout.write(JSON.stringify(record) + "\n");
