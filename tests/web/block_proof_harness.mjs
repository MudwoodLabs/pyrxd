// Drive shared.js's `proveMarkBlock` — the loop both pages run to verify a mark's block — under
// Node, against a stub ElectrumX answering the proof requests from a table.
//
// shared.js is loaded VERBATIM in a `vm` context, as index.html loads it. The bridge is either
// the REAL `glue.verify_mark_block` (one Python subprocess per call, glue_subprocess_bridge.mjs),
// or, for the loop's own safety stop, a bridge that never stops asking.
//
// Contract:
//   node block_proof_harness.mjs < case.json
//   stdin:  {"txid": hex, "raw_hex": hex, "anchor": {...},   — what the page hands the loop
//            "python"?: path, "checkpoints"?: [[h, hash], …],  — the real bridge, and the mainnet
//                      checkpoints its subprocess uses
//            "bridge"?: "always_asks" | "repeats",            — instead: a bridge that asks for a
//                      new header range on every call, forever; or one that asks for the SAME
//                      request (the merkle branch, key "merkle") on every call, forever
//            "proof": {…}}                                    — the server's answers (proof_server.mjs)
//   stdout: {"answer": {...} | null,        — what `proveMarkBlock` resolved to
//            "server_log": [[method, params], …],
//            "bridge_calls": n,
//            "__constants__": {"max_block_proof_requests": n}}

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";
import { makeGlueSubprocessBridge } from "./glue_subprocess_bridge.mjs";
import { answerProof } from "./proof_server.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const SHARED_JS = resolve(HERE, "../../docs/inspect_static/inspect/shared.js");
const GLUE_DIR = resolve(HERE, "../../docs/inspect_static/inspect");

function makeServer(proof, log) {
  return class ProofWebSocket {
    constructor() {
      this.listeners = {};
      setTimeout(() => this.dispatch("open", {}), 0);
    }
    addEventListener(type, cb) {
      (this.listeners[type] ||= []).push(cb);
    }
    dispatch(type, ev) {
      for (const cb of this.listeners[type] || []) cb(ev);
    }
    send(text) {
      const req = JSON.parse(text);
      log.push([req.method, req.params]);
      const answer = answerProof(proof, req.method, req.params);
      if (answer && answer.hang) return;
      const frame = !answer
        ? { id: req.id, error: { code: -32601, message: `the stub answers only proof requests, not ${req.method}` } }
        : answer.error
          ? { id: req.id, error: answer.error }
          : { id: req.id, result: answer.result };
      setTimeout(() => this.dispatch("message", { data: JSON.stringify(frame) }), 0);
    }
    close() {}
  };
}

async function main() {
  const spec = JSON.parse(readFileSync(0, "utf8"));
  const log = [];
  const calls = [];
  const sandbox = {
    console: { log() {}, warn() {}, error() {} },
    setTimeout,
    clearTimeout,
    WebSocket: makeServer(spec.proof || {}, log),
  };
  sandbox.globalThis = sandbox;
  vm.createContext(sandbox);
  vm.runInContext(readFileSync(SHARED_JS, "utf8"), sandbox, { filename: SHARED_JS });
  if (typeof sandbox.proveMarkBlock !== "function") {
    throw new Error("proveMarkBlock is not reachable after loading shared.js — do NOT delete the guard.");
  }
  let bridge;
  if (spec.bridge === "always_asks") {
    // A bridge that never has enough: a fresh, well-formed request every call. The loop's own
    // cap is all that ends it.
    bridge = (...args) => {
      calls.push(args);
      const n = calls.length;
      return { needs: { key: `headers:${n}:1`, method: "blockchain.block.headers", params: [n, 1] } };
    };
  } else if (spec.bridge === "repeats") {
    // A bridge that asks again for what it was already given: the loop's duplicate-request guard,
    // not its cap, is what must end it — after one request.
    bridge = (...args) => {
      calls.push(args);
      return {
        needs: { key: "merkle", method: "blockchain.transaction.get_merkle", params: [spec.txid, spec.anchor.height] },
      };
    };
  } else {
    bridge = makeGlueSubprocessBridge(spec.python, GLUE_DIR, calls, {
      fn: "verify_mark_block",
      checkpoints: spec.checkpoints,
    });
  }
  const answer = await sandbox.proveMarkBlock(bridge, spec.txid, spec.raw_hex, spec.anchor, () => false);
  process.stdout.write(JSON.stringify({
    answer,
    server_log: log,
    bridge_calls: calls.length,
    __constants__: {
      max_block_proof_requests: vm.runInContext(
        'typeof MAX_BLOCK_PROOF_REQUESTS === "number" ? MAX_BLOCK_PROOF_REQUESTS : null',
        sandbox,
      ),
    },
  }));
}

main().catch((err) => {
  process.stderr.write(String((err && err.stack) || err) + "\n");
  process.exit(1);
});
