// The page's `glue` bridges, answered by the REAL Python — one subprocess per call.
//
// WHY A SUBPROCESS AND NOT A CANNED LIST. The mark's block is decided by a loop that runs
// across the bridge: the page calls `glue.mark_anchor`, which may answer "fetch me the header at
// height H" (`needs_headers`); the page fetches it and calls again with everything it has so far.
// The block PROOF is the same shape (`glue.verify_mark_block` answers `needs` until it has every
// reply it wants). What the page passes on the second call depends on what the server answered on
// the first, so a list of answers computed in advance would either repeat the page's logic in the
// test (and then test the copy) or go stale the moment the rule changed. Here every call reaches
// the real glue function, with exactly the arguments the page passed, and returns exactly what it
// returned — so what the page draws is what it draws for the real rule's real answers.
//
// The bridge is SYNCHRONOUS in the page (`fromPy(markAnchorBridge(...))`, a Pyodide proxy call),
// and `execFileSync` keeps it synchronous here.
//
// Contract: makeGlueSubprocessBridge(python, glueDir, calls, options?) -> (...args) => answer
//   `python` is the interpreter to run (the test passes its own `sys.executable`, with a
//   PYTHONPATH that reaches `src/`); `calls` receives every argument list, verbatim.
//   `options.fn` names the glue function (default `mark_anchor`). `options.checkpoints`, when
//   given, REPLACES the shipped mainnet checkpoint table in that subprocess — a test-only seam,
//   set here, never in glue.py: the fixture chains are 17 headers long, and the shipped
//   checkpoints nearest them are further away than that.
//   The arguments travel on stdin, so a large one is not cut by the OS's per-argument limit.

import { execFileSync } from "node:child_process";

const SNIPPET = [
  "import json, sys",
  "sys.path.insert(0, sys.argv[1])",
  "spec = json.loads(sys.stdin.read())",
  "if spec.get('checkpoints') is not None:",
  "    from pyrxd.spv import radiant_checkpoints",
  "    radiant_checkpoints.CHECKPOINTS['mainnet'] = tuple(tuple(c) for c in spec['checkpoints'])",
  "import glue",
  "print(json.dumps(getattr(glue, spec['fn'])(*spec['args'])))",
].join("\n");

export function makeGlueSubprocessBridge(python, glueDir, calls, options = {}) {
  const fn = options.fn || "mark_anchor";
  const checkpoints = options.checkpoints === undefined ? null : options.checkpoints;
  return (...args) => {
    calls.push(args);
    const out = execFileSync(python, ["-c", SNIPPET, glueDir], {
      encoding: "utf8",
      env: process.env,
      input: JSON.stringify({ fn, args, checkpoints }),
      maxBuffer: 64 * 1024 * 1024,
    });
    return JSON.parse(out.trim().split("\n").pop());
  };
}
