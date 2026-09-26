// The page's `glue.mark_anchor` bridge, answered by the REAL Python — one subprocess per call.
//
// WHY A SUBPROCESS AND NOT A CANNED LIST. The mark's block is now decided by a loop that runs
// across the bridge: the page calls `glue.mark_anchor`, which may answer "fetch me the header at
// height H" (`needs_headers`); the page fetches it and calls again with everything it has so far.
// What the page passes on the second call depends on what the server answered on the first, so a
// list of answers computed in advance would either repeat the page's logic in the test (and then
// test the copy) or go stale the moment the rule changed. Here every call reaches the real
// `glue.mark_anchor`, with exactly the arguments the page passed, and returns exactly what it
// returned — so what the page draws is what it draws for the real rule's real answers.
//
// The bridge is SYNCHRONOUS in the page (`fromPy(markAnchorBridge(...))`, a Pyodide proxy call),
// and `execFileSync` keeps it synchronous here.
//
// Contract: makeGlueSubprocessBridge(python, glueDir, calls) -> (...args) => answer
//   `python` is the interpreter to run (the test passes its own `sys.executable`, with a
//   PYTHONPATH that reaches `src/`); `calls` receives every argument list, verbatim.

import { execFileSync } from "node:child_process";

const SNIPPET = [
  "import json, sys",
  "sys.path.insert(0, sys.argv[1])",
  "import glue",
  "print(json.dumps(glue.mark_anchor(*json.loads(sys.argv[2]))))",
].join("\n");

export function makeGlueSubprocessBridge(python, glueDir, calls) {
  return (...args) => {
    calls.push(args);
    const out = execFileSync(python, ["-c", SNIPPET, glueDir, JSON.stringify(args)], {
      encoding: "utf8",
      env: process.env,
    });
    return JSON.parse(out.trim().split("\n").pop());
  };
}
