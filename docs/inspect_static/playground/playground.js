// Radiant Playground. Boots pyrxd under Pyodide with the same audited boot /inspect/ and
// /verify/ use (`bootPyrxdRuntime` in ../inspect/shared.js), then loads three Python files
// of its own, each SHA-256 checked against manifest.json before it runs:
//
//   sandbox_curve.py  the pure-Python secp256k1 stand-in (coincurve has no Pyodide build)
//   playground.py     the sandbox chain and the program runner
//   lessons.py        the lessons, as data
//
// Every string that reaches the page goes through `textContent`. Nothing is inserted as
// HTML except the editor's highlight layer, which escapes its input first (`escapeHtml`).

const WHEELS_BASE = new URL("../inspect/wheels/", document.baseURI).toString();
const GLUE_URL = new URL("../inspect/glue.py", document.baseURI).toString();
const PY_FILES = [
  { name: "sandbox_curve.py", key: "playground_curve_sha256" },
  { name: "playground.py", key: "playground_sha256" },
  { name: "lessons.py", key: "playground_lessons_sha256" },
];
const STORE_PREFIX = "pyrxd-playground:v1:";

// By id, the one DOM lookup the boot harness (tests/web/boot_packages_harness.mjs) models.
const $ = (id) => document.getElementById(id);

function el(tag, attrs, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") node.className = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v === true ? "" : String(v));
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    node.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return node;
}

function store(key, value) {
  try {
    if (value === undefined) return localStorage.getItem(STORE_PREFIX + key);
    if (value === null) localStorage.removeItem(STORE_PREFIX + key);
    else localStorage.setItem(STORE_PREFIX + key, value);
  } catch (_) {
    // Private windows and blocked storage: edits just are not kept.
  }
  return null;
}

const rxd = (photons) => (photons / 1e8).toLocaleString(undefined, { maximumFractionDigits: 8 });
const short = (h) => (h && h.length > 16 ? `${h.slice(0, 8)}…${h.slice(-6)}` : h || "");

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------

let py = null; // { pyodide, pg }
let LESSONS = [];
let cur = 0;
let running = false;

function toJs(proxy) {
  if (proxy === null || proxy === undefined) return proxy;
  if (typeof proxy.toJs !== "function") return proxy;
  const out = proxy.toJs({ dict_converter: Object.fromEntries, create_pyproxies: false });
  proxy.destroy();
  return out;
}

// Two stages. boot() brings up the runtime and imports the playground's Python, then shows
// the bench: the same contract /inspect/ and /verify/ keep (footer = buildLine(runtime),
// then #ready-content or #error-content un-hidden). initUi() then reads the lessons out of
// Python and draws them; a failure there is shown in place, never as a silent blank page.
async function boot() {
  const bar = $("load-progress");
  let runtime;
  try {
    runtime = await bootPyrxdRuntime({
      wheelsBase: WHEELS_BASE,
      glueUrl: GLUE_URL,
      onProgress: (p) => { bar.value = Math.min(p, 90); },
    });
    const footer = buildLine(runtime);
    if (footer) $("build-version").textContent = footer;
    const manifest = await loadManifest(new URL("./manifest.json", WHEELS_BASE).toString());
    const { pyodide } = runtime;
    for (const f of PY_FILES) {
      _assertHexSha256(manifest[f.key], f.key);
      const bytes = await fetchAndVerify(new URL(f.name, document.baseURI).toString(), manifest[f.key], f.name);
      pyodide.FS.writeFile(`/home/pyodide/${f.name}`, new Uint8Array(bytes));
    }
    bar.value = 95;
    pyodide.runPython(`
import sys
if "/home/pyodide" not in sys.path:
    sys.path.insert(0, "/home/pyodide")
import playground as _pyrxd_playground
_pyrxd_playground_changed = _pyrxd_playground.prepare_runtime()
`);
    py = { pyodide, pg: pyodide.globals.get("_pyrxd_playground"), runtime };
  } catch (err) {
    showError(`The playground could not start: ${err && err.message ? err.message : err}`);
    return;
  }
  bar.value = 100;
  $("loading").hidden = true;
  $("ready-content").hidden = false;
  try {
    initUi();
  } catch (err) {
    showError(`The playground loaded, but its lessons did not: ${err && err.message ? err.message : err}`);
  }
}

function showError(text) {
  $("loading").hidden = true;
  $("error-block").textContent = text;
  $("error-content").hidden = false;
}

function initUi() {
  const { pg, runtime } = py;
  LESSONS = toJs(pg.lesson_list());
  if (!Array.isArray(LESSONS) || LESSONS.length === 0) throw new Error("no lessons came back from Python");
  const changed = toJs(py.pyodide.globals.get("_pyrxd_playground_changed")) || [];
  $("runtime-pill").textContent = `${String(runtime.versionText).split(" loaded")[0]} · Python in browser`;
  $("runtime-info").textContent = `${runtime.versionText} · ${changed.join("; ")}`;
  const rules = toJs(pg.RULES);
  $("rules-list").replaceChildren(...rules.map(([, text]) => el("li", null, text)));
  wireEditor();
  wireTabs();
  const saved = Number(store("lesson"));
  cur = Number.isInteger(saved) && saved >= 0 && saved < LESSONS.length ? saved : 0;
  render();
  refreshChain();
}

// ---------------------------------------------------------------------------
// Lessons and the editor
// ---------------------------------------------------------------------------

function lessonButton(l, i) {
  const done = store(`done:${l.id}`) === "1";
  const isScratch = l.id === "scratch";
  return el(
    "button",
    {
      type: "button",
      class: `lesson${done ? " done" : ""}`,
      "aria-current": i === cur ? "step" : null,
      onclick: () => { cur = i; store("lesson", String(i)); render(); },
    },
    el("span", { class: "n" }, done ? "✓" : isScratch ? "+" : String(i + 1)),
    el("span", null, el("span", { class: "t" }, l.title), el("span", { class: "m" }, l.meta)),
  );
}

function renderRail() {
  const lessons = LESSONS.map((l, i) => [l, i]).filter(([l]) => l.id !== "scratch");
  const scratch = LESSONS.map((l, i) => [l, i]).filter(([l]) => l.id === "scratch");
  $("lessons").replaceChildren(...lessons.map(([l, i]) => lessonButton(l, i)));
  $("scratch-slot").replaceChildren(...scratch.map(([l, i]) => lessonButton(l, i)));
}

function codeFor(l) {
  return store(`code:${l.id}`) ?? l.code;
}

function render() {
  const l = LESSONS[cur];
  const lessonCount = LESSONS.filter((x) => x.id !== "scratch").length;
  renderRail();
  $("brief").replaceChildren(
    el("div", { class: "eyebrow" }, l.id === "scratch" ? "Scratch mode" : `Lesson ${cur + 1} of ${lessonCount}`),
    el("h2", null, l.heading),
    el("p", null, l.intro),
    l.steps.length ? el("ol", null, l.steps.map((s) => el("li", null, s))) : null,
  );
  $("fname").textContent = l.file;
  const ta = $("code");
  ta.value = codeFor(l);
  errorLine = null;
  paint();
  renderTry(l);
  $("export-note").hidden = true;
  $("console").replaceChildren(el("span", { class: "c-muted" }, `Ready. Press Run (or Ctrl+Enter) to run ${l.file}.`));
}

function renderTry(l) {
  const box = $("try");
  box.replaceChildren();
  if (!l.try_it) return;
  const t = l.try_it;
  box.append(el("span", null, el("b", null, "Try it: "), t.text));
  box.append(
    el("button", {
      type: "button",
      class: "btn",
      onclick: () => {
        const ta = $("code");
        if (!ta.value.includes(t.find)) {
          box.append(el("span", null, "That line has changed in your copy. Reset the code to try this edit."));
          return;
        }
        ta.value = ta.value.replace(t.find, t.replace);
        saveCode();
        paint();
      },
    }, "Apply this edit"),
  );
}

let errorLine = null;

const PY_KEYWORDS = new Set("False None True and as assert async await break class continue def del elif else except finally for from global if import in is lambda nonlocal not or pass raise return try while with yield".split(" "));

function escapeHtml(s) {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function highlightLine(line) {
  const re = /(#.*$)|("(?:[^"\\]|\\.)*"?|'(?:[^'\\]|\\.)*'?)|(\b\d[\d_]*(?:\.\d+)?\b)|([A-Za-z_]\w*)(?=\s*\()|([A-Za-z_]\w*)/g;
  let out = "";
  let last = 0;
  let m;
  while ((m = re.exec(line)) !== null) {
    out += escapeHtml(line.slice(last, m.index));
    const [tok, cmt, str, num, fn, word] = m;
    if (cmt) out += `<span class="cm">${escapeHtml(tok)}</span>`;
    else if (str) out += `<span class="str">${escapeHtml(tok)}</span>`;
    else if (num) out += `<span class="num">${escapeHtml(tok)}</span>`;
    else if (fn) out += PY_KEYWORDS.has(fn) ? `<span class="kw">${fn}</span>` : `<span class="fn">${escapeHtml(fn)}</span>`;
    else if (word && PY_KEYWORDS.has(word)) out += `<span class="kw">${word}</span>`;
    else out += escapeHtml(tok);
    last = m.index + tok.length;
  }
  return out + escapeHtml(line.slice(last));
}

function paint() {
  const lines = $("code").value.split("\n");
  $("hl").innerHTML = lines
    .map((ln, i) => {
      const body = highlightLine(ln) || " ";
      return i + 1 === errorLine ? `<span class="errline">${body}</span>` : body;
    })
    .join("\n") + "\n";
  $("gutter").replaceChildren(
    ...lines.map((_, i) => el("span", { class: i + 1 === errorLine ? "err" : null }, String(i + 1))),
  );
  const ta = $("code");
  ta.style.height = "auto";
  ta.style.height = `${ta.scrollHeight}px`;
}

function saveCode() {
  const l = LESSONS[cur];
  const v = $("code").value;
  store(`code:${l.id}`, v === l.code ? null : v);
}

function wireEditor() {
  const ta = $("code");
  ta.addEventListener("input", () => { errorLine = null; paint(); saveCode(); });
  ta.addEventListener("keydown", (e) => {
    if (e.key === "Tab" && !e.shiftKey) {
      e.preventDefault();
      const { selectionStart: a, selectionEnd: b } = ta;
      ta.setRangeText("    ", a, b, "end");
      ta.dispatchEvent(new Event("input"));
    } else if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
      e.preventDefault();
      runCode();
    }
  });
  $("reset-code").addEventListener("click", () => {
    const l = LESSONS[cur];
    store(`code:${l.id}`, null);
    ta.value = l.code;
    errorLine = null;
    paint();
  });
  $("run").addEventListener("click", runCode);
  $("export").addEventListener("click", showExport);
}

// The starter kit (`pyrxd new`) is being built separately. Until it ships, this says so and
// offers the one thing that already works: copying the code.
function showExport() {
  const note = $("export-note");
  note.hidden = false;
  note.replaceChildren(
    el("div", null, el("b", null, "Coming with the pyrxd starter kit. "),
      "This button will hand you a ready-made project (made by ", el("code", null, "pyrxd new"),
      ") with this code in it and a test that runs it on a local regtest chain. Until then, copy the code and run it against ",
      el("code", null, "pyrxd regtest up"), ", swapping the sandbox objects for a real client and wallet."),
    el("button", {
      type: "button",
      class: "btn",
      onclick: async (e) => {
        try {
          await navigator.clipboard.writeText($("code").value);
          e.target.textContent = "Copied";
        } catch (_) {
          e.target.textContent = "Copy failed: select the code and copy it by hand";
        }
      },
    }, "Copy code"),
  );
}

// ---------------------------------------------------------------------------
// Running
// ---------------------------------------------------------------------------

async function runCode() {
  if (running || !py) return;
  running = true;
  const btn = $("run");
  btn.disabled = true;
  btn.querySelector("span").textContent = "Running…";
  try {
    await runCodeInner();
  } catch (err) {
    $("console").append(el("span", { class: "c-bad" }, `\nThe page hit a bug drawing the result: ${err && err.message ? err.message : err}\n`));
  } finally {
    btn.disabled = false;
    btn.querySelector("span").textContent = "Run";
    running = false;
  }
}

async function runCodeInner() {
  selectTab("console");
  const out = $("console");
  const l = LESSONS[cur];
  out.replaceChildren(el("span", { class: "c-muted" }, `$ python ${l.file}\n`));
  errorLine = null;
  let result;
  try {
    result = toJs(await py.pg.run_program($("code").value));
  } catch (err) {
    result = { stdout: "", error: { type: "InternalError", message: String(err), line: null, rule: "", hint: "" }, txids: [] };
  }
  if (result.stdout) out.append(result.stdout);
  const e = result.error;
  if (e) {
    errorLine = e.line;
    const where = e.line ? ` (line ${e.line})` : "";
    if (e.type === "SandboxRejected") {
      out.append(el("span", { class: "c-bad" }, `\n✗ The sandbox refused the transaction${where}: ${e.message}\n`));
      out.append(el("span", { class: "c-muted" }, `  rule: ${e.rule}\n`));
    } else {
      out.append(el("span", { class: "c-bad" }, `\n${e.type}${where}: ${e.message}\n`));
    }
    if (e.hint) out.append(el("span", { class: "c-hint" }, `  hint: ${e.hint}\n`));
  } else {
    out.append(el("span", { class: "c-ok" }, `\n✓ finished${result.txids.length ? `, ${result.txids.length} transaction(s) added to the sandbox chain` : ""}\n`));
    if (l.id !== "scratch") {
      store(`done:${l.id}`, "1");
      renderRail();
    }
  }
  paint();
  refreshChain(result.txids);
  if (result.txids.length) renderTx(null);
}

// ---------------------------------------------------------------------------
// Tabs
// ---------------------------------------------------------------------------

function selectTab(name) {
  for (const n of ["console", "tx", "chain"]) {
    $(`t-${n}`).setAttribute("aria-selected", String(n === name));
    $(`p-${n}`).hidden = n !== name;
  }
}

function wireTabs() {
  for (const b of document.querySelectorAll(".tab")) {
    b.addEventListener("click", () => {
      selectTab(b.dataset.tab);
      if (b.dataset.tab === "tx") renderTx(currentTx);
    });
  }
}

// ---------------------------------------------------------------------------
// Transaction view
// ---------------------------------------------------------------------------

let currentTx = null;

const STATUS_MARK = { pass: "✓", warn: "!", fail: "✗" };

function ioCard(item, side, onPick, pressed) {
  const c = item.class;
  const title = side === "out" ? `#${item.index} ${c.label}` : c.label;
  const value = item.value === null || item.value === undefined ? "" : `${item.value.toLocaleString()} ph`;
  const sub = [
    c.owner ? `owner: ${c.owner}` : "",
    c.ref ? `ref ${c.ref}` : "",
    side === "in" ? item.outpoint : "",
  ].filter(Boolean).join(" · ");
  const attrs = { class: `io ${c.kind}` };
  if (onPick) {
    attrs.type = "button";
    attrs.onclick = onPick;
    attrs["aria-pressed"] = String(Boolean(pressed));
  }
  return el(onPick ? "button" : "div", attrs,
    el("div", { class: "k" }, el("span", null, title), el("span", null, value)),
    sub ? el("div", { class: "s" }, sub) : null);
}

function renderTx(txid) {
  const pane = $("p-tx");
  if (!py) return;
  const d = toJs(py.pg.describe_tx(txid));
  if (!d) {
    pane.replaceChildren(el("p", { class: "note" }, "Run a lesson that sends a transaction, and it is decoded here: its inputs, its outputs, each output's script opcode by opcode, and the checks the sandbox ran."));
    return;
  }
  currentTx = d.txid;
  let picked = d.outputs.findIndex((o) => o.class.kind === "nft" || o.class.kind === "ft");
  if (picked < 0) picked = 0;

  const pick = el("select", { class: "tx-pick", "aria-label": "Transaction", onchange: (e) => renderTx(e.target.value) },
    d.order.slice().reverse().map((t) => el("option", { value: t, selected: t === d.txid ? true : null }, `${short(t)}${t === d.txid ? " (shown)" : ""}`)));

  const scriptBox = el("div", { class: "script" });
  const outCol = el("div", { class: "col" }, el("div", { class: "sect-label" }, "Outputs"));
  const outButtons = d.outputs.map((o, j) => ioCard(o, "out", () => { picked = j; drawScript(); }, j === picked));
  outCol.append(...outButtons);

  function drawScript() {
    outButtons.forEach((b, j) => b.setAttribute("aria-pressed", String(j === picked)));
    const o = d.outputs[picked];
    const noteBox = el("div", { class: "op-note", "aria-live": "polite" }, "Select an opcode to see what it does.");
    const ops = o.ops.map((op) => el("button", {
      type: "button",
      class: `op ${op.kind}`,
      onclick: () => {
        noteBox.replaceChildren(el("b", null, `${op.name}: `), op.note || (op.kind === "push" ? "Data pushed onto the stack." : "A standard opcode."));
      },
    }, op.note && op.kind !== "op" ? el("small", null, op.kind === "ref" ? "token ref" : "covenant") : null,
       el("code", null, op.data ? `${op.name} ${op.kind === "push" ? short(op.data) : op.data}` : op.name)));
    const hexView = el("div", { class: "hexv mono", hidden: true }, o.hex);
    const toggle = el("button", { type: "button", class: "btn", onclick: (e) => {
      hexView.hidden = !hexView.hidden;
      e.target.textContent = hexView.hidden ? "Show hex" : "Hide hex";
    } }, "Show hex");
    scriptBox.replaceChildren(
      el("div", { class: "tx-head" }, el("div", { class: "sect-label" }, `Output #${o.index} locking script`), toggle),
      el("div", { class: "ops" }, ops),
      noteBox,
      hexView,
      el("div", { class: "legend" },
        el("span", null, el("i", { class: "ref" }), "holds or names a token ref"),
        el("span", null, el("i", { class: "cov" }), "covenant: reads the spending transaction")),
    );
  }
  drawScript();

  const checks = el("ul", { class: "checks" }, d.checks.map((c) => el("li", null,
    el("span", { class: c.status }, STATUS_MARK[c.status] || "·"),
    el("span", { class: c.status === "warn" ? "warn-text" : null }, `${c.rule}: ${c.detail}`))));

  pane.replaceChildren(
    el("div", { class: "tx-head" },
      el("h3", null, d.faucet ? "Faucet payment" : "Transaction"),
      pick),
    el("p", { class: "mono" }, `${d.txid} · ${d.size} bytes · fee ${d.fee.toLocaleString()} photons · block ${d.height} · ${d.confirmations} confirmation(s)`),
    el("div", { class: "flow" },
      el("div", { class: "col" }, el("div", { class: "sect-label" }, "Inputs"), d.inputs.map((i) => ioCard(i, "in"))),
      el("div", { class: "arrow", "aria-hidden": "true" }, "→"),
      outCol),
    scriptBox,
    el("div", { class: "sect-label" }, "What the sandbox checked"),
    checks,
    el("div", { class: "explain" },
      el("p", null, el("b", null, "Refs. "), "A ref is a 36-byte outpoint (txid and output index) that names a token for good. It is minted from an outpoint the transaction spends, so it cannot be minted twice. An output holds a token by pushing its ref with OP_PUSHINPUTREF (fungible) or OP_PUSHINPUTREFSINGLETON (one of a kind). A ref can only appear in an output if an input already held it."),
      el("p", null, el("b", null, "Covenants. "), "Radiant scripts can read the transaction spending them: its inputs, outputs, values and refs. A script that uses that to limit how it may be spent is a covenant. A Glyph FT's script ends in one: after OP_STATESEPARATOR it sums the token's value across inputs and outputs and fails if the outputs hold more. The commit script in a mint is one too: OP_REFTYPE_OUTPUT demands an output that holds the new ref.")),
  );
}

// ---------------------------------------------------------------------------
// Chain & wallet
// ---------------------------------------------------------------------------

function refreshChain(newTxids) {
  if (!py) return;
  const s = toJs(py.pg.chain_state());
  $("height").textContent = s.height.toLocaleString();
  $("bal").textContent = `${rxd(s.you.rxd_photons)} RXD`;
  const fresh = new Set(newTxids || []);
  const blocks = s.blocks.map((b) => el("div", { class: `block${b.txids.some((t) => fresh.has(t)) ? " new" : ""}` },
    el("span", { class: "h" }, `#${b.height}`),
    el("span", null, b.height === 0 ? "genesis" : `${b.txids.length} tx`),
    b.txids.map((t) => el("button", { type: "button", class: "op", onclick: () => { selectTab("tx"); renderTx(t); } }, el("code", null, short(t))))));
  const card = (who, w) => [
    el("div", null, el("div", { class: "lab" }, `${who} · RXD`), el("div", { class: "val" }, rxd(w.rxd_photons)), el("div", { class: "sub" }, w.address)),
    el("div", null, el("div", { class: "lab" }, `${who} · Glyph NFTs`), el("div", { class: "val" }, String(w.nfts))),
    el("div", null, el("div", { class: "lab" }, `${who} · FT units`), el("div", { class: "val" }, w.ft_units.toLocaleString())),
  ];
  $("p-chain").replaceChildren(
    el("div", { class: "sect-label" }, "Sandbox chain, newest on the right"),
    el("div", { class: "chain" }, blocks),
    el("div", { class: "wallet" }, card("You", s.you), card("Friend", s.friend)),
    el("div", { class: "chain-actions" },
      el("button", { type: "button", class: "btn", onclick: () => { toJs(py.pg.sandbox.mine(1)); refreshChain(); } }, "Mine a block"),
      el("button", { type: "button", class: "btn", onclick: () => { toJs(py.pg.reset_sandbox()); currentTx = null; refreshChain(); renderTx(null); } }, "Start a fresh chain")),
    el("p", { class: "note" }, "The chain lives in this tab and is gone when you close it. To keep a token, run the same code on your own regtest node."),
  );
}

boot();
