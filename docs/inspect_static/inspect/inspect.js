// inspect.js — pyrxd inspect tool: boot + classifier UI.
//
// LOADED SECOND. `shared.js` must already have run: the runtime boot, the
// ElectrumX wire, `stripControlChars`, `verdictClass` and the file-check
// mechanics live there because the public page at /verify/ needs the same ones,
// and a second copy of a supply-chain guard or a verdict colour is the copy that
// a later fix misses. index.html loads it with a plain <script> tag, which runs
// before this deferred module.
//
// Two phases:
//
//  1. Boot — `bootPyrxdRuntime` (shared.js) loads Pyodide, installs the
//     same-origin pyrxd wheel and loads the Pyodide-side glue (`glue.py`).
//     This phase ends when the bridge handles are stashed on module-scope
//     and the form is enabled.
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
const GLUE_URL = new URL("./glue.py", document.baseURI).toString();
// The secp256k1 the Python side does not have under Pyodide. Without it this
// page reported "not checked" for every signed record too.
const CURVE_URL = new URL("./secp256k1-bridge.js", document.baseURI).toString();

// Module-scope handles to the Python entry points once boot completes.
// Keeping these on the module rather than `window` avoids polluting the
// global namespace and keeps the surface explicit.
let pyGlue = null;          // glue.run(text) -> dict
let pyGlueFetch = null;     // glue.inspect_txid_with_raw(txid, raw_hex) -> dict
// The verdict view's three extra bridges. Each is a thin forward to pyrxd: the
// block comes from `resolve_mark_anchor`, the hash choice from `algorithm_for`,
// and the digest comparison and its wording from `_inspect_core`. None of the
// three is reimplemented here, which is the point of routing them through Python
// at all rather than doing the obvious one-liners in JS.
let pyMarkAnchor = null;      // glue.mark_anchor(txid, verbose_json, tip) -> dict
let pyFileCheckPlan = null;   // glue.file_check_plan(algorithm_id) -> dict
let pyJudgeFileDigest = null; // glue.judge_file_digest(expected, computed, algo) -> dict

// The ElectrumX endpoint, the wire timeout and the transaction size cap are
// `ELECTRUMX_WSS_URL` / `FETCH_TIMEOUT_MS` / `MAX_FETCHED_TX_HEX_LEN` in shared.js,
// which this page loads first. MAINNET is not incidental: glue.py's `_PAGE_NETWORK`
// is bound to that endpoint and passes it to the classifier, because a HashMark v2
// signature covers the chain's genesis hash — the same bytes on another chain verify
// against a different key.

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

// `bootPyrxdRuntime` lives in shared.js. The manifest fetch, the SHA-256
// pinning of both wheels and of glue.py, the Pyodide install and the bridge
// handles are identical on the public /verify/ page, and a second copy of a
// supply-chain guard is the copy a later fix misses. What stays here is the
// half that is about THIS page: which element shows progress, which shows the
// error, and what to do once the form is live.
async function boot() {
  let runtime;
  try {
    runtime = await bootPyrxdRuntime({
      wheelsBase: WHEELS_BASE,
      glueUrl: GLUE_URL,
      curveUrl: CURVE_URL,
      onProgress: setProgress,
    });
  } catch (err) {
    showError(err.message);
    return;
  }

  pyGlue = runtime.bridges.run;
  pyGlueFetch = runtime.bridges.inspectTxidWithRaw;
  pyMarkAnchor = runtime.bridges.markAnchor;
  pyFileCheckPlan = runtime.bridges.fileCheckPlan;
  pyJudgeFileDigest = runtime.bridges.judgeFileDigest;

  showReady(runtime.versionText, runtime.gitSha);
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
      // The block is a fact about the TRANSACTION, so it is resolved once and handed
      // to every row that carries a mark rather than looked up per output.
      outList.appendChild(renderOutputRow(row, {
        anchor: payload.mark_anchor,
        anchorReason: "the block was not looked up for this transaction",
      }));
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
  //
  // WHICH GLYPH THIS IS (#577). A multi-glyph reveal carries one payload per
  // minted glyph. The Python reports the FIRST decodable one as `metadata`,
  // stamps `of_n_payloads` on it when there is more than one, and lists every
  // payload-carrying input in `metadata_inputs` — and this card read neither.
  // Under a bare "Reveal metadata" heading, one name, ticker, description and
  // media therefore read as a description of the whole transaction. The
  // classifier's own note records an observed mainnet reveal minting 35 refs
  // from 36 inputs, so 34 of those refs were being shown another token's
  // identity. The CLI was fixed (`_render_txid_human`); this page was not.
  const metadata = payload.metadata;
  const metadataInputs = Array.isArray(payload.metadata_inputs) ? payload.metadata_inputs : [];
  if (metadata) {
    const ofN = metadata.of_n_payloads;
    wrapper.appendChild(el("h3", {
      class: "result-subhead",
      text: ofN
        ? `Reveal metadata (from input ${metadata.input_index} — 1 of ${ofN} glyphs minted here)`
        : `Reveal metadata (from input ${metadata.input_index})`,
    }));
    const mdl = el("dl", { class: "kv-list" });
    const warnings = (metadata && metadata.display_warnings) || {};
    mdl.appendChild(kv("input index", metadata.input_index));
    // WHAT THE ATTRIBUTION IS WORTH. Both readers take the first `gly` push in the
    // first input that decodes, so the name shown need not be the one the commit
    // committed to. `mismatch` means it demonstrably is not. Rendered for every
    // state, because "not checked" and "checked and held" are opposite facts and
    // omitting the weak one leaves the confident reading in place.
    if (metadata.payload_binding) {
      const pb = metadata.payload_binding;
      const cls = pb.state === "mismatch" ? "kv-warning" : undefined;
      mdl.appendChild(kv("payload binding", `${pb.state} — ${pb.reason}`, cls));
    }
    // Named whatever the verdict. On `unchecked` it is the outpoint someone would
    // fetch to settle it; on `mismatch` it is where the committed payload lives.
    if (metadata.input_outpoint) {
      mdl.appendChild(kv("spent outpoint", metadata.input_outpoint));
    }
    if (Array.isArray(metadata.protocol) && metadata.protocol.length > 0) {
      mdl.appendChild(kvWithWarning("protocol", metadata.protocol.join(", "), warnings.protocol));
    }
    // The classifier's own highest-specificity label ("wave", "container",
    // "timelock", …). It is drawn from a fixed internal vocabulary, computed
    // from the real GlyphMetadata — and it was the one field on this block that
    // states what the token IS, dropped while the raw protocol integers beside
    // it were shown.
    if (metadata.classification) mdl.appendChild(kv("classification", metadata.classification));
    if (metadata.name) mdl.appendChild(kvWithWarning("name", metadata.name, warnings.name));
    if (metadata.ticker) mdl.appendChild(kvWithWarning("ticker", metadata.ticker, warnings.ticker));
    if (metadata.description) mdl.appendChild(kvWithWarning("description", metadata.description, warnings.description));
    if (metadata.decimals !== undefined && metadata.decimals !== null) {
      mdl.appendChild(kv("decimals", metadata.decimals));
    }
    if (metadata.main) mdl.appendChild(kv("main", metadata.main));
    // The claim AND its verdict. This card showed protocol, name, ticker,
    // description and timelock, and dropped `relationships` and
    // `delegate_burns` entirely — so a token's collection and creator claims
    // reached nobody here at all.
    appendRelationshipVerdicts(mdl, metadata.relationships, metadata.delegate_burns);
    if (Array.isArray(metadata.delegate_burns) && metadata.delegate_burns.length > 1) {
      mdl.appendChild(kv("delegate burns", metadata.delegate_burns.join(", ")));
    }
    if (metadata.delegate_bases_unresolved) {
      mdl.appendChild(kv(
        "delegate bases not resolved",
        `${metadata.delegate_bases_unresolved} more — capped to bound the fetches`,
        "kv-warning",
      ));
    }
    // TIMELOCK: WHEN it opens (#556). The page already carried a banner saying a
    // TIMELOCK marker means "the reveal is subject to a time-based condition",
    // and then showed nothing about what the condition IS — the decoded spec was
    // in the payload and rendered nowhere.
    //
    // NO UNLOCKED/LOCKED VERDICT, deliberately, and for the reason the Python
    // and the CLI both give: deciding it needs a chain tip for mode="block" or a
    // timestamp for mode="time", and this renderer is handed a payload, not a
    // node. A verdict off the browser's wall clock would be a guess wearing the
    // clothes of a fact, and for mode="block" it would be meaningless.
    if (metadata.timelock) {
      const tl = metadata.timelock;
      mdl.appendChild(kv("timelock", `opens at ${tl.unlock_at} (${tl.mode})`));
      if (tl.hint) mdl.appendChild(kv("timelock hint", tl.hint));
      mdl.appendChild(kv("timelock cek commitment", tl.cek_hash));
    }

    // AUTHORITY — claims, EXPIRED, and anything validate_authority could not read.
    //
    // The Python computed this whole block and NEITHER renderer read it, so an authority that
    // expired years ago looked identical to a live one on both surfaces — while the AUTHORITY
    // banner on this page affirmatively told the reader the holder "can authorize operations".
    // `problems` is the signal that the expiry did not even parse, and it was the least visible
    // of the lot. Every value goes through `kv`, which assigns to textContent.
    const authority = metadata.authority;
    if (authority) {
      const claims = authority.claims || {};
      if (claims.issuer) mdl.appendChild(kv("authority issuer", _capText(claims.issuer)));
      if (claims.scope) mdl.appendChild(kv("authority scope", _capText(claims.scope)));
      if (Array.isArray(claims.permissions) && claims.permissions.length > 0) {
        const shown = claims.permissions.slice(0, _ENTRY_CAP).map((p) => _capText(p)).join(", ");
        mdl.appendChild(kv("authority permissions", shown));
        if (claims.permissions.length > _ENTRY_CAP) {
          mdl.appendChild(kv("", `… and ${claims.permissions.length - _ENTRY_CAP} more not shown`));
        }
      }
      if (claims.expires) mdl.appendChild(kv("authority expires", _capText(claims.expires)));
      if (claims.revocable === false) mdl.appendChild(kv("authority revocable", "false"));
      if (authority.expired) mdl.appendChild(kv("authority status", "*** EXPIRED ***"));
      for (const problem of authority.problems || []) {
        mdl.appendChild(kv("authority unreadable", _capText(problem)));
      }
    }
    wrapper.appendChild(mdl);
    if (authority) {
      // WHAT THE MARKER IS NOT. It says the token calls itself an authority; it does not
      // establish that any item was minted under it, nor that the issuer still honours it.
      wrapper.appendChild(el("p", {
        class: "card-note",
        text: "These are the token's own claims, not a verdict — the AUTHORITY marker does not " +
              "establish that any item was minted under this authority. That question is " +
              "verify_authority_gate's, and it needs the item's genesis output.",
      }));
    }
    if (metadata.timelock) {
      wrapper.appendChild(el("p", {
        class: "card-note",
        text: "Whether that timelock has opened is not decided here — it needs " +
              "the chain tip for a block-mode lock, or the current time for a " +
              "time-mode one. Pass this token's metadata and your chain tip to " +
              "pyrxd.is_unlocked / pyrxd.get_unlock_remaining.",
      }));
    }

    // Top-level warning banner if any field tripped a display flag.
    //
    // THE BANNER STATES THE REASON IT WAS GIVEN, it does not invent one. It
    // used to assert that the metadata "contains characters that visually mimic
    // Latin letters" for every entry in `display_warnings` — but one of the
    // producing branches (`glue.py` `_suspicious_reason`) is a pure category
    // test: every Letter is non-Latin, therefore flag. No confusability check
    // runs there at all, so a token honestly named in Japanese, Chinese or
    // Arabic was told the whole page it was imitating Latin. A warning that
    // fires on every non-Latin name is the false positive that teaches a reader
    // to skip the real one.
    //
    // Three reason strings reach this field today — "mixed scripts (possible
    // homoglyph)" and "non-Latin script (…)" from `_suspicious_reason`, and the
    // TR39 skeleton check's "characters that mimic Latin letters (…)" — and
    // they do not all mean the same thing. Rendering the reason keeps the
    // banner correct as that set changes, which a hardcoded sentence cannot.
    if (Object.keys(warnings).length > 0) {
      const reasons = Object.keys(warnings)
        .sort()
        .map((field) => `${field}: ${warnings[field]}`)
        .join("; ");
      const banner = el("p", { class: "warning-banner" });
      banner.textContent =
        "⚠ The displayed text on this token was flagged — " + reasons + ". " +
        "A reason naming mixed scripts or mimicry means characters from " +
        "another alphabet may be imitating Latin ones (Cyrillic 'а' is not " +
        "Latin 'a'). A reason naming a non-Latin script means only that the " +
        "text is not written in Latin at all, which is ordinary for a name in " +
        "Japanese, Chinese or Arabic and is not by itself evidence of a spoof. " +
        "Either way, the only reliable identifier for this token is the txid " +
        "above — verify by txid, not by visual name.";
      wrapper.appendChild(banner);
    }
  }

  // The OTHER glyphs in a multi-glyph reveal. Rendered outside the `metadata`
  // block, exactly as the CLI computes it: the headline payload is one entry in
  // `metadata_inputs`, and the rest of that list is the part a reader has no
  // other way to learn about. `kv` assigns to textContent, so a hostile token
  // name here cannot become markup.
  const headlineIndex = metadata ? metadata.input_index : undefined;
  const otherGlyphs = metadataInputs.filter((row) => row.input_index !== headlineIndex);
  if (otherGlyphs.length > 0) {
    wrapper.appendChild(el("h3", {
      class: "result-subhead",
      text: `Other glyphs minted in this transaction (${otherGlyphs.length})`,
    }));
    const odl = el("dl", { class: "kv-list" });
    for (const row of otherGlyphs) {
      // Name AND ticker, not whichever is truthy first: a glyph carrying both
      // and shown one of them is the same "you were told about a different
      // token" failure one level down.
      const label = [row.name, row.ticker].filter(Boolean).join(" / ") || "(unnamed)";
      odl.appendChild(kv(`input ${row.input_index}`, `${row.classification || "?"} — ${label}`));
    }
    wrapper.appendChild(odl);
  }

  // Glyph envelopes carrying no full payload.
  //
  // EMITTED BY THE PYTHON AND READ BY NOBODY HERE. `glyph_envelopes` reached the
  // JSON and the CLI's human mode and this card rendered none of it, so on the
  // web page a mutable glyph's UPDATE — the transaction that changes where a
  // WAVE name points — showed as an ordinary transfer, and an envelope neither
  // reader could parse showed as nothing at all. "I could not read this" and
  // "there is nothing here" are opposite facts, and the blind one reads as
  // reassuring.
  //
  // Every value goes through `kv`, which assigns to textContent, so an
  // attacker-authored key or value cannot become markup. Keys are truncated as
  // well as values: they are as publisher-chosen as the values, and capping only
  // the value left a 100,000-character key rendering in full.
  const envelopes = Array.isArray(payload.glyph_envelopes) ? payload.glyph_envelopes : [];
  if (envelopes.length > 0) {
    wrapper.appendChild(el("h3", {
      class: "result-subhead",
      text: `Glyph envelopes carrying no full payload (${envelopes.length})`,
    }));
    for (const env of envelopes) {
      const edl = el("dl", { class: "kv-list" });
      if (env.kind === "update") {
        edl.appendChild(kv(`input ${env.input_index}`, "UPDATE — a mutable glyph's fields are being changed here"));
        const fields = env.fields || {};
        const attrs = fields.attrs;
        if (attrs && typeof attrs === "object" && !Array.isArray(attrs)) {
          // `target` first and on its own row: for a WAVE name it is where the
          // name will point, which is the one value a reader is here for.
          if (attrs.target !== undefined) edl.appendChild(kv("attrs.target", _capText(attrs.target)));
          const others = Object.keys(attrs).filter((k) => k !== "target").sort();
          for (const k of others.slice(0, _ENTRY_CAP)) {
            edl.appendChild(kv(`attrs.${_capText(k)}`, _capText(attrs[k])));
          }
          if (others.length > _ENTRY_CAP) {
            edl.appendChild(kv("", `… and ${others.length - _ENTRY_CAP} more attrs not shown`));
          }
        }
        const top = Object.keys(fields).filter((k) => k !== "attrs").sort();
        for (const k of top.slice(0, _ENTRY_CAP)) {
          edl.appendChild(kv(_capText(k), _capText(fields[k])));
        }
        if (top.length > _ENTRY_CAP) {
          edl.appendChild(kv("", `… and ${top.length - _ENTRY_CAP} more fields not shown`));
        }
        wrapper.appendChild(edl);
        // WHAT THIS DOES NOT SAY. The envelope changes a GLYPH's fields. Whether
        // that glyph is the name someone means is an index's answer, not this
        // transaction's, and the gap between the two is the whole of HashMark §7.6.
        wrapper.appendChild(el("p", {
          class: "card-note",
          text: "Changes this glyph's fields — does NOT establish which name resolves " +
                "to it, nor who held that name when.",
        }));
        continue;
      }
      if (env.kind === "payload_unrendered") {
        // A DISAGREEMENT, not an unreadable envelope. One reader decoded a full
        // payload here and the other did not, so neither "rendered above" nor
        // "could not be read" is true.
        edl.appendChild(kv(`input ${env.input_index}`, "payload_unrendered — PAYLOAD the reveal reader did not return"));
        // The classifier's own reason, not a re-description of it. It names which
        // reader saw what, and re-wording it here is how the rendered sentence
        // drifts from the fact it claims to report.
        if (env.reason) edl.appendChild(kv("reason", _capText(env.reason)));
        wrapper.appendChild(edl);
        wrapper.appendChild(el("p", {
          class: "card-note",
          text: "The two glyph readers disagree about these bytes — treat the reveal " +
                "metadata above as incomplete for this input.",
        }));
        continue;
      }
      edl.appendChild(kv(`input ${env.input_index}`, "UNREADABLE — a 'gly' marker with content neither reader accepted"));
      if (env.reason) edl.appendChild(kv("reason", _capText(env.reason)));
      wrapper.appendChild(edl);
    }
  }

  return wrapper;
}

// Display caps for publisher-chosen text, mirroring `_HUMAN_STRING_CAP` and
// `_HUMAN_ENTRY_CAP` on the Python side. The count cap matters as much as the
// length one: a 256 KB envelope of one-byte keys renders tens of thousands of
// rows and pushes every verified fact off the screen, and no single row is long
// enough for a length cap to notice.
const _STRING_CAP = 200;
const _ENTRY_CAP = 32;

function _capText(value) {
  const text = value === null || value === undefined ? "" : String(value);
  return text.length <= _STRING_CAP ? text : text.slice(0, _STRING_CAP - 1) + "…";
}

// The OP_RETURN payload decoders (HashMark, the Photonic `msg` convention) and
// the relationship verifier, for EVERY card that can show one.
//
// One function because there are two cards and there was one renderer — and the
// comment inside `renderOutputRow` already states the rule: "a field that only
// the standalone-script card shows is a field most readers never see." The new
// fields were added to the Python classifier and to neither card, so this page
// rendered a forged HashMark as an authoritative-looking `OP_RETURN-HASHMARK-V2`
// badge with no signer and NO VERDICT. The affirmative half of the record
// survived and the part that contradicts it did not.
//
// Every value goes through `kv`, which assigns to textContent, so an attacker's
// label cannot become markup. That is why the CLI needed an escaping fix here and
// this does not.
function appendOpReturnPayload(dl, row) {
  const msg = row.message;
  if (msg) {
    if (msg.outcome === "ok") {
      if (msg.is_utf8) {
        dl.appendChild(kv(`message (${msg.byte_length} bytes)`, msg.text));
      } else {
        // Say WHY there is no text, or a reader assumes the field is empty
        // rather than that the bytes simply are not text.
        dl.appendChild(kv("message", `${msg.byte_length} bytes, not valid UTF-8 (see data_hex)`));
      }
    } else {
      dl.appendChild(kv("message", msg.detail ? `${msg.outcome} — ${msg.detail}` : msg.outcome));
    }
  }

  // A Glyph BURN proof. Every field is operator CBOR, so the header says
  // "claims" and the caveat travels with them: without it a reader sees
  // "token_ref: <X>  action: burn" and concludes X was burned, which this
  // output alone does not establish.
  const burn = row.burn;
  if (burn) {
    const c = burn.claims || {};
    dl.appendChild(kv("burn proof", "CLAIMED — operator-supplied, see note", "kv-warning"));
    if (c.token_ref) dl.appendChild(kv("token ref (claimed)", c.token_ref));
    if (c.action) dl.appendChild(kv("action (claimed)", c.action));
    if (c.amount !== undefined && c.amount !== null) {
      dl.appendChild(kv("amount (claimed)", c.amount));
    }
    if (c.reason) dl.appendChild(kv("reason (claimed)", c.reason));
    if (burn.note) dl.appendChild(kv("note", burn.note, "kv-warning"));
  }

  // A HashMark record is NOT rendered here. It has its own panel, on the card
  // wrapper rather than inside this field list — see `appendMarkVerdict`. Two
  // reasons, and the second is the one that matters: the verdict is the headline
  // and must not sit below a scroll of kv pairs, and there is exactly ONE element
  // on the screen describing a mark, so the script card and the tx row cannot
  // drift into contradicting each other about the same record.

  // Declared container/creator membership, WITH its verdict. `in` and `by` are
  // operator-supplied CBOR — anyone can name any collection — so the claim is
  // never shown without whether the transaction was authorised to carry it.
  appendRelationshipVerdicts(
    dl,
    (row.metadata && row.metadata.relationships) || row.relationships,
    (row.metadata && row.metadata.delegate_burns) || [],
  );
}

// ──────────────────────────────────────── HashMark: the verdict view ──
//
// The ONE place a HashMark record is rendered.
//
// It used to be a handful of kv rows inside `appendOpReturnPayload`, and the
// branch that matters most on this page was missing from them. `verify_attestation`
// returns UNVERIFIABLE when secp256k1 is absent, and in the browser it is ALWAYS
// absent: pyrxd installs here with `deps=False` and coincurve has no pure-Python
// wheel. So the commonest outcome on this surface had no branch at all.
//
// Measured before this change, on the real mainnet record in
// a1a86ab4503901af4df3d092fcf668b07c03c5cd89240fe918ae70e02e045916 (height
// 460,572), whose signature genuinely verifies: the card printed
// `signer 26ba…95d2` and then went straight to "what this proves". Not a wrong
// verdict — NO verdict, which is worse, because a reader supplies the missing
// sentence themselves and supplies the affirmative one.
//
// THE ASYMMETRY THIS PANEL EXISTS TO KEEP. A missing curve is a REFUSAL on the
// write side (`MarkPlan` will not fund a transaction it cannot self-verify) and a
// MISSING CAPABILITY OF THE READER on the read side. Painting a red cross beside
// an honest signer's mark because this browser has no secp256k1 would be the
// single worst thing this page could do, so "not checked here" is said in as many
// words, and whose limitation it is is named. `shared.js` installs a vendored
// curve at boot, so that branch is now the exception rather than the rule — but it
// is still reachable, and it still must not read as a verdict.
//
// Every sentence below that judges anything comes from the payload, which got it
// from `_inspect_core._ATTESTATION_VERDICTS` — the same table `pyrxd glyph
// inspect` prints from. Nothing here decides what a verdict means.

// `verdictClass` lives in shared.js: one status-word-to-colour mapping for both
// pages, so a reader who checks the public page against the inspector cannot find
// an honest mark neutral on one and red on the other.
function verdictBlock(label, status, meaning, detail) {
  const box = el("div", { class: `verdict ${verdictClass(status)}` });
  box.appendChild(el("span", { class: "verdict-label", text: label }));
  box.appendChild(el("strong", { class: "verdict-status", text: status || "NOT CHECKED" }));
  if (detail) box.appendChild(el("p", { class: "verdict-detail", text: detail }));
  if (meaning) box.appendChild(el("p", { class: "verdict-meaning", text: meaning }));
  return box;
}

// The block a mark's transaction sits in, or the reason there isn't one.
//
// `resolve_mark_anchor` produced this, not JS: it binds the echoed txid, refuses an
// unreadable depth rather than reading it as zero, and derives the height from the
// chain tip because the verbose reply carries no height field of its own (measured
// against both shipped public servers). What is rendered here is that result plus
// the caveat it carries — the height is the endpoint's CLAIM, and pyrxd has no
// Radiant header, proof-of-work or merkle check to test it with.
function appendAnchor(dl, caveats, anchor, anchorReason) {
  if (!anchor) {
    // NOT a warning. Nothing went wrong: this input never had a transaction to look
    // one up for, so form 2 is unavailable BY CONSTRUCTION. Painting it red would
    // make the ordinary case of pasting a script look like a fault, and a warning
    // colour that fires on the common path is a warning nobody reads by the time a
    // real one appears.
    dl.appendChild(kv("block", `not established — ${anchorReason}`, "kv-muted"));
    return;
  }
  if (!anchor.resolved) {
    dl.appendChild(kv("block", `not established — ${anchor.reason || "no reason given"}`, "kv-warning"));
    return;
  }
  if (anchor.height === null || anchor.height === undefined) {
    // Unconfirmed. A mark in the mempool fixes no time at all, and saying
    // "0 confirmations" without saying what that costs invites the reader to
    // treat it as a mark that is merely young.
    dl.appendChild(kv(
      "block",
      "none yet — this transaction is unconfirmed, and a mark in the mempool fixes no time. " +
      "It proves nothing about when until a block carries it.",
      "kv-warning",
    ));
    return;
  }
  dl.appendChild(kv("block", `${anchor.height} — ${anchor.confirmations} confirmation(s) deep`));
  // The caveat is COLLECTED, not appended here: it qualifies the row above and has to
  // be rendered after the field list, not before it. Printed first it read as a
  // preamble to a block nobody had been shown yet.
  caveats.push(`About that block: ${anchor.caveat}. The source is ${anchor.source}.`);
  caveats.push(`Depth: ${anchor.confirmations} confirmation(s). ${anchor.no_depth_policy}.`);
}

// The file check. Hashed HERE, in this page, with the algorithm the RECORD names.
function appendFileCheck(panel, hm) {
  if (!hm.digest || !hm.algorithm) return;
  const box = el("div", { class: "filecheck" });
  box.appendChild(el("h4", { class: "filecheck-title", text: "Do you have the file?" }));
  box.appendChild(el("p", {
    class: "filecheck-privacy",
    text:
      `Choose a file and this page hashes it with ${hm.algorithm} — the algorithm this ` +
      `record names — and compares the result with the digest above. ` +
      // The PROMISE comes from shared.js. Both pages make it, and a promise a reader
      // relies on before pointing this at a private file must not be two strings.
      `${FILE_NEVER_LEAVES_THIS_MACHINE} That is the same promise from the other ` +
      `side that pyrxd mark makes when it publishes one — the digest goes on chain, the ` +
      `contents do not.`,
  }));
  const input = el("input", { class: "filecheck-input" });
  input.type = "file";
  input.setAttribute("aria-label", "File to check against this digest");
  box.appendChild(input);
  const out = el("div", { class: "filecheck-result" });
  out.hidden = true;
  box.appendChild(out);
  input.addEventListener("change", () => onFileChosen(input, out, hm));
  panel.appendChild(box);
}

// The file check's MECHANICS — which hash, the size cap, the secure-context
// check, the digest, and the comparison — are `hashFileWithRecordAlgorithm` in
// shared.js, so this page and /verify/ cannot come to disagree about whether a
// file is the marked one. What is left here is this page's rendering of the
// answer it gets back.
function _fileCheckDegrade(out, reason, algorithm) {
  out.hidden = false;
  out.replaceChildren(verdictBlock("file", "NOT CHECKED", fileCheckFallback(algorithm), reason));
}

async function onFileChosen(input, out, hm) {
  const file = input.files && input.files[0];
  if (!file) return;
  // The user's own filename, but it can still carry a bidi override that makes the
  // rendered name differ from the real one. Same treatment as a server string.
  const name = stripControlChars(file.name || "(unnamed)");
  out.hidden = false;
  out.replaceChildren(el("p", { class: "filecheck-status", text: `Hashing ${name}…` }));

  const result = await hashFileWithRecordAlgorithm(file, hm, {
    fileCheckPlan: pyFileCheckPlan,
    judgeFileDigest: pyJudgeFileDigest,
  });
  if (!result.ok) {
    _fileCheckDegrade(out, result.reason, result.algorithm);
    return;
  }

  // The label is styled uppercase, and a FILENAME is not something to case-fold: it
  // would show MARKED.TXT for a file called marked.txt, on a page whose whole job is
  // telling a reader whether two things are the same. The name goes in a value.
  const block = verdictBlock("file", result.verdict.status, result.verdict.meaning);
  const dl = el("dl", { class: "kv-list" });
  dl.appendChild(kv("file", name));
  dl.appendChild(kv(`${result.algorithm} of your file`, result.computed));
  dl.appendChild(kv("digest in the record", hm.digest));
  out.replaceChildren(block, dl);
}

// The panel itself. Called by BOTH card renderers, from one definition, so the
// pasted-script view and the fetched-transaction view cannot describe one record
// two ways.
function appendMarkVerdict(wrapper, row, opts) {
  const hm = row && row.hashmark;
  if (!hm) return;
  const options = opts || {};
  const panel = el("section", { class: "mark-panel" });

  if (hm.outcome !== "ok") {
    // Claims to be a HashMark and is not readable as one. This is a statement
    // about the BYTES, not about any signature — an unknown version or algorithm
    // is a record from the future, not a forgery, and must not read as one.
    panel.appendChild(el("h3", { class: "mark-title", text: "HashMark record — not readable here" }));
    panel.appendChild(verdictBlock(
      "record",
      String(hm.outcome || "").toUpperCase().replace(/_/g, " "),
      "this is a verdict on the BYTES, not on anyone's signature: nothing here was checked against a key",
      hm.detail || "",
    ));
    const dl = el("dl", { class: "kv-list" });
    if (hm.version !== null && hm.version !== undefined) dl.appendChild(kv("version", hm.version));
    if (hm.algorithm_id !== null && hm.algorithm_id !== undefined) {
      dl.appendChild(kv("algorithm id", `0x${Number(hm.algorithm_id).toString(16).padStart(2, "0")}`));
    }
    panel.appendChild(dl);
    wrapper.appendChild(panel);
    return;
  }

  const algoId = hm.algorithm_id === null || hm.algorithm_id === undefined
    ? "?"
    : `0x${Number(hm.algorithm_id).toString(16).padStart(2, "0")}`;
  panel.appendChild(el("h3", {
    class: "mark-title",
    text: `HashMark v${hm.version} · ${hm.algorithm} (algorithm id ${algoId})`,
  }));

  const att = hm.attestation || {};
  // Sentences that qualify a row. Gathered as the rows are built and rendered AFTER
  // the field list, so each caveat sits below the fact it is about.
  const caveats = [];
  // `status` and `meaning` are the payload's, from the one table in `_inspect_core`.
  // The fallbacks are for a payload built before those fields existed, and they fail
  // toward "we do not know" rather than toward either verdict.
  const status = att.status || "NOT CHECKED";
  const meaning = att.meaning || "this build could not read the outcome of the signature check";
  if (hm.signer_hash160) {
    panel.appendChild(verdictBlock("signature", status, meaning, att.detail || ""));
    if (status === "VERIFIED" && att.assumed_network) {
      // The assumption is load-bearing exactly where the verdict is affirmative: the
      // chain's genesis hash is inside the signed statement, so the same bytes on
      // another chain are a different statement and recover a different key.
      caveats.push(
        `Checked against ${att.assumed_network}. The chain is part of the signed ` +
        `statement, so the same bytes read against another chain recover a different key.`
      );
    }
  } else {
    // v1: there is no signature to check, and the absence IS the finding.
    panel.appendChild(verdictBlock("signature", status, meaning, att.detail || ""));
  }

  const dl = el("dl", { class: "kv-list mark-fields" });
  dl.appendChild(kv("digest", hm.digest));
  if (hm.label) {
    dl.appendChild(kv("label", hm.label));
  } else if (hm.label_withheld) {
    // v1 keeps its timestamp evidence; the label is withheld WITH a reason, because
    // showing nothing looks like a record that carried no label.
    dl.appendChild(kv("label", `[withheld — ${hm.label_withheld}]`, "kv-warning"));
  }
  if (hm.signer_hash160) {
    // WHOSE ADDRESS IS THIS? The page used to print `att.signer_address` under the
    // label "signer address" for EVERY outcome. That field is the key the signature
    // RECOVERS TO — which, on a forged record, is whatever key the attacker's
    // signature happens to recover, and it was being labelled as the signer directly
    // below a line saying the signature does not verify. The CLI never did this: it
    // prints that address only when the outcome is `valid`, where recovered and
    // committed are the same value by construction.
    //
    // So the two are now told apart by name. The COMMITTED key is what the record
    // says and is always shown; the RECOVERED key is shown only when it means
    // something, and when it disagrees it is labelled as the disagreement it is.
    dl.appendChild(kv(
      status === "VERIFIED" ? "signer address" : "signer address (committed, unverified here)",
      hm.committed_signer_address || hm.signer_hash160,
    ));
    dl.appendChild(kv("signer hash160", hm.signer_hash160));
    if (att.recovered_hash160 && att.recovered_hash160 !== hm.signer_hash160) {
      dl.appendChild(kv(
        "recovered from the signature",
        `${att.signer_address || att.recovered_hash160} — NOT the signer this record names`,
        "kv-warning",
      ));
    }
  }
  appendAnchor(dl, caveats, options.anchor, options.anchorReason || "no block was looked up for this record");
  panel.appendChild(dl);
  for (const text of caveats) panel.appendChild(el("p", { class: "mark-caveat", text }));

  appendFileCheck(panel, hm);

  // LAST, and deliberately after everything a reader might have taken further than
  // it goes. A verified signature reaches this: the key had made this statement by the
  // block that carries it — not that its holder put it there, since a signed record can
  // be copied into anyone's transaction. Never authorship, never ownership, never location.
  // FROM shared.js, not from a literal here. This is the sentence that says what a
  // verified result MEANS, and the public page at /verify/ prints it too — two
  // copies is how one surface eventually claims more than the other about the same
  // record.
  panel.appendChild(el("p", { class: "mark-proves", text: WHAT_A_MARK_PROVES }));

  wrapper.appendChild(panel);
}

// FOUR verdicts, not two, and ONE definition of them.
//
// This logic lived only in the output-row renderer and had two states: `backed`
// → "spent in this tx", everything else → "nothing in this tx authorises it".
// BOTH are false for a delegated mint. A DELEGATED claim was spent when the
// delegate BASE was created, by someone who need not be this minter; and a claim
// whose base could not be resolved is "we did not look", not "nobody authorised
// it" — the exact false accusation the CLI change existed to stop.
//
// It was also absent from the fetched-tx card entirely, which is the surface
// most people meet. That card's own comment above records this same shape
// happening before ("The CLI was fixed; this page was not"). Hence one function,
// called from both.
function appendRelationshipVerdicts(dl, rels, burnedRefs) {
  if (!Array.isArray(rels) || rels.length === 0) return;
  const burned = Array.isArray(burnedRefs) ? burnedRefs : [];
  for (const rel of rels) {
    const label = rel.kind === "author" ? "creator claim" : "collection claim";
    const backed = rel.ok === true;
    let verdict;
    let cls = "kv-warning";
    if (backed && rel.basis === "delegated") {
      const via = burned.length === 1 ? ` ${burned[0]}` : "";
      verdict = `VERIFIED via delegate${via} — authorised by its base, not spent here`;
      cls = undefined;
    } else if (backed) {
      verdict = "VERIFIED (spent in this tx)";
      cls = undefined;
    } else if (burned.length) {
      const which = burned.length === 1 ? ` (${burned[0]})` : "";
      verdict = `UNRESOLVED — this tx burned a delegate${which}; fetch it to check`;
    } else {
      verdict = "UNVERIFIED CLAIM (nothing in this tx authorises it)";
    }
    dl.appendChild(kv(label, `${rel.ref} — ${verdict}`, cls));
  }
}

function renderOutputRow(row, opts) {
  const type = String(row.type || "unknown").toLowerCase();
  const wrapper = el("section", { class: "output-row" });
  const head = el("header", { class: "output-row-head" });
  head.appendChild(el("span", { class: "output-vout", text: `vout ${row.vout}` }));
  head.appendChild(badge(type.toUpperCase(), scriptBadgeKind(type)));
  head.appendChild(el("span", { class: "output-sats", text: `${row.satoshis} sats` }));
  wrapper.appendChild(head);

  // A fetched-tx row is the SAME dict a pasted script produces, minus
  // `form` and plus `vout` / `satoshis` (_inspect_core `_classify_raw_tx`).
  // Every field the classifier can emit therefore has to be rendered here
  // too — this path is how most people meet the tool, and a field that only
  // the standalone-script card shows is a field most readers never see.
  // Dropping them is what let a token-bearing `unknown` output, a dead
  // container and a DISABLED relative lock all render as a bare badge.
  //
  // Only `form`, `hex` and `length` are deliberately absent: `form` is
  // constant inside a tx listing, and the full script hex plus its byte
  // count belong to the JSON drawer, not to a scannable row (the CLI's
  // `_render_txid_human` omits both for the same reason).
  const relativeLockDisabled = row.relative_lock_disabled === true;
  const dl = el("dl", { class: "kv-list" });
  // FIRST, because on an OP_RETURN row it is the whole content of the row, and
  // because "signature DOES NOT VERIFY" must not sit below a scroll of kv pairs.
  appendOpReturnPayload(dl, row);
  if (row.owner_pkh) dl.appendChild(kv("owner pkh", row.owner_pkh));
  if (row.ref_outpoint) dl.appendChild(kv("ref", row.ref_outpoint));
  // Dead pre-0.15.0 CONTAINER output. The child ref is the reason it cannot
  // be spent, so the two travel together, and the verdict is stated in the
  // row rather than left to the note the reader may not open. CLI parity:
  // `child_ref=` + `UNSPENDABLE`.
  if (row.child_ref_outpoint) dl.appendChild(kv("child ref", row.child_ref_outpoint));
  // The authority an item is gated on. It is a DIFFERENT ref from the item's
  // own, so unlike the delegate rows it is not covered by printing `ref` —
  // dropping it would leave the reader unable to tell WHICH issuer gates this.
  if (row.authority_ref) dl.appendChild(kv("authority ref", row.authority_ref));
  if (row.spendable === false) {
    dl.appendChild(kv("spendable", "*** UNSPENDABLE ***", "kv-warning"));
  }
  if (row.payload_hash) dl.appendChild(kv("payload hash", row.payload_hash));
  if (row.script_hash) dl.appendChild(kv("script hash", row.script_hash));

  // Time-locks. Same ordering rule as the standalone card: the disable
  // warning comes BEFORE the delay it invalidates. CLI parity:
  // `lock=<units> <basis>  *** DISABLED ***`.
  if (row.locktime_basis) {
    if (relativeLockDisabled) {
      dl.appendChild(kv(
        "relative lock",
        "*** RELATIVE LOCK DISABLED — SPENDABLE IMMEDIATELY ***",
        "kv-warning",
      ));
    }
    dl.appendChild(kv(
      relativeLockDisabled ? "lock (ignored)" : "lock",
      `${row.locktime_units} ${row.locktime_basis} (raw ${row.locktime_value})`,
      relativeLockDisabled ? "kv-warning" : undefined,
    ));
    if (row.locktime_earliest !== undefined) {
      dl.appendChild(kv("earliest spend", row.locktime_earliest));
    }
  }

  // Covenant tiers. `transferability` is present only on the EXACT-match
  // tier — the weaker `self-replicating-covenant` withholds it on purpose,
  // so rendering it conditionally is what keeps the two tiers distinct here.
  if (row.bound_ref_outpoint) dl.appendChild(kv("bound ref", row.bound_ref_outpoint));
  if (row.variant) dl.appendChild(kv("covenant variant", row.variant));
  if (row.transferability) {
    dl.appendChild(kv("transferability", `${row.transferability} (non-transferable at consensus)`));
  }
  if (row.has_self_replication !== undefined) {
    dl.appendChild(kv("self-replication branch", String(row.has_self_replication)));
  }
  if (row.has_burn_branch !== undefined) {
    dl.appendChild(kv("burn branch", String(row.has_burn_branch)));
  }

  if (row.contract_ref_outpoint) dl.appendChild(kv("contract ref", row.contract_ref_outpoint));
  if (row.token_ref_outpoint) dl.appendChild(kv("token ref", row.token_ref_outpoint));
  if (row.height !== undefined) dl.appendChild(kv("height", row.height));
  if (row.max_height !== undefined) dl.appendChild(kv("max height", row.max_height));
  if (row.reward !== undefined) dl.appendChild(kv("reward", row.reward));
  if (row.algo) dl.appendChild(kv("algo", row.algo));
  if (row.daa_mode) dl.appendChild(kv("daa mode", row.daa_mode));
  if (row.version) dl.appendChild(kv("version", row.version));

  // Token-bearing verdict on a shape nobody named. This is the row that
  // matters most and the one the tx path used to drop entirely: a
  // ref-carrying UTXO spent as plain funding BURNS its token, and the
  // warning was invisible on the exact screen where users meet these
  // outputs. CLI parity: `ref=… (0xd0) TOKEN-BEARING`.
  if (row.token_bearing !== undefined) {
    dl.appendChild(kv(
      "token-bearing",
      row.token_bearing === null ? "unknown (script does not decode)" : String(row.token_bearing),
      row.token_bearing === false ? undefined : "kv-warning",
    ));
    for (const ref of row.input_refs || []) {
      dl.appendChild(kv(`ref (${ref.opcode})`, `${ref.ref_outpoint} TOKEN-BEARING`, "kv-warning"));
    }
    // 0xd1/0xd2/0xd3 name a ref without holding one — a gate, not a
    // carrier. Kept visually apart from the line above so it never reads
    // as a burn warning.
    for (const ref of row.referenced_refs || []) {
      dl.appendChild(kv(`ref (${ref.opcode})`, `${ref.ref_outpoint} — named, not carried`));
    }
  }

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
  // The delegate base this row is bound to, for EVERY row that carries one.
  // The classifier recovers it from all three commit types, but only emitted it
  // for the DAT branch and only the delegate-token/delegate-burn rows rendered
  // it — so a delegate-bound NFT or FT commit, whose reveal the covenant rejects
  // without a burn output naming that base, looked exactly like a plain commit
  // here. Generic, because hand-keeping which types show it is what lost it.
  if (row.delegate_base_ref && type !== "delegate-token" && type !== "delegate-burn") {
    dl.appendChild(kv("delegate_base_ref", row.delegate_base_ref));
  }
  // THE MARK'S VERDICT, above the field list and on the wrapper. `appendOpReturnPayload`
  // no longer renders one: both card renderers call this, so there is exactly one element
  // on screen describing a record and the two surfaces cannot contradict each other.
  appendMarkVerdict(wrapper, row, {
    anchor: opts && opts.anchor,
    anchorReason: (opts && opts.anchorReason) || "no block was looked up for this transaction",
  });
  wrapper.appendChild(dl);

  // The classifier's own caveat for the shapes where naming them is only
  // half the answer (dead container, both covenant tiers). It is a fixed
  // internal vocabulary, never CBOR — and dropping it here was how a row
  // could say "SOULBOUND-COVENANT" with nothing saying what that does and
  // does not prove.
  if (row.note) {
    wrapper.appendChild(el("p", { class: "card-note", text: row.note }));
  }

  // Structural-match qualifier — parity with the CLI human renderer
  // (issue #53 / PR #58). The script classifier matches by hex
  // pattern, not by cryptographic provenance — a custom locking
  // script whose bytes happen to fit one of these templates would
  // also classify as ft/nft/mut/dmint/commit. The qualifier nudges
  // the user to verify by ref / outpoint, not by the type badge
  // alone.
  const qualifier = _structuralQualifierNote(type, row);
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
  // appearing in the reveal-metadata's protocol list.
  //
  // THE TRIGGER IS A CBOR FLAG AND NOTHING ELSE, so the banner may not claim an
  // on-chain outcome. It used to say the tokens "are removed from circulation"
  // and that "subsequent transfers cannot reference the burned ref" — two
  // consensus-level assertions derived from one operator-supplied integer in
  // the reveal envelope. Nothing here reads the outputs, and nothing could:
  // `GlyphMetadata` has no field naming WHICH ref is burned (glyph/types.py),
  // so "the burned ref" is not something this payload identifies. A tx can
  // carry protocol 6 and still hand every ref straight back out to an ordinary
  // FT output; the marker does not stop it.
  //
  // The sibling markers below already state this correctly ("the marker is
  // purely a CBOR metadata flag", "not enforced by script"). BURN was the one
  // branch that dropped the caveat, and it was the branch making the largest
  // claim.
  const protocol = ((payload.metadata || {}).protocol || []).map(String);
  if (protocol.includes("6") || protocol.some((p) => p.endsWith("BURN"))) {
    return (
      "This transaction carries the Glyph BURN marker (protocol = 6) — the " +
      "deployer/holder DECLARED that an FT or NFT is destroyed. The marker is " +
      "purely a CBOR metadata flag: nothing in the locking scripts and nothing " +
      "in Radiant consensus enforces it, and the envelope does not name which " +
      "ref is burned. This tool does not verify that any token stopped " +
      "circulating — read the output rows below for what the scripts in this " +
      "transaction actually do."
    );
  }

  // Rarer Glyph protocol markers — detected from reveal-metadata protocol
  // list, not from output shapes (the locking scripts are ordinary NFT/MUT
  // shapes; the marker is purely a CBOR metadata flag). These are structural
  // pattern matches only; semantic correctness is not verified.

  // CONTAINER (7) — an NFT that groups other tokens/NFTs into a collection.
  if (protocol.includes("7") || protocol.some((p) => p.endsWith("CONTAINER"))) {
    return (
      "This transaction carries the Glyph CONTAINER marker (protocol = 7). " +
      "A CONTAINER is an NFT that acts as a collection envelope — other tokens " +
      "or NFTs reference it to signal membership in the collection. The locking " +
      "script is an ordinary Glyph NFT singleton; the CONTAINER role is " +
      "declared only in the reveal metadata."
    );
  }

  // ENCRYPTED (8) — an NFT whose payload is encrypted; requires companion key NFT.
  if (protocol.includes("8") || protocol.some((p) => p.endsWith("ENCRYPTED"))) {
    return (
      "This transaction carries the Glyph ENCRYPTED marker (protocol = 8). " +
      "The payload embedded in this NFT's reveal metadata is encrypted. " +
      "Decrypting it typically requires a companion key NFT held by the " +
      "intended recipient. The on-chain shape is an ordinary Glyph NFT; " +
      "the encryption is a metadata-layer convention, not enforced by script."
    );
  }

  // TIMELOCK (9) — a timelocked reveal; requires ENCRYPTED per the protocol spec.
  if (protocol.includes("9") || protocol.some((p) => p.endsWith("TIMELOCK"))) {
    return (
      "This transaction carries the Glyph TIMELOCK marker (protocol = 9). " +
      "A TIMELOCK signals that the reveal or transfer is subject to a " +
      "time-based condition encoded in the metadata. Per the Glyph protocol " +
      "spec, TIMELOCK requires ENCRYPTED to also be present. " +
      "The on-chain locking script is an ordinary Glyph NFT; " +
      "the time condition is a metadata-layer convention."
    );
  }

  // AUTHORITY (10) — an issuer authority NFT; grants permission to modify/issue tokens.
  if (protocol.includes("10") || protocol.some((p) => p.endsWith("AUTHORITY"))) {
    return (
      "This transaction carries the Glyph AUTHORITY marker (protocol = 10). " +
      "An AUTHORITY is a special NFT that confers issuer rights — the holder " +
      "can authorize operations (such as additional mints or metadata updates) " +
      "on a related token family. The on-chain script is an ordinary Glyph NFT; " +
      "the authority role is declared in the reveal metadata."
    );
  }

  // WAVE (11) — an on-chain name-claim NFT (requires NFT + MUT per spec).
  if (protocol.includes("11") || protocol.some((p) => p.endsWith("WAVE"))) {
    return (
      "This transaction carries the Glyph WAVE marker (protocol = 11). " +
      "WAVE is the Glyph on-chain naming protocol — this NFT claims a " +
      "human-readable name on Radiant. The name can be updated by spending " +
      "this output (it requires NFT + MUT per the protocol spec). " +
      "Note: WAVE support in pyrxd is currently deferred; this banner is " +
      "informational only."
    );
  }

  // DAT (3) — a data-storage NFT (raw data anchored on-chain).
  if (protocol.includes("3") || protocol.some((p) => p.endsWith("DAT"))) {
    return (
      "This transaction carries the Glyph DAT marker (protocol = 3). " +
      "DAT anchors arbitrary data on-chain inside a Glyph NFT's reveal " +
      "payload. The data blob is embedded in the CBOR metadata; the " +
      "locking script is an ordinary Glyph NFT singleton."
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
    // THE ROWS, not just a count of them. This branch used to assert from
    // `counts["dmint"]` alone that N contracts were "all sharing the same
    // token_ref" and that "total supply is reward × max_height × N" — claims
    // about three fields it never compared, while every dmint row carries all
    // three (_inspect_core's dmint classification emits token_ref_outpoint,
    // reward and max_height). N rows of type dmint is not N contracts of ONE
    // token: a transaction may carry dmint outputs for unrelated tokens, or for
    // one token on different terms, and the banner called it a parallel deploy
    // of a single token either way.
    const dmintRows = outputs.filter((o) => String(o.type).toLowerCase() === "dmint");
    const dmintCount = dmintRows.length;
    // `undefined === undefined` is true, so a field absent from every row would
    // "agree" vacuously and the check would pass by having nothing to compare.
    // Require it present before believing it matches.
    const agreesOn = (field) =>
      dmintRows.every(
        (o) => o[field] !== undefined && o[field] !== null && o[field] === dmintRows[0][field],
      );
    if (dmintOutput.height === 0 || dmintOutput.height === "0") {
      // V1 deploy reveal: typically ships N parallel contracts in one
      // tx (mainnet GLYPH had 32). One-contract deploys are also valid;
      // distinguish in the banner so callers don't confuse a multi-
      // contract V1 deploy with a V2 single-contract deploy.
      let parallel;
      if (dmintCount > 1) {
        const oneToken = agreesOn("token_ref_outpoint");
        const sameTerms = agreesOn("reward") && agreesOn("max_height");
        parallel = `${dmintCount} dMint contract UTXOs. `;
        if (!oneToken) {
          parallel +=
            `They do NOT all carry the same token_ref, so this is not one ` +
            `token deployed in parallel — check the token ref on each row ` +
            `before treating the contracts as interchangeable. `;
        } else if (sameTerms) {
          parallel +=
            `All ${dmintCount} carry the same token_ref and agree on reward ` +
            `and max_height, so they mint one token in parallel, claims race ` +
            `between them, and the supply ceiling is reward × max_height × ` +
            `${dmintCount}. `;
        } else {
          parallel +=
            `All ${dmintCount} carry the same token_ref, so claims race ` +
            `between them — but their reward / max_height are not all equal, ` +
            `so no single reward × max_height × ${dmintCount} figure ` +
            `describes this deploy. Read the per-row values below. `;
        }
      } else {
        parallel = "a single dMint contract UTXO. ";
      }
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
    // "The freshly-minted FT lives in a separate ft output in this same tx" and
    // "the canonical mint tx has 4 outputs: …" were stated unconditionally, on
    // every tx carrying a dmint output at height > 0 — including one with no ft
    // output at all. Both are checkable from rows this function has already
    // walked, so check them and say which way it came out. The canonical shape
    // is a claim about POSITIONS, so the test is positional.
    //
    // A PARTIAL OUTPUTS LIST ANSWERS NEITHER. `classify_raw_tx` takes an
    // `only_vout` that returns one row while `output_count` still reports the
    // whole transaction, and off a one-row list "this transaction has NO ft
    // output" would be the same unchecked claim wearing a new sentence — a
    // defect the fix invents for itself. So the completeness test gates BOTH
    // notes, not only the shape one.
    const outputsComplete =
      typeof payload.output_count !== "number" || outputs.length === payload.output_count;
    const ftRows = outputs.filter((o) => String(o.type).toLowerCase() === "ft");
    const typeAt = (i) => String((outputs[i] || {}).type || "").toLowerCase();
    const canonicalShape =
      outputs.length === 4 &&
      typeAt(0) === "dmint" &&
      typeAt(1) === "ft" &&
      typeAt(2).startsWith("op_return") &&
      typeAt(3) === "p2pkh";
    const shapeSentence =
      "the canonical mint tx has 4 outputs: [0] dMint continuation, [1] " +
      "75-byte FT-wrapped reward, [2] OP_RETURN message, [3] P2PKH change";
    let ftNote;
    let shapeNote;
    if (!outputsComplete) {
      ftNote =
        `Only ${outputs.length} of this transaction's ${payload.output_count} ` +
        `outputs were classified here, so where the minted FT sits is not ` +
        `decided from this view. `;
      shapeNote = `For reference, ${shapeSentence}. `;
    } else {
      ftNote =
        ftRows.length === 1
          ? `The freshly-minted FT is the ft output at vout ${ftRows[0].vout}. `
          : ftRows.length > 1
            ? `${ftRows.length} ft outputs are present here; the minted reward is one of them. `
            : "This transaction has NO ft output, so the minted reward is not " +
              "where the canonical mint shape puts it — read the rows below " +
              "rather than assuming a reward output exists. ";
      shapeNote = canonicalShape
        ? `Its outputs match the canonical mint shape — ${shapeSentence}. `
        : `Its ${outputs.length} outputs do NOT match the canonical mint shape ` +
          `in count or in order — ${shapeSentence}. Read the rows below. `;
    }
    return (
      `This is a dMint claim transaction (height ${dmintOutput.height} ` +
      `of ${dmintOutput.max_height}) — somebody spent the contract's ` +
      "previous output to mint themselves a token, and the contract " +
      "continues at the new dmint output. " +
      ftNote +
      shapeNote +
      "V1 is verified on mainnet against pinned golden vectors; V2 is " +
      "byte-identical by construction (R1 fix) but untested on chain. " +
      "Inspect the contract's deploy outpoint to see the original parameters." +
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
//
// ``payload`` is the classified row/script dict. It exists solely for the
// CSV disable-bit case: the stock p2pkh-csv qualifier tells the reader their
// spending input "must carry at least this delay", which is FALSE when bit 31
// is set — consensus ignores the lock. The CLI suppresses that sentence for
// the disabled shape (``_render_timelock_body``); so does this. Nothing here
// re-derives the flag: ``relative_lock_disabled`` is decided in Python.
function _structuralQualifierNote(type, payload) {
  // A recognised payload renames the type to `op_return-hashmark-v2` /
  // `op_return-msg`, so a lookup on the bare literal silently dropped the
  // OP_RETURN note from exactly the outputs that had just gained content.
  if (typeof type === "string" && type.startsWith("op_return-")) type = "op_return";
  if (type === "p2pkh-csv" && payload && payload.relative_lock_disabled === true) {
    return "Structural pattern match. Bit 31 of the sequence " +
           "(SEQUENCE_LOCKTIME_DISABLE_FLAG) is set, so consensus enforces no " +
           "relative lock at all and this output is spendable immediately — " +
           "the decoded delay is inert script bytes. pyrxd's builder refuses " +
           "to emit this shape.";
  }
  // OP_RETURN. The note used to end "Does NOT carry value" — printed six lines
  // under a row header that reads `${row.satoshis} sats`. For a nonzero-value
  // OP_RETURN the sentence is false AND it buries the fact worth stating: the
  // output does carry photons, no scriptSig can ever satisfy OP_RETURN, so
  // those photons are unrecoverable. `satoshis` exists on a fetched-tx row and
  // not on a pasted script, so the amount is quoted only where it is known and
  // the script-card path keeps the general statement.
  if (type === "op_return") {
    const known = payload && payload.satoshis !== undefined && payload.satoshis !== null;
    const sats = known ? Number(payload.satoshis) : NaN;
    let valueNote;
    if (Number.isFinite(sats) && sats > 0) {
      valueNote =
        `This output carries ${sats} photons and no scriptSig can ever ` +
        `satisfy OP_RETURN, so those photons are destroyed — they are not ` +
        `spendable by anyone, including the sender.`;
    } else if (Number.isFinite(sats)) {
      valueNote =
        "This output carries no photons, which is the usual shape: nothing " +
        "can satisfy OP_RETURN, so any photons paid to one would be destroyed.";
    } else {
      valueNote =
        "Nothing can satisfy OP_RETURN, so any photons paid to one are " +
        "destroyed; paste the transaction to see what this output was funded " +
        "with.";
    }
    return (
      "OP_RETURN: an unspendable data carrier, not part of the Glyph " +
      "protocol. Used by some non-Glyph protocols (legacy Atomicals-style " +
      "markers, third-party tooling) to embed arbitrary bytes on-chain. " +
      valueNote
    );
  }
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
    // NOT "the NFT singleton anchor that every Glyph FT deploy carries …
    // not a separately-mintable collectible". That sentence was printed for
    // EVERY commit-nft row, and a plain NFT mint produces one: `prepare_commit`
    // (glyph/builder.py) sets `is_nft = GlyphProtocol.NFT in metadata.protocol`
    // and `build_commit_locking_script` then emits OP_2/SINGLETON, which is
    // exactly what `is_commit_nft_script` matches. So the note told the holder
    // of a standalone collectible that their own commit output was somebody
    // else's FT-deploy artifact — and this page's own tx banner for that shape
    // ("commit-nft without commit-ft") says the opposite. The FT-deploy framing
    // is correct only where `_detectTxShape` already states it: on the branch
    // guarded by commit-ft AND commit-nft together.
    "commit-nft": "Structural pattern match. The payload_hash is an opaque " +
        "commitment to the reveal-tx CBOR. The single byte separating this " +
        "from a commit-ft is OP_REFTYPE_OUTPUT = 2 (SINGLETON): the commit " +
        "requires its reveal to produce a singleton output. pyrxd emits this " +
        "shape for any metadata carrying the NFT protocol marker — a " +
        "standalone NFT, a mutable / container / WAVE NFT, and the authority " +
        "NFT alongside an FT deploy alike — so this output on its own does " +
        "not say which of those it anchors; the reveal tx does.",
    dmint: "Structural pattern match: does NOT verify the contract_ref " +
        "points to a valid mint chain or that the parameters match a " +
        "deployed token.",
    p2sh: "Pay-to-script-hash. The redeem script this commits to is not " +
        "on-chain until the output is spent, so nothing further can be " +
        "said about what it does.",
    "p2pkh-cltv": "Structural pattern match. The tool cannot tell you whether " +
        "the lock has elapsed — that needs the chain tip. A spending tx " +
        "must set nLockTime to at least this value and use a non-final " +
        "nSequence on the input. The encoded value is a floor on that " +
        "nLockTime, not a height at which the output turns spendable — " +
        "consensus requires nLockTime to be strictly less than the " +
        "containing block's height, so see 'earliest spend'.",
    "p2pkh-csv": "Structural pattern match. The tool cannot tell you whether " +
        "the lock has elapsed — that needs this output's confirmation " +
        "height. The spending input's nSequence must carry at least this " +
        "delay and the tx must be version 2 or later.",
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
    "container-legacy": "Dead container output (unspendable)",
    p2pkh: "P2PKH locking script",
    p2sh: "P2SH locking script",
    "p2pkh-cltv": "Time-locked P2PKH (absolute / CLTV)",
    "p2pkh-csv": "Time-locked P2PKH (relative / CSV)",
    "soulbound-covenant": "Soulbound NFT covenant",
    "self-replicating-covenant": "Self-replicating covenant",
    op_return: "OP_RETURN data output",
    // A HashMark is a READABLE data output, and calling it "OP_RETURN data output"
    // under an `UNKNOWN` badge sat directly above a panel saying VERIFIED. Two
    // elements on one card, describing the same output, disagreeing about whether
    // anything had been understood.
    "op_return-hashmark-v1": "HashMark record (v1 — a time, and no signer)",
    "op_return-hashmark-v2": "HashMark record (v2 — signed)",
    unknown: "Unrecognised script",
  };
  // `type` is now `op_return-hashmark-v2` / `op_return-msg` for a recognised
  // payload, so a map keyed on the bare literal loses the title AND the structural
  // note for exactly the outputs that gained content.
  const baseType = type.startsWith("op_return") ? "op_return" : type;
  const wrapper = card(titleMap[type] || titleMap[baseType] || "Locking script", scriptBadgeKind(type));

  const dl = el("dl", { class: "kv-list" });
  appendOpReturnPayload(dl, payload);
  dl.appendChild(kv("type", type));
  if (payload.length !== undefined) {
    dl.appendChild(kv("length", `${payload.length} bytes`));
  }
  if (payload.owner_pkh) dl.appendChild(kv("owner pkh (20 hex)", payload.owner_pkh));
  if (payload.ref_txid) dl.appendChild(kv("ref txid", payload.ref_txid));
  if (payload.ref_vout !== undefined) dl.appendChild(kv("ref vout", payload.ref_vout));
  if (payload.ref_outpoint) dl.appendChild(kv("ref outpoint", payload.ref_outpoint));
  // TWO sibling renderers read these rows — this one and renderOutputRow. The first
  // fix for the dropped delegate base only patched the other, and the drift guard
  // caught it. A delegate-bound commit's reveal is rejected by the covenant without a
  // burn output naming this base, so omitting it here showed a script that cannot be
  // spent as it stands as though it were an ordinary commit.
  if (payload.delegate_base_ref) dl.appendChild(kv("delegate base ref", payload.delegate_base_ref));
  if (payload.child_ref_outpoint) {
    dl.appendChild(kv("child ref outpoint", payload.child_ref_outpoint));
  }
  if (payload.authority_ref) {
    dl.appendChild(kv("authority ref", payload.authority_ref));
  }
  // The dead pre-0.15.0 container. The title and the note both say so, but
  // the verdict also belongs in the field list where a reader scanning
  // key/value pairs will meet it. CLI parity: `*** UNSPENDABLE ***`.
  if (payload.spendable === false) {
    dl.appendChild(kv("spendable", "*** UNSPENDABLE ***", "kv-warning"));
  }
  if (payload.payload_hash) dl.appendChild(kv("payload hash (sha256)", payload.payload_hash));
  if (payload.script_hash) dl.appendChild(kv("script hash (20 hex)", payload.script_hash));

  // Time-lock fields. `locktime_units` is the count in whatever unit
  // `locktime_basis` names, which is the number a reader actually wants;
  // `locktime_value` is the raw on-stack integer and differs from it for CSV
  // (it carries the type flag in bit 22). `locktime_earliest` is CLTV-only
  // and is DERIVED IN PYTHON (_inspect_core) — the encoded value is a floor
  // on the spending tx's nLockTime, and IsFinalTx wants that strictly less
  // than the containing block's height, so the first block that can carry the
  // spend is one past it. This renderer must not re-derive consensus facts.
  //
  // ORDERING IS LOAD-BEARING here, and it mirrors the CLI's
  // `_render_timelock_body` deliberately: when bit 31
  // (SEQUENCE_LOCKTIME_DISABLE_FLAG) is set, consensus ignores the relative
  // lock entirely, and a reader who meets "delay: 144 blocks" before the
  // "…but it enforces nothing" line leaves believing the opposite of the
  // truth. These shapes are HTLC refund legs. Warning first (as a banner
  // above the whole list), delay second, and the delay relabelled "(ignored)"
  // so a row read in isolation still cannot mislead.
  const relativeLockDisabled = payload.relative_lock_disabled === true;
  if (payload.locktime_basis) {
    dl.appendChild(kv("lock basis", payload.locktime_basis));
    dl.appendChild(kv("raw value", payload.locktime_value));
    if (relativeLockDisabled) {
      dl.appendChild(kv(
        "relative lock",
        "*** RELATIVE LOCK DISABLED — SPENDABLE IMMEDIATELY ***",
        "kv-warning",
      ));
    }
    dl.appendChild(kv(relativeLockDisabled ? "delay (ignored)" : "lock units", payload.locktime_units));
    if (payload.locktime_earliest !== undefined) {
      dl.appendChild(kv("earliest spend", payload.locktime_earliest));
    }
  }

  // Soulbound / self-replicating covenant fields.
  if (payload.variant) dl.appendChild(kv("covenant variant", payload.variant));
  if (payload.transferability) dl.appendChild(kv("transferability", payload.transferability));
  if (payload.bound_ref_outpoint) dl.appendChild(kv("bound ref", payload.bound_ref_outpoint));
  if (payload.has_self_replication !== undefined) {
    dl.appendChild(kv("self-replication branch", String(payload.has_self_replication)));
  }
  if (payload.has_burn_branch !== undefined) {
    dl.appendChild(kv("burn branch", String(payload.has_burn_branch)));
  }

  // Token-bearing summary on an unnamed script. Whether a shape nobody
  // recognises carries a ref is the fact worth surfacing: spending such a
  // UTXO as plain funding destroys the token it carries. `null` means the
  // script did not decode, so absence was never established.
  //
  // `input_refs` is the CARRIED set (0xd0 / 0xd8) and `referenced_refs` the
  // set the script only names (0xd1 require, 0xd2 / 0xd3 disallow). Python
  // splits them; this side must keep them apart, because only the first
  // burns when the output is spent.
  if (payload.token_bearing !== undefined) {
    dl.appendChild(kv(
      "token-bearing",
      payload.token_bearing === null ? "unknown (script does not decode)" : String(payload.token_bearing),
    ));
    for (const row of payload.input_refs || []) {
      dl.appendChild(kv(`input ref (${row.opcode})`, row.ref_outpoint));
    }
    for (const row of payload.referenced_refs || []) {
      dl.appendChild(kv(`referenced ref (${row.opcode})`, `${row.ref_outpoint} — named, not carried`));
    }
  }

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

  // BEFORE the list, not after it. The delay this qualifies is rendered
  // below, and "the delay below … enforces nothing" is only true — and only
  // read in time — in this position. Wording is the CLI's verbatim.
  if (relativeLockDisabled) {
    wrapper.appendChild(el("p", {
      class: "warning-banner warning-banner-lead",
      text: "Bit 31 (SEQUENCE_LOCKTIME_DISABLE_FLAG) is set, so consensus " +
            "ignores the relative lock entirely. The delay below is encoded " +
            "in the script but enforces nothing. pyrxd's builder refuses to " +
            "emit this shape.",
    }));
  }

  // A PASTED SCRIPT HAS NO TRANSACTION, so it has no block — not because this page
  // declined to look, but because there is nothing to look up. HashMark 7.6's
  // point-in-time form needs the block that carried the mark, so it is unavailable
  // here by construction. Saying that beats an empty row, which reads as "we did not
  // bother" and invites the reader to assume it would have been fine.
  appendMarkVerdict(wrapper, payload, {
    anchorReason:
      "a pasted script carries no transaction, so there is no block to place it in. " +
      "Paste the transaction id instead and this page will fetch one.",
  });
  wrapper.appendChild(dl);

  if (type === "unknown") {
    wrapper.appendChild(el("p", {
      class: "card-note",
      text: "This doesn't match any known Glyph or P2PKH script template. " +
            "It may be a custom contract, a different protocol, or malformed bytes.",
    }));
  }

  if (payload.token_bearing === true) {
    wrapper.appendChild(el("p", {
      class: "card-note",
      text: "TOKEN-BEARING: the opcode-aware walk found OP_PUSHINPUTREF-family " +
            "refs in this script. Do not spend it as plain funding — a " +
            "ref-carrying UTXO fed in as a fee input destroys the token it carries.",
    }));
  } else if (payload.token_bearing === null) {
    wrapper.appendChild(el("p", {
      class: "card-note",
      text: "The script does not decode as an opcode stream, so the walk could " +
            "not rule out an input ref. Treat it as token-bearing.",
    }));
  }

  // The classifier attaches a `note` to the shapes where recognising the shape
  // is only half the answer: the dead pre-0.15.0 container (whose holder would
  // otherwise go hunting for a wallet that can move it — none can) and the two
  // covenant tiers (where the note is what keeps a marker match from reading as
  // proof). The text comes from a fixed internal vocabulary, never from CBOR.
  if (payload.note) {
    wrapper.appendChild(el("p", { class: "card-note", text: payload.note }));
  }

  // Structural-match qualifier (issue #53 / PR #58). Same wording the
  // CLI's _render_script_human emits.
  const qualifier = _structuralQualifierNote(type, payload);
  if (qualifier) {
    wrapper.appendChild(el("p", { class: "structural-note", text: qualifier }));
  }

  return wrapper;
}

// Every badge kind the stylesheet actually defines (inspect.css
// `.badge-*`). Anything outside this set would emit a class with no rule
// and render unstyled, so `scriptBadgeKind` maps to the nearest one that
// exists instead of passing the raw type through.
const _BADGE_KINDS = new Set(["ft", "nft", "mut", "dmint", "commit", "p2pkh", "hashmark", "unknown"]);

// Map a script `type` value (which may include a hyphen, e.g. "commit-ft")
// to a CSS-safe badge kind. Hyphenated commit variants share the
// `commit` badge colour.
function scriptBadgeKind(type) {
  if (type.startsWith("commit")) return "commit";
  // Time-locked P2PKH is still P2PKH-shaped at the tail; borrow its colour.
  if (type === "p2pkh-cltv" || type === "p2pkh-csv") return "p2pkh";
  // The covenant shapes bind an NFT singleton; borrow the NFT colour.
  if (type === "soulbound-covenant" || type === "self-replicating-covenant") return "nft";
  // An authority-gated item and a delegate token are both NFT-shaped singletons
  // wearing an extra ref opcode; borrow the NFT colour rather than reading as
  // "unknown", which is what the classifier says when it could not tell.
  if (type === "authority-gated-nft" || type === "delegate-token") return "nft";
  // A HashMark IS recognised — by the same classifier that produced the verdict
  // beside the badge — so it must not wear the colour that means "could not tell".
  if (type.startsWith("op_return-hashmark")) return "hashmark";
  // A burn proof is an OP_RETURN refinement, like the message and hashmark
  // variants; a DAT commit is a commit variant.
  if (type === "op_return-burn") return "unknown";
  // No badge colour is defined for the dead container shape or for P2SH;
  // reuse the `unknown` styling rather than emitting a class the stylesheet
  // lacks.
  return _BADGE_KINDS.has(type) ? type : "unknown";
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

// `electrumxRpc`, `fetchRawTxFromElectrumx`, `resolveMarkAnchor` and
// `stripControlChars` live in shared.js. The socket loop carries four guards a
// second copy would eventually be missing one of — a frame cap before JSON.parse,
// a mismatched-id frame discarded without disarming the timeout, a sanitised
// server error string, and a hard timeout — and the public /verify/ page makes
// exactly the same three calls over it.

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

  // PAYLOAD BINDING — a SECOND fetch. The first pass classifies the transaction and,
  // if it carries a reveal, names the outpoint that reveal's attributed input spent.
  // That output is the commit whose `payload_hash` is the only thing binding the
  // displayed name/attrs to anything, and the classifier is network-free, so without
  // this the verdict can only ever read "unchecked".
  //
  // BOUNDED BY CONSTRUCTION: one attributed input, one prevout, one extra round trip.
  // Best-effort throughout — a failure here leaves the first pass standing and the
  // verdict degrades to its own stated "unchecked" reason rather than erroring out.
  let result;
  try {
    let pyResult = pyGlueFetch(txid, rawHex);
    result = pyResult.toJs({ dict_converter: Object.fromEntries });
    pyResult.destroy();

    const outpoint = result && result.payload && result.payload.metadata
      ? result.payload.metadata.input_outpoint
      : null;
    if (outpoint) {
      statusEl.textContent = "checking payload binding…";
      const prevTxid = String(outpoint).slice(0, String(outpoint).lastIndexOf(":"));
      let prevRawHex = null;
      try {
        prevRawHex = await fetchRawTxFromElectrumx(prevTxid);
      } catch {
        prevRawHex = null;  // stays "unchecked", with its own reason
      }
      if (prevRawHex) {
        pyResult = pyGlueFetch(txid, rawHex, prevRawHex);
        result = pyResult.toJs({ dict_converter: Object.fromEntries });
        pyResult.destroy();
      }
    }
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

  // THE BLOCK, and only when there is a mark to place in one. A HashMark's whole
  // claim is "no later than the block that confirms this", so the block is not
  // decoration — but it costs two more round trips, and an ordinary transfer has
  // nothing to gain from them.
  if (carriesAMark(result)) {
    statusEl.textContent = "placing the mark in a block…";
    result.payload.mark_anchor = await resolveMarkAnchor(pyMarkAnchor, txid);
  }

  renderResult(result);
}

// ---------------------------------------------------------------------
// Kick off
// ---------------------------------------------------------------------

boot();
