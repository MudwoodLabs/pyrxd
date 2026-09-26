// verify.js — the public HashMark check.
//
// LOADED SECOND. `../inspect/shared.js` must already have run; see its own header
// for the loading contract. Everything this page could be checked against the
// inspector on — the runtime boot, the wire, the verdict colour, the file-check
// mechanics, and the two sentences that are claims — comes from there.
//
// WHO THIS IS FOR, because it is the whole reason the file exists. /inspect/ is a
// developer tool inside SDK documentation: it assumes you know what a Glyph script
// is and shows you every field of one. This page assumes nothing. Someone was handed
// a transaction number and a claim attached to it, and wants to know what that claim
// is worth. So there is one input, four questions in plain English, and the limits
// of the answer stated before the answer rather than after it.
//
// THE CLAIM DISCIPLINE, which is the only thing here that can really go wrong:
//
//   * The claim is that someone knew this digest by this block and, if the signature
//     verifies, that this key had signed it by then. NOT that the key's holder put it
//     in that block: the signed statement does not bind the transaction, so a genuine
//     record can be copied into anyone's. Never authorship, never ownership, never
//     location, and never evidence that the document is true.
//   * `UNVERIFIABLE` — rendered NOT CHECKED — is "this browser did not check",
//     never "the claim failed". It used to be the ONLY outcome here: pyrxd installs
//     under Pyodide with `deps=False` and coincurve has no pure-Python wheel, so
//     every mark read "not checked" and this page's headline question went
//     unanswered. `shared.js` now installs a vendored secp256k1 as a recovery
//     backend, so the verdict is a real VERIFIED or DOES NOT VERIFY. NOT CHECKED
//     remains for the tab where that curve does not load, and it must stay neutral:
//     painting an honest signer's mark with the error colour because of a library
//     missing from the READER's machine is the single worst thing this page could do.
//   * Every status word and every sentence that judges anything comes out of
//     `pyrxd.glyph._inspect_core` through `glue.py` — the same table `pyrxd glyph
//     inspect` and `pyrxd verify` print from. Nothing here decides what a verdict
//     means; this file decides what a stranger reads first.
//
// Trust boundary: every string written to the DOM goes through `textContent`, never
// `innerHTML`. The Python side sanitises anything publisher-chosen before it crosses
// the bridge; `safeText` doubles that at the render layer for the one field an
// attacker picks (the label).

"use strict";

// ---------------------------------------------------------------------
// DOM handles
// ---------------------------------------------------------------------

const STATUS_BLOCK = document.getElementById("loading-status");
const PROGRESS = document.getElementById("load-progress");
const READY_BLOCK = document.getElementById("ready-content");
const ERROR_BLOCK = document.getElementById("error-content");
const ERROR_PRE = document.getElementById("error-block");
const BUILD_VERSION = document.getElementById("build-version");
const INPUT_BOX = document.getElementById("tx-input");
const CHECK_BTN = document.getElementById("check-btn");
const CLEAR_BTN = document.getElementById("clear-btn");
const SHARE_BTN = document.getElementById("share-btn");
const FORM_STATUS = document.getElementById("form-status");
const RESULT_BLOCK = document.getElementById("result-block");
const ONBOARDING = document.getElementById("onboarding");
const EXAMPLE_CHIPS = document.querySelectorAll(".example-chip");

// THE WHEEL, THE MANIFEST AND glue.py LIVE UNDER /inspect/ AND ARE READ FROM THERE.
// The docs CI step builds them once into `docs/inspect_static/inspect/wheels/` and
// SHA-256 pins all three in one manifest. A second copy staged under /verify/ would
// be a second thing for that step to keep in step, and the copy that goes stale is
// always the one nobody is looking at — which here would mean a public page checking
// marks with an old decoder while the developer tool used a current one.
const WHEELS_BASE = new URL("../inspect/wheels/", document.baseURI).toString();
const GLUE_URL = new URL("../inspect/glue.py", document.baseURI).toString();
// The secp256k1 the Python side does not have. Same copy as /inspect/, for the
// same reason as the wheel: two curves deciding whether a stranger's mark is
// genuine is one curve too many.
const CURVE_URL = new URL("../inspect/secp256k1-bridge.js", document.baseURI).toString();

// Bridge handles, filled in by boot. `bridges` is passed whole to the shared file
// check; the two this file calls directly are pulled out for readability.
let bridges = null;
let pyRun = null;         // glue.run(text) -> dict  (offline classification)
let pyFetch = null;       // glue.inspect_txid_with_raw(txid, raw_hex) -> dict

// A transaction number, as typed. 64 hex characters, either case.
const TXID_RE = /^[0-9a-fA-F]{64}$/;

// ---------------------------------------------------------------------
// Status / error helpers
// ---------------------------------------------------------------------

function showError(message) {
  console.error(message);
  STATUS_BLOCK.hidden = true;
  ERROR_BLOCK.hidden = false;
  // textContent only — never innerHTML.
  ERROR_PRE.textContent = String(message);
}

function setProgress(pct) {
  if (PROGRESS) PROGRESS.value = Math.max(0, Math.min(100, pct));
}

function setFormStatus(text) {
  if (FORM_STATUS) FORM_STATUS.textContent = text || "";
}

// ---------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------

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

  bridges = runtime.bridges;
  pyRun = runtime.bridges.run;
  pyFetch = runtime.bridges.inspectTxidWithRaw;

  STATUS_BLOCK.hidden = true;
  READY_BLOCK.hidden = false;
  if (runtime.gitSha) BUILD_VERSION.textContent = `build: ${runtime.gitSha}`;
  enableForm();
  hydrateFromUrl();
}

function enableForm() {
  for (const node of [INPUT_BOX, CHECK_BTN, CLEAR_BTN, SHARE_BTN]) {
    if (node) node.disabled = false;
  }
  CHECK_BTN.addEventListener("click", () => { onCheck(); });
  CLEAR_BTN.addEventListener("click", onClear);
  SHARE_BTN.addEventListener("click", onShare);
  INPUT_BOX.addEventListener("keydown", (ev) => {
    if (ev.key === "Enter") {
      ev.preventDefault();
      onCheck();
    }
  });
  for (const chip of EXAMPLE_CHIPS) {
    chip.addEventListener("click", () => {
      INPUT_BOX.value = chip.getAttribute("data-input") || "";
      onCheck();
    });
  }
  INPUT_BOX.focus();
}

// ---------------------------------------------------------------------
// Check / clear / share
// ---------------------------------------------------------------------

// A CHECK IS NOT REENTRANT. Two overlapping checks race to write the same result
// block, and the one that finishes last wins regardless of which the reader asked
// for — so a slow answer about the wrong transaction can overwrite a fast answer
// about the right one. The button is disabled for the duration, and a token guards
// the hydrate path, which can fire while a click is already in flight.
let inFlight = 0;

async function onCheck() {
  const text = (INPUT_BOX.value || "").trim();
  if (!text) {
    // BUMP THE TOKEN even here. Submitting nothing is still a new intention, and a
    // lookup already in flight must not land on a screen the reader has just emptied.
    inFlight += 1;
    renderEmpty();
    setFormStatus("Paste a transaction number first.");
    return;
  }
  const token = ++inFlight;
  CHECK_BTN.disabled = true;
  try {
    const result = await lookUp(text, token);
    if (token !== inFlight) return;
    renderResult(result);
    updateUrlForInput(text);
  } finally {
    if (token === inFlight) {
      CHECK_BTN.disabled = false;
      setFormStatus("");
    }
  }
}

// Turn what was typed into a classification, with the block attached when there is
// a mark to place in one.
//
// TWO SHAPES, because two things are the same shape as each other and neither is
// the same shape as the third. A TRANSACTION NUMBER is 64 hex characters, and so is
// a DIGEST — nothing about the string says which. Anything else is classified
// offline: an outpoint (`<txid>:<vout>`) or a contract id names a transaction, and
// that transaction is looked up; everything else is read as a pasted script. A
// digest typed in here will be looked up as
// a transaction, find nothing, and be told exactly that, which is the honest answer:
// there is no digest-to-transaction index on Radiant.
async function lookUp(text, token) {
  if (!TXID_RE.test(text)) {
    setFormStatus("Reading what you pasted…");
    let classified;
    try {
      classified = fromPy(pyRun(text));
    } catch (err) {
      return bridgeError(err);
    }
    if (classified && !classified.ok) {
      // The classifier's refusal is written for /inspect/, where the reader is a
      // developer holding a script. Lead with the sentence that helps a stranger,
      // and keep the classifier's own words below it — never instead of them.
      return {
        ok: false,
        form: "error",
        error: "That is not a transaction number, and it does not read as a HashMark record.",
        hint:
          "A transaction number is 64 letters and numbers (0-9 and a-f), with nothing else " +
          "around it. If a link brought you here, check it was not cut short.",
        detail: [classified.error, classified.hint].filter(Boolean).map(stripControlChars).join(" "),
      };
    }
    // A POINTER TO A TRANSACTION IS LOOKED UP, NOT JUDGED. `<txid>:<vout>` and a 72-character
    // contract id both NAME an output of a transaction; neither is a record. This page used to
    // hand them straight to the renderer, which told the reader "it is not a HashMark record" —
    // about a real mark, given in a form that points at it. The transaction it names is what a
    // mark is checked by, so that is what is fetched, and the page says it did so.
    const named = transactionNamedBy(classified);
    if (named) {
      const result = await lookUpTransaction(named.txid, token);
      if (result) result.named_by = named;
      return result;
    }
    return classified;
  }

  return lookUpTransaction(text.toLowerCase(), token);
}

// The transaction an outpoint or a contract id points at, or null. Only those two forms, and
// only with a well-formed txid: the classifier already refused anything else, and this does not
// get to widen what counts as a transaction number.
function transactionNamedBy(classified) {
  if (!classified || !classified.ok) return null;
  if (classified.form !== "outpoint" && classified.form !== "contract") return null;
  const payload = classified.payload || {};
  const txid = typeof payload.txid === "string" ? payload.txid.toLowerCase() : "";
  if (!TXID_RE.test(txid)) return null;
  return { form: classified.form, txid, vout: payload.vout };
}

// One transaction, by number: fetch it, classify it, and place any mark in a block.
async function lookUpTransaction(txid, token) {
  setFormStatus("Looking up the transaction…");
  let rawHex;
  try {
    rawHex = await fetchRawTxFromElectrumx(txid);
  } catch (err) {
    return lookupFailure(err);
  }
  if (token !== inFlight) return null;

  setFormStatus("Reading the record…");
  let result;
  try {
    // THE PANEL LIMIT IS ALSO THE CHECKING LIMIT. The classifier checks the signatures of the
    // first MAX_MARK_PANELS records only (and of any later byte-for-byte copy of one of them,
    // which costs nothing), so a transaction of thousands of signed records costs this tab no
    // more curve work than the page draws. One number, passed here, so the two cannot drift.
    result = fromPy(pyFetch(txid, rawHex, MAX_MARK_PANELS));
  } catch (err) {
    return bridgeError(err);
  }

  // THE BLOCK, and only when there is a mark to place in one. A HashMark's whole
  // claim is "no later than the block that confirms this", so the block is not
  // decoration — but it costs two more round trips, and a transaction with no mark
  // in it has nothing to gain from them.
  if (carriesAMark(result)) {
    setFormStatus("Finding the block…");
    const anchor = await resolveMarkAnchor(bridges.markAnchor, txid);
    if (token !== inFlight) return null;
    result.payload.mark_anchor = anchor;
  }
  return result;
}

// TWO DIFFERENT FACTS, TOLD APART. A server that answers "I have no such
// transaction" and a server nobody could reach arrive here as the same rejected
// promise, and this page's first version rendered both as "the server did not
// answer — try again in a moment". That is the wrong advice for the case a reader
// will actually hit, which is a wrong or mistyped number: retrying will never fix
// it, and the sentence sends them away from the one thing that would.
//
// `err.kind` comes from `electrumxRpc` in shared.js and is structural — not a
// match on the daemon's English, which varies by server and version.
//
// THE SERVER'S OWN WORDS ARE ALWAYS CARRIED, in `detail`. Leading with plain
// language is not the same as hiding the reason, and a page that replaced the
// reason with a friendlier guess would be the worse failure of the two.
function lookupFailure(err) {
  const detail = stripControlChars(String((err && err.message) || err));
  const kind = (err && err.kind) || "unknown";

  if (kind === "refused") {
    // By what the frame says (`refusalReason`, shared.js). A refusal is not always about the
    // transaction: a busy or failing server refuses in the same frame shape, and telling that
    // reader "retrying will not change this answer" sent them away from the one thing that works.
    const reason = refusalReason(err);
    const sameShape =
      "A fingerprint and a transaction number are the same shape — 64 letters and numbers — " +
      "and a fingerprint locates nothing on its own. ";
    let hint;
    if (reason === "absent") {
      hint =
        "The server's node has no transaction with that number, in its chain or among those " +
        "waiting to join it. The number may be wrong, or the transaction may not have reached " +
        "that node yet — one sent moments ago may not have. " + sameShape +
        "Check what you were given.";
    } else if (reason === "server") {
      hint =
        "The server declined to answer this time — it was busy, or something failed on its " +
        "side. Nothing was learned about the mark either way. Trying again in a moment may work.";
    } else if (reason === "request") {
      hint =
        "The server refused the request itself, so asking again the same way will get the same " +
        "answer. " + sameShape + "Check what you were given.";
    } else {
      hint =
        "The server's reply does not say whether it has no such transaction or could not answer " +
        "this time, so this page will not guess. " + sameShape +
        "Check what you were given, and if it is right, try again later.";
    }
    return {
      ok: false,
      form: "error",
      error: "The blockchain server answered, and it did not give back a transaction for that number.",
      hint,
      detail,
    };
  }
  if (kind === "unreachable") {
    return {
      ok: false,
      form: "error",
      error: "The blockchain server this page uses could not be reached.",
      hint:
        "Nothing was learned about the mark either way — this is a fact about the lookup, " +
        "not about the record. Trying again in a moment may work.",
      detail,
    };
  }
  if (kind === "malformed") {
    return {
      ok: false,
      form: "error",
      error: "The blockchain server's answer could not be used.",
      hint:
        "The reply did not have the shape a transaction has, so it was refused rather than " +
        "read. Nothing was learned about the mark either way.",
      detail,
    };
  }
  // THE SERVER'S ANSWER WAS WRONG, not missing and not unreadable: what came back is whole
  // bytes, and they hash to a different number from the one asked for. Retrying
  // the same server may well get the same wrong answer, so this does not promise that it
  // helps; and it says nothing about whether the number itself is right, because a wrong
  // number gets "no such transaction" from an honest server, never somebody else's bytes.
  if (kind === "mismatch") {
    return {
      ok: false,
      form: "error",
      error: "The blockchain server's answer is not the transaction that was asked for.",
      hint:
        "A transaction number is a fingerprint of the transaction's own bytes, and the bytes that " +
        "came back do not have that fingerprint — so the answer was refused rather than read. " +
        "Nothing was learned about the mark either way. `pyrxd verify` in a terminal makes the " +
        "same check and can be pointed at a different server.",
      detail,
    };
  }
  // AN UNTAGGED REJECTION GETS THE WEAKER SENTENCE, and this branch exists precisely
  // so it cannot borrow the one above. "The reply did not have the shape a transaction
  // has" is a CLAIM about what arrived — true for a `malformed` rejection, and
  // something nobody checked for a rejection from a path that tags nothing. Reusing
  // it here would be the same conflation this function was written to fix, one level
  // further down: two different facts told in one set of words, the confident set.
  return {
    ok: false,
    form: "error",
    error: "The lookup did not finish.",
    hint:
      "This page could not tell why, so it is not going to guess. Nothing was learned " +
      "about the mark either way — the text below is what came back.",
    detail,
  };
}

// An error from the Python bridge, in words a stranger can act on — with the
// original kept underneath rather than swallowed.
function bridgeError(err) {
  return {
    ok: false,
    form: "error",
    error: "That could not be read as a transaction number or as a HashMark record.",
    hint:
      "If you were given a link, open it again in full — a truncated one lands here. " +
      "If you typed it, a transaction number is 64 letters and numbers with nothing else " +
      "around it.",
    detail: stripControlChars(String((err && err.message) || err)),
  };
}

function onClear() {
  // "START OVER" MUST ACTUALLY STOP. Without this the token of an in-flight lookup
  // still matches, so a result the reader asked to be rid of appears a second later
  // and the button reads as broken — a correct answer to a question that was
  // withdrawn is still the wrong thing on screen.
  inFlight += 1;
  INPUT_BOX.value = "";
  renderEmpty();
  setFormStatus("");
  CHECK_BTN.disabled = false;
  const url = new URL(window.location.href);
  url.searchParams.delete("input");
  window.history.replaceState({}, "", url.toString());
  INPUT_BOX.focus();
}

function onShare() {
  // Quiet failure: clipboard APIs are best-effort and may be denied; the URL is in
  // the address bar either way, and saying so is more use than a dead button.
  const url = window.location.href;
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(url).then(
      () => flashShare("Link copied"),
      () => flashShare("Copy denied — the link is in the address bar"),
    );
  } else {
    flashShare("The link is in the address bar");
  }
}

function flashShare(msg) {
  const original = SHARE_BTN.textContent;
  SHARE_BTN.textContent = msg;
  setTimeout(() => { SHARE_BTN.textContent = original; }, 1800);
}

// `input`, the SAME parameter name /inspect/ uses, so one link opens on either page.
// A reader sent a link by someone technical should not find it inert on the plain
// page, and vice versa.
function updateUrlForInput(text) {
  const url = new URL(window.location.href);
  url.searchParams.set("input", text);
  window.history.replaceState({}, "", url.toString());
}

function hydrateFromUrl() {
  const initial = new URLSearchParams(window.location.search).get("input");
  if (initial && INPUT_BOX) {
    INPUT_BOX.value = initial;
    onCheck();
  }
}

// ---------------------------------------------------------------------
// Rendering — every DOM write is textContent. No innerHTML anywhere.
// ---------------------------------------------------------------------

function el(tag, opts) {
  const node = document.createElement(tag);
  if (!opts) return node;
  if (opts.class) node.className = opts.class;
  if (opts.text !== undefined) node.textContent = String(opts.text);
  return node;
}

// DEFENCE IN DEPTH on the one string an attacker picks. `label` is publisher-chosen
// and reaches this page already sanitised — the decoder refuses a non-canonical
// label outright (spec 5.4) and `glue.py` strips control, format and combining
// codepoints from every payload string on the way across. Stripping again here costs
// nothing and means a future payload field, or a change on either of those two
// layers, cannot put a bidi override into a sentence a reader is using to decide
// whether two things are the same.
function safeText(value) {
  return stripControlChars(value === null || value === undefined ? "" : String(value));
}

function para(text, cls) {
  return el("p", { class: cls || "answer-body", text });
}

// A label/value row for the identifiers a reader may want to copy or compare.
function fact(label, value, valueClass) {
  const row = el("div", { class: "fact" });
  row.appendChild(el("dt", { class: "fact-label", text: label }));
  row.appendChild(el("dd", { class: `fact-value${valueClass ? " " + valueClass : ""}`, text: safeText(value) }));
  return row;
}

// The headline. `verdictClass` is shared.js's, so the colour vocabulary is the same
// one the inspector uses — a neutral class for NOT CHECKED, the error colour only
// for a verdict that really failed.
//
// COLOUR IS NEVER THE ONLY SIGNAL: the status is printed in words, so a reader who
// cannot separate the greens from the reds, or who is looking at a screenshot,
// loses nothing.
function verdictBlock(label, status, meaning, detail) {
  const box = el("div", { class: `verdict ${verdictClass(status)}` });
  box.appendChild(el("span", { class: "verdict-label", text: label }));
  box.appendChild(el("strong", { class: "verdict-status", text: status || "NOT CHECKED" }));
  if (detail) box.appendChild(el("p", { class: "verdict-detail", text: safeText(detail) }));
  if (meaning) box.appendChild(el("p", { class: "verdict-meaning", text: safeText(meaning) }));
  return box;
}

function question(headingText) {
  const sec = el("section", { class: "qa" });
  sec.appendChild(el("h3", { class: "qa-question", text: headingText }));
  return sec;
}

function renderEmpty() {
  RESULT_BLOCK.hidden = true;
  RESULT_BLOCK.replaceChildren();
  if (ONBOARDING) ONBOARDING.hidden = false;
}

function renderResult(result) {
  if (!result) return;
  if (ONBOARDING) ONBOARDING.hidden = true;
  RESULT_BLOCK.hidden = false;
  RESULT_BLOCK.replaceChildren(renderReport(result));
}

// HOW MANY MARK PANELS ONE PAGE RENDERS, and why there is a limit at all.
//
// Nothing bounds how many HashMark outputs a transaction carries. Radiant mainnet
// enforces no standardness, so a transaction of many OP_RETURN outputs relays, and the
// classifier accepts up to 100,000 outputs. A minimal record is a 46-byte script, so one
// 4 MB transaction holds about 72,000 of them. Rendered whole under the render harness
// (tests/web/verify_render_harness.mjs, Node's stub DOM, not a browser), 72,000 records
// made 72,000 panels, 2,304,005 elements and 72,000 file choosers — from one
// broadcastable transaction that anyone can link to.
//
// 50 is far above any honest multi-mark transaction a person would read panel by panel
// (a mark transaction ordinarily carries one), and it bounds the page: the same 72,000
// records now render 50 panels and 1,606 elements, the same as 51 records do.
// `pyrxd verify` has no such screen and checks every record, and the note under the last
// panel says so.
const MAX_MARK_PANELS = 50;

// THE WHOLE ANSWER, as one node. Everything below this line is pure: it takes the
// classification dict and returns DOM, touching no globals and no network, which is
// what lets `tests/web/verify_render_harness.mjs` drive the real renderer under Node
// against payloads the real Python classifier produced.
function renderReport(result) {
  const wrap = el("div", { class: "report" });

  // SAY WHAT WAS LOOKED UP, when it is not what was typed. A reader who pasted an outpoint
  // or a contract id is shown the transaction it points at, and must be able to tell —
  // including when the OUTPUT they named is not the mark, or is not there at all.
  const named = result && result.named_by;
  if (named) {
    wrap.appendChild(para(namedByNote(named), "answer-body multi-note"));
    if (result.ok) {
      const about = namedOutputNote(named, result.payload || {});
      if (about) wrap.appendChild(para(about, "answer-body multi-note named-output"));
    }
  }

  if (!result || !result.ok) {
    wrap.appendChild(renderProblem(
      safeText((result && result.error) || "This could not be checked"),
      safeText((result && result.hint) || ""),
      safeText((result && result.detail) || ""),
    ));
    return wrap;
  }

  const payload = result.payload || {};
  const records = hashmarkRecords(payload);

  if (records.length === 0) {
    wrap.appendChild(renderNoMark(result, payload));
    return wrap;
  }

  if (payload.txid) {
    wrap.appendChild(fact("transaction", payload.txid, "mono"));
  }
  // MORE THAN ONE RECORD IS NOT AN ERROR and must not be quietly collapsed to the
  // first. One transaction can carry several marks, and showing one while silently
  // dropping the rest would answer a question the reader did not ask. Each gets its
  // own full report, numbered, and the count is stated.
  //
  // UP TO `MAX_MARK_PANELS`, and never silently fewer. The count is stated before the
  // first panel, and what was left out is stated after the last one.
  const shown = records.slice(0, MAX_MARK_PANELS);
  const hidden = records.length - shown.length;
  if (records.length > 1) {
    wrap.appendChild(para(
      `This transaction carries ${records.length} marks. Each is a separate record ` +
      (hidden > 0
        ? `and is checked on its own. The first ${shown.length} are shown below; the ` +
          `other ${hidden} are not shown on this page.`
        : `and is checked separately below.`),
      "answer-body multi-note",
    ));
  }
  shown.forEach((entry, index) => {
    wrap.appendChild(renderOneMark(entry.hashmark, {
      anchor: payload.mark_anchor,
      anchorReason: anchorReasonFor(result),
      ordinal: records.length > 1 ? `Mark ${index + 1} of ${records.length}` : null,
      vout: entry.vout,
      // WHICH OUTPUT, whenever the reader named one. A single mark used to carry no output
      // number at all, so `<txid>:1` — a change output — sat above a green VERIFIED that was
      // about output 0, and nothing on the page said so.
      showVout: records.length > 1 || Boolean(named),
    }));
  });
  if (hidden > 0) {
    for (const line of hiddenMarksNote(records.slice(shown.length), payload.txid)) {
      wrap.appendChild(para(line, "answer-body multi-note"));
    }
  }
  return wrap;
}

// What this page can truthfully say about the marks it did not draw — EXACT counts, taken
// from what the classifier actually did to each one, never inferred from the position.
//
// Past MAX_MARK_PANELS a signature is not checked, UNLESS the record is a byte-for-byte copy
// of one that was (an attestation is a function of the bytes, so the copy's answer is known
// and cost nothing). So "not shown" and "not checked" are different counts, and a forged
// record past the limit is reported as NOT CHECKED — never folded into a total that reads as
// clean. Worst first, in the page's own status words.
function hiddenMarksNote(hiddenRecords, txid) {
  const n = hiddenRecords.length;
  const tally = new Map();
  for (const entry of hiddenRecords) {
    const word = hiddenStatus(entry.hashmark || {});
    tally.set(word, (tally.get(word) || 0) + 1);
  }
  const order = [
    "DOES NOT VERIFY", RECORD_DOES_NOT_DECODE, NOT_CHECKED_HERE_WORDS, "NOT CHECKED", "NO SIGNATURE", "VERIFIED",
  ];
  const parts = order.filter((w) => tally.has(w)).map((w) => `${tally.get(w)} ${w}`);
  for (const [w, count] of tally) if (!order.includes(w)) parts.push(`${count} ${w}`);

  const lines = [
    `${n} more ${n === 1 ? "mark is" : "marks are"} in this transaction and ${n === 1 ? "is" : "are"} ` +
    `not shown here. What this page knows about ${n === 1 ? "it" : "them"}: ${parts.join(", ")}.`,
  ];
  const unchecked = tally.get(NOT_CHECKED_HERE_WORDS) || 0;
  if (unchecked > 0) {
    lines.push(
      `This page checks the signatures of the first ${MAX_MARK_PANELS} marks in a transaction, and of ` +
      "any later mark that is a byte-for-byte copy of one of them. The " +
      `${unchecked === 1 ? "one" : unchecked} ${NOT_CHECKED_HERE_WORDS} ${unchecked === 1 ? "was" : "were"} ` +
      "past that, so nothing here says whether " + (unchecked === 1 ? "it verifies" : "they verify") +
      " — a mark that does not verify could be among them.",
    );
  }
  // THE WHOLE COMMAND, not a placeholder that the CLI then refuses. `pyrxd verify` has no
  // default depth, on purpose, so the one thing a reader must supply is N — and what it means.
  //
  // N IS CONFIRMATIONS, NOT BLOCKS ON TOP. The CLI holds the mark's block to
  // `confirmations >= N` (`MarkAnchor.provisional`), and a confirmation count includes the
  // block itself (`mark_anchor.py` places it at `tip - confirmations + 1`). This said "blocks
  // built on top", which is one more than the command asks for.
  lines.push(
    `To check every mark in it: pyrxd verify ${safeText(txid || "<transaction number>")} ` +
    "--min-confirmations N — where N is how many confirmations the mark's block must have " +
    "before you rely on it. The block itself is the first confirmation, so N means the block " +
    "and N − 1 built on top of it. The command deliberately has no default for N.",
  );
  return lines;
}

// How the hidden-records note names one record, in the same words its panel would use.
const NOT_CHECKED_HERE_WORDS = "not checked here";
function hiddenStatus(hm) {
  if (hm.outcome === "invalid") return RECORD_DOES_NOT_DECODE;
  if (hm.outcome !== "ok") return "NOT CHECKED";
  const att = hm.attestation || {};
  if (att.outcome === "not_checked_here") return NOT_CHECKED_HERE_WORDS;
  return att.status || "NOT CHECKED";
}

// Why there is no block to report, when there is none. NEVER SILENCE: a record with
// no block cannot support a point-in-time claim at all, and the reason a reader is
// owed differs by how they got here.
function anchorReasonFor(result) {
  if (result.form === "txid") {
    return "the block was not looked up for this transaction";
  }
  return (
    "you pasted the record itself rather than a transaction number. A record on its " +
    "own is not in any block, so there is nothing to date it by — paste the " +
    "transaction number to get that half of the answer"
  );
}

// THE TITLE IS THE ANSWER, and the underlying reason is never dropped.
//
// `detail` is whatever the server or the classifier actually said. It is the least
// readable line on the page and the most load-bearing one when something is really
// wrong, so it is kept, quiet and verbatim, under the plain-language explanation
// rather than replaced by it.
function renderProblem(title, body, detail) {
  const sec = el("section", { class: "problem" });
  sec.appendChild(el("h2", { class: "problem-title", text: title }));
  if (body) sec.appendChild(para(body));
  if (detail) {
    sec.appendChild(el("p", { class: "problem-detail-label", text: "What the server or decoder said" }));
    sec.appendChild(el("p", { class: "problem-detail", text: detail }));
  }
  return sec;
}

// What the reader typed, and what this page looked up because of it.
function namedByNote(named) {
  const txid = safeText(named.txid);
  const vout = Number.isInteger(named.vout) ? ` output ${named.vout} of` : "";
  const what = named.form === "contract" ? "a contract id" : "an output reference (transaction:output)";
  return (
    `You pasted ${what}, which points at${vout} transaction ${txid}. A mark is checked by the ` +
    "transaction that carries it, so this page looked up that transaction."
  );
}

// THE OUTPUT THE READER NAMED, against what the transaction actually has. Without this a
// change output (`:1`) or an output that does not exist (`:7` of a two-output transaction)
// sat above a green VERIFIED about a DIFFERENT output, and the page never said which. The
// facts told apart: the named output holds a record that is drawn below, or one past the
// panel limit that is not; it exists and is not a record; or the transaction has no such
// output. Null when there is nothing to compare against.
function namedOutputNote(named, payload) {
  const n = named.vout;
  const count = payload.output_count;
  if (!Number.isInteger(n) || !Number.isInteger(count)) return null;
  const marked = hashmarkRecords(payload).map((r) => r.vout).filter((v) => Number.isInteger(v));
  // A COUNT past one, never a list: a transaction can carry tens of thousands of records, and
  // this sentence must not grow with it (see MAX_MARK_PANELS).
  const where = marked.length === 0
    ? "It carries no HashMark record in any output."
    : marked.length === 1
      ? `Its HashMark record is in output ${marked[0]}, and the panel below is about that output.`
      : `It carries ${marked.length} HashMark records in other outputs; each panel below names its own.`;
  if (n < 0 || n >= count) {
    return (
      `That transaction has ${count} output${count === 1 ? "" : "s"} (numbered 0 to ${count - 1}), ` +
      `so there is no output ${n}: what you were given points at nothing in it. ${where}`
    );
  }
  const at = marked.indexOf(n);
  if (at !== -1) {
    // "HOLDS THE RECORD", not "carries a HashMark record": the record there may be one that
    // does not decode, and its own panel says so in the error colour. And only a panel that is
    // DRAWN can be pointed at — past MAX_MARK_PANELS the record is counted, not shown.
    if (at >= MAX_MARK_PANELS) {
      return (
        `Output ${n}, the one you named, holds a record, but it is past the first ` +
        `${MAX_MARK_PANELS} this page draws, so it is not shown here and nothing below is about it. ` +
        "The note at the end counts it with the others; `pyrxd verify` in a terminal checks every mark."
      );
    }
    return `Output ${n}, the one you named, holds the record in the panel below marked "output ${n}".`;
  }
  return (
    `Output ${n}, the one you named, is NOT a HashMark record, so nothing below is about it. ${where}`
  );
}

// NO MARK, SAID ABOUT WHAT WAS ACTUALLY READ. "It is not a HashMark record" is a claim about
// one script, and it was being printed for every input that was not a transaction number —
// including an outpoint and a contract id that point at a real mark, and a raw transaction,
// which the classifier reads as ONE script. So the words now depend on the form: a transaction
// that carries no mark, a single script that is not a record, or (for any form this page does
// not know) only what the page did and did not find.
function renderNoMark(result, payload) {
  const sec = el("section", { class: "problem" });
  if (result.form === "txid") {
    sec.appendChild(el("h2", { class: "problem-title", text: "There is no HashMark here" }));
    sec.appendChild(para(
      "That transaction is on the chain, and none of its outputs carries a HashMark " +
      "record. This says nothing about anyone's honesty: it is simply not a mark.",
    ));
  } else if (result.form === "script") {
    sec.appendChild(el("h2", { class: "problem-title", text: "This script is not a HashMark record" }));
    sec.appendChild(para(
      "What you pasted was read as a single output script, and this single script is not a " +
      "HashMark record.",
    ));
    sec.appendChild(para(
      "If what you pasted was a whole transaction rather than one output's script, it was read " +
      "the wrong way: this page does not take a transaction's raw bytes. Paste its transaction " +
      "number instead, and every output in it will be read.",
      "answer-body muted",
    ));
  } else {
    sec.appendChild(el("h2", { class: "problem-title", text: "No HashMark was found" }));
    sec.appendChild(para("This page found no HashMark record in what you pasted."));
  }
  // THE MISTAKE THIS PAGE WILL ACTUALLY MEET, for a bare transaction number. A digest and
  // a transaction number are both 64 hex characters and nothing about the string
  // distinguishes them, so a reader given a digest will paste it here and get "not found".
  // `pyrxd verify` says the same thing in its own help; it is worth saying twice. Not said
  // when the reader gave an outpoint or a contract id: those are not the shape of a digest.
  if (result.form === "txid" && !result.named_by) {
    sec.appendChild(para(
      "One thing worth ruling out: a fingerprint and a transaction number are the same " +
      "shape — 64 letters and numbers — and nothing about the text says which you have. " +
      "A fingerprint on its own locates nothing, because there is no index from " +
      "fingerprints back to transactions. Ask whoever gave you the mark for the " +
      "transaction number.",
      "answer-body muted",
    ));
  }
  if (payload.txid) sec.appendChild(fact("transaction", payload.txid, "mono"));
  return sec;
}

// ---------------------------------------------------------------------
// One record, four questions
// ---------------------------------------------------------------------

function renderOneMark(hm, opts) {
  const options = opts || {};
  const panel = el("section", { class: "mark" });

  if (options.ordinal) {
    const head = el("h2", { class: "mark-heading", text: options.ordinal });
    panel.appendChild(head);
  }
  if ((options.ordinal || options.showVout) && options.vout !== null && options.vout !== undefined) {
    panel.appendChild(el("p", { class: "mark-subheading", text: `output ${options.vout}` }));
  }

  if (hm.outcome !== "ok") {
    renderUnreadableRecord(panel, hm);
    return panel;
  }

  const att = hm.attestation || {};
  // `status` and `meaning` are the PAYLOAD'S, from `_inspect_core._ATTESTATION_VERDICTS`
  // — the one table `pyrxd glyph inspect`, `pyrxd verify` and the inspector all read.
  // The fallbacks are for a payload built before those fields existed, and they fail
  // toward "we do not know" rather than toward either verdict.
  const status = att.status || "NOT CHECKED";
  const meaning = att.meaning || "this build could not read the outcome of the signature check";

  panel.appendChild(verdictBlock("the signature on this mark", status, meaning, att.detail || ""));

  panel.appendChild(answerWhoSigned(hm, att, status));
  panel.appendChild(answerWhatWasFingerprinted(hm));
  panel.appendChild(answerWhen(options.anchor, options.anchorReason));
  panel.appendChild(answerIsThisYourFile(hm));

  // LAST, and deliberately after everything a reader might have taken further than
  // it goes. The sentence comes from shared.js so this page and the inspector cannot
  // claim different amounts for the same record.
  panel.appendChild(el("p", { class: "mark-proves", text: WHAT_A_MARK_PROVES }));
  return panel;
}

// A record that claims to be a HashMark and could not be read as one.
//
// THREE DIFFERENT FACTS, AND THEY USED TO SHARE ONE PANEL. `unknown_version` and
// `unknown_algorithm` are records from the future: well-formed, just newer than this
// build, and the neutral NOT CHECKED with "that is not a sign that anything is wrong
// with it" is the truth about them. `invalid` is the opposite: the bytes break the
// format's own rules. It was rendered in that same neutral panel, reassurance
// included, while `pyrxd verify` calls it RECORD DOES NOT DECODE and fails the verdict
// on it. That also gave a forger a way down from the error colour: a record whose
// signature DOES NOT VERIFY is red, and one more defect in its bytes turned it into
// this grey, reassuring panel.
//
// THE WORD IS `pyrxd verify`'s, for the same record — `_signature_check`'s literal,
// pinned against this page by `tests/web/test_verify_page.py`, which runs both over
// every `HashMarkOutcome` taken from the enum itself.
const RECORD_DOES_NOT_DECODE = "RECORD DOES NOT DECODE";

function renderUnreadableRecord(panel, hm) {
  if (hm.outcome === "invalid") {
    panel.appendChild(verdictBlock(
      "this record",
      RECORD_DOES_NOT_DECODE,
      "the bytes say they are a HashMark record and break the format's own rules, so " +
      "nothing in them — fingerprint, key or signature — can be relied on",
      safeText(hm.detail || ""),
    ));
    panel.appendChild(para(
      "This output claims to be a HashMark record and is malformed. Treat it as no mark " +
      "at all: a record that breaks the format vouches for nothing, and none of it was " +
      "checked here.",
    ));
  } else if (hm.outcome === "unknown_version" || hm.outcome === "unknown_algorithm") {
    // Claims to be a HashMark and is not readable HERE. A statement about the BYTES,
    // not about anyone's signature — an unknown version or algorithm is a record from
    // the future, not a forgery, and must not read as one.
    panel.appendChild(verdictBlock(
      "this record",
      "NOT CHECKED",
      "this is a statement about the record's format, not about anyone's signature: " +
      "nothing here was checked against a key",
      safeText(hm.detail || ""),
    ));
    // BOTH HALVES OF THE SENTENCE. The first is true of a record from the future and
    // must stay; the second is what stops it reading as an endorsement. Anyone can write
    // these bytes — changing the algorithm byte of a forged record lands here — and
    // nothing in it was read, so it vouches for nothing.
    panel.appendChild(para(
      "This is a HashMark record that this page cannot read — most likely a newer " +
      "version, or a fingerprint made with a hash this build does not implement. " +
      "That is not a sign that anything is wrong with it, and it is not evidence of " +
      "anything either: none of it could be read, so none of it was checked.",
    ));
  } else {
    // An outcome this page has never heard of. Fails toward "we do not know", and
    // WITHOUT the reassurance above: that sentence is true of a record from the
    // future, and nothing says this is one.
    panel.appendChild(verdictBlock(
      "this record",
      "NOT CHECKED",
      "this page does not know what that outcome means, so it says nothing about the record",
      safeText(`the decoder reported ${hm.outcome}` + (hm.detail ? `: ${hm.detail}` : "")),
    ));
  }
  if (hm.version !== null && hm.version !== undefined) {
    panel.appendChild(fact("record version", hm.version));
  }
  if (hm.algorithm_id !== null && hm.algorithm_id !== undefined) {
    panel.appendChild(fact("hash it names", `0x${Number(hm.algorithm_id).toString(16).padStart(2, "0")}`));
  }
}

// ── 1. who ──────────────────────────────────────────────────────────────
//
// THE HEADLINE AND THIS ANSWER CANNOT DISAGREE, and that is structural rather than
// careful: both are switched on the SAME `status` string the payload carried, and
// the affirmative sentence exists in exactly one branch of this function. A page
// whose banner said NOT CHECKED while its "who signed" paragraph said "signed by
// Alice" would be worse than one that said nothing, because the reader believes the
// sentence and skims the banner.
function answerWhoSigned(hm, att, status) {
  const sec = question("Who vouched for it?");
  const committed = hm.committed_signer_address || hm.signer_hash160;

  if (!hm.signer_hash160) {
    // v1 — there is no signature to check, and the absence IS the finding.
    sec.appendChild(para(
      "Nobody. This is a version-1 record: it carries no signature at all. It fixes a " +
      "fingerprint to a point in time and says nothing whatever about who published it.",
    ));
    return sec;
  }

  if (status === "VERIFIED") {
    sec.appendChild(para(
      "The signature checks out against the key this record names. Whoever held that " +
      "key made this statement.",
    ));
    sec.appendChild(para(
      // NOT "key custody". What a verified signature shows is that the key had signed this —
      // NOT that its holder put it in this transaction: the signed statement does not bind the
      // transaction, so a genuine record can be copied into anyone's. Same meaning as
      // `pyrxd verify` prints.
      "That is all it shows. It does not show that they put this mark here — a signed record " +
      "can be copied, byte for byte, into anyone's transaction — and it does not say they " +
      "wrote the file, own it, or were first to it: only that the holder of this key vouched " +
      "for this fingerprint.",
      "answer-body muted",
    ));
  } else if (status === "DOES NOT VERIFY") {
    // AGAINST WHICH CHAIN, SAID IN THE SENTENCE. The chain's genesis hash is inside the signed
    // statement, so a genuine record signed for another Radiant network (a testnet) fails here
    // exactly as a forgery does. "The signature does not come from that key" said more than the
    // check found: it found that the signature does not verify against that key ON THIS CHAIN.
    const network = networkInWords(att.assumed_network);
    sec.appendChild(para(
      "Nobody that this page can confirm. The record names a key, and the signature it " +
      `carries does not verify against that key on ${network}.`,
    ));
    sec.appendChild(para(
      "The network is part of what a HashMark signs, so a genuine record made for a different " +
      `Radiant network — a testnet, say — lands here too. This page checks against ${network} ` +
      "only; `pyrxd --network testnet glyph inspect` in a terminal checks a record against testnet.",
      "answer-body muted",
    ));
    if (att.signer_address || att.recovered_hash160) {
      // "RECOVERS TO", never "belongs to". Recovery on this curve returns a key for
      // ANY well-formed signature, including bytes nobody ever signed with anything —
      // so "the signature belongs to a different key" asserts an owner that the
      // arithmetic did not find. It also invites a reader to go looking for whoever
      // that other key is, on the strength of a number that may be an artefact.
      sec.appendChild(para(
        "Recovering a key from the signature gives a different one from the key the " +
        "record names, which is what a signature that does not hold looks like. It does " +
        "not tell you who, if anyone, made it.",
        "answer-body muted",
      ));
    }
  } else if (att.outcome === "not_checked_here") {
    // Not checked BY CHOICE, to bound the work: this record is past the number this page checks
    // per transaction. Not the curve failing to load, which is what the branch below says — so
    // it gets its own sentence. Unreachable while the panel limit and the checking limit are the
    // one number `lookUp` passes, and kept true for the day they are not.
    sec.appendChild(para(
      "The record names a key. Whether the signature really comes from that key was NOT " +
      "checked here: this page checks a limited number of marks per transaction, and this one " +
      "is past that limit. It is not evidence either way. `pyrxd verify` in a terminal checks " +
      "every mark.",
    ));
  } else {
    // NOT CHECKED — and this is no longer the ordinary path. The page installs a
    // curve at boot and normally reaches a real verdict; landing here means that
    // failed in THIS tab. Say whose limitation it is, and say it before the reader
    // can supply the affirmative sentence themselves.
    sec.appendChild(para(
      "The record names a key. Whether the signature really comes from that key was " +
      "NOT checked here — this page normally does check it, and in this browser the " +
      "code that does the maths did not load, so the check was withheld rather than " +
      "guessed at.",
    ));
    sec.appendChild(para(
      "Read the key below as something the record claims, not as something this page " +
      "confirmed. It is not evidence that the mark is bad: an honest mark and a forged " +
      "one look exactly the same until that check runs. Reloading the page may be " +
      "enough; otherwise run `pyrxd verify` from a terminal.",
      "answer-body muted",
    ));
  }

  const dl = el("dl", { class: "facts" });
  dl.appendChild(fact(
    status === "VERIFIED" ? "the signing key" : "the key this record names",
    committed,
    "mono",
  ));
  if (att.recovered_hash160 && att.recovered_hash160 !== hm.signer_hash160) {
    // The inspector's own label for this row is "recovered from the signature". Same
    // words here on purpose: it is the same number, and a reader checking one page
    // against the other must not meet two descriptions of it.
    dl.appendChild(fact(
      "recovered from the signature",
      `${att.signer_address || att.recovered_hash160} — not the key this record names`,
      "mono warn",
    ));
  }
  if (att.assumed_network) {
    // FOR EVERY OUTCOME, not only VERIFIED. The chain's genesis hash is inside the signed
    // statement, so the same bytes read against another chain recover a different key — which
    // makes the assumption load-bearing for a failure as much as for a success: a testnet
    // record read as mainnet is a red DOES NOT VERIFY, and the reader is owed the reason it
    // might be. Where no check ran, the row says what a check WOULD assume, not "checked".
    const checked = status === "VERIFIED" || status === "DOES NOT VERIFY";
    dl.appendChild(fact(checked ? "checked against" : "network assumed", att.assumed_network));
  }
  sec.appendChild(dl);
  return sec;
}

// The network a check assumed, in words. The payload carries `radiant-<name>`; anything else is
// shown as it came, sanitised, rather than guessed at.
function networkInWords(assumed) {
  const known = {
    "radiant-mainnet": "Radiant mainnet",
    "radiant-testnet": "Radiant testnet",
    "radiant-regtest": "Radiant regtest",
  };
  if (typeof assumed === "string" && Object.prototype.hasOwnProperty.call(known, assumed)) return known[assumed];
  return assumed ? safeText(assumed) : "the network this page assumes";
}

// ── 2. what ─────────────────────────────────────────────────────────────
function answerWhatWasFingerprinted(hm) {
  const sec = question("What was fingerprinted?");
  sec.appendChild(para(
    `A ${safeText(hm.algorithm || "hash")} fingerprint of some file's exact bytes. The file ` +
    "itself is not on the chain and cannot be recovered from this — a fingerprint goes " +
    "one way only. Change one byte of the file and it comes out completely different.",
  ));

  const dl = el("dl", { class: "facts" });
  dl.appendChild(fact("fingerprint", hm.digest, "mono"));
  dl.appendChild(fact("made with", hm.algorithm));
  if (hm.label) {
    // PUBLISHER-CHOSEN TEXT. Sanitised on the Python side and again by `safeText`,
    // and it is a claim by whoever published the mark — not a fact this page checked.
    dl.appendChild(fact("label the publisher attached", hm.label));
  } else if (hm.label_withheld) {
    dl.appendChild(fact("label", `withheld — ${hm.label_withheld}`, "warn"));
  }
  sec.appendChild(dl);

  if (hm.label) {
    sec.appendChild(para(
      "The label is whatever the publisher typed. Nothing checks it against the file, " +
      "and it is not part of what makes the fingerprint match.",
      "answer-body muted",
    ));
  }
  return sec;
}

// HOW DEEP, in words that do not add a block. `confirmations` INCLUDES the mark's own
// block — `mark_anchor.py` derives the height as `tip - confirmations + 1`, so a mark in
// the newest block has one confirmation and nothing on top of it. The page used to print
// "N block(s) built on top of it", which overstated every mark's burial by one.
function depthInWords(confirmations) {
  const n = Number(confirmations);
  if (!Number.isInteger(n) || n < 1) {
    // Not reachable with a height (`resolve_mark_anchor` only derives one for n >= 1), and
    // kept truthful for the day it is: the count as reported, with no arithmetic on it.
    return `which the server reports has ${safeText(confirmations)} confirmation(s)`;
  }
  const count = `${n} confirmation${n === 1 ? "" : "s"}`;
  if (n === 1) {
    return `which has ${count}: the block itself, with none built on top of it yet`;
  }
  return `which has ${count}: the block itself and ${n - 1} built on top of it`;
}

// ── 3. when ─────────────────────────────────────────────────────────────
//
// DEGRADE WITH A REASON, NEVER TO SILENCE. A mark with no block supports no
// point-in-time claim at all, and every way of not having one says so differently:
// no lookup was made, the lookup failed, or the transaction is not in a block yet.
// Those are three different facts and only one of them is benign.
function answerWhen(anchor, anchorReason) {
  const sec = question("When was it published?");

  if (!anchor) {
    sec.appendChild(para(`Not established — ${safeText(anchorReason)}.`));
    sec.appendChild(para(
      "Without a block there is no point in time here, so the mark establishes nothing " +
      "about when. Everything above is still true about the record itself.",
      "answer-body muted",
    ));
    return sec;
  }
  if (!anchor.resolved) {
    sec.appendChild(para(`Not established — ${safeText(anchor.reason || "no reason was given")}.`));
    sec.appendChild(para(
      "The record was read; its block was not. That is a fact about the lookup, not " +
      "about the mark — but until it succeeds there is no point-in-time claim to rely on.",
      "answer-body muted",
    ));
    return sec;
  }
  if (anchor.height === null || anchor.height === undefined) {
    sec.appendChild(para(
      "Not yet. This transaction has been sent but is not in a block, and a mark that is " +
      "not in a block fixes no time at all. It establishes nothing about when until a " +
      "block carries it.",
    ));
    return sec;
  }

  // safeText ON THE NUMBERS TOO. They are ints by the time `resolve_mark_anchor` is
  // done with them — `nonneg_int` refuses anything else and the height is arithmetic
  // on them — so this is not closing a live hole. It closes the LAST place on this
  // page where a payload value reaches a sentence without passing the sanitiser,
  // which is what keeps "every string is sanitised" a property of the file rather
  // than a fact about today's callers.
  sec.appendChild(para(
    // "KNEW THE FINGERPRINT", not "knew the file". A signed record can be copied into
    // anyone's transaction and a v1 record can carry any fingerprint its publisher was
    // given, so the block shows the fingerprint was known by then — not that whoever
    // published this transaction ever had the file.
    `In block ${safeText(anchor.height)}, ${depthInWords(anchor.confirmations)}. So the ` +
    "fingerprint above existed no later than that block — whoever published it knew that " +
    "fingerprint by then, which is not the same as having had the file.",
  ));
  const dl = el("dl", { class: "facts" });
  dl.appendChild(fact("block", anchor.height));
  dl.appendChild(fact("confirmations", anchor.confirmations));
  sec.appendChild(dl);
  // THE CAVEAT TRAVELS WITH THE NUMBER. `mark_anchor_dict` carries it precisely so a
  // height cannot reach a screen without it: pyrxd has no Radiant header, proof-of-work
  // or merkle check, so the height is one server's claim and nothing here tested it.
  sec.appendChild(para(
    `About that block number: ${safeText(anchor.caveat)}. It was reported by ${safeText(anchor.source)}.`,
    "answer-body muted",
  ));
  if (anchor.no_depth_policy) {
    sec.appendChild(para(`${safeText(anchor.no_depth_policy)}.`, "answer-body muted"));
  }
  return sec;
}

// ── 4. the file ─────────────────────────────────────────────────────────
function answerIsThisYourFile(hm) {
  const sec = question("Is this your file?");
  if (!hm.digest || !hm.algorithm) {
    sec.appendChild(para("This record carries no fingerprint to compare a file against."));
    return sec;
  }
  sec.appendChild(para(
    `If you have the file this mark is supposed to be about, choose it and this page will ` +
    `fingerprint it with ${safeText(hm.algorithm)} — the hash this record itself names, not one ` +
    `chosen here — and tell you whether the two match.`,
  ));
  // THE PROMISE, from shared.js. It is what a reader relies on before pointing this
  // at a private file, so it is one string, made identically on both pages.
  sec.appendChild(para(FILE_NEVER_LEAVES_THIS_MACHINE, "answer-body privacy"));

  const input = el("input", { class: "file-input" });
  input.type = "file";
  input.setAttribute("aria-label", "Choose a file to compare against this fingerprint");
  sec.appendChild(input);

  const out = el("div", { class: "file-result" });
  out.hidden = true;
  sec.appendChild(out);
  input.addEventListener("change", () => onFileChosen(input, out, hm));
  return sec;
}

async function onFileChosen(input, out, hm) {
  const file = input.files && input.files[0];
  if (!file) return;
  // The reader's own filename, but it can still carry a bidi override that makes the
  // rendered name differ from the real one — on a page whose job is telling someone
  // whether two things are the same.
  const name = safeText(file.name || "(unnamed)");
  out.hidden = false;
  out.replaceChildren(el("p", { class: "file-status", text: `Fingerprinting ${name}…` }));

  // THE MECHANICS ARE shared.js's: which hash (the record's, via `file_check_plan`),
  // the size cap, the secure-context check, and the comparison itself — whose verdict
  // and whose WORDS come from `judge_file_digest` in Python. One line of `===` here
  // would have been a third opinion on what "this is the file" is allowed to mean.
  const outcome = await hashFileWithRecordAlgorithm(file, hm, bridges);

  if (!outcome.ok) {
    out.replaceChildren(verdictBlock(
      "your file",
      "NOT CHECKED",
      fileCheckFallback(outcome.algorithm),
      outcome.reason,
    ));
    return;
  }

  const block = verdictBlock("your file", outcome.verdict.status, outcome.verdict.meaning);
  const dl = el("dl", { class: "facts" });
  dl.appendChild(fact("the file you chose", name));
  dl.appendChild(fact(`its ${outcome.algorithm} fingerprint`, outcome.computed, "mono"));
  dl.appendChild(fact("the fingerprint in the record", outcome.expected, "mono"));
  out.replaceChildren(block, dl);
}

// ---------------------------------------------------------------------
// Kick off
// ---------------------------------------------------------------------

boot();
