"""The public verify page: what a stranger is told, and what it is not allowed to say.

``/inspect/`` is a diagnostic for someone who already knows what a HashMark is.
``/verify/`` is the page a stranger lands on from a link, and the difference changes
what can go wrong. A missing field on the inspector is a developer's inconvenience.
A SENTENCE on this page that claims more than the verdict above it supports is read
by someone with no way to tell — so on this surface the prose IS the product, and
prose is the one thing no ordinary test evaluates.

Three properties this file exists to hold:

1.  **UNVERIFIABLE is a limitation of the READER, never a verdict on the record.**
    ``verify_attestation`` returns it when ``coincurve`` cannot be imported, and in a
    browser it never can: pyrxd installs under Pyodide with ``deps=False`` and
    coincurve ships no pure-Python wheel. So this is not an edge case here, it is
    *the outcome for every v2 record anyone will ever paste into this page*. In CI,
    with coincurve installed, no script can produce it by varying the BYTES — what
    varies is the RUNTIME — so these tests block the import the way the browser does
    and run the real classifier under that block.

2.  **The headline and the four answers cannot disagree.** A banner reading NOT
    CHECKED above a paragraph saying "signed by X" is worse than no page at all: the
    reader believes the sentence and skims the banner. The affirmative sentence lives
    in exactly one branch, switched on the same status string the headline prints,
    and ``test_the_affirmative_sentence_appears_only_when_the_signature_verified``
    is what keeps it there.

3.  **Degrading says why.** A record with no block supports no point-in-time claim.
    Every way of not having one — no lookup, a failed lookup, an unconfirmed
    transaction — is a different fact, and this file checks each says so in its own
    words rather than going quiet.

Everything is rendered through ``verify_render_harness.mjs``, which loads the REAL
``shared.js`` and ``verify.js`` verbatim in a Node ``vm``. The payloads come from the
REAL Python classifier wherever a real record can produce them.
"""

from __future__ import annotations

import importlib.abc
import json
import re
import shutil
import subprocess  # nosec B404 — fixed argv, no shell, repo-local script
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
_HARNESS = _REPO_ROOT / "tests" / "web" / "verify_render_harness.mjs"
_STATIC = _REPO_ROOT / "docs" / "inspect_static"
_VERIFY_DIR = _STATIC / "verify"
_INSPECT_DIR = _STATIC / "inspect"

#: The real signed mainnet record, byte-identical to the one in
#: ``tests/test_hashmark_mainnet_vectors.py`` — written by the protocol author's own
#: implementation, not by ours, and carried in transaction
#: ``a1a86ab4503901af4df3d092fcf668b07c03c5cd89240fe918ae70e02e045916`` at height
#: 460,572. Used here because the whole point is what this page shows for a mark that
#: is GENUINE: a forgery rendered as unchecked is a nuisance, an honest mark rendered
#: as suspect is the failure this page must not commit.
_V2_SIGNED_HEX = (
    "6a08484153484d41524b02020120e2c55efb34b6e9d6db008ee72d56bf86456ab3f55ae76488ff677fda88df1f1e"
    "1426ba056431ec69cf27eabeaab250d99ddbd895d2411f750d18df9ab44ba66ced01285a5a067b9ebf7c8ff6b32d"
    "ddb40cc276c5e98d4c2054937e44a40d7628d80cafdd6a372b0aae8f8bb31dbb4d975273a23e8c9771"
)
_REAL_DIGEST = "e2c55efb34b6e9d6db008ee72d56bf86456ab3f55ae76488ff677fda88df1f1e"
_REAL_ADDRESS = "14XmXG3dSBWZUukGT3xzS9zxpiZ53vgx1i"

#: The sentence that exists in exactly ONE branch of ``answerWhoSigned`` — the
#: affirmative one. Anything that makes it reachable under another status is the
#: defect this file's second property is about.
_AFFIRMATIVE = "Whoever held that key made this statement"


class _BlockCoincurve(importlib.abc.MetaPathFinder):
    """Reproduce the browser: secp256k1 simply is not there."""

    def find_spec(self, name, path=None, target=None):
        if name == "coincurve" or name.startswith("coincurve."):
            raise ModuleNotFoundError("No module named 'coincurve'")
        return None


@pytest.fixture
def without_coincurve():
    blocker = _BlockCoincurve()
    sys.meta_path.insert(0, blocker)
    saved = {n: m for n, m in sys.modules.items() if n == "pyrxd.keys" or n.startswith("coincurve")}
    for n in saved:
        del sys.modules[n]
    try:
        yield
    finally:
        sys.meta_path.remove(blocker)
        sys.modules.update(saved)


def _require_node() -> str:
    node = shutil.which("node")
    if node is None:
        import os

        if os.environ.get("PYRXD_SKIP_JS_RENDER_GUARD") == "1":
            pytest.skip("node is missing and PYRXD_SKIP_JS_RENDER_GUARD=1 — the verify page is UNGUARDED in this run")
        pytest.fail(
            "node is required to run the verify-page guard (it loads shared.js and "
            "verify.js in a Node vm). Install node, or set PYRXD_SKIP_JS_RENDER_GUARD=1 "
            "to skip it deliberately and accept that the page is unverified in this run."
        )
    return node


def _render(cases: dict) -> dict:
    """Render through the production ``verify.js``, loaded verbatim."""
    proc = subprocess.run(  # nosec B603 — fixed argv, no shell, repo-local script
        [_require_node(), str(_HARNESS), "-"],
        input=json.dumps(cases),
        capture_output=True,
        text=True,
        check=False,
        cwd=str(_REPO_ROOT),
    )
    if proc.returncode != 0:
        pytest.fail(f"verify render harness failed (exit {proc.returncode}):\n{proc.stderr}")
    return json.loads(proc.stdout)


def _page(result: dict) -> dict:
    """``{"text": …, "classes": [...]}`` for one classification."""
    return _render({"case": {"result": result}})["case"]


def _as_script_result(payload: dict) -> dict:
    """The shape ``glue.run`` returns for a pasted record."""
    return {"ok": True, "form": "script", "input": "(pasted)", "payload": payload}


def _as_tx_result(payload: dict, *, anchor: dict | None = None) -> dict:
    """The shape ``glue.inspect_txid_with_raw`` returns, with the block attached the
    way ``lookUp`` attaches it in production."""
    row = {k: v for k, v in payload.items() if k != "form"}
    row["vout"] = 0
    row["satoshis"] = 0
    tx_payload: dict = {"txid": "ab" * 32, "outputs": [row], "output_count": 1}
    if anchor is not None:
        tx_payload["mark_anchor"] = anchor
    return {"ok": True, "form": "txid", "input": "ab" * 32, "payload": tx_payload}


# ─────────────────────────────── the outcome the corpus cannot reach ──


class TestAMissingCurveIsNotAVerdict:
    """The single most important property on this page, and the one CI cannot reach
    by varying the input bytes."""

    @pytest.fixture
    def payload(self, without_coincurve) -> dict:
        from pyrxd.glyph._inspect_core import _inspect_script

        return _inspect_script(_V2_SIGNED_HEX)

    def test_the_classifier_really_does_withhold_here(self, payload) -> None:
        """Non-vacuity. Without this, every assertion below could be passing against a
        payload whose signature verified normally, and the whole class would prove
        nothing about the browser at all."""
        assert payload["hashmark"]["attestation"]["outcome"] == "unverifiable", (
            "the coincurve block did not take effect, so these tests are not exercising the browser's situation"
        )

    def test_the_page_says_it_was_not_checked(self, payload) -> None:
        assert "NOT CHECKED" in _page(_as_script_result(payload))["text"]

    def test_it_says_that_is_not_a_verdict_on_the_record(self, payload) -> None:
        assert "this is not a verdict on it" in _page(_as_script_result(payload))["text"]

    def test_it_names_whose_limitation_it_is(self, payload) -> None:
        """ "Not checked" with no reason invites the reader to assume the record is at
        fault. The reason is their own browser, and it says so twice: once in the
        payload's own detail, once in this page's plain-language paragraph."""
        text = _page(_as_script_result(payload))["text"]
        assert "secp256k1" in text
        assert "this browser has no library for the maths involved" in text

    def test_it_never_says_the_signature_failed(self, payload) -> None:
        """THE WHOLE POINT. A red cross beside an honest signer's mark because the
        READER's browser lacks a curve library is an accusation this page has no basis
        for — and the record here is real, from mainnet, and genuine."""
        text = _page(_as_script_result(payload))["text"]
        assert "DOES NOT VERIFY" not in text
        assert "INVALID" not in text.upper().replace("UNVERIFIABLE", "")

    def test_it_is_not_painted_with_the_error_colour(self, payload) -> None:
        """THE PIXELS, NOT THE WORDS. Every assertion above reads TEXT. The verdict
        carries its colour in a CLASS, so a one-word change in ``verdictClass`` could
        paint an honest mark red while "NOT CHECKED" still appeared and every text
        assertion stayed green."""
        classes = _page(_as_script_result(payload))["classes"]
        assert any("verdict-unchecked" in c for c in classes), f"expected a neutral verdict block, got: {classes}"
        assert not any("verdict-bad" in c for c in classes), f"an unverifiable mark was painted red: {classes}"

    def test_the_class_assertion_can_actually_see_a_bad_verdict(self, payload) -> None:
        """The control: prove ``verdict-bad`` IS reachable on this page, so the absence
        check above is not vacuous. A renderer emitting no classes at all would satisfy
        that half for the wrong reason."""
        forged = json.loads(json.dumps(payload))
        forged["hashmark"]["attestation"]["outcome"] = "invalid_signature"
        forged["hashmark"]["attestation"]["status"] = "DOES NOT VERIFY"
        classes = _page(_as_script_result(forged))["classes"]
        assert any("verdict-bad" in c for c in classes), (
            "the harness never reports verdict-bad, so the absence check above proves nothing"
        )

    def test_the_evidence_a_reader_can_act_on_still_reaches_them(self, payload) -> None:
        """Only the VERDICT is withheld. The digest and the key the record names need
        no curve at all, and withholding them too would turn a missing dependency into
        a missing record — and leave the reader with nothing to take elsewhere."""
        text = _page(_as_script_result(payload))["text"]
        assert _REAL_DIGEST in text
        assert _REAL_ADDRESS in text

    def test_it_points_at_the_surface_that_can_finish_the_check(self, payload) -> None:
        """A withheld check that names no way to complete it is a dead end. The CLI has
        the curve library this page never will."""
        assert "pyrxd verify" in _page(_as_script_result(payload))["text"]


# ──────────────────────────── the headline and the answers cannot disagree ──


def _payload_with_status(outcome: str) -> dict:
    """A record carrying the shared table's own words for ``outcome``."""
    from pyrxd.glyph._inspect_core import _attestation_verdict

    status, meaning = _attestation_verdict(outcome)
    hm = {
        "outcome": "ok",
        "version": 1 if outcome == "not_attested" else 2,
        "algorithm": "sha256",
        "algorithm_id": 1,
        "digest": "cd" * 32,
        "attestation": {"outcome": outcome, "status": status, "meaning": meaning, "detail": ""},
    }
    if outcome != "not_attested":
        hm["signer_hash160"] = "ab" * 20
        hm["committed_signer_address"] = "1NotARealAddressAtAll"
    return {"type": "op_return-hashmark-v2", "length": 133, "hashmark": hm}


class TestTheHeadlineAndTheAnswerAgree:
    """Two elements on one screen describing the same thing. A page fixed in one half
    and left contradicting itself in the other is a defect this project has shipped
    before; here the two read the same ``status`` string and this is what keeps them
    doing so."""

    @pytest.mark.parametrize("outcome", ["valid", "invalid_signature", "unverifiable", "not_attested"])
    def test_the_affirmative_sentence_appears_only_when_the_signature_verified(self, outcome) -> None:
        from pyrxd.glyph._inspect_core import _attestation_verdict

        status, _ = _attestation_verdict(outcome)
        text = _page(_as_script_result(_payload_with_status(outcome)))["text"]
        if status == "VERIFIED":
            assert _AFFIRMATIVE in text, "a verified signature must actually say so"
        else:
            assert _AFFIRMATIVE not in text, (
                f"the page told the reader someone signed this while the headline said {status!r}"
            )

    @pytest.mark.parametrize("outcome", ["valid", "invalid_signature", "unverifiable", "not_attested"])
    def test_the_status_word_and_its_meaning_both_reach_the_page(self, outcome) -> None:
        """One vocabulary, every surface. These words come from
        ``_inspect_core._ATTESTATION_VERDICTS`` — the same table ``pyrxd glyph
        inspect``, ``pyrxd verify`` and the inspector read — so one record cannot be
        described two ways depending on which page you happen to be looking at."""
        from pyrxd.glyph._inspect_core import _attestation_verdict

        status, meaning = _attestation_verdict(outcome)
        text = _page(_as_script_result(_payload_with_status(outcome)))["text"]
        assert status in text, f"the page did not print {status!r} for outcome {outcome!r}"
        assert meaning in text

    def test_a_verified_mark_still_refuses_to_claim_authorship(self) -> None:
        """The riskiest sentence on the page is the one under an affirmative result
        that says what it MEANS. It inherits the authority of the verdict while
        asserting something nobody checked."""
        text = _page(_as_script_result(_payload_with_status("valid")))["text"]
        assert "key custody and nothing more" in text
        assert "does not say they wrote the file, own it, or were first to it" in text

    def test_a_v1_record_says_nobody_rather_than_going_quiet(self) -> None:
        """A record with no signer is not a record with an unchecked signer. Rendering
        the two the same way would let "nobody signed this" read as "we did not look"."""
        text = _page(_as_script_result(_payload_with_status("not_attested")))["text"]
        assert "Nobody." in text
        assert "carries no signature at all" in text

    def test_an_outcome_nobody_has_heard_of_lands_on_the_neutral_class(self) -> None:
        """A new outcome rendered green is a forgery shown as genuine; one rendered red
        is an honest mark shown as a lie. Neither is acceptable, so an unknown status
        takes the neutral colour and the withheld wording."""
        payload = _payload_with_status("unverifiable")
        payload["hashmark"]["attestation"]["status"] = "SOMETHING THIS BUILD HAS NEVER HEARD OF"
        rendered = _page(_as_script_result(payload))
        assert any("verdict-unchecked" in c for c in rendered["classes"])
        assert not any("verdict-ok" in c or "verdict-bad" in c for c in rendered["classes"])
        assert _AFFIRMATIVE not in rendered["text"]


# ────────────────────────────────────── degrade with a reason, never to silence ──


class TestEveryMissingBlockSaysWhy:
    """A mark's whole claim is "no later than the block that confirms it". Three ways
    of not having a block, three different facts, and only one of them is benign."""

    def test_a_pasted_record_says_it_is_in_no_block_by_construction(self) -> None:
        text = _page(_as_script_result(_payload_with_status("unverifiable")))["text"]
        assert "A record on its own is not in any block" in text
        assert "the mark establishes nothing about when" in text

    def test_a_failed_lookup_carries_the_endpoints_reason(self) -> None:
        """The record was read and its block was not. That is a fact about the lookup,
        and a page that showed no block without saying so would leave the reader
        believing the mark has no block at all."""
        anchor = {"resolved": False, "reason": "the endpoint answered about another transaction"}
        text = _page(_as_tx_result(_payload_with_status("unverifiable"), anchor=anchor))["text"]
        assert "the endpoint answered about another transaction" in text
        assert "The record was read; its block was not" in text

    def test_an_unconfirmed_transaction_fixes_no_time(self) -> None:
        """ "0 confirmations" without saying what it costs invites the reader to treat a
        mempool entry as a mark that is merely young."""
        anchor = {"resolved": True, "height": None, "confirmations": 0, "caveat": "c", "source": "s"}
        text = _page(_as_tx_result(_payload_with_status("unverifiable"), anchor=anchor))["text"]
        assert "not in a block" in text
        assert "fixes no time at all" in text

    def test_a_real_block_never_reaches_the_page_without_its_caveat(self) -> None:
        """``mark_anchor_dict`` carries the caveat precisely so a height cannot be shown
        unqualified: pyrxd has no Radiant header, proof-of-work or merkle check, so the
        number is one endpoint's claim. A page showing the number and not the caveat has
        published the unqualified sentence that helper exists to prevent."""
        from pyrxd.glyph.mark_anchor import UNVERIFIED_CAVEAT

        anchor = {
            "resolved": True,
            "height": 460572,
            "confirmations": 5140,
            "caveat": UNVERIFIED_CAVEAT,
            "source": "the single ElectrumX endpoint this page is allowed to talk to",
            "no_depth_policy": "This page sets no confirmation-depth requirement",
        }
        text = _page(_as_tx_result(_payload_with_status("unverifiable"), anchor=anchor))["text"]
        assert "460572" in text
        assert UNVERIFIED_CAVEAT in text, "a height reached the screen without the caveat that qualifies it"
        assert "the single ElectrumX endpoint this page is allowed to talk to" in text
        assert "sets no confirmation-depth requirement" in text

    def test_a_transaction_with_no_mark_says_so_and_rules_out_the_likely_mistake(self) -> None:
        """The mistake this page will really meet: a digest and a txid are both 64 hex
        characters, and a reader given a digest will paste it here."""
        text = _page({"ok": True, "form": "txid", "payload": {"txid": "ab" * 32, "outputs": [], "output_count": 0}})[
            "text"
        ]
        assert "There is no HashMark here" in text
        assert "no index from fingerprints back to transactions" in text

    def test_an_unreadable_record_is_a_statement_about_bytes_not_about_a_signature(self) -> None:
        """An unknown version or algorithm is a record from the FUTURE, not a forgery,
        and must not read as one."""
        payload = {
            "type": "op_return-hashmark",
            "hashmark": {
                "outcome": "unknown_version",
                "version": 9,
                "algorithm_id": 1,
                "detail": "version 9 is not implemented by this build",
            },
        }
        rendered = _page(_as_script_result(payload))
        assert "not about anyone's signature" in rendered["text"]
        assert "newer version" in rendered["text"]
        assert not any("verdict-bad" in c for c in rendered["classes"])


# ────────────────────────────────────────── one copy of the sentences that CLAIM ──


class TestTheClaimSentencesAreNotWrittenTwice:
    """Assertive text is a CLAIM, and no test evaluates claims — so prose drifts from
    the code beside it in silence, and prose is the part people believe. The two
    sentences here are the ones a reader acts on, and both pages print them from one
    definition in ``shared.js`` rather than from two literals."""

    def test_the_verify_page_prints_the_shared_claim_sentence(self) -> None:
        rendered = _render({"case": {"result": _as_script_result(_payload_with_status("valid"))}})
        shared_sentence = rendered["__constants__"]["what_a_mark_proves"]
        assert shared_sentence in rendered["case"]["text"]

    def test_the_inspector_prints_the_same_sentence_from_the_same_constant(self) -> None:
        """The cross-surface half. Both pages reference the NAME, so a change reaches
        both at once — and if someone re-inlines a literal in either file, this fails."""
        shared = (_INSPECT_DIR / "shared.js").read_text(encoding="utf-8")
        assert shared.count("const WHAT_A_MARK_PROVES") == 1, "the shared sentence has more than one definition"
        for page in (_INSPECT_DIR / "inspect.js", _VERIFY_DIR / "verify.js"):
            text = page.read_text(encoding="utf-8")
            assert "WHAT_A_MARK_PROVES" in text, f"{page.name} does not use the shared claim sentence"
            assert "What a mark proves: someone knew this digest" not in text, (
                f"{page.name} has re-inlined the claim sentence instead of using the shared constant"
            )

    def test_the_privacy_promise_is_also_one_string(self) -> None:
        """A promise a reader relies on before pointing this page at a private file.
        Two copies is how one of them eventually says something weaker."""
        shared = (_INSPECT_DIR / "shared.js").read_text(encoding="utf-8")
        assert shared.count("const FILE_NEVER_LEAVES_THIS_MACHINE") == 1
        for page in (_INSPECT_DIR / "inspect.js", _VERIFY_DIR / "verify.js"):
            assert "FILE_NEVER_LEAVES_THIS_MACHINE" in page.read_text(encoding="utf-8")

    def test_the_page_says_the_file_is_not_uploaded_before_asking_for_one(self) -> None:
        """ORDER, not merely presence. The promise below the control is the promise a
        reader reads after deciding."""
        rendered = _render({"case": {"result": _as_script_result(_payload_with_status("unverifiable"))}})
        text = rendered["case"]["text"]
        promise = rendered["__constants__"]["file_never_leaves"]
        assert promise in text
        assert text.index("Is this your file?") < text.index(promise)


# ─────────────────────────────────────────────── publisher-chosen text is inert ──


class TestAttackerAuthoredTextIsSanitised:
    """The label is the one string on this page an attacker picks. It is sanitised on
    the Python side and again at the render layer, and this checks the layer that is
    actually this page's responsibility."""

    _HOSTILE = "quarterly\u001b[2Kreport\u202e\u200bfdp.xcod"

    def test_a_label_carrying_control_bytes_renders_inert(self) -> None:
        payload = _payload_with_status("unverifiable")
        payload["hashmark"]["label"] = self._HOSTILE
        text = _page(_as_script_result(payload))["text"]
        for bad in ("\u001b", "\u202e", "\u200b"):
            assert bad not in text, f"{bad!r} reached the rendered page"

    def test_the_label_still_reaches_the_reader(self) -> None:
        """A guard that refuses valid work is a bug. Stripping the hostile codepoints
        must not silently drop the label — the reader needs what the publisher wrote."""
        payload = _payload_with_status("unverifiable")
        payload["hashmark"]["label"] = self._HOSTILE
        text = _page(_as_script_result(payload))["text"]
        assert "quarterly" in text and "report" in text

    def test_the_label_is_never_presented_as_something_the_page_checked(self) -> None:
        """It is whatever the publisher typed. Nothing binds it to the file, and a
        reader who takes it as verified has taken the publisher's word for the one
        field they chose freely."""
        payload = _payload_with_status("unverifiable")
        payload["hashmark"]["label"] = "quarterly-report.pdf"
        text = _page(_as_script_result(payload))["text"]
        assert "The label is whatever the publisher typed" in text
        assert "Nothing checks it against the file" in text

    def test_the_transport_is_not_what_removed_them(self) -> None:
        """NON-VACUITY, and it needs its own test: "the codepoints are absent from the
        rendered page" is satisfied just as well by a harness that dropped them in
        transit as by a sanitiser that stripped them. That would be a green test
        proving nothing.

        So send a NON-ASCII character the sanitiser has no reason to touch - a CJK
        ideograph is a Letter, not a control, format or combining mark - through the
        same JSON transport and the same field, and require it to arrive. If it does,
        the pipe carries exotic codepoints and the absence of the control bytes above
        is ``stripControlChars`` doing its job.
        """
        payload = _payload_with_status("unverifiable")
        payload["hashmark"]["label"] = "\u6f22\u5b57-report"
        text = _page(_as_script_result(payload))["text"]
        assert "\u6f22\u5b57-report" in text, (
            "a non-ASCII label did not survive the harness transport, so the "
            "control-byte tests above prove nothing about the sanitiser"
        )

    def test_the_render_layer_never_uses_innerhtml(self) -> None:
        """Structural. The Python side sanitises, but the render layer is the last
        place a future field could become markup, and ``textContent`` is what makes
        that impossible rather than merely unlikely."""
        source = (_VERIFY_DIR / "verify.js").read_text(encoding="utf-8")
        code = "\n".join(line for line in source.splitlines() if not line.lstrip().startswith("//"))
        assert "innerHTML" not in code, "verify.js assigns innerHTML somewhere outside a comment"


# ──────────────────────────────────────────────── the page is actually publishable ──


class TestThePageIsWiredTheWayTheSiteExpects:
    def test_it_is_a_subfolder_of_the_extra_path_so_it_lands_at_slash_verify(self) -> None:
        """``html_extra_path`` copies the CONTENTS of ``inspect_static/`` to the site
        root. A file at the top level of that directory lands at the root, and an
        ``index.html`` there would overwrite the docs landing page."""
        assert (_VERIFY_DIR / "index.html").is_file()
        stray = [p.name for p in _STATIC.iterdir() if p.is_file()]
        assert not stray, f"files at the top of inspect_static/ land at the SITE ROOT: {stray}"

    def test_conf_py_names_every_page_that_will_be_published(self) -> None:
        """The comment in ``conf.py`` is the only place the layout rule is written
        down, and it named exactly one subfolder until this page existed.

        THE SET IS DERIVED FROM THE FILESYSTEM, not typed here. A version of this that
        pinned the literal ``inspect/`` and ``verify/`` would go stale in exactly the
        way the comment it guards just did — silently, on the next page. What is
        asserted is that every directory that Sphinx will publish is mentioned.

        Flattened before searching: that prose is hard-wrapped, and a line-oriented
        grep for a wrapped phrase finds nothing while every word is present.
        """
        flat = " ".join((_REPO_ROOT / "docs" / "conf.py").read_text(encoding="utf-8").split())
        published = sorted(p.name for p in _STATIC.iterdir() if p.is_dir())
        assert published, "no pages found under inspect_static/ — this scan is broken, not conf.py"
        missing = [name for name in published if f"``{name}/``" not in flat]
        assert not missing, (
            f"conf.py's html_extra_path comment does not mention {missing}, which will be "
            f"published at the site root anyway"
        )

    def test_the_page_loads_the_shared_script_before_its_own(self) -> None:
        """``verify.js`` resolves ``verdictClass``, ``stripControlChars`` and the two
        claim sentences by name. A classic script runs before a deferred module, so
        the ORDER of these two tags is what makes the page work at all."""
        html = (_VERIFY_DIR / "index.html").read_text(encoding="utf-8")
        shared_tag = re.search(r'<script\b[^>]*\bsrc="\.\./inspect/shared\.js"[^>]*>', html)
        assert shared_tag, "the page does not load ../inspect/shared.js at all"
        own_at = html.index('src="verify.js"')
        assert shared_tag.start() < own_at, "verify.js is loaded before the shared script it depends on"
        # SCOPED TO THE TAG, not to a character window around it. A window wide enough
        # to be safe reaches the NEXT script tag, which IS a module, so the check read
        # the wrong element and failed on a page that was perfectly correct.
        assert 'type="module"' not in shared_tag.group(0), (
            "shared.js must load as a CLASSIC script; a module's bindings are not visible by name"
        )

    def test_it_reads_the_one_wheel_the_ci_step_builds(self) -> None:
        """One artefact, SHA-256 pinned once. A second copy staged under /verify/ is a
        second thing for the docs CI step to keep in step, and the stale one is always
        the copy nobody is looking at."""
        source = (_VERIFY_DIR / "verify.js").read_text(encoding="utf-8")
        assert '"../inspect/wheels/"' in source
        assert '"../inspect/glue.py"' in source
        assert not (_VERIFY_DIR / "wheels").exists(), "a second wheel directory has appeared under /verify/"

    def test_its_content_security_policy_whitelists_nothing_new(self) -> None:
        """DERIVED, not retyped. The public page must stay inside the policy the
        inspector already ships — a page that quietly widened ``connect-src`` or
        ``script-src`` would be the one a reader trusts most and the one with the
        largest attack surface."""
        directives = {}
        for name, path in (("verify", _VERIFY_DIR / "index.html"), ("inspect", _INSPECT_DIR / "index.html")):
            html = path.read_text(encoding="utf-8")
            match = re.search(r'http-equiv="Content-Security-Policy"\s+content="([^"]*)"', html)
            assert match, f"{name}/index.html has no CSP meta tag"
            parsed = {}
            for clause in match.group(1).split(";"):
                parts = clause.split()
                if parts:
                    parsed[parts[0]] = set(parts[1:])
            directives[name] = parsed

        assert directives["verify"], "the CSP scan found nothing — it is broken, not the page"
        for directive, sources in directives["verify"].items():
            allowed = directives["inspect"].get(directive)
            assert allowed is not None, f"/verify/ adds a CSP directive the inspector does not have: {directive}"
            extra = sources - allowed
            assert not extra, f"/verify/ widens {directive} beyond the inspector's policy: {sorted(extra)}"

    def test_the_endpoint_is_the_one_the_policy_allows(self) -> None:
        """A wire address and a CSP that disagree produce a page whose lookups are
        blocked by the browser with nothing on screen to say why."""
        shared = (_INSPECT_DIR / "shared.js").read_text(encoding="utf-8")
        match = re.search(r'const ELECTRUMX_WSS_URL = "([^"]+)"', shared)
        assert match, "could not find the endpoint constant — this scan is broken, not the page"
        html = (_VERIFY_DIR / "index.html").read_text(encoding="utf-8")
        assert match.group(1) in html, "the page's CSP does not allow the endpoint shared.js connects to"


# ───────────────────────────────────────────── two walkers over one payload shape ──


class TestTheTwoShapeWalkersAgree:
    """A pasted script carries one record at the top level; a fetched transaction
    carries one per output. ``hashmark_records`` (Python, three CLI callers) and
    ``hashmarkRecords`` (JS, this page) each walk both shapes, and the JS one exists
    because ``glyph_inspect`` imports click and cannot be loaded in Pyodide.

    Two implementations of one expression is how ``--verify-wave <txid> --fetch`` once
    attached nothing at all and never said why. This runs both over the same payloads.
    """

    @staticmethod
    def _js_count(payload: dict) -> int:
        node = shutil.which("node")
        if node is None:
            pytest.skip("node is missing")
        script = (
            f"const fs=require('node:fs'),vm=require('node:vm');"
            f"const s={{console}};s.globalThis=s;vm.createContext(s);"
            f"vm.runInContext(fs.readFileSync({str(_INSPECT_DIR / 'shared.js')!r},'utf8'),s);"
            f"console.log(s.hashmarkRecords({json.dumps(payload)}).length)"
        )
        out = subprocess.run(  # nosec B603 — fixed argv, no shell
            [node, "-e", script], capture_output=True, text=True, check=True
        )
        return int(out.stdout.strip())

    @pytest.mark.parametrize(
        "payload",
        [
            pytest.param({"hashmark": {"outcome": "ok"}}, id="pasted-script-one-record"),
            pytest.param({"outputs": []}, id="transaction-with-no-outputs"),
            pytest.param({"outputs": [{"vout": 0}, {"vout": 1}]}, id="transaction-with-no-marks"),
            pytest.param(
                {"outputs": [{"vout": 0, "hashmark": {"outcome": "ok"}}, {"vout": 1}]},
                id="transaction-with-one-mark",
            ),
            pytest.param(
                {
                    "outputs": [
                        {"vout": 0, "hashmark": {"outcome": "ok"}},
                        {"vout": 1, "hashmark": {"outcome": "ok"}},
                    ]
                },
                id="transaction-with-two-marks",
            ),
            pytest.param({}, id="empty-payload"),
        ],
    )
    def test_both_walkers_find_the_same_number_of_records(self, payload) -> None:
        from pyrxd.cli.glyph_inspect import hashmark_records

        assert self._js_count(payload) == len(hashmark_records(payload))

    def test_a_transaction_carrying_two_marks_renders_both(self) -> None:
        """NOT collapsed to the first. Showing one mark while silently dropping another
        answers a question the reader did not ask."""
        one = _payload_with_status("unverifiable")
        two = _payload_with_status("valid")
        rows = []
        for index, payload in enumerate((one, two)):
            row = {k: v for k, v in payload.items() if k != "form"}
            row["vout"] = index
            row["satoshis"] = 0
            rows.append(row)
        result = {"ok": True, "form": "txid", "payload": {"txid": "ab" * 32, "outputs": rows, "output_count": 2}}
        text = _page(result)["text"]
        assert "This transaction carries 2 marks" in text
        assert "Mark 1 of 2" in text and "Mark 2 of 2" in text
        assert text.count("Who vouched for it?") == 2


# ───────────────────────────── "no such transaction" is not "the server is down" ──


def _wire_failure(kind: str | None, message: str) -> dict:
    """Render what a reader sees for a rejected ElectrumX promise of this kind.

    Goes through ``lookupFailure`` — the production function ``lookUp`` calls — not
    through a hand-built result dict, because the translation from a rejection to a
    sentence is the half that was wrong.
    """
    spec: dict = {"message": message}
    if kind is not None:
        spec["kind"] = kind
    return _render({"case": {"wire_error": spec}})["case"]


class TestALookupThatFailedSaysWhichWayItFailed:
    """FOUND BY LOOKING AT THE PAGE, not by a test — so it gets a test.

    A server that answers "I have no such transaction" and a server nobody can
    reach arrive here as the same rejected promise. The first version of this page
    rendered both as "the server did not answer — try again in a moment", which is
    the wrong advice for the case a reader will actually hit: a mistyped or wrong
    number, where retrying can never help and the sentence sends them away from the
    one thing that would.

    It is the same shape as a search fallback where "no matches" and "the upstream
    is gone" are both an empty array. The branch you did not build for is the one
    that ships broken, and here the branch real users take is the wrong-number one.
    """

    def test_a_server_that_refused_does_not_tell_the_reader_to_retry(self) -> None:
        rendered = _wire_failure("refused", "server error: No such mempool or blockchain transaction")
        assert "did not give back a transaction for that number" in rendered["text"]
        assert "retrying will not change this answer" in rendered["text"]
        assert "Trying again in a moment" not in rendered["text"]

    def test_a_server_nobody_could_reach_does_tell_the_reader_to_retry(self) -> None:
        """The OTHER branch, in the app rather than only in a test of the first."""
        rendered = _wire_failure("unreachable", "WebSocket error connecting to ElectrumX")
        assert "could not be reached" in rendered["text"]
        assert "Trying again in a moment" in rendered["text"]
        assert "retrying will not change this answer" not in rendered["text"]

    def test_the_two_are_not_the_same_words(self) -> None:
        """The property itself, stated once rather than inferred from the two above:
        a reader must be able to tell which happened."""
        refused = _wire_failure("refused", "server error: nope")["text"]
        unreachable = _wire_failure("unreachable", "WebSocket closed before any response")["text"]
        assert refused != unreachable

    def test_neither_blames_the_record(self) -> None:
        """A failed lookup says nothing about the mark. A page that let a reader come
        away thinking otherwise would have turned its own outage into an accusation."""
        for kind, message in (("refused", "server error: nope"), ("unreachable", "timed out after 10000ms")):
            text = _wire_failure(kind, message)["text"]
            assert "DOES NOT VERIFY" not in text
            assert "forged" not in text

    def test_the_servers_own_words_are_never_dropped(self) -> None:
        """Leading with plain language is not the same as hiding the reason. The
        verbatim text is the least readable line on the page and the most
        load-bearing one when something is really wrong."""
        detail = "server error: DaemonError({'code': -5, 'message': 'No such ...'})"
        assert detail in _wire_failure("refused", detail)["text"]

    def test_an_unusable_answer_says_what_was_wrong_with_it(self) -> None:
        """The third tagged case: something arrived and could not be read as a
        transaction. That IS a checked fact about the reply, so the page may say it."""
        rendered = _wire_failure("malformed", "server returned a non-hex string")
        assert "could not be used" in rendered["text"]
        assert "did not have the shape a transaction has" in rendered["text"]

    def test_an_untagged_rejection_claims_less_than_a_malformed_one(self) -> None:
        """A rejection from a path that tags nothing must not borrow the sentence
        above it. "The reply did not have the shape a transaction has" is a claim
        about what arrived — checked for a `malformed` rejection, and unchecked for
        one nobody classified. Reusing it would be the same conflation this class is
        about, one level further down: two facts told in the confident set of words.
        """
        rendered = _wire_failure(None, "something nobody has classified")
        assert "The lookup did not finish" in rendered["text"]
        assert "could not tell why, so it is not going to guess" in rendered["text"]
        assert "did not have the shape a transaction has" not in rendered["text"]
        assert "something nobody has classified" in rendered["text"]
        assert "retrying will not change this answer" not in rendered["text"]
        assert "Trying again in a moment" not in rendered["text"]

    def test_the_page_reads_the_tag_the_wire_actually_sets(self) -> None:
        """THE JOIN, and the reason this is not two tests that pass past each other.

        ``test_inspect_fetch_error_sanitizer`` proves the WIRE tags its rejections;
        the cases above prove the PAGE branches on tags. Neither proves the two use
        the same vocabulary — a wire emitting "server-refused" and a page switching
        on "refused" would leave both files green and every real failure landing on
        the cautious branch. So: derive the page's vocabulary from its own source and
        require the wire's to be a subset of it.
        """
        page = (_VERIFY_DIR / "verify.js").read_text(encoding="utf-8")
        shared = (_INSPECT_DIR / "shared.js").read_text(encoding="utf-8")
        page_kinds = set(re.findall(r'kind === "([a-z]+)"', page))
        wire_kinds = set(re.findall(r'wireError\("([a-z]+)"', shared))
        assert page_kinds, "the page branches on no kinds at all — this scan is broken"
        assert wire_kinds, "the wire tags nothing at all — this scan is broken"
        unhandled = wire_kinds - page_kinds
        assert not unhandled, f"the wire emits kinds the page has no branch for: {sorted(unhandled)}"
        stale = page_kinds - wire_kinds
        assert not stale, f"the page branches on kinds nothing emits: {sorted(stale)}"
