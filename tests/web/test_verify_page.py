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

from pyrxd.script.hashmark import HashMarkOutcome

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
def without_coincurve(monkeypatch):
    # `verify_attestation` remembers a failed curve import (it is attempted once per process),
    # so the memory is cleared here and restored by monkeypatch afterwards: a failure
    # remembered from inside this fixture must not outlive it.
    import pyrxd.script.hashmark as hashmark

    monkeypatch.setattr(hashmark, "_secp256k1_import_failure", None)
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
        payload's own detail, once in this page's plain-language paragraph.

        The wording changed when the page gained a curve: this is no longer the
        ordinary path, and a sentence implying no browser can do this maths would now
        be false. What must not change is that the reason names the READER's machine."""
        text = _page(_as_script_result(payload))["text"]
        assert "secp256k1" in text
        assert "the code that does the maths did not load" in text
        assert "this page normally does check it" in text

    def test_it_does_not_claim_a_browser_CANNOT_check_a_signature(self, payload) -> None:
        """The page checks signatures now, so every sentence that said otherwise is a
        false claim sitting under a verdict. These are the exact phrasings this page
        shipped with; none may come back, here or in the ordinary path."""
        text = _page(_as_script_result(payload))["text"]
        for stale in (
            "this browser has no library for the maths involved",
            "where the signature check does run",
        ):
            assert stale not in text, f"a sentence the page outgrew is back: {stale!r}"

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
        flat = " ".join(_page(_as_script_result(_payload_with_status("valid")))["text"].split())
        assert "does not say they wrote the file, own it, or were first to it" in flat

    def test_a_verified_mark_does_not_claim_its_signer_put_it_here(self) -> None:
        """ON THE RENDERED PAGE, not in a comment. The page said "key custody, nothing more" and
        "That is key custody and nothing more" under a verified signature — and a signed record
        can be copied into anyone's transaction, so a verified signature does not show that its
        key's holder published THIS one. The same meaning `pyrxd verify` prints, pinned the same
        way: the overstated word is gone, and the copy is named."""
        rendered = _render({"case": {"result": _as_tx_result(_payload_with_status("valid"))}})
        flat = " ".join(rendered["case"]["text"].split())
        assert "custody" not in flat.lower(), "the overstated claim is still rendered"
        assert "It does not show that they put this mark here" in flat
        assert "a signed record can be copied, byte for byte, into anyone's transaction" in flat
        shared = rendered["__constants__"]["what_a_mark_proves"]
        assert shared in flat and "custody" not in shared.lower()
        assert "a signed record can be copied into anyone's transaction" in shared

    def test_a_failed_signature_says_recovers_to_rather_than_belongs_to(self) -> None:
        """THE PARENTHETICAL UNDER A RESULT, which is where this page's riskiest text
        lives: it inherits the authority of the verdict above it while asserting
        something nobody checked.

        Recovery on this curve returns a key for ANY well-formed signature, including
        bytes nobody ever signed with anything. So "the signature belongs to a
        different key" asserts an OWNER the arithmetic did not find, and invites a
        reader to go looking for whoever that other key is on the strength of a number
        that may be an artefact. The honest sentence is weaker, and it is the one that
        ships.

        The label is also the inspector's own ("recovered from the signature"), so the
        same number is not described two ways across the two pages.
        """
        payload = _payload_with_status("invalid_signature")
        payload["hashmark"]["attestation"]["recovered_hash160"] = "cd" * 20
        payload["hashmark"]["attestation"]["signer_address"] = "1SomeOtherKeyEntirely"
        text = _page(_as_script_result(payload))["text"]
        assert "recovered from the signature" in text
        assert "Recovering a key from the signature gives a different one" in text
        assert "does not tell you who, if anyone, made it" in text
        assert "belongs to" not in text, "the page claims the signature has an owner; recovery does not establish one"

    def test_the_recovered_key_is_shown_only_when_it_disagrees(self) -> None:
        """Paired with the test above so the row cannot simply be deleted to satisfy
        it. When the signature verifies, recovered and committed are the same value by
        construction and a second row for it would read as a second piece of evidence.
        """
        verified = _page(_as_script_result(_payload_with_status("valid")))["text"]
        assert "recovered from the signature" not in verified

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
        assert '"../inspect/secp256k1-bridge.js"' in source
        assert not (_VERIFY_DIR / "wheels").exists(), "a second wheel directory has appeared under /verify/"
        assert not (_VERIFY_DIR / "vendor").exists(), "a second vendored curve has appeared under /verify/"

    def test_the_PAGE_CHROME_does_not_say_the_signature_is_unchecked(self) -> None:
        """THE SENTENCES THE RENDER HARNESS CANNOT SEE.

        Every other prose guard here drives ``verify.js`` and reads what it emitted.
        ``index.html``'s own copy — the primer, the footer — is never rendered by that
        harness, so a claim there can go false and stay false with a completely green
        suite. It did: the footer said the check "does run" in a terminal, meaning it
        did not run here, and that stopped being true the day the page got a curve.

        Searched with the newlines squeezed out, because this text is hard-wrapped and
        a line-oriented grep cannot see a sentence that wraps.
        """
        flat = " ".join((_VERIFY_DIR / "index.html").read_text(encoding="utf-8").split())
        for stale in (
            "where the signature check does run",
            "has no library for the maths",
            "there never will be",
        ):
            assert stale not in flat, (
                f"index.html still tells a reader the signature is not checked here: {stale!r}. "
                f"The page checks it now; this sentence is a false claim under a real verdict."
            )
        assert "The signature check runs in this browser" in flat, (
            "index.html no longer says the check runs here — if that became untrue, the "
            "asymmetry test above should have caught it first; if it is merely reworded, "
            "reword this guard deliberately."
        )

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

    # REAL error frames, through shared.js's own fetch. The three transient ones are aiorpcX
    # 0.25.0's (``aiorpcx/session.py`` ``_throttled_request``; codes from ``aiorpcx/jsonrpc.py``),
    # which ElectrumX servers answer through; "not-found" and "bad-request" are what the public
    # endpoint the pages use was measured (2026-09-23) to send for a txid it does not have and
    # for "zz".
    _FRAMES = {
        "server-busy": (-102, "server busy - request timed out"),
        "excessive-resource-usage": (-101, "excessive resource usage"),
        "internal-server-error": (-32603, "internal server error"),
        "not-found": (
            2,
            "daemon error: DaemonError({'code': -5, 'message': 'No such mempool or blockchain transaction. "
            "Use gettransaction for wallet transactions.'})",
        ),
        "bad-request": (1, "zz should be a transaction hash"),
    }

    @staticmethod
    def _framed(code: int, message: str) -> str:
        frame = json.dumps({"jsonrpc": "2.0", "error": {"code": code, "message": message}, "id": 1})
        return " ".join(_render({"case": {"wire_frame": frame}})["case"]["text"].split())

    @pytest.mark.parametrize("case", ["server-busy", "excessive-resource-usage", "internal-server-error"])
    def test_a_busy_or_failing_server_is_told_to_retry(self, case) -> None:
        """It told every refusal "retrying will not change this answer" — for these three,
        retrying is the one thing that can."""
        code, message = self._FRAMES[case]
        text = self._framed(code, message)
        assert "declined to answer this time" in text and "Trying again in a moment may work" in text
        assert "will not change" not in text and "commonest" not in text
        assert "Nothing was learned about the mark either way" in text
        assert message in text, "the server's own words are kept"

    def test_a_transaction_the_node_does_not_have_says_check_the_number(self) -> None:
        """The honest neighbour, and it no longer promises retrying cannot help: a transaction
        sent moments ago may not have reached the server's node yet."""
        text = self._framed(*self._FRAMES["not-found"])
        assert "did not give back a transaction for that number" in text
        assert "has no transaction with that number" in text and "may not have reached that node" in text
        assert "Check what you were given" in text
        assert "will not change" not in text and "commonest" not in text

    def test_a_malformed_request_says_asking_again_gets_the_same_answer(self) -> None:
        text = self._framed(*self._FRAMES["bad-request"])
        assert "refused the request itself" in text and "same answer" in text

    def test_a_refusal_the_frame_does_not_explain_gets_advice_true_for_both(self) -> None:
        """A frame with no code, as a server that omits it would send."""
        frame = json.dumps({"id": 1, "error": {"message": "No such mempool or blockchain transaction"}})
        text = " ".join(_render({"case": {"wire_frame": frame}})["case"]["text"].split())
        assert "will not guess" in text and "Check what you were given" in text and "try again later" in text
        assert "will not change" not in text and "declined to answer this time" not in text

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

    def test_a_server_answering_with_another_transaction_is_named_as_that(self) -> None:
        """The fourth tagged case: whole bytes came back, and they are not the transaction asked
        for. Not "could not be reached" (it answered), not "did not have the shape a transaction
        has" (nothing parsed them to find out), and not a claim that the NUMBER is wrong."""
        detail = "the server's answer is not the transaction asked for: it hashes to " + "cd" * 32
        rendered = _wire_failure("mismatch", detail)
        text = " ".join(rendered["text"].split())
        assert "answer is not the transaction that was asked for" in text
        assert "refused rather than read" in text
        assert "Nothing was learned about the mark either way" in text
        assert detail in rendered["text"], "the server's own answer is never dropped"
        for other in ("could not be reached", "did not have the shape a transaction has", "DOES NOT VERIFY"):
            assert other not in text

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


# ───────────────────── every decode outcome, in the words `pyrxd verify` uses ──


def _push(b: bytes) -> bytes:
    return bytes([len(b)]) + b


def _record_script(header: bytes, digest: bytes) -> bytes:
    return b"\x6a" + _push(b"HASHMARK") + _push(header) + _push(digest)


def _signed_script(content: bytes) -> bytes:
    """A real v2 record over ``content``, signed by a key generated here."""
    import hashlib

    from pyrxd.constants import genesis_hash_for
    from pyrxd.hashmark_tx import plan_hashmark
    from pyrxd.keys import PrivateKey

    digest = hashlib.sha256(content).digest()
    return plan_hashmark(
        digest, PrivateKey(), label="quarterly report", network_genesis=genesis_hash_for("mainnet")
    ).op_return_script


def _with_bad_label(script: bytes) -> bytes:
    """The same record with a control character in its label. §5.4 makes that non-canonical,
    and the label is inside the signed statement, so the decoder refuses the whole record."""
    hostile = b"quarterly\x1breport"[: len(b"quarterly report")]
    assert len(hostile) == len(b"quarterly report")
    out = bytearray(script)
    at = out.rfind(b"quarterly report")
    out[at : at + len(hostile)] = hostile
    return bytes(out)


#: One REAL script per decode outcome. Keyed by the enum member, and compared against the
#: enum in both directions below, so an outcome added upstream fails here instead of being
#: silently left out of the parametrisation.
_OUTCOME_SCRIPTS = {
    "ok": lambda: _signed_script(b"the advisory, as published\n"),
    "not_hashmark": lambda: b"\x6a" + _push(b"NOTAMARK") + _push(b"\x01" * 8),
    "invalid": lambda: _record_script(bytes([1, 1]), b"\x22" * 20),  # sha256 names 32 bytes; 20 here
    "unknown_version": lambda: _record_script(bytes([9, 1]), b"\x11" * 32),
    "unknown_algorithm": lambda: _record_script(bytes([1, 0x7F]), b"\x11" * 32),
}


def _glue():
    import importlib.util

    spec = importlib.util.spec_from_file_location("pyrxd_inspect_glue", _INSPECT_DIR / "glue.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["pyrxd_inspect_glue"] = module
    spec.loader.exec_module(module)
    return module


def _tx_result(*scripts: bytes, limit: int | None = None) -> tuple[str, bytes, dict]:
    """A real transaction carrying ``scripts``, classified by the page's own Python entry point
    (``glue.inspect_txid_with_raw``) — the exact dict ``verify.js`` receives in the browser.
    ``limit`` is the attestation limit the page passes (``MAX_MARK_PANELS``); ``None`` checks all."""
    from tests.test_hashmark_verify_cli import _tx_with

    txid, raw = _tx_with(*scripts)
    result = _glue().inspect_txid_with_raw(txid, raw.hex(), limit)
    assert result["ok"], result
    return txid, raw, result


def _cli_word(monkeypatch, tmp_path, txid: str, raw: bytes) -> str | None:
    """What `pyrxd verify` — the real command — calls this record. ``None`` when it finds no
    record at all. Read from ``--json``, so a change to the human layout cannot move it."""
    from tests.test_hashmark_verify_cli import _FakeServer, _run

    r = _run(
        monkeypatch,
        _FakeServer({txid: raw}),
        ["--json", "verify", txid, "--min-confirmations", "1"],
        tmp_path=tmp_path,
    )
    if r.exit_code == 1 and "no HashMark record" in r.output:
        return None
    return json.loads(r.stdout)["checks"]["signature"]["state"]


def _first_verdict_class(classes: list[str]) -> str:
    return next(c for c in classes if c.split()[0] == "verdict")


class TestEveryDecodeOutcomeReadsAsPyrxdVerifyReadsIt:
    """A record the decoder calls malformed was a grey "NOT CHECKED" here, with "That is not a
    sign that anything is wrong with it", while `pyrxd verify` called the same bytes RECORD
    DOES NOT DECODE and failed its verdict. The page and the command a reader is pointed to must
    not describe one record two ways — so this runs BOTH, over one real script per outcome."""

    def test_there_is_a_script_for_every_outcome_and_no_other(self) -> None:
        """NON-VACUITY, both directions. The parametrisation below is the enum itself; this is
        what makes a missing script fail loudly rather than skip."""
        assert set(_OUTCOME_SCRIPTS) == {o.value for o in HashMarkOutcome}
        assert len(HashMarkOutcome) >= 5, "the enum shrank — re-read what this test is for"

    @pytest.mark.parametrize("outcome", [o.value for o in HashMarkOutcome])
    def test_the_page_prints_the_word_the_command_prints(self, monkeypatch, tmp_path, outcome) -> None:
        from pyrxd.cli.hashmark_cmds import _CHECK_HOLDS
        from pyrxd.script.hashmark import decode_hashmark

        script = _OUTCOME_SCRIPTS[outcome]()
        assert decode_hashmark(script).outcome.value == outcome, "the premise: these bytes reach this outcome"
        txid, raw, result = _tx_result(script)
        cli = _cli_word(monkeypatch, tmp_path, txid, raw)
        rendered = _page(result)

        if outcome == "not_hashmark":
            assert cli is None, "the command found a record the decoder says is not one"
            assert rendered["panels"] == [] and "There is no HashMark here" in rendered["text"]
            return

        assert cli, "the command printed no signature state — this comparison is vacuous"
        assert rendered["statuses"], "the page printed no verdict — this comparison is vacuous"
        assert rendered["statuses"][0] == cli, (
            f"{outcome}: the page says {rendered['statuses'][0]!r} and `pyrxd verify` says {cli!r} "
            "about the same record"
        )
        # AND THE COLOUR AGREES WITH THE COMMAND'S VERDICT. A word the command fails on must
        # not be painted in the colour of "nothing wrong"; a word it holds on must not be red.
        painted = _first_verdict_class(rendered["classes"])
        assert ("verdict-bad" in painted) == (cli not in _CHECK_HOLDS), (outcome, cli, painted)


class TestAMalformedRecordIsNotAFutureRecord:
    def test_it_says_malformed_in_the_error_colour_and_does_not_reassure(self) -> None:
        _txid, _raw, result = _tx_result(_OUTCOME_SCRIPTS["invalid"]())
        rendered = _page(result)
        assert rendered["statuses"][0] == "RECORD DOES NOT DECODE"
        assert "verdict-bad" in _first_verdict_class(rendered["classes"])
        flat = " ".join(rendered["text"].split())
        assert "is malformed" in flat and "nothing in them" in flat and "can be relied on" in flat
        for reassurance in ("That is not a sign that anything is wrong", "newer version"):
            assert reassurance not in flat, f"a malformed record is told {reassurance!r}"

    @pytest.mark.parametrize("outcome", ["unknown_version", "unknown_algorithm"])
    def test_a_record_from_the_future_keeps_the_neutral_panel(self, outcome) -> None:
        """The honest pair: these ARE well-formed and newer, and the reassurance is true of them."""
        _txid, _raw, result = _tx_result(_OUTCOME_SCRIPTS[outcome]())
        rendered = _page(result)
        assert rendered["statuses"][0] == "NOT CHECKED"
        assert "verdict-unchecked" in _first_verdict_class(rendered["classes"])
        flat = " ".join(rendered["text"].split())
        assert "newer version" in flat and "not a sign that anything is wrong" in flat
        # And not an endorsement: a forged record with its algorithm byte changed lands here.
        assert "it is not evidence of anything either" in flat

    def test_a_decode_breaking_defect_does_not_move_a_forgery_out_of_the_error_colour(self) -> None:
        """THE DOWNGRADE. A forged record is red. Add a defect that breaks its DECODE (here, a
        control character in the signed label) and it used to become the grey "cannot read this —
        nothing is wrong with it" panel. It stays red now.

        What this does NOT cover, on purpose: changing the forged record's version byte to 9, or
        its algorithm byte to an unknown one, makes a WELL-FORMED record from the future, and that
        still reads NOT CHECKED — the spec separates it from a broken record and `pyrxd verify`
        says the same. `TestAMalformedRecordIsNotAFutureRecord` pins that it says it is not
        evidence of anything."""
        forged = bytearray(_signed_script(b"the advisory, as published\n"))
        forged[20] ^= 0x01  # one bit of the digest: well-formed, and the signature no longer holds
        _t, _r, as_forged = _tx_result(bytes(forged))
        _t, _r, as_broken = _tx_result(_with_bad_label(bytes(forged)))
        first, second = _page(as_forged), _page(as_broken)
        assert first["statuses"][0] == "DOES NOT VERIFY", "the premise: the forgery reaches the red verdict"
        assert second["statuses"][0] == "RECORD DOES NOT DECODE", "the premise: the label defect breaks the decode"
        for rendered in (first, second):
            assert "verdict-bad" in _first_verdict_class(rendered["classes"])
        assert "not a sign that anything is wrong" not in second["text"]

    def test_an_outcome_nobody_has_heard_of_is_neutral_and_does_not_reassure(self) -> None:
        payload = {"type": "op_return", "hashmark": {"outcome": "from_the_year_3000", "detail": "?"}}
        rendered = _page(_as_script_result(payload))
        assert rendered["statuses"][0] == "NOT CHECKED"
        assert "verdict-unchecked" in _first_verdict_class(rendered["classes"])
        assert "not a sign that anything is wrong" not in rendered["text"]
        assert "from_the_year_3000" in rendered["text"], "it says what the decoder reported"


class TestTheInspectorDoesNotGreyOutAMalformedRecordEither:
    """THE SIBLING. /inspect/ renders the decoder's own outcome name, INVALID, through the same
    `verdictClass` — and it was grey there too. Its word stays (the developer view shows the
    decoder's vocabulary); its colour is the one that must not reassure."""

    def test_invalid_is_red_and_a_future_record_is_not(self) -> None:
        node = shutil.which("node") or _require_node()
        script = (
            "const fs=require('node:fs'),vm=require('node:vm');"
            "const s={console,document:{getElementById:()=>({}),querySelectorAll:()=>[]}};"
            "s.globalThis=s;vm.createContext(s);"
            f"vm.runInContext(fs.readFileSync({str(_INSPECT_DIR / 'shared.js')!r},'utf8'),s);"
            "console.log(JSON.stringify(['INVALID','UNKNOWN VERSION','UNKNOWN ALGORITHM','RECORD DOES NOT DECODE']"
            ".map((w)=>s.verdictClass(w))))"
        )
        out = subprocess.run([node, "-e", script], capture_output=True, text=True, check=True)  # nosec B603
        assert json.loads(out.stdout) == ["verdict-bad", "verdict-unchecked", "verdict-unchecked", "verdict-bad"]

    def test_the_inspector_really_passes_the_decoder_word_to_that_function(self) -> None:
        """The premise of the test above: /inspect/ builds its word from the outcome and hands
        it to `verdictBlock`, which is `verdictClass`. If that path changes, re-derive this."""
        source = (_INSPECT_DIR / "inspect.js").read_text(encoding="utf-8")
        assert 'String(hm.outcome || "").toUpperCase().replace(/_/g, " ")' in source
        assert "class: `verdict ${verdictClass(status)}`" in source


# ───────────────────────────────────── a transaction cannot flood the page ──


def _v1_rows(count: int) -> list[dict]:
    """``count`` output rows exactly as the classifier emits them, from ONE real classified v1
    record — the size of the transaction is the point here, not the variety of its records."""
    _t, _r, result = _tx_result(_record_script(bytes([1, 1]), b"\x33" * 32))
    template = result["payload"]["outputs"][0]
    assert template["hashmark"]["outcome"] == "ok"
    return [{**template, "vout": i} for i in range(count)]


def _many(count: int) -> dict:
    return {
        "ok": True,
        "form": "txid",
        "input": "ab" * 32,
        "payload": {"txid": "ab" * 32, "outputs": _v1_rows(count), "output_count": count},
    }


@pytest.fixture(scope="module")
def limit() -> int:
    """``MAX_MARK_PANELS``, read from verify.js through the harness rather than retyped here."""
    n = _render({})["__constants__"]["max_mark_panels"]
    assert isinstance(n, int), f"verify.js exposes no MAX_MARK_PANELS (got {n!r})"
    return n


class TestATransactionOfManyMarksCannotFloodThePage:
    """One broadcastable transaction of ~72,000 minimal marks rendered every one of them. The
    page now renders a bounded number and says, before and after, how many it left out."""

    def test_the_limit_is_small_and_positive(self, limit) -> None:
        assert 1 <= limit <= 100

    def test_real_marks_past_the_limit_are_counted_not_rendered(self, limit) -> None:
        scripts = [_record_script(bytes([1, 1]), bytes([i % 256]) * 32) for i in range(limit + 7)]
        txid, _r, result = _tx_result(*scripts, limit=limit)
        rendered = _page(result)
        assert len(rendered["panels"]) == limit and rendered["file_inputs"] == limit
        total = limit + 7
        assert f"Mark {limit} of {total}" in rendered["text"]
        assert f"Mark {limit + 1} of" not in rendered["text"]
        flat = " ".join(rendered["text"].split())
        assert f"This transaction carries {total} marks." in flat
        assert f"The first {limit} are shown below; the other 7 are not shown on this page." in flat
        # v1 records: nothing to check, and their NO SIGNATURE is free, so it is KNOWN, not unchecked.
        assert (
            "7 more marks are in this transaction and are not shown here. What this page knows about them: 7 NO SIGNATURE."
            in flat
        )
        assert "not checked here" not in flat and "could be among them" not in flat, "nothing went unchecked"
        assert f"To check every mark in it: pyrxd verify {txid} --min-confirmations N" in flat
        # ORDER: the count before the first panel, the remainder after the last one.
        assert flat.index("The first") < flat.index("Mark 1 of") < flat.index("7 more marks")

    def test_the_page_does_not_grow_with_the_transaction(self, limit) -> None:
        """THE BOUND ITSELF, at the size of the attack. 72,000 rows render exactly as much page
        as limit+1 rows do — the same number of elements, only different numbers in the text."""
        both = _render({"small": {"result": _many(limit + 1)}, "huge": {"result": _many(72_000)}})
        small, huge = both["small"], both["huge"]
        assert len(huge["panels"]) == limit == len(small["panels"])
        assert len(huge["classes"]) == len(small["classes"]), "the page grew with the transaction"
        assert f"{72_000 - limit} more marks are in this transaction" in " ".join(huge["text"].split())

    def test_exactly_the_limit_is_all_shown_with_no_remainder_line(self, limit) -> None:
        """The honest edge: nothing was left out, so nothing may say something was."""
        rendered = _page(_many(limit))
        assert len(rendered["panels"]) == limit
        assert "more mark" not in rendered["text"] and "not shown" not in rendered["text"]
        assert "and is checked separately below." in rendered["text"]

    def test_one_past_the_limit_says_one_in_the_singular(self, limit) -> None:
        flat = " ".join(_page(_many(limit + 1))["text"].split())
        assert (
            "1 more mark is in this transaction and is not shown here. What this page knows about it: 1 NO SIGNATURE."
            in flat
        )


# ─────────────────────────── the WORK is bounded too, and the note says what was done ──


def _signed_distinct(n: int) -> list[bytes]:
    return [_signed_script(f"document {i}\n".encode()) for i in range(n)]


class TestTheWorkIsBoundedNotOnlyTheDrawing:
    """Drawing 50 panels bounded the DOM; the classifier still checked every signature first.
    About 26,000 signed records fit under the 4 MB cap, and in the browser each check is a curve
    recovery on the page's main thread. Now the page's own limit is passed to the classifier:
    signatures past it are not checked (unless the record is a byte-for-byte copy of one that
    was), and the note says exactly which is which."""

    @pytest.fixture
    def recoveries(self, monkeypatch) -> list:
        """Every call the classifier makes to the real `verify_attestation` — each is a recovery."""
        from pyrxd.glyph import _inspect_core

        calls: list = []
        real = _inspect_core.verify_attestation

        def counting(record, **kw):
            calls.append(record.signature_hex)
            return real(record, **kw)

        monkeypatch.setattr(_inspect_core, "verify_attestation", counting)
        return calls

    def test_distinct_signed_records_past_the_limit_are_not_checked(self, limit, recoveries) -> None:
        scripts = _signed_distinct(limit + 5)
        _t, _r, result = _tx_result(*scripts, limit=limit)
        outcomes = [row["hashmark"]["attestation"]["outcome"] for row in result["payload"]["outputs"]]
        assert len(recoveries) == limit, f"{len(recoveries)} signature checks for a limit of {limit}"
        assert outcomes[:limit] == ["valid"] * limit and outcomes[limit:] == ["not_checked_here"] * 5

    def test_copies_are_answered_without_another_check_with_or_without_a_limit(self, limit, recoveries) -> None:
        """Exact, not an approximation: an attestation is a function of the bytes."""
        one = _signed_script(b"the one document\n")
        for lim in (limit, None):
            recoveries.clear()
            _t, _r, result = _tx_result(*([one] * (limit + 20)), limit=lim)
            atts = [row["hashmark"]["attestation"] for row in result["payload"]["outputs"]]
            assert len(recoveries) == 1, (lim, len(recoveries))
            assert all(a == atts[0] for a in atts) and atts[0]["outcome"] == "valid"

    def test_copies_do_not_share_one_mutable_attestation(self) -> None:
        """Checked on the classifier the CLI calls, NOT through glue: glue's sanitiser rebuilds
        every dict on the way out, so aliasing is invisible there — measured, a plant that handed
        every copy the same dict passed the glue-level test. The CLI gets these dicts unrebuilt."""
        from pyrxd.glyph._inspect_core import _classify_raw_tx
        from tests.test_hashmark_verify_cli import _tx_with

        txid, raw = _tx_with(*([_signed_script(b"the one document\n")] * 4))
        for lim in (1, None):
            atts = [
                row["hashmark"]["attestation"]
                for row in _classify_raw_tx(txid, raw, attest_hashmark_limit=lim)["outputs"]
            ]
            assert all(a == atts[0] for a in atts)
            assert len({id(a) for a in atts}) == 4, f"copies share one attestation dict (limit={lim})"

    def test_no_limit_still_checks_every_distinct_record(self, recoveries) -> None:
        """The CLI's path — and the honest pair of the bound: nothing is skipped without a limit."""
        _t, _r, result = _tx_result(*_signed_distinct(7))
        assert len(recoveries) == 7
        assert {row["hashmark"]["attestation"]["outcome"] for row in result["payload"]["outputs"]} == {"valid"}

    def test_a_forgery_past_the_limit_is_reported_not_checked_and_a_clean_copy_is_not(self, limit) -> None:
        """The reviewer's case. CLEAN: limit+1 copies of one genuine record. FORGED: limit copies
        and one forged record last. The page cannot know the forgery is forged without checking
        it — so it must SAY it did not check it, and the two pages must differ."""
        good = _signed_script(b"release 1.0\n")
        forged = bytearray(good)
        forged[20] ^= 0x01  # well-formed; the signature no longer holds
        _t, _r, clean = _tx_result(*([good] * (limit + 1)), limit=limit)
        _t, _r, dirty = _tx_result(*([good] * limit), bytes(forged), limit=limit)
        for result in (clean, dirty):  # the same txid string, so only the records differ
            result["payload"]["txid"] = result["input"] = "ab" * 32
        both = _render({"clean": {"result": clean}, "dirty": {"result": dirty}})
        c, d = (" ".join(both[k]["text"].split()) for k in ("clean", "dirty"))
        assert c != d
        assert "What this page knows about it: 1 VERIFIED." in c and "could be among them" not in c
        assert "What this page knows about it: 1 not checked here." in d
        assert "The one not checked here was past that, so nothing here says whether it verifies" in d
        assert "a mark that does not verify could be among them" in d

    def test_a_forgery_within_the_limit_is_shown_in_the_error_colour(self, limit) -> None:
        good = _signed_script(b"release 1.0\n")
        forged = bytearray(good)
        forged[20] ^= 0x01
        _t, _r, result = _tx_result(*([good] * 10), bytes(forged), *([good] * limit), limit=limit)
        rendered = _page(result)
        assert rendered["statuses"][10] == "DOES NOT VERIFY"
        assert "DOES NOT VERIFY" not in [s for i, s in enumerate(rendered["statuses"]) if i != 10]

    def test_the_page_passes_its_panel_limit_as_the_checking_limit(self) -> None:
        """The one number, structurally: `lookUp` hands MAX_MARK_PANELS to the classifier. The
        render harness drives `renderReport`, not `lookUp`, so this is read from the source."""
        source = (_VERIFY_DIR / "verify.js").read_text(encoding="utf-8")
        code = "\n".join(line for line in source.splitlines() if not line.lstrip().startswith("//"))
        assert "fromPy(pyFetch(txid, rawHex, MAX_MARK_PANELS))" in code
        assert code.count("pyFetch(") == 1, "a second call path to the classifier that may not pass the limit"

    @pytest.mark.parametrize("bad", [-1, 1.5, "50", True])
    def test_the_glue_refuses_a_limit_that_is_not_a_whole_number(self, bad) -> None:
        from tests.test_hashmark_verify_cli import _tx_with

        txid, raw = _tx_with(_record_script(bytes([1, 1]), b"\x11" * 32))
        result = _glue().inspect_txid_with_raw(txid, raw.hex(), bad)
        assert result["ok"] is False and "attest_hashmark_limit" in result["error"]

    def test_the_glue_takes_a_javascript_whole_number(self) -> None:
        """Pyodide may hand a JS number over as a float; 50.0 is 50, not a refusal."""
        from tests.test_hashmark_verify_cli import _tx_with

        txid, raw = _tx_with(_signed_script(b"x"), _signed_script(b"y"))
        result = _glue().inspect_txid_with_raw(txid, raw.hex(), 1.0)
        assert result["ok"], result
        assert [r["hashmark"]["attestation"]["outcome"] for r in result["payload"]["outputs"]] == [
            "valid",
            "not_checked_here",
        ]

    def test_a_record_not_checked_here_never_says_the_curve_failed(self) -> None:
        """Unreachable while the two limits are one number — and kept true if they ever are not."""
        from tests.test_hashmark_verify_cli import _tx_with

        txid, raw = _tx_with(_signed_script(b"x"), _signed_script(b"y"))
        result = _glue().inspect_txid_with_raw(txid, raw.hex(), 1)
        result["payload"]["outputs"] = result["payload"]["outputs"][1:]  # the unchecked one, alone
        flat = " ".join(_page(result)["text"].split())
        assert "NOT CHECKED" in flat and "this one is past that limit" in flat
        assert "did not load" not in flat, "a deliberate skip was blamed on the reader's browser"


class TestTheCommandTheNoteGivesWorks:
    """The note used to say `pyrxd verify <transaction number>`, which the CLI refuses without
    --min-confirmations. The note now carries the whole command; this runs it, as printed, with
    only N filled in, through the real CLI."""

    def test_the_printed_command_runs(self, monkeypatch, tmp_path, limit) -> None:
        import shlex

        from tests.test_hashmark_verify_cli import _FakeServer, _run

        scripts = [_record_script(bytes([1, 1]), bytes([i % 256]) * 32) for i in range(limit + 1)]
        txid, raw, result = _tx_result(*scripts, limit=limit)
        flat = " ".join(_page(result)["text"].split())
        match = re.search(r"To check every mark in it: (pyrxd verify \S+ --min-confirmations N)", flat)
        assert match, "the note carries no command"
        argv = shlex.split(match.group(1).replace(" N", " 6"))
        assert argv[:2] == ["pyrxd", "verify"] and argv[2] == txid
        r = _run(monkeypatch, _FakeServer({txid: raw}), argv[1:], tmp_path=tmp_path)
        assert r.exit_code == 0, r.output
        assert "needs --min-confirmations" not in r.output
        assert "where N is how many blocks must be built on top of the mark's block" in flat


# ─────────────────────────────────── each panel's file check is ITS record's ──


class TestEachPanelComparesAFileAgainstItsOwnRecord:
    """Three marks, three file choosers. A file chosen in panel k must be compared against
    record k's fingerprint — not the first record's, not the last one's. Driven through the
    page's OWN change listeners, with the file really hashed by WebCrypto and the real plan
    from Python; only the judge is a recorder, so what is asserted is what the page hands it."""

    CONTENTS = (b"first file\n", b"second file\n", b"third file\n")

    def test_the_file_is_compared_with_the_panel_it_was_chosen_in(self) -> None:
        import hashlib

        from pyrxd.glyph.inspect import file_check_plan

        digests = [hashlib.sha256(c).hexdigest() for c in self.CONTENTS]
        _t, _r, result = _tx_result(*(_record_script(bytes([1, 1]), bytes.fromhex(d)) for d in digests))
        a, _b, c = (x.decode() for x in self.CONTENTS)
        case = {
            "result": result,
            "file_check_plan": file_check_plan(0x01),
            # A in panel 0 (its own), A in panel 1 (not its own), C in panel 2 (its own).
            "choose_files": [{"input": 0, "text": a}, {"input": 1, "text": a}, {"input": 2, "text": c}],
        }
        rendered = _render({"case": case})["case"]
        assert rendered["file_inputs"] == 3 and len(rendered["panels"]) == 3

        expected = [digests[0], digests[1], digests[2]]
        computed = [digests[0], digests[0], digests[2]]
        assert [j["expected"] for j in rendered["judged"]] == expected, "a panel compared against another's record"
        assert [j["computed"] for j in rendered["judged"]] == computed, "the file was not really hashed"
        assert digests[0] != digests[1], "the premise: the two records differ"

        for k, panel in enumerate(rendered["panels"]):
            lines = panel.split("\n")
            shown = lines[lines.index("the fingerprint in the record") + 1]
            assert shown == digests[k], f"panel {k} showed another record's fingerprint beside the file"
        assert "MATCHES" in rendered["panels"][0] and "DOES NOT MATCH" in rendered["panels"][1]
        assert "MATCHES" in rendered["panels"][2] and "DOES NOT MATCH" not in rendered["panels"][2]


class TestTheBlockShowsTheFingerprintWasKnownNotTheFile:
    """ "Whoever published it knew the file by then" claimed more than a mark supports: a signed
    record can be copied into anyone's transaction, and a v1 record carries whatever fingerprint
    its publisher was given. What the block shows is that the FINGERPRINT was known by then."""

    def test_the_rendered_answer_says_fingerprint(self) -> None:
        from pyrxd.glyph.mark_anchor import UNVERIFIED_CAVEAT

        anchor = {"resolved": True, "height": 460572, "confirmations": 9, "caveat": UNVERIFIED_CAVEAT, "source": "s"}
        flat = " ".join(_page(_as_tx_result(_payload_with_status("valid"), anchor=anchor))["text"].split())
        assert "whoever published it knew that fingerprint by then" in flat
        assert "which is not the same as having had the file" in flat
        assert "knew the file" not in flat

    def test_the_page_chrome_says_it_too(self) -> None:
        """The primer is never rendered by the harness, so it is read directly — flattened,
        because it is hard-wrapped and a sentence can straddle a line break."""
        flat = " ".join((_VERIFY_DIR / "index.html").read_text(encoding="utf-8").split())
        assert "whoever published it knew that fingerprint by then" in flat
        assert "knew the file" not in flat
