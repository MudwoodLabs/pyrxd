"""The browser panel's verdict on a HashMark, including the outcome CI cannot produce.

Why this file is separate from ``test_inspect_js_render_drift``
--------------------------------------------------------------

That guard is structural about FIELDS and derives its shape list from the
classifier's own source, which is why it is the right place for almost everything.
It cannot reach the case this one is about, and the reason is worth stating plainly
because it is a general trap:

    **the corpus is built in an environment where secp256k1 exists.**

``verify_attestation`` returns ``UNVERIFIABLE`` when ``coincurve`` cannot be
imported, and in the browser it never can be — pyrxd installs under Pyodide with
``deps=False`` and coincurve ships no pure-Python wheel. So ``unverifiable`` is not
an edge case on that page, it is *the normal outcome for every v2 record anyone
will ever paste*. In CI, with coincurve installed, no script can produce it: the
axis is invisible to a guard that varies the BYTES, because what varies here is the
RUNTIME.

That blindness had a cost, measured before this file existed. ``inspect.js`` had
branches for ``valid`` and ``invalid_signature`` and none for ``unverifiable``, so
the real mainnet record in
``a1a86ab4503901af4df3d092fcf668b07c03c5cd89240fe918ae70e02e045916`` (height
460,572, and its signature genuinely verifies) rendered a signer and then **no word
at all about its signature**. Not a wrong verdict — no verdict, which is worse,
because a reader supplies the missing sentence and supplies the affirmative one.

So these tests block the import the way the browser does, run the REAL classifier,
and render through the REAL renderer.

What must hold, in one line: **a missing curve is a limitation of the reader, and
must never be rendered as a fact about the record.**
"""

from __future__ import annotations

import importlib.abc
import json
import shutil
import subprocess  # nosec B404 — fixed argv, no shell, repo-local script
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
_HARNESS = _REPO_ROOT / "tests" / "web" / "inspect_render_harness.mjs"

#: The real signed mainnet record, byte-identical to the one in
#: ``tests/test_hashmark_mainnet_vectors.py`` — written by the protocol author's own
#: implementation, not by ours. Used here because the whole point is what this page
#: shows for a mark that is GENUINE: a forgery rendered as unchecked is a nuisance,
#: an honest mark rendered as unchecked-and-therefore-suspect is the failure this
#: page must not commit.
_V2_SIGNED_HEX = (
    "6a08484153484d41524b02020120e2c55efb34b6e9d6db008ee72d56bf86456ab3f55ae76488ff677fda88df1f1e"
    "1426ba056431ec69cf27eabeaab250d99ddbd895d2411f750d18df9ab44ba66ced01285a5a067b9ebf7c8ff6b32d"
    "ddb40cc276c5e98d4c2054937e44a40d7628d80cafdd6a372b0aae8f8bb31dbb4d975273a23e8c9771"
)


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
            pytest.skip("node is missing and PYRXD_SKIP_JS_RENDER_GUARD=1 — the browser panel is UNGUARDED in this run")
        pytest.fail(
            "node is required to run the browser-panel guard (it loads "
            "docs/inspect_static/inspect/inspect.js in a Node vm). Install node, or set "
            "PYRXD_SKIP_JS_RENDER_GUARD=1 to skip it deliberately and accept that the "
            "panel is unverified in this run."
        )
    return node


def _render(cases: dict) -> dict:
    """Render through the production `inspect.js`, loaded verbatim."""
    proc = subprocess.run(  # nosec B603 — fixed argv, no shell, repo-local script
        [_require_node(), str(_HARNESS), "-"],
        input=json.dumps(cases),
        capture_output=True,
        text=True,
        check=False,
        cwd=str(_REPO_ROOT),
    )
    if proc.returncode != 0:
        pytest.fail(f"render harness failed (exit {proc.returncode}):\n{proc.stderr}")
    return json.loads(proc.stdout)


def _as_row(script_payload: dict) -> dict:
    """The same dict a fetched transaction's output row carries."""
    row = dict(script_payload)
    row.pop("form", None)
    row["vout"] = 0
    row["satoshis"] = 0
    return row


def _both_surfaces(payload: dict, *, row_opts: dict | None = None) -> dict[str, str]:
    """``{"script_card": text, "output_row": text}`` from the real renderer."""
    case = {"script": payload, "row": _as_row(payload)}
    if row_opts is not None:
        case["row_opts"] = row_opts
    return _render({"case": case})["case"]


# ───────────────────────────────── the outcome the corpus cannot reach ──


def _classes(payload: dict) -> list[str]:
    """Every `class` attribute the script card renders, in document order."""
    return _render({"case": {"script": payload}})["case"]["script_card_classes"]


class TestAMissingCurveIsNotAVerdict:
    """The single most important property on this page."""

    @pytest.fixture
    def payload(self, without_coincurve) -> dict:
        from pyrxd.glyph._inspect_core import _inspect_script

        return _inspect_script(_V2_SIGNED_HEX)

    def test_the_classifier_really_does_withhold_here(self, payload) -> None:
        """Non-vacuity. Without this, every assertion below could be passing against
        a payload whose signature verified normally, and the whole file would prove
        nothing about the browser at all."""
        assert payload["hashmark"]["attestation"]["outcome"] == "unverifiable", (
            "the coincurve block did not take effect, so these tests are not exercising the browser's situation"
        )

    @pytest.mark.parametrize("surface", ["script_card", "output_row"])
    def test_the_page_says_it_was_not_checked(self, payload, surface) -> None:
        """The branch that did not exist. A v2 record showing a signer and no word
        about its signature reads as "fine" far more than it reads as "unchecked"."""
        text = _both_surfaces(payload)[surface]
        assert "NOT CHECKED" in text

    @pytest.mark.parametrize("surface", ["script_card", "output_row"])
    def test_it_says_that_is_not_a_verdict_on_the_record(self, payload, surface) -> None:
        text = _both_surfaces(payload)[surface]
        assert "this is not a verdict on it" in text

    @pytest.mark.parametrize("surface", ["script_card", "output_row"])
    def test_it_names_whose_limitation_it_is(self, payload, surface) -> None:
        """ "Not checked" without a reason invites the reader to assume the record is
        at fault. The reason is the reader's browser, and it says so."""
        assert "secp256k1" in _both_surfaces(payload)[surface]

    @pytest.mark.parametrize("surface", ["script_card", "output_row"])
    def test_it_never_says_the_signature_failed(self, payload, surface) -> None:
        """THE WHOLE POINT. Showing a red cross beside an honest signer's mark
        because the reader's browser lacks a curve library is the worst thing this
        page could do — and the record here is real, from mainnet, and genuine."""
        text = _both_surfaces(payload)[surface]
        assert "DOES NOT VERIFY" not in text
        assert "INVALID" not in text.upper().replace("UNVERIFIABLE", "")

    def test_it_is_not_painted_with_the_error_colour(self, payload: dict) -> None:
        """THE PIXELS, NOT THE WORDS.

        Every other assertion here reads TEXT. The verdict blocks carry their colour in
        a class — `verdict-unchecked` takes the normal foreground, `verdict-bad` takes
        the error colour. Nothing pinned that, so a one-word change in `_verdictClass`
        could paint an honest signer's mark red while "NOT CHECKED" still appeared and
        every test above stayed green.

        A forgery shown as unchecked is a nuisance. An honest mark shown in the error
        colour because the READER's browser has no curve library is an accusation the
        page has no basis for, and it is the failure this whole surface exists to avoid.
        """
        classes = _classes(payload)
        assert any("verdict-unchecked" in c for c in classes), (
            f"expected a neutral verdict block, got classes: {classes}"
        )
        assert not any("verdict-bad" in c for c in classes), (
            f"an unverifiable mark was painted with the error class: {classes}"
        )

    def test_the_class_assertion_can_actually_see_a_bad_verdict(self, payload: dict) -> None:
        """The control: prove `verdict-bad` IS reachable, so the check above is not vacuous.

        Without this, a renderer that emitted no classes at all would satisfy the
        "no verdict-bad" half for the wrong reason.
        """
        forged = json.loads(json.dumps(payload))
        forged["hashmark"]["attestation"]["outcome"] = "invalid_signature"
        forged["hashmark"]["attestation"]["status"] = "DOES NOT VERIFY"
        assert any("verdict-bad" in c for c in _classes(forged)), (
            "the harness never reports verdict-bad, so the absence check above proves nothing"
        )

    @pytest.mark.parametrize("surface", ["script_card", "output_row"])
    def test_the_evidence_a_reader_can_act_on_still_reaches_them(self, payload, surface) -> None:
        """Only the VERDICT is withheld. The digest and the signer the record names
        need no curve at all, and withholding them too would turn a missing
        dependency into a missing record."""
        text = _both_surfaces(payload)[surface]
        assert "e2c55efb34b6e9d6db008ee72d56bf86456ab3f55ae76488ff677fda88df1f1e" in text
        assert "26ba056431ec69cf27eabeaab250d99ddbd895d2" in text

    def test_the_two_surfaces_say_the_same_thing(self, payload) -> None:
        """A pasted script and a fetched output are the same record. One renderer
        serves both precisely so they cannot come to disagree on screen; this is the
        assertion that keeps it that way."""
        rendered = _both_surfaces(payload)
        for phrase in ("NOT CHECKED", "this is not a verdict on it", "secp256k1"):
            assert phrase in rendered["script_card"] and phrase in rendered["output_row"], phrase


# ─────────────────────────────────────── one vocabulary, three surfaces ──


class TestTheTerminalAndThePageUseOneVocabulary:
    """Two prose copies in two languages is how the browser lost its
    ``unverifiable`` branch while the CLI kept one. The words now come from
    ``_inspect_core._ATTESTATION_VERDICTS`` and both surfaces read them."""

    @pytest.mark.parametrize(
        "outcome,expected",
        [
            ("valid", "VERIFIED"),
            ("invalid_signature", "DOES NOT VERIFY"),
            ("unverifiable", "NOT CHECKED"),
            # "NO SIGNATURE" — `pyrxd verify` shipped that spelling first and the shared
            # table adopted it, so one record is not described two ways.
            ("not_attested", "NO SIGNATURE"),
        ],
    )
    def test_every_outcome_has_a_status_and_the_cli_prints_it(self, outcome, expected) -> None:
        from pyrxd.cli.glyph_inspect import _op_return_payload_lines
        from pyrxd.glyph._inspect_core import _attestation_verdict

        status, meaning = _attestation_verdict(outcome)
        assert status == expected
        hm = {
            "outcome": "ok",
            "version": 2 if outcome != "not_attested" else 1,
            "algorithm": "sha256",
            "digest": "cd" * 32,
            "attestation": {"outcome": outcome, "status": status, "meaning": meaning, "detail": ""},
        }
        if outcome != "not_attested":
            hm["signer_hash160"] = "ab" * 20
        text = "\n".join(_op_return_payload_lines({"hashmark": hm}))
        assert f"signature {status}" in text

    @pytest.mark.parametrize("outcome", ["valid", "invalid_signature", "unverifiable", "not_attested"])
    def test_the_browser_prints_the_same_status_word(self, outcome) -> None:
        from pyrxd.glyph._inspect_core import _attestation_verdict

        status, meaning = _attestation_verdict(outcome)
        payload = {
            "type": "op_return-hashmark-v2",
            "length": 133,
            "hashmark": {
                "outcome": "ok",
                "version": 2,
                "algorithm": "sha256",
                "algorithm_id": 1,
                "digest": "cd" * 32,
                "signer_hash160": "ab" * 20,
                "committed_signer_address": "1SomeAddressThatIsNotReal",
                "attestation": {"outcome": outcome, "status": status, "meaning": meaning, "detail": ""},
            },
        }
        text = _both_surfaces(payload)["script_card"]
        assert status in text, f"the page did not print {status!r} for outcome {outcome!r}"
        assert meaning in text

    def test_an_outcome_nobody_has_heard_of_fails_toward_unknown(self) -> None:
        """A new outcome defaulting to VERIFIED is a forgery shown as genuine; one
        defaulting to DOES NOT VERIFY is an honest mark shown as a lie. Neither is an
        acceptable default, so the default is neither."""
        from pyrxd.glyph._inspect_core import _attestation_verdict

        status, meaning = _attestation_verdict("some_future_outcome")
        assert status == "NOT CHECKED"
        assert "does not know" in meaning


# ──────────────────────────────── whose address is on the screen, and why ──


class TestTheRecoveredKeyIsNotCalledTheSigner:
    """``attestation.signer_address`` is the key the signature RECOVERS TO.

    The page printed it under the label "signer address" for every outcome — so on a
    forged record it labelled *whatever key the attacker's signature recovers to* as
    the signer, directly below a line saying the signature does not verify. Two
    elements on one card, disagreeing. The CLI never did this: it prints that address
    only when the outcome is ``valid``, where recovered and committed are equal by
    construction.
    """

    @staticmethod
    def _forged_payload() -> dict:
        return {
            "type": "op_return-hashmark-v2",
            "length": 133,
            "hashmark": {
                "outcome": "ok",
                "version": 2,
                "algorithm": "sha256",
                "algorithm_id": 1,
                "digest": "cd" * 32,
                "signer_hash160": "ab" * 20,
                "committed_signer_address": "1CommittedAddressFromTheRecord",
                "attestation": {
                    "outcome": "invalid_signature",
                    "status": "DOES NOT VERIFY",
                    "meaning": "the record is well-formed; its claim is not supported",
                    "recovered_hash160": "ee" * 20,
                    "signer_address": "1AttackerRecoveredAddress",
                    "detail": "recovered key does not match the committed signer",
                },
            },
        }

    @pytest.mark.parametrize("surface", ["script_card", "output_row"])
    def test_the_recovered_address_is_never_labelled_as_the_signer(self, surface) -> None:
        """Scoped to the row's OWN label, not to a character window before it.

        The first version of this test looked back 200 characters and failed on the
        *neighbouring* row's label — the same defect shape as a guard that judges
        negation by scanning a raw span instead of the governing unit. The harness
        emits one text node per line, and a kv pair is label-then-value, so the label
        of a value is the line directly above it. That is the unit.
        """
        lines = _both_surfaces(self._forged_payload())[surface].splitlines()
        assert "1AttackerRecoveredAddress" in "\n".join(lines), "the recovered key must still be shown"
        for i, line in enumerate(lines):
            if "1AttackerRecoveredAddress" not in line:
                continue
            label = lines[i - 1].strip().lower()
            assert label != "signer address", (
                f"line {i} holds the key a FAILED signature recovers to, under the label "
                f"{lines[i - 1]!r}. That is the attacker's key, named as the signer.\n" + "\n".join(lines)
            )
            assert "recovered" in label, f"expected a label naming it as recovered, got {lines[i - 1]!r}"

    @pytest.mark.parametrize("surface", ["script_card", "output_row"])
    def test_it_says_the_recovered_key_is_not_the_one_named(self, surface) -> None:
        assert "NOT the signer this record names" in _both_surfaces(self._forged_payload())[surface]

    @pytest.mark.parametrize("surface", ["script_card", "output_row"])
    def test_the_committed_address_is_flagged_unverified_when_nothing_was_checked(self, surface) -> None:
        """The honest path for the browser's own normal case: the record NAMES a key,
        and saying so is useful — as long as "named" is not allowed to read as
        "proved"."""
        payload = self._forged_payload()
        att = payload["hashmark"]["attestation"]
        att.update(
            {"outcome": "unverifiable", "status": "NOT CHECKED", "recovered_hash160": None, "signer_address": None}
        )
        text = _both_surfaces(payload)[surface]
        assert "committed, unverified here" in text
        assert "1CommittedAddressFromTheRecord" in text

    def test_a_verified_signature_drops_the_qualifier(self) -> None:
        """A guard that refuses valid work is a bug: when the signature DOES verify,
        the address is the signer's and must not be hedged into uselessness."""
        payload = self._forged_payload()
        payload["hashmark"]["attestation"] = {
            "outcome": "valid",
            "status": "VERIFIED",
            "meaning": "recovers to the committed signer",
            "recovered_hash160": "ab" * 20,
            "signer_address": "1CommittedAddressFromTheRecord",
            "assumed_network": "radiant-mainnet",
            "detail": None,
        }
        text = _both_surfaces(payload)["script_card"]
        assert "committed, unverified here" not in text
        assert "NOT the signer this record names" not in text
        assert "1CommittedAddressFromTheRecord" in text


# ────────────────────────────────────────── the block, and its absence ──


class TestTheBlockDegradesWithAReason:
    """A mark's claim is "no later than the block that confirms this", so the block is
    load-bearing — and the commonest input to this page has none."""

    @staticmethod
    def _payload() -> dict:
        return {
            "type": "op_return-hashmark-v2",
            "length": 133,
            "hashmark": {
                "outcome": "ok",
                "version": 2,
                "algorithm": "sha256",
                "algorithm_id": 1,
                "digest": "cd" * 32,
                "signer_hash160": "ab" * 20,
                "committed_signer_address": "1Committed",
                "attestation": {"outcome": "unverifiable", "status": "NOT CHECKED", "meaning": "m", "detail": "d"},
            },
        }

    def test_a_pasted_script_says_why_there_is_no_block(self) -> None:
        """Failure degrades with a REASON, never to silence. A pasted script has no
        transaction, so the point-in-time form is unavailable by construction — and
        an empty row would read as "we did not bother"."""
        text = _both_surfaces(self._payload())["script_card"]
        assert "not established" in text
        assert "carries no transaction" in text

    def test_a_resolved_anchor_shows_the_height_and_the_depth(self) -> None:
        anchor = {
            "resolved": True,
            "txid": "aa" * 32,
            "height": 460572,
            "confirmations": 5143,
            "source": "an endpoint",
            "caveat": "height reported by the endpoint and NOT verified",
            "height_is_verified": False,
            "no_depth_policy": "this page sets no confirmation-depth requirement",
        }
        text = _both_surfaces(self._payload(), row_opts={"anchor": anchor})["output_row"]
        assert "460572" in text
        assert "5143" in text

    def test_the_height_is_never_presented_as_proved(self) -> None:
        """pyrxd has no Radiant header, proof-of-work or merkle check. The height is
        an endpoint's claim, and the caveat that says so travels with it."""
        anchor = {
            "resolved": True,
            "height": 460572,
            "confirmations": 5143,
            "source": "an endpoint",
            "caveat": "height reported by the endpoint and NOT verified",
            "no_depth_policy": "this page sets no confirmation-depth requirement",
        }
        text = _both_surfaces(self._payload(), row_opts={"anchor": anchor})["output_row"]
        assert "NOT verified" in text

    def test_no_depth_verdict_is_invented(self) -> None:
        """``resolve_mark_anchor`` ships no default depth because depth is
        value-scaled per chain and a shipped number is folklore. This page does not
        invent one either: it publishes the count and says the judgement is the
        reader's."""
        anchor = {
            "resolved": True,
            "height": 1,
            "confirmations": 1,
            "source": "an endpoint",
            "caveat": "c",
            "no_depth_policy": "this page sets no confirmation-depth requirement",
        }
        text = _both_surfaces(self._payload(), row_opts={"anchor": anchor})["output_row"]
        assert "sets no confirmation-depth requirement" in text

    def test_an_unconfirmed_mark_says_it_fixes_no_time(self) -> None:
        """0 confirmations is not a young mark, it is no mark yet. Printing
        "0 confirmations" alone invites the first reading."""
        anchor = {"resolved": True, "height": None, "confirmations": 0, "source": "an endpoint", "caveat": "c"}
        text = _both_surfaces(self._payload(), row_opts={"anchor": anchor})["output_row"]
        assert "fixes no time" in text

    def test_a_failed_lookup_says_so_rather_than_showing_nothing(self) -> None:
        anchor = {"resolved": False, "reason": "the endpoint answered about a different transaction"}
        text = _both_surfaces(self._payload(), row_opts={"anchor": anchor})["output_row"]
        assert "not established" in text
        assert "answered about a different transaction" in text


# ─────────────────────────────────────────────────────── the file check ──


class TestTheFileCheckIsOfferedHonestly:
    @staticmethod
    def _payload(**over) -> dict:
        hm = {
            "outcome": "ok",
            "version": 2,
            "algorithm": "sha256",
            "algorithm_id": 1,
            "digest": "cd" * 32,
            "signer_hash160": "ab" * 20,
            "committed_signer_address": "1Committed",
            "attestation": {"outcome": "unverifiable", "status": "NOT CHECKED", "meaning": "m", "detail": "d"},
        }
        hm.update(over)
        return {"type": "op_return-hashmark-v2", "length": 133, "hashmark": hm}

    @pytest.mark.parametrize("surface", ["script_card", "output_row"])
    def test_the_privacy_promise_is_stated_where_the_file_is_chosen(self, surface) -> None:
        """``pyrxd mark`` promises ITS CONTENTS DO NOT GO ON CHAIN. A checking
        surface that quietly uploaded the file would break that promise from the
        other end, so the page states the same thing at the point of choosing."""
        text = _both_surfaces(self._payload())[surface]
        assert "never leaves this machine" in text
        assert "nothing is uploaded" in text

    @pytest.mark.parametrize("surface", ["script_card", "output_row"])
    def test_the_named_algorithm_is_the_records_own(self, surface) -> None:
        """Not a hardcoded "sha256". A surface that picked its own hash would produce
        a well-formed, confident, wrong answer that nothing downstream could detect."""
        text = _both_surfaces(self._payload())[surface]
        assert "hashes it with sha256 — the algorithm this record names" in text

    def test_the_sentence_names_whatever_the_record_says_not_sha256(self) -> None:
        """A case whose answer cannot be faked by the status quo.

        The test above cannot tell a renderer that reads ``hm.algorithm`` from one
        that prints the literal "sha256": today ``_ALGORITHMS`` holds exactly one
        entry, so both produce the same sentence for every record that exists.
        Measured — planting the hardcode broke nothing.

        So this feeds a record naming an algorithm that is NOT sha256. The classifier
        cannot produce one yet, and that is the point: the RENDERER's contract is to
        print the name the record carries, and the day a second id is registered is
        the day a hardcode starts telling people to hash with the wrong function
        while every other field on the card stays correct.
        """
        payload = self._payload(algorithm="sha512", algorithm_id=2, digest="ab" * 64)
        text = _both_surfaces(payload)["script_card"]
        assert "hashes it with sha512" in text
        assert "sha256" not in text, "the note printed a hash the record does not name"

    def test_a_record_with_no_digest_is_offered_no_check(self) -> None:
        """Offering a comparison against nothing is worse than offering none."""
        text = _both_surfaces(self._payload(digest=None))["script_card"]
        assert "Do you have the file?" not in text


class TestTheFileVerdictWordsComeFromPython:
    """The comparison is one line of ``===``; the WORDS are what a reader acts on,
    and they live beside the attestation's in ``_inspect_core`` so one screen cannot
    show two vocabularies."""

    def test_a_matching_digest_matches(self) -> None:
        from pyrxd.glyph.inspect import judge_file_digest

        verdict = judge_file_digest("ab" * 32, "AB" * 32, algorithm="sha256")
        assert verdict["status"] == "MATCHES" and verdict["match"] is True

    def test_the_meaning_stops_short_of_authorship(self) -> None:
        """The sentence next to a verified result is the riskiest text on the page:
        it inherits the result's authority while asserting something nobody checked.
        A digest match says these are the bytes. It says nothing about who made them."""
        from pyrxd.glyph.inspect import judge_file_digest

        meaning = judge_file_digest("ab" * 32, "ab" * 32, algorithm="sha256")["meaning"]
        assert "does not say who made them" in meaning

    def test_a_different_file_does_not_match(self) -> None:
        from pyrxd.glyph.inspect import judge_file_digest

        verdict = judge_file_digest("ab" * 32, "cd" * 32, algorithm="sha256")
        assert verdict["status"] == "DOES NOT MATCH" and verdict["match"] is False

    def test_a_different_WIDTH_is_not_a_mismatch(self) -> None:
        """ "DOES NOT MATCH" would tell someone their file is the wrong file, when
        what actually happened is that the wrong hash ran. Two values of different
        widths are not comparable, and that is a third answer, not a negative one."""
        from pyrxd.glyph.inspect import judge_file_digest

        verdict = judge_file_digest("ab" * 32, "cd" * 20, algorithm="sha256")
        assert verdict["status"] == "NOT CHECKED"
        assert verdict["match"] is None
        assert "cannot be compared" in verdict["meaning"]

    def test_a_record_with_no_digest_is_not_judged(self) -> None:
        from pyrxd.glyph.inspect import judge_file_digest

        assert judge_file_digest(None, "ab" * 32)["status"] == "NOT CHECKED"


class TestTheHashComesFromTheRecordNotFromThePage:
    def test_the_records_algorithm_id_selects_the_hash(self) -> None:
        from pyrxd.glyph.inspect import file_check_plan

        plan = file_check_plan(0x01)
        assert plan == {"ok": True, "algorithm": "sha256", "webcrypto_name": "SHA-256"}

    def test_an_algorithm_this_build_cannot_read_degrades_with_its_id(self) -> None:
        """A record from the future is not a broken record. Saying WHICH algorithm it
        names is the difference between a reader who can go and find out and one who
        cannot."""
        from pyrxd.glyph.inspect import file_check_plan

        plan = file_check_plan(0x07)
        assert plan["ok"] is False
        assert "0x07" in plan["reason"]

    def test_the_spelling_is_derived_rather_than_tabulated(self) -> None:
        """A hand-kept map of the one entry that exists today goes stale silently the
        moment a second algorithm id is registered — and the page would fall back to
        whatever it had hardcoded and check the file against the wrong hash."""
        from pyrxd.glyph._inspect_core import _webcrypto_name

        assert _webcrypto_name("sha256") == "SHA-256"
        assert _webcrypto_name("sha512") == "SHA-512"
        assert _webcrypto_name("sha384") == "SHA-384"

    def test_a_hash_no_browser_can_compute_returns_none(self) -> None:
        """SubtleCrypto implements a closed set. Guessing a spelling for something
        outside it would produce a silent failure at the one moment the reader is
        trusting the answer."""
        from pyrxd.glyph._inspect_core import _webcrypto_name

        assert _webcrypto_name("sha3_256") is None
        assert _webcrypto_name("blake2b") is None
        assert _webcrypto_name("") is None

    def test_the_algorithm_table_is_the_only_authority(self) -> None:
        """``file_check_plan`` must not spell an algorithm name itself: the decoder
        read the record's header byte through ``_ALGORITHMS`` and anything that
        re-spells it has created a second source of truth for what the record CLAIMS
        versus what was actually hashed."""
        import ast
        import inspect as _i
        import textwrap

        from pyrxd.glyph import _inspect_core
        from pyrxd.script.hashmark import algorithm_for

        source = _i.getsource(_inspect_core._file_check_plan)
        assert "algorithm_for(" in source, "the table must be consulted, not bypassed"

        # AST, not a substring search: the function's own docstring says the word
        # "sha256" while EXPLAINING that it must not spell it, and a text search
        # cannot tell the explanation from the offence. String CONSTANTS in the code
        # are the thing being forbidden.
        tree = ast.parse(textwrap.dedent(source))
        func = tree.body[0]
        body = func.body[1:] if ast.get_docstring(func) else func.body
        literals = {
            node.value
            for stmt in body
            for node in ast.walk(stmt)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
        }
        known = {algorithm_for(0x01)}
        assert not (literals & known), (
            f"_file_check_plan spells an algorithm name itself ({literals & known}), which makes it "
            f"a second source of truth for what the record claims versus what was hashed"
        )


class TestAnUnreadableRecordIsNotAFailedSignature:
    """The three ways a record can claim to be a HashMark and not be readable as one.

    None of these reaches the corpus in ``test_inspect_js_render_drift``, and not by
    oversight: the classifier leaves ``type`` as plain ``op_return`` for all of them,
    so that file's coverage check — which asks whether every emitted ``type`` has a
    corpus shape — is satisfied by the ordinary ``op_return`` entry and never looks
    at the ``hashmark`` block these carry.

    What must hold is a distinction: ``unknown_version`` and ``unknown_algorithm``
    are records from the FUTURE, not forgeries. A page that rendered them in the
    language of a failed signature would teach a reader to distrust the next
    protocol version.
    """

    @staticmethod
    def _script(header: bytes) -> str:
        def push(b: bytes) -> bytes:
            return bytes([len(b)]) + b

        return (b"\x6a" + push(b"HASHMARK") + push(header) + push(bytes(32))).hex()

    @pytest.fixture
    def cases(self) -> dict[str, dict]:
        from pyrxd.glyph._inspect_core import _inspect_script

        return {
            "unknown_version": _inspect_script(self._script(bytes([9, 1]))),
            "unknown_algorithm": _inspect_script(self._script(bytes([2, 7]))),
        }

    def test_the_classifier_really_produces_these_outcomes(self, cases) -> None:
        """Non-vacuity: these bytes must actually reach the branch under test."""
        for expected, payload in cases.items():
            assert payload["hashmark"]["outcome"] == expected

    @pytest.mark.parametrize("which", ["unknown_version", "unknown_algorithm"])
    @pytest.mark.parametrize("surface", ["script_card", "output_row"])
    def test_it_says_the_verdict_is_about_the_bytes(self, cases, which, surface) -> None:
        text = _both_surfaces(cases[which])[surface]
        assert "not readable here" in text
        assert "not on anyone's signature" in text

    @pytest.mark.parametrize("which", ["unknown_version", "unknown_algorithm"])
    @pytest.mark.parametrize("surface", ["script_card", "output_row"])
    def test_it_never_borrows_the_language_of_a_failed_signature(self, cases, which, surface) -> None:
        text = _both_surfaces(cases[which])[surface]
        assert "DOES NOT VERIFY" not in text
        assert "VERIFIED" not in text

    @pytest.mark.parametrize("surface", ["script_card", "output_row"])
    def test_an_unknown_algorithm_says_WHICH_one(self, cases, surface) -> None:
        """``algorithm`` is ``None`` for this outcome, so the NAME cannot carry it.
        Without ``algorithm_id`` in the payload a reader is told a record names an
        algorithm this build cannot read, and never told which — which is the
        difference between being able to go and find out and not."""
        text = _both_surfaces(cases["unknown_algorithm"])[surface]
        assert "0x07" in text

    @pytest.mark.parametrize("surface", ["script_card", "output_row"])
    def test_an_unknown_version_says_WHICH_one(self, cases, surface) -> None:
        text = _both_surfaces(cases["unknown_version"])[surface]
        assert "9" in text

    @pytest.mark.parametrize("surface", ["script_card", "output_row"])
    def test_no_file_check_is_offered_for_a_record_with_no_digest(self, cases, surface) -> None:
        """Offering to compare a file against nothing would be a control that cannot
        answer, on a card that has just said it cannot read the record."""
        assert "Do you have the file?" not in _both_surfaces(cases["unknown_version"])[surface]
