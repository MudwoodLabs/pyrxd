"""The browser hashes a chosen file with the algorithm the RECORD names.

WHY THIS FILE EXISTS: a planted defect survived the whole suite.

``hashFileWithRecordAlgorithm`` in ``docs/inspect_static/inspect/shared.js`` was
changed from ``crypto.subtle.digest(plan.webcrypto_name, …)`` to
``crypto.subtle.digest("SHA-256", …)`` and 428 tests passed. That is precisely the
defect ``file_check_plan`` exists to prevent: a surface that picks its own hash
produces a well-formed, confident, completely wrong MATCHES or DOES NOT MATCH for
any record that names something other than sha256, and nothing downstream can
detect the disagreement — the record still decodes, the signature still verifies.

The Python half was never the gap. ``pyrxd.glyph.inspect.file_check_plan`` reads
``algorithm_for``, and ``test_hashmark_panel_verdict.TestTheHashComesFromTheRecord
NotFromThePage`` AST-scans it to prove it never spells an algorithm name itself.
What nothing executed was the JAVASCRIPT that decides what to do with the plan:
both render harnesses stub ``crypto: {"subtle": {}}`` and never reach this
function.

WHAT IS REAL AND WHAT IS SHIMMED — stated plainly, because a mock standing in for
the subject proves the mock:

* REAL: the function under test, loaded verbatim; Node's WebCrypto doing the
  hashing; a real ``File``; and a reference digest computed independently with
  ``node:crypto``, so the BYTES are checked and not merely the call.
* SHIMMED: ``file_check_plan`` and ``judge_file_digest``, the two Python bridges.
  They are not the subject here and they are exercised for real, directly, in
  ``tests/web/test_hashmark_panel_verdict.py``; ``test_mark_anchor_bridge.py``
  proves the page can reach them at all. This file owns one claim only — that the
  JS hashes with the algorithm the plan named, and hands the judge both digests
  unchanged.

THE FIXTURE USES SHA-512 DELIBERATELY. Under sha256 a hardcoded ``"SHA-256"`` and
a plan-driven one produce identical bytes, and every assertion here would pass for
the wrong reason. Where two quantities can be equal by construction, pick values
where they differ.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess  # nosec B404 — fixed argv, no shell, repo-local script
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
_HARNESS = _REPO_ROOT / "tests" / "web" / "file_check_harness.mjs"

_CONTENT = "the-file-this-mark-is-about\n"
_SHA512 = hashlib.sha512(_CONTENT.encode()).hexdigest()
_SHA256 = hashlib.sha256(_CONTENT.encode()).hexdigest()

_SHA512_PLAN = {"ok": True, "algorithm": "sha512", "webcrypto_name": "SHA-512"}


def _require_node() -> str:
    node = shutil.which("node")
    if node is None:
        if os.environ.get("PYRXD_SKIP_JS_RENDER_GUARD") == "1":
            pytest.skip("node is missing and PYRXD_SKIP_JS_RENDER_GUARD=1 — the file check is UNGUARDED in this run")
        pytest.fail(
            "node is required to run the file-check guard (it loads shared.js in a Node "
            "vm against Node's WebCrypto). Install node, or set "
            "PYRXD_SKIP_JS_RENDER_GUARD=1 to skip it deliberately."
        )
    return node


def _check(**spec) -> dict:
    proc = subprocess.run(  # nosec B603 — fixed argv, no shell, repo-local script
        [_require_node(), str(_HARNESS), "-"],
        input=json.dumps({"case": spec}),
        capture_output=True,
        text=True,
        check=False,
        cwd=str(_REPO_ROOT),
    )
    if proc.returncode != 0:
        pytest.fail(f"file-check harness failed (exit {proc.returncode}):\n{proc.stderr}")
    return json.loads(proc.stdout)["case"]


class TestTheHashIsTheRecordsChoiceNotThePages:
    def test_it_asks_webcrypto_for_the_algorithm_the_plan_named(self) -> None:
        """THE ASSERTION THE PLANT BROKE. Nothing else in the suite looks at which
        algorithm the browser actually requested."""
        out = _check(plan=_SHA512_PLAN, bytes=_CONTENT, digest=_SHA512)
        assert out["requested"] == ["SHA-512"], (
            f"the page hashed with {out['requested']} while the record's plan named SHA-512"
        )

    def test_the_digest_it_produces_is_the_right_one(self) -> None:
        """Not only the call — the BYTES, against a digest Python computed here and
        one Node computed independently inside the harness. Three routes, one answer."""
        out = _check(plan=_SHA512_PLAN, bytes=_CONTENT, digest=_SHA512)
        assert out["computed"] == _SHA512
        assert out["reference"] == _SHA512

    def test_the_two_algorithms_really_do_differ_on_this_fixture(self) -> None:
        """NON-VACUITY, and the reason the fixture is sha512. If the record's hash and
        the one a defect would hardcode produced the same bytes, every assertion above
        would pass just as well against the defect."""
        assert _SHA512 != _SHA256
        assert len(_SHA512) != len(_SHA256)

    def test_the_judge_receives_both_digests_unchanged(self) -> None:
        """The comparison and its words are Python's. What this side owes it is the
        record's digest and the computed one, untouched — a page that normalised,
        truncated or re-cased either would be deciding the outcome here."""
        out = _check(plan=_SHA512_PLAN, bytes=_CONTENT, digest=_SHA512)
        assert out["judged"] == {"expected": _SHA512, "computed": _SHA512, "algorithm": "sha512"}

    def test_a_plan_the_build_cannot_satisfy_refuses_rather_than_guessing(self) -> None:
        """A record naming an algorithm no browser implements must produce NOTHING,
        not a fallback. The fallback IS the defect — and the reason travels with it,
        because a control that goes dead without saying why reads as a broken page."""
        out = _check(
            plan={"ok": False, "reason": "blake2b is not one of the hashes a browser can compute"},
            bytes=_CONTENT,
            digest=_SHA512,
        )
        assert out["ok"] is False
        assert out["requested"] == [], "the page hashed the file anyway after the plan refused"
        assert "blake2b" in out["reason"]

    def test_a_page_with_no_webcrypto_says_so_instead_of_dying_quietly(self) -> None:
        """Plain http:// from anything but localhost is not a secure context and gets
        no WebCrypto at all. A silent dead control is worse than a stated limitation."""
        out = _check(plan=_SHA512_PLAN, bytes=_CONTENT, digest=_SHA512, no_subtle=True)
        assert out["ok"] is False
        assert "secure context" in out["reason"]
        assert out["algorithm"] == "sha512", "the refusal must still name the record's algorithm"

    def test_a_file_too_large_to_hold_is_refused_with_its_size(self) -> None:
        """``crypto.subtle.digest`` has no streaming form, so the whole file has to be
        resident. The cap is a real limit and the refusal names it rather than taking
        the tab down."""
        out = _check(plan=_SHA512_PLAN, bytes=_CONTENT, digest=_SHA512, size_override=512 * 1024 * 1024)
        assert out["ok"] is False
        assert out["requested"] == []
        assert "streaming digest" in out["reason"]

    def test_an_honest_file_of_ordinary_size_is_not_refused(self) -> None:
        """A guard that refuses valid work is a bug. Paired with the cap test above so
        the limit cannot drift down into the range real files occupy."""
        out = _check(plan=_SHA512_PLAN, bytes=_CONTENT, digest=_SHA512, size_override=64 * 1024 * 1024)
        assert out["ok"] is True
        assert out["requested"] == ["SHA-512"]
