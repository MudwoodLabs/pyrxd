"""`stripControlChars` must run on both sibling error paths, not just one.

``docs/inspect_static/inspect/inspect.js``'s ``fetchRawTxFromElectrumx``
builds an ``Error`` from server-supplied bytes on two branches of its
WebSocket "message" handler:

* the ``JSON.parse`` catch — ``server returned non-JSON: ${err.message}``,
  where ``err`` is a V8 ``SyntaxError`` that echoes a slice of the raw,
  attacker-controlled frame text verbatim (confirmed against Node: a
  malformed frame straddled by U+202E/U+200B reproduces those characters
  inside ``err.message``);
* the ``frame.error`` branch — ``server error: ${...}``, built from
  ``frame.error.message`` after a well-formed JSON-RPC error frame.

Only the second branch was passed through ``stripControlChars`` before this
test existed. The first has *fewer* preconditions to reach (no ``id === 1``
match required) and was the unguarded sibling: a hostile ElectrumX server
could embed a bidi override (U+202E, RIGHT-TO-LEFT OVERRIDE) or a zero-width
character (U+200B) into a raw response and have it render, unmodified, in
the error card a human reads. ``textContent`` keeps this from being XSS —
this is visual spoofing, not script injection.

``stripControlChars`` itself had exactly two references repo-wide (its
definition and the one guarded call site) and zero tests, so nothing proved
either path — including the one that was supposedly already safe — actually
worked. This file drives the real function through
``inspect_fetch_error_harness.mjs``, which loads ``inspect.js`` verbatim in
a Node ``vm`` context (same technique as ``inspect_render_harness.mjs`` /
``test_inspect_js_render_drift.py``) against a stub, fully-controllable
WebSocket, and asserts both branches — and the sanitiser directly — strip
the hostile codepoints.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess  # nosec B404 — fixed argv, no shell, repo-local script
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
_HARNESS = _REPO_ROOT / "tests" / "web" / "inspect_fetch_error_harness.mjs"

# The two hostile codepoints stripControlChars exists to neutralise.
_BIDI = "‮"  # RIGHT-TO-LEFT OVERRIDE
_ZWSP = "​"  # ZERO WIDTH SPACE


def _require_node() -> str:
    node = shutil.which("node")
    if node is None:
        if os.environ.get("PYRXD_SKIP_JS_RENDER_GUARD") == "1":
            pytest.skip(
                "node is missing and PYRXD_SKIP_JS_RENDER_GUARD=1 — the browser "
                "fetch-error sanitiser is UNGUARDED in this run"
            )
        pytest.fail(
            "node is required to run the fetch-error sanitiser guard (it loads "
            "docs/inspect_static/inspect/inspect.js in a Node vm). Install node, "
            "or set PYRXD_SKIP_JS_RENDER_GUARD=1 to skip it deliberately and "
            "accept that inspect.js's error-sanitising is unverified in this run."
        )
    return node


@pytest.fixture(scope="module")
def probe() -> dict[str, str]:
    node = _require_node()
    proc = subprocess.run(  # nosec B603 — fixed argv, no shell, repo-local script
        [node, str(_HARNESS)],
        capture_output=True,
        text=True,
        check=False,
        cwd=str(_REPO_ROOT),
    )
    if proc.returncode != 0:
        pytest.fail(f"fetch-error harness failed (exit {proc.returncode}):\n{proc.stderr}")
    return json.loads(proc.stdout)


class TestBothErrorBranchesAreSanitized:
    """The unguarded JSON.parse-catch branch and the already-guarded
    frame.error branch must both neutralise hostile codepoints."""

    def test_malformed_json_branch_strips_bidi_and_zero_width(self, probe):
        """This is the branch that was unguarded: a V8 SyntaxError echoing
        raw server bytes, with fewer preconditions to reach than the sibling
        below (no id===1 match needed)."""
        message = probe["fromMalformedJson"]
        assert _BIDI not in message
        assert _ZWSP not in message
        # Prove this is really the JSON.parse-catch branch and not some
        # other rejection path swallowing everything.
        assert "server returned non-JSON" in message

    def test_frame_error_branch_strips_bidi_and_zero_width(self, probe):
        """The branch stripControlChars was already applied to — pinned so
        a future refactor can't quietly drop the call on this side while
        fixing the other."""
        message = probe["fromFrameError"]
        assert _BIDI not in message
        assert _ZWSP not in message
        assert "server error" in message
        assert "boom" in message

    def test_strip_control_chars_direct(self, probe):
        """Unit-level pin of the sanitiser itself, independent of either
        call site: both hostile codepoints become '?', everything else is
        preserved."""
        result = probe["stripControlCharsDirect"]
        assert _BIDI not in result
        assert _ZWSP not in result
        assert result == "gly?bar?baz"


class TestHarnessIntegrity:
    """A guard that silently stops guarding is worse than no guard."""

    def test_the_harness_loads_the_real_file(self, probe):
        """Any output at all proves fetchRawTxFromElectrumx and
        stripControlChars were both reachable after loading the real file —
        the harness throws otherwise (see inspect_fetch_error_harness.mjs)."""
        assert probe["fromMalformedJson"]
        assert probe["fromFrameError"]
        assert probe["stripControlCharsDirect"]


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
