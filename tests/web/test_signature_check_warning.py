"""The boot's "signature checking is off" console warning, and the one page allowed to drop it.

``bootPyrxdRuntime`` (``docs/inspect_static/inspect/shared.js``) warns in the console when the
tab ends up with no JS curve. That is true on /inspect/ and /verify/, whose signature verdicts
need one. It was false on the playground, whose sandbox checks signatures in Python through
``sandbox_curve.py``, and a visitor who opened the console was told signature checking was off.

``signatureCheckWarning`` is executed here under node, so what is tested is the shipped
function, not a Python restatement of it.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess  # nosec B404 — fixed argv, no shell, repo-local script
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
_STATIC = _REPO_ROOT / "docs" / "inspect_static"

#: Loads shared.js as test_curve_install.py does, then calls signatureCheckWarning on the cases
#: passed in argv as JSON: a list of [signatureCheck, opts] pairs.
_SNIPPET = """
const vm = require("node:vm");
const fs = require("node:fs");
const path = require("node:path");
const shared = path.resolve("docs/inspect_static/inspect/shared.js");
const sandbox = {
  console: { log() {}, warn() {}, error() {} },
  URL, URLSearchParams, TextDecoder, TextEncoder, setTimeout, clearTimeout,
  crypto: globalThis.crypto, fetch: () => { throw new Error("no fetch here"); },
  document: { baseURI: "https://pyrxd.invalid/playground/" },
  WebSocket: class {}, navigator: {},
  location: { href: "https://pyrxd.invalid/playground/", search: "" },
  history: { replaceState() {} },
};
sandbox.window = sandbox; sandbox.globalThis = sandbox;
vm.createContext(sandbox);
vm.runInContext(fs.readFileSync(shared, "utf8"), sandbox, { filename: shared });
const cases = JSON.parse(process.argv[1]);
process.stdout.write(JSON.stringify(cases.map(([check, opts]) => sandbox.signatureCheckWarning(check, opts))));
"""


def _require_node() -> str:
    """As tests/web/test_curve_install.py: node is required, unless the JS guards are waived."""
    node = shutil.which("node")
    if node is None:
        if os.environ.get("PYRXD_SKIP_JS_RENDER_GUARD") == "1":
            pytest.skip("node is missing and PYRXD_SKIP_JS_RENDER_GUARD=1 — the console warning is UNGUARDED")
        pytest.fail("node is required to run shared.js's signatureCheckWarning, or set PYRXD_SKIP_JS_RENDER_GUARD=1")
    return node


_OFF = {"installed": False, "reason": "this page did not point at a curve bridge"}
_ON = {"installed": True, "reason": None}


def _warnings(cases: list) -> list:
    proc = subprocess.run(  # nosec B603 — fixed argv, no shell, repo-local script
        [_require_node(), "--no-warnings", "-e", _SNIPPET, json.dumps(cases)],
        capture_output=True,
        text=True,
        cwd=str(_REPO_ROOT),
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr[-1500:]
    return json.loads(proc.stdout)


def test_a_page_with_no_curve_is_warned_about_unless_it_says_it_uses_none():
    off_default, off_other, off_not_used, on_not_used, on_default = _warnings(
        [
            [_OFF, None],
            [_OFF, {"signatureCheck": "yes"}],
            [_OFF, {"signatureCheck": "not-used"}],
            [_ON, {}],
            [_ON, None],
        ]
    )
    # A page that forgot curveUrl, or says anything but "not-used", is still warned about.
    assert off_default == "signature checking is off in this tab: this page did not point at a curve bridge"
    assert off_other == off_default
    # The opt-out, and an installed curve, say nothing.
    assert off_not_used is None
    assert on_not_used is None and on_default is None


def _pages_passing(token: str) -> set[str]:
    return {
        p.parent.name
        for p in _STATIC.glob("*/*.js")
        if p.name != "shared.js" and token in p.read_text(encoding="utf-8")
    }


def test_only_the_playground_drops_the_warning_and_it_installs_no_curve():
    """A MEMBERSHIP pin, reviewed rather than derived: a page that checks signatures with the JS
    curve must never silence the warning, so a new page joining this set is a decision to re-read."""
    silenced = _pages_passing('signatureCheck: "not-used"')
    assert silenced == {"playground"}, silenced
    with_a_curve = _pages_passing("curveUrl:")
    assert with_a_curve, "no page installs a curve: re-read this test"
    assert not silenced & with_a_curve, f"{silenced & with_a_curve} installs a curve and silences its warning"


def test_the_boot_routes_its_warning_through_the_helper():
    """The helper is only worth testing if the boot uses it: one console.warn, fed by it."""
    text = (_STATIC / "inspect" / "shared.js").read_text(encoding="utf-8")
    assert len(re.findall(r"signature checking is off", text)) == 1
    assert "const warning = signatureCheckWarning(signatureCheck, opts);" in text
    assert "if (warning) console.warn(warning);" in text


@pytest.mark.parametrize("page", ["inspect/inspect.js", "verify/verify.js"])
def test_the_signature_checking_pages_keep_the_warning(page: str):
    assert 'signatureCheck: "not-used"' not in (_STATIC / page).read_text(encoding="utf-8")
