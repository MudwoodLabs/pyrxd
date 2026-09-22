"""The boot step that gives the browser a curve — EXECUTED, not just read.

FOUND BY PLANTING, not by reading, and that is the point of the file. Every other
guard over ``installCurveBackend`` asserted on its TEXT. The render harnesses in this
directory stub ``fetch`` to reject and ``crypto.subtle`` to ``{}``, so ``boot()`` dies
on its first line and nothing in the suite ever ran the install. The plant that proved
it: swap ``manifest.curve_sha256`` with ``manifest.curve_bridge_sha256`` in
``shared.js``. Every real page then fails its own integrity check, no backend is
registered, and every mark in every browser silently reverts to NOT CHECKED — while
480 tests stayed green, because the swap changes no string any of them looks at.

That is the worst shape a defect can take on this page. It is SILENT (the page loads,
the record renders, only the verdict is missing), it is INVISIBLE to CI, and it
restores exactly the broken behaviour the curve was added to fix.

``tests/test_signature_backend_differential.py`` proves the curve computes the same
verdicts as coincurve. This proves the page can actually GET that curve — the two
halves of "a signature check runs in this browser", and neither implies the other.

The known-answer vector is the real mainnet mark's own signature, so "installed" here
cannot mean "something truthy was passed along": the function the boot handed over is
called, and the key it returns is compared.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess  # nosec B404 — fixed argv, no shell, repo-local script
from pathlib import Path

import pytest

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parents[1]
_HARNESS = _HERE / "curve_install_harness.mjs"
_INSPECT = _REPO_ROOT / "docs" / "inspect_static" / "inspect"
_CURVE = _INSPECT / "vendor" / "noble-secp256k1.js"
_BRIDGE = _INSPECT / "secp256k1-bridge.js"

#: The compressed key the real mainnet mark a1a86ab4…5916 recovers to. Independently
#: produced by coincurve; ``tests/test_hashmark_mainnet_vectors.py`` pins the hash160
#: of this same key as the committed signer.
_EXPECTED_KEY = "0261e83b6afde19c567257a669c90c01cf47e5b665dd0616271d4f91a1875a3db9"


def _require_node() -> str:
    node = shutil.which("node")
    if node is None:
        if os.environ.get("PYRXD_SKIP_JS_RENDER_GUARD") == "1":
            pytest.skip("node is missing and PYRXD_SKIP_JS_RENDER_GUARD=1 — the curve install is UNGUARDED")
        pytest.fail(
            "node is required to run the curve-install guard (it executes shared.js's "
            "installCurveBackend against the real vendored curve). Install node, or set "
            "PYRXD_SKIP_JS_RENDER_GUARD=1 to run without this guard."
        )
    return node


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _manifest(tmp_path: Path, **overrides: str) -> Path:
    """A manifest shaped the way ``docs.yml`` writes one.

    The two curve digests are COMPUTED from the files on disk, never typed: a literal
    here would have to be updated by hand on every edit to the bridge, and the version
    that goes stale is the one that makes this guard pass for the wrong reason.
    """
    data = {
        "wheel": "pyrxd-0.0.0-py3-none-any.whl",
        "wheel_sha256": "00" * 32,
        "cbor2_wheel": "cbor2-5.4.6-py3-none-any.whl",
        "cbor2_sha256": "00" * 32,
        "glue_sha256": "00" * 32,
        "curve_sha256": _sha256(_CURVE),
        "curve_bridge_sha256": _sha256(_BRIDGE),
        "git_sha": "local",
    }
    data.update(overrides)
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _install(manifest: Path) -> dict:
    proc = subprocess.run(  # nosec B603 — fixed argv, no shell, repo-local script
        [_require_node(), "--no-warnings", str(_HARNESS), str(manifest)],
        capture_output=True,
        text=True,
        cwd=str(_REPO_ROOT),
        timeout=120,
    )
    if proc.returncode != 0:
        pytest.fail(f"the curve-install harness failed:\n{proc.stderr[-2000:]}")
    return json.loads(proc.stdout.strip().splitlines()[-1])


class TestThePageCanActuallyGetACurve:
    def test_the_honest_path_installs_a_WORKING_curve(self, tmp_path: Path) -> None:
        """The whole feature in one assertion: with the manifest the docs build writes,
        the boot fetches both files, verifies both digests, imports the bridge, and hands
        the Python side a function that recovers the right key for a real mainnet mark."""
        result = _install(_manifest(tmp_path))
        assert result["installed"] is True, f"the curve did not install: {result['reason']}"
        assert result["received"] is True, "nothing was handed to the Python bridge"
        assert result["recovered"] == _EXPECTED_KEY, (
            f"the installed curve recovered {result['recovered']}, not the key the real "
            f"mainnet mark a1a86ab4…5916 is signed with"
        )

    def test_the_digests_are_not_interchangeable(self, tmp_path: Path) -> None:
        """THE PLANT THAT STARTED THIS FILE, made permanent.

        Swapping the two manifest keys is a one-token edit in ``shared.js`` that turns
        signature checking off for every visitor and changes no rendered string. Asserting
        the SWAPPED manifest is refused is what makes the honest-path test above mean
        "each file was checked against its OWN digest" rather than "two hashes were
        computed and something matched".
        """
        swapped = _manifest(tmp_path, curve_sha256=_sha256(_BRIDGE), curve_bridge_sha256=_sha256(_CURVE))
        result = _install(swapped)
        assert result["installed"] is False
        assert result["received"] is False, "a curve that failed its integrity check was installed anyway"
        assert "SHA-256 mismatch" in (result["reason"] or "")


class TestAFailedInstallIsNEVERAVerdict:
    """The asymmetry, at the layer where it is easiest to lose.

    ``verify_attestation`` cannot paint an honest mark red on a failed load because no
    backend gets registered — but only if this function really does refuse rather than
    install something broken. Each case below is a way the curve can fail to arrive.
    """

    @pytest.mark.parametrize(
        "overrides, why",
        [
            ({"curve_sha256": "11" * 32}, "the vendored curve's bytes do not match the manifest"),
            ({"curve_bridge_sha256": "11" * 32}, "the bridge's bytes do not match the manifest"),
        ],
    )
    def test_a_bad_digest_refuses_QUIETLY(self, tmp_path: Path, overrides: dict, why: str) -> None:
        result = _install(_manifest(tmp_path, **overrides))
        assert result["installed"] is False, why
        assert result["received"] is False
        # A REASON, not just a refusal. It reaches the console, and it is the only thing
        # that distinguishes "the deploy is broken" from "this record has no signature".
        assert result["reason"], "the install refused without saying why"

    def test_a_missing_curve_url_refuses_rather_than_throwing(self, tmp_path: Path) -> None:
        """A page that forgot to pass ``curveUrl`` must lose its signature check, not its
        ability to load. ``boot()`` does not catch this call."""
        proc = subprocess.run(  # nosec B603 — fixed argv, no shell, repo-local script
            [_require_node(), "--no-warnings", "-e", _NO_URL_SNIPPET],
            capture_output=True,
            text=True,
            cwd=str(_REPO_ROOT),
            timeout=120,
        )
        assert proc.returncode == 0, f"installCurveBackend threw instead of refusing:\n{proc.stderr[-1500:]}"
        assert json.loads(proc.stdout.strip())["installed"] is False


#: Loads shared.js the same way the harness does and calls the installer with no
#: ``curveUrl``. Inline because it needs no files, no manifest and no fetch — the
#: function must return before any of that is touched.
_NO_URL_SNIPPET = """
const vm = require("node:vm");
const fs = require("node:fs");
const path = require("node:path");
const shared = path.resolve("docs/inspect_static/inspect/shared.js");
const sandbox = {
  console: { log() {}, warn() {}, error() {} },
  URL, URLSearchParams, TextDecoder, TextEncoder, setTimeout, clearTimeout,
  crypto: globalThis.crypto,
  fetch: () => { throw new Error("installCurveBackend fetched despite having no curveUrl"); },
  document: { baseURI: "https://pyrxd.invalid/verify/" },
  WebSocket: class {}, navigator: {},
  location: { href: "https://pyrxd.invalid/verify/", search: "" },
  history: { replaceState() {} },
};
sandbox.window = sandbox; sandbox.globalThis = sandbox;
vm.createContext(sandbox);
vm.runInContext(fs.readFileSync(shared, "utf8"), sandbox, { filename: shared });
sandbox.installCurveBackend({ installSignatureBackend: () => { throw new Error("installed with no URL"); } }, {}, "")
  .then((r) => { process.stdout.write(JSON.stringify(r)); });
"""
