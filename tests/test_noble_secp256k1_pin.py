"""The vendored curve must still be the bytes somebody looked at.

``docs/inspect_static/inspect/vendor/noble-secp256k1.js`` is the only third-party
JavaScript this repository serves, and it decides whether a stranger reading
/verify/ is told a mark is VERIFIED or DOES NOT VERIFY. The wheels that page
installs are SHA-256 pinned and verified before micropip sees them; a curve with
that much say over a verdict gets the same standard rather than a weaker one.

WHAT EACH HALF PROVES, because they are different claims and only one of them is
about provenance:

* This file checks the bytes on disk against
  ``tests/fixtures/noble_secp256k1_upstream_pin.json``. That is the PROVENANCE
  check — it fails when someone edits, patches or replaces the vendored library,
  and forces the pin (and the review that writing one implies) to be redone.
* The page's own runtime SHA-256 check, against ``manifest.json``, is a DEPLOY
  check — it fails when the deployed bytes are not what CI built. It cannot tell
  you which upstream release they are; only this file can.

Neither is a sandbox. ``script-src 'self'`` is what bounds what executes on those
pages at all.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_PIN = _ROOT / "tests" / "fixtures" / "noble_secp256k1_upstream_pin.json"
_VENDOR_DIR = _ROOT / "docs" / "inspect_static" / "inspect" / "vendor"
_BRIDGE = _ROOT / "docs" / "inspect_static" / "inspect" / "secp256k1-bridge.js"
_WORKFLOW = _ROOT / ".github" / "workflows" / "docs.yml"


@pytest.fixture(scope="module")
def pin() -> dict:
    return json.loads(_PIN.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class TestTheVendoredCurveMatchesItsPin:
    def test_the_curve_is_present(self) -> None:
        assert (_VENDOR_DIR / "noble-secp256k1.js").exists(), (
            "the vendored secp256k1 is gone, so /verify/ cannot check a signature at all"
        )

    def test_the_curve_bytes_are_the_pinned_bytes(self, pin: dict) -> None:
        """The whole point. A patched or bumped curve must not reach a reader without
        someone redoing the pin, because redoing the pin is the step where a human
        establishes what the new bytes are."""
        actual = _sha256(_VENDOR_DIR / "noble-secp256k1.js")
        assert actual == pin["files"]["index_js_sha256"], (
            f"docs/inspect_static/inspect/vendor/noble-secp256k1.js is sha256 {actual}, "
            f"but {_PIN.name} pins {pin['files']['index_js_sha256']}. If this is a deliberate "
            f"upgrade, refresh the pin AND say in the commit message what you established "
            f"about the new bytes — a pin nobody re-derived is a number, not provenance."
        )

    def test_the_licence_travels_with_it(self, pin: dict) -> None:
        """MIT requires the notice to ship with the code. It is served from the same
        directory as the file it covers."""
        licence = _VENDOR_DIR / "noble-secp256k1.LICENSE.txt"
        assert licence.exists(), "the vendored curve's MIT licence is missing"
        assert _sha256(licence) == pin["files"]["license_sha256"]
        assert pin["license"] == "MIT"

    def test_the_pin_names_a_checkable_upstream(self, pin: dict) -> None:
        """A pin whose provenance is 'trust me' is a number. Each of these is
        something a reader can go and fetch."""
        assert pin["package"] == "@noble/secp256k1"
        assert pin["repo"] == "paulmillr/noble-secp256k1"
        assert pin["version"] == pin["tag"]
        assert len(pin["commit"]) == 40 and all(c in "0123456789abcdef" for c in pin["commit"])
        assert pin["tarball"].startswith("https://registry.npmjs.org/")
        assert pin["version"] in pin["tarball"]
        for key in ("tarball_sha256", "files"):
            assert key in pin
        for name, digest in pin["files"].items():
            assert len(digest) == 64, name

    def test_the_pin_says_what_was_NOT_verified(self, pin: dict) -> None:
        """The riskiest sentence in a provenance record is the one that overstates it.

        ``index.js`` is tsc output and is not in the upstream git tree, so nobody here
        recompiled it and compared; the chain is 'tagged source == published source,
        published .js == vendored .js'. If that admission is ever dropped, this pin
        starts implying a compile step somebody checked, and nobody did.
        """
        comment = " ".join(pin["_comment"])
        assert "WHAT WAS NOT VERIFIED" in comment
        assert "404" in comment, "the pin no longer records that index.js is absent from the git tree"

    def test_the_vendor_directory_holds_nothing_unpinned(self, pin: dict) -> None:
        """Derived both ways. A file appearing in vendor/ without a pin entry is an
        unreviewed third-party dependency on a public page; a pin entry with no file
        is a check that has silently stopped running."""
        on_disk = {p.name for p in _VENDOR_DIR.iterdir() if p.is_file()}
        assert on_disk == {"noble-secp256k1.js", "noble-secp256k1.LICENSE.txt"}, (
            f"vendor/ holds {sorted(on_disk)}; every file served from there must be pinned "
            f"in {_PIN.name} and checked above"
        )


class TestTheCurveIsActuallyWiredToThePages:
    """A pinned file nothing loads is a pinned file, not a working signature check."""

    def test_the_bridge_imports_the_vendored_curve(self) -> None:
        assert 'from "./vendor/noble-secp256k1.js"' in _BRIDGE.read_text(encoding="utf-8")

    @pytest.mark.parametrize("page", ["verify/verify.js", "inspect/inspect.js"])
    def test_every_page_points_the_boot_at_the_bridge(self, page: str) -> None:
        """BOTH pages, not just the one this was written for. /inspect/ reported "not
        checked" for every signed record too, and a fix applied to one surface while
        the other kept the old answer is how two pages come to describe one record
        differently."""
        text = (_ROOT / "docs" / "inspect_static" / page).read_text(encoding="utf-8")
        assert "secp256k1-bridge.js" in text, f"{page} never names the curve bridge"
        assert "curveUrl:" in text, f"{page} never passes curveUrl to bootPyrxdRuntime"

    def test_the_docs_build_publishes_both_digests(self) -> None:
        """The runtime check compares against ``manifest.json``, which CI writes. If
        the workflow stops emitting either digest the page refuses to start — but only
        because ``loadManifest`` asserts them, so assert that pairing is still intact
        rather than trusting it."""
        workflow = _WORKFLOW.read_text(encoding="utf-8")
        shared = (_ROOT / "docs" / "inspect_static" / "inspect" / "shared.js").read_text(encoding="utf-8")
        for key in ("curve_sha256", "curve_bridge_sha256"):
            assert f'"{key}"' in workflow, f"docs.yml no longer writes {key} into manifest.json"
            assert f"_assertHexSha256(manifest.{key}" in shared, (
                f"shared.js no longer requires {key}, so a docs build that dropped it would "
                f"turn signature checking off silently instead of failing loudly"
            )
