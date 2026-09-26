"""The curve a page CHECKS must be the curve it RUNS.

WHAT WAS BROKEN. ``installCurveBackend`` in ``shared.js`` downloaded the secp256k1 bridge
and the vendored library, compared each download's SHA-256 against ``manifest.json``,
threw the bytes away, and then called ``import(bridgeUrl)`` — which downloaded the bridge
AGAIN, and the bridge's own ``import`` downloaded the library AGAIN. Neither second
download was checked, and the second downloads are what executed. A reviewer served the
second request for the bridge with a tampered file from a server sending
``Cache-Control: no-store``, and headless Chromium rendered a forged mark as a green
VERIFIED. On the live site it held only because GitHub Pages sends ``max-age=600`` and the
browser answered the ``import()`` from its cache — a property of somebody else's caching,
not of this code.

THE FIX, and what each test here pins about it. The page now imports the VERIFIED bytes
through ``blob:`` URLs: the library as downloaded, and the bridge as downloaded with its
one import specifier pointed at the library's ``blob:`` URL. So:

* a second download can never be what runs (``TestTheBytesThatRunAreTheBytesThatWereChecked``);
* the one rewrite is of a string that must occur exactly once, and anything else the bridge
  tried to import fails to load rather than being fetched unchecked (``TestTheOneRewrite``);
* the pages' Content-Security-Policy allows ``blob:`` scripts, or the whole signature check
  silently turns into NOT CHECKED for every visitor — measured in Chromium, where removing
  ``blob:`` from ``script-src`` did exactly that with nothing on the page to say so
  (``TestThePolicyLetsTheVerifiedBytesRun``).

Driven through ``curve_install_harness.mjs``, which loads ``shared.js`` verbatim and whose
``--tamper-second-download`` mode answers any load the MODULE LOADER makes of a file under
/inspect/ with a module that records that it ran and returns a wrong key. That is the
reviewer's attack moved to the one layer Node lets a harness intercept: the page's own
``fetch`` still gets the genuine bytes, exactly as the tampering server gave the first
request the genuine bytes.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess  # nosec B404 — fixed argv, no shell, repo-local script
from pathlib import Path

from tests.web.test_curve_install import _BRIDGE, _CURVE, _EXPECTED_KEY, _HARNESS, _manifest, _require_node

_REPO_ROOT = Path(__file__).resolve().parents[2]
_STATIC = _REPO_ROOT / "docs" / "inspect_static"
_SHARED = _STATIC / "inspect" / "shared.js"


def _run(manifest: Path, *flags: str) -> dict:
    proc = subprocess.run(  # nosec B603 — fixed argv, no shell, repo-local script
        [_require_node(), "--no-warnings", str(_HARNESS), str(manifest), *flags],
        capture_output=True,
        text=True,
        cwd=str(_REPO_ROOT),
        timeout=120,
    )
    assert proc.returncode == 0, f"the curve-install harness failed:\n{proc.stderr[-2000:]}"
    return json.loads(proc.stdout.strip().splitlines()[-1])


def _specifier() -> str:
    """The import specifier ``shared.js`` rewrites — read from ``shared.js``, not retyped."""
    match = re.search(r'const CURVE_LIBRARY_SPECIFIER = ("[^"]+");', _SHARED.read_text(encoding="utf-8"))
    assert match, "shared.js no longer declares CURVE_LIBRARY_SPECIFIER — this scan is broken, not the page"
    return json.loads(match.group(1))


def _variant_bridge(tmp_path: Path, text: str) -> tuple[Path, Path]:
    """A substitute bridge and a manifest whose bridge digest is ITS digest, so the integrity
    check passes and what is under test is what the page does next."""
    path = tmp_path / "bridge-variant.js"
    path.write_text(text, encoding="utf-8")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return path, _manifest(tmp_path, curve_bridge_sha256=digest)


class TestTheBytesThatRunAreTheBytesThatWereChecked:
    def test_a_tampered_second_download_never_runs(self, tmp_path: Path) -> None:
        """THE REVIEWER'S ATTACK. With the loader answering every load of a file under
        /inspect/ with a lying module, a page that imports by URL runs the liar — and the
        key it recovers for the real mainnet mark is ``02ee…``, which in the browser is a
        forged mark rendered VERIFIED. A page that imports the bytes it checked never asks
        the loader for a file at all."""
        result = _run(_manifest(tmp_path), "--tamper-second-download")
        assert result["second_download_ran"] == [], (
            f"code the module loader downloaded for itself EXECUTED: {result['second_download_ran']}. "
            f"That download was never checked against the manifest."
        )
        assert result["installed"] is True, f"the curve did not install: {result['reason']}"
        assert result["recovered"] == _EXPECTED_KEY, (
            f"the installed curve recovered {result['recovered']} for the real mainnet mark, not its signer"
        )

    def test_each_curve_file_is_downloaded_exactly_once(self, tmp_path: Path) -> None:
        """One download per file, and it is the one that was hashed. Two downloads of the same
        URL are two different sets of bytes as far as any check is concerned."""
        result = _run(_manifest(tmp_path))
        assert result["installed"] is True, result["reason"]
        wanted = {_BRIDGE.resolve().as_uri(), _CURVE.resolve().as_uri()}
        assert set(result["fetches"]) == wanted, f"the page downloaded {sorted(result['fetches'])}"
        assert all(n == 1 for n in result["fetches"].values()), f"downloaded more than once: {result['fetches']}"

    def test_the_verified_bytes_reach_the_loader_through_object_urls_it_then_revokes(self, tmp_path: Path) -> None:
        """Two modules, two object URLs, both revoked once the import has settled — so nothing
        else on the page can import them afterwards."""
        result = _run(_manifest(tmp_path))
        assert result["installed"] is True, result["reason"]
        assert result["module_urls"] == 2
        assert result["revoked"] == 2


class TestTheOneRewrite:
    def test_the_bridge_names_the_library_exactly_once(self) -> None:
        """The page rewrites the bridge's import specifier and REFUSES unless it occurs exactly
        once. This is the honest-path half: the shipped bridge satisfies it, and the specifier
        resolves, against the bridge, to the vendored file the manifest pins."""
        spec = _specifier()
        assert _BRIDGE.read_text(encoding="utf-8").count(json.dumps(spec)) == 1
        assert (_BRIDGE.parent / spec).resolve() == _CURVE.resolve()

    def test_a_bridge_naming_it_twice_is_refused_not_guessed(self, tmp_path: Path) -> None:
        """Two occurrences means the page cannot tell which one is the import, so it installs
        nothing. Refused QUIETLY and with a reason — the NOT CHECKED path, never a verdict."""
        text = _BRIDGE.read_text(encoding="utf-8") + f"\n// see {json.dumps(_specifier())}\n"
        bridge, manifest = _variant_bridge(tmp_path, text)
        result = _run(manifest, "--bridge", str(bridge))
        assert result["installed"] is False
        assert result["received"] is False
        assert "exactly once" in (result["reason"] or ""), result["reason"]

    def test_a_second_import_fails_to_load_instead_of_being_fetched_unchecked(self, tmp_path: Path) -> None:
        """A ``blob:`` module has no path to resolve a relative import against. So a bridge that
        grew a second import does not quietly download it: the load fails, and no curve is
        installed. Run under the tampering loader, which would have recorded the second file
        running had the page fetched it."""
        text = 'import "./shared-helpers.js";\n' + _BRIDGE.read_text(encoding="utf-8")
        bridge, manifest = _variant_bridge(tmp_path, text)
        result = _run(manifest, "--bridge", str(bridge), "--tamper-second-download")
        assert result["installed"] is False, "a bridge with an unverified second import was installed"
        assert result["received"] is False
        assert result["second_download_ran"] == []


def _pages_that_install_a_curve() -> dict[str, Path]:
    """Every published page whose own script hands ``bootPyrxdRuntime`` a curve. DERIVED from
    the tree, so a third page that installs one is covered without anyone adding it here."""
    pages = {}
    for page_dir in sorted(p for p in _STATIC.iterdir() if p.is_dir()):
        scripts = [p for p in page_dir.glob("*.js") if p.name != "shared.js"]
        if any("curveUrl:" in s.read_text(encoding="utf-8") for s in scripts):
            pages[page_dir.name] = page_dir / "index.html"
    return pages


def _script_src(html: str) -> set[str]:
    match = re.search(r'http-equiv="Content-Security-Policy"\s+content="([^"]*)"', html)
    assert match, "no CSP meta tag"
    for clause in match.group(1).split(";"):
        parts = clause.split()
        if parts and parts[0] == "script-src":
            return set(parts[1:])
    raise AssertionError("the CSP has no script-src")


class TestThePolicyLetsTheVerifiedBytesRun:
    def test_the_derivation_found_both_pages(self) -> None:
        pages = _pages_that_install_a_curve()
        assert {"inspect", "verify"} <= set(pages), f"found only {sorted(pages)} — this scan is broken"

    def test_every_page_that_installs_a_curve_allows_blob_scripts(self) -> None:
        """MEASURED, the failure this prevents: with ``blob:`` missing from ``script-src``,
        Chromium blocks the import, ``installCurveBackend`` returns not-installed as designed,
        and a genuine mark reads NOT CHECKED — on every visitor's screen, with the only trace
        a console line. No other test in this directory runs a browser, so this is the guard."""
        missing = [
            name
            for name, html in _pages_that_install_a_curve().items()
            if "blob:" not in _script_src(html.read_text(encoding="utf-8"))
        ]
        assert not missing, f"these pages import the verified curve from blob: URLs and their CSP forbids it: {missing}"

    def test_blob_is_allowed_only_while_the_page_needs_it(self) -> None:
        """The other direction. ``blob:`` widens ``script-src``; if ``shared.js`` ever stops
        importing from object URLs, the widening should go with it rather than outlive its
        reason."""
        uses_object_urls = "URL.createObjectURL(" in _SHARED.read_text(encoding="utf-8")
        for name, html in _pages_that_install_a_curve().items():
            allows = "blob:" in _script_src(html.read_text(encoding="utf-8"))
            assert allows == uses_object_urls, (
                f"{name}: CSP blob: is {allows}, shared.js imports from object URLs: {uses_object_urls}"
            )

    def test_the_cost_the_policy_comment_points_at_is_really_written_down(self) -> None:
        """Both ``index.html`` comments said the cost of ``'unsafe-eval'`` was "documented in
        docs/threat-model.md", which never mentioned it — a citation that certified nothing.
        Whatever document the comment names now, it must exist and discuss both sources this
        policy grants beyond ``'self'`` and the CDN."""
        for name, html_path in _pages_that_install_a_curve().items():
            html = html_path.read_text(encoding="utf-8")
            comment = html[html.index("script-src") : html.index("style-src")]
            cited = re.findall(r"docs/[\w./-]+\.md", comment)
            assert cited, f"{name}: the script-src comment cites no document"
            for rel in cited:
                doc = _REPO_ROOT / rel
                assert doc.is_file(), f"{name}: the CSP comment cites {rel}, which does not exist"
                flat = " ".join(doc.read_text(encoding="utf-8").split())
                for source in ("'unsafe-eval'", "blob:"):
                    assert source in flat, (
                        f"{name}: {rel} is cited for the cost of the policy and never mentions {source}"
                    )
