"""Pyodide's OpenSSL on the pages: reported at runtime, and kept off the known load paths (#757).

WHY IT IS NOT LOADED. PR #756 loaded Pyodide's ``hashlib`` package because Pyodide 0.26.4's
``hashlib`` has no SHA-512/256, the Radiant block hash. With it loaded, OpenSSL 1.1.1n (end of
life) computed EVERY hash on the page, the SHA-256 and RIPEMD-160 behind the signature verdict
included (measured in headless Chromium), and it was about 3.7 MB more code checked only against
a lockfile fetched unverified from the same CDN. ``pyrxd.hash`` now computes SHA-512/256 in pure
Python where ``hashlib`` has none, so the package buys nothing.

WHY THE OUTCOME IS WHAT IS CHECKED. Two review rounds walked doors past static checks of the boot:
a ``packages`` option, a variable, ``fullStdLib: true`` (which fetched hashlib, openssl, ssl and
sqlite3 in Chromium, with the page still showing VERIFIED), an aliased ``micropip.install`` of
``ssl``. A list of doors never closes. So there are two layers, and each claims only its own:

* **The runtime report** (``TestThePageReportsWhatComputedItsHashes``). ``glue.hashing_backend``
  reads, in the running page, which code computes the block hash (SHA-512/256), SHA-256 and
  RIPEMD-160, and whether ``_hashlib`` or ``_ssl`` is importable. It claims exactly that and no
  more: another copy of OpenSSL (the ``cryptography`` package's, or the bare ``openssl``
  package) is not looked for, so the report never says "no OpenSSL". It is reported, never
  refused: OpenSSL is extra code, not a wrong answer. Tested here against the real glue under
  CPython, with each signal both ways; and ``TestTheRenderedFooterCarriesTheReport`` renders
  each page that loads ``shared.js`` (its ``index.html``'s scripts, verbatim, against a stub DOM)
  and reads the footer its own ``boot()`` wrote.
* **Static checks of the known load paths**, cheap and deliberately partial:
  ``boot_packages_harness.mjs`` runs the real boot under Node against a stand-in Pyodide that
  records every call; the ``loadPyodide`` options must be on an allowlist (``fullStdLib`` and
  anything unknown are refused), ``loadPackage`` must ask for exactly the reviewed set,
  ``loadPackagesFromImports`` must not be called, the boot's Python may micropip-install only
  the two SHA-checked wheels (the pyrxd one with ``deps=False``), and no unmodelled Pyodide API
  may be touched. Sweeps add that every package-loading call site is inside the boot, that no
  non-comment line of page code names hashlib or openssl, and that the Python the page runs
  imports no package loader. Each static rule is shown to fire by one planted copy of
  ``shared.js`` (``TestEachStaticRuleFires``). These catch the known spellings, not every way.

NOT checked here: what ``micropip`` and ``pycryptodome`` pull in as Pyodide dependencies. Pyodide
0.26.4's ``pyodide-lock.json`` (read 2026-09-28) gives ``micropip -> packaging`` and
``pycryptodome -> none``; the runtime report is what would show anything else.
"""

from __future__ import annotations

import ast
import json
import re
import subprocess  # nosec B404 — fixed argv, no shell, repo-local script
import sys
from pathlib import Path

import pytest

from tests.web.test_curve_install import _require_node

_REPO_ROOT = Path(__file__).resolve().parents[2]
_STATIC = _REPO_ROOT / "docs" / "inspect_static"
_SHARED = _STATIC / "inspect" / "shared.js"
_GLUE = _STATIC / "inspect" / "glue.py"
_HARNESS = Path(__file__).with_name("boot_packages_harness.mjs")

#: The Pyodide packages the boot may ask for, REVIEWED. Adding one is a decision: make it by
#: editing this line, after checking in Chromium what it pulls in and what the footer then says.
_REVIEWED_PYODIDE_PACKAGES = frozenset({"micropip", "pycryptodome"})

#: The ``loadPyodide`` options the boot may pass. ``fullStdLib: true`` loads every unvendored
#: stdlib package, OpenSSL's among them; ``packages`` loads whatever it names. Anything not listed
#: here is refused until someone reads what it does.
_ALLOWED_LOADPYODIDE_OPTIONS = frozenset({"indexURL"})

_CBOR2_INSTALL = "emfs:/tmp/cbor2-5.4.6-py3-none-any.whl"
_PYRXD_INSTALL = "emfs:/tmp/pyrxd-0.0.0-py3-none-any.whl"

_OPENSSL = re.compile(r"hashlib|openssl", re.IGNORECASE)
_LOADERS = re.compile(r"\b(loadPyodide|loadPackage|loadPackagesFromImports|micropip|pyimport|pyodide_js)\b")
_WHOLE_LINE_COMMENT = re.compile(r"^\s*(//|/\*|\*|<!--)")
_MICROPIP_INSTALL = re.compile(r"micropip\.install\(")
_MICROPIP_LITERAL = re.compile(r"micropip\.install\(\s*([\"'])([^\"']*)\1([^)]*)\)")


def _page_files() -> list[Path]:
    files = sorted(p for p in _STATIC.rglob("*") if p.suffix in {".js", ".html"})
    assert _SHARED in files and len(files) >= 5, f"the page-file sweep found only {files} — it is broken"
    return files


def _page_texts() -> dict[str, str]:
    return {str(p.relative_to(_STATIC)): p.read_text(encoding="utf-8") for p in _page_files()}


def _run_boot(shared: Path | None = None, hashing_report: dict | None = None) -> dict:
    argv = [_require_node(), "--no-warnings", str(_HARNESS)]
    if shared is not None:
        argv += ["--shared", str(shared)]
    if hashing_report is not None:
        argv += ["--hashing-report", json.dumps(hashing_report)]
    proc = subprocess.run(  # nosec B603 — fixed argv, no shell, repo-local script
        argv, capture_output=True, text=True, cwd=str(_REPO_ROOT), timeout=120
    )
    assert proc.returncode == 0, f"the boot harness failed:\n{proc.stderr[-2000:]}"
    return json.loads(proc.stdout.strip().splitlines()[-1])


def _names(value: object) -> list[str]:
    """Package names in one ``loadPackage`` argument, as Pyodide reads it: a string or a list of
    strings. Anything else is reported as itself, so it cannot vanish."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(v, str) for v in value):
        return list(value)
    return [f"<not a name or list of names: {value!r}>"]


def boot_package_violations(result: dict) -> list[str]:
    """Everything wrong with what one boot asked Pyodide to load, on the KNOWN paths."""
    problems: list[str] = []
    if not result["finished"] or 100 not in result["progress"]:
        problems.append(
            f"the boot did not run to the end ({result['error']!r}, progress {result['progress']}), "
            "so whatever it would load after that point was never seen"
        )
    for options in result["loadPyodideOptions"]:
        extra = sorted(set(options) - _ALLOWED_LOADPYODIDE_OPTIONS) if isinstance(options, dict) else [repr(options)]
        if extra:
            problems.append(
                f"loadPyodide is passed {extra}, outside the allowlist {sorted(_ALLOWED_LOADPYODIDE_OPTIONS)}"
            )
    asked = [name for call in result["loadPackage"] for name in _names(call)]
    if set(asked) != _REVIEWED_PYODIDE_PACKAGES:
        problems.append(
            f"loadPackage asks for {sorted(set(asked))}, not the reviewed {sorted(_REVIEWED_PYODIDE_PACKAGES)}"
        )
    if result["loadPackagesFromImports"]:
        problems.append(f"the boot calls loadPackagesFromImports({result['loadPackagesFromImports']})")

    installs: list[tuple[str, str]] = []
    for source in result["python"]:
        literal = _MICROPIP_LITERAL.findall(source)
        if len(literal) != len(_MICROPIP_INSTALL.findall(source)):
            problems.append(f"the boot runs a micropip.install whose target is not a literal:\n{source}")
        installs += [(target, rest) for _, target, rest in literal]
        if re.search(r"pyodide_js|loadPackage|^\s*(import|from)\s+js\b", source, re.MULTILINE):
            problems.append(f"the Python the boot runs reaches Pyodide's loader itself:\n{source}")
    targets = [target for target, _ in installs]
    if targets != [_CBOR2_INSTALL, _PYRXD_INSTALL]:
        problems.append(f"the boot micropip-installs {targets}, not only the two SHA-checked wheels")
    for target, rest in installs:
        if target == _PYRXD_INSTALL and not re.fullmatch(r"\s*,\s*deps\s*=\s*False\s*", rest):
            problems.append(f"the pyrxd wheel is installed without deps=False (arguments after it: {rest!r})")
    if result["unknown"]:
        problems.append(f"the boot reached Pyodide APIs the harness does not model: {result['unknown']}")
    return problems


def openssl_on_code_lines(files: dict[str, str]) -> list[str]:
    """Every line of page code (not a whole-line comment) that names hashlib or openssl."""
    return [
        f"{name}:{n}: {line.strip()}"
        for name, text in files.items()
        for n, line in enumerate(text.splitlines(), 1)
        if _OPENSSL.search(line) and not _WHOLE_LINE_COMMENT.match(line)
    ]


def loader_sites_outside_the_boot(files: dict[str, str]) -> list[str]:
    """Every non-comment mention of a package-loading API outside ``bootPyrxdRuntime`` — the only
    code ``boot_packages_harness.mjs`` runs."""
    shared_lines = files["inspect/shared.js"].splitlines()
    start = next(i for i, line in enumerate(shared_lines) if line.startswith("async function bootPyrxdRuntime("))
    end = next(i for i in range(start + 1, len(shared_lines)) if shared_lines[i] == "}")
    outside = []
    for name, text in files.items():
        for i, line in enumerate(text.splitlines()):
            in_boot = name == "inspect/shared.js" and start < i < end
            if _LOADERS.search(line) and not _WHOLE_LINE_COMMENT.match(line) and not in_boot:
                outside.append(f"{name}:{i + 1}: {line.strip()}")
    return outside


# ──────────────────────────────────────────────────────────── the outcome, at runtime ──


@pytest.fixture(scope="module")
def page_glue():
    """The page's own glue module, imported the way the page imports it."""
    sys.path.insert(0, str(_GLUE.parent))
    try:
        import glue as module

        yield module
    finally:
        sys.path.remove(str(_GLUE.parent))
        sys.modules.pop("glue", None)


def _builtin_sha256():
    """CPython's own SHA-256 constructor (``_sha2`` on 3.12, ``_sha256`` before), which is what
    Pyodide's ``hashlib`` hands out without its OpenSSL package."""
    import hashlib

    return hashlib.__get_builtin_constructor("sha256")


def _find_spec_without(monkeypatch, missing: set[str]) -> None:
    """``importlib.util.find_spec`` as it answers in a runtime where *missing* are not installed."""
    import importlib.util

    real = importlib.util.find_spec

    def find_spec(name, *args, **kwargs):
        return None if name in missing else real(name, *args, **kwargs)

    monkeypatch.setattr(importlib.util, "find_spec", find_spec)


def _as_on_the_pages(monkeypatch, missing: frozenset[str] = frozenset({"_hashlib", "_ssl"})) -> None:
    """This CPython made to look like the pages' Pyodide (measured in headless Chromium on the
    shipped boot): ``hashlib`` hands out CPython's own SHA-256 and refuses SHA-512/256 and
    RIPEMD-160, ``pyrxd.hash`` has picked its pure-Python RIPEMD-160, and neither ``_hashlib`` nor
    ``_ssl`` is importable (*missing*)."""
    import hashlib

    import pyrxd.hash as pyrxd_hash

    real_new = hashlib.new

    def new(name, *args, **kwargs):
        if name in {"sha512_256", "ripemd160"}:
            raise ValueError(f"unsupported hash type {name}")
        return real_new(name, *args, **kwargs)

    monkeypatch.setattr(hashlib, "sha256", _builtin_sha256())
    monkeypatch.setattr(hashlib, "new", new)
    monkeypatch.setattr(pyrxd_hash, "_ripemd160_impl", pyrxd_hash._ripemd160_pure_python)
    _find_spec_without(monkeypatch, set(missing))


def _no_claim_beyond_what_was_checked(summary: str) -> None:
    """The report looks for two modules and three implementations. It must not speak for OpenSSL
    as a whole (a ``cryptography`` or bare ``openssl`` package is not looked for), nor call
    pyrxd's own pure-Python code "Python's built-ins"."""
    assert "no OpenSSL" not in summary, summary
    assert "built-in" not in summary, summary


class TestThePageReportsWhatComputedItsHashes:
    """``glue.hashing_backend``, reached as the page reaches it, with each signal both ways."""

    def test_on_the_pages_it_names_the_code_that_ran(self, page_glue, monkeypatch) -> None:
        _as_on_the_pages(monkeypatch)
        report = page_glue.hashing_backend()
        builtin = _builtin_sha256().__module__
        assert report == {
            "block_hash": "pyrxd's pure Python",
            "sha256": f"CPython's {builtin}",
            "ripemd160": "pyrxd's pure Python",
            "openssl_modules": [],
            "summary": f"hashing: block hash and RIPEMD-160 by pyrxd's pure Python, SHA-256 by CPython's {builtin}; "
            "no _hashlib or _ssl module",
        }
        _no_claim_beyond_what_was_checked(report["summary"])

    def test_the_block_hash_line_follows_the_same_test_pyrxd_makes(self, page_glue, monkeypatch) -> None:
        """The report says pyrxd's pure Python computes the block hash exactly when ``hashlib``
        refuses SHA-512/256, which is when ``pyrxd.hash._sha512_256`` falls back. Shown by
        counting that ``radiant_block_hash`` really did ask ``hashlib`` and was refused."""
        import hashlib

        from pyrxd.constants import GENESIS_BLOCK_HASHES
        from pyrxd.hash import radiant_block_hash
        from tests.network.test_registry import _MAINNET_GENESIS_HEADER_HEX

        _as_on_the_pages(monkeypatch)
        refusing, refused = hashlib.new, []

        def counting(name, *args, **kwargs):
            try:
                return refusing(name, *args, **kwargs)
            except ValueError:
                refused.append(name)
                raise

        monkeypatch.setattr(hashlib, "new", counting)
        assert radiant_block_hash(bytes.fromhex(_MAINNET_GENESIS_HEADER_HEX)) == GENESIS_BLOCK_HASHES["mainnet"]
        assert "sha512_256" in refused, "hashlib was never asked, so pyrxd's fallback was not what ran"
        assert page_glue.hashing_backend()["block_hash"] == "pyrxd's pure Python"

    def test_when_openssl_computes_the_hashes_it_says_so(self, page_glue, monkeypatch) -> None:
        """This CPython's own ``hashlib``, which is OpenSSL's, as it was on the pages under #756
        (measured: ``openssl_sha256`` from ``_hashlib``). RIPEMD-160 is pinned to pyrxd's pure
        Python, the choice ``pyrxd.hash`` makes at import on an OpenSSL 3 without the legacy
        provider, so the report is shown naming two different implementers at once."""
        import hashlib

        import pyrxd.hash as pyrxd_hash

        assert hashlib.sha256.__module__ == "_hashlib", "the premise: this CPython's SHA-256 is OpenSSL's"
        monkeypatch.setattr(pyrxd_hash, "_ripemd160_impl", pyrxd_hash._ripemd160_pure_python)
        _find_spec_without(monkeypatch, {"_ssl"})
        report = page_glue.hashing_backend()
        assert report["summary"] == (
            "hashing: block hash and SHA-256 by OpenSSL (_hashlib), RIPEMD-160 by pyrxd's pure Python; "
            "_hashlib importable"
        )
        _no_claim_beyond_what_was_checked(report["summary"])

    def test_when_ripemd160_is_hashlibs_it_says_so(self, page_glue, monkeypatch) -> None:
        """The other branch: ``pyrxd.hash`` selected ``hashlib``'s RIPEMD-160, so the report names
        the module of the object ``hashlib.new("ripemd160")`` returns. That object is stood in by
        CPython's own SHA-256 one, because an OpenSSL 3 without the legacy provider (CI's, often)
        has no RIPEMD-160 to return; only the module name is read."""
        import pyrxd.hash as pyrxd_hash

        _as_on_the_pages(monkeypatch)
        monkeypatch.setattr(pyrxd_hash, "_ripemd160_impl", pyrxd_hash._ripemd160_via_hashlib)
        import hashlib

        real_new = hashlib.new
        monkeypatch.setattr(
            hashlib,
            "new",
            lambda name, *a, **k: _builtin_sha256()() if name == "ripemd160" else real_new(name, *a, **k),
        )
        builtin = _builtin_sha256().__module__
        assert page_glue.hashing_backend()["ripemd160"] == f"CPython's {builtin}"

    def test_when_openssl_is_present_but_not_hashing_it_still_says_so(self, page_glue, monkeypatch) -> None:
        """The ``ssl``-only case a static check missed (an aliased micropip install of ``ssl``):
        ``_ssl`` is importable although nothing hashes with OpenSSL."""
        _as_on_the_pages(monkeypatch, missing=frozenset({"_hashlib"}))
        report = page_glue.hashing_backend()
        assert report["openssl_modules"] == ["_ssl"]
        assert report["summary"].endswith("; _ssl importable")
        _no_claim_beyond_what_was_checked(report["summary"])

    def test_a_check_that_cannot_run_says_it_could_not_tell(self, page_glue, monkeypatch) -> None:
        """Never raises across the bridge, and claims nothing it did not establish."""
        import importlib.util

        def broken(name, *args, **kwargs):
            raise RuntimeError("simulated import-system failure")

        monkeypatch.setattr(importlib.util, "find_spec", broken)
        report = page_glue.hashing_backend()
        assert report["openssl_modules"] is None and report["block_hash"] is None
        assert report["summary"].startswith("hashing: could not tell which code computes the hashes")

    def test_the_boots_report_reaches_buildline(self) -> None:
        """The runtime's report goes through the real boot's ``readHashingBackend`` and ``buildLine``
        (the harness returns it from the stand-in glue as a PyProxy-shaped dict)."""
        report = {"summary": "hashing: block hash, SHA-256 and RIPEMD-160 by OpenSSL (_hashlib); _hashlib importable"}
        result = _run_boot(hashing_report=report)
        assert result["hashing"] == report
        assert result["footer"] == f"build: 0000000 · {report['summary']}"


# ─────────────────────────────────────────────────────────── the rendered footer ──

_SCRIPT_SRC = re.compile(r"<script\b[^>]*\bsrc=\"([^\"]+)\"")


def _pages_that_boot() -> dict[str, list[Path]]:
    """Every published page that loads ``shared.js``, with the local scripts its ``index.html``
    loads, in order. DERIVED from the tree, so a third page is rendered without anyone adding it."""
    pages = {}
    for html in sorted(_STATIC.glob("*/index.html")):
        srcs = [s for s in _SCRIPT_SRC.findall(html.read_text(encoding="utf-8")) if "://" not in s]
        scripts = [(html.parent / s).resolve() for s in srcs]
        if _SHARED.resolve() in scripts:
            pages[html.parent.name] = scripts
    return pages


def _render(page: str, scripts: list[Path], hashing_report: dict) -> dict:
    """Render *page* under Node: its ``index.html``'s scripts, verbatim, against a stub DOM and
    the recording Pyodide. The page's own ``boot()`` writes the footer."""
    spec = {"base": f"https://pages.invalid/{page}/", "scripts": [str(s) for s in scripts]}
    argv = [_require_node(), "--no-warnings", str(_HARNESS), "--page", json.dumps(spec)]
    argv += ["--hashing-report", json.dumps(hashing_report)]
    proc = subprocess.run(  # nosec B603 — fixed argv, no shell, repo-local script
        argv, capture_output=True, text=True, cwd=str(_REPO_ROOT), timeout=120
    )
    assert proc.returncode == 0, f"the page harness failed:\n{proc.stderr[-2000:]}"
    return json.loads(proc.stdout.strip().splitlines()[-1])


#: A report no page could print by accident, so finding it in the footer means it came through.
_MARKER_REPORT = {"summary": "hashing: block hash by marker-7f3a; no _hashlib or _ssl module"}


def footer_problems(result: dict) -> list[str]:
    """What is wrong with one rendered footer: it must be the build line, then the runtime's report."""
    if not result["finished"]:
        return [f"the page did not finish booting: {result['error']!r} / {result['rendered']!r}"]
    footer = result["rendered"]["build-version"]
    if footer != f"build: 0000000 · {_MARKER_REPORT['summary']}":
        return [f"the rendered footer is {footer!r}, without the hashing report"]
    return []


#: Per page, a footer that drops the hashing line while leaving ``buildLine(runtime)`` in a comment
#: — the plant a source grep passed (#764 round 4).
_FOOTER_PLANTS = {
    "verify": (
        "  const footer = buildLine(runtime);\n  if (footer) BUILD_VERSION.textContent = footer;",
        "  // buildLine(runtime)\n  if (runtime.gitSha) BUILD_VERSION.textContent = `build: ${runtime.gitSha}`;",
    ),
    "inspect": (
        "showReady(runtime.versionText, buildLine(runtime));",
        "showReady(runtime.versionText, `build: ${runtime.gitSha}`); // buildLine(runtime)",
    ),
}


class TestTheRenderedFooterCarriesTheReport:
    def test_the_derivation_found_both_pages(self) -> None:
        assert {"inspect", "verify"} <= set(_pages_that_boot()), f"found only {sorted(_pages_that_boot())}"

    @pytest.mark.parametrize("page", sorted(_pages_that_boot()))
    def test_the_page_prints_the_report_in_its_footer(self, page: str) -> None:
        result = _render(page, _pages_that_boot()[page], _MARKER_REPORT)
        assert footer_problems(result) == []

    @pytest.mark.parametrize("page", sorted(_FOOTER_PLANTS))
    def test_a_footer_without_the_report_fails(self, page: str, tmp_path: Path) -> None:
        scripts = _pages_that_boot()[page]
        own = scripts[-1]
        old, new = _FOOTER_PLANTS[page]
        text = own.read_text(encoding="utf-8")
        assert text.count(old) == 1, f"the plant's anchor occurs {text.count(old)} times in {own.name}"
        planted = tmp_path / own.name
        planted.write_text(text.replace(old, new), encoding="utf-8")
        assert "buildLine(runtime)" in planted.read_text(encoding="utf-8")
        result = _render(page, [*scripts[:-1], planted], _MARKER_REPORT)
        assert result["rendered"]["build-version"] == "build: 0000000"
        assert footer_problems(result), "a footer without the hashing report passed"


# ──────────────────────────────────────────────────────────── the known load paths ──


class TestTheKnownLoadPathsAreClean:
    def test_the_premise_the_block_hash_needs_no_openssl(self, monkeypatch) -> None:
        """Gated on the reason holding BEHAVIOURALLY: with ``hashlib`` refusing SHA-512/256, as on
        Pyodide without the package, the mainnet genesis header still hashes to the registry's
        genesis hash. If this fails, dropping the package broke the pages."""
        import hashlib

        from pyrxd.constants import GENESIS_BLOCK_HASHES
        from pyrxd.hash import radiant_block_hash
        from tests.network.test_registry import _MAINNET_GENESIS_HEADER_HEX

        real_new, refused = hashlib.new, []

        def new(name, *args, **kwargs):
            if name == "sha512_256":
                refused.append(name)
                raise ValueError("unsupported hash type sha512_256")
            return real_new(name, *args, **kwargs)

        monkeypatch.setattr(hashlib, "new", new)
        assert radiant_block_hash(bytes.fromhex(_MAINNET_GENESIS_HEADER_HEX)) == GENESIS_BLOCK_HASHES["mainnet"]
        assert refused, "hashlib was never asked, so this proved nothing"

    def test_the_boot_passes_every_static_rule(self) -> None:
        result = _run_boot()
        assert boot_package_violations(result) == []
        # The control, so a clean result cannot mean "nothing was recorded".
        assert result["loadPackage"] and result["python"] and result["loadPyodideOptions"]

    def test_every_package_loading_call_site_is_inside_the_boot_the_harness_runs(self) -> None:
        texts = _page_texts()
        assert loader_sites_outside_the_boot(texts) == []
        shared = texts["inspect/shared.js"]
        assert all(re.search(rf"\b{api}\b", shared) for api in ("loadPyodide", "loadPackage", "micropip"))

    def test_no_line_of_page_code_names_openssl(self) -> None:
        texts = _page_texts()
        assert openssl_on_code_lines(texts) == []
        assert _OPENSSL.search(texts["inspect/shared.js"]), (
            "shared.js no longer mentions hashlib — the sweep reads nothing"
        )

    def test_the_python_the_page_runs_imports_no_package_loader(self) -> None:
        sources = [_GLUE, *sorted((_REPO_ROOT / "src" / "pyrxd").rglob("*.py"))]
        assert len(sources) > 100, "the src/pyrxd sweep found almost nothing — it is broken"
        banned = {"micropip", "pyodide_js", "js"}
        offenders = []
        for path in sources:
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                names = []
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module:
                    names = [node.module]
                offenders += [f"{path}:{node.lineno}: {n}" for n in names if n.split(".")[0] in banned]
        assert offenders == []


#: One planted copy of ``shared.js`` per static rule: (rule, anchor that must occur exactly once,
#: replacement, text the rule's complaint must contain). Not a list of doors — the runtime report
#: is what answers the doors — but the proof that each rule is live.
_RULES = [
    (
        "loadPyodide options allowlist",
        "loadPyodide({ indexURL: PYODIDE_INDEX_URL })",
        "loadPyodide({ indexURL: PYODIDE_INDEX_URL, fullStdLib: true })",
        "['fullStdLib'], outside the allowlist",
    ),
    (
        "the reviewed loadPackage set",
        'await pyodide.loadPackage(["micropip", "pycryptodome"]);',
        'const BOOT_PKGS = ["hashlib", "micropip", "pycryptodome"];\n    await pyodide.loadPackage(BOOT_PKGS);',
        "not the reviewed",
    ),
    (
        "no loadPackagesFromImports",
        'await pyodide.loadPackage(["micropip", "pycryptodome"]);',
        'await pyodide.loadPackage(["micropip", "pycryptodome"]);\n'
        '    await pyodide.loadPackagesFromImports("import _hashlib");',
        "loadPackagesFromImports(",
    ),
    (
        "only the two wheels",
        "\nimport micropip\n",
        '\nimport micropip\nawait micropip.install("ssl")\n',
        "not only the two SHA-checked wheels",
    ),
    (
        "deps=False on the pyrxd wheel",
        '", deps=False)',
        '")',
        "without deps=False",
    ),
    (
        "no unmodelled Pyodide API",
        'await pyodide.loadPackage(["micropip", "pycryptodome"]);',
        'await pyodide.loadPackage(["micropip", "pycryptodome"]);\n    await pyodide.pyimport("micropip");',
        "does not model",
    ),
]


class TestEachStaticRuleFires:
    @staticmethod
    def _planted(tmp_path: Path, old: str, new: str) -> tuple[Path, str]:
        text = _SHARED.read_text(encoding="utf-8")
        assert text.count(old) == 1, f"the rule's anchor {old!r} occurs {text.count(old)} times in shared.js"
        planted = text.replace(old, new)
        path = tmp_path / "shared.js"
        path.write_text(planted, encoding="utf-8")
        return path, planted

    @pytest.mark.parametrize(("rule", "old", "new", "complaint"), _RULES, ids=[r[0] for r in _RULES])
    def test_the_rule_fires(self, tmp_path: Path, rule: str, old: str, new: str, complaint: str) -> None:
        path, _ = self._planted(tmp_path, old, new)
        problems = boot_package_violations(_run_boot(path))
        assert any(complaint in p for p in problems), f"{rule} did not fire: {problems}"

    def test_the_code_line_sweep_fires(self, tmp_path: Path) -> None:
        _, planted = self._planted(tmp_path, _RULES[1][1], _RULES[1][2])
        assert openssl_on_code_lines({**_page_texts(), "inspect/shared.js": planted})

    def test_the_call_site_sweep_fires(self) -> None:
        texts = _page_texts()
        texts["verify/verify.js"] += '\nasync function later(py) { await py.loadPackage("ssl"); }\n'
        outside = loader_sites_outside_the_boot(texts)
        assert len(outside) == 1 and outside[0].startswith("verify/verify.js:"), outside
