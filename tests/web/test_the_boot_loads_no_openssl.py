"""The pages must not load Pyodide's OpenSSL, by ANY route the boot has (#757).

WHY ABSENT. PR #756 loaded Pyodide's ``hashlib`` package because Pyodide 0.26.4's ``hashlib``
has no SHA-512/256, the Radiant block hash. With it loaded, OpenSSL 1.1.1n (end of life)
computed EVERY hash on the page, the SHA-256 and RIPEMD-160 behind the signature verdict
included (measured in headless Chromium), and it was about 3.7 MB more code checked only
against a lockfile fetched unverified from the same CDN. ``pyrxd.hash`` now computes
SHA-512/256 in pure Python where ``hashlib`` has none, so the package buys nothing.

WHAT THE FIRST GUARD MISSED. It scanned ``shared.js`` for a literal list handed to
``loadPackage``. A review planted two doors it could not see, and both passed all of
tests/web: ``loadPyodide({..., packages: ["hashlib"]})`` (confirmed in Chromium to fetch the
OpenSSL zips) and ``loadPackage(BOOT_PKGS)`` through a variable. So the checks here are:

* **What the boot asks for, derived by running it** (``boot_packages_harness.mjs``): the real
  ``shared.js`` boot runs under Node against a stand-in Pyodide that records every call. The
  set of Pyodide packages it asks for — through ``loadPyodide``'s options, ``loadPackage`` with
  any argument, ``loadPackagesFromImports`` — must be EXACTLY the reviewed set, and the Python
  it runs may ``micropip.install`` only the two SHA-checked wheels. Any Pyodide API the harness
  does not model is a failure, not a pass.
* **Every package-loading call site is one the harness runs**: each non-comment mention of
  ``loadPyodide`` / ``loadPackage`` / ``loadPackagesFromImports`` / ``micropip`` /
  ``pyimport`` / ``pyodide_js`` in the page scripts lies inside ``bootPyrxdRuntime``.
* **No line of page code names OpenSSL**: in every page script and page, any line naming
  ``hashlib`` or ``openssl`` must be a whole-line comment.
* **The Python the page runs cannot load packages itself**: ``glue.py`` and ``src/pyrxd``
  import none of ``micropip``, ``pyodide_js``, ``js``.

Every door is replayed as a PERMANENT test (``TestTheDoorsStayShut``), against a copy of
``shared.js`` with that door planted, and must be caught.

NOT checked here: what the two allowed packages pull in as Pyodide dependencies. Pyodide 0.26.4's
``pyodide-lock.json`` (read 2026-09-28) gives ``micropip -> packaging`` and ``pycryptodome -> none``,
and headless Chromium the same day loaded cbor2, micropip, packaging, pycryptodome and pyrxd and
requested no OpenSSL file. Nor is Python that reaches a loader without importing one (say,
through ``importlib``) — the import check is for the plain spelling.
"""

from __future__ import annotations

import ast
import json
import re
import subprocess  # nosec B404 — fixed argv, no shell, repo-local script
from pathlib import Path

import pytest

from tests.web.test_curve_install import _require_node

_REPO_ROOT = Path(__file__).resolve().parents[2]
_STATIC = _REPO_ROOT / "docs" / "inspect_static"
_SHARED = _STATIC / "inspect" / "shared.js"
_GLUE = _STATIC / "inspect" / "glue.py"
_HARNESS = Path(__file__).with_name("boot_packages_harness.mjs")

#: The Pyodide packages the boot may ask for, REVIEWED. Adding one is a decision: make it by
#: editing this line, after checking in Chromium what it pulls in. ``hashlib`` (and its
#: ``openssl`` dependency) must not be on it; see the module docstring.
_REVIEWED_PYODIDE_PACKAGES = frozenset({"micropip", "pycryptodome"})

_OPENSSL = re.compile(r"hashlib|openssl", re.IGNORECASE)
_LOADERS = re.compile(r"\b(loadPyodide|loadPackage|loadPackagesFromImports|micropip|pyimport|pyodide_js)\b")
_WHOLE_LINE_COMMENT = re.compile(r"^\s*(//|/\*|\*|<!--)")
_MICROPIP_INSTALL = re.compile(r"micropip\.install\(")
_MICROPIP_LITERAL = re.compile(r"micropip\.install\(\s*([\"'])([^\"']*)\1")


def _page_files() -> list[Path]:
    files = sorted(p for p in _STATIC.rglob("*") if p.suffix in {".js", ".html"})
    assert _SHARED in files and len(files) >= 5, f"the page-file sweep found only {files} — it is broken"
    return files


def _run_boot(shared: Path | None = None) -> dict:
    argv = [_require_node(), "--no-warnings", str(_HARNESS)]
    if shared is not None:
        argv += ["--shared", str(shared)]
    proc = subprocess.run(  # nosec B603 — fixed argv, no shell, repo-local script
        argv, capture_output=True, text=True, cwd=str(_REPO_ROOT), timeout=120
    )
    assert proc.returncode == 0, f"the boot harness failed:\n{proc.stderr[-2000:]}"
    return json.loads(proc.stdout.strip().splitlines()[-1])


def _names(value: object) -> list[str]:
    """Package names in one ``loadPackage`` argument or ``packages`` option, as Pyodide reads it:
    a string or a list of strings. Anything else is reported as itself, so it cannot vanish."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(v, str) for v in value):
        return list(value)
    return [f"<not a name or list of names: {value!r}>"]


def boot_package_violations(result: dict) -> list[str]:
    """Everything wrong with what one boot asked Pyodide to load. Empty means clean."""
    problems: list[str] = []
    if not result["finished"] or 100 not in result["progress"]:
        problems.append(
            f"the boot did not run to the end ({result['error']!r}, progress {result['progress']}), "
            "so whatever it would load after that point was never seen"
        )
    asked: list[str] = []
    for options in result["loadPyodideOptions"]:
        if isinstance(options, dict) and "packages" in options:
            asked += _names(options["packages"])
    for call in result["loadPackage"]:
        asked += _names(call)
    if result["loadPackagesFromImports"]:
        problems.append(
            f"the boot calls loadPackagesFromImports({result['loadPackagesFromImports']}): it loads "
            "whatever the imports map to, which no reviewed list can bound"
        )
    opened = sorted(name for name in asked if _OPENSSL.search(name))
    if opened:
        problems.append(f"the boot asks Pyodide for its OpenSSL: {opened}")
    if set(asked) != _REVIEWED_PYODIDE_PACKAGES:
        problems.append(
            f"the boot asks Pyodide for {sorted(set(asked))}, not the reviewed {sorted(_REVIEWED_PYODIDE_PACKAGES)}"
        )

    installs: list[str] = []
    for source in result["python"]:
        literal = _MICROPIP_LITERAL.findall(source)
        if len(literal) != len(_MICROPIP_INSTALL.findall(source)):
            problems.append(f"the boot runs a micropip.install whose target is not a literal:\n{source}")
        installs += [target for _, target in literal]
        if re.search(r"pyodide_js|loadPackage|^\s*(import|from)\s+js\b", source, re.MULTILINE):
            problems.append(f"the Python the boot runs reaches Pyodide's loader itself:\n{source}")
    wheels = ["emfs:/tmp/cbor2-5.4.6-py3-none-any.whl", "emfs:/tmp/pyrxd-0.0.0-py3-none-any.whl"]
    if installs != wheels:
        problems.append(f"the boot's micropip installs are {installs}, not only the two SHA-checked wheels {wheels}")
    if result["unknown"]:
        problems.append(
            f"the boot reached Pyodide APIs the harness does not model, so what they load is unchecked: "
            f"{result['unknown']}"
        )
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
    code ``boot_packages_harness.mjs`` runs, so the only code whose loads are derived."""
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


def _page_texts() -> dict[str, str]:
    return {str(p.relative_to(_STATIC)): p.read_text(encoding="utf-8") for p in _page_files()}


class TestTheBootLoadsOnlyTheReviewedPackages:
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

    def test_what_the_boot_asks_for_is_exactly_the_reviewed_set(self) -> None:
        result = _run_boot()
        assert boot_package_violations(result) == []
        # The control, so a clean result cannot mean "nothing was recorded".
        assert result["loadPackage"] and result["python"] and result["loadPyodideOptions"]

    def test_every_package_loading_call_site_is_inside_the_boot_the_harness_runs(self) -> None:
        texts = _page_texts()
        assert loader_sites_outside_the_boot(texts) == []
        # The control: the sweep finds the boot's own sites (loadPyodide, loadPackage, micropip).
        shared = texts["inspect/shared.js"]
        assert all(re.search(rf"\b{api}\b", shared) for api in ("loadPyodide", "loadPackage", "micropip"))

    def test_no_line_of_page_code_names_openssl(self) -> None:
        texts = _page_texts()
        assert openssl_on_code_lines(texts) == []
        # The control: the sweep does see these words, in shared.js's own comments.
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


#: Each door: (name, text in shared.js that must occur exactly once, what replaces it). The first
#: two are the ones the review planted past the first guard; the rest are the other routes a name
#: can take to Pyodide's loader.
_DOORS = [
    (
        "loadPyodide packages option",
        "loadPyodide({ indexURL: PYODIDE_INDEX_URL })",
        'loadPyodide({ indexURL: PYODIDE_INDEX_URL, packages: ["hashlib"] })',
    ),
    (
        "loadPackage through a variable",
        'await pyodide.loadPackage(["micropip", "pycryptodome"]);',
        'const BOOT_PKGS = ["hashlib", "micropip", "pycryptodome"];\n    await pyodide.loadPackage(BOOT_PKGS);',
    ),
    (
        "loadPackage with a bare string",
        'await pyodide.loadPackage(["micropip", "pycryptodome"]);',
        'await pyodide.loadPackage(["micropip", "pycryptodome"]);\n    await pyodide.loadPackage("openssl");',
    ),
    (
        "loadPackagesFromImports",
        'await pyodide.loadPackage(["micropip", "pycryptodome"]);',
        'await pyodide.loadPackage(["micropip", "pycryptodome"]);\n'
        '    await pyodide.loadPackagesFromImports("import _hashlib");',
    ),
    (
        "micropip.install from the boot's Python",
        "\nimport micropip\n",
        '\nimport micropip\nawait micropip.install("hashlib")\n',
    ),
    (
        "an unmodelled Pyodide API",
        'await pyodide.loadPackage(["micropip", "pycryptodome"]);',
        'await pyodide.loadPackage(["micropip", "pycryptodome"]);\n'
        '    await pyodide.pyimport("micropip").install("hashlib");',
    ),
]


class TestTheDoorsStayShut:
    """Each door planted into a COPY of ``shared.js``; each must be caught by the boot check and by
    the code-line sweep. A door whose anchor text no longer occurs fails here, rather than
    passing because nothing was planted."""

    @staticmethod
    def _planted(tmp_path: Path, old: str, new: str) -> tuple[Path, str]:
        text = _SHARED.read_text(encoding="utf-8")
        assert text.count(old) == 1, f"the door's anchor {old!r} occurs {text.count(old)} times in shared.js"
        planted = text.replace(old, new)
        path = tmp_path / "shared.js"
        path.write_text(planted, encoding="utf-8")
        return path, planted

    @pytest.mark.parametrize(("door", "old", "new"), _DOORS, ids=[d[0] for d in _DOORS])
    def test_the_boot_check_catches_it(self, tmp_path: Path, door: str, old: str, new: str) -> None:
        path, _ = self._planted(tmp_path, old, new)
        problems = boot_package_violations(_run_boot(path))
        assert problems, f"the {door} door was not caught by the boot check"
        assert any(_OPENSSL.search(p) for p in problems), f"caught, but not as OpenSSL: {problems}"

    @pytest.mark.parametrize(("door", "old", "new"), _DOORS, ids=[d[0] for d in _DOORS])
    def test_the_code_line_sweep_catches_it(self, tmp_path: Path, door: str, old: str, new: str) -> None:
        _, planted = self._planted(tmp_path, old, new)
        texts = {**_page_texts(), "inspect/shared.js": planted}
        assert openssl_on_code_lines(texts), f"the {door} door was not caught by the code-line sweep"

    def test_a_loader_call_outside_the_boot_is_caught(self) -> None:
        """A load on some later click would never reach the harness; the site check catches it."""
        texts = _page_texts()
        texts["verify/verify.js"] += '\nasync function later(py) { await py.loadPackage("ssl"); }\n'
        outside = loader_sites_outside_the_boot(texts)
        assert len(outside) == 1 and outside[0].startswith("verify/verify.js:"), outside

    def test_a_new_reviewed_package_is_caught_even_without_openssl_in_its_name(self, tmp_path: Path) -> None:
        """Pyodide's ``ssl`` package depends on ``openssl`` without naming it: the exact-set pin is
        what catches it."""
        path, _ = self._planted(
            tmp_path,
            'await pyodide.loadPackage(["micropip", "pycryptodome"]);',
            'await pyodide.loadPackage(["micropip", "pycryptodome", "ssl"]);',
        )
        problems = boot_package_violations(_run_boot(path))
        assert any("not the reviewed" in p for p in problems), problems
