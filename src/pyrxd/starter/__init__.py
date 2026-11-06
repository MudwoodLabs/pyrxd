"""The ``pyrxd new`` starter project: a template app with a test on a local regtest chain.

Two entry points, so the template is usable from code as well as from the CLI:

* :func:`render_project` returns the project as ``{relative_path: text}`` and touches no
  disk. Anything that wants to hand a user a project (a browser playground's "export",
  a zip download, a test) can start here.
* :func:`write_project` renders and writes it to a new directory. ``pyrxd new`` calls it.

``overrides`` on both replaces or adds files verbatim, after the template is rendered, so
a caller can drop its own code into ``src/<package>/mint.py``. Override text is never
passed through placeholder substitution.
"""

from __future__ import annotations

import keyword
import re
import sys
from collections.abc import Mapping
from pathlib import Path, PurePosixPath

from .. import __version__
from . import _template

__all__ = [
    "ProjectNameError",
    "package_name_for",
    "pyrxd_requirement",
    "render_project",
    "write_project",
]

# PEP 508's name rule, case-insensitive.
_PROJECT_NAME_RE = re.compile(r"[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?")
_VERSION_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")

# Import names a project must not take: its own package would shadow the library it
# depends on, or the test directory, for every import in the project.
_RESERVED_PACKAGE_NAMES = frozenset({"pyrxd", "test", "tests", "conftest"})


class ProjectNameError(ValueError):
    """The requested project name cannot be used."""


def package_name_for(project_name: str) -> str:
    """The import name for ``project_name`` (``my-token-app`` -> ``my_token_app``).

    Raises :class:`ProjectNameError` if the name is not a valid distribution name, or its
    import name is not an identifier, is a keyword, or would shadow pyrxd, the tests
    directory or a standard-library module.
    """
    if not isinstance(project_name, str) or not _PROJECT_NAME_RE.fullmatch(project_name):
        raise ProjectNameError(
            f"{project_name!r} is not a valid project name: use letters, digits, '-', '_' or '.', "
            "starting and ending with a letter or digit"
        )
    package = re.sub(r"[-_.]+", "_", project_name).lower()
    if not package.isidentifier() or keyword.iskeyword(package):
        raise ProjectNameError(
            f"{project_name!r} gives the import name {package!r}, which is not a Python identifier; "
            "start the name with a letter"
        )
    if package in _RESERVED_PACKAGE_NAMES or package in sys.stdlib_module_names:
        raise ProjectNameError(
            f"{project_name!r} gives the import name {package!r}, which would shadow an existing module; "
            "pick another name"
        )
    return package


def pyrxd_requirement(version: str = __version__) -> str:
    """The pyrxd requirement a new project gets: this release and later, same minor series.

    Derived from the running pyrxd rather than written down, so it moves with each release.
    pyrxd is pre-1.0 and a minor release may break the API, so the upper bound is the next
    minor (``0.28.1`` -> ``pyrxd>=0.28.1,<0.29``); from 1.0 it is the next major.
    """
    m = _VERSION_RE.match(version)
    if m is None:
        raise ValueError(f"cannot read a release number from pyrxd version {version!r}")
    major, minor, patch = (int(g) for g in m.groups())
    upper = f"{major}.{minor + 1}" if major == 0 else f"{major + 1}"
    return f"pyrxd>={major}.{minor}.{patch},<{upper}"


def _check_override_path(path: str) -> str:
    p = PurePosixPath(path)
    if (
        not path
        or "\\" in path
        or p.is_absolute()
        or path.startswith("/")
        or any(part in ("", ".", "..") for part in path.split("/"))
        or ":" in p.parts[0]
    ):
        raise ValueError(f"override path {path!r} must be a relative path inside the project, using '/'")
    return path


def render_project(project_name: str, *, overrides: Mapping[str, str] | None = None) -> dict[str, str]:
    """The starter project for ``project_name`` as ``{relative_path: file_text}``.

    Paths use ``/``. ``overrides`` maps relative paths to text that replaces the rendered
    file at that path, or adds a new one; it is used verbatim. Raises
    :class:`ProjectNameError` for an unusable name and :class:`ValueError` for an override
    path that is absolute or leaves the project.
    """
    package = package_name_for(project_name)
    tokens = {
        "__PROJECT_NAME__": project_name,
        "__PACKAGE_NAME__": package,
        "__PYRXD_REQUIREMENT__": pyrxd_requirement(),
        "__CHECKOUT_ACTION__": _template.CHECKOUT_ACTION,
        "__SETUP_PYTHON_ACTION__": _template.SETUP_PYTHON_ACTION,
    }

    def fill(text: str) -> str:
        for token, value in tokens.items():
            text = text.replace(token, value)
        return text

    files = {fill(path): fill(text) for path, text in _template.FILES.items()}
    for path, text in (overrides or {}).items():
        if not isinstance(text, str):
            raise TypeError(f"override for {path!r} must be text, not {type(text).__name__}")
        files[_check_override_path(path)] = text
    return files


def write_project(
    project_name: str,
    directory: str | Path | None = None,
    *,
    overrides: Mapping[str, str] | None = None,
) -> Path:
    """Render the starter project and write it to ``directory`` (default ``./<project_name>``).

    Refuses (``FileExistsError``) if ``directory`` exists and is not an empty directory, so
    it never overwrites anything. Returns the directory written.
    """
    files = render_project(project_name, overrides=overrides)
    target = Path(directory) if directory is not None else Path(project_name)
    if target.exists() and (not target.is_dir() or any(target.iterdir())):
        raise FileExistsError(f"{target} already exists and is not empty")
    target.mkdir(parents=True, exist_ok=True)
    for rel, text in files.items():
        out = target.joinpath(*rel.split("/"))
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
    return target
