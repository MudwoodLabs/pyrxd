"""No test module may SPELL the regtest image tag; it must derive it.

``scripts/refresh_radiant_core_vendor.py --check`` decides whether the vendored
consensus oracle describes the node the integration lane runs. It reads
:data:`pyrxd.devnet.DEFAULT_RADIANT_VERSION`. If a test module spells
``radiant-core:vX.Y.Z-amd64`` itself, the check reads one source while the lane uses
another — it passes, and measures nothing. That is not hypothetical: five modules
spelled it independently, and when the source pin moved to v3.1.2 while those literals
stayed at v3.1.1, every parity assertion in those lanes was describing an interpreter
the node did not implement.

**WHAT THIS COVERS, AND WHAT IT DOES NOT.** It scans module-level string assignments
only — the constants that select an image for a lane. It deliberately does NOT flag a
literal inside a function body: ``tests/test_devnet.py`` passes an explicit version to
``build_image`` and asserts the tag it formats, which is a test OF the formatter and is
correct as a literal. Nor does it read comments or docstrings: those record which node a
result was measured on, and rewriting that history to match a newer pin would falsify
the record rather than fix anything.

So this is a check on ONE axis. A lane that selected an image some other way — computed
at runtime, read from an environment variable, passed as a fixture parameter — would not
be caught here, and that is worth remembering before trusting a green result.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

TESTS_DIR = Path(__file__).resolve().parent
#: Matches the image tags this repo builds, at any version.
_IMAGE_LITERAL = re.compile(r"radiant-core:v\d+\.\d+\.\d+-amd64")


def _module_level_string_assignments(tree: ast.Module) -> list[tuple[str, str, int]]:
    """Every ``NAME = "..."`` at module scope, as (name, value, lineno)."""
    out: list[tuple[str, str, int]] = []
    for node in tree.body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        value = node.value
        if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        for t in targets:
            if isinstance(t, ast.Name):
                out.append((t.id, value.value, node.lineno))
    return out


def _test_modules() -> list[Path]:
    return sorted(p for p in TESTS_DIR.rglob("test_*.py") if "__pycache__" not in p.parts)


def test_the_scan_is_not_vacuous() -> None:
    """A sweep that cannot find anything has told you the sweep is broken.

    Without this, a glob that silently matched zero files would make the real
    assertion below pass by having nothing to iterate.
    """
    modules = _test_modules()
    assert len(modules) > 50, f"only {len(modules)} test modules found — the scan is not reaching the suite"
    assert any(p.name == "test_htlc_regtest_e2e.py" for p in modules), "a known regtest module is missing from the scan"


def test_the_pattern_matches_a_string_we_know_it_should() -> None:
    """The control: prove the regex finds the thing it exists to find."""
    assert _IMAGE_LITERAL.search('_IMAGE = "radiant-core:v3.1.1-amd64"')
    assert _IMAGE_LITERAL.search("radiant-core:v9.9.9-amd64")
    assert not _IMAGE_LITERAL.search("radiant-core")


@pytest.mark.parametrize("path", _test_modules(), ids=lambda p: p.name)
def test_no_module_level_constant_spells_the_image_tag(path: Path) -> None:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    offenders = [
        f"{path.name}:{lineno}  {name} = {value!r}"
        for name, value, lineno in _module_level_string_assignments(tree)
        if _IMAGE_LITERAL.search(value)
    ]
    assert not offenders, (
        "a module-level constant spells the regtest image tag instead of deriving it "
        "from pyrxd.devnet.RegtestNode.IMAGE, so refresh_radiant_core_vendor.py --check "
        "can pass while this lane runs a different node:\n  " + "\n  ".join(offenders)
    )
