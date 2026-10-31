"""``scripts/run_tests_in_chunks.py`` must run every test file once and never report a failure as a pass.

The script exists so a memory-limited review guest can run the whole default suite. Its two ways to
mislead are dropping files (a "no test catches this" claim from a partial run) and reading green
when a chunk failed or ran nothing, so those are what these tests pin, each beside an honest case.
"""

from __future__ import annotations

import importlib.util
import pathlib
import sys

import pytest

_SCRIPT = pathlib.Path(__file__).resolve().parent.parent / "scripts" / "run_tests_in_chunks.py"
_spec = importlib.util.spec_from_file_location("run_tests_in_chunks", _SCRIPT)
assert _spec is not None and _spec.loader is not None
chunks = importlib.util.module_from_spec(_spec)
sys.modules["run_tests_in_chunks"] = chunks
_spec.loader.exec_module(chunks)


def test_the_repo_file_set_is_non_empty_and_holds_this_file() -> None:
    files = chunks.test_files()
    assert len(files) > 100
    assert pathlib.Path(__file__).resolve() in files
    assert all(f.name.startswith("test_") and f.suffix == ".py" for f in files)


@pytest.mark.parametrize("n", [1, 2, 3, 7, 8, 50])
def test_every_file_lands_in_exactly_one_chunk(n: int) -> None:
    files = chunks.test_files()
    groups = chunks.split(files, n)
    assigned = [f for g in groups for f in g]
    assert assigned == files
    assert len(groups) == min(n, len(files))
    sizes = {len(g) for g in groups}
    assert max(sizes) - min(sizes) <= 1
    assert all(groups)


def test_more_chunks_than_files_gives_one_file_per_chunk() -> None:
    files = [pathlib.Path(f"tests/test_{i}.py") for i in range(3)]
    assert chunks.split(files, 10) == [[f] for f in files]


def test_zero_chunks_is_refused() -> None:
    with pytest.raises(ValueError, match="at least 1"):
        chunks.split([pathlib.Path("tests/test_a.py")], 0)


def _tree(tmp_path: pathlib.Path, bodies: dict[str, str]) -> pathlib.Path:
    """A throwaway project: an empty pytest config and a tests/ directory holding ``bodies``."""
    (tmp_path / "pytest.ini").write_text("[pytest]\nmarkers =\n    integration: node-backed\n")
    tests = tmp_path / "tests"
    tests.mkdir()
    for name, body in bodies.items():
        (tests / name).write_text(body)
    return tests


_PASS = "def test_ok():\n    assert True\n"
_FAIL = "def test_bad():\n    assert False\n"
_ONLY_DESELECTED = "import pytest\n\n@pytest.mark.integration\ndef test_node():\n    assert True\n"


def test_all_passing_chunks_exit_zero(tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = _tree(tmp_path, {"test_a.py": _PASS, "test_b.py": _PASS, "test_c.py": _PASS})
    assert chunks.run(2, tmp_path / "reports", [], root=root) == 0
    out = capsys.readouterr().out
    assert "TOTAL: 3 tests, 0 failed, 0 errors" in out
    assert out.count("peak RSS") == 2


def test_one_failing_chunk_fails_the_run(tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = _tree(tmp_path, {"test_a.py": _PASS, "test_b.py": _PASS, "test_c.py": _FAIL})
    assert chunks.run(3, tmp_path / "reports", [], root=root) == 1
    captured = capsys.readouterr()
    assert "1 failed" in captured.out
    assert "chunk(s) 3 did not pass" in captured.err


def test_a_chunk_of_only_deselected_tests_is_not_a_failure(tmp_path: pathlib.Path) -> None:
    root = _tree(tmp_path, {"test_a.py": _PASS, "test_z.py": _ONLY_DESELECTED})
    assert chunks.run(2, tmp_path / "reports", ["-m", "not integration"], root=root) == 0


def test_a_run_that_selects_nothing_at_all_fails(tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = _tree(tmp_path, {"test_y.py": _ONLY_DESELECTED, "test_z.py": _ONLY_DESELECTED})
    assert chunks.run(2, tmp_path / "reports", ["-m", "not integration"], root=root) == 1
    assert "ran no test at all" in capsys.readouterr().err


def test_a_chunk_that_errors_at_collection_fails_the_run(tmp_path: pathlib.Path) -> None:
    root = _tree(tmp_path, {"test_a.py": _PASS, "test_b.py": "import no_such_module_xyz\n"})
    assert chunks.run(2, tmp_path / "reports", [], root=root) == 1


def test_no_test_files_is_an_error(tmp_path: pathlib.Path) -> None:
    root = _tree(tmp_path, {})
    assert chunks.run(2, tmp_path / "reports", [], root=root) == 2
