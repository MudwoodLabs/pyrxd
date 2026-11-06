"""Offline tests for the ``pyrxd new`` starter template (``pyrxd.starter``).

What the generated project's own test does on a real node is
``tests/test_starter_kit_regtest_e2e.py``; this file covers rendering, naming, writing and
the CLI, none of which needs a node.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

import pyrxd
from pyrxd.cli.main import cli
from pyrxd.starter import (
    ProjectNameError,
    _template,
    package_name_for,
    pyrxd_requirement,
    render_project,
    write_project,
)

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - 3.10 only
    import tomli as tomllib

_REPO = Path(__file__).resolve().parent.parent
_TOKEN_RE = re.compile(r"__[A-Z][A-Z_]*__")

# --------------------------------------------------------------------------- render


def test_render_produces_every_template_file_with_the_package_substituted():
    files = render_project("my-token-app")
    expected = {p.replace("__PACKAGE_NAME__", "my_token_app") for p in _template.FILES}
    assert expected  # the template is not empty
    assert set(files) == expected
    assert "src/my_token_app/mint.py" in files
    assert "tests/test_mint.py" in files
    assert ".github/workflows/ci.yml" in files


def test_render_leaves_no_template_token_behind():
    # The set of tokens is read from the template itself, so a new token cannot be missed.
    tokens = {t for text in [*_template.FILES, *_template.FILES.values()] for t in _TOKEN_RE.findall(text)}
    assert tokens >= {"__PROJECT_NAME__", "__PACKAGE_NAME__", "__PYRXD_REQUIREMENT__"}
    for path, text in render_project("demo").items():
        assert not _TOKEN_RE.search(path), path
        assert not _TOKEN_RE.search(text), (path, _TOKEN_RE.findall(text))


def test_rendered_pyproject_depends_on_this_pyrxd_series():
    meta = tomllib.loads(render_project("my-token-app")["pyproject.toml"])
    assert meta["project"]["name"] == "my-token-app"
    assert meta["project"]["dependencies"] == [pyrxd_requirement(pyrxd.__version__)]
    assert meta["tool"]["hatch"]["build"]["targets"]["wheel"]["packages"] == ["src/my_token_app"]
    assert meta["tool"]["pytest"]["ini_options"]["pythonpath"] == ["src"]


@pytest.mark.parametrize(
    ("version", "requirement"),
    [
        ("0.27.1", "pyrxd>=0.27.1,<0.28"),
        ("0.28.0", "pyrxd>=0.28.0,<0.29"),
        ("0.28.0.dev3", "pyrxd>=0.28.0,<0.29"),
        ("1.2.3", "pyrxd>=1.2.3,<2"),
    ],
)
def test_pyrxd_requirement_floors_at_this_release_and_stops_before_the_next_breaking_one(version, requirement):
    assert pyrxd_requirement(version) == requirement


def test_pyrxd_requirement_refuses_a_version_it_cannot_read():
    with pytest.raises(ValueError, match="cannot read a release number"):
        pyrxd_requirement("unknown")


def test_rendered_python_files_compile():
    files = render_project("my-token-app")
    py = {p: t for p, t in files.items() if p.endswith(".py")}
    assert len(py) == 4
    for path, text in py.items():
        compile(text, path, "exec")


def test_rendered_workflow_parses_and_uses_the_same_action_pins_as_pyrxds_own_ci():
    workflow = yaml.safe_load(render_project("demo")[".github/workflows/ci.yml"])
    steps = workflow["jobs"]["test"]["steps"]
    used = [s["uses"] for s in steps if "uses" in s]
    ours = (_REPO / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    pins = set(re.findall(r"uses:\s*(actions/[\w-]+@[0-9a-f]{40})", ours))
    assert pins
    assert len(used) == 2
    for ref in used:
        assert ref in pins, f"{ref} is not the pin .github/workflows/ci.yml uses: {sorted(pins)}"
    commands = " ".join(s.get("run", "") for s in steps)
    assert "pyrxd regtest setup" in commands
    assert "pytest" in commands


def test_generated_test_asks_the_node_not_the_minter():
    test = render_project("demo")["tests/test_mint.py"]
    assert "get_transaction_verbose(result.reveal_txid)" in test
    assert "script_carries_ref(" in test
    conftest = render_project("demo")["tests/conftest.py"]
    assert 'pytest_plugins = ["pyrxd.testing.pytest_plugin"]' in conftest


# --------------------------------------------------------------------------- names


@pytest.mark.parametrize(
    ("name", "package"),
    [("my-token-app", "my_token_app"), ("My.App", "my_app"), ("app2", "app2"), ("a__b--c", "a_b_c")],
)
def test_package_name_for_accepts_ordinary_names(name, package):
    assert package_name_for(name) == package


@pytest.mark.parametrize(
    ("name", "why"),
    [
        ("", "not a valid project name"),
        ("-app", "not a valid project name"),
        ("app-", "not a valid project name"),
        ("my app", "not a valid project name"),
        ("../evil", "not a valid project name"),
        ("a/b", "not a valid project name"),
        ("2fast", "not a Python identifier"),
        ("class", "not a Python identifier"),
        ("pyrxd", "would shadow"),
        ("PyRXD", "would shadow"),
        ("tests", "would shadow"),
        ("json", "would shadow"),
        ("asyncio", "would shadow"),
    ],
)
def test_package_name_for_refuses_unusable_names(name, why):
    with pytest.raises(ProjectNameError, match=why):
        package_name_for(name)


def test_stdlib_refusal_is_read_from_the_interpreter():
    assert sys.stdlib_module_names  # the set the refusal reads is not empty
    with pytest.raises(ProjectNameError):
        package_name_for(sorted(n for n in sys.stdlib_module_names if n.isidentifier() and "_" not in n)[0])


# --------------------------------------------------------------------------- overrides


def test_override_replaces_a_file_verbatim_and_can_add_one():
    user_code = "# keeps __PACKAGE_NAME__ as typed\nasync def mint_nft(*a, **k): ...\n"
    files = render_project("demo", overrides={"src/demo/mint.py": user_code, "notes/idea.md": "hi"})
    assert files["src/demo/mint.py"] == user_code
    assert files["notes/idea.md"] == "hi"
    assert files["pyproject.toml"] == render_project("demo")["pyproject.toml"]


@pytest.mark.parametrize("path", ["", "/etc/passwd", "../x.py", "src/../../x", "a\\b.py", "C:/x.py", "./x", "a//b"])
def test_override_refuses_a_path_outside_the_project(path):
    with pytest.raises(ValueError, match="relative path inside the project"):
        render_project("demo", overrides={path: "x"})


def test_override_refuses_non_text():
    with pytest.raises(TypeError, match="must be text"):
        render_project("demo", overrides={"a.py": b"x"})  # type: ignore[dict-item]


# --------------------------------------------------------------------------- write


def test_write_project_writes_exactly_what_render_returns(tmp_path):
    target = write_project("my-token-app", tmp_path / "out")
    written = {p.relative_to(target).as_posix(): p.read_bytes() for p in target.rglob("*") if p.is_file()}
    rendered = {p: t.encode("utf-8") for p, t in render_project("my-token-app").items()}
    assert written == rendered


def test_write_project_defaults_to_a_directory_named_after_the_project(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert write_project("demo") == Path("demo")
    assert (tmp_path / "demo" / "src" / "demo" / "mint.py").is_file()


def test_write_project_fills_an_existing_empty_directory(tmp_path):
    (tmp_path / "empty").mkdir()
    write_project("demo", tmp_path / "empty")
    assert (tmp_path / "empty" / "pyproject.toml").is_file()


def test_write_project_never_overwrites(tmp_path):
    busy = tmp_path / "busy"
    busy.mkdir()
    (busy / "keep.txt").write_text("mine")
    with pytest.raises(FileExistsError, match="not empty"):
        write_project("demo", busy)
    assert [p.name for p in busy.iterdir()] == ["keep.txt"]
    afile = tmp_path / "afile"
    afile.write_text("mine")
    with pytest.raises(FileExistsError):
        write_project("demo", afile)
    assert afile.read_text() == "mine"


# --------------------------------------------------------------------------- CLI


def test_cli_new_creates_the_project_and_says_what_to_run(tmp_path):
    result = CliRunner().invoke(cli, ["new", "my-token-app", "--dir", str(tmp_path / "p")])
    assert result.exit_code == 0, result.output
    assert (tmp_path / "p" / "tests" / "test_mint.py").is_file()
    assert "pyrxd regtest setup" in result.output
    assert "src/my_token_app/mint.py" in result.output


def test_cli_new_json_lists_the_files(tmp_path):
    result = CliRunner().invoke(cli, ["new", "demo", "--dir", str(tmp_path / "p"), "--json"])
    assert result.exit_code == 0, result.output
    out = json.loads(result.output)
    assert out["directory"] == str(tmp_path / "p")
    assert set(out["files"]) == set(render_project("demo"))


def test_cli_new_refuses_a_bad_name_and_writes_nothing(tmp_path):
    result = CliRunner().invoke(cli, ["new", "pyrxd", "--dir", str(tmp_path / "p")])
    assert result.exit_code != 0
    assert "would shadow" in result.output
    assert not (tmp_path / "p").exists()


def test_cli_new_refuses_a_non_empty_directory(tmp_path):
    (tmp_path / "p").mkdir()
    (tmp_path / "p" / "x").write_text("x")
    result = CliRunner().invoke(cli, ["new", "demo", "--dir", str(tmp_path / "p")])
    assert result.exit_code != 0
    assert "not empty" in result.output
