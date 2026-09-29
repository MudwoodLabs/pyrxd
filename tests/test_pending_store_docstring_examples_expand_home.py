"""The documented ``JsonFilePendingStore`` examples put records under the home directory (#755).

Both examples passed a bare ``"~/.pyrxd/..."`` string, and the constructor uses its argument as
given, so run as written they made a directory literally named ``~`` under the current one. This
runs each documented line, as written, with ``HOME`` and the working directory pointed at two
different temporary directories, and checks where the store landed.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from pyrxd.glyph import client as glyph_client
from pyrxd.glyph import mint as glyph_mint
from pyrxd.glyph.mint import JsonFilePendingStore

_STORE_LINE = re.compile(r"^\s*(store = JsonFilePendingStore\(.*\))\s*$", re.M)


def _documented_lines() -> list[tuple[str, str]]:
    found = []
    for name, doc in (
        ("GlyphMinter", glyph_mint.GlyphMinter.__doc__),
        ("GlyphClient", glyph_client.GlyphClient.__doc__),
    ):
        lines = _STORE_LINE.findall(doc or "")
        assert lines, f"{name}'s docstring no longer shows how to build a store; update this test"
        found += [(name, line) for line in lines]
    return found


@pytest.mark.parametrize(("where", "line"), _documented_lines())
def test_the_documented_store_lands_under_home(where, line, tmp_path, monkeypatch) -> None:
    home, cwd = tmp_path / "home", tmp_path / "cwd"
    home.mkdir()
    cwd.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.chdir(cwd)
    scope: dict = {"JsonFilePendingStore": JsonFilePendingStore, "Path": Path}
    exec(line, scope)
    store = scope["store"]
    assert Path(store.directory).is_relative_to(home), (where, store.directory)
    assert not (cwd / "~").exists(), f"{where}'s example made a literal '~' directory"


def test_a_bare_tilde_string_is_still_used_as_given(tmp_path, monkeypatch) -> None:
    """Why the examples call ``expanduser()``: the constructor does not, and says so."""
    monkeypatch.chdir(tmp_path)
    store = JsonFilePendingStore("~/pending")
    assert Path(store.directory) == Path("~/pending")
    assert (tmp_path / "~" / "pending").is_dir()
    assert "expanduser" in (JsonFilePendingStore.__doc__ or "")


_REPO = Path(__file__).resolve().parents[1]
_STORE_CALL = re.compile(r"\bJsonFilePendingStore\(")


def _call_args(text: str, open_paren: int) -> str:
    """The argument text of the call whose ``(`` is at *open_paren*, up to its matching ``)``."""
    depth = 0
    for i in range(open_paren, len(text)):
        depth += {"(": 1, ")": -1}.get(text[i], 0)
        if depth == 0:
            return text[open_paren + 1 : i]
    return text[open_paren + 1 :]


def _uses_tilde_unexpanded(args: str) -> bool:
    """A ``~`` reaches the constructor unexpanded: in a string literal, positional or ``directory=``,
    bare or wrapped in ``Path(...)``, and no ``expanduser`` anywhere in the argument."""
    return re.search(r"[\"']~", args) is not None and "expanduser" not in args


def _shipped_text_files() -> list[Path]:
    """Everything a reader copies from: the README (also the PyPI page), docs, examples, source."""
    files = [_REPO / "README.md"]
    for sub, pattern in (("docs", "*.md"), ("docs", "*.rst"), ("examples", "*.py"), ("src", "*.py")):
        files += sorted((_REPO / sub).rglob(pattern))
    return [f for f in files if f.is_file()]


def test_no_shipped_example_hands_a_store_a_bare_tilde_string() -> None:
    """The docstring test above runs two examples it names; this one scans every ``JsonFilePendingStore(`` call (#755).

    The README carried the same bare ``"~/..."`` string after both docstrings were fixed, because the
    list above is typed by hand. This scan derives its scope from the tree instead.
    """
    calls: dict[str, int] = {}
    offenders = []
    for path in _shipped_text_files():
        text = path.read_text(encoding="utf-8", errors="replace")
        rel = str(path.relative_to(_REPO))
        for m in _STORE_CALL.finditer(text):
            calls[rel] = calls.get(rel, 0) + 1
            if _uses_tilde_unexpanded(_call_args(text, m.end() - 1)):
                offenders.append(f"{rel}:{text.count(chr(10), 0, m.start()) + 1}")
    # Non-vacuity, by place: the README is where #755's gap survived, so it must be seen.
    assert calls.get("README.md", 0) >= 1, f"the scan no longer sees the README's store example: {calls}"
    assert any(k.startswith("examples/") for k in calls), f"the scan no longer sees the examples: {calls}"
    assert not offenders, f"a store is built from an unexpanded '~' path (it is used as given): {offenders}"


@pytest.mark.parametrize(
    "args",
    ['"~/x"', 'Path("~/x")', 'directory="~/x"', 'r"~/x"', "'~/x'", '"""~/x"""'],
)
def test_the_scan_flags_every_spelling_of_an_unexpanded_tilde(args) -> None:
    assert _uses_tilde_unexpanded(args)


@pytest.mark.parametrize("args", ['Path("~/x").expanduser()', "STORE_DIR", 'os.path.expanduser("~/x")', '"./pending"'])
def test_the_scan_passes_an_expanded_or_tilde_free_path(args) -> None:
    assert not _uses_tilde_unexpanded(args)
