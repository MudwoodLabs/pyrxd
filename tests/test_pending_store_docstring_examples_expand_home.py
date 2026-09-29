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
_ANY_STORE_CALL = re.compile(r"PendingStore\(")
_BARE_TILDE_ARG = re.compile(r"PendingStore\(\s*[rbfu]?[\"']~")


def _shipped_text_files() -> list[Path]:
    """Everything a reader copies from: the README (also the PyPI page), docs, examples, source."""
    files = [_REPO / "README.md"]
    for sub, pattern in (("docs", "*.md"), ("docs", "*.rst"), ("examples", "*.py"), ("src", "*.py")):
        files += sorted((_REPO / sub).rglob(pattern))
    return [f for f in files if f.is_file()]


def test_no_shipped_example_hands_a_store_a_bare_tilde_string() -> None:
    """The docstring test above runs two examples it names; this one finds every example (#755).

    The README carried the same bare ``"~/..."`` string after both docstrings were fixed, because the
    list above is typed by hand. This scan derives its scope from the tree instead.
    """
    calls, offenders = 0, []
    for path in _shipped_text_files():
        text = path.read_text(encoding="utf-8", errors="replace")
        calls += len(_ANY_STORE_CALL.findall(text))
        offenders += [
            f"{path.relative_to(_REPO)}:{text.count(chr(10), 0, m.start()) + 1}" for m in _BARE_TILDE_ARG.finditer(text)
        ]
    assert calls >= 3, f"found only {calls} store constructions; the scan has stopped seeing the examples"
    assert not offenders, f"a store is built from a bare '~' string (it is used as given): {offenders}"
