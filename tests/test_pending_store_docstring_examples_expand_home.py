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
