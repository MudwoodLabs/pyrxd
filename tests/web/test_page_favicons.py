"""Each published page's favicon: it exists, is what its link claims, credits the logo, and the CSP lets it load.

The pages are every ``docs/inspect_static/*/index.html``, and each page's icons are read from its own
``<link>`` tags, so a new page, or an icon link added or renamed later, is checked without anyone
editing this file.
"""

from __future__ import annotations

import re
import struct
from pathlib import Path

import pytest

_STATIC = Path(__file__).resolve().parents[2] / "docs" / "inspect_static"
_PAGES = sorted(p.parent.name for p in _STATIC.glob("*/index.html"))
_LICENCE = "RADIANT-LOGO-LICENSE.txt"  # one per page folder: nothing may sit at the top of inspect_static/


def _html(page: str) -> str:
    return (_STATIC / page / "index.html").read_text(encoding="utf-8")


def _icon_links(page: str) -> list[dict[str, str]]:
    links = []
    for tag in re.findall(r"<link\b[^>]*>", _html(page)):
        attrs = dict(re.findall(r'(\w[\w-]*)="([^"]*)"', tag))
        if attrs.get("rel") in ("icon", "apple-touch-icon"):
            links.append(attrs)
    return links


def _png_size(path: Path) -> tuple[int, int]:
    data = path.read_bytes()
    assert data[:8] == b"\x89PNG\r\n\x1a\n", f"{path.name} is not a PNG"
    return struct.unpack(">II", data[16:24])


def test_the_pages_were_found():
    assert {"inspect", "playground", "verify"} <= set(_PAGES), _PAGES


@pytest.mark.parametrize("page", _PAGES)
def test_every_linked_icon_exists_next_to_the_page(page: str):
    links = _icon_links(page)
    assert links, f"{page}/index.html links no favicon"
    for link in links:
        href = link["href"]
        assert "/" not in href and ":" not in href, f"{page}: {href}: icons are served from the page's own folder"
        assert (_STATIC / page / href).is_file(), f"{page}/index.html links {href}, which is not in its folder"


@pytest.mark.parametrize("page", _PAGES)
def test_each_icon_is_the_type_and_size_its_link_declares(page: str):
    for link in _icon_links(page):
        path = _STATIC / page / link["href"]
        if path.suffix == ".svg":
            assert link.get("type") == "image/svg+xml"
            svg = path.read_text(encoding="utf-8")
            assert svg.startswith("<svg ") and 'viewBox="0 0 64 64"' in svg
            # A static picture: no script and no external reference, nothing for img-src to refuse.
            # url(#id) points at a gradient defined in the same file, so it is allowed.
            assert not re.search(r"<script|href=|url\((?!#)|<foreignObject", svg), svg[:200]
        else:
            width, height = _png_size(path)
            assert width == height, f"{path.name} is {width}x{height}"
            if "sizes" in link:
                assert link["sizes"] == f"{width}x{height}", f"{path.name} says {link['sizes']}, is {width}x{height}"
            if link["rel"] == "apple-touch-icon":
                assert width == 180, f"apple-touch-icon is {width}px, iOS expects 180"


@pytest.mark.parametrize("page", _PAGES)
def test_the_logo_is_credited_and_its_licence_ships(page: str):
    """The R is Radiant-Core's MIT-licensed logo: the notice must travel with every copy of it."""
    for link in _icon_links(page):
        if link["href"].endswith(".svg"):
            svg = (_STATIC / page / link["href"]).read_text(encoding="utf-8")
            assert "The Radiant Developers" in svg and _LICENCE in svg
    text = (_STATIC / page / _LICENCE).read_text(encoding="utf-8")
    assert "Copyright (c) 2022-2026 The Radiant Developers" in text
    assert "The above copyright notice and this permission notice shall be included" in text


@pytest.mark.parametrize("page", _PAGES)
def test_the_csp_lets_the_icons_load(page: str):
    csp = re.search(r'http-equiv="Content-Security-Policy"\s+content="([^"]*)"', _html(page))
    assert csp, f"{page}: no CSP meta tag"
    img_src = next((c.split() for c in csp.group(1).split(";") if c.split()[:1] == ["img-src"]), None)
    assert img_src is not None and "'self'" in img_src, f"{page}: img-src {img_src} would block its own icons"
