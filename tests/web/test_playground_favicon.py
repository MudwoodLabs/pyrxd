"""The playground's favicon: every icon the page links exists, is what it claims, and the CSP lets it load.

The set of icons is read from ``index.html`` itself, so an icon link added or renamed later is checked
without anyone editing this file.
"""

from __future__ import annotations

import re
import struct
from pathlib import Path

_PAGE_DIR = Path(__file__).resolve().parents[2] / "docs" / "inspect_static" / "playground"
_HTML = (_PAGE_DIR / "index.html").read_text(encoding="utf-8")


def _icon_links() -> list[dict[str, str]]:
    links = []
    for tag in re.findall(r"<link\b[^>]*>", _HTML):
        attrs = dict(re.findall(r'(\w[\w-]*)="([^"]*)"', tag))
        if attrs.get("rel") in ("icon", "apple-touch-icon"):
            links.append(attrs)
    return links


def _png_size(path: Path) -> tuple[int, int]:
    data = path.read_bytes()
    assert data[:8] == b"\x89PNG\r\n\x1a\n", f"{path.name} is not a PNG"
    return struct.unpack(">II", data[16:24])


def test_every_linked_icon_exists_next_to_the_page():
    links = _icon_links()
    assert links, "index.html links no favicon"
    for link in links:
        href = link["href"]
        assert "/" not in href and ":" not in href, f"{href}: icons are served from the page's own folder"
        assert (_PAGE_DIR / href).is_file(), f"index.html links {href}, which is not in the playground folder"


def test_each_icon_is_the_type_and_size_its_link_declares():
    for link in _icon_links():
        path = _PAGE_DIR / link["href"]
        if path.suffix == ".svg":
            assert link.get("type") == "image/svg+xml"
            svg = path.read_text(encoding="utf-8")
            assert svg.startswith("<svg ") and 'viewBox="0 0 64 64"' in svg
            # A static picture: no script, no external reference, nothing for img-src to refuse.
            assert not re.search(r"<script|href=|url\(|<foreignObject", svg), svg
        else:
            width, height = _png_size(path)
            assert width == height, f"{path.name} is {width}x{height}"
            if "sizes" in link:
                assert link["sizes"] == f"{width}x{height}", f"{path.name} says {link['sizes']}, is {width}x{height}"
            if link["rel"] == "apple-touch-icon":
                assert width == 180, f"apple-touch-icon is {width}px, iOS expects 180"


def test_the_csp_lets_the_icons_load():
    csp = re.search(r'http-equiv="Content-Security-Policy"\s+content="([^"]*)"', _HTML)
    assert csp, "no CSP meta tag"
    img_src = next((c.split() for c in csp.group(1).split(";") if c.split()[:1] == ["img-src"]), None)
    assert img_src is not None and "'self'" in img_src, f"img-src {img_src} would block the page's own icons"
