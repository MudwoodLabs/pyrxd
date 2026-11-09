"""The visit counter on each tool page stays walled off from the page it counts.

Every ``docs/inspect_static/*/index.html`` loads Cloudflare Web Analytics only through its own
``count.html``, in a frame sandboxed with ``allow-scripts`` alone. That gives the frame an opaque
origin, so the third-party beacon cannot read the page, its inputs or its keys. The page's own CSP
must not admit the beacon, and it may frame nothing but itself.
"""

from __future__ import annotations

from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit

import pytest

_STATIC = Path(__file__).resolve().parents[2] / "docs" / "inspect_static"
_PAGES = sorted(p.parent.name for p in _STATIC.glob("*/index.html"))
_BEACON_HOSTS = ("static.cloudflareinsights.com", "cloudflareinsights.com")


class _Tags(HTMLParser):
    """Every start tag with its attributes, read by the standard HTML parser (case-insensitive)."""

    def __init__(self, html: str) -> None:
        super().__init__()
        self.tags: list[tuple[str, dict[str, str]]] = []
        self.feed(html)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append((tag, {k: v or "" for k, v in attrs}))

    def named(self, name: str) -> list[dict[str, str]]:
        return [attrs for tag, attrs in self.tags if tag == name]


def _csp(html: str) -> dict[str, list[str]]:
    metas = [m for m in _Tags(html).named("meta") if m.get("http-equiv", "").lower() == "content-security-policy"]
    assert len(metas) == 1, "expected exactly one CSP meta tag"
    directives = {}
    for part in metas[0].get("content", "").split(";"):
        words = part.split()
        if words:
            directives[words[0]] = words[1:]
    return directives


def _host(url: str) -> str:
    return urlsplit(url).hostname or ""


def test_the_page_set_is_not_empty():
    assert _PAGES, "found no tool pages: the glob is broken, not the pages"


@pytest.mark.parametrize("page", _PAGES)
def test_the_page_frames_its_counter_with_scripts_only(page: str):
    frames = _Tags((_STATIC / page / "index.html").read_text(encoding="utf-8")).named("iframe")
    assert [f.get("src") for f in frames] == ["count.html"], f"{page}: expected exactly one frame, count.html"
    assert frames[0].get("sandbox") == "allow-scripts", (
        f"{page}: the counter frame must be sandboxed with allow-scripts only"
    )
    assert (_STATIC / page / "count.html").is_file()


@pytest.mark.parametrize("page", _PAGES)
def test_the_page_csp_admits_no_beacon_and_frames_only_itself(page: str):
    html = (_STATIC / page / "index.html").read_text(encoding="utf-8")
    csp = _csp(html)
    assert csp.get("frame-src") == ["'self'"], f"{page}: frame-src must be exactly 'self'"
    for directive, sources in csp.items():
        for source in sources:
            assert _host(source) not in _BEACON_HOSTS, f"{page}: {directive} admits {source}"
    for script in _Tags(html).named("script"):
        assert _host(script.get("src", "")) not in _BEACON_HOSTS, f"{page} loads the beacon itself"


@pytest.mark.parametrize("page", _PAGES)
def test_the_counter_runs_only_the_beacon(page: str):
    html = (_STATIC / page / "count.html").read_text(encoding="utf-8")
    csp = _csp(html)
    assert csp.get("default-src") == ["'none'"]
    assert csp.get("script-src") == ["https://static.cloudflareinsights.com"]
    assert csp.get("connect-src") == ["https://cloudflareinsights.com"]
    scripts = _Tags(html).named("script")
    assert [s.get("src") for s in scripts] == ["https://static.cloudflareinsights.com/beacon.min.js"]
