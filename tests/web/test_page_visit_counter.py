"""The visit counter on each tool page stays walled off from the page it counts.

Every ``docs/inspect_static/*/index.html`` loads Cloudflare Web Analytics only through its own
``count.html``, in a frame sandboxed with ``allow-scripts`` alone. That gives the frame an opaque
origin, so the third-party beacon cannot read the page, its inputs or its keys. The page's own CSP
must not admit the beacon, and it may frame nothing but itself.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_STATIC = Path(__file__).resolve().parents[2] / "docs" / "inspect_static"
_PAGES = sorted(p.parent.name for p in _STATIC.glob("*/index.html"))
_BEACON_HOSTS = ("static.cloudflareinsights.com", "cloudflareinsights.com")


def _csp(html: str) -> dict[str, list[str]]:
    match = re.search(r'http-equiv="Content-Security-Policy"\s+content="([^"]*)"', html)
    assert match, "no CSP meta tag"
    directives = {}
    for part in match.group(1).split(";"):
        words = part.split()
        if words:
            directives[words[0]] = words[1:]
    return directives


def _frames(html: str) -> list[dict[str, str]]:
    return [dict(re.findall(r'(\w[\w-]*)="([^"]*)"', tag)) for tag in re.findall(r"<iframe\b[^>]*>", html)]


def test_the_page_set_is_not_empty():
    assert _PAGES, "found no tool pages: the glob is broken, not the pages"


@pytest.mark.parametrize("page", _PAGES)
def test_the_page_frames_its_counter_with_scripts_only(page: str):
    frames = _frames((_STATIC / page / "index.html").read_text(encoding="utf-8"))
    assert [f.get("src") for f in frames] == ["count.html"], f"{page}: expected exactly one frame, count.html"
    assert frames[0].get("sandbox") == "allow-scripts", f"{page}: the counter frame must be sandboxed with allow-scripts only"
    assert (_STATIC / page / "count.html").is_file()


@pytest.mark.parametrize("page", _PAGES)
def test_the_page_csp_admits_no_beacon_and_frames_only_itself(page: str):
    html = (_STATIC / page / "index.html").read_text(encoding="utf-8")
    csp = _csp(html)
    assert csp.get("frame-src") == ["'self'"], f"{page}: frame-src must be exactly 'self'"
    for directive, sources in csp.items():
        for source in sources:
            host = re.sub(r"^[a-z]+://", "", source).split("/")[0].split(":")[0]
            assert host not in _BEACON_HOSTS, f"{page}: {directive} admits {source}"
    assert not re.search(r"<script\b[^>]*cloudflareinsights", html), f"{page} loads the beacon itself"


@pytest.mark.parametrize("page", _PAGES)
def test_the_counter_runs_only_the_beacon(page: str):
    html = (_STATIC / page / "count.html").read_text(encoding="utf-8")
    csp = _csp(html)
    assert csp.get("default-src") == ["'none'"]
    assert csp.get("script-src") == ["https://static.cloudflareinsights.com"]
    assert csp.get("connect-src") == ["https://cloudflareinsights.com"]
    scripts = re.findall(r"<script\b[^>]*>", html)
    assert len(scripts) == 1 and 'src="https://static.cloudflareinsights.com/beacon.min.js"' in scripts[0]
