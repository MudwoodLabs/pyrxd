"""The visit counter on each tool page stays walled off from the page it counts.

Every ``docs/inspect_static/*/index.html`` loads Cloudflare Web Analytics only through a frame of
``https://count.mudwoodlabs.com/<page>.html`` (source: ``tools/visit-counter/``). That is a different
origin, so the browser's same-origin policy keeps the third-party beacon from reading the page, its
inputs or its keys. The page's own CSP must not admit the beacon and may frame only that host. The
counter pages run only the beacon, and only github.io may frame them.

A same-site frame sandboxed to an opaque origin would also isolate the beacon, but Cloudflare refuses
beacons whose Origin is ``null`` (Web Analytics FAQ), which is why the counter is on its own host.
"""

from __future__ import annotations

import json
import re
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit

import pytest

_STATIC = Path(__file__).resolve().parents[2] / "docs" / "inspect_static"
_PAGES = sorted(p.parent.name for p in _STATIC.glob("*/index.html"))
_COUNTER = Path(__file__).resolve().parents[2] / "tools" / "visit-counter"
_COUNTER_HOST = "count.mudwoodlabs.com"
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
def test_the_page_frames_its_counter_from_the_counter_host(page: str):
    frames = _Tags((_STATIC / page / "index.html").read_text(encoding="utf-8")).named("iframe")
    assert [f.get("src") for f in frames] == [f"https://{_COUNTER_HOST}/{page}.html"], (
        f"{page}: expected exactly one frame, the counter on {_COUNTER_HOST}"
    )
    assert _host(frames[0]["src"]) != "mudwoodlabs.github.io", "a same-origin counter could read the page"
    assert set(frames[0].get("sandbox", "").split()) <= {"allow-scripts", "allow-same-origin"}, (
        f"{page}: the counter frame may run scripts and keep its own origin, nothing more"
    )
    assert (_COUNTER / f"{page}.html").is_file(), f"tools/visit-counter/ has no page for {page}"


@pytest.mark.parametrize("page", _PAGES)
def test_the_page_csp_admits_no_beacon_and_frames_only_the_counter(page: str):
    html = (_STATIC / page / "index.html").read_text(encoding="utf-8")
    csp = _csp(html)
    assert csp.get("frame-src") == [f"https://{_COUNTER_HOST}"], f"{page}: frame-src must be exactly the counter host"
    for directive, sources in csp.items():
        for source in sources:
            assert _host(source) not in _BEACON_HOSTS, f"{page}: {directive} admits {source}"
    for script in _Tags(html).named("script"):
        assert _host(script.get("src", "")) not in _BEACON_HOSTS, f"{page} loads the beacon itself"


@pytest.mark.parametrize("page", _PAGES)
def test_the_counter_page_runs_only_the_beacon(page: str):
    scripts = _Tags((_COUNTER / f"{page}.html").read_text(encoding="utf-8")).named("script")
    assert [s.get("src") for s in scripts] == ["https://static.cloudflareinsights.com/beacon.min.js"]


def test_the_counter_site_headers_allow_only_the_beacon_and_github_pages():
    lines = (_COUNTER / "_headers").read_text(encoding="utf-8").splitlines()
    assert lines[0] == "/*", "the headers must cover every counter page"
    csp_line = next(line for line in lines if line.strip().startswith("Content-Security-Policy:"))
    directives = {}
    for part in csp_line.split(":", 1)[1].split(";"):
        words = part.split()
        if words:
            directives[words[0]] = words[1:]
    assert directives.get("default-src") == ["'none'"]
    assert directives.get("script-src") == ["https://static.cloudflareinsights.com"]
    assert directives.get("connect-src") == ["https://cloudflareinsights.com"]
    assert directives.get("frame-ancestors") == ["https://mudwoodlabs.github.io"]


def test_every_counter_page_belongs_to_a_tool_page():
    counters = sorted(p.stem for p in _COUNTER.glob("*.html"))
    assert counters == _PAGES, "a counter page with no tool page, or the reverse"


@pytest.mark.parametrize("page", _PAGES)
def test_the_counter_page_carries_a_real_site_token(page: str):
    scripts = _Tags((_COUNTER / f"{page}.html").read_text(encoding="utf-8")).named("script")
    token = json.loads(scripts[0].get("data-cf-beacon", "{}")).get("token", "")
    assert re.fullmatch(r"[0-9a-f]{32}", token), f"{page}: the beacon token is {token!r}, not a site token"
