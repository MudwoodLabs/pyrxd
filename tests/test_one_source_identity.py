"""ONE source identity, everywhere a source is counted: distinct operators, as declared, or by
registered domain.

THE DEFECT CLASS. Each quorum in pyrxd grew its own idea of "a different source": the watchtower's
RXD quorum folded case and a trailing slash, the Esplora helper only lower-cased the host, the ETH
quorum had no identity at all, HashMark §7.6 form 2's judge and walker compared raw label strings,
and only ``Endpoint.source`` canonicalised. So ``wss://h`` and ``wss://h:443`` were one source in one
place and two in another, and wherever the cheap identity was used, one server reached through two
spellings corroborated itself. In the watchtower that turned one server's "not locked" into a
corroborated absence that permits an autonomous refund.

THE FIX IS ONE FUNCTION, :func:`pyrxd.network.source_identity.source_key`, and these guards keep it
the only one:

(a) An AST scan fails on any ``.hostname`` read or ``.rstrip("/").lower()`` fold outside that module,
    and on any ``.lower()`` / ``.casefold()`` / ``urlsplit`` / ``urlparse`` INSIDE a counting site,
    except PINNED non-source uses (a connect key, a loopback test, an alert-channel compare, txids
    folded by the chain walker). The pins are exact in both directions, and a control proves the
    scanner sees each pattern at all.
(b) The counting sites are DERIVED from the code, across ``src/`` AND ``scripts/`` — every function
    with a ``quorum`` / ``threshold`` / ``min_agreeing`` / ``min_sources`` / ``corroborat*``
    parameter (or reading ``args.<such>``), and every function that CONSTRUCTS a class whose
    ``__init__`` has one. A short reviewed list adds the sites that count sources with neither (the
    form-2 judge and walker, ``swap_run_verify``'s ETH fetcher). Every site must have a planter here,
    and every planter a site: a new quorum fails this file until someone shows it counts one host
    once. Each planter feeds its site two spellings of ONE host and must count ONE source.
(c) The honest paths: two genuinely different hosts count as two at every site, and several URLs on
    one host still work as failover.
(d) The key is an OPERATOR GROUP, not a host, at every site: two subdomains of one registered
    domain and one shipped operator's two servers each count ONE; two registered domains under
    ``co.uk``, the three shipped operators and two IP addresses each count TWO.
(e) A DECLARED operator reaches only the counts it is handed to. The sites that take declarations
    are derived (an ``operators`` parameter) and pinned; there, two domains declared one operator
    count ONE and one domain declared two operators counts TWO. Every other site is run AFTER the
    same declaration was made on a profile in the same process, and must count by domain as though
    it had never been made — the leak a process-wide registry had.

What the key does not claim — that a group is an independent operator — is stated once, in
:mod:`pyrxd.network.source_identity`.
"""

from __future__ import annotations

import ast
import contextlib
import functools
import pathlib
import re
import sys
from collections.abc import Callable

import pytest

from pyrxd.network.source_identity import SameSourceFailover, SourceKey, group_by_source, source_key, source_key_of
from pyrxd.security.errors import NetworkError, ValidationError

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_SRC = _ROOT / "src" / "pyrxd"
_SCRIPTS = _ROOT / "scripts"
_IDENTITY_MODULE = _SRC / "network" / "source_identity.py"

# Two spellings of ONE host: the default port written out, and a trailing dot.
ONE_HOST_PAIRS = [
    ("wss://h.example", "wss://h.example:443"),
    ("wss://h.example", "wss://h.example."),
    ("wss://[2001:db8::7]", "wss://[2001:db8:0:0:0:0:0:7]:443"),
]
TWO_HOSTS = ("wss://a.example", "wss://b.example")


def _https(url: str) -> str:
    return "https://" + url.split("://", 1)[1]


# ══════════════════════════════════════════════════════════════════════════════
# The identity itself
# ══════════════════════════════════════════════════════════════════════════════


@pytest.mark.parametrize(
    "spellings",
    [
        [
            "wss://h.example",
            "wss://h.example:443",
            "wss://h.example/x",
            "wss://H.EXAMPLE.",
            "wss://u@h.example:50022/?q",
        ],
        ["https://mempool.space/api", "https://mempool.space./api", "mempool.space", "https://mempool.space:443/x"],
        ["http://127.0.0.1:8545", "http://2130706433", "http://0x7f.0.0.1/", "127.0.0.1:1"],
        ["wss://[2001:db8::7]/", "wss://[2001:db8:0:0:0:0:0:7]:443/"],
        [
            "2001:db8::1",  # bare, as an ssh destination is written
            "2001:DB8:0:0:0:0:0:1",  # expanded, upper case
            "user@2001:db8::1",  # ssh user@host
            "[2001:db8::1]",
            "[2001:db8::1]:50022",
            "wss://[2001:db8::1]:50022",
            "wss://[2001:db8:0::1]/x",
            "2001:db8::1/path",
        ],
        [
            "fe80::1%eth0",  # bare, with a zone id
            "fe80:0:0:0:0:0:0:1%eth0",
            "[fe80::1%eth0]",
            "[fe80::1%25eth0]:50022",  # RFC 6874: the zone delimiter percent-encoded in a URL
            "wss://[fe80::1%25eth0]:50022/",
        ],
        ["::ffff:203.0.113.7", "[::ffff:203.0.113.7]:1", "203.0.113.7"],
    ],
    ids=[
        "port-path-case-dot-userinfo",
        "esplora",
        "ipv4-spellings",
        "ipv6-spellings",
        "bare-ipv6",
        "ipv6-zone",
        "ipv4-mapped-bare",
    ],
)
def test_every_spelling_of_one_host_is_one_key(spellings) -> None:
    keys = {source_key(s) for s in spellings}
    assert len(keys) == 1, keys
    assert all(isinstance(source_key(s), SourceKey) for s in spellings)


def test_distinct_hosts_stay_distinct() -> None:
    """The honest half. A name and its IP address are two hosts here: the URL cannot show otherwise,
    and folding them would be a claim nobody checked. (Loopback is the one exception, because
    ``localhost`` and ``127.0.0.1`` are this machine by definition: see
    ``test_source_operator_groups.py``.)"""
    assert source_key("wss://a.example") != source_key("wss://b.example")
    assert source_key("http://node.example:8545") != source_key("http://203.0.113.7:8545")
    assert source_key("https://eth.drpc.org") != source_key("https://rpc.mevblocker.io")


@pytest.mark.parametrize(
    ("a", "b"),
    [
        ("2001:db8::1", "2001:db9::2"),  # both used to key as "0.0.7.209"
        ("2001:db8::1", "2001:db8::2"),
        ("2001:db8::1", "[2001:db8::2]:50022"),
        ("fe80::1%eth0", "fe80::1%eth1"),  # one address on two interfaces
        ("fe80::1%eth0", "fe80::1"),
        ("2001:db8::1", "0.0.7.209"),  # what the bare literal used to be misread as
        ("2001:db8::1", "2001"),
    ],
)
def test_distinct_ipv6_hosts_stay_distinct(a, b) -> None:
    """The honest half of the bare-IPv6 fix. Before it, ``urlsplit`` read an unbracketed IPv6
    literal as ``host:port`` and every bare ``2001:...`` address became the one key ``0.0.7.209``,
    so two machines were refused as one."""
    assert source_key(a) != source_key(b)


async def test_an_ssh_node_and_a_wss_url_on_one_ipv6_machine_are_ONE_source(monkeypatch) -> None:
    """The fail-open the bare-IPv6 fix closes, through the watchtower's real builder: the node
    reached over ssh at ``2001:db8::1`` and an ElectrumX server at ``wss://[2001:db8::1]:50022``
    are one machine. The ssh destination used to key as ``0.0.7.209``, so the quorum accepted
    them as two sources, and one machine's "not locked" was a corroborated absence."""
    from pyrxd.gravity.watch import run

    mp = monkeypatch
    mp.setattr(run, "ElectrumXClient", _NoConnectElectrumX)

    async def build(ssh_host: str, url: str):
        argv = ["--records-dir", "/nonexistent", "--rxd-include-node", "--ssh-container", "radiant"]
        args = run._parse_args([*argv, "--ssh-host", ssh_host, "--rxd-electrumx-url", url])
        async with contextlib.AsyncExitStack() as stack:
            return await run._build_rxd_source(args, stack)

    for ssh_host in ("2001:db8::1", "user@2001:db8:0:0:0:0:0:1"):
        with pytest.raises(ValidationError, match="same source"):
            await build(ssh_host, "wss://[2001:db8::1]:50022")
    # The honest path: the node on a DIFFERENT v6 machine is a second source.
    src, corroborated = await build("2001:db9::2", "wss://[2001:db8::1]:50022")
    assert corroborated is True and _count_rxd(src) == 2


def test_an_empty_url_is_not_a_source() -> None:
    for blank in ("", "   "):
        with pytest.raises(ValidationError):
            source_key(blank)


def test_a_quorum_refuses_a_client_that_cannot_name_its_host() -> None:
    """A caller-typed label is not a key: only `source_key` makes a SourceKey."""

    class _Labelled:
        source_key = "a"  # a plain str, as a caller might type it

    with pytest.raises(ValidationError, match="does not say which source"):
        source_key_of(_Labelled())
    with pytest.raises(ValidationError, match="does not say which source"):
        source_key_of(object())


# ══════════════════════════════════════════════════════════════════════════════
# The counting sites — DERIVED from the code (used by both guards below)
# ══════════════════════════════════════════════════════════════════════════════

#: A parameter (or an `args.<name>` a CLI builder reads) with one of these in its name makes a
#: function a counting site: a quorum size, an agreement threshold, a minimum source count, or
#: a corroborator.
_COUNTING_PARAM = re.compile(r"quorum|threshold|min_agreeing|min_sources|corroborat")

#: Sites that count sources with no such parameter and construct no quorum class, so the
#: derivation cannot find them. REVIEWED, not derived; each must still have a planter, so a
#: deleted or renamed one fails the orphan check. HashMark §7.6 form 2 compares source labels
#: inside the first two; `swap_run_verify`'s ETH fetcher de-duplicates its RPC URLs by host.
_UNDERIVED_SITES = frozenset(
    {
        "pyrxd.glyph.wave_identity:judge_name_at_mark",
        "pyrxd.glyph.mutable_chain:walk_mutable_chain",
        "scripts.swap_run_verify:_MultiEthFetcher.__init__",
    }
)

#: Derived sites whose counting-named parameter is not a count of SOURCES. REVIEWED, and pinned
#: in both directions: each must still be derived (or the entry is stale and must go).
_NOT_COUNTING_SITES: dict[str, str] = {
    "pyrxd.script.type:BareMultisig.lock": "`threshold` is the m of an m-of-n multisig: signatures, not sources",
}


@functools.cache
def _py_files() -> tuple[tuple[pathlib.Path, str, ast.Module], ...]:
    """Every shipped .py file under src/ and scripts/: its path, dotted module name, and AST."""
    out = []
    for base in (_SRC, _SCRIPTS):
        for path in sorted(base.rglob("*.py")):
            module = ".".join(path.relative_to(base.parent).with_suffix("").parts)
            out.append((path, module, ast.parse(path.read_text(), filename=str(path))))
    return tuple(out)


def _functions(tree: ast.AST):
    """`(qualname, class_name_or_None, node)` for every function in *tree*, nested ones included."""

    def visit(node: ast.AST, prefix: str, cls: str | None):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.ClassDef):
                yield from visit(child, f"{prefix}{child.name}.", child.name)
            elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                yield f"{prefix}{child.name}", cls, child
                yield from visit(child, f"{prefix}{child.name}.<locals>.", None)

    yield from visit(tree, "", None)


def _has_counting_param(fn: ast.AST) -> bool:
    a = fn.args
    names = [x.arg for x in (*a.posonlyargs, *a.args, *a.kwonlyargs)]
    if any(_COUNTING_PARAM.search(n) for n in names):
        return True
    return "args" in names and any(  # a CLI builder reading `args.rxd_quorum`
        isinstance(n, ast.Attribute)
        and isinstance(n.value, ast.Name)
        and n.value.id == "args"
        and _COUNTING_PARAM.search(n.attr)
        for n in ast.walk(fn)
    )


def _constructs(fn: ast.AST, classes: set[str]) -> bool:
    """Whether *fn* builds one of *classes*: `C(...)` or a constructor classmethod `C.x(...)`."""
    for n in ast.walk(fn):
        if not isinstance(n, ast.Call):
            continue
        f = n.func
        if isinstance(f, ast.Name) and f.id in classes:
            return True
        if isinstance(f, ast.Attribute) and (
            f.attr in classes or (isinstance(f.value, ast.Name) and f.value.id in classes)
        ):
            return True
    return False


def _derive() -> dict[str, ast.AST]:
    """`{"module:qualname": function node}` for every counting site under src/ and scripts/.

    A site is a function with a counting-named parameter, or one that CONSTRUCTS a quorum class —
    a class whose ``__init__`` has such a parameter. The class set is derived too, so a new quorum
    class makes every builder of it a site without anyone listing it.
    """
    parsed = [(module, tree) for _path, module, tree in _py_files()]
    by_param: dict[str, ast.AST] = {}
    quorum_classes: set[str] = set()
    for module, tree in parsed:
        for qual, cls, fn in _functions(tree):
            if _has_counting_param(fn):
                by_param[f"{module}:{qual}"] = fn
                if cls is not None and fn.name == "__init__":
                    quorum_classes.add(cls)
    sites = dict(by_param)
    for module, tree in parsed:
        for qual, _cls, fn in _functions(tree):
            if _constructs(fn, quorum_classes):
                sites.setdefault(f"{module}:{qual}", fn)
    return sites


def _all_sites() -> dict[str, ast.AST]:
    """Derived sites plus the reviewed underived ones, minus the reviewed non-counting ones."""
    derived = _derive()
    everything = {f"{module}:{qual}": fn for _path, module, tree in _py_files() for qual, _cls, fn in _functions(tree)}
    sites = {k: v for k, v in derived.items() if k not in _NOT_COUNTING_SITES}
    for site in _UNDERIVED_SITES:
        if site in everything:
            sites[site] = everything[site]
    return sites


def test_the_reviewed_site_lists_are_not_stale() -> None:
    derived = _derive()
    stale = set(_NOT_COUNTING_SITES) - set(derived)
    assert not stale, f"non-counting exemptions that are no longer derived; delete them: {stale}"
    already = _UNDERIVED_SITES & set(derived)
    assert not already, f"reviewed sites the derivation now finds itself; delete them from the list: {already}"


# ══════════════════════════════════════════════════════════════════════════════
# (a) No second identity: the AST scan
# ══════════════════════════════════════════════════════════════════════════════

#: Uses that look like a hand-built host/URL identity but are NOT source identity, each with its
#: reason. REVIEWED, not derived — and pinned: the scan must find exactly these, so adding one
#: forces a reviewer to read this list, and removing one forces the entry out.
_NOT_SOURCE_IDENTITY: dict[tuple[str, str], str] = {
    ("src/pyrxd/network/registry.py", "Endpoint.key"): (
        "the CONNECT identity (keeps port, path and query) used to de-duplicate a profile's endpoints; "
        "its host part is canonical_host, and source counting uses Endpoint.source -> source_key"
    ),
    ("src/pyrxd/network/registry.py", "_is_loopback_url"): (
        "decides whether an endpoint is this machine's loopback interface, not which source it is"
    ),
    ("src/pyrxd/gravity/watch/escalation.py", "_normalize_url"): (
        "compares two ALERT CHANNELS for equality, where a different path (an ntfy topic) IS a "
        "different channel; nothing is counted as a source"
    ),
    ("src/pyrxd/cli/swap_recovery.py", "endpoint_source_label"): (
        "a DISPLAY label naming the one server an answer came from; nothing is counted. It uses "
        "canonical_host but not source_key on purpose: source_key keys an unparseable URL by its "
        "whole text, and printing that could print an API key carried in an RPC URL"
    ),
    ("src/pyrxd/network/redaction.py", "redacted_url"): (
        "a DISPLAY form (scheme://host:port) for naming an endpoint in a message without its "
        "credentials; nothing is counted, and it must keep the port the operator typed"
    ),
}

#: Inside a counting site, any of these is the site building its own identity: case-folding text,
#: or parsing a URL itself instead of asking `source_key`.
_FOLDS_IN_A_SITE = frozenset({"lower", "casefold", "urlsplit", "urlparse"})

#: Folds inside a counting site that fold something OTHER than a source, pinned to the exact
#: expression folded — so a new `.lower()` in the same function, on anything else, still fails.
#: REVIEWED, not derived, and exact in both directions.
_NOT_SOURCE_FOLDS: dict[str, frozenset[tuple[str, str]]] = {
    # The chain walker lower-cases TXIDS (hex) to compare them; its two source labels are compared
    # through `_one_source`, i.e. `source_key`.
    "pyrxd.glyph.mutable_chain:walk_mutable_chain": frozenset(
        {
            ("lower", "t"),
            ("lower", "mint_txid"),
            ("lower", "txid"),
            ("lower", "cur_txid"),
            ("lower", "str(getattr(i, 'source_txid', ''))"),
        }
    ),
}


def _is_rstrip_slash(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "rstrip"
        and len(node.args) == 1
        and isinstance(node.args[0], ast.Constant)
        and node.args[0].value == "/"
    )


def _identity_folds(tree: ast.AST) -> list[tuple[str, str]]:
    """Every `(qualname, kind)` in *tree* that builds a host/URL identity by hand, anywhere."""
    found: list[tuple[str, str]] = []

    def visit(node: ast.AST, qual: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                visit(child, f"{qual}.{child.name}" if qual else child.name)
                continue
            # `<anything>.hostname`: in this codebase every `.hostname` is a parsed URL's; the
            # direct `urlsplit(u).hostname` form is the obvious one, the variable form
            # (`parts = urlsplit(u); parts.hostname`) is the same thing one line later.
            if isinstance(child, ast.Attribute) and child.attr == "hostname":
                found.append((qual or "<module>", "hostname"))
            # `x.rstrip("/").lower()` and `x.lower().rstrip("/")`
            if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute):
                inner = child.func.value
                if child.func.attr == "lower" and _is_rstrip_slash(inner):
                    found.append((qual or "<module>", "rstrip-lower"))
                if (
                    _is_rstrip_slash(child)
                    and isinstance(inner, ast.Call)
                    and isinstance(inner.func, ast.Attribute)
                    and inner.func.attr == "lower"
                ):
                    found.append((qual or "<module>", "rstrip-lower"))
            visit(child, qual)

    visit(tree, "")
    return found


def _folds_in_site(fn: ast.AST) -> set[tuple[str, str]]:
    """`(call, what it folds)` for each `.lower()` / `.casefold()` / `urlsplit` / `urlparse` inside
    one counting site (nested functions and lambdas included). A bare `.lower()` is everywhere in
    this codebase — hex, network names — so it is only flagged where sources are being counted."""
    folds = set()
    for n in ast.walk(fn):
        if not isinstance(n, ast.Call):
            continue
        if isinstance(n.func, ast.Attribute) and n.func.attr in _FOLDS_IN_A_SITE:
            folds.add((n.func.attr, ast.unparse(n.func.value)))
        elif isinstance(n.func, ast.Name) and n.func.id in _FOLDS_IN_A_SITE:
            folds.add((n.func.id, ", ".join(ast.unparse(a) for a in n.args)))
    return folds


def _scan() -> dict[tuple[str, str], set[str]]:
    hits: dict[tuple[str, str], set[str]] = {}
    for path, _module, tree in _py_files():
        if path == _IDENTITY_MODULE:
            continue
        rel = str(path.relative_to(_ROOT))
        for qual, kind in _identity_folds(tree):
            hits.setdefault((rel, qual), set()).add(kind)
    return hits


def test_no_second_source_identity_exists() -> None:
    hits = _scan()
    unexpected = {k: v for k, v in hits.items() if k not in _NOT_SOURCE_IDENTITY}
    assert not unexpected, (
        "a host/URL identity is built by hand outside pyrxd.network.source_identity — count sources "
        f"through source_key() instead, or (if it is not source identity) add it to the reviewed list: {unexpected}"
    )
    stale = set(_NOT_SOURCE_IDENTITY) - set(hits)
    assert not stale, f"reviewed exemptions no longer match any code; delete them: {stale}"


def test_no_counting_site_folds_its_own_keys() -> None:
    """A site that counts sources must take its keys from `source_key`, never make them: `{u.lower()
    for u in urls}` counts `wss://h` and `wss://h:443` as two hosts."""
    sites = _all_sites()
    folding = {
        site: folds
        for site, fn in sites.items()
        if (folds := _folds_in_site(fn) - _NOT_SOURCE_FOLDS.get(site, frozenset()))
    }
    assert not folding, f"a counting site builds its own host identity; key it through source_key(): {folding}"
    stale = {
        site: pinned - _folds_in_site(sites[site]) if site in sites else pinned
        for site, pinned in _NOT_SOURCE_FOLDS.items()
    }
    stale = {k: v for k, v in stale.items() if v}
    assert not stale, f"reviewed non-source folds that no longer exist; delete them: {stale}"


def test_the_scan_can_see_the_pattern_it_forbids() -> None:
    """Non-vacuity, with cases whose answer is known. Each forbidden shape must be flagged in a
    snippet, and the pinned non-source uses must actually be found in the tree. A scan that finds
    nothing anywhere would pass the tests above for the wrong reason."""
    for snippet, kind in (
        ("def f(u):\n    return u.rstrip('/').lower()\n", "rstrip-lower"),
        ("def f(u):\n    return u.lower().rstrip('/')\n", "rstrip-lower"),
        ("from urllib.parse import urlsplit\ndef f(u):\n    return urlsplit(u).hostname\n", "hostname"),
        ("from urllib.parse import urlparse\ndef f(u):\n    p = urlparse(u)\n    return p.hostname\n", "hostname"),
    ):
        assert ("f", kind) in _identity_folds(ast.parse(snippet)), snippet
    for snippet, kind in (
        ("def f(urls):\n    return len({u.lower() for u in urls})\n", ("lower", "u")),
        ("def f(urls):\n    return len(set(map(lambda u: u.casefold(), urls)))\n", ("casefold", "u")),
        (
            "from urllib.parse import urlsplit\ndef f(urls):\n    return {urlsplit(u).netloc for u in urls}\n",
            ("urlsplit", "u"),
        ),
    ):
        assert kind in _folds_in_site(ast.parse(snippet).body[-1]), snippet
    assert len(_scan()) >= len(_NOT_SOURCE_IDENTITY) > 0


# ══════════════════════════════════════════════════════════════════════════════
# (b) Every counting site counts one host once
# ══════════════════════════════════════════════════════════════════════════════


# ---- planters: build the site from two URLs, return how many SOURCES it counted ----------------
# A refusal naming "the same source" is the site declining to count one source twice: it returns 1.
# Any other exception propagates, so a planter cannot pass by failing for an unrelated reason —
# and the honest-path test runs the SAME planter and must see 2.


def _refused_as_one_host(fn: Callable[[], int]) -> int:
    try:
        return fn()
    except ValidationError as exc:
        if "same source" not in str(exc):
            raise
        return 1


def _plant_btc_data_source(a: str, b: str, _mp) -> int:
    from pyrxd.network.bitcoin import MempoolSpaceSource, MultiSourceBtcDataSource

    def build() -> int:
        multi = MultiSourceBtcDataSource([MempoolSpaceSource(_https(a)), MempoolSpaceSource(_https(b))], quorum=1)
        return len(multi._sources)

    return _refused_as_one_host(build)


def _plant_funding_reader_init(a: str, b: str, _mp) -> int:
    from pyrxd.network.bitcoin import MempoolSpaceFundingReader, MultiSourceBtcFundingReader

    def build() -> int:
        readers = [MempoolSpaceFundingReader(base_url=_https(a)), MempoolSpaceFundingReader(base_url=_https(b))]
        return len(MultiSourceBtcFundingReader(readers, quorum=1)._readers)

    return _refused_as_one_host(build)


def _plant_from_endpoints(a: str, b: str, _mp) -> int:
    from pyrxd.network.bitcoin import MultiSourceBtcFundingReader

    return len(MultiSourceBtcFundingReader.from_endpoints([_https(a), _https(b)], quorum=1)._readers)


def _plant_default_mainnet(a: str, b: str, mp) -> int:
    from pyrxd.network.bitcoin import MultiSourceBtcFundingReader

    mp.setattr(MultiSourceBtcFundingReader, "DEFAULT_MAINNET_ENDPOINTS", (_https(a), _https(b)))
    return len(MultiSourceBtcFundingReader.default_mainnet(quorum=1)._readers)


def _rxd_clients(a: str, b: str):
    from pyrxd.gravity.watch.adapters import ElectrumRxdChainSource
    from pyrxd.network.electrumx import ElectrumXClient

    return [ElectrumRxdChainSource(ElectrumXClient([a])), ElectrumRxdChainSource(ElectrumXClient([b]))]


def _plant_rxd_quorum(a: str, b: str, _mp) -> int:
    from pyrxd.gravity.watch.adapters import MultiSourceRxdChainSource

    return _refused_as_one_host(lambda: len(MultiSourceRxdChainSource(_rxd_clients(a, b), quorum=1)._sources))


def _plant_eth_quorum(a: str, b: str, _mp) -> int:
    pytest.importorskip("web3")
    from pyrxd.eth_wallet.multi_rpc import MultiSourceEthRpc
    from pyrxd.eth_wallet.rpc import EthRpc

    def build() -> int:
        rpcs = [EthRpc(_https(a), expected_chain_id=1), EthRpc(_https(b), expected_chain_id=1)]
        return len(MultiSourceEthRpc(rpcs, min_agreeing=2).sources)

    return _refused_as_one_host(build)


def _plant_build_funding_reader(a: str, b: str, _mp) -> int:
    from pyrxd.gravity.watch import run

    return len(run._build_funding_reader("tb", [_https(a), _https(b)], 1)._readers)


class _NoConnectElectrumX:
    """The REAL ElectrumXClient constructor (so its real `source_key` rule), minus the socket."""

    def __new__(cls, urls, **kw):
        from pyrxd.network.electrumx import ElectrumXClient

        class _Client(ElectrumXClient):
            async def __aenter__(self):
                return self

            async def __aexit__(self, *_exc):
                return False

        return _Client(urls, **kw)


async def _rxd_source_from_run(a: str, b: str, mp):
    from pyrxd.gravity.watch import run

    mp.setattr(run, "ElectrumXClient", _NoConnectElectrumX)
    # --accept-single-source: this harness measures how many sources the builder COUNTS, and a pair
    # that is one source would otherwise be refused as below the default --rxd-quorum 2.
    args = run._parse_args(
        ["--records-dir", "/nonexistent", "--rxd-electrumx-url", a, "--rxd-electrumx-url", b, "--accept-single-source"]
    )
    async with contextlib.AsyncExitStack() as stack:
        return await run._build_rxd_source(args, stack)


def _count_rxd(src) -> int:
    from pyrxd.gravity.watch.adapters import MultiSourceRxdChainSource

    return len(src._sources) if isinstance(src, MultiSourceRxdChainSource) else 1


async def _plant_build_rxd_source(a: str, b: str, mp) -> int:
    src, corroborated = await _rxd_source_from_run(a, b, mp)
    count = _count_rxd(src)
    assert corroborated is (count >= 2), (count, corroborated)
    return count


async def _plant_chain_observer(a: str, b: str, mp) -> int:
    from pyrxd.gravity.watch.quorum import ChainObserver

    src, corroborated = await _rxd_source_from_run(a, b, mp)
    # Asserting corroboration over what the builder produced is refused unless it is a real quorum.
    try:
        ChainObserver(rxd=src, btc=object(), rxd_corroborated=True)  # type: ignore[arg-type]
    except ValidationError as exc:
        assert "requires a multi-source RXD quorum" in str(exc)
        assert corroborated is False
        return 1
    return _count_rxd(src)


async def _plant_build_reconciler(a: str, b: str, mp) -> int:
    from pyrxd.gravity.swap_coordinator import MarginPolicy
    from pyrxd.gravity.watch import run
    from pyrxd.gravity.watch.adapters import LoggingAlertChannel
    from pyrxd.network.bitcoin import MultiSourceBtcFundingReader

    src, corroborated = await _rxd_source_from_run(a, b, mp)
    reconciler = run.build_reconciler(
        records_dir="/nonexistent-records",  # read only when a tick runs
        rxd_source=src,
        rxd_corroborated=corroborated,
        btc_funding_reader=MultiSourceBtcFundingReader.from_endpoints(["https://x.test", "https://y.test"]),
        http_session=None,  # type: ignore[arg-type]  # only used when a tick runs
        mempool_base_urls=["https://x.test"],
        policy=MarginPolicy.estimated(),
        safety_window_blocks=6,
        alert_channel=LoggingAlertChannel(),
    )
    return 2 if reconciler._observer._rxd_corroborated else 1


async def _plant_claim_executor(a: str, b: str, mp) -> int:
    """The corroborator comes from the watchtower's REAL builder (`_build_rxd_source`, the only
    code that turns a URL list into an RXD quorum), not from a quorum this test assembles, and
    goes into the real `ClaimExecutor` constructor. `ClaimExecutor` keys nothing itself: it reads
    depth from whatever corroborator it is handed. And nothing in production constructs it yet
    (see gravity/watch/README.md), so this is the path it would be wired through."""
    from pyrxd.gravity.swap_coordinator import MarginPolicy
    from pyrxd.gravity.watch.claim_executor import ClaimExecutor

    src, _corroborated = await _rxd_source_from_run(a, b, mp)
    ex = ClaimExecutor(
        resolve_leg=None,
        claim_status_source=None,
        claim_bytes_source=None,
        policy=MarginPolicy.estimated(),
        network="bcrt",
        rxd_depth_corroborator=src,
    )
    return _count_rxd(ex._rxd_depth_corroborator)


_SCRIPT_MODULES: dict[str, object] = {}


def _script(name: str):
    """Load `scripts/<name>.py` the way the scripts' own tests do, once per session."""
    if name not in _SCRIPT_MODULES:
        import importlib.util

        spec = importlib.util.spec_from_file_location(f"{name}_under_identity_test", _SCRIPTS / f"{name}.py")
        mod = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = mod  # a dataclass in the script looks its module up by name
        spec.loader.exec_module(mod)
        _SCRIPT_MODULES[name] = mod
    return _SCRIPT_MODULES[name]


def _plant_eth_swap_run_rpc(a: str, b: str, _mp) -> int:
    """`eth_swap_run.py --eth-rpc-url a,b`: the runner's real factory, which refuses a repeated host."""
    pytest.importorskip("web3")
    runner = _script("eth_swap_run")
    saved = sys.argv
    try:
        sys.argv = ["eth_swap_run.py", "--stage", "dry-run", "--counter-asset", "native", "--eth-chain-id", "1"]
        args = runner._args()
    finally:
        sys.argv = saved
    try:
        rpc = runner._eth_rpc(args, rpc_url=f"{_https(a)},{_https(b)}", chain_id=1)
    except SystemExit as exc:
        assert "names one source" in str(exc), exc
        return 1
    return len(rpc.sources)


def _plant_verify_eth_fetcher(a: str, b: str, _mp) -> int:
    """`swap_run_verify.py`'s ETH cross-check, which collapses same-host RPC URLs to one."""
    pytest.importorskip("web3")
    return _script("swap_run_verify")._MultiEthFetcher([_https(a), _https(b)], 1).source_count


async def _plant_judge(a: str, b: str, _mp, operators=None) -> int:
    from pyrxd.glyph.wave_identity import HeightReport, judge_name_at_mark
    from tests.test_wave_identity_form2 import _HEIGHTS, NAME, _anchor, _walk

    walk = await _walk()
    anchor = _anchor(458605, source=a)
    reports = [HeightReport(source=s, mark_height=anchor.height, step_heights=_HEIGHTS) for s in (a, b)]
    verdict = judge_name_at_mark(
        ref=walk.ref,
        name=NAME,
        binding_source="index-B",
        anchor=anchor,
        walk=walk,
        height_reports=reports,
        operators=operators,
    )
    if verdict.form == 2:
        return len(verdict.height_sources)
    assert "every block height came from" in verdict.degraded_reason, verdict.degraded_reason
    return 1


async def _plant_walker(a: str, b: str, _mp, operators=None) -> int:
    from pyrxd.glyph.mutable_chain import walk_mutable_chain
    from tests.test_wave_identity_form2 import _RAW, MINT, _fetch, _unspent

    walk = await walk_mutable_chain(
        mint_txid=MINT,
        candidates=list(_RAW),
        fetch_tx=_fetch,
        is_unspent=_unspent,
        candidate_source=a,
        tip_source=b,
        operators=operators,
    )
    if walk.complete:
        return 2
    assert "came from the same source" in walk.reason, walk.reason
    return 1


PLANTERS: dict[str, Callable] = {
    "pyrxd.network.bitcoin:MultiSourceBtcDataSource.__init__": _plant_btc_data_source,
    "pyrxd.network.bitcoin:MultiSourceBtcFundingReader.__init__": _plant_funding_reader_init,
    "pyrxd.network.bitcoin:MultiSourceBtcFundingReader.from_endpoints": _plant_from_endpoints,
    "pyrxd.network.bitcoin:MultiSourceBtcFundingReader.default_mainnet": _plant_default_mainnet,
    "pyrxd.gravity.watch.adapters:MultiSourceRxdChainSource.__init__": _plant_rxd_quorum,
    "pyrxd.eth_wallet.multi_rpc:MultiSourceEthRpc.__init__": _plant_eth_quorum,
    "pyrxd.gravity.watch.run:_build_funding_reader": _plant_build_funding_reader,
    "pyrxd.gravity.watch.run:_build_rxd_source": _plant_build_rxd_source,
    "pyrxd.gravity.watch.run:build_reconciler": _plant_build_reconciler,
    "pyrxd.gravity.watch.quorum:ChainObserver.__init__": _plant_chain_observer,
    "pyrxd.gravity.watch.claim_executor:ClaimExecutor.__init__": _plant_claim_executor,
    "pyrxd.glyph.wave_identity:judge_name_at_mark": _plant_judge,
    "pyrxd.glyph.mutable_chain:walk_mutable_chain": _plant_walker,
    "scripts.eth_swap_run:_eth_rpc": _plant_eth_swap_run_rpc,
    "scripts.swap_run_verify:_MultiEthFetcher.__init__": _plant_verify_eth_fetcher,
}


def test_every_counting_site_has_a_planter_and_every_planter_a_site() -> None:
    sites = _all_sites()
    # NON-VACUITY, one known site per rule: a counting parameter (`quorum`, `min_agreeing`,
    # `rxd_depth_corroborator`), an `args.<quorum>` read, and a builder in scripts/ found only
    # because it CONSTRUCTS a quorum class. If the derivation ever returns nothing, the
    # parametrised tests below would run over the hand-kept dict alone and prove nothing new.
    assert {
        "pyrxd.gravity.watch.adapters:MultiSourceRxdChainSource.__init__",
        "pyrxd.eth_wallet.multi_rpc:MultiSourceEthRpc.__init__",
        "pyrxd.gravity.watch.claim_executor:ClaimExecutor.__init__",
        "pyrxd.gravity.watch.run:_build_rxd_source",
        "scripts.eth_swap_run:_eth_rpc",
    } <= set(sites), sorted(sites)
    expected = set(sites)
    missing = expected - set(PLANTERS)
    assert not missing, f"a source-counting site has no one-host plant: {sorted(missing)}"
    orphans = set(PLANTERS) - expected
    assert not orphans, f"planters for sites that no longer exist (or no longer count): {sorted(orphans)}"


async def _run(planter: Callable, a: str, b: str, mp, operators=None) -> int:
    result = planter(a, b, mp) if operators is None else planter(a, b, mp, operators=operators)
    if hasattr(result, "__await__"):
        result = await result
    return result


@pytest.mark.parametrize(("a", "b"), ONE_HOST_PAIRS, ids=["default-port", "trailing-dot", "ipv6-spelling"])
@pytest.mark.parametrize("site", sorted(PLANTERS))
async def test_one_host_counts_as_ONE_source_at_every_site(site, a, b, monkeypatch) -> None:
    assert await _run(PLANTERS[site], a, b, monkeypatch) == 1, site


@pytest.mark.parametrize("site", sorted(PLANTERS))
async def test_two_distinct_hosts_still_count_as_TWO_at_every_site(site, monkeypatch) -> None:
    """(c) The honest path. A guard that refuses two different hosts would refuse valid work."""
    assert await _run(PLANTERS[site], *TWO_HOSTS, monkeypatch) == 2, site


# ---- (d) ...and every site counts OPERATOR GROUPS, not hosts --------------------------------------
# Distinct operators, by registered domain or an operator pyrxd ships (`source_key`). The same
# planters, fed two HOSTS of one group — which #801's host identity counted as two.

#: Two hosts, ONE group: subdomains of one registered domain (nothing shipped — the Public Suffix
#: List alone), and one shipped operator's two servers.
ONE_GROUP_CASES = {
    "subdomains-of-one-registered-domain": ("wss://x.pool.example.org", "wss://y.pool.example.org"),
    "subdomains-under-a-multi-label-suffix": ("wss://a.one.co.uk", "wss://b.one.co.uk"),
    "shipped-operator-two-servers": (
        "wss://electrumx.radiant4people.com:50022",
        "wss://electrumx2.radiant4people.com:50022",
    ),
}

#: Two hosts, TWO groups: the honest paths the grouping must not collapse.
TWO_GROUP_CASES = {
    "two-registered-domains-under-co.uk": ("wss://a.co.uk", "wss://b.co.uk"),
    "shipped-operators-radiantcore-radiant4people": (
        "wss://electrumx.radiantcore.org",
        "wss://electrumx.radiant4people.com:50022",
    ),
    "shipped-operators-radiantcore-bladenet": (
        "wss://electrumx.radiantcore.org",
        "wss://radiant2.bladenet.online:50022",
    ),
    "shipped-operators-radiant4people-bladenet": (
        "wss://electrumx2.radiant4people.com:50022",
        "wss://radiant4.bladenet.online:50022",
    ),
    "two-ip-addresses-in-one-slash-24": ("wss://203.0.113.7", "wss://203.0.113.8"),
}


@pytest.mark.parametrize("case", sorted(ONE_GROUP_CASES))
@pytest.mark.parametrize("site", sorted(PLANTERS))
async def test_one_operator_group_counts_as_ONE_source_at_every_site(site, case, monkeypatch) -> None:
    assert await _run(PLANTERS[site], *ONE_GROUP_CASES[case], monkeypatch) == 1, (site, case)


@pytest.mark.parametrize("case", sorted(TWO_GROUP_CASES))
@pytest.mark.parametrize("site", sorted(PLANTERS))
async def test_two_operator_groups_count_as_TWO_at_every_site(site, case, monkeypatch) -> None:
    """The honest half of (d): three operators are three, ``a.co.uk``/``b.co.uk`` are two. A
    grouping that refused these would refuse valid work."""
    assert await _run(PLANTERS[site], *TWO_GROUP_CASES[case], monkeypatch) == 2, (site, case)


def test_the_group_cases_are_what_they_claim() -> None:
    """The fixtures above are only evidence if they are the shapes named: each ONE case is two
    different HOSTS (so #801's host identity would have counted two), each TWO case two groups."""
    from pyrxd.network.source_identity import _canonical_host_of

    for case, (a, b) in ONE_GROUP_CASES.items():
        assert _canonical_host_of(a) != _canonical_host_of(b), case
        assert source_key(a) == source_key(b), case
    for case, (a, b) in TWO_GROUP_CASES.items():
        assert source_key(a) != source_key(b), case


# ---- (e) A declaration reaches ONLY the counts it is handed to ------------------------------------
# `(a, b, {url: operator}, count where declared, count by domain)`. Each case moves the count, so
# a site that ignores a declaration it was handed fails, and so does a site that sees one it was not.
DECLARED_CASES = {
    "two-domains-declared-one-operator": (
        "wss://node.alpha.example",
        "wss://node.beta.example",
        {"wss://node.alpha.example": "acme", "wss://node.beta.example": "acme"},
        1,
        2,
    ),
    "one-domain-declared-two-operators": (
        "wss://x.shared.example",
        "wss://y.shared.example",
        {"wss://x.shared.example": "op-x", "wss://y.shared.example": "op-y"},
        2,
        1,
    ),
}

#: The sites a declaration can reach: HashMark §7.6 form 2's judge and walker, which the CLI hands
#: its config's declarations. PINNED, not only derived: a quorum that starts taking declarations
#: moves what a config's `operator = "…"` can split, and must be looked at, not inherited.
_DECLARING_SITES = frozenset(
    {"pyrxd.glyph.wave_identity:judge_name_at_mark", "pyrxd.glyph.mutable_chain:walk_mutable_chain"}
)


def _takes_declarations(fn: ast.AST) -> bool:
    a = fn.args
    return "operators" in {x.arg for x in (*a.posonlyargs, *a.args, *a.kwonlyargs)}


def test_the_declaring_sites_are_derived_and_pinned() -> None:
    sites = _all_sites()
    derived = {site for site, fn in sites.items() if _takes_declarations(fn)}
    assert derived == _DECLARING_SITES, sorted(derived)


@pytest.mark.parametrize("case", sorted(DECLARED_CASES))
@pytest.mark.parametrize("site", sorted(PLANTERS))
async def test_a_declaration_reaches_only_the_sites_it_is_handed_to(site, case, monkeypatch) -> None:
    from pyrxd.network.registry import NetworkProfile

    a, b, operators, declared_count, domain_count = DECLARED_CASES[case]
    if site in _DECLARING_SITES:
        assert await _run(PLANTERS[site], a, b, monkeypatch, operators=operators) == declared_count, (site, case)
        # ...and without the declaration handed in, the same site counts by domain.
        assert await _run(PLANTERS[site], a, b, monkeypatch) == domain_count, (site, case)
        return
    # The leak: a profile declared these operators, in this process. No other count may see it.
    NetworkProfile.build("mainnet", [a, b], operators=operators)
    assert await _run(PLANTERS[site], a, b, monkeypatch) == domain_count, (site, case)


# ══════════════════════════════════════════════════════════════════════════════
# (c) Failover with duplicate URLs still works — and counts once
# ══════════════════════════════════════════════════════════════════════════════


async def test_watchtower_gives_one_host_ONE_client_that_fails_over_across_its_urls(monkeypatch, caplog) -> None:
    caplog.set_level("WARNING", logger="pyrxd.watchtower")
    src, corroborated = await _rxd_source_from_run("wss://h.example/", "wss://h.example:50022/", monkeypatch)
    assert corroborated is False
    assert src._c._urls == ["wss://h.example/", "wss://h.example:50022/"], "both URLs kept, raced by one client"
    # Safe (single-source is the cautious posture), but not SILENT: the operator wrote two URLs
    # and must be told they got one source and no corroboration.
    assert "RXD corroboration is OFF" in caplog.text, caplog.text
    assert "are ONE source (registered domain 'h.example')" in caplog.text, caplog.text


async def test_two_distinct_hosts_do_not_warn_that_corroboration_is_off(monkeypatch, caplog) -> None:
    caplog.set_level("WARNING", logger="pyrxd.watchtower")
    _src, corroborated = await _rxd_source_from_run(*TWO_HOSTS, monkeypatch)
    assert corroborated is True
    assert "corroboration is OFF" not in caplog.text and "are ONE source" not in caplog.text, caplog.text


async def test_same_host_esplora_urls_become_one_failover_reader(monkeypatch) -> None:
    from pyrxd.network.bitcoin import MultiSourceBtcFundingReader

    reader = MultiSourceBtcFundingReader.from_endpoints(
        ["https://h.example/api", "https://h.example:443/api", "https://g.example/api"], quorum=2
    )
    assert len(reader._readers) == 2
    failover = reader._readers[0]
    assert isinstance(failover, SameSourceFailover) and failover.source_key == "h.example"

    class _Member:
        def __init__(self, fails: bool) -> None:
            self.source_key = source_key("https://h.example/")
            self.fails = fails

        async def confirmations(self, txid: str) -> int:
            if self.fails:
                raise NetworkError("this URL is down")
            return 7

    assert await SameSourceFailover([_Member(True), _Member(False)]).confirmations("00" * 32) == 7


async def test_same_host_failover_does_not_shop_for_a_better_answer() -> None:
    """Only UNREACHABLE fails over. An answer — even a refusal — from the first URL is the host's
    answer; trying the next spelling until one says something convenient is not failover."""

    class _Refuses:
        source_key = source_key("https://h.example/")

        async def read(self) -> int:
            raise ValueError("the host's answer")

    class _Agrees:
        source_key = source_key("https://h.example:443/")

        async def read(self) -> int:
            return 1

    with pytest.raises(ValueError, match="the host's answer"):
        await SameSourceFailover([_Refuses(), _Agrees()]).read()


def test_failover_group_refuses_members_on_different_hosts() -> None:
    class _M:
        def __init__(self, url: str) -> None:
            self.source_key = source_key(url)

    with pytest.raises(ValidationError, match="must all be one source"):
        SameSourceFailover([_M("https://a.example"), _M("https://b.example")])


def test_a_profile_may_still_list_one_host_twice_for_failover() -> None:
    """The ElectrumX profile is failover, not a quorum: listing both spellings is allowed, and the
    CLI's form-2 pair skips the second spelling for a genuinely different host."""
    from pyrxd.network.registry import Endpoint, NetworkProfile, genesis_hash_for

    profile = NetworkProfile(
        network="mainnet",
        endpoints=(Endpoint("wss://h.example/"), Endpoint("wss://h.example/x"), Endpoint("wss://g.example/")),
        genesis_hash=genesis_hash_for("mainnet"),
    )
    assert [e.url for e in profile.endpoints] == ["wss://h.example/", "wss://h.example/x", "wss://g.example/"]
    assert len({e.source for e in profile.endpoints}) == 2
    assert [k for k, _ in group_by_source(e.url for e in profile.endpoints)] == ["h.example", "g.example"]
