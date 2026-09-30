"""ONE source identity, everywhere a source is counted — and it is a HOST, not an operator.

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
    except a PINNED set of non-source uses (a connect key, a loopback test, an alert-channel compare).
    The pin is exact in both directions, and a control proves the scanner sees the pattern at all.
(b) The counting sites are DERIVED from the code — every function with a ``quorum`` /
    ``min_agreeing`` / ``corroborat*`` parameter (or reading ``args.<such>``), plus the form-2 judge
    and walker, which count sources without such a parameter. Every derived site must have a planter
    here, and every planter a site: a new quorum fails this file until someone shows it counts one
    host once. Each planter feeds its site two spellings of ONE host and must count ONE source.
(c) The honest paths: two genuinely different hosts count as two at every site, and several URLs on
    one host still work as failover.

WHAT THE KEY DOES NOT CLAIM. Two distinct hosts may be one operator, share a CDN or an upstream node,
or carry certificates from one mis-issuing CA. Nothing here tests independence, because nothing a
client can observe establishes it.
"""

from __future__ import annotations

import ast
import contextlib
import pathlib
import re
from collections.abc import Callable

import pytest

from pyrxd.network.source_identity import SameHostFailover, SourceKey, group_by_source, source_key, source_key_of
from pyrxd.security.errors import NetworkError, ValidationError

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_SRC = _ROOT / "src" / "pyrxd"
_SCRIPTS = _ROOT / "scripts"
_IDENTITY_MODULE = _SRC / "network" / "source_identity.py"

# Two spellings of ONE host: the default port written out, and a trailing dot.
ONE_HOST_PAIRS = [
    ("wss://h.example", "wss://h.example:443"),
    ("wss://h.example", "wss://h.example."),
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
    ],
    ids=["port-path-case-dot-userinfo", "esplora", "ipv4-spellings", "ipv6-spellings"],
)
def test_every_spelling_of_one_host_is_one_key(spellings) -> None:
    keys = {source_key(s) for s in spellings}
    assert len(keys) == 1, keys
    assert all(isinstance(source_key(s), SourceKey) for s in spellings)


def test_distinct_hosts_stay_distinct() -> None:
    """The honest half. A name and its IP address are two hosts here: the URL cannot show otherwise,
    and folding them would be a claim nobody checked."""
    assert source_key("wss://a.example") != source_key("wss://b.example")
    assert source_key("http://localhost:8545") != source_key("http://127.0.0.1:8545")
    assert source_key("https://eth.drpc.org") != source_key("https://rpc.mevblocker.io")


def test_an_empty_url_is_not_a_source() -> None:
    for blank in ("", "   "):
        with pytest.raises(ValidationError):
            source_key(blank)


def test_a_quorum_refuses_a_client_that_cannot_name_its_host() -> None:
    """A caller-typed label is not a key: only `source_key` makes a SourceKey."""

    class _Labelled:
        source_key = "a"  # a plain str, as a caller might type it

    with pytest.raises(ValidationError, match="does not say which host"):
        source_key_of(_Labelled())
    with pytest.raises(ValidationError, match="does not say which host"):
        source_key_of(object())


# ══════════════════════════════════════════════════════════════════════════════
# (a) No second identity: the AST scan
# ══════════════════════════════════════════════════════════════════════════════

#: Uses of `.hostname` / `.rstrip("/").lower()` that are NOT source identity, each with its reason.
#: REVIEWED, not derived — and pinned: the scan must find exactly these, so adding one forces a
#: reviewer to read this list, and removing one forces the entry out.
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
    """Every `(qualname, kind)` in *tree* that builds a host/URL identity by hand."""
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


def _scan() -> dict[tuple[str, str], set[str]]:
    hits: dict[tuple[str, str], set[str]] = {}
    for base in (_SRC, _SCRIPTS):
        for path in sorted(base.rglob("*.py")):
            if path == _IDENTITY_MODULE:
                continue
            rel = str(path.relative_to(_ROOT))
            for qual, kind in _identity_folds(ast.parse(path.read_text(), filename=rel)):
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


def test_the_scan_can_see_the_pattern_it_forbids() -> None:
    """Non-vacuity, with cases whose answer is known. The one identity function itself parses a
    `.hostname` — the scanner must see it there — and each forbidden shape must be flagged in a
    snippet. A scan that finds nothing anywhere would pass the test above for the wrong reason."""
    own = _identity_folds(ast.parse(_IDENTITY_MODULE.read_text()))
    assert ("source_key", "hostname") in own, own
    for snippet, kind in (
        ("def f(u):\n    return u.rstrip('/').lower()\n", "rstrip-lower"),
        ("def f(u):\n    return u.lower().rstrip('/')\n", "rstrip-lower"),
        ("from urllib.parse import urlsplit\ndef f(u):\n    return urlsplit(u).hostname\n", "hostname"),
        ("from urllib.parse import urlparse\ndef f(u):\n    p = urlparse(u)\n    return p.hostname\n", "hostname"),
    ):
        assert ("f", kind) in _identity_folds(ast.parse(snippet)), snippet
    assert len(_scan()) >= len(_NOT_SOURCE_IDENTITY) > 0


# ══════════════════════════════════════════════════════════════════════════════
# (b) Every counting site counts one host once — the DERIVED registry
# ══════════════════════════════════════════════════════════════════════════════

_COUNTING_PARAM = re.compile(r"quorum|min_agreeing|corroborat")

#: Sites that count sources with no quorum-named parameter, so the derivation cannot find them.
#: HashMark §7.6 form 2 compares source labels inside these two functions. REVIEWED, not derived.
_FORM2_SITES = frozenset(
    {
        "pyrxd.glyph.wave_identity:judge_name_at_mark",
        "pyrxd.glyph.mutable_chain:walk_mutable_chain",
    }
)


def _derived_counting_sites() -> set[str]:
    sites: set[str] = set()
    for path in sorted(_SRC.rglob("*.py")):
        module = ".".join(path.relative_to(_SRC.parent).with_suffix("").parts)
        tree = ast.parse(path.read_text())

        def visit(node: ast.AST, prefix: str, module: str = module) -> None:
            for child in ast.iter_child_nodes(node):
                if isinstance(child, ast.ClassDef):
                    visit(child, f"{prefix}{child.name}.")
                elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    a = child.args
                    names = [x.arg for x in (*a.posonlyargs, *a.args, *a.kwonlyargs)]
                    counts = any(_COUNTING_PARAM.search(n) for n in names)
                    if "args" in names:  # a CLI builder reading `args.rxd_quorum`
                        counts = counts or any(
                            isinstance(n, ast.Attribute)
                            and isinstance(n.value, ast.Name)
                            and n.value.id == "args"
                            and _COUNTING_PARAM.search(n.attr)
                            for n in ast.walk(child)
                        )
                    if counts:
                        sites.add(f"{module}:{prefix}{child.name}")
                    visit(child, f"{prefix}{child.name}.<locals>.")

        visit(tree, "")
    return sites


# ---- planters: build the site from two URLs, return how many SOURCES it counted ----------------
# A refusal naming "the same host" is the site declining to count one host twice: it returns 1.
# Any other exception propagates, so a planter cannot pass by failing for an unrelated reason —
# and the honest-path test runs the SAME planter and must see 2.


def _refused_as_one_host(fn: Callable[[], int]) -> int:
    try:
        return fn()
    except ValidationError as exc:
        if "same host" not in str(exc):
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
    args = run._parse_args(["--records-dir", "/nonexistent", "--rxd-electrumx-url", a, "--rxd-electrumx-url", b])
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


def _plant_claim_executor(a: str, b: str, _mp) -> int:
    from pyrxd.gravity.swap_coordinator import MarginPolicy
    from pyrxd.gravity.watch.adapters import MultiSourceRxdChainSource
    from pyrxd.gravity.watch.claim_executor import ClaimExecutor

    def build() -> int:
        corroborator = MultiSourceRxdChainSource(_rxd_clients(a, b), quorum=2)
        ex = ClaimExecutor(
            resolve_leg=None,
            claim_status_source=None,
            claim_bytes_source=None,
            policy=MarginPolicy.estimated(),
            network="bcrt",
            rxd_depth_corroborator=corroborator,
        )
        return len(ex._rxd_depth_corroborator._sources)

    return _refused_as_one_host(build)


async def _plant_judge(a: str, b: str, _mp) -> int:
    from pyrxd.glyph.wave_identity import HeightReport, judge_name_at_mark
    from tests.test_wave_identity_form2 import _HEIGHTS, NAME, _anchor, _walk

    walk = await _walk()
    anchor = _anchor(458605, source=a)
    reports = [HeightReport(source=s, mark_height=anchor.height, step_heights=_HEIGHTS) for s in (a, b)]
    verdict = judge_name_at_mark(
        ref=walk.ref, name=NAME, binding_source="index-B", anchor=anchor, walk=walk, height_reports=reports
    )
    if verdict.form == 2:
        return len(verdict.height_sources)
    assert "every block height came from" in verdict.degraded_reason, verdict.degraded_reason
    return 1


async def _plant_walker(a: str, b: str, _mp) -> int:
    from pyrxd.glyph.mutable_chain import walk_mutable_chain
    from tests.test_wave_identity_form2 import _RAW, MINT, _fetch, _unspent

    walk = await walk_mutable_chain(
        mint_txid=MINT,
        candidates=list(_RAW),
        fetch_tx=_fetch,
        is_unspent=_unspent,
        candidate_source=a,
        tip_source=b,
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
}


def test_every_counting_site_has_a_planter_and_every_planter_a_site() -> None:
    derived = _derived_counting_sites()
    # NON-VACUITY: the derivation finds the sites known to exist. If it ever returns nothing, the
    # parametrised tests below would run over the hand-kept dict alone and prove nothing new.
    assert {
        "pyrxd.gravity.watch.adapters:MultiSourceRxdChainSource.__init__",
        "pyrxd.eth_wallet.multi_rpc:MultiSourceEthRpc.__init__",
        "pyrxd.gravity.watch.run:_build_rxd_source",
    } <= derived, derived
    expected = derived | _FORM2_SITES
    missing = expected - set(PLANTERS)
    assert not missing, f"a source-counting site has no one-host plant: {sorted(missing)}"
    orphans = set(PLANTERS) - expected
    assert not orphans, f"planters for sites that no longer exist (or no longer count): {sorted(orphans)}"


async def _run(planter: Callable, a: str, b: str, mp) -> int:
    result = planter(a, b, mp)
    if hasattr(result, "__await__"):
        result = await result
    return result


@pytest.mark.parametrize(("a", "b"), ONE_HOST_PAIRS, ids=["default-port", "trailing-dot"])
@pytest.mark.parametrize("site", sorted(PLANTERS))
async def test_one_host_counts_as_ONE_source_at_every_site(site, a, b, monkeypatch) -> None:
    assert await _run(PLANTERS[site], a, b, monkeypatch) == 1, site


@pytest.mark.parametrize("site", sorted(PLANTERS))
async def test_two_distinct_hosts_still_count_as_TWO_at_every_site(site, monkeypatch) -> None:
    """(c) The honest path. A guard that refuses two different hosts would refuse valid work."""
    assert await _run(PLANTERS[site], *TWO_HOSTS, monkeypatch) == 2, site


# ══════════════════════════════════════════════════════════════════════════════
# (c) Failover with duplicate URLs still works — and counts once
# ══════════════════════════════════════════════════════════════════════════════


async def test_watchtower_gives_one_host_ONE_client_that_fails_over_across_its_urls(monkeypatch) -> None:
    src, corroborated = await _rxd_source_from_run("wss://h.example/", "wss://h.example:50022/", monkeypatch)
    assert corroborated is False
    assert src._c._urls == ["wss://h.example/", "wss://h.example:50022/"], "both URLs kept, raced by one client"


async def test_same_host_esplora_urls_become_one_failover_reader(monkeypatch) -> None:
    from pyrxd.network.bitcoin import MultiSourceBtcFundingReader

    reader = MultiSourceBtcFundingReader.from_endpoints(
        ["https://h.example/api", "https://h.example:443/api", "https://g.example/api"], quorum=2
    )
    assert len(reader._readers) == 2
    failover = reader._readers[0]
    assert isinstance(failover, SameHostFailover) and failover.source_key == "h.example"

    class _Member:
        def __init__(self, fails: bool) -> None:
            self.source_key = source_key("https://h.example/")
            self.fails = fails

        async def confirmations(self, txid: str) -> int:
            if self.fails:
                raise NetworkError("this URL is down")
            return 7

    assert await SameHostFailover([_Member(True), _Member(False)]).confirmations("00" * 32) == 7


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
        await SameHostFailover([_Refuses(), _Agrees()]).read()


def test_failover_group_refuses_members_on_different_hosts() -> None:
    class _M:
        def __init__(self, url: str) -> None:
            self.source_key = source_key(url)

    with pytest.raises(ValidationError, match="must all be one host"):
        SameHostFailover([_M("https://a.example"), _M("https://b.example")])


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
