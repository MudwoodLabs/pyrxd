"""Sources are counted by OPERATOR: as declared, or by registered domain.

The per-site guard lives in ``tests/test_one_source_identity.py`` (section (d)): every derived
counting site is planted with two hosts of ONE group and must count one, and with two groups and
must count two. This file covers what that guard rests on:

* the vendored Public Suffix List is the pinned file, and a changed byte is refused;
* the registered-domain rule gives the known answers (``co.uk``, a wildcard, an exception, the
  private section);
* the shipped operator facts are the maintainer's statement, and the shipped endpoints agree with it;
* the honest paths: three operators are three, radiant4people's two servers one, and the shipped
  defaults still reach corroboration (the watchtower's RXD quorum, and form 2's endpoint pair);
* every refusal: unparseable input, a malformed operator id, a declaration that contradicts a shipped
  operator, one host counted as two sources (at every entry point that keys a set), a malformed
  config entry;
* the config field, end to end: ``{ url, operator }`` in a real config file reaches form 2's judge —
  and nothing else: not a BTC quorum, not another profile, not a later load.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import re
import shutil
from pathlib import Path

import pytest

from pyrxd.network import registry
from pyrxd.network import source_identity as si
from pyrxd.network.registry import (
    DEFAULT_ENDPOINTS,
    KNOWN_OPERATORS,
    SHIPPED_ENDPOINTS,
    Endpoint,
    NetworkProfile,
    shipped_operator_domains,
)
from pyrxd.network.source_identity import (
    describe_source,
    group_by_source,
    registered_domain,
    source_key,
    source_keys,
)
from pyrxd.security.errors import ValidationError

_DATA = Path(si.__file__).resolve().parent / "data"

#: Photonic's `packages/app/src/config.json` `defaultConfig.servers.mainnet`
#: (Radiant-Core/Photonic-Wallet @ becf41a): three operators, six servers.
PHOTONIC_MAINNET = (
    "wss://electrumx.radiantcore.org",
    "wss://electrumx.radiant4people.com:50022",
    "wss://electrumx2.radiant4people.com:50022",
    "wss://radiant2.bladenet.online:50022",
    "wss://radiantus.bladenet.online:50022",
    "wss://radiant4.bladenet.online:50022",
)


# ══════════════════════════════════════════════════════════════════════════════
# The Public Suffix List: pinned, and read correctly
# ══════════════════════════════════════════════════════════════════════════════


def test_the_vendored_public_suffix_list_is_the_pinned_file() -> None:
    manifest = json.loads((_DATA / "MANIFEST.json").read_text(encoding="utf-8"))
    raw = (_DATA / "public_suffix_list.dat").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == manifest["files"]["public_suffix_list.dat"]
    # The file names the upstream commit the manifest records: the pin is to a version, not a mood.
    assert f"// COMMIT: {manifest['commit']}".encode() in raw
    assert set(manifest["files"]) == {"public_suffix_list.dat"}, "every vendored data file must be pinned"
    assert {p.name for p in _DATA.iterdir() if p.is_file()} == {"public_suffix_list.dat", "MANIFEST.json"}


@pytest.fixture
def _fresh_rules():
    si._public_suffix_rules.cache_clear()
    yield
    si._public_suffix_rules.cache_clear()


def test_a_changed_byte_in_the_list_is_refused(tmp_path, monkeypatch, _fresh_rules) -> None:
    """Plant: the list with ``bladenet.online`` made a public suffix — which would make every
    ``*.bladenet.online`` host a source of its own — and the SAME manifest. The loader refuses it."""
    for name in ("public_suffix_list.dat", "MANIFEST.json"):
        shutil.copy(_DATA / name, tmp_path / name)
    with (tmp_path / "public_suffix_list.dat").open("a", encoding="utf-8") as f:
        f.write("bladenet.online\n")
    monkeypatch.setattr(si, "_DATA_DIR", tmp_path)
    with pytest.raises(ValidationError, match="not the pinned file"):
        source_key("wss://radiant2.bladenet.online:50022")


def test_the_unchanged_copy_is_accepted(tmp_path, monkeypatch, _fresh_rules) -> None:
    """The honest half of the plant above: the same copy procedure, no change, reads fine — so the
    refusal is the digest, not the copy."""
    for name in ("public_suffix_list.dat", "MANIFEST.json"):
        shutil.copy(_DATA / name, tmp_path / name)
    monkeypatch.setattr(si, "_DATA_DIR", tmp_path)
    assert registered_domain("radiant2.bladenet.online") == "bladenet.online"


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("radiant2.bladenet.online", "bladenet.online"),
        ("electrumx2.radiant4people.com", "radiant4people.com"),
        ("a.b.c.example.com", "example.com"),
        ("x.foo.co.uk", "foo.co.uk"),  # a two-label public suffix
        ("co.uk", None),  # a public suffix has no registered domain
        ("a.co.uk", "a.co.uk"),
        ("x.y.ck", "x.y.ck"),  # `*.ck`: every second-level name under ck is a suffix
        ("www.ck", "www.ck"),  # `!www.ck`: the exception
        ("a.www.ck", "www.ck"),
        ("a.github.io", "a.github.io"),  # the PRIVATE section: different owners under github.io
        ("h.example", "h.example"),  # not listed: the implicit `*` rule
        ("localhost", None),
        ("xn--bcher-kva.de", "xn--bcher-kva.de"),
    ],
)
def test_registered_domain_known_answers(host, expected) -> None:
    assert registered_domain(host) == expected


def test_an_internationalised_suffix_rule_is_matched_by_its_a_label() -> None:
    """The list spells IDN suffixes as U-labels; hosts arrive as A-labels. `个人.hk` is a listed
    suffix, so two names under it are two registered domains."""
    assert source_key("wss://a.个人.hk") != source_key("wss://b.个人.hk")
    assert registered_domain("a.xn--ciqpn.hk") == "a.xn--ciqpn.hk"


def test_idna2003_folds_sharp_s_and_that_is_the_documented_deviation() -> None:
    """Python's codec is IDNA2003, so ``faß.de`` and ``fass.de`` are ONE key, while yarl/aiohttp
    (IDNA2008) connect them to two hosts. Pinned so a codec change fails here and the note in
    `source_identity` is revisited; the direction is closed (a lower count)."""
    assert source_key("wss://faß.de") == source_key("wss://fass.de")
    assert "IDNA2003" in (si.__doc__ or "") and "fails CLOSED" in (si.__doc__ or "")


# ══════════════════════════════════════════════════════════════════════════════
# The shipped operator facts
# ══════════════════════════════════════════════════════════════════════════════


def test_known_operators_are_the_maintainers_statement() -> None:
    """radiant4people.com, radiantcore.org and bladenet.online are three DIFFERENT operators (the
    Radiant maintainer, 2026-09-29)."""
    assert dict(KNOWN_OPERATORS) == {
        "radiant4people.com": "radiant4people",
        "radiantcore.org": "radiantcore",
        "bladenet.online": "bladenet",
    }
    assert len(set(KNOWN_OPERATORS.values())) == 3
    assert dict(shipped_operator_domains()) == dict(KNOWN_OPERATORS)


def test_the_shipped_mainnet_defaults() -> None:
    mainnet = SHIPPED_ENDPOINTS["mainnet"]
    assert [(e.url, e.operator) for e in mainnet] == [
        ("wss://electrumx.radiant4people.com:50022/", "radiant4people"),
        ("wss://electrumx.radiantcore.org/", "radiantcore"),
        ("wss://electrumx2.radiant4people.com:50022/", "radiant4people"),
    ]
    assert DEFAULT_ENDPOINTS["mainnet"] == tuple(e.url for e in mainnet)
    assert not any("bladenet" in u for u in DEFAULT_ENDPOINTS["mainnet"]), "bladenet was unreachable 2026-09-29"
    assert DEFAULT_ENDPOINTS["testnet"] == DEFAULT_ENDPOINTS["regtest"] == ()
    # Every shipped endpoint is counted as the operator it declares.
    for endpoint in mainnet:
        assert source_key(endpoint.url) == f"operator:{endpoint.operator}"
        assert Endpoint(endpoint.url).source == f"operator:{endpoint.operator}"


def test_a_shipped_endpoint_whose_operator_contradicts_known_operators_is_refused(monkeypatch) -> None:
    """Plant: electrumx2 labelled as a different operator. The check that ties the per-endpoint label
    to the statement must refuse it."""
    wrong = (registry.ShippedEndpoint("wss://electrumx2.radiant4people.com:50022/", operator="radiantcore"),)
    monkeypatch.setattr(registry, "SHIPPED_ENDPOINTS", {"mainnet": wrong})
    registry.shipped_operator_domains.cache_clear()
    try:
        with pytest.raises(ValidationError, match="declares operator 'radiantcore'"):
            registry.shipped_operator_domains()
    finally:
        monkeypatch.undo()
        registry.shipped_operator_domains.cache_clear()
    assert registry.shipped_operator_domains()["radiant4people.com"] == "radiant4people"


def test_the_watchtower_default_is_the_registry_default() -> None:
    from pyrxd.gravity.watch.run import DEFAULT_RXD_ELECTRUMX

    assert tuple(DEFAULT_RXD_ELECTRUMX) == DEFAULT_ENDPOINTS["mainnet"]


# ══════════════════════════════════════════════════════════════════════════════
# Honest paths
# ══════════════════════════════════════════════════════════════════════════════


def test_the_three_operators_count_as_three_and_radiant4people_as_one() -> None:
    groups = group_by_source(PHOTONIC_MAINNET)
    assert [(str(k), len(urls)) for k, urls in groups] == [
        ("operator:radiantcore", 1),
        ("operator:radiant4people", 2),
        ("operator:bladenet", 3),
    ]
    assert source_key(PHOTONIC_MAINNET[1]) == source_key(PHOTONIC_MAINNET[2])


def test_an_rxd_quorum_of_the_three_operators_has_three_sources() -> None:
    from pyrxd.gravity.watch.adapters import ElectrumRxdChainSource, MultiSourceRxdChainSource
    from pyrxd.network.electrumx import ElectrumXClient

    clients = [ElectrumRxdChainSource(ElectrumXClient(urls)) for _k, urls in group_by_source(PHOTONIC_MAINNET)]
    assert len(MultiSourceRxdChainSource(clients, quorum=2)._sources) == 3


async def test_the_shipped_defaults_still_reach_rxd_corroboration(monkeypatch, caplog) -> None:
    """The watchtower's REAL builder with no --rxd-electrumx-url: the defaults are two operators,
    so corroboration is ON, and radiant4people's two servers are ONE client that fails over."""
    from pyrxd.gravity.watch import run
    from tests.test_one_source_identity import _NoConnectElectrumX

    caplog.set_level("INFO", logger="pyrxd.watchtower")
    monkeypatch.setattr(run, "ElectrumXClient", _NoConnectElectrumX)
    args = run._parse_args(["--records-dir", "/nonexistent"])
    async with contextlib.AsyncExitStack() as stack:
        src, corroborated = await run._build_rxd_source(args, stack)
    assert corroborated is True
    assert [c._c._urls for c in src._sources] == [
        ["wss://electrumx.radiant4people.com:50022/", "wss://electrumx2.radiant4people.com:50022/"],
        ["wss://electrumx.radiantcore.org/"],
    ]
    assert "corroboration is OFF" not in caplog.text
    # Two URLs became one source, and the log says so rather than hiding it — naming what they
    # are: pyrxd's defaults, not a flag this run never passed. For the defaults that grouping is
    # the DESIGN (radiant4people's failover beside a second operator), so it is INFO: a WARNING on
    # every default run is one an operator learns to ignore.
    grouped = [r for r in caplog.records if "are ONE source" in r.getMessage()]
    assert len(grouped) == 1, caplog.text
    assert "2 default RXD ElectrumX endpoints (no --rxd-electrumx-url given) are ONE source" in grouped[0].getMessage()
    assert "(operator 'radiant4people')" in grouped[0].getMessage()
    assert grouped[0].levelname == "INFO", grouped[0].levelname
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING], caplog.text
    assert "--rxd-electrumx-url values" not in caplog.text, caplog.text


async def test_the_watchtower_names_the_flags_when_the_flags_were_given(monkeypatch, caplog) -> None:
    """The other branch of the wording above: URLs the operator passed are called the flag's values."""
    from tests.test_one_source_identity import _rxd_source_from_run

    caplog.set_level("WARNING", logger="pyrxd.watchtower")
    await _rxd_source_from_run("wss://x.pool.example.org", "wss://y.pool.example.org", monkeypatch)
    assert "2 --rxd-electrumx-url values are ONE source" in caplog.text, caplog.text
    # A list the operator SUPPLIED that collapses is still a WARNING: only the defaults are INFO.
    assert [r.levelname for r in caplog.records if "are ONE source" in r.getMessage()] == ["WARNING"]
    assert "the 2 --rxd-electrumx-url values are all one source" in caplog.text, caplog.text
    assert "default RXD ElectrumX endpoints" not in caplog.text


async def test_the_watchtower_warns_when_one_registered_domain_turns_corroboration_off(monkeypatch, caplog) -> None:
    from tests.test_one_source_identity import _rxd_source_from_run

    caplog.set_level("WARNING", logger="pyrxd.watchtower")
    _src, corroborated = await _rxd_source_from_run(
        "wss://radiant2.bladenet.online:50022", "wss://radiant4.bladenet.online:50022", monkeypatch
    )
    assert corroborated is False
    assert "RXD corroboration is OFF" in caplog.text
    assert "are ONE source (operator 'bladenet')" in caplog.text


def test_the_shipped_defaults_give_form_2_two_operators(tmp_path, monkeypatch) -> None:
    """The CLI's form-2 pair on a config naming no servers: the first endpoint and the first of a
    DIFFERENT operator, not radiant4people's second server."""
    from pyrxd.cli import config as cfg_mod
    from pyrxd.cli import glyph_inspect
    from pyrxd.cli.context import CliContext

    for var in ("PYRXD_NETWORK", "PYRXD_ELECTRUMX"):
        monkeypatch.delenv(var, raising=False)
    cfg = cfg_mod.load(tmp_path / "absent.toml").for_network("mainnet")
    ctx = CliContext(config=cfg, output_mode="human", wallet_path=tmp_path / "w", network="mainnet")
    _a, label_a, _b, label_b = glyph_inspect._endpoint_pair(ctx)
    assert (label_a, label_b) == ("wss://electrumx.radiant4people.com:50022/", "wss://electrumx.radiantcore.org/")


# ══════════════════════════════════════════════════════════════════════════════
# Refusals
# ══════════════════════════════════════════════════════════════════════════════


@pytest.mark.parametrize("text", ["[bad", "wss://[::1", "[::1]x", "wss://", "[not-v6]", "wss://[not-v6]:1/"])
def test_input_that_names_no_host_is_refused(text) -> None:
    """These used to become a key of their own, so a typo was a source."""
    with pytest.raises(ValidationError, match="names no host"):
        source_key(text)


def test_an_endpoint_that_names_no_host_is_refused_at_wiring_time() -> None:
    with pytest.raises(ValidationError, match="names no host"):
        Endpoint("wss://")
    with pytest.raises(ValidationError):
        Endpoint("wss://[::1")


def test_no_shipped_default_is_unparseable() -> None:
    """The shipped URL lists are the inputs no user types; each must name a host."""
    from pyrxd.network.bitcoin import MultiSourceBtcFundingReader

    for url in (*DEFAULT_ENDPOINTS["mainnet"], *MultiSourceBtcFundingReader.DEFAULT_MAINNET_ENDPOINTS):
        assert si._canonical_host_of(url)


@pytest.mark.parametrize("bad", ["", "Acme", "a b", "-acme", "acme-", "ac_me", "a" * 65, 7])
def test_a_malformed_operator_id_is_refused(bad) -> None:
    with pytest.raises(ValidationError, match="not a valid operator id"):
        source_key("wss://node.example", operator=bad)  # type: ignore[arg-type]
    with pytest.raises(ValidationError, match="not a valid operator id"):
        source_keys(["wss://node.example"], {"wss://node.example": bad})  # type: ignore[dict-item]


def test_passing_no_operator_means_undeclared() -> None:
    assert source_key("wss://node.example", operator=None) == "node.example"
    assert source_keys(["wss://node.example"]) == {"wss://node.example": "node.example"}


def test_a_well_formed_operator_id_is_accepted() -> None:
    """The honest half: the id grammar admits the ordinary shapes."""
    for good in ("acme", "a", "radiant4people", "node-1", "example.org", "a" * 64):
        assert source_key("wss://node.example", operator=good) == f"operator:{good}"


def test_a_declaration_that_splits_a_shipped_operator_is_refused() -> None:
    url = "wss://electrumx2.radiant4people.com:50022"
    with pytest.raises(ValidationError, match="cannot split an operator pyrxd ships"):
        source_keys([url], {url: "someone-else"})
    with pytest.raises(ValidationError, match="cannot split an operator pyrxd ships"):
        Endpoint(url + "/", operator="someone-else")


def test_declaring_the_shipped_operator_or_merging_into_it_is_accepted() -> None:
    """Refusal is for the direction that adds sources. Agreeing with the shipped operator, or
    declaring a host of your own to BE that operator, only removes one."""
    r4p, mirror = "wss://electrumx2.radiant4people.com:50022", "wss://r4p-mirror.my-own.example/x"
    keys = source_keys([r4p, mirror], {r4p: "radiant4people", mirror: "radiant4people"})
    assert keys[r4p] == keys[mirror] == source_key("wss://electrumx.radiant4people.com:50022")


# ---- One host, one operator: refused wherever a SET of keys is built -------------------------------
# A single `source_key(url, operator=)` or `Endpoint` cannot see the host's other URLs, so the rule
# lives where a set is keyed. Each entry point below used to accept two ports of one host as two
# operators (0.25.x review of #803: `['operator:a', 'operator:b']`).

_ONE_HOST = ("wss://h.one.example:1/", "wss://h.one.example:2/")


def test_one_host_same_operator_on_every_url_is_accepted() -> None:
    """The honest path: a host's URLs all declared one operator, or all undeclared, key as one."""
    a, b = _ONE_HOST
    assert len(set(source_keys([a, b], {a: "acme", b: "acme"}).values())) == 1
    assert len(set(source_keys([a, b]).values())) == 1
    assert [e.source for e in NetworkProfile.build("mainnet", [a, b], operators={a: "acme", b: "acme"}).endpoints] == [
        "operator:acme",
        "operator:acme",
    ]


@pytest.mark.parametrize(
    "operators",
    [{_ONE_HOST[0]: "a", _ONE_HOST[1]: "b"}, {_ONE_HOST[0]: "a"}],
    ids=["two-operators", "declared-and-undeclared"],
)
class TestOneHostIsOneOperatorAtEveryEntryPoint:
    def test_source_keys(self, operators) -> None:
        with pytest.raises(ValidationError, match="counted as two sources"):
            source_keys(_ONE_HOST, operators)

    def test_network_profile_build(self, operators) -> None:
        with pytest.raises(ValidationError, match="counted as two sources"):
            NetworkProfile.build("mainnet", list(_ONE_HOST), operators=operators)

    def test_network_profile_from_endpoints(self, operators) -> None:
        endpoints = tuple(Endpoint(u, operator=operators.get(u)) for u in _ONE_HOST)
        with pytest.raises(ValidationError, match="counted as two sources"):
            NetworkProfile(network="mainnet", endpoints=endpoints)

    def test_config_load(self, operators, tmp_path, monkeypatch) -> None:
        entries = ", ".join(
            f'{{ url = "{u}", operator = "{operators[u]}" }}' if u in operators else f'"{u}"' for u in _ONE_HOST
        )
        with pytest.raises(ValidationError, match="counted as two sources"):
            _load(tmp_path, monkeypatch, f'network = "mainnet"\nelectrumx_servers = [{entries}]\n')

    def test_config_per_network_list(self, operators, tmp_path, monkeypatch) -> None:
        entries = ", ".join(
            f'{{ url = "{u}", operator = "{operators[u]}" }}' if u in operators else f'"{u}"' for u in _ONE_HOST
        )
        cfg = _load(
            tmp_path, monkeypatch, f'network = "mainnet"\n[networks.testnet]\nelectrumx_servers = [{entries}]\n'
        )
        with pytest.raises(ValidationError, match="counted as two sources"):
            cfg.for_network("testnet")

    async def test_form_2_judge_and_walker(self, operators) -> None:
        from tests.test_one_source_identity import _plant_judge, _plant_walker

        for planter in (_plant_judge, _plant_walker):
            with pytest.raises(ValidationError, match="counted as two sources"):
                await planter(*_ONE_HOST, None, operators=operators)

    def test_a_quorum_of_clients_keyed_by_hand(self, operators) -> None:
        from pyrxd.network.bitcoin import MempoolSpaceFundingReader, MultiSourceBtcFundingReader

        readers = []
        for url in _ONE_HOST:
            reader = MempoolSpaceFundingReader(base_url=url.replace("wss://", "https://"))
            reader.source_key = source_key(url, operator=operators.get(url))
            readers.append(reader)
        with pytest.raises(ValidationError, match="counted as two sources"):
            MultiSourceBtcFundingReader(readers, quorum=1)


def test_de_duplication_cannot_hide_one_host_declared_twice() -> None:
    """``wss://h/`` and ``wss://h:443/`` are one CONNECT key, so the profile keeps only the first; the
    check runs over every endpoint as given, before that, so the contradiction is not dropped."""
    with pytest.raises(ValidationError, match="counted as two sources"):
        NetworkProfile.build(
            "mainnet",
            ["wss://h.one.example/", "wss://h.one.example:443/"],
            operators={"wss://h.one.example/": "a", "wss://h.one.example:443/": "b"},
        )


def test_describe_source_names_the_kind_of_group() -> None:
    assert describe_source(source_key("wss://electrumx.radiantcore.org")) == "operator 'radiantcore'"
    assert describe_source(source_key("wss://x.pool.example.org")) == "registered domain 'example.org'"
    assert describe_source(source_key("wss://0xcb.0.113.7")) == "IP address '203.0.113.7'"
    assert describe_source(source_key("localhost:1")).startswith("loopback (this machine")
    assert describe_source(source_key("myalias:22")) == "host 'myalias'"


# ══════════════════════════════════════════════════════════════════════════════
# The config field, end to end
# ══════════════════════════════════════════════════════════════════════════════


def _load(tmp_path, monkeypatch, body: str):
    from pyrxd.cli import config as cfg_mod

    for var in ("PYRXD_NETWORK", "PYRXD_ELECTRUMX"):
        monkeypatch.delenv(var, raising=False)
    path = tmp_path / "config.toml"
    path.write_text(body)
    return cfg_mod.load(path)


def test_a_config_entry_declares_its_operator(tmp_path, monkeypatch) -> None:
    body = (
        'network = "mainnet"\n'
        "electrumx_servers = [\n"
        '  { url = "wss://x.shared.example/", operator = "op-x" },\n'
        '  { url = "wss://y.shared.example/", operator = "op-y" },\n'
        '  "wss://z.other.example/",\n'
        "]\n"
    )
    cfg = _load(tmp_path, monkeypatch, body).for_network("mainnet")
    assert cfg.endpoint_operators == {"wss://x.shared.example/": "op-x", "wss://y.shared.example/": "op-y"}
    assert cfg.declared_operators() == cfg.endpoint_operators
    profile = cfg.require_profile()
    assert [e.operator for e in profile.endpoints] == ["op-x", "op-y", None]
    assert [e.source for e in profile.endpoints] == ["operator:op-x", "operator:op-y", "other.example"]
    # The declaration stays on the endpoint. A key asked for without it is the registered domain.
    assert source_key("wss://x.shared.example/") == source_key("wss://y.shared.example/") == "shared.example"


# ---- A declaration is invisible to everything it was not handed to ---------------------------------


_SPLIT = (
    'network = "mainnet"\nelectrumx_servers = [\n'
    '  { url = "wss://x.shared.example", operator = "op-x" },\n'
    '  { url = "wss://y.shared.example", operator = "op-y" },\n]\n'
)


def test_a_config_declaration_does_not_reach_a_btc_quorum(tmp_path, monkeypatch) -> None:
    """The review's leak (#803): once a config declared ``x``/``y.shared.example`` two operators, a
    BTC ``from_endpoints`` over those hosts that had been refused was ACCEPTED — an ElectrumX
    declaration reached the Esplora quorum. It must stay refused."""
    from pyrxd.network.bitcoin import MultiSourceBtcFundingReader

    urls = ["https://x.shared.example/api", "https://y.shared.example/api"]
    with pytest.raises(ValidationError, match="only 1 distinct source"):
        MultiSourceBtcFundingReader.from_endpoints(urls, quorum=2)
    profile = _load(tmp_path, monkeypatch, _SPLIT).for_network("mainnet").require_profile()
    assert [e.source for e in profile.endpoints] == ["operator:op-x", "operator:op-y"]  # the declaration held
    with pytest.raises(ValidationError, match="only 1 distinct source"):
        MultiSourceBtcFundingReader.from_endpoints(urls, quorum=2)


def test_a_reload_without_the_declarations_groups_by_domain_again(tmp_path, monkeypatch) -> None:
    """Fail-open before: the split outlived the config that made it."""
    _load(tmp_path, monkeypatch, _SPLIT).for_network("mainnet").require_profile()
    plain = 'network = "mainnet"\nelectrumx_servers = ["wss://x.shared.example", "wss://y.shared.example"]\n'
    cfg = _load(tmp_path, monkeypatch, plain).for_network("mainnet")
    assert cfg.declared_operators() == {}
    assert [e.source for e in cfg.require_profile().endpoints] == ["shared.example", "shared.example"]
    assert source_key("wss://x.shared.example") == source_key("wss://y.shared.example") == "shared.example"


async def test_two_profiles_in_one_process_stay_independent(tmp_path, monkeypatch) -> None:
    """One profile declares the split; another lists the same hosts undeclared. Each counts by its
    own declarations, in either order, and form 2's judge follows whichever it is handed."""
    from tests.test_one_source_identity import _plant_judge

    a, b = "wss://x.shared.example", "wss://y.shared.example"
    split = NetworkProfile.build("mainnet", [a, b], operators={a: "op-x", b: "op-y"})
    plain = NetworkProfile.build("mainnet", [a, b])
    again = NetworkProfile.build("mainnet", [a, b], operators={a: "op-x", b: "op-y"})
    assert (
        [e.source for e in split.endpoints] == [e.source for e in again.endpoints] == ["operator:op-x", "operator:op-y"]
    )
    assert [e.source for e in plain.endpoints] == ["shared.example", "shared.example"]
    declared = {e.url: e.operator for e in split.endpoints}
    assert await _plant_judge(a, b, None, operators=declared) == 2
    assert await _plant_judge(a, b, None) == 1


def test_a_per_network_entry_and_a_single_electrumx_table_declare_too(tmp_path, monkeypatch) -> None:
    body = (
        'network = "mainnet"\n'
        'electrumx = { url = "wss://solo.example/", operator = "solo" }\n'
        "[networks.regtest]\n"
        "allow_insecure = true\n"
        'electrumx_servers = [{ url = "ws://127.0.0.1:50022", operator = "me" }]\n'
    )
    cfg = _load(tmp_path, monkeypatch, body)
    assert cfg.for_network("mainnet").endpoint_operators == {"wss://solo.example/": "solo"}
    regtest = cfg.for_network("regtest")
    assert regtest.endpoint_operators == {"ws://127.0.0.1:50022": "me"}
    assert regtest.require_profile().endpoints[0].source == "operator:me"


def test_an_env_endpoint_drops_the_files_declarations(tmp_path, monkeypatch) -> None:
    body = 'network = "mainnet"\nelectrumx_servers = [{ url = "wss://x.example/", operator = "acme" }]\n'
    cfg = _load(tmp_path, monkeypatch, body)
    monkeypatch.setenv("PYRXD_ELECTRUMX", "wss://other.example/")
    from pyrxd.cli import config as cfg_mod

    cfg = cfg_mod.load(tmp_path / "config.toml").for_network("mainnet")
    assert cfg.endpoints == ("wss://other.example/",) and cfg.endpoint_operators == {}


@pytest.mark.parametrize(
    ("entry", "match"),
    [
        ('{ url = "wss://x.example/", operater = "acme" }', "unknown key"),
        ('{ operator = "acme" }', "needs a non-empty string url"),
        ('{ url = "wss://x.example/", operator = "Acme" }', "not a valid operator id"),
        ('{ url = "wss://electrumx.radiantcore.org/", operator = "acme" }', "cannot split an operator"),
        (
            '{ url = "wss://h.example:1/", operator = "a" }, { url = "wss://h.example:2/", operator = "b" }',
            "counted as two sources",
        ),
        ("5", "list of URLs"),
    ],
)
def test_a_malformed_config_entry_is_refused_at_load(tmp_path, monkeypatch, entry, match) -> None:
    with pytest.raises(ValidationError, match=match):
        _load(tmp_path, monkeypatch, f'network = "mainnet"\nelectrumx_servers = [{entry}]\n')


def test_profile_operators_must_name_profile_urls() -> None:
    with pytest.raises(ValidationError, match="not in the profile"):
        NetworkProfile.build("mainnet", ["wss://a.example/"], operators={"wss://b.example/": "acme"})


class TestADeclaredSplitReachesFormTwo:
    """Real config file, real loader, real ``_endpoint_pair``, real judge; only the client class is
    replaced. Two hosts of ONE registered domain are one source — form 2 degrades — until the
    config declares them two operators, and then both are asked and the verdict is form 2."""

    def _attach(self, monkeypatch, tmp_path, body, servers):
        from pyrxd.cli import config as cfg_mod
        from pyrxd.cli import glyph_inspect
        from pyrxd.cli.context import CliContext
        from tests.test_name_at_mark_sees_which_server_answered import MOVED_H160, NAME, _payload

        for var in ("PYRXD_NETWORK", "PYRXD_ELECTRUMX"):
            monkeypatch.delenv(var, raising=False)
        import pyrxd.network.failover as failover

        built: list[str] = []

        def factory(profile, *_a, **_k):
            built.append(profile.endpoints[0].url)
            return servers(profile.endpoints[0].url)

        monkeypatch.setattr(failover, "FailoverElectrumXClient", factory)
        path = tmp_path / "c.toml"
        path.write_text(body)
        cfg = cfg_mod.load(path).for_network("mainnet")
        ctx = CliContext(config=cfg, output_mode="human", wallet_path=tmp_path / "w", network="mainnet")
        payload = _payload(MOVED_H160)
        glyph_inspect._attach_name_at_mark(ctx, payload, name=NAME, min_confirmations=6)
        return payload["outputs"][0]["hashmark"]["name_at_mark"], built

    def _servers(self):
        from tests.test_name_at_mark_sees_which_server_answered import _TRUE_MARK, MARK, _Server

        a = _Server(indexer=True, mark_heights={MARK: _TRUE_MARK})
        b = _Server(indexer=False, mark_heights={MARK: _TRUE_MARK})
        return lambda url: a if "//x." in url else b

    def test_one_registered_domain_is_one_source(self, monkeypatch, tmp_path) -> None:
        body = 'network = "mainnet"\nelectrumx_servers = ["wss://x.shared.example/", "wss://y.shared.example/"]\n'
        nam, built = self._attach(monkeypatch, tmp_path, body, self._servers())
        assert set(built) == {"wss://x.shared.example/"}, built
        assert nam["form"] == 1, nam

    def test_declared_as_two_operators_it_is_two_sources(self, monkeypatch, tmp_path) -> None:
        body = (
            'network = "mainnet"\nelectrumx_servers = [\n'
            '  { url = "wss://x.shared.example/", operator = "op-x" },\n'
            '  { url = "wss://y.shared.example/", operator = "op-y" },\n]\n'
        )
        nam, built = self._attach(monkeypatch, tmp_path, body, self._servers())
        assert set(built) == {"wss://x.shared.example/", "wss://y.shared.example/"}, built
        assert nam["form"] == 2, nam.get("degraded_reason")

    def test_two_domains_declared_one_operator_are_one_source(self, monkeypatch, tmp_path) -> None:
        body = (
            'network = "mainnet"\nelectrumx_servers = [\n'
            '  { url = "wss://x.alpha.example/", operator = "acme" },\n'
            '  { url = "wss://y.beta.example/", operator = "acme" },\n]\n'
        )
        nam, built = self._attach(monkeypatch, tmp_path, body, self._servers())
        assert set(built) == {"wss://x.alpha.example/"}, built
        assert nam["form"] == 1, nam


def test_a_quorum_refusal_says_what_can_be_done_where_nothing_can_be_declared() -> None:
    """A quorum of client objects (BTC, ETH, the watchtower's RXD) takes no operator declaration, so
    its refusal must not tell the user to declare one: it names the route that exists."""
    from pyrxd.network.bitcoin import MempoolSpaceFundingReader, MultiSourceBtcFundingReader

    readers = [MempoolSpaceFundingReader(base_url=u) for u in ("https://x.shared.example", "https://y.shared.example")]
    with pytest.raises(ValidationError, match="same source") as info:
        MultiSourceBtcFundingReader(readers, quorum=1)
    message = str(info.value)
    assert "declare the operators" not in message, message
    assert "takes no operator declaration" in message and "different operators" in message, message


# ══════════════════════════════════════════════════════════════════════════════
# A declaration may MERGE sources, never split a group it does not cover (#803 round 2)
# ══════════════════════════════════════════════════════════════════════════════
#
# `rpc.acme.io` declared "acme", `backup.acme.io` left bare: without the declaration the two are one
# source (registered domain acme.io); with it they were two (operator:acme and acme.io), so form 2's
# pair rpc | backup was judged two sources — a declaration making things LESS safe than the grouping
# it refines. Refused in `require_one_key_per_host`, the funnel every set-level count crosses.

_ACME_SPLIT_BY_OMISSION = (
    'network = "mainnet"\nelectrumx_servers = [\n'
    '  { url = "wss://rpc.acme.io/", operator = "acme" },\n'
    '  { url = "wss://edge.acme-cdn.net/", operator = "acme" },\n'
    '  "wss://backup.acme.io/",\n]\n'
)
_ACME_OPS = {"wss://rpc.acme.io/": "acme", "wss://edge.acme-cdn.net/": "acme"}


def test_a_declared_host_beside_an_undeclared_host_of_its_domain_is_refused_at_load(tmp_path, monkeypatch) -> None:
    with pytest.raises(ValidationError, match="declare 'backup.acme.io' too") as info:
        _load(tmp_path, monkeypatch, _ACME_SPLIT_BY_OMISSION)
    assert "'rpc.acme.io'" in str(info.value) and "remove the declaration" in str(info.value)


def test_the_same_refusal_for_a_networks_list_at_for_network(tmp_path, monkeypatch) -> None:
    body = _ACME_SPLIT_BY_OMISSION.replace('network = "mainnet"\n', 'network = "mainnet"\n[networks.mainnet]\n')
    cfg = _load(tmp_path, monkeypatch, body)  # the [networks.*] list is read when it is selected
    with pytest.raises(ValidationError, match="declare 'backup.acme.io' too"):
        cfg.for_network("mainnet")


def test_the_judge_refuses_such_a_map_handed_to_it_directly() -> None:
    from pyrxd.glyph.wave_identity import _same_source

    with pytest.raises(ValidationError, match="declare 'backup.acme.io' too"):
        _same_source("wss://rpc.acme.io/", "wss://backup.acme.io/", _ACME_OPS)
    # Control: the same pair with NO declarations is one source, which is what the refusal preserves.
    assert _same_source("wss://rpc.acme.io/", "wss://backup.acme.io/", None) is True


async def test_the_walker_refuses_such_a_map_handed_to_it_directly() -> None:
    from pyrxd.glyph.mutable_chain import _one_source, walk_mutable_chain

    with pytest.raises(ValidationError, match="declare 'backup.acme.io' too"):
        _one_source("wss://rpc.acme.io/", "wss://backup.acme.io/", _ACME_OPS)

    async def _no_fetch(_txid):  # never reached: the refusal comes before the walk
        raise AssertionError("walked")

    with pytest.raises(ValidationError, match="declare 'backup.acme.io' too"):
        await walk_mutable_chain(
            mint_txid="ab" * 32,
            candidates=[],
            fetch_tx=_no_fetch,
            candidate_source="wss://rpc.acme.io/",
            tip_source="wss://backup.acme.io/",
            operators=_ACME_OPS,
        )


def test_a_profile_built_with_such_a_map_is_refused() -> None:
    with pytest.raises(ValidationError, match="declare 'backup.acme.io' too"):
        NetworkProfile.build(
            "mainnet", ["wss://rpc.acme.io/", "wss://edge.acme-cdn.net/", "wss://backup.acme.io/"], operators=_ACME_OPS
        )


def test_the_refusal_covers_every_group_not_only_registered_domains() -> None:
    """The group is whatever the host would key as undeclared — here loopback and an IP address."""
    with pytest.raises(ValidationError, match="is not declared"):
        source_keys(["ws://localhost:1/", "ws://127.0.0.1:2/"], {"ws://localhost:1/": "tunnel-a"})
    with pytest.raises(ValidationError, match="counted as two sources"):  # one host: the host-level rule
        source_keys(["ws://203.0.113.7:1/", "ws://203.0.113.7:2/"], {"ws://203.0.113.7:1/": "a"})


# ---- the honest paths beside it ---------------------------------------------------------------------


def test_a_split_where_every_host_of_the_domain_is_declared_is_two_sources(tmp_path, monkeypatch) -> None:
    from pyrxd.glyph.mutable_chain import _one_source
    from pyrxd.glyph.wave_identity import _same_source

    ops = {"wss://rpc.acme.io/": "alice", "wss://backup.acme.io/": "bob"}
    assert _same_source("wss://rpc.acme.io/", "wss://backup.acme.io/", ops) is False
    assert _one_source("wss://rpc.acme.io/", "wss://backup.acme.io/", ops) is False
    body = (
        'network = "mainnet"\nelectrumx_servers = [\n'
        '  { url = "wss://rpc.acme.io/", operator = "alice" },\n'
        '  { url = "wss://backup.acme.io/", operator = "bob" },\n'
        '  "wss://other.example/",\n]\n'
    )
    profile = _load(tmp_path, monkeypatch, body).for_network("mainnet").require_profile()
    assert [e.source for e in profile.endpoints] == ["operator:alice", "operator:bob", "other.example"]


def test_declarations_merging_two_domains_still_count_one() -> None:
    from pyrxd.glyph.mutable_chain import _one_source
    from pyrxd.glyph.wave_identity import _same_source

    assert _same_source("wss://rpc.acme.io/", "wss://edge.acme-cdn.net/", _ACME_OPS) is True
    assert _one_source("wss://rpc.acme.io/", "wss://edge.acme-cdn.net/", _ACME_OPS) is True


def test_declaring_a_shipped_operator_beside_its_undeclared_twin_is_not_a_split() -> None:
    """Declaring what pyrxd already records moves no key, so the other radiant4people server may stay
    bare: the refusal is for a declaration that CHANGES the count, not for any declaration."""
    keys = source_keys(
        ["wss://electrumx.radiant4people.com:50022/", "wss://electrumx2.radiant4people.com:50022/"],
        {"wss://electrumx.radiant4people.com:50022/": "radiant4people"},
    )
    assert set(keys.values()) == {"operator:radiant4people"}


def test_a_declaring_config_without_a_split_loads_and_an_offline_inspect_runs(tmp_path, monkeypatch) -> None:
    from click.testing import CliRunner

    from pyrxd.cli.main import cli

    for var in ("PYRXD_NETWORK", "PYRXD_ELECTRUMX"):
        monkeypatch.delenv(var, raising=False)
    good = tmp_path / "good.toml"
    good.write_text(_ACME_SPLIT_BY_OMISSION.replace('"wss://backup.acme.io/"', '"wss://other.example/"'))
    contract = "b45dc453befb589aff8bfd76af0b994615b37eda094f48c380eb31deaf96a2a800000004"
    result = CliRunner().invoke(cli, ["--config", str(good), "glyph", "inspect", contract])
    assert result.exit_code == 0, result.output
    assert "vout:     4" in result.output
    # Control: the conflicting config is refused by the same command (a bad declaring list refuses
    # even offline, as a bad fee_rate does).
    bad = tmp_path / "bad.toml"
    bad.write_text(_ACME_SPLIT_BY_OMISSION)
    result = CliRunner().invoke(cli, ["--config", str(bad), "glyph", "inspect", contract])
    assert result.exit_code != 0, result.output
    assert isinstance(result.exception, ValidationError), result.output
    message = str(result.exception)
    assert re.search(r"'backup\.acme\.io', of the same registered domain 'acme\.io', is not declared", message), message


def test_the_shipped_defaults_are_still_two_operators() -> None:
    keys = source_keys(DEFAULT_ENDPOINTS["mainnet"])
    assert sorted(set(map(str, keys.values()))) == ["operator:radiant4people", "operator:radiantcore"]


# ══════════════════════════════════════════════════════════════════════════════
# Every loopback spelling is ONE source (#803 round 2)
# ══════════════════════════════════════════════════════════════════════════════


@pytest.mark.parametrize(
    "url",
    [
        "ws://localhost:50022",
        "ws://LOCALHOST.:50022",
        "ws://node.localhost:50022",
        "ws://127.0.0.1:50022",
        "ws://127.0.0.2:50022",
        "ws://127.1:50022",
        "ws://[::1]:50022",
        "ws://[::ffff:127.0.0.1]:50022",
        "ws://0.0.0.0:50022",
        "ws://[::]:50022",
        "localhost:8545",
    ],
)
def test_every_loopback_spelling_is_one_key(url) -> None:
    assert source_key(url) == source_key("ws://localhost:50022") == "localhost"


def test_a_non_loopback_address_is_not_folded_into_loopback() -> None:
    assert source_key("ws://128.0.0.1:1") != source_key("ws://localhost:1")
    assert source_key("ws://[::2]:1") != source_key("ws://localhost:1")
    assert source_key("ws://localhost.example:1") != source_key("ws://localhost:1")


@pytest.mark.parametrize(
    ("first", "second"),
    [
        ("ws://localhost:50022", "ws://127.0.0.1:50022"),
        ("ws://127.0.0.1:50022", "ws://0.0.0.0:50022"),
        ("ws://[::1]:50022", "ws://[::]:50022"),
    ],
)
async def test_the_watchtower_does_not_corroborate_one_machine_with_itself(monkeypatch, caplog, first, second) -> None:
    """Through the watchtower's real builder: two spellings of this machine are one local node, so
    the quorum is ONE source and corroboration is OFF. The unspecified addresses are in the set
    because a connection to ``0.0.0.0`` or ``::`` reaches this machine too."""
    from pyrxd.gravity.watch import run
    from tests.test_one_source_identity import _NoConnectElectrumX

    caplog.set_level("WARNING", logger="pyrxd.watchtower")
    monkeypatch.setattr(run, "ElectrumXClient", _NoConnectElectrumX)
    args = run._parse_args(
        [
            "--records-dir",
            "/nonexistent",
            "--rxd-electrumx-url",
            first,
            "--rxd-electrumx-url",
            second,
            "--allow-insecure",
            "--accept-single-source",  # one machine is one source: below --rxd-quorum 2 without it
        ]
    )
    async with contextlib.AsyncExitStack() as stack:
        _src, corroborated = await run._build_rxd_source(args, stack)
    assert corroborated is False
    assert "RXD corroboration is OFF" in caplog.text
    assert "loopback (this machine" in caplog.text, caplog.text
