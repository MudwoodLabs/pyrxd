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
  operator, one host declared as two operators, a malformed config entry;
* the config field, end to end: ``{ url, operator }`` in a real config file reaches form 2's judge.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
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
    declare_operator,
    describe_source,
    group_by_source,
    registered_domain,
    source_key,
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

    caplog.set_level("WARNING", logger="pyrxd.watchtower")
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
    # Two URLs became one source, and the log says so rather than hiding it.
    assert "are ONE source (operator 'radiant4people')" in caplog.text


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
        declare_operator("wss://node.example", bad)  # type: ignore[arg-type]


def test_declaring_no_operator_is_refused_but_passing_none_means_undeclared() -> None:
    with pytest.raises(ValidationError, match="not a valid operator id"):
        declare_operator("wss://node.example", None)  # type: ignore[arg-type]
    assert source_key("wss://node.example", operator=None) == "node.example"


def test_a_well_formed_operator_id_is_accepted() -> None:
    """The honest half: the id grammar admits the ordinary shapes."""
    for good in ("acme", "a", "radiant4people", "node-1", "example.org", "a" * 64):
        assert source_key("wss://node.example", operator=good) == f"operator:{good}"


def test_a_declaration_that_splits_a_shipped_operator_is_refused() -> None:
    with pytest.raises(ValidationError, match="cannot split an operator pyrxd ships"):
        declare_operator("wss://electrumx2.radiant4people.com:50022", "someone-else")
    with pytest.raises(ValidationError, match="cannot split an operator pyrxd ships"):
        Endpoint("wss://electrumx2.radiant4people.com:50022/", operator="someone-else")


def test_declaring_the_shipped_operator_or_merging_into_it_is_accepted() -> None:
    """Refusal is for the direction that adds sources. Agreeing with the shipped operator, or
    declaring a host of your own to BE that operator, only removes one."""
    assert declare_operator("wss://electrumx2.radiant4people.com:50022", "radiant4people") == "operator:radiant4people"
    declare_operator("wss://r4p-mirror.my-own.example", "radiant4people")
    assert source_key("wss://r4p-mirror.my-own.example/x") == source_key("wss://electrumx.radiant4people.com:50022")


def test_one_host_cannot_be_declared_two_operators() -> None:
    declare_operator("wss://node.example:50022", "acme")
    declare_operator("wss://NODE.example./other", "acme")  # the same declaration again: a no-op
    with pytest.raises(ValidationError, match="already declared as operator 'acme'"):
        declare_operator("wss://node.example", "globex")


def test_describe_source_names_the_kind_of_group() -> None:
    assert describe_source(source_key("wss://electrumx.radiantcore.org")) == "operator 'radiantcore'"
    assert describe_source(source_key("wss://x.pool.example.org")) == "registered domain 'example.org'"
    assert describe_source(source_key("wss://0xcb.0.113.7")) == "IP address '203.0.113.7'"
    assert describe_source(source_key("localhost:1")) == "host 'localhost'"


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
        '  "wss://z.shared.example/",\n'
        "]\n"
    )
    cfg = _load(tmp_path, monkeypatch, body).for_network("mainnet")
    assert cfg.endpoint_operators == {"wss://x.shared.example/": "op-x", "wss://y.shared.example/": "op-y"}
    # Before the profile is built nothing is declared: the three hosts are one registered domain.
    assert source_key("wss://x.shared.example/") == source_key("wss://y.shared.example/") == "shared.example"
    profile = cfg.require_profile()
    assert [e.operator for e in profile.endpoints] == ["op-x", "op-y", None]
    assert [e.source for e in profile.endpoints] == ["operator:op-x", "operator:op-y", "shared.example"]
    # ...and after, the declaration reaches every count in the process, not only `Endpoint.source`.
    assert source_key("wss://x.shared.example/") == "operator:op-x"


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
