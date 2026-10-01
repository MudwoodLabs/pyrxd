"""Wiring tests for scripts/watchtower_run.py::_build_rxd_source — the RXD source assembly.

Verifies that the runner composes a fail-closed multi-source quorum (and flips ``rxd_corroborated``)
only when >= quorum independent RXD sources are actually wired, and stays single-source /
low-corroboration otherwise. ElectrumX connections are mocked (no network); the ssh-tr node reader
constructs without connecting, so it is exercised for real.
"""

from __future__ import annotations

import contextlib
import sys
from pathlib import Path

import pytest

from pyrxd.gravity.watch import ElectrumRxdChainSource, MultiSourceRxdChainSource
from pyrxd.network.source_identity import source_key
from pyrxd.security.errors import ValidationError

_SCRIPTS = str(Path(__file__).resolve().parent.parent / "scripts")
if _SCRIPTS not in sys.path:
    sys.path.insert(0, _SCRIPTS)

import watchtower_run as w


class _FakeElectrumX:
    """Async-context-manager stand-in for ElectrumXClient (no real wss connect)."""

    def __init__(self, urls, **_kw):
        self.urls = urls
        # The real client's identity rule, through the real function: one host -> that host.
        keys = {source_key(u) for u in urls}
        self.source_key = next(iter(keys)) if len(keys) == 1 else None

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_a):
        return False


@pytest.fixture(autouse=True)
def _patch_electrumx(monkeypatch):
    monkeypatch.setattr(w, "ElectrumXClient", _FakeElectrumX)


async def _build(*argv):
    args = w._parse_args(["--records-dir", "/tmp/x", *argv])
    async with contextlib.AsyncExitStack() as stack:
        return await w._build_rxd_source(args, stack)


async def test_two_electrumx_urls_compose_corroborated_quorum():
    src, corr = await _build("--rxd-electrumx-url", "wss://a", "--rxd-electrumx-url", "wss://b")
    assert isinstance(src, MultiSourceRxdChainSource)
    assert corr is True


async def test_defaults_to_public_endpoints_when_none_given():
    # electrumx backend (default) with no URL → the two verified public endpoints → 2-of-2 corroborated.
    src, corr = await _build()
    assert isinstance(src, MultiSourceRxdChainSource)
    assert corr is True


async def test_single_source_stays_low_corroboration():
    src, corr = await _build("--rxd-electrumx-url", "wss://only", "--accept-single-source")
    assert isinstance(src, ElectrumRxdChainSource)
    assert corr is False


async def test_include_node_combines_with_electrumx_for_quorum():
    # the operator's own node + one public ElectrumX = 2 independent sources → corroborated.
    # --ssh-host/--ssh-container are required (no private-infra defaults) whenever the
    # operator's own node is included.
    src, corr = await _build(
        "--rxd-electrumx-url",
        "wss://a",
        "--rxd-include-node",
        "--ssh-host",
        "node.example.com",
        "--ssh-container",
        "radiant-node",
    )
    assert isinstance(src, MultiSourceRxdChainSource)
    assert corr is True


async def test_ssh_only_is_single_source():
    # node-only run (no electrumx default added) → single source, low-corroboration.
    src, corr = await _build(
        "--rxd-backend",
        "ssh-tr",
        "--ssh-host",
        "node.example.com",
        "--ssh-container",
        "radiant-node",
        "--accept-single-source",
    )
    assert isinstance(src, ElectrumRxdChainSource)
    assert corr is False


async def test_quorum_above_wired_sources_fails_loud():
    # 2 sources but --rxd-quorum 3 → a clean typed error (fail-loud), never silently weakened/raw-raised.
    # ValidationError, NOT SystemExit: this is package code now, so an embedder must be able to catch it.
    with pytest.raises(ValidationError):
        await _build("--rxd-electrumx-url", "wss://a", "--rxd-electrumx-url", "wss://b", "--rxd-quorum", "3")


async def test_dedup_identical_urls_collapses_to_single_source():
    # the same endpoint twice is NOT two independent sources → collapses to one → not corroborated.
    src, corr = await _build(
        "--rxd-electrumx-url", "wss://dup", "--rxd-electrumx-url", "wss://dup", "--accept-single-source"
    )
    assert isinstance(src, ElectrumRxdChainSource)
    assert corr is False


async def test_dedup_normalizes_trailing_slash_and_case():
    # trivially-different forms of ONE endpoint (trailing slash / case) must NOT fake a 2-source quorum.
    src, corr = await _build(
        "--rxd-electrumx-url",
        "wss://Dup.Example",
        "--rxd-electrumx-url",
        "wss://dup.example/",
        "--accept-single-source",
    )
    assert isinstance(src, ElectrumRxdChainSource)
    assert corr is False


async def test_ssh_backend_without_host_or_container_refuses_to_start():
    """No private-infra defaults: omitting them must fail loudly, not silently ssh to a default host.

    The old defaults were one operator's own host/container. A public user who passed only
    --rxd-include-node would have ssh'd to that host alias — handing whoever answers that name in
    their DNS search domain the txid set of their in-flight swaps.
    """
    with pytest.raises(ValidationError, match="--ssh-host and --ssh-container required"):
        await _build("--rxd-backend", "ssh-tr")

    # Only the genuinely-missing flag is named.
    with pytest.raises(ValidationError, match=r"^--ssh-container required"):
        await _build("--rxd-electrumx-url", "wss://a", "--rxd-include-node", "--ssh-host", "h")


# --------------------------------------------------------------------------- fewer sources than the quorum
#
# One rule for every shortfall: fewer sources of distinct operators than --rxd-quorum REFUSES TO START,
# unless --accept-single-source, which starts with a WARNING naming the sources. One configuration per
# row of the table the inconsistency was reported with (one URL, two URLs of one operator, the node
# alone, two operators against a quorum of three), each in both directions, plus the shipped defaults.

_NODE = ("--ssh-host", "node.example.com", "--ssh-container", "radiant-node")
_SHORTFALLS = {
    "one-url": (("--rxd-electrumx-url", "wss://one.example"), 1, "registered domain 'one.example'"),
    "two-urls-one-operator": (
        ("--rxd-electrumx-url", "wss://a.pool.example", "--rxd-electrumx-url", "wss://b.pool.example"),
        1,
        "registered domain 'pool.example'",
    ),
    "node-only": (("--rxd-backend", "ssh-tr", *_NODE), 1, "your own node over ssh"),
    "two-operators-quorum-3": (
        ("--rxd-electrumx-url", "wss://a.example", "--rxd-electrumx-url", "wss://b.example", "--rxd-quorum", "3"),
        2,
        "registered domain 'a.example'; registered domain 'b.example'",
    ),
}


@pytest.mark.parametrize("case", sorted(_SHORTFALLS))
async def test_fewer_sources_than_the_quorum_refuses_to_start(case):
    argv, count, named = _SHORTFALLS[case]
    with pytest.raises(ValidationError) as exc:
        await _build(*argv)
    msg = str(exc.value)
    assert f"but only {count} RXD source(s) of distinct operators wired ({named})" in msg, msg
    assert "--accept-single-source" in msg


@pytest.mark.parametrize("case", sorted(_SHORTFALLS))
async def test_accept_single_source_starts_on_fewer_sources_and_warns_naming_them(case, caplog):
    argv, count, named = _SHORTFALLS[case]
    caplog.set_level("WARNING", logger="pyrxd.watchtower")
    src, corr = await _build(*argv, "--accept-single-source")
    warned = [r.getMessage() for r in caplog.records if "RXD quorum NOT MET" in r.getMessage()]
    assert len(warned) == 1 and named in warned[0] and "--accept-single-source" in warned[0], caplog.text
    if count == 1:
        assert isinstance(src, ElectrumRxdChainSource) and corr is False
        assert "SINGLE-SOURCE" in warned[0]
    else:
        # Two operators really do corroborate: the quorum is clamped to 2-of-2, not dropped to one.
        assert isinstance(src, MultiSourceRxdChainSource) and corr is True
        assert len(src._sources) == count and "2-of-2" in warned[0]


async def test_a_quorum_the_sources_meet_starts_without_the_flag(caplog):
    """The honest half: the shipped defaults (two operators) and a deliberate --rxd-quorum 1 start, unwarned."""
    caplog.set_level("WARNING", logger="pyrxd.watchtower")
    src, corr = await _build()
    assert isinstance(src, MultiSourceRxdChainSource) and corr is True
    src, corr = await _build("--rxd-electrumx-url", "wss://one.example", "--rxd-quorum", "1")
    assert isinstance(src, ElectrumRxdChainSource) and corr is False
    assert "RXD quorum NOT MET" not in caplog.text, caplog.text


def test_the_refusal_reaches_the_console_script_as_exit_1(tmp_path, capsys):
    """Through ``main``: the operator sees the reason and exit code 1, not a traceback."""
    from pyrxd.gravity.watch import run

    code = run.main(["--records-dir", str(tmp_path), "--rxd-electrumx-url", "wss://one.example", "--once"])
    assert code == 1
    err = capsys.readouterr().err
    assert "--rxd-quorum 2 but only 1 RXD source(s)" in err and "Traceback" not in err
