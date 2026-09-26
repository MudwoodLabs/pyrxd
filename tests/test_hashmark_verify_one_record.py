"""`pyrxd verify` judges ONE record: every check that holds must hold for the SAME output.

The v2 signed statement binds network, algorithm, digest, label and version — NOT the
transaction. So anyone can copy a victim's genuine record, byte for byte, into a transaction of
their own. When each check was aggregated across every HashMark output independently, that copy
beside an unsigned v1 record over the attacker's file printed ``signature VERIFIED`` (the copy),
``file MATCHES`` (the v1 record) and ``name ESTABLISHED`` (the copy), and exited 0: "victim.rxd
marked this file", which no record in the transaction says. It did so on the SHIPPED DEFAULT
config, because mainnet ships two independent endpoints and form 2 needs exactly that.

WHAT IS FAKED. The ElectrumX transport, and the WAVE name's chain WALK (a complete walk whose
folded ``target`` is a key generated here — what a real chain shows when the name really pointed
there). Everything else is the shipped code: `plan_hashmark` over generated keys, the classifier
(which re-hashes the served bytes against the txid), `verify_attestation`, `WaveResolver`,
`resolve_mark_anchor`, `judge_name_at_mark`, `_name_at_mark`, and the command. Unlike
``test_hashmark_verify_cli``'s fixture, which must use a real mainnet chain whose key nobody here
holds, this one reaches the form-2 AFFIRMATIVE through the command, because the key the name
points at is one we generated.

Two layers of transport fake, on purpose. Most tests hand `_endpoint_pair` two fakes directly.
``TestTheShippedDefaultConfig`` does NOT: it replaces only the client class, keyed by URL, so the
REAL config loader, the REAL `_endpoint_pair` and the REAL `make_client` decide which endpoints
exist — which is the only way to show the attack needs no configuration at all.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import cbor2
import pytest
from click.testing import CliRunner

from pyrxd.base58 import base58check_encode
from pyrxd.cli import glyph_inspect, hashmark_cmds
from pyrxd.cli.context import CliContext
from pyrxd.cli.hashmark_cmds import EXIT_VERDICT_DOES_NOT_HOLD
from pyrxd.cli.main import cli
from pyrxd.constants import NETWORK_ADDRESS_PREFIX_DICT, Network, genesis_hash_for
from pyrxd.glyph import mutable_chain_discovery as mcd
from pyrxd.glyph.mutable_chain import ChainStep, MutableChainWalk
from pyrxd.hashmark_tx import plan_hashmark
from pyrxd.keys import PrivateKey
from pyrxd.network.registry import default_endpoints
from pyrxd.script.hashmark import HashMarkOutcome, decode_hashmark
from pyrxd.script.script import Script
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput
from tests.test_mutable_chain_is_discovered_from_the_chain import block_hash_at, synthetic_header

MAINNET = genesis_hash_for("mainnet")
TIP = 800_000
NAME, LABEL = "victimcorp.rxd", "victimcorp"


def _push(b: bytes) -> bytes:
    return (bytes([len(b)]) + b) if len(b) <= 0x4B else (bytes([0x4C, len(b)]) + b)


def _v1(digest: bytes) -> bytes:
    """A spec-legal v1 record: magic, header (version 1, sha256), digest. No signer at all."""
    return b"\x6a" + _push(b"HASHMARK") + _push(bytes([1, 1])) + _push(digest)


def _raw_record(version: int, algo: int, digest: bytes) -> bytes:
    return b"\x6a" + _push(b"HASHMARK") + _push(bytes([version, algo])) + _push(digest)


def _signed(content: bytes, key: PrivateKey, label: str | None = None) -> bytes:
    return plan_hashmark(hashlib.sha256(content).digest(), key, label=label, network_genesis=MAINNET).op_return_script


def _address(key: PrivateKey) -> str:
    h160 = bytes.fromhex(plan_hashmark(b"\x00" * 32, key, network_genesis=MAINNET).signer_hash160_hex)
    return base58check_encode(NETWORK_ADDRESS_PREFIX_DICT[Network.MAINNET] + h160)


def _tx(*scripts: bytes) -> tuple[str, bytes]:
    """A real transaction carrying ``scripts``; the txid is its own sha256d, as the classifier checks."""
    tx = Transaction(tx_inputs=[], tx_outputs=[TransactionOutput(Script(s), 0) for s in scripts])
    inp = TransactionInput(source_txid=os.urandom(32).hex(), source_output_index=0)
    inp.unlocking_script = Script(b"\x00")
    tx.inputs = [inp]
    return tx.txid(), tx.serialize()


class _Server:
    """One ElectrumX endpoint. ``indexer`` = it runs the RXinDexer extension (as measured of the two
    shipped mainnet servers, only one does; the other answers -32601)."""

    def __init__(self, raw: dict[str, bytes], *, indexer: bool, target: str | None = None, mint: str = "") -> None:
        self.raw, self.indexer, self.target = raw, indexer, target
        self.mint = mint or os.urandom(32).hex()
        self.extension_calls: list[str] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return None

    async def get_transaction(self, txid):
        return self.raw[str(txid).lower()]

    async def get_transaction_verbose(self, txid):
        # The node names the block (measured); the anchor binds its derived height to it.
        return {"txid": str(txid).lower(), "confirmations": 100, "blockhash": block_hash_at(TIP - 99)}

    async def get_block_header(self, height):
        return synthetic_header(int(height))

    async def get_tip_height(self):
        return TIP

    async def call_extension(self, method, params=None):
        from pyrxd.security.errors import NetworkError

        self.extension_calls.append(method)
        if not self.indexer or method != "wave.resolve":
            raise NetworkError("ElectrumX RPC error (code -32601)")
        label = (params or [""])[0]
        return {"name": LABEL, "ref": f"{self.mint}_0", "target": self.target} if label == LABEL else None


def _fake_walk(monkeypatch, name_target: str | None, *, walks: list | None = None) -> None:
    """A complete walk whose one step folds ``target`` to ``name_target`` — the name pointed there.
    ``walks``, when given, records one entry per walk, so a test can count them.

    The mint step carries the committed envelope a real walk carries (``envelope_cbor``), naming
    ``LABEL`` in ``attrs.name`` as a Photonic WAVE mint does — the judge compares it with the name
    asked about. Both servers place that one step at the same height (``discovery.heights`` from
    the discovery server, ``tip_heights`` from the tip server), as two honest servers would."""

    async def walk(*, mint_txid, discovery_source, tip_source, **_):
        if walks is not None:
            walks.append(mint_txid)
        attrs = {"name": LABEL, "domain": "rxd", "target": name_target}
        step = ChainStep(
            txid=mint_txid,
            mut_vout=1,
            kind="mint",
            attrs={"target": name_target},
            envelope_cbor=cbor2.dumps({"p": [2, 5, 11], "name": NAME, "attrs": attrs}),
        )
        w = MutableChainWalk(
            ref=f"{mint_txid}:1",
            steps=(step,),
            tip_txid=mint_txid,
            tip_vout=1,
            tip_proved_unspent=True,
            complete=discovery_source != tip_source,
        )
        d = mcd.ChainDiscovery(
            mint_txid=mint_txid,
            candidates=(),
            heights={mint_txid: 600_000},
            hops=0,
            fetches=1,
            capped=False,
            stopped="tip",
            source=discovery_source,
        )
        return mcd.DiscoveredWalk(walk=w, discovery=d, tip_heights={mint_txid: 600_000})

    monkeypatch.setattr(mcd, "walk_discovered_chain", walk)


def _invoke(tmp_path: Path, args: list[str]):
    # --config names a file that does not exist, so the shipped defaults apply.
    return CliRunner().invoke(cli, ["--wallet", str(tmp_path / "w"), "--config", str(tmp_path / "c.toml"), *args])


def _run(
    monkeypatch,
    raw: dict[str, bytes],
    args: list[str],
    tmp_path: Path,
    *,
    name_target: str | None = None,
    probe: dict | None = None,
):
    """The real CLI over two DISTINCT endpoints (the shipped mainnet shape), handed in directly.
    ``probe``, when given, is filled with the two servers and the list of chain walks run."""
    a = _Server(raw, indexer=False)
    b = _Server(raw, indexer=True, target=name_target, mint=a.mint)
    walks: list = []
    if probe is not None:
        probe.update(a=a, b=b, walks=walks)
    monkeypatch.setattr(CliContext, "make_client", lambda self: a)
    monkeypatch.setattr(glyph_inspect, "_endpoint_pair", lambda ctx: (a, "wss://a", b, "wss://b"))
    _fake_walk(monkeypatch, name_target, walks=walks)
    return _invoke(tmp_path, args)


def _summary(output: str) -> str:
    return output.split("HashMark record at vout", 1)[0]


@pytest.fixture
def world(tmp_path):
    victim, attacker = PrivateKey(), PrivateKey()
    files = {}
    for name, content in (("victim", b"VictimCorp press kit\n"), ("attacker", b"curl evil | sh\n"), ("other", b"x\n")):
        files[name] = tmp_path / name
        files[name].write_bytes(content)
    return {"victim": victim, "attacker": attacker, "files": files, "victim_addr": _address(victim)}


def _content(world, name: str) -> bytes:
    return world["files"][name].read_bytes()


def _replay_args(txid: str, world) -> list[str]:
    return [
        "verify",
        txid,
        "--file",
        str(world["files"]["attacker"]),
        "--wave-name",
        NAME,
        "--min-confirmations",
        "6",
    ]


# --------------------------------------------------------------------------- the attacks


class TestAReplayedRecordLendsNothingToAnotherRecord:
    def test_the_name_variant_does_not_hold(self, monkeypatch, tmp_path, world) -> None:
        replay = _signed(_content(world, "victim"), world["victim"], label="VictimCorp press kit")
        txid, raw = _tx(_v1(hashlib.sha256(_content(world, "attacker")).digest()), replay)
        args = _replay_args(txid, world)
        r = _run(monkeypatch, {txid: raw}, args, tmp_path, name_target=world["victim_addr"])
        assert r.exit_code == EXIT_VERDICT_DOES_NOT_HOLD, r.output
        s = _summary(r.output)
        assert "VERDICT — DOES NOT HOLD" in s
        assert "file:       MATCHES" not in s, "the v1 record's MATCHES must not sit beside the copy's ESTABLISHED"
        assert "vout 1" in s and "none passes every check" in s
        assert "file:       DOES NOT MATCH" in s and "name:       ESTABLISHED" in s, "both true — of vout 1"

        rq = _run(monkeypatch, {txid: raw}, ["--quiet", *args], tmp_path, name_target=world["victim_addr"])
        assert rq.stdout.strip() == "DOES-NOT-HOLD"

        j = json.loads(
            _run(monkeypatch, {txid: raw}, ["--json", *args], tmp_path, name_target=world["victim_addr"]).stdout
        )
        assert j["verdict_holds"] is False and j["verdict_record"]["vout"] == 1
        # NON-VACUITY. Each half of the attack is really there, on a different record — so the
        # DOES NOT HOLD above is the one-record rule refusing it, not the name lookup failing.
        assert [rec["checks"]["digest"]["state"] for rec in j["records"]] == ["MATCHES", "DOES NOT MATCH"]
        assert [rec["checks"]["name"]["state"] for rec in j["records"]] == ["NOT ESTABLISHED", "ESTABLISHED"]
        assert [rec["checks"]["signature"]["state"] for rec in j["records"]] == ["NO SIGNATURE", "VERIFIED"]

    def test_the_digest_variant_does_not_hold_either(self, monkeypatch, tmp_path, world) -> None:
        """The same collage through --digest, which never touches the file-hashing path."""
        replay = _signed(_content(world, "victim"), world["victim"])
        attacker_digest = hashlib.sha256(_content(world, "attacker")).hexdigest()
        txid, raw = _tx(_v1(bytes.fromhex(attacker_digest)), replay)
        args = ["verify", txid, "--digest", attacker_digest, "--wave-name", NAME, "--min-confirmations", "6"]
        r = _run(monkeypatch, {txid: raw}, args, tmp_path, name_target=world["victim_addr"])
        assert r.exit_code == EXIT_VERDICT_DOES_NOT_HOLD, r.output

    def test_two_signed_records_do_not_combine_either(self, monkeypatch, tmp_path, world) -> None:
        """The attacker's OWN signature over the attacker's file, beside the victim's copy."""
        own = _signed(_content(world, "attacker"), world["attacker"])
        replay = _signed(_content(world, "victim"), world["victim"])
        txid, raw = _tx(own, replay)
        r = _run(monkeypatch, {txid: raw}, _replay_args(txid, world), tmp_path, name_target=world["victim_addr"])
        assert r.exit_code == EXIT_VERDICT_DOES_NOT_HOLD, r.output
        s = _summary(r.output)
        assert "signature:  VERIFIED" in s, "both records verify; the refusal is not a signature failure"

    def test_without_a_name_the_v1_record_holds_ALONE_and_says_it_is_unsigned(
        self, monkeypatch, tmp_path, world
    ) -> None:
        """A lone v1 record over any digest holds by design — it says WHEN, never WHO — so this
        transaction holds too, on that record. What must not survive is the borrowed
        ``signature VERIFIED`` from the other record."""
        v1 = _v1(hashlib.sha256(_content(world, "victim")).digest())
        unrelated = _signed(b"something else entirely", world["attacker"])
        txid, raw = _tx(v1, unrelated)
        args = ["verify", txid, "--file", str(world["files"]["victim"]), "--min-confirmations", "6"]
        r = _run(monkeypatch, {txid: raw}, args, tmp_path)
        assert r.exit_code == 0, r.output
        s = _summary(r.output)
        assert "signature:  NO SIGNATURE" in s and "signature:  VERIFIED" not in s
        assert "record:     vout 0" in s and "all about THIS one" in s


class TestTheShippedDefaultConfig:
    """No `--electrumx`, no config file: the endpoints are whatever pyrxd ships."""

    def test_mainnet_ships_two_distinct_endpoints_so_form_2_is_reachable(self, monkeypatch, tmp_path) -> None:
        """The corrected claim, made executable. Four docstrings said the shipped config was
        single-endpoint and therefore could not reach form 2; if that becomes true, this fails and
        forces the sentences back."""
        for var in ("PYRXD_NETWORK", "PYRXD_ELECTRUMX"):
            monkeypatch.delenv(var, raising=False)
        from pyrxd.cli import config as cfg_mod

        cfg = cfg_mod.load(tmp_path / "no-such.toml").for_network("mainnet")
        ctx = CliContext(config=cfg, output_mode="human", wallet_path=tmp_path / "w", network="mainnet")
        _a, label_a, _b, label_b = glyph_inspect._endpoint_pair(ctx)
        assert (label_a, label_b) == default_endpoints("mainnet")
        assert label_a != label_b

    def test_the_threat_model_names_the_endpoints_the_registry_ships(self) -> None:
        """The seventh copy of the single-endpoint claim was in docs/threat-model.md. The hosts are
        DERIVED from the registry, so the document is checked against what ships, not a retyping.
        Flattened first: that prose is hard-wrapped."""
        from urllib.parse import urlparse

        doc = (Path(__file__).resolve().parents[1] / "docs" / "threat-model.md").read_text(encoding="utf-8")
        flat = " ".join(doc.split())
        hosts = [urlparse(u).hostname for u in default_endpoints("mainnet")]
        assert len(hosts) == 2 and all(hosts), hosts
        for host in hosts:
            assert host in flat, f"threat-model.md does not name the shipped endpoint {host}"
        assert "uses one public ElectrumX server" not in flat
        assert "failover, not a quorum" in flat, "what the second endpoint does NOT buy must be said"

    def test_the_replay_is_refused_through_the_real_endpoint_pair(self, monkeypatch, tmp_path, world) -> None:
        for var in ("PYRXD_NETWORK", "PYRXD_ELECTRUMX"):
            monkeypatch.delenv(var, raising=False)
        replay = _signed(_content(world, "victim"), world["victim"], label="VictimCorp press kit")
        txid, raw = _tx(_v1(hashlib.sha256(_content(world, "attacker")).digest()), replay)
        a_url, b_url = default_endpoints("mainnet")
        # The second shipped server runs the indexer, the first does not — as measured.
        a = _Server({txid: raw}, indexer=False)
        b = _Server({txid: raw}, indexer=True, target=world["victim_addr"], mint=a.mint)
        servers = {a_url: a, b_url: b}
        built: list[str] = []

        import pyrxd.network.failover as failover

        def factory(profile, *_a, **_k):
            built.append(profile.endpoints[0].url)
            return servers[profile.endpoints[0].url]

        monkeypatch.setattr(failover, "FailoverElectrumXClient", factory)
        _fake_walk(monkeypatch, world["victim_addr"])

        r = _invoke(tmp_path, ["--json", *_replay_args(txid, world)])
        assert r.exit_code == EXIT_VERDICT_DOES_NOT_HOLD, r.output
        j = json.loads(r.stdout)
        # NON-VACUITY: form 2 WAS reached on the default config — the name really is ESTABLISHED
        # for the copied record, over both shipped endpoints — so the refusal is the rule's.
        assert j["records"][1]["checks"]["name"]["state"] == "ESTABLISHED"
        assert j["records"][1]["name_at_mark"]["binding_source"] == b_url
        assert set(built) == {a_url, b_url}, built
        assert b.extension_calls, "the indexer on the second shipped endpoint was asked"


class TestAQuestionAskedAndNotAnsweredFails:
    @pytest.mark.parametrize(
        ("record", "outcome"),
        [
            (_raw_record(3, 1, b"\x11" * 32), HashMarkOutcome.UNKNOWN_VERSION),
            (_raw_record(1, 0x7F, b"\x11" * 32), HashMarkOutcome.UNKNOWN_ALGORITHM),
        ],
    )
    def test_an_unreadable_record_cannot_pass_a_file_gate(self, monkeypatch, tmp_path, world, record, outcome) -> None:
        assert decode_hashmark(record).outcome is outcome, "the premise: a record this build cannot read"
        txid, raw = _tx(record)
        for how in (["--file", str(world["files"]["attacker"])], ["--digest", "00" * 32]):
            r = _run(monkeypatch, {txid: raw}, ["verify", txid, *how, "--min-confirmations", "6"], tmp_path)
            assert r.exit_code == EXIT_VERDICT_DOES_NOT_HOLD, r.output
            assert "file:       CANNOT COMPARE" in _summary(r.output)
            assert "file/digest: CANNOT COMPARE" in r.output, "the per-record line says it too"
            assert "DOES NOT MATCH" not in r.output, "an inability is not an accusation"

    def test_the_honest_pair_nothing_asked_still_holds(self, monkeypatch, tmp_path, world) -> None:
        """The VACUOUS pass, kept on purpose and documented in `verify --help`: nothing was asked
        of a record nobody can read, so nothing failed. It is not a false claim — every check says
        NOT CHECKED — and it is the reason HOLDS is defined in the help rather than assumed."""
        txid, raw = _tx(_raw_record(3, 1, b"\x11" * 32))
        r = _run(monkeypatch, {txid: raw}, ["verify", txid, "--min-confirmations", "6"], tmp_path)
        assert r.exit_code == 0, r.output
        s = _summary(r.output)
        assert "file:       NOT CHECKED" in s and "signature:  NOT CHECKED" in s

    def test_the_help_says_what_HOLDS_means(self, tmp_path) -> None:
        r = _invoke(tmp_path, ["verify", "--help"])
        flat = " ".join(r.output.split())
        assert "THE VERDICT IS ABOUT ONE RECORD" in flat
        assert "What HOLDS means, and no more" in flat
        assert "a record this build cannot read" in flat and "holds with its checks reading NOT CHECKED" in flat
        assert "CANNOT COMPARE do fail it" in flat
        # The batch consequence of the transaction-wide refusal, stated rather than implied away.
        assert "including a BATCHED transaction" in flat and "fails the verdict for an honest one beside it" in flat

    @pytest.mark.parametrize(
        ("record", "says", "must_not_say"),
        [
            (_raw_record(9, 1, b"\x11" * 32), "cannot read a version-9 record", "malformed"),
            (_raw_record(1, 0x7F, b"\x11" * 32), "names hash algorithm 0x7f", "malformed"),
            (_raw_record(1, 1, b"\x22" * 20), "malformed", "cannot read a version"),
        ],
    )
    def test_the_reason_a_file_cannot_be_compared_fits_the_record(
        self, monkeypatch, tmp_path, record, says, must_not_say
    ) -> None:
        """CANNOT COMPARE used to say "this record does not decode (unknown_version), so it commits
        to no digest" for every unreadable record. For a record from a newer version both halves
        are wrong: "does not decode" is this command's word for a MALFORMED record, and such a
        record may well commit to a digest this build cannot read."""
        txid, raw = _tx(record)
        args = ["--json", "verify", txid, "--digest", "00" * 32, "--min-confirmations", "6"]
        r = _run(monkeypatch, {txid: raw}, args, tmp_path)
        rec = json.loads(r.stdout)["records"][0]
        reason = rec["digest_match"]["reason"]
        assert rec["digest_match"]["state"] == "CANNOT COMPARE", rec["digest_match"]
        assert says in reason and must_not_say not in reason, reason
        assert "commits to no digest" not in reason
        assert rec["checks"]["digest"]["reason"] == reason, "the summary and the record say the same thing"

    def test_verify_without_a_floor_names_what_needs_it_and_the_command_to_fix(self, monkeypatch, tmp_path) -> None:
        """`pyrxd verify <txid>` — the command the public verify page points people at — was
        refused with "--wave-name needs --min-confirmations", naming a flag they had not passed."""
        txid, raw = _tx(_raw_record(1, 1, b"\x11" * 32))
        r = _run(monkeypatch, {txid: raw}, ["verify", txid.upper()], tmp_path)
        assert r.exit_code == 1, r.output
        flat = " ".join(r.output.split())
        assert "pyrxd verify needs --min-confirmations" in flat
        assert f"add --min-confirmations N to `pyrxd verify {txid}`" in flat, "the canonical txid, not the raw input"
        assert "--wave-name" not in flat, "it named a flag the user never passed"

    def test_inspect_still_says_it_is_the_name_question_that_needs_it(self, monkeypatch, tmp_path) -> None:
        """The honest pair: for `glyph inspect`, --wave-name really is what needs the floor."""
        txid, raw = _tx(_raw_record(1, 1, b"\x11" * 32))
        r = _run(monkeypatch, {txid: raw}, ["glyph", "inspect", txid, "--fetch", "--wave-name", NAME], tmp_path)
        assert r.exit_code == 1, r.output
        assert "--wave-name needs --min-confirmations" in " ".join(r.output.split())

    def test_an_unreadable_record_beside_a_good_one_does_not_block_the_good_one(
        self, monkeypatch, tmp_path, world
    ) -> None:
        """The honest pair of the refusal above: CANNOT COMPARE is a fact about ONE record, not a
        refusal of the transaction. A record from the future is not a forgery."""
        txid, raw = _tx(_signed(_content(world, "victim"), world["victim"]), _raw_record(3, 1, b"\x11" * 32))
        args = ["verify", txid, "--file", str(world["files"]["victim"]), "--min-confirmations", "6"]
        r = _run(monkeypatch, {txid: raw}, args, tmp_path)
        assert r.exit_code == 0, r.output
        assert "record:     vout 0" in _summary(r.output)


# --------------------------------------------------------------------------- the honest paths


class TestHonestWorkStillHolds:
    def test_one_record_with_an_established_name_holds_through_the_command(self, monkeypatch, tmp_path, world) -> None:
        """The composition `test_hashmark_verify_cli` could not reach: form 2 AFFIRMATIVE, end to end."""
        txid, raw = _tx(_signed(_content(world, "victim"), world["victim"]))
        args = [
            "verify",
            txid,
            "--file",
            str(world["files"]["victim"]),
            "--wave-name",
            NAME,
            "--min-confirmations",
            "6",
        ]
        r = _run(monkeypatch, {txid: raw}, args, tmp_path, name_target=world["victim_addr"])
        assert r.exit_code == 0, r.output
        s = _summary(r.output)
        assert "name:       ESTABLISHED" in s and "file:       MATCHES" in s and "signature:  VERIFIED" in s
        assert "the only HashMark record" in s
        # The qualifiers of an ESTABLISHED name reach the terminal through the real command: the
        # expiry state (it was JSON-only) and which endpoints the heights came from.
        flat = " ".join(r.output.split())
        assert "expiry at that block: unknown: renewals are decided by treasury payments" in flat
        assert "reported identically by 'wss://a' and 'wss://b'" in flat

    def test_two_records_by_one_signer_each_answer_for_their_own_file(self, monkeypatch, tmp_path, world) -> None:
        key = world["victim"]
        txid, raw = _tx(_signed(_content(world, "victim"), key), _signed(_content(world, "attacker"), key))
        for file, vout in (("victim", 0), ("attacker", 1)):
            args = [
                "--json",
                "verify",
                txid,
                "--file",
                str(world["files"][file]),
                "--wave-name",
                NAME,
                "--min-confirmations",
                "6",
            ]
            r = _run(monkeypatch, {txid: raw}, args, tmp_path, name_target=world["victim_addr"])
            assert r.exit_code == 0, r.output
            j = json.loads(r.stdout)
            assert j["verdict_record"] == {
                "vout": vout,
                "records_in_tx": 2,
                "all_record_checks_hold": True,
                "refusal_vout": None,
            }
        r = _run(
            monkeypatch,
            {txid: raw},
            ["verify", txid, "--file", str(world["files"]["other"]), "--min-confirmations", "6"],
            tmp_path,
        )
        assert r.exit_code == EXIT_VERDICT_DOES_NOT_HOLD, "a third file is neither record's"
        r = _run(monkeypatch, {txid: raw}, ["verify", txid, "--min-confirmations", "6"], tmp_path)
        assert r.exit_code == 0 and "record:     vout 0" in _summary(r.output), "nothing asked: both hold, lowest vout"

    def test_a_signed_record_is_preferred_over_a_v1_record_over_the_same_digest(
        self, monkeypatch, tmp_path, world
    ) -> None:
        content = _content(world, "victim")
        txid, raw = _tx(_v1(hashlib.sha256(content).digest()), _signed(content, world["victim"]))
        r = _run(
            monkeypatch,
            {txid: raw},
            ["verify", txid, "--file", str(world["files"]["victim"]), "--min-confirmations", "6"],
            tmp_path,
        )
        assert r.exit_code == 0, r.output
        s = _summary(r.output)
        assert "record:     vout 1" in s and "signature:  VERIFIED" in s

    def test_a_forgery_anywhere_still_fails_and_the_record_line_says_which_is_which(
        self, monkeypatch, tmp_path, world
    ) -> None:
        """The refusal comes from vout 1 while file and name are about vout 0. The record line must
        not say "all about THIS one" over a signature line that is about another record."""
        good = _signed(_content(world, "victim"), world["victim"])
        forged = bytearray(_signed(b"forged", world["attacker"]))
        forged[20] ^= 0x01
        assert decode_hashmark(bytes(forged)).ok, "well-formed, so only the signature check refuses it"
        txid, raw = _tx(good, bytes(forged))
        r = _run(
            monkeypatch,
            {txid: raw},
            ["verify", txid, "--file", str(world["files"]["victim"]), "--min-confirmations", "6"],
            tmp_path,
        )
        assert r.exit_code == EXIT_VERDICT_DOES_NOT_HOLD, r.output
        s = " ".join(_summary(r.output).split())
        assert "signature: DOES NOT VERIFY the record at vout 1" in s
        assert "file and name are about THIS one, and the signature line is about the record at vout 1" in s
        assert "all about THIS one" not in s

    def test_an_undecodable_record_anywhere_fails_too(self, monkeypatch, tmp_path, world) -> None:
        """The decode half of the same rule: a record that claims HashMark and is broken."""
        broken = _raw_record(1, 1, b"\x22" * 20)  # sha256 names 32 bytes; this carries 20
        assert decode_hashmark(broken).outcome is HashMarkOutcome.INVALID, "the premise"
        txid, raw = _tx(_signed(_content(world, "victim"), world["victim"]), broken)
        r = _run(
            monkeypatch,
            {txid: raw},
            ["--json", "verify", txid, "--file", str(world["files"]["victim"]), "--min-confirmations", "6"],
            tmp_path,
        )
        assert r.exit_code == EXIT_VERDICT_DOES_NOT_HOLD, r.output
        j = json.loads(r.stdout)
        assert j["checks"]["signature"]["state"] == "RECORD DOES NOT DECODE"
        assert j["verdict_record"]["vout"] == 0 and j["verdict_record"]["refusal_vout"] == 1


class TestABatchWithOneBadRecordFailsTheHonestOnesToo:
    """The DOCUMENTED cost of the transaction-wide refusal. A transaction can batch several
    parties' records; one party's mis-signed record fails the verdict for an honest record beside
    it. Pinned, so the help text and the behaviour cannot drift apart — and so is the part that
    makes it bearable: the honest record's own checks are all there in --json."""

    def test_it_does_not_hold_and_the_honest_record_says_it_passed_on_its_own(self, monkeypatch, tmp_path, world):
        honest = _signed(_content(world, "victim"), world["victim"])
        mis_signed = bytearray(_signed(b"a third party's document", world["attacker"]))
        mis_signed[20] ^= 0x01  # well-formed, and its signature no longer holds
        txid, raw = _tx(honest, _signed(b"another customer", PrivateKey()), bytes(mis_signed))
        args = ["--json", "verify", txid, "--file", str(world["files"]["victim"]), "--min-confirmations", "6"]
        r = _run(monkeypatch, {txid: raw}, args, tmp_path)
        assert r.exit_code == EXIT_VERDICT_DOES_NOT_HOLD, r.output
        j = json.loads(r.stdout)
        assert j["verdict_record"] == {"vout": 0, "records_in_tx": 3, "all_record_checks_hold": True, "refusal_vout": 2}
        assert {k: v["state"] for k, v in j["records"][0]["checks"].items()} == {
            "signature": "VERIFIED",
            "digest": "MATCHES",
            "name": "NOT CHECKED",
        }


class TestOneLookupPerSignerNotPerRecord:
    """--wave-name and --verify-wave each ran a network lookup for EVERY verified record — for
    --wave-name a name resolution, an anchor and a chain walk across two servers. Within one run
    the name, txid and floor are fixed, so the answer depends only on the signer."""

    def test_copies_of_one_signed_record_are_looked_up_once(self, monkeypatch, tmp_path, world) -> None:
        copy = _signed(_content(world, "victim"), world["victim"])
        other = _signed(b"someone else's document", world["attacker"])
        txid, raw = _tx(*([copy] * 5), other)
        probe: dict = {}
        args = ["--json", *_replay_args(txid, world), "--verify-wave"]
        r = _run(monkeypatch, {txid: raw}, args, tmp_path, name_target=world["victim_addr"], probe=probe)
        j = json.loads(r.stdout)
        # TWO signers, so two of each lookup — not six.
        assert probe["b"].extension_calls.count("wave.resolve") == 2, probe["b"].extension_calls
        assert len(probe["walks"]) == 2, probe["walks"]
        assert probe["a"].extension_calls.count("wave.reverse_lookup") == 2, probe["a"].extension_calls
        # And every record still carries ITS OWN signer's answer.
        names = [rec["checks"]["name"]["state"] for rec in j["records"]]
        assert names == ["ESTABLISHED"] * 5 + ["NOT THE SIGNER"], names
        assert j["records"][0]["name_at_mark"] == j["records"][4]["name_at_mark"], "one signer, one answer"

    def test_records_sharing_a_signer_get_separate_copies_of_the_answer(self, monkeypatch) -> None:
        """Not one shared dict: `verify` writes into each record's dicts afterwards, and an edit to
        one must not reach another. Driven at the attach function, with the judge replaced by a
        counter — the judge itself runs for real in the test above."""
        calls: list = []

        def judge(ctx, hm, **_):
            calls.append(hm)
            hm["name_at_mark"] = {"resolved": True, "chain": {"steps": 1}}

        monkeypatch.setattr(glyph_inspect, "_judge_one_name_at_mark", judge)
        signed = {"attestation": {"outcome": "valid", "recovered_hash160": "ab" * 20}}
        payload = {
            "txid": "cd" * 32,
            "outputs": [{"vout": i, "hashmark": json.loads(json.dumps(signed))} for i in range(3)],
        }
        glyph_inspect._attach_name_at_mark(object(), payload, name=NAME, min_confirmations=6)
        got = [row["hashmark"]["name_at_mark"] for row in payload["outputs"]]
        assert len(calls) == 1 and got[0] == got[1] == got[2]
        assert len({id(x) for x in got}) == 3, "records share one mutable answer"
        assert len({id(x["chain"]) for x in got}) == 3, "records share a nested mutable dict"


def test_the_block_is_inherited_from_the_verdicts_own_record_first() -> None:
    """Each record's name lookup runs alone and may take its binding from a different endpoint,
    so the anchor inherited from ANOTHER record may come from the server that supplied THIS
    record's binding. The record the verdict is about is asked first."""
    first = {"name_at_mark": {"resolved": True, "anchor": {"height": 1, "source": "wss://b"}}}
    witness = {"name_at_mark": {"resolved": True, "anchor": {"height": 2, "source": "wss://a"}}}
    payload = {"txid": "cd" * 32, "outputs": [{"vout": 0, "hashmark": first}, {"vout": 1, "hashmark": witness}]}
    assert hashmark_cmds._verify_anchor(object(), payload, min_confirmations=6, prefer=witness)["height"] == 2
    assert hashmark_cmds._verify_anchor(object(), payload, min_confirmations=6)["height"] == 1, "unchanged default"
