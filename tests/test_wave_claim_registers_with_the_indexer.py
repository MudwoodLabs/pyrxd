"""A WAVE claim pyrxd builds is one the public indexer registers (#728).

Through 0.24.0 ``build_wave_metadata("alice.rxd", ...)`` wrote ``attrs.name = "alice.rxd"``
and left the top-level ``name`` empty. RXinDexer registers a claim from ``attrs.name`` and its
``validate_wave_name`` refuses the ``.``, logging at debug level and returning. So, by the
indexer's source, no claim ``build_wave_metadata`` built from a QUALIFIED name was registered:
such a reveal confirms, spends its fee, and registers nothing. Given a bare label
(``build_wave_metadata("alice", ...)``) it wrote ``attrs.name = "alice"``, which does register
``alice.rxd``; ``tests/test_wave_fee_matches_the_pinned_indexer.py`` runs the indexer's own code
on both. (No pyrxd-built claim has been put to a live indexer. Hand-built CBOR of the right
shape could always be revealed through ``prepare_wave_reveal``.)
Every existing test passed, because each one checked pyrxd's output against pyrxd's own idea of
the shape; none ran it past the indexer's rule, and the one that compared against "the Photonic
shape" had hand-typed it wrong.

This file checks the shape against two things pyrxd did not write:

1. A REAL CLAIM the public indexer resolves — ``f644794b…`` in
   ``fixtures/wave_update_chain_mainnet.json`` (``custodian-gate-x7f3.rxd``, block 458585,
   reveal input 0). ``wave.resolve("custodian-gate-x7f3")`` on ``electrumx.radiantcore.org``
   returned ``ref f644794b…_0``, ``status active`` (measured 2026-09-24). Its FIELD SET and
   values are those of Photonic's ``createWaveNameMetadata``; the builder reproduces its BYTES
   from its name, target and expiry. Those bytes were NOT encoded by Photonic: they are
   canonical CBOR (short map headers, sorted keys) and carry no ``desc``, while Photonic's
   ``cbor-x`` ``encode`` writes 16-bit map headers in object order (measured with cbor-x 1.6.6
   on ``createWaveNameMetadata``'s object: ``b9 0005 61 76 …``) and its register page always
   sets ``desc`` (``WaveRegister.tsx:127``). The claim is probably hand-assembled; that is an
   inference, not established. What it proves is that this shape registers.
2. A TRANSCRIPTION of the indexer's own rules, from Radiant-Core/RXinDexer at commit
   ``ca8a6a4e77ef0ad3f24ec6f41cb0a73eb5f3651e`` (main, 2026-08-05):
   ``electrumx/server/wave_index.py`` — ``WAVE_CHARS`` / ``WAVE_MAX_NAME_LENGTH`` (37, 42),
   ``validate_wave_name`` (287-310), the claim path in ``process_tx`` (707-727), the zone
   address in ``WaveZoneRecords.from_metadata`` (189-197) and the backfill path in
   ``backfill_from_glyph_db`` (1378-1391); and ``electrumx/lib/glyph.py`` — the envelope's
   standalone-``gly`` case in ``parse_glyph_envelope`` (214-232) and the token name (672).
   Transcribed, not imported, in this file (the indexer is not a dependency);
   ``tests/test_wave_fee_matches_the_pinned_indexer.py`` runs verbatim vendored copies of
   the same code (``tests/vendor/rxindexer/``). Both files are pinned by
   digest in ``fixtures/rxindexer_upstream_pin.json`` at that commit, and
   ``scripts/check_photonic_drift.py --target rxindexer`` reports when upstream moves.

Photonic's builder is ``createWaveNameMetadata``, ``packages/lib/src/wave.ts`` lines 71-109 at
Radiant-Core/Photonic-Wallet ``becf41a731e78ab98fdd88652527d7dda12784c6``. The rule pyrxd
holds every claim to is in ``src/pyrxd/glyph/wave_rules.py``.
"""

from __future__ import annotations

import ast
import functools
import inspect
import json
import pathlib
import textwrap

import cbor2
import pytest

from pyrxd.glyph._inspect_core import _classify_metadata_protocol, _classify_raw_tx
from pyrxd.glyph.builder import CommitParams, GlyphBuilder, RevealParams
from pyrxd.glyph.fees import estimate_reveal_fee
from pyrxd.glyph.inspector import GlyphInspector
from pyrxd.glyph.payload import (
    GLY_MARKER,
    build_mutable_scriptsig,
    build_reveal_scriptsig_suffix,
    decode_payload,
    encode_payload,
)
from pyrxd.glyph.script import build_commit_locking_script, extract_payload_hash_from_commit_script, hash_payload
from pyrxd.glyph.types import GlyphMetadata, GlyphProtocol
from pyrxd.glyph.wave import (
    build_wave_metadata,
    classify_glyph_metadata,
    extract_wave_attrs,
    wave_attrs_from_metadata,
)
from pyrxd.glyph.wave_rules import wave_claim_problem, wave_registration_fee_for
from pyrxd.hash import hash256
from pyrxd.script.script import Script
from pyrxd.security.errors import ValidationError
from pyrxd.security.types import Hex20
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput

_FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "wave_update_chain_mainnet.json"
_MINT = next(t for t in json.loads(_FIXTURE.read_text())["transactions"] if t["txid"].startswith("f644794b"))
_MINT_TX = Transaction.from_hex(_MINT["raw"])
#: The claim's CBOR, exactly as it sits in the mainnet reveal's scriptSig (input 0).
_MINT_CBOR: bytes = GlyphInspector().extract_reveal_cbor(_MINT_TX.inputs[0].unlocking_script.serialize())
_MINT_DICT: dict = cbor2.loads(_MINT_CBOR)

PKH = Hex20(bytes(range(20)))
TXID = "ab" * 32
#: A real mainnet address: the claim's own target.
TARGET = _MINT_DICT["attrs"]["target"]
_SRC = pathlib.Path(__file__).resolve().parent.parent / "src" / "pyrxd"


def _old_pyrxd_claim(qualified: str = "alice.rxd", target: str = TARGET) -> dict:
    """What ``build_wave_metadata`` emitted through 0.24.0, as decoded CBOR.

    Written out rather than derived, because the code that produced it is the defect and is
    gone. The shape is the one ``test_glyph_wave.py::test_attrs_match_photonic_shape`` pinned
    before #728: qualified ``attrs.name``, ``attrs.domain``, no top-level ``name``, no ``v``,
    no ``type``.
    """
    return {
        "p": [GlyphProtocol.NFT, GlyphProtocol.MUT, GlyphProtocol.WAVE],
        "attrs": {
            "name": qualified,
            "domain": qualified.rpartition(".")[2],
            "target": target,
            "target_type": "address",
        },
    }


#: What each release from v0.6.0 to v0.24.0 produced, run from its own source.
_LEGACY: dict = json.loads(
    (pathlib.Path(__file__).parent / "fixtures" / "wave_build_metadata_v0_6_to_v0_24.json").read_text()
)


def _old_commit_bytes() -> bytes:
    """The bytes a 0.24.0 commit committed to for ``alice.rxd`` — recorded from the release."""
    assert _LEGACY["cases"]["plain"] == {"qualified_name": "alice.rxd", "target": TARGET}
    return bytes.fromhex(_LEGACY["cbor_hex"]["plain"])


# ─────────────────────────────── RXinDexer, transcribed (ca8a6a4e) ──

_WAVE_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789-"  # wave_index.py:37
_WAVE_MAX_NAME_LENGTH = 63  # wave_index.py:42


def _validate_wave_name(name: str) -> tuple[bool, str | None]:
    """wave_index.py:287-310, line for line."""
    if not name:
        return False, "Name cannot be empty"
    if len(name) > _WAVE_MAX_NAME_LENGTH:
        return False, f"Name exceeds maximum length of {_WAVE_MAX_NAME_LENGTH}"
    if name.startswith("-"):
        return False, "Name cannot start with hyphen"
    if name.endswith("-"):
        return False, "Name cannot end with hyphen"
    if "--" in name and not name.lower().startswith("xn--"):
        return False, "Name cannot contain consecutive hyphens (except Punycode prefix)"
    for char in name.lower():
        if char not in _WAVE_CHARS:
            return False, f"Invalid character: {char}"
    return True, None


def _indexer_registers(metadata: dict) -> tuple[str, str | None] | str:
    """The claim path of ``WaveIndex.process_tx`` (wave_index.py:707-727).

    Returns ``(name, parent)`` for a claim it goes on to register — ``parent`` ``None`` means
    the root, which is what ``domain == "rxd"`` folds to — or the reason it skips the claim.
    """
    attrs = metadata.get("attrs", {})
    app_data = metadata.get("app", {}).get("data", {})
    name = attrs.get("name", "") or app_data.get("name", "")
    parent_name = attrs.get("domain") if not app_data.get("parent") else app_data.get("parent")
    if parent_name == "rxd":
        parent_name = None
    if not name:
        return "has no name"
    valid, error = _validate_wave_name(name)
    if not valid:
        return f"Invalid WAVE name {name!r}: {error}"
    return name, parent_name


def _indexer_zone_address(metadata: dict) -> str | None:
    """``WaveZoneRecords.from_metadata`` (wave_index.py:189-197): what ``resolve`` returns as
    ``target``."""
    zone = metadata.get("app", {}).get("data", {}).get("zone", {})
    attrs = metadata.get("attrs", {})
    attrs_address = attrs.get("target") if attrs.get("target_type", "address") == "address" else None
    return zone.get("address") or attrs_address


def _indexer_backfills(metadata: dict) -> str | None:
    """``backfill_from_glyph_db`` (wave_index.py:1378-1391), fed the token name the glyph index
    stores (lib/glyph.py:672, ``metadata.get('name') or metadata.get('n')``). The name this
    path would register, or ``None`` if it skips the token."""
    raw_name = metadata.get("name") or metadata.get("n") or ""
    name = raw_name[:-4] if raw_name.endswith(".rxd") else raw_name
    if not name:
        return None
    valid, _ = _validate_wave_name(name)
    return name if valid else None


def _pushes(script: bytes) -> list[bytes]:
    out, i = [], 0
    while i < len(script):
        op = script[i]
        i += 1
        if 1 <= op <= 75:
            n = op
        elif op == 0x4C:
            n, i = script[i], i + 1
        elif op == 0x4D:
            n, i = int.from_bytes(script[i : i + 2], "little"), i + 2
        elif op == 0x4E:
            n, i = int.from_bytes(script[i : i + 4], "little"), i + 4
        else:
            continue
        out.append(script[i : i + n])
        i += n
    return out


def _indexer_reveal_metadata(scriptsig: bytes) -> dict | None:
    """``parse_glyph_envelope``'s standalone-``gly`` case (lib/glyph.py:214-232): the push after
    a ``gly`` push, if it decodes to a CBOR map, is a reveal carrying that metadata."""
    pushes = _pushes(scriptsig)
    for i, push in enumerate(pushes):
        if push == b"gly" and i + 1 < len(pushes) and len(pushes[i + 1]) >= 2:
            decoded = cbor2.loads(pushes[i + 1])
            if isinstance(decoded, dict):
                return decoded
    return None


class TestTheTranscriptionAgreesWithCasesWhoseAnswerIsKnown:
    """A check that cannot pass the thing known to be registered, or refuse the things its
    source refuses, has told you it is broken — not that anything else is."""

    def test_the_indexed_mainnet_claim_registers(self) -> None:
        assert _indexer_registers(_MINT_DICT) == ("custodian-gate-x7f3", None)
        assert _indexer_backfills(_MINT_DICT) == "custodian-gate-x7f3"

    @pytest.mark.parametrize(
        ("name", "reason"),
        [
            ("alice.rxd", "Invalid character: ."),
            ("-alice", "Name cannot start with hyphen"),
            ("a--b", "Name cannot contain consecutive hyphens (except Punycode prefix)"),
            ("ab-xn--c", "Name cannot contain consecutive hyphens (except Punycode prefix)"),
            ("a" * 64, "Name exceeds maximum length of 63"),
            ("", "Name cannot be empty"),
        ],
    )
    def test_it_refuses_what_upstream_refuses(self, name: str, reason: str) -> None:
        assert _validate_wave_name(name) == (False, reason)

    def test_the_envelope_reader_finds_the_mainnet_claim(self) -> None:
        assert _indexer_reveal_metadata(_MINT_TX.inputs[0].unlocking_script.serialize()) == _MINT_DICT


# ─────────────────────────────── (a) Photonic's fields, a registered claim's bytes ──


class TestTheBuilderWritesPhotonicsFields:
    def test_it_reproduces_an_indexed_mainnet_claim_byte_for_byte(self) -> None:
        """Name, target and expiry taken from the mainnet claim; the expected bytes ARE that
        claim, which the public indexer resolves. Not Photonic's encoding — see the next test."""
        md = build_wave_metadata(
            qualified_name=_MINT_DICT["name"],
            target=_MINT_DICT["attrs"]["target"],
            expires=_MINT_DICT["attrs"]["expires"],
        )
        assert encode_payload(md)[0] == _MINT_CBOR

    def test_those_bytes_are_canonical_cbor_not_photonics_encoder(self) -> None:
        """What the byte test does and does not show, made executable. Photonic's ``cbor-x``
        writes a 16-bit map header (``b9 0005``) with ``v`` first; this claim opens with a
        short header and keys in canonical order, so it is not Photonic's encoder output."""
        assert _MINT_CBOR[0] == 0xA5
        assert list(_MINT_DICT) == ["p", "v", "name", "type", "attrs"]
        assert cbor2.dumps(_MINT_DICT, canonical=True) == _MINT_CBOR
        assert "desc" not in _MINT_DICT

    def test_the_field_set_is_create_wave_name_metadatas(self) -> None:
        """``createWaveNameMetadata`` (wave.ts:89-108) writes v, p, name, type and attrs with
        name/domain/target/target_type/expires — and ``desc`` only when given."""
        md = build_wave_metadata(qualified_name="alice.rxd", target=TARGET, expires=1)
        d = cbor2.loads(encode_payload(md)[0])
        assert set(d) == {"v", "p", "name", "type", "attrs"}
        assert set(d["attrs"]) == {"name", "domain", "target", "target_type", "expires"}
        assert (d["v"], d["p"], d["name"], d["type"]) == (2, [2, 5, 11], "alice.rxd", "wave_name")

    def test_without_an_expiry_it_is_that_claim_less_attrs_expires(self) -> None:
        """Photonic always writes ``attrs.expires`` (``now + 2 years``). pyrxd writes it only
        when asked, so its bytes do not depend on the clock; the indexer stamps the real term
        from the block time and does not read this field for expiry."""
        md = build_wave_metadata(qualified_name=_MINT_DICT["name"], target=_MINT_DICT["attrs"]["target"])
        expected = {**_MINT_DICT, "attrs": {k: v for k, v in _MINT_DICT["attrs"].items() if k != "expires"}}
        assert cbor2.loads(encode_payload(md)[0]) == expected

    def test_the_fixture_is_the_shape_this_file_claims(self) -> None:
        """Non-vacuity: the byte test above is only evidence if the real claim differs from
        what pyrxd built before #728 in exactly the fields at issue."""
        assert _MINT_DICT["name"] == "custodian-gate-x7f3.rxd"
        assert _MINT_DICT["attrs"]["name"] == "custodian-gate-x7f3"
        assert (_MINT_DICT["v"], _MINT_DICT["type"]) == (2, "wave_name")


# ──────────────────────────────── (b) the regression, as the indexer sees it ──


class TestTheIndexerRegistersTheNewShapeAndNotTheOld:
    def test_the_new_shape_registers_on_both_indexer_paths(self) -> None:
        claim = cbor2.loads(encode_payload(build_wave_metadata(qualified_name="alice.rxd", target=TARGET))[0])
        assert _indexer_registers(claim) == ("alice", None)
        assert _indexer_backfills(claim) == "alice"
        assert _indexer_zone_address(claim) == TARGET

    def test_the_shape_pyrxd_built_through_0_24_0_registers_on_neither(self) -> None:
        """THE BUG. Refused on the live path for the '.', and skipped by the backfill for
        having no top-level name at all."""
        claim = _old_pyrxd_claim()
        assert _indexer_registers(claim) == "Invalid WAVE name 'alice.rxd': Invalid character: ."
        assert _indexer_backfills(claim) is None


# ─────────────────────────── (c) through the entry points that build the claim ──


class TestThroughTheProductionEntryPoint:
    def _reveal_scriptsig_suffix(self, qualified: str, *, name_arg: str | None = None) -> bytes:
        builder = GlyphBuilder()
        md = build_wave_metadata(qualified_name=qualified, target=TARGET)
        commit = builder.prepare_commit(
            CommitParams(metadata=md, owner_pkh=PKH, change_pkh=PKH, funding_satoshis=10_000_000)
        )
        scripts = builder.prepare_wave_reveal(TXID, 0, commit.cbor_bytes, PKH, name_arg or qualified)
        assert scripts.payload_hash == commit.payload_hash
        return scripts.scriptsig_suffix

    def test_the_reveal_bytes_register_the_name_asked_for(self) -> None:
        """The scriptSig bytes a caller would broadcast, read by the indexer's own envelope
        rule and claim rule — not pyrxd's."""
        metadata = _indexer_reveal_metadata(self._reveal_scriptsig_suffix("alice.rxd"))
        assert metadata is not None
        assert GlyphProtocol.WAVE in metadata["p"]
        assert _indexer_registers(metadata) == ("alice", None)
        assert _indexer_zone_address(metadata) == TARGET

    def test_a_bare_label_argument_means_the_rxd_name(self) -> None:
        metadata = _indexer_reveal_metadata(self._reveal_scriptsig_suffix("alice", name_arg="alice"))
        assert _indexer_registers(metadata) == ("alice", None)
        assert metadata["name"] == "alice.rxd"


# ───────────────────────────── the rule, on every door; and none refuses honest work ──


def _claim(label: object, **extra: object) -> dict:
    """A WAVE claim carrying ``label`` in attrs.name, otherwise in Photonic's shape."""
    d: dict = {
        "v": 2,
        "p": [GlyphProtocol.NFT, GlyphProtocol.MUT, GlyphProtocol.WAVE],
        "type": "wave_name",
        "attrs": {"name": label, "domain": "rxd", "target": TARGET, "target_type": "address"},
    }
    d.update(extra)
    return d


def _commit(d: dict) -> object:
    md = GlyphMetadata(
        protocol=d["p"],
        attrs=d.get("attrs", {}),
        name=d.get("name", "") if isinstance(d.get("name", ""), str) else "",
    )
    return GlyphBuilder().prepare_commit(
        CommitParams(metadata=md, owner_pkh=PKH, change_pkh=PKH, funding_satoshis=10_000)
    )


#: Every way to write a WAVE claim, each fed decoded CBOR. ``prepare_commit`` is the point
#: of no return; the others write an envelope. Which functions COUNT as writers is derived
#: and pinned in ``TestTheWriterSetIsDerived`` below, not trusted to this dict.
_DOORS = {
    "prepare_commit": _commit,
    "prepare_wave_reveal": lambda d: GlyphBuilder().prepare_wave_reveal(TXID, 0, cbor2.dumps(d), PKH, "alice.rxd"),
    "prepare_mutable_reveal": lambda d: GlyphBuilder().prepare_mutable_reveal(TXID, 0, cbor2.dumps(d), PKH),
    "prepare_reveal": lambda d: GlyphBuilder().prepare_reveal(
        RevealParams(
            commit_txid=TXID, commit_vout=0, commit_value=10_000, cbor_bytes=cbor2.dumps(d), owner_pkh=PKH, is_nft=True
        )
    ),
    # The two raw writers also require the caller to state the WAVE registration fee for a
    # claim that registers (tests/test_wave_registration_fee.py); stated here as the fee
    # wave_registration_fee_for derives, so these cases exercise the label rule alone.
    "build_reveal_scriptsig_suffix": lambda d: build_reveal_scriptsig_suffix(
        cbor2.dumps(d), registration_fee=wave_registration_fee_for(d)
    ),
    "build_mutable_scriptsig": lambda d: build_mutable_scriptsig(
        "mod", cbor2.dumps(d), 1, 1, 0, 0, registration_fee=wave_registration_fee_for(d)
    ),
}

#: (attrs.name, the reason it must be refused for). Asserting the REASON, not just a refusal,
#: is what stops a case passing because some other clause fired first — which is why the
#: hyphen cases are four characters, not the two-character "-a" that the length clause
#: would refuse on its own.
_REFUSED_LABELS = [
    ("alice.rxd", "contains '.'"),
    ("sub.alice", "contains '.'"),
    ("a.b.c", "contains '.'"),
    ("alice．rxd", "write a non-ASCII name as xn-- punycode"),  # U+FF0E FULLWIDTH FULL STOP
    ("Alice", "uppercase is refused"),
    ("-abc", "starts or ends with '-'"),
    ("abc-", "starts or ends with '-'"),
    ("a--b", "contains '--'"),
    # The xn-- exception is for a label that STARTS xn-- (upstream: name.lower().startswith).
    # One that merely contains it elsewhere is refused by the indexer, so it is refused here.
    ("ab-xn--c", "contains '--'"),
    ("ab", "is 2 characters"),
    ("a" * 64, "is 64 characters"),
    (b"alice", "must be text"),
    (5, "must be text"),
]
_ACCEPTED_LABELS = ["abc", "a" * 63, "xn--caf-dma", "custodian-gate-x7f3", "usdt1"]


class TestTheLabelRuleOnEveryDoor:
    @pytest.mark.parametrize("door", sorted(_DOORS))
    @pytest.mark.parametrize(("label", "reason"), _REFUSED_LABELS, ids=[repr(c[0])[:12] for c in _REFUSED_LABELS])
    def test_refused_for_its_reason(self, door: str, label: object, reason: str) -> None:
        with pytest.raises(ValidationError, match="outside the rule pyrxd writes claims by") as exc:
            _DOORS[door](_claim(label))
        assert reason in str(exc.value)

    @pytest.mark.parametrize("door", sorted(_DOORS))
    @pytest.mark.parametrize("label", _ACCEPTED_LABELS)
    def test_accepted(self, door: str, label: str) -> None:
        # prepare_wave_reveal cross-checks its name argument, so give it this claim's name.
        if door == "prepare_wave_reveal":
            assert GlyphBuilder().prepare_wave_reveal(TXID, 0, cbor2.dumps(_claim(label)), PKH, f"{label}.rxd")
        else:
            assert _DOORS[door](_claim(label)) is not None

    @pytest.mark.parametrize("label", _ACCEPTED_LABELS)
    def test_every_accepted_label_the_indexer_also_accepts(self, label: str) -> None:
        """The rule is an INTERSECTION: nothing pyrxd accepts may be something the indexer
        refuses. (The converse is deliberate: 1-2 character labels, which RXinDexer alone
        allows.)"""
        assert _indexer_registers(_claim(label)) == (label, None)

    @pytest.mark.parametrize(("label", "reason"), [c for c in _REFUSED_LABELS if isinstance(c[0], str)])
    def test_the_builder_refuses_the_same_labels(self, label: str, reason: str) -> None:
        with pytest.raises(ValidationError):
            build_wave_metadata(qualified_name=f"{label}.rxd", target=TARGET)


#: The doors that take raw CBOR. ``prepare_commit`` takes a ``GlyphMetadata``, which has no
#: ``app`` field and types ``attrs`` as a dict, so it cannot WRITE an ``app.data`` name or
#: parent or a non-map ``attrs`` — those cases exist only on the doors below.
_CBOR_DOORS = sorted(d for d in _DOORS if d != "prepare_commit")


class TestTheDomainAndTheNameTheIndexerReads:
    """The indexer reads the name from attrs.name, then app.data.name, and the parent from
    app.data.parent, then attrs.domain (wave_index.py:711-717). The rule reads the same."""

    @pytest.mark.parametrize("door", sorted(_DOORS))
    def test_a_domain_other_than_rxd_is_refused(self, door: str) -> None:
        claim = _claim("alice")
        claim["attrs"]["domain"] = "evil"
        assert _indexer_registers(claim) == ("alice", "evil")  # a subdomain, to the indexer
        with pytest.raises(ValidationError, match="parent/domain 'evil'"):
            _DOORS[door](claim)

    def test_an_uppercase_domain_is_refused_not_folded(self) -> None:
        """The indexer compares the parent with 'rxd' exactly (wave_index.py:716), so 'RXD'
        is looked up as a parent name, not treated as the root."""
        claim = _claim("alice")
        claim["attrs"]["domain"] = "RXD"
        assert _indexer_registers(claim) == ("alice", "RXD")
        with pytest.raises(ValidationError, match="parent/domain 'RXD'"):
            _DOORS["prepare_commit"](claim)
        with pytest.raises(ValidationError, match="must be lowercase"):
            build_wave_metadata(qualified_name="alice.RXD", target=TARGET)

    def test_a_missing_domain_is_the_root_and_is_accepted(self) -> None:
        claim = _claim("alice")
        del claim["attrs"]["domain"]
        assert _indexer_registers(claim) == ("alice", None)
        assert _DOORS["build_reveal_scriptsig_suffix"](claim)

    @pytest.mark.parametrize("door", _CBOR_DOORS)
    def test_an_app_data_name_is_checked_when_attrs_has_none(self, door: str) -> None:
        claim = _claim("")
        claim["app"] = {"data": {"name": "alice.rxd"}}
        assert _indexer_registers(claim) == "Invalid WAVE name 'alice.rxd': Invalid character: ."
        with pytest.raises(ValidationError, match=r"attrs\.name 'alice\.rxd' contains '\.'"):
            _DOORS[door](claim)

    @pytest.mark.parametrize("door", _CBOR_DOORS)
    def test_a_parent_hidden_in_app_data_is_refused(self, door: str) -> None:
        claim = _claim("alice", app={"data": {"parent": "bob"}})
        assert _indexer_registers(claim) == ("alice", "bob")
        with pytest.raises(ValidationError, match="parent/domain 'bob'"):
            _DOORS[door](claim)

    @pytest.mark.parametrize("door", _CBOR_DOORS)
    def test_a_second_name_in_app_data_is_refused(self, door: str) -> None:
        claim = _claim("alice", app={"data": {"name": "bob"}})
        with pytest.raises(ValidationError, match="name different claims"):
            _DOORS[door](claim)

    @pytest.mark.parametrize("door", sorted(_DOORS))
    def test_a_top_level_name_naming_something_else_is_refused(self, door: str) -> None:
        """The live indexer registers from attrs; its backfill registers from the top-level
        name. A payload where they disagree registers two different names."""
        claim = _claim("alice", name="bob.rxd")
        assert _indexer_registers(claim) == ("alice", None) and _indexer_backfills(claim) == "bob"
        with pytest.raises(ValidationError, match="names a different claim"):
            _DOORS[door](claim)

    @pytest.mark.parametrize("door", _CBOR_DOORS)
    def test_a_top_level_n_naming_something_else_is_refused(self, door: str) -> None:
        """``n`` is the short key the glyph index reads when ``name`` is absent
        (lib/glyph.py:672, ``metadata.get('name') or metadata.get('n')``), so the backfill would
        register ``bob`` from it. ``GlyphMetadata`` cannot write ``n``; the CBOR doors can."""
        claim = _claim("alice", n="bob.rxd")
        assert _indexer_registers(claim) == ("alice", None) and _indexer_backfills(claim) == "bob"
        with pytest.raises(ValidationError, match="top-level n 'bob.rxd' names a different claim"):
            _DOORS[door](claim)

    @pytest.mark.parametrize("door", _CBOR_DOORS)
    def test_unreadable_attrs_is_refused(self, door: str) -> None:
        claim = _claim("alice")
        claim["attrs"] = ["alice"]
        with pytest.raises(ValidationError, match="not a map"):
            _DOORS[door](claim)

    @pytest.mark.parametrize("door", _CBOR_DOORS)
    @pytest.mark.parametrize("app", ["not-a-map", {"data": "not-a-map"}, {"data": ["x"]}], ids=["app", "data", "list"])
    def test_an_unreadable_app_or_app_data_is_refused_not_crashed(self, door: str, app: object) -> None:
        """RXinDexer does ``metadata.get('app', {}).get('data', {})`` (wave_index.py:712): a
        non-map there raises inside the indexer, which skips the claim. The rule must say so as
        a ``ValidationError`` — an ``AttributeError`` escaping it would reach callers as a crash
        from a builder, not a refusal they can read."""
        claim = _claim("alice", app=app)
        with pytest.raises(ValidationError, match=r"attrs, app or app\.data is not a map"):
            _DOORS[door](claim)


class TestPInEveryContainerTheIndexerSearches:
    """RXinDexer asks ``GLYPH_WAVE not in protocols`` (``wave_index.py:685``) of
    ``protocols = metadata.get('p', [])`` (``glyph_index.py:872``), with GLYPH_WAVE the int 11.
    That is Python's ``in``: true for a byte string and a map as well as a list. The rule
    checked a list or tuple only, so ``p: h'02050b'`` with ``attrs.name: "alice.rxd"`` passed
    every writer while the indexer read it as a registration and refused the name."""

    FORMS = {"bytes": b"\x02\x05\x0b", "map": {2: True, 5: True, 11: True}}

    @pytest.mark.parametrize("form", sorted(FORMS))
    def test_the_indexer_reads_it_as_wave_marked(self, form: str) -> None:
        assert 11 in self.FORMS[form]  # wave_index.py:685, transcribed

    @pytest.mark.parametrize("door", _CBOR_DOORS)
    @pytest.mark.parametrize("form", sorted(FORMS))
    def test_an_unregistrable_claim_is_refused(self, door: str, form: str) -> None:
        claim = _old_pyrxd_claim()
        claim["p"] = self.FORMS[form]
        with pytest.raises(ValidationError) as exc:
            _DOORS[door](claim)
        # prepare_wave_reveal wants p as an array and says so first; every other door is
        # reached only through the rule.
        expected = (
            "must include GlyphProtocol.WAVE"
            if door == "prepare_wave_reveal"
            else "outside the rule pyrxd writes claims by"
        )
        assert expected in str(exc.value)

    @pytest.mark.parametrize("door", [d for d in _CBOR_DOORS if d != "prepare_wave_reveal"])
    @pytest.mark.parametrize("form", sorted(FORMS))
    def test_a_registrable_claim_is_accepted(self, door: str, form: str) -> None:
        """The honest half: the rule judges the NAME, not the container ``p`` came in."""
        claim = _claim("alice")
        claim["p"] = self.FORMS[form]
        assert _DOORS[door](claim) is not None

    def test_prepare_commit_cannot_write_one(self) -> None:
        with pytest.raises(ValidationError, match="protocol must be a list"):
            GlyphMetadata(protocol=self.FORMS["bytes"], attrs={"name": "alice.rxd"})  # type: ignore[arg-type]

    @pytest.mark.parametrize("p", ["\x02\x05\x0b", 11, None], ids=["text", "int", "null"])
    def test_a_p_the_indexer_cannot_search_is_not_a_claim(self, p: object) -> None:
        """For these ``in`` raises TypeError in the indexer — first at ``get_token_type``
        (lib/glyph.py:727) — which aborts that transaction's glyph overlay, so nothing is
        registered and nothing is refused here either."""
        with pytest.raises(TypeError):
            assert 11 in p  # type: ignore[operator]  # raises before it can assert
        claim = _old_pyrxd_claim()
        claim["p"] = p
        assert wave_claim_problem(claim) is None


class TestATopLevelOnlyClaimIsRefused:
    """Older pyrxd put the name only at the top level. The indexer's LIVE claim path, which is
    how a new claim is registered, skips it; only a backfill of an empty index reads it."""

    def _legacy(self) -> dict:
        return {"p": [GlyphProtocol.NFT, GlyphProtocol.MUT, GlyphProtocol.WAVE], "name": "alice.rxd"}

    def test_the_live_path_skips_it_and_the_backfill_would_not(self) -> None:
        assert _indexer_registers(self._legacy()) == "has no name"
        assert _indexer_backfills(self._legacy()) == "alice"

    @pytest.mark.parametrize("door", sorted(_DOORS))
    def test_refused(self, door: str) -> None:
        with pytest.raises(ValidationError, match="carries no attrs.name"):
            _DOORS[door](self._legacy())

    def test_a_wave_marked_payload_that_is_not_a_claim_is_refused_too(self) -> None:
        """Photonic's commit-reveal ``wave_commit`` metadata is WAVE-marked with no attrs.name.
        pyrxd has no flow that writes one, and the rule cannot tell it from a claim that lost
        its name, so it is refused. Recorded so the choice is visible."""
        commitment = {
            "p": [2, 5, 11],
            "name": "wave_commit_ab12cd34",
            "type": "wave_commit",
            "attrs": {"commitment": "ab" * 32, "revealAfterHeight": 1, "owner": TARGET},
        }
        assert wave_claim_problem(commitment) is not None


class TestTheRuleLeavesOtherPayloadsAlone:
    def test_a_dot_in_a_non_wave_attrs_name_is_not_touched(self) -> None:
        """The rule is about WAVE claims. An ordinary NFT called ``photo.png`` is honest."""
        cbor = encode_payload(GlyphMetadata(protocol=[GlyphProtocol.NFT], attrs={"name": "photo.png"}))[0]
        assert build_reveal_scriptsig_suffix(cbor).startswith(b"\x03" + GLY_MARKER)

    def test_an_update_envelope_without_p_is_not_touched(self) -> None:
        """RXinDexer reads only ``target`` from a ``p``-less update, so the name in it decides
        nothing — and a holder of a pre-0.25 name must still be able to write one."""
        cbor = cbor2.dumps({"attrs": {"name": "alice.rxd", "domain": "rxd", "target": TARGET}})
        assert build_mutable_scriptsig("mod", cbor, 1, 1, 0, 0)


# ──────────────────── the escape: recovering a commit pyrxd <=0.24.0 already broadcast ──


class TestACommitMadeBy024CanStillBeRevealed:
    """A 0.24.0 commit can only be spent by revealing the exact CBOR it commits to. Refusing
    that reveal would strand the commit's value, so the reveal paths take an explicit escape.
    The commit path does not: a new commit with this shape is the bug."""

    def test_the_commit_path_refuses_and_has_no_escape(self) -> None:
        with pytest.raises(ValidationError, match="outside the rule pyrxd writes claims by"):
            _commit(_old_pyrxd_claim())
        assert "allow_unregistrable_wave" not in CommitParams.__dataclass_fields__

    def test_the_reveal_is_refused_by_default(self) -> None:
        with pytest.raises(ValidationError, match="allow_unregistrable_wave=True"):
            GlyphBuilder().prepare_wave_reveal(TXID, 0, _old_commit_bytes(), PKH, "alice.rxd")

    def test_the_reveal_is_built_with_the_escape_and_spends_that_commit(self) -> None:
        old = _old_commit_bytes()
        scripts = GlyphBuilder().prepare_wave_reveal(TXID, 0, old, PKH, "alice.rxd", allow_unregistrable_wave=True)
        assert scripts.payload_hash == hash_payload(old)  # the hash the 0.24.0 commit locked
        assert _indexer_reveal_metadata(scripts.scriptsig_suffix) == cbor2.loads(old)
        # ...and, as the docstring says, the claim so revealed does not register.
        assert _indexer_registers(cbor2.loads(old)).startswith("Invalid WAVE name")

    def test_the_escape_still_checks_the_name_is_the_payloads(self) -> None:
        with pytest.raises(ValidationError, match="not a name this CBOR carries"):
            GlyphBuilder().prepare_wave_reveal(
                TXID, 0, _old_commit_bytes(), PKH, "bob.rxd", allow_unregistrable_wave=True
            )

    def test_the_other_reveal_paths_take_the_escape_too(self) -> None:
        old = _old_commit_bytes()
        assert GlyphBuilder().prepare_mutable_reveal(TXID, 0, old, PKH, allow_unregistrable_wave=True)
        assert GlyphBuilder().prepare_reveal(
            RevealParams(
                commit_txid=TXID,
                commit_vout=0,
                commit_value=10_000,
                cbor_bytes=old,
                owner_pkh=PKH,
                is_nft=True,
                allow_unregistrable_wave=True,
            )
        )
        assert build_reveal_scriptsig_suffix(old, allow_unregistrable_wave=True)

    def test_the_recovery_reveal_can_be_priced(self) -> None:
        assert estimate_reveal_fee(cbor_bytes=_old_commit_bytes(), is_nft=True).fee > 0

    def test_an_update_has_no_escape(self) -> None:
        """An update payload is chosen fresh, so refusing one strands nothing."""
        with pytest.raises(TypeError):
            build_mutable_scriptsig("mod", _old_commit_bytes(), 1, 1, 0, 0, allow_unregistrable_wave=True)  # type: ignore[call-arg]


_HEX_MARKER = "676c79"  # b"gly".hex()


def _is_marker_literal(node: ast.AST) -> bool:
    """A literal that IS the marker: ``b"gly"``, ``"gly"``, or its hex ``"676c79"`` (str or bytes)."""
    return isinstance(node, ast.Constant) and node.value in (b"gly", "gly", _HEX_MARKER, _HEX_MARKER.encode())


def _carries_marker_literal(node: ast.AST) -> bool:
    """A literal that CARRIES the marker somewhere in it: bytes containing ``b"gly"`` or its hex,
    or text containing the hex (``"aa20…03676c7988"``). Text containing ``"gly"`` is NOT matched —
    every docstring that says "glyph" would — only text that is exactly ``"gly"``."""
    if not isinstance(node, ast.Constant):
        return False
    value = node.value
    if isinstance(value, bytes):
        return b"gly" in value or _HEX_MARKER.encode() in value
    if isinstance(value, str):
        return value == "gly" or _HEX_MARKER in value
    return False


def _marker_names(trees: list[ast.Module]) -> set[str]:
    """Every name that holds the marker, derived to a fixpoint across ``src/pyrxd``.

    A name joins when it is the target of an assignment at module or class level, or of an
    attribute assignment anywhere (``self._m = ...``), whose value mentions an exact marker
    literal or a name already found — so ``GLY_MARKER = b"gly"``, ``GLYPH_MAGIC_BYTES =
    bytes.fromhex("676c79")`` and ``_MARK = GLY_MARKER`` are all found without being listed —
    and when it is the ``as`` name of an import of a name already found.
    """

    def mentions(value: ast.AST, names: set[str]) -> bool:
        return any(
            _is_marker_literal(n)
            or (isinstance(n, ast.Name) and n.id in names)
            or (isinstance(n, ast.Attribute) and n.attr in names)
            for n in ast.walk(value)
        )

    def scoped(tree: ast.Module) -> list[ast.stmt]:
        out = list(tree.body)
        for cls in (n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)):
            out.extend(cls.body)
        out.extend(
            n
            for n in ast.walk(tree)
            if isinstance(n, ast.Assign) and any(isinstance(t, ast.Attribute) for t in n.targets)
        )
        return out

    statements = [stmt for tree in trees for stmt in scoped(tree)]
    names: set[str] = set()
    changed = True
    while changed:
        changed = False
        for stmt in statements:
            new: set[str] = set()
            if isinstance(stmt, (ast.Assign, ast.AnnAssign)) and stmt.value is not None and mentions(stmt.value, names):
                targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
                for target in targets:
                    new |= {n.id for n in ast.walk(target) if isinstance(n, ast.Name)}
                    new |= {n.attr for n in ast.walk(target) if isinstance(n, ast.Attribute)}
            elif isinstance(stmt, ast.ImportFrom):
                new = {a.asname for a in stmt.names if a.name in names and a.asname}
            if new - names:
                names |= new
                changed = True
    return names


@functools.lru_cache(maxsize=1)
def _src_trees() -> dict[str, ast.Module]:
    """Every module under src/pyrxd, parsed once per session."""
    return {str(p.relative_to(_SRC)): ast.parse(p.read_text(encoding="utf-8")) for p in sorted(_SRC.rglob("*.py"))}


def _marker_functions(extra_files: dict[str, str] | None = None) -> set[tuple[str, str]]:
    """Every function in ``src/pyrxd`` that touches the ``gly`` marker, in any spelling
    :func:`_marker_names` and :func:`_carries_marker_literal` recognise. ``extra_files`` adds
    source as if it were in the tree — how the plants in ``TestTheWriterScanSeesEverySpelling``
    are fed in without writing into ``src/``."""
    trees = dict(_src_trees())
    trees.update({rel: ast.parse(text) for rel, text in (extra_files or {}).items()})
    names = _marker_names(list(trees.values()))
    found = set()
    for rel, tree in trees.items():
        for fn in ast.walk(tree):
            if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)) and any(
                (isinstance(n, ast.Name) and n.id in names)
                or (isinstance(n, ast.Attribute) and n.attr in names)
                or _carries_marker_literal(n)
                for n in ast.walk(fn)
            ):
                found.add((rel, fn.name))
    return found


class TestTheRecoveryRecipe:
    """``prepare_wave_reveal`` documents how to rebuild a <=0.24.0 commit's bytes. The recipe is
    run here FROM THE DOCSTRING and held to what every release that shipped
    ``build_wave_metadata`` actually produced (``scripts/record_legacy_wave_bytes.py`` ran each
    release's own source), so neither the prose nor the fixture can drift from the other."""

    @staticmethod
    def _docstring_block() -> str:
        doc = inspect.getdoc(GlyphBuilder.prepare_wave_reveal) or ""
        lines = doc.splitlines()
        start = next(i for i, line in enumerate(lines) if line.rstrip().endswith("reproduces them::")) + 1
        block: list[str] = []
        for line in lines[start:]:
            if line.strip() and not line.startswith("    "):
                break
            block.append(line)
        return textwrap.dedent("\n".join(block))

    @classmethod
    def _run(cls, case: dict, *, domain: str | None = None) -> bytes:
        qualified = case["qualified_name"]
        namespace = {
            "qualified_name": qualified,
            # "the text after its LAST '.', or 'rxd' if none", as the docstring says
            "domain": domain if domain is not None else (qualified.rpartition(".")[2] if "." in qualified else "rxd"),
            "target": case["target"],
            "target_type": case.get("target_type", "address"),
            "description": case.get("description", ""),
        }
        exec(compile(cls._docstring_block(), "prepare_wave_reveal docstring", "exec"), namespace)
        out: bytes = namespace["old_cbor"]
        return out

    def test_the_record_covers_every_release_and_they_all_agree(self) -> None:
        assert _LEGACY["releases"][0] == "v0.6.0" and _LEGACY["releases"][-1] == "v0.24.0"
        assert _LEGACY["disagreements"] == {}
        assert set(_LEGACY["cbor_hex"]) == set(_LEGACY["cases"])

    def test_the_docstring_block_is_the_recipe(self) -> None:
        """Non-vacuity: the extraction found code, not an empty block."""
        block = self._docstring_block()
        assert "encode_payload(" in block and "old_cbor" in block

    @pytest.mark.parametrize("case", sorted(_LEGACY["cases"]))
    def test_the_recipe_reproduces_what_the_releases_wrote(self, case: str) -> None:
        assert self._run(_LEGACY["cases"][case]).hex() == _LEGACY["cbor_hex"][case]

    def test_the_last_dot_instruction_is_load_bearing(self) -> None:
        """Split on the FIRST dot, as the current builder does, and the multi-dot case no
        longer matches — so a recovery that reused parse_wave_name's split would be rejected."""
        case = _LEGACY["cases"]["multi-dot"]
        assert self._run(case, domain="alice.rxd").hex() != _LEGACY["cbor_hex"]["multi-dot"]

    def test_the_hand_written_old_shape_is_what_the_releases_wrote(self) -> None:
        assert cbor2.loads(bytes.fromhex(_LEGACY["cbor_hex"]["plain"])) == _old_pyrxd_claim()

    def test_the_rebuilt_bytes_match_the_commit_and_the_reveal_spends_it(self) -> None:
        old = self._run(_LEGACY["cases"]["plain"])
        commit_script = build_commit_locking_script(hash_payload(old), PKH, is_nft=True)
        assert extract_payload_hash_from_commit_script(commit_script) == hash_payload(old)
        scripts = GlyphBuilder().prepare_wave_reveal(TXID, 0, old, PKH, "alice.rxd", allow_unregistrable_wave=True)
        assert scripts.payload_hash == hash_payload(old)


class TestTheWriterSetIsDerived:
    """Every function in src/pyrxd that touches the ``gly`` marker, found by walking the AST —
    not a hand-kept list of doors. A new one fails here until someone says what it is.

    WHAT THE SCAN SEES: a reference, by bare name or as an attribute (``payload.GLY_MARKER``),
    to any name that holds the marker, where those names are DERIVED (module- and class-level
    assignments, attribute assignments, ``import ... as``, to a fixpoint — see
    :func:`_marker_names`); a bytes literal containing ``b"gly"``; a literal exactly ``"gly"``;
    and a str or bytes literal containing the hex ``676c79``, which covers
    ``bytes.fromhex("676c79")``.

    WHAT IT DOES NOT SEE: a marker assembled at run time (``b"g" + b"ly"``,
    ``bytes([0x67, 0x6C, 0x79])``, ``getattr(payload, "GLY_" + "MARKER")``), a marker that
    reaches a function only as an argument (the caller is found, the callee is not), and a
    function-local alias used in some OTHER function. Those are not claimed.
    """

    #: REVIEWED, not derived: why each member is or is not a WAVE door. The membership is
    #: pinned exactly, so adding or removing a function forces this table to be re-read.
    _MEMBERS = {
        ("glyph/payload.py", "build_reveal_scriptsig_suffix"): "WRITER — must call the rule",
        ("glyph/payload.py", "build_mutable_scriptsig"): "WRITER — must call the rule",
        (
            "glyph/payload.py",
            "build_dat_reveal_scriptsig_suffix",
        ): "DAT: 'dat' follows 'gly', so the indexer does not read it as a claim",
        ("glyph/burn.py", "build_burn_proof_script"): "burn proof: a 1-byte push follows 'gly' (lib/glyph.py:218)",
        ("glyph/timelock_reveal_tx.py", "create_reveal_proof"): "timelock proof: a 1-byte push follows 'gly'",
        ("glyph/script.py", "build_commit_locking_script"): "commit script: checks the marker, carries no payload",
        ("glyph/script.py", "build_dat_commit_locking_script"): "commit script: checks the marker, carries no payload",
        ("glyph/burn.py", "parse_burn_proof"): "reader",
        ("glyph/inspector.py", "_parse_reveal_scriptsig"): "reader",
        ("glyph/inspector.py", "classify_glyph_scriptsig"): "reader",
        ("glyph/inspector.py", "extract_reveal_cbor"): "reader",
        ("glyph/mutable_chain.py", "_envelope_of"): "reader",
        ("glyph/timelock_reveal_tx.py", "parse_reveal_proof_script"): "reader",
        # The registration fee reads a reveal's envelope to learn the name it registers.
        ("glyph/wave_rules.py", "registered_label_in_scriptsig"): "reader",
        ("glyph/fees.py", "_reveal_envelope_label"): "reader",
    }

    @staticmethod
    def _functions(pred) -> set[tuple[str, str]]:  # type: ignore[no-untyped-def]
        found = set()
        for path in sorted(_SRC.rglob("*.py")):
            for fn in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)) and any(pred(n) for n in ast.walk(fn)):
                    found.add((str(path.relative_to(_SRC)), fn.name))
        return found

    def test_the_marker_names_are_derived_not_listed(self) -> None:
        """Non-vacuity for the derivation: the two names the code really uses are FOUND, from
        their literals, not seeded."""
        assert {"GLY_MARKER", "GLYPH_MAGIC_BYTES"} <= _marker_names(list(_src_trees().values()))

    def test_the_set_is_exactly_the_reviewed_one(self) -> None:
        found = _marker_functions()
        assert found, "the scan found nothing — it is broken, not the codebase"
        assert found == set(self._MEMBERS)

    def test_each_writer_and_the_commit_path_calls_the_rule(self) -> None:
        callers = self._functions(
            lambda n: (
                isinstance(n, ast.Call)
                and isinstance(n.func, ast.Name)
                and n.func.id == "refuse_unregistrable_wave_claim"
            )
        )
        writers = {k for k, why in self._MEMBERS.items() if why.startswith("WRITER")}
        assert writers <= callers
        assert ("glyph/builder.py", "prepare_commit") in callers


#: Each a spelling of the marker the scan must see, fed in as an extra source file or appended
#: to a real one. The review planted these into the tree and the previous scan missed all four.
_SPELLINGS = {
    "A1-attribute-in-new-file": (
        "glyph/_planted_writer.py",
        "sneak",
        "from . import payload\n\n\ndef sneak(cbor):\n    return b'\\x03' + payload.GLY_MARKER + cbor\n",
    ),
    "A2-module-level-fromhex": (
        "glyph/_planted_fromhex.py",
        "sneak",
        "_M = bytes.fromhex('676c79')\n\n\ndef sneak(cbor):\n    return b'\\x03' + _M + cbor\n",
    ),
    "A3-attribute-in-builder": (
        "glyph/builder.py",
        "_sneak",
        "\n\nfrom . import payload as _p\n\n\ndef _sneak(cbor):\n    return b'\\x03' + _p.GLY_MARKER + cbor\n",
    ),
    "A4-alias-in-payload": (
        "glyph/payload.py",
        "_sneak",
        "\n\n_MARK = GLY_MARKER\n\n\ndef _sneak(cbor):\n    return b'\\x03' + _MARK + cbor\n",
    ),
}


class TestTheWriterScanSeesEverySpelling:
    @pytest.mark.parametrize("spelling", sorted(_SPELLINGS))
    def test_a_planted_writer_is_found(self, spelling: str) -> None:
        rel, function, code = _SPELLINGS[spelling]
        existing = _SRC / rel
        source = (existing.read_text(encoding="utf-8") if existing.exists() else "") + code
        found = _marker_functions({rel: source})
        assert (rel, function) in found
        assert found != set(TestTheWriterSetIsDerived._MEMBERS)  # so the pinned test would fail


# ──────────────────────────────── (d) readers accept both shapes, verbatim ──


def _tx_carrying(cbor: bytes) -> tuple[str, bytes]:
    """A transaction whose input carries ``cbor`` the way a claim already ON CHAIN does —
    written directly, because pyrxd's writers now refuse the old shape."""
    push = bytes([len(cbor)]) if len(cbor) <= 75 else b"\x4c" + bytes([len(cbor)])
    tx = Transaction(
        tx_inputs=[
            TransactionInput(
                source_txid="a" * 64,
                source_output_index=0,
                unlocking_script=Script(b"\x03" + GLY_MARKER + push + cbor),
            )
        ],
        tx_outputs=[TransactionOutput(Script(b"\x6a"), 0)],
    )
    raw = bytes(tx.serialize())
    return hash256(raw)[::-1].hex(), raw


class TestReadersAcceptBothShapes:
    def test_the_photonic_claim_reads_as_the_label_and_its_domain(self) -> None:
        md = decode_payload(_MINT_CBOR)
        attrs = wave_attrs_from_metadata(md)
        assert (attrs.name, attrs.domain) == ("custodian-gate-x7f3", "rxd")
        assert md.name == "custodian-gate-x7f3.rxd"
        assert classify_glyph_metadata(md) == _classify_metadata_protocol(md) == "wave"
        result = _classify_raw_tx(_MINT["txid"], bytes.fromhex(_MINT["raw"]))
        assert (result["metadata"]["classification"], result["metadata"]["name"]) == ("wave", "custodian-gate-x7f3.rxd")

    def test_a_pre_0_25_pyrxd_claim_still_reads_verbatim(self) -> None:
        """Not re-qualified to ``alice.rxd.rxd``, not stripped to ``alice``: the reader reports
        what the chain says. Any pyrxd release through 0.24.0 could have minted one (none has
        been located on mainnet yet), and refusing to read them would hide them from the
        people who paid for them."""
        cbor = cbor2.dumps(_old_pyrxd_claim())
        md = decode_payload(cbor)
        attrs = wave_attrs_from_metadata(md)
        assert (attrs.name, attrs.domain, attrs.target) == ("alice.rxd", "rxd", TARGET)
        assert extract_wave_attrs(cbor2.loads(cbor)) == attrs
        assert classify_glyph_metadata(md) == _classify_metadata_protocol(md) == "wave"
        txid, raw = _tx_carrying(cbor)
        result = _classify_raw_tx(txid, raw)
        assert (result["metadata"]["classification"], result["metadata"]["name"]) == ("wave", "")

    def test_the_longest_wave_name_round_trips(self) -> None:
        """A 63-character label makes a 67-character top-level name. The decoder capped
        ``name`` at 64 and dropped it; the cap is now RXinDexer's 200 (glyph_index.py:1465)."""
        qualified = "a" * 63 + ".rxd"
        md = decode_payload(encode_payload(build_wave_metadata(qualified_name=qualified, target=TARGET))[0])
        assert md.name == qualified
        assert wave_attrs_from_metadata(md).name == "a" * 63


# ──────────────────────────────────────────── (e) the honest path ──


class TestTheHonestPath:
    @pytest.mark.parametrize("qualified", ["alice.rxd", "alice"])
    def test_an_ordinary_name_builds_and_the_reveal_validates(self, qualified: str) -> None:
        md = build_wave_metadata(qualified_name=qualified, target=TARGET, description="hi")
        assert (md.name, md.attrs["name"], md.attrs["domain"], md.description) == ("alice.rxd", "alice", "rxd", "hi")
        cbor = encode_payload(md)[0]
        assert GlyphBuilder().prepare_wave_reveal(TXID, 0, cbor, PKH, qualified).nft_script

    def test_photonics_other_builder_writes_the_label_at_the_top_and_is_accepted(self) -> None:
        """``createWaveName`` (``packages/lib/src/wavenaming.ts``) with no domain option writes
        the bare label at the top level. The indexer registers it from attrs all the same."""
        cbor = cbor2.dumps(
            {
                "v": 2,
                "p": [2, 5, 11],
                "name": "alice",
                "type": "wave_name",
                "attrs": {"name": "alice", "target": TARGET, "domain": "rxd", "target_type": "address"},
            }
        )
        assert _indexer_registers(cbor2.loads(cbor)) == ("alice", None)
        assert GlyphBuilder().prepare_wave_reveal(TXID, 0, cbor, PKH, "alice.rxd").nft_script

    def test_a_name_argument_that_is_not_the_claim_is_refused(self) -> None:
        cbor = encode_payload(build_wave_metadata(qualified_name="alice.rxd", target=TARGET))[0]
        with pytest.raises(ValidationError, match="does not match the claim in the CBOR"):
            GlyphBuilder().prepare_wave_reveal(TXID, 0, cbor, PKH, "bob.rxd")

    @pytest.mark.parametrize(
        ("qualified", "reason"),
        [
            ("sub.alice.rxd", "more than one '.'"),
            ("sub.alice", "has domain 'alice'"),
            ("alice.RXD", "must be lowercase"),
            ("alice.eth", "has domain 'eth'"),
        ],
    )
    def test_a_name_that_is_not_label_dot_rxd_is_refused(self, qualified: str, reason: str) -> None:
        """Subdomains are 'Planned' in the WAVE protocol (ANNOUNCEMENT.md:70). pyrxd used to
        split on the LAST dot, so ``sub.alice`` built ``('sub', 'alice')`` — a subdomain claim
        under a message saying none was built."""
        with pytest.raises(ValidationError, match=reason):
            build_wave_metadata(qualified_name=qualified, target=TARGET)
        with pytest.raises(ValidationError, match=reason):
            GlyphBuilder().prepare_wave_reveal(TXID, 0, cbor2.dumps(_claim("alice")), PKH, qualified)

    @pytest.mark.parametrize("bad", [True, -1, 1.5, "1850743929"])
    def test_an_unusable_expires_is_refused(self, bad: object) -> None:
        with pytest.raises(ValidationError, match="expires"):
            build_wave_metadata(qualified_name="alice.rxd", target=TARGET, expires=bad)  # type: ignore[arg-type]
