"""A WAVE claim pyrxd builds is one the public indexer registers (#728).

Through 0.24.0 ``build_wave_metadata("alice.rxd", ...)`` wrote ``attrs.name = "alice.rxd"``
and left the top-level ``name`` empty. RXinDexer registers a claim from ``attrs.name`` and its
``validate_wave_name`` refuses the ``.``, logging at debug level and returning. So, by the
indexer's source, such a reveal confirms, spends its fee, and registers nothing. (Read from
source: no pyrxd-built claim has been put to a live indexer.) Every existing test passed,
because each one checked pyrxd's output against pyrxd's own idea of the shape; none ran it past
the indexer's rule, and the one that compared against "the Photonic shape" had hand-typed it
wrong.

This file checks the shape against two things pyrxd did not write:

1. A REAL CLAIM built by Photonic and indexed on mainnet — ``f644794b…`` in
   ``fixtures/wave_update_chain_mainnet.json`` (``custodian-gate-x7f3.rxd``, block 458585,
   reveal input 0). The builder has to reproduce it byte for byte from its own name, target
   and expiry.
2. A TRANSCRIPTION of the indexer's own rules, from Radiant-Core/RXinDexer at commit
   ``ca8a6a4e77ef0ad3f24ec6f41cb0a73eb5f3651e`` (main, 2026-08-05):
   ``electrumx/server/wave_index.py`` — ``WAVE_CHARS`` / ``WAVE_MAX_NAME_LENGTH`` (37, 42),
   ``validate_wave_name`` (287-310), the claim path in ``process_tx`` (707-727), the zone
   address in ``WaveZoneRecords.from_metadata`` (189-197) and the backfill path in
   ``backfill_from_glyph_db`` (1378-1391); and ``electrumx/lib/glyph.py`` — the envelope's
   standalone-``gly`` case in ``parse_glyph_envelope`` (214-232) and the token name (672).
   Transcribed, not imported: the indexer is not a dependency. If upstream changes these
   lines, this file is stale and has to be re-read against them.

Photonic's builder is ``createWaveNameMetadata``, ``packages/lib/src/wave.ts`` lines 71-109 at
Radiant-Core/Photonic-Wallet ``becf41a731e78ab98fdd88652527d7dda12784c6``.
"""

from __future__ import annotations

import json
import pathlib

import cbor2
import pytest

from pyrxd.glyph._inspect_core import _classify_metadata_protocol, _classify_raw_tx
from pyrxd.glyph.builder import CommitParams, GlyphBuilder, RevealParams
from pyrxd.glyph.inspector import GlyphInspector
from pyrxd.glyph.payload import (
    GLY_MARKER,
    build_mutable_scriptsig,
    build_reveal_scriptsig_suffix,
    decode_payload,
    encode_payload,
)
from pyrxd.glyph.types import GlyphMetadata, GlyphProtocol
from pyrxd.glyph.wave import (
    build_wave_metadata,
    classify_glyph_metadata,
    extract_wave_attrs,
    wave_attrs_from_metadata,
)
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
            ("a" * 64, "Name exceeds maximum length of 63"),
            ("", "Name cannot be empty"),
        ],
    )
    def test_it_refuses_what_upstream_refuses(self, name: str, reason: str) -> None:
        assert _validate_wave_name(name) == (False, reason)

    def test_the_envelope_reader_finds_the_mainnet_claim(self) -> None:
        assert _indexer_reveal_metadata(_MINT_TX.inputs[0].unlocking_script.serialize()) == _MINT_DICT


# ─────────────────────────────────────────── (a) Photonic's shape ──


class TestTheBuilderBuildsPhotonicsShape:
    def test_it_reproduces_a_real_photonic_claim_byte_for_byte(self) -> None:
        """Name, target and expiry taken from the mainnet claim; the expected bytes ARE the
        mainnet claim. Nothing here is pyrxd's own idea of the shape."""
        md = build_wave_metadata(
            qualified_name=_MINT_DICT["name"],
            target=_MINT_DICT["attrs"]["target"],
            expires=_MINT_DICT["attrs"]["expires"],
        )
        assert encode_payload(md)[0] == _MINT_CBOR

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


# ─────────────────────────── (c) through the entry point that builds the reveal ──


class TestThroughTheProductionEntryPoint:
    def _reveal_scriptsig_suffix(self, qualified: str, *, name_arg: str | None = None) -> bytes:
        builder = GlyphBuilder()
        md = build_wave_metadata(qualified_name=qualified, target=TARGET)
        commit = builder.prepare_commit(
            CommitParams(metadata=md, owner_pkh=PKH, change_pkh=PKH, funding_satoshis=10_000_000)
        )
        scripts = builder.prepare_wave_reveal(TXID, 0, commit.cbor_bytes, PKH, name_arg or qualified)
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


# ───────────────────── every writer refuses the old shape; none refuses honest work ──


def _old_cbor() -> bytes:
    return cbor2.dumps(_old_pyrxd_claim())


def _new_cbor() -> bytes:
    return encode_payload(build_wave_metadata(qualified_name="alice.rxd", target=TARGET))[0]


#: Each builder that writes a reveal or update envelope, called on one payload. The refusal
#: lives in the two envelope writers, so these are the DOORS to them, not the check itself.
_WRITERS = {
    "prepare_wave_reveal": lambda cbor: GlyphBuilder().prepare_wave_reveal(TXID, 0, cbor, PKH, "alice.rxd"),
    "prepare_mutable_reveal": lambda cbor: GlyphBuilder().prepare_mutable_reveal(TXID, 0, cbor, PKH),
    "prepare_reveal": lambda cbor: GlyphBuilder().prepare_reveal(
        RevealParams(commit_txid=TXID, commit_vout=0, commit_value=10_000, cbor_bytes=cbor, owner_pkh=PKH, is_nft=True)
    ),
    "build_reveal_scriptsig_suffix": build_reveal_scriptsig_suffix,
    "build_mutable_scriptsig": lambda cbor: build_mutable_scriptsig("mod", cbor, 1, 1, 0, 0),
}


class TestEveryWriterRefusesTheOldShape:
    @pytest.mark.parametrize("writer", sorted(_WRITERS))
    def test_refused(self, writer: str) -> None:
        with pytest.raises(ValidationError, match=r"attrs\.name 'alice\.rxd' is a qualified name"):
            _WRITERS[writer](_old_cbor())

    @pytest.mark.parametrize("writer", sorted(_WRITERS))
    def test_the_photonic_shape_passes(self, writer: str) -> None:
        assert _WRITERS[writer](_new_cbor()) is not None

    def test_a_dot_in_a_non_wave_attrs_name_is_not_touched(self) -> None:
        """The rule is about WAVE claims. An ordinary NFT called ``photo.png`` is honest."""
        cbor = encode_payload(GlyphMetadata(protocol=[GlyphProtocol.NFT], attrs={"name": "photo.png"}))[0]
        assert build_reveal_scriptsig_suffix(cbor).startswith(b"\x03" + GLY_MARKER)

    def test_an_update_envelope_without_p_is_not_touched(self) -> None:
        """RXinDexer reads only ``target`` from a ``p``-less update, so the name in it decides
        nothing — and a holder of a pre-0.25 name must still be able to write one."""
        cbor = cbor2.dumps({"attrs": {"name": "alice.rxd", "domain": "rxd", "target": TARGET}})
        assert build_mutable_scriptsig("mod", cbor, 1, 1, 0, 0)


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
        cbor = _old_cbor()
        md = decode_payload(cbor)
        attrs = wave_attrs_from_metadata(md)
        assert (attrs.name, attrs.domain, attrs.target) == ("alice.rxd", "rxd", TARGET)
        assert extract_wave_attrs(cbor2.loads(cbor)) == attrs
        assert classify_glyph_metadata(md) == _classify_metadata_protocol(md) == "wave"
        txid, raw = _tx_carrying(cbor)
        result = _classify_raw_tx(txid, raw)
        assert (result["metadata"]["classification"], result["metadata"]["name"]) == ("wave", "")


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

    def test_a_top_level_name_naming_something_else_is_refused(self) -> None:
        """The live indexer registers from attrs; its backfill registers from the top-level
        name. A payload where they disagree registers two different names."""
        claim = cbor2.loads(_new_cbor())
        claim["name"] = "bob.rxd"
        assert _indexer_registers(claim) == ("alice", None) and _indexer_backfills(claim) == "bob"
        with pytest.raises(ValidationError, match="disagrees with attrs"):
            GlyphBuilder().prepare_wave_reveal(TXID, 0, cbor2.dumps(claim), PKH, "alice.rxd")

    def test_a_name_argument_that_is_not_the_claim_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="does not match the CBOR's attrs"):
            GlyphBuilder().prepare_wave_reveal(TXID, 0, _new_cbor(), PKH, "bob.rxd")

    def test_a_label_with_a_dot_is_refused_by_the_builder(self) -> None:
        """``foo.bar.rxd`` cannot be a single label, and Photonic's split would register
        ``foo`` under ``bar`` — a different name from the one asked for."""
        with pytest.raises(ValidationError, match="contains '.'"):
            build_wave_metadata(qualified_name="foo.bar.rxd", target=TARGET)

    @pytest.mark.parametrize("bad", [True, -1, 1.5, "1850743929"])
    def test_an_unusable_expires_is_refused(self, bad: object) -> None:
        with pytest.raises(ValidationError, match="expires"):
            build_wave_metadata(qualified_name="alice.rxd", target=TARGET, expires=bad)  # type: ignore[arg-type]
