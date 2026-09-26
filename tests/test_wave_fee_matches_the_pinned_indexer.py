"""pyrxd's WAVE fee decision, graded by RXinDexer's OWN code at the pinned commit.

Whether a reveal owes the WAVE registration fee is whether the indexer registers the name it
carries, and the fee is the indexer's price for that name paid to the indexer's treasury. pyrxd
decides all three itself (``wave_registered_label``, ``wave_registration_price``,
``WaveRegistrationFee.locking_script`` in ``src/pyrxd/glyph/wave_rules.py``). Until this file,
every test of those decisions compared pyrxd with pyrxd, or with a second transcription of
RXinDexer written into a test file (0.25.0 pre-release panel, reviewer D).

Here the grader is RXinDexer itself: ``WaveIndex.process_tx``, ``wave_name_price`` and the
treasury script the index builds, imported from the verbatim copies under
``tests/vendor/rxindexer/`` (see its README, and ``tests/rxindexer_oracle.py`` for the one
transcribed step). The first class proves those copies ARE the code the drift pin pins.

The CLI half — ``pyrxd glyph mint-nft``'s actual reveal registering the name it pays for — is in
``tests/cli/test_wave_registration_fee_cli.py`` (``test_the_reveal_spends_the_commit_and_its_change…``)
and ``tests/cli/test_wave_mint_cli_panel_fixes.py``, graded by the same oracle.
"""

from __future__ import annotations

import json
import pathlib

import cbor2
import pytest

from pyrxd.glyph.builder import GlyphBuilder, RevealParams
from pyrxd.glyph.payload import build_reveal_scriptsig_suffix, encode_payload
from pyrxd.glyph.wave import build_wave_metadata
from pyrxd.glyph.wave_rules import (
    WAVE_TREASURY_ADDRESS,
    WaveRegistrationFee,
    refuse_unregistrable_wave_claim,
    wave_registered_label,
    wave_registration_fee_for,
)
from pyrxd.script.type import encode_pushdata
from pyrxd.security.errors import ValidationError
from pyrxd.security.types import Hex20
from tests import rxindexer_oracle as oracle

TARGET = "1BoatSLRHtKNngkdXEeobR76b53LETtpyT"
_LEGACY: dict = json.loads(
    (pathlib.Path(__file__).parent / "fixtures" / "wave_build_metadata_v0_6_to_v0_24.json").read_text()
)


def _reveal_input_script(cbor: bytes) -> bytes:
    """``<sig> <pubkey> "gly" <cbor>`` as pyrxd's envelope writer lays it out; the signature and
    key are placeholders (the indexer does not verify them — consensus already has)."""
    suffix = build_reveal_scriptsig_suffix(cbor, allow_unregistrable_wave=True, registration_fee=None)
    return encode_pushdata(b"\x30" * 71) + encode_pushdata(b"\x02" * 33) + suffix


def _indexer_verdict(cbor: bytes) -> oracle.Verdict:
    tx = oracle.UpTx([oracle.UpIn(_reveal_input_script(cbor), b"\x01" * 32, 0)], [oracle.UpOut(b"\x51", 1)])
    return oracle.registers(tx)


def _claim(label: str) -> bytes:
    return encode_payload(build_wave_metadata(qualified_name=f"{label}.rxd", target=TARGET))[0]


# ───────────────────────────────────────── the oracle is the pinned code ──


class TestTheVendoredIndexerIsThePinnedOne:
    def test_every_vendored_byte_is_the_manifests(self) -> None:
        files = oracle.manifest()["files"]
        assert files, "an empty manifest checks nothing"
        for rel, digest in files.items():
            assert oracle.sha256_file(oracle.VENDOR_DIR / rel) == digest, rel

    def test_the_files_on_disk_are_exactly_the_manifests(self) -> None:
        """Both directions: an unlisted file is unchecked code; a listed, missing one is a check
        that has stopped running."""
        on_disk = {
            p.relative_to(oracle.VENDOR_DIR).as_posix()
            for p in oracle.VENDOR_DIR.rglob("*")
            if p.is_file() and "__pycache__" not in p.parts
        } - {"MANIFEST.json", "README.md"}
        assert on_disk == set(oracle.manifest()["files"])

    def test_the_pinned_files_carry_the_pins_digests_at_the_pins_commit(self) -> None:
        manifest, pin = oracle.manifest(), oracle.pin()
        assert (manifest["repo"], manifest["commit"]) == (pin["repo"], pin["commit"])
        shared = set(manifest["files"]) & set(pin["files"])
        # Non-vacuity: the claim path and the envelope parser are the files that matter.
        assert {"electrumx/server/wave_index.py", "electrumx/lib/glyph.py"} <= shared
        for rel in shared:
            assert manifest["files"][rel] == pin["files"][rel], rel

    def test_the_licence_is_mit_and_keeps_its_notices(self) -> None:
        text = (oracle.VENDOR_DIR / "LICENCE").read_text()
        assert "The MIT License (MIT)" in text
        assert "Copyright (c) 2016-2017, Neil Booth" in text
        assert "Radiant Community Devs" in text

    def test_the_code_imported_is_the_vendored_code(self) -> None:
        glyph, wave_index = oracle.upstream()
        for module in (glyph, wave_index):
            assert pathlib.Path(module.__file__).resolve().is_relative_to(oracle.VENDOR_DIR.resolve())


# ───────────────────────────────────────── the fee decision is the indexer's ──

#: Payloads whose parent is the ``rxd`` root, so an empty index decides them exactly as a live one
#: would for a free name. Built by pyrxd, written by pyrxd <=0.24.0, and hand-made shapes pyrxd
#: refuses to write but the indexer reads — the fee must follow the INDEXER on all of them.
_ROOT_PARENT: list = [
    *(pytest.param(_claim(label), id=f"built-{label}") for label in ("abc", "abcd", "abcde", "xn--caf-dma")),
    pytest.param(_claim("custodian-gate-x7f3"), id="built-6plus"),
    *(pytest.param(bytes.fromhex(hx), id=f"v0.24-{case}") for case, hx in sorted(_LEGACY["cbor_hex"].items())),
    pytest.param(cbor2.dumps({"p": [2, 5, 11], "attrs": {"name": "ab"}}), id="two-chars"),
    pytest.param(cbor2.dumps({"p": [2, 5, 11], "attrs": {"name": "a"}}), id="one-char"),
    pytest.param(cbor2.dumps({"p": [2, 5, 11], "attrs": {"name": "Alice"}}), id="upper-case"),
    pytest.param(cbor2.dumps({"p": [2, 5, 11], "attrs": {"name": "alice.rxd"}}), id="dotted"),
    pytest.param(cbor2.dumps({"p": [2, 5, 11], "attrs": {"name": "-alice"}}), id="leading-hyphen"),
    pytest.param(cbor2.dumps({"p": [2, 5, 11], "attrs": {"name": "al--ice"}}), id="double-hyphen"),
    pytest.param(cbor2.dumps({"p": [2, 5, 11], "attrs": {"name": "a" * 64}}), id="64-chars"),
    pytest.param(cbor2.dumps({"p": [2, 5, 11], "attrs": {"name": "a" * 63}}), id="63-chars"),
    pytest.param(cbor2.dumps({"p": [2, 5, 11], "app": {"data": {"name": "bob"}}}), id="app-data-name"),
    pytest.param(cbor2.dumps({"p": [2, 5, 11], "name": "bob.rxd"}), id="top-level-name-only"),
    pytest.param(cbor2.dumps({"p": [2, 5, 11], "name": "bob.rxd", "attrs": {"name": "alice"}}), id="names-differ"),
    pytest.param(cbor2.dumps({"p": b"\x02\x05\x0b", "attrs": {"name": "alice"}}), id="p-as-bytes"),
    pytest.param(cbor2.dumps({"p": {11: 1}, "attrs": {"name": "alice"}}), id="p-as-map"),
    pytest.param(cbor2.dumps({"p": "wave", "attrs": {"name": "alice"}}), id="p-as-text"),
    pytest.param(cbor2.dumps({"p": [2, 5], "attrs": {"name": "alice"}}), id="not-wave"),
    pytest.param(cbor2.dumps({"p": [2, 5, 11], "attrs": ["alice"]}), id="attrs-not-a-map"),
]


class TestTheFeeFollowsTheIndexer:
    @pytest.mark.parametrize("cbor", _ROOT_PARENT)
    def test_pyrxd_charges_for_exactly_what_the_indexer_registers(self, cbor: bytes) -> None:
        verdict = _indexer_verdict(cbor)
        assert wave_registered_label(cbor) == verdict.label
        fee = wave_registration_fee_for(cbor)
        if verdict.label is None:
            assert fee is None
        else:
            assert verdict.canonical, "a fresh index registers the first claim as canonical"
            assert fee is not None
            assert fee.value == oracle.price(verdict.label)
            assert fee.locking_script == oracle.treasury_script()

    def test_the_corpus_has_both_verdicts(self) -> None:
        """Non-vacuity: a corpus the indexer registers all of (or none of) cannot tell a rule that
        charges everything, or nothing, from the right one."""
        verdicts = [_indexer_verdict(p.values[0]).label for p in _ROOT_PARENT]
        assert sum(v is None for v in verdicts) >= 5 and sum(v is not None for v in verdicts) >= 5

    @pytest.mark.parametrize("label", ["a", "ab", "abc", "abcd", "abcde", "abcdef", "a" * 63])
    def test_every_tier_is_the_indexers_price(self, label: str) -> None:
        assert WaveRegistrationFee(label).value == oracle.price(label)

    def test_the_published_treasury_is_the_one_the_indexer_checks_renewals_against(self) -> None:
        assert WaveRegistrationFee("alice").locking_script == oracle.treasury_script()
        _glyph, wave_index = oracle.upstream()
        assert wave_index.WAVE_TREASURY_ADDRESS_DEFAULT == WAVE_TREASURY_ADDRESS

    def test_a_parent_other_than_rxd_is_charged_though_an_empty_index_registers_nothing(self) -> None:
        """The one DELIBERATE difference, documented on wave_registered_label: a non-root parent
        registers only if that parent exists in the index, which no offline check can know, so
        pyrxd charges (never under-pays). Pinned so a change to either side is seen."""
        cbor = cbor2.dumps({"p": [2, 5, 11], "attrs": {"name": "bob", "domain": "alice"}})
        assert _indexer_verdict(cbor).label is None
        assert wave_registered_label(cbor) == "bob"


# ─────────────────── what the 0.24.0 builder wrote, and what the recovery flag reveals ──


class TestWhatTheOldBuilderWroteAndWhatRecoveryReveals:
    """The facts behind two sentences that were false (panel D-I3): "no claim this function built
    was registered" (a bare label registered), and "the claim so revealed WILL NOT REGISTER"
    (``allow_unregistrable_wave=True`` reveals claims the indexer registers)."""

    @pytest.mark.parametrize("case", ["plain", "description", "multi-dot", "non-ascii", "target-type"])
    def test_a_qualified_name_the_old_builder_wrote_registers_nothing(self, case: str) -> None:
        cbor = bytes.fromhex(_LEGACY["cbor_hex"][case])
        assert "." in cbor2.loads(cbor)["attrs"]["name"]
        assert _indexer_verdict(cbor).label is None and wave_registered_label(cbor) is None

    def test_a_bare_label_the_old_builder_wrote_registers_and_owes_the_fee(self) -> None:
        assert _LEGACY["cases"]["no-dot"]["qualified_name"] == "alice"
        cbor = bytes.fromhex(_LEGACY["cbor_hex"]["no-dot"])
        assert _indexer_verdict(cbor) == oracle.Verdict("alice.rxd", True)
        assert wave_registration_fee_for(cbor) == WaveRegistrationFee("alice")

    @pytest.mark.parametrize("name", ["ab", "Alice"])
    def test_the_recovery_flag_can_reveal_a_claim_that_registers_and_the_fee_is_charged(self, name: str) -> None:
        cbor = cbor2.dumps({"p": [2, 5, 11], "attrs": {"name": name, "domain": "rxd", "target": TARGET}})
        with pytest.raises(ValidationError):
            refuse_unregistrable_wave_claim(cbor)  # pyrxd will not write it...
        scripts = GlyphBuilder().prepare_reveal(
            RevealParams(
                commit_txid="ab" * 32,
                commit_vout=0,
                commit_value=10_000_000,
                cbor_bytes=cbor,
                owner_pkh=Hex20(bytes(20)),
                is_nft=True,
                allow_unregistrable_wave=True,
            )
        )
        # ...but the recovery flag reveals it, the indexer registers it, and the fee is owed.
        script = encode_pushdata(b"\x30" * 71) + encode_pushdata(b"\x02" * 33) + scripts.scriptsig_suffix
        verdict = oracle.registers(oracle.UpTx([oracle.UpIn(script, b"\x01" * 32, 0)], [oracle.UpOut(b"\x51", 1)]))
        assert verdict == oracle.Verdict(f"{name}.rxd", True)
        assert scripts.registration_fee_output == WaveRegistrationFee(name)
        assert scripts.registration_fee_output.value == oracle.price(name)
