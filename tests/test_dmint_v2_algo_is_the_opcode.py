"""A V2 contract's proof-of-work algorithm is the hash opcode the covenant runs, not its tag.

The V2 state carries an ``algoId`` tag, but the covenant never reads it: the hash it runs is
the opcode right after Part A. ``DmintState.from_script`` used to report the tag, so a contract
whose tag said SHA256D over an ``OP_BLAKE3`` covenant passed every "pyrxd grinds SHA256d only"
check, and ``build_dmint_mint_tx`` built a mint for it. The parser now takes the algorithm from
the opcode and refuses a script whose tag disagrees; the mint funnel refuses a code section that
does not open with Part A and the state's own opcode.
"""

from __future__ import annotations

import pytest

from pyrxd.glyph.dmint import (
    DaaMode,
    DmintAlgo,
    DmintContractUtxo,
    DmintDeployParams,
    DmintMinerFundingUtxo,
    DmintState,
    build_dmint_contract_script,
    build_dmint_mint_tx,
)
from pyrxd.glyph.dmint.builders import _PART_A, _POW_HASH_OP, build_dmint_state_script
from pyrxd.glyph.types import GlyphRef
from pyrxd.security.errors import ValidationError
from tests.test_dmint_deploy_bounds import TestOneTargetFormulaForEveryAlgorithm

_LAST = 1_700_000_000


def _params(algo: DmintAlgo) -> DmintDeployParams:
    return DmintDeployParams(
        contract_ref=GlyphRef(txid="aa" * 32, vout=1),
        token_ref=GlyphRef(txid="aa" * 32, vout=0),
        max_height=100,
        reward=1000,
        difficulty=10,
        algo=algo,
        daa_mode=DaaMode.FIXED,
        last_time=_LAST,
    )


def _op_offset(algo: DmintAlgo) -> int:
    """Where the hash opcode sits: right after the state, its 0xbd, and Part A."""
    return len(build_dmint_state_script(_params(algo))) + 1 + len(_PART_A)


def _with_opcode(algo: DmintAlgo, op: int) -> bytes:
    script = build_dmint_contract_script(_params(algo))
    i = _op_offset(algo)
    assert script[i : i + 1] == _POW_HASH_OP[algo]
    return script[:i] + bytes([op]) + script[i + 1 :]


def _mint(utxo: DmintContractUtxo):
    funding = DmintMinerFundingUtxo(
        txid="ee" * 32, vout=0, value=50_000_000, script=b"\x76\xa9\x14" + bytes(20) + b"\x88\xac"
    )
    return build_dmint_mint_tx(utxo, b"\x00" * 8, b"\x22" * 20, _LAST + 60, funding_utxo=funding)


class TestTheParserTakesTheAlgorithmFromTheOpcode:
    @pytest.mark.parametrize("algo", list(DmintAlgo))
    def test_a_consistent_contract_parses_to_its_opcodes_algorithm(self, algo: DmintAlgo) -> None:
        """The honest path, every algorithm: tag and opcode agree, the parse reports that one."""
        assert DmintState.from_script(build_dmint_contract_script(_params(algo))).algo is algo

    @pytest.mark.parametrize("name", sorted(TestOneTargetFormulaForEveryAlgorithm._MAINNET))
    def test_mainnet_blake3_and_k12_contracts_still_parse(self, name: str) -> None:
        script = bytes.fromhex(TestOneTargetFormulaForEveryAlgorithm._MAINNET[name][2])
        assert DmintState.from_script(script).algo is not DmintAlgo.SHA256D

    @pytest.mark.parametrize(
        ("tag", "planted"),
        [
            (DmintAlgo.SHA256D, DmintAlgo.BLAKE3),
            (DmintAlgo.SHA256D, DmintAlgo.K12),
            (DmintAlgo.BLAKE3, DmintAlgo.SHA256D),
        ],
    )
    def test_a_tag_that_disagrees_with_the_opcode_is_refused_naming_both(
        self, tag: DmintAlgo, planted: DmintAlgo
    ) -> None:
        """The reviewer's plant: only the opcode after Part A flipped; the tag unchanged."""
        script = _with_opcode(tag, _POW_HASH_OP[planted][0])
        with pytest.raises(
            ValidationError,
            match=rf"algoId tag says {tag.name}, but the covenant hashes the proof of work with {planted.name}",
        ):
            DmintState.from_script(script)

    def test_an_opcode_that_is_no_known_hash_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="is not OP_HASH256, OP_BLAKE3 or OP_K12"):
            DmintState.from_script(_with_opcode(DmintAlgo.SHA256D, 0xA8))  # OP_SHA256


class TestTheMintFunnelChecksTheOpcode:
    def test_a_state_object_that_disagrees_with_the_script_is_refused_before_any_grind(self) -> None:
        """The mint builder takes the caller's DmintContractUtxo, whose state need not come from
        its script — the reviewer's case: a SHA256D state over a script whose covenant runs
        OP_BLAKE3 used to build a mint. The builder reads the script itself and refuses."""
        good = build_dmint_contract_script(_params(DmintAlgo.SHA256D))
        flipped = _with_opcode(DmintAlgo.SHA256D, _POW_HASH_OP[DmintAlgo.BLAKE3][0])
        stale = DmintContractUtxo(txid="dd" * 32, vout=0, value=1, script=flipped, state=DmintState.from_script(good))
        with pytest.raises(
            ValidationError, match="algoId tag says SHA256D, but the covenant hashes the proof of work with BLAKE3"
        ):
            _mint(stale)
        _mint(DmintContractUtxo(txid="dd" * 32, vout=0, value=1, script=good, state=DmintState.from_script(good)))

    def test_a_code_section_without_part_a_is_refused_in_fixed_mode_too(self) -> None:
        """No DAA fragment check runs for FIXED, so this is the only thing between another
        template and a grind. The parser reads such a script (by its tag); the mint refuses."""
        good = build_dmint_contract_script(_params(DmintAlgo.SHA256D))
        start = len(build_dmint_state_script(_params(DmintAlgo.SHA256D))) + 1
        other = good[:start] + b"\x51\x75" + good[start:]  # an OP_1 OP_DROP prefix, as older templates carry
        st_ = DmintState.from_script(other)
        with pytest.raises(ValidationError, match="does not open with the Part A template"):
            _mint(DmintContractUtxo(txid="dd" * 32, vout=0, value=1, script=other, state=st_))
