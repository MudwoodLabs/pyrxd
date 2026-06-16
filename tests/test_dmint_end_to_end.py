"""Tests for the dMint end-to-end pipeline (v1.0 blocker items).

Covers:
1. DmintState.from_script() — round-trip parser against build_dmint_contract_script()
2. GlyphBuilder.prepare_dmint_deploy() — commit/reveal/deploy script builder
3. build_dmint_mint_tx() — mint transaction builder
"""

from __future__ import annotations

import pytest

from pyrxd.glyph.builder import (
    DmintV2DeployParams,
    DmintV2DeployResult,
    GlyphBuilder,
)
from pyrxd.glyph.dmint import (
    MAX_SHA256D_TARGET,
    MAX_V2_TARGET_256,
    DaaMode,
    DmintAlgo,
    DmintContractUtxo,
    DmintDeployParams,
    DmintMinerFundingUtxo,
    DmintState,
    build_dmint_contract_script,
    build_dmint_mint_tx,
)
from pyrxd.glyph.types import GlyphMetadata, GlyphRef
from pyrxd.security.errors import ValidationError

# ---------------------------------------------------------------------------
# Shared test fixtures
# ---------------------------------------------------------------------------

_CONTRACT_REF = GlyphRef(txid="aa" * 32, vout=1)
_TOKEN_REF = GlyphRef(txid="bb" * 32, vout=2)

_BASE_PARAMS = DmintDeployParams(
    contract_ref=_CONTRACT_REF,
    token_ref=_TOKEN_REF,
    max_height=1_000,
    reward=100,
    difficulty=10,
)

_ASERT_PARAMS = DmintDeployParams(
    contract_ref=_CONTRACT_REF,
    token_ref=_TOKEN_REF,
    max_height=5_000,
    reward=200,
    difficulty=5,
    algo=DmintAlgo.SHA256D,
    daa_mode=DaaMode.ASERT,
    target_time=120,
    half_life=3_600,
    height=42,
    last_time=1_700_000_000,
)

_LWMA_PARAMS = DmintDeployParams(
    contract_ref=_CONTRACT_REF,
    token_ref=_TOKEN_REF,
    max_height=20_000,
    reward=50,
    difficulty=100,
    algo=DmintAlgo.BLAKE3,
    daa_mode=DaaMode.LWMA,
    target_time=60,
    height=0,
    last_time=0,
)


# ---------------------------------------------------------------------------
# 1. DmintState.from_script() — round-trip tests
# ---------------------------------------------------------------------------


class TestDmintStateFromScript:
    """Round-trip: build_dmint_contract_script → DmintState.from_script."""

    def _round_trip(self, params: DmintDeployParams) -> DmintState:
        script = build_dmint_contract_script(params)
        return DmintState.from_script(script)

    def test_height_round_trips(self):
        state = self._round_trip(_BASE_PARAMS)
        assert state.height == _BASE_PARAMS.height

    def test_height_nonzero_round_trips(self):
        params = DmintDeployParams(
            contract_ref=_CONTRACT_REF,
            token_ref=_TOKEN_REF,
            max_height=100,
            reward=10,
            difficulty=5,
            height=999,
        )
        state = self._round_trip(params)
        assert state.height == 999

    def test_contract_ref_round_trips(self):
        state = self._round_trip(_BASE_PARAMS)
        assert state.contract_ref == _CONTRACT_REF

    def test_token_ref_round_trips(self):
        state = self._round_trip(_BASE_PARAMS)
        assert state.token_ref == _TOKEN_REF

    def test_max_height_round_trips(self):
        state = self._round_trip(_BASE_PARAMS)
        assert state.max_height == _BASE_PARAMS.max_height

    def test_reward_round_trips(self):
        state = self._round_trip(_BASE_PARAMS)
        assert state.reward == _BASE_PARAMS.reward

    def test_algo_sha256d_round_trips(self):
        state = self._round_trip(_BASE_PARAMS)
        assert state.algo == DmintAlgo.SHA256D

    def test_algo_blake3_round_trips(self):
        params = DmintDeployParams(
            contract_ref=_CONTRACT_REF,
            token_ref=_TOKEN_REF,
            max_height=100,
            reward=10,
            difficulty=5,
            algo=DmintAlgo.BLAKE3,
        )
        state = self._round_trip(params)
        assert state.algo == DmintAlgo.BLAKE3

    def test_algo_k12_round_trips(self):
        params = DmintDeployParams(
            contract_ref=_CONTRACT_REF,
            token_ref=_TOKEN_REF,
            max_height=100,
            reward=10,
            difficulty=5,
            algo=DmintAlgo.K12,
        )
        state = self._round_trip(params)
        assert state.algo == DmintAlgo.K12

    def test_daa_mode_fixed_round_trips(self):
        state = self._round_trip(_BASE_PARAMS)
        assert state.daa_mode == DaaMode.FIXED

    def test_daa_mode_asert_round_trips(self):
        state = self._round_trip(_ASERT_PARAMS)
        assert state.daa_mode == DaaMode.ASERT

    def test_daa_mode_lwma_round_trips(self):
        state = self._round_trip(_LWMA_PARAMS)
        assert state.daa_mode == DaaMode.LWMA

    def test_target_time_round_trips(self):
        state = self._round_trip(_ASERT_PARAMS)
        assert state.target_time == _ASERT_PARAMS.target_time

    def test_last_time_zero_round_trips(self):
        state = self._round_trip(_BASE_PARAMS)
        assert state.last_time == 0

    def test_last_time_nonzero_round_trips(self):
        state = self._round_trip(_ASERT_PARAMS)
        assert state.last_time == _ASERT_PARAMS.last_time

    def test_target_sha256d_round_trips(self):
        state = self._round_trip(_BASE_PARAMS)
        expected = MAX_SHA256D_TARGET // _BASE_PARAMS.difficulty
        assert state.target == expected

    def test_target_blake3_round_trips(self):
        state = self._round_trip(_LWMA_PARAMS)
        expected = MAX_V2_TARGET_256 // _LWMA_PARAMS.difficulty
        assert state.target == expected

    def test_full_state_object_equality(self):
        """All fields: DmintState rebuilt from script equals hand-constructed expected."""
        state = self._round_trip(_ASERT_PARAMS)
        assert state.height == _ASERT_PARAMS.height
        assert state.contract_ref == _ASERT_PARAMS.contract_ref
        assert state.token_ref == _ASERT_PARAMS.token_ref
        assert state.max_height == _ASERT_PARAMS.max_height
        assert state.reward == _ASERT_PARAMS.reward
        assert state.algo == _ASERT_PARAMS.algo
        assert state.daa_mode == _ASERT_PARAMS.daa_mode
        assert state.target_time == _ASERT_PARAMS.target_time
        assert state.last_time == _ASERT_PARAMS.last_time
        assert state.target == _ASERT_PARAMS.initial_target

    def test_is_exhausted_false_when_below_max_height(self):
        state = self._round_trip(_BASE_PARAMS)
        assert not state.is_exhausted

    def test_is_exhausted_true_when_at_max_height(self):
        params = DmintDeployParams(
            contract_ref=_CONTRACT_REF,
            token_ref=_TOKEN_REF,
            max_height=5,
            reward=10,
            difficulty=1,
            height=5,
        )
        state = self._round_trip(params)
        assert state.is_exhausted

    def test_no_state_separator_raises(self):
        """A script that doesn't contain a valid state-then-separator must
        raise ValidationError. Post-N7, the parser walks the layout
        first instead of pre-slicing on 0xbd, so this kind of bogus
        input fails on the layout check (0x00 is not the expected
        0x04 push-4 height opcode) — still a ValidationError, just
        a more accurate one.
        """
        with pytest.raises(ValidationError):
            DmintState.from_script(b"\x00" * 20)

    def test_empty_script_raises(self):
        with pytest.raises(ValidationError):
            DmintState.from_script(b"")

    def test_large_max_height_round_trips(self):
        params = DmintDeployParams(
            contract_ref=_CONTRACT_REF,
            token_ref=_TOKEN_REF,
            max_height=2_100_000_000,
            reward=5_000_000_000,
            difficulty=10,
        )
        state = self._round_trip(params)
        assert state.max_height == 2_100_000_000
        assert state.reward == 5_000_000_000

    def test_all_9_algo_daa_variants_round_trip(self):
        """All combinations from the test_dmint_module matrix."""
        variants = [
            (DmintAlgo.SHA256D, DaaMode.FIXED),
            (DmintAlgo.SHA256D, DaaMode.ASERT),
            (DmintAlgo.SHA256D, DaaMode.LWMA),
            (DmintAlgo.BLAKE3, DaaMode.FIXED),
            (DmintAlgo.BLAKE3, DaaMode.ASERT),
            (DmintAlgo.BLAKE3, DaaMode.LWMA),
            (DmintAlgo.K12, DaaMode.FIXED),
            (DmintAlgo.K12, DaaMode.ASERT),
            (DmintAlgo.K12, DaaMode.LWMA),
        ]
        for algo, daa_mode in variants:
            params = DmintDeployParams(
                contract_ref=_CONTRACT_REF,
                token_ref=_TOKEN_REF,
                max_height=10_000,
                reward=100,
                difficulty=10,
                algo=algo,
                daa_mode=daa_mode,
                target_time=60,
                half_life=3_600,
                last_time=1_700_000_000,
            )
            state = self._round_trip(params)
            assert state.algo == algo, f"algo mismatch for {algo},{daa_mode}"
            assert state.daa_mode == daa_mode, f"daa_mode mismatch for {algo},{daa_mode}"
            assert state.target == params.initial_target, f"target mismatch for {algo},{daa_mode}"


class TestStateSeparatorN7:
    """Closes ultrareview re-review N7: DmintState.from_script must walk the
    state layout and only accept ``OP_STATESEPARATOR`` (0xbd) at the
    position immediately after the 10-item state. The pre-fix parser
    searched for the FIRST 0xbd byte in the script and sliced there —
    a byte-pattern attacker (or a perfectly-natural high-entropy ref or
    target value) could shift the cut into the middle of a push and
    produce a malformed-but-not-rejected state.
    """

    def test_0xbd_inside_contract_ref_does_not_truncate_state(self):
        """A contract_ref txid containing 0xbd must round-trip cleanly —
        the parser must walk past those bytes inside the wire ref's
        push-data, not stop at them.
        """
        # txid = bd repeated → wire ref begins with 0xbd, sitting inside
        # the push payload of item [1]. Pre-fix: byte-search would slice
        # the script at position 6 (first 0xbd inside the contractRef
        # payload), state_bytes too short for height+contractRef → parse
        # fails on the contractRef opcode check and surfaces a misleading
        # error. Post-fix: walk consumes the 36-byte wire ref payload,
        # ignoring its content, and finds the real separator.
        contract_ref_with_bd = GlyphRef(txid="bd" * 32, vout=1)
        params = DmintDeployParams(
            contract_ref=contract_ref_with_bd,
            token_ref=_TOKEN_REF,
            max_height=100,
            reward=10,
            difficulty=5,
        )
        script = build_dmint_contract_script(params)
        # Sanity: 0xbd really does appear inside the ref payload.
        assert script.count(b"\xbd") >= 33  # 32 from txid + at least 1 separator
        state = DmintState.from_script(script)
        assert state.contract_ref == contract_ref_with_bd

    def test_0xbd_inside_token_ref_does_not_truncate_state(self):
        """Same hazard for tokenRef (item 2)."""
        token_ref_with_bd = GlyphRef(txid="bd" * 32, vout=7)
        params = DmintDeployParams(
            contract_ref=_CONTRACT_REF,
            token_ref=token_ref_with_bd,
            max_height=100,
            reward=10,
            difficulty=5,
        )
        script = build_dmint_contract_script(params)
        state = DmintState.from_script(script)
        assert state.token_ref == token_ref_with_bd

    def test_0xbd_inside_last_time_does_not_truncate_state(self):
        """A 4-byte LE timestamp can carry 0xbd in any of its bytes —
        e.g. 0x00bd0000 → bytes [00, 00, bd, 00] in LE order.
        """
        # last_time chosen so its LE encoding contains a 0xbd byte.
        last_time = 0x12BD3456
        params = DmintDeployParams(
            contract_ref=_CONTRACT_REF,
            token_ref=_TOKEN_REF,
            max_height=100,
            reward=10,
            difficulty=5,
            algo=DmintAlgo.SHA256D,
            daa_mode=DaaMode.ASERT,
            target_time=120,
            half_life=3_600,
            last_time=last_time,
        )
        script = build_dmint_contract_script(params)
        state = DmintState.from_script(script)
        assert state.last_time == last_time

    def test_0xbd_inside_target_does_not_truncate_state(self):
        """A 256-bit target value (BLAKE3 / K12 algos) can contain 0xbd
        bytes anywhere in its 32-byte representation.
        """
        params = DmintDeployParams(
            contract_ref=_CONTRACT_REF,
            token_ref=_TOKEN_REF,
            max_height=100,
            reward=10,
            difficulty=189,  # 0xbd — likely to put 0xbd bytes in target
            algo=DmintAlgo.BLAKE3,
            daa_mode=DaaMode.LWMA,
            target_time=60,
        )
        script = build_dmint_contract_script(params)
        state = DmintState.from_script(script)
        # Round-trip: rebuild from same params, confirm targets match.
        assert state.target == params.initial_target

    def test_garbage_after_state_with_no_separator_rejected(self):
        """If the 10 state items parse cleanly but the next byte is NOT
        0xbd, the parser must raise — refusing to silently accept a
        state with no terminator.
        """
        # Build a real state, then strip the separator + code section
        # and replace with a non-0xbd byte.
        script = bytearray(build_dmint_contract_script(_BASE_PARAMS))
        # Walk to find the actual separator boundary (we know item count
        # so just locate the 0xbd that comes immediately after item 9).
        # The simplest reliable approach: replace the separator byte at
        # the position where the parser would expect it. We don't know
        # the position without running the parser, so use a different
        # approach: find LAST 0xbd in the script (separator is followed
        # only by code section bytes which are 0x00 .. plus perhaps
        # other 0xbd's, but in practice for our test fixtures the
        # separator byte is what we want). Safest: re-walk and grab pos.
        from pyrxd.glyph.dmint import _OP_STATESEPARATOR

        # Find separator by parsing the valid script first.
        DmintState.from_script(bytes(script))  # sanity: must succeed
        # Now corrupt: change every 0xbd byte that's NOT inside push-data
        # is hard; easier — replace the WHOLE byte range from the
        # separator onward with 0xff bytes (no separator left).
        first_bd = bytes(script).index(_OP_STATESEPARATOR)
        # Confirm this 0xbd is the actual separator by verifying parse
        # succeeded with the original bytes; replace it with 0xff.
        script[first_bd] = 0xFF
        with pytest.raises(ValidationError, match="OP_STATESEPARATOR"):
            DmintState.from_script(bytes(script))


# ---------------------------------------------------------------------------
# 2. GlyphBuilder.prepare_dmint_deploy()
# ---------------------------------------------------------------------------


class TestPrepareDmintDeploy:
    _META = GlyphMetadata.for_dmint_ft(
        ticker="TST",
        name="Test Token",
        description="dMint deploy test",
    )
    _OWNER_PKH = bytes(b"\x11" * 20)

    from pyrxd.security.types import Hex20 as _Hex20

    _OWNER_PKH_HEX = None  # lazy init below

    def _make_params(self, num_contracts=1):
        from pyrxd.security.types import Hex20

        # V2 deploy mirrors V1 (value-1 singletons in the reveal); the deprecation
        # warning for DmintFullDeployParams is exercised in test_dmint_v1_deploy.py.
        return DmintV2DeployParams(
            metadata=self._META,
            owner_pkh=Hex20(bytes(b"\x11" * 20)),
            num_contracts=num_contracts,
            max_height=1_000,
            reward_photons=1_000,
            difficulty=10,
        )

    def test_returns_dmint_deploy_result(self):
        result = GlyphBuilder().prepare_dmint_deploy(self._make_params(), allow_v2_deploy=True)
        assert isinstance(result, DmintV2DeployResult)

    def test_commit_result_has_ft_shape(self):
        result = GlyphBuilder().prepare_dmint_deploy(self._make_params(), allow_v2_deploy=True)
        # FT commit: OP_1 (0x51) at offset 48
        assert result.commit_result.commit_script[48] == 0x51

    def test_cbor_bytes_round_trip(self):
        import cbor2

        result = GlyphBuilder().prepare_dmint_deploy(self._make_params(), allow_v2_deploy=True)
        d = cbor2.loads(result.cbor_bytes)
        assert d["ticker"] == "TST"
        assert d["name"] == "Test Token"

    def test_num_contracts_echoed(self):
        result = GlyphBuilder().prepare_dmint_deploy(self._make_params(num_contracts=3), allow_v2_deploy=True)
        assert result.num_contracts == 3
        assert len(result.placeholder_contract_scripts) == 3

    def test_placeholder_contract_scripts_have_state_separator(self):
        result = GlyphBuilder().prepare_dmint_deploy(self._make_params(num_contracts=2), allow_v2_deploy=True)
        assert all(b"\xbd" in s for s in result.placeholder_contract_scripts)

    def test_premine_amount_none_when_not_set(self):
        result = GlyphBuilder().prepare_dmint_deploy(self._make_params(), allow_v2_deploy=True)
        assert result.premine_amount is None

    def test_rejects_premine(self):
        # V2 deploy with premine is deferred (mirrors V1).
        from dataclasses import replace

        params = replace(self._make_params(), premine_amount=10_000)
        with pytest.raises(ValidationError, match="premine"):
            GlyphBuilder().prepare_dmint_deploy(params, allow_v2_deploy=True)

    def test_build_reveal_outputs_emits_value_1_v2_contracts(self):
        result = GlyphBuilder().prepare_dmint_deploy(self._make_params(num_contracts=2), allow_v2_deploy=True)
        rev = result.build_reveal_outputs("ab" * 32)
        assert len(rev.contract_scripts) == 2
        assert rev.contract_value == 1  # singleton, like V1
        for script in rev.contract_scripts:
            assert b"\xbd" in script  # OP_STATESEPARATOR
            state = DmintState.from_script(script)
            assert state.is_v1 is False  # V2 contract
            assert state.height == 0

    def test_build_reveal_outputs_refs_are_commit_outpoints(self):
        result = GlyphBuilder().prepare_dmint_deploy(self._make_params(num_contracts=2), allow_v2_deploy=True)
        commit_txid = "cd" * 32
        rev = result.build_reveal_outputs(commit_txid)
        for i, script in enumerate(rev.contract_scripts):
            state = DmintState.from_script(script)
            # contractRef[i] = commit:(i+1), tokenRef = commit:0 (V1-style)
            assert state.contract_ref == GlyphRef(txid=commit_txid, vout=i + 1)
            assert state.token_ref == GlyphRef(txid=commit_txid, vout=0)


# ---------------------------------------------------------------------------
# 3. build_dmint_mint_tx()
# ---------------------------------------------------------------------------


def _make_contract_utxo(height: int = 0, daa_mode=DaaMode.FIXED, value: int = 1) -> DmintContractUtxo:
    """Build a synthetic V2 DmintContractUtxo for testing.

    The contract is a 1-photon singleton (the covenant enforces
    ``OP_OUTPUTVALUE==1`` on the recreated output); the FT reward + tx fee come
    from a separate funding input (same shape as V1).
    """
    params = DmintDeployParams(
        contract_ref=_CONTRACT_REF,
        token_ref=_TOKEN_REF,
        max_height=100,
        reward=1_000,
        difficulty=10,
        height=height,
        daa_mode=daa_mode,
        target_time=60,
        half_life=3_600,
        last_time=1_700_000_000 if height > 0 else 0,
    )
    script = build_dmint_contract_script(params)
    state = DmintState.from_script(script)
    return DmintContractUtxo(txid="cc" * 32, vout=0, value=value, script=script, state=state)


_MINER_PKH = bytes(b"\x33" * 20)
_NONCE = bytes(8)
_OP_RETURN = b"msg"


def _funding(value: int = 500_000_000) -> DmintMinerFundingUtxo:
    """Synthetic plain-RXD funding UTXO (pays reward + fee + change)."""
    return DmintMinerFundingUtxo(txid="aa" * 32, vout=0, value=value, script=b"\x76\xa9\x14" + bytes(20) + b"\x88\xac")


def _mint(utxo, *, nonce=_NONCE, pkh=_MINER_PKH, current_time=0, funding=None, op_return_msg=_OP_RETURN):
    return build_dmint_mint_tx(
        utxo,
        nonce,
        pkh,
        current_time,
        funding_utxo=_funding() if funding is None else funding,
        op_return_msg=op_return_msg,
    )


class TestBuildDmintMintTx:
    """The V2 mint builder emits the consensus-correct shape (proven on regtest
    by tests/test_dmint_v2_regtest_e2e.py): same as V1 — a 1-photon contract
    singleton + a plain funding input, recreating the contract at height+1
    (value 1) and paying the FT reward, with an OP_RETURN at vout[2]."""

    def test_returns_dmint_mint_result(self):
        from pyrxd.glyph.dmint import DmintMintResult

        assert isinstance(_mint(_make_contract_utxo()), DmintMintResult)

    def test_updated_height_incremented(self):
        assert _mint(_make_contract_utxo(height=0)).updated_state.height == 1

    def test_updated_height_incremented_from_mid_height(self):
        assert _mint(_make_contract_utxo(height=42)).updated_state.height == 43

    def test_updated_state_target_unchanged_for_fixed_daa(self):
        utxo = _make_contract_utxo()
        assert _mint(utxo).updated_state.target == utxo.state.target

    def test_updated_state_last_time_equals_current_time(self):
        # Redesign: the covenant rebuilds lastTime from OP_TXLOCKTIME on EVERY
        # mint (FIXED included), so the recreated state's last_time == current_time.
        utxo = _make_contract_utxo(height=5)
        assert _mint(utxo, current_time=1_700_000_123).updated_state.last_time == 1_700_000_123

    def test_contract_script_has_state_separator(self):
        assert b"\xbd" in _mint(_make_contract_utxo()).contract_script

    def test_contract_script_parses_back_to_updated_state(self):
        utxo = _make_contract_utxo(height=5)
        result = _mint(utxo)
        reparsed = DmintState.from_script(result.contract_script)
        assert reparsed.height == result.updated_state.height
        assert reparsed.last_time == result.updated_state.last_time
        assert reparsed.target == result.updated_state.target

    def test_recreated_state_preserves_immutable_fields(self):
        # Redesign: the recreated contract changes height/lastTime/target but
        # preserves the immutable slots (refs, maxHeight, reward, algo, daa,
        # targetTime) and the entire code section (Part A/B/C after 0xbd).
        utxo = _make_contract_utxo(height=7)
        result = _mint(utxo, current_time=1_700_000_000)
        reparsed = DmintState.from_script(result.contract_script)
        assert reparsed.height == 8
        assert reparsed.last_time == 1_700_000_000
        assert reparsed.contract_ref == utxo.state.contract_ref
        assert reparsed.token_ref == utxo.state.token_ref
        assert reparsed.max_height == utxo.state.max_height
        assert reparsed.reward == utxo.state.reward
        assert reparsed.algo == utxo.state.algo
        assert reparsed.daa_mode == utxo.state.daa_mode
        assert reparsed.target_time == utxo.state.target_time
        # The code section (Part A/B/C) is invariant across mints: the spent
        # contract's code suffix appears verbatim at the tail of the recreated
        # script. The Part C prologue is a stable anchor inside that code.
        part_c_prologue = bytes.fromhex("577ae500a069567ae600a06901d053797e0cdec0e9aa76e378e4a269e69d7e")
        assert part_c_prologue in result.contract_script
        assert part_c_prologue in utxo.script

    def test_reward_script_is_ft_wrapped_75_bytes(self):
        from pyrxd.glyph.dmint import build_dmint_v1_ft_output_script

        utxo = _make_contract_utxo()
        result = _mint(utxo)
        expected = build_dmint_v1_ft_output_script(_MINER_PKH, utxo.state.token_ref)
        assert result.reward_script == expected
        assert len(result.reward_script) == 75
        assert result.reward_script[:3] == b"\x76\xa9\x14"
        assert result.reward_script[3:23] == _MINER_PKH
        assert result.reward_script[23:25] == b"\x88\xac"
        assert result.reward_script[25:26] == b"\xbd"
        assert result.reward_script[26:27] == b"\xd0"
        assert result.reward_script[63:] == bytes.fromhex("dec0e9aa76e378e4a269e69d")

    def test_tx_has_two_inputs_four_outputs(self):
        result = _mint(_make_contract_utxo())
        assert len(result.tx.inputs) == 2  # contract + funding
        assert len(result.tx.outputs) == 4  # contract, reward, OP_RETURN, change

    def test_tx_output_0_is_contract_value_1(self):
        result = _mint(_make_contract_utxo())
        assert result.tx.outputs[0].locking_script.script == result.contract_script
        assert result.tx.outputs[0].satoshis == 1  # singleton

    def test_tx_output_1_value_equals_reward(self):
        utxo = _make_contract_utxo()
        assert _mint(utxo).tx.outputs[1].satoshis == utxo.state.reward

    def test_tx_output_2_is_op_return(self):
        result = _mint(_make_contract_utxo())
        assert result.tx.outputs[2].locking_script.script[0] == 0x6A
        assert result.tx.outputs[3].satoshis > 546  # change

    def test_fee_is_positive(self):
        assert _mint(_make_contract_utxo()).fee > 0

    def test_requires_funding_utxo(self):
        with pytest.raises(ValidationError, match="funding_utxo"):
            build_dmint_mint_tx(_make_contract_utxo(), _NONCE, _MINER_PKH, 0, op_return_msg=_OP_RETURN)

    def test_contract_value_not_1_rejected(self):
        with pytest.raises(ValidationError, match="1-photon singleton"):
            _mint(_make_contract_utxo(value=100))

    def test_current_time_sets_last_time_and_locktime(self):
        # Redesign: current_time is the block locktime; it lands in the recreated
        # state's lastTime AND the tx nLockTime (the covenant rebuilds lastTime
        # from OP_TXLOCKTIME, so the two MUST agree).
        result = _mint(_make_contract_utxo(), current_time=1_700_000_000)
        assert result.updated_state.last_time == 1_700_000_000
        assert result.tx.locktime == 1_700_000_000

    def test_exhausted_contract_raises(self):
        from pyrxd.security.errors import ContractExhaustedError

        with pytest.raises(ContractExhaustedError, match="exhausted"):
            _mint(_make_contract_utxo(height=100))  # max_height=100

    def test_wrong_nonce_length_raises(self):
        with pytest.raises(ValidationError, match="nonce"):
            _mint(_make_contract_utxo(), nonce=bytes(7))

    def test_wrong_pkh_length_raises(self):
        with pytest.raises(ValidationError, match="miner_pkh"):
            _mint(_make_contract_utxo(), pkh=bytes(19))

    def test_funding_too_small_raises(self):
        from pyrxd.security.errors import PoolTooSmallError

        with pytest.raises(PoolTooSmallError, match="too small"):
            _mint(_make_contract_utxo(), funding=_funding(value=10_000))  # << fee + reward

    def test_asert_daa_updates_target(self):
        # Redesign: ASERT is mintable. A slow block (delta=2*targetTime over the
        # half-life worth of excess) eases difficulty → target grows.
        utxo = _make_contract_utxo(height=5, daa_mode=DaaMode.ASERT)
        last_time = utxo.state.last_time
        result = _mint(utxo, current_time=last_time + 7200)  # excess 7140, drift +1
        assert result.updated_state.target > utxo.state.target
        assert result.updated_state.last_time == last_time + 7200

    def test_epoch_daa_not_buildable(self):
        # EPOCH/SCHEDULE DAA bytecode emitters are not yet ported in pyrxd, so the
        # builder refuses to construct such a contract (it can never be deployed).
        with pytest.raises(NotImplementedError, match="not yet implemented"):
            _make_contract_utxo(daa_mode=DaaMode.EPOCH)

    def test_consecutive_mints_chain_state(self):
        utxo = _make_contract_utxo()
        result1 = _mint(utxo)
        utxo2 = DmintContractUtxo(
            txid="dd" * 32,
            vout=0,
            value=result1.tx.outputs[0].satoshis,  # singleton, == 1
            script=result1.contract_script,
            state=result1.updated_state,
        )
        result2 = _mint(utxo2)
        assert result2.updated_state.height == 2
        assert result2.updated_state.last_time == utxo.state.last_time  # unchanged


# ---------------------------------------------------------------------------
# build_dmint_v2_mint_preimage — V2 analog of the V1 helper
# ---------------------------------------------------------------------------
#
# Added 2026-05-12 to close the security audit's H1 finding: V2 had no
# preimage helper that pulled the input/output scripts from the unsigned
# tx, so a V2 caller could reproduce the M1-class bug by feeding wrong
# scripts to `build_pow_preimage` directly. The V2 helper mirrors V1
# byte-for-byte (the preimage shape doesn't differ between versions;
# only the nonce width does, and that's a parameter of
# `build_mint_scriptsig`, not this helper).
#
# Every test below uses synthetic V2 fixtures because no V2 contract
# exists on chain to validate against. The helper itself emits
# V2UnvalidatedWarning to make the "untested on chain" status visible
# at runtime; tests suppress the warning where it would otherwise
# create test-output noise.


_FUNDING_VALUE = 500_000_000  # 5 RXD, plenty for fee + reward + change


def _make_funding_utxo(value: int = _FUNDING_VALUE) -> DmintMinerFundingUtxo:
    """Synthetic plain-RXD funding UTXO for V2 preimage tests."""
    return DmintMinerFundingUtxo(
        txid="aa" * 32,
        vout=0,
        value=value,
        script=b"\x76\xa9\x14" + bytes(20) + b"\x88\xac",  # P2PKH to zero-PKH
    )


class TestBuildDmintV2MintPreimage:
    """The library helper that closes audit finding security-H1.

    V2 callers must use this helper instead of calling `build_pow_preimage`
    directly with caller-chosen scripts — otherwise they reproduce the
    M1-class footgun where mismatched scripts produce a preimage that
    fails the covenant check after mining.

    Unlike the V1 helper (which infers ``output_script`` from
    ``unsigned_tx.outputs[2]`` per Photonic-Wallet convention), the V2
    helper takes ``output_script`` as an explicit argument. V2 has no
    canonical output-layout convention — the covenant binds outputHash
    to whatever bytes the caller pushes, so V2 callers must commit to
    a specific output script themselves.
    """

    # A synthetic V2 "output script" for tests. The actual byte content
    # is arbitrary — the covenant only cares that the SAME bytes get
    # hashed on both miner and chain sides.
    _SYNTH_OUTPUT_SCRIPT = bytes.fromhex("6a045465737400")  # OP_RETURN "Test\x00"

    def test_returns_pow_preimage_result(self):
        from pyrxd.glyph.dmint import build_dmint_v2_mint_preimage

        utxo = _make_contract_utxo()
        funding = _make_funding_utxo()
        result = build_dmint_v2_mint_preimage(utxo, funding, self._SYNTH_OUTPUT_SCRIPT)
        assert len(result.preimage) == 64
        assert len(result.input_hash) == 32
        assert len(result.output_hash) == 32

    def test_input_hash_is_sha256d_of_funding_script(self):
        """The covenant pulls inputHash from the scriptSig push and
        expects it to equal SHA256d(funding_script). Same convention
        as V1 — and the same invariant the M1 bug violated."""
        import hashlib
        import warnings

        from pyrxd.glyph.dmint import V2UnvalidatedWarning, build_dmint_v2_mint_preimage

        utxo = _make_contract_utxo()
        funding = _make_funding_utxo()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", V2UnvalidatedWarning)
            result = build_dmint_v2_mint_preimage(utxo, funding, self._SYNTH_OUTPUT_SCRIPT)
        expected = hashlib.sha256(hashlib.sha256(funding.script).digest()).digest()
        assert result.input_hash == expected

    def test_output_hash_is_sha256d_of_caller_supplied_output_script(self):
        """The covenant pulls outputHash from the scriptSig push and
        expects it to equal SHA256d(caller's output_script)."""
        import hashlib
        import warnings

        from pyrxd.glyph.dmint import V2UnvalidatedWarning, build_dmint_v2_mint_preimage

        utxo = _make_contract_utxo()
        funding = _make_funding_utxo()
        custom_script = bytes.fromhex("6a065769746e657373")  # OP_RETURN "Witness"
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", V2UnvalidatedWarning)
            result = build_dmint_v2_mint_preimage(utxo, funding, custom_script)
        expected = hashlib.sha256(hashlib.sha256(custom_script).digest()).digest()
        assert result.output_hash == expected

    def test_preimage_byte_identical_to_direct_build_pow_preimage(self):
        """The V2 helper must be byte-equivalent to a hand-built
        `build_pow_preimage` call with the exact same field bindings —
        same property the V1 helper has."""
        import warnings

        from pyrxd.glyph.dmint import (
            V2UnvalidatedWarning,
            build_dmint_v2_mint_preimage,
            build_pow_preimage,
        )

        utxo = _make_contract_utxo()
        funding = _make_funding_utxo()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", V2UnvalidatedWarning)
            actual = build_dmint_v2_mint_preimage(utxo, funding, self._SYNTH_OUTPUT_SCRIPT)
        expected = build_pow_preimage(
            txid_le=bytes.fromhex(utxo.txid)[::-1],
            contract_ref_bytes=utxo.state.contract_ref.to_bytes(),
            input_script=funding.script,
            output_script=self._SYNTH_OUTPUT_SCRIPT,
        )
        assert actual.preimage == expected.preimage
        assert actual.input_hash == expected.input_hash
        assert actual.output_hash == expected.output_hash

    def test_refuses_v1_contract_utxo(self):
        """Passing a V1 contract UTXO to the V2 helper is a programming
        error — must raise immediately rather than silently produce a
        preimage with the wrong nonce-width binding downstream."""
        import warnings

        from pyrxd.glyph.dmint import (
            DmintContractUtxo,
            DmintState,
            V2UnvalidatedWarning,
            build_dmint_v1_contract_script,
            build_dmint_v2_mint_preimage,
        )
        from pyrxd.security.errors import ValidationError

        v1_script = build_dmint_v1_contract_script(
            height=0,
            contract_ref=_CONTRACT_REF,
            token_ref=_TOKEN_REF,
            max_height=10,
            reward=1000,
            target=0x7FFFFFFFFFFFFFFF,
        )
        v1_state = DmintState.from_script(v1_script)
        assert v1_state.is_v1  # sanity check
        v1_utxo = DmintContractUtxo(txid="cc" * 32, vout=0, value=1, script=v1_script, state=v1_state)
        funding = _make_funding_utxo()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", V2UnvalidatedWarning)
            with pytest.raises(ValidationError, match="V1 contract UTXO"):
                build_dmint_v2_mint_preimage(v1_utxo, funding, self._SYNTH_OUTPUT_SCRIPT)

    def test_refuses_empty_output_script(self):
        """Empty output_script would produce a degenerate preimage —
        rejected at the boundary rather than silently allowed."""
        import warnings

        from pyrxd.glyph.dmint import V2UnvalidatedWarning, build_dmint_v2_mint_preimage
        from pyrxd.security.errors import ValidationError

        utxo = _make_contract_utxo()
        funding = _make_funding_utxo()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", V2UnvalidatedWarning)
            with pytest.raises(ValidationError, match="output_script must be non-empty"):
                build_dmint_v2_mint_preimage(utxo, funding, b"")

    def test_does_not_emit_v2_unvalidated_warning(self):
        """V2 is consensus-proven (#219) — the preimage helper no longer emits
        the quarantine warning."""
        import warnings

        from pyrxd.glyph.dmint import V2UnvalidatedWarning, build_dmint_v2_mint_preimage

        utxo = _make_contract_utxo()
        funding = _make_funding_utxo()
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", V2UnvalidatedWarning)
            build_dmint_v2_mint_preimage(utxo, funding, self._SYNTH_OUTPUT_SCRIPT)
        assert [w for w in caught if issubclass(w.category, V2UnvalidatedWarning)] == []
