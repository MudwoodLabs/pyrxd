"""Tests for the dMint end-to-end pipeline (v1.0 blocker items).

Covers:
1. DmintState.from_script() — round-trip parser against build_dmint_contract_script()
2. GlyphBuilder.prepare_dmint_deploy() — commit/reveal/deploy script builder
3. build_dmint_mint_tx() — mint transaction builder
"""

from __future__ import annotations

import pytest

from pyrxd.glyph.builder import (
    DmintDeployResult,
    DmintFullDeployParams,
    GlyphBuilder,
)
from pyrxd.glyph.dmint import (
    MAX_SHA256D_TARGET,
    MAX_V2_TARGET_256,
    DaaMode,
    DmintAlgo,
    DmintContractUtxo,
    DmintDeployParams,
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

    def _make_params(self, premine=None, pool=100_000):
        from pyrxd.security.types import Hex20

        return DmintFullDeployParams(
            metadata=self._META,
            owner_pkh=Hex20(bytes(b"\x11" * 20)),
            max_height=1_000,
            reward_photons=1_000,
            difficulty=10,
            initial_pool_photons=pool,
            premine_amount=premine,
        )

    def test_returns_dmint_deploy_result(self):
        result = GlyphBuilder().prepare_dmint_deploy(self._make_params())
        assert isinstance(result, DmintDeployResult)

    def test_commit_result_has_ft_shape(self):
        result = GlyphBuilder().prepare_dmint_deploy(self._make_params())
        # FT commit: OP_1 (0x51) at offset 48
        assert result.commit_result.commit_script[48] == 0x51

    def test_cbor_bytes_round_trip(self):
        import cbor2

        result = GlyphBuilder().prepare_dmint_deploy(self._make_params())
        d = cbor2.loads(result.cbor_bytes)
        assert d["ticker"] == "TST"
        assert d["name"] == "Test Token"

    def test_placeholder_contract_script_has_state_separator(self):
        result = GlyphBuilder().prepare_dmint_deploy(self._make_params())
        assert b"\xbd" in result.placeholder_contract_script

    def test_initial_pool_photons_echoed(self):
        result = GlyphBuilder().prepare_dmint_deploy(self._make_params(pool=500_000))
        assert result.initial_pool_photons == 500_000

    def test_premine_amount_none_when_not_set(self):
        result = GlyphBuilder().prepare_dmint_deploy(self._make_params())
        assert result.premine_amount is None

    def test_premine_amount_echoed_when_set(self):
        result = GlyphBuilder().prepare_dmint_deploy(self._make_params(premine=10_000))
        assert result.premine_amount == 10_000

    def test_rejects_premine_below_dust(self):
        with pytest.raises(ValidationError, match="dust"):
            GlyphBuilder().prepare_dmint_deploy(self._make_params(premine=100))

    def test_rejects_pool_less_than_reward(self):
        with pytest.raises(ValidationError, match="initial_pool_photons"):
            GlyphBuilder().prepare_dmint_deploy(self._make_params(pool=500))  # reward=1000

    def test_build_reveal_scripts_with_premine(self):
        result = GlyphBuilder().prepare_dmint_deploy(self._make_params(premine=1_000_000))
        from pyrxd.glyph.builder import FtDeployRevealScripts

        reveal = result.build_reveal_scripts(
            commit_txid="ab" * 32,
            commit_vout=0,
            commit_value=5_000_000,
        )
        assert isinstance(reveal, FtDeployRevealScripts)
        assert len(reveal.locking_script) == 75

    def test_build_reveal_scripts_without_premine(self):
        result = GlyphBuilder().prepare_dmint_deploy(self._make_params())
        from pyrxd.glyph.builder import RevealScripts

        reveal = result.build_reveal_scripts(
            commit_txid="ab" * 32,
            commit_vout=0,
            commit_value=5_000_000,
        )
        assert isinstance(reveal, RevealScripts)

    def test_build_contract_script_with_real_refs(self):
        result = GlyphBuilder().prepare_dmint_deploy(self._make_params())
        real_token_ref = GlyphRef(txid="cc" * 32, vout=0)
        real_contract_ref = GlyphRef(txid="dd" * 32, vout=0)
        script = result.build_contract_script(
            token_ref=real_token_ref,
            contract_ref=real_contract_ref,
        )
        # Should contain both ref bytes and the state separator
        assert b"\xbd" in script
        assert real_token_ref.to_bytes() in script
        assert real_contract_ref.to_bytes() in script

    def test_contract_script_parses_back_with_real_refs(self):
        result = GlyphBuilder().prepare_dmint_deploy(self._make_params())
        real_token_ref = GlyphRef(txid="cc" * 32, vout=0)
        real_contract_ref = GlyphRef(txid="dd" * 32, vout=0)
        script = result.build_contract_script(
            token_ref=real_token_ref,
            contract_ref=real_contract_ref,
        )
        state = DmintState.from_script(script)
        assert state.token_ref == real_token_ref
        assert state.contract_ref == real_contract_ref
        assert state.max_height == 1_000
        assert state.reward == 1_000


# ---------------------------------------------------------------------------
# 3. build_dmint_mint_tx()
# ---------------------------------------------------------------------------


def _make_contract_utxo(height: int = 0, pool: int = 50_000_000, daa_mode=DaaMode.FIXED) -> DmintContractUtxo:
    """Build a synthetic DmintContractUtxo for testing.

    Default pool is 50M photons — enough to cover fee (~4.3M ph) + reward (1000 ph)
    at 10,000 ph/byte for a ~430-byte mint tx.
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
    return DmintContractUtxo(
        txid="cc" * 32,
        vout=0,
        value=pool,
        script=script,
        state=state,
    )


_MINER_PKH = bytes(b"\x33" * 20)
_NONCE = bytes(8)
_CURRENT_TIME = 1_700_000_060


class TestBuildDmintMintTx:
    def test_returns_dmint_mint_result(self):
        utxo = _make_contract_utxo()
        result = build_dmint_mint_tx(utxo, _NONCE, _MINER_PKH, _CURRENT_TIME)
        from pyrxd.glyph.dmint import DmintMintResult

        assert isinstance(result, DmintMintResult)

    def test_updated_height_incremented(self):
        utxo = _make_contract_utxo(height=0)
        result = build_dmint_mint_tx(utxo, _NONCE, _MINER_PKH, _CURRENT_TIME)
        assert result.updated_state.height == 1

    def test_updated_height_incremented_from_mid_height(self):
        utxo = _make_contract_utxo(height=42)
        result = build_dmint_mint_tx(utxo, _NONCE, _MINER_PKH, _CURRENT_TIME)
        assert result.updated_state.height == 43

    def test_updated_state_target_unchanged_for_fixed_daa(self):
        utxo = _make_contract_utxo()
        result = build_dmint_mint_tx(utxo, _NONCE, _MINER_PKH, _CURRENT_TIME)
        assert result.updated_state.target == utxo.state.target

    def test_updated_state_last_time_is_current_time(self):
        utxo = _make_contract_utxo()
        result = build_dmint_mint_tx(utxo, _NONCE, _MINER_PKH, _CURRENT_TIME)
        assert result.updated_state.last_time == _CURRENT_TIME

    def test_contract_script_has_state_separator(self):
        utxo = _make_contract_utxo()
        result = build_dmint_mint_tx(utxo, _NONCE, _MINER_PKH, _CURRENT_TIME)
        assert b"\xbd" in result.contract_script

    def test_contract_script_parses_back_to_updated_state(self):
        utxo = _make_contract_utxo(height=5)
        result = build_dmint_mint_tx(utxo, _NONCE, _MINER_PKH, _CURRENT_TIME)
        reparsed = DmintState.from_script(result.contract_script)
        assert reparsed.height == result.updated_state.height
        assert reparsed.last_time == result.updated_state.last_time
        assert reparsed.target == result.updated_state.target

    def test_reward_script_is_p2pkh(self):
        utxo = _make_contract_utxo()
        result = build_dmint_mint_tx(utxo, _NONCE, _MINER_PKH, _CURRENT_TIME)
        # P2PKH: 76 a9 14 <20-byte PKH> 88 ac
        assert result.reward_script == b"\x76\xa9\x14" + _MINER_PKH + b"\x88\xac"

    def test_tx_has_one_input_two_outputs(self):
        utxo = _make_contract_utxo()
        result = build_dmint_mint_tx(utxo, _NONCE, _MINER_PKH, _CURRENT_TIME)
        assert len(result.tx.inputs) == 1
        assert len(result.tx.outputs) == 2

    def test_tx_output_1_value_equals_reward(self):
        utxo = _make_contract_utxo()
        result = build_dmint_mint_tx(utxo, _NONCE, _MINER_PKH, _CURRENT_TIME)
        assert result.tx.outputs[1].satoshis == utxo.state.reward

    def test_tx_output_0_contract_script(self):
        utxo = _make_contract_utxo()
        result = build_dmint_mint_tx(utxo, _NONCE, _MINER_PKH, _CURRENT_TIME)
        assert result.tx.outputs[0].locking_script.script == result.contract_script

    def test_fee_is_positive(self):
        utxo = _make_contract_utxo()
        result = build_dmint_mint_tx(utxo, _NONCE, _MINER_PKH, _CURRENT_TIME)
        assert result.fee > 0

    def test_exhausted_contract_raises(self):
        from pyrxd.security.errors import ContractExhaustedError

        utxo = _make_contract_utxo(height=100)  # max_height=100
        with pytest.raises(ContractExhaustedError, match="exhausted"):
            build_dmint_mint_tx(utxo, _NONCE, _MINER_PKH, _CURRENT_TIME)

    def test_wrong_nonce_length_raises(self):
        utxo = _make_contract_utxo()
        with pytest.raises(ValidationError, match="nonce"):
            build_dmint_mint_tx(utxo, bytes(7), _MINER_PKH, _CURRENT_TIME)

    def test_wrong_pkh_length_raises(self):
        utxo = _make_contract_utxo()
        with pytest.raises(ValidationError, match="miner_pkh"):
            build_dmint_mint_tx(utxo, _NONCE, bytes(19), _CURRENT_TIME)

    def test_pool_too_small_raises(self):
        # Pool much smaller than fee → contract output would be negative.
        from pyrxd.security.errors import PoolTooSmallError

        utxo = _make_contract_utxo(pool=10_000)  # fee ~4.3M, pool=10k → far too small
        with pytest.raises(PoolTooSmallError, match="too small"):
            build_dmint_mint_tx(utxo, _NONCE, _MINER_PKH, _CURRENT_TIME)

    def test_asert_daa_updates_target(self):
        """With ASERT DAA and a slow block time, the target should increase."""
        utxo = _make_contract_utxo(height=0, pool=50_000_000, daa_mode=DaaMode.ASERT)
        # current_time is 7200s after last_time=0, target_time=60 → drift=+1 → target doubled
        slow_time = 0 + 7_200  # last_time=0, current_time=7200
        result = build_dmint_mint_tx(utxo, _NONCE, _MINER_PKH, slow_time)
        # drift = (7200-0-60)//3600 = 1 → target <<= 1 (doubled)
        expected = utxo.state.target << 1
        assert result.updated_state.target == expected

    def test_consecutive_mints_chain_state(self):
        """The contract script from mint N can feed mint N+1."""
        utxo = _make_contract_utxo(pool=100_000_000)
        result1 = build_dmint_mint_tx(utxo, _NONCE, _MINER_PKH, _CURRENT_TIME)
        # Build second utxo from first result
        utxo2 = DmintContractUtxo(
            txid="dd" * 32,
            vout=0,
            value=result1.tx.outputs[0].satoshis,
            script=result1.contract_script,
            state=result1.updated_state,
        )
        result2 = build_dmint_mint_tx(utxo2, _NONCE, _MINER_PKH, _CURRENT_TIME + 60)
        assert result2.updated_state.height == 2
        assert result2.updated_state.last_time == _CURRENT_TIME + 60
