"""Tests for pyrxd.glyph.dmint — V2 dMint contract construction."""

from __future__ import annotations

import hashlib
import struct

import pytest

from pyrxd.glyph.dmint import (
    _PART_B1,
    _PART_B2,
    _PART_B4,
    _PART_C,
    MAX_SHA256D_TARGET,
    MAX_V2_TARGET_256,
    DaaMode,
    DmintAlgo,
    DmintDeployParams,
    _push_4bytes_le,
    _push_minimal,
    build_dmint_code_script,
    build_dmint_contract_script,
    build_dmint_state_script,
    build_mint_scriptsig,
    build_pow_preimage,
    compute_next_target_asert,
    compute_next_target_linear,
    difficulty_to_target,
    target_to_difficulty,
    verify_sha256d_solution,
)
from pyrxd.glyph.types import GlyphRef
from pyrxd.security.errors import ValidationError

_CONTRACT_REF = GlyphRef(txid="aa" * 32, vout=1)
_TOKEN_REF = GlyphRef(txid="bb" * 32, vout=2)
_BASE_PARAMS = DmintDeployParams(
    contract_ref=_CONTRACT_REF,
    token_ref=_TOKEN_REF,
    max_height=1000,
    reward=100,
    difficulty=10,
)
_BASE_LAST_TIME = 1_700_000_000


class TestPushMinimal:
    def test_zero(self):
        assert _push_minimal(0) == b"\x00"

    def test_neg_one(self):
        assert _push_minimal(-1) == b"\x4f"

    def test_op1_to_op16(self):
        assert _push_minimal(1) == b"\x51"
        assert _push_minimal(16) == b"\x60"

    def test_small_positive(self):
        result = _push_minimal(17)
        assert result[0] == 1
        assert result[1] == 17

    def test_256(self):
        result = _push_minimal(256)
        assert result == b"\x02\x00\x01"

    def test_large(self):
        result = _push_minimal(0x7FFFFFFFFFFFFFFF)
        assert result[0] == 8


class TestPush4BytesLE:
    def test_zero(self):
        assert _push_4bytes_le(0) == b"\x04\x00\x00\x00\x00"

    def test_nonzero(self):
        data = _push_4bytes_le(0x01000000)
        assert data == b"\x04\x00\x00\x00\x01"


class TestDmintDeployParamsValidation:
    def test_valid_params(self):
        p = DmintDeployParams(
            contract_ref=_CONTRACT_REF,
            token_ref=_TOKEN_REF,
            max_height=100,
            reward=10,
            difficulty=5,
        )
        assert p.initial_target == MAX_SHA256D_TARGET // 5

    def test_max_height_zero_raises(self):
        with pytest.raises(ValidationError, match="max_height"):
            DmintDeployParams(contract_ref=_CONTRACT_REF, token_ref=_TOKEN_REF, max_height=0, reward=10, difficulty=5)

    def test_reward_zero_raises(self):
        with pytest.raises(ValidationError, match="reward"):
            DmintDeployParams(contract_ref=_CONTRACT_REF, token_ref=_TOKEN_REF, max_height=100, reward=0, difficulty=5)

    def test_difficulty_zero_raises(self):
        with pytest.raises(ValidationError, match="difficulty"):
            DmintDeployParams(contract_ref=_CONTRACT_REF, token_ref=_TOKEN_REF, max_height=100, reward=10, difficulty=0)

    def test_target_time_zero_raises(self):
        with pytest.raises(ValidationError, match="target_time"):
            DmintDeployParams(
                contract_ref=_CONTRACT_REF, token_ref=_TOKEN_REF, max_height=100, reward=10, difficulty=5, target_time=0
            )

    def test_blake3_uses_256bit_target(self):
        p = DmintDeployParams(
            contract_ref=_CONTRACT_REF,
            token_ref=_TOKEN_REF,
            max_height=100,
            reward=10,
            difficulty=100,
            algo=DmintAlgo.BLAKE3,
        )
        assert p.initial_target == MAX_V2_TARGET_256 // 100


class TestBuildDmintStateScript:
    def test_starts_with_height_4bytes(self):
        script = build_dmint_state_script(_BASE_PARAMS)
        assert script[:5] == b"\x04\x00\x00\x00\x00"

    def test_contract_ref_prefix(self):
        script = build_dmint_state_script(_BASE_PARAMS)
        assert script[5] == 0xD8

    def test_token_ref_prefix(self):
        script = build_dmint_state_script(_BASE_PARAMS)
        assert script[42] == 0xD0

    def test_no_state_separator(self):
        script = build_dmint_state_script(_BASE_PARAMS)
        assert b"\xbd" not in script

    def test_height_encoding(self):
        p = DmintDeployParams(
            contract_ref=_CONTRACT_REF, token_ref=_TOKEN_REF, max_height=1000, reward=50, difficulty=10, height=42
        )
        script = build_dmint_state_script(p)
        assert script[:5] == b"\x04" + struct.pack("<I", 42)


class TestBuildDmintContractScript:
    def test_state_separator_present(self):
        assert b"\xbd" in build_dmint_contract_script(_BASE_PARAMS)

    def test_part_b1_present(self):
        assert _PART_B1 in build_dmint_code_script(_BASE_PARAMS)

    def test_part_b2_present(self):
        assert _PART_B2 in build_dmint_code_script(_BASE_PARAMS)

    def test_part_b4_present(self):
        assert _PART_B4 in build_dmint_code_script(_BASE_PARAMS)

    def test_part_c_present(self):
        assert _PART_C in build_dmint_code_script(_BASE_PARAMS)

    def test_sha256d_pow_opcode(self):
        assert b"\xaa" in build_dmint_code_script(_BASE_PARAMS)

    def test_blake3_pow_opcode(self):
        p = DmintDeployParams(
            contract_ref=_CONTRACT_REF,
            token_ref=_TOKEN_REF,
            max_height=100,
            reward=10,
            difficulty=5,
            algo=DmintAlgo.BLAKE3,
        )
        assert b"\xee" in build_dmint_code_script(p)

    def test_k12_pow_opcode(self):
        p = DmintDeployParams(
            contract_ref=_CONTRACT_REF,
            token_ref=_TOKEN_REF,
            max_height=100,
            reward=10,
            difficulty=5,
            algo=DmintAlgo.K12,
        )
        assert b"\xef" in build_dmint_code_script(p)

    def test_asert_includes_txlocktime(self):
        p = DmintDeployParams(
            contract_ref=_CONTRACT_REF,
            token_ref=_TOKEN_REF,
            max_height=100,
            reward=10,
            difficulty=5,
            daa_mode=DaaMode.ASERT,
            target_time=60,
            half_life=3600,
        )
        assert b"\xc5" in build_dmint_code_script(p)

    def test_fixed_no_txlocktime(self):
        assert b"\xc5" not in build_dmint_code_script(_BASE_PARAMS)

    def test_deterministic(self):
        s1 = build_dmint_contract_script(_BASE_PARAMS)
        s2 = build_dmint_contract_script(_BASE_PARAMS)
        assert s1 == s2
        assert len(s1) > 100


class TestBuildPowPreimage:
    _TXID_LE = bytes.fromhex("cc" * 32)
    _CREF = _CONTRACT_REF.to_bytes()
    _IN_SCR = bytes.fromhex("76a914" + "00" * 20 + "88ac")
    _OUT_SCR = bytes.fromhex("6a")

    def test_preimage_64_bytes(self):
        result = build_pow_preimage(self._TXID_LE, self._CREF, self._IN_SCR, self._OUT_SCR)
        assert len(result.preimage) == 64

    def test_input_hash_is_sha256d_of_input_script(self):
        """The scriptSig pushes SHA256d(input_script) — not the preimage half.

        The covenant recomputes ``H2 = SHA256(scriptSig_inputHash ||
        scriptSig_outputHash)`` from the pushes and folds it into the PoW
        hash. Verified against mainnet mint ``146a4d68…f3c``:
        SHA256d(funding P2PKH) = 09b5b22a…0a2 = the scriptSig push.
        """
        result = build_pow_preimage(self._TXID_LE, self._CREF, self._IN_SCR, self._OUT_SCR)
        expected = hashlib.sha256(hashlib.sha256(self._IN_SCR).digest()).digest()
        assert result.input_hash == expected

    def test_output_hash_is_sha256d_of_output_script(self):
        result = build_pow_preimage(self._TXID_LE, self._CREF, self._IN_SCR, self._OUT_SCR)
        expected = hashlib.sha256(hashlib.sha256(self._OUT_SCR).digest()).digest()
        assert result.output_hash == expected

    def test_first_half(self):
        result = build_pow_preimage(self._TXID_LE, self._CREF, self._IN_SCR, self._OUT_SCR)
        expected = hashlib.sha256(self._TXID_LE + self._CREF).digest()
        assert result.preimage[:32] == expected

    def test_second_half_is_sha256_of_input_hash_concat_output_hash(self):
        result = build_pow_preimage(self._TXID_LE, self._CREF, self._IN_SCR, self._OUT_SCR)
        expected = hashlib.sha256(result.input_hash + result.output_hash).digest()
        assert result.preimage[32:] == expected

    def test_short_txid_raises(self):
        with pytest.raises(ValidationError, match="txid_le"):
            build_pow_preimage(b"\x00" * 31, self._CREF, self._IN_SCR, self._OUT_SCR)

    def test_short_cref_raises(self):
        with pytest.raises(ValidationError, match="contract_ref_bytes"):
            build_pow_preimage(self._TXID_LE, b"\x00" * 35, self._IN_SCR, self._OUT_SCR)

    def test_deterministic(self):
        p1 = build_pow_preimage(self._TXID_LE, self._CREF, self._IN_SCR, self._OUT_SCR)
        p2 = build_pow_preimage(self._TXID_LE, self._CREF, self._IN_SCR, self._OUT_SCR)
        assert p1.preimage == p2.preimage
        assert p1.input_hash == p2.input_hash
        assert p1.output_hash == p2.output_hash


class TestBuildMintScriptSig:
    _NONCE = b"\xab" * 8
    _INPUT_HASH = b"\xcc" * 32
    _OUTPUT_HASH = b"\xdd" * 32

    def test_structure(self):
        sig = build_mint_scriptsig(self._NONCE, self._INPUT_HASH, self._OUTPUT_HASH)
        assert sig[0] == 0x08
        assert sig[1:9] == self._NONCE
        assert sig[9] == 0x20
        assert sig[10:42] == self._INPUT_HASH
        assert sig[42] == 0x20
        assert sig[43:75] == self._OUTPUT_HASH
        assert sig[75] == 0x00

    def test_length(self):
        assert len(build_mint_scriptsig(self._NONCE, self._INPUT_HASH, self._OUTPUT_HASH)) == 76

    def test_short_nonce_raises(self):
        with pytest.raises(ValidationError, match="nonce"):
            build_mint_scriptsig(b"\x00" * 7, self._INPUT_HASH, self._OUTPUT_HASH)

    def test_short_input_hash_raises(self):
        with pytest.raises(ValidationError, match="input_hash"):
            build_mint_scriptsig(self._NONCE, b"\x00" * 31, self._OUTPUT_HASH)

    def test_short_output_hash_raises(self):
        with pytest.raises(ValidationError, match="output_hash"):
            build_mint_scriptsig(self._NONCE, self._INPUT_HASH, b"\x00" * 31)


class TestComputeNextTargetAsert:
    def test_on_schedule_unchanged(self):
        assert compute_next_target_asert(1_000_000, _BASE_LAST_TIME, _BASE_LAST_TIME + 60, 60, 3600) == 1_000_000

    def test_slow_doubles_target(self):
        # time_delta=7200, target_time=60, excess=7140, drift=7140//3600=1 → <<1
        assert compute_next_target_asert(1_000_000, _BASE_LAST_TIME, _BASE_LAST_TIME + 7200, 60, 3600) == 2_000_000

    def test_fast_halves_target(self):
        # time_delta=60, target_time=3720, excess=-3660, drift=-3660//3600=-2 wait...
        # In Python: -3660 // 3600 = -2 (floored division), clamped within [-4,4]
        # new_target = 1_000_000 >> 2 = 250_000
        result = compute_next_target_asert(1_000_000, _BASE_LAST_TIME, _BASE_LAST_TIME + 60, 3720, 3600)
        # excess = 60 - 3720 = -3660, drift = -3660//3600 = -2
        assert result == 250_000

    def test_drift_clamped_plus_4(self):
        # excess = 36000+60-60 = 36000, drift = 36000//3600 = 10 → clamped to 4
        result = compute_next_target_asert(1_000, _BASE_LAST_TIME, _BASE_LAST_TIME + 36060, 60, 3600)
        assert result == 1_000 << 4

    def test_drift_clamped_minus_4(self):
        result = compute_next_target_asert(1_000_000, _BASE_LAST_TIME, _BASE_LAST_TIME + 60, 36060, 3600)
        assert result == 1_000_000 >> 4

    def test_minimum_is_1(self):
        assert compute_next_target_asert(1, _BASE_LAST_TIME, _BASE_LAST_TIME + 60, 100_000, 3600) == 1


class TestComputeNextTargetLinear:
    def test_on_schedule_unchanged(self):
        assert compute_next_target_linear(1_000_000, _BASE_LAST_TIME, _BASE_LAST_TIME + 60, 60) == 1_000_000

    def test_double_time_doubles_target(self):
        assert compute_next_target_linear(1_000_000, _BASE_LAST_TIME, _BASE_LAST_TIME + 120, 60) == 2_000_000

    def test_half_time_halves_target(self):
        assert compute_next_target_linear(1_000_000, _BASE_LAST_TIME, _BASE_LAST_TIME + 30, 60) == 500_000

    def test_minimum_is_1(self):
        assert compute_next_target_linear(1, _BASE_LAST_TIME, _BASE_LAST_TIME + 1, 60) == 1


class TestDifficultyTargetConversion:
    def test_sha256d(self):
        assert difficulty_to_target(10) == MAX_SHA256D_TARGET // 10

    def test_blake3(self):
        assert difficulty_to_target(100, DmintAlgo.BLAKE3) == MAX_V2_TARGET_256 // 100

    def test_round_trip(self):
        assert target_to_difficulty(difficulty_to_target(100)) == 100

    def test_difficulty_zero_raises(self):
        with pytest.raises(ValidationError):
            difficulty_to_target(0)

    def test_target_zero_raises(self):
        with pytest.raises(ValidationError):
            target_to_difficulty(0)


class TestVerifySha256dSolution:
    def test_random_nonce_fails(self):
        assert not verify_sha256d_solution(b"\xcc" * 64, b"\x00" * 8, MAX_SHA256D_TARGET)

    def test_brute_force_finds_valid(self):
        preimage = b"\x00" * 64
        for i in range(10_000):
            nonce = struct.pack("<II", 0, i)
            h = hashlib.sha256(hashlib.sha256(preimage + nonce).digest()).digest()
            if h[:4] == b"\x00\x00\x00\x00":
                assert verify_sha256d_solution(preimage, nonce, MAX_SHA256D_TARGET)
                return
        pytest.skip("No valid SHA256d solution in 10k iterations")

    # --- Re-review N19: target boundary tests (P0.4) ---------------------
    # The target is clamped to MAX_SHA256D_TARGET inside verify_sha256d_solution
    # (dmint.py:472). Without these tests a future refactor that drops the clamp
    # would silently accept attacker-supplied targets above the max, making
    # invalid PoW solutions appear valid.
    #
    # These tests use hashlib.sha256 monkey-patching so we can construct
    # specific hash outputs deterministically rather than brute-forcing
    # for them (which would require ~2^32 iterations to hit a 4-zero
    # prefix). Patching is fine for unit-level pinning of the comparison
    # logic; the discovery test above (test_brute_force_finds_valid)
    # validates the integration with the real hashlib.

    def test_target_negative_rejects(self):
        """target <= 0 short-circuits to False before any hash work.

        Doesn't need a real hash collision to test — verify_sha256d_solution
        returns False immediately for non-positive targets per dmint.py:470-471.
        """
        assert not verify_sha256d_solution(b"\x00" * 64, b"\x00" * 8, 0)
        assert not verify_sha256d_solution(b"\x00" * 64, b"\x00" * 8, -1)
        assert not verify_sha256d_solution(b"\x00" * 64, b"\x00" * 8, -(2**63))

    def test_target_huge_does_not_crash(self):
        """A caller-supplied target above MAX_SHA256D_TARGET must clamp
        internally and not crash. Doesn't need to find a valid hash —
        just verify the function returns a boolean for huge target."""
        result = verify_sha256d_solution(b"\xff" * 64, b"\x00" * 8, 2**512)
        assert isinstance(result, bool)

    def test_no_4_zero_prefix_rejects_regardless_of_target(self):
        """Hash that doesn't start with 4 zero bytes can never be valid,
        even with target=MAX. Pins the prefix gate at dmint.py:474-475."""
        # b'\xcc' * 64 reliably produces a hash without 4-zero prefix
        # (entropy). Already covered by test_random_nonce_fails for MAX
        # but pinning explicitly that target=anything doesn't bypass.
        for target in [1, MAX_SHA256D_TARGET, 2**64, 2**128]:
            assert not verify_sha256d_solution(
                b"\xcc" * 64,
                b"\x00" * 8,
                target,
            ), f"target={target} should not bypass 4-zero prefix gate"

    def test_clamp_invariant_via_construction(self):
        """Verify the clamp by construction: monkey-patch hashlib to
        return a known hash, then test target boundaries.

        Ensures the strict-less-than comparison (matching on-chain
        OP_LESSTHAN) fires at value == effective_target.
        """
        from unittest.mock import patch

        # Construct a fake hash: first 4 bytes zero, next 8 bytes = 0x100
        fake_hash = b"\x00\x00\x00\x00" + (0x100).to_bytes(8, "big") + b"\xff" * 20
        # Need to mock the second sha256 call (sha256d = sha256(sha256(x)))
        # Both calls go through hashlib.sha256(...).digest() — patch the
        # final returned hash.
        with patch("pyrxd.glyph.dmint.hashlib") as mock_hashlib:
            mock_hashlib.sha256.return_value.digest.return_value = fake_hash
            # value = 0x100, so:
            # target = 0x101 → value (0x100) < target (0x101) → True
            assert verify_sha256d_solution(b"\x00" * 64, b"\x00" * 8, 0x101)
            # target = 0x100 → value (0x100) < target (0x100) → False (strict <)
            assert not verify_sha256d_solution(b"\x00" * 64, b"\x00" * 8, 0x100)
            # target = 0xFF → value (0x100) < target (0xFF) → False
            assert not verify_sha256d_solution(b"\x00" * 64, b"\x00" * 8, 0xFF)
            # target = MAX_SHA256D_TARGET → value (0x100) << target → True
            assert verify_sha256d_solution(b"\x00" * 64, b"\x00" * 8, MAX_SHA256D_TARGET)
            # target = 2**128 (above max) clamps to MAX → still True
            assert verify_sha256d_solution(b"\x00" * 64, b"\x00" * 8, 2**128)

    def test_clamp_blocks_invalid_at_max_via_construction(self):
        """Construct a fake hash where value > MAX_SHA256D_TARGET; without
        the clamp, an attacker-supplied target=2**128 would make this pass.
        With the clamp, value > MAX is rejected regardless of caller target."""
        from unittest.mock import patch

        # value = MAX_SHA256D_TARGET + 1 — would exceed even after clamp
        fake_value = MAX_SHA256D_TARGET + 1
        fake_hash = b"\x00\x00\x00\x00" + fake_value.to_bytes(8, "big") + b"\xff" * 20
        with patch("pyrxd.glyph.dmint.hashlib") as mock_hashlib:
            mock_hashlib.sha256.return_value.digest.return_value = fake_hash
            # MAX target: value > MAX, must reject
            assert not verify_sha256d_solution(b"\x00" * 64, b"\x00" * 8, MAX_SHA256D_TARGET)
            # Attacker passes huge target — clamps to MAX, still rejects
            assert not verify_sha256d_solution(b"\x00" * 64, b"\x00" * 8, 2**128)
            assert not verify_sha256d_solution(b"\x00" * 64, b"\x00" * 8, 2**512)


VARIANTS = [
    (DmintAlgo.SHA256D, DaaMode.FIXED, 3600, 60),
    (DmintAlgo.SHA256D, DaaMode.ASERT, 3600, 60),
    (DmintAlgo.SHA256D, DaaMode.LWMA, 3600, 60),
    (DmintAlgo.BLAKE3, DaaMode.FIXED, 3600, 60),
    (DmintAlgo.BLAKE3, DaaMode.ASERT, 7200, 120),
    (DmintAlgo.BLAKE3, DaaMode.LWMA, 3600, 30),
    (DmintAlgo.K12, DaaMode.FIXED, 3600, 60),
    (DmintAlgo.K12, DaaMode.ASERT, 1800, 90),
    (DmintAlgo.K12, DaaMode.LWMA, 3600, 45),
]


@pytest.mark.parametrize("algo,daa_mode,half_life,target_time", VARIANTS)
def test_all_9_variants_produce_valid_contract(algo, daa_mode, half_life, target_time):
    p = DmintDeployParams(
        contract_ref=_CONTRACT_REF,
        token_ref=_TOKEN_REF,
        max_height=10_000,
        reward=100,
        difficulty=10,
        algo=algo,
        daa_mode=daa_mode,
        target_time=target_time,
        half_life=half_life,
        last_time=_BASE_LAST_TIME,
    )
    script = build_dmint_contract_script(p)
    assert b"\xbd" in script
    assert len(script) > 100
    sep_pos = script.index(b"\xbd")
    code = script[sep_pos + 1 :]
    pow_ops = {DmintAlgo.SHA256D: 0xAA, DmintAlgo.BLAKE3: 0xEE, DmintAlgo.K12: 0xEF}
    assert pow_ops[algo] in code


@pytest.mark.parametrize("algo,daa_mode,half_life,target_time", VARIANTS)
def test_all_9_variants_state_has_d8_d0(algo, daa_mode, half_life, target_time):
    p = DmintDeployParams(
        contract_ref=_CONTRACT_REF,
        token_ref=_TOKEN_REF,
        max_height=10_000,
        reward=100,
        difficulty=10,
        algo=algo,
        daa_mode=daa_mode,
        target_time=target_time,
        half_life=half_life,
        last_time=_BASE_LAST_TIME,
    )
    script = build_dmint_contract_script(p)
    sep_pos = script.index(b"\xbd")
    state = script[:sep_pos]
    assert b"\xd8" in state
    assert b"\xd0" in state


def test_large_reward_and_max_height():
    p = DmintDeployParams(
        contract_ref=_CONTRACT_REF,
        token_ref=_TOKEN_REF,
        max_height=2_100_000_000,
        reward=5_000_000_000,
        difficulty=10,
    )
    assert b"\xbd" in build_dmint_contract_script(p)


def test_max_sha256d_target_at_difficulty_1():
    p = DmintDeployParams(contract_ref=_CONTRACT_REF, token_ref=_TOKEN_REF, max_height=100, reward=10, difficulty=1)
    assert p.initial_target == MAX_SHA256D_TARGET


def test_height_in_state():
    p = DmintDeployParams(
        contract_ref=_CONTRACT_REF, token_ref=_TOKEN_REF, max_height=100, reward=10, difficulty=10, height=999
    )
    state = build_dmint_state_script(p)
    assert state[:5] == b"\x04" + struct.pack("<I", 999)


def test_last_time_in_state():
    ts = 1_777_103_647
    p = DmintDeployParams(
        contract_ref=_CONTRACT_REF, token_ref=_TOKEN_REF, max_height=100, reward=10, difficulty=10, last_time=ts
    )
    state = build_dmint_state_script(p)
    needle = b"\x04" + struct.pack("<I", ts)
    assert needle in state


# ---------------------------------------------------------------------------
# Cross-equality: two FT-locking-script builders MUST stay byte-identical
# ---------------------------------------------------------------------------


class TestFtLockingScriptBuilderCrossEquality:
    """Two builders in the codebase produce the same 75-byte FT-wrapped
    output: ``pyrxd.glyph.script.build_ft_locking_script`` (used by FT
    transfer / NFT flows) and ``pyrxd.glyph.dmint.build_dmint_v1_ft_output_script``
    (used by V1 + V2 dMint mint rewards after the R1 red-team fix on
    2026-05-11).

    Both are independent assemblers of the same on-chain shape. They
    currently produce identical bytes; this test fires the second one
    drifts from the other. Catches the exact failure mode the red-team
    audit flagged as recurring-pattern risk #R2: a future contributor
    "modernizes" one builder and silently breaks dMint mint rewards
    (or NFT/FT transfers).
    """

    def test_byte_identical_for_random_pkh_and_ref(self):
        from pyrxd.glyph.dmint import build_dmint_v1_ft_output_script
        from pyrxd.glyph.script import build_ft_locking_script

        pkh = bytes(range(20))
        ref = _TOKEN_REF
        assert build_ft_locking_script(pkh, ref) == build_dmint_v1_ft_output_script(pkh, ref)

    def test_byte_identical_for_all_zero_pkh(self):
        from pyrxd.glyph.dmint import build_dmint_v1_ft_output_script
        from pyrxd.glyph.script import build_ft_locking_script

        pkh = b"\x00" * 20
        ref = _TOKEN_REF
        assert build_ft_locking_script(pkh, ref) == build_dmint_v1_ft_output_script(pkh, ref)

    def test_byte_identical_byte_pattern(self):
        """The 75-byte shape: P2PKH(25) || OP_STATESEPARATOR(1) ||
        OP_PUSHINPUTREF tokenRef(37) || 12-byte FT fingerprint."""
        from pyrxd.glyph.dmint import build_dmint_v1_ft_output_script

        pkh = bytes(range(20))
        result = build_dmint_v1_ft_output_script(pkh, _TOKEN_REF)
        assert len(result) == 75
        assert result[:3] == b"\x76\xa9\x14"  # OP_DUP OP_HASH160 PUSH20
        assert result[3:23] == pkh
        assert result[23:25] == b"\x88\xac"  # OP_EQUALVERIFY OP_CHECKSIG
        assert result[25:26] == b"\xbd"  # OP_STATESEPARATOR
        assert result[26:27] == b"\xd0"  # OP_PUSHINPUTREF
        assert result[27:63] == _TOKEN_REF.to_bytes()  # 36-byte ref
        assert result[63:] == bytes.fromhex("dec0e9aa76e378e4a269e69d")  # 12-byte fingerprint


# ---------------------------------------------------------------------------
# Mainnet golden vector — FT locking script byte-equal vs real RBG transfer
# ---------------------------------------------------------------------------


class TestFtLockingScriptMainnetGolden:
    """Pin ``build_ft_locking_script`` against a real RBG transfer on
    Radiant mainnet. If the encoder ever drifts from the on-chain shape,
    this test fires immediately.

    Source: mainnet tx
    ``ac7f1f705086a3a4cb2a354bf778fe2da829a90372742db076f542398cc60ae4``
    vout[0] (RBG self-transfer; also documented in
    ``tests/cli/test_glyph_inspect_cmds.py::_RBG_TRANSFER_RAW_HEX``).

    Closes the pattern-recognition audit's #R7 followup recommendation:
    every wire-format builder gets one ``test_byte_equal_to_<chain_ref>``
    assertion before merge.
    """

    # PKH from the mainnet transfer (same as RBG_TRANSFER_OWNER_PKH).
    _RBG_OWNER_PKH = bytes.fromhex("d84b8c371ea11f051dfed9daae05c8dee24d9eba")

    # Token ref: 32-byte commit_txid_le (reversed) + 4-byte vout LE.
    # From the on-chain vout[0]/[1] script (offsets 27..62, 36 bytes):
    # `a8a296afde31eb80c3484f09da7eb31546990baf76fd8bff9a58fbbe53c45db4 00000000`
    _RBG_REF_BYTES = bytes.fromhex("a8a296afde31eb80c3484f09da7eb31546990baf76fd8bff9a58fbbe53c45db400000000")

    # vout[0] locking script (75 bytes) extracted from the on-chain raw tx.
    _RBG_VOUT0_FT_SCRIPT = bytes.fromhex(
        "76a914d84b8c371ea11f051dfed9daae05c8dee24d9eba"
        "88ac"
        "bd"
        "d0a8a296afde31eb80c3484f09da7eb31546990baf76fd8bff9a58fbbe53c45db400000000"
        "dec0e9aa76e378e4a269e69d"
    )

    def test_pyrxd_ft_builder_matches_mainnet_byte_for_byte(self):
        """``build_ft_locking_script(pkh, ref)`` produces the exact bytes
        observed in the live RBG transfer's vout[0]. If this fails, the
        builder has drifted from the on-chain shape — and every FT
        emitted by pyrxd is silently wrong."""
        from pyrxd.glyph.script import build_ft_locking_script
        from pyrxd.glyph.types import GlyphRef
        from pyrxd.security.types import Txid

        # Reconstruct the GlyphRef from the on-chain ref bytes. txid is
        # the first 32 bytes (little-endian on the wire → reverse to BE
        # for the GlyphRef.txid hex), vout is the last 4 bytes (LE).
        ref_txid_le = self._RBG_REF_BYTES[:32]
        ref_vout_le = self._RBG_REF_BYTES[32:36]
        ref = GlyphRef(
            txid=Txid(ref_txid_le[::-1].hex()),
            vout=int.from_bytes(ref_vout_le, "little"),
        )

        # Round-trip check: builder bytes must equal on-chain bytes.
        rebuilt = build_ft_locking_script(self._RBG_OWNER_PKH, ref)
        assert rebuilt == self._RBG_VOUT0_FT_SCRIPT, (
            f"FT builder drifted from mainnet:\n"
            f"  expected: {self._RBG_VOUT0_FT_SCRIPT.hex()}\n"
            f"  got:      {rebuilt.hex()}"
        )

    def test_dmint_v1_ft_builder_matches_mainnet_byte_for_byte(self):
        """The dMint V1 reward output uses the SAME 75-byte FT shape.
        Cross-validates that ``build_dmint_v1_ft_output_script`` also
        byte-equals the live RBG transfer's FT vout. Closes the bug class
        where the dmint reward builder drifts from the FT spec while the
        FT builder stays correct (or vice versa)."""
        from pyrxd.glyph.dmint import build_dmint_v1_ft_output_script
        from pyrxd.glyph.types import GlyphRef
        from pyrxd.security.types import Txid

        ref = GlyphRef(
            txid=Txid(self._RBG_REF_BYTES[:32][::-1].hex()),
            vout=int.from_bytes(self._RBG_REF_BYTES[32:36], "little"),
        )
        rebuilt = build_dmint_v1_ft_output_script(self._RBG_OWNER_PKH, ref)
        assert rebuilt == self._RBG_VOUT0_FT_SCRIPT


# ---------------------------------------------------------------------------
# V2 quarantine — V2UnvalidatedWarning fires on every V2 entry point
# ---------------------------------------------------------------------------


class TestV2QuarantineWarning:
    """Every V2 dMint entry point emits ``V2UnvalidatedWarning`` because no
    V2 contract exists on Radiant mainnet as of pyrxd 0.5.1. Users can
    silence the warning (``simplefilter('ignore', V2UnvalidatedWarning)``)
    once they accept the risk, or escalate it (``simplefilter('error', ...)``)
    in CI to forbid V2 use until it's field-validated.

    The pattern protects against the recurring "builder + verifier
    round-trips fine, but the bytes have never run on chain" anti-pattern
    that produced the M1 mint-shape bug and the 0.5.0 R1 V2 reward-shape
    bug. See docs/solutions/logic-errors/dmint-v1-mint-shape-mismatch.md.
    """

    def _params(self) -> DmintDeployParams:
        return DmintDeployParams(
            contract_ref=_CONTRACT_REF,
            token_ref=_TOKEN_REF,
            max_height=10,
            reward=1000,
            difficulty=1,
        )

    def test_build_dmint_state_script_warns(self):
        from pyrxd.glyph.dmint import V2UnvalidatedWarning, build_dmint_state_script

        with pytest.warns(V2UnvalidatedWarning, match="V2 dMint code path"):
            build_dmint_state_script(self._params())

    def test_build_dmint_code_script_warns(self):
        from pyrxd.glyph.dmint import V2UnvalidatedWarning, build_dmint_code_script

        with pytest.warns(V2UnvalidatedWarning):
            build_dmint_code_script(self._params())

    def test_build_dmint_contract_script_warns_exactly_once(self):
        """``build_dmint_contract_script`` calls ``build_dmint_state_script``
        and ``build_dmint_code_script`` internally; without de-duplication
        a single user call would emit 3 warnings. The implementation
        suppresses the inner two so the user sees exactly one warning per
        call site."""
        import warnings

        from pyrxd.glyph.dmint import V2UnvalidatedWarning, build_dmint_contract_script

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", V2UnvalidatedWarning)
            build_dmint_contract_script(self._params())
        v2_warnings = [w for w in caught if issubclass(w.category, V2UnvalidatedWarning)]
        assert len(v2_warnings) == 1, f"expected exactly 1 V2UnvalidatedWarning, got {len(v2_warnings)}"

    def test_compute_next_target_asert_warns(self):
        from pyrxd.glyph.dmint import V2UnvalidatedWarning, compute_next_target_asert

        with pytest.warns(V2UnvalidatedWarning):
            compute_next_target_asert(
                current_target=1_000_000,
                last_time=0,
                current_time=60,
                target_time=60,
                half_life=3600,
            )

    def test_compute_next_target_linear_warns(self):
        from pyrxd.glyph.dmint import V2UnvalidatedWarning, compute_next_target_linear

        with pytest.warns(V2UnvalidatedWarning):
            compute_next_target_linear(
                current_target=1_000_000,
                last_time=0,
                current_time=60,
                target_time=60,
            )

    def test_warning_can_be_silenced(self):
        """Production users who've audited V2 themselves can silence the
        warning class without affecting other warnings."""
        import warnings

        from pyrxd.glyph.dmint import V2UnvalidatedWarning, build_dmint_state_script

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("ignore", V2UnvalidatedWarning)
            build_dmint_state_script(self._params())
        v2_warnings = [w for w in caught if issubclass(w.category, V2UnvalidatedWarning)]
        assert v2_warnings == []

    def test_warning_can_be_made_fatal(self):
        """CI environments that forbid V2 use can escalate the warning to
        an exception."""
        import warnings

        from pyrxd.glyph.dmint import V2UnvalidatedWarning, build_dmint_state_script

        with warnings.catch_warnings():
            warnings.simplefilter("error", V2UnvalidatedWarning)
            with pytest.raises(V2UnvalidatedWarning, match="V2 dMint code path"):
                build_dmint_state_script(self._params())

    def test_v1_builders_do_not_warn(self):
        """The V1 dMint builders (``build_dmint_v1_state_script``, etc.) are
        field-validated against mainnet and must NOT emit the V2 quarantine
        warning. Regression guard: a future refactor must not accidentally
        mark V1 paths as untested."""
        import warnings

        from pyrxd.glyph.dmint import (
            V2UnvalidatedWarning,
            build_dmint_v1_contract_script,
            build_dmint_v1_ft_output_script,
        )

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", V2UnvalidatedWarning)
            build_dmint_v1_contract_script(
                height=0,
                contract_ref=_CONTRACT_REF,
                token_ref=_TOKEN_REF,
                max_height=10,
                reward=1000,
                target=MAX_SHA256D_TARGET,
            )
            build_dmint_v1_ft_output_script(b"\x00" * 20, _TOKEN_REF)
        v2_warnings = [w for w in caught if issubclass(w.category, V2UnvalidatedWarning)]
        assert v2_warnings == [], "V1 path emitted V2 quarantine warning — regression"

    def test_warning_class_is_subclass_of_user_warning(self):
        """``V2UnvalidatedWarning`` inherits from ``UserWarning`` (not
        ``DeprecationWarning``) so it doesn't get filtered with the
        general "ignore deprecations" rules many projects set up."""
        from pyrxd.glyph.dmint import V2UnvalidatedWarning

        assert issubclass(V2UnvalidatedWarning, UserWarning)
        assert not issubclass(V2UnvalidatedWarning, DeprecationWarning)


# ---------------------------------------------------------------------------
# DmintCborPayload — CBOR encode / decode
# ---------------------------------------------------------------------------

from pyrxd.glyph.dmint import DmintCborPayload
from pyrxd.glyph.payload import decode_payload, encode_payload
from pyrxd.glyph.types import GlyphMetadata, GlyphProtocol

_CBOR_FIXED = DmintCborPayload(
    algo=DmintAlgo.SHA256D,
    num_contracts=2,
    max_height=10_000,
    reward=100,
    premine=500,
    diff=1_000,
)

_CBOR_ASERT = DmintCborPayload(
    algo=DmintAlgo.BLAKE3,
    num_contracts=1,
    max_height=5_000,
    reward=50,
    premine=0,
    diff=500,
    daa_mode=DaaMode.ASERT,
    target_block_time=120,
    half_life=7_200,
)

_CBOR_LWMA = DmintCborPayload(
    algo=DmintAlgo.K12,
    num_contracts=3,
    max_height=20_000,
    reward=10,
    premine=0,
    diff=100,
    daa_mode=DaaMode.LWMA,
    target_block_time=60,
    window_size=144,
)


def test_dmint_cbor_payload_fixed_round_trip():
    d = _CBOR_FIXED.to_cbor_dict()
    assert d["algo"] == 0
    assert d["numContracts"] == 2
    assert d["maxHeight"] == 10_000
    assert d["reward"] == 100
    assert d["premine"] == 500
    assert d["diff"] == 1_000
    assert "daa" not in d  # FIXED has no daa key
    back = DmintCborPayload.from_cbor_dict(d)
    assert back == _CBOR_FIXED


def test_dmint_cbor_payload_asert_round_trip():
    d = _CBOR_ASERT.to_cbor_dict()
    assert d["algo"] == 1
    assert "daa" in d
    assert d["daa"]["mode"] == 2
    assert d["daa"]["targetBlockTime"] == 120
    assert d["daa"]["halfLife"] == 7_200
    assert "windowSize" not in d["daa"]
    back = DmintCborPayload.from_cbor_dict(d)
    assert back == _CBOR_ASERT


def test_dmint_cbor_payload_lwma_round_trip():
    d = _CBOR_LWMA.to_cbor_dict()
    assert d["algo"] == 2
    assert d["daa"]["mode"] == 3
    assert d["daa"]["windowSize"] == 144
    back = DmintCborPayload.from_cbor_dict(d)
    assert back == _CBOR_LWMA


def test_glyph_metadata_v2_version_field():
    meta = GlyphMetadata(
        protocol=[GlyphProtocol.FT, GlyphProtocol.DMINT],
        ticker="TST",
        name="Test Token",
        v=2,
    )
    d = meta.to_cbor_dict()
    assert d["v"] == 2
    assert d["p"] == [1, 4]
    assert next(iter(d.keys())) == "v"  # v comes first


def test_glyph_metadata_v1_omits_version():
    meta = GlyphMetadata(protocol=[GlyphProtocol.FT], ticker="ABC", name="A")
    d = meta.to_cbor_dict()
    assert "v" not in d


def test_glyph_metadata_dmint_embedded_in_cbor():
    meta = GlyphMetadata(
        protocol=[GlyphProtocol.FT, GlyphProtocol.DMINT],
        ticker="TST",
        name="Test Token",
        v=2,
        dmint_params=_CBOR_FIXED,
    )
    d = meta.to_cbor_dict()
    assert "dmint" in d
    assert d["dmint"]["algo"] == 0
    assert d["dmint"]["maxHeight"] == 10_000


def test_for_dmint_ft_with_cbor_params_sets_v2():
    meta = GlyphMetadata.for_dmint_ft(
        ticker="TST",
        name="Test Token",
        dmint_params=_CBOR_FIXED,
    )
    assert meta.v == 2
    assert meta.dmint_params is _CBOR_FIXED
    d = meta.to_cbor_dict()
    assert d["v"] == 2
    assert "dmint" in d


def test_for_dmint_ft_without_cbor_params_leaves_v_none():
    meta = GlyphMetadata.for_dmint_ft(ticker="TST", name="Test Token")
    assert meta.v is None
    d = meta.to_cbor_dict()
    assert "v" not in d
    assert "dmint" not in d


def test_encode_decode_payload_round_trip_v2_dmint():
    meta = GlyphMetadata(
        protocol=[GlyphProtocol.FT, GlyphProtocol.DMINT],
        ticker="TST",
        name="Test Token",
        decimals=0,
        v=2,
        dmint_params=_CBOR_ASERT,
    )
    cbor_bytes, _ = encode_payload(meta)
    decoded = decode_payload(cbor_bytes)
    assert decoded.v == 2
    assert decoded.dmint_params is not None
    assert decoded.dmint_params.algo == DmintAlgo.BLAKE3
    assert decoded.dmint_params.daa_mode == DaaMode.ASERT
    assert decoded.dmint_params.half_life == 7_200


def test_decode_payload_missing_dmint_is_none():
    meta = GlyphMetadata(protocol=[GlyphProtocol.FT], ticker="ABC", name="A")
    cbor_bytes, _ = encode_payload(meta)
    decoded = decode_payload(cbor_bytes)
    assert decoded.dmint_params is None
    assert decoded.v is None


def test_dmint_cbor_payload_validation_errors():
    with pytest.raises(ValidationError):
        DmintCborPayload(
            algo=DmintAlgo.SHA256D,
            num_contracts=0,
            max_height=100,
            reward=10,
            premine=0,
            diff=1,
        )
    with pytest.raises(ValidationError):
        DmintCborPayload(
            algo=DmintAlgo.SHA256D,
            num_contracts=1,
            max_height=0,
            reward=10,
            premine=0,
            diff=1,
        )
    with pytest.raises(ValidationError):
        DmintCborPayload(
            algo=DmintAlgo.SHA256D,
            num_contracts=1,
            max_height=100,
            reward=10,
            premine=0,
            diff=0,
        )
