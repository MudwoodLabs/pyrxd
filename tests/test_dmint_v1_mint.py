"""Tests for the dMint V1 mint path (Milestone 1 of dMint integration).

V1 is the only dMint contract format on Radiant mainnet. These tests mirror
``TestBuildDmintMintTx`` in ``test_dmint_end_to_end.py`` but exercise the V1
branch of ``build_dmint_mint_tx`` (4-byte nonce, 6-item state, fixed code
epilogue, no DAA).

The V1 builders themselves (``build_dmint_v1_state_script`` /
``build_dmint_v1_code_script`` / ``build_dmint_v1_contract_script``) are
also exercised here since they're new and the existing parser tests in
``test_dmint_end_to_end.py`` only fingerprint *parsed* V1 bytes (not bytes
we constructed ourselves).

The ``mine_solution`` and ``mine_solution_external`` reference miners are
exercised via monkey-patched ``hashlib.sha256`` so unit tests don't need to
brute-force a real 32-bit-leading-zero hash (which would take ~30 minutes
single-core in pure Python). The brute-force shape is covered by the
existing ``test_brute_force_finds_valid`` in ``test_dmint_module.py``.
"""

from __future__ import annotations

import json
import sys
import warnings
from unittest.mock import patch

import pytest

from pyrxd.glyph.dmint import (
    DEFAULT_MAX_ATTEMPTS,
    DaaMode,
    DmintAlgo,
    DmintContractUtxo,
    DmintMineResult,
    DmintMintResult,
    DmintState,
    build_dmint_mint_tx,
    build_dmint_v1_code_script,
    build_dmint_v1_contract_script,
    build_dmint_v1_state_script,
    build_mint_scriptsig,
    mine_solution,
    mine_solution_external,
    verify_sha256d_solution,
)
from pyrxd.glyph.types import GlyphRef
from pyrxd.security.errors import (
    ContractExhaustedError,
    MaxAttemptsError,
    PoolTooSmallError,
    ValidationError,
)

# ---------------------------------------------------------------------------
# Shared fixtures — mainnet-like RBG parameters
# ---------------------------------------------------------------------------

_CONTRACT_REF = GlyphRef(txid="aa" * 32, vout=1)
_TOKEN_REF = GlyphRef(txid="bb" * 32, vout=2)
_RBG_TARGET = 0x00DA740DA740DA74  # observed mainnet target on RBG, docs §2.3
_RBG_REWARD = 50_000
_RBG_MAX_HEIGHT = 628_328
_MINER_PKH = bytes(b"\x33" * 20)
_NONCE_V1 = bytes(4)


def _make_v1_contract_utxo(
    height: int = 0,
    pool: int = 100_000_000,
    target: int = _RBG_TARGET,
    max_height: int = _RBG_MAX_HEIGHT,
    reward: int = _RBG_REWARD,
    algo: DmintAlgo = DmintAlgo.SHA256D,
) -> DmintContractUtxo:
    """Synthesize a V1 dMint contract UTXO with mainnet-like parameters.

    Default pool of 100M photons covers reward (50k) + fee (~4M ph for a
    ~407-byte V1 mint tx at 10k photons/byte) with headroom.
    """
    script = build_dmint_v1_contract_script(
        height=height,
        contract_ref=_CONTRACT_REF,
        token_ref=_TOKEN_REF,
        max_height=max_height,
        reward=reward,
        target=target,
        algo=algo,
    )
    state = DmintState.from_script(script)
    return DmintContractUtxo(
        txid="cc" * 32,
        vout=0,
        value=pool,
        script=script,
        state=state,
    )


# ---------------------------------------------------------------------------
# 1. V1 script builders — round-trip through the parser
# ---------------------------------------------------------------------------


class TestBuildDmintV1ContractScript:
    def test_roundtrip_default(self):
        script = build_dmint_v1_contract_script(
            height=0,
            contract_ref=_CONTRACT_REF,
            token_ref=_TOKEN_REF,
            max_height=_RBG_MAX_HEIGHT,
            reward=_RBG_REWARD,
            target=_RBG_TARGET,
        )
        # 96-byte state + 145-byte epilogue (which begins with 0xbd) = 241
        assert len(script) == 241
        state = DmintState.from_script(script)
        assert state.is_v1
        assert state.height == 0
        assert state.max_height == _RBG_MAX_HEIGHT
        assert state.reward == _RBG_REWARD
        assert state.target == _RBG_TARGET
        assert state.contract_ref == _CONTRACT_REF
        assert state.token_ref == _TOKEN_REF
        assert state.algo == DmintAlgo.SHA256D
        assert state.daa_mode == DaaMode.FIXED
        assert state.target_time == 0
        assert state.last_time == 0

    def test_roundtrip_high_height(self):
        # Heights up to 0xFFFFFFFF must round-trip (4-byte LE encoding)
        script = build_dmint_v1_contract_script(
            height=0xDEADBEEF,
            contract_ref=_CONTRACT_REF,
            token_ref=_TOKEN_REF,
            max_height=0xFFFFFFFF,
            reward=1,
            target=1,
        )
        state = DmintState.from_script(script)
        assert state.height == 0xDEADBEEF
        assert state.max_height == 0xFFFFFFFF

    @pytest.mark.parametrize("algo", [DmintAlgo.SHA256D, DmintAlgo.BLAKE3, DmintAlgo.K12])
    def test_roundtrip_each_algo(self, algo: DmintAlgo):
        script = build_dmint_v1_contract_script(
            height=1,
            contract_ref=_CONTRACT_REF,
            token_ref=_TOKEN_REF,
            max_height=100,
            reward=1000,
            target=1,
            algo=algo,
        )
        state = DmintState.from_script(script)
        assert state.algo == algo
        assert state.is_v1

    def test_state_script_negative_height_raises(self):
        with pytest.raises(ValidationError, match="height"):
            build_dmint_v1_state_script(
                height=-1,
                contract_ref=_CONTRACT_REF,
                token_ref=_TOKEN_REF,
                max_height=100,
                reward=1000,
                target=1,
            )

    def test_state_script_target_too_large_raises(self):
        with pytest.raises(ValidationError, match="target"):
            build_dmint_v1_state_script(
                height=0,
                contract_ref=_CONTRACT_REF,
                token_ref=_TOKEN_REF,
                max_height=100,
                reward=1000,
                target=1 << 64,  # too large for 8-byte LE push
            )

    def test_code_script_length(self):
        # The V1 code epilogue starts with 0xbd (OP_STATESEPARATOR — part of
        # the epilogue itself, not a separator emitted by the contract builder)
        # and is 145 bytes total per docs/dmint-research-mainnet.md §3.
        for algo in (DmintAlgo.SHA256D, DmintAlgo.BLAKE3, DmintAlgo.K12):
            code = build_dmint_v1_code_script(algo)
            assert len(code) == 145
            assert code[0] == 0xBD


# ---------------------------------------------------------------------------
# 2. build_dmint_mint_tx — V1 path
# ---------------------------------------------------------------------------


class TestBuildDmintMintTxV1:
    def test_returns_dmint_mint_result(self):
        utxo = _make_v1_contract_utxo()
        result = build_dmint_mint_tx(utxo, _NONCE_V1, _MINER_PKH, current_time=0)
        assert isinstance(result, DmintMintResult)

    def test_updated_height_incremented(self):
        utxo = _make_v1_contract_utxo(height=42)
        result = build_dmint_mint_tx(utxo, _NONCE_V1, _MINER_PKH, current_time=0)
        assert result.updated_state.height == 43

    def test_updated_state_target_unchanged_v1_no_daa(self):
        # V1 has no DAA — target must always equal the input contract's target,
        # regardless of current_time.
        utxo = _make_v1_contract_utxo(height=10)
        result = build_dmint_mint_tx(utxo, _NONCE_V1, _MINER_PKH, current_time=999_999)
        assert result.updated_state.target == utxo.state.target

    def test_updated_state_is_v1_preserved(self):
        utxo = _make_v1_contract_utxo()
        result = build_dmint_mint_tx(utxo, _NONCE_V1, _MINER_PKH, current_time=0)
        assert result.updated_state.is_v1 is True
        assert result.updated_state.daa_mode == DaaMode.FIXED

    def test_contract_script_reparses_as_v1(self):
        utxo = _make_v1_contract_utxo(height=5)
        result = build_dmint_mint_tx(utxo, _NONCE_V1, _MINER_PKH, current_time=0)
        reparsed = DmintState.from_script(result.contract_script)
        assert reparsed.is_v1 is True
        assert reparsed.height == 6
        assert reparsed.target == utxo.state.target

    def test_contract_script_is_241_bytes(self):
        utxo = _make_v1_contract_utxo()
        result = build_dmint_mint_tx(utxo, _NONCE_V1, _MINER_PKH, current_time=0)
        assert len(result.contract_script) == 241

    def test_scriptsig_is_72_bytes_with_4byte_nonce(self):
        """V1 scriptSig: <0x04 nonce(4)> <0x20 inputHash(32)> <0x20 outputHash(32)> <0x00>"""
        utxo = _make_v1_contract_utxo()
        result = build_dmint_mint_tx(utxo, _NONCE_V1, _MINER_PKH, current_time=0)
        sig = result.tx.inputs[0].unlocking_script.script
        assert len(sig) == 72
        assert sig[0] == 0x04  # 4-byte push opcode (V1's nonce width)
        assert sig[5] == 0x20  # 32-byte push for inputHash
        assert sig[38] == 0x20  # 32-byte push for outputHash
        assert sig[71] == 0x00  # trailing OP_0

    def test_reward_script_is_p2pkh(self):
        utxo = _make_v1_contract_utxo()
        result = build_dmint_mint_tx(utxo, _NONCE_V1, _MINER_PKH, current_time=0)
        assert result.reward_script == b"\x76\xa9\x14" + _MINER_PKH + b"\x88\xac"

    def test_tx_has_one_input_two_outputs(self):
        utxo = _make_v1_contract_utxo()
        result = build_dmint_mint_tx(utxo, _NONCE_V1, _MINER_PKH, current_time=0)
        assert len(result.tx.inputs) == 1
        assert len(result.tx.outputs) == 2

    def test_tx_output_1_value_equals_reward(self):
        utxo = _make_v1_contract_utxo()
        result = build_dmint_mint_tx(utxo, _NONCE_V1, _MINER_PKH, current_time=0)
        assert result.tx.outputs[1].satoshis == utxo.state.reward

    def test_fee_is_positive(self):
        utxo = _make_v1_contract_utxo()
        result = build_dmint_mint_tx(utxo, _NONCE_V1, _MINER_PKH, current_time=0)
        assert result.fee > 0

    def test_exhausted_contract_raises_typed_error(self):
        # height >= max_height
        utxo = _make_v1_contract_utxo(height=_RBG_MAX_HEIGHT)
        with pytest.raises(ContractExhaustedError, match="exhausted"):
            build_dmint_mint_tx(utxo, _NONCE_V1, _MINER_PKH, current_time=0)

    def test_pool_too_small_raises_typed_error(self):
        # Pool = 10_000 < reward (50_000) + fee (~4M)
        utxo = _make_v1_contract_utxo(pool=10_000)
        with pytest.raises(PoolTooSmallError, match="too small"):
            build_dmint_mint_tx(utxo, _NONCE_V1, _MINER_PKH, current_time=0)

    def test_wrong_nonce_width_raises(self):
        # Caller passing a V2-width (8-byte) nonce against a V1 contract is an error.
        utxo = _make_v1_contract_utxo()
        with pytest.raises(ValidationError, match="V1 nonce"):
            build_dmint_mint_tx(utxo, bytes(8), _MINER_PKH, current_time=0)

    def test_wrong_pkh_length_raises(self):
        utxo = _make_v1_contract_utxo()
        with pytest.raises(ValidationError, match="miner_pkh"):
            build_dmint_mint_tx(utxo, _NONCE_V1, bytes(19), current_time=0)

    def test_consecutive_mints_chain_state(self):
        """The contract script from V1 mint N feeds V1 mint N+1."""
        utxo = _make_v1_contract_utxo(height=0)
        r1 = build_dmint_mint_tx(utxo, _NONCE_V1, _MINER_PKH, current_time=0)

        utxo2 = DmintContractUtxo(
            txid="dd" * 32,
            vout=0,
            value=r1.tx.outputs[0].satoshis,
            script=r1.contract_script,
            state=r1.updated_state,
        )
        r2 = build_dmint_mint_tx(utxo2, _NONCE_V1, _MINER_PKH, current_time=0)
        assert r2.updated_state.height == 2
        assert r2.updated_state.is_v1
        assert r2.updated_state.target == utxo.state.target  # still no DAA


# ---------------------------------------------------------------------------
# 3. build_mint_scriptsig — V1 width
# ---------------------------------------------------------------------------


class TestBuildMintScriptsigV1:
    def test_v1_scriptsig_layout(self):
        nonce = bytes.fromhex("01020304")
        preimage = b"\xaa" * 64
        sig = build_mint_scriptsig(nonce, preimage, nonce_width=4)
        assert len(sig) == 72
        assert sig[0:5] == b"\x04" + nonce
        assert sig[5] == 0x20
        assert sig[6:38] == preimage[:32]
        assert sig[38] == 0x20
        assert sig[39:71] == preimage[32:]
        assert sig[71] == 0x00

    def test_v2_default_scriptsig_layout(self):
        nonce = bytes.fromhex("0102030405060708")
        preimage = b"\xbb" * 64
        sig = build_mint_scriptsig(nonce, preimage)  # default nonce_width=8
        assert len(sig) == 76
        assert sig[0:9] == b"\x08" + nonce

    def test_wrong_nonce_width_raises(self):
        with pytest.raises(ValidationError, match="nonce_width"):
            build_mint_scriptsig(b"\x00" * 4, b"\x00" * 64, nonce_width=6)  # type: ignore[arg-type]

    def test_nonce_length_mismatch_raises(self):
        with pytest.raises(ValidationError, match="nonce must be"):
            build_mint_scriptsig(b"\x00" * 8, b"\x00" * 64, nonce_width=4)


# ---------------------------------------------------------------------------
# 4. verify_sha256d_solution — nonce_width parameterization
# ---------------------------------------------------------------------------


class TestVerifySha256dSolutionNonceWidth:
    def test_default_nonce_width_8_preserves_v2_behavior(self):
        # Pre-V1-support default is 8. Wrong-length nonce raises.
        with pytest.raises(ValidationError, match="nonce must be 8"):
            verify_sha256d_solution(b"\x00" * 64, b"\x00" * 4, 1)

    def test_nonce_width_4_for_v1(self):
        # 4-byte nonce works with nonce_width=4
        with patch("pyrxd.glyph.dmint.hashlib") as mock_hashlib:
            mock_hashlib.sha256.return_value.digest.return_value = b"\x00\x00\x00\x00" + b"\x00" * 28
            assert verify_sha256d_solution(b"\x00" * 64, b"\x00" * 4, 1, nonce_width=4)

    def test_invalid_nonce_width_raises(self):
        with pytest.raises(ValidationError, match="nonce_width"):
            verify_sha256d_solution(b"\x00" * 64, b"\x00" * 4, 1, nonce_width=5)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# 5. mine_solution — reference miner
# ---------------------------------------------------------------------------


class TestMineSolution:
    def test_finds_solution_on_first_attempt_via_mock(self):
        """Patch hashlib so the very first nonce satisfies the target.

        Real PoW search has a hard 32-bit leading-zero floor; brute-forcing
        in unit tests is impractical (~30 min single-core). Mock-based tests
        verify the search/verify integration without paying that cost.
        """
        fake_hash = b"\x00\x00\x00\x00" + (0).to_bytes(8, "big") + b"\xff" * 20
        with patch("pyrxd.glyph.dmint.hashlib") as mock_hashlib:
            mock_hashlib.sha256.return_value.digest.return_value = fake_hash
            result = mine_solution(b"\x00" * 64, target=1, nonce_width=4)
        assert isinstance(result, DmintMineResult)
        # First nonce sweep starts at 0 → little-endian 4 bytes of zero
        assert result.nonce == b"\x00\x00\x00\x00"
        assert result.attempts == 1
        assert result.elapsed_s >= 0.0

    def test_v2_nonce_width(self):
        fake_hash = b"\x00\x00\x00\x00" + (0).to_bytes(8, "big") + b"\xff" * 20
        with patch("pyrxd.glyph.dmint.hashlib") as mock_hashlib:
            mock_hashlib.sha256.return_value.digest.return_value = fake_hash
            result = mine_solution(b"\x00" * 64, target=1, nonce_width=8)
        assert len(result.nonce) == 8
        assert result.nonce == b"\x00" * 8

    def test_max_attempts_exhaustion_raises_typed_error(self):
        # No nonce satisfies the impossibly-tight target=1 with random preimage,
        # but the mock returns a hash that's too small to satisfy `value < target`.
        non_winning = b"\x00\x00\x00\x00" + (5).to_bytes(8, "big") + b"\xff" * 20
        with patch("pyrxd.glyph.dmint.hashlib") as mock_hashlib:
            mock_hashlib.sha256.return_value.digest.return_value = non_winning
            with pytest.raises(MaxAttemptsError) as exc_info:
                mine_solution(b"\x00" * 64, target=1, nonce_width=4, max_attempts=10)
        assert exc_info.value.attempts == 10
        assert exc_info.value.elapsed_s >= 0.0

    def test_invalid_nonce_width_raises(self):
        with pytest.raises(ValidationError, match="nonce_width"):
            mine_solution(b"\x00" * 64, target=1, nonce_width=5)  # type: ignore[arg-type]

    def test_invalid_preimage_length_raises(self):
        with pytest.raises(ValidationError, match="preimage"):
            mine_solution(b"\x00" * 32, target=1, nonce_width=4)

    def test_non_positive_target_raises(self):
        with pytest.raises(ValidationError, match="target"):
            mine_solution(b"\x00" * 64, target=0, nonce_width=4)

    def test_non_sha256d_algo_raises(self):
        with pytest.raises(NotImplementedError, match="BLAKE3"):
            mine_solution(b"\x00" * 64, target=1, algo=DmintAlgo.BLAKE3, nonce_width=4)

    def test_zero_max_attempts_raises(self):
        with pytest.raises(ValidationError, match="max_attempts"):
            mine_solution(b"\x00" * 64, target=1, nonce_width=4, max_attempts=0)


# ---------------------------------------------------------------------------
# 6. mine_solution_external — subprocess shim
# ---------------------------------------------------------------------------


def _make_mock_miner_script(tmp_path, response_dict):
    """Write a tiny Python script that ignores stdin and prints `response_dict` as JSON.

    Returns argv list to invoke it.
    """
    import stat

    response_json = json.dumps(response_dict)
    script_text = (
        "#!/usr/bin/env python3\n"
        "import json, sys\n"
        "sys.stdin.read()\n"  # consume request
        f"sys.stdout.write({response_json!r})\n"
    )
    path = tmp_path / "mock_miner.py"
    path.write_text(script_text)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return [sys.executable, str(path)]


class TestMineSolutionExternal:
    def test_accepts_valid_nonce(self, tmp_path):
        """Mock miner returns a known-good nonce; pyrxd re-verifies and accepts."""
        # Construct a fake hash that passes verify_sha256d_solution
        fake_hash = b"\x00\x00\x00\x00" + (0).to_bytes(8, "big") + b"\xff" * 20
        miner_argv = _make_mock_miner_script(
            tmp_path,
            {"nonce_hex": "deadbeef", "attempts": 12345, "elapsed_s": 0.5},
        )
        with patch("pyrxd.glyph.dmint.hashlib") as mock_hashlib:
            mock_hashlib.sha256.return_value.digest.return_value = fake_hash
            result = mine_solution_external(
                preimage=b"\x00" * 64,
                target=1,
                miner_argv=miner_argv,
                nonce_width=4,
                timeout_s=10,
            )
        assert result.nonce == bytes.fromhex("deadbeef")
        assert result.attempts == 12345

    def test_rejects_wrong_nonce(self, tmp_path):
        """A miner returning a nonce that fails local verification must raise."""
        # Mock verify to *fail* — i.e. don't patch hashlib, use a real fake_hash that won't match
        miner_argv = _make_mock_miner_script(
            tmp_path,
            {"nonce_hex": "deadbeef", "attempts": 1, "elapsed_s": 0.1},
        )
        # No hashlib patch → real verify_sha256d_solution runs on (preimage, deadbeef, 1)
        # which will fail because target=1 is impossibly tight.
        with pytest.raises(ValidationError, match="fails local SHA256d verification"):
            mine_solution_external(
                preimage=b"\x00" * 64,
                target=1,
                miner_argv=miner_argv,
                nonce_width=4,
                timeout_s=10,
            )

    def test_rejects_wrong_nonce_width(self, tmp_path):
        miner_argv = _make_mock_miner_script(
            tmp_path,
            {"nonce_hex": "deadbeefdeadbeef", "attempts": 1, "elapsed_s": 0.1},
        )
        with pytest.raises(ValidationError, match="wrong width"):
            mine_solution_external(
                preimage=b"\x00" * 64,
                target=1,
                miner_argv=miner_argv,
                nonce_width=4,  # but miner returned 8 bytes
                timeout_s=10,
            )

    def test_rejects_non_hex_nonce(self, tmp_path):
        miner_argv = _make_mock_miner_script(
            tmp_path,
            {"nonce_hex": "not-hex!", "attempts": 1, "elapsed_s": 0.1},
        )
        with pytest.raises(ValidationError, match="non-hex"):
            mine_solution_external(
                preimage=b"\x00" * 64,
                target=1,
                miner_argv=miner_argv,
                nonce_width=4,
                timeout_s=10,
            )

    def test_rejects_missing_nonce_field(self, tmp_path):
        miner_argv = _make_mock_miner_script(tmp_path, {"oops": "no nonce here"})
        with pytest.raises(ValidationError, match="nonce_hex"):
            mine_solution_external(
                preimage=b"\x00" * 64,
                target=1,
                miner_argv=miner_argv,
                nonce_width=4,
                timeout_s=10,
            )

    def test_rejects_non_json_stdout(self, tmp_path):
        # Script that prints garbage instead of JSON
        import stat

        path = tmp_path / "bad_miner.py"
        path.write_text("#!/usr/bin/env python3\nimport sys\nsys.stdin.read()\nsys.stdout.write('this is not json')\n")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
        with pytest.raises(ValidationError, match="non-JSON"):
            mine_solution_external(
                preimage=b"\x00" * 64,
                target=1,
                miner_argv=[sys.executable, str(path)],
                nonce_width=4,
                timeout_s=10,
            )

    def test_subprocess_timeout_raises_max_attempts(self, tmp_path):
        # Script that sleeps longer than the timeout
        import stat

        path = tmp_path / "slow_miner.py"
        path.write_text("#!/usr/bin/env python3\nimport time, sys\nsys.stdin.read()\ntime.sleep(10)\n")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
        with pytest.raises(MaxAttemptsError, match="did not return"):
            mine_solution_external(
                preimage=b"\x00" * 64,
                target=1,
                miner_argv=[sys.executable, str(path)],
                nonce_width=4,
                timeout_s=0.5,
            )

    def test_empty_argv_raises(self):
        with pytest.raises(ValidationError, match="miner_argv"):
            mine_solution_external(
                preimage=b"\x00" * 64,
                target=1,
                miner_argv=[],
                nonce_width=4,
            )


# ---------------------------------------------------------------------------
# 7. prepare_dmint_deploy — V2 footgun warning
# ---------------------------------------------------------------------------


class TestPrepareDmintDeployV2Warning:
    def test_emits_deprecation_warning(self):
        from pyrxd.glyph.builder import DmintFullDeployParams, GlyphBuilder
        from pyrxd.glyph.types import GlyphMetadata, GlyphProtocol
        from pyrxd.security.types import Hex20

        builder = GlyphBuilder()
        params = DmintFullDeployParams(
            metadata=GlyphMetadata(
                protocol=[GlyphProtocol.FT, GlyphProtocol.DMINT],
                name="TEST",
                ticker="TST",
            ),
            owner_pkh=Hex20(bytes(20)),
            max_height=1000,
            reward_photons=1000,
            difficulty=10,
            initial_pool_photons=10_000_000,
            contract_ref_placeholder=_CONTRACT_REF,
            token_ref_placeholder=_TOKEN_REF,
        )
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            builder.prepare_dmint_deploy(params)
        deprecation_warnings = [w for w in caught if issubclass(w.category, DeprecationWarning)]
        assert len(deprecation_warnings) >= 1
        msg = str(deprecation_warnings[0].message)
        assert "V2" in msg
        assert "M2" in msg or "Milestone 2" in msg


# ---------------------------------------------------------------------------
# 8. Slow brute-force smoke test — same shape as the existing V2 module test
# ---------------------------------------------------------------------------


@pytest.mark.skip(
    reason="real 32-bit leading-zero search is ~4B attempts on average; would skip in practice. Kept for future GPU/external-miner integration."
)
def test_brute_force_v1_finds_valid():
    """Real-hashlib brute force for a V1 nonce. Skipped by default —
    documents that the search loop integrates with real hashlib but cannot
    realistically complete in unit-test time given the 32-bit floor."""
    result = mine_solution(
        b"\x00" * 64,
        target=(1 << 63) - 1,  # max sha256d target
        nonce_width=4,
        max_attempts=DEFAULT_MAX_ATTEMPTS,
    )
    assert verify_sha256d_solution(b"\x00" * 64, result.nonce, (1 << 63) - 1, nonce_width=4)
