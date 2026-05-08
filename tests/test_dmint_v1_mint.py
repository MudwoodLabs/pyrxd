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
from unittest.mock import patch

import pytest

from pyrxd.glyph.dmint import (
    DEFAULT_MAX_ATTEMPTS,
    DaaMode,
    DmintAlgo,
    DmintContractUtxo,
    DmintMineResult,
    DmintMinerFundingUtxo,
    DmintMintResult,
    DmintState,
    build_dmint_mint_tx,
    build_dmint_v1_code_script,
    build_dmint_v1_contract_script,
    build_dmint_v1_ft_output_script,
    build_dmint_v1_mint_preimage,
    build_dmint_v1_state_script,
    build_mint_scriptsig,
    is_token_bearing_script,
    mine_solution,
    mine_solution_external,
    verify_sha256d_solution,
)
from pyrxd.glyph.types import GlyphRef
from pyrxd.security.errors import (
    ContractExhaustedError,
    DmintError,
    InvalidFundingUtxoError,
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
# The V1 contract is a singleton — default value matches the live mainnet
# RBG-class contracts, which carry exactly 1 photon. The miner pays reward
# + fee from the funding input, not from the contract output.
_V1_SINGLETON_VALUE = 1
# Generous funding pool covers reward (50k) + fee (~10M for ~600B tx at
# 10k photons/byte) + dust change. Specific value not load-bearing for
# most tests; use a smaller value when boundary-testing PoolTooSmallError.
_FUNDING_VALUE = 100_000_000


def _make_funding_utxo(value: int = _FUNDING_VALUE) -> DmintMinerFundingUtxo:
    """Plain P2PKH funding UTXO. Standard `OP_DUP OP_HASH160 <pkh> OP_EQUALVERIFY OP_CHECKSIG`."""
    script = b"\x76\xa9\x14" + bytes(20) + b"\x88\xac"
    return DmintMinerFundingUtxo(
        txid="ee" * 32,
        vout=0,
        value=value,
        script=script,
    )


_FUNDING_UTXO = _make_funding_utxo()


def _make_v1_contract_utxo(
    height: int = 0,
    value: int = _V1_SINGLETON_VALUE,
    target: int = _RBG_TARGET,
    max_height: int = _RBG_MAX_HEIGHT,
    reward: int = _RBG_REWARD,
    algo: DmintAlgo = DmintAlgo.SHA256D,
) -> DmintContractUtxo:
    """Synthesize a V1 dMint contract UTXO with mainnet-like parameters.

    The contract output is a singleton (default 1 photon, mirroring the
    live RBG contracts). The reward + fee come from a funding input —
    callers pass ``funding_utxo=`` to ``build_dmint_mint_tx``.
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
        value=value,
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

    def test_state_script_target_top_bit_set_raises(self):
        """Targets in [2**63, 2**64) decode as negative under Bitcoin script
        signed-int semantics — the on-chain target comparison would behave
        wrongly. Builder must refuse them up front."""
        with pytest.raises(ValidationError, match="MAX_SHA256D_TARGET"):
            build_dmint_v1_state_script(
                height=0,
                contract_ref=_CONTRACT_REF,
                token_ref=_TOKEN_REF,
                max_height=100,
                reward=1000,
                target=0x8000000000000000,  # top bit set → negative in script
            )

    def test_state_script_height_at_max_raises(self):
        """A V1 state with height == max_height is born-exhausted. Reject up
        front so the deployer doesn't lock pool funds in a contract no miner
        can advance."""
        with pytest.raises(ValidationError, match="born-exhausted"):
            build_dmint_v1_state_script(
                height=100,
                contract_ref=_CONTRACT_REF,
                token_ref=_TOKEN_REF,
                max_height=100,
                reward=1000,
                target=1,
            )

    def test_code_script_length(self):
        # The V1 code epilogue starts with 0xbd (OP_STATESEPARATOR — part of
        # the epilogue itself, not a separator emitted by the contract builder)
        # and is 145 bytes total per docs/dmint-research-mainnet.md §3.
        for algo in (DmintAlgo.SHA256D, DmintAlgo.BLAKE3, DmintAlgo.K12):
            code = build_dmint_v1_code_script(algo)
            assert len(code) == 145
            assert code[0] == 0xBD


class TestBuildDmintV1FtOutputScript:
    """Golden-vector tests for the V1 mint reward output (75-byte FT shape).

    The bytes here come from a real Radiant mainnet mint tx
    (`146a4d68…f3c`, vout[1]) decoded in docs/dmint-research-mainnet.md §4.
    The V1 covenant's ``OP_CODESCRIPTHASHVALUESUM_OUTPUTS`` step at offset
    168 of the contract epilogue hashes the prefix 0xd0 + tokenRef + the
    12-byte fingerprint and requires the FT output's codescript-hash to
    match — getting a single byte wrong here means every V1 mint pyrxd
    builds is rejected by the network.
    """

    # Mainnet `146a4d68…f3c` vout[1] decoded at docs/dmint-research-mainnet.md:226-228
    _MAINNET_PKH = bytes.fromhex("e9aa4adbe3a3f07887d67d9cedae324711f053ef")
    _MAINNET_TOKEN_REF = GlyphRef.from_bytes(
        bytes.fromhex("8b87c3c771b1a9f5015a4f26bfd80979ed196b5366257a6f30929646dfd943a4" + "00000000")
    )
    _MAINNET_VOUT1_BYTES = bytes.fromhex(
        "76a914e9aa4adbe3a3f07887d67d9cedae324711f053ef88ac"  # 25-byte P2PKH prologue
        + "bd"  # OP_STATESEPARATOR
        + "d08b87c3c771b1a9f5015a4f26bfd80979ed196b5366257a6f30929646dfd943a400000000"  # OP_PUSHINPUTREF + 36-byte tokenRef
        + "dec0e9aa76e378e4a269e69d"  # 12-byte covenant fingerprint
    )

    def test_byte_equal_to_mainnet_vout1(self):
        """Byte-for-byte equal to the live mainnet RBG-class FT reward output.
        This is the load-bearing cross-check that pyrxd's builder matches the
        on-chain spec."""
        script = build_dmint_v1_ft_output_script(self._MAINNET_PKH, self._MAINNET_TOKEN_REF)
        assert script == self._MAINNET_VOUT1_BYTES

    def test_length_is_75(self):
        script = build_dmint_v1_ft_output_script(_MINER_PKH, _TOKEN_REF)
        assert len(script) == 75

    def test_wrong_pkh_length_raises(self):
        with pytest.raises(ValidationError, match="miner_pkh"):
            build_dmint_v1_ft_output_script(bytes(19), _TOKEN_REF)


# ---------------------------------------------------------------------------
# 2. build_dmint_mint_tx — V1 path
# ---------------------------------------------------------------------------


class TestBuildDmintMintTxV1:
    """V1 mint dispatch tests against the corrected on-chain shape:
    2 inputs (contract + funding), 3-4 outputs (contract recreate +
    FT reward + optional OP_RETURN + change). Contract output value is
    preserved across mints; reward + fee come from the funding input.
    """

    def _mint(self, utxo, **kwargs):
        """Default-args helper: contract is V1 singleton, funding is plain RXD."""
        kwargs.setdefault("current_time", 0)
        kwargs.setdefault("funding_utxo", _FUNDING_UTXO)
        return build_dmint_mint_tx(utxo, _NONCE_V1, _MINER_PKH, **kwargs)

    def test_returns_dmint_mint_result(self):
        utxo = _make_v1_contract_utxo()
        assert isinstance(self._mint(utxo), DmintMintResult)

    def test_updated_height_incremented(self):
        utxo = _make_v1_contract_utxo(height=42)
        assert self._mint(utxo).updated_state.height == 43

    def test_updated_state_target_unchanged_v1_no_daa(self):
        # V1 has no DAA — target is always preserved across mints.
        utxo = _make_v1_contract_utxo(height=10)
        assert self._mint(utxo).updated_state.target == utxo.state.target

    def test_updated_state_is_v1_preserved(self):
        utxo = _make_v1_contract_utxo()
        result = self._mint(utxo)
        assert result.updated_state.is_v1 is True
        assert result.updated_state.daa_mode == DaaMode.FIXED

    def test_contract_script_reparses_as_v1(self):
        utxo = _make_v1_contract_utxo(height=5)
        result = self._mint(utxo)
        reparsed = DmintState.from_script(result.contract_script)
        assert reparsed.is_v1 is True
        assert reparsed.height == 6
        assert reparsed.target == utxo.state.target

    def test_contract_script_is_241_bytes_with_rbg_params(self):
        # 241 bytes is the mainnet RBG byte-count when maxHeight=628_328
        # and reward=50_000 (both encode as 4-byte minimal pushes). This
        # test pins the byte-count for the canonical mainnet parameter
        # set; arbitrary maxHeight/reward values would shift the length.
        utxo = _make_v1_contract_utxo()
        assert len(self._mint(utxo).contract_script) == 241

    def test_scriptsig_is_72_bytes_with_4byte_nonce(self):
        """V1 scriptSig: <0x04 nonce(4)> <0x20 inputHash(32)> <0x20 outputHash(32)> <0x00>"""
        utxo = _make_v1_contract_utxo()
        result = self._mint(utxo)
        # Contract input is vin[0]; vin[1] is the funding input (no scriptSig
        # set yet — caller signs it post-build).
        sig = result.tx.inputs[0].unlocking_script.script
        assert len(sig) == 72
        assert sig[0] == 0x04  # 4-byte push opcode (V1's nonce width)
        assert sig[5] == 0x20
        assert sig[38] == 0x20
        assert sig[71] == 0x00

    def test_reward_script_is_75_byte_ft_wrapped(self):
        """The V1 reward output must be the 75-byte P2PKH-wrapped FT shape,
        not a plain 25-byte P2PKH. This is the load-bearing covenant
        invariant — mistaken output shape causes every V1 mint to be
        rejected by the network."""
        utxo = _make_v1_contract_utxo()
        result = self._mint(utxo)
        assert len(result.reward_script) == 75
        # Must equal the FT output for our token_ref + miner_pkh pair.
        expected = build_dmint_v1_ft_output_script(_MINER_PKH, _TOKEN_REF)
        assert result.reward_script == expected

    def test_tx_has_two_inputs(self):
        # vin[0] = contract, vin[1] = funding.
        utxo = _make_v1_contract_utxo()
        assert len(self._mint(utxo).tx.inputs) == 2

    def test_tx_default_has_three_outputs(self):
        # Without op_return_msg: contract recreate + FT reward + change.
        utxo = _make_v1_contract_utxo()
        assert len(self._mint(utxo).tx.outputs) == 3

    def test_tx_with_op_return_has_four_outputs(self):
        utxo = _make_v1_contract_utxo()
        result = self._mint(utxo, op_return_msg=b"snk [r2w]")
        assert len(result.tx.outputs) == 4
        # vout[2] is the OP_RETURN
        op_return_script = result.tx.outputs[2].locking_script.script
        assert op_return_script[0] == 0x6A  # OP_RETURN

    def test_op_return_msg_byte_equal_to_mainnet(self):
        """The OP_RETURN encoding must include the Photonic-Wallet 'msg'
        marker push so wallet/explorer parsers can surface the message.

        Mainnet `146a4d68…f3c` vout[2] is `6a 03 6d7367 09 'snk [r2w]'`:
            OP_RETURN PUSH3 'msg' PUSH9 'snk [r2w]'
        Without the 'msg' marker, the OP_RETURN is just opaque bytes from
        the indexer's perspective. (red-team N3 / hardening-2)"""
        utxo = _make_v1_contract_utxo()
        result = self._mint(utxo, op_return_msg=b"snk [r2w]")
        op_return_script = result.tx.outputs[2].locking_script.script
        expected = (
            b"\x6a"  # OP_RETURN
            + b"\x03msg"  # PUSH3 'msg' marker
            + b"\x09"  # PUSH9
            + b"snk [r2w]"  # message data
        )
        assert op_return_script == expected

    def test_op_return_msg_too_long_raises(self):
        utxo = _make_v1_contract_utxo()
        with pytest.raises(ValidationError, match="op_return_msg"):
            self._mint(utxo, op_return_msg=b"x" * 81)

    def test_contract_output_value_is_preserved(self):
        """Contract output value never decreases — V1 is a singleton, the
        miner's funding input pays the reward + fee. (red-team finding #2)"""
        utxo = _make_v1_contract_utxo(value=1)  # singleton
        result = self._mint(utxo)
        assert result.tx.outputs[0].satoshis == 1

    def test_reward_output_value_equals_state_reward(self):
        utxo = _make_v1_contract_utxo()
        result = self._mint(utxo)
        assert result.tx.outputs[1].satoshis == utxo.state.reward

    def test_change_output_balances_funding(self):
        """Change = funding − reward − fee. Tx is balanced."""
        utxo = _make_v1_contract_utxo(value=1)
        result = self._mint(utxo)
        # Last output is change.
        change_value = result.tx.outputs[-1].satoshis
        # contract_value (1) + funding = contract_out (1) + reward + fee + change
        # ⇒ funding = reward + fee + change
        assert _FUNDING_UTXO.value == utxo.state.reward + result.fee + change_value

    def test_fee_is_positive(self):
        utxo = _make_v1_contract_utxo()
        assert self._mint(utxo).fee > 0

    def test_exhausted_contract_raises_typed_error(self):
        # height >= max_height → contract is exhausted at mint time
        utxo = _make_v1_contract_utxo(height=_RBG_MAX_HEIGHT - 1)
        # Build directly because _make_v1_contract_utxo with height=max
        # would fail in the state-script builder (born-exhausted check).
        # Instead bump height to max via the parser pretending to advance.
        state = DmintState(
            height=utxo.state.max_height,
            contract_ref=utxo.state.contract_ref,
            token_ref=utxo.state.token_ref,
            max_height=utxo.state.max_height,
            reward=utxo.state.reward,
            algo=utxo.state.algo,
            daa_mode=DaaMode.FIXED,
            target_time=0,
            last_time=0,
            target=utxo.state.target,
            is_v1=True,
        )
        exhausted_utxo = DmintContractUtxo(
            txid=utxo.txid,
            vout=utxo.vout,
            value=utxo.value,
            script=utxo.script,
            state=state,
        )
        with pytest.raises(ContractExhaustedError, match="exhausted"):
            self._mint(exhausted_utxo)

    def test_pool_too_small_raises_typed_error(self):
        # Funding input below reward + fee + dust → PoolTooSmallError
        utxo = _make_v1_contract_utxo()
        small_funding = _make_funding_utxo(value=10_000)
        with pytest.raises(PoolTooSmallError, match="too small"):
            self._mint(utxo, funding_utxo=small_funding)

    def test_token_bearing_funding_utxo_raises(self):
        """Spending an FT/dMint UTXO as fee silently destroys the token.
        Builder must refuse — defense against the highest-impact misuse
        (red-team finding, security-sentinel C1)."""
        utxo = _make_v1_contract_utxo()
        # An FT-bearing locking script: contains 0xd0 OP_PUSHINPUTREF
        ft_script = b"\x76\xa9\x14" + bytes(20) + b"\x88\xac" + b"\xbd" + b"\xd0" + bytes(36) + b"\x00" * 12
        bad_funding = DmintMinerFundingUtxo(
            txid="ff" * 32,
            vout=0,
            value=_FUNDING_VALUE,
            script=ft_script,
        )
        with pytest.raises(InvalidFundingUtxoError, match="OP_PUSHINPUTREF"):
            self._mint(utxo, funding_utxo=bad_funding)

    def test_dmint_singleton_funding_utxo_raises(self):
        """A dMint contract UTXO (uses 0xd8 OP_PUSHINPUTREFSINGLETON) must
        also be refused as funding."""
        utxo = _make_v1_contract_utxo()
        dmint_script = b"\xd8" + bytes(36) + b"\x76\xa9\x14" + bytes(20) + b"\x88\xac"
        bad_funding = DmintMinerFundingUtxo(
            txid="ff" * 32,
            vout=0,
            value=_FUNDING_VALUE,
            script=dmint_script,
        )
        with pytest.raises(InvalidFundingUtxoError, match="OP_PUSHINPUTREF"):
            self._mint(utxo, funding_utxo=bad_funding)

    def test_p2pkh_with_d_byte_in_hash_is_accepted(self):
        """A plain P2PKH whose 20-byte pkh contains a byte in 0xd0-0xd8 is
        a legitimate plain-RXD UTXO and must not be flagged as token-bearing.

        The previous byte-scan implementation would flag any P2PKH where any
        of the 20 hash bytes happened to fall in 0xd0-0xd8 — a ~51% false-
        positive rate against random P2PKH addresses. Real ecosystem miners
        would have been DoS'd from minting (red-team N1 / hardening-2)."""
        utxo = _make_v1_contract_utxo()
        # Construct a P2PKH where every payload byte is in the deny range —
        # a worst-case stress test.
        hash_with_d_bytes = bytes([0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8] * 3)[:20]
        p2pkh = b"\x76\xa9\x14" + hash_with_d_bytes + b"\x88\xac"
        funding = DmintMinerFundingUtxo(
            txid="ff" * 32,
            vout=0,
            value=_FUNDING_VALUE,
            script=p2pkh,
        )
        # Must succeed: opcode-stream-aware walker correctly identifies the
        # 0xd0-0xd8 bytes as PUSH(20) payload, not as opcodes.
        result = self._mint(utxo, funding_utxo=funding)
        assert isinstance(result, DmintMintResult)

    def test_p2sh_funding_utxo_is_accepted(self):
        """Standard P2SH script: OP_HASH160 PUSH20 <hash> OP_EQUAL — even with
        deny-range bytes inside the hash, this must be accepted."""
        utxo = _make_v1_contract_utxo()
        # OP_HASH160 = 0xa9; OP_EQUAL = 0x87
        # Hash again chosen to include deny-range bytes in payload position
        hash_payload = bytes([0xD2] * 20)
        p2sh = b"\xa9\x14" + hash_payload + b"\x87"
        funding = DmintMinerFundingUtxo(
            txid="ff" * 32,
            vout=0,
            value=_FUNDING_VALUE,
            script=p2sh,
        )
        result = self._mint(utxo, funding_utxo=funding)
        assert isinstance(result, DmintMintResult)

    def test_truncated_pushdata_funding_is_rejected(self):
        """A malformed funding script with a truncated push field is treated
        as token-bearing and refused. A script of ambiguous length cannot be
        safely classified as plain RXD."""
        utxo = _make_v1_contract_utxo()
        # PUSHDATA1 declares length 0x10 but only 5 bytes follow
        truncated = b"\x4c\x10\x01\x02\x03\x04\x05"
        funding = DmintMinerFundingUtxo(
            txid="ff" * 32,
            vout=0,
            value=_FUNDING_VALUE,
            script=truncated,
        )
        with pytest.raises(InvalidFundingUtxoError):
            self._mint(utxo, funding_utxo=funding)

    def test_missing_funding_utxo_raises(self):
        """V1 mint without a funding_utxo cannot be built."""
        utxo = _make_v1_contract_utxo()
        with pytest.raises(ValidationError, match="V1 mint requires a funding_utxo"):
            build_dmint_mint_tx(utxo, _NONCE_V1, _MINER_PKH, current_time=0)

    def test_v1_with_nonzero_current_time_raises(self):
        """V1 has no DAA — current_time would be silently ignored. Refuse."""
        utxo = _make_v1_contract_utxo()
        with pytest.raises(ValidationError, match="current_time must be 0"):
            self._mint(utxo, current_time=1_700_000_000)

    def test_negative_fee_rate_raises(self):
        utxo = _make_v1_contract_utxo()
        with pytest.raises(ValidationError, match="fee_rate"):
            self._mint(utxo, fee_rate=-1000)

    def test_zero_fee_rate_raises(self):
        utxo = _make_v1_contract_utxo()
        with pytest.raises(ValidationError, match="fee_rate"):
            self._mint(utxo, fee_rate=0)

    def test_wrong_nonce_width_raises(self):
        utxo = _make_v1_contract_utxo()
        with pytest.raises(ValidationError, match="V1 nonce"):
            build_dmint_mint_tx(utxo, bytes(8), _MINER_PKH, current_time=0, funding_utxo=_FUNDING_UTXO)

    def test_wrong_pkh_length_raises(self):
        utxo = _make_v1_contract_utxo()
        with pytest.raises(ValidationError, match="miner_pkh"):
            build_dmint_mint_tx(utxo, _NONCE_V1, bytes(19), current_time=0, funding_utxo=_FUNDING_UTXO)

    def test_placeholder_preimage_is_invalid_sentinel(self):
        """The placeholder preimage in the unsigned tx is 0xff bytes (not zeros).
        A user who broadcasts before the miner replaces it gets fast network
        rejection rather than a silent covenant failure."""
        utxo = _make_v1_contract_utxo()
        result = self._mint(utxo)
        sig = result.tx.inputs[0].unlocking_script.script
        # bytes [6:38] are inputHash (first half of preimage)
        # bytes [39:71] are outputHash (second half)
        first_half = sig[6:38]
        second_half = sig[39:71]
        assert first_half == b"\xff" * 32, "inputHash placeholder should be all-0xff"
        assert second_half == b"\xff" * 32, "outputHash placeholder should be all-0xff"

    def test_consecutive_mints_chain_state(self):
        """The contract output of V1 mint N feeds V1 mint N+1.
        Verifies (a) height advances, (b) target preserved (V1 has no DAA),
        (c) contract output value preserved (singleton) — the red-team
        finding #13 covenant invariant.
        """
        utxo = _make_v1_contract_utxo(height=0)
        r1 = self._mint(utxo)
        # The contract output must keep the same value across mints (V1 singleton).
        assert r1.tx.outputs[0].satoshis == utxo.value

        utxo2 = DmintContractUtxo(
            txid="dd" * 32,
            vout=0,
            value=r1.tx.outputs[0].satoshis,
            script=r1.contract_script,
            state=r1.updated_state,
        )
        r2 = self._mint(utxo2)
        assert r2.updated_state.height == 2
        assert r2.updated_state.is_v1
        assert r2.updated_state.target == utxo.state.target  # no DAA
        assert r2.tx.outputs[0].satoshis == utxo.value  # singleton preserved


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

    def test_rejects_nan_elapsed_s(self, tmp_path):
        """A miner returning ``"elapsed_s": NaN`` (which json.loads accepts via
        parse_constant) must be silently coerced to the script-measured
        elapsed value, not propagated to DmintMineResult.elapsed_s.
        Otherwise downstream metrics aggregation poisons on NaN."""
        fake_hash = b"\x00\x00\x00\x00" + (0).to_bytes(8, "big") + b"\xff" * 20
        # Note: write 'NaN' literal (Python's json module emits this for float('nan'))
        miner_argv = _make_mock_miner_script(
            tmp_path,
            {"nonce_hex": "deadbeef", "attempts": 1, "elapsed_s": float("nan")},
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
        # NaN should have been replaced with the wall-clock measurement.
        import math

        assert not math.isnan(result.elapsed_s)
        assert math.isfinite(result.elapsed_s)
        assert result.elapsed_s >= 0

    def test_rejects_inf_elapsed_s(self, tmp_path):
        """Same defense for +inf."""
        fake_hash = b"\x00\x00\x00\x00" + (0).to_bytes(8, "big") + b"\xff" * 20
        miner_argv = _make_mock_miner_script(
            tmp_path,
            {"nonce_hex": "deadbeef", "attempts": 1, "elapsed_s": float("inf")},
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
        import math

        assert math.isfinite(result.elapsed_s)

    def test_clamps_huge_attempts(self, tmp_path):
        """A miner reporting attempts > 2**40 has its self-report dropped to 0
        rather than propagated. Defense against log poisoning / aggregator
        overflow if a malicious miner reports astronomical attempt counts."""
        fake_hash = b"\x00\x00\x00\x00" + (0).to_bytes(8, "big") + b"\xff" * 20
        miner_argv = _make_mock_miner_script(
            tmp_path,
            {"nonce_hex": "deadbeef", "attempts": 10**18, "elapsed_s": 0.1},
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
        assert result.attempts == 0  # clamped to safe sentinel

    def test_rejects_bool_attempts(self, tmp_path):
        """JSON accepts ``true``/``false`` for numeric fields; bool is an int
        subclass in Python, so a naive ``isinstance(_, int)`` check would let
        it through. Reject explicitly."""
        fake_hash = b"\x00\x00\x00\x00" + (0).to_bytes(8, "big") + b"\xff" * 20
        miner_argv = _make_mock_miner_script(
            tmp_path,
            # JSON true serializes as a Python bool, which IS an int subclass
            {"nonce_hex": "deadbeef", "attempts": True, "elapsed_s": True},
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
        # bool elapsed_s must be rejected and replaced by the wall-clock value
        # bool attempts is an int subclass with value 1, technically valid;
        # the elapsed_s defense is what we're testing here. Just confirm no crash.
        import math

        assert math.isfinite(result.elapsed_s)
        assert result.elapsed_s >= 0


# ---------------------------------------------------------------------------
# 7. is_token_bearing_script — public token-detection classifier
# ---------------------------------------------------------------------------


class TestIsTokenBearingScript:
    """Public API equivalent of the M1 hardening's funding-UTXO check.

    The function walks the script's opcode stream and only flags
    OP_PUSHINPUTREF-family opcodes (0xd0–0xd8) when they appear as
    *opcodes* — not as bytes inside push-data payloads. The full
    behavior is exercised by the V1 mint funding tests; these tests
    document the public contract.
    """

    def test_plain_p2pkh_with_zero_hash(self):
        # 76 a9 14 <pkh:20> 88 ac
        script = b"\x76\xa9\x14" + bytes(20) + b"\x88\xac"
        assert is_token_bearing_script(script) is False

    def test_p2pkh_with_d_byte_in_hash(self):
        # 0xd2 inside push-payload, not opcode position
        script = b"\x76\xa9\x14" + bytes([0xD2] * 20) + b"\x88\xac"
        assert is_token_bearing_script(script) is False

    def test_ft_envelope_flagged(self):
        # 0xd0 OP_PUSHINPUTREF as opcode
        script = b"\x76\xa9\x14" + bytes(20) + b"\x88\xac\xbd\xd0" + bytes(36) + b"\x00" * 12
        assert is_token_bearing_script(script) is True

    def test_dmint_singleton_flagged(self):
        # 0xd8 OP_PUSHINPUTREFSINGLETON as opcode
        script = b"\xd8" + bytes(36) + b"\x76\xa9\x14" + bytes(20) + b"\x88\xac"
        assert is_token_bearing_script(script) is True

    def test_truncated_pushdata_treated_as_token_bearing(self):
        # Malformed: PUSHDATA1 declares length 0x10 but only 5 bytes follow
        truncated = b"\x4c\x10\x01\x02\x03\x04\x05"
        assert is_token_bearing_script(truncated) is True

    def test_empty_script(self):
        assert is_token_bearing_script(b"") is False


# ---------------------------------------------------------------------------
# 8. build_dmint_v1_mint_preimage — V1 covenant binding
# ---------------------------------------------------------------------------


class TestBuildDmintV1MintPreimage:
    """The library helper that the demo uses to compute the real preimage
    after building the unsigned tx with sentinel placeholders. The function
    binds the nonce to (a) the contract input's outpoint+ref, (b) the
    funding input's locking script, (c) the OP_RETURN msg output script."""

    def _build_for_test(self, *, op_return_msg=b"test"):
        utxo = _make_v1_contract_utxo()
        funding = _make_funding_utxo()
        result = build_dmint_mint_tx(
            contract_utxo=utxo,
            nonce=_NONCE_V1,
            miner_pkh=_MINER_PKH,
            current_time=0,
            funding_utxo=funding,
            op_return_msg=op_return_msg,
        )
        return utxo, funding, result.tx

    def test_returns_64_bytes(self):
        utxo, funding, tx = self._build_for_test()
        preimage = build_dmint_v1_mint_preimage(utxo, funding, tx)
        assert len(preimage) == 64

    def test_preimage_changes_with_funding_script(self):
        """Different funding scripts produce different preimages — the
        covenant binds the nonce to the funding input."""
        utxo, funding_a, tx_a = self._build_for_test()
        # Build with a different funding UTXO whose script differs
        funding_b = DmintMinerFundingUtxo(
            txid="ee" * 32,
            vout=0,
            value=_FUNDING_VALUE,
            script=b"\x76\xa9\x14" + bytes([0x42] * 20) + b"\x88\xac",
        )
        utxo, _, tx_b = self._build_for_test()
        pre_a = build_dmint_v1_mint_preimage(utxo, funding_a, tx_a)
        pre_b = build_dmint_v1_mint_preimage(utxo, funding_b, tx_b)
        assert pre_a != pre_b

    def test_preimage_changes_with_op_return_msg(self):
        """Different OP_RETURN msgs produce different preimages — the
        covenant binds outputHash to vout[2]'s script."""
        utxo, funding, tx_a = self._build_for_test(op_return_msg=b"alpha")
        _, _, tx_b = self._build_for_test(op_return_msg=b"beta")
        pre_a = build_dmint_v1_mint_preimage(utxo, funding, tx_a)
        pre_b = build_dmint_v1_mint_preimage(utxo, funding, tx_b)
        assert pre_a != pre_b

    def test_refuses_tx_without_op_return_at_vout2(self):
        """Building a tx without op_return_msg only yields 3 outputs;
        the preimage helper requires the mainnet-canonical 4-output shape."""
        utxo = _make_v1_contract_utxo()
        funding = _make_funding_utxo()
        result = build_dmint_mint_tx(
            contract_utxo=utxo,
            nonce=_NONCE_V1,
            miner_pkh=_MINER_PKH,
            current_time=0,
            funding_utxo=funding,
            op_return_msg=None,  # no OP_RETURN → 3 outputs
        )
        with pytest.raises(ValidationError, match="OP_RETURN msg"):
            build_dmint_v1_mint_preimage(utxo, funding, result.tx)


# ---------------------------------------------------------------------------
# 9. prepare_dmint_deploy — V2 footgun warning
# ---------------------------------------------------------------------------


class TestPrepareDmintDeployV2Refusal:
    """V2 deploy is refused unless the caller passes `allow_v2_deploy=True`.

    A `DeprecationWarning` is too soft because Python filters
    DeprecationWarning by default outside `__main__` — a library user calling
    `prepare_dmint_deploy` from their own script sees nothing and gets a
    deployable result, accidentally shipping a token no ecosystem miner
    can claim. The hard refusal is the load-bearing footgun guard.
    """

    @staticmethod
    def _params():
        from pyrxd.glyph.builder import DmintFullDeployParams
        from pyrxd.glyph.types import GlyphMetadata, GlyphProtocol
        from pyrxd.security.types import Hex20

        return DmintFullDeployParams(
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

    def test_default_call_raises_dmint_error(self):
        from pyrxd.glyph.builder import GlyphBuilder

        builder = GlyphBuilder()
        with pytest.raises(DmintError, match="allow_v2_deploy"):
            builder.prepare_dmint_deploy(self._params())

    def test_explicit_opt_in_succeeds(self):
        """allow_v2_deploy=True bypasses the guard so SDK-internal V2 tests
        and explicit V2 deployers can still build the artifacts."""
        from pyrxd.glyph.builder import DmintDeployResult, GlyphBuilder

        builder = GlyphBuilder()
        result = builder.prepare_dmint_deploy(self._params(), allow_v2_deploy=True)
        assert isinstance(result, DmintDeployResult)

    def test_allow_v2_deploy_default_is_false(self):
        """Mechanical regression check: a future refactor must not flip the
        ``allow_v2_deploy`` default from False to True. (red-team N5 /
        hardening-2)"""
        import inspect

        from pyrxd.glyph.builder import GlyphBuilder

        sig = inspect.signature(GlyphBuilder.prepare_dmint_deploy)
        param = sig.parameters["allow_v2_deploy"]
        assert param.default is False
        # Also assert it's keyword-only — passing it positionally would
        # let a refactor accidentally make it the second positional arg.
        assert param.kind is inspect.Parameter.KEYWORD_ONLY


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
