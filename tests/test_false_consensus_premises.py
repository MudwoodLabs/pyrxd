"""Regression tests for Bitcoin rules that this SDK used to assert as Radiant's.

Each rule below was checked against Radiant Core at tag ``v3.1.2``
(``45e0aa40d6ae022ba69439a58b706748b083a35b`` — the pin in
``tests/vendor/radiant_core/MANIFEST.json``), not against pyrxd's own docs:

============================  =======================================================
Radiant's actual rule          Where it lives
============================  =======================================================
``GetDustThreshold`` == 1 sat  ``src/policy/policy.cpp:19-21``
``IsDust`` is ``nValue <= 0``  ``src/policy/policy.cpp:23-25``
``fRequireStandard`` == false  ``src/validation.cpp:271``; ``src/init.cpp:1995``
OP_RETURN policy cap == 1024   ``DEFAULT_DATACARRIER_BYTES``, ``src/script/standard.h:35``
relay floor 10_000_000 / kB    ``src/policy/policy.h:49``; charged at ``src/validation.cpp:779``
target block time 300s         ``nPowTargetSpacing``, ``src/chainparams.cpp:117``
Radiant SLIP-0044 coin type    512
============================  =======================================================

None of these is Bitcoin's number. The tests here fail if any of the corrected
premises regresses.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from pyrxd.constants import (
    DUST_THRESHOLD_PHOTONS,
    MAX_OP_RETURN_MSG_BYTES,
    TRANSACTION_FEE_RATE,
)
from pyrxd.fee_sizing import RADIANT_EFFECTIVE_MIN_RELAY_PHOTONS_PER_KB, min_relay_fee
from pyrxd.glyph.dmint import (
    DaaMode,
    DmintContractUtxo,
    DmintDeployParams,
    DmintMinerFundingUtxo,
    DmintState,
    build_dmint_contract_script,
    build_dmint_mint_tx,
    build_dmint_v1_contract_script,
)
from pyrxd.glyph.types import GlyphRef
from pyrxd.keys import PrivateKey
from pyrxd.script.type import P2PKH
from pyrxd.security.errors import PoolTooSmallError, ValidationError
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src" / "pyrxd"

_CONTRACT_REF = GlyphRef(txid="bb" * 32, vout=1)
_TOKEN_REF = GlyphRef(txid="bb" * 32, vout=0)
_MINER_PKH = b"\x33" * 20
_NONCE_V2 = bytes(8)
_NONCE_V1 = bytes(4)


def _contract_utxo(*, is_v1: bool = False) -> DmintContractUtxo:
    """A synthetic 1-photon dMint contract singleton (V1 or V2)."""
    if is_v1:
        script = build_dmint_v1_contract_script(
            height=0,
            contract_ref=_CONTRACT_REF,
            token_ref=_TOKEN_REF,
            max_height=100,
            reward=1_000,
            target=0x7FFFFFFFFFFFFFFF,
        )
    else:
        script = build_dmint_contract_script(
            DmintDeployParams(
                contract_ref=_CONTRACT_REF,
                token_ref=_TOKEN_REF,
                max_height=100,
                reward=1_000,
                difficulty=10,
                height=0,
                daa_mode=DaaMode.FIXED,
                target_time=60,
                half_life=3_600,
                last_time=0,
            )
        )
    state = DmintState.from_script(script)
    assert state.is_v1 is is_v1
    return DmintContractUtxo(txid="cc" * 32, vout=0, value=1, script=script, state=state)


def _funding(value: int = 500_000_000) -> DmintMinerFundingUtxo:
    return DmintMinerFundingUtxo(txid="aa" * 32, vout=0, value=value, script=b"\x76\xa9\x14" + bytes(20) + b"\x88\xac")


def _mint(*, is_v1: bool, op_return_msg: bytes | None, funding_value: int = 500_000_000):
    return build_dmint_mint_tx(
        _contract_utxo(is_v1=is_v1),
        _NONCE_V1 if is_v1 else _NONCE_V2,
        _MINER_PKH,
        0,
        funding_utxo=_funding(funding_value),
        op_return_msg=op_return_msg,
    )


# ---------------------------------------------------------------------------
# 1. The 80-byte OP_RETURN "standardness limit"
# ---------------------------------------------------------------------------


class TestOpReturnCapIsAnEncoderLimitNotStandardness:
    """Radiant never runs ``IsStandardTx`` (``fRequireStandard`` is hardcoded
    ``false``), so Bitcoin's 80-byte OP_RETURN cap has no force here. Even if it
    ran, the limit applied is ``nMaxDatacarrierBytes``, default
    ``DEFAULT_DATACARRIER_BYTES`` = 1024. pyrxd's real bound is its own
    OP_PUSHDATA1 encoder: a one-byte length field, hence 255."""

    def test_cap_is_255_not_80(self):
        assert MAX_OP_RETURN_MSG_BYTES == 255

    @pytest.mark.parametrize("is_v1", [False, True], ids=["v2", "v1"])
    @pytest.mark.parametrize("size", [81, 200, 255])
    def test_mint_accepts_op_return_over_80_bytes(self, is_v1: bool, size: int):
        """The refusal at 81..255 bytes was the false-premise lockout."""
        result = _mint(is_v1=is_v1, op_return_msg=b"z" * size)
        op_return = [o for o in result.tx.outputs if o.locking_script.serialize()[:1] == b"\x6a"]
        assert len(op_return) == 1
        script = op_return[0].locking_script.serialize()
        # OP_RETURN 0x03 "msg" OP_PUSHDATA1 <len> <body>
        assert script[:5] == b"\x6a\x03msg"
        assert script[5:7] == bytes([0x4C, size])
        assert script[7:] == b"z" * size

    @pytest.mark.parametrize("is_v1", [False, True], ids=["v2", "v1"])
    def test_mint_still_refuses_over_255_bytes(self, is_v1: bool):
        """256 bytes cannot be expressed by OP_PUSHDATA1 — a real limit."""
        with pytest.raises(ValidationError) as exc:
            _mint(is_v1=is_v1, op_return_msg=b"z" * 256)
        assert "OP_PUSHDATA1" in str(exc.value)

    @pytest.mark.parametrize("is_v1", [False, True], ids=["v2", "v1"])
    def test_refusal_no_longer_blames_standardness(self, is_v1: bool):
        with pytest.raises(ValidationError) as exc:
            _mint(is_v1=is_v1, op_return_msg=b"z" * 300)
        assert "standardness" not in str(exc.value).lower()

    def test_no_source_file_claims_an_80_byte_standardness_limit(self):
        offenders = [
            f"{p.relative_to(REPO_ROOT)}:{n}"
            for p in SRC.rglob("*.py")
            for n, line in enumerate(p.read_text().splitlines(), start=1)
            if "standardness limit is 80" in line or "standardness limit is 80 bytes" in line
        ]
        assert offenders == []


# ---------------------------------------------------------------------------
# 2. 546 — one definition, honestly labelled
# ---------------------------------------------------------------------------


class TestDustThresholdHasOneDefinition:
    """546 is Bitcoin's P2PKH dust convention. On Radiant it is pyrxd POLICY:
    ``GetDustThreshold`` returns 1 satoshi and ``IsDust`` is ``nValue <= 0``."""

    def test_every_radiant_side_alias_is_the_shared_constant(self):
        from pyrxd.glyph.builder import CommitParams
        from pyrxd.glyph.ft import DUST_LIMIT as FT_DUST_LIMIT
        from pyrxd.glyph.mint import NFT_CARRIER_VALUE
        from pyrxd.gravity.htlc_spend import DUST_FLOOR_PHOTONS
        from pyrxd.swap.partial import _DUST_PHOTONS as PARTIAL_DUST
        from pyrxd.swap.rswp.covenant import _DUST_PHOTONS as RSWP_DUST
        from pyrxd.wallet import DUST_THRESHOLD

        for alias in (
            DUST_THRESHOLD,
            FT_DUST_LIMIT,
            NFT_CARRIER_VALUE,
            DUST_FLOOR_PHOTONS,
            PARTIAL_DUST,
            RSWP_DUST,
            CommitParams.__dataclass_fields__["dust_limit"].default,
        ):
            assert alias == DUST_THRESHOLD_PHOTONS

    def test_bitcoin_leg_keeps_its_own_546_deliberately(self):
        """The BTC leg's 546 IS Bitcoin's real rule and must not be aliased away."""
        from pyrxd.btc_wallet import payment

        assert payment.DUST_LIMIT == 546
        src = (SRC / "btc_wallet" / "payment.py").read_text()
        assert "BITCOIN's dust limit" in src

    def test_only_two_modules_define_a_546_literal(self):
        """One Radiant-side definition (``constants``) + Bitcoin's (``btc_wallet``)."""
        allowed = {"constants.py", "btc_wallet/payment.py"}
        # An OPERATIONAL 546: assigned, compared, or passed as an argument. Prose that
        # explains the number is fine and is the point; a bare literal that a future edit
        # can move independently of the shared constant is not.
        pattern = re.compile(r"[=<>+\-*/(,\[]\s*546(?![\w])")
        offenders = set()
        for path in SRC.rglob("*.py"):
            rel = path.relative_to(SRC).as_posix()
            if rel in allowed:
                continue
            for n, line in enumerate(path.read_text().splitlines(), start=1):
                code = line.split("#", 1)[0]
                if pattern.search(code):
                    offenders.add(f"{rel}:{n}: {line.strip()}")
        assert offenders == set(), f"operational 546 literals outside the one definition: {sorted(offenders)}"

    def test_dmint_pool_too_small_does_not_claim_a_node_dust_limit(self):
        """The message used to read 'below 546 dust limit' — a limit no node applies."""
        # Reward 1_000 + fee; a funding UTXO just short of clearing the policy floor.
        with pytest.raises(PoolTooSmallError) as exc:
            _mint(is_v1=False, op_return_msg=None, funding_value=1_200)
        msg = str(exc.value)
        assert "dust limit" not in msg
        assert "pyrxd" in msg
        assert "Radiant's floor is 1 photon" in msg

    def test_no_source_file_says_below_546_dust_limit(self):
        offenders = [
            f"{p.relative_to(REPO_ROOT)}:{n}"
            for p in SRC.rglob("*.py")
            for n, line in enumerate(p.read_text().splitlines(), start=1)
            if "below 546 dust limit" in line
        ]
        assert offenders == []


# ---------------------------------------------------------------------------
# 3. Transaction.fee() default
# ---------------------------------------------------------------------------


class TestDefaultFeeRateClearsTheRelayFloor:
    """The old 5 photons/kB default was 2_000_000x under Radiant's floor, and
    Radiant has neither RBF nor CPFP to repair an under-fee'd transaction."""

    def test_constant_is_the_relay_floor(self):
        assert TRANSACTION_FEE_RATE == RADIANT_EFFECTIVE_MIN_RELAY_PHOTONS_PER_KB

    def test_default_model_pays_at_least_the_relay_floor(self):
        key = PrivateKey(998)
        locking = P2PKH().lock(key.address())
        src_tx = Transaction(tx_inputs=[], tx_outputs=[TransactionOutput(locking, 1_000_000_000)])
        tx = Transaction(
            tx_inputs=[
                TransactionInput(
                    source_transaction=src_tx,
                    source_output_index=0,
                    unlocking_script_template=P2PKH().unlock(key),
                )
            ],
            tx_outputs=[
                TransactionOutput(locking, 100_000_000, change=False),
                TransactionOutput(locking, None, change=True),
            ],
        )
        tx.fee()  # default model
        change = tx.outputs[-1].satoshis
        assert change is not None
        paid = 1_000_000_000 - 100_000_000 - change
        assert paid >= min_relay_fee(tx.estimated_byte_length())


# ---------------------------------------------------------------------------
# 4. BIP44 coin type
# ---------------------------------------------------------------------------


class TestBip44GuidanceUsesRadiantsCoinType:
    def test_hardened_derivation_error_suggests_512_not_0(self):
        from pyrxd.hd.bip32 import Xprv

        xprv = Xprv.from_seed(bytes(range(64)))
        with pytest.raises(ValidationError) as exc:
            xprv.xpub().ckd(0x80000000)
        message = str(exc.value)
        assert "m/44'/512'/0'" in message
        assert "m/44'/0'/0'" not in message

    def test_default_derivation_path_is_radiants(self):
        from pyrxd.constants import BIP44_DERIVATION_PATH

        assert BIP44_DERIVATION_PATH == "m/44'/512'/0'"


# ---------------------------------------------------------------------------
# 5. Block time and citation anchoring (prose that a reader will act on)
# ---------------------------------------------------------------------------


class TestProseAgreesWithRadiantCore:
    def test_no_doc_claims_a_two_minute_block_time(self):
        """``nPowTargetSpacing = 5 * 60`` on mainnet, testnet, scalenet and regtest."""
        tutorial = (REPO_ROOT / "docs" / "tutorials" / "mint-a-glyph-nft.md").read_text()
        assert "target block time is ~2 minutes" not in tutorial
        assert "~5 minutes" in tutorial
        confirm = (SRC / "network" / "confirm.py").read_text()
        assert "Radiant blocks target ~5 minutes" in confirm

    @pytest.mark.parametrize(
        "stale",
        ["init.cpp:1965", "feerate.cpp:51", "miner.cpp:380", "validation.cpp:856", "validation.cpp:770"],
    )
    def test_no_citation_points_at_a_stale_line_number(self, stale: str):
        """Line numbers are at the tag ``tests/vendor/radiant_core/MANIFEST.json`` pins."""
        roots = [SRC, REPO_ROOT / "docs" / "runbooks", REPO_ROOT / "docs" / "reference"]
        offenders = [
            f"{p.relative_to(REPO_ROOT)}:{n}"
            for root in roots
            for p in list(root.rglob("*.py")) + list(root.rglob("*.md"))
            for n, line in enumerate(p.read_text().splitlines(), start=1)
            if stale in line
        ]
        assert offenders == []

    def test_vendor_readme_states_the_citation_anchor(self):
        readme = (REPO_ROOT / "tests" / "vendor" / "radiant_core" / "README.md").read_text()
        assert "anchor for every Radiant-Core line citation" in readme

    def test_changelog_no_longer_states_the_wrong_case_count(self):
        changelog = (REPO_ROOT / "CHANGELOG.md").read_text()
        assert "(442 cases)" not in changelog
        assert "459 collected cases" in changelog
