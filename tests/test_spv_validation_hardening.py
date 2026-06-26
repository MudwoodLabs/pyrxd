"""Mutation-driven SPV input-validation hardening tests.

cosmic-ray mutation testing of ``src/pyrxd/spv`` (2026-06) surfaced surviving mutants in the **length
guards** and the **chain-link check** of ``pow.py`` / ``chain.py`` — those branches execute, but no
existing test fed an adversarial length or a broken link, so flipping ``!= 80`` to ``< 80`` (etc.) went
undetected. Each test here kills a specific surviving mutant, hardening the SPV verifier's input
validation — the first line of defense before any PoW/Merkle math runs.
"""

from __future__ import annotations

import pytest

from pyrxd.security.errors import SpvVerificationError, ValidationError
from pyrxd.spv.chain import verify_chain
from pyrxd.spv.pow import verify_header_pow

# Real, consecutive mainnet headers: block 840000 -> 840001 (840001.prevHash == hash256(840000)).
BLOCK_840000 = bytes.fromhex(
    "00e05f2aab948491071265ad552351d0ad625745668da54b01720100000000000000"
    "00004f89a5d73bd4d4887f25981fe81892ccafda10c27f52d6f3dd28183a7c411b03"
    "b7072366194203177d9863ea"
)
BLOCK_840001 = bytes.fromhex(
    "04002020a583da1c3ff29b687248ff737822f8ce4827033a28200300000000000000"
    "0000bcc07f8618b7b063f833100724e2b40d6ee9dfa78087bfbe5d3441058a63de38"
    "0e082366194203176d9026cc"
)


class TestPowHeaderLengthGuard:
    # Use a REAL header +/- a byte (not all-zeros): the length guard must reject as ValidationError BEFORE
    # any PoW math. A mutated guard (`< 80` / `> 80`) falls through to PoW on the wrong-length data, which
    # raises SpvVerificationError instead -> the mismatch kills the mutant. (All-zeros wouldn't work: the
    # downstream Nbits check rejects zero-mantissa as ValidationError either way, masking the mutation.)
    @pytest.mark.parametrize("header", [BLOCK_840000 + b"\x00", BLOCK_840000[:79]], ids=["81-byte", "79-byte"])
    def test_rejects_wrong_length_header(self, header: bytes) -> None:
        with pytest.raises(ValidationError):
            verify_header_pow(header)


class TestChainLengthGuards:
    @pytest.mark.parametrize("n", [79, 81])
    def test_rejects_wrong_length_header(self, n: int) -> None:
        with pytest.raises(ValidationError):
            verify_chain([b"\x00" * n])

    @pytest.mark.parametrize("n", [31, 33])
    def test_rejects_wrong_length_chain_anchor(self, n: int) -> None:
        with pytest.raises(ValidationError, match="chain_anchor"):
            verify_chain([BLOCK_840000], chain_anchor=b"\x00" * n)

    @pytest.mark.parametrize("n", [3, 5])
    def test_rejects_wrong_length_expected_nbits(self, n: int) -> None:
        with pytest.raises(ValidationError, match="expected_nbits"):
            verify_chain([BLOCK_840000], expected_nbits=b"\x00" * n)

    @pytest.mark.parametrize("n", [3, 5])
    def test_rejects_wrong_length_expected_nbits_next(self, n: int) -> None:
        with pytest.raises(ValidationError, match="expected_nbits_next"):
            verify_chain([BLOCK_840000], expected_nbits=b"\xff\xff\x00\x1d", expected_nbits_next=b"\x00" * n)


class TestChainLinkVerification:
    def test_valid_consecutive_link_passes(self) -> None:
        # A genuinely linked 2-header chain must NOT raise — kills `!=` -> `==` / `>=` / `<=` on the
        # link check (those wrongly reject a valid link where prevHash == hash(prev)).
        hashes = verify_chain([BLOCK_840000, BLOCK_840001])
        assert len(hashes) == 2

    def test_broken_link_rejected(self) -> None:
        # Reversed order: header[1] (840000).prevHash != hash256(840001) -> broken link.
        with pytest.raises(SpvVerificationError, match="chain link broken"):
            verify_chain([BLOCK_840001, BLOCK_840000])
