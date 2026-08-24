"""Pinned-token registry and base-unit arithmetic.

The failure this file exists to prevent is a 10^12 error: USDC is 6 decimals where ETH is 18, and
both travel as raw ints through the same code paths.
"""

from __future__ import annotations

import pytest

from pyrxd.eth_wallet.tokens import KNOWN_TOKENS, Erc20Token, token_by_address, token_for
from pyrxd.security.errors import ValidationError


class TestTheRegistryIsPinnedNotResolved:
    def test_usdc_is_six_decimals_on_every_pinned_chain(self) -> None:
        """One wrong entry is a 10^12 error on that chain only — the kind of per-chain
        conflation this project has hit repeatedly."""
        for (symbol, chain_id), token in KNOWN_TOKENS.items():
            if symbol == "USDC":
                assert token.decimals == 6, f"USDC on chain {chain_id} pinned at {token.decimals}"

    def test_an_unknown_symbol_or_chain_is_refused_not_guessed(self) -> None:
        with pytest.raises(ValidationError, match="no pinned"):
            token_for("DAI", 1)
        with pytest.raises(ValidationError, match="no pinned"):
            token_for("USDC", 999_999)

    @pytest.mark.parametrize(
        ("address", "chain_id", "what"),
        [
            ("0xFF970A61A04b1cA14834A43f5dE4533eBDDB5CC8", 42161, "Arbitrum"),
            ("0x7F5c764cBc14f9669B88837ca1490cCa17c31607", 10, "Optimism"),
        ],
    )
    def test_bridged_lookalikes_are_refused_BY_NAME(self, address: str, chain_id: int, what: str) -> None:
        """USDC.e is a different contract with different liquidity, and it shares the symbol.
        A bare "unknown token" would send the operator hunting; naming it tells them what they
        actually have."""
        with pytest.raises(ValidationError, match="bridged"):
            token_by_address(address, chain_id)

    def test_the_same_address_on_the_wrong_chain_is_not_the_same_asset(self) -> None:
        """A token address means nothing without its chain id."""
        mainnet_usdc = token_for("USDC", 1)
        with pytest.raises(ValidationError, match="no pinned token"):
            token_by_address(mainnet_usdc.address, 8453)

    def test_addresses_are_normalised_so_comparison_cannot_miss_on_case(self) -> None:
        assert token_for("USDC", 1).address == token_for("USDC", 1).address.lower()


class TestBaseUnitsCannotSilentlyLoseValue:
    @pytest.fixture
    def usdc(self) -> Erc20Token:
        return token_for("USDC", 1)

    def test_a_non_round_amount_converts_exactly(self, usdc: Erc20Token) -> None:
        assert usdc.base_units("12.345678") == 12_345_678
        assert usdc.base_units("1") == 1_000_000
        assert usdc.base_units("0.000001") == 1

    def test_a_float_is_refused_because_it_cannot_represent_the_amount(self, usdc: Erc20Token) -> None:
        """12.345678 is not representable in binary floating point. One base unit of drift fails
        the counterparty's funded-amount bind, so refuse the type outright."""
        with pytest.raises(ValidationError, match="decimal STRING"):
            usdc.base_units(12.345678)  # type: ignore[arg-type]

    def test_excess_precision_is_refused_rather_than_truncated(self, usdc: Erc20Token) -> None:
        """Silently dropping the tail is how a caller funds less than they negotiated."""
        with pytest.raises(ValidationError, match="decimal places"):
            usdc.base_units("1.1234567")

    @pytest.mark.parametrize("bad", ["-1", "abc", "1.2.3", "1e6", ""])
    def test_malformed_amounts_are_refused(self, usdc: Erc20Token, bad: str) -> None:
        with pytest.raises(ValidationError):
            usdc.base_units(bad)

    def test_the_honest_path_still_works_across_the_range(self, usdc: Erc20Token) -> None:
        """A guard that refuses valid work is a bug. Every ordinary amount must pass."""
        for whole, expected in [("0.01", 10_000), ("100", 100_000_000), ("1000000", 10**12)]:
            assert usdc.base_units(whole) == expected


class TestTheErc20HtlcArtifactMatchesWhatTheLegNeeds:
    """The artifact is compiled in a DIFFERENT REPO (`MudwoodLabs/pyrxd-eth-htlc`), so nothing in
    this one would notice it drifting. These are the cross-repo compatibility pins."""

    @staticmethod
    def _artifact() -> dict:
        import json
        from pathlib import Path

        return json.loads((Path(__file__).parent / "fixtures" / "Erc20Htlc.json").read_text())

    def test_it_has_the_keys_load_artifact_requires(self) -> None:
        art = self._artifact()
        for key in ("abi", "bytecode", "runtime_bytecode"):
            assert key in art, key
            assert art[key], f"{key} is empty"

    def test_the_claimed_event_keeps_the_preimage_UNINDEXED(self) -> None:
        """THE load-bearing pin. `eth_wallet/secret.py` recovers the secret by scanning the log
        DATA for a 32-byte window hashing to H. If the preimage were `indexed` it would live in
        topics as a HASH, the secret would be unrecoverable, and the failure would present as a
        successful swap with an unclaimable counter-leg."""
        events = [e for e in self._artifact()["abi"] if e.get("type") == "event" and e["name"] == "Claimed"]
        assert len(events) == 1, "exactly one Claimed event"
        (preimage,) = events[0]["inputs"]
        assert preimage["type"] == "bytes32"
        assert not preimage.get("indexed", False), "the preimage MUST stay in log data, not topics"

    def test_the_immutables_verify_funded_reads_back_are_all_present(self) -> None:
        """`verify_funded` binds the on-chain immutables to the negotiated terms. A missing getter
        is a check that silently cannot run."""
        getters = {f["name"] for f in self._artifact()["abi"] if f.get("type") == "function"}
        assert {"hashlock", "claimant", "refundee", "timeout", "token", "amount"} <= getters

    def test_there_is_no_approve_or_transferFrom_surface(self) -> None:
        """The design has no allowances at all. A funding path that appeared here would mean the
        contract had grown a pull mechanism nobody decided on."""
        names = {f["name"] for f in self._artifact()["abi"] if f.get("type") == "function"}
        assert not (names & {"approve", "transferFrom", "fund", "deposit"}), names


class TestTheRegistryValidatesAsStrictlyAsEveryOtherAddressField:
    """These were weaker than `locator._check_hex_addr` and than the `token_address` check on the
    negotiated terms — the same field, validated three ways on one branch."""

    def test_a_non_hex_address_is_refused_at_construction(self) -> None:
        """Prefix and length alone admit "0x" + "z"*40, deferring the failure to
        `to_checksum_address` at first on-chain use — far from the construction that caused it."""
        with pytest.raises(ValidationError, match="0x-prefixed 20-byte hex address"):
            Erc20Token("X", "0x" + "z" * 40, 6, 1)

    @pytest.mark.parametrize(
        ("label", "addr"),
        [
            # THE round-5 finding, measured: `bytes.fromhex` silently skips ASCII whitespace, so
            # this is 42 characters, round-trips as hex, and decodes to NINETEEN bytes.
            ("trailing whitespace padding a short address", "0x" + "ab" * 19 + "  "),
            ("interior whitespace", "0x" + "ab" * 10 + " " + "ab" * 9 + " "),
            ("a trailing newline", "0x" + "ab" * 20 + "\n"),
            ("no 0x prefix", "ab" * 20),
        ],
    )
    def test_whitespace_cannot_smuggle_a_SHORT_address_past_the_length_check(self, label: str, addr: str) -> None:
        """`len(addr) == 42` and a clean `bytes.fromhex` were BOTH true for the first case, which
        is why round 4's round-trip fix did not close this. Only an anchored ASCII regex does."""
        with pytest.raises(ValidationError, match="0x-prefixed 20-byte hex address"):
            Erc20Token(symbol="USDC", address=addr, decimals=6, chain_id=1)

    def test_an_honest_address_in_MIXED_case_is_still_accepted(self) -> None:
        """A guard that refuses valid work is a bug. Checksummed addresses are mixed-case by
        construction and must pass, normalising to lower."""
        t = Erc20Token(symbol="USDC", address="0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", decimals=6, chain_id=1)
        assert t.address == "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"

    def test_a_unicode_digit_amount_raises_the_documented_type(self) -> None:
        """`"²".isdigit()` is True but `int("²")` raises, so this escaped as a bare
        ValueError — which every caller here, catching ValidationError, would have missed."""
        with pytest.raises(ValidationError, match="not a decimal amount"):
            token_for("USDC", 1).base_units("²")

    @pytest.mark.parametrize("bad", ["²", "①"])  # NB fullwidth digits ARE decimal and int() parses them
    def test_other_unicode_digit_forms_too(self, bad: str) -> None:
        with pytest.raises(ValidationError):
            token_for("USDC", 1).base_units(bad)

    def test_the_honest_path_is_untouched(self) -> None:
        assert token_for("USDC", 1).base_units("12.345678") == 12_345_678
