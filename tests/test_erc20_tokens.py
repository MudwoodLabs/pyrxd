"""Pinned-token registry and base-unit arithmetic.

The failure this file exists to prevent is a 10^12 error: USDC is 6 decimals where ETH is 18, and
both travel as raw ints through the same code paths.
"""

from __future__ import annotations

import pytest

from pyrxd.eth_wallet.chains import evm_chain_by_id
from pyrxd.eth_wallet.tokens import (
    _BRIDGED_LOOKALIKES,
    KNOWN_TOKENS,
    Erc20Token,
    token_by_address,
    token_for,
)
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

    @pytest.mark.parametrize("address", sorted(_BRIDGED_LOOKALIKES))
    def test_EVERY_lookalike_is_refused_and_named(self, address: str) -> None:
        """Parametrised over the registry itself, not over a hand-copied list.

        The hand-written list covered the two USDC.e entries and silently missed the others as
        they were added — a refusal nobody tests is a refusal nobody notices losing. Driving the
        parametrisation off `_BRIDGED_LOOKALIKES` means a new entry cannot be added without
        arriving with this test already applied to it.

        The assertion is that the message NAMES the thing, because a bare "unknown token" sends
        an operator hunting for a typo when what they actually hold is a different asset.
        """
        with pytest.raises(ValidationError) as exc:
            token_by_address(address, 1)
        assert _BRIDGED_LOOKALIKES[address] in str(exc.value)

    def test_the_lookalike_that_ALSO_differs_in_decimals(self) -> None:
        """BNB Smart Chain's Binance-Peg "USDC" is 18 decimals where Circle's is 6 everywhere.

        Every other look-alike matches Circle's metadata exactly, which is the stated reason the
        address is the only discriminator. This one would be a wrong-issuer error AND a 10^12
        scale error at once, so it is pinned as refused rather than left to a symbol lookup.
        """
        bsc_pegged = "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d"
        assert bsc_pegged in _BRIDGED_LOOKALIKES
        assert "18 decimals" in _BRIDGED_LOOKALIKES[bsc_pegged]
        for (symbol, chain_id), token in KNOWN_TOKENS.items():
            assert token.address != bsc_pegged, f"refused look-alike pinned as {symbol} on {chain_id}"

    def test_BSC_fails_closed_on_BOTH_the_token_and_the_chain(self) -> None:
        """BSC USDT audits clean but BSC's finality is its own validator set's, not Ethereum's.

        Both refusals are asserted because they are independent: pinning the token later without
        answering the chain question would produce a swap whose reorg gate silently means
        something else. Measured 2026-08-25: BSC's `finalized` tag runs 0-2 s behind the tip,
        where an Ethereum-anchored chain cannot beat the 768 s L1 checkpoint.
        """
        with pytest.raises(ValidationError, match="no pinned"):
            token_for("USDT", 56)
        with pytest.raises(ValidationError, match="unknown EVM chain id"):
            evm_chain_by_id(56)

    def test_the_chains_that_ARE_supported_still_resolve(self) -> None:
        """The honest-path pair for the refusals above — a fail-closed registry that refused
        everything would pass every test in this class."""
        for (symbol, chain_id), token in KNOWN_TOKENS.items():
            assert token_for(symbol, chain_id) is token
            assert evm_chain_by_id(chain_id).chain_id == chain_id

    def test_the_same_symbol_can_mean_different_decimals_per_chain(self) -> None:
        """Guards the assumption a reader of this registry is most likely to carry in.

        Every token pinned today is 6 decimals, which makes "USDT is 6 decimals" look like a
        property of the symbol. It is a property of the (symbol, chain) PAIR — BSC's USDT is 18 —
        so this asserts the lookup key, not the current values. If a non-6-decimal token is ever
        pinned, this test keeps passing and the ones assuming 6 are the ones that break.
        """
        for (symbol, chain_id), token in KNOWN_TOKENS.items():
            assert token is token_for(symbol, chain_id)
            assert token.chain_id == chain_id, "a token must know the chain its decimals belong to"

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
        # The key set is the leg's OWN constant, not a copy of it: a hand-kept tuple here missed
        # the immutable layout keys when they became required.
        from pyrxd.eth_wallet.htlc_leg import _REQUIRED_ARTIFACT_KEYS, _validate_artifact

        art = self._artifact()
        assert {"immutableReferences", "immutable_names"} <= set(_REQUIRED_ARTIFACT_KEYS)
        for key in _REQUIRED_ARTIFACT_KEYS:
            assert key in art, key
            assert art[key], f"{key} is empty"
        _validate_artifact(art)  # the constructor's own check, layout included

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


class TestTheDecimalsGuardIsLoadBearing:
    """The 10^N guard. Every fake returned decimals()==6 against a 6-decimal pin — equal by
    construction — so planting `if False` on the comparison left all 9,780 tests green. This is the
    check whose own message says "at these scales the difference is a factor of 10^N in every
    amount", and it runs on both fund and verify_funded."""

    @staticmethod
    def _rpc(on_chain_decimals: int):
        class _Call:
            async def call(self, *a, **k):
                return on_chain_decimals

        class _Fns:
            def decimals(self):
                return _Call()

        class _Contract:
            functions = _Fns()

        class _Eth:
            def contract(self, *a, **k):
                return _Contract()

        class _W3:
            eth = _Eth()

        class _Rpc:
            w3 = _W3()

        return _Rpc()

    def test_a_chain_that_reports_18_against_a_6_decimal_pin_is_REFUSED(self) -> None:
        import asyncio

        from pyrxd.eth_wallet.erc20 import assert_token_matches_chain

        usdc = token_for("USDC", 1)
        assert usdc.decimals == 6, "fixture premise"
        with pytest.raises(ValidationError, match="decimals"):
            asyncio.run(assert_token_matches_chain(self._rpc(18), usdc))

    def test_the_matching_case_is_ACCEPTED(self) -> None:
        """The honest-path pair — deliberately the ONLY place the two are equal, so the refusal
        test above cannot be satisfied by a guard that refuses everything."""
        import asyncio

        from pyrxd.eth_wallet.erc20 import assert_token_matches_chain

        asyncio.run(assert_token_matches_chain(self._rpc(6), token_for("USDC", 1)))


class TestRegistryAndConstructorBoundsFromTheMutationRun:
    """Added from the 2026-09-29 `ethleg` mutation run: the USDT pins and the constructor's
    numeric bounds could each be changed with no test failing."""

    def test_every_pinned_token_is_six_decimals(self) -> None:
        # USDC was pinned by the test above; USDT on Optimism and Base was not. A 7 there is a
        # 10x error on every amount on that chain.
        assert {(s, c): t.decimals for (s, c), t in KNOWN_TOKENS.items()} == {k: 6 for k in KNOWN_TOKENS}

    @pytest.mark.parametrize("decimals", [0, 18, 36])
    def test_decimals_across_the_allowed_range_are_accepted(self, decimals: int) -> None:
        assert Erc20Token("T", "0x" + "ab" * 20, decimals, 1).decimals == decimals

    @pytest.mark.parametrize("decimals", [-1, 37, True, "6"])
    def test_decimals_outside_0_to_36_or_not_an_int_are_refused(self, decimals) -> None:
        with pytest.raises(ValidationError, match="decimals"):
            Erc20Token("T", "0x" + "ab" * 20, decimals, 1)

    @pytest.mark.parametrize("chain_id", [0, -1, True, "1"])
    def test_a_chain_id_that_is_not_a_positive_int_is_refused(self, chain_id) -> None:
        with pytest.raises(ValidationError, match="chain_id"):
            Erc20Token("T", "0x" + "ab" * 20, 6, chain_id)


class TestTheDecimalsCrossCheckFromTheMutationRun:
    """`assert_token_matches_chain`, beyond the 18-vs-6 case above (2026-09-29 `ethleg` run).

    A chain reporting FEWER decimals than the pin is just as wrong as one reporting more, and the
    read must happen at the checkpoint the caller pinned — reading decimals at the tip while the
    rest of a verification pass reads `finalized` is the mixed-checkpoint read the docstring of
    `balance_of` warns about. Neither was asserted anywhere.
    """

    @staticmethod
    def _rpc(on_chain_decimals: int, seen: list):
        class _Call:
            async def call(self, *, block_identifier):
                seen.append(block_identifier)
                return on_chain_decimals

        class _Fns:
            def decimals(self):
                return _Call()

        class _Contract:
            functions = _Fns()

        class _Eth:
            def contract(self, *a, **k):
                return _Contract()

        class _W3:
            eth = _Eth()

        class _Rpc:
            w3 = _W3()

        return _Rpc()

    def test_a_chain_reporting_FEWER_decimals_than_the_pin_is_refused_with_the_right_factor(self) -> None:
        import asyncio

        from pyrxd.eth_wallet.erc20 import assert_token_matches_chain

        token = Erc20Token("T18", "0x" + "ab" * 20, 18, 1)
        with pytest.raises(ValidationError, match=r"decimals=6 .* says 18\. .* 10\^12 in every amount"):
            asyncio.run(assert_token_matches_chain(self._rpc(6, []), token))

    def test_the_message_states_the_factor_for_the_upward_case_too(self) -> None:
        import asyncio

        from pyrxd.eth_wallet.erc20 import assert_token_matches_chain

        with pytest.raises(ValidationError, match=r"10\^3 in every amount"):
            asyncio.run(assert_token_matches_chain(self._rpc(9, []), token_for("USDC", 1)))

    def test_the_read_defaults_to_latest_and_honours_a_pinned_checkpoint(self) -> None:
        import asyncio

        from pyrxd.eth_wallet.erc20 import assert_token_matches_chain

        seen: list = []
        usdc = token_for("USDC", 1)
        asyncio.run(assert_token_matches_chain(self._rpc(6, seen), usdc))
        asyncio.run(assert_token_matches_chain(self._rpc(6, seen), usdc, block_identifier="finalized"))
        asyncio.run(assert_token_matches_chain(self._rpc(6, seen), usdc, block_identifier=12_345))
        assert seen == ["latest", "finalized", 12_345]

    def test_a_decimals_read_that_FAILS_is_a_network_error_not_a_pass(self) -> None:
        import asyncio

        from pyrxd.eth_wallet.erc20 import assert_token_matches_chain
        from pyrxd.security.errors import NetworkError

        class _Down:
            @property
            def w3(self):
                raise ConnectionError("endpoint unreachable")

        with pytest.raises(NetworkError, match="could not read decimals"):
            asyncio.run(assert_token_matches_chain(_Down(), token_for("USDC", 1)))

    def test_balance_of_defaults_to_latest_and_honours_a_pinned_checkpoint(self) -> None:
        # A balance read at the tip while the immutables were read at `finalized` lets a reorg show
        # funding the finalized state does not have — the pin must reach the call.
        import asyncio

        from pyrxd.eth_wallet.erc20 import balance_of

        seen: list = []

        class _Call:
            async def call(self, *, block_identifier):
                seen.append(block_identifier)
                return 1_234_567

        class _Fns:
            def balanceOf(self, _who):
                return _Call()

        from types import SimpleNamespace

        rpc = SimpleNamespace(
            w3=SimpleNamespace(eth=SimpleNamespace(contract=lambda **_k: SimpleNamespace(functions=_Fns())))
        )
        usdc, who = token_for("USDC", 1), "0x" + "11" * 20
        assert asyncio.run(balance_of(rpc, usdc, who)) == 1_234_567
        assert asyncio.run(balance_of(rpc, usdc, who, "finalized")) == 1_234_567
        assert seen == ["latest", "finalized"]


class TestReverseLookupAndAmountBoundsFromTheMutationRun:
    """`token_by_address`'s honest path ran under no test — deleting its loop left the suite green —
    and `base_units`' integer-digit cap was never touched at its edge (2026-09-29 `ethleg` run)."""

    @pytest.mark.parametrize(("symbol", "chain_id"), sorted(KNOWN_TOKENS))
    def test_every_pinned_token_resolves_back_from_its_address(self, symbol: str, chain_id: int) -> None:
        token = KNOWN_TOKENS[(symbol, chain_id)]
        # Upper-cased input: the lookup normalises, so a checksummed paste still resolves.
        assert token_by_address(token.address.upper().replace("0X", "0x"), chain_id) is token

    def test_the_chain_id_is_compared_by_value(self) -> None:
        # A chain id parsed from config or JSON is a fresh int; 8453 is outside CPython's small-int
        # cache, so an identity comparison would miss every such lookup.
        base_usdc = token_for("USDC", 8453)
        assert token_by_address(base_usdc.address, int("8453")) is base_usdc

    def test_a_pinned_address_asked_about_on_a_LOWER_chain_id_is_not_that_token(self) -> None:
        base_usdc = token_for("USDC", 8453)
        with pytest.raises(ValidationError, match="no pinned token"):
            token_by_address(base_usdc.address, 10)

    def test_a_token_cannot_be_mutated_in_place(self) -> None:
        import dataclasses

        with pytest.raises(dataclasses.FrozenInstanceError):
            token_for("USDC", 1).decimals = 18  # type: ignore[misc]

    def test_the_integer_digit_cap_is_exactly_32(self) -> None:
        t = Erc20Token("T", "0x" + "ab" * 20, 0, 1)
        assert t.base_units("9" * 32) == int("9" * 32)
        with pytest.raises(ValidationError, match="33 integer digits"):
            t.base_units("9" * 33)
