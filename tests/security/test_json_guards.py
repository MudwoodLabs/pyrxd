"""The JSON coercions, tested from inside the 100%-coverage gate's own scope.

``pyrxd.security.json_guards`` is read by the browser panel and by the network
clients: every one of these functions stands between a server's JSON and a value the
caller treats as an amount, an index, a liveness flag or a hash.

**WHY THIS FILE EXISTS SEPARATELY FROM ``tests/network/test_guards.py``.** The module
moved under ``pyrxd.security`` so the browser could import it without dragging in
coincurve and aiohttp. Everything in that package is held to 100% coverage by a gate
that runs ``tests/security`` **and nothing else** — so the move silently dropped this
module's real tests out of the gate's scope, and it landed at 94% with two lines
uncovered while the whole suite passed. Tests elsewhere still exercise these functions;
they simply cannot satisfy a gate scoped to this directory.

The two lines that were uncovered are called out by name below, because they are the
reason this file was written and a future reader should not have to diff coverage
reports to find out why.
"""

from __future__ import annotations

import math
from decimal import Decimal
from fractions import Fraction

import pytest

from pyrxd.security.json_guards import (
    MAX_EXACT_FLOAT_INT,
    cbor_int,
    finite_int,
    hex_str,
    merkle_branch,
    nonneg_int,
    require_bool,
)


class TestFiniteInt:
    def test_an_int_passes_through(self) -> None:
        assert finite_int(7) == 7
        assert finite_int(-7) == -7

    def test_a_float_with_no_fractional_part_becomes_an_int(self) -> None:
        """THE FIRST PREVIOUSLY-UNCOVERED LINE (`return int(value)`).

        JSON has one number type, so a server that means 5 may legitimately send 5.0.
        Refusing it would be a guard refusing valid work; truncating 5.5 would be the
        guard failing open. This is the honest-path half of that pair.
        """
        result = finite_int(5.0)
        assert result == 5
        assert isinstance(result, int) and not isinstance(result, bool)

    def test_a_float_with_a_fractional_part_is_refused(self) -> None:
        with pytest.raises(ValueError, match="refusing to truncate"):
            finite_int(5.5)

    @pytest.mark.parametrize("value", [math.inf, -math.inf, math.nan])
    def test_non_finite_is_refused(self, value: float) -> None:
        with pytest.raises(ValueError, match="non-finite"):
            finite_int(value)

    @pytest.mark.parametrize("value", [True, False])
    def test_a_bool_is_not_a_number(self, value: bool) -> None:
        """``bool`` is an ``int`` subclass, so without this branch ``True`` would be 1."""
        with pytest.raises(ValueError, match="boolean is not a numeric value"):
            finite_int(value)

    @pytest.mark.parametrize("value", ["5", None, [], {}, b"5"])
    def test_a_non_number_is_refused(self, value: object) -> None:
        with pytest.raises(ValueError, match="expected a JSON number"):
            finite_int(value)


class TestNonnegInt:
    def test_zero_and_positive_pass(self) -> None:
        assert nonneg_int(0) == 0
        assert nonneg_int(12) == 12

    def test_negative_is_refused(self) -> None:
        with pytest.raises(ValueError, match="non-negative"):
            nonneg_int(-1)

    def test_it_inherits_the_finite_int_refusals(self) -> None:
        with pytest.raises(ValueError, match="boolean is not a numeric value"):
            nonneg_int(True)


class TestRequireBool:
    @pytest.mark.parametrize("value", [True, False])
    def test_a_real_bool_passes(self, value: bool) -> None:
        assert require_bool(value) is value

    @pytest.mark.parametrize("value", [None, "false", "true", 0, 1, [], ""])
    def test_truthiness_is_never_used(self, value: object) -> None:
        """``None`` reads as False and the string ``"false"`` reads as True. Both shipped."""
        with pytest.raises(ValueError, match="expected a JSON boolean"):
            require_bool(value)


class TestHexStr:
    def test_even_length_hex_passes(self) -> None:
        assert hex_str("deadbeef") == "deadbeef"

    def test_exact_byte_length_is_enforced(self) -> None:
        assert hex_str("ab" * 32, nbytes=32) == "ab" * 32
        with pytest.raises(ValueError, match="expected a 32-byte hex string"):
            hex_str("abcd", nbytes=32)

    @pytest.mark.parametrize("value", ["abc", "a"])
    def test_odd_length_is_refused(self, value: str) -> None:
        """THE SECOND PREVIOUSLY-UNCOVERED LINE.

        An odd-length string is not decodable as bytes, and truncating it would hand
        the caller a silently shortened identifier.
        """
        with pytest.raises(ValueError, match="non-zero even length"):
            hex_str(value)

    def test_the_empty_string_is_refused(self) -> None:
        """Same line, other branch: ``len("") % 2`` is 0, so ``not value`` carries it."""
        with pytest.raises(ValueError, match="non-zero even length"):
            hex_str("")

    def test_non_hex_characters_are_refused(self) -> None:
        with pytest.raises(ValueError, match="not valid hex"):
            hex_str("zzzz")

    @pytest.mark.parametrize("value", [None, 5, b"dead", ["de"]])
    def test_a_non_string_is_refused(self, value: object) -> None:
        with pytest.raises(ValueError, match="expected a hex string"):
            hex_str(value)


class TestMerkleBranch:
    def test_a_list_of_32_byte_hashes_passes(self) -> None:
        branch = ["ab" * 32, "cd" * 32]
        assert merkle_branch(branch) == branch

    def test_an_empty_list_is_a_valid_branch(self) -> None:
        """A single-transaction block has no siblings. Refusing it would be a bug."""
        assert merkle_branch([]) == []

    def test_a_string_is_not_a_branch(self) -> None:
        """Iterating ``"deadbeef"`` yields eight one-character "hashes"."""
        with pytest.raises(ValueError, match="merkle branch must be a list"):
            merkle_branch("deadbeef")

    def test_a_sibling_of_the_wrong_width_is_refused(self) -> None:
        with pytest.raises(ValueError, match="expected a 32-byte hex string"):
            merkle_branch(["ab" * 31])


class TestCborInt:
    """``cbor_int`` — an integer decoded from untrusted CBOR, typed BEFORE any coercion.

    Tested here, inside the 100%-coverage gate's scope, for the reason the module docstring
    gives: the CLI tests that exercise it (``tests/cli/test_glyph_inspect_hostile_integers.py``)
    cannot satisfy a gate that runs ``tests/security`` and nothing else. That is exactly how this
    function first reached CI at 72%.
    """

    def test_an_int_passes_through(self) -> None:
        assert cbor_int(7) == 7
        assert cbor_int(-7) == -7
        assert cbor_int(2**80) == 2**80  # width is the CALLER's range check, not this one's

    @pytest.mark.parametrize("value", [5e9, float(MAX_EXACT_FLOAT_INT), -float(MAX_EXACT_FLOAT_INT), 0.0])
    def test_a_whole_float_up_to_2_53_is_the_integer_it_is(self, value) -> None:
        """The honest path: cbor-x writes every JS number of 2**32 or more as a float64."""
        assert cbor_int(value) == int(value)

    @pytest.mark.parametrize(
        ("value", "reason"),
        [
            (True, "a boolean is not an integer"),
            (float("inf"), "non-finite"),
            (float("nan"), "non-finite"),
            (1.5, "fractional part"),
            (float(MAX_EXACT_FLOAT_INT + 2), "cannot hold an exact integer"),
            (-float(MAX_EXACT_FLOAT_INT + 2), "cannot hold an exact integer"),
            (Decimal("1E+1000000"), "a Decimal is not an integer"),
            (Fraction(7, 1), "a Fraction is not an integer"),
            ("7", "a str is not an integer"),
            (b"7", "a bytes is not an integer"),
            (None, "a NoneType is not an integer"),
        ],
        ids=repr,
    )
    def test_everything_else_is_refused_with_its_reason(self, value, reason) -> None:
        with pytest.raises(ValueError, match=reason):
            cbor_int(value)
