"""Unit tests for the untrusted-JSON coercions in :mod:`pyrxd.network._guards`.

These four functions are now the single choke point through which every server-supplied
number, boolean and hash passes. ``tests/security/test_hostile_server_responses.py``
exercises them through the real boundaries; this file pins the primitives directly, so a
refactor that loosens one of them fails here with a one-line diagnosis instead of as a
scattering of boundary failures.

Every rejection is a ``ValueError`` on purpose — the fail-closed ``except`` tuples already
guarding these reads are shaped ``(KeyError, IndexError, TypeError, ValueError)``, so a
refusal is caught and re-raised as the ``NetworkError`` the caller documents without any
call site having to change its handler.
"""

from __future__ import annotations

from typing import Any

import pytest

from pyrxd.network._guards import finite_int, hex_str, merkle_branch, nonneg_int, require_bool


@pytest.mark.parametrize("value", [0, 1, -1, 2**80, 12.0, -3.0])
def test_finite_int_accepts_real_integral_numbers(value: Any) -> None:
    assert finite_int(value) == int(value)


@pytest.mark.parametrize(
    ("value", "why"),
    [
        (True, "int(True) == 1, so a boolean would read as depth 1"),
        (False, "int(False) == 0, an invented 'zero'"),
        (float("inf"), "json.loads accepts Infinity; int(inf) raises OverflowError"),
        (float("-inf"), "same, negative"),
        (float("nan"), "int(nan) raises ValueError"),
        (1.9, "int(1.9) == 1 silently truncates someone else's amount"),
        ("12", "a stringly-typed number is ambiguity, not data"),
        ("twelve", "not a number at all"),
        (None, "a present-but-null field"),
        ([12], "a wrapped number"),
        ({"value": 12}, "a wrapped number"),
        (b"12", "bytes are not a JSON number"),
    ],
)
def test_finite_int_refuses_everything_a_lie_could_hide_in(value: Any, why: str) -> None:
    with pytest.raises(ValueError):
        finite_int(value)


@pytest.mark.parametrize("value", [0, 1, 2**64, 7.0])
def test_nonneg_int_accepts_non_negative(value: Any) -> None:
    assert nonneg_int(value) == int(value)


@pytest.mark.parametrize("value", [-1, -0.0000001, -(2**64), -1.0])
def test_nonneg_int_refuses_negative(value: Any) -> None:
    with pytest.raises(ValueError):
        nonneg_int(value)


@pytest.mark.parametrize("value", [True, False])
def test_require_bool_accepts_real_booleans(value: bool) -> None:
    assert require_bool(value) is value


@pytest.mark.parametrize(
    ("value", "why"),
    [
        (None, "present-but-null read as False — the original `spent` bug"),
        (0, "falsy"),
        (1, "truthy but not a boolean"),
        ("", "falsy"),
        ("false", "NON-EMPTY string, so Python truthiness reads it as TRUE"),
        ("true", "still not a boolean"),
        ([], "falsy"),
        ({}, "falsy"),
        (float("nan"), "truthy, and not a boolean"),
    ],
)
def test_require_bool_refuses_anything_else(value: Any, why: str) -> None:
    with pytest.raises(ValueError):
        require_bool(value)


def test_hex_str_accepts_hex_of_the_right_length() -> None:
    assert hex_str("ab" * 32, nbytes=32) == "ab" * 32
    assert hex_str("00ff") == "00ff"  # no length constraint


@pytest.mark.parametrize(
    ("value", "nbytes"),
    [
        (None, 32),
        (12, 32),
        (["ab" * 32], 32),
        ("ab" * 31, 32),  # right charset, SHORT
        # ...and the other side of the equality. Only the short case was covered, so
        # relaxing `!= nbytes * 2` to `< nbytes * 2` left the whole suite green — a
        # 33-byte "hash" would then pass into an outpoint or a proof. An over-long
        # value is the likelier hostile shape of the two: it is what a concatenation
        # or an off-by-one length prefix produces.
        ("ab" * 33, 32),  # right charset, LONG
        ("ab" * 64, 32),  # exactly double — a doubled hash
        ("zz" * 32, 32),  # right length, wrong charset
        ("", None),  # empty
        ("abc", None),  # odd length
        ("zz", None),  # non-hex
    ],
)
def test_hex_str_refuses_anything_that_is_not_a_hash(value: Any, nbytes: int | None) -> None:
    with pytest.raises(ValueError):
        hex_str(value, nbytes=nbytes)


def test_merkle_branch_refuses_an_over_long_sibling() -> None:
    """The same boundary reached through the caller the guard exists to protect.

    ``merkle_branch`` is the only production caller that passes ``nbytes``; a sibling
    that is too LONG has to stop here rather than be truncated into a proof step.
    """
    with pytest.raises(ValueError):
        merkle_branch(["ab" * 32, "cd" * 33])


def test_merkle_branch_accepts_a_list_of_hashes() -> None:
    branch = ["ab" * 32, "cd" * 32]
    assert merkle_branch(branch) == branch
    assert merkle_branch([]) == []


@pytest.mark.parametrize(
    "value",
    ["deadbeef", {"0": "ab" * 32}, None, 7, [None], [123], ["zz" * 32], ["ab" * 31]],
    ids=["string", "dict", "null", "int", "list_of_null", "list_of_int", "non_hex", "short"],
)
def test_merkle_branch_refuses_a_type_confused_proof(value: Any) -> None:
    """A JSON string used to pass through as "the branch": iterating ``"deadbeef"``
    yields eight one-character "hashes"."""
    with pytest.raises(ValueError):
        merkle_branch(value)
