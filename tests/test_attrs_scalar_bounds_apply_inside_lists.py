"""``attrs`` scalar bounds were applied at the top level only, so a list evaded them.

``_decode_attr_value`` bounds an ``int``'s bit length and refuses a non-finite
``float`` — its own comments say why: CPython refuses ``str()`` on an integer
over ~4300 digits and ``json.dumps`` inherits that, and a bare ``NaN`` is not
JSON any strict parser reads back. The list branch then kept any ``int`` or
``float`` with no check at all, so ``{"a": [1 << 20000], "b": [float("nan")]}``
— ordinary CBOR anyone can mint — decoded cleanly and handed an SDK consumer
the exact exception the guard exists to prevent, one nesting level down.

Reach is library-level: no in-repo surface emits raw ``attrs`` (the inspect
payload does not), so this is a defect for callers that JSON-encode
``GlyphMetadata.attrs``, not a crash on a pyrxd screen.

BOTH DIRECTIONS. A guard that refuses honest work is a bug, and the honest
shape here is real: Photonic's authority tokens carry ``permissions: string[]``
and ``revocable: boolean`` (``packages/lib/src/authority.ts``), and the whole
reason the list branch exists is that coercing those with ``str()`` inverted
their meaning. Every list value in the wild must still decode with its types
and its ordering intact.
"""

from __future__ import annotations

import json
import math

import cbor2
import pytest

from pyrxd.glyph.payload import _MAX_ATTRS_INT_BITS, _MAX_ATTRS_LIST_LEN, decode_payload

#: Far past the ~4300-digit ceiling CPython puts on ``str(int)``, so a consumer
#: that stringifies this value raises rather than printing something long.
_HUGE_INT = 1 << 20_000


def _minted(attrs: dict) -> bytes:
    """CBOR an attacker can mint: built by the encoder a publisher controls, not ours.

    ``encode_payload`` would never produce these values, so building through it
    would test a shape the real system cannot deliver. The decoder's input is
    whatever bytes sit in the reveal.
    """
    return cbor2.dumps({"p": [2], "v": 2, "name": "token", "attrs": attrs})


def test_a_list_element_cannot_carry_an_unstringifiable_integer() -> None:
    attrs = decode_payload(_minted({"a": [_HUGE_INT]})).attrs

    assert attrs["a"] == [f"<oversized integer: {_HUGE_INT.bit_length()} bits>"]
    # The consequence, asserted rather than described: the decoded object is
    # JSON-encodable. Before the fix this raised ValueError: Exceeds the limit.
    json.dumps(attrs)


def test_a_list_element_cannot_carry_a_non_finite_float() -> None:
    attrs = decode_payload(_minted({"b": [float("nan")], "c": [float("inf")], "d": [float("-inf")]})).attrs

    assert attrs["b"] == ["<non-finite: nan>"]
    assert attrs["c"] == ["<non-finite: inf>"]
    assert attrs["d"] == ["<non-finite: inf>"]
    # `json.dumps` does not raise on NaN — it emits a bare `NaN`, which is not
    # JSON. So the assertion that bites is that the output PARSES back.
    json.loads(json.dumps(attrs))


def test_the_bound_is_the_same_one_the_top_level_applies() -> None:
    """One rule, not two spellings that can drift apart.

    The defect was two implementations of "bound this scalar", one of which was
    empty. Asserting the two positions agree on the same value is what notices
    if they diverge again.
    """
    at_bound = (1 << _MAX_ATTRS_INT_BITS) - 1
    over_bound = 1 << _MAX_ATTRS_INT_BITS

    attrs = decode_payload(_minted({"top_ok": at_bound, "top_over": over_bound})).attrs
    in_list = decode_payload(_minted({"list_ok": [at_bound], "list_over": [over_bound]})).attrs

    assert attrs["top_ok"] == at_bound
    assert in_list["list_ok"] == [at_bound]
    assert attrs["top_over"] == in_list["list_over"][0]
    assert isinstance(attrs["top_over"], str)


def test_mixed_hostile_and_honest_values_in_one_list() -> None:
    """The honest neighbours of a hostile element are not collateral damage."""
    attrs = decode_payload(_minted({"mixed": ["mint", 7, _HUGE_INT, True, 1.5, float("nan"), "revoke"]})).attrs

    assert attrs["mixed"] == [
        "mint",
        7,
        f"<oversized integer: {_HUGE_INT.bit_length()} bits>",
        True,
        1.5,
        "<non-finite: nan>",
        "revoke",
    ]


# ───────────────────────── the honest path, unchanged ─────────────────────────


def test_real_authority_permissions_still_decode_with_their_types() -> None:
    """The shape Photonic actually writes. Refusing this would be the real bug."""
    attrs = decode_payload(
        _minted(
            {
                "issuer": "rxd1qissuer",
                "permissions": ["mint", "revoke", "transfer"],
                "revocable": False,
                "edition": 3,
                "weight": 1.5,
                "tags": [],
            }
        )
    ).attrs

    assert attrs["permissions"] == ["mint", "revoke", "transfer"]  # order and type intact
    assert attrs["revocable"] is False  # not the truthy string "False"
    assert attrs["edition"] == 3 and isinstance(attrs["edition"], int)
    assert attrs["weight"] == 1.5 and math.isfinite(attrs["weight"])
    assert attrs["tags"] == []
    assert json.loads(json.dumps(attrs))["permissions"] == ["mint", "revoke", "transfer"]


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ([0], [0]),
        ([-1], [-1]),
        ([False, True], [False, True]),
        ([1e308], [1e308]),  # large but finite: a real float, not a refusal
        ([-1e308], [-1e308]),
        ([0.0], [0.0]),
        (["", "x"], ["", "x"]),
    ],
)
def test_ordinary_list_scalars_pass_through_untouched(value: list, expected: list) -> None:
    assert decode_payload(_minted({"k": value})).attrs["k"] == expected


def test_list_behaviour_the_fix_did_not_change() -> None:
    """Pins the two properties around the change, so neither drifted with it.

    The list is still truncated rather than rejected, and a nested list or map
    inside one is still DROPPED rather than recursed into — the decoder's work
    stays bounded by the payload size, not by a publisher's choice of depth.
    """
    long_list = list(range(_MAX_ATTRS_LIST_LEN + 10))
    assert decode_payload(_minted({"k": long_list})).attrs["k"] == long_list[:_MAX_ATTRS_LIST_LEN]

    nested = decode_payload(_minted({"k": ["keep", [1, 2], {"a": 1}, None, "keep2"]})).attrs["k"]
    assert nested == ["keep", "keep2"]
