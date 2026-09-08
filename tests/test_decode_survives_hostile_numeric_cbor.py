"""`decode_payload` must never propagate on attacker-authored bytes.

It parses whatever anyone minted. A token that every other decoder reads must not become
`metadata: NONE` in pyrxd — `GlyphInspector.extract_reveal_metadata` catches Exception and returns
None, so anything escaping here silently erases the token from the inspect surface.

The read path caught `(ValidationError, KeyError, ValueError, TypeError)`. **`OverflowError`
subclasses ArithmeticError, not ValueError**, so a CBOR float16 Infinity — 0x7c00, two bytes, legal
and cheap to mint — escaped through `int(...)` on a numeric field.

Found by re-reviewing #632's own fix. Its `crypto`/`encrypted_main` parsing was added precisely to
be defensive about third-party bytes, and it was, for every exception type its author thought of.
"""

from __future__ import annotations

import math

import cbor2
import pytest

from pyrxd.glyph.payload import decode_payload

_HOSTILE = {
    "positive_infinity": float("inf"),
    "negative_infinity": float("-inf"),
    "nan": float("nan"),
    "huge_int": 2**70,
    "negative": -1,
    "float_fraction": 0.5,
    "string_where_int_expected": "not-a-number",
    "list_where_int_expected": [1, 2, 3],
    "none": None,
}


def _token(size_value: object) -> bytes:
    """A WAVE-shaped NFT whose encrypted `main` carries a hostile numeric field."""
    return cbor2.dumps(
        {
            "p": [2, 8],
            "name": "alice.rxd",
            "type": "nft",
            "main": {"type": "text/plain", "hash": "sha256:" + "aa" * 32, "size": size_value},
        },
        canonical=True,
    )


class TestAHostileFieldNeverEscapes:
    @pytest.mark.parametrize("label", sorted(_HOSTILE))
    def test_decode_returns_metadata_instead_of_raising(self, label: str) -> None:
        raw = _token(_HOSTILE[label])
        # The bar: whatever a generic CBOR reader can get out of these bytes, pyrxd must too.
        assert cbor2.loads(raw)["name"] == "alice.rxd", "fixture must be readable by a plain decoder"
        m = decode_payload(raw)
        assert m.name == "alice.rxd", f"{label}: the rest of the token must survive one bad field"

    @pytest.mark.parametrize("label", sorted(_HOSTILE))
    def test_the_malformed_field_is_dropped_not_guessed(self, label: str) -> None:
        """Surviving must not mean inventing a value — a wrong `size` is worse than no `size`."""
        m = decode_payload(_token(_HOSTILE[label]))
        if m.encrypted_main is not None:
            assert isinstance(m.encrypted_main.size, int)
            assert not isinstance(m.encrypted_main.size, bool)
            assert m.encrypted_main.size >= 0
            assert not math.isinf(m.encrypted_main.size)


class TestTheHonestPathIsUntouched:
    """A guard this broad has to be shown NOT to swallow good data."""

    def test_a_well_formed_encrypted_main_still_decodes(self) -> None:
        m = decode_payload(_token(4096))
        assert m.encrypted_main is not None, "a valid size must produce an encrypted_main"
        assert m.encrypted_main.size == 4096
        assert m.name == "alice.rxd"

    def test_a_plaintext_main_is_still_read_as_media(self) -> None:
        raw = cbor2.dumps(
            {"p": [2], "name": "n", "type": "nft", "main": {"t": "image/png", "b": b"\x89PNG"}},
            canonical=True,
        )
        m = decode_payload(raw)
        assert m.main is not None and m.main.mime_type == "image/png"
        assert m.encrypted_main is None, "the plaintext branch must win when the shape matches it"
