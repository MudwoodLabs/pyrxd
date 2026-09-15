"""``decode_payload`` crashed on a Glyph token anyone could mint.

`crypto.recipients` is operator-authored CBOR read off the chain. Every ``from_dict``
in :mod:`pyrxd.glyph.encrypted_content` is annotated ``d: dict`` and none of them was
handed one it could trust — ``CryptoRecipient.from_dict`` calls ``d.get("mlkem_ct")``
first, so a recipient that is a string, an int, a list or null raised **AttributeError**.

That matters because of where it lands. ``payload._DECODE_REFUSALS`` is
``(ValidationError, KeyError, ValueError, TypeError, ArithmeticError)`` — AttributeError
is not in it, so the exception escaped the decoder's own "log the malformed field and
degrade" contract and came out of
:meth:`~pyrxd.glyph.inspector.GlyphInspector.extract_reveal_metadata`, the shipped path
that reads third-party tokens. Four shapes reached it: ``"x"``, ``[1]``, ``[[]]``,
``[None]``.

WHY NEITHER FUZZER FOUND IT, which is the more useful half. Both harnesses feed the
decoder RANDOM BYTES — ``tests/test_fuzz_parsers.py`` uses ``st.binary()`` and
``scripts/fuzz_atheris/harness_decode_payload.py`` mutates raw input. To reach this
line, a generator must produce a well-formed CBOR map carrying ``p``, then a ``crypto``
map, then a ``recipients`` key, then a non-map inside it. A byte-level generator
effectively never does, so **every defect living behind a well-formed envelope is
invisible to both** — not unlikely to be found, structurally unreachable.

So the third test below generates *structure*: valid envelopes with hostile values at
the nested positions the decoder walks into. That is the check that closes the class;
the parser fix closes the four instances.

The fix is at the parser boundary rather than in the catch: widening
``_DECODE_REFUSALS`` to swallow AttributeError would also swallow a genuine typo in
pyrxd's own parser, which is the bug such a catch exists to surface.
"""

from __future__ import annotations

import inspect as _inspect
import logging

import cbor2
import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from pyrxd.glyph import encrypted_content as _ec
from pyrxd.glyph.inspector import GlyphInspector
from pyrxd.glyph.payload import build_reveal_scriptsig_suffix, decode_payload
from pyrxd.security.errors import ValidationError

_GOOD_TIMELOCK = {"mode": "height", "unlock_at": 99_000_000, "cek_hash": "ab" * 32}

#: The four shapes measured to crash the shipped inspect path before this fix.
HOSTILE_RECIPIENTS = ["x", [1], [[]], [None], 5, {"not": "a list"}]


def _scriptsig(metadata_map: dict) -> bytes:
    """A reveal scriptSig carrying `metadata_map`, as a miner would publish it."""
    dummy_sig = bytes([0x47]) + bytes(71)
    dummy_pubkey = bytes([0x21]) + bytes(33)
    return dummy_sig + dummy_pubkey + build_reveal_scriptsig_suffix(cbor2.dumps(metadata_map))


@pytest.fixture(autouse=True)
def _quiet_decoder_warnings():
    """The decoder logs each dropped field; that is the correct behaviour, not noise to assert."""
    logging.disable(logging.CRITICAL)
    yield
    logging.disable(logging.NOTSET)


# ---------------------------------------------------------------------------
# 1. Through the PRODUCTION entry point, not through decode_payload directly
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("recipients", HOSTILE_RECIPIENTS, ids=lambda r: repr(r)[:16])
def test_the_inspect_path_survives_a_hostile_recipient(recipients: object) -> None:
    """`extract_reveal_metadata` is what reads somebody else's token. It must not raise."""
    scriptsig = _scriptsig(
        {"p": [2, 8, 9], "name": "t", "type": "nft", "crypto": {"recipients": recipients, "timelock": _GOOD_TIMELOCK}}
    )
    result = GlyphInspector().extract_reveal_metadata(scriptsig)
    assert result is not None, "the token still parses; only the malformed field is dropped"


@pytest.mark.parametrize("recipients", HOSTILE_RECIPIENTS, ids=lambda r: repr(r)[:16])
def test_a_valid_timelock_survives_its_malformed_neighbour(recipients: object) -> None:
    """The two parses are independent ON PURPOSE (`payload.py`), and this pins that.

    A token whose `recipients` is junk still declares a real unlock height, and a reader
    that drops the whole `crypto` block would tell the holder nothing about WHEN it opens.
    """
    result = GlyphInspector().extract_reveal_metadata(
        _scriptsig(
            {
                "p": [2, 8, 9],
                "name": "t",
                "type": "nft",
                "crypto": {"recipients": recipients, "timelock": _GOOD_TIMELOCK},
            }
        )
    )
    assert result is not None
    assert result.timelock is not None, "the malformed sibling took the timelock with it"
    assert result.timelock.unlock_at == 99_000_000
    assert result.crypto is None, "the malformed crypto block should have been dropped"


def test_an_honest_timelocked_token_still_decodes_in_full() -> None:
    """Pairs with the refusals above: the guard must not have eaten the honest case."""
    result = GlyphInspector().extract_reveal_metadata(
        _scriptsig(
            {
                "p": [2, 8, 9],
                "name": "t",
                "type": "nft",
                "crypto": {"mode": "height", "key_format": "raw", "cek_hash": "ab" * 32, "timelock": _GOOD_TIMELOCK},
            }
        )
    )
    assert result is not None
    assert result.crypto is not None, "an honest crypto block was refused"
    assert result.timelock is not None and result.timelock.unlock_at == 99_000_000


# ---------------------------------------------------------------------------
# 2. The guard's coverage is DERIVED from the module, not typed out
# ---------------------------------------------------------------------------


def _from_dict_parsers() -> list[tuple[str, object]]:
    """Every ``from_dict`` in the module, found by reflection.

    Hand-listing these is how the original gap survived: the annotation said ``dict`` on
    all five and only the reachable one would have been remembered. A parser added later
    is covered here the day it lands.
    """
    return [
        (name, obj)
        for name, obj in vars(_ec).items()
        if _inspect.isclass(obj)
        and getattr(obj, "__module__", None) == _ec.__name__
        and callable(getattr(obj, "from_dict", None))
    ]


def test_the_parser_set_is_not_empty() -> None:
    """Non-vacuity: if reflection stops finding parsers, the test below passes on nothing."""
    found = _from_dict_parsers()
    assert len(found) >= 5, f"expected the module's parsers, found {[n for n, _ in found]}"


@pytest.mark.parametrize("junk", ["x", 5, [1], None, b"bytes", 1.5])
def test_every_from_dict_refuses_a_non_mapping(junk: object) -> None:
    """A ValidationError is refusable by `decode_payload`; an AttributeError is not."""
    for name, cls in _from_dict_parsers():
        try:
            cls.from_dict(junk)  # type: ignore[attr-defined]
        except ValidationError:
            continue
        except Exception as exc:  # pragma: no cover - this is the assertion
            pytest.fail(
                f"{name}.from_dict({junk!r}) raised {type(exc).__name__}, which "
                "`payload._DECODE_REFUSALS` does not catch — it escapes decode_payload"
            )
        pytest.fail(f"{name}.from_dict({junk!r}) accepted a non-mapping")


# ---------------------------------------------------------------------------
# 3. Structure-aware generation — the class, not the four instances
# ---------------------------------------------------------------------------

#: Values a hostile writer can put where the decoder expects a map or an array.
_HOSTILE = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(),
    st.floats(allow_nan=True, allow_infinity=True),
    st.text(max_size=8),
    st.binary(max_size=8),
    st.lists(st.integers(), max_size=3),
    st.dictionaries(st.text(max_size=4), st.integers(), max_size=3),
)

#: The nested positions `decode_payload` walks into, with `crypto` ALWAYS a map and
#: `recipients` ALWAYS present. An earlier version of this strategy made both optional and
#: **passed against the planted defect** — with `crypto` optional, `recipients` optional and
#: an integer list allowed to be empty, 400 examples seldom produced the one shape that
#: crashes. A generator that reaches the interesting position only sometimes is a generator
#: that reports "no defect" for the wrong reason, and it read as thorough because it was
#: random. Guarantee the position; randomise the VALUE there.
_CRYPTO_ENVELOPE = st.fixed_dictionaries(
    {
        "p": st.just([2, 8, 9]),
        "name": st.just("t"),
        "type": st.just("nft"),
        "crypto": st.fixed_dictionaries(
            {"recipients": _HOSTILE},
            optional={"timelock": _HOSTILE, "mode": _HOSTILE, "cek_hash": _HOSTILE},
        ),
    }
)

#: The wider sweep: every nested position the decoder walks, each independently hostile.
_ENVELOPE = st.fixed_dictionaries(
    {"p": st.just([2, 8, 9]), "name": st.just("t"), "type": st.just("nft")},
    optional={
        "crypto": st.one_of(
            _HOSTILE,
            st.fixed_dictionaries(
                {},
                optional={
                    "recipients": _HOSTILE,
                    "timelock": _HOSTILE,
                    "mode": _HOSTILE,
                    "key_format": _HOSTILE,
                    "cek_hash": _HOSTILE,
                    "locator": _HOSTILE,
                },
            ),
        ),
        "main": _HOSTILE,
        "in": _HOSTILE,
        "by": _HOSTILE,
        "royalty": _HOSTILE,
        "policy": _HOSTILE,
        "rights": _HOSTILE,
        "creator": _HOSTILE,
    },
)


def _only_validation_error(envelope) -> None:
    try:
        raw = cbor2.dumps(envelope)
    except Exception:  # pragma: no cover - a value cbor2 cannot encode is not a wire case
        return
    try:
        decode_payload(raw)
    except ValidationError:
        pass
    except Exception as exc:  # pragma: no cover - this is the assertion
        pytest.fail(f"decode_payload leaked {type(exc).__name__}: {exc}\nenvelope: {envelope!r}\nhex: {raw.hex()}")


@given(envelope=_CRYPTO_ENVELOPE)
@settings(max_examples=300, suppress_health_check=[HealthCheck.too_slow])
def test_a_hostile_recipients_value_never_leaks_a_non_validation_error(envelope) -> None:
    """The focused case: `crypto.recipients` holds an arbitrary non-list, or a list of
    arbitrary non-maps. This is the shape that crashed, generated rather than enumerated,
    so a NEW hostile value in the same position is covered without editing a list."""
    _only_validation_error(envelope)


@given(envelope=_ENVELOPE)
@settings(max_examples=400, suppress_health_check=[HealthCheck.too_slow])
def test_a_well_formed_envelope_with_hostile_values_only_raises_validation_error(envelope) -> None:
    """The wider sweep both existing fuzzers cannot express.

    `st.binary()` reaches the CBOR boundary and stops; this reaches the FIELD parsers,
    which is where `crypto.recipients` lived.
    """
    _only_validation_error(envelope)


# ---------------------------------------------------------------------------
# 4. The comment on `GlyphMetadata.crypto` makes a claim. Make it executable.
# ---------------------------------------------------------------------------


def test_no_shipped_code_reads_the_per_recipient_wraps() -> None:
    """`decode_payload` now fills `crypto`, recipients included (#632).

    The field comment says that is not a disclosure, because the bytes are already public
    on chain AND because no shipped path reads them back for display. The second half is a
    claim about the code, and claims in comments rot in silence — so it is checked here
    instead of asserted there.

    An AST scan rather than a grep: a comment mentioning `crypto.recipients` (there are
    three, explaining this very decision) is not a read, and a string is not a read.

    If this fails, a new caller reads the wraps off a decoded token. That may be perfectly
    fine — but the comment on `GlyphMetadata.crypto` has to be re-read before it ships,
    which is the point.
    """
    import ast
    import pathlib

    root = pathlib.Path(__file__).resolve().parent.parent / "src" / "pyrxd"
    files = sorted(root.rglob("*.py"))
    assert len(files) > 50, f"the scan found only {len(files)} modules — it is not reaching src/"

    readers = []
    for path in files:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Attribute)
                and node.attr == "recipients"
                and isinstance(node.value, ast.Attribute)
                and node.value.attr == "crypto"
            ):
                readers.append(f"{path.relative_to(root.parent.parent)}:{node.lineno}")

    assert not readers, (
        "shipped code now reads the per-recipient key wraps off a decoded token: "
        f"{readers}. Re-read the note on `GlyphMetadata.crypto` before shipping this."
    )
