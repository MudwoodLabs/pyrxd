"""Fail-closed coercions for JSON fields that arrive from an untrusted server.

:func:`cbor_int` applies the same rule to integers decoded from on-chain CBOR, which can
additionally carry types JSON cannot (``Decimal``, ``Fraction``) — see its docstring.

**WHY THIS LIVES UNDER ``security`` AND NOT UNDER ``network``.** It used to be
``pyrxd.network._guards``, and importing it therefore executed
``pyrxd.network.__init__``, which eagerly re-exports the ElectrumX and Bitcoin
clients and so pulls in ``coincurve``, ``aiohttp`` and ``websockets``. None of the
three has a pure-Python wheel, so under Pyodide the import simply fails — which
made every module that coerced a server field unreachable from the browser
inspect page, ``pyrxd.glyph.mark_anchor`` among them.

That is the same move, for the same reason, as the genesis map: it went to
``constants.py``, the dependency-free bottom layer, with ``network.registry``
re-exporting it so there is still exactly one definition.
``pyrxd.network._guards`` re-exports these for the same reason, and
``tests/network/test_guards.py`` asserts the re-export is an identity rather than
a second copy.

Every field a remote server sends is attacker-influenced. These helpers are the single
place that turns one into a Python value, so the refusal rules live in one place instead
of being re-derived at ~30 call sites (the way two independent base58 decoders each
grew the same key-echo bug).

Why they raise ``ValueError``
----------------------------
The fail-closed ``except`` tuples already guarding these reads are shaped
``(KeyError, IndexError, TypeError, ValueError)``. Raising ``ValueError`` means every
existing tuple catches a refusal and re-raises it as the ``NetworkError`` its caller
documents — no call site has to change its handler to become safe.

What is refused, and why each one bit
-------------------------------------
``bool``
    ``int(True) == 1``. A ``{"confirmations": true}`` must not read as depth 1.

non-finite floats
    ``json.loads`` accepts the non-standard ``Infinity`` / ``-Infinity`` / ``NaN``
    literals by default. ``int(float("inf"))`` raises **``OverflowError``**, which is
    not a ``ValueError`` and was absent from every fail-closed tuple in this package —
    so it escaped as a bare traceback *past* the ``except NetworkError`` that exists to
    contain it. Worse, an unguarded ``inf`` compared against a depth threshold
    (``inf < 6`` is ``False``) passes a confirmation gate outright.

non-integral floats
    ``int(1234.99) == 1234``. Silently truncating someone else's amount by a satoshi is
    not a reading of the response; it is an invention.

strings
    A stringly-typed number is ambiguity, not data. Every protocol here (Esplora,
    Bitcoin Core JSON-RPC, ElectrumX) specifies real JSON numbers for these fields, so a
    string means the response is not the response we think it is.
"""

from __future__ import annotations

import math
from typing import Any

__all__ = ["MAX_EXACT_FLOAT_INT", "cbor_int", "finite_int", "hex_str", "merkle_branch", "nonneg_int", "require_bool"]

#: The largest magnitude at which every integer is exactly a float64. A JS writer's ``number``
#: past this is already rounded before it is encoded, so it cannot be read back as a count.
MAX_EXACT_FLOAT_INT = 2**53


def cbor_int(value: Any) -> int:
    """An integer decoded from untrusted CBOR, or ``ValueError`` saying why it is not one.

    CHECKED BEFORE ANY COERCION, and that ordering is the point. CBOR can carry a decimal
    fraction (tag 4) or a bigfloat (tag 5), which ``cbor2`` decodes to ``Decimal`` in constant
    time — and ``int(Decimal("1E+1000000"))`` then takes minutes: 15 bytes of payload,
    measured at 69.9 s through ``glyph inspect --fetch``. So ``int()`` is never applied to a
    value this function has not already typed.

    Accepted: a real ``int`` (not ``bool``), and a finite float with no fractional part whose
    magnitude is at most :data:`MAX_EXACT_FLOAT_INT`. The float case is not leniency: cbor-x,
    which Photonic Wallet encodes with, writes every JS ``number`` of 2**32 or more as a
    float64 (measured: 5_000_000_000 encodes as ``fb 41f2a05f20000000``), so an honest
    Photonic value above four billion ARRIVES as a float.

    Refused, each with its reason: ``bool``; a float that is non-finite, fractional, or past
    2**53; and every other type — ``Decimal``, ``Fraction``, ``str``, ``bytes``, containers.
    """
    if isinstance(value, bool):
        raise ValueError("a boolean is not an integer")
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("a non-finite float (Infinity/NaN) is not an integer")
        if not value.is_integer():
            raise ValueError("a float with a fractional part is not an integer")
        if abs(value) > MAX_EXACT_FLOAT_INT:
            raise ValueError("a float above 2**53 cannot hold an exact integer")
        return int(value)
    raise ValueError(f"a {type(value).__name__} is not an integer")


def finite_int(value: Any) -> int:
    """Return ``value`` as an ``int``, refusing anything a server could hide a lie in.

    Raises:
        ValueError: for ``bool``, non-numeric types, ``Infinity``/``-Infinity``/``NaN``,
            and floats with a fractional part.
    """
    if isinstance(value, bool):
        raise ValueError("a boolean is not a numeric value")
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("non-finite numeric value (Infinity/NaN); fail-closed")
        if not value.is_integer():
            raise ValueError("non-integral numeric value; refusing to truncate")
        return int(value)
    raise ValueError(f"expected a JSON number, got {type(value).__name__}")


def nonneg_int(value: Any) -> int:
    """:func:`finite_int` that additionally refuses a negative number.

    Amounts, output indices, confirmation depths and block heights are all
    non-negative by definition; a negative one is a server error or a lie.
    """
    result = finite_int(value)
    if result < 0:
        raise ValueError("expected a non-negative number; fail-closed")
    return result


def require_bool(value: Any) -> bool:
    """Return ``value`` if it is a real ``bool``, else refuse.

    The liveness/confirmation flags (``spent``, ``confirmed``) must never be read
    through Python truthiness: a present-but-falsy ``null`` reads as ``False`` and the
    non-empty **string** ``"false"`` reads as ``True``. Both have been live bugs.
    """
    if not isinstance(value, bool):
        raise ValueError(f"expected a JSON boolean, got {type(value).__name__}; fail-closed")
    return value


def hex_str(value: Any, *, nbytes: int | None = None) -> str:
    """Return ``value`` if it is a hex string (optionally of exactly ``nbytes`` bytes).

    Used for the fields a caller will treat as an identifier or a hash — a ``txid`` that
    is ``None``, or a Merkle sibling that is one character of a type-confused string,
    must stop here rather than propagate into an outpoint or a proof.
    """
    if not isinstance(value, str):
        raise ValueError(f"expected a hex string, got {type(value).__name__}")
    if nbytes is not None and len(value) != nbytes * 2:
        raise ValueError(f"expected a {nbytes}-byte hex string, got length {len(value)}")
    if len(value) % 2 or not value:
        raise ValueError("hex string must have a non-zero even length")
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError("value is not valid hex") from exc
    return value


def merkle_branch(value: Any) -> list[str]:
    """Return ``value`` if it is a list of 32-byte hex sibling hashes.

    The branch was assigned straight out of the response with no type check at all, so a
    JSON **string** passed through as "the branch": iterating ``"deadbeef"`` yields eight
    one-character "hashes", and the caller receives a type-confused inclusion proof
    rather than a refusal.
    """
    if not isinstance(value, list):
        raise ValueError(f"merkle branch must be a list of hashes, got {type(value).__name__}")
    return [hex_str(sibling, nbytes=32) for sibling in value]
