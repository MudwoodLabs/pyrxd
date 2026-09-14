"""``GlyphRef`` accepted txids that ``Txid`` itself refuses, and the chain could not tell.

``GlyphRef.txid`` is annotated ``Txid``, but an annotation is not a runtime check: a
dataclass stores whatever it is handed. So ``GlyphRef(txid=<raw str>, vout=...)`` skipped
``Txid.__new__`` entirely — and mypy found **14 call sites** doing exactly that, in code
that had never been inside the typecheck scope.

Two demonstrated consequences:

* **A ref for one outpoint that does not equal itself.** ``Txid`` requires LOWERCASE hex
  and rejects uppercase outright. ``GlyphRef`` accepted it, producing a ref whose
  ``to_bytes()`` is BYTE-IDENTICAL to the lowercase one while ``==`` and ``hash()``
  differ. Set membership, dict keys and every ``ref == other`` check then see two
  different tokens where consensus sees one.
* **The wrong error, far from the cause.** A non-hex string was accepted here and failed
  later inside ``to_bytes()`` with a bare ``ValueError`` rather than a ``ValidationError``
  — which matters because only ``RxdSdkError`` subclasses are mapped by the CLI; a bare
  ``ValueError`` lands on its "unexpected failure" bug path.

The fix coerces through ``Txid`` in ``__post_init__``, so the guard is INSIDE the
constructor rather than beside it and no caller has to remember. That is the difference
between a rule and a convention.

The honest path is pinned too: a plain lowercase hex string must still be accepted, and
must produce a ref EQUAL to the ``Txid``-constructed one — a guard that refuses valid work
would be its own bug.
"""

from __future__ import annotations

import os

import pytest

from pyrxd.glyph.types import GlyphRef
from pyrxd.security.errors import ValidationError
from pyrxd.security.types import Txid


def _hex_txid() -> str:
    """Generated, never hand-written — a weak inline key in this repo was once swept."""
    return os.urandom(32).hex()


def test_an_uppercase_txid_is_refused_exactly_as_Txid_refuses_it() -> None:
    """The sharp case: uppercase is not a formatting nit, it forks identity."""
    raw = _hex_txid().upper()
    with pytest.raises(ValidationError):
        Txid(raw)  # the contract GlyphRef must not undercut
    with pytest.raises(ValidationError):
        GlyphRef(txid=raw, vout=0)  # type: ignore[arg-type]


def test_two_refs_for_one_outpoint_cannot_disagree() -> None:
    """Before the fix these compared unequal while encoding to identical wire bytes.

    That is the dangerous shape — not a crash, but a silent identity fork that only shows
    up as a membership test quietly returning False.
    """
    lower = _hex_txid()
    a = GlyphRef(txid=Txid(lower), vout=7)
    b = GlyphRef(txid=lower, vout=7)  # type: ignore[arg-type]  # raw str: the flagged shape
    assert a == b
    assert hash(a) == hash(b)
    assert {a} == {a, b}, "a set must not hold two entries for one outpoint"
    assert a.to_bytes() == b.to_bytes()


def test_a_non_hex_txid_fails_HERE_with_the_right_error_class() -> None:
    """It used to be accepted and blow up later in to_bytes() with a bare ValueError.

    ``ValidationError`` matters specifically: the CLI maps only ``RxdSdkError`` subclasses,
    so a bare ``ValueError`` reaches the catch-all and is reported as an internal bug
    rather than as bad input.
    """
    with pytest.raises(ValidationError):
        GlyphRef(txid="z" * 64, vout=0)  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        GlyphRef(txid="abc", vout=0)  # type: ignore[arg-type]


def test_the_honest_path_still_works_and_normalises_the_type() -> None:
    """A guard that refuses valid work is a bug. A plain lowercase hex string is valid."""
    raw = _hex_txid()
    ref = GlyphRef(txid=raw, vout=1)  # type: ignore[arg-type]
    assert isinstance(ref.txid, Txid), "the stored txid should be the validated type"
    assert ref.txid == raw
    assert len(ref.to_bytes()) == 36
    # and the constructors that already wrapped it keep working unchanged
    assert GlyphRef.from_bytes(ref.to_bytes()) == ref


def test_vout_validation_was_not_lost() -> None:
    """The pre-existing check shares __post_init__ with the new one; keep it pinned."""
    raw = _hex_txid()
    with pytest.raises(ValidationError):
        GlyphRef(txid=Txid(raw), vout=-1)
    with pytest.raises(ValidationError):
        GlyphRef(txid=Txid(raw), vout=0x1_0000_0000)
