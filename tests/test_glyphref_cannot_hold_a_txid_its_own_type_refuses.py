"""``GlyphRef`` accepted txids that ``Txid`` itself refuses, and the chain could not tell.

``GlyphRef.txid`` is annotated ``Txid``, but an annotation is not a runtime check: a
dataclass stores whatever it is handed. So ``GlyphRef(txid=<raw str>, vout=...)`` skipped
``Txid.__new__`` entirely — and mypy found **15 call sites** doing exactly that (14 in
``glyph/builder.py``, 1 in ``gravity/htlc_covenant.py``), in code that had never been
inside the typecheck scope. #649 put all three files in it and wrapped every site.

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

import copy
import dataclasses
import os
import pickle

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


def test_a_raw_lowercase_str_agrees_with_the_Txid_built_ref() -> None:
    """The honest path, and NOT the identity fork.

    This test was originally named `test_two_refs_for_one_outpoint_cannot_disagree` and
    claimed to pin the fork. It did not: it compared a raw LOWERCASE str against a `Txid`,
    which `str.__eq__` already makes equal, so it passed against the unfixed code. Verified
    by running it on the pre-fix tree. The fork needs UPPERCASE, which the constructor now
    refuses outright — so the fork is unreachable through `__init__`, and the test for it is
    `test_a_pickled_pre_fix_ref_cannot_resurrect_the_fork` below.
    """
    lower = _hex_txid()
    a = GlyphRef(txid=Txid(lower), vout=7)
    b = GlyphRef(txid=lower, vout=7)  # type: ignore[arg-type]
    assert a == b
    assert hash(a) == hash(b)
    assert {a} == {a, b}
    assert a.to_bytes() == b.to_bytes()


def _pre_fix_ref(txid: str, vout: int) -> GlyphRef:
    """A `GlyphRef` as pyrxd <= 0.23.0 could hold one: constructed without `__post_init__`.

    This is exactly what `pickle.loads` produced before `__reduce__` existed — a frozen,
    non-slots dataclass is rebuilt via `__newobj__` + `__dict__.update`, so no validation
    runs. Building it here the same way lets the test reach a state the constructor can no
    longer create.
    """
    ghost = object.__new__(GlyphRef)
    ghost.__dict__.update({"txid": txid, "vout": vout})
    return ghost


def test_a_pickled_pre_fix_ref_cannot_resurrect_the_fork() -> None:
    """THE fork test. `__post_init__` alone did not close this.

    A ref pickled by an older pyrxd carries a raw uppercase `str`. Unpickling skips
    `__post_init__` entirely, so before `__reduce__` it came back with the fork intact:
    byte-identical `to_bytes()`, `==` False against the canonical ref — while the
    constructor refused the very value `pickle.loads` had just handed back.
    """
    h = _hex_txid()
    ghost = _pre_fix_ref(h.upper(), 0)
    assert not isinstance(ghost.txid, Txid), "fixture no longer reproduces the pre-fix shape"

    with pytest.raises(ValidationError):
        pickle.loads(pickle.dumps(ghost))
    with pytest.raises(ValidationError):
        copy.deepcopy(ghost)


def test_pickling_a_valid_ref_still_round_trips() -> None:
    """A guard that refuses valid work is a bug — `__reduce__` must not break normal use."""
    ref = GlyphRef(txid=Txid(_hex_txid()), vout=9)
    back = pickle.loads(pickle.dumps(ref))
    assert back == ref
    assert hash(back) == hash(ref)
    assert isinstance(back.txid, Txid)
    assert copy.deepcopy(ref) == ref
    assert dataclasses.replace(ref, vout=10).vout == 10


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
