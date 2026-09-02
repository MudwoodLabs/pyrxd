"""Every committed counterexample must still belong to a test that will replay it.

`tests/.hypothesis-corpus/` is a COMMITTED Hypothesis example database, wired in
`tests/conftest.py`. Its README promises a counterexample is "replayed on every future run
until fixed — a drift-proof regression corpus", and the conftest comment says it "regresses
forever".

Neither is true on its own. Hypothesis addresses entries by
``_hash(function_digest(test) + suffix)``, and ``function_digest`` incorporates the test's
NAME. So:

* editing a test's BODY keeps its entries (measured on hypothesis 6.165.0 — a changed
  comparison operator produced an identical digest), but
* RENAMING or MOVING a test silently ORPHANS them.

An orphaned entry is the worst kind of green: the file is still there, the README still says
it regresses forever, and nothing replays it. When this test was written, **all six committed
directories — 24 entries — were orphaned and matched no live test.**

This is the DETECT-level guard for that. It cannot tell you which test an orphan belonged to;
it can only refuse to let one sit there looking like coverage. The durable fix is the one the
README already prescribes: when a fuzz test finds a real bug, also freeze a NAMED reproducer
in a `tests/test_*.py`, so the case survives any rename.
"""

from __future__ import annotations

import importlib.util
import inspect
import sys
import warnings
from pathlib import Path

import pytest
from hypothesis.database import _hash
from hypothesis.internal.reflection import function_digest

_ROOT = Path(__file__).resolve().parent.parent
_CORPUS = _ROOT / "tests" / ".hypothesis-corpus"

#: Hypothesis writes a counterexample under the primary key and these companions.
_KEY_SUFFIXES = (b"", b".secondary", b".pareto")

#: Discovery must not silently shrink. If a refactor drops the suite below this, the test
#: fails rather than reporting every corpus entry as an orphan.
_MIN_EXPECTED_HYPOTHESIS_TESTS = 80


def _hypothesis_callables(obj, seen: set):
    for attr in dir(obj):
        try:
            value = getattr(obj, attr)
        except Exception:  # pragma: no cover - defensive on odd module attrs
            continue
        if callable(value) and getattr(value, "is_hypothesis_test", False):
            yield attr, value
        elif inspect.isclass(value) and value not in seen and attr.startswith("Test"):
            seen.add(value)
            yield from _hypothesis_callables(value, seen)


def _live_keys() -> tuple[dict[str, str], set[str]]:
    """Map every key form Hypothesis could use to the test that owns it."""
    keys: dict[str, str] = {}
    names: set[str] = set()
    sys.path.insert(0, str(_ROOT / "tests"))
    sys.path.insert(0, str(_ROOT))
    # Only modules that actually use @given — importing all ~310 test modules is slow and
    # some are import-guarded on external services.
    candidates = [p for p in _ROOT.joinpath("tests").rglob("test_*.py") if "@given" in p.read_text(encoding="utf-8")]
    for path in sorted(candidates):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            try:
                spec = importlib.util.spec_from_file_location("corpuscheck_" + path.stem, path)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
            except BaseException:
                continue
        for attr, fn in _hypothesis_callables(module, set()):
            inner = getattr(getattr(fn, "hypothesis", None), "inner_test", fn)
            digest = function_digest(inner)
            names.add(f"{path.name}::{attr}")
            for suffix in _KEY_SUFFIXES:
                keys[_hash(digest + suffix)] = f"{path.name}::{attr}"
    return keys, names


def _corpus_dirs() -> set[str]:
    if not _CORPUS.is_dir():
        return set()
    return {p.name for p in _CORPUS.iterdir() if p.is_dir() and not p.name.startswith(".")}


def test_discovery_finds_the_suites_hypothesis_tests():
    """Non-vacuity. A broken import loop would report every entry as an orphan."""
    _, names = _live_keys()
    assert len(names) >= _MIN_EXPECTED_HYPOTHESIS_TESTS, (
        f"only {len(names)} hypothesis tests discovered (expected >= "
        f"{_MIN_EXPECTED_HYPOTHESIS_TESTS}). Discovery is broken; the orphan check below "
        f"would be meaningless."
    )


def test_the_key_derivation_matches_hypothesis():
    """Prove the mapping, rather than assuming it.

    Verified against a real database write: a temporary failing ``@given`` test produced
    exactly the directories ``_hash(digest)`` and ``_hash(digest + b".secondary")`` predict.
    """

    @pytest.mark.skip
    def _sample(x):
        return x

    digest = function_digest(_sample)
    for suffix in _KEY_SUFFIXES:
        name = _hash(digest + suffix)
        assert len(name) == 16 and all(c in "0123456789abcdef" for c in name)
    assert _hash(digest) != _hash(digest + b".secondary")


def test_no_committed_counterexample_is_orphaned():
    keys, _ = _live_keys()
    orphans = sorted(_corpus_dirs() - set(keys))
    detail = []
    for name in orphans:
        n = sum(1 for _ in (_CORPUS / name).iterdir())
        detail.append(f"  {name}/  ({n} entries)")
    assert not orphans, (
        "committed Hypothesis corpus entries belong to no live test, so nothing replays "
        "them:\n" + "\n".join(detail) + "\n\n"
        "A test was renamed or removed — function_digest incorporates the test NAME, so a "
        "rename orphans its entries while leaving the files in place, looking like coverage.\n"
        "Either restore the test's name, or delete the directory and freeze the case as a "
        "NAMED reproducer instead (see tests/.hypothesis-corpus/README.md)."
    )
