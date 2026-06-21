# Committed Hypothesis example corpus

Hypothesis writes shrunk **counterexamples** here (a `DirectoryBasedExampleDatabase`, wired in
`tests/conftest.py`). Unlike the default gitignored `.hypothesis/`, this directory is **committed** so a
failure found by any property/fuzz test persists and is **replayed on every future run until fixed** —
a drift-proof regression corpus.

**Convention:** when a fuzz test surfaces a real bug, the reproducing entry lands here automatically;
commit it alongside the fix, and add a focused frozen reproducer to the relevant `tests/test_*.py` so
the case is also named and documented (not only replayed opaquely from the corpus).
