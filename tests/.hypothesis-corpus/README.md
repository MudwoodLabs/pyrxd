# Committed Hypothesis example corpus

Hypothesis writes shrunk **counterexamples** here (a `DirectoryBasedExampleDatabase`, wired in
`tests/conftest.py`). Unlike the default gitignored `.hypothesis/`, this directory is **committed** so a
failure found by any property/fuzz test persists and is replayed on future runs.

**It is not drift-proof, and this README said it was.** Hypothesis addresses entries by
`_hash(function_digest(test) + suffix)`, and `function_digest` incorporates the test's NAME.
Measured on hypothesis 6.165.0: editing a test's **body** keeps its entries (a changed comparison
operator produced an identical digest), but **renaming or moving a test silently orphans them** —
the files stay, nothing replays them, and the directory still looks like coverage.

When that was first checked, **all six committed directories (24 entries) were orphaned** and
matched none of the suite's 97 live hypothesis tests. `tests/test_hypothesis_corpus_is_live.py`
now fails on any orphan, so this cannot recur silently.

**Convention:** when a fuzz test surfaces a real bug, the reproducing entry lands here automatically;
commit it alongside the fix, and add a focused frozen reproducer to the relevant `tests/test_*.py` so
the case is also named and documented (not only replayed opaquely from the corpus).
