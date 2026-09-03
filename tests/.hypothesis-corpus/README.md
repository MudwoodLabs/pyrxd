# Committed Hypothesis example corpus

Hypothesis writes shrunk **counterexamples** here (a `DirectoryBasedExampleDatabase`, wired in
`tests/conftest.py`). Unlike the default gitignored `.hypothesis/`, this directory is **committed** so a
failure found by any property/fuzz test persists and is replayed on future runs.

**It is not drift-proof, and this README said it was.** Hypothesis addresses entries by
`_hash(function_digest(test) + suffix)`, and `function_digest` incorporates the test's NAME.
Measured on hypothesis 6.165.0: editing a test's **body** keeps its entries (a changed comparison
operator produced an identical digest), but **renaming or moving a test silently orphans them** —
the files stay, nothing replays them, and the directory still looks like coverage.

**Detecting an orphan from outside Hypothesis is harder than it looks, and a first
attempt at it here was wrong.** That check derived a directory name as
`_hash(function_digest(inner_test) + suffix)` for `suffix` in `("", ".secondary",
".pareto")`, reported all six committed directories as orphaned on that basis, and
they were archived out of the tree. A later fuzz failure then **re-created one of
them** (`04e6b3400353b141`), proving it belonged to a live test after all.

The derivation is incomplete: `hypothesis/core.py:1409` prefers an explicitly-set
`_hypothesis_internal_database_key` over `function_digest`, and where it does compute
one it uses the *wrapped* test rather than `inner_test`. Recomputing across the whole
suite with the attribute form still does not account for that directory, so at least
one more key path exists that has not been identified.

Treat an unmatched directory as **unexplained, not orphaned**, and do not delete one
on the strength of a key computation alone. The safe check is the reverse direction:
confirm a live test's keys resolve as expected, which
`tests/test_hypothesis_corpus_is_live.py` does.

**Convention:** when a fuzz test surfaces a real bug, the reproducing entry lands here automatically;
commit it alongside the fix, and add a focused frozen reproducer to the relevant `tests/test_*.py` so
the case is also named and documented (not only replayed opaquely from the corpus).
