#   ---------------------------------------------------------------------------------
#   Copyright (c) Microsoft Corporation. All rights reserved.
#   Licensed under the MIT License. See LICENSE in project root for information.
#   ---------------------------------------------------------------------------------
"""
This is a configuration file for pytest containing customizations and fixtures.

In VSCode, Code Coverage is recorded in config.xml. Delete this file to reset reporting.
"""

from __future__ import annotations

import os
import pathlib
import sys

import pytest

# Make ``from tests.X import ...`` resolvable for the integration e2e files that share helpers
# across test modules. pytest's console-script entrypoint only puts ``src`` on sys.path (pyproject
# ``pythonpath=["src"]``) and there is no ``tests/__init__.py``, so without this those modules fail
# to COLLECT under plain ``pytest`` (even though they are deselected as integration) — only
# ``python -m pytest`` worked, because it adds the CWD. conftest is imported before any test module,
# so adding the repo root here fixes collection for the whole suite regardless of file order.
_REPO_ROOT = str(pathlib.Path(__file__).resolve().parent.parent)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

# Hypothesis profiles for fuzz tests. The default `max_examples` is set per
# test (via @settings) and aimed at fast CI feedback. The "deep" profile
# overrides every test globally for a thorough one-off run — selected with
# HYPOTHESIS_PROFILE=deep (used by scripts/fuzz_deep.sh).
#
# Profile values:
#   ci       — CI default; no override (per-test settings win).
#   deep     — overnight run: 25_000 examples, no deadline.
#   overnight — extreme: 250_000 examples, no deadline. Hours per file.
try:
    from hypothesis import HealthCheck, settings
    from hypothesis.database import DirectoryBasedExampleDatabase

    # COMMITTED example database (tests/.hypothesis-corpus/) so a shrunk counterexample found by any
    # fuzz test PERSISTS and is replayed on every future run until fixed. The default .hypothesis/ dir is
    # gitignored and ephemeral on CI runners, so found failures were silently discarded (audit follow-up).
    # A developer who reproduces a failure commits the corpus entry; it then regresses forever. NOT
    # gitignored (the ignore is `.hypothesis/`, a different name).
    _corpus = DirectoryBasedExampleDatabase(os.path.join(os.path.dirname(__file__), ".hypothesis-corpus"))

    # ci: keep random exploration but replay the committed corpus first, so a previously-found
    # counterexample regresses on every run. (Hypothesis makes derandomize and a database mutually
    # exclusive — derandomize implies database=None — and the persistent corpus is the load-bearing half.)
    settings.register_profile("ci", database=_corpus)
    settings.register_profile(
        "deep",
        max_examples=25_000,
        deadline=None,
        database=_corpus,
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.large_base_example],
    )
    settings.register_profile(
        "overnight",
        max_examples=250_000,
        deadline=None,
        database=_corpus,
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.large_base_example],
    )
    settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "ci"))
except ImportError:
    # Hypothesis not installed — non-fuzz tests should still run.
    pass


# NOTE: there is deliberately no auto-marking hook here.
#
# This used to be:
#
#     def pytest_collection_modifyitems(items):
#         for item in items:
#             if "_int_" in item.nodeid:
#                 item.add_marker(pytest.mark.integration)
#
# ``"_int_"`` is a substring, not a word, so it matched any test whose name contained
# ``..._int_...`` — ``test_finite_int_refuses...``, ``test_nonneg_int_accepts...``,
# ``test_encode_int_zero_is_op_0``, ``test_reader_var_int_fd``, and so on. The default
# ``-m 'not integration'`` in ``pyproject.toml`` then dropped every one of them from
# every run: 55 pure-offline unit tests that had never executed in CI, including most of
# ``tests/network/test_guards.py`` — the hostile-server coercions whose whole job is to
# fail closed on an attacker-supplied number.
#
# It also never marked anything it was meant to: ``test_integration_*`` contains
# ``_integration_``, which does NOT contain ``_int_``. Every real integration module
# carries an explicit module-level ``pytestmark = pytest.mark.integration`` instead, so
# nothing depended on this hook. Deselection count with it: 193; without: 138.
#
# If a marker is ever needed by name again, match a whole path/name component — never a
# bare substring of an identifier.


@pytest.fixture
def unit_test_mocks(monkeypatch: None):
    """Include Mocks here to execute all commands offline and fast."""
    pass
