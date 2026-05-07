"""Lock the import-graph contract for the browser-hosted inspect tool.

Importing ``pyrxd.glyph.inspect`` (the public façade the browser tool
loads) MUST NOT transitively pull in any C-extension Python package
that has no pure-Python wheel. Under Pyodide, ``micropip.install``
fails on those — concretely:

  * ``coincurve`` — secp256k1 bindings (used for signing/verification
    inside ``pyrxd.keys`` / ``pyrxd.curve``)
  * ``Cryptodome.Cipher`` — pycryptodomex AES (used inside
    ``pyrxd.aes_cbc`` for encrypted-wallet I/O)
  * ``aiohttp`` — used by the ``MempoolSpaceSource`` BTC client
  * ``websockets`` — used by the ElectrumX client

Plus we lock the ``pyrxd.*`` module-count budget so a future change
that quietly re-eagers a top-level re-export shows up as a test
failure, not as a confusing browser-page boot error.

The browser tool actually needs:

  * ``cbor2`` — micropip-installable, pure-Python wheel exists
  * ``pycryptodome`` — Pyodide-bundled (the no-x sibling)

Both are explicitly installed by the JS-side ``pyodide.loadPackage``
call before pyrxd is loaded.
"""

from __future__ import annotations

import builtins
import sys

import pytest

# Heavy deps that MUST NOT be triggered by a clean
# ``import pyrxd.glyph.inspect``. Listed by package root so we catch
# any submodule trigger (``coincurve.context``, ``aiohttp._http_writer``
# etc.) at the same level.
_HEAVY_DEP_ROOTS = frozenset({"coincurve", "aiohttp", "websockets", "Cryptodome"})

# Soft cap on the number of ``pyrxd.*`` submodules a clean
# ``import pyrxd.glyph.inspect`` may load. Today's count is 25; we
# allow some growth headroom but a sudden jump means a re-eagered
# import somewhere upstream. Adjust deliberately when the count
# legitimately changes (and document why in the commit).
_PYRXD_MODULE_BUDGET = 35


def _clear_relevant_modules() -> None:
    """Remove pyrxd / heavy-dep modules from sys.modules so the
    fixture-imports below execute fresh."""
    for name in list(sys.modules):
        if name == "pyrxd" or name.startswith("pyrxd.") or name.split(".", 1)[0] in _HEAVY_DEP_ROOTS:
            sys.modules.pop(name)


@pytest.fixture
def heavy_dep_tracker():
    """Yield a list that gets every heavy-dep import attempt
    recorded during the fixture's body.

    Patches ``builtins.__import__`` to capture every import call,
    filters to the heavy-dep roots, and restores the original
    ``__import__`` on teardown. Modules already in ``sys.modules``
    when the import is requested don't trigger ``__import__``, so
    the fixture clears ``pyrxd`` + heavy-dep entries first.
    """
    _clear_relevant_modules()
    triggers: list[str] = []
    original = builtins.__import__

    def traced(name, globals=None, locals=None, fromlist=(), level=0):
        # Only flag first-time imports — re-imports from sys.modules
        # don't go through __import__'s loader path.
        if name not in sys.modules and name.split(".", 1)[0] in _HEAVY_DEP_ROOTS:
            triggers.append(name)
        return original(name, globals, locals, fromlist, level)

    builtins.__import__ = traced
    try:
        yield triggers
    finally:
        builtins.__import__ = original


class TestInspectFacadeIsPyodideClean:
    """``import pyrxd.glyph.inspect`` is the path the browser tool's
    glue takes. It MUST NOT reach for any C-extension dep with no
    pure-Python wheel."""

    def test_no_heavy_deps_triggered(self, heavy_dep_tracker):
        import pyrxd.glyph.inspect  # noqa: F401

        assert heavy_dep_tracker == [], (
            f"importing pyrxd.glyph.inspect triggered heavy deps: "
            f"{sorted({d.split('.', 1)[0] for d in heavy_dep_tracker})}. "
            f"This breaks Pyodide where these deps have no pure-Python wheel. "
            f"Look for a recently-added top-level `from X import Y` in the "
            f"inspect-path import graph (likely in pyrxd/__init__.py, "
            f"pyrxd/glyph/__init__.py, pyrxd/script/__init__.py, or one of "
            f"the helpers in pyrxd/glyph/_inspect_core.py)."
        )

    def test_pyrxd_module_count_within_budget(self):
        _clear_relevant_modules()
        import pyrxd.glyph.inspect  # noqa: F401

        loaded = [m for m in sys.modules if m == "pyrxd" or m.startswith("pyrxd.")]
        count = len(loaded)
        assert count <= _PYRXD_MODULE_BUDGET, (
            f"importing pyrxd.glyph.inspect loaded {count} pyrxd.* modules "
            f"(budget: {_PYRXD_MODULE_BUDGET}). A jump usually means an "
            f"`__init__.py` somewhere re-eagered a top-level re-export. "
            f"Modules loaded:\n  " + "\n  ".join(sorted(loaded))
        )


class TestSubpackageImportsArePyodideClean:
    """The submodules ``_inspect_core`` consumes individually must
    each be clean. Locking each separately makes regressions easier
    to bisect than the aggregated check above."""

    @pytest.mark.parametrize(
        "module_path",
        [
            "pyrxd.glyph._inspect_core",
            "pyrxd.glyph.types",
            "pyrxd.glyph.dmint",
            "pyrxd.glyph.script",
            "pyrxd.glyph.inspector",
            "pyrxd.glyph.payload",
            "pyrxd.glyph.confusables",
            "pyrxd.transaction.transaction",
            "pyrxd.hash",
            "pyrxd.security.errors",
            "pyrxd.security.types",
        ],
    )
    def test_submodule_does_not_trigger_heavy_deps(self, module_path, heavy_dep_tracker):
        import importlib

        importlib.import_module(module_path)
        assert heavy_dep_tracker == [], (
            f"importing {module_path} triggered heavy deps: {sorted({d.split('.', 1)[0] for d in heavy_dep_tracker})}"
        )


class TestLazyAttributeAccessStillWorks:
    """The lazy ``__getattr__`` must still resolve every name in
    ``__all__`` correctly. A bug in the lazy machinery would surface
    as ``AttributeError`` on first access in production."""

    def test_pyrxd_top_level_lazy_resolution(self):
        # Clear so we exercise the lazy-load codepath, not a cached
        # attribute from a previous test.
        _clear_relevant_modules()
        import pyrxd

        # Pick an arbitrary name from __all__ that requires the heavy
        # deps. The first access should succeed (and pull the heavy
        # deps in — that's the contract: lazy loads only when needed).
        cls = pyrxd.GlyphMetadata
        assert cls is not None
        # Subsequent access should hit the cache, not re-import.
        assert pyrxd.GlyphMetadata is cls

    def test_pyrxd_glyph_lazy_resolution(self):
        _clear_relevant_modules()
        import pyrxd.glyph

        cls = pyrxd.glyph.GlyphRef
        assert cls is not None
        assert pyrxd.glyph.GlyphRef is cls

    def test_pyrxd_script_lazy_resolution(self):
        _clear_relevant_modules()
        import pyrxd.script

        cls = pyrxd.script.Script
        assert cls is not None
        assert pyrxd.script.Script is cls

    def test_unknown_attribute_raises(self):
        _clear_relevant_modules()
        import pyrxd

        with pytest.raises(AttributeError, match="has no attribute 'NotARealName'"):
            _ = pyrxd.NotARealName

    def test_dir_returns_all(self):
        import pyrxd

        names = dir(pyrxd)
        assert "GlyphBuilder" in names
        assert "ValidationError" in names
        assert "__version__" in names
