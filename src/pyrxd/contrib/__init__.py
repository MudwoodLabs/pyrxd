"""pyrxd contrib — shipped but non-core components.

Code in ``pyrxd.contrib.*`` ships in the wheel and is invocable as
console scripts, but pyrxd makes **no semver promises** about the
``pyrxd.contrib.*`` import surface. Public-API stability is reserved
for ``pyrxd.*`` and ``pyrxd.glyph.*``.

The contrib boundary exists so the project can ship useful tooling
(a parallel miner today; potentially other operator-side utilities
later) without growing the core API surface or committing to keeping
their internal layout stable.

If a contrib module proves load-bearing enough to merit semver
guarantees, it gets promoted into ``pyrxd.*`` proper in a future
major release. Until then: treat ``pyrxd.contrib.*`` as a CLI
delivery vehicle, not a Python API.
"""
