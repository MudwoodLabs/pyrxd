"""pyrxd.contrib.miner — parallel pure-Python SHA256d miner.

A multiprocessing-based reference miner that satisfies the
:func:`pyrxd.glyph.dmint.mine_solution_external` protocol.

Invoked as a subprocess (the supported usage), not imported:

.. code-block:: python

    from pyrxd.glyph.dmint import mine_solution_external
    import sys

    result = mine_solution_external(
        preimage=pow_result.preimage,
        target=state.target,
        miner_argv=[sys.executable, "-m", "pyrxd.contrib.miner"],
        nonce_width=4,
    )

Or directly via the ``pyrxd-miner`` console script:

.. code-block:: bash

    echo '{"preimage_hex":"...","target_hex":"7fffffffffffffff","nonce_width":4}' \\
        | pyrxd-miner

See ``docs/concepts/parallel-mining.md`` for the full protocol spec
and operational notes.

Internal layout — not part of the public API:

- :mod:`pyrxd.contrib.miner.protocol` — request/response shapes.
- :mod:`pyrxd.contrib.miner.parallel` — worker + dispatcher.
- :mod:`pyrxd.contrib.miner.cli` — argparse + JSON-over-stdin/stdout main.
"""
