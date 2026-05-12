"""CLI entry point for the parallel miner.

Implements pyrxd's JSON-over-subprocess external-miner protocol. Reads
one JSON object from stdin, writes one JSON object to stdout, exits
with a documented code.

Invoke as a console script:

.. code-block:: bash

    pyrxd-miner

Or as a module:

.. code-block:: bash

    python -m pyrxd.contrib.miner

Or via :func:`pyrxd.glyph.dmint.mine_solution_external` with
``miner_argv=[sys.executable, "-m", "pyrxd.contrib.miner"]``.

See :mod:`pyrxd.contrib.miner.protocol` for the wire-format spec.
"""

from __future__ import annotations

import argparse
import sys

from .parallel import MineParams, default_n_workers, mine
from .protocol import (
    MAX_REQUEST_BYTES,
    PROTOCOL_VERSION,
    MineExhausted,
    MineRequest,
    MineSuccess,
    ProtocolError,
)


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pyrxd-miner",
        description=(
            "Parallel pure-Python SHA256d miner — implements pyrxd's "
            f"external-miner JSON protocol v{PROTOCOL_VERSION}. Reads "
            "one JSON request from stdin, writes one JSON response to "
            "stdout. See docs/concepts/parallel-mining.md."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exit codes:\n"
            "  0  solution found (stdout: {nonce_hex, attempts, elapsed_s})\n"
            "  1  usage / protocol error (stderr has details)\n"
            "  2  nonce space exhausted (stdout: {exhausted: true})\n"
        ),
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=None,
        metavar="N",
        help=("Number of worker processes (default: os.cpu_count()). Use --workers 1 to disable parallelism."),
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress stderr progress messages on exhaustion.",
    )
    parser.add_argument(
        "--protocol-version",
        action="version",
        version=f"pyrxd-miner protocol v{PROTOCOL_VERSION}",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point.

    :param argv: argv minus the program name. ``None`` means use
        :data:`sys.argv` (the real-CLI path). Tests pass explicit lists.
    :returns: Exit code. Process-level ``sys.exit`` is the caller's
        responsibility — this function only returns the int.
    """
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    n_workers = args.workers if args.workers is not None else default_n_workers()
    if n_workers < 1:
        sys.stderr.write(f"--workers must be ≥ 1, got {n_workers}\n")
        return 1

    # Bounded stdin read. A request larger than this is malformed by
    # construction (well under 1 KB is normal). Defends against an
    # upstream component dumping unbounded data into the miner.
    try:
        raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    except (OSError, ValueError) as exc:
        sys.stderr.write(f"stdin read failed: {exc}\n")
        return 1
    if len(raw) > MAX_REQUEST_BYTES:
        sys.stderr.write(f"request exceeds {MAX_REQUEST_BYTES}-byte cap\n")
        return 1

    try:
        request = MineRequest.from_json(raw)
    except ProtocolError as exc:
        sys.stderr.write(f"protocol error: {exc}\n")
        return 1

    nonce_max = 2 ** (request.nonce_width * 8)
    params = MineParams(
        preimage=request.preimage,
        target=request.target,
        nonce_width=request.nonce_width,
        n_workers=n_workers,
        nonce_max=nonce_max,
    )

    result = mine(params)

    if isinstance(result, MineExhausted):
        if not args.quiet:
            sys.stderr.write(f"exhausted {nonce_max:,} nonces across {n_workers} workers without finding a solution\n")
        sys.stdout.write(result.to_json() + "\n")
        return 2

    # mine() returns Union[MineSuccess, MineExhausted]; the only other
    # arm of the union was handled above. A mismatch here is a
    # programming bug in mine(), not a user-input concern.
    if not isinstance(result, MineSuccess):
        sys.stderr.write(f"internal error: mine() returned unexpected type {type(result).__name__}\n")
        return 1
    sys.stdout.write(result.to_json() + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
