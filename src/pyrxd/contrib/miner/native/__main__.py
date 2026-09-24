"""``python -m pyrxd.contrib.miner.native --out PATH``: build the native grinder.

Compiles ``sha256d_grind.c`` with the machine's C compiler, runs the binary's
self-test, and prints where it is and what the self-test reported. Exit code 0
on success, 1 on any failure (the message says which step failed).
"""

from __future__ import annotations

import argparse
import sys

from . import SOURCE, NativeGrinderBuildError, build, selftest_line


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m pyrxd.contrib.miner.native",
        description=(
            "Build the native SHA256d grinder from the C source shipped with pyrxd, then run its "
            "self-test. The result speaks pyrxd's external-miner protocol: pass its path to "
            "`pyrxd glyph claim-dmint --miner-cmd` or to mine_solution_external(miner_argv=[...])."
        ),
    )
    parser.add_argument("--out", metavar="PATH", help="where to write the executable (required unless --print-source)")
    parser.add_argument(
        "--cc", default=None, metavar="CMD", help="C compiler command (default: $CC, else cc/gcc/clang)"
    )
    parser.add_argument("--print-source", action="store_true", help="print the C source's path and exit")
    args = parser.parse_args(argv)

    if args.print_source:
        print(SOURCE)
        return 0
    if not args.out:
        parser.error("--out is required")
    try:
        path = build(args.out, cc=args.cc)
        report = selftest_line(path)
    except NativeGrinderBuildError as exc:
        sys.stderr.write(f"{exc}\n")
        return 1
    print(f"built {path}")
    print(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
