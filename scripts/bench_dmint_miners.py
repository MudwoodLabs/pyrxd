#!/usr/bin/env python3
"""Measure this machine's SHA256d rate with pyrxd's miners, the way the dMint grinds use them.

Runs each miner over a fixed number of nonces with a target no digest can meet (1), so every
run sweeps exactly that many and ``attempts / wall-clock`` is a clean rate, start-up included:

* the bundled pure-Python parallel miner (``pyrxd.contrib.miner.parallel.mine``), and
* the native grinder, when ``--grinder PATH`` is given (build it with
  ``python -m pyrxd.contrib.miner.native --out PATH``).

Prints one JSON line per run: MEASURED fields (``attempts``, ``elapsed_s``, ``mhs``), and a
PROJECTED ``mean_difficulty1_grind_s`` — the EXACT mean attempts of a difficulty-1 grind
(``estimate_attempts``, about 2**33) divided by the measured rate. The nightly dMint job runs
this before its suites, so each night's log records the runner's rate for both miners.

Each run is stopped after ``--timeout-s`` seconds (default 300) and the script then fails, so a
miner that hangs cannot hold the nightly job until its own limit.

Usage::

    python scripts/bench_dmint_miners.py --grinder ./sha256d-grind [--workers N]
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess  # nosec B404 -- runs the grinder binary the caller names
import sys
import time

from pyrxd.contrib.miner.parallel import MineParams, default_n_workers, mine
from pyrxd.contrib.miner.protocol import MineExhausted
from pyrxd.glyph.dmint import MAX_SHA256D_TARGET, estimate_attempts

_PREIMAGE = bytes(range(64))
_UNREACHABLE_TARGET = 1  # a hit needs 12 zero bytes: p = 2**-96 per nonce
_DEFAULT_TIMEOUT_S = 300.0  # per run; the 2026-09-23 runner's slowest run took 37 s


def _report(miner: str, workers: int, attempts: int, elapsed_s: float) -> dict[str, object]:
    rate = attempts / elapsed_s
    mean = estimate_attempts(MAX_SHA256D_TARGET).expected_attempts
    return {
        "miner": miner,
        "workers": workers,
        "attempts": attempts,
        "elapsed_s": round(elapsed_s, 3),
        "mhs": round(rate / 1e6, 2),
        "mean_difficulty1_grind_s_PROJECTED": round(mean / rate, 1),
    }


def bench_python(workers: int, nonces: int, timeout_s: float = _DEFAULT_TIMEOUT_S) -> dict[str, object]:
    def deadline(_attempts: int, elapsed_s: float) -> None:
        # mine()'s supported deadline: a progress callback that raises. Its workers are reaped.
        if elapsed_s > timeout_s:
            raise TimeoutError(f"the bundled Python miner did not sweep {nonces} nonces within {timeout_s} s")

    started = time.monotonic()
    result = mine(
        MineParams(preimage=_PREIMAGE, target=_UNREACHABLE_TARGET, nonce_width=4, n_workers=workers, nonce_max=nonces),
        progress=deadline,
    )
    elapsed = time.monotonic() - started
    if not isinstance(result, MineExhausted):
        raise RuntimeError(f"expected the sweep to find nothing, got {result!r}")
    return _report("bundled Python miner", workers, nonces, elapsed)


def bench_native(grinder: str, workers: int, nonces: int, timeout_s: float = _DEFAULT_TIMEOUT_S) -> dict[str, object]:
    request = json.dumps(
        {"preimage_hex": _PREIMAGE.hex(), "target_hex": f"{_UNREACHABLE_TARGET:016x}", "nonce_width": 4}
    )
    started = time.monotonic()
    done = subprocess.run(  # nosec B603 -- the grinder path the caller passed
        [grinder, "--quiet", "--workers", str(workers), "--nonce-count", str(nonces)],
        input=request.encode(),
        capture_output=True,
        timeout=timeout_s,  # on expiry the grinder is killed and TimeoutExpired raised
        check=False,
    )
    elapsed = time.monotonic() - started
    if done.returncode != 2 or json.loads(done.stdout) != {"exhausted": True}:
        raise RuntimeError(
            f"expected the sweep to find nothing: exit {done.returncode}, {done.stdout!r} {done.stderr!r}"
        )
    return _report(f"native grinder ({os.path.basename(grinder)})", workers, nonces, elapsed)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--grinder", help="path to a built native grinder; omitted = Python miner only")
    parser.add_argument("--workers", type=int, default=default_n_workers(), help="default: os.cpu_count()")
    parser.add_argument("--python-nonces", type=int, default=1 << 25, help="nonces for the Python miner")
    parser.add_argument("--native-nonces", type=int, default=1 << 30, help="nonces for the native grinder")
    parser.add_argument("--repeats", type=int, default=2)
    parser.add_argument(
        "--timeout-s", type=float, default=_DEFAULT_TIMEOUT_S, help="per run; the script fails when one exceeds it"
    )
    args = parser.parse_args(argv)
    for _ in range(args.repeats):
        print(json.dumps(bench_python(args.workers, args.python_nonces, args.timeout_s)), flush=True)
        if args.grinder:
            print(json.dumps(bench_native(args.grinder, args.workers, args.native_nonces, args.timeout_s)), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
