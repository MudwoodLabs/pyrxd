#!/usr/bin/env python3
"""Run the default test suite as a series of fresh pytest processes, one chunk of files each.

WHY THIS EXISTS: the review sandbox guest has 8 GB of RAM and no swap, and the full suite in one
process does not finish there (it ended in INTERNALERROR/MemoryError on every run; see the
mythos-run skill). A reviewer that cannot run the whole suite picks a few test files instead, and a
"no test catches this" claim made from a few files is wrong when the catching test lives in a file
it left out (the 0.27 release pass reported exactly that, and it was false). Memory a pytest
process grows is only returned when the process exits, so running the same files in several
processes caps the peak at the largest chunk instead of the whole suite.

WHAT IT RUNS: every ``test_*.py`` under ``tests/``, sorted and cut into ``--chunks`` contiguous
groups, each run as ``pytest --no-cov -p no:cacheprovider <files>``. The repository's ``addopts``
still apply, so ``-m 'not integration'`` deselects the node-backed lanes exactly as ``task test``
does, and ``tests/conftest.py``'s skip audit runs in every chunk. Coverage is off: a coverage
number from chunks is not the CI gate's number (``task coverage-overall``), so none is printed.

WHAT IT REFUSES: it exits non-zero when any chunk fails, when a chunk ends in anything but
"passed" or "nothing selected", or when the chunks together ran no test at all. Every file is
assigned to exactly one chunk, and the script checks that before it starts.

It prints, per chunk, the exit code, the test counts from the chunk's JUnit report and the
chunk's peak resident memory (``ru_maxrss`` of that pytest process and its waited children), so
an operator can see how close the largest chunk came to the guest's limit.

Usage::

    python scripts/run_tests_in_chunks.py [--chunks N] [--report-dir DIR] [-- EXTRA PYTEST ARGS]
"""

from __future__ import annotations

import argparse
import os
import pathlib
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET

REPO = pathlib.Path(__file__).resolve().parent.parent
TESTS = REPO / "tests"

#: pytest's exit codes this script accepts from one chunk: every selected test passed, or the
#: chunk's files held only deselected (integration-marked) tests.
_OK_EXIT_CODES = frozenset({0, 5})


def test_files(root: pathlib.Path = TESTS) -> list[pathlib.Path]:
    """Every ``test_*.py`` under ``root``, sorted."""
    return sorted(p for p in root.rglob("test_*.py") if "__pycache__" not in p.parts)


def split(files: list[pathlib.Path], chunks: int) -> list[list[pathlib.Path]]:
    """Cut ``files`` into ``chunks`` contiguous groups whose sizes differ by at most one."""
    if chunks < 1:
        raise ValueError(f"--chunks must be at least 1 (got {chunks})")
    chunks = min(chunks, len(files))
    base, extra = divmod(len(files), chunks)
    out: list[list[pathlib.Path]] = []
    start = 0
    for i in range(chunks):
        size = base + (1 if i < extra else 0)
        out.append(files[start : start + size])
        start += size
    return out


def _junit_counts(path: pathlib.Path) -> dict[str, int]:
    """Totals from one JUnit report; all zero when pytest wrote none (nothing collected)."""
    counts = {"tests": 0, "failures": 0, "errors": 0, "skipped": 0}
    if not path.exists():
        return counts
    root = ET.parse(path).getroot()  # noqa: S314 - our own pytest's report, written a moment ago
    suites = [root] if root.tag == "testsuite" else list(root.iter("testsuite"))
    for suite in suites:
        for key in counts:
            counts[key] += int(suite.get(key, "0"))
    return counts


def run(chunks: int, report_dir: pathlib.Path, extra: list[str], root: pathlib.Path = TESTS) -> int:
    """Run every test file under ``root`` in ``chunks`` processes; 0 only if all of them passed."""
    files = test_files(root)
    if not files:
        print(f"no test files found under {root}", file=sys.stderr)
        return 2
    cwd = root.parent
    groups = split(files, chunks)
    assigned = [f for g in groups for f in g]
    if sorted(assigned) != files or len(set(assigned)) != len(assigned):
        print("internal error: the chunks do not cover every test file exactly once", file=sys.stderr)
        return 2

    report_dir.mkdir(parents=True, exist_ok=True)
    print(f"{len(files)} test files in {len(groups)} chunks; JUnit reports in {report_dir}")
    total = {"tests": 0, "failures": 0, "errors": 0, "skipped": 0}
    bad: list[int] = []
    for i, group in enumerate(groups, 1):
        junit = report_dir / f"chunk-{i:02d}.xml"
        junit.unlink(missing_ok=True)
        cmd = ["pytest", "--no-cov", "-p", "no:cacheprovider", "-q", f"--junitxml={junit}", *extra, *map(str, group)]
        first, last = (f.relative_to(cwd) for f in (group[0], group[-1]))
        print(f"\n=== chunk {i}/{len(groups)}: {first} .. {last} ({len(group)} files)", flush=True)
        started = time.monotonic()
        proc = subprocess.Popen(cmd, cwd=cwd)
        _, status, usage = os.wait4(proc.pid, 0)
        proc.returncode = os.waitstatus_to_exitcode(status)
        counts = _junit_counts(junit)
        for key in total:
            total[key] += counts[key]
        peak_mib = usage.ru_maxrss / 1024  # Linux reports KiB
        print(
            f"=== chunk {i}: exit {proc.returncode}, {counts['tests']} tests, {counts['failures']} failed, "
            f"{counts['errors']} errors, {counts['skipped']} skipped, peak RSS {peak_mib:.0f} MiB, "
            f"{time.monotonic() - started:.0f} s",
            flush=True,
        )
        if proc.returncode not in _OK_EXIT_CODES:
            bad.append(i)

    print(
        f"\nTOTAL: {total['tests']} tests, {total['failures']} failed, {total['errors']} errors, "
        f"{total['skipped']} skipped, in {len(groups)} chunks"
    )
    if bad:
        print(f"FAILED: chunk(s) {', '.join(map(str, bad))} did not pass", file=sys.stderr)
        return 1
    if total["tests"] == 0:
        print("FAILED: the chunks ran no test at all", file=sys.stderr)
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    extra: list[str] = []
    if "--" in args:
        at = args.index("--")
        args, extra = args[:at], args[at + 1 :]
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("--chunks", type=int, default=8, help="number of pytest processes (default 8)")
    parser.add_argument("--report-dir", type=pathlib.Path, default=None, help="where JUnit reports go")
    ns = parser.parse_args(args)
    report_dir = ns.report_dir or pathlib.Path(tempfile.mkdtemp(prefix="pyrxd-chunks-"))
    return run(ns.chunks, report_dir, extra)


if __name__ == "__main__":
    sys.exit(main())
