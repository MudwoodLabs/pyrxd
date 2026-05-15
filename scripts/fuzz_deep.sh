#!/usr/bin/env bash
#
# Deep Hypothesis fuzz run — re-executes tests/test_fuzz_parsers.py and
# tests/test_property_based.py with a much higher example budget than CI.
#
# Usage:
#   scripts/fuzz_deep.sh                 # 25 000× per-test budget (~30-60 min)
#   scripts/fuzz_deep.sh overnight       # 250 000× budget (hours)
#   scripts/fuzz_deep.sh quick           # 5 000× budget (~5 min smoke)
#
# Output:
#   logs/fuzz-deep-<profile>-<timestamp>.log  — full pytest output
#
# Same code as the CI fuzz run; FUZZ_BUDGET_MULTIPLIER scales every per-test
# `max_examples`, and HYPOTHESIS_PROFILE switches Hypothesis to a no-deadline
# profile so deep searches don't trip the per-example timeout.
#
# Why a separate script (not a `task fuzz` target): this is a one-off
# stress run, not part of the standard `task ci` pipeline. Adding it to
# taskipy would tempt callers to run it routinely; keeping it as an
# explicit script makes the cost obvious.

set -euo pipefail

cd "$(dirname "$0")/.."

profile="${1:-deep}"

case "$profile" in
  quick)
    multiplier=12     # 400 → 4_800 examples per test
    hypothesis_profile=deep
    ;;
  deep)
    multiplier=62     # 400 → ~25_000 examples per test
    hypothesis_profile=deep
    ;;
  overnight)
    multiplier=625    # 400 → ~250_000 examples per test
    hypothesis_profile=overnight
    ;;
  *)
    echo "Unknown profile: $profile" >&2
    echo "Use one of: quick, deep, overnight" >&2
    exit 2
    ;;
esac

mkdir -p logs
timestamp="$(date +%Y%m%d-%H%M%S)"
log="logs/fuzz-deep-${profile}-${timestamp}.log"

echo "Hypothesis deep fuzz — profile=$profile, multiplier=${multiplier}x"
echo "Logging to: $log"
echo

# -p no:cacheprovider keeps the fuzz run from polluting the rootdir's
# .pytest_cache (Hypothesis's own database lives separately under
# .hypothesis/ and *is* useful between runs — Hypothesis re-tries
# previously-failing inputs from there).
FUZZ_BUDGET_MULTIPLIER="$multiplier" \
HYPOTHESIS_PROFILE="$hypothesis_profile" \
PYTHONUNBUFFERED=1 \
  python3 -m pytest \
    tests/test_fuzz_parsers.py \
    tests/test_property_based.py \
    --no-cov \
    -p no:cacheprovider \
    -v \
    --tb=short \
    -o addopts= \
    2>&1 | tee "$log"

echo
echo "Done. Full log: $log"
