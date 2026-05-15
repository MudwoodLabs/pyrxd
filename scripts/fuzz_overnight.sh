#!/usr/bin/env bash
#
# Run the full fuzz suite — Hypothesis deep + every atheris harness — in
# parallel for an overnight stress run. Each lane logs to its own file under
# logs/. The script returns a non-zero exit if *any* lane found a crash.
#
# Usage:
#   scripts/fuzz_overnight.sh                   # 8 hours per atheris lane
#   scripts/fuzz_overnight.sh 3600              # 1 hour per atheris lane
#   scripts/fuzz_overnight.sh 28800 overnight   # 8h atheris + overnight Hypothesis
#
# Args:
#   $1 — atheris max_total_time per harness (seconds, default 28800 = 8h)
#   $2 — Hypothesis profile (quick / deep / overnight, default deep)
#
# Lanes (all in parallel):
#   - Hypothesis deep run (CPU-bound, single Python process)
#   - 5 atheris harnesses (each is its own Python+libFuzzer process)
#
# Total CPU footprint: 6 cores at ~100%. If you have fewer cores, atheris
# lanes share CPU — they're libFuzzer mutators bottlenecked on Python
# execution speed and degrade gracefully.
#
# Findings:
#   Each atheris harness crashes loudly into its log on first failure and
#   drops a reproducer at logs/atheris-<target>-crash-<sha>. The
#   Hypothesis lane fails the pytest run.
#
# Atheris is not pinned in pyproject.toml (it's a one-off dev tool, not a
# CI dep). Install with: pip install atheris

set -uo pipefail  # NOT -e: we want all lanes to run even if one fails.

cd "$(dirname "$0")/.."

atheris_seconds="${1:-28800}"   # default 8 hours
hypothesis_profile="${2:-deep}"

# Confirm atheris is importable before launching anything.
if ! .venv/bin/python3 -c "import atheris" 2>/dev/null; then
    echo "atheris is not installed in .venv/. Install with:" >&2
    echo "    .venv/bin/pip install atheris" >&2
    exit 2
fi

mkdir -p logs
timestamp="$(date +%Y%m%d-%H%M%S)"

echo "=============================================="
echo "Overnight fuzz run — $timestamp"
echo "  atheris max_total_time per lane : ${atheris_seconds}s"
echo "  hypothesis profile              : $hypothesis_profile"
echo "  logs                            : logs/fuzz-overnight-${timestamp}/"
echo "=============================================="

run_dir="logs/fuzz-overnight-${timestamp}"
mkdir -p "$run_dir"

declare -a pids=()
declare -a names=()

# --- Lane 1: Hypothesis deep run ---
(
    HYPOTHESIS_PROFILE="$hypothesis_profile" \
        scripts/fuzz_deep.sh "$hypothesis_profile" \
        > "$run_dir/hypothesis.log" 2>&1
    echo "$?" > "$run_dir/hypothesis.exit"
) &
pids+=($!)
names+=("hypothesis")

# --- Lanes 2..N: one per atheris harness ---
for harness in scripts/fuzz_atheris/harness_*.py; do
    name="$(basename "$harness" .py)"
    name="${name#harness_}"
    artifact_prefix="$run_dir/atheris-${name}-crash-"
    (
        .venv/bin/python3 "$harness" \
            -atheris_runs=0 \
            -max_total_time="$atheris_seconds" \
            -artifact_prefix="$artifact_prefix" \
            > "$run_dir/atheris-${name}.log" 2>&1
        echo "$?" > "$run_dir/atheris-${name}.exit"
    ) &
    pids+=($!)
    names+=("atheris-$name")
done

echo
echo "Launched ${#pids[@]} fuzz lanes:"
for i in "${!pids[@]}"; do
    echo "  - ${names[$i]} (pid ${pids[$i]})"
done
echo
echo "Monitor with:  tail -f $run_dir/*.log"
echo

# Wait for everything; track failures.
failures=0
for i in "${!pids[@]}"; do
    wait "${pids[$i]}" || true
    exit_file="$run_dir/${names[$i]}.exit"
    code="$(cat "$exit_file" 2>/dev/null || echo "?")"
    if [[ "$code" != "0" ]]; then
        failures=$((failures + 1))
        echo "FAILED: ${names[$i]} (exit $code) — see $run_dir/${names[$i]}.log"
    else
        echo "OK:     ${names[$i]}"
    fi
done

echo
if [[ $failures -gt 0 ]]; then
    echo "Total failures: $failures / ${#pids[@]}"
    echo "Reproducers (if any) are in $run_dir/atheris-*-crash-*"
    exit 1
fi

echo "All ${#pids[@]} lanes finished cleanly."
