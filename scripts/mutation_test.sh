#!/usr/bin/env bash
# Mutation-test the consensus-critical modules with cosmic-ray.
#
# Usage:
#   scripts/mutation_test.sh                # default: spv (the original scope)
#   scripts/mutation_test.sh script         # script/ primitives
#   scripts/mutation_test.sh transaction    # transaction/ incl. FORKID sighash preimage
#   scripts/mutation_test.sh dmint          # glyph/dmint/ covenant builders + DAA + parser
#   scripts/mutation_test.sh all            # every group, sequentially
#
# Scope by group (why these files — the verification/byte-exact arithmetic):
#   spv          pow.py (PoW/difficulty), merkle.py (proof), chain.py (header-chain link +
#                nBits pin), payment.py (output parse). The parser modules proof.py/witness.py
#                are intentionally excluded: covered by the fuzz harness
#                (tests/test_fuzz_spv_parsers.py) and ~30x slower per mutant.
#   script       script.py (push parse/encode), timelock.py (CLTV/CSV), type.py (P2PKH &c.
#                lock/unlock builders). __init__/unlocking_template are trivial re-exports.
#   transaction  serialization, txid, input/output wire parse, and the Radiant FORKID
#                sighash preimage (transaction_preimage.py) — the fund-loss surface.
#   dmint        builders.py (covenant script bytes), chain.py (state re-derivation parse),
#                types.py (params validation/CBOR), miner.py (DAA target arithmetic + mint
#                tx/preimage construction).
#
# Mechanism: cosmic-ray mutates src/pyrxd/<path>.py IN PLACE (the editable install picks it up),
# runs the module-targeted tests, then we restore the file via git. A trap restores the whole
# scope on any exit. Do NOT run concurrent git ops on src/pyrxd while this runs — prefer running
# the whole thing in a detached worktree (see docs/how-to/mutation-testing.md).
#
# Env:
#   MUTATION_SESSION_DIR   keep cosmic-ray session .sqlite files here (default: mktemp, deleted
#                          on exit). Set it to triage survivors afterwards with cr-report/cr-html.
#   MUTATION_MIN_KILL_PCT  opt-in gate: fail if total kill rate is below this percentage.
set -uo pipefail

cd "$(git rev-parse --show-toplevel)" || { echo "not in a git repo"; exit 1; }

PYTEST="$(command -v pytest || true)"
if [ -z "$PYTEST" ]; then echo "pytest not found — run inside the project venv (poetry run task mutate)"; exit 1; fi
if ! command -v cosmic-ray >/dev/null 2>&1; then echo "cosmic-ray not installed — poetry install --with dev"; exit 1; fi

# Shared fast test files that hold the long-tail assertions for core primitives.
GAPS="tests/test_coverage_gaps.py tests/test_coverage_gaps2.py tests/test_coverage_gaps3.py tests/test_coverage_gaps4.py tests/test_coverage_gaps5.py tests/test_coverage_gaps6.py tests/test_coverage_gaps7.py tests/test_coverage_gaps8.py"

group_files() {
  case "$1" in
    spv)         echo "spv/pow spv/merkle spv/chain spv/payment" ;;
    script)      echo "script/script script/timelock script/type" ;;
    transaction) echo "transaction/transaction transaction/transaction_input transaction/transaction_output transaction/transaction_preimage" ;;
    dmint)       echo "glyph/dmint/builders glyph/dmint/chain glyph/dmint/types glyph/dmint/miner" ;;
    *)           return 1 ;;
  esac
}

group_tests() {
  case "$1" in
    spv)         echo "tests/test_spv.py tests/test_merkle_path.py tests/test_spv_validation_hardening.py" ;;
    script)      echo "tests/test_script.py tests/test_timelock.py tests/test_covenant.py tests/test_glyph_timelock.py tests/test_transaction.py tests/test_preimage.py tests/test_htlc_spend.py $GAPS" ;;
    transaction) echo "tests/test_transaction.py tests/test_preimage.py tests/test_htlc_spend.py tests/test_glyph_transfer.py tests/test_ft_transfer.py tests/test_swap_partial.py tests/test_swap_resolve.py tests/test_fuzz_parsers.py $GAPS" ;;
    dmint)       echo "tests/test_dmint_module.py tests/test_glyph_dmint.py tests/test_dmint_v2_canonical.py tests/test_dmint_v2_daa_canonical.py tests/test_dmint_conformance_vectors.py tests/test_dmint_v2_mainnet_golden.py tests/test_dmint_daa_offchain_onchain_differential.py tests/test_dmint_v1_deploy.py tests/test_dmint_v1_mint.py tests/test_dmint_end_to_end.py tests/test_dmint_deploy_integration.py $GAPS" ;;
  esac
}

# Per-mutant timeout: ~5-8x the group's clean-suite wall time, so a slowed (not hung)
# mutant still gets a fair run while true hangs are bounded.
group_timeout() {
  case "$1" in
    spv)    echo "30.0" ;;
    script) echo "30.0" ;;
    *)      echo "45.0" ;;
  esac
}

GROUPS_REQUESTED="${*:-spv}"
[ "$GROUPS_REQUESTED" = "all" ] && GROUPS_REQUESTED="spv script transaction dmint"
for g in $GROUPS_REQUESTED; do
  group_files "$g" >/dev/null || { echo "unknown group: $g (use spv|script|transaction|dmint|all)"; exit 2; }
done

WORK="${MUTATION_SESSION_DIR:-$(mktemp -d)}"
mkdir -p "$WORK"
cleanup() {
  git checkout -- src/pyrxd/spv/ src/pyrxd/script/ src/pyrxd/transaction/ src/pyrxd/glyph/dmint/ 2>/dev/null
  [ -z "${MUTATION_SESSION_DIR:-}" ] && rm -rf "$WORK"
}
trap cleanup EXIT

total=0; killed=0; surv=0
for g in $GROUPS_REQUESTED; do
  TESTS="$(group_tests "$g")"
  TIMEOUT="$(group_timeout "$g")"
  g_total=0; g_surv=0
  echo "== group: $g =="
  for path in $(group_files "$g"); do
    name="${path//\//-}"
    cfg="$WORK/cr-$name.toml"; sess="$WORK/$name.sqlite"
    rm -f "$sess"
    cat > "$cfg" <<EOF
[cosmic-ray]
module-path = "src/pyrxd/$path.py"
timeout = $TIMEOUT
excluded-modules = []
test-command = "$PYTEST $TESTS -x -q -p no:randomly -p no:cacheprovider -o addopts= --no-cov"

[cosmic-ray.distributor]
name = "local"
EOF
    cosmic-ray init "$cfg" "$sess" >/dev/null 2>&1
    cosmic-ray exec "$cfg" "$sess" >/dev/null 2>&1
    git checkout -- "src/pyrxd/$path.py" 2>/dev/null
    t="$(cr-report "$sess" 2>/dev/null | grep -oE 'total jobs: [0-9]+' | grep -oE '[0-9]+')"
    s="$(cr-report "$sess" 2>/dev/null | grep -oE 'surviving mutants: [0-9]+' | grep -oE '[0-9]+' | head -1)"
    : "${t:=0}"; : "${s:=0}"
    pct=0; [ "$t" -gt 0 ] && pct=$(( (t - s) * 100 / t ))
    printf '  %-28s %4d mutants  %4d killed  %4d survived  (%d%% killed)\n' "$path" "$t" "$((t - s))" "$s" "$pct"
    g_total=$((g_total + t)); g_surv=$((g_surv + s))
  done
  gpct=0; [ "$g_total" -gt 0 ] && gpct=$(( (g_total - g_surv) * 100 / g_total ))
  printf '  %-28s %4d mutants  %4d killed  %4d survived  (%d%% killed)\n' "[$g total]" "$g_total" "$((g_total - g_surv))" "$g_surv" "$gpct"
  total=$((total + g_total)); killed=$((killed + g_total - g_surv)); surv=$((surv + g_surv))
done
# Fail closed on a broken run: zero mutants means cosmic-ray init/exec silently no-op'd (missing tool,
# wrong module path, env breakage) and the redirected stderr hid it — otherwise this would print
# "0% killed" and exit 0, indistinguishable from a healthy run to a CI consumer.
if [ "$total" -eq 0 ]; then
  echo "ERROR: cosmic-ray produced 0 mutants — the run is broken (tool missing, wrong path, or every step no-op'd). Failing." >&2
  exit 1
fi
tpct=$(( killed * 100 / total ))
printf 'TOTAL: %d mutants, %d killed, %d survived (%d%% killed)\n' "$total" "$killed" "$surv" "$tpct"

# Opt-in gate: when MUTATION_MIN_KILL_PCT is set, exit non-zero if the total kill rate is below it.
# Unset (the default) => report-only measurement. The score includes known equivalent mutants that
# cannot be killed (see docs/how-to/mutation-testing.md), so pick a threshold below 100.
MIN_KILL="${MUTATION_MIN_KILL_PCT:-}"
if [ -n "$MIN_KILL" ] && [ "$tpct" -lt "$MIN_KILL" ]; then
  echo "FAIL: total kill rate ${tpct}% < threshold ${MIN_KILL}% (MUTATION_MIN_KILL_PCT)" >&2
  exit 1
fi
