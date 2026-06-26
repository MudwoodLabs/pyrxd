#!/usr/bin/env bash
# Mutation-test the consensus-critical SPV verification modules with cosmic-ray.
#
# Scope: the verification ARITHMETIC — pow.py (PoW/difficulty), merkle.py (proof), chain.py
# (header-chain link + nBits pin), payment.py (output parse). The parser modules proof.py /
# witness.py are intentionally excluded here: they are covered by the fuzz harness
# (tests/test_fuzz_spv_parsers.py), and the full test command needed to cover them is ~30x slower
# per mutant, so mixing them in would make this gate impractical.
#
# Mechanism: cosmic-ray mutates src/pyrxd/spv/<file>.py IN PLACE (the editable install picks it up),
# runs the SPV verification tests, then we restore the file via git. A trap restores the whole
# directory on any exit. Do NOT run concurrent git ops on src/pyrxd/spv while this runs.
#
# See docs/how-to/mutation-testing.md for the survivor analysis and what the score means.
set -uo pipefail

cd "$(git rev-parse --show-toplevel)" || { echo "not in a git repo"; exit 1; }

PYTEST="$(command -v pytest || true)"
if [ -z "$PYTEST" ]; then echo "pytest not found — run inside the project venv (poetry run task mutate)"; exit 1; fi
if ! command -v cosmic-ray >/dev/null 2>&1; then echo "cosmic-ray not installed — poetry install --with dev"; exit 1; fi

FILES="pow merkle chain payment"
TESTS="tests/test_spv.py tests/test_merkle_path.py tests/test_spv_validation_hardening.py"
WORK="$(mktemp -d)"
trap 'git checkout -- src/pyrxd/spv/ 2>/dev/null; rm -rf "$WORK"' EXIT

total=0; killed=0; surv=0
for f in $FILES; do
  cfg="$WORK/cr-$f.toml"; sess="$WORK/$f.sqlite"
  cat > "$cfg" <<EOF
[cosmic-ray]
module-path = "src/pyrxd/spv/$f.py"
timeout = 30.0
excluded-modules = []
test-command = "$PYTEST $TESTS -x -q -p no:randomly -p no:cacheprovider -o addopts= --no-cov"

[cosmic-ray.distributor]
name = "local"
EOF
  cosmic-ray init "$cfg" "$sess" >/dev/null 2>&1
  cosmic-ray exec "$cfg" "$sess" >/dev/null 2>&1
  git checkout -- "src/pyrxd/spv/$f.py" 2>/dev/null
  t="$(cr-report "$sess" 2>/dev/null | grep -oE 'total jobs: [0-9]+' | grep -oE '[0-9]+')"
  s="$(cr-report "$sess" 2>/dev/null | grep -oE 'surviving mutants: [0-9]+' | grep -oE '[0-9]+' | head -1)"
  : "${t:=0}"; : "${s:=0}"
  pct=0; [ "$t" -gt 0 ] && pct=$(( (t - s) * 100 / t ))
  printf '  %-9s %4d mutants  %4d killed  %4d survived  (%d%% killed)\n' "$f" "$t" "$((t - s))" "$s" "$pct"
  total=$((total + t)); killed=$((killed + t - s)); surv=$((surv + s))
done
tpct=0; [ "$total" -gt 0 ] && tpct=$(( killed * 100 / total ))
printf 'TOTAL: %d mutants, %d killed, %d survived (%d%% killed)\n' "$total" "$killed" "$surv" "$tpct"
