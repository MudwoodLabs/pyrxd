#!/usr/bin/env bash
# Mutation-test the consensus-critical and value-moving modules with cosmic-ray.
#
# Usage:
#   scripts/mutation_test.sh                # default: spv (the original scope)
#   scripts/mutation_test.sh script         # script/ primitives
#   scripts/mutation_test.sh transaction    # transaction/ incl. FORKID sighash preimage
#   scripts/mutation_test.sh dmint          # glyph/dmint/ covenant builders + DAA + parser
#   scripts/mutation_test.sh fee            # fee_sizing.py — the one fee-sizing rule
#   scripts/mutation_test.sh wallet         # wallet.py — the flat-key send/sweep builders
#   scripts/mutation_test.sh hdwallet       # hd/wallet.py — the BIP32/44 send/sweep builders
#   scripts/mutation_test.sh glyph          # glyph/ft.py + glyph/builder.py — token builders
#   scripts/mutation_test.sh mint           # glyph/mint.py + transfer.py + client.py — the mint/move facade
#   scripts/mutation_test.sh glyphscript    # glyph/script.py + glyph/payload.py — token script + CBOR bytes
#   scripts/mutation_test.sh swap           # gravity/htlc_spend.py + swap/rswp/orders.py
#   scripts/mutation_test.sh coordinator    # gravity/swap_coordinator.py — the swap state machine
#   scripts/mutation_test.sh network        # network/ — RPC/ElectrumX response parsing + failover
#   scripts/mutation_test.sh consensus      # the original four groups
#   scripts/mutation_test.sh value          # the nine value-moving groups
#   scripts/mutation_test.sh all            # every group, sequentially (many hours)
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
# The value-moving groups below were added because every guard audited in 2026-08 that shipped
# correct with nothing able to detect its removal sat in a module mutation testing had never
# touched. Consensus-critical byte arithmetic was covered; the code that decides *how much* moves
# and *to whom* was not.
#
#   fee          fee_sizing.py — the single implementation of "how many photons must this tx pay".
#                Radiant has neither RBF nor CPFP, so an under-sized fee strands the inputs for
#                8 hours; this rule previously existed as three drifting copies.
#   wallet       wallet.py — the flat-key send/send-max/sweep builders: input selection, change,
#                and the two-pass trial/final fee sizing.
#   hdwallet     hd/wallet.py — the same builders over BIP32/44 derivation, plus gap-limit
#                discovery and the change/receive chain split.
#   glyph        glyph/ft.py + glyph/builder.py — FT/NFT transfer and mint builders. ft.py is the
#                module the 0.15.0 whole-balance-send fund-safety bug lived in.
#   mint         glyph/mint.py (the two-phase commit/reveal — the commit output is a hashlock with
#                no owner-only spend path, so a defect here strands value rather than losing a
#                transaction), glyph/transfer.py (the FT/NFT transfer path and its fee guards) and
#                glyph/client.py (the facade both go through). Added after 0.19.0, where the
#                26 RXD fee-ceiling burn and a commit-stranding facade default both lived in
#                modules mutation testing had never touched — the same reason the value groups
#                exist at all. See docs/solutions/logic-errors/glyph-mint-fee-ceiling-*.md.
#   glyphscript  glyph/script.py (the locking scripts every token is held under) and
#                glyph/payload.py (the CBOR a Glyph carries). Distinct from the `script` group,
#                which is the Bitcoin script PRIMITIVES. These bytes are an interop surface: they
#                must match what Photonic's indexer and the network expect, and a mutation that
#                changes them CONSISTENTLY on both the write and read side is invisible to a
#                round-trip test — only frozen-byte vectors can see it. `build_ft_locking_script`
#                in particular is compared against real bytes in exactly one place
#                (test_dmint_premine_regtest_e2e.py), which is integration-marked and therefore
#                excluded from every mutation run by `-m 'not integration'`.
#   swap         gravity/htlc_spend.py (hashlock claim + CSV refund spends) and
#                swap/rswp/orders.py (the on-chain orderbook wire format).
#   coordinator  gravity/swap_coordinator.py — the cross-chain HTLC state machine that decides
#                when it is safe to claim, refund, or abort.
#   network      network/ — every remote response this SDK trusts: RPC/ElectrumX parsing,
#                endpoint failover, TLS pinning, confirmation counting. A hostile or buggy server
#                is a trust boundary, so a deleted guard here is a fund-safety issue.
#
# Mechanism: cosmic-ray mutates src/pyrxd/<path>.py IN PLACE (the editable install picks it up),
# runs the module-targeted tests, then we restore the file via git. A trap restores exactly the
# files the requested groups touch, on any exit. Do NOT run concurrent git ops on src/pyrxd while
# this runs — prefer running the whole thing in a detached worktree (see
# docs/how-to/mutation-testing.md).
#
# Env:
#   MUTATION_SESSION_DIR   keep cosmic-ray session .sqlite files here (default: mktemp, deleted
#                          on exit). Set it to triage survivors afterwards with cr-report/cr-html.
#   MUTATION_REPORT_DIR    where the per-group Markdown survivor lists are written
#                          (default: .mutation-reports/ in the repo root, gitignored).
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
    fee)         echo "fee_sizing" ;;
    wallet)      echo "wallet" ;;
    hdwallet)    echo "hd/wallet" ;;
    glyph)       echo "glyph/ft glyph/builder" ;;
    mint)        echo "glyph/mint glyph/transfer glyph/client" ;;
    glyphscript) echo "glyph/script glyph/payload" ;;
    swap)        echo "gravity/htlc_spend swap/rswp/orders" ;;
    coordinator) echo "gravity/swap_coordinator" ;;
    network)     echo "network/bitcoin network/electrumx network/failover network/confirm network/_guards network/tls_pin network/registry network/rxindexer network/chaintracker" ;;
    keys)        echo "security/errors security/secrets base58 hd/bip32 hd/descriptor gravity/watch/cli_secrets" ;;
    *)           return 1 ;;
  esac
}

group_tests() {
  # tests/test_mutation_hardening.py leads each list: it holds the targeted
  # mutant-killing assertions and runs in ~0.05s, so `-x` exits cheapest on
  # the mutants it pins. The property/differential suites close each list
  # (the expensive net for whatever the unit files miss).
  case "$1" in
    spv)         echo "tests/test_spv.py tests/test_merkle_path.py tests/test_spv_validation_hardening.py" ;;
    script)      echo "tests/test_mutation_hardening.py tests/test_script.py tests/test_timelock.py tests/test_covenant.py tests/test_glyph_timelock.py tests/test_transaction.py tests/test_preimage.py tests/test_htlc_spend.py $GAPS" ;;
    transaction) echo "tests/test_mutation_hardening.py tests/test_transaction.py tests/test_preimage.py tests/test_htlc_spend.py tests/test_glyph_transfer.py tests/test_ft_transfer.py tests/test_swap_partial.py tests/test_swap_resolve.py $GAPS tests/test_fuzz_parsers.py tests/test_preimage_differential.py" ;;
    dmint)       echo "tests/test_mutation_hardening.py tests/test_dmint_module.py tests/test_glyph_dmint.py tests/test_dmint_v2_canonical.py tests/test_dmint_v2_daa_canonical.py tests/test_dmint_conformance_vectors.py tests/test_dmint_v2_mainnet_golden.py tests/test_dmint_daa_offchain_onchain_differential.py tests/test_dmint_v1_deploy.py tests/test_dmint_v1_mint.py tests/test_dmint_end_to_end.py tests/test_dmint_deploy_integration.py $GAPS tests/test_dmint_vector_derivations.py" ;;
    # The value-moving lists are ordered cheapest-first (measured per-file, 2026-08) so `-x`
    # exits soonest on the mutants each file pins; the slow-but-decisive suites close each list.
    fee)         echo "tests/test_capped_fee_source.py tests/cli/test_swap_fee_sizing.py tests/test_htlc_spend_fee_floor.py tests/test_wallet_send_fee_control_offline.py tests/test_glyph_reveal_fees.py tests/test_remaining_builder_relay_fee_floors.py tests/test_swap_and_nft_fee_floors.py tests/test_regtest_relay_floor_declarations.py tests/test_builder_relay_fee_floors.py $GAPS tests/test_wallet_fee_sizing.py" ;;
    # tests/cli/* stay CONTIGUOUS and last. Splitting files from a sub-package across the arg list
    # makes pytest 9.1.1 drop that directory's conftest.py for the later ones — `tests/cli/`'s
    # `runner` fixture goes missing and 32 tests ERROR. Green suite, wrong reason: cosmic-ray reads
    # the non-zero exit as "killed" and would have scored hd/wallet.py 100%.
    #
    # wallet.py and hd/wallet.py are separate groups, not one: their decisive suites are nearly
    # disjoint (test_wallet.py vs test_hd_wallet.py + the BIP44 vectors), so a combined list made
    # every hd/wallet.py mutant pay for the wallet.py tests and vice versa — a 15s clean suite
    # instead of ~8s, on 1 496 mutants. Split, each keeps its coverage (96% / 93%) and the two
    # halves can run on separate runners.
    wallet)      echo "tests/test_wallet.py tests/test_wallet_send_fee_control_offline.py tests/test_wallet_fee_sizing.py $GAPS tests/cli/test_wallet_send.py tests/cli/test_wallet_sweep.py tests/cli/test_wallet_cmds.py" ;;
    hdwallet)    echo "tests/test_keys.py tests/test_hd.py tests/test_hd_descriptor.py tests/test_bip44_conformance_vectors.py tests/test_hd_discovery.py $GAPS tests/test_hd_wallet.py tests/cli/test_wallet_recover.py tests/cli/test_wallet_cmds.py" ;;
    glyph)       echo "tests/test_ft_transfer.py tests/test_ft_airdrop.py tests/test_glyph_ft_red_team.py tests/test_glyph.py tests/test_glyph_transfer.py tests/test_glyph_red_team.py tests/test_mut_container_wave_builders.py tests/test_glyph_reveal_fees.py tests/test_glyph_dmint.py tests/test_glyph_scanner.py $GAPS tests/test_golden_vectors.py" ;;
    # Ordered cheapest-first (measured per file, 2026-08) so `-x` exits soonest. The single
    # tests/cli/ entry is LAST, which is both the cheapest-first answer (1.47s, the most
    # expensive) and the required one: see the contiguity note above — a tests/cli/ file that is
    # not contiguous-and-last loses that directory's conftest and its `runner` fixture.
    #
    # test_glyph_mint_facade.py cost 30.8s until `poll_interval_s` was exposed; two reveal waits
    # slept a 10s default nothing could shorten. At 31s this group was ~11 hours and not worth
    # running. Keep an eye on it: this group's whole viability is that clean-suite number.
    # Cheapest-first matters more here than usual: with `-x`, a killed mutant exits at the first
    # failing file, so the two ~1s files at the end only run for mutants that survived everything
    # cheaper. No tests/cli/ entry, so the contiguity rule does not bite this list.
    glyphscript) echo "tests/test_glyph_dmint.py tests/test_golden_vectors.py tests/test_glyph_red_team.py tests/test_mut_container_wave_builders.py tests/test_glyph.py tests/test_glyph_scanner.py tests/test_glyph_mint_facade.py tests/test_dmint_v1_mint.py" ;;
    mint)        echo "tests/test_glyph_transfer.py tests/test_glyph_nft_transfer.py tests/test_glyph_client_transfer.py tests/test_ft_transfer.py tests/test_ft_airdrop.py tests/test_glyph_mint_facade.py tests/cli/test_glyph_cmds.py" ;;
    swap)        echo "tests/test_htlc_spend_productized.py tests/test_htlc_spend_fee_floor.py tests/test_rswp_orders.py tests/test_rswp_wire.py tests/test_rswp_book.py tests/test_rswp_quoting.py tests/test_rswp_tracker.py tests/test_swap_order.py tests/test_htlc_covenant.py tests/test_rswp_covenant.py $GAPS tests/test_rswp_conformance_vectors.py" ;;
    coordinator) echo "tests/test_swap_coordinator.py tests/test_swap_coordinator_credential_gate.py tests/test_max_protected_value.py tests/test_finality_verdict.py tests/test_taker_asset_funding_gate_adversarial.py tests/test_btc_maker_counter_funding_adversarial.py tests/test_radiant_leg.py tests/test_btc_htlc_leg.py $GAPS tests/test_htlc_handshake_conformance_vectors.py" ;;
    network)     echo "tests/network/test_guards.py tests/network/test_registry.py tests/network/test_bitcoin.py tests/network/test_confirm.py tests/network/test_tls_pin.py tests/network/test_chaintracker.py tests/test_mempool_adapters.py tests/test_endpoint_diversity.py tests/network/test_failover.py tests/test_network_bitcoin.py tests/security/test_hostile_server_responses.py $GAPS tests/network/test_electrumx.py" ;;
    keys)        echo "tests/security/ tests/test_keys.py tests/test_base58.py tests/test_hd_wallet.py tests/test_hd_descriptor.py tests/cli/test_swap_recovery.py tests/cli/test_swap_cmds.py tests/test_watch_secret_and_ack_hardening.py" ;;
  esac
}

# Per-mutant timeout: ~5-8x the group's clean-suite wall time, so a slowed (not hung)
# mutant still gets a fair run while true hangs are bounded. The value-group numbers come from
# the measured clean-suite times recorded in docs/how-to/mutation-testing.md; fee and wallet are
# the slow lists (~9-11s clean) because ECDSA signing dominates them.
group_timeout() {
  case "$1" in
    spv)         echo "30.0" ;;
    script)      echo "30.0" ;;
    fee)         echo "60.0" ;;
    wallet)      echo "60.0" ;;
    hdwallet)    echo "60.0" ;;
    glyph)       echo "30.0" ;;
    mint)        echo "20.0" ;;
    glyphscript) echo "15.0" ;;
    swap)        echo "30.0" ;;
    coordinator) echo "30.0" ;;
    network)     echo "30.0" ;;
    *)           echo "45.0" ;;
  esac
}

# The value-moving groups run with `-m "not integration"`. The test command sets `-o addopts=`,
# which drops this repo's default `-m 'not integration'` filter, so without re-adding it these
# lists would try to reach a regtest node — thousands of times over. The original four groups
# keep their historical command verbatim so their published baselines stay comparable.
# Emits the literal text spliced into the TOML test-command; cosmic-ray shlex-splits it, so the
# single quotes survive to make "not integration" one argument.
group_marker() {
  case "$1" in
    spv|script|transaction|dmint) echo "" ;;
    *) echo "-m 'not integration'" ;;
  esac
}

CONSENSUS_GROUPS="spv script transaction dmint"
VALUE_GROUPS="fee wallet hdwallet glyph mint glyphscript swap coordinator network"

GROUPS_REQUESTED="${*:-spv}"
case "$GROUPS_REQUESTED" in
  all)       GROUPS_REQUESTED="$CONSENSUS_GROUPS $VALUE_GROUPS" ;;
  consensus) GROUPS_REQUESTED="$CONSENSUS_GROUPS" ;;
  value)     GROUPS_REQUESTED="$VALUE_GROUPS" ;;
esac
for g in $GROUPS_REQUESTED; do
  group_files "$g" >/dev/null || {
    echo "unknown group: $g (use $CONSENSUS_GROUPS $VALUE_GROUPS consensus|value|all)"; exit 2; }
done

# Exactly the files the requested groups will mutate. Restoring this list (rather than whole
# directories) is both complete — cosmic-ray only ever rewrites its own module-path — and safer,
# since it cannot discard unrelated work in a neighbouring file.
TARGET_FILES=""
for g in $GROUPS_REQUESTED; do
  for path in $(group_files "$g"); do TARGET_FILES="$TARGET_FILES src/pyrxd/$path.py"; done
done

# --- Preflight ------------------------------------------------------------------------------
# Three ways this run can silently produce a meaningless number, all cheap to rule out first.

# 1. A dirty target file means the "restore" at the end would destroy uncommitted work, and the
#    baseline would not be the committed code. Refuse rather than gamble.
DIRTY="$(git status --porcelain -- $TARGET_FILES 2>/dev/null)"
if [ -n "$DIRTY" ]; then
  echo "ERROR: target sources have uncommitted changes — commit or stash them first." >&2
  echo "$DIRTY" >&2
  echo "(this script restores mutated files with 'git checkout --', which would discard them)" >&2
  exit 1
fi

# 2. The tests must import THIS checkout's src. A shared virtualenv whose editable install points
#    at another clone (a .pth naming a different repo root) would have cosmic-ray mutate files
#    nobody imports: every mutant "survives" and the run reports ~0% killed for healthy code.
#    pytest's own `pythonpath = ["src"]` ini setting normally wins, so this asserts the result
#    under pytest rather than under a bare interpreter.
EXPECTED_SRC="$(cd "$(pwd -P)/src/pyrxd" && pwd -P)"
IMPORTED="$(PYTHONPATH="$(pwd -P)/src" python -c \
            'import pyrxd,os;print(os.path.realpath(os.path.dirname(pyrxd.__file__)))' 2>/dev/null)"
if [ -n "$IMPORTED" ] && [ "$IMPORTED" != "$EXPECTED_SRC" ]; then
  echo "ERROR: 'import pyrxd' resolves to $IMPORTED, not this checkout's $EXPECTED_SRC." >&2
  echo "       cosmic-ray would mutate files the tests never import — every mutant would" >&2
  echo "       'survive' and the score would be meaningless. Fix the environment first." >&2
  exit 1
fi

WORK="${MUTATION_SESSION_DIR:-$(mktemp -d)}"
mkdir -p "$WORK"
REPORT_DIR="${MUTATION_REPORT_DIR:-.mutation-reports}"
mkdir -p "$REPORT_DIR"
cleanup() {
  git checkout -- $TARGET_FILES 2>/dev/null
  [ -z "${MUTATION_SESSION_DIR:-}" ] && rm -rf "$WORK"
}
# EXIT alone is not enough: bash does not run an EXIT trap when it is killed by an *untrapped*
# signal, so a `kill`, a Ctrl-C, or a CI step timeout would leave a half-mutated source file in
# the tree — silently, and looking exactly like a hand edit. Trapping the signals explicitly and
# re-raising with the default disposition restores first and still reports the right exit status.
# (Observed for real: a run killed at ~9 minutes left src/pyrxd/swap/rswp/orders.py mutated.)
trap cleanup EXIT
for sig in INT TERM HUP; do
  # shellcheck disable=SC2064 # $sig must expand now, at trap-installation time
  trap "cleanup; trap - $sig EXIT; kill -s $sig \$\$" "$sig"
done

total=0; killed=0; surv=0; incomplete=0
for g in $GROUPS_REQUESTED; do
  TESTS="$(group_tests "$g")"
  TIMEOUT="$(group_timeout "$g")"
  MARKER="$(group_marker "$g")"
  g_total=0; g_surv=0
  echo "== group: $g =="

  # 3. The group's own test list must be GREEN on unmutated source. cosmic-ray reads a non-zero
  #    exit as "mutant killed", so a red or uncollectable list scores 100% killed on every module
  #    — the most flattering possible number and a complete fiction. Time it too: the clean wall
  #    time is what a surviving mutant costs, and it is the basis for group_timeout above.
  base_t0=$(date +%s)
  # shellcheck disable=SC2086 # TESTS/MARKER are deliberately word-split argument lists
  if ! eval "\"$PYTEST\" $TESTS -q -p no:randomly -p no:cacheprovider -o addopts= --no-cov $MARKER" \
       >"$WORK/baseline-$g.log" 2>&1; then
    echo "ERROR: group '$g' clean-suite baseline is NOT green — every mutant would be scored" >&2
    echo "       'killed' and the result would be meaningless. See $WORK/baseline-$g.log" >&2
    tail -15 "$WORK/baseline-$g.log" >&2
    exit 1
  fi
  base_t1=$(date +%s)
  echo "  (clean-suite baseline green in $((base_t1 - base_t0))s)"

  for path in $(group_files "$g"); do
    name="${path//\//-}"
    cfg="$WORK/cr-$name.toml"; sess="$WORK/$name.sqlite"
    # `cosmic-ray exec` only runs jobs that have no result yet, so an existing session resumes
    # where it stopped. That is opt-in (MUTATION_RESUME=1) rather than automatic because the
    # session's mutation specs were computed from the source as it was at `init` time: resuming
    # across an edit to the module would mix results from two different files under one score.
    # Default is wipe-and-init, which is always correct. Resume is for picking a multi-hour group
    # back up after a timeout or a kill, when the tree has not moved.
    if [ -z "${MUTATION_RESUME:-}" ] || [ ! -s "$sess" ]; then
      rm -f "$sess"
    else
      echo "  (resuming existing session $sess)"
    fi
    cat > "$cfg" <<EOF
[cosmic-ray]
module-path = "src/pyrxd/$path.py"
timeout = $TIMEOUT
excluded-modules = []
test-command = "$PYTEST $TESTS -x -q -p no:randomly -p no:cacheprovider -o addopts= --no-cov $MARKER"

[cosmic-ray.distributor]
name = "local"
EOF
    f_t0=$(date +%s)
    # Skip `init` when the session already exists. cosmic-ray 8.4.6 was observed to leave both the
    # specs and the stored results intact when re-init'd over a populated session, so this is
    # belt-and-braces rather than a fix for a known wipe — but re-deriving specs is exactly the
    # step that would silently renumber them if the module had changed, so don't run it.
    [ -s "$sess" ] || cosmic-ray init "$cfg" "$sess" >/dev/null 2>&1
    cosmic-ray exec "$cfg" "$sess" >/dev/null 2>&1
    git checkout -- "src/pyrxd/$path.py" 2>/dev/null
    f_t1=$(date +%s)
    rep="$(cr-report "$sess" 2>/dev/null)"
    t="$(echo "$rep" | grep -oE 'total jobs: [0-9]+' | grep -oE '[0-9]+')"
    # `complete` is the number of mutants that actually RAN. It is not the same as `total jobs`
    # whenever a run was interrupted — and killed MUST be derived from it. Deriving killed as
    # (total - survived), as this script used to, counts every mutant that never executed as a
    # kill: a sweep stopped at 34% reported "87% killed" instead of the true 64% over the third
    # of the file it had reached. Observed on hd/wallet.py, 411 of 1201 complete.
    c="$(echo "$rep" | grep -oE 'complete: [0-9]+' | grep -oE '[0-9]+' | head -1)"
    s="$(echo "$rep" | grep -oE 'surviving mutants: [0-9]+' | grep -oE '[0-9]+' | head -1)"
    : "${t:=0}"; : "${c:=0}"; : "${s:=0}"
    pct=0; [ "$c" -gt 0 ] && pct=$(( (c - s) * 100 / c ))
    if [ "$c" -lt "$t" ]; then
      printf '  %-28s %4d/%d RAN  %4d killed  %4d survived  (%d%% of those run)  %ds  ** INCOMPLETE **\n' \
        "$path" "$c" "$t" "$((c - s))" "$s" "$pct" "$((f_t1 - f_t0))"
      incomplete=$((incomplete + 1))
    else
      printf '  %-28s %4d mutants  %4d killed  %4d survived  (%d%% killed)  %ds\n' \
        "$path" "$t" "$((c - s))" "$s" "$pct" "$((f_t1 - f_t0))"
    fi
    g_total=$((g_total + c)); g_surv=$((g_surv + s))
  done
  # g_total is the count that RAN, not the count that exists — see the per-file note above.
  gpct=0; [ "$g_total" -gt 0 ] && gpct=$(( (g_total - g_surv) * 100 / g_total ))
  printf '  %-28s %4d ran      %4d killed  %4d survived  (%d%% killed)\n' "[$g total]" "$g_total" "$((g_total - g_surv))" "$g_surv" "$gpct"
  total=$((total + g_total)); killed=$((killed + g_total - g_surv)); surv=$((surv + g_surv))

  # Persist the survivors. A count in a terminal tells the next person nothing actionable; this
  # writes file:line + enclosing definition + the exact source change, ready to triage.
  sessions=""
  for path in $(group_files "$g"); do sessions="$sessions $WORK/${path//\//-}.sqlite"; done
  # shellcheck disable=SC2086 # sessions is a deliberately word-split path list
  python "$(dirname "$0")/mutation_survivors.py" "$REPORT_DIR/survivors-$g.md" $sessions || true
done
# Fail closed on a broken run: zero mutants means cosmic-ray init/exec silently no-op'd (missing tool,
# wrong module path, env breakage) and the redirected stderr hid it — otherwise this would print
# "0% killed" and exit 0, indistinguishable from a healthy run to a CI consumer.
if [ "$total" -eq 0 ]; then
  echo "ERROR: cosmic-ray produced 0 mutants — the run is broken (tool missing, wrong path, or every step no-op'd). Failing." >&2
  exit 1
fi
tpct=$(( killed * 100 / total ))
printf 'TOTAL: %d mutants run, %d killed, %d survived (%d%% killed)\n' "$total" "$killed" "$surv" "$tpct"

# An interrupted sweep is not a baseline. The numbers above are honest about the mutants that ran,
# but they describe a fraction of the file, and cosmic-ray executes jobs grouped by operator rather
# than at random — so the fraction is not a representative sample and the rate cannot be quoted as
# the module's score. Fail, so a CI consumer cannot mistake a truncated run for a passing one;
# MUTATION_RESUME=1 picks the session back up rather than starting over.
if [ "$incomplete" -gt 0 ]; then
  echo "ERROR: $incomplete module(s) did not run to completion — the rates above cover only the" >&2
  echo "       mutants that ran and are NOT the modules' scores. Re-run with MUTATION_RESUME=1" >&2
  echo "       (and MUTATION_SESSION_DIR set) to finish them." >&2
  exit 1
fi

# Opt-in gate: when MUTATION_MIN_KILL_PCT is set, exit non-zero if the total kill rate is below it.
# Unset (the default) => report-only measurement. The score includes known equivalent mutants that
# cannot be killed (see docs/how-to/mutation-testing.md), so pick a threshold below 100.
MIN_KILL="${MUTATION_MIN_KILL_PCT:-}"
if [ -n "$MIN_KILL" ] && [ "$tpct" -lt "$MIN_KILL" ]; then
  echo "FAIL: total kill rate ${tpct}% < threshold ${MIN_KILL}% (MUTATION_MIN_KILL_PCT)" >&2
  exit 1
fi
