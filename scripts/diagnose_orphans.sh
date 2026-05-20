#!/usr/bin/env bash
#
# Diagnose orphaned Python multiprocessing workers from this repo's .venv.
#
# Symptom: load average jumps; `ps` shows many
#     <repo>/.venv/bin/python3 -c from multiprocessing.spawn ...
# processes pegging cores, all reparented to PID 1 or `systemd --user`
# because their original pytest/script parent already died.
#
# This script does NOT kill anything. It snapshots enough state to
# identify *which* code spawned them so the spawn site can be fixed.
#
# Usage:
#     scripts/diagnose_orphans.sh                 # prints diagnosis to stdout
#     scripts/diagnose_orphans.sh > orphans.txt   # save for later
#
# Optional: install py-spy in the venv for Python stack traces:
#     .venv/bin/pip install py-spy
# (sudo may be needed for py-spy dump on Linux with ptrace_scope=1)
#
# What it shows per worker:
#   - PID, PPID, %CPU, elapsed time
#   - Working directory (/proc/<pid>/cwd) — identifies the source worktree
#   - Full cmdline — confirms multiprocessing.spawn vs. other entry points
#   - Open files relevant to pytest / tmp_path
#   - Python stack (only if py-spy is installed)

set -uo pipefail

# Resolve the repo root from this script's location so the diagnostic
# works in any clone or worktree without hardcoded paths.
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
venv_python="$repo_root/.venv/bin/python3"

if [[ ! -x "$venv_python" ]]; then
    echo "No venv python at: $venv_python" >&2
    echo "Run from a checkout with a .venv/, or adjust venv_python." >&2
    exit 2
fi

# Match the exact spawn pattern we keep seeing. Adjust if the orphan
# signature changes.
pattern="${venv_python} -c from multiprocessing"

pids=$(pgrep -f "$pattern" || true)

if [[ -z "$pids" ]]; then
    echo "No orphan workers matching: $pattern"
    exit 0
fi

# py-spy is optional. Detect once.
pyspy=""
if command -v py-spy >/dev/null 2>&1; then
    pyspy="py-spy"
elif [[ -x "$repo_root/.venv/bin/py-spy" ]]; then
    pyspy="$repo_root/.venv/bin/py-spy"
fi

count=$(echo "$pids" | wc -l)
echo "Found $count orphan worker(s) matching multiprocessing.spawn pattern."
echo "Snapshot time: $(date -Iseconds)"
echo "Host: $(hostname)  load: $(uptime | awk -F'load average: ' '{print $2}')"
echo

for pid in $pids; do
    echo "============================================================"
    echo "PID $pid"
    echo "============================================================"

    # Process metadata
    ps -p "$pid" -o pid,ppid,pgid,sid,user,stat,pcpu,pmem,etime,start_time,cmd 2>&1 | sed 's/^/  /'

    # The parent — usually 1 (systemd) or a `systemd --user` PID. If it's
    # something else, that *is* the leak source.
    ppid=$(ps -p "$pid" -o ppid= 2>/dev/null | tr -d ' ')
    if [[ -n "$ppid" && "$ppid" != "0" ]]; then
        echo "  Parent ($ppid):"
        ps -p "$ppid" -o pid,user,stat,etime,cmd 2>/dev/null | sed 's/^/    /'
    fi

    # Working directory — biggest clue. Tells us which worktree/branch
    # the spawning code lived in.
    cwd_link=$(readlink "/proc/$pid/cwd" 2>/dev/null || echo "<unreadable>")
    echo "  cwd: $cwd_link"

    # Original exe path
    exe_link=$(readlink "/proc/$pid/exe" 2>/dev/null || echo "<unreadable>")
    echo "  exe: $exe_link"

    # Full cmdline (NULs to spaces) — confirms spawn args
    cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null || echo "<unreadable>")
    echo "  cmdline: $cmdline"

    # Open files restricted to pytest tmp dirs and the repo — keeps the
    # output focused, avoids dumping every shared library.
    repo_basename="$(basename "$repo_root")"
    echo "  Relevant open files:"
    ls -l "/proc/$pid/fd" 2>/dev/null \
        | awk '{ for (i=9; i<=NF; i++) printf "%s ", $i; print "" }' \
        | grep -E "/tmp/pytest|$repo_basename|/proc/[0-9]+/" \
        | grep -v ' /proc/' \
        | sed 's/^/    /' \
        || echo "    (none)"

    # Python stack — only useful if py-spy is installed and ptrace is allowed.
    if [[ -n "$pyspy" ]]; then
        echo "  Python stack (py-spy dump):"
        "$pyspy" dump --pid "$pid" 2>&1 | sed 's/^/    /' | head -40
    else
        echo "  Python stack: (install py-spy for stack traces — see header)"
    fi
    echo
done

echo "============================================================"
echo "Next steps:"
echo "  - 'cwd' values point at the worktree of the spawning code."
echo "  - If py-spy stacks show, the top frames identify the test/script."
echo "  - To kill all matched orphans without diagnosing further:"
echo "      pkill -f '$pattern'"
