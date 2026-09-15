"""Derive each mutation group's test list from COVERAGE, not from filenames.

Three rounds of wrong numbers came from name-based derivation:
  1. a frequency cap dropped 27 modules' own dedicated tests;
  2. substring pairing matched `btc_wallet/validate` to `test_margin_policy_validateS_...`;
  3. and the one it structurally cannot fix — `_sign_custom_k`'s real test lives in
     `tests/test_coverage_gaps2.py`, whose name relates to nothing.

Coverage contexts are ground truth: coverage.py records which TEST executed which line, so
"which tests exercise this module" stops being a guess. Ranking by lines-covered also puts the
tests that exercise a module MOST at the top, which is what a capped list should keep.
"""

from __future__ import annotations

import ast
import json
import re
import sqlite3
import sys
from collections import defaultdict
from pathlib import Path

DB = sys.argv[1]
ROOT = Path(sys.argv[2])
CAP = int(sys.argv[3]) if len(sys.argv) > 3 else 14

db = sqlite3.connect(DB)
files = {fid: path for fid, path in db.execute("select id, path from file")}
ctxs = {cid: c for cid, c in db.execute("select id, context from context")}

# module -> {test file: lines covered}
weight: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
# ARC, not line_bits: this project runs branch coverage, so coverage.py stores (from, to) arcs
# and leaves line_bits empty. Counting DISTINCT destination lines per (module, test) gives the
# same "how much of this module does this test actually execute" signal.
rows = db.execute("select file_id, context_id, count(distinct tono) from arc group by file_id, context_id")
for fid, cid, n in rows:
    path, ctx = files.get(fid, ""), ctxs.get(cid, "")
    if "/src/pyrxd/" not in path.replace("\\", "/") or not ctx:
        continue
    test_file = ctx.split("::")[0]
    if not test_file.startswith("tests/"):
        continue
    mod = path.replace("\\", "/").split("/src/pyrxd/")[1][: -len(".py")]
    weight[mod][test_file] += n

# group -> modules, from the script that actually runs them
#
# `[a-z0-9_]+`, not `[a-z]+`: a group named with a digit or underscore (`spv2`, `eth_leg`) would
# be invisible to this parser while matching every other one — tests/test_mutation_groups_are_
# wired.py's `_script_groups()` parses the same case statement and MUST use the identical
# character class (a guard there asserts the two agree), or the derivation and the guard written
# to catch its own gaps would share the one blind spot neither could see.
script = (ROOT / "scripts" / "mutation_test.sh").read_text()
groups: dict[str, list[str]] = {}
for line in script.split("\n"):
    m = re.match(r'\s*([a-z0-9_]+)\)\s+echo "([^"]*)" ;;', line)
    if not m:
        continue
    items = m.group(2).split()
    if not items or items[0].startswith("tests/") or all(re.fullmatch(r"[\d.]+", i) for i in items):
        continue
    groups[m.group(1)] = items


# A THIRD SIGNAL, because the other two provably cannot see this one.
#
# `tests/test_sign_custom_k_emits_strict_der.py` killed 117 mutants in `keys._sign_custom_k`
# (41% -> 56% reported for the module) and NEITHER existing signal finds it:
#
#   * name-pairing looks for `tests/test_keys.py`; this test is named after a FUNCTION.
#   * coverage ranks it 60th of 97 by arcs, 48th of 77 among tests that import `keys`, and it
#     has ZERO exclusive arcs — every line it touches, something else already touched.
#
# That is not a tuning problem. `test_coverage_gaps2.py` already EXECUTED `sign(k=...)`; it
# simply asserted determinism, which every mutant satisfies. The two tests run the same lines
# and differ only in what they CHECK, and coverage cannot observe assertions. No ranking over
# execution data can separate them, so a test whose value is its assertions must say so itself.
#
# Declared in the test file, not in a list here: the declaration lives beside the thing it
# describes, so it cannot rot in a central registry nobody reads. `tests/test_mutation_groups_
# are_wired.py` asserts every declared target names a module that exists.
def declared_targets(test_path: Path) -> set[str]:
    """Modules a test declares it targets, via a module-level ``MUTATION_TARGETS`` list."""
    try:
        tree = ast.parse(test_path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError):  # pragma: no cover - unreadable test file
        return set()
    for node in tree.body:  # module level only; a nested one is not a declaration
        if not isinstance(node, ast.Assign):
            continue
        if not any(isinstance(t, ast.Name) and t.id == "MUTATION_TARGETS" for t in node.targets):
            continue
        if isinstance(node.value, (ast.List, ast.Tuple, ast.Set)):
            return {e.value for e in node.value.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)}
    return set()


# module -> tests that DECLARE it, scanned once
declared: dict[str, list[str]] = defaultdict(list)
for tf in sorted((ROOT / "tests").rglob("test_*.py")):
    rel = tf.relative_to(ROOT).as_posix()
    for mod in declared_targets(tf):
        declared[mod].append(rel)

out = {}
for g, mods in groups.items():
    # Union the per-module rankings so a group's list covers EVERY module, not just the loudest.
    per_mod_top, pooled = [], defaultdict(int)
    for mod in mods:
        ranked = sorted(weight.get(mod, {}).items(), key=lambda kv: -kv[1])
        # TOP THREE per module, not top one. Taking a single test dropped
        # `tests/test_ripemd160_fallback.py` for `hash.py`: it reaches 61 distinct lines and is
        # the ONLY test that forces the pure-Python RIPEMD160 path (it monkeypatches
        # `hashlib.new` to raise), and it lost to `test_consensus_parser_strictness.py` at 69.
        # `hash` then scored 0% across 1,400 mutants: where OpenSSL provides ripemd160 the
        # fallback never executes, and mutating unexecuted code always survives. Third time a
        # cap on a derived list silently removed the load-bearing entry.
        per_mod_top.extend(t for t, _ in ranked[:3])
        for t, n in ranked:
            pooled[t] += n
    # BOTH SIGNALS, because each misses what the other catches.
    #
    # Coverage measures EXECUTION, not ASSERTION. A broad test that runs 56 lines of a module
    # while asserting on none of them kills no mutants; a tight unit test that runs 20 lines with
    # sharp assertions kills many. Ranking purely by coverage dropped `test_aes_cbc.py`,
    # `test_crypto_aead.py` and `test_curve.py` — the very tests that produced this group's only
    # trustworthy scores (91%, 82%, 64%).
    #
    # Name-pairing alone was worse: it cannot find `test_coverage_gaps2.py`, which holds the only
    # real test for `keys._sign_custom_k` and is named after nothing.
    #
    # So: the dedicated test by name (tight assertions) AND the top covering tests (real reach).
    chosen, seen = [], set()

    def take(t, _chosen=chosen, _seen=seen):
        if t and t not in _seen and (ROOT / t).exists():
            _chosen.append(t)
            _seen.add(t)

    for mod in mods:
        parts = mod.split("/")
        leaf = parts[-1]
        cands = (
            {f"tests/test_{leaf}.py"}
            if len(parts) == 1
            else {
                f"tests/test_{'_'.join(parts[:-1])}_{leaf}.py",
                f"tests/{'/'.join(parts[:-1])}/test_{leaf}.py",
                f"tests/test_{parts[-2]}_{leaf}.py",
            }
        )
        for c in sorted(cands):
            take(c)
        # Declared targets are unconditional: they exist precisely because ranking misses them.
        for c in declared.get(mod, []):
            take(c)
    for t in per_mod_top:
        take(t)
    for t, _ in sorted(pooled.items(), key=lambda kv: -kv[1]):
        if len(chosen) >= CAP:
            break
        if t not in seen and (ROOT / t).exists() and not re.search(r"regtest|_e2e|xchain", t):
            chosen.append(t)
            seen.add(t)
    # THREE REASONS A MODULE HAS NO COVERING TEST, and only one is a defect. Reporting them as
    # one bucket produced a false finding against an established group: `eth_wallet/keys`,
    # `locator` and `private_submit` looked untested and are simply on coverage's `omit` list —
    # deliberately, with a written rationale, and measured at 88%/71% when it is lifted. And
    # `gravity/counter_chain_leg` is an abstract base class: 44 arcs, every one at import time,
    # nothing to execute because its methods are abstract.
    omitted_paths = set()
    try:
        import tomllib

        cfg = tomllib.loads((ROOT / "pyproject.toml").read_text())
        omitted_paths = {
            o.replace("src/pyrxd/", "")[: -len(".py")]
            for o in cfg.get("tool", {}).get("coverage", {}).get("run", {}).get("omit", [])
        }
    except Exception:  # pragma: no cover - config absent or unreadable
        pass

    omitted = [m for m in mods if m in omitted_paths]
    import_only = [
        m
        for m in mods
        if m not in omitted_paths and not weight.get(m) and (ROOT / "src" / "pyrxd" / f"{m}.py").exists()
    ]
    out[g] = {
        "tests": chosen,
        "omitted_from_coverage": omitted,  # tested; excluded from the gate on purpose
        "no_test_executes_it": import_only,  # the only bucket worth investigating
    }

print(json.dumps(out, indent=1))
