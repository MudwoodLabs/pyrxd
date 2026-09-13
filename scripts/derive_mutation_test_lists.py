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
script = (ROOT / "scripts" / "mutation_test.sh").read_text()
groups: dict[str, list[str]] = {}
for line in script.split("\n"):
    m = re.match(r'\s*([a-z]+)\)\s+echo "([^"]*)" ;;', line)
    if not m:
        continue
    items = m.group(2).split()
    if not items or items[0].startswith("tests/") or all(re.fullmatch(r"[\d.]+", i) for i in items):
        continue
    groups[m.group(1)] = items

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
