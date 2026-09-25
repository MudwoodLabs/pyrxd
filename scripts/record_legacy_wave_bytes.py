#!/usr/bin/env python3
"""Record the WAVE claim bytes every released ``build_wave_metadata`` produced.

pyrxd v0.6.0 to v0.24.0 built WAVE claims with the qualified name in ``attrs.name``, a shape
the indexer does not register (#728). A commit made with one of those releases can only be
spent by revealing exactly the CBOR it committed to, and the current ``build_wave_metadata``
no longer produces it. ``GlyphBuilder.prepare_wave_reveal`` documents a recipe that rebuilds
those bytes; this script records what the releases themselves produced, so a test can hold the
recipe to them rather than to a hand-typed expectation.

It extracts each tagged release that ships ``src/pyrxd/glyph/wave.py`` with ``git archive``,
runs that release's own ``build_wave_metadata`` and ``encode_payload`` in a fresh interpreter
with only that tree on ``sys.path``, and writes ``tests/fixtures/wave_build_metadata_v0_6_to_v0_24.json``.
Nothing here decides anything: a case where releases disagree is recorded per release.

Run from the repository root: ``python scripts/record_legacy_wave_bytes.py``.
"""

from __future__ import annotations

import io
import json
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "tests/fixtures/wave_build_metadata_v0_6_to_v0_24.json"
LAST = "v0.24.0"
ADDR = "1CPfirXZahPrTb93QouwBfKDoz1ykfcBb7"
CASES = {
    "plain": {"qualified_name": "alice.rxd", "target": ADDR},
    "description": {"qualified_name": "alice.rxd", "target": ADDR, "description": "my name"},
    "no-dot": {"qualified_name": "alice", "target": ADDR},
    "multi-dot": {"qualified_name": "pay.alice.rxd", "target": ADDR},
    "non-ascii": {"qualified_name": "トークン.rxd", "target": ADDR},
    "target-type": {"qualified_name": "custodian-gate-x7f3.rxd", "target": ADDR, "target_type": "cross_chain"},
}

#: Runs inside the release's own tree. Imports ONLY from sys.path[0], and says where it did.
_INNER = """
import json, sys
sys.path.insert(0, sys.argv[1])
import pyrxd
from pyrxd.glyph.payload import encode_payload
from pyrxd.glyph.wave import build_wave_metadata
cases = json.loads(sys.argv[2])
out = {}
for cid, kw in cases.items():
    out[cid] = encode_payload(build_wave_metadata(**kw))[0].hex()
print(json.dumps({"imported_from": pyrxd.__file__, "cbor_hex": out}))
"""


def _git(*args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, check=False)


def main() -> int:
    tags = _git("tag", "-l", "v0.*", "--sort=v:refname").stdout.decode().split()
    shipping = [t for t in tags if _git("cat-file", "-e", f"{t}:src/pyrxd/glyph/wave.py").returncode == 0]
    if LAST not in shipping:
        print(f"{LAST} not found among tags — refusing to write a partial record", file=sys.stderr)
        return 2
    shipping = shipping[: shipping.index(LAST) + 1]
    per_release: dict[str, dict[str, str]] = {}
    with tempfile.TemporaryDirectory() as tmp:
        for tag in shipping:
            dest = Path(tmp) / tag
            archive = _git("archive", tag, "src/pyrxd")
            archive.check_returncode()
            with tarfile.open(fileobj=io.BytesIO(archive.stdout)) as tf:
                tf.extractall(dest, filter="data")
            run = subprocess.run(
                [sys.executable, "-c", _INNER, str(dest / "src"), json.dumps(CASES)],
                capture_output=True,
                text=True,
                check=False,
            )
            if run.returncode != 0:
                print(f"{tag}: {run.stderr.strip()}", file=sys.stderr)
                return 2
            result = json.loads(run.stdout)
            if not result["imported_from"].startswith(str(dest)):
                print(f"{tag}: imported pyrxd from {result['imported_from']}, not the release", file=sys.stderr)
                return 2
            per_release[tag] = result["cbor_hex"]
    agreed = {cid: {r[cid] for r in per_release.values()} for cid in CASES}
    record = {
        "_comment": [
            "What build_wave_metadata + encode_payload produced in every tagged pyrxd release that",
            "shipped them, run from each release's own source. Regenerate with",
            "python scripts/record_legacy_wave_bytes.py; do not hand-edit.",
        ],
        "releases": shipping,
        "cases": CASES,
        "cbor_hex": {cid: next(iter(v)) for cid, v in agreed.items() if len(v) == 1},
        "disagreements": {cid: {t: r[cid] for t, r in per_release.items()} for cid, v in agreed.items() if len(v) > 1},
    }
    OUT.write_text(json.dumps(record, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"recorded {len(CASES)} cases across {len(shipping)} releases; disagreements: {len(record['disagreements'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
