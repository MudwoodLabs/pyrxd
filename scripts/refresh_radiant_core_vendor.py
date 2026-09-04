#!/usr/bin/env python3
"""Refresh the vendored Radiant Core consensus sources used as a test oracle.

``tests/test_consensus_opcode_parity.py`` derives Radiant's opcode table and
ref-operand rules by parsing pinned copies of ``script.h`` and ``script.cpp``
committed under ``tests/vendor/radiant_core/``. Vendoring keeps that test
hermetic and offline (see the README there for why that is the right trade).
The cost is that the pin can go stale — this script is how that is managed.

    # what upstream release are we pinned to, and has upstream moved?
    python scripts/refresh_radiant_core_vendor.py --check      # or: task check-vendor

    # move the pin
    python scripts/refresh_radiant_core_vendor.py --tag v3.2.0

``--check`` answers two questions, not one:

1. have the vendored files changed upstream since the pinned tag?
2. does the pinned tag still share those files with the release the regtest
   image's binary is built from (``pyrxd.devnet.DEFAULT_RADIANT_VERSION``)?

The second matters because the sha256 in ``MANIFEST.json`` proves the vendored
bytes are self-consistent, not that they describe the interpreter the
integration lane actually runs. The two pins move on different schedules and
are allowed to differ — but only while the consensus files are identical
between them.

Both modes need network, which is exactly why neither is a pytest test: a
GitHub outage should fail a job someone chose to run, not turn a pull request
red for an unrelated change. The scheduled owner is the ``vendor-freshness``
job in ``.github/workflows/integration.yml``.

After refreshing, run the parity test. If it now fails, that is the oracle
working — upstream changed a consensus fact and pyrxd has not caught up. Fix
``src/pyrxd/constants.py``; never edit the vendored files.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess  # nosec B404 -- invokes the `gh` CLI; no shell, fixed argv
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = "Radiant-Core/Radiant-Core"
REPO_ROOT = Path(__file__).resolve().parent.parent
VENDOR_DIR = REPO_ROOT / "tests" / "vendor" / "radiant_core"
MANIFEST_PATH = VENDOR_DIR / "MANIFEST.json"
DEVNET_PATH = REPO_ROOT / "src" / "pyrxd" / "devnet.py"

# local filename -> upstream path
FILES = {
    "script.h": "src/script/script.h",
    "script.cpp": "src/script/script.cpp",
    # BIP68 relative-locktime constants (CTxIn::SEQUENCE_LOCKTIME_*) — the
    # definition site for every sequence/CSV constant pyrxd re-spells.
    "primitives_transaction.h": "src/primitives/transaction.h",
    # CheckSequence: the code that consumes those constants, and VerifyScript,
    # which folds STRICTENC in whenever SIGHASH_FORKID is enabled.
    "interpreter.cpp": "src/script/interpreter.cpp",
    # IsValidDERSignatureEncoding + the LOW_S / STRICTENC gates on it.
    "sigencoding.cpp": "src/script/sigencoding.cpp",
    # SCRIPT_VERIFY_* bit definitions.
    "script_flags.h": "src/script/script_flags.h",
    # Which of those flags are MANDATORY (consensus) vs merely STANDARD (policy).
    "policy.h": "src/policy/policy.h",
    # GetNextBlockScriptFlags — the flag set a block is actually connected under,
    # which is the only authority on "consensus vs policy". Also the file where
    # `fRequireStandard = false` is hardcoded, so the policy layer is absent here.
    "validation.cpp": "src/validation.cpp",
    # MAX_SCRIPT_STACK_MEMORY_USAGE and MAX_SCRIPT_OPCODE_COST — the per-script
    # resource budgets `interpreter.cpp` enforces (it references both but declares
    # neither), so without this file their VALUES are uncheckable.
    "consensus.h": "src/consensus/consensus.h",
    # base_blob::Compare / operator< — the comparator behind `std::set<uint288>`,
    # and therefore the ref ordering inside hashOutputHashes. `transaction.h` holds
    # the sets but not the ordering: sorting refs the wrong way made dMint signing
    # fail ~50% of the time, and nothing vendored could adjudicate the rule.
    "uint256.h": "src/uint256.h",
}


def _image_tag() -> str | None:
    """The Radiant-Core release the regtest node image is built from.

    Read out of ``pyrxd.devnet.DEFAULT_RADIANT_VERSION`` by regex rather than by
    importing it, so this script keeps working with no ``pyrxd`` on the path.
    Returns ``None`` if the constant cannot be found, which downgrades the
    image-tag comparison to a warning instead of breaking ``--check``.
    """
    try:
        source = DEVNET_PATH.read_text(encoding="utf-8")
    except OSError:
        return None
    match = re.search(r'^DEFAULT_RADIANT_VERSION\s*=\s*"([^"]+)"', source, re.M)
    return match.group(1) if match else None


def _gh(*args: str) -> str:
    """Run the `gh` CLI and return stdout."""
    try:
        result = subprocess.run(  # nosec B603 -- fixed argv, no shell
            ["gh", *args], capture_output=True, text=True, check=True
        )
    except FileNotFoundError:
        sys.exit("error: the `gh` CLI is required to refresh the vendored sources (https://cli.github.com)")
    except subprocess.CalledProcessError as exc:
        sys.exit(f"error: gh {' '.join(args)} failed:\n{exc.stderr.strip()}")
    return result.stdout


def _resolve_commit(tag: str) -> str:
    """Resolve a tag to a commit sha, dereferencing annotated tags."""
    ref = json.loads(_gh("api", f"repos/{REPO}/git/ref/tags/{tag}"))["object"]
    if ref["type"] == "commit":
        return ref["sha"]
    return json.loads(_gh("api", f"repos/{REPO}/git/tags/{ref['sha']}"))["object"]["sha"]


def _fetch(path: str, ref: str) -> bytes:
    import base64

    content = json.loads(_gh("api", f"repos/{REPO}/contents/{path}?ref={ref}"))["content"]
    return base64.b64decode(content)


def _latest_tag() -> str:
    tags = json.loads(_gh("api", f"repos/{REPO}/tags"))
    if not tags:
        sys.exit(f"error: {REPO} reported no tags")
    return tags[0]["name"]


def _load_manifest() -> dict:
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def check() -> int:
    manifest = _load_manifest()
    pinned_tag = manifest["tag"]
    latest = _latest_tag()
    image_tag = _image_tag()

    print(f"pinned : {pinned_tag} ({manifest['commit'][:12]})")
    print(f"latest : {latest}")
    print(f"image  : {image_tag or '(DEFAULT_RADIANT_VERSION not found in src/pyrxd/devnet.py)'}")

    drift = 0
    for name, upstream_path in FILES.items():
        local = (VENDOR_DIR / name).read_bytes()
        recorded = manifest["files"][name]["sha256"]
        actual = hashlib.sha256(local).hexdigest()
        if actual != recorded:
            print(f"  ! {name}: local bytes do NOT match MANIFEST.json (hand-edited?)")
            drift = 1
            continue
        remote = _fetch(upstream_path, latest)
        if hashlib.sha256(remote).hexdigest() != actual:
            print(f"  ! {name}: changed upstream between {pinned_tag} and {latest}")
            drift = 1
        else:
            print(f"  = {name}: unchanged upstream at {latest}")

    # The sha256 in MANIFEST.json proves the vendored bytes are SELF-CONSISTENT — that
    # nobody hand-edited the oracle. It does not prove they describe the node the
    # regtest lane actually runs, which is built from `DEFAULT_RADIANT_VERSION`. Those
    # two tags are allowed to differ (the source pin tracks upstream releases; the image
    # pin is bumped deliberately, with revalidation) — but only while the CONSENSUS
    # FILES are identical between them. If they ever diverge, every parity assertion is
    # describing a different interpreter than the one the integration lane asks.
    if image_tag and image_tag != pinned_tag:
        for name, upstream_path in FILES.items():
            recorded = manifest["files"][name]["sha256"]
            at_image = hashlib.sha256(_fetch(upstream_path, image_tag)).hexdigest()
            if at_image != recorded:
                print(
                    f"  ! {name}: the pin ({pinned_tag}) and the regtest image "
                    f"({image_tag}) do NOT share this file — the opcode/ref oracle "
                    "describes a different interpreter than the lane runs"
                )
                drift = 1
            else:
                print(f"  = {name}: identical at the regtest image tag {image_tag}")

    if drift:
        print(f"\nUpstream moved. Refresh with:\n  python {Path(__file__).name} --tag {latest}")
    else:
        print("\nVendored consensus sources are current.")
    return drift


def refresh(tag: str) -> int:
    commit = _resolve_commit(tag)
    print(f"pinning {REPO} @ {tag} ({commit[:12]})")

    files: dict[str, dict] = {}
    changed = []
    for name, upstream_path in FILES.items():
        data = _fetch(upstream_path, commit)
        target = VENDOR_DIR / name
        if not target.exists() or target.read_bytes() != data:
            changed.append(name)
        target.write_bytes(data)
        files[name] = {"upstream_path": upstream_path, "sha256": hashlib.sha256(data).hexdigest()}
        print(f"  {name}: {len(data)} bytes, sha256 {files[name]['sha256'][:16]}…")

    manifest = _load_manifest()
    manifest.update(
        {
            "tag": tag,
            "commit": commit,
            "fetched_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "files": files,
        }
    )
    MANIFEST_PATH.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    if changed:
        print(f"\nCONTENT CHANGED: {', '.join(changed)}")
        print("Review the diff, then run:\n  .venv/bin/pytest tests/test_consensus_opcode_parity.py")
        print("A failure there means a consensus fact moved and pyrxd must be updated to match.")
    else:
        print("\nFile contents unchanged; only the pin metadata moved.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--check", action="store_true", help="report whether upstream has moved (exit 1 if so)")
    group.add_argument("--tag", metavar="TAG", help="re-vendor from this upstream tag, e.g. v3.2.0")
    args = parser.parse_args()
    return check() if args.check else refresh(args.tag)


if __name__ == "__main__":
    raise SystemExit(main())
