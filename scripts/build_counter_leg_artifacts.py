#!/usr/bin/env python3
"""Build the ETH counter-leg contract artifacts from the Solidity source in ``contracts/``.

``tests/fixtures/EthHtlc.json`` and ``tests/fixtures/Erc20Htlc.json`` are what this repo's swap
runners and tests check a taker-deployed contract against, byte for byte. Until this script they
were compiled in another repository and copied in, so nothing here could rebuild them. Now the
source lives in ``contracts/`` and this script is the only way the artifacts are produced:

    python3 scripts/build_counter_leg_artifacts.py           # rebuild and write both artifacts
    python3 scripts/build_counter_leg_artifacts.py --check   # rebuild in memory; exit 1 on ANY difference

The build is meant to reproduce on any linux-amd64 machine, so every input is pinned:

* **The compiler.** The official static ``solc`` binary for :data:`SOLC_VERSION`, downloaded from
  binaries.soliditylang.org and refused unless its sha256 equals :data:`SOLC_SHA256` (the value
  soliditylang publishes for that build in ``linux-amd64/list.json``). The digest is checked on
  every run, cached copy included, before the binary executes. Never ``latest``.
* **The settings.** :data:`SETTINGS`, passed as solc standard JSON. Each artifact records them in
  ``_compiler``, rendered from the same dict, so the description cannot drift from the build.
* **The source unit name.** Each source is compiled alone, under its repo-relative path.
* **No metadata hash.** ``metadata.bytecodeHash`` is ``"none"``: solc otherwise appends an IPFS
  hash of the metadata JSON, which covers the source text (comments included) and the source unit
  name, so a moved file or an edited comment would change the deployed bytes. With ``"none"`` the
  bytes depend only on what the compiler compiles. The trailing CBOR still names the compiler
  version. Nothing in pyrxd reads the metadata hash.

What it writes, per contract, in the shape ``pyrxd.eth_wallet.htlc_leg.load_artifact`` documents:
``abi``, ``bytecode`` (creation code), ``runtime_bytecode``, ``immutableReferences`` (copied from
solc unchanged) and ``immutable_names``. The names are read from the SAME compilation's AST, as
``load_artifact`` prescribes: each ``VariableDeclaration`` whose ``mutability`` is
``"immutable"`` maps its node id to its name, and the build fails unless those ids are exactly the
ids in ``immutableReferences``. ``tests/test_eth_htlc_immutable_names.py`` independently re-derives
the same map from the bytecode and ABI alone.

``--check`` also fails if ``tests/fixtures/`` holds a contract artifact this script does not
build, so a hand-copied artifact cannot sit beside the built ones.

Stdlib only, so CI runs it without installing anything.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
import tempfile
import urllib.request
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"

SOLC_VERSION = "0.8.24+commit.e11b9ed9"
SOLC_URL = f"https://binaries.soliditylang.org/linux-amd64/solc-linux-amd64-v{SOLC_VERSION}"
#: From https://binaries.soliditylang.org/linux-amd64/list.json, entry ``solc-linux-amd64-v0.8.24+commit.e11b9ed9``.
SOLC_SHA256 = "fb03a29a517452b9f12bcf459ef37d0a543765bb3bbc911e70a87d6a37c30d5f"

#: Every setting that affects the output bytes. Rendered verbatim into each artifact's ``_compiler``.
SETTINGS: dict = {
    "evmVersion": "cancun",
    "metadata": {"bytecodeHash": "none"},
    "optimizer": {"enabled": True, "runs": 200},
}

_OUTPUT_SELECTION = {
    "*": {
        "*": [
            "abi",
            "evm.bytecode.object",
            "evm.deployedBytecode.object",
            "evm.deployedBytecode.immutableReferences",
        ],
        "": ["ast"],
    }
}


@dataclass(frozen=True)
class Contract:
    name: str  # the contract's name inside its source
    source: str  # repo-relative path; also the solc source unit name
    artifact: str  # repo-relative output path
    origin: str  # where the source was copied from when it moved into this repo
    origin_blob: str  # the git blob id of the source at that origin
    note: str
    #: What changed since the copy, in words. Recorded in ``_source``; REQUIRED when the blob no
    #: longer matches ``origin_blob`` and refused when it does, so the description cannot go stale.
    changes: str = ""


CONTRACTS: tuple[Contract, ...] = (
    Contract(
        name="EthHtlc",
        source="contracts/EthHtlc.sol",
        artifact="tests/fixtures/EthHtlc.json",
        origin="MudwoodLabs/pyrxd-eth-htlc@726446c4070d2e88e52598fe346f5445f63e116f:contracts/EthHtlc.sol",
        origin_blob="2f8fea4a53857965dc652a24d96349865070e835",
        changes="one comment only: the plan it cites is named by the repo it lives in, not by a path absent here",
        note=(
            "Per-swap deploy model: claim(bytes32 preimage) + immutable hashlock/claimant/refundee/timeout; "
            "Claimed(bytes32 preimage) non-indexed. Test fixture for the Anvil integration proof of the pyrxd EthLeg."
        ),
    ),
    Contract(
        name="Erc20Htlc",
        source="contracts/Erc20Htlc.sol",
        artifact="tests/fixtures/Erc20Htlc.json",
        origin="MudwoodLabs/pyrxd-eth-htlc@7b7d005e9148a8ffd88b1a2e36b0e36450e0e40a:contracts/src/Erc20Htlc.sol",
        origin_blob="a0c9010f0125e5ba9baba4970108a6b20b8405e9",
        note=(
            "Per-swap ERC-20 HTLC. Funded by a plain token transfer to the CREATE address (no allowance is "
            "ever created); claim/refund sweep balanceOf. claim() requires balanceOf >= amount before revealing "
            "the preimage. The Claimed(bytes32) event keeps the preimage NON-INDEXED because pyrxd scrapes the "
            "secret from the log data."
        ),
    ),
)


class BuildError(Exception):
    pass


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _git_blob_id(data: bytes) -> str:
    """What ``git hash-object`` prints for these bytes, so a reader can check ``_source`` with git."""
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()  # git object id, not a security use


def _default_cache() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "pyrxd" / "solc"


def _verified_solc(path: Path) -> Path:
    digest = _sha256(path)
    if digest != SOLC_SHA256:
        raise BuildError(
            f"{path}: sha256 {digest} is not the pinned solc {SOLC_VERSION} ({SOLC_SHA256}); refusing to run it"
        )
    return path


def obtain_solc(explicit: str | None, cache: Path) -> Path:
    """The pinned solc binary, downloaded if needed; its sha256 is checked BEFORE every use."""
    if explicit:
        return _verified_solc(Path(explicit))
    if platform.system() != "Linux" or platform.machine() not in ("x86_64", "AMD64"):
        raise BuildError(
            f"the pinned compiler is the linux-amd64 static build; this is {platform.system()} {platform.machine()}. "
            "Run on linux-amd64 (or in a linux-amd64 container), or pass --solc with that exact binary."
        )
    target = cache / f"solc-linux-amd64-v{SOLC_VERSION}"
    if not target.exists():
        cache.mkdir(parents=True, exist_ok=True)
        print(f"downloading {SOLC_URL}", file=sys.stderr)
        fd, tmp = tempfile.mkstemp(dir=cache, prefix=".solc-download-")
        # The host refuses urllib's default User-Agent with a 403.
        request = urllib.request.Request(SOLC_URL, headers={"User-Agent": "pyrxd-build-counter-leg-artifacts"})
        try:
            try:
                with os.fdopen(fd, "wb") as out, urllib.request.urlopen(request, timeout=120) as resp:  # noqa: S310 - fixed https URL
                    while chunk := resp.read(1 << 20):
                        out.write(chunk)
            except OSError as exc:  # URLError and HTTPError are OSErrors
                raise BuildError(f"could not download {SOLC_URL}: {exc}") from exc
            _verified_solc(Path(tmp))
            os.chmod(tmp, 0o700)  # owner-only executable; its digest was just checked
            os.replace(tmp, target)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
    return _verified_solc(target)


def _immutable_names(ast: dict) -> dict[str, str]:
    found: dict[str, str] = {}

    def walk(node: object) -> None:
        if isinstance(node, dict):
            if node.get("nodeType") == "VariableDeclaration" and node.get("mutability") == "immutable":
                found[str(node["id"])] = node["name"]
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(ast)
    return found


def _source_claim(c: Contract, blob: str) -> str:
    if blob == c.origin_blob:
        if c.changes:
            raise BuildError(f"{c.source} is the origin blob again, but CONTRACTS still describes changes to it")
        return f"{c.source} (git blob {blob}), copied unchanged from {c.origin}"
    if not c.changes:
        raise BuildError(f"{c.source} differs from what was copied from {c.origin}; say what changed in CONTRACTS")
    return (
        f"{c.source} (git blob {blob}), modified since it was copied from {c.origin} "
        f"(git blob {c.origin_blob}); changed: {c.changes}"
    )


def build(c: Contract, solc: Path) -> dict:
    data = (ROOT / c.source).read_bytes()
    request = {
        "language": "Solidity",
        "sources": {c.source: {"content": data.decode("utf-8")}},
        "settings": {**SETTINGS, "outputSelection": _OUTPUT_SELECTION},
    }
    proc = subprocess.run(
        [str(solc), "--standard-json"], input=json.dumps(request), capture_output=True, text=True, check=False
    )
    if proc.returncode != 0:
        raise BuildError(f"{c.source}: solc exited {proc.returncode}: {proc.stderr.strip()}")
    out = json.loads(proc.stdout)
    errors = [e for e in out.get("errors", []) if e.get("severity") == "error"]
    if errors:
        raise BuildError(f"{c.source}: " + "\n".join(e.get("formattedMessage", str(e)) for e in errors))
    for e in out.get("errors", []):
        print(f"{c.source}: solc {e.get('severity')}: {e.get('message')}", file=sys.stderr)
    compiled = out["contracts"][c.source][c.name]
    runtime = compiled["evm"]["deployedBytecode"]["object"]
    creation = compiled["evm"]["bytecode"]["object"]
    if not runtime or not creation:
        raise BuildError(f"{c.source}: solc produced no bytecode for {c.name}")

    refs = compiled["evm"]["deployedBytecode"]["immutableReferences"]
    names = _immutable_names(out["sources"][c.source]["ast"])
    if set(refs) != set(names):
        raise BuildError(
            f"{c.source}: immutable declarations {sorted(names)} are not the ids in immutableReferences "
            f"{sorted(refs)}; the leg's slot-exact compare needs a name for every referenced id"
        )
    code = bytes.fromhex(runtime)
    for rid, slots in refs.items():
        for slot in slots:
            if code[slot["start"] : slot["start"] + slot["length"]] != bytes(slot["length"]):
                raise BuildError(
                    f"{c.source}: immutable {names[rid]} slot at {slot['start']} is not a zero placeholder"
                )

    by_id = sorted(refs, key=int)
    settings = json.dumps(SETTINGS, sort_keys=True, separators=(", ", ": "))
    return {
        "_source": _source_claim(c, _git_blob_id(data)),
        "_compiler": (
            f"solc {SOLC_VERSION} (official static linux-amd64 build, sha256 {SOLC_SHA256}), standard JSON, "
            f"settings {settings}, source unit {c.source}. Built by scripts/build_counter_leg_artifacts.py; "
            "`--check` rebuilds and compares."
        ),
        "_note": c.note,
        "abi": compiled["abi"],
        "bytecode": "0x" + creation,
        "runtime_bytecode": "0x" + runtime,
        "immutableReferences": {rid: refs[rid] for rid in by_id},
        "immutable_names": {rid: names[rid] for rid in by_id},
    }


def render(artifact: dict) -> str:
    return json.dumps(artifact, indent=2) + "\n"


def _unbuilt_fixtures() -> list[str]:
    """Contract artifacts in tests/fixtures/ that no entry in CONTRACTS builds."""
    built = {(ROOT / c.artifact).resolve() for c in CONTRACTS}
    stray = []
    for path in sorted(FIXTURES.glob("*.json")):
        try:
            doc = json.loads(path.read_text())
        except (ValueError, UnicodeDecodeError):
            continue
        if isinstance(doc, dict) and "runtime_bytecode" in doc and path.resolve() not in built:
            stray.append(str(path.relative_to(ROOT)))
    return stray


def _differences(old_text: str, new_text: str) -> list[str]:
    try:
        old = json.loads(old_text)
    except ValueError:
        return ["the committed file is not valid JSON"]
    new = json.loads(new_text)
    keys = sorted(set(old) | set(new))
    diffs = [k for k in keys if old.get(k) != new.get(k)]
    return diffs or ["formatting only (same values, different bytes)"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="rebuild in memory and fail on any difference")
    parser.add_argument("--solc", help=f"use this solc binary (must be the pinned {SOLC_VERSION} build, by sha256)")
    parser.add_argument("--cache-dir", type=Path, default=None, help="where the downloaded solc is kept")
    args = parser.parse_args(argv)

    try:
        solc = obtain_solc(args.solc, args.cache_dir or _default_cache())
        built = [(c, render(build(c, solc))) for c in CONTRACTS]
    except BuildError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if not args.check:
        for c, text in built:
            (ROOT / c.artifact).write_text(text)
            print(f"wrote {c.artifact}")
        return 0

    failed = False
    for c, text in built:
        path = ROOT / c.artifact
        current = path.read_text() if path.exists() else None
        if current == text:
            print(f"ok    {c.artifact} is exactly what {c.source} builds to")
            continue
        failed = True
        what = "is missing" if current is None else "differs in " + ", ".join(_differences(current, text))
        print(f"FAIL  {c.artifact} {what}")
    stray = _unbuilt_fixtures()
    for path in stray:
        failed = True
        print(f"FAIL  {path} is a contract artifact that this script does not build")
    if failed:
        print(
            "\nThe committed artifacts are not what the committed source builds to. If the change is "
            "intended, run this script without --check and update the digest pins in "
            "tests/test_counter_leg_artifact_provenance.py and scripts/swap_run_verify.py in the same commit.",
            file=sys.stderr,
        )
        return 1
    print(f"checked {len(built)} artifacts: all reproduce byte for byte")
    return 0


if __name__ == "__main__":
    sys.exit(main())
