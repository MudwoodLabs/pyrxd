"""Reachability, mechanized: a capability nothing in shipped code invokes is not finished.

The single most repeated defect class in this project's history is a symbol that was written,
tested, and merged while NOTHING in production ever called it — the tests passed because they
called it directly. Live examples from this very corridor: `eth_absolute_to_rxd_relative_blocks`
was correct, documented, exported in its module's `__all__`, and UNCALLED for the life of the
corridor while a runner used a hand-typed default; `--eth-key-file` existed on one runner with
zero users while every document still showed `--eth-key-hex`. The engineering rule ("grep for
callers in the shipped source, excluding the definition and the tests") lives in prose that is
read once and not applied at fix time; these scans apply it on every CI run.

Shape stolen deliberately from `test_preimage_survives_pre_broadcast_failure.py::
test_the_marker_is_not_raised_anywhere_outside_the_legs`: scan EVERYTHING under the shipped
trees for a predicate, allowlist the legitimate exceptions, and make every allowlist entry carry
its reason. Two ratchets keep the allowlist honest: a NEW unreachable symbol fails (wire it or
allowlist it with a reason), and a STALE entry — one whose symbol has since gained a caller or
disappeared — also fails (remove it), so the list can only shrink toward the truth.

Everything here is checked against the AST, never the text. Text scans on this codebase have
been defeated by comments and line wrapping, and have false-alarmed on docstrings — an AST
`Name`/`Attribute` node cannot come from either.

KNOWN, ACCEPTED MISSES (precision over recall — a guard that refuses honest work is itself a
defect, so each of these errs toward NOT firing):
  * Name collisions: references are matched by bare name, so if two modules define the same
    public name and only one is called, the other is presumed reachable.
  * A recursive function referenced only by itself counts as reachable.
  * An identifier-shaped string constant anywhere in shipped code counts as a reference
    (registries and lazy-dispatch tables name their targets as strings; the cost is that an
    error message naming a symbol also shields it).
  * A symbol re-exported by any `__init__.py`, or listed in the top-level `_LAZY_EXPORTS`
    map, is consumer API surface by this repo's own convention and needs no internal caller.
  * A top-level def/class whose decorator is an attribute (or attribute call) is treated as
    registered by that decorator at import time (click's `group.command(...)` is the shipped
    caller of every CLI handler). Bare-name decorators (`@dataclass`) do not exempt.
"""

from __future__ import annotations

import ast
from functools import lru_cache
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_SRC = _ROOT / "src" / "pyrxd"
_SCRIPTS = _ROOT / "scripts"


# ---------------------------------------------------------------------------
# The allowlist. Keyed by "relative/module/path.py::symbol" so a NEW symbol reusing an
# allowlisted name elsewhere cannot hide under an old entry. EVERY entry carries its reason;
# an entry whose symbol gains a shipped caller must be REMOVED (the stale-entry test enforces it).
# ---------------------------------------------------------------------------
_KNOWN_UNREACHED: dict[str, str] = {
    # -- deprecated back-compat aliases: kept importable for external consumers through their
    #    deprecation window; an internal caller would itself be a defect.
    "src/pyrxd/glyph/builder.py::DmintDeployResult": "deprecated alias of DmintV2DeployResult",
    "src/pyrxd/glyph/builder.py::DmintFullDeployParams": "deprecated alias of DmintV2DeployParams",
    # -- external-caller protocol: the contrib miner BINARY (out of repo) speaks this protocol;
    #    in-repo callers are not expected.
    "src/pyrxd/contrib/miner/protocol.py::parse_progress_line": "caller is the external contrib miner",
    "src/pyrxd/contrib/miner/protocol.py::parse_response": "caller is the external contrib miner",
    # -- long-standing public SDK utility surface (this is a published library): low-level
    #    primitives kept for library consumers, not re-exported at package top level. PRE-EXISTING
    #    when this scan landed (2026-08-27); wiring or a deliberate __init__ export removes the
    #    entry. They are grouped rather than silently exempted so the list is visible and shrinks.
    "src/pyrxd/base58.py::from_base58check": "PRE-EXISTING utility surface, test-only callers",
    "src/pyrxd/base58.py::to_base58check": "PRE-EXISTING utility surface, test-only callers",
    "src/pyrxd/curve.py::curve_get_y": "PRE-EXISTING utility surface, test-only callers",
    "src/pyrxd/hash.py::hmac_sha512": "PRE-EXISTING utility surface, test-only callers",
    "src/pyrxd/keys.py::verify_signed_text": "PRE-EXISTING utility surface, test-only callers",
    "src/pyrxd/script/type.py::RPuzzle": "PRE-EXISTING script template, docstring-referenced only",
    "src/pyrxd/transaction/transaction_preimage.py::tx_preimages": "PRE-EXISTING utility surface",
    "src/pyrxd/utils.py::deserialize_ecdsa_der": "PRE-EXISTING utility surface, test-only callers",
    "src/pyrxd/utils.py::from_base58_check": "PRE-EXISTING utility surface, test-only callers",
    "src/pyrxd/utils.py::randbytes": "PRE-EXISTING utility surface, test-only callers",
    "src/pyrxd/utils.py::serialize_ecdsa_recoverable": "PRE-EXISTING utility surface, test-only callers",
    "src/pyrxd/utils.py::to_base58_check": "PRE-EXISTING utility surface, test-only callers",
    "src/pyrxd/utils.py::to_base64": "PRE-EXISTING utility surface, test-only callers",
    # -- flagged and REPORTED as findings when this scan landed (2026-08-27). Each is a shipped
    #    capability whose only callers are tests — the exact defect class this file exists to
    #    catch, found already present. They are allowlisted so the scan can land green, and left
    #    here deliberately loud; wiring them (or deleting them) removes the entry.
    "src/pyrxd/cli/errors.py::is_debug": "FINDING 2026-08-27: no shipped caller — wire or remove",
    "src/pyrxd/cli/errors.py::render_error": "FINDING 2026-08-27: no shipped caller — wire or remove",
    "src/pyrxd/glyph/script.py::is_commit_script": "FINDING 2026-08-27: test-only callers — wire or remove",
    "src/pyrxd/glyph/script.py::is_dmint_contract_script": "FINDING 2026-08-27: test-only callers — wire or remove",
    "src/pyrxd/eth_wallet/tokens.py::token_by_address": (
        "FINDING 2026-08-27: new in feat/erc20-usdc-leg with test-only callers — wire or remove"
    ),
}


@lru_cache(maxsize=1)
def _shipped_trees() -> tuple[tuple[Path, ast.Module], ...]:
    """Parse every shipped module once: src/pyrxd/**/*.py plus the top-level scripts/*.py."""
    files = sorted(_SRC.rglob("*.py")) + sorted(_SCRIPTS.glob("*.py"))
    return tuple((p, ast.parse(p.read_text(), filename=str(p))) for p in files)


def _has_registering_decorator(node: ast.stmt) -> bool:
    """True when a decorator plausibly REGISTERS the object somewhere at import time.

    `@wallet_group.command("new")` hands the function to click's command table — that IS the
    shipped caller of every CLI handler. Restricted to attribute(-call) decorators so bare
    wrappers (`@dataclass`, `@lru_cache`) do not exempt anything: they transform the object but
    register it nowhere, and the transformed object still needs a caller.
    """
    for d in getattr(node, "decorator_list", []):
        if isinstance(d, ast.Attribute):
            return True
        if isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute):
            return True
    return False


@lru_cache(maxsize=1)
def _referenced_names() -> frozenset[str]:
    """Every name shipped code refers to: loads/calls, attribute access, imports, and
    identifier-shaped string constants (registries name their targets as strings)."""
    names: set[str] = set()
    for _p, tree in _shipped_trees():
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                names.add(node.id)
            elif isinstance(node, ast.Attribute):
                names.add(node.attr)
            elif isinstance(node, ast.ImportFrom):
                names.update(a.name for a in node.names)
            elif isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value.isidentifier():
                names.add(node.value)
    return frozenset(names)


@lru_cache(maxsize=1)
def _consumer_surface() -> frozenset[str]:
    """Names this repo itself declares to be consumer API: anything an `__init__.py` re-exports,
    plus the keys of the top-level `_LAZY_EXPORTS` map (the curated `pyrxd` namespace)."""
    names: set[str] = set()
    for p, tree in _shipped_trees():
        if p.name != "__init__.py":
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                names.update(a.asname or a.name for a in node.names)
            elif isinstance(node, ast.Assign):
                for t in node.targets:
                    if isinstance(t, ast.Name) and t.id == "_LAZY_EXPORTS" and isinstance(node.value, ast.Dict):
                        names.update(
                            k.value for k in node.value.keys if isinstance(k, ast.Constant) and isinstance(k.value, str)
                        )
    return frozenset(names)


def _unreached_public_symbols() -> dict[str, str]:
    """Every public top-level def/class under src/pyrxd with NO shipped reference anywhere,
    keyed like the allowlist. The definition itself produces no Name node, so a symbol that is
    merely defined — however well tested — does not count as its own caller."""
    referenced = _referenced_names()
    consumer = _consumer_surface()
    out: dict[str, str] = {}
    for p, tree in _shipped_trees():
        if p.name == "__init__.py" or _SCRIPTS in p.parents:
            continue
        for node in tree.body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            if node.name.startswith("_") or node.name in referenced or node.name in consumer:
                continue
            if _has_registering_decorator(node):
                continue
            out[f"{p.relative_to(_ROOT).as_posix()}::{node.name}"] = node.name
    return out


class TestEveryPublicSymbolHasAShippedCaller:
    def test_no_public_symbol_is_unreachable_from_shipped_code(self) -> None:
        offenders = {k for k in _unreached_public_symbols() if k not in _KNOWN_UNREACHED}
        assert not offenders, (
            "these public symbols have NO caller anywhere in src/ or scripts/ — a capability "
            "only tests invoke is not finished:\n  "
            + "\n  ".join(sorted(offenders))
            + "\nFor each: wire the production caller it was written for (and make at least one "
            "test reach it through that entry point), export it deliberately via an __init__ / "
            "_LAZY_EXPORTS if it is consumer API, or delete it. Allowlisting it here (with a "
            "reason) is the LAST resort, for capabilities whose caller is genuinely out of repo."
        )

    def test_the_allowlist_carries_no_stale_entries(self) -> None:
        """The ratchet's other jaw: once an allowlisted symbol gains a shipped caller (or is
        deleted), its entry must go, so the list only ever shrinks toward zero and never quietly
        shields a name that later loses its caller again."""
        current = _unreached_public_symbols()
        stale = {k: v for k, v in _KNOWN_UNREACHED.items() if k not in current}
        assert not stale, (
            "allowlist entries whose symbols are now reachable (or gone) — delete these lines "
            "from _KNOWN_UNREACHED:\n  " + "\n  ".join(f"{k}  ({v})" for k, v in sorted(stale.items()))
        )


# ---------------------------------------------------------------------------
# CLI flags: a flag that is parsed but whose dest nothing ever reads is dead configuration —
# worse than absent, because an operator can set it and be silently ignored. `--eth-key-file`
# shipped exactly this way. Zero entries needed on the current tree (measured 2026-08-27:
# 217 flags across scripts/, all read); keep it that way.
# ---------------------------------------------------------------------------

_KNOWN_DEAD_FLAGS: dict[str, str] = {}


def _dead_cli_flags() -> dict[str, str]:
    """Every optional argparse flag defined in scripts/*.py whose dest is never read.

    A read is an attribute access (`args.foo` — argparse Namespaces are always read this way)
    or a `getattr`/`hasattr` with a literal name, anywhere in shipped code. Deliberately
    STRICTER than the symbol scan (no string-constant shield): measured on the current tree,
    the tight detector produces zero false alarms, and a flag's dest has no registry pattern
    that would need one. Loosen only with a measurement in hand.
    """
    reads: set[str] = set()
    for _p, tree in _shipped_trees():
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute):
                reads.add(node.attr)
            elif (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in ("getattr", "hasattr")
                and len(node.args) >= 2
                and isinstance(node.args[1], ast.Constant)
                and isinstance(node.args[1].value, str)
            ):
                reads.add(node.args[1].value)

    dead: dict[str, str] = {}
    for p, tree in _shipped_trees():
        if _SCRIPTS not in p.parents:
            continue
        for node in ast.walk(tree):
            if not (
                isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "add_argument"
            ):
                continue
            opts = [a.value for a in node.args if isinstance(a, ast.Constant) and isinstance(a.value, str)]
            if not opts or not opts[0].startswith("-"):
                continue  # positionals are always consumed by position
            kw = {k.arg: k.value for k in node.keywords}
            action = kw.get("action")
            if isinstance(action, ast.Constant) and action.value in ("help", "version"):
                continue  # argparse consumes these itself
            dest_node = kw.get("dest")
            if isinstance(dest_node, ast.Constant) and isinstance(dest_node.value, str):
                dest = dest_node.value
            else:
                longs = [o for o in opts if o.startswith("--")]
                dest = (longs[0] if longs else opts[0]).lstrip("-").replace("-", "_")
            if dest not in reads:
                dead[f"{p.relative_to(_ROOT).as_posix()}::{opts[0]}"] = dest
    return dead


class TestEveryCliFlagIsRead:
    def test_no_flag_is_parsed_and_then_ignored(self) -> None:
        dead = {k: v for k, v in _dead_cli_flags().items() if k not in _KNOWN_DEAD_FLAGS}
        assert not dead, (
            "these flags are defined but their dest is never read — an operator setting them is "
            "silently ignored:\n  "
            + "\n  ".join(f"{k} (dest={v})" for k, v in sorted(dead.items()))
            + "\nRead the dest where the flag was meant to act, or delete the flag."
        )

    def test_the_dead_flag_allowlist_carries_no_stale_entries(self) -> None:
        current = _dead_cli_flags()
        stale = {k: v for k, v in _KNOWN_DEAD_FLAGS.items() if k not in current}
        assert not stale, "delete these now-read (or removed) flags from _KNOWN_DEAD_FLAGS:\n  " + "\n  ".join(
            sorted(stale)
        )
