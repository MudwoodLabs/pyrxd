"""``FileFundLock`` excludes two processes that pass the SAME path. Nothing else.

Its docstring used to say the path came from "the caller's key path, so two swaps sharing a
funding key share a lock — conservative (over-exclusion) rather than unsafe" (#504 item 5).
That was false in the direction that matters: both runners construct it from
``args.keys_out``, which is PER-RUN, so two concurrent swaps on ONE funding key with
different ``--keys-out`` get two different lock files and exclude nothing at all.

Why a docstring defect is worth a test file. This lock stands between a resume and a
DOUBLE-FUND: two funders each read the same pre-push balance, each send the shortfall, and
the HTLC ends up holding twice the negotiated amount — whose claim sweeps the whole balance
to the counterparty. The sentence describing its scope is what the next person reasons from
when deciding whether a deployment is covered. A lock whose documented scope is WIDER than
its real scope is worse than no lock, because no lock at least looks like no lock.

Prose cannot be tested. Behaviour can, so the behaviour is asserted here and the docstring
now describes it — and the two construction sites are pinned as membership, so keying this
by ``H`` (#504 item 3) fails this file and forces the paragraph to be re-read rather than
silently inherited.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

from pyrxd.gravity.record_sink import FileFundLock
from pyrxd.security.errors import ValidationError


def test_the_same_path_is_excluded(tmp_path: pathlib.Path) -> None:
    """The exclusion that DOES exist. Stated positively, because it is the useful half."""
    held = FileFundLock(str(tmp_path / "run1"))
    other = FileFundLock(str(tmp_path / "run1"))
    with held():
        with pytest.raises(ValidationError):
            with other():
                pass  # pragma: no cover - reaching here IS the failure


def test_two_paths_exclude_NOTHING_even_for_one_funding_key(tmp_path: pathlib.Path) -> None:
    """The invariant the old docstring claimed, demonstrated absent.

    This is the case an operator running two swaps off one funding wallet is actually in:
    same key, two ``--keys-out`` paths. The old sentence said they would share a lock. They
    do not, and if this test ever starts failing because they DO, the docstring's scope
    paragraph is the thing to update.
    """
    first = FileFundLock(str(tmp_path / "swap-A"))
    second = FileFundLock(str(tmp_path / "swap-B"))
    with first():
        with second():
            pass  # both acquire — no exclusion between runs


def test_the_lock_file_name_is_the_path_plus_a_suffix(tmp_path: pathlib.Path) -> None:
    """Keyed by the path, not by the hashlock and not by the funding key."""
    lock = FileFundLock(str(tmp_path / "keys.json"))
    with lock():
        assert (tmp_path / "keys.json.fundlock").exists()


def test_a_crashed_holder_does_not_deadlock_the_swap(tmp_path: pathlib.Path) -> None:
    """`flock` is the right primitive BECAUSE the kernel releases it — the docstring's
    stated reason for not using a lease. A resume exists to recover from a crash, so a lock
    that outlived its holder would block the very path it protects."""
    lock = FileFundLock(str(tmp_path / "run1"))
    with lock():
        pass
    with FileFundLock(str(tmp_path / "run1"))():
        pass  # released on close; a second acquisition must succeed


#: The construction sites, pinned as (file, WHAT IS PASSED). The argument is the whole story:
#: the lock file is that expression plus a suffix, so the expression IS the lock's scope.
#:
#: A first version of this pinned only the FILENAMES, and planting a second construction inside
#: an already-listed file passed it — a set of paths cannot express "two different keys in one
#: module", which is precisely the change that would widen or narrow the lock without moving it.
EXPECTED_CONSTRUCTIONS = {
    ("scripts/eth_swap_run.py", "str(Path(args.keys_out).expanduser())"),
    ("scripts/eth_swap_grief_run.py", "str(Path(args.keys_out).expanduser())"),
}


def _constructions() -> set[tuple[str, str]]:
    root = pathlib.Path(__file__).resolve().parent.parent
    found = set()
    for path in sorted([*(root / "src").rglob("*.py"), *(root / "scripts").rglob("*.py")]):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "FileFundLock":
                arg = ast.unparse(node.args[0]) if node.args else "<no positional arg>"
                found.add((str(path.relative_to(root)), arg))
    return found


def test_the_scan_finds_something() -> None:
    """Non-vacuity. A scan that reaches no modules would pass the test below on an empty set."""
    assert _constructions(), "the AST scan found no FileFundLock constructions — it is not reaching the tree"


def test_what_is_passed_to_the_lock_is_exactly_this() -> None:
    """A change here means the lock's SCOPE changed, and the docstring must be re-read.

    An AST scan, so a mention in a comment or docstring is not a construction, and the argument
    is compared as source text so a DIFFERENT key in an already-listed file is caught too.

    If #504 item 3 lands and the lock is keyed by `H`, this fails — which is the intent: the
    paragraph explaining what the lock does and does not cover must not survive the change that
    invalidates it.
    """
    found = _constructions()
    assert found == EXPECTED_CONSTRUCTIONS, (
        f"FileFundLock constructions changed: {found ^ EXPECTED_CONSTRUCTIONS}. Re-read the scope "
        "paragraph on FileFundLock before updating this set — it states what the lock does and "
        "does not exclude, and that answer depends entirely on what is passed here."
    )
