"""No deploy receipt anywhere in the package may name the address value goes to.

The token leg was fixed for this. The native leg was not — for weeks — and it is the leg that has
carried real value on mainnet. That is the whole failure mode of an instance fix: the property is
"a CREATE address is derived, never reported", and a property stated only at the two sites where
someone happened to look is not a property, it is a coincidence.

`wait_receipt` is primary-only by design and always will be — a receipt is a single-node artifact.
So ONE endpoint chose where an entire counter leg went, and nothing downstream noticed, because
the funds really were at the address it named. Re-verifying the code there does not help either:
an attacker deploys the same bytecode and simply owns the claim key.

The address was never something to be told. `keccak(rlp([sender, nonce]))[12:]` derives it from
two values the deployer already holds, so the derivation needs no second endpoint and no trust.

This scans every module under `src/pyrxd/` and allowlists nothing. It parses the AST rather than
the text: text scans on this codebase have been defeated by comments naming the call and by line
wrapping, and have false-alarmed on docstrings that merely mention the field.
"""

from __future__ import annotations

import ast
import os
import pathlib

import pytest

_SRC = pathlib.Path(__file__).resolve().parent.parent / "src" / "pyrxd"


# --------------------------------------------------------------------- the AST predicate


def _reads_contract_address(node: ast.AST) -> bool:
    """Whether ``node`` is an expression that pulls ``contractAddress`` out of a mapping.

    Both spellings, because both appear in this repo: ``receipt["contractAddress"]`` and
    ``receipt.get("contractAddress", "")``.
    """
    if isinstance(node, ast.Subscript):
        key = node.slice
        return isinstance(key, ast.Constant) and key.value == "contractAddress"
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "get":
        return bool(node.args) and isinstance(node.args[0], ast.Constant) and node.args[0].value == "contractAddress"
    return False


def _is_create_derivation(node: ast.AST) -> bool:
    """Whether ``node`` is a call to a CREATE-address derivation.

    Matched by NAME, not by identity: the native leg exports ``create_address`` and the token leg
    still holds a private ``_create_address`` (importing the shared one would be circular). A
    differential test below pins the two to the same arithmetic, so either satisfies the rule.
    """
    if not isinstance(node, ast.Call):
        return False
    fn = node.func
    name = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
    return name.endswith("create_address")


def _names_bound_to(fn: ast.AST, predicate) -> set[str]:
    """Every local name assigned from an expression containing a node matching ``predicate``."""
    bound: set[str] = set()
    for node in ast.walk(fn):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        if node.value is None or not any(predicate(sub) for sub in ast.walk(node.value)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        for t in targets:
            for sub in ast.walk(t):
                if isinstance(sub, ast.Name):
                    bound.add(sub.id)
    return bound


def _guarded_comparison(fn: ast.AST, left: set[str], right: set[str]) -> bool:
    """Whether some ``if`` in ``fn`` compares a name from each set and RAISES on the mismatch.

    The comparison alone is not the guard — a function could compute it and log it. What makes it
    a guard is that the branch does not continue.
    """
    for node in ast.walk(fn):
        if not isinstance(node, ast.If) or not isinstance(node.test, ast.Compare):
            continue
        used = {n.id for n in ast.walk(node.test) if isinstance(n, ast.Name)}
        if not (used & left) or not (used & right):
            continue
        if any(isinstance(b, ast.Raise) for b in ast.walk(node)):
            return True
    return False


def _enclosing_functions(tree: ast.AST) -> dict[ast.AST, ast.AST | None]:
    """Map every node to the innermost function that contains it (``None`` at module level)."""
    owner: dict[ast.AST, ast.AST | None] = {tree: None}
    stack: list[tuple[ast.AST, ast.AST | None]] = [(tree, None)]
    while stack:
        node, fn = stack.pop()
        here = node if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) else fn
        for child in ast.iter_child_nodes(node):
            owner[child] = here
            stack.append((child, here))
    return owner


def _violations(path: pathlib.Path) -> list[str]:
    tree = ast.parse(path.read_text())
    owner = _enclosing_functions(tree)
    found: list[str] = []
    seen: set[int] = set()
    for node in ast.walk(tree):
        if not _reads_contract_address(node):
            continue
        fn = owner.get(node)
        if fn is None:
            found.append(f"{path.name}:{node.lineno}: read at module level, outside any function")
            continue
        if id(fn) in seen:
            continue
        seen.add(id(fn))
        reported = _names_bound_to(fn, _reads_contract_address)
        derived = _names_bound_to(fn, _is_create_derivation)
        if not derived:
            found.append(f"{path.name}:{fn.lineno}: {fn.name} reads contractAddress but derives no CREATE address")
        elif not reported:
            found.append(f"{path.name}:{fn.lineno}: {fn.name} uses contractAddress without binding it for comparison")
        elif not _guarded_comparison(fn, derived, reported):
            found.append(f"{path.name}:{fn.lineno}: {fn.name} derives and reports but never refuses on a mismatch")
    return found


# --------------------------------------------------------------------- the guard itself


class TestEveryDeployReceiptAddressIsCrossChecked:
    def test_no_module_under_src_trusts_a_reported_contract_address(self) -> None:
        offenders: list[str] = []
        for path in sorted(_SRC.rglob("*.py")):
            offenders.extend(_violations(path))
        assert offenders == [], (
            "a deploy receipt's contractAddress is used without a CREATE-derivation cross-check:\n  "
            + "\n  ".join(offenders)
            + "\nThe address is keccak(rlp([sender, nonce]))[12:] — derive it and refuse a receipt "
            "that disagrees. There is no allowlist here on purpose: the last time this was fixed "
            "at one site, the other one kept moving real value on an endpoint's word."
        )

    def test_the_scan_actually_reaches_the_two_known_sites(self) -> None:
        """A scan that finds nothing because it looks nowhere passes just as green.

        This pins that the predicate really fires on the two functions the rule is about, so an
        import rename or a refactor that hides the read cannot silently empty the scan.
        """
        hits = {
            path.name
            for path in _SRC.rglob("*.py")
            if any(_reads_contract_address(n) for n in ast.walk(ast.parse(path.read_text())))
        }
        assert hits == {"htlc_leg.py", "erc20_leg.py"}, (
            f"the set of modules reading a deploy receipt's contractAddress changed: {sorted(hits)}. "
            "If that is intended, the new one must carry the derivation cross-check; if a read "
            "disappeared, this scan has stopped covering what it claims to."
        )

    @pytest.mark.parametrize("module", ["htlc_leg.py", "erc20_leg.py"])
    def test_the_predicate_catches_the_check_being_removed(self, module: str) -> None:
        """The scan's own regression test: strip the derivation out of the real source and the
        predicate must object. Without this, `_violations` returning `[]` proves only that it
        returns `[]`."""
        src = (_SRC / "eth_wallet" / module).read_text()
        lines = [
            ln
            for ln in src.splitlines(keepends=True)
            if "create_address(" not in ln or ln.lstrip().startswith("def ")  # keep the definition
        ]
        tree = ast.parse("".join(lines))
        owner = _enclosing_functions(tree)
        reads = [n for n in ast.walk(tree) if _reads_contract_address(n)]
        assert reads, f"{module} no longer reads contractAddress at all — this test is now vacuous"
        fn = owner[reads[0]]
        assert not _names_bound_to(fn, _is_create_derivation), (
            "the predicate still sees a derivation after every call to it was deleted"
        )


# --------------------------------------------------------------- the derivation itself


class TestTheTwoDerivationsAgree:
    """`htlc_leg.create_address` and `erc20_leg._create_address` are the same arithmetic in two
    files: the token leg imports FROM the native one, so importing back would be circular, and
    collapsing them means editing a module this change deliberately does not touch.

    Duplication is only safe while it is pinned. A comment saying "keep these in sync" is not a
    pin; a test that runs both is. A wrong branch does not raise — it names a valid-looking
    address nobody controls, and the ETH goes there.
    """

    @pytest.mark.parametrize("nonce", [0, 1, 127, 128, 255, 256, 65535, 1_000_000, 2**32])
    def test_the_native_derivation_matches_an_INDEPENDENT_rlp_encoder(self, nonce: int) -> None:
        """Differential against a real RLP library, not against its twin. Two copies of the same
        mistake agree perfectly."""
        import rlp
        from eth_utils import keccak, to_checksum_address

        from pyrxd.eth_wallet.htlc_leg import create_address

        sender = "0x" + os.urandom(20).hex()
        expected = to_checksum_address(keccak(rlp.encode([bytes.fromhex(sender[2:]), nonce]))[12:])
        assert create_address(sender, nonce) == expected

    @pytest.mark.parametrize("nonce", [0, 1, 127, 128, 255, 256, 65535, 1_000_000, 2**32])
    def test_both_copies_produce_the_same_address(self, nonce: int) -> None:
        pytest.importorskip("web3", reason="erc20_leg needs the eth extra")
        from pyrxd.eth_wallet.erc20_leg import _create_address
        from pyrxd.eth_wallet.htlc_leg import create_address

        sender = "0x" + os.urandom(20).hex()
        assert create_address(sender, nonce) == _create_address(sender, nonce)

    def test_a_sender_that_is_not_20_bytes_is_refused(self) -> None:
        """The one input that can be malformed. A short address silently produces a valid-looking
        CREATE address for a sender that does not exist."""
        from pyrxd.eth_wallet.htlc_leg import create_address
        from pyrxd.security.errors import ValidationError

        with pytest.raises(ValidationError, match="20-byte"):
            create_address("0x" + "11" * 19, 0)

    def test_a_bare_hex_sender_works_like_a_prefixed_one(self) -> None:
        """The honest-path pair for the refusal above: '0x' is optional, and rejecting a bare hex
        address would be a guard refusing valid input."""
        from pyrxd.eth_wallet.htlc_leg import create_address

        sender = os.urandom(20).hex()
        assert create_address(sender, 7) == create_address("0x" + sender, 7)
