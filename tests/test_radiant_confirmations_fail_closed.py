"""``RadiantChainIO.confirmations`` must convert a lying node into a NetworkError.

This gate decides how deep the RXD covenant funding is, on a value-moving path. It was a
bare ``int(info.get("confirmations", 0) or 0)``, and two things got through:

* a STRING ``"999999"`` coerced silently to a depth of 999,999 — an untrusted server
  choosing the answer to "is the maker's asset buried yet?";
* a JSON ``Infinity``, which raised **OverflowError** — not a ``NetworkError``, so it
  escaped every ``except NetworkError`` on the path and surfaced as a bare traceback.

The fix landed with the incident. **No test came with it**, which is what #510 recorded:
"`RadiantChainIO.confirmations`' fail-closed guard is untested — it was added after a real
bug." A fix with no test is a fix that can be reverted by the next refactor in silence, and
this one is three lines.

What this file pins, in both directions:

1. Every hostile shape raises ``NetworkError`` **specifically** — not merely "an exception".
   The bug was never that nothing was raised; it was that the WRONG type was, and the
   callers' ``except NetworkError`` did not catch it. An assertion of ``Exception`` here
   would have passed against the original defect.
2. Falsy and negative depths fail **closed** — depth 0, "not buried" — rather than raising.
   A node that omits the field, or returns null, must not take the swap down; it must read
   as unconfirmed.
3. The honest path still returns the real depth. A confirmation gate that refuses good data
   stalls an honest swap, which is the failure this project treats as a bug in its own right.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

from pyrxd.gravity.radiant_leg import RadiantChainIO
from pyrxd.security.errors import NetworkError

#: Shapes an untrusted ElectrumX server can return in `confirmations`. Each one is a way to
#: be a number without being one; `"999999"` and `float("inf")` are the two that actually
#: shipped.
LYING_DEPTHS = [
    pytest.param("999999", id="string-that-coerces"),
    pytest.param(float("inf"), id="json-Infinity"),
    pytest.param(float("-inf"), id="json-negative-Infinity"),
    pytest.param(float("nan"), id="json-NaN"),
    pytest.param(1.5, id="fractional-float"),
    pytest.param(True, id="bool-is-not-a-depth"),
    pytest.param([6], id="list"),
    pytest.param({"depth": 6}, id="dict"),
]

#: Present-but-falsy, and negative. These must READ AS ZERO, not raise: a swap must not die
#: because a node omitted a field, and "unmined" is the safe reading.
FAIL_CLOSED_DEPTHS = [
    pytest.param(None, id="null"),
    pytest.param(0, id="zero"),
    pytest.param("", id="empty-string"),
    pytest.param(-3, id="negative"),
]


class _Node:
    """A minimal ElectrumX client. `RadiantChainIO` checks for these three by name."""

    def __init__(self, verbose_result: object) -> None:
        self._verbose_result = verbose_result

    async def broadcast(self, raw_tx: bytes) -> str:  # pragma: no cover - not exercised here
        return "ab" * 32

    async def get_utxos(self, script_hash: str) -> list:  # pragma: no cover - likewise
        return []

    async def get_transaction_verbose(self, txid: str) -> object:
        return self._verbose_result


def _io(depth: object) -> RadiantChainIO:
    return RadiantChainIO(_Node({"confirmations": depth}))


@pytest.mark.parametrize("depth", LYING_DEPTHS)
async def test_a_lying_depth_raises_NetworkError_specifically(depth: object) -> None:
    """The type is the assertion. `OverflowError` was raised, and was not caught."""
    with pytest.raises(NetworkError):
        await _io(depth).confirmations("ab" * 32)


@pytest.mark.parametrize("depth", LYING_DEPTHS)
async def test_no_other_exception_type_escapes(depth: object) -> None:
    """Stated separately from the test above because it is a different claim.

    `pytest.raises(NetworkError)` proves NetworkError was raised. It does not prove that
    some OTHER shape raises something else — and the original defect was exactly one shape
    raising a type nothing caught. This walks every shape and names the escapee.
    """
    try:
        await _io(depth).confirmations("ab" * 32)
    except NetworkError:
        return
    except BaseException as exc:  # pragma: no cover - this is the assertion
        pytest.fail(
            f"confirmations({depth!r}) raised {type(exc).__name__}, which callers' "
            f"`except NetworkError` does not catch: {exc}"
        )
    pytest.fail(f"confirmations({depth!r}) returned instead of refusing")


@pytest.mark.parametrize("depth", FAIL_CLOSED_DEPTHS)
async def test_a_missing_or_negative_depth_reads_as_unconfirmed(depth: object) -> None:
    """Fail CLOSED, not loud. Absent/at-zero/negative all mean "not buried yet"."""
    assert await _io(depth).confirmations("ab" * 32) == 0


async def test_a_missing_confirmations_key_reads_as_unconfirmed() -> None:
    """The field absent entirely — the ordinary shape for an unmined transaction."""
    assert await RadiantChainIO(_Node({})).confirmations("ab" * 32) == 0


async def test_a_non_dict_response_is_refused() -> None:
    with pytest.raises(NetworkError):
        await RadiantChainIO(_Node([])).confirmations("ab" * 32)


@pytest.mark.parametrize("depth", [1, 6, 12, 100, 999_999])
async def test_an_honest_depth_is_returned_unchanged(depth: int) -> None:
    """Pairs with every refusal above: a guard that refuses valid work is a bug.

    999_999 is here deliberately — it is the value the STRING case sends. The defect was
    never the magnitude, it was the type, and a guard that refused large-but-honest depths
    would stall a swap on a well-buried covenant.
    """
    assert await _io(depth).confirmations("ab" * 32) == depth


def test_confirmations_has_shipped_callers() -> None:
    """Reachability, executably. This guard protects a path only if something walks it.

    An AST scan rather than a grep: a comment or docstring mentioning `.confirmations(`
    is not a call. If this ever fails, the method is orphaned and the tests above are
    verifying a mechanism nobody invokes.
    """
    root = pathlib.Path(__file__).resolve().parent.parent / "src" / "pyrxd"
    files = sorted(root.rglob("*.py"))
    assert len(files) > 50, f"the scan found only {len(files)} modules — it is not reaching src/"

    callers = []
    for path in files:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "confirmations"
            ):
                callers.append(f"{path.relative_to(root.parent.parent)}:{node.lineno}")

    assert callers, "nothing in shipped source calls .confirmations() — the guard is unreachable"
