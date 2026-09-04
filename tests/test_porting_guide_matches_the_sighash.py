"""The BIP143 porting guide is copied into other languages. Pin it to the code.

`docs/how-to/handle-radiant-bip143-quirks.md` exists so someone can implement
Radiant's sighash in another language. That makes every claim on it a claim about
CONSENSUS, and a wrong one propagates into an implementation we will never see —
the same failure as publishing conformance vectors that accepted the exploitable
HTLC timelock ordering, which is what 0.22.0 was a security release about.

It told porters two things pyrxd itself had already shipped, hit and fixed:

* to scan for `0xd0`/`0xd8` only — while all FIVE ref-operand opcodes carry a
  36-byte immediate and must be WALKED to stay in step with the opcode stream.
  Treating one as a bare opcode resumes the walk inside the ref bytes: measured at
  ~80% of refs wrong on a Photonic `nftAuthScript`, an invalid signature on every
  input.
* to sort refs "ascending by their 36 bytes" — lexicographic, where consensus
  orders by `uint288` numeric value, i.e. the fully-reversed bytes. Agrees for
  single-ref outputs and diverges for two or more: the bug that made dMint
  contract-output signing fail ~50% of the time against a real node.

Both are checked here against the source rather than against a remembered phrase.
"""

from __future__ import annotations

import inspect
import pathlib
import re

from pyrxd.constants import OPCODE_VALUE_NAME_DICT, REF_OPERAND_OPCODES
from pyrxd.transaction import transaction_preimage

_GUIDE = pathlib.Path(__file__).resolve().parent.parent / "docs/how-to/handle-radiant-bip143-quirks.md"


def _guide_text() -> str:
    return _GUIDE.read_text(encoding="utf-8")


def test_the_guide_names_EVERY_ref_operand_opcode() -> None:
    """Derived from the constant, not from a list in this test — a sixth
    operand-carrying opcode would fail here the day it is added, which is the
    property the old wording lacked."""
    text = _guide_text()
    missing = [
        f"0x{op:02x} ({OPCODE_VALUE_NAME_DICT.get(bytes([op]), '?')})"
        for op in sorted(REF_OPERAND_OPCODES)
        if f"0x{op:02x}" not in text.lower()
    ]
    assert not missing, (
        "the porting guide does not mention these operand-carrying ref opcodes, so a "
        f"porter following it will desynchronise their script walk: {missing}"
    )


def test_the_guide_states_the_SAME_sort_key_the_code_uses() -> None:
    """The code sorts by `ref[::-1]`. The guide said 'ascending by their 36 bytes',
    which is the opposite order for any output with two or more refs."""
    source = inspect.getsource(transaction_preimage)
    assert "key=lambda r: r[::-1]" in source, "the sort key moved; re-read before trusting this test"
    assert "ref[::-1]" in _guide_text(), (
        "the porting guide no longer states the reversed-byte sort key the code uses. "
        "Lexicographic order agrees for single-ref outputs and diverges for 2+, so a "
        "porter's vectors can pass while their node rejects real transactions."
    )


def test_the_guide_does_not_still_teach_the_lexicographic_sort() -> None:
    """The specific wrong phrasing that shipped, as a regression guard. Narrow on
    purpose: it pins the sentence that was wrong, and the two tests above pin the
    properties."""
    text = _guide_text()
    for wrong in ("sorted ascending and deduplicated", "sorted ascending by their 36 bytes"):
        assert wrong not in text, f"the guide teaches the lexicographic sort again: {wrong!r}"


def test_the_scan_is_not_vacuous() -> None:
    """The guide existing and being non-trivial is a precondition for all of the
    above; an empty or moved file would pass every `not in` assertion."""
    text = _guide_text()
    assert len(text) > 4_000, f"the porting guide is only {len(text)} chars — has it moved?"
    assert "hashOutputHashes" in text
    assert len(re.findall(r"0x[0-9a-f]{2}", text)) > 5
