"""Opcode and consensus-constant parity against Radiant Core.

pyrxd re-implements Radiant consensus rules in Python. Nothing about a Python
constant makes it track the C++ that defines it, so these tests derive the
ground truth by parsing vendored, pinned Radiant Core sources (see
``tests/vendor/radiant_core/README.md``) and assert pyrxd matches.

This file exists because of three bugs that all shipped within a day of each
other, all the same shape — a hand-written spelling of the ref-operand rule
that disagreed with ``GetScriptOp``:

* ``glyph/script.py`` treated the operand set as the contiguous range
  ``0xd0-0xd8``, so it invented refs out of the operand bytes of the four
  ``REFHASH*`` stack ops sitting in the middle of that range, and lost the real
  ref.
* ``transaction/transaction_preimage.py`` walked only ``0xd0``/``0xd8``,
  desynchronising on ``0xd1``/``0xd2``/``0xd3`` and producing a
  ``hashOutputHashes`` that disagreed with the node — an invalid signature on
  every input.
* ``glyph/credential_binding.py`` carried its own copy of the ``0xd0-0xd8``
  walk and named an attacker as owner.

Two more spellings existed and were correct, which is the important detail: the
codebase contained both answers simultaneously and had no way to tell which was
right. These tests are that way.

Everything here runs offline in milliseconds. There is no network, no node, and
no skip path — a consensus oracle that can silently disable itself is not an
oracle.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

import pyrxd.constants as pyrxd_constants
from pyrxd.constants import (
    MAX_OPCODE,
    OPCODE_VALUE_NAME_DICT,
    PUSH_REF_OPCODES,
    REF_OPERAND_OPCODES,
    REF_OPERAND_WIDTH,
    OpCode,
)
from tests.consensus_oracle import (
    VENDOR_DIR,
    consensus_limit,
    manifest,
    max_opcode,
    opcode_table,
    push_ref_opcode_names,
    push_ref_opcodes,
    push_refs_guard_opcode_names,
    ref_operand_opcode_names,
    ref_operand_opcodes,
    ref_operand_width,
    script_budgets_enforced_by_interpreter,
    script_limit,
    vendored_digest,
)

pytestmark = pytest.mark.unit

_REPO_ROOT = Path(__file__).resolve().parents[1]
_REFRESH_SCRIPT = _REPO_ROOT / "scripts" / "refresh_radiant_core_vendor.py"


# Enumerators in `enum opcodetype` that are not opcodes: a sentinel used to
# define MAX_OPCODE, and a value the header itself annotates "Not a real
# OPCODE!".
_NON_OPCODE_ENUMERATORS = frozenset({"FIRST_UNDEFINED_OP_VALUE", "INVALIDOPCODE"})

# pyrxd names with no counterpart in Radiant's enum. All are Bitcoin Core
# legacy pseudo-words, all are unused throughout pyrxd, and all sit above
# MAX_OPCODE — so they cannot appear in a script Radiant would accept. The
# exemption is not taken on trust: test_pseudo_words_are_all_above_max_opcode
# re-checks that property from the oracle.
_PSEUDO_WORDS = frozenset({"OP_DATA", "OP_SIG", "OP_PUBKEYHASH", "OP_PUBKEY", "OP_INVALIDOPCODE"})


def _pyrxd_opcodes() -> dict[str, int]:
    """``{name: byte}`` for every ``OpCode`` member, aliases included.

    ``__members__`` rather than iteration: ``OP_FALSE``/``OP_TRUE`` are aliases
    of ``OP_0``/``OP_1`` and iteration would drop them, hiding a rename.
    """
    return {name: member.value[0] for name, member in OpCode.__members__.items()}


def _upstream_opcodes() -> dict[str, int]:
    return {name: value for name, value in opcode_table().items() if name not in _NON_OPCODE_ENUMERATORS}


# ---------------------------------------------------------------------------
# The oracle itself must be trustworthy before anything is asserted against it
# ---------------------------------------------------------------------------

#: Every vendored file, taken from the manifest instead of hand-listed. This was
#: spelled ``["script.h", "script.cpp"]`` while eight files were vendored, so the
#: digest check — structurally correct — ran over a quarter of its subject and
#: passed vacuously for everything added after it was written. Deriving the set
#: from the manifest makes "vendored" and "digest-checked" the same list by
#: construction; ``test_every_vendored_file_is_digest_checked`` closes the other
#: direction, and asserts non-emptiness so a parametrisation over nothing cannot
#: report green.
_VENDORED_FILES = sorted(manifest()["files"])


class TestOracleIntegrity:
    """Guard the oracle. Each of these failing means the differentials below
    are meaningless, so they must fail loudly rather than degrade."""

    @pytest.mark.parametrize("name", _VENDORED_FILES)
    def test_vendored_sources_match_manifest_digest(self, name):
        expected = manifest()["files"][name]["sha256"]
        assert vendored_digest(name) == expected, (
            f"tests/vendor/radiant_core/{name} does not match the sha256 recorded in "
            f"MANIFEST.json. The vendored Radiant Core sources are verbatim upstream "
            f"copies and must never be hand-edited — re-run "
            f"scripts/refresh_radiant_core_vendor.py to update them and the manifest together."
        )

    def test_every_vendored_file_is_digest_checked(self):
        """Both directions, so neither half can drift out of the other's sight.

        A source in the vendor directory with no manifest entry is an oracle
        input nothing digests; a manifest entry with no file on disk is a check
        that has silently stopped running. Either way the failure is invisible
        in the output of the test above, which only ever reports on the names it
        was handed.
        """
        assert _VENDORED_FILES, "MANIFEST.json lists no files — the digest parametrisation would be empty"
        on_disk = {p.name for p in VENDOR_DIR.iterdir() if p.suffix in {".h", ".cpp"}}
        assert on_disk == set(_VENDORED_FILES), (
            "the vendored sources and MANIFEST.json disagree about what is vendored.\n"
            f"  on disk, not in the manifest: {sorted(on_disk - set(_VENDORED_FILES))}\n"
            f"  in the manifest, not on disk: {sorted(set(_VENDORED_FILES) - on_disk)}\n"
            "Re-run scripts/refresh_radiant_core_vendor.py so the two are written together."
        )

    def test_the_refresh_script_covers_every_vendored_file(self):
        """The third list that has to agree: what ``--check`` actually re-fetches.

        A file added to the manifest but not to the script's ``FILES`` map is
        digest-checked locally and never compared against upstream again, so it
        would go stale in exactly the silent way vendoring exists to prevent.
        """
        spec = importlib.util.spec_from_file_location("_refresh_radiant_core_vendor", _REFRESH_SCRIPT)
        assert spec and spec.loader, f"could not load {_REFRESH_SCRIPT}"
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        assert set(module.FILES) == set(_VENDORED_FILES), (
            "scripts/refresh_radiant_core_vendor.py and MANIFEST.json disagree about what is vendored.\n"
            f"  in the script, not in the manifest: {sorted(set(module.FILES) - set(_VENDORED_FILES))}\n"
            f"  in the manifest, not in the script: {sorted(set(_VENDORED_FILES) - set(module.FILES))}"
        )
        upstream = {name: manifest()["files"][name]["upstream_path"] for name in _VENDORED_FILES}
        assert upstream == module.FILES, (
            "the script and the manifest disagree about where a vendored file comes from upstream; "
            "a refresh would overwrite it from a different path than the one recorded as its provenance."
        )

    def test_opcode_table_parsed_plausibly(self):
        table = opcode_table()
        assert len(table) > 150, f"only {len(table)} enumerators parsed from `enum opcodetype`"
        # Spot-anchor three values that a broken parser could not fake.
        assert table["OP_0"] == 0x00
        assert table["OP_CHECKSIG"] == 0xAC
        assert table["OP_PUSHINPUTREFSINGLETON"] == 0xD8

    def test_push_refs_guard_agrees_with_get_script_op(self):
        """Cross-check across two different C++ functions.

        ``GetScriptOp``'s operand branch and ``GetPushRefs``'s outer guard list
        the same five opcodes independently. Agreement is evidence the parser
        located the real blocks rather than plausible-looking ones.
        """
        assert push_refs_guard_opcode_names() == ref_operand_opcode_names()


# ---------------------------------------------------------------------------
# The rule that broke three times
# ---------------------------------------------------------------------------


class TestRefOperandParity:
    def test_ref_operand_opcodes_match_get_script_op(self):
        assert ref_operand_opcodes() == REF_OPERAND_OPCODES, (
            "pyrxd's REF_OPERAND_OPCODES disagrees with the set Radiant's GetScriptOp "
            "follows with a 36-byte immediate operand.\n"
            f"  pyrxd    : {sorted(hex(o) for o in REF_OPERAND_OPCODES)}\n"
            f"  consensus: {sorted(hex(o) for o in ref_operand_opcodes())} "
            f"({sorted(ref_operand_opcode_names())})\n"
            "Any walker using the wrong set desynchronises the moment one of these "
            "appears, and starts reading ref bytes as opcodes."
        )

    def test_ref_operand_set_is_not_a_contiguous_range(self):
        """The specific mistake ``glyph/script.py`` made.

        Pinning this explicitly means a future refactor that "simplifies" the
        set back into ``0xd0 <= op <= 0xd8`` fails with an explanation rather
        than a mystery.
        """
        low, high = min(REF_OPERAND_OPCODES), max(REF_OPERAND_OPCODES)
        gap = frozenset(range(low, high + 1)) - REF_OPERAND_OPCODES
        assert gap, "expected the operand set to have holes in it"
        names = {opcode_table()[n]: n for n in opcode_table()}
        assert gap == {0xD4, 0xD5, 0xD6, 0xD7}, (
            f"unexpected holes {sorted(hex(o) for o in gap)} — upstream changed the layout"
        )
        for op in sorted(gap):
            assert op not in ref_operand_opcodes(), (
                f"{hex(op)} ({names.get(op)}) is a stack op carrying no operand; a walker "
                f"that consumes 36 bytes after it fabricates refs and hides the real one"
            )

    def test_push_ref_opcodes_match_get_push_refs(self):
        assert push_ref_opcodes() == PUSH_REF_OPCODES, (
            "pyrxd's PUSH_REF_OPCODES disagrees with the opcodes Radiant's GetPushRefs "
            "files into foundPushRefs (the set that feeds hashOutputHashes).\n"
            f"  pyrxd    : {sorted(hex(o) for o in PUSH_REF_OPCODES)}\n"
            f"  consensus: {sorted(hex(o) for o in push_ref_opcodes())} "
            f"({sorted(push_ref_opcode_names())})"
        )

    def test_collected_refs_are_a_strict_subset_of_walked_refs(self):
        """ "Carries an operand" and "contributes a ref" are different questions.

        Conflating them is what produced the sighash bug: 0xd1/0xd2/0xd3 must be
        WALKED (36 bytes consumed) but not COLLECTED.
        """
        assert PUSH_REF_OPCODES < REF_OPERAND_OPCODES
        walked_not_collected = REF_OPERAND_OPCODES - PUSH_REF_OPCODES
        assert walked_not_collected == {0xD1, 0xD2, 0xD3}

    def test_ref_operand_width_matches_get_script_op(self):
        assert ref_operand_width() == REF_OPERAND_WIDTH


# ---------------------------------------------------------------------------
# Whole-table parity
# ---------------------------------------------------------------------------


class TestOpcodeTableParity:
    def test_shared_opcode_names_have_identical_values(self):
        pyrxd, upstream = _pyrxd_opcodes(), _upstream_opcodes()
        mismatched = {
            name: (pyrxd[name], upstream[name])
            for name in pyrxd.keys() & upstream.keys()
            if pyrxd[name] != upstream[name]
        }
        assert not mismatched, "opcode value mismatches (pyrxd, consensus): " + ", ".join(
            f"{n}=({hex(a)}, {hex(b)})" for n, (a, b) in sorted(mismatched.items())
        )

    def test_pyrxd_defines_every_radiant_opcode(self):
        missing = {n: v for n, v in _upstream_opcodes().items() if n not in _pyrxd_opcodes()}
        assert not missing, (
            "Radiant defines opcodes pyrxd's OpCode enum does not: "
            + ", ".join(f"{n}={hex(v)}" for n, v in sorted(missing.items(), key=lambda kv: kv[1]))
            + ". Anything decoding or disassembling a script will fail to name these, "
            "and callers tend to hard-code the raw byte locally instead — which is how "
            "the ref-operand rule ended up spelled in four places."
        )

    def test_pyrxd_defines_no_opcode_radiant_does_not(self):
        extra = {n: v for n, v in _pyrxd_opcodes().items() if n not in _upstream_opcodes() and n not in _PSEUDO_WORDS}
        assert not extra, "pyrxd's OpCode enum names opcodes Radiant does not define: " + ", ".join(
            f"{n}={hex(v)}" for n, v in sorted(extra.items(), key=lambda kv: kv[1])
        )

    def test_pseudo_words_are_all_above_max_opcode(self):
        """Keeps the pseudo-word exemption honest.

        These names are exempt from parity only because Radiant can never
        interpret their bytes as opcodes. If that stopped being true the
        exemption would be hiding a real divergence.
        """
        pyrxd = _pyrxd_opcodes()
        for name in sorted(_PSEUDO_WORDS):
            assert name in pyrxd, f"{name} is allow-listed but no longer defined; drop it from _PSEUDO_WORDS"
            assert pyrxd[name] > max_opcode(), (
                f"{name}={hex(pyrxd[name])} is at or below MAX_OPCODE ({hex(max_opcode())}), so Radiant "
                f"would accept that byte in a script. It can no longer be exempted as a pseudo-word."
            )

    def test_max_opcode_matches(self):
        assert max_opcode() == MAX_OPCODE, (
            f"pyrxd MAX_OPCODE={hex(MAX_OPCODE)} but Radiant's script.h derives "
            f"{hex(max_opcode())} from FIRST_UNDEFINED_OP_VALUE - 1"
        )

    def test_every_radiant_opcode_resolves_to_a_name(self):
        """``OPCODE_VALUE_NAME_DICT`` is what disassembly and inspection use."""
        unnamed = sorted(v for v in _upstream_opcodes().values() if bytes([v]) not in OPCODE_VALUE_NAME_DICT)
        assert not unnamed, f"no name for consensus opcodes: {[hex(v) for v in unnamed]}"


#: Every scalar limit pyrxd pins, mapped to the C++ name it comes from. Adding a
#: constant to ``pyrxd.constants`` without adding it here is caught by
#: ``test_no_pinned_limit_is_unchecked`` below.
_PINNED_SCALAR_LIMITS = [
    "LOCKTIME_THRESHOLD",
    "MAX_OPS_PER_SCRIPT",
    "MAX_SCRIPT_ELEMENT_SIZE",
    "MAX_SCRIPT_ELEMENT_SIZE_LEGACY",
    "MAX_SCRIPT_SIZE",
    "MAX_STACK_SIZE",
]


class TestScalarConsensusLimits:
    """The ``script.h`` limits, checked against the C++ that declares them.

    Written as a table rather than one test per constant so that a constant
    pinned without a check is a test failure, not an omission nobody notices —
    which is the state ``MAX_OPCODE`` was in before it had a consumer.
    """

    @pytest.mark.parametrize("name", _PINNED_SCALAR_LIMITS)
    def test_pinned_limit_matches_radiant(self, name):
        pinned = getattr(pyrxd_constants, name)
        upstream = script_limit(name)
        assert pinned == upstream, f"pyrxd pins {name}={pinned:,} but Radiant's script.h declares {upstream:,}"

    def test_no_pinned_limit_is_unchecked(self):
        """Catch a seventh limit added to constants.py and never compared."""
        declared = {
            name
            for name in dir(pyrxd_constants)
            if (name.startswith("MAX_") or name.endswith("_THRESHOLD"))
            and isinstance(getattr(pyrxd_constants, name), int)
            and name != "MAX_OPCODE"  # derived, not a literal — checked separately above
            # pyrxd's OWN encoder bound, not a Radiant limit: the miner emits the message
            # with OP_PUSHDATA1, whose length field is one byte, so 255 is the most it can
            # express. Radiant's would-be datacarrier limits (nMaxDatacarrierBytes=1024,
            # MAX_OP_RETURN_RELAY=223) are standardness, and standardness never runs here
            # (fRequireStandard is hardcoded false). There is nothing upstream to compare to.
            and name != "MAX_OP_RETURN_MSG_BYTES"
        }
        unchecked = declared - set(_PINNED_SCALAR_LIMITS)
        assert not unchecked, (
            f"these pinned constants are never compared against Radiant Core: {sorted(unchecked)}. "
            f"Add them to _PINNED_SCALAR_LIMITS (and to consensus_oracle.script_limit if the "
            f"C++ declares them differently)."
        )

    def test_the_radiant_push_limit_is_not_bitcoins(self):
        """Radiant raised it to 32,000,000 and kept 520 under a ``_LEGACY`` name.

        Pinned as its own assertion because "MAX_SCRIPT_ELEMENT_SIZE is 520" is
        the single most likely thing for someone to believe while wiring this
        constant into a builder, and it would reject scripts the chain accepts.
        """
        assert script_limit("MAX_SCRIPT_ELEMENT_SIZE") == 32_000_000
        assert script_limit("MAX_SCRIPT_ELEMENT_SIZE_LEGACY") == 520


#: The per-script resource budgets, and the values ``consensus.h`` gives them.
#: Pinned as literals on purpose: this is the one fact in this file with no
#: pyrxd-side constant to compare against (pyrxd builds and parses scripts, it
#: has no interpreter), so the assertion's whole job is to turn an upstream
#: change into a reviewable diff rather than a silent one. ``ONE_MEGABYTE`` is
#: 1,000,000 here, not 1,048,576 — reading the budget as 2^20-based overstates
#: the memory ceiling by 6.3 MB.
_PINNED_SCRIPT_BUDGETS = {
    "MAX_SCRIPT_STACK_MEMORY_USAGE": 128_000_000,
    "MAX_SCRIPT_OPCODE_COST": 1_000_000_000,
}


class TestScriptResourceBudgets:
    """The budgets ``interpreter.cpp`` enforces and ``consensus/consensus.h`` declares.

    Both were cited in pyrxd comments while the header that defines them was not
    vendored, so their VALUES could not be checked by anything — the same shape
    as the ref-operand rule: a consensus number in the repo with no mechanism
    tying it to the C++.
    """

    @pytest.mark.parametrize(("name", "expected"), sorted(_PINNED_SCRIPT_BUDGETS.items()))
    def test_budget_matches_radiant(self, name, expected):
        upstream = consensus_limit(name)
        assert upstream == expected, (
            f"Radiant's consensus.h declares {name}={upstream:,}; this test pins {expected:,}. "
            "A budget moving upstream is a consensus change — read the diff before re-pinning."
        )

    def test_no_enforced_budget_is_unpinned(self):
        """The set comes from ``interpreter.cpp``'s comparisons, not from a list.

        Both directions: a budget the interpreter enforces and nothing here pins
        is the gap this test exists for, and a name pinned above that the
        interpreter never compares against means the pin has stopped describing
        anything.
        """
        enforced = script_budgets_enforced_by_interpreter()
        assert enforced == set(_PINNED_SCRIPT_BUDGETS), (
            "the consensus.h budgets EvalScript compares against and the ones pinned here differ.\n"
            f"  enforced, not pinned: {sorted(enforced - set(_PINNED_SCRIPT_BUDGETS))}\n"
            f"  pinned, not enforced: {sorted(set(_PINNED_SCRIPT_BUDGETS) - enforced)}"
        )

    def test_the_memory_budget_admits_a_maximum_size_push(self):
        """Cross-file consistency, ``consensus.h`` against ``script.h``.

        ``MAX_SCRIPT_ELEMENT_SIZE`` is what a builder may push; the stack-memory
        budget is what the interpreter will hold. A budget at or below the push
        limit would make a single legal push unspendable, so the two limits
        being read from the same pin and still disagreeing is a fact worth
        failing on rather than a coincidence worth assuming.
        """
        budget = consensus_limit("MAX_SCRIPT_STACK_MEMORY_USAGE")
        element = script_limit("MAX_SCRIPT_ELEMENT_SIZE")
        assert budget > element, (
            f"the stack-memory budget ({budget:,}) does not exceed the maximum pushable element "
            f"({element:,}); a single maximum-size push would exhaust it."
        )
