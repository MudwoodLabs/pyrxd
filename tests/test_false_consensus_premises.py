"""Regression tests for Bitcoin rules that this SDK used to assert as Radiant's.

Each rule below was checked against Radiant Core at tag ``v3.1.2``
(``45e0aa40d6ae022ba69439a58b706748b083a35b`` — the pin in
``tests/vendor/radiant_core/MANIFEST.json``), not against pyrxd's own docs:

============================  =======================================================
Radiant's actual rule          Where it lives
============================  =======================================================
``GetDustThreshold`` == 1 sat  ``src/policy/policy.cpp:19-21``
``IsDust`` is ``nValue <= 0``  ``src/policy/policy.cpp:23-25``
``fRequireStandard`` == false  ``src/validation.cpp:271``; ``src/init.cpp:1995``
OP_RETURN policy cap == 1024   ``DEFAULT_DATACARRIER_BYTES``, ``src/script/standard.h:35``
relay floor 10_000_000 / kB    ``src/policy/policy.h:49``; charged at ``src/validation.cpp:779``
target block time 300s         ``nPowTargetSpacing``, ``src/chainparams.cpp:117``
Radiant SLIP-0044 coin type    512
============================  =======================================================

None of these is Bitcoin's number. The tests here fail if any of the corrected
premises regresses.
"""

from __future__ import annotations

import functools
import re
from pathlib import Path

import pytest

from pyrxd.constants import (
    DUST_THRESHOLD_PHOTONS,
    MAX_OP_RETURN_MSG_BYTES,
    TRANSACTION_FEE_RATE,
)
from pyrxd.fee_sizing import RADIANT_EFFECTIVE_MIN_RELAY_PHOTONS_PER_KB, min_relay_fee
from pyrxd.glyph.dmint import (
    DaaMode,
    DmintContractUtxo,
    DmintDeployParams,
    DmintMinerFundingUtxo,
    DmintState,
    build_dmint_contract_script,
    build_dmint_mint_tx,
    build_dmint_v1_contract_script,
)
from pyrxd.glyph.types import GlyphRef
from pyrxd.keys import PrivateKey
from pyrxd.script.type import P2PKH
from pyrxd.security.errors import PoolTooSmallError, ValidationError
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src" / "pyrxd"

_CONTRACT_REF = GlyphRef(txid="bb" * 32, vout=1)
_TOKEN_REF = GlyphRef(txid="bb" * 32, vout=0)
_MINER_PKH = b"\x33" * 20
_NONCE_V2 = bytes(8)
_NONCE_V1 = bytes(4)


def _contract_utxo(*, is_v1: bool = False) -> DmintContractUtxo:
    """A synthetic 1-photon dMint contract singleton (V1 or V2)."""
    if is_v1:
        script = build_dmint_v1_contract_script(
            height=0,
            contract_ref=_CONTRACT_REF,
            token_ref=_TOKEN_REF,
            max_height=100,
            reward=1_000,
            target=0x7FFFFFFFFFFFFFFF,
        )
    else:
        script = build_dmint_contract_script(
            DmintDeployParams(
                contract_ref=_CONTRACT_REF,
                token_ref=_TOKEN_REF,
                max_height=100,
                reward=1_000,
                difficulty=10,
                height=0,
                daa_mode=DaaMode.FIXED,
                target_time=60,
                half_life=3_600,
                last_time=0,
            )
        )
    state = DmintState.from_script(script)
    assert state.is_v1 is is_v1
    return DmintContractUtxo(txid="cc" * 32, vout=0, value=1, script=script, state=state)


def _funding(value: int = 500_000_000) -> DmintMinerFundingUtxo:
    return DmintMinerFundingUtxo(txid="aa" * 32, vout=0, value=value, script=b"\x76\xa9\x14" + bytes(20) + b"\x88\xac")


def _mint(*, is_v1: bool, op_return_msg: bytes | None, funding_value: int = 500_000_000):
    return build_dmint_mint_tx(
        _contract_utxo(is_v1=is_v1),
        _NONCE_V1 if is_v1 else _NONCE_V2,
        _MINER_PKH,
        0,
        funding_utxo=_funding(funding_value),
        op_return_msg=op_return_msg,
    )


# ---------------------------------------------------------------------------
# 1. The 80-byte OP_RETURN "standardness limit"
# ---------------------------------------------------------------------------
@functools.cache
def _citation_corpus() -> tuple[tuple[Path, tuple[str, ...]], ...]:
    """Every file a stale-citation check has to scan, read once.

    Three roots x two glob patterns x one read per file, previously redone for each
    parametrised ``stale`` value. Returns tuples so a cached result cannot be mutated
    by one case and observed by the next.
    """
    roots = [SRC, REPO_ROOT / "docs" / "runbooks", REPO_ROOT / "docs" / "reference"]
    return tuple(
        (path, tuple(path.read_text().splitlines()))
        for root in roots
        for path in list(root.rglob("*.py")) + list(root.rglob("*.md"))
    )


class TestOpReturnCapIsAnEncoderLimitNotStandardness:
    """Radiant never runs ``IsStandardTx`` (``fRequireStandard`` is hardcoded
    ``false``), so Bitcoin's 80-byte OP_RETURN cap has no force here. Even if it
    ran, the limit applied is ``nMaxDatacarrierBytes``, default
    ``DEFAULT_DATACARRIER_BYTES`` = 1024. pyrxd's real bound is its own
    OP_PUSHDATA1 encoder: a one-byte length field, hence 255."""

    def test_cap_is_255_not_80(self):
        assert MAX_OP_RETURN_MSG_BYTES == 255

    @pytest.mark.parametrize("is_v1", [False, True], ids=["v2", "v1"])
    @pytest.mark.parametrize("size", [81, 200, 255])
    def test_mint_accepts_op_return_over_80_bytes(self, is_v1: bool, size: int):
        """The refusal at 81..255 bytes was the false-premise lockout."""
        result = _mint(is_v1=is_v1, op_return_msg=b"z" * size)
        op_return = [o for o in result.tx.outputs if o.locking_script.serialize()[:1] == b"\x6a"]
        assert len(op_return) == 1
        script = op_return[0].locking_script.serialize()
        # OP_RETURN 0x03 "msg" OP_PUSHDATA1 <len> <body>
        assert script[:5] == b"\x6a\x03msg"
        assert script[5:7] == bytes([0x4C, size])
        assert script[7:] == b"z" * size

    @pytest.mark.parametrize("is_v1", [False, True], ids=["v2", "v1"])
    def test_mint_still_refuses_over_255_bytes(self, is_v1: bool):
        """256 bytes cannot be expressed by OP_PUSHDATA1 — a real limit."""
        with pytest.raises(ValidationError) as exc:
            _mint(is_v1=is_v1, op_return_msg=b"z" * 256)
        assert "OP_PUSHDATA1" in str(exc.value)

    @pytest.mark.parametrize("is_v1", [False, True], ids=["v2", "v1"])
    def test_refusal_no_longer_blames_standardness(self, is_v1: bool):
        with pytest.raises(ValidationError) as exc:
            _mint(is_v1=is_v1, op_return_msg=b"z" * 300)
        assert "standardness" not in str(exc.value).lower()

    def test_no_source_file_claims_an_80_byte_standardness_limit(self):
        offenders = [
            f"{p.relative_to(REPO_ROOT)}:{n}"
            for p in SRC.rglob("*.py")
            for n, line in enumerate(p.read_text().splitlines(), start=1)
            if "standardness limit is 80" in line or "standardness limit is 80 bytes" in line
        ]
        assert offenders == []


# ---------------------------------------------------------------------------
# 2. 546 — one definition, honestly labelled
# ---------------------------------------------------------------------------


class TestDustThresholdHasOneDefinition:
    """546 is Bitcoin's P2PKH dust convention. On Radiant it is pyrxd POLICY:
    ``GetDustThreshold`` returns 1 satoshi and ``IsDust`` is ``nValue <= 0``."""

    def test_every_radiant_side_alias_is_the_shared_constant(self):
        from pyrxd.glyph.builder import CommitParams
        from pyrxd.glyph.ft import DUST_LIMIT as FT_DUST_LIMIT
        from pyrxd.glyph.mint import NFT_CARRIER_VALUE
        from pyrxd.gravity.htlc_spend import DUST_FLOOR_PHOTONS
        from pyrxd.swap.partial import _DUST_PHOTONS as PARTIAL_DUST
        from pyrxd.swap.rswp.covenant import _DUST_PHOTONS as RSWP_DUST
        from pyrxd.wallet import DUST_THRESHOLD

        for alias in (
            DUST_THRESHOLD,
            FT_DUST_LIMIT,
            NFT_CARRIER_VALUE,
            DUST_FLOOR_PHOTONS,
            PARTIAL_DUST,
            RSWP_DUST,
            CommitParams.__dataclass_fields__["dust_limit"].default,
        ):
            assert alias == DUST_THRESHOLD_PHOTONS

    def test_bitcoin_leg_keeps_its_own_546_deliberately(self):
        """The BTC leg's 546 IS Bitcoin's real rule and must not be aliased away."""
        from pyrxd.btc_wallet import payment

        assert payment.DUST_LIMIT == 546
        src = (SRC / "btc_wallet" / "payment.py").read_text()
        assert "BITCOIN's dust limit" in src

    def test_only_two_modules_define_a_546_literal(self):
        """One Radiant-side definition (``constants``) + Bitcoin's (``btc_wallet``)."""
        allowed = {"constants.py", "btc_wallet/payment.py"}
        # An OPERATIONAL 546: assigned, compared, or passed as an argument. Prose that
        # explains the number is fine and is the point; a bare literal that a future edit
        # can move independently of the shared constant is not.
        pattern = re.compile(r"[=<>+\-*/(,\[]\s*546(?![\w])")
        offenders = set()
        for path in SRC.rglob("*.py"):
            rel = path.relative_to(SRC).as_posix()
            if rel in allowed:
                continue
            for n, line in enumerate(path.read_text().splitlines(), start=1):
                code = line.split("#", 1)[0]
                if pattern.search(code):
                    offenders.add(f"{rel}:{n}: {line.strip()}")
        assert offenders == set(), f"operational 546 literals outside the one definition: {sorted(offenders)}"

    def test_dmint_pool_too_small_does_not_claim_a_node_dust_limit(self):
        """The message used to read 'below 546 dust limit' — a limit no node applies."""
        # Reward 1_000 + fee; a funding UTXO just short of clearing the policy floor.
        with pytest.raises(PoolTooSmallError) as exc:
            _mint(is_v1=False, op_return_msg=None, funding_value=1_200)
        msg = str(exc.value)
        assert "dust limit" not in msg
        assert "pyrxd" in msg
        assert "Radiant's floor is 1 photon" in msg

    def test_no_source_file_says_below_546_dust_limit(self):
        offenders = [
            f"{p.relative_to(REPO_ROOT)}:{n}"
            for p in SRC.rglob("*.py")
            for n, line in enumerate(p.read_text().splitlines(), start=1)
            if "below 546 dust limit" in line
        ]
        assert offenders == []


# ---------------------------------------------------------------------------
# 3. Transaction.fee() default
# ---------------------------------------------------------------------------


class TestDefaultFeeRateClearsTheRelayFloor:
    """The old 5 photons/kB default was 2_000_000x under Radiant's floor, and
    Radiant has neither RBF nor CPFP to repair an under-fee'd transaction."""

    def test_constant_is_the_relay_floor(self):
        assert TRANSACTION_FEE_RATE == RADIANT_EFFECTIVE_MIN_RELAY_PHOTONS_PER_KB

    def test_default_model_pays_at_least_the_relay_floor(self):
        key = PrivateKey(998)
        locking = P2PKH().lock(key.address())
        src_tx = Transaction(tx_inputs=[], tx_outputs=[TransactionOutput(locking, 1_000_000_000)])
        tx = Transaction(
            tx_inputs=[
                TransactionInput(
                    source_transaction=src_tx,
                    source_output_index=0,
                    unlocking_script_template=P2PKH().unlock(key),
                )
            ],
            tx_outputs=[
                TransactionOutput(locking, 100_000_000, change=False),
                TransactionOutput(locking, None, change=True),
            ],
        )
        tx.fee()  # default model
        change = tx.outputs[-1].satoshis
        assert change is not None
        paid = 1_000_000_000 - 100_000_000 - change
        assert paid >= min_relay_fee(tx.estimated_byte_length())


# ---------------------------------------------------------------------------
# 4. BIP44 coin type
# ---------------------------------------------------------------------------


class TestBip44GuidanceUsesRadiantsCoinType:
    def test_hardened_derivation_error_suggests_512_not_0(self):
        from pyrxd.hd.bip32 import Xprv

        xprv = Xprv.from_seed(bytes(range(64)))
        with pytest.raises(ValidationError) as exc:
            xprv.xpub().ckd(0x80000000)
        message = str(exc.value)
        assert "m/44'/512'/0'" in message
        assert "m/44'/0'/0'" not in message

    def test_default_derivation_path_is_radiants(self):
        from pyrxd.constants import BIP44_DERIVATION_PATH

        assert BIP44_DERIVATION_PATH == "m/44'/512'/0'"


# ---------------------------------------------------------------------------
# 5. Block time and citation anchoring (prose that a reader will act on)
# ---------------------------------------------------------------------------


class TestProseAgreesWithRadiantCore:
    def test_no_doc_claims_a_two_minute_block_time(self):
        """``nPowTargetSpacing = 5 * 60`` on mainnet, testnet, scalenet and regtest."""
        tutorial = (REPO_ROOT / "docs" / "tutorials" / "mint-a-glyph-nft.md").read_text()
        assert "target block time is ~2 minutes" not in tutorial
        assert "~5 minutes" in tutorial
        confirm = (SRC / "network" / "confirm.py").read_text()
        assert "Radiant blocks target ~5 minutes" in confirm

    @pytest.mark.parametrize(
        "stale",
        ["init.cpp:1965", "feerate.cpp:51", "miner.cpp:380", "validation.cpp:856", "validation.cpp:770"],
    )
    def test_no_citation_points_at_a_stale_line_number(self, stale: str):
        """Line numbers are at the tag ``tests/vendor/radiant_core/MANIFEST.json`` pins."""
        offenders = [
            f"{path.relative_to(REPO_ROOT)}:{n}"
            for path, lines in _citation_corpus()
            for n, line in enumerate(lines, start=1)
            if stale in line
        ]
        assert offenders == []

    def test_vendor_readme_states_the_citation_anchor(self):
        readme = (REPO_ROOT / "tests" / "vendor" / "radiant_core" / "README.md").read_text()
        assert "anchor for every Radiant-Core line citation" in readme

    def test_changelog_no_longer_states_the_wrong_case_count(self):
        changelog = (REPO_ROOT / "CHANGELOG.md").read_text()
        assert "(442 cases)" not in changelog
        assert "459 collected cases" in changelog


# ---------------------------------------------------------------------------
# 6. The premise, not one spelling of it
# ---------------------------------------------------------------------------
#
# Every literal scan above pins ONE sentence ("standardness limit is 80",
# "below 546 dust limit"). Both were real, and both are blind to the next author
# who writes the same false premise in different words — which is how
# ``script/type.py`` came to say "is not relayed" twice and
# ``swap/rswp/covenant.py`` to say "(node-rejected)" while ``glyph/ft.py`` and
# ``glyph/builder.py`` already spelled out, correctly, that neither can happen.
#
# The premise underneath all of them is one fact: *standardness has force on a
# default Radiant node*. It does not. ``IsStandardTx`` is reached from exactly
# one place (``validation.cpp:586`` @ ``v3.1.2``), gated on ``fRequireStandard``,
# which is hardcoded ``false`` (``validation.cpp:271``) — so ``IsDust``
# (``policy.h:173``), the output-script classifier, and every other standardness
# rule never run. This scan is keyed to that fact instead of to a sentence.

#: Prose naming a standardness / dust SUBJECT. Presence of one of these is what
#: makes a nearby refusal a *standardness* claim rather than a fee or consensus
#: claim — the min-relay-fee floor and BIP68 maturity DO make nodes reject
#: transactions, and prose saying so is true and must survive this scan.
_STANDARDNESS_SUBJECT = re.compile(r"standardness|non-?standard|TX_NONSTANDARD|IsStandardTx|IsDust|dust", re.I)

#: The asserted CONSEQUENCE: a node refusing the transaction.
_NODE_REFUSAL = re.compile(
    r"not\s+be\s+relay|not\s+relay|never\s+relay|won'?t\s+relay|will\s+not\s+relay|non-?relayable|"
    r"node-rejected|rejected\s+by\s+(?:the\s+|most\s+|a\s+|any\s+)?node|node\s+(?:will|would|may)\s+reject|"
    r"refus\w+\s+by\s+(?:the\s+|a\s+)?node|reject\w*\s+for\s+relay",
    re.I,
)

#: Prose that REFUTES the premise in the same breath is the correct writing and
#: must not be flagged — a correction has to be able to quote the claim it is
#: correcting. Each of these names the reason the rule does not run.
_PREMISE_REFUTED = re.compile(
    r"fRequireStandard|never\s+consult|not\s+consult|never\s+run|no\s+path\s+by\s+which|"
    r"NOT\s+a\s+(?:node|chain|Radiant)\s+rule|no\s+force\s+on\s+Radiant",
    re.I,
)

#: Characters either side of a refusal that count as "the same breath". Measured,
#: not chosen: the three offenders live on the parent commit need windows of 25,
#: 40 and 555 characters to reach their subject — the widest being
#: ``script/type.py``'s second "is not relayed", whose subject is the
#: ``TX_NONSTANDARD`` nine lines above it. 600 clears that with a little headroom;
#: wider starts joining unrelated paragraphs.
_PREMISE_WINDOW = 600

#: Bitcoin and Ethereum subtrees. Bitcoin really does enforce a 546-satoshi dust
#: rule and really does refuse non-standard scripts, so the same sentence there
#: is TRUE — excluded rather than allowlisted, because the exclusion is a chain
#: boundary and not a list of forgiven lines.
_OTHER_CHAIN_PREFIXES = ("btc_wallet/", "eth_wallet/")


def _premise_hits(text: str) -> list[tuple[int, str]]:
    """Every asserted standardness refusal in *text*, as ``(line, matched phrase)``."""
    return [
        (text[: m.start()].count("\n") + 1, m.group(0))
        for m in _NODE_REFUSAL.finditer(text)
        for window in [text[max(0, m.start() - _PREMISE_WINDOW) : m.end() + _PREMISE_WINDOW]]
        if _STANDARDNESS_SUBJECT.search(window) and not _PREMISE_REFUTED.search(window)
    ]


@functools.cache
def _premise_corpus() -> tuple[tuple[str, str], ...]:
    """Shipped Radiant-side source plus the published docs, as ``(label, text)``.

    ``docs/brainstorms`` and ``docs/plans`` are deliberately absent: they are
    working space where a wrong premise may legitimately be written down and
    then argued with.
    """
    files = [(p, p.relative_to(SRC).as_posix()) for p in sorted(SRC.rglob("*.py"))]
    files = [(p, f"src/pyrxd/{rel}") for p, rel in files if not rel.startswith(_OTHER_CHAIN_PREFIXES)]
    for sub in ("how-to", "runbooks", "reference", "tutorials"):
        root = REPO_ROOT / "docs" / sub
        files += [(p, p.relative_to(REPO_ROOT).as_posix()) for p in sorted(root.rglob("*.md"))]
    return tuple((label, path.read_text()) for path, label in files)


class TestNoProseAssertsAStandardnessRefusal:
    """A node-level refusal asserted for a standardness or dust reason is false here.

    What this covers: any sentence in shipped Radiant-side source or published
    docs that pairs a standardness/dust subject with "the node rejects it" or
    "it is not relayed", in either order, within ``_PREMISE_WINDOW`` characters,
    without also stating why the rule does not run.

    What it does NOT cover, said plainly rather than implied:

    * The *other* shape of the same premise — "the limit is N" (Bitcoin's 80-byte
      OP_RETURN cap, the 546 floor). Those remain pinned by the two literal
      checks in sections 1 and 2, which this does not subsume.
    * A refusal with no standardness subject within the window. That shape is
      indistinguishable from the honest fee refusal at
      ``swap/rswp/covenant.py``'s ``_assert_relayable``, so it is left alone on purpose.
    * Semantics. It matches phrasing, so a claim written in words it does not
      know stays invisible. It is a net, not a proof.
    * Anything outside the corpus: the BTC/ETH subtrees (where the rules are
      real), brainstorms and plans (working space), and tests.

    If it fires on an honest sentence — a genuine min-relay-fee or BIP68
    refusal that happens to sit near the word "dust" — the fix is to say which
    rule does the rejecting, not to widen the pattern.
    """

    def test_no_shipped_file_asserts_a_standardness_refusal(self):
        offenders = [
            f"{label}:{line}: {phrase!r}" for label, text in _premise_corpus() for line, phrase in _premise_hits(text)
        ]
        assert offenders == [], (
            "standardness/dust is asserted as a node-level refusal, but Radiant never reaches "
            f"IsStandardTx (validation.cpp:271/586 @ v3.1.2): {offenders}"
        )

    def test_the_corpus_is_not_empty(self):
        """A pass must mean "nothing asserts it", never "nothing was scanned"."""
        corpus = _premise_corpus()
        assert len(corpus) > 100, f"only {len(corpus)} files scanned — the corpus roots have moved"
        assert any(label == "src/pyrxd/script/type.py" for label, _ in corpus)
        assert any(label.startswith("docs/") for label, _ in corpus)

    @pytest.mark.parametrize(
        "claim",
        [
            # The three that were live on the parent commit...
            "A reservation below the dust floor produces an unspendable (node-rejected) covenant UTXO.",
            "``OP_FALSE OP_RETURN`` falls through to ``TX_NONSTANDARD`` and is not relayed.",
            "Core classifies it TX_NONSTANDARD, so such an output is not relayed. Opt in only if "
            "you know the node you are broadcasting to accepts it.",
            # ...and spellings that have never appeared in this repo, which is the
            # point: a scan proved only against its own examples proves nothing.
            "an output below the dust threshold will not be relayed by any node",
            "a nonstandard script is rejected by the node, so keep the output above 546",
            "sub-dust change is non-relayable and must be folded into the fee",
            "outputs under the dust limit are refused by the node at relay time",
            "the node will reject a transaction carrying a non-standard output script",
        ],
    )
    def test_the_scan_catches_spellings_it_was_not_written_from(self, claim: str):
        assert _premise_hits(claim), f"premise scan is blind to: {claim}"

    @pytest.mark.parametrize(
        "claim",
        [
            # Radiant DOES charge a min-relay fee (validation.cpp:779) and DOES
            # enforce BIP68 maturity (interpreter.cpp:3006-3023). Refusing these
            # would make the guard itself a bug.
            "Refuse to return a v2 transaction the node will reject as ``min relay fee not met``.",
            "THE CSV IS NOT MATURE - a node will reject this refund until it is. Do not send it yet.",
            "Radiant has NO dust threshold and standardness is not consulted, so nothing is rejected by the node.",
            # A DELIBERATE blind spot, asserted so it stays deliberate: a refusal
            # with no standardness subject anywhere near it is indistinguishable
            # from the honest fee refusal above, so this scan does not judge it.
            # ``swap/rswp/covenant.py``'s ``_assert_relayable`` is this shape, and TRUE.
            "Refuse to return a v3 covenant transaction the node will not relay.",
        ],
    )
    def test_the_scan_leaves_true_node_refusals_alone(self, claim: str):
        assert not _premise_hits(claim), f"premise scan refuses an honest sentence: {claim}"
