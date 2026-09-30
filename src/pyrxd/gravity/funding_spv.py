"""The swap TAKER GATE: prove the maker's Radiant funding before the taker locks anything.

Before this module, :meth:`pyrxd.gravity.swap_coordinator.SwapCoordinator.taker_verify_asset_funding`
read the maker's covenant UTXO — its scriptPubKey, its value and its depth — from ONE ElectrumX
server's ``listunspent`` and verbose ``confirmations``, with no merkle proof and no header. A server
that invented the covenant made the real coordinator lock the taker's counter leg against an output
that exists on no chain. This module is what the coordinator runs instead.

WHAT IS PROVED, for the one funding transaction the taker is about to rely on:

* its raw bytes hash to its txid, and its output ``vout`` — parsed from those bytes, NOT taken from
  ``listunspent`` — pays exactly the covenant scriptPubKey the taker re-derived from its own terms,
  for exactly the negotiated photon value;
* it is in the block at the height the server named: its merkle branch leads to that block's header,
  at the depth the block's coinbase branch pins (:func:`pyrxd.glyph.mark_block.verify_mark_block`,
  the verifier ``pyrxd verify`` runs, reused here rather than re-implemented);
* that header is linked hash by hash to a checkpoint pyrxd ships, and every header above the newest
  checkpoint that the server served meets its own proof-of-work target and the work floor
  (checkpoint work ÷ :data:`~pyrxd.glyph.mark_block.FLOOR_WORK_DIVISOR`);
* at least ``k`` of those blocks, counting the funding block as 1, where ``k`` is the SETTLED RULE
  below. Anything short of that refuses the lock.

THE RULE (maintainer decision, 2026-09-30)::

    k = max(6, burial, ceil(2 × value_at_stake ÷ C))
    C = floor(subsidy(H) × floor_work ÷ max_header_work)

``C`` is what one forged confirmation costs, in photons: a server lying about the funding can serve
the real headers below the funding height and has to MINE only the headers from there up, each at
the floor or above (see :mod:`pyrxd.glyph.mark_block`, "WHAT THAT COSTS A LIAR"). Mining a
floor-work header costs the fraction ``floor_work ÷ real_work`` of a real block, whose reward is the
subsidy — so ``C`` prices it at the subsidy scaled by that fraction. Every input is pyrxd's own or
proved here, never a server's figure:

* ``subsidy(H)`` — Radiant Core's ``GetBlockSubsidy``: ``50000 * COIN >> (H /
  nSubsidyHalvingInterval)``, zero from 64 halvings (``tests/vendor/radiant_core/validation.cpp``
  lines 1108-1119), with ``nSubsidyHalvingInterval`` 210,000 on mainnet and 150 on regtest
  (``tests/vendor/radiant_core/chainparams.cpp`` lines 96 and 447). Both files are vendored verbatim
  at the pinned tag and a test re-derives these constants from them.
* ``floor_work`` — the newest shipped checkpoint's header work ÷ 16, the floor the verifier enforces.
* ``max_header_work`` — the MOST work any header carries, over every header the verifier checked
  in this run AND the whole last checkpoint interval (linked between the two newest shipped
  checkpoints). The maximum, because a higher real work makes the floor a smaller fraction of a real
  block, i.e. a cheaper forgery and a smaller ``C``; including the checkpoint interval keeps a server
  from lowering it by serving only easy headers above the checkpoint.

``burial`` is the swap's existing Radiant reorg burial (the policy's measured claim burial, raised by
the value-scaled burial of :func:`pyrxd.gravity.swap_coordinator._value_scaled_burial_blocks`), and
``value_at_stake`` is the swap's value in photons as the coordinator already assesses it. On a
value-bearing network a missing value, or a ``C`` of zero, refuses: there is nothing to size ``k``
from. On a test network (regtest) there is no value to protect, so ``k`` is the configured depth —
but the proof is the same one: the same linkage, proof-of-work and merkle code, anchored to the
network's genesis, which is its only checkpoint.

FRESHNESS. The walk from the newest checkpoint is capped at :data:`MAX_HEADERS_FROM_CHECKPOINT_SDK`
(20,160 headers) here, against the pages' 4,032 (maintainer decision, 2026-09-30). When ``H + k - 1``
lies past it, the refusal says to upgrade pyrxd (newer checkpoints) or verify against the taker's
own node — never to proceed.

THE UPPER BOUND ON ELAPSED DEPTH. SPV proves a LOWER bound on how deep the funding is. The timelock
gates that follow (``pre_btc_lock_check`` steps 6 and 7) need an UPPER bound, because ``t_rxd`` is a
CSV counted from the covenant's mining and an under-counted depth makes the maker's refund look
further away than it is. A server can under-count by withholding its newest headers. The bound used
is::

    max(proved, (R - H + 1) + ceil(max(0, now - T_R) ÷ interval), reported)

where ``R`` is the REFERENCE header: the one ``max(1, value_term)`` deep below the newest header
served (the newest counting as 1), and ``T_R`` its timestamp. The blocks from the funding up to
``R`` are proved; every block after ``R`` is covered by the allowance for all that could have been
mined since ``T_R``, at the interval the coordinator uses for converting time to blocks (the
measured fast tail, required on a value-bearing network). The server's own verbose
``confirmations`` can only raise it. A server that stops serving at an older header hands the taker
an older ``T_R`` and a larger allowance — the withholding shows up as elapsed time.

WHY THAT DEPTH. Elapsed time is measured from a header deep enough that changing its time costs as
much as the rule already demands of the depth: a different header at ``R`` means different headers
above it too, each mined at the floor or above, which prices it at ``value_term × C ≥ 2 × value at
stake`` — the value term of ``k``. Deeper would charge every honest swap the time of more blocks at
the fast-tail rate without raising that price past what ``k`` already settles. ``value_term <= k <=
proved``, so ``R`` is never below the funding block. A test network has no value term, and ``R`` is
the newest header served.

The clock is the caller's (``now_unix_s``); the coordinator never reads one. It is REQUIRED on a
value-bearing network; on a test network without it the allowance is omitted and the result says so.

WHAT REMAINS THE SERVER'S WORD, stated rather than implied:

* that the covenant output is still UNSPENT. SPV proves a transaction was mined, never that an
  output has not been spent since; the ``listunspent`` read that locates the outpoint is kept for
  that, and is no longer the evidence of the output's existence, script or value.
* withholding hidden inside the allowance above: the reference header's timestamp is set by its miner,
  and Radiant Core accepts one up to ``MAX_FUTURE_BLOCK_TIME`` ahead of its adjusted time
  (``tests/vendor/radiant_core/validation.cpp`` line 3936; the constant lives in ``chain.h``, which
  is not vendored — two hours in the Bitcoin Core lineage), so a reference header its miner dated
  ahead can hide the blocks mined in that difference; so can blocks arriving faster
  than the fast-tail interval. No tolerance is added for it: adding the full limit would charge
  every honest swap that many hours of blocks.
* which chain is Radiant's most-work chain, and whether each nBits is the value Radiant's
  difficulty rules require: neither is checked (see :mod:`pyrxd.glyph.mark_block`); the floor and
  ``k`` bound what a forgery costs instead.
* the checkpoint table itself is only as good as its sources (see
  :mod:`pyrxd.spv.radiant_checkpoints`).
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from pyrxd.btc_wallet.htlc_leg import AUDIT_CLEARED_NETWORKS
from pyrxd.constants import GENESIS_BLOCK_HASHES
from pyrxd.eth_wallet.chains import KNOWN_EVM_CHAINS
from pyrxd.glyph.mark_block import (
    FLOOR_WORK_DIVISOR,
    MAX_HEADERS_PER_REQUEST,
    VERIFIED,
    plan_block_verification,
    verify_mark_block,
)
from pyrxd.gravity.reorg_cost import PHOTONS_PER_RXD
from pyrxd.hash import hash256, radiant_block_hash
from pyrxd.security.errors import ValidationError
from pyrxd.security.types import BlockHeight
from pyrxd.spv.radiant import radiant_header_prev_hash, radiant_header_work
from pyrxd.spv.radiant_checkpoints import CHECKPOINTS
from pyrxd.transaction.transaction import Transaction

__all__ = [
    "FORGERY_COST_FACTOR",
    "LOCAL_DEVNET_CHAIN_IDS",
    "MAX_HEADERS_FROM_CHECKPOINT_SDK",
    "MIN_FUNDING_CONFIRMATIONS",
    "MakerFundingEvidence",
    "MakerFundingNotVerified",
    "RadiantChain",
    "VerifiedMakerFunding",
    "block_subsidy_photons",
    "forged_confirmation_cost_ceiling_photons",
    "funding_header_ranges",
    "radiant_chain_for_leg",
    "required_funding_confirmations",
    "verify_maker_funding",
]

# ── PARAMETERS — maintainer decisions for phase 2b, 2026-09-30. ─────────────────────────────────
# Each changes what the taker gate accepts; a change needs the maintainer's sign-off and a
# CHANGELOG entry.

#: The fewest confirmations a value-bearing funding is accepted at, whatever the value.
MIN_FUNDING_CONFIRMATIONS = 6

#: ``k`` makes forging the funding cost at least this multiple of the value at stake.
FORGERY_COST_FACTOR = 2

#: The most headers linked above the newest checkpoint by this gate (ten checkpoint intervals).
#: The browser pages and ``pyrxd verify`` keep :data:`pyrxd.glyph.mark_block.MAX_HEADERS_FROM_CHECKPOINT`.
MAX_HEADERS_FROM_CHECKPOINT_SDK = 20_160

# ─────────────────────────────────────────────────────────────────────────────────────────────

#: ``GetBlockSubsidy``'s starting reward, ``50000 * COIN`` (``tests/vendor/radiant_core/validation.cpp``
#: line 1115), in photons.
INITIAL_SUBSIDY_PHOTONS = 50_000 * PHOTONS_PER_RXD


class MakerFundingNotVerified(ValidationError):
    """The maker's Radiant funding could not be proved to the depth this swap requires.

    A :class:`~pyrxd.security.errors.ValidationError`, so every existing fail-closed handler on the
    lock path refuses on it. The message names what was required and what was proved.
    """


@dataclass(frozen=True)
class RadiantChain:
    """The consensus facts the gate needs for one Radiant network, all from the vendored sources."""

    name: str
    #: ``((height, block hash display hex), ...)`` ascending — the anchors headers are linked to.
    checkpoints: tuple[tuple[int, str], ...]
    #: ``consensus.powLimit``.
    pow_limit: int
    #: ``consensus.nSubsidyHalvingInterval``.
    subsidy_halving_interval: int
    #: Whether a swap on it moves real value (then the value term and the clock are required).
    value_bearing: bool


#: Radiant mainnet: the shipped checkpoint table; ``powLimit`` ``00000000ff…ff`` and halving interval
#: 210,000 (``tests/vendor/radiant_core/chainparams.cpp`` lines 113-114 and 96).
MAINNET_CHAIN = RadiantChain(
    name="mainnet",
    checkpoints=CHECKPOINTS["mainnet"],
    pow_limit=(1 << 224) - 1,
    subsidy_halving_interval=210_000,
    value_bearing=True,
)

#: Radiant regtest: no shipped table, so its genesis (``chainparams.cpp`` line 509, and
#: :data:`pyrxd.constants.GENESIS_BLOCK_HASHES`) is the one checkpoint; ``powLimit`` ``7fff…ff`` and
#: halving interval 150 (lines 465-466 and 447).
REGTEST_CHAIN = RadiantChain(
    name="regtest",
    checkpoints=((0, GENESIS_BLOCK_HASHES["regtest"]),),
    pow_limit=(1 << 255) - 1,
    subsidy_halving_interval=150,
    value_bearing=False,
)

_REGTEST_TAGS = frozenset({"bcrt", "regtest"})

#: EIP-155 chain ids of local development chains, which hold nothing: anvil's and hardhat's default.
LOCAL_DEVNET_CHAIN_IDS = frozenset({31337})

_EVM_TESTNET_CHAIN_IDS = frozenset(c.chain_id for c in KNOWN_EVM_CHAINS.values() if c.is_testnet)


def _counter_leg_value(leg: Any) -> str | None:
    """What makes the counter leg value-bearing, as a phrase for a refusal — or ``None`` if nothing.

    An EVM leg (one exposing an int ``chain_id``) is judged by the chain it signs for: value-bearing
    unless that is a testnet in :data:`~pyrxd.eth_wallet.chains.KNOWN_EVM_CHAINS` or a local
    development chain (:data:`LOCAL_DEVNET_CHAIN_IDS`). Its ``network`` tag cannot answer this — every
    EVM tag reads as uncleared (see :mod:`pyrxd.eth_wallet.chains`) — while EIP-155 makes a
    signature for one chain id invalid on every other. An unknown chain id counts as value-bearing.
    Any other leg is judged by the tag partition
    :func:`pyrxd.gravity.swap_coordinator._leg_is_value_bearing` draws; a leg with neither is a test
    fake.
    """
    chain_id = getattr(leg, "chain_id", None)
    if isinstance(chain_id, int) and not isinstance(chain_id, bool):
        if chain_id in LOCAL_DEVNET_CHAIN_IDS or chain_id in _EVM_TESTNET_CHAIN_IDS:
            return None
        return f"EVM chain id {chain_id}"
    net = getattr(leg, "network", None)
    if isinstance(net, str) and net and net not in AUDIT_CLEARED_NETWORKS:
        return f"network {net!r}"
    return None


def radiant_chain_for_leg(leg: Any, *, counter_leg: Any) -> RadiantChain:
    """The Radiant network the maker's funding is proved on, for a swap with these two legs.

    The Radiant leg's ``network`` tag, by the partition
    :func:`pyrxd.gravity.swap_coordinator._leg_is_value_bearing` draws: a non-empty tag outside
    :data:`~pyrxd.btc_wallet.htlc_leg.AUDIT_CLEARED_NETWORKS` moves real value, and is Radiant
    mainnet — there is no other value-bearing Radiant network. The regtest tags (and a leg with no
    tag, which is a test fake) are regtest; any other cleared tag has no chain parameters in pyrxd,
    and refuses.

    The COUNTER leg decides too, because it is what the taker is about to lock. When it moves real
    value (:func:`_counter_leg_value`) and the Radiant leg names a test network, this REFUSES: the
    proof would be anchored to regtest's genesis with no value term. So no tag on either leg selects
    a weaker check than mainnet's for a swap in which real value is locked.
    """
    net = getattr(leg, "network", None)
    if isinstance(net, str) and net and net not in AUDIT_CLEARED_NETWORKS:
        return MAINNET_CHAIN
    if isinstance(net, str) and net and net not in _REGTEST_TAGS:
        raise MakerFundingNotVerified(
            f"pyrxd has no Radiant chain parameters for the test network tag {net!r}, so the maker's "
            "funding cannot be proved there; use a regtest ('bcrt') or mainnet leg"
        )
    counter_value = _counter_leg_value(counter_leg)
    if counter_value is not None:
        tagged = f"tagged {net!r}" if isinstance(net, str) and net else "untagged"
        raise MakerFundingNotVerified(
            f"the counter leg moves real value ({counter_value}) but the Radiant leg is {tagged}, "
            "a test network: the maker's funding "
            "would be proved against a test chain, which proves nothing about value. Tag the Radiant leg "
            "for mainnet, or run both legs on test networks"
        )
    return REGTEST_CHAIN


def block_subsidy_photons(height: int, chain: RadiantChain) -> int:
    """``GetBlockSubsidy(height)`` in photons (``validation.cpp`` lines 1108-1119)."""
    if not isinstance(height, int) or isinstance(height, bool) or height < 0:
        raise ValidationError("height must be a non-negative int")
    halvings = height // chain.subsidy_halving_interval
    if halvings >= 64:
        return 0
    return INITIAL_SUBSIDY_PHOTONS >> halvings


def forged_confirmation_cost_ceiling_photons(chain: RadiantChain) -> int:
    """The most ``C`` can be for a funding made from now on, from the SHIPPED checkpoint table alone.

    For the negotiation-time check, which runs before any funding or header exists. Two facts make it
    an upper bound on the ``C`` :func:`verify_maker_funding` will compute: ``max_header_work``
    includes the newest checkpoint's own header, whose work ÷ :data:`FLOOR_WORK_DIVISOR` is
    ``floor_work``, so ``floor_work ÷ max_header_work <= 1/16``; and the subsidy never rises with
    height, while a funding made for terms agreed now is mined above every shipped checkpoint (each is
    at least a thousand blocks below the tip it was generated at). A ``k`` sized from this is
    therefore never larger than the ``k`` the gate will require — so a check built on it refuses only
    what the gate would refuse.
    """
    return block_subsidy_photons(chain.checkpoints[-1][0], chain) // FLOOR_WORK_DIVISOR


def required_funding_confirmations(
    *,
    value_bearing: bool,
    burial_blocks: int,
    value_at_stake_photons: int | None,
    forged_confirmation_cost_photons: int | None,
) -> tuple[int, int]:
    """``(k, value_term)`` — the settled rule. Raises :class:`MakerFundingNotVerified` when a
    value-bearing swap gives nothing to size ``k`` from."""
    if not isinstance(burial_blocks, int) or isinstance(burial_blocks, bool) or burial_blocks < 0:
        raise ValidationError("burial_blocks must be a non-negative int")
    if not value_bearing:
        return max(1, burial_blocks), 0
    if value_at_stake_photons is None or value_at_stake_photons <= 0:
        raise MakerFundingNotVerified(
            "no value at stake is available for this swap, so the confirmations that make forging "
            "the maker's funding cost more than it can win cannot be sized; set "
            "MarginPolicy.value_at_risk_photons to the swap's value in photons"
        )
    cost = forged_confirmation_cost_photons
    if cost is None or cost <= 0:
        raise MakerFundingNotVerified(
            f"one forged confirmation of the maker's funding prices at {cost} photons at this height, so "
            "no confirmation count makes forging it cost more than the value at stake"
        )
    value_term = -((-FORGERY_COST_FACTOR * value_at_stake_photons) // cost)
    return max(MIN_FUNDING_CONFIRMATIONS, burial_blocks, value_term), value_term


def _merged_ranges(spans: Sequence[tuple[int, int]]) -> tuple[tuple[int, int], ...]:
    """Inclusive ``(lo, hi)`` spans, merged, as ``(start, count)`` chunks of at most 2016."""
    out: list[tuple[int, int]] = []
    for lo, hi in sorted(spans):
        if out and lo <= out[-1][1] + 1:
            out[-1] = (out[-1][0], max(out[-1][1], hi))
        else:
            out.append((lo, hi))
    chunks: list[tuple[int, int]] = []
    for lo, hi in out:
        h = lo
        while h <= hi:
            n = min(MAX_HEADERS_PER_REQUEST, hi - h + 1)
            chunks.append((h, n))
            h += n
    return tuple(chunks)


def funding_header_ranges(
    chain: RadiantChain, height: int, *, cap: int = MAX_HEADERS_FROM_CHECKPOINT_SDK
) -> tuple[tuple[int, int], ...]:
    """The ``(start, count)`` header ranges to fetch to judge a funding at *height* — decided here.

    Three spans, merged: the last checkpoint interval (between the two newest checkpoints, for
    ``max_header_work``); the funding block up to the checkpoint above it, when it is at or below
    the newest one (:func:`~pyrxd.glyph.mark_block.plan_block_verification`'s own range); and the
    newest checkpoint up to ``cap`` headers above it. A server answers FEWER headers past its tip,
    and that is where its chain ends for this gate. Raises :class:`MakerFundingNotVerified` for a
    height nothing fetched could prove.

    A funding at or below the newest checkpoint gets the WHOLE span from its block up to the newest
    checkpoint, when that span is at most ``cap`` headers: the reference header the elapsed-depth
    bound is measured from (:func:`verify_maker_funding`, step 5) can lie anywhere between the
    funding block and the served tip, which the three spans above leave a gap in once the funding
    is two or more checkpoint intervals down. Past ``cap`` the gap is not fetched, and a reference
    header that falls in it refuses there, naming it.
    """
    table = chain.checkpoints
    newest_h = table[-1][0]
    if not isinstance(height, int) or isinstance(height, bool) or not 0 <= height <= BlockHeight.MAX:
        raise MakerFundingNotVerified(f"the server named no usable funding height ({height!r})")
    top = newest_h + cap
    if height > top:
        raise MakerFundingNotVerified(
            f"the funding is at block {height}, {height - newest_h} blocks past this pyrxd's newest checkpoint "
            f"({newest_h}); this gate links at most {cap} — upgrade pyrxd (newer checkpoints) or verify "
            "against your own node"
        )
    plan = plan_block_verification(
        height=height,
        min_confirmations=top - height + 1,
        checkpoints=table,
        max_headers_from_checkpoint=cap,
    )
    if plan.reason is not None:
        raise MakerFundingNotVerified(f"the funding block cannot be verified: {plan.reason}")
    spans = [(start, start + count - 1) for start, count in plan.header_ranges]
    if height <= newest_h and newest_h - height <= cap:
        spans.append((height, newest_h))
    if len(table) >= 2:
        spans.append((table[-2][0], newest_h))
    spans.append((newest_h, top))
    return _merged_ranges(spans)


@dataclass(frozen=True)
class MakerFundingEvidence:
    """What the Radiant leg fetched for the coordinator to judge. Nothing here is trusted as given."""

    txid: str
    vout: int
    #: The height the server NAMED for the funding; the proof decides whether it holds.
    height: int
    raw_tx: bytes
    #: ``blockchain.transaction.get_merkle``'s reply (a dict), or a parsed ``TxMerkleBranch``.
    merkle: Any
    #: ``blockchain.transaction.id_from_pos(height, 0, true)``'s reply for the same block.
    coinbase_merkle: Any
    #: ``height -> raw 80-byte header`` for :func:`funding_header_ranges`' ranges, as served.
    headers: Mapping[int, bytes]
    #: The server's verbose ``confirmations`` for the funding tx: used only to RAISE the elapsed
    #: upper bound, never as proof of depth. ``None`` when it did not answer.
    reported_confirmations: int | None = None


@dataclass(frozen=True)
class VerifiedMakerFunding:
    """A funding proved to the required depth, with every number the decision rested on."""

    outpoint: str
    value_photons: int
    height: int
    blockhash: str
    #: Blocks proved from the funding block (counting it as 1) up to the newest header served.
    proved_depth: int
    #: ``k``: the depth required, and the value term that entered it (0 on a test network).
    required_confirmations: int
    value_term: int
    burial_blocks: int
    value_at_stake_photons: int | None
    #: ``C`` in photons, with its inputs.
    forged_confirmation_cost_photons: int
    subsidy_photons: int
    floor_work: int
    max_header_work: int
    #: The conservative UPPER bound on blocks since the funding was mined, for the timelock gates.
    elapsed_blocks_upper: int
    #: The clock allowance inside it — blocks that could have been mined since the reference header's
    #: timestamp — or ``None`` when no clock was supplied (test networks only).
    withheld_allowance_blocks: int | None
    reported_confirmations: int | None
    served_tip: int
    #: The header the clock allowance is measured from: ``max(1, value_term)`` deep below the served
    #: tip (the tip itself on a test network).
    reference_height: int
    #: The verifier's own sentence for what it proved.
    claim: str


def _log2(n: int) -> str:
    return f"2^{n.bit_length() - 1}" if n > 0 else "0"


def _rule(value_bearing: bool) -> str:
    if value_bearing:
        return (
            f"k = max({MIN_FUNDING_CONFIRMATIONS}, burial, ceil({FORGERY_COST_FACTOR} × value at stake ÷ C)), "
            "C = subsidy × floor work ÷ max header work"
        )
    return "k = the configured depth (test network: no value term)"


def _header_time(header: bytes) -> int:
    return int.from_bytes(header[68:72], "little")


def verify_maker_funding(
    evidence: MakerFundingEvidence,
    *,
    chain: RadiantChain,
    expected_spk: bytes,
    expected_value: int,
    value_at_stake_photons: int | None,
    burial_blocks: int,
    now_unix_s: int | None,
    withheld_block_interval_s: float,
    cap: int = MAX_HEADERS_FROM_CHECKPOINT_SDK,
) -> VerifiedMakerFunding:
    """Prove *evidence* pays *expected_spk* / *expected_value* at the required depth, or RAISE.

    Raises :class:`MakerFundingNotVerified` (a ``ValidationError``) for anything short of a verified
    inclusion at depth ``k``; the message names what was required and what was proved. Never
    returns on the server's word. See the module docstring for the rule and the upper bound.
    """
    if not isinstance(evidence, MakerFundingEvidence):
        raise MakerFundingNotVerified("the Radiant leg returned no funding evidence")
    if not (isinstance(withheld_block_interval_s, (int, float)) and withheld_block_interval_s > 0):
        raise ValidationError("withheld_block_interval_s must be a positive number")
    if now_unix_s is not None and (not isinstance(now_unix_s, int) or isinstance(now_unix_s, bool)):
        raise ValidationError("now_unix_s must be an int or None")
    rule = _rule(chain.value_bearing)

    def refuse(what: str, required: str, proved: str) -> MakerFundingNotVerified:
        return MakerFundingNotVerified(f"{what}. Required: {required}. Proved: {proved}.")

    # 1. The bytes are the transaction, and ITS output is the covenant — not listunspent's report.
    txid = evidence.txid.lower() if isinstance(evidence.txid, str) else ""
    raw = evidence.raw_tx
    if not isinstance(raw, (bytes, bytearray)) or hash256(bytes(raw))[::-1].hex() != txid:
        raise refuse(
            "the raw funding transaction the server served does not hash to the funding txid",
            "the transaction's own bytes",
            "nothing",
        )
    tx = Transaction.from_hex(bytes(raw))
    vout = evidence.vout
    if tx is None or not isinstance(vout, int) or isinstance(vout, bool) or not 0 <= vout < len(tx.outputs):
        raise refuse(
            f"output {vout!r} of the funding transaction could not be read from its raw bytes",
            "the covenant output, parsed from the verified bytes",
            "nothing",
        )
    out = tx.outputs[vout]
    if out.locking_script.serialize() != bytes(expected_spk):
        raise refuse(
            f"output {txid}:{vout} does not pay the covenant scriptPubKey re-derived from the terms",
            "the exact covenant script",
            "a different script, from the transaction's own bytes",
        )
    if int(out.satoshis) != int(expected_value):
        raise refuse(
            f"output {txid}:{vout} carries {int(out.satoshis)} photons, not the negotiated {int(expected_value)}",
            "the negotiated value",
            f"{int(out.satoshis)} photons, from the transaction's own bytes",
        )

    # 2. Inclusion + linkage + PoW over every header served from the funding up to the served tip.
    table = chain.checkpoints
    newest_h, newest_hash = table[-1]
    headers = evidence.headers if isinstance(evidence.headers, Mapping) else {}
    height = evidence.height
    top = newest_h - 1
    while isinstance(headers.get(top + 1), (bytes, bytearray)) and top + 1 <= newest_h + cap:
        top += 1
    if top < newest_h:
        raise refuse(
            f"the server did not serve the header at pyrxd's newest checkpoint ({newest_h})",
            rule,
            "nothing",
        )
    if not isinstance(height, int) or isinstance(height, bool) or height < 0 or height > top:
        raise refuse(
            f"the funding height the server named ({height!r}) is not among the headers it served "
            f"(newest checkpoint {newest_h} to {top})",
            rule,
            "nothing",
        )
    v = verify_mark_block(
        txid=txid,
        raw_tx=bytes(raw),
        height=height,
        merkle=evidence.merkle,
        coinbase_merkle=evidence.coinbase_merkle,
        headers=headers,
        min_confirmations=top - height + 1,
        network=chain.name,
        checkpoints=table,
        max_headers_from_checkpoint=cap,
        pow_limit=chain.pow_limit,
    )
    if v.state != VERIFIED or v.verified_depth is None or v.blockhash is None:
        raise refuse(
            f"the funding transaction's block did not verify ({v.state}: {v.reason})",
            rule,
            "nothing — the depth rests on the server's word until the proof passes",
        )
    proved = v.verified_depth

    # 3. C, from pyrxd's own schedule and headers proved above or linked between two checkpoints.
    verified_heights = set(range(newest_h, top + 1))
    if height <= newest_h:
        cp_above = next(h for h, _ in table if h >= height)
        verified_heights.update(range(height, cp_above + 1))
    try:
        if len(table) >= 2:
            prev_h, prev_hash = table[-2]
            below = prev_hash
            if radiant_block_hash(bytes(headers[prev_h])) != prev_hash:
                raise KeyError(prev_h)
            for h in range(prev_h + 1, newest_h + 1):
                hdr = bytes(headers[h])
                if radiant_header_prev_hash(hdr) != below:
                    raise KeyError(h)
                below = radiant_block_hash(hdr)
            if below != newest_hash:
                raise KeyError(newest_h)
            verified_heights.update(range(prev_h, newest_h + 1))
        max_work = max(radiant_header_work(bytes(headers[h]), pow_limit=chain.pow_limit) for h in verified_heights)
        floor_work = radiant_header_work(bytes(headers[newest_h]), pow_limit=chain.pow_limit) // FLOOR_WORK_DIVISOR
    except (KeyError, TypeError, ValueError, ValidationError):
        raise refuse(
            "the last checkpoint interval could not be linked from the headers served, so the cost of a "
            "forged confirmation cannot be priced from proved headers",
            rule,
            f"the funding in block {height}, at least {proved} deep",
        ) from None
    subsidy = block_subsidy_photons(height, chain)
    cost = subsidy * floor_work // max_work if max_work > 0 else 0

    # 4. k.
    try:
        k, value_term = required_funding_confirmations(
            value_bearing=chain.value_bearing,
            burial_blocks=burial_blocks,
            value_at_stake_photons=value_at_stake_photons,
            forged_confirmation_cost_photons=cost,
        )
    except MakerFundingNotVerified as exc:
        raise refuse(str(exc), rule, f"the funding in block {height}, at least {proved} deep") from None
    pricing = (
        f"C = {cost} photons (subsidy {subsidy} at block {height} × floor work {_log2(floor_work)} ÷ max header "
        f"work {_log2(max_work)})"
    )
    if chain.value_bearing:
        why = (
            f"k = {k} = max({MIN_FUNDING_CONFIRMATIONS}, burial {burial_blocks}, "
            f"ceil({FORGERY_COST_FACTOR} × value {value_at_stake_photons} photons ÷ C) = {value_term}); {pricing}"
        )
    else:
        why = f"k = {k} (test network {chain.name}: the configured depth {burial_blocks}, no value term)"
    if height + k - 1 > newest_h + cap:
        raise refuse(
            f"block {height + k - 1}, where the funding would reach the required depth, is "
            f"{height + k - 1 - newest_h} blocks past this pyrxd's newest checkpoint ({newest_h}) and this gate "
            f"links at most {cap} — upgrade pyrxd (newer checkpoints) or verify against your own node",
            why,
            f"the funding in block {height}, {proved} deep",
        )
    if proved < k:
        raise refuse(
            f"the maker's funding {txid}:{vout} is proved only {proved} block(s) deep; wait for {k - proved} "
            "more, then retry",
            why,
            f"inclusion in block {height} ({v.blockhash}), {proved} deep, linked to checkpoint {newest_h}",
        )

    # 5. The upper bound on elapsed depth, for the timelock gates. The allowance is measured from the
    #    REFERENCE header, `max(1, value_term)` deep below the newest header served (the newest counts
    #    as 1): a different header there means different headers above it too, each at the floor or
    #    above, so its time costs `value_term × C` to change — the price the rule already sets on the
    #    depth. `value_term <= k <= proved`, so the reference is never below the funding block. A
    #    test network has no value term: the reference is the newest header served.
    ref_depth = max(1, value_term)
    ref_h = top - ref_depth + 1
    if ref_h not in verified_heights:
        # Below the last checkpoint interval and above the funding block's own checkpoint: nothing
        # above linked it yet. Link it to the checkpoint at or above it before reading its time.
        cp_ref_h, cp_ref_hash = next((h, b) for h, b in table if h >= ref_h)
        try:
            below = radiant_block_hash(bytes(headers[ref_h]))
            for h in range(ref_h + 1, cp_ref_h + 1):
                hdr = bytes(headers[h])
                if radiant_header_prev_hash(hdr) != below:
                    raise KeyError(h)
                below = radiant_block_hash(hdr)
            if below != cp_ref_hash:
                raise KeyError(cp_ref_h)
        except (KeyError, TypeError, ValueError, ValidationError):
            raise refuse(
                f"the reference header the elapsed-depth bound is measured from (block {ref_h}, {ref_depth} "
                f"deep counting the newest header served as 1) was not served linked to checkpoint {cp_ref_h}, "
                "so the "
                "blocks since the funding cannot be bounded from above",
                why,
                f"the funding in block {height}, {proved} deep",
            ) from None
    if now_unix_s is None:
        if chain.value_bearing:
            raise refuse(
                "no wall clock (now_unix_s) was supplied, so the blocks a server may have withheld above "
                "the newest header it served cannot be bounded, and the timelock checks would judge a CSV "
                "window that may already be shorter",
                "now_unix_s",
                f"the funding in block {height}, at least {proved} deep",
            )
        allowance: int | None = None
    else:
        stale_s = max(0, now_unix_s - _header_time(bytes(headers[ref_h])))
        allowance = math.ceil(stale_s / float(withheld_block_interval_s))
    reported = evidence.reported_confirmations
    reported_i = reported if isinstance(reported, int) and not isinstance(reported, bool) and reported >= 0 else None
    # Blocks up to and including the reference header are proved; every block after it is inside the
    # allowance, which counts all that could have been mined since its timestamp. Never below the
    # proved depth; the server's own count can only raise it.
    upper = max(proved, (ref_h - height + 1) + (allowance or 0), reported_i or 0)

    return VerifiedMakerFunding(
        outpoint=f"{txid}:{vout}",
        value_photons=int(out.satoshis),
        height=height,
        blockhash=v.blockhash,
        proved_depth=proved,
        required_confirmations=k,
        value_term=value_term,
        burial_blocks=burial_blocks,
        value_at_stake_photons=value_at_stake_photons,
        forged_confirmation_cost_photons=cost,
        subsidy_photons=subsidy,
        floor_work=floor_work,
        max_header_work=max_work,
        elapsed_blocks_upper=upper,
        withheld_allowance_blocks=allowance,
        reported_confirmations=reported_i,
        served_tip=top,
        reference_height=ref_h,
        claim=v.claim or "",
    )
