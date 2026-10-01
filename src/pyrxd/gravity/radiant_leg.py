"""Concrete Radiant covenant leg for the Gravity Taproot-HTLC atomic swap.

This is the production ``radiant_leg`` the
:class:`pyrxd.gravity.swap_coordinator.SwapCoordinator` drives (the coordinator
tests use a duck-typed fake; this is the real object). It composes:

* :mod:`pyrxd.gravity.htlc_covenant` — the funded covenant SPK builders;
* :mod:`pyrxd.gravity.htlc_spend` — the claim (preimage) / refund (CSV) TX builders;
* a :class:`RadiantChainIO` over :class:`pyrxd.network.electrumx.ElectrumXClient`
  for broadcast + confirmation polling + reading the funded covenant value;
* a :class:`SeenStore` (in-memory) for H-freshness.

Plus a :class:`RxinDexerRefAdapter` that resolves a genesis ref to a
:class:`pyrxd.gravity.ref_authenticity.ResolvedRef` via the RXinDexer
``glyph.get_token`` RPC, so the coordinator's pre-lock REF-authenticity gate has a
real backend.

Design notes (T7 plan D5/D6, reviewed)
--------------------------------------
* ``RadiantChainIO`` is a thin helper (broadcast + wait_confirmations + read UTXO),
  NOT unified with :class:`pyrxd.gravity.trade.GravityTrade` — that drives the
  *different* SPV-oracle finalize swap.
* The leg holds the party's own Radiant pkhs (taker + maker) so it can build the
  covenant and the spend holder outputs. ``expected_covenant_scriptpubkey`` builds
  the covenant from the negotiated terms and **asserts the resulting
  ``hash256(holder)`` binds equal the terms' ``taker_dest_hash``/``maker_dest_hash``**
  — fail-closed if the leg's configured pkhs don't produce the covenant the terms
  committed to (a wrong-key/wrong-party guard).
* ``carrier_value`` (the funded covenant output value) is read from the on-chain
  UTXO, never self-reported.
* **AUDIT GATE (non-blocking since 0.9.0):** the constructor still calls
  :func:`pyrxd.btc_wallet.htlc_leg.require_audit_cleared`, but that function has been
  a no-op since 0.9.0, when the maintainer chose to match Radiant's own posture rather
  than hard-block mainnet use. The leg constructs on ANY network, with or without
  ``audit_cleared``. The stack is unaudited; what still keys on the network tag is the
  coordinator's value-bearing setup checks (see ``_leg_is_value_bearing``).
* ``SeenStore`` is an in-memory ``set`` for this milestone (a SQLite durable store
  is deferred to the audit-gated track; a blocking ``sqlite3`` call would stall the
  async loop). The duck-typed ``has_seen``/``mark_seen`` shape lets a durable store
  drop in later.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import math
import re
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from pyrxd.btc_wallet.htlc_leg import require_audit_cleared
from pyrxd.btc_wallet.taproot import TimeUnit
from pyrxd.glyph.types import GlyphRef
from pyrxd.gravity.covenant_selection import earliest_confirmed_key
from pyrxd.gravity.fee_policy import (
    DEFAULT_RADIANT_DEADLINE_FEE_POLICY,
    DeadlineFeePolicy,
    assert_fee_covers,
)
from pyrxd.gravity.funding_spv import UNIDENTIFIED_SOURCE_PREFIX, MakerFundingEvidence
from pyrxd.gravity.htlc_covenant import (
    HtlcCovenant,
    build_htlc_covenant_ft,
    build_htlc_covenant_nft,
    build_htlc_covenant_rxd,
)
from pyrxd.gravity.htlc_spend import FeeInput, build_htlc_claim_tx, build_htlc_refund_tx
from pyrxd.gravity.ref_authenticity import ResolvedRef
from pyrxd.gravity.swap_state import NegotiatedTerms, SwapRecord
from pyrxd.network._guards import finite_int
from pyrxd.network.source_identity import SourceKey, source_key_of
from pyrxd.security.errors import InsufficientFundsError, NetworkError, ValidationError
from pyrxd.security.types import Hex20, Txid
from pyrxd.security.units import ChainHeight, Confirmations, PhotonValue

_LOG = logging.getLogger(__name__)

__all__ = [
    "FeeUtxoSource",
    "RadiantBroadcaster",
    "RadiantChainIO",
    "RadiantCovenantLeg",
    "RxinDexerRefAdapter",
    "SeenStore",
    "blocks_to_claim_deadline",
]

logger = logging.getLogger(__name__)


def blocks_to_claim_deadline(t_rxd_blocks: int, confirmations: int) -> int:
    """Radiant blocks left in which ONLY the taker's claim can be mined.

    The covenant's refund branch is a BIP68 relative lock of ``t_rxd`` blocks, valid once the
    covenant is ``t_rxd`` confirmations deep (the maturity :meth:`RadiantCovenantLeg.refund_asset`
    checks). So ``t_rxd - confirmations`` more blocks can be mined before the maker's refund
    can be too; at 0 the refund is valid now. Clamped at 0: a deadline already passed is 0,
    never negative.

    ONE definition on purpose. :meth:`RadiantCovenantLeg.claim_asset` sizes the claim fee
    against it and ``pyrxd swap status`` prints it; the status screen used to compute its own
    ``funding_height + t_rxd - tip``, which is this figure plus one — a block of margin the
    taker did not have.
    """
    return max(0, t_rxd_blocks - confirmations)


# --------------------------------------------------------------------------- SeenStore


class SeenStore:
    """In-memory H-freshness store (the coordinator's ``reserve``/``has_seen``).

    Records every hashlock H the coordinator has committed to funding, so a reused
    H is rejected for BOTH reasons: economic (free-option replay) and cross-swap
    preimage replay. ``reserve(H)`` is the authoritative atomic test-and-set the
    coordinator calls PRE-broadcast; ``has_seen`` is a read-only advisory probe
    (the pre-lock gate's cheap early-reject), never the binding decision.

    NON-DURABLE (``durable = False``): a plain ``set``, so freshness does NOT
    survive a restart or a second process. That is acceptable only for a
    single-process, single-shot run that mints a fresh H per swap (the dust
    runbook); the coordinator's construct-time guard refuses this store on a
    value-bearing network unless the operator passes
    ``CoordinatorConfig(accept_nondurable_seen=True)``. A durable replacement
    (SQLite ``INSERT OR IGNORE`` keyed on H, declaring ``durable = True``) is
    deferred to the external-audit track; it MUST stay non-blocking
    (``asyncio.to_thread`` behind an async ``reserve``) and fsync the reservation
    BEFORE the BTC broadcast. The method shape is duck-compatible so that durable
    store drops in unchanged.
    """

    durable = False

    def __init__(self) -> None:
        self._seen: set[bytes] = set()

    def reserve(self, hashlock: bytes) -> bool:
        """Atomically record H if unseen; True if freshly reserved, else False.

        Atomic on the single-threaded event loop precisely because there is no
        ``await`` between the membership test and the add.
        """
        h = bytes(hashlock)
        if h in self._seen:
            return False
        self._seen.add(h)
        return True

    def has_seen(self, hashlock: bytes) -> bool:
        return bytes(hashlock) in self._seen

    def mark_seen(self, hashlock: bytes) -> None:
        # Retained as an unused primitive for the roundtrip test + back-compat; the
        # coordinator's authoritative consume is reserve() (atomic, pre-broadcast).
        self._seen.add(bytes(hashlock))


# --------------------------------------------------------------------------- chain IO


@runtime_checkable
class RadiantBroadcaster(Protocol):
    """Submit a raw Radiant tx; idempotent on an already-known tx."""

    async def broadcast(self, raw_tx: bytes) -> str:  # pragma: no cover - Protocol
        ...


#: How long :meth:`RadiantChainIO.depth_reports` waits for any one depth source before dropping
#: it. The sources are asked concurrently, so this bounds the whole call, not each source in turn.
DEPTH_SOURCE_TIMEOUT_S = 20.0

#: How many headers, ending at its own tip, :meth:`RadiantChainIO.depth_reports` asks each source for
#: — about half a day of Radiant blocks at the nominal 300 s — so the taker gate's maximum header
#: work reflects the chain's recent difficulty as every operator sees it, not only the headers the
#: proof's server chose to serve.
TIP_HEADERS_FOR_WORK = 144


def _names_txid(reported: Any, requested: str) -> bool:
    """Whether a verbose reply's own ``txid`` field names *requested*: both exactly 64 hex characters,
    equal ignoring case."""
    if not isinstance(reported, str) or not isinstance(requested, str):
        return False
    if len(reported) != 64 or len(requested) != 64:
        return False
    hexdigits = set("0123456789abcdefABCDEF")
    if not (set(reported) <= hexdigits and set(requested) <= hexdigits):
        return False
    return reported.lower() == requested.lower()


@dataclass(frozen=True)
class DepthReports:
    """What the configured sources said about one funding's depth, by operator group — nothing proved.

    ``reported``: each source's larger of its verbose ``confirmations`` for the funding and its
    ``tip - height + 1`` (what may RAISE the gate's elapsed-depth upper bound). ``funding_tx``: the
    confirmations each source reported for the funding TRANSACTION ITSELF, from its verbose reply for
    that txid — the only reports the gate counts toward its two-operator rule above dust. A source
    whose verbose read failed (a txid it does not know, an error, a timeout) and that answered only
    its tip height appears in ``reported`` and not in ``funding_tx``.
    """

    reported: tuple[tuple[str, int], ...]
    funding_tx: tuple[tuple[str, int], ...]
    #: ``((source, start_height, headers, reported_tip), ...)``: the :data:`TIP_HEADERS_FOR_WORK` headers
    #: each source served ending at the tip height it reported, as served — for the gate's maximum
    #: header work, which they can only raise (:func:`pyrxd.gravity.funding_spv.verify_maker_funding`
    #: checks each header's own proof-of-work, their linkage, that the last is at ``reported_tip``, and
    #: that the run links to a header the gate verified). A source that did not serve them is absent.
    tip_headers: tuple[tuple[str, int, tuple[bytes, ...], int], ...] = ()


#: An outpoint's vout: ASCII decimal digits only, at most ten (a vout is a uint32).
_VOUT_RE = re.compile(r"[0-9]{1,10}")


def _split_outpoint(outpoint: object) -> tuple[str, int]:
    """``"<txid>:<vout>"`` -> ``(txid, vout)``, or ``ValidationError``.

    ``str.isdigit`` is the wrong test for a vout: it is true for ``"²"`` (which ``int`` then
    refuses with a bare ``ValueError``) and for Arabic-Indic or full-width digits (which ``int``
    silently converts, so ``"txid:١"`` became vout 1). Only ``0-9`` is a vout digit.
    """
    txid, sep, vout = str(outpoint).partition(":")
    if not sep or not _VOUT_RE.fullmatch(vout) or int(vout) > 0xFFFFFFFF:
        raise ValidationError(f"bad covenant outpoint {outpoint!r}")
    return txid, int(vout)


class RadiantChainIO:
    """Thin chain helper over an ``ElectrumXClient``-like object.

    Provides exactly what the leg needs: broadcast, confirmation depth, and the
    on-chain value of a covenant output. NOT unified with ``GravityTrade`` (that
    drives the SPV-oracle finalize swap, a different protocol).

    The injected ``client`` must expose ``broadcast(raw)->txid``,
    ``get_transaction_verbose(txid)->dict`` (with ``confirmations``), and
    ``get_utxos(script_hash)->list`` (records with ``tx_hash``/``tx_pos``/``value``).

    ``proof_client``, when given, answers the four reads the swap taker gate PROVES a covenant
    funding from (:meth:`funding_evidence`); by default ``client`` does. Any server will do for
    those: the proof rests on the checkpoints pyrxd ships, not on who served it — so a transport
    that cannot serve them (the operator scripts' node-over-ssh shim) pairs with an ElectrumX client.

    ``depth_sources`` are further Radiant readers (each with ``get_transaction_verbose`` and/or
    ``get_tip_height``) whose REPORTED depth of the funding the gate's elapsed-depth upper bound may
    be raised by, beside ``client``'s and ``proof_client``'s. A report never lowers the bound, so a
    source reporting less costs nothing; each is grouped by its ``source_key`` (its operator). Above
    dust on a value-bearing network the gate requires reports from at least two distinct operators
    (:data:`pyrxd.gravity.funding_spv.MIN_REPORTING_OPERATORS`): :meth:`configured_depth_operators`
    says which this configuration asks. A client over the URLs of several operators — an
    ``ElectrumXClient`` given pyrxd's shipped mainnet endpoints, which races them — is asked once
    PER OPERATOR (``ElectrumXClient.per_source_clients``), since one reply from it cannot say which
    operator sent it. The sources are asked CONCURRENTLY, each under ``depth_timeout_s`` (default
    :data:`DEPTH_SOURCE_TIMEOUT_S`): a source that does not answer in time is dropped, as one that
    fails is, and costs the call one timeout, not one per unresponsive source.
    """

    def __init__(
        self,
        client: Any,
        *,
        proof_client: Any = None,
        depth_sources: tuple[Any, ...] = (),
        depth_timeout_s: float = DEPTH_SOURCE_TIMEOUT_S,
    ) -> None:
        for m in ("broadcast", "get_transaction_verbose", "get_utxos"):
            if not hasattr(client, m):
                raise ValidationError(f"RadiantChainIO client must provide {m}()")
        if (
            not isinstance(depth_timeout_s, (int, float))
            or isinstance(depth_timeout_s, bool)
            or not math.isfinite(depth_timeout_s)
            or depth_timeout_s <= 0
        ):
            raise ValidationError("RadiantChainIO depth_timeout_s must be a finite number > 0")
        self._client = client
        self._proof_client = client if proof_client is None else proof_client
        self._depth_sources = tuple(depth_sources)
        self._depth_timeout_s = float(depth_timeout_s)

    async def broadcast(self, raw_tx: bytes) -> str:
        if not isinstance(raw_tx, (bytes, bytearray)) or len(raw_tx) == 0:
            raise ValidationError("raw_tx must be non-empty bytes")
        try:
            return str(await self._client.broadcast(bytes(raw_tx)))
        except Exception as exc:
            msg = str(exc).lower()
            if "already" in msg and ("known" in msg or "mempool" in msg or "chain" in msg):
                # Idempotent: the node already has it. Re-derive nothing; the caller
                # tracks the txid from the builder. Surface a sentinel for the leg.
                raise _AlreadyKnown() from exc
            raise NetworkError(f"radiant broadcast failed: {exc}") from exc

    async def confirmations(self, txid: str) -> Confirmations:
        info = await self._client.get_transaction_verbose(txid)
        if not isinstance(info, dict):
            raise NetworkError("get_transaction_verbose did not return a dict")
        # This is the RXD covenant leg's confirmation gate, and it was a bare
        # `int(info.get("confirmations", 0) or 0)`: a string "999999" coerced to a depth, and a
        # JSON `Infinity` raised OverflowError — not a NetworkError, so it escaped every
        # `except NetworkError` on a value-moving path as a bare traceback. The `or 0` keeps a
        # present-but-falsy value reading as depth 0, which is the fail-closed direction.
        raw = info.get("confirmations", 0) or 0
        try:
            depth = finite_int(raw)
        except ValueError as exc:
            raise NetworkError("node reported an unreadable confirmation depth; fail-closed") from exc
        # A DEPTH, tagged as one. `Confirmations` and `ChainHeight` are both ints and both
        # non-negative, and 0 means "unmined" under both readings — which is exactly why the
        # shim's conflation survived review. They order OPPOSITELY, so the checker now keeps
        # this return value out of every slot that wants a height.
        return Confirmations(depth) if depth > 0 else Confirmations(0)

    async def find_covenant_utxo(
        self, spk: bytes, *, expected_value: PhotonValue | None = None, pin_outpoint: str | None = None
    ) -> tuple[str, PhotonValue, ChainHeight]:
        """Locate the funded covenant UTXO for ``spk`` -> ``(outpoint, value, height)``.

        Scans the UTXO set of the covenant scriptPubKey (ElectrumX script-hash =
        ``sha256(spk)`` reversed). The HONEST funding is one output, but the SPK is a pure
        function of PUBLIC negotiated terms, so anyone can pay it and the scan can return
        several — see the ``len(utxos) > 1`` branch below, which SELECTS the earliest-confirmed
        match rather than refusing (refusing on ambiguity is a denial anyone can trigger). If
        ``expected_value`` is given, a match must equal it (a wrong value is a mis-funded
        covenant -> fail-closed); ``pin_outpoint``, once known, selects instead of
        re-discovering. The returned value is the ON-CHAIN value, never a self-report.

        THIS SAID "the covenant funds exactly one output, so there is one matching UTXO", one
        screen above the address-poisoning branch that exists because that is not true.

        UNITS. ``expected_value`` is a :data:`~pyrxd.security.units.PhotonValue` because it
        is matched against the UTXO's NATIVE carrier value. It is NOT a Glyph FT token
        count: a token covenant enforces ``refValueSum(ref) == amount`` and its carrier can
        be dust of any size, so an FT amount passed here is a units error (#505). The third
        element is a :data:`~pyrxd.security.units.ChainHeight` — the height the covenant was
        MINED at, never a confirmation depth; the two sort in opposite directions and the
        earliest-confirmed rule below inverts under the wrong one.
        """
        import hashlib

        # A script-hash-keyed client (e.g. SshTrRadiantClient via scantxoutset) can only
        # resolve a script_hash back to its SPK from a registry; an UNregistered covenant
        # SPK scans EMPTY and is misread as "not funded / already spent". A fresh per-swap
        # claim leg (sidecar_leg_resolver) never pre-registers, so register the SPK we are
        # about to scan here — idempotent, and a no-op for clients without register_spk.
        register = getattr(self._client, "register_spk", None)
        if callable(register):
            register(bytes(spk))
        script_hash = hashlib.sha256(bytes(spk)).digest()[::-1]
        utxos = await self._client.get_utxos(script_hash)
        if not utxos:
            raise NetworkError("no UTXO found for the covenant scriptPubKey (not yet funded / wrong SPK)")
        if expected_value is not None:
            utxos = [u for u in utxos if int(u.value) == int(expected_value)]
            if not utxos:
                raise NetworkError("no covenant UTXO matches the expected carrier value; fail-closed")
        if pin_outpoint is not None:
            # PIN, do not re-discover. The covenant scriptPubKey is a pure function of PUBLIC
            # negotiated terms, so anyone can pay it — and a second payment of the same value makes
            # this scan ambiguous. Refusing on ambiguity then denies the spend, which turns a
            # payment anyone can make into a permanent block on the taker's claim while the maker
            # waits out the CSV and refunds. Once the funded outpoint is known there is nothing to
            # discover: select it and ignore the noise. The value filter above still applies to it,
            # so a record pointing at a wrong-value output is still refused.
            picked = [u for u in utxos if f"{u.tx_hash}:{u.tx_pos}" == pin_outpoint]
            if not picked:
                raise NetworkError(
                    f"the recorded covenant outpoint {pin_outpoint} is not in this scriptPubKey's "
                    "live UTXO set — it has been spent, reorged out, or the record is wrong; "
                    "fail-closed"
                )
            utxos = picked
        if len(utxos) > 1:
            # SELECT, do not refuse. Refusing here was still the attack: the pin's only WRITER
            # comes through this discovery path, so poisoning the address BEFORE the outpoint is
            # recorded stopped the pin from ever being written — and every later spend then ran
            # unpinned, back to the original brick. A refusal that can be triggered by anyone
            # paying a public address is a denial, not a defence.
            #
            # Deterministic rule: the EARLIEST-confirmed match. The honest funding necessarily
            # precedes any poison (the address is only interesting once it is funded), and both
            # parties derive the same answer from the same chain, which a "deepest" or "first
            # returned" rule would not guarantee across differing UTXO orderings. Height 0 means
            # unconfirmed, which sorts last — a mempool output must never displace a mined one.
            #
            # "Earliest" is only earliest because u.height is a BLOCK HEIGHT. Ascending order on a
            # CONFIRMATION COUNT is newest-first, so a producer that stores confs in the field turns
            # this exact line into a poison-selector — the mainnet ssh-tr shim did, and every
            # real-value run inherited the inversion. The producer contract (height, 0=unconfirmed)
            # is enforced per producer by tests/test_utxo_record_units.py.
            utxos = sorted(utxos, key=lambda u: earliest_confirmed_key(int(u.height), u.tx_hash, u.tx_pos))
            _LOG.warning(
                "covenant scriptPubKey has %d matching UTXOs; selecting the earliest-confirmed "
                "(%s:%d at height %s). Extra payments to a covenant address are anyone's to make "
                "and must not block the spend.",
                len(utxos),
                utxos[0].tx_hash,
                utxos[0].tx_pos,
                utxos[0].height,
            )
        u = utxos[0]
        return f"{u.tx_hash}:{u.tx_pos}", PhotonValue(int(u.value)), ChainHeight(int(u.height))

    async def funding_evidence(
        self, outpoint: str, height: int, *, header_ranges: tuple[tuple[int, int], ...]
    ) -> MakerFundingEvidence:
        """Fetch what the swap taker gate needs to PROVE a covenant funding: nothing here is judged.

        The funding transaction's raw bytes, its merkle branch in block *height*, that block's
        coinbase branch (which pins the tree's depth), the header ranges the coordinator planned
        (:func:`pyrxd.gravity.funding_spv.funding_header_ranges`), and the depth each configured
        source reports (:meth:`depth_reports`). :func:`pyrxd.gravity.funding_spv.verify_maker_funding`
        decides what they prove; a reply this cannot fetch raises ``NetworkError``, and the gate
        refuses on it.

        Header ranges are fetched in ascending order and fetching stops at the first SHORT reply: a
        server answers fewer headers past its tip, so everything above that is beyond its chain.
        """
        client = self._proof_client
        needed = (
            "get_transaction",
            "get_transaction_merkle_branch",
            "get_transaction_id_from_pos",
            "get_block_headers",
        )
        missing = [m for m in needed if not callable(getattr(client, m, None))]
        if missing:
            raise NetworkError(
                f"this Radiant client cannot serve the proof of the maker's funding (it has no {', '.join(missing)}); "
                "the taker gate refuses without it — use an ElectrumX client"
            )
        txid, vout = _split_outpoint(outpoint)
        try:
            raw = bytes(await client.get_transaction(txid))
            merkle = await client.get_transaction_merkle_branch(txid, height)
            coinbase = await client.get_transaction_id_from_pos(height, 0)
            headers: dict[int, bytes] = {}
            for start, count in sorted(header_ranges):
                got = list(await client.get_block_headers(start, count))
                for i, header in enumerate(got):
                    headers.setdefault(start + i, bytes(header))
                if len(got) < count:
                    break
        except NetworkError:
            raise
        except Exception as exc:
            raise NetworkError(
                f"could not fetch the proof of the maker's funding: {type(exc).__name__}: {exc}"
            ) from exc
        reports = await self.depth_reports(txid, int(height))
        return MakerFundingEvidence(
            txid=txid.lower(),
            vout=vout,
            height=int(height),
            raw_tx=raw,
            merkle=merkle,
            coinbase_merkle=coinbase,
            headers=headers,
            reported_depths=reports.reported,
            funding_tx_depths=reports.funding_tx,
            operator_tip_headers=reports.tip_headers,
            configured_operators=self.configured_depth_operators(),
        )

    def _distinct_sources(self) -> list[Any]:
        seen: list[Any] = []
        for src in (self._client, self._proof_client, *self._depth_sources):
            if not any(src is s for s in seen):
                seen.append(src)
        return seen

    @staticmethod
    def _unidentified_label(index: int, src: Any) -> str:
        return f"{UNIDENTIFIED_SOURCE_PREFIX} #{index} ({type(src).__name__})"

    @classmethod
    def _operator_label(cls, index: int, src: Any) -> str:
        """*src*'s operator group, through the ONE funnel every quorum counts by
        (:func:`pyrxd.network.source_identity.source_key_of`): a :class:`SourceKey` derived from its
        URL. Anything else — no key, or a hand-chosen plain string, which would let one server
        wrapped twice as ``"a"`` and ``"b"`` count as two operators — is an unidentified source:
        its report can still raise the bound, and it never counts as an operator."""
        try:
            return str(source_key_of(src))
        except ValidationError:
            return cls._unidentified_label(index, src)

    @staticmethod
    def _splits(src: Any) -> bool:
        """A client over several operators' URLs that can be asked once per operator."""
        keys = getattr(src, "source_keys", None)
        return (
            getattr(src, "source_key", None) is None
            and isinstance(keys, tuple)
            and len(keys) > 1
            and callable(getattr(src, "per_source_clients", None))
        )

    def configured_depth_operators(self) -> tuple[str, ...]:
        """The operator groups this configuration asks for a funding's depth — ``client``,
        ``proof_client`` and every ``depth_sources`` reader — derived from each one's ``source_key``
        (every group of a client over several operators' URLs), each once. A source that cannot say
        which operator runs it appears as ``"unidentified source #i (<type>)"``, which
        :func:`pyrxd.gravity.funding_spv.counted_operators` does not count. Nothing is connected."""
        out: list[str] = []
        for index, src in enumerate(self._distinct_sources()):
            if self._splits(src):
                out.extend(
                    str(k) if isinstance(k, SourceKey) else self._unidentified_label(index, src)
                    for k in src.source_keys
                )
                continue
            out.append(self._operator_label(index, src))
        return tuple(dict.fromkeys(out))

    async def reported_depths(self, txid: str, height: int) -> tuple[tuple[str, int], ...]:
        """``((operator, depth), ...)``: :attr:`DepthReports.reported` of :meth:`depth_reports` — the
        depth each configured source reports for *txid* (mined at *height*), the larger of its
        verbose ``confirmations`` and its ``tip - height + 1``."""
        return (await self.depth_reports(txid, height)).reported

    async def depth_reports(self, txid: str, height: int) -> DepthReports:
        """What each configured source REPORTS about the depth of *txid* (mined at *height*) —
        ``client``, ``proof_client`` and every ``depth_sources`` reader, each once, and a client over
        several operators' URLs once per operator (on clients made for this call and closed before it
        returns).

        A source's ``reported`` depth is the larger of its verbose ``confirmations`` and its
        ``tip - height + 1``, whichever it answers; its ``funding_tx`` entry is the verbose
        ``confirmations`` alone, present only when it answered the verbose read for THIS txid with a
        positive count and a reply whose own ``txid`` names it. A source that answers neither is left out of both. Each is labelled by its
        ``source_key`` (its operator group, :func:`pyrxd.network.source_identity.source_key`), or
        ``"unidentified source #i (<type>)"`` for a client that cannot say — never merged with another.
        ``reported`` RAISES the gate's elapsed upper bound; above dust the gate counts the operators in
        ``funding_tx`` only. The proof does not depend on either.

        Each source is also asked for the :data:`TIP_HEADERS_FOR_WORK` headers ending at the tip it
        reported (``tip_headers``, with that tip), one header-range read, for the gate's maximum header
        work — which they can only RAISE: a source that serves none, or headers that do not count (see
        :func:`pyrxd.gravity.funding_spv._tip_run_max_work`), leaves the gate on the headers of the
        proof alone, and the gate says so.

        The sources are asked CONCURRENTLY, each under ``depth_timeout_s`` for its depth reads and again
        for its header read; one that times out or fails is left out exactly as one that answers
        neither. So an unresponsive operator costs the call at most two timeouts, not two per source
        in turn.
        """
        asked: list[tuple[int, Any]] = []
        made: list[Any] = []
        for index, src in enumerate(self._distinct_sources()):
            if self._splits(src):
                parts = tuple(src.per_source_clients())
                made.extend(parts)
                asked.extend((index, part) for part in parts)
            else:
                asked.append((index, src))
        try:
            answers = await self._ask_depths(asked, txid, height)
        finally:
            for part in made:
                with contextlib.suppress(Exception):
                    await part.close()
        reported: list[tuple[str, int]] = []
        funding_tx: list[tuple[str, int]] = []
        tip_headers: list[tuple[str, int, tuple[bytes, ...], int]] = []
        for label, confs, tip, served in answers:
            tip_depth = tip - height + 1 if tip is not None and tip >= height else None
            found = [d for d in (confs, tip_depth) if d is not None]
            if found:
                reported.append((label, max(found)))
            if confs is not None:
                funding_tx.append((label, confs))
            if served is not None and tip is not None:
                tip_headers.append((label, served[0], served[1], tip))
        return DepthReports(reported=tuple(reported), funding_tx=tuple(funding_tx), tip_headers=tuple(tip_headers))

    async def _ask_depths(
        self, asked: list[tuple[int, Any]], txid: str, height: int
    ) -> tuple[tuple[str, int | None, int | None, tuple[int, tuple[bytes, ...]] | None], ...]:
        async def one(
            index: int, src: Any
        ) -> tuple[str, int | None, int | None, tuple[int, tuple[bytes, ...]] | None] | None:
            try:
                confs, tip = await asyncio.wait_for(self._ask_one(index, src, txid, height), self._depth_timeout_s)
            except asyncio.TimeoutError:
                logger.debug("depth source %d did not answer within %.1f s", index, self._depth_timeout_s)
                return None
            served = None
            if tip is not None:
                # After the depth reads, on the same connection (see `_ask_one`); its own timeout, so a
                # slow header read never costs the depth answers already in hand.
                try:
                    served = await asyncio.wait_for(self._ask_tip_headers(index, src, tip), self._depth_timeout_s)
                except asyncio.TimeoutError:
                    logger.debug("depth source %d served no tip headers within %.1f s", index, self._depth_timeout_s)
            if confs is None and tip is None:
                return None
            return (self._operator_label(index, src), confs, tip, served)

        # Concurrently: one unresponsive operator costs one timeout, not one per source in turn.
        # `gather` keeps the order they were asked in.
        answers = await asyncio.gather(*(one(index, src) for index, src in asked))
        return tuple(a for a in answers if a is not None)

    @staticmethod
    async def _ask_tip_headers(index: int, src: Any, tip: int) -> tuple[int, tuple[bytes, ...]] | None:
        """``(start, headers)``: the :data:`TIP_HEADERS_FOR_WORK` headers ending at *tip*, as *src*
        serves them, or ``None`` when it cannot (no ``get_block_headers``, a failed read, nothing
        served). Nothing here is checked: the gate verifies each header and their linkage."""
        fetch = getattr(src, "get_block_headers", None)
        if not callable(fetch) or tip < 0:
            return None
        start = max(0, tip - TIP_HEADERS_FOR_WORK + 1)
        try:
            got = tuple(bytes(h) for h in await fetch(start, tip - start + 1))
        except Exception:
            logger.debug("depth source %d served no tip headers", index, exc_info=True)
            return None
        return (start, got) if got else None

    @staticmethod
    async def _ask_one(index: int, src: Any, txid: str, height: int) -> tuple[int | None, int | None]:
        """``(confirmations, tip)`` one source reports: its verbose ``confirmations`` for *txid*
        (``None`` unless it answered that read with a positive count) and its tip height (``None``
        unless it answered one at or above *height*); a read that fails is ``None``.

        The two reads are asked ONE AFTER THE OTHER. Only different sources run concurrently: two
        concurrent first calls on one fresh ``ElectrumXClient`` would each open a connection, and
        the reply to the one whose socket lost the race would never be read."""

        async def confirmations() -> int | None:
            verbose = getattr(src, "get_transaction_verbose", None)
            if not callable(verbose):
                return None
            try:
                info = await verbose(txid)
                # The reply must NAME the transaction asked about: a report of some other transaction's
                # confirmations is not a report of this one (every shipped mainnet operator's reply carries
                # a `txid` equal to the one requested, measured 2026-10-01). Hex, compared ignoring case.
                if not isinstance(info, dict) or not _names_txid(info.get("txid"), txid):
                    return None
                confs = finite_int(info.get("confirmations", 0) or 0)
                return confs if confs > 0 else None
            except Exception:
                logger.debug("depth source %d gave no confirmations", index, exc_info=True)
                return None

        async def from_tip() -> int | None:
            tip = getattr(src, "get_tip_height", None)
            if not callable(tip):
                return None
            try:
                t = finite_int(await tip())
                return t if t >= height else None
            except Exception:
                logger.debug("depth source %d gave no tip height", index, exc_info=True)
                return None

        return await confirmations(), await from_tip()

    async def covenant_unspent_incl_mempool(self, outpoint: str) -> bool | None:
        """Mempool-AWARE liveness of a covenant outpoint — the complement to
        ``find_covenant_utxo``'s mempool-BLIND scantxoutset scan.

        ``True`` = unspent considering the mempool; ``False`` = spent (confirmed OR by a
        PENDING mempool tx); ``None`` = the client cannot answer (the caller keeps its own
        idempotency guard). With a client that answers, the autonomous claim executor treats a
        covenant already spent IN THE MEMPOOL as claimed, which stops the per-tick re-carve
        without a durable cross-restart store.

        It delegates to an optional client method, ``txout_unspent_incl_mempool(txid, vout)``.
        No client shipped in pyrxd implements it (``ElectrumXClient`` does not), so with those
        clients this returns ``None`` and the caller's other guards (the SeenStore, the
        mempool-blind covenant scan) are all there is.
        """
        fn = getattr(self._client, "txout_unspent_incl_mempool", None)
        if not callable(fn):
            return None
        txid, vout = _split_outpoint(outpoint)
        return bool(await fn(txid, vout))


class _AlreadyKnown(Exception):
    """Internal sentinel: a broadcast hit an already-known tx (idempotent success)."""


# --------------------------------------------------------------------------- ref adapter


class RxinDexerRefAdapter:
    """Resolve a genesis ref to a :class:`ResolvedRef` via RXinDexer ``glyph.get_token``.

    Implements the ``RefAuthenticityIndexer`` protocol the pre-lock gate awaits.
    Maps the indexer's token dict to the inspectable fields the gate binds:

    * **genesis_outpoint** — from the token's ``ref_outpoint`` (``txid:vout``),
      re-encoded to the 36-byte wire ref so it compares equal to the advertised
      ``genesis_ref``. (``glyph.get_token`` only returns genuinely-minted Glyph
      tokens, so a resolvable token IS a ``gly`` reveal — see ``has_gly_marker``.)
    * **has_gly_marker** — ``True`` whenever the indexer returned a token dict for
      the ref (the indexer only indexes real ``gly`` envelopes). A bare wallet-UTXO
      singleton (the R1 forgery) resolves to ``None`` and the gate fails closed.
    * **payload_hash** — from ``payload_hash`` (bytes), or ``b""`` if absent.
    * **confirmations** — read separately from the genesis tx via ``chain_io``
      (``glyph.get_token`` does not carry confs).

    NOTE (T7 plan D3): a single indexer is a SPOF, and decoding a token dict is NOT
    SPV authenticity (no Merkle/header binding). For the regtest milestone the local
    node is ground truth; SPV-bound / multi-source cross-checking is the audit-gated
    track. This adapter is the single-indexer regtest backend.
    """

    def __init__(self, indexer: Any, chain_io: RadiantChainIO) -> None:
        if not hasattr(indexer, "glyph_get_token"):
            raise ValidationError("indexer must provide glyph_get_token()")
        if not isinstance(chain_io, RadiantChainIO):
            raise ValidationError("chain_io must be a RadiantChainIO")
        self._indexer = indexer
        self._chain_io = chain_io

    async def resolve_ref(self, genesis_ref: bytes) -> ResolvedRef | None:
        ref = GlyphRef.from_bytes(bytes(genesis_ref))  # raises on malformed -> gate fail-closed
        token = await self._indexer.glyph_get_token(f"{ref.txid}:{ref.vout}")
        if token is None:
            return None  # unknown token -> the gate fails closed (R1 forgery)
        if not isinstance(token, dict):
            raise NetworkError(f"glyph_get_token returned {type(token).__name__}, expected dict|None")

        resolved_outpoint = self._genesis_outpoint(token, ref)
        payload_hash = self._payload_hash(token)
        confs = await self._chain_io.confirmations(ref.txid)
        return ResolvedRef(
            genesis_outpoint=resolved_outpoint,
            has_gly_marker=True,  # glyph.get_token only resolves real gly reveals
            payload_hash=payload_hash,
            confirmations=confs,
        )

    @staticmethod
    def _genesis_outpoint(token: dict[str, Any], queried: GlyphRef) -> bytes:
        """Re-encode the token's reported genesis outpoint to the 36-byte wire ref.

        RXinDexer's ``glyph.get_token`` reports the genesis outpoint under
        ``glyph_id`` (``txid:vout``), alongside ``txid``+``vout`` and an
        ``is_reveal`` flag (verified against a live regtest RXinDexer 2026-06-01:
        a genuine reveal resolves with ``glyph_id == queried`` and
        ``is_reveal=True``; the commit outpoint and bare wallet UTXOs resolve to
        ``None``). We also accept the legacy ``ref_outpoint`` / ``ref_txid`` +
        ``ref_vout`` field names as fallbacks for other indexer builds.

        The token must be a genesis REVEAL for the outpoint to be a genesis: a
        transfer UTXO would report the genesis under ``glyph_id`` but is itself a
        different outpoint than ``queried``, so the gate's
        ``genesis_outpoint == advertised_ref`` binding would (correctly) reject it.
        If the indexer reports no resolvable outpoint, we return a value that will
        NOT equal the advertised ref, so the binding fails closed.
        """
        # RXinDexer native: glyph_id == "txid:vout" of the genesis reveal.
        glyph_id = token.get("glyph_id")
        if isinstance(glyph_id, str) and glyph_id.count(":") == 1:
            gid_txid, vout_s = glyph_id.split(":")
            try:
                return GlyphRef(txid=Txid(gid_txid.lower()), vout=int(vout_s)).to_bytes()
            except (ValidationError, ValueError):
                return b"\x00" * 36
        # RXinDexer native: separate txid + vout fields.
        txid = token.get("txid")
        vout = token.get("vout")
        if isinstance(txid, str) and isinstance(vout, int) and not isinstance(vout, bool):
            try:
                return GlyphRef(txid=Txid(txid.lower()), vout=vout).to_bytes()
            except (ValidationError, ValueError):
                return b"\x00" * 36
        # Legacy/alternate indexer field names.
        outpoint = token.get("ref_outpoint")
        if isinstance(outpoint, str) and outpoint.count(":") == 1:
            op_txid, vout_s = outpoint.split(":")
            try:
                return GlyphRef(txid=Txid(op_txid.lower()), vout=int(vout_s)).to_bytes()
            except (ValidationError, ValueError):
                return b"\x00" * 36
        rtxid = token.get("ref_txid")
        rvout = token.get("ref_vout")
        if isinstance(rtxid, str) and isinstance(rvout, int) and not isinstance(rvout, bool):
            try:
                return GlyphRef(txid=Txid(rtxid.lower()), vout=rvout).to_bytes()
            except (ValidationError, ValueError):
                return b"\x00" * 36
        # No outpoint reported -> cannot confirm it equals the advertised ref.
        return b"\x00" * 36

    @staticmethod
    def _payload_hash(token: dict[str, Any]) -> bytes:
        ph = token.get("payload_hash")
        if isinstance(ph, str):
            try:
                return bytes.fromhex(ph)
            except ValueError:
                return b""
        if isinstance(ph, (bytes, bytearray)):
            return bytes(ph)
        return b""


# --------------------------------------------------------------------------- fee source


@runtime_checkable
class FeeUtxoSource(Protocol):
    """Supplies a plain-RXD fee UTXO (+ its WIF) for a covenant spend."""

    def next_fee_input(self) -> FeeInput:  # pragma: no cover - Protocol
        ...


# --------------------------------------------------------------------------- the leg


class RadiantCovenantLeg:
    """The concrete Radiant ``radiant_leg`` (HTLC covenant claim/refund).

    Parameters
    ----------
    network:
        Radiant network tag. The coordinator reads it to decide whether the swap is
        value-bearing; the leg itself constructs on any tag.
    taker_pkh / maker_pkh:
        The taker (claim) and maker (refund) Radiant holder pubkey-hashes. The
        covenant binds ``hash256(holder(pkh))``; these must reproduce the terms'
        ``taker_dest_hash``/``maker_dest_hash`` (asserted in
        :meth:`expected_covenant_scriptpubkey`).
    chain_io:
        A :class:`RadiantChainIO` (broadcast + confirmations + UTXO value).
    fee_source:
        A :class:`FeeUtxoSource` supplying the fee input for each spend.
    min_confirmations:
        Confirmations required before the funded covenant value is trusted.
    audit_cleared:
        Accepted for backward compatibility and has no effect: it feeds
        :func:`pyrxd.btc_wallet.htlc_leg.require_audit_cleared`, a no-op since 0.9.0.
    fee_policy:
        The :class:`~pyrxd.gravity.fee_policy.DeadlineFeePolicy` the pre-broadcast
        affordability gate enforces. Defaults to the reference node's advertised
        0.10 RXD/kB effective relay rate; pass an explicit policy when the node this
        leg broadcasts to advertises a different ``effective_minrelaytxfee``.
    """

    def __init__(
        self,
        *,
        network: str,
        taker_pkh: bytes,
        maker_pkh: bytes,
        chain_io: RadiantChainIO,
        fee_source: FeeUtxoSource,
        min_confirmations: int = 1,
        audit_cleared: bool = False,
        fee_policy: DeadlineFeePolicy | None = None,
    ) -> None:
        require_audit_cleared(network, audit_cleared=audit_cleared)
        if not isinstance(chain_io, RadiantChainIO):
            raise ValidationError("chain_io must be a RadiantChainIO")
        if not isinstance(fee_source, FeeUtxoSource):
            raise ValidationError("fee_source must implement next_fee_input()")
        if not isinstance(min_confirmations, int) or isinstance(min_confirmations, bool) or min_confirmations < 0:
            raise ValidationError("min_confirmations must be a non-negative int")
        if fee_policy is not None and not isinstance(fee_policy, DeadlineFeePolicy):
            raise ValidationError("fee_policy must be a DeadlineFeePolicy or None")
        self.fee_policy = fee_policy or DEFAULT_RADIANT_DEADLINE_FEE_POLICY
        self.network = network
        self.taker_pkh = bytes(Hex20(taker_pkh))
        self.maker_pkh = bytes(Hex20(maker_pkh))
        self.chain_io = chain_io
        self.fee_source = fee_source
        self.min_confirmations = min_confirmations

    # -- covenant construction (binds the leg's pkhs to the terms) ----------
    def _build_covenant(self, terms: NegotiatedTerms) -> HtlcCovenant:
        if not isinstance(terms, NegotiatedTerms):
            raise ValidationError("terms must be a NegotiatedTerms")
        # F-002 (belt-and-suspenders; NegotiatedTerms already enforces this): the
        # covenant CSV operand is a BIP68 BLOCK count with no SECONDS path on this
        # leg, so terms.t_rxd.value is used raw as refund_csv. Refuse a non-BLOCKS
        # t_rxd fail-closed rather than silently coercing it.
        if terms.t_rxd.unit is not TimeUnit.BLOCKS:
            raise ValidationError("Radiant leg requires a BLOCKS t_rxd (no SECONDS CSV encoding); fail-closed")
        variant = terms.asset_variant
        if variant == "rxd":
            cov = build_htlc_covenant_rxd(
                amount=terms.radiant_amount,
                taker_pkh=self.taker_pkh,
                maker_pkh=self.maker_pkh,
                hashlock=terms.hashlock,
                refund_csv=terms.t_rxd.value,
            )
        else:
            ref = GlyphRef.from_bytes(terms.genesis_ref)
            if variant == "ft":
                cov = build_htlc_covenant_ft(
                    genesis_txid=ref.txid,
                    genesis_vout=ref.vout,
                    amount=terms.radiant_amount,
                    taker_pkh=self.taker_pkh,
                    maker_pkh=self.maker_pkh,
                    hashlock=terms.hashlock,
                    refund_csv=terms.t_rxd.value,
                )
            elif variant == "nft":
                cov = build_htlc_covenant_nft(
                    genesis_txid=ref.txid,
                    genesis_vout=ref.vout,
                    nft_carrier_value=terms.radiant_amount,
                    taker_pkh=self.taker_pkh,
                    maker_pkh=self.maker_pkh,
                    hashlock=terms.hashlock,
                    refund_csv=terms.t_rxd.value,
                )
            else:  # pragma: no cover - NegotiatedTerms already constrains the variant
                raise ValidationError(f"unsupported asset_variant {variant!r}")

        # Bind the leg's configured pkhs to what the terms committed: the covenant's
        # hash256(holder) MUST equal the negotiated dest hashes, else the leg is
        # configured for the wrong party/keys — fail closed before any spend.
        if cov.expected_taker_hash != terms.taker_dest_hash:
            raise ValidationError("covenant taker hash != terms.taker_dest_hash (wrong taker pkh?); fail-closed")
        if cov.expected_maker_hash != terms.maker_dest_hash:
            raise ValidationError("covenant maker hash != terms.maker_dest_hash (wrong maker pkh?); fail-closed")
        return cov

    async def expected_covenant_scriptpubkey(self, terms: NegotiatedTerms) -> bytes:
        """The covenant SPK the on-chain lock must equal (built from the terms)."""
        return self._build_covenant(terms).funded_spk

    async def covenant_outpoint(self, terms: NegotiatedTerms) -> str:
        """Locate the funded covenant UTXO ``txid:vout`` by scanning its SPK's UTXO set.

        The maker locks the asset into the covenant SPK (a pure function of the
        terms); the leg finds that single funded UTXO on-chain via ElectrumX. The
        carrier value is bound to ``terms.radiant_amount`` so a mis-funded covenant
        fails closed.
        """
        cov = self._build_covenant(terms)
        outpoint, _value, _height = await self.chain_io.find_covenant_utxo(
            cov.funded_spk,
            # Well-typed and correct for every variant. On Radiant an FT's quantity IS its
            # output's photon value (1 photon = 1 token unit), so matching `radiant_amount`
            # against the UTXO's native value is right for rxd, nft AND ft. #505 asserted
            # otherwise; see security/units.py for why that was wrong and how the type model
            # briefly manufactured evidence for it.
            expected_value=terms.radiant_amount,
        )
        return outpoint

    async def verify_maker_asset_funded(
        self, terms: NegotiatedTerms, *, min_confirmations: int | None = None
    ) -> tuple[str, int, int]:
        """A SERVER-REPORTED pre-check and locator of the maker's covenant funding — NOT the taker gate.

        Returns ``(outpoint, value_photons, confirmations)`` as ONE server reports them
        (``listunspent`` and verbose ``confirmations``: no merkle proof, no header), and RAISES on
        anything short of the checks below. A server that invents the covenant satisfies it, so
        passing it proves nothing a lying server cannot fake. The taker gate is
        :meth:`pyrxd.gravity.swap_coordinator.SwapCoordinator.taker_verify_asset_funding`, which
        PROVES the funding from :meth:`maker_funding_evidence` with
        :func:`pyrxd.gravity.funding_spv.verify_maker_funding` and no longer calls this. Its
        production caller is the coordinator's ``_covenant_elapsed_blocks``, the post-confirm
        ordering recheck's read of the covenant's depth — a measurement there, not a gate.

        The rule it was written for: ``docs/htlc-handshake-wire-format.md`` HZ-1 — *"a taker MUST NOT
        fund the counter leg until it has confirmed the maker's asset lock on chain, at the agreed
        scriptPubKey, for the agreed value, at a depth the taker chose."* Nothing else in the
        handshake gives the taker that. The BTC claim leaf is ``<H> … <makerClaimPk> OP_CHECKSIG``
        with no precondition that the asset was ever locked, and the maker holds both ``p`` and the
        claim key from the moment it publishes the envelope. So a maker that locks NOTHING and
        simply waits can sweep the taker's HTLC the instant it appears: the taker's loss is the
        full ``btc_sats``, and the FSM's nominal "taker locks first" ordering is bookkeeping, not
        a safety guarantee.

        What is checked, all fail-closed:

        1. the covenant scriptPubKey is **re-derived here from the taker's own ``terms``**
           (:meth:`_build_covenant` — amount, H, ``t_rxd`` CSV, both dest hashes, the asset REF),
           never taken from anything the maker advertises;
        2. that exact SPK holds a funded UTXO, and its ON-CHAIN value equals
           ``terms.radiant_amount`` — an unfunded SPK and a mis-valued one raise; SEVERAL matches do
           not (the earliest-confirmed is selected: :meth:`RadiantChainIO.find_covenant_utxo`);
        3. the funding is buried ``min_confirmations`` deep. "Funded" alone is NOT enough:
           ElectrumX ``listunspent`` includes MEMPOOL outputs, so a maker can fund with a
           replaceable transaction, wait for the taker's lock, then double-spend the funding away
           — it still claims the counter leg with ``p`` while the vanished covenant leaves the
           taker nothing to claim. ``None`` uses this leg's configured ``min_confirmations``; the
           coordinator passes the policy's RXD burial depth for a real-value swap.
        """
        cov = self._build_covenant(terms)
        required = self.min_confirmations if min_confirmations is None else int(min_confirmations)
        if not isinstance(required, int) or isinstance(required, bool) or required < 0:
            raise ValidationError("min_confirmations must be a non-negative int or None")
        outpoint, value, _height = await self.chain_io.find_covenant_utxo(
            cov.funded_spk,
            # Well-typed and correct for every variant. On Radiant an FT's quantity IS its
            # output's photon value (1 photon = 1 token unit), so matching `radiant_amount`
            # against the UTXO's native value is right for rxd, nft AND ft. #505 asserted
            # otherwise; see security/units.py for why that was wrong and how the type model
            # briefly manufactured evidence for it.
            expected_value=terms.radiant_amount,
        )
        confs = await self.chain_io.confirmations(outpoint.split(":")[0])
        if not isinstance(confs, int) or isinstance(confs, bool) or confs < 0:
            raise NetworkError("confirmations reader returned a non-negative-int depth; fail-closed")
        if confs < required:
            raise NetworkError(
                f"the maker's Radiant covenant funding {outpoint} has {confs} confirmation(s) < the required "
                f"{required}: a shallow/mempool funding is reorgable and can be double-spent away after the "
                "counter leg is locked. Wait for it to bury, then retry."
            )
        return outpoint, int(value), confs

    async def maker_funding_evidence(
        self,
        terms: NegotiatedTerms,
        *,
        header_ranges: Any,
        min_confirmations: int | None = None,
    ) -> MakerFundingEvidence:
        """TAKER-side: fetch the evidence the coordinator PROVES the maker's covenant funding from.

        The swap taker gate (``SwapCoordinator.taker_verify_asset_funding``) calls this and runs
        :func:`pyrxd.gravity.funding_spv.verify_maker_funding` on what it returns; nothing is
        judged here. The covenant scriptPubKey is re-derived from the taker's own ``terms``, and
        its ``listunspent`` entry is used only to LOCATE the outpoint and the height the server
        names for it — the script and value the coordinator accepts are read from the funding
        transaction's own raw bytes, and the height is proved or refused. The same read is what
        still stands behind "the output is unspent", which SPV cannot show.

        *header_ranges* is a callable ``height -> ((start, count), ...)``: the coordinator decides
        what to fetch once the height is known. *min_confirmations*, when given, is the depth the
        coordinator already knows it will require; a server that itself reports less is refused
        here before thousands of headers are fetched. That refusal is the only use of the reported
        depth on this path: a server over-reporting it gains nothing, because the proof decides.
        """
        cov = self._build_covenant(terms)
        outpoint, _listed_value, height = await self.chain_io.find_covenant_utxo(
            cov.funded_spk, expected_value=terms.radiant_amount
        )
        if int(height) <= 0:
            raise NetworkError(
                f"the maker's covenant funding {outpoint} is not yet mined (the server lists it unconfirmed); "
                "wait for it to confirm, then retry"
            )
        if min_confirmations is not None:
            reported = await self.chain_io.confirmations(outpoint.split(":")[0])
            if reported < int(min_confirmations):
                raise NetworkError(
                    f"the maker's Radiant covenant funding {outpoint} has {reported} confirmation(s) by the server's "
                    f"own count, below the {int(min_confirmations)} this swap requires before it is even proved. "
                    "Wait for it to bury, then retry."
                )
        return await self.chain_io.funding_evidence(outpoint, int(height), header_ranges=header_ranges(int(height)))

    def configured_depth_operators(self) -> tuple[str, ...]:
        """The operator groups this leg asks for the maker's funding depth
        (:meth:`RadiantChainIO.configured_depth_operators`): what the coordinator checks, before
        anyone locks, against the taker gate's two-operator rule above dust."""
        return self.chain_io.configured_depth_operators()

    # -- spends -------------------------------------------------------------
    async def _resolve_covenant(self, record: SwapRecord) -> tuple[HtlcCovenant, str, int, int]:
        """Build the covenant, locate its funded UTXO, conf-gate it, return value + depth.

        Reads the on-chain value (never a self-report) and rejects a covenant
        shallower than ``min_confirmations`` so a reorg cannot un-fund it mid-spend.
        The confirmation depth is returned alongside because the claim path needs it
        to compute blocks-to-deadline (the covenant's CSV refund branch opens at
        ``confirmations >= refund_csv``) — re-reading it would be a second network
        round-trip for a number we already have.
        """
        cov = self._build_covenant(record.terms)
        # Pin to the outpoint recorded when the covenant was revalidated. Re-deriving it by scan
        # would let anyone brick this spend by paying the covenant SPK a second time.
        outpoint, value, _height = await self.chain_io.find_covenant_utxo(
            cov.funded_spk,
            # Well-typed and correct for every variant — an FT amount IS a photon value on
            # Radiant. See security/units.py; #505 asserted the opposite and was wrong.
            expected_value=record.terms.radiant_amount,
            pin_outpoint=record.radiant_covenant_outpoint,
        )
        txid = outpoint.split(":")[0]
        confs = await self.chain_io.confirmations(txid)
        if confs < self.min_confirmations:
            raise NetworkError(
                f"covenant has {confs} confirmations < required {self.min_confirmations}; not yet spendable"
            )
        if (
            value <= 0
        ):  # pragma: no cover - defense-in-depth; find_covenant_utxo already pins value>0 via expected_value
            raise NetworkError("covenant output value is non-positive; fail-closed")
        return cov, outpoint, value, confs

    @contextlib.contextmanager
    def _unspent_on_failure(self, fee: FeeInput) -> Iterator[None]:
        """Report a dispensed fee input back to the source when the spend never gets built.

        The fee input must be dispensed BEFORE the transaction can be built (its value and
        script are inputs to the build), and the build can refuse: ``build_htlc_*_tx`` and
        :meth:`_assert_affordable` both raise :class:`InsufficientFundsError` when the
        dispensed input cannot clear the node's relay floor. Nothing reaches a node on that
        path and no fee is paid — but the source had already committed the input and charged
        its cumulative cap, so a run of refusals ate the operator's budget and left a funded
        pool that could no longer dispense the one input large enough to work (audit B3).

        Everything inside this block is strictly pre-broadcast, so a raise here provably means
        the input was never spent. The broadcast itself is deliberately OUTSIDE the block: once
        bytes are handed to a node the input may well be spent, and crediting it back then
        would under-count real spend against the cap.

        The report is duck-typed and optional — a plain ``FeeUtxoSource`` (only
        ``next_fee_input``) keeps working unchanged, it just does not get the credit.
        """
        try:
            yield
        except BaseException:
            release = getattr(self.fee_source, "release_unspent", None)
            if callable(release):
                try:
                    release(fee)
                except Exception:
                    logger.warning(
                        "could not return the unspent fee input %s:%s to the pool after a refused build",
                        fee.txid,
                        fee.vout,
                    )
            raise

    def _assert_affordable(self, tx: Any, fee: FeeInput, *, blocks_to_deadline: int | None, kind: str) -> None:
        """PRE-BROADCAST affordability gate (gap-closure A1) — refuse, and PAGE, rather
        than emit a time-critical spend that cannot be repaired.

        Radiant has no RBF and no CPFP (see :mod:`pyrxd.gravity.fee_policy`), so a
        transaction broadcast below the effective relay floor is not merely slow — it is
        unfixable, and it squats on its own inputs until mempool expiry (8h). If the
        deadline falls inside that window the asset is simply lost to the counterparty's
        refund. Failing loudly here is strictly better than that outcome.

        Sized against ``len(tx.serialize())`` — the exact wire bytes, not an estimate.
        The whole fee input is the miner fee (single-output covenant, no change).
        """
        try:
            target = assert_fee_covers(
                fee_value=fee.value,
                size_bytes=len(tx.serialize()),
                policy=self.fee_policy,
                blocks_to_deadline=blocks_to_deadline,
                what=f"HTLC covenant {kind} (pre-broadcast gate)",
            )
            # Above the node's floor but below the urgency TARGET: broadcast anyway (the
            # node accepts it, and refusing would hand the asset to the counterparty's
            # refund) but page — the operator should fund a larger pool before the next
            # deadline-critical spend.
            if fee.value < target:
                logger.warning(
                    "Radiant covenant %s on %s clears the relay floor but is below the "
                    "urgency target (%d < %d photons, blocks_to_deadline=%s) — broadcasting, "
                    "but inclusion may be slow; fund a larger fee input",
                    kind,
                    self.network,
                    fee.value,
                    target,
                    blocks_to_deadline,
                )
        except InsufficientFundsError as exc:
            # PAGE: an operator has to fund a larger fee input before this spend can go
            # out, and on the claim path the clock to the counterparty's refund is running.
            logger.error(
                "REFUSING to broadcast the Radiant covenant %s on %s: %s (blocks_to_deadline=%s)",
                kind,
                self.network,
                exc,
                blocks_to_deadline,
            )
            raise

    async def claim_asset(self, record: SwapRecord, preimage: bytes) -> str:
        """Build + broadcast the TAKER's claim spend (reveals ``p``). Returns the txid.

        Fee-sized against the DEADLINE: the maker's CSV refund branch opens once the
        covenant is ``t_rxd`` confirmations deep, so ``t_rxd - confirmations`` is the
        number of Radiant blocks in which this claim must be *mined*, not merely
        broadcast. The pre-broadcast gate refuses (and pages) if the dispensed fee input
        cannot meet that requirement — there is no post-broadcast remedy on Radiant.
        """
        if not isinstance(record, SwapRecord):
            raise ValidationError("record must be a SwapRecord")
        cov, outpoint, carrier, confs = await self._resolve_covenant(record)
        # The covenant CSV is a BIP68 BLOCK count (_build_covenant refuses any other
        # unit), so this subtraction is in Radiant blocks. Clamped at 0: a deadline
        # already passed takes the maximum urgency premium, never a negative one.
        blocks_to_deadline = blocks_to_claim_deadline(record.terms.t_rxd.value, confs)
        fee = self.fee_source.next_fee_input()
        with self._unspent_on_failure(fee):
            tx = build_htlc_claim_tx(
                covenant=cov,
                covenant_outpoint=outpoint,
                carrier_value=carrier,
                preimage=bytes(preimage),
                fee=fee,
                fee_policy=self.fee_policy,
            )
            self._assert_affordable(tx, fee, blocks_to_deadline=blocks_to_deadline, kind="claim")
        return await self._broadcast(tx)

    async def rebroadcast_claim_if_evicted(self, record: SwapRecord, preimage: bytes) -> str | None:
        """Re-broadcast the taker's claim if it has fallen out of the mempool. Returns the new txid,
        or None when nothing needed doing.

        WHY THIS EXISTS. A non-BIP68-final refund is rejected from the mempool
        (Radiant Core ``validation.cpp:724-728``), so the maker CANNOT pre-broadcast and a claim
        already sitting in the mempool at CSV maturity wins the race. The whole safety of the claim
        window therefore rests on the claim STAYING there — and Radiant has no RBF and no CPFP, so
        a claim that is evicted cannot be bumped back in. Mempool expiry is about eight hours.

        The coordinator broadcast the claim and advanced straight to a completed state, so an
        eviction was invisible: the maker's refund became valid at maturity, confirmed, and took
        both legs while the swap's own record said it had finished.

        Single-shot on purpose — no loop, no clock. The caller drives it on whatever tick it
        already has, which keeps this testable and keeps clock ownership where the rest of the
        module puts it.

        Returns None when the covenant is already spent (our claim is in the mempool or mined —
        nothing to do) and when the source ABSTAINS, because an unknown answer must not be treated
        as "evicted" and turned into a duplicate broadcast.
        """
        _cov, outpoint, _carrier, _confs = await self._resolve_covenant(record)
        unspent = await self.chain_io.covenant_unspent_incl_mempool(outpoint)
        if unspent is None:
            _LOG.warning(
                "could not determine whether the covenant %s is still unspent; NOT re-broadcasting "
                "(an unknown answer is not an eviction, and a duplicate broadcast is its own risk)",
                outpoint,
            )
            return None
        if not unspent:
            return None  # spent or in the mempool — the claim is alive
        _LOG.warning(
            "covenant %s is unspent again: the claim has been evicted or reorged out. Re-broadcasting "
            "— with no RBF and no CPFP this is the ONLY way back into the mempool, and the maker's "
            "refund becomes valid at CSV maturity.",
            outpoint,
        )
        return await self.claim_asset(record, preimage)

    async def refund_asset(self, record: SwapRecord) -> str:
        """Build + broadcast the MAKER's CSV refund spend. Returns the txid.

        P3 maturity self-check: the covenant's CSV refund leaf is only spendable once the covenant UTXO
        is buried ``t_rxd`` deep (the BIP68 relative-block timelock the covenant was built with:
        ``refund_csv=t_rxd.value``, mature at ``confirmations >= t_rxd.value``). Refuse a non-final
        refund HERE rather than emit a tx a node rejects — under a deadline-pinning mempool "rely on
        node rejection" is fragile — with an exact "needs N confirmations, has M" message a block-based
        poller retries on. This guards EVERY ``refund_asset`` caller (``mutual_refund``,
        ``maybe_refund_asset_on_maker_stall``) at the leg, complementing the coordinator-side height
        check in ``maybe_refund_asset_on_maker_stall``. (The CLAIM branch has no CSV, so ``claim_asset``
        is intentionally NOT gated this way.)
        """
        if not isinstance(record, SwapRecord):
            raise ValidationError("record must be a SwapRecord")
        cov, outpoint, carrier, _confs = await self._resolve_covenant(record)
        required_csv = record.terms.t_rxd.value
        confs = await self.chain_io.confirmations(outpoint.split(":")[0])
        if confs < required_csv:
            raise NetworkError(
                f"covenant CSV refund is not yet mature: needs {required_csv} confirmations, has {confs} "
                f"({required_csv - confs} block(s) to go) — refusing to broadcast a non-final refund "
                "(P3 maturity self-check); poll and retry at maturity rather than relying on node rejection."
            )
        fee = self.fee_source.next_fee_input()
        with self._unspent_on_failure(fee):
            tx = build_htlc_refund_tx(
                covenant=cov,
                covenant_outpoint=outpoint,
                carrier_value=carrier,
                fee=fee,
                fee_policy=self.fee_policy,
            )
            # blocks_to_deadline=None (the plain relay floor, no urgency premium): unlike the
            # claim, the CSV refund has no closing window. It only becomes broadcastable AT
            # maturity and stays valid indefinitely thereafter — the competing claim branch
            # needs p, which on this path the counterparty has not revealed. A premium here
            # would burn fee for urgency that does not exist. The floor itself still binds.
            self._assert_affordable(tx, fee, blocks_to_deadline=None, kind="refund")
        return await self._broadcast(tx)

    async def _broadcast(self, tx: Any) -> str:
        raw = tx.serialize()
        try:
            return await self.chain_io.broadcast(raw)
        except _AlreadyKnown:
            # Idempotent: the node already has this exact tx -> its txid is authoritative.
            return str(tx.txid())
