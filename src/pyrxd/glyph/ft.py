"""Fungible-token (FT) UTXO management and transfer-tx construction.

Radiant FTs use ``OP_PUSHINPUTREF (0xd0)`` in their locking script (unlike NFT
singletons which use ``OP_PUSHINPUTREFSINGLETON (0xd8)``), and every FT transfer
must satisfy **conservation**:

    sum(input FT amounts) >= sum(output FT amounts)

That is ``>=``, not ``==``: the epilogue opcode is ``0xa2``
(``OP_GREATERTHANOREQUAL``), so inflation is impossible but **burning is
permitted**. pyrxd's builders emit exact-balance transactions anyway — a
transfer that silently burned the difference would be a fund-loss bug — but an
implementation reading the chain must not assume every transfer balanced. The
full opcode walk is in ``pyrxd.glyph.script`` and in
``docs/reference/glyph-token-protocol-spec.md`` §9.2.

This module owns the fee-aware transfer builder. Mirrors the two-pass signing
pattern in :meth:`GlyphBuilder.build_nft_transfer_tx` (see that method's
docstring for the stale-signature pitfall we defend against).

``value`` and ``ft_amount`` are the SAME NUMBER on chain
-------------------------------------------------------
This module was written around a model where ``FtUtxo.ft_amount`` (the token
quantity) and ``FtUtxo.value`` (the RXD on the output) are **orthogonal**:
conservation applies to one, fee and dust accounting to the other. That model is
wrong for Radiant. An FT's quantity *is* its output's ``satoshis`` — 1 photon =
1 token unit (``docs/concepts/radiant-fts-are-on-chain.md``), which is exactly
what the CLI constructs (``ft_amount = utxo.value``).

The distinction is not academic. :meth:`FtUtxoSet.build_transfer_tx` used to size
the recipient's output from the RXD budget (``rxd_in - fee - change_alloc``)
rather than from ``amount``, so on a real holding it delivered the wrong number
of tokens — measured at 46,739,454 units for an ``amount=250`` transfer out of a
50,000,000-unit UTXO. An interim fix bolted an ``if value == ft_amount: raise``
tripwire onto it, which is not a fix: a re-run at **±1 photon** still delivered
46.7 million units for a 250-unit request, because the sizing expression was
untouched. Predicting which input shapes are wrong cannot make a wrong
expression right.

``build_transfer_tx`` is therefore now a **single-recipient call into**
:meth:`FtUtxoSet.build_airdrop_tx`, which has always been written for the real
model:

* every output's value is the units it carries, so the recipient receives
  exactly ``amount`` for any input shape — by construction, not by guard;
* the fee therefore cannot come out of a token output — that would burn units —
  so it comes from plain-RXD :class:`AirdropFunding` inputs, which
  ``build_transfer_tx`` now also takes.

One implementation, so the two cannot drift apart again. The ``value !=
ft_amount`` check that survives inside ``build_airdrop_tx`` is a fail-closed
backstop against a caller who built :class:`FtUtxo` from the wrong field, not
the thing that makes the amount correct.

Other design notes
------------------
* ``FtUtxoSet.select`` uses a trivial greedy-largest-first strategy. Smarter
  coin-selection (branch-and-bound etc.) is out of scope here.
* :meth:`FtUtxoSet.build_airdrop_tx` gives each recipient exactly the units
  requested and returns the remaining funding as plain-RXD change, so an airdrop
  never gifts the sender's RXD to recipient #1.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from pyrxd.constants import DUST_THRESHOLD_PHOTONS
from pyrxd.fee_sizing import (
    SIG_SIZE_SLACK_BYTES,
    assert_fee_rate_clears_relay_floor,
    assert_pays_for_its_size,
    relay_floor_photons_per_byte,
    trial_size_with_slack,
)
from pyrxd.security.errors import ValidationError
from pyrxd.security.types import Hex20

from .royalty import RoyaltyPayout, royalty_output_scripts, royalty_payouts
from .script import build_ft_locking_script, extract_ref_from_ft_script, is_ft_script
from .types import GlyphRef, GlyphRoyalty

# Post-V2 relay minimum, DERIVED from the one definition of Radiant's effective
# relay floor (10_000_000 photons/kB) rather than restated — see
# :mod:`pyrxd.fee_sizing`, which now owns that constant precisely so the wallet,
# the glyph builders and the swap stack cannot drift apart on it.
MIN_FEE_RATE: int = relay_floor_photons_per_byte()  # photons / byte

# pyrxd POLICY, not a chain rule — and the distinction is load-bearing here,
# because this is the value re-exported as ``FT_DUST_LIMIT`` and defaulted into
# ``FtTransferParams``/``FtAirdropParams``. Radiant has NO dust threshold:
# ``GetDustThreshold`` returns 1 satoshi and ``IsDust`` is ``nValue <= 0``
# (Radiant-Core/src/policy/policy.cpp:19-25) — and standardness is not consulted
# at all, since ``fRequireStandard`` is hardcoded ``false``
# (Radiant-Core/src/validation.cpp:271, re-set unconditionally at
# src/init.cpp:1995), which is the only reason a 75-byte FT script relays in the
# first place (``Solver`` classifies it ``TX_NONSTANDARD``). So there is no path
# by which a sub-546 output is rejected. (Line numbers are @ tag ``v3.1.2``, the
# version pinned in ``tests/vendor/radiant_core/MANIFEST.json``.)
#
# It is used ONLY as a fold-to-fee threshold for the plain-RXD CHANGE output.
# It is deliberately NOT a floor on a token output: an FT output's value IS its
# unit count, so a 546 floor would forbid transferring 100 units of anything —
# and the comment that used to sit here, "standard relay dust threshold", is
# exactly the false premise that produced that class of refusal elsewhere in
# this SDK.
#
# Aliased from :data:`pyrxd.constants.DUST_THRESHOLD_PHOTONS` (the one definition);
# the name is kept because it is public API and re-exported as ``FT_DUST_LIMIT``.
DUST_LIMIT: int = DUST_THRESHOLD_PHOTONS  # photons — pyrxd change-output policy; see above

# A pyrxd ergonomics guard, NOT a chain rule. Radiant's ``MAX_STANDARD_TX_SIZE``
# is 20_000_000 bytes (``Radiant-Core/src/policy/policy.h:69`` @ ``v3.1.2``),
# so an airdrop is limited by what it costs, not by what relays: one FT output is
# 84 serialised bytes (75-byte script + 8-byte value + 1-byte length), which at
# the 10_000 photons/byte relay floor is ~840_000 photons — 0.0084 RXD — of fee
# per recipient. 1000 recipients is therefore ~8.4 RXD in fee before any dust,
# which is a deliberate decision rather than a typo in a recipient file. Raise it
# explicitly if you mean it.
MAX_AIRDROP_RECIPIENTS: int = 1000

# Per-input headroom added to the trial-pass size before the fee is computed.
# The reasoning, the measurements and the value now live in :mod:`pyrxd.fee_sizing`,
# which is the single implementation of this rule for every builder in the SDK —
# this module, the swap CLI, and (as of the fee-undersizing fix) ``pyrxd.wallet``.
# Re-bound here rather than re-derived so the name keeps working for callers and
# tests that reference it.
_SIG_SIZE_SLACK_BYTES: int = SIG_SIZE_SLACK_BYTES


def _check_fee_rate(fee_rate: int, *, allow_overpay: bool = False, allow_below_relay_floor: bool = False) -> None:
    """Reject a fee rate the network will not relay.

    Radiant has neither RBF nor CPFP (threat-model S21, verified against
    ``Radiant-Core`` @ ``v3.1.2``), so an under-fee'd transaction cannot be
    bumped by any means: it squats on its own inputs until mempool expiry, 8
    hours later. That makes a sub-floor rate a fund-safety bug, not a tuning
    mistake, which is why this refuses rather than warns.

    The CHECK, not merely the floor, is taken from :mod:`pyrxd.fee_sizing` — this
    used to be a second copy of the same three lines, and the NFT transfer builder
    next door had a third copy of *nothing*, which is the bug that made this shared.
    Kept as a named function because its callers document it by name.

    ``allow_below_relay_floor`` is the sub-floor escape hatch the mint paths have had
    since #456. Until #458 the transfer paths had no equivalent, and
    :func:`~pyrxd.fee_sizing.relay_floor_photons_per_byte` is a fixed **mainnet**
    constant, so a regtest node running at a tenth of that floor could mint but not
    transfer — the guard refused work that was valid on the caller's own chain.
    """
    assert_fee_rate_clears_relay_floor(
        fee_rate,
        what="FT builder",
        allow_overpay=allow_overpay,
        allow_below_relay_floor=allow_below_relay_floor,
    )


def outpoint_key(txid: str, vout: int) -> tuple[str, int]:
    """Canonical identity of an outpoint, for comparing one against another.

    A txid is a 32-byte hash *rendered* as hex, and hex has no case: the wire form is
    ``bytes.fromhex(txid)[::-1]``, which is byte-identical for ``"ab…"`` and ``"AB…"``.
    Every duplicate-outpoint guard in this module compared the rendering instead of the
    identity, so a caller who mixed cases — trivially, one txid from a JSON API that
    upper-cases and one from a local read — walked straight through all three of them.

    Measured before this existed, with one 1,000-photon UTXO listed twice, the second
    time upper-cased: :class:`FtUtxoSet` accepted the set, ``total()`` reported
    **2,000**, and the builder went on to sign a transaction with a duplicate input that
    no node accepts. That is precisely the failure the guards were added to stop; they
    simply were not looking at the outpoint.

    Case-folding is a canonicalisation, not a validation — it cannot refuse anything
    that used to work, and a non-hex ``txid`` is left to the caller and the serialiser
    to reject as before.
    """
    return (txid.lower() if isinstance(txid, str) else txid, vout)


@dataclass(frozen=True)
class FtUtxo:
    """A single UTXO holding some quantity of one FT.

    ``value`` and ``ft_amount`` are the SAME NUMBER, and this class refuses to
    hold them apart. Radiant's FT conservation epilogue sums the *satoshi
    values* of the outputs carrying the token's code-script hash
    (``OP_CODESCRIPTHASHVALUESUM_UTXOS`` / ``_OUTPUTS`` push
    ``sumAmount / SATOSHI`` — ``Radiant-Core/src/script/interpreter.cpp:2196``
    and ``:2215``), so an FT's quantity is not merely *conventionally* its
    output value, it **is** its output value at the consensus layer. There is no
    second number to disagree with.

    Why that is enforced *here*, in ``__post_init__``, rather than in the
    builder that consumes it: an ``FtUtxo`` with ``value != ft_amount``
    describes a UTXO that has never existed on Radiant and never can, and this
    repo has already shipped the consequence twice. The transfer builder used to
    size the recipient output from the inputs' RXD instead of the requested
    amount and delivered 46,739,454 units for an ``amount=250`` request; the
    first "fix" was an ``if value == ft_amount: raise`` guard *inside the
    builder*, which left the fund loss reachable at ``value == ft_amount ± 1``.
    A guard inside one caller only protects that caller. Refusing at
    construction means no ``FtUtxo`` anywhere in the process can carry the bad
    state, so no builder — including one not yet written — can be handed it.

    It also fixes the two set-level queries that had no guard at all:
    :meth:`FtUtxoSet.total` sums ``ft_amount`` and :meth:`FtUtxoSet.select`
    ranks and covers by it, so a wrong ``ft_amount`` used to report a wrong
    balance and pick the wrong inputs long before any builder's backstop ran.

    Build one with :meth:`from_output` when reading a UTXO off chain — it takes
    the output value once and there is no second field to get wrong.

    :param txid:        txid of the UTXO
    :param vout:        output index within that tx
    :param value:       photons on the output — which IS the token quantity
    :param ft_amount:   token units held on the output. Must equal ``value``;
                        kept as an explicit field only so existing callers and
                        the ``u.ft_amount`` reading sites keep working.
    :param ft_script:   full FT locking script (75 bytes, see
                        :func:`pyrxd.glyph.script.build_ft_locking_script`)

    :raises ValidationError: ``value`` or ``ft_amount`` is not a non-negative
        ``int``, or the two differ.
    """

    txid: str
    vout: int
    value: int
    ft_amount: int
    ft_script: bytes

    def __post_init__(self) -> None:
        # Canonicalise the txid's case at construction, so no comparison anywhere —
        # including one not yet written — can be fooled by the rendering. The guards
        # in this module also fold through ``outpoint_key``, because a guard living in
        # one caller only protects that caller (the lesson this class's own docstring
        # records). Hex has no case, so this cannot refuse anything.
        if isinstance(self.txid, str):
            object.__setattr__(self, "txid", self.txid.lower())
        # ``bool`` is an ``int`` subclass, and ``True`` would sail through every
        # arithmetic check below as 1 — reject it by type, not by value. Same
        # for ``float``: 1.5 passed the old ``ft_amount < 0`` check.
        for name, v in (("value", self.value), ("ft_amount", self.ft_amount)):
            if isinstance(v, bool) or not isinstance(v, int):
                raise ValidationError(f"{name} must be int, got {type(v).__name__!r}: {v!r}")
            if v < 0:
                raise ValidationError(f"{name} must be >= 0, got {v}")
        if self.value != self.ft_amount:
            raise ValidationError(
                f"FtUtxo {self.txid}:{self.vout} has value={self.value} but ft_amount={self.ft_amount}. "
                "On Radiant an FT's quantity IS its output value (1 photon = 1 unit — the conservation "
                "epilogue sums output satoshis, Radiant-Core src/script/interpreter.cpp:2215), so this "
                "UTXO cannot exist on chain. You almost certainly meant FtUtxo.from_output(...), which "
                "takes the value once."
            )

    @classmethod
    def from_output(cls, *, txid: str, vout: int, value: int, ft_script: bytes) -> FtUtxo:
        """An :class:`FtUtxo` read straight off a chain output.

        The preferred constructor: the token quantity is taken from the output's
        value rather than supplied a second time, so the two cannot disagree.
        """
        return cls(txid=txid, vout=vout, value=value, ft_amount=value, ft_script=ft_script)


@dataclass
class FtTransferResult:
    """Output of :meth:`FtUtxoSet.build_transfer_tx`.

    :param tx:                 signed :class:`Transaction`, ready to broadcast
    :param new_ft_script:      locking script of the transfer (recipient) output
    :param change_ft_script:   locking script of the change output, or
                               ``None`` if the transfer was an exact match
    :param ref:                the FT's :class:`GlyphRef`
    :param fee:                fee paid in photons

    .. note::
       No ``royalty_payouts`` here, unlike :class:`FtAirdropResult`. Paying a
       royalty without reporting who was paid would be worse than not offering
       it, so :meth:`FtUtxoSet.build_transfer_tx` takes no ``royalty`` argument
       at all. Use :meth:`FtUtxoSet.build_airdrop_tx` (one recipient is a legal
       airdrop) when a royalty is in play — it returns the payouts.
    """

    tx: Any
    new_ft_script: bytes
    change_ft_script: bytes | None
    ref: GlyphRef
    fee: int


@dataclass(frozen=True)
class AirdropRecipient:
    """One destination in a multi-recipient FT airdrop.

    :param pkh:    recipient's 20-byte public-key hash.
    :param amount: FT units for this recipient, and — because 1 photon is 1
                   unit on Radiant — the exact photon value of their output.
                   Must be ``> 0``.
    """

    pkh: Hex20
    amount: int


@dataclass(frozen=True)
class AirdropFunding:
    """A plain-P2PKH RXD UTXO that pays an airdrop's fee (and any royalty).

    The token cannot pay its own fee: an FT output's value *is* its unit count,
    so taking the fee out of one would burn units and deliver less than the
    caller asked for. Plain RXD covers it instead — the same reason
    ``transfer-nft`` sources a separate input to move a dust-carrying singleton.

    Each funding UTXO carries its own key, so the RXD may sit at a different
    wallet address from the token. (The FT inputs themselves still share one
    key; that restriction is inherited from :meth:`FtUtxoSet.build_transfer_tx`.)

    :param txid:        txid of the plain-P2PKH UTXO
    :param vout:        output index within that tx
    :param value:       photons available. Must be a positive ``int``, checked
                        here for the same reason :class:`FtUtxo` checks its own:
                        this number is summed into the RXD budget the fee comes
                        out of, and a wrong one used to be noticed only much
                        later and unhelpfully — measured as
                        ``'float' object has no attribute 'to_bytes'`` from the
                        middle of output serialisation for ``1_000_000.5``,
                        ``OverflowError`` for a negative, and for ``True`` a
                        nonsense "budget 1 photons" in the funding error.
    :param private_key: :class:`pyrxd.keys.PrivateKey` that unlocks it

    :raises ValidationError: ``value`` is not a positive ``int``.
    """

    txid: str
    vout: int
    value: int
    private_key: Any

    def __post_init__(self) -> None:
        # Same canonicalisation as :class:`FtUtxo`, for the same reason: the funding
        # list and the FT list are compared against each other across the seam in
        # ``estimate_airdrop``, so they have to agree on what an outpoint IS.
        if isinstance(self.txid, str):
            object.__setattr__(self, "txid", self.txid.lower())
        # ``bool`` first: it is an ``int`` subclass, so ``True`` would pass every
        # arithmetic check below as 1.
        if isinstance(self.value, bool) or not isinstance(self.value, int):
            raise ValidationError(
                f"AirdropFunding {self.txid}:{self.vout} value must be int (photons), "
                f"got {type(self.value).__name__!r}: {self.value!r}"
            )
        if self.value <= 0:
            raise ValidationError(
                f"AirdropFunding {self.txid}:{self.vout} value must be > 0 photons, got {self.value}. "
                "A funding input exists to pay the fee; one worth nothing cannot."
            )


@dataclass
class FtAirdropResult:
    """Output of :meth:`FtUtxoSet.build_airdrop_tx`.

    :param tx:                 signed :class:`Transaction`, ready to broadcast
    :param recipient_scripts:  FT locking scripts, index-aligned with the
                               ``recipients`` argument and with ``tx.outputs``
                               — the builder never reorders an airdrop list, so
                               a caller can reconcile who got what by index.
    :param change_ft_script:   locking script of the FT change output, or
                               ``None`` when the airdrop consumed the selected
                               inputs exactly.
    :param rxd_change_photons: photons returned as a plain P2PKH change output,
                               or ``0`` when there was none (see the builder's
                               docstring for where leftover RXD goes).
    :param royalty_payouts:    royalty recipients actually paid, in output order.
    :param ref:                the FT's :class:`GlyphRef`
    :param fee:                fee paid in photons. This is the **actual** fee —
                               ``value_in - value_out`` — which can exceed
                               ``size * fee_rate`` when a sub-dust remainder was
                               folded into it rather than emitted as change.
    """

    tx: Any
    recipient_scripts: tuple[bytes, ...]
    change_ft_script: bytes | None
    rxd_change_photons: int
    royalty_payouts: tuple[RoyaltyPayout, ...]
    ref: GlyphRef
    fee: int
    recipients: tuple[AirdropRecipient, ...] = field(default_factory=tuple)


class FtUtxoSet:
    """Manages a set of FT UTXOs for a single token ``ref``.

    Responsibilities:

    * Total the FT amount across the set.
    * Select a minimum set of UTXOs to cover a requested transfer amount.
    * Build + sign a transfer tx (two-pass fee calculation) that respects
      conservation.
    """

    def __init__(self, ref: GlyphRef, utxos: list[FtUtxo]) -> None:
        if not isinstance(ref, GlyphRef):
            raise ValidationError("ref must be a GlyphRef")
        if not isinstance(utxos, list):
            raise ValidationError("utxos must be a list")
        # An outpoint is unique on chain, so the same ``(txid, vout)`` twice is
        # always a caller mistake — and an expensive one, because nothing further
        # down notices. Measured before this check: a set holding one UTXO twice
        # reported DOUBLE the real balance from :meth:`total`, :meth:`select`
        # returned the same outpoint twice, and :meth:`build_airdrop_tx` went on to
        # sign a transaction carrying a duplicate input (rejected by every node as
        # ``bad-txns-inputs-duplicate``) while reporting a fee 4x the real one. The
        # check is on ``(txid, vout)`` and not on ``txid`` alone: one transaction
        # paying a holder at several output indexes is ordinary.
        #
        # The key goes through ``outpoint_key`` rather than using ``u.txid`` raw:
        # a txid is case-insensitive hex, so the guard has to compare it the way
        # the WIRE does. See ``outpoint_key`` for the measurement.
        seen_outpoints: set[tuple[str, int]] = set()
        for u in utxos:
            # ``value``/``ft_amount`` type, sign and equality are not re-checked
            # here: :meth:`FtUtxo.__post_init__` refuses to build an instance
            # that fails any of them, so an ``FtUtxo`` that reaches this loop has
            # already satisfied them. Re-stating the checks would be a second
            # copy of a rule to drift, and this repo's FT fund-loss bug came from
            # exactly that shape — a guard living in one caller instead of in the
            # type.
            if not isinstance(u, FtUtxo):
                raise ValidationError("utxos must contain FtUtxo instances")
            # Reject non-FT scripts (e.g. plain P2PKH) up front. The Radiant
            # node would later reject the broadcast with "bad-txns-inputs-
            # outputs-invalid-transaction-reference-operations" because no
            # input carries the ref the output materialises — fail fast with
            # a useful error instead of a cryptic mempool rejection.
            if not isinstance(u.ft_script, (bytes, bytearray)):
                raise ValidationError(
                    f"ft_script must be bytes (the 75-byte on-chain locking script of the UTXO "
                    f"you're spending), got {type(u.ft_script).__name__!r}"
                )
            if not is_ft_script(bytes(u.ft_script).hex()):
                raise ValidationError(
                    f"UTXO {u.txid}:{u.vout} ft_script is not a valid 75-byte FT locking script. "
                    f"FT transfers can only spend FT UTXOs (script: 76a914<pkh>88ac bdd0 <ref:36> "
                    f"dec0e9aa76e378e4a269e69d). Spending a plain P2PKH UTXO and producing an FT "
                    f"output violates ref conservation and will be rejected by the network."
                )
            input_ref = extract_ref_from_ft_script(bytes(u.ft_script))
            if input_ref != ref:
                raise ValidationError(
                    f"UTXO {u.txid}:{u.vout} carries ref {input_ref} which differs from the set's ref {ref}"
                )
            outpoint = outpoint_key(u.txid, u.vout)
            if outpoint in seen_outpoints:
                raise ValidationError(
                    f"UTXO {u.txid}:{u.vout} appears more than once in this set. An outpoint is unique on "
                    "chain, so a repeat is a duplicated read rather than a second holding: it would report "
                    "twice the real balance from total(), let select() return the same outpoint twice, and "
                    "produce a transaction with a duplicate input that no node will accept."
                )
            seen_outpoints.add(outpoint)
        self.ref = ref
        self.utxos = list(utxos)

    # ----------------------------------------------------------------- queries

    def total(self) -> int:
        """Return the sum of ``ft_amount`` across all UTXOs in the set."""
        return sum(u.ft_amount for u in self.utxos)

    def select(self, amount: int) -> list[FtUtxo]:
        """Greedily select the minimum number of UTXOs covering ``amount``.

        Strategy: sort by ``ft_amount`` descending, take until covered.

        :raises ValueError: ``amount`` exceeds :meth:`total` (including the
            empty-set case, where ``total == 0``).
        """
        if amount <= 0:
            raise ValueError(f"amount must be > 0, got {amount}")
        if self.total() < amount:
            raise ValueError(f"Insufficient FT balance: requested {amount}, have {self.total()}")

        # Descending by ft_amount, then by value as a stable tiebreaker.
        sorted_utxos = sorted(self.utxos, key=lambda u: (-u.ft_amount, -u.value))
        selected: list[FtUtxo] = []
        running = 0
        for u in sorted_utxos:
            selected.append(u)
            running += u.ft_amount
            if running >= amount:
                break
        return selected

    # ------------------------------------------------------------ royalty glue

    @staticmethod
    def _resolve_royalty(
        royalty: GlyphRoyalty | None,
        sale_price: int,
        pay_royalty: bool | None,
    ) -> tuple[RoyaltyPayout, ...]:
        """Payouts a transfer should honour, or ``()``.

        Three-way, and the default consults the token rather than overriding it:

        * ``None`` — pay iff ``royalty.enforced``. That flag is the creator's own
          statement about whether wallets should insist, and it defaults to
          ``False`` everywhere a ``GlyphRoyalty`` is built. This builder used to
          ignore it and pay anyway, which spends the *sender's* funding photons
          on a payment the creator did not ask to be insisted on.
        * ``True`` — pay regardless. The explicit opt-in: an advisory royalty a
          caller has decided to honour is exactly the case this exists for.
        * ``False`` — never pay. Not a cheat: a royalty on an ordinary transfer
          is advisory (see :mod:`pyrxd.glyph.royalty`), so a caller who skips it
          is not breaking a rule the chain would have enforced.

        The decision is recorded in the result either way, so it is visible
        rather than silent.
        """
        if royalty is None or pay_royalty is False:
            return ()
        if pay_royalty is None and not royalty.enforced:
            return ()
        return royalty_payouts(royalty, sale_price)

    # --------------------------------------------------------------- tx build

    def build_transfer_tx(
        self,
        amount: int,
        new_owner_pkh: Hex20,
        private_key: Any,
        fee_rate: int = MIN_FEE_RATE,
        change_pkh: Hex20 | None = None,
        dust_limit: int = DUST_LIMIT,
        funding: Sequence[AirdropFunding] = (),
        *,
        allow_overpay: bool = False,
        allow_below_relay_floor: bool = False,
    ) -> FtTransferResult:
        """Build a signed FT transfer: ``amount`` units of this token to one PKH.

        A single-recipient :meth:`build_airdrop_tx`, and deliberately nothing
        more. The recipient output's value **is** ``amount`` and the change
        output's value **is** ``ft_in - amount``, because on Radiant an FT's
        quantity is its output's ``satoshis`` — 1 photon = 1 unit
        (``docs/concepts/radiant-fts-are-on-chain.md``).

        .. warning::
           **Fund-safety history — read before "simplifying" this back.** This
           method used to size the recipient output from the inputs' RXD
           (``rxd_in_total - fee - change_alloc``) rather than from ``amount``.
           On a realistic holding — one 50,000,000-unit UTXO, ``amount=250`` —
           that delivered **46,739,454 units** to the recipient and kept 546:
           the sender's whole balance, silently, to a counterparty who asked for
           250. An interim patch added an ``if value == ft_amount: raise``
           tripwire; re-running at ``value == ft_amount ± 1`` still delivered
           ~46.7 million units, because the sizing expression was never touched.
           The only fix that holds for input shapes nobody predicted is to size
           the output from the number the caller asked for, which is what the
           airdrop builder does — so this now *is* the airdrop builder.

        **The token cannot pay its own fee.** Every photon on an FT input is a
        token unit, so subtracting a fee from a token output burns units. The
        fee comes from plain-RXD ``funding`` inputs, exactly as ``transfer-nft``
        sources a separate input to move a dust-carrying singleton. A call with
        no ``funding`` therefore raises rather than quietly shipping a 0-fee
        transaction that no node will relay.

        Output layout::

            [0]     recipient FT output, value == amount
            [1]     FT change,           value == ft_in - amount  (iff any)
            [last]  plain P2PKH RXD change                        (iff >= dust_limit)

        :param amount:         FT units to transfer to ``new_owner_pkh``
        :param new_owner_pkh:  recipient's 20-byte PKH
        :param private_key:    :class:`pyrxd.keys.PrivateKey` owning the inputs
        :param fee_rate:       photons/byte. Validated against Radiant's
                               effective relay floor — see :func:`_check_fee_rate`.
        :param change_pkh:     FT- and RXD-change PKH. Defaults to the sender's
                               PKH derived from ``private_key``.
        :param dust_limit:     fold-to-fee threshold for the RXD change output.
                               NOT a floor on the token output: Radiant's dust
                               threshold is 1 photon, and a 546 floor would
                               forbid transferring 100 units of anything.
        :param funding:        plain-P2PKH RXD UTXOs paying the fee.
        :param allow_overpay:  accept a ``fee_rate`` above the overpay ceiling.
                               The deliberate, greppable opt-out, mirroring
                               ``allow_below_relay_floor`` at the other end — a
                               ceiling with no reachable override refuses valid
                               work, and on a chain with neither RBF nor CPFP a
                               refusal can cost the funds it was protecting.

        :raises ValidationError: ``new_owner_pkh`` is not 20 bytes, or a selected
            UTXO has ``value != ft_amount`` (the fail-closed backstop — see
            :meth:`build_airdrop_tx`).
        :raises ValueError: ``amount <= 0``; total FT < ``amount``; ``fee_rate``
            below the relay floor; or ``funding`` cannot cover the fee.

        :returns: :class:`FtTransferResult` (signed tx, scripts, fee, ref).
        """
        # Checked here as well as in build_airdrop_tx so the failure mode of a
        # non-positive amount stays a ValueError with this method's wording;
        # the airdrop builder raises ValidationError from its recipient loop.
        if isinstance(amount, bool) or not isinstance(amount, int):
            raise ValueError(f"amount must be an int (FT units), got {type(amount).__name__}")
        if amount <= 0:
            raise ValueError(f"amount must be > 0, got {amount}")

        result = self.build_airdrop_tx(
            recipients=[AirdropRecipient(pkh=new_owner_pkh, amount=amount)],
            private_key=private_key,
            funding=funding,
            fee_rate=fee_rate,
            change_pkh=change_pkh,
            dust_limit=dust_limit,
            allow_overpay=allow_overpay,
            allow_below_relay_floor=allow_below_relay_floor,
        )
        return FtTransferResult(
            tx=result.tx,
            new_ft_script=result.recipient_scripts[0],
            change_ft_script=result.change_ft_script,
            ref=result.ref,
            fee=result.fee,
        )

    # ------------------------------------------------------------- airdrop

    def build_airdrop_tx(
        self,
        recipients: Sequence[AirdropRecipient],
        private_key: Any,
        funding: Sequence[AirdropFunding] = (),
        fee_rate: int = MIN_FEE_RATE,
        change_pkh: Hex20 | None = None,
        dust_limit: int = DUST_LIMIT,
        *,
        royalty: GlyphRoyalty | None = None,
        sale_price: int = 0,
        pay_royalty: bool | None = None,
        allow_overpay: bool = False,
        allow_below_relay_floor: bool = False,
    ) -> FtAirdropResult:
        """Build one signed transaction paying FT units to N recipients.

        Why one transaction rather than N calls to :meth:`build_transfer_tx`:
        sequential transfers chain, each spending the previous one's change, so
        a failure partway leaves the set half-delivered and the token's ref
        alone cannot tell you which half. One transaction lands whole or not at
        all.

        **Conservation goes through the same path, not around it.** The per-ref
        input check is :meth:`FtUtxoSet.__init__`, which refuses any UTXO whose
        embedded ref differs from the set's; "do I hold enough" is
        :meth:`select`; and the arithmetic is the same ``ft_in - out == change``
        identity as a single transfer, with ``out`` now ``sum(r.amount)``. No
        new code computes token amounts, so there is no new way to mint units.

        **Each recipient output carries exactly the units requested.** On
        Radiant an FT's quantity *is* its output's ``satoshis`` — 1 photon = 1
        unit (``docs/concepts/radiant-fts-are-on-chain.md``) — so an output's
        value is not free to choose. Setting it to anything but ``amount``
        would deliver a different number of tokens than the caller asked for.
        That is also why the fee cannot come out of the token: subtracting it
        from an output would silently burn units. It comes from plain-RXD
        ``funding`` inputs instead, the same way ``transfer-nft`` sources a
        separate input to pay for a dust-carrying singleton.

        Output layout, in this exact order::

            [0 .. N-1]  recipient FT outputs, value == units, order preserved
            [N]         FT change, value == leftover units   (iff any remain)
            [...]       royalty payouts, plain P2PKH         (iff a royalty is paid)
            [last]      plain P2PKH RXD change               (iff >= dust_limit)

        **Floors.** A recipient output's floor is **1 photon**, the chain's
        actual rule — ``GetDustThreshold`` returns 1 satoshi unconditionally
        (``Radiant-Core/src/policy/policy.cpp:19-25``). It is deliberately NOT
        546: an FT output's value is a token quantity, so a 546 floor would
        forbid airdropping 100 units of anything. ``dust_limit`` here governs
        only the plain-RXD **change** output — a remainder below it is folded
        into the fee instead of being emitted, matching
        :func:`pyrxd.swap.partial._balance_and_add_change`. Folding can only
        raise the fee paid, never lower it, so it cannot produce an under-fee'd
        transaction; ``FtAirdropResult.fee`` reports the real amount.

        :param recipients:   destinations, in output order. Non-empty, at most
                             :data:`MAX_AIRDROP_RECIPIENTS`, no repeated PKH.
        :param private_key:  :class:`pyrxd.keys.PrivateKey` owning every
                             selected FT input (single-key, as
                             :meth:`build_transfer_tx`).
        :param funding:      plain-P2PKH RXD UTXOs paying the fee and any
                             royalty. Each carries its own key, so the RXD may
                             sit at a different wallet address from the token.
        :param fee_rate:     photons/byte. Validated against Radiant's effective
                             relay floor — see :func:`_check_fee_rate`.
        :param change_pkh:   FT- and RXD-change PKH. Defaults to the sender's,
                             derived from ``private_key``.
        :param dust_limit:   fold-to-fee threshold for the RXD change output.
        :param royalty:      optional. Advisory — see :mod:`pyrxd.glyph.royalty`.
        :param sale_price:   photons the seller receives; the royalty base. Also
                             the cap: a royalty can never exceed it.
        :param pay_royalty:  ``None`` (default) pays iff ``royalty.enforced``;
                             ``True`` pays an advisory royalty anyway; ``False``
                             never pays. See :meth:`_resolve_royalty`.

        :raises ValidationError: empty/oversized recipient list, a duplicate
            recipient PKH, a non-positive amount, a malformed PKH, or the
            conservation backstop.
        :raises ValueError: fee rate below the relay floor, or the funding
            cannot cover ``fee + royalty``.

        :returns: :class:`FtAirdropResult`.
        """
        from pyrxd.script.script import Script
        from pyrxd.script.type import P2PKH
        from pyrxd.transaction.transaction import Transaction
        from pyrxd.transaction.transaction_input import TransactionInput
        from pyrxd.transaction.transaction_output import TransactionOutput

        # 1. Validate. Fee rate first — the recipient-cap message quotes it, and
        #    quoting an unvalidated value produces a nonsense number in the one
        #    place a caller is being asked to reconsider a cost.
        _check_fee_rate(fee_rate, allow_overpay=allow_overpay, allow_below_relay_floor=allow_below_relay_floor)
        if dust_limit < 1:
            raise ValueError(f"dust_limit must be >= 1, got {dust_limit}")

        recipients = tuple(recipients)
        funding = tuple(funding)
        if not recipients:
            raise ValidationError("recipients must not be empty")
        if len(recipients) > MAX_AIRDROP_RECIPIENTS:
            raise ValidationError(
                f"airdrop has {len(recipients)} recipients, above pyrxd's guard of "
                f"{MAX_AIRDROP_RECIPIENTS}. This is a pyrxd limit, not a chain limit — Radiant's "
                f"MAX_STANDARD_TX_SIZE is 20 MB — but at {fee_rate} photons/byte each recipient "
                f"costs ~{84 * fee_rate} photons of fee, so a list this long is a deliberate "
                "decision. Split it into batches, or raise MAX_AIRDROP_RECIPIENTS knowingly."
            )
        seen_pkh: set[bytes] = set()
        for i, r in enumerate(recipients):
            if isinstance(r.amount, bool) or not isinstance(r.amount, int):
                raise ValidationError(f"recipients[{i}].amount must be an int, got {type(r.amount).__name__}")
            if r.amount <= 0:
                # An FT output's value IS its unit count, so 0 units is an
                # output the chain would treat as valueless — and IsDust is
                # `nValue <= 0`, the one thing Radiant does reject.
                raise ValidationError(f"recipients[{i}].amount must be > 0, got {r.amount}")
            pkh = bytes(r.pkh)
            if len(pkh) != 20:
                raise ValidationError(f"recipients[{i}].pkh must be 20 bytes, got {len(pkh)}")
            if pkh in seen_pkh:
                # Merging would quietly change the caller's list; paying twice
                # is unrecoverable. A repeated address in an airdrop file is a
                # mistake often enough that refusing is the safer default.
                raise ValidationError(
                    f"recipients[{i}] repeats PKH {pkh.hex()}, which already appears earlier in the "
                    "list. Combine the two entries into one if the double payment is intended."
                )
            seen_pkh.add(pkh)

        # Every input this builder signs must be a DISTINCT outpoint, and the
        # funding side is the half no other check reaches: :meth:`FtUtxoSet.__init__`
        # now refuses a repeated token UTXO, but ``funding`` arrives here directly.
        # A repeat is not merely redundant — ``funding_total`` counts it twice, so
        # the builder sizes change and reports a fee against RXD that exists once,
        # and the final ``assert_pays_for_its_size`` agrees, because it is handed the
        # same double-counted total. Measured before this check: one funding UTXO
        # passed twice produced a signed transaction with a duplicate input and a
        # reported fee 4x the real one.
        funding_outpoints: set[tuple[str, int]] = set()
        for i, f in enumerate(funding):
            outpoint = outpoint_key(f.txid, f.vout)
            if outpoint in funding_outpoints:
                raise ValidationError(
                    f"funding[{i}] repeats outpoint {f.txid}:{f.vout}, which already appears earlier in "
                    "the list. An outpoint is unique on chain, so this would double-count the RXD budget "
                    "and sign a transaction with a duplicate input that no node will accept."
                )
            funding_outpoints.add(outpoint)

        # 2. Selection + conservation — the same two calls build_transfer_tx makes.
        total_out = sum(r.amount for r in recipients)
        selected = self.select(total_out)

        # The two input lists are built independently and concatenated, so an
        # outpoint appearing in BOTH is the same duplicate-input defect across the
        # seam that neither list can see on its own.
        for u in selected:
            if outpoint_key(u.txid, u.vout) in funding_outpoints:
                raise ValidationError(
                    f"outpoint {u.txid}:{u.vout} is listed both as an FT UTXO and as plain-RXD funding. "
                    "It can only be one of the two, and spending it twice in one transaction is a "
                    "duplicate input that no node will accept."
                )

        # Defence in depth, and NOTHING MORE: :meth:`FtUtxo.__post_init__` now
        # refuses to construct a UTXO whose `value` and `ft_amount` differ, so
        # normal code cannot reach this raise at all. It survives because the
        # consequence is severe and one-directional — `ft_amount > value`
        # materialises more of the ref than the inputs carry and the node rejects
        # the broadcast; `ft_amount < value` sends the surplus photons to change
        # or fee, which for a real token BURNS units — and because a check that
        # only ever fires if the type-level guarantee is later loosened is a
        # cheap tripwire on exactly that regression. Do not treat it as the thing
        # that makes the amounts correct: the recipient outputs are sized from
        # `r.amount`, not from this.
        for u in selected:
            if u.value != u.ft_amount:
                raise ValidationError(
                    f"UTXO {u.txid}:{u.vout} has value={u.value} but ft_amount={u.ft_amount}. On "
                    "Radiant an FT's quantity is its output value (1 photon = 1 unit), so an "
                    "airdrop cannot reconcile the two: set ft_amount = value, or use "
                    "FtUtxo.from_output(). Reaching this message at all means FtUtxo's "
                    "construction-time guarantee was bypassed."
                )

        ft_in_total = sum(u.ft_amount for u in selected)
        ft_change = ft_in_total - total_out
        if ft_change < 0:
            raise ValidationError(
                f"FT conservation invariant violated: in={ft_in_total}, "
                f"out={total_out}, change={ft_change} (negative change means inputs insufficient)"
            )

        if change_pkh is None:
            sender_pkh = Hex20(private_key.public_key().hash160())
        else:
            sender_pkh = change_pkh if isinstance(change_pkh, Hex20) else Hex20(change_pkh)

        recipient_scripts = tuple(build_ft_locking_script(r.pkh, self.ref) for r in recipients)
        change_ft_script: bytes | None = build_ft_locking_script(sender_pkh, self.ref) if ft_change > 0 else None
        rxd_change_spk = P2PKH().lock(bytes(sender_pkh)).serialize()

        payouts = self._resolve_royalty(royalty, sale_price, pay_royalty)
        royalty_outs = royalty_output_scripts(payouts)
        royalty_total = sum(photons for _, photons in royalty_outs)

        # 3. The RXD budget IS the funding, and nothing else. Every photon on the
        #    FT inputs is a token unit (asserted above) and every one of them is
        #    already committed to a recipient or to change, so the token side
        #    contributes exactly zero to the fee. That is the whole reason
        #    `funding` exists rather than being optional.
        ft_value_in = sum(u.value for u in selected)  # == ft_in_total, by the check above
        funding_total = sum(f.value for f in funding)
        rxd_budget = funding_total

        unlocking_template = P2PKH().unlock(private_key)

        def _make_inputs() -> list[TransactionInput]:
            """Fresh inputs per signing pass — see build_transfer_tx."""
            inputs: list[TransactionInput] = []
            for u in selected:
                padding_output = TransactionOutput(Script(b""), 0)
                shim_outputs = [padding_output] * u.vout + [TransactionOutput(Script(bytes(u.ft_script)), u.value)]
                src = Transaction(tx_inputs=[], tx_outputs=shim_outputs)
                src.txid = lambda _txid=u.txid: _txid  # type: ignore[method-assign]
                inp = TransactionInput(
                    source_transaction=src,
                    source_txid=u.txid,
                    source_output_index=u.vout,
                    unlocking_script_template=unlocking_template,
                )
                inp.satoshis = u.value
                inp.locking_script = Script(bytes(u.ft_script))
                inputs.append(inp)
            for f in funding:
                spk = P2PKH().lock(f.private_key.public_key().hash160())
                padding_output = TransactionOutput(Script(b""), 0)
                shim_outputs = [padding_output] * f.vout + [TransactionOutput(spk, f.value)]
                src = Transaction(tx_inputs=[], tx_outputs=shim_outputs)
                src.txid = lambda _txid=f.txid: _txid  # type: ignore[method-assign]
                inp = TransactionInput(
                    source_transaction=src,
                    source_txid=f.txid,
                    source_output_index=f.vout,
                    unlocking_script_template=P2PKH().unlock(f.private_key),
                )
                inp.satoshis = f.value
                inp.locking_script = spk
                inputs.append(inp)
            return inputs

        def _make_outputs(rxd_change_value: int | None):
            outs = [
                TransactionOutput(Script(spk), r.amount) for spk, r in zip(recipient_scripts, recipients, strict=True)
            ]
            if change_ft_script is not None:
                outs.append(TransactionOutput(Script(change_ft_script), ft_change))
            for spk, photons in royalty_outs:
                outs.append(TransactionOutput(Script(spk), photons))
            if rxd_change_value is not None:
                outs.append(TransactionOutput(Script(rxd_change_spk), rxd_change_value))
            return outs

        # 4. Trial pass. It must carry the SAME output count as the final or the
        #    measured size understates the fee, so the RXD change output is
        #    present here even when the final may drop it. Output values are
        #    fixed-width 8 bytes, so a provisional value does not change the size.
        trial_tx = Transaction(tx_inputs=_make_inputs(), tx_outputs=_make_outputs(dust_limit))
        trial_tx.sign()
        size = trial_size_with_slack(trial_tx.byte_length(), len(selected) + len(funding))
        fee = size * fee_rate

        remainder = rxd_budget - fee - royalty_total
        if remainder < 0:
            royalty_note = f" + royalty ({royalty_total})" if royalty_total else ""
            raise ValueError(
                f"Insufficient RXD to fund the airdrop: budget {rxd_budget} photons "
                f"({funding_total} from funding inputs) cannot cover the fee "
                f"({fee} for {size} bytes at {fee_rate} ph/B){royalty_note} — short by "
                f"{-remainder} photons. Add a plain-RXD funding input, or airdrop to fewer "
                "recipients per transaction. The fee cannot be taken from the token outputs: "
                "an FT output's value IS its unit count, so that would burn units."
            )

        rxd_change_value: int | None = remainder if remainder >= dust_limit else None
        # A sub-dust remainder is left to the fee rather than emitted. The tx
        # then serialises SHORTER than the trial, so the effective rate rises
        # above fee_rate — never below it.

        final_tx = Transaction(tx_inputs=_make_inputs(), tx_outputs=_make_outputs(rxd_change_value))
        final_tx.sign()

        # 5. The fee the transaction actually pays must clear the rate it was
        #    built for. Backstop, not decoration: the trial and final passes sign
        #    different messages, so their DER signatures can differ in length and
        #    a fee sized purely off the trial can land BELOW the floor. That is
        #    unfixable on Radiant — no RBF, no CPFP — so failing here beats
        #    broadcasting. `_SIG_SIZE_SLACK_BYTES` is what should make this
        #    unreachable; this is what proves it, rather than trusting it. Shared
        #    with ``pyrxd.wallet`` so the two builders cannot drift apart on the
        #    check or on what it demands.
        actual_fee = ft_value_in + funding_total - sum(o.satoshis for o in final_tx.outputs)
        assert_pays_for_its_size(
            size_bytes=final_tx.byte_length(),
            fee_paid=actual_fee,
            fee_rate=fee_rate,
            what="build_airdrop_tx",
        )
        return FtAirdropResult(
            tx=final_tx,
            recipient_scripts=recipient_scripts,
            change_ft_script=change_ft_script,
            rxd_change_photons=rxd_change_value or 0,
            royalty_payouts=payouts,
            ref=self.ref,
            fee=actual_fee,
            recipients=recipients,
        )
