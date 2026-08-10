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

from pyrxd.security.errors import ValidationError
from pyrxd.security.types import Hex20

from .royalty import RoyaltyPayout, royalty_output_scripts, royalty_payouts
from .script import build_ft_locking_script, extract_ref_from_ft_script, is_ft_script
from .types import GlyphRef, GlyphRoyalty

# Post-V2 relay minimum — mirrored from builder.py to avoid an import cycle.
# Numerically identical to ``gravity.fee_policy.RADIANT_EFFECTIVE_MIN_RELAY_PHOTONS_PER_KB``
# (10_000_000 per kB); see ``_check_fee_rate`` for the binding.
MIN_FEE_RATE: int = 10_000  # photons / byte
DUST_LIMIT: int = 546  # photons, standard relay dust threshold

# A pyrxd ergonomics guard, NOT a chain rule. Radiant's ``MAX_STANDARD_TX_SIZE``
# is 20_000_000 bytes (``Radiant-Core/src/policy/policy.h:69`` @ ``afdf57b1``),
# so an airdrop is limited by what it costs, not by what relays: one FT output is
# 84 serialised bytes (75-byte script + 8-byte value + 1-byte length), which at
# the 10_000 photons/byte relay floor is ~840_000 photons — 0.0084 RXD — of fee
# per recipient. 1000 recipients is therefore ~8.4 RXD in fee before any dust,
# which is a deliberate decision rather than a typo in a recipient file. Raise it
# explicitly if you mean it.
MAX_AIRDROP_RECIPIENTS: int = 1000

# Per-input headroom added to the trial-pass size before the fee is computed.
#
# The trial and final passes sign DIFFERENT messages (the final commits to the
# real output values), so their DER signatures can differ in length — low-S
# normalisation puts a P2PKH sig at roughly 70-72 bytes, and the leading zero
# byte on `r` or `s` comes and goes with the nonce. A fee sized purely off the
# trial can therefore land 1-2 bytes per input BELOW the rate it was built for.
# Under normal circumstances that is a rounding curiosity; at the relay floor it
# is the difference between relayed and not, and Radiant has neither RBF nor
# CPFP to fix it afterwards (threat-model S21) — the transaction would simply sit
# on its inputs until mempool expiry, 8 hours later.
#
# 3 bytes per input, not 2: a DER signature is usually 71 or 72 bytes, but both
# `r` and `s` can shed their leading zero at once, giving 69 — so the worst-case
# growth from trial to final is 3 bytes per input, not 2. A review measured a
# 1000-recipient/2-input build clearing the required fee by a factor of 1.000047
# at 2 bytes: the whole margin was the slack, and one unlucky trial signature
# would have consumed it. Overpaying by at most 3 * fee_rate photons per input is
# the correct trade against a transaction that cannot be repaired.
#
# ``build_airdrop_tx`` re-checks the built transaction against the rate
# afterwards, so this bound is asserted rather than assumed — if it is ever
# wrong, the builder raises instead of returning something unbroadcastable.
_SIG_SIZE_SLACK_BYTES: int = 3


def _check_fee_rate(fee_rate: int) -> None:
    """Reject a fee rate the network will not relay.

    Radiant has neither RBF nor CPFP (threat-model S21, verified against
    ``Radiant-Core`` @ ``afdf57b1``), so an under-fee'd transaction cannot be
    bumped by any means: it squats on its own inputs until mempool expiry, 8
    hours later. That makes a sub-floor rate a fund-safety bug, not a tuning
    mistake, which is why this refuses rather than warns.

    The floor is taken from :mod:`pyrxd.gravity.fee_policy` rather than restated,
    so the glyph and swap stacks cannot drift apart. Imported lazily — the swap
    stack is not otherwise on the glyph import path.
    """
    if isinstance(fee_rate, bool) or not isinstance(fee_rate, int):
        raise ValueError(f"fee_rate must be an int (photons/byte), got {type(fee_rate).__name__}")
    from pyrxd.gravity.fee_policy import RADIANT_EFFECTIVE_MIN_RELAY_PHOTONS_PER_KB

    floor_per_byte = RADIANT_EFFECTIVE_MIN_RELAY_PHOTONS_PER_KB // 1000
    if fee_rate < floor_per_byte:
        raise ValueError(
            f"fee_rate must be >= {floor_per_byte} photons/byte (Radiant's effective relay floor of "
            f"{RADIANT_EFFECTIVE_MIN_RELAY_PHOTONS_PER_KB} per kB), got {fee_rate}. A transaction built "
            "below the floor will not relay, and Radiant has no RBF and no CPFP — it cannot be "
            "fee-bumped and will hold its inputs until mempool expiry."
        )


@dataclass(frozen=True)
class FtUtxo:
    """A single UTXO holding some quantity of one FT.

    :param txid:        txid of the UTXO
    :param vout:        output index within that tx
    :param value:       RXD value (photons) on the output
    :param ft_amount:   token units held on the output
    :param ft_script:   full FT locking script (75 bytes, see
                        :func:`pyrxd.glyph.script.build_ft_locking_script`)
    """

    txid: str
    vout: int
    value: int
    ft_amount: int
    ft_script: bytes


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
    :param value:       photons available
    :param private_key: :class:`pyrxd.keys.PrivateKey` that unlocks it
    """

    txid: str
    vout: int
    value: int
    private_key: Any


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
        for u in utxos:
            if not isinstance(u, FtUtxo):
                raise ValidationError("utxos must contain FtUtxo instances")
            if not isinstance(u.ft_amount, int) or isinstance(u.ft_amount, bool):
                raise ValidationError(f"ft_amount must be int, got {type(u.ft_amount).__name__!r}: {u.ft_amount!r}")
            if u.ft_amount < 0:
                raise ValidationError("ft_amount must be >= 0")
            if not isinstance(u.value, int) or isinstance(u.value, bool):
                raise ValidationError(f"value must be int, got {type(u.value).__name__!r}: {u.value!r}")
            if u.value < 0:
                raise ValidationError("value must be >= 0")
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
        _check_fee_rate(fee_rate)
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

        # 2. Selection + conservation — the same two calls build_transfer_tx makes.
        total_out = sum(r.amount for r in recipients)
        selected = self.select(total_out)

        # An airdrop is stricter than a transfer about the inputs it will spend:
        # every output's value here is a token quantity, so `value` and
        # `ft_amount` describing the same UTXO differently is not a modelling
        # nuance, it is a wrong transaction. If `ft_amount > value` the outputs
        # materialise more of the ref than the inputs carry and consensus
        # rejects the broadcast; if `ft_amount < value` the surplus photons flow
        # to change or fee, which for a real token means burning units. On chain
        # the two are always equal — an FT's quantity IS its satoshis
        # (``docs/concepts/radiant-fts-are-on-chain.md``) — so a mismatch means
        # the caller built ``FtUtxo`` from the wrong field. Say so here rather
        # than at a mempool rejection, or worse, silently.
        for u in selected:
            if u.value != u.ft_amount:
                raise ValidationError(
                    f"UTXO {u.txid}:{u.vout} has value={u.value} but ft_amount={u.ft_amount}. On "
                    "Radiant an FT's quantity is its output value (1 photon = 1 unit), so an "
                    "airdrop cannot reconcile the two: set ft_amount = value. (The single-recipient "
                    "build_transfer_tx tolerates a mismatch because it does not size outputs from "
                    "token amounts; this builder does.)"
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
        size = trial_tx.byte_length() + _SIG_SIZE_SLACK_BYTES * (len(selected) + len(funding))
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
        #    unreachable; this is what proves it, rather than trusting it.
        final_size = final_tx.byte_length()
        actual_fee = ft_value_in + funding_total - sum(o.satoshis for o in final_tx.outputs)
        if actual_fee < final_size * fee_rate:  # pragma: no cover — the slack bound should prevent this
            raise ValueError(
                f"internal fee-sizing invariant violated: the built transaction is {final_size} bytes "
                f"and pays {actual_fee} photons, below {final_size * fee_rate} at {fee_rate} ph/B. "
                "Refusing to return an unrelayable transaction — Radiant has no RBF and no CPFP, so "
                "it could not be fee-bumped."
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
