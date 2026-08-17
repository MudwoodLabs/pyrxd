"""Library-level Glyph transfer paths.

Extracted from :mod:`pyrxd.cli.glyph_cmds`, where the only working FT-transfer
implementation lived as private helpers. Nothing under ``cli/`` is importable as an
SDK surface, so every non-CLI caller re-implemented the path by hand —
``examples/ft_transfer_demo.py`` ran to 399 lines doing exactly that.

**Why this routes through the airdrop builder.** These functions build through
:meth:`~pyrxd.glyph.builder.GlyphBuilder.build_ft_airdrop_tx` with a single
recipient rather than through
:meth:`~pyrxd.glyph.builder.GlyphBuilder.build_ft_transfer_tx`, because that is the
shape the CLI had settled on and an extraction should carry decisions across, not
re-litigate them.

**Corrected 2026-08-15.** This paragraph used to justify the choice by saying the
transfer builder "sizes its recipient output from the inputs' RXD rather than from
the amount asked for", and quoted a measured 46,739,454-unit output for a 250-unit
request. That WAS true, and it is exactly the kind of fund-losing defect worth
routing around — but it was fixed in #393 (``3f4bce8``), before this module existed.
The number is the historical figure recorded in
:meth:`~pyrxd.glyph.ft.FtUtxoSet.build_transfer_tx`'s own warning, not a fresh
observation, and writing it in the present tense implied a live hazard that is not
there.

What is true today: ``build_transfer_tx`` *is* the airdrop builder — it calls
``build_airdrop_tx`` with one recipient and returns the result (``glyph/ft.py``).
So the two paths are equivalent, and this module's choice is a matter of using the
underlying builder directly rather than a fund-safety necessity. The reason to leave
it alone is that ft.py's warning docstring asks the next reader not to "simplify"
that sizing back, and a second caller of the wrapper is one more place to have to
check.

The FT hazard is therefore historical. The **NFT** hazard documented further down is
current and measured — see the comment above :func:`build_nft_transfer`.

**Build, don't broadcast.** Every entry point here returns a signed transaction and
stops. The CLI shows the user a summary and asks before broadcasting; a facade
broadcasts immediately. Putting the broadcast inside these functions would force one
of those two callers to be wrong, so the caller owns it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..constants import DUST_THRESHOLD_PHOTONS
from ..security.errors import InsufficientFundsError, NetworkError, ValidationError
from ..security.types import Hex20, Txid
from ..transaction.transaction import Transaction
from .builder import (
    AirdropFunding,
    AirdropRecipient,
    FtAirdropParams,
    FtUtxo,
    GlyphBuilder,
)
from .types import GlyphRef

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ..hd.wallet import HdWallet
    from ..keys import PrivateKey
    from ..network.electrumx import ElectrumXClient, UtxoRecord

__all__ = [
    "NFT_TRANSFER_MODELLED_BYTES",
    "FtTransferBuild",
    "NftTransferBuild",
    "NoFeeFundingError",
    "NoHoldingsError",
    "assert_fee_matches_size",
    "build_ft_transfer",
    "build_nft_transfer",
    "find_nft_utxo",
    "find_plain_rxd_utxo",
    "ft_funding",
    "ft_ref_or_none",
    "nft_transfer_funding_bar",
    "select_ft_inputs",
    "single_ft_signing_key",
]


class NoHoldingsError(InsufficientFundsError):
    """This wallet holds none of the requested token.

    Distinct from "holds some, but not enough" and from "cannot pay the fee", because
    the three want different advice and the CLI used to tell them apart by matching
    substrings of the message. Rewording a message then silently changed which
    remedy the user was given — and the fallback remedy, "fund the wallet with a
    little plain RXD", is the wrong direction for two of the three.
    """


class NoFeeFundingError(InsufficientFundsError):
    """No plain-RXD UTXO large enough to pay this transaction's fee.

    The token cannot pay for itself: an FT output's value IS its unit count, and an
    NFT singleton carries dust.
    """


@dataclass(frozen=True)
class FtTransferBuild:
    """A signed, un-broadcast FT transfer.

    :param tx: the signed :class:`~pyrxd.transaction.transaction.Transaction`
    :param fee: photons paid, sourced from plain RXD rather than from the token
    :param ref: the token transferred
    :param amount: units delivered to ``to_pkh`` — sized from this number, not
        from the inputs' value
    :param to_pkh: recipient's 20-byte public-key hash
    """

    tx: Transaction
    fee: int
    ref: GlyphRef
    amount: int
    to_pkh: Hex20

    def serialize(self) -> bytes:
        """Raw transaction BYTES, ready for ``await client.broadcast(...)``.

        Annotated ``-> str`` and documented as "hex" until 2026-08-15, which was
        wrong on both counts: :meth:`Transaction.serialize` returns bytes and
        :meth:`ElectrumXClient.broadcast` takes them. Runtime was always correct;
        the contract was not, and it was the same mistaken belief that made
        :func:`assert_fee_matches_size` halve every size it judged. CI's mypy scope
        is ``src/pyrxd/security/`` only, so nothing checked this annotation.
        """
        return self.tx.serialize()


def ft_ref_or_none(script: bytes) -> GlyphRef | None:
    """Best-effort extract of the FT ref from a locking script, or ``None``."""
    from .script import extract_ref_from_ft_script

    try:
        return extract_ref_from_ft_script(script)
    except Exception:
        return None


async def select_ft_inputs(
    wallet: HdWallet,
    ref: GlyphRef,
    amount: int,
    client: ElectrumXClient,
    triples: list[tuple[UtxoRecord, str, PrivateKey]] | None = None,
) -> list[tuple[FtUtxo, str, PrivateKey]]:
    """Find this wallet's FT UTXOs for ``ref`` and greedily cover ``amount``.

    Every candidate is checked against its **on-chain** locking script — that it is
    an FT script, and that the ref embedded in it is the one asked for. A holding is
    never inferred from an index or a cached balance.

    Returns ``(FtUtxo, address, key)`` triples in selection order.

    Raises:
        InsufficientFundsError: no holdings of ``ref``, or holdings that do not
            cover ``amount``. Raised before anything is built.
    """
    if not isinstance(amount, int) or isinstance(amount, bool) or amount <= 0:
        raise ValidationError("FT transfer amount must be a positive int")

    from .script import is_ft_script

    # The classification loop below is the ONLY source of truth for what this wallet
    # holds. A `GlyphScanner` pre-pass used to run here over every used address, purely
    # to produce a nicer "no holdings" message, and its result was then discarded — a
    # full second sweep of the wallet, serial, for an emptiness check the loop below
    # already answers. It also contradicted this function's own rule: the scanner IS
    # the index path, and holdings here are read from the on-chain locking script.
    if triples is None:
        triples = await wallet.collect_spendable(client)
    ft_inputs: list[tuple[FtUtxo, str, PrivateKey]] = []
    total_ft = 0
    for utxo, addr, pk in triples:
        try:
            raw = await client.get_transaction(Txid(utxo.tx_hash))
        except NetworkError:
            continue
        tx = Transaction.from_hex(bytes(raw))
        if tx is None or utxo.tx_pos >= len(tx.outputs):
            continue
        out_script = tx.outputs[utxo.tx_pos].locking_script.serialize()
        if not is_ft_script(out_script.hex()):
            continue
        if ft_ref_or_none(out_script) != ref:
            continue
        # 1 photon = 1 FT unit — ``from_output`` takes the number once so a future
        # edit cannot reintroduce a second, divergent quantity.
        ft_utxo = FtUtxo.from_output(
            txid=utxo.tx_hash,
            vout=utxo.tx_pos,
            value=utxo.value,
            ft_script=out_script,
        )
        ft_inputs.append((ft_utxo, addr, pk))
        total_ft += ft_utxo.ft_amount

    if not ft_inputs:
        raise NoHoldingsError(
            f"no FT holdings for {ref.txid}:{ref.vout} in this wallet — refresh the wallet's used addresses and retry"
        )
    if total_ft < amount:
        raise InsufficientFundsError(f"insufficient FT balance: need {amount}, have {total_ft}")

    # Select WITHIN one address, because `FtUtxoSet` signs every input with a single
    # key and `single_ft_signing_key` refuses a selection that spans several.
    #
    # Sorting the whole wallet by amount and taking greedily — what this did before —
    # produced selections that the very next call then rejected. A wallet holding
    # A=100+100 and B=150, asked for 200, picked B then A, spanned two addresses, and
    # was refused with "consolidate the token to one address first" — prescribing work
    # that was not needed, since A alone covers 200 exactly. A guard refusing valid
    # work is its own bug, and this one refused work it had itself constructed.
    by_address: dict[str, list[tuple[FtUtxo, str, PrivateKey]]] = {}
    for triple in ft_inputs:
        by_address.setdefault(triple[1], []).append(triple)

    # Choose by INPUT COUNT first, not by holding size.
    #
    # An earlier version took the address with the smallest sufficient total, reasoning
    # that a large consolidated holding should not be fragmented. That is the wrong cost
    # model: the fee-funding bar scales with the number of inputs (`ft_funding` sizes at
    # ~148 B each), so for amount=1000 it preferred an address holding 500+500 (two
    # inputs) over one holding 1,000,000 (one input) — a more expensive transaction that
    # can then be REFUSED for fee funding the single-input build would not have needed.
    #
    # So: fewest inputs wins; ties break on the smaller total, which keeps the original
    # anti-fragmentation intent where it costs nothing.
    def _inputs_needed(group: list[tuple[FtUtxo, str, PrivateKey]]) -> tuple[int, int]:
        """(inputs required to cover `amount`, total held) for this address."""
        running = 0
        for n, triple in enumerate(sorted(group, key=lambda t: t[0].ft_amount, reverse=True), 1):
            running += triple[0].ft_amount
            if running >= amount:
                return n, sum(t[0].ft_amount for t in group)
        return len(group), sum(t[0].ft_amount for t in group)

    sufficient = [
        (*_inputs_needed(group), addr, group)
        for addr, group in by_address.items()
        if sum(t[0].ft_amount for t in group) >= amount
    ]
    if not sufficient:
        best = max((sum(t[0].ft_amount for t in g) for g in by_address.values()), default=0)
        raise InsufficientFundsError(
            f"insufficient FT balance at any single address: need {amount}, and the largest "
            f"single-address holding is {best} (wallet total {total_ft} across "
            f"{len(by_address)} addresses). Consolidate the token to one address first — "
            "every input of an FT transfer is signed with one key."
        )
    sufficient.sort(key=lambda t: (t[0], t[1]))
    _n_inputs, _total, _addr, group = sufficient[0]

    group.sort(key=lambda t: t[0].ft_amount, reverse=True)
    selected: list[tuple[FtUtxo, str, PrivateKey]] = []
    selected_total = 0
    for triple in group:
        selected.append(triple)
        selected_total += triple[0].ft_amount
        if selected_total >= amount:
            break
    return selected


def single_ft_signing_key(
    selected: list[tuple[FtUtxo, str, PrivateKey]],
    what: str,
) -> PrivateKey:
    """The one key that signs every selected FT input, or a clear refusal.

    :class:`~pyrxd.glyph.ft.FtUtxoSet` signs all inputs with a single key. If the
    selection spans several HD-derived addresses, signing anyway emits a transaction
    with invalid signatures on some inputs — rejected at broadcast, but only after
    the caller believed the spend was under way. Refuse first instead.
    """
    if not selected:
        raise ValidationError(f"{what}: no inputs were selected, so there is no key to sign with")
    first_key = selected[0][2]
    for _utxo, _addr, k in selected:
        if k.public_key().address() != first_key.public_key().address():
            raise ValidationError(
                f"{what} across multiple wallet addresses isn't supported — consolidate the token to one address first"
            )
    return first_key


async def find_plain_rxd_utxo(
    triples: list[tuple[UtxoRecord, str, PrivateKey]],
    client: ElectrumXClient,
    *,
    exclude: set[tuple[str, int]],
    needed: int,
) -> tuple[UtxoRecord, str, PrivateKey] | None:
    """Pick a plain-P2PKH (non-token) wallet UTXO >= ``needed`` to fund a fee.

    Each candidate's **on-chain** script is verified to be a bare 25-byte P2PKH, so a
    token-bearing UTXO is never spent as fee — which would burn the token it carries.
    ``exclude`` drops outpoints already committed to the transaction.
    """
    for u, a, k in sorted(triples, key=lambda t: t[0].value, reverse=True):
        if (u.tx_hash, u.tx_pos) in exclude or u.value < needed:
            continue
        try:
            raw = await client.get_transaction(Txid(u.tx_hash))
        except NetworkError:
            continue
        tx = Transaction.from_hex(bytes(raw))
        if tx is None or u.tx_pos >= len(tx.outputs):
            continue
        spk = tx.outputs[u.tx_pos].locking_script.serialize()
        if len(spk) == 25 and spk[:3] == b"\x76\xa9\x14" and spk[23:25] == b"\x88\xac":
            return u, a, k
    return None


async def ft_funding(
    wallet: HdWallet,
    selected: list[tuple[FtUtxo, str, PrivateKey]],
    *,
    n_outputs: int,
    fee_rate: int,
    client: ElectrumXClient,
    triples: list[tuple[UtxoRecord, str, PrivateKey]] | None = None,
) -> AirdropFunding:
    """Find a plain-RXD UTXO big enough to pay for ``n_outputs`` token outputs.

    The token cannot pay its own fee: an FT output's value IS its unit count, so
    taking the fee from one would burn units and short the recipient.

    The estimate is deliberately generous. An unfunded build fails cleanly, but a
    build that squeaks past and lands under the relay floor cannot be repaired on
    Radiant — there is neither RBF nor CPFP. ~84 B per FT output, ~148 B per input,
    ~50 B of envelope, then doubled for headroom.
    """
    est_bytes = 84 * (n_outputs + 2) + 148 * (len(selected) + 1) + 50
    needed = est_bytes * fee_rate * 2
    if triples is None:
        triples = await wallet.collect_spendable(client)
    fund = await find_plain_rxd_utxo(
        triples,
        client,
        exclude={(u.txid, u.vout) for u, _a, _k in selected},
        needed=needed,
    )
    if fund is None:
        raise NoFeeFundingError(
            f"no plain-RXD UTXO large enough to fund the fee — need about {needed:,} photons "
            "on a single non-token UTXO. An FT output's value is its unit count, so the token "
            "cannot pay for itself."
        )
    utxo, _addr, key = fund
    return AirdropFunding(txid=utxo.tx_hash, vout=utxo.tx_pos, value=utxo.value, private_key=key)


async def build_ft_transfer(
    wallet: HdWallet,
    ref: GlyphRef,
    amount: int,
    to_pkh: Hex20,
    *,
    client: ElectrumXClient,
    fee_rate: int,
    allow_overpay: bool = False,
) -> FtTransferBuild:
    """Build (and sign) an FT transfer, without broadcasting it.

    Routed through :meth:`~pyrxd.glyph.builder.GlyphBuilder.build_ft_airdrop_tx` with
    a single recipient — see the module docstring for why the transfer builder is not
    used. The recipient output is sized from ``amount``; the fee comes from a
    separate plain-RXD input.

    Raises:
        InsufficientFundsError: not enough of the token, or no plain-RXD UTXO to pay
            the fee. Raised before anything is signed.
        ValidationError: the selected inputs span multiple keys, or the builder
            rejected the parameters.
    """
    if not isinstance(amount, int) or isinstance(amount, bool) or amount <= 0:
        raise ValidationError("FT transfer amount must be a positive int")

    # ONE wallet enumeration per build. Selection and fee funding both need the same
    # UTXO set, and each used to fetch it (and each candidate's parent transaction)
    # independently — doubling the round trips and opening a window in which the two
    # phases could disagree about what the wallet holds.
    triples = await wallet.collect_spendable(client)
    selected = await select_ft_inputs(wallet, ref, amount, client, triples)
    first_key = single_ft_signing_key(selected, "FT transfer")
    funding = await ft_funding(wallet, selected, n_outputs=1, fee_rate=fee_rate, client=client, triples=triples)

    params = FtAirdropParams(
        ref=ref,
        utxos=[t[0] for t in selected],
        recipients=[AirdropRecipient(pkh=to_pkh, amount=amount)],
        private_key=first_key,
        funding=[funding],
        fee_rate=fee_rate,
        allow_overpay=allow_overpay,
    )
    try:
        result = GlyphBuilder().build_ft_airdrop_tx(params)
    except (ValidationError, ValueError) as exc:
        raise ValidationError(f"could not build the FT transfer: {exc}") from exc

    assert_fee_matches_size(result.fee, result.tx, fee_rate=fee_rate, allow_overpay=allow_overpay)
    return FtTransferBuild(tx=result.tx, fee=result.fee, ref=ref, amount=amount, to_pkh=to_pkh)


def assert_fee_matches_size(
    fee: int,
    tx: Transaction,
    *,
    fee_rate: int,
    allow_overpay: bool = False,
) -> None:
    """Refuse a build paying grossly more than its own size demands.

    Named ``assert_change_survived`` until 2026-08-17, which described a mechanism that
    does not exist — see the paragraph below. Three independent reviewers flagged the
    name as no longer matching the behaviour, which is how a guard ends up being
    "simplified" by someone who trusts its name over its body.

    **What this catches, stated accurately (rewritten 2026-08-15).** The original
    version of this docstring said
    :meth:`~pyrxd.transaction.transaction.Transaction.fee` "happily burns an
    arbitrarily large remainder if the size estimate was off". It does not. That
    branch is ``if change <= change_count`` where ``change`` is already net of the
    fee, so it drops the change outputs only when the remainder is at most **one
    photon per change output** — a rounding crumb, never a wallet. The mechanism this
    guard was written for cannot produce a meaningful loss.

    What can, and what this actually checks, is a fee grossly out of proportion to the
    transaction's size — from a mis-set rate, a bad estimate, or a builder change. The
    rate itself is already bounded by :func:`~pyrxd.fee_sizing.fee_overpay_ceiling`,
    so this is a second, independent net measured against the SIGNED bytes rather than
    against the rate. Radiant has neither RBF nor CPFP, so an overpay discovered after
    broadcast cannot be repaired; a cheap redundant check before the caller ever sees
    the transaction is worth its keep.

    **The tolerance has to exceed the builders' own slack.** Every builder here sizes
    its fee from a TRIAL signing pass plus
    :data:`~pyrxd.fee_sizing.SIG_SIZE_SLACK_BYTES` per input, deliberately, so that a
    final signature longer than the trial one cannot leave the transaction underpaid.
    That designed-in overshoot is denominated in BYTES times the rate, while
    :data:`~pyrxd.constants.DUST_THRESHOLD_PHOTONS` is 546 photons — 0.055 bytes at
    Radiant's floor rate. Comparing the two refuses every honest build: measured over
    300 single-recipient FT transfers at the floor rate, the overshoot ran 4-9 bytes
    (40,000-90,000 photons) and **300 of 300 were refused**.

    So the allowance is the slack itself, plus the same allowance again for
    trial-versus-final DER signature variance, plus the dust threshold. A genuine
    overpay clears it by orders of magnitude — the measured 23.3 RXD burn that motivated
    the guard is 2,330,000,000 photons, i.e. 233,000 bytes' worth at the floor rate,
    against an allowance of 12.

    ``allow_overpay=True`` is the deliberate, greppable way through, matching the
    builders' existing opt-out.
    """
    if allow_overpay:
        return
    from ..fee_sizing import SIG_SIZE_SLACK_BYTES

    # ``Transaction.serialize()`` returns BYTES, so its length is the byte count.
    # This read ``len(...) // 2`` until 2026-08-15, halving every size it judged.
    # The tests missed it because their stub returned a hex STRING, so the stub and
    # the guard agreed with each other and both disagreed with ``Transaction``.
    size_bytes = len(tx.serialize())
    # ``SIG_SIZE_SLACK_BYTES`` per input is the builders' deliberate overshoot; the
    # second term is the trial-vs-final DER variance that rides on top of it (each
    # ECDSA signature encodes to 70-72 bytes, and the two passes sign different
    # messages). Measured worst case on two inputs was 9 bytes against this 12.
    allowance = (2 * SIG_SIZE_SLACK_BYTES) * max(len(tx.inputs), 1) * fee_rate + DUST_THRESHOLD_PHOTONS
    excess = fee - (size_bytes * fee_rate)
    if excess > allowance:
        raise ValidationError(
            f"refusing to broadcast: the fee exceeds what this transaction's size demands by "
            f"{excess:,} photons, past the {allowance:,} allowed for sizing slack "
            f"(fee {fee:,} against {size_bytes:,} bytes at {fee_rate:,}/byte over "
            f"{len(tx.inputs)} input(s)). Pass allow_overpay=True to accept it."
        )


# ---------------------------------------------------------------------------
# NFT
# ---------------------------------------------------------------------------
#
# The NFT half is FUNDED — two inputs, the singleton's own value untouched. That
# is not the same operation as `GlyphBuilder.build_nft_transfer_tx`, which spends
# the NFT alone and takes the fee out of the singleton's own value. Both are real
# transfers; only one of them works on a real NFT.
#
# An NFT singleton carries dust. `build_nft_transfer_tx` computes
# `output_value = nft_utxo_value - fee` and refuses when that drops below the
# uneconomic-output floor, with a message telling the caller to "attach funding
# instead" — a capability the SDK did not expose. So the self-funded builder is
# unusable for exactly the tokens it exists to move, and the only working path
# lived under `cli/`, which nothing can import.
#
# Measured on 2026-08-15 at Radiant's relay floor (10,000 photons/byte), which is
# what makes this a live limitation rather than an inherited claim:
#
#     NFT carrying       546 photons -> REFUSED
#     NFT carrying     1,000 photons -> REFUSED
#     NFT carrying    10,000 photons -> REFUSED
#     NFT carrying 1,000,000 photons -> REFUSED
#     NFT carrying 3,000,000 photons -> built, fee 2,330,000, singleton left 670,000
#
# The cutoff is the fee plus the floor, ~2,330,546 photons. Above it the builder
# works but erodes the carrier by the fee on every hop, so a singleton funded to
# survive one transfer may not survive two.
#
# Note the FT half of this module documents a hazard that is HISTORICAL (fixed in
# #393). This one is not: `TestWhyTheSelfFundedBuilderIsNotUsed` in
# tests/test_glyph_nft_transfer.py re-measures the table above, so if the builder
# ever grows a funding parameter this comment fails rather than rots.
#
# `build_nft_transfer_tx` is left exactly as it is — correct for a carrier that
# holds enough RXD to pay its own way, and reachable for callers who want that.


@dataclass(frozen=True)
class NftTransferBuild:
    """A signed, un-broadcast NFT transfer.

    :param tx: the signed :class:`~pyrxd.transaction.transaction.Transaction`
    :param fee: photons paid, sourced from a plain-RXD input rather than from the
        singleton — its value crosses the transfer unchanged
    :param ref: the token transferred
    :param to_pkh: recipient's 20-byte public-key hash
    :param from_address: the wallet address the singleton was held at
    :param has_change: ``False`` when the whole funding UTXO became the fee. That is
        an accepted outcome, not a fault — see :func:`nft_transfer_funding_bar` —
        but a caller showing a confirmation prompt should say so.
    """

    tx: Transaction
    fee: int
    ref: GlyphRef
    to_pkh: Hex20
    from_address: str
    has_change: bool

    def serialize(self) -> bytes:
        """Raw transaction bytes, ready for ``await client.broadcast(...)``."""
        return self.tx.serialize()


#: Modelled bytes of an NFT transfer WITHOUT its change output and WITHOUT the NFT
#: locking script (whose exact length is known at build time and is added by
#: :func:`nft_transfer_funding_bar`).
#:
#: ``4`` version + ``1`` input count + 2 x (``36`` outpoint + ``1`` script varint +
#: ``107`` unlocking script + ``4`` sequence) + ``1`` output count + ``8`` value +
#: ``1`` script varint + ``4`` locktime = **315**.
#:
#: ``107`` is :meth:`P2PKH.unlock`'s ``estimated_unlocking_byte_length``, and on this
#: template it is an UPPER bound rather than an estimate: the real script is
#: ``push(DER 69-71 B + sighash byte) + push(33-byte pubkey)`` = 105-107 bytes. So this
#: models the LARGEST transaction the builder can produce, and a funding UTXO that
#: clears it clears the real one.
NFT_TRANSFER_MODELLED_BYTES = 315


def nft_transfer_funding_bar(new_locking: bytes, fee_rate: int) -> int:
    """Photons a plain-RXD UTXO must hold to fund one NFT transfer, at *fee_rate*.

    Modelled on the **no-change** shape deliberately.
    :meth:`~pyrxd.transaction.transaction.Transaction.fee` drops the change output
    entirely when the funding cannot also cover it (``if change <= change_count``),
    and the whole funding input then becomes the fee — so the smallest UTXO that can
    work is the one that pays for the ONE-output transaction, not the two-output one.
    Sizing the bar against the larger shape would refuse funding that in fact relays
    perfectly well, which is its own fund-safety bug.
    """
    from ..fee_sizing import required_fee

    return required_fee(NFT_TRANSFER_MODELLED_BYTES + len(new_locking), fee_rate)


async def find_nft_utxo(
    triples: list[tuple[UtxoRecord, str, PrivateKey]],
    ref: GlyphRef,
    client: ElectrumXClient,
) -> tuple[UtxoRecord, str, PrivateKey, bytes] | None:
    """Locate the wallet UTXO holding the NFT singleton for *ref*.

    Each candidate's **on-chain** locking script is fetched and parsed rather than
    trusting any index: the ref is read back out of the script that actually
    encumbers the coin. Returns the UTXO, its address, its key and that script, or
    ``None`` when this wallet does not hold the singleton.
    """
    from .script import extract_ref_from_nft_script

    for utxo, addr, key in triples:
        try:
            raw = await client.get_transaction(Txid(utxo.tx_hash))
        except NetworkError:
            continue
        tx = Transaction.from_hex(bytes(raw))
        if tx is None or utxo.tx_pos >= len(tx.outputs):
            continue
        out_script = tx.outputs[utxo.tx_pos].locking_script.serialize()
        try:
            this_ref = extract_ref_from_nft_script(out_script)
        except Exception:  # noqa: S112 — non-NFT scripts raise; this loop filters, it does not handle  # nosec B112
            continue
        if this_ref == ref:
            return utxo, addr, key, out_script
    return None


async def build_nft_transfer(
    wallet: HdWallet,
    ref: GlyphRef,
    to_pkh: Hex20,
    *,
    client: ElectrumXClient,
    fee_rate: int,
    allow_overpay: bool = False,
) -> NftTransferBuild:
    """Build (and sign) an NFT transfer, without broadcasting it.

    Re-locks the singleton to ``to_pkh`` with its ref and its value both unchanged,
    and pays the fee from a separate plain-RXD input.

    The ref in the new lock is the caller's, but it cannot diverge from the coin's:
    :func:`find_nft_utxo` selects only a UTXO whose **on-chain** script parses to
    exactly this ref, so a wrong ref finds nothing and raises rather than minting a
    lock for a token that was not spent.

    Raises:
        InsufficientFundsError: the wallet does not hold this NFT, or has no
            plain-RXD UTXO large enough to pay the fee. Raised before anything is
            signed.
        ValidationError: the signed transaction does not pay for its own size.
    """
    from ..fee_models import SatoshisPerKilobyte
    from ..fee_sizing import assert_fee_rate_clears_relay_floor, assert_pays_for_its_size
    from ..script.script import Script
    from ..script.type import P2PKH
    from ..transaction.transaction_input import TransactionInput
    from ..transaction.transaction_output import TransactionOutput
    from .script import build_nft_locking_script

    # Judge the RATE before any bytes exist. This is the gate every other
    # fund-moving builder in this package already had and this path did not:
    # `builder.py` calls it in `build_nft_transfer_tx`, `ft.py` calls it for the FT
    # path. Without it this function was unbounded in BOTH directions.
    #
    # Below the floor: `assert_pays_for_its_size` further down cannot catch it, because
    # it measures against the CALLER'S rate — a sub-floor build is internally
    # consistent and agrees with itself. It would relay nowhere and squat the NFT plus
    # the wallet's largest plain UTXO until mempool expiry, ~8h, with no RBF and no
    # CPFP to repair it.
    #
    # Above the ceiling: `fee_sizing` records why that bound exists, and it is this
    # exact transaction shape — `build_nft_transfer_tx` at `fee_rate=10_000_000` (the
    # per-kB constant, one import away from the per-byte one) burned 23.2-23.3 RXD off
    # a 230-byte transfer, silently, reporting success. An NFT transfer whose funding
    # cannot also cover change has NO change output, so the whole difference leaves
    # with the miner.
    assert_fee_rate_clears_relay_floor(
        fee_rate,
        what="build_nft_transfer",
        allow_overpay=allow_overpay,
    )

    triples = await wallet.collect_spendable(client)
    found = await find_nft_utxo(triples, ref, client)
    if found is None:
        raise NoHoldingsError(f"NFT {ref.txid}:{ref.vout} is not held by this wallet")
    utxo, addr, pk, nft_script = found

    # The new locking script is built before funding is chosen because its length is
    # part of the size the funding bar has to cover.
    new_locking = build_nft_locking_script(to_pkh, ref)
    needed = nft_transfer_funding_bar(new_locking, fee_rate)
    fund = await find_plain_rxd_utxo(
        triples,
        client,
        exclude={(utxo.tx_hash, utxo.tx_pos)},
        needed=needed,
    )
    if fund is None:
        raise NoFeeFundingError(
            "no plain-RXD UTXO large enough to fund the NFT transfer fee — need at least "
            f"{needed:,} photons on a single non-token UTXO "
            f"(~{NFT_TRANSFER_MODELLED_BYTES + len(new_locking)} B at {fee_rate:,} photons/B). "
            "The NFT itself carries only dust."
        )
    fund_utxo, fund_addr, fund_key = fund
    fund_spk = P2PKH().lock(fund_addr)

    def _shim(vout: int, script: Script, value: int, txid: str) -> Transaction:
        """A stand-in parent tx so preimage computation can index ``outputs[vout]``.

        Only the txid and the output at ``vout`` are real; the padding exists to make
        the index valid.
        """
        outs = [TransactionOutput(Script(b""), 0) for _ in range(vout)]
        outs.append(TransactionOutput(script, value))
        src = Transaction(tx_inputs=[], tx_outputs=outs)
        src.txid = lambda: txid  # type: ignore[method-assign]
        return src

    nft_input = TransactionInput(
        source_transaction=_shim(utxo.tx_pos, Script(nft_script), utxo.value, utxo.tx_hash),
        source_txid=utxo.tx_hash,
        source_output_index=utxo.tx_pos,
        unlocking_script_template=P2PKH().unlock(pk),
    )
    nft_input.satoshis = utxo.value
    nft_input.locking_script = Script(nft_script)

    fund_input = TransactionInput(
        source_transaction=_shim(fund_utxo.tx_pos, fund_spk, fund_utxo.value, fund_utxo.tx_hash),
        source_txid=fund_utxo.tx_hash,
        source_output_index=fund_utxo.tx_pos,
        unlocking_script_template=P2PKH().unlock(fund_key),
    )
    fund_input.satoshis = fund_utxo.value
    fund_input.locking_script = fund_spk

    nft_tx = Transaction(
        tx_inputs=[nft_input, fund_input],
        tx_outputs=[
            TransactionOutput(Script(new_locking), utxo.value),  # singleton -> new owner, value intact
            TransactionOutput(fund_spk, 0, change=True),  # fee change back to this wallet
        ],
    )
    # `Transaction.fee` is untyped (transaction/ is outside this module's typecheck
    # scope); the call is correct, the annotation debt is upstream.
    nft_tx.fee(SatoshisPerKilobyte(fee_rate * 1000))  # type: ignore[no-untyped-call]
    nft_tx.sign()

    # Prove the SIGNED bytes pay for themselves, after the last `sign()`.
    # `Transaction.fee()` sizes against an ESTIMATE and, when the funding falls short,
    # silently drops the change output instead of failing — turning a shortfall into
    # "the whole UTXO is the fee", which is how this path once signed transactions no
    # node would relay. The funding bar should make this unreachable; this is what
    # proves it rather than trusting it. Radiant has neither RBF nor CPFP, so an
    # under-fee'd broadcast cannot be repaired.
    raw = nft_tx.serialize()
    fee_paid = nft_tx.get_fee()
    assert_pays_for_its_size(
        size_bytes=len(raw),
        fee_paid=fee_paid,
        fee_rate=fee_rate,
        what="the NFT transfer",
    )

    return NftTransferBuild(
        tx=nft_tx,
        fee=fee_paid,
        ref=ref,
        to_pkh=to_pkh,
        from_address=addr,
        has_change=len(nft_tx.outputs) > 1,
    )
