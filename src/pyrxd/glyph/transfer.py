"""Library-level Glyph transfer paths.

Extracted from :mod:`pyrxd.cli.glyph_cmds`, where the only working FT-transfer
implementation lived as private helpers. Nothing under ``cli/`` is importable as an
SDK surface, so every non-CLI caller re-implemented the path by hand —
``examples/ft_transfer_demo.py`` ran to 399 lines doing exactly that.

**Why this is an extraction and not a fresh facade.** The obvious-looking way to
build a transfer facade is over :class:`~pyrxd.glyph.builder.FtTransferParams` /
:meth:`~pyrxd.glyph.builder.GlyphBuilder.build_ft_transfer_tx`. That is wrong, and
wrong in a fund-losing direction: the transfer builder sizes its recipient output
from the *inputs' RXD* rather than from the amount asked for, and on Radiant an FT's
quantity **is** its output value, so it delivers the wrong number of units. Measured
on a real holding — one 50,000,000-unit UTXO, ``amount=250`` — it produced a
46,739,454-unit output to the recipient and kept 546.

The CLI worked around that by building through the *airdrop* builder with a single
recipient, which sizes each output from the units requested and pays the fee from a
separate plain-RXD input. This module preserves that decision rather than
rediscovering the bug.

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
from .scanner import GlyphScanner
from .types import GlyphFt, GlyphRef

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ..hd.wallet import HdWallet
    from ..keys import PrivateKey
    from ..network.electrumx import ElectrumXClient, UtxoRecord

__all__ = [
    "FtTransferBuild",
    "assert_change_survived",
    "build_ft_transfer",
    "find_plain_rxd_utxo",
    "ft_funding",
    "ft_ref_or_none",
    "select_ft_inputs",
    "single_ft_signing_key",
]


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
        :func:`assert_change_survived` halve every size it judged. CI's mypy scope
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
    from .script import is_ft_script

    scanner = GlyphScanner(client)
    items: list[GlyphFt] = []
    for rec in [r for r in wallet.addresses.values() if r.used]:
        for item in await scanner.scan_address(rec.address):
            if isinstance(item, GlyphFt) and item.ref == ref:
                items.append(item)

    if not items:
        raise InsufficientFundsError(
            f"no FT holdings for {ref.txid}:{ref.vout} in this wallet — refresh the wallet's used addresses and retry"
        )

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

    if total_ft < amount:
        raise InsufficientFundsError(f"insufficient FT balance: need {amount}, have {total_ft}")

    ft_inputs.sort(key=lambda t: t[0].ft_amount, reverse=True)
    selected: list[tuple[FtUtxo, str, PrivateKey]] = []
    selected_total = 0
    for triple in ft_inputs:
        selected.append(triple)
        selected_total += triple[0].ft_amount
        if selected_total >= amount:
            break
    return selected


def single_ft_signing_key(
    selected: list[tuple[FtUtxo, str, PrivateKey]],
    what: str = "FT transfer",
) -> PrivateKey:
    """The one key that signs every selected FT input, or a clear refusal.

    :class:`~pyrxd.glyph.ft.FtUtxoSet` signs all inputs with a single key. If the
    selection spans several HD-derived addresses, signing anyway emits a transaction
    with invalid signatures on some inputs — rejected at broadcast, but only after
    the caller believed the spend was under way. Refuse first instead.
    """
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
    triples = await wallet.collect_spendable(client)
    fund = await find_plain_rxd_utxo(
        triples,
        client,
        exclude={(u.txid, u.vout) for u, _a, _k in selected},
        needed=needed,
    )
    if fund is None:
        raise InsufficientFundsError(
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

    selected = await select_ft_inputs(wallet, ref, amount, client)
    first_key = single_ft_signing_key(selected, "FT transfer")
    funding = await ft_funding(wallet, selected, n_outputs=1, fee_rate=fee_rate, client=client)

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

    assert_change_survived(result.fee, result.tx, fee_rate=fee_rate, allow_overpay=allow_overpay)
    return FtTransferBuild(tx=result.tx, fee=result.fee, ref=ref, amount=amount, to_pkh=to_pkh)


def assert_change_survived(
    fee: int,
    tx: Transaction,
    *,
    fee_rate: int,
    allow_overpay: bool = False,
) -> None:
    """Refuse a build paying grossly more than its own size demands.

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
    overpay clears it by orders of magnitude — the 23.1 RXD case that motivated the
    guard is 2,310,000 bytes' worth against an allowance of 12.

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
