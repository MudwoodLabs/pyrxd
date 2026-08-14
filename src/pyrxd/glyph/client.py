"""``GlyphClient`` — one object for minting and moving Glyph tokens.

The pieces already existed and were simply not reachable together:
:class:`~pyrxd.glyph.mint.GlyphMinter` covers the two-phase mint, and
:mod:`pyrxd.glyph.transfer` covers transfers. This composes them so a caller
configures a client and a wallet once instead of assembling the pipeline by hand —
``examples/ft_transfer_demo.py`` needed 399 lines to do that.

Composition, not inheritance or replacement: ``GlyphMinter`` is public API and keeps
working exactly as before. Nothing here re-implements a build.

The store is **optional**. Minting needs one — the commit output is a hashlock and
losing the CBOR payload between commit and reveal makes it permanently unspendable,
so crash recovery is not decoration. Transfers are a single atomic transaction with
no gap to crash in, and requiring a store to move a token would be a configuration
tax with nothing behind it. Calling a mint method without a store raises with the
one-line fix rather than failing later.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ..network.confirm import DEFAULT_CONFIRMATION_TIMEOUT_S
from ..security.errors import ValidationError
from ..security.types import Hex20
from .builder import MIN_FEE_RATE
from .mint import (
    DEFAULT_MINT_CONFIRMATIONS,
    GlyphMinter,
    MintResult,
    PendingMint,
    PendingStore,
)
from .transfer import FtTransferBuild, build_ft_transfer

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .types import GlyphMetadata, GlyphRef

__all__ = ["GlyphClient", "TransferReceipt"]


class TransferReceipt:
    """What a broadcast transfer actually did.

    Deliberately reports the broadcast txid **and** the fee, because the fee is the
    number a caller cannot recover afterwards without re-fetching and re-deriving.
    """

    __slots__ = ("amount", "fee", "ref", "to_pkh", "txid")

    def __init__(self, *, txid: str, ref: GlyphRef, amount: int, fee: int, to_pkh: Hex20) -> None:
        self.txid = txid
        self.ref = ref
        self.amount = amount
        self.fee = fee
        self.to_pkh = to_pkh

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"TransferReceipt(txid={self.txid!r}, amount={self.amount}, fee={self.fee})"


class GlyphClient:
    """Mint and transfer Glyph tokens over one ElectrumX client and one wallet.

    Usage::

        client = GlyphClient(electrumx, wallet, store=JsonFilePendingStore("~/.pyrxd/pending"))
        result = await client.mint_nft(metadata)
        receipt = await client.transfer_ft(ref, 250, recipient_pkh)

    Transfer-only callers can skip the store::

        client = GlyphClient(electrumx, wallet)
        receipt = await client.transfer_ft(ref, 250, recipient_pkh)

    Args:
        client: an ElectrumX-style client — ``await broadcast(hex) -> txid``,
            ``await get_transaction(txid)``, ``await get_utxos(script_hash)``.
        wallet: an :class:`~pyrxd.hd.wallet.HdWallet`, or anything exposing
            ``await collect_spendable(client)``, ``privkey_for_address(address)`` and
            ``addresses``.
        store: where a :class:`~pyrxd.glyph.mint.PendingMint` lives between commit and
            reveal. Required for minting, unused by transfers.
        fee_rate: photons per byte, applied to every build.
        min_confirmations: depth required on a mint's commit before its reveal.
        confirmation_timeout_s: how long a reveal waits for the commit.
    """

    def __init__(
        self,
        client: Any,
        wallet: Any,
        *,
        store: PendingStore | None = None,
        fee_rate: int = MIN_FEE_RATE,
        min_confirmations: int = DEFAULT_MINT_CONFIRMATIONS,
        confirmation_timeout_s: float = DEFAULT_CONFIRMATION_TIMEOUT_S,
    ) -> None:
        if store is not None and not isinstance(store, PendingStore):
            raise ValidationError(
                "GlyphClient store must be a PendingStore — pass JsonFilePendingStore(path), "
                "UnsafeNullPendingStore() to opt out of crash recovery, or omit it entirely "
                "if you only need transfers"
            )
        if not isinstance(fee_rate, int) or isinstance(fee_rate, bool) or fee_rate <= 0:
            raise ValidationError("GlyphClient fee_rate must be a positive int")
        self._client = client
        self._wallet = wallet
        self._store = store
        self._fee_rate = fee_rate
        self._min_confirmations = min_confirmations
        self._confirmation_timeout_s = confirmation_timeout_s
        self._minter: GlyphMinter | None = None

    # -- minting (delegated to GlyphMinter, unchanged) ----------------------

    @property
    def minter(self) -> GlyphMinter:
        """The underlying :class:`~pyrxd.glyph.mint.GlyphMinter`.

        Built on first use so a transfer-only client never needs a store.

        Raises:
            ValidationError: if this client was constructed without a store.
        """
        if self._store is None:
            raise ValidationError(
                "minting needs a PendingStore — construct with "
                "GlyphClient(client, wallet, store=JsonFilePendingStore(path)). "
                "The commit output is a hashlock: lose the CBOR payload between commit and "
                "reveal and it can never be spent."
            )
        if self._minter is None:
            self._minter = GlyphMinter(
                self._client,
                self._wallet,
                self._store,
                fee_rate=self._fee_rate,
                min_confirmations=self._min_confirmations,
                confirmation_timeout_s=self._confirmation_timeout_s,
            )
        return self._minter

    async def mint_nft(self, metadata: GlyphMetadata, *, owner_pkh: Hex20 | bytes | None = None) -> MintResult:
        """Commit and reveal an NFT singleton. See :meth:`GlyphMinter.mint_nft`."""
        return await self.minter.mint_nft(metadata, owner_pkh=owner_pkh)

    async def deploy_ft(self, *args: Any, **kwargs: Any) -> MintResult:
        """Deploy a fungible token with a full premine. See :meth:`GlyphMinter.deploy_ft`."""
        return await self.minter.deploy_ft(*args, **kwargs)

    async def commit_nft(self, metadata: GlyphMetadata, *, owner_pkh: Hex20 | bytes | None = None) -> PendingMint:
        """Phase 1 of an NFT mint. See :meth:`GlyphMinter.commit_nft`."""
        return await self.minter.commit_nft(metadata, owner_pkh=owner_pkh)

    async def reveal_nft(self, pending: PendingMint) -> MintResult:
        """Phase 2 of an NFT mint. See :meth:`GlyphMinter.reveal_nft`."""
        return await self.minter.reveal_nft(pending)

    # -- transfers ---------------------------------------------------------

    async def build_ft_transfer(
        self,
        ref: GlyphRef,
        amount: int,
        to_pkh: Hex20,
        *,
        allow_overpay: bool = False,
    ) -> FtTransferBuild:
        """Build and sign an FT transfer **without broadcasting it**.

        For callers that want to show the user what is about to be spent — which is
        exactly what the CLI does — or to inspect the transaction first.
        """
        return await build_ft_transfer(
            self._wallet,
            ref,
            amount,
            to_pkh,
            client=self._client,
            fee_rate=self._fee_rate,
            allow_overpay=allow_overpay,
        )

    async def transfer_ft(
        self,
        ref: GlyphRef,
        amount: int,
        to_pkh: Hex20,
        *,
        allow_overpay: bool = False,
    ) -> TransferReceipt:
        """Send ``amount`` units of ``ref`` to ``to_pkh``, and broadcast.

        The recipient output is sized from ``amount``; the fee is paid from a separate
        plain-RXD input, because an FT output's value **is** its unit count and taking
        the fee from the token would short the recipient.

        Raises:
            InsufficientFundsError: not enough of the token, or no plain-RXD UTXO to
                pay the fee. Raised before anything is signed or sent.
            ValidationError: inputs span multiple keys, the builder refused the
                parameters, or change would have been paid to the miner.
        """
        build = await self.build_ft_transfer(ref, amount, to_pkh, allow_overpay=allow_overpay)
        txid = await self._client.broadcast(build.serialize())
        return TransferReceipt(
            txid=str(txid),
            ref=ref,
            amount=amount,
            fee=build.fee,
            to_pkh=to_pkh,
        )
