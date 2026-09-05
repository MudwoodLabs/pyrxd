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

import inspect
from collections.abc import Callable, Sequence
from typing import TYPE_CHECKING, Any, Protocol

from ..fee_sizing import assert_fee_rate_clears_relay_floor
from ..network.confirm import (
    _MAX_WAIT_TIMEOUT_S,
    _MIN_WAIT_INTERVAL_S,
    DEFAULT_CONFIRMATION_TIMEOUT_S,
    DEFAULT_POLL_INTERVAL_S,
    _assert_positive_finite,
)
from ..security.errors import RxdSdkError, ValidationError
from ..security.types import Hex20
from .builder import MIN_FEE_RATE
from .ft import AirdropRecipient
from .mint import (
    DEFAULT_MINT_CONFIRMATIONS,
    GlyphMinter,
    MintResult,
    PendingMint,
    PendingStore,
)
from .timelock import (
    TimelockMintBuild,
    TimelockParams,
    TimelockRecipient,
    build_timelock_mint,
)
from .timelock_reveal_tx import (
    TimelockRevealBuild,
    TimelockRevealPlan,
    build_timelock_reveal,
    plan_timelock_reveal,
)
from .transfer import (
    FtAirdropBuild,
    FtTransferBuild,
    NftTransferBuild,
    build_ft_airdrop,
    build_ft_transfer,
    build_nft_transfer,
)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .types import GlyphMetadata, GlyphRef

__all__ = [
    "BroadcastEchoMismatch",
    "GlyphClient",
    "NftTransferReceipt",
    "TimelockMintReceipt",
    "TimelockRevealReceipt",
    "TransferReceipt",
]


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


class AirdropReceipt:
    """What a broadcast airdrop actually did — the multi-recipient :class:`TransferReceipt`.

    Carries ``recipients`` in **output order** as well as ``total``, because after the
    fact those are two different questions: "how much left the wallet" is reconcilable
    from the total, while "who got what, at which vout" is only answerable from the
    ordered list, and re-deriving it means re-fetching and re-parsing the transaction.
    """

    __slots__ = ("fee", "recipients", "ref", "total", "txid")

    def __init__(
        self,
        *,
        txid: str,
        ref: GlyphRef,
        recipients: tuple[AirdropRecipient, ...],
        total: int,
        fee: int,
    ) -> None:
        self.txid = txid
        self.ref = ref
        self.recipients = recipients
        self.total = total
        self.fee = fee

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return (
            f"AirdropReceipt(txid={self.txid!r}, recipients={len(self.recipients)}, total={self.total}, fee={self.fee})"
        )


class BroadcastEchoMismatch(RxdSdkError):
    """The server's txid did not match the transaction we signed.

    Deliberately NOT a :class:`ValidationError`. Those are raised before anything is
    SENT — ``transfer_nft``'s is raised after signing but before broadcast — whereas this
    one can only happen after the broadcast, when the transaction may well have relayed.
    A caller with ``except ValidationError: retry`` would re-broadcast a transfer that
    already moved tokens.

    Carries ``local_txid`` so the caller can check the chain for what was actually sent.
    """

    def __init__(self, local_txid: str, echoed: object) -> None:
        super().__init__(
            f"broadcast echoed txid {echoed!r} but the signed transaction hashes to "
            f"{local_txid!r}. The server may not have relayed what was sent. Check "
            f"{local_txid} on an explorer before treating this transfer as done; if it is "
            "there, the transfer succeeded and only the server's reply was wrong."
        )
        self.local_txid = local_txid
        self.echoed = echoed


class _HasSignedTx(Protocol):
    """Anything carrying the signed transaction that is about to be broadcast.

    Structural on purpose. The check below needs one thing — the bytes we signed — and
    every fund-moving build in this package has them under ``.tx``. Naming concrete
    types here instead made the annotation the reason an airdrop kept the weaker,
    warn-only txid helper while its transfer siblings raised.
    """

    @property
    def tx(self) -> Any: ...


def _confirmed_txid(build: _HasSignedTx, echoed: object) -> str:
    """The txid of what we signed — not merely what the server said it was.

    `broadcast` returns whatever the server replies, and the reply is only
    format-checked. A lying or buggy ElectrumX can drop the transaction and echo any
    well-formed txid — including a real, already-confirmed one — and the caller then
    polls a txid that has nothing to do with their tokens, sees "confirmed", and
    believes a transfer happened that did not.

    The txid is a pure function of the signed bytes, so we do not have to take the
    server's word for it. `get_transaction` already binds `hash256(raw)` to the
    requested txid for reads; this is the same discipline on the write path, which the
    swap stack adopted for the same reason.

    A mismatch RAISES rather than warning. An earlier version warned and returned a
    normal success receipt, which is the wrong default for fund-moving code: programmatic
    callers do not see warnings (``-W ignore``, log filters, non-tty runs), so a hostile
    server could drop every transfer while the application recorded success. Failing loudly
    costs an exception on a transfer that may have relayed anyway — and the exception
    carries the local txid so that is checkable — while failing quietly costs the tokens.
    """
    local = str(build.tx.txid())
    if str(echoed) != local:
        raise BroadcastEchoMismatch(local, echoed)
    return local


class NftTransferReceipt:
    """What a broadcast NFT transfer actually did.

    Separate from :class:`TransferReceipt` rather than reusing it with ``amount=1``:
    an NFT is a singleton, and its output value is dust that crosses the transfer
    unchanged, not a unit count. Reporting a quantity for it would invite exactly the
    confusion that makes FT value handling hazardous — where the output's value *is*
    the number of units.
    """

    __slots__ = ("fee", "ref", "to_pkh", "txid")

    def __init__(self, *, txid: str, ref: GlyphRef, fee: int, to_pkh: Hex20) -> None:
        self.txid = txid
        self.ref = ref
        self.fee = fee
        self.to_pkh = to_pkh

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"NftTransferReceipt(txid={self.txid!r}, fee={self.fee})"


class TimelockMintReceipt:
    """A minted timelocked token, and the two things only the minter now holds.

    ``mint`` is the ordinary :class:`~pyrxd.glyph.mint.MintResult`. The rest is what makes
    this different from every other receipt in this module: a mint that finishes leaves the
    caller holding material the chain does not have, and losing either half loses the
    content permanently.

    - ``cek`` — the key. Nothing on chain carries it, only ``sha256(cek)``. Persist it
      encrypted at rest, alongside the ``ref`` it belongs to.
    - ``ciphertext`` — the encrypted payload. The mint carries its plaintext hash, size and
      chunk count; **it does not carry the bytes**. Publish or store them yourself.

    ``cek`` is ``repr=False``: the printed form of a 32-byte key is a working key, and a
    receipt is exactly the object that ends up in a log line.
    """

    __slots__ = ("cek", "cek_hash", "ciphertext", "mint", "stub", "unlock_at")

    def __init__(
        self,
        *,
        mint: MintResult,
        cek: bytes,
        cek_hash: str,
        ciphertext: Any,
        stub: Any,
        unlock_at: int,
    ) -> None:
        self.mint = mint
        self.cek = cek
        self.cek_hash = cek_hash
        self.ciphertext = ciphertext
        self.stub = stub
        self.unlock_at = unlock_at

    @property
    def ref(self) -> GlyphRef:
        """The token's permanent ref — what a reveal names as its ``token_ref``."""
        return self.mint.ref

    @property
    def token_ref(self) -> str:
        """``"<txid>:<vout>"``, the form :meth:`GlyphClient.reveal_timelock` takes."""
        return f"{self.mint.ref.txid}:{self.mint.ref.vout}"

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"TimelockMintReceipt(ref={self.token_ref!r}, unlock_at={self.unlock_at}, cek_hash={self.cek_hash!r})"


class TimelockRevealReceipt:
    """What a broadcast reveal actually published.

    Reports the ``cek`` that is now public, deliberately. Every other secret in this SDK is
    kept out of a ``repr`` — this one stopped being a secret the moment the transaction
    relayed, and a receipt that hid it would be describing the wrong state of the world.
    """

    __slots__ = ("cek", "commitment", "fee", "token_ref", "txid")

    def __init__(self, *, txid: str, token_ref: str, cek: str, commitment: str, fee: int) -> None:
        self.txid = txid
        self.token_ref = token_ref
        self.cek = cek
        self.commitment = commitment
        self.fee = fee

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"TimelockRevealReceipt(txid={self.txid!r}, token_ref={self.token_ref!r}, fee={self.fee})"


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
        client: an ElectrumX-style client — ``await broadcast(raw_tx: bytes) -> txid``,
            ``await get_transaction(txid)``, ``await get_utxos(script_hash)``.
        wallet: an :class:`~pyrxd.hd.wallet.HdWallet`, or anything exposing
            ``await collect_spendable(client)``, ``privkey_for_address(address)`` and
            ``addresses``.
        store: where a :class:`~pyrxd.glyph.mint.PendingMint` lives between commit and
            reveal. Required for minting, unused by transfers.
        fee_rate: photons per byte, applied to every build. A rate above the overpay
            ceiling is always refused here. A sub-floor rate is refused here too when
            ``store`` is given — mints judge it in the constructor — and otherwise left to
            each build path, since the floor is a property of the chain.
        allow_below_relay_floor: accept a sub-floor ``fee_rate``, for chains whose floor
            really is lower — :func:`~pyrxd.fee_sizing.relay_floor_photons_per_byte` is a
            fixed **mainnet** constant, and a regtest node runs at a tenth of it. Required
            at construction when ``store`` is given, since minting judges the rate in the
            constructor rather than per build. **Since #458 this covers transfers as well
            as mints**, on both the FT and NFT paths: it is threaded to the FT builder and
            to ``build_nft_transfer`` together, because doing it for one alone would
            reintroduce the FT/NFT asymmetry that caused a release blocker on this surface.
        min_confirmations: depth required on a mint's commit before its reveal.
        confirmation_timeout_s: how long a reveal waits for the commit.
        poll_interval_s: seconds between confirmation polls, forwarded to
            :class:`~pyrxd.glyph.mint.GlyphMinter`. Lower it for a chain that mines on
            demand; the default suits minutes-apart blocks.
    """

    def __init__(
        self,
        client: Any,
        wallet: Any,
        *,
        store: PendingStore | None = None,
        fee_rate: int = MIN_FEE_RATE,
        allow_below_relay_floor: bool = False,
        min_confirmations: int = DEFAULT_MINT_CONFIRMATIONS,
        confirmation_timeout_s: float = DEFAULT_CONFIRMATION_TIMEOUT_S,
        poll_interval_s: float = DEFAULT_POLL_INTERVAL_S,
    ) -> None:
        if store is not None and not isinstance(store, PendingStore):
            raise ValidationError(
                "GlyphClient store must be a PendingStore — pass JsonFilePendingStore(path), "
                "UnsafeNullPendingStore() to opt out of crash recovery, or omit it entirely "
                "if you only need transfers"
            )
        if not isinstance(fee_rate, int) or isinstance(fee_rate, bool) or fee_rate <= 0:
            raise ValidationError("GlyphClient fee_rate must be a positive int")
        # Judge the CEILING here, and only the ceiling.
        #
        # The two ends of this check answer different questions. A rate far ABOVE the
        # floor is never legitimate — it is the fat-finger that pays a per-kB number as
        # if it were per-byte, and it burns the difference — so refuse it at construction,
        # before any build can spend it, and give the message the caller's own parameter
        # name rather than one from a lazily-built object they never mentioned.
        #
        # A rate BELOW the floor is chain-dependent, not wrong: a regtest node's floor
        # really is a tenth of mainnet's. Each build path judges that against its own
        # context, so deciding it here would be deciding it too early and in the wrong
        # place.
        # The floor is judged here too WHEN THIS CLIENT CAN MINT. Deferring it entirely
        # meant `GlyphClient(store=..., fee_rate=1000)` constructed happily and then failed
        # from the lazily-built minter with `GlyphMinter fee_rate: ...` — a deferred
        # refusal naming a parameter the caller never spelled, which is the exact fault
        # this gate was added to fix, reappearing at the other end of it.
        #
        # A transfer-only client keeps the deferral, because there its build paths really
        # do judge the floor, each against its own chain.
        assert_fee_rate_clears_relay_floor(
            fee_rate,
            what="GlyphClient fee_rate",
            allow_below_relay_floor=allow_below_relay_floor or store is None,
            error_type=ValidationError,
        )
        # Validate the wait parameters HERE, not on first `.minter` access. Deferring them
        # reproduces, on the two newest arguments, exactly the fault the fee-rate gate above
        # was added to fix: `GlyphClient(store=..., poll_interval_s=0)` constructed happily
        # and then failed with "GlyphMinter poll_interval_s must be > 0" — a class the
        # caller never wrote, about a parameter they spelled on this one. Third time this
        # cycle, so it is checked here even though the minter checks it again.
        if not isinstance(min_confirmations, int) or isinstance(min_confirmations, bool) or min_confirmations < 1:
            # The fourth instance of the same fault, and it was sitting in the function
            # where the other three were fixed. `fee_rate`, then the sub-floor gate, then
            # the two wait parameters — each was validated here only after a review found
            # the refusal arriving late and naming `GlyphMinter`. This one was left because
            # I was fixing the parameters a reviewer had named, not the ones that shared
            # their shape.
            raise ValidationError("GlyphClient min_confirmations must be an int >= 1")
        _assert_positive_finite(
            confirmation_timeout_s, what="GlyphClient confirmation_timeout_s", maximum=_MAX_WAIT_TIMEOUT_S
        )
        _assert_positive_finite(poll_interval_s, what="GlyphClient poll_interval_s", minimum=_MIN_WAIT_INTERVAL_S)
        self._client = client
        self._wallet = wallet
        self._store = store
        self._fee_rate = fee_rate
        self._allow_below_relay_floor = allow_below_relay_floor
        self._min_confirmations = min_confirmations
        self._confirmation_timeout_s = confirmation_timeout_s
        self._poll_interval_s = poll_interval_s
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
                allow_below_relay_floor=self._allow_below_relay_floor,
                min_confirmations=self._min_confirmations,
                confirmation_timeout_s=self._confirmation_timeout_s,
                poll_interval_s=self._poll_interval_s,
            )
        return self._minter

    async def mint_nft(self, metadata: GlyphMetadata, *, owner_pkh: Hex20 | bytes | None = None) -> MintResult:
        """Commit and reveal an NFT singleton. See :meth:`GlyphMinter.mint_nft`."""
        return await self.minter.mint_nft(metadata, owner_pkh=owner_pkh)

    async def deploy_ft(
        self,
        metadata: GlyphMetadata,
        *,
        supply: int,
        treasury_pkh: Hex20 | bytes | None = None,
    ) -> MintResult:
        """Deploy a fungible token with a full premine. See :meth:`GlyphMinter.deploy_ft`.

        Spelled out rather than ``*args, **kwargs``: this is a published SDK, and the
        erased signature was the only one of the five facade methods that gave a caller
        no completion, no type checking, and a ``TypeError`` from inside the minter
        instead of at the call site.
        """
        return await self.minter.deploy_ft(metadata, supply=supply, treasury_pkh=treasury_pkh)

    async def commit_nft(self, metadata: GlyphMetadata, *, owner_pkh: Hex20 | bytes | None = None) -> PendingMint:
        """Phase 1 of an NFT mint. See :meth:`GlyphMinter.commit_nft`."""
        return await self.minter.commit_nft(metadata, owner_pkh=owner_pkh)

    async def reveal_nft(
        self,
        pending: PendingMint,
        *,
        fee_rate: int | None = None,
        allow_below_relay_floor: bool | None = None,
        allow_overpay: bool = False,
    ) -> MintResult:
        """Phase 2 of an NFT mint. See :meth:`GlyphMinter.reveal_nft`.

        The three overrides are forwarded because without them the minter's escape hatch
        is unreachable from this facade: a commit whose stored fee rate now sits below a
        risen relay floor cannot be revealed at all, and re-pricing upward is only
        possible when the commit holds enough to pay it.

        ``allow_below_relay_floor`` must stay ``None``-defaulted, not ``False``. The
        minter reads ``None`` as "the caller said nothing, inherit the constructor" and
        ``False`` as "the caller re-asserted the floor for this reveal". Defaulting to
        ``False`` here forwarded a deliberate override on every ordinary call, so a client
        built with ``allow_below_relay_floor=True`` committed and then refused to reveal —
        stranding the commit, which is a hashlock with no owner-only spend path. That is
        exactly the failure the constructor flag exists to prevent, reintroduced one layer
        above it by a default that looked harmless.
        """
        return await self.minter.reveal_nft(
            pending,
            fee_rate=fee_rate,
            allow_below_relay_floor=allow_below_relay_floor,
            allow_overpay=allow_overpay,
        )

    async def commit_ft(
        self,
        metadata: GlyphMetadata,
        *,
        supply: int,
        treasury_pkh: Hex20 | bytes | None = None,
    ) -> PendingMint:
        """Phase 1 of an FT deploy. See :meth:`GlyphMinter.commit_ft`.

        Added alongside :meth:`reveal_ft` rather than after it: exposing only the reveal
        would let a caller FINISH a two-phase FT deploy through this facade that they
        could not START through it — half of a pair is the asymmetry the facade exists to
        remove, not a smaller version of the fix.
        """
        return await self.minter.commit_ft(metadata, supply=supply, treasury_pkh=treasury_pkh)

    async def reveal_ft(
        self,
        pending: PendingMint,
        *,
        fee_rate: int | None = None,
        allow_below_relay_floor: bool | None = None,
        allow_overpay: bool = False,
    ) -> MintResult:
        """Phase 2 of an FT deploy. See :meth:`GlyphMinter.reveal_ft`.

        The FT counterpart of :meth:`reveal_nft`, and it exists for the sharper half of
        the reason that one does. A two-phase FT deploy could not be FINISHED through this
        facade at all: a caller who committed had to reach past it into ``.minter``. The
        commit output is a hashlock with **no owner-only spend path**, so the phase a
        caller most needs to resume was the one not exposed.

        ``allow_below_relay_floor`` must stay ``None``-defaulted, not ``False`` — the same
        trap documented at length on :meth:`reveal_nft`. ``None`` means "inherit the
        constructor"; ``False`` means "the caller re-asserted the floor for this reveal".
        A ``False`` default here would forward a deliberate override on every ordinary
        call, so a client built with ``allow_below_relay_floor=True`` would commit and then
        refuse to reveal, stranding the commit and everything funded into it.
        """
        return await self.minter.reveal_ft(
            pending,
            fee_rate=fee_rate,
            allow_below_relay_floor=allow_below_relay_floor,
            allow_overpay=allow_overpay,
        )

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
            allow_below_relay_floor=self._allow_below_relay_floor,
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
        echoed = await self._client.broadcast(build.serialize())
        return TransferReceipt(
            txid=_confirmed_txid(build, echoed),
            ref=ref,
            amount=amount,
            fee=build.fee,
            to_pkh=to_pkh,
        )

    async def build_ft_airdrop(
        self,
        ref: GlyphRef,
        recipients: Sequence[AirdropRecipient],
        *,
        allow_overpay: bool = False,
    ) -> FtAirdropBuild:
        """Build and sign a multi-recipient FT airdrop **without broadcasting it**.

        One transaction, not N transfers: sequential transfers chain, each spending the
        previous one's change, so a failure partway leaves the set half-delivered and the
        token's ref alone cannot tell you which half. Output order follows ``recipients``.
        """
        return await build_ft_airdrop(
            self._wallet,
            ref,
            recipients,
            client=self._client,
            fee_rate=self._fee_rate,
            allow_overpay=allow_overpay,
            allow_below_relay_floor=self._allow_below_relay_floor,
        )

    async def airdrop_ft(
        self,
        ref: GlyphRef,
        recipients: Sequence[AirdropRecipient],
        *,
        allow_overpay: bool = False,
    ) -> AirdropReceipt:
        """Distribute ``ref`` to many recipients in one transaction, and broadcast.

        The orchestration behind this lived only in the CLI until now, so a library
        caller had to reimplement it or drive the builder directly.

        Like its transfer siblings the returned txid is derived from the bytes that were
        signed, not from the node's echo: a lying or buggy server could drop the
        transaction and echo a well-formed — even real and already-confirmed — txid,
        leaving a caller polling something unrelated to their tokens.

        Raises:
            BroadcastEchoMismatch: the node echoed a txid other than the one the signed
                bytes hash to. Deliberately **not** a ``ValidationError``: those are
                raised before anything is sent, and a caller retrying on one would
                re-broadcast a distribution that may already have moved tokens.
            InsufficientFundsError: not enough of the token, or no plain-RXD UTXO to pay
                the fee. Raised before anything is signed or sent.
        """
        build = await self.build_ft_airdrop(ref, recipients, allow_overpay=allow_overpay)
        echoed = await self._client.broadcast(build.serialize())
        return AirdropReceipt(
            txid=_confirmed_txid(build, echoed),
            ref=ref,
            recipients=build.recipients,
            total=build.total,
            fee=build.fee,
        )

    async def build_nft_transfer(
        self, ref: GlyphRef, to_pkh: Hex20, *, allow_overpay: bool = False
    ) -> NftTransferBuild:
        """Build and sign an NFT transfer **without broadcasting it**.

        The singleton keeps its own value; the fee comes from a separate plain-RXD
        input. See :func:`pyrxd.glyph.transfer.build_nft_transfer` for why this does
        not go through :meth:`GlyphBuilder.build_nft_transfer_tx`.
        """
        return await build_nft_transfer(
            self._wallet,
            ref,
            to_pkh,
            client=self._client,
            fee_rate=self._fee_rate,
            allow_overpay=allow_overpay,
            allow_below_relay_floor=self._allow_below_relay_floor,
        )

    async def transfer_nft(self, ref: GlyphRef, to_pkh: Hex20, *, allow_overpay: bool = False) -> NftTransferReceipt:
        """Send the NFT singleton ``ref`` to ``to_pkh``, and broadcast.

        The singleton's value crosses unchanged and the fee is paid from plain RXD.
        There is no ``amount``: a singleton is indivisible, and the value on an NFT
        output is dust rather than a quantity.

        Raises:
            InsufficientFundsError: this wallet does not hold the NFT, or has no
                plain-RXD UTXO large enough to pay the fee. Raised before anything is
                signed or sent.
            ValidationError: the signed transaction does not pay for its own size.
        """
        build = await self.build_nft_transfer(ref, to_pkh, allow_overpay=allow_overpay)
        echoed = await self._client.broadcast(build.serialize())
        return NftTransferReceipt(txid=_confirmed_txid(build, echoed), ref=ref, fee=build.fee, to_pkh=to_pkh)

    # -- timelocked content (#556) -----------------------------------------

    def build_timelock_mint(
        self,
        *,
        name: str,
        content_type: str,
        plaintext: bytes,
        params: TimelockParams,
        cek: bytes | None = None,
        recipients: Sequence[TimelockRecipient] = (),
        locator: str | None = None,
    ) -> TimelockMintBuild:
        """Encrypt and seal content **without minting it**. See :func:`~pyrxd.glyph.timelock.build_timelock_mint`.

        Synchronous and network-free: this is pure construction, and it is exposed on the
        client so a caller can inspect the envelope — and take a copy of the CEK — before
        committing anything to a chain. :meth:`mint_timelocked_nft` is this plus the mint.
        """
        return build_timelock_mint(
            name=name,
            content_type=content_type,
            plaintext=plaintext,
            params=params,
            cek=cek,
            recipients=recipients,
            locator=locator,
        )

    async def mint_timelocked_nft(
        self,
        *,
        name: str,
        content_type: str,
        plaintext: bytes,
        params: TimelockParams,
        persist: Callable[[TimelockMintBuild], Any] | None = None,
        cek: bytes | None = None,
        recipients: Sequence[TimelockRecipient] = (),
        locator: str | None = None,
        owner_pkh: Hex20 | bytes | None = None,
    ) -> TimelockMintReceipt:
        """Seal ``plaintext`` behind a timelock and mint the NFT that commits to its key.

        The mint itself is :meth:`mint_nft` — the same two-phase commit/reveal, the same
        store, the same fee rules. What this adds is the envelope: the content is encrypted
        with ``chunked-aead-v1``, the key's SHA-256 goes on chain as ``crypto.timelock``, and
        the key comes back to the caller.

        **The CEK and ciphertext are not recoverable from the chain.** The mint carries a
        commitment to the key and a hash of the plaintext, nothing more; a mint cannot be
        re-run and there is no path from ``sha256(cek)`` back to ``cek``.

        **KEY CUSTODY HAS TO PRECEDE THE COMMIT, so this method makes you say how.** Supply
        either ``persist`` — called with the :class:`~pyrxd.glyph.timelock.TimelockMintBuild`
        after the envelope is built and **before a single byte is broadcast** — or ``cek``,
        a key you already hold. With neither, this raises before touching the network.

        The refusal is not pedantry about defaults. Generating the key inside a call that
        then blocks on confirmation put the only copy of it in a local variable for as long
        as a Radiant block takes: a ``NetworkError``, a ``ConfirmationTimeoutError``, a
        cancellation or a kill in that window and the receipt is never constructed, while
        the pending store holds a resumable commit whose CBOR commits to ``sha256(cek)``.
        The documented recovery — :meth:`reveal_nft` on that pending mint — then succeeds,
        and mints a token nobody can ever open. The advice this docstring used to give
        instead ("persist both halves of the receipt before doing anything else with it")
        is advice a caller cannot act on: the receipt does not exist until after the window
        has closed. ``pyrxd glyph timelock-mint`` never had this problem because it writes
        its files before broadcasting; the hook is that ordering, for the SDK.

        ``persist`` may be sync or async, and anything it raises propagates with nothing
        broadcast. The build it receives carries ``cek``, ``ciphertext``, ``cek_hash``,
        ``stub`` and ``metadata`` — and ``metadata`` is worth saving too: a commit that
        confirms while its reveal does not is spendable only by a reveal pushing
        byte-identical CBOR, which a build with ``recipients`` cannot reproduce.

        See :func:`~pyrxd.glyph.timelock.build_timelock_mint` for the rest of the arguments.
        ``owner_pkh`` behaves as it does on :meth:`mint_nft`, defaulting to the funding key's
        own hash.

        Raises:
            ~pyrxd.security.errors.ValidationError: neither ``persist`` nor ``cek`` was
                given, no store was configured (minting needs one), or the parameters were
                refused. Raised before anything is broadcast.
        """
        if persist is None and cek is None:
            raise ValidationError(
                "mint_timelocked_nft needs somewhere to put the key BEFORE it commits anything. "
                "Pass persist=<callable> — it is handed the TimelockMintBuild (cek, ciphertext, "
                "metadata) before the first broadcast — or pass cek=<32 bytes> you already hold. "
                "Without one of those, the generated key exists only inside this call while it "
                "waits for a confirmation, and a failure there leaves a resumable commit whose "
                "reveal would mint a token no one can ever open: there is no path from "
                "sha256(cek) back to cek."
            )
        build = self.build_timelock_mint(
            name=name,
            content_type=content_type,
            plaintext=plaintext,
            params=params,
            cek=cek,
            recipients=recipients,
            locator=locator,
        )
        # BEFORE the mint, not after. This is the whole point of the parameter; awaiting it
        # here means a persist that raises stops the mint, which is the correct direction —
        # an un-saved key is a reason not to broadcast.
        if persist is not None:
            outcome = persist(build)
            if inspect.isawaitable(outcome):
                await outcome
        result = await self.mint_nft(build.metadata, owner_pkh=owner_pkh)
        return TimelockMintReceipt(
            mint=result,
            cek=build.cek,
            cek_hash=build.cek_hash,
            ciphertext=build.ciphertext,
            stub=build.stub,
            unlock_at=params.unlock_at,
        )

    async def plan_timelock_reveal(
        self,
        metadata: Any,
        *,
        token_ref: str,
        cek: bytes,
        hint: str = "",
        allow_early: bool = False,
    ) -> TimelockRevealPlan:
        """Check a reveal against the chain's own clock, and return what it would publish.

        The clock is read here rather than taken from the caller, which is the point of the
        method existing: :func:`~pyrxd.glyph.timelock_reveal_tx.plan_timelock_reveal` cannot
        judge a lock it is not given a time for, and a caller passing its own number is a
        caller who can pass the wrong one.

        * ``mode="block"`` — the tip height from ``get_tip_height()``.
        * ``mode="time"`` — the **timestamp in the tip block's header**, not this process's
          wall clock. A local clock can be wrong by any amount and nothing would say so,
          and the header timestamp is at least the unit the lock was written in. It is not
          exact — a block's timestamp may run ahead of real time under consensus rules — so
          this is a gate against the obvious mistake, not a substitute for the operator
          knowing what they are publishing.

        **The clock is the SERVER'S, and this SDK does not authenticate it.** Neither read
        is verified: ``get_tip_height`` checks only that a non-negative integer came back
        and ``get_block_header`` only that 80 bytes did. Nothing checks the proof of work
        behind that height, links the header to one already known, or asks a second
        endpoint — and pyrxd's default endpoints are third-party public servers. So an
        endpoint that overstates the tip obtains a permanent early reveal from a gate that
        reports itself satisfied, and one that merely lags refuses an honest holder past
        ``unlock_at``. Calling this "the chain's clock" would be the more reassuring
        sentence and it would not be true: it is one server's claim about the chain.

        What the reveal path does with that is show it. The returned plan carries
        :attr:`~pyrxd.glyph.timelock_reveal_tx.TimelockRevealPlan.judged_at` — the reading
        actually compared against — and ``pyrxd glyph timelock-reveal`` prints it beside
        ``opens at`` in the confirmation prompt, so the operator can disagree with a number
        that would otherwise never have been on screen. An SDK caller who needs more than
        that should pass a clock they trust to
        :func:`~pyrxd.glyph.timelock_reveal_tx.plan_timelock_reveal` directly.

        Everything the plan is checked for happens in the underlying function; see its
        docstring. This adds only the clock.
        """
        current_block: int | None = None
        current_time: int | None = None
        spec_mode = getattr(getattr(metadata, "crypto", None), "timelock", None) or getattr(metadata, "timelock", None)
        mode = getattr(spec_mode, "mode", "block")
        tip = int(await self._client.get_tip_height())
        if mode == "time":
            header = bytes(await self._client.get_block_header(tip))
            if len(header) < 72:  # pragma: no cover - a short header is a broken server
                raise ValidationError(
                    f"the node returned a {len(header)}-byte block header for height {tip}; "
                    "a time-mode timelock cannot be judged without the tip's timestamp"
                )
            # Bitcoin/Radiant 80-byte header: version(4) prev(32) merkle(32) time(4) ...
            current_time = int.from_bytes(header[68:72], "little")
        else:
            current_block = tip
        return plan_timelock_reveal(
            metadata,
            token_ref=token_ref,
            cek=cek,
            current_block=current_block,
            current_time=current_time,
            hint=hint,
            allow_early=allow_early,
        )

    async def build_timelock_reveal(
        self,
        metadata: Any,
        *,
        token_ref: str,
        cek: bytes,
        hint: str = "",
        allow_early: bool = False,
        allow_overpay: bool = False,
    ) -> TimelockRevealBuild:
        """Build and sign a reveal **without broadcasting it** — the dry run.

        For showing an operator exactly what would become public before it does, which is
        what ``pyrxd glyph timelock-reveal --dry-run`` does with it. The plan inside the
        returned build has already passed the commitment check and the unlock gate; there is
        no way to obtain one of these that has not.
        """
        plan = await self.plan_timelock_reveal(
            metadata, token_ref=token_ref, cek=cek, hint=hint, allow_early=allow_early
        )
        return await build_timelock_reveal(
            self._wallet,
            plan,
            client=self._client,
            fee_rate=self._fee_rate,
            allow_overpay=allow_overpay,
            allow_below_relay_floor=self._allow_below_relay_floor,
        )

    async def reveal_timelock(
        self,
        metadata: Any,
        *,
        token_ref: str,
        cek: bytes,
        hint: str = "",
        allow_early: bool = False,
        allow_overpay: bool = False,
    ) -> TimelockRevealReceipt:
        """Publish the CEK on chain, and broadcast.

        **Irreversible.** After this relays, anyone holding the ciphertext can decrypt it,
        forever. There is no unreveal and no second reveal.

        Two mistakes are refused before anything is sent, both by
        :func:`~pyrxd.glyph.timelock_reveal_tx.plan_timelock_reveal`: a CEK that is not the
        one this token committed to, and a reveal before ``unlock_at`` without
        ``allow_early``. Both are :class:`~pyrxd.security.errors.ValidationError` subclasses,
        so they land with everything else raised pre-broadcast.

        Raises:
            ~pyrxd.glyph.timelock_reveal_tx.CekCommitmentMismatch: ``sha256(cek)`` is not the
                token's commitment. Publishing it would spend the reveal and leave the
                payload unreadable for good.
            ~pyrxd.glyph.timelock_reveal_tx.TimelockNotExpired: the lock has not expired and
                ``allow_early`` was not set.
            BroadcastEchoMismatch: the node echoed a txid other than the one the signed bytes
                hash to. Deliberately not a ``ValidationError`` — a caller retrying on one
                would re-publish a key that may already be public.
            ~pyrxd.security.errors.InsufficientFundsError: no plain-RXD UTXO large enough to
                fund the reveal. Raised before anything is signed.
        """
        build = await self.build_timelock_reveal(
            metadata,
            token_ref=token_ref,
            cek=cek,
            hint=hint,
            allow_early=allow_early,
            allow_overpay=allow_overpay,
        )
        return await self.broadcast_timelock_reveal(build)

    async def broadcast_timelock_reveal(self, build: TimelockRevealBuild) -> TimelockRevealReceipt:
        """Broadcast a reveal that was already built and shown to someone.

        Split out from :meth:`reveal_timelock` so a caller that displayed a build can send
        **those bytes**. The CLI confirms a reveal by printing the key it is about to
        publish; calling ``reveal_timelock`` after that prompt would build a second
        transaction and broadcast it instead — a confirmation showing one artifact and
        sending another, which is worse than no confirmation because it looks like one.

        The build already carries a checked plan; there is no way to construct a
        :class:`~pyrxd.glyph.timelock_reveal_tx.TimelockRevealBuild` that has not been
        through :func:`~pyrxd.glyph.timelock_reveal_tx.plan_timelock_reveal`.
        """
        echoed = await self._client.broadcast(build.serialize())
        return TimelockRevealReceipt(
            txid=_confirmed_txid(build, echoed),
            token_ref=build.plan.token_ref,
            cek=build.plan.proof.cek,
            commitment=build.plan.commitment,
            fee=build.fee,
        )
