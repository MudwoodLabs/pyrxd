"""``pyrxd glyph …`` subcommand group — Cut 2 of the v0.3 wallet/CLI plan.

Commands:
  glyph init-metadata   Write a metadata.json scaffold for a token type.
  glyph mint-nft        Two-tx commit/reveal NFT mint.
  glyph deploy-ft       FT premine deploy (full supply at vout[0]).
  glyph deploy-dmint    V1 dMint contract genesis (commit/reveal).
  glyph claim-dmint     PoW-mine a claim from a live dMint contract.
  glyph transfer-ft     FT transfer with conservation enforcement.
  glyph airdrop-ft      One-tx FT distribution to many recipients.
  glyph transfer-nft    NFT singleton transfer.
  glyph timelock-mint   Seal content behind a timelock and mint the NFT.
  glyph timelock-reveal Publish the key for a timelocked token (irreversible).
  glyph list            Scan wallet addresses for Glyph holdings.

Design choices that follow the v0.3 plan:

* **File-driven metadata** — every mint command takes
  ``<metadata.json>`` as a positional argument. ``init-metadata``
  scaffolds a template appropriate to the requested token type so
  the user doesn't have to hand-write the full surface.
* **--json + --yes required for any broadcast.** Same gate as Cut 1.
* **No double-signing.** Long-running flows (mint-nft polls between
  commit and reveal) only re-prompt for the mnemonic if they need to
  resume after a failure.
* **claim-dmint gates ONCE, before the PoW grind.** The mint takes
  minutes to mine between the value decision and the broadcast, so the
  confirmation gate fires up front (all value facts — contract, funding,
  reward, network — are known then) rather than immediately before the
  broadcast. This fails fast for ``--json``-without-``--yes`` and avoids a
  hostile re-prompt after a long walk-away. The signed raw hex is echoed to
  stderr before broadcast so a dropped connection is recoverable.
"""

from __future__ import annotations

import asyncio
import json
import shlex
import sys
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

import click

from ..constants import DUST_THRESHOLD_PHOTONS, MAX_OP_RETURN_MSG_BYTES, Network
from ..fee_models import SatoshisPerKilobyte
from ..fee_sizing import MAX_FEE_OVERPAY_MULTIPLE, assert_fee_rate_clears_relay_floor, relay_floor_photons_per_byte
from ..glyph.builder import (
    AirdropFunding,
    AirdropRecipient,
    CommitParams,
    DmintV1DeployParams,
    DmintV2DeployParams,
    FtDeployRevealScripts,
    FtUtxo,
    GlyphBuilder,
    RevealParams,
)
from ..glyph.client import BroadcastEchoMismatch, _confirmed_txid
from ..glyph.dmint import (
    DEFAULT_ASERT_HALFLIFE,
    DEFAULT_MAX_ATTEMPTS,
    MAX_SHA256D_TARGET,
    DaaMode,
    DmintAlgo,
    DmintContractUtxo,
    DmintMinerFundingUtxo,
    build_dmint_mint_tx,
    build_dmint_v1_mint_preimage,
    build_dmint_v2_mint_preimage,
    build_mint_scriptsig,
    estimate_attempts,
    find_dmint_contract_utxos,
    find_dmint_funding_utxo,
    mine_solution_dispatch,
)
from ..glyph.dmint.miner import _unmintable_reason
from ..glyph.dmint.types import check_dmint_v1_bounds, check_v2_numeric_bounds
from ..glyph.fees import (
    RevealFeeEstimate,
    assert_reveal_balances,
    check_reveal_funding,
    commit_value_for_reveal,
    estimate_reveal_fee_for_metadata,
)
from ..glyph.mint import JsonFilePendingStore, PendingMint
from ..glyph.payload import encode_payload
from ..glyph.scanner import GlyphScanner
from ..glyph.transfer import NoFeeFundingError, NoHoldingsError, build_ft_airdrop
from ..glyph.transfer import build_ft_transfer as lib_build_ft_transfer
from ..glyph.transfer import build_nft_transfer as lib_build_nft_transfer
from ..glyph.transfer import find_plain_rxd_utxo as lib_find_plain_rxd_utxo
from ..glyph.transfer import ft_funding as lib_ft_funding
from ..glyph.transfer import select_ft_inputs as lib_select_ft_inputs
from ..glyph.transfer import single_ft_signing_key as lib_single_ft_signing_key
from ..glyph.types import GlyphFt, GlyphMetadata, GlyphNft, GlyphProtocol, GlyphRef
from ..glyph.wave_rules import (
    FEE_DECLINED,
    WAVE_TREASURY_ADDRESS,
    WaveRegistrationFee,
    format_rxd,
    wave_registered_label,
    wave_registration_fee_for,
)
from ..hd.wallet import HdWallet
from ..network.confirm import (
    DEFAULT_CONFIRMATION_TIMEOUT_S,
    DEFAULT_POLL_INTERVAL_S,
    wait_for_confirmation,
)
from ..script.script import Script
from ..script.type import P2PKH, encode_pushdata
from ..security.errors import (
    ConfirmationTimeoutError,
    DmintError,
    InsufficientFundsError,
    InvalidFundingUtxoError,
    MaxAttemptsError,
    NetworkError,
    PolicyRejection,
    UnrecognizedDaaBytecodeError,
    ValidationError,
)
from ..security.types import Hex20, Txid
from ..transaction.transaction import Transaction
from ..transaction.transaction_input import TransactionInput
from ..transaction.transaction_output import TransactionOutput
from ..utils import validate_address
from .config import DEFAULT_CONFIG_DIR, DEFAULT_CONFIG_PATH
from .context import CliContext
from .errors import CliError, NetworkBoundaryError, UserError
from .format import emit, emit_table, format_photons
from .glyph_estimate import MiningDeadline, _MiningReporter, dmint_estimate_cmd
from .glyph_helpers import (
    _TEMPLATE_TYPES,
    _BroadcastSummary,
    _build_glyph_unlock,
    _confirm_or_abort,
    _fetch_dmint_contract,
    _metadata_summary,
    _parse_ref,
    _read_metadata_file,
    _scaffold_for,
)
from .glyph_inspect import _HUMAN_STRING_CAP as _HUMAN_STRING_CAP
from .glyph_inspect import _sanitize_display_string as _sanitize_display_string
from .glyph_inspect import inspect_cmd
from .prompts import _load_wallet

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from ..glyph.dmint import DmintMintResult, PowPreimageResult
    from ..keys import PrivateKey
    from ..network.electrumx import ElectrumXClient, UtxoRecord


# ---------------------------------------------------------------------------
# Group registration
# ---------------------------------------------------------------------------


@click.group(name="glyph")
def glyph_group() -> None:
    """Mint, transfer, and inspect Glyph tokens."""


_UNVERIFIED_FLAG_HELP = (
    "Go ahead when no indexer can say whether the WAVE name is free. If the name is already "
    "registered, the reveal is a duplicate claim the indexer does not register, and the "
    "registration fee buys NOTHING."
)


@glyph_group.command(name="init-metadata")
@click.option(
    "--type",
    "kind",
    type=click.Choice(_TEMPLATE_TYPES),
    default="nft",
    help="Token-type template to scaffold.",
)
@click.option(
    "--out",
    "out_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Write to FILE (default: stdout).",
)
@click.pass_obj
def init_metadata_cmd(ctx: CliContext, kind: str, out_path: Path | None) -> None:
    """Scaffold a metadata.json for a Glyph mint command."""
    body = json.dumps(_scaffold_for(kind), indent=2) + "\n"
    if out_path is None:
        sys.stdout.write(body)
        return
    if out_path.exists():
        raise UserError(
            f"refusing to overwrite {out_path}",
            cause="file already exists",
            fix=f"choose a different --out path, or remove {out_path} first",
        )
    out_path.write_text(body)
    if ctx.output_mode == "json":
        click.echo(emit({"path": str(out_path)}, mode="json"))
    elif ctx.output_mode == "quiet":
        click.echo(emit({"path": str(out_path)}, mode="quiet", quiet_field="path"))
    else:
        click.echo(f"wrote {kind} metadata template to {out_path}")


# ---------------------------------------------------------------------------
# mint-nft
# ---------------------------------------------------------------------------


@glyph_group.command(name="mint-nft")
@click.argument("metadata_file", type=click.Path(path_type=Path))
@click.option(
    "--passphrase/--no-passphrase",
    default=False,
    help="Prompt for the BIP39 passphrase used at wallet creation.",
)
@click.option(
    "--wave-registration-fee/--no-wave-registration-fee",
    "pay_wave_fee",
    default=True,
    show_default=True,
    help=(
        "When the metadata registers a WAVE name, pay the protocol's registration fee to the WAVE "
        "treasury in the reveal (100/50/10/5 RXD for a 3/4/5/6+ character name). "
        "--no-wave-registration-fee registers the name without paying: the published protocol "
        "expects the fee, the indexer does not check it at registration (so the name still "
        "resolves), and renewing the name requires paying its price to the treasury."
    ),
)
@click.option(
    "--wave-treasury",
    "wave_treasury",
    default=None,
    metavar="ADDRESS",
    help=(
        "Pay the WAVE registration fee to this address instead of the published mainnet treasury. "
        "Required to pay the fee on testnet or regtest, where no treasury is published."
    ),
)
@click.option("--allow-unverified-wave-name", "allow_unverified_wave_name", is_flag=True, help=_UNVERIFIED_FLAG_HELP)
@click.option(
    "--ignore-pending-mint",
    "ignore_pending_mint",
    is_flag=True,
    help=(
        "Commit even though this wallet's pending-mints/ holds an unrevealed commit for the same WAVE name. "
        "That commit keeps its value until it is revealed; a second one spends again, and at most one of the "
        "two claims can register the name."
    ),
)
@click.pass_obj
def mint_nft_cmd(
    ctx: CliContext,
    metadata_file: Path,
    passphrase: bool,
    pay_wave_fee: bool,
    wave_treasury: str | None,
    allow_unverified_wave_name: bool,
    ignore_pending_mint: bool,
) -> None:
    """Mint a Glyph NFT via two-phase commit + reveal.

    Builds and broadcasts the commit transaction, polls for
    confirmation, then builds and broadcasts the reveal. Both txs
    require a separate confirmation in human mode (or a single
    --yes for both in scripted mode). A record of the commit is saved
    before it is broadcast; if the reveal does not happen, every exit
    says how to finish it with `glyph resume-mint`.

    If the metadata registers a WAVE name, an indexer must say the name
    is free (it is asked before the commit, before the reveal's
    confirmation and again just before the reveal is broadcast), no
    unrevealed commit for the same name may be pending in this wallet
    (--ignore-pending-mint overrides), and the reveal pays the WAVE
    registration fee to the treasury from a wallet input unless
    --no-wave-registration-fee is given. The confirmation shows the
    amount, the treasury and the input.
    """
    metadata = _read_metadata_file(metadata_file)
    if GlyphProtocol.NFT not in metadata.protocol:
        raise UserError(
            "metadata.protocol does not include NFT",
            cause=f"got protocol={list(metadata.protocol)}",
            fix='set "protocol": ["NFT"] (or ["NFT", "MUT"], etc.) in the metadata file',
        )
    if wave_treasury is not None:
        if not pay_wave_fee:
            raise UserError(
                "--wave-treasury was given with --no-wave-registration-fee",
                cause="nothing would be paid to the treasury named",
                fix="drop one of the two",
            )
        _require_address_on_network(ctx, wave_treasury, what="--wave-treasury")
    wallet = _load_wallet(ctx, prompt_passphrase=passphrase)

    async def _do_mint() -> dict:
        client = ctx.make_client()
        async with client:
            return await _mint_nft_inner(
                ctx,
                wallet,
                metadata,
                client,
                pay_registration_fee=pay_wave_fee,
                registration_treasury=wave_treasury,
                allow_unverified_wave_name=allow_unverified_wave_name,
                ignore_pending_mint=ignore_pending_mint,
            )

    try:
        result = asyncio.run(_do_mint())
    except NetworkError as exc:
        raise NetworkBoundaryError(
            "could not reach ElectrumX",
            cause=str(exc),
            fix=f"check that {ctx.electrumx_url} is reachable",
        ) from exc

    _echo_mint_result(ctx, result)


def _echo_mint_result(ctx: CliContext, result: dict[str, Any]) -> None:
    if ctx.output_mode == "json":
        click.echo(emit(result, mode="json"))
    elif ctx.output_mode == "quiet":
        click.echo(emit(result, mode="quiet", quiet_field="reveal_txid"))
    else:
        click.echo("\nNFT minted!")
        click.echo(f"  commit txid: {result['commit_txid']}")
        click.echo(f"  reveal txid: {result['reveal_txid']}")
        click.echo(f"  glyph ref:   {result['ref']}")
        wave = result.get("wave_registration")
        if wave is not None:
            fee = wave["fee"]
            click.echo(
                f"  WAVE fee:    {fee['rxd']} RXD to {fee['treasury']} (reveal vout {wave['fee_vout']}, "
                f"paid from {wave['fee_input']})"
                if fee is not None
                else f"  WAVE fee:    NOT PAID for {wave['name']} (--no-wave-registration-fee)"
            )


@glyph_group.command(name="resume-mint")
@click.argument("commit_txid", type=str)
@click.option(
    "--passphrase/--no-passphrase",
    default=False,
    help="Prompt for the BIP39 passphrase used at wallet creation.",
)
@click.option(
    "--wave-registration-fee/--no-wave-registration-fee",
    "pay_wave_fee",
    default=None,
    help=(
        "Normally unnecessary: resume-mint does what the mint chose, which its record keeps. "
        "--no-wave-registration-fee reveals without paying: the way to recover a commit whose name was "
        "taken in the meantime (the reveal is then a duplicate claim the indexer does not register; the "
        "carrier and the change come back to this wallet). A mint that declined the fee is never made to "
        "pay here: --wave-registration-fee against such a record is refused."
    ),
)
@click.option(
    "--wave-treasury",
    "wave_treasury",
    default=None,
    metavar="ADDRESS",
    help=(
        "The treasury the mint named with --wave-treasury. REQUIRED when the record keeps one: the fee goes to an "
        "address other than the published WAVE treasury only if this command line names it too. Refused if it is "
        "not the one the record keeps."
    ),
)
@click.option("--allow-unverified-wave-name", "allow_unverified_wave_name", is_flag=True, help=_UNVERIFIED_FLAG_HELP)
@click.pass_obj
def resume_mint_cmd(
    ctx: CliContext,
    commit_txid: str,
    passphrase: bool,
    pay_wave_fee: bool | None,
    wave_treasury: str | None,
    allow_unverified_wave_name: bool,
) -> None:
    """Reveal a commit `glyph mint-nft` broadcast but did not reveal.

    Reads the record mint-nft saved before broadcasting the commit, checks it against this
    wallet and the chain, waits for the commit to confirm, and builds, checks and (after
    confirmation) broadcasts its reveal. For a WAVE name it does what the mint chose: it
    pays the fee from a plain wallet input only if the mint chose to pay it and an indexer
    still says the name is free, and it pays a treasury other than the published one only if
    this command names it with --wave-treasury. The record is deleted once the reveal
    confirms.
    """
    try:
        Txid(commit_txid)
    except ValidationError as exc:
        raise UserError("not a transaction id", cause=str(exc)) from exc
    if wave_treasury is not None:
        if pay_wave_fee is False:
            raise UserError(
                "--wave-treasury was given with --no-wave-registration-fee",
                cause="nothing would be paid to the treasury named",
                fix="drop one of the two",
            )
        _require_address_on_network(ctx, wave_treasury, what="--wave-treasury")
    wallet = _load_wallet(ctx, prompt_passphrase=passphrase)

    async def _do() -> dict[str, Any]:
        client = ctx.make_client()
        async with client:
            return await _resume_mint_inner(
                ctx,
                wallet,
                client,
                commit_txid,
                pay_registration_fee=pay_wave_fee,
                registration_treasury=wave_treasury,
                allow_unverified_wave_name=allow_unverified_wave_name,
            )

    try:
        result = asyncio.run(_do())
    except NetworkError as exc:
        raise NetworkBoundaryError(
            "could not reach ElectrumX",
            cause=str(exc),
            fix=f"check that {ctx.electrumx_url} is reachable, then run resume-mint again",
        ) from exc
    _echo_mint_result(ctx, result)


# Commit sizing now lives in ``pyrxd.glyph.fees`` — the library-side mint facade
# (``pyrxd.glyph.mint``) sizes its commits from the same function, and a private CLI copy
# would be a second fund-safety constant free to drift from it. Re-bound as a module-level
# name so it stays monkeypatchable in tests/cli/test_glyph_cmds.py.
_commit_value_for_reveal = commit_value_for_reveal


# Stand-in commit txid for the dry-run reveal built by :func:`_assert_reveal_is_fundable`
# before the real commit exists. A txid occupies 32 bytes in the input outpoint and 32
# bytes in the reveal locking script's ref push whatever its value, so the dry-run reveal
# serializes to exactly the same length as the real one — which is what the fee model
# measures. ``tests/test_glyph_reveal_fees.py`` pins that equality.
_PLACEHOLDER_COMMIT_TXID = "00" * 32


def _fee_statement(
    fee: WaveRegistrationFee | None, registered_label: str | None
) -> WaveRegistrationFee | Literal["declined"] | None:
    """What a reveal says it pays for a WAVE name, in :func:`~pyrxd.glyph.fees.measure_reveal_fee`'s terms."""
    if fee is not None:
        return fee
    return FEE_DECLINED if registered_label is not None else None


def _assert_reveal_is_fundable(
    commit_value: int,
    carrier_value: int,
    reveal_tx: Transaction,
    fee_rate: int,
    cbor_bytes_len: int,
    *,
    registration_fee: WaveRegistrationFee | Literal["declined"] | None,
) -> RevealFeeEstimate:
    """Fail the mint *before* the commit is broadcast if the reveal cannot pay its fee.

    Takes the **built** (dry-run) reveal transaction and measures it, rather than
    re-checking the estimate the commit value was derived from. That distinction is the
    whole value of this function: ``_commit_value_for_reveal`` sets
    ``commit_value = carrier + max(floor, estimate.fee + slack)``, so re-testing
    ``commit_value >= carrier + estimate.fee`` against that same estimate is a tautology
    that can never fail. Measuring the real transaction is an independent check — it
    fires if the estimator's shim (its prefix constant, its locking-script sizes, its
    assumed output set) has stopped describing the transaction the CLI actually builds.

    Two checks. The commit alone must cover the carrier and the reveal's whole miner fee
    (:func:`~pyrxd.glyph.fees.check_reveal_funding`), as it always has. And the reveal as a
    whole must balance (:func:`~pyrxd.glyph.fees.assert_reveal_balances`): exactly one
    output pays the WAVE treasury exactly the tier value when a fee is paid, the inputs —
    the commit, plus the wallet input that funds the fee — cover every output and the
    miner fee, and the change output survives.

    Returns the measured estimate so the caller can display the real number. Raises
    :class:`UserError` naming the shortfall while the money is still in the wallet,
    instead of leaving a rejected reveal and a commit output nothing can spend.
    """
    try:
        measured = assert_reveal_balances(
            reveal_tx, fee_rate=fee_rate, cbor_bytes_len=cbor_bytes_len, registration_fee=registration_fee
        )
        check_reveal_funding(commit_value=commit_value, carrier_value=carrier_value, estimate=measured)
    except InsufficientFundsError as exc:
        raise UserError(
            "commit value cannot cover the reveal fee — refusing to broadcast the commit",
            cause=str(exc),
            fix=("shrink the metadata (the reveal scriptSig carries the whole CBOR payload) or lower --fee-rate"),
        ) from exc
    except ValidationError as exc:
        raise UserError(
            "the reveal this mint would broadcast is wrong — refusing to broadcast the commit", cause=str(exc)
        ) from exc
    return measured


@dataclass(frozen=True)
class _FeeFunding:
    """The plain wallet UTXO a reveal that registers a WAVE name spends to pay the fee.

    ``mint-nft`` uses its own commit's change (Photonic's shape; mainnet claim ``f644794b…``'s
    third input is its commit's vout 2). ``resume-mint`` picks one from the wallet with
    :func:`~pyrxd.glyph.transfer.find_plain_rxd_utxo`, which checks the on-chain script is a
    bare P2PKH, so a token UTXO is never spent as the fee.
    """

    txid: str
    vout: int
    value: int
    address: str
    key: PrivateKey


def _build_reveal_tx(
    *,
    commit_txid: str,
    commit_value: int,
    commit_script: bytes,
    reveal_locking_script: bytes,
    carrier_value: int,
    change_locking: Script,
    funding_key: PrivateKey,
    scriptsig_suffix: bytes,
    registration_fee: WaveRegistrationFee | None,
    fee_funding: _FeeFunding | None = None,
) -> Transaction:
    """Build (unsigned, un-fee'd) the reveal that spends the commit output.

    Shared by the pre-broadcast dry run and the real post-confirmation build so the two
    cannot diverge — a dry run that measured a *different* transaction would be worth no
    more than the tautology it replaced.

    With a WAVE ``registration_fee`` (pass the builder result's ``registration_fee_output``)
    the reveal takes a second input, ``fee_funding``, a plain wallet UTXO, and puts the fee
    at vout 1, right after the token and before change: the order Photonic's ``mintToken``
    uses (token outputs, then the extra outputs, then change; see
    :mod:`pyrxd.glyph.wave_rules`). Photonic's WAVE reveal also carries the mutable contract,
    so its fee lands at vout 2; this reveal has no contract output. The commit is never the
    fee's source: what the fee input holds beyond the fee comes back as change.
    """
    if (registration_fee is None) != (fee_funding is None):
        raise ValueError("a WAVE registration fee and the wallet input that funds it go together")
    shim_commit_out = TransactionOutput(Script(commit_script), commit_value)
    src_commit_tx = Transaction(tx_inputs=[], tx_outputs=[shim_commit_out])
    src_commit_tx.txid = lambda: commit_txid  # type: ignore[method-assign]

    reveal_input = TransactionInput(
        source_transaction=src_commit_tx,
        source_output_index=0,
        unlocking_script_template=_build_glyph_unlock(funding_key, scriptsig_suffix),
    )
    reveal_input.satoshis = commit_value
    reveal_input.locking_script = Script(commit_script)
    inputs = [reveal_input]

    fee_outputs: list[TransactionOutput] = []
    if registration_fee is not None and fee_funding is not None:
        spk = P2PKH().lock(fee_funding.address)
        src_outs = [TransactionOutput(Script(b""), 0) for _ in range(fee_funding.vout)]
        src_outs.append(TransactionOutput(spk, fee_funding.value))
        src_fee_tx = Transaction(tx_inputs=[], tx_outputs=src_outs)
        src_fee_tx.txid = lambda: fee_funding.txid  # type: ignore[method-assign]
        fee_input = TransactionInput(
            source_transaction=src_fee_tx,
            source_txid=fee_funding.txid,
            source_output_index=fee_funding.vout,
            unlocking_script_template=P2PKH().unlock(fee_funding.key),
        )
        fee_input.satoshis = fee_funding.value
        fee_input.locking_script = spk
        inputs.append(fee_input)
        fee_outputs.append(TransactionOutput(Script(registration_fee.locking_script), registration_fee.value))

    # The token sits on vout[0] (a dust carrier for an NFT, the whole supply for an FT
    # premine); the rest of the inputs returns as change (fee() sized from the real
    # length) instead of being burned to fee.
    return Transaction(
        tx_inputs=inputs,
        tx_outputs=[
            TransactionOutput(Script(reveal_locking_script), carrier_value),
            *fee_outputs,
            TransactionOutput(change_locking, 0, change=True),
        ],
    )


#: Where ``_build_reveal_tx`` puts a WAVE registration fee: right after the token.
_REVEAL_FEE_VOUT = 1


def _wave_registration_summary(
    label: str | None,
    fee: WaveRegistrationFee | None,
    *,
    name_status: str | None,
    fee_funding: _FeeFunding | None,
) -> list[_BroadcastSummary]:
    """The confirmation section for a mint that registers a WAVE name; nothing otherwise."""
    if label is None:
        return []
    lines = [f"name:          {label}.rxd", f"available:     {name_status or 'not checked'}"]
    if fee is None:
        lines += [
            "fee:           NOT PAID (--no-wave-registration-fee)",
            "               The published WAVE protocol expects this fee. The indexer does not",
            "               check it at registration, so the name still resolves if it is free;",
            "               renewing it requires paying the name's price to the WAVE treasury.",
        ]
    else:
        lines += [
            f"fee:           {format_photons(fee.value)}",
            f"treasury:      {fee.treasury_address}"
            + ("" if fee.is_published_treasury else "  (NOT the published WAVE treasury)"),
            f"paid:          in the reveal, vout {_REVEAL_FEE_VOUT}, from a wallet input (not the commit)",
        ]
        if fee_funding is not None:
            lines.append(
                f"fee input:     {fee_funding.txid[:16]}…:{fee_funding.vout}  {fee_funding.value:,} photons "
                f"({fee_funding.address}; the rest comes back as change)"
            )
    return [_BroadcastSummary(title="WAVE registration fee", lines=lines)]


# ---------------------------------------------------------------------------
# WAVE name availability
# ---------------------------------------------------------------------------


async def _wave_name_available(client: ElectrumXClient, label: str) -> bool | None:
    """The indexer's answer to "is ``label`` free?", or ``None`` if no server could answer.

    :meth:`~pyrxd.glyph.wave.WaveResolver.check_available`, which fails over to a server
    running the RXinDexer extension (#730) and raises rather than guessing on any answer that
    is not a definite ``available`` boolean. Every such failure is ``None`` here: unknown.
    """
    from ..glyph.wave import WaveResolver
    from ..network.rxindexer import RxinDexerError

    try:
        return await WaveResolver(client).check_available(label)
    except (RxinDexerError, NetworkError):
        return None


async def _require_wave_name_free_before_commit(client: ElectrumXClient, label: str, *, allow_unverified: bool) -> str:
    """Refuse to commit a claim for a name that is taken, or that no indexer vouches for."""
    available = await _wave_name_available(client, label)
    if available is False:
        raise UserError(
            f"the WAVE name {label}.rxd is already registered",
            cause="the indexer (wave.check_available) reports it taken; a claim for it would be a duplicate",
            fix="choose another name. Nothing was broadcast.",
        )
    if available is None:
        if not allow_unverified:
            raise UserError(
                f"could not confirm the WAVE name {label}.rxd is available",
                cause="no configured server answered wave.check_available",
                fix=(
                    "retry when an RXinDexer server answers, or pass --allow-unverified-wave-name to mint "
                    "anyway: if the name is already registered, the registration fee buys nothing. "
                    "Nothing was broadcast."
                ),
            )
        return "NOT VERIFIED (--allow-unverified-wave-name): if it is taken, the fee buys nothing"
    return "yes (the indexer says it is free)"


class _RevealRefused(UserError):
    """A refusal after the commit is broadcast and before the reveal is: nothing more is spent.

    :func:`_after_commit` adds the commit's recovery after whatever ``fix`` it carries (most
    carry none).
    """


class _NothingToRecover(UserError):
    """An exit after the commit that has nothing left to recover (the commit is already spent).

    :func:`_after_commit` passes it through as it is, rather than pointing at a recovery that
    would find nothing.
    """


class _RecordRefused(UserError):
    """The commit's record cannot be trusted to sign with (a fee rate out of bounds, a value
    the chain does not agree with). Carries its own fix; passed through as it is, because the
    usual recovery — run resume-mint — would read the same record and refuse again."""


class _Inconclusive(NetworkBoundaryError):
    """The server's answers do not say whether the commit is spent. The record is KEPT, and the
    error carries its own fix; passed through as it is."""


async def _require_wave_name_free_before_reveal(
    client: ElectrumXClient, label: str, *, allow_unverified: bool, resume_unverified: str
) -> str:
    """The same check, after the commit: a refusal here pays nothing and loses nothing.

    ``resume_unverified`` is the resume command with ``--allow-unverified-wave-name``, offered
    when no server answers: the one way to pay without an answer, and it says what it risks.
    """
    available = await _wave_name_available(client, label)
    if available is False:
        raise _RevealRefused(
            f"the WAVE name {label}.rxd is registered now — NOT paying the registration fee",
            cause=(
                "the indexer (wave.check_available) reports the name taken. If it is, this claim is a duplicate "
                "the indexer does not register, and the fee would buy nothing"
            ),
        )
    if available is None:
        if not allow_unverified:
            raise _RevealRefused(
                f"could not confirm the WAVE name {label}.rxd is still available — NOT paying the registration fee",
                cause="no configured server answered wave.check_available",
                fix=(
                    "retry when an RXinDexer server answers (another server: --electrumx), or pay without an "
                    f"answer: `{resume_unverified}` — if the name is already registered, the registration fee "
                    "buys nothing"
                ),
            )
        return "NOT VERIFIED (--allow-unverified-wave-name): if it is taken, the fee buys nothing"
    return "yes (the indexer says it is free)"


# ---------------------------------------------------------------------------
# The commit's record, and what every exit after the commit says
# ---------------------------------------------------------------------------


def _pending_dir(ctx: CliContext) -> Path:
    """Beside the wallet file (``~/.pyrxd/pending-mints`` for the default wallet)."""
    wallet_path = Path(ctx.wallet_path).expanduser()
    base = wallet_path.parent if str(wallet_path) not in ("", ".") else DEFAULT_CONFIG_DIR
    return base / "pending-mints"


def _pending_store(ctx: CliContext) -> JsonFilePendingStore:
    """Where ``mint-nft`` keeps the record that lets a broadcast commit be revealed later.

    :func:`_pending_dir`, owner-only. Creates the directory.
    """
    return JsonFilePendingStore(_pending_dir(ctx))


def _refuse_a_second_commit_for(ctx: CliContext, label: str, *, allow_unverified: bool) -> None:
    """Refuse to commit a claim for ``label`` while this wallet holds an unrevealed commit for it.

    Every exit after a commit says "do not re-run the mint command", and nothing enforced it: a
    second ``mint-nft`` for the same name committed, and paid, again (panel D-I1). At most one of
    the two claims can register the name, so the second fee — or the first commit's reveal —
    buys a duplicate. A record is deleted only once its reveal confirms, so a record for the
    name means that name's earlier commit is not known to be revealed.

    Reads the directory without creating it. A record that cannot be read is skipped: it cannot
    be resumed either, and refusing every future mint over a damaged file is not this check's
    job. ``--ignore-pending-mint`` skips the check.
    """
    from ..glyph.mint import PendingMintNotFound

    directory = _pending_dir(ctx)
    if not directory.is_dir():
        return
    store = JsonFilePendingStore(directory)
    waiting: list[PendingMint] = []
    for txid in store.list_pending():
        try:
            record = store.load(txid)
        except (ValidationError, PendingMintNotFound, OSError):
            continue
        if wave_registered_label(record.cbor_bytes) == label:
            waiting.append(record)
    if not waiting:
        return
    first = waiting[0]
    resumes = "; ".join(f"`{_resume_command(ctx, p, allow_unverified=allow_unverified)}`" for p in waiting)
    raise UserError(
        f"this wallet already has an unrevealed commit for the WAVE name {label}.rxd — refusing to commit again",
        cause=(
            f"{_shown_path(directory / (first.commit_txid + '.json'))} records the commit {first.commit_txid}:"
            f"{first.commit_vout} ({first.commit_value:,} photons)"
            + (f" and {len(waiting) - 1} more" if len(waiting) > 1 else "")
            + "; a record is deleted only once its reveal confirms. A second commit spends again, and at most "
            "one of the claims can register the name"
        ),
        fix=(
            f"reveal the one you have: {resumes}. If that commit never confirmed and has left the mempool, "
            f"nothing was spent: delete its record and mint again. To commit a second claim anyway, pass "
            f"--ignore-pending-mint. Nothing was broadcast."
        ),
    )


@dataclass
class _Progress:
    """What has happened since the commit was broadcast, so an exit says what is true."""

    #: Set once the reveal is broadcast. From then on the record is kept until it confirms.
    reveal_txid: str | None = None
    #: Set when the server lists the commit output at a value the record does not say, so the
    #: recovery reports both numbers instead of asserting the record's.
    server_value: int | None = None


def _shown_path(path: Path | str) -> str:
    """``path`` for text a person reads or pastes: ``~/…`` under the home directory (#737).

    Recovery text and ``--json`` documents get pasted into issues, and an absolute path under
    ``/home/<user>`` names the user. Outside the home directory the absolute path is shown.
    """
    absolute = Path(path).expanduser().absolute()
    try:
        rel = absolute.relative_to(Path.home())
    except (ValueError, RuntimeError):  # not under home, or no home directory to resolve
        return str(absolute)
    return "~" if str(rel) == "." else f"~/{rel}"


def _shell_path(path: Path | str) -> str:
    """:func:`_shown_path`, quoted for a shell command line.

    The ``~/`` prefix is left UNQUOTED so the shell expands it (``~/'my wallets/w.dat'`` is
    ``$HOME/my wallets/w.dat``); a quoted ``~`` would reach pyrxd literally — which also works,
    since ``--wallet`` and ``--config`` expand it themselves, but reads as a mistake.
    """
    shown = _shown_path(path)
    if shown == "~":
        return shown
    if shown.startswith("~/"):
        return "~/" + shlex.quote(shown[2:])
    return shlex.quote(shown)


def _shown_url(url: str) -> str:
    """An ``--electrumx`` URL for a printed command, with any password in it replaced.

    A URL can carry credentials (``wss://user:secret@host``). The recovery command is printed,
    and pasted; a command with ``<password>`` in it fails loudly at authentication, where one
    that printed the secret would have leaked it.
    """
    from urllib.parse import urlsplit, urlunsplit

    try:
        parts = urlsplit(url)
        password = parts.password
    except ValueError:
        return url
    if password is None:
        return url
    netloc = parts.netloc.replace(f":{password}@", ":<password>@", 1)
    return urlunsplit(parts._replace(netloc=netloc))


def _resume_command(ctx: CliContext, pending: PendingMint, *, allow_unverified: bool, decline: bool = False) -> str:
    """The exact command that finishes ``pending``, with the options it needs to find it.

    The global options come first because the record lives beside the wallet file and the
    commit on one network: a bare ``pyrxd glyph resume-mint <txid>`` run with a different
    ``--wallet`` or ``--network`` looks in the wrong place, and a mint run against a server named
    with ``--electrumx`` resumes against that server. The wallet path is shown home-relative
    (#737). A wallet opened with a BIP39 passphrase gets ``--passphrase``, which prompts for it:
    without it the same wallet cannot re-derive the commit's key. And the mint's WAVE fee choice
    is repeated, so the printed command is exactly what the mint agreed to: a declined fee stays
    declined, a named treasury stays named, and a mint that went ahead on an unverified name
    (``allow_unverified``, this run's ``--allow-unverified-wave-name``) says so again — resume-mint
    does not carry that choice over from anywhere else.
    """
    args = [shlex.quote("pyrxd")]
    source = ctx.config.source_path
    if source is not None and Path(source) != DEFAULT_CONFIG_PATH:
        args += ["--config", _shell_path(source)]
    if ctx.electrumx_override:
        args += ["--electrumx", shlex.quote(_shown_url(ctx.electrumx_override))]
    args += ["--network", shlex.quote(ctx.network), "--wallet", _shell_path(ctx.wallet_path)]
    args += ["glyph", "resume-mint", shlex.quote(pending.commit_txid)]
    if ctx.opened_with_passphrase:
        args.append("--passphrase")
    if decline or pending.wave_fee == "decline":
        args.append("--no-wave-registration-fee")
    else:
        if pending.wave_treasury is not None:
            args += ["--wave-treasury", shlex.quote(pending.wave_treasury)]
        if allow_unverified and pending.wave_fee == "pay":
            args.append("--allow-unverified-wave-name")
    return " ".join(args)


def _commit_recovery(
    ctx: CliContext, pending: PendingMint, store_dir: Path, progress: _Progress, *, allow_unverified: bool
) -> str:
    """How to recover a commit that has been broadcast and not revealed. Never just "re-run"."""
    txid = pending.commit_txid
    registered_label = wave_registered_label(pending.cbor_bytes)
    resume = _resume_command(ctx, pending, allow_unverified=allow_unverified)
    shown_dir = _shown_path(store_dir)
    passphrase_note = (
        " `--passphrase` there prompts for this wallet's BIP39 passphrase, which is not printed."
        if ctx.opened_with_passphrase
        else ""
    )
    if progress.reveal_txid is not None:
        return (
            f"The reveal {progress.reveal_txid} of the commit {txid}:{pending.commit_vout} was broadcast and has not "
            f"been seen to confirm. The commit's record is kept in {shown_dir} until it does. Do not re-run the mint "
            f"command. Run `{resume}`: it finds the reveal, waits for it to confirm and deletes the record — or, "
            f"if the reveal was dropped from the mempool, reveals the commit again.{passphrase_note}"
        )
    holds = (
        f"holds {pending.commit_value:,} photons ({pending.carrier_value:,} for the NFT carrier; the rest pays the "
        "reveal's miner fee and comes back as change)"
    )
    if progress.server_value is not None:
        # The server disputes the record's number; say what each side says, and assert neither.
        opening = (
            f"The commit {txid}:{pending.commit_vout} was broadcast. Its record says it {holds}; the server lists "
            f"{progress.server_value:,} photons."
        )
    else:
        opening = f"The commit {txid}:{pending.commit_vout} was broadcast and {holds}."
    lines = [
        f"{opening} Only a reveal of its exact envelope can spend it, and its record is saved in {shown_dir}.",
        f"Do not re-run the mint command: that commits, and spends, again. To reveal this one, run `{resume}`."
        + passphrase_note,
    ]
    if registered_label is not None and pending.wave_fee == "decline":
        lines.append(
            f"This mint declined the WAVE registration fee for {registered_label}.rxd, and that command keeps "
            "that choice: it reveals without paying."
        )
    elif registered_label is not None:
        lines.append(
            f"resume-mint asks an indexer whether {registered_label}.rxd is still free and pays the registration "
            f"fee from a wallet input only if it says so. If the name is taken, reveal without the fee: "
            f"`{_resume_command(ctx, pending, allow_unverified=allow_unverified, decline=True)}` — the reveal is "
            f"then a duplicate claim the indexer does not register, and the carrier and the change come back to "
            f'this wallet. A "taken" answer is one server\'s: if the name is in fact free, that reveal registers '
            f"it without paying the fee."
        )
    lines.append(
        "If the commit never confirms and leaves the mempool, its inputs were never spent and the record can "
        "be deleted."
    )
    return " ".join(lines)


def _json_recovery_document(
    ctx: CliContext,
    pending: PendingMint,
    store_dir: Path,
    progress: _Progress,
    *,
    allow_unverified: bool,
    status: str = "commit_broadcast_reveal_not_done",
) -> dict[str, Any]:
    registered_label = wave_registered_label(pending.cbor_bytes)
    return {
        "status": "reveal_broadcast_not_confirmed" if progress.reveal_txid is not None else status,
        "commit_txid": pending.commit_txid,
        "commit_vout": pending.commit_vout,
        "commit_value": pending.commit_value,
        "reveal_txid": progress.reveal_txid,
        # A path a program opens, so it stays absolute; `recover` is for a shell, which expands `~`.
        "pending_record": str(store_dir / f"{pending.commit_txid}.json"),
        "wave_name": None if registered_label is None else f"{registered_label}.rxd",
        "wave_fee": pending.wave_fee,
        "recover": _resume_command(ctx, pending, allow_unverified=allow_unverified),
        "recover_without_wave_fee": (
            _resume_command(ctx, pending, allow_unverified=allow_unverified, decline=True)
            if pending.wave_fee == "pay"
            else None
        ),
    }


# ---------------------------------------------------------------------------
# The reveal, shared by mint-nft and resume-mint
# ---------------------------------------------------------------------------


async def _utxo_is_unspent(client: ElectrumXClient, funding: _FeeFunding) -> bool:
    """Whether ``funding`` is still in its address's unspent set, as the server reports it."""
    from ..network.electrumx import script_hash_for_address

    utxos = await client.get_utxos(script_hash_for_address(funding.address))
    return any(u.tx_hash == funding.txid and u.tx_pos == funding.vout for u in utxos)


def _reveal_fee_rate(pending: PendingMint, store_dir: Path) -> int:
    """The record's fee rate, judged from both ends before it is spent (M1).

    A record's ``fee_rate`` is read off disk, and ``mint-nft`` only ever writes the configured
    rate, which :func:`~pyrxd.cli.config.validated_fee_rate` has held to the relay floor and
    the 10x ceiling. Anything else was edited or written by other code, and signing at it is
    how a record carrying ``10_000_000`` (the per-kB constant) paid 58 RXD to miners. The same
    bounds :class:`~pyrxd.glyph.mint.GlyphMinter` applies to its records.
    """
    try:
        return assert_fee_rate_clears_relay_floor(pending.fee_rate, what="glyph reveal", error_type=ValidationError)
    except ValidationError as exc:
        floor = relay_floor_photons_per_byte()
        raise _RecordRefused(
            f"the commit's record asks for a reveal fee rate of {pending.fee_rate:,} photons/byte — refusing "
            "to sign at it",
            cause=(
                f"Radiant relays at {floor:,} photons/byte, and resume-mint signs at no more than "
                f"{floor * MAX_FEE_OVERPAY_MULTIPLE:,} ({MAX_FEE_OVERPAY_MULTIPLE}x): below the floor the reveal "
                "would not relay, above the ceiling it would overpay with no way to recover the difference"
            ),
            fix=(
                f"glyph mint-nft writes the configured fee_rate, so the fee_rate in "
                f"{_shown_path(store_dir / (pending.commit_txid + '.json'))} was changed after the mint. Put back "
                "the rate "
                "the mint used (the fee_rate in your config; 10000 by default). Nothing was broadcast."
            ),
        ) from exc


async def _reveal_committed(
    ctx: CliContext,
    client: ElectrumXClient,
    pending: PendingMint,
    *,
    key: PrivateKey,
    pay_registration_fee: bool,
    registration_treasury: str | None,
    allow_unverified_wave_name: bool,
    fee_funding: _FeeFunding | None,
    store: JsonFilePendingStore,
    progress: _Progress,
) -> dict[str, Any]:
    """Reveal a CONFIRMED commit. Every refusal here happens before anything is broadcast.

    The record's fee rate is judged first (:func:`_reveal_fee_rate`). For a claim that
    registers a WAVE name and pays for it: the indexer must still say the name is free (asked
    again now, since the commit, and once more AFTER the confirmation prompt, immediately before
    the broadcast — a prompt can wait for as long as the operator reads it, and a name taken in
    that time would be paid for as a duplicate), and the wallet input that funds the fee must
    still be unspent. The built reveal is gated before signing, and again after, and only then
    shown for confirmation and broadcast. The commit's record is deleted only once the reveal
    CONFIRMS: a mempool accept is not a block, and a reveal that is dropped needs the record to
    be rebuilt (the same reasoning as :class:`~pyrxd.glyph.mint.GlyphMinter`).
    """
    resume_unverified = _resume_command(ctx, pending, allow_unverified=True)
    fee_rate = _reveal_fee_rate(pending, store.directory)
    builder = GlyphBuilder()
    scripts = builder.prepare_reveal(
        RevealParams(
            commit_txid=pending.commit_txid,
            commit_vout=pending.commit_vout,
            commit_value=pending.commit_value,
            cbor_bytes=pending.cbor_bytes,
            owner_pkh=Hex20(pending.owner_pkh),
            is_nft=pending.is_nft,
            pay_registration_fee=pay_registration_fee,
            registration_treasury=registration_treasury,
        )
    )
    fee = scripts.registration_fee_output
    registered_label = wave_registered_label(pending.cbor_bytes)
    name_status: str | None = None
    if fee is not None:
        name_status = await _require_wave_name_free_before_reveal(
            client, fee.label, allow_unverified=allow_unverified_wave_name, resume_unverified=resume_unverified
        )
        if fee_funding is None:
            raise _RevealRefused(
                f"no plain-RXD wallet UTXO holds the {format_rxd(fee.value)} WAVE registration fee for {fee.label}.rxd",
                cause="the fee is paid from a wallet input, never from the commit",
            )
        if not await _utxo_is_unspent(client, fee_funding):
            raise _RevealRefused(
                f"the wallet UTXO chosen to pay the WAVE fee ({fee_funding.txid}:{fee_funding.vout}) is spent or "
                "not visible — NOT paying",
                cause="the server no longer lists it as unspent for its address",
            )
    change_locking = P2PKH().lock(pending.funding_address)
    reveal_tx = _build_reveal_tx(
        commit_txid=pending.commit_txid,
        commit_value=pending.commit_value,
        commit_script=pending.commit_script,
        reveal_locking_script=scripts.locking_script,  # type: ignore[arg-type]
        carrier_value=pending.carrier_value,
        change_locking=change_locking,
        funding_key=key,
        scriptsig_suffix=scripts.scriptsig_suffix,
        registration_fee=fee,
        fee_funding=fee_funding if fee is not None else None,
    )
    statement = _fee_statement(fee, registered_label)
    try:
        measured = assert_reveal_balances(
            reveal_tx, fee_rate=fee_rate, cbor_bytes_len=len(pending.cbor_bytes), registration_fee=statement
        )
    except (InsufficientFundsError, ValidationError) as exc:
        raise _RevealRefused(
            "the reveal does not balance — NOT broadcasting it",
            cause=str(exc),
            fix=(
                "resume-mint builds the same reveal from the same record, so first fix what the cause names: fund "
                "the wallet if its input is short, or, if the record's fee_rate was changed after the mint, put "
                "back the rate the mint used"
            ),
        ) from exc
    reveal_tx.fee(SatoshisPerKilobyte(fee_rate * 1000))
    if not any(o.change for o in reveal_tx.outputs):
        raise _RevealRefused("the reveal lost its change output when fee'd — NOT broadcasting it")
    reveal_tx.sign()
    try:
        assert_reveal_balances(
            reveal_tx, fee_rate=fee_rate, cbor_bytes_len=len(pending.cbor_bytes), registration_fee=statement
        )
    except (InsufficientFundsError, ValidationError) as exc:
        raise _RevealRefused("the signed reveal does not pay its way — NOT broadcasting it", cause=str(exc)) from exc
    reveal_hex = reveal_tx.serialize()

    change_value = sum(o.satoshis for o in reveal_tx.outputs if o.change)
    reveal_lines = [
        f"commit:        {pending.commit_txid}:{pending.commit_vout}  ({pending.commit_value:,} photons)",
        f"nft to:        {Hex20(pending.owner_pkh).hex()}  ({pending.carrier_value:,}-photon carrier)",
    ]
    if fee is not None and fee_funding is not None:
        reveal_lines += [
            f"fee input:     {fee_funding.txid}:{fee_funding.vout}  ({fee_funding.value:,} photons, {fee_funding.address})",
            f"WAVE fee:      {fee.describe()} (vout {_REVEAL_FEE_VOUT})"
            + ("" if fee.is_published_treasury else "  (NOT the published WAVE treasury)"),
            f"name free:     {name_status}",
        ]
    elif registered_label is not None:
        reveal_lines.append(f"WAVE fee:      NOT PAID for {registered_label}.rxd (--no-wave-registration-fee)")
    reveal_lines += [
        f"miner fee:     {reveal_tx.get_fee():,} photons ({len(reveal_hex):,} B @ {fee_rate:,}/B, from the commit)",
        f"change:        {change_value:,} photons back to {pending.funding_address}",
    ]
    try:
        _confirm_or_abort(ctx, [_BroadcastSummary(title="Reveal transaction", lines=reveal_lines)])
    except UserError as exc:
        # Its own fix says "re-run with the inputs you want", which after a commit would spend
        # again. The reveal was not broadcast; the recovery names the commit.
        raise _RevealRefused(f"the reveal was not broadcast: {exc.message}", cause=exc.cause) from exc
    if fee is not None:
        # Asked AGAIN, here and nowhere later: the prompt above waits on a person, and a name
        # registered by someone else in that time would take the fee for a duplicate. The same
        # refusal as before the prompt; nothing has been broadcast yet.
        name_status = await _require_wave_name_free_before_reveal(
            client, fee.label, allow_unverified=allow_unverified_wave_name, resume_unverified=resume_unverified
        )
    _echoed_reveal = await client.broadcast(reveal_hex)
    reveal_txid = _confirmed_reveal_txid(reveal_hex, _echoed_reveal)
    progress.reveal_txid = str(reveal_txid)
    if ctx.output_mode == "human":
        click.echo(f"\nreveal broadcast: {reveal_txid}")
        click.echo("waiting for it to confirm before deleting the commit's record...")
    await _await_reveal(ctx, client, str(reveal_txid))
    store.delete(pending.commit_txid)
    # The genesis ref is the COMMIT outpoint, not the reveal txid: prepare_reveal
    # embeds GlyphRef(commit_txid, commit_vout) into the reveal's locking script
    # (glyph/builder.py), and that is what extract_ref_from_{nft,ft}_script reads
    # back — so it is what `transfer-nft` / `transfer-ft` match on.
    ref = GlyphRef(txid=Txid(pending.commit_txid), vout=pending.commit_vout)
    result: dict[str, object] = {
        "commit_txid": pending.commit_txid,
        "reveal_txid": str(reveal_txid),
        "ref": f"{ref.txid}:{ref.vout}",
        "owner_address": pending.funding_address,
        "reveal_fee": measured.fee,
    }
    if registered_label is not None:
        result["wave_registration"] = {
            "name": f"{registered_label}.rxd",
            "fee_paid": fee is not None,
            "fee": None if fee is None else fee.to_dict(),
            "fee_vout": None if fee is None else _REVEAL_FEE_VOUT,
            "fee_input": None if fee_funding is None or fee is None else f"{fee_funding.txid}:{fee_funding.vout}",
            "name_available": name_status,
        }
    return result


async def _await_reveal(ctx: CliContext, client: ElectrumXClient, reveal_txid: str) -> None:
    """Wait for a broadcast reveal to confirm; a timeout says the reveal, not the commit, is pending."""
    try:
        await wait_for_confirmation(client, reveal_txid, interval_s=_poll_interval_for(ctx))
    except ConfirmationTimeoutError as exc:
        raise NetworkBoundaryError(
            f"the reveal {reveal_txid} was broadcast and has not confirmed yet", cause=str(exc)
        ) from exc


async def _after_commit(
    ctx: CliContext,
    pending: PendingMint,
    store: JsonFilePendingStore,
    step: Callable[[_Progress], Awaitable[dict[str, Any]]],
    *,
    allow_unverified: bool,
) -> dict[str, Any]:
    """Run everything after the commit broadcast so that EVERY exit names the commit and its recovery.

    A refusal or an error keeps its exit code and gains the commit's txid, value, record and
    recovery commands (and in ``--json`` mode the same, as a JSON document on stdout, since
    errors go to stderr). Anything else — a crash, Ctrl-C — prints the recovery to stderr
    before propagating. The record was saved before the commit was broadcast, so it survives
    all of them. The recovery is worked out when the exit happens, so once the reveal is
    broadcast it says so instead of offering to reveal again. ``allow_unverified`` is this
    run's ``--allow-unverified-wave-name``, repeated in the printed command.
    """
    progress = _Progress()

    def _recovery() -> str:
        return _commit_recovery(ctx, pending, store.directory, progress, allow_unverified=allow_unverified)

    def _document() -> None:
        if ctx.output_mode == "json":
            doc = _json_recovery_document(ctx, pending, store.directory, progress, allow_unverified=allow_unverified)
            click.echo(emit(doc, mode="json"))

    try:
        return await step(progress)
    except (_NothingToRecover, _RecordRefused):
        raise
    except _Inconclusive:
        _document()
        raise
    except CliError as exc:
        _document()
        # Keep what the error itself advises (a timeout's "it may still confirm", a mismatched
        # echo's "check it on an explorer"), then the recovery. A refusal has no advice of its own.
        exc.fix = _recovery() if not exc.fix else f"{exc.fix} — {_recovery()}"
        raise
    except PolicyRejection as exc:
        # The node answered, and said no: nothing was spent by the reveal it refused.
        _document()
        raise NetworkBoundaryError(
            "the node rejected the reveal transaction — nothing was spent by it", cause=str(exc), fix=_recovery()
        ) from exc
    except NetworkError as exc:
        _document()
        raise NetworkBoundaryError(
            "a server stopped answering after the commit was broadcast", cause=str(exc), fix=_recovery()
        ) from exc
    except BaseException:
        click.echo(f"\ninterrupted after the commit was broadcast. {_recovery()}", err=True)
        raise


async def _mint_nft_inner(
    ctx: CliContext,
    wallet: HdWallet,
    metadata: GlyphMetadata,
    client: ElectrumXClient,
    *,
    pay_registration_fee: bool = True,
    registration_treasury: str | None = None,
    allow_unverified_wave_name: bool = False,
    ignore_pending_mint: bool = False,
) -> dict:
    """Heavy lifting for `glyph mint-nft`. Returns a result dict.

    A metadata file that registers a WAVE name: the indexer must say the name is free (asked
    before the commit, before the reveal's confirmation and again right before its broadcast),
    and the reveal pays the registration fee from a wallet input — the commit's own change —
    unless ``pay_registration_fee`` is ``False``. Nothing for the fee goes in the commit output.
    And no unrevealed commit for the same name may be waiting in this wallet's pending-mints/
    (``ignore_pending_mint`` overrides): a second commit spends again, and at most one of the
    two claims can register the name.
    """
    fee_rate = ctx.fee_rate
    # C-1: the reveal's scriptSig carries the whole CBOR payload, so the reveal fee
    # scales with metadata size and is paid entirely out of the commit output. Size
    # the commit from the real estimate instead of the old flat 5,000,000, which at
    # 10,000 photons/byte only covered ~230 bytes of CBOR. For a WAVE registration the
    # estimate also sizes the wallet input that funds the fee and the fee's output; the
    # fee's VALUE is not the commit's. Worked out before the wallet is scanned, so a network
    # with no treasury is refused before anything else happens.
    try:
        reveal_estimate = estimate_reveal_fee_for_metadata(
            metadata,
            fee_rate=fee_rate,
            pay_registration_fee=pay_registration_fee,
            registration_treasury=registration_treasury,
        )
    except ValidationError as exc:
        raise UserError("could not size the reveal", cause=str(exc)) from exc
    registered_label = wave_registered_label(encode_payload(metadata)[0])
    registration_fee = reveal_estimate.registration_fee
    if registration_fee is not None and registration_treasury is None and ctx.network != Network.MAINNET.value:
        raise UserError(
            f"no WAVE treasury is published for {ctx.network}",
            cause=(
                f"this metadata registers {registered_label}.rxd, and the WAVE registration fee is paid by "
                f"default; the only published treasury, {WAVE_TREASURY_ADDRESS}, is a mainnet address"
            ),
            fix=(
                f"pass --wave-treasury <a {ctx.network} address> to pay one you choose, or "
                "--no-wave-registration-fee to register without paying"
            ),
        )
    name_status: str | None = None
    if registered_label is not None:
        if not ignore_pending_mint:
            _refuse_a_second_commit_for(ctx, registered_label, allow_unverified=allow_unverified_wave_name)
        name_status = await _require_wave_name_free_before_commit(
            client, registered_label, allow_unverified=allow_unverified_wave_name
        )

    # 1) Pick a funding UTXO.
    builder = GlyphBuilder()
    triples = await wallet.collect_spendable(client)
    if not triples:
        raise UserError(
            "no spendable UTXOs in the wallet",
            cause="collect_spendable returned an empty list",
            fix="fund the wallet, or run `pyrxd balance --refresh` to discover used addresses",
        )

    # The NFT's carrier value on the reveal. Same number as
    # ``pyrxd.glyph.mint.NFT_CARRIER_VALUE``, which derives from the same constant.
    # It is a pyrxd convention, not a chain minimum: Radiant would carry the NFT on
    # 1 photon (`GetDustThreshold` returns 1) — dMint contracts do exactly that.
    carrier_value = DUST_THRESHOLD_PHOTONS
    commit_value = _commit_value_for_reveal(carrier_value, reveal_estimate)
    commit_fee_estimate = 300 * fee_rate  # ~300-byte commit
    # The reveal's miner fee comes out of commit_value (sized above), so the funding UTXO
    # needs the commit value plus the commit's own fee; the extra carrier_value is slack so a
    # UTXO is not selected on an exact tie. A WAVE fee is paid by the reveal from the commit's
    # CHANGE, so the same UTXO must also leave at least the fee in change — it stays in the
    # wallet until the reveal that registers the name spends it.
    total_required = commit_value + commit_fee_estimate + carrier_value + reveal_estimate.required_funding_value

    # Token-free: the on-chain script is checked to be a bare P2PKH, so a UTXO carrying a
    # Glyph token is never spent as funding (which would burn the token), and the commit's
    # change — which pays the WAVE fee — is plain RXD by construction.
    funding = await lib_find_plain_rxd_utxo(triples, client, exclude=set(), needed=total_required)
    if funding is None:
        includes = (
            ""
            if registration_fee is None
            else (
                f", including the {format_rxd(registration_fee.value)} WAVE registration fee for "
                f"{registration_fee.label}.rxd, which the reveal pays from this UTXO's change"
            )
        )
        largest = max(t[0].value for t in triples)
        raise UserError(
            "no single UTXO is large enough to fund the mint",
            cause=(
                f"need ≥ {total_required:,} photons in one plain-RXD (token-free) UTXO{includes}; "
                f"largest in the wallet is {largest:,}"
            ),
            fix="consolidate UTXOs first, or fund the wallet from a single source",
        )
    funding_utxo, funding_addr, funding_key = funding
    funding_pkh = Hex20(funding_key.public_key().hash160())

    # 2) Build commit script + tx.
    commit_result = builder.prepare_commit(
        CommitParams(
            metadata=metadata,
            owner_pkh=funding_pkh,
            change_pkh=funding_pkh,
            funding_satoshis=funding_utxo.value,
        )
    )

    # Build the commit input + outputs.
    locking = P2PKH().lock(funding_addr)
    # Pad the source shim so the funding output sits at its real vout (the largest
    # wallet UTXO is often change at vout != 0; TransactionInput + fee() index it).
    src_outs = [TransactionOutput(Script(b""), 0) for _ in range(funding_utxo.tx_pos)]
    src_outs.append(TransactionOutput(locking, funding_utxo.value))
    src_tx = Transaction(tx_inputs=[], tx_outputs=src_outs)
    src_tx.txid = lambda: funding_utxo.tx_hash  # type: ignore[method-assign]

    commit_input = TransactionInput(
        source_transaction=src_tx,
        source_txid=funding_utxo.tx_hash,
        source_output_index=funding_utxo.tx_pos,
        unlocking_script_template=P2PKH().unlock(funding_key),
    )
    commit_input.satoshis = funding_utxo.value
    commit_input.locking_script = locking

    # change=True lets fee() size the fee from the real length and fill the change;
    # a manual change output + fee() ZeroDivisions when there are no change=True outputs.
    commit_outputs = [
        TransactionOutput(Script(commit_result.commit_script), commit_value),
        TransactionOutput(locking, 0, change=True),
    ]
    commit_tx = Transaction(tx_inputs=[commit_input], tx_outputs=commit_outputs)
    commit_tx.fee(SatoshisPerKilobyte(fee_rate * 1000))
    commit_tx.sign()
    commit_hex = commit_tx.serialize()
    local_commit_txid = str(commit_tx.txid())

    # The commit's change (vout 1) is the wallet input that pays a WAVE fee. Chosen HERE,
    # before anything is broadcast, and re-checked unspent just before the reveal. Whether it
    # is enough is the dry-run gate's question below (the reveal must balance with the fee
    # input at this value); a separate "change below the fee" check stood here and could not
    # fire, because total_required already reserves required_funding_value in the change.
    fee_funding: _FeeFunding | None = None
    if registration_fee is not None:
        fee_funding = _FeeFunding(
            txid=local_commit_txid,
            vout=1,
            value=sum(o.satoshis for o in commit_tx.outputs[1:] if o.change),
            address=funding_addr,
            key=funding_key,
        )

    # C-1 gate: the last point at which nothing has been spent. Once the commit is
    # broadcast an unfundable reveal strands the commit output permanently. Build the
    # reveal now, against a placeholder commit txid, and MEASURE it — an independent
    # check on the estimate that sized commit_value above.
    cbor_bytes = commit_result.cbor_bytes
    dry_run_scripts = builder.prepare_reveal(
        RevealParams(
            commit_txid=_PLACEHOLDER_COMMIT_TXID,
            commit_vout=0,
            commit_value=commit_value,
            cbor_bytes=cbor_bytes,
            owner_pkh=funding_pkh,
            is_nft=True,
            pay_registration_fee=pay_registration_fee,
            registration_treasury=registration_treasury,
        )
    )
    # The fee the estimate sized the reveal for must be the fee the reveal pays. Both come
    # from wave_registration_fee_for with the same arguments, so a difference is a bug here.
    if dry_run_scripts.registration_fee_output != registration_fee:
        raise UserError(
            "internal error: the reveal's WAVE registration fee is not the one the estimate sized",
            cause=f"estimate {registration_fee!r}, reveal {dry_run_scripts.registration_fee_output!r}",
        )
    dry_run_reveal = _build_reveal_tx(
        commit_txid=_PLACEHOLDER_COMMIT_TXID,
        commit_value=commit_value,
        commit_script=commit_result.commit_script,
        reveal_locking_script=dry_run_scripts.locking_script,  # type: ignore[arg-type]
        carrier_value=carrier_value,
        change_locking=locking,
        funding_key=funding_key,
        scriptsig_suffix=dry_run_scripts.scriptsig_suffix,
        registration_fee=dry_run_scripts.registration_fee_output,
        fee_funding=fee_funding,
    )
    measured = _assert_reveal_is_fundable(
        commit_value,
        carrier_value,
        dry_run_reveal,
        fee_rate,
        len(cbor_bytes),
        registration_fee=_fee_statement(dry_run_scripts.registration_fee_output, registered_label),
    )

    commit_fee = commit_tx.get_fee()
    total_cost = commit_fee + carrier_value + measured.fee + reveal_estimate.registration_fee_value
    sections = [
        _metadata_summary(metadata),
        *_wave_registration_summary(
            registered_label, registration_fee, name_status=name_status, fee_funding=fee_funding
        ),
        _BroadcastSummary(
            title="Commit transaction",
            lines=[
                f"funding addr:  {funding_addr}",
                f"funding utxo:  {funding_utxo.tx_hash}:{funding_utxo.tx_pos}",
                f"funding value: {funding_utxo.value:,} photons",
                f"commit value:  {commit_value:,} photons (the NFT carrier + the reveal's miner fee)",
                f"owner_pkh:     {funding_pkh.hex()}  (this wallet)",
                f"commit fee:    {commit_fee:,} photons",
                f"reveal fee:    {measured.fee:,} photons "
                f"({measured.size_bytes:,} B @ {fee_rate:,}/B, paid from commit value)",
                f"total cost:    {format_photons(total_cost)} (commit fee + {carrier_value}-photon carrier + "
                "reveal fee" + (" + WAVE registration fee)" if registration_fee is not None else ")"),
                f"network:       {ctx.network}",
            ],
        ),
    ]
    _confirm_or_abort(ctx, sections)

    # The record that lets this commit be revealed after a crash, a timeout or a refusal, saved
    # and read back BEFORE the commit is broadcast. GlyphMinter keeps records the same way. It
    # keeps the WAVE fee decision too, so resume-mint does what this mint agreed to: a declined
    # fee stays declined, a named treasury stays named.
    pending = PendingMint(
        commit_txid=local_commit_txid,
        commit_vout=0,
        commit_value=commit_tx.outputs[0].satoshis,
        commit_script=commit_result.commit_script,
        cbor_bytes=cbor_bytes,
        owner_pkh=bytes(funding_pkh),
        is_nft=True,
        carrier_value=carrier_value,
        fee_rate=fee_rate,
        funding_address=funding_addr,
        wave_fee=None if registered_label is None else ("pay" if registration_fee is not None else "decline"),
        wave_treasury=registration_treasury if registration_fee is not None else None,
    )
    store = _pending_store(ctx)
    store.save(pending)

    try:
        _echoed_commit = await client.broadcast(commit_hex)
    except BaseException as exc:
        # A failed or interrupted broadcast is ambiguous: a server can drop the connection after
        # relaying, and Ctrl-C can land after the bytes left. So this says what to look for, and
        # both answers, rather than "check the server" — which invites a second commit that
        # spends again.
        _commit_broadcast_uncertain(ctx, pending, store, exc, allow_unverified=allow_unverified_wave_name)
        raise

    async def _step(progress: _Progress) -> dict[str, Any]:
        commit_txid = _local_commit_txid(commit_hex, _echoed_commit)
        if ctx.output_mode == "human":
            click.echo(f"\ncommit broadcast: {commit_txid}")
            click.echo(f"pending record:   {_shown_path(store.directory / (commit_txid + '.json'))}")
            click.echo("waiting for confirmation (this can take 10+ minutes)...")
        await _wait_for_tx(client, str(commit_txid), interval_s=_poll_interval_for(ctx))
        return await _reveal_committed(
            ctx,
            client,
            pending,
            key=funding_key,
            pay_registration_fee=pay_registration_fee,
            registration_treasury=registration_treasury,
            allow_unverified_wave_name=allow_unverified_wave_name,
            fee_funding=fee_funding,
            store=store,
            progress=progress,
        )

    return await _after_commit(ctx, pending, store, _step, allow_unverified=allow_unverified_wave_name)


def _commit_broadcast_uncertain(
    ctx: CliContext, pending: PendingMint, store: JsonFilePendingStore, exc: BaseException, *, allow_unverified: bool
) -> None:
    """Say what is true when the commit broadcast did not return: it may have relayed.

    A :class:`NetworkError` becomes a :class:`NetworkBoundaryError` carrying both answers (and,
    in ``--json`` mode, a JSON document on stdout). Anything else — Ctrl-C, a crash — prints
    the same text to stderr and lets the caller re-raise it. The record exists already.
    """
    record = _shown_path(store.directory / f"{pending.commit_txid}.json")
    recovery = _commit_recovery(ctx, pending, store.directory, _Progress(), allow_unverified=allow_unverified)
    fix = (
        f"look up {pending.commit_txid} on a block explorer before running anything else. If it is there: "
        f"{recovery} If it never appears, nothing was spent: delete {record} and mint again."
    )
    if not isinstance(exc, NetworkError):
        click.echo(
            f"\ninterrupted while the commit was being broadcast: it may or may not have reached the network. {fix}",
            err=True,
        )
        return
    if ctx.output_mode == "json":
        doc = _json_recovery_document(
            ctx,
            pending,
            store.directory,
            _Progress(),
            allow_unverified=allow_unverified,
            status="commit_broadcast_failed_may_have_relayed",
        )
        click.echo(emit(doc, mode="json"))
    headline = (
        "the node rejected the commit broadcast"
        if isinstance(exc, PolicyRejection)
        else "the commit broadcast failed, and the commit may or may not have reached the network"
    )
    raise NetworkBoundaryError(headline, cause=str(exc), fix=fix) from exc


async def _find_commit_spend(client: ElectrumXClient, pending: PendingMint) -> tuple[str, int] | None:
    """POSITIVE evidence that the commit output is spent: ``(spending txid, height)``, or ``None``.

    Reads the commit script's history and returns the transaction that has an input spending
    ``commit_txid:commit_vout`` AND pushing, in that input, the record's exact envelope (the
    ``gly`` marker and ``pending.cbor_bytes``). Two checks, because the answer decides whether
    the record — the one way to rebuild the reveal — is deleted (#736):

    - the transaction is re-hashed locally, so a server cannot hand back one transaction's bytes
      under another's txid (and height);
    - its spending input must push the committed payload. The commit output is
      ``OP_HASH256 <payload hash> OP_EQUALVERIFY …``, so a spend that did not push those bytes
      could not be valid, and a server cannot invent one that does without knowing the payload:
      it learns it from a real reveal of this commit, or has to reconstruct it and match the
      commit's payload hash. Re-hashing proves the bytes match the txid, not that the
      transaction is valid or was mined; this is the check that ties it to THIS commit.

    Neither check verifies the spend's signature, and the height is the server's word, as it is
    everywhere else in the CLI. What they stop is the cheap lie (#736): a transaction invented
    from nothing, with any unlocking script, that hashes to its own txid.

    A height of 0 or less means it is still in the mempool. ``None`` means no such transaction
    was found — which is NOT evidence that the commit is unspent either.
    """
    from ..glyph.inspector import GlyphInspector
    from ..network.electrumx import script_hash_for_script

    inspector = GlyphInspector()
    history = await client.get_history(script_hash_for_script(pending.commit_script))
    for item in history:
        txid = str(item["tx_hash"])
        if txid == pending.commit_txid:
            continue
        tx = Transaction.from_hex(bytes(await client.get_transaction(Txid(txid))))
        if tx is None or str(tx.txid()) != txid:
            continue
        for i in tx.inputs:
            if i.source_txid != pending.commit_txid or i.source_output_index != pending.commit_vout:
                continue
            scriptsig = i.unlocking_script.serialize() if i.unlocking_script is not None else b""
            if inspector.extract_reveal_cbor(scriptsig) == pending.cbor_bytes:
                return txid, int(item["height"])
    return None


def _refuse_record(store: JsonFilePendingStore, commit_txid: str, field: str, detail: str) -> _RecordRefused:
    return _RecordRefused(
        f"the record for {commit_txid} does not match: {field}",
        cause=detail,
        fix=(
            f"the record in {_shown_path(store.directory / (commit_txid + '.json'))} is not the one glyph mint-nft "
            "wrote for this commit, or this is not the wallet that made it. Nothing was broadcast."
        ),
    )


class _ValueDisputed(UserError):
    """The server lists the commit output at a value its record does not say. Either may be wrong.

    Not a :class:`_RecordRefused`: the record is not known to be at fault, so the recovery is
    kept (panel E-L2). :func:`_after_commit` adds it after this error's own fix.
    """


def _resume_fee_choice(
    ctx: CliContext,
    pending: PendingMint,
    registered_label: str | None,
    flag: bool | None,
    treasury: str | None,
    *,
    allow_unverified: bool,
) -> tuple[bool, str | None]:
    """``(pay, treasury)`` for this reveal: the mint's recorded choice, never a guess (M2).

    The recorded choice wins. A flag may only DECLINE a recorded payment — the recovery for a
    name that was taken after the commit, which spends nothing the mint did not agree to. A
    flag that would pay what the mint declined, or pay a different treasury, is refused. A
    record with no choice (not written by ``glyph mint-nft``) needs the flag said out loud.

    A recorded treasury that is NOT the published one is paid only when this command line names
    it too (panel D-L1). The record is a file anyone with write access to the wallet directory
    can change, and it is read with the same suspicion as its ``fee_rate`` (M1): taken on its
    own word, an edited ``wave_treasury`` sent the whole fee to another address. The command the
    mint printed already carries ``--wave-treasury``, so the honest path is unchanged. Naming
    the published treasury is the same choice as naming none (D-L3).
    """
    if registered_label is None:
        return False, None
    stored = pending.wave_fee
    if stored is None:
        if flag is None:
            raise UserError(
                f"the record for {pending.commit_txid} registers {registered_label}.rxd but does not say whether "
                "the WAVE registration fee is paid",
                cause="it was not written by glyph mint-nft, which always records the choice",
                fix="say which: --wave-registration-fee or --no-wave-registration-fee",
            )
        return flag, treasury
    if stored == "decline":
        if flag is True or treasury is not None:
            raise UserError(
                f"the mint declined the WAVE registration fee for {registered_label}.rxd, and resume-mint will not "
                "pay what the mint declined",
                cause="the record says --no-wave-registration-fee; this run says "
                + ("--wave-registration-fee" if flag is True else f"--wave-treasury {treasury}"),
                fix=(
                    f"run `{_resume_command(ctx, pending, allow_unverified=allow_unverified)}`, which reveals "
                    "without paying, as the mint chose"
                ),
            )
        return False, None
    recorded = pending.wave_treasury or WAVE_TREASURY_ADDRESS
    # Either refusal below may be facing an edited record, so neither tells the operator to
    # pay the recorded address: it says which command pays it, and which pays nothing.
    choose = (
        f"If {recorded} is where the mint was to pay the fee, run "
        f"`{_resume_command(ctx, pending, allow_unverified=allow_unverified)}` (the command the mint printed). If it "
        "is not, the record was changed after the mint: do not pay it. "
        f"`{_resume_command(ctx, pending, allow_unverified=allow_unverified, decline=True)}` reveals without paying "
        "(if the name is free it still registers, unpaid). Nothing was broadcast."
    )
    if treasury is not None and treasury != recorded:
        raise UserError(
            "--wave-treasury is not the treasury the mint chose",
            cause=f"the record pays {recorded}; this run names {treasury}",
            fix=choose,
        )
    if flag is False:
        # The recovery for a name taken after the commit: nothing is paid, so no treasury.
        return False, None
    if pending.wave_treasury is not None and treasury is None:
        raise UserError(
            f"the record pays the WAVE registration fee to {pending.wave_treasury}, which is NOT the published "
            "WAVE treasury — resume-mint pays it only if this command names it too",
            cause=(
                f"the record keeps the address the mint named with --wave-treasury; the published treasury is "
                f"{WAVE_TREASURY_ADDRESS}. A record can be changed after the mint, so its word alone does not "
                "choose where the fee goes"
            ),
            fix=choose,
        )
    return True, pending.wave_treasury


async def _resume_mint_inner(
    ctx: CliContext,
    wallet: HdWallet,
    client: ElectrumXClient,
    commit_txid: str,
    *,
    pay_registration_fee: bool | None,
    registration_treasury: str | None,
    allow_unverified_wave_name: bool,
) -> dict[str, Any]:
    """Heavy lifting for `glyph resume-mint`: reveal a commit from its saved record.

    The record is checked before anything else: it must be the record for THIS txid, its
    commit script must re-derive from its payload and this wallet's key, the NFT must go to
    this wallet, and (once the commit is confirmed) the server must list the commit output at
    the value the record says. The record is deleted only on POSITIVE evidence that the commit
    is spent — a transaction whose input spends it, confirmed — never because the server
    lists nothing.
    """
    from ..glyph.mint import GlyphMinter, PendingMintNotFound
    from ..network.electrumx import script_hash_for_script

    store = _pending_store(ctx)
    try:
        pending = store.load(commit_txid)
    except PendingMintNotFound as exc:
        listed = ", ".join(store.list_pending()) or "none"
        raise UserError(
            f"no pending mint recorded for {commit_txid}",
            cause=f"looked in {_shown_path(store.directory)}; records there: {listed}",
            fix="pass the commit txid mint-nft printed, with the same --wallet",
        ) from exc
    if pending.commit_txid != commit_txid:
        raise _refuse_record(
            store, commit_txid, "commit_txid", f"the file for {commit_txid} holds {pending.commit_txid}"
        )
    registered_label = wave_registered_label(pending.cbor_bytes)
    try:
        key = wallet.privkey_for_address(pending.funding_address)
        # Re-derive the commit script from the stored payload and this key: the reveal can
        # only spend the commit if both are what the commit was built from.
        GlyphMinter._assert_payload_still_matches(pending, key)
    except ValidationError as exc:
        raise UserError("this wallet cannot reveal that commit", cause=str(exc)) from exc
    if bytes(pending.owner_pkh) != bytes(key.public_key().hash160()):
        # mint-nft mints to the wallet that pays. Revealing to another owner would mint the NFT
        # to someone else while this wallet pays the fee.
        raise _refuse_record(
            store,
            commit_txid,
            "owner_pkh",
            f"the record mints to {bytes(pending.owner_pkh).hex()}, not to this wallet's "
            f"{bytes(key.public_key().hash160()).hex()}",
        )
    pay, treasury = _resume_fee_choice(
        ctx,
        pending,
        registered_label,
        pay_registration_fee,
        registration_treasury,
        allow_unverified=allow_unverified_wave_name,
    )
    if treasury is not None:
        _require_address_on_network(ctx, treasury, what="the recorded WAVE treasury")
    if pay and registered_label is not None and treasury is None and ctx.network != Network.MAINNET.value:
        raise UserError(
            f"no WAVE treasury is published for {ctx.network}",
            cause=f"this commit registers {registered_label}.rxd and the mint chose to pay the fee",
            fix=f"pass --wave-treasury <a {ctx.network} address>, or --no-wave-registration-fee",
        )

    async def _step(progress: _Progress) -> dict[str, Any]:
        await _wait_for_tx(client, pending.commit_txid, interval_s=_poll_interval_for(ctx))
        listed = [
            u
            for u in await client.get_utxos(script_hash_for_script(pending.commit_script))
            if u.tx_hash == pending.commit_txid and u.tx_pos == pending.commit_vout
        ]
        if not listed:
            spend = await _find_commit_spend(client, pending)
            if spend is None:
                raise _Inconclusive(
                    f"the server lists the commit {pending.commit_txid}:{pending.commit_vout} neither as unspent "
                    "nor as spent — the record is kept",
                    cause="no unspent entry for the commit output, and no transaction in its history spends it",
                    fix=(
                        "run resume-mint again later, or against another server (--electrumx). Delete the record "
                        f"in {_shown_path(store.directory)} only once an explorer shows the commit output spent."
                    ),
                )
            spender, height = spend
            if height <= 0:
                progress.reveal_txid = spender
                await _await_reveal(ctx, client, spender)
            store.delete(pending.commit_txid)
            raise _NothingToRecover(
                f"the commit {pending.commit_txid}:{pending.commit_vout} is already revealed, by {spender}",
                cause=f"{spender} spends the commit output and is confirmed",
                fix=f"nothing to recover; the record in {_shown_path(store.directory)} has been deleted",
            )
        if listed[0].value != pending.commit_value:
            # The signature commits to the value, so signing at either number risks a reveal the
            # node refuses. Which one is wrong cannot be told from here: a server can misreport,
            # and a record can be edited. Nothing is broadcast; the recovery is kept.
            progress.server_value = listed[0].value
            raise _ValueDisputed(
                f"the record and the server disagree about the value of the commit "
                f"{pending.commit_txid}:{pending.commit_vout} — NOT revealing",
                cause=(
                    f"the record says {pending.commit_value:,} photons; the server lists {listed[0].value:,}. "
                    "The record or the server is wrong"
                ),
                fix=(
                    "retry against another server (--electrumx <URL>) or check the commit on a block explorer. If "
                    f"the chain agrees with the server, the record in "
                    f"{_shown_path(store.directory / (commit_txid + '.json'))} was changed after the mint: put back "
                    "the commit_value the mint printed. Nothing was broadcast"
                ),
            )
        fee_funding: _FeeFunding | None = None
        fee = wave_registration_fee_for(pending.cbor_bytes, pay_registration_fee=pay, registration_treasury=treasury)
        if fee is not None:
            triples = await wallet.collect_spendable(client)
            taken = {(pending.commit_txid, pending.commit_vout)}
            found = await lib_find_plain_rxd_utxo(triples, client, exclude=taken, needed=fee.value)
            if found is not None:
                utxo, address, fkey = found
                fee_funding = _FeeFunding(
                    txid=utxo.tx_hash, vout=utxo.tx_pos, value=utxo.value, address=address, key=fkey
                )
        return await _reveal_committed(
            ctx,
            client,
            pending,
            key=key,
            pay_registration_fee=pay,
            registration_treasury=treasury,
            allow_unverified_wave_name=allow_unverified_wave_name,
            fee_funding=fee_funding,
            store=store,
            progress=progress,
        )

    return await _after_commit(ctx, pending, store, _step, allow_unverified=allow_unverified_wave_name)


def _poll_interval_for(ctx: CliContext) -> float:
    """How often to re-ask the node whether a commit has confirmed.

    The default suits a chain whose blocks are minutes apart. A regtest node mines on
    demand — usually in the same script that is waiting — so a 10s poll there means the
    CLI sleeps ten seconds after the block already exists, on every mint, and a developer
    following the quickstart concludes the tool is slow.

    Deliberately derived from the network rather than added as a flag: nothing else about
    the wait is user-tunable, and an argument no caller passes is the stranded escape hatch
    this project has now shipped twice. If a real per-chain knob is wanted it belongs in
    `[networks.<net>]` beside `fee_rate`, not as a one-off option on three commands.
    """
    return 0.25 if ctx.network == "regtest" else DEFAULT_POLL_INTERVAL_S


async def _wait_for_tx(
    client: ElectrumXClient,
    txid: str,
    *,
    timeout_s: float = DEFAULT_CONFIRMATION_TIMEOUT_S,
    interval_s: float = DEFAULT_POLL_INTERVAL_S,
) -> None:
    """CLI wrapper around :func:`pyrxd.network.confirm.wait_for_confirmation`.

    The polling logic itself lives in the library, where both time seams are injected
    so the timeout branch is reachable in a test. All this adds is the click-level
    translation: the library raises ``ConfirmationTimeoutError``; the CLI turns it into
    a ``NetworkBoundaryError`` (exit code 2) with a recovery hint.

    The hint used to read "re-run with ``COMMIT_TXID=<txid>`` to resume reveal". No such
    flag or environment variable exists in this CLI — that spelling comes from the
    standalone ``examples/*.py`` demo scripts, which carry their own hard-coded metadata
    and cannot resume a CLI mint. Since the commit script has no owner-only spend path
    (``OP_HASH256 <payload_hash> OP_EQUALVERIFY`` runs before the P2PKH tail, so the only
    way to spend the output is a reveal pushing byte-identical CBOR), a timeout here can
    strand real value — and sending that user to a flag that does not exist is the worst
    possible answer. The text below names the recovery that actually works.

    It also used to say "Not confirmed: nothing is stranded — re-run the command". A commit
    that has not confirmed yet may still confirm, and a re-run commits and spends again, so
    that was false exactly when it mattered. And it told every WAVE mint to add the
    registration fee on a rebuilt reveal, unconditionally — paying a second fee for a
    duplicate if the name had been registered meanwhile.
    """
    try:
        await wait_for_confirmation(client, txid, timeout_s=timeout_s, interval_s=interval_s)
    except ConfirmationTimeoutError as exc:
        raise NetworkBoundaryError(
            "timed out waiting for confirmation",
            cause=str(exc),
            fix=(
                f"the transaction {txid} was broadcast and has not confirmed yet. It may still confirm, so do "
                "not simply re-run the command: that would commit, and spend, again. Check the txid on a block "
                "explorer. `glyph mint-nft` and `glyph timelock-mint` saved a record of the commit and print, "
                "with this error, the exact `pyrxd glyph resume-mint` command that reveals it once it confirms. "
                "Without that record (`glyph deploy-ft` and `glyph deploy-dmint` keep none), rebuild the reveal "
                "with the SDK — GlyphBuilder.prepare_reveal(RevealParams(commit_txid=<txid>, commit_vout=0, "
                "commit_value=<photons>, cbor_bytes=..., owner_pkh=..., is_nft=...)) with the SAME wallet "
                "and BYTE-IDENTICAL CBOR — that is what the commit output is a hashlock over. For "
                "`glyph mint-nft` the bytes come from re-encoding the SAME unmodified metadata file; for "
                "`glyph timelock-mint` they are also in the file --envelope-out wrote "
                "(a timelocked envelope with --recipient is NOT reproducible from the same inputs — each "
                "wrap draws a fresh ephemeral key and nonce). A WAVE claim: keep the mint's fee choice. If it "
                "declined the fee, build with pay_registration_fee=False. Otherwise pay its "
                "registration_fee_output from a wallet input ONLY if WaveResolver.check_available says the "
                "name is still free; if it is taken, build with pay_registration_fee=False, which reveals a "
                "duplicate the indexer does not register and returns the value. If the commit is never mined "
                "and leaves the mempool, its inputs were never spent. See docs/how-to/troubleshoot-common-errors.md"
            ),
        ) from exc


# ---------------------------------------------------------------------------
# deploy-ft (FT premine)
# ---------------------------------------------------------------------------


@glyph_group.command(name="deploy-ft")
@click.argument("metadata_file", type=click.Path(path_type=Path))
@click.option("--supply", type=int, required=True, help="Total supply (photons; 1 unit = 1 photon).")
@click.option("--treasury", required=True, help="Address to receive the entire supply.")
@click.option("--passphrase/--no-passphrase", default=False)
@click.pass_obj
def deploy_ft_cmd(
    ctx: CliContext,
    metadata_file: Path,
    supply: int,
    treasury: str,
    passphrase: bool,
) -> None:
    """Deploy a Glyph FT with the entire supply premined to *treasury*.

    Single-recipient premine: vout[0] of the reveal carries the full
    supply with the FT locking script pinned to the treasury PKH.
    """
    if supply <= 0:
        raise UserError("--supply must be > 0")

    metadata = _read_metadata_file(metadata_file)
    if GlyphProtocol.FT not in metadata.protocol:
        raise UserError(
            "metadata.protocol does not include FT",
            cause=f"got protocol={list(metadata.protocol)}",
            fix='set "protocol": ["FT"] (or ["FT", "DMINT"]) in the metadata file',
        )

    from ..utils import address_to_public_key_hash

    # Pin the network BEFORE deriving the PKH, for the reason `_require_address_on_network`
    # documents: `address_to_public_key_hash` decodes a testnet address into a perfectly
    # valid-looking 20-byte PKH, and the deploy then locks the ENTIRE premined supply to a
    # script no key on this network can spend. Every other destination in this CLI is
    # pinned — `transfer-ft`, `transfer-nft`, each airdrop recipient — and this one, which
    # carries the most value of any of them, was not.
    _require_address_on_network(ctx, treasury, what="--treasury address")

    try:
        treasury_pkh = Hex20(address_to_public_key_hash(treasury))
    except (ValidationError, ValueError) as exc:
        raise UserError("invalid --treasury address", cause=str(exc)) from exc

    wallet = _load_wallet(ctx, prompt_passphrase=passphrase)

    async def _do_deploy() -> dict:
        client = ctx.make_client()
        async with client:
            return await _deploy_ft_inner(ctx, wallet, metadata, treasury_pkh, supply, client)

    try:
        result = asyncio.run(_do_deploy())
    except NetworkError as exc:
        raise NetworkBoundaryError(
            "could not reach ElectrumX",
            cause=str(exc),
            fix=f"check that {ctx.electrumx_url} is reachable",
        ) from exc

    if ctx.output_mode == "json":
        click.echo(emit(result, mode="json"))
    elif ctx.output_mode == "quiet":
        click.echo(emit(result, mode="quiet", quiet_field="reveal_txid"))
    else:
        click.echo("\nFT deployed!")
        click.echo(f"  commit txid: {result['commit_txid']}")
        click.echo(f"  reveal txid: {result['reveal_txid']}")
        click.echo(f"  ref:         {result['ref']}")
        click.echo(f"  supply:      {result['supply']:,} units to {treasury}")


async def _deploy_ft_inner(
    ctx: CliContext,
    wallet: HdWallet,
    metadata: GlyphMetadata,
    treasury_pkh: Hex20,
    supply: int,
    client: ElectrumXClient,
) -> dict:
    builder = GlyphBuilder()
    triples = await wallet.collect_spendable(client)
    if not triples:
        raise UserError("no spendable UTXOs in the wallet")

    fee_rate = ctx.fee_rate
    # The FT premine puts the entire supply on the reveal's vout[0], so the "carrier"
    # the commit must cover on top of the reveal fee is the supply itself. C-1: the
    # reveal fee scales with the CBOR payload the reveal scriptSig carries.
    carrier_value = supply
    reveal_estimate = estimate_reveal_fee_for_metadata(metadata, fee_rate=fee_rate)
    commit_value = _commit_value_for_reveal(carrier_value, reveal_estimate)
    commit_fee_estimate = 300 * fee_rate
    # + one uneconomic-change floor so the funding UTXO can still emit change.
    total_required = commit_value + commit_fee_estimate + DUST_THRESHOLD_PHOTONS

    triples.sort(key=lambda t: t[0].value, reverse=True)
    funding = next((t for t in triples if t[0].value >= total_required), None)
    if funding is None:
        raise UserError(
            "no single UTXO is large enough to fund the deploy",
            cause=f"need ≥ {total_required:,} photons in one UTXO; largest is {triples[0][0].value:,}",
            fix="consolidate UTXOs first, or fund the wallet from a single source",
        )
    funding_utxo, funding_addr, funding_key = funding
    funding_pkh = Hex20(funding_key.public_key().hash160())

    commit_result = builder.prepare_commit(
        CommitParams(
            metadata=metadata,
            owner_pkh=funding_pkh,
            change_pkh=funding_pkh,
            funding_satoshis=funding_utxo.value,
        )
    )

    locking = P2PKH().lock(funding_addr)
    # Pad the source shim so the funding output sits at its real vout (the largest
    # wallet UTXO is often change at vout != 0; TransactionInput + fee() index it).
    src_outs = [TransactionOutput(Script(b""), 0) for _ in range(funding_utxo.tx_pos)]
    src_outs.append(TransactionOutput(locking, funding_utxo.value))
    src_tx = Transaction(tx_inputs=[], tx_outputs=src_outs)
    src_tx.txid = lambda: funding_utxo.tx_hash  # type: ignore[method-assign]

    commit_input = TransactionInput(
        source_transaction=src_tx,
        source_txid=funding_utxo.tx_hash,
        source_output_index=funding_utxo.tx_pos,
        unlocking_script_template=P2PKH().unlock(funding_key),
    )
    commit_input.satoshis = funding_utxo.value
    commit_input.locking_script = locking

    # change=True lets fee() size the fee from the real length and fill the change;
    # a manual change output + fee() ZeroDivisions when there are no change=True outputs.
    commit_outputs = [
        TransactionOutput(Script(commit_result.commit_script), commit_value),
        TransactionOutput(locking, 0, change=True),
    ]
    commit_tx = Transaction(tx_inputs=[commit_input], tx_outputs=commit_outputs)
    commit_tx.fee(SatoshisPerKilobyte(fee_rate * 1000))
    commit_tx.sign()

    # C-1 gate: the last point at which nothing has been spent. Once the commit is
    # broadcast an unfundable reveal strands the commit output permanently. Build the
    # reveal now, against a placeholder commit txid, and MEASURE it — an independent
    # check on the estimate that sized commit_value above.
    def _ft_reveal_scripts(txid: str) -> FtDeployRevealScripts:
        return builder.prepare_ft_deploy_reveal(
            commit_txid=txid,
            commit_vout=0,
            commit_value=commit_value,
            cbor_bytes=commit_result.cbor_bytes,
            premine_pkh=treasury_pkh,
            premine_amount=supply,
        )

    dry_run_scripts = _ft_reveal_scripts(_PLACEHOLDER_COMMIT_TXID)
    # No WAVE registration fee on an FT deploy: prepare_ft_deploy_reveal refuses a payload
    # that would register a WAVE name rather than return one without its fee.
    dry_run_reveal = _build_reveal_tx(
        commit_txid=_PLACEHOLDER_COMMIT_TXID,
        commit_value=commit_value,
        commit_script=commit_result.commit_script,
        reveal_locking_script=dry_run_scripts.locking_script,
        carrier_value=carrier_value,
        change_locking=locking,
        funding_key=funding_key,
        scriptsig_suffix=dry_run_scripts.scriptsig_suffix,
        registration_fee=None,
    )
    measured = _assert_reveal_is_fundable(
        commit_value, carrier_value, dry_run_reveal, fee_rate, len(commit_result.cbor_bytes), registration_fee=None
    )

    _confirm_or_abort(
        ctx,
        [
            _metadata_summary(metadata),
            _BroadcastSummary(
                title="Commit transaction",
                lines=[
                    f"funding addr:  {funding_addr}",
                    f"funding utxo:  {funding_utxo.tx_hash}:{funding_utxo.tx_pos}",
                    f"funding value: {funding_utxo.value:,} photons",
                    f"commit value:  {commit_value:,} photons",
                    f"owner_pkh:     {funding_pkh.hex()}  (this wallet)",
                    f"reveal fee:    {measured.fee:,} photons "
                    f"({measured.size_bytes:,} B @ {fee_rate:,}/B, paid from commit value)",
                    f"network:       {ctx.network}",
                ],
            ),
        ],
    )
    _echoed_commit = await client.broadcast(commit_tx.serialize())
    commit_txid = _local_commit_txid(commit_tx, _echoed_commit)

    if ctx.output_mode == "human":
        click.echo(f"\ncommit broadcast: {commit_txid}")
        click.echo("waiting for confirmation (this can take 10+ minutes)...")
    await _wait_for_tx(client, str(commit_txid), interval_s=_poll_interval_for(ctx))

    # The same builder the dry run above measured, now with the real commit txid.
    # Premine: vout[0].value = the supply (1 photon = 1 unit).
    reveal_scripts = _ft_reveal_scripts(str(commit_txid))
    reveal_tx = _build_reveal_tx(
        commit_txid=str(commit_txid),
        commit_value=commit_value,
        commit_script=commit_result.commit_script,
        reveal_locking_script=reveal_scripts.locking_script,
        carrier_value=carrier_value,
        change_locking=locking,
        funding_key=funding_key,
        scriptsig_suffix=reveal_scripts.scriptsig_suffix,
        registration_fee=None,
    )
    reveal_tx.fee(SatoshisPerKilobyte(fee_rate * 1000))
    reveal_tx.sign()

    _confirm_or_abort(
        ctx,
        [
            _BroadcastSummary(
                title="Reveal transaction (FT premine)",
                lines=[
                    f"commit txid: {commit_txid}",
                    f"supply:      {supply:,} units → {treasury_pkh.hex()}",
                ],
            ),
        ],
    )
    _echoed_reveal = await client.broadcast(reveal_tx.serialize())
    reveal_txid = _confirmed_reveal_txid(reveal_tx, _echoed_reveal)
    # The genesis ref is the COMMIT outpoint, not the reveal txid: prepare_reveal
    # embeds GlyphRef(commit_txid, commit_vout) into the reveal's locking script
    # (glyph/builder.py), and that is what extract_ref_from_{nft,ft}_script reads
    # back — so it is what `transfer-nft` / `transfer-ft` match on.
    ref = GlyphRef(txid=Txid(str(commit_txid)), vout=0)

    return {
        "commit_txid": str(commit_txid),
        "reveal_txid": str(reveal_txid),
        "ref": f"{ref.txid}:{ref.vout}",
        "supply": supply,
    }


# ---------------------------------------------------------------------------
# transfer-ft and transfer-nft
# ---------------------------------------------------------------------------


@glyph_group.command(name="transfer-ft")
@click.argument("ref", type=str)
@click.argument("amount", type=int)
@click.option("--to", "to_address", required=True, help="Recipient address.")
@click.option("--passphrase/--no-passphrase", default=False)
@click.option(
    "--allow-overpay",
    is_flag=True,
    default=False,
    help="Accept a fee far above what the signed transaction's size demands. Relaxes the rate "
    "ceiling (10x the relay floor) and the overpay check. It does NOT relax the underpay "
    "invariant — a transaction must always pay for its own size. Exists so a refusal is "
    "never a dead end on a chain with no RBF or CPFP.",
)
@click.pass_obj
def transfer_ft_cmd(
    ctx: CliContext, ref: str, amount: int, to_address: str, passphrase: bool, allow_overpay: bool
) -> None:
    """Transfer FT units of REF (txid:vout) to --to ADDRESS.

    Builds a conservation-enforcing FT transfer via FtUtxoSet.
    """
    if amount <= 0:
        raise UserError("amount must be > 0")
    glyph_ref = _parse_ref(ref)

    from ..utils import address_to_public_key_hash

    # Same network pin as `airdrop-ft` and `wallet sweep`: a testnet-prefixed
    # address decodes fine on mainnet and the tokens land on a script no
    # mainnet key can spend.
    _require_address_on_network(ctx, to_address, what="--to address")
    to_pkh = Hex20(address_to_public_key_hash(to_address))

    wallet = _load_wallet(ctx, prompt_passphrase=passphrase)

    async def _do_transfer() -> dict:
        client = ctx.make_client()
        async with client:
            return await _transfer_ft_inner(
                ctx, wallet, glyph_ref, amount, to_pkh, to_address, client, allow_overpay=allow_overpay
            )

    try:
        result = asyncio.run(_do_transfer())
    except NetworkError as exc:
        raise NetworkBoundaryError(
            "could not reach ElectrumX",
            cause=str(exc),
            fix=f"check that {ctx.electrumx_url} is reachable",
        ) from exc

    if ctx.output_mode == "json":
        click.echo(emit(result, mode="json"))
    elif ctx.output_mode == "quiet":
        click.echo(emit(result, mode="quiet", quiet_field="txid"))
    else:
        click.echo(f"\nFT transfer broadcast: {result['txid']}")


def _require_address_on_network(ctx: CliContext, address: str, *, what: str) -> None:
    """Refuse a destination address that is not valid on the ACTIVE network.

    ``address_to_public_key_hash`` decodes any well-formed base58check P2PKH
    address and returns its hash160 regardless of the version byte, so a
    testnet-prefixed address (``m…``/``n…``) pasted into a mainnet command
    produced a perfectly valid-looking 20-byte PKH and an output locked to a
    script no mainnet key can spend. Token quantities are not recoverable from
    that; there is no refund path and no RBF to pull the transaction back.

    ``wallet sweep`` and ``wallet send`` already pin the network this way. The
    glyph transfer paths did not, which is the same unrecoverable paste error
    with tokens on it instead of RXD.
    """
    # `Network` has only MAINNET and TESTNET, but `--network` also accepts `regtest`, so
    # `Network(ctx.network)` raised a bare `ValueError` — an unhandled traceback, not a
    # UserError — for every pinned command on regtest. Regtest is the developer onramp
    # `pyrxd regtest` exists to serve, so the guard was refusing the workflow the project
    # ships to newcomers. Regtest addresses carry testnet's version byte and decode to
    # `Network.TESTNET` (there are only two prefixes in ADDRESS_PREFIX_NETWORK_DICT), so
    # that is the network to pin against.
    expected = Network.TESTNET if ctx.network == "regtest" else Network(ctx.network)
    if not validate_address(address, network=expected):
        raise UserError(
            f"invalid {what}",
            cause=f"not a valid {ctx.network} Radiant P2PKH address",
            fix=f"pass a {ctx.network} address" + (" (starts with 1)" if ctx.network == "mainnet" else ""),
        )


async def _select_ft_inputs(
    wallet: HdWallet,
    ref: GlyphRef,
    amount: int,
    client: ElectrumXClient,
    triples: list[tuple[UtxoRecord, str, PrivateKey]] | None = None,
) -> list[tuple[FtUtxo, str, PrivateKey]]:
    """Find this wallet's FT UTXOs for ``ref`` and greedily cover ``amount``.

    Shared by ``transfer-ft`` and ``airdrop-ft``. Extracted rather than copied:
    the two commands must agree on what counts as a spendable holding of a
    token, and a second copy of the "is this output really an FT of this ref"
    filter is a place for them to silently diverge.

    Returns ``(FtUtxo, address, key)`` triples in the order they were selected.

    The selection itself lives in :func:`pyrxd.glyph.transfer.select_ft_inputs` so the
    SDK and the CLI cannot disagree about what counts as a spendable holding. This
    wrapper only re-dresses the SDK error as a CLI one with a runnable fix.
    """
    try:
        return await lib_select_ft_inputs(wallet, ref, amount, client, triples)
    except NoHoldingsError as exc:
        raise UserError(
            f"no FT holdings for {ref.txid}:{ref.vout} in this wallet",
            fix="run `pyrxd balance --refresh` to discover used addresses, then retry",
        ) from exc
    except InsufficientFundsError as exc:
        raise UserError(
            str(exc),
            fix="check holdings with `pyrxd glyph list --type ft`",
        ) from exc


def _single_ft_signing_key(
    selected: list[tuple[FtUtxo, str, PrivateKey]],
    what: str,
) -> PrivateKey:
    """The one key that signs every selected FT input, or a clear refusal.

    ``FtUtxoSet`` signs all inputs with a single key. If the selection spans
    several HD-derived addresses, signing anyway would emit a transaction with
    invalid signatures on some inputs — rejected at broadcast, but only after
    the user has confirmed a spend. Refuse first instead.
    """
    try:
        return lib_single_ft_signing_key(selected, what)
    except ValidationError as exc:
        raise UserError(
            f"{what} across multiple wallet addresses isn't supported in Cut 2",
            cause="selected FT utxos span multiple HD-derived keys",
            fix="consolidate FT holdings to one address first (Cut 3 will lift this restriction)",
        ) from exc


def _local_commit_txid(commit_tx_or_hex: object, echoed: object) -> str:
    """The commit txid derived from the bytes we signed, not the server's reply.

    This one matters more than the transfer equivalent. The commit txid is not merely
    reported — the REVEAL is built from it: it becomes the outpoint the reveal spends and
    the ref baked into the token's locking script. Take the server's word for it and a
    node that echoes some other confirmed txid gets a reveal built against the wrong
    outpoint, carrying the wrong ref, which can never spend the real commit. That commit
    is a hashlock with no owner-only path, so its value is gone.

    Warns rather than raises: the commit may well have relayed, and the caller needs the
    locally derived txid to carry on with the reveal either way.
    """
    from ..transaction.transaction import Transaction

    tx = commit_tx_or_hex if hasattr(commit_tx_or_hex, "txid") else Transaction.from_hex(commit_tx_or_hex)
    if tx is None:
        # `from_hex` returns None rather than raising, and we are PAST the broadcast here.
        # Letting that None reach `.txid()` raised `AttributeError` between the broadcast
        # and the line that prints the txid — so the commit was on chain and the user was
        # never told its id, which is the exact stranding this helper exists to prevent.
        # Hand back the echoed txid in the message: unverified, but it is the only handle
        # left on a commit that has already relayed.
        raise UserError(
            "the commit was broadcast but its txid could not be re-derived locally",
            cause="the signed commit bytes did not parse back into a transaction",
            # Name a recovery that EXISTS. An earlier version of this sent the user to a
            # "PendingMint record still in the store" when no command kept one, so the advice
            # was fiction on a path where the commit is a hashlock with no owner-only spend
            # path. `deploy-ft` and `deploy-dmint` still keep no record, so the SDK recipe is
            # their recovery; `mint-nft` does, and `_after_commit` appends its `resume-mint`
            # recovery to this. `_wait_for_tx` below calls a recovery that does not exist
            # "the worst possible answer". Same answer here, same reason.
            fix=(
                f"the server echoed {echoed} — check it on an explorer. If it is there the commit "
                "relayed: rebuild the reveal with the SDK — GlyphBuilder.prepare_reveal("
                "RevealParams(commit_txid=<txid>, commit_vout=0, commit_value=<photons>, "
                "cbor_bytes=..., owner_pkh=..., is_nft=...)) using the SAME unmodified metadata "
                "file and the SAME wallet. See docs/how-to/troubleshoot-common-errors.md"
            ),
        )
    local = str(tx.txid())
    if str(echoed) != local:
        click.echo(
            f"warning: the server returned txid {echoed} but the commit we signed hashes "
            f"to {local}. Continuing with {local}; if the reveal fails, check both on an "
            "explorer.",
            err=True,
        )
    return local


def _confirmed_reveal_txid(reveal_tx_or_hex: object, echoed: object) -> str:
    """The reveal txid derived from the bytes we signed. RAISES on a mismatch.

    The counterpart to :func:`_local_commit_txid`, and deliberately stricter. That one
    warns because a commit has a next phase to carry on with, and the caller needs the
    derived value to build it. A reveal is where the mint ENDS, so there is no later step
    to notice the discrepancy — and what the CLI prints from this txid is not merely a
    receipt. ``deploy-dmint`` builds its ``contracts`` outpoints and ``premine_outpoint``
    from it, which is what miners then grind against and what the owner later spends. Take
    a lying server's word here and the user is handed outpoints that do not exist, with
    real work aimed at them.

    The token's own ref is safe either way — it is the COMMIT outpoint, embedded in the
    reveal's locking script — which is exactly why this went unnoticed: the most
    load-bearing identifier on the page never depended on the echo.
    """
    from ..transaction.transaction import Transaction

    tx = reveal_tx_or_hex if hasattr(reveal_tx_or_hex, "txid") else Transaction.from_hex(reveal_tx_or_hex)
    if tx is None:
        raise UserError(
            "the reveal was broadcast but its txid could not be re-derived locally",
            cause="the signed reveal bytes did not parse back into a transaction",
            fix=f"the server echoed {echoed} — check it on an explorer before spending anything built on it",
        )
    local = str(tx.txid())
    if str(echoed) != local:
        raise UserError(
            "the server returned a different transaction id than the reveal we signed",
            cause=f"echoed {echoed}, but the signed reveal hashes to {local}",
            fix=f"check {local} on an explorer — if it is there the mint completed and only the "
            "server's reply was wrong. Do not use the echoed id: outpoints derived from it "
            "would point at a transaction that does not exist.",
        )
    return local


async def _transfer_ft_inner(
    ctx: CliContext,
    wallet: HdWallet,
    ref: GlyphRef,
    amount: int,
    to_pkh: Hex20,
    to_address: str,
    client: ElectrumXClient,
    *,
    allow_overpay: bool = False,
) -> dict:
    """FT transfer: scan wallet, find FT utxos for ref, build + broadcast.

    The build lives in :func:`pyrxd.glyph.transfer.build_ft_transfer` — including the
    decision to route through ``build_ft_airdrop_tx`` with a single recipient. Keeping
    that decision in one place is the point: a second copy is a place for a bug to
    come back.

    ``allow_overpay`` is the escape hatch for two fee bounds that both refuse rather
    than warn — the rate ceiling and the fee-vs-signed-bytes check. Neither should
    ever refuse an ordinary transfer (measured: 0 refusals over 3,600+ builds at 2-10
    inputs and 1-9x the floor rate), but Radiant has neither RBF nor CPFP, so a bound
    with no reachable override can cost the funds it was protecting. It is off by
    default and greppable when used.

    This function owns what the SDK deliberately does not — showing the user what is
    about to be spent, and broadcasting only after they agree.
    """
    try:
        build = await lib_build_ft_transfer(
            wallet,
            ref,
            amount,
            to_pkh,
            client=client,
            fee_rate=ctx.fee_rate,
            allow_overpay=allow_overpay,
        )
    except NoHoldingsError as exc:
        raise UserError(
            f"no FT holdings for {ref.txid}:{ref.vout} in this wallet",
            fix="run `pyrxd balance --refresh` to discover used addresses, then retry",
        ) from exc
    except NoFeeFundingError as exc:
        raise UserError(
            "no plain-RXD UTXO large enough to fund the fee",
            cause=str(exc),
            fix="send some plain RXD to this wallet — the token cannot pay its own fee",
        ) from exc
    except InsufficientFundsError as exc:
        raise UserError(str(exc), fix="check holdings with `pyrxd glyph list --type ft`") from exc
    except (ValidationError, ValueError) as exc:
        # A fee-bound refusal and a funding shortfall are different problems with
        # different remedies. Telling someone to add RXD when the build was refused
        # for paying too MUCH sends them in the opposite direction, and on a chain
        # with no RBF/CPFP a refusal the operator cannot act on is its own hazard.
        if "allow_overpay=True" in str(exc):
            raise UserError(
                "refusing to broadcast: the fee is above what this transaction's size demands",
                cause=str(exc),
                fix="lower --fee-rate, or pass --allow-overpay to accept it deliberately",
            ) from exc
        raise UserError(
            "could not build the transfer",
            cause=str(exc),
            fix="fund the wallet with a little plain RXD — the token cannot pay its own fee",
        ) from exc

    transfer_result = build
    raw = build.serialize()  # bytes, not hex — `broadcast` takes bytes

    _confirm_or_abort(
        ctx,
        [
            _BroadcastSummary(
                title="FT transfer",
                lines=[
                    f"ref:          {ref.txid}:{ref.vout}",
                    f"amount:       {amount:,} units",
                    f"recipient:    {to_address}",
                    f"fee:          {transfer_result.fee:,} photons (from plain RXD, not the token)",
                    f"network:      {ctx.network}",
                ],
            ),
        ],
    )
    echoed = await client.broadcast(raw)
    # Report the txid of what we signed. A server that drops the transfer and echoes some
    # other well-formed txid would otherwise have the CLI print it as success.
    try:
        txid = _confirmed_txid(build, echoed)
    except BroadcastEchoMismatch as exc:
        raise UserError(
            "the server returned a different transaction id than the one we signed",
            cause=str(exc),
            fix=f"check {exc.local_txid} on an explorer — if it is there the transfer went "
            "through and only the server's reply was wrong",
        ) from exc
    return {"txid": txid, "ref": f"{ref.txid}:{ref.vout}", "amount": amount, "to": to_address}


async def _airdrop_funding(
    ctx: CliContext,
    wallet: HdWallet,
    selected: list[tuple[FtUtxo, str, PrivateKey]],
    *,
    n_outputs: int,
    client: ElectrumXClient,
    triples: list[tuple[UtxoRecord, str, PrivateKey]] | None = None,
) -> AirdropFunding:
    """Find a plain-RXD UTXO big enough to pay for ``n_outputs`` token outputs.

    The token cannot pay the fee: an FT output's value IS its unit count, so
    taking the fee from one would burn units and short a recipient. This sources
    the fee the same way ``transfer-nft`` sources it for a dust singleton.

    The estimate is deliberately generous — an unfunded build fails cleanly, but
    a build that squeaks past and lands under the relay floor cannot be repaired
    on Radiant (no RBF, no CPFP). ~84 B per FT output, ~148 B per input, ~50 B of
    envelope, then doubled for headroom.
    """
    est_bytes = 84 * (n_outputs + 2) + 148 * (len(selected) + 1) + 50
    needed = est_bytes * ctx.fee_rate * 2
    try:
        return await lib_ft_funding(
            wallet,
            selected,
            n_outputs=n_outputs,
            fee_rate=ctx.fee_rate,
            client=client,
            triples=triples,
        )
    except InsufficientFundsError as exc:
        raise UserError(
            "no plain-RXD UTXO large enough to fund the fee",
            cause=f"need about {needed:,} photons on a single non-token UTXO",
            fix="send some plain RXD to this wallet — an FT output's value is its unit count, "
            "so the token itself cannot pay the fee without burning units",
        ) from exc


# ---------------------------------------------------------------------------
# airdrop-ft
# ---------------------------------------------------------------------------


def _parse_recipient_spec(spec: str) -> tuple[str, int]:
    """Parse one ``ADDRESS:AMOUNT`` pair from ``--to``.

    Split on the LAST colon so nothing breaks if an address form ever carries
    one (``rxd:qq…`` prefixes exist in the wider Radiant ecosystem).
    """
    address, sep, amount_str = spec.rpartition(":")
    if not sep or not address:
        raise UserError(
            f"malformed recipient {spec!r}",
            cause="expected ADDRESS:AMOUNT",
            fix="e.g. --to 1Alice…:250",
        )
    try:
        amount = int(amount_str)
    except ValueError:
        raise UserError(
            f"malformed recipient {spec!r}",
            cause=f"{amount_str!r} is not an integer amount",
            fix="amounts are whole FT units, e.g. --to 1Alice…:250",
        ) from None
    return address, amount


def _load_recipients_file(path: Path) -> list[tuple[str, int]]:
    """Read a recipients file: JSON array of objects, or ``address,amount`` CSV.

    Both shapes are accepted because both are what people actually have. The
    format is chosen by extension so a mis-named file fails loudly instead of
    being parsed as the wrong thing.
    """
    try:
        text = path.read_text()
    except OSError as exc:
        raise UserError(
            f"could not read recipients file: {path}",
            cause=str(exc),
            fix="check the path and permissions",
        ) from exc

    if path.suffix.lower() == ".json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise UserError(
                f"recipients file is not valid JSON: {path}",
                cause=str(exc),
            ) from exc
        if not isinstance(data, list):
            raise UserError(
                "recipients JSON must be an array",
                cause=f"got {type(data).__name__}",
                fix='e.g. [{"address": "1Alice…", "amount": 250}]',
            )
        out: list[tuple[str, int]] = []
        for i, row in enumerate(data):
            if not isinstance(row, dict) or "address" not in row or "amount" not in row:
                raise UserError(
                    f"recipients[{i}] must be an object with 'address' and 'amount'",
                    cause=f"got {row!r}",
                )
            try:
                out.append((str(row["address"]), int(row["amount"])))
            except (TypeError, ValueError) as exc:
                raise UserError(f"recipients[{i}].amount is not an integer", cause=str(exc)) from exc
        return out

    rows: list[tuple[str, int]] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = [p.strip() for p in stripped.split(",")]
        if len(parts) != 2:
            raise UserError(
                f"{path}:{lineno} is not `address,amount`",
                cause=f"got {stripped!r}",
                fix="one recipient per line, e.g. 1Alice…,250",
            )
        try:
            rows.append((parts[0], int(parts[1])))
        except ValueError:
            raise UserError(
                f"{path}:{lineno} has a non-integer amount",
                cause=f"got {parts[1]!r}",
            ) from None
    return rows


@glyph_group.command(name="airdrop-ft")
@click.argument("ref", type=str)
@click.option(
    "--to",
    "to_specs",
    multiple=True,
    help="Recipient as ADDRESS:AMOUNT. Repeatable; combine with or instead of --recipients.",
)
@click.option(
    "--recipients",
    "recipients_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Recipients file: `.json` array of {address, amount}, or `address,amount` CSV.",
)
@click.option("--passphrase/--no-passphrase", default=False)
@click.option(
    "--allow-overpay",
    is_flag=True,
    default=False,
    help="Accept a fee far above what the signed transaction's size demands. Relaxes the rate "
    "ceiling (10x the relay floor) and the overpay check. It does NOT relax the underpay "
    "invariant. Exists so a refusal is never a dead end on a chain with no RBF or CPFP.",
)
@click.pass_obj
def airdrop_ft_cmd(
    ctx: CliContext,
    ref: str,
    to_specs: tuple[str, ...],
    recipients_path: Path | None,
    passphrase: bool,
    allow_overpay: bool,
) -> None:
    """Send FT units of REF (txid:vout) to many recipients in ONE transaction.

    One transaction, not N: an airdrop split across N transactions chains each
    one onto the previous one's change output, so a failure partway through
    leaves the set half-delivered and the token's ref alone cannot tell you
    which half. Conservation is enforced by the same
    ``FtUtxoSet``/``select`` path ``transfer-ft`` uses.

    \b
    Examples:
      pyrxd glyph airdrop-ft REF --to 1Alice:250 --to 1Bob:100
      pyrxd glyph airdrop-ft REF --recipients holders.csv
    """
    glyph_ref = _parse_ref(ref)

    pairs: list[tuple[str, int]] = [_parse_recipient_spec(s) for s in to_specs]
    if recipients_path is not None:
        if not recipients_path.exists():
            raise UserError(
                f"recipients file not found: {recipients_path}",
                fix="pass an existing .json or .csv file, or use --to ADDRESS:AMOUNT",
            )
        pairs.extend(_load_recipients_file(recipients_path))
    if not pairs:
        raise UserError(
            "no recipients given",
            fix="pass --to ADDRESS:AMOUNT (repeatable) and/or --recipients FILE",
        )

    from ..glyph.ft import AirdropRecipient
    from ..utils import address_to_public_key_hash

    recipients: list[AirdropRecipient] = []
    seen: dict[str, int] = {}
    for address, amount in pairs:
        if amount <= 0:
            raise UserError(
                f"recipient {address} has amount {amount}",
                cause="airdrop amounts must be > 0",
            )
        if address in seen:
            # Refuse rather than merge: a repeated address in a holder list is
            # usually a duplicated row, and paying it twice cannot be undone.
            raise UserError(
                f"recipient {address} appears more than once",
                cause=f"amounts {seen[address]} and {amount}",
                fix="combine the entries into a single line if the total is intended",
            )
        seen[address] = amount
        # Pin every recipient to the ACTIVE network, the way `wallet sweep` and
        # `wallet send` do. Without this a testnet-prefixed address (m…/n…)
        # decodes cleanly on mainnet and the airdrop pays a script no mainnet
        # key can spend — units gone, with no way back. An airdrop file is
        # exactly where a stray line survives review, and it pays N recipients
        # in one irreversible transaction.
        _require_address_on_network(ctx, address, what=f"recipient {address}")
        pkh = Hex20(address_to_public_key_hash(address))
        recipients.append(AirdropRecipient(pkh=pkh, amount=amount))

    wallet = _load_wallet(ctx, prompt_passphrase=passphrase)

    async def _do_airdrop() -> dict:
        client = ctx.make_client()
        async with client:
            return await _airdrop_ft_inner(
                ctx, wallet, glyph_ref, recipients, pairs, client, allow_overpay=allow_overpay
            )

    try:
        result = asyncio.run(_do_airdrop())
    except NetworkError as exc:
        raise NetworkBoundaryError(
            "could not reach ElectrumX",
            cause=str(exc),
            fix=f"check that {ctx.electrumx_url} is reachable",
        ) from exc

    if ctx.output_mode == "json":
        click.echo(emit(result, mode="json"))
    elif ctx.output_mode == "quiet":
        click.echo(emit(result, mode="quiet", quiet_field="txid"))
    else:
        click.echo(f"\nFT airdrop broadcast: {result['txid']}")
        click.echo(emit_table(result["recipients"], ["address", "amount", "vout"], mode="human"))


async def _airdrop_ft_inner(
    ctx: CliContext,
    wallet: HdWallet,
    ref: GlyphRef,
    recipients: list,  # list[AirdropRecipient]
    pairs: list[tuple[str, int]],
    client: ElectrumXClient,
    *,
    allow_overpay: bool = False,
) -> dict:
    """FT airdrop: scan wallet, select FT utxos for ref, fund the fee, broadcast."""
    total = sum(r.amount for r in recipients)
    # The orchestration — enumerate the wallet ONCE, select, fund, build, then assert the
    # fee against the built size — is `pyrxd.glyph.transfer.build_ft_airdrop` as of #459.
    # It used to live here, which meant a library caller had to reimplement it; keeping a
    # second copy would mean keeping two fund-safety sequences in step.
    try:
        build = await build_ft_airdrop(
            wallet,
            ref,
            recipients,
            client=client,
            fee_rate=ctx.fee_rate,
            allow_overpay=allow_overpay,
        )
    except (ValidationError, ValueError) as exc:
        raise UserError(
            "could not build the airdrop",
            cause=str(exc),
            fix="fund the wallet with more plain RXD, or split the list into smaller batches",
        ) from exc
    airdrop_result = build

    rows = [{"address": address, "amount": amount, "vout": vout} for vout, (address, amount) in enumerate(pairs)]
    _confirm_or_abort(
        ctx,
        [
            _BroadcastSummary(
                title="FT airdrop",
                lines=[
                    f"ref:          {ref.txid}:{ref.vout}",
                    f"recipients:   {len(recipients)}",
                    f"total:        {total:,} units",
                    f"fee:          {airdrop_result.fee:,} photons (from plain RXD, not the token)",
                    f"network:      {ctx.network}",
                ],
            ),
            _BroadcastSummary(
                title="Destinations",
                lines=[f"vout {r['vout']}: {r['amount']:,} units → {r['address']}" for r in rows],
            ),
        ],
    )
    _echoed = await client.broadcast(airdrop_result.tx.serialize())
    # RAISE on a mismatch, like `transfer-ft` and `transfer-nft` — not the commit
    # helper's warn-and-continue. That helper warns because a commit has a next phase to
    # carry on with; an airdrop is terminal, so a warning on a non-tty run is no warning
    # at all and `--json` would report success for tokens that never moved. It is also
    # the widest blast radius of the three: N recipients in one transaction.
    try:
        txid = _confirmed_txid(airdrop_result, _echoed)
    except BroadcastEchoMismatch as exc:
        raise UserError(
            "the server returned a different transaction id than the one we signed",
            cause=str(exc),
            fix=f"check {exc.local_txid} on an explorer — if it is there the airdrop went "
            "through to every recipient and only the server's reply was wrong",
        ) from exc
    return {
        "txid": str(txid),
        "ref": f"{ref.txid}:{ref.vout}",
        "recipient_count": len(recipients),
        "total_units": total,
        "fee": airdrop_result.fee,
        "recipients": rows,
    }


@glyph_group.command(name="transfer-nft")
@click.argument("ref", type=str)
@click.option("--to", "to_address", required=True, help="Recipient address.")
@click.option("--passphrase/--no-passphrase", default=False)
@click.option(
    "--allow-overpay",
    is_flag=True,
    default=False,
    help="Accept a fee far above what the signed transaction's size demands. Relaxes the rate "
    "ceiling (10x the relay floor). It does NOT relax the underpay invariant. Exists so a "
    "refusal is never a dead end on a chain with no RBF or CPFP.",
)
@click.pass_obj
def transfer_nft_cmd(ctx: CliContext, ref: str, to_address: str, passphrase: bool, allow_overpay: bool) -> None:
    """Transfer the NFT singleton REF (txid:vout) to --to ADDRESS."""
    glyph_ref = _parse_ref(ref)

    from ..utils import address_to_public_key_hash

    # Same network pin as `transfer-ft` and `airdrop-ft` do, and this is the
    # worst of the three to omit: a testnet-prefixed address decodes to a perfectly valid
    # PKH on mainnet, so the singleton is re-locked to a script no mainnet key can spend.
    # An NFT has no second copy and Radiant has no RBF/CPFP — the transfer cannot be
    # recalled and the token cannot be reissued.
    _require_address_on_network(ctx, to_address, what="--to address")
    try:
        to_pkh = Hex20(address_to_public_key_hash(to_address))
    except (ValidationError, ValueError) as exc:
        raise UserError("invalid --to address", cause=str(exc)) from exc

    wallet = _load_wallet(ctx, prompt_passphrase=passphrase)

    async def _do_transfer() -> dict:
        client = ctx.make_client()
        async with client:
            return await _transfer_nft_inner(
                ctx, wallet, glyph_ref, to_pkh, to_address, client, allow_overpay=allow_overpay
            )

    try:
        result = asyncio.run(_do_transfer())
    except PolicyRejection as exc:
        # BEFORE the NetworkError arm, and not merged into it: `PolicyRejection`
        # subclasses `NetworkError`, so a node VERDICT on the transaction was being
        # reported as "could not reach ElectrumX — check that <url> is reachable",
        # sending the operator to debug connectivity for a transaction the node saw,
        # evaluated and refused. The node reached us; it said no.
        raise UserError(
            "the node rejected the NFT transfer",
            cause=str(exc),
            fix="this is the node's verdict on the transaction, not a connectivity fault — "
            "re-run with --debug for the full reason",
        ) from exc
    except NetworkError as exc:
        raise NetworkBoundaryError(
            "could not reach ElectrumX",
            cause=str(exc),
            fix=f"check that {ctx.electrumx_url} is reachable",
        ) from exc

    if ctx.output_mode == "json":
        click.echo(emit(result, mode="json"))
    elif ctx.output_mode == "quiet":
        click.echo(emit(result, mode="quiet", quiet_field="txid"))
    else:
        click.echo(f"\nNFT transfer broadcast: {result['txid']}")


async def _find_plain_rxd_utxo(
    triples: list[tuple[UtxoRecord, str, PrivateKey]],
    client: ElectrumXClient,
    *,
    exclude: set[tuple[str, int]],
    needed: int,
) -> tuple[UtxoRecord, str, PrivateKey] | None:
    """Pick a plain-P2PKH (non-token) wallet UTXO >= ``needed`` to fund a fee.

    Verifies each candidate's on-chain script is a bare 25-byte P2PKH so a
    token-bearing UTXO is never spent as fee (which would burn the token).
    Excludes the given outpoints (e.g. the NFT being transferred).

    Delegates to :func:`pyrxd.glyph.transfer.find_plain_rxd_utxo`; the P2PKH check is
    a fund-safety property, so it lives in one place.
    """
    return await lib_find_plain_rxd_utxo(triples, client, exclude=exclude, needed=needed)


#: The ``transfer-nft`` funding bar moved to :mod:`pyrxd.glyph.transfer` alongside the
#: build it sizes — see :data:`~pyrxd.glyph.transfer.NFT_TRANSFER_MODELLED_BYTES` and
#: :func:`~pyrxd.glyph.transfer.nft_transfer_funding_bar`. No alias is left behind on
#: purpose: two tests monkeypatch the bar by module path to restore the old flat
#: literal and ask a node what happens, and an alias here would let those patches
#: bind a name the build no longer reads — a differential test that silently proves
#: nothing is worse than one that fails to import.


async def _transfer_nft_inner(
    ctx: CliContext,
    wallet: HdWallet,
    ref: GlyphRef,
    to_pkh: Hex20,
    to_address: str,
    client: ElectrumXClient,
    *,
    allow_overpay: bool = False,
) -> dict:
    """Find the singleton NFT utxo and re-lock it to to_pkh.

    The build lives in :func:`pyrxd.glyph.transfer.build_nft_transfer` — including
    the decision to fund the fee from a separate plain-RXD input instead of taking
    it out of the singleton, which is what ``GlyphBuilder.build_nft_transfer_tx``
    does and why that builder cannot move a dust-valued NFT at all. Keeping the
    working path in one importable place is the point; a second copy is a place for
    the bug to come back.

    This function owns what the SDK deliberately does not — showing the user what is
    about to be spent, and broadcasting only after they agree.
    """
    try:
        build = await lib_build_nft_transfer(
            wallet,
            ref,
            to_pkh,
            client=client,
            fee_rate=ctx.fee_rate,
            allow_overpay=allow_overpay,
        )
    except NoHoldingsError as exc:
        raise UserError(
            f"NFT {ref.txid}:{ref.vout} is not held by this wallet",
            fix="run `pyrxd balance --refresh` first; if still missing, the NFT is owned elsewhere",
        ) from exc
    except InsufficientFundsError as exc:
        raise UserError(
            "no plain-RXD UTXO large enough to fund the NFT transfer fee",
            cause=str(exc),
            fix="fund this wallet with plain RXD (the NFT itself carries only dust)",
        ) from exc
    except (ValidationError, ValueError) as exc:
        raise UserError(
            "could not build the NFT transfer",
            cause=str(exc),
            fix="fund this wallet with a little plain RXD and retry",
        ) from exc

    raw = build.serialize()

    _confirm_or_abort(
        ctx,
        [
            _BroadcastSummary(
                title="NFT transfer",
                lines=[
                    f"ref:        {ref.txid}:{ref.vout}",
                    f"from:       {build.from_address}",
                    f"to:         {to_address}",
                    f"fee:        {build.fee:,} photons ({len(raw)} B @ {ctx.fee_rate:,}/B)"
                    + ("" if build.has_change else " — no change: the whole funding UTXO is the fee"),
                    f"network:    {ctx.network}",
                ],
            ),
        ],
    )
    echoed = await client.broadcast(raw)
    try:
        txid = _confirmed_txid(build, echoed)
    except BroadcastEchoMismatch as exc:
        raise UserError(
            "the server returned a different transaction id than the one we signed",
            cause=str(exc),
            fix=f"check {exc.local_txid} on an explorer — if it is there the transfer went "
            "through and only the server's reply was wrong",
        ) from exc
    return {"txid": txid, "ref": f"{ref.txid}:{ref.vout}", "to": to_address, "fee": build.fee}


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------


@glyph_group.command(name="list")
@click.option(
    "--type",
    "kind",
    type=click.Choice(["nft", "ft", "all"]),
    default="all",
    help="Filter holdings by token type.",
)
@click.option("--passphrase/--no-passphrase", default=False)
@click.pass_obj
def list_cmd(ctx: CliContext, kind: str, passphrase: bool) -> None:
    """Scan wallet addresses for Glyph holdings."""
    wallet = _load_wallet(ctx, prompt_passphrase=passphrase)

    async def _do_scan() -> list[dict]:
        client = ctx.make_client()
        async with client:
            scanner = GlyphScanner(client)
            rows: list[dict] = []
            for rec in [r for r in wallet.addresses.values() if r.used]:
                items = await scanner.scan_address(rec.address)
                for item in items:
                    if isinstance(item, GlyphNft) and kind in ("nft", "all"):
                        rows.append(
                            {
                                "type": "NFT",
                                "ref": f"{item.ref.txid}:{item.ref.vout}",
                                "address": rec.address,
                                "amount": "1",
                                "name": (item.metadata.name if item.metadata else ""),
                            }
                        )
                    elif isinstance(item, GlyphFt) and kind in ("ft", "all"):
                        rows.append(
                            {
                                "type": "FT",
                                "ref": f"{item.ref.txid}:{item.ref.vout}",
                                "address": rec.address,
                                "amount": str(item.amount),
                                "name": (item.metadata.name if item.metadata else ""),
                            }
                        )
            return rows

    try:
        rows = asyncio.run(_do_scan())
    except NetworkError as exc:
        raise NetworkBoundaryError(
            "could not reach ElectrumX",
            cause=str(exc),
            fix=f"check that {ctx.electrumx_url} is reachable",
        ) from exc

    columns = ["type", "ref", "address", "amount", "name"]
    click.echo(emit_table(rows, columns, mode=ctx.output_mode, quiet_field="ref"))


# ---------------------------------------------------------------------------
# inspect — classify any Glyph input (script hex, outpoint, contract id, txid)
# ---------------------------------------------------------------------------
# The command and all its helpers live in ``glyph_inspect`` — the single
# largest, most self-contained feature this module used to carry. It is built
# there with a bare ``@click.command`` and attached to the group here, the
# canonical Click pattern for splitting a group's subcommands across files.
glyph_group.add_command(inspect_cmd)

# ---------------------------------------------------------------------------
# dmint-estimate — benchmark this machine, estimate time-to-mint
# ---------------------------------------------------------------------------
# Same split: the command, its renderers, and the live-progress reporter that
# ``claim-dmint`` reuses all live in ``glyph_estimate``.
glyph_group.add_command(dmint_estimate_cmd)

# ---------------------------------------------------------------------------
# timelock-mint / timelock-reveal — the write side of Glyph TIMELOCK (#556)
# ---------------------------------------------------------------------------
# Same split again. Imported here rather than at the top of the file because
# ``glyph_timelock_cmds`` imports ``_mint_nft_inner`` from this module: the mint
# half is the ordinary two-phase NFT mint with a sealed envelope, and a second
# copy of that flow is a second place for its fund-safety ordering to drift.
from .glyph_timelock_cmds import timelock_mint_cmd, timelock_reveal_cmd  # noqa: E402

glyph_group.add_command(timelock_mint_cmd)
glyph_group.add_command(timelock_reveal_cmd)


# ---------------------------------------------------------------------------
# deploy-dmint (V1 dMint contract genesis)
# ---------------------------------------------------------------------------
#
# Lifts the consensus-proven deploy flow (tests/test_dmint_v1_regtest_e2e.py)
# onto the deploy-ft command template. A V1 dMint contract is a 1-photon
# singleton: each PoW-mined claim pays `--reward` photons of the FT and
# recreates the contract at height+1, up to `--max-height` claims.

_DMINT_REF_SEED = 1_000  # > dust; one per contract, genesises each contractRef
# Serialized cost of the optional premine output on the reveal: 8-byte value +
# 1-byte script length + the 75-byte FT locking script.
_PREMINE_OUTPUT_BYTES = 8 + 1 + 75


def _varint_len(n: int) -> int:
    return 1 if n < 0xFD else (3 if n <= 0xFFFF else 5)


def _estimate_dmint_reveal_bytes(
    *,
    contract_scripts: tuple[bytes, ...],
    cbor_len: int,
    premine: bool,
    op_return_len: int,
) -> int:
    """Upper-bound the serialized size of the dMint deploy reveal, in bytes.

    This has to be an over-estimate, never an under-estimate. ``commit0_value``
    is derived from it, and the reveal has no funding input of its own: if the
    commit carries forward less than the reveal's fee, the commit is already
    confirmed by the time that is discovered and its value is stranded behind an
    unbroadcastable reveal.

    The previous formula was a flat ``num_contracts * 260 + 400``, which does not
    describe the transaction the CLI builds — it under-counts the ref-seed inputs
    and assumes a V1-sized contract script. Measured against the real builder it
    was short for every V1 deploy with 2+ contracts and for *every* V2 deploy
    (V2's contract script is ~380 bytes, not 241). Sizing from the actual script
    bytes instead removes the whole class of error.
    """
    # 4 version + 4 locktime + the two count varints (num_contracts <= 250, so
    # the input/output counts stay inside 3 bytes even with premine + OP_RETURN).
    size = 4 + 4 + 3 + 3
    # vin[0], the FT-commit hashlock: 32 txid + 4 index + 4 sequence, a scriptSig
    # length varint (the CBOR body pushes it well past 252 bytes), then
    # <sig+sighash> <pubkey> <"gly"> <CBOR>, each at its worst-case push encoding.
    size += 40 + 3 + (1 + 73) + (1 + 33) + (1 + 3) + (5 + cbor_len)
    # vin[1..N], the ref-seeds: plain P2PKH spends.
    size += len(contract_scripts) * (40 + 1 + (1 + 73) + (1 + 33))
    # Outputs: 8-byte value + script-length varint + script.
    for script in contract_scripts:
        size += 8 + _varint_len(len(script)) + len(script)
    if premine:
        size += _PREMINE_OUTPUT_BYTES
    if op_return_len:
        # OP_RETURN + push prefix (1 byte direct, or 2 for OP_PUSHDATA1) + data.
        size += 8 + 1 + 1 + (1 if op_return_len > 75 else 0) + op_return_len
    size += 8 + 1 + 25  # change (P2PKH)
    return size


_MAX_ADJUSTMENT_TO_LOG2 = {"2": 1, "4": 2, "8": 3, "16": 4}


def _parse_schedule(schedule_json: str) -> tuple[tuple[int, int], ...]:
    """Parse ``--schedule '[[height, difficulty], ...]'`` → ascending (height, target) entries.

    Entries take *difficulty* (1 = easiest), converted to a target via the
    SHA256d formula, to match how ``--difficulty`` works everywhere else.
    """
    try:
        raw = json.loads(schedule_json)
    except json.JSONDecodeError as exc:
        raise UserError("--schedule is not valid JSON", cause=str(exc), fix="e.g. --schedule '[[100, 4], [1000, 8]]'")
    if not isinstance(raw, list) or not all(isinstance(e, list) and len(e) == 2 for e in raw):
        raise UserError("--schedule must be a JSON list of [height, difficulty] pairs", cause=repr(raw))
    if not raw:
        raise UserError("--schedule must have at least one [height, difficulty] entry")
    if len(raw) > 10:
        raise UserError(f"--schedule allows at most 10 entries, got {len(raw)}")
    out: list[tuple[int, int]] = []
    prev_h = -1
    for i, (h, d) in enumerate(raw):
        # JSON `true`/`false` are ints in Python (bool ⊂ int) — reject explicitly.
        if type(h) is not int or type(d) is not int:
            raise UserError(f"--schedule entry {i} [{h!r}, {d!r}]: height and difficulty must be integers")
        if d < 1:
            raise UserError(f"--schedule entry {i}: difficulty must be >= 1, got {d}")
        target = MAX_SHA256D_TARGET // d
        if target < 1:
            raise UserError(
                f"--schedule entry {i}: difficulty {d} too large (yields target 0; max is {MAX_SHA256D_TARGET})"
            )
        if h < 0:
            raise UserError(f"--schedule entry {i}: height must be >= 0, got {h}")
        if h <= prev_h:
            raise UserError(f"--schedule entry {i}: heights must be strictly ascending (got {h} after {prev_h})")
        prev_h = h
        out.append((h, target))
    return tuple(out)


#: The deploy-dmint flag behind each parameter ``check_v2_numeric_bounds`` bounds (V1 uses the
#: first three, through ``check_dmint_v1_bounds``), so a refusal names what the user typed.
_V2_BOUND_FLAGS = {
    "max_height": "--max-height",
    "reward": "--reward",
    "difficulty": "--difficulty",
    "target_time": "--target-time",
    "half_life": "--half-life",
    "epoch_length": "--epoch-length",
    "schedule": "--schedule",
}


@glyph_group.command(name="deploy-dmint")
@click.argument("metadata_file", type=click.Path(path_type=Path))
@click.option(
    "--v2",
    is_flag=True,
    default=False,
    help="Deploy a V2 (DAA-capable) contract. Default: V1 (the established mainnet format).",
)
@click.option(
    "--daa-mode",
    type=click.Choice(["fixed", "asert", "lwma", "epoch", "schedule"]),
    default="fixed",
    show_default=True,
    help="V2 difficulty mode (requires --v2).",
)
@click.option("--num-contracts", type=int, default=1, show_default=True, help="Parallel contracts to genesis [1..250].")
@click.option(
    "--max-height",
    type=int,
    required=True,
    help=(
        "Mints per contract. V1: [1..2^31] (a V1 contract's 4-byte height field cannot pass "
        "2^31 - 1, so a larger value would leave mints that can never happen). "
        "V2: [1..2^63-1] (the covenant reads it as a script number)."
    ),
)
@click.option(
    "--reward",
    type=int,
    required=True,
    help="Photons of the FT paid per successful mint, up to Radiant's money supply (2.1e18).",
)
@click.option(
    "--difficulty",
    type=int,
    default=1,
    show_default=True,
    help="Initial PoW difficulty (1 = easiest; EPOCH needs >= 32768).",
)
@click.option(
    "--target-time",
    type=int,
    default=60,
    show_default=True,
    help=(
        "V2 DAA: target seconds between mints. ASERT/LWMA/EPOCH, whose retarget reads it: "
        "[1..0xFFFFFFFF]; FIXED/SCHEDULE: [1..2^63-1]."
    ),
)
@click.option(
    "--half-life",
    type=int,
    default=DEFAULT_ASERT_HALFLIFE,
    show_default=True,
    help="V2 ASERT: half-life in seconds (canonical Photonic default; was 3600 before 2026-09-16).",
)
@click.option(
    "--last-time",
    type=int,
    default=None,
    help=(
        "V2 DAA: Unix timestamp written into the deployed state's lastTime — the baseline the "
        "FIRST mint retargets against. Default: the deploy time (what Photonic passes). ASERT and "
        "LWMA read it as a script number on the first mint, so values below 2^23 (including 0) "
        "build a contract no miner can ever spend and are refused, as are values above 0x7FFFFFFF "
        "(bit 31 is the script-number sign)."
    ),
)
@click.option("--epoch-length", type=int, default=2016, show_default=True, help="V2 EPOCH: retarget every N blocks.")
@click.option(
    "--max-adjustment",
    type=click.Choice(["2", "4", "8", "16"]),
    default="4",
    show_default=True,
    help="V2 EPOCH: max difficulty adjustment per epoch.",
)
@click.option(
    "--schedule",
    default=None,
    help="V2 SCHEDULE: JSON [[height, difficulty], ...] (<=10, ascending), e.g. '[[100, 4], [1000, 8]]'.",
)
@click.option("--op-return", "op_return", default=None, help="Optional OP_RETURN carrier on the reveal (<=255 bytes).")
@click.option(
    "--premine",
    type=int,
    default=None,
    help="Premine photons issued to the deployer on the reveal, ON TOP of the mineable supply. "
    "You fund these photons yourself (1 photon = 1 FT unit).",
)
@click.option(
    "--premine-to",
    default=None,
    help="Address that receives --premine (default: the funding/deploy address).",
)
@click.option("--passphrase/--no-passphrase", default=False)
@click.pass_obj
def deploy_dmint_cmd(
    ctx: CliContext,
    metadata_file: Path,
    v2: bool,
    daa_mode: str,
    num_contracts: int,
    max_height: int,
    reward: int,
    difficulty: int,
    target_time: int,
    half_life: int,
    last_time: int | None,
    epoch_length: int,
    max_adjustment: str,
    schedule: str | None,
    op_return: str | None,
    premine: int | None,
    premine_to: str | None,
    passphrase: bool,
) -> None:
    """Deploy a dMint contract (commit -> reveal) that miners claim from.

    Genesises ``--num-contracts`` parallel 1-photon singleton contracts; each
    pays ``--reward`` photons of the FT per PoW-mined claim, up to ``--max-height``
    claims. V1 by default (the only established mainnet format). Pass ``--v2`` for
    a DAA-capable V2 contract (``--daa-mode fixed/asert/lwma/epoch/schedule``);
    V2 is consensus-validated (regtest + mainnet) but pre-external-audit.

    ``--premine`` adds one FT output to the reveal carrying that many photons to
    the deployer (or ``--premine-to``). Those photons come out of the deployer's
    wallet — total issued supply becomes
    ``reward * max_height * num_contracts + premine``.
    """
    metadata = _read_metadata_file(metadata_file)
    if GlyphProtocol.FT not in metadata.protocol or GlyphProtocol.DMINT not in metadata.protocol:
        raise UserError(
            "metadata.protocol must include both FT and DMINT for a dMint deploy",
            cause=f"got protocol={list(metadata.protocol)}",
            fix='set "protocol": ["FT", "DMINT"], or scaffold with `glyph init-metadata --type dmint-ft`',
        )
    op_return_bytes = op_return.encode("utf-8") if op_return else None
    # Validate the OP_RETURN length UP FRONT — build_reveal_outputs only checks it
    # after the commit is already on-chain (an over-long value would strand the
    # commit). The cap is pyrxd's OP_PUSHDATA1 ENCODER limit and matches the builder
    # and mint paths; it is NOT a node standardness limit, which Radiant never
    # consults (see :data:`pyrxd.constants.MAX_OP_RETURN_MSG_BYTES`).
    if op_return_bytes is not None and len(op_return_bytes) > MAX_OP_RETURN_MSG_BYTES:
        raise UserError(
            f"--op-return is {len(op_return_bytes)} bytes; pyrxd encodes it with OP_PUSHDATA1 "
            f"(one-byte length), so the cap is {MAX_OP_RETURN_MSG_BYTES} bytes"
        )
    if not v2 and daa_mode != "fixed":
        raise UserError("--daa-mode requires --v2 (V1 dMint is FIXED difficulty only)")
    if not v2 and last_time is not None:
        raise UserError(
            "--last-time requires --v2",
            cause="the V1 dMint state has no lastTime slot (6 items, no DAA)",
            fix="add --v2, or drop --last-time",
        )
    if premine is not None and premine < 1:
        raise UserError("--premine must be >= 1 photon (omit the flag for no premine)")
    if premine_to is not None and premine is None:
        raise UserError(
            "--premine-to was given without --premine",
            cause="there would be no premine output to send anywhere",
            fix="add --premine <photons>, or drop --premine-to",
        )
    premine_pkh: Hex20 | None = None
    if premine_to is not None:
        from ..utils import address_to_public_key_hash

        try:
            premine_pkh = Hex20(address_to_public_key_hash(premine_to))
        except (ValidationError, ValueError) as exc:
            raise UserError("invalid --premine-to address", cause=str(exc)) from exc

    # Build (and bound-validate) the deploy params; owner_pkh is a placeholder
    # here, bound to the funding key inside _deploy_dmint_inner.
    placeholder_pkh = Hex20(b"\x00" * 20)
    try:
        if v2:
            parsed_schedule = _parse_schedule(schedule) if schedule else ()
            # The V2 upper bounds, checked first so a refusal names the flag the user typed
            # (--reward, not reward_photons). DmintV2DeployParams runs the same check.
            check_v2_numeric_bounds(
                stage="deploy-dmint",
                max_height=max_height,
                reward=reward,
                difficulty=difficulty,
                daa_mode=DaaMode[daa_mode.upper()],
                target_time=target_time,
                half_life=half_life,
                epoch_length=epoch_length,
                schedule=parsed_schedule,
                names=_V2_BOUND_FLAGS,
            )
            deploy_params: DmintV1DeployParams | DmintV2DeployParams = DmintV2DeployParams(
                metadata=metadata,
                owner_pkh=placeholder_pkh,
                num_contracts=num_contracts,
                max_height=max_height,
                reward_photons=reward,
                difficulty=difficulty,
                premine_amount=premine,
                premine_pkh=premine_pkh,
                op_return_msg=op_return_bytes,
                daa_mode=DaaMode[daa_mode.upper()],
                target_time=target_time,
                half_life=half_life,
                last_time=last_time,
                epoch_length=epoch_length,
                max_adjustment_log2=_MAX_ADJUSTMENT_TO_LOG2[max_adjustment],
                schedule=parsed_schedule,
            )
        else:
            # The V1 bounds (those it shares with V2, and its 2**31 max_height), checked first for
            # the same reason: a refusal names the flag the user typed. DmintV1DeployParams runs
            # the same check.
            check_dmint_v1_bounds(
                stage="deploy-dmint", max_height=max_height, reward=reward, difficulty=difficulty, names=_V2_BOUND_FLAGS
            )
            deploy_params = DmintV1DeployParams(
                metadata=metadata,
                owner_pkh=placeholder_pkh,
                num_contracts=num_contracts,
                max_height=max_height,
                reward_photons=reward,
                difficulty=difficulty,
                premine_amount=premine,
                premine_pkh=premine_pkh,
                op_return_msg=op_return_bytes,
            )
    except ValidationError as exc:
        raise UserError("invalid dMint deploy parameters", cause=str(exc)) from exc

    wallet = _load_wallet(ctx, prompt_passphrase=passphrase)

    async def _do() -> dict:
        client = ctx.make_client()
        async with client:
            return await _deploy_dmint_inner(ctx, wallet, deploy_params, client)

    try:
        result = asyncio.run(_do())
    except NetworkError as exc:
        raise NetworkBoundaryError(
            "could not reach ElectrumX", cause=str(exc), fix=f"check that {ctx.electrumx_url} is reachable"
        ) from exc

    if ctx.output_mode == "json":
        click.echo(emit(result, mode="json"))
    elif ctx.output_mode == "quiet":
        click.echo(emit(result, mode="quiet", quiet_field="reveal_txid"))
    else:
        click.echo(f"\ndMint {result['version']} contract deployed!")
        click.echo(f"  commit txid:  {result['commit_txid']}")
        click.echo(f"  reveal txid:  {result['reveal_txid']}")
        click.echo(f"  token_ref:    {result['token_ref']}")
        if result["version"] == "V2":
            click.echo(f"  daa_mode:     {result['daa_mode']}")
        click.echo(f"  contracts ({result['num_contracts']}):")
        for outpoint in result["contracts"]:
            click.echo(f"    {outpoint}")
        if result["premine"]:
            click.echo(f"  premine:      {result['premine']:,} photons at {result['premine_outpoint']}")
        click.echo(f"  total supply: {result['total_supply']:,} photons")
        # claim-dmint auto-detects V1/V2 from the contract — there is NO --v2 flag.
        # EPOCH/SCHEDULE bake their params into the contract code (not the on-chain
        # state), so the claimer must re-supply them; surface that in the hint.
        _claim_hint = f"glyph claim-dmint --contract {result['contracts'][0]}"
        if v2 and daa_mode == "epoch":
            _claim_hint += f" --epoch-length {epoch_length} --max-adjustment {max_adjustment}"
        elif v2 and daa_mode == "schedule":
            _claim_hint += f" --schedule '{schedule}'"
        click.echo(f"\n  claim with:   {_claim_hint}")


async def _deploy_dmint_inner(
    ctx: CliContext,
    wallet: HdWallet,
    deploy_params: DmintV1DeployParams | DmintV2DeployParams,
    client: ElectrumXClient,
) -> dict:
    # Version-agnostic: V1 and V2 DeployResult share the commit_result /
    # build_reveal_outputs interface, so the only V1-vs-V2 difference is which
    # params class the caller built. allow_v2_deploy is ignored for V1.
    metadata = deploy_params.metadata
    num_contracts = deploy_params.num_contracts
    max_height = deploy_params.max_height
    reward = deploy_params.reward_photons
    is_v2 = isinstance(deploy_params, DmintV2DeployParams)
    builder = GlyphBuilder()

    # Size the reveal from the REAL script bytes before touching the wallet.
    # owner_pkh is still the caller's placeholder here, but nothing this needs
    # depends on it: contract script lengths and the CBOR body are owner-agnostic,
    # and the premine/change output sizes are fixed. Building here also surfaces
    # per-mode parameter errors (the EPOCH 2^48 cap, SCHEDULE shape) before the
    # user is told their wallet is too small.
    try:
        sizing = builder.prepare_dmint_deploy(deploy_params, allow_v2_deploy=True)
    except ValidationError as exc:
        raise UserError("invalid dMint deploy parameters", cause=str(exc)) from exc

    triples = await wallet.collect_spendable(client)
    if not triples:
        raise UserError("no spendable UTXOs in the wallet")

    fee_rate = ctx.fee_rate
    # The premine is REAL photons on an extra 75-byte FT output of the reveal, so it
    # widens both the value the commit must carry forward and the reveal's size.
    premine = deploy_params.premine_amount or 0
    # vout0 (FT-commit hashlock) must cover the N 1-photon carriers + the premine +
    # the reveal fee; vouts 1..N are above-dust ref-seeds that genesis each
    # contractRef when the reveal spends them.
    reveal_bytes = _estimate_dmint_reveal_bytes(
        contract_scripts=sizing.placeholder_contract_scripts,
        cbor_len=len(sizing.cbor_bytes),
        premine=bool(premine),
        op_return_len=len(deploy_params.op_return_msg or b""),
    )
    reveal_fee_estimate = reveal_bytes * fee_rate
    commit0_value = num_contracts + premine + reveal_fee_estimate + 10_000
    commit_fee_estimate = (num_contracts * 40 + 300) * fee_rate
    # + one uneconomic-change floor so the funding UTXO can still emit change.
    total_required = commit0_value + num_contracts * _DMINT_REF_SEED + commit_fee_estimate + DUST_THRESHOLD_PHOTONS

    triples.sort(key=lambda t: t[0].value, reverse=True)
    funding = next((t for t in triples if t[0].value >= total_required), None)
    if funding is None:
        raise UserError(
            "no single UTXO is large enough to fund the dMint deploy",
            cause=f"need >= {total_required:,} photons in one UTXO; largest is {triples[0][0].value:,}",
            fix="consolidate UTXOs first, or fund the wallet from a single source",
        )
    funding_utxo, funding_addr, owner_key = funding
    owner_pkh = Hex20(owner_key.public_key().hash160())
    owner_spk = P2PKH().lock(funding_addr)

    # The owner_pkh on the params object was a placeholder (validated upfront);
    # bind it to the actual funding key now.
    deploy_params = replace(deploy_params, owner_pkh=owner_pkh)
    # Rebuild with the real owner. Same script lengths as the sizing pass above
    # (only the embedded PKH and the ref txids differ), so `reveal_bytes` still
    # describes the transaction that gets built below.
    try:
        deploy = builder.prepare_dmint_deploy(deploy_params, allow_v2_deploy=True)
    except ValidationError as exc:
        raise UserError("invalid dMint deploy parameters", cause=str(exc)) from exc
    commit_script = deploy.commit_result.commit_script

    # --- commit tx: [FT-commit hashlock | N ref-seeds | change] ---
    # The source shim must place the funding output at funding_utxo.tx_pos
    # (the largest wallet UTXO is often change at vout != 0); both
    # TransactionInput.__init__ and fee() index source_transaction.outputs[tx_pos].
    src_outs = [TransactionOutput(Script(b""), 0) for _ in range(funding_utxo.tx_pos)]
    src_outs.append(TransactionOutput(owner_spk, funding_utxo.value))
    src_tx = Transaction(tx_inputs=[], tx_outputs=src_outs)
    src_tx.txid = lambda: funding_utxo.tx_hash  # type: ignore[method-assign]
    commit_input = TransactionInput(
        source_transaction=src_tx,
        source_txid=funding_utxo.tx_hash,
        source_output_index=funding_utxo.tx_pos,
        unlocking_script_template=P2PKH().unlock(owner_key),
    )
    commit_input.satoshis = funding_utxo.value
    commit_input.locking_script = owner_spk

    # change=True lets fee() size the fee from the real serialized length and
    # fill the change (mixing a manual change output with fee() ZeroDivisions
    # when change_count==0 and the residual is positive).
    commit_outputs = [TransactionOutput(Script(commit_script), commit0_value)]
    commit_outputs += [TransactionOutput(owner_spk, _DMINT_REF_SEED) for _ in range(num_contracts)]
    commit_outputs.append(TransactionOutput(owner_spk, 0, change=True))
    commit_tx = Transaction(tx_inputs=[commit_input], tx_outputs=commit_outputs)
    commit_tx.fee(SatoshisPerKilobyte(fee_rate * 1000))
    commit_tx.sign()

    _confirm_or_abort(
        ctx,
        [
            _metadata_summary(metadata),
            _BroadcastSummary(
                title="Commit (dMint deploy)",
                lines=[
                    f"funding utxo:  {funding_utxo.tx_hash}:{funding_utxo.tx_pos} ({funding_utxo.value:,} photons)",
                    f"contracts:     {num_contracts}  (reward {reward:,}/mint, max_height {max_height:,})",
                    f"owner_pkh:     {owner_pkh.hex()}  (this wallet)",
                    *(
                        [
                            f"premine:       {premine:,} photons -> "
                            f"{(deploy_params.premine_pkh or owner_pkh).hex()}"
                            "  (funded by you, on top of the mineable supply)"
                        ]
                        if premine
                        else []
                    ),
                    f"network:       {ctx.network}",
                ],
            ),
        ],
    )
    _echoed_commit = await client.broadcast(commit_tx.serialize())
    commit_txid = _local_commit_txid(commit_tx, _echoed_commit)
    # stderr (all modes): if the reveal later fails, the confirmed commit is recoverable.
    click.echo(f"commit broadcast: {commit_txid}", err=True)
    if ctx.output_mode == "human":
        click.echo("waiting for confirmation (this can take 10+ minutes)...")
    await _wait_for_tx(client, str(commit_txid), interval_s=_poll_interval_for(ctx))

    # --- reveal tx: spend commit:0 (tokenRef + CBOR) AND commit:1..N (contractRefs) ---
    rev = deploy.build_reveal_outputs(str(commit_txid))
    # Use commit_tx.outputs (post-fee): the FT-commit (idx 0) + ref-seeds (1..N)
    # keep stable values/indices even if fee() dropped a dust change output.
    shim_commit = Transaction(tx_inputs=[], tx_outputs=list(commit_tx.outputs))
    shim_commit.txid = lambda: str(commit_txid)  # type: ignore[method-assign]

    rin0 = TransactionInput(
        source_transaction=shim_commit,
        source_output_index=0,
        unlocking_script_template=_build_glyph_unlock(owner_key, rev.scriptsig_suffix),
    )
    rin0.satoshis = commit0_value
    rin0.locking_script = Script(commit_script)
    reveal_inputs = [rin0]
    for i in range(num_contracts):
        rin = TransactionInput(
            source_transaction=shim_commit,
            source_output_index=i + 1,
            unlocking_script_template=P2PKH().unlock(owner_key),
        )
        rin.satoshis = _DMINT_REF_SEED
        rin.locking_script = owner_spk
        reveal_inputs.append(rin)

    # Output order is fixed by DmintV1RevealScripts (Photonic createRevealOutputs
    # parity): N contracts, then the premine, then OP_RETURN, then change.
    reveal_outputs = [
        TransactionOutput(Script(rev.contract_scripts[i]), rev.contract_value) for i in range(num_contracts)
    ]
    premine_vout: int | None = None
    if rev.premine_script is not None and rev.premine_amount:
        premine_vout = len(reveal_outputs)
        reveal_outputs.append(TransactionOutput(Script(rev.premine_script), rev.premine_amount))
    if rev.op_return_script:
        reveal_outputs.append(TransactionOutput(Script(rev.op_return_script), 0))
    reveal_outputs.append(TransactionOutput(owner_spk, 0, change=True))
    reveal_tx = Transaction(tx_inputs=reveal_inputs, tx_outputs=reveal_outputs)
    reveal_tx.fee(SatoshisPerKilobyte(fee_rate * 1000))
    reveal_tx.sign()

    _confirm_or_abort(
        ctx,
        [
            _BroadcastSummary(
                title="Reveal (dMint contract genesis)",
                lines=[
                    f"commit txid: {commit_txid}",
                    f"contracts:   {num_contracts} x 1-photon singleton",
                    f"token_ref:   {commit_txid}:0",
                    *([f"premine:     {premine:,} photons at vout {premine_vout}"] if premine else []),
                ],
            ),
        ],
    )
    _echoed_reveal = await client.broadcast(reveal_tx.serialize())
    reveal_txid = _confirmed_reveal_txid(reveal_tx, _echoed_reveal)
    mineable_supply = reward * max_height * num_contracts
    return {
        "version": "V2" if is_v2 else "V1",
        "daa_mode": deploy_params.daa_mode.name if is_v2 else "FIXED",
        "commit_txid": str(commit_txid),
        "reveal_txid": str(reveal_txid),
        "token_ref": f"{commit_txid}:0",
        "contracts": [f"{reveal_txid}:{i}" for i in range(num_contracts)],
        "num_contracts": num_contracts,
        "premine": premine,
        "premine_outpoint": f"{reveal_txid}:{premine_vout}" if premine_vout is not None else None,
        "mineable_supply": mineable_supply,
        "total_supply": mineable_supply + premine,
    }


# ---------------------------------------------------------------------------
# claim-dmint (PoW-mine a claim from a live contract)
# ---------------------------------------------------------------------------


def _resolve_miner_choice(miner_cmd: str | None) -> tuple[str, list[str] | None]:
    """Resolve --miner-cmd to a ``(kind, argv)`` pair.

    * ``None`` (default) -> ``("parallel", None)``: the bundled parallel miner,
      run **in this process** via ``pyrxd.contrib.miner.parallel.mine``. Same
      workers, same hashing, same full nonce-space sweep as before; what
      changes is that the parent can now read the shared attempts counter and
      stream live hash rate + ETA. Spawned workers get only the pickled search
      arguments (``spawn``, not ``fork``), so no wallet key material reaches
      them.
    * ``"in-process"`` -> ``("sequential", None)``: the slow single-threaded
      reference miner. Retained because it is the only miner with no
      multiprocessing at all.
    * anything else -> ``("external", shlex.split(...))``: a user-supplied
      binary over the JSON-over-stdio protocol. Live progress here depends
      on the miner: the protocol carries OPTIONAL progress frames on
      stderr (added after 0.13.0 — see ``docs/concepts/parallel-mining.md``),
      so an updated third-party miner streams the same way the in-process
      paths do; an older one that has never heard of progress frames just
      stays silent until it finishes, which still works exactly as before.
      ``--miner-cmd "python -m pyrxd.contrib.miner"`` still reaches the
      bundled miner over that protocol if subprocess isolation is wanted
      (and now streams progress too — it's the reference implementation
      of the extension).

    Before this, ``None`` meant "spawn the bundled miner as a subprocess". The
    reason for that default was nonce-space coverage (the sequential miner's
    ``DEFAULT_MAX_ATTEMPTS`` is < 2**32 and would sweep only part of the V1
    space) — which the in-process parallel miner satisfies identically.
    """
    if miner_cmd is None:
        return "parallel", None
    if miner_cmd == "in-process":
        return "sequential", None
    return "external", shlex.split(miner_cmd)


def _mine_bundled_parallel(
    preimage: bytes,
    target: int,
    *,
    nonce_width: int,
    workers: int,
    progress: Callable[[int, float], None] | None,
    algo: DmintAlgo = DmintAlgo.SHA256D,
) -> bytes:
    """Run the bundled parallel miner in this process and return the nonce.

    Imported lazily: ``pyrxd.glyph.dmint`` deliberately does not depend on
    ``pyrxd.contrib``, so the bridge between the two lives at the CLI edge.

    Sweeps the whole nonce space (``2**(8*nonce_width)``); exhaustion becomes
    :class:`MaxAttemptsError`, which is what the V1 reroll loop expects, and
    matches what the external miner's exit-code-2 path already raises.

    The bundled miner computes SHA256d only and ``MineParams`` has no algorithm field, so
    ``algo`` (the contract's) is checked here: anything else raises ``NotImplementedError``
    before a worker starts. ``_claim_prepare`` refuses such contracts first; this is the
    second line.
    """
    if algo is not DmintAlgo.SHA256D:
        raise NotImplementedError(
            f"the bundled parallel miner grinds SHA256d only; this contract's proof of work is {algo.name}"
        )
    from ..contrib.miner.parallel import MineParams, mine
    from ..contrib.miner.protocol import MineSuccess

    nonce_max = 2 ** (nonce_width * 8)
    try:
        result = mine(
            MineParams(
                preimage=preimage,
                target=target,
                nonce_width=nonce_width,
                n_workers=workers,
                nonce_max=nonce_max,
            ),
            progress=progress,
        )
    except RuntimeError as exc:  # workers died before finishing their slices
        raise UserError(
            "the bundled parallel miner could not run its workers",
            cause=str(exc),
            fix="retry with --miner-cmd 'in-process' (single-threaded, no worker processes), or point --miner-cmd at an external miner",
        ) from exc
    if not isinstance(result, MineSuccess):
        raise MaxAttemptsError(
            f"the bundled parallel miner swept the {nonce_width}-byte nonce space without a solution",
            attempts=nonce_max,
            elapsed_s=0.0,
        )
    return result.nonce


def _mine_claim_with_rerolls(
    contract: DmintContractUtxo,
    funding: DmintMinerFundingUtxo,
    miner_pkh: bytes,
    op_return_base: bytes,
    fee_rate: int,
    *,
    mine: Callable[[bytes, int], bytes],
    max_rerolls: int,
    miner_kind: str = "parallel",
) -> tuple[DmintMintResult, PowPreimageResult, bytes]:
    """Reroll the OP_RETURN until a nonce is found; return (mint_result, preimage_result, nonce).

    V1's 4-byte nonce space has only ~39% chance of containing a solution per
    preimage at difficulty 1, so real miners reroll a preimage-bound field on
    exhaustion. Each attempt builds a FRESH mint shell + preimage (the scriptSig
    hashes must come from the same build_dmint_v1_mint_preimage call). ``mine``
    is injected so the loop is unit-testable without a real grind; it raises
    MaxAttemptsError on a swept-without-hit preimage.

    The rerolls are deterministic — reroll ``i`` grinds ``op_return_base`` with ``i`` appended
    — so a rerun with the same ``--op-return`` repeats every search this run made before it
    tries a new one. The advice when all rerolls fail says so, and names ``--timeout`` only
    when some grind was actually stopped by the clock (a swept nonce space is not helped by
    more time) and ``--max-attempts`` only for the in-process miner, the one it reaches.
    """
    stopped_by_clock = 0
    for attempt in range(max_rerolls):
        op_msg = op_return_base + attempt.to_bytes(4, "big")
        mint = build_dmint_mint_tx(
            contract,
            nonce=b"\x00" * 4,
            miner_pkh=miner_pkh,
            current_time=0,
            fee_rate=fee_rate,
            funding_utxo=funding,
            op_return_msg=op_msg,
        )
        pre = build_dmint_v1_mint_preimage(contract, funding, mint.tx)
        try:
            nonce = mine(pre.preimage, contract.state.target)
        except MaxAttemptsError as exc:
            stopped_by_clock += _stopped_by_clock(exc)
            continue
        return mint, pre, nonce
    shown = op_return_base.decode("utf-8", errors="replace")
    fix = [
        f"pass a different --op-return (this run used {shown!r}): reroll i grinds that value with i appended, so a "
        f"rerun with the same one repeats these {max_rerolls} searches before it tries a new one; --max-rerolls adds "
        "rerolls after them"
    ]
    if stopped_by_clock:
        fix.append(
            f"{stopped_by_clock} of the {max_rerolls} grinds stopped at --timeout before covering their nonce range, "
            "so a longer --timeout lets each search further"
        )
    if miner_kind == "sequential":
        fix.append("--max-attempts raises the in-process miner's cap on each grind")
    fix.append("a faster --miner-cmd shortens every grind")
    raise UserError(f"no nonce found within {max_rerolls} preimage rerolls", fix="; ".join(fix))


def _stopped_by_clock(exc: MaxAttemptsError) -> bool:
    """Did this grind end because the wall clock ran out, not because a count did?

    The bundled and in-process miners stop at ``--timeout`` by raising :class:`MiningDeadline`
    out of the progress callback (``_mine`` chains it as the cause), and an external miner's
    timeout is the ``subprocess.TimeoutExpired`` that :func:`mine_solution_external` chains.
    Anything else — the in-process ``--max-attempts`` cap, or a miner that swept its nonce
    space — is a count.
    """
    from subprocess import TimeoutExpired  # nosec B404 — exception class only; spawns nothing

    return isinstance(exc.__cause__, (MiningDeadline, TimeoutExpired))


def _v2_claim_daa_kwargs(
    daa_mode: DaaMode, epoch_length: int, max_adjustment: str, schedule: str | None, half_life: int | None
) -> dict:
    """The DAA params build_dmint_mint_tx needs for a V2 claim.

    EPOCH's epoch_length/max_adjustment and the SCHEDULE entries bake into the contract
    code (not the parsed state) and pyrxd ships no reader for them, so the claimer must
    re-supply those (``build_dmint_mint_tx`` fails fast if they do not reproduce the baked
    bytecode). ASERT's half_life IS readable from the bytecode, so ``None`` is forwarded
    unchanged and the builder uses the detected value."""
    if daa_mode == DaaMode.ASERT:
        return {"half_life": half_life}
    if daa_mode == DaaMode.EPOCH:
        return {"epoch_length": epoch_length, "max_adjustment_log2": _MAX_ADJUSTMENT_TO_LOG2[max_adjustment]}
    if daa_mode == DaaMode.SCHEDULE:
        if not schedule:
            raise UserError(
                "claiming a SCHEDULE contract requires --schedule (the contract's baked schedule)",
                fix="pass the same --schedule JSON used at deploy, e.g. --schedule '[[100, 4]]'",
            )
        return {"schedule": _parse_schedule(schedule)}
    return {}  # FIXED / LWMA need no extra params


def _mine_claim_v2(
    contract: DmintContractUtxo,
    funding: DmintMinerFundingUtxo,
    miner_pkh: bytes,
    op_return_base: bytes,
    fee_rate: int,
    current_time: int,
    daa_kwargs: dict,
    *,
    mine: Callable[[bytes, int], bytes],
) -> tuple[DmintMintResult, PowPreimageResult, bytes]:
    """Build + mine a V2 claim: 8-byte nonce, single ~2**32 sweep (the wide nonce
    space always contains a solution, so no preimage rerolls like V1). The recreated
    state advances height/lastTime/target per the contract's DAA mode."""
    mint = build_dmint_mint_tx(
        contract,
        nonce=b"\x00" * 8,
        miner_pkh=miner_pkh,
        current_time=current_time,
        fee_rate=fee_rate,
        funding_utxo=funding,
        op_return_msg=op_return_base,
        **daa_kwargs,
    )
    op_return_script = mint.tx.outputs[2].locking_script.script
    pre = build_dmint_v2_mint_preimage(contract, funding, op_return_script)
    nonce = mine(pre.preimage, contract.state.target)
    return mint, pre, nonce


@glyph_group.command(name="claim-dmint")
@click.option("--contract", default=None, help="Live contract UTXO as TXID:VOUT (direct).")
@click.option("--token-ref", "token_ref", default=None, help="Token ref TXID:0 to auto-discover a live contract.")
@click.option(
    "--op-return",
    "op_return",
    default="pyrxd-mint",
    show_default=True,
    help=(
        "Base OP_RETURN message; part of the proof-of-work preimage. V1 claims append a reroll "
        "counter to it when a grind ends without a nonce; V2 claims use it as given."
    ),
)
@click.option(
    "--miner-cmd",
    default=None,
    help="External miner argv (shlex). Default: the bundled parallel miner, in-process with live progress. 'in-process' forces the slow single-threaded miner.",
)
@click.option(
    "--timeout",
    "timeout_s",
    type=float,
    default=600.0,
    show_default=True,
    help="Wall-clock cap on one mining grind (s). Applies to every miner; on nonce exhaustion or timeout, V1 rerolls the OP_RETURN and starts a fresh grind.",
)
@click.option(
    "--workers",
    type=int,
    default=None,
    help="Parallel miner worker count [default: one per logical CPU].",
)
@click.option(
    "--progress/--no-progress",
    default=True,
    show_default=True,
    help="Stream live hash rate + remaining-time quantiles to stderr while mining (stdout stays clean).",
)
@click.option("--max-attempts", type=int, default=None, help="In-process nonce cap (default: the library default).")
@click.option(
    "--max-rerolls", type=int, default=40, show_default=True, help="V1: preimage rerolls on nonce-space exhaustion."
)
@click.option(
    "--reward-address",
    default=None,
    help="Wallet address that funds the mint and receives the FT reward + change. Default: the wallet address with the largest UTXO (pass this explicitly if that address holds no plain RXD).",
)
@click.option(
    "--current-time",
    type=int,
    default=None,
    help=(
        "V2 only: the mint's locktime, written into the recreated state's lastTime and used by the "
        "DAA retarget. Default: the wall-clock time when the claim is built — leave it unset. If you "
        "pass it, pass a real Unix timestamp at or after the contract's lastTime."
    ),
)
@click.option(
    "--epoch-length", type=int, default=2016, show_default=True, help="V2 EPOCH claim: the contract's epoch length."
)
@click.option(
    "--max-adjustment",
    type=click.Choice(["2", "4", "8", "16"]),
    default="4",
    show_default=True,
    help="V2 EPOCH claim: the contract's max adjustment.",
)
@click.option(
    "--schedule", default=None, help="V2 SCHEDULE claim: the contract's schedule as JSON [[height, difficulty], ...]."
)
@click.option(
    "--half-life",
    type=int,
    default=None,
    help=(
        "V2 ASERT claim: the contract's half-life (s). Omit it — the default is to READ the value "
        "out of the contract's own bytecode, which is the only value that can work. Pass it only to "
        "assert what you expect: a supplied value that disagrees with the baked one fails fast, "
        "naming the baked value, before the PoW grind."
    ),
)
@click.option("--passphrase/--no-passphrase", default=False)
@click.pass_obj
def claim_dmint_cmd(
    ctx: CliContext,
    contract: str | None,
    token_ref: str | None,
    op_return: str,
    miner_cmd: str | None,
    timeout_s: float,
    workers: int | None,
    progress: bool,
    max_attempts: int | None,
    max_rerolls: int,
    reward_address: str | None,
    current_time: int | None,
    epoch_length: int,
    max_adjustment: str,
    schedule: str | None,
    half_life: int | None,
    passphrase: bool,
) -> None:
    """PoW-mine a claim from a live dMint contract (V1 or V2) and broadcast the mint.

    Locate the contract (``--contract TXID:VOUT`` or ``--token-ref TXID:0``),
    fund the mint from this wallet, mine a nonce (rerolling the OP_RETURN on
    exhaustion, the way real miners do), and broadcast. The FT reward + change
    go to ``--reward-address`` (default: the wallet's largest-UTXO address).

    While mining, live hash rate and remaining-time quantiles stream to stderr
    (``--no-progress`` to silence). The remaining-time figures are a memoryless
    distribution, not a countdown: hashes already spent do not shorten what is
    left. Run ``pyrxd glyph dmint-estimate`` first for the same numbers before
    committing to the grind.
    """
    if (contract is None) == (token_ref is None):
        raise UserError("pass exactly one of --contract TXID:VOUT or --token-ref TXID:0")
    miner_kind, miner_argv = _resolve_miner_choice(miner_cmd)
    if workers is not None and workers < 1:
        raise UserError(f"--workers must be >= 1, got {workers}")
    op_return_base = op_return.encode("utf-8")

    wallet = _load_wallet(ctx, prompt_passphrase=passphrase)

    async def _read() -> tuple[DmintContractUtxo, DmintMinerFundingUtxo, PrivateKey, bytes]:
        client = ctx.make_client()
        async with client:
            return await _claim_prepare(ctx, wallet, contract, token_ref, reward_address, client)

    try:
        contract_utxo, funding, miner_key, miner_pkh = asyncio.run(_read())
    except NetworkError as exc:
        raise NetworkBoundaryError(
            "could not reach ElectrumX", cause=str(exc), fix=f"check that {ctx.electrumx_url} is reachable"
        ) from exc

    # Gate ONCE here — before the multi-minute grind. All value facts (contract,
    # funding, reward, network) are known now; only the final txid/nonce are not.
    # This fails fast for --json-without--yes and avoids a hostile re-prompt after
    # a long walk-away. (Deviation from the per-broadcast gate; see the module docstring.)
    summary_lines = [
        f"contract:    {contract_utxo.txid}:{contract_utxo.vout} (height {contract_utxo.state.height} -> {contract_utxo.state.height + 1})",
        f"reward:      {contract_utxo.state.reward:,} photons of the FT",
        f"funding:     {funding.txid}:{funding.vout} ({funding.value:,} photons)",
        f"network:     {ctx.network}",
    ]
    if contract_utxo.state.next_mint_is_final:
        summary_lines.append(
            f"final mint:  height {contract_utxo.state.max_height} is this contract's last; this mint burns "
            "the contract output, so nothing can mint it afterwards"
        )
    _confirm_or_abort(ctx, [_BroadcastSummary(title="Mint (dMint claim)", lines=summary_lines)])

    is_v2 = not contract_utxo.state.is_v1
    nonce_width = 8 if is_v2 else 4

    if miner_kind == "parallel":
        from ..contrib.miner.parallel import default_n_workers

        n_workers = default_n_workers() if workers is None else workers
    else:
        n_workers = workers or 1
    if miner_kind == "external" and progress:
        click.echo(
            "note: live progress for an external --miner-cmd depends on the miner emitting "
            "the optional stderr progress frames (see docs/concepts/parallel-mining.md); an "
            "older miner that doesn't know about them just stays silent until it finishes, which "
            "still works. Run 'pyrxd glyph dmint-estimate' for the up-front numbers either way.",
            err=True,
        )

    def _mine(preimage: bytes, target: int) -> bytes:
        # One reporter per grind, so each V1 reroll gets a fresh --timeout
        # budget — the same per-invocation semantics the external miner's
        # subprocess timeout has always had.
        reporter = _MiningReporter(
            estimate_attempts(target),
            enabled=progress and ctx.output_mode != "quiet",
            deadline_s=None if miner_kind == "external" else timeout_s,
        )
        try:
            if miner_kind == "parallel":
                return _mine_bundled_parallel(
                    preimage,
                    target,
                    nonce_width=nonce_width,
                    workers=n_workers,
                    progress=reporter,
                    algo=contract_utxo.state.algo,
                )
            # sequential -> mine_solution's in-process progress hook;
            # external -> mine_solution_external's stderr progress-frame
            # stream (silent no-op if the miner never emits one).
            return mine_solution_dispatch(
                preimage=preimage,
                target=target,
                nonce_width=nonce_width,
                miner_argv=miner_argv,
                max_attempts=max_attempts if max_attempts is not None else DEFAULT_MAX_ATTEMPTS,
                timeout_s=timeout_s,
                progress=reporter,
                # The contract's own algorithm, so the dispatcher refuses BLAKE3/K12 on either
                # path. _claim_prepare already refused them; this is the second line.
                algo=contract_utxo.state.algo,
            ).nonce
        except MiningDeadline as exc:
            # Same signal an external miner's timeout raises, so the V1 reroll
            # loop upstream does not need to know which miner ran.
            raise MaxAttemptsError(str(exc), attempts=0, elapsed_s=timeout_s) from exc
        finally:
            reporter.finish()

    try:
        if is_v2:
            daa_kwargs = _v2_claim_daa_kwargs(
                contract_utxo.state.daa_mode, epoch_length, max_adjustment, schedule, half_life
            )
            if current_time is None:
                # The wall clock at claim, the way a deploy stamps its own lastTime. The old
                # default, 0, wrote a lastTime the contract's next retarget could not read.
                current_time = int(time.time())
            mint, pre, nonce = _mine_claim_v2(
                contract_utxo, funding, miner_pkh, op_return_base, ctx.fee_rate, current_time, daa_kwargs, mine=_mine
            )
        else:
            mint, pre, nonce = _mine_claim_with_rerolls(
                contract_utxo,
                funding,
                miner_pkh,
                op_return_base,
                ctx.fee_rate,
                mine=_mine,
                max_rerolls=max_rerolls,
                miner_kind=miner_kind,
            )
    except UnrecognizedDaaBytecodeError as exc:
        # MUST precede the `except DmintError` below. This error is BOTH a DmintError and
        # a ValidationError, and except clauses are tried in source order — so without
        # this clause an unrecognised-bytecode refusal was reported as "funding can't
        # cover the mint reward + fee" and the user was advised to add RXD or lower the
        # fee rate. Both wrong; no amount of funding makes an unknown retarget formula
        # mineable. (Reordering the base classes does NOT fix that: the object is a
        # DmintError either way, so the first matching clause still wins.)
        raise UserError(
            "this contract's retarget bytecode matches no DAA generation pyrxd knows",
            cause=str(exc),
            fix=(
                "pyrxd will not mine under a guessed formula — the target it computed would be "
                "rejected by the covenant after the whole PoW grind. Check --contract/--token-ref "
                "points at the contract you meant; if it does, this contract was built by another "
                "implementation (or a newer one) and pyrxd needs a mirror for its formula."
            ),
        ) from exc
    except MaxAttemptsError as exc:
        # MUST precede `except DmintError` for the same reason as the clause above: a
        # MaxAttemptsError IS a DmintError, and it was reported as "funding can't cover the
        # mint reward + fee" — so a V2 grind that hit --timeout told the user to add RXD.
        # Only V2 reaches here: the V1 reroll loop turns its own exhaustion into a UserError.
        raise _grind_stopped_error(
            exc, timeout_s=timeout_s, miner_kind=miner_kind, op_return=op_return, max_attempts=max_attempts
        ) from exc
    except InvalidFundingUtxoError as exc:
        # Also a DmintError, and also reported as a funding SHORTFALL before: the cause named
        # the token on the UTXO correctly under a headline about the amount. Defensive: the
        # funding scan in _claim_prepare already skips token-bearing UTXOs, so no claim-dmint
        # run is known to reach this — it maps the mint builder's own second line of defence.
        raise UserError(
            "the funding UTXO carries a token and cannot pay for the mint",
            cause=str(exc),
            fix="fund the reward address with plain RXD, or pass --reward-address naming an address that holds some",
        ) from exc
    except DmintError as exc:  # PoolTooSmallError: funding can't cover reward + fee + dust
        # claim-dmint has no --fee-rate flag: the rate is the configured one (fee_rate in the
        # pyrxd config, or PYRXD_FEE_RATE). The fix used to say "lower --fee-rate", and then
        # "lower the configured fee_rate" — which cannot be done on the default config, whose
        # rate IS the relay floor (validated_fee_rate refuses anything below it).
        raise UserError(
            "funding can't cover the mint reward + fee",
            cause=str(exc),
            fix=(
                "fund the reward address with one plain-RXD UTXO of at least the reward + the fee above "
                f"+ {DUST_THRESHOLD_PHOTONS} photons. The fee is the mint's size times the configured "
                "fee_rate: if fee_rate or PYRXD_FEE_RATE is set above the relay floor, lowering it "
                "lowers the fee"
            ),
        ) from exc
    except ValidationError as exc:  # the A1 non-1-photon-carrier guard, or a rejected miner solution
        raise UserError("could not build a valid mint", cause=str(exc)) from exc

    mint.tx.inputs[0].unlocking_script = Script(
        build_mint_scriptsig(nonce, pre.input_hash, pre.output_hash, nonce_width=nonce_width)
    )
    _sign_funding_input(mint.tx, 1, miner_key)
    raw_hex = mint.tx.serialize().hex()
    # Always surface the raw hex on stderr (recovery), keeping stdout clean for --json.
    click.echo(f"signed mint tx: {raw_hex}", err=True)

    async def _broadcast() -> str:
        client = ctx.make_client()
        async with client:
            return str(await client.broadcast(mint.tx.serialize()))

    try:
        mint_txid = asyncio.run(_broadcast())
    except NetworkError as exc:
        raise NetworkBoundaryError(
            "could not broadcast the mint",
            cause=str(exc),
            fix=f"re-broadcast the signed hex (stderr) via {ctx.electrumx_url}",
        ) from exc

    result = {
        "txid": mint_txid,
        "contract": f"{contract_utxo.txid}:{contract_utxo.vout}",
        "reward": contract_utxo.state.reward,
        "new_height": contract_utxo.state.height + 1,
        # From the transaction actually built, not re-derived: output 0 is the burn.
        "final_mint": mint.is_final_mint,
    }
    if ctx.output_mode == "json":
        click.echo(emit(result, mode="json"))
    elif ctx.output_mode == "quiet":
        click.echo(emit(result, mode="quiet", quiet_field="txid"))
    else:
        click.echo("\ndMint claimed!")
        click.echo(f"  mint txid:  {mint_txid}")
        if mint.is_final_mint:
            click.echo(
                f"  reward:     {contract_utxo.state.reward:,} photons (the final mint: height "
                f"{result['new_height']} of {contract_utxo.state.max_height}; this transaction burns the "
                "contract output, so the contract cannot be minted again)"
            )
        else:
            click.echo(
                f"  reward:     {contract_utxo.state.reward:,} photons (contract now at height {result['new_height']})"
            )


def _grind_stopped_error(
    exc: MaxAttemptsError, *, timeout_s: float, miner_kind: str, op_return: str, max_attempts: int | None
) -> UserError:
    """The claim-dmint error for a PoW grind that ended without a nonce.

    A wall-clock stop is told apart from a count-based one by :func:`_stopped_by_clock`.

    The count-based remedy has to change what the miner searches. The V2 preimage is
    ``SHA256(contract txid || contractRef) || SHA256(SHA256d(funding script) ||
    SHA256d(OP_RETURN script))`` (:func:`build_dmint_v2_mint_preimage`): it binds the contract,
    the funding script and the OP_RETURN, so re-running with the same inputs hands the miner
    the same preimage — and the in-process miner sweeps from nonce 0 again. A different
    ``--op-return`` changes the preimage, whichever miner runs; ``--max-attempts`` only reaches
    the in-process miner.
    """
    if _stopped_by_clock(exc):
        return UserError(
            f"mining timed out after {timeout_s:g}s without finding a nonce",
            cause=str(exc),
            fix=(
                f"allow a longer grind with --timeout SECONDS (this run allowed {timeout_s:g}); "
                "`pyrxd glyph dmint-estimate` shows how long this contract's target is likely to take "
                "here, and a faster --miner-cmd shortens it"
            ),
        )
    fresh = (
        f"pass a different --op-return (this run used {op_return!r}): the proof-of-work preimage binds the "
        "contract, the funding script and the OP_RETURN, so a new value is a new search, and re-running with "
        "the same inputs hands the miner this same preimage again"
    )
    if miner_kind == "sequential":
        allowed = max_attempts if max_attempts is not None else DEFAULT_MAX_ATTEMPTS
        fix = f"raise --max-attempts (this run allowed {allowed:,}), or {fresh}"
    else:
        fix = f"{fresh}. (--max-attempts applies only to --miner-cmd in-process.)"
    return UserError("mining stopped without finding a nonce", cause=str(exc), fix=fix)


async def _claim_prepare(
    ctx: CliContext,
    wallet: HdWallet,
    contract_arg: str | None,
    token_ref_arg: str | None,
    reward_address: str | None,
    client: ElectrumXClient,
) -> tuple[DmintContractUtxo, DmintMinerFundingUtxo, PrivateKey, bytes]:
    # 1. Resolve the live contract UTXO.
    if contract_arg is not None:
        ref = _parse_ref(contract_arg)
        contract_utxo = await _fetch_dmint_contract(client, str(ref.txid), ref.vout)
    else:
        tref = _parse_ref(token_ref_arg)  # type: ignore[arg-type]
        contracts = await find_dmint_contract_utxos(client, token_ref=tref)
        contract_utxo = next((c for c in contracts if not c.state.is_exhausted), None)  # type: ignore[assignment]
        if contract_utxo is None:
            raise UserError(
                "no live (non-exhausted) dMint contract found for that token_ref",
                fix="check the token_ref, or pass --contract TXID:VOUT directly",
            )
    if contract_utxo.state.is_exhausted:
        raise UserError(
            f"contract is exhausted (height {contract_utxo.state.height} >= max_height {contract_utxo.state.max_height})"
        )
    # Contracts pyrxd will not mint, refused here — after the contract read (the only way to
    # learn any of this) and before the wallet's UTXO scan, the funding scan, the confirmation
    # prompt and any grind. The wallet file itself is loaded (and its passphrase asked for)
    # earlier, in claim_dmint_cmd. Every locator (--contract, --token-ref), both versions and
    # every --miner-cmd reach the grind only through this function.
    never = _unmintable_reason(contract_utxo.script)
    if never is not None:
        raise UserError(
            "pyrxd will not mint this contract",
            cause=never,
            fix="nothing was ground, signed or broadcast",
        )
    algo = contract_utxo.state.algo
    if algo is not DmintAlgo.SHA256D:
        raise UserError(
            f"pyrxd cannot mine this contract: its proof of work is {algo.name}",
            cause=(
                "pyrxd's miners grind SHA256d only — the bundled parallel miner, --miner-cmd in-process, "
                "and the external-miner protocol, whose request carries no algorithm and whose answer "
                "pyrxd re-checks with SHA256d"
            ),
            fix=f"mint it with a miner that computes {algo.name}; pyrxd does not ship one",
        )

    # 2. Select the miner identity (HD wallet -> single funding/reward address).
    miner_address, miner_key = await _select_miner_identity(wallet, reward_address, client)
    miner_pkh = bytes(Hex20(miner_key.public_key().hash160()))

    # 3. Scan that address for a plain-RXD funding UTXO (excludes token-bearing UTXOs).
    needed = contract_utxo.state.reward + 10_000_000 + DUST_THRESHOLD_PHOTONS
    try:
        funding = await find_dmint_funding_utxo(client, miner_address, needed)
    except (DmintError, ValidationError) as exc:  # InvalidFundingUtxoError is a DmintError, not a ValidationError
        raise UserError(
            "could not find a plain-RXD funding UTXO for the mint",
            cause=str(exc),
            fix=f"fund {miner_address} with >= {needed:,} photons of plain RXD, or pass --reward-address",
        ) from exc
    return contract_utxo, funding, miner_key, miner_pkh


async def _select_miner_identity(
    wallet: HdWallet, reward_address: str | None, client: ElectrumXClient
) -> tuple[str, PrivateKey]:
    triples = await wallet.collect_spendable(client)
    if not triples:
        raise UserError("no spendable UTXOs in the wallet to fund the mint")
    if reward_address is not None:
        match = next((t for t in triples if t[1] == reward_address), None)
        if match is None:
            raise UserError(f"--reward-address {reward_address} is not a wallet address with spendable UTXOs")
        return match[1], match[2]
    triples.sort(key=lambda t: t[0].value, reverse=True)
    return triples[0][1], triples[0][2]


def _sign_funding_input(tx: Transaction, idx: int, key: PrivateKey) -> None:
    """Sign a P2PKH funding input (vin[1] of the mint); vin[0] is the contract scriptSig."""
    sig = key.sign(tx.preimage(idx))
    sighash = tx.inputs[idx].sighash
    pub = key.public_key().serialize()
    tx.inputs[idx].unlocking_script = Script(
        encode_pushdata(sig + sighash.to_bytes(1, "little")) + encode_pushdata(pub)
    )


__all__ = [
    "airdrop_ft_cmd",
    "claim_dmint_cmd",
    "deploy_dmint_cmd",
    "deploy_ft_cmd",
    "glyph_group",
    "init_metadata_cmd",
    "inspect_cmd",
    "list_cmd",
    "mint_nft_cmd",
    "timelock_mint_cmd",
    "timelock_reveal_cmd",
    "transfer_ft_cmd",
    "transfer_nft_cmd",
]
