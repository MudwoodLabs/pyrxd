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
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING

import click

from ..constants import DUST_THRESHOLD_PHOTONS, MAX_OP_RETURN_MSG_BYTES, Network
from ..fee_models import SatoshisPerKilobyte
from ..glyph.builder import (
    AirdropFunding,
    AirdropRecipient,
    CommitParams,
    DmintV1DeployParams,
    DmintV2DeployParams,
    FtAirdropParams,
    FtDeployRevealScripts,
    FtUtxo,
    GlyphBuilder,
    RevealParams,
    RevealScripts,
)
from ..glyph.dmint import (
    DEFAULT_MAX_ATTEMPTS,
    MAX_SHA256D_TARGET,
    DaaMode,
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
from ..glyph.fees import (
    RevealFeeEstimate,
    check_reveal_funding,
    commit_value_for_reveal,
    estimate_reveal_fee_for_metadata,
    measure_reveal_fee,
)
from ..glyph.scanner import GlyphScanner
from ..glyph.transfer import NoFeeFundingError, NoHoldingsError
from ..glyph.transfer import build_ft_transfer as lib_build_ft_transfer
from ..glyph.transfer import build_nft_transfer as lib_build_nft_transfer
from ..glyph.transfer import find_plain_rxd_utxo as lib_find_plain_rxd_utxo
from ..glyph.transfer import ft_funding as lib_ft_funding
from ..glyph.transfer import select_ft_inputs as lib_select_ft_inputs
from ..glyph.transfer import single_ft_signing_key as lib_single_ft_signing_key
from ..glyph.types import GlyphFt, GlyphMetadata, GlyphNft, GlyphProtocol, GlyphRef
from ..hd.wallet import HdWallet
from ..network.confirm import wait_for_confirmation
from ..script.script import Script
from ..script.type import P2PKH, encode_pushdata
from ..security.errors import (
    ConfirmationTimeoutError,
    DmintError,
    InsufficientFundsError,
    MaxAttemptsError,
    NetworkError,
    PolicyRejection,
    ValidationError,
)
from ..security.types import Hex20, Txid
from ..transaction.transaction import Transaction
from ..transaction.transaction_input import TransactionInput
from ..transaction.transaction_output import TransactionOutput
from ..utils import validate_address
from .context import CliContext
from .errors import NetworkBoundaryError, UserError
from .format import emit, emit_table
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
    from collections.abc import Callable

    from ..glyph.dmint import DmintMintResult, PowPreimageResult
    from ..keys import PrivateKey
    from ..network.electrumx import ElectrumXClient, UtxoRecord


# ---------------------------------------------------------------------------
# Group registration
# ---------------------------------------------------------------------------


@click.group(name="glyph")
def glyph_group() -> None:
    """Mint, transfer, and inspect Glyph tokens."""


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
@click.pass_obj
def mint_nft_cmd(ctx: CliContext, metadata_file: Path, passphrase: bool) -> None:
    """Mint a Glyph NFT via two-phase commit + reveal.

    Builds and broadcasts the commit transaction, polls for
    confirmation, then builds and broadcasts the reveal. Both txs
    require a separate confirmation in human mode (or a single
    --yes for both in scripted mode).
    """
    metadata = _read_metadata_file(metadata_file)
    if GlyphProtocol.NFT not in metadata.protocol:
        raise UserError(
            "metadata.protocol does not include NFT",
            cause=f"got protocol={list(metadata.protocol)}",
            fix='set "protocol": ["NFT"] (or ["NFT", "MUT"], etc.) in the metadata file',
        )
    wallet = _load_wallet(ctx, prompt_passphrase=passphrase)

    async def _do_mint() -> dict:
        client = ctx.make_client()
        async with client:
            return await _mint_nft_inner(ctx, wallet, metadata, client)

    try:
        result = asyncio.run(_do_mint())
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
        click.echo("\nNFT minted!")
        click.echo(f"  commit txid: {result['commit_txid']}")
        click.echo(f"  reveal txid: {result['reveal_txid']}")
        click.echo(f"  glyph ref:   {result['ref']}")


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


def _assert_reveal_is_fundable(
    commit_value: int,
    carrier_value: int,
    reveal_tx: Transaction,
    fee_rate: int,
    cbor_bytes_len: int,
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

    Returns the measured estimate so the caller can display the real number. Raises
    :class:`UserError` naming the shortfall while the money is still in the wallet,
    instead of leaving a rejected reveal and a commit output nothing can spend.
    """
    measured = measure_reveal_fee(reveal_tx, fee_rate=fee_rate, cbor_bytes_len=cbor_bytes_len)
    try:
        check_reveal_funding(commit_value=commit_value, carrier_value=carrier_value, estimate=measured)
    except InsufficientFundsError as exc:
        raise UserError(
            "commit value cannot cover the reveal fee — refusing to broadcast the commit",
            cause=str(exc),
            fix=("shrink the metadata (the reveal scriptSig carries the whole CBOR payload) or lower --fee-rate"),
        ) from exc
    return measured


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
) -> Transaction:
    """Build (unsigned, un-fee'd) the reveal that spends the commit output.

    Shared by the pre-broadcast dry run and the real post-confirmation build so the two
    cannot diverge — a dry run that measured a *different* transaction would be worth no
    more than the tautology it replaced.
    """
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

    # The token sits on vout[0] (a dust carrier for an NFT, the whole supply for an FT
    # premine); the rest of the commit value returns as change (fee() sized from the real
    # length) instead of being burned to fee.
    return Transaction(
        tx_inputs=[reveal_input],
        tx_outputs=[
            TransactionOutput(Script(reveal_locking_script), carrier_value),
            TransactionOutput(change_locking, 0, change=True),
        ],
    )


async def _mint_nft_inner(
    ctx: CliContext,
    wallet: HdWallet,
    metadata: GlyphMetadata,
    client: ElectrumXClient,
) -> dict:
    """Heavy lifting for `glyph mint-nft`. Returns a result dict."""
    # 1) Pick a funding UTXO.
    builder = GlyphBuilder()
    triples = await wallet.collect_spendable(client)
    if not triples:
        raise UserError(
            "no spendable UTXOs in the wallet",
            cause="collect_spendable returned an empty list",
            fix="fund the wallet, or run `pyrxd balance --refresh` to discover used addresses",
        )

    # Estimate funding requirement: commit value + commit fee + reveal fee buffer.
    fee_rate = ctx.fee_rate
    # The NFT's carrier value on the reveal. Same number as
    # ``pyrxd.glyph.mint.NFT_CARRIER_VALUE``, which derives from the same constant.
    # It is a pyrxd convention, not a chain minimum: Radiant would carry the NFT on
    # 1 photon (`GetDustThreshold` returns 1) — dMint contracts do exactly that.
    carrier_value = DUST_THRESHOLD_PHOTONS
    # C-1: the reveal's scriptSig carries the whole CBOR payload, so the reveal fee
    # scales with metadata size and is paid entirely out of the commit output. Size
    # the commit from the real estimate instead of the old flat 5,000,000, which at
    # 10,000 photons/byte only covered ~230 bytes of CBOR.
    reveal_estimate = estimate_reveal_fee_for_metadata(metadata, fee_rate=fee_rate)
    commit_value = _commit_value_for_reveal(carrier_value, reveal_estimate)
    commit_fee_estimate = 300 * fee_rate  # ~300-byte commit
    # The reveal fee comes out of commit_value (sized above), so the funding UTXO needs
    # the commit value plus the commit's own fee; the extra carrier_value is slack so a
    # UTXO is not selected on an exact tie.
    total_required = commit_value + commit_fee_estimate + carrier_value

    triples.sort(key=lambda t: t[0].value, reverse=True)
    funding = next((t for t in triples if t[0].value >= total_required), None)
    if funding is None:
        raise UserError(
            "no single UTXO is large enough to fund the mint",
            cause=f"need ≥ {total_required:,} photons in one UTXO; largest is {triples[0][0].value:,}",
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

    # C-1 gate: the last point at which nothing has been spent. Once the commit is
    # broadcast an unfundable reveal strands the commit output permanently. Build the
    # reveal now, against a placeholder commit txid, and MEASURE it — an independent
    # check on the estimate that sized commit_value above.
    cbor_bytes = commit_result.cbor_bytes
    is_nft = True

    def _nft_reveal_scripts(txid: str) -> RevealScripts:
        return builder.prepare_reveal(
            RevealParams(
                commit_txid=txid,
                commit_vout=0,
                commit_value=commit_value,
                cbor_bytes=cbor_bytes,
                owner_pkh=funding_pkh,
                is_nft=is_nft,
            )
        )

    dry_run_scripts = _nft_reveal_scripts(_PLACEHOLDER_COMMIT_TXID)
    dry_run_reveal = _build_reveal_tx(
        commit_txid=_PLACEHOLDER_COMMIT_TXID,
        commit_value=commit_value,
        commit_script=commit_result.commit_script,
        reveal_locking_script=dry_run_scripts.locking_script,
        carrier_value=carrier_value,
        change_locking=locking,
        funding_key=funding_key,
        scriptsig_suffix=dry_run_scripts.scriptsig_suffix,
    )
    measured = _assert_reveal_is_fundable(commit_value, carrier_value, dry_run_reveal, fee_rate, len(cbor_bytes))

    sections = [
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
    ]
    _confirm_or_abort(ctx, sections)
    commit_txid = await client.broadcast(commit_hex)

    # 3) Poll for confirmation.
    if ctx.output_mode == "human":
        click.echo(f"\ncommit broadcast: {commit_txid}")
        click.echo("waiting for confirmation (this can take 10+ minutes)...")
    await _wait_for_tx(client, str(commit_txid))

    # 4) Build reveal — the same builder the dry run above measured, now with the real
    # commit txid (same length, so the same size and fee).
    reveal_scripts = _nft_reveal_scripts(str(commit_txid))
    reveal_tx = _build_reveal_tx(
        commit_txid=str(commit_txid),
        commit_value=commit_value,
        commit_script=commit_result.commit_script,
        reveal_locking_script=reveal_scripts.locking_script,
        carrier_value=carrier_value,
        change_locking=locking,
        funding_key=funding_key,
        scriptsig_suffix=reveal_scripts.scriptsig_suffix,
    )
    reveal_tx.fee(SatoshisPerKilobyte(fee_rate * 1000))
    reveal_tx.sign()
    reveal_hex = reveal_tx.serialize()

    _confirm_or_abort(
        ctx,
        [
            _BroadcastSummary(
                title="Reveal transaction",
                lines=[
                    f"commit txid:   {commit_txid}",
                    f"nft to:        {funding_pkh.hex()}  ({carrier_value}-photon carrier; change returned)",
                ],
            )
        ],
    )
    reveal_txid = await client.broadcast(reveal_hex)
    # The genesis ref is the COMMIT outpoint, not the reveal txid: prepare_reveal
    # embeds GlyphRef(commit_txid, commit_vout) into the reveal's locking script
    # (glyph/builder.py), and that is what extract_ref_from_{nft,ft}_script reads
    # back — so it is what `transfer-nft` / `transfer-ft` match on.
    ref = GlyphRef(txid=Txid(str(commit_txid)), vout=0)

    return {
        "commit_txid": str(commit_txid),
        "reveal_txid": str(reveal_txid),
        "ref": f"{ref.txid}:{ref.vout}",
        "owner_address": funding_addr,
    }


async def _wait_for_tx(client: ElectrumXClient, txid: str, *, timeout_s: float = 1800.0) -> None:
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
    """
    try:
        await wait_for_confirmation(client, txid, timeout_s=timeout_s)
    except ConfirmationTimeoutError as exc:
        raise NetworkBoundaryError(
            "timed out waiting for confirmation",
            cause=str(exc),
            fix=(
                "check the txid on a block explorer. Not confirmed: nothing is stranded — re-run the "
                "command. Confirmed: this CLI has no resume flag, so rebuild the reveal with the SDK — "
                "GlyphBuilder.prepare_reveal(RevealParams(commit_txid=<txid>, commit_vout=0, "
                "commit_value=<photons>, cbor_bytes=..., owner_pkh=..., is_nft=...)) using the SAME "
                "unmodified metadata file and the SAME wallet (the commit output is spendable only by a "
                "reveal carrying byte-identical metadata). See docs/how-to/troubleshoot-common-errors.md"
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
    dry_run_reveal = _build_reveal_tx(
        commit_txid=_PLACEHOLDER_COMMIT_TXID,
        commit_value=commit_value,
        commit_script=commit_result.commit_script,
        reveal_locking_script=dry_run_scripts.locking_script,
        carrier_value=carrier_value,
        change_locking=locking,
        funding_key=funding_key,
        scriptsig_suffix=dry_run_scripts.scriptsig_suffix,
    )
    measured = _assert_reveal_is_fundable(
        commit_value, carrier_value, dry_run_reveal, fee_rate, len(commit_result.cbor_bytes)
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
    commit_txid = await client.broadcast(commit_tx.serialize())

    if ctx.output_mode == "human":
        click.echo(f"\ncommit broadcast: {commit_txid}")
        click.echo("waiting for confirmation (this can take 10+ minutes)...")
    await _wait_for_tx(client, str(commit_txid))

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
    reveal_txid = await client.broadcast(reveal_tx.serialize())
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
    if not validate_address(address, network=Network(ctx.network)):
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
        return await lib_select_ft_inputs(wallet, ref, amount, client)
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
    txid = await client.broadcast(raw)
    return {"txid": str(txid), "ref": f"{ref.txid}:{ref.vout}", "amount": amount, "to": to_address}


async def _airdrop_funding(
    ctx: CliContext,
    wallet: HdWallet,
    selected: list[tuple[FtUtxo, str, PrivateKey]],
    *,
    n_outputs: int,
    client: ElectrumXClient,
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
@click.pass_obj
def airdrop_ft_cmd(
    ctx: CliContext,
    ref: str,
    to_specs: tuple[str, ...],
    recipients_path: Path | None,
    passphrase: bool,
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
            return await _airdrop_ft_inner(ctx, wallet, glyph_ref, recipients, pairs, client)

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
) -> dict:
    """FT airdrop: scan wallet, select FT utxos for ref, fund the fee, broadcast."""
    total = sum(r.amount for r in recipients)
    selected = await _select_ft_inputs(wallet, ref, total, client)
    first_key = _single_ft_signing_key(selected, "FT airdrop")

    funding = await _airdrop_funding(ctx, wallet, selected, n_outputs=len(recipients), client=client)

    params = FtAirdropParams(
        ref=ref,
        utxos=[t[0] for t in selected],
        recipients=recipients,
        private_key=first_key,
        funding=[funding],
        fee_rate=ctx.fee_rate,
    )
    try:
        airdrop_result = GlyphBuilder().build_ft_airdrop_tx(params)
    except (ValidationError, ValueError) as exc:
        raise UserError(
            "could not build the airdrop",
            cause=str(exc),
            fix="fund the wallet with more plain RXD, or split the list into smaller batches",
        ) from exc

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
    txid = await client.broadcast(airdrop_result.tx.serialize())
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
    txid = await client.broadcast(raw)
    return {"txid": str(txid), "ref": f"{ref.txid}:{ref.vout}", "to": to_address, "fee": build.fee}


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
@click.option("--max-height", type=int, required=True, help="Mints per contract [1..0xFFFFFF].")
@click.option("--reward", type=int, required=True, help="Photons of the FT paid per successful mint [1..0xFFFFFF].")
@click.option(
    "--difficulty",
    type=int,
    default=1,
    show_default=True,
    help="Initial PoW difficulty (1 = easiest; EPOCH needs >= 32768).",
)
@click.option("--target-time", type=int, default=60, show_default=True, help="V2 DAA: target seconds between mints.")
@click.option("--half-life", type=int, default=3600, show_default=True, help="V2 ASERT: half-life in seconds.")
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
                epoch_length=epoch_length,
                max_adjustment_log2=_MAX_ADJUSTMENT_TO_LOG2[max_adjustment],
                schedule=_parse_schedule(schedule) if schedule else (),
            )
        else:
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
    commit_txid = await client.broadcast(commit_tx.serialize())
    # stderr (all modes): if the reveal later fails, the confirmed commit is recoverable.
    click.echo(f"commit broadcast: {commit_txid}", err=True)
    if ctx.output_mode == "human":
        click.echo("waiting for confirmation (this can take 10+ minutes)...")
    await _wait_for_tx(client, str(commit_txid))

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
    reveal_txid = await client.broadcast(reveal_tx.serialize())
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
) -> bytes:
    """Run the bundled parallel miner in this process and return the nonce.

    Imported lazily: ``pyrxd.glyph.dmint`` deliberately does not depend on
    ``pyrxd.contrib``, so the bridge between the two lives at the CLI edge.

    Sweeps the whole nonce space (``2**(8*nonce_width)``); exhaustion becomes
    :class:`MaxAttemptsError`, which is what the V1 reroll loop expects, and
    matches what the external miner's exit-code-2 path already raises.
    """
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
) -> tuple[DmintMintResult, PowPreimageResult, bytes]:
    """Reroll the OP_RETURN until a nonce is found; return (mint_result, preimage_result, nonce).

    V1's 4-byte nonce space has only ~39% chance of containing a solution per
    preimage at difficulty 1, so real miners reroll a preimage-bound field on
    exhaustion. Each attempt builds a FRESH mint shell + preimage (the scriptSig
    hashes must come from the same build_dmint_v1_mint_preimage call). ``mine``
    is injected so the loop is unit-testable without a real grind; it raises
    MaxAttemptsError on a swept-without-hit preimage.
    """
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
        except MaxAttemptsError:
            continue
        return mint, pre, nonce
    raise UserError(
        f"no nonce found within {max_rerolls} preimage rerolls",
        fix="raise --max-rerolls or --timeout, or use a faster --miner-cmd (e.g. a GPU glyph-miner)",
    )


def _v2_claim_daa_kwargs(
    daa_mode: DaaMode, epoch_length: int, max_adjustment: str, schedule: str | None, half_life: int
) -> dict:
    """The DAA params build_dmint_mint_tx needs for a V2 claim. ASERT half_life,
    EPOCH epoch_length/max_adjustment, and the SCHEDULE entries bake into the contract
    code (not the parsed state), so the claimer must re-supply the ones their contract
    used (``build_dmint_mint_tx`` fails fast if they don't reproduce the baked bytecode)."""
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
    help="Base OP_RETURN; rerolled on nonce exhaustion.",
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
    "--max-rerolls", type=int, default=40, show_default=True, help="Preimage rerolls on nonce-space exhaustion."
)
@click.option(
    "--reward-address",
    default=None,
    help="Wallet address that funds the mint and receives the FT reward + change. Default: the wallet address with the largest UTXO (pass this explicitly if that address holds no plain RXD).",
)
@click.option(
    "--current-time",
    type=int,
    default=0,
    show_default=True,
    help="V2 only: block locktime written into the recreated state's lastTime (and the DAA retarget). 0 = always-final; for real DAA tracking pass a timestamp <= the chain's median-time-past.",
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
    "--half-life", type=int, default=3600, show_default=True, help="V2 ASERT claim: the contract's half-life (s)."
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
    current_time: int,
    epoch_length: int,
    max_adjustment: str,
    schedule: str | None,
    half_life: int,
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
    _confirm_or_abort(
        ctx,
        [
            _BroadcastSummary(
                title="Mint (dMint claim)",
                lines=[
                    f"contract:    {contract_utxo.txid}:{contract_utxo.vout} (height {contract_utxo.state.height} -> {contract_utxo.state.height + 1})",
                    f"reward:      {contract_utxo.state.reward:,} photons of the FT",
                    f"funding:     {funding.txid}:{funding.vout} ({funding.value:,} photons)",
                    f"network:     {ctx.network}",
                ],
            ),
        ],
    )

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
            mint, pre, nonce = _mine_claim_v2(
                contract_utxo, funding, miner_pkh, op_return_base, ctx.fee_rate, current_time, daa_kwargs, mine=_mine
            )
        else:
            mint, pre, nonce = _mine_claim_with_rerolls(
                contract_utxo, funding, miner_pkh, op_return_base, ctx.fee_rate, mine=_mine, max_rerolls=max_rerolls
            )
    except DmintError as exc:  # PoolTooSmallError: funding can't cover reward + fee + dust
        raise UserError(
            "funding can't cover the mint reward + fee",
            cause=str(exc),
            fix="fund the reward address with more plain RXD, or lower --fee-rate",
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
    }
    if ctx.output_mode == "json":
        click.echo(emit(result, mode="json"))
    elif ctx.output_mode == "quiet":
        click.echo(emit(result, mode="quiet", quiet_field="txid"))
    else:
        click.echo("\ndMint claimed!")
        click.echo(f"  mint txid:  {mint_txid}")
        click.echo(
            f"  reward:     {contract_utxo.state.reward:,} photons (contract now at height {result['new_height']})"
        )


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
    "transfer_ft_cmd",
    "transfer_nft_cmd",
]
