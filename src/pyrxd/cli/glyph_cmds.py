"""``pyrxd glyph …`` subcommand group — Cut 2 of the v0.3 wallet/CLI plan.

Commands:
  glyph init-metadata   Write a metadata.json scaffold for a token type.
  glyph mint-nft        Two-tx commit/reveal NFT mint.
  glyph deploy-ft       FT premine deploy (full supply at vout[0]).
  glyph deploy-dmint    V1 dMint contract genesis (commit/reveal).
  glyph claim-dmint     PoW-mine a claim from a live dMint contract.
  glyph transfer-ft     FT transfer with conservation enforcement.
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
from pathlib import Path
from typing import TYPE_CHECKING

import click

from ..fee_models import SatoshisPerKilobyte
from ..glyph.builder import (
    CommitParams,
    DmintV1DeployParams,
    FtTransferParams,
    FtUtxo,
    GlyphBuilder,
    RevealParams,
)
from ..glyph.dmint import (
    DEFAULT_MAX_ATTEMPTS,
    DmintContractUtxo,
    DmintMinerFundingUtxo,
    DmintState,
    build_dmint_mint_tx,
    build_dmint_v1_mint_preimage,
    build_mint_scriptsig,
    find_dmint_contract_utxos,
    find_dmint_funding_utxo,
    mine_solution_dispatch,
)
from ..glyph.scanner import GlyphScanner
from ..glyph.script import build_nft_locking_script, extract_ref_from_nft_script
from ..glyph.types import GlyphFt, GlyphMetadata, GlyphNft, GlyphProtocol, GlyphRef
from ..hd.wallet import HdWallet
from ..script.script import Script
from ..script.type import P2PKH, encode_pushdata
from ..security.errors import DmintError, MaxAttemptsError, NetworkError, ValidationError
from ..security.types import Hex20, Txid
from ..transaction.transaction import Transaction
from ..transaction.transaction_input import TransactionInput
from ..transaction.transaction_output import TransactionOutput
from .context import CliContext
from .errors import NetworkBoundaryError, UserError
from .format import emit, emit_table
from .glyph_helpers import (
    _TEMPLATE_TYPES,
    _BroadcastSummary,
    _build_glyph_unlock,
    _confirm_or_abort,
    _metadata_summary,
    _parse_ref,
    _read_metadata_file,
    _scaffold_for,
    _try_extract_ft_ref,
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
    commit_value = 5_000_000  # photons; covers reveal-time outputs + headroom
    commit_fee_estimate = 300 * fee_rate  # ~300-byte commit
    reveal_fee_estimate = 600 * fee_rate  # ~600-byte reveal w/ CBOR
    total_required = commit_value + commit_fee_estimate + reveal_fee_estimate + 546

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

    # 4) Build reveal.
    cbor_bytes = commit_result.cbor_bytes
    is_nft = True
    reveal_scripts = builder.prepare_reveal(
        RevealParams(
            commit_txid=str(commit_txid),
            commit_vout=0,
            commit_value=commit_value,
            cbor_bytes=cbor_bytes,
            owner_pkh=funding_pkh,
            is_nft=is_nft,
        )
    )

    shim_commit_out = TransactionOutput(Script(commit_result.commit_script), commit_value)
    src_commit_tx = Transaction(tx_inputs=[], tx_outputs=[shim_commit_out])
    src_commit_tx.txid = lambda: str(commit_txid)  # type: ignore[method-assign]

    reveal_input = TransactionInput(
        source_transaction=src_commit_tx,
        source_output_index=0,
        unlocking_script_template=_build_glyph_unlock(funding_key, reveal_scripts.scriptsig_suffix),
    )
    reveal_input.satoshis = commit_value
    reveal_input.locking_script = Script(commit_result.commit_script)

    # The NFT sits on a dust carrier; the rest of the commit value returns as change
    # (fee() sized from the real length) instead of being burned to fee.
    reveal_tx = Transaction(
        tx_inputs=[reveal_input],
        tx_outputs=[
            TransactionOutput(Script(reveal_scripts.locking_script), 546),
            TransactionOutput(locking, 0, change=True),
        ],
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
                    f"nft to:        {funding_pkh.hex()}  (546-photon carrier; change returned)",
                ],
            )
        ],
    )
    reveal_txid = await client.broadcast(reveal_hex)
    ref = GlyphRef(txid=Txid(str(reveal_txid)), vout=0)

    return {
        "commit_txid": str(commit_txid),
        "reveal_txid": str(reveal_txid),
        "ref": f"{ref.txid}:{ref.vout}",
        "owner_address": funding_addr,
    }


async def _wait_for_tx(client: ElectrumXClient, txid: str, *, timeout_s: float = 1800.0) -> None:
    """Poll get_transaction_verbose until ``confirmations`` is >= 1.

    Mirrors the polling pattern used in examples/. Re-raises on
    persistent network failure; treats a transient miss as "not yet
    confirmed."
    """
    start = asyncio.get_event_loop().time()
    interval = 10.0
    while True:
        try:
            info = await client.get_transaction_verbose(Txid(txid))
            confirmations = int(info.get("confirmations", 0)) if isinstance(info, dict) else 0
            if confirmations >= 1:
                return
        except NetworkError:
            # Tx may not be visible yet; keep polling.
            pass
        if asyncio.get_event_loop().time() - start > timeout_s:
            raise NetworkBoundaryError(
                "timed out waiting for confirmation",
                cause=f"{txid} did not confirm within {timeout_s:.0f}s",
                fix="check the chain explorer; if confirmed, re-run with COMMIT_TXID=<txid> to resume reveal",
            )
        await asyncio.sleep(interval)


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
    commit_value = supply + 5_000_000  # supply + overhead
    commit_fee_estimate = 300 * fee_rate
    reveal_fee_estimate = 600 * fee_rate
    total_required = commit_value + commit_fee_estimate + reveal_fee_estimate + 546

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

    reveal_scripts = builder.prepare_ft_deploy_reveal(
        commit_txid=str(commit_txid),
        commit_vout=0,
        commit_value=commit_value,
        cbor_bytes=commit_result.cbor_bytes,
        premine_pkh=treasury_pkh,
        premine_amount=supply,
    )

    shim_commit_out = TransactionOutput(Script(commit_result.commit_script), commit_value)
    src_commit_tx = Transaction(tx_inputs=[], tx_outputs=[shim_commit_out])
    src_commit_tx.txid = lambda: str(commit_txid)  # type: ignore[method-assign]

    reveal_input = TransactionInput(
        source_transaction=src_commit_tx,
        source_output_index=0,
        unlocking_script_template=_build_glyph_unlock(funding_key, reveal_scripts.scriptsig_suffix),
    )
    reveal_input.satoshis = commit_value
    reveal_input.locking_script = Script(commit_result.commit_script)

    # Premine: vout[0].value = the supply (1 photon = 1 unit); the commit headroom
    # returns as change (fee() sized from the real length) instead of burning to fee.
    reveal_tx = Transaction(
        tx_inputs=[reveal_input],
        tx_outputs=[
            TransactionOutput(Script(reveal_scripts.locking_script), supply),
            TransactionOutput(locking, 0, change=True),
        ],
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
    ref = GlyphRef(txid=Txid(str(reveal_txid)), vout=0)

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
@click.pass_obj
def transfer_ft_cmd(ctx: CliContext, ref: str, amount: int, to_address: str, passphrase: bool) -> None:
    """Transfer FT units of REF (txid:vout) to --to ADDRESS.

    Builds a conservation-enforcing FT transfer via FtUtxoSet.
    """
    if amount <= 0:
        raise UserError("amount must be > 0")
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
            return await _transfer_ft_inner(ctx, wallet, glyph_ref, amount, to_pkh, to_address, client)

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


async def _transfer_ft_inner(
    ctx: CliContext,
    wallet: HdWallet,
    ref: GlyphRef,
    amount: int,
    to_pkh: Hex20,
    to_address: str,
    client: ElectrumXClient,
) -> dict:
    """FT transfer: scan wallet, find FT utxos for ref, build + broadcast."""
    # Scan wallet for FT holdings of this ref.
    scanner = GlyphScanner(client)
    items: list[GlyphFt] = []
    for rec in [r for r in wallet.addresses.values() if r.used]:
        scanned = await scanner.scan_address(rec.address)
        for item in scanned:
            if isinstance(item, GlyphFt) and item.ref == ref:
                items.append(item)

    if not items:
        raise UserError(
            f"no FT holdings for {ref.txid}:{ref.vout} in this wallet",
            fix="run `pyrxd balance --refresh` to discover used addresses, then retry",
        )

    # Convert GlyphFt holdings into FtUtxo records suitable for the builder.
    # We need the actual utxo (tx_hash, vout, value) and ft_amount and the
    # raw ft_script from each. The scanner's GlyphFt has ref + amount but
    # we also need the underlying tx_hash and vout — those live on the
    # original UtxoRecord. Use collect_spendable + per-address scan to
    # rebuild the (utxo, address, key) → ft_amount mapping.
    from ..glyph.script import is_ft_script

    triples = await wallet.collect_spendable(client)
    ft_inputs: list[tuple[FtUtxo, str, PrivateKey]] = []
    total_ft = 0
    for utxo, addr, pk in triples:
        # Each utxo's locking script must be checked against the ref.
        # We need the source tx output's script.
        try:
            raw = await client.get_transaction(Txid(utxo.tx_hash))
            tx = Transaction.from_hex(bytes(raw))
            if tx is None or utxo.tx_pos >= len(tx.outputs):
                continue
            out_script = tx.outputs[utxo.tx_pos].locking_script.serialize()
            if not is_ft_script(out_script.hex()):
                continue
            ref_in_script = _try_extract_ft_ref(out_script)
            if ref_in_script != ref:
                continue
            ft_amount = utxo.value  # 1 photon = 1 FT unit
            ft_inputs.append(
                (
                    FtUtxo(
                        txid=utxo.tx_hash,
                        vout=utxo.tx_pos,
                        value=utxo.value,
                        ft_amount=ft_amount,
                        ft_script=out_script,
                    ),
                    addr,
                    pk,
                )
            )
            total_ft += ft_amount
        except NetworkError:
            continue

    if total_ft < amount:
        raise UserError(
            f"insufficient FT balance: need {amount}, have {total_ft}",
            fix="check holdings with `pyrxd glyph list --type ft`",
        )

    # Greedy descending selection until we have enough.
    ft_inputs.sort(key=lambda t: t[0].ft_amount, reverse=True)
    selected: list[tuple[FtUtxo, str, PrivateKey]] = []
    selected_total = 0
    for triple in ft_inputs:
        selected.append(triple)
        selected_total += triple[0].ft_amount
        if selected_total >= amount:
            break

    # Use FtUtxoSet to build the transfer (conservation enforcement).
    builder = GlyphBuilder()
    # Need a single signing key; FtUtxoSet expects one. We assume all
    # FT utxos in the wallet share the same key — the wallet is a
    # single HD chain with one address per FT receipt typically. If
    # they don't, this will produce an invalid signature on inputs
    # signed with the wrong key.
    # For Cut 2 simplicity, restrict transfer to FT utxos that all use
    # the same signing key (the one for input 0). Caller can split if
    # they hit a multi-key wallet.
    first_key = selected[0][2]
    for _utxo, _addr, k in selected:
        if k.public_key().address() != first_key.public_key().address():
            raise UserError(
                "FT transfer across multiple wallet addresses isn't supported in Cut 2",
                cause="selected FT utxos span multiple HD-derived keys",
                fix="consolidate FT holdings to one address first (Cut 3 will lift this restriction)",
            )

    params = FtTransferParams(
        ref=ref,
        utxos=[t[0] for t in selected],
        amount=amount,
        new_owner_pkh=to_pkh,
        private_key=first_key,
        fee_rate=ctx.fee_rate,
    )
    transfer_result = builder.build_ft_transfer_tx(params)
    raw_hex = transfer_result.tx.serialize()

    _confirm_or_abort(
        ctx,
        [
            _BroadcastSummary(
                title="FT transfer",
                lines=[
                    f"ref:          {ref.txid}:{ref.vout}",
                    f"amount:       {amount:,} units",
                    f"recipient:    {to_address}",
                    f"network:      {ctx.network}",
                ],
            ),
        ],
    )
    txid = await client.broadcast(raw_hex)
    return {"txid": str(txid), "ref": f"{ref.txid}:{ref.vout}", "amount": amount, "to": to_address}


@glyph_group.command(name="transfer-nft")
@click.argument("ref", type=str)
@click.option("--to", "to_address", required=True, help="Recipient address.")
@click.option("--passphrase/--no-passphrase", default=False)
@click.pass_obj
def transfer_nft_cmd(ctx: CliContext, ref: str, to_address: str, passphrase: bool) -> None:
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
            return await _transfer_nft_inner(ctx, wallet, glyph_ref, to_pkh, to_address, client)

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


async def _transfer_nft_inner(
    ctx: CliContext,
    wallet: HdWallet,
    ref: GlyphRef,
    to_pkh: Hex20,
    to_address: str,
    client: ElectrumXClient,
) -> dict:
    """Find the singleton NFT utxo and re-lock it to to_pkh."""
    triples = await wallet.collect_spendable(client)
    found: tuple | None = None
    for utxo, addr, pk in triples:
        try:
            raw = await client.get_transaction(Txid(utxo.tx_hash))
            tx = Transaction.from_hex(bytes(raw))
            if tx is None or utxo.tx_pos >= len(tx.outputs):
                continue
            out_script = tx.outputs[utxo.tx_pos].locking_script.serialize()
            try:
                this_ref = extract_ref_from_nft_script(out_script)
            except Exception:  # noqa: S112 — non-NFT scripts raise; the loop is filtering, not handling errors  # nosec B112
                continue
            if this_ref == ref:
                found = (utxo, addr, pk, out_script)
                break
        except NetworkError:
            continue
    if found is None:
        raise UserError(
            f"NFT {ref.txid}:{ref.vout} is not held by this wallet",
            fix="run `pyrxd balance --refresh` first; if still missing, the NFT is owned elsewhere",
        )
    utxo, addr, pk, nft_script = found

    # The NFT singleton carries only dust, so the fee must come from a separate
    # plain-RXD funding input (else the tx pays 0 fee and the node rejects it).
    fund = await _find_plain_rxd_utxo(triples, client, exclude={(utxo.tx_hash, utxo.tx_pos)}, needed=100_000)
    if fund is None:
        raise UserError(
            "no plain-RXD UTXO to fund the NFT transfer fee",
            fix="fund this wallet with a little plain RXD (the NFT itself carries only dust)",
        )
    fund_utxo, fund_addr, fund_key = fund
    fund_spk = P2PKH().lock(fund_addr)

    # Input 0: the NFT (P2PKH-gated to the owner), re-locked to the new owner.
    # Input 1: the fee funding. Both source shims are padded to the real vout.
    nft_src_outs = [TransactionOutput(Script(b""), 0) for _ in range(utxo.tx_pos)]
    nft_src_outs.append(TransactionOutput(Script(nft_script), utxo.value))
    nft_src = Transaction(tx_inputs=[], tx_outputs=nft_src_outs)
    nft_src.txid = lambda: utxo.tx_hash  # type: ignore[method-assign]
    nft_input = TransactionInput(
        source_transaction=nft_src,
        source_txid=utxo.tx_hash,
        source_output_index=utxo.tx_pos,
        unlocking_script_template=P2PKH().unlock(pk),
    )
    nft_input.satoshis = utxo.value
    nft_input.locking_script = Script(nft_script)

    fund_src_outs = [TransactionOutput(Script(b""), 0) for _ in range(fund_utxo.tx_pos)]
    fund_src_outs.append(TransactionOutput(fund_spk, fund_utxo.value))
    fund_src = Transaction(tx_inputs=[], tx_outputs=fund_src_outs)
    fund_src.txid = lambda: fund_utxo.tx_hash  # type: ignore[method-assign]
    fund_input = TransactionInput(
        source_transaction=fund_src,
        source_txid=fund_utxo.tx_hash,
        source_output_index=fund_utxo.tx_pos,
        unlocking_script_template=P2PKH().unlock(fund_key),
    )
    fund_input.satoshis = fund_utxo.value
    fund_input.locking_script = fund_spk

    new_locking = build_nft_locking_script(to_pkh, ref)
    nft_tx = Transaction(
        tx_inputs=[nft_input, fund_input],
        tx_outputs=[
            TransactionOutput(Script(new_locking), utxo.value),  # NFT singleton -> new owner
            TransactionOutput(fund_spk, 0, change=True),  # fee change back to this wallet
        ],
    )
    nft_tx.fee(SatoshisPerKilobyte(ctx.fee_rate * 1000))
    nft_tx.sign()

    _confirm_or_abort(
        ctx,
        [
            _BroadcastSummary(
                title="NFT transfer",
                lines=[
                    f"ref:        {ref.txid}:{ref.vout}",
                    f"from:       {addr}",
                    f"to:         {to_address}",
                    f"network:    {ctx.network}",
                ],
            ),
        ],
    )
    txid = await client.broadcast(nft_tx.serialize())
    return {"txid": str(txid), "ref": f"{ref.txid}:{ref.vout}", "to": to_address}


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
# deploy-dmint (V1 dMint contract genesis)
# ---------------------------------------------------------------------------
#
# Lifts the consensus-proven deploy flow (tests/test_dmint_v1_regtest_e2e.py)
# onto the deploy-ft command template. A V1 dMint contract is a 1-photon
# singleton: each PoW-mined claim pays `--reward` photons of the FT and
# recreates the contract at height+1, up to `--max-height` claims.

_DMINT_REF_SEED = 1_000  # > dust; one per contract, genesises each contractRef


@glyph_group.command(name="deploy-dmint")
@click.argument("metadata_file", type=click.Path(path_type=Path))
@click.option(
    "--num-contracts", type=int, default=1, show_default=True, help="Parallel V1 contracts to genesis [1..250]."
)
@click.option("--max-height", type=int, required=True, help="Mints per contract [1..0xFFFFFF].")
@click.option("--reward", type=int, required=True, help="Photons of the FT paid per successful mint [1..0xFFFFFF].")
@click.option("--difficulty", type=int, default=1, show_default=True, help="Initial PoW difficulty (1 = easiest).")
@click.option("--op-return", "op_return", default=None, help="Optional OP_RETURN carrier on the reveal (<=255 bytes).")
@click.option("--passphrase/--no-passphrase", default=False)
@click.pass_obj
def deploy_dmint_cmd(
    ctx: CliContext,
    metadata_file: Path,
    num_contracts: int,
    max_height: int,
    reward: int,
    difficulty: int,
    op_return: str | None,
    passphrase: bool,
) -> None:
    """Deploy a V1 dMint contract (commit -> reveal) that miners claim from.

    Genesises ``--num-contracts`` parallel 1-photon singleton contracts; each
    pays ``--reward`` photons of the FT per PoW-mined claim, up to
    ``--max-height`` claims. Prints the token_ref and per-contract outpoints so
    they can be claimed with ``glyph claim-dmint``.
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
    # commit). 80 bytes is the node standardness limit (matches the mint path).
    if op_return_bytes is not None and len(op_return_bytes) > 80:
        raise UserError(f"--op-return is {len(op_return_bytes)} bytes; the standardness limit is 80")

    # Validate parameter bounds early (DmintV1DeployParams.__post_init__) before
    # any wallet prompt; owner_pkh is a placeholder here (bound to the funding key in _inner).
    try:
        DmintV1DeployParams(
            metadata=metadata,
            owner_pkh=Hex20(b"\x00" * 20),
            num_contracts=num_contracts,
            max_height=max_height,
            reward_photons=reward,
            difficulty=difficulty,
            op_return_msg=op_return_bytes,
        )
    except ValidationError as exc:
        raise UserError("invalid dMint deploy parameters", cause=str(exc)) from exc

    wallet = _load_wallet(ctx, prompt_passphrase=passphrase)

    async def _do() -> dict:
        client = ctx.make_client()
        async with client:
            return await _deploy_dmint_inner(
                ctx, wallet, metadata, num_contracts, max_height, reward, difficulty, op_return_bytes, client
            )

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
        click.echo("\ndMint contract deployed!")
        click.echo(f"  commit txid:  {result['commit_txid']}")
        click.echo(f"  reveal txid:  {result['reveal_txid']}")
        click.echo(f"  token_ref:    {result['token_ref']}")
        click.echo(f"  contracts ({result['num_contracts']}):")
        for outpoint in result["contracts"]:
            click.echo(f"    {outpoint}")
        click.echo(f"  total supply: {result['total_supply']:,} photons")
        click.echo(f"\n  claim with:   glyph claim-dmint --contract {result['contracts'][0]}")


async def _deploy_dmint_inner(
    ctx: CliContext,
    wallet: HdWallet,
    metadata: GlyphMetadata,
    num_contracts: int,
    max_height: int,
    reward: int,
    difficulty: int,
    op_return_bytes: bytes | None,
    client: ElectrumXClient,
) -> dict:
    builder = GlyphBuilder()
    triples = await wallet.collect_spendable(client)
    if not triples:
        raise UserError("no spendable UTXOs in the wallet")

    fee_rate = ctx.fee_rate
    # vout0 (FT-commit hashlock) must cover the N 1-photon carriers + the reveal fee;
    # vouts 1..N are above-dust ref-seeds that genesis each contractRef when the reveal spends them.
    reveal_fee_estimate = (num_contracts * 260 + 400) * fee_rate
    commit0_value = num_contracts + reveal_fee_estimate + 10_000
    commit_fee_estimate = (num_contracts * 40 + 300) * fee_rate
    total_required = commit0_value + num_contracts * _DMINT_REF_SEED + commit_fee_estimate + 546

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

    deploy = builder.prepare_dmint_deploy(
        DmintV1DeployParams(
            metadata=metadata,
            owner_pkh=owner_pkh,
            num_contracts=num_contracts,
            max_height=max_height,
            reward_photons=reward,
            difficulty=difficulty,
            op_return_msg=op_return_bytes,
        )
    )
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

    reveal_outputs = [
        TransactionOutput(Script(rev.contract_scripts[i]), rev.contract_value) for i in range(num_contracts)
    ]
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
                ],
            ),
        ],
    )
    reveal_txid = await client.broadcast(reveal_tx.serialize())
    total_supply = reward * max_height * num_contracts
    return {
        "commit_txid": str(commit_txid),
        "reveal_txid": str(reveal_txid),
        "token_ref": f"{commit_txid}:0",
        "contracts": [f"{reveal_txid}:{i}" for i in range(num_contracts)],
        "num_contracts": num_contracts,
        "total_supply": total_supply,
    }


# ---------------------------------------------------------------------------
# claim-dmint (PoW-mine a claim from a live contract)
# ---------------------------------------------------------------------------


def _resolve_miner_argv(miner_cmd: str | None) -> list[str] | None:
    """Resolve --miner-cmd to a mine_solution_dispatch argv (or None for in-process).

    None -> bundled parallel miner (the safe default: the in-process miner's
    DEFAULT_MAX_ATTEMPTS is < 2**32 and would sweep only part of the nonce space);
    "in-process" -> in-process miner; anything else -> shlex.split(...).
    """
    if miner_cmd is None:
        return [sys.executable, "-m", "pyrxd.contrib.miner"]
    if miner_cmd == "in-process":
        return None
    return shlex.split(miner_cmd)


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
    help="External miner argv (shlex). Default: bundled 'python -m pyrxd.contrib.miner'. 'in-process' forces the slow in-process miner.",
)
@click.option(
    "--timeout",
    "timeout_s",
    type=float,
    default=600.0,
    show_default=True,
    help="External-miner subprocess timeout (s).",
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
@click.option("--passphrase/--no-passphrase", default=False)
@click.pass_obj
def claim_dmint_cmd(
    ctx: CliContext,
    contract: str | None,
    token_ref: str | None,
    op_return: str,
    miner_cmd: str | None,
    timeout_s: float,
    max_attempts: int | None,
    max_rerolls: int,
    reward_address: str | None,
    passphrase: bool,
) -> None:
    """PoW-mine a claim from a live V1 dMint contract and broadcast the mint.

    Locate the contract (``--contract TXID:VOUT`` or ``--token-ref TXID:0``),
    fund the mint from this wallet, mine a nonce (rerolling the OP_RETURN on
    exhaustion, the way real miners do), and broadcast. The FT reward + change
    go to ``--reward-address`` (default: the wallet's largest-UTXO address).
    """
    if (contract is None) == (token_ref is None):
        raise UserError("pass exactly one of --contract TXID:VOUT or --token-ref TXID:0")
    miner_argv = _resolve_miner_argv(miner_cmd)
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

    def _mine(preimage: bytes, target: int) -> bytes:
        return mine_solution_dispatch(
            preimage=preimage,
            target=target,
            nonce_width=4,
            miner_argv=miner_argv,
            max_attempts=max_attempts if max_attempts is not None else DEFAULT_MAX_ATTEMPTS,
            timeout_s=timeout_s,
        ).nonce

    try:
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
        build_mint_scriptsig(nonce, pre.input_hash, pre.output_hash, nonce_width=4)
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
        contract_utxo = next((c for c in contracts if c.state.is_v1 and not c.state.is_exhausted), None)  # type: ignore[assignment]
        if contract_utxo is None:
            raise UserError(
                "no live (non-exhausted) V1 dMint contract found for that token_ref",
                fix="check the token_ref, or pass --contract TXID:VOUT directly",
            )
    if not contract_utxo.state.is_v1:
        raise UserError("not a V1 dMint contract (only V1 is mintable today)")
    if contract_utxo.state.is_exhausted:
        raise UserError(
            f"contract is exhausted (height {contract_utxo.state.height} >= max_height {contract_utxo.state.max_height})"
        )

    # 2. Select the miner identity (HD wallet -> single funding/reward address).
    miner_address, miner_key = await _select_miner_identity(wallet, reward_address, client)
    miner_pkh = bytes(Hex20(miner_key.public_key().hash160()))

    # 3. Scan that address for a plain-RXD funding UTXO (excludes token-bearing UTXOs).
    needed = contract_utxo.state.reward + 10_000_000 + 546
    try:
        funding = await find_dmint_funding_utxo(client, miner_address, needed)
    except (DmintError, ValidationError) as exc:  # InvalidFundingUtxoError is a DmintError, not a ValidationError
        raise UserError(
            "could not find a plain-RXD funding UTXO for the mint",
            cause=str(exc),
            fix=f"fund {miner_address} with >= {needed:,} photons of plain RXD, or pass --reward-address",
        ) from exc
    return contract_utxo, funding, miner_key, miner_pkh


async def _fetch_dmint_contract(client: ElectrumXClient, txid: str, vout: int) -> DmintContractUtxo:
    tx_bytes = await client.get_transaction(Txid(txid))
    tx = Transaction.from_hex(bytes(tx_bytes))
    if tx is None or vout >= len(tx.outputs):
        raise UserError(f"contract output {txid}:{vout} not found in the fetched tx")
    out = tx.outputs[vout]
    script = out.locking_script.serialize()
    try:
        state = DmintState.from_script(script)
    except ValidationError as exc:
        raise UserError(f"{txid}:{vout} is not a dMint contract", cause=str(exc)) from exc
    return DmintContractUtxo(txid=txid, vout=vout, value=out.satoshis, script=script, state=state)


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
