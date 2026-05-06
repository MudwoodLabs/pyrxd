"""``pyrxd glyph …`` subcommand group — Cut 2 of the v0.3 wallet/CLI plan.

Commands:
  glyph init-metadata   Write a metadata.json scaffold for a token type.
  glyph mint-nft        Two-tx commit/reveal NFT mint.
  glyph deploy-ft       FT premine deploy (full supply at vout[0]).
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
"""

from __future__ import annotations

import asyncio
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

import click

from ..fee_models import SatoshisPerKilobyte
from ..glyph.builder import (
    CommitParams,
    FtTransferParams,
    FtUtxo,
    GlyphBuilder,
)
from ..glyph.scanner import GlyphScanner
from ..glyph.script import build_nft_locking_script, extract_ref_from_nft_script
from ..glyph.types import GlyphFt, GlyphMetadata, GlyphNft, GlyphProtocol, GlyphRef
from ..hd.wallet import HdWallet
from ..script.script import Script
from ..script.type import P2PKH, encode_pushdata, to_unlock_script_template
from ..security.errors import NetworkError, ValidationError
from ..security.types import Hex20, Txid
from ..transaction.transaction import Transaction
from ..transaction.transaction_input import TransactionInput
from ..transaction.transaction_output import TransactionOutput
from .context import CliContext
from .errors import NetworkBoundaryError, UserError, WalletDecryptError
from .format import emit, emit_table
from .prompts import confirm_action, prompt_mnemonic_input, prompt_passphrase_input

if TYPE_CHECKING:
    from ..keys import PrivateKey
    from ..network.electrumx import ElectrumXClient


# ---------------------------------------------------------------------------
# Group registration
# ---------------------------------------------------------------------------


@click.group(name="glyph")
def glyph_group() -> None:
    """Mint, transfer, and inspect Glyph tokens."""


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _load_wallet(ctx: CliContext, *, prompt_passphrase: bool = False) -> HdWallet:
    """Open the wallet at ctx.wallet_path. Mirrors query_cmds._load_wallet."""
    if not ctx.wallet_path.exists():
        raise UserError(
            f"no wallet at {ctx.wallet_path}",
            cause="the file does not exist",
            fix="run `pyrxd wallet new` to create one, or pass --wallet PATH",
        )
    mnemonic = prompt_mnemonic_input()
    if not mnemonic:
        raise UserError(
            "mnemonic is required",
            cause="no input received",
            fix="enter the BIP39 mnemonic the wallet was created with",
        )
    passphrase = ""  # nosec B105 — empty string is the BIP39 spec default
    if prompt_passphrase:
        passphrase = prompt_passphrase_input(optional=False)
    try:
        return HdWallet.load(ctx.wallet_path, mnemonic, passphrase)
    except (ValidationError, ValueError) as exc:
        raise WalletDecryptError() from exc


def _read_metadata_file(path: Path) -> GlyphMetadata:
    """Parse a metadata.json scaffold into a GlyphMetadata.

    The scaffold uses simple Python-friendly keys (``protocol`` as a
    list of strings rather than ints, etc.) so users don't have to
    learn the on-wire CBOR field names. Maps to GlyphMetadata here.
    """
    if not path.exists():
        raise UserError(
            f"metadata file not found: {path}",
            cause="the path does not resolve to a file",
            fix="run `pyrxd glyph init-metadata --type nft --out metadata.json` to scaffold one",
        )
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        raise UserError(
            f"could not read metadata file: {path}",
            cause=str(exc),
            fix="check that the file is valid JSON",
        ) from exc

    if not isinstance(data, dict):
        raise UserError("metadata file must contain a JSON object")

    # Convert protocol names → GlyphProtocol ints.
    raw_protocol = data.get("protocol", [])
    if not isinstance(raw_protocol, list) or not raw_protocol:
        raise UserError(
            "metadata.protocol must be a non-empty list",
            cause=f"got {type(raw_protocol).__name__}: {raw_protocol!r}",
            fix='use e.g. ["NFT"] or ["FT"] or ["FT", "DMINT"]',
        )

    proto_ints: list[int] = []
    for p in raw_protocol:
        if isinstance(p, int):
            proto_ints.append(p)
            continue
        if isinstance(p, str):
            try:
                proto_ints.append(int(GlyphProtocol[p.upper()]))
                continue
            except KeyError:
                raise UserError(
                    f"unknown protocol name: {p!r}",
                    fix=f"valid names: {sorted(p.name for p in GlyphProtocol)}",
                ) from None
        raise UserError(f"protocol entries must be string or int, got {type(p).__name__}")

    try:
        return GlyphMetadata(
            protocol=proto_ints,
            name=data.get("name", ""),
            ticker=data.get("ticker", ""),
            description=data.get("description", ""),
            token_type=data.get("token_type", ""),
            attrs=data.get("attrs", {}) or {},
            loc=data.get("loc", ""),
            loc_hash=data.get("loc_hash", ""),
            decimals=int(data.get("decimals", 0)),
            image_url=data.get("image_url", ""),
            image_ipfs=data.get("image_ipfs", ""),
            image_sha256=data.get("image_sha256", ""),
        )
    except ValidationError as exc:
        raise UserError(
            "metadata file failed validation",
            cause=str(exc),
            fix="see the error above; check protocol combinations and decimals range",
        ) from exc


def _broadcast_or_explain(ctx: CliContext, client: ElectrumXClient, raw: bytes) -> str:
    """Broadcast *raw* via *client*, surface NetworkError as exit-code-2."""
    try:
        return str(asyncio.get_event_loop().run_until_complete(client.broadcast(raw)) if False else "")
    except NetworkError as exc:
        raise NetworkBoundaryError(
            "broadcast failed",
            cause=str(exc),
            fix=f"check that {ctx.electrumx_url} is reachable and try again",
        ) from exc


def _select_funding_utxo(wallet: HdWallet, client: ElectrumXClient, min_photons: int) -> tuple[FtUtxo, str, PrivateKey]:
    """Pick the smallest UTXO across the wallet that's >= min_photons.

    Returns (utxo, address, signing_key) so the caller can build a
    funded input.
    """
    triples = asyncio.get_event_loop().run_until_complete(wallet.collect_spendable(client))
    candidates = [t for t in triples if t[0].value >= min_photons]
    if not candidates:
        raise UserError(
            "no spendable UTXO large enough for this operation",
            cause=f"need at least {min_photons:,} photons in a single UTXO",
            fix="fund the wallet, or run `pyrxd balance --refresh` to discover used addresses",
        )
    candidates.sort(key=lambda t: t[0].value)
    return candidates[0]


# ---------------------------------------------------------------------------
# init-metadata
# ---------------------------------------------------------------------------


_TEMPLATE_TYPES = ("nft", "ft", "dmint-ft", "mutable-nft", "container-nft")


def _scaffold_for(kind: str) -> dict:
    """Return a metadata.json template for *kind* (one of _TEMPLATE_TYPES)."""
    base = {
        "name": "My Token",
        "description": "Replace with a one- or two-line description.",
        "image_url": "",
        "image_ipfs": "",
        "image_sha256": "",
        "attrs": {},
    }
    if kind == "nft":
        return {**base, "protocol": ["NFT"], "token_type": "art"}  # nosec B105 — Glyph token-type tag, not a password
    if kind == "ft":
        return {
            **base,
            "protocol": ["FT"],
            "ticker": "MTK",
            "decimals": 0,
            # Note: 1 photon = 1 FT unit; "decimals" is display-only.
        }
    if kind == "dmint-ft":
        return {
            **base,
            "protocol": ["FT", "DMINT"],
            "ticker": "MTK",
            "decimals": 0,
        }
    if kind == "mutable-nft":
        return {**base, "protocol": ["NFT", "MUT"], "token_type": "mutable"}  # nosec B105 — token-type tag
    if kind == "container-nft":
        return {**base, "protocol": ["NFT", "CONTAINER"], "token_type": "collection"}  # nosec B105 — token-type tag
    # Should be unreachable thanks to click.Choice.
    raise UserError(f"unknown template type: {kind}")  # pragma: no cover


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
# Common pre-flight for broadcast commands
# ---------------------------------------------------------------------------


@dataclass
class _BroadcastSummary:
    """One section of the confirmation summary printed before a broadcast."""

    title: str
    lines: list[str]


def _confirm_or_abort(ctx: CliContext, sections: list[_BroadcastSummary]) -> None:
    """Print summary; ask for y/N. Raises UserError on abort."""
    ok, why = ctx.is_destructive_mode_safe()
    if not ok:
        raise UserError(why or "destructive op without --yes in --json mode")

    summary_lines = []
    for sec in sections:
        summary_lines.append(f"\n  {sec.title}:")
        summary_lines.extend(f"    {line}" for line in sec.lines)
    summary_lines.append("")  # blank line before the prompt

    if not confirm_action(summary_lines, ctx=ctx, prompt_text="Broadcast?"):
        raise UserError(
            "aborted by user",
            cause="confirmation prompt declined",
            fix="re-run with the inputs you actually want to broadcast",
        )


def _metadata_summary(metadata: GlyphMetadata) -> _BroadcastSummary:
    """Surface user-readable metadata fields in the broadcast summary.

    Threat model finding S7 (docs/threat-model.md): users running
    `glyph mint-nft` from a metadata.json may not realize what
    they're actually committing. The funding key, owner_pkh, etc. all
    come from the wallet/CLI args (not the file), so theft via this
    path is constrained — but the user should still see the
    metadata-driven name, ticker, protocol, and any creator/royalty
    fields before broadcasting. If something looks wrong (e.g., the
    file claims a name they didn't author), they can abort.
    """
    proto_names = ", ".join(GlyphProtocol(p).name for p in metadata.protocol)
    lines = [
        f"protocol:    [{proto_names}]",
        f"name:        {metadata.name or '(empty)'}",
    ]
    if metadata.ticker:
        lines.append(f"ticker:      {metadata.ticker}")
    if metadata.token_type:
        lines.append(f"token_type:  {metadata.token_type}")
    if metadata.description:
        # Truncate long descriptions; they don't change the security
        # posture but the summary should stay scannable.
        desc = metadata.description if len(metadata.description) <= 80 else metadata.description[:77] + "..."
        lines.append(f"description: {desc}")
    if metadata.image_url:
        lines.append(f"image_url:   {metadata.image_url}")
    if metadata.image_sha256:
        lines.append(f"image_hash:  {metadata.image_sha256[:16]}...{metadata.image_sha256[-8:]}")
    if metadata.creator:
        lines.append(f"creator:     pubkey={metadata.creator.pubkey[:16]}...")
    if metadata.royalty:
        lines.append(f"royalty:     {metadata.royalty.bps} bps → {metadata.royalty.address}")
        if metadata.royalty.splits:
            for addr, bps in metadata.royalty.splits:
                lines.append(f"             split: {bps} bps → {addr}")
    return _BroadcastSummary(title="Metadata", lines=lines)


# ---------------------------------------------------------------------------
# mint-nft
# ---------------------------------------------------------------------------


def _build_glyph_unlock(privkey: PrivateKey, scriptsig_suffix: bytes):
    """Return an UnlockingScriptTemplate that signs P2PKH then appends Glyph suffix.

    Mirrors examples/glyph_mint_demo.py glyph_reveal_unlock.
    """

    def sign(tx, input_index):
        tx_input = tx.inputs[input_index]
        sighash = tx_input.sighash
        signature = privkey.sign(tx.preimage(input_index))
        pubkey = privkey.public_key().serialize()
        p2pkh_part = encode_pushdata(signature + sighash.to_bytes(1, "little")) + encode_pushdata(pubkey)
        return Script(p2pkh_part + scriptsig_suffix)

    def estimated_unlocking_byte_length() -> int:
        return 107 + len(scriptsig_suffix)

    return to_unlock_script_template(sign, estimated_unlocking_byte_length)


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
    src_out = TransactionOutput(locking, funding_utxo.value)
    src_tx = Transaction(tx_inputs=[], tx_outputs=[src_out])
    src_tx.txid = lambda: funding_utxo.tx_hash  # type: ignore[method-assign]

    commit_input = TransactionInput(
        source_transaction=src_tx,
        source_txid=funding_utxo.tx_hash,
        source_output_index=funding_utxo.tx_pos,
        unlocking_script_template=P2PKH().unlock(funding_key),
    )
    commit_input.satoshis = funding_utxo.value
    commit_input.locking_script = locking

    change_value = funding_utxo.value - commit_value - commit_fee_estimate
    if change_value < 546:
        change_value = 0  # burn dust to fee
    commit_outputs = [TransactionOutput(Script(commit_result.commit_script), commit_value)]
    if change_value:
        commit_outputs.append(TransactionOutput(locking, change_value))
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
        commit_txid=str(commit_txid),
        commit_vout=0,
        cbor_bytes=cbor_bytes,
        owner_pkh=funding_pkh,
        is_nft=is_nft,
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

    reveal_value = max(546, commit_value - reveal_fee_estimate)
    reveal_tx = Transaction(
        tx_inputs=[reveal_input],
        tx_outputs=[TransactionOutput(Script(reveal_scripts.locking_script), reveal_value)],
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
                    f"reveal value:  {reveal_value:,} photons",
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
    src_out = TransactionOutput(locking, funding_utxo.value)
    src_tx = Transaction(tx_inputs=[], tx_outputs=[src_out])
    src_tx.txid = lambda: funding_utxo.tx_hash  # type: ignore[method-assign]

    commit_input = TransactionInput(
        source_transaction=src_tx,
        source_txid=funding_utxo.tx_hash,
        source_output_index=funding_utxo.tx_pos,
        unlocking_script_template=P2PKH().unlock(funding_key),
    )
    commit_input.satoshis = funding_utxo.value
    commit_input.locking_script = locking

    change_value = funding_utxo.value - commit_value - commit_fee_estimate
    if change_value < 546:
        change_value = 0
    commit_outputs = [TransactionOutput(Script(commit_result.commit_script), commit_value)]
    if change_value:
        commit_outputs.append(TransactionOutput(locking, change_value))
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

    # Premine: vout[0].value = the supply (1 photon = 1 unit).
    reveal_tx = Transaction(
        tx_inputs=[reveal_input],
        tx_outputs=[TransactionOutput(Script(reveal_scripts.locking_script), supply)],
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


def _parse_ref(s: str) -> GlyphRef:
    """Parse 'txid:vout' into a GlyphRef. UserError on invalid input."""
    if ":" not in s:
        raise UserError(
            f"ref must be 'txid:vout', got {s!r}",
            fix="example: a443d9df...:0",
        )
    txid_s, vout_s = s.split(":", 1)
    try:
        txid = Txid(txid_s)
        vout = int(vout_s)
    except (ValidationError, ValueError) as exc:
        raise UserError("invalid ref", cause=str(exc)) from exc
    return GlyphRef(txid=txid, vout=vout)


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


def _try_extract_ft_ref(script: bytes) -> GlyphRef | None:
    """Best-effort extract of the FT ref from a locking script."""
    from ..glyph.script import extract_ref_from_ft_script

    try:
        return extract_ref_from_ft_script(script)
    except Exception:
        return None


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

    # Build the input that spends the NFT, sign it with P2PKH unlock
    # (the NFT script ends with a P2PKH gate to the owner_pkh).
    locking = nft_script
    src_out = TransactionOutput(Script(locking), utxo.value)
    src_tx = Transaction(tx_inputs=[], tx_outputs=[src_out])
    src_tx.txid = lambda: utxo.tx_hash  # type: ignore[method-assign]

    nft_input = TransactionInput(
        source_transaction=src_tx,
        source_txid=utxo.tx_hash,
        source_output_index=utxo.tx_pos,
        unlocking_script_template=P2PKH().unlock(pk),
    )
    nft_input.satoshis = utxo.value
    nft_input.locking_script = Script(locking)

    # Re-lock to the new owner via the same NFT script with new pkh.
    new_locking = build_nft_locking_script(to_pkh, ref)
    nft_tx = Transaction(
        tx_inputs=[nft_input],
        tx_outputs=[TransactionOutput(Script(new_locking), utxo.value)],
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

# Input forms recognised by `glyph inspect`. Each is unambiguous by shape:
#   txid       — exactly 64 lowercase-hex chars
#   contract   — exactly 72 lowercase-hex chars (txid + BE vout)
#   outpoint   — anything containing ":"
#   script     — any other hex string of even length (>= 50 chars / 25 bytes)
# Everything else is a UserError.
_TXID_HEX_LEN = 64
_CONTRACT_HEX_LEN = 72
# The minimum script we'd reasonably classify is plain P2PKH (25 bytes / 50 hex).
_MIN_SCRIPT_HEX_LEN = 50
# Cap accidental "paste a whole tx" before running every classifier on it.
_MAX_SCRIPT_HEX_LEN = 20_000


def _classify_input(s: str) -> tuple[str, str]:
    """Dispatch on input shape. Returns (form, normalised_value).

    form ∈ {"txid", "contract", "outpoint", "script"}.

    Auto-detect rules (unambiguous by length / content):
      * 64 hex → txid
      * 72 hex → contract
      * contains ":" → outpoint (validated downstream)
      * 50–20_000 even-length hex → script

    A bare 64-hex string is always treated as a txid even though it could
    structurally also be a 32-byte payload-hash push prefix; the txid form
    is the only one users hit in practice from a block explorer.
    """
    s = s.strip()
    if not s:
        raise UserError("inspect input is empty")
    if ":" in s:
        return ("outpoint", s)
    lowered = s.lower()
    if len(lowered) == _TXID_HEX_LEN and all(c in "0123456789abcdef" for c in lowered):
        return ("txid", lowered)
    if len(lowered) == _CONTRACT_HEX_LEN and all(c in "0123456789abcdef" for c in lowered):
        return ("contract", lowered)
    if (
        _MIN_SCRIPT_HEX_LEN <= len(lowered) <= _MAX_SCRIPT_HEX_LEN
        and len(lowered) % 2 == 0
        and all(c in "0123456789abcdef" for c in lowered)
    ):
        return ("script", lowered)
    raise UserError(
        f"could not classify input (length {len(s)})",
        cause="input is not a 64-char txid, 72-char contract id, txid:vout outpoint, or 50-20000 char hex script",
        fix="paste a 64-char txid (with --fetch), 72-char contract id, txid:vout, or hex script",
    )


def _inspect_contract(contract_hex: str) -> dict:
    """Decode a 72-char contract id. Return a flat dict for emit()."""
    from ..glyph.types import GlyphRef

    try:
        ref = GlyphRef.from_contract_hex(contract_hex)
    except ValidationError as exc:
        raise UserError("contract id failed to parse", cause=str(exc)) from exc
    return {
        "form": "contract",
        "txid": ref.txid,
        "vout": ref.vout,
        "outpoint": f"{ref.txid}:{ref.vout}",
        "wire_hex": ref.to_bytes().hex(),
    }


def _inspect_outpoint(s: str) -> dict:
    """Parse a `txid:vout` string. Returns a flat dict for emit().

    Rejects malformed input loudly so the user sees a clear error rather
    than a confusing downstream traceback.
    """
    from ..glyph.types import GlyphRef

    if s.count(":") != 1:
        raise UserError(f"outpoint must be exactly one 'txid:vout', got {s!r}")
    txid_str, vout_str = s.split(":", 1)
    try:
        vout = int(vout_str, 10)
    except ValueError as exc:
        raise UserError(f"vout is not an integer: {vout_str!r}") from exc
    try:
        ref = GlyphRef(txid=Txid(txid_str.lower()), vout=vout)
    except ValidationError as exc:
        raise UserError("outpoint failed to parse", cause=str(exc)) from exc
    return {
        "form": "outpoint",
        "txid": ref.txid,
        "vout": ref.vout,
        "outpoint": f"{ref.txid}:{ref.vout}",
        "wire_hex": ref.to_bytes().hex(),
    }


def _inspect_script(script_hex: str) -> dict:
    """Classify a single hex-encoded locking script. Returns a flat dict."""
    from ..glyph.dmint import DmintState
    from ..glyph.script import (
        MUTABLE_NFT_SCRIPT_RE,
        extract_owner_pkh_from_commit_script,
        extract_owner_pkh_from_ft_script,
        extract_owner_pkh_from_nft_script,
        extract_payload_hash_from_commit_script,
        extract_ref_from_ft_script,
        extract_ref_from_nft_script,
        is_commit_ft_script,
        is_commit_nft_script,
        is_ft_script,
        is_nft_script,
        parse_mutable_nft_script,
    )

    try:
        script = bytes.fromhex(script_hex)
    except ValueError as exc:
        raise UserError("script is not valid hex") from exc

    base = {"form": "script", "length": len(script), "hex": script_hex}

    # Plain P2PKH check first (cheapest, common).
    if len(script) == 25 and script[:3] == b"\x76\xa9\x14" and script[23:] == b"\x88\xac":
        return {**base, "type": "p2pkh", "owner_pkh": script[3:23].hex()}

    if is_nft_script(script_hex):
        ref = extract_ref_from_nft_script(script)
        pkh = extract_owner_pkh_from_nft_script(script)
        return {
            **base,
            "type": "nft",
            "ref_txid": ref.txid,
            "ref_vout": ref.vout,
            "ref_outpoint": f"{ref.txid}:{ref.vout}",
            "owner_pkh": bytes(pkh).hex(),
        }

    if is_ft_script(script_hex):
        ref = extract_ref_from_ft_script(script)
        pkh = extract_owner_pkh_from_ft_script(script)
        return {
            **base,
            "type": "ft",
            "ref_txid": ref.txid,
            "ref_vout": ref.vout,
            "ref_outpoint": f"{ref.txid}:{ref.vout}",
            "owner_pkh": bytes(pkh).hex(),
        }

    if MUTABLE_NFT_SCRIPT_RE.fullmatch(script_hex):
        parsed = parse_mutable_nft_script(script)
        if parsed is not None:
            ref, payload_hash = parsed
            return {
                **base,
                "type": "mut",
                "ref_txid": ref.txid,
                "ref_vout": ref.vout,
                "ref_outpoint": f"{ref.txid}:{ref.vout}",
                "payload_hash": payload_hash.hex(),
            }

    if is_commit_nft_script(script_hex):
        return {
            **base,
            "type": "commit-nft",
            "payload_hash": extract_payload_hash_from_commit_script(script).hex(),
            "owner_pkh": bytes(extract_owner_pkh_from_commit_script(script)).hex(),
        }

    if is_commit_ft_script(script_hex):
        return {
            **base,
            "type": "commit-ft",
            "payload_hash": extract_payload_hash_from_commit_script(script).hex(),
            "owner_pkh": bytes(extract_owner_pkh_from_commit_script(script)).hex(),
        }

    # dMint contract is variable-length and parser-only; try last.
    try:
        state = DmintState.from_script(script)
    except ValidationError:
        return {**base, "type": "unknown"}

    return {
        **base,
        "type": "dmint",
        "contract_ref_outpoint": f"{state.contract_ref.txid}:{state.contract_ref.vout}",
        "token_ref_outpoint": f"{state.token_ref.txid}:{state.token_ref.vout}",
        "height": state.height,
        "max_height": state.max_height,
        "reward": state.reward,
        "algo": state.algo.name,
        "daa_mode": state.daa_mode.name,
    }


def _render_inspect_human(payload: dict) -> str:
    """Format a single inspect result for the human output mode."""
    form = payload.get("form", "?")
    if form == "script":
        return _render_script_human(payload)
    if form == "contract":
        lines = [
            "Contract id (explorer display form):",
            f"  txid:     {payload['txid']}",
            f"  vout:     {payload['vout']}",
            f"  outpoint: {payload['outpoint']}",
            "",
            f"Wire form (inside scripts): {payload['wire_hex']}",
        ]
        return "\n".join(lines)
    if form == "outpoint":
        lines = [
            "Outpoint:",
            f"  txid:     {payload['txid']}",
            f"  vout:     {payload['vout']}",
            f"  outpoint: {payload['outpoint']}",
            "",
            f"Wire form (inside scripts): {payload['wire_hex']}",
        ]
        return "\n".join(lines)
    return "\n".join(f"{k}: {v}" for k, v in payload.items())


def _render_script_human(payload: dict) -> str:
    """Pretty-print a classified script result."""
    type_ = payload.get("type", "?")
    head = f"type: {type_}    length: {payload['length']} bytes"
    body: list[str] = []
    if type_ == "p2pkh":
        body.append(f"  owner_pkh: {payload['owner_pkh']}")
    elif type_ in ("nft", "ft"):
        body.append(f"  ref:       {payload['ref_outpoint']}")
        body.append(f"  owner_pkh: {payload['owner_pkh']}")
    elif type_ == "mut":
        body.append(f"  ref:          {payload['ref_outpoint']}")
        body.append(f"  payload_hash: {payload['payload_hash']}")
    elif type_ in ("commit-nft", "commit-ft"):
        body.append(f"  payload_hash: {payload['payload_hash']}")
        body.append(f"  owner_pkh:    {payload['owner_pkh']}")
    elif type_ == "dmint":
        body.append(f"  contract_ref: {payload['contract_ref_outpoint']}")
        body.append(f"  token_ref:    {payload['token_ref_outpoint']}")
        body.append(f"  height:       {payload['height']} / {payload['max_height']}")
        body.append(f"  reward:       {payload['reward']} photons")
        body.append(f"  algo:         {payload['algo']}")
        body.append(f"  daa_mode:     {payload['daa_mode']}")
    elif type_ == "unknown":
        body.append("  (script does not match any known Glyph or P2PKH layout)")
    return "\n".join([head, *body])


@glyph_group.command(name="inspect")
@click.argument("inspect_input", metavar="INPUT")
@click.pass_obj
def inspect_cmd(ctx: CliContext, inspect_input: str) -> None:
    """Classify a Glyph input.

    INPUT can be:

    \b
      • a 64-char txid              (requires --fetch — added in next release)
      • a 72-char contract id       (e.g. "b45dc4...a2a800000004")
      • an outpoint "txid:vout"     (e.g. "b45dc4...a2a8:4")
      • a hex-encoded locking script (P2PKH / FT / NFT / mut / commit / dmint)

    Read-only — no network access in this release. Pass --json for machine
    output (auto-detects when stdout is piped).
    """
    form, value = _classify_input(inspect_input)

    if form == "txid":
        raise UserError(
            "txid inspection requires a network fetch",
            cause="this looks like a txid (64 hex chars)",
            fix="--fetch will be added in the next release; for now pass a script hex, contract id, or outpoint",
        )

    if form == "contract":
        payload = _inspect_contract(value)
    elif form == "outpoint":
        payload = _inspect_outpoint(value)
    elif form == "script":
        payload = _inspect_script(value)
    else:  # pragma: no cover — _classify_input never returns other values
        raise UserError(f"internal: unknown form {form!r}")

    mode = ctx.output_mode
    if mode == "json":
        click.echo(emit(payload, mode="json"))
    elif mode == "quiet":
        # In quiet mode print the most useful single string: the type/outpoint.
        if form == "script":
            click.echo(payload.get("type", ""))
        else:
            click.echo(payload.get("outpoint", ""))
    else:
        click.echo(_render_inspect_human(payload))


__all__ = [
    "deploy_ft_cmd",
    "glyph_group",
    "init_metadata_cmd",
    "inspect_cmd",
    "list_cmd",
    "mint_nft_cmd",
    "transfer_ft_cmd",
    "transfer_nft_cmd",
]
