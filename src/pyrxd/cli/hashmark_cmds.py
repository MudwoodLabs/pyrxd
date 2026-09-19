"""``pyrxd mark`` — hash a file, sign the digest, and publish the HashMark record.

HashMark is a THIRD-PARTY ``OP_RETURN`` format (see :mod:`pyrxd.script.hashmark`), not a
Glyph protocol, which is why this command sits at the top level beside ``balance`` and
``utxos`` rather than under ``glyph``.

Shaped after ``pyrxd glyph timelock-reveal``: the same ``--dry-run``, ``--allow-overpay``
and ``--passphrase`` options, the same ``_load_wallet`` / ``_confirm_or_abort`` flow, the
same three output modes, and the same rule that the bytes shown to the operator are the
bytes broadcast (:func:`~pyrxd.hashmark_tx.broadcast_hashmark_mark` sends the build that
was displayed, never a rebuilt one).

**What this file adds that the library deliberately cannot.** §5.4 makes canonicalising a
label an encoder obligation *and* requires that the user be shown the result, "because
that is what will be published". :func:`~pyrxd.script.hashmark.encode_hashmark` therefore
REFUSES a non-canonical label rather than trimming it — a library function cannot show
anyone anything, and in v2 the label is inside the signed statement, so an encoder that
trimmed silently would sign a string its caller never saw. This command is the half that
can: it canonicalises, and when the canonical form differs from what was typed it says so
in its own banner in the confirmation summary. (``--yes`` skips the QUESTION, never the
DISCLOSURE — see :func:`pyrxd.cli.prompts.confirm_action`.)

**And the network is not cosmetic here.** The chain's genesis hash is part of the signed
statement and is NOT carried by the record, so the same bytes on another chain are a
different statement and verify against a different key. ``--network`` therefore selects
what is signed, not merely where it is sent, and an unknown network is refused outright:
at read time :mod:`pyrxd.glyph._inspect_core` falls back to mainnet and says so, which is
right for a pasted script with no context, but a WRITE has context and guessing it would
publish a permanent claim about a chain nobody chose.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import TYPE_CHECKING, Any

import click

from ..constants import genesis_hash_for
from ..glyph.client import BroadcastEchoMismatch
from ..script.hashmark import canonicalize_label, max_label_bytes
from ..security.errors import InsufficientFundsError, NetworkError, PolicyRejection, ValidationError
from .errors import NetworkBoundaryError, UserError
from .format import emit
from .glyph_helpers import _BroadcastSummary, _confirm_or_abort
from .prompts import _load_wallet

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ..hashmark_tx import MarkBuild
    from .context import CliContext

#: Where the signing identity comes from when ``--signer-address`` is not given: the
#: wallet's first external address, ``m/44'/512'/0'/0/0``.
#:
#: A FIXED path rather than "whichever UTXO funded this", because the signature is the
#: identity. §14.1: it permanently links this mark to that key and to every other mark
#: it signed, and `docs/plans/2026-09-18-feat-sealed-attestation-poc-plan.md` builds the
#: whole product on that binding — a name resolved at a block is a claim about a key. If
#: the signer drifted with the funding UTXO, two marks by one person would be two
#: strangers, and no amount of later tooling could stitch them back together.
_DEFAULT_SIGNER_CHANGE, _DEFAULT_SIGNER_INDEX = 0, 0


def _canonical_label(label: str | None) -> tuple[str | None, bool]:
    """``(canonical, changed)`` for an operator-typed label, or a ``UserError``.

    ``changed`` drives the banner below. It is computed here, against the string the
    operator actually typed, because it is the one fact the record itself cannot carry:
    once encoded there is no trace of what was typed, only of what was signed.
    """
    if label is None:
        return None, False
    try:
        canonical = canonicalize_label(label)
    except ValidationError as exc:
        raise UserError(
            "that label cannot be published as typed",
            cause=str(exc),
            fix="HashMark 5.4 rejects control characters, bidi overrides and line "
            "separators in a label — they can make the rendered text differ from the "
            "signed text. Remove them, or omit --label.",
        ) from exc
    return canonical, canonical != label


def _mark_lines(
    build: MarkBuild,
    *,
    network: str,
    fee_rate: int,
    signer_address: str,
    typed_label: str | None,
) -> list[str]:
    """The human-readable account of what a mark would publish.

    Shows the genesis hash beside the network name. It is the part of the signed
    statement that is NOT recoverable from the record, so an operator reading the record
    back later cannot tell from it which chain it was signed for — this prompt is the
    only place the two are ever seen together.
    """
    plan = build.plan
    raw = build.serialize()
    lines = [
        f"file:        {plan.source}",
        f"{plan.algorithm}:      {plan.digest_hex}",
        f"label:       {plan.label if plan.label is not None else '(none)'}",
        f"signer:      {signer_address}",
        f"             hash160 {plan.signer_hash160_hex} — committed in the record and in the statement",
        f"network:     {network} (genesis {plan.network_genesis})",
        f"record:      {plan.size_bytes} B of the 223-byte ceiling",
        f"funded from: {build.from_address}",
        f"fee:         {build.fee:,} photons ({len(raw)} B @ {fee_rate:,}/B)"
        + ("" if build.has_change else " — no change: the whole funding UTXO is the fee"),
    ]
    if typed_label is not None and plan.label != typed_label:
        lines.append("")
        lines.append("*** LABEL CANONICALISED — what gets signed is NOT what you typed:")
        lines.append(f"***   you typed:  {typed_label!r}")
        lines.append(f"***   published:  {plan.label!r}")
        lines.append("*** HashMark 5.4 requires the label be trimmed and NFC-normalised before")
        lines.append("*** signing. The published spelling above is the one inside the signature.")
    lines.append("")
    lines.append("A mark proves someone knew this digest by the block that confirms it. It does NOT")
    lines.append("prove authorship, ownership, originality, or that the contents are true.")
    lines.append("The label is permanently public and the signature permanently links this mark to")
    lines.append("that key and to every other mark it signs. This cannot be undone.")
    return lines


@click.command(name="mark")
@click.argument("file_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--label",
    default=None,
    help="Optional public caption, signed with the digest. Trimmed and NFC-normalised "
    "before signing (HashMark 5.4); the canonical form is shown before anything is "
    "broadcast. Capped in UTF-8 BYTES, not characters — 88 for sha256.",
)
@click.option(
    "--signer-address",
    default=None,
    metavar="ADDR",
    help="Wallet address whose key signs the statement. Default: the wallet's first "
    "receive address, so repeated marks share one identity. The funding UTXO is chosen "
    "separately and need not be this address.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Hash, sign, fund and print the exact record and transaction — and broadcast nothing.",
)
@click.option(
    "--allow-overpay",
    is_flag=True,
    default=False,
    help="Accept a fee far above what the signed transaction's size demands. Does NOT relax the underpay invariant.",
)
@click.option("--passphrase/--no-passphrase", default=False)
@click.pass_obj
def mark_cmd(
    ctx: CliContext,
    file_path: Path,
    label: str | None,
    signer_address: str | None,
    dry_run: bool,
    allow_overpay: bool,
    passphrase: bool,
) -> None:
    """Publish a signed HashMark record committing to the digest of FILE_PATH.

    The file is hashed locally and streamed; ITS CONTENTS DO NOT GO ON CHAIN. What is
    published is the digest, the signer's hash160, a signature over both, and the
    optional label — 133 bytes unlabelled, at most 223.

    IRREVERSIBLE once broadcast. The label is permanently public, and the signature
    permanently links this mark to the signing key.

    Use --dry-run first. It runs every check, prints the record hex and its decoded
    fields, and sends nothing.
    """
    from ..hashmark_tx import broadcast_hashmark_mark, build_hashmark_mark, plan_hashmark_for_file

    canonical_label, label_changed = _canonical_label(label)

    # Before the wallet is opened, because refusing here costs nothing and refusing after
    # a mnemonic prompt costs the operator the prompt.
    genesis = genesis_hash_for(ctx.network)
    if genesis is None:
        raise UserError(
            f"no genesis hash known for network {ctx.network!r}, so nothing can be signed for it",
            cause="a HashMark v2 signature covers the chain's genesis hash; without it the "
            "record would make a statement about a chain pyrxd cannot name",
            fix="use --network mainnet, testnet or regtest",
        )

    wallet = _load_wallet(ctx, prompt_passphrase=passphrase)
    try:
        if signer_address is None:
            signer_address = wallet.derive_address(_DEFAULT_SIGNER_CHANGE, _DEFAULT_SIGNER_INDEX)
            signer_key = wallet.privkey_for(_DEFAULT_SIGNER_CHANGE, _DEFAULT_SIGNER_INDEX)
        else:
            signer_key = wallet.privkey_for_address(signer_address)
    except ValidationError as exc:
        raise UserError(
            f"cannot sign with {signer_address}",
            cause=str(exc),
            fix="pass an address this wallet derived — `pyrxd address --index N` prints one "
            "by index, `pyrxd address` the next unused receive address — or omit "
            "--signer-address to use the wallet's first receive address (index 0)",
        ) from exc

    # Hash, sign and self-verify BEFORE the network is touched. A label over the cap or a
    # rejected codepoint fails here, with nothing spent and nothing sent.
    try:
        plan = plan_hashmark_for_file(
            file_path,
            signer_key,
            label=canonical_label,
            network_genesis=genesis,
        )
    except ValidationError as exc:
        raise UserError(
            "could not build the HashMark record",
            cause=str(exc),
            fix=f"a sha256 mark allows a label of up to {max_label_bytes()} UTF-8 bytes; "
            "everything else in the record is fixed-width",
        ) from exc
    except OSError as exc:
        raise UserError(f"could not read {file_path}", cause=str(exc)) from exc

    async def _do_build() -> Any:
        client = ctx.make_client()
        async with client:
            build = await build_hashmark_mark(
                wallet,
                plan,
                client=client,
                fee_rate=ctx.fee_rate,
                allow_overpay=allow_overpay,
            )
            if dry_run:
                return build, None
            _confirm_or_abort(
                ctx,
                [
                    _BroadcastSummary(
                        title="HashMark",
                        lines=_mark_lines(
                            build,
                            network=ctx.network,
                            fee_rate=ctx.fee_rate,
                            signer_address=signer_address,
                            typed_label=label,
                        ),
                    )
                ],
            )
            # THESE bytes, not a fresh build — the prompt above showed this transaction.
            return build, await broadcast_hashmark_mark(client, build)

    try:
        build, txid = asyncio.run(_do_build())
    except BroadcastEchoMismatch as exc:
        # NOT a "nothing was broadcast" refusal, and the wording has to say so: the
        # transaction may well have relayed and only the reply was wrong. The same
        # handler shape as `glyph transfer-nft`'s, for the same reason — printing the
        # server's txid would report a mark that may not exist.
        raise UserError(
            "the server returned a different transaction id than the one we signed",
            cause=str(exc),
            fix=f"check {exc.local_txid} on an explorer — if it is there the mark was "
            "published and only the server's reply was wrong. Do NOT re-run blindly: a "
            "second mark is a second permanent record, not a retry.",
        ) from exc
    except InsufficientFundsError as exc:
        raise UserError(
            "no plain-RXD UTXO large enough to fund the mark",
            cause=str(exc),
            fix="fund this wallet with a little plain RXD and retry. A token-bearing UTXO "
            "is never spent here, so an NFT or FT balance does not count.",
        ) from exc
    except ValidationError as exc:
        raise UserError("could not build the mark transaction", cause=str(exc)) from exc
    except PolicyRejection as exc:
        raise UserError(
            "the node rejected the mark",
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

    record = build.plan.record
    payload = {
        "file": str(file_path),
        "algorithm": build.plan.algorithm,
        "digest": build.plan.digest_hex,
        "label": build.plan.label,
        # The string the operator typed, whenever canonicalisation changed it. Present so
        # a scripted caller can notice the same thing the banner tells a human; absent
        # when nothing changed, rather than echoed back as a duplicate of `label`.
        "label_as_typed": label if label_changed else None,
        "version": record.version,
        "signer_address": signer_address,
        "signer_hash160": build.plan.signer_hash160_hex,
        # Named for what it is. `verify_attestation` ran over the bytes below, against
        # the genesis below, before this transaction was funded — so this field says our
        # own record verifies, which is a weaker claim than a stranger's verdict and must
        # not be rendered as one.
        "self_attestation": build.plan.attestation.outcome.value,
        "network": ctx.network,
        "network_genesis": build.plan.network_genesis,
        "record_bytes": build.plan.size_bytes,
        "op_return_script_hex": build.plan.op_return_script.hex(),
        "fee": build.fee,
        "raw_tx_hex": build.serialize().hex(),
        "broadcast": txid is not None,
        "txid": txid,
    }
    if ctx.output_mode == "json":
        click.echo(emit(payload, mode="json"))
    elif ctx.output_mode == "quiet":
        click.echo(emit(payload, mode="quiet", quiet_field="txid" if txid is not None else "digest"))
    elif txid is None:
        click.echo("\nDRY RUN — nothing was broadcast.")
        for line in _mark_lines(
            build,
            network=ctx.network,
            fee_rate=ctx.fee_rate,
            signer_address=signer_address,
            typed_label=label,
        ):
            click.echo(f"  {line}")
        click.echo(f"\n  record:      {build.plan.op_return_script.hex()}")
        click.echo(f"  decoded:     v{record.version} {record.algorithm} digest={record.digest_hex}")
        click.echo(f"               label={record.label!r} signer={record.signer_hash160_hex}")
        click.echo(f"               signature (unverified by a third party)={record.signature_hex}")
        click.echo(f"  raw tx:      {payload['raw_tx_hex']}")
        click.echo("\n  Re-run without --dry-run to publish it.")
    else:
        click.echo(f"\nMarked: {txid}")
        click.echo(f"  file:       {file_path}")
        click.echo(f"  {build.plan.algorithm}:     {build.plan.digest_hex}")
        click.echo(f"  label:      {build.plan.label if build.plan.label is not None else '(none)'}")
        click.echo(f"  signer:     {signer_address}")
        click.echo(f"  network:    {ctx.network} (genesis {build.plan.network_genesis})")
        click.echo(f"  record:     {build.plan.size_bytes} B")
        click.echo(f"  fee:        {build.fee:,} photons")
        click.echo("\n  The mark is provable once the transaction confirms — a mark in the mempool")
        click.echo("  fixes no time. Anyone can check it with `pyrxd glyph inspect --fetch <txid>`.")


__all__ = ["mark_cmd"]
