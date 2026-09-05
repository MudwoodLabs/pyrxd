"""``pyrxd glyph timelock-mint`` / ``timelock-reveal`` — the write side of Glyph TIMELOCK.

Two commands, and the asymmetry between them is the whole design.

``timelock-mint`` seals content: it encrypts locally, commits ``sha256(key)`` on chain, and
hands the operator back the things the chain does **not** have — the key, the ciphertext,
and the envelope bytes the reveal must push. All three are written to files, and all three
paths are required arguments rather than optional conveniences. A mint that succeeded while
its key scrolled off a terminal is a token nobody can ever open, and there is no second
mint; a mint whose commit confirms while its reveal does not is value spendable by nothing
but those exact envelope bytes, which this command cannot rebuild once the process is gone.

``timelock-reveal`` publishes that key, and is irreversible in the other direction. It
refuses two things before anything is signed:

* a CEK that is not the one this token committed to — checked against the commitment
  **fetched from the chain**, never one the operator supplied, because a CEK checked
  against a typed-in hash proves only that they typed two matching things;
* a reveal before ``unlock_at``, unless ``--allow-early`` is passed.

Neither refusal is in this file. Both live inside
:func:`pyrxd.glyph.timelock_reveal_tx.plan_timelock_reveal`, which is the only way to obtain
a publishable reveal script at all — so the CLI cannot forget them and neither can any other
caller. What this file adds is the part a library cannot: showing a person the exact key
about to become public, and asking.
"""

from __future__ import annotations

import asyncio
import json
import mimetypes
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any

import click

from ..glyph.client import GlyphClient
from ..glyph.payload import encode_payload
from ..glyph.scanner import GlyphScanner
from ..glyph.timelock import TimelockParams, TimelockRecipient
from ..glyph.timelock_reveal_tx import (
    CekCommitmentMismatch,
    TimelockNotExpired,
)
from ..security.errors import InsufficientFundsError, NetworkError, PolicyRejection, ValidationError
from .errors import NetworkBoundaryError, UserError
from .format import emit
from .glyph_helpers import _BroadcastSummary, _confirm_or_abort, _parse_ref
from .prompts import _load_wallet

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ..glyph.timelock import TimelockMintBuild
    from ..glyph.timelock_reveal_tx import TimelockRevealBuild
    from .context import CliContext

#: Cap on the operator ``--hint``. The hint rides in the reveal's OP_RETURN, whose size is
#: not a relay problem on Radiant (``fRequireStandard`` is hardcoded false — see
#: :data:`pyrxd.constants.MAX_OP_RETURN_MSG_BYTES` for the citation), but an unbounded
#: string in a data carrier is still an unbounded string. 200 bytes leaves the whole reveal
#: comfortably under 512 B.
_MAX_HINT_BYTES = 200


def _write_secret(path: Path, data: str) -> None:
    """Write ``data`` to ``path`` with mode 0600, creating it exclusively.

    ``O_EXCL``, so an existing file is a refusal rather than an overwrite: the file this
    writes is the only copy of a key, and clobbering the previous mint's key while reporting
    success is the failure this whole command exists to avoid.

    The mode is set in ``os.open`` rather than with a later ``chmod`` — between the two there
    is a window in which the key sits world-readable, and on a shared host that window is the
    vulnerability.
    """
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(data)


def _read_cek_file(path: Path) -> bytes:
    """Load a 32-byte CEK from ``path``, accepting hex text or raw bytes.

    Both forms are accepted because both exist in practice: ``timelock-mint`` writes hex, and
    an operator whose key came out of a hardware token or a password manager may hold the raw
    32 bytes. Refusing one of the two would be this repo's "a guard that refuses valid work"
    on the one input that cannot be regenerated.
    """
    raw = path.read_bytes()
    text = raw.strip()
    try:
        decoded = bytes.fromhex(text.decode("ascii"))
    except (UnicodeDecodeError, ValueError):
        decoded = None
    if decoded is not None and len(decoded) == 32:
        return decoded
    if len(raw) == 32:
        return raw
    raise UserError(
        f"{path} does not hold a 32-byte CEK",
        cause=f"read {len(raw)} bytes; neither 64 hex characters nor 32 raw bytes",
        fix="point --cek-file at the file `glyph timelock-mint --cek-out` wrote",
    )


def _parse_recipient(spec: str) -> TimelockRecipient:
    """``KID:HEX64`` -> a :class:`TimelockRecipient`.

    The kid may itself contain ``:``; only the LAST colon separates the key, because a key is
    always 64 hex characters and a label is arbitrary operator text.
    """
    if ":" not in spec:
        raise UserError(
            f"--recipient {spec!r} is not KID:HEX",
            fix="pass e.g. --recipient auctioneer:9f55403a...4263 (64 hex chars of X25519 public key)",
        )
    kid, _, key_hex = spec.rpartition(":")
    if not kid:
        raise UserError(f"--recipient {spec!r} has an empty key id", fix="pass --recipient <label>:<64 hex chars>")
    try:
        key = bytes.fromhex(key_hex.strip())
    except ValueError as exc:
        raise UserError(f"--recipient {spec!r} has a non-hex public key", cause=str(exc)) from exc
    if len(key) != 32:
        raise UserError(
            f"--recipient {spec!r} public key is {len(key)} bytes, not 32",
            fix="an X25519 public key is 32 bytes / 64 hex chars — see pyrxd.x25519_public_key",
        )
    return TimelockRecipient(kid=kid, public_key=key)


def _ciphertext_json(build: TimelockMintBuild) -> str:
    """The encrypted payload, in the shape Photonic's own chunk vectors use.

    Hex rather than base64, and per-chunk ``nonce`` / ``ciphertext`` keys, matching
    ``tests/fixtures/photonic_timelock_vectors.json``. This file is what a recipient feeds
    back to :func:`pyrxd.decrypt_chunked` after the reveal, so its shape is part of the
    feature, not a debug dump.
    """
    return json.dumps(
        {
            "scheme": build.stub.main.scheme,
            "enc": build.stub.main.enc,
            "plaintext_hash": build.ciphertext.plaintext_hash.hex(),
            "size": build.stub.main.size,
            "chunks": [{"nonce": c.nonce.hex(), "ciphertext": c.ciphertext.hex()} for c in build.ciphertext.chunks],
        },
        indent=2,
    )


# ---------------------------------------------------------------------------
# timelock-mint
# ---------------------------------------------------------------------------


@click.command(name="timelock-mint")
@click.option(
    "--content",
    "content_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="File whose bytes are sealed. Encrypted locally; the CIPHERTEXT DOES NOT GO ON CHAIN.",
)
@click.option("--name", required=True, help="The token's display name.")
@click.option(
    "--content-type",
    default=None,
    help="MIME type of the plaintext. Default: guessed from the file name, else application/octet-stream.",
)
@click.option(
    "--mode",
    type=click.Choice(["block", "time"]),
    default="block",
    show_default=True,
    help="Whether --unlock-at is a block height or a unix timestamp.",
)
@click.option(
    "--unlock-at",
    type=int,
    required=True,
    help="Block height (--mode block) or unix timestamp (--mode time) from which the reveal is allowed.",
)
@click.option("--hint", default="", help="Public note carried on chain beside the lock (<=200 bytes).")
@click.option(
    "--recipient",
    "recipient_specs",
    multiple=True,
    metavar="KID:HEX64",
    help="Wrap the key to an X25519 public key so this party can decrypt IMMEDIATELY, without "
    "waiting for the reveal. Repeatable. Omit for a lock only the reveal can open.",
)
@click.option("--locator", default=None, help="Off-chain pointer to the ciphertext (crypto.locator). Unverified.")
@click.option(
    "--cek-out",
    required=True,
    type=click.Path(dir_okay=False, path_type=Path),
    help="REQUIRED. Where to write the 32-byte key, hex, mode 0600. Nothing on chain carries it; "
    "lose it and the content is unopenable forever.",
)
@click.option(
    "--ciphertext-out",
    required=True,
    type=click.Path(dir_okay=False, path_type=Path),
    help="REQUIRED. Where to write the encrypted payload. The mint carries only its hash and size.",
)
@click.option(
    "--envelope-out",
    required=True,
    type=click.Path(dir_okay=False, path_type=Path),
    help="REQUIRED. Where to write the raw envelope CBOR — the exact bytes the reveal must push. "
    "This mint has no metadata file to rebuild from and, with --recipient, the envelope is NOT "
    "reproducible from the same inputs. Without this file a commit that confirms while the reveal "
    "does not is unspendable forever.",
)
@click.option("--passphrase/--no-passphrase", default=False)
@click.pass_obj
def timelock_mint_cmd(
    ctx: CliContext,
    content_path: Path,
    name: str,
    content_type: str | None,
    mode: str,
    unlock_at: int,
    hint: str,
    recipient_specs: tuple[str, ...],
    locator: str | None,
    cek_out: Path,
    ciphertext_out: Path,
    envelope_out: Path,
    passphrase: bool,
) -> None:
    """Encrypt --content, mint an NFT committing to its key, and save both halves.

    The token is spendable and transferable from the moment it is minted; only the
    VISIBILITY of the payload is gated. Anyone can read the commitment, the unlock point and
    the hint; nobody can read the content until the key is published by
    `pyrxd glyph timelock-reveal` (or, for a --recipient, immediately).

    All three output files are written BEFORE the mint is broadcast. That ordering is
    deliberate: a mint that succeeds while the key write fails is a permanently sealed token.

    --envelope-out is the third for a different reason. The mint is two transactions: a
    commit whose output is a hashlock over the envelope bytes, then a reveal that pushes
    those exact bytes to spend it. If the commit confirms and the reveal does not — a
    timeout, a kill during the 10+ minute wait, a declined prompt — the only way to recover
    the commit's value is to rebuild the reveal from BYTE-IDENTICAL CBOR, and this CLI keeps
    no pending store. `glyph mint-nft` can rebuild from its metadata file; this command has
    none, and with --recipient the envelope cannot be rebuilt from the same inputs at all,
    because each wrap draws a fresh ephemeral X25519 key and nonce. So the bytes are saved.
    """
    if unlock_at <= 0:
        raise UserError(f"--unlock-at must be positive, got {unlock_at}")
    if len(hint.encode("utf-8")) > _MAX_HINT_BYTES:
        raise UserError(
            f"--hint is {len(hint.encode('utf-8'))} bytes, over the {_MAX_HINT_BYTES}-byte cap",
            fix="shorten it — the hint is a public label, not the content",
        )
    for out in (cek_out, ciphertext_out, envelope_out):
        if out.exists():
            raise UserError(
                f"{out} already exists",
                cause="refusing to overwrite; it may be another token's only key",
                fix="choose a different path, or move the existing file aside deliberately",
            )

    plaintext = content_path.read_bytes()
    if content_type is None:
        guessed, _ = mimetypes.guess_type(content_path.name)
        content_type = guessed or "application/octet-stream"
    recipients = [_parse_recipient(s) for s in recipient_specs]

    wallet = _load_wallet(ctx, prompt_passphrase=passphrase)

    # Built BEFORE the network is touched. The envelope, the commitment and the key all exist
    # at this point; nothing has been spent.
    from ..glyph.timelock import build_timelock_mint

    try:
        build = build_timelock_mint(
            name=name,
            content_type=content_type,
            plaintext=plaintext,
            params=TimelockParams(mode=mode, unlock_at=unlock_at, hint=hint),  # type: ignore[arg-type]
            recipients=recipients,
            locator=locator,
        )
    except (ValidationError, ValueError) as exc:
        raise UserError("could not build the timelocked mint", cause=str(exc)) from exc

    _confirm_or_abort(
        ctx,
        [
            _BroadcastSummary(
                title="TIMELOCK mint",
                lines=[
                    f"name:        {name}",
                    f"content:     {content_path} ({len(plaintext):,} B, {content_type})",
                    f"opens at:    {unlock_at} ({mode})" + (f"  — hint: {hint}" if hint else ""),
                    f"commitment:  {build.cek_hash}",
                    f"recipients:  {', '.join(r.kid for r in recipients) if recipients else '(none — reveal only)'}",
                    f"key file:    {cek_out}  <- THE ONLY COPY. Nothing on chain carries the key.",
                    f"ciphertext:  {ciphertext_out}  <- the payload itself is NOT on chain.",
                    f"envelope:    {envelope_out}  <- the only way to rebuild the reveal if it fails.",
                    f"network:     {ctx.network}",
                ],
            )
        ],
    )

    # Write all three before broadcasting anything. If a disk write fails, nothing has been
    # minted and the operator can retry; if the mint were first, a failed write would leave
    # a sealed token whose key existed only in this process.
    #
    # The envelope is the third because the two-phase mint below can strand its own commit.
    # `_mint_nft_inner` broadcasts the commit, waits 10+ minutes for confirmation, then
    # prompts AGAIN for the reveal — and the commit output is `OP_HASH256 <payload_hash>
    # OP_EQUALVERIFY`, spendable only by a reveal pushing byte-identical CBOR. A timeout, a
    # kill or a declined prompt in that window leaves value recoverable ONLY from these
    # bytes: there is no pending store on this path, no metadata file for this command, and
    # `wrap_cek_x25519` draws a fresh ephemeral key and nonce per call, so re-running the
    # same command with the same key does not reproduce the envelope when --recipient was
    # given. Written raw rather than hex: these bytes go into `RevealParams(cbor_bytes=...)`
    # unmodified, and a re-encode from anything else is exactly the drift that strands it.
    try:
        _write_secret(cek_out, build.cek.hex() + "\n")
        ciphertext_out.write_text(_ciphertext_json(build))
        envelope_out.write_bytes(encode_payload(build.metadata)[0])
    except OSError as exc:
        raise UserError(
            "could not write the key, ciphertext or envelope file — nothing was broadcast",
            cause=str(exc),
            fix="fix the path or permissions and re-run; no funds and no token were committed",
        ) from exc

    from .glyph_cmds import _mint_nft_inner

    async def _do_mint() -> dict[str, object]:
        client = ctx.make_client()
        async with client:
            return await _mint_nft_inner(ctx, wallet, build.metadata, client)

    try:
        result = asyncio.run(_do_mint())
    except PolicyRejection as exc:
        raise UserError(
            "the node rejected the timelocked mint",
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

    payload = {
        **result,
        "cek_hash": build.cek_hash,
        "unlock_at": unlock_at,
        "mode": mode,
        "cek_file": str(cek_out),
        "ciphertext_file": str(ciphertext_out),
        "envelope_file": str(envelope_out),
    }
    if ctx.output_mode == "json":
        click.echo(emit(payload, mode="json"))
    elif ctx.output_mode == "quiet":
        click.echo(emit(payload, mode="quiet", quiet_field="ref"))
    else:
        click.echo("\nTimelocked NFT minted.")
        click.echo(f"  glyph ref:   {payload['ref']}")
        click.echo(f"  commit txid: {payload['commit_txid']}")
        click.echo(f"  reveal txid: {payload['reveal_txid']}")
        click.echo(f"  opens at:    {unlock_at} ({mode})")
        click.echo(f"  commitment:  {build.cek_hash}")
        click.echo(f"\n  key:         {cek_out} (mode 0600)")
        click.echo(f"  ciphertext:  {ciphertext_out}")
        click.echo(f"  envelope:    {envelope_out}")
        click.echo("\n  Back up all three files now. The chain carries none of them, and a mint cannot be redone.")
        click.echo(f"  To open it later:  pyrxd glyph timelock-reveal {payload['ref']} --cek-file {cek_out}")


# ---------------------------------------------------------------------------
# timelock-reveal
# ---------------------------------------------------------------------------


def _reveal_lines(build: TimelockRevealBuild, *, network: str, fee_rate: int) -> list[str]:
    """The human-readable account of what a reveal would publish.

    Shows the CEK itself. Every other secret in this CLI is masked; this one is the payload
    of the transaction being confirmed, and a prompt that hid the thing about to become
    public would be asking the operator to approve something it declined to show them.

    It shows ``chain says`` for the same reason. The number that decides whether this key
    becomes public is read from an ElectrumX server, and nothing in this SDK authenticates
    it — no proof-of-work check, no link to a known header, no second endpoint asked. A
    server that overstates the tip gets an irreversible reveal past a gate that reports
    itself satisfied, with the ``*** EARLY REVEAL`` banner silent because by its own
    arithmetic the lock HAS expired. Printing ``opens at`` alone gave the operator nothing
    to disagree with; printing both sides of the comparison gives them the one check this
    code cannot do for them.
    """
    plan = build.plan
    raw = build.serialize()
    # Built as a branch, not as an f-string chosen by one: `judged_at` is None whenever the
    # token's mode is neither "block" nor "time", and `f"{None:,}"` is a TypeError. That is a
    # reachable prompt — a third-party token with mode "BLOCK" plus --allow-early gets here —
    # so formatting it eagerly would have turned this very fix into the traceback-instead-of-a-
    # message defect it was written beside.
    if plan.judged_at is None:
        judged = f"(no clock for lock mode {plan.mode!r} — the gate could not evaluate it)"
    else:
        clock_units = "block" if plan.mode == "block" else "unix time"
        judged = f"{plan.judged_at:,} ({clock_units}, as reported by the node — unverified)"
    lines = [
        f"token:       {plan.token_ref}",
        f"opens at:    {plan.unlock_at:,} ({plan.mode})",
        f"chain says:  {judged}",
        f"commitment:  {plan.commitment}  <- matched by this key",
        f"PUBLISHES:   {plan.proof.cek}",
        f"funded from: {build.from_address}",
        f"fee:         {build.fee:,} photons ({len(raw)} B @ {fee_rate:,}/B)"
        + ("" if build.has_change else " — no change: the whole funding UTXO is the fee"),
        f"network:     {network}",
    ]
    if plan.proof.hint:
        lines.append(f"hint:        {plan.proof.hint}")
    if plan.early_override:
        lines.append("")
        lines.append(f"*** EARLY REVEAL: {plan.remaining:,} {'blocks' if plan.mode == 'block' else 'seconds'} short of")
        lines.append("*** the unlock point. Publishing now ends the timelock permanently, for everyone.")
    lines.append("")
    lines.append("This cannot be undone. Once the transaction relays the key is public forever.")
    return lines


@click.command(name="timelock-reveal")
@click.argument("ref", type=str)
@click.option(
    "--cek-file",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="File holding the 32-byte key (hex or raw) — what `timelock-mint --cek-out` wrote. "
    "A file rather than a --cek option on purpose: a key on a command line lands in shell history.",
)
@click.option("--hint", default="", help="Public note carried in the reveal proof (<=200 bytes).")
@click.option(
    "--allow-early",
    is_flag=True,
    default=False,
    help="Publish the key BEFORE the unlock point. This destroys the timelock permanently and "
    "cannot be undone. Exists because opening a sealed lot early is legitimate work, not "
    "because the refusal is a formality.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Run every check, build and sign the transaction, print exactly what would be published "
    "— and broadcast nothing.",
)
@click.option(
    "--allow-overpay",
    is_flag=True,
    default=False,
    help="Accept a fee far above what the signed transaction's size demands. Does NOT relax the underpay invariant.",
)
@click.option("--passphrase/--no-passphrase", default=False)
@click.pass_obj
def timelock_reveal_cmd(
    ctx: CliContext,
    ref: str,
    cek_file: Path,
    hint: str,
    allow_early: bool,
    dry_run: bool,
    allow_overpay: bool,
    passphrase: bool,
) -> None:
    """Publish the decryption key for the timelocked token REF (txid:vout).

    IRREVERSIBLE. The key goes into an OP_RETURN on a public chain; there is no unreveal.

    The token's own mint envelope is fetched from the chain and the key is checked against
    the commitment recorded there. A key that does not match is refused before anything is
    signed — publishing the wrong one spends the reveal and leaves the payload unreadable
    for good.

    Use --dry-run first. It runs every check and prints the exact bytes.
    """
    glyph_ref = _parse_ref(ref)
    if len(hint.encode("utf-8")) > _MAX_HINT_BYTES:
        raise UserError(f"--hint is over the {_MAX_HINT_BYTES}-byte cap", fix="shorten it")
    cek = _read_cek_file(cek_file)
    wallet = _load_wallet(ctx, prompt_passphrase=passphrase)
    token_ref = f"{glyph_ref.txid}:{glyph_ref.vout}"

    async def _do_build() -> Any:
        client = ctx.make_client()
        async with client:
            metadata = await GlyphScanner(client).fetch_metadata(glyph_ref)
            if metadata is None:
                raise UserError(
                    f"could not find the mint envelope for {token_ref}",
                    cause="no reveal transaction spending that outpoint carried Glyph metadata",
                    fix="check the ref — it is the COMMIT outpoint, which is what `glyph list` and "
                    "`glyph inspect` report as the token's ref",
                )
            glyph = GlyphClient(client, wallet, fee_rate=ctx.fee_rate)
            build = await glyph.build_timelock_reveal(
                metadata,
                token_ref=token_ref,
                cek=cek,
                hint=hint,
                allow_early=allow_early,
                allow_overpay=allow_overpay,
            )
            if dry_run:
                return build, None
            _confirm_or_abort(
                ctx,
                [
                    _BroadcastSummary(
                        title="TIMELOCK reveal",
                        lines=_reveal_lines(build, network=ctx.network, fee_rate=ctx.fee_rate),
                    )
                ],
            )
            # THESE bytes, not a fresh build. `reveal_timelock` would build a second
            # transaction after the operator approved the first — a prompt showing one
            # artifact and sending another.
            receipt = await glyph.broadcast_timelock_reveal(build)
            return build, receipt

    try:
        build, receipt = asyncio.run(_do_build())
    except CekCommitmentMismatch as exc:
        raise UserError(
            "this key is not the one this token committed to — nothing was broadcast",
            cause=str(exc),
            fix=f"load the CEK saved for {token_ref}; publishing the wrong key would spend the "
            "reveal and leave the payload permanently unreadable",
        ) from exc
    except TimelockNotExpired as exc:
        raise UserError(
            "the timelock has not expired — nothing was broadcast",
            cause=str(exc),
            fix="wait for the unlock point, or pass --allow-early if you genuinely mean to open "
            "it now (permanently, for everyone)",
        ) from exc
    except InsufficientFundsError as exc:
        raise UserError(
            "no plain-RXD UTXO large enough to fund the reveal",
            cause=str(exc),
            fix="fund this wallet with a little plain RXD and retry",
        ) from exc
    except ValidationError as exc:
        raise UserError("could not build the reveal", cause=str(exc)) from exc
    except PolicyRejection as exc:
        raise UserError(
            "the node rejected the reveal",
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

    plan = build.plan
    payload = {
        "token_ref": plan.token_ref,
        "cek": plan.proof.cek,
        "cek_hash": plan.commitment,
        "unlock_at": plan.unlock_at,
        "mode": plan.mode,
        "unlocked": plan.unlocked,
        # The clock the gate compared against, so a scripted caller can disagree with it —
        # it comes from an ElectrumX server this SDK does not authenticate.
        "judged_at": plan.judged_at,
        "early_override": plan.early_override,
        "fee": build.fee,
        "op_return_script_hex": plan.op_return_script.hex(),
        "raw_tx_hex": build.serialize().hex(),
        "broadcast": receipt is not None,
        "txid": receipt.txid if receipt is not None else None,
    }
    if ctx.output_mode == "json":
        click.echo(emit(payload, mode="json"))
    elif ctx.output_mode == "quiet":
        click.echo(emit(payload, mode="quiet", quiet_field="txid" if receipt is not None else "cek"))
    elif receipt is None:
        click.echo("\nDRY RUN — nothing was broadcast.")
        for line in _reveal_lines(build, network=ctx.network, fee_rate=ctx.fee_rate):
            click.echo(f"  {line}")
        click.echo(f"\n  raw tx:      {payload['raw_tx_hex']}")
        click.echo("\n  Re-run without --dry-run to publish it.")
    else:
        click.echo(f"\nTimelock revealed: {receipt.txid}")
        click.echo(f"  token:      {receipt.token_ref}")
        click.echo(f"  key (now public): {receipt.cek}")
        click.echo(f"  commitment: {receipt.commitment}")
        click.echo(f"  fee:        {receipt.fee:,} photons")


__all__ = ["timelock_mint_cmd", "timelock_reveal_cmd"]
