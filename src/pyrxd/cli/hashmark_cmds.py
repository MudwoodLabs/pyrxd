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
from contextlib import AsyncExitStack
from pathlib import Path
from typing import TYPE_CHECKING, Any

import click

from ..constants import genesis_hash_for
from ..glyph._inspect_core import _truncate_for_human
from ..glyph.client import BroadcastEchoMismatch
from ..script.hashmark import canonicalize_label, max_label_bytes
from ..security.errors import InsufficientFundsError, NetworkError, PolicyRejection, ValidationError
from ..security.types import Txid

# THE §7.6 MACHINERY IS IMPORTED, NOT RESTATED. `verify` is a new entry point onto the verdict
# `glyph inspect` already computes — the form-1/form-2 resolution, the degrade-with-a-reason,
# the display sanitiser, the attestation rendering. Two implementations of that verdict is how
# two surfaces start contradicting each other on screen about the same mark.
from . import glyph_inspect as _inspect
from .errors import NetworkBoundaryError, UserError
from .format import emit
from .glyph_helpers import _BroadcastSummary, _confirm_or_abort
from .glyph_inspect import (
    _attach_name_at_mark,
    _attach_wave_identity,
    _op_return_payload_lines,
    _require_min_confirmations,
    _run_fetch_inspect,
    _sanitize_display_string,
    hashmark_records,
    mark_anchor_dict,
    mark_anchor_lines,
    resolve_anchor_from,
)
from .prompts import _load_wallet

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ..hashmark_tx import MarkBuild
    from .context import CliContext

#: Where the signing identity comes from when ``--signer-address`` is not given: the
#: wallet's first external address, ``m/44'/512'/0'/0/0``.
#:
#: A FIXED path rather than "whichever UTXO funded this", because the signature is the
#: identity. §14.1: it permanently links this mark to that key and to every other mark
#: it signed, and the attestation work this belongs to rests on that binding — a name
#: resolved at a block is a claim about a key. If
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


# =============================================================================================
# ``pyrxd verify`` — the read half.
#
# WHAT THIS FILE ADDS, AND WHAT IT DELIBERATELY DOES NOT. Everything about a HashMark record's
# own verdict — decode, attestation, §7.6 form-1/form-2 resolution, the degrade-with-a-reason,
# display sanitisation, the chain walk, `binding_verified`, `provisional`, `expiry`, `caveat` —
# already exists in :mod:`pyrxd.cli.glyph_inspect` and :mod:`pyrxd.glyph._inspect_core`, and is
# IMPORTED here rather than restated. A second implementation of that verdict is how two
# surfaces start contradicting each other on screen, which is the failure the §7.6 work exists
# to prevent in the first place.
#
# Two things were genuinely missing and are added here:
#
#   1. THE FILE-MATCHING HALF. `inspect` shows the digest a record commits to. It has never
#      answered "is this file that digest", which is the question a human actually arrives
#      with.
#   2. A BLOCK, unconditionally. `inspect` establishes a height only as a side effect of
#      `--wave-name`; without it the mark's own block was never reported at all, and "someone
#      knew this digest by block N" is unusable without N.
#
# One thing was factored OUT rather than copied: `resolve_anchor_from` / `mark_anchor_dict` /
# `hashmark_records` now live in `glyph_inspect` and are shared. See that module.
# =============================================================================================

#: Exit code for a verdict that DOES NOT HOLD — a signature that does not verify, a file that is
#: not what was marked, a block shallower than the floor the caller set, or a name question that
#: was asked and not answered. Distinct from 1 (bad input) on purpose: `verify` is meant to be
#: used as a gate, and a gate whose "no" is spelled the same as "you typed it wrong" cannot be
#: scripted. 0-4 are documented in `docs/wallet-cli-plan.md`; this extends that table.
EXIT_VERDICT_DOES_NOT_HOLD = 5

#: Check states that leave the overall verdict standing. Everything else fails it.
#:
#: THE ASYMMETRY IS DELIBERATE AND IS THE ONE THING TO GET RIGHT HERE. "NOT CHECKED" holds;
#: "NOT ESTABLISHED" does not. On the WRITE side `MarkPlan` treats an UNVERIFIABLE attestation
#: as a refusal, because funding a broadcast needs the same curve library that signs and a mark
#: nobody could self-check must not be published. On the READ side the same word means a missing
#: capability in the READER — the curve library is absent — and failing the verdict on it would
#: accuse an honest signer of forgery because of something missing on the verifier's machine.
#: So it is reported loudly and does not fail.
#:
#: "NOT ESTABLISHED" is the opposite case: the caller ASKED a question (`--wave-name`) and it
#: could not be answered. A gate that waves that through is the quiet, dangerous direction.
_CHECK_HOLDS = frozenset(
    {
        "VERIFIED",
        "NO SIGNATURE",  # a v1 record makes no signature claim; there is nothing to fail
        "NOT CHECKED",  # a capability the reader lacks, or a question the caller did not ask
        "MATCHES",
        "ESTABLISHED",
        "CONFIRMED",
    }
)


def _digest_expectation(
    records: list[dict], *, file_path: Path | None, digest_hex: str | None
) -> tuple[str | None, str]:
    """``(digest to compare against, why there is none)`` — hashed with the algorithm the RECORD names.

    Not with a spelling chosen here. :func:`pyrxd.script.hashmark.algorithm_for` is explicit
    that a caller who writes ``"sha256"`` itself has created a second source of truth for what
    was hashed, and nothing downstream can detect the disagreement — both halves are well-formed
    and the signature still verifies. So the id travels from the decoded record into
    :func:`~pyrxd.hashmark_tx.digest_file`, which derives its hasher from that one table.

    The second element is never dropped. "Nothing was asked" and "you asked and I could not
    hash it" are different facts, and the blind one reads as reassuring.
    """
    if digest_hex is not None:
        return digest_hex.strip().lower(), ""
    if file_path is None:
        return None, "no --file or --digest was given"
    from ..hashmark_tx import digest_file

    ids = {r.get("algorithm_id") for r in records if r.get("outcome") == "ok" and r.get("algorithm_id") is not None}
    if not ids:
        return None, "no readable record here names a hash algorithm, so there is nothing to hash the file with"
    if len(ids) > 1:
        # The transaction carries records under DIFFERENT algorithms. One answer would be about
        # whichever one happened to get hashed, so say that instead of picking.
        return None, f"this transaction carries records under {len(ids)} different hash algorithms"
    try:
        return digest_file(file_path, algorithm_id=next(iter(ids))).hex(), ""
    except OSError as exc:
        raise UserError(f"could not read {file_path}", cause=str(exc)) from exc


def judge_digest_match(record: dict, expected_hex: str | None, *, source: str, absent_reason: str = "") -> dict:
    """Does this record commit to *expected_hex*? Pure, and never guesses.

    Three outcomes, kept distinct because two of them are routinely conflated into the third:

    * ``MATCHES`` — the digests are equal. What that is worth is the caller's to render, and
      it is LESS than it sounds: it says whoever signed knew this file's digest by the block
      that confirmed the mark. Not that they wrote it, own it, or were first to it.
    * ``DOES NOT MATCH`` — the digests are both present and differ. A definite, checkable fact
      about the bytes in hand. A width difference lands here too, with its own reason: a 20-byte
      digest is not the 32-byte digest this record commits to, whatever produced it.
    * ``NOT CHECKED`` — there was nothing to compare, or the record carries no digest. Reported
      with the reason, never as a mismatch.
    """
    have = (record.get("digest") or "").lower()
    if expected_hex is None:
        return {"state": "NOT CHECKED", "reason": absent_reason, "source": source}
    if record.get("outcome") != "ok" or not have:
        return {
            "state": "NOT CHECKED",
            "reason": f"this record does not decode ({record.get('outcome')}), so it commits to no digest",
            "source": source,
            "expected": expected_hex,
        }
    if len(expected_hex) != len(have):
        return {
            "state": "DOES NOT MATCH",
            "reason": (
                f"you gave {len(expected_hex) // 2} bytes; this record commits to a "
                f"{len(have) // 2}-byte {record.get('algorithm')} digest"
            ),
            "source": source,
            "expected": expected_hex,
            "record_digest": have,
        }
    ok = expected_hex == have
    return {
        "state": "MATCHES" if ok else "DOES NOT MATCH",
        "reason": "" if ok else "the two digests are the same width and differ",
        "source": source,
        "expected": expected_hex,
        "record_digest": have,
        "algorithm": record.get("algorithm"),
    }


def _signature_check(records: list[dict]) -> tuple[str, str]:
    """The signature state ACROSS every record, and why.

    Refusals are taken from ANY record; affirmations need at least one. Both directions are
    the conservative one: a transaction carrying a forged mark is not made trustworthy by
    also carrying a good one, and a single verified record is enough to say a verified record
    is here. In practice a mark transaction carries exactly one.
    """
    outcomes = [(r.get("attestation") or {}).get("outcome") for r in records]
    if any(r.get("outcome") == "invalid" for r in records):
        detail = next(r.get("detail") for r in records if r.get("outcome") == "invalid")
        return "RECORD DOES NOT DECODE", _sanitize_display_string(
            str(detail or "the bytes claim HashMark and are broken")
        )
    if "invalid_signature" in outcomes:
        detail = next(
            (r.get("attestation") or {}).get("detail")
            for r in records
            if (r.get("attestation") or {}).get("outcome") == "invalid_signature"
        )
        return "DOES NOT VERIFY", _sanitize_display_string(
            str(detail or "the recovered key is not the committed signer")
        )
    if "unverifiable" in outcomes:
        detail = next(
            (r.get("attestation") or {}).get("detail")
            for r in records
            if (r.get("attestation") or {}).get("outcome") == "unverifiable"
        )
        # A MISSING CAPABILITY ON THIS MACHINE, not a verdict on the record. Getting this
        # backwards accuses an honest signer, so it holds and says exactly what is absent.
        return "NOT CHECKED", _sanitize_display_string(str(detail or "no curve library available here"))
    if "valid" in outcomes:
        return "VERIFIED", "the signature recovers to the hash160 committed in the record"
    if any(r.get("outcome") == "ok" and not r.get("signer_hash160") for r in records):
        return "NO SIGNATURE", "a v1 record carries no signer and makes no signature claim"
    return "NOT CHECKED", "no record here carries a signature this tool reads"


def _digest_check(records: list[dict]) -> tuple[str, str]:
    """MATCHES if the expectation equals the digest of at least one record; the reason otherwise."""
    verdicts = [r.get("digest_match") or {} for r in records]
    states = [v.get("state") for v in verdicts]
    if "MATCHES" in states:
        return "MATCHES", next(
            f"equals the digest in record {i}" for i, v in enumerate(verdicts) if v.get("state") == "MATCHES"
        )
    if "DOES NOT MATCH" in states:
        return "DOES NOT MATCH", next(v.get("reason") or "" for v in verdicts if v.get("state") == "DOES NOT MATCH")
    return "NOT CHECKED", next((v.get("reason") or "" for v in verdicts), "there are no records to compare against")


def _name_check(records: list[dict], *, asked: bool) -> tuple[str, str]:
    """ESTABLISHED only for a form-2 verdict whose target at that height IS the signing key.

    FAIL-CLOSED on a degrade. The shipped single-endpoint config cannot reach form 2, so
    `--wave-name` on it lands here — correctly: the question was asked and not answered, and a
    gate that passes on "not answered" is the quiet direction this codebase keeps finding.
    """
    if not asked:
        return "NOT CHECKED", "--wave-name was not given"
    for r in records:
        nam = r.get("name_at_mark") or {}
        if nam.get("form") == 2 and nam.get("signer_is_target_at_height") is True:
            return "ESTABLISHED", f"{nam.get('name')} pointed at the signing key at block {nam.get('height')}"
    for r in records:
        nam = r.get("name_at_mark") or {}
        if nam.get("form") == 2:
            return (
                "NOT THE SIGNER",
                f"{nam.get('name')} pointed at {nam.get('target_at_height')}, which is not the signing key",
            )
    reasons = [
        (r.get("name_at_mark") or {}).get("degraded_reason") or (r.get("name_at_mark") or {}).get("reason")
        for r in records
    ]
    return "NOT ESTABLISHED", _sanitize_display_string(
        str(next((x for x in reasons if x), "no name verdict was produced"))
    )


def _block_check(anchor: dict | None) -> tuple[str, str]:
    """A mark in the mempool fixes no time, and a mark below the floor you set can be reorged out.

    Both are refusals here rather than footnotes: the whole claim is "no later than the block
    that confirms it", so without a block deep enough to stand on there is no claim to hold.
    """
    if not anchor or anchor.get("height") is None:
        return "NO BLOCK", "this transaction is not in a block; a mark in the mempool fixes no time"
    if anchor.get("provisional"):
        return (
            "PROVISIONAL",
            f"{anchor['confirmations']} confirmation(s) against the floor of {anchor['min_confirmations']} you set",
        )
    return "CONFIRMED", f"block {anchor['height']}, {anchor['confirmations']} confirmation(s)"


def _digest_match_lines(dm: dict | None, indent: str = "  ") -> list[str]:
    """The file/digest comparison, printed where the name context is printed.

    OUTSIDE the record's own block, at the outer indent — the same placement rule §7.6 sets for
    a name. The record's statement is about a digest; whether some local file hashes to that
    digest is a fact about a file on this machine, and folding it inside the record's block
    would read as though the record carried it.
    """
    if not dm:
        return []
    state = dm.get("state")
    if state == "NOT CHECKED":
        reason = dm.get("reason") or ""
        return [f"{indent}file/digest: NOT CHECKED" + (f" — {_truncate_for_human(str(reason))}" if reason else "")]
    if state == "MATCHES":
        return [
            f"{indent}file/digest: MATCHES — the {dm.get('algorithm')} you supplied IS the digest in this record",
            f"{indent}  {dm.get('expected')}",
            f"{indent}  (so whoever signed knew THIS content's digest by the block above. Not that",
            f"{indent}   they wrote it, own it, were first to it, or that its contents are true)",
        ]
    return [
        f"{indent}file/digest: DOES NOT MATCH — this is not what the record commits to",
        f"{indent}  you supplied: {dm.get('expected')}",
        f"{indent}  the record:   {dm.get('record_digest')}",
        f"{indent}  ({_truncate_for_human(str(dm.get('reason') or ''))})",
    ]


def _verify_lines(payload: dict, rows: list[dict]) -> list[str]:
    """The whole human answer: a summary, then the detail the summary is derived from.

    THE TWO HALVES CANNOT DISAGREE, and that is structural rather than careful. Every summary
    line reads the same dict the detail below it renders — ``checks`` is computed from the
    record dicts, and the detail is :func:`~pyrxd.cli.glyph_inspect._op_return_payload_lines`
    over those same records. A card fixed in one half while the other half contradicts it is a
    defect this project has shipped before; here there is nothing to keep in step by hand.
    """
    checks = payload["checks"]
    lines = [
        f"Mark: {payload['txid']}",
        f"  network:      {payload['network']}",
        "",
        "  VERDICT" + (" — holds" if payload["verdict_holds"] else " — DOES NOT HOLD"),
        f"    signature:  {checks['signature']['state']:<22} {_truncate_for_human(checks['signature']['reason'])}",
        f"    file:       {checks['digest']['state']:<22} {_truncate_for_human(checks['digest']['reason'])}",
        f"    name:       {checks['name']['state']:<22} {_truncate_for_human(checks['name']['reason'])}",
        f"    block:      {checks['block']['state']:<22} {_truncate_for_human(checks['block']['reason'])}",
        "",
    ]
    lines.extend(mark_anchor_lines(payload.get("mark_anchor"), indent="  "))
    lines.append("")
    for row in rows:
        hm = row.get("hashmark") or {}
        lines.append(f"  HashMark record at vout {row.get('vout')}:")
        lines.extend(_op_return_payload_lines(row, indent="    "))
        lines.extend(_digest_match_lines(hm.get("digest_match"), indent="    "))
        lines.append("")
    lines.append("  WHAT A MARK IS. A signature over a digest, published in a block. It establishes")
    lines.append("  KEY CUSTODY AT THAT BLOCK — that the holder of that key knew that digest by then.")
    lines.append("  It is not authorship, not ownership, not originality, not location, and not a")
    lines.append("  statement that the marked content is true.")
    return lines


def _verify_anchor(ctx: CliContext, payload: dict, *, min_confirmations: int) -> dict:
    """The mark's block — from the name lookup's own anchor when there was one, else our own.

    A HOSTILE SOURCE MUST NOT MOVE BOTH THE NAME BINDING AND THE BLOCK. That rule is enforced
    exactly once, inside :func:`~pyrxd.cli.glyph_inspect._name_at_mark`, which takes the height
    from whichever endpoint did NOT answer ``wave.resolve``. Asking a second server the same
    question here would not re-check that rule, it would bypass it: this call has no idea which
    endpoint supplied the binding, so it could land on the same one.

    So the anchor is INHERITED whenever a name verdict resolved. The invariant that makes that
    safe is structural rather than hopeful: ``_name_at_mark`` returns ``resolved: False`` only
    from the three early returns that all precede the anchor step, and anything failing at or
    after it raises into ``_judge_one_name_at_mark`` and also lands on ``resolved: False``.
    So ``resolved`` implies an anchor, and ``not resolved`` implies no binding was obtained —
    and with no binding there is no pair for one endpoint to move.
    """
    for hm in hashmark_records(payload):
        nam = hm.get("name_at_mark") or {}
        if nam.get("resolved") and nam.get("anchor"):
            return dict(nam["anchor"])

    txid = payload.get("txid")

    async def _do() -> dict:
        # Through the MODULE, not a from-import. `_endpoint_pair` is the one seam both this
        # command and `_name_at_mark` reach the network through, and a name bound here would
        # be a second, independently-patchable copy of it — so a test (or a later change) could
        # move one endpoint and not the other, which is exactly the split this function exists
        # to prevent.
        client_a, label_a, _client_b, _label_b = _inspect._endpoint_pair(ctx)
        async with AsyncExitStack() as stack:
            await stack.enter_async_context(client_a)  # type: ignore[arg-type]
            anchor = await resolve_anchor_from(client_a, label_a, mark_txid=txid, min_confirmations=min_confirmations)
            return mark_anchor_dict(anchor)
        raise AssertionError("unreachable")  # pragma: no cover - AsyncExitStack always returns

    try:
        return asyncio.run(_do())
    except NetworkError as exc:
        raise NetworkBoundaryError(
            "could not establish which block the mark is in",
            cause=str(exc),
            fix=f"check that {ctx.electrumx_url} is reachable; without a block there is no mark claim to check",
        ) from exc


@click.command(name="verify")
@click.argument("txid")
@click.option(
    "--file",
    "file_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Hash this local file with the algorithm the RECORD names and say whether it is what "
    "the mark commits to. The file never leaves this machine.",
)
@click.option(
    "--digest",
    "digest_hex",
    default=None,
    metavar="HEX",
    help="Compare a digest you already have, without the file. Mutually exclusive with --file.",
)
@click.option(
    "--min-confirmations",
    "min_confirmations",
    type=click.IntRange(min=1),
    default=None,
    metavar="N",
    help="Depth below which the mark's block is too shallow to rely on. REQUIRED: a mark's whole "
    "claim is 'no later than the block that confirms it', and depth is value-scaled per chain, "
    "so there is deliberately no default.",
)
@click.option(
    "--wave-name",
    "wave_name",
    default=None,
    metavar="NAME",
    help="HashMark 7.6 form 2: did NAME (e.g. company.rxd) point at the signing key AT THE BLOCK "
    "THAT CARRIED THIS MARK? Needs two configured ElectrumX servers; with one it degrades to "
    "form 1, says why, and the verdict does NOT hold.",
)
@click.option(
    "--verify-wave",
    "verify_wave",
    is_flag=True,
    default=False,
    help="Also list the WAVE names resolving to the signing key RIGHT NOW. Present-tense context, "
    "never part of the mark's verdict.",
)
@click.pass_obj
def verify_cmd(
    ctx: CliContext,
    txid: str,
    file_path: Path | None,
    digest_hex: str | None,
    min_confirmations: int | None,
    wave_name: str | None,
    verify_wave: bool,
) -> None:
    """Check a published HashMark record: who signed, what digest, which block — and, given a
    file, whether it matches.

    TXID is the transaction carrying the mark.

    \b
    A DIGEST AND A TXID ARE THE SAME SHAPE — both are 64 lowercase hex characters, and nothing
    about the string says which it is. The ARGUMENT is always the transaction; a digest is
    passed with --digest, because a digest alone locates nothing: there is no digest-to-txid
    index on Radiant.

    \b
    What the four checks mean:
      signature  VERIFIED / DOES NOT VERIFY / NOT CHECKED / NO SIGNATURE
      file       MATCHES / DOES NOT MATCH / NOT CHECKED
      name       ESTABLISHED / NOT THE SIGNER / NOT ESTABLISHED / NOT CHECKED
      block      CONFIRMED / PROVISIONAL / NO BLOCK

    \b
    Exit codes: 0 the verdict holds, 5 it does not, 1 bad input, 2 network.
    NOT CHECKED never fails the verdict — it means this tool did not check, most often because
    the curve library is absent, and failing on it would accuse an honest signer of forgery for
    something missing on YOUR machine. NOT ESTABLISHED does fail it: you asked a question and it
    could not be answered, and a gate that passes on "not answered" is worse than no gate.

    Read-only: no wallet, no broadcast, no mnemonic prompt. Nothing is sent anywhere but the
    transaction id you typed.
    """
    if file_path is not None and digest_hex is not None:
        raise UserError(
            "--file and --digest both name the thing to compare",
            fix="pass one: --file to hash a local file, --digest if you already have the digest",
        )
    if digest_hex is not None:
        candidate = digest_hex.strip().lower()
        if not candidate or len(candidate) % 2 or any(c not in "0123456789abcdef" for c in candidate):
            raise UserError(
                "--digest is not an even-length hex string",
                cause=f"got {digest_hex!r}",
                fix="pass the digest as hex, e.g. the output of `sha256sum <file>`",
            )
    # The same refusal `glyph inspect --wave-name` raises, from the same function — one rule,
    # one wording. Required here for EVERY run, not only the name ones: `verify` always places
    # the mark at a height, and a height with no floor under it is a number nobody can act on.
    _require_min_confirmations(min_confirmations)

    wanted = txid.strip().lower()
    try:
        Txid(wanted)
    except ValidationError as exc:
        raise UserError(
            "that is not a transaction id",
            cause=str(exc),
            fix="TXID is the transaction carrying the mark — 64 hex characters. If what you have "
            "is the DIGEST (the same shape), it locates nothing on its own: pass it with --digest "
            "and give the mark's txid as the argument.",
        ) from exc

    payload = _run_fetch_inspect(ctx, form="txid", value=wanted)
    rows = [row for row in (payload.get("outputs") or []) if row.get("hashmark")]
    records = hashmark_records(payload)
    if not records:
        raise UserError(
            "no HashMark record in that transaction",
            cause=f"{wanted} has {payload.get('output_count', '?')} output(s) and none of them decodes as a HashMark",
            fix="check the txid. A digest is the same shape as a txid and is not one: if that is "
            "what you have, give the mark's txid and pass the digest with --digest.",
        )

    if verify_wave:
        _attach_wave_identity(ctx, payload)
    if wave_name:
        _attach_name_at_mark(ctx, payload, name=wave_name, min_confirmations=min_confirmations)  # type: ignore[arg-type]

    anchor = _verify_anchor(ctx, payload, min_confirmations=min_confirmations)  # type: ignore[arg-type]

    expected, absent_reason = _digest_expectation(records, file_path=file_path, digest_hex=digest_hex)
    source = "--digest" if digest_hex is not None else (str(file_path) if file_path else "")
    for hm in records:
        hm["digest_match"] = judge_digest_match(
            hm, expected, source=_sanitize_display_string(source), absent_reason=absent_reason
        )

    checks = {
        "signature": dict(zip(("state", "reason"), _signature_check(records), strict=True)),
        "digest": dict(zip(("state", "reason"), _digest_check(records), strict=True)),
        "name": dict(zip(("state", "reason"), _name_check(records, asked=bool(wave_name)), strict=True)),
        "block": dict(zip(("state", "reason"), _block_check(anchor), strict=True)),
    }
    failed = [f"{k}: {v['state']}" for k, v in checks.items() if v["state"] not in _CHECK_HOLDS]

    out = {
        "txid": payload.get("txid"),
        "network": ctx.network,
        "mark_anchor": anchor,
        "records": [{"vout": row.get("vout"), **(row.get("hashmark") or {})} for row in rows],
        "checks": checks,
        "verdict_holds": not failed,
        "verdict_failed_checks": failed,
    }

    if ctx.output_mode == "json":
        click.echo(emit(out, mode="json"))
    elif ctx.output_mode == "quiet":
        # ONE token, and it is the answer — not the txid the caller already typed.
        click.echo("HOLDS" if not failed else "DOES-NOT-HOLD")
    else:
        click.echo("\n".join(_verify_lines(out, rows)))

    if failed:
        # AFTER the report, never instead of it. The reasons are on screen and in the JSON; the
        # exit code is what makes `pyrxd verify ... && deploy` mean something.
        click.get_current_context().exit(EXIT_VERDICT_DOES_NOT_HOLD)


__all__ = ["mark_cmd", "verify_cmd"]
