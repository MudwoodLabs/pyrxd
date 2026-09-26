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
import unicodedata
from pathlib import Path
from typing import TYPE_CHECKING, Any

import click

from ..constants import genesis_hash_for
from ..glyph._inspect_core import _truncate_for_human
from ..glyph.client import BroadcastEchoMismatch
from ..glyph.mark_anchor import MIN_CONFIRMATIONS_MEANING, AnchorBindingError
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
    _require_wave_name,
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


#: How many distinct codepoints the label banner names one by one before summarising.
_MAX_NAMED_LABEL_CODEPOINTS = 8

#: Unicode's Default_Ignorable_Code_Point property, as merged codepoint ranges: what a renderer
#: draws as NOTHING when it has no special handling for it. The variation selectors
#: (U+FE00-FE0F, U+E0100-E01EF), U+034F COMBINING GRAPHEME JOINER, the TAG block and the Hangul
#: fillers are all here — including ones whose general category is Mn or Lo, which is why a
#: category test cannot find them: VS-17..256 are "combining marks", and a run of them after any
#: letter is a published way to carry arbitrary bytes inside text that looks unchanged.
#:
#: GENERATED, NOT HAND-TYPED, AND NOT DERIVED AT RUN TIME. Python's ``unicodedata`` has no accessor
#: for this property, so the ranges were extracted once from DerivedCoreProperties.txt of Unicode
#: 17.0.0 (https://www.unicode.org/Public/17.0.0/ucd/DerivedCoreProperties.txt, file sha256
#: 24c7fed1195c482faaefd5c1e7eb821c5ee1fb6de07ecdbaa64b56a99da22c08), merged, and checked in; the
#: 16.0.0 file yields the identical set. A test pins the membership
#: (`test_the_default_ignorable_table_is_the_reviewed_unicode_17_set`), so a change to it has to be
#: made — and reviewed — on purpose.
_DEFAULT_IGNORABLE: tuple[tuple[int, int], ...] = (
    (0x00AD, 0x00AD),
    (0x034F, 0x034F),
    (0x061C, 0x061C),
    (0x115F, 0x1160),
    (0x17B4, 0x17B5),
    (0x180B, 0x180F),
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x206F),
    (0x3164, 0x3164),
    (0xFE00, 0xFE0F),
    (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0),
    (0xFFF0, 0xFFF8),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0000, 0xE0FFF),
)

#: The two joiners §5.4 calls "load-bearing in Devanagari and emoji sequences".
_JOINERS = frozenset({"\u200c", "\u200d"})

#: Text / emoji presentation selectors. The only default-ignorables an honest label routinely
#: carries on their own, and only straight after a symbol (a heart followed by U+FE0F).
_PRESENTATION_SELECTORS = frozenset({"\ufe0e", "\ufe0f"})


def _is_default_ignorable(ch: str) -> bool:
    cp = ord(ch)
    return any(lo <= cp <= hi for lo, hi in _DEFAULT_IGNORABLE)


def _follows_a_symbol(label: str, i: int) -> bool:
    """Whether position *i* comes straight after a non-ASCII symbol (So, Sm) — an emoji base."""
    return i > 0 and not label[i - 1].isascii() and unicodedata.category(label[i - 1]) in ("So", "Sm")


def _escaped_positions(label: str) -> list[bool]:
    """For each character of *label*, whether `mark` must print it as ``<U+XXXX>``.

    The rule is "escape whatever can be signed without being SEEN", with exactly three ways honest
    text is written left to print as itself — each narrowed to where honest text puts it:

    * a combining mark (Mn, Me) that is NOT default-ignorable. It renders ON its base character:
      the virama and vowel signs of Devanagari, an accent written as a separate mark. The
      default-ignorable combining marks (U+034F, the variation selectors, U+17B4-17B5,
      U+180B-180F) render as nothing and are escaped wherever they are.
    * U+FE0E / U+FE0F straight after a non-ASCII symbol (So, Sm), and nowhere else.
    * ZWJ / ZWNJ between two non-ASCII characters that are themselves printed as written — a
      joined emoji, a Devanagari conjunct. Between ASCII letters (``pay`` + ZWJ + ``pal``) a
      joiner joins nothing visible, so it is escaped.

    Everything else the reader's sanitiser replaces, and every other default-ignorable, is
    escaped. Round 2 exempted every Mn/Me and both joiners by CATEGORY, which let a run of
    variation selectors after ``invoice 42`` — a whole hidden sentence — print as ``invoice 42``
    with no banner. The exemption is now by what renders, and where.
    """
    n = len(label)
    escaped = [False] * n
    for i, ch in enumerate(label):  # everything but the joiners, which depend on their neighbours
        if ch in _JOINERS:
            continue
        if _is_default_ignorable(ch):
            escaped[i] = not (ch in _PRESENTATION_SELECTORS and _follows_a_symbol(label, i))
        elif _sanitize_display_string(ch) != ch:
            escaped[i] = unicodedata.category(ch) not in ("Mn", "Me")

    def _printed_non_ascii(j: int) -> bool:
        return 0 <= j < n and label[j] not in _JOINERS and not label[j].isascii() and not escaped[j]

    for i, ch in enumerate(label):
        if ch in _JOINERS:
            escaped[i] = not (_printed_non_ascii(i - 1) and _printed_non_ascii(i + 1))
    return escaped


def _label_for_display(label: str | None) -> str:
    """The label as `mark` prints it: every character that could be signed unseen becomes ``<U+XXXX>``.

    The raw label is what gets SIGNED, and printing it raw hid part of it: ``invoice 42`` followed
    by Unicode TAG characters spelling ``pay 9999`` showed as ``invoice 42`` on a terminal that
    does not render format characters, while the whole string went into the signature. §5.4's
    reject table does not list those characters, so the encoder accepts them; the defence is to
    make them visible before the operator agrees. See :func:`_escaped_positions` for which ones.
    """
    if label is None:
        return "(none)"
    return "".join(f"<U+{ord(ch):04X}>" if esc else ch for ch, esc in zip(label, _escaped_positions(label)))


def _label_lines(label: str | None, *, head: str, indent: str) -> list[str]:
    """The ``label:`` line, and — for any label with a non-ASCII character — its ``ascii()`` form.

    THE ESCAPES ARE NOT THE WHOLE OF WHAT MISLEADS. Some characters print as something while
    meaning something else: a Cyrillic ``о`` beside Latin letters, a blank Braille pattern
    (U+2800) that renders as white space. Neither renders as nothing, so neither is escaped. The
    ``ascii()`` form names every codepoint, so the operator can see what is about to be signed
    whatever it looks like. An ASCII label gets no second line: its ``ascii()`` would say nothing new.
    """
    lines = [f"{head}{_label_for_display(label)}"]
    if label is not None and not label.isascii():
        lines.append(f"{indent}ascii: {label!a}  (the exact codepoints signed)")
    return lines


def _hidden_label_lines(label: str | None) -> list[str]:
    """The banner for a label that renders as less than it is, or that readers print differently.

    IT FIRES WHENEVER ``pyrxd verify`` AND ``glyph inspect`` WILL PRINT THE LABEL DIFFERENTLY —
    derived from the very function they print it through
    (:func:`~pyrxd.glyph._inspect_core._sanitize_display_string`), not from a list kept here — and
    whenever this screen escaped anything. So the signer is warned exactly when the reader will
    show something other than what they saw. That includes honest text: a Devanagari label prints
    naturally above and reads ``?`` for its combining marks in the reader, and the banner says so.

    SHOWN, NOT REFUSED — and that is a reading of HashMark §5.4, not a convenience. §5.4 names the
    characters an encoder must reject and says outright that ZWJ and ZWNJ are "load-bearing in
    Devanagari and emoji sequences". Refusing everything outside that table that a terminal cannot
    print would refuse text §5.4 permits: combining marks are ordinary in Indic scripts, TAG
    characters spell the England, Scotland and Wales flag emoji, and an emoji newer than this
    Python's Unicode tables is "unassigned" here. pyrxd must not refuse an honest label, so it
    discloses: the codepoints, their names, where each appears above, and how the reader prints it.
    """
    if label is None:
        return []
    escaped = _escaped_positions(label)
    as_read = _sanitize_display_string(label)
    flagged = [i for i, ch in enumerate(label) if escaped[i] or _sanitize_display_string(ch) != ch]
    if not flagged:
        return []
    lines = [
        "",
        f"*** THE LABEL HOLDS {len(flagged)} CHARACTER(S) THAT RENDER AS NOTHING HERE OR THAT `pyrxd verify`",
        "*** PRINTS DIFFERENTLY — EVERY ONE OF THEM IS SIGNED AND PUBLISHED:",
    ]
    distinct = list(dict.fromkeys(label[i] for i in flagged))
    for ch in distinct[:_MAX_NAMED_LABEL_CODEPOINTS]:
        at = [escaped[i] for i in flagged if label[i] == ch]
        if all(at):
            here = f"shown above as <U+{ord(ch):04X}>"
        elif not any(at):
            here = "printed above as written"
        else:
            here = f"printed as written in one place, as <U+{ord(ch):04X}> in another"
        read = "verify prints it as ?" if _sanitize_display_string(ch) != ch else "verify prints it as written"
        name = unicodedata.name(ch, "(no Unicode name: unassigned or private use)")
        lines.append(f"***   U+{ord(ch):04X}  {name} — {here}; {read}")
    if len(distinct) > _MAX_NAMED_LABEL_CODEPOINTS:
        lines.append(f"***   ... and {len(distinct) - _MAX_NAMED_LABEL_CODEPOINTS} more distinct codepoint(s)")
    if as_read != label:
        lines.append(f"*** `pyrxd verify` and `glyph inspect` will print this label as: {as_read}")
    lines.append("*** HashMark 5.4 does not forbid these, and honest text uses some of them, so they are shown,")
    lines.append("*** not refused. If you did not put them there, do not publish this: retype the label.")
    return lines


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

    NOTHING HERE IS PRINTED RAW THAT SOMEONE ELSE COULD HAVE CHOSEN. The file path is sanitised
    the way `verify` already sanitised it — a file named ``report.pdf\\x1b[8m`` switched the
    terminal to concealed text for every line after it, the fee and the warnings included — and
    the label is escaped, see :func:`_label_for_display`.
    """
    plan = build.plan
    raw = build.serialize()
    lines = [
        f"file:        {_sanitize_display_string(plan.source) if plan.source is not None else '(not recorded)'}",
        f"{plan.algorithm}:      {plan.digest_hex}",
        *_label_lines(plan.label, head="label:       ", indent="             "),
        f"signer:      {signer_address}",
        f"             hash160 {plan.signer_hash160_hex} — committed in the record and in the statement",
        f"network:     {network} (genesis {plan.network_genesis})",
        f"record:      {plan.size_bytes} B of the 223-byte ceiling",
        f"funded from: {build.from_address}",
        f"fee:         {build.fee:,} photons ({len(raw)} B @ {fee_rate:,}/B)"
        + ("" if build.has_change else " — no change: the whole funding UTXO is the fee"),
    ]
    lines.extend(_hidden_label_lines(plan.label))
    if typed_label is not None and plan.label != typed_label:
        lines.append("")
        lines.append("*** LABEL CANONICALISED — what gets signed is NOT what you typed:")
        lines.append(f"***   you typed:  {typed_label!a}")
        lines.append(f"***   published:  {plan.label!a}")
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
        raise UserError(
            f"could not read {_sanitize_display_string(str(file_path))}", cause=_sanitize_display_string(str(exc))
        ) from exc

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
        click.echo(f"               label={record.label!a} signer={record.signer_hash160_hex}")
        click.echo(f"               signature (unverified by a third party)={record.signature_hex}")
        click.echo(f"  raw tx:      {payload['raw_tx_hex']}")
        click.echo("\n  Re-run without --dry-run to publish it.")
    else:
        click.echo(f"\nMarked: {txid}")
        click.echo(f"  file:       {_sanitize_display_string(str(file_path))}")
        click.echo(f"  {build.plan.algorithm}:     {build.plan.digest_hex}")
        for line in _label_lines(build.plan.label, head="  label:      ", indent="              "):
            click.echo(line)
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
#: "NOT ESTABLISHED" does not. In THIS command "NOT CHECKED" means the tool did not examine
#: something: a question the caller did not ask (no --file/--digest, no --wave-name), or a
#: record this build cannot read (an unknown version or hash), which has no signature it could
#: check. Neither is a finding against the record, and failing the verdict on it would accuse an
#: honest signer. So it is reported loudly and does not fail.
#:
#: NOT "the curve library is absent", which this used to say. That is the shared inspect core's
#: case in the BROWSER; the CLI cannot even import without coincurve, which
#: `test_the_cli_cannot_load_without_a_curve_so_not_checked_never_means_that` pins. On the WRITE
#: side `MarkPlan` refuses an UNVERIFIABLE attestation outright: a mark nobody could self-check
#: must not be published.
#:
#: "NOT ESTABLISHED" is the opposite case: the caller ASKED a question (`--wave-name`) and it
#: could not be answered. A gate that waves that through is the quiet, dangerous direction.
_CHECK_HOLDS = frozenset(
    {
        "VERIFIED",
        "NO SIGNATURE",  # a v1 record makes no signature claim; there is nothing to fail
        "NOT CHECKED",  # a question the caller did not ask, or a record this build cannot read
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
        raise UserError(
            f"could not read {_sanitize_display_string(str(file_path))}", cause=_sanitize_display_string(str(exc))
        ) from exc


def _why_no_digest_to_compare(record: dict) -> str:
    """Why a record gave nothing to compare a file against — in words that fit THAT record.

    It said "this record does not decode (unknown_version), so it commits to no digest" for every
    unreadable record. Both halves were wrong for a record from a newer version: "does not
    decode" is this command's word for a MALFORMED record (RECORD DOES NOT DECODE), and a
    well-formed record of an unknown version or hash may very well commit to a digest — this
    build just cannot read it.
    """
    outcome = record.get("outcome")
    version, algorithm_id = record.get("version"), record.get("algorithm_id")
    if outcome == "unknown_version":
        return f"this build cannot read a version-{version} record, so its digest could not be compared"
    if outcome == "unknown_algorithm":
        named = f"0x{algorithm_id:02x}" if isinstance(algorithm_id, int) else "an algorithm"
        return (
            f"this record names hash algorithm {named}, which this build does not implement, "
            "so its digest could not be compared"
        )
    if outcome == "invalid":
        return "this record is malformed (RECORD DOES NOT DECODE), so no digest can be read from it"
    return f"this record could not be read ({outcome}), so its digest could not be compared"


def judge_digest_match(
    record: dict, expected_hex: str | None, *, source: str, asked: bool, absent_reason: str = ""
) -> dict:
    """Does this record commit to *expected_hex*? Pure, and never guesses.

    Four outcomes, kept distinct because two of them are routinely conflated into the third:

    * ``MATCHES`` — the digests are equal. What that is worth is the caller's to render, and
      it is LESS than it sounds: it says someone knew this file's digest by the block that
      confirmed the mark — the signer, if the record is signed and verifies. Not that they wrote
      it, own it, or were first to it.
    * ``DOES NOT MATCH`` — the digests are both present and differ. A definite, checkable fact
      about the bytes in hand. A width difference lands here too, with its own reason: a 20-byte
      digest is not the 32-byte digest this record commits to, whatever produced it.
    * ``NOT CHECKED`` — nothing was asked: no ``--file`` and no ``--digest``. Holds.
    * ``CANNOT COMPARE`` — something WAS asked and there is nothing to compare it with: the
      record is one this build cannot read, or no digest could be computed from the file. Never
      a mismatch — it accuses nobody — but it FAILS the verdict, for the same reason an
      unanswered ``--wave-name`` does. It used to be reported as ``NOT CHECKED``, which holds,
      so ``verify <txid> --file ANYTHING`` exited 0 on a transaction whose only record had an
      unknown version: the question was asked and never answered.

    ``asked`` has NO DEFAULT on purpose. A default of ``False`` would hand every caller that
    forgot it the passing state; and a non-``None`` *expected_hex* is itself proof something was
    asked, so that case is ``CANNOT COMPARE`` whatever ``asked`` says.
    """
    have = (record.get("digest") or "").lower()
    if expected_hex is None:
        return {"state": "CANNOT COMPARE" if asked else "NOT CHECKED", "reason": absent_reason, "source": source}
    if record.get("outcome") != "ok" or not have:
        return {
            "state": "CANNOT COMPARE",
            "reason": _why_no_digest_to_compare(record),
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


def _signature_check(record: dict) -> tuple[str, str]:
    """The signature state of ONE record, and why.

    ONE record, not a list, and that is the fix rather than a style choice. This used to take
    every record in the transaction and affirm VERIFIED if ANY record verified — while
    ``_digest_check`` affirmed MATCHES if any record matched and ``_name_check`` affirmed
    ESTABLISHED if any record's name did. Three independent "any"s make a verdict true of no
    single record: a victim's genuine v2 record copied verbatim beside an unsigned v1 record
    over someone else's file printed VERIFIED + MATCHES + ESTABLISHED and exited 0. (The v2
    statement binds network, algorithm, digest, label and version — NOT the transaction — so
    anyone can copy one.) Taking a single record makes that composition unrepresentable here;
    :func:`_record_checks` is where the three are combined, and only for one record.

    The "a forged record anywhere fails the transaction" rule is kept, in
    :func:`_tx_refusal`, which calls this once per record.
    """
    # THE STATUS WORDS ARE LITERALS HERE ON PURPOSE, and they are not free-floating.
    # `_inspect_core._ATTESTATION_VERDICTS` is the one definition of what each
    # attestation outcome is CALLED — `glyph inspect` and the browser panel read it
    # directly — and `test_the_status_words_match_the_shared_table` below pins every
    # literal below to it, so the three surfaces cannot come to describe one record
    # differently.
    #
    # Why a pin rather than reading the table here: `test_every_state_the_checks_can_emit
    # _is_classified` derives the emitted set by AST-scanning THESE returns for string
    # constants, and routing them through a call made the set invisible — the guard then
    # correctly reported that `_CHECK_HOLDS` named states nothing emits. Keeping the
    # literals keeps that derivation working; the pin keeps them true.
    att = record.get("attestation") or {}
    outcome = att.get("outcome")
    if record.get("outcome") == "invalid":
        return "RECORD DOES NOT DECODE", _sanitize_display_string(
            str(record.get("detail") or "the bytes claim HashMark and are broken")
        )
    # THE CHAIN IS PART OF THE ANSWER. The genesis hash is inside the signed statement, so the
    # same record verifies on the chain it was signed for and DOES NOT VERIFY on any other. A
    # summary of "DOES NOT VERIFY" with no chain named read an honest testnet record, checked
    # on the default mainnet, as a plain forgery. Named on every outcome that involves a key.
    net = att.get("assumed_network")
    against = f" (checked against {net})" if net else ""
    if outcome == "invalid_signature":
        return "DOES NOT VERIFY", _sanitize_display_string(
            str(att.get("detail") or "the recovered key is not the committed signer")
            + (
                f" — checked against {net}; a record signed for another chain does not verify here, "
                "so if it was made on another network, re-run with that --network"
                if net
                else ""
            )
        )
    if outcome == "unverifiable":
        # A MISSING CAPABILITY ON THIS MACHINE, not a verdict on the record. Getting this
        # backwards accuses an honest signer, so it holds and says exactly what is absent.
        return "NOT CHECKED", _sanitize_display_string(
            str(att.get("detail") or "no curve library available here")
            + (f" (it would be checked against {net})" if net else "")
        )
    if outcome == "valid":
        return "VERIFIED", f"the signature recovers to the hash160 committed in the record{against}"
    if record.get("outcome") == "ok" and not record.get("signer_hash160"):
        return "NO SIGNATURE", "a v1 record carries no signer and makes no signature claim"
    return "NOT CHECKED", "this record carries no signature this tool reads"


def _digest_check(record: dict) -> tuple[str, str]:
    """Whether the file or digest the caller supplied is the one THIS record commits to.

    One record: a MATCHES taken from any record in the transaction is how an unsigned v1 record
    over one file lent its MATCHES to a signed record that commits to a different one.
    """
    verdict = record.get("digest_match") or {}
    state = verdict.get("state")
    if state == "MATCHES":
        return "MATCHES", "equals the digest in this record"
    if state == "DOES NOT MATCH":
        return "DOES NOT MATCH", verdict.get("reason") or ""
    if state == "CANNOT COMPARE":
        return "CANNOT COMPARE", verdict.get("reason") or ""
    return "NOT CHECKED", verdict.get("reason") or "no --file or --digest was given"


def _name_check(record: dict, *, asked: bool) -> tuple[str, str]:
    """ESTABLISHED only for a form-2 verdict whose target at that height is THIS record's signing key.

    FAIL-CLOSED on a degrade. With ONE configured endpoint (``--electrumx URL``,
    ``PYRXD_ELECTRUMX``, or a config naming a single server) form 2 is unreachable, so
    `--wave-name` lands here — correctly: the question was asked and not answered, and a gate
    that passes on "not answered" is the quiet direction this codebase keeps finding. That is
    NOT the shipped mainnet default: ``network/registry.py`` ships two independent endpoints, so
    form 2 — and ESTABLISHED — is reachable with no configuration at all.
    """
    if not asked:
        return "NOT CHECKED", "--wave-name was not given"
    nam = record.get("name_at_mark") or {}
    if nam.get("form") == 2 and nam.get("signer_is_target_at_height") is True:
        return "ESTABLISHED", f"{nam.get('name')} pointed at the signing key at block {nam.get('height')}"
    if nam.get("form") == 2:
        return (
            "NOT THE SIGNER",
            f"{nam.get('name')} pointed at {nam.get('target_at_height')}, which is not the signing key",
        )
    return "NOT ESTABLISHED", _sanitize_display_string(
        str(nam.get("degraded_reason") or nam.get("reason") or "no name verdict was produced")
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
    if state in ("NOT CHECKED", "CANNOT COMPARE"):
        # Both are inabilities, never accusations. CANNOT COMPARE needs its own branch here or it
        # falls through to the DOES NOT MATCH rendering below — a mismatch nobody measured.
        reason = dm.get("reason") or ""
        return [f"{indent}file/digest: {state}" + (f" — {_truncate_for_human(str(reason))}" if reason else "")]
    if state == "MATCHES":
        return [
            f"{indent}file/digest: MATCHES — the {dm.get('algorithm')} you supplied IS the digest in this record",
            f"{indent}  {dm.get('expected')}",
            # "someone", not "whoever signed": a v1 record has no signer, and in a transaction
            # of several records this line sits under whichever record matched.
            f"{indent}  (so someone knew THIS content's digest by the block above — the signer, if this",
            f"{indent}   record is signed and verifies. Not that they wrote it, own it, were first to",
            f"{indent}   it, or that its contents are true)",
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
        f"    record:     {'vout ' + str(payload['verdict_record']['vout']):<22} {_verdict_record_about(payload)}",
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
    # THE WEAKER SENTENCE, because it is the true one. This said "KEY CUSTODY AT THAT BLOCK", and
    # a signed record supports less than that: the statement does not bind the transaction, so
    # anyone can copy a genuine record into a transaction of their own, in a later block. What
    # survives the copy is that the key had signed this digest by the block that carries it.
    lines.append("  WHAT A MARK IS. A digest published in a block, usually with a signature over it.")
    lines.append("  It establishes that the digest was known by that block and, if the signature")
    lines.append("  verifies, that the key had signed it by then — NOT that the key's holder put it")
    lines.append("  here: a signed record can be copied into anyone's transaction. It is not")
    lines.append("  authorship, not ownership, not originality, not location, and not a statement")
    lines.append("  that the marked content is true.")
    return lines


def _verdict_record_about(payload: dict) -> str:
    """Which record the summary lines describe, in words — and when one of them does not.

    Every summary line must be true of ONE record, and the reader has to be told which. The one
    line that can come from elsewhere is the signature line, when another record is broken or
    forged: that fails the whole transaction, and saying "all about THIS one" over it would put
    two records' facts under one heading, which is the defect this line exists to prevent.
    """
    rec = payload["verdict_record"]
    n = rec["records_in_tx"]
    refused = rec.get("refusal_vout")
    if n == 1:
        return "the only HashMark record in this transaction"
    if refused is not None and refused != rec["vout"]:
        return (
            f"one of {n} HashMark records; file and name are about THIS one, and the signature line is "
            f"about the record at vout {refused}, because a broken or forged record anywhere fails the "
            "whole transaction"
        )
    if rec["all_record_checks_hold"]:
        return f"one of {n} HashMark records here; signature, file and name below are all about THIS one"
    return (
        f"of the {n} HashMark records here, none passes every check on its own; this is the closest, "
        "and each record is shown separately below"
    )


def _as_check(state_reason: tuple[str, str]) -> dict:
    state, reason = state_reason
    return {"state": state, "reason": reason}


def _record_checks(hm: dict, *, name_asked: bool) -> dict[str, dict]:
    """The three checks that are facts about ONE record, each computed from that record ALONE.

    THE VERDICT IS ABOUT ONE RECORD, and this is the one place the three checks are put
    together — for a single record. Each of the check functions takes one record, so there is
    no list to aggregate over by accident.
    """
    return {
        "signature": _as_check(_signature_check(hm)),
        "digest": _as_check(_digest_check(hm)),
        "name": _as_check(_name_check(hm, asked=name_asked)),
    }


def _all_hold(checks: dict[str, dict]) -> bool:
    return all(c["state"] in _CHECK_HOLDS for c in checks.values())


def _choose_witness(per_record: list[tuple[Any, dict, dict]]) -> tuple[Any, dict, dict]:
    """The record the summary is about: one that passes every check if any does, else the closest.

    Choosing it cannot make a failing transaction hold: if any record passes all three checks,
    the one chosen does too (the first sort key is how many hold), and if none does, the one
    chosen does not either. What the choice decides is only which record's words are shown.

    Among records that all pass, the STRONGEST is shown — a verified signature over a v1 record's
    NO SIGNATURE, an established name over an unasked one — so a v1 record sharing a transaction
    with a signed record over the same digest does not hide the signature. Ties go to the lowest
    vout, so the answer does not depend on iteration order.
    """

    def rank(item: tuple[Any, dict, dict]) -> tuple:
        vout, _hm, checks = item
        return (
            sum(c["state"] in _CHECK_HOLDS for c in checks.values()),
            checks["signature"]["state"] == "VERIFIED",
            checks["digest"]["state"] == "MATCHES",
            checks["name"]["state"] == "ESTABLISHED",
            -(vout if isinstance(vout, int) else 0),
        )

    return max(per_record, key=rank)


def _tx_refusal(per_record: list[tuple[Any, dict, dict]]) -> tuple[Any, dict] | None:
    """``(vout, signature check)`` of the first record that is broken or forged, or ``None``.

    Kept from the old rule, and the conservative direction: a transaction carrying a forgery is
    not made trustworthy by also carrying a good record.

    IT DOES REFUSE HONEST WORK IN ONE CASE, and that is a choice, not an accident. A third party
    cannot add an output to a transaction someone else signed — but a transaction can BATCH
    several parties' records (a marking service publishing many customers' marks at once), and
    then one party's broken or mis-signed record fails the verdict for every honest record beside
    it. That is kept because `verify` is a gate that scripts run (`pyrxd verify … && deploy`), and
    a gate should fail closed on a transaction that carries a forgery. The honest record is not
    hidden: its own checks are in ``records[i].checks`` in ``--json``, and the summary names the
    vout that failed. Stated in ``--help`` too. Named by vout, because the summary's record line
    may be about another record.
    """
    for vout, _hm, checks in per_record:
        sig = checks["signature"]
        if sig["state"] not in _CHECK_HOLDS:
            return vout, {
                "state": sig["state"],
                "reason": f"the record at vout {vout}: {sig['reason']}",
            }
    return None


def _verify_anchor(ctx: CliContext, payload: dict, *, min_confirmations: int, prefer: dict | None = None) -> dict:
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

    ``prefer`` is the record the verdict is about, and it is tried FIRST. Each record's name
    lookup runs on its own and may take its binding from a different endpoint (a transient
    failure on one), so an anchor inherited from ANOTHER record could have come from the very
    endpoint that supplied THIS record's binding — the one pairing the rule above forbids.
    """
    ordered = ([prefer] if prefer is not None else []) + [hm for hm in hashmark_records(payload) if hm is not prefer]
    for hm in ordered:
        nam = hm.get("name_at_mark") or {}
        if nam.get("resolved") and nam.get("anchor"):
            return dict(nam["anchor"])

    txid = payload.get("txid")

    asked: list[str] = []  # the endpoint `_do` asked, for an error that names it

    async def _do() -> dict:
        # Through the MODULE, not a from-import. `_endpoint_pair` is the one seam both this
        # command and `_name_at_mark` reach the network through, and a name bound here would
        # be a second, independently-patchable copy of it — so a test (or a later change) could
        # move one endpoint and not the other, which is exactly the split this function exists
        # to prevent.
        #
        # ONE endpoint, pinned to ONE URL — not `ctx.make_client()`. A failover client retries
        # across endpoints, so the label it carries would name the configured primary rather
        # than whoever actually answered, and `MarkAnchor.source` is the field the independence
        # rule is checked against. A source label that is a guess is worse than no label.
        client_a, label_a, _client_b, _label_b = _inspect._endpoint_pair(ctx)
        asked.append(label_a)
        async with client_a:  # type: ignore[attr-defined]
            anchor = await resolve_anchor_from(client_a, label_a, mark_txid=txid, min_confirmations=min_confirmations)
        return mark_anchor_dict(anchor)

    try:
        return asyncio.run(_do())
    except AnchorBindingError as exc:
        # THE ENDPOINT ANSWERED. "Check that it is reachable" sent people to debug a connection that
        # worked (0.25.0 panel, round 3). WHICH failure it was comes from the exception's attributes,
        # not its words: "its index and its node disagree" only when every header in the window was
        # served and none matched — with one missing, the missing one may be the match, and the
        # sentence would accuse an honest server (0.25.0 review, round 2).
        where = asked[0] if asked else ctx.electrumx_url
        retry = "re-run in a moment, or ask another server with --electrumx URL"
        if exc.disagrees:
            fix = (
                f"{where} answered, but its index and its node disagree about the mark's block — re-run in "
                "a moment (a new block usually settles it), or ask another server with --electrumx URL"
            )
        elif exc.unserved:
            heights = ", ".join(map(str, sorted(exc.unserved)))
            fix = (
                f"{where} answered, but did not serve the block headers at heights {heights}, so the "
                f"mark's block could not be checked — {retry}"
            )
        else:
            fix = f"{where} answered, but named no block for the mark's transaction — {retry}"
        raise NetworkBoundaryError(
            "could not establish which block the mark is in",
            cause=str(exc),
            fix=fix,
        ) from exc
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
    help=f"The confirmation floor for the mark's block — {MIN_CONFIRMATIONS_MEANING}. Below it the "
    "block is too shallow to rely on. REQUIRED: a mark's whole claim is 'no later than the block "
    "that confirms it', and depth is value-scaled per chain, so there is deliberately no default.",
)
@click.option(
    "--wave-name",
    "wave_name",
    default=None,
    metavar="NAME",
    help="HashMark 7.6 form 2: did NAME (e.g. company.rxd) point at the signing key AT THE BLOCK "
    "THAT CARRIED THIS MARK? Needs two configured ElectrumX servers that report the same block "
    "heights; with one, or if they disagree, it degrades to form 1, says why, and the verdict "
    "does NOT hold.",
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
      signature  VERIFIED / DOES NOT VERIFY / RECORD DOES NOT DECODE / NOT CHECKED / NO SIGNATURE
      file       MATCHES / DOES NOT MATCH / CANNOT COMPARE / NOT CHECKED
      name       ESTABLISHED / NOT THE SIGNER / NOT ESTABLISHED / NOT CHECKED
      block      CONFIRMED / PROVISIONAL / NO BLOCK

    \b
    THE VERDICT IS ABOUT ONE RECORD. A transaction can carry several HashMark outputs, and the
    signature, file and name checks must all hold for the SAME one; the summary names its vout.
    A record that does not decode, or whose signature does not verify, fails the whole
    transaction wherever it sits — including a BATCHED transaction that carries several
    parties' records, where one bad record fails the verdict for an honest one beside it. That
    is deliberate (a gate should fail closed on a transaction carrying a forgery); --json shows
    each record's own checks under records[i].checks.

    \b
    What HOLDS means, and no more: one record passes every check you asked for, no record in the
    transaction is broken or forged, and the block is at or past your floor. It does not mean the
    record says anything in particular. With no --file, --digest or --wave-name, a record this
    build cannot read (a newer version, an unknown hash) holds with its checks reading NOT
    CHECKED — nothing was asked of it, so nothing failed.

    \b
    Exit codes: 0 the verdict holds, 5 it does not, 1 bad input, 2 network.
    NOT CHECKED never fails the verdict. Here it means you did not ask that question (no --file
    or --digest, no --wave-name), or the record is a version or hash this build cannot read, so
    no signature in it could be checked. Neither is a finding against the record, and failing
    on it would accuse an honest signer. NOT ESTABLISHED and CANNOT COMPARE do fail it: you asked a
    question and it could not be answered, and a gate that passes on "not answered" is worse
    than no gate.

    Read-only: no wallet, no broadcast, no mnemonic prompt. The configured ElectrumX servers see
    the transaction id you typed; with --wave-name they also see that name, and with
    --verify-wave a lookup keyed on the signer's address. A --file is hashed on this machine and
    never sent.
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
    # The same shape of refusal as --digest "" above, and for the same reason: an empty value is
    # a question typed wrong, not a question not asked. See `_require_wave_name`.
    wave_name = _require_wave_name(wave_name)
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
    # The same refusal `glyph inspect --wave-name` raises, from the same function — one rule. The
    # WORDING is this command's: required here for EVERY run, not only the name ones, because
    # `verify` always places the mark at a height and a height with no floor under it is a number
    # nobody can act on. Naming --wave-name here refused `pyrxd verify <txid>` over a flag the user
    # had not passed. After the txid check, so the command it tells you to re-run is a valid one.
    _require_min_confirmations(min_confirmations, needed_by="pyrxd verify", command=f"pyrxd verify {wanted}")

    payload = _run_fetch_inspect(ctx, form="txid", value=wanted)
    rows = [row for row in (payload.get("outputs") or []) if row.get("hashmark")]
    # FROM THE ROWS, so a record and its vout cannot come apart: every check below is attached
    # to a record, and the summary names the record by the vout of the row it came from.
    records = [row["hashmark"] for row in rows]
    if not records:
        raise UserError(
            "no HashMark record in that transaction",
            cause=f"{wanted} has {payload.get('output_count', '?')} output(s) and none of them decodes as a HashMark",
            fix="check the txid. A digest is the same shape as a txid and is not one: if that is "
            "what you have, give the mark's txid and pass the digest with --digest.",
        )

    # `is not None`, NEVER truthiness, for every "was this asked?" below. A falsy-but-present value
    # read as "not asked" is how `--wave-name ""` passed the gate; see `_require_wave_name`.
    name_asked = wave_name is not None
    if verify_wave:
        _attach_wave_identity(ctx, payload)
    if name_asked:
        _attach_name_at_mark(ctx, payload, name=wave_name, min_confirmations=min_confirmations)  # type: ignore[arg-type]

    expected, absent_reason = _digest_expectation(records, file_path=file_path, digest_hex=digest_hex)
    source = "--digest" if digest_hex is not None else (str(file_path) if file_path is not None else "")
    for hm in records:
        hm["digest_match"] = judge_digest_match(
            hm,
            expected,
            source=_sanitize_display_string(source),
            asked=file_path is not None or digest_hex is not None,
            absent_reason=absent_reason,
        )

    # ONE RECORD, EVERY CHECK. Each record is judged alone; the summary is ONE record's checks
    # (the witness), plus the transaction-wide refusal and the block. See `_signature_check`.
    per_record = [
        (row.get("vout"), row["hashmark"], _record_checks(row["hashmark"], name_asked=name_asked)) for row in rows
    ]
    w_vout, w_hm, w_checks = _choose_witness(per_record)
    refusal = _tx_refusal(per_record)

    anchor = _verify_anchor(ctx, payload, min_confirmations=min_confirmations, prefer=w_hm)  # type: ignore[arg-type]

    checks = {
        "signature": refusal[1] if refusal else w_checks["signature"],
        "digest": w_checks["digest"],
        "name": w_checks["name"],
        "block": _as_check(_block_check(anchor)),
    }
    failed = [f"{k}: {v['state']}" for k, v in checks.items() if v["state"] not in _CHECK_HOLDS]

    out = {
        "txid": payload.get("txid"),
        "network": ctx.network,
        "mark_anchor": anchor,
        # Each record carries ITS OWN three checks, so a JSON consumer can see every record's
        # answer rather than only the one the summary is about.
        "records": [{"vout": vout, **hm, "checks": c} for vout, hm, c in per_record],
        "checks": checks,
        # WHICH record `checks` describes. Without it a consumer cannot tell a verdict about one
        # record from a collage of several — which is what `checks` used to be.
        "verdict_record": {
            "vout": w_vout,
            "records_in_tx": len(per_record),
            "all_record_checks_hold": _all_hold(w_checks),
            "refusal_vout": refusal[0] if refusal else None,
        },
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
