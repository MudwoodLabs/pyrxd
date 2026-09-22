"""``pyrxd glyph inspect`` — read-only classifier for Glyph inputs.

Extracted from :mod:`pyrxd.cli.glyph_cmds` so the single largest, most
self-contained feature in that module stands on its own. ``inspect`` is
read-only by design (no wallet load, no broadcast, no mnemonic prompt):
it classifies a txid / contract id / outpoint / hex locking script and
renders the result in json / quiet / human modes.

The pure classifiers and threat-model constants live one layer down in
:mod:`pyrxd.glyph._inspect_core` so the browser-hosted inspect tool
(loaded into Pyodide) can import them without dragging in the CLI's
``click`` / wallet / network dependencies. The thin wrappers here
translate the SDK-level :class:`~pyrxd.security.errors.ValidationError`
into the CLI-shaped :class:`~pyrxd.cli.errors.UserError` with the
cause/fix decorations the formatter expects.

The command object is built with a bare ``@click.command`` and attached
to the ``glyph`` group by :mod:`pyrxd.cli.glyph_cmds` via
``glyph_group.add_command(inspect_cmd)`` — the canonical Click pattern
for splitting a group's subcommands across modules.
"""

from __future__ import annotations

import asyncio
import logging
import textwrap
from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

import click

from ..glyph._inspect_core import _HUMAN_ENTRY_CAP, _attestation_verdict, _truncate_for_human
from ..glyph._inspect_core import _HUMAN_STRING_CAP as _HUMAN_STRING_CAP
from ..glyph._inspect_core import _classify_input as _classify_input_core
from ..glyph._inspect_core import _classify_raw_tx as _classify_raw_tx_core
from ..glyph._inspect_core import _inspect_contract as _inspect_contract_core
from ..glyph._inspect_core import _inspect_outpoint as _inspect_outpoint_core
from ..glyph._inspect_core import _inspect_script as _inspect_script_core
from ..glyph._inspect_core import _sanitize_display_string as _sanitize_display_string
from ..glyph.mark_anchor import mark_anchor_dict
from ..glyph.relationships import resolve_delegated_refs
from ..glyph.types import GlyphRef
from ..script.timelock import LOCKTIME_THRESHOLD
from ..security.errors import NetworkError, ValidationError
from ..security.types import Txid
from ..transaction.transaction import Transaction
from .context import CliContext
from .errors import NetworkBoundaryError, UserError
from .format import emit

if TYPE_CHECKING:
    from ..network.electrumx import ElectrumXClient

_log = logging.getLogger(__name__)

#: Most delegate bases one `inspect --fetch` will resolve. See the loop below.
_MAX_DELEGATE_BASES = 25

__all__ = [
    "hashmark_records",
    "inspect_cmd",
    "mark_anchor_dict",
    "mark_anchor_lines",
    "resolve_anchor_from",
]


# Input forms recognised by `glyph inspect`. Each is unambiguous by shape:
#   txid       — exactly 64 lowercase-hex chars
#   contract   — exactly 72 lowercase-hex chars (txid + BE vout)
#   outpoint   — anything containing ":"
#   script     — any other hex string of even length (>= 46 chars / 23 bytes)
# Everything else is a UserError.


def _classify_input(s: str) -> tuple[str, str]:
    """CLI wrapper: translate ``ValidationError`` to ``UserError``."""
    try:
        return _classify_input_core(s)
    except ValidationError as exc:
        msg = str(exc)
        if msg == "inspect input is empty":
            raise UserError(msg) from exc
        # The "could not classify" case carries the input length in the
        # message; the original CLI exposed that plus a cause/fix pair.
        raise UserError(
            msg,
            cause="input is not a 64-char txid, 72-char contract id, txid:vout outpoint, or 46-20000 char hex script",
            fix="paste a 64-char txid (with --fetch), 72-char contract id, txid:vout, or hex script",
        ) from exc


def _inspect_contract(contract_hex: str) -> dict:
    """CLI wrapper: translate ``ValidationError`` to ``UserError``."""
    try:
        return _inspect_contract_core(contract_hex)
    except ValidationError as exc:
        raise UserError("contract id failed to parse", cause=str(exc)) from exc


def _inspect_outpoint(s: str) -> dict:
    """CLI wrapper: translate ``ValidationError`` to ``UserError``.

    The shape errors carried by ``_inspect_outpoint_core`` are
    self-contained (e.g. ``"vout is not an integer"``); parser errors
    from downstream get the historic ``"outpoint failed to parse"``
    prefix so existing CLI test assertions match unchanged."""
    try:
        return _inspect_outpoint_core(s)
    except ValidationError as exc:
        msg = str(exc)
        if msg.startswith("outpoint must be") or msg.startswith("vout is not an integer"):
            raise UserError(msg) from exc
        raise UserError("outpoint failed to parse", cause=msg) from exc


def _inspect_script(script_hex: str, *, network: str = "mainnet") -> dict:
    """CLI wrapper: translate ``ValidationError`` to ``UserError``."""
    try:
        return _inspect_script_core(script_hex, network=network)
    except ValidationError as exc:
        raise UserError(str(exc)) from exc


def _classify_raw_tx(
    txid_hex: str,
    raw: bytes,
    *,
    only_vout: int | None = None,
    network: str = "mainnet",
    delegated_refs: Mapping[bytes, Sequence[bytes]] | None = None,
    spent_scripts: Mapping[int, bytes] | None = None,
) -> dict:
    """CLI wrapper: translate ``ValidationError`` to ``UserError`` with
    the historic CLI-formatted cause/fix decorations.

    The core raises a flat ``ValidationError`` whose message embeds the
    relevant detail. Pattern-match on the message to reconstruct the
    CLI's three-line ``error / cause / fix`` formatting so existing
    test assertions (e.g. on ``"--electrumx"``) keep matching."""
    try:
        return _classify_raw_tx_core(
            txid_hex,
            raw,
            only_vout=only_vout,
            network=network,
            delegated_refs=delegated_refs,
            spent_scripts=spent_scripts,
        )
    except ValidationError as exc:
        msg = str(exc)
        if "raw bytes too short" in msg:
            raise UserError(
                "raw bytes too short for a valid transaction",
                cause=f"got {len(raw)} bytes; need >64",
                fix="confirm the source returned a real transaction, not a header or stub",
            ) from exc
        if "transaction is larger than the policy max" in msg:
            from ..glyph._inspect_core import _MAX_RAW_TX_BYTES

            raise UserError(
                "transaction is larger than the policy max",
                cause=f"server returned {len(raw)} bytes; policy max is {_MAX_RAW_TX_BYTES}",
                fix="confirm the txid; a tx this large is consensus-invalid",
            ) from exc
        if "does not match the requested txid" in msg:
            cause = msg.split("(", 1)[1].rstrip(")") if "(" in msg else msg
            raise UserError(
                "server returned a transaction whose hash does not match the requested txid",
                cause=cause,
                fix="try a different ElectrumX server (--electrumx URL)",
            ) from exc
        if msg == "could not parse the raw transaction bytes":
            raise UserError(
                "could not parse the raw transaction bytes",
                cause="Transaction.from_hex returned None",
                fix="the server response is malformed; try another ElectrumX server",
            ) from exc
        if "exceeds inspect's safety caps" in msg:
            from ..glyph._inspect_core import _MAX_INPUT_COUNT, _MAX_OUTPUT_COUNT

            cause = msg.split("(", 1)[1].rstrip(")") if "(" in msg else msg
            raise UserError(
                "transaction structure exceeds inspect's safety caps",
                cause=cause,
                fix=f"caps are {_MAX_INPUT_COUNT}/{_MAX_OUTPUT_COUNT} — re-run on a saner tx",
            ) from exc
        if "out of range" in msg:
            head = msg.split("(", 1)[0].strip()
            cause = msg.split("(", 1)[1].rstrip(")") if "(" in msg else ""
            raise UserError(head, cause=cause) from exc
        if msg.startswith("invalid txid") or "Txid" in msg or "must be 64-char" in msg:
            raise UserError("invalid txid", cause=msg) from exc
        # Fallthrough: surface unexpected ValidationError as a bare
        # UserError so the CLI stays deterministic.
        raise UserError(msg) from exc


async def _inspect_txid_inner(
    client: ElectrumXClient, txid_hex: str, *, only_vout: int | None = None, network: str = "mainnet"
) -> dict:
    """Fetch *txid_hex* via *client* and classify every output.

    Thin async wrapper around :func:`_classify_raw_tx`. The split is so
    the browser-hosted inspect tool can fetch raw bytes via its own
    WebSocket and feed them directly into the synchronous classifier
    without setting up an event loop or an ``ElectrumXClient`` under
    Pyodide.

    :param only_vout: if not None, restrict the outputs list to a single
        vout — used by the ``--resolve`` outpoint flow.
    """
    # Validate the txid locally before any network call so a malformed
    # input never reaches the server.
    try:
        txid = Txid(txid_hex.lower())
    except ValidationError as exc:
        raise UserError("invalid txid", cause=str(exc)) from exc

    raw = await client.get_transaction(txid)
    payload = _classify_raw_tx(str(txid), bytes(raw), only_vout=only_vout, network=network)

    # DELEGATED CLAIMS. A token may authorise its `in`/`by` through a delegate
    # rather than by spending the parent here, and `_classify_raw_tx` cannot see
    # that: resolving it means fetching the base transaction the burn points at.
    # Skipping the fetch would render an honest token as "CLAIMED ONLY —
    # nothing authorised it", which is a false accusation, not a safe default.
    burns = ((payload.get("metadata") or {}) if isinstance(payload, dict) else {}).get("delegate_burns") or []
    # BOUNDED. Each entry costs a `blockchain.transaction.get` round trip, and
    # the burn output that produces one is 42 bytes — a single transaction
    # within the 4 MB / 100,000-output classifier caps can name ~78,000 distinct
    # bases, so an unbounded loop lets one crafted txid hang the CLI and get the
    # user's ElectrumX endpoint rate-limited. Resolve a prefix and say what was
    # left; an unresolved claim already renders honestly as UNRESOLVED.
    unresolved_over_cap = max(0, len(burns) - _MAX_DELEGATE_BASES)
    resolved: dict[bytes, tuple[bytes, ...]] = {}
    for outpoint in burns[:_MAX_DELEGATE_BASES]:
        base_txid, _, vout_str = str(outpoint).rpartition(":")
        try:
            base_ref = GlyphRef(txid=Txid(base_txid.lower()), vout=int(vout_str))
            base_raw = await client.get_transaction(Txid(base_txid.lower()))
            # INSIDE the try. This was `Transaction.from_bytes`, which does not
            # exist, and it sat outside — so every transaction carrying a
            # delegate burn raised AttributeError out of a block whose stated
            # contract is that a failed resolution never fails the inspect.
            # Anyone could crash `inspect --fetch` by emitting one.
            base_tx = Transaction.from_hex(bytes(base_raw))
            if base_tx is None:
                raise ValidationError(f"base tx {base_txid} did not decode")
            base_outputs = [bytes(o.locking_script.serialize()) for o in base_tx.outputs]
        except (ValidationError, ValueError):
            continue
        except Exception as exc:
            # An unreachable or unknown base leaves the claim UNRESOLVED rather
            # than failing the whole inspect — the rest of the report is still
            # true, and the renderer says the resolution did not happen.
            # Logged, not swallowed: a claim that reads UNRESOLVED because a
            # fetch failed looks identical to one whose base does not exist,
            # and whoever is debugging that needs to know which it was.
            _log.debug("could not resolve delegate base %s: %s", outpoint, exc)
            continue
        # Keyed by base, NOT flattened. Flattening threw away which base each ref
        # came from, which is exactly the binding the verifier needs: without it a
        # reveal that burned any base at all vouched for refs resolved from another.
        resolved[base_ref.to_bytes()] = resolve_delegated_refs(base_ref.to_bytes(), base_outputs)

    # PAYLOAD BINDING. The metadata above is whatever envelope the first decodable
    # input carried. What actually commits to a payload is the `payload_hash` in the
    # commit output that input SPENT — and the classifier is network-free, so without
    # this fetch `payload_binding` can only ever read "unchecked". That silent state
    # is the thing the report exists to eliminate, so resolve it here, where a network
    # connection is already in hand.
    #
    # EXACTLY ONE round trip, bounded by construction rather than by a cap: there is
    # one attributed input and it has one prevout. No loop, so nothing to bound.
    spent_scripts: dict[int, bytes] = {}
    meta = ((payload.get("metadata") or {}) if isinstance(payload, dict) else {}) or {}
    outpoint = meta.get("input_outpoint")
    if outpoint:
        prev_txid, _, prev_vout = str(outpoint).rpartition(":")
        try:
            prev_raw = await client.get_transaction(Txid(prev_txid.lower()))
            prev_tx = Transaction.from_hex(bytes(prev_raw))
            if prev_tx is None:
                raise ValidationError(f"prevout tx {prev_txid} did not decode")
            spent_scripts[int(meta["input_index"])] = bytes(prev_tx.outputs[int(prev_vout)].locking_script.serialize())
        except (ValidationError, ValueError, IndexError, KeyError):
            pass
        except Exception as exc:
            # Same contract as the delegate block above: a failed resolution leaves
            # the verdict "unchecked" — with its own stated reason — rather than
            # failing the whole inspect. Logged, not swallowed: "unchecked because
            # the server was unreachable" and "unchecked because nobody asked" render
            # identically, and whoever is debugging that needs to know which it was.
            _log.debug("could not resolve the attributed input's prevout %s: %s", outpoint, exc)

    if resolved or spent_scripts:
        payload = _classify_raw_tx(
            str(txid),
            bytes(raw),
            only_vout=only_vout,
            network=network,
            delegated_refs=resolved or None,
            spent_scripts=spent_scripts or None,
        )
    if unresolved_over_cap and isinstance(payload, dict) and payload.get("metadata"):
        payload["metadata"]["delegate_bases_unresolved"] = unresolved_over_cap
    return payload


def _render_txid_human(payload: dict) -> str:
    """Format a fetched-tx inspect result for human mode."""
    lines = [
        f"Transaction: {payload['txid']}",
        f"  size:    {payload['byte_length']} bytes",
        f"  inputs:  {payload['input_count']}",
        f"  outputs: {payload['output_count']}",
        "",
    ]
    rows = payload.get("outputs") or []
    if not rows:
        lines.append("  (no outputs)")
    else:
        lines.append("Outputs:")
        for row in rows:
            sats = row.get("satoshis", "?")
            type_ = row.get("type", "?")
            head = f"  vout {row['vout']:>3}  type={type_:<10}  sats={sats}"
            lines.append(head)
            # An OP_RETURN payload's verdict must reach the terminal HERE too, not
            # only in the pasted-script view. This is the path that reaches a record
            # actually on chain, and without it a v2 whose signature DOES NOT VERIFY
            # rendered identically to a genuine one.
            lines.extend(_op_return_payload_lines(row, indent="            "))
            if type_ in ("nft", "ft"):
                lines.append(f"            ref={row.get('ref_outpoint', '')}")
                lines.append(f"            owner_pkh={row.get('owner_pkh', '')}")
            elif type_ == "mut":
                lines.append(f"            ref={row.get('ref_outpoint', '')}")
                lines.append(f"            payload_hash={row.get('payload_hash', '')}")
            elif type_ in ("commit-nft", "commit-ft"):
                lines.append(f"            payload_hash={row.get('payload_hash', '')}")
                lines.append(f"            owner_pkh={row.get('owner_pkh', '')}")
            elif type_ == "dmint":
                lines.append(f"            contract_ref={row.get('contract_ref_outpoint', '')}")
                lines.append(f"            token_ref={row.get('token_ref_outpoint', '')}")
                lines.append(
                    f"            height={row.get('height')}/{row.get('max_height')} "
                    f"reward={row.get('reward')} algo={row.get('algo')}"
                )
            elif type_ == "container-legacy":
                lines.append(f"            ref={row.get('ref_outpoint', '')}")
                lines.append(f"            child_ref={row.get('child_ref_outpoint', '')}")
                lines.append("            UNSPENDABLE — see `pyrxd glyph inspect <script>` for why")
            elif type_ == "p2pkh":
                lines.append(f"            owner_pkh={row.get('owner_pkh', '')}")
            elif type_ == "p2sh":
                lines.append(f"            script_hash={row.get('script_hash', '')}")
            elif type_ in ("p2pkh-cltv", "p2pkh-csv"):
                lines.append(f"            owner_pkh={row.get('owner_pkh', '')}")
                lines.append(
                    f"            lock={row.get('locktime_units')} {row.get('locktime_basis')}"
                    + ("  *** DISABLED ***" if row.get("relative_lock_disabled") else "")
                )
            elif type_ == "soulbound-covenant":
                lines.append(f"            bound_ref={row.get('bound_ref_outpoint', '')}")
                lines.append(f"            owner_pkh={row.get('owner_pkh', '')}")
                lines.append(f"            variant={row.get('variant', '')} (non-transferable at consensus)")
                # The classifier attaches a `note` saying what this verdict does NOT
                # establish, and this row used to drop it while the standalone script
                # card printed it in full. This is the path most people meet the tool
                # on, and "non-transferable at consensus" is exactly the sentence a
                # credential or swap gate would over-trust. The sibling
                # container-legacy branch already points the reader onward; soulbound
                # did not.
                lines.append("            does NOT verify the singleton is held here — see")
                lines.append("            `pyrxd glyph inspect <script>` for the full qualifier")
            elif type_ == "self-replicating-covenant":
                lines.append(f"            bound_ref={row.get('bound_ref_outpoint', '(multiple)')}")
                lines.append("            markers only — NOT proof of soulbound")
            elif type_ == "unknown":
                # Carried (0xd0/0xd8) vs merely named (0xd1/0xd2/0xd3). Only the
                # first burns when this output is spent as plain funding.
                for ref_row in row.get("input_refs") or []:
                    lines.append(f"            ref={ref_row['ref_outpoint']} ({ref_row['opcode']}) TOKEN-BEARING")
                for ref_row in row.get("referenced_refs") or []:
                    lines.append(
                        f"            ref={ref_row['ref_outpoint']} ({ref_row['opcode']}) referenced, not carried"
                    )
                if row.get("token_bearing") is None:
                    lines.append("            token-bearing UNKNOWN (does not decode) — treat as token-bearing")
            elif type_ == "authority-gated-nft":
                lines.append(f"            ref={row.get('ref_outpoint', '')}")
                lines.append(f"            authority_ref={row.get('authority_ref', '')}")
                lines.append(f"            owner_pkh={row.get('owner_pkh', '')}")
            elif type_ in ("delegate-token", "delegate-burn"):
                lines.append(f"            ref={row.get('ref_outpoint', '')}")
                lines.append(f"            delegate_base_ref={row.get('delegate_base_ref', '')}")
                if row.get("owner_pkh"):
                    lines.append(f"            owner_pkh={row['owner_pkh']}")
                if row.get("spendable") is False:
                    lines.append("            *** UNSPENDABLE *** (OP_RETURN — the value on it is gone)")
            elif type_ == "error":
                lines.append(f"            (classifier error: {row.get('error')})")

            # THE CAVEAT, FOR EVERY TYPE THAT HAS ONE — printed generically rather than per
            # branch. The classifier attaches `note` to say what a row does NOT establish
            # ("gated on this authority NOW — the holder can transfer to a plain NFT script and
            # drop the gate"; "anyone can write one about any token"). Five new row types had no
            # branch here at all, so on the CLI the affirmative type label survived and every one
            # of those sentences was dropped, while the browser rendered them in full. That is
            # exactly the failure `_op_return_payload_lines` was written to fix one level down.
            #
            # Generic because the alternative is hand-keeping a list of which types have notes,
            # and the next type added would repeat this.
            # Same reasoning as `note` below: generic, not per-branch. `delegate_base_ref`
            # was emitted only from the `delegate-token`/`delegate-burn` branch, so a
            # delegate-BOUND commit — whose reveal the covenant rejects without a burn
            # output naming that base — rendered identically to a plain one. The classifier
            # recovers it for all three commit types; hand-keeping which branches print it
            # is what lost it.
            delegate_base = row.get("delegate_base_ref")
            if delegate_base and type_ not in ("delegate-token", "delegate-burn"):
                lines.append(f"            delegate_base_ref={delegate_base}")

            note = row.get("note")
            if note:
                lines.append(f"            {_truncate_for_human(str(note))}")
    metadata = payload.get("metadata")
    if metadata is not None:
        lines.append("")
        # SAY WHEN IT IS ONE OF SEVERAL (#577). A multi-glyph reveal carries a
        # payload per minted glyph; printing one under a bare "Reveal metadata"
        # heading told the reader it described the transaction. One observed
        # mainnet reveal mints 35 refs from 36 inputs.
        n_payloads = metadata.get("of_n_payloads")
        if n_payloads:
            lines.append(
                f"Reveal metadata (from input {metadata['input_index']} — "
                f"1 of {n_payloads} glyphs minted here; see metadata_inputs for the rest):"
            )
        else:
            lines.append(f"Reveal metadata (from input {metadata['input_index']}):")
        _pb = metadata.get("payload_binding")
        if _pb:
            # Same reasoning as the browser: every state, including "unchecked".
            _mark = "  *** " if _pb.get("state") == "mismatch" else "  "
            lines.append(f"{_mark}payload_binding={_pb.get('state')} — {_pb.get('reason')}")
            # Named whatever the verdict. On `unchecked` it is what someone would
            # fetch to settle it; on `mismatch` it is where the real payload is.
            if metadata.get("input_outpoint"):
                lines.append(f"    spent outpoint: {metadata['input_outpoint']}")
        lines.append(f"  protocol: {metadata['protocol']}")
        # BEFORE the fields themselves. A look-alike warning printed after the name
        # it applies to is a warning the reader has already acted on — and the whole
        # point is that the rendered name looks correct.
        for field, reason in (metadata.get("display_warnings") or {}).items():
            lines.append(f"  *** WARNING: {field} contains {reason} ***")
        if metadata.get("name"):
            lines.append(f"  name:     {_truncate_for_human(metadata['name'])}")
        if metadata.get("ticker"):
            lines.append(f"  ticker:   {_truncate_for_human(metadata['ticker'])}")
        if metadata.get("description"):
            lines.append(f"  desc:     {_truncate_for_human(metadata['description'])}")
        if metadata.get("decimals"):
            lines.append(f"  decimals: {metadata['decimals']}")
        # The claim AND the verdict, never the claim alone (#591). Rendering
        # "in collection X" without saying whether anything authorised it is the
        # defect this exists to fix — the same shape as showing a WAVE name for
        # an unverified HashMark signer.
        # Four verdicts, not two. "spent in this tx" is FALSE for a delegated
        # claim — the parent was spent when the delegate BASE was created, by
        # someone who need not be this minter — and "nothing authorised it" is
        # false when a delegate was burned and simply could not be resolved.
        # Both wrong strings are the confident kind, which is the kind people
        # act on.
        burned = metadata.get("delegate_burns") or []
        for rel in metadata.get("relationships") or []:
            label = "collection" if rel["kind"] == "container" else "creator"
            basis = rel.get("basis")
            if rel["ok"] and basis == "delegated":
                via = f" via delegate {burned[0]}" if len(burned) == 1 else " via delegate"
                lines.append(f"  {label}: {rel['ref']}  [VERIFIED{via} — authorised by its base, not spent here]")
            elif rel["ok"]:
                lines.append(f"  {label}: {rel['ref']}  [VERIFIED — spent in this tx]")
            elif burned:
                # Name a specific delegate ONLY when there is exactly one. With
                # two burns, `burned[0]` pointed at a delegate that may have
                # nothing to do with this particular claim.
                which = f" {burned[0]}" if len(burned) == 1 else ""
                lines.append(
                    f"  {label}: {rel['ref']}  [UNRESOLVED — this tx burned a delegate{which}; fetch it to check]"
                )
            else:
                lines.append(f"  {label}: {rel['ref']}  [CLAIMED ONLY — nothing authorised it]")

        if metadata.get("main"):
            lines.append(f"  main:     {metadata['main']}")
        tl = metadata.get("timelock")
        if tl:
            lines.append(f"  timelock: opens at {tl['unlock_at']} ({tl['mode']})")
            if tl.get("hint"):
                lines.append(f"            hint: {_truncate_for_human(tl['hint'])}")
            lines.append(f"            cek commitment: {tl['cek_hash']}")
            # NO "unlocked/locked" LINE. Deciding that needs the caller's view of the chain — a tip
            # height for mode="block", a timestamp for mode="time" — and this renderer is handed a
            # payload, not a node. `pyrxd.is_unlocked(...)` answers it for a caller who has one.
            # Printing a verdict off this process's wall clock would be a guess dressed as a fact,
            # and for mode="block" it would be meaningless.
            lines.append("            (unlocked? pass this token's metadata and your chain tip to")
            lines.append("             pyrxd.is_unlocked / pyrxd.get_unlock_remaining)")
        # AUTHORITY — the claims, whether it has EXPIRED, and anything `validate_authority` could
        # not read. The classifier computed all of this and neither renderer read it, so an
        # authority token that expired years ago printed identically to a live one, on both the
        # terminal and the browser. The one signal that flags an unparseable expiry — `problems` —
        # was the one nobody could see.
        auth = metadata.get("authority")
        if auth:
            claims = auth.get("claims") or {}
            lines.append("  authority:")
            for key in ("issuer", "scope", "expires"):
                if claims.get(key):
                    lines.append(f"            {key}: {_truncate_for_human(str(claims[key]))}")
            perms = claims.get("permissions") or []
            if perms:
                shown = ", ".join(_truncate_for_human(str(x)) for x in perms[:_HUMAN_ENTRY_CAP])
                lines.append(f"            permissions: {shown}")
                if len(perms) > _HUMAN_ENTRY_CAP:
                    lines.append(f"            ... and {len(perms) - _HUMAN_ENTRY_CAP} more not shown")
            if claims.get("revocable") is False:
                lines.append("            revocable: false")
            if auth.get("expired"):
                lines.append("            *** EXPIRED *** (by the `expires` claim above)")
            for problem in auth.get("problems") or []:
                lines.append(f"            unreadable: {_truncate_for_human(str(problem))}")
            # WHAT THIS IS NOT. The marker says the token calls itself an authority; it does not
            # establish that anything was minted under it, nor that the issuer still honours it.
            lines.append("            (a marker and its claims — NOT proof any item was minted")
            lines.append("             under it; see verify_authority_gate for that question)")
    # THE OTHER GLYPHS IN A MULTI-GLYPH REVEAL (#577). Pointing at a JSON key is
    # no use to someone reading the terminal, which is where this renderer is read.
    others = [
        row
        for row in (payload.get("metadata_inputs") or [])
        if row["input_index"] != (metadata or {}).get("input_index")
    ]
    if others:
        lines.append("")
        lines.append(f"Other glyphs minted in this transaction ({len(others)}):")
        for row in others:
            label = _truncate_for_human(row["name"] or row["ticker"] or "(unnamed)")
            lines.append(f"  input {row['input_index']:>3}: {row['classification']:<12} {label}")

    # GLYPH ENVELOPES THAT ARE NOT FULL PAYLOADS (#661 follow-up). `metadata` above renders
    # only a full token payload, so a mutable-glyph UPDATE transaction rendered NOTHING here —
    # `type=unknown / type=mut / type=p2pkh` and no mention of the change. #661 taught the
    # classifier to read those envelopes and put them in the JSON, and stopped there: nothing
    # consumed `glyph_envelopes`, so the default terminal output stayed exactly as blind as
    # before. A production caller is necessary and not sufficient; the result has to reach a
    # human, and this is the surface humans read.
    envelopes = payload.get("glyph_envelopes") or []
    if envelopes:
        lines.append("")
        lines.append(f"Glyph envelopes carrying no full payload ({len(envelopes)}):")
        for env in envelopes:
            idx = env.get("input_index")
            if env.get("kind") == "update":
                lines.append(f"  input {idx:>3}: UPDATE — a mutable glyph's fields are being changed here")
                fields = env.get("fields") or {}
                attrs = fields.get("attrs")
                if isinstance(attrs, dict):
                    # `target` FIRST and on its own line: for a WAVE name it is where the name
                    # will point, which is the one value a reader is here for.
                    if "target" in attrs:
                        lines.append(f"           attrs.target = {_truncate_for_human(str(attrs['target']))}")
                    # KEYS ARE TRUNCATED TOO. They are as publisher-chosen as the values, and
                    # capping only the value left a 100,000-character key rendering in full - a
                    # 200,004-character line, measured.
                    others = [(k, v) for k, v in sorted(attrs.items()) if k != "target"]
                    rest = ", ".join(
                        f"{_truncate_for_human(str(k))}={_truncate_for_human(str(v))}"
                        for k, v in others[:_HUMAN_ENTRY_CAP]
                    )
                    if rest:
                        lines.append(f"           attrs: {rest}")
                    if len(others) > _HUMAN_ENTRY_CAP:
                        lines.append(f"           ... and {len(others) - _HUMAN_ENTRY_CAP} more attrs not shown")
                top = [(k, v) for k, v in sorted(fields.items()) if k != "attrs"]
                for key, value in top[:_HUMAN_ENTRY_CAP]:
                    lines.append(f"           {_truncate_for_human(str(key))} = {_truncate_for_human(str(value))}")
                if len(top) > _HUMAN_ENTRY_CAP:
                    lines.append(f"           ... and {len(top) - _HUMAN_ENTRY_CAP} more fields not shown")
                # WHAT THIS DOES NOT SAY. The envelope changes a GLYPH's fields. Whether that
                # glyph is the name someone means is an index's answer, not this transaction's,
                # and the gap between the two is the whole of HashMark §7.6.
                lines.append("           (changes this glyph's fields — does NOT establish which")
                lines.append("            name resolves to it, nor who held that name when)")
            elif env.get("kind") == "payload_unrendered":
                # A DISAGREEMENT, not an unreadable envelope. One reader decoded a full payload
                # here and the other did not, so neither "rendered above" nor "could not be read"
                # is true — and silently trusting the reveal reader made the glyph vanish.
                lines.append(f"  input {idx:>3}: PAYLOAD the reveal reader did not return")
                lines.append("           the two glyph readers disagree about these bytes — treat")
                lines.append("           the metadata section above as incomplete for this input")
            else:
                # NOT SILENTLY DROPPED. "I could not read this" and "there is nothing here" are
                # opposite facts, and the blind one reads as reassuring.
                lines.append(f"  input {idx:>3}: UNREADABLE — a 'gly' marker with content neither reader accepted")
                reason = env.get("reason") or ""
                if reason:
                    lines.append(f"           {_truncate_for_human(reason)}")

    # dMint mint-claim scriptSig (vin[0] only). 4 canonical pushes:
    # nonce, SHA256d(funding_script), SHA256d(OP_RETURN_script), OP_0.
    # V1 = 4-byte nonce / 72-byte scriptSig; V2 = 8-byte / 76-byte.
    mint_scriptsig = payload.get("mint_scriptsig")
    if mint_scriptsig is not None:
        lines.append("")
        lines.append("dMint mint scriptSig (vin 0):")
        lines.append(f"  version (by nonce width): {mint_scriptsig.get('version_hint', '?')}")
        lines.append(f"  scriptSig length:         {mint_scriptsig.get('scriptsig_length')} bytes")
        lines.append(f"  nonce (LE):               {mint_scriptsig.get('nonce_hex')}")
        lines.append(f"  input  hash (SHA256d):    {mint_scriptsig.get('input_hash')}")
        lines.append(f"  output hash (SHA256d):    {mint_scriptsig.get('output_hash')}")
        lines.append("  (input  hash = SHA256d of the funding-input locking script;")
        lines.append("   output hash = SHA256d of the OP_RETURN message script at vout[2];")
        lines.append("   these are literal SHA256d pushes, not preimage halves —")
        lines.append("   the covenant recomputes SHA256(input_hash || output_hash))")
    return "\n".join(lines)


def _render_inspect_human(payload: dict) -> str:
    """Format a single inspect result for the human output mode."""
    form = payload.get("form", "?")
    if form == "script":
        return _render_script_human(payload)
    if form == "txid":
        return _render_txid_human(payload)
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


def hashmark_records(payload: Mapping[str, object]) -> list[dict]:
    """Every HashMark record in an inspect payload, in BOTH shapes it comes in.

    A pasted script carries one record at the top level; a fetched transaction carries
    one per output. Three callers needed this and two of them had open-coded the same
    five lines — which is how `--verify-wave <txid> --fetch` once attached nothing at
    all and never said why. ``pyrxd verify`` is the third, so the expression is written
    once here rather than a third time there.
    """
    top = payload.get("hashmark")
    if top:
        return [top]  # type: ignore[list-item]
    return [row["hashmark"] for row in (payload.get("outputs") or []) if row.get("hashmark")]  # type: ignore[union-attr,index]


async def resolve_anchor_from(client: object, label: str, *, mark_txid: str | None, min_confirmations: int):
    """The mark's block, asked of ONE named endpoint — or the empty anchor when there is no block.

    Lifted out of :func:`_name_at_mark` so ``pyrxd verify`` reports the block from the same
    code the §7.6 judge is handed. Two resolutions of "which block is this mark in" is how
    one surface ends up naming a height the other contradicts, and the height is the whole
    load-bearing input of form 2.

    A pasted script has no transaction and therefore no block. That is not an error and not
    silence: it returns an anchor with ``height=None``, which every consumer must render as
    "form 2 is unavailable by construction", with the reason.

    ``label`` is the endpoint's URL, carried into :attr:`MarkAnchor.source` so the caller's
    independence rules — the height must not come from whoever supplied the name binding —
    are checkable rather than assumed.
    """
    from ..glyph.mark_anchor import MarkAnchor, resolve_mark_anchor

    if not mark_txid:
        return MarkAnchor(txid="", height=None, confirmations=0, min_confirmations=min_confirmations, source=label)
    tip_height = await client.get_tip_height()  # type: ignore[attr-defined]
    return await resolve_mark_anchor(
        txid=mark_txid,
        fetch_verbose=client.get_transaction_verbose,  # type: ignore[attr-defined]
        source=label,
        min_confirmations=min_confirmations,
        tip_height=int(tip_height),
    )


# `mark_anchor_dict` moved to `pyrxd.glyph.mark_anchor`, beside the dataclass it
# describes, and is re-exported above so every caller here is unchanged.
#
# WHY IT MOVED: the browser panel needs the same display shape, and it cannot import
# this module — `glyph_inspect` imports click, and the Pyodide page has none. Left
# here, the page would have had to build its own dict of height/confirmations/caveat,
# which is exactly the second display shape this helper was factored out to prevent:
# a number reaching a screen without the caveat saying it is one endpoint's unverified
# claim. One definition, three surfaces (this terminal, `pyrxd verify`, the panel).


def mark_anchor_lines(a: Mapping[str, object] | None, indent: str = "  ") -> list[str]:
    """A block, its depth against the floor the caller set, and what the number is worth.

    Never prints a bare height. ``height_is_verified`` is ``False`` for every anchor this
    codebase can build, so the caveat is unconditional rather than conditional on a flag
    that is always the same — a conditional would read as though the other branch existed.
    """
    if not a:
        return []
    if a.get("height") is None:
        return [
            f"{indent}block:        none — this transaction is not in a block "
            f"(unconfirmed, or the endpoint reports no depth)",
            f"{indent}              a mark in the mempool fixes no time; nothing below is anchored",
        ]
    depth = f"{a['confirmations']} confirmation(s), floor {a['min_confirmations']}"
    verdict = "PROVISIONAL — below the floor you set" if a.get("provisional") else "at or past the floor you set"
    lines = [f"{indent}block:        {a['height']}  ({depth}) — {verdict}"]
    # WRAPPED, NOT TRUNCATED. `_truncate_for_human` caps at 200 characters and this caveat is
    # longer, so it cut mid-word — and the half it dropped is the half that says WHY the number
    # is unverified. Truncation is the right default for publisher-chosen text, where the risk
    # is a hostile 100,000-character field; this string is a constant in `mark_anchor.py`, and
    # a safety qualifier that stops halfway is worse than no qualifier because it still reads
    # as complete. Sanitised anyway, so a future caveat from elsewhere cannot carry control
    # bytes, and bounded by line count rather than by cutting the sentence.
    caveat = _sanitize_display_string(str(a.get("caveat") or ""))
    for chunk in textwrap.wrap(caveat, width=92)[:6]:
        lines.append(f"{indent}              {chunk}")
    lines.append(f"{indent}              (source: {_truncate_for_human(str(a.get('source') or ''))})")
    return lines


def _wave_context_lines(wi: dict | None, indent: str) -> list[str]:
    """Names resolving to the signer's key NOW — as context, never as part of the mark.

    HashMark §7.6 is explicit that a naming system must not be folded into a mark's
    verdict. A name resolves to whatever it points at now; a mark was made at a past
    block. Applying a present-tense lookup to a past event is wrong in BOTH directions
    once a name changes hands:

    * a genuine mark signed by the previous holder starts failing, because the name
      resolves elsewhere — a real record rejected;
    * whoever acquires a lapsed name can make NEW marks that verify as "signed by
      whoever owns company.rxd", which is TRUE and which a reader hears as "the
      company made this". Names on Radiant have terms and expire, so this is ordinary
      rather than exotic.

    This block previously read "the signing key owns these names — file matches the
    digest AND was recorded by that name's holder". That is the unsound form verbatim:
    a past-tense claim manufactured from a present-tense lookup, printed inside the
    attestation block as though the mark carried it.

    So the two facts are separated, per §7.6 form 1: the signer ADDRESS sits with the
    signature, where it belongs, and the name sits below the mark, at the outer indent,
    marked present-tense. The sound form — "recorded by the holder at that time" —
    needs point-in-time resolution against the mark's own block, which is issue-tracked
    rather than approximated here.
    """
    if not wi:
        return []
    if not wi.get("resolved"):
        return [f"{indent}separately — WAVE names: not resolved ({wi.get('reason')})"]
    names = wi.get("names_resolving_now") or []
    if not names:
        return [f"{indent}separately — no WAVE name resolves to that key right now"]
    return [
        f"{indent}separately, and NOT part of the mark above:",
        f"{indent}  WAVE names resolving to that key RIGHT NOW: {', '.join(names)}",
        f"{indent}  (a present-tense lookup. Names change hands, so this does not say who",
        f"{indent}   held the name when the mark was made, nor that the named party made it)",
    ]


def _name_at_mark_lines(nam: dict | None, indent: str = "  ") -> list[str]:
    """§7.6 form 2 rendered — and, far more often, its degrade to form 1 WITH THE REASON.

    Sits where the present-tense name context sits: after the mark's own statement closes,
    at the outer indent, never between the signature and what the signature proves. A form-2
    sentence reads as authoritative, so every qualifier the verdict carries is printed with it;
    the honest sentence is the weaker one, and it ships.
    """
    if not nam:
        return []
    name = nam.get("name", "?")
    if not nam.get("resolved"):
        return [f"{indent}at the mark's block — {name}: not established ({nam.get('reason')})"]
    if nam.get("form") != 2:
        return [
            f"{indent}at the mark's block — {name}: not established ({nam.get('degraded_reason')})",
            f"{indent}  (form 1 only: nothing beyond the present-tense lookup can be said)",
        ]
    chain = nam.get("chain") or {}
    same = nam.get("signer_is_target_at_height")
    lines = [
        f"{indent}at the mark's block ({nam.get('height')}), {name} pointed at {nam.get('target_at_height')}",
        (
            f"{indent}  the signing key IS that address — key custody at that block; not authorship, not location"
            if same
            else f"{indent}  the signing key is NOT that address"
        ),
        f"{indent}  glyph {nam.get('ref')}; {chain.get('steps')} step(s) walked, tip {chain.get('tip')} proved unspent",
    ]
    if nam.get("provisional"):
        lines.append(f"{indent}  PROVISIONAL: the mark is below the confirmation floor you set")
    lines.append(f"{indent}  ({nam.get('caveat')})")
    lines.append(f"{indent}  (name→glyph binding is {nam.get('binding_source')}'s claim, not verified on chain)")
    return lines


def _require_min_confirmations(min_confirmations: int | None) -> None:
    """``--wave-name`` without ``--min-confirmations`` is refused, not defaulted.

    The depth registry (``btc_wallet/chains.py``) states the rule: confirmation depth is
    value-scaled per chain, and a shipped default would be folklore. ``resolve_mark_anchor``
    enforces the same at the library layer; this is the CLI-shaped refusal that names the flag.
    """
    if min_confirmations is None:
        raise UserError(
            "--wave-name needs --min-confirmations",
            cause="confirmation depth is value-scaled per chain and deliberately has no default",
            fix="pass --min-confirmations N, the depth below which the mark's block is treated as provisional",
        )


def _endpoint_pair(ctx: CliContext) -> tuple[object, str, object, str]:
    """Two clients pinned to two DIFFERENT configured endpoints, each labelled by its URL.

    Form 2 needs two independent sources twice over: the walker refuses a tip proof from the
    server that supplied the candidates, and the judge refuses a block height from the server
    that supplied the name→glyph binding. With ONE configured endpoint both clients are that
    endpoint and both labels are equal, so each of those rules degrades with its reason — which
    is the truth of a single-server configuration, and is the shipped default. A second server
    under ``electrumx_servers`` (pyrxd ships two independent mainnet operators in
    ``network/registry.py``) is what makes form 2 reachable.

    Tests patch this to hand in fakes.
    """
    if ctx.client_factory is not None:
        client = ctx.client_factory()
        return client, "factory", client, "factory"
    from ..network.failover import FailoverElectrumXClient
    from ..network.registry import NetworkProfile

    profile = ctx.config.require_profile()
    first = profile.endpoints[0]
    second = profile.endpoints[1] if len(profile.endpoints) > 1 else profile.endpoints[0]

    def _one(endpoint: object) -> FailoverElectrumXClient:
        return FailoverElectrumXClient(
            NetworkProfile(network=profile.network, endpoints=(endpoint,), genesis_hash=profile.genesis_hash)  # type: ignore[arg-type]
        )

    return _one(first), first.url, _one(second), second.url


def _attach_name_at_mark(ctx: CliContext, payload: dict, *, name: str, min_confirmations: int) -> None:
    """Attach a §7.6 form-2 verdict (or its degrade) to every VERIFIED HashMark record.

    Same two shapes as :func:`_attach_wave_identity` — a pasted script carries one record at the
    top level, a fetched transaction one per output — and the same contract: errors are attached
    with a reason, never raised, because a failed name resolution is not a reason to lose the
    classification the user asked for. The mark's txid comes from the fetched transaction; a
    pasted script has none, and form 2 is then unavailable by construction.
    """
    mark_txid = payload.get("txid") if isinstance(payload.get("txid"), str) else None
    for hm in hashmark_records(payload):
        _judge_one_name_at_mark(ctx, hm, mark_txid=mark_txid, name=name, min_confirmations=min_confirmations)


def _judge_one_name_at_mark(
    ctx: CliContext, hm: dict, *, mark_txid: str | None, name: str, min_confirmations: int
) -> None:
    if not hm:
        return
    att = hm.get("attestation") or {}
    shown = _sanitize_display_string(name)
    if att.get("outcome") != "valid":
        hm["name_at_mark"] = {
            "resolved": False,
            "name": shown,
            "reason": (
                "signature did not verify; refusing to place an unproven signer at any block"
                if att.get("outcome") == "invalid_signature"
                else "no verified v2 signature on this record"
            ),
        }
        return
    try:
        hm["name_at_mark"] = asyncio.run(
            _name_at_mark(
                ctx,
                name=name,
                mark_txid=mark_txid,
                min_confirmations=min_confirmations,
                signer_hash160=bytes.fromhex(att["recovered_hash160"]),
            )
        )
    except Exception as exc:
        # The exception text can contain a server-controlled response body.
        hm["name_at_mark"] = {
            "resolved": False,
            "name": shown,
            "reason": _sanitize_display_string(f"lookup failed: {exc}"),
        }


async def _name_at_mark(
    ctx: CliContext, *, name: str, mark_txid: str | None, min_confirmations: int, signer_hash160: bytes
) -> dict:
    """Binding from one endpoint, height from the other; candidates from one, tip proof from
    the other. Then the pure judge. Every source is labelled by URL so the two rules that refuse
    a shared source can see when it IS shared."""
    from contextlib import AsyncExitStack

    from ..base58 import base58check_encode
    from ..constants import NETWORK_ADDRESS_PREFIX_DICT, Network
    from ..glyph.mutable_chain_discovery import walk_discovered_chain
    from ..glyph.wave import WaveNameNotFound, WaveResolver
    from ..glyph.wave_identity import judge_name_at_mark

    san = _sanitize_display_string
    shown = san(name)
    client_a, label_a, client_b, label_b = _endpoint_pair(ctx)

    async with AsyncExitStack() as stack:
        await stack.enter_async_context(client_a)  # type: ignore[arg-type]
        if client_b is not client_a:
            await stack.enter_async_context(client_b)  # type: ignore[arg-type]

        # 1. THE BINDING, name -> reveal txid, from whichever endpoint runs the indexer
        #    extension. Tried second-first so that, when both do, the binding and the anchor
        #    still land on different servers.
        record = None
        binding_label = ""
        failures: list[str] = []
        for client, label in ((client_b, label_b), (client_a, label_a)):
            try:
                record = await WaveResolver(client).resolve(name)  # type: ignore[arg-type]
                binding_label = label
                break
            except WaveNameNotFound:
                return {
                    "resolved": False,
                    "name": shown,
                    "reason": "the indexer has no registration for this name (unregistered, or lapsed)",
                }
            except Exception as exc:
                failures.append(f"{label}: {exc}")
            if client_b is client_a:
                break
        if record is None:
            return {
                "resolved": False,
                "name": shown,
                "reason": san("no configured endpoint answered wave.resolve — " + "; ".join(failures)),
            }
        mint = record.reveal_txid
        if not mint:
            return {
                "resolved": False,
                "name": shown,
                "reason": san(
                    f"the indexer's record carries no usable ref ({record.ref!r}); cannot locate the registration"
                ),
            }

        # 2. THE ANCHOR, from the endpoint that did NOT supply the binding. The label is the
        #    URL, the same string the binding is labelled with, so `judge_name_at_mark` can see
        #    when they are one server.
        anchor_client, anchor_label = (client_a, label_a) if binding_label == label_b else (client_b, label_b)
        anchor = await resolve_anchor_from(
            anchor_client, anchor_label, mark_txid=mark_txid, min_confirmations=min_confirmations
        )

        # 3. THE CHAIN: discovered on A, tip proved on B.
        found = await walk_discovered_chain(
            mint_txid=mint,
            discovery_client=client_a,
            tip_client=client_b,
            discovery_source=label_a,
            tip_source=label_b,
        )

    walk, discovery = found.walk, found.discovery
    # 4. THE VERDICT — pure. `ref` is the walk's own, so the "walk is of another ref" rule can
    #    never fire here; what the binding asserts is that THIS chain is the name, and that stays
    #    `binding_verified=False` because nothing checked it on chain.
    verdict = judge_name_at_mark(
        ref=walk.ref or mint,
        binding_source=binding_label,
        anchor=anchor,
        walk=walk,
        step_heights=discovery.heights,
    )
    network = Network(ctx.network) if ctx.network in {n.value for n in Network} else Network.TESTNET
    signer_address = base58check_encode(NETWORK_ADDRESS_PREFIX_DICT[network] + signer_hash160)
    same: bool | None = (verdict.target_at_height == signer_address) if verdict.form == 2 else None
    return {
        "resolved": True,
        "name": san(record.name),
        "ref": san(verdict.ref),
        "reveal_txid": mint,
        "form": verdict.form,
        "point_in_time": verdict.form == 2,
        "height": verdict.height,
        "target_at_height": san(verdict.target_at_height) if verdict.target_at_height else None,
        "target_now": san(record.target),
        "signer_address": signer_address,
        "signer_is_target_at_height": same,
        "provisional": verdict.provisional,
        "expiry": verdict.expiry,
        "degraded_reason": san(verdict.degraded_reason),
        "caveat": verdict.caveat,
        "binding_source": san(verdict.binding_source),
        "binding_via": "indexer",
        "binding_verified": verdict.binding_verified,
        "anchor_source": san(anchor_label),
        # THE ANCHOR ITSELF, not only its height and source. `pyrxd verify` has to report a
        # block too, and the one rule that matters is that the block must NOT come from
        # whoever supplied the name binding. That rule is enforced four lines above, once.
        # Handing the resulting anchor out means the second surface inherits it instead of
        # re-deriving it from a server it picked on its own — where a hostile endpoint that
        # had already supplied the binding could move the block as well.
        "anchor": mark_anchor_dict(anchor),
        "chain": {
            "steps": len(walk.steps),
            "complete": walk.complete,
            "tip": f"{walk.tip_txid}:{walk.tip_vout}",
            "reason": san(walk.reason),
            "discovery_source": san(label_a),
            "tip_source": san(label_b),
            "hops": discovery.hops,
            "fetches": discovery.fetches,
            "capped": discovery.capped,
        },
    }


def _op_return_payload_lines(payload: dict, indent: str = "  ") -> list[str]:
    """The `msg` and HashMark rendering, for EVERY human surface that shows one.

    Factored out because there are two such surfaces and there was one renderer. The
    pasted-script view printed the digest, the signer and the attestation verdict; the
    txid view — the DEFAULT path, and the only one that reaches a record actually on
    chain — printed the type label alone. So a v2 whose signature DOES NOT VERIFY and
    a genuine one rendered byte-identically, with the affirmative-sounding
    `op_return-hashmark-v2` label surviving and the verdict discarded.

    A computed verdict that no human sees is not a feature. Two copies of a renderer
    is how one of them ends up missing the line that matters, so there is one.
    """
    out: list[str] = []
    msg = payload.get("message")
    if msg:
        if msg["outcome"] == "ok":
            if msg["is_utf8"]:
                out.append(f"{indent}message ({msg['byte_length']} bytes): {_truncate_for_human(msg['text'])}")
            else:
                # Say WHY there is no text rather than printing nothing, or a caller
                # assumes the field is empty when the bytes simply are not text.
                out.append(f"{indent}message: {msg['byte_length']} bytes, not valid UTF-8 (see data_hex)")
        else:
            out.append(f"{indent}message: {msg['outcome']}" + (f" — {msg['detail']}" if msg.get("detail") else ""))

    hm = payload.get("hashmark")
    if hm:
        # HashMark is a third-party OP_RETURN format (MIT, github.com/cdonnachie/hashmark.rxd).
        # Classifying it in JSON and not printing it here would leave the feature
        # invisible to the person actually reading a terminal.
        if hm["outcome"] == "ok":
            out.append(f"{indent}HashMark v{hm['version']} ({hm['algorithm']})")
            out.append(f"{indent}  digest:  {hm['digest']}")
            if hm.get("label"):
                out.append(f"{indent}  label:   {_truncate_for_human(hm['label'])}")
            elif hm.get("label_withheld"):
                # v1 keeps its timestamp evidence; the label is withheld WITH a reason,
                # because silently showing nothing looks like a record that had no label.
                out.append(f"{indent}  label:   [withheld — {hm['label_withheld']}]")
            att = hm.get("attestation") or {}
            outcome = att.get("outcome")
            if hm.get("signer_hash160"):
                out.append(f"{indent}  signer:  {hm['signer_hash160']}")
                # THE WORDS COME FROM `_attestation_verdict`, not from here. Both this
                # terminal and the browser panel used to spell the verdict themselves,
                # which is exactly how the page ended up with no branch at all for
                # `unverifiable`: this file grew one, `inspect.js` did not, and nothing
                # could notice because the two copies were unrelated strings in
                # unrelated languages. One table, three surfaces.
                status, meaning = _attestation_verdict(outcome or "")
                if outcome == "valid":
                    out.append(f"{indent}  signature {status} — {meaning}")
                    if att.get("signer_address"):
                        out.append(f"{indent}    signer address: {att['signer_address']}")
                    out.append(f"{indent}    (assuming {att.get('assumed_network')}; the chain is part of")
                    out.append(f"{indent}     the signed statement and a pasted script carries no context)")
                else:
                    # Withheld or refused — either way SAY SO. Falling through silently
                    # would leave a v2 record showing a signer and no word about its
                    # signature, which reads as "fine" far more than as "unchecked".
                    # `else` rather than a list of known outcomes, so an outcome added
                    # upstream is still announced; `_attestation_verdict` fails toward
                    # "we do not know" rather than toward either verdict.
                    out.append(f"{indent}  signature {status} — {att.get('detail') or meaning}")
                    out.append(f"{indent}    ({meaning})")
            elif outcome == "not_attested":
                # v1. There IS no signature, and the absence is the finding: a v1 mark
                # fixes a time and names nobody. Printing nothing here left the reader
                # to infer that from a missing line.
                status, meaning = _attestation_verdict(outcome)
                out.append(f"{indent}  signature {status} — {meaning}")
            out.append(f"{indent}  (proves someone knew this digest no later than the confirming")
            out.append(f"{indent}   block — not authorship, ownership, originality or contents)")
            # AFTER the mark's own statement closes, and at the outer indent. §7.6
            # allows a name only as present-tense context, "never beside the mark as
            # though it were part of it", so it does not sit inside the block or
            # between the signature and what that signature proves.
            out.extend(_wave_context_lines(hm.get("wave_identity"), indent))
            out.extend(_name_at_mark_lines(hm.get("name_at_mark"), indent))
        else:
            out.append(f"{indent}HashMark: {hm['outcome']}" + (f" — {hm['detail']}" if hm.get("detail") else ""))

    # BURN — the claims AND the note. The browser prints both (`inspect.js`); the CLI printed
    # neither, so a burn proof rendered as the bare label `type: op_return-burn` and the sentence
    # that stops a reader believing it ("anyone can write one about any token") reached nobody.
    # Every value is CLAIMED: the proof is an OP_RETURN, so it is whatever its author typed.
    burn = payload.get("burn")
    if burn:
        claims = burn.get("claims") or {}
        out.append(f"{indent}burn proof (CLAIMED — an OP_RETURN, not a verdict):")
        for key in ("token_ref", "action", "amount", "reason"):
            value = claims.get(key)
            if value not in (None, ""):
                out.append(f"{indent}  {key}: {_truncate_for_human(str(value))}")
            elif key == "amount" and burn.get("amount_withheld"):
                # Said, not skipped: a missing line reads as "no amount was claimed".
                out.append(f"{indent}  amount: [withheld — {_truncate_for_human(burn['amount_withheld'])}]")
        if burn.get("note"):
            out.append(f"{indent}  {_truncate_for_human(str(burn['note']))}")

    return out


def _render_script_human(payload: dict) -> str:
    """Pretty-print a classified script result."""
    type_ = payload.get("type", "?")
    head = f"type: {type_}    length: {payload['length']} bytes"
    body: list[str] = []
    body.extend(_op_return_payload_lines(payload))

    if type_ == "p2pkh":
        body.append(f"  owner_pkh: {payload['owner_pkh']}")
    elif type_ in ("nft", "ft"):
        body.append(f"  ref:       {payload['ref_outpoint']}")
        body.append(f"  owner_pkh: {payload['owner_pkh']}")
        body.append("  (structural pattern match: bytes match the FT/NFT script template;")
        body.append("   does NOT verify the ref points to a valid Glyph contract)")
    elif type_ == "mut":
        body.append(f"  ref:          {payload['ref_outpoint']}")
        body.append(f"  payload_hash: {payload['payload_hash']}")
        body.append("  (structural pattern match; payload_hash is an opaque commitment")
        body.append("   to off-chain CBOR — resolve via the reveal tx; `inspect` cannot")
        body.append("   verify provenance of the ref locally)")
    elif type_ in ("commit-nft", "commit-ft"):
        body.append(f"  payload_hash: {payload['payload_hash']}")
        body.append(f"  owner_pkh:    {payload['owner_pkh']}")
        body.append("  (structural pattern match; payload_hash is an opaque commitment")
        body.append("   to the reveal-tx CBOR)")
    elif type_ == "container-legacy":
        body.append(f"  ref:          {payload['ref_outpoint']}")
        body.append(f"  child_ref:    {payload['child_ref_outpoint']}")
        body.append(f"  owner_pkh:    {payload['owner_pkh']}")
        body.append("  *** UNSPENDABLE ***")
        body.append("  A pre-0.15.0 CONTAINER-with-child-ref output. OP_PUSHINPUTREF leaves")
        body.append("  the child ref on the stack, so the P2PKH tail hashes the ref instead of")
        body.append("  the pubkey and OP_EQUALVERIFY fails for every possible scriptSig. The")
        body.append("  photons on this output cannot be recovered, and the child NFT whose ref")
        body.append("  it names was consumed to create it and cannot be re-minted.")
        body.append("  Collection membership now lives in the envelope's 'in' field.")
    elif type_ == "dmint":
        version = payload.get("version", "?")
        body.append(f"  version:      dMint {version}")
        body.append(f"  contract_ref: {payload['contract_ref_outpoint']}")
        body.append(f"  token_ref:    {payload['token_ref_outpoint']}")
        body.append(f"  height:       {payload['height']} / {payload['max_height']}")
        body.append(f"  reward:       {payload['reward']} photons/mint")
        # THIS CONTRACT's cap, which is not the token's supply. The label said
        # "total supply" flat, with the "if all mints succeed" hedge living only in
        # this comment where no reader sees it — and a real dMint token commonly
        # deploys N parallel contracts sharing ONE token_ref, so its supply is the
        # sum across them. The browser tool computes `reward x max_height x N` for
        # the same token, so the two surfaces of one tool answered "what is this
        # token's supply" with figures differing by the parallel-contract count.
        #
        # Naming the quantity is the fix: this output can only ever see the one
        # contract script it was handed.
        max_height, reward = payload["max_height"], payload["reward"]
        # Either may arrive as "<oversized integer: N bits>": the payload is bounded
        # (`_render_safe`), and a contract script's state pushes are whatever its deployer
        # wrote. Multiplying a string raised TypeError; formatting it with `,` raised
        # ValueError — the crash the bound exists to prevent, moved one line down.
        if isinstance(max_height, int) and isinstance(reward, int):
            cap = max_height * reward
            body.append(f"  this contract's cap: {cap:,} photons ({max_height:,} mints x {reward:,})")
        else:
            body.append("  this contract's cap: not computed — max_height or reward is too large to render")
        body.append("  (the cap IF every mint succeeds, and for THIS contract only —")
        body.append("   a token may deploy several contracts against one token_ref,")
        body.append("   and its supply is the sum across them)")
        body.append(f"  algo:         {payload['algo']}")
        body.append(f"  daa_mode:     {payload['daa_mode']}")
        body.append("  (structural pattern match; does NOT verify the contract_ref points")
        body.append("   to a valid mint chain or that the parameters match a deployed token)")
    elif type_ == "p2sh":
        body.append(f"  script_hash: {payload['script_hash']}")
        body.append("  (pay-to-script-hash. The redeem script is not on-chain until this")
        body.append("   output is spent, so nothing further can be said about it here.)")
    elif type_ in ("p2pkh-cltv", "p2pkh-csv"):
        body.extend(_render_timelock_body(payload, type_))
    elif type_ == "soulbound-covenant":
        body.append(f"  variant:      {payload.get('variant', '?')}")
        body.append(f"  bound_ref:    {payload['bound_ref_outpoint']}")
        body.append(f"  owner_pkh:    {payload['owner_pkh']}")
        body.append(f"  self-replication branch: {payload['has_self_replication']}")
        body.append(f"  burn branch:             {payload['has_burn_branch']}")
        body.append("  NON-TRANSFERABLE AT CONSENSUS — the only spends this lock permits are")
        # The two variants pin DIFFERENT things, and this said "byte-identical" for
        # both. The fixed-index builder compares whole scripts
        # (OP_OUTPUTBYTECODE / OP_UTXOBYTECODE); the composable one compares
        # CODE-SCRIPT HASHES, and its own docstring says "code-identical clone".
        #
        # Those coincide only because neither builder emits OP_STATESEPARATOR, so the
        # code script IS the whole script. That is not a detail to paper over: code-
        # script equality plus a state prefix lets the OWNER change between hops, and
        # `classify_soulbound` returns MUTABLE_STATE_COVENANT for exactly that shape.
        # Naming the weaker constraint accurately is what makes the distinction
        # visible to whoever reads this next.
        if payload.get("variant") == "composable":
            body.append("  a CODE-identical self-clone or a burn. There is no transfer path.")
            body.append("  (this variant pins its code-script hash, not the whole script; the two")
            body.append("   coincide here because the builder emits no OP_STATESEPARATOR, so there")
            body.append("   is no mutable state for a clone to change)")
        else:
            body.append("  a byte-identical self-clone or a burn. There is no transfer path.")
        body.append("  (exact match against pyrxd's soulbound covenant builder. It does NOT")
        body.append("   verify the bound ref names a live Glyph singleton, that the singleton")
        body.append("   is actually held here, or that the covenant is defect-free — the")
        body.append("   covenant is a pre-external-audit prototype.)")
    elif type_ == "self-replicating-covenant":
        body.append(f"  bound_ref:    {payload.get('bound_ref_outpoint', '(more than one ref)')}")
        body.append(f"  self-replication branch: {payload['has_self_replication']}")
        body.append(f"  burn branch:             {payload['has_burn_branch']}")
        body.append("  (structural marker match ONLY: this script binds a singleton ref and")
        body.append("   contains a self-replication-or-burn constraint, but its bytes are not")
        body.append("   a covenant pyrxd builds. That is NOT proof it is soulbound — container")
        body.append("   and vault covenants replicate themselves too. Read the script before")
        body.append("   trusting it as a credential.)")
        body.extend(_render_ref_summary_body(payload))
    elif type_ == "unknown":
        body.append("  (script does not match any known Glyph or P2PKH layout)")
        body.extend(_render_ref_summary_body(payload))
    return "\n".join([head, *body])


def _render_timelock_body(payload: dict, type_: str) -> list[str]:
    """The CLTV / CSV time-lock detail lines.

    These outputs are HTLC refund legs in practice, so the reader is usually
    asking "when can I spend this?". Say what the encoded value means in the
    unit it is actually denominated in, and never imply the lock has elapsed —
    that needs a chain tip (CLTV) or the funding output's confirmation height
    (CSV), neither of which a locking script carries.
    """
    body = [f"  owner_pkh:    {payload['owner_pkh']}"]
    basis = payload["locktime_basis"]
    units = payload["locktime_units"]
    if type_ == "p2pkh-cltv":
        # Two different numbers, one block apart, and printing only the first
        # answers a question nobody asked. OP_CLTV constrains the SPENDING TX's
        # nLockTime (>= the encoded value); IsFinalTx then requires that
        # nLockTime be STRICTLY LESS than the containing block's height/time.
        # So the encoded value is a floor on a tx field, and the earliest block
        # that can carry the spend is one past it. ``locktime_earliest`` is
        # derived in _inspect_core so every surface prints the same number.
        earliest = payload.get("locktime_earliest")
        body.append("  lock:         ABSOLUTE (OP_CHECKLOCKTIMEVERIFY)")
        if basis == "height":
            body.append(f"  requires:     spending tx nLockTime >= {units:,} (block height)")
            if earliest is not None:
                body.append(f"  earliest spend: a block at height {earliest:,} or later")
        else:
            body.append(f"  requires:     spending tx nLockTime >= {units} (Unix time; >= {LOCKTIME_THRESHOLD:,})")
            if earliest is not None:
                body.append(f"  earliest spend: the first block whose time-lock clock passes {earliest}")
        body.append("  The encoded value is a floor on the transaction's nLockTime, NOT a")
        body.append("  height at which this output turns spendable: consensus (IsFinalTx)")
        body.append("  requires nLockTime to be STRICTLY LESS than the height/time of the")
        body.append("  block containing the spend, so the encoded value itself is one block")
        body.append("  too early. The spending input's nSequence must also be non-final.")
    else:
        body.append("  lock:         RELATIVE (OP_CHECKSEQUENCEVERIFY, BIP-68/112)")
        body.append(f"  raw sequence: {payload['locktime_value']} (0x{payload['locktime_value']:x})")
        disabled = bool(payload.get("relative_lock_disabled"))
        # State the disable bit BEFORE the decoded delay. Printing "delay: 144
        # blocks" first and the "…but it is ignored" line after is how a reader
        # skimming the top of the block walks away with the opposite of the
        # truth.
        if disabled:
            body.append("  *** RELATIVE LOCK DISABLED — SPENDABLE IMMEDIATELY ***")
            body.append("  Bit 31 (SEQUENCE_LOCKTIME_DISABLE_FLAG) is set, so consensus ignores")
            body.append("  the relative lock entirely. The delay below is encoded in the script")
            body.append("  but enforces nothing. pyrxd's builder refuses to emit this shape.")
        prefix = "  delay (ignored):" if disabled else "  delay:       "
        if basis == "blocks":
            body.append(f"{prefix} {units:,} block(s) after this output confirms")
        else:
            body.append(f"{prefix} {units:,} x 512s = {units * 512:,}s after this output confirms")
        if not disabled:
            body.append("  The spending input's nSequence must carry at least this delay, and")
            body.append("  the spending tx must be version 2 or later.")
    body.append("  (structural pattern match; inspect cannot tell you whether the lock has")
    body.append("   already elapsed — that needs the chain tip / this output's confirmation)")
    return body


def _render_ref_summary_body(payload: dict) -> list[str]:
    """Report the input refs an unnamed script carries, if any.

    The one fact worth surfacing about a script no classifier claims: whether
    it is token-bearing. Spending a ref-carrying UTXO as plain funding burns
    the token it carries.

    ``input_refs`` is the CARRIED set (0xd0 / 0xd8 — Radiant's
    ``foundPushRefs``); ``referenced_refs`` is the set the script merely names
    (0xd1 require / 0xd2, 0xd3 disallow). Only the first burns when spent, so
    only the first gets the warning — see :func:`._ref_summary`.
    """
    token_bearing = payload.get("token_bearing")
    refs = payload.get("input_refs") or []
    named = payload.get("referenced_refs") or []
    # A script that merely gates on a ref is worth reporting, but never under
    # the burn warning — that is the false positive that trains readers to
    # ignore the real one.
    named_body: list[str] = []
    if named:
        named_body.append(f"  references (does NOT carry) {len(named)} ref(s):")
        for row in named:
            named_body.append(f"      {row['opcode']}  {row['ref_outpoint']}")
        named_body.append("  0xd1 OP_REQUIREINPUTREF gates on a ref being live among the spending")
        named_body.append("  tx's inputs; 0xd2/0xd3 forbid one. Neither holds a token here, so")
        named_body.append("  spending this output destroys nothing.")
    if token_bearing is None:
        return [
            "  token-bearing: UNKNOWN — the script does not decode as an opcode stream,",
            "  so the walk could not rule out an input ref. Treat it as token-bearing.",
        ]
    if not refs:
        return ["  token-bearing: no (the opcode-aware walk found no OP_PUSHINPUTREF/SINGLETON)", *named_body]
    body = [f"  token-bearing: YES — carries {len(refs)} input ref(s):"]
    for row in refs:
        body.append(f"      {row['opcode']}  {row['ref_outpoint']}")
    body.append("  Do NOT spend this as plain funding: a ref-carrying UTXO fed in as a fee")
    body.append("  input destroys the token it carries.")
    body.extend(named_body)
    return body


@click.command(name="inspect")
@click.argument("inspect_input", metavar="INPUT")
@click.option(
    "--fetch",
    "fetch",
    is_flag=True,
    default=False,
    help="Fetch the transaction from ElectrumX. Required for txid input.",
)
@click.option(
    "--resolve",
    "resolve",
    is_flag=True,
    default=False,
    help="For an outpoint, fetch its source tx and classify the named vout.",
)
@click.option(
    "--verify-wave",
    "verify_wave",
    is_flag=True,
    default=False,
    help=(
        "For a VERIFIED HashMark v2 signature, look up the WAVE names the signing "
        "key owns. Needs the network. Never runs on an unverified signature."
    ),
)
@click.option(
    "--wave-name",
    "wave_name",
    default=None,
    metavar="NAME",
    help=(
        "HashMark §7.6 form 2: what did NAME (e.g. company.rxd) point at AT THE BLOCK THAT "
        "CARRIED THIS MARK, and was it the signing key? Needs --min-confirmations and two "
        "configured ElectrumX servers; with one it degrades to the present-tense answer and "
        "says why. Never runs on an unverified signature."
    ),
)
@click.option(
    "--min-confirmations",
    "min_confirmations",
    type=click.IntRange(min=1),
    default=None,
    metavar="N",
    help=(
        "Depth below which the mark's block is too shallow to build a form-2 claim on. "
        "Required with --wave-name; deliberately has no default (depth is value-scaled)."
    ),
)
@click.pass_obj
def inspect_cmd(
    ctx: CliContext,
    inspect_input: str,
    fetch: bool,
    resolve: bool,
    verify_wave: bool,
    wave_name: str | None,
    min_confirmations: int | None,
) -> None:
    """Classify a Glyph input.

    INPUT can be:

    \b
      • a 64-char txid              (requires --fetch)
      • a 72-char contract id       (e.g. "b45dc4...a2a800000004")
      • an outpoint "txid:vout"     (add --resolve to fetch its source tx)
      • a hex-encoded locking script (P2PKH / FT / NFT / mut / commit / dmint)

    Pass --json for machine output (auto-detects when stdout is piped). Read-
    only by design — no broadcast, no wallet load, no mnemonic prompt.

    \b
    --json response schema (stable; new fields may be added without notice):
      contract  → {form, txid, vout, outpoint, wire_hex}
      outpoint  → {form, txid, vout, outpoint, wire_hex}
      script    → {form, length, hex, type, ...type-specific fields}
        type=p2pkh        → owner_pkh
        type=p2sh         → script_hash
        type=nft / ft     → ref_txid, ref_vout, ref_outpoint, owner_pkh
        type=mut          → ref_txid, ref_vout, ref_outpoint, payload_hash
        type=commit-nft / commit-ft → payload_hash, owner_pkh
        type=dmint        → version (v1|v2), contract_ref_outpoint,
                            token_ref_outpoint, height, max_height, reward,
                            algo, daa_mode
        type=p2pkh-cltv   → owner_pkh, locktime_value, locktime_basis
                            ("height"|"unix_time"), locktime_units,
                            locktime_earliest. Absolute time-lock (BIP-65);
                            basis is decided by LOCKTIME_THRESHOLD
                            (500,000,000). locktime_units is the FLOOR on the
                            spending tx's nLockTime; locktime_earliest
                            (= locktime_units + 1) is the first block
                            height/time that can carry the spend, because
                            IsFinalTx requires nLockTime < the containing
                            block's height/time.
        type=p2pkh-csv    → owner_pkh, locktime_value, locktime_basis
                            ("blocks"|"time_512s"), locktime_units,
                            relative_lock_disabled. Relative time-lock
                            (BIP-68/112); relative_lock_disabled=true means
                            bit 31 is set and consensus ignores the lock.
        type=soulbound-covenant → variant ("fixed-index"|"composable"),
                            transferability, bound_ref_txid, bound_ref_vout,
                            bound_ref_outpoint, owner_pkh,
                            has_self_replication, has_burn_branch, note.
                            An EXACT match against pyrxd's soulbound builder:
                            the lock permits only a self-clone or a burn.
        type=self-replicating-covenant → has_self_replication,
                            has_burn_branch, bound_ref_outpoint (only when the
                            script binds exactly one ref), note,
                            token_bearing, input_refs[], referenced_refs[].
                            Structural MARKERS only — not proof the script is
                            a soulbound token. Carries NO transferability key,
                            deliberately: that field is the soulbound verdict
                            and this tier has not earned it.
        type=container-legacy → spendable (always false), ref_outpoint,
                            child_ref_outpoint, owner_pkh, note. A dead
                            pre-0.15.0 CONTAINER output; nothing can spend it.
        type=unknown      → token_bearing (true|false|null), input_refs[],
                            referenced_refs[]; each entry {opcode,
                            ref_outpoint}. token_bearing=null means the script
                            does not decode, so the absence of a ref is NOT
                            proven. input_refs[] is the CARRIED set (0xd0
                            OP_PUSHINPUTREF / 0xd8 OP_PUSHINPUTREFSINGLETON —
                            Radiant's foundPushRefs), and only those make an
                            output token-bearing. referenced_refs[] is the set
                            the script names without holding (0xd1
                            OP_REQUIREINPUTREF gates on one; 0xd2/0xd3 forbid
                            one); spending such an output destroys nothing.

    Script-level vs envelope-level: the type above is read from the LOCKING
    SCRIPT. The Glyph protocol labels that live in the reveal transaction's
    CBOR envelope — dat / container / authority / encrypted / timelock / wave —
    are a different classifier, reported under metadata.classification on the
    txid form only. A TIMELOCK *token* has no script signature to find; the
    p2pkh-cltv / p2pkh-csv types above are ordinary BIP-65/112 script locks and
    are unrelated to it.
      txid (--fetch)   → {form, txid, byte_length, input_count, output_count,
                          outputs[], metadata, mint_scriptsig}
        outputs[]: {vout, type, satoshis, ...same per-type fields as script form}
        mint_scriptsig: null OR {nonce_hex, input_hash, output_hash,
                          version_hint ("v1"|"v2"), scriptsig_length} —
                          present when vin[0] is a dMint V1/V2 mint claim

    All hex values are lowercase. Outpoints render as "txid:vout"
    (display order). Wire forms (txid reversed + vout LE) appear under
    ``wire_hex`` for contract/outpoint forms.

    Network defaults (fetch path): connects to the configured ElectrumX URL
    (override with the top-level --electrumx flag). TLS is enforced; raw
    ws:// is rejected by the underlying client. Default timeout: 30s. Server
    responses are bound-checked (size cap, input/output count caps) and the
    returned tx is verified against the requested txid by sha256d roundtrip.
    """
    form, value = _classify_input(inspect_input)

    # Forms that need a network fetch.
    needs_fetch = (form == "txid") or (form == "outpoint" and resolve)

    if form == "txid" and not fetch:
        raise UserError(
            "txid inspection requires --fetch",
            cause="this looks like a txid (64 hex chars)",
            fix="re-run with --fetch to query ElectrumX for the transaction",
        )
    if fetch and form not in ("txid",):
        raise UserError(
            "--fetch is only meaningful for txid input",
            fix="use --resolve to fetch an outpoint's source tx",
        )
    if resolve and form != "outpoint":
        raise UserError(
            "--resolve is only meaningful for an outpoint input",
        )

    if needs_fetch:
        payload = _run_fetch_inspect(ctx, form=form, value=value)
    elif form == "contract":
        payload = _inspect_contract(value)
    elif form == "outpoint":
        payload = _inspect_outpoint(value)
    elif form == "script":
        payload = _inspect_script(value, network=ctx.network)
    else:  # pragma: no cover — _classify_input never returns other values
        raise UserError(f"internal: unknown form {form!r}")

    if verify_wave:
        _attach_wave_identity(ctx, payload)
    if wave_name:
        _require_min_confirmations(min_confirmations)
        _attach_name_at_mark(ctx, payload, name=wave_name, min_confirmations=min_confirmations)  # type: ignore[arg-type]

    mode = ctx.output_mode
    if mode == "json":
        click.echo(emit(payload, mode="json"))
    elif mode == "quiet":
        # Pick the single most-useful string per form.
        if form == "script":
            click.echo(payload.get("type", ""))
        elif form == "txid":
            click.echo(payload.get("txid", ""))
        else:
            click.echo(payload.get("outpoint", ""))
    else:
        click.echo(_render_inspect_human(payload))


def _run_fetch_inspect(ctx: CliContext, *, form: str, value: str) -> dict:
    """Spin up an ElectrumX client, run _inspect_txid_inner, surface errors.

    Wraps NetworkError → NetworkBoundaryError (exit code 2) so a
    user can distinguish "wrong input" (UserError, exit 1) from
    "network is down" (exit 2).
    """

    async def _do() -> dict:
        client = ctx.make_client()
        async with client:
            if form == "txid":
                return await _inspect_txid_inner(client, value, network=ctx.network)
            # form == "outpoint" + resolve: parse, fetch the source, classify
            # only the named vout.
            outpoint_payload = _inspect_outpoint(value)
            return await _inspect_txid_inner(
                client,
                outpoint_payload["txid"],
                only_vout=outpoint_payload["vout"],
                network=ctx.network,
            )

    try:
        return asyncio.run(_do())
    except NetworkError as exc:
        raise NetworkBoundaryError(
            "could not reach ElectrumX",
            cause=str(exc),
            fix=f"check that {ctx.electrumx_url} is reachable",
        ) from exc


def _attach_wave_identity(ctx: CliContext, payload: dict) -> None:
    """Attach the WAVE names that resolve to a VERIFIED signer's key RIGHT NOW.

    Present tense throughout, and deliberately not "the names the signer owns" — that
    phrasing was the bug. See :func:`_resolve_one_wave_identity` and HashMark §7.6.

    ONLY runs on a signature that actually verified. Resolving an unverified
    signer would dress a claim up as an identity — the exact failure the
    signature check exists to prevent — so an unverified or absent attestation
    attaches nothing and says why.

    Errors are attached rather than raised: a name lookup failing is not a reason
    to lose the classification the user asked for.
    """
    for hm in hashmark_records(payload):
        _resolve_one_wave_identity(ctx, hm)


def _resolve_one_wave_identity(ctx: CliContext, hm: dict) -> None:
    if not hm:
        return
    att = hm.get("attestation") or {}
    if att.get("outcome") != "valid":
        hm["wave_identity"] = {
            "resolved": False,
            "reason": (
                "signature did not verify; refusing to resolve an unproven signer"
                if att.get("outcome") == "invalid_signature"
                else "no verified v2 signature on this record"
            ),
        }
        return

    from ..glyph.wave import wave_names_for_hash160

    async def _do() -> list[str]:
        client = ctx.make_client()
        async with client:
            return await wave_names_for_hash160(client, bytes.fromhex(att["recovered_hash160"]))

    try:
        names = asyncio.run(_do())
    except Exception as exc:
        # The exception text can contain a server-controlled response body.
        hm["wave_identity"] = {"resolved": False, "reason": _sanitize_display_string(f"lookup failed: {exc}")}
        return
    # SANITIZED AT THE BOUNDARY, like every other name the indexer hands back. A
    # WAVE name is registration text an attacker chooses, and it lands directly
    # under "signature VERIFIED" — the one line in this output that states an
    # independently checked cryptographic fact. Raw, it can carry the ANSI to
    # scroll that line off the screen and reprint it saying something else.
    hm["wave_identity"] = {
        "resolved": True,
        # NAMED FOR WHAT IT IS. This was `names`, which invites exactly the inference
        # §7.6 forbids: a name resolves to whatever it points at NOW, and the mark was
        # made at a past block. Applying a present-tense lookup to a past event is
        # wrong in both directions the moment a name changes hands — a genuine mark by
        # the previous holder starts failing, and whoever picks up a lapsed name can
        # make NEW marks that truthfully verify as "signed by whoever owns
        # company.rxd", which a reader hears as "the company made this".
        "names_resolving_now": [_sanitize_display_string(n) for n in names],
        # Explicit so a downstream consumer cannot reach for this field believing it
        # is the historical answer. Doing that properly means establishing what the
        # name pointed at AT THE MARK'S OWN BLOCK, by fetching and verifying the chain
        # of modification transactions — not by trusting an index (§2.8, §7.6).
        "point_in_time": False,
        "caveat": (
            "present-tense lookup, not a property of the mark: names change hands, so this "
            "does not establish who held the name when the mark was made"
        ),
    }
