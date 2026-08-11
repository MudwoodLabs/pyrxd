"""Private helpers for the ``pyrxd glyph …`` commands.

Extracted from :mod:`pyrxd.cli.glyph_cmds` to keep that module focused on
command flow. Everything here is package-internal (underscore-prefixed) and
imported by ``glyph_cmds``:

* metadata file parsing + scaffolding (``_read_metadata_file``,
  ``_TEMPLATE_TYPES``, ``_scaffold_for``),
* the pre-broadcast confirmation summary (``_BroadcastSummary``,
  ``_confirm_or_abort``, ``_metadata_summary``),
* the Glyph reveal unlock-script builder (``_build_glyph_unlock``),
* Glyph ref parsing (``_parse_ref``, ``_try_extract_ft_ref``),
* live dMint contract lookup (``_fetch_dmint_contract``) — shared by
  ``glyph_cmds`` (claim) and ``glyph_estimate`` (estimate), which is why it
  sits here rather than in either of them.

These are glyph-specific; the shared ``_load_wallet`` lives in
:mod:`pyrxd.cli.prompts` (it is used by query commands too).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from ..glyph.dmint import DmintCborPayload
from ..glyph.mint import build_reveal_unlock_template
from ..glyph.types import GlyphMetadata, GlyphProtocol, GlyphRef, GlyphRoyalty
from ..security.errors import ValidationError
from ..security.types import Txid
from .context import CliContext
from .errors import UserError
from .prompts import confirm_action

if TYPE_CHECKING:
    from ..glyph.dmint import DmintContractUtxo
    from ..keys import PrivateKey
    from ..network.electrumx import ElectrumXClient


# ---------------------------------------------------------------------------
# Metadata file parsing + scaffolding
# ---------------------------------------------------------------------------


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
            royalty=_read_royalty(data.get("royalty")),
            dmint_params=_read_dmint(data.get("dmint")),
        )
    except ValidationError as exc:
        raise UserError(
            "metadata file failed validation",
            cause=str(exc),
            fix="see the error above; check protocol combinations and decimals range",
        ) from exc


def _read_dmint(raw: object) -> DmintCborPayload | None:
    """Parse the optional ``dmint`` block of a metadata file.

    Until this existed the key was **silently dropped**. ``_read_metadata_file``
    never passed ``dmint_params`` to :class:`GlyphMetadata`, so ``deploy-dmint``
    emitted CBOR with no ``dmint`` object — and
    :func:`pyrxd.glyph.builder._assert_declared_dmint_matches`, the guard that
    exists precisely to stop a token advertising a supply it does not mint,
    returned early on every deploy the CLI made. It was unreachable from the
    only command that emits a premine. A metadata file declaring
    ``"premine": 999999999`` deployed with no premine at all, and nothing said
    so.

    Declaring the block is optional. What is not optional is that a declaration,
    once made, is checked against the contract actually built — see that guard
    for which fields are reconciled and why the ``daa`` sub-object is not.

    ``algo`` accepts either the CBOR integer or a name (``"sha256d"``,
    ``"blake3"``, ``"k12"``), because a hand-written metadata file is written by
    a person and ``"algo": 1`` is not a thing a person can check.

    Shape (mirrors the CBOR the envelope carries)::

        "dmint": {
            "algo": "sha256d",
            "numContracts": 1,
            "maxHeight": 10000,
            "reward": 1000,
            "premine": 0,
            "diff": 1
        }
    """
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise UserError(
            "metadata.dmint must be a JSON object",
            cause=f"got {type(raw).__name__}: {raw!r}",
            fix='use {"numContracts": 1, "maxHeight": 10000, "reward": 1000, "premine": 0, "diff": 1}',
        )

    from ..glyph.dmint import DmintAlgo

    block = dict(raw)
    algo = block.get("algo", int(DmintAlgo.SHA256D))
    if isinstance(algo, str):
        try:
            block["algo"] = int(DmintAlgo[algo.upper()])
        except KeyError:
            raise UserError(
                f"unknown metadata.dmint.algo name: {algo!r}",
                fix=f"valid names: {sorted(a.name.lower() for a in DmintAlgo)}",
            ) from None
    else:
        block["algo"] = algo

    try:
        return DmintCborPayload.from_cbor_dict(block)
    except (ValidationError, KeyError, TypeError, ValueError) as exc:
        raise UserError(
            "metadata.dmint failed validation",
            cause=str(exc),
            fix="required keys: maxHeight, reward, diff (numContracts and premine default to 1 and 0)",
        ) from exc


def _read_royalty(raw: object) -> GlyphRoyalty | None:
    """Parse the optional ``royalty`` block of a metadata file.

    Until this existed the key was **silently dropped**: ``_read_metadata_file``
    never passed ``royalty`` to :class:`GlyphMetadata`, so a creator could write
    a complete royalty block, mint, and end up with a token whose CBOR carried
    no royalty at all — with no warning, and nothing to notice afterwards except
    that no wallet ever showed one. Minting is one-way, so the failure was
    permanent for that token.

    The royalty that lands here is a **declaration, not a guarantee**. Nothing in
    Radiant consensus makes a later transfer pay it; see
    :mod:`pyrxd.glyph.royalty` for what "honouring" it can and cannot mean.

    Shape (mirrors the CBOR the envelope carries)::

        "royalty": {
            "bps": 500,
            "address": "1Recipient…",
            "enforced": false,
            "minimum": 0,
            "splits": [{"address": "1A…", "bps": 300},
                       {"address": "1B…", "bps": 200}]
        }
    """
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise UserError(
            "metadata.royalty must be a JSON object",
            cause=f"got {type(raw).__name__}: {raw!r}",
            fix='use {"bps": 500, "address": "<radiant address>"}',
        )
    if "bps" not in raw or "address" not in raw:
        raise UserError(
            "metadata.royalty needs both 'bps' and 'address'",
            cause=f"got keys {sorted(raw)}",
            fix='e.g. {"bps": 500, "address": "<radiant address>"} for 5%',
        )

    # Not `raw.get("splits", []) or []` — that turns any falsy value, including
    # a wrong-typed `{}`, into an empty list and skips the type check below.
    splits_raw = raw["splits"] if "splits" in raw and raw["splits"] is not None else []
    if not isinstance(splits_raw, list):
        raise UserError(
            "metadata.royalty.splits must be a list of objects",
            cause=f"got {type(splits_raw).__name__}",
            fix='e.g. [{"address": "<addr>", "bps": 300}]',
        )
    splits: list[tuple[str, int]] = []
    for i, s in enumerate(splits_raw):
        if not isinstance(s, dict) or "address" not in s or "bps" not in s:
            raise UserError(
                f"metadata.royalty.splits[{i}] must be an object with 'address' and 'bps'",
                cause=f"got {s!r}",
            )
        # int() is inside its own guard: a non-numeric split bps would otherwise
        # escape as a raw ValueError/TypeError traceback rather than the
        # message/cause/fix block every other CLI failure produces.
        try:
            split_bps = int(s["bps"])
        except (TypeError, ValueError) as exc:
            raise UserError(
                f"metadata.royalty.splits[{i}].bps is not an integer",
                cause=f"got {s['bps']!r}",
                fix="basis points are whole numbers, e.g. 300 for 3%",
            ) from exc
        splits.append((str(s["address"]), split_bps))

    try:
        royalty = GlyphRoyalty(
            bps=int(raw["bps"]),
            address=str(raw["address"]),
            enforced=bool(raw.get("enforced", False)),
            minimum=int(raw.get("minimum", 0)),
            splits=tuple(splits),
        )
    except (ValidationError, TypeError, ValueError) as exc:
        raise UserError(
            "metadata.royalty failed validation",
            cause=str(exc),
            fix="bps must be 0..10000, address non-empty, minimum >= 0, and splits must not exceed bps",
        ) from exc

    # GlyphRoyalty accepts any non-empty address string, so an unusable address
    # would otherwise be signed into the token's CBOR and only surface when
    # somebody tried to pay it. Decode EVERY address named in the block — not
    # whichever ones happen to be paid at some probe price. Running
    # `royalty_payouts` and hoping looked equivalent and is not: it drops
    # recipients whose share floors to zero, so splits that exactly cover `bps`
    # leave the top-level address unchecked, and `bps=0` with no minimum checks
    # nothing at all. Minting is one-way; a typo caught here is free.
    from ..utils import address_to_public_key_hash

    for label, address in [
        ("address", royalty.address),
        *((f"splits[{i}].address", a) for i, (a, _) in enumerate(royalty.splits)),
    ]:
        try:
            if len(address_to_public_key_hash(address)) != 20:
                raise ValueError("decoded to the wrong length")
        except (ValidationError, ValueError) as exc:
            raise UserError(
                f"metadata.royalty.{label} is not a valid Radiant address",
                cause=f"{address!r}: {exc}",
                fix="check every 'address' in the royalty block, including any splits",
            ) from exc
    return royalty


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
        # ``token_type`` is Photonic's ``type`` field, and its container value is
        # the literal string "container" (packages/app/src/pages/Mint.tsx:
        # ``TokenType = "object" | "container" | "user" | "fungible"``). Emitting
        # "collection" here produced a token Photonic renders as a plain object.
        return {**base, "protocol": ["NFT", "CONTAINER"], "token_type": "container"}  # nosec B105 — token-type tag
    # Should be unreachable thanks to click.Choice.
    raise UserError(f"unknown template type: {kind}")  # pragma: no cover


# ---------------------------------------------------------------------------
# Broadcast confirmation summary
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
        # Say it here, at the only moment the creator is still deciding. A
        # royalty recorded in a Glyph envelope is a declaration honoured by
        # compliant wallets, not something Radiant consensus can compel — see
        # pyrxd.glyph.royalty for the evidence behind that sentence.
        lines.append("             (ADVISORY — recorded on chain, not enforced by consensus)")
    return _BroadcastSummary(title="Metadata", lines=lines)


# ---------------------------------------------------------------------------
# Glyph reveal unlock-script builder
# ---------------------------------------------------------------------------


def _build_glyph_unlock(privkey: PrivateKey, scriptsig_suffix: bytes):
    """Return an UnlockingScriptTemplate that signs P2PKH then appends the Glyph suffix.

    Thin alias for :func:`pyrxd.glyph.mint.build_reveal_unlock_template`. This template
    existed in four places at once — here plus one copy in each of the three
    ``examples/*.py`` mint scripts — and each copy restated the estimated unlocking
    length, the number ``pyrxd.glyph.fees`` sizes the reveal fee from. A copy that
    drifted low would make the fee guard under-estimate and pass, stranding the commit.
    One definition now, in the library where the examples can import it too.
    """
    return build_reveal_unlock_template(privkey, scriptsig_suffix)


# ---------------------------------------------------------------------------
# Glyph ref parsing
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


def _try_extract_ft_ref(script: bytes) -> GlyphRef | None:
    """Best-effort extract of the FT ref from a locking script."""
    from ..glyph.script import extract_ref_from_ft_script

    try:
        return extract_ref_from_ft_script(script)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Live dMint contract lookup
# ---------------------------------------------------------------------------


async def _fetch_dmint_contract(client: ElectrumXClient, txid: str, vout: int) -> DmintContractUtxo:
    """Fetch a dMint contract UTXO and parse its on-chain state.

    Shared by ``glyph claim-dmint`` and ``glyph dmint-estimate`` — both need
    the same "read the live contract's target" step, and a second copy would
    be a place for the two to disagree about what counts as a dMint output.
    """
    from ..glyph.dmint import DmintContractUtxo, DmintState
    from ..security.types import Txid as _Txid
    from ..transaction.transaction import Transaction

    tx_bytes = await client.get_transaction(_Txid(txid))
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
