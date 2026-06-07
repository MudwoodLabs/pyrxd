#!/usr/bin/env python3
"""Operator harness for a GO-GATED watchtower v2 autonomous-refund dust run.

This drives a real (dust-value) "maker-never-locks" BTC HTLC refund through the SAME production
artifacts the tower consumes — a :class:`SwapRecord` (whose ``btc_locator`` is the full durable
Tapscript tree + control blocks) and a keyless :class:`PresignedRefund` sidecar — so the live run
exercises the shipped code, not a parallel re-implementation.

Why this file exists at all: an earlier ad-hoc run hand-rolled persistence and saved only the refund
private key, discarding the maker x-only pubkey. A Taproot script-path refund needs the WHOLE taptree
(``BtcHtlcLocator``'s docstring says exactly this), so the funded HTLC became unspendable and the dust
was stranded. The lesson is encoded here as a hard gate: ``setup`` REFUSES to print a funding address
unless a refund transaction can be rebuilt **purely from the on-disk state** (see ``_self_test``). An
unspendable HTLC can no longer be funded.

Flow (each on-chain step is a separate subcommand so the operator can Go-gate it):

    setup    generate the HTLC, self-test reconstruction-from-disk, then print the funding address.
    record   after the operator funds it, build + persist the production SwapRecord for the outpoint.
    presign  call the production presign_refund() to write the keyless <swap_id>.refund.json sidecar.
    plan     print the exact watchtower_run.py command that arms the (keyless) autonomous broadcast.

The taker refund private key lives ONLY in the 0600 state file and is used ONLY by ``presign`` (which
signs once, exactly as the operator would online). The tower/daemon is keyless: it broadcasts the
pre-signed bytes. The state file is custody-sensitive (it holds the key that controls the funded dust)
— protect it; the dust is recoverable from it even if everything else is lost.

The autonomous broadcast path itself is proven end-to-end on real bitcoind by
``tests/test_xchain_swap_regtest_e2e.py::TestWatchtowerDustHarnessRegtest`` — which runs THIS harness's
setup/record/presign and then lets the production RefundExecutor broadcast, asserting the dust lands at
the pinned refund scriptPubKey. Run that proof (``XCHAIN_REGTEST=1``) before trusting the harness with
mainnet value.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import stat
import tempfile
from pathlib import Path

import coincurve

from pyrxd.btc_wallet import taproot as bt
from pyrxd.btc_wallet.keys import generate_keypair
from pyrxd.btc_wallet.payment import DUST_LIMIT
from pyrxd.gravity.swap_state import NegotiatedTerms, SwapRecord, SwapState
from pyrxd.security.errors import ValidationError

# A placeholder outpoint for the setup-time self-test: 32 zero bytes is valid 64-char hex. The refund
# built against it is never broadcast — the self-test only proves the refund RECONSTRUCTS + BINDS from
# the persisted state (the real signature is produced over the real outpoint at presign time).
_PLACEHOLDER_TXID = "00" * 32
_ZERO32 = bytes(32)


def _xonly(privkey: bytes) -> bytes:
    """The 32-byte BIP340 x-only pubkey for a raw private key (codebase idiom)."""
    return coincurve.PublicKeyXOnly.from_secret(privkey).format()


def _is_standard_spk(spk: bytes) -> bool:
    """True iff ``spk`` is a standard, spendable scriptPubKey template (P2WPKH/P2TR/P2WSH/P2PKH/P2SH).

    The refund must pay a real address; an empty or OP_RETURN/malformed output would burn the dust. The
    operator derives the refund SPK from a checksum-validated address, but the gate verifies it anyway."""
    return (
        (len(spk) == 22 and spk[:2] == b"\x00\x14")  # P2WPKH
        or (len(spk) == 34 and spk[:2] == b"\x51\x20")  # P2TR
        or (len(spk) == 34 and spk[:2] == b"\x00\x20")  # P2WSH
        or (len(spk) == 25 and spk[:3] == b"\x76\xa9\x14" and spk[-2:] == b"\x88\xac")  # P2PKH
        or (len(spk) == 23 and spk[:2] == b"\xa9\x14" and spk[-1:] == b"\x87")  # P2SH
    )


def _write_0600(path: Path, text: str) -> None:
    """Atomically write ``text`` to ``path`` at mode 0600 from CREATION.

    The state file holds the refund private key, so it must never exist even briefly as a
    world/group-readable file (a plain ``write_text`` + later ``chmod`` leaves a TOCTOU window at the
    process umask). ``mkstemp`` creates the temp at 0600; we fsync and ``os.replace`` it into place
    (atomic, mode-preserving) — which also means a crash mid-write can never leave a half-written state
    that a later step would rebuild a wrong taptree from."""
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp")
    try:
        os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)  # 0600 before any content is written
        with os.fdopen(fd, "w") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)  # atomic; preserves the temp's 0600 mode
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise


# --------------------------------------------------------------------------------------------------
# Pure reconstruction (takes ONLY the persisted dict — never an in-memory HTLC/key object). This is
# the heart of the fix: every spend artifact is rebuilt from disk, so an incompletely persisted state
# fails the self-test instead of stranding funds.
# --------------------------------------------------------------------------------------------------


def reconstruct_htlc(state: dict) -> bt.BtcHtlc:
    """Rebuild the HTLC from ONLY the on-disk state. Pure; no key needed to derive the address/SPK."""
    refund_priv = bytes.fromhex(state["taker_refund_privkey"])
    return bt.build_htlc(
        hashlock=bytes.fromhex(state["hashlock"]),
        claim_pubkey_xonly=bytes.fromhex(state["maker_claim_pubkey_xonly"]),
        refund_pubkey_xonly=_xonly(refund_priv),
        timeout=bt.Timelock(int(state["t_btc_blocks"]), bt.TimeUnit.BLOCKS),
        network=str(state["network"]),
    )


def build_refund_from_state(state: dict, outpoint: bt.BtcOutpoint, fee_sats: int) -> bytes:
    """Rebuild + sign the refund tx from ONLY the on-disk state + a funding outpoint."""
    htlc = reconstruct_htlc(state)
    locator = htlc.with_funding(outpoint, int(state["btc_sats"]))
    return bt.build_refund_tx(
        locator=locator,
        refund_privkey=bytes.fromhex(state["taker_refund_privkey"]),
        timeout=bt.Timelock(int(state["t_btc_blocks"]), bt.TimeUnit.BLOCKS),
        to_scriptpubkey=bytes.fromhex(state["refund_spk"]),
        fee_sats=fee_sats,
        aux_rand=bt.fresh_aux_rand(),
    )


def _assert_reconstructs_to_funded(state: dict) -> bt.BtcHtlc:
    """Reconstruct the HTLC from disk and assert it matches the persisted (funded) address/SPK.

    ``htlc_address``/``htlc_spk`` are the truth-anchor the operator actually funded. Re-deriving the
    taptree from ``t_btc_blocks`` + the keys and comparing it back catches any post-setup DRIFT
    (corruption, an operator hand-edit, a stale-copy restore, a partial write) that would otherwise let
    ``record``/``presign`` silently build a refund for the WRONG taptree — a refund consensus rejects
    against the real UTXO, stranding the dust. EVERY value-moving step calls this, so the funded-output
    path fails closed exactly like ``setup``."""
    htlc = reconstruct_htlc(state)
    if htlc.address != state["htlc_address"]:
        raise ValidationError(
            f"reconstruct-from-disk address {htlc.address} != persisted {state['htlc_address']} — "
            "the on-disk state no longer rebuilds the funded HTLC (state drift)"
        )
    if htlc.scriptpubkey.hex() != state["htlc_spk"]:
        raise ValidationError("reconstruct-from-disk scriptPubKey != persisted — state drift")
    return htlc


def _self_test(state_path: Path) -> None:
    """RECONSTRUCT-FROM-DISK gate. Reloads the state file fresh and proves a valid refund can be rebuilt
    from it alone — raising (so the caller refuses to emit a funding address) if anything is incomplete.

    Checks, all from the reloaded dict only:
      1. the rebuilt HTLC address + scriptPubKey match the persisted ones (state fully determines the HTLC);
      2. a refund tx rebuilds against a placeholder outpoint and parses as a single-in/single-out spend;
      3. its input nSequence == t_btc CSV, its output pays the pinned refund SPK, and 0 < value < funded.
    These are exactly the binds presign_refund() and the RefundExecutor enforce — so a state that would
    strand funds (the original bug) fails HERE, before any sats move.
    """
    state = json.loads(state_path.read_text())  # FRESH read — never the in-memory build
    _assert_reconstructs_to_funded(state)  # (1) the rebuilt taptree must match the persisted funded SPK

    btc_sats = int(state["btc_sats"])
    t_btc = bt.Timelock(int(state["t_btc_blocks"]), bt.TimeUnit.BLOCKS)
    refund_spk = bytes.fromhex(state["refund_spk"])
    if not _is_standard_spk(refund_spk):
        raise ValidationError(
            f"self-test: refund SPK {refund_spk.hex() or '(empty)'} is not a standard spendable output "
            "(P2WPKH/P2TR/P2WSH/P2PKH/P2SH) — a refund there would burn the dust"
        )
    fee = max(1, min(btc_sats // 4, 1000))  # any 0<fee<amount; the real fee is chosen at presign time
    raw = build_refund_from_state(state, bt.BtcOutpoint(_PLACEHOLDER_TXID, 0), fee)

    fields = bt.btc_spend_fields_from_raw(raw)  # fail-closed structural parse
    if len(fields.input_prevouts) != 1 or len(fields.outputs) != 1:
        raise ValidationError("self-test: refund is not single-input/single-output")
    if fields.input_sequences[0] != t_btc.to_nsequence():
        raise ValidationError("self-test: refund nSequence != t_btc CSV")
    value, out_spk = fields.outputs[0]
    if out_spk != refund_spk:
        raise ValidationError("self-test: refund output does not pay the pinned refund SPK")
    if not (0 < value < btc_sats):
        raise ValidationError(f"self-test: refund value {value} not in (0, {btc_sats})")


# --------------------------------------------------------------------------------------------------
# SwapRecord assembly (the production durable artifact the tower + presign consume)
# --------------------------------------------------------------------------------------------------


def build_record(state: dict, outpoint: bt.BtcOutpoint) -> SwapRecord:
    """A 'maker-never-locks' BTC_LOCKED record: terms + the funded BtcHtlcLocator, no Radiant lock."""
    htlc = reconstruct_htlc(state)
    locator = htlc.with_funding(outpoint, int(state["btc_sats"]))
    refund_priv = bytes.fromhex(state["taker_refund_privkey"])
    btc_sats = int(state["btc_sats"])
    terms = NegotiatedTerms(
        hashlock=bytes.fromhex(state["hashlock"]),
        btc_sats=btc_sats,
        radiant_amount=int(state.get("radiant_amount", 1000)),  # nominal; the RXD leg is never locked
        t_btc=bt.Timelock(int(state["t_btc_blocks"]), bt.TimeUnit.BLOCKS),
        t_rxd=bt.Timelock(int(state["t_rxd_blocks"]), bt.TimeUnit.BLOCKS),
        asset_variant="rxd",
        genesis_ref=b"",
        taker_dest_hash=_ZERO32,
        maker_dest_hash=_ZERO32,
        btc_claim_pubkey_xonly=bytes.fromhex(state["maker_claim_pubkey_xonly"]),
        btc_refund_pubkey_xonly=_xonly(refund_priv),
        counter_chain="btc",
    )
    return SwapRecord(state=SwapState.BTC_LOCKED, terms=terms, counterchain_locator=locator)


# --------------------------------------------------------------------------------------------------
# Subcommands
# --------------------------------------------------------------------------------------------------


def cmd_setup(args: argparse.Namespace) -> int:
    state_path = Path(args.state_file)
    if state_path.exists() and not args.force:
        raise SystemExit(f"{state_path} already exists (pass --force to overwrite a prior run's state)")
    try:
        refund_spk = bytes.fromhex(args.refund_spk.removeprefix("0x"))
    except ValueError as exc:
        raise SystemExit("--refund-spk must be hex (the operator's pinned refund scriptPubKey)") from exc
    if not _is_standard_spk(refund_spk):
        raise SystemExit(
            "--refund-spk must be a standard spendable scriptPubKey (P2WPKH/P2TR/P2WSH/P2PKH/P2SH); "
            "derive it from your checksum-validated refund address"
        )
    if args.t_btc <= args.t_rxd:
        raise SystemExit(f"--t-btc ({args.t_btc}) must be > --t-rxd ({args.t_rxd}) (BTC is the longer leg)")

    # Keys: taker refund key (generated, persisted 0600) + a maker claim PUBKEY (we never claim, so its
    # private half is discarded — only the x-only pubkey is needed to reconstruct the taptree).
    taker_kp = generate_keypair(args.network)
    taker_refund_priv = bytes(taker_kp._privkey.unsafe_raw_bytes())
    maker_claim_xonly = _xonly(os.urandom(32))
    preimage = os.urandom(32)  # never revealed (no claim leg); persisted only for completeness
    import hashlib

    hashlock = hashlib.sha256(preimage).digest()

    htlc = bt.build_htlc(
        hashlock=hashlock,
        claim_pubkey_xonly=maker_claim_xonly,
        refund_pubkey_xonly=_xonly(taker_refund_priv),
        timeout=bt.Timelock(args.t_btc, bt.TimeUnit.BLOCKS),
        network=args.network,
    )

    state = {
        "version": 1,
        "swap_id": args.swap_id,
        "network": args.network,
        "btc_sats": args.btc_sats,
        "t_btc_blocks": args.t_btc,
        "t_rxd_blocks": args.t_rxd,
        "hashlock": hashlock.hex(),
        "preimage": preimage.hex(),
        "maker_claim_pubkey_xonly": maker_claim_xonly.hex(),
        "taker_refund_privkey": taker_refund_priv.hex(),  # SECRET — 0600
        "htlc_address": htlc.address,
        "htlc_spk": htlc.scriptpubkey.hex(),
        "refund_spk": refund_spk.hex(),
        "refund_address": args.refund_address or "",
        "funding": None,
        "step": "awaiting_funding",
    }
    _write_0600(state_path, json.dumps(state, indent=2))

    # THE GATE: reconstruct a valid refund from the file we just wrote, or refuse to emit the address.
    try:
        _self_test(state_path)
    except Exception as exc:
        state_path.unlink(missing_ok=True)  # don't leave a half-baked state that could be funded
        raise SystemExit(f"SELF-TEST FAILED — refusing to print a funding address (state discarded): {exc}") from exc

    print(f"STEP setup OK — reconstruct-from-disk self-test PASSED. State saved 0600 to {state_path}")
    print()
    print(f"  FUND THIS ADDRESS (send exactly {args.btc_sats} sats):")
    print(f"    {htlc.address}")
    print()
    print(
        f"  t_btc = {args.t_btc} blocks  |  refund returns ~{args.btc_sats} - fee  →  {state['refund_address'] or refund_spk.hex()}"
    )
    print(f"  next: fund it, then run:  watchtower_dust_run.py record --state-file {state_path} \\")
    print("            --funding-txid <txid> --funding-vout <n> --funding-sats <sats> --records-dir <dir>")
    return 0


def cmd_record(args: argparse.Namespace) -> int:
    state_path = Path(args.state_file)
    state = json.loads(state_path.read_text())
    outpoint = bt.BtcOutpoint(args.funding_txid, args.funding_vout)
    if args.funding_sats != int(state["btc_sats"]):
        raise SystemExit(
            f"funded {args.funding_sats} sats != setup btc_sats {state['btc_sats']} — refusing "
            "(the refund/record amount must match the actual funding)"
        )
    # The on-disk state must still rebuild the FUNDED HTLC (fail closed on any drift), or the record we
    # write would bind a refund to the wrong taptree and strand the dust.
    try:
        _assert_reconstructs_to_funded(state)
    except ValidationError as exc:
        raise SystemExit(f"STATE DRIFT — refusing to write a record for an un-fundable HTLC: {exc}") from exc

    # Prove the refund reconstructs against the REAL outpoint before persisting the record.
    raw = build_refund_from_state(state, outpoint, fee_sats=max(1, min(int(state["btc_sats"]) // 4, 1000)))
    fields = bt.btc_spend_fields_from_raw(raw)
    if fields.input_prevouts[0] != outpoint.prevout_bytes():
        raise SystemExit("record: rebuilt refund does not spend the funding outpoint — aborting")

    record = build_record(state, outpoint)
    records_dir = Path(args.records_dir)
    records_dir.mkdir(parents=True, exist_ok=True)
    record_path = records_dir / f"{state['swap_id']}.json"
    record_path.write_text(json.dumps(record.to_dict(), indent=2))

    state["funding"] = {"txid": args.funding_txid, "vout": args.funding_vout, "sats": args.funding_sats}
    state["step"] = "recorded"
    _write_0600(state_path, json.dumps(state, indent=2))
    print(f"STEP record OK — wrote production SwapRecord (state=BTC_LOCKED) to {record_path}")
    print(f"  funding outpoint: {args.funding_txid}:{args.funding_vout} ({args.funding_sats} sats)")
    print(
        f"  next:  watchtower_dust_run.py presign --state-file {state_path} --records-dir {records_dir} --fee-sats <fee>"
    )
    return 0


def cmd_presign(args: argparse.Namespace) -> int:
    from presign_refund import presign_refund  # production presigner (scripts/ sibling)

    state_path = Path(args.state_file)
    state = json.loads(state_path.read_text())
    records_dir = Path(args.records_dir)
    record_path = records_dir / f"{state['swap_id']}.json"
    if not record_path.is_file():
        raise SystemExit(f"no SwapRecord at {record_path} — run `record` first")
    # Re-assert the funded taptree (defense in depth — the same gate as record), so a drifted state can
    # never sign a refund the real UTXO will reject.
    try:
        _assert_reconstructs_to_funded(state)
    except ValidationError as exc:
        raise SystemExit(f"STATE DRIFT — refusing to pre-sign an un-spendable refund: {exc}") from exc
    # Reject a sub-dust refund output: presign/executor only check 0 < value < amount, but an output below
    # the relay dust floor is non-relayable (the broadcast would fail-loud and never deliver autonomously).
    out_value = int(state["btc_sats"]) - args.fee_sats
    if out_value < DUST_LIMIT:
        raise SystemExit(
            f"--fee-sats {args.fee_sats} leaves {out_value} sats < relay dust floor {DUST_LIMIT} — "
            "the refund would be non-relayable; lower the fee"
        )

    dest = presign_refund(
        record_path=record_path,
        refund_privkey=bytes.fromhex(state["taker_refund_privkey"]),
        to_scriptpubkey=bytes.fromhex(state["refund_spk"]),
        fee_sats=args.fee_sats,
        out_dir=records_dir,
    )
    from pyrxd.gravity.watch import PresignedRefund

    blob = PresignedRefund.from_dict(json.loads(Path(dest).read_text()))
    state["step"] = "presigned"
    _write_0600(state_path, json.dumps(state, indent=2))
    print(f"STEP presign OK — wrote keyless sidecar {dest}")
    print(f"  refund txid : {blob.txid}")
    print(f"  value       : {blob.output_value_sats} sats → {state['refund_spk']}")
    print(f"  next:  watchtower_dust_run.py plan --state-file {state_path} --records-dir {records_dir}")
    return 0


def cmd_plan(args: argparse.Namespace) -> int:
    state_path = Path(args.state_file)
    state = json.loads(state_path.read_text())
    records_dir = Path(args.records_dir)
    cleared = "--audit-cleared " if state["network"] == "bc" else ""
    print("Arm the KEYLESS autonomous broadcast with the production daemon:")
    print()
    print("  python scripts/watchtower_run.py \\")
    print(f"      --records-dir {records_dir} \\")
    print(f"      --refund-blobs-dir {records_dir} \\")
    print(f"      --network {state['network']} {cleared}\\")
    print(f"      --refund-spk {state['refund_spk']} \\")
    print(f"      --autonomous-refund-cap-sats {min(int(state['btc_sats']) + 1, 10_000)} \\")
    print("      --accept-single-source \\")
    print("      --rxd-backend ssh-tr \\")
    print("      --measured --poll-interval-s 30 --heartbeat-file ~/.pyrxd/watchtower/heartbeat")
    print()
    print("  The daemon holds NO key; it broadcasts the pre-signed sidecar once the BTC funding buries")
    print(f"  >= t_btc ({state['t_btc_blocks']}) blocks and the RXD asset is observed un-locked.")
    return 0


def _parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Go-gated watchtower v2 autonomous-refund dust run harness")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("setup", help="generate the HTLC + self-test reconstruction + print the funding address")
    s.add_argument("--state-file", required=True, help="path to write the 0600 run-state file")
    s.add_argument("--swap-id", default="dust1", help="swap id (== the SwapRecord/sidecar file stem)")
    s.add_argument("--network", default="bc", help="bc | bcrt | tb | signet")
    s.add_argument("--btc-sats", type=int, required=True, help="exact sats to fund the HTLC with")
    s.add_argument("--t-btc", type=int, default=2, help="BTC refund CSV in blocks (the longer leg)")
    s.add_argument("--t-rxd", type=int, default=1, help="RXD refund CSV in blocks (must be < --t-btc)")
    s.add_argument("--refund-spk", required=True, help="hex scriptPubKey the refund must pay (YOUR address)")
    s.add_argument("--refund-address", help="the refund address, for display only")
    s.add_argument("--force", action="store_true", help="overwrite an existing state file")
    s.set_defaults(func=cmd_setup)

    r = sub.add_parser("record", help="after funding, build + persist the production SwapRecord")
    r.add_argument("--state-file", required=True)
    r.add_argument("--funding-txid", required=True, help="big-endian (explorer) funding txid")
    r.add_argument("--funding-vout", type=int, required=True)
    r.add_argument("--funding-sats", type=int, required=True, help="must equal the setup --btc-sats")
    r.add_argument("--records-dir", required=True, help="dir to write <swap_id>.json into")
    r.set_defaults(func=cmd_record)

    g = sub.add_parser("presign", help="write the keyless <swap_id>.refund.json via the production presigner")
    g.add_argument("--state-file", required=True)
    g.add_argument("--records-dir", required=True)
    g.add_argument("--fee-sats", type=int, required=True, help="absolute fee baked into the unbumpable refund")
    g.set_defaults(func=cmd_presign)

    pl = sub.add_parser("plan", help="print the watchtower_run.py command that arms the keyless broadcast")
    pl.add_argument("--state-file", required=True)
    pl.add_argument("--records-dir", required=True)
    pl.set_defaults(func=cmd_plan)

    return p.parse_args(argv)


def main(argv=None) -> int:
    args = _parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
