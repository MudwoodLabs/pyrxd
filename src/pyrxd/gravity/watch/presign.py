#!/usr/bin/env python3
"""Pre-sign a BTC HTLC refund for the autonomous watchtower (v2) — the ONLINE setup step.

Run this ONCE per swap, while you are online and hold your refund key, to produce the operator-
pre-signed refund the keyless tower will later broadcast if the maker walks away. The signing key is
used HERE and NEVER reaches the tower: the output is just signed transaction bytes (a
``<swap_id>.refund.json`` sidecar beside the SwapRecord).

It reconstructs the refund from the persisted SwapRecord's locator (full durable taptree) + the
negotiated ``t_btc``, signs with your refund private key, and verifies the result binds to the swap
exactly as the tower will (spends THIS funding outpoint, carries the ``t_btc`` CSV nSequence, pays YOUR
pinned ``--to-scriptpubkey`` within range). The sidecar is written LAST (the record already exists), so
a partial setup can never yield an armed-but-mismatched pair.

SECURITY: the sidecar is a signed tx that pays you — a custody-sensitive artifact. It carries NO key
and NO preimage, but protect it (and your key file) at rest. Pass the SAME ``--to-scriptpubkey`` to the
tower as ``--refund-spk``: the tower refuses to broadcast a blob whose output is not that address.

Example (console script, installed with the package):
    pyrxd-presign-refund \\
        --record   ~/.pyrxd/watchtower/swaps/swap1.json \\
        --refund-key-file ~/.keys/taker_refund.hex \\
        --to-scriptpubkey 5120<32-byte-hex> \\
        --fee-sats 500

Also runnable in-tree as ``python scripts/presign_refund.py`` (a thin back-compat shim
over this module) or as ``python -m pyrxd.gravity.watch.presign``.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

from pyrxd.btc_wallet import taproot as t
from pyrxd.gravity.swap_state import SwapRecord
from pyrxd.gravity.watch import PresignedRefund
from pyrxd.gravity.watch.cli_secrets import read_secret_file
from pyrxd.security.errors import RxdSdkError, ValidationError


def presign_refund(
    *,
    record_path: str | Path,
    refund_privkey: bytes,
    to_scriptpubkey: bytes,
    fee_sats: int,
    out_dir: str | Path | None = None,
    aux_rand: bytes | None = None,
) -> Path:
    """Build + verify + persist the pre-signed refund sidecar. Returns the written path.

    Fail-closed: raises before writing if the record is not a funded BTC swap, or if the built tx does
    not bind to the swap exactly as the tower will check (so a mismatch surfaces HERE, not silently)."""
    record_path = Path(record_path)
    swap_id = record_path.stem  # the JsonDirRecordStore keys swaps by the file stem
    record = SwapRecord.from_dict(json.loads(record_path.read_text()))
    if record.terms.counter_chain != "btc":
        raise ValidationError(
            f"{record_path} is a {record.terms.counter_chain!r} swap — only BTC refunds are pre-signable"
        )
    locator = record.btc_locator
    if locator is None:
        raise ValidationError(f"{record_path} has no funded BTC locator yet — fund the BTC leg before pre-signing")
    timeout = record.terms.t_btc
    raw = t.build_refund_tx(
        locator=locator,
        refund_privkey=refund_privkey,
        timeout=timeout,
        to_scriptpubkey=to_scriptpubkey,
        fee_sats=fee_sats,
        aux_rand=aux_rand if aux_rand is not None else os.urandom(32),
    )
    blob = PresignedRefund(raw_tx=raw, swap_id=swap_id)  # validates structure
    # Verify the binds the tower will enforce, so a wrong key/fee/address fails HERE not at the tower.
    if blob.funding_prevout != locator.funding_outpoint.prevout_bytes():
        raise ValidationError("built refund does not spend the swap's funding outpoint (wrong locator?)")
    if blob.input_nsequence != timeout.to_nsequence():
        raise ValidationError("built refund nSequence != negotiated t_btc CSV")
    if blob.output_spk != to_scriptpubkey:
        raise ValidationError("built refund output != --to-scriptpubkey")
    if not (0 < blob.output_value_sats < locator.amount_sats):
        raise ValidationError(
            f"refund value {blob.output_value_sats} not in (0, funded {locator.amount_sats}) — bad fee"
        )
    out = Path(out_dir) if out_dir is not None else record_path.parent
    dest = out / f"{swap_id}.refund.json"
    # Write LAST (the record already exists) so a partial setup never yields an armed-but-mismatched pair.
    _atomic_write_0600(dest, json.dumps(blob.to_dict()).encode())
    return dest


def _atomic_write_0600(dest: Path, payload: bytes) -> None:
    """mkstemp + fchmod + fsync + os.replace — the house convention (``pyrxd.hd.wallet.save``).

    The sidecar is custody-sensitive (a signed transaction that pays you), and the tower reads
    it unattended, so ``write_text`` + ``chmod`` was wrong twice over: the file existed at the
    process umask (typically 0644 — world-readable) for the window before the ``chmod``, and a
    crash mid-write left a TRUNCATED blob at the armed path for the tower to load. Here the mode
    is set on the fd before any bytes are written, and the destination only ever appears as the
    complete, fsynced file (or not at all).
    """
    parent = dest.parent
    parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=parent, prefix=f".{dest.name}.", suffix=".tmp")
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, payload)
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.replace(tmp_path, dest)
    except Exception:
        if fd != -1:
            try:
                os.close(fd)
            except OSError:  # best-effort cleanup; the original exception is re-raised below
                pass
        try:
            os.unlink(tmp_path)
        except OSError:  # best-effort cleanup; the original exception is re-raised below
            pass
        raise


def _read_privkey(path: str) -> bytes:
    """Load the 32-byte hex refund key from an owner-only file.

    Gated by :func:`read_secret_file` — the same 0600 + owner + no-symlink check the tower
    applies to the (far lower-value) webhook secret. This file holds a PRIVATE KEY; reading it
    with no mode check at all while refusing a group-readable webhook secret was backwards.
    """
    raw = read_secret_file(path, label="--refund-key-file").strip().removeprefix("0x")
    try:
        key = bytes.fromhex(raw)
    except ValueError as exc:
        raise ValidationError("--refund-key-file must contain a 32-byte hex private key") from exc
    if len(key) != 32:
        raise ValidationError("--refund-key-file must contain a 32-byte hex private key")
    return key


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Pre-sign a BTC HTLC refund for the autonomous watchtower")
    p.add_argument("--record", required=True, help="path to the SwapRecord JSON (its stem is the swap_id)")
    p.add_argument("--refund-key-file", required=True, help="file containing your 32-byte hex refund private key")
    p.add_argument(
        "--to-scriptpubkey", required=True, help="hex scriptPubKey of YOUR refund address (== the tower's --refund-spk)"
    )
    p.add_argument("--fee-sats", type=int, required=True, help="absolute fee baked into the (unbumpable) refund tx")
    p.add_argument("--out-dir", help="where to write <swap_id>.refund.json (default: the record's dir)")
    args = p.parse_args(argv)
    # Package code raises typed errors; this shell is the ONE place they become an exit code
    # (1 — the same code the bare `raise SystemExit("...")` produced), so an embedding
    # application that imports presign_refund()/_read_privkey() gets a catchable exception
    # instead of a killed process.
    try:
        return _run(args)
    except RxdSdkError as exc:
        print(str(exc), file=sys.stderr)
        return 1


def _run(args: argparse.Namespace) -> int:
    try:
        spk = bytes.fromhex(args.to_scriptpubkey.removeprefix("0x"))
    except ValueError as exc:
        raise ValidationError("--to-scriptpubkey must be hex") from exc
    dest = presign_refund(
        record_path=args.record,
        refund_privkey=_read_privkey(args.refund_key_file),
        to_scriptpubkey=spk,
        fee_sats=args.fee_sats,
        out_dir=args.out_dir,
    )
    blob = PresignedRefund.from_dict(json.loads(Path(dest).read_text()))
    print(f"wrote {dest}")
    print(f"  swap_id : {blob.swap_id}")
    print(f"  refund txid: {blob.txid}")
    print(f"  value   : {blob.output_value_sats} sats → {args.to_scriptpubkey}")
    print("ARM the tower with:  --refund-spk", args.to_scriptpubkey, "--refund-blobs-dir", Path(dest).parent)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
