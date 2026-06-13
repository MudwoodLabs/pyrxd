"""Shared helpers for the dust-swap ops scripts (NOT a shipped library module).

Imported by ``dust_swap_run.py`` (forward runner) and ``dust_swap_resume.py``
(crash-recovery runner). Both scripts must agree on the same object graph (the
forward writes the keys file; the resume reads it and rebuilds the SAME
coordinator), so the helpers used to build that graph live here rather than being
duplicated in each script. Extracting them was an architecture-review finding on
cbd5fc0 — the duplication had already caused one drift bug (Bug 5: differing
``get_raw_tx`` semantics between the two scripts).

Underscore-prefixed module name signals "internal to ``scripts/``, do not import
from ``src/pyrxd/``" — the standing follow-up is a real Fulcrum/ElectrumX
RadiantChainIO client that replaces the ssh shim altogether.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import math
import os
import struct
import time
from pathlib import Path

from pyrxd.gravity.swap_coordinator import measure_margin_from_btc_block_times
from pyrxd.network.bitcoin import MempoolSpaceSource

_MAINNET_BTC_API = "https://mempool.space/api"

# HTTP request timeout for mempool.space — caps the worst-case stall on any single call
# so a hostile/flaky endpoint can't push wall-clock far past the resume_deadline check.
# Tuned conservatively: each call is a few KB at most, 30s is enough headroom even on a
# slow link. Without this, aiohttp's default 5-min per-request timeout would let a single
# stuck request blow through the deadline by minutes. (Red-team finding NEW #7 on 44707a3.)
HTTP_REQUEST_TIMEOUT_S = 30.0


# ---------------------------------------------------------------------------
# Helper classes (the coordinator object graph)
# ---------------------------------------------------------------------------


class CapturingBroadcaster:
    """Wraps a ``BtcBroadcaster``, recording the last raw tx broadcast.

    The coordinator's ``maker_claims_btc`` broadcasts the claim but returns no bytes,
    and the taker must read the claim off-chain to scrape ``p``. Capturing the last
    raw here lets the harness derive the claim txid locally (``btc_txid_from_raw``)
    and fetch the on-chain copy, without trusting any out-of-band txid.

    ``last_raw`` is assigned AFTER the await succeeds — a transport failure must not
    leave stale bytes that the downstream guard mistakes for a successful broadcast
    (review of cbd5fc0).
    """

    def __init__(self, inner) -> None:
        self._inner = inner
        self.last_raw: bytes | None = None

    async def broadcast(self, raw_tx: bytes) -> str:
        txid = await self._inner.broadcast(raw_tx)
        self.last_raw = bytes(raw_tx)
        return txid


class InMemSeen:
    """In-memory ``SeenStore`` for the coordinator (single-process, NON-durable).

    ``reserve(H)`` is the authoritative atomic test-and-set the coordinator calls
    pre-broadcast; ``has_seen`` is the gate's read-only advisory probe. Durable
    replay-defence belongs to a SQLite-backed store (``durable = True``) in
    production; the dust runner is single-process, single-shot and mints a fresh H
    per run, and crashes are recovered by re-broadcasting the same txs (idempotent),
    so an in-memory set is sufficient HERE — but the coordinator's construct-time
    guard requires the operator to pass ``accept_nondurable_seen=True`` to use it on
    a value-bearing network, which the dust scripts do consciously.
    """

    durable = False

    def __init__(self) -> None:
        self._s: set[bytes] = set()

    def reserve(self, hsh: bytes) -> bool:
        # Atomic on the single-threaded loop: no await between the test and the add.
        h = bytes(hsh)
        if h in self._s:
            return False
        self._s.add(h)
        return True

    def has_seen(self, hsh: bytes) -> bool:
        return bytes(hsh) in self._s

    def mark_seen(self, hsh: bytes) -> None:
        self._s.add(bytes(hsh))


class SshTrFeeSource:
    """``FeeSource`` that carves a plain-RXD fee UTXO via the ssh-tr wallet.

    ``next_fee_input(amount_photons)`` is the surface the ``RadiantCovenantLeg``
    drives; the carve helper on ``SshTrRadiantClient`` handles the listunspent /
    sign / broadcast over ssh.
    """

    def __init__(self, client, fee_amount_photons: int) -> None:
        self._client = client
        self._amount = fee_amount_photons

    def next_fee_input(self):
        return self._client.carve_fee_input(self._amount)


# ---------------------------------------------------------------------------
# I/O helpers (operator + chain state + atomic disk writes)
# ---------------------------------------------------------------------------


def confirm(prompt: str, *, auto_yes: bool) -> None:
    """Block on operator confirmation before an irreversible broadcast.

    Called before EACH broadcast — approval never carries to the next. ``--yes``
    bypasses this for unattended scripted runs; the operator is responsible for
    knowing what they signed up for in that mode.
    """
    print(f"\n  >>> IRREVERSIBLE: {prompt}")
    if auto_yes:
        print("  >>> (--yes) proceeding")
        return
    if input("  >>> type 'broadcast' to proceed, anything else ABORTS: ").strip() != "broadcast":
        raise SystemExit("operator aborted before broadcast")


def atomic_write_mode_600(path: Path, content: str) -> None:
    """Write ``content`` to ``path`` atomically at mode ``0o600``.

    ``Path.write_text`` + ``chmod`` is non-atomic — the file existed at umask-default
    mode (typically ``0o664`` on multi-user boxes) for microseconds. A same-group
    daemon (plex, clamav, any backup walker) with inotify could read every key
    during that window. ``O_CREAT|O_EXCL`` with explicit mode at ``open()`` avoids
    the race and also rejects a pre-placed symlink (red-team review of cbd5fc0).
    """
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
    except Exception:
        # Best-effort cleanup of a half-written file — re-raise the original error.
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        raise


def validated_resume_deadline_s(
    *,
    operator_value: float | None,
    t_rxd_blocks: int,
    rxd_block_interval_s: float,
    safety_factor: float = 0.5,
    floor_s: float = 600.0,
) -> float:
    """Return a safe deadline (seconds) for the post-claim WAIT loop.

    The deadline exists so a hostile or flaky chain reader can't stall the loop past
    ``t_rxd`` (after which the maker can refund the asset and the taker has forfeited).
    Best-practice bound is ``safety_factor × t_rxd_seconds`` — past that, the operator
    has already lost on every counterparty-honest analysis.

    * Rejects ``inf`` / ``nan`` / ``<= 0`` (footgun: ``--resume-deadline-s inf`` re-opens
      the unbounded-loop attack the deadline was meant to close).
    * Caps any operator-supplied value at ``safety_factor × t_rxd × interval`` to keep
      the operator from accidentally setting a deadline LONGER than t_rxd.
    * Floor at ``floor_s`` so a tiny ``t_rxd`` (test config) still gets a sane minimum.

    Found by sec-sentinel + red-team review of 44707a3 (the prior default 4h exceeded
    the default ~1.67h t_rxd — bound was strictly above the window it was meant to fit
    inside).
    """
    t_rxd_seconds = float(t_rxd_blocks) * float(rxd_block_interval_s)
    upper_bound = max(safety_factor * t_rxd_seconds, floor_s)
    if operator_value is None:
        return upper_bound
    if not math.isfinite(operator_value) or operator_value <= 0:
        raise SystemExit(f"--resume-deadline-s must be a finite positive number, got {operator_value!r}")
    if operator_value > upper_bound:
        print(
            f"  WARN: --resume-deadline-s={operator_value:.0f}s exceeds the safe "
            f"upper bound ({upper_bound:.0f}s = {safety_factor:.1f} × t_rxd of "
            f"{t_rxd_seconds:.0f}s). Capping to the upper bound to keep the deadline "
            "INSIDE the t_rxd window."
        )
        return upper_bound
    return operator_value


def rxd_blockcount(client) -> int:
    """``getblockcount`` over the ssh-tr shim, normalised to ``int``.

    Replaces the prior ``int(json.loads(json.dumps(_run_sync("getblockcount"))))``
    triple-round-trip (the shim's ``_run_sync`` already returns the parsed JSON;
    on success that's an int). Fail-closed if the node returns anything else —
    catches transport mangling that would otherwise be silently truncated.
    """
    res = client._run_sync("getblockcount")
    if not isinstance(res, int):
        raise RuntimeError(f"getblockcount returned non-int: {res!r}")
    return res


# ---------------------------------------------------------------------------
# Measured margin (mainnet BTC header timestamps -> MarginPolicy)
# ---------------------------------------------------------------------------


async def measured_margin_from_mainnet(args: argparse.Namespace):
    """Read recent MAINNET BTC header timestamps and build a measured ``MarginPolicy``.

    Timing always comes from MAINNET BTC data regardless of stage — signet header
    intervals are not representative. Returns the same ``(policy, provenance)``
    tuple the forward runner and resume both consume.
    """
    src = MempoolSpaceSource(base_url=_MAINNET_BTC_API)
    try:
        tip = int(await src.get_tip_height())
        timestamps: list[int] = []
        for h in range(tip - args.margin_sample_blocks + 1, tip + 1):
            header = await src.get_block_header_hex(h)  # type: ignore[arg-type]
            # BTC block header time = bytes[68:72] little-endian uint32.
            timestamps.append(struct.unpack("<I", header[68:72])[0])
    finally:
        await src.close()
    return measure_margin_from_btc_block_times(
        btc_block_timestamps=timestamps,
        btc_tail_percentile=args.btc_tail_percentile,
        btc_claim_reorg_depth_blocks=args.btc_claim_reorg_depth,
        rxd_claim_burial_blocks=args.rxd_claim_burial,
        rxd_block_interval_s=args.rxd_block_interval_s,
        # This is a DUST harness (gated on --i-accept-dust-loss): the value is below the Radiant
        # reorg cost, so opt out of value-scaled burial. A real-value run must NOT use this path.
        accept_flat_burial=True,
    )


# ---------------------------------------------------------------------------
# Step report (provenance journal, never logs the preimage)
# ---------------------------------------------------------------------------


class StepReport:
    """Append-only provenance report -> JSON. NEVER records the preimage ``p``."""

    def __init__(self, stage: str, margin_provenance: dict) -> None:
        self._t0 = time.monotonic()
        self.doc: dict = {
            "stage": stage,
            "started_unix": int(time.time()),
            "margin_provenance": margin_provenance,
            "steps": [],
        }

    def step(self, *, name: str, chain: str, **fields) -> None:
        entry = {"step": name, "chain": chain, "wall_clock_s": round(time.monotonic() - self._t0, 1), **fields}
        self.doc["steps"].append(entry)
        print(f"  [report] {json.dumps(entry)}")

    def dump(self, path: str) -> None:
        """Write the report at mode 0o600.

        The report contains the BTC funding txid, HTLC address, measured margin policy,
        and step timings — enough to link operator identity to a real on-chain HTLC
        (red-team finding NEW #2 on 44707a3). The keys file is already mode-600; the
        report living alongside at default umask was an inconsistency. Replaces the
        file if it exists (unlike the keys file's O_EXCL guard — reports are operator
        artifacts that may be rewritten across runs).
        """
        p = Path(path).expanduser()
        try:
            p.unlink()
        except FileNotFoundError:
            pass
        atomic_write_mode_600(p, json.dumps(self.doc, indent=2))
        print(f"\nReport -> {p}")


__all__ = [
    "HTTP_REQUEST_TIMEOUT_S",
    "CapturingBroadcaster",
    "InMemSeen",
    "SshTrFeeSource",
    "StepReport",
    "atomic_write_mode_600",
    "confirm",
    "measured_margin_from_mainnet",
    "rxd_blockcount",
    "validated_resume_deadline_s",
]


# Pre-emptive asyncio guard — silence the noisy import-time warning on Python 3.13+
# when this module is imported but never await'd. Cheap, removes nothing.
_ = asyncio
