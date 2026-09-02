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
import hashlib
import json
import math
import os
import stat
import struct
import tempfile
import time
from pathlib import Path
from typing import Any

from pyrxd.gravity.swap_coordinator import measure_margin_from_btc_block_times
from pyrxd.network.bitcoin import MempoolSpaceSource
from pyrxd.security.units import ChainHeight

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

    def __init__(self, inner: Any) -> None:
        self._inner = inner
        self.last_raw: bytes | None = None

    async def broadcast(self, raw_tx: bytes) -> str:
        txid = await self._inner.broadcast(raw_tx)
        self.last_raw = bytes(raw_tx)
        return str(txid)


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

    def __init__(self, client: Any, fee_amount_photons: int) -> None:
        self._client = client
        self._amount = fee_amount_photons

    def next_fee_input(self) -> Any:
        return self._client.carve_fee_input(self._amount)


# ---------------------------------------------------------------------------
# I/O helpers (operator + chain state + atomic disk writes)
# ---------------------------------------------------------------------------


def read_own_private_file(path: Path, *, what: str, limit: int = 1 << 20) -> str:
    """Read a file this user owns, following no symlink and trusting no other account.

    OPEN FIRST, then fstat THAT descriptor. `path.stat()` followed by `path.read_text()` checks one
    file and reads another: between the two calls the path can be replaced, so a permissive file
    passes the check while a different one supplies the contents.

    O_NOFOLLOW refuses a symlink standing in for the file. O_NONBLOCK stops a FIFO from HANGING the
    open before fstat can reject it — an operator who mistypes a path should get a message, not an
    indefinite wait — and is a no-op for the regular files this accepts. The uid check refuses a
    file another account can rewrite, and the mode check refuses one other accounts can read.

    ``what`` names the stake in the refusal, because "permission denied" does not tell an operator
    mid-swap why the run stopped.
    """
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as exc:
        raise SystemExit(f"cannot open {path}: {exc}") from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise SystemExit(f"{path} is not a regular file; refusing to read {what} from it")
        if st.st_uid != os.getuid():
            raise SystemExit(
                f"{path} is owned by uid {st.st_uid}, not you ({os.getuid()}). Refusing: it holds "
                f"{what}, and a file another account can rewrite is not a file you control."
            )
        if st.st_mode & 0o077:
            raise SystemExit(
                f"{path} is mode {oct(st.st_mode & 0o777)}: readable by other users, and it holds {what}. chmod 600 it."
            )
        return os.read(fd, limit).decode()
    finally:
        os.close(fd)


def resolve_eth_key_file(args: argparse.Namespace) -> None:
    """Fold ``--eth-key-file`` into ``args.eth_key_hex`` so downstream code is unchanged.

    A secret on argv is readable by every local user for as long as the process runs, and it
    persists in shell history afterwards. A PATH on argv is not a secret.

    Shared rather than reimplemented per runner: the file flag existed on exactly one script and
    every document still showed `--eth-key-hex`, so the safer option had no callers and the whole
    documented two-host flow — the two-party run — put a live key on the command line.
    """
    if not getattr(args, "eth_key_file", ""):
        return
    if getattr(args, "eth_key_hex", ""):
        raise SystemExit("pass --eth-key-file OR --eth-key-hex, not both")
    raw = read_own_private_file(Path(args.eth_key_file).expanduser(), what="an ETH signing key", limit=4096).strip()
    args.eth_key_hex = _validated_eth_key_hex(raw, source=args.eth_key_file)


def _validated_eth_key_hex(raw: str, *, source: str) -> str:
    """Normalise and check the key HERE, not several hundred lines into the run.

    A `0x` prefix is how every EVM tool prints a key, so a file containing one is honest input and
    accepting it is the point — refusing it would be a guard rejecting valid work. What must not
    happen is discovering the problem late: the length check used to live deep inside the run, past
    the point where an NFT variant has already MINTED on RXD mainnet, so a mistyped key cost a real
    transaction before anything complained.

    Deliberately says nothing about the contents of the file beyond its length and alphabet.
    """
    key = raw[2:] if raw[:2].lower() == "0x" else raw
    if len(key) != 64 or any(c not in "0123456789abcdefABCDEF" for c in key):
        raise SystemExit(
            f"{source} does not contain a 32-byte hex key: got {len(key)} hex characters after "
            f"stripping any 0x prefix, expected 64. Refusing now, before the run spends anything."
        )
    return key


def add_eth_key_arguments(ap: argparse.ArgumentParser) -> None:
    """The key flags, defined once so every ETH runner offers the same safer option."""
    ap.add_argument(
        "--eth-key-hex",
        default="",
        help="Signing key as hex ON THE COMMAND LINE — visible in `ps` and in shell history. "
        "Prefer --eth-key-file. Kept for compatibility and for throwaway keys.",
    )
    ap.add_argument(
        "--eth-key-file",
        default="",
        help="Path to a mode-600 file containing the signing key as hex. Preferred over "
        "--eth-key-hex: a path on argv is not a secret.",
    )


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


def merge_into_mode_600(path: Path, extra: dict[str, Any]) -> None:
    """Merge ``extra`` into an existing mode-0600 JSON file, atomically.

    :func:`atomic_write_mode_600` is ``O_EXCL`` (create-only) by design, so it cannot
    update a file that already exists. This is the update peer: write the merged
    document to a fresh 0600 temp file in the SAME directory, fsync it, then
    ``os.replace`` — a rename within one filesystem, so a reader only ever sees the old
    document or the new one, never a truncated one.

    Why it exists: the recovery file is written BEFORE funding (so a crash mid-run
    cannot strand value), which means the locators that only exist afterwards — the BTC
    HTLC funding outpoint, the deployed ETH contract address — were printed to the
    console and then lost. Both are required by ``pyrxd swap recover-preimage`` /
    ``build-claim`` to prove a claim belongs to THIS swap, and an operator recovering
    from a crash does not have the console any more.
    """
    doc = json.loads(path.read_text())
    doc.update(extra)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=path.name + ".", suffix=".tmp")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(json.dumps(doc, indent=2))
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, str(path))
    except Exception:
        try:
            os.unlink(tmp)
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


def rxd_blockcount(client: Any) -> ChainHeight:
    """``getblockcount`` over the ssh-tr shim, normalised to ``int``.

    Replaces the prior ``int(json.loads(json.dumps(_run_sync("getblockcount"))))``
    triple-round-trip (the shim's ``_run_sync`` already returns the parsed JSON;
    on success that's an int). Fail-closed if the node returns anything else —
    catches transport mangling that would otherwise be silently truncated.
    """
    res = client._run_sync("getblockcount")
    if not isinstance(res, int):
        raise RuntimeError(f"getblockcount returned non-int: {res!r}")
    # getblockcount is the TIP HEIGHT, not a depth. Tagged here, at the one place the number
    # enters the runner, so it can be compared against a covenant fund height and never
    # against a confirmation count.
    return ChainHeight(res)


# ---------------------------------------------------------------------------
# Measured margin (mainnet BTC header timestamps -> MarginPolicy)
# ---------------------------------------------------------------------------


async def measured_margin_from_mainnet(args: argparse.Namespace) -> Any:
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

    def __init__(self, stage: str, margin_provenance: dict[str, Any]) -> None:
        self._t0 = time.monotonic()
        self.doc: dict[str, Any] = {
            "stage": stage,
            "started_unix": int(time.time()),
            "margin_provenance": margin_provenance,
            "steps": [],
        }

    def step(self, *, name: str, chain: str, **fields: Any) -> None:
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


async def wait_for_covenant_funding(
    client: Any, *, covenant_spk: bytes, expected_photons: int, poll_s: float = 30.0
) -> Any:
    """Block until the covenant SPK actually holds a confirmed UTXO of the pinned amount.

    This replaces an operator ATTESTATION that appeared in every runner — a confirm() reading
    "you have funded the RXD covenant SPK on mainnet and it has >= 1 conf".

    There are two kinds of prompt in these scripts and they were sharing one flag. An
    AUTHORISATION ("I am about to broadcast X, proceed?") is exactly what --yes is for: the
    operator pre-authorised an unattended run. An ATTESTATION asks the operator to certify an
    external fact, and under --yes it does not skip the question, it FABRICATES the answer — the
    run then proceeds asserting something nobody checked.

    A question whose answer is on the chain should be asked of the chain.
    """
    client.register_spk(covenant_spk)
    script_hash = hashlib.sha256(bytes(covenant_spk)).digest()[::-1]
    print(f"\n  Fund the RXD covenant SPK as the maker ({expected_photons} photons):")
    print(f"    {covenant_spk.hex()}")
    print("  waiting for it to appear on chain (this run does NOT proceed until it does)...")
    while True:
        utxos = await client.get_utxos(script_hash)
        for u in utxos or []:
            # height 0 means unconfirmed. The prompt this replaces said ">= 1 conf", and the reorg
            # gate downstream assumes a mined covenant, so require it here rather than racing it.
            if int(u.value) == int(expected_photons) and int(getattr(u, "height", 0)) > 0:
                print(f"  covenant funded: {u.tx_hash}:{u.tx_pos} ({u.value} photons, height {u.height})")
                return u
        if utxos:
            # Present but wrong value: say so rather than waiting silently forever. The covenant
            # pins its amount, so a mis-funded UTXO is not one this swap can ever use.
            print(
                f"  SPK holds {[(int(u.value), int(getattr(u, 'height', 0))) for u in utxos]} "
                f"(photons, height) — need exactly {expected_photons} at height > 0"
            )
        await asyncio.sleep(poll_s)


def covenant_fund_height(height: ChainHeight) -> ChainHeight:
    """THE one place a covenant funding output's on-chain height becomes the reorg gate's anchor.

    UNITS, stated once so no call site has to restate them: this takes a TRUE BLOCK HEIGHT — the
    meaning ``UtxoRecord.height`` and ``find_covenant_utxo``'s third element have always promised
    and, since the shim fix, actually carry. It was not always so. ``radiant_mainnet_chainio``'s
    ``get_utxos`` used to read the real height out of ``scantxoutset`` and then overwrite it with
    ``tip - height + 1``, a CONFIRMATION COUNT, so every ``scripts/`` caller on the mainnet shim
    was handed a depth in a field named for a height. Code that compensated for that
    (``fund_height = tip - confs + 1``) is now the bug rather than the fix: a conf count is no
    longer representable here, so there is nothing left to compensate for, and a leftover
    compensation would put the anchor a full chain-length in the past.

    That units contract is now the CHECKER's, not just the docstring's: the parameter is a
    :data:`~pyrxd.security.units.ChainHeight`, so handing this a
    :data:`~pyrxd.security.units.Confirmations` — or the ``tip - confs + 1`` compensation that
    became an inversion once the producer was fixed — does not type-check.

    ``height == 0`` still means UNCONFIRMED, under both conventions — the one thing the change did
    not touch. Fail closed on it: an unconfirmed covenant has no fund height, and inventing one
    hands the coordinator's F-013 anchor check an impossible value much further downstream, where
    it is far harder to read.
    """
    if not isinstance(height, int) or isinstance(height, bool):
        raise RuntimeError(f"covenant fund height must be an int block height, got {height!r} (fail-closed)")
    if height < 1:
        raise RuntimeError(
            f"covenant UTXO reports height {height} — unconfirmed, so it has no fund height for the "
            "reorg gate to anchor on (fail-closed)"
        )
    return height


async def scan_covenant_fund_height(client: Any, *, covenant_spk: bytes, expected_photons: int) -> ChainHeight:
    """The anchor for paths that locked the asset WITHOUT :func:`wait_for_covenant_funding` — the
    NFT and FT variants, which lock by SPENDING into the covenant rather than by waiting on an
    operator payment. Same conversion, same fail-closed rules, one scan.

    NOT the tip, and that is the bug this exists to close. Both runners read the tip BEFORE
    blocking on the asset lock, so the anchor was low by however long the lock took — minutes to
    hours. The comment defending it said a low value "can only make the reorg-gate squeeze MORE
    cautious, never less". True of the gate, false of the runner:
    ``blocks_left = asset_locked_at_height + t_rxd - now``, so a low anchor shortens the window and
    returns SQUEEZED, whose handler is ``taker_claim_asset_from_vulnerable`` — winner-take-all by
    design, with no ``assess_claim_finality`` call anywhere inside it, and unattended under
    ``--yes``. A more cautious gate produces a LESS gated broadcast.
    """
    register = getattr(client, "register_spk", None)
    if callable(register):
        register(bytes(covenant_spk))
    script_hash = hashlib.sha256(bytes(covenant_spk)).digest()[::-1]
    utxos = await client.get_utxos(script_hash)
    return covenant_fund_height(ChainHeight(int(getattr(_covenant_utxo(utxos, expected_photons), "height", 0))))


def _covenant_utxo(utxos: Any, expected_photons: int) -> Any:
    """The covenant's funding UTXO — fail-closed on anything ambiguous.

    Matched on the PINNED amount, exactly as :func:`wait_for_covenant_funding` does: the covenant
    SPK is a pure function of public terms, so anyone can pay it, and a wrong-value output is not
    the one this swap locked.
    """
    matches = [u for u in utxos or [] if int(u.value) == int(expected_photons)]
    confirmed = [u for u in matches if int(getattr(u, "height", 0)) > 0]
    if not confirmed:
        raise RuntimeError(
            f"no CONFIRMED covenant UTXO of exactly {expected_photons} photons is on chain — cannot "
            f"derive the reorg gate's anchor height (fail-closed); saw {len(matches)} matching output(s)"
        )
    # A second payment of the same value is possible (anyone can pay the SPK). Take the EARLIEST-
    # mined, i.e. the LOWEST height: that is the one the maker's lock produced, and a decoy paid
    # later cannot push the anchor forward and slacken the gate. (Under the old confs-in-height
    # convention the same choice was `max`. Getting that flip wrong is exactly the unit bug the
    # named conversion above exists to make visible.)
    return min(confirmed, key=lambda u: int(getattr(u, "height", 0)))


async def resolve_asset_locked_at_height(
    rxd_leg: Any,
    *,
    covenant_spk: bytes,
    expected_photons: int,
    explicit: int,
    now_rxd_height: ChainHeight,
) -> ChainHeight:
    """The two-host taker's reorg-gate anchor: read off the chain unless the operator pinned it.

    ``--asset-locked-at-height`` was declared with ``default=0``, passed straight into
    ``taker_scrape_and_claim_asset``, and validated nowhere — while ``--taker-min-rxd-confs >= 1``
    was validated on the adjacent line. With anchor 0 the gate computes
    ``blocks_left = 0 + t_rxd - now``, hugely negative at any realistic tip, so it reads SQUEEZED
    on the FIRST assessment: the two-party adversarial run — the project's stated hard gate before
    real value — went SQUEEZED -> ASSET_VULNERABLE -> winner-take-all every time and never once
    exercised the finality wait it exists to prove.

    So 0 no longer means "height zero"; it means "ask the chain", and the honest value is what an
    operator who passes nothing now gets. The read re-derives nothing from the maker: the caller
    passes the SPK it derived from its OWN terms, and the value is pinned, so a covenant funded at
    the wrong amount is refused rather than anchored on.
    """
    if int(explicit) < 0:
        raise SystemExit(
            f"--asset-locked-at-height {explicit} is negative; it is a Radiant block height. Omit it "
            "to read the covenant's true fund height off the chain."
        )
    if int(explicit) > 0:
        # The operator's pinned value is a raw CLI int; re-tagging it here is the claim that it
        # is a height, and `covenant_fund_height` is the check that it is a usable one.
        anchor = covenant_fund_height(ChainHeight(int(explicit)))
        source = "pinned by --asset-locked-at-height"
    else:
        _outpoint, _value, height = await rxd_leg.chain_io.find_covenant_utxo(
            bytes(covenant_spk), expected_value=int(expected_photons)
        )
        anchor = covenant_fund_height(ChainHeight(int(height)))
        source = "read from the covenant's funding output on chain"
    if anchor > int(now_rxd_height):
        # The coordinator fails closed on now < locked_at (F-013) with a message about lying nodes.
        # Catching it here says which INPUT is wrong, before a claim decision depends on it.
        raise SystemExit(
            f"asset_locked_at_height {anchor} is above the current RXD tip {now_rxd_height} — a "
            f"covenant cannot have been mined in a block that does not exist yet ({source})."
        )
    print(f"  reorg-gate anchor: asset_locked_at_height = {anchor} ({source})")
    return anchor


async def wait_for_covenant_via_leg(
    leg: Any, *, covenant_spk: bytes, expected_photons: int, poll_s: float = 10.0
) -> Any:
    """Same contract as :func:`wait_for_covenant_funding`, driven through the RadiantCovenantLeg.

    The two-host scripts hold a leg rather than a raw client, and `find_covenant_utxo` is the
    PRODUCTION lookup the coordinator itself uses — including its fail-closed value match, so a
    mis-funded covenant is rejected here instead of surfacing later as a confusing gate refusal.
    """
    print(f"\n  Fund the RXD covenant SPK as the maker ({expected_photons} photons):")
    print(f"    {bytes(covenant_spk).hex()}")
    print("  waiting for it to appear on chain (this run does NOT proceed until it does)...")
    while True:
        try:
            outpoint, value, _height = await leg.find_covenant_utxo(
                bytes(covenant_spk), expected_value=int(expected_photons)
            )
            print(f"  covenant funded: {outpoint} ({value} photons)")
            return outpoint, value
        except Exception as exc:  # not funded yet, or funded with the wrong amount
            print(f"  not yet: {str(exc)[:110]}")
        await asyncio.sleep(poll_s)


#: RADIANT blocks of headroom the derived counter leg must survive.
#:
#: ``assert_timelock_margin`` is called from ``pre_btc_lock_check`` as
#: ``elapsed_blocks=cov_confs`` — the covenant's CONFIRMATION COUNT — and it does
#: ``rxd_blocks -= elapsed_blocks`` before judging. The taker refuses to fund BTC until the
#: covenant has confirmed, so ``cov_confs`` is NEVER 0 on a real run.
#:
#: A derivation that solves the gate's inequality to equality therefore produces terms the
#: production gate ALWAYS refuses — it passes only at ``elapsed=0``, which never occurs. That
#: shipped, and it was found by testing the derivation against the call the coordinator really
#: makes rather than against the one the unit tests make.
#:
#: 12 blocks is ~1 h at the 300 s nominal and ~44 min at the 222 s measured median: the covenant
#: confirming, the taker's depth floor, and the operational gap before it funds.
PRE_BTC_LOCK_ELAPSED_RESERVE_BLOCKS = 12


def elapsed_reserve_blocks(*, rxd_claim_burial_blocks: int) -> int:
    """The Radiant blocks to reserve, COUPLED to the depth the taker is made to wait.

    The flat constant above is not sufficient on its own, and shipping it alone was a defect in
    the fix that introduced it. ``pre_btc_lock_check`` step 5 refuses to fund the counter leg
    until the covenant is ``rxd_claim_burial`` deep, and step 7 then re-runs the margin gate with
    ``elapsed_blocks=cov_confs``. So the elapsed depth the gate sees is AT LEAST the burial. With
    a flat 12, any operator who measured a burial above 12 got their own runner refused at step 7,
    with a message about the maker's terms — pointing at the wrong knob entirely.

    Measured before this fix (t_rxd=180, margin=2, derived t_btc=82): burial 12 passed, burial 13
    and burial 20 were both refused as "insufficient margin in WALL CLOCK".

    The slack on top covers the operational gap between reaching the depth and the gate running.
    """
    if not isinstance(rxd_claim_burial_blocks, int) or isinstance(rxd_claim_burial_blocks, bool):
        raise SystemExit("rxd_claim_burial_blocks must be an int")
    if rxd_claim_burial_blocks < 0:
        raise SystemExit("rxd_claim_burial_blocks must be >= 0")
    return max(PRE_BTC_LOCK_ELAPSED_RESERVE_BLOCKS, rxd_claim_burial_blocks + _OPERATIONAL_SLACK_BLOCKS)


#: Radiant blocks between the covenant reaching its required depth and the gate actually running:
#: the taker noticing, building and broadcasting the counter leg.
_OPERATIONAL_SLACK_BLOCKS = 4


def derive_counter_timelock(
    *,
    t_rxd_blocks: int,
    margin_blocks: int,
    rxd_block_interval_s: float,
    btc_block_interval_s: float,
    elapsed_reserve_blocks: int,
    rxd_flag: str = "--t-rxd-blocks",
) -> int:
    """Derive ``t_btc`` (BITCOIN blocks) from ``t_rxd`` (RADIANT blocks), IN SECONDS.

    ONE DEFINITION, because there were three and they were all wrong the same way. Each runner
    computed ``t_btc = t_rxd - margin - 4``, subtracting a BITCOIN-block margin from a RADIANT-block
    count as though the two were the same unit. At the real rates (~600 s vs ~300 s) that yields a
    NEGATIVE wall-clock margin at every realistic parameter — the layout in which the maker refunds
    the leg it locked and still claims the other with ``p`` (#567).

    The gate this must satisfy is ``t_rxd * i_rxd >= t_btc * i_btc + margin * i_btc``. Solving for
    the largest safe ``t_btc``::

        t_btc = floor(((t_rxd - elapsed_reserve) * i_rxd) / i_btc) - margin

    At 600/300 that is ``t_rxd/2 - margin``, so a Radiant leg buys HALF as many Bitcoin blocks —
    which is the whole point the raw subtraction obscured.

    Raises ``SystemExit`` (an operator-facing message naming the flag) when no positive ``t_btc``
    exists. ``refund_leaf_script`` also refuses a zero-block leaf by construction, so this cannot be
    bypassed by a caller that forgets to check — but a message about "0 blocks" from deep inside a
    script builder does not tell an operator WHICH flag to change, and this does.
    """
    if rxd_block_interval_s <= 0 or btc_block_interval_s <= 0:
        raise SystemExit("block intervals must be positive to derive a counter-leg timelock")
    if not isinstance(elapsed_reserve_blocks, int) or isinstance(elapsed_reserve_blocks, bool):
        raise SystemExit("elapsed_reserve_blocks must be an int")
    if elapsed_reserve_blocks < 0:
        raise SystemExit("elapsed_reserve_blocks must be >= 0")
    # Derive against the WORST case the gate will judge, not the best. The gate subtracts the
    # covenant's confirmations from t_rxd, so reserving them here is what makes the produced
    # t_btc survive `elapsed` anywhere in [0, elapsed_reserve_blocks].
    budget_rxd_blocks = t_rxd_blocks - elapsed_reserve_blocks
    usable_btc_blocks = int((budget_rxd_blocks * rxd_block_interval_s) // btc_block_interval_s)
    t_btc_blocks = usable_btc_blocks - margin_blocks
    if t_btc_blocks < 1:
        # The smallest t_rxd that yields t_btc >= 1, inverted from the relation above.
        need = elapsed_reserve_blocks + int(
            -(-((margin_blocks + 1) * btc_block_interval_s) // rxd_block_interval_s)
        )
        raise SystemExit(
            f"{rxd_flag} {t_rxd_blocks} leaves no room for a counter leg: {t_rxd_blocks} Radiant "
            f"blocks is {t_rxd_blocks * rxd_block_interval_s / 3600:.2f} h, and the "
            f"{margin_blocks}-block margin alone is "
            f"{margin_blocks * btc_block_interval_s / 3600:.2f} h.\n"
            f"  raise {rxd_flag} to at least {need}, or lower --margin-blocks.\n"
            "  (t_btc is derived in WALL CLOCK since #567: a Radiant block is worth about half a "
            "Bitcoin block, so a Radiant leg buys half as many counter-leg blocks as its raw count "
            "suggests.)"
        )
    return t_btc_blocks
