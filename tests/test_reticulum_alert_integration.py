"""``ReticulumAlertChannel`` over a real Reticulum stack — no radio required.

Opt-in: ``@pytest.mark.integration`` + the ``reticulum`` extra. Never runs in the default
suite (``-m 'not integration'``), and skips cleanly when ``rns`` is absent.

**What this proves, and what it does not.** Two Reticulum instances talk over a
``TCPServerInterface``/``TCPClientInterface`` pair on localhost. That exercises the whole
production path — announce, identity recall, encryption to a SINGLE destination, the
465-byte wire budget, and ``RnsTransport`` itself — with nothing mocked below the channel.

It does **not** prove the thing the channel exists for. Reticulum tunnelled over TCP fails
exactly when IP fails, which is the outage the alert path is meant to survive. A green run
here means "the plumbing is real"; it does not mean a page would arrive with the WAN
unplugged. That claim needs a LoRa or serial interface and is deliberately not asserted.

The two-process shape is not incidental: a SINGLE destination is addressed by hash but
encrypted to a public key learned from an announce, so a sender must genuinely receive the
receiver's announce before it can encrypt anything. One process sharing an identity would
skip the step most likely to break in the field.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

pytest.importorskip("RNS", reason="needs the reticulum extra: pip install 'pyrxd[reticulum]'")

from pyrxd.gravity.watch.adapters import ReticulumAlertChannel, RnsTransport
from pyrxd.gravity.watch.alerts import Page, Severity
from pyrxd.gravity.watch.decide import Intent

pytestmark = pytest.mark.integration

#: Localhost only, and a high port so a stray run cannot collide with anything real.
_PORT = 37428

_RECEIVER = textwrap.dedent(
    """
    import sys, time, RNS
    cfg, idfile = sys.argv[1], sys.argv[2]
    RNS.Reticulum(cfg)
    rx = RNS.Destination(RNS.Identity(), RNS.Destination.IN, RNS.Destination.SINGLE,
                         "pyrxd", "watchtower", "alert")
    open(idfile, "w").write(RNS.hexrep(rx.hash, delimit=False))
    rx.set_packet_callback(lambda data, packet: print("RECEIVED " + data.decode(), flush=True))
    for _ in range(60):
        rx.announce()
        time.sleep(1.0)
    """
)


def _write_config(path: Path, body: str) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    (path / "config").write_text(textwrap.dedent(body))
    return path


@pytest.fixture
def reticulum_pair(tmp_path):
    """A receiver process on a TCP server interface, and a config for a client to reach it."""
    rx_cfg = _write_config(
        tmp_path / "rx",
        f"""
        [reticulum]
          enable_transport = Yes
          share_instance = No
        [logging]
          loglevel = 3
        [interfaces]
          [[TCP Server]]
            type = TCPServerInterface
            enabled = Yes
            listen_ip = 127.0.0.1
            listen_port = {_PORT}
        """,
    )
    tx_cfg = _write_config(
        tmp_path / "tx",
        f"""
        [reticulum]
          enable_transport = No
          share_instance = No
        [logging]
          loglevel = 3
        [interfaces]
          [[TCP Client]]
            type = TCPClientInterface
            enabled = Yes
            target_host = 127.0.0.1
            target_port = {_PORT}
        """,
    )
    script = tmp_path / "receiver.py"
    script.write_text(_RECEIVER)
    dest_file = tmp_path / "dest.hex"
    log = (tmp_path / "rx.log").open("w")

    proc = subprocess.Popen(
        [sys.executable, str(script), str(rx_cfg), str(dest_file)],
        stdout=log,
        stderr=subprocess.STDOUT,
    )
    try:
        for _ in range(40):
            if dest_file.exists() and dest_file.read_text().strip():
                break
            time.sleep(0.5)
        else:
            pytest.fail("receiver never published a destination hash")
        yield dest_file.read_text().strip(), tx_cfg, tmp_path / "rx.log"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:  # pragma: no cover - defensive
            proc.kill()
        log.close()


@pytest.mark.skipif(os.environ.get("PYRXD_RETICULUM_E2E") != "1", reason="set PYRXD_RETICULUM_E2E=1")
def test_a_page_arrives_over_a_real_reticulum_link(reticulum_pair):
    dest_hex, tx_cfg, rx_log = reticulum_pair
    import RNS

    transport = RnsTransport(config_path=str(tx_cfg))

    # A SINGLE destination is encrypted to a key that arrives in an announce. Wait for it
    # rather than assuming — this is the step a one-process test would skip.
    for _ in range(45):
        if RNS.Identity.recall(bytes.fromhex(dest_hex)) is not None:
            break
        time.sleep(1.0)
    assert RNS.Identity.recall(bytes.fromhex(dest_hex)) is not None, "no announce reached the sender"

    channel = ReticulumAlertChannel(dest_hex, transport=transport)
    page = Page(
        swap_id="swap-2026-08-21-btc-rxd-0007",
        intent=Intent.PAGE_CLAIM,
        severity=Severity.CRITICAL,
        message="BTC HTLC claim is live; refund window opens at RXD height 172",
        recommended_action="taker_scrape_and_claim_asset",
        deadline_rxd_height=172,
        low_corroboration=False,
    )
    assert len(channel.encode(page)) <= 465
    asyncio.run(channel.send(page))

    for _ in range(20):
        if "RECEIVED " in rx_log.read_text():
            break
        time.sleep(0.5)
    body = rx_log.read_text()
    assert "RECEIVED " in body, f"the page never arrived; receiver log:\n{body[-2000:]}"

    decoded = json.loads(body.split("RECEIVED ", 1)[1].splitlines()[0])
    assert decoded["s"] == "swap-2026-08-21-btc-rxd-0007"
    assert decoded["v"] == "critical"
    assert decoded["d"] == 172, "the deadline must survive the wire — it is the actionable field"
    assert decoded["a"] == "taker_scrape_and_claim_asset"


@pytest.mark.skipif(os.environ.get("PYRXD_RETICULUM_E2E") != "1", reason="set PYRXD_RETICULUM_E2E=1")
def test_sending_to_an_unannounced_destination_raises_rather_than_silently_dropping(reticulum_pair):
    """A destination whose announce we have never seen cannot be encrypted to.

    That is an ordinary condition — a fresh instance, or a partitioned mesh — and the
    channel must raise so ``DedupAlerter`` retries once the announce lands, rather than
    reporting a page as delivered that was never encrypted.
    """
    from pyrxd.security.errors import NetworkError

    _dest_hex, tx_cfg, _log = reticulum_pair
    transport = RnsTransport(config_path=str(tx_cfg))
    never_announced = "00" * 16

    channel = ReticulumAlertChannel(never_announced, transport=transport)
    with pytest.raises(NetworkError, match="announce"):
        asyncio.run(channel.send(_page_for_unknown()))


def _page_for_unknown() -> Page:
    return Page(
        swap_id="swap-unknown",
        intent=Intent.PAGE_CLAIM,
        severity=Severity.CRITICAL,
        message="unreachable",
        recommended_action="taker_scrape_and_claim_asset",
        deadline_rxd_height=1,
        low_corroboration=False,
    )


@pytest.mark.skipif(os.environ.get("PYRXD_RETICULUM_E2E") != "1", reason="set PYRXD_RETICULUM_E2E=1")
def test_a_page_crosses_a_non_ip_link_with_networking_severed(tmp_path):
    """The claim the whole channel exists for: a page arrives when IP does not work.

    The TCP test above proves the plumbing and nothing more — Reticulum tunnelled over TCP
    fails exactly when TCP fails, which is the outage being defended against. This runs the
    same production path inside `unshare -rn`, where the only interface is a DOWN loopback:
    no internet, no localhost. The two Reticulum instances talk over a virtual serial pair
    (kernel ptys, cross-wired by a pump thread), so the bytes never touch the network stack.

    A real RNode is a serial device too, driven by the same `SerialInterface`. What remains
    untested after this is the physical layer — the radio itself — not the software path.

    The probe asserts its own premise first and refuses to run if localhost is reachable,
    because a green result from a namespace that quietly had networking would be worse than
    no test at all.
    """
    if shutil.which("unshare") is None:
        pytest.skip("needs unshare(1) to sever networking")
    probe = Path(__file__).parent / "support" / "reticulum_noip_probe.py"
    assert probe.is_file(), probe

    env = {**os.environ, "PYRXD_NOIP_WORKDIR": str(tmp_path / "noip")}
    proc = subprocess.run(
        ["unshare", "-rn", sys.executable, str(probe)],
        capture_output=True,
        text=True,
        timeout=300,
        env=env,
    )
    if proc.returncode == 2:
        pytest.skip(f"namespace still had connectivity: {proc.stdout.strip()}")
    assert proc.returncode == 0, f"probe failed:\n{proc.stdout[-3000:]}\n{proc.stderr[-2000:]}"
    assert "no IP connectivity" in proc.stdout, "the probe did not verify its own premise"
    assert "PAGE ARRIVED OVER A NON-IP LINK" in proc.stdout, proc.stdout[-2000:]
    assert "deadline=172" in proc.stdout, "the actionable field did not survive the link"
