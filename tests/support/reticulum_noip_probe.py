"""Prove a watchtower page crosses a NON-IP link with networking severed.

Run under `unshare -rn`, where the only interface is a DOWN loopback: no localhost, no
internet. Two Reticulum instances talk over a virtual serial pair, so the bytes traverse
kernel ptys rather than the network stack.

A real RNode is a serial device too, so this is the same code path a LoRa radio would take
— only the physical layer differs.
"""

from __future__ import annotations

import json
import os
import pty
import subprocess
import sys
import termios
import threading
import time
import tty
from pathlib import Path

HERE = Path(__file__).resolve().parent
WORK = Path(os.environ.get("PYRXD_NOIP_WORKDIR", HERE))


def _raw(fd: int) -> None:
    tty.setraw(fd)
    attrs = termios.tcgetattr(fd)
    attrs[3] &= ~termios.ECHO  # lflag
    termios.tcsetattr(fd, termios.TCSANOW, attrs)


def make_serial_pair() -> tuple[str, str, threading.Event]:
    """Two /dev/pts paths cross-wired by a pump thread — a null-modem cable in software."""
    m1, s1 = pty.openpty()
    m2, s2 = pty.openpty()
    for fd in (m1, s1, m2, s2):
        _raw(fd)
    stop = threading.Event()

    def pump(src: int, dst: int) -> None:
        while not stop.is_set():
            try:
                data = os.read(src, 4096)
            except OSError:
                return
            if not data:
                return
            try:
                os.write(dst, data)
            except OSError:
                return

    for a, b in ((m1, m2), (m2, m1)):
        threading.Thread(target=pump, args=(a, b), daemon=True).start()
    return os.ttyname(s1), os.ttyname(s2), stop


def write_config(path: Path, device: str, *, transport: bool) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    (path / "config").write_text(
        f"""[reticulum]
  enable_transport = {"Yes" if transport else "No"}
  share_instance = No
  panic_on_interface_error = No

[logging]
  loglevel = 3

[interfaces]
  [[Serial]]
    type = SerialInterface
    enabled = Yes
    port = {device}
    speed = 115200
    databits = 8
    parity = none
    stopbits = 1
"""
    )
    return path


RECEIVER = """
import sys, time, RNS
cfg, idfile = sys.argv[1], sys.argv[2]
RNS.Reticulum(cfg)
rx = RNS.Destination(RNS.Identity(), RNS.Destination.IN, RNS.Destination.SINGLE,
                     "pyrxd", "watchtower", "alert")
open(idfile, "w").write(RNS.hexrep(rx.hash, delimit=False))
rx.set_packet_callback(lambda data, packet: print("RECEIVED " + data.decode(), flush=True))
for _ in range(90):
    rx.announce()
    time.sleep(1.0)
"""


def main() -> int:
    import socket

    # Prove the premise before proving the claim: if IP works here, the test means nothing.
    s = socket.socket()
    s.settimeout(1.0)
    try:
        s.connect(("127.0.0.1", 37428))
        print("REFUSING: localhost is reachable — not running inside a severed namespace")
        return 2
    except OSError:
        print("premise: no IP connectivity (localhost unreachable)", flush=True)
    finally:
        s.close()

    dev_a, dev_b, _stop = make_serial_pair()
    print(f"serial pair: {dev_a} <-> {dev_b}", flush=True)

    rx_cfg = write_config(WORK / "rx", dev_a, transport=True)
    tx_cfg = write_config(WORK / "tx", dev_b, transport=False)
    WORK.mkdir(parents=True, exist_ok=True)
    script = WORK / "receiver.py"
    script.write_text(RECEIVER)
    dest_file = WORK / "dest.hex"
    dest_file.unlink(missing_ok=True)
    log_path = WORK / "rx.log"
    log = log_path.open("w")

    proc = subprocess.Popen(
        [sys.executable, str(script), str(rx_cfg), str(dest_file)], stdout=log, stderr=subprocess.STDOUT
    )
    try:
        for _ in range(40):
            if dest_file.exists() and dest_file.read_text().strip():
                break
            time.sleep(0.5)
        else:
            print("FAIL: receiver never published a destination")
            return 1
        dest_hex = dest_file.read_text().strip()
        print(f"receiver destination: {dest_hex}", flush=True)

        sys.path.insert(0, str(HERE.parents[2] / "src"))
        import RNS

        from pyrxd.gravity.watch.adapters import ReticulumAlertChannel, RnsTransport
        from pyrxd.gravity.watch.alerts import Page, Severity
        from pyrxd.gravity.watch.decide import Intent

        transport = RnsTransport(config_path=str(tx_cfg))
        for _ in range(60):
            if RNS.Identity.recall(bytes.fromhex(dest_hex)) is not None:
                break
            time.sleep(1.0)
        if RNS.Identity.recall(bytes.fromhex(dest_hex)) is None:
            print("FAIL: no announce crossed the serial link")
            return 1
        print("announce crossed the serial link", flush=True)

        page = Page(
            swap_id="swap-2026-08-21-btc-rxd-0007",
            intent=Intent.PAGE_CLAIM,
            severity=Severity.CRITICAL,
            message="BTC HTLC claim is live; refund window opens at RXD height 172",
            recommended_action="taker_scrape_and_claim_asset",
            deadline_rxd_height=172,
            low_corroboration=False,
        )
        channel = ReticulumAlertChannel(dest_hex, transport=transport)
        payload = channel.encode(page)
        import asyncio

        asyncio.run(channel.send(page))
        print(f"sent {len(payload)} bytes", flush=True)

        for _ in range(30):
            if "RECEIVED " in log_path.read_text():
                break
            time.sleep(0.5)
        body = log_path.read_text()
        if "RECEIVED " not in body:
            print("FAIL: page never arrived\n" + body[-1500:])
            return 1
        decoded = json.loads(body.split("RECEIVED ", 1)[1].splitlines()[0])
        print("PAGE ARRIVED OVER A NON-IP LINK")
        print(f"  swap={decoded['s']} severity={decoded['v']} deadline={decoded['d']} action={decoded['a']}")
        return 0
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        log.close()


if __name__ == "__main__":
    raise SystemExit(main())
