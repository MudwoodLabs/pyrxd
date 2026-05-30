#!/usr/bin/env python3
"""Phase-4b live-swap BTC HTTP I/O helper (signet first, mainnet-capable).

pyrxd's production BTC client (network/bitcoin.py MempoolSpaceSource) is READ-ONLY
(headers/tx/merkle for SPV) — there is no broadcast method, and it is gated by
coverage. This spike-local helper supplies the small read/write HTTP the live cross-
chain swap needs, mirroring the mempool.space API the earlier sweeps already proved:

  broadcast <hex>                 POST /tx                  -> txid
  utxos <address>                 GET  /address/:a/utxo     -> [{txid,vout,value},...]
  rawtx <txid>                    GET  /tx/:id/hex          -> raw tx hex
  tx <txid>                       GET  /tx/:id              -> status json (confirmed?)
  tip                             GET  /blocks/tip/height   -> height

Network select via --net {signet|mainnet|testnet4} (default signet). Signet base:
https://mempool.space/signet/api. This is the broadcast/UTXO/confirm path; the
preimage scrape itself is done by taproot.scrape_secret over the fetched claim tx.
"""
import json
import sys
import urllib.request
import urllib.error

BASES = {
    "signet": "https://mempool.space/signet/api",
    "mainnet": "https://mempool.space/api",
    "testnet4": "https://mempool.space/testnet4/api",
}


def _net() -> str:
    if "--net" in sys.argv:
        return sys.argv[sys.argv.index("--net") + 1]
    return "signet"


def _base() -> str:
    return BASES[_net()]


def _get(path: str, raw_text: bool = False):
    url = f"{_base()}/{path.lstrip('/')}"
    req = urllib.request.Request(url, headers={"User-Agent": "pyrxd-spike"})
    with urllib.request.urlopen(req, timeout=30) as r:
        body = r.read().decode()
    return body if raw_text else json.loads(body)


def _post(path: str, data: str) -> str:
    url = f"{_base()}/{path.lstrip('/')}"
    req = urllib.request.Request(
        url, data=data.encode(), headers={"User-Agent": "pyrxd-spike", "Content-Type": "text/plain"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.read().decode().strip()
    except urllib.error.HTTPError as e:
        msg = e.read().decode()
        raise SystemExit(f"broadcast HTTP {e.code}: {msg}")


def main() -> None:
    cmd = sys.argv[1]
    if cmd == "tip":
        print(_get("blocks/tip/height", raw_text=True))
    elif cmd == "broadcast":
        hex_tx = sys.argv[2]
        print(json.dumps({"txid": _post("tx", hex_tx), "net": _net()}))
    elif cmd == "utxos":
        addr = sys.argv[2]
        utxos = _get(f"address/{addr}/utxo")
        print(json.dumps(utxos))
    elif cmd == "rawtx":
        print(_get(f"tx/{sys.argv[2]}/hex", raw_text=True))
    elif cmd == "tx":
        print(json.dumps(_get(f"tx/{sys.argv[2]}")))
    else:
        raise SystemExit(f"unknown cmd: {cmd}")


if __name__ == "__main__":
    main()
