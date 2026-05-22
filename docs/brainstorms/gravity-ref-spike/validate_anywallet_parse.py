#!/usr/bin/env python3
"""Reference validation of the any-wallet BTC-tx parser's offset arithmetic
(mirrors the RadiantScript walk in AnyWalletParse.rxd). Builds a 2-input,
change-first, mixed-output-type tx and confirms the walk finds the P2WPKH
payment at output[1] — the shape the single-input covenant rejected.
Run: python3 validate_anywallet_parse.py
"""

import struct


def build_multi_input_tx(btc_hash: bytes, pay_sats: int) -> bytes:
    p2wpkh = b"\x00\x14" + btc_hash
    payment = struct.pack("<Q", pay_sats) + bytes([len(p2wpkh)]) + p2wpkh
    p2tr = b"\x51\x20" + b"\x11" * 32  # change is a different output type
    change = struct.pack("<Q", 99999) + bytes([len(p2tr)]) + p2tr

    def inp(txid_b, vout):
        return txid_b + struct.pack("<I", vout) + b"\x00" + b"\xff\xff\xff\xff"

    return (
        struct.pack("<I", 2)
        + b"\x02"
        + inp(b"\xaa" * 32, 0)
        + inp(b"\xbb" * 32, 1)
        + b"\x02"
        + change  # output[0] = change (payment is NOT first)
        + payment  # output[1] = payment
        + struct.pack("<I", 0)
    )


def parse_find_payment(rawtx: bytes, btc_hash: bytes, min_sats: int) -> bool:
    """The covenant's walk: skip version + N native-segwit inputs, scan outputs."""
    i = lambda b: int.from_bytes(b, "little")
    pos = 4
    n_in = rawtx[pos]
    pos += 1
    assert 1 <= n_in <= 8
    for _ in range(n_in):
        assert rawtx[pos + 36] == 0x00, "native segwit (empty scriptSig) only"
        pos += 41
    n_out = rawtx[pos]
    pos += 1
    found = False
    for _ in range(n_out):
        v = i(rawtx[pos : pos + 8])
        sl = rawtx[pos + 8]
        spk = rawtx[pos + 9 : pos + 9 + sl]
        if sl == 22 and spk[:2] == b"\x00\x14" and spk[2:] == btc_hash and v >= min_sats:
            found = True
        pos += 9 + sl
    return found


if __name__ == "__main__":
    h = bytes.fromhex("9995c9ac3bd932a75dca3229e3195c3544d5db36")
    tx = build_multi_input_tx(h, 10000)
    assert parse_find_payment(tx, h, 10000), "parser failed to find payment"
    # negative: wrong hash must NOT be found
    assert not parse_find_payment(tx, b"\x00" * 20, 10000), "false positive on wrong hash"
    # negative: amount too high must NOT be found
    assert not parse_find_payment(tx, h, 20000), "false positive on insufficient value"
    print("any-wallet parser offset arithmetic: PASS (2-input, change-first, mixed types)")


def build_mixed_input_tx(btc_hash: bytes, pay_sats: int) -> bytes:
    """3 inputs (P2SH-P2WPKH 23B scriptSig + 2 native segwit), 3 outputs with
    the P2WPKH payment in the MIDDLE (P2PKH change, payment, P2TR change)."""
    import struct as _s

    def inp(txid_b, vout, scriptsig):
        return txid_b + _s.pack("<I", vout) + bytes([len(scriptsig)]) + scriptsig + b"\xff\xff\xff\xff"

    def out(sats, spk):
        return _s.pack("<Q", sats) + bytes([len(spk)]) + spk

    in1 = inp(b"\xaa" * 32, 0, b"\x16\x00\x14" + b"\x33" * 20)  # P2SH-P2WPKH 23B
    in2 = inp(b"\xbb" * 32, 1, b"")
    in3 = inp(b"\xcc" * 32, 2, b"")
    return (
        _s.pack("<I", 2)
        + b"\x03"
        + in1
        + in2
        + in3
        + b"\x03"
        + out(55555, b"\x76\xa9\x14" + b"\x44" * 20 + b"\x88\xac")  # P2PKH change
        + out(pay_sats, b"\x00\x14" + btc_hash)  # P2WPKH payment (middle)
        + out(99999, b"\x51\x20" + b"\x11" * 32)  # P2TR change
        + _s.pack("<I", 0)
    )


def parse_find_payment_v3(rawtx: bytes, btc_hash: bytes, min_sats: int) -> bool:
    """v3 walk: per-input scriptSigLen-varint skip (handles P2SH-P2WPKH)."""
    i = lambda b: int.from_bytes(b, "little")
    pos = 4
    n_in = rawtx[pos]
    pos += 1
    assert 1 <= n_in <= 4
    for _ in range(n_in):
        ssl = rawtx[pos + 36]
        pos += 36 + 1 + ssl + 4
    n_out = rawtx[pos]
    pos += 1
    found = False
    for _ in range(n_out):
        v = i(rawtx[pos : pos + 8])
        sl = rawtx[pos + 8]
        if (
            sl == 22
            and rawtx[pos + 9 : pos + 11] == b"\x00\x14"
            and rawtx[pos + 11 : pos + 31] == btc_hash
            and v >= min_sats
        ):
            found = True
        pos += 9 + sl
    return found


if __name__ == "__main__":
    h = bytes.fromhex("9995c9ac3bd932a75dca3229e3195c3544d5db36")
    tx3 = build_mixed_input_tx(h, 10000)
    assert parse_find_payment_v3(tx3, h, 10000), "v3 failed mixed-input tx"
    assert not parse_find_payment_v3(tx3, b"\x00" * 20, 10000), "v3 false positive wrong hash"
    print("any-wallet parser v3: PASS (3 mixed-type inputs incl P2SH-P2WPKH, payment mid-outputs)")


def scan_4way(rawtx: bytes, maker_hash: bytes, min_sats: int) -> bool:
    """Mirror of the 4-way any-wallet output scan: matches a maker payment of
    type P2WPKH / P2PKH / P2SH / P2TR at any output index."""
    i = lambda b: int.from_bytes(b, "little")
    pos = 4
    n_in = rawtx[pos]
    pos += 1
    for _ in range(n_in):
        pos += 36 + 1 + rawtx[pos + 36] + 4
    n_out = rawtx[pos]
    pos += 1
    found = False
    for _ in range(n_out):
        v = i(rawtx[pos : pos + 8])
        sl = rawtx[pos + 8]
        spk = rawtx[pos + 9 : pos + 9 + sl]
        ok = (
            (sl == 22 and spk[:2] == b"\x00\x14" and spk[2:] == maker_hash)
            or (sl == 25 and spk[:3] == b"\x76\xa9\x14" and spk[3:23] == maker_hash and spk[23:] == b"\x88\xac")
            or (sl == 23 and spk[:2] == b"\xa9\x14" and spk[2:22] == maker_hash and spk[22:] == b"\x87")
            or (sl == 34 and spk[:2] == b"\x51\x20" and spk[2:] == maker_hash)
        )
        if ok and v >= min_sats:
            found = True
        pos += 9 + sl
    return found


def _test_4way():
    import struct as _s

    def out(s, spk):
        return _s.pack("<Q", s) + bytes([len(spk)]) + spk

    def mk(payment_spk):
        inp = b"\xaa" * 32 + _s.pack("<I", 0) + b"\x00" + b"\xff\xff\xff\xff"
        return (
            _s.pack("<I", 2)
            + b"\x01"
            + inp
            + b"\x02"
            + out(10000, payment_spk)
            + out(500, b"\x00\x14" + b"\xcc" * 20)
            + _s.pack("<I", 0)
        )

    h20, h32 = b"\x11" * 20, b"\x22" * 32
    cases = {
        "P2WPKH": (b"\x00\x14" + h20, h20),
        "P2PKH": (b"\x76\xa9\x14" + h20 + b"\x88\xac", h20),
        "P2SH": (b"\xa9\x14" + h20 + b"\x87", h20),
        "P2TR": (b"\x51\x20" + h32, h32),
    }
    for name, (spk, h) in cases.items():
        tx = mk(spk)
        assert scan_4way(tx, h, 10000), f"{name} payment not found"
        assert not scan_4way(tx, b"\x99" * len(h), 10000), f"{name} wrong-hash not rejected"
        assert not scan_4way(tx, h, 20000), f"{name} low-value not rejected"
    print("any-wallet 4-way output scan: PASS (P2WPKH/P2PKH/P2SH/P2TR + wrong-hash/low-value rejects)")


if __name__ == "__main__":
    _test_4way()
