"""Differential test: off-chain Python SPV parser  vs  on-chain covenant ASM.

Cross-checks the two independent implementations of "does this raw BTC tx pay
the maker?": the Python SDK (``_output_offsets`` + ``verify_payment``) and the
compiled any-wallet covenant scan, modelled faithfully by the spike simulator
``docs/brainstorms/gravity-ref-spike/rxd_sim.py`` (which encodes the EXACT
opcode semantics incl. the audit guards ``ssl/sl in [0,252]`` and the terminal
``pos == len-4`` check).

They MUST agree on accept/reject for every well-formed tx. This file proves
agreement on a corpus AND pins the ONE known, characterized divergence:

  KNOWN DIVERGENCE (covenant limitation, documented 2026-05-24 rigorous audit):
  the covenant reads each input's scriptSig-length as a SINGLE byte and decodes
  it via OP_BIN2NUM (signed CScriptNum). A length >= 0x80 (128) decodes NEGATIVE,
  so the ``ssl >= 0`` guard rejects ANY payment whose funding tx has an input
  with a scriptSig >= 128 bytes (e.g. P2SH multisig ~250B). The Python SDK parses
  the real varint and accepts. Net: a taker paying from a P2SH/multisig input
  builds a valid-per-SDK SPV proof the covenant rejects on-chain -> failed swap,
  and on the no-refund SPV-oracle path the taker can LOSE the BTC. Native-segwit
  (empty scriptSig) and P2PKH (~107B) inputs are unaffected.
"""

from __future__ import annotations

import importlib.util
import struct
from pathlib import Path

import pytest

from pyrxd.security.errors import SpvVerificationError, ValidationError
from pyrxd.spv.payment import P2PKH, P2SH, P2TR, P2WPKH, verify_payment
from pyrxd.spv.proof import _output_offsets

_SIM_PATH = Path(__file__).resolve().parents[1] / "docs/brainstorms/gravity-ref-spike/rxd_sim.py"


def _load_sim():
    spec = importlib.util.spec_from_file_location("rxd_sim", _SIM_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


rxd_sim = _load_sim()

MAKER20 = b"\xee" * 20
MAKER32 = b"\xee" * 32
SATS = 100_000


def _vi(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


def _build(scriptsigs, outputs):
    p = [struct.pack("<I", 2), _vi(len(scriptsigs))]
    for ss in scriptsigs:
        p += [b"\x11" * 32 + b"\x00\x00\x00\x00", _vi(len(ss)), ss, b"\xff\xff\xff\xff"]
    p.append(_vi(len(outputs)))
    for v, spk in outputs:
        p += [struct.pack("<Q", v), _vi(len(spk)), spk]
    p.append(b"\x00\x00\x00\x00")
    return b"".join(p)


def _python_accepts(raw):
    try:
        offs = _output_offsets(raw)
    except (ValidationError, SpvVerificationError):
        return False
    for off in offs:
        for otype, h in ((P2PKH, MAKER20), (P2WPKH, MAKER20), (P2SH, MAKER20), (P2TR, MAKER32)):
            try:
                verify_payment(raw, off, h, otype, SATS)
                return True
            except (ValidationError, SpvVerificationError):
                continue
    return False


def _covenant_accepts(raw, receive_hash=MAKER20):
    try:
        return rxd_sim.parse(raw, receive_hash, SATS)
    except rxd_sim.ScriptFail:
        return False


_P2WPKH = b"\x00\x14" + MAKER20
_OTHER = b"\x00\x14" + b"\x33" * 20

# (label, scriptsigs, outputs, receive_hash) — receive_hash differs for P2TR.
_AGREE_CASES = [
    ("happy_single", [b""], [(SATS, _P2WPKH)], MAKER20),
    ("change_then_maker", [b""], [(50, _OTHER), (SATS, _P2WPKH)], MAKER20),
    ("maker_then_change", [b""], [(SATS, _P2WPKH), (50, _OTHER)], MAKER20),
    ("underpay_rejected", [b""], [(SATS - 1, _P2WPKH)], MAKER20),
    ("wrong_hash_rejected", [b""], [(SATS, _OTHER)], MAKER20),
    ("forged_blob_in_scriptsig", [struct.pack("<Q", SATS) + b"\x16" + _P2WPKH], [(50, _OTHER)], MAKER20),
    ("four_inputs", [b"", b"", b"", b""], [(SATS, _P2WPKH)], MAKER20),
    ("p2pkh_maker", [b""], [(SATS, b"\x76\xa9\x14" + MAKER20 + b"\x88\xac")], MAKER20),
    ("p2sh_maker", [b""], [(SATS, b"\xa9\x14" + MAKER20 + b"\x87")], MAKER20),
    ("p2tr_maker", [b""], [(SATS, b"\x51\x20" + MAKER32)], MAKER32),
    ("scriptsig_127_ok", [b"\x01" * 127], [(SATS, _P2WPKH)], MAKER20),
]


@pytest.mark.parametrize("label,ss,outs,rh", _AGREE_CASES, ids=[c[0] for c in _AGREE_CASES])
def test_python_and_covenant_agree(label, ss, outs, rh):
    raw = _build(ss, outs)
    assert _python_accepts(raw) == _covenant_accepts(raw, rh), f"divergence on {label}"


@pytest.mark.parametrize("ss_len", [128, 150, 200, 252])
def test_known_divergence_scriptsig_ge_128(ss_len):
    """The covenant rejects (single-byte signed scriptSig-len) what the SDK accepts.

    This is a covenant FUNCTIONAL LIMITATION, not theft: the taker's funding tx
    must spend only inputs with scriptSig < 128 bytes (native-segwit / P2PKH).
    Pinned so a future covenant fix that closes the gap will flip this test and
    force a conscious update.
    """
    raw = _build([b"\x01" * ss_len], [(SATS, _P2WPKH)])
    assert _python_accepts(raw) is True, "SDK should accept a well-formed payment regardless of scriptSig size"
    assert _covenant_accepts(raw) is False, f"covenant unexpectedly accepted scriptSig={ss_len}B (boundary moved?)"


def test_scriptsig_boundary_is_exactly_128():
    """Covenant accepts scriptSig <= 127B and rejects >= 128B (the CScriptNum sign bit)."""
    assert _covenant_accepts(_build([b"\x01" * 127], [(SATS, _P2WPKH)])) is True
    assert _covenant_accepts(_build([b"\x01" * 128], [(SATS, _P2WPKH)])) is False
