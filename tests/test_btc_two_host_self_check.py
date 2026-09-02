"""Automated coverage of the btc_swap_two_host.py PREP harness's OFFLINE self-check.

The two-host harness's ``--self-check`` is its validatable deliverable (no chain): it round-trips the
security-critical seam — the maker serialises the envelope, the taker re-derives the covenant + runs
the INDEPENDENT margin check, the maker re-derives the expected BTC HTLC SPK — and asserts ``p`` never
appears in any serialised artifact. This test wires that into CI; the ETH sibling is covered by
``tests/test_eth_two_host_self_check.py``.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "btc_swap_two_host.py"


def _load():
    sys.path.insert(0, str(_SCRIPT.parent))  # the harness imports its sibling _dust_swap_shared
    spec = importlib.util.spec_from_file_location("btc_swap_two_host", _SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_self_check_passes():
    """run_self_check asserts internally and raises on ANY seam failure (leaked p, SPK mismatch,
    margin gate not firing) — so a clean return IS the pass."""
    _load().run_self_check()


def test_dispatch_table_is_complete():
    mod = _load()
    assert set(mod._DISPATCH) == {
        ("taker", "intro"),
        ("taker", "fund"),
        ("taker", "claim"),
        ("maker", "envelope"),
        ("maker", "lock-claim"),
    }


def test_public_only_guard_rejects_smuggled_secret():
    mod = _load()
    # A secret nested under an innocuous key is still caught (recursive, case-insensitive).
    with pytest.raises(SystemExit):
        mod._assert_public_only({"note": {"maker_wif": "L5..."}}, what="t")
    with pytest.raises(SystemExit):
        mod._assert_public_only({"terms": {"preimage_p_hex": "de" * 32}}, what="t")
    # A genuinely-public doc passes.
    mod._assert_public_only({"terms": {"hashlock": "ab" * 32}, "maker_pkh_hex": "cd" * 20}, what="t")


def test_terms_from_public_is_deterministic_and_btc_counterchain():
    """Both roles MUST re-derive the identical covenant + terms from the same public inputs (the trust
    anchor), and the counter chain is 'btc'."""
    import hashlib
    import os

    mod = _load()
    h = hashlib.sha256(os.urandom(32)).digest()
    kw = dict(
        hashlock=h,
        btc_sats=100_000,
        # INVERTED (#482): the maker locks the Radiant leg, so it carries the LONGER timeout.
        t_rxd_blocks=60,
        t_btc_blocks=20,
        taker_pkh=b"\x11" * 20,
        maker_pkh=b"\x22" * 20,
        btc_claim_xonly=b"\x33" * 32,
        btc_refund_xonly=b"\x44" * 32,
    )
    terms_a, cov_a = mod._terms_from_public(**kw)
    terms_b, cov_b = mod._terms_from_public(**kw)
    assert cov_a.funded_spk == cov_b.funded_spk
    assert terms_a.to_dict() == terms_b.to_dict()
    assert terms_a.counter_chain == "btc"
