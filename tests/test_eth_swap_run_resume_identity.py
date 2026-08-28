"""`--resume` must rebuild the SAME swap, not mint a new one.

The defect this pins was found by a real-value mainnet run and cost a funded covenant.
`_build_terms_and_covenant` called `os.urandom` for the preimage and both RXD keys unconditionally,
and `run_sepolia_dust` recomputed `eth_timeout` from the clock — so `--resume` built a covenant with
a DIFFERENT hashlock and silently abandoned the one holding the money. Nothing detected it: the only
thing that stopped the run was the O_EXCL create of the recovery file failing afterwards, which is
accidental protection that would not have fired with a different `--keys-out`.

These run entirely offline. `_build_terms_and_covenant` for `asset_variant="rxd"` is pure — it
builds a covenant from keys and a hashlock and touches no chain — which is exactly why the absence
of a test here was a choice rather than a constraint.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_RUNNER = Path(__file__).resolve().parent.parent / "scripts" / "eth_swap_run.py"


@pytest.fixture(scope="module")
def runner():
    spec = importlib.util.spec_from_file_location("eth_swap_run_resume_under_test", _RUNNER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _args(runner, *argv):
    saved = sys.argv
    try:
        sys.argv = ["eth_swap_run.py", "--stage", "dry-run", *argv]
        return runner._args()
    finally:
        sys.argv = saved


def _fresh(runner, eth_timeout=2_000_000_000):
    a = _args(runner, "--t-rxd-blocks", "240", "--rxd-photons", "1000")
    return a, runner._build_terms_and_covenant(a, eth_timeout=eth_timeout)


def _recovery_from(terms_bundle, eth_timeout=2_000_000_000):
    _terms, cov, p_secret, h, rkeys = terms_bundle
    return {
        "preimage_p_hex": p_secret.unsafe_raw_bytes().hex(),
        "hashlock_H": h.hex(),
        "taker_rxd_wif": rkeys[0].wif(),
        "maker_rxd_wif": rkeys[1].wif(),
        "rxd_covenant_spk": cov.funded_spk.hex(),
        "eth_timeout_unix_s": eth_timeout,
    }


class TestResumeRebuildsTheSameSwap:
    def test_restoring_reproduces_the_covenant_BYTE_FOR_BYTE(self, runner) -> None:
        """The property that matters. Not "the inputs look right" — the actual script that holds
        the money must come out identical, because that script is what the funded UTXO pays to."""
        args, first = _fresh(runner)
        rec = _recovery_from(first)
        _t2, cov2, p2, h2, _k2 = runner._build_terms_and_covenant(
            args, eth_timeout=rec["eth_timeout_unix_s"], restore=rec
        )
        assert cov2.funded_spk.hex() == rec["rxd_covenant_spk"]
        assert h2.hex() == rec["hashlock_H"]
        assert p2.unsafe_raw_bytes().hex() == rec["preimage_p_hex"]

    def test_WITHOUT_restore_it_builds_a_DIFFERENT_swap(self, runner) -> None:
        """The defect, stated as a test. This is what `--resume` used to do every time, and it is
        why the guard above cannot be assumed: two runs with identical arguments legitimately
        produce different covenants, so 'the arguments matched' proves nothing."""
        args, first = _fresh(runner)
        _t2, cov2, _p2, h2, _k2 = runner._build_terms_and_covenant(args, eth_timeout=2_000_000_000)
        assert cov2.funded_spk.hex() != first[1].funded_spk.hex()
        assert h2 != first[3]

    def test_a_TAMPERED_preimage_is_refused_not_used(self, runner) -> None:
        """sha256(p) is checked against the recorded hashlock, so a corrupted or swapped recovery
        file cannot quietly drive a swap it does not belong to."""
        args, first = _fresh(runner)
        rec = _recovery_from(first)
        rec["preimage_p_hex"] = "00" * 32
        with pytest.raises(SystemExit, match="sha256\\(p\\) != recorded hashlock_H"):
            runner._build_terms_and_covenant(args, eth_timeout=2_000_000_000, restore=rec)

    def test_a_MISMATCHED_parameter_is_caught_by_the_SPK_comparison(self, runner) -> None:
        """The keys and preimage can all restore correctly and still produce the wrong covenant if
        a parameter differs — t_rxd is baked into the script. Restoring with a different
        --t-rxd-blocks must therefore NOT reproduce the funded SPK, which is precisely what the
        runner's post-restore assertion checks for.
        """
        _args_unused, first = _fresh(runner)
        rec = _recovery_from(first)
        other = _args(runner, "--t-rxd-blocks", "241", "--rxd-photons", "1000")
        _t2, cov2, _p2, _h2, _k2 = runner._build_terms_and_covenant(
            other, eth_timeout=rec["eth_timeout_unix_s"], restore=rec
        )
        assert cov2.funded_spk.hex() != rec["rxd_covenant_spk"], (
            "a different t_rxd must change the covenant — otherwise the SPK check cannot catch it"
        )

    def test_the_eth_timeout_is_taken_FROM_THE_RECORD(self, runner) -> None:
        """It is an immutable of the deployed HTLC and it anchors every cross-clock margin.

        The first version of this test was TAUTOLOGICAL: it passed `eth_timeout` in itself and
        asserted the same value came back, while `_build_terms_and_covenant` never reads it from
        `restore` at all — the caller does. Equal by construction, unable to fail, in the file
        whose entire purpose is that defect. Found by mutation testing.

        `resolve_eth_timeout` is the decision, extracted so there is something real to drive. Here
        the record's value and the clock-derived one are deliberately FAR APART, so taking the
        wrong one cannot look like taking the right one.
        """
        rec = {"eth_timeout_unix_s": 1_900_000_000}
        got = runner.resolve_eth_timeout(rec, now_unix_s=1_000_000_000, eth_timeout_s=86_400)
        assert got == 1_900_000_000, "resume must take the deadline from the record"
        assert got != 1_000_000_000 + 86_400, "and must NOT recompute it from the clock"

    def test_a_FRESH_run_computes_the_timeout_from_the_clock(self, runner) -> None:
        """The honest-path pair. A function that always returned the record's value would satisfy
        the test above and break every fresh run."""
        assert runner.resolve_eth_timeout(None, now_unix_s=1_000_000_000, eth_timeout_s=86_400) == 1_000_086_400
