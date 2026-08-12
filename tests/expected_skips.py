"""The allowlist of skips this suite is permitted to report, and why.

A skipped test reports as green. That is fine when the skip is *deliberate* — an
optional dependency is absent, an artifact only CI builds is missing — and it is a
silent hole when the skip is *accidental*. An audit found sixteen golden-vector tests
that had skipped on every clean checkout, including CI, since the day they were
written: the fixture they read is gitignored, so the tests had never run anywhere but
one developer's machine. Among them were the only tests covering a fail-closed
broadcast guard; widening that guard's match to a bare ``"already"`` — so that
*"inputs already spent by another transaction"* (a counterparty front-ran the HTLC
output) reads as a **successful** broadcast and returns a txid for a transaction that
never entered a mempool — passed the entire 8456-test suite.

This is the same shape as the ``"_int_"`` collection hook documented in ``conftest.py``,
which silently deselected 55 offline unit tests for months. Both failures were invisible
because the reporting channel said "green" either way.

So: every skip must be declared here, with a reason. ``conftest.py`` fails the run on
any skip that is not. Adding an entry is cheap and deliberately visible in review —
that is the point. Do **not** add one to silence a fixture that has gone missing;
restore the fixture instead, and prefer committing a sanitized vector so the test
cannot skip at all (see ``tests/fixtures/mainnet_btc_segwit_tx.json``).

Each entry matches on the skip *reason* (a regex, matched with ``re.search``) and
optionally on the test's node id. Node-id scoping is what keeps an entry from growing
into a blanket exemption: the golden-vector entries below name the exact tests that may
skip, so the *same reason* arising in a *new* test is still reported as unexpected.
"""

from __future__ import annotations

from typing import NamedTuple


class ExpectedSkip(NamedTuple):
    """One permitted skip. ``reason``/``nodeid`` are ``re.search`` patterns."""

    reason: str
    why: str
    nodeid: str = ""  # empty = any test may skip for this reason


EXPECTED_SKIPS: tuple[ExpectedSkip, ...] = (
    # --- genuinely optional dependency -------------------------------------------------
    ExpectedSkip(
        reason=r"could not import 'web3'",
        why=(
            "web3 is an optional extra (the ETH<->RXD leg). The BTC<->RXD stack and every "
            "offline unit test run without it, so a plain `pip install pyrxd` checkout "
            "legitimately skips these. Install the eth extra to run them."
        ),
    ),
    # --- opt-in live-node lanes ----------------------------------------------------------
    ExpectedSkip(
        reason=r"^[A-Z][A-Z_]* not set\b",
        why=(
            "An env-var opt-in gate on a node-backed e2e suite (RADIANT_REGTEST, BTC_REGTEST, "
            "XCHAIN_REGTEST, RSWP_REGTEST, RADIANT_INTEGRATION). These need a live node and run "
            "in .github/workflows/integration.yml. `task test` never sees them — pyproject's "
            "addopts deselect the `integration` marker — but `task coverage-overall` clears "
            "addopts, so they collect and skip. Deliberate, and the skip reason names the "
            "variable that would run them."
        ),
    ),
    ExpectedSkip(
        reason=r"^(docker|anvil)\b.*not available|^anvil binary not available",
        why=(
            "An external tool the live lanes drive (docker for the regtest node images, anvil "
            "for the ETH leg) is absent. Only reachable from integration-marked tests, which "
            "the default run never selects."
        ),
    ),
    ExpectedSkip(
        reason=r"image not available|could not (build|obtain)\b",
        why=(
            "A regtest node image could not be built or pulled, so the live e2e cannot run. "
            "Integration-marked only. NOTE: this one is a gate on an unavailable environment "
            "AND a place a genuine build failure would read as a skip — a pre-existing property "
            "of the live lanes, recorded here rather than silently inherited."
        ),
    ),
    # --- artifact only produced by another CI job ---------------------------------------
    ExpectedSkip(
        reason=r"wheel \+ manifest only built by docs\.yml CI step",
        why=(
            "The web facade smoke tests assert against a built wheel + manifest that the "
            "docs.yml job produces. Deliberate: the test job does not build a wheel, and "
            "docs.yml runs these for real."
        ),
        nodeid=r"^tests/web/test_facade_smoke\.py::",
    ),
    # --- superseded placeholders, resolved by a live integration test --------------------
    ExpectedSkip(
        reason=r"RESOLVED live in tests/test_spv_covenant_differential_regtest\.py",
        why=(
            "Placeholders kept as documentation. Each question was answered on a real "
            "radiant-core regtest node by the named integration test, which is the "
            "evidence; the placeholder records the finding and stays skipped by design."
        ),
        nodeid=r"^tests/test_spv_covenant_differential_deployed\.py::",
    ),
    # --- compute-bound by construction ---------------------------------------------------
    ExpectedSkip(
        reason=r"real 32-bit leading-zero search is ~4B attempts",
        why=(
            "A genuine 32-bit PoW grind averages ~4e9 hashes — minutes to hours per run. "
            "Kept for future GPU/external-miner integration; the mining path is covered at "
            "a tractable difficulty elsewhere."
        ),
        nodeid=r"^tests/test_dmint_v1_mint\.py::",
    ),
    ExpectedSkip(
        reason=r"No valid SHA256d solution in \S+ iterations",
        why=(
            "Probabilistic: the test grinds a bounded number of nonces and skips if none "
            "solves. Bounded so the suite stays fast; it usually runs."
        ),
        nodeid=r"^tests/test_dmint_module\.py::",
    ),
    # --- developer-only mainnet vectors, node-id-scoped ----------------------------------
    #
    # These read `docs/brainstorms/gravity-ref-spike/.live_swap_{nft,ft}.json`, which is
    # gitignored (.gitignore:208) and MUST stay so: it holds six live mainnet WIFs and the
    # HTLC preimage. The fixture cannot be committed, so these tests cannot be made to run
    # on a clean checkout without publishing key material.
    #
    # They are allowlisted only because the audit MEASURED what each one protects and found
    # it covered elsewhere:
    #   * breaking segwit witness-stripping in `btc_txid_from_raw` is killed by
    #     tests/test_taker_asset_funding_gate_adversarial.py on a clean tree; and
    #   * breaking the HTLC covenant shape is killed by the git-tracked
    #     conformance/htlc-handshake-vectors.json.
    # The one cluster that was NOT redundant — the mempool broadcaster's fail-closed
    # idempotency match — was fixed properly instead, by committing a sanitized vector
    # (tests/fixtures/mainnet_btc_segwit_tx.json). It no longer skips, and a missing file
    # there is a hard error rather than a skip.
    #
    # Each entry names its exact tests. The same reason in a NEW test is still unexpected.
    ExpectedSkip(
        reason=r"mainnet golden vector \.live_swap_(nft|ft)\.json not present",
        why=(
            "Reads a gitignored developer-only record holding live mainnet WIFs and the HTLC "
            "preimage; it cannot be committed. Audit-measured as redundant: the segwit "
            "witness-stripping regression it would catch is killed by "
            "tests/test_taker_asset_funding_gate_adversarial.py on a clean tree."
        ),
        nodeid=r"^tests/test_btc_txid_from_raw\.py::test_("
        r"reproduces_mainnet_claim_txid"
        r"|reproduces_mainnet_funding_txid"
        r"|fail_closed_on_trailing_bytes"
        r"|fail_closed_on_truncated_witness"
        r"|input_outpoints_mainnet_claim_spends_funding"
        r")$",
    ),
    ExpectedSkip(
        reason=r"mainnet golden vector \.live_swap_(nft|ft)\.json not present",
        why=(
            "Same gitignored key-bearing record. Audit-measured as redundant: the covenant-shape "
            "regression it would catch is killed by the git-tracked "
            "conformance/htlc-handshake-vectors.json."
        ),
        nodeid=r"^tests/test_htlc_covenant\.py::test_("
        r"nft_covenant_v2_pins_preimage_length_holder_unchanged"
        r"|ft_covenant_v2_pins_preimage_length_holder_unchanged"
        r"|nft_and_ft_bind_exactly_the_genesis_ref"
        r")$",
    ),
)
