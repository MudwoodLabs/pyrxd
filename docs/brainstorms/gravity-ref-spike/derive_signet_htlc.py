#!/usr/bin/env python3
"""Phase-4b: derive the signet Taproot HTLC address for the live cross-chain swap.

Role invariant: MAKER_SECRET_TAKER_LOCKS_BTC_FIRST.
  - MAKER generates secret p, publishes H = sha256(p); claims BTC with p (claim leaf).
  - TAKER locks BTC into this P2TR first; refunds via the CSV leaf after timeout.

The same H is the Radiant covenant hashlock — the BTC claim witness reveals p, which
the taker scrapes (taproot.scrape_secret) to claim the Radiant asset. Atomicity hinge:
the BTC refund timeout MUST exceed the Radiant claim deadline (secret revealed on
Radiant first, used on BTC second). On signet we use a short CSV so the refund path is
testable in-session; the *ordering* is what's load-bearing, the absolute margin must be
derived from MAINNET block data before any real-value swap (Phase-4a MarginPolicy).

Writes the keyfile to docs/brainstorms/gravity-ref-spike/.live_swap_signet.json
(gitignored by `gravity-ref-spike/.*`). Contains the secret + both WIFs — NEVER commit.
"""
import hashlib
import json
import os
import sys

from pyrxd.btc_wallet import keys, taproot

NET = sys.argv[sys.argv.index("--net") + 1] if "--net" in sys.argv else "signet"
_HRP = {"signet": "tb", "mainnet": "bc", "testnet4": "tb"}[NET]
KEYFILE = os.path.join(os.path.dirname(__file__), f".live_swap_{NET}.json")
BTC_REFUND_CSV_BLOCKS = 6  # ~10min/block; short so MUTUAL_REFUND is testable today


def main() -> None:
    if os.path.exists(KEYFILE) and "--force" not in sys.argv:
        existing = json.load(open(KEYFILE))
        print(json.dumps({"reused": True, "address": existing["htlc_address"],
                          "hashlock": existing["hashlock"]}, indent=2))
        return

    # Fresh CSPRNG secret (NEVER hand-write key material — prior weak-key incident).
    p = os.urandom(32)
    H = hashlib.sha256(p).digest()

    maker = keys.generate_keypair(network=_HRP)  # claims BTC, reveals p
    taker = keys.generate_keypair(network=_HRP)  # locks + refunds BTC

    maker_xonly = maker.pubkey_bytes[1:]
    taker_xonly = taker.pubkey_bytes[1:]

    htlc = taproot.build_htlc(
        hashlock=H,
        claim_pubkey_xonly=maker_xonly,
        refund_pubkey_xonly=taker_xonly,
        timeout=taproot.Timelock(BTC_REFUND_CSV_BLOCKS, taproot.TimeUnit.BLOCKS),
        network=_HRP,
    )

    state = {
        "network": NET,
        "role_invariant": "MAKER_SECRET_TAKER_LOCKS_BTC_FIRST",
        "hashlock": H.hex(),
        "secret_p": p.hex(),  # MAKER-only in production; here for the spike driver
        "btc_refund_csv_blocks": BTC_REFUND_CSV_BLOCKS,
        "maker_wif": maker.unsafe_wif(),
        "maker_xonly": maker_xonly.hex(),
        "maker_p2tr_keypath_addr": maker.p2tr_address,  # where maker receives claimed BTC
        "taker_wif": taker.unsafe_wif(),
        "taker_xonly": taker_xonly.hex(),
        "taker_p2tr_keypath_addr": taker.p2tr_address,  # where taker receives refunded BTC
        "htlc_address": htlc.address,
        "htlc_scriptpubkey": htlc.scriptpubkey.hex(),
        "htlc_output_key": htlc.output_key.hex(),
    }
    with open(KEYFILE, "w") as f:
        json.dump(state, f, indent=2)
    os.chmod(KEYFILE, 0o600)

    print(json.dumps({
        "htlc_address": htlc.address,
        "hashlock": H.hex(),
        "btc_refund_csv_blocks": BTC_REFUND_CSV_BLOCKS,
        "maker_receives_at": maker.p2tr_address,
        "taker_refunds_to": taker.p2tr_address,
        "keyfile": KEYFILE,
    }, indent=2))


if __name__ == "__main__":
    main()
