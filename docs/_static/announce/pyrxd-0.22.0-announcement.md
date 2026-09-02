🔒 **pyrxd 0.22.0 — our published handshake spec had the timelock ordering backwards**

**If you implemented against pyrxd's HTLC material before today, re-derive your timelock ordering.**

Every release through 0.21.0 shipped conformance vectors that **accepted** `t_btc=60 / t_rxd=20` and **rejected** the correct ordering — the safe layout was published under the name `margin-inverted-ordering`.

The accepted one is where the maker refunds its own leg while the preimage is still secret and *then* claims the counter leg with it, taking both. So an implementation that got the direction **right** would have run our vectors, failed, and been told by a spec with a green test run behind it to switch to the broken layout.

The maker holds the preimage. It **locks** the Radiant leg and **claims** the counter leg, so the leg it locks carries the **longer** refund window — Herlihy, *Atomic Cross-Chain Swaps* §1.

A second defect sat underneath it: the margin was compared in raw block counts across two chains. A Radiant block is ~300s, a Bitcoin block ~600s. `t_rxd=180` "exceeds" `t_btc=144` by 36 blocks while being 15h against 24h in wall clock. It's judged in seconds now, so **honest swaps need a longer Radiant leg than before** — check your parameters, don't just bump the version.

Vectors are regenerated from the builders and bumped to schema `radiant-htlc-handshake/3`, so the two files can't be confused by version alone.

```
pip install -U pyrxd
```

pyrxd's own gate was fail-safe under the old rule — the exposure was to anyone building from the published spec. Swaps remain **UNAUDITED**; external audit is still the gate before real value. Apache-2.0, as-is.

https://pypi.org/project/pyrxd/
