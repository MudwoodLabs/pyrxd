**pyrxd 0.20.0** — confirmation waits that respect their own deadline, and a poll interval you can actually set.

**`confirmation_timeout_s` could not take effect below 10 seconds.** A reveal has two confirmation waits, and neither was passed a poll interval — so both slept the 10s default. The wait sleeps a full interval before re-checking the deadline, so a 0.001s timeout still cost ten seconds. `poll_interval_s` is now a constructor argument on `GlyphMinter` and `GlyphClient`, forwarded to both. Default unchanged at 10s; the CLI polls every 0.25s on regtest, where the node mines on demand from the very script that is waiting.

**Waits no longer overshoot their deadline.** The poll happens before the sleep, so an unclamped `sleep(interval_s)` ran to the next interval boundary instead of to `timeout_s` — at `timeout_s=0.2, interval_s=3.0` the timeout fired after 3.00s, a 15x overshoot. Fixed in `network/confirm.py` and in `btc_wallet/htlc_leg.py`, where that deadline decides when a caller stops waiting for funding and starts thinking about refund.

**Non-finite arguments are refused rather than hanging.** `nan` and `inf` passed every check — both `nan <= 0` and `inf <= 0` are False. A `nan` deadline is never reached; `asyncio.sleep(nan)` never returns. And once the deadline clamp landed, `max(0.0, nan)` collapsed to `sleep(0.0)`: ~590,000 reads per second, deadline never firing. The fix for one bug created the second; both are closed.

Both classes now bound their wait arguments at construction and refuse by their own name, instead of raising an error that named the wrong class.

Two new mutation groups found that `ft_funding`'s fee estimate — which decides whether a UTXO can pay an FT transfer's fee — had no test at all: 104 surviving mutants on two lines.

Offline suite: 147.8s, down from 175s. Upgrade note: both validation changes refuse input that used to construct.

The swap stack remains unaudited.

https://github.com/MudwoodLabs/pyrxd/releases/tag/v0.20.0
