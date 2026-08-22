Confirmation waits that respect their own deadline, and a poll interval you can actually set.

## `confirmation_timeout_s` could not take effect below 10 seconds

A reveal has **two** confirmation waits — the commit wait and the reveal wait — and neither was passed a poll interval, so both slept the 10s default. Because the wait sleeps a full interval before re-checking the deadline, a `confirmation_timeout_s` of 0.001s still cost ten seconds. The timeout was, in practice, rounded up to the poll interval.

`poll_interval_s` is now a constructor argument on `GlyphMinter` and `GlyphClient`, forwarded to both waits. The default is unchanged at 10s.

The CLI picks it up too: `pyrxd glyph mint-nft`, `deploy-ft` and `deploy-dmint` poll every **0.25s on regtest** and 10s elsewhere. A regtest node mines on demand — usually from the very script that is waiting — so a 10s poll meant sleeping ten seconds after the block already existed.

## Waits no longer overshoot the deadline they were given

The poll happens before the sleep, so an unclamped `sleep(interval_s)` ran the wait to the next interval boundary rather than to `timeout_s`. Measured at `timeout_s=0.2, interval_s=3.0`, the timeout fired after **3.00s** — a 15x overshoot. A milliseconds/seconds slip in a caller would turn that into hours.

Fixed in `network/confirm.py`, and in **`btc_wallet/htlc_leg.py`**, whose funding wait had the identical shape. That one matters more than its size suggests: on an HTLC leg, the deadline is when the caller stops waiting for funding and starts deciding about the refund path.

## Non-finite arguments are refused instead of hanging

`nan` and `inf` passed every existing check — `nan <= 0` and `inf <= 0` are both False — and each broke the wait differently. A `nan` deadline is never reached; `asyncio.sleep(nan)` never returns.

Worse in combination: once the deadline clamp landed, `max(0.0, nan)` collapsed to `sleep(0.0)`, turning `BitcoinTaprootLeg`'s funding wait into roughly **590,000 reads per second** against the funding reader with the deadline never firing. The fix for one bug created the second; both are closed now.

`interval_s=0` is still allowed, because a test injecting a fake `sleep` legitimately wants no delay — but only together with `max_iterations`. Unbounded, it polls the node **644,164 times a second** for the whole timeout.

## Wait parameters are validated where they are spelled

`GlyphMinter` and `GlyphClient` now bound their wait arguments at construction: `poll_interval_s` finite and `>= 0.001s`, `confirmation_timeout_s` finite and `<= 1 year`, `min_confirmations` an `int >= 1`. These previously constructed fine and failed later — or, for a sub-millisecond interval, did not fail at all and simply busy-looped.

Each class now refuses by its own name, rather than deferring to an error that said `GlyphMinter` about a parameter the caller had spelled on `GlyphClient`. The rule itself lives in one place, `network/confirm.py`, with the constructors importing it downward.

## Test coverage that should have existed

`ft_funding`'s fee estimate — the number deciding which plain-RXD UTXO can pay an FT transfer's fee — had no test at all. A mutation sweep found 104 surviving mutants across its two lines, including one that deletes the 2x headroom its own docstring promises. No defect shipped; nothing would have noticed if one had.

Two new mutation-testing groups came out of this work, `mint` and `glyphscript`, with survivor worklists published under `docs/reference/mutation-survivors/`. Effective kill rates against killable mutants: script 92%, client 86%, mint 82%, transfer 76%, payload 75%.

The offline suite now runs **147.8s, down from 175s** on the same machine — three tests were each paying 10.01s to wait out a poll interval they had no way to shorten.

## Upgrade notes

Both changes below refuse input that previously constructed. If you pass wait parameters programmatically, check them against the bounds above.

- `wait_for_confirmation` rejects non-finite arguments, and rejects `interval_s=0` unless `max_iterations` bounds the loop.
- `GlyphMinter` and `GlyphClient` validate `poll_interval_s`, `confirmation_timeout_s` and `min_confirmations` at construction.

## Still true

The swap stack remains **unaudited**. An external audit is a hard gate before it is used with real value.
