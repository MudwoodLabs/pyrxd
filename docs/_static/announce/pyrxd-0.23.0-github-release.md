Most of this release came from one audit — of a defect class rather than a component.

## Assertive text is a claim, and no test evaluates claims

Tests pin that a sentence is *emitted*, never that it is *true*. So prose drifts from the code beside it in silence, and prose is what people act on. Chasing that turned up six fund-safety defects sitting underneath sentences that read as settled.

## Read this first if you use `pyrxd swap reserve`

`swap reserve` prints **"Reclaim at `--expiry` is GUARANTEED"** on the consent screen. Its only amount guard refused below the 546-photon dust floor — but a refund pays its fee *out of* the covenant value and must still leave a non-dust output, so it needs roughly **2,000,000 photons**.

Measured through the production builders: reservations of 546, 100,000, 1,000,000 and 1,900,000 photons were all accepted and then produced **no refund at any fee**. `swap cancel` — documented as the only hard revocation there is — failed identically. **If you reserved below ~0.02 RXD on any earlier version, those funds are not reclaimable by any pyrxd path.**

## The ETH runner's "THE safety gate" was exactly inverted

`assert_t_rxd_fits_the_eth_deadline` named the sizer's output `largest` and refused anything above it — while #482 had already turned that sizer into a *lower* bound. Measured against the relation the protocol actually enforces, it **accepted every unsafe value and refused every safe one**, while the runner printed `margin OK: (independent check passed)`.

Its error text quoted the pre-#482 relation and told operators to *shorten* `t_rxd`, which is the exploitable direction. The too-short direction is backstopped downstream, so this was not by itself a clean theft path — the harm was refusing honest configurations under a reassuring message, and documenting the unsafe direction as safe.

## Four more, briefly

- **A zero relative lock, one unit tag away.** `refund_leaf_script`'s floor was BLOCKS-only; BIP68 quantises time locks to 512 s, and the unit tag comes off the *wire*. A counterparty envelope carrying `{"value": 0, "unit": "seconds"}` produced a refund leaf spendable in its own funding block. The refusal now keys on the encoded magnitude.
- **A covenant whose owner can change**, classified "transfer is impossible at consensus" — and gating credential binding before a maker locks an asset.
- **A "dormant-by-construction" interlock that did not exist.** The function it rests on has returned `None` since 0.9.0.
- **A claim-finality verdict arming one block shallower than policy**, under a docstring saying the two "cannot diverge".

## Documentation that taught defects to other implementations

The BIP143 porting guide exists so others can implement Radiant's sighash in another language. It told them to sort refs "ascending by their 36 bytes" — the code sorts by the *reversed* bytes, and the lexicographic reading is the bug that made dMint signing fail ~50% of the time against a real node. It also said to scan two of the five ref-operand opcodes; missing the others was measured at ~80% of refs wrong.

**The two sort orders agree for single-ref outputs**, so a porter's own vectors pass.

The README claimed swaps were "proven end-to-end … against BTC, ETH, and EVM L2s (Base / Optimism / Arbitrum / Linea)" while this repo's own reference table marks six of those rows **not run**.

## Also

HashMark labels are now checked against §5.4 — a v2 signer could otherwise forge a line *inside* the block marked "signature VERIFIED". A documented TR39 confusables check that had **no production caller** is wired. HashMark records did not classify at all in the browser; they now degrade to `UNVERIFIABLE` rather than failing the decode. `validation.h`, `consensus.h` and `uint256.h` are vendored — 44% of this repo's citations into Radiant Core previously pointed at files no test could read, which is exactly how the ref-backing defect shipped.

Four **changelog entries were corrected rather than extended** — three of them repeated claims this very release refutes. A release note is read more than any docstring.

## Still true

The cross-chain swap stack is **unaudited**. An external audit remains the hard gate before real value.

Full detail in [CHANGELOG.md](https://github.com/MudwoodLabs/pyrxd/blob/v0.23.0/CHANGELOG.md).
