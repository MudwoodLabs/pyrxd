A security release, most of it from re-reviewing the previous release's own fixes.

## Upgrade if you use `MultiSourceBtcDataSource`, swap recovery files, or a custom `fee_rate`

- **A minority of BTC sources could win a quorum read by making the honest ones unreachable.** Votes were counted over the sources that *answered*, so silence read as absence rather than dissent — and an attacker never has to out-argue an endpoint it can make unreachable. Measured against the previous source: **three lying sources of seven, at the default `quorum=2`, had their forged value returned once two honest endpoints were down.** Seven fund-critical reads route through this, raw transaction and merkle proof included. The winning group must now outvote every source that did not back it. `get_tip_height` had the same shape plus one of its own: because the configured `quorum` also floored the index, raising it made the tip *more* deflatable — at five sources with `quorum=5` a single source reporting 0 returned 0.
- **Swap recovery files were read with a bare `json.loads`** — no mode, ownership, symlink or size check — while the single-key `--fee-wif-file` beside them had gone through the hardened reader all along. In a single-operator harness run that one file holds **both** counterparties' spending keys. The writer creates it `O_EXCL` at 0600; the gap was every way a correct file stops being one — `cp`, `rsync -p`, an unzip, a restore from backup. Worth checking the mode on any you kept.
- **The recovery-file key gate now decodes values rather than matching field names.** A name list only recognises the names somebody thought of. Measured with a real WIF: `{"key": …}`, `{"priv": …}`, `{"parties": [wif, wif]}` (no field name at all) and `{"recovery_phrase": "<12 BIP-39 words>"}` were all judged keyless and read at 0644 with the key in them. Every string is now decoded as a WIF, an xprv, or a BIP-39 phrase.
- **A fee rate is now bounded from above as well as below.** The shared gate refused anything under the relay floor and accepted anything over it. An NFT transfer and a sweep have no change output, so the whole overpay leaves with the miner. Measured on `build_nft_transfer_tx`: `fee_rate=10_000_000` — the per-**kB** constant that sits one import away from the per-**byte** one — burned **2.31–2.33 billion photons (23.1–23.3 RXD)** off a 228–230 byte transfer, silently, with the build reporting success. The ceiling is 100,000 photons/byte; `allow_overpay=True` is the deliberate opt-out.

Also fixed: a TOCTOU in the wallet seed file's permission check, `redact()` letting a mnemonic through unless it was written in lowercase (steel backup plates are uppercase-only), duplicate outpoints accepted by three FT builders — and a hex-case bypass of those new guards — `min_confirmations=0` returning `confirmed=True` at zero depth, and a vestigial tip read that could abort a BTC confirmation wait outright.

## Three of the fixes are guards that refused valid work

The fee-overpay ceiling shipped with no reachable override, so `RxdWallet(pk, url, fee_rate=150_000)` had nowhere to go. `NetworkProfile` rejected `ws://127.0.0.1` beside a `wss://` endpoint — the ordinary developer layout — under the rule that stops failover silently downgrading TLS. And the BTC tip quorum demanded an exact match on the one value honest sources legitimately disagree about, so a one-block propagation skew aborted an HTLC confirmation wait.

Radiant has neither RBF nor CPFP, so a refusal during a timelock race costs the same funds a wrong answer would.

## The tests

Mutation testing now reaches the code that decides how much value moves and to whom, not only the consensus arithmetic: seven new groups covering fee sizing, the wallets, the Glyph and swap builders, the coordinator, and `network/`. First full baseline — **8,171 mutants, 5,049 killed (61%)**, 5h36m of compute. All 3,122 survivors are listed with `file:line` in [`docs/reference/mutation-survivors/`](https://github.com/MudwoodLabs/pyrxd/tree/main/docs/reference/mutation-survivors), and a weekly CI lane keeps the numbers current.

Two hand-mutation sweeps found guards that were already **correct**, with nothing able to notice their removal. In the HTLC swap stack, 104 planted defects against the 1,606-test swap suite left **14** survivors — several coordinator steps broadcast *before* they advance the FSM, so the method's own state precondition is the only thing between a wrong-state call and an irreversible broadcast. Across the network boundary, 113 neutered guards left 12 survivors, 11 of them real; the sharpest was a binding that was thoroughly tested in isolation while **deleting its call site left all 8,777 offline tests green**. Every new test names the mutant it kills and was proved by planting that defect and watching the suite go red.

## Also new

`pyrxd glyph inspect` names four more script shapes — `soulbound-covenant` (only on an exact round-trip against pyrxd's own builder; a looser marker match reports `self-replicating-covenant`, since dMint and mutable-NFT scripts carry the same markers), `p2pkh-cltv` and `p2pkh-csv` for the HTLC refund legs, and `p2sh`. An unnamed script now reports `token_bearing` and its `input_refs[]`, because spending a ref-carrying UTXO as plain funding destroys the token it carries.

## Upgrade notes

Multi-source BTC reads need a majority of the **configured** sources, not of the ones that answered — if you genuinely want to trust one source, configure one. A recovery file containing a private key is refused unless it is `0600`; one holding only public locators and pkhs is still readable at `0644`. Fee rates above 100,000 photons/byte need `allow_overpay=True`. `wait_confirmations(min_confirmations=N)` requires `N >= 1`. Full detail in the [CHANGELOG](https://github.com/MudwoodLabs/pyrxd/blob/main/CHANGELOG.md).

---

The cross-chain swap stack remains **experimental and UNAUDITED**. An external security audit and a live two-party adversarial run are still the hard gates before real value.
