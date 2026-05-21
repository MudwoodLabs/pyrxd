# BTC recovery procedure (real-BTC announcement swap, 2026-05-21)

The real-BTC swap moves BTC through two addresses, BOTH controlled by keys in
this spike's gitignored dotfiles. The covenant only READS the payment via SPV;
it never controls the BTC. So the BTC is fully recoverable.

## Where the BTC is

1. User sends ~11,000 sats → **taker funding wallet** `bc1qz0c6hlkas7lcyk7978uyst8h56aq7d67geehwc`
   key: `.taker_btc_funding_wallet.json` (WIF)
2. We spend that → **maker BTC address** `bc1qnx2untpmmye2whw2xg57xx2ux4zdtkekvgl05n`
   (10,000 sats covenant payment) — key: `.maker_btc_keypair.json` (WIF)
3. Final resting place of the BTC: the maker address, ~10,000 sats.

## To recover (sweep back to a user-specified BTC address)

Use `pyrxd.btc_wallet.build_payment_tx` with the maker keypair (from
`.maker_btc_keypair.json`) spending the maker-address UTXO → user's address,
fee ~110-150 sats at 1 sat/vByte. Net recoverable ≈ 10,000 − sweep fee.

Unavoidable loss = network fees across the hops (~few hundred sats total) +
whatever change dust was dropped to fee. Everything else is recoverable.

## Keys (gitignored — never committed)
- `.taker_btc_funding_wallet.json`
- `.maker_btc_keypair.json`
