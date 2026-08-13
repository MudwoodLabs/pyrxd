⚡ **pyrxd 0.18.0 is out**

Nine releases since we last posted (0.11.0), mostly security hardening — a long stretch of tightening the parts that move value.

```
pip install -U pyrxd
```

✅ **What's better**

**Token transfers send exactly what you asked.** Before 0.14.0, `glyph transfer-ft` sized the token amount from the RXD side and could send more than intended. Fixed in 0.14.0 — if you made FT transfers before then, a balance check is worth the minute.

**Collections behave.** The `child_ref=` argument on a container reveal destroyed the child token rather than linking it; removed in 0.15.0. Radiant can't link a container to a live child at all — collections work through the child's metadata instead.

**Files that hold keys are treated like it.** Swap recovery files now go through the same owner, mode and symlink checks as everything else in the SDK. If you've kept any, `ls -l` should show `-rw-------`.

🔒 **Under the hood**

Multi-endpoint Bitcoin checks now need a majority of the endpoints you *configured*, not just of the ones that answered — silence no longer counts as agreement. Fee rates are bounded from above as well as below, so a mistyped rate can't quietly overpay. The seed-phrase redactor now catches uppercase phrases, which is how steel backup plates are stamped. And the wallet seed permission check is race-free.

🆕 **New**

`glyph inspect` names soulbound covenants, timelock scripts and P2SH instead of `unknown`. Mutation testing now covers fees, wallets, builders and the swap coordinator. Also since 0.11.0: watch-only wallets, FT airdrops, dMint premine and ElectrumX failover.

Most of this came from asking whether our own tests *could* fail, and from re-reviewing our own fixes.

Apache 2.0, as-is. The cross-chain swap stack is **experimental and unaudited** — an external audit and a live two-party run remain the gates before real value.

📦 https://pypi.org/project/pyrxd/
