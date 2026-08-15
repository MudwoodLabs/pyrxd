⚡ **pyrxd 0.17.0 — please upgrade**

Eight releases since we last posted (0.11.0, a month ago). Most of that work was security, and some of it affects anyone still on 0.11.x–0.13.x.

```
pip install -U pyrxd
```

🔴 **Two things to check, not just upgrade past**

**If you moved FTs with `glyph transfer-ft` before 0.14.0** — it could send far more than you asked, up to your whole balance. For a Glyph FT an output's value *is* its unit count, and the recipient output was sized from the inputs' RXD instead of the requested amount. Asking to send 250 from a 50,000,000-unit holding sent 46,739,454.

**If you built collections with `prepare_container_reveal(child_ref=...)` before 0.15.0** — that call permanently destroyed the child token. Upgrading doesn't bring it back; check whether tokens you expected in a collection still exist. A script-level container→live-token link is impossible on Radiant, so the call is gone rather than fixed.

Also fixed: every MUT and WAVE reveal was rejected by consensus (no WAVE name could ever be registered), and `wallet send` built below the relay floor about a third of the time — unrepairable, since Radiant has neither RBF nor CPFP.

🆕 **New**

📜 Normative **Glyph protocol spec** + **cross-chain HTLC handshake wire format**, with conformance vectors
🔑 Watch-only **descriptor export** (`wallet export-xpub --descriptor`)
🪙 **FT airdrop**, **dMint deploy-with-premine**, **offline swap recovery**
🌐 ElectrumX **registry + failover + optional TLS pinning**
🔬 `glyph inspect` now reads soulbound covenants, CLTV/CSV timelocks and P2SH

Most were found by asking whether the tests *could* fail — several guards shipped correct with nothing able to detect their removal.

Apache 2.0, as-is. The cross-chain swap stack remains **experimental and unaudited**; an external audit is still the gate before real value.

📦 https://pypi.org/project/pyrxd/
📚 https://mudwoodlabs.github.io/pyrxd/
