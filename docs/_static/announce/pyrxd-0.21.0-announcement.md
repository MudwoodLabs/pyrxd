⚡ **First RXD↔USDT atomic swap — real value on both public mainnets**

1.000000 USDT ↔ 1000 photons, Radiant mainnet ↔ Ethereum L1, about $0.20 in gas.

No bridge, no custodian, no wrapped RXD, no issuer — both legs settle or neither does. The same corridor carries Glyph FTs and NFTs, so a Glyph token can trade against a major stablecoin the same way.

```
USDT HTLC  0x181B841dba4eb8B92A94bB5A138F5f7A95d1d9Da
RXD claim  54641bb753fe59bd873d941e0f2779180a3079ae123514a0763dd31afcd24ed6
```

**Also out — 0.19.0 through 0.21.0.** `GlyphClient` puts minting and transfers behind one object. NFT transfers work with ordinary dust-carrying carriers. `deploy-ft --treasury` checks the address network before the premine lands. Broadcast txids are derived from the bytes we signed rather than taken from the node. And `pip install 'pyrxd[eth]'` now gets you the Ethereum stack.

```
pip install -U pyrxd
```
Open-source, Apache-2.0, provided as-is — the same posture as Radiant Core itself. This run was single-operator; verify your outputs before moving real value.

https://pypi.org/project/pyrxd/
