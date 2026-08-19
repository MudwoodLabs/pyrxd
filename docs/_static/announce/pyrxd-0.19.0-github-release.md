One object for minting and moving Glyph tokens — and the fund-safety work that came out of reviewing it seven times.

## `GlyphClient`

`from pyrxd import GlyphClient` composes the existing `GlyphMinter` with a new library-level transfer path. The `PendingStore` is optional: minting needs one, transfers do not.

NFT transfers are importable for the first time. `GlyphBuilder.build_nft_transfer_tx` spends the singleton alone and takes the fee out of its own value, so at Radiant's relay floor it refuses any carrier holding less than ~2,330,546 photons — measured, i.e. every ordinary dust-carrying NFT. `GlyphClient.transfer_nft` keeps the singleton's value intact and funds the fee from a separate plain-RXD input. The old builder is unchanged and still correct for a carrier that can pay its own way.

`examples/ft_transfer_demo.py` needed 399 hand-rolled lines because the working implementation was reachable only as private CLI helpers. It now calls the library.

## The txid of a broadcast is no longer taken on trust

`broadcast` returns whatever the node says, and the reply was only format-checked. A lying or buggy ElectrumX could drop a transaction and echo any well-formed txid — including a real, already-confirmed one — leaving the caller polling a txid unrelated to their tokens, seeing "confirmed", and believing a transfer happened that did not.

Every fund-moving path now derives the txid from the bytes it signed. FT transfers, NFT transfers and airdrops raise `BroadcastEchoMismatch`, which carries `local_txid` and is deliberately **not** a `ValidationError` — those are raised before anything is sent, and a caller retrying on one would re-broadcast a transfer that already moved tokens. `deploy-dmint` built its `contracts` outpoints and `premine_outpoint` straight from the echoed reveal txid; those are what miners grind against and the owner later spends.

## A fee ceiling that was unreachable on the only path that mattered

The overpay ceiling was waived whenever a reveal was not given an explicit `fee_rate=` — which is the only path `mint_nft` and `deploy_ft` take. `PendingMint` restores its stored rate from disk checking only that it is a positive integer, so a record written before the ceiling existed could carry a per-**kB** figure in a per-**byte** field.

Measured on such a record, funded to match: the reveal paid **2,600,000,000 photons (26 RXD)** on a 260-byte transaction, with no refusal and no warning. Nothing downstream caught it — `assert_pays_for_its_size` returns as soon as the fee covers the size, so it is a floor check an overpay passes trivially. The rate is now judged before it is spent, at both ends, whatever its provenance.

## Two destinations were not pinned to the network

`glyph transfer-nft` did not pin its recipient, and `glyph deploy-ft --treasury` — which receives the **entire premined supply** — did not either. `address_to_public_key_hash` decodes a testnet address into a perfectly valid-looking 20-byte PKH, so a pasted address of the wrong network would have built, confirmed, and locked tokens to a script no key on this network can spend. There is no refund path and no RBF.

Both are pinned now, on all three networks. Pinning them surfaced a second bug: `Network` has only `mainnet` and `testnet` while `--network` also accepts `regtest`, so the shared guard crashed with an unhandled `ValueError` on the one network the `pyrxd regtest` developer onramp is built around.

## Guards that refused honest work

Three of this release's own fixes had to be fixed again for refusing valid input, which is the failure mode this project keeps hitting:

- Judging the fee rate at construction also refused every legitimate sub-floor rate — a regtest node's floor really is a tenth of mainnet's — so a regtest minter could not be built at all. `allow_below_relay_floor` is now a constructor argument that reaches the reveal.
- `allow_below_relay_floor or self._allow_below_relay_floor` swallowed an explicit `False`, overruling a caller who deliberately re-asserted the floor.
- `GlyphClient.reveal_nft` defaulted that flag to `False` and forwarded it, which the minter reads as a deliberate override — so a client built for a sub-floor chain broadcast its commit and was then refused its own reveal, stranding a hashlock that has no owner-only spend path.

Radiant has neither RBF nor CPFP, so a refusal costs the same funds a wrong answer would.

## CI

The Python 3.10 and 3.11 jobs took **39.0 and 34.2 minutes against 3.12's 8.2**, on identical tests. The whole gap was `ast.get_source_segment`, called per AST node by the consensus-constant guards: it re-splits the entire file on every call, and 3.12 added a bound the older versions lack. Sources are now split once and cached; the matrix runs **8.3 / 7.8 / 6.7 minutes**. Equivalence with the stdlib is pinned by 14 tests covering CRLF, lone CR, form feed, vertical tab and multi-byte offsets, because a faster answer that differs would turn a real consensus-constant violation into a pass.

## How this was reviewed

An eight-reviewer panel, then seven adversarial rounds. **Every round found a defect introduced by the previous round's fixes** — including two that moved funds: the 26 RXD burn above, and the stranded commit. The last round found five false claims in these release notes' own source, two of them describing fund-safety properties the code does not have.

Two lanes disagreed about the severity of the burn; one had funded its test commit too small to pay the overpay, so the build died of insufficient funds and looked contained. Resolving that disagreement, rather than taking the reassuring answer, is what turned it from MEDIUM into a measured 26 RXD.

Every new test was verified by planting the defect it targets, watching the suite go red, and restoring. Two mutants that fully reverted an earlier round's headline fix had passed 129 and 97 tests respectively.

**9,241 tests pass.** Known gaps are tracked in #457, #458 and #459.

## Upgrade notes

Three refusals changed from `ValueError` to `ValidationError` (which does not subclass it) — this affects only callers tracking `main`, since all three functions postdate the 0.18.0 tag. A fee rate above 100,000 photons/byte is refused at construction; `allow_overpay=True` is the opt-out. Constructing a minter below the relay floor needs `allow_below_relay_floor=True`. Full detail in the [CHANGELOG](https://github.com/MudwoodLabs/pyrxd/blob/main/CHANGELOG.md).

The swap and gravity stacks remain experimental and unaudited.
