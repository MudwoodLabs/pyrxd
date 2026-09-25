This release fixes WAVE names that pyrxd built but the public indexer never registered, and makes pyrxd pay the WAVE protocol's registration fee when it registers one. It also fixes dMint contracts pyrxd deployed that could never be minted, and adds `pyrxd verify` for checking a HashMark record. **Several changes break callers.** Read the last section if you build WAVE names, construct reveal results yourself, read `parse_mint_scriptsig`, or exchange encrypted Glyph content with pyrxd 0.24.0.

## WAVE names built by `build_wave_metadata` never registered

`build_wave_metadata` wrote the qualified name (`alice.rxd`) into `attrs.name` and left the top-level `name` empty. RXinDexer registers a claim from `attrs.name` and refuses any character outside `a-z 0-9 -`, so it skipped every such claim without an error. The reveal confirmed, the fee was spent, and the name never resolved. This is read from RXinDexer's source; no pyrxd-built claim was checked against a live indexer.

pyrxd now writes the claim with Photonic's field set: the qualified name at the top level, and the bare label in `attrs.name`. A regtest node confirms the new claim. Every path that can write a WAVE claim now applies one label rule before the commit: 3 to 63 characters of lowercase `a`–`z`, `0`–`9` and `-`, with domain `rxd`. Non-ASCII names are written as `xn--` punycode.

**If you minted a name with an earlier pyrxd:** an update cannot repair it, because the indexer applies updates only to names it registered. Registering the label again is a new, first-come claim. A commit made by 0.24.0 and not yet revealed can still be revealed with `allow_unregistrable_wave=True`, which recovers its value without registering the name. The recipe is in `GlyphBuilder.prepare_wave_reveal`'s docstring.

## Registering a WAVE name pays the protocol's fee

The WAVE protocol charges a one-time, length-based registration fee, paid to the protocol treasury `1GrwkQNJfjbEJjH25heszNZLpbZou8nfXG`:

| Name length | Fee |
|---|---|
| 3 characters | 100 RXD |
| 4 | 50 RXD |
| 5 | 10 RXD |
| 6 or more | 5 RXD |

pyrxd now pays it by default, as Photonic does.

- `pyrxd glyph mint-nft` checks that the name is free before the commit and again before the reveal, and refuses one that is taken.
- The fee is paid from a wallet input in the reveal itself, so it leaves the wallet only in the transaction that registers the name.
- The confirmation shows the fee, the treasury and the total before anything is broadcast.
- `--no-wave-registration-fee` opts out. The indexer does not check the fee at registration, but it requires the same payment to renew the name.

A mint interrupted after its commit no longer loses track of it. The command saves a record before broadcasting, and every exit after the commit prints the exact `pyrxd glyph resume-mint <txid>` command that finishes it.

## dMint contracts pyrxd deployed that could never be minted

pyrxd's contract builders had defects that made some deployed contracts unmineable from the moment they confirmed, whichever miner found the nonce:

- An adaptive (ASERT or LWMA) contract was deployed with a `lastTime` that its first retarget could not read.
- A V1 contract at difficulty 256 or more carried a target encoded in a way the covenant cannot read.
- A BLAKE3 or K12 contract carried a target too wide for the covenant's arithmetic.

The adaptive-contract fix was proven on a Radiant Core regtest node, with a control: the new contract mints, and the old shape is refused by the node. The V1 and BLAKE3/K12 fixes make pyrxd's contract bytes agree with a transcription of Photonic's builder. For contracts already deployed in these shapes, `claim-dmint` and `dmint-estimate` now say they can never be minted, instead of grinding for a mint the node would reject.

pyrxd can now also build a contract's **final** mint, and it parses mainnet V1 contracts deployed at difficulty 256 or more, which it previously called "not a dMint contract".

## `pyrxd verify`: check a HashMark record with one command

`pyrxd verify <txid> --min-confirmations N` answers four questions:

- who signed the record;
- whether a file matches it (`--file`), hashed on your machine;
- whether a WAVE name pointed at the signing key at the mark's block (`--wave-name`);
- whether the block is buried deep enough.

It exits 5 when the verdict does not hold. The report says what a verified signature supports, which is that the key had signed this digest by that block, and does not claim authorship. The documentation site's `/verify/` page checks a record's signature, a chosen file and the block in the browser, with nothing to install.

## Also in this release

- **`glyph inspect`**:
  - Shows whether a reveal's metadata matches the `payload_hash` its commit committed to.
  - Answers HashMark §7.6 form 2 with `--wave-name`.
  - No longer crashes on an oversized integer anywhere in a transaction.
- **`--verify-wave`** works with the default servers. Indexer reads now fail over past a server that does not run the RXinDexer extension, which the first default server does not.
- **`WaveResolver.check_available`** reported every name as available. It now reports registered names correctly.
- **`mnemonic_from_entropy(b"")`** returned a random mnemonic. It now raises.
- **Photonic interop**: Photonic's decryption now opens pyrxd's recipient wraps, and pyrxd opens Photonic's. Photonic's unlock screen still cannot fetch pyrxd-minted content, because pyrxd writes no storage locator. Valid Photonic burns are no longer reported as "no burn proof output found".
- **A native SHA256d grinder**, shipped as C source, mines dMint proof of work about 12 times faster than the bundled Python miner on one 32-thread machine. Nothing is added to the default install.
- **`pyrxd regtest`** builds and runs Radiant Core v3.1.2.

## Breaking changes

- **WAVE labels:** `build_wave_metadata` and every writer refuse labels outside the rule above. That includes non-ASCII names, which must be written as punycode, and 1–2 character names. `attrs.name` now holds the bare label.
- **WAVE fee in the SDK:**
  - The reveal builders return a required `registration_fee_output` for you to add to the reveal.
  - `build_reveal_scriptsig_suffix` and `build_mutable_scriptsig` refuse a registering payload until `registration_fee=` is stated.
  - `measure_reveal_fee` raises for a registering reveal unless the fee is stated.
  - Code that constructs `RevealScripts` and its siblings directly must pass the new field.
- **`mint-nft` and `timelock-mint`** now wait for the reveal to confirm, and exit 2 if it has not confirmed by the timeout.
- **Encrypted content:** content wrapped by this release cannot be opened by pyrxd 0.24.0 or earlier. Content 0.24.0 wrapped still opens here, as described in the changelog.
- **`GlyphInspector.parse_mint_scriptsig`** returns `nonce_width` instead of `version_hint`. The hint called almost every mint of a V1 contract "v2".

The full list, with measurements, is in [CHANGELOG.md](https://github.com/MudwoodLabs/pyrxd/blob/main/CHANGELOG.md).
