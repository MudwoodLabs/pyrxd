# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in pyrxd, please report it
**privately** rather than filing a public GitHub issue.

Send disclosure to: **security@mudwoodlabs.com**

Include:

- A description of the issue and its impact
- Reproduction steps or a proof-of-concept
- Affected versions of pyrxd (and Python, if relevant)
- Your name / handle for credit (optional — anonymous reports accepted)

We aim to:

- Acknowledge receipt within **2 business days**
- Provide an initial assessment within **7 business days**
- Coordinate a fix and disclosure timeline based on severity, typically
  within **90 days** following Google Project Zero norms

We will publicly credit reporters in the changelog and security
advisories unless you request otherwise.

Our internal handling steps — triage, private fix, coordinated disclosure,
and release — are documented in
[`docs/runbooks/incident-response.md`](docs/runbooks/incident-response.md).

## Scope

Security reports are welcome on:

- Cryptographic primitives in `pyrxd.curve`, `pyrxd.security`,
  `pyrxd.aes_cbc`, `pyrxd.crypto`
- Key derivation in `pyrxd.hd` (BIP32/39/44)
- Transaction construction and signing in `pyrxd.transaction`,
  `pyrxd.script`
- Glyph token protocol handling in `pyrxd.glyph`
- Gravity Protocol covenant code in `pyrxd.gravity`
- Network code in `pyrxd.network` (ElectrumX client)

Out of scope:

- Vulnerabilities in dependencies (please report to the upstream project)
- Social-engineering attacks against pyrxd users or maintainers
- Issues requiring physical access to a victim's device
- Issues already documented in the public CHANGELOG or issue tracker

## Safe Harbor for Good-Faith Research

We support security research conducted in good faith and will not pursue or
support legal action against researchers who:

- Make a good-faith effort to avoid privacy violations, data destruction, and
  service disruption while testing;
- Test only against their **own** wallets, keys, and testnet/regtest deployments
  — never against another user's funds or a third party's infrastructure;
- Do not exploit a finding beyond the minimum needed to demonstrate it, and do
  not exfiltrate, retain, or publicly disclose others' data;
- Report privately (see above) and give us reasonable time to remediate before
  any public disclosure.

This is **authorization to test within those bounds — not a paid bug bounty.**
pyrxd is a volunteer-maintained, pre-1.0, open-source project; there is **no
monetary reward** at this time. We credit researchers in this file and the
changelog with their consent. If demonstrating a finding would require moving
real value, describe the mechanism instead — never put anyone's funds at risk.

## Status

pyrxd is **pre-1.0 software**. The cryptographic primitives have not
been independently audited. Use at your own risk for production
deployments. The library is in active development; APIs may change
between minor versions before 1.0.

If you are deploying pyrxd in a production system handling real funds:

- Pin to a specific commit SHA in your `pyproject.toml` / requirements
- Run integration tests against a regtest or testnet network before
  any mainnet broadcast
- Hold private keys outside the web tier — see the architectural
  pattern in our README under "Production Architecture"
- Watch this repository's **Releases** — security-relevant defects are
  disclosed in the release notes and recorded under "Known security-relevant
  defects in published releases" below, not as GitHub Security Advisories

## Known security-relevant defects in published releases

Recorded here rather than as a GitHub Security Advisory, because the affected
population is reachable through this repository and the release notes rather
than through dependency scanners.

### The published handshake spec and conformance vectors taught the timelock ordering backwards

**Affected: every release through 0.22.0.** **Fixed in 0.22.0.**

`conformance/htlc-handshake-vectors.json`, shipped in the sdist at schema
`radiant-htlc-handshake/1`, **accepted `t_btc=60 / t_rxd=20`** and **rejected
`t_btc=20 / t_rxd=60`** — the correct ordering, published under the name
`margin-inverted-ordering`. `docs/htlc-handshake-wire-format.md` and four
user-facing guides stated the same relation the same way round.

The accepted layout is the one in which the maker refunds its own leg while the
preimage `p` is still secret and *then* claims the counter leg with `p`, taking
both, with no recourse for the counterparty. The maker holds `p`; it **locks**
the Radiant leg and **claims** the counter leg, so the leg it locks must carry
the **longer** refund window (Herlihy, *Atomic Cross-Chain Swaps*,
[arXiv:1801.09515](https://arxiv.org/abs/1801.09515) §1).

**Scope, stated precisely in both directions.** pyrxd's own gate was *fail-safe*
under the superseded rule: this library refused to build the layout its own
specification described. The exposure was to **a second implementation built
from the published material** — one that derived the ordering correctly would
have run these vectors, failed, and been told by a specification with a passing
test suite behind it to invert into the vulnerable arrangement.

**If you implemented a Radiant HTLC against any pyrxd handshake material
published before 2026-09-02, re-derive your timelock ordering.** The vectors are
regenerated from the builders and the schema is bumped to
`radiant-htlc-handshake/3`, so a consumer pinned to `/1` can tell the two apart
by version.

A second defect sat underneath it and is also fixed in 0.22.0: the margin was
compared in **raw block counts across two chains**. A Radiant block is ~300 s
against Bitcoin's ~600 s, so `t_rxd=180` "exceeded" `t_btc=144` by 36 blocks
while being 15 h against 24 h in wall clock. The relation is now evaluated in
seconds, which means **honest swaps need a longer Radiant leg than before** —
re-check your parameters rather than only bumping the version.

**Not affected:** the Glyph stack — minting, commit/reveal, Wave names, key
derivation, transfers and resolution. `pyrxd.glyph` does not import
`pyrxd.gravity`; a mint never loads the swap code. Deployments using pyrxd only
for Glyph/Wave operations are untouched by the above.

## Supported Versions

pyrxd is pre-1.0: the API and on-chain formats may change between minors, and
security fixes land on the latest minor only. Security-relevant fixes have
already shipped across recent minors (e.g. the HTLC preimage-length pin in
0.8.0), so running an older release means running known-unfixed code — upgrade
to receive them.

| Version | Supported |
|---------|-----------|
| Latest published minor | ✅ Yes — receives security fixes (see CHANGELOG / PyPI) |
| Any earlier release     | ❌ No — upgrade to the latest minor |

Once we reach 1.0, the policy will move to a published support window
covering at least the current major and the most recent minor of the
prior major.
