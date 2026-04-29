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
- Subscribe to GitHub Security Advisories for this repository

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.2.x   | ✅ Yes (current) |
| < 0.2   | ❌ No (pre-public release; do not use) |

Once we reach 1.0, the policy will move to a published support window
covering at least the current major and the most recent minor of the
prior major.
