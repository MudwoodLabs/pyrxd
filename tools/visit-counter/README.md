# Visit counter

Three one-line pages that count visits to the pyrxd tool pages
(`mudwoodlabs.github.io/pyrxd/inspect/`, `/verify/`, `/playground/`) with Cloudflare Web Analytics.

## Why a separate site

The tool pages pin every script they run with a SHA-256 check, and Cloudflare's beacon cannot be
pinned. So the beacon runs here, in a frame from a **different origin**: the browser's same-origin
policy keeps it from reading or scripting the tool page. Cloudflare also requires a real `Origin`
or `Referer` on each beacon, which rules out a sandboxed same-site frame (its origin is `null`).

- Each tool page frames `https://count.mudwoodlabs.com/<tool>.html` and admits that host only in
  `frame-src`. `tests/web/test_page_visit_counter.py` pins this.
- `_headers` gives every page here a CSP that runs only the beacon, and `frame-ancestors` lets only
  `https://mudwoodlabs.github.io` frame them.
- Cloudflare learns that someone loaded a tool page, from the visitor's IP address and browser, as
  for any request. Ad blockers, including Brave Shields, block the beacon, so counts are a floor.

## Hosting

- **Where:** Cloudflare Pages project `pyrxd-count`, custom domain `count.mudwoodlabs.com`.
- **Web Analytics site:** `count.mudwoodlabs.com`. Its token is in the three pages; its site tag is
  in the `CF_SITE_TAG` repository variable with the docs site's, comma-separated, so
  `scripts/collect_web_analytics.py` reads both.
- **Not behind Access:** browsers must be able to load these pages anonymously.

## Deploy

```bash
CLOUDFLARE_ACCOUNT_ID=<Mudwood account id> \
  npx --yes wrangler@4 pages deploy tools/visit-counter \
  --project-name=pyrxd-count --branch=main --commit-dirty=true
```

The first time, create the project (`npx wrangler@4 pages project create pyrxd-count
--production-branch=main`) and add the custom domain in the Pages project's settings.
