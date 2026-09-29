# pyrxd Adoption Signals

A single static page that charts PyPI downloads and GitHub traffic for pyrxd.

It holds no data. When it loads, it fetches:
- `pypi.json` and `traffic.json` from the `traffic-data` branch, which the daily `traffic.yml` job updates;
- the release list from the GitHub API, for the release markers.

So it is current without being rebuilt. Redeploy only when this page's own code changes.

## Hosting

- **Where:** Cloudflare Pages project `pyrxd-stats`, served at `stats.mudwoodlabs.com`.
- **Who can open it:** Cloudflare Access restricts it to the maintainer. The Access app covers `stats.mudwoodlabs.com`, `pyrxd-stats.pages.dev` and `*.pyrxd-stats.pages.dev`, so neither the free address nor a deploy preview is public.
- **What that protects:** only the page. The data is on a public branch of a public repository, and anyone can already read it there.

## Deploy

From a machine whose `CLOUDFLARE_API_TOKEN` has **Account → Cloudflare Pages: Edit**:

```bash
CLOUDFLARE_ACCOUNT_ID=<Mudwood account id> \
  npx --yes wrangler@4 pages deploy tools/adoption-dashboard \
  --project-name=pyrxd-stats --branch=main --commit-dirty=true
```

Set the account ID explicitly. Without it, wrangler first asks Cloudflare which accounts the token belongs to, which a deploy-scoped token is not allowed to see, and fails with an authentication error.
