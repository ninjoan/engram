# Personal Engram Cloud on Dokploy

Personal-only deployment. Lives on the fork's `personal/main` branch and never goes into upstream PRs.

Both environments run the official prebuilt image `ghcr.io/gentleman-programming/engram`, pinned to a version tag. Never use `latest`: a new upstream release must not update a server by itself.

| Environment | Domain | Dokploy service |
|---|---|---|
| Staging | `https://engram-staging.ninpartners.xyz` | Compose service #1 |
| Production | `https://engram.ninpartners.xyz` | Compose service #2, separate database and secrets |

## Dokploy service (one per environment)

- Type: **Compose**
- Source: GitHub `ninjoan/engram`, branch `personal/main`
- Compose path: `./deploy/dokploy/docker-compose.yml`
- Domain: service `cloud`, container port `18080`, path `/`, HTTPS on (Let's Encrypt)
- PostgreSQL is not published; it is only reachable on the internal compose network.

## Environment (Dokploy "Environment" tab)

Generate each secret with `openssl rand -hex 32`. Never commit real values, and never reuse a secret between staging and production.

| Key | Value |
|---|---|
| `ENGRAM_IMAGE` | `ghcr.io/gentleman-programming/engram:v3.7.2` (pinned version tag) |
| `POSTGRES_USER` | `engram` |
| `POSTGRES_PASSWORD` | secret |
| `POSTGRES_DB` | `engram_cloud` |
| `ENGRAM_JWT_SECRET` | secret, non-default, distinct from the others |
| `ENGRAM_CLOUD_TOKEN` | secret bearer token shared with clients |
| `ENGRAM_CLOUD_ALLOWED_PROJECTS` | comma-separated project names, e.g. `engram-staging-smoke` |

## Upgrading

1. Read the upstream release notes for the new version.
2. Change `ENGRAM_IMAGE` on staging first, redeploy, check `/health` and a sync from `engram-dev`.
3. Only then change it on production.

## Cloudflare

If Cloudflare proxies the domain and the origin answers `526 Invalid SSL certificate`, let Let's Encrypt issue the certificate first (record set to "DNS only"), then re-enable the proxy, or install a Cloudflare Origin Certificate in Dokploy.

## Checks

```sh
curl -fsS https://engram-staging.ninpartners.xyz/health
```

Client side, test staging with the isolated `engram-dev` wrapper (`~/.engram-dev`, port 7438), never the production `engram`.
