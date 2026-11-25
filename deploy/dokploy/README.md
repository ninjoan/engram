# Personal staging Engram Cloud on Dokploy

Personal-only deployment. Lives on the fork's `personal/main` branch and never goes into upstream PRs.

Domain: `https://engram-staging.ninpartnerz.xyz`

## Dokploy service

- Type: **Compose**
- Source: GitHub `ninjoan/engram`, branch `personal/main`
- Compose path: `./deploy/dokploy/docker-compose.yml`
- Domain: host `engram-staging.ninpartnerz.xyz`, service `cloud`, container port `18080`, path `/`, HTTPS on (Let's Encrypt)
- PostgreSQL is not published; it is only reachable on the internal compose network.

## Environment (Dokploy "Environment" tab)

Generate each secret with `openssl rand -hex 32`. Never commit real values.

| Key | Value |
|---|---|
| `POSTGRES_USER` | `engram` |
| `POSTGRES_PASSWORD` | secret |
| `POSTGRES_DB` | `engram_cloud` |
| `ENGRAM_JWT_SECRET` | secret, non-default, distinct from the others |
| `ENGRAM_CLOUD_TOKEN` | secret bearer token shared with clients |
| `ENGRAM_CLOUD_ALLOWED_PROJECTS` | comma-separated project names, e.g. `engram-staging-smoke` |
| `ENGRAM_BUILD_VERSION` | optional label, e.g. `personal-staging` |

## Checks

```sh
curl -fsS https://engram-staging.ninpartnerz.xyz/health
```

Client side, use the isolated `engram-dev` wrapper (`~/.engram-dev`, port 7438), never the production `engram`.
