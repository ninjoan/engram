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

## Dev instance (unreleased features, built from source)

`docker-compose.dev.yml` builds `engram` from this branch on every Deploy, so you can try features before upstream ships them (currently: cloud backups to S3/R2, Dropbox and Google Drive). Production keeps `docker-compose.yml` and the official image.

- Dokploy: Compose service, branch `personal/main`, compose path `./deploy/dokploy/docker-compose.dev.yml`, domain on service `cloud`, port `18080`, HTTPS on.
- Use its own database (the compose has its own volume). Never point dev at production data: the dev build adds tables and columns that the official image does not know.

| Key | Value |
|---|---|
| `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_DB` | as above, dev-only password |
| `ENGRAM_JWT_SECRET` | secret (`openssl rand -hex 32`) |
| `ENGRAM_CLOUD_TOKEN` | secret; still required for `cloud serve` to start |
| `ENGRAM_CLOUD_TOKEN_PEPPER` | secret, distinct; enables managed admin tokens (needed for the backups page) |
| `ENGRAM_CLOUD_ALLOWED_PROJECTS` | comma-separated projects |
| `ENGRAM_CLOUD_BACKUP_KEY` | `openssl rand -base64 32`; seals destination credentials. Back it up separately: without it saved destinations cannot be opened |
| `ENGRAM_CLOUD_PUBLIC_URL` | `https://<dev domain>` (no path); needed for Connect with Google |
| `ENGRAM_BUILD_VERSION` | optional label |

After the first deploy, create the managed admin from the Dokploy terminal of the `cloud` container:

```sh
engram cloud bootstrap admin --username <you> --email <you@example.com> --grant-project <project> --issue-token admin
```

The token is printed once: use it to log in to `/dashboard/`, then open Admin → Backups.

To update: merge the feature branch into `personal/main`, push, press Deploy.

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
