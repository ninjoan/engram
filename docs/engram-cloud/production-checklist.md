[← Back to Engram Cloud](./README.md)

# Engram Cloud Production Checklist

Use this checklist before operating a self-hosted Engram Cloud endpoint for users. Engram provides the Cloud runtime; the operator owns the surrounding production platform, its security boundaries, and its recovery process. The Compose examples are starting points, not a complete production platform.

## Before public operation

### Transport and ingress

- [ ] Terminate TLS at a reverse proxy or equivalent boundary that you operate, then configure clients with that HTTPS endpoint using `engram cloud config --server https://<cloud-host>`.
- [ ] Keep bearer-token traffic on HTTPS. Authenticated clients require HTTPS, including after redirects; `ENGRAM_CLOUD_INSECURE_NO_AUTH=1` is local/development smoke mode only and must not be used in production.
- [ ] Have the TLS-terminating proxy forward `X-Forwarded-Proto: https` (and keep the original `Host`, or send `X-Forwarded-Host`). The dashboard's backup settings routes compare the browser's `Origin` with the request's own scheme and host; without the header a browser on `https://` is seen as cross-origin and every backup mutation (save destination, test, schedule, **Back up now**, download) is refused with 403.
- [ ] Expose only the intended Cloud endpoint to public ingress. Restrict administrative access to the proxy, host, and deployment controls according to your environment.
- [ ] Keep PostgreSQL and other private dependencies off public ingress. A Compose port mapping or `ENGRAM_CLOUD_HOST` bind address controls where a process listens or is published; it is not a firewall policy.

### Configuration and secrets

- [ ] Configure the required Cloud runtime values: `ENGRAM_DATABASE_URL`, `ENGRAM_CLOUD_ALLOWED_PROJECTS`, `ENGRAM_CLOUD_TOKEN`, and a non-default `ENGRAM_JWT_SECRET` for authenticated mode.
- [ ] Store secret values outside source control and restrict access to the operators and deployment processes that need them. The reference Compose flow keeps its `.env` file on the server and out of Git.
- [ ] Treat `ENGRAM_DATABASE_URL`, `ENGRAM_CLOUD_TOKEN`, `ENGRAM_JWT_SECRET`, and, when used, `ENGRAM_CLOUD_ADMIN` and `ENGRAM_CLOUD_TOKEN_PEPPER` as deployment secrets. The reference Compose example also uses `POSTGRES_PASSWORD`.
- [ ] If scheduled backups are used, treat `ENGRAM_CLOUD_BACKUP_KEY` as a deployment secret, keep it distinct from the other secrets, and back it up separately from the database and from backup archives: it is never stored in either, and without it the stored destination credentials cannot be opened (scheduled runs are then recorded as skipped until an admin saves the destination again).
- [ ] If backups go to Google Drive, set `ENGRAM_CLOUD_PUBLIC_URL` to the dashboard's public `https` origin (for example `https://engram.example.com`, no path) and register exactly `<ENGRAM_CLOUD_PUBLIC_URL>/dashboard/admin/backups/gdrive/callback` as the OAuth client's authorized redirect URI. Engram never derives it from `Host` or `X-Forwarded-*` headers; an invalid value makes `engram cloud serve` refuse to start. Move the Google OAuth app (External user type) from publishing status **Testing** to **In production**: in Testing, Google expires refresh tokens after 7 days and scheduled uploads stop until an admin presses **Reconnect with Google**. See [Google Drive destination](../../DOCS.md#google-drive-destination).
- [ ] If managed-token authentication is enabled, keep `ENGRAM_CLOUD_TOKEN_PEPPER` distinct from `ENGRAM_JWT_SECRET`. It is required both when issuing managed tokens and when the running Cloud runtime authenticates them.
- [ ] Define who may change each secret, where its current value is stored, and how rotation triggers a safe redeployment. Operators own rotation and redeployment; this guide does not provide a secret manager or rotation automation.

### Data protection and recovery

- [ ] Use durable storage for Cloud PostgreSQL data. The reference Compose file mounts `engram-cloud-pg` at `/var/lib/postgresql/data`; choose equivalent durable storage for your platform.
- [ ] Own backups for the Cloud database, including retention, access protection, and an off-host or otherwise independent copy where appropriate for your environment. Engram provides a logical export/import of Cloud data (`engram cloud backup export` / `import`, see [Cloud Backup and Restore](../../DOCS.md#cloud-backup-and-restore)) and optional scheduled uploads to an S3-compatible bucket configured from the dashboard (see [Scheduled backups](../../DOCS.md#scheduled-backups-to-an-s3-compatible-destination)); you still own the bucket and its access policy, how long archives are kept (Engram never deletes uploaded backups; use bucket lifecycle rules), free disk on the server for one archive during a scheduled run, and restore rehearsal. Engram does not define recovery objectives.
- [ ] Treat backup archives as sensitive: they contain plaintext memories. Keep them at mode `0600` and encrypt them before copying them off the host. Archives never contain tokens, token hashes, password hashes, or environment secrets, so keep your secrets backed up separately.
- [ ] Preserve local SQLite data as well. Engram is local-first: local SQLite remains authoritative and Cloud is optional replication and browser visibility.
- [ ] Document a restore procedure that does not overwrite a live service during rehearsal.

## Rehearse and verify

### Restore rehearsal

- [ ] Restore a backup into an isolated environment, using a separate endpoint and database from production. With Engram's export, create an empty database and, with `ENGRAM_DATABASE_URL` pointing at it, run `engram cloud backup import --input <archive> --dry-run`, then `--apply`. Import refuses a database that already has Cloud data, so do this before `engram cloud bootstrap admin`.
- [ ] Re-issue managed tokens for the rehearsal: backups never carry tokens. Run `engram cloud bootstrap recover-token --principal <id|username>` once to issue the first token for one enabled managed admin (`--principal` may be omitted when the restored data has exactly one enabled managed admin), then have that admin issue the other tokens. Legacy username/password users cannot log in after a restore.
- [ ] Start the restored Cloud runtime with its own protected configuration; do not reuse production credentials merely to perform the rehearsal.
- [ ] Verify the restored endpoint responds at `GET /health` and that an authorized test client can complete `engram sync --cloud --project <project>`.
- [ ] Confirm observable success: `engram sync --cloud --status --project <project>` reports the expected restored remote chunks and a pending-import state you understand, and the expected replicated data is visible in the isolated dashboard. Record the result and any gaps before relying on the backup process.

### Health and version checks

- [ ] Probe the documented Cloud health endpoint through the production ingress: `GET /health`. A healthy Cloud runtime returns `{"status": "ok", "service": "engram-cloud"}`.
- [ ] Use `engram cloud status` to verify client configuration and auth readiness, then use `engram sync --cloud --status --project <project>` to inspect replication progress.
- [ ] Use `engram version` to record the client binary version. For the Cloud runtime, record the image reference configured by your deployment; the documented Cloud `/health` response does not expose a server version.

## Responsibility boundary and non-goals

| Engram runtime | Operator and platform |
|---|---|
| Cloud sync API, dashboard, authenticated-mode configuration requirements, the documented health endpoint, the `engram cloud backup` export/import commands, and optional scheduled uploads of backup archives to an S3-compatible bucket you configure | TLS termination, reverse proxy, ingress/firewall rules, secret storage and rotation, durable storage, backup storage (the bucket and its access policy), retention and off-host copies, restore rehearsal, and deployment version selection |

This checklist does not configure infrastructure, select a provider, implement high availability, store or expire backups, supply monitoring products, define recovery objectives, or change PostgreSQL configuration. Use the [Quickstart](./quickstart.md) for the supported setup and runtime variables, and the [Technical Cloud Reference](../../DOCS.md#cloud-cli-opt-in) for the full command and endpoint contract.
