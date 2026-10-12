# Operations runbook (pre-production)

This is a preparation guide, not proof of a live production deployment. The application remains on SQLite. Do not run the local backup verifier as a production backup job: it compares the current checkout's `data/aroused.sqlite` and `uploads/` to one fixed historical backup.

## Verified existing backup and restore copy

The verified artifact is:

```text
migration-backups/migration-20261008T154037Z/
```

It contains `aroused.sqlite`, `uploads/`, `verification.json`, and a separate `restore-test/` copy. The verification command is read-only with respect to the source, backup, and restore databases:

```powershell
Set-Location 'C:\Users\ahmed\Documents\Codex\2026-10-03\hel\outputs'
& 'C:\Users\ahmed\.cache\codex-runtimes\codex-primary-runtime\dependencies\node\bin\node.exe' .\scripts\verify-migration-backup.mjs
```

The verified result for that artifact: source, backup, and restored SQLite `PRAGMA integrity_check` each returned `ok`; 16 source table counts matched the backup and restore; all 24 upload files totaling 37,557,936 bytes matched by relative path, size, and SHA-256. This is a historical local verification, not a recurring or production backup service.

The script accepts an optional backup directory argument. Only pass a directory containing the expected `verification.json`, `aroused.sqlite`, `uploads/`, and `restore-test/` structure. The restore copy is deliberately separate; never restore over `data/aroused.sqlite` or `uploads/` without a reviewed, explicitly approved recovery procedure. No generic live backup-creation command is documented as production-safe yet because it must coordinate SQLite WAL state and a consistent media snapshot while uploads can change.

## Health probes and logs

- `GET /api/health/live` is a process liveness check.
- `GET /api/health/ready` checks SQLite and the selected storage provider. HTTP success does not mean production-ready; inspect `readyForProduction` and provider status.
- `GET /api/health` is descriptive. Admin details remain behind authenticated admin APIs.
- JSON operational logs use an allowlist. Do not add request bodies, full URLs/query strings, credentials, session tokens, OTPs, report text, or uploaded filenames to logs. `requestId`, method, generic route, status, duration, component, port, and normalized error code are the allowed fields.
- No external alerting, log aggregation, or metrics integration is configured. A deployment must alert on readiness failures, job failures/backlog age, security events, disk/database growth, provider outages, and backup age.

## Production configuration preflight

Run the validator only in the environment intended for deployment. It prints only error messages and variable names, never values:

```powershell
npm run check:production-config
```

Production validation currently requires:

| Variable | Requirement |
|---|---|
| `NODE_ENV` | `production` to activate validation |
| `AROUSED_BIND_HOST` | Explicit host; bind only behind the intended TLS-terminating proxy |
| `AROUSED_API_PORT` | Integer 1–65535 |
| `AROUSED_DATA_DIR` | Absolute persistent path for SQLite |
| `AROUSED_PUBLIC_BASE_URL` | HTTPS URL |
| `AROUSED_ALLOWED_ORIGINS` | Comma-separated exact HTTPS origins; no wildcard |
| `AROUSED_EMAIL_CODE_SECRET` | At least 64 characters, stored in a secret manager |
| `RESEND_API_KEY`, `AROUSED_FROM_EMAIL` | Required for email verification/recovery; real delivery still needs an integration test |
| `AROUSED_STORAGE_DRIVER` | Must be `s3` in production |
| `AROUSED_OBJECT_STORAGE_BUCKET`, `AROUSED_OBJECT_STORAGE_REGION` | Required private object bucket |
| `AROUSED_OBJECT_STORAGE_ACCESS_KEY_ID`, `AROUSED_OBJECT_STORAGE_SECRET_ACCESS_KEY` | Set together, or use `AROUSED_OBJECT_STORAGE_USE_INSTANCE_ROLE=true` where supported |
| `AROUSED_OBJECT_STORAGE_ENDPOINT` | Optional HTTPS S3-compatible endpoint; explicit access keys are required for custom endpoints |
| `AROUSED_OBJECT_STORAGE_FORCE_PATH_STYLE` | Optional `true` for compatible providers that require path-style addressing |

Never place real values in source control, tickets, terminal transcripts, or this file. Configuration-shape validation does not prove credentials work, bucket privacy is correct, or that an external provider passed a real test. Production startup independently verifies bucket reachability and privacy controls. `npm start` loads `.env` for local convenience; production secrets should come from the platform's secret manager, not a committed file.

## Deploy/restore gates still required

Before any production deployment, choose and test a platform-specific deployment manifest and TLS/proxy policy; use persistent storage for SQLite only during the approved SQLite phase; configure private object storage and test bucket policy with real credentials; set up recurring encrypted backups that capture a consistent SQLite snapshot and all required media/object metadata; verify an isolated restore; define retention and alerting; and run a rollback rehearsal. Keep the media migration process in dry-run/verification mode until real destination privacy and authorization checks pass. Do not use PostgreSQL as the runtime database without separate explicit approval.
