# Aroused production architecture and migration plan

**Assessment date: 2026-10-08. Status: NOT READY.** This is an architecture and risk analysis of the current code, not a claim that a provider is configured or that a scan, age check, or moderation decision has happened. No application code, database, media file, or provider configuration was changed for this analysis. Do not migrate or run a production deployment until the backup and staging gates below pass.

## 1. Current architecture

| Component | Current design | Source files / data |
|---|---|---|
| Framework and runtime | No framework. Node.js ES modules, minimum Node 22.13. Built-in `node:http`, `node:sqlite`, and Web APIs; no runtime package dependencies. | `package.json`, `server.mjs` |
| Frontend | One large static HTML application with inline CSS and JavaScript; separate static admin page. The server also serves these files. | `index.html`, `admin.html`, `server.mjs` |
| API/backend | One native HTTP server owns API routing, database access, uploads, static hosting, and scheduled publishing. Default bind is loopback port 8767; `AROUSED_API_PORT` can change the port. | `server.mjs` |
| Database | SQLite in WAL mode with foreign keys enabled. Tables are created/altered by startup SQL rather than a versioned migration system. | `server.mjs`; default `data/aroused.sqlite`; `.gitignore` |
| Authentication | Email/password; password hashes are scrypt with random salts. Signup uses a six-digit HMAC-hashed email code sent directly through Resend. Google, Reddit, and X are not implemented. | `server.mjs`, auth UI in `index.html`, `.env.example` |
| Session storage | Random bearer tokens are SHA-256 hashed into SQLite `sessions`; browser cookie is HttpOnly, SameSite=Lax, 30 days, and gets Secure only when `NODE_ENV=production`. | `server.mjs` |
| Media storage | Local disk under `uploads/` by default. Multipart bodies are accumulated in memory before `FormData` parsing and files are then written to disk. | `server.mjs`; `uploads/`; `AROUSED_UPLOAD_DIR` |
| Upload/pipeline | Album-first: `stories` is feed-facing, `albums` owns a post and `album_media` the ordered files. Basic MIME/extension and magic-byte checks run. SHA-256 and `media_pipeline`/`processing_jobs` rows are created, but there is no scanner, processor, or worker. Upload eligibility rejects age status other than `verified`; no provider can currently set a verified result. | `server.mjs`, upload/creator UI in `index.html`, `provider-status.mjs` |
| Media serving | App routes `/media/:id` and `/uploads/:name` read files from local disk, support byte ranges, and do visibility/owner checks for album-associated files. No signed media URLs, object store, or CDN. | `server.mjs` |
| Moderation | Reports create cases; suspected-minor/non-consensual album reports set a restricted/pending state. Account actions, reports, comments, appeals, and audit events use SQLite. This is software workflow, not an established staffed escalation service. | `server.mjs`, `admin.html`, account/report UI in `index.html` |
| Background work | A 15-second in-process timer publishes scheduled albums. A `processing_jobs` table exists, but no process claims or executes those jobs. | `server.mjs` |
| Admin | `/admin` serves `admin.html`; admin API checks role on the server. The same Node process handles application and admin actions. | `server.mjs`, `admin.html` |
| Deployment assumptions | Local prototype, `.env` configuration, local SQLite/files, Resend API over outbound HTTPS. There is no TLS termination, deployment manifest, proxy trust policy, production environment validator, monitoring, or backup automation in this repository. | `README.md`, `.env.example`, `.gitignore`, `server.mjs`, `package.json` |

`PRODUCTION_READINESS.md` is the evolving verification checklist. The following section records the baseline findings before the implementation pass documented below; use the implementation update and the current readiness checklist for verified status.

## 2. Baseline risks found before security fixes

Severity is a planning priority, not a guarantee that an incident has occurred.

| Priority / finding | Exact code behavior | Risk and required correction |
|---|---|---|
| **Critical — no real age assurance** | `canUserUpload()` requires `users.age_status === 'verified'`; `/upload/accept-eligibility` records self-attestation, not provider verification. There is no age provider adapter. | Keep creator uploads disabled until a selected provider returns a verifiable result and the system records provider reference, verification time, status, and policy. Never map the checkbox to verified. |
| **Critical — media safety providers and worker do not exist** | `registerMediaPipeline()` computes exact SHA-256, sets scanner/processor/content/safety states to `NOT_CONFIGURED`, and inserts a blocked job. No worker can change those states. | Current new uploads cannot become safe or publish. Maintain fail-closed states until real providers and a reviewed worker state machine exist. Hashing alone does not detect known content or establish safety. |
| **High — account enumeration** | `/auth/signup` returns 409 for an existing email; `/auth/resend-code` distinguishes invalid/missing pending records and cooldown. `/auth/verify-email` distinguishes missing, expired, attempts-exhausted, wrong-code, and duplicate-account conditions. | These responses disclose account/verification state. Normalize public responses and timing where practical, while recording private operational reasons. Current audit text overstates protection. |
| **High — album state can advance without a complete pipeline decision** | `/albums/:id/publish` checks `album_media.state === 'ready'`, but does not require `mediaPipelineReady()` for each item. The “add media” route creates rows with `state='ready'` while the pipeline stays `SCAN_PENDING`. | Feed/story/media-byte gates separately block unready album bytes, but the album/story status can still become published and `/albums/:slug` exposes metadata and media URLs. Make one transactional `canPublishAlbum()` gate require all media/provider/declaration/moderation states before changing publication state. |
| **High — unassociated upload files are served publicly** | `/uploads/:name` applies owner/visibility/pipeline checks only when the filename is found in `album_media`. If it is unassociated, the handler attempts to serve it without authentication. | Orphaned files, partially deleted media, or future upload paths may be exposed to anyone who learns a filename. Only serve an explicit public-avatar class or an authorized media record; deny unknown/unassociated names. |
| **High — request-sized memory amplification** | `readBody()` buffers a full request, then multipart parsing and per-file `arrayBuffer()`/`Buffer` copies create additional in-memory copies. Default request cap is 100 MiB; no streaming upload, global concurrency budget, upload timeout, or per-user upload rate limit. | Concurrent uploads can exhaust memory and block the single Node process. Use bounded streaming or private presigned multipart object uploads, global concurrency controls, timeouts, per-user quotas, and worker-side size verification. |
| **High — CSRF lacks a token** | Unsafe methods use allowed-Origin checks and Fetch Metadata in `postAllowed()`, but no synchronizer/double-submit CSRF token exists. Cookies use SameSite=Lax. | Keep exact Origin + Fetch Metadata checks and add a CSRF token for authenticated state changes; test browser, proxy, and missing-header behavior. Do not rely on CORS alone. |
| **High — local session/secret operational risks** | Session bearer tokens are stored as SHA-256 hashes (good for database-only exposure), but session rows are not periodically pruned. The OTP HMAC secret is stored in SQLite if `AROUSED_EMAIL_CODE_SECRET` is absent. | Use a managed secret store and mandatory production secret validation; prune expired sessions; provide revocation and key-rotation procedures. Consider session idle/absolute limits and reauthentication for sensitive operations. |
| **High — password recovery is not production-operational** | `POST /auth/request-password-reset` and `/auth/reset-password` now use generic responses, rate limits, one-time random tokens stored as hashes, 30-minute expiry, single-use consumption, password replacement, and all-session revocation. The reset UI and configured Resend delivery are absent. | No user-facing flow can be completed until Resend credentials and a reset UI are provided. Verify real delivery, expiry/replay behavior, and recovery operations before launch; no token is issued when delivery is unavailable. |
| **High — rate limits are process/database-bound** | SQL buckets key the socket `remoteAddress`; there is no bucket cleanup or global upload limiter. Behind a reverse proxy, socket identity may be the proxy for every user; forwarded headers are not trusted or normalized. | Implement a documented proxy trust boundary, bounded/pruned/distributed rate limits, and upload quotas. Do not blindly trust `X-Forwarded-For`. |
| **High — production configuration is not validated** | `Secure` depends only on `NODE_ENV`; the server binds `127.0.0.1`; default allowed origins are localhost ports; invalid numeric ports/limits and unset provider credentials do not produce a comprehensive startup readiness failure. | Add a production startup validator for HTTPS/proxy assumptions, exact origins, secrets, host/port, database, storage, and mandatory providers. Terminate TLS at the platform proxy and bind to the container interface only behind that proxy. |
| **High — reports/admin views are not a restricted evidence system** | Admin report rows include free-text report details for the admin reports view. Role checks exist, but audit notes, evidence segregation, retention, and specialist access boundaries are not established. | Minimize data in reports; restrict high-risk details to assigned senior specialists; log evidence access; encrypt and define retention/legal holds. Staff escalation remains an operational blocker. |
| **Medium — media parser and file-validation gaps** | Browser MIME and filename extension are checked against a short allowlist and a few magic-byte prefixes. No image decoder, video/container parser, malware scanner, metadata scrubber, transcoder, sandbox, CPU/time cap, or pixel/frame limit exists. Archives are not accepted, but malformed media may still target future parsers. | Run parsers/scanners in isolated workers with CPU/memory/time limits, validate actual container/codecs and decoded dimensions, strip metadata where appropriate, and quarantine on parser/provider errors. Never execute uploaded files. |
| **Medium — content sniffing and media origin** | `/media/:id` sets `X-Content-Type-Options: nosniff`; `/uploads/:name` does not. App responses have no comprehensive CSP/HSTS/frame/referrer policy in this server. | Set safe headers consistently; serve user media from a separate cookieless domain/origin, with correct content types and restrictive disposition/policy. Enable HSTS only after HTTPS is correct. |
| **Medium — path handling robustness** | Stored object names are generated and URLs use `basename`, mitigating ordinary traversal. However `/uploads/` calls `decodeURIComponent()` outside a local error guard, so malformed escapes can throw in the HTTP callback. Static-file serving uses basename but is not an explicit allowlist. | Guard URL decoding; map static routes to an explicit asset allowlist; deny unknown media. Add traversal/malformed-encoding tests. No user-controlled outbound fetch URL was found: the only server `fetch()` targets the fixed Resend API, so no direct SSRF sink was found in current code. |
| **Medium — password/session details** | Password hashes use Node scrypt with 16-byte random salts and timing-safe comparison after deriving the hash. Login has rate limiting and a generic invalid-credentials message. | Version password-hash parameters so they can be raised; revoke other sessions after password change/reset; test login timing and rate limits. No breached-password policy is implemented. |
| **Medium — admin bootstrap can re-promote an account** | If `AROUSED_ADMIN_EMAIL` and `AROUSED_ADMIN_PASSWORD` are present, startup promotes the matching email to admin on every start, retaining its existing password. | Treat bootstrap variables as a one-time controlled operation or use a dedicated break-glass process; remove them after bootstrap, alert on role changes, and require MFA for production administrators. |
| **Medium — unbounded/static operational data** | Rate limit, audit, security-event, report, and job tables have no retention/archival jobs; logs are console messages rather than structured, redacted, correlated operational logs. | Define retention and legal holds; add structured event IDs, redaction, alerts, and storage/DB growth monitoring. Never log OTPs, passwords, session tokens, or raw sensitive media. |
| **Low-to-medium — identifier/authorization coverage needs testing** | Album ownership is checked in edit/delete routes; media visibility and story lookup have server checks. Numeric IDs and direct album routes remain direct object references, so route-by-route authorization must stay tested as features expand. | Add automated owner/other-user/admin matrix tests for every mutation and media view (including private, unlisted, deleted, quarantined, and orphaned rows). No confirmed ordinary album-IDOR was identified in the reviewed paths. |

### Implementation update (2026-10-08)

The baseline auth-enumeration, unsafe publication-state transitions, unassociated `/uploads/` access, malformed upload decoding, static-file fallback exposure, bootstrap re-promotion, and untested owner/role paths were corrected in `server.mjs`. Public read and byte delivery, immediate publish, visibility edits, admin restore, and scheduled publication now use the canonical `canPublishAlbum()` state/policy/eligibility gate. Quarantined and rejected bytes are denied even to the owner; private and unpublished previews remain owner-only. New unlisted album slugs use 128 random bits; older slugs are retained to avoid breaking existing links and are rate-limited on reads. A restart regression test verifies a demoted bootstrap account is not silently re-promoted.

Unsafe requests now fail closed without an allowed `Origin` or `Sec-Fetch-Site: same-origin`; cross-site and hostile-Origin requests are denied. There is no synchronizer token, so any future cross-origin browser client or deployment that strips these headers must add one before launch. Login performs a dummy scrypt derivation for unknown email addresses. Session rotation/logout/password change revoke server-side records, cookies use `SameSite=Strict`, and rate-limit buckets are pruned with authenticated upload quotas.

Direct API regression coverage is in `tests/security-gates.test.mjs`; provider-passed states are created only inside an isolated test database to verify gates. No provider adapter or success-producing worker was added. The actual age/scanning/processing providers remain unavailable, so ordinary app uploads cannot be published. `PRODUCTION_READINESS.md` records the test command/results and remaining production blockers.

### Security details requested

- **OAuth state/PKCE:** no OAuth start/callback routes use the `oauth_transactions` table; state and PKCE are not active controls.
- **SSRF:** current server-side outbound request is to the fixed Resend URL; no request parameter chooses the fetch URL. Keep all future provider endpoints allowlisted and never fetch arbitrary creator URLs from the server.
- **Filename execution/traversal:** media storage keys are random server-generated names, not the original filename; original names are metadata. Media routes validate decoding and only serve database-associated media/avatar references; static serving is allowlisted. Direct malformed encoding and orphan paths are covered by the security tests.
- **IDOR:** album mutation handlers compare `owner_id` to session user. Direct tests cover cross-account album read/write/publish and media access across public, unlisted, private, unpublished, quarantined, and rejected states.
- **TLS/signed URLs:** neither TLS termination nor signed object/CDN URLs are implemented. Current local routes proxy bytes from Node.
- **Archive bombs:** archive extensions are outside the current allowlist; future ingestion must continue to reject archives unless specifically isolated and bounded. Malformed or decompression-heavy image/video files remain a risk because media decoders are absent.

## 3. Production target architecture

Keep one application codebase and two process roles, not a mesh of microservices:

```text
Browser ── HTTPS ── Platform proxy / CDN ── Node web + API process
                                      │             │
                                      │             ├── Managed PostgreSQL
                                      │             ├── Private object storage
                                      │             └── Provider adapters
                                      │
                                      └── Private media origin (origin access only)

Node worker process (same repository/image) ── PostgreSQL job queue
       ├── malware scanner adapter
       ├── fingerprint / known-content adapter
       ├── media processor
       ├── content-safety adapter
       └── human moderation queue
```

| Area | Target |
|---|---|
| Web/API | Keep the current `index.html` creator workflow, album-first API contract, and `admin.html` functions. Refactor server modules beneath them; deploy the same Node application image as a web/API process and a worker process. Serve frontend and API same-origin where possible to simplify cookies and CSRF. |
| Database | Managed PostgreSQL, private network only, versioned forward/rollback-aware migrations. Preserve current IDs and data shape while adding explicit media/pipeline transitions, object keys, provider results, constraints, and migration ledger. |
| Session/auth | Continue opaque random browser tokens, store only token hashes; production secure cookie and explicit CSRF token. Add reset flow. OAuth adapters each validate state, PKCE, issuer/audience, redirect URI and provider identity; link only after recent authentication to the existing account. |
| Media storage | `StorageProvider` interface. Production adapter stores uploads in a private quarantine prefix/bucket and processed renditions in a separate private prefix/bucket. Browser gets short-lived presigned upload URLs only for scoped staging keys. No public bucket ACL. |
| Delivery | Keep stable app `/media/:id` authorization. After authorization, provide a short-lived signed CDN URL/cookie for the approved rendition; private/unlisted reads remain short-lived and non-cacheable or policy-controlled. CDN origin access is restricted to the private bucket. |
| Jobs | Start with a PostgreSQL-backed durable queue/outbox and `FOR UPDATE SKIP LOCKED`, retry count, lease/heartbeat, idempotency key, backoff, dead-letter state, and per-provider timeout. This avoids adding Redis before scale justifies it. |
| Worker | Same repo, separate process/container with low privileges and no public listener. Download one private object to an isolated temp workspace, scan, hash, inspect, process, obtain provider results, and update states transactionally. Limit CPU, memory, disk, and runtime; delete temp files on success/failure. |
| Safety and moderation | Provider adapters only return provider evidence/status, never fabricate clean outcomes. Risky/unknown/unavailable outcomes remain quarantined. Restrict sensitive reports/evidence to assigned, authorized reviewers; retain immutable audit/access events and escalation procedures. |
| Admin | Preserve current page and add operational status/actions only through server authorization. Separate admin and moderator permissions; show queue age/provider outage without exposing quarantined media broadly. Require MFA and reauthentication for privileged changes. |
| Operations | JSON structured/redacted logs to managed collection; metrics/traces and alerts for API errors, login abuse, queue age, scan/provider failures, quarantined volume, object-store errors, DB pool/replication/storage, backup age, and restore tests. |

## 4. Provider abstractions and requirements

The code currently has a `providerStatus()` reporting helper, not runtime adapter interfaces. Introduce interfaces at application boundaries and keep the existing API/UI contract stable. An unconfigured mandatory method returns a typed `NOT_CONFIGURED`/unavailable error; it must never return a success-shaped default.

| Interface | Needed contract | Current state / outage rule |
|---|---|---|
| `EmailProvider` | `sendVerificationCode`, `sendPasswordReset`; provider delivery ID and sanitized error. | Resend is hard-coded in `server.mjs`. Extract it; if unavailable, signup/reset cannot complete. No OTP fallback to console/UI. |
| `OAuthProvider` | Build authorization URL; exchange one-time code; validate state/PKCE; fetch stable provider subject and verified email claims. | Missing for Google, Reddit, X. Provider identifiers must be unique; never link accounts solely because emails happen to match. |
| `AgeVerificationProvider` | Start verification, consume signed callback/result, verify authenticity, return scoped status/reference and timestamp. | Missing. No creator upload without a current verified provider result; outage keeps existing unverified attempts blocked. |
| `StorageProvider` | Private multipart initiate/complete/abort, head/size/checksum, get/read, copy/promote, delete, signed delivery. | Missing; local filesystem only. Production must use private storage. Storage outages block finalization and publication. |
| `QueueProvider` | Durable enqueue/claim/lease/heartbeat/retry/dead-letter/cancel. | Table exists but no executor. PostgreSQL table-based queue is a simple first production choice; if PostgreSQL is unavailable, do not accept a publication as queued. |
| `MalwareScanner` | Scan an immutable object/hash; return clean, malicious, unknown, timeout/error plus provider reference. | Missing. Unknown, timeout, and error quarantine; never equate with clean. |
| `MediaFingerprintService` | SHA-256 and, if needed, versioned perceptual fingerprints over validated bytes. | Exact SHA-256 computation exists. Keep this internal and versioned; an exact hash is not a known-content verdict. |
| `KnownContentService` | Query fingerprints against authorized corpus; return clear, match, unknown, with match reference and confidence policy. | Missing. A provider outage or unknown result prevents publication when this check is mandatory. |
| `ContentSafetyService` | Submit normalized media/context and obtain provider status, risk labels, provider reference, and error. | Missing. No invented risk score. Unknown/outage routes to quarantine/manual review. |
| `MediaProcessor` | Probe real container/codecs, enforce limits, remove metadata as policy dictates, create thumbnails/renditions, emit checksums and duration/dimensions. | Missing. Malformed or unsupported media fails or quarantines; it is not marked ready. |

### Cost and complexity by service category

No vendor or usage levels are chosen, so dollar estimates would be misleading. Recurring costs generally track requests/verification, stored GB, transfer/egress, processing time, retained logs, and human-review volume. Complexity is relative.

| Category | Why / mandatory? | Expected behavior and outage policy | Development alternative | Cost / complexity |
|---|---|---|---|---|
| Transactional email (Resend or selected equivalent) | Email verification and reset. Mandatory for email signup. | Provider accepts a send and returns an ID; failures leave signup pending and generic. Do not return codes. | Configured provider sandbox/test domain; otherwise signups disabled. | Low-to-medium integration; per-email operating cost. |
| Google OAuth | Only mandatory if Google sign-in is offered. | Authorization-code + state + PKCE and stable subject validation. Outage disables that login method; existing email login can remain. | Local OAuth app registration on localhost; no simulated callback success. | Low-to-medium per provider, plus account-linking security review. |
| Reddit OAuth | Same as above, only if offered. | Provider outage disables Reddit login/linking only. | Local/test OAuth registration. | Medium; provider app policy/review can add operational work. |
| X OAuth | Same as above, only if offered. | Provider outage disables X login/linking only. | Local/test OAuth registration. | Medium; provider access/terms and rate policies can change. |
| Age assurance | Required before this adults-only creator workflow can accept uploads. | Provider outage or unverifiable callback blocks new verification and upload authorization. Preserve verified result only according to policy and provider expiry. | Provider sandbox only for tests; production cannot use a test result. | Medium-to-high legal/product integration; often per-check and support cost. |
| Managed PostgreSQL | Mandatory for multi-process production consistency and durable jobs. | DB unavailable means auth/mutations/job claims fail safely; no local fallback split-brain. | SQLite remains local development only. | Low-to-medium operations; managed tiers, storage, HA and connections add cost. |
| Private object storage | Mandatory for durable/scalable production media. | Upload finalization, scanning, or delivery fail closed if object verification fails. Keep bucket private. | Local disk for local-only development; never mark provider scan success. | Low initial integration, usage and request cost; migration and lifecycle complexity medium. |
| CDN/media delivery | Strongly recommended for video bandwidth; not a content-safety decision provider. | CDN outage may degrade delivery; authorization/signature expiry still blocks unauthorized reads. Purge/restrict removed content. | App proxy in local development. | Medium setup; egress may dominate variable cost. |
| Durable job queue | Mandatory asynchronous processing; first version can be a PostgreSQL table, not another managed service. | If enqueue/lease/heartbeat fails, media stays pending/private. Retries are idempotent; exhausted jobs go dead-letter/quarantine. | Same PostgreSQL queue in development; no fake worker results. | Medium implementation, low extra infra cost initially. |
| Malware scanning | Mandatory for user-provided media before publishing. | Timeout, unavailable, or unknown means quarantined; retries and operations alert. | Scanner sandbox/test fixture only; production upload stays blocked without adapter. | Medium integration; per-volume or compute cost. |
| Fingerprint/known-content matching | Exact SHA-256 can be local; known-content corpus lookup is a separate mandatory policy decision for launch. | Match/unknown/provider outage follows documented quarantine/reporting policy. Exact hash alone cannot imply clear. | Local deterministic hash generation is real; no local substitute for external corpus. | Low for hash; high/legal-sensitive for corpus provider and operational handling. |
| Content-safety provider | Mandatory if launch policy relies on automated content risk screening; human moderation remains required for edge/urgent cases. | Provider error/unknown routes private pending work to review; never default to safe. | Sandbox/test fixture only; no production publishing without real provider. | Medium-to-high integration; typically usage-based plus reviewer labor. |
| Media processing workers | Mandatory to validate/normalize accepted media and make renditions. | Failed parse/timeout is FAILED or QUARANTINED, never READY. | Local worker process can run in dev with real test media; must still produce truthful results. | Medium-to-high engineering, compute and temporary storage costs. |
| Moderation staffing/escalation | Mandatory for the stated human queue and critical escalation. Not a software API alone. | Page/content remains restricted until trained reviewer decision; on-call/escalation coverage must meet published policy. | Staging exercises with synthetic test cases only. | High operational complexity; labor/legal response cost. |
| Monitoring/logging | Minimum production visibility is mandatory. | Alert on sustained API/provider failure, queue age, scan backlog, suspicious auth, DB/storage/backup health. Redact sensitive values. | Local structured console logs/tests; no alerting substitute. | Low-to-medium setup; log/metric volume adds cost. |
| Backups/restore | Mandatory before migration and for production data. | A backup is considered valid only after isolated restore/integrity checks. | Local encrypted snapshots plus restore drill. | Low-to-medium implementation; storage/retention cost. |
| Hosting/TLS/DNS/secrets | Mandatory for public service. | HTTPS only; secure cookies; exact production origin; secret manager. If trust boundary/config is invalid, fail startup/deployment. | Localhost HTTP only for development. | Low-to-medium initial setup; ongoing domain/hosting cost. |

Do not select vendors solely on popularity. Compare jurisdiction/data residency, adult-content terms, retention/deletion guarantees, API behavior on unknown/error, auditability, response SLA, integration workload, total cost at expected throughput, and exit/export capability.

## 5. Storage migration: SQLite and local files

**Do not migrate against the live `data/aroused.sqlite` or `uploads/` directory. Do not delete or overwrite either.** Current startup code performs schema creation and legacy-media conversion, so all experimentation must use isolated copies.

### Backup and restore gate (before any schema or provider work)

1. Record the current application revision, Node version, database path, media path, approximate table counts, disk free space, and active processes. Do not paste `.env` contents into reports.
2. Put the site in a maintenance window. Stop every process that can write to this SQLite database or `uploads/`; wait for graceful exit. Do not copy only `aroused.sqlite` while a writer is active because WAL data may still be in `-wal`.
3. From a separate backup directory on a different volume or encrypted backup target, create a consistent SQLite snapshot using SQLite's online backup mechanism (or `VACUUM INTO` after all writers stop). Save the original DB, any required WAL state, and metadata. Keep the source untouched.
4. Copy the entire media tree without transformations. Produce a manifest of relative path, byte size, and SHA-256 for every file. Store the manifest and database snapshot with restrictive permissions. Back up secrets separately in an encrypted secret manager; do not include plaintext secrets in the architecture document or source control.
5. Restore the snapshot and media copy into a new isolated directory. Run SQLite `PRAGMA integrity_check` and `PRAGMA foreign_key_check`, compare row counts for all tables, and verify every referenced media object exists and matches the file manifest. Exercise the app only against this restored clone.
6. Repeat a restore from the backup artifact on a separate machine/environment before declaring the backup gate complete. Retain the original SQLite DB and media unchanged through migration, acceptance, and the agreed rollback period.

### SQLite → PostgreSQL

1. Add a versioned PostgreSQL schema/migration ledger in a staging branch. Keep current Node API routes and frontend response shapes stable. Convert SQLite-specific SQL/transactions deliberately; do not point the current `DatabaseSync` code at PostgreSQL.
2. Define type mapping: integer IDs to `BIGINT` (preserve IDs), integer flags to `BOOLEAN`, ISO time strings/epoch fields to documented `TIMESTAMPTZ`/`BIGINT`, `tags_json` and audit `details_json` to validated `JSONB` (preserve original values), text status fields to constrained enums/checks, and `email`/`username` to case-insensitive unique indexes. Preserve provider identity uniqueness and album/media ordering constraints.
3. Preserve the full relational graph and IDs: `users`, `user_identities`, `sessions` (see session decision below), `stories`, `albums`, `album_media`, likes/follows/saves/reposts/comments/messages, reports, moderation cases, enforcement actions, appeals, admin audit log, security events, policy acceptances, creator declarations, media fingerprints/scan results/pipeline/jobs, app secrets, and site settings. Keep nullable/deleted references and timestamps consistent; validate foreign keys after load.
4. Migrate into an empty staging PostgreSQL database from the restored SQLite snapshot in deterministic table order, using transactions and explicit IDs. Import large tables in bounded batches. Re-seed PostgreSQL identity sequences to `MAX(id)+1`. Do not update or delete the SQLite source.
5. Sessions: because active sessions are bearer cookies, either migrate unexpired `token_hash` rows exactly while preserving the same host/cookie name and verifying expiry policy, or intentionally invalidate all sessions at cutover and require login. Prefer a forced session rotation for the first production launch; record the decision and communicate it. Do not copy raw tokens (the DB should only have hashes).
6. Validate counts, unique constraints, foreign-key checks, user login/hash compatibility, policy history, reports/cases/audits, pending state, and application-level read APIs against staging. Run a full test suite and compare normalized row hashes for critical tables. No production traffic should write to both databases casually; use a maintenance-window snapshot/replay or a tested change-data-capture plan if writes cannot be paused.
7. Cut over by placing the site read-only/maintenance, taking a final consistent snapshot, migrating the final delta, rerunning validations, and deploying the PostgreSQL-backed app. Keep the old DB read-only and backed up. Do not route production writes back to an old snapshot after new writes occur unless a deliberate data reconciliation/forward-replay plan exists.

### Local media → private object storage

1. Implement `StorageProvider` behind the current album/media service first. Keep `/media/:id` as the stable API path so `index.html` and the album-first UI do not need redesign. Introduce a separate `object_key`, storage provider, checksum, and object version/etag; keep `storage_name` and current IDs during the transition.
2. Provision a private staging prefix and private processed prefix. Deny public ACLs; restrict bucket access to the app/worker role and CDN origin identity. Define encryption, lifecycle, deletion, legal-hold, and region policies before bulk copy.
3. Copy files idempotently, retaining a map from existing `album_media.id` and `storage_name` to object key. For every object, verify byte length and SHA-256 against source; compute a new fingerprint if an old file has no `media_fingerprints` row. Store migration status and checksum in a separate migration ledger; do not mark the media safe because it copied successfully.
4. Keep all copied objects private and in `SCAN_PENDING`/quarantine until the real scanner/processor flow runs. A migration copy is not a scan. Run object count, database reference count, missing-file, extra-object, checksum, permission, and restore tests.
5. Cut over app reads/writes to object storage after staging validation; support a temporary read-only fallback to local storage only while the SQLite source is retained. After acceptance and backup retention, plan an explicit deletion/retention operation; do not automatically remove source files during cutover.
6. For delivery, authorize via album/media ID then issue a short-lived signed URL/cookie or stream through the app. CDN origin access must be private. Revoke/purge CDN cache when an item is quarantined, deleted, or loses public visibility. Private/unlisted URLs expire quickly; a guessed key alone never grants access.

## 6. Media pipeline and state ownership

The current schema has `album_media.state`, `media_pipeline.status` and per-capability status columns, and `processing_jobs`. It does not yet enforce a complete transition graph or have a worker. The production state machine should be centralized in transaction-safe service functions, not scattered status assignments.

| State | Stored in / transition owner | Required gate |
|---|---|---|
| `UPLOADING` | `media_pipeline`; API creates upload session/staging key. | Private staging object only; short expiry and scoped owner. |
| `UPLOADED` | API finalizer after object `HEAD`, expected size, checksum, owner, and album membership are confirmed. | Bytes verified in private storage; not public. |
| `SCAN_PENDING` | Job/outbox and media row in the same DB transaction as finalization. | Durable queued job and provider capability snapshot. |
| `SCANNING` | Worker claims a leased job and records scanner attempts/provider reference. | Malware scanner must explicitly return a valid clean result. |
| `PROCESSING` | Worker after malware clean; media probe/transcode/thumbnail pipeline. | Container, codec, dimensions, duration, size, and outputs validate under resource limits. |
| `MODERATION_PENDING` | API/worker after required automated checks complete; creates specialist case as policy requires. | Known-content and content-safety checks explicitly complete, no match/unknown, declarations and age requirement valid. |
| `READY` | Senior reviewer or policy-controlled processor transition after all required provider results and human approval. | All required checks current, all derivatives/private objects verified; atomic eligibility recheck. |
| `PUBLISHED` | Publication service changes album/story state only after every item is `READY` and account/policy visibility checks pass. | One canonical `canPublishAlbum()` transaction protects every route, scheduler, profile, feed, search, and media delivery path. |
| `QUARANTINED` | Worker/provider error or high-priority report/moderator action. | Immediately private, removed from feeds, no downloadable admin gallery; assigned review/escalation. |
| `REJECTED` | Scanner/provider or authorized moderator decision with reason code. | Never publish; preserve minimum evidence/audit per retention and legal policy. |
| `FAILED` | Worker after retry policy, parser failure, or exhausted provider outage. | Not public; retry or manual queue action only. |
| `DELETED` | Owner/admin delete service records tombstone and deletion job. | Revoke URLs/cache, remove derivatives/objects after retention/legal-hold rules, preserve required audit metadata. |

Failure transitions: any state before `READY` may go to `QUARANTINED` or `FAILED`; confirmed policy violation can go to `REJECTED`; a deletion request can tombstone to `DELETED`. A provider timeout, missing adapter, unknown result, stale result, hash mismatch, unrecognized media, or moderation disagreement is never a clean/ready transition. A report is not itself a safety verdict, but suspected-minor/non-consensual reports must trigger immediate restricted review under the documented response policy.

The DB is authoritative for access state. The job queue is delivery/retry state, not the public/private authority. Object-store tags and CDN caches are not authorization. Every public request must re-check DB publication and media states (or a short-lived signed grant minted only after those checks).

## 7. Deployment architecture

Practical small-startup deployment, with vendor selection left open:

1. One managed Node application environment, behind its managed HTTPS reverse proxy. Build once; run the web/API command as one process role and `worker` as another role from the same release. Keep admin under the same secured origin.
2. One managed PostgreSQL primary with automated PITR/backups and private network access. Use connection pooling; set connection limits for both process roles.
3. One private S3-compatible object-storage account/bucket with staging and processed prefixes, lifecycle/versioning settings, and role-based credentials. Give the browser only narrowly scoped presigned upload grants; give workers read/write only required prefixes.
4. Optional CDN with private origin access for approved public renditions. Do not publish the bucket. Use signed URLs/cookies after app authorization and short expiry for private/unlisted assets.
5. DNS for one canonical HTTPS site/API origin. Platform-managed TLS certificates and renewal. Redirect HTTP to HTTPS; configure HSTS only after validation. Set exact `AROUSED_ALLOWED_ORIGINS`, cookie Secure, trusted proxy hops, request limits, and host allowlist.
6. Keep Resend/provider credentials in deployment secret storage, not browser JavaScript, `.env.example`, image layers, or logs. No production default secrets.
7. Managed logs/metrics/alerts and encrypted database/object backups. A separate staging environment uses test provider credentials and test media; it must not set real creator accounts to verified or treat sandbox results as production decisions.

Initial production environment variable groups (names are design targets, not currently implemented unless listed):

- Existing: `NODE_ENV`, `AROUSED_API_PORT`, `AROUSED_ALLOWED_ORIGINS`, `AROUSED_MAX_UPLOAD_BYTES`, `AROUSED_ADMIN_EMAIL`, `AROUSED_ADMIN_PASSWORD`, `RESEND_API_KEY`, `AROUSED_FROM_EMAIL`, `AROUSED_EMAIL_CODE_SECRET`, `AROUSED_DATA_DIR`, `AROUSED_UPLOAD_DIR`.
- Proposed: `DATABASE_URL` (secret), `PUBLIC_BASE_URL`, `TRUSTED_PROXY_HOPS`, `OBJECT_STORAGE_ENDPOINT`, `OBJECT_STORAGE_BUCKET`, `OBJECT_STORAGE_REGION`, object role/secret references, `CDN_BASE_URL`, `QUEUE_CONCURRENCY`, `MEDIA_TEMP_DIR`, provider client IDs/secrets/callback URLs, provider webhook secrets, monitoring/OTel endpoint and sampling configuration.
- Never check in actual values. Validate required values at production startup and report only variable names/status, never values.

## 8. Backup and recovery plan

- Before migration: complete the SQLite/media snapshot, manifest, isolated restore, integrity checks, and tested rollback copy in Section 5.
- PostgreSQL: managed PITR with a proposed initial 7-day point-in-time window plus encrypted daily snapshots retained 30 days (confirm legal, budget, and platform limits). Set provisional targets of RPO ≤15 minutes and RTO ≤4 hours, then test and revise based on service needs.
- Object storage: enable versioning or an equivalent recovery window for processed/source objects, object lock/legal hold only where policy requires, and independent inventory/checksum audits. Versioning is not a substitute for application-level delete/privacy processes.
- Secrets/configuration: backup references/configuration in a secret manager with restricted break-glass access; rotate credentials after suspected exposure. Do not store secrets beside downloadable media.
- Restore drills: at least quarterly and before major migrations. Restore DB and objects into isolated staging, verify foreign keys/object checksums/provider state, exercise login, dashboard, album, moderation, deletion, and signed-media revocation. Record duration and gaps.
- Incident recovery: disable uploads/publication through a tested kill switch; retain original evidence as law/policy requires; restore to a new environment; rotate session/provider credentials if exposure is suspected; reconcile changes after the backup point before reopening writes.

## 9. Monitoring, logging, and alerting

Minimum signals and alerts:

- API availability/error rate/latency; authentication failures, OTP/provider send failures, reset attempts, admin role changes, and unusual rate-limit spikes.
- Job queue depth and oldest-job age by stage/provider; worker heartbeat, retries, dead letters, provider timeout rates, quarantine/rejection counts, and time awaiting human review.
- Database availability, connection pool saturation, slow queries, disk/storage growth, replication/PITR age, and migration failures.
- Object-store upload/HEAD/checksum failures, rejected size/type, processing temp disk exhaustion, CDN 4xx/5xx, signed URL expiry behavior, and unexpected public access denials/grants.
- Backup freshness and restore drill success; alert when any backup is stale or unverified.

Use structured JSON logs with request/trace IDs and stable error codes. Redact emails where possible, never log passwords, OTPs, cookie/session tokens, full signed URLs, raw report text, or media bytes. Restrict high-risk event logs. Define on-call owners and critical safety escalation paging before the corresponding content workflow is enabled. Monitoring must page a human; dashboard-only display is not escalation.

## 10. Implementation sequence

Do not break the existing UI or replace its album-first model. Keep endpoint payloads and browser route behavior stable while infrastructure changes underneath.

1. **Freeze and back up:** maintenance window, SQLite online snapshot, complete upload tree/hash manifest, encrypted secret/config backup, independent restore and integrity check. No data deletion.
2. **Security fixes implemented and locally verified:** generic public auth responses, dummy scrypt for unknown login emails, strict same-origin provenance for unsafe requests, secure unknown/orphan upload paths, a canonical `canPublishAlbum()` gate across public reads/immediate publish/visibility/admin restore/scheduling, guarded URL decoding, one-time admin bootstrap, session revocation/rotation, and direct route authorization tests. Staging verification and residual timing/proxy/cross-origin hardening are still required. Keep provider-dependent publication disabled.
3. **Stage-only architecture seam:** define DB, email, identity, storage, job, scan, processing, and safety interfaces without changing UI contracts. Explicit provider result types include `NOT_CONFIGURED`, `UNKNOWN`, and errors.
4. **PostgreSQL migration in staging:** versioned schema and importer; preserve IDs/history; compare counts/constraints/data hashes; test session invalidation/preservation decision. Leave SQLite source untouched.
5. **Private storage adapter and copy tool:** use a staging bucket/prefix, stable media IDs/object keys, checksum verification, private ACLs, and read-only fallback. Test signed delivery; do not change public records to READY due to copy.
6. **Durable queue and worker skeleton:** PostgreSQL lease/outbox, idempotency, retry/dead-letter, worker isolation/limits/temp cleanup. Unknown states stay private.
7. **Media validation/processing:** actual parser/probe/transcode/thumbnail pipeline, resource limits, deletion/retention workflow. Maintain `/media/:id` so UI remains intact.
8. **Malware scanner and exact fingerprinting:** integrate configured real scanner; persist provider/version/evidence. SHA-256 is implemented locally; add result protocol and known-content provider separately. Test timeout/mismatch behavior.
9. **Known-content/content-safety and human moderation:** provider contracts, restricted human queue, critical escalation/on-call playbook, privacy controls, appeals/audit retention. No provider selection by assumption.
10. **Age assurance and creator policy evidence:** choose provider after jurisdiction/legal review; signed callback verification, expiry/recheck rules, and owner-visible status. Keep uploads blocked until this passes production tests.
11. **Email account recovery and OAuth (only providers to be offered):** configure Resend and add a reset UI around the implemented reset API; each OAuth adapter, state/PKCE/callback allowlist, stable provider ID, safe linking/unlinking, account recovery end-to-end tests.
12. **Monitoring/backups and threat tests:** metrics, redacted logs, alerts, backup restore drill, abuse/race/load tests, malware/parser corpus, IDOR/CSRF/URL tests, and provider-down tests.
13. **Production deployment and staged cutover:** exact origins/TLS/secrets, private DB/bucket, web + worker, canary with uploads disabled, data reconciliation, then controlled enablement after all hard gates pass.
14. **Preserve UI acceptance:** run existing creator dashboard, album create/edit/media reorder/delete, public album/media viewer, login/signup, admin moderation, and appeals end-to-end against staging. No redesign; change only backend services and necessary error/status messages.

## 11. Remaining blockers

1. Resend credentials and verified sending domain are absent, and no user-facing reset UI exists; the API fails closed without delivery configuration.
2. Google, Reddit, and X OAuth adapters are missing; decide whether each remains a supported login feature.
3. No age-assurance provider or valid provider-backed verification state exists.
4. No malware scanner, known-content provider, content-safety provider, or media processing worker exists.
5. Queue rows exist but no queue consumer; current provider states are not a complete constrained state machine.
6. SQLite and local disk remain; no tested backup/restore migration or PostgreSQL/object-storage adapter exists.
7. TLS/proxy/production origin/security-header configuration and environment validation are unfinished.
8. Monitoring, alerting, incident response, backup automation, and restore drills are absent.
9. Human safety escalation, moderator staffing, sensitive evidence rules, and retention/legal process are not established.
10. Proxy-aware/distributed rate limits, a synchronizer CSRF token for any future cross-origin client, and timing equalization for email-provider-dependent signup paths remain hardening work. Current same-origin API controls and security regression tests do not replace a staging threat review.

**Final state: NOT READY.** Keep production signup (without verified email), creator upload, processing, and publication disabled until their mandatory provider and operational gates are implemented and verified. Existing local SQLite and media data remain the source of record until a backed-up, restored, validated migration is accepted.

## 12. Production go/no-go decision

**Decision: NO-GO for production today.** The current application is a local prototype, not a production deployment. Do not expose creator uploads or public media delivery to production traffic until all of these gates have evidence in staging:

- PostgreSQL and private object storage are deployed, and a complete data/media migration has been restored and reconciled without deleting the local source data.
- Authentication, authorization, CSRF provenance, upload-path, and publication-gate findings in Section 2 have implementation fixes and isolated direct-request regression tests; repeat the suite against the actual staging deployment before go-live.
- The age-assurance, malware, known-content, content-safety, email, and media-processing dependencies required by enabled features are configured, health-checked, and fail closed when unavailable.
- A durable worker queue, human safety escalation, moderator access controls, and appeal handling are operational.
- TLS, secret management, monitoring, alerting, tested backups, and a successful restore drill are in place.
- The existing UI workflows pass end-to-end against staging, including signup/login, uploads, album playback, moderation, and appeals.

If a gate is not ready, keep the dependent feature disabled and retain the media privately. Reassess the decision only after deployment evidence, test results, and named operational owners are recorded; provider selection and legal review remain explicit decisions for the project owner.
