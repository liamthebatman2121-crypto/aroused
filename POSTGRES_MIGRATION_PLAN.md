# PostgreSQL staging migration plan

**Status (2026-10-09): staging migration completed and verified; runtime remains on SQLite.**

Generated 2026-10-08 from the current server schema initialized on an isolated copy of the verified backup. The source snapshot itself has 16 tables; current startup migrations expand it to 31 tables without changing the 13 users, 12 stories, or remaining source-table counts. Tables added at startup are represented in the PostgreSQL target schema and begin with zero rows in this snapshot. No source database or upload was changed by schema inspection.

## Source and backup inventory

- SQLite source: `data/aroused.sqlite` (opened read-only by migration runner).
- Verified snapshot: `migration-backups/migration-20261008T154037Z/aroused.sqlite`.
- Current app schema: 31 tables after startup migrations on a copy.
- Source tables at backup time: 16; target-only startup tables are empty at snapshot time.
- Verified source counts at backup time:

```text
admin_audit_log: 7
album_media: 0
albums: 0
app_secrets: 1
comments: 1
follows: 0
likes: 0
messages: 3
pending_email_verifications: 0
reports: 0
reposts: 0
saves: 0
sessions: 1
site_settings: 2
stories: 12
users: 13
```

The backup was invoked in PowerShell with:

```powershell
$env:AROUSED_BACKUP_ROOT = 'C:\Users\ahmed\Documents\Codex\2026-10-03\hel\outputs\migration-backups\migration-20261008T154037Z'
& 'C:\Users\ahmed\.cache\codex-runtimes\codex-primary-runtime\dependencies\node\bin\node.exe' '.\migration-backups\migration-20261008T154037Z\backup-and-verify.mjs'
```

That script ran SQLite `VACUUM INTO` for a consistent database snapshot, copied the entire `uploads/` tree, compared SHA-256/size/path manifests, reopened and integrity-checked the snapshot, copied the database and media into `restore-test/`, then repeated integrity, row-count, and manifest checks. Result: all three database integrity checks were `ok`, all 16 table counts matched source/backup/restore, and all 24 upload files totaling 37,557,936 bytes matched both copies. Machine-readable output is in `migration-backups/migration-20261008T154037Z/verification.json`.

## Table-by-table schema

### `admin_audit_log`

- Snapshot rows: 7
- Columns: id INTEGER [PK]; admin_user_id INTEGER; action TEXT NOT NULL; target_type TEXT NOT NULL; target_id TEXT NOT NULL; details_json TEXT NOT NULL DEFAULT '{}'; created_at TEXT NOT NULL
- Primary key: id
- Foreign keys: admin_user_id → users.id (ON DELETE SET NULL)
- Indexes: admin_audit_created_idx [created_at]
- Unique constraints/indexes: none
- Timestamp fields: created_at
- Status/enum-like fields: action

### `album_media`

- Snapshot rows: 0
- Columns: id INTEGER [PK]; album_id INTEGER NOT NULL; storage_name TEXT NOT NULL; original_name TEXT NOT NULL; mime_type TEXT NOT NULL; byte_size INTEGER NOT NULL; position INTEGER NOT NULL; state TEXT NOT NULL DEFAULT 'ready'; created_at TEXT NOT NULL
- Primary key: id
- Foreign keys: album_id → albums.id (ON DELETE CASCADE)
- Indexes: album_media_album_idx [album_id, position]; sqlite_autoindex_album_media_2 [UNIQUE album_id, position]; sqlite_autoindex_album_media_1 [UNIQUE storage_name]
- Unique constraints/indexes: album_id, position; storage_name
- Timestamp fields: created_at
- Status/enum-like fields: none

### `albums`

- Snapshot rows: 0
- Columns: id INTEGER [PK]; story_id INTEGER NOT NULL; owner_id INTEGER NOT NULL; slug TEXT NOT NULL; description TEXT NOT NULL DEFAULT ''; visibility TEXT NOT NULL DEFAULT 'public'; status TEXT NOT NULL DEFAULT 'draft'; allow_comments INTEGER NOT NULL DEFAULT 1; cover_media_id INTEGER; created_at TEXT NOT NULL; updated_at TEXT NOT NULL; publish_mode TEXT NOT NULL DEFAULT 'immediate'; scheduled_at TEXT; review_status TEXT NOT NULL DEFAULT 'not_required'
- Primary key: id
- Foreign keys: owner_id → users.id (ON DELETE CASCADE); story_id → stories.id (ON DELETE CASCADE)
- Indexes: albums_visibility_idx [visibility, status, created_at]; albums_owner_idx [owner_id, status, updated_at]; sqlite_autoindex_albums_2 [UNIQUE slug]; sqlite_autoindex_albums_1 [UNIQUE story_id]
- Unique constraints/indexes: slug; story_id
- Timestamp fields: created_at, updated_at, scheduled_at
- Status/enum-like fields: visibility, status, publish_mode, review_status

### `app_secrets`

- Snapshot rows: 1
- Columns: name TEXT [PK]; value TEXT NOT NULL
- Primary key: name
- Foreign keys: none
- Indexes: sqlite_autoindex_app_secrets_1 [UNIQUE name]
- Unique constraints/indexes: name
- Timestamp fields: none
- Status/enum-like fields: none

### `appeals`

- Snapshot rows: 0 (table is created by current server startup; absent from pre-startup snapshot)
- Columns: id INTEGER [PK]; user_id INTEGER NOT NULL; enforcement_id INTEGER; reason TEXT NOT NULL; status TEXT NOT NULL DEFAULT 'open'; assigned_to INTEGER; created_at TEXT NOT NULL; updated_at TEXT NOT NULL; decision_reason TEXT
- Primary key: id
- Foreign keys: assigned_to → users.id (ON DELETE SET NULL); enforcement_id → enforcement_actions.id (ON DELETE SET NULL); user_id → users.id (ON DELETE CASCADE)
- Indexes: none
- Unique constraints/indexes: none
- Timestamp fields: created_at, updated_at
- Status/enum-like fields: status

### `comments`

- Snapshot rows: 1
- Columns: id INTEGER [PK]; user_id INTEGER NOT NULL; story_id INTEGER NOT NULL; body TEXT NOT NULL; created_at TEXT NOT NULL
- Primary key: id
- Foreign keys: story_id → stories.id (ON DELETE CASCADE); user_id → users.id (ON DELETE CASCADE)
- Indexes: comments_story_idx [story_id, created_at]
- Unique constraints/indexes: none
- Timestamp fields: created_at
- Status/enum-like fields: none

### `creator_declarations`

- Snapshot rows: 0 (table is created by current server startup; absent from pre-startup snapshot)
- Columns: id INTEGER [PK]; album_id INTEGER NOT NULL; user_id INTEGER NOT NULL; declaration_key TEXT NOT NULL; policy_version TEXT NOT NULL; accepted_at TEXT NOT NULL
- Primary key: id
- Foreign keys: user_id → users.id (ON DELETE CASCADE); album_id → albums.id (ON DELETE CASCADE)
- Indexes: sqlite_autoindex_creator_declarations_1 [UNIQUE album_id, declaration_key, policy_version]
- Unique constraints/indexes: album_id, declaration_key, policy_version
- Timestamp fields: accepted_at
- Status/enum-like fields: declaration_key

### `enforcement_actions`

- Snapshot rows: 0 (table is created by current server startup; absent from pre-startup snapshot)
- Columns: id INTEGER [PK]; user_id INTEGER NOT NULL; admin_user_id INTEGER; action TEXT NOT NULL; reason TEXT NOT NULL; expires_at TEXT; created_at TEXT NOT NULL; revoked_at TEXT
- Primary key: id
- Foreign keys: admin_user_id → users.id (ON DELETE SET NULL); user_id → users.id (ON DELETE CASCADE)
- Indexes: none
- Unique constraints/indexes: none
- Timestamp fields: expires_at, created_at, revoked_at
- Status/enum-like fields: action

### `follows`

- Snapshot rows: 0
- Columns: follower_id INTEGER NOT NULL [PK]; creator_id INTEGER NOT NULL [PK]
- Primary key: follower_id, creator_id
- Foreign keys: creator_id → users.id (ON DELETE CASCADE); follower_id → users.id (ON DELETE CASCADE)
- Indexes: sqlite_autoindex_follows_1 [UNIQUE follower_id, creator_id]
- Unique constraints/indexes: follower_id, creator_id
- Timestamp fields: none
- Status/enum-like fields: none

### `likes`

- Snapshot rows: 0
- Columns: user_id INTEGER NOT NULL [PK]; story_id INTEGER NOT NULL [PK]
- Primary key: user_id, story_id
- Foreign keys: story_id → stories.id (ON DELETE CASCADE); user_id → users.id (ON DELETE CASCADE)
- Indexes: sqlite_autoindex_likes_1 [UNIQUE user_id, story_id]
- Unique constraints/indexes: user_id, story_id
- Timestamp fields: none
- Status/enum-like fields: none

### `media_fingerprints`

- Snapshot rows: 0 (table is created by current server startup; absent from pre-startup snapshot)
- Columns: media_id INTEGER [PK]; sha256 TEXT NOT NULL; byte_size INTEGER NOT NULL; created_at TEXT NOT NULL
- Primary key: media_id
- Foreign keys: media_id → album_media.id (ON DELETE CASCADE)
- Indexes: none
- Unique constraints/indexes: none
- Timestamp fields: created_at
- Status/enum-like fields: none

### `media_pipeline`

- Snapshot rows: 0 (table is created by current server startup; absent from pre-startup snapshot)
- Columns: media_id INTEGER [PK]; status TEXT NOT NULL DEFAULT 'SCAN_PENDING'; malware_status TEXT NOT NULL DEFAULT 'NOT_CONFIGURED'; processing_status TEXT NOT NULL DEFAULT 'NOT_CONFIGURED'; known_content_status TEXT NOT NULL DEFAULT 'NOT_CONFIGURED'; safety_status TEXT NOT NULL DEFAULT 'NOT_CONFIGURED'; moderation_status TEXT NOT NULL DEFAULT 'PENDING'; attempts INTEGER NOT NULL DEFAULT 0; error_code TEXT; updated_at TEXT NOT NULL
- Primary key: media_id
- Foreign keys: media_id → album_media.id (ON DELETE CASCADE)
- Indexes: media_pipeline_status_idx [status, updated_at]
- Unique constraints/indexes: none
- Timestamp fields: updated_at
- Status/enum-like fields: status, malware_status, processing_status, known_content_status, safety_status, moderation_status

### `media_scan_results`

- Snapshot rows: 0 (table is created by current server startup; absent from pre-startup snapshot)
- Columns: id INTEGER [PK]; media_id INTEGER NOT NULL; provider TEXT NOT NULL; result TEXT NOT NULL; detail_code TEXT; created_at TEXT NOT NULL; check_type TEXT; provider_reference TEXT; started_at TEXT; completed_at TEXT; audit_metadata_json TEXT NOT NULL DEFAULT '{}'
- Primary key: id
- Foreign keys: media_id → album_media.id (ON DELETE CASCADE)
- Indexes: media_scan_results_media_idx [media_id, created_at]
- Unique constraints/indexes: none
- Timestamp fields: created_at, started_at, completed_at
- Status/enum-like fields: provider, result, check_type

### `messages`

- Snapshot rows: 3
- Columns: id INTEGER [PK]; sender_id INTEGER NOT NULL; recipient_id INTEGER NOT NULL; body TEXT NOT NULL; created_at TEXT NOT NULL; is_system_notice INTEGER NOT NULL DEFAULT 0
- Primary key: id
- Foreign keys: recipient_id → users.id (ON DELETE CASCADE); sender_id → users.id (ON DELETE CASCADE)
- Indexes: messages_pair_idx [sender_id, recipient_id, created_at]
- Unique constraints/indexes: none
- Timestamp fields: created_at
- Status/enum-like fields: none

### `moderation_cases`

- Snapshot rows: 0 (table is created by current server startup; absent from pre-startup snapshot)
- Columns: id INTEGER [PK]; album_id INTEGER; media_id INTEGER; report_id INTEGER; category TEXT NOT NULL; priority TEXT NOT NULL DEFAULT 'normal'; status TEXT NOT NULL DEFAULT 'open'; restricted INTEGER NOT NULL DEFAULT 0; assigned_to INTEGER; decision TEXT; decision_reason TEXT; created_at TEXT NOT NULL; updated_at TEXT NOT NULL; resolved_at TEXT
- Primary key: id
- Foreign keys: assigned_to → users.id (ON DELETE SET NULL); media_id → album_media.id (ON DELETE SET NULL); album_id → albums.id (ON DELETE SET NULL)
- Indexes: moderation_cases_queue_idx [status, priority, created_at]
- Unique constraints/indexes: none
- Timestamp fields: created_at, updated_at, resolved_at
- Status/enum-like fields: category, priority, status

### `oauth_transactions`

- Snapshot rows: 0 (table is created by current server startup; absent from pre-startup snapshot)
- Columns: state_hash TEXT [PK]; provider TEXT NOT NULL; purpose TEXT NOT NULL; user_id INTEGER; code_verifier TEXT; adult_confirmed INTEGER NOT NULL DEFAULT 0; terms_version TEXT; guidelines_version TEXT; created_at INTEGER NOT NULL; expires_at INTEGER NOT NULL
- Primary key: state_hash
- Foreign keys: user_id → users.id (ON DELETE CASCADE)
- Indexes: sqlite_autoindex_oauth_transactions_1 [UNIQUE state_hash]
- Unique constraints/indexes: state_hash
- Timestamp fields: created_at, expires_at
- Status/enum-like fields: provider, purpose

### `password_reset_tokens`

- Snapshot rows: 0 (table is created by current server startup; absent from pre-startup snapshot)
- Columns: token_hash TEXT [PK]; user_id INTEGER NOT NULL; expires_at INTEGER NOT NULL; used_at TEXT; created_at TEXT NOT NULL
- Primary key: token_hash
- Foreign keys: user_id → users.id (ON DELETE CASCADE)
- Indexes: sqlite_autoindex_password_reset_tokens_1 [UNIQUE token_hash]
- Unique constraints/indexes: token_hash
- Timestamp fields: expires_at, used_at, created_at
- Status/enum-like fields: none

### `pending_email_verifications`

- Snapshot rows: 0
- Columns: email TEXT [PK]; display_name TEXT NOT NULL; password_hash TEXT NOT NULL; code_hash TEXT NOT NULL; expires_at INTEGER NOT NULL; next_send_at INTEGER NOT NULL; attempts INTEGER NOT NULL DEFAULT 0; created_at TEXT NOT NULL; terms_accepted_at TEXT; guidelines_accepted_at TEXT; terms_version TEXT; guidelines_version TEXT
- Primary key: email
- Foreign keys: none
- Indexes: sqlite_autoindex_pending_email_verifications_1 [UNIQUE email]
- Unique constraints/indexes: email
- Timestamp fields: expires_at, next_send_at, created_at, terms_accepted_at, guidelines_accepted_at
- Status/enum-like fields: none

### `policy_acceptances`

- Snapshot rows: 0 (table is created by current server startup; absent from pre-startup snapshot)
- Columns: id INTEGER [PK]; user_id INTEGER NOT NULL; album_id INTEGER; policy_key TEXT NOT NULL; policy_version TEXT NOT NULL; accepted_at TEXT NOT NULL
- Primary key: id
- Foreign keys: user_id → users.id (ON DELETE CASCADE)
- Indexes: policy_acceptances_user_idx [user_id, policy_key, accepted_at]; sqlite_autoindex_policy_acceptances_1 [UNIQUE user_id, album_id, policy_key, policy_version]
- Unique constraints/indexes: user_id, album_id, policy_key, policy_version
- Timestamp fields: accepted_at
- Status/enum-like fields: policy_key

### `processing_jobs`

- Snapshot rows: 0 (table is created by current server startup; absent from pre-startup snapshot)
- Columns: id INTEGER [PK]; media_id INTEGER NOT NULL; status TEXT NOT NULL; attempts INTEGER NOT NULL DEFAULT 0; available_at INTEGER NOT NULL; created_at TEXT NOT NULL; updated_at TEXT NOT NULL; error_code TEXT
- Primary key: id
- Foreign keys: media_id → album_media.id (ON DELETE CASCADE)
- Indexes: processing_jobs_queue_idx [status, available_at]
- Unique constraints/indexes: none
- Timestamp fields: available_at, created_at, updated_at
- Status/enum-like fields: status

### `rate_limit_buckets`

- Snapshot rows: 0 (table is created by current server startup; absent from pre-startup snapshot)
- Columns: bucket_key TEXT [PK]; hits INTEGER NOT NULL; reset_at INTEGER NOT NULL
- Primary key: bucket_key
- Foreign keys: none
- Indexes: sqlite_autoindex_rate_limit_buckets_1 [UNIQUE bucket_key]
- Unique constraints/indexes: bucket_key
- Timestamp fields: reset_at
- Status/enum-like fields: none

### `reports`

- Snapshot rows: 0
- Columns: id INTEGER [PK]; reporter_id INTEGER; story_id INTEGER; target_user_id INTEGER; reason TEXT NOT NULL; details TEXT NOT NULL DEFAULT ''; status TEXT NOT NULL DEFAULT 'open'; created_at TEXT NOT NULL; category TEXT NOT NULL DEFAULT 'other'; priority TEXT NOT NULL DEFAULT 'normal'; assigned_to INTEGER; updated_at TEXT
- Primary key: id
- Foreign keys: assigned_to → users.id (ON DELETE SET NULL); target_user_id → users.id (ON DELETE SET NULL); story_id → stories.id (ON DELETE SET NULL); reporter_id → users.id (ON DELETE SET NULL)
- Indexes: none
- Unique constraints/indexes: none
- Timestamp fields: created_at, updated_at
- Status/enum-like fields: status, category, priority

### `reposts`

- Snapshot rows: 0
- Columns: user_id INTEGER NOT NULL [PK]; story_id INTEGER NOT NULL [PK]; created_at TEXT NOT NULL
- Primary key: user_id, story_id
- Foreign keys: story_id → stories.id (ON DELETE CASCADE); user_id → users.id (ON DELETE CASCADE)
- Indexes: sqlite_autoindex_reposts_1 [UNIQUE user_id, story_id]
- Unique constraints/indexes: user_id, story_id
- Timestamp fields: created_at
- Status/enum-like fields: none

### `saves`

- Snapshot rows: 0
- Columns: user_id INTEGER NOT NULL [PK]; story_id INTEGER NOT NULL [PK]; created_at TEXT NOT NULL
- Primary key: user_id, story_id
- Foreign keys: story_id → stories.id (ON DELETE CASCADE); user_id → users.id (ON DELETE CASCADE)
- Indexes: sqlite_autoindex_saves_1 [UNIQUE user_id, story_id]
- Unique constraints/indexes: user_id, story_id
- Timestamp fields: created_at
- Status/enum-like fields: none

### `security_events`

- Snapshot rows: 0 (table is created by current server startup; absent from pre-startup snapshot)
- Columns: id INTEGER [PK]; user_id INTEGER; event_type TEXT NOT NULL; severity TEXT NOT NULL DEFAULT 'info'; detail_code TEXT NOT NULL; created_at TEXT NOT NULL
- Primary key: id
- Foreign keys: user_id → users.id (ON DELETE SET NULL)
- Indexes: security_events_created_idx [created_at]
- Unique constraints/indexes: none
- Timestamp fields: created_at
- Status/enum-like fields: event_type, severity

### `sessions`

- Snapshot rows: 1
- Columns: token_hash TEXT [PK]; user_id INTEGER NOT NULL; expires_at INTEGER NOT NULL
- Primary key: token_hash
- Foreign keys: user_id → users.id (ON DELETE CASCADE)
- Indexes: sqlite_autoindex_sessions_1 [UNIQUE token_hash]
- Unique constraints/indexes: token_hash
- Timestamp fields: expires_at
- Status/enum-like fields: none

### `site_settings`

- Snapshot rows: 2
- Columns: name TEXT [PK]; value TEXT NOT NULL
- Primary key: name
- Foreign keys: none
- Indexes: sqlite_autoindex_site_settings_1 [UNIQUE name]
- Unique constraints/indexes: name
- Timestamp fields: none
- Status/enum-like fields: none

### `stories`

- Snapshot rows: 12
- Columns: id INTEGER [PK]; creator_id INTEGER NOT NULL; title TEXT NOT NULL; category TEXT NOT NULL; tags_json TEXT NOT NULL DEFAULT '[]'; media_name TEXT; media_path TEXT; media_type TEXT; duration TEXT NOT NULL DEFAULT '00:00'; views INTEGER NOT NULL DEFAULT 0; seeded_likes INTEGER NOT NULL DEFAULT 0; tone_a TEXT NOT NULL DEFAULT '#59352f'; tone_b TEXT NOT NULL DEFAULT '#c17767'; status TEXT NOT NULL DEFAULT 'published'; created_at TEXT NOT NULL; cover_media_id INTEGER
- Primary key: id
- Foreign keys: creator_id → users.id (ON DELETE NO ACTION)
- Indexes: story_search_idx [title, category]; story_creator_idx [creator_id, created_at]
- Unique constraints/indexes: none
- Timestamp fields: created_at
- Status/enum-like fields: category, status

### `upload_jobs`

- Snapshot rows: 0 (table is created by current server startup; absent from pre-startup snapshot)
- Columns: id INTEGER [PK]; album_id INTEGER NOT NULL; status TEXT NOT NULL; created_at TEXT NOT NULL; updated_at TEXT NOT NULL; error_code TEXT
- Primary key: id
- Foreign keys: album_id → albums.id (ON DELETE CASCADE)
- Indexes: none
- Unique constraints/indexes: none
- Timestamp fields: created_at, updated_at
- Status/enum-like fields: status

### `user_identities`

- Snapshot rows: 0 (table is created by current server startup; absent from pre-startup snapshot)
- Columns: id INTEGER [PK]; user_id INTEGER NOT NULL; provider TEXT NOT NULL; provider_user_id TEXT NOT NULL; provider_email TEXT; created_at TEXT NOT NULL; updated_at TEXT NOT NULL
- Primary key: id
- Foreign keys: user_id → users.id (ON DELETE CASCADE)
- Indexes: user_identities_user_idx [user_id]; sqlite_autoindex_user_identities_2 [UNIQUE user_id, provider]; sqlite_autoindex_user_identities_1 [UNIQUE provider, provider_user_id]
- Unique constraints/indexes: user_id, provider; provider, provider_user_id
- Timestamp fields: created_at, updated_at
- Status/enum-like fields: provider, provider_user_id, provider_email

### `users`

- Snapshot rows: 13
- Columns: id INTEGER [PK]; display_name TEXT NOT NULL; email TEXT; password_hash TEXT; avatar_initial TEXT NOT NULL; adult_confirmed INTEGER NOT NULL DEFAULT 0; created_at TEXT NOT NULL; onlyfans_url TEXT NOT NULL DEFAULT ''; avatar_path TEXT; updated_at TEXT; username TEXT NOT NULL DEFAULT ''; bio TEXT NOT NULL DEFAULT ''; email_verified_at TEXT; terms_accepted_at TEXT; guidelines_accepted_at TEXT; upload_restricted INTEGER NOT NULL DEFAULT 0; suspended INTEGER NOT NULL DEFAULT 0; role TEXT NOT NULL DEFAULT 'user'; banned INTEGER NOT NULL DEFAULT 0; age_status TEXT NOT NULL DEFAULT 'unverified'; age_verified_at TEXT; creator_agreement_version TEXT
- Primary key: id
- Foreign keys: none
- Indexes: users_username_unique [UNIQUE username]; sqlite_autoindex_users_1 [UNIQUE email]
- Unique constraints/indexes: username; email
- Timestamp fields: created_at, updated_at, email_verified_at, terms_accepted_at, guidelines_accepted_at, age_verified_at
- Status/enum-like fields: role, age_status

## PostgreSQL mapping and migration concerns

- SQL types: SQLite `INTEGER` becomes PostgreSQL `BIGINT`; integer primary keys use `GENERATED BY DEFAULT AS IDENTITY` so original IDs can be inserted. SQLite `TEXT` stays `TEXT`; timestamps remain their original ISO-text or integer epoch representation in this staging pass to avoid timezone/coercion loss.
- Status/enumeration values: retain as text and preserve SQLite CHECK constraints where present. Fields without a SQLite CHECK (including report status, user role, album publish mode/review status, moderation status/decision, and job status) are not treated as closed enums; validation can be added only after observed values are inventoried.
- Case-insensitive uniqueness: SQLite `NOCASE` semantics are represented by PostgreSQL unique indexes on `lower(email)`, `lower(username)`, and `lower(pending_email_verifications.email)`. Existing values must be checked for case-folded collisions before applying these indexes.
- Foreign keys and cascade behavior: preserve declared references and ON DELETE actions. Validate with `PRAGMA foreign_key_check` before export and PostgreSQL constraint checks after import.
- JSON-shaped fields such as `tags_json` and `details_json` remain text in phase 1; converting to `JSONB` could reject legacy strings and is deliberately deferred.
- Password hashes, session token hashes, pending OTP hashes, reset token hashes, app secrets, audit details, report details, and safety metadata are sensitive. The migration uses a private staging database and must not print row contents or DSNs. Expired sessions/tokens are copied as-is for data preservation; session invalidation/cutover policy needs explicit decision.
- PostgreSQL target schema is in `migrations/postgres/001_schema.sql`; data import runner is in `scripts/postgres/migrate-staging.mjs`. Before any DDL/write transaction it requires an explicitly confirmed staging DSN, exact database name ending `_staging` or `_test`, configured dedicated owner/login, a database comment marker `aroused-disposable-staging`, an empty `public` schema, and no user-created schemas. It is not referenced by `server.mjs`.
- Rollback is to discard only the staging database; the SQLite snapshot and uploads remain intact. A production cutover requires a separately approved freeze/reconciliation/restore plan.
- Albums/media currently have zero rows in the verified SQLite snapshot; stories have 12 legacy rows. Current server boot on the probe database did not synthesize albums/media for those rows because the verified snapshot has no corresponding local file entries. The importer preserves story rows and does not invent media rows.
- The local uploads tree has 24 files, but there are zero albums/album_media in this snapshot. Reconcile all 24 file hashes and legacy story paths before any future object-store move; do not infer association from filenames.

## Staging verification matrix

The importer reports per-table row counts and verifies them against source. It additionally compares every declared SQLite unique index and foreign-key definition (including delete action) with PostgreSQL catalogs, checks target FK values, and compares relationship counts for identities, sessions, story creators, album owners/media, reports, moderation cases, and creator declarations. The integration test seeds a disposable source copy with an album/media-owner relationship and quarantined pipeline state before migration, then verifies preserved IDs, ownership, relationships, and state. Verified run on 2026-10-09: PostgreSQL 18.6 staging target `aroused_staging` passed database name, owner/login, disposable marker, and empty-target preflight. Import completed for all 31 tables with matching counts, 7 matching relationship counts, 22 unique indexes, and 42 foreign keys. The PostgreSQL integration test passed 3/3; the full local suite passed 9/9 with its PostgreSQL case skipped in that run. The separately marked `aroused_test` database is now populated by the integration fixture and must be recreated as a fresh disposable DB before another integration run. `server.mjs` remains on SQLite; no media was migrated. The prepared source passed integrity check and its 16 original tables match the current SQLite data across common columns.
