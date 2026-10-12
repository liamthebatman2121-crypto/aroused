# Private media storage migration plan

**Status: local storage abstraction implemented; no media moved and no object-storage provider configured.** Runtime still uses the existing SQLite database and local `uploads/` directory.

## Abstraction

`storage/storage-provider.mjs` defines `StorageProvider` operations for upload, metadata, private reads, and deletion. `AuthorizedStorage` requires an authorization callback before it requests object bytes. The current `LocalFileStorageProvider` is a development adapter that confines keys to a private root, creates files without overwriting, and keeps its storage directory outside the static web root. Media HTTP routes retain their database-level ownership, visibility, publication, and moderation gates, then stream bytes through the authorization wrapper. The application does not issue public object URLs or signed URLs. Direct authorized streaming is the access mechanism until a production object-store adapter is selected.

## Production adapter contract

Implement a provider only after selecting and configuring a real private object-storage service. The adapter must:

- upload a stream without making the object public; return stable object key and provider metadata;
- retain stable logical keys so existing media IDs, `album_media.storage_name`, `stories.media_path`, and `users.avatar_path` can remain unchanged during the copy;
- read an object only after application authorization, optionally using short-lived signed origin requests that never escape to the browser;
- support byte ranges, content type, object size, and deletion;
- preserve source key and application metadata including media/story/album/user IDs, owner, MIME type, original name, byte size, current status, visibility, and moderation state;
- fail closed on missing credentials, provider errors, missing objects, or authorization errors; never generate a public ACL or public bucket policy.

The interface is deliberately provider-neutral. No fake cloud provider or credential stub has been added.

## Copy-only migration

`scripts/migrate-local-media.mjs` is the future copy-and-verify process. It reads a prepared SQLite copy in read-only mode, enumerates only database-referenced album media, legacy story media, and avatars, verifies each source file size against stored metadata where available, uploads under the unchanged storage key with ownership/moderation metadata, and compares byte counts and SHA-256 hashes by reading the destination back. It is idempotent for already-copied identical keys and fails if the destination key contains different bytes. It never writes to SQLite and never deletes or moves local files.

Run only with a real private destination adapter module that exports `createStorageProvider()`:

```powershell
node scripts/migrate-local-media.mjs `
  --database .\migration-backups\schema-probe-verified\data\aroused.sqlite `
  --local-root .\uploads `
  --provider-module C:\path\to\private-object-storage-adapter.mjs `
  --manifest .\media-copy-manifest.json
```

The verified SQLite snapshot currently has 0 album-media rows, 12 legacy story rows, and 13 users; 24 files (37,557,936 bytes) exist in `uploads/`. The copy tool intentionally does not infer ownership or status for files not referenced by the database. Inventory/associate those orphans explicitly before any future migration run. No migration has run against those files.

## Access verification required before any cutover

For each object class, test allowed owner reads and denied anonymous/other-user reads; private, unpublished, deleted, quarantined, and rejected media must remain denied; public published media must be served only after the canonical publication gate; byte-range responses must re-run authorization; object deletion must not delete database records or backups unexpectedly. Retain the local source and verified backup through staging and an approved production cutover. No production switch or source deletion is included in this phase.
