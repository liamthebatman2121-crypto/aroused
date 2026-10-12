import { createReadStream } from 'node:fs';
import { readFile } from 'node:fs/promises';
import crypto from 'node:crypto';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { DatabaseSync } from 'node:sqlite';

const args = process.argv.slice(2);
const option = name => { const at = args.indexOf(name); return at < 0 ? undefined : args[at + 1]; };
const sourceDbPath = option('--database');
const sourceRoot = option('--local-root');
const providerModule = option('--provider-module');
if (!sourceDbPath || !sourceRoot || !providerModule) {
  throw new Error('Usage: node scripts/migrate-local-media.mjs --database <readonly-sqlite-copy> --local-root <uploads-dir> --provider-module <private-storage-adapter-module>');
}
const providerPath = path.resolve(providerModule);
const imported = await import(pathToFileURL(providerPath));
if (typeof imported.createStorageProvider !== 'function') throw new Error('Provider module must export createStorageProvider().');
const provider = await imported.createStorageProvider();
for (const method of ['upload', 'openRead', 'getMetadata', 'verifyPrivateDestination']) if (typeof provider?.[method] !== 'function') throw new Error(`Storage provider must implement ${method}().`);
const destinationVerification = await provider.verifyPrivateDestination();
if (destinationVerification?.verified !== true || destinationVerification?.private !== true) throw new Error('Storage destination did not verify as private; refusing to copy media.');

const db = new DatabaseSync(path.resolve(sourceDbPath), { readOnly: true });
const tables = new Set(db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all().map(row => row.name));
for (const required of ['album_media', 'albums', 'stories', 'users']) if (!tables.has(required)) throw new Error(`Source schema is missing ${required}; prepare a migrated SQLite copy first.`);
const refs = new Map();
const add = (key, entry) => {
  if (!key) return;
  if (typeof key !== 'string' || key !== path.basename(key) || key.includes('\\') || key.includes('\0') || key === '.' || key === '..') throw new Error(`Unsafe storage key in database (${entry.kind}); refusing copy.`);
  const prior = refs.get(key);
  if (prior && prior.kind !== entry.kind) prior.references.push(entry); else refs.set(key, prior ? { ...prior, references: [...prior.references, entry] } : { ...entry, references: [] });
};
for (const row of db.prepare('SELECT m.id,m.storage_name,m.original_name,m.mime_type,m.byte_size,m.state,m.album_id,a.owner_id FROM album_media m JOIN albums a ON a.id=m.album_id ORDER BY m.id').all()) add(row.storage_name, { kind: 'album-media', mediaId: row.id, albumId: row.album_id, ownerId: row.owner_id, originalName: row.original_name, contentType: row.mime_type, byteSize: row.byte_size, status: row.state });
for (const row of db.prepare('SELECT id,media_path,media_name,media_type,creator_id,status FROM stories WHERE media_path IS NOT NULL').all()) add(path.basename(row.media_path), { kind: 'legacy-story-media', storyId: row.id, ownerId: row.creator_id, originalName: row.media_name, contentType: row.media_type, status: row.status });
for (const row of db.prepare('SELECT id,avatar_path FROM users WHERE avatar_path IS NOT NULL').all()) add(row.avatar_path, { kind: 'avatar', userId: row.id, contentType: 'application/octet-stream' });

const digest = async stream => {
  const hash = crypto.createHash('sha256'); let bytes = 0;
  for await (const chunk of stream) { hash.update(chunk); bytes += chunk.length; }
  return { sha256: hash.digest('hex'), bytes };
};
const result = [];
for (const [key, ref] of refs) {
  const sourcePath = path.join(path.resolve(sourceRoot), key);
  const source = await digest(createReadStream(sourcePath));
  if (ref.byteSize !== undefined && source.bytes !== ref.byteSize) throw new Error(`Source size differs from SQLite metadata for object key ${key}.`);
  const metadata = { contentType: ref.contentType || 'application/octet-stream', metadata: { ...ref, mediaId: ref.mediaId === undefined ? undefined : String(ref.mediaId), albumId: ref.albumId === undefined ? undefined : String(ref.albumId), ownerId: ref.ownerId === undefined ? undefined : String(ref.ownerId), userId: ref.userId === undefined ? undefined : String(ref.userId), storyId: ref.storyId === undefined ? undefined : String(ref.storyId) } };
  let object;
  try {
    await provider.getMetadata(key, metadata);
    object = await provider.openRead(key, { metadata });
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  if (object) {
    const existing = await digest(object.stream);
    if (existing.sha256 !== source.sha256 || existing.bytes !== source.bytes) throw new Error(`Destination already has different bytes for object key ${key}.`);
  } else {
    await provider.upload(key, createReadStream(sourcePath), metadata);
  }
  object = await provider.openRead(key, { metadata });
  const copied = await digest(object.stream);
  if (source.sha256 !== copied.sha256 || source.bytes !== copied.bytes) throw new Error(`Target verification failed for object key ${key}.`);
  result.push({ key, kind: ref.kind, references: [ref, ...ref.references], bytes: copied.bytes, sha256: copied.sha256, status: 'copied-and-verified' });
}
const report = { status: 'copy-verified-local-source-retained', destinationVerification: { driver: destinationVerification.driver || 'unknown', private: true }, database: path.resolve(sourceDbPath), localRoot: path.resolve(sourceRoot), objectsCopied: result.length, bytesCopied: result.reduce((sum, row) => sum + row.bytes, 0), objects: result };
const reportPath = option('--manifest');
if (reportPath) await (await import('node:fs/promises')).writeFile(path.resolve(reportPath), JSON.stringify(report, null, 2) + '\n');
console.log(JSON.stringify(report, null, 2));
db.close();
