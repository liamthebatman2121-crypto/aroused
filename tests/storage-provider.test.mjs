import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { DatabaseSync } from 'node:sqlite';
import { LocalFileStorageProvider, AuthorizedStorage, StorageAccessDenied } from '../storage/storage-provider.mjs';

test('private local storage uploads bytes, reports metadata, streams ranges, and deletes', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'aroused-storage-'));
  try {
    const provider = new LocalFileStorageProvider(path.join(root, 'private'));
    await provider.upload('media/asset.bin', Buffer.from('abcdef'), { contentType: 'application/octet-stream', metadata: { mediaId: '17', ownerId: '4' } });
    const metadata = await provider.getMetadata('media/asset.bin');
    assert.equal(metadata.size, 6);
    assert.equal(metadata.contentType, 'application/octet-stream');
    assert.deepEqual(metadata.metadata, { mediaId: '17', ownerId: '4' });
    const read = await provider.openRead('media/asset.bin', { start: 1, end: 3 });
    const chunks = [];
    for await (const chunk of read.stream) chunks.push(chunk);
    assert.equal(Buffer.concat(chunks).toString(), 'bcd');
    assert.equal((await readFile(path.join(root, 'private', 'media', 'asset.bin'))).toString(), 'abcdef');
    await provider.delete('media/asset.bin');
    await assert.rejects(provider.getMetadata('media/asset.bin'), { code: 'ENOENT' });
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('authorized storage denies private, unpublished, deleted, quarantined, and rejected reads before object access', async () => {
  let openCalls = 0;
  const storage = new AuthorizedStorage({ async openRead() { openCalls++; return { stream: null }; } });
  for (const state of ['private-other-owner', 'unpublished', 'deleted', 'quarantined', 'rejected', 'unauthorized']) {
    await assert.rejects(storage.openRead('private/object', () => state === 'public-published'), StorageAccessDenied);
  }
  assert.equal(openCalls, 0);
  await storage.openRead('public/object', () => true);
  assert.equal(openCalls, 1);
});

test('local storage rejects traversal and refuses to overwrite an existing object', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'aroused-storage-'));
  try {
    const provider = new LocalFileStorageProvider(path.join(root, 'private'));
    await assert.rejects(provider.upload('../escape', Buffer.from('x')));
    await assert.rejects(provider.upload('..\\escape', Buffer.from('x')));
    await provider.upload('same', Buffer.from('one'));
    await assert.rejects(provider.upload('same', Buffer.from('two')));
    assert.equal((await readFile(path.join(root, 'private', 'same'))).toString(), 'one');
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('local-media migration copies stable IDs and metadata and retains the source file', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'aroused-media-copy-'));
  try {
    const database = path.join(root, 'source.sqlite');
    const sourceRoot = path.join(root, 'uploads');
    const destinationRoot = path.join(root, 'private-destination');
    const adapterPath = path.join(root, 'test-adapter.mjs');
    await import('node:fs/promises').then(fs => fs.mkdir(sourceRoot, { recursive: true }));
    const bytes = Buffer.from('small media sample');
    await import('node:fs/promises').then(fs => fs.writeFile(path.join(sourceRoot, 'media-31.bin'), bytes));
    const db = new DatabaseSync(database);
    db.exec(`CREATE TABLE albums(id INTEGER PRIMARY KEY, owner_id INTEGER); CREATE TABLE album_media(id INTEGER PRIMARY KEY, storage_name TEXT, original_name TEXT, mime_type TEXT, byte_size INTEGER, state TEXT, album_id INTEGER); CREATE TABLE stories(id INTEGER PRIMARY KEY, media_path TEXT, media_name TEXT, media_type TEXT, creator_id INTEGER, status TEXT); CREATE TABLE users(id INTEGER PRIMARY KEY, avatar_path TEXT);`);
    db.prepare('INSERT INTO albums VALUES (?,?)').run(8, 9);
    db.prepare('INSERT INTO album_media VALUES (?,?,?,?,?,?,?)').run(31, 'media-31.bin', 'clip.bin', 'application/octet-stream', bytes.length, 'QUARANTINED', 8);
    db.close();
    await (await import('node:fs/promises')).writeFile(adapterPath, `import { LocalFileStorageProvider } from ${JSON.stringify(pathToFileURL(path.resolve(import.meta.dirname, '../storage/storage-provider.mjs')).href)};\nexport async function createStorageProvider(){return new LocalFileStorageProvider(${JSON.stringify(destinationRoot)});}\n`);
    const child = spawnSync(process.execPath, ['scripts/migrate-local-media.mjs', '--database', database, '--local-root', sourceRoot, '--provider-module', adapterPath], { cwd: path.resolve(import.meta.dirname, '..'), encoding: 'utf8' });
    assert.equal(child.status, 0, child.stderr || child.stdout);
    const report = JSON.parse(child.stdout);
    assert.equal(report.status, 'copy-verified-local-source-retained');
    assert.equal(report.objectsCopied, 1);
    assert.equal(report.objects[0].key, 'media-31.bin');
    assert.equal(report.objects[0].references[0].mediaId, 31);
    assert.equal(report.objects[0].references[0].albumId, 8);
    assert.equal(report.objects[0].references[0].ownerId, 9);
    assert.equal(report.objects[0].references[0].status, 'QUARANTINED');
    assert.equal((await readFile(path.join(sourceRoot, 'media-31.bin'))).toString(), bytes.toString());
    assert.equal((await readFile(path.join(destinationRoot, 'media-31.bin'))).toString(), bytes.toString());
    const destination = await new LocalFileStorageProvider(destinationRoot).getMetadata('media-31.bin');
    assert.equal(destination.metadata.mediaId, '31');
    assert.equal(destination.metadata.ownerId, '9');
    assert.equal(destination.metadata.status, 'QUARANTINED');
  } finally { await rm(root, { recursive: true, force: true }); }
});
