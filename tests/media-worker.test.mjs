import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { createMediaWorker } from '../processing/media-worker.mjs';

function fixture() {
  const db = new DatabaseSync(':memory:');
  db.exec(`CREATE TABLE processing_jobs(id INTEGER PRIMARY KEY,media_id INTEGER,status TEXT,attempts INTEGER,available_at INTEGER,created_at TEXT,updated_at TEXT,error_code TEXT);
    CREATE TABLE media_pipeline(media_id INTEGER PRIMARY KEY,status TEXT,processing_status TEXT,malware_status TEXT,known_content_status TEXT,safety_status TEXT,moderation_status TEXT,updated_at TEXT);
    INSERT INTO processing_jobs VALUES(1,14,'blocked',0,1000,'2025-01-01T00:00:00.000Z','2025-01-01T00:00:00.000Z','PROVIDERS_NOT_CONFIGURED');
    INSERT INTO media_pipeline VALUES(14,'QUARANTINED','NOT_CONFIGURED','BLOCKED','NOT_CONFIGURED','NOT_CONFIGURED','PENDING','2025-01-01T00:00:00.000Z');
    UPDATE processing_jobs SET status='queued',error_code=NULL;`);
  return db;
}

test('unconfigured worker leaves blocked jobs and media gates untouched', async () => {
  const db = fixture();
  try {
    assert.deepEqual(await createMediaWorker({ db }).runOnce(), { status: 'NOT_CONFIGURED', claimed: false });
    assert.equal(db.prepare('SELECT status FROM processing_jobs WHERE id=1').get().status, 'queued');
    assert.equal(db.prepare('SELECT status FROM media_pipeline WHERE media_id=14').get().status, 'QUARANTINED');
  } finally { db.close(); }
});

test('transient failures get bounded backoff and success never bypasses safety gates', async () => {
  const db = fixture();
  let currentTime = 1000;
  let calls = 0;
  const worker = createMediaWorker({ db, now: () => currentTime, retryBaseMs: 100, retryMaxMs: 1000, processor: async ({ idempotencyKey }) => {
    calls++;
    assert.equal(idempotencyKey, 'media:14:job:1');
    if (calls === 1) throw Object.assign(new Error('private provider details'), { code: 'E_TRANSIENT', retryable: true });
    return { artifactsVerified: true };
  } });
  try {
    assert.equal((await worker.runOnce()).status, 'retry-scheduled');
    assert.equal(db.prepare('SELECT status FROM media_pipeline WHERE media_id=14').get().status, 'QUARANTINED');
    currentTime += 100;
    assert.equal((await worker.runOnce()).status, 'completed');
    const pipeline = db.prepare('SELECT * FROM media_pipeline WHERE media_id=14').get();
    assert.equal(pipeline.processing_status, 'READY');
    assert.equal(pipeline.status, 'QUARANTINED');
    assert.equal(pipeline.malware_status, 'BLOCKED');
    assert.equal(pipeline.safety_status, 'NOT_CONFIGURED');
    assert.equal(pipeline.moderation_status, 'PENDING');
    assert.equal(db.prepare('SELECT error_code FROM processing_jobs WHERE id=1').get().error_code, null);
  } finally { db.close(); }
});

test('terminal processor failures are sanitized and keep media quarantined', async () => {
  const db = fixture();
  const worker = createMediaWorker({ db, now: () => 2000, maxAttempts: 1, processor: async () => { throw new Error('secret endpoint and credentials'); } });
  try {
    assert.equal((await worker.runOnce()).status, 'failed');
    const job = db.prepare('SELECT status,error_code FROM processing_jobs WHERE id=1').get();
    assert.equal(job.status, 'failed');
    assert.equal(job.error_code, 'PROCESSING_FAILED');
    assert.equal(db.prepare('SELECT status,processing_status FROM media_pipeline WHERE media_id=14').get().status, 'QUARANTINED');
    assert.equal(db.prepare('SELECT processing_status FROM media_pipeline WHERE media_id=14').get().processing_status, 'FAILED');
  } finally { db.close(); }
});
