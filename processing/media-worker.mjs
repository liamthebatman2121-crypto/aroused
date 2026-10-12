const safeErrorCode = error => typeof error?.code === 'string' && /^[A-Z0-9_.-]{1,48}$/i.test(error.code) ? error.code : 'PROCESSING_FAILED';
const dateAt = milliseconds => new Date(milliseconds).toISOString();

function updatePipelineFailure(db, mediaId, updatedAt) {
  db.prepare("UPDATE media_pipeline SET status=CASE WHEN status='REJECTED' THEN 'REJECTED' ELSE 'QUARANTINED' END,processing_status='FAILED',updated_at=? WHERE media_id=?").run(updatedAt, mediaId);
}

/** Atomically ensure a media item has at most one active/blocked processing job. */
export function enqueueMediaJob(db, mediaId, { now = Date.now(), status = 'blocked', errorCode = 'PROVIDERS_NOT_CONFIGURED' } = {}) {
  if (!Number.isSafeInteger(Number(mediaId)) || Number(mediaId) <= 0) throw new TypeError('A valid mediaId is required.');
  if (!['blocked', 'queued'].includes(status)) throw new TypeError('New jobs may only be blocked or queued.');
  const timestamp = dateAt(now);
  const inserted = db.prepare(`INSERT INTO processing_jobs(media_id,status,attempts,available_at,created_at,updated_at,error_code)
    SELECT ?,?,0,?,?,?,? WHERE NOT EXISTS (
      SELECT 1 FROM processing_jobs WHERE media_id=? AND status IN ('blocked','queued','retry','processing','review_required')
    )`).run(Number(mediaId), status, now, timestamp, timestamp, errorCode, Number(mediaId));
  const didInsert = Number(inserted.changes) === 1;
  return { inserted: didInsert, jobId: didInsert ? Number(inserted.lastInsertRowid) : null };
}

/** SQLite queue lease. A task stays private/quarantined unless a real processor verifies its output. */
export function claimMediaJob(db, { now = Date.now(), leaseMs = 10 * 60_000, maxAttempts = 5 } = {}) {
  const timestamp = dateAt(now), expiredBefore = dateAt(now - leaseMs);
  db.exec('BEGIN IMMEDIATE');
  try {
    const expired = db.prepare("SELECT id,media_id,attempts FROM processing_jobs WHERE status='processing' AND updated_at<=?").all(expiredBefore);
    for (const job of expired) {
      if (Number(job.attempts) >= maxAttempts) {
        db.prepare("UPDATE processing_jobs SET status='failed',updated_at=?,error_code='LEASE_EXPIRED' WHERE id=? AND status='processing'").run(timestamp, job.id);
        updatePipelineFailure(db, job.media_id, timestamp);
      } else {
        db.prepare("UPDATE processing_jobs SET status='retry',available_at=?,updated_at=?,error_code='LEASE_EXPIRED' WHERE id=? AND status='processing'").run(now, timestamp, job.id);
      }
    }
    const job = db.prepare("SELECT id,media_id,attempts FROM processing_jobs WHERE status IN ('queued','retry') AND available_at<=? ORDER BY available_at,id LIMIT 1").get(now);
    if (!job) { db.exec('COMMIT'); return null; }
    db.prepare("UPDATE processing_jobs SET status='processing',attempts=attempts+1,updated_at=?,error_code=NULL WHERE id=? AND status IN ('queued','retry')").run(timestamp, job.id);
    db.exec('COMMIT');
    return { id: Number(job.id), mediaId: Number(job.media_id), attempt: Number(job.attempts) + 1, idempotencyKey: `media:${job.media_id}:job:${job.id}` };
  } catch (error) {
    try { db.exec('ROLLBACK'); } catch {}
    throw error;
  }
}

function finishJob(db, job, result, now) {
  const timestamp = dateAt(now);
  if (result?.reviewRequired === true) {
    db.exec('BEGIN IMMEDIATE');
    try {
      const updated = db.prepare("UPDATE processing_jobs SET status='review_required',updated_at=?,error_code=? WHERE id=? AND media_id=? AND status='processing'").run(timestamp, result.errorCode || 'HUMAN_REVIEW_REQUIRED', job.id, job.mediaId);
      if (Number(updated.changes) !== 1) throw Object.assign(new Error('Job lease is no longer current.'), { code: 'JOB_LEASE_LOST' });
      const pipeline = db.prepare("UPDATE media_pipeline SET status='QUARANTINED',moderation_status='PENDING',updated_at=? WHERE media_id=?").run(timestamp, job.mediaId);
      if (Number(pipeline.changes) !== 1) throw Object.assign(new Error('Media safety pipeline row is missing.'), { code: 'PIPELINE_STATE_MISSING' });
      db.exec('COMMIT');
      return { status: 'review_required', jobId: job.id, mediaId: job.mediaId };
    } catch (error) { try { db.exec('ROLLBACK'); } catch {} throw error; }
  }
  if (result?.artifactsVerified !== true) throw Object.assign(new Error('Processor output was not verified.'), { code: 'OUTPUT_NOT_VERIFIED' });
  db.exec('BEGIN IMMEDIATE');
  try {
    const updated = db.prepare("UPDATE processing_jobs SET status='completed',updated_at=?,error_code=NULL WHERE id=? AND media_id=? AND status='processing'").run(timestamp, job.id, job.mediaId);
    if (Number(updated.changes) !== 1) throw Object.assign(new Error('Job lease is no longer current.'), { code: 'JOB_LEASE_LOST' });
    // This records only the processing stage. It deliberately does not mark the
    // media READY or clear quarantine, malware, safety, or moderation gates.
    const pipeline = db.prepare("UPDATE media_pipeline SET processing_status='READY',updated_at=? WHERE media_id=?").run(timestamp, job.mediaId);
    if (Number(pipeline.changes) !== 1) throw Object.assign(new Error('Media safety pipeline row is missing.'), { code: 'PIPELINE_STATE_MISSING' });
    db.exec('COMMIT');
    return { status: 'completed', jobId: job.id, mediaId: job.mediaId };
  } catch (error) {
    try { db.exec('ROLLBACK'); } catch {}
    throw error;
  }
}

function failJob(db, job, error, { now, maxAttempts, retryBaseMs, retryMaxMs }) {
  const timestamp = dateAt(now), code = safeErrorCode(error);
  const retryable = error?.retryable === true && job.attempt < maxAttempts;
  db.exec('BEGIN IMMEDIATE');
  try {
    if (retryable) {
      const delay = Math.min(retryMaxMs, retryBaseMs * (2 ** Math.max(0, job.attempt - 1)));
      db.prepare("UPDATE processing_jobs SET status='retry',available_at=?,updated_at=?,error_code=? WHERE id=? AND media_id=? AND status='processing'").run(now + delay, timestamp, code, job.id, job.mediaId);
      db.prepare("UPDATE media_pipeline SET status=CASE WHEN status='REJECTED' THEN 'REJECTED' ELSE 'QUARANTINED' END,updated_at=? WHERE media_id=?").run(timestamp, job.mediaId);
      db.exec('COMMIT');
      return { status: 'retry-scheduled', jobId: job.id, mediaId: job.mediaId, retryAt: now + delay, errorCode: code };
    }
    const updated = db.prepare("UPDATE processing_jobs SET status='failed',updated_at=?,error_code=? WHERE id=? AND media_id=? AND status='processing'").run(timestamp, code, job.id, job.mediaId);
    if (Number(updated.changes) !== 1) throw Object.assign(new Error('Job lease is no longer current.'), { code: 'JOB_LEASE_LOST' });
    updatePipelineFailure(db, job.mediaId, timestamp);
    db.exec('COMMIT');
    return { status: 'failed', jobId: job.id, mediaId: job.mediaId, errorCode: code };
  } catch (failure) {
    try { db.exec('ROLLBACK'); } catch {}
    throw failure;
  }
}

export function createMediaWorker({ db, processor, now = Date.now, leaseMs = 10 * 60_000, maxAttempts = 5, retryBaseMs = 5_000, retryMaxMs = 15 * 60_000 } = {}) {
  if (!db) throw new TypeError('A SQLite database handle is required.');
  return {
    async runOnce() {
      if (typeof processor !== 'function') return { status: 'NOT_CONFIGURED', claimed: false };
      const claimedAt = now();
      const job = claimMediaJob(db, { now: claimedAt, leaseMs, maxAttempts });
      if (!job) return { status: 'idle', claimed: false };
      try {
        const output = await processor({ ...job });
        if (output?.retryable === true) throw Object.assign(new Error('Processing dependencies are unavailable.'), { code: output.errorCode || 'PROCESSING_UNAVAILABLE', retryable: true });
        return finishJob(db, job, output, now());
      } catch (error) {
        return failJob(db, job, error, { now: now(), maxAttempts, retryBaseMs, retryMaxMs });
      }
    },
  };
}
