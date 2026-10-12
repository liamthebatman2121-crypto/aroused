export const SCAN_OUTCOMES = Object.freeze(['clear', 'match', 'review_required', 'unavailable']);
export const SCAN_CHECKS = Object.freeze({
  image: ['known_csam_image', 'malware', 'prohibited_content_review', 'safe_decode'],
  video: ['known_csam_video', 'malware', 'prohibited_content_review', 'safe_decode'],
});

const safeIdentifier = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/;
const safeAuditKeys = new Set(['algorithm', 'modelVersion', 'signatureVersion', 'confidenceBand', 'matchedSegmentCount', 'latencyMs']);

export class ScannerProvider {
  constructor({ providerId, checks }) {
    if (typeof providerId !== 'string' || !safeIdentifier.test(providerId)) throw new TypeError('A safe scanner providerId is required.');
    if (!Array.isArray(checks) || !checks.length || checks.some(check => !Object.values(SCAN_CHECKS).flat().includes(check))) throw new TypeError('Supported scanner checks are required.');
    this.providerId = providerId;
    this.checks = Object.freeze([...new Set(checks)]);
  }

  async scan() { throw new Error('ScannerProvider.scan must be implemented by a configured provider.'); }
}

/** Explicitly unavailable adapter. It never opens or transmits a media stream. */
export class UnavailableScannerProvider extends ScannerProvider {
  constructor({ providerId, checks }) { super({ providerId, checks }); }
  async scan() { return { outcome: 'unavailable', providerId: this.providerId, auditMetadata: {} }; }
}

export function validateScannerResponse(value, expectedProviderId) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new TypeError('Invalid scanner response.');
  const allowed = new Set(['outcome', 'providerId', 'providerReference', 'auditMetadata']);
  if (Object.keys(value).some(key => !allowed.has(key))) throw new TypeError('Scanner response contains unsupported fields.');
  if (!SCAN_OUTCOMES.includes(value.outcome) || value.providerId !== expectedProviderId) throw new TypeError('Scanner response identity or outcome is invalid.');
  if (value.providerReference !== undefined && (typeof value.providerReference !== 'string' || !safeIdentifier.test(value.providerReference))) throw new TypeError('Scanner provider reference is invalid.');
  const source = value.auditMetadata === undefined ? {} : value.auditMetadata;
  if (!source || typeof source !== 'object' || Array.isArray(source)) throw new TypeError('Scanner audit metadata is invalid.');
  const auditMetadata = {};
  for (const [key, item] of Object.entries(source)) {
    if (!safeAuditKeys.has(key)) throw new TypeError('Scanner audit metadata contains an unsupported field.');
    if (typeof item === 'string') {
      if (item.length > 80 || /[\r\n\0]/.test(item)) throw new TypeError('Scanner audit metadata value is invalid.');
      auditMetadata[key] = item;
    } else if (typeof item === 'number' && Number.isFinite(item) && item >= 0 && item <= 1_000_000) auditMetadata[key] = item;
    else throw new TypeError('Scanner audit metadata value is invalid.');
  }
  return { outcome: value.outcome, providerId: value.providerId, providerReference: value.providerReference || null, auditMetadata };
}

function codeForError(error) {
  if (error?.code === 'SCANNER_TIMEOUT') return 'SCANNER_TIMEOUT';
  if (['ECONNRESET', 'ETIMEDOUT', 'EAI_AGAIN', 'ENOTFOUND', 'ABORT_ERR'].includes(error?.code)) return error.code;
  return 'SCANNER_PROVIDER_ERROR';
}

function outcomeForPipeline(check, outcome) {
  if (check === 'malware') return outcome === 'clear' ? 'CLEAN' : outcome === 'unavailable' ? 'UNAVAILABLE' : 'BLOCKED';
  if (check === 'safe_decode') return outcome === 'clear' ? 'READY' : outcome === 'unavailable' ? 'UNAVAILABLE' : 'FAILED';
  return outcome === 'clear' ? 'CLEAR' : outcome === 'unavailable' ? 'UNAVAILABLE' : 'REVIEW_REQUIRED';
}

function moderationCaseFor(check, outcome) {
  if (!['match', 'review_required'].includes(outcome)) return null;
  if (check.startsWith('known_csam_')) return { category: 'suspected_minor', priority: 'critical', restricted: 1, detailCode: outcome === 'match' ? 'KNOWN_CSAI_MATCH' : 'KNOWN_CSAI_REVIEW' };
  if (check === 'prohibited_content_review') return { category: 'non_consensual', priority: 'high', restricted: 1, detailCode: outcome === 'match' ? 'ABUSE_CONTENT_MATCH' : 'ABUSE_CONTENT_REVIEW' };
  if (check === 'malware') return { category: 'other', priority: 'high', restricted: 1, detailCode: 'MALWARE_REVIEW_REQUIRED' };
  return { category: 'other', priority: 'high', restricted: 1, detailCode: 'MEDIA_DECODE_REVIEW_REQUIRED' };
}

/**
 * Execute the required media checks and persist only normalized outcomes and
 * allow-listed metadata. `openMedia` must return a new private stream per call.
 * This function does not grant publication or transmit media unless a caller's
 * explicitly configured provider chooses to consume that stream.
 */
export async function runMediaSafetyChecks({ db, mediaId, jobId = 'manual', mediaType, providers = [], openMedia, now = () => new Date(), timeoutMs = 30_000 }) {
  if (!db || !Number.isSafeInteger(Number(mediaId)) || Number(mediaId) <= 0) throw new TypeError('A database and valid mediaId are required.');
  const checks = SCAN_CHECKS[mediaType];
  if (!checks) throw new TypeError('Media type must be image or video.');
  if (typeof openMedia !== 'function') throw new TypeError('openMedia must provide a private stream factory.');
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 5 * 60_000) throw new TypeError('Scanner timeout must be between 1 ms and 5 minutes.');
  const pipeline = db.prepare('SELECT status FROM media_pipeline WHERE media_id=?').get(Number(mediaId));
  if (!pipeline) throw new Error('Media safety-pipeline state is missing.');
  if (!['SCAN_PENDING', 'QUARANTINED'].includes(pipeline.status)) throw new Error('Media is not in a scannable quarantine state.');

  const results = [];
  for (const checkType of checks) {
    const matches = providers.filter(candidate => candidate instanceof ScannerProvider && candidate.checks.includes(checkType));
    const provider = matches.length === 1 ? matches[0] : null;
    const startedAt = now().toISOString();
    let response;
    let errorCode = null;
    if (!provider) {
      response = { outcome: 'unavailable', providerId: 'unconfigured', providerReference: null, auditMetadata: {} };
      errorCode = matches.length > 1 ? 'SCANNER_CONFIGURATION_AMBIGUOUS' : 'SCANNER_NOT_CONFIGURED';
    } else {
      const controller = new AbortController();
      let timer;
      let fullyRead = false;
      try {
        const guardedOpenMedia = async () => {
          const object = await openMedia();
          if (!object?.stream || typeof object.stream.once !== 'function') throw new TypeError('Private media stream is invalid.');
          object.stream.once('end', () => { fullyRead = true; });
          return object;
        };
        response = await Promise.race([
          Promise.resolve().then(() => provider.scan({ checkType, mediaType, openMedia: guardedOpenMedia, signal: controller.signal, idempotencyKey: `media-scan:${mediaId}:${jobId}:${checkType}` })),
          new Promise((_, reject) => { timer = setTimeout(() => { controller.abort(); reject(Object.assign(new Error('Scanner timed out.'), { code: 'SCANNER_TIMEOUT' })); }, timeoutMs); }),
        ]);
        response = validateScannerResponse(response, provider.providerId);
        if (response.outcome !== 'unavailable' && !fullyRead) {
          response = { outcome: 'unavailable', providerId: provider.providerId, providerReference: null, auditMetadata: {} };
          errorCode = 'SCANNER_DID_NOT_CONSUME_MEDIA';
        }
      } catch (error) {
        response = { outcome: 'unavailable', providerId: provider.providerId, providerReference: null, auditMetadata: {} };
        errorCode = error?.code === 'SCANNER_TIMEOUT' ? 'SCANNER_TIMEOUT' : error instanceof TypeError ? 'INVALID_SCANNER_RESPONSE' : codeForError(error);
      } finally { clearTimeout(timer); }
    }
    const completedAt = now().toISOString();
    if (response.outcome === 'unavailable' && !errorCode) errorCode = 'SCANNER_UNAVAILABLE';
    results.push({ checkType, ...response, errorCode, startedAt, completedAt });
  }

  const at = now().toISOString();
  db.exec('BEGIN IMMEDIATE');
  try {
    for (const result of results) {
      db.prepare(`INSERT INTO media_scan_results(media_id,provider,result,detail_code,created_at,check_type,provider_reference,started_at,completed_at,audit_metadata_json)
        VALUES(?,?,?,?,?,?,?,?,?,?)`).run(Number(mediaId), result.providerId, result.outcome, result.errorCode, result.completedAt, result.checkType, result.providerReference, result.startedAt, result.completedAt, JSON.stringify(result.auditMetadata));
      const suspiciousCase = moderationCaseFor(result.checkType, result.outcome);
      if (suspiciousCase) {
        const media = db.prepare('SELECT m.album_id,a.story_id FROM album_media m JOIN albums a ON a.id=m.album_id WHERE m.id=?').get(Number(mediaId));
        const existing = db.prepare("SELECT id FROM moderation_cases WHERE media_id=? AND category=? AND status IN ('open','reviewing') LIMIT 1").get(Number(mediaId), suspiciousCase.category);
        if (!existing) db.prepare(`INSERT INTO moderation_cases(album_id,media_id,category,priority,status,restricted,created_at,updated_at)
          VALUES(?,?,?,?,'open',1,?,?)`).run(media?.album_id || null, Number(mediaId), suspiciousCase.category, suspiciousCase.priority, at, at);
        if (media) {
          db.prepare("UPDATE albums SET status='processing',updated_at=? WHERE id=?").run(at, media.album_id);
          db.prepare("UPDATE stories SET status='draft' WHERE id=?").run(media.story_id);
        }
        db.prepare('INSERT INTO security_events(user_id,event_type,severity,detail_code,created_at) VALUES(NULL,?,?,?,?)').run('automated_media_scan_escalation', suspiciousCase.priority === 'critical' ? 'critical' : 'high', suspiciousCase.detailCode, at);
      }
    }
    for (const result of results) {
      const column = result.checkType === 'malware' ? 'malware_status' : result.checkType === 'safe_decode' ? 'processing_status' : result.checkType === 'prohibited_content_review' ? 'safety_status' : 'known_content_status';
      db.prepare(`UPDATE media_pipeline SET ${column}=?,status='QUARANTINED',updated_at=? WHERE media_id=?`).run(outcomeForPipeline(result.checkType, result.outcome), at, Number(mediaId));
    }
    // Processing is a separate gate from scan outcomes. Always remain quarantined
    // until the full consent/age/rights/human moderation/publication chain passes.
    db.prepare("UPDATE media_pipeline SET status='QUARANTINED',moderation_status='PENDING',updated_at=? WHERE media_id=?").run(at, Number(mediaId));
    db.exec('COMMIT');
  } catch (error) { try { db.exec('ROLLBACK'); } catch {} throw error; }

  const unavailable = results.some(result => result.outcome === 'unavailable');
  const reviewRequired = results.some(result => result.outcome === 'match' || result.outcome === 'review_required');
  return {
    status: unavailable ? 'unavailable' : reviewRequired ? 'review_required' : 'clear',
    results,
    retryable: unavailable,
    reviewRequired,
    artifactsVerified: !unavailable && !reviewRequired && results.every(result => result.outcome === 'clear'),
    errorCode: unavailable ? 'SCANNER_UNAVAILABLE' : null,
    idempotencyKey: `media-scan:${mediaId}:${jobId}`,
  };
}
