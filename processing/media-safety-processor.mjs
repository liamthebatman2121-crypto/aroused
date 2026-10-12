import { runMediaSafetyChecks } from './scanner-provider.mjs';

/** Adapter from the existing job worker to the provider-neutral safety pipeline. */
export function createMediaSafetyProcessor({ db, storage, providers = [], timeoutMs = 30_000, now = () => new Date() } = {}) {
  if (!db || !storage || typeof storage.openRead !== 'function') throw new TypeError('A database and private storage provider are required.');
  return async ({ id: jobId, mediaId }) => {
    const row = db.prepare(`SELECT m.storage_name,m.mime_type,p.status AS pipeline_status
      FROM album_media m JOIN media_pipeline p ON p.media_id=m.id WHERE m.id=?`).get(Number(mediaId));
    if (!row) throw Object.assign(new Error('Media record is missing.'), { code: 'MEDIA_RECORD_MISSING' });
    if (!['SCAN_PENDING', 'QUARANTINED'].includes(row.pipeline_status)) throw Object.assign(new Error('Media is not in a scannable quarantine state.'), { code: 'MEDIA_NOT_QUARANTINED' });
    const mediaType = String(row.mime_type).startsWith('image/') ? 'image' : String(row.mime_type).startsWith('video/') ? 'video' : null;
    if (!mediaType) throw Object.assign(new Error('Unsupported media type.'), { code: 'UNSUPPORTED_MEDIA_TYPE' });
    return runMediaSafetyChecks({
      db, mediaId: Number(mediaId), jobId: String(jobId), mediaType, providers, timeoutMs, now,
      openMedia: async () => {
        const object = await storage.openRead(row.storage_name, { metadata: { contentType: row.mime_type } });
        return { stream: object.stream, size: object.size, contentType: object.contentType };
      },
    });
  };
}
