import { createReadStream } from 'node:fs';
import { constants as fsConstants } from 'node:fs';
import { access, mkdir, open, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { dirname, isAbsolute, relative, resolve, sep } from 'node:path';
import { pipeline } from 'node:stream/promises';
import { Readable } from 'node:stream';

export class StorageAccessDenied extends Error {
  constructor() {
    super('Storage access denied.');
    this.name = 'StorageAccessDenied';
    this.status = 403;
  }
}

export class StorageProvider {
  async upload() { throw new Error('StorageProvider.upload must be implemented.'); }
  async getMetadata() { throw new Error('StorageProvider.getMetadata must be implemented.'); }
  async openRead() { throw new Error('StorageProvider.openRead must be implemented.'); }
  async delete() { throw new Error('StorageProvider.delete must be implemented.'); }
  async verifyPrivateDestination() { throw new Error('StorageProvider.verifyPrivateDestination must be implemented.'); }
}

/** Development adapter. Keep this root private and outside the static web root. */
export class LocalFileStorageProvider extends StorageProvider {
  constructor(root) {
    super();
    if (!root) throw new TypeError('A private local storage root is required.');
    this.root = resolve(root);
  }

  async verifyPrivateDestination() {
    await mkdir(this.root, { recursive: true, mode: 0o700 });
    const info = await stat(this.root);
    if (!info.isDirectory()) throw new Error('Local storage root is not a directory.');
    return { verified: true, private: true, driver: 'local-filesystem', productionSuitable: false };
  }

  async healthCheck() {
    try { await mkdir(this.root, { recursive: true, mode: 0o700 }); await access(this.root, fsConstants.W_OK); return { available: true, driver: 'local-filesystem' }; }
    catch { return { available: false, driver: 'local-filesystem' }; }
  }

  #path(key) {
    if (typeof key !== 'string' || !key || key.includes('\0') || key.includes('\\') || key.startsWith('/')) {
      throw new TypeError('Invalid storage key.');
    }
    const target = resolve(this.root, key);
    const rel = relative(this.root, target);
    if (!rel || rel === '..' || rel.startsWith(`..${sep}`) || isAbsolute(rel)) throw new TypeError('Invalid storage key.');
    return target;
  }

  #metadataPath(key) { return `${this.#path(key)}.meta.json`; }

  async upload(key, body, metadata = {}) {
    const target = this.#path(key);
    await mkdir(dirname(target), { recursive: true, mode: 0o700 });
    const source = Buffer.isBuffer(body) || body instanceof Uint8Array ? Readable.from([body]) : body;
    if (!source || typeof source.pipe !== 'function') throw new TypeError('Upload body must be bytes or a readable stream.');
    let handle;
    try {
      handle = await open(target, 'wx', 0o600);
      await pipeline(source, handle.createWriteStream());
      await writeFile(this.#metadataPath(key), JSON.stringify({ contentType: metadata.contentType || 'application/octet-stream', metadata: metadata.metadata || {} }), { flag: 'wx', mode: 0o600 });
    } catch (error) {
      if (handle) await rm(target, { force: true }).catch(() => {});
      throw error;
    }
    return this.getMetadata(key, metadata);
  }

  async getMetadata(key, metadata = {}) {
    const info = await stat(this.#path(key));
    if (!info.isFile()) throw Object.assign(new Error('Stored object is not a file.'), { code: 'ENOENT' });
    let stored = {};
    try { stored = JSON.parse(await readFile(this.#metadataPath(key), 'utf8')); } catch (error) { if (error.code !== 'ENOENT') throw error; }
    return { key, size: info.size, lastModified: info.mtime.toISOString(), contentType: stored.contentType || metadata.contentType || 'application/octet-stream', metadata: stored.metadata || metadata.metadata || {} };
  }

  async openRead(key, { start, end, metadata } = {}) {
    const object = await this.getMetadata(key, metadata);
    const range = start === undefined ? {} : { start, end };
    return { ...object, stream: createReadStream(this.#path(key), range) };
  }

  async delete(key) {
    await Promise.all([rm(this.#path(key), { force: true }), rm(this.#metadataPath(key), { force: true })]);
    return true;
  }
}

/** Enforces authorization before the provider is asked for object bytes. */
export class AuthorizedStorage {
  constructor(provider) {
    if (!provider || typeof provider.openRead !== 'function') throw new TypeError('A storage provider is required.');
    this.provider = provider;
  }

  async openRead(key, authorize, options = {}) {
    if (typeof authorize !== 'function' || !(await authorize())) throw new StorageAccessDenied();
    return this.provider.openRead(key, options);
  }
}

export async function createStorageProvider({ env = process.env, localRoot } = {}) {
  const driver = String(env.AROUSED_STORAGE_DRIVER || '').trim().toLowerCase();
  if (driver === 's3') {
    const { S3StorageProvider } = await import('./s3-storage-provider.mjs');
    return S3StorageProvider.fromEnvironment(env);
  }
  if (driver && driver !== 'local') throw new Error('AROUSED_STORAGE_DRIVER must be local or s3.');
  if (env.NODE_ENV === 'production') throw new Error('Production requires AROUSED_STORAGE_DRIVER=s3; local disk storage is development-only.');
  return new LocalFileStorageProvider(localRoot);
}
