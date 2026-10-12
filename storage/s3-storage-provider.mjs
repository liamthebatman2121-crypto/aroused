import { Readable } from 'node:stream';
import {
  S3Client, PutObjectCommand, HeadObjectCommand, GetObjectCommand, DeleteObjectCommand,
  HeadBucketCommand, GetPublicAccessBlockCommand, GetBucketOwnershipControlsCommand,
} from '@aws-sdk/client-s3';
import { StorageProvider } from './storage-provider.mjs';

const toNodeStream = body => {
  if (body && typeof body.pipe === 'function') return body;
  if (body && typeof body.transformToWebStream === 'function') return Readable.fromWeb(body.transformToWebStream());
  if (body && typeof body[Symbol.asyncIterator] === 'function') return Readable.from(body);
  throw new Error('Object storage returned an unreadable object body.');
};

const normalizedMetadata = metadata => Object.fromEntries(Object.entries(metadata || {})
  .filter(([key, value]) => /^[a-z0-9-]{1,64}$/i.test(key) && value !== undefined && value !== null)
  .map(([key, value]) => [key.toLowerCase(), String(value).slice(0, 1024)]));

export class S3StorageProvider extends StorageProvider {
  constructor({ bucket, region, endpoint, accessKeyId, secretAccessKey, forcePathStyle = false, client, commands = {} }) {
    super();
    if (!bucket || !region) throw new TypeError('S3 bucket and region are required.');
    if (Boolean(accessKeyId) !== Boolean(secretAccessKey)) throw new TypeError('S3 access key ID and secret key must be supplied together.');
    if (endpoint && !accessKeyId) throw new TypeError('S3-compatible endpoints require explicit access credentials.');
    this.bucket = bucket;
    this.client = client || new S3Client({
      region, endpoint: endpoint || undefined, forcePathStyle,
      ...(accessKeyId ? { credentials: { accessKeyId, secretAccessKey } } : {}),
    });
    this.commands = {
      PutObjectCommand, HeadObjectCommand, GetObjectCommand, DeleteObjectCommand,
      HeadBucketCommand, GetPublicAccessBlockCommand, GetBucketOwnershipControlsCommand,
      ...commands,
    };
  }

  static fromEnvironment(env = process.env) {
    return new S3StorageProvider({
      bucket: String(env.AROUSED_OBJECT_STORAGE_BUCKET || '').trim(),
      region: String(env.AROUSED_OBJECT_STORAGE_REGION || '').trim(),
      endpoint: String(env.AROUSED_OBJECT_STORAGE_ENDPOINT || '').trim() || undefined,
      accessKeyId: String(env.AROUSED_OBJECT_STORAGE_ACCESS_KEY_ID || '').trim() || undefined,
      secretAccessKey: String(env.AROUSED_OBJECT_STORAGE_SECRET_ACCESS_KEY || '') || undefined,
      forcePathStyle: env.AROUSED_OBJECT_STORAGE_FORCE_PATH_STYLE === 'true',
    });
  }

  #key(key) {
    if (typeof key !== 'string' || !key || key.startsWith('/') || key.includes('\\') || key.includes('\0') || key.split('/').some(part => !part || part === '.' || part === '..')) {
      throw new TypeError('Invalid storage key.');
    }
    return key;
  }

  async verifyPrivateDestination() {
    await this.client.send(new this.commands.HeadBucketCommand({ Bucket: this.bucket }));
    const access = await this.client.send(new this.commands.GetPublicAccessBlockCommand({ Bucket: this.bucket }));
    const block = access.PublicAccessBlockConfiguration;
    if (!block || !block.BlockPublicAcls || !block.IgnorePublicAcls || !block.BlockPublicPolicy || !block.RestrictPublicBuckets) {
      throw new Error('Object bucket must have all four public-access-block settings enabled.');
    }
    const ownership = await this.client.send(new this.commands.GetBucketOwnershipControlsCommand({ Bucket: this.bucket }));
    if (!ownership.OwnershipControls?.Rules?.some(rule => rule.ObjectOwnership === 'BucketOwnerEnforced')) {
      throw new Error('Object bucket must enforce bucket-owner ownership with ACLs disabled.');
    }
    return { verified: true, private: true, driver: 's3', productionSuitable: true };
  }

  async healthCheck() {
    try { await this.verifyPrivateDestination(); return { available: true, driver: 's3' }; }
    catch { return { available: false, driver: 's3' }; }
  }

  async upload(key, body, metadata = {}) {
    key = this.#key(key);
    await this.client.send(new this.commands.PutObjectCommand({
      Bucket: this.bucket, Key: key, Body: body,
      ContentType: metadata.contentType || 'application/octet-stream',
      Metadata: normalizedMetadata(metadata.metadata),
      ServerSideEncryption: 'AES256',
      IfNoneMatch: '*',
    }));
    return this.getMetadata(key, metadata);
  }

  async getMetadata(key, metadata = {}) {
    key = this.#key(key);
    const result = await this.client.send(new this.commands.HeadObjectCommand({ Bucket: this.bucket, Key: key }));
    return {
      key, size: Number(result.ContentLength || 0),
      lastModified: result.LastModified?.toISOString?.() || null,
      contentType: result.ContentType || metadata.contentType || 'application/octet-stream',
      metadata: result.Metadata || metadata.metadata || {},
      etag: result.ETag || null, serverSideEncryption: result.ServerSideEncryption || null,
    };
  }

  async openRead(key, { start, end, metadata } = {}) {
    key = this.#key(key);
    const info = await this.getMetadata(key, metadata);
    const range = start === undefined ? undefined : `bytes=${start}-${end === undefined ? '' : end}`;
    const result = await this.client.send(new this.commands.GetObjectCommand({ Bucket: this.bucket, Key: key, ...(range ? { Range: range } : {}) }));
    return { ...info, stream: toNodeStream(result.Body) };
  }

  async delete(key) {
    key = this.#key(key);
    await this.client.send(new this.commands.DeleteObjectCommand({ Bucket: this.bucket, Key: key }));
    return true;
  }
}
