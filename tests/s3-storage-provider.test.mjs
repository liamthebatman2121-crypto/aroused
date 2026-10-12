import test from 'node:test';
import assert from 'node:assert/strict';
import { Readable } from 'node:stream';
import { S3StorageProvider } from '../storage/s3-storage-provider.mjs';

class Command { constructor(input) { this.input = input; } }
const commands = Object.fromEntries([
  'PutObjectCommand', 'HeadObjectCommand', 'GetObjectCommand', 'DeleteObjectCommand',
  'HeadBucketCommand', 'GetPublicAccessBlockCommand', 'GetBucketOwnershipControlsCommand',
].map(name => [name, Command]));

test('S3 adapter verifies private bucket controls and writes private immutable encrypted objects', async () => {
  const sent = [];
  const bytes = Buffer.from('private media');
  const client = { async send(command) {
    sent.push(command.input);
    if (sent.length === 2) return { PublicAccessBlockConfiguration: { BlockPublicAcls: true, IgnorePublicAcls: true, BlockPublicPolicy: true, RestrictPublicBuckets: true } };
    if (sent.length === 3) return { OwnershipControls: { Rules: [{ ObjectOwnership: 'BucketOwnerEnforced' }] } };
    if (command.input.Key && command.input.Range) return { Body: Readable.from([bytes.subarray(0, 7)]) };
    if (command.input.Key && command.input.ContentType) return {};
    if (command.input.Key) return { ContentLength: bytes.length, ContentType: 'image/jpeg', Metadata: { mediaid: '9' }, ETag: '"etag"', ServerSideEncryption: 'AES256' };
    return {};
  } };
  const provider = new S3StorageProvider({ bucket: 'private-test', region: 'us-east-1', client, commands });
  assert.deepEqual(await provider.verifyPrivateDestination(), { verified: true, private: true, driver: 's3', productionSuitable: true });
  const metadata = await provider.upload('media/9.jpg', bytes, { contentType: 'image/jpeg', metadata: { mediaId: 9 } });
  const put = sent.find(input => input.ContentType === 'image/jpeg');
  assert.equal(put.ACL, undefined);
  assert.equal(put.ServerSideEncryption, 'AES256');
  assert.equal(put.IfNoneMatch, '*');
  assert.deepEqual(put.Metadata, { mediaid: '9' });
  assert.equal(metadata.size, bytes.length);
  assert.equal(metadata.serverSideEncryption, 'AES256');
  const read = await provider.openRead('media/9.jpg', { start: 0, end: 6 });
  assert.equal(sent.at(-1).Range, 'bytes=0-6');
  const chunks = [];
  for await (const chunk of read.stream) chunks.push(chunk);
  assert.equal(Buffer.concat(chunks).toString(), 'private');
  await assert.rejects(provider.getMetadata('../public.jpg'));
});

test('S3 adapter refuses buckets without all public access blocks and enforced ownership', async () => {
  const client = { async send(command) {
    if (command.input.Bucket && command.input.Key) return {};
    if ('Bucket' in command.input) return { PublicAccessBlockConfiguration: { BlockPublicAcls: true } };
    return {};
  } };
  const provider = new S3StorageProvider({ bucket: 'not-private', region: 'us-east-1', client, commands });
  await assert.rejects(provider.verifyPrivateDestination(), /all four public-access-block settings/);
});

test('production storage factory rejects local disk and malformed S3 credentials', async () => {
  const { createStorageProvider } = await import('../storage/storage-provider.mjs');
  await assert.rejects(createStorageProvider({ env: { NODE_ENV: 'production' }, localRoot: 'uploads' }), /requires AROUSED_STORAGE_DRIVER=s3/);
  await assert.rejects(createStorageProvider({ env: { NODE_ENV: 'production', AROUSED_STORAGE_DRIVER: 's3', AROUSED_OBJECT_STORAGE_BUCKET: 'b', AROUSED_OBJECT_STORAGE_REGION: 'us-east-1', AROUSED_OBJECT_STORAGE_ACCESS_KEY_ID: 'only-half' }, localRoot: 'uploads' }), /must be supplied together/);
});
