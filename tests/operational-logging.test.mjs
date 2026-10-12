import test from 'node:test';
import assert from 'node:assert/strict';
import { operationalLog, safeErrorCode } from '../observability/logger.mjs';

test('operational logs serialize only allow-listed, bounded fields', () => {
  const lines = [];
  const record = operationalLog('error', 'api_request_failed', {
    requestId: 'abc123', method: 'POST', route: 'api', status: 500,
    durationMs: 17, errorCode: 'EACCES',
    password: 'must-not-appear', url: '/auth?token=private', email: 'private@example.test',
  }, line => lines.push(line));
  assert.equal(lines.length, 1);
  assert.deepEqual(JSON.parse(lines[0]), record);
  assert.equal(record.password, undefined);
  assert.equal(record.url, undefined);
  assert.equal(record.email, undefined);
  assert.equal(lines[0].includes('must-not-appear'), false);
  assert.equal(lines[0].includes('private'), false);
});

test('error codes are normalized without leaking exception messages', () => {
  assert.equal(safeErrorCode(Object.assign(new Error('secret DSN'), { code: 'ECONNRESET' })), 'ECONNRESET');
  assert.equal(safeErrorCode(Object.assign(new Error('email=private@example.test'), { code: 'bad password' })), 'INTERNAL_ERROR');
  assert.equal(safeErrorCode(Object.assign(new Error('hidden'), { status: 404 })), 'HTTP_404');
});
