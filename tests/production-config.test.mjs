import test from 'node:test';
import assert from 'node:assert/strict';
import { validateProductionEnvironment } from '../config/production-env.mjs';

const valid = {
  NODE_ENV: 'production', AROUSED_BIND_HOST: '127.0.0.1', AROUSED_API_PORT: '8767',
  AROUSED_DATA_DIR: 'C:\\app-data', AROUSED_PUBLIC_BASE_URL: 'https://aroused.example',
  AROUSED_ALLOWED_ORIGINS: 'https://aroused.example', AROUSED_EMAIL_CODE_SECRET: 'a'.repeat(64),
  RESEND_API_KEY: 'redacted', AROUSED_FROM_EMAIL: 'noreply@example.test',
  AROUSED_STORAGE_DRIVER: 's3', AROUSED_OBJECT_STORAGE_BUCKET: 'private-media', AROUSED_OBJECT_STORAGE_REGION: 'us-east-1',
  AROUSED_OBJECT_STORAGE_USE_INSTANCE_ROLE: 'true',
};

test('production config validates required security, persistent SQLite, email, and private S3 settings', () => {
  assert.deepEqual(validateProductionEnvironment(valid), []);
  const missing = validateProductionEnvironment({ NODE_ENV: 'production' });
  assert.ok(missing.some(item => item.includes('AROUSED_DATA_DIR')));
  assert.ok(missing.some(item => item.includes('AROUSED_STORAGE_DRIVER')));
  assert.ok(missing.some(item => item.includes('RESEND_API_KEY')));
});

test('production config rejects HTTP/wildcard origins, weak pepper, mixed S3 credentials, and old Node', () => {
  const env = { ...valid, AROUSED_ALLOWED_ORIGINS: 'https://aroused.example,*', AROUSED_PUBLIC_BASE_URL: 'http://aroused.example', AROUSED_EMAIL_CODE_SECRET: 'short', AROUSED_OBJECT_STORAGE_ACCESS_KEY_ID: 'key' };
  const errors = validateProductionEnvironment(env, '20.20.0');
  assert.ok(errors.some(item => item.includes('HTTPS')));
  assert.ok(errors.some(item => item.includes('64 characters')));
  assert.ok(errors.some(item => item.includes('configured together')));
  assert.ok(errors.some(item => item.includes('22.13')));
  assert.ok(errors.every(item => !item.includes('redacted') && !item.includes('key')));
});

test('non-production local defaults are not constrained by production deployment checks', () => {
  assert.deepEqual(validateProductionEnvironment({ NODE_ENV: 'development' }), []);
});
