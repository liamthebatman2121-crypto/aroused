import { isAbsolute } from 'node:path';

const nonEmpty = value => typeof value === 'string' && value.trim().length > 0;
const secretPair = (env, first, second, errors) => {
  const hasFirst = nonEmpty(env[first]);
  const hasSecond = nonEmpty(env[second]);
  if (hasFirst !== hasSecond) errors.push(`${first} and ${second} must be configured together.`);
  return hasFirst && hasSecond;
};

export function validateProductionEnvironment(env = process.env, nodeVersion = process.versions.node) {
  if (env.NODE_ENV !== 'production') return [];
  const errors = [];
  const version = String(nodeVersion).match(/^(\d+)\.(\d+)\.(\d+)/);
  if (!version || Number(version[1]) < 22 || (Number(version[1]) === 22 && Number(version[2]) < 13)) {
    errors.push('Node.js 22.13 or newer is required.');
  }
  if (!nonEmpty(env.AROUSED_BIND_HOST)) errors.push('AROUSED_BIND_HOST must be set explicitly.');
  const port = Number(env.AROUSED_API_PORT);
  if (!Number.isInteger(port) || port < 1 || port > 65535) errors.push('AROUSED_API_PORT must be an integer between 1 and 65535.');
  if (!nonEmpty(env.AROUSED_DATA_DIR) || !isAbsolute(env.AROUSED_DATA_DIR)) errors.push('AROUSED_DATA_DIR must be an absolute persistent path for SQLite.');
  if (!nonEmpty(env.AROUSED_PUBLIC_BASE_URL)) errors.push('AROUSED_PUBLIC_BASE_URL must be set.');
  else {
    try { if (new URL(env.AROUSED_PUBLIC_BASE_URL).protocol !== 'https:') errors.push('AROUSED_PUBLIC_BASE_URL must use HTTPS.'); }
    catch { errors.push('AROUSED_PUBLIC_BASE_URL must be a valid HTTPS URL.'); }
  }
  const origins = String(env.AROUSED_ALLOWED_ORIGINS || '').split(',').map(value => value.trim()).filter(Boolean);
  if (!origins.length) errors.push('AROUSED_ALLOWED_ORIGINS must contain at least one HTTPS origin.');
  for (const origin of origins) {
    try {
      const parsed = new URL(origin);
      if (parsed.protocol !== 'https:' || parsed.origin !== origin || origin.includes('*')) errors.push('AROUSED_ALLOWED_ORIGINS must contain exact HTTPS origins only.');
    } catch { errors.push('AROUSED_ALLOWED_ORIGINS contains an invalid origin.'); }
  }
  if (!nonEmpty(env.AROUSED_EMAIL_CODE_SECRET) || env.AROUSED_EMAIL_CODE_SECRET.length < 64) errors.push('AROUSED_EMAIL_CODE_SECRET must contain at least 64 characters.');
  if (!nonEmpty(env.RESEND_API_KEY)) errors.push('RESEND_API_KEY is required for production email verification and recovery.');
  if (!nonEmpty(env.AROUSED_FROM_EMAIL)) errors.push('AROUSED_FROM_EMAIL is required for production email delivery.');

  if (env.AROUSED_STORAGE_DRIVER !== 's3') errors.push('AROUSED_STORAGE_DRIVER must be s3 in production.');
  if (!nonEmpty(env.AROUSED_OBJECT_STORAGE_BUCKET)) errors.push('AROUSED_OBJECT_STORAGE_BUCKET is required.');
  if (!nonEmpty(env.AROUSED_OBJECT_STORAGE_REGION)) errors.push('AROUSED_OBJECT_STORAGE_REGION is required.');
  const hasKeys = secretPair(env, 'AROUSED_OBJECT_STORAGE_ACCESS_KEY_ID', 'AROUSED_OBJECT_STORAGE_SECRET_ACCESS_KEY', errors);
  if (!hasKeys && env.AROUSED_OBJECT_STORAGE_USE_INSTANCE_ROLE !== 'true') errors.push('Configure an object-storage credential pair or explicitly select AROUSED_OBJECT_STORAGE_USE_INSTANCE_ROLE=true.');
  if (nonEmpty(env.AROUSED_OBJECT_STORAGE_ENDPOINT)) {
    try { if (new URL(env.AROUSED_OBJECT_STORAGE_ENDPOINT).protocol !== 'https:') errors.push('AROUSED_OBJECT_STORAGE_ENDPOINT must use HTTPS.'); }
    catch { errors.push('AROUSED_OBJECT_STORAGE_ENDPOINT must be a valid HTTPS URL.'); }
    if (!hasKeys) errors.push('S3-compatible endpoints require explicit access credentials.');
  }
  return [...new Set(errors)];
}

export function assertProductionEnvironment(env = process.env, nodeVersion = process.versions.node) {
  const errors = validateProductionEnvironment(env, nodeVersion);
  if (errors.length) throw new Error(`Production configuration is incomplete: ${errors.join(' ')}`);
  return true;
}
