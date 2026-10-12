import { oauthProviders } from './auth/oauth-providers.mjs';

const configured = (env, keys) => keys.every(key => Boolean(String(env[key] || '').trim()));

// This reports configuration and implemented runtime capabilities only. It never
// infers that a provider returned a clean/safe/verified result.
export function providerStatus(env = process.env) {
  const production = env.NODE_ENV === 'production';
  const emailConfigured = configured(env, ['RESEND_API_KEY', 'AROUSED_FROM_EMAIL']);
  const social=oauthProviders(env);
  const objectStorageConfigured = env.AROUSED_STORAGE_DRIVER === 's3'
    && configured(env, ['AROUSED_OBJECT_STORAGE_BUCKET', 'AROUSED_OBJECT_STORAGE_REGION'])
    && (configured(env, ['AROUSED_OBJECT_STORAGE_ACCESS_KEY_ID', 'AROUSED_OBJECT_STORAGE_SECRET_ACCESS_KEY']) || env.AROUSED_OBJECT_STORAGE_USE_INSTANCE_ROLE === 'true')
    && (!env.AROUSED_OBJECT_STORAGE_ENDPOINT || (String(env.AROUSED_OBJECT_STORAGE_ENDPOINT).startsWith('https://') && configured(env, ['AROUSED_OBJECT_STORAGE_ACCESS_KEY_ID', 'AROUSED_OBJECT_STORAGE_SECRET_ACCESS_KEY'])));
  const providers = {
    resend: { status: emailConfigured ? 'CONFIGURED' : 'NOT_CONFIGURED', implemented: true },
    googleOAuth: { status: social.google.configured ? 'CONFIGURED' : 'NOT_CONFIGURED', implemented: true, missing: social.google.configured ? [] : ['Google OAuth client registration, credentials, and exact callback URI'] },
    redditOAuth: { status: social.reddit.configured ? 'CONFIGURED' : 'NOT_CONFIGURED', implemented: true, missing: social.reddit.configured ? [] : ['Reddit OAuth client registration, credentials, and exact callback URI'] },
    xOAuth: { status: social.x.configured ? 'CONFIGURED' : 'NOT_CONFIGURED', implemented: true, missing: social.x.configured ? [] : ['X OAuth 2.0 client registration, credentials, and exact callback URI'] },
    storage: objectStorageConfigured
      ? { status: 'CONFIGURED', driver: 's3', implemented: true, verified: false, missing: ['Real bucket-access and private-access integration test'] }
      : { status: production ? 'NOT_CONFIGURED' : 'DEGRADED', driver: 'local-filesystem', implemented: true, missing: production ? ['Private production object storage'] : [] },
    mediaProcessor: { status: 'NOT_CONFIGURED', implemented: true, interface: true, missing: ['Configured isolated image/video decoder and transcoder'] },
    malwareScanner: { status: 'NOT_CONFIGURED', implemented: true, interface: true, missing: ['Configured malware scanner provider and real integration test'] },
    fingerprint: { status: 'HEALTHY', implemented: true, algorithm: 'SHA-256' },
    knownContent: { status: 'NOT_CONFIGURED', implemented: true, interface: true, missing: ['Approved known-CSAM image matcher', 'Approved known-CSAM video matcher'] },
    contentSafety: { status: 'NOT_CONFIGURED', implemented: true, interface: true, missing: ['Configured prohibited-abuse review provider', 'Restricted human review operations'] },
    ageAssurance: { status: 'NOT_CONFIGURED', implemented: false, missing: ['Age-assurance provider and adapter'] }
  };
  const readiness = Object.values(providers).every(item => ['CONFIGURED', 'HEALTHY'].includes(item.status));
  return { status: readiness ? 'HEALTHY' : 'DEGRADED', readyForProduction: readiness, providers };
}
