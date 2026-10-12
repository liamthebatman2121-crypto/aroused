import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer } from 'node:net';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const node = process.execPath;
const freePort = () => new Promise((resolve, reject) => {
  const server = createServer();
  server.once('error', reject);
  server.listen(0, '127.0.0.1', () => {
    const { port } = server.address();
    server.close(error => error ? reject(error) : resolve(port));
  });
});

test('readiness reports missing safety providers and protects admin health', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'aroused-readiness-'));
  const port = await freePort();
  const email = `admin-${Date.now()}@example.test`;
  const password = `Test!${Date.now()}-Production-Readiness`;
  const child = spawn(node, ['server.mjs'], {
    cwd: root,
    env: { ...process.env, NODE_ENV: 'test', AROUSED_API_PORT: String(port), AROUSED_DATA_DIR: join(dir, 'data'), AROUSED_UPLOAD_DIR: join(dir, 'uploads'), AROUSED_ADMIN_EMAIL: email, AROUSED_ADMIN_PASSWORD: password },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  let logs = '';
  child.stdout.on('data', data => { logs += data.toString(); });
  child.stderr.on('data', data => { logs += data.toString(); });
  t.after(async () => {
    if (child.exitCode === null) {
      await new Promise(resolve => {
        child.once('exit', resolve);
        child.kill('SIGTERM');
        setTimeout(resolve, 2000).unref();
      });
    }
    await rm(dir, { recursive: true, force: true });
  });

  const base = `http://127.0.0.1:${port}/api`;
  let health;
  for (let attempt = 0; attempt < 80; attempt++) {
    if (child.exitCode !== null) throw new Error(`Server exited during startup: ${logs}`);
    try { health = await fetch(`${base}/health`); break; } catch { await new Promise(resolve => setTimeout(resolve, 100)); }
  }
  assert.ok(health, `Server did not start: ${logs}`);
  assert.equal(health.status, 200);
  const healthBody = await health.json();
  assert.equal(healthBody.readyForProduction, false);
  assert.equal(healthBody.providers.ageAssurance.status, 'NOT_CONFIGURED');
  assert.equal(healthBody.providers.malwareScanner.status, 'NOT_CONFIGURED');
  assert.equal(healthBody.providers.googleOAuth.status, 'NOT_CONFIGURED');
  assert.equal(healthBody.providers.redditOAuth.status, 'NOT_CONFIGURED');
  assert.equal(healthBody.providers.xOAuth.status, 'NOT_CONFIGURED');
  const live = await fetch(`${base}/health/live`);
  assert.equal(live.status, 200);
  assert.equal((await live.json()).ok, true);
  const ready = await fetch(`${base}/health/ready`);
  assert.equal(ready.status, 200);
  const readyBody = await ready.json();
  assert.equal(readyBody.database, 'available');
  assert.equal(readyBody.storage, 'available');
  assert.equal(readyBody.readyForProduction, false);

  const unauthorized = await fetch(`${base}/admin/health`);
  assert.equal(unauthorized.status, 401);
  const login = await fetch(`${base}/auth/login`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', 'Sec-Fetch-Site': 'same-origin' },
    body: JSON.stringify({ email, password })
  });
  assert.equal(login.status, 200);
  const cookie = login.headers.get('set-cookie').split(';')[0];
  const eligibility = await fetch(`${base}/upload/eligibility`, { headers: { Cookie: cookie } });
  assert.equal(eligibility.status, 200);
  const eligibilityBody = await eligibility.json();
  assert.equal(eligibilityBody.eligible, false);
  assert.equal(eligibilityBody.reason, 'AGE_ASSURANCE_NOT_CONFIGURED');
  const legacyUpload = await fetch(`${base}/stories/upload`, {
    method: 'POST', headers: { Cookie: cookie, 'Content-Type': 'application/json', 'Sec-Fetch-Site': 'same-origin' },
    body: '{}'
  });
  assert.equal(legacyUpload.status, 410);
  const adminHealth = await fetch(`${base}/admin/health`, { headers: { Cookie: cookie } });
  assert.equal(adminHealth.status, 200);
  const adminHealthBody = await adminHealth.json();
  assert.equal(adminHealthBody.readiness.readyForProduction, false);
  assert.ok('mediaPending' in adminHealthBody.queues);

  const report = await fetch(`${base}/reports/profile`, {
    method: 'POST', headers: { Cookie: cookie, 'Content-Type': 'application/json', 'Sec-Fetch-Site': 'same-origin' },
    body: JSON.stringify({ creator: 'Mila Rose', category: 'suspected_minor', reason: 'Safety review', details: 'Test record only.' })
  });
  assert.equal(report.status, 201);
  const caseList = await fetch(`${base}/moderation/cases`, { headers: { Cookie: cookie } });
  assert.equal(caseList.status, 200);
  const casesBody = await caseList.json();
  assert.equal(casesBody.items[0].priority, 'critical');
  assert.equal(casesBody.items[0].restricted, 1);

  const crossSite = await fetch(`${base}/auth/login`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', 'Sec-Fetch-Site': 'cross-site' },
    body: JSON.stringify({ email, password })
  });
  assert.equal(crossSite.status, 403);
});
