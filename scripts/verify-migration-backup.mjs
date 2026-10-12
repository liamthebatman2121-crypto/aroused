import { readFile, readdir, stat } from 'node:fs/promises';
import crypto from 'node:crypto';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';

const root = path.resolve(import.meta.dirname, '..');
const backup = path.resolve(process.argv[2] || path.join(root, 'migration-backups', 'migration-20261008T154037Z'));
const originalDb = path.join(root, 'data', 'aroused.sqlite');
const originalUploads = path.join(root, 'uploads');
const hash = async file => crypto.createHash('sha256').update(await readFile(file)).digest('hex');
const inventory = async directory => {
  const files = [];
  async function walk(current) {
    for (const entry of await readdir(current, { withFileTypes: true })) {
      const full = path.join(current, entry.name);
      const relative = path.relative(directory, full).split(path.sep).join('/');
      if (entry.isDirectory()) await walk(full);
      else if (entry.isFile()) files.push({ path: relative, size: (await stat(full)).size, sha256: await hash(full) });
      else throw new Error(`Unsupported upload entry: ${full}`);
    }
  }
  await walk(directory);
  return files.sort((a, b) => a.path.localeCompare(b.path));
};
const counts = database => Object.fromEntries(database.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").all().map(({ name }) => [name, database.prepare(`SELECT count(*) AS n FROM "${name.replaceAll('"', '""')}"`).get().n]));
const expected = JSON.parse(await readFile(path.join(backup, 'verification.json'), 'utf8'));
const source = new DatabaseSync(originalDb, { readOnly: true });
const copy = new DatabaseSync(path.join(backup, 'aroused.sqlite'), { readOnly: true });
const restored = new DatabaseSync(path.join(backup, 'restore-test', 'aroused.sqlite'), { readOnly: true });
const checks = {
  sourceIntegrity: source.prepare('PRAGMA integrity_check').get().integrity_check,
  backupIntegrity: copy.prepare('PRAGMA integrity_check').get().integrity_check,
  restoreIntegrity: restored.prepare('PRAGMA integrity_check').get().integrity_check,
  sourceCountsMatchBackup: JSON.stringify(counts(source)) === JSON.stringify(counts(copy)),
  backupCountsMatchRestore: JSON.stringify(counts(copy)) === JSON.stringify(counts(restored)),
  uploadsMatchBackup: JSON.stringify(await inventory(originalUploads)) === JSON.stringify(await inventory(path.join(backup, 'uploads'))),
  uploadsMatchRestore: JSON.stringify(await inventory(originalUploads)) === JSON.stringify(await inventory(path.join(backup, 'restore-test', 'uploads'))),
};
source.close(); copy.close(); restored.close();
if (checks.sourceIntegrity !== 'ok' || checks.backupIntegrity !== 'ok' || checks.restoreIntegrity !== 'ok' || Object.values(checks).some(value => value === false)) throw new Error(`Backup verification failed: ${JSON.stringify(checks)}`);
console.log(JSON.stringify({ backup, checks, expectedBackupTimestamp: expected.backup, uploadFileCount: expected.uploadFileCount, uploadBytes: expected.uploadBytes, tableCount: Object.keys(expected.sourceCounts).length }, null, 2));
