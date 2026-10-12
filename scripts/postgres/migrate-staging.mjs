import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';

const root = path.resolve(import.meta.dirname, '../..');
const sourcePath = process.argv[2];
const dsn = process.env.AROUSED_STAGING_DATABASE_URL;
const expectedDatabaseName = process.env.AROUSED_STAGING_DATABASE_NAME;
const expectedDatabaseRole = process.env.AROUSED_STAGING_DATABASE_ROLE;
if (!sourcePath) throw new Error('Usage: node scripts/postgres/migrate-staging.mjs <prepared-readonly-sqlite-copy>');
if (!dsn) throw new Error('Set AROUSED_STAGING_DATABASE_URL to an isolated staging PostgreSQL database.');
if (!expectedDatabaseName || !/^[a-z0-9_]+_(staging|test)$/i.test(expectedDatabaseName)) throw new Error('Set AROUSED_STAGING_DATABASE_NAME to the exact disposable database name ending in _staging or _test.');
if (!expectedDatabaseRole || !/^[a-z0-9_]+_(migrator|staging)$/i.test(expectedDatabaseRole)) throw new Error('Set AROUSED_STAGING_DATABASE_ROLE to the dedicated staging database owner/login.');
if (process.env.AROUSED_STAGING_DATABASE_DISPOSABLE !== 'YES') throw new Error('Set AROUSED_STAGING_DATABASE_DISPOSABLE=YES only after marking this dedicated staging database disposable.');
if (process.env.AROUSED_ALLOW_STAGING_POSTGRES_MIGRATION !== 'YES') {
  throw new Error('Set AROUSED_ALLOW_STAGING_POSTGRES_MIGRATION=YES only after confirming this DSN points to staging.');
}

let pg;
try { pg = await import('pg'); }
catch { throw new Error('PostgreSQL client package "pg" is missing. Install project dependencies before running this staging-only migration.'); }
const { Pool } = pg;
const sqlite = new DatabaseSync(path.resolve(sourcePath), { readOnly: true });
const integrity = sqlite.prepare('PRAGMA integrity_check').get()?.integrity_check;
if (integrity !== 'ok') throw new Error(`SQLite source integrity check failed (${integrity || 'no result'}); refusing migration.`);
const fkProblems = sqlite.prepare('PRAGMA foreign_key_check').all();
if (fkProblems.length) throw new Error(`SQLite source has ${fkProblems.length} foreign-key violation(s); refusing migration.`);
const tables = sqlite.prepare("SELECT name,sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").all();
const tableMap = new Map(tables.map(table => [table.name, {
  ...table,
  columns: sqlite.prepare(`PRAGMA table_info("${table.name.replaceAll('"', '""')}")`).all(),
  foreignKeys: sqlite.prepare(`PRAGMA foreign_key_list("${table.name.replaceAll('"', '""')}")`).all(),
}]));
const schemaSql = await readFile(path.join(root, 'migrations', 'postgres', '001_schema.sql'), 'utf8');
const schemaTables = new Set([...schemaSql.matchAll(/CREATE TABLE\s+(?:"([^"]+)"|([A-Za-z0-9_]+))/gi)].map(match => match[1] || match[2]));
const missing = [...schemaTables].filter(name => !tableMap.has(name));
const unexpected = [...tableMap.keys()].filter(name => !schemaTables.has(name));
if (missing.length || unexpected.length) throw new Error(`SQLite schema is not prepared/current. Missing source tables: ${missing.join(', ') || 'none'}; unexpected source tables: ${unexpected.join(', ') || 'none'}. Start the application only against an isolated copy, then retry.`);
const ordered = [], remaining = new Set(tableMap.keys());
while (remaining.size) {
  const ready = [...remaining].filter(name => tableMap.get(name).foreignKeys.every(fk => !remaining.has(fk.table) || fk.table === name)).sort();
  if (!ready.length) throw new Error(`Foreign-key cycle in SQLite source: ${[...remaining].join(', ')}`);
  for (const name of ready) { ordered.push(tableMap.get(name)); remaining.delete(name); }
}

const pool = new Pool({ connectionString: dsn, max: 1, application_name: 'aroused-staging-migration' });
const client = await pool.connect();
const quote = value => `"${String(value).replaceAll('"', '""')}"`;
let transactionOpen = false;
try {
  // Read-only identity preflight. The database must carry the marker set by the DBA
  // and the name must match exactly before any DDL or data writes are attempted.
  const identity = await client.query("SELECT current_database() AS name, current_user AS login, pg_get_userbyid(datdba) AS owner, shobj_description(oid, 'pg_database') AS marker FROM pg_database WHERE datname=current_database()");
  if (identity.rows[0]?.name !== expectedDatabaseName) throw new Error('Connected PostgreSQL database name does not match AROUSED_STAGING_DATABASE_NAME; refusing to proceed.');
  if (identity.rows[0]?.login !== expectedDatabaseRole || identity.rows[0]?.owner !== expectedDatabaseRole) throw new Error('Connected login must be the configured dedicated database owner; refusing to modify this database.');
  if (identity.rows[0]?.marker !== 'aroused-disposable-staging') throw new Error('PostgreSQL database is not marked aroused-disposable-staging; refusing to proceed.');
  const userSchemas = await client.query("SELECT nspname FROM pg_catalog.pg_namespace WHERE nspname NOT IN ('public','pg_catalog','information_schema') AND nspname NOT LIKE 'pg_toast%' AND nspname NOT LIKE 'pg_temp_%'");
  if (userSchemas.rows.length) throw new Error('Target contains user schemas; refusing to modify this non-disposable database.');
  const publicObjects = await client.query("SELECT count(*)::bigint AS count FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','S','f')");
  if (Number(publicObjects.rows[0].count)) throw new Error('Target public schema contains database objects; refusing to modify this non-empty database.');
  const targetTables = await client.query("SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname='public'");
  if (targetTables.rows.length) throw new Error('Target public schema is not empty; refusing to modify it.');
  await client.query('BEGIN'); transactionOpen = true;
  await client.query(schemaSql);
  const counts = {};
  for (const table of ordered) {
    const columns = table.columns.map(column => column.name);
    const select = sqlite.prepare(`SELECT ${columns.map(quote).join(',')} FROM ${quote(table.name)}`);
    const insertSql = `INSERT INTO ${quote(table.name)} (${columns.map(quote).join(',')}) VALUES (${columns.map((_, i) => `$${i + 1}`).join(',')})`;
    let count = 0;
    for (const row of select.iterate()) {
      const values = columns.map(column => row[column]);
      await client.query(insertSql, values);
      count++;
    }
    counts[table.name] = { sqlite: count };
  }
  for (const table of ordered) {
    const quoted = quote(table.name);
    const result = await client.query(`SELECT count(*)::bigint AS count FROM ${quoted}`);
    const pgCount = Number(result.rows[0].count);
    counts[table.name].postgres = pgCount;
    if (pgCount !== counts[table.name].sqlite) throw new Error(`Row-count mismatch for ${table.name}: SQLite=${counts[table.name].sqlite} PostgreSQL=${pgCount}`);
    for (const fk of table.foreignKeys) {
      const child = quote(table.name), parent = quote(fk.table), childColumn = quote(fk.from), parentColumn = quote(fk.to);
      const check = await client.query(`SELECT count(*)::bigint AS count FROM ${child} c LEFT JOIN ${parent} p ON c.${childColumn}=p.${parentColumn} WHERE c.${childColumn} IS NOT NULL AND p.${parentColumn} IS NULL`);
      if (Number(check.rows[0].count)) throw new Error(`Foreign-key mismatch: ${table.name}.${fk.from} references missing ${fk.table}.${fk.to}.`);
    }
  }
  const uniqueIndexes = await client.query(`SELECT t.relname AS table_name, to_json(ARRAY(
      SELECT COALESCE(a.attname, pg_get_indexdef(i.indexrelid, k.ordinality::integer, true))
      FROM unnest(i.indkey::smallint[]) WITH ORDINALITY AS k(attnum, ordinality)
      LEFT JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=k.attnum
      WHERE k.ordinality <= i.indnkeyatts ORDER BY k.ordinality
    )) AS key_parts
    FROM pg_index i JOIN pg_class t ON t.oid=i.indrelid JOIN pg_namespace n ON n.oid=t.relnamespace
    WHERE n.nspname='public' AND i.indisunique`);
  const uniqueKey = (table, columns) => `${table}:${columns.map(column => column.trim().replaceAll('"', '').replace(/\s+/g, '').toLowerCase()).join(',')}`;
  const actualUnique = new Set(uniqueIndexes.rows.map(row => uniqueKey(row.table_name, row.key_parts)));
  const expectedUnique = new Set();
  for (const table of ordered) {
    const indexes = sqlite.prepare(`PRAGMA index_list(${quote(table.name)})`).all();
    for (const index of indexes.filter(item => item.unique)) {
      const columns = sqlite.prepare(`PRAGMA index_info(${quote(index.name)})`).all().map(item => item.name);
      if (table.name === 'pending_email_verifications' && index.origin === 'pk' && columns.includes('email')) expectedUnique.add(uniqueKey(table.name, columns));
      const mapped = columns.map(column => ['users.email', 'users.username', 'pending_email_verifications.email'].includes(`${table.name}.${column}`) ? `lower(${column})` : column);
      expectedUnique.add(uniqueKey(table.name, mapped));
    }
  }
  const missingUnique = [...expectedUnique].filter(key => !actualUnique.has(key));
  if (missingUnique.length) throw new Error(`PostgreSQL unique constraints/indexes missing after schema creation: ${missingUnique.join('; ')}`);

  const foreignKeyRows = await client.query(`SELECT child.relname AS child_table, parent.relname AS parent_table,
      to_json(ARRAY(SELECT a.attname FROM unnest(con.conkey) WITH ORDINALITY AS k(attnum, ordinality)
        JOIN pg_attribute a ON a.attrelid=con.conrelid AND a.attnum=k.attnum ORDER BY k.ordinality)) AS child_columns,
      to_json(ARRAY(SELECT a.attname FROM unnest(con.confkey) WITH ORDINALITY AS k(attnum, ordinality)
        JOIN pg_attribute a ON a.attrelid=con.confrelid AND a.attnum=k.attnum ORDER BY k.ordinality)) AS parent_columns,
      con.confdeltype AS delete_action
    FROM pg_constraint con JOIN pg_class child ON child.oid=con.conrelid
    JOIN pg_namespace n ON n.oid=child.relnamespace JOIN pg_class parent ON parent.oid=con.confrelid
    WHERE con.contype='f' AND n.nspname='public'`);
  const deleteAction = { a: 'NO ACTION', r: 'RESTRICT', c: 'CASCADE', n: 'SET NULL', d: 'SET DEFAULT' };
  const foreignKeyKey = (child, childColumns, parent, parentColumns, action) => `${child}:${childColumns.join(',')}->${parent}:${parentColumns.join(',')}:${action}`;
  const actualForeignKeys = new Set(foreignKeyRows.rows.map(row => foreignKeyKey(row.child_table, row.child_columns, row.parent_table, row.parent_columns, deleteAction[row.delete_action])));
  const expectedForeignKeys = new Set();
  for (const table of ordered) {
    const grouped = new Map();
    for (const fk of table.foreignKeys) {
      const group = grouped.get(fk.id) || [];
      group.push(fk);
      grouped.set(fk.id, group);
    }
    for (const [id, rows] of grouped) {
      rows.sort((a, b) => a.seq - b.seq);
      expectedForeignKeys.add(foreignKeyKey(table.name, rows.map(row => row.from), rows[0].table, rows.map(row => row.to), rows[0].on_delete));
    }
  }
  const missingForeignKeys = [...expectedForeignKeys].filter(key => !actualForeignKeys.has(key));
  if (missingForeignKeys.length) throw new Error(`PostgreSQL foreign-key constraints missing or mismatched: ${missingForeignKeys.join('; ')}`);
  // Advance identity sequences after preserving explicit SQLite IDs.
  for (const table of ordered) {
    const pk = table.columns.filter(column => column.pk).sort((a, b) => a.pk - b.pk);
    if (pk.length !== 1 || !/INT/i.test(pk[0].type)) continue;
    const relation = `public.${table.name}`;
    await client.query(`SELECT setval(pg_get_serial_sequence($1,$2), GREATEST(COALESCE(MAX(${quote(pk[0].name)}),1),1), MAX(${quote(pk[0].name)}) IS NOT NULL) FROM ${quote(table.name)}`, [relation, pk[0].name]);
  }
  const relationshipCounts = {};
  const relationshipSql = {
    identities: 'SELECT count(*)::bigint AS count FROM user_identities',
    sessions: 'SELECT count(*)::bigint AS count FROM sessions',
    storiesWithOwners: 'SELECT count(*)::bigint AS count FROM stories s JOIN users u ON u.id=s.creator_id',
    albumMediaWithOwners: 'SELECT count(*)::bigint AS count FROM album_media m JOIN albums a ON a.id=m.album_id JOIN users u ON u.id=a.owner_id',
    reportsWithTargetOrNull: 'SELECT count(*)::bigint AS count FROM reports',
    moderationCases: 'SELECT count(*)::bigint AS count FROM moderation_cases',
    creatorDeclarations: 'SELECT count(*)::bigint AS count FROM creator_declarations',
  };
  for (const [name, sql] of Object.entries(relationshipSql)) {
    const sourceCount = Number(sqlite.prepare(sql.replace('::bigint', '')).get().count);
    const targetCount = Number((await client.query(sql)).rows[0].count);
    relationshipCounts[name] = { sqlite: sourceCount, postgres: targetCount };
    if (sourceCount !== targetCount) throw new Error(`Relationship-count mismatch for ${name}: SQLite=${sourceCount} PostgreSQL=${targetCount}`);
  }
  await client.query('COMMIT'); transactionOpen = false;
  console.log(JSON.stringify({ status: 'staging-import-verified', sourcePath: path.resolve(sourcePath), tableCount: tables.length, counts, relationshipCounts, constraintsVerified: { uniqueIndexes: expectedUnique.size, foreignKeys: expectedForeignKeys.size }, runtimeSwitched: false }, null, 2));
} catch (error) {
  if (transactionOpen) await client.query('ROLLBACK').catch(() => {});
  throw error;
} finally {
  client.release();
  await pool.end();
  sqlite.close();
}
