import { createServer } from 'node:http';
import { DatabaseSync } from 'node:sqlite';
import { randomBytes, scryptSync, timingSafeEqual, createHash, createHmac } from 'node:crypto';
import { mkdir, readFile } from 'node:fs/promises';
import { extname, join, basename, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { providerStatus } from './provider-status.mjs';
import { AuthorizedStorage, createStorageProvider } from './storage/storage-provider.mjs';
import { assertProductionEnvironment } from './config/production-env.mjs';
import { operationalLog, safeErrorCode } from './observability/logger.mjs';
import { enqueueMediaJob } from './processing/media-worker.mjs';
import { sendResendEmail } from './auth/resend-mailer.mjs';
import { oauthProviders, createOAuthAuthorization, fetchOAuthIdentity } from './auth/oauth-providers.mjs';

assertProductionEnvironment(process.env);

const root = fileURLToPath(new URL('.', import.meta.url));
const dataDir = process.env.AROUSED_DATA_DIR ? resolve(process.env.AROUSED_DATA_DIR) : join(root, 'data');
const uploadDir = process.env.AROUSED_UPLOAD_DIR ? resolve(process.env.AROUSED_UPLOAD_DIR) : join(root, 'uploads');
const storageProvider = await createStorageProvider({ env: process.env, localRoot: uploadDir });
if (process.env.NODE_ENV === 'production') await storageProvider.verifyPrivateDestination();
const authorizedStorage = new AuthorizedStorage(storageProvider);
await mkdir(dataDir, { recursive: true });

const db = new DatabaseSync(join(dataDir, 'aroused.sqlite'));
db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA foreign_keys = ON;
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY, display_name TEXT NOT NULL,
    email TEXT UNIQUE COLLATE NOCASE, password_hash TEXT,
    avatar_initial TEXT NOT NULL, adult_confirmed INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS user_identities (
    id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider TEXT NOT NULL CHECK(provider IN ('email','google','reddit','x')),
    provider_user_id TEXT NOT NULL, provider_email TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
    UNIQUE(provider,provider_user_id), UNIQUE(user_id,provider)
  );
  CREATE INDEX IF NOT EXISTS user_identities_user_idx ON user_identities(user_id);
  CREATE TABLE IF NOT EXISTS oauth_transactions (
    state_hash TEXT PRIMARY KEY, provider TEXT NOT NULL, purpose TEXT NOT NULL,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, code_verifier TEXT,
    adult_confirmed INTEGER NOT NULL DEFAULT 0, terms_version TEXT, guidelines_version TEXT,
    created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS rate_limit_buckets (
    bucket_key TEXT PRIMARY KEY, hits INTEGER NOT NULL, reset_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS password_reset_tokens (
    token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL, used_at TEXT, created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS policy_acceptances (
    id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    album_id INTEGER, policy_key TEXT NOT NULL, policy_version TEXT NOT NULL,
    accepted_at TEXT NOT NULL, UNIQUE(user_id,album_id,policy_key,policy_version)
  );
  CREATE INDEX IF NOT EXISTS policy_acceptances_user_idx ON policy_acceptances(user_id,policy_key,accepted_at DESC);
  CREATE TABLE IF NOT EXISTS creator_declarations (
    id INTEGER PRIMARY KEY, album_id INTEGER NOT NULL REFERENCES albums(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    declaration_key TEXT NOT NULL, policy_version TEXT NOT NULL, accepted_at TEXT NOT NULL,
    UNIQUE(album_id,declaration_key,policy_version)
  );
  CREATE TABLE IF NOT EXISTS upload_jobs (
    id INTEGER PRIMARY KEY, album_id INTEGER NOT NULL REFERENCES albums(id) ON DELETE CASCADE,
    status TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, error_code TEXT
  );
  CREATE TABLE IF NOT EXISTS processing_jobs (
    id INTEGER PRIMARY KEY, media_id INTEGER NOT NULL REFERENCES album_media(id) ON DELETE CASCADE,
    status TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, available_at INTEGER NOT NULL,
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL, error_code TEXT
  );
  CREATE INDEX IF NOT EXISTS processing_jobs_queue_idx ON processing_jobs(status,available_at);
  CREATE TABLE IF NOT EXISTS media_fingerprints (
    media_id INTEGER PRIMARY KEY REFERENCES album_media(id) ON DELETE CASCADE,
    sha256 TEXT NOT NULL, byte_size INTEGER NOT NULL, created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS media_scan_results (
    id INTEGER PRIMARY KEY, media_id INTEGER NOT NULL REFERENCES album_media(id) ON DELETE CASCADE,
    provider TEXT NOT NULL, result TEXT NOT NULL, detail_code TEXT, created_at TEXT NOT NULL,
    check_type TEXT, provider_reference TEXT, started_at TEXT, completed_at TEXT,
    audit_metadata_json TEXT NOT NULL DEFAULT '{}'
  );
  CREATE INDEX IF NOT EXISTS media_scan_results_media_idx ON media_scan_results(media_id,created_at DESC);
  CREATE TABLE IF NOT EXISTS moderation_cases (
    id INTEGER PRIMARY KEY, album_id INTEGER REFERENCES albums(id) ON DELETE SET NULL,
    media_id INTEGER REFERENCES album_media(id) ON DELETE SET NULL,
    report_id INTEGER, category TEXT NOT NULL, priority TEXT NOT NULL DEFAULT 'normal',
    status TEXT NOT NULL DEFAULT 'open', restricted INTEGER NOT NULL DEFAULT 0,
    assigned_to INTEGER REFERENCES users(id) ON DELETE SET NULL,
    decision TEXT, decision_reason TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
    resolved_at TEXT
  );
  CREATE INDEX IF NOT EXISTS moderation_cases_queue_idx ON moderation_cases(status,priority,created_at);
  CREATE TABLE IF NOT EXISTS enforcement_actions (
    id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    admin_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL, action TEXT NOT NULL,
    reason TEXT NOT NULL, expires_at TEXT, created_at TEXT NOT NULL, revoked_at TEXT
  );
  CREATE TABLE IF NOT EXISTS appeals (
    id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    enforcement_id INTEGER REFERENCES enforcement_actions(id) ON DELETE SET NULL,
    reason TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open', assigned_to INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL, decision_reason TEXT
  );
  CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    event_type TEXT NOT NULL, severity TEXT NOT NULL DEFAULT 'info', detail_code TEXT NOT NULL,
    created_at TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS security_events_created_idx ON security_events(created_at DESC);
  CREATE TABLE IF NOT EXISTS pending_email_verifications (
    email TEXT PRIMARY KEY COLLATE NOCASE, display_name TEXT NOT NULL,
    password_hash TEXT NOT NULL, code_hash TEXT NOT NULL,
    expires_at INTEGER NOT NULL, next_send_at INTEGER NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL,
    terms_accepted_at TEXT, guidelines_accepted_at TEXT
  );
  CREATE TABLE IF NOT EXISTS app_secrets (name TEXT PRIMARY KEY, value TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS site_settings (name TEXT PRIMARY KEY, value TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS stories (
    id INTEGER PRIMARY KEY, creator_id INTEGER NOT NULL REFERENCES users(id),
    title TEXT NOT NULL, category TEXT NOT NULL, tags_json TEXT NOT NULL DEFAULT '[]',
    media_name TEXT, media_path TEXT, media_type TEXT, duration TEXT NOT NULL DEFAULT '00:00',
    views INTEGER NOT NULL DEFAULT 0, seeded_likes INTEGER NOT NULL DEFAULT 0,
    tone_a TEXT NOT NULL DEFAULT '#59352f', tone_b TEXT NOT NULL DEFAULT '#c17767',
    status TEXT NOT NULL DEFAULT 'published', created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS likes (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    story_id INTEGER NOT NULL REFERENCES stories(id) ON DELETE CASCADE,
    PRIMARY KEY(user_id, story_id)
  );
  CREATE TABLE IF NOT EXISTS follows (
    follower_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    creator_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY(follower_id, creator_id), CHECK(follower_id <> creator_id)
  );
  CREATE TABLE IF NOT EXISTS saves (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    story_id INTEGER NOT NULL REFERENCES stories(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL, PRIMARY KEY(user_id, story_id)
  );
  CREATE TABLE IF NOT EXISTS reposts (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    story_id INTEGER NOT NULL REFERENCES stories(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL, PRIMARY KEY(user_id, story_id)
  );
  CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    story_id INTEGER NOT NULL REFERENCES stories(id) ON DELETE CASCADE,
    body TEXT NOT NULL, created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY, sender_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    recipient_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    body TEXT NOT NULL, created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY, reporter_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    story_id INTEGER REFERENCES stories(id) ON DELETE SET NULL,
    target_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    reason TEXT NOT NULL, details TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'open',
    created_at TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS story_creator_idx ON stories(creator_id, created_at DESC);
  CREATE INDEX IF NOT EXISTS story_search_idx ON stories(title, category);
  CREATE INDEX IF NOT EXISTS comments_story_idx ON comments(story_id, created_at);
  CREATE INDEX IF NOT EXISTS messages_pair_idx ON messages(sender_id, recipient_id, created_at);
`);
const mediaScanColumns=new Set(db.prepare('PRAGMA table_info(media_scan_results)').all().map(column=>column.name));
for(const [column,definition] of [['check_type','TEXT'],['provider_reference','TEXT'],['started_at','TEXT'],['completed_at','TEXT'],['audit_metadata_json',"TEXT NOT NULL DEFAULT '{}'"]])if(!mediaScanColumns.has(column))db.exec(`ALTER TABLE media_scan_results ADD COLUMN ${column} ${definition}`);
const messageColumns=new Set(db.prepare('PRAGMA table_info(messages)').all().map(column=>column.name));
if(!messageColumns.has('is_system_notice'))db.exec('ALTER TABLE messages ADD COLUMN is_system_notice INTEGER NOT NULL DEFAULT 0');
for(const [key,value] of [['signups_enabled','true'],['uploads_enabled','true']])db.prepare('INSERT OR IGNORE INTO site_settings(name,value) VALUES(?,?)').run(key,value);
const pendingColumns=new Set(db.prepare('PRAGMA table_info(pending_email_verifications)').all().map(column=>column.name));
if(!pendingColumns.has('terms_accepted_at'))db.exec('ALTER TABLE pending_email_verifications ADD COLUMN terms_accepted_at TEXT');
if(!pendingColumns.has('guidelines_accepted_at'))db.exec('ALTER TABLE pending_email_verifications ADD COLUMN guidelines_accepted_at TEXT');
if(!pendingColumns.has('terms_version'))db.exec('ALTER TABLE pending_email_verifications ADD COLUMN terms_version TEXT');
if(!pendingColumns.has('guidelines_version'))db.exec('ALTER TABLE pending_email_verifications ADD COLUMN guidelines_version TEXT');
const userColumns=new Set(db.prepare('PRAGMA table_info(users)').all().map(column=>column.name));
if(!userColumns.has('onlyfans_url'))db.exec("ALTER TABLE users ADD COLUMN onlyfans_url TEXT NOT NULL DEFAULT ''");
if(!userColumns.has('avatar_path'))db.exec('ALTER TABLE users ADD COLUMN avatar_path TEXT');
if(!userColumns.has('updated_at'))db.exec('ALTER TABLE users ADD COLUMN updated_at TEXT');
if(!userColumns.has('username'))db.exec("ALTER TABLE users ADD COLUMN username TEXT NOT NULL DEFAULT ''");
if(!userColumns.has('bio'))db.exec("ALTER TABLE users ADD COLUMN bio TEXT NOT NULL DEFAULT ''");
for(const [column,definition] of [['email_verified_at','TEXT'],['terms_accepted_at','TEXT'],['guidelines_accepted_at','TEXT'],['upload_restricted','INTEGER NOT NULL DEFAULT 0'],['suspended','INTEGER NOT NULL DEFAULT 0'],['banned','INTEGER NOT NULL DEFAULT 0'],['age_status',"TEXT NOT NULL DEFAULT 'unverified'"],['age_verified_at','TEXT'],['creator_agreement_version','TEXT']])if(!userColumns.has(column))db.exec(`ALTER TABLE users ADD COLUMN ${column} ${definition}`);
if(!userColumns.has('role'))db.exec("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'");
db.exec(`
  CREATE TABLE IF NOT EXISTS admin_audit_log (
    id INTEGER PRIMARY KEY, admin_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    action TEXT NOT NULL, target_type TEXT NOT NULL, target_id TEXT NOT NULL,
    details_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS admin_audit_created_idx ON admin_audit_log(created_at DESC);
`);
const reportColumns=new Set(db.prepare('PRAGMA table_info(reports)').all().map(column=>column.name));
for(const [column,definition] of [['category',"TEXT NOT NULL DEFAULT 'other'"],['priority',"TEXT NOT NULL DEFAULT 'normal'"],['assigned_to','INTEGER REFERENCES users(id) ON DELETE SET NULL'],['updated_at','TEXT']])if(!reportColumns.has(column))db.exec(`ALTER TABLE reports ADD COLUMN ${column} ${definition}`);
const albumMediaColumns=new Set(db.prepare('PRAGMA table_info(album_media)').all().map(column=>column.name));
// Detailed processing/scanning state lives in related queue/result tables so the
// existing album_media CHECK constraint remains compatible with old databases.
db.exec(`CREATE TABLE IF NOT EXISTS media_pipeline (
  media_id INTEGER PRIMARY KEY REFERENCES album_media(id) ON DELETE CASCADE,
  status TEXT NOT NULL DEFAULT 'SCAN_PENDING',
  malware_status TEXT NOT NULL DEFAULT 'NOT_CONFIGURED',
  processing_status TEXT NOT NULL DEFAULT 'NOT_CONFIGURED',
  known_content_status TEXT NOT NULL DEFAULT 'NOT_CONFIGURED',
  safety_status TEXT NOT NULL DEFAULT 'NOT_CONFIGURED',
  moderation_status TEXT NOT NULL DEFAULT 'PENDING',
  attempts INTEGER NOT NULL DEFAULT 0, error_code TEXT, updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS media_pipeline_status_idx ON media_pipeline(status,updated_at);`);
db.prepare(`UPDATE users SET email_verified_at=COALESCE(email_verified_at,created_at) WHERE email IS NOT NULL AND password_hash IS NOT NULL`).run();
db.exec(`
  CREATE TABLE IF NOT EXISTS albums (
    id INTEGER PRIMARY KEY,
    story_id INTEGER NOT NULL UNIQUE REFERENCES stories(id) ON DELETE CASCADE,
    owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    slug TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    visibility TEXT NOT NULL DEFAULT 'public' CHECK(visibility IN ('public','unlisted','private')),
    status TEXT NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','processing','published','removed','error')),
    allow_comments INTEGER NOT NULL DEFAULT 1,
    cover_media_id INTEGER,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS album_media (
    id INTEGER PRIMARY KEY,
    album_id INTEGER NOT NULL REFERENCES albums(id) ON DELETE CASCADE,
    storage_name TEXT NOT NULL UNIQUE,
    original_name TEXT NOT NULL,
    mime_type TEXT NOT NULL,
    byte_size INTEGER NOT NULL,
    position INTEGER NOT NULL,
    state TEXT NOT NULL DEFAULT 'ready' CHECK(state IN ('waiting','processing','ready','error')),
    created_at TEXT NOT NULL,
    UNIQUE(album_id,position)
  );
  CREATE INDEX IF NOT EXISTS albums_owner_idx ON albums(owner_id,status,updated_at DESC);
CREATE INDEX IF NOT EXISTS albums_visibility_idx ON albums(visibility,status,created_at DESC);
CREATE INDEX IF NOT EXISTS album_media_album_idx ON album_media(album_id,position);
`);
// Old rows have never passed the configured processor/scanner pipeline. Add an
// explicit blocked state so upgrades cannot accidentally expose legacy uploads.
db.prepare(`INSERT OR IGNORE INTO media_pipeline(media_id,status,malware_status,processing_status,known_content_status,safety_status,moderation_status,updated_at)
  SELECT id,'SCAN_PENDING','NOT_CONFIGURED','NOT_CONFIGURED','NOT_CONFIGURED','NOT_CONFIGURED','PENDING',? FROM album_media`).run(new Date().toISOString());
const storyColumns=new Set(db.prepare('PRAGMA table_info(stories)').all().map(column=>column.name));
if(!storyColumns.has('cover_media_id'))db.exec('ALTER TABLE stories ADD COLUMN cover_media_id INTEGER');
const albumColumns=new Set(db.prepare('PRAGMA table_info(albums)').all().map(column=>column.name));
if(!albumColumns.has('publish_mode'))db.exec("ALTER TABLE albums ADD COLUMN publish_mode TEXT NOT NULL DEFAULT 'immediate'");
if(!albumColumns.has('scheduled_at'))db.exec('ALTER TABLE albums ADD COLUMN scheduled_at TEXT');
if(!albumColumns.has('review_status'))db.exec("ALTER TABLE albums ADD COLUMN review_status TEXT NOT NULL DEFAULT 'not_required'");
for(const row of db.prepare("SELECT id,display_name FROM users WHERE username='' OR username IS NULL").all()){
  const base=String(row.display_name||'creator').normalize('NFKD').replace(/[\u0300-\u036f]/g,'').toLowerCase().replace(/[^a-z0-9]+/g,'_').replace(/^_+|_+$/g,'').slice(0,20)||'creator';
  let username=base,n=2;while(db.prepare('SELECT 1 FROM users WHERE username=? COLLATE NOCASE AND id<>?').get(username,row.id))username=`${base.slice(0,20-String(n).length)}${n++}`;
  db.prepare('UPDATE users SET username=? WHERE id=?').run(username,row.id);
}
db.exec('CREATE UNIQUE INDEX IF NOT EXISTS users_username_unique ON users(username COLLATE NOCASE)');
db.prepare(`INSERT OR IGNORE INTO user_identities(user_id,provider,provider_user_id,provider_email,created_at,updated_at)
  SELECT id,'email',lower(email),email,created_at,COALESCE(updated_at,created_at) FROM users WHERE email IS NOT NULL`).run();
const currentPolicyVersions={terms:'terms-2026-10-08',guidelines:'guidelines-2026-10-08',creatorAgreement:'creator-upload-2026-10-08',rights:'creator-rights-2026-10-08'};

const seedStories = [
  ['Golden hour, all to myself','Mila Rose','Portraits',2400,842,'08:42','#59352f','#c17767','2 hours ago'],
  ['A slow Sunday morning','Nico Lane','Lifestyle',1800,721,'12:18','#28393b','#62817d','4 hours ago'],
  ['After the last train','Jules A.','Behind the scenes',5100,1290,'03:42','#513035','#b45c68','6 hours ago'],
  ['Soft light, softer edges','Sora Blue','Portraits',3600,987,'06:31','#343052','#887cb3','8 hours ago'],
  ['The art of doing nothing','Liv Anders','Lifestyle',980,403,'09:04','#47402f','#aa9362','10 hours ago'],
  ['A little after dark','Rae Quinn','Late night',4200,1120,'05:18','#342b41','#9b7092','12 hours ago'],
  ['Unfiltered, unhurried','Alex Moon','Behind the scenes',2200,605,'14:22','#354139','#8b9671','1 day ago'],
  ['Room for a little wonder','Emi Hart','Art & expression',3100,916,'07:56','#573a48','#c1828b','1 day ago'],
  ['Between the sheets & sunlight','Mila Rose','Portraits',1400,502,'11:09','#4a312e','#bb8a70','2 days ago'],
  ['No plans, just us','Theo James','Lifestyle',6800,1610,'04:09','#273846','#6084a0','2 days ago'],
  ['Notes from a quiet night','Jules A.','Late night',2900,774,'05:47','#3c2937','#976b80','3 days ago'],
  ['A study in warm tones','Sora Blue','Art & expression',3900,1005,'10:33','#463434','#bd856a','3 days ago']
];
const ago = value => {
  const parts = value.split(' '), n = Number(parts[0]);
  return new Date(Date.now() - (parts[1].startsWith('hour') ? n * 3600000 : n * 86400000)).toISOString();
};
if (db.prepare('SELECT COUNT(*) AS n FROM stories').get().n === 0) {
  const insertUser = db.prepare('INSERT INTO users(display_name,username,email,password_hash,avatar_initial,adult_confirmed,created_at) VALUES(?,?,NULL,NULL,?,0,?)');
  const insertStory = db.prepare('INSERT INTO stories(id,creator_id,title,category,tags_json,duration,views,seeded_likes,tone_a,tone_b,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)');
  const creators = new Map();
  for (const [title, creator, category, views, likes, duration, a, b, age] of seedStories) {
    if (!creators.has(creator)) {
      const initial = creator[0].toUpperCase();
      const username=creator.toLowerCase().replace(/[^a-z0-9]+/g,'_').replace(/^_|_$/g,'');const result = insertUser.run(creator,username,initial,new Date().toISOString());
      creators.set(creator, Number(result.lastInsertRowid));
    }
    const id = seedStories.findIndex(item => item[0] === title) + 1;
    insertStory.run(id, creators.get(creator), title, category, JSON.stringify([category]), duration, views, likes, a, b, ago(age));
  }
  const addComment = db.prepare('INSERT INTO comments(user_id,story_id,body,created_at) VALUES(?,?,?,?)');
  const mira = Number(insertUser.run('Mira','mira','M',new Date().toISOString()).lastInsertRowid);
  const jules = Number(insertUser.run('Jules','jules','J',new Date().toISOString()).lastInsertRowid);
  addComment.run(mira, 1, 'Love the atmosphere in this one.', new Date(Date.now() - 3600000).toISOString());
  addComment.run(jules, 1, 'That last shot is beautiful.', new Date().toISOString());
}

const serverPort = Number(process.env.AROUSED_API_PORT || 8767);
const bindHost = process.env.AROUSED_BIND_HOST || '127.0.0.1';
const maxUploadBytes = Number(process.env.AROUSED_MAX_UPLOAD_BYTES || 100 * 1024 * 1024);
const allowedOrigins = new Set((process.env.AROUSED_ALLOWED_ORIGINS || 'http://localhost:8765,http://127.0.0.1:8765,http://localhost:8766,http://127.0.0.1:8766,http://localhost:8767,http://127.0.0.1:8767,http://localhost:8768,http://127.0.0.1:8768').split(',').map(value=>value.trim()).filter(Boolean));
const sessionsDays = 30;
const mimeExt = new Map([
  ['video/mp4','.mp4'], ['video/webm','.webm'], ['video/quicktime','.mov'],
  ['image/jpeg','.jpg'], ['image/png','.png'], ['image/webp','.webp']
]);
const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const emailCodePepper = process.env.AROUSED_EMAIL_CODE_SECRET || (() => {
  const stored=db.prepare('SELECT value FROM app_secrets WHERE name=?').get('email_code_pepper');
  if(stored)return stored.value;
  const value=randomBytes(32).toString('hex');db.prepare('INSERT INTO app_secrets(name,value) VALUES(?,?)').run('email_code_pepper',value);return value;
})();
const nowIso = () => new Date().toISOString();
const hashToken = token => createHash('sha256').update(token).digest('hex');
const slug = value => String(value || '').normalize('NFKD').replace(/[\u0300-\u036f]/g,'').toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,'');
const findCreator = value => {const decoded=safeDecode(value);if(decoded===null)return null;return db.prepare('SELECT * FROM users').all().find(row => slug(row.display_name) === slug(decoded) || slug(row.username) === slug(decoded)) || null};
for(const row of db.prepare(`SELECT s.* FROM stories s LEFT JOIN albums a ON a.story_id=s.id LEFT JOIN album_media m ON m.album_id=a.id WHERE m.id IS NULL AND s.media_path IS NOT NULL`).all()){
  const filename=basename(row.media_path);let size=0;try{size=(await storageProvider.getMetadata(filename)).size}catch{continue}
  const created=nowIso(),albumSlug=`${slug(row.title)||'album'}-${row.id}`;let album=db.prepare('SELECT id FROM albums WHERE story_id=?').get(row.id);
  if(!album){const inserted=db.prepare(`INSERT INTO albums(story_id,owner_id,slug,visibility,status,allow_comments,created_at,updated_at) VALUES(?,?,?,'public','published',1,?,?)`).run(row.id,row.creator_id,albumSlug,row.created_at||created,created);album={id:Number(inserted.lastInsertRowid)}}
  if(db.prepare('SELECT 1 FROM album_media WHERE album_id=? LIMIT 1').get(album.id))continue;
  const result=db.prepare(`INSERT INTO album_media(album_id,storage_name,original_name,mime_type,byte_size,position,state,created_at) VALUES(?,?,?,?,?,0,'ready',?)`).run(album.id,filename,row.media_name||filename,row.media_type||'application/octet-stream',size,created);
  db.prepare('UPDATE albums SET cover_media_id=? WHERE story_id=?').run(Number(result.lastInsertRowid),row.id);
  db.prepare('UPDATE stories SET cover_media_id=? WHERE id=?').run(Number(result.lastInsertRowid),row.id);
}
const json = (res, status, payload, headers={}) => { res.writeHead(status, { 'Content-Type':'application/json; charset=utf-8', 'Cache-Control':'no-store', ...headers }); res.end(JSON.stringify(payload)); };
const fail = (res, status, message) => json(res, status, { error: message });

function cors(req, res) {
  const origin = req.headers.origin;
  if (origin && allowedOrigins.has(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PATCH,DELETE,OPTIONS');
  }
}
function cookieValue(req, key) {
  return (req.headers.cookie || '').split(';').map(part => part.trim()).find(part => part.startsWith(key+'='))?.slice(key.length+1) || '';
}
function decodedCookie(req,key){try{return decodeURIComponent(cookieValue(req,key))}catch{return ''}}
function publicUser(row) {
  if(!row)return null;
  return {id:row.id,name:row.display_name,username:row.username||slug(row.display_name).replaceAll('-','_'),bio:row.bio||'',email:row.email,initial:row.avatar_initial,onlyfansUrl:row.onlyfans_url||'',avatarUrl:row.avatar_path?`/uploads/${basename(row.avatar_path)}?v=${encodeURIComponent(row.updated_at||row.created_at||'')}`:'',suspended:!!row.suspended,banned:!!row.banned};
}
function sessionUser(req) {
  const token = decodedCookie(req, 'aroused_session');
  if (!token) return null;
  const row = db.prepare(`SELECT u.id,u.display_name,u.username,u.bio,u.email,u.avatar_initial,u.onlyfans_url,u.avatar_path,u.created_at,u.updated_at,u.role,u.suspended,u.banned FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?`).get(hashToken(token), Date.now());
  return publicUser(row);
}
function requireUser(req, res) {
  const user = sessionUser(req);
  if (!user) { fail(res, 401, 'Sign in to use this feature.'); return null; }
  if(user.banned){fail(res,403,'This account is banned. You may submit an appeal.');return null;}
  if(user.suspended){fail(res,403,'This account is suspended. You can read notices in Messages, but account actions are unavailable.');return null;}
  return user;
}
function requireMessageUser(req,res){const user=sessionUser(req);if(!user){fail(res,401,'Sign in to use this feature.');return null;}return user;}
function requireAdmin(req,res){
  const user=requireUser(req,res);if(!user)return null;
  const row=db.prepare("SELECT role FROM users WHERE id=? AND suspended=0").get(user.id);
  if(row?.role!=='admin'){fail(res,403,'Administrator access is required.');return null;}
  return user;
}
function requireModerator(req,res,minimum='moderator'){
  const user=requireUser(req,res);if(!user)return null;
  const roles={user:0,moderator:1,senior_moderator:2,admin:3};
  const row=db.prepare('SELECT role FROM users WHERE id=? AND suspended=0 AND banned=0').get(user.id);
  if((roles[row?.role]??0)<(roles[minimum]??1)){fail(res,403,'Moderator access is required.');return null;}
  return user;
}
function setting(name){return db.prepare('SELECT value FROM site_settings WHERE name=?').get(name)?.value??'';}
function setSetting(name,value){db.prepare('INSERT INTO site_settings(name,value) VALUES(?,?) ON CONFLICT(name) DO UPDATE SET value=excluded.value').run(name,String(value));}
function auditAdmin(admin,action,targetType,targetId,details={}){
  db.prepare('INSERT INTO admin_audit_log(admin_user_id,action,target_type,target_id,details_json,created_at) VALUES(?,?,?,?,?,?)').run(admin.id,action,targetType,String(targetId),JSON.stringify(details),nowIso());
}
function adminNotice(admin,userId,body){if(!userId||Number(userId)===Number(admin.id))return;db.prepare('INSERT INTO messages(sender_id,recipient_id,body,created_at,is_system_notice) VALUES(?,?,?,?,1)').run(admin.id,userId,String(body).slice(0,2000),nowIso());}
function canUserUpload(userId){
  if(setting('uploads_enabled')==='false')return {eligible:false,reason:'UPLOADS_DISABLED',message:'Uploads are temporarily disabled by site staff.'};
  const row=db.prepare('SELECT email,email_verified_at,adult_confirmed,age_status,terms_accepted_at,guidelines_accepted_at,creator_agreement_version,upload_restricted,suspended,banned FROM users WHERE id=?').get(userId);
  if(!row||!row.email_verified_at)return {eligible:false,reason:'EMAIL_NOT_VERIFIED',message:'Verify your email before uploading.'};
  if(!row.adult_confirmed)return {eligible:false,reason:'AGE_CONFIRMATION_REQUIRED',message:'Confirm that you are 18 or older before uploading.'};
  if(row.age_status!=='verified')return {eligible:false,reason:'AGE_ASSURANCE_NOT_CONFIGURED',message:'Age assurance is not configured yet. Uploading remains disabled until it is available.'};
  if(!row.terms_accepted_at)return {eligible:false,reason:'TERMS_NOT_ACCEPTED',message:'Accept the Terms before uploading.'};
  if(!row.guidelines_accepted_at)return {eligible:false,reason:'GUIDELINES_NOT_ACCEPTED',message:'Accept the Content Guidelines before uploading.'};
  if(row.creator_agreement_version!==currentPolicyVersions.creatorAgreement)return {eligible:false,reason:'CREATOR_AGREEMENT_REQUIRED',message:'Accept the current Creator Agreement before uploading.'};
  if(row.banned)return {eligible:false,reason:'ACCOUNT_BANNED',message:'This account is banned from uploading.'};
  if(row.suspended)return {eligible:false,reason:'ACCOUNT_SUSPENDED',message:'This account is suspended from uploading.'};
  if(row.upload_restricted)return {eligible:false,reason:'UPLOAD_RESTRICTED',message:'Uploading is restricted on this account.'};
  return {eligible:true};
}
async function readBody(req, limit=maxUploadBytes) {
  const declaredLength=Number(req.headers['content-length']);
  if(Number.isSafeInteger(declaredLength)&&declaredLength>limit){req.resume();throw Object.assign(new Error('Request is too large.'),{status:413})}
  const chunks=[]; let size=0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > limit) throw Object.assign(new Error('Request is too large.'), { status: 413 });
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}
async function readJson(req, limit=128*1024) {
  const body=await readBody(req,limit);
  try { return body.length ? JSON.parse(body.toString('utf8')) : {}; }
  catch { throw Object.assign(new Error('Invalid JSON.'), {status:400}); }
}
function passwordDigest(password) {
  const salt=randomBytes(16);
  const key=scryptSync(password,salt,64);
  return `${salt.toString('hex')}:${key.toString('hex')}`;
}
function passwordMatches(password, digest) {
  try { const [saltHex,keyHex]=digest.split(':'); const expected=Buffer.from(keyHex,'hex'); const actual=scryptSync(password,Buffer.from(saltHex,'hex'),expected.length); return timingSafeEqual(actual,expected); }
  catch { return false; }
}
const dummyLoginDigest=passwordDigest(randomBytes(32).toString('hex'));
// Optional first-run bootstrap. It never creates a known default credential.
if(process.env.AROUSED_ADMIN_EMAIL&&process.env.AROUSED_ADMIN_PASSWORD){
  const adminEmail=String(process.env.AROUSED_ADMIN_EMAIL).trim().toLowerCase(),adminPassword=String(process.env.AROUSED_ADMIN_PASSWORD);
  if(!emailPattern.test(adminEmail)||adminPassword.length<14)throw new Error('Admin bootstrap requires a valid email and a password of at least 14 characters.');
  if(setting('admin_bootstrap_completed')!=='true'){
    if(!db.prepare("SELECT 1 FROM users WHERE role='admin'").get()){
      const existing=db.prepare('SELECT id FROM users WHERE email=?').get(adminEmail);
      if(existing)db.prepare("UPDATE users SET role='admin',updated_at=? WHERE id=?").run(new Date().toISOString(),existing.id);
      else {const name=adminEmail.split('@')[0].slice(0,40)||'Site Admin';const username=`admin_${randomBytes(4).toString('hex')}`;const at=new Date().toISOString();db.prepare("INSERT INTO users(display_name,username,email,password_hash,avatar_initial,adult_confirmed,email_verified_at,terms_accepted_at,guidelines_accepted_at,role,created_at) VALUES(?,?,?,?,?,1,?,?,?,'admin',?)").run(name,username,adminEmail,passwordDigest(adminPassword),name[0].toUpperCase(),at,at,at,at);}
    }
    setSetting('admin_bootstrap_completed','true');
  }
}
function emailCodeHash(email, code) {
  return createHmac('sha256', emailCodePepper).update(`${email}:${code}`).digest('hex');
}
async function sendVerificationEmail(email, code) {
  const apiKey = process.env.RESEND_API_KEY;
  const from = process.env.AROUSED_FROM_EMAIL;
  return sendResendEmail({
    apiKey, from, to: email, subject: 'Your Aroused verification code',
    text: `Your Aroused verification code is ${code}. It expires in 10 minutes. If you did not request this, you can ignore this email.`,
    html: `<div style="font-family:Arial,sans-serif;max-width:520px;margin:auto;color:#222"><h1 style="color:#e83f50">Verify your email</h1><p>Enter this code in Aroused to finish creating your account:</p><p style="font-size:32px;font-weight:bold;letter-spacing:8px">${code}</p><p>This code expires in 10 minutes. If you did not request it, you can ignore this email.</p></div>`
  });
}
async function sendExistingAccountSignInNotice(email) {
  const apiKey=process.env.RESEND_API_KEY,from=process.env.AROUSED_FROM_EMAIL;
  await sendResendEmail({apiKey,from,to:email,subject:'Aroused sign-in information',text:'A sign-up request was made with this address. If you already have an Aroused account, sign in or use the password reset option. If you did not make this request, you can ignore this email.',html:'<div style="font-family:Arial,sans-serif;max-width:520px;margin:auto;color:#222"><h1 style="color:#e83f50">Aroused sign-in information</h1><p>A sign-up request was made with this address. If you already have an Aroused account, sign in or use the password reset option.</p><p>If you did not make this request, you can ignore this email.</p></div>'});
}
function logEmailDeliveryFailure(route,error) {
  operationalLog('error','email_delivery_failed',{component:'resend',route,status:error?.status,errorCode:error?.code||safeErrorCode(error)});
}
async function sendPasswordResetEmail(email, token) {
  const apiKey=process.env.RESEND_API_KEY,from=process.env.AROUSED_FROM_EMAIL;
  await sendResendEmail({apiKey,from,to:email,subject:'Reset your Aroused password',text:`Your one-time password reset token is ${token}. It expires in 30 minutes. Enter it in the Reset your password form in Aroused. If you did not request this, ignore this email.`,html:`<div style="font-family:Arial,sans-serif;max-width:520px;margin:auto;color:#222"><h1 style="color:#e83f50">Reset your password</h1><p>Use this one-time token in the Aroused password reset form. It expires in 30 minutes.</p><p style="font-size:20px;font-weight:bold;word-break:break-all">${token}</p><p>If you did not request this, you can ignore this email.</p></div>`});
}
function createSession(userId, res, req=null) {
  const priorToken=req&&decodedCookie(req,'aroused_session');if(priorToken)db.prepare('DELETE FROM sessions WHERE token_hash=?').run(hashToken(priorToken));
  const token=randomBytes(32).toString('base64url');
  const expires=Date.now()+sessionsDays*86400000;
  db.prepare('INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)').run(hashToken(token),userId,expires);
  const secure=process.env.NODE_ENV==='production'?' Secure;':'';
  appendSetCookie(res,`aroused_session=${encodeURIComponent(token)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${sessionsDays*86400};${secure}`);
}
function appendSetCookie(res,value){const current=res.getHeader('Set-Cookie');res.setHeader('Set-Cookie',current?[...(Array.isArray(current)?current:[current]),value]:value)}
function clearSessionCookie(res){const secure=process.env.NODE_ENV==='production'?' Secure;':'';appendSetCookie(res,`aroused_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0;${secure}`)}
function storyObject(row, user=null) {
  if (!row) return null;
  const tags=JSON.parse(row.tags_json || '[]');
  const ageMs=Math.max(0,Date.now()-Date.parse(row.created_at));
  const age=ageMs<86400000?`${Math.max(1,Math.floor(ageMs/3600000))} hours ago`:`${Math.floor(ageMs/86400000)} days ago`;
  const likes=Number(db.prepare('SELECT COUNT(*) AS n FROM likes WHERE story_id=?').get(row.id).n);
  const followers=Number(db.prepare('SELECT COUNT(*) AS n FROM follows WHERE creator_id=?').get(row.creator_id).n);
  return {
    id:row.id, title:row.title, creator:row.creator, creatorId:row.creator_id,
    creatorSlug:slug(row.creator), initial:row.avatar_initial, creatorAvatarUrl:row.avatar_path?`/uploads/${basename(row.avatar_path)}`:'', creatorOnlyfansUrl:row.onlyfans_url||'', category:row.category,
    tags, views:Number(row.views), viewsLabel:formatCount(row.views), likes:likes+Number(row.seeded_likes),
    liked:!!user && !!db.prepare('SELECT 1 FROM likes WHERE user_id=? AND story_id=?').get(user.id,row.id),
    saved:!!user && !!db.prepare('SELECT 1 FROM saves WHERE user_id=? AND story_id=?').get(user.id,row.id),
    reposted:!!user && !!db.prepare('SELECT 1 FROM reposts WHERE user_id=? AND story_id=?').get(user.id,row.id),
    following:!!user && !!db.prepare('SELECT 1 FROM follows WHERE follower_id=? AND creator_id=?').get(user.id,row.creator_id),
    followers, age, createdAt:row.created_at, tone:[row.tone_a,row.tone_b], count:row.duration,
    video:row.cover_media_id&&String(row.cover_mime||'').startsWith('video/')?`/media/${row.cover_media_id}${row.album_visibility==='unlisted'?`?album=${encodeURIComponent(row.album_slug)}`:''}`:(row.media_path&&!row.cover_media_id?`/uploads/${basename(row.media_path)}`:''), image:row.cover_media_id&&String(row.cover_mime||'').startsWith('image/')?`/media/${row.cover_media_id}${row.album_visibility==='unlisted'?`?album=${encodeURIComponent(row.album_slug)}`:''}`:'', mediaType:row.cover_mime||row.media_type||'', mediaName:row.cover_name||row.media_name||'', albumSlug:row.album_slug||'', visibility:row.album_visibility||'public'
  };
}
function formatCount(n) { const value=Number(n)||0; return value>=1000000?`${(value/1e6).toFixed(1)}m`:value>=1000?`${(value/1000).toFixed(1)}k`:String(value); }
function storyRows(where='',params=[]) {
  return db.prepare(`SELECT s.*,u.display_name AS creator,u.avatar_initial,u.avatar_path,u.onlyfans_url,a.id AS album_id,a.slug AS album_slug,a.visibility AS album_visibility,a.status AS album_status,m.mime_type AS cover_mime,m.original_name AS cover_name FROM stories s JOIN users u ON u.id=s.creator_id JOIN albums a ON a.story_id=s.id LEFT JOIN album_media m ON m.id=COALESCE(a.cover_media_id,s.cover_media_id) WHERE s.status='published' AND a.status='published' AND a.visibility='public' AND EXISTS(SELECT 1 FROM album_media am WHERE am.album_id=a.id) AND NOT EXISTS(SELECT 1 FROM album_media am LEFT JOIN media_pipeline mp ON mp.media_id=am.id WHERE am.album_id=a.id AND (mp.media_id IS NULL OR mp.status<>'READY' OR mp.malware_status<>'CLEAN' OR mp.processing_status<>'READY' OR mp.known_content_status<>'CLEAR' OR mp.safety_status<>'CLEAR' OR mp.moderation_status<>'APPROVED')) ${where} ORDER BY s.created_at DESC,s.id DESC`).all(...params).filter(row=>canPublishAlbum(albumRecordById(row.album_id)));
}
function postAllowed(req, res) {
  const origin=req.headers.origin;
  if (origin && !allowedOrigins.has(origin)) { fail(res,403,'Request origin is not allowed.'); return false; }
  const fetchSite=String(req.headers['sec-fetch-site']||'').toLowerCase();
  if(fetchSite==='cross-site'||(!origin&&fetchSite!=='same-origin')||(origin&&!allowedOrigins.has(origin))){fail(res,403,'This request failed the same-origin security check.');return false;}
  return true;
}
let lastRateLimitPrune=0;
function rateLimit(req,res,scope,{limit=10,windowMs=15*60*1000,identity=''}={}){
  const now=Date.now(),ip=String(req.socket?.remoteAddress||'unknown');
  if(now-lastRateLimitPrune>60_000){db.prepare('DELETE FROM rate_limit_buckets WHERE reset_at<=?').run(now);lastRateLimitPrune=now;}
  const key=createHmac('sha256',emailCodePepper).update(`${scope}:${ip}:${identity}`).digest('hex');
  const prior=db.prepare('SELECT hits,reset_at FROM rate_limit_buckets WHERE bucket_key=?').get(key);
  const next=prior&&Number(prior.reset_at)>now?{hits:Number(prior.hits)+1,resetAt:Number(prior.reset_at)}:{hits:1,resetAt:now+windowMs};
  db.prepare('INSERT INTO rate_limit_buckets(bucket_key,hits,reset_at) VALUES(?,?,?) ON CONFLICT(bucket_key) DO UPDATE SET hits=excluded.hits,reset_at=excluded.reset_at').run(key,next.hits,next.resetAt);
  if(next.hits>limit){const retry=Math.max(1,Math.ceil((next.resetAt-now)/1000));res.setHeader('Retry-After',String(retry));fail(res,429,'Too many requests. Please wait and try again.');return false;}
  return true;
}
function securityEvent(userId,eventType,severity='info',detailCode=eventType){db.prepare('INSERT INTO security_events(user_id,event_type,severity,detail_code,created_at) VALUES(?,?,?,?,?)').run(userId||null,eventType,severity,detailCode,nowIso());}
function recordReport({reporterId,storyId=null,targetUserId=null,input}){
  const categories=['suspected_minor','non_consensual','copyright','privacy','harassment','other'];
  const requested=String(input.category||input.reason||'other').toLowerCase().replace(/[\s-]+/g,'_');
  const category=categories.includes(requested)?requested:'other';
  const reason=String(input.reason||category).slice(0,100),details=String(input.details||'').trim().slice(0,2000),created=nowIso();
  const priority=category==='suspected_minor'?'critical':['non_consensual','copyright'].includes(category)?'high':'normal';
  const album=storyId?db.prepare('SELECT id,story_id FROM albums WHERE story_id=?').get(storyId):null;
  const media=album?db.prepare('SELECT id FROM album_media WHERE album_id=? ORDER BY position LIMIT 1').get(album.id):null;
  db.exec('BEGIN IMMEDIATE');
  try{
    const result=db.prepare('INSERT INTO reports(reporter_id,story_id,target_user_id,reason,details,status,created_at,category,priority,updated_at) VALUES(?,?,?,?,?,\'open\',?,?,?,?)').run(reporterId,storyId,targetUserId,reason,details,created,category,priority,created);
    const reportId=Number(result.lastInsertRowid);
    db.prepare(`INSERT INTO moderation_cases(report_id,album_id,media_id,category,priority,status,restricted,created_at,updated_at) VALUES(?,?,?,?,?,'open',?,?,?)`).run(reportId,album?.id||null,media?.id||null,category,priority,category==='suspected_minor'||category==='non_consensual'?1:0,created,created);
    if(album&&['suspected_minor','non_consensual'].includes(category)){
      db.prepare("UPDATE media_pipeline SET status='QUARANTINED',moderation_status='PENDING',updated_at=? WHERE media_id IN (SELECT id FROM album_media WHERE album_id=?)").run(created,album.id);
      db.prepare("UPDATE albums SET status='processing',updated_at=? WHERE id=?").run(created,album.id);
      db.prepare("UPDATE stories SET status='draft' WHERE id=?").run(album.story_id);
    }
    if(priority==='critical')securityEvent(reporterId,'critical_safety_report','critical','SUSPECTED_MINOR_REPORT');
    db.exec('COMMIT');
    return reportId;
  }catch(error){try{db.exec('ROLLBACK')}catch{}throw error}
}
function setToggle(table, fromColumn, fromId, toColumn, toId) {
  const found=db.prepare(`SELECT 1 FROM ${table} WHERE ${fromColumn}=? AND ${toColumn}=?`).get(fromId,toId);
  if (found) db.prepare(`DELETE FROM ${table} WHERE ${fromColumn}=? AND ${toColumn}=?`).run(fromId,toId);
  else db.prepare(`INSERT INTO ${table}(${fromColumn},${toColumn}${['saves','reposts'].includes(table)?',created_at':''}) VALUES(?,?${['saves','reposts'].includes(table)?',?':''})`).run(...(['saves','reposts'].includes(table)?[fromId,toId,nowIso()]:[fromId,toId]));
  return !found;
}
function lookupStory(id,user=null,unlistedSlug='') {
  const row=db.prepare(`SELECT s.*,u.display_name AS creator,u.avatar_initial,u.avatar_path,u.onlyfans_url,a.id AS album_id,a.slug AS album_slug,a.visibility AS album_visibility,a.status AS album_status,m.mime_type AS cover_mime,m.original_name AS cover_name FROM stories s JOIN users u ON u.id=s.creator_id JOIN albums a ON a.story_id=s.id LEFT JOIN album_media m ON m.id=COALESCE(a.cover_media_id,s.cover_media_id) WHERE s.id=? AND s.status='published' AND a.status='published'`).get(Number(id));
  if(!row)return null;
  const album=albumRecordById(row.album_id),owner=Number(row.creator_id)===Number(user?.id);
  const media=db.prepare('SELECT id FROM album_media WHERE album_id=?').all(row.album_id);
  if(!media.length||media.some(item=>['QUARANTINED','REJECTED'].includes(db.prepare('SELECT status FROM media_pipeline WHERE media_id=?').get(item.id)?.status)))return null;
  if(!owner&&!canPublishAlbum(album))return null;
  if(row.album_visibility==='private'&&!owner)return null;
  if(row.album_visibility==='unlisted'&&!owner&&unlistedSlug!==row.album_slug)return null;
  if(row.album_visibility==='public'&&owner===false&&!canPublishAlbum(album))return null;
  return row;
}
function safeDecode(value){try{return decodeURIComponent(value)}catch{return null}}
function albumRecordById(id){return db.prepare(`SELECT a.*,s.title,s.category,s.tags_json,s.views,s.seeded_likes,s.duration,s.tone_a,s.tone_b,s.status AS story_status,u.display_name AS creator,u.username,u.avatar_initial,u.avatar_path FROM albums a JOIN stories s ON s.id=a.story_id JOIN users u ON u.id=a.owner_id WHERE a.id=?`).get(Number(id));}
function albumRecordBySlug(value){return db.prepare(`SELECT a.*,s.title,s.category,s.tags_json,s.views,s.seeded_likes,s.duration,s.tone_a,s.tone_b,s.status AS story_status,u.display_name AS creator,u.username,u.avatar_initial,u.avatar_path FROM albums a JOIN stories s ON s.id=a.story_id JOIN users u ON u.id=a.owner_id WHERE a.slug=?`).get(String(value));}
function albumMedia(album){return db.prepare('SELECT id,original_name,mime_type,byte_size,position,state,created_at FROM album_media WHERE album_id=? ORDER BY position,id').all(album.id).map(item=>({id:item.id,name:item.original_name,type:item.mime_type,size:item.byte_size,position:item.position,state:item.state,url:`/media/${item.id}${album.visibility==='unlisted'?`?album=${encodeURIComponent(album.slug)}`:''}`}));}
function registerMediaPipeline(mediaId,buffer,createdAt){
  const digest=createHash('sha256').update(buffer).digest('hex');
  db.prepare('INSERT OR REPLACE INTO media_fingerprints(media_id,sha256,byte_size,created_at) VALUES(?,?,?,?)').run(mediaId,digest,buffer.length,createdAt);
  db.prepare(`INSERT OR REPLACE INTO media_pipeline(media_id,status,malware_status,processing_status,known_content_status,safety_status,moderation_status,updated_at)
    VALUES(?,'SCAN_PENDING','NOT_CONFIGURED','NOT_CONFIGURED','NOT_CONFIGURED','NOT_CONFIGURED','PENDING',?)`).run(mediaId,createdAt);
  enqueueMediaJob(db,Number(mediaId),{now:Date.parse(createdAt)||Date.now(),status:'blocked',errorCode:'SCANNERS_NOT_CONFIGURED'});
}
function mediaPipelineReady(mediaId){return !!db.prepare(`SELECT 1 FROM media_pipeline WHERE media_id=? AND status='READY' AND malware_status='CLEAN' AND processing_status='READY' AND known_content_status='CLEAR' AND safety_status='CLEAR' AND moderation_status='APPROVED'`).get(mediaId);}
function canPublishAlbum(album){
  if(!album||!['public','unlisted'].includes(album.visibility)||album.review_status&&album.review_status!=='not_required')return false;
  if(!canUserUpload(Number(album.owner_id)).eligible)return false;
  const media=db.prepare('SELECT id,state FROM album_media WHERE album_id=?').all(album.id);
  if(!media.length||media.some(item=>item.state!=='ready'||!mediaPipelineReady(item.id)))return false;
  const declarations=db.prepare('SELECT declaration_key,policy_version FROM creator_declarations WHERE album_id=? AND user_id=?').all(album.id,album.owner_id);
  return ['rights','consent'].every(key=>declarations.some(item=>item.declaration_key===key&&item.policy_version===currentPolicyVersions.rights));
}
function albumMediaAccessible(item,user,{unlistedSlug=''}={}){
  if(!item||item.status==='removed'||item.story_status==='removed')return false;
  const owner=Number(item.owner_id)===Number(user?.id);
  const pipeline=db.prepare('SELECT status FROM media_pipeline WHERE media_id=?').get(item.id);
  if(['QUARANTINED','REJECTED'].includes(pipeline?.status))return false;
  if(owner)return true;
  if(item.status!=='published'||item.story_status!=='published'||!mediaPipelineReady(item.id))return false;
  if(item.visibility==='public')return canPublishAlbum(albumRecordById(item.album_id));
  if(item.visibility==='unlisted'&&unlistedSlug===item.slug)return canPublishAlbum(albumRecordById(item.album_id));
  return false;
}
function albumObject(album,user=null){
  const story=db.prepare(`SELECT s.*,u.display_name AS creator,u.avatar_initial,u.avatar_path,u.onlyfans_url,a.slug AS album_slug,a.visibility AS album_visibility,m.mime_type AS cover_mime,m.original_name AS cover_name FROM stories s JOIN users u ON u.id=s.creator_id LEFT JOIN albums a ON a.story_id=s.id LEFT JOIN album_media m ON m.id=COALESCE(a.cover_media_id,s.cover_media_id) WHERE s.id=?`).get(album.story_id);
  return {id:album.id,storyId:album.story_id,slug:album.slug,title:album.title,description:album.description,category:album.category,tags:JSON.parse(album.tags_json||'[]'),visibility:album.visibility,status:album.status,publishMode:album.publish_mode||'immediate',scheduledAt:album.scheduled_at||null,reviewStatus:album.review_status||'not_required',allowComments:!!album.allow_comments,coverMediaId:album.cover_media_id,creator:album.creator,username:album.username||slug(album.creator).replaceAll('-','_'),initial:album.avatar_initial,avatarUrl:album.avatar_path?`/uploads/${basename(album.avatar_path)}`:'',createdAt:album.created_at,updatedAt:album.updated_at,media:albumMedia(album),story:story?storyObject(story,user):null};
}
function publishDueAlbums(){
  const timestamp=nowIso(),due=db.prepare(`SELECT id FROM albums WHERE status='draft' AND publish_mode='schedule' AND review_status='not_required' AND scheduled_at IS NOT NULL AND scheduled_at<=?`).all(timestamp);
  for(const candidate of due){
    db.exec('BEGIN IMMEDIATE');try{
      const album=albumRecordById(candidate.id);
      if(!canPublishAlbum(album)){db.exec('COMMIT');continue;}
      const updateAlbum=db.prepare("UPDATE albums SET status='published',publish_mode='immediate',scheduled_at=NULL,updated_at=? WHERE id=? AND status='draft' AND publish_mode='schedule'").run(timestamp,album.id);
      const updateStory=db.prepare("UPDATE stories SET status='published' WHERE id=? AND status='draft'").run(album.story_id);
      if(updateAlbum.changes!==1||updateStory.changes!==1)throw new Error('Scheduled publication state changed unexpectedly.');
      db.exec('COMMIT');
    }catch(error){db.exec('ROLLBACK');throw error}
  }
}
function mediaBytesMatch(mime,buffer){
  if(mime==='image/jpeg')return buffer.length>3&&buffer[0]===0xff&&buffer[1]===0xd8&&buffer[2]===0xff;
  if(mime==='image/png')return buffer.length>8&&buffer.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10]));
  if(mime==='image/webp')return buffer.length>12&&buffer.toString('ascii',0,4)==='RIFF'&&buffer.toString('ascii',8,12)==='WEBP';
  if(mime==='video/mp4'||mime==='video/quicktime')return buffer.length>12&&buffer.toString('ascii',4,8)==='ftyp';
  if(mime==='video/webm')return buffer.length>4&&buffer.subarray(0,4).equals(Buffer.from([0x1a,0x45,0xdf,0xa3]));
  return false;
}
function respondStory(res, id, user, unlistedSlug='') {
  const row=lookupStory(id,user,unlistedSlug);
  if (!row) return fail(res,404,'Video not found.');
  return json(res,200,{story:storyObject(row,user)});
}
function csvList(value) { return String(value||'').split(',').map(item=>item.trim().replace(/^#+/,'').replace(/\s+/g,'').toLowerCase()).filter(Boolean).slice(0,12); }

async function handleApi(req,res,url) {
  const method=req.method, path=url.pathname.replace(/\/+$/,'')||'/';
  if (method==='OPTIONS') { res.writeHead(204); return res.end(); }
  if (method!=='GET' && !postAllowed(req,res)) return;

  if (method==='GET' && path==='/health/live') return json(res,200,{ok:true});
  if (method==='GET' && path==='/health/ready') {
    let databaseReady=false,storageReady=false;
    try { databaseReady=Number(db.prepare('SELECT 1 AS ok').get().ok)===1; } catch {}
    try { storageReady=(await storageProvider.healthCheck()).available===true; } catch {}
    const ready=databaseReady&&storageReady;
    return json(res,ready?200:503,{ok:ready,database:databaseReady?'available':'unavailable',storage:storageReady?'available':'unavailable',readyForProduction:providerStatus().readyForProduction});
  }
  if (method==='GET' && path==='/health') {const readiness=providerStatus();return json(res,200,{ok:true,storage:process.env.AROUSED_STORAGE_DRIVER==='s3'?'s3':'sqlite-local',maxUploadBytes,readiness:readiness.status,readyForProduction:readiness.readyForProduction,providers:readiness.providers});}
  if (method==='GET' && path==='/session') return json(res,200,{user:sessionUser(req)});
  if(path.startsWith('/admin/')){
    const admin=requireAdmin(req,res);if(!admin)return;
    if(method==='GET'&&path==='/admin/overview'){
      return json(res,200,{admin:{id:admin.id,name:admin.name,email:admin.email},stats:{users:Number(db.prepare('SELECT COUNT(*) n FROM users').get().n),activeUsers:Number(db.prepare('SELECT COUNT(*) n FROM users WHERE suspended=0').get().n),posts:Number(db.prepare("SELECT COUNT(*) n FROM stories WHERE status<>'removed'").get().n),pendingReports:Number(db.prepare("SELECT COUNT(*) n FROM reports WHERE status IN ('open','reviewing')").get().n),uploads:Number(db.prepare("SELECT COUNT(*) n FROM albums WHERE status='published'").get().n)},settings:{signupsEnabled:setting('signups_enabled')!=='false',uploadsEnabled:setting('uploads_enabled')!=='false'}});
    }
    if(method==='GET'&&path==='/admin/health'){
      const backlog=db.prepare("SELECT COUNT(*) n FROM album_media m LEFT JOIN media_pipeline p ON p.media_id=m.id WHERE p.media_id IS NULL OR p.status NOT IN ('READY','REJECTED')").get().n;
      const failedProcessing=db.prepare("SELECT COUNT(*) n FROM media_pipeline WHERE status='ERROR' OR processing_status='FAILED'").get().n;
      const pendingCases=db.prepare("SELECT COUNT(*) n FROM moderation_cases WHERE status IN ('open','reviewing')").get().n;
      const criticalCases=db.prepare("SELECT COUNT(*) n FROM moderation_cases WHERE restricted=1 AND status IN ('open','reviewing')").get().n;
      const readiness=providerStatus();
      return json(res,200,{readiness,queues:{mediaPending:Number(backlog),processingFailed:Number(failedProcessing),moderationOpen:Number(pendingCases),restrictedPriority:Number(criticalCases)},security:{events24h:Number(db.prepare("SELECT COUNT(*) n FROM security_events WHERE created_at>=?").get(new Date(Date.now()-86400000).toISOString()).n)}});
    }
    if(method==='GET'&&path==='/admin/appeals'){
      const items=db.prepare(`SELECT a.id,a.user_id,a.reason,a.status,a.created_at,a.updated_at,a.decision_reason,u.username,u.display_name,e.action,e.reason AS enforcement_reason FROM appeals a JOIN users u ON u.id=a.user_id LEFT JOIN enforcement_actions e ON e.id=a.enforcement_id ORDER BY CASE a.status WHEN 'open' THEN 0 WHEN 'reviewing' THEN 1 ELSE 2 END,a.created_at`).all();return json(res,200,{items});
    }
    const appealAdminRoute=path.match(/^\/admin\/appeals\/(\d+)$/);
    if(appealAdminRoute&&method==='PATCH'){
      const input=await readJson(req),status=String(input.status||''),reason=String(input.reason||'').trim().slice(0,2000);if(!['open','reviewing','granted','denied'].includes(status))return fail(res,400,'Choose open, reviewing, granted, or denied.');const appeal=db.prepare('SELECT a.*,u.id AS target_id FROM appeals a JOIN users u ON u.id=a.user_id WHERE a.id=?').get(Number(appealAdminRoute[1]));if(!appeal)return fail(res,404,'Appeal not found.');const now=nowIso();db.prepare('UPDATE appeals SET status=?,decision_reason=?,updated_at=?,assigned_to=? WHERE id=?').run(status,reason,now,admin.id,appeal.id);if(status==='granted'&&appeal.enforcement_id){db.prepare('UPDATE enforcement_actions SET revoked_at=? WHERE id=?').run(now,appeal.enforcement_id);const enforcement=db.prepare('SELECT action FROM enforcement_actions WHERE id=?').get(appeal.enforcement_id);if(enforcement?.action==='ban')db.prepare('UPDATE users SET banned=0,updated_at=? WHERE id=?').run(now,appeal.user_id);if(enforcement?.action==='suspend')db.prepare('UPDATE users SET suspended=0,updated_at=? WHERE id=?').run(now,appeal.user_id);if(enforcement?.action==='restrict_uploads')db.prepare('UPDATE users SET upload_restricted=0,updated_at=? WHERE id=?').run(now,appeal.user_id)}if(['granted','denied'].includes(status))adminNotice(admin,appeal.user_id,`Your account appeal was ${status}.${reason?` Staff note: ${reason}`:''}`);auditAdmin(admin,`appeal_${status}`,'appeal',appeal.id,{reason});return json(res,200,{ok:true});
    }
    if(method==='GET'&&path==='/admin/users'){
      const items=db.prepare(`SELECT u.id,u.display_name,u.username,u.email,u.role,u.suspended,u.banned,u.upload_restricted,u.created_at,COUNT(DISTINCT s.id) AS posts FROM users u LEFT JOIN stories s ON s.creator_id=u.id AND s.status<>'removed' GROUP BY u.id ORDER BY u.created_at DESC`).all();return json(res,200,{items});
    }
    const adminUserRoute=path.match(/^\/admin\/users\/(\d+)$/);
    if(adminUserRoute&&method==='PATCH'){
      const id=Number(adminUserRoute[1]);if(!Number.isSafeInteger(id)||id===Number(admin.id))return fail(res,400,'You cannot change your own admin account here.');const target=db.prepare('SELECT id,role FROM users WHERE id=?').get(id);if(!target)return fail(res,404,'User not found.');const input=await readJson(req),now=nowIso();
      if(input.suspended!==undefined){const value=input.suspended===true?1:input.suspended===false?0:null;if(value===null)return fail(res,400,'suspended must be true or false.');db.prepare('UPDATE users SET suspended=?,updated_at=? WHERE id=?').run(value,now,id);if(value)db.prepare(`INSERT INTO enforcement_actions(user_id,admin_user_id,action,reason,created_at) VALUES(?,?, 'suspend',?,?)`).run(id,admin.id,String(input.reason||'Account suspended by site staff').slice(0,1000),now);else db.prepare("UPDATE enforcement_actions SET revoked_at=? WHERE user_id=? AND action='suspend' AND revoked_at IS NULL").run(now,id);adminNotice(admin,id,value?'Your account has been suspended by site staff. You can still view this notice in Messages. Contact Support if you believe this is a mistake.':'The suspension on your account has been lifted. You can use your account again.');auditAdmin(admin,value?'suspend_user':'restore_user','user',id);}
      if(input.uploadRestricted!==undefined){const value=input.uploadRestricted===true?1:input.uploadRestricted===false?0:null;if(value===null)return fail(res,400,'uploadRestricted must be true or false.');db.prepare('UPDATE users SET upload_restricted=?,updated_at=? WHERE id=?').run(value,now,id);if(value)db.prepare(`INSERT INTO enforcement_actions(user_id,admin_user_id,action,reason,created_at) VALUES(?,?, 'restrict_uploads',?,?)`).run(id,admin.id,String(input.reason||'Uploads restricted by site staff').slice(0,1000),now);else db.prepare("UPDATE enforcement_actions SET revoked_at=? WHERE user_id=? AND action='restrict_uploads' AND revoked_at IS NULL").run(now,id);adminNotice(admin,id,value?'Uploads have been restricted on your account by site staff. Your existing posts are unchanged. Contact Support if you believe this is a mistake.':'The upload restriction on your account has been removed. You can upload again.');auditAdmin(admin,value?'restrict_uploads':'allow_uploads','user',id);}
      if(input.banned!==undefined){const value=input.banned===true?1:input.banned===false?0:null;if(value===null)return fail(res,400,'banned must be true or false.');db.prepare('UPDATE users SET banned=?,updated_at=? WHERE id=?').run(value,now,id);if(value)db.prepare(`INSERT INTO enforcement_actions(user_id,admin_user_id,action,reason,created_at) VALUES(?,?, 'ban',?,?)`).run(id,admin.id,String(input.reason||'Account banned by site staff').slice(0,1000),now);else db.prepare("UPDATE enforcement_actions SET revoked_at=? WHERE user_id=? AND action='ban' AND revoked_at IS NULL").run(now,id);adminNotice(admin,id,value?'Your account has been banned by site staff. You may submit an appeal through the account appeal page.':'Your account ban has been lifted.');auditAdmin(admin,value?'ban_user':'unban_user','user',id);}
      if(input.role!==undefined){if(!['user','moderator','senior_moderator','admin'].includes(input.role))return fail(res,400,'Choose a supported account role.');db.prepare('UPDATE users SET role=?,updated_at=? WHERE id=?').run(input.role,now,id);auditAdmin(admin,'change_user_role','user',id,{role:input.role});}
      return json(res,200,{ok:true});
    }
    if(method==='GET'&&path==='/admin/posts'){
      const items=db.prepare(`SELECT s.id,s.title,s.status,s.created_at,s.views,u.display_name AS creator,u.username,a.slug AS album_slug,a.status AS album_status,a.visibility,COALESCE(a.allow_comments,1) AS comments_enabled,(SELECT COUNT(*) FROM comments c WHERE c.story_id=s.id) AS comment_count,(SELECT COUNT(*) FROM album_media m WHERE m.album_id=a.id) AS media_count FROM stories s JOIN users u ON u.id=s.creator_id LEFT JOIN albums a ON a.story_id=s.id ORDER BY s.created_at DESC`).all();return json(res,200,{items});
    }
    const adminPostCommentsRoute=path.match(/^\/admin\/posts\/(\d+)\/comments$/);
    if(adminPostCommentsRoute&&method==='GET'){
      const post=db.prepare(`SELECT s.id,s.title,s.status,u.username AS creator,COALESCE(a.allow_comments,1) AS comments_enabled FROM stories s JOIN users u ON u.id=s.creator_id LEFT JOIN albums a ON a.story_id=s.id WHERE s.id=?`).get(Number(adminPostCommentsRoute[1]));if(!post)return fail(res,404,'Post not found.');if(!post.comments_enabled)return fail(res,403,'Comments are disabled for this post.');const items=db.prepare(`SELECT c.id,c.body,c.created_at,u.id AS author_id,u.display_name AS author,u.username FROM comments c JOIN users u ON u.id=c.user_id WHERE c.story_id=? ORDER BY c.created_at DESC`).all(post.id);return json(res,200,{post,items});
    }
    const adminPostRoute=path.match(/^\/admin\/posts\/(\d+)$/);
    if(adminPostRoute&&method==='PATCH'){
      const id=Number(adminPostRoute[1]),input=await readJson(req),status=String(input.status||'');if(!['published','removed'].includes(status))return fail(res,400,'Post status must be published or removed.');const row=db.prepare('SELECT s.id,s.title,s.creator_id FROM stories s WHERE s.id=?').get(id);if(!row)return fail(res,404,'Post not found.');const album=db.prepare('SELECT id FROM albums WHERE story_id=?').get(id);if(status==='published'&&(!album||!canPublishAlbum(albumRecordById(album.id))))return fail(res,409,'Post restoration is blocked until every required provider, policy, and moderation gate has passed.');const now=nowIso();db.exec('BEGIN IMMEDIATE');try{if(status==='published'&&(!canPublishAlbum(albumRecordById(album.id))))throw Object.assign(new Error('Post restoration is blocked until every required provider, policy, and moderation gate has passed.'),{status:409});db.prepare('UPDATE stories SET status=? WHERE id=?').run(status,id);db.prepare('UPDATE albums SET status=?,updated_at=? WHERE story_id=?').run(status,now,id);db.exec('COMMIT')}catch(error){db.exec('ROLLBACK');if(error.status===409)return fail(res,409,error.message);throw error}adminNotice(admin,row.creator_id,status==='removed'?`Your post “${row.title}” was removed by site staff. Contact Support if you believe this is a mistake.`:`Your post “${row.title}” was restored by site staff.`);auditAdmin(admin,status==='removed'?'remove_post':'restore_post','post',id,{title:row.title});return json(res,200,{ok:true});
    }
    const adminCommentRoute=path.match(/^\/admin\/comments\/(\d+)$/);
    if(adminCommentRoute&&method==='DELETE'){
      const id=Number(adminCommentRoute[1]),row=db.prepare(`SELECT c.id,c.body,c.user_id,s.title FROM comments c JOIN stories s ON s.id=c.story_id WHERE c.id=?`).get(id);if(!row)return fail(res,404,'Comment not found.');db.prepare('DELETE FROM comments WHERE id=?').run(id);adminNotice(admin,row.user_id,`Your comment on “${row.title}” was removed by site staff for violating the community rules. Contact Support if you believe this is a mistake.`);auditAdmin(admin,'remove_comment','comment',id,{storyTitle:row.title});return json(res,200,{ok:true});
    }
    if(method==='GET'&&path==='/admin/reports'){
      const items=db.prepare(`SELECT r.id,r.reason,r.details,r.status,r.created_at,reporter.username AS reporter,target.username AS reported_user,s.id AS story_id,s.title AS story_title FROM reports r LEFT JOIN users reporter ON reporter.id=r.reporter_id LEFT JOIN users target ON target.id=r.target_user_id LEFT JOIN stories s ON s.id=r.story_id ORDER BY CASE r.status WHEN 'open' THEN 0 WHEN 'reviewing' THEN 1 ELSE 2 END,r.created_at DESC`).all();return json(res,200,{items});
    }
    const adminReportRoute=path.match(/^\/admin\/reports\/(\d+)$/);
    if(adminReportRoute&&method==='PATCH'){
      const id=Number(adminReportRoute[1]),input=await readJson(req),status=String(input.status||'');if(!['open','reviewing','resolved','dismissed'].includes(status))return fail(res,400,'Choose a valid report status.');const report=db.prepare('SELECT reporter_id FROM reports WHERE id=?').get(id);if(!report)return fail(res,404,'Report not found.');db.prepare('UPDATE reports SET status=? WHERE id=?').run(status,id);if(['resolved','dismissed'].includes(status))adminNotice(admin,report.reporter_id,`Your report has been ${status}. Thank you for helping keep the community safe.`);auditAdmin(admin,`report_${status}`,'report',id);return json(res,200,{ok:true});
    }
    if(method==='PATCH'&&path==='/admin/settings'){
      const input=await readJson(req);for(const [key,name] of [['signupsEnabled','signups_enabled'],['uploadsEnabled','uploads_enabled']])if(input[key]!==undefined){if(typeof input[key]!=='boolean')return fail(res,400,`${key} must be true or false.`);setSetting(name,input[key]);auditAdmin(admin,`set_${name}`,'setting',name,{value:input[key]});}return json(res,200,{ok:true,settings:{signupsEnabled:setting('signups_enabled')!=='false',uploadsEnabled:setting('uploads_enabled')!=='false'}});
    }
    if(method==='GET'&&path==='/admin/audit')return json(res,200,{items:db.prepare(`SELECT l.id,l.action,l.target_type,l.target_id,l.details_json,l.created_at,u.username AS admin FROM admin_audit_log l LEFT JOIN users u ON u.id=l.admin_user_id ORDER BY l.created_at DESC,l.id DESC`).all()});
    return fail(res,404,'Admin endpoint not found.');
  }
  if(method==='GET'&&path==='/moderation/cases'){
    const moderator=requireModerator(req,res,'moderator');if(!moderator)return;const role=db.prepare('SELECT role FROM users WHERE id=?').get(moderator.id)?.role;const canSeeRestricted=['senior_moderator','admin'].includes(role);const items=db.prepare(`SELECT c.id,c.report_id,c.category,c.priority,c.status,c.restricted,c.assigned_to,c.created_at,c.updated_at FROM moderation_cases c WHERE c.status IN ('open','reviewing') AND (c.restricted=0 OR ?=1) ORDER BY CASE c.priority WHEN 'critical' THEN 0 WHEN 'high' THEN 1 ELSE 2 END,c.created_at`).all(canSeeRestricted?1:0);return json(res,200,{items});
  }
  const moderationCaseRoute=path.match(/^\/moderation\/cases\/(\d+)$/);
  if(moderationCaseRoute&&method==='PATCH'){
    const moderator=requireModerator(req,res,'senior_moderator');if(!moderator)return;const input=await readJson(req),status=String(input.status||'');if(!['reviewing','resolved','dismissed','quarantined'].includes(status))return fail(res,400,'Choose a supported case status.');const item=db.prepare('SELECT id,report_id,album_id,media_id,category,priority FROM moderation_cases WHERE id=?').get(Number(moderationCaseRoute[1]));if(!item)return fail(res,404,'Case not found.');const decisionReason=String(input.reason||'').trim().slice(0,2000),updated=nowIso(),caseStatus=status==='quarantined'?'reviewing':status;db.prepare('UPDATE moderation_cases SET status=?,assigned_to=?,decision=?,decision_reason=?,updated_at=?,resolved_at=? WHERE id=?').run(caseStatus,moderator.id,status,decisionReason,updated,['resolved','dismissed'].includes(status)?updated:null,item.id);db.prepare('UPDATE reports SET status=?,assigned_to=?,updated_at=? WHERE id=?').run(caseStatus,moderator.id,updated,item.report_id);if(status==='quarantined'&&item.album_id){db.prepare("UPDATE media_pipeline SET status='QUARANTINED',moderation_status='PENDING',updated_at=? WHERE media_id IN (SELECT id FROM album_media WHERE album_id=?)").run(updated,item.album_id);db.prepare("UPDATE albums SET status='processing',updated_at=? WHERE id=?").run(updated,item.album_id);db.prepare("UPDATE stories SET status='draft' WHERE id=(SELECT story_id FROM albums WHERE id=?)").run(item.album_id)}auditAdmin(moderator,`moderation_case_${status}`,'moderation_case',item.id,{category:item.category,priority:item.priority,reason:decisionReason});return json(res,200,{ok:true});
  }
  if(method==='GET'&&path==='/upload/eligibility'){
    const user=requireUser(req,res);if(!user)return;const result=canUserUpload(user.id);return json(res,200,result);
  }
  if(method==='POST'&&path==='/upload/accept-eligibility'){
    const user=requireUser(req,res);if(!user)return;const input=await readJson(req);
    if(input.adultConfirmed!==true||input.termsAccepted!==true||input.guidelinesAccepted!==true||input.creatorAgreementAccepted!==true)return fail(res,400,'Confirm your age and accept the Terms, Content Guidelines, and Creator Agreement before uploading.');
    const verified=db.prepare('SELECT email_verified_at FROM users WHERE id=?').get(user.id);if(!verified?.email_verified_at)return fail(res,403,'Verify your email before uploading.');
    const acceptedAt=nowIso();db.prepare("UPDATE users SET adult_confirmed=1,age_status='self_attested',terms_accepted_at=?,guidelines_accepted_at=?,creator_agreement_version=?,updated_at=? WHERE id=?").run(acceptedAt,acceptedAt,currentPolicyVersions.creatorAgreement,acceptedAt,user.id);
    const accept=db.prepare('INSERT OR IGNORE INTO policy_acceptances(user_id,policy_key,policy_version,accepted_at) VALUES(?,?,?,?)');for(const [key,version] of [['terms',currentPolicyVersions.terms],['guidelines',currentPolicyVersions.guidelines],['creator_agreement',currentPolicyVersions.creatorAgreement]])accept.run(user.id,key,version,acceptedAt);
    return json(res,200,canUserUpload(user.id));
  }
  if(method==='GET'&&path==='/account'){
    const user=requireUser(req,res);if(!user)return;
    const row=db.prepare('SELECT id,display_name,username,bio,email,avatar_initial,onlyfans_url,avatar_path,created_at,updated_at FROM users WHERE id=?').get(user.id);
    return json(res,200,{user:publicUser(row)});
  }
  if(method==='PATCH'&&path==='/account'){
    const user=requireUser(req,res);if(!user)return;const input=await readJson(req);
    const name=String(input.displayName||'').trim(),rawLink=String(input.onlyfansUrl||'').trim(),username=String(input.username||'').trim().toLowerCase(),bio=String(input.bio||'').trim();
    if(name.length<2||name.length>40)return fail(res,400,'Choose a display name between 2 and 40 characters.');
    if(db.prepare('SELECT 1 FROM users WHERE id<>? AND display_name=? COLLATE NOCASE').get(user.id,name))return fail(res,409,'That display name is already in use.');
    if(!/^[a-z0-9_]{3,24}$/.test(username))return fail(res,400,'Username must be 3–24 characters using letters, numbers, or underscores.');
    if(db.prepare('SELECT 1 FROM users WHERE id<>? AND username=? COLLATE NOCASE').get(user.id,username))return fail(res,409,'That username is already taken.');
    if(bio.length>30)return fail(res,400,'Bio must be 30 characters or fewer.');
    let onlyfansUrl='';if(rawLink){let parsed;try{parsed=new URL(rawLink)}catch{return fail(res,400,'Enter a valid OnlyFans link.')}if(parsed.protocol!=='https:'||!['onlyfans.com','www.onlyfans.com'].includes(parsed.hostname.toLowerCase()))return fail(res,400,'Use a secure OnlyFans link, such as https://onlyfans.com/yourname.');onlyfansUrl=parsed.href.slice(0,500)}
    db.prepare('UPDATE users SET display_name=?,username=?,bio=?,avatar_initial=?,onlyfans_url=?,updated_at=? WHERE id=?').run(name,username,bio,Array.from(name)[0].toUpperCase(),onlyfansUrl,nowIso(),user.id);
    const row=db.prepare('SELECT id,display_name,username,bio,email,avatar_initial,onlyfans_url,avatar_path,created_at,updated_at FROM users WHERE id=?').get(user.id);return json(res,200,{user:publicUser(row)});
  }
  if(method==='POST'&&path==='/account/password'){
    const user=requireUser(req,res);if(!user)return;const input=await readJson(req),currentPassword=String(input.currentPassword||''),newPassword=String(input.newPassword||'');
    const row=db.prepare('SELECT password_hash FROM users WHERE id=?').get(user.id);if(!row?.password_hash||!passwordMatches(currentPassword,row.password_hash))return fail(res,401,'Your current password is incorrect.');
    if(newPassword.length<8||newPassword.length>200)return fail(res,400,'Use a new password with at least 8 characters.');
    if(newPassword===currentPassword)return fail(res,400,'Choose a password different from your current one.');
    db.prepare('UPDATE users SET password_hash=?,updated_at=? WHERE id=?').run(passwordDigest(newPassword),nowIso(),user.id);db.prepare('DELETE FROM sessions WHERE user_id=?').run(user.id);clearSessionCookie(res);return json(res,200,{ok:true});
  }
  if(method==='POST'&&path==='/account/avatar'){
    const user=requireUser(req,res);if(!user)return;if(!rateLimit(req,res,'avatar-upload',{limit:6,windowMs:60*60*1000,identity:String(user.id)}))return;const contentType=req.headers['content-type']||'';if(!contentType.toLowerCase().startsWith('multipart/form-data;'))return fail(res,415,'Choose an image file.');
    const bytes=await readBody(req,5*1024*1024+128*1024),formRequest=new Request('http://local/avatar',{method:'POST',headers:{'content-type':contentType},body:bytes}),form=await formRequest.formData(),file=form.get('avatar');
    if(!(file instanceof File)||!file.size)return fail(res,400,'Choose an image file.');if(file.size>5*1024*1024)return fail(res,413,'Profile pictures must be 5 MB or smaller.');
    const mime=file.type.toLowerCase(),extension={ 'image/jpeg':'.jpg','image/png':'.png','image/webp':'.webp' }[mime];if(!extension)return fail(res,415,'Use a JPG, PNG, or WebP image.');
    const image=Buffer.from(await file.arrayBuffer()),valid=mime==='image/jpeg'?image.subarray(0,3).equals(Buffer.from([0xff,0xd8,0xff])):mime==='image/png'?image.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10])):image.length>12&&image.toString('ascii',0,4)==='RIFF'&&image.toString('ascii',8,12)==='WEBP';if(!valid)return fail(res,415,'That file is not a valid JPG, PNG, or WebP image.');
    const filename=`avatar-${user.id}-${randomBytes(16).toString('hex')}${extension}`;await storageProvider.upload(filename,image,{contentType:mime});
    const prior=db.prepare('SELECT avatar_path FROM users WHERE id=?').get(user.id);db.prepare('UPDATE users SET avatar_path=?,updated_at=? WHERE id=?').run(filename,nowIso(),user.id);if(prior?.avatar_path)await storageProvider.delete(basename(prior.avatar_path)).catch(()=>{});
    const row=db.prepare('SELECT id,display_name,username,bio,email,avatar_initial,onlyfans_url,avatar_path,created_at,updated_at FROM users WHERE id=?').get(user.id);return json(res,200,{user:publicUser(row)});
  }
  if(method==='DELETE'&&path==='/account'){
    const user=requireUser(req,res);if(!user)return;const input=await readJson(req),confirmation=String(input.confirmation||''),password=String(input.password||'');
    if(confirmation!=='DELETE')return fail(res,400,'Type DELETE to confirm account deletion.');const row=db.prepare('SELECT password_hash,avatar_path FROM users WHERE id=?').get(user.id);if(!row?.password_hash||!passwordMatches(password,row.password_hash))return fail(res,401,'Your password is incorrect.');
    const media=db.prepare(`SELECT storage_name FROM album_media m JOIN albums a ON a.id=m.album_id WHERE a.owner_id=?
      UNION SELECT media_path AS storage_name FROM stories WHERE creator_id=? AND media_path IS NOT NULL`).all(user.id,user.id).map(item=>item.storage_name),avatar=row.avatar_path;
    db.exec('BEGIN IMMEDIATE');try{db.prepare('DELETE FROM stories WHERE creator_id=?').run(user.id);db.prepare('DELETE FROM users WHERE id=?').run(user.id);db.exec('COMMIT')}catch(error){db.exec('ROLLBACK');throw error}
    for(const filename of [...media,avatar].filter(Boolean))await storageProvider.delete(basename(filename)).catch(()=>{});
    clearSessionCookie(res);return json(res,200,{ok:true});
  }

  if(method==='GET'&&path==='/auth/oauth/providers'){
    const configured=oauthProviders(process.env);
    return json(res,200,{providers:Object.fromEntries(Object.entries(configured).map(([name,value])=>[name,{available:value.configured}]))});
  }
  const oauthRoute=path.match(/^\/auth\/oauth\/(google|reddit|x)\/(start|callback)$/);
  if(oauthRoute&&oauthRoute[2]==='start'&&method==='POST'){
    if(!rateLimit(req,res,'oauth-start',{limit:12,windowMs:15*60*1000}))return;
    const [,provider]=oauthRoute,input=await readJson(req),mode=String(input.mode||'login');
    if(!['login','signup','link'].includes(mode))return fail(res,400,'Choose sign in, sign up, or account linking.');
    const config=oauthProviders(process.env)[provider];
    if(!config.configured)return fail(res,503,`${provider==='x'?'X':provider[0].toUpperCase()+provider.slice(1)} sign-in is not configured yet.`);
    let user=null;
    if(mode==='link'){user=requireUser(req,res);if(!user)return}
    if(mode==='signup'){
      if(setting('signups_enabled')==='false')return fail(res,403,'New account registration is temporarily disabled.');
      if(input.adultConfirmed!==true)return fail(res,400,'Confirm that you are 18 or older to create an account.');
      if(input.termsAccepted!==true)return fail(res,400,'Accept the Terms to create an account.');
      if(input.guidelinesAccepted!==true)return fail(res,400,'Accept the Community Guidelines to create an account.');
    }
    const state=randomBytes(32).toString('base64url'),verifier=config.pkce?randomBytes(32).toString('base64url'):null,created=Date.now(),termsAt=mode==='signup'?nowIso():null;
    db.prepare('DELETE FROM oauth_transactions WHERE expires_at<=?').run(created);
    db.prepare('INSERT INTO oauth_transactions(state_hash,provider,purpose,user_id,code_verifier,adult_confirmed,terms_version,guidelines_version,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?)').run(hashToken(state),provider,mode,user?.id||null,verifier,mode==='signup'?1:0,termsAt?currentPolicyVersions.terms:null,termsAt?currentPolicyVersions.guidelines:null,created,created+10*60_000);
    const secure=config.callback.startsWith('https://')?' Secure;':'';
    appendSetCookie(res,`aroused_oauth_${provider}=${encodeURIComponent(state)}; HttpOnly; SameSite=Lax; Path=/api/auth/oauth/${provider}/callback; Max-Age=600;${secure}`);
    return json(res,200,{authorizationUrl:createOAuthAuthorization({provider,state,codeVerifier:verifier||'',config})});
  }
  if(oauthRoute&&oauthRoute[2]==='callback'&&method==='GET'){
    const [,provider]=oauthRoute,config=oauthProviders(process.env)[provider];
    if(!config.configured)return fail(res,503,'This social sign-in provider is not configured.');
    const state=url.searchParams.get('state')||'',providedCookie=decodedCookie(req,`aroused_oauth_${provider}`),expected=Buffer.from(state),cookie=Buffer.from(providedCookie);
    if(!state||!providedCookie||expected.length!==cookie.length||!timingSafeEqual(expected,cookie))return fail(res,400,'This sign-in request expired or could not be verified. Start again.');
    db.exec('BEGIN IMMEDIATE');let transaction;
    try{
      transaction=db.prepare('SELECT * FROM oauth_transactions WHERE state_hash=? AND provider=? AND expires_at>?').get(hashToken(state),provider,Date.now());
      if(!transaction){db.exec('ROLLBACK');return fail(res,400,'This sign-in request expired or could not be verified. Start again.')}
      db.prepare('DELETE FROM oauth_transactions WHERE state_hash=?').run(hashToken(state));db.exec('COMMIT');
    }catch(error){try{db.exec('ROLLBACK')}catch{}throw error}
    const clearOAuthCookie=()=>appendSetCookie(res,`aroused_oauth_${provider}=; HttpOnly; SameSite=Lax; Path=/api/auth/oauth/${provider}/callback; Max-Age=0;${config.callback.startsWith('https://')?' Secure;':''}`);
    const redirectError=code=>{clearOAuthCookie();res.writeHead(303,{Location:`/?authError=${encodeURIComponent(code)}#home`,'Cache-Control':'no-store'});res.end()};
    if(url.searchParams.has('error')){redirectError('provider_denied');return}
    const authCode=url.searchParams.get('code')||'';if(authCode.length>4096){redirectError('provider_error');return}
    let identity;
    try{identity=await fetchOAuthIdentity({provider,code:authCode,codeVerifier:transaction.code_verifier||'',config})}
    catch(error){operationalLog('error','oauth_identity_exchange_failed',{component:`oauth-${provider}`,route:'/auth/oauth/callback',status:error.status,errorCode:error.code||safeErrorCode(error)});redirectError('provider_error');return}
    const linked=db.prepare('SELECT id,user_id FROM user_identities WHERE provider=? AND provider_user_id=?').get(provider,identity.providerId);
    let userId;
    if(transaction.purpose==='link'){
      if(!transaction.user_id){redirectError('account_link_failed');return}
      if(linked&&Number(linked.user_id)!==Number(transaction.user_id)){redirectError('account_link_conflict');return}
      const otherProvider=db.prepare('SELECT id FROM user_identities WHERE user_id=? AND provider=?').get(transaction.user_id,provider);
      if(otherProvider&&(!linked||Number(otherProvider.id)!==Number(linked.id))){redirectError('account_link_conflict');return}
      userId=Number(transaction.user_id);
      if(linked)db.prepare('UPDATE user_identities SET provider_email=?,updated_at=? WHERE id=?').run(identity.email,nowIso(),linked.id);
      else db.prepare('INSERT INTO user_identities(user_id,provider,provider_user_id,provider_email,created_at,updated_at) VALUES(?,?,?,?,?,?)').run(userId,provider,identity.providerId,identity.email,nowIso(),nowIso());
    }else if(linked){userId=Number(linked.user_id)}
    else if(transaction.purpose==='login'){
      redirectError('account_not_found');return;
    }else{
      if(!transaction.adult_confirmed||transaction.terms_version!==currentPolicyVersions.terms||transaction.guidelines_version!==currentPolicyVersions.guidelines){redirectError('signup_policy_required');return}
      if(identity.email&&db.prepare('SELECT 1 FROM users WHERE email=? COLLATE NOCASE').get(identity.email)){redirectError('account_link_required');return}
      const displayName=String(identity.displayName||provider+' creator').trim().slice(0,40)||provider+' creator';
      const usernameBase=displayName.normalize('NFKD').replace(/[\u0300-\u036f]/g,'').toLowerCase().replace(/[^a-z0-9]+/g,'_').replace(/^_+|_+$/g,'').slice(0,20)||provider+'_creator';
      let username=usernameBase,suffix=2;while(db.prepare('SELECT 1 FROM users WHERE username=? COLLATE NOCASE').get(username))username=`${usernameBase.slice(0,20-String(suffix).length)}${suffix++}`;
      const verifiedAt=identity.email?nowIso():null,acceptedAt=nowIso();
      db.exec('BEGIN IMMEDIATE');try{
        const created=db.prepare('INSERT INTO users(display_name,username,bio,email,password_hash,avatar_initial,adult_confirmed,terms_accepted_at,guidelines_accepted_at,email_verified_at,created_at) VALUES(?,?,\'\',?,NULL,?,1,?,?,?,?)').run(displayName,username,identity.email,Array.from(displayName)[0].toUpperCase(),acceptedAt,acceptedAt,verifiedAt,acceptedAt);
        userId=Number(created.lastInsertRowid);
        db.prepare('INSERT INTO user_identities(user_id,provider,provider_user_id,provider_email,created_at,updated_at) VALUES(?,?,?,?,?,?)').run(userId,provider,identity.providerId,identity.email,acceptedAt,acceptedAt);
        db.prepare('INSERT OR IGNORE INTO policy_acceptances(user_id,album_id,policy_key,policy_version,accepted_at) VALUES(?,NULL,?,?,?)').run(userId,'terms',transaction.terms_version,acceptedAt);
        db.prepare('INSERT OR IGNORE INTO policy_acceptances(user_id,album_id,policy_key,policy_version,accepted_at) VALUES(?,NULL,?,?,?)').run(userId,'guidelines',transaction.guidelines_version,acceptedAt);
        db.exec('COMMIT');
      }catch(error){db.exec('ROLLBACK');if(String(error.code||'').startsWith('SQLITE_CONSTRAINT')){redirectError('account_link_required');return}throw error}
    }
    const account=db.prepare('SELECT id FROM users WHERE id=?').get(userId);
    if(!account){redirectError('account_not_found');return}
    clearOAuthCookie();createSession(userId,res,req);
    res.writeHead(303,{Location:transaction.purpose==='link'?'/?oauthLinked=1#settings':'/?oauthSignedIn=1#home','Cache-Control':'no-store'});res.end();return;
  }

  if(method==='POST'&&path==='/auth/request-password-reset'){
    if(!rateLimit(req,res,'password-reset-ip',{limit:10,windowMs:60*60*1000}))return;
    const input=await readJson(req),email=String(input.email||'').trim().toLowerCase();
    if(!emailPattern.test(email)||email.length>254)return fail(res,400,'Enter a valid email address.');
    if(!rateLimit(req,res,'password-reset-email',{limit:4,windowMs:60*60*1000,identity:email}))return;
    const generic={ok:true,message:'If an eligible account exists, password reset instructions will be sent.'};
    const account=db.prepare('SELECT id FROM users WHERE email=? COLLATE NOCASE AND password_hash IS NOT NULL AND email_verified_at IS NOT NULL').get(email);
    if(!account)return json(res,202,generic);
    const token=randomBytes(32).toString('base64url'),tokenHash=hashToken(token),created=nowIso();
    db.prepare('DELETE FROM password_reset_tokens WHERE user_id=? AND used_at IS NULL').run(account.id);
    db.prepare('INSERT INTO password_reset_tokens(token_hash,user_id,expires_at,used_at,created_at) VALUES(?,?,?,NULL,?)').run(tokenHash,account.id,Date.now()+30*60*1000,created);
    try{await sendPasswordResetEmail(email,token)}catch(error){logEmailDeliveryFailure('/auth/request-password-reset',error);db.prepare('DELETE FROM password_reset_tokens WHERE token_hash=?').run(tokenHash);return json(res,202,generic)}
    return json(res,202,generic);
  }
  if(method==='POST'&&path==='/auth/reset-password'){
    if(!rateLimit(req,res,'password-reset-consume-ip',{limit:12,windowMs:60*60*1000}))return;
    const input=await readJson(req),email=String(input.email||'').trim().toLowerCase(),token=String(input.token||''),newPassword=String(input.newPassword||'');
    if(!emailPattern.test(email)||email.length>254)return fail(res,400,'The password reset request could not be completed. Request a new reset token.');
    if(newPassword.length<8||newPassword.length>200)return fail(res,400,'Use a new password with at least 8 characters.');
    if(!rateLimit(req,res,'password-reset-consume-email',{limit:8,windowMs:60*60*1000,identity:email}))return;
    if(!/^[A-Za-z0-9_-]{40,60}$/.test(token))return fail(res,400,'The password reset request could not be completed. Request a new reset token.');
    const tokenHash=hashToken(token);let userId=null;db.exec('BEGIN IMMEDIATE');try{
      const reset=db.prepare('SELECT t.user_id FROM password_reset_tokens t JOIN users u ON u.id=t.user_id WHERE t.token_hash=? AND u.email=? COLLATE NOCASE AND t.used_at IS NULL AND t.expires_at>?').get(tokenHash,email,Date.now());
      if(!reset){db.exec('ROLLBACK');return fail(res,400,'The password reset request could not be completed. Request a new reset token.')}
      userId=Number(reset.user_id);db.prepare('UPDATE users SET password_hash=?,updated_at=? WHERE id=?').run(passwordDigest(newPassword),nowIso(),userId);
      const consumed=db.prepare('UPDATE password_reset_tokens SET used_at=? WHERE token_hash=? AND used_at IS NULL AND expires_at>?').run(nowIso(),tokenHash,Date.now());if(consumed.changes!==1)throw new Error('Reset token consumption race.');
      db.prepare('DELETE FROM sessions WHERE user_id=?').run(userId);db.exec('COMMIT');
    }catch(error){try{db.exec('ROLLBACK')}catch{}throw error}
    securityEvent(userId,'password_reset_completed','info','PASSWORD_RESET');clearSessionCookie(res);return json(res,200,{ok:true,message:'Password reset complete. Sign in with your new password.'});
  }
  if (method==='POST' && path==='/auth/signup') {
    if(!rateLimit(req,res,'signup-ip',{limit:10,windowMs:60*60*1000}))return;
    if(setting('signups_enabled')==='false')return fail(res,403,'New account registration is temporarily disabled.');
    const input=await readJson(req); const name=String(input.displayName||'').trim(); const email=String(input.email||'').trim().toLowerCase(); const password=String(input.password||'');
    if (name.length<2 || name.length>40) return fail(res,400,'Choose a display name between 2 and 40 characters.');
    if (!emailPattern.test(email) || email.length>254) return fail(res,400,'Enter a valid email address.');
    if (password.length<8 || password.length>200) return fail(res,400,'Use a password with at least 8 characters.');
    if (input.adultConfirmed!==true) return fail(res,400,'Confirm that you are 18 or older to create an account.');
    if (input.termsAccepted!==true) return fail(res,400,'Accept the Terms to create an account.');
    if (input.guidelinesAccepted!==true) return fail(res,400,'Accept the Community Guidelines to create an account.');
    if(!rateLimit(req,res,'signup-email',{limit:4,windowMs:60*60*1000,identity:email}))return;
    const existingAccount=!!db.prepare('SELECT 1 FROM users WHERE email=?').get(email);
    const prior=db.prepare('SELECT next_send_at FROM pending_email_verifications WHERE email=?').get(email);
    if(!existingAccount&&prior && Number(prior.next_send_at)>Date.now()) return json(res,202,{verificationRequired:true,email,message:'If this address can be verified, a code will be sent.'});
    const code=String(randomBytes(4).readUInt32BE(0)%1000000).padStart(6,'0');
    try{if(existingAccount)await sendExistingAccountSignInNotice(email);else await sendVerificationEmail(email,code)}catch(error){logEmailDeliveryFailure('/auth/signup',error);return fail(res,error.status||503,'Email delivery is temporarily unavailable. Check the address and try again later.')}
    if(existingAccount)return json(res,202,{verificationRequired:true,email,message:'If this address can be verified, a code will be sent.'});
    const now=Date.now();
    const acceptedAt=nowIso();
    db.prepare(`INSERT INTO pending_email_verifications(email,display_name,password_hash,code_hash,expires_at,next_send_at,attempts,created_at,terms_accepted_at,guidelines_accepted_at)
      VALUES(?,?,?,?,?,?,0,?,?,?) ON CONFLICT(email) DO UPDATE SET display_name=excluded.display_name,password_hash=excluded.password_hash,code_hash=excluded.code_hash,expires_at=excluded.expires_at,next_send_at=excluded.next_send_at,attempts=0,created_at=excluded.created_at,terms_accepted_at=excluded.terms_accepted_at,guidelines_accepted_at=excluded.guidelines_accepted_at`)
      .run(email,name,passwordDigest(password),emailCodeHash(email,code),now+10*60*1000,now+60*1000,acceptedAt,acceptedAt,acceptedAt);
    return json(res,202,{verificationRequired:true,email,message:'If this address can be verified, a code will be sent.'});
  }
  if (method==='POST' && path==='/auth/resend-code') {
    if(!rateLimit(req,res,'resend-ip',{limit:10,windowMs:60*60*1000}))return;
    const input=await readJson(req);const email=String(input.email||'').trim().toLowerCase();
    if(!rateLimit(req,res,'resend-email',{limit:4,windowMs:60*60*1000,identity:email}))return;
    const pending=db.prepare('SELECT next_send_at FROM pending_email_verifications WHERE email=?').get(email);
    if(!emailPattern.test(email)||!pending)return json(res,202,{verificationRequired:true,email,message:'If this address can be verified, a code will be sent.'});
    if(Number(pending.next_send_at)>Date.now())return json(res,202,{verificationRequired:true,email,message:'If this address can be verified, a code will be sent.'});
    const code=String(randomBytes(4).readUInt32BE(0)%1000000).padStart(6,'0');
    try{await sendVerificationEmail(email,code)}catch(error){logEmailDeliveryFailure('/auth/resend-code',error);return fail(res,error.status||503,'Email delivery is temporarily unavailable. Try again later.')}
    const now=Date.now();db.prepare('UPDATE pending_email_verifications SET code_hash=?,expires_at=?,next_send_at=?,attempts=0 WHERE email=?').run(emailCodeHash(email,code),now+10*60*1000,now+60*1000,email);
    return json(res,202,{verificationRequired:true,email,message:'If this address can be verified, a code will be sent.'});
  }
  if (method==='POST' && path==='/auth/verify-email') {
    if(!rateLimit(req,res,'verify-ip',{limit:20,windowMs:15*60*1000}))return;
    const input=await readJson(req);const email=String(input.email||'').trim().toLowerCase();const code=String(input.code||'').trim();
    if(!emailPattern.test(email)||!/^\d{6}$/.test(code))return fail(res,400,'The verification request could not be completed. Check your code or request a new one.');
    if(!rateLimit(req,res,'verify-email',{limit:8,windowMs:15*60*1000,identity:email}))return;
    const pending=db.prepare('SELECT * FROM pending_email_verifications WHERE email=?').get(email);
    if(!pending)return fail(res,400,'The verification request could not be completed. Check your code or request a new one.');
    if(Number(pending.expires_at)<=Date.now()){db.prepare('DELETE FROM pending_email_verifications WHERE email=?').run(email);return fail(res,400,'The verification request could not be completed. Check your code or request a new one.');}
    if(Number(pending.attempts)>=5){db.prepare('DELETE FROM pending_email_verifications WHERE email=?').run(email);return fail(res,400,'The verification request could not be completed. Check your code or request a new one.');}
    const expected=Buffer.from(pending.code_hash,'hex'),actual=Buffer.from(emailCodeHash(email,code),'hex');
    if(expected.length!==actual.length||!timingSafeEqual(expected,actual)){db.prepare('UPDATE pending_email_verifications SET attempts=attempts+1 WHERE email=?').run(email);return fail(res,400,'The verification request could not be completed. Check your code or request a new one.');}
    if(db.prepare('SELECT 1 FROM users WHERE email=?').get(email)){db.prepare('DELETE FROM pending_email_verifications WHERE email=?').run(email);return fail(res,400,'The verification request could not be completed. Check your code or request a new one.');}
    const usernameBase=String(pending.display_name||'creator').normalize('NFKD').replace(/[\u0300-\u036f]/g,'').toLowerCase().replace(/[^a-z0-9]+/g,'_').replace(/^_+|_+$/g,'').slice(0,20)||'creator';let username=usernameBase,suffix=2;while(db.prepare('SELECT 1 FROM users WHERE username=? COLLATE NOCASE').get(username))username=`${usernameBase.slice(0,20-String(suffix).length)}${suffix++}`;
    if(!pending.terms_accepted_at||!pending.guidelines_accepted_at)return fail(res,400,'Start signup again and accept the Terms and Community Guidelines.');
    const verifiedAt=nowIso();
    const result=db.prepare('INSERT INTO users(display_name,username,bio,email,password_hash,avatar_initial,adult_confirmed,terms_accepted_at,guidelines_accepted_at,email_verified_at,created_at) VALUES(?,?,\'\',?,?,?,1,?,?,?,?)').run(pending.display_name,username,email,pending.password_hash,Array.from(pending.display_name)[0].toUpperCase(),pending.terms_accepted_at,pending.guidelines_accepted_at,verifiedAt,verifiedAt);
    db.prepare('DELETE FROM pending_email_verifications WHERE email=?').run(email);
    createSession(Number(result.lastInsertRowid),res,req);
    const createdUser=db.prepare('SELECT id,display_name,username,bio,email,avatar_initial,onlyfans_url,avatar_path,created_at,updated_at FROM users WHERE id=?').get(Number(result.lastInsertRowid));
    return json(res,201,{user:publicUser(createdUser),verified:true});
  }
  if (method==='POST' && path==='/auth/login') {
    const input=await readJson(req); const email=String(input.email||'').trim().toLowerCase(); const password=String(input.password||'');
    if(!rateLimit(req,res,'login-ip',{limit:25,windowMs:15*60*1000}))return;
    if(!rateLimit(req,res,'login-email',{limit:8,windowMs:15*60*1000,identity:email}))return;
    const user=db.prepare('SELECT id,password_hash,suspended FROM users WHERE email=?').get(email);
    const passwordValid=passwordMatches(password,user?.password_hash||dummyLoginDigest);
    if (!user || !user.password_hash || !passwordValid) return fail(res,401,'Email or password is incorrect.');
    createSession(user.id,res,req);
    const loggedInUser=db.prepare('SELECT id,display_name,username,bio,email,avatar_initial,onlyfans_url,avatar_path,created_at,updated_at,suspended FROM users WHERE id=?').get(user.id);
    return json(res,200,{user:publicUser(loggedInUser)});
  }
  if (method==='POST' && path==='/auth/logout') {
    const token=decodedCookie(req,'aroused_session'); if(token)db.prepare('DELETE FROM sessions WHERE token_hash=?').run(hashToken(token));
    clearSessionCookie(res); return json(res,200,{ok:true});
  }
  if (method==='GET' && path==='/stories') {
    publishDueAlbums();
    const q=(url.searchParams.get('q')||'').trim().slice(0,100), creator=url.searchParams.get('creator'), category=url.searchParams.get('category');
    const filters=[],params=[];
    if(q){filters.push('(s.title LIKE ? OR s.category LIKE ? OR s.tags_json LIKE ? OR u.display_name LIKE ?)');const like=`%${q}%`;params.push(like,like,like,like)}
    if(creator){filters.push('u.display_name=?');params.push(creator)}
    if(category && category!=='All'){filters.push('s.category=?');params.push(category)}
    const rows=storyRows(filters.length?'AND '+filters.join(' AND '):'',params);
    const user=sessionUser(req); const items=rows.map(row=>storyObject(row,user));
    return json(res,200,{items,total:items.length});
  }
  if(method==='GET'&&path==='/reposts'){
    const user=requireUser(req,res);if(!user)return;
    const rows=db.prepare(`SELECT s.*,u.display_name AS creator,u.avatar_initial,u.avatar_path,u.onlyfans_url,a.slug AS album_slug,a.visibility AS album_visibility,m.mime_type AS cover_mime,m.original_name AS cover_name FROM reposts r JOIN stories s ON s.id=r.story_id JOIN users u ON u.id=s.creator_id LEFT JOIN albums a ON a.story_id=s.id LEFT JOIN album_media m ON m.id=COALESCE(a.cover_media_id,s.cover_media_id) WHERE r.user_id=? AND s.status='published' AND (a.id IS NULL OR a.visibility<>'private' OR a.owner_id=?) ORDER BY r.created_at DESC`).all(user.id,user.id);
    return json(res,200,{items:rows.filter(row=>row.album_slug&&row.album_visibility==='public'&&canPublishAlbum(albumRecordBySlug(row.album_slug))).map(row=>storyObject(row,user))});
  }
  if(method==='GET'&&path==='/dashboard'){
    publishDueAlbums();
    const user=requireUser(req,res);if(!user)return;const rows=db.prepare(`SELECT a.* FROM albums a WHERE a.owner_id=? AND a.status<>'removed' ORDER BY a.updated_at DESC`).all(user.id);return json(res,200,{items:rows.map(row=>albumObject(albumRecordById(row.id),user))});
  }
  if(path==='/appeals'&&method==='GET'){
    const user=sessionUser(req);if(!user)return fail(res,401,'Sign in to view account appeals.');const items=db.prepare('SELECT id,reason,status,created_at,updated_at,decision_reason FROM appeals WHERE user_id=? ORDER BY created_at DESC').all(user.id);return json(res,200,{items});
  }
  if(path==='/appeals'&&method==='POST'){
    const user=sessionUser(req);if(!user)return fail(res,401,'Sign in to submit an appeal.');const input=await readJson(req);const reason=String(input.reason||'').trim().slice(0,2000);if(reason.length<10)return fail(res,400,'Explain your appeal in at least 10 characters.');const active=db.prepare("SELECT id FROM enforcement_actions WHERE user_id=? AND revoked_at IS NULL AND action IN ('suspend','ban','restrict_uploads','remove_post') ORDER BY created_at DESC LIMIT 1").get(user.id);if(!active&&!user.suspended&&!user.banned)return fail(res,409,'There is no active account enforcement to appeal.');if(!rateLimit(req,res,'appeal-user',{limit:3,windowMs:86400000,identity:String(user.id)}))return;const prior=db.prepare("SELECT 1 FROM appeals WHERE user_id=? AND status IN ('open','reviewing')").get(user.id);if(prior)return fail(res,409,'You already have an appeal awaiting review.');const created=nowIso();db.prepare('INSERT INTO appeals(user_id,enforcement_id,reason,status,created_at,updated_at) VALUES(?,?,?,\'open\',?,?)').run(user.id,active?.id||null,reason,created,created);securityEvent(user.id,'appeal_submitted','info','ENFORCEMENT_APPEAL');return json(res,201,{ok:true});
  }
  const albumMediaAddRoute=path.match(/^\/albums\/(\d+)\/media$/);
  if(albumMediaAddRoute&&method==='POST'){
    const user=requireUser(req,res);if(!user)return;
    if(!rateLimit(req,res,'media-upload',{limit:10,windowMs:60*60*1000,identity:String(user.id)}))return;
    const eligibility=canUserUpload(user.id);if(!eligibility.eligible)return fail(res,403,eligibility.message);
    const album=albumRecordById(albumMediaAddRoute[1]);if(!album)return fail(res,404,'Album not found.');
    if(Number(album.owner_id)!==Number(user.id))return fail(res,403,'You can only edit your own albums.');
    const contentType=req.headers['content-type']||'';if(!contentType.toLowerCase().startsWith('multipart/form-data;'))return fail(res,415,'Choose media files.');
    const bytes=await readBody(req,maxUploadBytes);const form=await new Request('http://local/albums/media',{method:'POST',headers:{'content-type':contentType},body:bytes}).formData();
    const old=albumMedia(album),files=form.getAll('media').filter(file=>file instanceof File&&file.size);
    if(!files.length)return fail(res,400,'Choose at least one photo or video.');
    if(old.length+files.length>20)return fail(res,400,'An album can contain up to 20 media files.');
    const staged=[];let total=old.reduce((sum,item)=>sum+Number(item.size||0),0);
    for(const file of files){
      total+=file.size;if(total>maxUploadBytes)return fail(res,413,'The album exceeds the total upload size limit.');
      const mime=file.type.toLowerCase(),extension=mimeExt.get(mime),fileExtension=extname(file.name).toLowerCase();
      if(!extension||fileExtension!==extension&&!(mime==='image/jpeg'&&fileExtension==='.jpeg'))return fail(res,415,`${file.name}: use a matching supported media type and extension.`);
      const buffer=Buffer.from(await file.arrayBuffer());if(!mediaBytesMatch(mime,buffer))return fail(res,415,`${file.name}: the file header does not match its media type.`);
      staged.push({file,mime,buffer,storage:`album-${user.id}-${randomBytes(20).toString('hex')}${extension}`});
    }
    const stored=[];try{
      for(const item of staged){await storageProvider.upload(item.storage,item.buffer,{contentType:item.mime,metadata:{originalName:item.file.name}});stored.push(item.storage)}
      const created=nowIso();db.exec('BEGIN IMMEDIATE');
      try{
        const insert=db.prepare(`INSERT INTO album_media(album_id,storage_name,original_name,mime_type,byte_size,position,state,created_at) VALUES(?,?,?,?,?,?,'processing',?)`);
        staged.forEach((item,index)=>{const mediaId=Number(insert.run(album.id,item.storage,item.file.name,item.mime,item.buffer.length,old.length+index,created).lastInsertRowid);registerMediaPipeline(mediaId,item.buffer,created)});
        const cover=album.cover_media_id||Number(db.prepare('SELECT id FROM album_media WHERE album_id=? ORDER BY position LIMIT 1').get(album.id)?.id)||null;
        db.prepare('UPDATE albums SET cover_media_id=?,updated_at=? WHERE id=?').run(cover,created,album.id);db.prepare('UPDATE stories SET cover_media_id=? WHERE id=?').run(cover,album.story_id);db.exec('COMMIT');
      }catch(error){db.exec('ROLLBACK');throw error}
    }catch(error){for(const name of stored)await storageProvider.delete(name).catch(()=>{});throw error}
    return json(res,201,{album:albumObject(albumRecordById(album.id),user)});
  }
  const albumRoute=path.match(/^\/albums\/([^/]+)(?:\/(publish|media\/\d+))?$/);
  if(method==='GET'&&albumRoute&&!albumRoute[2]){
    if(!rateLimit(req,res,'album-read',{limit:120,windowMs:15*60*1000}))return;
    const decodedSlug=safeDecode(albumRoute[1]);if(decodedSlug===null)return fail(res,404,'Album not found.');const album=albumRecordBySlug(decodedSlug);if(!album)return fail(res,404,'Album not found.');const user=sessionUser(req),owner=Number(album.owner_id)===Number(user?.id);
    if(!owner&&(album.status!=='published'||album.story_status!=='published'||album.visibility==='private'||!canPublishAlbum(album)))return fail(res,404,'Album not found.');
    return json(res,200,{album:albumObject(album,user)});
  }
  if(method==='POST'&&path==='/albums'){
    const user=requireUser(req,res);if(!user)return;if(!rateLimit(req,res,'media-upload',{limit:10,windowMs:60*60*1000,identity:String(user.id)}))return;const eligibility=canUserUpload(user.id);if(!eligibility.eligible)return fail(res,403,eligibility.message);
    const contentType=req.headers['content-type']||'';if(!contentType.toLowerCase().startsWith('multipart/form-data;'))return fail(res,415,'Choose media files to create an album.');
    const bytes=await readBody(req,maxUploadBytes);const multipart=await new Request('http://local/albums',{method:'POST',headers:{'content-type':contentType},body:bytes}).formData();
    const title=String(multipart.get('title')||'').trim(),description=String(multipart.get('description')||'').trim(),category=String(multipart.get('category')||'Creator upload').trim().slice(0,60),tags=csvList(multipart.get('tags')),visibility=String(multipart.get('visibility')||'public'),mode=String(multipart.get('mode')||'draft'),publishMode=mode==='draft'?'immediate':String(multipart.get('publishMode')||'immediate'),scheduledInput=String(multipart.get('scheduledAt')||''),allowComments=multipart.get('allowComments')!=='false';
    if(mode==='published'&&multipart.get('rightsDeclarationAccepted')!=='true')return fail(res,400,'Accept the rights and consent declaration for this post.');
    if(title.length<2||title.length>140)return fail(res,400,'Album title must be between 2 and 140 characters.');if(description.length>3000)return fail(res,400,'Album description must be 3,000 characters or fewer.');if(!['public','unlisted','private'].includes(visibility))return fail(res,400,'Choose public, unlisted, or private visibility.');if(!['draft','published'].includes(mode)||!['immediate','schedule','approval'].includes(publishMode))return fail(res,400,'Choose publish now, schedule, or submit for approval.');
    let scheduledAt=null;if(mode!=='draft'&&publishMode==='schedule'){const parsed=Date.parse(scheduledInput);if(!Number.isFinite(parsed)||parsed<=Date.now())return fail(res,400,'Choose a future date and time for the scheduled post.');scheduledAt=new Date(parsed).toISOString()}
    const files=multipart.getAll('media').filter(file=>file instanceof File&&file.size);if(!files.length&&mode!=='draft')return fail(res,400,'Choose at least one photo or video.');if(files.length>20)return fail(res,400,'An album can contain up to 20 media files.');
    const staged=[];for(const [index,file] of files.entries()){
      if(file.size>maxUploadBytes)return fail(res,413,`${file.name} exceeds the upload size limit.`);const mime=file.type.toLowerCase(),extension=mimeExt.get(mime);if(!extension)return fail(res,415,`${file.name}: use JPG, PNG, WebP, MP4, WebM, or MOV.`);
      const originalExtension=extname(file.name).toLowerCase();if(originalExtension!==extension&&!(mime==='image/jpeg'&&originalExtension==='.jpeg'))return fail(res,415,`${file.name}: the filename extension does not match its detected media type.`);
      const buffer=Buffer.from(await file.arrayBuffer());if(!mediaBytesMatch(mime,buffer))return fail(res,415,`${file.name}: the file header does not match a supported media format.`);
      staged.push({file,mime,buffer,index,storage:`album-${user.id}-${randomBytes(20).toString('hex')}${extension}`});
    }
    if(mode==='published'&&staged.some(item=>!item.buffer.length))return fail(res,400,'All album media must finish processing before publishing.');
    const stored=[];try{for(const item of staged){await storageProvider.upload(item.storage,item.buffer,{contentType:item.mime,metadata:{originalName:item.file.name}});stored.push(item.storage)}}catch(error){for(const filename of stored)await storageProvider.delete(filename).catch(()=>{});throw error}
    const created=nowIso(),requestedPublish=mode==='published',reviewStatus=requestedPublish&&publishMode==='approval'?'pending':'not_required',storyStatus='draft',albumStatus='draft';let albumId;
    try{
      db.exec('BEGIN IMMEDIATE');const storyResult=db.prepare(`INSERT INTO stories(creator_id,title,category,tags_json,media_name,media_path,media_type,duration,views,seeded_likes,tone_a,tone_b,status,created_at) VALUES(?,?,?,?,NULL,NULL,NULL,'00:00',0,0,'#513035','#b45c68',?,?)`).run(user.id,title,category,JSON.stringify(tags),storyStatus,created);
      const storyId=Number(storyResult.lastInsertRowid);const baseSlug=slug(title)||'album';let albumSlug=`${baseSlug}-${randomBytes(16).toString('hex')}`;const savedPublishMode=mode==='draft'?'immediate':publishMode;const albumResult=db.prepare(`INSERT INTO albums(story_id,owner_id,slug,description,visibility,status,allow_comments,created_at,updated_at,publish_mode,scheduled_at,review_status) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`).run(storyId,user.id,albumSlug,description,visibility,albumStatus,allowComments?1:0,created,created,savedPublishMode,scheduledAt,reviewStatus);albumId=Number(albumResult.lastInsertRowid);
      const insertMedia=db.prepare(`INSERT INTO album_media(album_id,storage_name,original_name,mime_type,byte_size,position,state,created_at) VALUES(?,?,?,?,?,?,'processing',?)`);let coverId=0;for(const item of staged){const mediaResult=insertMedia.run(albumId,item.storage,item.file.name,item.mime,item.buffer.length,item.index,created),mediaId=Number(mediaResult.lastInsertRowid);registerMediaPipeline(mediaId,item.buffer,created);if(item.index===Number(multipart.get('coverIndex')||0))coverId=mediaId}
      if(mode==='published'){const declaration=db.prepare('INSERT OR IGNORE INTO creator_declarations(album_id,user_id,declaration_key,policy_version,accepted_at) VALUES(?,?,?,?,?)');declaration.run(albumId,user.id,'rights',currentPolicyVersions.rights,created);declaration.run(albumId,user.id,'consent',currentPolicyVersions.rights,created);}
      db.prepare('UPDATE albums SET cover_media_id=? WHERE id=?').run(coverId,albumId);db.prepare('UPDATE stories SET cover_media_id=? WHERE id=?').run(coverId,storyId);db.exec('COMMIT');
    }catch(error){try{db.exec('ROLLBACK')}catch{}for(const filename of stored)await storageProvider.delete(filename).catch(()=>{});throw error}
    const album=albumRecordById(albumId);return json(res,201,{album:albumObject(album,user)});
  }
  if(albumRoute&&method==='POST'&&albumRoute[2]==='publish'){
    const user=requireUser(req,res);if(!user)return;const album=albumRecordById(albumRoute[1]);if(!album)return fail(res,404,'Album not found.');if(Number(album.owner_id)!==Number(user.id))return fail(res,403,'You can only publish your own albums.');const eligibility=canUserUpload(user.id);if(!eligibility.eligible)return fail(res,403,eligibility.message);
    const input=await readJson(req),publishMode=String(input.publishMode||'immediate'),media=albumMedia(album);if(!['immediate','schedule','approval'].includes(publishMode))return fail(res,400,'Choose publish now, schedule, or submit for approval.');if(!album.title||album.title.length<2)return fail(res,400,'Add an album title before publishing.');if(!media.length)return fail(res,400,'Add at least one photo or video before publishing.');let scheduledAt=null;if(publishMode==='schedule'){const parsed=Date.parse(input.scheduledAt||'');if(!Number.isFinite(parsed)||parsed<=Date.now())return fail(res,400,'Choose a future date and time for the scheduled post.');scheduledAt=new Date(parsed).toISOString()}if(publishMode==='immediate'&&!canPublishAlbum(album))return fail(res,409,'Publishing is blocked until every required provider, policy, and moderation gate has passed.');const timestamp=nowIso(),nextStatus=publishMode==='immediate'?'published':'draft',reviewStatus=publishMode==='approval'?'pending':'not_required';db.exec('BEGIN IMMEDIATE');try{const current=albumRecordById(album.id);if(publishMode==='immediate'&&!canPublishAlbum(current))throw Object.assign(new Error('Publishing is blocked until every required provider, policy, and moderation gate has passed.'),{status:409});db.prepare('UPDATE albums SET status=?,publish_mode=?,scheduled_at=?,review_status=?,updated_at=? WHERE id=?').run(nextStatus,publishMode==='immediate'?'immediate':publishMode,scheduledAt,reviewStatus,timestamp,album.id);db.prepare('UPDATE stories SET status=? WHERE id=?').run(nextStatus,album.story_id);db.exec('COMMIT')}catch(error){db.exec('ROLLBACK');if(error.status===409)return fail(res,409,error.message);throw error}return json(res,200,{album:albumObject(albumRecordById(album.id),user)});
  }
  if(albumRoute&&method==='PATCH'&&!albumRoute[2]){
    const user=requireUser(req,res);if(!user)return;const album=albumRecordById(albumRoute[1]);if(!album)return fail(res,404,'Album not found.');if(Number(album.owner_id)!==Number(user.id))return fail(res,403,'You can only edit your own albums.');
    const input=await readJson(req),title=input.title===undefined?album.title:String(input.title).trim(),description=input.description===undefined?album.description:String(input.description).trim(),category=input.category===undefined?album.category:String(input.category).trim(),visibility=input.visibility===undefined?album.visibility:String(input.visibility),tags=input.tags===undefined?JSON.parse(album.tags_json||'[]'):csvList(Array.isArray(input.tags)?input.tags.join(','):input.tags),allowComments=input.allowComments===undefined?!!album.allow_comments:input.allowComments===true;
    if(title.length<2||title.length>140)return fail(res,400,'Album title must be between 2 and 140 characters.');if(description.length>3000)return fail(res,400,'Album description must be 3,000 characters or fewer.');if(!['public','unlisted','private'].includes(visibility))return fail(res,400,'Choose public, unlisted, or private visibility.');
    const media=albumMedia(album);let coverId=input.coverMediaId===undefined?album.cover_media_id:Number(input.coverMediaId);if(coverId&&!media.some(item=>Number(item.id)===coverId))return fail(res,400,'Choose a cover image from this album.');if(!coverId&&media.length)coverId=Number(media[0].id);
    let desired=null;if(input.order!==undefined){if(!Array.isArray(input.order))return fail(res,400,'The media order must include every album file exactly once.');desired=input.order.map(Number);if(desired.length!==media.length||new Set(desired).size!==desired.length||desired.some(id=>!media.some(item=>Number(item.id)===id)))return fail(res,400,'The media order must include every album file exactly once.')}
    const publishMode=String(input.publishMode??album.publish_mode??'immediate'),rawSchedule=input.scheduledAt===undefined?album.scheduled_at:input.scheduledAt;let scheduledAt=null;if(!['immediate','schedule','approval'].includes(publishMode))return fail(res,400,'Choose publish now, schedule, or submit for approval.');if(publishMode==='schedule'){const parsed=Date.parse(rawSchedule||'');if(!Number.isFinite(parsed)||parsed<=Date.now())return fail(res,400,'Choose a future date and time to publish.');scheduledAt=new Date(parsed).toISOString()}
    const reviewStatus=publishMode==='approval'?'pending':'not_required',status=publishMode==='immediate'&&album.status==='published'?'published':'draft',updated=nowIso();db.exec('BEGIN IMMEDIATE');try{if(desired){const update=db.prepare('UPDATE album_media SET position=? WHERE id=? AND album_id=?');desired.forEach((id,index)=>update.run(index,id,album.id))}db.prepare('UPDATE albums SET description=?,visibility=?,allow_comments=?,cover_media_id=?,publish_mode=?,scheduled_at=?,review_status=?,status=?,updated_at=? WHERE id=?').run(description,visibility,allowComments?1:0,coverId,publishMode,scheduledAt,reviewStatus,status,updated,album.id);db.prepare('UPDATE stories SET title=?,category=?,tags_json=?,cover_media_id=?,status=? WHERE id=?').run(title,category||'Creator upload',JSON.stringify(tags),coverId,status,album.story_id);if(status==='published'&&visibility!=='private'&&!canPublishAlbum(albumRecordById(album.id)))throw Object.assign(new Error('Public visibility is blocked until every required provider, policy, and moderation gate has passed.'),{status:409});db.exec('COMMIT')}catch(error){db.exec('ROLLBACK');if(error.status===409)return fail(res,409,error.message);throw error}return json(res,200,{album:albumObject(albumRecordById(album.id),user)});
  }
  if(albumRoute&&method==='DELETE'&&albumRoute[2]?.startsWith('media/')){
    const user=requireUser(req,res);if(!user)return;const album=albumRecordById(albumRoute[1]);if(!album)return fail(res,404,'Album not found.');if(Number(album.owner_id)!==Number(user.id))return fail(res,403,'You can only edit your own albums.');const mediaId=Number(albumRoute[2].split('/')[1]),item=db.prepare('SELECT * FROM album_media WHERE id=? AND album_id=?').get(mediaId,album.id);if(!item)return fail(res,404,'Media not found.');const remaining=db.prepare('SELECT id FROM album_media WHERE album_id=? AND id<>? ORDER BY position,id').all(album.id,mediaId);if(!remaining.length)return fail(res,400,'An album must keep at least one media item.');db.exec('BEGIN IMMEDIATE');try{db.prepare('DELETE FROM album_media WHERE id=?').run(mediaId);const update=db.prepare('UPDATE album_media SET position=? WHERE id=?');remaining.forEach((row,index)=>update.run(index,row.id));const nextCover=Number(album.cover_media_id)===mediaId?remaining[0].id:album.cover_media_id;db.prepare('UPDATE albums SET cover_media_id=?,updated_at=? WHERE id=?').run(nextCover,nowIso(),album.id);db.prepare('UPDATE stories SET cover_media_id=? WHERE id=?').run(nextCover,album.story_id);db.exec('COMMIT')}catch(error){db.exec('ROLLBACK');throw error}await storageProvider.delete(basename(item.storage_name)).catch(()=>{});return json(res,200,{album:albumObject(albumRecordById(album.id),user)});
  }
  if(albumRoute&&method==='DELETE'&&!albumRoute[2]){
    const user=requireUser(req,res);if(!user)return;const album=albumRecordById(albumRoute[1]);if(!album)return fail(res,404,'Album not found.');if(Number(album.owner_id)!==Number(user.id))return fail(res,403,'You can only delete your own albums.');const media=db.prepare('SELECT storage_name FROM album_media WHERE album_id=?').all(album.id);db.exec('BEGIN IMMEDIATE');try{db.prepare("UPDATE albums SET status='removed',updated_at=? WHERE id=?").run(nowIso(),album.id);db.prepare("UPDATE stories SET status='removed' WHERE id=?").run(album.story_id);db.exec('COMMIT')}catch(error){db.exec('ROLLBACK');throw error}for(const item of media)await storageProvider.delete(basename(item.storage_name)).catch(()=>{});return json(res,200,{ok:true});
  }
  if (method==='GET' && path==='/saved') {
    const user=requireUser(req,res);if(!user)return;
    const rows=db.prepare(`SELECT s.*,u.display_name AS creator,u.avatar_initial,a.slug AS album_slug,a.visibility AS album_visibility,m.mime_type AS cover_mime,m.original_name AS cover_name FROM saves x JOIN stories s ON s.id=x.story_id JOIN users u ON u.id=s.creator_id LEFT JOIN albums a ON a.story_id=s.id LEFT JOIN album_media m ON m.id=COALESCE(a.cover_media_id,s.cover_media_id) WHERE x.user_id=? AND s.status='published' AND (a.id IS NULL OR a.visibility<>'private' OR a.owner_id=?) ORDER BY x.created_at DESC`).all(user.id,user.id);
    return json(res,200,{items:rows.filter(row=>row.album_slug&&row.album_visibility==='public'&&canPublishAlbum(albumRecordBySlug(row.album_slug))).map(row=>storyObject(row,user))});
  }
  if(method==='GET'&&path==='/chats'){
    const user=requireMessageUser(req,res);if(!user)return;
    const items=db.prepare(`SELECT u.id AS creator_id,u.display_name AS creator,u.username,u.avatar_initial AS initial,u.avatar_path,u.role='admin' AS is_admin,
      (SELECT body FROM messages m WHERE (m.sender_id=? AND m.recipient_id=u.id) OR (m.sender_id=u.id AND m.recipient_id=?) ORDER BY m.created_at DESC LIMIT 1) AS last_message,
      (SELECT sender_id FROM messages m WHERE (m.sender_id=? AND m.recipient_id=u.id) OR (m.sender_id=u.id AND m.recipient_id=?) ORDER BY m.created_at DESC LIMIT 1) AS last_sender_id,
      (SELECT is_system_notice FROM messages m WHERE (m.sender_id=? AND m.recipient_id=u.id) OR (m.sender_id=u.id AND m.recipient_id=?) ORDER BY m.created_at DESC LIMIT 1) AS is_system_notice,
      (SELECT created_at FROM messages m WHERE (m.sender_id=? AND m.recipient_id=u.id) OR (m.sender_id=u.id AND m.recipient_id=?) ORDER BY m.created_at DESC LIMIT 1) AS last_at
      FROM users u WHERE u.id<>? AND EXISTS(SELECT 1 FROM messages m WHERE (m.sender_id=? AND m.recipient_id=u.id) OR (m.sender_id=u.id AND m.recipient_id=?)) ORDER BY last_at DESC`).all(user.id,user.id,user.id,user.id,user.id,user.id,user.id,user.id,user.id,user.id,user.id);
    for(const item of items){item.follows_you=!!db.prepare('SELECT 1 FROM follows WHERE follower_id=? AND creator_id=?').get(item.creator_id,user.id);item.you_follow=!!db.prepare('SELECT 1 FROM follows WHERE follower_id=? AND creator_id=?').get(user.id,item.creator_id);item.avatarUrl=item.avatar_path?`/uploads/${basename(item.avatar_path)}`:'';delete item.avatar_path}
    return json(res,200,{items});
  }
  const chatRoute=path.match(/^\/chats\/([^/]+)(?:\/messages)?$/);
  if(chatRoute&&method==='GET'){
    const user=requireMessageUser(req,res);if(!user)return;const otherRow=findCreator(chatRoute[1]);const other=otherRow&&{id:otherRow.id,name:otherRow.display_name,username:otherRow.username||slug(otherRow.display_name).replaceAll('-','_'),initial:otherRow.avatar_initial,avatarUrl:otherRow.avatar_path?`/uploads/${basename(otherRow.avatar_path)}`:'',isAdmin:otherRow.role==='admin',followsYou:!!db.prepare('SELECT 1 FROM follows WHERE follower_id=? AND creator_id=?').get(otherRow.id,user.id),youFollow:!!db.prepare('SELECT 1 FROM follows WHERE follower_id=? AND creator_id=?').get(user.id,otherRow.id)};if(!other)return fail(res,404,'Creator not found.');
    const items=db.prepare(`SELECT m.id,m.body,m.created_at,m.is_system_notice,u.id AS sender_id,u.display_name AS sender,u.avatar_initial AS initial FROM messages m JOIN users u ON u.id=m.sender_id WHERE (m.sender_id=? AND m.recipient_id=?) OR (m.sender_id=? AND m.recipient_id=?) ORDER BY m.created_at ASC`).all(user.id,other.id,other.id,user.id);
    return json(res,200,{creator:other,items});
  }
  if(chatRoute&&method==='POST'&&path.endsWith('/messages')){
    const user=requireUser(req,res);if(!user)return;const otherRow=findCreator(chatRoute[1]);const other=otherRow&&{id:otherRow.id};if(!other)return fail(res,404,'Creator not found.');if(other.id===user.id)return fail(res,400,'You cannot message yourself.');
    const input=await readJson(req);const body=String(input.body||'').trim();if(!body||body.length>2000)return fail(res,400,'Messages must be between 1 and 2,000 characters.');
    const result=db.prepare('INSERT INTO messages(sender_id,recipient_id,body,created_at) VALUES(?,?,?,?)').run(user.id,other.id,body,nowIso());const message=db.prepare(`SELECT m.id,m.body,m.created_at,u.id AS sender_id,u.display_name AS sender,u.avatar_initial AS initial FROM messages m JOIN users u ON u.id=m.sender_id WHERE m.id=?`).get(Number(result.lastInsertRowid));return json(res,201,{message});
  }
  if (method==='GET' && path.startsWith('/creators/')) {
    const creatorSlug=path.slice('/creators/'.length);const creator=findCreator(creatorSlug);
    if(!creator)return fail(res,404,'Creator not found.');
    const user=sessionUser(req);const rows=storyRows('AND s.creator_id=?',[creator.id]);
    const followCount=Number(db.prepare('SELECT COUNT(*) AS n FROM follows WHERE creator_id=?').get(creator.id).n);
    return json(res,200,{creator:{id:creator.id,name:creator.display_name,username:creator.username||slug(creator.display_name).replaceAll('-','_'),bio:creator.bio||'',initial:creator.avatar_initial,avatarUrl:creator.avatar_path?`/uploads/${basename(creator.avatar_path)}`:'',onlyfansUrl:creator.onlyfans_url||'',followers:followCount,following:!!user&&!!db.prepare('SELECT 1 FROM follows WHERE follower_id=? AND creator_id=?').get(user.id,creator.id)},items:rows.map(row=>storyObject(row,user))});
  }

  const storyRoute=path.match(/^\/stories\/(\d+)(?:\/(like|save|repost|comments|report))?$/);
  if(storyRoute){
    const id=Number(storyRoute[1]), action=storyRoute[2]||'';
    if(method==='GET'&&!action){const user=sessionUser(req),unlistedSlug=url.searchParams.get('album')||'';if(!rateLimit(req,res,'story-read',{limit:120,windowMs:15*60*1000,identity:String(id)}))return;const row=lookupStory(id,user,unlistedSlug);if(!row)return fail(res,404,'Video not found.');db.prepare('UPDATE stories SET views=views+1 WHERE id=?').run(id);return respondStory(res,id,user,unlistedSlug);}
    if(method==='GET'&&action==='comments'){
      if(!lookupStory(id,sessionUser(req),url.searchParams.get('album')||''))return fail(res,404,'Video not found.');
      const album=db.prepare('SELECT a.allow_comments FROM albums a WHERE a.story_id=?').get(id);if(album&&!album.allow_comments)return fail(res,403,'Comments are turned off for this album.');
      const rows=db.prepare(`SELECT c.id,c.body,c.created_at,u.display_name AS author,u.avatar_initial AS initial FROM comments c JOIN users u ON u.id=c.user_id WHERE c.story_id=? ORDER BY c.created_at ASC`).all(id);
      return json(res,200,{items:rows});
    }
    if(method==='POST'&&action==='like'){
      const user=requireUser(req,res);if(!user)return;if(!lookupStory(id,user,url.searchParams.get('album')||''))return fail(res,404,'Video not found.');
      const liked=setToggle('likes','user_id',user.id,'story_id',id);return respondStory(res,id,user);
    }
    if(method==='POST'&&action==='save'){
      const user=requireUser(req,res);if(!user)return;if(!lookupStory(id,user,url.searchParams.get('album')||''))return fail(res,404,'Video not found.');
      const saved=setToggle('saves','user_id',user.id,'story_id',id);return json(res,200,{saved,story:storyObject(lookupStory(id,user,url.searchParams.get('album')||''),user)});
    }
    if(method==='POST'&&action==='repost'){
      const user=requireUser(req,res);if(!user)return;if(!lookupStory(id,user,url.searchParams.get('album')||''))return fail(res,404,'Video not found.');
      const reposted=setToggle('reposts','user_id',user.id,'story_id',id);return json(res,200,{reposted});
    }
    if(method==='POST'&&action==='comments'){
      const user=requireUser(req,res);if(!user)return;if(!lookupStory(id,user,url.searchParams.get('album')||''))return fail(res,404,'Video not found.');
      const album=db.prepare('SELECT a.allow_comments FROM albums a WHERE a.story_id=?').get(id);if(album&&!album.allow_comments)return fail(res,403,'Comments are turned off for this album.');
      const input=await readJson(req);const body=String(input.body||'').trim();if(!body||body.length>1000)return fail(res,400,'Comments must be between 1 and 1,000 characters.');
      const result=db.prepare('INSERT INTO comments(user_id,story_id,body,created_at) VALUES(?,?,?,?)').run(user.id,id,body,nowIso());
      const comment=db.prepare(`SELECT c.id,c.body,c.created_at,u.display_name AS author,u.avatar_initial AS initial FROM comments c JOIN users u ON u.id=c.user_id WHERE c.id=?`).get(Number(result.lastInsertRowid));
      return json(res,201,{comment});
    }
    if(method==='POST'&&action==='report'){
      const user=requireUser(req,res);if(!user)return;if(!lookupStory(id,user))return fail(res,404,'Video not found.');
      const input=await readJson(req);if(!String(input.reason||'').trim())return fail(res,400,'Choose a report reason.');
      recordReport({reporterId:user.id,storyId:id,input});return json(res,201,{ok:true});
    }
  }
  const creatorRoute=path.match(/^\/creators\/([^/]+)\/(follow|report)$/);
  if(creatorRoute&&method==='POST'){
    const user=requireUser(req,res);if(!user)return;
    const creator=findCreator(creatorRoute[1]);if(!creator)return fail(res,404,'Creator not found.');
    if(creatorRoute[2]==='follow'){
      if(creator.id===user.id)return fail(res,400,'You cannot follow your own profile.');
      const following=setToggle('follows','follower_id',user.id,'creator_id',creator.id);return json(res,200,{following,followers:Number(db.prepare('SELECT COUNT(*) AS n FROM follows WHERE creator_id=?').get(creator.id).n)});
    }
    const input=await readJson(req);if(!String(input.reason||'').trim())return fail(res,400,'Choose a report reason.');
    recordReport({reporterId:user.id,targetUserId:creator.id,input});return json(res,201,{ok:true});
  }
  if(method==='POST'&&path==='/stories/upload')return fail(res,410,'The legacy single-file upload route is disabled. Use the post uploader so media receives its private processing record.');
  if(method==='POST'&&path==='/reports/profile'){
    const user=requireUser(req,res);if(!user)return;const input=await readJson(req);const creator=findCreator(input.creator);
    if(!creator)return fail(res,404,'Creator not found.');if(!String(input.reason||'').trim())return fail(res,400,'Choose a report reason.');
    recordReport({reporterId:user.id,targetUserId:creator.id,input});return json(res,201,{ok:true});
  }
  if(method==='DELETE'&&path.startsWith('/stories/')){
    const user=requireUser(req,res);if(!user)return;const id=Number(path.split('/').at(-1));const row=db.prepare('SELECT creator_id,media_path FROM stories WHERE id=?').get(id);
    if(!row)return fail(res,404,'Video not found.');if(row.creator_id!==user.id)return fail(res,403,'You can only remove your own uploads.');
    db.prepare("UPDATE stories SET status='removed' WHERE id=?").run(id);if(row.media_path)await storageProvider.delete(basename(row.media_path)).catch(()=>{});return json(res,200,{ok:true});
  }
  return fail(res,404,'API endpoint not found.');
}

async function sendStoredMedia(req,res,{key,mimeType,cacheControl,authorize}){
  let object;
  try{object=await authorizedStorage.openRead(key,authorize,{metadata:{contentType:mimeType}})}catch{return fail(res,404,'Media not found.')}
  const range=req.headers.range;
  res.setHeader('Content-Type',mimeType);res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('Accept-Ranges','bytes');res.setHeader('Cache-Control',cacheControl);
  if(range){const match=range.match(/^bytes=(\d+)-(\d*)$/);if(!match){object.stream.destroy();res.writeHead(416);return res.end()}
    const start=Number(match[1]),end=Math.min(match[2]?Number(match[2]):object.size-1,object.size-1);object.stream.destroy();
    if(!Number.isSafeInteger(start)||!Number.isSafeInteger(end)||start>end||start>=object.size){res.writeHead(416);return res.end()}
    try{object=await authorizedStorage.openRead(key,authorize,{start,end,metadata:{contentType:mimeType}})}catch{return fail(res,404,'Media not found.')}
    res.writeHead(206,{'Content-Range':`bytes ${start}-${end}/${object.size}`,'Content-Length':end-start+1});object.stream.on('error',()=>res.destroy());return object.stream.pipe(res)
  }
  res.writeHead(200,{'Content-Length':object.size});object.stream.on('error',()=>res.destroy());return object.stream.pipe(res)
}

const app=createServer(async(req,res)=>{
  cors(req,res);
  const url=new URL(req.url,'http://localhost');
  if(url.pathname.startsWith('/api/')){
    const requestId=randomBytes(12).toString('hex'),started=Date.now();let errorCode;
    res.setHeader('X-Request-ID',requestId);
    res.once('finish',()=>{if(res.statusCode>=500)operationalLog('error','api_request_failed',{requestId,method:req.method,route:'api',status:res.statusCode,durationMs:Date.now()-started,errorCode:errorCode||`HTTP_${res.statusCode}`});});
    try { await handleApi(req,res,new URL(url.pathname.slice(4)+url.search,'http://api.local')); }
    catch(error){errorCode=safeErrorCode(error);if(!res.headersSent)fail(res,error.status||500,error.status?error.message:'Server error.');else res.destroy();}
    return;
  }
  if(url.pathname.startsWith('/uploads/')){
    const decoded=safeDecode(url.pathname.slice('/uploads/'.length));if(!decoded||decoded!==basename(decoded)||decoded.includes('\\')||decoded.includes('\0')||decoded==='.'||decoded==='..')return fail(res,404,'Media not found.');
    const name=decoded,user=sessionUser(req),associated=db.prepare(`SELECT m.id,m.storage_name,m.mime_type,a.id AS album_id,a.slug,a.visibility,a.status,s.status AS story_status,a.owner_id FROM album_media m JOIN albums a ON a.id=m.album_id JOIN stories s ON s.id=a.story_id WHERE m.storage_name=?`).get(name);
    let type='';
    if(associated){if(associated.visibility==='unlisted'&&Number(associated.owner_id)!==Number(user?.id)&&!rateLimit(req,res,'unlisted-media-read',{limit:30,windowMs:15*60*1000}))return;if(!albumMediaAccessible(associated,user,{unlistedSlug:url.searchParams.get('album')||''}))return fail(res,404,'Media not found.');type=associated.mime_type}
    else {const avatar=db.prepare('SELECT id FROM users WHERE avatar_path=? LIMIT 1').get(name);if(!avatar||Number(avatar.id)!==Number(user?.id))return fail(res,404,'Media not found.');type=({'.jpg':'image/jpeg','.png':'image/png','.webp':'image/webp'})[extname(name).toLowerCase()]||'';if(!type)return fail(res,404,'Media not found.')}
    return sendStoredMedia(req,res,{key:name,mimeType:type,cacheControl:associated&&associated.visibility==='public'?'private, max-age=3600':'private, no-store',authorize:()=>associated?albumMediaAccessible(associated,user,{unlistedSlug:url.searchParams.get('album')||''}):Number(db.prepare('SELECT id FROM users WHERE avatar_path=? LIMIT 1').get(name)?.id)===Number(user?.id)});
  }
  const mediaMatch=url.pathname.match(/^\/media\/(\d+)$/);
  if(mediaMatch){
    const item=db.prepare(`SELECT m.id,m.storage_name,m.mime_type,a.id AS album_id,a.slug,a.visibility,a.status,s.status AS story_status,a.owner_id FROM album_media m JOIN albums a ON a.id=m.album_id JOIN stories s ON s.id=a.story_id WHERE m.id=?`).get(Number(mediaMatch[1]));const user=sessionUser(req);if(item?.visibility==='unlisted'&&Number(item.owner_id)!==Number(user?.id)&&!rateLimit(req,res,'unlisted-media-read',{limit:30,windowMs:15*60*1000}))return;if(!item||!albumMediaAccessible(item,user,{unlistedSlug:url.searchParams.get('album')||''}))return fail(res,404,'Media not found.');
    return sendStoredMedia(req,res,{key:basename(item.storage_name),mimeType:item.mime_type,cacheControl:item.visibility==='public'?'private, max-age=3600':'private, no-store',authorize:()=>albumMediaAccessible(item,user,{unlistedSlug:url.searchParams.get('album')||''})});
  }
  if(url.pathname==='/admin'||url.pathname==='/admin/'){
    try{const file=await readFile(join(root,'admin.html'));res.writeHead(200,{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store'});res.end(file)}catch{fail(res,404,'Admin panel is not installed.')}return;
  }
  const requested=safeDecode(url.pathname);if(requested===null)return fail(res,404,'Not found.');
  const assetName=basename(requested);if(extname(requested)&&!['index.html','admin.html'].includes(assetName))return fail(res,404,'Not found.');
  const target=requested==='/'||!extname(requested)?join(root,'index.html'):join(root,assetName);
  try {const file=await readFile(target);res.writeHead(200,{'Content-Type':target.endsWith('.html')?'text/html; charset=utf-8':'application/octet-stream'});res.end(file);}
  catch {fail(res,404,'Not found.');}
});

publishDueAlbums();
const scheduleTimer=setInterval(()=>{try{publishDueAlbums()}catch(error){operationalLog('error','scheduled_publication_failed',{component:'scheduler',errorCode:safeErrorCode(error)})}},15000);
app.listen(serverPort,bindHost,()=>operationalLog('info','server_started',{component:'api',port:serverPort}));
for(const signal of ['SIGINT','SIGTERM'])process.on(signal,()=>{clearInterval(scheduleTimer);db.close();app.close(()=>process.exit(0));});
