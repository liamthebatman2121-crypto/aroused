import test from 'node:test';
import assert from 'node:assert/strict';
import { Readable } from 'node:stream';
import { DatabaseSync } from 'node:sqlite';
import { enqueueMediaJob, createMediaWorker } from '../processing/media-worker.mjs';
import { createMediaSafetyProcessor } from '../processing/media-safety-processor.mjs';
import { SCAN_CHECKS, ScannerProvider, runMediaSafetyChecks } from '../processing/scanner-provider.mjs';

const allChecks=[...new Set(Object.values(SCAN_CHECKS).flat())];
function fixture(mime='image/jpeg') {
  const db=new DatabaseSync(':memory:');
  db.exec(`CREATE TABLE albums(id INTEGER PRIMARY KEY,story_id INTEGER,status TEXT,updated_at TEXT);
    CREATE TABLE stories(id INTEGER PRIMARY KEY,status TEXT);
    CREATE TABLE album_media(id INTEGER PRIMARY KEY,album_id INTEGER,storage_name TEXT,mime_type TEXT);
    CREATE TABLE media_pipeline(media_id INTEGER PRIMARY KEY,status TEXT,malware_status TEXT,processing_status TEXT,known_content_status TEXT,safety_status TEXT,moderation_status TEXT,updated_at TEXT);
    CREATE TABLE processing_jobs(id INTEGER PRIMARY KEY,media_id INTEGER,status TEXT,attempts INTEGER,available_at INTEGER,created_at TEXT,updated_at TEXT,error_code TEXT);
    CREATE TABLE media_scan_results(id INTEGER PRIMARY KEY,media_id INTEGER,provider TEXT,result TEXT,detail_code TEXT,created_at TEXT,check_type TEXT,provider_reference TEXT,started_at TEXT,completed_at TEXT,audit_metadata_json TEXT);
    CREATE TABLE moderation_cases(id INTEGER PRIMARY KEY,album_id INTEGER,media_id INTEGER,category TEXT,priority TEXT,status TEXT,restricted INTEGER,created_at TEXT,updated_at TEXT);
    CREATE TABLE security_events(id INTEGER PRIMARY KEY,user_id INTEGER,event_type TEXT,severity TEXT,detail_code TEXT,created_at TEXT);
    INSERT INTO albums VALUES(2,3,'draft','2026-10-10T00:00:00.000Z');
    INSERT INTO stories VALUES(3,'draft');
    INSERT INTO album_media VALUES(4,2,'private/media-4','${mime}');
    INSERT INTO media_pipeline VALUES(4,'QUARANTINED','BLOCKED','NOT_CONFIGURED','NOT_CONFIGURED','NOT_CONFIGURED','PENDING','2026-10-10T00:00:00.000Z');`);
  return db;
}
class FixedProvider extends ScannerProvider {
  constructor(outcomes={}, checks=allChecks) { super({providerId:'synthetic-provider-v1',checks}); this.outcomes=outcomes; this.calls=[]; }
  async scan(input) {
    this.calls.push(input);
    const media=await input.openMedia();
    for await (const _chunk of media.stream) {}
    const outcome=this.outcomes[input.checkType]||'clear';
    return {outcome,providerId:this.providerId,providerReference:`synthetic-${input.checkType}`,auditMetadata:{algorithm:'fixture-v1',latencyMs:2}};
  }
}
const deterministicNow=(()=>{let n=0;return()=>new Date(Date.UTC(2026,9,10,0,0,n++))})();

test('image checks record normalized outcomes and remain quarantined after all simulated clears',async()=>{
  const db=fixture(),provider=new FixedProvider();
  try {
    const result=await runMediaSafetyChecks({db,mediaId:4,jobId:'job-7',mediaType:'image',providers:[provider],openMedia:async()=>({stream:Readable.from(['synthetic']),size:9}),now:deterministicNow});
    assert.equal(result.status,'clear');assert.equal(result.artifactsVerified,true);
    assert.deepEqual(provider.calls.map(call=>call.checkType),SCAN_CHECKS.image);
    assert.ok(provider.calls.every(call=>call.idempotencyKey.startsWith('media-scan:4:job-7:')));
    const pipeline=db.prepare('SELECT * FROM media_pipeline WHERE media_id=4').get();
    assert.equal(pipeline.status,'QUARANTINED');assert.equal(pipeline.malware_status,'CLEAN');assert.equal(pipeline.known_content_status,'CLEAR');assert.equal(pipeline.safety_status,'CLEAR');assert.equal(pipeline.processing_status,'READY');assert.equal(pipeline.moderation_status,'PENDING');
    const rows=db.prepare('SELECT provider,result,check_type,provider_reference,started_at,completed_at,audit_metadata_json,detail_code FROM media_scan_results ORDER BY id').all();
    assert.equal(rows.length,4);assert.ok(rows.every(row=>row.provider==='synthetic-provider-v1'&&row.result==='clear'&&row.provider_reference&&row.started_at&&row.completed_at&&JSON.parse(row.audit_metadata_json).algorithm==='fixture-v1'&&row.detail_code===null));
  } finally {db.close()}
});

test('video plan uses known-video matching and suspicious matches create restricted critical quarantine',async()=>{
  const db=fixture('video/mp4'),provider=new FixedProvider({known_csam_video:'match'});
  try {
    const result=await runMediaSafetyChecks({db,mediaId:4,jobId:'v-1',mediaType:'video',providers:[provider],openMedia:async()=>({stream:Readable.from(['synthetic-video']),size:14}),now:deterministicNow});
    assert.deepEqual(provider.calls.map(call=>call.checkType),SCAN_CHECKS.video);assert.equal(result.reviewRequired,true);assert.equal(result.artifactsVerified,false);
    const item=db.prepare('SELECT status,moderation_status FROM media_pipeline WHERE media_id=4').get();assert.equal(item.status,'QUARANTINED');assert.equal(item.moderation_status,'PENDING');
    const caseRow=db.prepare('SELECT category,priority,restricted,status FROM moderation_cases WHERE media_id=4').get();assert.deepEqual({...caseRow},{category:'suspected_minor',priority:'critical',restricted:1,status:'open'});
    assert.equal(db.prepare('SELECT detail_code FROM security_events').get().detail_code,'KNOWN_CSAI_MATCH');
    assert.equal(db.prepare('SELECT status FROM albums WHERE id=2').get().status,'processing');assert.equal(db.prepare('SELECT status FROM stories WHERE id=3').get().status,'draft');
  } finally {db.close()}
});

test('review-required non-consensual outcome is held for restricted human review',async()=>{
  const db=fixture(),provider=new FixedProvider({prohibited_content_review:'review_required'});
  try {
    const result=await runMediaSafetyChecks({db,mediaId:4,jobId:'review-1',mediaType:'image',providers:[provider],openMedia:async()=>({stream:Readable.from(['synthetic'])}),now:deterministicNow});
    assert.equal(result.status,'review_required');assert.equal(result.retryable,false);
    const item=db.prepare('SELECT safety_status,status FROM media_pipeline WHERE media_id=4').get();assert.deepEqual({...item},{safety_status:'REVIEW_REQUIRED',status:'QUARANTINED'});
    const review=db.prepare('SELECT category,priority,restricted FROM moderation_cases WHERE media_id=4').get();assert.deepEqual({...review},{category:'non_consensual',priority:'high',restricted:1});
  } finally {db.close()}
});

test('missing, unavailable, malformed, ambiguous, and timed-out scanners fail closed with audit rows',async()=>{
  const db=fixture();
  try {
    const missing=await runMediaSafetyChecks({db,mediaId:4,jobId:'missing',mediaType:'image',providers:[],openMedia:async()=>({stream:Readable.from(['synthetic'])}),now:deterministicNow});
    assert.equal(missing.status,'unavailable');assert.equal(missing.retryable,true);assert.ok(missing.results.every(row=>row.outcome==='unavailable'));
    assert.ok(db.prepare('SELECT COUNT(*) n FROM media_scan_results').get().n===4);
    const malformed=new FixedProvider();malformed.scan=async()=>({outcome:'clear',providerId:malformed.providerId,rawPayload:'sensitive'});
    const invalid=await runMediaSafetyChecks({db,mediaId:4,jobId:'invalid',mediaType:'image',providers:[malformed],openMedia:async()=>({stream:Readable.from(['synthetic'])}),now:deterministicNow});
    assert.equal(invalid.status,'unavailable');assert.ok(invalid.results.every(row=>row.errorCode==='INVALID_SCANNER_RESPONSE'));
    assert.equal(db.prepare("SELECT COUNT(*) n FROM media_scan_results WHERE audit_metadata_json LIKE '%sensitive%' OR provider_reference LIKE '%payload%'").get().n,0);
    const timeoutProvider=new FixedProvider();timeoutProvider.scan=async({signal})=>await new Promise((resolve)=>signal.addEventListener('abort',()=>resolve({outcome:'unavailable',providerId:timeoutProvider.providerId}),{once:true}));
    const timeout=await runMediaSafetyChecks({db,mediaId:4,jobId:'timeout',mediaType:'image',providers:[timeoutProvider],openMedia:async()=>({stream:Readable.from(['synthetic'])}),now:deterministicNow,timeoutMs:5});
    assert.equal(timeout.status,'unavailable');assert.ok(timeout.results.every(row=>row.errorCode==='SCANNER_TIMEOUT'));
    const duplicate=await runMediaSafetyChecks({db,mediaId:4,jobId:'duplicate-provider',mediaType:'image',providers:[new FixedProvider(),new FixedProvider()],openMedia:async()=>({stream:Readable.from(['synthetic'])}),now:deterministicNow});
    assert.equal(duplicate.status,'unavailable');assert.ok(duplicate.results.every(row=>row.errorCode==='SCANNER_CONFIGURATION_AMBIGUOUS'));
    const nonConsumer=new FixedProvider();nonConsumer.scan=async()=>({outcome:'clear',providerId:nonConsumer.providerId});
    const unread=await runMediaSafetyChecks({db,mediaId:4,jobId:'unread',mediaType:'image',providers:[nonConsumer],openMedia:async()=>({stream:Readable.from(['synthetic'])}),now:deterministicNow});
    assert.equal(unread.status,'unavailable');assert.ok(unread.results.every(row=>row.errorCode==='SCANNER_DID_NOT_CONSUME_MEDIA'));
    assert.equal(db.prepare('SELECT status FROM media_pipeline WHERE media_id=4').get().status,'QUARANTINED');
  } finally {db.close()}
});

test('video safety processor streams only from private storage and maps scanner failures to retryable jobs',async()=>{
  const db=fixture('video/webm');let reads=0;const provider=new FixedProvider({malware:'unavailable'});
  provider.scan=async input=>{provider.calls.push(input);const object=await input.openMedia();for await(const _chunk of object.stream){}return {outcome:provider.outcomes[input.checkType]||'clear',providerId:provider.providerId,providerReference:`synthetic-${input.checkType}`,auditMetadata:{algorithm:'fixture-v1'}}};
  const storage={async openRead(key){reads++;assert.equal(key,'private/media-4');return {stream:Readable.from(['synthetic']),size:9,contentType:'video/webm'}}};
  try {
    const processor=createMediaSafetyProcessor({db,storage,providers:[provider],now:deterministicNow});
    const result=await processor({id:22,mediaId:4});assert.equal(result.status,'unavailable');assert.equal(result.retryable,true);assert.equal(reads,4);assert.ok(provider.calls.every(call=>call.mediaType==='video'));
    const enqueue1=enqueueMediaJob(db,4,{status:'queued',now:Date.UTC(2026,9,10)}),enqueue2=enqueueMediaJob(db,4,{status:'queued',now:Date.UTC(2026,9,10)});
    assert.equal(enqueue1.inserted,true);assert.equal(enqueue2.inserted,false);assert.equal(db.prepare('SELECT COUNT(*) n FROM processing_jobs WHERE media_id=4').get().n,1);
  } finally {db.close()}
});

test('worker retries scanner timeouts and parks match/review jobs without clearing quarantine',async()=>{
  const db=fixture();
  db.exec("INSERT INTO processing_jobs VALUES(1,4,'queued',0,1000,'2026-10-10T00:00:00.000Z','2026-10-10T00:00:00.000Z',NULL)");
  let currentTime=1000;
  try {
    const retryWorker=createMediaWorker({db,now:()=>currentTime,retryBaseMs:10,processor:async()=>({retryable:true,errorCode:'SCANNER_TIMEOUT'})});
    assert.equal((await retryWorker.runOnce()).status,'retry-scheduled');assert.equal(db.prepare('SELECT status,error_code FROM processing_jobs WHERE id=1').get().status,'retry');
    db.prepare("UPDATE processing_jobs SET status='queued',available_at=1000 WHERE id=1").run();
    const reviewWorker=createMediaWorker({db,now:()=>currentTime,processor:async()=>({reviewRequired:true,errorCode:'SCAN_REVIEW_REQUIRED'})});
    assert.equal((await reviewWorker.runOnce()).status,'review_required');assert.equal(db.prepare('SELECT status,error_code FROM processing_jobs WHERE id=1').get().status,'review_required');
    assert.equal(db.prepare('SELECT status FROM media_pipeline WHERE media_id=4').get().status,'QUARANTINED');
  } finally {db.close()}
});
