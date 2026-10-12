import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes, scryptSync } from 'node:crypto';
import { spawn } from 'node:child_process';
import { request as httpRequest } from 'node:http';
import { DatabaseSync } from 'node:sqlite';
import { mkdtemp, mkdir, rm, writeFile, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer } from 'node:net';
import { Readable } from 'node:stream';
import { fileURLToPath } from 'node:url';
import { ScannerProvider, runMediaSafetyChecks } from '../processing/scanner-provider.mjs';

const root=fileURLToPath(new URL('..',import.meta.url));
const freePort=()=>new Promise((resolve,reject)=>{const server=createServer();server.once('error',reject);server.listen(0,'127.0.0.1',()=>{const {port}=server.address();server.close(error=>error?reject(error):resolve(port))})});
const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const sessionCookie=token=>`aroused_session=${token}`;

test('direct API requests enforce auth, role, media, publication, schedule, CSRF and rate-limit gates',async t=>{
  const dir=await mkdtemp(join(tmpdir(),'aroused-security-')),port=await freePort(),adminEmail=`root-${Date.now()}@example.test`,adminPassword=`Test!${Date.now()}-Security-Readiness`;
  const databasePath=join(dir,'data','aroused.sqlite'),uploadDir=join(dir,'uploads');
  const child=spawn(process.execPath,['server.mjs'],{cwd:root,env:{...process.env,NODE_ENV:'test',AROUSED_API_PORT:String(port),AROUSED_DATA_DIR:join(dir,'data'),AROUSED_UPLOAD_DIR:uploadDir,AROUSED_MAX_UPLOAD_BYTES:'4096',AROUSED_ADMIN_EMAIL:adminEmail,AROUSED_ADMIN_PASSWORD:adminPassword,RESEND_API_KEY:'',AROUSED_FROM_EMAIL:''},stdio:['ignore','pipe','pipe']});
  let logs='';child.stdout.on('data',d=>logs+=d.toString());child.stderr.on('data',d=>logs+=d.toString());
  t.after(async()=>{if(child.exitCode===null){await new Promise(resolve=>{child.once('exit',resolve);child.kill('SIGTERM');setTimeout(resolve,2000).unref()})}await rm(dir,{recursive:true,force:true})});
  const base=`http://127.0.0.1:${port}/api`,host=`http://127.0.0.1:${port}`;
  let health;for(let i=0;i<100;i++){if(child.exitCode!==null)throw new Error(`Server exited during startup: ${logs}`);try{health=await fetch(`${base}/health`);break}catch{await sleep(100)}}assert.ok(health,`Server did not start: ${logs}`);
  const db=new DatabaseSync(databasePath),now=new Date().toISOString(),policy='creator-upload-2026-10-08',rights='creator-rights-2026-10-08';
  const insertUser=db.prepare(`INSERT INTO users(display_name,username,email,password_hash,avatar_initial,adult_confirmed,created_at,email_verified_at,terms_accepted_at,guidelines_accepted_at,age_status,age_verified_at,creator_agreement_version,role) VALUES(?,?,?,?,?,1,?,?,?,?, 'verified',?,?,?)`);
  const createAccount=(name,role='user')=>Number(insertUser.run(name,name.toLowerCase(),`${name.toLowerCase()}-${Date.now()}-${randomBytes(3).toString('hex')}@example.test`,'test-hash',name[0],now,now,now,now,now,policy,role).lastInsertRowid);
  const createCookie=userId=>{const token=randomBytes(32).toString('base64url');db.prepare('INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)').run(createHash('sha256').update(token).digest('hex'),userId,Date.now()+3600_000);return sessionCookie(token)};
  const adminLogin=await fetch(`${base}/auth/login`,{method:'POST',headers:{'Content-Type':'application/json','Sec-Fetch-Site':'same-origin'},body:JSON.stringify({email:adminEmail,password:adminPassword})});assert.equal(adminLogin.status,200);let adminCookie=adminLogin.headers.get('set-cookie').split(';')[0];
  assert.match(adminLogin.headers.get('set-cookie'),/HttpOnly/i);assert.match(adminLogin.headers.get('set-cookie'),/SameSite=Strict/i);
  const ownerId=createAccount('Owner'),otherId=createAccount('Other'),moderatorId=createAccount('Mod','moderator'),seniorId=createAccount('Senior','senior_moderator');
  const ownerCookie=createCookie(ownerId),otherCookie=createCookie(otherId),moderatorCookie=createCookie(moderatorId),seniorCookie=createCookie(seniorId);
  const jsonHeaders={'Content-Type':'application/json','Sec-Fetch-Site':'same-origin'};
  const call=(path,{method='GET',cookie='',body,headers={}}={})=>fetch(`${base}${path}`,{method,headers:{...headers,...(cookie?{Cookie:cookie}:{})},...(body===undefined?{}:{body:typeof body==='string'?body:JSON.stringify(body)})});
  const mediaCall=(id,cookie='')=>fetch(`${host}/media/${id}`,{headers:cookie?{Cookie:cookie}:{}});

  // Authentication and CSRF: unauthenticated writes denied, same-origin authenticated writes allowed, hostile or missing browser provenance denied.
  assert.equal((await call('/albums',{method:'POST',headers:jsonHeaders,body:{}})).status,401);
  assert.equal((await call('/reports/profile',{method:'POST',headers:jsonHeaders,body:{creator:'Owner',reason:'spam'}})).status,401);
  assert.equal((await call('/session',{cookie:ownerCookie})).status,200);
  assert.equal((await call('/auth/login',{method:'POST',headers:{...jsonHeaders,Origin:'https://evil.example'},body:{email:adminEmail,password:adminPassword}})).status,403);
  assert.equal((await fetch(`${base}/account`,{method:'PATCH',headers:{Cookie:ownerCookie,'Content-Type':'application/json'},body:'{}'})).status,403);
  const knownBadLogin=await call('/auth/login',{method:'POST',headers:jsonHeaders,body:{email:adminEmail,password:'wrong-password'}}),unknownBadLogin=await call('/auth/login',{method:'POST',headers:jsonHeaders,body:{email:'not-registered@example.test',password:'wrong-password'}});assert.equal(knownBadLogin.status,401);assert.equal(unknownBadLogin.status,401);assert.equal((await knownBadLogin.json()).error,(await unknownBadLogin.json()).error);
  const signupDeliveryFailure=await call('/auth/signup',{method:'POST',headers:jsonHeaders,body:{displayName:'Enum Test',email:'enum-new@example.test',password:'Valid!Password123',adultConfirmed:true,termsAccepted:true,guidelinesAccepted:true}});
  const duplicateSignup=await call('/auth/signup',{method:'POST',headers:jsonHeaders,body:{displayName:'Admin',email:adminEmail,password:'Valid!Password123',adultConfirmed:true,termsAccepted:true,guidelinesAccepted:true}});
  assert.equal(signupDeliveryFailure.status,503);assert.equal(duplicateSignup.status,503);assert.deepEqual(await signupDeliveryFailure.json(),await duplicateSignup.json());
  assert.equal(Number(db.prepare('SELECT COUNT(*) n FROM pending_email_verifications').get().n),0);
  assert.match(logs,/email_delivery_failed/);assert.match(logs,/EMAIL_DELIVERY_NOT_CONFIGURED/);assert.doesNotMatch(logs,/enum-new@example\.test|Valid!Password123|\b\d{6}\b/);
  assert.equal((await call('/auth/oauth/google/start',{method:'POST',headers:jsonHeaders,body:{mode:'login'}})).status,503);
  assert.equal((await fetch(`${base}/auth/oauth/providers`).then(response=>response.json())).providers.google.available,false);
  const resendMissing=await call('/auth/resend-code',{method:'POST',headers:jsonHeaders,body:{email:'missing@example.test'}});assert.equal(resendMissing.status,202);
  const missingVerify=await call('/auth/verify-email',{method:'POST',headers:jsonHeaders,body:{email:'missing@example.test',code:'123456'}});assert.equal(missingVerify.status,400);
  db.prepare('INSERT INTO pending_email_verifications(email,display_name,password_hash,code_hash,expires_at,next_send_at,attempts,created_at) VALUES(?,?,?,?,?,?,0,?)').run('pending@example.test','Pending','placeholder','0'.repeat(64),Date.now()+600_000,Date.now(),now);
  const invalidVerify=await call('/auth/verify-email',{method:'POST',headers:jsonHeaders,body:{email:'pending@example.test',code:'123456'}});assert.equal(invalidVerify.status,400);assert.equal((await missingVerify.json()).error,(await invalidVerify.json()).error);

  // Authenticated upload is allowed for an eligible test account, but remains private/unpublished without genuine provider results.
  const unauthUpload=await call('/albums',{method:'POST',headers:{'Sec-Fetch-Site':'same-origin'}});assert.equal(unauthUpload.status,401);
  const form=new FormData();form.set('title','Gate fixture');form.set('mode','draft');form.set('visibility','public');form.set('publishMode','immediate');form.append('media',new Blob([Uint8Array.from([0xff,0xd8,0xff,0xe0])],{type:'image/jpeg'}),'fixture.jpg');
  const upload=await fetch(`${base}/albums`,{method:'POST',headers:{Cookie:ownerCookie,'Sec-Fetch-Site':'same-origin'},body:form});assert.equal(upload.status,201);const album=(await upload.json()).album;assert.equal(album.status,'draft');assert.equal(album.media.length,1);const mediaId=album.media[0].id,storyId=album.storyId,slug=album.slug,storageName=db.prepare('SELECT storage_name FROM album_media WHERE id=?').get(mediaId).storage_name;
  const albumsBeforeOversize=Number(db.prepare('SELECT COUNT(*) n FROM albums').get().n),mediaBeforeOversize=Number(db.prepare('SELECT COUNT(*) n FROM album_media').get().n);
  const oversizedForm=new FormData();oversizedForm.set('title','Oversized fixture');oversizedForm.set('padding','x'.repeat(6000));oversizedForm.append('media',new Blob([Uint8Array.from([0xff,0xd8,0xff,0xe0])],{type:'image/jpeg'}),'fixture.jpg');
  const oversizedUpload=await fetch(`${base}/albums`,{method:'POST',headers:{Cookie:ownerCookie,'Sec-Fetch-Site':'same-origin'},body:oversizedForm});assert.equal(oversizedUpload.status,413);
  assert.equal(Number(db.prepare('SELECT COUNT(*) n FROM albums').get().n),albumsBeforeOversize);assert.equal(Number(db.prepare('SELECT COUNT(*) n FROM album_media').get().n),mediaBeforeOversize);
  const declaredOversizeStatus=await new Promise((resolve,reject)=>{
    const request=httpRequest(`${base}/albums`,{method:'POST',headers:{Cookie:ownerCookie,'Sec-Fetch-Site':'same-origin','Content-Type':'multipart/form-data; boundary=test','Content-Length':'4097'}},response=>{response.resume();response.once('end',()=>resolve(response.statusCode))});
    request.once('error',reject);request.end();
  });
  assert.equal(declaredOversizeStatus,413);
  const invalidUploads=[
    {mime:'text/plain',name:'fixture.txt',bytes:Buffer.from('not media')},
    {mime:'image/jpeg',name:'fixture.jpg',bytes:Buffer.from('not a jpeg')},
    {mime:'image/png',name:'fixture.jpg',bytes:Buffer.from([137,80,78,71,13,10,26,10])},
  ];
  for(const [index,item] of invalidUploads.entries()){
    const invalidForm=new FormData();invalidForm.set('title',`Invalid ${index}`);invalidForm.append('media',new Blob([item.bytes],{type:item.mime}),item.name);
    const invalidUpload=await fetch(`${base}/albums`,{method:'POST',headers:{Cookie:ownerCookie,'Sec-Fetch-Site':'same-origin'},body:invalidForm});assert.equal(invalidUpload.status,415);
  }
  assert.equal(Number(db.prepare('SELECT COUNT(*) n FROM albums').get().n),albumsBeforeOversize);assert.equal(Number(db.prepare('SELECT COUNT(*) n FROM album_media').get().n),mediaBeforeOversize);
  assert.equal((await call(`/albums/${album.id}/publish`,{method:'POST',cookie:ownerCookie,headers:jsonHeaders,body:{publishMode:'immediate'}})).status,409);
  assert.equal((await call(`/albums/${album.id}`,{method:'PATCH',cookie:otherCookie,headers:jsonHeaders,body:{title:'IDOR'}})).status,403);
  assert.equal((await call(`/albums/${album.id}/publish`,{method:'POST',cookie:otherCookie,headers:jsonHeaders,body:{publishMode:'immediate'}})).status,403);
  assert.equal((await call(`/albums/${album.id}`,{method:'PATCH',cookie:ownerCookie,headers:jsonHeaders,body:{visibility:'public',publishMode:'immediate'}})).status,200); // remains a private draft in publication terms
  assert.equal((await mediaCall(mediaId)).status,404);
  assert.equal((await fetch(`${host}/uploads/${storageName}`)).status,404);
  assert.equal((await call(`/stories/${storyId}`)).status,404);
  assert.equal((await call(`/albums/${slug}`)).status,404);

  // Unassociated files and source/config files cannot be fetched by guessing paths.
  await writeFile(join(uploadDir,'orphan.jpg'),Buffer.from([0xff,0xd8,0xff,0xe0]));
  assert.equal((await fetch(`${host}/uploads/orphan.jpg`)).status,404);
  for(const name of ['server.mjs','.env.example','package.json','PRODUCTION_READINESS.md'])assert.equal((await fetch(`${host}/${name}`)).status,404,`${name} must not be statically served`);
  await writeFile(join(uploadDir,'owner-avatar.jpg'),Buffer.from([0xff,0xd8,0xff,0xe0]));db.prepare('UPDATE users SET avatar_path=? WHERE id=?').run('owner-avatar.jpg',ownerId);
  assert.equal((await fetch(`${host}/uploads/owner-avatar.jpg`,{headers:{Cookie:ownerCookie}})).status,200);
  assert.equal((await fetch(`${host}/uploads/owner-avatar.jpg`,{headers:{Cookie:otherCookie}})).status,404);
  assert.equal((await fetch(`${host}/uploads/%E0%A4%A`)).status,404);

  const syntheticMatchProvider=new class extends ScannerProvider{
    constructor(){super({providerId:'synthetic-match-fixture',checks:['known_csam_image']})}
    async scan({openMedia}){const media=await openMedia();for await(const _chunk of media.stream){}return {outcome:'match',providerId:this.providerId,providerReference:'synthetic-case-1',auditMetadata:{algorithm:'fixture-only'}}}
  }();
  const scanMatch=await runMediaSafetyChecks({db,mediaId,jobId:'security-fixture',mediaType:'image',providers:[syntheticMatchProvider],openMedia:async()=>({stream:Readable.from(['synthetic fixture bytes'])})});
  assert.equal(scanMatch.status,'unavailable');assert.equal(scanMatch.reviewRequired,true);assert.equal(db.prepare('SELECT status FROM media_pipeline WHERE media_id=?').get(mediaId).status,'QUARANTINED');
  assert.equal((await mediaCall(mediaId,ownerCookie)).status,404);assert.equal((await fetch(`${host}/uploads/${storageName}`,{headers:{Cookie:ownerCookie}})).status,404);
  assert.equal((await call(`/albums/${slug}`,{cookie:otherCookie})).status,404);assert.equal((await call(`/stories/${storyId}`,{cookie:otherCookie})).status,404);

  // Test-only fixture represents a full provider-passed record; application code never manufactures these outcomes.
  const timestamp=new Date().toISOString();db.prepare("UPDATE album_media SET state='ready' WHERE id=?").run(mediaId);db.prepare("UPDATE media_pipeline SET status='READY',malware_status='CLEAN',processing_status='READY',known_content_status='CLEAR',safety_status='CLEAR',moderation_status='APPROVED' WHERE media_id=?").run(mediaId);
  for(const key of ['rights','consent'])db.prepare('INSERT INTO creator_declarations(album_id,user_id,declaration_key,policy_version,accepted_at) VALUES(?,?,?,?,?)').run(album.id,ownerId,key,rights,timestamp);
  db.prepare("UPDATE albums SET status='published',visibility='public',review_status='not_required',publish_mode='immediate' WHERE id=?").run(album.id);db.prepare("UPDATE stories SET status='published' WHERE id=?").run(storyId);
  assert.equal((await mediaCall(mediaId)).status,200);
  assert.equal((await fetch(`${host}/uploads/${storageName}`)).status,200);
  assert.equal((await call(`/stories/${storyId}`)).status,200);
  assert.equal((await call(`/albums/${slug}`)).status,200);
  const searchResult=await call('/stories?q=Gate');assert.equal(searchResult.status,200);assert.ok((await searchResult.json()).items.some(item=>item.id===storyId));
  const creatorProfile=await call('/creators/owner');assert.equal(creatorProfile.status,200);assert.equal((await creatorProfile.json()).creator.id,ownerId);
  const likeFirst=await call(`/stories/${storyId}/like`,{method:'POST',cookie:otherCookie,headers:jsonHeaders,body:{}});assert.equal((await likeFirst.json()).story.liked,true);
  const likeAgain=await call(`/stories/${storyId}/like`,{method:'POST',cookie:otherCookie,headers:jsonHeaders,body:{}});assert.equal((await likeAgain.json()).story.liked,false);
  const saveFirst=await call(`/stories/${storyId}/save`,{method:'POST',cookie:otherCookie,headers:jsonHeaders,body:{}});assert.equal((await saveFirst.json()).saved,true);
  assert.ok((await (await call('/saved',{cookie:otherCookie})).json()).items.some(item=>item.id===storyId));
  const saveAgain=await call(`/stories/${storyId}/save`,{method:'POST',cookie:otherCookie,headers:jsonHeaders,body:{}});assert.equal((await saveAgain.json()).saved,false);
  const followFirst=await call('/creators/owner/follow',{method:'POST',cookie:otherCookie,headers:jsonHeaders,body:{}});assert.equal((await followFirst.json()).following,true);
  const followAgain=await call('/creators/owner/follow',{method:'POST',cookie:otherCookie,headers:jsonHeaders,body:{}});assert.equal((await followAgain.json()).following,false);
  const postedComment=await call(`/stories/${storyId}/comments`,{method:'POST',cookie:otherCookie,headers:jsonHeaders,body:{body:'Benign end-to-end comment'}});assert.equal(postedComment.status,201);
  assert.ok((await (await call(`/stories/${storyId}/comments`)).json()).items.some(item=>item.body==='Benign end-to-end comment'));
  assert.equal((await call(`/albums/${album.id}`,{method:'PATCH',cookie:ownerCookie,headers:jsonHeaders,body:{allowComments:false}})).status,200);
  assert.equal((await call(`/stories/${storyId}/comments`)).status,403);
  assert.equal((await call(`/albums/${album.id}`,{method:'PATCH',cookie:ownerCookie,headers:jsonHeaders,body:{allowComments:true}})).status,200);
  assert.equal((await call(`/albums/${album.id}`,{method:'PATCH',cookie:ownerCookie,headers:jsonHeaders,body:{visibility:'unlisted'}})).status,200);
  assert.equal((await mediaCall(mediaId)).status,404);assert.equal((await fetch(`${host}/media/${mediaId}?album=${encodeURIComponent(slug)}`)).status,200);
  assert.equal((await fetch(`${host}/uploads/${storageName}`)).status,404);assert.equal((await fetch(`${host}/uploads/${storageName}?album=${encodeURIComponent(slug)}`)).status,200);
  assert.equal((await call(`/stories/${storyId}`)).status,404);assert.equal((await call(`/stories/${storyId}?album=${encodeURIComponent(slug)}`)).status,200);
  assert.equal((await call(`/albums/${album.id}`,{method:'PATCH',cookie:ownerCookie,headers:jsonHeaders,body:{visibility:'public'}})).status,200);
  assert.equal((await call(`/albums/${album.id}`,{method:'PATCH',cookie:ownerCookie,headers:jsonHeaders,body:{visibility:'private'}})).status,200);
  assert.equal((await mediaCall(mediaId,ownerCookie)).status,200);assert.equal((await mediaCall(mediaId,otherCookie)).status,404);
  assert.equal((await call(`/albums/${album.id}`,{method:'PATCH',cookie:ownerCookie,headers:jsonHeaders,body:{visibility:'public'}})).status,200);
  assert.equal((await call(`/stories/${storyId}/like`,{method:'POST',cookie:otherCookie,headers:jsonHeaders,body:{}})).status,200);
  assert.equal((await fetch(`${base}/stories/${storyId}/like`,{method:'POST',headers:{Cookie:otherCookie,'Content-Type':'application/json','Sec-Fetch-Site':'cross-site'},body:'{}'})).status,403);
  db.prepare("UPDATE albums SET status='draft',publish_mode='immediate' WHERE id=?").run(album.id);db.prepare("UPDATE stories SET status='draft' WHERE id=?").run(storyId);
  assert.equal((await call(`/albums/${album.id}/publish`,{method:'POST',cookie:ownerCookie,headers:jsonHeaders,body:{publishMode:'immediate'}})).status,200);
  assert.equal(db.prepare('SELECT status FROM albums WHERE id=?').get(album.id).status,'published');

  db.prepare("UPDATE albums SET visibility='private' WHERE id=?").run(album.id);
  assert.equal((await mediaCall(mediaId,ownerCookie)).status,200);
  assert.equal((await mediaCall(mediaId,otherCookie)).status,404);
  db.prepare("UPDATE albums SET visibility='public',status='draft' WHERE id=?").run(album.id);db.prepare("UPDATE stories SET status='draft' WHERE id=?").run(storyId);
  assert.equal((await mediaCall(mediaId,ownerCookie)).status,200);
  assert.equal((await mediaCall(mediaId,otherCookie)).status,404);
  db.prepare("UPDATE albums SET status='published',visibility='public' WHERE id=?").run(album.id);db.prepare("UPDATE stories SET status='published' WHERE id=?").run(storyId);
  for(const state of ['QUARANTINED','REJECTED']){db.prepare('UPDATE media_pipeline SET status=? WHERE media_id=?').run(state,mediaId);assert.equal((await mediaCall(mediaId,ownerCookie)).status,404,`${state}: owner denied`);assert.equal((await mediaCall(mediaId,otherCookie)).status,404,`${state}: other user denied`)}
  db.prepare("UPDATE media_pipeline SET status='SCAN_PENDING',malware_status='NOT_CONFIGURED' WHERE media_id=?").run(mediaId);
  assert.equal((await mediaCall(mediaId,ownerCookie)).status,200);
  assert.equal((await mediaCall(mediaId,otherCookie)).status,404);
  assert.equal((await call(`/albums/${album.id}`,{method:'PATCH',cookie:ownerCookie,headers:jsonHeaders,body:{visibility:'public',publishMode:'immediate'}})).status,409);
  assert.equal((await call(`/admin/posts/${storyId}`,{method:'PATCH',cookie:adminCookie,headers:jsonHeaders,body:{status:'published'}})).status,409);

  // Due schedules re-evaluate every gate at the actual publication point.
  db.prepare("UPDATE albums SET status='draft',visibility='public',publish_mode='schedule',scheduled_at=?,review_status='not_required' WHERE id=?").run(new Date(Date.now()-5000).toISOString(),album.id);db.prepare("UPDATE stories SET status='draft' WHERE id=?").run(storyId);
  await call('/stories');assert.equal(db.prepare('SELECT status FROM albums WHERE id=?').get(album.id).status,'draft');
  db.prepare("UPDATE media_pipeline SET status='READY',malware_status='CLEAN',processing_status='READY',known_content_status='CLEAR',safety_status='CLEAR',moderation_status='APPROVED' WHERE media_id=?").run(mediaId);db.prepare("UPDATE albums SET status='draft',publish_mode='schedule',review_status='not_required',scheduled_at=? WHERE id=?").run(new Date(Date.now()-5000).toISOString(),album.id);db.prepare("UPDATE stories SET status='draft' WHERE id=?").run(storyId);
  db.prepare('UPDATE users SET upload_restricted=1 WHERE id=?').run(ownerId);await call('/stories');assert.equal(db.prepare('SELECT status FROM albums WHERE id=?').get(album.id).status,'draft');db.prepare('UPDATE users SET upload_restricted=0 WHERE id=?').run(ownerId);
  await call('/stories');assert.equal(db.prepare('SELECT status FROM albums WHERE id=?').get(album.id).status,'published');assert.equal(db.prepare('SELECT status FROM stories WHERE id=?').get(storyId).status,'published');

  // Report creation, moderation case creation, and urgent quarantine are atomic.
  const reportCountBefore=Number(db.prepare('SELECT COUNT(*) n FROM reports').get().n);
  db.exec("CREATE TRIGGER reject_moderation_case BEFORE INSERT ON moderation_cases BEGIN SELECT RAISE(ABORT,'forced test failure'); END");
  const failedReport=await call(`/stories/${storyId}/report`,{method:'POST',cookie:otherCookie,headers:jsonHeaders,body:{category:'suspected_minor',reason:'Safety review'}});
  assert.equal(failedReport.status,500);
  assert.equal(Number(db.prepare('SELECT COUNT(*) n FROM reports').get().n),reportCountBefore);
  assert.equal(db.prepare('SELECT status FROM media_pipeline WHERE media_id=?').get(mediaId).status,'READY');
  assert.equal(db.prepare('SELECT status FROM albums WHERE id=?').get(album.id).status,'published');
  db.exec('DROP TRIGGER reject_moderation_case');
  const urgentReport=await call(`/stories/${storyId}/report`,{method:'POST',cookie:otherCookie,headers:jsonHeaders,body:{category:'suspected_minor',reason:'Safety review'}});
  assert.equal(urgentReport.status,201);
  assert.equal(Number(db.prepare('SELECT COUNT(*) n FROM reports').get().n),reportCountBefore+1);
  const urgentCase=db.prepare("SELECT id,priority,restricted,status FROM moderation_cases WHERE report_id=(SELECT MAX(id) FROM reports)").get();
  assert.deepEqual({...urgentCase},{id:urgentCase.id,priority:'critical',restricted:1,status:'open'});
  assert.equal(db.prepare('SELECT status FROM media_pipeline WHERE media_id=?').get(mediaId).status,'QUARANTINED');
  assert.equal(db.prepare('SELECT status FROM albums WHERE id=?').get(album.id).status,'processing');
  assert.equal(db.prepare('SELECT status FROM stories WHERE id=?').get(storyId).status,'draft');
  assert.equal((await mediaCall(mediaId)).status,404);
  assert.equal((await fetch(`${host}/uploads/${storageName}`)).status,404);
  assert.equal((await call(`/albums/${slug}`,{cookie:otherCookie})).status,404);
  assert.equal((await call(`/stories/${storyId}`)).status,404);
  const ordinaryQueue=await call('/moderation/cases',{cookie:moderatorCookie}),seniorQueue=await call('/moderation/cases',{cookie:seniorCookie});
  assert.equal(ordinaryQueue.status,200);assert.ok(!(await ordinaryQueue.json()).items.some(item=>item.id===urgentCase.id));
  assert.equal(seniorQueue.status,200);assert.ok((await seniorQueue.json()).items.some(item=>item.id===urgentCase.id));

  // Admin comment review is scoped to a post, obeys that post's comment setting, and only admins can remove comments.
  const commentRow=Number(db.prepare('INSERT INTO comments(user_id,story_id,body,created_at) VALUES(?,?,?,?)').run(ownerId,storyId,'moderation fixture',timestamp).lastInsertRowid);
  assert.equal((await call(`/admin/posts/${storyId}/comments`,{cookie:moderatorCookie})).status,403);
  const visibleComments=await call(`/admin/posts/${storyId}/comments`,{cookie:adminCookie});assert.equal(visibleComments.status,200);assert.ok((await visibleComments.json()).items.some(comment=>comment.id===commentRow));
  db.prepare('UPDATE albums SET allow_comments=0 WHERE id=?').run(album.id);
  assert.equal((await call(`/admin/posts/${storyId}/comments`,{cookie:adminCookie})).status,403);
  db.prepare('UPDATE albums SET allow_comments=1 WHERE id=?').run(album.id);
  assert.equal((await call(`/admin/comments/${commentRow}`,{method:'DELETE',cookie:moderatorCookie,headers:jsonHeaders})).status,403);
  assert.equal((await call(`/admin/comments/${commentRow}`,{method:'DELETE',cookie:adminCookie,headers:jsonHeaders})).status,200);
  assert.equal(db.prepare('SELECT 1 FROM comments WHERE id=?').get(commentRow),undefined);

  // Admin/moderator authorization is checked against current server-side roles.
  const caseInsert=db.prepare("INSERT INTO moderation_cases(album_id,media_id,category,priority,status,restricted,created_at,updated_at) VALUES(?,?, 'other','normal','open',0,?,?)");const caseId=Number(caseInsert.run(album.id,mediaId,timestamp,timestamp).lastInsertRowid);
  assert.equal((await call('/moderation/cases',{cookie:moderatorCookie})).status,200);
  assert.equal((await call('/admin/health',{cookie:moderatorCookie})).status,403);
  assert.equal((await call(`/moderation/cases/${caseId}`,{method:'PATCH',cookie:moderatorCookie,headers:jsonHeaders,body:{status:'reviewing'}})).status,403);
  assert.equal((await call(`/moderation/cases/${caseId}`,{method:'PATCH',cookie:seniorCookie,headers:jsonHeaders,body:{status:'reviewing'}})).status,200);
  assert.equal((await call('/admin/health',{cookie:seniorCookie})).status,403);
  assert.equal((await call('/admin/health',{cookie:adminCookie})).status,200);

  // Sessions are rotated and revoked server-side; malformed and expired tokens are anonymous.
  const secondLogin=await fetch(`${base}/auth/login`,{method:'POST',headers:{...jsonHeaders,Cookie:adminCookie},body:JSON.stringify({email:adminEmail,password:adminPassword})});assert.equal(secondLogin.status,200);const rotatedCookie=secondLogin.headers.get('set-cookie').split(';')[0];
  assert.equal((await (await call('/session',{cookie:adminCookie})).json()).user,null);
  const logout=await call('/auth/logout',{method:'POST',cookie:rotatedCookie,headers:jsonHeaders});assert.equal(logout.status,200);assert.equal((await (await call('/session',{cookie:rotatedCookie})).json()).user,null);
  assert.equal((await (await call('/session',{cookie:'aroused_session=%ZZ'})).json()).user,null);
  const expiredToken='expired-token';db.prepare('INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)').run(createHash('sha256').update(expiredToken).digest('hex'),ownerId,Date.now()-1);assert.equal((await (await call('/session',{cookie:sessionCookie(expiredToken)})).json()).user,null);

  // Password recovery uses the real configured email provider only; absent credentials do not create usable reset tokens.
  const ownerEmail=db.prepare('SELECT email FROM users WHERE id=?').get(ownerId).email;
  const unknownReset=await call('/auth/request-password-reset',{method:'POST',headers:jsonHeaders,body:{email:'not-registered-reset@example.test'}}),knownReset=await call('/auth/request-password-reset',{method:'POST',headers:jsonHeaders,body:{email:ownerEmail}});
  assert.equal(unknownReset.status,202);assert.equal(knownReset.status,202);assert.equal((await unknownReset.json()).message,(await knownReset.json()).message);assert.equal(db.prepare('SELECT COUNT(*) n FROM password_reset_tokens WHERE user_id=?').get(ownerId).n,0);
  for(let i=0;i<3;i++)assert.equal((await call('/auth/request-password-reset',{method:'POST',headers:jsonHeaders,body:{email:ownerEmail}})).status,202);
  assert.equal((await call('/auth/request-password-reset',{method:'POST',headers:jsonHeaders,body:{email:ownerEmail}})).status,429);
  const resetToken=randomBytes(32).toString('base64url');db.prepare('INSERT INTO password_reset_tokens(token_hash,user_id,expires_at,used_at,created_at) VALUES(?,?,?,NULL,?)').run(createHash('sha256').update(resetToken).digest('hex'),ownerId,Date.now()+30*60*1000,now);
  const reset=await call('/auth/reset-password',{method:'POST',cookie:ownerCookie,headers:jsonHeaders,body:{email:ownerEmail,token:resetToken,newPassword:'NewValid!Password123'}});assert.equal(reset.status,200);assert.equal((await (await call('/session',{cookie:ownerCookie})).json()).user,null);
  assert.equal((await call('/auth/reset-password',{method:'POST',headers:jsonHeaders,body:{email:ownerEmail,token:resetToken,newPassword:'AnotherValid!Password123'}})).status,400);
  assert.equal((await fetch(`${base}/auth/login`,{method:'POST',headers:jsonHeaders,body:JSON.stringify({email:ownerEmail,password:'NewValid!Password123'})})).status,200);
  const expiredResetToken=randomBytes(32).toString('base64url');db.prepare('INSERT INTO password_reset_tokens(token_hash,user_id,expires_at,used_at,created_at) VALUES(?,?,?,NULL,?)').run(createHash('sha256').update(expiredResetToken).digest('hex'),ownerId,Date.now()-1,now);
  assert.equal((await call('/auth/reset-password',{method:'POST',headers:jsonHeaders,body:{email:ownerEmail,token:expiredResetToken,newPassword:'OtherValid!Password123'}})).status,400);

  // Auth rate limit: first eight invalid logins allowed for evaluation, ninth denied; upload requests have a separate per-user quota.
  for(let i=0;i<8;i++)assert.equal((await fetch(`${base}/auth/login`,{method:'POST',headers:jsonHeaders,body:JSON.stringify({email:'rate-test@example.test',password:'wrong-password'})})).status,401);
  assert.equal((await fetch(`${base}/auth/login`,{method:'POST',headers:jsonHeaders,body:JSON.stringify({email:'rate-test@example.test',password:'wrong-password'})})).status,429);
  for(let i=0;i<10;i++)assert.equal((await call('/albums',{method:'POST',cookie:otherCookie,headers:{'Sec-Fetch-Site':'same-origin'}})).status,415);
  assert.equal((await call('/albums',{method:'POST',cookie:otherCookie,headers:{'Sec-Fetch-Site':'same-origin'}})).status,429);

  const activeOwnerCookie=createCookie(ownerId);
  const profileUpdate=await call('/account',{method:'PATCH',cookie:activeOwnerCookie,headers:jsonHeaders,body:{displayName:'Owner',username:'owner_creator',bio:'A creator bio, under 30',onlyfansUrl:'https://onlyfans.com/owner'}});
  assert.equal(profileUpdate.status,200);assert.equal((await profileUpdate.json()).user.username,'owner_creator');
  assert.equal((await call('/account',{method:'PATCH',cookie:activeOwnerCookie,headers:jsonHeaders,body:{displayName:'Owner',username:'other',bio:'ok'}})).status,409);
  assert.equal((await call('/account',{method:'PATCH',cookie:activeOwnerCookie,headers:jsonHeaders,body:{displayName:'Owner',username:'owner_creator',bio:'A bio that is definitely more than thirty characters long'}})).status,400);

  const videoBytes=Buffer.from([0,0,0,24,0x66,0x74,0x79,0x70,0x69,0x73,0x6f,0x6d,0,0,0,0,0,0,0,0,0,0,0,0]);
  const videoForm=new FormData();videoForm.append('media',new Blob([videoBytes],{type:'video/mp4'}),'synthetic-benign.mp4');
  const addVideo=await fetch(`${base}/albums/${album.id}/media`,{method:'POST',headers:{Cookie:activeOwnerCookie,'Sec-Fetch-Site':'same-origin'},body:videoForm});assert.equal(addVideo.status,201);
  const uploadedVideo=(await addVideo.json()).album.media.find(item=>item.name==='synthetic-benign.mp4');assert.ok(uploadedVideo);
  const videoPipeline=db.prepare('SELECT status,malware_status,processing_status,known_content_status,safety_status,moderation_status FROM media_pipeline WHERE media_id=?').get(uploadedVideo.id);
  assert.deepEqual({...videoPipeline},{status:'SCAN_PENDING',malware_status:'NOT_CONFIGURED',processing_status:'NOT_CONFIGURED',known_content_status:'NOT_CONFIGURED',safety_status:'NOT_CONFIGURED',moderation_status:'PENDING'});
  assert.equal((await mediaCall(uploadedVideo.id)).status,404);assert.equal((await mediaCall(uploadedVideo.id,activeOwnerCookie)).status,200);
  const videoStorage=db.prepare('SELECT storage_name FROM album_media WHERE id=?').get(uploadedVideo.id).storage_name;

  // Account deletion cascades relational data and removes this account's new album media from private storage.
  const deletionPassword='Delete!Account-Test-2026',salt=randomBytes(16);
  db.prepare('UPDATE users SET password_hash=? WHERE id=?').run(`${salt.toString('hex')}:${scryptSync(deletionPassword,salt,64).toString('hex')}`,ownerId);
  const deleteAccount=await call('/account',{method:'DELETE',cookie:activeOwnerCookie,headers:jsonHeaders,body:{confirmation:'DELETE',password:deletionPassword}});
  assert.equal(deleteAccount.status,200);
  assert.equal((await mediaCall(mediaId,activeOwnerCookie)).status,404);
  await assert.rejects(()=>readFile(join(uploadDir,storageName)));
  await assert.rejects(()=>readFile(join(uploadDir,videoStorage)));
  await assert.rejects(()=>readFile(join(uploadDir,'owner-avatar.jpg')));
  assert.equal(db.prepare('SELECT id FROM users WHERE id=?').get(ownerId),undefined);

  db.close();
});
