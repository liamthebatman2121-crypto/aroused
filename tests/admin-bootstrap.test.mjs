import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { DatabaseSync } from 'node:sqlite';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer } from 'node:net';
import { fileURLToPath } from 'node:url';

const root=fileURLToPath(new URL('..',import.meta.url));
const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const freePort=()=>new Promise((resolve,reject)=>{const server=createServer();server.once('error',reject);server.listen(0,'127.0.0.1',()=>{const {port}=server.address();server.close(error=>error?reject(error):resolve(port))})});
const stop=async child=>{if(child.exitCode!==null)return;const exited=new Promise(resolve=>child.once('exit',resolve));child.kill('SIGTERM');await Promise.race([exited,sleep(1500)]);if(child.exitCode===null){child.kill('SIGKILL');await Promise.race([exited,sleep(500)])}};

test('bootstrap is one-time and admin authorization uses the current role',async t=>{
  const dir=await mkdtemp(join(tmpdir(),'aroused-admin-bootstrap-')),email=`bootstrap-${Date.now()}@example.test`,password=`Test!${Date.now()}-Bootstrap-Admin`,dataDir=join(dir,'data'),uploadDir=join(dir,'uploads');
  const launch=async()=>{const port=await freePort(),child=spawn(process.execPath,['server.mjs'],{cwd:root,env:{...process.env,NODE_ENV:'test',AROUSED_API_PORT:String(port),AROUSED_DATA_DIR:dataDir,AROUSED_UPLOAD_DIR:uploadDir,AROUSED_ADMIN_EMAIL:email,AROUSED_ADMIN_PASSWORD:password},stdio:['ignore','pipe','pipe']});let logs='';child.stdout.on('data',d=>logs+=d.toString());child.stderr.on('data',d=>logs+=d.toString());let health;for(let i=0;i<100;i++){if(child.exitCode!==null)throw new Error(`Server exited: ${logs}`);try{health=await fetch(`http://127.0.0.1:${port}/api/health`);break}catch{await sleep(100)}}assert.ok(health,`Server did not start: ${logs}`);await health.arrayBuffer();return {port,child,logs}};
  let current;
  t.after(async()=>{if(current)await stop(current.child);await rm(dir,{recursive:true,force:true})});
  current=await launch();const base=`http://127.0.0.1:${current.port}/api`,headers={'Content-Type':'application/json','Sec-Fetch-Site':'same-origin'};
  const login=await fetch(`${base}/auth/login`,{method:'POST',headers,body:JSON.stringify({email,password})});assert.equal(login.status,200);const cookie=login.headers.get('set-cookie').split(';')[0];
  assert.equal((await fetch(`${base}/admin/health`,{headers:{Cookie:cookie}})).status,200);
  const dbPath=join(dataDir,'aroused.sqlite'),db=new DatabaseSync(dbPath),id=Number(db.prepare('SELECT id FROM users WHERE email=?').get(email).id);db.prepare("UPDATE users SET role='user' WHERE id=?").run(id);db.close();
  await stop(current.child);current=null;
  current=await launch();
  const afterRestart=await fetch(`http://127.0.0.1:${current.port}/api/admin/health`,{headers:{Cookie:cookie}});assert.equal(afterRestart.status,403);
  const check=new DatabaseSync(dbPath),account=check.prepare('SELECT role FROM users WHERE id=?').get(id);assert.equal(account.role,'user');check.close();
});
