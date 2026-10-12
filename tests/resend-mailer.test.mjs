import test from 'node:test';
import assert from 'node:assert/strict';
import { sendResendEmail } from '../auth/resend-mailer.mjs';

const input = { apiKey:'not-a-real-key', from:'Aroused <verify@example.test>', to:'creator@example.test', subject:'Verify', text:'test code 654321', html:'<p>test code 654321</p>' };

test('Resend sender reports accepted only after a valid provider message ID', async()=>{
  let request;
  const result=await sendResendEmail({...input,fetchImpl:async(url,options)=>{request={url,options};return {ok:true,status:200,json:async()=>({id:'re_0123456789abcdef'})}}});
  assert.deepEqual(result,{accepted:true});
  assert.equal(request.url,'https://api.resend.com/emails');
  assert.equal(request.options.method,'POST');
  assert.equal(request.options.headers.Authorization,'Bearer not-a-real-key');
  assert.equal(JSON.parse(request.options.body).to[0],input.to);
});

test('missing Resend config fails without calling the provider',async()=>{
  let called=false;
  await assert.rejects(sendResendEmail({...input,apiKey:'',fetchImpl:async()=>{called=true}}),error=>error.code==='EMAIL_DELIVERY_NOT_CONFIGURED'&&error.status===503);
  assert.equal(called,false);
});

test('provider rejection returns a normalized failure, never accepted',async()=>{
  await assert.rejects(sendResendEmail({...input,fetchImpl:async()=>({ok:false,status:422,json:async()=>({message:'contains recipient details and provider payload'})})}),error=>error.code==='EMAIL_PROVIDER_REJECTED'&&error.status===422&&!error.message.includes('recipient'));
});

test('network errors, timeouts, and malformed success payloads fail closed',async t=>{
  await t.test('network error',async()=>assert.rejects(sendResendEmail({...input,fetchImpl:async()=>{throw new Error('secret payload')}}),error=>error.code==='EMAIL_DELIVERY_NETWORK_ERROR'));
  await t.test('timeout',async()=>assert.rejects(sendResendEmail({...input,timeoutMs:5,fetchImpl:(_url,{signal})=>new Promise((resolve,reject)=>signal.addEventListener('abort',()=>reject(new Error('aborted'))))}),error=>error.code==='EMAIL_DELIVERY_TIMEOUT'));
  await t.test('malformed accepted response',async()=>assert.rejects(sendResendEmail({...input,fetchImpl:async()=>({ok:true,status:200,json:async()=>({})})}),error=>error.code==='EMAIL_PROVIDER_INVALID_RESPONSE'));
});
