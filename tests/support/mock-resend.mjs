import { writeFileSync } from 'node:fs';

if (process.env.NODE_ENV !== 'test' || !process.env.AROUSED_TEST_RESEND_CAPTURE_FILE) {
  throw new Error('The Resend test interception may only run in the isolated auth test process.');
}

globalThis.fetch = async (input, options = {}) => {
  const url=String(input);
  if(url==='https://oauth2.googleapis.com/token'||url==='https://www.reddit.com/api/v1/access_token'||url==='https://api.x.com/2/oauth2/token')return new Response(JSON.stringify({access_token:'test-only-access-token'}),{status:200,headers:{'Content-Type':'application/json'}});
  if(url==='https://openidconnect.googleapis.com/v1/userinfo')return new Response(JSON.stringify({sub:'google-test-subject',email:'oauth-flow@example.test',email_verified:true,name:'OAuth Tester'}),{status:200,headers:{'Content-Type':'application/json'}});
  if(url==='https://oauth.reddit.com/api/v1/me')return new Response(JSON.stringify({id:'reddit-test-id',name:'reddit_test_user'}),{status:200,headers:{'Content-Type':'application/json'}});
  if(url==='https://api.x.com/2/users/me?user.fields=name,username')return new Response(JSON.stringify({data:{id:'x-test-id',name:'X Tester',username:'x_test_user'}}),{status:200,headers:{'Content-Type':'application/json'}});
  if (url !== 'https://api.resend.com/emails') throw new Error('Unexpected network request in isolated auth test.');
  const payload = JSON.parse(options.body || '{}');
  if (String(payload.to?.[0] || '').startsWith('reject-')) {
    return new Response(JSON.stringify({ message: 'simulated provider rejection with sensitive-looking details' }), { status: 422 });
  }
  writeFileSync(process.env.AROUSED_TEST_RESEND_CAPTURE_FILE, JSON.stringify(payload), { mode: 0o600 });
  return new Response(JSON.stringify({ id: 're_test0123456789abcdef' }), { status: 200, headers: { 'Content-Type': 'application/json' } });
};
