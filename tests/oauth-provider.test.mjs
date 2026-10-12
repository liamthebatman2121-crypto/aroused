import test from 'node:test';
import assert from 'node:assert/strict';
import { createOAuthAuthorization, fetchOAuthIdentity, oauthProviders } from '../auth/oauth-providers.mjs';

const creds={AROUSED_PUBLIC_URL:'https://aroused.example',GOOGLE_OAUTH_CLIENT_ID:'google-id',GOOGLE_OAUTH_CLIENT_SECRET:'google-secret',REDDIT_OAUTH_CLIENT_ID:'reddit-id',REDDIT_OAUTH_CLIENT_SECRET:'reddit-secret',X_OAUTH_CLIENT_ID:'x-id',X_OAUTH_CLIENT_SECRET:'x-secret'};

test('OAuth providers stay disabled without credentials or with a mismatched callback URI',()=>{
  assert.deepEqual(Object.values(oauthProviders({})).map(provider=>provider.configured),[false,false,false]);
  assert.equal(oauthProviders({...creds,AROUSED_PUBLIC_URL:'not a url'}).google.configured,false);
  assert.equal(oauthProviders({...creds,GOOGLE_OAUTH_REDIRECT_URI:'https://evil.example/callback'}).google.configured,false);
  assert.equal(oauthProviders({...creds,GOOGLE_OAUTH_REDIRECT_URI:'https://aroused.example/api/auth/oauth/google/callback'}).google.configured,true);
});

test('authorization requests use minimum documented identity scopes, state, and PKCE where supported',()=>{
  const providers=oauthProviders(creds);
  const google=new URL(createOAuthAuthorization({provider:'google',state:'state-token',codeVerifier:'verifier-token',config:providers.google}));
  assert.equal(google.searchParams.get('scope'),'openid email profile');assert.equal(google.searchParams.get('state'),'state-token');assert.equal(google.searchParams.get('code_challenge_method'),'S256');
  const reddit=new URL(createOAuthAuthorization({provider:'reddit',state:'state-token',codeVerifier:'',config:providers.reddit}));
  assert.equal(reddit.searchParams.get('scope'),'identity');assert.equal(reddit.searchParams.get('state'),'state-token');assert.equal(reddit.searchParams.has('code_challenge'),false);
  const x=new URL(createOAuthAuthorization({provider:'x',state:'state-token',codeVerifier:'verifier-token',config:providers.x}));
  assert.equal(x.searchParams.get('scope'),'users.read');assert.equal(x.searchParams.get('code_challenge_method'),'S256');
});

test('OAuth identity exchange validates provider identity and never treats unverified Google email as verified',async()=>{
  const config=oauthProviders(creds),calls=[];
  const responses=new Map([
    ['https://oauth2.googleapis.com/token',{access_token:'token-google'}],
    ['https://openidconnect.googleapis.com/v1/userinfo',{sub:'google-sub',email:'unverified@example.test',email_verified:false,name:'Google User'}],
    ['https://www.reddit.com/api/v1/access_token',{access_token:'token-reddit'}],
    ['https://oauth.reddit.com/api/v1/me',{id:'reddit-id',name:'reddit_user'}],
    ['https://api.x.com/2/oauth2/token',{access_token:'token-x-test'}],
    ['https://api.x.com/2/users/me?user.fields=name,username',{data:{id:'x-id',name:'X User',username:'x_user'}}]
  ]);
  const fetchImpl=async(url,options)=>{calls.push({url:String(url),options});const data=responses.get(String(url));assert.ok(data,`unexpected request ${url}`);return {ok:true,status:200,json:async()=>data}};
  const google=await fetchOAuthIdentity({provider:'google',code:'auth-code',codeVerifier:'verifier',config:config.google,fetchImpl});assert.equal(google.providerId,'google-sub');assert.equal(google.email,null);
  const reddit=await fetchOAuthIdentity({provider:'reddit',code:'auth-code',config:config.reddit,fetchImpl});assert.equal(reddit.providerId,'reddit-id');assert.equal(reddit.email,null);
  const x=await fetchOAuthIdentity({provider:'x',code:'auth-code',codeVerifier:'verifier',config:config.x,fetchImpl});assert.equal(x.providerId,'x-id');assert.equal(x.displayName,'X User');
  assert.equal(calls.length,6);assert.ok(calls.some(call=>call.options.headers.Authorization?.startsWith('Basic ')));
});
