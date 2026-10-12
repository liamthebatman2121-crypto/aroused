import { createHash } from 'node:crypto';

const definitions = {
  google: { id:'GOOGLE_OAUTH_CLIENT_ID', secret:'GOOGLE_OAUTH_CLIENT_SECRET', redirect:'GOOGLE_OAUTH_REDIRECT_URI', authorize:'https://accounts.google.com/o/oauth2/v2/auth', token:'https://oauth2.googleapis.com/token', scopes:['openid','email','profile'], pkce:true },
  reddit: { id:'REDDIT_OAUTH_CLIENT_ID', secret:'REDDIT_OAUTH_CLIENT_SECRET', redirect:'REDDIT_OAUTH_REDIRECT_URI', authorize:'https://www.reddit.com/api/v1/authorize', token:'https://www.reddit.com/api/v1/access_token', scopes:['identity'], pkce:false },
  x: { id:'X_OAUTH_CLIENT_ID', secret:'X_OAUTH_CLIENT_SECRET', redirect:'X_OAUTH_REDIRECT_URI', authorize:'https://x.com/i/oauth2/authorize', token:'https://api.x.com/2/oauth2/token', scopes:['users.read'], pkce:true }
};

export function oauthProviders(env=process.env) {
  return Object.fromEntries(Object.entries(definitions).map(([name,def])=>{
    const redirect=String(env[def.redirect]||'').trim();
    const publicUrl=String(env.AROUSED_PUBLIC_URL||env.AROUSED_PUBLIC_BASE_URL||'http://localhost:8767').replace(/\/$/,'');
    let expected=null;try{expected=new URL(`/api/auth/oauth/${name}/callback`,publicUrl)}catch{}
    const candidate=redirect?(()=>{try{return new URL(redirect)}catch{return null}})():expected;
    const callbackValid=!!expected&&!!candidate&&candidate.origin===expected.origin&&candidate.pathname===expected.pathname&&!candidate.search&&!candidate.hash&&(env.NODE_ENV!=='production'||candidate.protocol==='https:');
    const callback=callbackValid?candidate.toString():'';
    const configured=Boolean(callbackValid&&String(env[def.id]||'').trim()&&String(env[def.secret]||'').trim());
    return [name,{configured,clientId:String(env[def.id]||''),clientSecret:String(env[def.secret]||''),callback,authorizationEndpoint:def.authorize,tokenEndpoint:def.token,scopes:def.scopes,pkce:def.pkce}];
  }));
}

export function createOAuthAuthorization({provider,state,codeVerifier,config}) {
  const url=new URL(config.authorizationEndpoint);
  url.searchParams.set('response_type','code');url.searchParams.set('client_id',config.clientId);url.searchParams.set('redirect_uri',config.callback);url.searchParams.set('scope',config.scopes.join(provider==='reddit'?',':' '));url.searchParams.set('state',state);
  if(provider==='google')url.searchParams.set('access_type','online');
  if(provider==='reddit'){url.searchParams.set('duration','temporary');url.searchParams.set('approval_prompt','auto')}
  if(config.pkce){const challenge=createHash('sha256').update(codeVerifier).digest('base64url');url.searchParams.set('code_challenge',challenge);url.searchParams.set('code_challenge_method','S256')}
  return url.toString();
}

async function jsonRequest(fetchImpl,url,options) {
  let response;
  try { response=await fetchImpl(url,{...options,signal:AbortSignal.timeout(10_000)}); }
  catch { throw Object.assign(new Error('OAuth provider request failed.'),{code:'OAUTH_PROVIDER_NETWORK_ERROR'}); }
  if(!response.ok)throw Object.assign(new Error('OAuth provider rejected the authentication request.'),{code:'OAUTH_PROVIDER_REJECTED',status:502});
  try { return await response.json(); }
  catch { throw Object.assign(new Error('OAuth provider returned an invalid response.'),{code:'OAUTH_PROVIDER_INVALID_RESPONSE',status:502}); }
}

export async function fetchOAuthIdentity({provider,code,codeVerifier,config,fetchImpl=fetch}) {
  const form=new URLSearchParams({grant_type:'authorization_code',code,redirect_uri:config.callback});
  if(provider==='google'){
    form.set('client_id',config.clientId);form.set('client_secret',config.clientSecret);form.set('code_verifier',codeVerifier);
  } else if(provider==='reddit') {
    // Reddit documents confidential web-app auth-code exchange; PKCE is not
    // advertised in its flow, so state validation and its client secret apply.
  } else if(provider==='x') {
    form.set('client_id',config.clientId);form.set('code_verifier',codeVerifier);
  } else throw Object.assign(new Error('Unsupported OAuth provider.'),{code:'OAUTH_PROVIDER_UNSUPPORTED',status:404});
  const tokenHeaders={'Content-Type':'application/x-www-form-urlencoded'};
  if(provider==='reddit'||provider==='x')tokenHeaders.Authorization=`Basic ${Buffer.from(`${encodeURIComponent(config.clientId)}:${encodeURIComponent(config.clientSecret)}`).toString('base64')}`;
  if(provider==='reddit')tokenHeaders['User-Agent']='Aroused/1.0 (account authentication)';
  const token=await jsonRequest(fetchImpl,config.tokenEndpoint,{method:'POST',headers:tokenHeaders,body:form.toString()});
  if(typeof token.access_token!=='string'||token.access_token.length<8)throw Object.assign(new Error('OAuth provider returned an invalid token response.'),{code:'OAUTH_PROVIDER_INVALID_RESPONSE',status:502});
  if(provider==='google'){
    const profile=await jsonRequest(fetchImpl,'https://openidconnect.googleapis.com/v1/userinfo',{headers:{Authorization:`Bearer ${token.access_token}`}});
    if(typeof profile.sub!=='string'||!profile.sub||profile.sub.length>255)throw Object.assign(new Error('OAuth provider returned an invalid identity.'),{code:'OAUTH_PROVIDER_INVALID_IDENTITY',status:502});
    return {providerId:profile.sub,email:profile.email_verified===true&&typeof profile.email==='string'?profile.email.toLowerCase():null,displayName:typeof profile.name==='string'?profile.name.slice(0,40):'Google creator'};
  }
  if(provider==='reddit'){
    const profile=await jsonRequest(fetchImpl,'https://oauth.reddit.com/api/v1/me',{headers:{Authorization:`Bearer ${token.access_token}`,'User-Agent':'Aroused/1.0 (account authentication)'}});
    if((typeof profile.id!=='string'&&!Number.isInteger(profile.id))||typeof profile.name!=='string'||!profile.name)throw Object.assign(new Error('OAuth provider returned an invalid identity.'),{code:'OAUTH_PROVIDER_INVALID_IDENTITY',status:502});
    return {providerId:String(profile.id),email:null,displayName:profile.name.slice(0,40)};
  }
  const profile=await jsonRequest(fetchImpl,'https://api.x.com/2/users/me?user.fields=name,username',{headers:{Authorization:`Bearer ${token.access_token}`}});
  if(!profile.data||typeof profile.data.id!=='string'||!profile.data.id)throw Object.assign(new Error('OAuth provider returned an invalid identity.'),{code:'OAUTH_PROVIDER_INVALID_IDENTITY',status:502});
  return {providerId:profile.data.id,email:null,displayName:String(profile.data.name||profile.data.username||'X creator').slice(0,40)};
}
