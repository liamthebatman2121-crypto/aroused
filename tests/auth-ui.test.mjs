import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { Script } from 'node:vm';
import { fileURLToPath } from 'node:url';

const html=await readFile(fileURLToPath(new URL('../index.html',import.meta.url)),'utf8');

test('authentication UI scripts parse and expose clear email, password reset, and social login controls',()=>{
  const scripts=[...html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/gi)].map(match=>match[1]).filter(source=>source.trim());
  assert.ok(scripts.length>0);
  for(const [index,source] of scripts.entries())assert.doesNotThrow(()=>new Script(source,{filename:`index-inline-${index+1}.js`}));
  assert.doesNotMatch(html,/We sent a six-digit code to/);
  assert.match(html,/If this address can be used to create an account, a six-digit code will be sent/);
  assert.match(html,/\['google','reddit','x'\]/);assert.match(html,/Continue with X/);
  assert.match(html,/Forgot password\?/);assert.match(html,/settings-social/);
});
