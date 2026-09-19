import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

test('licensing server does not contain Supabase references', async () => {
  const files = ['README.md','DEPLOY.md','netlify.toml','netlify/functions/api.mjs','migrations/001_initial.sql'];
  for (const file of files) {
    const text = await readFile(new URL(`../${file}`, import.meta.url), 'utf8');
    assert.equal(/supabase/i.test(text), false, `unexpected Supabase reference in ${file}`);
  }
});

test('private signing key is not hardcoded in source', async () => {
  const text = await readFile(new URL('../netlify/functions/api.mjs', import.meta.url), 'utf8');
  assert.match(text, /LICENSE_PRIVATE_JWK_JSON/);
  assert.doesNotMatch(text, /BEGIN (PRIVATE|OPENSSH) KEY/);
});
