import test from 'node:test';
import assert from 'node:assert/strict';
import { hashPassword, verifyPassword, randomToken, sha256 } from '../netlify/functions/auth.mjs';

test('password hashing is salted and verifies correctly', async () => {
  const h1 = await hashPassword('correct horse battery staple');
  const h2 = await hashPassword('correct horse battery staple');
  assert.notEqual(h1, h2);
  assert.equal(await verifyPassword('correct horse battery staple', h1), true);
  assert.equal(await verifyPassword('wrong password', h1), false);
});

test('random session tokens are non-empty and sha256 is deterministic', () => {
  assert.notEqual(randomToken(), randomToken());
  assert.equal(sha256('abc'), sha256('abc'));
  assert.notEqual(sha256('abc'), sha256('abd'));
});
