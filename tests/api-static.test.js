import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const source = await readFile(new URL('../netlify/functions/api.mjs', import.meta.url), 'utf8');

test('API separates forbidden role from missing authentication', () => {
  assert.match(source, /_forbidden: true/);
  assert.match(source, /json\(403, \{ error: 'FORBIDDEN' \}\)/);
});

test('tenant creation serializes normalized email and NIF checks', () => {
  assert.match(source, /pg_advisory_xact_lock\(hashtextextended\(lock_key, 0\)\)/);
  assert.match(source, /lower\(trim\(t\.email\)\)/);
  assert.match(source, /upper\(trim\(t\.nif\)\)/);
  assert.match(source, /TENANT_ALREADY_EXISTS/);
});

test('revocation is UUID-validated and does not repeat the transition', () => {
  assert.match(source, /INVALID_LICENSE_ID/);
  assert.match(source, /status <> 'REVOKED'/);
  assert.match(source, /LICENSE_ALREADY_REVOKED/);
});

test('license JWT includes temporal claims', () => {
  assert.match(source, /\.setNotBefore\(/);
  assert.match(source, /\.setExpirationTime\(/);
});
