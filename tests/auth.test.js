import test from 'node:test';
import assert from 'node:assert/strict';
import { hashPassword, verifyPassword } from '../netlify/functions/auth.mjs';

test('Scrypt password hash verifies correct password', async () => {
  const encoded = await hashPassword('Senha-forte-de-teste-2026');
  assert.equal(await verifyPassword('Senha-forte-de-teste-2026', encoded), true);
});

test('Scrypt password hash rejects wrong password', async () => {
  const encoded = await hashPassword('Senha-forte-de-teste-2026');
  assert.equal(await verifyPassword('Outra-senha-qualquer-2026', encoded), false);
});

test('Scrypt verifier rejects malformed and attacker-controlled parameters', async () => {
  assert.equal(await verifyPassword('qualquer', 'scrypt$999999$8$1$abc$def'), false);
  assert.equal(await verifyPassword('qualquer', 'invalid'), false);
  assert.equal(await verifyPassword(null, 'scrypt$16384$8$1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'), false);
});
