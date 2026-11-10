import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve(new URL('..', import.meta.url).pathname);
const api = readFileSync(resolve(root, 'netlify/functions/api.mjs'), 'utf8');
const netlify = readFileSync(resolve(root, 'netlify.toml'), 'utf8');
const pkg = JSON.parse(readFileSync(resolve(root, 'package.json'), 'utf8'));

test('bootstrap creates the unique principal role and checks one-time claim', () => {
  assert.match(api, /'SUPER_ADMIN_PRINCIPAL'/);
  assert.match(api, /claimed_at IS NULL/);
  assert.match(api, /NOT EXISTS \(SELECT 1 FROM admin_users\)/);
});

test('commercial mutation routes exclude ADMIN role', () => {
  assert.match(api, /adminCreateTenant\(event\)[\s\S]*?adminSession\(event, \[?'SUPER_ADMIN_PRINCIPAL'/);
  assert.match(api, /adminCreateCode\(event\)[\s\S]*?adminSession\(event, \[?'SUPER_ADMIN_PRINCIPAL'/);
  assert.match(api, /adminRevoke\(event\)[\s\S]*?adminSession\(event, \[?'SUPER_ADMIN_PRINCIPAL'/);
});

test('SUPER_ADMIN account listing is scoped to ADMIN accounts', () => {
  assert.match(api, /WHERE \(\$\{isPrincipal\(admin\)\} OR role = 'ADMIN'\)/);
});

test('Netlify publishes only the public directory', () => {
  assert.match(netlify, /publish = "public"/);
  assert.ok(existsSync(resolve(root, 'public/index.html')));
});

test('package scripts point only to present scripts', () => {
  for (const [name, command] of Object.entries(pkg.scripts)) {
    if (name === 'test') { assert.ok(existsSync(resolve(root, 'tests/admin-hierarchy.test.js'))); continue; }
    const file = command.match(/^node (.+)$/)?.[1];
    if (file) assert.ok(existsSync(resolve(root, file)), `${name} points to missing ${file}`);
  }
});
