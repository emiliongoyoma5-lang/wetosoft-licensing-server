import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
const api = await readFile(new URL('../netlify/functions/api.mjs', import.meta.url), 'utf8');
const ui = await readFile(new URL('../public/index.html', import.meta.url), 'utf8');
const migration = await readFile(new URL('../migrations/001_admin_hierarchy.sql', import.meta.url), 'utf8');
test('principal role and hierarchy endpoints exist', () => {
  assert.match(api, /SUPER_ADMIN_PRINCIPAL/);
  assert.match(api, /ONLY_PRINCIPAL_CAN_CREATE_SUPER_ADMIN/);
  assert.match(api, /admin\/users\/reset-password/);
  assert.match(api, /admin\/users\/change-password/);
});
test('temporary credentials require first password change and expire', () => {
  assert.match(api, /must_change_password/);
  assert.match(api, /temporary_password_expires_at/);
  assert.match(api, /interval '24 hours'/);
});
test('UI contains administrator management and forced password flow', () => {
  assert.match(ui, /id=["']forcePassword["']/);
  assert.match(ui, /id=["']changePasswordBtn["']/);
  assert.match(ui, /mustChangePassword/);

  assert.match(ui, /id=["']page-admins["']/);
  assert.match(ui, /id=["']adminManagement["']/);
  assert.match(ui, /id=["']newRole["']/);
  assert.match(ui, /id=["']createAdminBtn["']/);
  assert.match(ui, /id=["']loadAdminsBtn["']/);

  assert.match(ui, /admin\/users\/reset-password/);
  assert.match(ui, /admin\/users\/change-password/);
});
test('migration protects single principal and adds role', () => {
  assert.match(migration, /Expected exactly one existing SUPER_ADMIN/);
  assert.match(migration, /SUPER_ADMIN_PRINCIPAL/);
});
test('self-suspension is rejected and status target must be a UUID', () => {
  assert.match(api, /SELF_STATUS_CHANGE_NOT_ALLOWED/);
  assert.match(api, /uuidPattern\.test\(String\(input\.userId\)\)/);
});
test('duplicate username or email returns HTTP 409', () => {
  assert.match(api, /error\?\.code === '23505'/);
  assert.match(api, /ADMIN_IDENTIFIER_ALREADY_EXISTS/);
});
