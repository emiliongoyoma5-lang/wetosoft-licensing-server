import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const files = ['netlify/functions/api.mjs', 'netlify/functions/auth.mjs'];
for (const file of files) {
  const result = spawnSync(process.execPath, ['--check', resolve(root, file)], { stdio: 'inherit' });
  if (result.status !== 0) process.exit(result.status ?? 1);
}
console.log('Syntax OK');
