import { hashPassword } from '../netlify/functions/auth.mjs';
const username = process.argv[2];
const password = process.argv[3];
if (!username || !password) { console.error('Usage: node scripts/create-admin.mjs USERNAME PASSWORD'); process.exit(1); }
console.log(JSON.stringify({ username, passwordHash: await hashPassword(password), role: 'SUPER_ADMIN' }, null, 2));
