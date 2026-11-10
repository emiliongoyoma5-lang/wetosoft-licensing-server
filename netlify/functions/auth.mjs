import { randomBytes, scrypt as scryptCb, createHash, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';
const scrypt = promisify(scryptCb);

export const sha256 = value => createHash('sha256').update(value, 'utf8').digest('hex');
export const randomToken = (bytes=32) => randomBytes(bytes).toString('base64url');

export async function hashPassword(password) {
  if (typeof password !== 'string' || password.length < 12) throw new Error('PASSWORD_TOO_SHORT');
  const salt = randomBytes(16);
  const derived = await scrypt(password, salt, 64, { N: 16384, r: 8, p: 1 });
  return `scrypt$16384$8$1$${salt.toString('base64url')}$${Buffer.from(derived).toString('base64url')}`;
}

export async function verifyPassword(password, encoded) {
  try {
    if (typeof password !== 'string' || typeof encoded !== 'string') return false;
    const parts = encoded.split('$');
    if (parts.length !== 6) return false;
    const [scheme, n, r, p, saltB64, hashB64] = parts;

    // Accept only the exact parameters and encoding emitted by hashPassword.
    // This prevents attacker-controlled scrypt cost parameters in stored data.
    if (scheme !== 'scrypt' || n !== '16384' || r !== '8' || p !== '1') return false;
    if (!/^[A-Za-z0-9_-]{22}$/.test(saltB64) || !/^[A-Za-z0-9_-]{86}$/.test(hashB64)) return false;

    const salt = Buffer.from(saltB64, 'base64url');
    const expected = Buffer.from(hashB64, 'base64url');
    if (salt.length !== 16 || expected.length !== 64) return false;

    const derived = await scrypt(password, salt, 64, { N: 16384, r: 8, p: 1 });
    const actual = Buffer.from(derived);
    return timingSafeEqual(expected, actual);
  } catch {
    return false;
  }
}
