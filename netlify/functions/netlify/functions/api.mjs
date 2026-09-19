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
    const [scheme, n, r, p, saltB64, hashB64] = String(encoded).split('$');
    if (scheme !== 'scrypt') return false;
    const derived = await scrypt(password, Buffer.from(saltB64, 'base64url'), 64, { N: Number(n), r: Number(r), p: Number(p) });
    const expected = Buffer.from(hashB64, 'base64url');
    const actual = Buffer.from(derived);
    return expected.length === actual.length && timingSafeEqual(expected, actual);
  } catch { return false; }
                            }
      
