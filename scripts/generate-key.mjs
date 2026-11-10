import { generateKeyPairSync } from 'node:crypto';

const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const privateJwk = privateKey.export({ format: 'jwk' });
const publicJwk = publicKey.export({ format: 'jwk' });
privateJwk.alg = 'EdDSA';
privateJwk.use = 'sig';
publicJwk.alg = 'EdDSA';
publicJwk.use = 'sig';
console.log('LICENSE_PRIVATE_JWK_JSON (store as a secret; never commit):');
console.log(JSON.stringify(privateJwk));
console.log('LICENSE_PUBLIC_JWK_JSON (safe to distribute):');
console.log(JSON.stringify(publicJwk));
