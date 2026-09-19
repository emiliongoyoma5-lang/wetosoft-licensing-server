import { generateKeyPair, exportJWK } from 'node:crypto';

const { privateKey, publicKey } = await new Promise((resolve, reject) =>
  generateKeyPair('ed25519', (err, publicKey, privateKey) => err ? reject(err) : resolve({ publicKey, privateKey }))
);
const [priv, pub] = await Promise.all([exportJWK(privateKey), exportJWK(publicKey)]);
priv.alg = 'EdDSA'; priv.use = 'sig'; priv.kid = 'wetosoft-license-1';
pub.alg = 'EdDSA'; pub.use = 'sig'; pub.kid = 'wetosoft-license-1';
console.log('LICENSE_PRIVATE_JWK_JSON=' + JSON.stringify(priv));
console.log('LICENSE_PUBLIC_JWK_JSON=' + JSON.stringify(pub));
