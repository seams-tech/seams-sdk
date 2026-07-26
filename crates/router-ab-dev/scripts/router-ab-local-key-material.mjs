import { createPrivateKey, createPublicKey } from 'node:crypto';

const ED25519_PKCS8_SEED_PREFIX = Buffer.from(
  '302e020100300506032b657004220420',
  'hex',
);

export function localPeerSigningKeyBase64Url(value) {
  return Buffer.from(localPeerSigningSeedHex(value), 'hex').toString('base64url');
}

export function localPeerVerifyingKeyHex(value) {
  const seed = Buffer.from(localPeerSigningSeedHex(value), 'hex');
  const privateKey = createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_SEED_PREFIX, seed]),
    format: 'der',
    type: 'pkcs8',
  });
  const publicKey = createPublicKey(privateKey).export({ format: 'der', type: 'spki' });
  return Buffer.from(publicKey).subarray(-32).toString('hex');
}

function localPeerSigningSeedHex(value) {
  if (!/^[A-Za-z0-9_-]{43}$/.test(value)) {
    throw new Error('Router A/B local peer signing key must be 32-byte base64url');
  }
  const seed = Buffer.from(value, 'base64url');
  if (seed.length !== 32) {
    throw new Error('Router A/B local peer signing key must decode to 32 bytes');
  }
  return seed.toString('hex');
}
