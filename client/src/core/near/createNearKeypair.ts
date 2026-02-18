import { base58Encode } from '../../../../shared/src/utils/base58';
import { base64UrlDecode } from '../../../../shared/src/utils/base64';
import { ensureEd25519Prefix } from '../../../../shared/src/utils/validation';

type NearKeypair = {
  publicKey: string;
  privateKey: string;
};

function requireBase64Url32(value: unknown, label: string): Uint8Array {
  const raw = typeof value === 'string' ? value.trim() : '';
  if (!raw) throw new Error(`Missing ${label} in exported JWK`);
  const bytes = base64UrlDecode(raw);
  if (bytes.length !== 32) {
    throw new Error(`${label} must decode to 32 bytes (got ${bytes.length})`);
  }
  return bytes;
}

/**
 * Generate a NEAR-compatible Ed25519 keypair.
 *
 * Notes:
 * - Uses WebCrypto native Ed25519 primitives (no JS curve library).
 * - Outputs NEAR string format:
 *   - publicKey:  `ed25519:` + base58(pub32)
 *   - privateKey: `ed25519:` + base58(seed32 || pub32)
 */
export async function createNearKeypair(): Promise<NearKeypair> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    throw new Error('WebCrypto is unavailable; cannot generate Ed25519 keypair');
  }

  let generated: CryptoKeyPair;
  try {
    generated = await subtle.generateKey(
      { name: 'Ed25519' },
      true,
      ['sign', 'verify'],
    ) as CryptoKeyPair;
  } catch {
    throw new Error('WebCrypto Ed25519 key generation is unavailable in this runtime');
  }

  const [privateJwk, publicJwk] = await Promise.all([
    subtle.exportKey('jwk', generated.privateKey),
    subtle.exportKey('jwk', generated.publicKey),
  ]);

  const seed32 = requireBase64Url32(privateJwk.d, 'private JWK d');
  const pub32 = requireBase64Url32(publicJwk.x || privateJwk.x, 'public JWK x');

  const secret64 = new Uint8Array(64);
  secret64.set(seed32, 0);
  secret64.set(pub32, 32);

  return {
    publicKey: ensureEd25519Prefix(base58Encode(pub32)),
    privateKey: ensureEd25519Prefix(base58Encode(secret64)),
  };
}
