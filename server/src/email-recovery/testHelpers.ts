import type { EncryptedEmailEnvelope, EmailEncryptionContext } from './emailEncryptor';
import {
  chacha20poly1305Decrypt,
  hkdfSha25632,
  x25519PublicKeyFromSecret,
  x25519SharedSecret,
} from './nearSignerWasm';

export interface DecryptEmailForOutlayerTestOnlyInput {
  envelope: EncryptedEmailEnvelope;
  context: EmailEncryptionContext;
  recipientSk: Uint8Array;
}

/*
 * Sort the context keys by alphbetical order, then stringify
 * Needed for AEAD associated data in ChaCha20-Poly1305 decryption in the Outlayer worker
 */
function serializeContextForAad(context: EmailEncryptionContext): string {
  const entries = Object.entries(context).sort(([a], [b]) => a.localeCompare(b));
  return JSON.stringify(Object.fromEntries(entries));
}

/**
 * Test-only helper to decrypt an EncryptedEmailEnvelope using the recipient's
 * X25519 private key. This mirrors the Outlayer worker logic so unit tests can
 * perform deterministic round-trip checks of encryptEmailForOutlayer.
 */
export async function decryptEmailForOutlayerTestOnly(
  input: DecryptEmailForOutlayerTestOnlyInput,
): Promise<string> {
  const { envelope, context, recipientSk } = input;

  if (!(recipientSk instanceof Uint8Array) || recipientSk.length !== 32) {
    throw new Error('recipientSk must be a 32-byte X25519 secret key');
  }

  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  const fromB64 = (value: string): Uint8Array => {
    if (!value) return new Uint8Array();
    if (typeof Buffer !== 'undefined') {
      return new Uint8Array(Buffer.from(value, 'base64'));
    }
    const bin = atob(value);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) {
      out[i] = bin.charCodeAt(i);
    }
    return out;
  };

  const ephemeralPub = fromB64(envelope.ephemeral_pub);
  const nonce = fromB64(envelope.nonce);
  const ciphertext = fromB64(envelope.ciphertext);

  if (ephemeralPub.length !== 32) {
    throw new Error(`ephemeral_pub must decode to 32 bytes, got ${ephemeralPub.length}`);
  }
  if (nonce.length !== 12) {
    throw new Error(`nonce must decode to 12 bytes, got ${nonce.length}`);
  }

  // Derive shared secret and symmetric key exactly as in encryptEmailForOutlayer
  const sharedSecret = await x25519SharedSecret({
    secretKey32: recipientSk,
    peerPublicKey32: ephemeralPub,
  });
  const symmetricKey = await hkdfSha25632({
    ikm: sharedSecret,
    info: encoder.encode('email-dkim-encryption-key'),
  });

  const aad = encoder.encode(serializeContextForAad(context));
  const plaintext = await chacha20poly1305Decrypt({
    key32: symmetricKey,
    nonce12: nonce,
    aad,
    ciphertext,
  });

  return decoder.decode(plaintext);
}

/**
 * Test-only helper to derive a deterministic X25519 keypair from a seed string.
 * This is used only in unit tests.
 */
export async function deriveTestX25519KeypairFromSeed(
  seed: string,
): Promise<{ secretKey: Uint8Array; publicKey: Uint8Array }> {
  const encoder = new TextEncoder();
  const bytes = encoder.encode(seed || '');
  const sk = new Uint8Array(32);
  sk.set(bytes.slice(0, 32));
  const pk = await x25519PublicKeyFromSecret(sk);
  return { secretKey: sk, publicKey: pk };
}
