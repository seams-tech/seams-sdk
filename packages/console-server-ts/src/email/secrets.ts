import { base64UrlDecode, base64UrlEncode } from '../boundary';

export const CONSOLE_INVITATION_SECRET_ENVELOPE_VERSION = 'console-invitation-secret:aes-gcm:v1';
const INVITATION_SECRET_AAD_DOMAIN = 'seams/console-invitation-secret/aes-gcm/v1';
const INVITATION_SECRET_NONCE_BYTES = 12;
const INVITATION_SECRET_KEY_BYTES = 32;
const INVITATION_SECRET_MAGIC = new Uint8Array([0x73, 0x69, 0x6e, 0x76, 0x01]);

export interface SealedConsoleInvitationSecret {
  readonly ciphertextB64u: string;
  readonly keyId: string;
  readonly envelopeVersion: typeof CONSOLE_INVITATION_SECRET_ENVELOPE_VERSION;
}

export interface ConsoleInvitationSecretSealInput {
  readonly namespace: string;
  readonly orgId: string;
  readonly outboxId: string;
  readonly invitationId: string;
  readonly plaintextSecret: string;
}

export interface ConsoleInvitationSecretOpenInput {
  readonly namespace: string;
  readonly orgId: string;
  readonly outboxId: string;
  readonly invitationId: string;
  readonly sealedSecret: SealedConsoleInvitationSecret;
}

export interface ConsoleInvitationSecretCipher {
  seal(input: ConsoleInvitationSecretSealInput): Promise<SealedConsoleInvitationSecret>;
  open(input: ConsoleInvitationSecretOpenInput): Promise<string>;
}

export interface AesGcmConsoleInvitationSecretCipherOptions {
  readonly keyId: string;
  readonly keyBytes: Uint8Array;
}

export function createAesGcmConsoleInvitationSecretCipher(
  options: AesGcmConsoleInvitationSecretCipherOptions,
): ConsoleInvitationSecretCipher {
  return new AesGcmConsoleInvitationSecretCipher(options);
}

class AesGcmConsoleInvitationSecretCipher implements ConsoleInvitationSecretCipher {
  private readonly keyId: string;
  private readonly keyBytes: Uint8Array;

  constructor(options: AesGcmConsoleInvitationSecretCipherOptions) {
    this.keyId = requiredText(options.keyId, 'invitation secret keyId');
    if (!(options.keyBytes instanceof Uint8Array)) {
      throw new Error('invitation secret keyBytes must be Uint8Array');
    }
    if (options.keyBytes.byteLength !== INVITATION_SECRET_KEY_BYTES) {
      throw new Error(`invitation secret keyBytes must be ${INVITATION_SECRET_KEY_BYTES} bytes`);
    }
    this.keyBytes = new Uint8Array(options.keyBytes);
  }

  async seal(input: ConsoleInvitationSecretSealInput): Promise<SealedConsoleInvitationSecret> {
    const plaintextSecret = requiredText(input.plaintextSecret, 'invitationSecret');
    const crypto = requireCrypto();
    const nonce = crypto.getRandomValues(new Uint8Array(INVITATION_SECRET_NONCE_BYTES));
    const plaintextBytes = new TextEncoder().encode(plaintextSecret);
    try {
      const key = await importAesGcmKey(this.keyBytes, ['encrypt']);
      const ciphertext = new Uint8Array(
        await crypto.subtle.encrypt(
          {
            name: 'AES-GCM',
            iv: arrayBufferCopy(nonce),
            additionalData: arrayBufferCopy(
              invitationSecretAad({
                namespace: input.namespace,
                orgId: input.orgId,
                outboxId: input.outboxId,
                invitationId: input.invitationId,
                keyId: this.keyId,
              }),
            ),
            tagLength: 128,
          },
          key,
          arrayBufferCopy(plaintextBytes),
        ),
      );
      return {
        ciphertextB64u: base64UrlEncode(
          concatenateBytes([INVITATION_SECRET_MAGIC, nonce, ciphertext]),
        ),
        keyId: this.keyId,
        envelopeVersion: CONSOLE_INVITATION_SECRET_ENVELOPE_VERSION,
      };
    } finally {
      plaintextBytes.fill(0);
    }
  }

  async open(input: ConsoleInvitationSecretOpenInput): Promise<string> {
    if (input.sealedSecret.envelopeVersion !== CONSOLE_INVITATION_SECRET_ENVELOPE_VERSION) {
      throw new Error('Unsupported invitation secret envelope version');
    }
    if (input.sealedSecret.keyId !== this.keyId) {
      throw new Error(`Invitation secret key ${input.sealedSecret.keyId} is not configured`);
    }
    const envelope = base64UrlDecode(input.sealedSecret.ciphertextB64u);
    requireEnvelopeMagic(envelope);
    const nonceStart = INVITATION_SECRET_MAGIC.byteLength;
    const ciphertextStart = nonceStart + INVITATION_SECRET_NONCE_BYTES;
    const nonce = envelope.slice(nonceStart, ciphertextStart);
    const ciphertext = envelope.slice(ciphertextStart);
    const key = await importAesGcmKey(this.keyBytes, ['decrypt']);
    const plaintext = new Uint8Array(
      await requireCrypto().subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: arrayBufferCopy(nonce),
          additionalData: arrayBufferCopy(
            invitationSecretAad({
              namespace: input.namespace,
              orgId: input.orgId,
              outboxId: input.outboxId,
              invitationId: input.invitationId,
              keyId: this.keyId,
            }),
          ),
          tagLength: 128,
        },
        key,
        arrayBufferCopy(ciphertext),
      ),
    );
    try {
      return new TextDecoder().decode(plaintext);
    } finally {
      plaintext.fill(0);
      envelope.fill(0);
    }
  }
}

function invitationSecretAad(input: {
  readonly namespace: string;
  readonly orgId: string;
  readonly outboxId: string;
  readonly invitationId: string;
  readonly keyId: string;
}): Uint8Array {
  return new TextEncoder().encode(
    [
      INVITATION_SECRET_AAD_DOMAIN,
      requiredText(input.namespace, 'namespace'),
      requiredText(input.orgId, 'orgId'),
      requiredText(input.outboxId, 'outboxId'),
      requiredText(input.invitationId, 'invitationId'),
      requiredText(input.keyId, 'keyId'),
    ].join('\n'),
  );
}

function requireEnvelopeMagic(envelope: Uint8Array): void {
  const minimumLength = INVITATION_SECRET_MAGIC.byteLength + INVITATION_SECRET_NONCE_BYTES + 16;
  if (envelope.byteLength < minimumLength) {
    throw new Error('Invitation secret envelope is too short');
  }
  for (let index = 0; index < INVITATION_SECRET_MAGIC.byteLength; index += 1) {
    if (envelope[index] !== INVITATION_SECRET_MAGIC[index]) {
      throw new Error('Invitation secret envelope has invalid magic');
    }
  }
}

async function importAesGcmKey(
  keyBytes: Uint8Array,
  usages: readonly KeyUsage[],
): Promise<CryptoKey> {
  return await requireCrypto().subtle.importKey(
    'raw',
    arrayBufferCopy(keyBytes),
    { name: 'AES-GCM' },
    false,
    usages,
  );
}

function requireCrypto(): Crypto {
  if (!globalThis.crypto?.getRandomValues || !globalThis.crypto.subtle) {
    throw new Error('WebCrypto getRandomValues and subtle are required for invitation secrets');
  }
  return globalThis.crypto;
}

function concatenateBytes(parts: readonly Uint8Array[]): Uint8Array {
  let totalLength = 0;
  for (const part of parts) totalLength += part.byteLength;
  const output = new Uint8Array(totalLength);
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.byteLength;
  }
  return output;
}

function arrayBufferCopy(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

function requiredText(value: string, field: string): string {
  const normalized = value.trim();
  if (!normalized) throw new Error(`${field} is required`);
  return normalized;
}
