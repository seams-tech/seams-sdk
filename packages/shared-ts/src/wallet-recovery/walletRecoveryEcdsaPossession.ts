import { base64UrlDecode, base64UrlEncode } from '../utils/base64';
import { sha256Bytes } from '../utils/digests';
import { parseDigestB64u, type DigestB64u } from '../utils/canonicalPrimitives';

const POSSESSION_CHALLENGE_DOMAIN_V1 =
  'seams/wallet-recovery/ecdsa-existing-material-possession/v1';
const POSSESSION_PROOF_SCHEME_V1 = 'secp256k1_bip340_sha256_v1';

export type WalletRecoveryEcdsaPossessionChallengeV1 = {
  readonly kind: 'wallet_recovery_ecdsa_possession_challenge_v1';
  readonly walletId: string;
  readonly reservationId: string;
  readonly replacementId: string;
  readonly keySetId: `evm_family_ecdsa:${string}`;
  readonly keyHandle: string;
  readonly recordedKeyManifestDigestB64u: DigestB64u;
  readonly publicCapabilityDigestB64u: DigestB64u;
  readonly authorityRefDigestB64u: DigestB64u;
  readonly derivationClientSharePublicKey33B64u: string;
  readonly expectedServerGeneration: string;
  readonly expiresAtMs: number;
  readonly serverNonceB64u: DigestB64u;
};

export type WalletRecoveryEcdsaPossessionProofV1 = {
  readonly kind: 'wallet_recovery_ecdsa_possession_proof_v1';
  readonly scheme: typeof POSSESSION_PROOF_SCHEME_V1;
  readonly signature64B64u: string;
};

function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function requireExactKeys(
  record: Record<string, unknown>,
  label: string,
  keys: readonly string[],
): void {
  const allowed = new Set(keys);
  for (const key of Object.keys(record)) {
    if (!allowed.has(key)) throw new Error(`${label}.${key} is not a supported field`);
  }
  for (const key of keys) {
    if (!Object.hasOwn(record, key)) throw new Error(`${label}.${key} is required`);
  }
}

function requireVisibleIdentifier(value: unknown, label: string): string {
  if (typeof value !== 'string' || value.length === 0 || value.trim() !== value) {
    throw new Error(`${label} must be a non-empty canonical identifier`);
  }
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code < 0x21 || code > 0x7e) {
      throw new Error(`${label} must contain visible ASCII bytes`);
    }
  }
  return value;
}

function isEcdsaKeySetId(value: string): value is `evm_family_ecdsa:${string}` {
  return value.startsWith('evm_family_ecdsa:') && value.length > 'evm_family_ecdsa:'.length;
}

function requireEcdsaKeySetId(value: unknown, label: string): `evm_family_ecdsa:${string}` {
  const keySetId = requireVisibleIdentifier(value, label);
  if (!isEcdsaKeySetId(keySetId)) throw new Error(`${label} must identify an ECDSA key set`);
  return keySetId;
}

function requireDigest(value: unknown, label: string): DigestB64u {
  try {
    return parseDigestB64u(value);
  } catch {
    throw new Error(`${label} must be canonical base64url for 32 bytes`);
  }
}

function requireCompressedPublicKey(value: unknown, label: string): string {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error(`${label} must be canonical base64url`);
  }
  let bytes: Uint8Array;
  try {
    bytes = base64UrlDecode(value);
  } catch {
    throw new Error(`${label} must be valid base64url`);
  }
  if (
    bytes.length !== 33 ||
    (bytes[0] !== 0x02 && bytes[0] !== 0x03) ||
    base64UrlEncode(bytes) !== value
  ) {
    throw new Error(`${label} must be canonical compressed secp256k1 public key bytes`);
  }
  return value;
}

function requirePositiveSafeInteger(value: unknown, label: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${label} must be a positive safe integer`);
  }
  return value;
}

function requireSignature64(value: unknown, label: string): string {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error(`${label} must be canonical base64url`);
  }
  let bytes: Uint8Array;
  try {
    bytes = base64UrlDecode(value);
  } catch {
    throw new Error(`${label} must be valid base64url`);
  }
  if (bytes.length !== 64 || base64UrlEncode(bytes) !== value) {
    throw new Error(`${label} must be canonical base64url for 64 bytes`);
  }
  return value;
}

export function parseWalletRecoveryEcdsaPossessionChallengeV1(
  value: unknown,
): WalletRecoveryEcdsaPossessionChallengeV1 {
  const record = requireRecord(value, 'walletRecoveryEcdsaPossessionChallenge');
  requireExactKeys(record, 'walletRecoveryEcdsaPossessionChallenge', [
    'kind',
    'walletId',
    'reservationId',
    'replacementId',
    'keySetId',
    'keyHandle',
    'recordedKeyManifestDigestB64u',
    'publicCapabilityDigestB64u',
    'authorityRefDigestB64u',
    'derivationClientSharePublicKey33B64u',
    'expectedServerGeneration',
    'expiresAtMs',
    'serverNonceB64u',
  ]);
  if (record.kind !== 'wallet_recovery_ecdsa_possession_challenge_v1') {
    throw new Error('walletRecoveryEcdsaPossessionChallenge.kind is invalid');
  }
  const keySetId = requireEcdsaKeySetId(
    record.keySetId,
    'walletRecoveryEcdsaPossessionChallenge.keySetId',
  );
  return {
    kind: 'wallet_recovery_ecdsa_possession_challenge_v1',
    walletId: requireVisibleIdentifier(
      record.walletId,
      'walletRecoveryEcdsaPossessionChallenge.walletId',
    ),
    reservationId: requireVisibleIdentifier(
      record.reservationId,
      'walletRecoveryEcdsaPossessionChallenge.reservationId',
    ),
    replacementId: requireVisibleIdentifier(
      record.replacementId,
      'walletRecoveryEcdsaPossessionChallenge.replacementId',
    ),
    keySetId,
    keyHandle: requireVisibleIdentifier(
      record.keyHandle,
      'walletRecoveryEcdsaPossessionChallenge.keyHandle',
    ),
    recordedKeyManifestDigestB64u: requireDigest(
      record.recordedKeyManifestDigestB64u,
      'walletRecoveryEcdsaPossessionChallenge.recordedKeyManifestDigestB64u',
    ),
    publicCapabilityDigestB64u: requireDigest(
      record.publicCapabilityDigestB64u,
      'walletRecoveryEcdsaPossessionChallenge.publicCapabilityDigestB64u',
    ),
    authorityRefDigestB64u: requireDigest(
      record.authorityRefDigestB64u,
      'walletRecoveryEcdsaPossessionChallenge.authorityRefDigestB64u',
    ),
    derivationClientSharePublicKey33B64u: requireCompressedPublicKey(
      record.derivationClientSharePublicKey33B64u,
      'walletRecoveryEcdsaPossessionChallenge.derivationClientSharePublicKey33B64u',
    ),
    expectedServerGeneration: requireVisibleIdentifier(
      record.expectedServerGeneration,
      'walletRecoveryEcdsaPossessionChallenge.expectedServerGeneration',
    ),
    expiresAtMs: requirePositiveSafeInteger(
      record.expiresAtMs,
      'walletRecoveryEcdsaPossessionChallenge.expiresAtMs',
    ),
    serverNonceB64u: requireDigest(
      record.serverNonceB64u,
      'walletRecoveryEcdsaPossessionChallenge.serverNonceB64u',
    ),
  };
}

export function parseWalletRecoveryEcdsaPossessionProofV1(
  value: unknown,
): WalletRecoveryEcdsaPossessionProofV1 {
  const record = requireRecord(value, 'walletRecoveryEcdsaPossessionProof');
  requireExactKeys(record, 'walletRecoveryEcdsaPossessionProof', [
    'kind',
    'scheme',
    'signature64B64u',
  ]);
  if (record.kind !== 'wallet_recovery_ecdsa_possession_proof_v1') {
    throw new Error('walletRecoveryEcdsaPossessionProof.kind is invalid');
  }
  if (record.scheme !== POSSESSION_PROOF_SCHEME_V1) {
    throw new Error('walletRecoveryEcdsaPossessionProof.scheme is invalid');
  }
  return {
    kind: 'wallet_recovery_ecdsa_possession_proof_v1',
    scheme: POSSESSION_PROOF_SCHEME_V1,
    signature64B64u: requireSignature64(
      record.signature64B64u,
      'walletRecoveryEcdsaPossessionProof.signature64B64u',
    ),
  };
}

export function walletRecoveryEcdsaPossessionChallengeCanonicalBytesV1(
  challenge: WalletRecoveryEcdsaPossessionChallengeV1,
): Uint8Array {
  const parsed = parseWalletRecoveryEcdsaPossessionChallengeV1(challenge);
  const fields: readonly (Uint8Array | string)[] = [
    POSSESSION_CHALLENGE_DOMAIN_V1,
    POSSESSION_PROOF_SCHEME_V1,
    parsed.walletId,
    parsed.reservationId,
    parsed.replacementId,
    parsed.keySetId,
    parsed.keyHandle,
    base64UrlDecode(parsed.recordedKeyManifestDigestB64u),
    base64UrlDecode(parsed.publicCapabilityDigestB64u),
    base64UrlDecode(parsed.authorityRefDigestB64u),
    base64UrlDecode(parsed.derivationClientSharePublicKey33B64u),
    parsed.expectedServerGeneration,
    base64UrlDecode(parsed.serverNonceB64u),
    expiryBytes(parsed.expiresAtMs),
  ];
  const output: number[] = [];
  for (const field of fields) {
    const bytes = typeof field === 'string' ? new TextEncoder().encode(field) : field;
    const length = bytes.length;
    if (length > 0xffffffff) throw new Error('wallet recovery possession field is too large');
    output.push(
      (length >>> 24) & 0xff,
      (length >>> 16) & 0xff,
      (length >>> 8) & 0xff,
      length & 0xff,
      ...bytes,
    );
  }
  return Uint8Array.from(output);
}

function expiryBytes(value: number): Uint8Array {
  let remaining = BigInt(value);
  const bytes = new Uint8Array(8);
  for (let index = bytes.length - 1; index >= 0; index -= 1) {
    bytes[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return bytes;
}

export async function walletRecoveryEcdsaPossessionChallengeDigestB64uV1(
  challenge: WalletRecoveryEcdsaPossessionChallengeV1,
): Promise<DigestB64u> {
  return parseDigestB64u(
    base64UrlEncode(
      await sha256Bytes(walletRecoveryEcdsaPossessionChallengeCanonicalBytesV1(challenge)),
    ),
  );
}

export const WALLET_RECOVERY_ECDSA_POSSESSION_PROOF_SCHEME_V1 = POSSESSION_PROOF_SCHEME_V1;
