import { base64UrlEncode } from './base64';
import { alphabetizeStringify, sha256BytesUtf8 } from './digests';

export type ThresholdEcdsaKeyHandle = string & {
  readonly __brand: 'ThresholdEcdsaKeyHandle';
};

export type ThresholdEcdsaKeyHandleInput = {
  ecdsaThresholdKeyId: unknown;
  signingRootId: unknown;
  signingRootVersion: unknown;
};

function requiredString(value: unknown, field: string): string {
  const normalized = String(value ?? '').trim();
  if (!normalized) throw new Error(`[threshold-ecdsa-key-handle] ${field} is required`);
  return normalized;
}

function normalizedSigningRootVersion(value: unknown): string {
  return String(value ?? '').trim() || 'default';
}

export async function deriveThresholdEcdsaKeyHandle(
  input: ThresholdEcdsaKeyHandleInput,
): Promise<ThresholdEcdsaKeyHandle> {
  const canonical = alphabetizeStringify({
    domain: 'seams.threshold_ecdsa.key_handle.v1',
    ecdsaThresholdKeyId: requiredString(input.ecdsaThresholdKeyId, 'ecdsaThresholdKeyId'),
    signingRootId: requiredString(input.signingRootId, 'signingRootId'),
    signingRootVersion: normalizedSigningRootVersion(input.signingRootVersion),
  });
  const digest = await sha256BytesUtf8(canonical);
  return `ederivation-key-${base64UrlEncode(digest)}` as ThresholdEcdsaKeyHandle;
}
