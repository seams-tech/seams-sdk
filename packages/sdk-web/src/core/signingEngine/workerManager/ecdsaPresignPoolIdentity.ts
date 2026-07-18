export const FIXED_ECDSA_PRESIGN_PROTOCOL_ID =
  'seams/router-ab-ecdsa-presign/fixed-2of2/v1' as const;

export type EcdsaClientPresignPoolIdentity = {
  readonly poolKey: string;
  readonly walletKeyId: string;
  readonly walletId: string;
  readonly signingScopeB64u: string;
  readonly pairRole: 'client';
  readonly keyEpoch: string;
  readonly activationEpoch: string;
  readonly protocolId: typeof FIXED_ECDSA_PRESIGN_PROTOCOL_ID;
};

function requireIdentityString(value: unknown, label: string): string {
  if (typeof value !== 'string' || !value.trim()) throw new Error(`${label} is required`);
  return value;
}

export function parseEcdsaClientPresignPoolIdentity(
  value: unknown,
): EcdsaClientPresignPoolIdentity {
  if (typeof value !== 'object' || value === null) {
    throw new Error('poolIdentity is required');
  }
  const raw = value as Record<string, unknown>;
  if (raw.pairRole !== 'client') throw new Error('poolIdentity.pairRole must be client');
  if (raw.protocolId !== FIXED_ECDSA_PRESIGN_PROTOCOL_ID) {
    throw new Error('poolIdentity.protocolId is unsupported');
  }
  return {
    poolKey: requireIdentityString(raw.poolKey, 'poolIdentity.poolKey'),
    walletKeyId: requireIdentityString(raw.walletKeyId, 'poolIdentity.walletKeyId'),
    walletId: requireIdentityString(raw.walletId, 'poolIdentity.walletId'),
    signingScopeB64u: requireIdentityString(
      raw.signingScopeB64u,
      'poolIdentity.signingScopeB64u',
    ),
    pairRole: 'client',
    keyEpoch: requireIdentityString(raw.keyEpoch, 'poolIdentity.keyEpoch'),
    activationEpoch: requireIdentityString(
      raw.activationEpoch,
      'poolIdentity.activationEpoch',
    ),
    protocolId: FIXED_ECDSA_PRESIGN_PROTOCOL_ID,
  };
}

export function equalEcdsaClientPresignPoolIdentity(
  left: EcdsaClientPresignPoolIdentity,
  right: EcdsaClientPresignPoolIdentity,
): boolean {
  return (
    left.poolKey === right.poolKey &&
    left.walletKeyId === right.walletKeyId &&
    left.walletId === right.walletId &&
    left.signingScopeB64u === right.signingScopeB64u &&
    left.pairRole === right.pairRole &&
    left.keyEpoch === right.keyEpoch &&
    left.activationEpoch === right.activationEpoch &&
    left.protocolId === right.protocolId
  );
}
