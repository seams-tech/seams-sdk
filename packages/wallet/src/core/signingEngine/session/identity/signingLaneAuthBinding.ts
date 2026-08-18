import type { RpId } from './evmFamilyEcdsaIdentity';
import { SIGNER_AUTH_METHODS, type SignerAuthMethod } from '@shared/utils/signerDomain';

export type SigningLaneAuthBinding =
  | {
      kind: typeof SIGNER_AUTH_METHODS.passkey;
      rpId: RpId;
      credentialIdB64u: string;
      providerSubjectId?: never;
    }
  | {
      kind: typeof SIGNER_AUTH_METHODS.emailOtp;
      providerSubjectId: string;
      rpId?: never;
      credentialIdB64u?: never;
    };

/**
 * R103C: the exact owner an authenticated human operation acts as. Derived
 * from the active Wallet Session authority through the active wallet auth
 * method — never assembled from independently supplied wallet, credential,
 * and slot values. A Passkey owner carries the signer slot of its one local
 * authenticator; Email OTP has no local authenticator and no slot.
 */
export type OwnerLaneScope =
  | {
      auth: Extract<SigningLaneAuthBinding, { kind: typeof SIGNER_AUTH_METHODS.passkey }>;
      signerSlot: number;
    }
  | {
      auth: Extract<SigningLaneAuthBinding, { kind: typeof SIGNER_AUTH_METHODS.emailOtp }>;
      signerSlot?: never;
    };

export function signingLaneAuthMethod(auth: SigningLaneAuthBinding): SignerAuthMethod {
  switch (auth.kind) {
    case SIGNER_AUTH_METHODS.passkey:
      return SIGNER_AUTH_METHODS.passkey;
    case SIGNER_AUTH_METHODS.emailOtp:
      return SIGNER_AUTH_METHODS.emailOtp;
  }
  auth satisfies never;
  throw new Error('[SigningSession] unsupported signing lane auth binding');
}

function requireSigningLaneAuthKeyPart(value: string, label: string): string {
  const normalized = String(value || '').trim();
  if (!normalized) {
    throw new Error(`[SigningSession] ${label} is required for signing lane authority`);
  }
  return normalized;
}

export function signingLaneAuthBindingKey(auth: SigningLaneAuthBinding): string {
  switch (auth.kind) {
    case SIGNER_AUTH_METHODS.passkey:
      return [
        SIGNER_AUTH_METHODS.passkey,
        requireSigningLaneAuthKeyPart(String(auth.rpId), 'passkey rpId'),
        requireSigningLaneAuthKeyPart(auth.credentialIdB64u, 'passkey credential'),
      ].join(':');
    case SIGNER_AUTH_METHODS.emailOtp:
      return [
        SIGNER_AUTH_METHODS.emailOtp,
        requireSigningLaneAuthKeyPart(auth.providerSubjectId, 'Email OTP provider subject'),
      ].join(':');
  }
  auth satisfies never;
  throw new Error('[SigningSession] unsupported signing lane auth binding');
}
