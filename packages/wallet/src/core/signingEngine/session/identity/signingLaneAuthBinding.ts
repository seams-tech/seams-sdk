import type { RpId } from './evmFamilyEcdsaIdentity';
import { SIGNER_AUTH_METHODS, type SignerAuthMethod } from '@shared/utils/signerDomain';
import type { DigestB64u } from '@shared/utils/canonicalPrimitives';
import type { LinkedDeviceEnrollmentId, LinkedDeviceId } from '@shared/signing-lanes/ids';
import type { WalletAuthMethodId } from '@shared/utils/domainIds';

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
 * Identity that distinguishes one linked Email OTP owner from the wallet-wide
 * factor and from another enrollment using that factor. It is separate from
 * `SigningLaneAuthBinding` because the provider subject describes the
 * authentication mechanism, while this tuple names the linked principal.
 */
export type LinkedOwnerLaneIdentityV1 = {
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly deviceId: LinkedDeviceId;
  readonly walletAuthMethodId: WalletAuthMethodId;
  readonly authorityDigest: DigestB64u;
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
      linkedOwner?: never;
    }
  | {
      auth: Extract<SigningLaneAuthBinding, { kind: typeof SIGNER_AUTH_METHODS.emailOtp }>;
      signerSlot?: never;
      linkedOwner?: never;
    }
  | {
      auth: Extract<SigningLaneAuthBinding, { kind: typeof SIGNER_AUTH_METHODS.emailOtp }>;
      signerSlot?: never;
      linkedOwner: LinkedOwnerLaneIdentityV1;
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
