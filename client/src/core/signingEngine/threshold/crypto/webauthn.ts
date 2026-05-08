import type { AccountId } from '../../../types/accountIds';
import type { ProfileAuthenticatorRecord } from '../../../indexedDB';
import {
  type WebAuthnAuthenticatorRecord,
  type WebAuthnIndexedDbClientPort,
  type WebAuthnIndexedDbPort,
  type WebAuthnPromptPort,
} from '../../walletAuth/webauthn/credentials/collectAuthenticationCredentialForChallengeB64u';
import {
  getPrfFirstB64uFromCredential,
  redactCredentialExtensionOutputs,
} from '../../walletAuth/webauthn/credentials/credentialExtensions';

export { getPrfFirstB64uFromCredential, redactCredentialExtensionOutputs };

export type ThresholdAuthenticatorRecord = ProfileAuthenticatorRecord & WebAuthnAuthenticatorRecord;
export type ThresholdIndexedDbClientPort =
  WebAuthnIndexedDbClientPort<ThresholdAuthenticatorRecord>;
export type ThresholdIndexedDbPort = WebAuthnIndexedDbPort<ThresholdAuthenticatorRecord>;
export type ThresholdWebAuthnPromptPort = WebAuthnPromptPort;

export type ThresholdEd25519ClientShareDeriverPort = {
  deriveThresholdEd25519ClientVerifyingShare: (args: {
    sessionId: string;
    nearAccountId: AccountId;
    prfFirstB64u: string;
    wrapKeySalt: string;
  }) => Promise<{
    success: boolean;
    nearAccountId?: string;
    clientVerifyingShareB64u: string;
    error?: string;
  }>;
};

export type ThresholdWarmSessionMaterialPort = {
  putWarmSessionMaterial: (args: {
    sessionId: string;
    prfFirstB64u: string;
    expiresAtMs: number;
    remainingUses: number;
    transport?: {
      curve?: 'ed25519' | 'ecdsa';
      relayerUrl?: string;
      walletSigningSessionId?: string;
      thresholdSessionAuthToken?: string;
      keyVersion?: string;
      shamirPrimeB64u?: string;
    };
  }) => Promise<void>;
  claimWarmSessionMaterial?: (args: { sessionId: string; uses?: number }) => Promise<{
    ok: boolean;
    code?: string;
    message?: string;
    prfFirstB64u?: string;
    remainingUses?: number;
    expiresAtMs?: number;
  }>;
  getWarmSessionStatus?: (args: { sessionId: string }) => Promise<{
    ok: boolean;
    code?: string;
    message?: string;
    remainingUses?: number;
    expiresAtMs?: number;
  }>;
  persistSigningSessionSealForThresholdSession?: (args: {
    sessionId: string;
    transport?: import('@/core/types/secure-confirm-worker').WarmSessionSealTransportInput;
  }) => Promise<{
    ok: boolean;
    code?: string;
    message?: string;
    keyVersion?: string;
    sealedSecretB64u?: string;
    remainingUses?: number;
    expiresAtMs?: number;
  }>;
};
export type ThresholdWarmSessionMaterialWriter = Pick<
  ThresholdWarmSessionMaterialPort,
  'putWarmSessionMaterial'
>;
export type ThresholdSigningKeyOpsPort = ThresholdEd25519ClientShareDeriverPort;
