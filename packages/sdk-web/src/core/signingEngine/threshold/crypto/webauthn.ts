import type { WarmSessionMaterialOperationTarget } from '../../session/emailOtp/sealedRuntimePurpose';
import type { WarmSessionSealTransportInput } from '@/core/types/secure-confirm-worker';
import type { ProfileAuthenticatorRecord } from '../../../indexedDB';
import {
  type WebAuthnAuthenticatorRecord,
  type WebAuthnCredentialStorePort,
  type WebAuthnPromptPort,
} from '../../webauthnAuth/credentials/collectAuthenticationCredentialForChallengeB64u';
import {
  getPrfFirstB64uFromCredential,
  redactCredentialExtensionOutputs,
} from '../../webauthnAuth/credentials/credentialExtensions';

export {
  getPrfFirstB64uFromCredential,
  redactCredentialExtensionOutputs,
};

export type ThresholdAuthenticatorRecord = ProfileAuthenticatorRecord & WebAuthnAuthenticatorRecord;
export type ThresholdCredentialStorePort =
  WebAuthnCredentialStorePort<ThresholdAuthenticatorRecord>;
export type ThresholdWebAuthnPromptPort = WebAuthnPromptPort;

export type ThresholdWarmSessionMaterialPort = {
  putWarmSessionMaterial: (args: {
    thresholdSessionId: string;
    prfFirstB64u: string;
    expiresAtMs: number;
    remainingUses: number;
    transport?: WarmSessionSealTransportInput;
  }) => Promise<void>;
  claimWarmSessionMaterial?: (args: WarmSessionMaterialOperationTarget & {
    uses?: number;
  }) => Promise<{
    ok: boolean;
    code?: string;
    message?: string;
    prfFirstB64u?: string;
    remainingUses?: number;
    expiresAtMs?: number;
  }>;
  getWarmSessionStatus?: (args: { thresholdSessionId: string }) => Promise<{
    ok: boolean;
    code?: string;
    message?: string;
    remainingUses?: number;
    expiresAtMs?: number;
  }>;
  persistSigningSessionSealForThresholdSession?: (args: {
    thresholdSessionId: string;
    transport: Exclude<WarmSessionSealTransportInput, { authMethod: 'email_otp' }>;
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
