import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import type { ThresholdEcdsaEmailOtpAuthContext } from '../../session/identity/laneIdentity';
import type { ensureEvmFamilyThresholdEcdsaRecordReady } from './ecdsaReadiness';

declare const readinessArgs: Parameters<typeof ensureEvmFamilyThresholdEcdsaRecordReady>[0];
declare const webauthnAuthentication: WebAuthnAuthenticationCredential;

const rawPasskeyReconnectArgs: Parameters<typeof ensureEvmFamilyThresholdEcdsaRecordReady>[0] = {
  ...readinessArgs,
  mode: 'planned_reconnect',
  reconnectPlan: {
    // @ts-expect-error raw passkey payloads must be normalized into an ECDSA provision plan first
    sessionId: 'threshold-session-1',
    walletSigningSessionId: 'wallet-signing-session-1',
    webauthnAuthentication,
  },
};
void rawPasskeyReconnectArgs;

const rawEmailOtpAuthContext = {
  policy: 'session',
  retention: 'session',
  reason: 'sign',
  authMethod: 'email_otp',
} satisfies ThresholdEcdsaEmailOtpAuthContext;

const rawEmailOtpReconnectArgs: Parameters<typeof ensureEvmFamilyThresholdEcdsaRecordReady>[0] = {
  ...readinessArgs,
  mode: 'planned_reconnect',
  reconnectPlan: {
    // @ts-expect-error raw Email OTP payloads must be normalized into an ECDSA provision plan first
    sessionId: 'threshold-session-1',
    walletSigningSessionId: 'wallet-signing-session-1',
    emailOtpAuthContext: rawEmailOtpAuthContext,
  },
};
void rawEmailOtpReconnectArgs;

export {};
