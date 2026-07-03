import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import { buildEmailOtpAuthContextForWalletAuthMethod } from '../../session/identity/laneIdentity';
import type { ensureEvmFamilyThresholdEcdsaRecordReady } from './ecdsaReadiness';

declare const readinessArgs: Parameters<typeof ensureEvmFamilyThresholdEcdsaRecordReady>[0];
declare const webauthnAuthentication: WebAuthnAuthenticationCredential;

const rawPasskeyReconnectArgs: Parameters<typeof ensureEvmFamilyThresholdEcdsaRecordReady>[0] = {
  ...readinessArgs,
  mode: 'planned_reconnect',
  reconnectPlan: {
    sessionId: 'threshold-session-1',
    signingGrantId: 'signing-grant-1',
    // @ts-expect-error raw passkey payloads must be normalized into an ECDSA provision plan first
    webauthnAuthentication,
  },
};
void rawPasskeyReconnectArgs;

const rawEmailOtpAuthContext = buildEmailOtpAuthContextForWalletAuthMethod({
walletId: 'wallet.testnet',
emailHashHex: 'email-hash',
policy: 'session',
  retention: 'session',
  reason: 'sign',
  provider: 'google',
  providerUserId: 'google-subject-1',
});

const rawEmailOtpReconnectArgs: Parameters<typeof ensureEvmFamilyThresholdEcdsaRecordReady>[0] = {
  ...readinessArgs,
  mode: 'planned_reconnect',
  reconnectPlan: {
    sessionId: 'threshold-session-1',
    signingGrantId: 'signing-grant-1',
    // @ts-expect-error raw Email OTP payloads must be normalized into an ECDSA provision plan first
    emailOtpAuthContext: rawEmailOtpAuthContext,
  },
};
void rawEmailOtpReconnectArgs;

export {};
