import {
  SigningAuthPlanKind,
  type SigningAuthPlan,
  type WarmSessionStepUpAuthorization,
} from '@/core/signingEngine/stepUpConfirmation/types';
import { buildExportStepUpAuthorization } from './stepUpAuthorization';
import type { ExportStepUpAuthorization } from './stepUpAuthorization';
import type { UserConfirmDecision } from '@/core/signingEngine/stepUpConfirmation/types';

declare const confirmedPasskeyDecision: UserConfirmDecision;

void buildExportStepUpAuthorization({
  method: 'passkey',
  decision: confirmedPasskeyDecision,
  walletSessionUserId: 'wallet-1',
  publicKey: 'ed25519:public-key',
  curve: 'ed25519',
  intent: 'ed25519_export',
  chain: 'near',
  nearAccountId: 'alice.testnet',
  nearEd25519SigningKeyId: 'near-key-1',
  signerSlot: 1,
  thresholdSessionId: 'threshold-ed25519-1',
  signingGrantId: 'grant-ed25519-1',
});

void buildExportStepUpAuthorization({
  method: 'email_otp',
  decision: {
    confirmed: true,
    otpCode: '123456',
    emailOtpChallengeId: 'challenge-1',
  },
  emailOtpPrompt: {
    challengeId: 'challenge-1',
  },
  walletSessionUserId: 'wallet-1',
  publicKey: 'ed25519:public-key',
  curve: 'ed25519',
  intent: 'ed25519_export',
  chain: 'near',
  nearAccountId: 'alice.testnet',
  nearEd25519SigningKeyId: 'near-key-1',
  signerSlot: 1,
  thresholdSessionId: 'threshold-ed25519-1',
  signingGrantId: 'grant-ed25519-1',
});

const warmSigningAuthorization = {
  kind: 'warm_session',
  signingAuthPlan: {
    kind: SigningAuthPlanKind.WarmSession,
    method: 'passkey',
    accountId: 'alice.testnet',
    intent: 'transaction_sign',
    sessionId: 'session-1',
    expiresAtMs: 1,
    remainingUses: 1,
  },
  sessionId: 'session-1',
  expiresAtMs: 1,
  remainingUses: 1,
} satisfies WarmSessionStepUpAuthorization<
  Extract<SigningAuthPlan, { kind: typeof SigningAuthPlanKind.WarmSession }>
>;
void warmSigningAuthorization;

const invalidDirectWarmExportAuthorization: ExportStepUpAuthorization = {
  // @ts-expect-error export authorization requires fresh export-scoped passkey or Email OTP auth.
  kind: 'warm_session',
  signingAuthPlan: {
    // @ts-expect-error export authorization rejects warm-session signing plans.
    kind: SigningAuthPlanKind.WarmSession,
    method: 'passkey',
    accountId: 'alice.testnet',
    intent: 'ecdsa_export',
    sessionId: 'session-1',
    expiresAtMs: 1,
    remainingUses: 1,
  },
  sessionId: 'session-1',
  expiresAtMs: 1,
  remainingUses: 1,
  walletSessionUserId: 'alice.testnet',
  publicKey: '02'.padEnd(66, '1'),
  curve: 'ecdsa' as const,
  intent: 'ecdsa_export' as const,
  chain: 'evm' as const,
};
void invalidDirectWarmExportAuthorization;

const spreadWarmSigningAuthorization = {
  ...warmSigningAuthorization,
  walletSessionUserId: 'alice.testnet',
  publicKey: '02'.padEnd(66, '1'),
  curve: 'ecdsa',
  intent: 'ecdsa_export',
  chain: 'evm',
};

// @ts-expect-error broad spreads cannot upgrade transaction warm authority into export authority.
const invalidSpreadWarmExportAuthorization: ExportStepUpAuthorization =
  spreadWarmSigningAuthorization;
void invalidSpreadWarmExportAuthorization;

export {};
