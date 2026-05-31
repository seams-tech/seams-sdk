import type { AccountId } from '@/core/types/accountIds';
import {
  SigningAuthPlanKind,
  type SigningAuthPlan,
  type WarmSessionStepUpAuthorization,
} from '@/core/signingEngine/stepUpConfirmation/types';
import type { ExportStepUpAuthorization } from './stepUpAuthorization';

declare const nearAccountId: AccountId;

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
    intent: 'ed25519_export',
    sessionId: 'session-1',
    expiresAtMs: 1,
    remainingUses: 1,
  },
  sessionId: 'session-1',
  expiresAtMs: 1,
  remainingUses: 1,
  nearAccountId,
  publicKey: 'ed25519:public-key',
  curve: 'ed25519' as const,
  intent: 'ed25519_export' as const,
  chain: 'near' as const,
};
void invalidDirectWarmExportAuthorization;

const spreadWarmSigningAuthorization = {
  ...warmSigningAuthorization,
  nearAccountId,
  publicKey: 'ed25519:public-key',
  curve: 'ed25519',
  intent: 'ed25519_export',
  chain: 'near',
};

// @ts-expect-error broad spreads cannot upgrade transaction warm authority into export authority.
const invalidSpreadWarmExportAuthorization: ExportStepUpAuthorization =
  spreadWarmSigningAuthorization;
void invalidSpreadWarmExportAuthorization;

export {};
