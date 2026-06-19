import { SigningAuthPlanKind, type SigningAuthPlan } from './types';

const warmSessionSigningAuthPlan = {
  kind: SigningAuthPlanKind.WarmSession,
  method: 'passkey',
  accountId: 'wallet.testnet',
  intent: 'transaction_sign',
  curve: 'ecdsa',
  sessionId: 'threshold-session-1',
  retention: 'session',
  expiresAtMs: 1_900_000_000_000,
  remainingUses: 1,
} satisfies SigningAuthPlan;
void warmSessionSigningAuthPlan;

const rootScopedWarmSessionSigningAuthPlan = {
  ...warmSessionSigningAuthPlan,
  // @ts-expect-error warm-session auth plans must not carry signing-root identity.
  signingRootId: 'project:dev',
} satisfies SigningAuthPlan;
void rootScopedWarmSessionSigningAuthPlan;
