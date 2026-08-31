import { SigningAuthPlanKind, type SigningAuthPlan } from './types';
import type { ExactEvmFamilyWalletSessionAuthorization } from '../session/material/ecdsaSigningCapability';
import type { MpcMaterialActivationRef } from '@shared/utils/domainIds';

declare const materialActivation: MpcMaterialActivationRef;
declare const authorization: ExactEvmFamilyWalletSessionAuthorization;

const warmSessionSigningAuthPlan = {
  kind: SigningAuthPlanKind.WarmSession,
  method: 'passkey',
  accountId: 'wallet.testnet',
  intent: 'transaction_sign',
  curve: 'ed25519',
  thresholdSessionId: 'threshold-session-1',
  retention: 'session',
  expiresAtMs: 1_900_000_000_000,
  remainingUses: 1,
} satisfies SigningAuthPlan;
void warmSessionSigningAuthPlan;

const ecdsaWarmSessionSigningAuthPlan = {
  kind: SigningAuthPlanKind.WarmSession,
  method: 'email_otp',
  accountId: 'wallet.testnet',
  intent: 'transaction_sign',
  curve: 'ecdsa',
  materialActivation,
  authorization,
  retention: 'session',
  expiresAtMs: 1_900_000_000_000,
  remainingUses: 1,
} satisfies SigningAuthPlan;
void ecdsaWarmSessionSigningAuthPlan;

// @ts-expect-error ECDSA warm authorization has no threshold session identity.
const ecdsaWarmSessionWithThresholdId: SigningAuthPlan = {
  ...ecdsaWarmSessionSigningAuthPlan,
  thresholdSessionId: 'fabricated-threshold-session',
};
void ecdsaWarmSessionWithThresholdId;

// @ts-expect-error Ed25519 warm authorization requires threshold session identity.
const ed25519WarmSessionWithoutThresholdId: SigningAuthPlan = {
  kind: SigningAuthPlanKind.WarmSession,
  method: 'passkey',
  accountId: 'wallet.testnet',
  intent: 'transaction_sign',
  curve: 'ed25519',
  retention: 'session',
  expiresAtMs: 1_900_000_000_000,
  remainingUses: 1,
};
void ed25519WarmSessionWithoutThresholdId;

const rootScopedWarmSessionSigningAuthPlan = {
  ...warmSessionSigningAuthPlan,
  // @ts-expect-error warm-session auth plans must not carry signing-root identity.
  signingRootId: 'project:dev',
} satisfies SigningAuthPlan;
void rootScopedWarmSessionSigningAuthPlan;
