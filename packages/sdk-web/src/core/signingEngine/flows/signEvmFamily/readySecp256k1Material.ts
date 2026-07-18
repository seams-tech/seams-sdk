import {
  assertMatchingEvmFamilySigningKeySlotId,
  requireEvmFamilySigningKeySlotId,
} from '@shared/signing-lanes';
import {
  buildKnownReadyThresholdEcdsaSessionPolicy,
  buildReadyEcdsaSignerSession,
  buildThresholdEcdsaSecp256k1KeyRefFromSessionRecord,
  toVerifiedEcdsaPublicFactsFromRecord,
} from '../../session/identity/evmFamilyEcdsaIdentity';
import type { ThresholdEcdsaSessionRecord } from '../../session/persistence/records';
import {
  emailOtpAuthContextConsumedAtMs,
  emailOtpAuthContextRetention,
} from '../../session/identity/laneIdentity';
import {
  requireRouterAbEcdsaDerivationSigningWalletSessionFromRecord,
} from '../../session/routerAbSigningWalletSession';
import { resolveEcdsaCapabilityHydration } from '../../session/identity/ecdsaCapabilityHydration';
import type { MpcCapabilityHydrationEntryPoint } from '../../capability/mpcCapabilityHydration';
import {
  buildReadySecp256k1SigningMaterial,
  type ReadySecp256k1SigningMaterial,
} from './signers/secp256k1';

type EcdsaSessionChain = 'tempo' | 'evm';

function inferThresholdEcdsaSessionChainFromLabel(labelRaw: unknown): EcdsaSessionChain | null {
  const label = String(labelRaw || '')
    .trim()
    .toLowerCase();
  if (!label) return null;
  if (label === 'tempo' || label.startsWith('tempo:')) return 'tempo';
  if (label === 'evm' || label.startsWith('evm:')) return 'evm';
  return null;
}

export async function buildReadySecp256k1SigningMaterialFromRecord(args: {
  record: ThresholdEcdsaSessionRecord;
  requestLabel: unknown;
  evmFamilySigningKeySlotId: unknown;
  hydrationEntryPoint: MpcCapabilityHydrationEntryPoint;
}): Promise<ReadySecp256k1SigningMaterial> {
  const evmFamilySigningKeySlotId = requireEvmFamilySigningKeySlotId(
    args.evmFamilySigningKeySlotId,
    'threshold-ecdsa signing evmFamilySigningKeySlotId',
  );
  assertMatchingEvmFamilySigningKeySlotId({
    expected: evmFamilySigningKeySlotId,
    actual: args.record.evmFamilySigningKeySlotId,
    actualLabel: 'threshold-ecdsa session record evmFamilySigningKeySlotId',
    message: '[multichain] threshold-ecdsa evmFamilySigningKeySlotId mismatch; reconnect threshold session',
  });
  assertMatchingEvmFamilySigningKeySlotId({
    expected: evmFamilySigningKeySlotId,
    actual: args.record.ecdsaRoleLocalPublicFacts.evmFamilySigningKeySlotId,
    actualLabel: 'threshold-ecdsa role-local publicFacts evmFamilySigningKeySlotId',
    message: '[multichain] threshold-ecdsa evmFamilySigningKeySlotId mismatch; reconnect threshold session',
  });
  const requestChain = inferThresholdEcdsaSessionChainFromLabel(args.requestLabel);
  if (requestChain && args.record.chainTarget.kind !== requestChain) {
    throw new Error('[multichain] threshold-ecdsa chain mismatch; reconnect threshold session');
  }
  if (
    args.record.source === 'email_otp' &&
    emailOtpAuthContextRetention(args.record.emailOtpAuthContext) === 'single_use' &&
    Number(emailOtpAuthContextConsumedAtMs(args.record.emailOtpAuthContext)) > 0
  ) {
    throw new Error(
      `[SigningEngine] ${requestChain || args.record.chainTarget.kind} signing requires fresh Email OTP verification with per_operation policy`,
    );
  }

  const hydration = resolveEcdsaCapabilityHydration({
    record: args.record,
    entryPoint: args.hydrationEntryPoint,
    nowMs: Date.now(),
  });
  switch (hydration.plan.kind) {
    case 'use_live_runtime':
    case 'rehydrate_active_session':
      break;
    case 'reauthorize_public_anchor':
      throw new Error(
        `[multichain] threshold-ecdsa role-local session requires ${hydration.plan.retirement} reauthorization`,
      );
    case 'blocked':
      throw new Error(
        `[multichain] threshold-ecdsa role-local session hydration is blocked: ${hydration.plan.reason}`,
      );
  }

  const signingWalletSession = requireRouterAbEcdsaDerivationSigningWalletSessionFromRecord(args.record);
  const walletSessionJwt = signingWalletSession.auth.walletSessionJwt;

  const keyRef = buildThresholdEcdsaSecp256k1KeyRefFromSessionRecord({
    record: args.record,
  });
  const publicFacts = await toVerifiedEcdsaPublicFactsFromRecord({ record: args.record });
  const signerSession = buildReadyEcdsaSignerSession({
    keyRef,
    publicFacts,
    sessionPolicy: buildKnownReadyThresholdEcdsaSessionPolicy({
      remainingUses: args.record.remainingUses,
      expiresAtMs: args.record.expiresAtMs,
    }),
    walletSessionJwt,
  });

  return buildReadySecp256k1SigningMaterial({
    walletId: args.record.walletId,
    signerSession,
    singleUseEmailOtpSession:
      args.record.source === 'email_otp' &&
      emailOtpAuthContextRetention(args.record.emailOtpAuthContext) === 'single_use',
  });
}
