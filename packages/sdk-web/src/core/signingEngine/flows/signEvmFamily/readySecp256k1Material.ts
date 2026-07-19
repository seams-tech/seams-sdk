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
import {
  requirePersistedEcdsaRoleLocalMaterial,
  type ThresholdEcdsaSessionRecord,
} from '../../session/persistence/records';
import {
  emailOtpAuthContextConsumedAtMs,
  emailOtpAuthContextRetention,
} from '../../session/identity/laneIdentity';
import { requireRouterAbEcdsaDerivationSigningWalletSessionFromRecord } from '../../session/routerAbSigningWalletSession';
import type { EcdsaRoleLocalWorkerHandle } from '../../session/keyMaterialBrands';
import {
  persistedEcdsaRoleLocalMaterialSource,
  resolveEcdsaRoleLocalMaterial,
  type EcdsaRoleLocalMaterialResolution,
} from '../../session/material/ecdsaRoleLocalMaterialResolver';
import { markRouterAbEcdsaDerivationWorkerMaterialRuntimeValidated } from '../../session/routerAbSigningWalletSession';
import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';
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

function requireResolvedRoleLocalWorkerHandle(
  resolution: EcdsaRoleLocalMaterialResolution,
): EcdsaRoleLocalWorkerHandle {
  switch (resolution.kind) {
    case 'live':
    case 'rehydrated':
      return resolution.liveHandle;
    case 'device_link_required':
      throw new Error(
        '[multichain] device_link_required: local threshold ECDSA material is unavailable',
      );
    case 'corrupt':
      throw new Error(
        `[multichain] threshold-ecdsa role-local material is corrupt (${resolution.reason}): ${resolution.message}`,
      );
    default: {
      const exhaustive: never = resolution;
      throw new Error(`Unsupported ECDSA role-local material resolution: ${String(exhaustive)}`);
    }
  }
}

export async function hydrateEcdsaRoleLocalMaterialForSigning(args: {
  record: ThresholdEcdsaSessionRecord;
  workerCtx: WorkerOperationContext;
}): Promise<EcdsaRoleLocalWorkerHandle> {
  const persistedMaterial = requirePersistedEcdsaRoleLocalMaterial(args.record);
  const resolution = await resolveEcdsaRoleLocalMaterial({
    purpose: 'transaction_signing',
    source: persistedEcdsaRoleLocalMaterialSource(persistedMaterial),
    workerCtx: args.workerCtx,
  });
  const liveHandle = requireResolvedRoleLocalWorkerHandle(resolution);
  if (!markRouterAbEcdsaDerivationWorkerMaterialRuntimeValidated(args.record)) {
    throw new Error(
      '[multichain] threshold-ecdsa hydrated material could not be bound to its signing session',
    );
  }
  return liveHandle;
}

function assertThresholdEcdsaSessionAuthorizationIsActive(
  record: ThresholdEcdsaSessionRecord,
): void {
  if (record.remainingUses <= 0) {
    throw new Error(
      '[multichain] threshold-ecdsa role-local session requires exhausted reauthorization',
    );
  }
  if (record.expiresAtMs <= Date.now()) {
    throw new Error(
      '[multichain] threshold-ecdsa role-local session requires expired reauthorization',
    );
  }
}

export async function buildReadySecp256k1SigningMaterialFromRecord(args: {
  record: ThresholdEcdsaSessionRecord;
  requestLabel: unknown;
  evmFamilySigningKeySlotId: unknown;
  workerCtx: WorkerOperationContext;
}): Promise<ReadySecp256k1SigningMaterial> {
  const evmFamilySigningKeySlotId = requireEvmFamilySigningKeySlotId(
    args.evmFamilySigningKeySlotId,
    'threshold-ecdsa signing evmFamilySigningKeySlotId',
  );
  assertMatchingEvmFamilySigningKeySlotId({
    expected: evmFamilySigningKeySlotId,
    actual: args.record.evmFamilySigningKeySlotId,
    actualLabel: 'threshold-ecdsa session record evmFamilySigningKeySlotId',
    message:
      '[multichain] threshold-ecdsa evmFamilySigningKeySlotId mismatch; reconnect threshold session',
  });
  assertMatchingEvmFamilySigningKeySlotId({
    expected: evmFamilySigningKeySlotId,
    actual: args.record.ecdsaRoleLocalPublicFacts.evmFamilySigningKeySlotId,
    actualLabel: 'threshold-ecdsa role-local publicFacts evmFamilySigningKeySlotId',
    message:
      '[multichain] threshold-ecdsa evmFamilySigningKeySlotId mismatch; reconnect threshold session',
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

  assertThresholdEcdsaSessionAuthorizationIsActive(args.record);
  const liveRoleLocalWorkerHandle = await hydrateEcdsaRoleLocalMaterialForSigning({
    record: args.record,
    workerCtx: args.workerCtx,
  });

  const signingWalletSession = requireRouterAbEcdsaDerivationSigningWalletSessionFromRecord(
    args.record,
  );
  const walletSessionJwt = signingWalletSession.auth.walletSessionJwt;

  const keyRef = buildThresholdEcdsaSecp256k1KeyRefFromSessionRecord({
    record: args.record,
  });
  if (
    keyRef.backendBinding?.materialKind !== 'role_local_worker_handle' ||
    keyRef.backendBinding.roleLocalMaterialHandle.materialHandle !==
      liveRoleLocalWorkerHandle.materialHandle
  ) {
    throw new Error(
      '[multichain] threshold-ecdsa signer material does not reference the hydrated role-local handle',
    );
  }
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
