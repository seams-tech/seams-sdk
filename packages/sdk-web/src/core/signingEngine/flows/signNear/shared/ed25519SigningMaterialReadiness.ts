import type { ThresholdEd25519KeyMaterial } from '@/core/accountData/near/nearAccountData.types';
import { restoreThresholdEd25519WorkerMaterialNearSignerWasm } from '@/core/signingEngine/chains/near/nearSignerWasm';
import {
  persistStoredThresholdEd25519SessionMaterialHandle,
  type ThresholdEd25519SessionRecord,
} from '@/core/signingEngine/session/persistence/records';
import type { WarmSessionCapabilityReader } from '@/core/signingEngine/session/warmCapabilities/types';
import {
  classifyRouterAbEd25519PersistedSigningRecord,
  markRouterAbEd25519WorkerMaterialRuntimeValidated,
  resolveRouterAbEd25519SigningRootFromRecord,
  type RouterAbEd25519PersistedSigningRecordState,
} from '@/core/signingEngine/session/routerAbSigningWalletSession';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type {
  ThresholdEd25519RestoreWorkerMaterialRequest,
  ThresholdEd25519WorkerMaterialCredentialAuthorization,
  ThresholdEd25519WorkerMaterialFailure,
} from '@/core/types/signer-worker';
import { buildRouterAbEd25519WorkerMaterialBinding } from '@/core/signingEngine/threshold/ed25519/workerMaterialBinding';
import {
  parseEd25519ClientVerifyingShareB64u,
  parseEd25519HssKeyVersion,
  parseEd25519RelayerKeyId,
} from '@/core/signingEngine/session/keyMaterialBrands';
import {
  requireThresholdEd25519WorkerMaterialHandle,
  type RouterAbEd25519RuntimeValidatedMaterial,
} from '@/core/signingEngine/threshold/ed25519/workerMaterialHandle';
import {
  resolveRouterAbEd25519WalletSessionStateFromCurrentRecord,
  resolveRouterAbEd25519WalletSessionStateFromRecord,
  type ResolvedRouterAbEd25519WalletSessionState,
} from './routerAbEd25519WalletSessionState';
import {
  requireRouterAbEd25519NormalSigningReadyState,
  type RouterAbEd25519NormalSigningReadyState,
} from './routerAbWalletSessionCredential';
import { SIGNING_SESSION_AUTH_UNAVAILABLE_ERROR } from './signingSessionAuthMode';
import {
  ed25519MaterialUnsealAuthorizationRequiredError,
  throwEd25519MaterialRestoreRequired,
  type Ed25519MaterialRestoreOperation,
} from './ed25519MaterialRestore';

export type RouterAbEd25519WorkerMaterialRestoreAuthorization =
  | {
      kind: 'unseal_authorization_available';
      unsealAuthorization: ThresholdEd25519WorkerMaterialCredentialAuthorization;
    }
  | {
      kind: 'unseal_authorization_unavailable';
      unsealAuthorization?: never;
    };

export type RouterAbEd25519ReadySigningMaterialState = {
  walletSessionState: ResolvedRouterAbEd25519WalletSessionState;
  routerAbReadyState: RouterAbEd25519NormalSigningReadyState;
  signingMaterial: RouterAbEd25519RuntimeValidatedMaterial;
};

function assertNeverRouterAbEd25519PersistedSigningRecordState(value: never): never {
  throw new Error(`Unexpected Router A/B Ed25519 persisted signing state: ${String(value)}`);
}

function thresholdEd25519ParticipantId(
  participant: ThresholdEd25519KeyMaterial['participants'][number],
): number {
  return participant.id;
}

function thresholdEd25519ParticipantIds(keyMaterial: ThresholdEd25519KeyMaterial): number[] {
  return keyMaterial.participants.map(thresholdEd25519ParticipantId);
}

export function requireSignableRouterAbEd25519WalletSessionState(args: {
  signingSessionCoordinator: WarmSessionCapabilityReader;
  thresholdSessionId: string;
  operation: Ed25519MaterialRestoreOperation;
}): ResolvedRouterAbEd25519WalletSessionState {
  const thresholdSessionId = String(args.thresholdSessionId || '').trim();
  if (!thresholdSessionId) {
    throw new Error(SIGNING_SESSION_AUTH_UNAVAILABLE_ERROR);
  }

  const record =
    args.signingSessionCoordinator.resolveEd25519RecordByThresholdSessionId(thresholdSessionId);
  const state = classifyRouterAbEd25519PersistedSigningRecord(record);
  switch (state.kind) {
    case 'runtime_validated': {
      // Sign-ready: auth/grant, threshold session identity, budget, Router A/B scope,
      // and current worker-owned material have all been validated for this runtime.
      const resolved = resolveRouterAbEd25519WalletSessionStateFromRecord(state.record);
      if (!resolved) {
        throw new Error(`${SIGNING_SESSION_AUTH_UNAVAILABLE_ERROR}: unresolved_signable_record`);
      }
      return resolved;
    }
    case 'material_hint_unvalidated':
      // A persisted worker-material handle exists, but the current worker has not
      // validated it against the active session/grant/material binding.
      throwEd25519MaterialRestoreRequired({
        operation: args.operation,
        thresholdSessionId,
        reason: 'pending_material',
      });
    case 'auth_ready_material_pending':
      // Auth/grant state exists, but required Router A/B worker material is missing.
      throwEd25519MaterialRestoreRequired({
        operation: args.operation,
        thresholdSessionId,
        reason: 'pending_material',
      });
    case 'restore_available':
      // Restore-ready: durable sealed worker material exists, so an explicit restore
      // phase can run before signing.
      throwEd25519MaterialRestoreRequired({
        operation: args.operation,
        thresholdSessionId,
        reason: 'restore_available',
      });
    case 'non_signing':
      // This record is valid for some session/lifecycle purpose, but cannot authorize
      // Router A/B signing.
      throw new Error(`${SIGNING_SESSION_AUTH_UNAVAILABLE_ERROR}: ${state.reason}`);
    case 'invalid':
      // The record is missing required Router A/B signing identity, auth, budget,
      // threshold material, or scope fields.
      throw new Error(`${SIGNING_SESSION_AUTH_UNAVAILABLE_ERROR}: ${state.reason}`);
    default:
      assertNeverRouterAbEd25519PersistedSigningRecordState(state satisfies never);
  }
}

export async function requireOrRestoreRouterAbEd25519WalletSessionState(args: {
  ctx: WorkerOperationContext;
  signingSessionCoordinator: WarmSessionCapabilityReader;
  thresholdSessionId: string;
  operation: Ed25519MaterialRestoreOperation;
  nearAccountId: string;
  thresholdKeyMaterial: ThresholdEd25519KeyMaterial;
  restoreAuthorization: RouterAbEd25519WorkerMaterialRestoreAuthorization;
}): Promise<RouterAbEd25519ReadySigningMaterialState> {
  const thresholdSessionId = String(args.thresholdSessionId || '').trim();
  if (!thresholdSessionId) {
    throw new Error(SIGNING_SESSION_AUTH_UNAVAILABLE_ERROR);
  }

  const record =
    args.signingSessionCoordinator.resolveEd25519RecordByThresholdSessionId(thresholdSessionId);
  const state = classifyRouterAbEd25519PersistedSigningRecord(record);
  switch (state.kind) {
    case 'runtime_validated':
      return await requireLoadedOrRestoreRouterAbEd25519SigningMaterial({
        ctx: args.ctx,
        record: state.record,
        thresholdSessionId,
        operation: args.operation,
        nearAccountId: args.nearAccountId,
        thresholdKeyMaterial: args.thresholdKeyMaterial,
        restoreAuthorization: args.restoreAuthorization,
      });
    case 'restore_available': {
      return await requireLoadedOrRestoreRouterAbEd25519SigningMaterial({
        ctx: args.ctx,
        record: state.record,
        thresholdSessionId,
        operation: args.operation,
        nearAccountId: args.nearAccountId,
        thresholdKeyMaterial: args.thresholdKeyMaterial,
        restoreAuthorization: args.restoreAuthorization,
      });
    }
    case 'material_hint_unvalidated': {
      const loaded = await tryRequireLoadedRouterAbEd25519SigningMaterial({
        ctx: args.ctx,
        record: state.record,
        thresholdSessionId,
        operation: args.operation,
        nearAccountId: args.nearAccountId,
        thresholdKeyMaterial: args.thresholdKeyMaterial,
      });
      if (loaded) return loaded;
      throwEd25519MaterialRestoreRequired({
        operation: args.operation,
        thresholdSessionId,
        reason: 'pending_material',
      });
    }
    case 'auth_ready_material_pending':
      throwEd25519MaterialRestoreRequired({
        operation: args.operation,
        thresholdSessionId,
        reason: 'pending_material',
      });
    case 'non_signing':
    case 'invalid':
      throw new Error(`${SIGNING_SESSION_AUTH_UNAVAILABLE_ERROR}: ${state.reason}`);
    default:
      assertNeverRouterAbEd25519PersistedSigningRecordState(state satisfies never);
  }
}

async function requireLoadedOrRestoreRouterAbEd25519SigningMaterial(args: {
  ctx: WorkerOperationContext;
  record: ThresholdEd25519SessionRecord;
  thresholdSessionId: string;
  operation: Ed25519MaterialRestoreOperation;
  nearAccountId: string;
  thresholdKeyMaterial: ThresholdEd25519KeyMaterial;
  restoreAuthorization: RouterAbEd25519WorkerMaterialRestoreAuthorization;
}): Promise<RouterAbEd25519ReadySigningMaterialState> {
  const loaded = await tryRequireLoadedRouterAbEd25519SigningMaterial({
    ctx: args.ctx,
    record: args.record,
    thresholdSessionId: args.thresholdSessionId,
    operation: args.operation,
    nearAccountId: args.nearAccountId,
    thresholdKeyMaterial: args.thresholdKeyMaterial,
  });
  if (loaded) return loaded;
  return await restoreRouterAbEd25519SigningMaterial(args);
}

async function tryRequireLoadedRouterAbEd25519SigningMaterial(args: {
  ctx: WorkerOperationContext;
  record: ThresholdEd25519SessionRecord;
  thresholdSessionId: string;
  operation: Ed25519MaterialRestoreOperation;
  nearAccountId: string;
  thresholdKeyMaterial: ThresholdEd25519KeyMaterial;
}): Promise<RouterAbEd25519ReadySigningMaterialState | null> {
  const state = classifyRouterAbEd25519PersistedSigningRecord(args.record);
  if (state.kind !== 'runtime_validated' && state.kind !== 'material_hint_unvalidated') {
    return null;
  }
  try {
    return await requireLoadedRouterAbEd25519SigningMaterial(args);
  } catch {
    return null;
  }
}

async function requireLoadedRouterAbEd25519SigningMaterial(args: {
  ctx: WorkerOperationContext;
  record: ThresholdEd25519SessionRecord;
  thresholdSessionId: string;
  operation: Ed25519MaterialRestoreOperation;
  nearAccountId: string;
  thresholdKeyMaterial: ThresholdEd25519KeyMaterial;
}): Promise<RouterAbEd25519ReadySigningMaterialState> {
  const walletSessionState = resolveRouterAbEd25519WalletSessionStateFromCurrentRecord(args.record);
  if (!walletSessionState) {
    throwEd25519MaterialRestoreRequired({
      operation: args.operation,
      thresholdSessionId: args.thresholdSessionId,
      reason: 'pending_material',
    });
  }
  const routerAbReadyState = requireRouterAbEd25519NormalSigningReadyState({
    state: walletSessionState,
    thresholdSessionId: args.thresholdSessionId,
    nearAccountId: args.nearAccountId,
    thresholdKeyMaterial: args.thresholdKeyMaterial,
  });
  const signingMaterial = await requireThresholdEd25519WorkerMaterialHandle({
    ctx: args.ctx,
    thresholdSessionId: args.thresholdSessionId,
    signingGrantId: walletSessionState.signingGrantId,
    existingMaterialHandle: walletSessionState.signingWalletSession.signingMaterial.materialHandle,
    existingMaterialBindingDigest:
      walletSessionState.signingWalletSession.signingMaterial.bindingDigest,
    existingMaterialClientVerifierB64u:
      walletSessionState.signingWalletSession.signingMaterial.clientVerifierB64u,
    signingRootId: routerAbReadyState.signingRootId,
    signingRootVersion: routerAbReadyState.signingRootVersion,
    expiresAtMs: routerAbReadyState.expiresAtMs,
    relayerKeyId: args.thresholdKeyMaterial.relayerKeyId,
    nearAccountId: args.nearAccountId,
    participantIds: thresholdEd25519ParticipantIds(args.thresholdKeyMaterial),
    signingWorkerId: routerAbReadyState.signingWorkerId,
    materialCreatedAtMs: args.record.materialCreatedAtMs,
    runtimePolicyScope: routerAbReadyState.runtimePolicyScope,
    thresholdKeyMaterial: args.thresholdKeyMaterial,
  });
  markRouterAbEd25519WorkerMaterialRuntimeValidated(args.record);
  return {
    walletSessionState,
    routerAbReadyState,
    signingMaterial,
  };
}

async function restoreRouterAbEd25519SigningMaterial(args: {
  ctx: WorkerOperationContext;
  record: ThresholdEd25519SessionRecord;
  thresholdSessionId: string;
  operation: Ed25519MaterialRestoreOperation;
  nearAccountId: string;
  thresholdKeyMaterial: ThresholdEd25519KeyMaterial;
  restoreAuthorization: RouterAbEd25519WorkerMaterialRestoreAuthorization;
}): Promise<RouterAbEd25519ReadySigningMaterialState> {
  if (args.restoreAuthorization.kind === 'unseal_authorization_unavailable') {
    throw ed25519MaterialUnsealAuthorizationRequiredError({
      operation: args.operation,
      thresholdSessionId: args.thresholdSessionId,
    });
  }
  const material = await buildExpectedWorkerMaterialBindingForRestore({
    record: args.record,
    operation: args.operation,
    thresholdSessionId: args.thresholdSessionId,
    thresholdKeyMaterial: args.thresholdKeyMaterial,
  });
  const restored = await restoreThresholdEd25519WorkerMaterialNearSignerWasm({
    request: {
      kind: 'ed25519_restore_worker_material_v1',
      sealedMaterial: sealedMaterialTransportFromRecord(args.record),
      expectedMaterialBinding: material.materialBinding,
      unsealAuthorization: args.restoreAuthorization.unsealAuthorization,
    },
    workerCtx: args.ctx,
  });
  if (!restored.ok) {
    throwWorkerMaterialRestoreFailure({
      failure: restored,
      operation: args.operation,
      thresholdSessionId: args.thresholdSessionId,
    });
  }
  if (
    restored.materialBindingDigest !== material.materialBindingDigest ||
    restored.clientVerifyingShareB64u !== material.materialBinding.clientVerifyingShareB64u
  ) {
    throw new Error('Router A/B Ed25519 restored worker material binding mismatch');
  }
  const persistedRecord = persistStoredThresholdEd25519SessionMaterialHandle({
    thresholdSessionId: args.thresholdSessionId,
    ed25519WorkerMaterialHandle: restored.materialHandle,
    ed25519WorkerMaterialBindingDigest: restored.materialBindingDigest,
    clientVerifyingShareB64u: restored.clientVerifyingShareB64u,
    sealedWorkerMaterialRef: restored.sealedWorkerMaterialRef,
    sealedWorkerMaterialB64u: restored.sealedWorkerMaterialB64u,
    materialFormatVersion: restored.materialFormatVersion,
    materialKeyId: restored.materialKeyId,
    materialCreatedAtMs: material.materialBinding.createdAtMs,
    signerSlot: restored.signerSlot,
    keyVersion: restored.keyVersion,
  });
  if (!persistedRecord) {
    throw new Error('Router A/B Ed25519 restored worker material persistence failed');
  }
  markRouterAbEd25519WorkerMaterialRuntimeValidated(persistedRecord);
  const walletSessionState = resolveRouterAbEd25519WalletSessionStateFromRecord(persistedRecord);
  if (!walletSessionState) {
    throw new Error('Router A/B Ed25519 restored worker material state did not become signable');
  }
  const routerAbReadyState = requireRouterAbEd25519NormalSigningReadyState({
    state: walletSessionState,
    thresholdSessionId: args.thresholdSessionId,
    nearAccountId: args.nearAccountId,
    thresholdKeyMaterial: args.thresholdKeyMaterial,
  });
  const signingMaterial = await requireThresholdEd25519WorkerMaterialHandle({
    ctx: args.ctx,
    thresholdSessionId: args.thresholdSessionId,
    signingGrantId: walletSessionState.signingGrantId,
    existingMaterialHandle: walletSessionState.signingWalletSession.signingMaterial.materialHandle,
    existingMaterialBindingDigest:
      walletSessionState.signingWalletSession.signingMaterial.bindingDigest,
    existingMaterialClientVerifierB64u:
      walletSessionState.signingWalletSession.signingMaterial.clientVerifierB64u,
    signingRootId: routerAbReadyState.signingRootId,
    signingRootVersion: routerAbReadyState.signingRootVersion,
    expiresAtMs: routerAbReadyState.expiresAtMs,
    relayerKeyId: args.thresholdKeyMaterial.relayerKeyId,
    nearAccountId: args.nearAccountId,
    participantIds: thresholdEd25519ParticipantIds(args.thresholdKeyMaterial),
    signingWorkerId: routerAbReadyState.signingWorkerId,
    materialCreatedAtMs: material.materialBinding.createdAtMs,
    runtimePolicyScope: routerAbReadyState.runtimePolicyScope,
    thresholdKeyMaterial: args.thresholdKeyMaterial,
  });
  return {
    walletSessionState,
    routerAbReadyState,
    signingMaterial,
  };
}

async function buildExpectedWorkerMaterialBindingForRestore(args: {
  record: ThresholdEd25519SessionRecord;
  operation: Ed25519MaterialRestoreOperation;
  thresholdSessionId: string;
  thresholdKeyMaterial: ThresholdEd25519KeyMaterial;
}): Promise<Awaited<ReturnType<typeof buildRouterAbEd25519WorkerMaterialBinding>>> {
  const materialCreatedAtMs = Math.floor(Number(args.record.materialCreatedAtMs) || 0);
  if (materialCreatedAtMs <= 0) {
    throwEd25519MaterialRestoreRequired({
      operation: args.operation,
      thresholdSessionId: args.thresholdSessionId,
      reason: 'restore_available',
    });
  }
  const signingRoot = resolveRouterAbEd25519SigningRootFromRecord(args.record);
  if (!signingRoot.ok) {
    throw new Error(
      `Router A/B Ed25519 sealed material signing root invalid: ${signingRoot.reason}`,
    );
  }
  const material = await buildRouterAbEd25519WorkerMaterialBinding({
    nearAccountId: String(args.record.nearAccountId || '').trim(),
    signerSlot: Math.floor(Number(args.record.signerSlot) || 0),
    signingRootId: signingRoot.value.signingRootId,
    signingRootVersion: signingRoot.value.signingRootVersion,
    relayerKeyId: parseEd25519RelayerKeyId(args.record.relayerKeyId),
    ed25519HssKeyVersion: parseEd25519HssKeyVersion(args.record.keyVersion),
    participantIds: args.record.participantIds,
    clientVerifyingShareB64u: parseEd25519ClientVerifyingShareB64u(
      args.record.clientVerifyingShareB64u,
    ),
    createdAtMs: materialCreatedAtMs,
  });
  if (
    material.materialBindingDigest !==
    String(args.record.ed25519WorkerMaterialBindingDigest || '').trim()
  ) {
    throw new Error('Router A/B Ed25519 sealed material binding digest mismatch');
  }
  if (material.materialBinding.materialKeyId !== String(args.record.materialKeyId || '').trim()) {
    throw new Error('Router A/B Ed25519 sealed material key id mismatch');
  }
  if (String(args.thresholdKeyMaterial.nearAccountId) !== material.materialBinding.nearAccountId) {
    throw new Error('Router A/B Ed25519 sealed material account mismatch');
  }
  if (Number(args.thresholdKeyMaterial.signerSlot) !== material.materialBinding.signerSlot) {
    throw new Error('Router A/B Ed25519 sealed material signer slot mismatch');
  }
  if (
    String(args.thresholdKeyMaterial.relayerKeyId || '').trim() !==
    material.materialBinding.relayerKeyId
  ) {
    throw new Error('Router A/B Ed25519 sealed material relayer key mismatch');
  }
  if (
    String(args.thresholdKeyMaterial.keyVersion || '').trim() !==
    material.materialBinding.keyVersion
  ) {
    throw new Error('Router A/B Ed25519 sealed material key version mismatch');
  }
  return material;
}

function sealedMaterialTransportFromRecord(
  record: ThresholdEd25519SessionRecord,
): ThresholdEd25519RestoreWorkerMaterialRequest['sealedMaterial'] {
  const sealedWorkerMaterialRef = String(record.sealedWorkerMaterialRef || '').trim();
  const sealedWorkerMaterialB64u = String(record.sealedWorkerMaterialB64u || '').trim();
  if (!sealedWorkerMaterialRef) {
    throw new Error('Router A/B Ed25519 sealed worker material ref is missing');
  }
  if (sealedWorkerMaterialB64u) {
    return {
      kind: 'inline_sealed_blob',
      sealedWorkerMaterialRef,
      sealedWorkerMaterialB64u,
    };
  }
  return {
    kind: 'storage_ref',
    sealedWorkerMaterialRef,
  };
}

function throwWorkerMaterialRestoreFailure(args: {
  failure: ThresholdEd25519WorkerMaterialFailure;
  operation: Ed25519MaterialRestoreOperation;
  thresholdSessionId: string;
}): never {
  if (args.failure.code === 'material_unseal_authorization_required') {
    throw ed25519MaterialUnsealAuthorizationRequiredError({
      operation: args.operation,
      thresholdSessionId: args.thresholdSessionId,
    });
  }
  if (args.failure.code === 'material_restore_required') {
    throwEd25519MaterialRestoreRequired({
      operation: args.operation,
      thresholdSessionId: args.thresholdSessionId,
      reason: 'restore_available',
    });
  }
  throw new Error(args.failure.message || args.failure.code);
}

export function isPendingRouterAbEd25519SigningMaterialState(
  state: RouterAbEd25519PersistedSigningRecordState,
): boolean {
  return (
    state.kind === 'material_hint_unvalidated' ||
    state.kind === 'auth_ready_material_pending' ||
    state.kind === 'restore_available'
  );
}
