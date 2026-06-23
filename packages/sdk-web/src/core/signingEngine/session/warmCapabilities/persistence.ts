import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import { normalizePositiveInteger } from '@shared/utils/normalize';
import type { AccountId } from '@/core/types/accountIds';
import {
  getStoredThresholdEd25519SessionRecordByThresholdSessionId,
  getStoredThresholdEd25519SessionRecordForAccount,
  listStoredThresholdEd25519SessionLaneRecordsForAccount,
  type ThresholdEd25519SessionRecord,
  upsertStoredThresholdEd25519SessionRecord,
} from '../persistence/records';
import type { RouterAbEd25519NormalSigningState } from '../../threshold/ed25519/routerAbNormalSigningState';
import type {
  ThresholdEcdsaEmailOtpAuthContext,
  ThresholdEd25519SessionStoreSource,
} from '../identity/laneIdentity';
import {
  parseThresholdRuntimePolicyScopeFromJwt,
  type ThresholdRuntimePolicyScope,
} from '../../threshold/sessionPolicy';
import { signingRootScopeFromRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import { publishResolvedIdentity } from '../persistence/sealedSessionStore';
import {
  parseEd25519ClientVerifyingShareB64u,
  parseEd25519SealedWorkerMaterialRef,
  parseEd25519WorkerMaterialBindingDigest,
  parseEd25519WorkerMaterialHandle,
  parseEd25519WorkerMaterialKeyId,
  type Ed25519ClientVerifyingShareB64u,
  type Ed25519SealedWorkerMaterialRef,
  type Ed25519WorkerMaterialBindingDigest,
  type Ed25519WorkerMaterialHandle,
  type Ed25519WorkerMaterialKeyId,
} from '../keyMaterialBrands';

type PersistWarmSessionEd25519CapabilityIdentity = {
  walletId: string;
  nearAccountId: AccountId;
  ed25519KeyScopeId: string;
  rpId: string;
  relayerUrl: string;
  relayerKeyId: string;
  signingRootId?: string;
  signingRootVersion?: string;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  participantIds: readonly number[];
  sessionId: string;
  signingGrantId: string;
  expiresAtMs: number;
  remainingUses: number;
  signerSlot: number;
  routerAbNormalSigning?: RouterAbEd25519NormalSigningState;
  updatedAtMs?: number;
};

type PersistWarmSessionEd25519NoWorkerMaterial = {
  clientVerifyingShareB64u?: never;
  ed25519WorkerMaterialHandle?: never;
  ed25519WorkerMaterialBindingDigest?: never;
  sealedWorkerMaterialRef?: never;
  sealedWorkerMaterialB64u?: never;
  materialFormatVersion?: never;
  materialKeyId?: never;
  materialCreatedAtMs?: never;
  keyVersion?: never;
};

type PersistWarmSessionEd25519RuntimeWorkerMaterial = {
  clientVerifyingShareB64u: Ed25519ClientVerifyingShareB64u;
  ed25519WorkerMaterialHandle: Ed25519WorkerMaterialHandle;
  ed25519WorkerMaterialBindingDigest: Ed25519WorkerMaterialBindingDigest;
  sealedWorkerMaterialRef?: never;
  sealedWorkerMaterialB64u?: never;
  materialFormatVersion?: never;
  materialKeyId?: never;
  materialCreatedAtMs: number;
  keyVersion: string;
};

type PersistWarmSessionEd25519SealedWorkerMaterial = {
  clientVerifyingShareB64u: Ed25519ClientVerifyingShareB64u;
  ed25519WorkerMaterialHandle?: Ed25519WorkerMaterialHandle;
  ed25519WorkerMaterialBindingDigest: Ed25519WorkerMaterialBindingDigest;
  sealedWorkerMaterialRef: Ed25519SealedWorkerMaterialRef;
  sealedWorkerMaterialB64u: string;
  materialFormatVersion: string;
  materialKeyId: Ed25519WorkerMaterialKeyId;
  materialCreatedAtMs: number;
  keyVersion: string;
};

type PersistWarmSessionEd25519WorkerMaterialFacts =
  | PersistWarmSessionEd25519NoWorkerMaterial
  | PersistWarmSessionEd25519RuntimeWorkerMaterial
  | PersistWarmSessionEd25519SealedWorkerMaterial;

type PersistWarmSessionEd25519CapabilityCommon = PersistWarmSessionEd25519CapabilityIdentity &
  PersistWarmSessionEd25519WorkerMaterialFacts;

export type PersistWarmSessionEd25519JwtEmailOtpCapabilityArgs =
  PersistWarmSessionEd25519CapabilityCommon & {
    kind: 'jwt_email_otp';
    sessionKind: 'jwt';
    jwt: string;
    source: 'email_otp';
    emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
  };

export type PersistWarmSessionEd25519JwtPasskeyCapabilityArgs =
  PersistWarmSessionEd25519CapabilityCommon & {
    kind: 'jwt_passkey';
    sessionKind: 'jwt';
    jwt: string;
    source: Exclude<ThresholdEd25519SessionStoreSource, 'email_otp'>;
    emailOtpAuthContext?: never;
  };

export type PersistWarmSessionEd25519CapabilityArgs =
  | PersistWarmSessionEd25519JwtEmailOtpCapabilityArgs
  | PersistWarmSessionEd25519JwtPasskeyCapabilityArgs;

type RetainedEd25519WorkerMaterialFacts =
  | {
      kind: 'none';
      clientVerifyingShareB64u?: never;
      ed25519WorkerMaterialHandle?: never;
      ed25519WorkerMaterialBindingDigest?: never;
      sealedWorkerMaterialRef?: never;
      sealedWorkerMaterialB64u?: never;
      materialFormatVersion?: never;
      materialKeyId?: never;
      materialCreatedAtMs?: never;
      keyVersion?: never;
    }
  | {
      kind: 'runtime_worker_material';
      clientVerifyingShareB64u: Ed25519ClientVerifyingShareB64u;
      ed25519WorkerMaterialHandle: Ed25519WorkerMaterialHandle;
      ed25519WorkerMaterialBindingDigest: Ed25519WorkerMaterialBindingDigest;
      sealedWorkerMaterialRef?: never;
      sealedWorkerMaterialB64u?: never;
      materialFormatVersion?: never;
      materialKeyId?: never;
      materialCreatedAtMs: number;
      keyVersion: string;
    }
  | {
      kind: 'sealed_worker_material';
      clientVerifyingShareB64u: Ed25519ClientVerifyingShareB64u;
      ed25519WorkerMaterialHandle?: Ed25519WorkerMaterialHandle;
      ed25519WorkerMaterialBindingDigest: Ed25519WorkerMaterialBindingDigest;
      sealedWorkerMaterialRef: Ed25519SealedWorkerMaterialRef;
      sealedWorkerMaterialB64u: string;
      materialFormatVersion: string;
      materialKeyId: Ed25519WorkerMaterialKeyId;
      materialCreatedAtMs: number;
      keyVersion: string;
    };

function nonEmptyString(value: unknown): string {
  return String(value || '').trim();
}

function positiveInteger(value: unknown): number {
  const parsed = Math.floor(Number(value));
  return Number.isFinite(parsed) && parsed > 0 ? parsed : 0;
}

function sameEd25519Participants(left: readonly number[], right: readonly number[]): boolean {
  const normalizedLeft = normalizeThresholdEd25519ParticipantIds(left);
  const normalizedRight = normalizeThresholdEd25519ParticipantIds(right);
  return Boolean(
    normalizedLeft &&
    normalizedRight &&
    normalizedLeft.length === normalizedRight.length &&
    normalizedLeft.every((value, index) => value === normalizedRight[index]),
  );
}

function resolveRetainedEd25519WorkerMaterialFacts(args: {
  sessionId: string;
  nearAccountId: AccountId;
  relayerKeyId: string;
  participantIds: readonly number[];
  signingRootId: string;
  signingRootVersion: string;
  signerSlot: number;
}): RetainedEd25519WorkerMaterialFacts {
  const candidates = listRetainedEd25519WorkerMaterialCandidateRecords(args);
  for (const existing of candidates) {
    const retained = readRetainedEd25519WorkerMaterialFacts({ ...args, existing });
    if (retained.kind !== 'none') return retained;
  }
  return { kind: 'none' };
}

function listRetainedEd25519WorkerMaterialCandidateRecords(args: {
  sessionId: string;
  nearAccountId: AccountId;
}): ThresholdEd25519SessionRecord[] {
  const candidates = new Map<string, ThresholdEd25519SessionRecord>();
  const push = (record: ThresholdEd25519SessionRecord | null): void => {
    if (!record) return;
    const sessionId = nonEmptyString(record.thresholdSessionId);
    if (!sessionId) return;
    candidates.set(sessionId, record);
  };
  push(getStoredThresholdEd25519SessionRecordByThresholdSessionId(args.sessionId));
  push(getStoredThresholdEd25519SessionRecordForAccount(args.nearAccountId));
  for (const record of listStoredThresholdEd25519SessionLaneRecordsForAccount(args.nearAccountId)) {
    push(record);
  }
  return [...candidates.values()].sort(
    (left, right) =>
      positiveInteger(right.updatedAtMs) - positiveInteger(left.updatedAtMs),
  );
}

function readRetainedEd25519WorkerMaterialFacts(args: {
  existing: ThresholdEd25519SessionRecord;
  nearAccountId: AccountId;
  relayerKeyId: string;
  participantIds: readonly number[];
  signingRootId: string;
  signingRootVersion: string;
  signerSlot: number;
}): RetainedEd25519WorkerMaterialFacts {
  const existing = args.existing;
  if (String(existing.nearAccountId) !== String(args.nearAccountId)) return { kind: 'none' };
  if (nonEmptyString(existing.relayerKeyId) !== args.relayerKeyId) return { kind: 'none' };
  if (!sameEd25519Participants(existing.participantIds, args.participantIds)) {
    return { kind: 'none' };
  }
  if (nonEmptyString(existing.signingRootId) !== args.signingRootId) return { kind: 'none' };
  if (nonEmptyString(existing.signingRootVersion) !== args.signingRootVersion) {
    return { kind: 'none' };
  }
  if (positiveInteger(existing.signerSlot) !== args.signerSlot) return { kind: 'none' };

  const clientVerifyingShareB64u = nonEmptyString(existing.clientVerifyingShareB64u);
  const ed25519WorkerMaterialHandle = nonEmptyString(existing.ed25519WorkerMaterialHandle);
  const ed25519WorkerMaterialBindingDigest = nonEmptyString(
    existing.ed25519WorkerMaterialBindingDigest,
  );
  const sealedWorkerMaterialRef = nonEmptyString(existing.sealedWorkerMaterialRef);
  const sealedWorkerMaterialB64u = nonEmptyString(existing.sealedWorkerMaterialB64u);
  const materialFormatVersion = nonEmptyString(existing.materialFormatVersion);
  const materialKeyId = nonEmptyString(existing.materialKeyId);
  const materialCreatedAtMs = positiveInteger(existing.materialCreatedAtMs);
  const keyVersion = nonEmptyString(existing.keyVersion);
  if (
    clientVerifyingShareB64u &&
    ed25519WorkerMaterialBindingDigest &&
    materialCreatedAtMs &&
    keyVersion
  ) {
    if (
      sealedWorkerMaterialRef &&
      sealedWorkerMaterialB64u &&
      materialFormatVersion &&
      materialKeyId
    ) {
      return {
        kind: 'sealed_worker_material',
        clientVerifyingShareB64u: parseEd25519ClientVerifyingShareB64u(clientVerifyingShareB64u),
        ...(ed25519WorkerMaterialHandle
          ? {
              ed25519WorkerMaterialHandle: parseEd25519WorkerMaterialHandle(
                ed25519WorkerMaterialHandle,
              ),
            }
          : {}),
        ed25519WorkerMaterialBindingDigest: parseEd25519WorkerMaterialBindingDigest(
          ed25519WorkerMaterialBindingDigest,
        ),
        sealedWorkerMaterialRef: parseEd25519SealedWorkerMaterialRef(sealedWorkerMaterialRef),
        sealedWorkerMaterialB64u,
        materialFormatVersion,
        materialKeyId: parseEd25519WorkerMaterialKeyId(materialKeyId),
        materialCreatedAtMs,
        keyVersion,
      };
    }
    if (ed25519WorkerMaterialHandle) {
      return {
        kind: 'runtime_worker_material',
        clientVerifyingShareB64u: parseEd25519ClientVerifyingShareB64u(clientVerifyingShareB64u),
        ed25519WorkerMaterialHandle: parseEd25519WorkerMaterialHandle(ed25519WorkerMaterialHandle),
        ed25519WorkerMaterialBindingDigest: parseEd25519WorkerMaterialBindingDigest(
          ed25519WorkerMaterialBindingDigest,
        ),
        materialCreatedAtMs,
        keyVersion,
      };
    }
  }
  return { kind: 'none' };
}

export function persistWarmSessionEd25519Capability(
  args: PersistWarmSessionEd25519CapabilityArgs,
): ThresholdEd25519SessionRecord {
  const sessionId = String(args.sessionId || '').trim();
  const signingGrantId = String(args.signingGrantId || '').trim();
  const expiresAtMs = Math.floor(Number(args.expiresAtMs));
  const remainingUses = normalizePositiveInteger(args.remainingUses) ?? 0;
  if (!sessionId) {
    throw new Error('Missing sessionId for warm threshold-ed25519 capability');
  }
  if (!signingGrantId) {
    throw new Error('Missing signingGrantId for warm threshold-ed25519 capability');
  }
  if (!Number.isFinite(expiresAtMs) || expiresAtMs <= 0) {
    throw new Error('Invalid expiresAtMs for warm threshold-ed25519 capability');
  }
  if (remainingUses <= 0) {
    throw new Error('Invalid remainingUses for warm threshold-ed25519 capability');
  }

  const participantIds = normalizeThresholdEd25519ParticipantIds(args.participantIds);
  if (!participantIds) {
    throw new Error('Missing participantIds for warm threshold-ed25519 capability');
  }

  const clientVerifyingShareB64u = String(args.clientVerifyingShareB64u || '').trim();
  const ed25519WorkerMaterialHandle = String(args.ed25519WorkerMaterialHandle || '').trim();
  const ed25519WorkerMaterialBindingDigest = String(
    args.ed25519WorkerMaterialBindingDigest || '',
  ).trim();
  const sealedWorkerMaterialRef = String(args.sealedWorkerMaterialRef || '').trim();
  const sealedWorkerMaterialB64u = String(args.sealedWorkerMaterialB64u || '').trim();
  const materialFormatVersion = String(args.materialFormatVersion || '').trim();
  const materialKeyId = String(args.materialKeyId || '').trim();
  const materialCreatedAtMs = Math.floor(Number(args.materialCreatedAtMs) || 0);
  const signerSlot = Math.floor(Number(args.signerSlot) || 0);
  if (signerSlot <= 0) {
    throw new Error('Invalid signerSlot for warm threshold-ed25519 capability');
  }
  const keyVersion = String(args.keyVersion || '').trim();
  const jwt = String(args.jwt || '').trim();
  const runtimePolicyScope =
    args.runtimePolicyScope || parseThresholdRuntimePolicyScopeFromJwt(jwt);
  const signingRootBinding = runtimePolicyScope
    ? signingRootScopeFromRuntimePolicyScope(runtimePolicyScope)
    : null;
  const signingRootId =
    String(args.signingRootId || '').trim() ||
    String(signingRootBinding?.signingRootId || '').trim();
  const signingRootVersion =
    String(args.signingRootVersion || '').trim() ||
    String(signingRootBinding?.signingRootVersion || '').trim();
  const authMethod = args.kind === 'jwt_email_otp' ? 'email_otp' : 'passkey';
  const source = args.source;
  const walletId = nonEmptyString(args.walletId);
  const ed25519KeyScopeId = nonEmptyString(args.ed25519KeyScopeId);
  if (!walletId) {
    throw new Error('Missing walletId for warm threshold-ed25519 capability');
  }
  if (!ed25519KeyScopeId) {
    throw new Error('Missing ed25519KeyScopeId for warm threshold-ed25519 capability');
  }
  const retainedMaterial =
    !clientVerifyingShareB64u &&
    !ed25519WorkerMaterialBindingDigest &&
    !sealedWorkerMaterialRef &&
    !sealedWorkerMaterialB64u &&
    signingRootId &&
    signingRootVersion
      ? resolveRetainedEd25519WorkerMaterialFacts({
          sessionId,
          nearAccountId: args.nearAccountId,
          relayerKeyId: String(args.relayerKeyId || '').trim(),
          participantIds,
          signingRootId,
          signingRootVersion,
          signerSlot,
        })
      : { kind: 'none' as const };

  const record = upsertStoredThresholdEd25519SessionRecord({
    walletId,
    nearAccountId: args.nearAccountId,
    ed25519KeyScopeId,
    rpId: String(args.rpId || '').trim(),
    relayerUrl: String(args.relayerUrl || '').trim(),
    relayerKeyId: String(args.relayerKeyId || '').trim(),
    participantIds,
    ...(signingRootId ? { signingRootId } : {}),
    ...(signingRootVersion ? { signingRootVersion } : {}),
    ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
    ...(clientVerifyingShareB64u
      ? { clientVerifyingShareB64u }
      : retainedMaterial.kind !== 'none'
        ? { clientVerifyingShareB64u: retainedMaterial.clientVerifyingShareB64u }
        : {}),
    ...(ed25519WorkerMaterialHandle ? { ed25519WorkerMaterialHandle } : {}),
    ...(!ed25519WorkerMaterialHandle &&
    retainedMaterial.kind !== 'none' &&
    retainedMaterial.ed25519WorkerMaterialHandle
      ? { ed25519WorkerMaterialHandle: retainedMaterial.ed25519WorkerMaterialHandle }
      : {}),
    ...(ed25519WorkerMaterialBindingDigest
      ? { ed25519WorkerMaterialBindingDigest }
      : retainedMaterial.kind !== 'none'
        ? {
            ed25519WorkerMaterialBindingDigest: retainedMaterial.ed25519WorkerMaterialBindingDigest,
          }
        : {}),
    ...(sealedWorkerMaterialRef
      ? { sealedWorkerMaterialRef }
      : retainedMaterial.kind === 'sealed_worker_material'
        ? { sealedWorkerMaterialRef: retainedMaterial.sealedWorkerMaterialRef }
        : {}),
    ...(sealedWorkerMaterialB64u
      ? { sealedWorkerMaterialB64u }
      : retainedMaterial.kind === 'sealed_worker_material'
        ? { sealedWorkerMaterialB64u: retainedMaterial.sealedWorkerMaterialB64u }
        : {}),
    ...(materialFormatVersion
      ? { materialFormatVersion }
      : retainedMaterial.kind === 'sealed_worker_material'
        ? { materialFormatVersion: retainedMaterial.materialFormatVersion }
        : {}),
    ...(materialKeyId
      ? { materialKeyId }
      : retainedMaterial.kind === 'sealed_worker_material'
        ? { materialKeyId: retainedMaterial.materialKeyId }
        : {}),
    ...(materialCreatedAtMs > 0
      ? { materialCreatedAtMs }
      : retainedMaterial.kind !== 'none'
        ? { materialCreatedAtMs: retainedMaterial.materialCreatedAtMs }
        : {}),
    signerSlot,
    ...(keyVersion
      ? { keyVersion }
      : retainedMaterial.kind !== 'none'
        ? { keyVersion: retainedMaterial.keyVersion }
        : {}),
    ...(args.routerAbNormalSigning ? { routerAbNormalSigning: args.routerAbNormalSigning } : {}),
    thresholdSessionKind: 'jwt',
    thresholdSessionId: sessionId,
    signingGrantId,
    ...(jwt ? { walletSessionJwt: jwt } : {}),
    expiresAtMs,
    remainingUses,
    ...(args.kind === 'jwt_email_otp' ? { emailOtpAuthContext: args.emailOtpAuthContext } : {}),
    updatedAtMs: Math.floor(Number(args.updatedAtMs ?? Date.now()) || 0),
    source,
  });
  if (!record) {
    throw new Error('Failed to persist warm threshold-ed25519 capability');
  }
  publishResolvedIdentity({
    walletId: record.walletId,
    authMethod,
    curve: 'ed25519',
    chain: 'near',
    signingGrantId,
    thresholdSessionId: sessionId,
  });
  return record;
}
