import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import { normalizePositiveInteger } from '@shared/utils/normalize';
import type { AccountId } from '@/core/types/accountIds';
import {
  buildOperationUsableThresholdEd25519SessionRecord,
  buildThresholdEd25519SessionFact,
  commitCurrentThresholdEd25519Session,
  describeOperationUsableThresholdEd25519SessionRecordRejection,
  getStoredThresholdEd25519SessionRecordByThresholdSessionId,
  getStoredThresholdEd25519SessionRecordForAccount,
  listStoredThresholdEd25519SessionLaneRecordsForAccount,
  requireCommittedThresholdEd25519Session,
  upsertThresholdEd25519SessionFact,
  type ThresholdEd25519MaterialReadySessionRecord,
  type ThresholdEd25519RestoreAvailableSessionRecord,
  type ThresholdEd25519SessionRecord,
  type ThresholdEd25519UpsertMaterialFields,
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
  nearEd25519SigningKeyId: string;
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
  routerAbNormalSigning: RouterAbEd25519NormalSigningState;
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
};

type PersistWarmSessionEd25519WorkerMaterialFacts =
  | PersistWarmSessionEd25519NoWorkerMaterial
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
    passkeyCredentialIdB64u: string;
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
    };

function nonEmptyString(value: unknown): string {
  return String(value || '').trim();
}

function isMaterialPendingOnlyRejection(reasons: readonly string[]): boolean {
  return reasons.length === 1 && reasons[0] === 'material_pending';
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
  // Advance-only retention: order candidates by MATERIAL GENERATION
  // (materialCreatedAtMs — see session/ed25519MaterialAdvance.ts), newest first,
  // not by updatedAtMs. Policy writes bump updatedAtMs without touching material,
  // so an updatedAtMs ordering could retain an older material generation over a
  // newer one and regress the session's material at login. The material binding
  // does not include the threshold session id, so the newest generation that
  // passes the retain gates (account/relayer/participants/root/slot) is valid
  // for any session sharing that binding context.
  return [...candidates.values()].sort(
    (left, right) =>
      positiveInteger(right.materialCreatedAtMs) - positiveInteger(left.materialCreatedAtMs) ||
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

  switch (existing.materialState) {
    case 'material_ready':
      return retainedEd25519WorkerMaterialFactsFromReadyRecord(existing);
    case 'restore_available':
      return retainedEd25519WorkerMaterialFactsFromRestoreRecord(existing);
    case 'auth_ready_material_pending':
      return { kind: 'none' };
  }
}

function retainedEd25519WorkerMaterialFactsFromReadyRecord(
  record: ThresholdEd25519MaterialReadySessionRecord,
): RetainedEd25519WorkerMaterialFacts {
  return {
    kind: 'sealed_worker_material',
    clientVerifyingShareB64u: parseEd25519ClientVerifyingShareB64u(
      record.clientVerifyingShareB64u,
    ),
    ed25519WorkerMaterialHandle: parseEd25519WorkerMaterialHandle(
      record.ed25519WorkerMaterialHandle,
    ),
    ed25519WorkerMaterialBindingDigest: parseEd25519WorkerMaterialBindingDigest(
      record.ed25519WorkerMaterialBindingDigest,
    ),
    sealedWorkerMaterialRef: parseEd25519SealedWorkerMaterialRef(record.sealedWorkerMaterialRef),
    sealedWorkerMaterialB64u: record.sealedWorkerMaterialB64u,
    materialFormatVersion: record.materialFormatVersion,
    materialKeyId: parseEd25519WorkerMaterialKeyId(record.materialKeyId),
    materialCreatedAtMs: record.materialCreatedAtMs,
  };
}

function retainedEd25519WorkerMaterialFactsFromRestoreRecord(
  record: ThresholdEd25519RestoreAvailableSessionRecord,
): RetainedEd25519WorkerMaterialFacts {
  const sealedWorkerMaterialB64u = nonEmptyString(record.sealedWorkerMaterialB64u);
  if (!sealedWorkerMaterialB64u) return { kind: 'none' };
  return {
    kind: 'sealed_worker_material',
    clientVerifyingShareB64u: parseEd25519ClientVerifyingShareB64u(
      record.clientVerifyingShareB64u,
    ),
    ed25519WorkerMaterialBindingDigest: parseEd25519WorkerMaterialBindingDigest(
      record.ed25519WorkerMaterialBindingDigest,
    ),
    sealedWorkerMaterialRef: parseEd25519SealedWorkerMaterialRef(record.sealedWorkerMaterialRef),
    sealedWorkerMaterialB64u,
    materialFormatVersion: record.materialFormatVersion,
    materialKeyId: parseEd25519WorkerMaterialKeyId(record.materialKeyId),
    materialCreatedAtMs: record.materialCreatedAtMs,
  };
}

function hasAnyDirectEd25519WorkerMaterialFacts(args: {
  clientVerifyingShareB64u: string;
  ed25519WorkerMaterialHandle: string;
  ed25519WorkerMaterialBindingDigest: string;
  sealedWorkerMaterialRef: string;
  sealedWorkerMaterialB64u: string;
  materialFormatVersion: string;
  materialKeyId: string;
  materialCreatedAtMs: number;
}): boolean {
  return Boolean(
    args.clientVerifyingShareB64u ||
      args.ed25519WorkerMaterialHandle ||
      args.ed25519WorkerMaterialBindingDigest ||
      args.sealedWorkerMaterialRef ||
      args.sealedWorkerMaterialB64u ||
      args.materialFormatVersion ||
      args.materialKeyId ||
      args.materialCreatedAtMs > 0,
  );
}

function hasCompleteDirectRuntimeEd25519WorkerMaterialFacts(args: {
  clientVerifyingShareB64u: string;
  ed25519WorkerMaterialHandle: string;
  ed25519WorkerMaterialBindingDigest: string;
  materialKeyId: string;
  materialCreatedAtMs: number;
}): boolean {
  return Boolean(
    args.clientVerifyingShareB64u &&
      args.ed25519WorkerMaterialHandle &&
      args.ed25519WorkerMaterialBindingDigest &&
      args.materialKeyId &&
      args.materialCreatedAtMs > 0,
  );
}

function hasCompleteDirectSealedEd25519WorkerMaterialFacts(args: {
  clientVerifyingShareB64u: string;
  ed25519WorkerMaterialBindingDigest: string;
  sealedWorkerMaterialRef: string;
  sealedWorkerMaterialB64u: string;
  materialFormatVersion: string;
  materialKeyId: string;
  materialCreatedAtMs: number;
}): boolean {
  return Boolean(
    args.clientVerifyingShareB64u &&
      args.ed25519WorkerMaterialBindingDigest &&
      args.sealedWorkerMaterialRef &&
      args.sealedWorkerMaterialB64u &&
      args.materialFormatVersion &&
      args.materialKeyId &&
      args.materialCreatedAtMs > 0,
  );
}

function shouldResolveRetainedEd25519WorkerMaterialFacts(args: {
  signingRootId: string;
  signingRootVersion: string;
  clientVerifyingShareB64u: string;
  ed25519WorkerMaterialHandle: string;
  ed25519WorkerMaterialBindingDigest: string;
  sealedWorkerMaterialRef: string;
  sealedWorkerMaterialB64u: string;
  materialFormatVersion: string;
  materialKeyId: string;
  materialCreatedAtMs: number;
}): boolean {
  if (!args.signingRootId || !args.signingRootVersion) return false;
  const hasAnyMaterial = hasAnyDirectEd25519WorkerMaterialFacts(args);
  if (!hasAnyMaterial) return true;
  return !(
    hasCompleteDirectRuntimeEd25519WorkerMaterialFacts(args) ||
    hasCompleteDirectSealedEd25519WorkerMaterialFacts(args)
  );
}

function assertDirectEd25519WorkerMaterialFactsMatchRetained(args: {
  direct: {
    clientVerifyingShareB64u: string;
    ed25519WorkerMaterialHandle: string;
    ed25519WorkerMaterialBindingDigest: string;
    sealedWorkerMaterialRef: string;
    sealedWorkerMaterialB64u: string;
    materialFormatVersion: string;
    materialKeyId: string;
    materialCreatedAtMs: number;
  };
  retained: Exclude<RetainedEd25519WorkerMaterialFacts, { kind: 'none' }>;
}): void {
  const retained = args.retained;
  const direct = args.direct;
  const conflicts = [
    direct.clientVerifyingShareB64u &&
    direct.clientVerifyingShareB64u !== String(retained.clientVerifyingShareB64u),
    direct.ed25519WorkerMaterialBindingDigest &&
    direct.ed25519WorkerMaterialBindingDigest !==
      String(retained.ed25519WorkerMaterialBindingDigest),
    direct.materialKeyId && direct.materialKeyId !== String(retained.materialKeyId),
    direct.materialCreatedAtMs > 0 &&
    direct.materialCreatedAtMs !== Number(retained.materialCreatedAtMs),
    retained.kind === 'sealed_worker_material' &&
    direct.ed25519WorkerMaterialHandle &&
    retained.ed25519WorkerMaterialHandle &&
    direct.ed25519WorkerMaterialHandle !== String(retained.ed25519WorkerMaterialHandle),
    retained.kind === 'sealed_worker_material' &&
    direct.sealedWorkerMaterialRef &&
    direct.sealedWorkerMaterialRef !== String(retained.sealedWorkerMaterialRef),
    retained.kind === 'sealed_worker_material' &&
    direct.sealedWorkerMaterialB64u &&
    direct.sealedWorkerMaterialB64u !== retained.sealedWorkerMaterialB64u,
    retained.kind === 'sealed_worker_material' &&
    direct.materialFormatVersion &&
    direct.materialFormatVersion !== retained.materialFormatVersion,
  ];
  if (conflicts.some(Boolean)) {
    throw new Error(
      'Warm threshold-ed25519 capability supplied partial worker material that conflicts with retained material',
    );
  }
}

function resolveEd25519WarmSessionUpsertMaterialFields(args: {
  direct: {
    clientVerifyingShareB64u: string;
    ed25519WorkerMaterialHandle: string;
    ed25519WorkerMaterialBindingDigest: string;
    sealedWorkerMaterialRef: string;
    sealedWorkerMaterialB64u: string;
    materialFormatVersion: string;
    materialKeyId: string;
    materialCreatedAtMs: number;
  };
  retained: RetainedEd25519WorkerMaterialFacts;
}): ThresholdEd25519UpsertMaterialFields {
  const direct = args.direct;
  const hasDirectMaterial = Boolean(
    direct.clientVerifyingShareB64u ||
      direct.ed25519WorkerMaterialHandle ||
      direct.ed25519WorkerMaterialBindingDigest ||
      direct.sealedWorkerMaterialRef ||
      direct.sealedWorkerMaterialB64u ||
      direct.materialFormatVersion ||
      direct.materialKeyId ||
      direct.materialCreatedAtMs > 0,
  );
  if (hasDirectMaterial) {
    if (
      !direct.clientVerifyingShareB64u ||
      !direct.ed25519WorkerMaterialBindingDigest ||
      !direct.sealedWorkerMaterialRef ||
      !direct.sealedWorkerMaterialB64u ||
      !direct.materialFormatVersion ||
      !direct.materialKeyId ||
      direct.materialCreatedAtMs <= 0
    ) {
      throw new Error('Warm threshold-ed25519 capability supplied incomplete worker material');
    }
    if (direct.ed25519WorkerMaterialHandle) {
      return {
        clientVerifyingShareB64u: direct.clientVerifyingShareB64u,
        ed25519WorkerMaterialHandle: direct.ed25519WorkerMaterialHandle,
        ed25519WorkerMaterialBindingDigest: direct.ed25519WorkerMaterialBindingDigest,
        sealedWorkerMaterialRef: direct.sealedWorkerMaterialRef,
        sealedWorkerMaterialB64u: direct.sealedWorkerMaterialB64u,
        materialFormatVersion: direct.materialFormatVersion,
        materialKeyId: direct.materialKeyId,
        materialCreatedAtMs: direct.materialCreatedAtMs,
      };
    }
    return {
      clientVerifyingShareB64u: direct.clientVerifyingShareB64u,
      ed25519WorkerMaterialBindingDigest: direct.ed25519WorkerMaterialBindingDigest,
      sealedWorkerMaterialRef: direct.sealedWorkerMaterialRef,
      sealedWorkerMaterialB64u: direct.sealedWorkerMaterialB64u,
      materialFormatVersion: direct.materialFormatVersion,
      materialKeyId: direct.materialKeyId,
      materialCreatedAtMs: direct.materialCreatedAtMs,
    };
  }
  if (args.retained.kind === 'sealed_worker_material') {
    const retained = args.retained;
    if (retained.ed25519WorkerMaterialHandle) {
      return {
        clientVerifyingShareB64u: retained.clientVerifyingShareB64u,
        ed25519WorkerMaterialHandle: retained.ed25519WorkerMaterialHandle,
        ed25519WorkerMaterialBindingDigest: retained.ed25519WorkerMaterialBindingDigest,
        sealedWorkerMaterialRef: retained.sealedWorkerMaterialRef,
        sealedWorkerMaterialB64u: retained.sealedWorkerMaterialB64u,
        materialFormatVersion: retained.materialFormatVersion,
        materialKeyId: retained.materialKeyId,
        materialCreatedAtMs: retained.materialCreatedAtMs,
      };
    }
    return {
      clientVerifyingShareB64u: retained.clientVerifyingShareB64u,
      ed25519WorkerMaterialBindingDigest: retained.ed25519WorkerMaterialBindingDigest,
      sealedWorkerMaterialRef: retained.sealedWorkerMaterialRef,
      sealedWorkerMaterialB64u: retained.sealedWorkerMaterialB64u,
      materialFormatVersion: retained.materialFormatVersion,
      materialKeyId: retained.materialKeyId,
      materialCreatedAtMs: retained.materialCreatedAtMs,
    };
  }
  return {};
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
  const nearEd25519SigningKeyId = nonEmptyString(args.nearEd25519SigningKeyId);
  const passkeyCredentialIdB64u =
    args.kind === 'jwt_passkey' ? nonEmptyString(args.passkeyCredentialIdB64u) : '';
  if (!walletId) {
    throw new Error('Missing walletId for warm threshold-ed25519 capability');
  }
  if (!nearEd25519SigningKeyId) {
    throw new Error('Missing nearEd25519SigningKeyId for warm threshold-ed25519 capability');
  }
  if (args.kind === 'jwt_passkey' && !passkeyCredentialIdB64u) {
    throw new Error('Missing passkeyCredentialIdB64u for warm threshold-ed25519 capability');
  }
  const retainedMaterial = shouldResolveRetainedEd25519WorkerMaterialFacts({
    signingRootId,
    signingRootVersion,
    clientVerifyingShareB64u,
    ed25519WorkerMaterialHandle,
    ed25519WorkerMaterialBindingDigest,
    sealedWorkerMaterialRef,
    sealedWorkerMaterialB64u,
    materialFormatVersion,
    materialKeyId,
    materialCreatedAtMs,
  })
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
  if (retainedMaterial.kind !== 'none') {
    assertDirectEd25519WorkerMaterialFactsMatchRetained({
      direct: {
        clientVerifyingShareB64u,
        ed25519WorkerMaterialHandle,
        ed25519WorkerMaterialBindingDigest,
        sealedWorkerMaterialRef,
        sealedWorkerMaterialB64u,
        materialFormatVersion,
        materialKeyId,
        materialCreatedAtMs,
      },
      retained: retainedMaterial,
    });
  }
  const materialFields = resolveEd25519WarmSessionUpsertMaterialFields({
    direct: {
      clientVerifyingShareB64u,
      ed25519WorkerMaterialHandle,
      ed25519WorkerMaterialBindingDigest,
      sealedWorkerMaterialRef,
      sealedWorkerMaterialB64u,
      materialFormatVersion,
      materialKeyId,
      materialCreatedAtMs,
    },
    retained: retainedMaterial,
  });

  const parsedRecord = buildThresholdEd25519SessionFact({
    walletId,
    nearAccountId: args.nearAccountId,
    nearEd25519SigningKeyId,
    rpId: String(args.rpId || '').trim(),
    ...(args.kind === 'jwt_passkey'
      ? { passkeyCredentialIdB64u }
      : {}),
    relayerUrl: String(args.relayerUrl || '').trim(),
    relayerKeyId: String(args.relayerKeyId || '').trim(),
    participantIds,
    ...(signingRootId ? { signingRootId } : {}),
    ...(signingRootVersion ? { signingRootVersion } : {}),
    ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
    ...materialFields,
    signerSlot,
    routerAbNormalSigning: args.routerAbNormalSigning,
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
  if (!parsedRecord) {
    throw new Error('Failed to persist warm threshold-ed25519 capability');
  }
  const currentRecord = buildOperationUsableThresholdEd25519SessionRecord(parsedRecord);
  if (!currentRecord) {
    const reasons = describeOperationUsableThresholdEd25519SessionRecordRejection(parsedRecord);
    if (isMaterialPendingOnlyRejection(reasons)) {
      const storedPending = upsertThresholdEd25519SessionFact({
        walletId,
        nearAccountId: args.nearAccountId,
        nearEd25519SigningKeyId,
        rpId: String(args.rpId || '').trim(),
        ...(args.kind === 'jwt_passkey' ? { passkeyCredentialIdB64u } : {}),
        relayerUrl: String(args.relayerUrl || '').trim(),
        relayerKeyId: String(args.relayerKeyId || '').trim(),
        participantIds,
        ...(signingRootId ? { signingRootId } : {}),
        ...(signingRootVersion ? { signingRootVersion } : {}),
        ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
        signerSlot,
        routerAbNormalSigning: args.routerAbNormalSigning,
        thresholdSessionKind: 'jwt',
        thresholdSessionId: sessionId,
        signingGrantId,
        ...(jwt ? { walletSessionJwt: jwt } : {}),
        expiresAtMs,
        remainingUses,
        ...(args.kind === 'jwt_email_otp' ? { emailOtpAuthContext: args.emailOtpAuthContext } : {}),
        updatedAtMs: parsedRecord.updatedAtMs,
        source,
      });
      if (!storedPending) {
        throw new Error('Failed to persist pending warm threshold-ed25519 capability');
      }
      return storedPending;
    }
    throw new Error(
      `Warm threshold-ed25519 capability produced an unusable current session: ${
        reasons.join(', ') || 'unknown'
      }`,
    );
  }
  const transition =
    source === 'registration' ? 'registration' : source === 'email_otp' ? 'step_up' : 'wallet_unlock';
  const record = requireCommittedThresholdEd25519Session(
    commitCurrentThresholdEd25519Session({
      record: currentRecord,
      transition,
    }),
  );
  publishResolvedIdentity({
    walletId: record.walletId,
    authMethod,
    curve: 'ed25519',
    chain: 'near',
    signingGrantId,
    thresholdSessionId: sessionId,
    updatedAtMs: record.updatedAtMs,
  });
  return record;
}
