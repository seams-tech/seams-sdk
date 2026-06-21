import {
  buildThresholdEd25519Participants2pV1,
  THRESHOLD_ED25519_2P_PARTICIPANT_IDS,
  normalizeThresholdEd25519ParticipantIds,
} from '@shared/threshold/participants';
import { isObject } from '@shared/utils/validation';
import { signingRootScopeFromRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import type {
  AccountId,
  WebAuthnAuthenticationCredential,
  WebAuthnRegistrationCredential,
} from '@/core/types';
import { toAccountId } from '@/core/types/accountIds';
import { IndexedDBManager } from '@/core/indexedDB';
import {
  getNearThresholdKeyMaterial,
  storeNearThresholdKeyMaterial,
} from '@/core/accountData/near/keyMaterial';
import {
  persistWarmSessionEd25519Capability,
  type PersistWarmSessionEd25519JwtEmailOtpCapabilityArgs,
  type PersistWarmSessionEd25519JwtPasskeyCapabilityArgs,
} from '@/core/signingEngine/session/warmCapabilities/persistence';
import { createWarmSessionCapabilityReader } from '@/core/signingEngine/session/warmCapabilities/capabilityReader';
import type { ThresholdEcdsaEmailOtpAuthContext } from '@/core/signingEngine/session/identity/laneIdentity';
import { getPrfFirstB64uFromCredential } from '@/core/signingEngine/threshold/crypto/webauthn';
import {
  getStoredThresholdEd25519SessionRecordByThresholdSessionId,
  persistStoredThresholdEd25519SessionMaterialHandle,
  type ThresholdEd25519SessionRecord,
  upsertStoredThresholdEd25519SessionRecord,
} from '@/core/signingEngine/session/persistence/records';
import {
  classifyRouterAbEd25519PersistedSigningRecord,
  markRouterAbEd25519WorkerMaterialRuntimeValidated,
} from '@/core/signingEngine/session/routerAbSigningWalletSession';
import {
  listEcdsaSealedSessionsForWallet,
  listExactSealedSessionsForWallet,
  type CurrentEd25519SealedSessionRecord,
  type CurrentSealedSessionRecord,
} from '@/core/signingEngine/session/persistence/sealedSessionStore';
import {
  THRESHOLD_SESSION_POLICY_VERSION,
  generateThresholdSessionId,
  generateSigningGrantId,
  normalizeThresholdRuntimePolicyScope,
  type ThresholdRuntimePolicyScope,
  type ThresholdSessionKind,
} from '@/core/signingEngine/threshold/sessionPolicy';
import {
  ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND,
  parseRouterAbEd25519NormalSigningState,
  type RouterAbEd25519NormalSigningState,
} from '@shared/utils/signingSessionSeal';
import type {
  SigningSessionSurface,
  ThresholdEd25519HssCeremonySurface,
  ThresholdEd25519HssClientSurface,
} from '@/SeamsWeb/signingSurface/types';
import type { SeamsConfigsReadonly } from '@/core/types/seams';
import type { ThresholdEd25519KeyMaterial } from '@/core/accountData/near/nearAccountData.types';
import {
  THRESHOLD_ED25519_HSS_DERIVATION_VERSION,
  THRESHOLD_ED25519_HSS_SIGNING_KEY_PURPOSE,
} from '@/core/signingEngine/threshold/ed25519/hssClientBase';
import type { WalletRegistrationFinalizeResponse } from '@/core/rpcClients/relayer/walletRegistration';
import type {
  ThresholdEd25519HssCanonicalContext,
  ThresholdEd25519HssClientRequestEnvelope,
  ThresholdEd25519HssPreparedSessionEnvelope,
  ThresholdEd25519HssServerInputDeliveryEnvelope,
  ThresholdEd25519HssStagedEvaluatorArtifactEnvelope,
} from '@/core/signingEngine/threshold/crypto/hssClientSignerWasm';
import { resolveThresholdWarmSessionDefaults } from '@/SeamsWeb/operations/session/thresholdWarmSessionDefaults';
import type { ThresholdEd25519WorkerMaterialBindingInputWithoutVerifier } from '@/core/types/signer-worker';
import { prepareThresholdEd25519PasskeyMaterialSealAuthorizationFromCredential } from '@/core/signingEngine/session/passkey/prfClaim';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import {
  requireOrRestoreRouterAbEd25519WalletSessionState,
  type RouterAbEd25519WorkerMaterialRestoreAuthorization,
} from '@/core/signingEngine/flows/signNear/shared/ed25519SigningMaterialReadiness';
import { resolveRouterAbEd25519WorkerMaterialRestoreAuthorizationForPasskeyCredential } from '@/core/signingEngine/flows/signNear/shared/ed25519MaterialRestoreAuthorization';

export const THRESHOLD_ED25519_SINGLE_KEY_HSS_KEY_VERSION_V1 = 'threshold-ed25519-hss-v1';

function signingRootIdFromRuntimePolicyScope(
  scope: ThresholdRuntimePolicyScope,
  errorContext: string,
): string {
  const signingRootId = String(
    signingRootScopeFromRuntimePolicyScope(scope).signingRootId || '',
  ).trim();
  if (!signingRootId) {
    throw new Error(`${errorContext} is missing signing root scope`);
  }
  return signingRootId;
}

export type RegisteredThresholdEd25519SessionAuth =
  | {
      kind: 'passkey';
      emailOtpAuthContext?: never;
    }
  | {
      kind: 'email_otp';
      emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
    };

export type ThresholdWarmSessionPolicyDraft = {
  sessionId: string;
  signingGrantId?: string;
  ttlMs: number;
  remainingUses: number;
  participantIds?: number[];
  routerAbNormalSigning: RouterAbEd25519NormalSigningState;
};

export type ThresholdWarmSessionPolicyDraftInput =
  | {
      kind?: 'generated_signing_grant';
      sessionId?: string;
      participantIds?: number[];
      signingGrantId?: never;
      ttlMs?: never;
      remainingUses?: never;
    }
  | {
      kind: 'shared_signing_grant';
      signingGrantId: string;
      ttlMs: number;
      remainingUses: number;
      sessionId?: string;
      participantIds?: number[];
    };

export type ThresholdWarmSessionRequestEnvelope = {
  session_policy: {
    version: typeof THRESHOLD_SESSION_POLICY_VERSION;
    nearAccountId?: string;
    rpId: string;
    relayerKeyId?: string;
    thresholdSessionId: string;
    signingGrantId?: string;
    participantIds?: number[];
    runtimePolicyScope?: ThresholdRuntimePolicyScope;
    routerAbNormalSigning: RouterAbEd25519NormalSigningState;
    ttlMs: number;
    remainingUses: number;
  };
  session_kind: 'jwt';
};

export type WalletRegistrationThresholdEd25519Response = NonNullable<
  WalletRegistrationFinalizeResponse['ed25519']
>;

export type CompletedThresholdEd25519Registration = {
  registered: WalletRegistrationThresholdEd25519Response;
  operationalPublicKey: string;
};

type PersistRegisteredThresholdEd25519SessionBaseArgs = {
  signingEngine: Pick<SigningSessionSurface, 'hydrateSigningSession'>;
  nearAccountId: AccountId;
  signerSlot: number;
  rpId: string;
  relayerUrl: string;
  registrationSessionPolicy: ThresholdWarmSessionRequestEnvelope['session_policy'];
  completedRegistration: CompletedThresholdEd25519Registration;
};

export type PersistRegisteredThresholdEd25519SessionArgs =
  | (PersistRegisteredThresholdEd25519SessionBaseArgs & {
      auth: Extract<RegisteredThresholdEd25519SessionAuth, { kind: 'passkey' }>;
      prfFirstB64u: string | null;
      registrationHssClientMaterial?: never;
    })
  | (PersistRegisteredThresholdEd25519SessionBaseArgs & {
      auth: Extract<RegisteredThresholdEd25519SessionAuth, { kind: 'email_otp' }>;
      prfFirstB64u: string;
      registrationHssClientMaterial: ThresholdEd25519RegistrationHssClientMaterial;
    });

type ThresholdWarmSessionRelayResult = {
  sessionKind?: string;
  thresholdSessionId?: string;
  signingGrantId?: string;
  expiresAtMs?: number;
  participantIds?: number[];
  remainingUses?: number;
  jwt?: string;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  routerAbNormalSigning?: RouterAbEd25519NormalSigningState;
};

export type ThresholdWarmSessionContext = {
  configs: SeamsConfigsReadonly;
  signingEngine: ThresholdEd25519HssClientSurface &
    ThresholdEd25519HssCeremonySurface &
    Pick<SigningSessionSurface, 'hydrateSigningSession'>;
};

export type ThresholdEd25519WorkerMaterialRestoreContext = {
  signingEngine: WorkerOperationContext;
};

export type ThresholdEd25519RegistrationHssContext = ThresholdEd25519HssCanonicalContext;

export type ThresholdEd25519RegistrationHssClientMaterial = {
  hssContext: ThresholdEd25519RegistrationHssContext;
  prfFirstB64u: string;
  clientInputs: {
    contextBindingB64u: string;
    yClientB64u: string;
    tauClientB64u: string;
  };
};

type RestoreThresholdEd25519WorkerMaterialPendingReason =
  | 'pending_material'
  | 'no_durable_restore_records'
  | 'durable_restore_missing_worker_material'
  | 'durable_restore_identity_mismatch';

export type RestoreThresholdEd25519WorkerMaterialFromCredentialResult =
  | {
      kind: 'already_loaded';
      thresholdSessionId: string;
      pendingReason?: never;
      pendingDetails?: never;
    }
  | {
      kind: 'restored';
      thresholdSessionId: string;
      pendingReason?: never;
      pendingDetails?: never;
    }
  | {
      kind: 'material_pending';
      thresholdSessionId: string;
      pendingReason: RestoreThresholdEd25519WorkerMaterialPendingReason;
      pendingDetails: string;
    };

function requireThresholdEd25519SessionRecordForWorkerMaterialRestore(args: {
  thresholdSessionId: string;
  nearAccountId: string;
  signerSlot: number;
}): ThresholdEd25519SessionRecord {
  const record = getStoredThresholdEd25519SessionRecordByThresholdSessionId(
    args.thresholdSessionId,
  );
  if (!record) {
    throw new Error('[threshold-ed25519] worker material restore requires a stored session record');
  }
  if (String(record.nearAccountId || '').trim() !== args.nearAccountId) {
    throw new Error('[threshold-ed25519] worker material restore account mismatch');
  }
  if (Math.floor(Number(record.signerSlot) || 0) !== args.signerSlot) {
    throw new Error('[threshold-ed25519] worker material restore signer slot mismatch');
  }
  return record;
}

type RouterAbEd25519RestoreAvailableState = Extract<
  ReturnType<typeof classifyRouterAbEd25519PersistedSigningRecord>,
  { kind: 'restore_available' }
>;

type CurrentEd25519RestoreSealedSessionRecord = CurrentSealedSessionRecord & {
  ed25519Restore: CurrentEd25519SealedSessionRecord['ed25519Restore'];
};

function normalizedRestoreString(value: unknown): string {
  return String(value || '').trim();
}

function normalizedRestorePositiveInteger(value: unknown): number {
  const parsed = Math.floor(Number(value));
  return Number.isFinite(parsed) && parsed > 0 ? parsed : 0;
}

function restoreParticipantIdsEqual(left: readonly number[], right: readonly number[]): boolean {
  const normalizedLeft = normalizeThresholdEd25519ParticipantIds(left);
  const normalizedRight = normalizeThresholdEd25519ParticipantIds(right);
  return Boolean(
    normalizedLeft &&
    normalizedRight &&
    normalizedLeft.length === normalizedRight.length &&
    normalizedLeft.every((participantId, index) => participantId === normalizedRight[index]),
  );
}

function ed25519RecordSigningRoot(record: ThresholdEd25519SessionRecord): {
  signingRootId: string;
  signingRootVersion: string;
} {
  const runtimePolicyScope = record.runtimePolicyScope
    ? signingRootScopeFromRuntimePolicyScope(record.runtimePolicyScope)
    : null;
  return {
    signingRootId:
      normalizedRestoreString(record.signingRootId) ||
      normalizedRestoreString(runtimePolicyScope?.signingRootId),
    signingRootVersion:
      normalizedRestoreString(record.signingRootVersion) ||
      normalizedRestoreString(runtimePolicyScope?.signingRootVersion),
  };
}

function sealedEd25519RestoreHasWorkerMaterial(
  record: CurrentEd25519RestoreSealedSessionRecord,
): boolean {
  return missingEd25519RestoreWorkerMaterialFields(record).length === 0;
}

function missingEd25519RestoreWorkerMaterialFields(
  record: CurrentEd25519RestoreSealedSessionRecord,
): string[] {
  const restore = record.ed25519Restore;
  const missing: string[] = [];
  if (!normalizedRestoreString(restore.clientVerifyingShareB64u)) {
    missing.push('clientVerifyingShareB64u');
  }
  if (!normalizedRestoreString(restore.ed25519WorkerMaterialBindingDigest)) {
    missing.push('ed25519WorkerMaterialBindingDigest');
  }
  if (!normalizedRestoreString(restore.sealedWorkerMaterialRef)) {
    missing.push('sealedWorkerMaterialRef');
  }
  if (!normalizedRestoreString(restore.materialFormatVersion)) {
    missing.push('materialFormatVersion');
  }
  if (!normalizedRestoreString(restore.materialKeyId)) {
    missing.push('materialKeyId');
  }
  if (!normalizedRestorePositiveInteger(restore.materialCreatedAtMs)) {
    missing.push('materialCreatedAtMs');
  }
  if (!normalizedRestorePositiveInteger(restore.signerSlot)) {
    missing.push('signerSlot');
  }
  if (!normalizedRestoreString(restore.keyVersion)) {
    missing.push('keyVersion');
  }
  return missing;
}

function hasEd25519RestoreMetadata(
  record: CurrentSealedSessionRecord,
): record is CurrentEd25519RestoreSealedSessionRecord {
  return Boolean(record.ed25519Restore);
}

function sealedEd25519RestoreSigningRoot(record: CurrentEd25519RestoreSealedSessionRecord): {
  signingRootId: string;
  signingRootVersion: string;
} {
  const runtimePolicyScope = normalizeThresholdRuntimePolicyScope(
    record.ed25519Restore.runtimePolicyScope,
  );
  const restoreRuntimePolicyScope = runtimePolicyScope
    ? signingRootScopeFromRuntimePolicyScope(runtimePolicyScope)
    : null;
  return {
    signingRootId:
      normalizedRestoreString(record.signingRootId) ||
      normalizedRestoreString(restoreRuntimePolicyScope?.signingRootId),
    signingRootVersion:
      normalizedRestoreString(record.signingRootVersion) ||
      normalizedRestoreString(restoreRuntimePolicyScope?.signingRootVersion),
  };
}

function sealedEd25519RestoreMatchesCurrentRecord(args: {
  current: ThresholdEd25519SessionRecord;
  sealed: CurrentEd25519RestoreSealedSessionRecord;
}): boolean {
  return ed25519RestoreIdentityMismatchReasons(args).length === 0;
}

function ed25519RestoreIdentityMismatchReasons(args: {
  current: ThresholdEd25519SessionRecord;
  sealed: CurrentEd25519RestoreSealedSessionRecord;
}): string[] {
  const current = args.current;
  const sealed = args.sealed;
  const restore = sealed.ed25519Restore;
  const signingRoot = ed25519RecordSigningRoot(current);
  const sealedSigningRoot = sealedEd25519RestoreSigningRoot(sealed);
  const reasons: string[] = [];
  if (normalizedRestoreString(sealed.walletId) !== normalizedRestoreString(current.nearAccountId)) {
    reasons.push('walletId');
  }
  if (sealedSigningRoot.signingRootId !== signingRoot.signingRootId) {
    reasons.push('signingRootId');
  }
  if (sealedSigningRoot.signingRootVersion !== signingRoot.signingRootVersion) {
    reasons.push('signingRootVersion');
  }
  if (normalizedRestoreString(restore.rpId) !== normalizedRestoreString(current.rpId)) {
    reasons.push('rpId');
  }
  if (
    normalizedRestoreString(restore.relayerKeyId) !== normalizedRestoreString(current.relayerKeyId)
  ) {
    reasons.push('relayerKeyId');
  }
  if (!restoreParticipantIdsEqual(restore.participantIds, current.participantIds)) {
    reasons.push('participantIds');
  }
  if (
    normalizedRestorePositiveInteger(restore.signerSlot) !==
    normalizedRestorePositiveInteger(current.signerSlot)
  ) {
    reasons.push('signerSlot');
  }
  return reasons;
}

function mostRecentEd25519SealedSessionRecord(
  records: CurrentEd25519RestoreSealedSessionRecord[],
): CurrentEd25519RestoreSealedSessionRecord | null {
  return (
    [...records].sort(
      (left, right) =>
        normalizedRestorePositiveInteger(right.updatedAtMs) -
        normalizedRestorePositiveInteger(left.updatedAtMs),
    )[0] || null
  );
}

function uniqueSealedSessionRecordsByStoreKey(
  records: readonly CurrentSealedSessionRecord[],
): CurrentSealedSessionRecord[] {
  const seen = new Set<string>();
  const unique: CurrentSealedSessionRecord[] = [];
  for (const record of records) {
    const storeKey = normalizedRestoreString(record.storeKey);
    if (!storeKey || seen.has(storeKey)) continue;
    seen.add(storeKey);
    unique.push(record);
  }
  return unique;
}

async function listPasskeyEd25519RestoreSealedSessionsForWallet(
  walletId: string,
): Promise<CurrentEd25519RestoreSealedSessionRecord[]> {
  const [ed25519Records, ecdsaRecords] = await Promise.all([
    listExactSealedSessionsForWallet({
      walletId,
      filter: {
        authMethod: 'passkey',
        curve: 'ed25519',
      },
    }),
    listEcdsaSealedSessionsForWallet({
      walletId,
      filter: {
        authMethod: 'passkey',
        curve: 'ecdsa',
      },
    }),
  ]);
  return uniqueSealedSessionRecordsByStoreKey([...ed25519Records, ...ecdsaRecords]).filter(
    hasEd25519RestoreMetadata,
  );
}

type Ed25519DurableRestoreLookupResult =
  | {
      kind: 'matched';
      record: CurrentEd25519RestoreSealedSessionRecord;
      pendingReason?: never;
      pendingDetails?: never;
    }
  | {
      kind: 'not_found';
      record?: never;
      pendingReason: RestoreThresholdEd25519WorkerMaterialPendingReason;
      pendingDetails: string;
    };

function summarizeEd25519DurableRestoreLookupFailure(args: {
  current: ThresholdEd25519SessionRecord;
  records: readonly CurrentEd25519RestoreSealedSessionRecord[];
}): Ed25519DurableRestoreLookupResult {
  if (args.records.length === 0) {
    return {
      kind: 'not_found',
      pendingReason: 'no_durable_restore_records',
      pendingDetails:
        'no passkey sealed session record contains Ed25519 worker-material restore metadata; no-HSS unlock cannot restore NEAR signing material for this account until registration or repair writes a sealed worker-material artifact',
    };
  }
  const materialRecords = args.records.filter(sealedEd25519RestoreHasWorkerMaterial);
  if (materialRecords.length === 0) {
    const missingFields = [
      ...new Set(args.records.flatMap(missingEd25519RestoreWorkerMaterialFields)),
    ].sort();
    return {
      kind: 'not_found',
      pendingReason: 'durable_restore_missing_worker_material',
      pendingDetails: `candidate records=${args.records.length}; missing fields=${missingFields.join(',') || 'unknown'}`,
    };
  }
  const matchingRecords = materialRecords.filter((sealedRecord) =>
    sealedEd25519RestoreMatchesCurrentRecord({ current: args.current, sealed: sealedRecord }),
  );
  const selected = mostRecentEd25519SealedSessionRecord(matchingRecords);
  if (selected) {
    return {
      kind: 'matched',
      record: selected,
    };
  }
  const mismatchReasons = [
    ...new Set(
      materialRecords.flatMap((sealedRecord) =>
        ed25519RestoreIdentityMismatchReasons({ current: args.current, sealed: sealedRecord }),
      ),
    ),
  ].sort();
  return {
    kind: 'not_found',
    pendingReason: 'durable_restore_identity_mismatch',
    pendingDetails: `candidate records=${materialRecords.length}; mismatch fields=${mismatchReasons.join(',') || 'unknown'}`,
  };
}

function ed25519DurableRestoreCandidateSummary(args: {
  current: ThresholdEd25519SessionRecord;
  sealed: CurrentEd25519RestoreSealedSessionRecord;
}): Record<string, unknown> {
  const restore = args.sealed.ed25519Restore;
  return {
    curve: args.sealed.curve,
    authMethod: args.sealed.authMethod,
    storeKey: normalizedRestoreString(args.sealed.storeKey),
    signingGrantId: normalizedRestoreString(args.sealed.signingGrantId),
    thresholdSessionIds: args.sealed.thresholdSessionIds,
    updatedAtMs: normalizedRestorePositiveInteger(args.sealed.updatedAtMs),
    expiresAtMs: normalizedRestorePositiveInteger(args.sealed.expiresAtMs),
    remainingUses: normalizedRestorePositiveInteger(args.sealed.remainingUses),
    hasEd25519Restore: true,
    hasWalletSessionJwt: Boolean(normalizedRestoreString(restore.walletSessionJwt)),
    hasClientVerifier: Boolean(normalizedRestoreString(restore.clientVerifyingShareB64u)),
    hasMaterialBindingDigest: Boolean(
      normalizedRestoreString(restore.ed25519WorkerMaterialBindingDigest),
    ),
    hasSealedWorkerMaterialRef: Boolean(normalizedRestoreString(restore.sealedWorkerMaterialRef)),
    hasMaterialFormatVersion: Boolean(normalizedRestoreString(restore.materialFormatVersion)),
    hasMaterialKeyId: Boolean(normalizedRestoreString(restore.materialKeyId)),
    hasMaterialCreatedAtMs: Boolean(normalizedRestorePositiveInteger(restore.materialCreatedAtMs)),
    hasKeyVersion: Boolean(normalizedRestoreString(restore.keyVersion)),
    missingFields: missingEd25519RestoreWorkerMaterialFields(args.sealed),
    identityMismatchFields: ed25519RestoreIdentityMismatchReasons(args),
  };
}

function logEd25519DurableRestoreLookupFailure(args: {
  current: ThresholdEd25519SessionRecord;
  records: readonly CurrentEd25519RestoreSealedSessionRecord[];
  lookup: Extract<Ed25519DurableRestoreLookupResult, { kind: 'not_found' }>;
}): void {
  console.warn('[threshold-ed25519] durable worker-material restore lookup failed', {
    thresholdSessionId: args.current.thresholdSessionId,
    nearAccountId: args.current.nearAccountId,
    signerSlot: args.current.signerSlot,
    signingGrantId: normalizedRestoreString(args.current.signingGrantId),
    pendingReason: args.lookup.pendingReason,
    pendingDetails: args.lookup.pendingDetails,
    candidateCount: args.records.length,
    candidates: args.records.map((sealed) =>
      ed25519DurableRestoreCandidateSummary({ current: args.current, sealed }),
    ),
  });
}

async function hydrateCurrentEd25519SessionFromDurableSealedWorkerMaterial(
  record: ThresholdEd25519SessionRecord,
): Promise<
  | {
      kind: 'hydrated';
      record: ThresholdEd25519SessionRecord;
      pendingReason?: never;
      pendingDetails?: never;
    }
  | {
      kind: 'not_found';
      record?: never;
      pendingReason: RestoreThresholdEd25519WorkerMaterialPendingReason;
      pendingDetails: string;
    }
> {
  const records = await listPasskeyEd25519RestoreSealedSessionsForWallet(record.nearAccountId);
  const lookup = summarizeEd25519DurableRestoreLookupFailure({
    current: record,
    records,
  });
  if (lookup.kind === 'not_found') {
    logEd25519DurableRestoreLookupFailure({
      current: record,
      records,
      lookup,
    });
    return lookup;
  }
  const selected = lookup.record;
  const restore = selected.ed25519Restore;
  const signingRoot = ed25519RecordSigningRoot(record);
  const hydrated = upsertStoredThresholdEd25519SessionRecord({
    nearAccountId: record.nearAccountId,
    rpId: record.rpId,
    relayerUrl: record.relayerUrl,
    relayerKeyId: record.relayerKeyId,
    participantIds: record.participantIds,
    signingRootId: signingRoot.signingRootId,
    signingRootVersion: signingRoot.signingRootVersion,
    ...(record.runtimePolicyScope ? { runtimePolicyScope: record.runtimePolicyScope } : {}),
    clientVerifyingShareB64u: normalizedRestoreString(restore.clientVerifyingShareB64u),
    ed25519WorkerMaterialBindingDigest: normalizedRestoreString(
      restore.ed25519WorkerMaterialBindingDigest,
    ),
    sealedWorkerMaterialRef: normalizedRestoreString(restore.sealedWorkerMaterialRef),
    sealedWorkerMaterialB64u: normalizedRestoreString(restore.sealedWorkerMaterialB64u),
    materialFormatVersion: normalizedRestoreString(restore.materialFormatVersion),
    materialKeyId: normalizedRestoreString(restore.materialKeyId),
    materialCreatedAtMs: normalizedRestorePositiveInteger(restore.materialCreatedAtMs),
    signerSlot: normalizedRestorePositiveInteger(restore.signerSlot),
    keyVersion: normalizedRestoreString(restore.keyVersion),
    ...(record.routerAbNormalSigning
      ? { routerAbNormalSigning: record.routerAbNormalSigning }
      : {}),
    thresholdSessionKind: 'jwt',
    thresholdSessionId: record.thresholdSessionId,
    ...(record.signingGrantId ? { signingGrantId: record.signingGrantId } : {}),
    walletSessionJwt: record.walletSessionJwt,
    expiresAtMs: record.expiresAtMs,
    remainingUses: record.remainingUses,
    updatedAtMs: Date.now(),
    source: record.source,
  });
  if (!hydrated) {
    return {
      kind: 'not_found',
      pendingReason: 'pending_material',
      pendingDetails: 'failed to hydrate current Ed25519 session record from durable metadata',
    };
  }
  return {
    kind: 'hydrated',
    record: hydrated,
  };
}

async function requireThresholdEd25519KeyMaterialForWorkerMaterialRestore(args: {
  nearAccountId: string;
  signerSlot: number;
}): Promise<ThresholdEd25519KeyMaterial> {
  const thresholdKeyMaterial = await getNearThresholdKeyMaterial(
    {
      clientDB: IndexedDBManager,
      keyMaterialStore: IndexedDBManager,
    },
    toAccountId(args.nearAccountId),
    args.signerSlot,
  ).catch(() => null);
  if (!thresholdKeyMaterial) {
    throw new Error('[threshold-ed25519] worker material restore requires threshold key material');
  }
  return thresholdKeyMaterial;
}

async function restoreAvailableThresholdEd25519WorkerMaterialFromCredential(args: {
  context: ThresholdEd25519WorkerMaterialRestoreContext;
  credential: WebAuthnAuthenticationCredential;
  nearAccountId: string;
  signerSlot: number;
  thresholdSessionId: string;
  state: RouterAbEd25519RestoreAvailableState;
}): Promise<RestoreThresholdEd25519WorkerMaterialFromCredentialResult> {
  const thresholdKeyMaterial = await requireThresholdEd25519KeyMaterialForWorkerMaterialRestore({
    nearAccountId: args.nearAccountId,
    signerSlot: args.signerSlot,
  });
  const restoreAuthorization =
    await resolveRouterAbEd25519WorkerMaterialRestoreAuthorizationForPasskeyCredential({
      ctx: args.context.signingEngine,
      record: args.state.record,
      credential: args.credential,
    });
  await requireOrRestoreRouterAbEd25519WalletSessionState({
    ctx: args.context.signingEngine,
    signingSessionCoordinator: createWarmSessionCapabilityReader(),
    thresholdSessionId: args.thresholdSessionId,
    operation: 'wallet_unlock',
    nearAccountId: args.nearAccountId,
    thresholdKeyMaterial,
    restoreAuthorization,
  });
  return {
    kind: 'restored',
    thresholdSessionId: args.thresholdSessionId,
  };
}

async function restoreDurableThresholdEd25519WorkerMaterialFromCredential(args: {
  context: ThresholdEd25519WorkerMaterialRestoreContext;
  credential: WebAuthnAuthenticationCredential;
  nearAccountId: string;
  signerSlot: number;
  thresholdSessionId: string;
  record: ThresholdEd25519SessionRecord;
}): Promise<RestoreThresholdEd25519WorkerMaterialFromCredentialResult | null> {
  const hydrated = await hydrateCurrentEd25519SessionFromDurableSealedWorkerMaterial(args.record);
  if (hydrated.kind === 'not_found') {
    return {
      kind: 'material_pending',
      thresholdSessionId: args.thresholdSessionId,
      pendingReason: hydrated.pendingReason,
      pendingDetails: hydrated.pendingDetails,
    };
  }
  const hydratedState = classifyRouterAbEd25519PersistedSigningRecord(hydrated.record);
  switch (hydratedState.kind) {
    case 'restore_available':
      return await restoreAvailableThresholdEd25519WorkerMaterialFromCredential({
        context: args.context,
        credential: args.credential,
        nearAccountId: args.nearAccountId,
        signerSlot: args.signerSlot,
        thresholdSessionId: args.thresholdSessionId,
        state: hydratedState,
      });
    case 'runtime_validated':
      return await validateOrRestoreSignableThresholdEd25519WorkerMaterialFromCredential({
        context: args.context,
        credential: args.credential,
        nearAccountId: args.nearAccountId,
        signerSlot: args.signerSlot,
        thresholdSessionId: args.thresholdSessionId,
        record: hydratedState.record,
      });
    case 'material_hint_unvalidated':
    case 'auth_ready_material_pending':
    case 'non_signing':
    case 'invalid':
      return null;
    default: {
      const exhaustive: never = hydratedState;
      return exhaustive;
    }
  }
}

async function validateOrRestoreSignableThresholdEd25519WorkerMaterialFromCredential(args: {
  context: ThresholdEd25519WorkerMaterialRestoreContext;
  credential: WebAuthnAuthenticationCredential;
  nearAccountId: string;
  signerSlot: number;
  thresholdSessionId: string;
  record: ThresholdEd25519SessionRecord;
}): Promise<RestoreThresholdEd25519WorkerMaterialFromCredentialResult> {
  const thresholdKeyMaterial = await requireThresholdEd25519KeyMaterialForWorkerMaterialRestore({
    nearAccountId: args.nearAccountId,
    signerSlot: args.signerSlot,
  });
  const restoreAuthorization =
    await resolveRouterAbEd25519WorkerMaterialRestoreAuthorizationForPasskeyCredential({
      ctx: args.context.signingEngine,
      record: args.record,
      credential: args.credential,
    });
  await requireOrRestoreRouterAbEd25519WalletSessionState({
    ctx: args.context.signingEngine,
    signingSessionCoordinator: createWarmSessionCapabilityReader(),
    thresholdSessionId: args.thresholdSessionId,
    operation: 'wallet_unlock',
    nearAccountId: args.nearAccountId,
    thresholdKeyMaterial,
    restoreAuthorization,
  });
  return {
    kind: 'already_loaded',
    thresholdSessionId: args.thresholdSessionId,
  };
}

export async function restoreThresholdEd25519WorkerMaterialFromCredential(args: {
  context: ThresholdEd25519WorkerMaterialRestoreContext;
  credential: WebAuthnAuthenticationCredential;
  nearAccountId: AccountId;
  signerSlot: number;
  thresholdSessionId: string;
}): Promise<RestoreThresholdEd25519WorkerMaterialFromCredentialResult> {
  const nearAccountId = String(args.nearAccountId || '').trim();
  const signerSlot = Number(args.signerSlot);
  const thresholdSessionId = String(args.thresholdSessionId || '').trim();
  if (!nearAccountId || !thresholdSessionId) {
    throw new Error('[threshold-ed25519] worker material restore requires account and session ids');
  }
  if (!Number.isInteger(signerSlot) || signerSlot <= 0) {
    throw new Error('[threshold-ed25519] worker material restore requires a valid signer slot');
  }

  const record = requireThresholdEd25519SessionRecordForWorkerMaterialRestore({
    thresholdSessionId,
    nearAccountId,
    signerSlot,
  });
  const signingSessionState = classifyRouterAbEd25519PersistedSigningRecord(record);
  switch (signingSessionState.kind) {
    case 'runtime_validated':
      return await validateOrRestoreSignableThresholdEd25519WorkerMaterialFromCredential({
        context: args.context,
        credential: args.credential,
        nearAccountId,
        signerSlot,
        thresholdSessionId,
        record: signingSessionState.record,
      });
    case 'material_hint_unvalidated': {
      const thresholdKeyMaterial =
        await requireThresholdEd25519KeyMaterialForWorkerMaterialRestore({
          nearAccountId,
          signerSlot,
        });
      try {
        await requireOrRestoreRouterAbEd25519WalletSessionState({
          ctx: args.context.signingEngine,
          signingSessionCoordinator: createWarmSessionCapabilityReader(),
          thresholdSessionId,
          operation: 'wallet_unlock',
          nearAccountId,
          thresholdKeyMaterial,
          restoreAuthorization: { kind: 'unseal_authorization_unavailable' },
        });
        return {
          kind: 'already_loaded',
          thresholdSessionId,
        };
      } catch (error: unknown) {
        const restored = await restoreDurableThresholdEd25519WorkerMaterialFromCredential({
          context: args.context,
          credential: args.credential,
          nearAccountId,
          signerSlot,
          thresholdSessionId,
          record: signingSessionState.record,
        });
        if (restored) return restored;
        throw error;
      }
    }
    case 'auth_ready_material_pending':
      {
        const restored = await restoreDurableThresholdEd25519WorkerMaterialFromCredential({
          context: args.context,
          credential: args.credential,
          nearAccountId,
          signerSlot,
          thresholdSessionId,
          record: signingSessionState.record,
        });
        if (restored) return restored;
      }
      return {
        kind: 'material_pending',
        thresholdSessionId,
        pendingReason: 'pending_material',
        pendingDetails: 'current Ed25519 session record has no restorable worker material facts',
      };
    case 'restore_available':
      return await restoreAvailableThresholdEd25519WorkerMaterialFromCredential({
        context: args.context,
        credential: args.credential,
        nearAccountId,
        signerSlot,
        thresholdSessionId,
        state: signingSessionState,
      });
    case 'non_signing':
    case 'invalid':
      throw new Error(
        `[threshold-ed25519] worker material restore requires Router A/B signable session state: ${signingSessionState.reason}`,
      );
    default: {
      const exhaustive: never = signingSessionState;
      return exhaustive;
    }
  }
}

function parsePositiveInt(value: unknown): number {
  const n = typeof value === 'number' ? value : Number(value);
  if (!Number.isFinite(n) || n <= 0) return 0;
  return Math.floor(n);
}

function assertNeverRouterAbNormalSigningConfig(value: never): never {
  throw new Error(`Unexpected Router A/B normal-signing config branch: ${String(value)}`);
}

export function createRouterAbNormalSigningPolicy(
  configs: SeamsConfigsReadonly,
): RouterAbEd25519NormalSigningState {
  const normalSigning = configs.signing.routerAb.normalSigning;
  switch (normalSigning.mode) {
    case 'disabled':
      throw new Error(
        '[threshold-warm-session] Router A/B normal signing must be enabled for threshold-signer warm sessions',
      );
    case 'enabled':
      return {
        kind: ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND,
        signingWorkerId: normalSigning.signingWorkerId,
      };
    default:
      return assertNeverRouterAbNormalSigningConfig(normalSigning);
  }
}

export function createThresholdWarmSessionPolicyDraft(
  context: ThresholdWarmSessionContext,
  input?: ThresholdWarmSessionPolicyDraftInput,
): ThresholdWarmSessionPolicyDraft | null {
  const defaults = resolveThresholdWarmSessionDefaults(context);
  if (!defaults) return null;
  const sessionId = String(input?.sessionId || '').trim() || generateThresholdSessionId();
  const sharedGrant = input?.kind === 'shared_signing_grant' ? input : null;
  const signingGrantId = sharedGrant
    ? String(sharedGrant.signingGrantId || '').trim()
    : generateSigningGrantId();
  if (!signingGrantId) {
    throw new Error('Threshold warm-session shared signing grant is missing signingGrantId');
  }
  const ttlMs = sharedGrant ? parsePositiveInt(sharedGrant.ttlMs) : defaults.ttlMs;
  const remainingUses = sharedGrant
    ? parsePositiveInt(sharedGrant.remainingUses)
    : defaults.remainingUses;
  if (sharedGrant && (!ttlMs || !remainingUses)) {
    throw new Error('Threshold warm-session shared signing grant has invalid policy limits');
  }
  const participantIds = normalizeThresholdEd25519ParticipantIds(input?.participantIds);
  const routerAbNormalSigning = createRouterAbNormalSigningPolicy(context.configs);
  return {
    sessionId,
    signingGrantId,
    ttlMs,
    remainingUses,
    ...(participantIds ? { participantIds } : {}),
    routerAbNormalSigning,
  };
}

export function buildThresholdWarmSessionRequestEnvelope(args: {
  rpId: string;
  requestedPolicy: ThresholdWarmSessionPolicyDraft;
  nearAccountId?: string;
  relayerKeyId?: string;
}): ThresholdWarmSessionRequestEnvelope {
  const rpId = String(args.rpId || '').trim();
  const thresholdSessionId = String(args.requestedPolicy.sessionId || '').trim();
  if (!rpId || !thresholdSessionId) {
    throw new Error('Threshold warm-session request is missing rpId or thresholdSessionId');
  }
  return {
    session_policy: {
      version: THRESHOLD_SESSION_POLICY_VERSION,
      ...(args.nearAccountId ? { nearAccountId: String(args.nearAccountId || '').trim() } : {}),
      rpId,
      ...(args.relayerKeyId ? { relayerKeyId: String(args.relayerKeyId || '').trim() } : {}),
      thresholdSessionId,
      ...(args.requestedPolicy.signingGrantId
        ? { signingGrantId: args.requestedPolicy.signingGrantId }
        : {}),
      ...(Array.isArray(args.requestedPolicy.participantIds)
        ? { participantIds: args.requestedPolicy.participantIds }
        : {}),
      routerAbNormalSigning: args.requestedPolicy.routerAbNormalSigning,
      ttlMs: args.requestedPolicy.ttlMs,
      remainingUses: args.requestedPolicy.remainingUses,
    },
    session_kind: 'jwt',
  };
}

export async function prepareThresholdEd25519RegistrationHssClientMaterial(args: {
  context: ThresholdWarmSessionContext;
  credential: WebAuthnRegistrationCredential | WebAuthnAuthenticationCredential;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  nearAccountId: AccountId;
  keyPurpose: string;
  keyVersion: string;
  participantIds: number[];
  derivationVersion: number;
  onProgress?: (message: string) => void;
}): Promise<ThresholdEd25519RegistrationHssClientMaterial> {
  const signingRootId = signingRootIdFromRuntimePolicyScope(
    args.runtimePolicyScope,
    'Threshold Ed25519 registration HSS material',
  );
  const prepared =
    await args.context.signingEngine.prepareThresholdEd25519HssClientCeremonyFromCredential({
      credential: args.credential,
      signingRootId,
      nearAccountId: String(args.nearAccountId),
      keyPurpose: args.keyPurpose,
      keyVersion: args.keyVersion,
      participantIds: args.participantIds,
      derivationVersion: args.derivationVersion,
      onProgress: args.onProgress,
    });
  if (!prepared.ok) {
    throw new Error(prepared.message || 'Failed to prepare threshold Ed25519 HSS registration');
  }
  const prfFirstB64u = String(getPrfFirstB64uFromCredential(args.credential) || '').trim();
  if (!prfFirstB64u) {
    throw new Error('Missing PRF.first output from credential for threshold Ed25519 HSS masking');
  }

  return {
    hssContext: {
      signingRootId,
      nearAccountId: args.nearAccountId,
      keyPurpose: args.keyPurpose,
      keyVersion: args.keyVersion,
      participantIds: prepared.participantIds,
      derivationVersion: args.derivationVersion,
    },
    prfFirstB64u,
    clientInputs: {
      contextBindingB64u: prepared.contextBindingB64u,
      yClientB64u: prepared.yClientB64u,
      tauClientB64u: prepared.tauClientB64u,
    },
  };
}

export async function prepareThresholdEd25519RegistrationHssClientMaterialFromPrfFirst(args: {
  context: ThresholdWarmSessionContext;
  prfFirstB64u: string;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  nearAccountId: AccountId;
  keyPurpose: string;
  keyVersion: string;
  participantIds: number[];
  derivationVersion: number;
  onProgress?: (message: string) => void;
}): Promise<ThresholdEd25519RegistrationHssClientMaterial> {
  const prfFirstB64u = String(args.prfFirstB64u || '').trim();
  if (!prfFirstB64u) {
    throw new Error('Missing PRF.first material for threshold Ed25519 HSS registration');
  }
  const signingRootId = signingRootIdFromRuntimePolicyScope(
    args.runtimePolicyScope,
    'Threshold Ed25519 registration HSS material',
  );
  const prepared =
    await args.context.signingEngine.prepareThresholdEd25519HssClientCeremonyFromPrfFirst({
      prfFirstB64u,
      signingRootId,
      nearAccountId: String(args.nearAccountId),
      keyPurpose: args.keyPurpose,
      keyVersion: args.keyVersion,
      participantIds: args.participantIds,
      derivationVersion: args.derivationVersion,
      onProgress: args.onProgress,
    });
  if (!prepared.ok) {
    throw new Error(prepared.message || 'Failed to prepare threshold Ed25519 HSS registration');
  }

  return {
    hssContext: {
      signingRootId,
      nearAccountId: args.nearAccountId,
      keyPurpose: args.keyPurpose,
      keyVersion: args.keyVersion,
      participantIds: prepared.participantIds,
      derivationVersion: args.derivationVersion,
    },
    prfFirstB64u,
    clientInputs: {
      contextBindingB64u: prepared.contextBindingB64u,
      yClientB64u: prepared.yClientB64u,
      tauClientB64u: prepared.tauClientB64u,
    },
  };
}

export async function prepareThresholdEd25519RegistrationHssClientRequest(args: {
  context: ThresholdWarmSessionContext;
  material: ThresholdEd25519RegistrationHssClientMaterial;
  preparedSession: ThresholdEd25519HssPreparedSessionEnvelope;
  clientOtOfferMessageB64u: string;
  ceremonyHandle: string;
}): Promise<{
  clientRequest: ThresholdEd25519HssClientRequestEnvelope;
  clientOutputMaskB64u: string;
}> {
  const { clientOutputMaskB64u } =
    await args.context.signingEngine.deriveThresholdEd25519HssClientOutputMask({
      clientRecoverableSecretB64u: args.material.prfFirstB64u,
      context: {
        ...args.material.hssContext,
        contextBindingB64u: args.preparedSession.contextBindingB64u,
        operation: 'registration',
        relayerKeyId: `registration:${args.ceremonyHandle}`,
      },
    });

  const clientRequest = await args.context.signingEngine.prepareThresholdEd25519HssClientRequest({
    evaluatorDriverStateB64u: args.preparedSession.evaluatorDriverStateB64u,
    clientOtOfferMessageB64u: args.clientOtOfferMessageB64u,
    clientInputs: args.material.clientInputs,
  });

  return { clientRequest, clientOutputMaskB64u };
}

export async function buildThresholdEd25519RegistrationHssClientOwnedArtifact(args: {
  context: ThresholdWarmSessionContext;
  preparedSession: ThresholdEd25519HssPreparedSessionEnvelope;
  clientRequest: ThresholdEd25519HssClientRequestEnvelope;
  serverInputDelivery: ThresholdEd25519HssServerInputDeliveryEnvelope;
  clientOutputMaskB64u: string;
}): Promise<ThresholdEd25519HssStagedEvaluatorArtifactEnvelope> {
  return await args.context.signingEngine.buildThresholdEd25519HssClientOwnedStagedEvaluatorArtifact(
    {
      preparedSession: args.preparedSession,
      clientRequest: args.clientRequest,
      serverInputDelivery: args.serverInputDelivery,
      clientOutputMaskB64u: args.clientOutputMaskB64u,
    },
  );
}

export function requireThresholdEd25519WarmSessionKeyVersion(
  raw: unknown,
  errorContext: string,
): {
  keyVersion: string;
} {
  const section = isObject(raw) ? raw : {};
  const keyVersion = String(section.keyVersion || '').trim();
  const recoveryExportCapable =
    typeof section.recoveryExportCapable === 'boolean'
      ? Boolean(section.recoveryExportCapable)
      : undefined;
  if (
    keyVersion !== THRESHOLD_ED25519_SINGLE_KEY_HSS_KEY_VERSION_V1 ||
    recoveryExportCapable !== true
  ) {
    throw new Error(`${errorContext} returned incomplete threshold-ed25519 key metadata`);
  }
  return { keyVersion };
}

export function completeRegisteredThresholdEd25519Registration(args: {
  thresholdEd25519: WalletRegistrationThresholdEd25519Response | undefined;
  expectedSessionPolicy: ThresholdWarmSessionRequestEnvelope['session_policy'];
}): CompletedThresholdEd25519Registration {
  const thresholdEd25519 = args.thresholdEd25519;
  if (!thresholdEd25519) {
    throw new Error('Registration did not return threshold-ed25519 material');
  }
  if (
    String(thresholdEd25519.keyVersion || '').trim() !==
    THRESHOLD_ED25519_SINGLE_KEY_HSS_KEY_VERSION_V1
  ) {
    throw new Error('Registration did not return the active threshold-ed25519 keyVersion');
  }
  if (thresholdEd25519.recoveryExportCapable !== true) {
    throw new Error('Registration did not return recoveryExportCapable=true for threshold-ed25519');
  }
  const operationalPublicKey = String(thresholdEd25519.publicKey || '').trim();
  const relayerKeyId = String(thresholdEd25519.relayerKeyId || '').trim();
  if (!operationalPublicKey) {
    throw new Error('Missing account public key after registration');
  }
  if (!relayerKeyId) {
    throw new Error('Threshold registration did not return relayerKeyId');
  }

  const session = thresholdEd25519.session;
  const sessionKind = String(session?.sessionKind || '')
    .trim()
    .toLowerCase();
  const thresholdSessionId = String(session?.thresholdSessionId || '').trim();
  const walletSessionJwt = String(session?.jwt || '').trim();
  const expiresAtMs = Number(session?.expiresAtMs);
  if (
    sessionKind !== 'jwt' ||
    !thresholdSessionId ||
    !walletSessionJwt ||
    !Number.isFinite(expiresAtMs) ||
    expiresAtMs <= 0
  ) {
    throw new Error('Registration did not return a valid threshold-ed25519 warm session');
  }
  if (thresholdSessionId !== String(args.expectedSessionPolicy.thresholdSessionId || '').trim()) {
    throw new Error('threshold-ed25519 thresholdSessionId mismatch');
  }
  const signingGrantId = String(session?.signingGrantId || '').trim();
  const expectedSigningGrantId = String(
    args.expectedSessionPolicy.signingGrantId ||
      args.expectedSessionPolicy.thresholdSessionId ||
      '',
  ).trim();
  if (signingGrantId && signingGrantId !== expectedSigningGrantId) {
    throw new Error('threshold-ed25519 signingGrantId mismatch');
  }

  return {
    registered: thresholdEd25519,
    operationalPublicKey,
  };
}

export async function storeThresholdEd25519KeyMaterial(args: {
  nearAccountId: AccountId;
  signerSlot: number;
  signerId: string;
  publicKey: string;
  relayerKeyId: string;
  keyVersion: string;
  clientParticipantId?: number | null;
  relayerParticipantId?: number | null;
  relayerUrl?: string | null;
  timestamp?: number;
}): Promise<void> {
  const nearAccountId = String(args.nearAccountId || '').trim();
  const publicKey = String(args.publicKey || '').trim();
  const signerId = String(args.signerId || '').trim();
  const relayerKeyId = String(args.relayerKeyId || '').trim();
  const keyVersion = String(args.keyVersion || '').trim();
  if (!nearAccountId) {
    throw new Error('Threshold Ed25519 key persistence requires nearAccountId');
  }
  if (!Number.isSafeInteger(args.signerSlot) || args.signerSlot < 1) {
    throw new Error('Threshold Ed25519 key persistence requires signerSlot >= 1');
  }
  if (!publicKey) {
    throw new Error('Threshold Ed25519 key persistence requires publicKey');
  }
  if (!signerId) {
    throw new Error('Threshold Ed25519 key persistence requires signerId');
  }
  if (!relayerKeyId || !keyVersion) {
    throw new Error('Threshold Ed25519 key persistence requires complete relayer metadata');
  }

  await storeNearThresholdKeyMaterial(
    {
      clientDB: IndexedDBManager,
      keyMaterialStore: IndexedDBManager,
    },
    {
      nearAccountId: nearAccountId as AccountId,
      signerSlot: args.signerSlot,
      signerId,
      publicKey,
      relayerKeyId,
      keyVersion,
      participants: buildThresholdEd25519Participants2pV1({
        clientParticipantId: Number.isFinite(Number(args.clientParticipantId))
          ? Math.floor(Number(args.clientParticipantId))
          : null,
        relayerParticipantId: Number.isFinite(Number(args.relayerParticipantId))
          ? Math.floor(Number(args.relayerParticipantId))
          : null,
        relayerKeyId,
        relayerUrl: args.relayerUrl,
        clientShareDerivation: 'prf_first_v1',
      }),
      timestamp: typeof args.timestamp === 'number' ? args.timestamp : Date.now(),
    },
  );
}

function validateEmailOtpRegisteredThresholdEd25519WarmSessionMaterial(args: {
  nearAccountId: AccountId;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  material: ThresholdEd25519RegistrationHssClientMaterial;
  prfFirstB64u: string;
}): void {
  const material = args.material;
  const signingRootScope = signingRootScopeFromRuntimePolicyScope(args.runtimePolicyScope);
  const signingRootId = String(signingRootScope.signingRootId || '').trim();
  const materialSigningRootId = String(material.hssContext.signingRootId || '').trim();
  const materialNearAccountId = String(material.hssContext.nearAccountId || '').trim();
  if (!signingRootId || materialSigningRootId !== signingRootId) {
    throw new Error('Email OTP Ed25519 registration HSS signing-root binding mismatch');
  }
  if (materialNearAccountId !== String(args.nearAccountId || '').trim()) {
    throw new Error('Email OTP Ed25519 registration HSS account binding mismatch');
  }
  const materialPrfFirstB64u = String(material.prfFirstB64u || '').trim();
  if (materialPrfFirstB64u !== String(args.prfFirstB64u || '').trim()) {
    throw new Error('Email OTP Ed25519 registration warm-session PRF binding mismatch');
  }
}

export async function persistRegisteredThresholdEd25519Session(
  args: PersistRegisteredThresholdEd25519SessionArgs,
): Promise<void> {
  await storeThresholdEd25519KeyMaterial({
    nearAccountId: args.nearAccountId,
    signerSlot: args.signerSlot,
    signerId: args.completedRegistration.operationalPublicKey,
    publicKey: args.completedRegistration.registered.publicKey,
    relayerKeyId: args.completedRegistration.registered.relayerKeyId,
    keyVersion: args.completedRegistration.registered.keyVersion,
    clientParticipantId: args.completedRegistration.registered.clientParticipantId,
    relayerParticipantId: args.completedRegistration.registered.relayerParticipantId,
    relayerUrl: args.relayerUrl,
    timestamp: Date.now(),
  });

  const prfFirstB64u = String(args.prfFirstB64u || '').trim();
  if (!prfFirstB64u) {
    if (args.auth.kind === 'email_otp') {
      throw new Error('Email OTP Ed25519 registration requires PRF.first warm-session material');
    }
    return;
  }

  const session = args.completedRegistration.registered.session;
  if (!session) {
    throw new Error('Threshold Ed25519 warm session missing from registration response');
  }
  const sessionId = String(session.thresholdSessionId || '').trim();
  const jwt = String(session.jwt || '').trim();
  const signingGrantId =
    String(session.signingGrantId || '').trim() ||
    String(args.registrationSessionPolicy.signingGrantId || '').trim() ||
    String(args.registrationSessionPolicy.thresholdSessionId || '').trim();
  const expiresAtMs = Number(session.expiresAtMs);
  const remainingUsesRaw =
    typeof session.remainingUses === 'number'
      ? session.remainingUses
      : Number(session.remainingUses);
  const remainingUses =
    Number.isFinite(remainingUsesRaw) && remainingUsesRaw > 0
      ? Math.floor(remainingUsesRaw)
      : Math.max(1, Math.floor(Number(args.registrationSessionPolicy.remainingUses) || 1));
  const participantIds = Array.isArray(session.participantIds)
    ? session.participantIds
    : normalizeThresholdEd25519ParticipantIds(args.registrationSessionPolicy.participantIds) || [
        ...THRESHOLD_ED25519_2P_PARTICIPANT_IDS,
      ];
  const runtimePolicyScope = normalizeThresholdRuntimePolicyScope(
    session.runtimePolicyScope || args.registrationSessionPolicy.runtimePolicyScope,
  );
  const signingRootBinding = runtimePolicyScope
    ? signingRootScopeFromRuntimePolicyScope(runtimePolicyScope)
    : null;
  const signingRootId = String(signingRootBinding?.signingRootId || '').trim();
  const signingRootVersion = String(signingRootBinding?.signingRootVersion || '').trim();
  const routerAbNormalSigning = parseRouterAbEd25519NormalSigningState(
    session.routerAbNormalSigning,
  );
  if (
    !sessionId ||
    !jwt ||
    !signingGrantId ||
    !runtimePolicyScope ||
    !signingRootId ||
    !signingRootVersion ||
    !routerAbNormalSigning
  ) {
    throw new Error(
      'Threshold Ed25519 registration warm session missing Router A/B Wallet Session state',
    );
  }

  if (args.auth.kind === 'email_otp') {
    const registrationHssClientMaterial = args.registrationHssClientMaterial;
    if (!registrationHssClientMaterial) {
      throw new Error('Email OTP Ed25519 registration requires HSS client material');
    }
    if (!runtimePolicyScope) {
      throw new Error('Email OTP Ed25519 registration warm session requires runtimePolicyScope');
    }
    validateEmailOtpRegisteredThresholdEd25519WarmSessionMaterial({
      nearAccountId: args.nearAccountId,
      runtimePolicyScope,
      material: registrationHssClientMaterial,
      prfFirstB64u,
    });
    const warmSessionArgs: PersistWarmSessionEd25519JwtEmailOtpCapabilityArgs = {
      kind: 'jwt_email_otp',
      nearAccountId: String(args.nearAccountId),
      rpId: args.rpId,
      relayerUrl: args.relayerUrl,
      relayerKeyId: args.completedRegistration.registered.relayerKeyId,
      participantIds,
      sessionKind: 'jwt',
      sessionId,
      signingGrantId,
      expiresAtMs,
      remainingUses,
      jwt,
      signerSlot: args.signerSlot,
      emailOtpAuthContext: args.auth.emailOtpAuthContext,
      source: 'email_otp',
    };
    warmSessionArgs.runtimePolicyScope = runtimePolicyScope;
    if (signingRootId) {
      warmSessionArgs.signingRootId = signingRootId;
    }
    if (signingRootVersion) {
      warmSessionArgs.signingRootVersion = signingRootVersion;
    }
    if (routerAbNormalSigning) {
      warmSessionArgs.routerAbNormalSigning = routerAbNormalSigning;
    }
    persistWarmSessionEd25519Capability(warmSessionArgs);
  } else {
    const warmSessionArgs: PersistWarmSessionEd25519JwtPasskeyCapabilityArgs = {
      kind: 'jwt_passkey',
      nearAccountId: String(args.nearAccountId),
      rpId: args.rpId,
      relayerUrl: args.relayerUrl,
      relayerKeyId: args.completedRegistration.registered.relayerKeyId,
      participantIds,
      sessionKind: 'jwt',
      sessionId,
      signingGrantId,
      expiresAtMs,
      remainingUses,
      jwt,
      signerSlot: args.signerSlot,
      source: 'registration',
    };
    if (runtimePolicyScope) {
      warmSessionArgs.runtimePolicyScope = runtimePolicyScope;
    }
    if (signingRootId) {
      warmSessionArgs.signingRootId = signingRootId;
    }
    if (signingRootVersion) {
      warmSessionArgs.signingRootVersion = signingRootVersion;
    }
    if (routerAbNormalSigning) {
      warmSessionArgs.routerAbNormalSigning = routerAbNormalSigning;
    }
    persistWarmSessionEd25519Capability(warmSessionArgs);
  }

  await args.signingEngine.hydrateSigningSession({
    sessionId,
    prfFirstB64u,
    expiresAtMs,
    remainingUses,
    transport: {
      curve: 'ed25519',
      walletId: String(args.nearAccountId),
      relayerUrl: args.relayerUrl,
      ...(signingGrantId ? { signingGrantId } : {}),
      ...(jwt ? { walletSessionJwt: jwt } : {}),
    },
  });
}

async function refreshDurableThresholdEd25519SealedSessionWithWorkerMaterial(args: {
  context: ThresholdWarmSessionContext;
  thresholdSessionId: string;
  prfFirstB64u: string;
  nearAccountId: AccountId;
  relayerUrl: string;
  signingGrantId: string;
  walletSessionJwt: string;
  expiresAtMs: number;
  remainingUses: number;
}): Promise<void> {
  await args.context.signingEngine.hydrateSigningSession({
    sessionId: args.thresholdSessionId,
    prfFirstB64u: args.prfFirstB64u,
    expiresAtMs: args.expiresAtMs,
    remainingUses: args.remainingUses,
    transport: {
      curve: 'ed25519',
      walletId: String(args.nearAccountId),
      relayerUrl: args.relayerUrl,
      signingGrantId: args.signingGrantId,
      walletSessionJwt: args.walletSessionJwt,
    },
  });
}

export async function reconstructThresholdEd25519SigningMaterialFromWarmSession(args: {
  context: ThresholdWarmSessionContext;
  credential: WebAuthnRegistrationCredential | WebAuthnAuthenticationCredential;
  nearAccountId: AccountId;
  rpId: string;
  relayerUrl: string;
  relayerKeyId: string;
  signerSlot: number;
  session: ThresholdWarmSessionRelayResult;
  keyVersion: string;
  materialCreatedAtMs: number;
  participantIdsHint?: number[];
}): Promise<{
  materialHandle: string;
  bindingDigest: string;
  clientVerifyingShareB64u: string;
}> {
  const thresholdSessionId = String(args.session.thresholdSessionId || '').trim();
  const walletSessionJwt = String(args.session.jwt || '').trim();
  if (!thresholdSessionId || !walletSessionJwt) {
    throw new Error('Threshold Ed25519 warm session is missing JWT session state');
  }
  const runtimePolicyScope = normalizeThresholdRuntimePolicyScope(args.session.runtimePolicyScope);
  const signingRootScope = runtimePolicyScope
    ? signingRootScopeFromRuntimePolicyScope(runtimePolicyScope)
    : null;
  const signingRootId = signingRootScope?.signingRootId || '';
  const signingRootVersion = signingRootScope?.signingRootVersion || '';
  if (!signingRootId) {
    throw new Error(
      'Threshold Ed25519 warm session is missing canonical single-key HSS signing-root scope',
    );
  }
  const participantIds = normalizeThresholdEd25519ParticipantIds(args.session.participantIds) ||
    normalizeThresholdEd25519ParticipantIds(args.participantIdsHint) || [
      ...THRESHOLD_ED25519_2P_PARTICIPANT_IDS,
    ];
  const relayerUrl = String(args.relayerUrl || '').trim();
  const relayerKeyId = String(args.relayerKeyId || '').trim();
  const keyVersion = String(args.keyVersion || '').trim();
  if (!relayerUrl || !relayerKeyId || !keyVersion) {
    throw new Error('Threshold Ed25519 warm-session reconstruction is missing relay metadata');
  }
  const signingGrantId = String(args.session.signingGrantId || '').trim();
  const expiresAtMs = Math.floor(Number(args.session.expiresAtMs));
  const remainingUses = Math.floor(Number(args.session.remainingUses));
  const signingWorkerId = String(args.session.routerAbNormalSigning?.signingWorkerId || '').trim();
  if (
    !signingGrantId ||
    !signingRootVersion ||
    !Number.isFinite(expiresAtMs) ||
    expiresAtMs <= 0 ||
    !Number.isFinite(remainingUses) ||
    remainingUses < 0
  ) {
    throw new Error('Threshold Ed25519 warm-session reconstruction is missing session binding');
  }
  if (!signingWorkerId) {
    throw new Error(
      'Threshold Ed25519 warm-session reconstruction is missing Router A/B SigningWorker scope',
    );
  }
  const prfFirstB64u = String(getPrfFirstB64uFromCredential(args.credential) || '').trim();
  if (!prfFirstB64u) {
    throw new Error('Missing PRF.first output from credential for threshold Ed25519 HSS masking');
  }
  const prepared =
    await args.context.signingEngine.prepareThresholdEd25519HssClientCeremonyFromCredential({
      credential: args.credential,
      signingRootId,
      nearAccountId: args.nearAccountId,
      keyPurpose: THRESHOLD_ED25519_HSS_SIGNING_KEY_PURPOSE,
      keyVersion,
      participantIds,
      derivationVersion: THRESHOLD_ED25519_HSS_DERIVATION_VERSION,
    });
  if (!prepared.ok) {
    throw new Error(
      prepared.message || 'Failed to prepare threshold Ed25519 HSS reconstruction ceremony',
    );
  }
  const materialBinding = {
    thresholdSessionId,
    signingGrantId,
    signingRootId,
    signingRootVersion,
    expiresAtMs,
    nearAccountId: String(args.nearAccountId || '').trim(),
    signerSlot: args.signerSlot,
    relayerKeyId,
    keyVersion,
    participantIds,
    createdAtMs: args.materialCreatedAtMs,
    signingWorkerId,
  };
  const bindingInput: ThresholdEd25519WorkerMaterialBindingInputWithoutVerifier = {
    nearAccountId: materialBinding.nearAccountId,
    signerSlot: materialBinding.signerSlot,
    signingRootId: materialBinding.signingRootId,
    signingRootVersion: materialBinding.signingRootVersion,
    relayerKeyId: materialBinding.relayerKeyId,
    keyVersion: materialBinding.keyVersion,
    participantIds: materialBinding.participantIds,
    createdAtMs: materialBinding.createdAtMs,
  };
  const preparedSealAuthorization =
    await prepareThresholdEd25519PasskeyMaterialSealAuthorizationFromCredential({
      authorizationPort: {
        prepareThresholdEd25519PasskeyPrfWorkerMaterialSealAuthorization: (authorizationArgs) =>
          args.context.signingEngine.prepareThresholdEd25519PasskeyPrfWorkerMaterialSealAuthorization(
            authorizationArgs,
          ),
      },
      bindingInput,
      rpId: args.rpId,
      credential: args.credential,
    });
  const completed =
    await args.context.signingEngine.runThresholdEd25519HssCeremonyWithMaterialHandle({
      relayerUrl,
      walletSessionJwt,
      relayerKeyId,
      operation: 'warm_session_reconstruction',
      context: {
        signingRootId,
        nearAccountId: args.nearAccountId,
        keyPurpose: THRESHOLD_ED25519_HSS_SIGNING_KEY_PURPOSE,
        keyVersion,
        participantIds,
        derivationVersion: THRESHOLD_ED25519_HSS_DERIVATION_VERSION,
      },
      clientInputs: {
        contextBindingB64u: prepared.contextBindingB64u,
        yClientB64u: prepared.yClientB64u,
        tauClientB64u: prepared.tauClientB64u,
      },
      outputProjection: {
        kind: 'client-masked-projection',
        clientRecoverableSecretB64u: prfFirstB64u,
      },
      materialBinding,
      preparedSealAuthorization,
    });
  if (!completed.ok) {
    throw new Error(
      completed.message || 'Failed to reconstruct threshold Ed25519 signing material',
    );
  }
  const signingMaterial = completed.signingMaterial;
  const clientVerifyingShareB64u = String(signingMaterial.clientVerifyingShareB64u || '').trim();
  if (!clientVerifyingShareB64u) {
    throw new Error('Failed to store threshold Ed25519 worker signing material');
  }
  const persisted = persistStoredThresholdEd25519SessionMaterialHandle({
    thresholdSessionId,
    clientVerifyingShareB64u,
    ed25519WorkerMaterialHandle: signingMaterial.materialHandle,
    ed25519WorkerMaterialBindingDigest: signingMaterial.materialBindingDigest,
    sealedWorkerMaterialRef: signingMaterial.sealedWorkerMaterialRef,
    sealedWorkerMaterialB64u: signingMaterial.sealedWorkerMaterialB64u,
    materialFormatVersion: signingMaterial.materialFormatVersion,
    materialKeyId: signingMaterial.materialKeyId,
    materialCreatedAtMs: materialBinding.createdAtMs,
    signerSlot: signingMaterial.signerSlot,
    keyVersion: signingMaterial.keyVersion,
  });
  if (!persisted) {
    throw new Error('Failed to persist HSS client output to the threshold session store');
  }
  markRouterAbEd25519WorkerMaterialRuntimeValidated(
    getStoredThresholdEd25519SessionRecordByThresholdSessionId(thresholdSessionId),
  );
  await refreshDurableThresholdEd25519SealedSessionWithWorkerMaterial({
    context: args.context,
    thresholdSessionId,
    prfFirstB64u,
    nearAccountId: args.nearAccountId,
    relayerUrl,
    signingGrantId,
    walletSessionJwt,
    expiresAtMs,
    remainingUses,
  });
  return {
    materialHandle: signingMaterial.materialHandle,
    bindingDigest: signingMaterial.materialBindingDigest,
    clientVerifyingShareB64u,
  };
}

export async function hydrateThresholdWarmSessionFromRelay(args: {
  context: ThresholdWarmSessionContext;
  nearAccountId: AccountId;
  relayerUrl: string;
  rpId: string;
  relayerKeyId: string;
  credential: WebAuthnAuthenticationCredential | WebAuthnRegistrationCredential;
  signerSlot: number;
  requestedPolicy: ThresholdWarmSessionPolicyDraft;
  session: ThresholdWarmSessionRelayResult;
  participantIdsHint?: number[];
}): Promise<{
  sessionId: string;
  expiresAtMs: number;
  remainingUses: number;
  participantIds: number[];
}> {
  const sessionKind = String(args.session?.sessionKind || 'jwt')
    .trim()
    .toLowerCase() as ThresholdSessionKind;
  if (sessionKind !== 'jwt') {
    throw new Error('threshold-ed25519 bootstrap sessionKind must be jwt');
  }

  const sessionId =
    String(args.session?.thresholdSessionId || '').trim() ||
    String(args.requestedPolicy.sessionId || '').trim();
  const signingGrantId =
    String(args.session?.signingGrantId || '').trim() ||
    String(args.requestedPolicy.signingGrantId || '').trim() ||
    String(args.requestedPolicy.sessionId || '').trim();
  const walletSessionJwt = String(args.session?.jwt || '').trim();
  const expiresAtMs = Number(args.session?.expiresAtMs);
  if (!sessionId || !walletSessionJwt || !Number.isFinite(expiresAtMs) || expiresAtMs <= 0) {
    throw new Error('threshold-ed25519 bootstrap response missing session fields');
  }

  const remainingUsesRaw = parsePositiveInt(args.session?.remainingUses);
  const remainingUses =
    remainingUsesRaw > 0 ? remainingUsesRaw : parsePositiveInt(args.requestedPolicy.remainingUses);
  if (remainingUses <= 0) {
    throw new Error('threshold-ed25519 bootstrap response missing remainingUses');
  }

  const participantIds = normalizeThresholdEd25519ParticipantIds(args.session?.participantIds) ||
    normalizeThresholdEd25519ParticipantIds(args.requestedPolicy.participantIds) ||
    normalizeThresholdEd25519ParticipantIds(args.participantIdsHint) || [
      ...THRESHOLD_ED25519_2P_PARTICIPANT_IDS,
    ];
  const runtimePolicyScope = normalizeThresholdRuntimePolicyScope(args.session?.runtimePolicyScope);
  const signingRootBinding = runtimePolicyScope
    ? signingRootScopeFromRuntimePolicyScope(runtimePolicyScope)
    : null;
  const signingRootId = String(signingRootBinding?.signingRootId || '').trim();
  const signingRootVersion = String(signingRootBinding?.signingRootVersion || '').trim();
  const routerAbNormalSigning = parseRouterAbEd25519NormalSigningState(
    args.session?.routerAbNormalSigning || args.requestedPolicy.routerAbNormalSigning,
  );
  const prfFirstB64u = String(getPrfFirstB64uFromCredential(args.credential) || '').trim();
  if (!prfFirstB64u) {
    throw new Error('Missing PRF.first output from credential for threshold session hydration');
  }

  persistWarmSessionEd25519Capability({
    kind: 'jwt_passkey',
    nearAccountId: String(args.nearAccountId),
    rpId: String(args.rpId || '').trim(),
    relayerUrl: String(args.relayerUrl || '').trim(),
    relayerKeyId: String(args.relayerKeyId || '').trim(),
    participantIds,
    sessionKind: 'jwt',
    sessionId,
    signingGrantId,
    expiresAtMs: Math.floor(expiresAtMs),
    remainingUses,
    jwt: walletSessionJwt,
    signerSlot: args.signerSlot,
    ...(signingRootId ? { signingRootId } : {}),
    ...(signingRootVersion ? { signingRootVersion } : {}),
    ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
    ...(routerAbNormalSigning ? { routerAbNormalSigning } : {}),
    source: 'bootstrap',
  });
  await args.context.signingEngine.hydrateSigningSession({
    sessionId,
    prfFirstB64u,
    expiresAtMs: Math.floor(expiresAtMs),
    remainingUses,
    transport: {
      curve: 'ed25519',
      walletId: String(args.nearAccountId),
      relayerUrl: String(args.relayerUrl || '').trim(),
      ...(signingGrantId ? { signingGrantId } : {}),
      ...(walletSessionJwt ? { walletSessionJwt } : {}),
    },
  });

  return {
    sessionId,
    expiresAtMs: Math.floor(expiresAtMs),
    remainingUses,
    participantIds,
  };
}
