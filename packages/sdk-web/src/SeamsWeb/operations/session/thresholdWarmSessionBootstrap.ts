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
import type {
  ThresholdEcdsaEmailOtpAuthContext,
  ThresholdEd25519SessionStoreSource,
} from '@/core/signingEngine/session/identity/laneIdentity';
import { emailOtpAuthContextProviderUserId } from '@/core/signingEngine/session/identity/laneIdentity';
import { getPrfFirstB64uFromCredential } from '@/core/signingEngine/threshold/crypto/webauthn';
import {
  type SigningGrantId,
  type ThresholdEd25519SessionId,
} from '@shared/utils/domainIds';
import {
  getStoredThresholdEd25519SessionRecordByThresholdSessionId,
  persistStoredThresholdEd25519SessionMaterialHandle,
  type ThresholdEd25519MaterialPendingSessionRecord,
  type ThresholdEd25519RestoreAvailableSessionRecord,
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
  parseThresholdRuntimePolicyScopeFromJwt,
  type Ed25519AuthorityScope,
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
  prepareRecoveryCodeSealAuthorizationForEmailOtp,
  recoveryCodeBindingDigestForEmailOtpMaterial,
} from '@/core/signingEngine/session/emailOtp/clientSecretSource';
import {
  requireOrRestoreRouterAbEd25519WalletSessionState,
  type RouterAbEd25519WorkerMaterialRestoreAuthorization,
} from '@/core/signingEngine/flows/signNear/shared/ed25519SigningMaterialReadiness';
import type { NearEd25519SigningKeyId } from '@shared/utils/registrationIntent';
import { resolveRouterAbEd25519WorkerMaterialRestoreAuthorizationForPasskeyCredential } from '@/core/signingEngine/flows/signNear/shared/ed25519MaterialRestoreAuthorization';
import {
  parseEd25519HssKeyVersion,
  parseEd25519ClientVerifyingShareB64u,
  parseEd25519SealedWorkerMaterialRef,
  parseEd25519WorkerMaterialBindingDigest,
  parseEd25519WorkerMaterialKeyId,
  type Ed25519ClientVerifyingShareB64u,
  type Ed25519HssKeyVersion,
  type Ed25519SealedWorkerMaterialRef,
  type Ed25519WorkerMaterialBindingDigest,
  type Ed25519WorkerMaterialKeyId,
} from '@/core/signingEngine/session/keyMaterialBrands';
import {
  computeSdkEd25519HssApplicationBindingDigestB64u,
  type SdkEd25519HssBindingFacts,
} from '@shared/threshold/ed25519HssBinding';
import {
  parseSdkEcdsaHssSigningRootId,
  parseSdkEcdsaHssSigningRootVersion,
} from '@shared/threshold/ecdsaHssRoleLocalBootstrap';

export const THRESHOLD_ED25519_SINGLE_KEY_HSS_KEY_VERSION_V1 = 'threshold-ed25519-hss-v1';

function passkeyCredentialIdB64uFromCredential(
  credential: WebAuthnAuthenticationCredential | WebAuthnRegistrationCredential,
): string {
  const credentialIdB64u = String(credential.rawId || credential.id || '').trim();
  if (!credentialIdB64u) {
    throw new Error('Missing passkey credential id for threshold session hydration');
  }
  return credentialIdB64u;
}

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

function thresholdEd25519HssBindingFactsFromRuntimePolicyScope(args: {
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  nearEd25519SigningKeyId: NearEd25519SigningKeyId;
}): SdkEd25519HssBindingFacts {
  const signingRootScope = signingRootScopeFromRuntimePolicyScope(args.runtimePolicyScope);
  return {
    nearEd25519SigningKeyId: args.nearEd25519SigningKeyId,
    signingRootId: parseSdkEcdsaHssSigningRootId(signingRootScope.signingRootId),
    signingRootVersion: parseSdkEcdsaHssSigningRootVersion(signingRootScope.signingRootVersion),
  };
}

export type RegisteredThresholdEd25519SessionAuth =
  | {
      kind: 'passkey';
      credentialIdB64u: string;
      emailOtpAuthContext?: never;
    }
  | {
      kind: 'email_otp';
      emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
    };

export type ThresholdWarmSessionPolicyDraft = {
  sessionId: string;
  signingGrantId: string;
  ttlMs: number;
  remainingUses: number;
  participantIds?: number[];
  routerAbNormalSigning: RouterAbEd25519NormalSigningState;
};

export type ThresholdWarmSessionPolicyDraftInput =
  | {
      kind: 'generated_signing_grant';
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
    walletId?: string;
    nearAccountId?: string;
    nearEd25519SigningKeyId?: string;
    authorityScope: Ed25519AuthorityScope;
    relayerKeyId?: string;
    thresholdSessionId: string;
    signingGrantId: string;
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

type ExpectedThresholdEd25519SessionIdentity = {
  walletId: string;
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
};

type PersistRegisteredThresholdEd25519SessionBaseArgs = {
  walletId: string;
  nearAccountId: AccountId;
  nearEd25519SigningKeyId: NearEd25519SigningKeyId;
  signerSlot: number;
  rpId: string;
  relayerUrl: string;
  registrationSessionPolicy: ThresholdWarmSessionRequestEnvelope['session_policy'];
  completedRegistration: CompletedThresholdEd25519Registration;
};

export type PersistRegisteredThresholdEd25519SessionArgs =
  | (PersistRegisteredThresholdEd25519SessionBaseArgs & {
      signingEngine: Pick<SigningSessionSurface, 'hydrateSigningSession'>;
      auth: Extract<RegisteredThresholdEd25519SessionAuth, { kind: 'passkey' }>;
      prfFirstB64u: string | null;
      registrationHssClientMaterial?: never;
      workerCtx?: never;
    })
  | (PersistRegisteredThresholdEd25519SessionBaseArgs & {
      signingEngine: Pick<SigningSessionSurface, 'hydrateSigningSession'> &
        Pick<
          ThresholdEd25519HssCeremonySurface,
          'runThresholdEd25519HssCeremonyWithMaterialHandle'
        >;
      auth: Extract<RegisteredThresholdEd25519SessionAuth, { kind: 'email_otp' }>;
      workerCtx: WorkerOperationContext;
      prfFirstB64u: string;
      registrationHssClientMaterial: ThresholdEd25519RegistrationHssClientMaterial;
    });

type ThresholdWarmSessionRouterApiResult = {
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
  bindingFacts: SdkEd25519HssBindingFacts;
  prfFirstB64u: string;
  clientInputs: {
    contextBindingB64u: string;
    yClientB64u: string;
    tauClientB64u: string;
  };
};

export type RestoreThresholdEd25519WorkerMaterialPendingReason =
  | 'pending_material'
  | 'no_durable_restore_records'
  | 'duplicate_worker_material_records'
  | 'durable_restore_identity_mismatch';

type WalletSessionJwt = string;

export type Ed25519SessionAuthority = {
  thresholdSessionId: ThresholdEd25519SessionId;
  signingGrantId: SigningGrantId;
  walletSessionJwt: WalletSessionJwt;
  expiresAtMs: number;
  remainingUses: number;
};

export type Ed25519WorkerMaterialIdentity = {
  materialKeyId: Ed25519WorkerMaterialKeyId;
  bindingDigest: Ed25519WorkerMaterialBindingDigest;
  clientVerifyingShareB64u: Ed25519ClientVerifyingShareB64u;
};

type Ed25519SealedWorkerMaterialCommon = {
  sealedRef: Ed25519SealedWorkerMaterialRef;
  materialFormatVersion: string;
  materialCreatedAtMs: number;
  signerSlot: number;
};

export type Ed25519SealedWorkerMaterial =
  | (Ed25519SealedWorkerMaterialCommon & {
      kind: 'storage_ref';
      sealedBlobB64u?: never;
    })
  | (Ed25519SealedWorkerMaterialCommon & {
      kind: 'inline_sealed_blob';
      sealedBlobB64u: string;
    });

export type Ed25519ReusableSealedWorkerMaterial = {
  identity: Ed25519WorkerMaterialIdentity;
  sealed: Ed25519SealedWorkerMaterial;
};

export type ThresholdEd25519LoginMaterialPendingSessionRecord = Omit<
  ThresholdEd25519MaterialPendingSessionRecord,
  | 'thresholdSessionKind'
  | 'thresholdSessionId'
  | 'signingGrantId'
  | 'walletSessionJwt'
  | 'passkeyCredentialIdB64u'
  | 'emailOtpAuthContext'
> & {
  source: 'login';
  thresholdSessionKind: 'jwt';
  thresholdSessionId: ThresholdEd25519SessionId;
  signingGrantId: SigningGrantId;
  walletSessionJwt: WalletSessionJwt;
  passkeyCredentialIdB64u: string;
  emailOtpAuthContext?: never;
};

export type Ed25519ReusableLoginMaterialResolution =
  | {
      kind: 'ready_from_reusable_durable_material';
      authority: Ed25519SessionAuthority;
      material: Ed25519ReusableSealedWorkerMaterial;
    }
  | {
      kind: 'pending_material';
      record: ThresholdEd25519LoginMaterialPendingSessionRecord;
      reason: RestoreThresholdEd25519WorkerMaterialPendingReason;
      details: string;
    };

type Ed25519ReusableWorkerMaterialSelector = {
  walletId: string;
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
  rpId: string;
  relayerKeyId: string;
  participantIds: readonly number[];
  signerSlot: number;
};

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

function requirePositiveRestoreInteger(value: unknown, label: string): number {
  const parsed = normalizedRestorePositiveInteger(value);
  if (!parsed) {
    throw new Error(`${label} must be a positive integer`);
  }
  return parsed;
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

function buildEd25519ReusableWorkerMaterialSelector(
  record: ThresholdEd25519LoginMaterialPendingSessionRecord,
): Ed25519ReusableWorkerMaterialSelector {
  const signingRoot = ed25519RecordSigningRoot(record);
  return {
    walletId: record.walletId,
    nearAccountId: record.nearAccountId,
    nearEd25519SigningKeyId: record.nearEd25519SigningKeyId,
    signingRootId: signingRoot.signingRootId,
    signingRootVersion: signingRoot.signingRootVersion,
    rpId: record.rpId,
    relayerKeyId: record.relayerKeyId,
    participantIds: record.participantIds,
    signerSlot: record.signerSlot,
  };
}

function ed25519ReusableSealedWorkerMaterialFromRecord(
  record: CurrentEd25519RestoreSealedSessionRecord,
): Ed25519ReusableSealedWorkerMaterial {
  const restore = record.ed25519Restore;
  const sealedBlobB64u = normalizedRestoreString(restore.sealedWorkerMaterialB64u);
  return {
    identity: {
      materialKeyId: parseEd25519WorkerMaterialKeyId(restore.materialKeyId),
      bindingDigest: parseEd25519WorkerMaterialBindingDigest(
        restore.ed25519WorkerMaterialBindingDigest,
      ),
      clientVerifyingShareB64u: parseEd25519ClientVerifyingShareB64u(
        restore.clientVerifyingShareB64u,
      ),
    },
    sealed: {
      sealedRef: parseEd25519SealedWorkerMaterialRef(restore.sealedWorkerMaterialRef),
      materialFormatVersion: restore.materialFormatVersion,
      materialCreatedAtMs: restore.materialCreatedAtMs,
      signerSlot: restore.signerSlot,
      ...(sealedBlobB64u
        ? { kind: 'inline_sealed_blob', sealedBlobB64u }
        : { kind: 'storage_ref' }),
    },
  };
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

function ed25519RestoreMaterialSelectorMismatchReasons(args: {
  selector: Ed25519ReusableWorkerMaterialSelector;
  sealed: CurrentEd25519RestoreSealedSessionRecord;
}): string[] {
  const selector = args.selector;
  const sealed = args.sealed;
  const restore = sealed.ed25519Restore;
  const sealedSigningRoot = sealedEd25519RestoreSigningRoot(sealed);
  const reasons: string[] = [];
  if (normalizedRestoreString(sealed.walletId) !== selector.walletId) {
    reasons.push('walletId');
  }
  if (normalizedRestoreString(restore.nearAccountId) !== selector.nearAccountId) {
    reasons.push('nearAccountId');
  }
  if (
    normalizedRestoreString(restore.nearEd25519SigningKeyId) !==
    selector.nearEd25519SigningKeyId
  ) {
    reasons.push('nearEd25519SigningKeyId');
  }
  if (sealedSigningRoot.signingRootId !== selector.signingRootId) {
    reasons.push('signingRootId');
  }
  if (sealedSigningRoot.signingRootVersion !== selector.signingRootVersion) {
    reasons.push('signingRootVersion');
  }
  if (normalizedRestoreString(restore.rpId) !== selector.rpId) {
    reasons.push('rpId');
  }
  if (normalizedRestoreString(restore.relayerKeyId) !== selector.relayerKeyId) {
    reasons.push('relayerKeyId');
  }
  if (!restoreParticipantIdsEqual(restore.participantIds, selector.participantIds)) {
    reasons.push('participantIds');
  }
  if (normalizedRestorePositiveInteger(restore.signerSlot) !== selector.signerSlot) {
    reasons.push('signerSlot');
  }
  return reasons;
}

function ed25519RestoreReusableMaterialMismatchReasons(args: {
  selector: Ed25519ReusableWorkerMaterialSelector;
  sealed: CurrentEd25519RestoreSealedSessionRecord;
}): string[] {
  return ed25519RestoreMaterialSelectorMismatchReasons(args);
}

function sealedEd25519RestoreMatchesReusableMaterialSelector(args: {
  selector: Ed25519ReusableWorkerMaterialSelector;
  sealed: CurrentEd25519RestoreSealedSessionRecord;
}): boolean {
  return ed25519RestoreReusableMaterialMismatchReasons(args).length === 0;
}

function listReusableEd25519WorkerMaterialSealedRecords(args: {
  selector: Ed25519ReusableWorkerMaterialSelector;
  records: readonly CurrentEd25519RestoreSealedSessionRecord[];
}): CurrentEd25519RestoreSealedSessionRecord[] {
  const matchingRecords: CurrentEd25519RestoreSealedSessionRecord[] = [];
  for (const sealedRecord of args.records) {
    if (
      sealedEd25519RestoreMatchesReusableMaterialSelector({
        selector: args.selector,
        sealed: sealedRecord,
      })
    ) {
      matchingRecords.push(sealedRecord);
    }
  }
  return matchingRecords;
}

function reusableEd25519WorkerMaterialMismatchDetails(args: {
  selector: Ed25519ReusableWorkerMaterialSelector;
  records: readonly CurrentEd25519RestoreSealedSessionRecord[];
}): string {
  const mismatchReasons = new Set<string>();
  for (const sealedRecord of args.records) {
    for (const reason of ed25519RestoreReusableMaterialMismatchReasons({
      selector: args.selector,
      sealed: sealedRecord,
    })) {
      mismatchReasons.add(reason);
    }
  }
  const fields = [...mismatchReasons].sort().join(',') || 'unknown';
  return `candidate records=${args.records.length}; mismatch fields=${fields}`;
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
  if (normalizedRestoreString(sealed.walletId) !== normalizedRestoreString(current.walletId)) {
    reasons.push('walletId');
  }
  if (
    normalizedRestoreString(restore.nearAccountId) !==
    normalizedRestoreString(current.nearAccountId)
  ) {
    reasons.push('nearAccountId');
  }
  if (
    normalizedRestoreString(restore.nearEd25519SigningKeyId) !==
    normalizedRestoreString(current.nearEd25519SigningKeyId)
  ) {
    reasons.push('nearEd25519SigningKeyId');
  }
  if (
    normalizedRestoreString(sealed.signingGrantId) !==
    normalizedRestoreString(current.signingGrantId)
  ) {
    reasons.push('signingGrantId');
  }
  if (
    ed25519ThresholdSessionIdFromSealedRecord(sealed) !==
    normalizedRestoreString(current.thresholdSessionId)
  ) {
    reasons.push('thresholdSessionId');
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
  const currentMaterialBindingDigest = normalizedRestoreString(
    current.ed25519WorkerMaterialBindingDigest,
  );
  const sealedMaterialBindingDigest = normalizedRestoreString(
    restore.ed25519WorkerMaterialBindingDigest,
  );
  if (
    currentMaterialBindingDigest &&
    sealedMaterialBindingDigest &&
    currentMaterialBindingDigest !== sealedMaterialBindingDigest
  ) {
    reasons.push('ed25519WorkerMaterialBindingDigest');
  }
  return reasons;
}

type ExactEd25519WorkerMaterialRestoreRecordSelection =
  | {
      kind: 'exact_match';
      record: CurrentEd25519RestoreSealedSessionRecord;
    }
  | {
      kind: 'duplicate_records';
      exactMatchCount: number;
      storeKeys: string[];
    }
  | {
      kind: 'not_found';
    };

function selectSingleEd25519WorkerMaterialRestoreRecord(
  records: readonly CurrentEd25519RestoreSealedSessionRecord[],
): ExactEd25519WorkerMaterialRestoreRecordSelection {
  switch (records.length) {
    case 0:
      return { kind: 'not_found' };
    case 1: {
      const record = records[0];
      return record ? { kind: 'exact_match', record } : { kind: 'not_found' };
    }
    default:
      return {
        kind: 'duplicate_records',
        exactMatchCount: records.length,
        storeKeys: records
          .map((record) => normalizedRestoreString(record.storeKey))
          .filter(Boolean),
      };
  }
}

function duplicateExactEd25519RestoreDetails(
  selection: Extract<
    ExactEd25519WorkerMaterialRestoreRecordSelection,
    { kind: 'duplicate_records' }
  >,
): string {
  return `candidate records=${selection.exactMatchCount}; storeKeys=${selection.storeKeys.join(',') || 'unknown'}`;
}

function assertNeverExactEd25519WorkerMaterialRestoreRecordSelection(value: never): never {
  throw new Error(`Unexpected exact Ed25519 restore selection branch: ${String(value)}`);
}

function ed25519ThresholdSessionIdFromSealedRecord(
  record: CurrentEd25519RestoreSealedSessionRecord,
): string {
  return normalizedRestoreString(record.thresholdSessionIds?.ed25519);
}

function sealedEd25519RestoreRecordMatchesExactSession(args: {
  record: CurrentEd25519RestoreSealedSessionRecord;
  walletId: string;
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  signingGrantId: string;
  thresholdSessionId: string;
}): boolean {
  return (
    normalizedRestoreString(args.record.walletId) === normalizedRestoreString(args.walletId) &&
    normalizedRestoreString(args.record.ed25519Restore.nearAccountId) ===
      normalizedRestoreString(args.nearAccountId) &&
    normalizedRestoreString(args.record.ed25519Restore.nearEd25519SigningKeyId) ===
      normalizedRestoreString(args.nearEd25519SigningKeyId) &&
    normalizedRestoreString(args.record.signingGrantId) ===
      normalizedRestoreString(args.signingGrantId) &&
    ed25519ThresholdSessionIdFromSealedRecord(args.record) ===
      normalizedRestoreString(args.thresholdSessionId)
  );
}

function sealedEd25519RestoreRuntimePolicyScope(
  record: CurrentEd25519RestoreSealedSessionRecord,
): ThresholdRuntimePolicyScope | undefined {
  return (
    normalizeThresholdRuntimePolicyScope(record.ed25519Restore.runtimePolicyScope) ||
    parseThresholdRuntimePolicyScopeFromJwt(record.ed25519Restore.walletSessionJwt)
  );
}

function upsertEd25519SessionRecordFromExactSealedWorkerMaterial(args: {
  sealed: CurrentEd25519RestoreSealedSessionRecord;
  source: ThresholdEd25519SessionStoreSource;
}): ThresholdEd25519SessionRecord | null {
  const sealed = args.sealed;
  const restore = sealed.ed25519Restore;
  const thresholdSessionId = ed25519ThresholdSessionIdFromSealedRecord(sealed);
  const runtimePolicyScope = sealedEd25519RestoreRuntimePolicyScope(sealed);
  const signingRoot = sealedEd25519RestoreSigningRoot(sealed);
  const walletSessionJwt = normalizedRestoreString(restore.walletSessionJwt);
  const sessionKind = restore.sessionKind === 'cookie' ? 'cookie' : 'jwt';
  const routerAbNormalSigning = parseRouterAbEd25519NormalSigningState(
    restore.routerAbNormalSigning,
  );
  if (!thresholdSessionId) return null;
  if (!routerAbNormalSigning) return null;
  return upsertStoredThresholdEd25519SessionRecord({
    walletId: sealed.walletId,
    nearAccountId: restore.nearAccountId,
    nearEd25519SigningKeyId: restore.nearEd25519SigningKeyId,
    rpId: restore.rpId,
    ...(normalizedRestoreString(restore.credentialIdB64u)
      ? { passkeyCredentialIdB64u: normalizedRestoreString(restore.credentialIdB64u) }
      : {}),
    relayerUrl: sealed.relayerUrl,
    relayerKeyId: restore.relayerKeyId,
    participantIds: restore.participantIds,
    signingRootId: signingRoot.signingRootId,
    signingRootVersion: signingRoot.signingRootVersion,
    ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
    clientVerifyingShareB64u: normalizedRestoreString(restore.clientVerifyingShareB64u),
    ed25519WorkerMaterialBindingDigest: normalizedRestoreString(
      restore.ed25519WorkerMaterialBindingDigest,
    ),
    // Persisted worker handles are hints; exact durable hydration forces restore
    // from sealed material so stale handles cannot look signable.
    sealedWorkerMaterialRef: normalizedRestoreString(restore.sealedWorkerMaterialRef),
    sealedWorkerMaterialB64u: normalizedRestoreString(restore.sealedWorkerMaterialB64u),
    materialFormatVersion: normalizedRestoreString(restore.materialFormatVersion),
    materialKeyId: normalizedRestoreString(restore.materialKeyId),
    materialCreatedAtMs: normalizedRestorePositiveInteger(restore.materialCreatedAtMs),
    signerSlot: normalizedRestorePositiveInteger(restore.signerSlot),
    routerAbNormalSigning,
    thresholdSessionKind: sessionKind,
    thresholdSessionId,
    signingGrantId: sealed.signingGrantId,
    ...(walletSessionJwt ? { walletSessionJwt } : {}),
    expiresAtMs: normalizedRestorePositiveInteger(sealed.expiresAtMs),
    remainingUses: normalizedRestorePositiveInteger(sealed.remainingUses),
    updatedAtMs: Date.now(),
    source: args.source,
  });
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

export async function hydrateExactEd25519SessionFromDurableSealedWorkerMaterial(args: {
  walletId: string;
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  signingGrantId: string;
  thresholdSessionId: string;
  source: ThresholdEd25519SessionStoreSource;
}): Promise<
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
  const walletId = normalizedRestoreString(args.walletId);
  const nearAccountId = normalizedRestoreString(args.nearAccountId);
  const nearEd25519SigningKeyId = normalizedRestoreString(args.nearEd25519SigningKeyId);
  const signingGrantId = normalizedRestoreString(args.signingGrantId);
  const thresholdSessionId = normalizedRestoreString(args.thresholdSessionId);
  if (
    !walletId ||
    !nearAccountId ||
    !nearEd25519SigningKeyId ||
    !signingGrantId ||
    !thresholdSessionId
  ) {
    return {
      kind: 'not_found',
      pendingReason: 'pending_material',
      pendingDetails: 'missing exact Ed25519 sealed-session lookup identity',
    };
  }
  const records = (await listPasskeyEd25519RestoreSealedSessionsForWallet(walletId)).filter(
    (record) =>
      sealedEd25519RestoreRecordMatchesExactSession({
        record,
        walletId,
        nearAccountId,
        nearEd25519SigningKeyId,
        signingGrantId,
        thresholdSessionId,
      }),
  );
  if (!records.length) {
    return {
      kind: 'not_found',
      pendingReason: 'no_durable_restore_records',
      pendingDetails:
        'no passkey sealed session record contains Ed25519 restore metadata for the exact threshold session',
    };
  }
  const selection = selectSingleEd25519WorkerMaterialRestoreRecord(records);
  switch (selection.kind) {
    case 'not_found':
      return {
        kind: 'not_found',
        pendingReason: 'pending_material',
        pendingDetails: 'failed to select exact Ed25519 session record from durable metadata',
      };
    case 'duplicate_records':
      return {
        kind: 'not_found',
        pendingReason: 'duplicate_worker_material_records',
        pendingDetails: duplicateExactEd25519RestoreDetails(selection),
      };
    case 'exact_match':
      break;
    default:
      return assertNeverExactEd25519WorkerMaterialRestoreRecordSelection(selection);
  }
  const hydrated = upsertEd25519SessionRecordFromExactSealedWorkerMaterial({
    sealed: selection.record,
    source: args.source,
  });
  if (!hydrated) {
    return {
      kind: 'not_found',
      pendingReason: 'pending_material',
      pendingDetails: 'failed to hydrate exact Ed25519 session record from durable metadata',
    };
  }
  return {
    kind: 'hydrated',
    record: hydrated,
  };
}

export async function hydrateAccountScopedDiscoveryEd25519SessionFromDurableSealedWorkerMaterial(args: {
  walletId: string;
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  source: ThresholdEd25519SessionStoreSource;
}): Promise<
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
  const walletId = normalizedRestoreString(args.walletId);
  const nearAccountId = normalizedRestoreString(args.nearAccountId);
  const nearEd25519SigningKeyId = normalizedRestoreString(args.nearEd25519SigningKeyId);
  if (!walletId || !nearAccountId || !nearEd25519SigningKeyId) {
    return {
      kind: 'not_found',
      pendingReason: 'pending_material',
      pendingDetails: 'missing latest Ed25519 sealed-session lookup account',
    };
  }
  const records = (await listPasskeyEd25519RestoreSealedSessionsForWallet(walletId)).filter(
    (record) =>
      normalizedRestoreString(record.ed25519Restore.nearAccountId) === nearAccountId &&
      normalizedRestoreString(record.ed25519Restore.nearEd25519SigningKeyId) ===
        nearEd25519SigningKeyId,
  );
  if (!records.length) {
    return {
      kind: 'not_found',
      pendingReason: 'no_durable_restore_records',
      pendingDetails:
        'no passkey sealed session record contains Ed25519 restore metadata for this account',
    };
  }
  const selection = selectSingleEd25519WorkerMaterialRestoreRecord(records);
  switch (selection.kind) {
    case 'not_found':
      return {
        kind: 'not_found',
        pendingReason: 'pending_material',
        pendingDetails: 'failed to select Ed25519 session record from durable metadata',
      };
    case 'duplicate_records':
      return {
        kind: 'not_found',
        pendingReason: 'duplicate_worker_material_records',
        pendingDetails: duplicateExactEd25519RestoreDetails(selection),
      };
    case 'exact_match':
      break;
    default:
      return assertNeverExactEd25519WorkerMaterialRestoreRecordSelection(selection);
  }
  const hydrated = upsertEd25519SessionRecordFromExactSealedWorkerMaterial({
    sealed: selection.record,
    source: args.source,
  });
  if (!hydrated) {
    return {
      kind: 'not_found',
      pendingReason: 'pending_material',
      pendingDetails: 'failed to hydrate Ed25519 session record from durable metadata',
    };
  }
  return {
    kind: 'hydrated',
    record: hydrated,
  };
}

function upsertEd25519SessionRecordFromReusableSealedWorkerMaterial(args: {
  current: ThresholdEd25519SessionRecord;
  sealed: CurrentEd25519RestoreSealedSessionRecord;
}): ThresholdEd25519SessionRecord | null {
  const restore = args.sealed.ed25519Restore;
  const signingRoot = ed25519RecordSigningRoot(args.current);
  return upsertStoredThresholdEd25519SessionRecord({
    walletId: args.current.walletId,
    nearAccountId: args.current.nearAccountId,
    nearEd25519SigningKeyId: args.current.nearEd25519SigningKeyId,
    rpId: args.current.rpId,
    ...(args.current.passkeyCredentialIdB64u
      ? { passkeyCredentialIdB64u: args.current.passkeyCredentialIdB64u }
      : {}),
    relayerUrl: args.current.relayerUrl,
    relayerKeyId: args.current.relayerKeyId,
    participantIds: args.current.participantIds,
    signingRootId: signingRoot.signingRootId,
    signingRootVersion: signingRoot.signingRootVersion,
    ...(args.current.runtimePolicyScope
      ? { runtimePolicyScope: args.current.runtimePolicyScope }
      : {}),
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
    routerAbNormalSigning: args.current.routerAbNormalSigning,
    thresholdSessionKind: 'jwt',
    thresholdSessionId: args.current.thresholdSessionId,
    ...(args.current.signingGrantId ? { signingGrantId: args.current.signingGrantId } : {}),
    walletSessionJwt: args.current.walletSessionJwt,
    expiresAtMs: args.current.expiresAtMs,
    remainingUses: args.current.remainingUses,
    updatedAtMs: Date.now(),
    source: args.current.source,
  });
}

export async function resolveReusableEd25519WorkerMaterialForLoginSession(
  record: ThresholdEd25519LoginMaterialPendingSessionRecord,
): Promise<Ed25519ReusableLoginMaterialResolution> {
  const selector = buildEd25519ReusableWorkerMaterialSelector(record);
  const records = await listPasskeyEd25519RestoreSealedSessionsForWallet(selector.walletId);
  const matchingRecords = listReusableEd25519WorkerMaterialSealedRecords({
    selector,
    records,
  });
  const selection = selectSingleEd25519WorkerMaterialRestoreRecord(matchingRecords);
  switch (selection.kind) {
    case 'exact_match':
      try {
        return {
          kind: 'ready_from_reusable_durable_material',
          authority: {
            thresholdSessionId: record.thresholdSessionId,
            signingGrantId: record.signingGrantId,
            walletSessionJwt: record.walletSessionJwt,
            expiresAtMs: record.expiresAtMs,
            remainingUses: record.remainingUses,
          },
          material: ed25519ReusableSealedWorkerMaterialFromRecord(selection.record),
        };
      } catch (error) {
        return {
          kind: 'pending_material',
          record,
          reason: 'pending_material',
          details:
            error instanceof Error
              ? error.message
              : 'failed to resolve reusable Ed25519 worker material',
        };
      }
    case 'duplicate_records':
      return {
        kind: 'pending_material',
        record,
        reason: 'duplicate_worker_material_records',
        details: duplicateExactEd25519RestoreDetails(selection),
      };
    case 'not_found': {
      return {
        kind: 'pending_material',
        record,
        reason: records.length
          ? 'durable_restore_identity_mismatch'
          : 'no_durable_restore_records',
        details: records.length
          ? reusableEd25519WorkerMaterialMismatchDetails({
              selector,
              records,
            })
          : 'no passkey sealed session record contains reusable Ed25519 worker material',
      };
    }
    default:
      return assertNeverExactEd25519WorkerMaterialRestoreRecordSelection(selection);
  }
}

export function persistEd25519LoginSessionFromReusableWorkerMaterial(args: {
  record: ThresholdEd25519LoginMaterialPendingSessionRecord;
  authority: Ed25519SessionAuthority;
  material: Ed25519ReusableSealedWorkerMaterial;
}): ThresholdEd25519RestoreAvailableSessionRecord | null {
  const signingRoot = ed25519RecordSigningRoot(args.record);
  const upserted = upsertStoredThresholdEd25519SessionRecord({
    walletId: args.record.walletId,
    nearAccountId: args.record.nearAccountId,
    nearEd25519SigningKeyId: args.record.nearEd25519SigningKeyId,
    rpId: args.record.rpId,
    passkeyCredentialIdB64u: args.record.passkeyCredentialIdB64u,
    relayerUrl: args.record.relayerUrl,
    relayerKeyId: args.record.relayerKeyId,
    participantIds: args.record.participantIds,
    signingRootId: signingRoot.signingRootId,
    signingRootVersion: signingRoot.signingRootVersion,
    runtimePolicyScope: args.record.runtimePolicyScope,
    clientVerifyingShareB64u: args.material.identity.clientVerifyingShareB64u,
    ed25519WorkerMaterialBindingDigest: args.material.identity.bindingDigest,
    sealedWorkerMaterialRef: args.material.sealed.sealedRef,
    ...(args.material.sealed.kind === 'inline_sealed_blob'
      ? { sealedWorkerMaterialB64u: args.material.sealed.sealedBlobB64u }
      : {}),
    materialFormatVersion: args.material.sealed.materialFormatVersion,
    materialKeyId: args.material.identity.materialKeyId,
    materialCreatedAtMs: args.material.sealed.materialCreatedAtMs,
    signerSlot: args.material.sealed.signerSlot,
    routerAbNormalSigning: args.record.routerAbNormalSigning,
    thresholdSessionKind: 'jwt',
    thresholdSessionId: args.authority.thresholdSessionId,
    signingGrantId: args.authority.signingGrantId,
    walletSessionJwt: args.authority.walletSessionJwt,
    expiresAtMs: args.authority.expiresAtMs,
    remainingUses: args.authority.remainingUses,
    updatedAtMs: Date.now(),
    source: args.record.source,
  });
  if (upserted?.materialState !== 'restore_available') {
    return null;
  }
  return upserted;
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
  const matchingRecords = args.records.filter((sealedRecord) =>
    sealedEd25519RestoreMatchesCurrentRecord({ current: args.current, sealed: sealedRecord }),
  );
  const selection = selectSingleEd25519WorkerMaterialRestoreRecord(matchingRecords);
  switch (selection.kind) {
    case 'exact_match':
      return {
        kind: 'matched',
        record: selection.record,
      };
    case 'duplicate_records':
      return {
        kind: 'not_found',
        pendingReason: 'duplicate_worker_material_records',
        pendingDetails: duplicateExactEd25519RestoreDetails(selection),
      };
    case 'not_found':
      break;
    default:
      return assertNeverExactEd25519WorkerMaterialRestoreRecordSelection(selection);
  }
  const mismatchReasons = [
    ...new Set(
      args.records.flatMap((sealedRecord) =>
        ed25519RestoreIdentityMismatchReasons({ current: args.current, sealed: sealedRecord }),
      ),
    ),
  ].sort();
  return {
    kind: 'not_found',
    pendingReason: 'durable_restore_identity_mismatch',
    pendingDetails: `candidate records=${args.records.length}; mismatch fields=${mismatchReasons.join(',') || 'unknown'}`,
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
    hasSealKeyVersion: Boolean(normalizedRestoreString(args.sealed.keyVersion)),
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
    walletId: args.current.walletId,
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

export async function hydrateCurrentEd25519SessionFromDurableSealedWorkerMaterial(
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
  const records = await listPasskeyEd25519RestoreSealedSessionsForWallet(record.walletId);
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
  const hydrated = upsertEd25519SessionRecordFromReusableSealedWorkerMaterial({
    current: record,
    sealed: selected,
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
      const thresholdKeyMaterial = await requireThresholdEd25519KeyMaterialForWorkerMaterialRestore(
        {
          nearAccountId,
          signerSlot,
        },
      );
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

function assertNeverThresholdWarmSessionPolicyDraftInput(value: never): never {
  throw new Error(`Unexpected threshold warm-session policy input: ${String(value)}`);
}

function parseSharedSigningGrantId(value: unknown): string {
  const signingGrantId = String(value || '').trim();
  if (!signingGrantId) {
    throw new Error('Threshold warm-session shared signing grant is missing signingGrantId');
  }
  return signingGrantId;
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
  input: ThresholdWarmSessionPolicyDraftInput,
): ThresholdWarmSessionPolicyDraft | null {
  const defaults = resolveThresholdWarmSessionDefaults(context);
  if (!defaults) return null;
  const sessionId = String(input.sessionId || '').trim() || generateThresholdSessionId();
  const budget =
    input.kind === 'generated_signing_grant'
      ? {
          signingGrantId: generateSigningGrantId(),
          ttlMs: defaults.ttlMs,
          remainingUses: defaults.remainingUses,
        }
      : input.kind === 'shared_signing_grant'
        ? {
            signingGrantId: parseSharedSigningGrantId(input.signingGrantId),
            ttlMs: parsePositiveInt(input.ttlMs),
            remainingUses: parsePositiveInt(input.remainingUses),
          }
        : assertNeverThresholdWarmSessionPolicyDraftInput(input);
  if (input.kind === 'shared_signing_grant' && (!budget.ttlMs || !budget.remainingUses)) {
    throw new Error('Threshold warm-session shared signing grant has invalid policy limits');
  }
  const participantIds = normalizeThresholdEd25519ParticipantIds(input.participantIds);
  const routerAbNormalSigning = createRouterAbNormalSigningPolicy(context.configs);
  return {
    sessionId,
    signingGrantId: budget.signingGrantId,
    ttlMs: budget.ttlMs,
    remainingUses: budget.remainingUses,
    ...(participantIds ? { participantIds } : {}),
    routerAbNormalSigning,
  };
}

export function buildThresholdWarmSessionRequestEnvelope(args: {
  authorityScope: Ed25519AuthorityScope;
  requestedPolicy: ThresholdWarmSessionPolicyDraft;
  walletId?: string;
  nearAccountId?: string;
  nearEd25519SigningKeyId?: string;
  relayerKeyId?: string;
}): ThresholdWarmSessionRequestEnvelope {
  const thresholdSessionId = String(args.requestedPolicy.sessionId || '').trim();
  const signingGrantId = String(args.requestedPolicy.signingGrantId || '').trim();
  if (!thresholdSessionId || !signingGrantId) {
    throw new Error(
      'Threshold warm-session request is missing thresholdSessionId or signingGrantId',
    );
  }
  return {
    session_policy: {
      version: THRESHOLD_SESSION_POLICY_VERSION,
      ...(args.walletId ? { walletId: String(args.walletId || '').trim() } : {}),
      ...(args.nearAccountId ? { nearAccountId: String(args.nearAccountId || '').trim() } : {}),
      ...(args.nearEd25519SigningKeyId
        ? { nearEd25519SigningKeyId: String(args.nearEd25519SigningKeyId || '').trim() }
        : {}),
      authorityScope: args.authorityScope,
      ...(args.relayerKeyId ? { relayerKeyId: String(args.relayerKeyId || '').trim() } : {}),
      thresholdSessionId,
      signingGrantId,
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
  nearEd25519SigningKeyId: NearEd25519SigningKeyId;
  participantIds: number[];
  onProgress?: (message: string) => void;
}): Promise<ThresholdEd25519RegistrationHssClientMaterial> {
  const bindingFacts = thresholdEd25519HssBindingFactsFromRuntimePolicyScope({
    runtimePolicyScope: args.runtimePolicyScope,
    nearEd25519SigningKeyId: args.nearEd25519SigningKeyId,
  });
  const prepared =
    await args.context.signingEngine.prepareThresholdEd25519HssClientCeremonyFromCredential({
      credential: args.credential,
      hssBindingFacts: bindingFacts,
      participantIds: args.participantIds,
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
    hssContext: prepared.hssContext,
    bindingFacts,
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
  nearEd25519SigningKeyId: NearEd25519SigningKeyId;
  participantIds: number[];
  onProgress?: (message: string) => void;
}): Promise<ThresholdEd25519RegistrationHssClientMaterial> {
  const prfFirstB64u = String(args.prfFirstB64u || '').trim();
  if (!prfFirstB64u) {
    throw new Error('Missing PRF.first material for threshold Ed25519 HSS registration');
  }
  const bindingFacts = thresholdEd25519HssBindingFactsFromRuntimePolicyScope({
    runtimePolicyScope: args.runtimePolicyScope,
    nearEd25519SigningKeyId: args.nearEd25519SigningKeyId,
  });
  const prepared =
    await args.context.signingEngine.prepareThresholdEd25519HssClientCeremonyFromPrfFirst({
      prfFirstB64u,
      hssBindingFacts: bindingFacts,
      participantIds: args.participantIds,
      onProgress: args.onProgress,
    });
  if (!prepared.ok) {
    throw new Error(prepared.message || 'Failed to prepare threshold Ed25519 HSS registration');
  }

  return {
    hssContext: prepared.hssContext,
    bindingFacts,
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
  clientOutputMaskHandle: string;
}> {
  const maskHandle =
    await args.context.signingEngine.prepareThresholdEd25519HssClientOutputMaskHandle({
      clientRecoverableSecretB64u: args.material.prfFirstB64u,
      context: {
        applicationBindingDigestB64u: args.material.hssContext.applicationBindingDigestB64u,
        participantIds: args.material.hssContext.participantIds,
        contextBindingB64u: args.preparedSession.contextBindingB64u,
        operation: 'registration',
        relayerKeyId: `registration:${args.ceremonyHandle}`,
      },
      expiresAtMs: Date.now() + 60_000,
    });
  if (maskHandle.contextBindingB64u !== args.preparedSession.contextBindingB64u) {
    throw new Error('Threshold Ed25519 registration HSS output-mask handle context mismatch');
  }

  const clientRequest = await args.context.signingEngine.prepareThresholdEd25519HssClientRequest({
    evaluatorDriverStateB64u: args.preparedSession.evaluatorDriverStateB64u,
    clientOtOfferMessageB64u: args.clientOtOfferMessageB64u,
    clientInputs: args.material.clientInputs,
  });

  return { clientRequest, clientOutputMaskHandle: maskHandle.clientOutputMaskHandle };
}

export async function buildThresholdEd25519RegistrationHssClientOwnedArtifact(args: {
  context: ThresholdWarmSessionContext;
  preparedSession: ThresholdEd25519HssPreparedSessionEnvelope;
  clientRequest: ThresholdEd25519HssClientRequestEnvelope;
  serverInputDelivery: ThresholdEd25519HssServerInputDeliveryEnvelope;
  clientOutputMaskHandle: string;
}): Promise<ThresholdEd25519HssStagedEvaluatorArtifactEnvelope> {
  return await args.context.signingEngine.buildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactFromMaskHandle(
    {
      preparedSession: args.preparedSession,
      clientRequest: args.clientRequest,
      serverInputDelivery: args.serverInputDelivery,
      clientOutputMaskHandle: args.clientOutputMaskHandle,
      expectedContextBindingB64u: args.preparedSession.contextBindingB64u,
    },
  );
}

export function requireThresholdEd25519WarmSessionKeyVersion(
  raw: unknown,
  errorContext: string,
): {
  ed25519HssKeyVersion: Ed25519HssKeyVersion;
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
  return { ed25519HssKeyVersion: parseEd25519HssKeyVersion(keyVersion) };
}

function assertThresholdEd25519WarmSessionIdentity(args: {
  session: NonNullable<WalletRegistrationThresholdEd25519Response['session']>;
  expectedIdentity: ExpectedThresholdEd25519SessionIdentity;
}): void {
  const walletId = String(args.session.walletId || '').trim();
  const nearAccountId = String(args.session.nearAccountId || '').trim();
  const nearEd25519SigningKeyId = String(args.session.nearEd25519SigningKeyId || '').trim();
  if (walletId !== args.expectedIdentity.walletId) {
    throw new Error('threshold-ed25519 warm session walletId mismatch');
  }
  if (nearAccountId !== args.expectedIdentity.nearAccountId) {
    throw new Error('threshold-ed25519 warm session nearAccountId mismatch');
  }
  if (nearEd25519SigningKeyId !== args.expectedIdentity.nearEd25519SigningKeyId) {
    throw new Error('threshold-ed25519 warm session nearEd25519SigningKeyId mismatch');
  }
}

export function completeRegisteredThresholdEd25519Registration(args: {
  thresholdEd25519: WalletRegistrationThresholdEd25519Response | undefined;
  expectedSessionPolicy: ThresholdWarmSessionRequestEnvelope['session_policy'];
  expectedIdentity: ExpectedThresholdEd25519SessionIdentity;
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
    !session ||
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
  assertThresholdEd25519WarmSessionIdentity({
    session,
    expectedIdentity: args.expectedIdentity,
  });

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

async function validateEmailOtpRegisteredThresholdEd25519WarmSessionMaterial(args: {
  nearEd25519SigningKeyId: NearEd25519SigningKeyId;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  material: ThresholdEd25519RegistrationHssClientMaterial;
  prfFirstB64u: string;
}): Promise<void> {
  const material = args.material;
  const expectedBindingFacts = thresholdEd25519HssBindingFactsFromRuntimePolicyScope({
    runtimePolicyScope: args.runtimePolicyScope,
    nearEd25519SigningKeyId: args.nearEd25519SigningKeyId,
  });
  if (
    material.bindingFacts.nearEd25519SigningKeyId !==
      expectedBindingFacts.nearEd25519SigningKeyId ||
    material.bindingFacts.signingRootId !== expectedBindingFacts.signingRootId ||
    material.bindingFacts.signingRootVersion !== expectedBindingFacts.signingRootVersion
  ) {
    throw new Error('Email OTP Ed25519 registration HSS SDK binding facts mismatch');
  }
  const expectedDigest =
    await computeSdkEd25519HssApplicationBindingDigestB64u(expectedBindingFacts);
  if (material.hssContext.applicationBindingDigestB64u !== expectedDigest) {
    throw new Error('Email OTP Ed25519 registration HSS digest binding mismatch');
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
    await validateEmailOtpRegisteredThresholdEd25519WarmSessionMaterial({
      nearEd25519SigningKeyId: args.nearEd25519SigningKeyId,
      runtimePolicyScope,
      material: registrationHssClientMaterial,
      prfFirstB64u,
    });
    const warmSessionArgs: PersistWarmSessionEd25519JwtEmailOtpCapabilityArgs = {
      kind: 'jwt_email_otp',
      walletId: args.walletId,
      nearAccountId: String(args.nearAccountId),
      nearEd25519SigningKeyId: args.nearEd25519SigningKeyId,
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
      routerAbNormalSigning,
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
    persistWarmSessionEd25519Capability(warmSessionArgs);
    await persistEmailOtpRegisteredThresholdEd25519WorkerMaterial({
      signingEngine: args.signingEngine,
      workerCtx: args.workerCtx,
      nearAccountId: args.nearAccountId,
      nearEd25519SigningKeyId: args.nearEd25519SigningKeyId,
      signerSlot: args.signerSlot,
      rpId: args.rpId,
      relayerUrl: args.relayerUrl,
      relayerKeyId: args.completedRegistration.registered.relayerKeyId,
      sessionId,
      signingGrantId,
      jwt,
      expiresAtMs,
      participantIds,
      runtimePolicyScope,
      routerAbNormalSigning,
      recoveryCodeSecret32B64u: prfFirstB64u,
      emailOtpAuthContext: args.auth.emailOtpAuthContext,
      registrationHssClientMaterial,
    });
  } else {
    const warmSessionArgs: PersistWarmSessionEd25519JwtPasskeyCapabilityArgs = {
      kind: 'jwt_passkey',
      walletId: args.walletId,
      nearAccountId: String(args.nearAccountId),
      nearEd25519SigningKeyId: args.nearEd25519SigningKeyId,
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
      passkeyCredentialIdB64u: args.auth.credentialIdB64u,
      signerSlot: args.signerSlot,
      routerAbNormalSigning,
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
    persistWarmSessionEd25519Capability(warmSessionArgs);
  }

  await args.signingEngine.hydrateSigningSession({
    sessionId,
    prfFirstB64u,
    expiresAtMs,
    remainingUses,
    transport: {
      curve: 'ed25519',
      walletId: args.walletId,
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
  walletId: string;
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
      walletId: args.walletId,
      relayerUrl: args.relayerUrl,
      signingGrantId: args.signingGrantId,
      walletSessionJwt: args.walletSessionJwt,
    },
  });
}

async function persistEmailOtpRegisteredThresholdEd25519WorkerMaterial(args: {
  signingEngine: Pick<
    ThresholdEd25519HssCeremonySurface,
    'runThresholdEd25519HssCeremonyWithMaterialHandle'
  >;
  workerCtx: WorkerOperationContext;
  nearAccountId: AccountId;
  nearEd25519SigningKeyId: NearEd25519SigningKeyId;
  signerSlot: number;
  rpId: string;
  relayerUrl: string;
  relayerKeyId: string;
  sessionId: string;
  signingGrantId: string;
  jwt: string;
  expiresAtMs: number;
  participantIds: number[];
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  routerAbNormalSigning: RouterAbEd25519NormalSigningState;
  recoveryCodeSecret32B64u: string;
  emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
  registrationHssClientMaterial: ThresholdEd25519RegistrationHssClientMaterial;
}): Promise<void> {
  const signingRootScope = signingRootScopeFromRuntimePolicyScope(args.runtimePolicyScope);
  const signingRootId = String(signingRootScope.signingRootId || '').trim();
  const signingRootVersion = String(signingRootScope.signingRootVersion || '').trim();
  const signingWorkerId = String(args.routerAbNormalSigning.signingWorkerId || '').trim();
  if (!signingRootId || !signingRootVersion || !signingWorkerId) {
    throw new Error('Email OTP Ed25519 registration worker material missing Router A/B binding');
  }
  const materialCreatedAtMs = Date.now();
  const materialBinding = {
    thresholdSessionId: args.sessionId,
    signingGrantId: args.signingGrantId,
    signingRootId,
    signingRootVersion,
    expiresAtMs: args.expiresAtMs,
    nearAccountId: String(args.nearAccountId),
    signerSlot: args.signerSlot,
    relayerKeyId: args.relayerKeyId,
    participantIds: args.participantIds,
    createdAtMs: materialCreatedAtMs,
    signingWorkerId,
  };
  const bindingInput: ThresholdEd25519WorkerMaterialBindingInputWithoutVerifier = {
    nearAccountId: materialBinding.nearAccountId,
    signerSlot: materialBinding.signerSlot,
    signingRootId: materialBinding.signingRootId,
    signingRootVersion: materialBinding.signingRootVersion,
    relayerKeyId: materialBinding.relayerKeyId,
    participantIds: materialBinding.participantIds,
    createdAtMs: materialBinding.createdAtMs,
  };
  const providerUserId = String(
    emailOtpAuthContextProviderUserId(args.emailOtpAuthContext),
  ).trim();
  if (!providerUserId) {
    throw new Error('Email OTP Ed25519 registration worker material requires provider user id');
  }
  const recoveryCodeBindingDigest = await recoveryCodeBindingDigestForEmailOtpMaterial({
    providerUserId,
    rpId: args.rpId,
    nearAccountId: String(args.nearAccountId),
  });
  const preparedSealAuthorization = await prepareRecoveryCodeSealAuthorizationForEmailOtp({
    bindingInput,
    providerUserId,
    recoveryCodeBindingDigest,
    recoveryCodeSecret32B64u: args.recoveryCodeSecret32B64u,
    workerCtx: args.workerCtx,
  });
  const completed = await args.signingEngine.runThresholdEd25519HssCeremonyWithMaterialHandle({
    relayerUrl: args.relayerUrl,
    walletSessionJwt: args.jwt,
    relayerKeyId: args.relayerKeyId,
    operation: 'warm_session_reconstruction',
    context: args.registrationHssClientMaterial.hssContext,
    clientInputs: args.registrationHssClientMaterial.clientInputs,
    outputProjection: {
      kind: 'client-masked-projection',
      clientRecoverableSecretB64u: args.recoveryCodeSecret32B64u,
    },
    materialBinding,
    preparedSealAuthorization,
  });
  if (!completed.ok) {
    throw new Error(
      completed.message || 'Email OTP Ed25519 registration worker material persistence failed',
    );
  }
  const signingMaterial = completed.signingMaterial;
  const clientVerifyingShareB64u = String(signingMaterial.clientVerifyingShareB64u || '').trim();
  if (!clientVerifyingShareB64u) {
    throw new Error('Email OTP Ed25519 registration worker material missing verifying share');
  }
  const persisted = persistStoredThresholdEd25519SessionMaterialHandle({
    thresholdSessionId: args.sessionId,
    clientVerifyingShareB64u,
    ed25519WorkerMaterialHandle: signingMaterial.materialHandle,
    ed25519WorkerMaterialBindingDigest: signingMaterial.materialBindingDigest,
    sealedWorkerMaterialRef: signingMaterial.sealedWorkerMaterialRef,
    sealedWorkerMaterialB64u: signingMaterial.sealedWorkerMaterialB64u,
    materialFormatVersion: signingMaterial.materialFormatVersion,
    materialKeyId: signingMaterial.materialKeyId,
    materialCreatedAtMs,
    signerSlot: signingMaterial.signerSlot,
  });
  if (!persisted) {
    throw new Error('Email OTP Ed25519 registration worker material record was not persisted');
  }
  markRouterAbEd25519WorkerMaterialRuntimeValidated(
    getStoredThresholdEd25519SessionRecordByThresholdSessionId(args.sessionId),
  );
}

export async function reconstructThresholdEd25519SigningMaterialFromWarmSession(args: {
  context: ThresholdWarmSessionContext;
  credential: WebAuthnRegistrationCredential | WebAuthnAuthenticationCredential;
  walletId: string;
  nearAccountId: AccountId;
  nearEd25519SigningKeyId: NearEd25519SigningKeyId;
  rpId: string;
  relayerUrl: string;
  relayerKeyId: string;
  signerSlot: number;
  session: ThresholdWarmSessionRouterApiResult;
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
  if (!relayerUrl || !relayerKeyId) {
    throw new Error('Threshold Ed25519 warm-session reconstruction is missing Router API metadata');
  }
  const signingGrantId = String(args.session.signingGrantId || '').trim();
  const expiresAtMs = Math.floor(Number(args.session.expiresAtMs));
  const remainingUses = Math.floor(Number(args.session.remainingUses));
  const routerAbNormalSigning = parseRouterAbEd25519NormalSigningState(
    args.session.routerAbNormalSigning,
  );
  if (!routerAbNormalSigning) {
    throw new Error(
      'Threshold Ed25519 warm-session reconstruction is missing Router A/B SigningWorker scope',
    );
  }
  const signingWorkerId = String(routerAbNormalSigning.signingWorkerId || '').trim();
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
  const hssBindingFacts: SdkEd25519HssBindingFacts = {
    nearEd25519SigningKeyId: args.nearEd25519SigningKeyId,
    signingRootId: parseSdkEcdsaHssSigningRootId(signingRootId),
    signingRootVersion: parseSdkEcdsaHssSigningRootVersion(signingRootVersion),
  };
  const prepared =
    await args.context.signingEngine.prepareThresholdEd25519HssClientCeremonyFromCredential({
      credential: args.credential,
      hssBindingFacts,
      participantIds,
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
      context: prepared.hssContext,
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
    walletId: args.walletId,
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
  walletId: string;
  nearAccountId: AccountId;
  nearEd25519SigningKeyId: string;
  relayerUrl: string;
  rpId: string;
  relayerKeyId: string;
  credential: WebAuthnAuthenticationCredential | WebAuthnRegistrationCredential;
  signerSlot: number;
  requestedPolicy: ThresholdWarmSessionPolicyDraft;
  session: ThresholdWarmSessionRouterApiResult;
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
  const passkeyCredentialIdB64u = passkeyCredentialIdB64uFromCredential(args.credential);
  const walletId = String(args.walletId || '').trim();
  const nearEd25519SigningKeyId = String(args.nearEd25519SigningKeyId || '').trim();
  if (!walletId || !nearEd25519SigningKeyId) {
    throw new Error('threshold-ed25519 bootstrap response missing wallet binding fields');
  }
  if (!routerAbNormalSigning) {
    throw new Error('threshold-ed25519 bootstrap response missing Router A/B Ed25519 signing route');
  }

  persistWarmSessionEd25519Capability({
    kind: 'jwt_passkey',
    walletId,
    nearAccountId: String(args.nearAccountId),
    nearEd25519SigningKeyId,
    rpId: String(args.rpId || '').trim(),
    relayerUrl: String(args.relayerUrl || '').trim(),
    relayerKeyId: String(args.relayerKeyId || '').trim(),
    participantIds,
    sessionKind: 'jwt',
    sessionId,
    passkeyCredentialIdB64u,
    signingGrantId,
    expiresAtMs: Math.floor(expiresAtMs),
    remainingUses,
    jwt: walletSessionJwt,
    signerSlot: args.signerSlot,
    ...(signingRootId ? { signingRootId } : {}),
    ...(signingRootVersion ? { signingRootVersion } : {}),
    ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
    routerAbNormalSigning,
    source: 'bootstrap',
  });
  await args.context.signingEngine.hydrateSigningSession({
    sessionId,
    prfFirstB64u,
    expiresAtMs: Math.floor(expiresAtMs),
    remainingUses,
    transport: {
      curve: 'ed25519',
      walletId,
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
