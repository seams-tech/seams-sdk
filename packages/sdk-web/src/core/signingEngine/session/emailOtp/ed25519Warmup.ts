import type { ThresholdEd25519KeyMaterial } from '@/core/accountData/near/nearAccountData.types';
import type { AccountId } from '@/core/types/accountIds';
import type { EmailOtpAuthPolicy, SeamsConfigsReadonly } from '@/core/types/seams';
import type {
  listStoredThresholdEcdsaSessionRecordsForWallet,
  OperationUsableThresholdEd25519SessionRecord,
  ThresholdEcdsaSessionRecord,
  ThresholdEd25519SessionRecord,
} from '@/core/signingEngine/session/persistence/records';
import {
  buildOperationUsableThresholdEd25519SessionRecord,
  listStoredThresholdEd25519SessionLaneRecordsForWallet,
  thresholdEcdsaEmailOtpAuthContext,
} from '@/core/signingEngine/session/persistence/records';
import type { WalletSessionRef } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  toWalletId,
  type WalletId,
  walletSessionRefFromSession,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';
import {
  generateSigningGrantId,
  parseThresholdRuntimePolicyScopeFromJwt,
} from '@/core/signingEngine/threshold/sessionPolicy';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type { EmailOtpWorkerProgressEvent } from '@/core/signingEngine/workerManager/workerTypes';
import { WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION } from '@shared/utils/emailOtpDomain';
import {
  buildEmailOtpAuthContextForWalletAuthMethod,
  emailOtpAuthContextEmailHashHex,
  emailOtpAuthContextProviderUserId,
  type ThresholdEcdsaEmailOtpAuthContext,
} from '../identity/laneIdentity';
import {
  canonicalizeLaneFacts,
  serverIssuedGenerationFromNumber,
  type CanonicalLaneInventoryAdapter,
  type CanonicalTieBreakOrder,
  type ServerIssuedGeneration,
} from '@/core/signingEngine/session/availability/canonicalLaneInventory';
import {
  ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND,
  type RouterAbEd25519NormalSigningState,
} from '@shared/utils/signingSessionSeal';
import type {
  BuildCurrentSealedSessionRecordInput,
  readExactSealedSession,
} from '@/core/signingEngine/session/persistence/sealedSessionStore';
import type { PersistWarmSessionEd25519CapabilityArgs } from '../warmCapabilities/persistence';
import {
  type EmailOtpRoutePlan,
  type EmailOtpSigningSessionAuthLane,
} from '../../stepUpConfirmation/otpPrompt/authLane';
import { appSessionSubjectFromEmailOtpAuthLane } from './appSessionJwtCache';
import {
  assertEmailOtpSigningSessionAuthLane,
  buildEmailOtpSigningSessionRoutePlan,
  routeAuthFromEmailOtpRoutePlan,
  type EmailOtpEcdsaBootstrapRouteAuth,
} from './routePlan';
import {
  selectEmailOtpEcdsaCompanionLaneForEd25519Signing,
  type EmailOtpEcdsaCompanionLaneForEd25519Signing,
  type EmailOtpEcdsaCompanionSelectionResult,
} from './companionSessions';
import {
  EMAIL_OTP_THRESHOLD_ED25519_HSS_KEY_VERSION,
  reconstructEmailOtpEd25519Session,
  type EmailOtpEd25519SessionReconstructionKey,
  type EmailOtpEd25519SessionReconstructionPlan,
  type EmailOtpThresholdEd25519ProvisioningResult,
  type EmailOtpThresholdEd25519ProvisioningTimings,
  type ReconstructEmailOtpEd25519SessionArgs,
} from './provisioning';
import type {
  EmailOtpThresholdEcdsaLoginResult,
  LoginEmailOtpEcdsaCapabilityArgs,
} from './ecdsaLogin';
import { emailOtpEcdsaProviderIdentityFromRecord } from './ecdsaLogin';
import {
  prepareEmailOtpEd25519UnlockMaterialAuthorization,
} from './clientSecretSource';
import { unlockEmailOtpWalletForEd25519Session } from './walletUnlock';
import type { EmailOtpEd25519RecoveryCodeSigningSessionHydration } from './recoveryCodeWarmSessionHydration';
import {
  classifyRouterAbEd25519PersistedSigningRecord,
  type RouterAbEd25519PersistedSigningRecordState,
} from '@/core/signingEngine/session/routerAbSigningWalletSession';
import type { NearEd25519EmailOtpRecoveryCodeUnsealAuthorization } from '@/core/signingEngine/interfaces/near';
import { requireOrRestoreRouterAbEd25519RecordSigningMaterial } from '@/core/signingEngine/session/warmCapabilities/ed25519SigningMaterialReadiness';
import {
  buildNearEd25519SignerBinding,
  nearAccountBindingFromRaw,
} from '@shared/utils/walletCapabilityBindings';
import type { ThresholdEd25519ParticipantV1 } from '@shared/threshold/participants';
import type {
  EmailOtpEd25519CommittedSessionRecord,
  RecordBackedEd25519CommittedLane,
} from './ed25519CommittedLane';
import type { EmailOtpEd25519SigningSessionAuthority } from './ed25519SigningSessionAuthority';
import { walletAuthAuthoritiesMatch } from '@shared/utils/walletAuthAuthority';

export type LoginEmailOtpEd25519CapabilityArgs = {
  walletSession: WalletSessionRef;
  emailOtpAuthPolicy?: EmailOtpAuthPolicy;
  relayUrl?: string;
  challengeId?: string;
  otpCode: string;
  shamirPrimeB64u?: string;
  appSessionJwt?: never;
  routeAuth?: never;
  sessionKind?: never;
  routePlan: EmailOtpRoutePlan;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  ttlMs?: number;
  remainingUses?: number;
  emailOtpAuthorityEmail?: string;
  emailHashHex: string;
  ed25519SessionReconstruction: Extract<
    EmailOtpEd25519SessionReconstructionPlan,
    { kind: 'reconstruct' }
  >;
  onProgress?: (progress: EmailOtpWorkerProgressEvent) => void;
};

export type EmailOtpThresholdEd25519LoginTimingBucket =
  | 'emailOtpProofVerificationMs'
  | 'ed25519MaterialRestoreMs'
  | 'warmCapabilityPersistenceMs';

export type EmailOtpThresholdEd25519LoginTimings = Record<
  EmailOtpThresholdEd25519LoginTimingBucket,
  number
>;

export type EmailOtpThresholdEd25519LoginResult =
  EmailOtpThresholdEd25519ProvisioningResult & {
    timings: EmailOtpThresholdEd25519LoginTimings;
  };

function nowMs(): number {
  return typeof performance !== 'undefined' && typeof performance.now === 'function'
    ? performance.now()
    : Date.now();
}

function createEmailOtpThresholdEd25519LoginTimings(): EmailOtpThresholdEd25519LoginTimings {
  return {
    emailOtpProofVerificationMs: 0,
    ed25519MaterialRestoreMs: 0,
    warmCapabilityPersistenceMs: 0,
  };
}

function addEmailOtpThresholdEd25519LoginTiming(
  timings: EmailOtpThresholdEd25519LoginTimings,
  bucket: EmailOtpThresholdEd25519LoginTimingBucket,
  startedAtMs: number,
): void {
  timings[bucket] += Math.max(0, Math.round(nowMs() - startedAtMs));
}

function mergeEmailOtpThresholdEd25519ProvisioningTimingsIntoLoginTimings(
  target: EmailOtpThresholdEd25519LoginTimings,
  source: EmailOtpThresholdEd25519ProvisioningTimings,
): void {
  target.warmCapabilityPersistenceMs += source.warmCapabilityPersistenceMs;
}

export type Ed25519SigningSessionRecord = EmailOtpEd25519CommittedSessionRecord;

export type Ed25519SigningLane = RecordBackedEd25519CommittedLane<Ed25519SigningSessionRecord>;

export function buildEd25519SigningLane(args: {
  record: ThresholdEd25519SessionRecord;
  authority: EmailOtpEd25519SigningSessionAuthority;
}): Ed25519SigningLane {
  if (args.record.source !== 'email_otp') {
    throw new Error('Email OTP Ed25519 signing committed lane requires Email OTP record');
  }
  const emailOtpAuthContext = args.record.emailOtpAuthContext;
  if (!emailOtpAuthContext) {
    throw new Error('Email OTP Ed25519 signing committed lane requires bound Email OTP authority');
  }
  const thresholdSessionId = String(args.record.thresholdSessionId || '').trim();
  const signingGrantId = String(args.record.signingGrantId || '').trim();
  if (!thresholdSessionId || !signingGrantId) {
    throw new Error('Email OTP Ed25519 signing committed lane requires session identity');
  }
  if (!walletAuthAuthoritiesMatch(emailOtpAuthContext.authority, args.authority.authority)) {
    throw new Error('Email OTP Ed25519 signing committed lane authority drifted');
  }
  if (
    args.authority.authLane.thresholdSessionId !== thresholdSessionId ||
    args.authority.authLane.authorizingSigningGrantId !== signingGrantId
  ) {
    throw new Error('Email OTP Ed25519 signing committed lane authority drifted');
  }
  return {
    source: 'record_backed',
    record: {
      ...args.record,
      source: 'email_otp',
      signingGrantId,
      emailOtpAuthContext,
    },
    authority: args.authority.authority,
    authLane: args.authority.authLane,
    walletSessionAuthority: {
      kind: 'wallet_session_authority',
      walletSessionJwt: args.authority.authLane.jwt,
      thresholdSessionId,
      signingGrantId,
    },
  };
}

function assertNeverEmailOtpEcdsaCompanionSelection(selection: never): never {
  throw new Error(
    `[EmailOtpSession] unsupported ECDSA companion selection: ${String(
      (selection as { kind?: unknown })?.kind || '',
    )}`,
  );
}

function requireEmailOtpEcdsaCompanionLaneForEd25519Signing(
  selection: EmailOtpEcdsaCompanionSelectionResult,
): EmailOtpEcdsaCompanionLaneForEd25519Signing {
  switch (selection.kind) {
    case 'ready':
      switch (selection.companion.kind) {
        case 'single_companion_lane':
          return selection.companion.lane;
        case 'chain_distinct_companion_lanes':
          return selection.companion.primaryLane;
      }
      selection.companion satisfies never;
      throw new Error('[EmailOtpSession] unsupported ready ECDSA companion selection');
    case 'duplicate_chain_lanes':
      throw new Error(
        `[EmailOtpSession] Email OTP Ed25519 signing ECDSA bootstrap lane has duplicate chain records: chain=${selection.chainTargetKey}, count=${selection.count}`,
      );
    case 'not_found':
      throw new Error('Email OTP Ed25519 signing requires an exact concrete ECDSA bootstrap lane');
    case 'ambiguous_material':
      throw new Error(
        `[EmailOtpSession] Email OTP Ed25519 signing ECDSA bootstrap lane is ambiguous: count=${selection.count}`,
      );
    case 'conflicting_key_material':
      throw new Error(
        `[EmailOtpSession] Email OTP Ed25519 signing ECDSA bootstrap lane has conflicting key material: field=${selection.field}, count=${selection.count}`,
      );
    case 'display_only_fallback':
      throw new Error(
        'Email OTP Ed25519 signing cannot use display-only ECDSA bootstrap lane fallback',
      );
    default:
      return assertNeverEmailOtpEcdsaCompanionSelection(selection);
  }
}

function emailOtpProviderUserIdForEd25519Login(args: {
  routePlan: EmailOtpRoutePlan;
  walletSession: WalletSessionRef;
}): string {
  const providerUserId = String(
    appSessionSubjectFromEmailOtpAuthLane(args.routePlan.authLane) ||
      args.walletSession.walletSessionUserId ||
      '',
  ).trim();
  if (!providerUserId) {
    throw new Error('Email OTP Ed25519 login requires providerUserId');
  }
  return providerUserId;
}

function routerAbNormalSigningStateFromConfigs(
  configs: SeamsConfigsReadonly,
): RouterAbEd25519NormalSigningState {
  const normalSigning = configs.signing.routerAb.normalSigning;
  switch (normalSigning.mode) {
    case 'enabled':
      return {
        kind: ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND,
        signingWorkerId: normalSigning.signingWorkerId,
      };
    case 'disabled':
      throw new Error(
        '[SigningEngine][email-otp] Router A/B normal signing must be enabled for Ed25519 login',
      );
    default: {
      const exhaustive: never = normalSigning;
      throw new Error(
        `[SigningEngine][email-otp] Unsupported Router A/B normal-signing mode: ${String(
          (exhaustive as { mode?: unknown })?.mode || '',
        )}`,
      );
    }
  }
}

type RestorableEmailOtpEd25519UnlockState = Extract<
  RouterAbEd25519PersistedSigningRecordState,
  { kind: 'runtime_validated' | 'restore_available' }
>;

type EmailOtpEd25519UnlockRecordFact = {
  record: OperationUsableThresholdEd25519SessionRecord;
  persistedState: RestorableEmailOtpEd25519UnlockState;
  groupKey: EmailOtpEd25519UnlockRecordGroupKey;
};

type EmailOtpEd25519UnlockRecordGroupKey = {
  walletId: string;
  providerUserId: string;
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  signerSlot: string;
};

type EmailOtpEd25519UnlockRecordConflict = {
  kind: 'same_generation_distinct_session';
  generation: ServerIssuedGeneration;
  thresholdSessionIds: readonly string[];
};

export type EmailOtpEd25519SealedUnlockActivationResult =
  | {
      kind: 'activated';
      result: EmailOtpThresholdEd25519ProvisioningResult;
    }
  | {
      kind: 'unavailable';
      reason:
        | 'no_exact_record'
        | 'ambiguous_material'
        | 'conflicting_material'
        | 'no_current_lane';
      result?: never;
    };

function positiveNumber(value: unknown): number {
  const parsed = Math.floor(Number(value));
  return Number.isFinite(parsed) && parsed > 0 ? parsed : 0;
}

function nonEmptyString(value: unknown): string {
  return String(value || '').trim();
}

function canonicalTieBreakFromString(left: string, right: string): CanonicalTieBreakOrder {
  const comparison = left.localeCompare(right);
  if (comparison > 0) return 1;
  if (comparison < 0) return -1;
  return 0;
}

function firstCanonicalTieBreakResult(
  results: readonly CanonicalTieBreakOrder[],
): CanonicalTieBreakOrder {
  for (const result of results) {
    if (result !== 0) return result;
  }
  return 0;
}

function emailOtpEd25519UnlockRecordGeneration(
  record: OperationUsableThresholdEd25519SessionRecord,
): ServerIssuedGeneration | null {
  return serverIssuedGenerationFromNumber(
    positiveNumber(record.updatedAtMs) || positiveNumber(record.expiresAtMs),
  );
}

function emailOtpEd25519UnlockRecordGroupKeyString(
  key: EmailOtpEd25519UnlockRecordGroupKey,
): string {
  return [
    key.walletId,
    key.providerUserId,
    key.nearAccountId,
    key.nearEd25519SigningKeyId,
    key.signerSlot,
  ]
    .map(encodeURIComponent)
    .join('|');
}

function emailOtpEd25519UnlockRecordGroupKey(
  fact: EmailOtpEd25519UnlockRecordFact,
): EmailOtpEd25519UnlockRecordGroupKey {
  return fact.groupKey;
}

function emailOtpEd25519UnlockRecordConflicts(
  facts: readonly EmailOtpEd25519UnlockRecordFact[],
): readonly EmailOtpEd25519UnlockRecordConflict[] {
  const sessionIdsByGeneration = new Map<ServerIssuedGeneration, Set<string>>();
  for (const fact of facts) {
    const generation = emailOtpEd25519UnlockRecordGeneration(fact.record);
    if (!generation) continue;
    const thresholdSessionId = nonEmptyString(fact.record.thresholdSessionId);
    if (!thresholdSessionId) continue;
    sessionIdsByGeneration.set(
      generation,
      new Set([...(sessionIdsByGeneration.get(generation) || []), thresholdSessionId]),
    );
  }
  const conflicts: EmailOtpEd25519UnlockRecordConflict[] = [];
  for (const [generation, thresholdSessionIds] of sessionIdsByGeneration.entries()) {
    if (thresholdSessionIds.size <= 1) continue;
    conflicts.push({
      kind: 'same_generation_distinct_session',
      generation,
      thresholdSessionIds: [...thresholdSessionIds].sort(),
    });
  }
  return conflicts;
}

function emailOtpEd25519UnlockFactOperationUsable(
  _fact: EmailOtpEd25519UnlockRecordFact,
): boolean {
  return true;
}

function emailOtpEd25519UnlockFactGeneration(
  fact: EmailOtpEd25519UnlockRecordFact,
): ServerIssuedGeneration | null {
  return emailOtpEd25519UnlockRecordGeneration(fact.record);
}

function emailOtpEd25519UnlockFactExactness(): 'exact_target' {
  return 'exact_target';
}

function emailOtpEd25519UnlockMaterialPriority(
  fact: EmailOtpEd25519UnlockRecordFact,
): number {
  switch (fact.persistedState.kind) {
    case 'runtime_validated':
      return 2;
    case 'restore_available':
      return 1;
    default: {
      const exhaustive: never = fact.persistedState;
      return exhaustive;
    }
  }
}

function emailOtpEd25519UnlockStableTieBreakKey(
  fact: EmailOtpEd25519UnlockRecordFact,
): string {
  return [
    fact.record.thresholdSessionId,
    fact.record.signingGrantId,
    fact.persistedState.kind,
  ].join('|');
}

function emailOtpEd25519UnlockFactTieBreak(
  left: EmailOtpEd25519UnlockRecordFact,
  right: EmailOtpEd25519UnlockRecordFact,
): CanonicalTieBreakOrder {
  return firstCanonicalTieBreakResult([
    emailOtpEd25519UnlockMaterialPriority(left) > emailOtpEd25519UnlockMaterialPriority(right)
      ? 1
      : emailOtpEd25519UnlockMaterialPriority(right) >
          emailOtpEd25519UnlockMaterialPriority(left)
        ? -1
        : 0,
    canonicalTieBreakFromString(
      emailOtpEd25519UnlockStableTieBreakKey(left),
      emailOtpEd25519UnlockStableTieBreakKey(right),
    ),
  ]);
}

const emailOtpEd25519UnlockLaneInventoryAdapter: CanonicalLaneInventoryAdapter<
  EmailOtpEd25519UnlockRecordFact,
  EmailOtpEd25519UnlockRecordGroupKey,
  EmailOtpEd25519UnlockRecordConflict
> = {
  groupKey: emailOtpEd25519UnlockRecordGroupKey,
  groupKeyString: emailOtpEd25519UnlockRecordGroupKeyString,
  groupConflicts: emailOtpEd25519UnlockRecordConflicts,
  supersession: {
    isOperationUsable: emailOtpEd25519UnlockFactOperationUsable,
    generation: emailOtpEd25519UnlockFactGeneration,
    exactness: emailOtpEd25519UnlockFactExactness,
    tieBreak: emailOtpEd25519UnlockFactTieBreak,
  },
};

function thresholdEd25519ParticipantFromId(args: {
  id: number;
  relayerKeyId: string;
}): ThresholdEd25519ParticipantV1 {
  return {
    id: args.id,
    role: args.id === 1 ? 'client' : 'relayer',
    ...(args.id === 1 ? { shareDerivation: 'derived_master_secret_v1' as const } : {}),
    ...(args.id !== 1
      ? {
          relayerKeyId: args.relayerKeyId,
          shareDerivation: 'kv_random_v1' as const,
        }
      : {}),
  };
}

function thresholdEd25519ParticipantsFromRecord(
  record: OperationUsableThresholdEd25519SessionRecord,
): ThresholdEd25519ParticipantV1[] {
  const participants: ThresholdEd25519ParticipantV1[] = [];
  for (const participantId of record.participantIds) {
    const id = Math.floor(Number(participantId));
    if (!Number.isSafeInteger(id) || id <= 0) continue;
    participants.push(
      thresholdEd25519ParticipantFromId({
        id,
        relayerKeyId: record.relayerKeyId,
      }),
    );
  }
  return participants;
}

function thresholdEd25519KeyMaterialFromUnlockRecord(
  record: OperationUsableThresholdEd25519SessionRecord,
): ThresholdEd25519KeyMaterial {
  return {
    kind: 'threshold_ed25519_v1',
    nearAccountId: record.nearAccountId,
    signerSlot: record.signerSlot,
    publicKey: record.clientVerifyingShareB64u,
    relayerKeyId: record.relayerKeyId,
    keyVersion: EMAIL_OTP_THRESHOLD_ED25519_HSS_KEY_VERSION,
    participants: thresholdEd25519ParticipantsFromRecord(record),
    timestamp: positiveNumber(record.materialCreatedAtMs) || positiveNumber(record.updatedAtMs),
  };
}

function requireEmailOtpRecoveryCodeUnsealAuthorizationForUnlock(
  authorization: Awaited<ReturnType<typeof prepareEmailOtpEd25519UnlockMaterialAuthorization>>,
): NearEd25519EmailOtpRecoveryCodeUnsealAuthorization {
  const unsealAuthorization = authorization.unsealAuthorization;
  if (
    unsealAuthorization.kind !== 'recovery_code_material_authorization_handle_v1' ||
    unsealAuthorization.purpose !== 'unseal'
  ) {
    throw new Error('Email OTP Ed25519 unlock produced invalid recovery-code unseal auth');
  }
  return {
    ...unsealAuthorization,
    purpose: 'unseal',
  };
}

function emailOtpEd25519UnlockRecordFact(args: {
  record: ThresholdEd25519SessionRecord;
  walletId: WalletId;
  emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
  ed25519Key: EmailOtpEd25519SessionReconstructionKey;
}): EmailOtpEd25519UnlockRecordFact | null {
  if (args.record.source !== 'email_otp') return null;
  if (!args.record.emailOtpAuthContext) return null;
  if (
    !walletAuthAuthoritiesMatch(
      args.record.emailOtpAuthContext.authority,
      args.emailOtpAuthContext.authority,
    )
  ) {
    return null;
  }
  const signer = args.ed25519Key.signer;
  if (String(args.record.walletId) !== String(args.walletId)) return null;
  if (String(args.record.nearAccountId) !== String(signer.account.nearAccountId)) return null;
  if (
    String(args.record.nearEd25519SigningKeyId) !==
    String(signer.nearEd25519SigningKeyId)
  ) {
    return null;
  }
  if (Math.floor(Number(args.record.signerSlot)) !== Math.floor(Number(signer.signerSlot))) {
    return null;
  }
  const operationUsableRecord = buildOperationUsableThresholdEd25519SessionRecord(args.record);
  if (!operationUsableRecord) return null;
  const persistedState = classifyRouterAbEd25519PersistedSigningRecord(operationUsableRecord);
  switch (persistedState.kind) {
    case 'runtime_validated':
    case 'restore_available':
      return {
        record: operationUsableRecord,
        persistedState,
        groupKey: {
          walletId: String(args.walletId),
          providerUserId: emailOtpAuthContextProviderUserId(args.emailOtpAuthContext),
          nearAccountId: String(operationUsableRecord.nearAccountId),
          nearEd25519SigningKeyId: String(operationUsableRecord.nearEd25519SigningKeyId),
          signerSlot: String(operationUsableRecord.signerSlot),
        },
      };
    case 'material_hint_unvalidated':
    case 'auth_ready_material_pending':
    case 'expired':
    case 'exhausted':
    case 'non_signing':
    case 'invalid':
      return null;
    default: {
      const exhaustive: never = persistedState;
      return exhaustive;
    }
  }
}

function selectEmailOtpEd25519UnlockRecord(args: {
  walletId: WalletId;
  emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
  ed25519Key: EmailOtpEd25519SessionReconstructionKey;
}): EmailOtpEd25519SealedUnlockActivationResult | { kind: 'selected'; fact: EmailOtpEd25519UnlockRecordFact } {
  const facts: EmailOtpEd25519UnlockRecordFact[] = [];
  const records = listStoredThresholdEd25519SessionLaneRecordsForWallet(args.walletId);
  for (const record of records) {
    const fact = emailOtpEd25519UnlockRecordFact({
      record,
      walletId: args.walletId,
      emailOtpAuthContext: args.emailOtpAuthContext,
      ed25519Key: args.ed25519Key,
    });
    if (fact) facts.push(fact);
  }
  if (facts.length === 0) return { kind: 'unavailable', reason: 'no_exact_record' };
  const selection = canonicalizeLaneFacts(facts, emailOtpEd25519UnlockLaneInventoryAdapter);
  switch (selection.kind) {
    case 'selected':
      return { kind: 'selected', fact: selection.selectedFact };
    case 'no_current_lane':
      return { kind: 'unavailable', reason: 'no_current_lane' };
    case 'conflicting_key_material':
      return { kind: 'unavailable', reason: 'conflicting_material' };
    case 'ambiguous_material':
      return { kind: 'unavailable', reason: 'ambiguous_material' };
    default: {
      const exhaustive: never = selection;
      return exhaustive;
    }
  }
}

function buildEmailOtpEd25519ProvisioningResultFromRecord(args: {
  record: OperationUsableThresholdEd25519SessionRecord;
}): EmailOtpThresholdEd25519ProvisioningResult {
  return {
    relayerKeyId: args.record.relayerKeyId,
    keyVersion: EMAIL_OTP_THRESHOLD_ED25519_HSS_KEY_VERSION,
    sessionId: args.record.thresholdSessionId,
    record: args.record,
    expiresAtMs: args.record.expiresAtMs,
    remainingUses: args.record.remainingUses,
    participantIds: args.record.participantIds,
    jwt: args.record.walletSessionJwt,
    clientVerifyingShareB64u: args.record.clientVerifyingShareB64u,
    reconstructionTimings: {
      warmCapabilityPersistenceMs: 0,
    },
  };
}

async function hydrateEmailOtpEd25519RecoveryCodeSigningSession(args: {
  hydration: EmailOtpEd25519RecoveryCodeSigningSessionHydration;
  record: OperationUsableThresholdEd25519SessionRecord;
  recoveryCodeSecret32B64u: string;
}): Promise<void> {
  await args.hydration.hydrateRecoveryCodeSigningSession({
    sessionId: args.record.thresholdSessionId,
    recoveryCodeSecret32B64u: args.recoveryCodeSecret32B64u,
    expiresAtMs: args.record.expiresAtMs,
    remainingUses: args.record.remainingUses,
    transport: {
      curve: 'ed25519',
      authMethod: 'email_otp',
      walletId: String(args.record.walletId),
      relayerUrl: args.record.relayerUrl,
      signingGrantId: args.record.signingGrantId,
      walletSessionJwt: args.record.walletSessionJwt,
    },
  });
}

export async function tryActivateEmailOtpEd25519UnlockFromSealedMaterial(args: {
  walletId: WalletId;
  rpId: string;
  recoveryCodeSecret32B64u: string;
  emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
  ed25519Key: EmailOtpEd25519SessionReconstructionKey;
  workerCtx: WorkerOperationContext;
  getThresholdEd25519SessionRecordByThresholdSessionId: (
    thresholdSessionId: string,
  ) => ThresholdEd25519SessionRecord | null;
  recoveryCodeSigningSessionHydration: EmailOtpEd25519RecoveryCodeSigningSessionHydration;
}): Promise<EmailOtpEd25519SealedUnlockActivationResult> {
  const selected = selectEmailOtpEd25519UnlockRecord({
    walletId: args.walletId,
    emailOtpAuthContext: args.emailOtpAuthContext,
    ed25519Key: args.ed25519Key,
  });
  if (selected.kind !== 'selected') return selected;
  const record = selected.fact.record;
  const providerUserId = emailOtpAuthContextProviderUserId(args.emailOtpAuthContext);
  if (!providerUserId) return { kind: 'unavailable', reason: 'no_exact_record' };
  const unsealAuthorization = await prepareEmailOtpEd25519UnlockMaterialAuthorization({
    materialBindingDigest: selected.fact.persistedState.restorableMaterial.identity.bindingDigest,
    providerUserId,
    rpId: args.rpId,
    nearAccountId: String(record.nearAccountId),
    recoveryCodeSecret32B64u: args.recoveryCodeSecret32B64u,
    expiresAtMs: Math.min(record.expiresAtMs, Date.now() + 60_000),
    workerCtx: args.workerCtx,
  });
  await requireOrRestoreRouterAbEd25519RecordSigningMaterial({
    ctx: args.workerCtx,
    record,
    thresholdSessionId: record.thresholdSessionId,
    operation: 'wallet_unlock',
    nearAccountId: String(record.nearAccountId),
    thresholdKeyMaterial: thresholdEd25519KeyMaterialFromUnlockRecord(record),
    restoreAuthorization: {
      kind: 'unseal_authorization_available',
      unsealAuthorization: requireEmailOtpRecoveryCodeUnsealAuthorizationForUnlock(
        unsealAuthorization,
      ),
    },
  });
  const restoredRecord = args.getThresholdEd25519SessionRecordByThresholdSessionId(
    record.thresholdSessionId,
  );
  if (!restoredRecord) {
    throw new Error('Email OTP Ed25519 sealed unlock restore lost the selected session record');
  }
  const operationUsableRecord =
    buildOperationUsableThresholdEd25519SessionRecord(restoredRecord);
  if (!operationUsableRecord) {
    throw new Error('Email OTP Ed25519 sealed unlock restore produced unusable current record');
  }
  await hydrateEmailOtpEd25519RecoveryCodeSigningSession({
    hydration: args.recoveryCodeSigningSessionHydration,
    record: operationUsableRecord,
    recoveryCodeSecret32B64u: args.recoveryCodeSecret32B64u,
  });
  return {
    kind: 'activated',
    result: buildEmailOtpEd25519ProvisioningResultFromRecord({
      record: operationUsableRecord,
    }),
  };
}

function ed25519ReconstructionKeyFromRecord(
  record: ThresholdEd25519SessionRecord,
): EmailOtpEd25519SessionReconstructionKey {
  const nearAccountId = String(record.nearAccountId || '').trim();
  const signerSlot = Number(record.signerSlot);
  if (!Number.isSafeInteger(signerSlot) || signerSlot < 0) {
    throw new Error('Email OTP Ed25519 reconstruction requires signerSlot');
  }
  const account = nearAccountBindingFromRaw({
    kind:
      nearAccountId.length === 64 && /^[0-9a-f]+$/i.test(nearAccountId)
        ? 'implicit_near_account'
        : 'named_near_account',
    wallet: { walletId: record.walletId },
    nearAccountId,
  });
  if (!account.ok) {
    throw new Error(account.error.message);
  }
  return {
    signer: buildNearEd25519SignerBinding({
      account: account.value,
      nearEd25519SigningKeyId: record.nearEd25519SigningKeyId,
      signerSlot,
    }),
    relayerKeyId: record.relayerKeyId,
    keyVersion: EMAIL_OTP_THRESHOLD_ED25519_HSS_KEY_VERSION,
    participantIds: record.participantIds,
  };
}

function emailOtpEcdsaBootstrapRouteAuthFromCompanionLane(
  companionLane: EmailOtpEcdsaCompanionLaneForEd25519Signing,
): EmailOtpEcdsaBootstrapRouteAuth {
  const authLane = companionLane.committedLane.authLane;
  if (authLane.kind !== 'signing_session' || authLane.curve !== 'ecdsa') {
    throw new Error('Email OTP Ed25519 signing requires companion ECDSA session auth');
  }
  return {
    kind: 'threshold_ecdsa_session',
    jwt: authLane.jwt,
    curve: 'ecdsa',
    thresholdSessionId: authLane.thresholdSessionId,
    signingGrantId: authLane.authorizingSigningGrantId,
    chainTarget: authLane.chainTarget,
  };
}

export type EmailOtpEd25519WarmupPorts = {
  configs: SeamsConfigsReadonly;
  getSignerWorkerContext: () => WorkerOperationContext | null | undefined;
  persistEmailOtpThresholdEd25519LocalMetadata: (args: {
    nearAccountId: AccountId;
    rpId: string;
    relayerUrl: string;
    publicKey: string;
    relayerKeyId: string;
    keyVersion: string;
    participantIds: number[];
  }) => Promise<void>;
  persistWarmSessionEd25519Capability: (
    args: PersistWarmSessionEd25519CapabilityArgs,
  ) => unknown | Promise<unknown>;
  recoveryCodeSigningSessionHydration: EmailOtpEd25519RecoveryCodeSigningSessionHydration;
  readExactSealedSession: typeof readExactSealedSession;
  getThresholdEcdsaSessionRecordByThresholdSessionId: (
    thresholdSessionId: string,
  ) => ThresholdEcdsaSessionRecord | null;
  getThresholdEd25519SessionRecordByThresholdSessionId: (
    thresholdSessionId: string,
  ) => ThresholdEd25519SessionRecord | null;
  registerSigningSession: (record: BuildCurrentSealedSessionRecordInput) => Promise<void>;
  requireRelayUrl: () => string;
  requireShamirPrimeB64u: () => string;
  requireRpId: (operation: string) => string;
  resolveAppSessionJwt: (args: {
    walletSession: WalletSessionRef;
    relayUrl: string;
  }) => Promise<string>;
  listThresholdEcdsaSessionRecordsForWallet?: typeof listStoredThresholdEcdsaSessionRecordsForWallet;
  loginWithEcdsaCapabilityInternal: (
    args: LoginEmailOtpEcdsaCapabilityArgs,
  ) => Promise<EmailOtpThresholdEcdsaLoginResult>;
};

function normalizeEmailOtpEd25519SigningRemainingUses(value: unknown): number {
  const remainingUses = Math.floor(Number(value) || 0);
  if (!Number.isFinite(remainingUses) || remainingUses <= 0) {
    throw new Error('[SigningEngine][email-otp][ed25519] signing remainingUses is required');
  }
  return remainingUses;
}

export class EmailOtpEd25519Warmup {
  constructor(private readonly ports: EmailOtpEd25519WarmupPorts) {}

  isPending(_args: { nearAccountId: AccountId }): boolean {
    return false;
  }

  async waitForPending(_args: { nearAccountId: AccountId }): Promise<boolean> {
    return false;
  }

  async reconstructSession(
    args: ReconstructEmailOtpEd25519SessionArgs,
  ): Promise<EmailOtpThresholdEd25519ProvisioningResult> {
    return await reconstructEmailOtpEd25519Session({
      input: args,
      getSignerWorkerContext: this.ports.getSignerWorkerContext,
      persistWarmSessionEd25519Capability: this.ports.persistWarmSessionEd25519Capability,
      recoveryCodeSigningSessionHydration: this.ports.recoveryCodeSigningSessionHydration,
      sessionPersistenceMode: this.ports.configs.signing.sessionPersistenceMode,
      readExactSealedSession: this.ports.readExactSealedSession,
      getThresholdEcdsaSessionRecordByThresholdSessionId:
        this.ports.getThresholdEcdsaSessionRecordByThresholdSessionId,
      getThresholdEd25519SessionRecordByThresholdSessionId:
        this.ports.getThresholdEd25519SessionRecordByThresholdSessionId,
      registerSigningSession: (record) => this.ports.registerSigningSession(record),
    });
  }

  async loginWithEd25519CapabilityInternal(
    args: LoginEmailOtpEd25519CapabilityArgs,
  ): Promise<EmailOtpThresholdEd25519LoginResult> {
    const timings = createEmailOtpThresholdEd25519LoginTimings();
    const relayUrl = String(args.relayUrl || this.ports.requireRelayUrl()).trim();
    const shamirPrimeB64u = String(
      args.shamirPrimeB64u || this.ports.requireShamirPrimeB64u(),
    ).trim();
    const rpId = this.ports.requireRpId('Email OTP Ed25519 login');
    const routePlan = args.routePlan;
    const routeAuth = routeAuthFromEmailOtpRoutePlan(routePlan);
    if (!routeAuth) {
      throw new Error('Email OTP Ed25519 login requires bearer route auth');
    }
    const runtimePolicyScope =
      args.runtimePolicyScope || parseThresholdRuntimePolicyScopeFromJwt(routeAuth.jwt);
    if (!runtimePolicyScope) {
      throw new Error('Email OTP Ed25519 login requires runtimePolicyScope');
    }
    const workerCtx = this.ports.getSignerWorkerContext();
    if (!workerCtx) {
      throw new Error('Email OTP Ed25519 login requires the dedicated emailOtp worker');
    }
    let timingStartedAtMs = nowMs();
    const workerResult = await unlockEmailOtpWalletForEd25519Session({
      walletSession: args.walletSession,
      relayUrl,
      shamirPrimeB64u,
      otpCode: args.otpCode,
      routePlan,
      workerCtx,
      runtimePolicyScope,
      ...(args.challengeId ? { challengeId: args.challengeId } : {}),
      ...(args.onProgress ? { onProgress: args.onProgress } : {}),
    });
    addEmailOtpThresholdEd25519LoginTiming(
      timings,
      'emailOtpProofVerificationMs',
      timingStartedAtMs,
    );
    const recoveryCodeSecret32B64u = String(
      workerResult.recovery.thresholdEd25519RecoveryCodeSecret32B64u || '',
    ).trim();
    if (!recoveryCodeSecret32B64u) {
      throw new Error('Email OTP Ed25519 login did not return recovery-code material');
    }
    const emailOtpAuthContext = buildEmailOtpAuthContextForWalletAuthMethod({
      policy: args.emailOtpAuthPolicy || this.ports.configs.signing.emailOtp.authPolicy,
      walletId: args.walletSession.walletId,
      emailHashHex: args.emailHashHex,
      retention: 'session',
      reason: 'login',
      provider: 'google',
      providerUserId: emailOtpProviderUserIdForEd25519Login({
        routePlan,
        walletSession: args.walletSession,
      }),
    });
    timingStartedAtMs = nowMs();
    const sealedActivation = await tryActivateEmailOtpEd25519UnlockFromSealedMaterial({
      walletId: toWalletId(args.walletSession.walletId),
      rpId,
      recoveryCodeSecret32B64u,
      emailOtpAuthContext,
      ed25519Key: args.ed25519SessionReconstruction.ed25519Key,
      workerCtx,
      getThresholdEd25519SessionRecordByThresholdSessionId:
        this.ports.getThresholdEd25519SessionRecordByThresholdSessionId,
      recoveryCodeSigningSessionHydration: this.ports.recoveryCodeSigningSessionHydration,
    });
    if (sealedActivation.kind === 'activated') {
      addEmailOtpThresholdEd25519LoginTiming(
        timings,
        'ed25519MaterialRestoreMs',
        timingStartedAtMs,
      );
      mergeEmailOtpThresholdEd25519ProvisioningTimingsIntoLoginTimings(
        timings,
        sealedActivation.result.reconstructionTimings,
      );
      return {
        ...sealedActivation.result,
        timings,
      };
    }
    const provisioned = await this.reconstructSession({
      kind: 'session_ed25519_reconstruction',
      relayUrl,
      rpId,
      recoveryCodeSecret32B64u,
      emailOtpAuthContext,
      routeAuth,
      runtimePolicyScope,
      routerAbNormalSigning: routerAbNormalSigningStateFromConfigs(this.ports.configs),
      ed25519Key: args.ed25519SessionReconstruction.ed25519Key,
      signingGrantId: generateSigningGrantId(),
      ...(typeof args.ttlMs === 'number' ? { ttlMs: args.ttlMs } : {}),
      ...(typeof args.remainingUses === 'number' ? { remainingUses: args.remainingUses } : {}),
    });
    addEmailOtpThresholdEd25519LoginTiming(
      timings,
      'ed25519MaterialRestoreMs',
      timingStartedAtMs,
    );
    mergeEmailOtpThresholdEd25519ProvisioningTimingsIntoLoginTimings(
      timings,
      provisioned.reconstructionTimings,
    );
    return {
      ...provisioned,
      timings,
    };
  }

  async loginForSigning(args: {
    nearAccountId: AccountId;
    challengeId: string;
    otpCode: string;
    committedLane: Ed25519SigningLane;
    record?: never;
    routeAuth?: never;
    authLane?: never;
    remainingUses: number;
  }): Promise<{ sessionId: string; record?: ThresholdEd25519SessionRecord }> {
    const nearAccountId = args.nearAccountId;
    const record = args.committedLane.record;
    const relayUrl = String(record.relayerUrl || this.ports.requireRelayUrl()).trim();
    const operation = WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION;
    const walletIdRaw = String(record.walletId || '').trim();
    if (!walletIdRaw) {
      throw new Error('Email OTP Ed25519 signing requires wallet identity');
    }
    const walletId = toWalletId(walletIdRaw);
    const routePlan = buildEmailOtpSigningSessionRoutePlan({
      authLane: assertEmailOtpSigningSessionAuthLane(args.committedLane.authLane),
      operation,
    });
    const defaultRemainingUses = normalizeEmailOtpEd25519SigningRemainingUses(args.remainingUses);
    const signingGrantId = String(record.signingGrantId || '').trim();
    if (!signingGrantId) {
      throw new Error('Email OTP Ed25519 signing requires a signing-grant identity');
    }
    const ecdsaCompanionLane = requireEmailOtpEcdsaCompanionLaneForEd25519Signing(
      selectEmailOtpEcdsaCompanionLaneForEd25519Signing({
        kind: 'current_wallet_authority',
        walletId,
        authority: args.committedLane.authority,
        listThresholdEcdsaSessionRecordsForWallet:
          this.ports.listThresholdEcdsaSessionRecordsForWallet,
      }),
    );
    const ecdsaBootstrapRouteAuth =
      emailOtpEcdsaBootstrapRouteAuthFromCompanionLane(ecdsaCompanionLane);
    const ecdsaCompanionRecord = ecdsaCompanionLane.committedLane.record;
    if (ecdsaCompanionRecord.source !== 'email_otp') {
      throw new Error('Email OTP Ed25519 warm-up requires an Email OTP ECDSA companion record');
    }
    const ecdsaCompanionAuthContext = thresholdEcdsaEmailOtpAuthContext(ecdsaCompanionRecord);
    if (!ecdsaCompanionAuthContext) {
      throw new Error('Email OTP Ed25519 warm-up requires Email OTP ECDSA auth context');
    }
    const ecdsaLogin = await this.ports.loginWithEcdsaCapabilityInternal({
      walletSession: walletSessionRefFromSession({
        walletId,
        walletSessionUserId: walletId,
      }),
      relayUrl,
      chainTarget: ecdsaCompanionRecord.chainTarget,
      emailOtpAuthPolicy: 'session',
      emailOtpAuthReason: 'sign',
      challengeId: args.challengeId,
      otpCode: args.otpCode,
      operation,
      participantIds: ecdsaCompanionRecord.participantIds || record.participantIds,
      routePlan,
      ecdsaBootstrapAuthorization: {
        kind: 'explicit_route_auth',
        routeAuth: ecdsaBootstrapRouteAuth,
      },
      emailHashHex: emailOtpAuthContextEmailHashHex(ecdsaCompanionAuthContext),
      providerIdentity: emailOtpEcdsaProviderIdentityFromRecord(ecdsaCompanionRecord),
      ...(record.runtimePolicyScope ? { runtimePolicyScope: record.runtimePolicyScope } : {}),
      remainingUses: defaultRemainingUses,
      ed25519ReconstructionMode: 'await',
      ed25519SessionReconstruction: record.runtimePolicyScope
        ? {
            kind: 'reconstruct',
            ed25519Key: ed25519ReconstructionKeyFromRecord(record),
            runtimePolicyScope: record.runtimePolicyScope,
          }
        : {
            kind: 'defer',
            reason: 'missing_runtime_policy_scope',
            ed25519Key: ed25519ReconstructionKeyFromRecord(record),
          },
    });
    if (ecdsaLogin.ed25519Reconstruction.kind !== 'completed') {
      throw new Error('Email OTP Ed25519 signing did not provision an Ed25519 signing session');
    }
    const provisioned = ecdsaLogin.ed25519Reconstruction.sessionMaterial;
    const refreshedRecord = this.ports.getThresholdEd25519SessionRecordByThresholdSessionId(
      provisioned.sessionId,
    );
    return {
      sessionId: provisioned.sessionId,
      ...(refreshedRecord ? { record: refreshedRecord } : {}),
    };
  }
}
