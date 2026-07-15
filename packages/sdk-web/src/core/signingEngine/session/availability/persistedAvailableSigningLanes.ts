import type { SigningSessionStatus } from '@/core/types/seams';
import { toAccountId } from '@/core/types/accountIds';
import { classifyThresholdEcdsaSessionRecordRoleLocalState } from '../persistence/ecdsaRoleLocalRecords';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  thresholdEcdsaChainTargetKey,
  toWalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { WarmSessionStatusResult } from '../../uiConfirm/uiConfirm.types';
import {
  buildEcdsaLaneBudgetStatusCheck,
  buildThresholdBudgetStatusCheck,
  ed25519WalletBudgetOwner,
  type SigningSessionBudgetStatusCheck,
} from '../budget/budget';
import {
  getStoredThresholdEd25519SessionRecordByThresholdSessionId,
  getThresholdEcdsaSessionRecordByKey,
  listStoredThresholdEd25519SessionLaneRecordsForWallet,
  listThresholdEcdsaRuntimeLanesForWallet,
  thresholdEd25519LaneCandidateFromSessionRecord,
  thresholdEcdsaLaneCandidateFromSessionRecord,
  thresholdEcdsaSessionRecordReadModel,
  type ThresholdEcdsaSessionStoreDeps,
  type ThresholdEd25519SessionRecord,
} from '../persistence/records';
import {
  listEcdsaSealedSessionsForWallet,
  listExactSealedSessionsForWallet,
  type CurrentEd25519SealedSessionRecord,
  type SigningSessionSealedStoreRecord,
} from '../persistence/sealedSessionStore';
import { nearEd25519SigningKeyIdFromString } from '@shared/utils/registrationIntent';
import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import { normalizeThresholdRuntimePolicyScope } from '../../threshold/sessionPolicy';
import { signingRootScopeFromRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import {
  buildEmailOtpAuthContextForWalletAuthMethod,
  type ThresholdEcdsaEmailOtpAuthContext,
} from '../identity/laneIdentity';
import type { ExactEd25519SigningLaneIdentity } from '../identity/exactSigningLaneIdentity';
import type { SigningLaneAuthBinding } from '../identity/signingLaneAuthBinding';
import { signingLaneAuthMethod } from '../identity/signingLaneAuthBinding';
import {
  classifyRouterAbEcdsaHssPersistedSigningRecord,
  classifyRouterAbEd25519PersistedSigningRecord,
  type RouterAbEd25519PersistedSigningRecordState,
} from '../routerAbSigningWalletSession';
import {
  ed25519AvailableLaneIdentityKey,
  readAvailableSigningLanes,
  runtimeEcdsaAvailableLaneIdentityKey,
  runtimeEcdsaRecordAdvisoryKey,
  durableRecordPolicyAdvisory,
  warmStatusToAvailableLaneStateAdvisory,
  type ReadAvailableSigningLanesForSigningInput,
  type ReadAvailableSigningLanesInput,
  type AvailableSigningLanes,
  type AvailableLaneStateAdvisory,
  type AvailableSigningLanesRuntimeEcdsaRecord,
  type AvailableSigningLanesRuntimeEd25519Record,
} from './availableSigningLanes';

export type PersistedAvailableSigningLanesDeps = {
  ecdsaSessions: ThresholdEcdsaSessionStoreDeps;
  statusReader: {
    getWarmSessionStatus: (args: { sessionId: string }) => Promise<WarmSessionStatusResult>;
  };
  getEmailOtpWarmSessionStatus: (sessionId: string) => Promise<WarmSessionStatusResult>;
  getWalletSigningBudgetStatus?: (
    args: SigningSessionBudgetStatusCheck,
  ) => Promise<SigningSessionStatus | null>;
};

type PersistedEd25519SessionRecordBase = Omit<
  ThresholdEd25519SessionRecord,
  | 'source'
  | 'passkeyCredentialIdB64u'
  | 'emailOtpAuthContext'
  | 'signingGrantId'
  | 'walletSessionJwt'
> & {
  signingGrantId: string;
  walletSessionJwt: string;
};

type PersistedPasskeyEd25519SessionRecord = PersistedEd25519SessionRecordBase & {
  source: 'login';
  passkeyCredentialIdB64u: string;
  emailOtpAuthContext?: never;
};

type PersistedEmailOtpEd25519SessionRecord = PersistedEd25519SessionRecordBase & {
  source: 'email_otp';
  emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
  passkeyCredentialIdB64u?: never;
};

type PersistedEd25519SessionRecord =
  | PersistedPasskeyEd25519SessionRecord
  | PersistedEmailOtpEd25519SessionRecord;

type NormalizedPersistedEd25519Fields = {
  thresholdSessionId: string;
  signingGrantId: string;
  walletSessionJwt: string;
  runtimePolicyScope: NonNullable<ThresholdEd25519SessionRecord['runtimePolicyScope']>;
  signingRootId: string;
  signingRootVersion: string;
  participantIds: number[];
};

function assertNeverPersistedEd25519AuthMethod(value: never): never {
  throw new Error(`Unsupported persisted Ed25519 auth method: ${String(value)}`);
}

function buildPersistedPasskeyEd25519SessionRecord(args: {
  record: CurrentEd25519SealedSessionRecord;
  normalized: NormalizedPersistedEd25519Fields;
  credentialIdB64u: string;
}): PersistedPasskeyEd25519SessionRecord {
  const restore = args.record.ed25519Restore;
  return {
    walletId: toWalletId(args.record.walletId),
    nearAccountId: toAccountId(restore.nearAccountId),
    nearEd25519SigningKeyId: nearEd25519SigningKeyIdFromString(restore.nearEd25519SigningKeyId),
    rpId: restore.rpId,
    passkeyCredentialIdB64u: args.credentialIdB64u,
    relayerUrl: args.record.relayerUrl,
    relayerKeyId: restore.relayerKeyId,
    participantIds: args.normalized.participantIds,
    signingRootId: args.normalized.signingRootId,
    signingRootVersion: args.normalized.signingRootVersion,
    runtimePolicyScope: args.normalized.runtimePolicyScope,
    signerSlot: restore.signerSlot,
    routerAbNormalSigning: restore.routerAbNormalSigning,
    thresholdSessionKind: 'jwt',
    thresholdSessionId: args.normalized.thresholdSessionId,
    signingGrantId: args.normalized.signingGrantId,
    walletSessionJwt: args.normalized.walletSessionJwt,
    expiresAtMs: args.record.expiresAtMs,
    remainingUses: args.record.remainingUses,
    updatedAtMs: args.record.updatedAtMs,
    source: 'login',
  };
}

function buildPersistedEmailOtpEd25519SessionRecord(args: {
  record: CurrentEd25519SealedSessionRecord;
  normalized: NormalizedPersistedEd25519Fields;
  provider: 'google' | 'email';
  providerSubjectId: string;
  emailHashHex: string;
}): PersistedEmailOtpEd25519SessionRecord {
  const restore = args.record.ed25519Restore;
  return {
    walletId: toWalletId(args.record.walletId),
    nearAccountId: toAccountId(restore.nearAccountId),
    nearEd25519SigningKeyId: nearEd25519SigningKeyIdFromString(restore.nearEd25519SigningKeyId),
    rpId: restore.rpId,
    emailOtpAuthContext: buildEmailOtpAuthContextForWalletAuthMethod({
      policy: 'session',
      walletId: args.record.walletId,
      emailHashHex: args.emailHashHex,
      reason: 'login',
      retention: 'session',
      provider: args.provider,
      providerUserId: args.providerSubjectId,
    }),
    relayerUrl: args.record.relayerUrl,
    relayerKeyId: restore.relayerKeyId,
    participantIds: args.normalized.participantIds,
    signingRootId: args.normalized.signingRootId,
    signingRootVersion: args.normalized.signingRootVersion,
    runtimePolicyScope: args.normalized.runtimePolicyScope,
    signerSlot: restore.signerSlot,
    routerAbNormalSigning: restore.routerAbNormalSigning,
    thresholdSessionKind: 'jwt',
    thresholdSessionId: args.normalized.thresholdSessionId,
    signingGrantId: args.normalized.signingGrantId,
    walletSessionJwt: args.normalized.walletSessionJwt,
    expiresAtMs: args.record.expiresAtMs,
    remainingUses: args.record.remainingUses,
    updatedAtMs: args.record.updatedAtMs,
    source: 'email_otp',
  };
}

function ed25519SessionRecordFromSealedRecord(
  record: CurrentEd25519SealedSessionRecord,
): PersistedEd25519SessionRecord | null {
  const restore = record.ed25519Restore;
  if (restore.sessionKind !== 'jwt') return null;
  const thresholdSessionId = String(record.thresholdSessionIds.ed25519 || '').trim();
  const signingGrantId = String(record.signingGrantId || '').trim();
  const walletSessionJwt = String(restore.walletSessionJwt || '').trim();
  const runtimePolicyScope = normalizeThresholdRuntimePolicyScope(restore.runtimePolicyScope);
  const signingRoot = runtimePolicyScope
    ? signingRootScopeFromRuntimePolicyScope(runtimePolicyScope)
    : null;
  const participantIds = normalizeThresholdEd25519ParticipantIds(restore.participantIds);
  if (
    !thresholdSessionId ||
    !signingGrantId ||
    !walletSessionJwt ||
    !runtimePolicyScope ||
    !signingRoot ||
    !participantIds
  ) {
    return null;
  }
  try {
    const normalized: NormalizedPersistedEd25519Fields = {
      thresholdSessionId,
      signingGrantId,
      walletSessionJwt,
      runtimePolicyScope,
      signingRootId: signingRoot.signingRootId,
      signingRootVersion: runtimePolicyScope.signingRootVersion,
      participantIds,
    };
    switch (record.authMethod) {
      case 'passkey': {
        const credentialIdB64u = String(restore.credentialIdB64u || '').trim();
        if (!credentialIdB64u) return null;
        return buildPersistedPasskeyEd25519SessionRecord({
          record,
          normalized,
          credentialIdB64u,
        });
      }
      case 'email_otp': {
        if (!('provider' in restore)) return null;
        const providerSubjectId = String(restore.providerSubjectId || '').trim();
        const emailHashHex = String(restore.emailHashHex || '').trim();
        if (!providerSubjectId || !emailHashHex) return null;
        return buildPersistedEmailOtpEd25519SessionRecord({
          record,
          normalized,
          provider: restore.provider,
          providerSubjectId,
          emailHashHex,
        });
      }
    }
    return assertNeverPersistedEd25519AuthMethod(record.authMethod);
  } catch {
    return null;
  }
}

function ed25519LaneAuthFromRecord(
  record: PersistedEd25519SessionRecord,
): SigningLaneAuthBinding | null {
  const candidate = thresholdEd25519LaneCandidateFromSessionRecord({ record });
  if (!candidate) return null;
  return candidate.auth;
}

function signingLaneAuthBindingsEqual(
  left: SigningLaneAuthBinding,
  right: SigningLaneAuthBinding,
): boolean {
  switch (left.kind) {
    case 'passkey':
      return (
        right.kind === 'passkey' &&
        left.rpId === right.rpId &&
        left.credentialIdB64u === right.credentialIdB64u
      );
    case 'email_otp':
      return right.kind === 'email_otp' && left.providerSubjectId === right.providerSubjectId;
  }
}

function sealedEd25519RecordMatchesLane(args: {
  record: ThresholdEd25519SessionRecord;
  laneIdentity: ExactEd25519SigningLaneIdentity;
}): boolean {
  const signer = args.laneIdentity.signer;
  const recordAuth = thresholdEd25519LaneCandidateFromSessionRecord({
    record: args.record,
  })?.auth;
  if (!recordAuth) return false;
  return (
    String(args.record.walletId) === String(signer.account.wallet.walletId) &&
    String(args.record.nearAccountId) === String(signer.account.nearAccountId) &&
    String(args.record.nearEd25519SigningKeyId) === String(signer.nearEd25519SigningKeyId) &&
    args.record.signerSlot === signer.signerSlot &&
    signingLaneAuthBindingsEqual(recordAuth, args.laneIdentity.auth) &&
    String(args.record.signingGrantId) === String(args.laneIdentity.signingGrantId) &&
    args.record.thresholdSessionId === args.laneIdentity.thresholdSessionId
  );
}

export async function readPersistedEd25519SessionRecordForSigning(args: {
  walletId: string;
  laneIdentity: ExactEd25519SigningLaneIdentity;
}): Promise<ThresholdEd25519SessionRecord | null> {
  const sealedRecords = await listExactSealedSessionsForWallet({
    walletId: args.walletId,
    filter: { authMethod: signingLaneAuthMethod(args.laneIdentity.auth), curve: 'ed25519' },
  });
  const candidates: ThresholdEd25519SessionRecord[] = [];
  for (const sealedRecord of sealedRecords) {
    if (sealedRecord.curve !== 'ed25519') continue;
    const record = ed25519SessionRecordFromSealedRecord(sealedRecord);
    if (!record || !sealedEd25519RecordMatchesLane({ record, laneIdentity: args.laneIdentity })) {
      continue;
    }
    candidates.push(record);
  }
  if (candidates.length > 1) {
    throw new Error('[SigningEngine][near] exact persisted Ed25519 lane is ambiguous');
  }
  return candidates[0] || null;
}

function applyWalletBudgetStatusToAdvisory(args: {
  sessionId: string;
  localAdvisory: AvailableLaneStateAdvisory | null;
  walletBudgetStatus: SigningSessionStatus | null;
}): AvailableLaneStateAdvisory | null {
  const budgetStatus = args.walletBudgetStatus;
  if (!budgetStatus) return args.localAdvisory;
  if (budgetStatus.status === 'active') {
    const budgetExpiresAtMs = Math.floor(Number(budgetStatus.expiresAtMs) || 0);
    if (args.localAdvisory?.kind === 'durable_policy') {
      return {
        kind: 'durable_policy',
        thresholdSessionId: args.sessionId,
        remainingUses: Math.max(0, Math.floor(Number(budgetStatus.remainingUses) || 0)),
        expiresAtMs: budgetExpiresAtMs > 0 ? budgetExpiresAtMs : args.localAdvisory.expiresAtMs,
        state: args.localAdvisory.state,
      };
    }
    if (args.localAdvisory?.kind !== 'warm_status' || args.localAdvisory.status !== 'active') {
      return args.localAdvisory;
    }
    return {
      kind: 'warm_status',
      status: 'active',
      thresholdSessionId: args.sessionId,
      remainingUses: Math.max(0, Math.floor(Number(budgetStatus.remainingUses) || 0)),
      expiresAtMs: budgetExpiresAtMs > 0 ? budgetExpiresAtMs : args.localAdvisory.expiresAtMs,
    };
  }
  if (budgetStatus.status === 'not_found') {
    return args.localAdvisory;
  }
  if (budgetStatus.status === 'expired') {
    return { kind: 'warm_status', status: 'expired', thresholdSessionId: args.sessionId };
  }
  if (budgetStatus.status === 'exhausted') {
    return {
      kind: 'warm_status',
      status: 'exhausted',
      thresholdSessionId: args.sessionId,
      remainingUses: 0,
    };
  }
  return args.localAdvisory;
}

async function readValidatedEd25519WarmClaim(args: {
  deps: Pick<PersistedAvailableSigningLanesDeps, 'statusReader' | 'getEmailOtpWarmSessionStatus'>;
  record: ThresholdEd25519SessionRecord;
  sessionId: string;
}): Promise<AvailableLaneStateAdvisory | null> {
  const status =
    args.record.source === SIGNER_AUTH_METHODS.emailOtp
      ? await args.deps.getEmailOtpWarmSessionStatus(args.sessionId).catch(() => null)
      : await args.deps.statusReader
          .getWarmSessionStatus({ sessionId: args.sessionId })
          .catch(() => null);
  if (!status) return null;
  const advisory = warmStatusToAvailableLaneStateAdvisory({
    thresholdSessionId: args.sessionId,
    status,
  });
  return advisory.kind === 'warm_status' &&
    (advisory.status === 'cache_miss' || advisory.status === 'unavailable')
    ? null
    : advisory;
}

function policyClaimForEd25519PersistedState(args: {
  state: RouterAbEd25519PersistedSigningRecordState;
  sessionId: string;
}): AvailableLaneStateAdvisory | null {
  switch (args.state.kind) {
    case 'ready':
      return durableRecordPolicyAdvisory({
        thresholdSessionId: args.sessionId,
        remainingUses: args.state.value.remainingUses,
        expiresAtMs: args.state.value.expiresAtMs,
        state: 'ready',
      });
    case 'expired':
      return durableRecordPolicyAdvisory({
        thresholdSessionId: args.sessionId,
        remainingUses: args.state.record.remainingUses,
        expiresAtMs: args.state.expiresAtMs,
        state: 'deferred',
      });
    case 'exhausted':
      return durableRecordPolicyAdvisory({
        thresholdSessionId: args.sessionId,
        remainingUses: args.state.remainingUses,
        expiresAtMs: args.state.record.expiresAtMs,
        state: 'deferred',
      });
    case 'non_signing':
    case 'invalid':
      return null;
    default: {
      const exhaustive: never = args.state;
      return exhaustive;
    }
  }
}

async function readEd25519StateAdvisoryForRecord(args: {
  deps: Pick<PersistedAvailableSigningLanesDeps, 'statusReader' | 'getEmailOtpWarmSessionStatus'>;
  record: ThresholdEd25519SessionRecord | null | undefined;
  sessionId: string;
}): Promise<AvailableLaneStateAdvisory | null> {
  const state = classifyRouterAbEd25519PersistedSigningRecord(args.record);
  if (state.kind === 'ready') {
    const warmAdvisory = await readValidatedEd25519WarmClaim({
      deps: args.deps,
      record: state.record,
      sessionId: args.sessionId,
    });
    return (
      warmAdvisory ||
      policyClaimForEd25519PersistedState({
        state,
        sessionId: args.sessionId,
      })
    );
  }
  return policyClaimForEd25519PersistedState({
    state,
    sessionId: args.sessionId,
  });
}

export async function readPersistedAvailableSigningLanes(
  deps: PersistedAvailableSigningLanesDeps,
  args: Omit<ReadAvailableSigningLanesInput, 'ecdsaChainTargets'>,
  ecdsaChainTargets: readonly ThresholdEcdsaChainTarget[],
): Promise<AvailableSigningLanes> {
  return await readPersistedAvailableSigningLanesForTargets(deps, {
    ...args,
    ecdsaChainTargets,
  });
}

export async function readPersistedAvailableSigningLanesForSigning(
  deps: PersistedAvailableSigningLanesDeps,
  args: ReadAvailableSigningLanesForSigningInput,
  defaultEcdsaChainTargets: readonly ThresholdEcdsaChainTarget[],
): Promise<AvailableSigningLanes> {
  if (args.curve === 'ecdsa') {
    const { curve, ...availableLanesArgs } = args;
    const ecdsaChainTargetsByKey = new Map<string, ThresholdEcdsaChainTarget>();
    for (const chainTarget of [...args.ecdsaChainTargets, ...defaultEcdsaChainTargets]) {
      ecdsaChainTargetsByKey.set(thresholdEcdsaChainTargetKey(chainTarget), chainTarget);
    }
    return await readPersistedAvailableSigningLanesForTargets(deps, {
      ...availableLanesArgs,
      ecdsaChainTargets: [...ecdsaChainTargetsByKey.values()],
    });
  }
  const { curve, ...availableLanesArgs } = args;
  return await readPersistedAvailableSigningLanes(
    deps,
    availableLanesArgs,
    defaultEcdsaChainTargets,
  );
}

function sealedRecordHasEd25519ThresholdSession(record: SigningSessionSealedStoreRecord): boolean {
  return String(record.thresholdSessionIds?.ed25519 || '').trim().length > 0;
}

function sealedEcdsaRecordMatchesAnyChainTarget(
  record: SigningSessionSealedStoreRecord,
  chainTargets: readonly ThresholdEcdsaChainTarget[],
): boolean {
  const recordChainTarget = record.ecdsaRestore?.chainTarget;
  if (!recordChainTarget) return false;
  const recordChainTargetKey = thresholdEcdsaChainTargetKey(recordChainTarget);
  for (const chainTarget of chainTargets) {
    if (recordChainTargetKey === thresholdEcdsaChainTargetKey(chainTarget)) return true;
  }
  return false;
}

function filterEmailOtpCompanionEcdsaRecords(
  records: readonly SigningSessionSealedStoreRecord[],
  chainTargets: readonly ThresholdEcdsaChainTarget[],
): SigningSessionSealedStoreRecord[] {
  const matchingRecords: SigningSessionSealedStoreRecord[] = [];
  for (const record of records) {
    if (!sealedRecordHasEd25519ThresholdSession(record)) continue;
    if (!sealedEcdsaRecordMatchesAnyChainTarget(record, chainTargets)) continue;
    matchingRecords.push(record);
  }
  return matchingRecords;
}

export async function readPersistedAvailableSigningLanesForTargets(
  deps: PersistedAvailableSigningLanesDeps,
  args: Omit<ReadAvailableSigningLanesInput, 'ecdsaChainTargets'> & {
    ecdsaChainTargets: readonly ThresholdEcdsaChainTarget[];
  },
): Promise<AvailableSigningLanes> {
  const walletId = String(toWalletId(args.walletId)).trim();
  const persistedEd25519RecordsBySessionId = new Map<string, ThresholdEd25519SessionRecord>();
  const pushRuntimeEcdsaRecord = async (
    records: AvailableSigningLanesRuntimeEcdsaRecord[],
    seen: Set<string>,
    record: AvailableSigningLanesRuntimeEcdsaRecord,
  ): Promise<void> => {
    const identityKey = await runtimeEcdsaAvailableLaneIdentityKey(record);
    if (!identityKey) return;
    if (seen.has(identityKey)) return;
    seen.add(identityKey);
    records.push(record);
  };

  return await readAvailableSigningLanes(
    {
      ...args,
      walletId,
      ecdsaChainTargets: args.ecdsaChainTargets,
    },
    {
      listSealedRecordsForWallet: async ({ walletId: recordWalletId, filter }) => {
        const listByAuthMethod = async (
          authMethod: 'email_otp' | 'passkey',
        ): Promise<SigningSessionSealedStoreRecord[]> => {
          if (filter.curve === 'ecdsa') {
            return await listExactSealedSessionsForWallet({
              walletId: recordWalletId,
              filter: {
                authMethod,
                curve: 'ecdsa',
                chainTarget: filter.chainTarget,
              },
            });
          }
          const ed25519Records = await listExactSealedSessionsForWallet({
            walletId: recordWalletId,
            filter: { authMethod, curve: 'ed25519' },
          });
          if (authMethod !== 'email_otp') return ed25519Records;
          const companionEcdsaRecords = filterEmailOtpCompanionEcdsaRecords(
            await listEcdsaSealedSessionsForWallet({
              walletId: recordWalletId,
              filter: {
                authMethod: 'email_otp',
                curve: 'ecdsa',
              },
            }),
            args.ecdsaChainTargets,
          );
          return [...ed25519Records, ...companionEcdsaRecords];
        };
        if (filter.authMethod) {
          return await listByAuthMethod(filter.authMethod);
        }
        const [emailOtpRecords, passkeyRecords] = await Promise.all([
          listByAuthMethod('email_otp'),
          listByAuthMethod('passkey'),
        ]);
        return [...emailOtpRecords, ...passkeyRecords];
      },
      listEcdsaSealedRecordsForWallet: async ({ walletId: recordWalletId, filter }) => {
        if (filter.authMethod) {
          return await listEcdsaSealedSessionsForWallet({
            walletId: recordWalletId,
            filter,
          });
        }
        const [emailOtpRecords, passkeyRecords] = await Promise.all([
          listEcdsaSealedSessionsForWallet({
            walletId: recordWalletId,
            filter: { authMethod: 'email_otp', curve: 'ecdsa' },
          }),
          listEcdsaSealedSessionsForWallet({
            walletId: recordWalletId,
            filter: { authMethod: 'passkey', curve: 'ecdsa' },
          }),
        ]);
        return [...emailOtpRecords, ...passkeyRecords];
      },
      listRuntimeEcdsaLanesForWallet: async ({ walletId: recordWalletId }) => {
        const records: AvailableSigningLanesRuntimeEcdsaRecord[] = [];
        const seen = new Set<string>();
        for (const runtimeLane of listThresholdEcdsaRuntimeLanesForWallet(
          deps.ecdsaSessions,
          recordWalletId,
        )) {
          const runtimeLaneAuthMethod = signingLaneAuthMethod(runtimeLane.auth);
          if (args.authMethod && args.authMethod !== runtimeLaneAuthMethod) continue;
          if (!runtimeLane.routerAbEcdsaHssNormalSigning) continue;
          const publicFactsFields = runtimeLane.verifiedPublicFacts
            ? { verifiedPublicFacts: runtimeLane.verifiedPublicFacts }
            : {};
          const baseRecord = {
            key: runtimeLane.key,
            routerAbEcdsaHssNormalSigning: runtimeLane.routerAbEcdsaHssNormalSigning,
            keyHandle: runtimeLane.keyHandle,
            ...publicFactsFields,
            thresholdEcdsaPublicKeyB64u: runtimeLane.thresholdEcdsaPublicKeyB64u,
            curve: 'ecdsa' as const,
            chainTarget: runtimeLane.chainTarget,
            thresholdSessionId: runtimeLane.thresholdSessionId,
            signingGrantId: runtimeLane.signingGrantId,
            ...(runtimeLane.remainingUses == null
              ? {}
              : { remainingUses: runtimeLane.remainingUses }),
            ...(runtimeLane.expiresAtMs == null ? {} : { expiresAtMs: runtimeLane.expiresAtMs }),
            ...(runtimeLane.updatedAtMs == null ? {} : { updatedAtMs: runtimeLane.updatedAtMs }),
          };
          if (runtimeLane.auth.kind === 'passkey') {
            const record: AvailableSigningLanesRuntimeEcdsaRecord = {
              ...baseRecord,
              auth: runtimeLane.auth,
              ...(runtimeLane.resolvedKey ? { resolvedKey: runtimeLane.resolvedKey } : {}),
            };
            await pushRuntimeEcdsaRecord(records, seen, record);
            continue;
          }
          const record: AvailableSigningLanesRuntimeEcdsaRecord = {
            ...baseRecord,
            auth: runtimeLane.auth,
          };
          await pushRuntimeEcdsaRecord(records, seen, record);
        }
        return records;
      },
      listRuntimeEd25519RecordsForWallet: async ({ walletId: recordWalletId }) => {
        const records: AvailableSigningLanesRuntimeEd25519Record[] = [];
        const seen = new Set<string>();
        const pushRecord = (record: AvailableSigningLanesRuntimeEd25519Record): void => {
          const identityKey = ed25519AvailableLaneIdentityKey(record);
          if (!identityKey || seen.has(identityKey)) return;
          seen.add(identityKey);
          records.push(record);
        };
        for (const runtimeRecord of listStoredThresholdEd25519SessionLaneRecordsForWallet(
          recordWalletId,
        )) {
          const authMethod =
            runtimeRecord.source === SIGNER_AUTH_METHODS.emailOtp ? 'email_otp' : 'passkey';
          if (args.authMethod && args.authMethod !== authMethod) continue;
          const candidate = thresholdEd25519LaneCandidateFromSessionRecord({
            record: runtimeRecord,
          });
          if (!candidate) continue;
          pushRecord({
            auth: candidate.auth,
            curve: 'ed25519',
            chain: 'near',
            walletId: runtimeRecord.walletId,
            nearAccountId: runtimeRecord.nearAccountId,
            nearEd25519SigningKeyId: runtimeRecord.nearEd25519SigningKeyId,
            signerSlot: candidate.signerSlot,
            routerAbNormalSigning: runtimeRecord.routerAbNormalSigning,
            thresholdSessionId: runtimeRecord.thresholdSessionId,
            signingGrantId: String(runtimeRecord.signingGrantId || '').trim(),
            source: 'runtime_session_record',
            remainingUses: runtimeRecord.remainingUses,
            expiresAtMs: runtimeRecord.expiresAtMs,
            updatedAtMs: runtimeRecord.updatedAtMs,
          });
        }
        const sealedRecords = args.authMethod
          ? await listExactSealedSessionsForWallet({
              walletId: recordWalletId,
              filter: { authMethod: args.authMethod, curve: 'ed25519' },
            })
          : (
              await Promise.all([
                listExactSealedSessionsForWallet({
                  walletId: recordWalletId,
                  filter: { authMethod: 'email_otp', curve: 'ed25519' },
                }),
                listExactSealedSessionsForWallet({
                  walletId: recordWalletId,
                  filter: { authMethod: 'passkey', curve: 'ed25519' },
                }),
              ])
            ).flat();
        for (const sealedRecord of sealedRecords) {
          if (sealedRecord.curve !== 'ed25519') continue;
          const persistedRecord = ed25519SessionRecordFromSealedRecord(sealedRecord);
          if (!persistedRecord) continue;
          const auth = ed25519LaneAuthFromRecord(persistedRecord);
          if (!auth) continue;
          persistedEd25519RecordsBySessionId.set(
            persistedRecord.thresholdSessionId,
            persistedRecord,
          );
          pushRecord({
            auth,
            curve: 'ed25519',
            chain: 'near',
            walletId: persistedRecord.walletId,
            nearAccountId: persistedRecord.nearAccountId,
            nearEd25519SigningKeyId: persistedRecord.nearEd25519SigningKeyId,
            signerSlot: persistedRecord.signerSlot,
            routerAbNormalSigning: persistedRecord.routerAbNormalSigning,
            thresholdSessionId: persistedRecord.thresholdSessionId,
            signingGrantId: persistedRecord.signingGrantId,
            source: 'durable_sealed_record',
            remainingUses: persistedRecord.remainingUses,
            expiresAtMs: persistedRecord.expiresAtMs,
            updatedAtMs: persistedRecord.updatedAtMs,
          });
        }
        return records;
      },
      readEcdsaWarmStatusAdvisoriesForRecords: async (runtimeRecords) => {
        const advisories = new Map<string, AvailableLaneStateAdvisory | null>();
        await Promise.all(
          runtimeRecords.map(async (runtimeRecord) => {
            const advisoryKey = runtimeEcdsaRecordAdvisoryKey(runtimeRecord);
            if (!advisoryKey) return;
            const keyHandle = String(runtimeRecord.keyHandle || '').trim();
            if (!keyHandle) {
              advisories.set(advisoryKey, null);
              return;
            }
            const sessionId = String(runtimeRecord.thresholdSessionId || '').trim();
            const signingGrantId = String(runtimeRecord.signingGrantId || '').trim();
            const ecdsaRecord = getThresholdEcdsaSessionRecordByKey(deps.ecdsaSessions, {
              walletId: toWalletId(runtimeRecord.key.walletId),
              keyHandle,
              authMethod: signingLaneAuthMethod(runtimeRecord.auth),
              curve: 'ecdsa',
              chainTarget: runtimeRecord.chainTarget,
              signingGrantId,
              thresholdSessionId: sessionId,
            });
            let localAdvisory: AvailableLaneStateAdvisory | null = null;
            if (!ecdsaRecord) {
              localAdvisory = null;
            } else if (ecdsaRecord.source === SIGNER_AUTH_METHODS.emailOtp) {
              const roleLocalState = classifyThresholdEcdsaSessionRecordRoleLocalState({
                record: ecdsaRecord,
                nowMs: Date.now(),
              });
              if (
                roleLocalState.kind === 'ready_email_otp_role_local_material_v1' &&
                roleLocalState.inlineSigningMaterial.kind === 'email_otp_worker_share'
              ) {
                const status = await deps
                  .getEmailOtpWarmSessionStatus(
                    roleLocalState.inlineSigningMaterial.workerSessionId,
                  )
                  .catch(() => null);
                localAdvisory = status
                  ? warmStatusToAvailableLaneStateAdvisory({
                      thresholdSessionId: sessionId,
                      status,
                    })
                  : null;
              } else if (
                roleLocalState.kind === 'ready_email_otp_role_local_material_v1' &&
                roleLocalState.inlineSigningMaterial.kind === 'role_local_ready_state_blob'
              ) {
                localAdvisory = durableRecordPolicyAdvisory({
                  thresholdSessionId: sessionId,
                  remainingUses: ecdsaRecord.remainingUses,
                  expiresAtMs: ecdsaRecord.expiresAtMs,
                  state: 'restorable',
                });
              } else {
                localAdvisory = null;
              }
            } else {
              const materialState = classifyRouterAbEcdsaHssPersistedSigningRecord(ecdsaRecord);
              if (materialState.kind === 'runtime_validated') {
                const status = await deps.statusReader
                  .getWarmSessionStatus({ sessionId })
                  .catch(() => null);
                localAdvisory = status
                  ? warmStatusToAvailableLaneStateAdvisory({
                      thresholdSessionId: sessionId,
                      status,
                    })
                  : null;
              } else if (materialState.kind === 'restore_available') {
                localAdvisory = durableRecordPolicyAdvisory({
                  thresholdSessionId: sessionId,
                  remainingUses: ecdsaRecord.remainingUses,
                  expiresAtMs: ecdsaRecord.expiresAtMs,
                  state: 'restorable',
                });
              } else if (materialState.kind === 'expired') {
                localAdvisory = durableRecordPolicyAdvisory({
                  thresholdSessionId: sessionId,
                  remainingUses: ecdsaRecord.remainingUses,
                  expiresAtMs: materialState.expiresAtMs,
                  state: 'deferred',
                });
              } else if (materialState.kind === 'exhausted') {
                localAdvisory = durableRecordPolicyAdvisory({
                  thresholdSessionId: sessionId,
                  remainingUses: materialState.remainingUses,
                  expiresAtMs: ecdsaRecord.expiresAtMs,
                  state: 'deferred',
                });
              } else if (materialState.kind === 'material_hint_unvalidated') {
                localAdvisory = durableRecordPolicyAdvisory({
                  thresholdSessionId: sessionId,
                  remainingUses: ecdsaRecord.remainingUses,
                  expiresAtMs: ecdsaRecord.expiresAtMs,
                  state: 'deferred',
                });
              } else {
                localAdvisory = null;
              }
            }
            const walletBudgetStatus =
              ecdsaRecord && deps.getWalletSigningBudgetStatus
                ? await deps
                    .getWalletSigningBudgetStatus(
                      buildEcdsaLaneBudgetStatusCheck({
                        key: thresholdEcdsaSessionRecordReadModel(ecdsaRecord).key,
                        keyHandle: ecdsaRecord.keyHandle,
                        auth: thresholdEcdsaLaneCandidateFromSessionRecord({ record: ecdsaRecord })
                          .auth,
                        chainTarget: ecdsaRecord.chainTarget,
                        signingGrantId,
                        thresholdSessionId: ecdsaRecord.thresholdSessionId,
                      }),
                    )
                    .catch(() => null)
                : null;
            advisories.set(
              advisoryKey,
              applyWalletBudgetStatusToAdvisory({
                sessionId,
                localAdvisory,
                walletBudgetStatus,
              }),
            );
          }),
        );
        return advisories;
      },
      readWarmStatusAdvisoriesForSessions: async (sessionIds) => {
        const advisories = new Map<string, AvailableLaneStateAdvisory | null>();
        await Promise.all(
          sessionIds.map(async (sessionId) => {
            const ed25519Record =
              getStoredThresholdEd25519SessionRecordByThresholdSessionId(sessionId) ||
              persistedEd25519RecordsBySessionId.get(sessionId) ||
              null;
            const localAdvisory = await readEd25519StateAdvisoryForRecord({
              deps,
              record: ed25519Record,
              sessionId,
            });
            const signingGrantId = String(ed25519Record?.signingGrantId || '').trim();
            const walletBudgetStatus =
              signingGrantId && deps.getWalletSigningBudgetStatus
                ? await deps
                    .getWalletSigningBudgetStatus(
                      buildThresholdBudgetStatusCheck({
                        owner: ed25519WalletBudgetOwner(walletId),
                        signingGrantId,
                        targetThresholdSessionIds: [sessionId],
                      }),
                    )
                    .catch(() => null)
                : null;
            advisories.set(
              sessionId,
              applyWalletBudgetStatusToAdvisory({
                sessionId,
                localAdvisory,
                walletBudgetStatus,
              }),
            );
          }),
        );
        return advisories;
      },
    },
  );
}
