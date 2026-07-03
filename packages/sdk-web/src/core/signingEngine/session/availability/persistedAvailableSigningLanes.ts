import type { SigningSessionStatus } from '@/core/types/seams';
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
  type SigningSessionSealedStoreRecord,
} from '../persistence/sealedSessionStore';
import { signingLaneAuthMethod } from '../identity/signingLaneAuthBinding';
import {
  classifyRouterAbEcdsaHssPersistedSigningRecord,
  classifyRouterAbEd25519PersistedSigningRecord,
  type RouterAbEd25519PersistedSigningRecordState,
} from '../routerAbSigningWalletSession';
import { ed25519AvailableMaterialStateFromSessionRecord } from './ed25519AvailableMaterialState';
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
    if (
      args.localAdvisory?.kind !== 'warm_status' ||
      args.localAdvisory.status !== 'active'
    ) {
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
    case 'restore_available':
      return durableRecordPolicyAdvisory({
        thresholdSessionId: args.sessionId,
        remainingUses: args.state.record.remainingUses,
        expiresAtMs: args.state.record.expiresAtMs,
        state: 'restorable',
      });
    case 'material_hint_unvalidated':
    case 'auth_ready_material_pending':
      return durableRecordPolicyAdvisory({
        thresholdSessionId: args.sessionId,
        remainingUses: args.state.record.remainingUses,
        expiresAtMs: args.state.record.expiresAtMs,
        state: 'deferred',
      });
    case 'runtime_validated':
      return durableRecordPolicyAdvisory({
        thresholdSessionId: args.sessionId,
        remainingUses: args.state.value.remainingUses,
        expiresAtMs: args.state.value.expiresAtMs,
        state: 'ready',
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
  if (state.kind === 'runtime_validated') {
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

function sealedRecordHasEd25519ThresholdSession(
  record: SigningSessionSealedStoreRecord,
): boolean {
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
          const material = ed25519AvailableMaterialStateFromSessionRecord(runtimeRecord);
          if (!material) continue;
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
            remainingUses: runtimeRecord.remainingUses,
            expiresAtMs: runtimeRecord.expiresAtMs,
            updatedAtMs: runtimeRecord.updatedAtMs,
            material,
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
            const signingGrantId = String(
              runtimeRecord.signingGrantId || '',
            ).trim();
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
                  ? warmStatusToAvailableLaneStateAdvisory({ thresholdSessionId: sessionId, status })
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
                  ? warmStatusToAvailableLaneStateAdvisory({ thresholdSessionId: sessionId, status })
                  : null;
              } else if (materialState.kind === 'restore_available') {
                localAdvisory = durableRecordPolicyAdvisory({
                  thresholdSessionId: sessionId,
                  remainingUses: ecdsaRecord.remainingUses,
                  expiresAtMs: ecdsaRecord.expiresAtMs,
                  state: 'restorable',
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
                        auth: thresholdEcdsaLaneCandidateFromSessionRecord({ record: ecdsaRecord }).auth,
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
              getStoredThresholdEd25519SessionRecordByThresholdSessionId(sessionId);
            const localAdvisory = await readEd25519StateAdvisoryForRecord({
              deps,
              record: ed25519Record,
              sessionId,
            });
            const signingGrantId = String(
              ed25519Record?.signingGrantId || '',
            ).trim();
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
